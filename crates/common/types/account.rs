use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use ethereum_types::{H256, U256};
use ethrex_crypto::{Crypto, NativeCrypto};
use ethrex_trie::Trie;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

use super::GenesisAccount;
use crate::constants::{EMPTY_KECCAK_HASH, EMPTY_TRIE_HASH};

/// Shared empty jumpdest bitmap. `Code::default()` and any bytecode without a
/// `JUMPDEST` clone this (a refcount bump) instead of allocating a fresh empty
/// `Arc` header each time. This matters because the per-tx `Code::default()`
/// placeholder and every EOA / empty-code load would otherwise each allocate.
static EMPTY_JUMPDESTS: LazyLock<Arc<[u8]>> = LazyLock::new(|| Arc::from(Vec::new()));

/// Trailing STOP bytes appended to every bytecode so the dispatch loop can read
/// the next opcode without a bounds check. 33 is the widest single-opcode advance
/// (PUSH32: 1 opcode byte + 32 immediate bytes), so `pc` can never step past the
/// padding regardless of which opcode sits at the last real byte.
pub const BYTECODE_PADDING: usize = 33;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Code {
    // hash is only used for bytecodes stored in the DB, either for reading it from the DB
    // or with the CODEHASH opcode, which needs an account address as argument and
    // thus only accessed persisted bytecodes.
    // We use a bogus H256::zero() value for initcodes as there is no way for the VM or
    // endpoints to access that hash, saving one expensive Keccak hash.
    pub hash: H256,
    /// bytecode padded with 33 zeroes (STOP opcodes, due to PUSH32) to avoid checks on the hot path.
    bytecode: Bytes,
    /// The real bytecode length, needed for some opcodes, `bytecode` is padded with 33 STOPs to avoid checked adds on hot loop.
    bytecode_len: usize,
    /// One bit per bytecode byte, set when that offset holds a `JUMPDEST` that is not
    /// part of a `PUSH` immediate. Costs `ceil(len / 8)` bytes regardless of how dense
    /// the jump destinations are, and validating a jump is a bit test rather than a
    /// search.
    ///
    /// Bytecode with no jump destination stores a zero-length bitmap ([`EMPTY_JUMPDESTS`])
    /// rather than an all-zero one, so this is not always `ceil(len / 8)` bytes long;
    /// [`Code::is_valid_jumpdest`] reads a missing byte as "no jump destination".
    //
    // `Arc<[u8]>` so cloning `Code` (hot: every message-call resolves and clones
    // the callee's code) is a refcount bump instead of deep-copying the bitmap.
    // Serializes via serde's `rc` feature (enabled workspace-wide).
    jumpdests: Arc<[u8]>,
}

impl Code {
    // SAFETY: hash will be stored as-is, so it either needs to match
    // the real code hash (i.e. it was precomputed and we're reusing)
    // or never be read (e.g. for initcode).
    //
    // `code` is the logical, unpadded bytecode; `BYTECODE_PADDING` STOP bytes are
    // appended internally by `from_parts_unchecked`.
    pub fn from_bytecode_unchecked(code: Bytes, hash: H256) -> Self {
        let jumpdests = Self::compute_jumpdests(&code);
        Self::from_parts_unchecked(hash, &code, jumpdests)
    }

    /// `code` is the logical, unpadded bytecode; `BYTECODE_PADDING` STOP bytes are
    /// appended internally by `from_parts_unchecked`.
    pub fn from_bytecode(code: Bytes, crypto: &dyn Crypto) -> Self {
        let jumpdests = Self::compute_jumpdests(&code);
        let hash = H256(crypto.keccak256(code.as_ref()));
        Self::from_parts_unchecked(hash, &code, jumpdests)
    }

    /// Builds a `Code` from precomputed parts. The caller must guarantee `hash`
    /// and `jumpdests` correspond to `code`; neither is recomputed or validated.
    ///
    /// `code` is the logical, unpadded bytecode: this function appends
    /// `BYTECODE_PADDING` STOP bytes and records the original length in
    /// `bytecode_len`. Never pass a pre-padded buffer, or the logical length and
    /// every `JUMPDEST`/`PUSH` offset derived from it would be wrong.
    pub fn from_parts_unchecked(hash: H256, code: &[u8], jumpdests: Arc<[u8]>) -> Self {
        let bytecode_len = code.len();
        let mut padded_code = Vec::with_capacity(bytecode_len + BYTECODE_PADDING);
        padded_code.extend_from_slice(code);
        padded_code.extend_from_slice(&[0u8; BYTECODE_PADDING]);
        Self {
            hash,
            bytecode: Bytes::from_owner(padded_code),
            bytecode_len,
            jumpdests,
        }
    }

    /// Builds the [`Code::jumpdests`] bitmap: one pass over the bytecode, setting the
    /// bit for every `JUMPDEST` while skipping `PUSH` immediates.
    ///
    /// The bits of a byte are accumulated in a register and written once the scan leaves
    /// that byte, which the monotonic `i` makes safe. Reading the bitmap back inside the
    /// loop instead would turn each `JUMPDEST` into a read-modify-write, and indexing it
    /// would put a bounds-check panic path in the loop body, which inhibits optimization
    /// of every iteration rather than only the ones that find a destination.
    pub fn compute_jumpdests(code: &[u8]) -> Arc<[u8]> {
        let mut bitmap = vec![0u8; code.len().div_ceil(8)];
        let mut any = false;
        let mut current_byte = usize::MAX;
        let mut bits = 0u8;
        let mut i = 0;
        while i < code.len() {
            // TODO: we don't use the constants from the vm module to avoid a circular dependency
            match code[i] {
                // OP_JUMPDEST
                0x5B => {
                    if i / 8 != current_byte {
                        if let Some(byte) = bitmap.get_mut(current_byte) {
                            *byte = bits;
                        }
                        current_byte = i / 8;
                        bits = 0;
                    }
                    bits |= 1 << (i % 8);
                    any = true;
                }
                // OP_PUSH1..32
                c @ 0x60..0x80 => {
                    // OP_PUSH0
                    i += (c - 0x5F) as usize;
                }
                _ => (),
            }
            i += 1;
        }
        if let Some(byte) = bitmap.get_mut(current_byte) {
            *byte = bits;
        }
        // Share the single empty bitmap for jumpless bytecode (very common: EOAs,
        // tiny contracts) so we don't allocate for an all-zero map; `is_valid_jumpdest`
        // reads a missing byte as "no jump destination".
        if any {
            Arc::from(bitmap)
        } else {
            EMPTY_JUMPDESTS.clone()
        }
    }

    /// Whether `offset` is a valid jump destination, i.e. it holds a `JUMPDEST` that is
    /// not part of a `PUSH` immediate. Offsets past the bytecode are not valid.
    #[inline]
    pub fn is_valid_jumpdest(&self, offset: usize) -> bool {
        self.jumpdests
            .get(offset / 8)
            .is_some_and(|byte| byte & (1 << (offset % 8)) != 0)
    }

    /// The raw [`Code::jumpdests`] bitmap, for persisting it alongside the bytecode.
    #[inline]
    pub fn jumpdests(&self) -> &[u8] {
        &self.jumpdests
    }

    #[inline]
    pub fn code(&self) -> &[u8] {
        self.bytecode.get(..self.bytecode_len).unwrap_or_default()
    }

    #[inline]
    pub fn code_bytes(&self) -> Bytes {
        self.bytecode.slice(..self.bytecode_len)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytecode_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytecode_len == 0
    }

    /// Returns the padded bytecode buffer (real code + [`BYTECODE_PADDING`] trailing
    /// STOPs) used by the opcode dispatch loop to read opcodes without bounds checks.
    /// Use [`Code::code`] for the real, unpadded bytecode.
    #[inline]
    pub fn dispatch_buf(&self) -> &[u8] {
        &self.bytecode
    }

    /// Estimates the size of the Code struct in bytes
    /// (including stack size and heap allocation).
    ///
    /// Note: an estimate. It ignores allocator overhead and the `Arc`/`Bytes` control
    /// blocks, so it slightly under-counts, and a shared allocation is attributed in
    /// full to every entry holding it.
    ///
    /// # Returns
    ///
    /// usize - Estimated size in bytes
    pub fn size(&self) -> usize {
        let hash_size = size_of::<H256>();
        let bytes_size = size_of::<Bytes>() + self.bytecode.len();
        let bitmap_size = size_of::<Arc<[u8]>>() + self.jumpdests.len();
        hash_size + bytes_size + bitmap_size
    }
}

/// Serde shadow for [`Code`]. Stores the *logical* (unpadded) bytecode so the
/// padding is never part of the serialized form. Deserialization re-pads through
/// [`Code::from_parts_unchecked`], which keeps the dispatch-loop invariant (every
/// `Code` is padded with [`BYTECODE_PADDING`] trailing STOPs) sound regardless of
/// where the bytes came from. Deserializing the padded buffer directly would
/// otherwise let unpadded input through and cause OOB reads during execution.
/// The jump destinations are deliberately absent: they are a pure function of the
/// bytecode, so carrying them would put a derived value in the wire format of everything
/// that embeds a `Code` (notably `AccountUpdate`, which the L2 rollup store persists with
/// bincode) and couple that format to how they happen to be represented.
/// Wire form of [`Code`]. Jump destinations are recomputed from `code` on
/// deserialize, never read from here — but the `jump_targets` field is kept so
/// the layout stays byte-identical to the pre-bitmap `Code` serialization.
/// `Code` is embedded in `AccountUpdate`, which is persisted with bincode (a
/// non-self-describing, positional codec) in the L2 rollup store; dropping the
/// field would shift every following field and make existing rows undecodable.
/// It is always serialized empty and ignored on read.
#[derive(Serialize, Deserialize)]
struct CodeSerde {
    hash: H256,
    code: Bytes,
    jump_targets: Arc<[u32]>,
}

impl Serialize for Code {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        CodeSerde {
            hash: self.hash,
            code: self.code_bytes(),
            jump_targets: Arc::from([]),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Code {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `jump_targets` is read only to consume its bytes (layout compatibility);
        // the bitmap is always recomputed from `code`.
        let CodeSerde {
            hash,
            code,
            jump_targets: _,
        } = CodeSerde::deserialize(deserializer)?;
        Ok(Self::from_parts_unchecked(
            hash,
            &code,
            Self::compute_jumpdests(&code),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeMetadata {
    pub length: u64,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub info: AccountInfo,
    pub code: Code,
    pub storage: FxHashMap<H256, U256>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct AccountInfo {
    pub code_hash: H256,
    pub balance: U256,
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

/// A slim codec for an [`AccountState`].
///
/// The slim codec will optimize both the [storage root](AccountState::storage_root) and the
/// [code hash](AccountState::code_hash)'s encoding so that it does not take space when empty.
///
/// The correct way to use it is to wrap the [`AccountState`] and encode it using this codec, and
/// not to store the codec as a field in a struct.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AccountStateSlimCodec(pub AccountState);

impl Default for AccountInfo {
    fn default() -> Self {
        Self {
            code_hash: *EMPTY_KECCAK_HASH,
            balance: Default::default(),
            nonce: Default::default(),
        }
    }
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            nonce: Default::default(),
            balance: Default::default(),
            storage_root: *EMPTY_TRIE_HASH,
            code_hash: *EMPTY_KECCAK_HASH,
        }
    }
}

impl Default for Code {
    fn default() -> Self {
        Self {
            bytecode: Bytes::from_static(&[0u8; BYTECODE_PADDING]),
            bytecode_len: 0,
            hash: *EMPTY_KECCAK_HASH,
            jumpdests: EMPTY_JUMPDESTS.clone(),
        }
    }
}

impl From<GenesisAccount> for Account {
    fn from(genesis: GenesisAccount) -> Self {
        let code = Code::from_bytecode(genesis.code, &NativeCrypto);
        Self {
            info: AccountInfo {
                code_hash: code.hash,
                balance: genesis.balance,
                nonce: genesis.nonce,
            },
            code,
            storage: genesis
                .storage
                .iter()
                .map(|(k, v)| (H256(k.to_big_endian()), *v))
                .collect(),
        }
    }
}

pub fn code_hash(code: &Bytes, crypto: &dyn Crypto) -> H256 {
    H256(crypto.keccak256(code.as_ref()))
}

/// EIP-7702 delegation designation: an EOA whose code is `0xef0100 || address`.
/// See <https://eips.ethereum.org/EIPS/eip-7702>.
pub const EIP7702_DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];
/// Total byte length of an EIP-7702 delegation designation: 3-byte prefix
/// plus the 20-byte target address.
pub const EIP7702_DELEGATED_CODE_LEN: usize = 23;

/// Returns true iff `code` is a valid EIP-7702 delegation designation
/// (exactly 23 bytes, prefixed with `0xef0100`).
pub fn is_eip7702_delegation(code: &[u8]) -> bool {
    code.len() == EIP7702_DELEGATED_CODE_LEN && code.starts_with(&EIP7702_DELEGATION_PREFIX)
}

impl RLPEncode for AccountInfo {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.code_hash)
            .encode_field(&self.balance)
            .encode_field(&self.nonce)
            .finish();
    }
}

impl RLPDecode for AccountInfo {
    fn decode_unfinished(rlp: &[u8]) -> Result<(AccountInfo, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (code_hash, decoder) = decoder.decode_field("code_hash")?;
        let (balance, decoder) = decoder.decode_field("balance")?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let account_info = AccountInfo {
            code_hash,
            balance,
            nonce,
        };
        Ok((account_info, decoder.finish()?))
    }
}

impl RLPEncode for AccountState {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.nonce)
            .encode_field(&self.balance)
            .encode_field(&self.storage_root)
            .encode_field(&self.code_hash)
            .finish();
    }
}

impl RLPDecode for AccountState {
    fn decode_unfinished(rlp: &[u8]) -> Result<(AccountState, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let (balance, decoder) = decoder.decode_field("balance")?;
        let (storage_root, decoder) = decoder.decode_field("storage_root")?;
        let (code_hash, decoder) = decoder.decode_field("code_hash")?;
        let state = AccountState {
            nonce,
            balance,
            storage_root,
            code_hash,
        };
        Ok((state, decoder.finish()?))
    }
}

impl RLPEncode for AccountStateSlimCodec {
    fn encode(&self, buf: &mut Vec<u8>) {
        struct StorageRootCodec<'a>(&'a H256);
        impl RLPEncode for StorageRootCodec<'_> {
            fn encode(&self, buf: &mut Vec<u8>) {
                let data = if *self.0 != *EMPTY_TRIE_HASH {
                    self.0.as_bytes()
                } else {
                    &[]
                };

                data.encode(buf);
            }
        }

        struct CodeHashCodec<'a>(&'a H256);
        impl RLPEncode for CodeHashCodec<'_> {
            fn encode(&self, buf: &mut Vec<u8>) {
                let data = if *self.0 != *EMPTY_KECCAK_HASH {
                    self.0.as_bytes()
                } else {
                    &[]
                };

                data.encode(buf);
            }
        }

        Encoder::new(buf)
            .encode_field(&self.0.nonce)
            .encode_field(&self.0.balance)
            .encode_field(&StorageRootCodec(&self.0.storage_root))
            .encode_field(&CodeHashCodec(&self.0.code_hash))
            .finish();
    }
}

impl RLPDecode for AccountStateSlimCodec {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        struct StorageRootCodec(H256);
        impl RLPDecode for StorageRootCodec {
            fn decode_unfinished(mut rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
                let value = match rlp.split_off_first() {
                    Some(0x80) => *EMPTY_TRIE_HASH,
                    Some(0xA0) => {
                        let data;
                        (data, rlp) = rlp
                            .split_first_chunk::<32>()
                            .ok_or(RLPDecodeError::InvalidLength)?;
                        H256(*data)
                    }
                    _ => return Err(RLPDecodeError::InvalidLength),
                };

                Ok((Self(value), rlp))
            }
        }

        struct CodeHashCodec(H256);
        impl RLPDecode for CodeHashCodec {
            fn decode_unfinished(mut rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
                let value = match rlp.split_off_first() {
                    Some(0x80) => *EMPTY_KECCAK_HASH,
                    Some(0xA0) => {
                        let data;
                        (data, rlp) = rlp
                            .split_first_chunk::<32>()
                            .ok_or(RLPDecodeError::InvalidLength)?;
                        H256(*data)
                    }
                    _ => return Err(RLPDecodeError::InvalidLength),
                };

                Ok((Self(value), rlp))
            }
        }

        let decoder = Decoder::new(rlp)?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let (balance, decoder) = decoder.decode_field("balance")?;
        let (StorageRootCodec(storage_root), decoder) = decoder.decode_field("storage_root")?;
        let (CodeHashCodec(code_hash), decoder) = decoder.decode_field("code_hash")?;

        Ok((
            Self(AccountState {
                nonce,
                balance,
                storage_root,
                code_hash,
            }),
            decoder.finish()?,
        ))
    }
}

pub fn compute_storage_root(storage: &BTreeMap<U256, U256>, crypto: &dyn Crypto) -> H256 {
    let iter = storage.iter().filter_map(|(k, v)| {
        (!v.is_zero()).then_some((
            crypto.keccak256(&k.to_big_endian()).to_vec(),
            v.encode_to_vec(),
        ))
    });
    Trie::compute_hash_from_unsorted_iter(iter, crypto)
}

impl From<&GenesisAccount> for AccountState {
    fn from(value: &GenesisAccount) -> Self {
        AccountState {
            nonce: value.nonce,
            balance: value.balance,
            storage_root: compute_storage_root(&value.storage, &NativeCrypto),
            code_hash: code_hash(&value.code, &NativeCrypto),
        }
    }
}

impl Account {
    pub fn new(balance: U256, code: Code, nonce: u64, storage: FxHashMap<H256, U256>) -> Self {
        Self {
            info: AccountInfo {
                balance,
                code_hash: code.hash,
                nonce,
            },
            code,
            storage,
        }
    }
}

impl AccountInfo {
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.code_hash == *EMPTY_KECCAK_HASH
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    // Pre-bitmap on-wire layout of `Code`: `{hash, code, jump_targets}`. `AccountUpdate`
    // embeds `Code` and is persisted with bincode (positional) in the L2 rollup store,
    // so a row written before the bitmap change carries a non-empty `jump_targets`.
    #[derive(serde::Serialize)]
    struct OldCodeSerde {
        hash: H256,
        code: Bytes,
        jump_targets: Vec<u32>,
    }

    // `Code` is never persisted alone — it sits inside `AccountUpdate`, which has fields
    // AFTER `code`. These wrappers mirror that: a field following the code. A standalone
    // `Code` would tolerate trailing bytes, hiding the bug; only an embedded field
    // exposes the positional shift.
    #[derive(serde::Serialize)]
    struct OldWrap {
        code: OldCodeSerde,
        tail: u64,
    }
    #[derive(serde::Deserialize)]
    struct NewWrap {
        code: Code,
        tail: u64,
    }

    // A row serialized under the old three-field layout must still decode with the field
    // following `code` intact: the current `Code` deserializer reads and discards
    // `jump_targets`, keeping the layout aligned. Without the retained field, bincode
    // reads `tail` from the `jump_targets` bytes and every following field is corrupt —
    // exactly the `store_account_updates_by_block_number` break.
    #[test]
    fn embedded_code_decodes_an_old_layout_bincode_row() {
        // PUSH1 0x00 JUMPDEST STOP — offset 2 is a real JUMPDEST, offset 1 a PUSH immediate.
        let bytecode = Bytes::from(vec![0x60, 0x00, 0x5b, 0x00]);
        let hash = H256::from_low_u64_be(0xabc);
        const SENTINEL: u64 = 0x0123_4567_89ab_cdef;
        let old = OldWrap {
            code: OldCodeSerde {
                hash,
                code: bytecode.clone(),
                jump_targets: vec![2], // non-empty, as an old row would hold
            },
            tail: SENTINEL,
        };
        let bytes = bincode::serialize(&old).expect("serialize old layout");

        let decoded: NewWrap = bincode::deserialize(&bytes).expect("decode old row under new Code");
        assert_eq!(decoded.code.hash, hash);
        assert_eq!(decoded.code.code_bytes(), bytecode);
        // The field after `code` must survive — this is what breaks if the layout shifts.
        assert_eq!(
            decoded.tail, SENTINEL,
            "field after Code corrupted by layout shift"
        );
        // Jump destinations recomputed from code, not read from the row.
        assert!(decoded.code.is_valid_jumpdest(2));
        assert!(!decoded.code.is_valid_jumpdest(1));
    }

    #[test]
    fn test_code_hash() {
        let empty_code = Bytes::new();
        let hash = code_hash(&empty_code, &NativeCrypto);
        assert_eq!(
            hash,
            H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
        )
    }

    #[test]
    fn test_is_eip7702_delegation_valid() {
        // 0xef0100 || 20-byte address
        let mut code = Vec::with_capacity(23);
        code.extend_from_slice(&EIP7702_DELEGATION_PREFIX);
        code.extend_from_slice(&[0x42; 20]);
        assert!(is_eip7702_delegation(&code));
    }

    #[test]
    fn test_is_eip7702_delegation_rejects_empty() {
        assert!(!is_eip7702_delegation(&[]));
    }

    #[test]
    fn test_is_eip7702_delegation_rejects_short() {
        // Prefix only, no address.
        assert!(!is_eip7702_delegation(&EIP7702_DELEGATION_PREFIX));
    }

    #[test]
    fn test_is_eip7702_delegation_rejects_long() {
        // Correct prefix but 24 bytes total.
        let mut code = Vec::with_capacity(24);
        code.extend_from_slice(&EIP7702_DELEGATION_PREFIX);
        code.extend_from_slice(&[0x42; 21]);
        assert!(!is_eip7702_delegation(&code));
    }

    #[test]
    fn test_is_eip7702_delegation_rejects_wrong_prefix() {
        // Right length, wrong magic.
        let mut code = Vec::with_capacity(23);
        code.extend_from_slice(&[0xef, 0x01, 0x01]); // off by one in the last prefix byte
        code.extend_from_slice(&[0x42; 20]);
        assert!(!is_eip7702_delegation(&code));
    }

    #[test]
    fn test_is_eip7702_delegation_rejects_arbitrary_contract_code() {
        // Real contract code starting with anything else.
        let code = vec![0x60, 0x60, 0x60, 0x40, 0x52 /* ... */];
        assert!(!is_eip7702_delegation(&code));
    }
}
