use std::{
    cmp::min,
    fmt::Display,
    num::NonZeroUsize,
    sync::{LazyLock, Mutex},
};

use crate::utils::keccak;
use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use ethrex_crypto::{Crypto, CryptoError, NativeCrypto};
use lru::LruCache;
pub use mempool::MempoolTransaction;

const MAX_SIGNER_CACHE_ENTRIES: usize = 100_000;

/// Global cache mapping transaction hash → recovered sender address.
/// Keyed by tx hash (unique per transaction), so each entry is safe to reuse.
/// Not suitable for EIP-7702 authorization tuples where the same message hash
/// can correspond to different signers (the message excludes the signature).
/// Uses LRU eviction to avoid periodic cold-start spikes from clearing all entries.
///
/// Lock with `.unwrap_or_else(|e| e.into_inner())` — a poisoned mutex just means
/// a thread panicked mid-update; the LruCache invariants are maintained by the
/// std Mutex (data is still accessible), and a missing entry only costs one
/// redundant recovery, so it's safe to keep using.
pub static GLOBAL_SIGNER_CACHE: LazyLock<Mutex<LruCache<H256, Address>>> = LazyLock::new(|| {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(MAX_SIGNER_CACHE_ENTRIES).expect("MAX_SIGNER_CACHE_ENTRIES is non-zero"),
    ))
});
use rkyv::{Archive, Deserialize as RDeserialize, Serialize as RSerialize};
use serde::{Serialize, ser::SerializeStruct};
pub use serde_impl::{
    AccessListEntry, AuthorizationTupleEntry, FrameEntry, GenericTransaction,
    GenericTransactionError,
};

/// The serialized length of a default eip1559 transaction
pub const EIP1559_DEFAULT_SERIALIZED_LENGTH: usize = 15;

use ethrex_rlp::{
    constants::RLP_NULL,
    decode::{RLPDecode, decode_bytes, decode_rlp_item},
    encode::{PayloadRLPEncode, RLPEncode},
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

#[cfg(all(feature = "zisk", target_arch = "riscv64"))]
use super::unsync_cell::OnceCell;
use crate::types::{
    AccessList, AuthorizationList, BlobsBundle, constants::VERSIONED_HASH_VERSION_KZG,
};
#[cfg(not(all(feature = "zisk", target_arch = "riscv64")))]
use once_cell::sync::OnceCell;

// The `#[serde(untagged)]` attribute allows the `Transaction` enum to be serialized without
// a tag indicating the variant type. This means that Serde will serialize the enum's variants
// directly according to the structure of the variant itself.
// For each variant, Serde will use the serialization logic implemented
// for the inner type of that variant (like `LegacyTransaction`, `EIP2930Transaction`, etc.).
// The serialization will fail if the data does not match the structure of any variant.
//
// A custom Deserialization method is implemented to match the specific transaction `type`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, RSerialize, RDeserialize, Archive)]
#[serde(untagged)]
pub enum Transaction {
    LegacyTransaction(LegacyTransaction),
    EIP2930Transaction(EIP2930Transaction),
    EIP1559Transaction(EIP1559Transaction),
    EIP4844Transaction(EIP4844Transaction),
    EIP7702Transaction(EIP7702Transaction),
    PrivilegedL2Transaction(PrivilegedL2Transaction),
    FeeTokenTransaction(FeeTokenTransaction),
    FrameTransaction(FrameTransaction),
}

/// The same as a Transaction enum, only that blob transactions are in wrapped format, including
/// the blobs bundle.
/// PrivilegedL2Transaction is not included as it is not expected to be sent over P2P.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2PTransaction {
    LegacyTransaction(LegacyTransaction),
    EIP2930Transaction(EIP2930Transaction),
    EIP1559Transaction(EIP1559Transaction),
    EIP4844TransactionWithBlobs(WrappedEIP4844Transaction),
    EIP7702Transaction(EIP7702Transaction),
    FeeTokenTransaction(FeeTokenTransaction),
    FrameTransaction(FrameTransaction),
}

impl TryInto<Transaction> for P2PTransaction {
    type Error = String;

    fn try_into(self) -> Result<Transaction, Self::Error> {
        match self {
            P2PTransaction::LegacyTransaction(itx) => Ok(Transaction::LegacyTransaction(itx)),
            P2PTransaction::EIP2930Transaction(itx) => Ok(Transaction::EIP2930Transaction(itx)),
            P2PTransaction::EIP1559Transaction(itx) => Ok(Transaction::EIP1559Transaction(itx)),
            P2PTransaction::EIP7702Transaction(itx) => Ok(Transaction::EIP7702Transaction(itx)),
            P2PTransaction::FrameTransaction(itx) => Ok(Transaction::FrameTransaction(itx)),
            _ => Err("Can't convert blob p2p transaction into regular transaction. Blob bundle would be lost.".to_string()),
        }
    }
}

impl RLPEncode for P2PTransaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        match self {
            P2PTransaction::LegacyTransaction(t) => t.encode(buf),
            tx => <[u8] as RLPEncode>::encode(&tx.encode_canonical_to_vec(), buf),
        };
    }
}

impl RLPDecode for P2PTransaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let (is_list, payload, remainder) = decode_rlp_item(rlp)?;
        if !is_list {
            let tx_type = *payload.first().ok_or(RLPDecodeError::InvalidLength)?;
            let tx_encoding = payload.get(1..).ok_or(RLPDecodeError::InvalidLength)?;
            // `from_type_byte` is the single gate for valid envelope types: it rejects 0x00
            // (legacy is the bare-list branch below) and any unassigned type byte.
            let tx = match EnvelopeTxType::from_type_byte(tx_type)? {
                EnvelopeTxType::EIP2930 => {
                    P2PTransaction::EIP2930Transaction(EIP2930Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::EIP1559 => {
                    P2PTransaction::EIP1559Transaction(EIP1559Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::EIP4844 => P2PTransaction::EIP4844TransactionWithBlobs(
                    WrappedEIP4844Transaction::decode(tx_encoding)?,
                ),
                EnvelopeTxType::EIP7702 => {
                    P2PTransaction::EIP7702Transaction(EIP7702Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::Frame => {
                    P2PTransaction::FrameTransaction(FrameTransaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::FeeToken => {
                    P2PTransaction::FeeTokenTransaction(FeeTokenTransaction::decode(tx_encoding)?)
                }
                // Privileged (L2) transactions are never gossiped over p2p.
                EnvelopeTxType::Privileged => {
                    return Err(RLPDecodeError::Custom(
                        "privileged transactions are not sent over p2p".to_string(),
                    ));
                }
            };
            Ok((tx, remainder))
        } else {
            // LegacyTransaction
            LegacyTransaction::decode_unfinished(rlp)
                .map(|(tx, rem)| (P2PTransaction::LegacyTransaction(tx), rem))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedEIP4844Transaction {
    pub tx: EIP4844Transaction,
    pub wrapper_version: Option<u8>,
    pub blobs_bundle: BlobsBundle,
}

impl RLPEncode for WrappedEIP4844Transaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        let encoder = Encoder::new(buf);
        encoder
            .encode_field(&self.tx)
            .encode_optional_field(&self.wrapper_version)
            .encode_field(&self.blobs_bundle.blobs)
            .encode_field(&self.blobs_bundle.commitments)
            .encode_field(&self.blobs_bundle.proofs)
            .finish();
    }
}

impl RLPDecode for WrappedEIP4844Transaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(WrappedEIP4844Transaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let Ok((tx, decoder)) = decoder.decode_field("tx") else {
            // Handle the case of blobless transaction
            let (tx, rest) = EIP4844Transaction::decode_unfinished(rlp)?;
            return Ok((
                WrappedEIP4844Transaction {
                    tx,
                    wrapper_version: None,
                    // Empty blobs bundles are not valid
                    blobs_bundle: BlobsBundle::empty(),
                },
                rest,
            ));
        };

        let (wrapper_version, decoder) = decoder.decode_optional_field();
        let (blobs, decoder) = decoder.decode_field("blobs")?;
        let (commitments, decoder) = decoder.decode_field("commitments")?;
        let (proofs, decoder) = decoder.decode_field("proofs")?;

        let wrapped = WrappedEIP4844Transaction {
            tx,
            wrapper_version,
            blobs_bundle: BlobsBundle {
                blobs,
                commitments,
                proofs,
                version: wrapper_version.unwrap_or_default(),
            },
        };
        Ok((wrapped, decoder.finish()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct LegacyTransaction {
    pub nonce: u64,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub gas_price: U256,
    pub gas: u64,
    /// The recipient of the transaction.
    /// Create transactions contain a [`null`](RLP_NULL) value in this field.
    pub to: TxKind,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub v: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub r: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub s: U256,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct EIP2930Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub gas_price: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::AccessListItemWrapper>)]
    pub access_list: AccessList,
    pub signature_y_parity: bool,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_r: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_s: U256,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct EIP1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    pub to: TxKind,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::AccessListItemWrapper>)]
    pub access_list: AccessList,
    pub signature_y_parity: bool,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_r: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_s: U256,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct EIP4844Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    pub gas: u64,
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    pub to: Address,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::AccessListItemWrapper>)]
    pub access_list: AccessList,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub max_fee_per_blob_gas: U256,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::H256Wrapper>)]
    pub blob_versioned_hashes: Vec<H256>,
    pub signature_y_parity: bool,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_r: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_s: U256,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct EIP7702Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    pub to: Address,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::AccessListItemWrapper>)]
    pub access_list: AccessList,
    pub authorization_list: AuthorizationList,
    pub signature_y_parity: bool,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_r: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_s: U256,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct PrivilegedL2Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    pub to: TxKind,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::AccessListItemWrapper>)]
    pub access_list: AccessList,
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    pub from: Address,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TxType {
    #[default]
    Legacy = 0x00,
    EIP2930 = 0x01,
    EIP1559 = 0x02,
    EIP4844 = 0x03,
    EIP7702 = 0x04,
    Frame = 0x06,
    FeeToken = 0x7d,
    // We take the same approach as Optimism to define the privileged tx prefix
    // https://github.com/ethereum-optimism/specs/blob/c6903a3b2cad575653e1f5ef472debb573d83805/specs/protocol/deposits.md#the-deposited-transaction-type
    Privileged = 0x7e,
}

/// The EIP-2718 typed-transaction **envelope** types — the subset of [`TxType`] that
/// can be encoded as a `0x{type} || payload` envelope. Excludes [`TxType::Legacy`]:
/// a legacy transaction is a bare RLP list, never a typed envelope. Decoders that
/// dispatch on the leading type byte match this exhaustively, so there is no
/// impossible `Legacy` arm to handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeTxType {
    EIP2930,
    EIP1559,
    EIP4844,
    EIP7702,
    Frame,
    FeeToken,
    Privileged,
}

impl EnvelopeTxType {
    /// Resolve a typed-transaction **envelope** type byte (EIP-2718) to its type.
    ///
    /// Reuses [`TxType::from_u8`] for the byte mapping (single source of truth) and
    /// [`TxType::as_envelope`] to reject non-envelope types. **Rejects `0x00`**: per EIP-2718
    /// a legacy transaction is a bare RLP list, never a `0x00`-typed envelope, so
    /// `0x00 || rlp(..)` is non-canonical and must be rejected (matching go-ethereum) rather
    /// than silently decoded as legacy. Unassigned type bytes are rejected too.
    pub fn from_type_byte(byte: u8) -> Result<Self, RLPDecodeError> {
        TxType::from_u8(byte)
            .and_then(TxType::as_envelope)
            .ok_or_else(|| RLPDecodeError::Custom(format!("Invalid transaction type: {byte}")))
    }
}

impl From<TxType> for u8 {
    fn from(val: TxType) -> Self {
        match val {
            TxType::Legacy => 0x00,
            TxType::EIP2930 => 0x01,
            TxType::EIP1559 => 0x02,
            TxType::EIP4844 => 0x03,
            TxType::EIP7702 => 0x04,
            TxType::Frame => 0x06,
            TxType::FeeToken => 0x7d,
            TxType::Privileged => 0x7e,
        }
    }
}

impl Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxType::Legacy => write!(f, "Legacy"),
            TxType::EIP2930 => write!(f, "EIP2930"),
            TxType::EIP1559 => write!(f, "EIP1559"),
            TxType::EIP4844 => write!(f, "EIP4844"),
            TxType::EIP7702 => write!(f, "EIP7702"),
            TxType::Frame => write!(f, "Frame"),
            TxType::Privileged => write!(f, "Privileged"),
            TxType::FeeToken => write!(f, "FeeToken"),
        }
    }
}

impl Transaction {
    pub fn tx_type(&self) -> TxType {
        match self {
            Transaction::LegacyTransaction(_) => TxType::Legacy,
            Transaction::EIP2930Transaction(_) => TxType::EIP2930,
            Transaction::EIP1559Transaction(_) => TxType::EIP1559,
            Transaction::EIP4844Transaction(_) => TxType::EIP4844,
            Transaction::EIP7702Transaction(_) => TxType::EIP7702,
            Transaction::FeeTokenTransaction(_) => TxType::FeeToken,
            Transaction::PrivilegedL2Transaction(_) => TxType::Privileged,
            Transaction::FrameTransaction(_) => TxType::Frame,
        }
    }

    fn calc_effective_gas_price(&self, base_fee_per_gas: Option<u64>) -> Option<U256> {
        let base_fee = U256::from(base_fee_per_gas?);
        let max_fee = self.max_fee_per_gas()?;
        if max_fee < base_fee {
            // This is invalid, can't calculate
            return None;
        }

        let priority_fee_per_gas = min(self.max_priority_fee()?, max_fee.saturating_sub(base_fee));
        Some(priority_fee_per_gas + base_fee)
    }

    pub fn effective_gas_price(&self, base_fee_per_gas: Option<u64>) -> Option<U256> {
        match self.tx_type() {
            TxType::Legacy => Some(self.gas_price()),
            TxType::EIP2930 => Some(self.gas_price()),
            TxType::EIP1559 => self.calc_effective_gas_price(base_fee_per_gas),
            TxType::EIP4844 => self.calc_effective_gas_price(base_fee_per_gas),
            TxType::EIP7702 => self.calc_effective_gas_price(base_fee_per_gas),
            TxType::Frame => self.calc_effective_gas_price(base_fee_per_gas),
            TxType::FeeToken => self.calc_effective_gas_price(base_fee_per_gas),
            TxType::Privileged => Some(self.gas_price()),
        }
    }

    pub fn cost_without_base_fee(&self) -> Option<U256> {
        let price = match self.tx_type() {
            TxType::Legacy => self.gas_price(),
            TxType::EIP2930 => self.gas_price(),
            TxType::EIP1559 => self.max_fee_per_gas()?,
            TxType::EIP4844 => self.max_fee_per_gas()?,
            TxType::EIP7702 => self.max_fee_per_gas()?,
            TxType::Frame => self.max_fee_per_gas()?,
            TxType::FeeToken => self.max_fee_per_gas()?,
            TxType::Privileged => self.gas_price(),
        };

        let base = U256::saturating_add(
            U256::saturating_mul(price, self.gas_limit().into()),
            self.value(),
        );

        // EIP-4844 blob txs pay an additional `blob_gas * max_fee_per_blob_gas`
        // upfront. Every peer client (geth, reth, nethermind, erigon, besu)
        // includes this in the balance-sufficiency check.
        if let Transaction::EIP4844Transaction(tx) = self {
            let blob_gas = U256::from(crate::constants::GAS_PER_BLOB)
                .saturating_mul(U256::from(tx.blob_versioned_hashes.len() as u64));
            let blob_cost = blob_gas.saturating_mul(tx.max_fee_per_blob_gas);
            return Some(base.saturating_add(blob_cost));
        }

        Some(base)
    }

    pub fn fee_token(&self) -> Option<Address> {
        if let Transaction::FeeTokenTransaction(tx) = self {
            Some(tx.fee_token)
        } else {
            None
        }
    }

    /// Returns a reference to the `cached_canonical` cell for non-legacy
    /// transaction types, or `None` for legacy transactions.
    fn cached_canonical_cell(&self) -> Option<&OnceCell<Vec<u8>>> {
        match self {
            Transaction::LegacyTransaction(_) => None,
            Transaction::EIP2930Transaction(t) => Some(&t.cached_canonical),
            Transaction::EIP1559Transaction(t) => Some(&t.cached_canonical),
            Transaction::EIP4844Transaction(t) => Some(&t.cached_canonical),
            Transaction::EIP7702Transaction(t) => Some(&t.cached_canonical),
            Transaction::PrivilegedL2Transaction(t) => Some(&t.cached_canonical),
            Transaction::FeeTokenTransaction(t) => Some(&t.cached_canonical),
            Transaction::FrameTransaction(t) => Some(&t.cached_canonical),
        }
    }
}

impl RLPEncode for Transaction {
    /// Transactions can be encoded in the following formats:
    /// A) Legacy transactions: rlp(LegacyTransaction)
    /// B) Non legacy transactions: rlp(Bytes) where Bytes represents the canonical encoding for the transaction as a bytes object.
    /// Checkout [Transaction::encode_canonical] for more information
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        match self {
            Transaction::LegacyTransaction(t) => t.encode(buf),
            _ => {
                let canonical = self.encode_canonical_to_vec();
                <[u8] as RLPEncode>::encode(canonical.as_slice(), buf)
            }
        };
    }
}

impl RLPDecode for Transaction {
    /// Transactions can be encoded in the following formats:
    /// A) Legacy transactions: rlp(LegacyTransaction)
    /// B) Non legacy transactions: rlp(Bytes) where Bytes represents the canonical encoding for the transaction as a bytes object.
    /// Checkout [Transaction::decode_canonical] for more information
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let (is_list, payload, remainder) = decode_rlp_item(rlp)?;
        if !is_list {
            let tx_type = *payload.first().ok_or(RLPDecodeError::InvalidLength)?;
            let tx_encoding = payload.get(1..).ok_or(RLPDecodeError::InvalidLength)?;
            // `from_type_byte` is the single gate for valid envelope types: it rejects 0x00
            // (a legacy tx is a bare RLP list, handled below, not a typed envelope) and any
            // unassigned type byte.
            let tx = match EnvelopeTxType::from_type_byte(tx_type)? {
                EnvelopeTxType::EIP2930 => {
                    Transaction::EIP2930Transaction(EIP2930Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::EIP1559 => {
                    Transaction::EIP1559Transaction(EIP1559Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::EIP4844 => {
                    Transaction::EIP4844Transaction(EIP4844Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::EIP7702 => {
                    Transaction::EIP7702Transaction(EIP7702Transaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::Frame => {
                    Transaction::FrameTransaction(FrameTransaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::FeeToken => {
                    Transaction::FeeTokenTransaction(FeeTokenTransaction::decode(tx_encoding)?)
                }
                EnvelopeTxType::Privileged => Transaction::PrivilegedL2Transaction(
                    PrivilegedL2Transaction::decode(tx_encoding)?,
                ),
            };
            Ok((tx, remainder))
        } else {
            // LegacyTransaction
            LegacyTransaction::decode_unfinished(rlp)
                .map(|(tx, rem)| (Transaction::LegacyTransaction(tx), rem))
        }
    }
}

/// The transaction's kind: call or create.
#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub enum TxKind {
    Call(#[rkyv(with=crate::rkyv_utils::H160Wrapper)] Address),
    #[default]
    Create,
}

impl RLPEncode for TxKind {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        match self {
            Self::Call(address) => address.encode(buf),
            Self::Create => buf.put_u8(RLP_NULL),
        }
    }
}

impl RLPDecode for TxKind {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let first_byte = rlp.first().ok_or(RLPDecodeError::InvalidLength)?;
        if *first_byte == RLP_NULL {
            return Ok((Self::Create, &rlp[1..]));
        }
        Address::decode_unfinished(rlp).map(|(t, rest)| (Self::Call(t), rest))
    }
}

impl RLPEncode for LegacyTransaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.nonce)
            .encode_field(&self.gas_price)
            .encode_field(&self.gas)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.v)
            .encode_field(&self.r)
            .encode_field(&self.s)
            .finish();
    }
}

impl RLPEncode for EIP2930Transaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.gas_price)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.signature_y_parity)
            .encode_field(&self.signature_r)
            .encode_field(&self.signature_s)
            .finish()
    }
}

impl RLPEncode for EIP1559Transaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.signature_y_parity)
            .encode_field(&self.signature_r)
            .encode_field(&self.signature_s)
            .finish()
    }
}

impl RLPEncode for EIP4844Transaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.max_fee_per_blob_gas)
            .encode_field(&self.blob_versioned_hashes)
            .encode_field(&self.signature_y_parity)
            .encode_field(&self.signature_r)
            .encode_field(&self.signature_s)
            .finish()
    }
}

impl RLPEncode for EIP7702Transaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.authorization_list)
            .encode_field(&self.signature_y_parity)
            .encode_field(&self.signature_r)
            .encode_field(&self.signature_s)
            .finish()
    }
}

impl RLPEncode for PrivilegedL2Transaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.from)
            .finish()
    }
}

impl RLPEncode for FeeTokenTransaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.fee_token)
            .encode_field(&self.signature_y_parity)
            .encode_field(&self.signature_r)
            .encode_field(&self.signature_s)
            .finish()
    }
}

impl PayloadRLPEncode for Transaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        match self {
            Transaction::LegacyTransaction(tx) => tx.encode_payload(buf),
            Transaction::EIP1559Transaction(tx) => tx.encode_payload(buf),
            Transaction::EIP2930Transaction(tx) => tx.encode_payload(buf),
            Transaction::EIP4844Transaction(tx) => tx.encode_payload(buf),
            Transaction::EIP7702Transaction(tx) => tx.encode_payload(buf),
            Transaction::PrivilegedL2Transaction(tx) => tx.encode_payload(buf),
            Transaction::FeeTokenTransaction(tx) => tx.encode_payload(buf),
            Transaction::FrameTransaction(tx) => tx.encode_payload(buf),
        }
    }
}

impl PayloadRLPEncode for LegacyTransaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.nonce)
            .encode_field(&self.gas_price)
            .encode_field(&self.gas)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .finish();
    }
}

impl PayloadRLPEncode for EIP1559Transaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .finish();
    }
}

impl PayloadRLPEncode for EIP2930Transaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.gas_price)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .finish();
    }
}

impl PayloadRLPEncode for EIP4844Transaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.max_fee_per_blob_gas)
            .encode_field(&self.blob_versioned_hashes)
            .finish();
    }
}

impl PayloadRLPEncode for EIP7702Transaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.authorization_list)
            .finish();
    }
}

impl PayloadRLPEncode for PrivilegedL2Transaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.from)
            .finish();
    }
}

impl PayloadRLPEncode for FeeTokenTransaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.gas_limit)
            .encode_field(&self.to)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .encode_field(&self.access_list)
            .encode_field(&self.fee_token)
            .finish();
    }
}

/// Decode a transaction `nonce` field.
///
/// EEST encodes an over-`u64` nonce (a value >= 2**64, i.e. more than 8
/// significant bytes) to exercise `TransactionException.NONCE_IS_MAX`. ethrex
/// represents the nonce as a `u64`, so a plain RLP decode fails with a generic
/// field-decode error that the EEST/Hive exception mapper classifies as
/// `RLP_STRUCTURES_ENCODING` instead of `NONCE_IS_MAX`. Detect the over-`u64`
/// case and surface a "Nonce is max" message so it maps to `NONCE_IS_MAX` in
/// both the upstream Python `ethrex.py` mapper and the local Rust mapper.
fn decode_nonce_field(decoder: Decoder) -> Result<(u64, Decoder), RLPDecodeError> {
    // Wrap every decode failure exactly as `Decoder::decode_field` would, so
    // non-overflow errors keep their original wording (and mapper classification);
    // only the intentional over-u64 case below diverges.
    let wrap =
        |err| RLPDecodeError::Custom(format!("Error decoding field 'nonce' of type u64: {err}"));
    let (item, rest) = decoder.get_encoded_item_ref().map_err(wrap)?;
    // A *canonical* over-u64 nonce (>= 2**64) has more than 8 significant bytes and,
    // being canonical, no leading zero byte. EEST uses it for
    // TransactionException.NONCE_IS_MAX; surface a nonce-domain rejection rather than
    // a generic RLP field-decode error so the exception mapper maps it to NONCE_IS_MAX
    // in both the upstream Python and local Rust mappers.
    //
    // A non-canonical >8-byte encoding (leading-zero padding) is a malformed RLP
    // integer, not an over-u64 value, so it must NOT be reported as NONCE_IS_MAX. Leave
    // it to fall through to `u64::decode_unfinished` below, which rejects it as an
    // ordinary field-decode error (mapped to RLP_STRUCTURES_ENCODING) — matching strict
    // mappers like Hive.
    if let Ok((content, _)) = decode_bytes(item)
        && content.len() > 8
        && content.first() != Some(&0)
    {
        return Err(RLPDecodeError::Custom("Nonce is max".into()));
    }
    let (nonce, _) = u64::decode_unfinished(item).map_err(wrap)?;
    Ok((nonce, rest))
}

impl RLPDecode for LegacyTransaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(LegacyTransaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (gas_price, decoder) = decoder.decode_field("gas_price")?;
        let (gas, decoder) = decoder.decode_field("gas")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (v, decoder) = decoder.decode_field("v")?;
        let (r, decoder) = decoder.decode_field("r")?;
        let (s, decoder) = decoder.decode_field("s")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();

        let tx = LegacyTransaction {
            nonce,
            gas_price,
            gas,
            to,
            value,
            data,
            v,
            r,
            s,
            inner_hash,
            sender_cache,
        };
        Ok((tx, decoder.finish()?))
    }
}

impl RLPDecode for EIP2930Transaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(EIP2930Transaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (gas_price, decoder) = decoder.decode_field("gas_price")?;
        let (gas_limit, decoder) = decoder.decode_field("gas_limit")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (access_list, decoder) = decoder.decode_field("access_list")?;
        let (signature_y_parity, decoder) = decoder.decode_field("signature_y_parity")?;
        let (signature_r, decoder) = decoder.decode_field("signature_r")?;
        let (signature_s, decoder) = decoder.decode_field("signature_s")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();
        let cached_canonical = OnceCell::new();

        let tx = EIP2930Transaction {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            access_list,
            signature_y_parity,
            signature_r,
            signature_s,
            inner_hash,
            sender_cache,
            cached_canonical,
        };
        Ok((tx, decoder.finish()?))
    }
}

impl RLPDecode for EIP1559Transaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(EIP1559Transaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (max_priority_fee_per_gas, decoder) =
            decoder.decode_field("max_priority_fee_per_gas")?;
        let (max_fee_per_gas, decoder) = decoder.decode_field("max_fee_per_gas")?;
        let (gas_limit, decoder) = decoder.decode_field("gas_limit")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (access_list, decoder) = decoder.decode_field("access_list")?;
        let (signature_y_parity, decoder) = decoder.decode_field("signature_y_parity")?;
        let (signature_r, decoder) = decoder.decode_field("signature_r")?;
        let (signature_s, decoder) = decoder.decode_field("signature_s")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();
        let cached_canonical = OnceCell::new();

        let tx = EIP1559Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            signature_y_parity,
            signature_r,
            signature_s,
            inner_hash,
            sender_cache,
            cached_canonical,
        };
        Ok((tx, decoder.finish()?))
    }
}

impl RLPDecode for EIP4844Transaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(EIP4844Transaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (max_priority_fee_per_gas, decoder) =
            decoder.decode_field("max_priority_fee_per_gas")?;
        let (max_fee_per_gas, decoder) = decoder.decode_field("max_fee_per_gas")?;
        let (gas, decoder) = decoder.decode_field("gas")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (access_list, decoder) = decoder.decode_field("access_list")?;
        let (max_fee_per_blob_gas, decoder) = decoder.decode_field("max_fee_per_blob_gas")?;
        let (blob_versioned_hashes, decoder) = decoder.decode_field("blob_versioned_hashes")?;
        let (signature_y_parity, decoder) = decoder.decode_field("signature_y_parity")?;
        let (signature_r, decoder) = decoder.decode_field("signature_r")?;
        let (signature_s, decoder) = decoder.decode_field("signature_s")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();
        let cached_canonical = OnceCell::new();

        let tx = EIP4844Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas,
            to,
            value,
            data,
            access_list,
            max_fee_per_blob_gas,
            blob_versioned_hashes,
            signature_y_parity,
            signature_r,
            signature_s,
            inner_hash,
            sender_cache,
            cached_canonical,
        };
        Ok((tx, decoder.finish()?))
    }
}

impl RLPDecode for EIP7702Transaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(EIP7702Transaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (max_priority_fee_per_gas, decoder) =
            decoder.decode_field("max_priority_fee_per_gas")?;
        let (max_fee_per_gas, decoder) = decoder.decode_field("max_fee_per_gas")?;
        let (gas_limit, decoder) = decoder.decode_field("gas_limit")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (access_list, decoder) = decoder.decode_field("access_list")?;
        let (authorization_list, decoder) = decoder.decode_field("authorization_list")?;
        let (signature_y_parity, decoder) = decoder.decode_field("signature_y_parity")?;
        let (signature_r, decoder) = decoder.decode_field("signature_r")?;
        let (signature_s, decoder) = decoder.decode_field("signature_s")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();
        let cached_canonical = OnceCell::new();

        let tx = EIP7702Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            authorization_list,
            signature_y_parity,
            signature_r,
            signature_s,
            inner_hash,
            sender_cache,
            cached_canonical,
        };
        Ok((tx, decoder.finish()?))
    }
}

impl RLPDecode for PrivilegedL2Transaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(PrivilegedL2Transaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (max_priority_fee_per_gas, decoder) =
            decoder.decode_field("max_priority_fee_per_gas")?;
        let (max_fee_per_gas, decoder) = decoder.decode_field("max_fee_per_gas")?;
        let (gas_limit, decoder) = decoder.decode_field::<u64>("gas_limit")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (access_list, decoder) = decoder.decode_field("access_list")?;
        let (from, decoder) = decoder.decode_field("from")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();
        let cached_canonical = OnceCell::new();

        let tx = PrivilegedL2Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            from,
            inner_hash,
            sender_cache,
            cached_canonical,
        };
        Ok((tx, decoder.finish()?))
    }
}

impl RLPDecode for FeeTokenTransaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(FeeTokenTransaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (max_priority_fee_per_gas, decoder) =
            decoder.decode_field("max_priority_fee_per_gas")?;
        let (max_fee_per_gas, decoder) = decoder.decode_field("max_fee_per_gas")?;
        let (gas_limit, decoder) = decoder.decode_field("gas_limit")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let (access_list, decoder) = decoder.decode_field("access_list")?;
        let (fee_token, decoder) = decoder.decode_field("fee_token")?;
        let (signature_y_parity, decoder) = decoder.decode_field("signature_y_parity")?;
        let (signature_r, decoder) = decoder.decode_field("signature_r")?;
        let (signature_s, decoder) = decoder.decode_field("signature_s")?;
        let inner_hash = OnceCell::new();
        let sender_cache = OnceCell::new();
        let cached_canonical = OnceCell::new();

        let tx = FeeTokenTransaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            fee_token,
            signature_y_parity,
            signature_r,
            signature_s,
            inner_hash,
            sender_cache,
            cached_canonical,
        };
        Ok((tx, decoder.finish()?))
    }
}

/// The bytes a transaction's signature covers, paired with the 65-byte
/// `r || s || v` signature itself. See [`Transaction::signing_payload`].
pub type SigningPayload = (Vec<u8>, [u8; 65]);

impl Transaction {
    pub fn sender(&self, crypto: &dyn Crypto) -> Result<Address, CryptoError> {
        // Frame transactions have explicit sender, no ECDSA recovery
        if let Transaction::FrameTransaction(tx) = self {
            return Ok(tx.sender);
        }
        let sender_cache = match self {
            Transaction::LegacyTransaction(tx) => &tx.sender_cache,
            Transaction::EIP2930Transaction(tx) => &tx.sender_cache,
            Transaction::EIP1559Transaction(tx) => &tx.sender_cache,
            Transaction::EIP4844Transaction(tx) => &tx.sender_cache,
            Transaction::EIP7702Transaction(tx) => &tx.sender_cache,
            Transaction::PrivilegedL2Transaction(tx) => &tx.sender_cache,
            Transaction::FeeTokenTransaction(tx) => &tx.sender_cache,
            Transaction::FrameTransaction(_) => unreachable!(),
        };
        sender_cache
            .get_or_try_init(|| {
                let tx_hash = self.hash(crypto);
                // Fast path: check process-level signer cache
                let mut cache = GLOBAL_SIGNER_CACHE
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(&addr) = cache.get(&tx_hash) {
                    return Ok(addr);
                }
                drop(cache);
                // Slow path: actual secp256k1 recovery
                let sender = self.compute_sender(crypto)?;
                // Store in global cache for future lookups (LRU evicts oldest on overflow)
                GLOBAL_SIGNER_CACHE
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .put(tx_hash, sender);
                Ok(sender)
            })
            .copied()
    }

    /// The bytes that were signed, plus the 65-byte `r || s || v` signature.
    ///
    /// `Ok(None)` for transactions that carry an explicit sender and no signature
    /// (privileged L2 and frame), for which there is nothing to recover.
    ///
    /// Exposed so callers needing the *public key* rather than the address can
    /// reuse this logic: the per-variant EIP-155 and typed-transaction handling
    /// below is subtle and must exist in exactly one place.
    pub fn signing_payload(&self) -> Result<Option<SigningPayload>, CryptoError> {
        let (buf, sig) = match self {
            Transaction::LegacyTransaction(tx) => {
                let v = u64::try_from(tx.v).map_err(|_| CryptoError::InvalidSignature)?;
                // EIP-155: valid legacy `v` is 27/28 (pre-155) or
                // {35,36} + chain_id * 2. Any other value is a malformed
                // signature and must be rejected rather than coerced into a
                // parity bit (which would recover a bogus sender).
                let signature_y_parity = match self.chain_id() {
                    Some(chain_id) => match v.checked_sub(35 + chain_id * 2) {
                        Some(0) => false,
                        Some(1) => true,
                        _ => return Err(CryptoError::InvalidSignature),
                    },
                    None => match v {
                        27 => false,
                        28 => true,
                        _ => return Err(CryptoError::InvalidSignature),
                    },
                };
                let mut buf = vec![];
                match self.chain_id() {
                    None => Encoder::new(&mut buf)
                        .encode_field(&tx.nonce)
                        .encode_field(&tx.gas_price)
                        .encode_field(&tx.gas)
                        .encode_field(&tx.to)
                        .encode_field(&tx.value)
                        .encode_field(&tx.data)
                        .finish(),
                    Some(chain_id) => Encoder::new(&mut buf)
                        .encode_field(&tx.nonce)
                        .encode_field(&tx.gas_price)
                        .encode_field(&tx.gas)
                        .encode_field(&tx.to)
                        .encode_field(&tx.value)
                        .encode_field(&tx.data)
                        .encode_field(&chain_id)
                        .encode_field(&0u8)
                        .encode_field(&0u8)
                        .finish(),
                }
                let mut sig = [0u8; 65];
                sig[..32].copy_from_slice(&tx.r.to_big_endian());
                sig[32..64].copy_from_slice(&tx.s.to_big_endian());
                sig[64] = signature_y_parity as u8;
                (buf, sig)
            }
            Transaction::EIP2930Transaction(tx) => {
                let mut buf = vec![self.tx_type() as u8];
                Encoder::new(&mut buf)
                    .encode_field(&tx.chain_id)
                    .encode_field(&tx.nonce)
                    .encode_field(&tx.gas_price)
                    .encode_field(&tx.gas_limit)
                    .encode_field(&tx.to)
                    .encode_field(&tx.value)
                    .encode_field(&tx.data)
                    .encode_field(&tx.access_list)
                    .finish();
                let mut sig = [0u8; 65];
                sig[..32].copy_from_slice(&tx.signature_r.to_big_endian());
                sig[32..64].copy_from_slice(&tx.signature_s.to_big_endian());
                sig[64] = tx.signature_y_parity as u8;
                (buf, sig)
            }
            Transaction::EIP1559Transaction(tx) => {
                let mut buf = vec![self.tx_type() as u8];
                Encoder::new(&mut buf)
                    .encode_field(&tx.chain_id)
                    .encode_field(&tx.nonce)
                    .encode_field(&tx.max_priority_fee_per_gas)
                    .encode_field(&tx.max_fee_per_gas)
                    .encode_field(&tx.gas_limit)
                    .encode_field(&tx.to)
                    .encode_field(&tx.value)
                    .encode_field(&tx.data)
                    .encode_field(&tx.access_list)
                    .finish();
                let mut sig = [0u8; 65];
                sig[..32].copy_from_slice(&tx.signature_r.to_big_endian());
                sig[32..64].copy_from_slice(&tx.signature_s.to_big_endian());
                sig[64] = tx.signature_y_parity as u8;
                (buf, sig)
            }
            Transaction::EIP4844Transaction(tx) => {
                let mut buf = vec![self.tx_type() as u8];
                Encoder::new(&mut buf)
                    .encode_field(&tx.chain_id)
                    .encode_field(&tx.nonce)
                    .encode_field(&tx.max_priority_fee_per_gas)
                    .encode_field(&tx.max_fee_per_gas)
                    .encode_field(&tx.gas)
                    .encode_field(&tx.to)
                    .encode_field(&tx.value)
                    .encode_field(&tx.data)
                    .encode_field(&tx.access_list)
                    .encode_field(&tx.max_fee_per_blob_gas)
                    .encode_field(&tx.blob_versioned_hashes)
                    .finish();
                let mut sig = [0u8; 65];
                sig[..32].copy_from_slice(&tx.signature_r.to_big_endian());
                sig[32..64].copy_from_slice(&tx.signature_s.to_big_endian());
                sig[64] = tx.signature_y_parity as u8;
                (buf, sig)
            }
            Transaction::EIP7702Transaction(tx) => {
                let mut buf = vec![self.tx_type() as u8];
                Encoder::new(&mut buf)
                    .encode_field(&tx.chain_id)
                    .encode_field(&tx.nonce)
                    .encode_field(&tx.max_priority_fee_per_gas)
                    .encode_field(&tx.max_fee_per_gas)
                    .encode_field(&tx.gas_limit)
                    .encode_field(&tx.to)
                    .encode_field(&tx.value)
                    .encode_field(&tx.data)
                    .encode_field(&tx.access_list)
                    .encode_field(&tx.authorization_list)
                    .finish();
                let mut sig = [0u8; 65];
                sig[..32].copy_from_slice(&tx.signature_r.to_big_endian());
                sig[32..64].copy_from_slice(&tx.signature_s.to_big_endian());
                sig[64] = tx.signature_y_parity as u8;
                (buf, sig)
            }
            // Explicit sender, no signature: nothing to recover from.
            Transaction::PrivilegedL2Transaction(_) | Transaction::FrameTransaction(_) => {
                return Ok(None);
            }
            Transaction::FeeTokenTransaction(tx) => {
                let mut buf = vec![self.tx_type() as u8];
                Encoder::new(&mut buf)
                    .encode_field(&tx.chain_id)
                    .encode_field(&tx.nonce)
                    .encode_field(&tx.max_priority_fee_per_gas)
                    .encode_field(&tx.max_fee_per_gas)
                    .encode_field(&tx.gas_limit)
                    .encode_field(&tx.to)
                    .encode_field(&tx.value)
                    .encode_field(&tx.data)
                    .encode_field(&tx.access_list)
                    .encode_field(&tx.fee_token)
                    .finish();
                let mut sig = [0u8; 65];
                sig[..32].copy_from_slice(&tx.signature_r.to_big_endian());
                sig[32..64].copy_from_slice(&tx.signature_s.to_big_endian());
                sig[64] = tx.signature_y_parity as u8;
                (buf, sig)
            }
        };
        Ok(Some((buf, sig)))
    }

    fn compute_sender(&self, crypto: &dyn Crypto) -> Result<Address, CryptoError> {
        match self {
            Transaction::PrivilegedL2Transaction(tx) => return Ok(tx.from),
            Transaction::FrameTransaction(tx) => return Ok(tx.sender),
            _ => {}
        }
        let Some((buf, sig)) = self.signing_payload()? else {
            // Unreachable: the two signature-less variants are handled above.
            return Err(CryptoError::InvalidSignature);
        };
        let msg = crypto.keccak256(&buf);
        crypto.recover_signer(&sig, &msg)
    }

    /// The signer's uncompressed secp256k1 public key (`0x04 || X || Y`).
    ///
    /// `Ok(None)` for privileged L2 and frame transactions, which carry an explicit
    /// sender and no signature. Used to populate
    /// `SszStatelessInput::public_keys`, which the stateless guest checks against
    /// each transaction's recovered sender.
    #[cfg(feature = "secp256k1")]
    pub fn public_key(&self, crypto: &dyn Crypto) -> Result<Option<[u8; 65]>, CryptoError> {
        let Some((buf, sig)) = self.signing_payload()? else {
            return Ok(None);
        };
        let msg = crypto.keccak256(&buf);
        crypto.recover_public_key(&sig, &msg).map(Some)
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            Transaction::LegacyTransaction(tx) => tx.gas,
            Transaction::EIP2930Transaction(tx) => tx.gas_limit,
            Transaction::EIP1559Transaction(tx) => tx.gas_limit,
            Transaction::EIP7702Transaction(tx) => tx.gas_limit,
            Transaction::EIP4844Transaction(tx) => tx.gas,
            Transaction::PrivilegedL2Transaction(tx) => tx.gas_limit,
            Transaction::FeeTokenTransaction(tx) => tx.gas_limit,
            Transaction::FrameTransaction(tx) => tx.max_gas(),
        }
    }

    //TODO: It's not very correct to return gas price for legacy and eip-2930 txs but return the max fee per gas for the others, make necessary changes for it to be technically correct.
    pub fn gas_price(&self) -> U256 {
        match self {
            Transaction::LegacyTransaction(tx) => tx.gas_price,
            Transaction::EIP2930Transaction(tx) => tx.gas_price,
            Transaction::EIP1559Transaction(tx) => U256::from(tx.max_fee_per_gas),
            Transaction::EIP7702Transaction(tx) => U256::from(tx.max_fee_per_gas),
            Transaction::EIP4844Transaction(tx) => U256::from(tx.max_fee_per_gas),
            Transaction::PrivilegedL2Transaction(tx) => U256::from(tx.max_fee_per_gas),
            Transaction::FeeTokenTransaction(tx) => U256::from(tx.max_fee_per_gas),
            Transaction::FrameTransaction(tx) => tx.max_fee_per_gas,
        }
    }

    pub fn to(&self) -> TxKind {
        match self {
            Transaction::LegacyTransaction(tx) => tx.to.clone(),
            Transaction::EIP2930Transaction(tx) => tx.to.clone(),
            Transaction::EIP1559Transaction(tx) => tx.to.clone(),
            Transaction::EIP4844Transaction(tx) => TxKind::Call(tx.to),
            Transaction::EIP7702Transaction(tx) => TxKind::Call(tx.to),
            Transaction::PrivilegedL2Transaction(tx) => tx.to.clone(),
            Transaction::FeeTokenTransaction(tx) => tx.to.clone(),
            Transaction::FrameTransaction(tx) => TxKind::Call(tx.sender),
        }
    }

    pub fn value(&self) -> U256 {
        match self {
            Transaction::LegacyTransaction(tx) => tx.value,
            Transaction::EIP2930Transaction(tx) => tx.value,
            Transaction::EIP1559Transaction(tx) => tx.value,
            Transaction::EIP4844Transaction(tx) => tx.value,
            Transaction::EIP7702Transaction(tx) => tx.value,
            Transaction::PrivilegedL2Transaction(tx) => tx.value,
            Transaction::FeeTokenTransaction(tx) => tx.value,
            Transaction::FrameTransaction(_) => U256::zero(),
        }
    }

    /// Widened to `U256` for the same reason as [`Self::max_fee_per_gas`].
    pub fn max_priority_fee(&self) -> Option<U256> {
        match self {
            Transaction::LegacyTransaction(_tx) => None,
            Transaction::EIP2930Transaction(_tx) => None,
            Transaction::EIP1559Transaction(tx) => Some(U256::from(tx.max_priority_fee_per_gas)),
            Transaction::EIP4844Transaction(tx) => Some(U256::from(tx.max_priority_fee_per_gas)),
            Transaction::EIP7702Transaction(tx) => Some(U256::from(tx.max_priority_fee_per_gas)),
            Transaction::PrivilegedL2Transaction(tx) => {
                Some(U256::from(tx.max_priority_fee_per_gas))
            }
            Transaction::FeeTokenTransaction(tx) => Some(U256::from(tx.max_priority_fee_per_gas)),
            Transaction::FrameTransaction(tx) => Some(tx.max_priority_fee_per_gas),
        }
    }

    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Transaction::LegacyTransaction(tx) => derive_legacy_chain_id(tx.v),
            Transaction::EIP2930Transaction(tx) => Some(tx.chain_id),
            Transaction::EIP1559Transaction(tx) => Some(tx.chain_id),
            Transaction::EIP4844Transaction(tx) => Some(tx.chain_id),
            Transaction::EIP7702Transaction(tx) => Some(tx.chain_id),
            Transaction::PrivilegedL2Transaction(tx) => Some(tx.chain_id),
            Transaction::FeeTokenTransaction(tx) => Some(tx.chain_id),
            Transaction::FrameTransaction(tx) => Some(tx.chain_id),
        }
    }

    pub fn access_list(&self) -> &AccessList {
        static EMPTY_ACCESS_LIST: AccessList = Vec::new();
        match self {
            Transaction::LegacyTransaction(_tx) => &EMPTY_ACCESS_LIST,
            Transaction::EIP2930Transaction(tx) => &tx.access_list,
            Transaction::EIP1559Transaction(tx) => &tx.access_list,
            Transaction::EIP4844Transaction(tx) => &tx.access_list,
            Transaction::EIP7702Transaction(tx) => &tx.access_list,
            Transaction::PrivilegedL2Transaction(tx) => &tx.access_list,
            Transaction::FeeTokenTransaction(tx) => &tx.access_list,
            Transaction::FrameTransaction(_) => &EMPTY_ACCESS_LIST,
        }
    }
    pub fn authorization_list(&self) -> Option<&AuthorizationList> {
        match self {
            Transaction::LegacyTransaction(_) => None,
            Transaction::EIP2930Transaction(_) => None,
            Transaction::EIP1559Transaction(_) => None,
            Transaction::EIP4844Transaction(_) => None,
            Transaction::EIP7702Transaction(tx) => Some(&tx.authorization_list),
            Transaction::PrivilegedL2Transaction(_) => None,
            Transaction::FeeTokenTransaction(_) => None,
            Transaction::FrameTransaction(_) => None,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Transaction::LegacyTransaction(tx) => tx.nonce,
            Transaction::EIP2930Transaction(tx) => tx.nonce,
            Transaction::EIP1559Transaction(tx) => tx.nonce,
            Transaction::EIP4844Transaction(tx) => tx.nonce,
            Transaction::EIP7702Transaction(tx) => tx.nonce,
            Transaction::PrivilegedL2Transaction(tx) => tx.nonce,
            Transaction::FeeTokenTransaction(tx) => tx.nonce,
            Transaction::FrameTransaction(tx) => tx.nonce,
        }
    }

    pub fn data(&self) -> &Bytes {
        match self {
            Transaction::LegacyTransaction(tx) => &tx.data,
            Transaction::EIP2930Transaction(tx) => &tx.data,
            Transaction::EIP1559Transaction(tx) => &tx.data,
            Transaction::EIP4844Transaction(tx) => &tx.data,
            Transaction::EIP7702Transaction(tx) => &tx.data,
            Transaction::PrivilegedL2Transaction(tx) => &tx.data,
            Transaction::FeeTokenTransaction(tx) => &tx.data,
            Transaction::FrameTransaction(_) => {
                static EMPTY_DATA: Bytes = Bytes::new();
                &EMPTY_DATA
            }
        }
    }

    pub fn blob_versioned_hashes(&self) -> Vec<H256> {
        match self {
            Transaction::LegacyTransaction(_) => Vec::new(),
            Transaction::EIP2930Transaction(_) => Vec::new(),
            Transaction::EIP1559Transaction(_) => Vec::new(),
            Transaction::EIP4844Transaction(tx) => tx.blob_versioned_hashes.clone(),
            Transaction::EIP7702Transaction(_) => Vec::new(),
            Transaction::PrivilegedL2Transaction(_) => Vec::new(),
            Transaction::FeeTokenTransaction(_) => Vec::new(),
            Transaction::FrameTransaction(tx) => tx.blob_versioned_hashes.clone(),
        }
    }

    pub fn max_fee_per_blob_gas(&self) -> Option<U256> {
        match self {
            Transaction::LegacyTransaction(_) => None,
            Transaction::EIP2930Transaction(_) => None,
            Transaction::EIP1559Transaction(_) => None,
            Transaction::EIP4844Transaction(tx) => Some(tx.max_fee_per_blob_gas),
            Transaction::EIP7702Transaction(_) => None,
            Transaction::PrivilegedL2Transaction(_) => None,
            Transaction::FeeTokenTransaction(_) => None,
            Transaction::FrameTransaction(tx) => {
                if tx.blob_versioned_hashes.is_empty() {
                    None
                } else {
                    Some(tx.max_fee_per_blob_gas)
                }
            }
        }
    }

    /// Whether this transaction carries blob data, and therefore an expensive
    /// EIP-4844 sidecar. True for EIP-4844 transactions and for EIP-8141 frame
    /// transactions with a non-empty `blob_versioned_hashes` — matching for
    /// which types [`Self::max_fee_per_blob_gas`] yields a fee. Prefer this
    /// over matching on `EIP4844Transaction` alone when the question is "does
    /// this tx have a sidecar to re-propagate".
    pub fn is_blob_carrying(&self) -> bool {
        self.max_fee_per_blob_gas().is_some()
    }

    pub fn is_contract_creation(&self) -> bool {
        match &self {
            Transaction::LegacyTransaction(t) => matches!(t.to, TxKind::Create),
            Transaction::EIP2930Transaction(t) => matches!(t.to, TxKind::Create),
            Transaction::EIP1559Transaction(t) => matches!(t.to, TxKind::Create),
            Transaction::EIP4844Transaction(_) => false,
            Transaction::EIP7702Transaction(_) => false,
            Transaction::PrivilegedL2Transaction(t) => matches!(t.to, TxKind::Create),
            Transaction::FeeTokenTransaction(t) => matches!(t.to, TxKind::Create),
            Transaction::FrameTransaction(_) => false,
        }
    }

    pub fn is_privileged(&self) -> bool {
        matches!(self, Transaction::PrivilegedL2Transaction(_))
    }

    /// The transaction's `max_fee_per_gas`, widened to `U256` because EIP-8141
    /// bounds a frame transaction's fee fields at 2**256 while every other type
    /// keeps them within `u64`.
    pub fn max_fee_per_gas(&self) -> Option<U256> {
        match self {
            Transaction::LegacyTransaction(_tx) => None,
            Transaction::EIP2930Transaction(_tx) => None,
            Transaction::EIP1559Transaction(tx) => Some(U256::from(tx.max_fee_per_gas)),
            Transaction::EIP4844Transaction(tx) => Some(U256::from(tx.max_fee_per_gas)),
            Transaction::EIP7702Transaction(tx) => Some(U256::from(tx.max_fee_per_gas)),
            Transaction::PrivilegedL2Transaction(tx) => Some(U256::from(tx.max_fee_per_gas)),
            Transaction::FeeTokenTransaction(tx) => Some(U256::from(tx.max_fee_per_gas)),
            Transaction::FrameTransaction(tx) => Some(tx.max_fee_per_gas),
        }
    }

    fn compute_hash(&self, crypto: &dyn Crypto) -> H256 {
        if let Transaction::PrivilegedL2Transaction(tx) = self {
            return tx.get_privileged_hash().unwrap_or_default();
        }
        H256(crypto.keccak256(&self.encode_canonical_to_vec()))
    }

    pub fn hash(&self, crypto: &dyn Crypto) -> H256 {
        let inner_hash = match self {
            Transaction::LegacyTransaction(tx) => &tx.inner_hash,
            Transaction::EIP2930Transaction(tx) => &tx.inner_hash,
            Transaction::EIP1559Transaction(tx) => &tx.inner_hash,
            Transaction::EIP4844Transaction(tx) => &tx.inner_hash,
            Transaction::EIP7702Transaction(tx) => &tx.inner_hash,
            Transaction::PrivilegedL2Transaction(tx) => &tx.inner_hash,
            Transaction::FeeTokenTransaction(tx) => &tx.inner_hash,
            Transaction::FrameTransaction(tx) => &tx.inner_hash,
        };

        *inner_hash.get_or_init(|| self.compute_hash(crypto))
    }

    pub fn gas_tip_cap(&self) -> U256 {
        self.max_priority_fee().unwrap_or_else(|| self.gas_price())
    }

    pub fn gas_fee_cap(&self) -> U256 {
        self.max_fee_per_gas().unwrap_or_else(|| self.gas_price())
    }

    /// Returns the effective tip per gas for this transaction.
    /// Returns `None` if the transaction's fee cap is below the base fee (i.e. the
    /// transaction cannot pay for its inclusion).
    pub fn effective_gas_tip(&self, base_fee: Option<u64>) -> Option<U256> {
        let tip_cap = self.gas_tip_cap();
        let Some(base_fee) = base_fee else {
            return Some(tip_cap);
        };
        let base_fee = U256::from(base_fee);
        let fee_cap = self.gas_fee_cap();
        let tip = fee_cap.checked_sub(base_fee)?;
        Some(min(tip, tip_cap))
    }

    /// Returns whether the transaction is replay-protected.
    /// For more information check out [EIP-155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md)
    pub fn protected(&self) -> bool {
        match self {
            Transaction::LegacyTransaction(tx) if tx.v.bits() <= 8 => {
                let v = tx.v.low_u64();
                v != 27 && v != 28 && v != 1 && v != 0
            }
            _ => true,
        }
    }
}

fn derive_legacy_chain_id(v: U256) -> Option<u64> {
    let v = u64::try_from(v).ok()?;
    // EIP-155 encodes the chain id as `v = chain_id * 2 + 35` (or 36), so any
    // replay-protected `v` is >= 35. Pre-EIP-155 txs use v=27/28, and malformed
    // signatures (e.g. v=0 from an unsigned IL transaction) are < 35 too; none
    // carry a chain id. Guard the subtraction to avoid an underflow panic.
    if v < 35 { None } else { Some((v - 35) / 2) }
}

impl TxType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Legacy),
            0x01 => Some(Self::EIP2930),
            0x02 => Some(Self::EIP1559),
            0x03 => Some(Self::EIP4844),
            0x04 => Some(Self::EIP7702),
            0x06 => Some(Self::Frame),
            0x7d => Some(Self::FeeToken),
            0x7e => Some(Self::Privileged),
            _ => None,
        }
    }

    /// The typed-envelope form of this transaction type, or `None` for [`TxType::Legacy`]
    /// (a bare RLP list, not a `0x{type} || payload` envelope). Exhaustive over `TxType`
    /// with no wildcard, so adding a new variant won't compile until it's classified here —
    /// keeping envelope decoding in step with the transaction-type set.
    pub fn as_envelope(self) -> Option<EnvelopeTxType> {
        match self {
            TxType::EIP2930 => Some(EnvelopeTxType::EIP2930),
            TxType::EIP1559 => Some(EnvelopeTxType::EIP1559),
            TxType::EIP4844 => Some(EnvelopeTxType::EIP4844),
            TxType::EIP7702 => Some(EnvelopeTxType::EIP7702),
            TxType::Frame => Some(EnvelopeTxType::Frame),
            TxType::FeeToken => Some(EnvelopeTxType::FeeToken),
            TxType::Privileged => Some(EnvelopeTxType::Privileged),
            TxType::Legacy => None,
        }
    }

    /// Transaction types that only exist on the L2 rollup and must never appear in
    /// an L1 block (`FeeToken` 0x7d, `Privileged` 0x7e). Privileged transactions in
    /// particular take their sender from an unsigned, caller-chosen `from` field.
    ///
    /// This match is intentionally exhaustive (no wildcard arm): adding a new
    /// `TxType` variant will not compile until it is explicitly classified here,
    /// so an L2-only type can never be silently accepted on L1 by omission.
    pub fn is_l2_only(self) -> bool {
        match self {
            Self::Legacy
            | Self::EIP2930
            | Self::EIP1559
            | Self::EIP4844
            | Self::EIP7702
            | Self::Frame => false,
            Self::FeeToken | Self::Privileged => true,
        }
    }
}

impl PrivilegedL2Transaction {
    /// Returns the formatted hash of the privileged transaction,
    /// or None if the transaction is not a privileged transaction.
    /// The hash is computed as keccak256(chain_id || from || to || transaction_id  || value || gas_limit || keccak256(calldata))
    pub fn get_privileged_hash(&self) -> Option<H256> {
        // Should this function be changed?
        let to = match self.to {
            TxKind::Call(to) => to,
            _ => return None,
        };

        let value = self.value.to_big_endian();

        // The nonce should be a U256,
        // in solidity the transactionId is a U256.
        let u256_nonce = U256::from(self.nonce);
        let nonce = u256_nonce.to_big_endian();

        Some(crate::utils::keccak(
            [
                U256::from(self.chain_id).to_big_endian().as_ref(),
                self.from.as_bytes(),
                to.as_bytes(),
                &nonce,
                &value,
                &U256::from(self.gas_limit).to_big_endian(),
                keccak(&self.data).as_bytes(),
            ]
            .concat(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct FeeTokenTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    pub to: TxKind,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::AccessListItemWrapper>)]
    pub access_list: AccessList,
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    pub fee_token: Address,
    pub signature_y_parity: bool,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_r: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub signature_s: U256,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub sender_cache: OnceCell<Address>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}

/// EIP-8141 Frame Transaction mode
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
#[repr(u8)]
pub enum FrameMode {
    #[default]
    Default = 0,
    Verify = 1,
    Sender = 2,
}

impl FrameMode {
    /// Convert from the lower 8 bits of the mode field.
    /// Returns None for reserved values (3-255).
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(FrameMode::Default),
            1 => Some(FrameMode::Verify),
            2 => Some(FrameMode::Sender),
            _ => None,
        }
    }
}

impl From<FrameMode> for u8 {
    fn from(mode: FrameMode) -> u8 {
        match mode {
            FrameMode::Default => 0,
            FrameMode::Verify => 1,
            FrameMode::Sender => 2,
        }
    }
}

/// EIP-8141 `limits`: a frame's gas budgets, one per gas dimension of EIP-8037.
///
/// The two budgets are independent: neither dimension can fund charges of the
/// other, and unused gas in one is not available to the other. A frame
/// transaction therefore carries no state-gas reservoir — the reservoir model
/// exists for transaction types that declare a single gas field and cannot name
/// a state budget of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct GasLimits {
    /// Maximum execution gas that can be expended in pursuit of the frame.
    pub execution: u64,
    /// Maximum state gas that can be expended in pursuit of the frame.
    pub state: u64,
}

impl RLPEncode for GasLimits {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.execution)
            .encode_field(&self.state)
            .finish();
    }
}

impl RLPDecode for GasLimits {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (execution, decoder) = decoder.decode_field("execution")?;
        let (state, decoder) = decoder.decode_field("state")?;
        Ok((GasLimits { execution, state }, decoder.finish()?))
    }
}

/// EIP-8141 Frame: a single execution step within a frame transaction.
///
/// `mode` is the execution mode (0=DEFAULT, 1=VERIFY, 2=SENDER; 3-255 reserved).
/// `flags` bits: 0-1 = APPROVE scope restriction, 2 = atomic batch flag (valid
/// on DEFAULT and SENDER frames only), 3-7 reserved (must be zero).
#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct Frame {
    pub mode: u8,
    pub flags: u8,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::H160Wrapper>)]
    pub target: Option<Address>,
    pub gas_limits: GasLimits,
    // Per EIP-8141 the frame is a 6-tuple [mode, flags, target, limits, value, data],
    // where `limits` is itself the two-element list `[execution, state]`.
    // Only SENDER frames may carry a non-zero value; see
    // `validate_static_constraints`.
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub value: U256,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub data: Bytes,
}

impl Frame {
    /// Extract the execution mode from the `mode` field.
    pub fn execution_mode(&self) -> FrameMode {
        FrameMode::from_u8(self.mode).unwrap_or_default()
    }

    /// Extract the APPROVE scope restriction from bits 0-1 of `flags`.
    pub fn scope_restriction(&self) -> u8 {
        self.flags & 0x03
    }

    /// Check if the atomic batch flag (bit 2 of `flags`) is set.
    pub fn is_atomic_batch(&self) -> bool {
        (self.flags >> 2) & 1 == 1
    }

    /// An expiry verifier frame is a VERIFY frame targeting EXPIRY_VERIFIER
    /// (EIP-8141).
    pub fn is_expiry_verifier(&self) -> bool {
        self.execution_mode() == FrameMode::Verify
            && self.target == Some(frame_tx_expiry_verifier())
    }
}

impl RLPEncode for Frame {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        // target: encode as address or RLP null (empty bytes) for None
        let target_kind = match self.target {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create, // RLP_NULL encodes "no target" → sender
        };
        Encoder::new(buf)
            .encode_field(&(self.mode as u64))
            .encode_field(&(self.flags as u64))
            .encode_field(&target_kind)
            .encode_field(&self.gas_limits)
            .encode_field(&self.value)
            .encode_field(&self.data)
            .finish();
    }
}

impl RLPDecode for Frame {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (mode_u64, decoder): (u64, _) = decoder.decode_field("mode")?;
        let mode = u8::try_from(mode_u64)
            .map_err(|_| RLPDecodeError::Custom(format!("Frame mode too large: {mode_u64}")))?;
        let (flags_u64, decoder): (u64, _) = decoder.decode_field("flags")?;
        let flags = u8::try_from(flags_u64)
            .map_err(|_| RLPDecodeError::Custom(format!("Frame flags too large: {flags_u64}")))?;
        let (target_kind, decoder): (TxKind, _) = decoder.decode_field("target")?;
        let target = match target_kind {
            TxKind::Call(addr) => Some(addr),
            TxKind::Create => None,
        };
        let (gas_limits, decoder) = decoder.decode_field("gas_limits")?;
        let (value, decoder): (U256, _) = decoder.decode_field("value")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let frame = Frame {
            mode,
            flags,
            target,
            gas_limits,
            value,
            data,
        };
        Ok((frame, decoder.finish()?))
    }
}

/// EIP-8141 transaction signature. RLP: `[scheme, signer, msg, signature]`.
/// `scheme`: 0 = ARBITRARY (`signer` MUST be empty; `signature` is arbitrary bytes),
/// 1 = SECP256K1 (sig = v||r||s, 65 bytes), 2 = P256 (sig = r||s||qx||qy, 128 bytes).
/// `signer`: `None` (empty) is required for ARBITRARY and allowed for SECP256K1/P256
/// (empty ⇒ the resolved signer is `tx.sender`, for introspection too); `Some(addr)` pins it.
/// `msg`: empty = signs compute_sig_hash(tx); 32 bytes = signs that explicit digest.
/// Raw `signature` bytes are intentionally not EVM-introspectable.
#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct FrameSignature {
    pub scheme: u8,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::H160Wrapper>)]
    pub signer: Option<Address>,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub msg: Bytes,
    #[rkyv(with=crate::rkyv_utils::BytesWrapper)]
    pub signature: Bytes,
}

impl RLPEncode for FrameSignature {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        // `signer` encodes as an address or RLP null (empty) for `None`, mirroring
        // `Frame.target`; an empty signer is required for ARBITRARY signatures.
        let signer_kind = match self.signer {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create,
        };
        Encoder::new(buf)
            .encode_field(&self.scheme)
            .encode_field(&signer_kind)
            .encode_field(&self.msg)
            .encode_field(&self.signature)
            .finish();
    }
}

impl RLPDecode for FrameSignature {
    fn decode_unfinished(rlp: &[u8]) -> Result<(FrameSignature, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (scheme, decoder) = decoder.decode_field("scheme")?;
        let (signer_kind, decoder): (TxKind, _) = decoder.decode_field("signer")?;
        let signer = match signer_kind {
            TxKind::Call(addr) => Some(addr),
            TxKind::Create => None,
        };
        let (msg, decoder) = decoder.decode_field("msg")?;
        let (signature, decoder) = decoder.decode_field("signature")?;
        Ok((
            FrameSignature {
                scheme,
                signer,
                msg,
                signature,
            },
            decoder.finish()?,
        ))
    }
}

/// EIP-8141 Frame Transaction
/// A transaction whose validity and gas payment are defined abstractly via frames.
/// No ECDSA signature — sender is explicit. Authentication happens via APPROVE opcode.
#[derive(Clone, Debug, PartialEq, Eq, Default, RSerialize, RDeserialize, Archive)]
pub struct FrameTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    pub sender: Address,
    pub frames: Vec<Frame>,
    /// EIP-8141 outer signature list. Validated
    /// before any frame executes; referenced by VERIFY frames and SIGPARAM.
    pub signatures: Vec<FrameSignature>,
    /// EIP-8141 bounds the fee fields at 2**256, not 2**64: a frame transaction
    /// may legitimately name a fee no balance could pay, and a node still has to
    /// decode it to reject it for the balance rather than for the field width.
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub max_priority_fee_per_gas: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub max_fee_per_gas: U256,
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub max_fee_per_blob_gas: U256,
    #[rkyv(with=rkyv::with::Map<crate::rkyv_utils::H256Wrapper>)]
    pub blob_versioned_hashes: Vec<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub inner_hash: OnceCell<H256>,
    #[rkyv(with=rkyv::with::Skip)]
    pub cached_canonical: OnceCell<Vec<u8>>,
}

/// Intrinsic gas cost for frame transactions (EIP-8141 `TX_FRAME_INTRINSIC`).
/// Equal to `TX_BASE`: a frame transaction prices signature recovery per
/// signature entry, so the recovery component of the base cost instead covers
/// payer settlement, which regular transactions do not price separately.
pub const FRAME_TX_INTRINSIC_COST: u64 = 12000;
/// Per-frame cost (EIP-8141): CALL context overhead (100) + G_log (375)
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;
/// EIP-8141 `TX_VALUE_COST`: the intrinsic cost of one frame's value transfer to
/// an explicit target other than the sender.
pub const FRAME_TX_VALUE_COST: u64 = 6000;
/// ENTRY_POINT address used as caller for DEFAULT/VERIFY frames per EIP-8141.
pub const FRAME_TX_ENTRY_POINT_U64: u64 = 0xaa;
/// Maximum number of frames allowed per EIP-8141 frame transaction.
pub const FRAME_TX_MAX_FRAMES: usize = 64;
/// EIP-7623 `STANDARD_TOKEN_COST`, and the EIP-7976 floor per token. Frame
/// transactions exist only from Hegota onward, which is after Amsterdam, so the
/// raised EIP-7976 floor always applies and neither needs a fork parameter.
const FRAME_TX_STANDARD_TOKEN_COST: u64 = 4;
const FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN: u64 = 16;
/// EIP-8141 signature schemes: ARBITRARY=0, SECP256K1=1, P256=2.
pub const FRAME_SIG_SCHEME_ARBITRARY: u8 = 0;
pub const FRAME_SIG_SCHEME_SECP256K1: u8 = 1;
pub const FRAME_SIG_SCHEME_P256: u8 = 2;
/// EIP-8141 §Mempool `MAX_VERIFY_GAS`: the maximum gas
/// a public-mempool node should expend validating signatures and simulating the
/// validation prefix. Signature validation counts against this budget (rule #6),
/// so a frame tx whose `signature_verification_cost()` alone exceeds it can never
/// satisfy the prefix budget and must be rejected at admission.
pub const FRAME_TX_MAX_VERIFY_GAS: u64 = 100_000;
/// EIP-8141 §Mempool `MAX_VERIFY_STATE_GAS`: the maximum state gas that may be
/// budgeted across the validation prefix. State gas does not measure a node's
/// validation work -- simulation stays bounded by `MAX_VERIFY_GAS` alone -- so it
/// carries its own, far larger cap, which bounds the state growth the public
/// mempool admits.
pub const FRAME_TX_MAX_VERIFY_STATE_GAS: u64 = 500_000;
/// EIP-8141 APPROVE scope-restriction values (bits 0-1 of `Frame.flags`).
/// Used by VERIFY and PAY frames to declare which capabilities they grant.
pub const APPROVE_PAYMENT: u8 = 0x1;
pub const APPROVE_EXECUTION: u8 = 0x2;
pub const APPROVE_EXECUTION_AND_PAYMENT: u8 = 0x3;
/// Maximum number of pending frame txs using a non-canonical paymaster per
/// paymaster address. Per OQ1, all paymasters are currently non-canonical
/// (FRAME_CANONICAL_PAYMASTER_CODE_HASH is unresolved in the draft EIP), so
/// this de-facto limits sponsored frame txs to 1 per paymaster in the pool.
pub const FRAME_TX_MAX_PENDING_NONCANONICAL_PAYMASTER: u8 = 1;

/// Returns the ENTRY_POINT `Address` (0x…00aa) used as caller for
/// DEFAULT/VERIFY frames per EIP-8141.
pub fn frame_tx_entry_point() -> Address {
    Address::from_low_u64_be(FRAME_TX_ENTRY_POINT_U64)
}

/// EXPIRY_VERIFIER predeploy address (EIP-8141).
pub const FRAME_TX_EXPIRY_VERIFIER_U64: u64 = 0x8141;
/// Required `data` length for an expiry verifier frame (8-byte BE deadline).
pub const FRAME_TX_EXPIRY_DATA_LENGTH: usize = 8;

/// Returns the EXPIRY_VERIFIER `Address` (0x…8141) per EIP-8141.
pub fn frame_tx_expiry_verifier() -> Address {
    Address::from_low_u64_be(FRAME_TX_EXPIRY_VERIFIER_U64)
}

impl FrameTransaction {
    /// Canonical signature hash (EIP-8141): the raw
    /// `signature` bytes of every signature with empty `msg` are elided (a
    /// signature over this hash cannot commit to its own bytes). Frame data is
    /// NO LONGER elided — it is fully covered. Signatures with an explicit
    /// 32-byte `msg` keep their bytes (they sign that digest, not this hash).
    pub fn compute_sig_hash(&self) -> H256 {
        let mut buf = vec![TxType::Frame as u8];
        let elided_signatures: Vec<FrameSignature> = self
            .signatures
            .iter()
            .map(|s| {
                if s.msg.is_empty() {
                    FrameSignature {
                        scheme: s.scheme,
                        signer: s.signer,
                        msg: s.msg.clone(),
                        signature: Bytes::new(),
                    }
                } else {
                    s.clone()
                }
            })
            .collect();
        // RLP-encode the tx with elided signature bytes, frames verbatim.
        Encoder::new(&mut buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.sender)
            .encode_field(&self.frames)
            .encode_field(&elided_signatures)
            .encode_field(&self.fees())
            .encode_field(&self.blob_versioned_hashes)
            .finish();
        keccak(&buf)
    }

    /// EIP-8141 `fees`: the transaction's three fee parameters, which the payload
    /// carries as one nested list rather than as three consecutive scalars. Kept
    /// flat on the struct — every accessor, the RPC shape and the mempool read the
    /// fields individually — and nested only where the wire format demands it, so
    /// the encoder and the signature hash agree by construction.
    fn fees(&self) -> (U256, U256, U256) {
        (
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.max_fee_per_blob_gas,
        )
    }

    /// Per EIP-8141: 100 gas per ARBITRARY signature, 2800 per SECP256K1, 6700
    /// per P256. Unknown schemes are rejected by static validation, so they are
    /// treated as 0 here (validation runs first).
    pub fn signature_verification_cost(&self) -> u64 {
        self.signatures
            .iter()
            .map(|s| match s.scheme {
                FRAME_SIG_SCHEME_ARBITRARY => 100u64,
                FRAME_SIG_SCHEME_SECP256K1 => 2800u64,
                FRAME_SIG_SCHEME_P256 => 6700u64,
                _ => 0,
            })
            .sum()
    }

    /// Iterate the EIP-8141 data fields the calldata cost is charged over:
    /// each frame's `data`, and each signature's `signer`, `msg` and `signature`.
    /// The RLP framing and the remaining scalar fields are not included.
    fn data_fields(&self) -> impl Iterator<Item = &[u8]> {
        const EMPTY: &[u8] = &[];
        self.frames
            .iter()
            .map(|f| f.data.as_ref())
            .chain(self.signatures.iter().flat_map(|s| {
                [
                    s.signer.as_ref().map_or(EMPTY, |a| a.as_bytes()),
                    s.msg.as_ref(),
                    s.signature.as_ref(),
                ]
            }))
    }

    /// EIP-7623 calldata cost over the frame and signature data: 4 gas per zero
    /// byte, 16 per non-zero byte.
    pub fn data_cost(&self) -> u64 {
        self.data_fields().flatten().fold(0u64, |acc, byte| {
            acc.saturating_add(if *byte == 0 { 4 } else { 16 })
        })
    }

    /// EIP-7623 token count over the frame and signature data, used for the
    /// calldata floor. Frame transactions exist only from Hegota onward, which is
    /// after Amsterdam, so EIP-7976's unweighted count (every byte costs
    /// `STANDARD_TOKEN_COST`) always applies.
    pub fn calldata_tokens(&self) -> u64 {
        self.data_fields()
            .fold(0u64, |acc, field| acc.saturating_add(field.len() as u64))
            .saturating_mul(FRAME_TX_STANDARD_TOKEN_COST)
    }

    /// The EIP-7623 calldata floor: the least the frame and signature data may
    /// cost, whatever execution actually consumes.
    pub fn calldata_floor_gas(&self) -> u64 {
        self.calldata_tokens()
            .saturating_mul(FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN)
    }

    /// EIP-8141 value-transfer component of the intrinsic cost: `TX_VALUE_COST`
    /// per value-bearing frame with an explicit target other than the sender,
    /// covering the recipient balance write and the transfer log. A frame paying
    /// its own sender moves no funds between accounts, so it is not charged.
    pub fn value_transfer_gas(&self) -> u64 {
        self.frames
            .iter()
            .filter(|f| !f.value.is_zero() && f.target.is_some_and(|target| target != self.sender))
            .fold(0u64, |acc, _| acc.saturating_add(FRAME_TX_VALUE_COST))
    }

    /// EIP-8141 `base_execution_gas`, the mandatory costs always charged in full
    /// and anchoring both the intrinsic cost and the calldata floor: the intrinsic
    /// base, the per-frame cost, signature verification, and the value transfers.
    pub fn mandatory_gas(&self) -> u64 {
        FRAME_TX_INTRINSIC_COST
            .saturating_add((self.frames.len() as u64).saturating_mul(FRAME_TX_PER_FRAME_COST))
            .saturating_add(self.signature_verification_cost())
            .saturating_add(self.value_transfer_gas())
    }

    /// The frames' total execution-gas budget.
    pub fn total_frame_execution_gas(&self) -> u64 {
        self.frames
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.gas_limits.execution))
    }

    /// The frames' total state-gas budget.
    pub fn total_frame_state_gas(&self) -> u64 {
        self.frames
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.gas_limits.state))
    }

    /// EIP-8141 `standard_gas_limit`, the settlement anchor: the intrinsic
    /// execution cost plus the frames' budgets in *both* dimensions.
    pub fn standard_gas_limit(&self) -> u64 {
        self.mandatory_gas()
            .saturating_add(self.data_cost())
            .saturating_add(self.total_frame_execution_gas())
            .saturating_add(self.total_frame_state_gas())
    }

    /// EIP-8141 `calldata_floor_gas`: the mandatory costs plus the EIP-7623
    /// floor over every byte this transaction carries. The mandatory costs are
    /// always charged, so they sit on both sides of the `max_gas` comparison.
    pub fn calldata_floor_total(&self) -> u64 {
        self.mandatory_gas()
            .saturating_add(self.calldata_floor_gas())
    }

    /// EIP-8141 `max_gas = max(standard_gas_limit, calldata_floor + Σ state)`: the
    /// gas reserved from the block pool before execution and the quantity
    /// `max_cost` is charged over. A transaction whose data floor exceeds what it
    /// declared for execution reserves the floor rather than being rejected. The
    /// floor binds the execution dimension alone, so the state budget is added to
    /// it: a floor-bound transaction pays the floor plus its state gas in full.
    pub fn max_gas(&self) -> u64 {
        self.standard_gas_limit().max(
            self.calldata_floor_total()
                .saturating_add(self.total_frame_state_gas()),
        )
    }

    /// The quantity EIP-7825's per-transaction gas cap bounds: the execution
    /// dimension alone — the intrinsic cost plus the frames' execution budgets,
    /// with the calldata floor checked against the same cap. State gas is bounded
    /// only by the encoding limit and the block's state gas capacity.
    pub fn execution_gas_cap_usage(&self) -> u64 {
        self.mandatory_gas()
            .saturating_add(self.data_cost())
            .saturating_add(self.total_frame_execution_gas())
            .max(self.calldata_floor_total())
    }

    /// The expiry deadline (8-byte big-endian) of this transaction's expiry
    /// verifier frame, if one exists with well-formed data.
    pub fn expiry_deadline(&self) -> Option<u64> {
        self.frames
            .iter()
            .find(|f| f.is_expiry_verifier())
            .and_then(|f| {
                let bytes: [u8; FRAME_TX_EXPIRY_DATA_LENGTH] = f.data.as_ref().try_into().ok()?;
                Some(u64::from_be_bytes(bytes))
            })
    }

    /// Validate static constraints per EIP-8141 spec.
    /// Returns an error string if the transaction is invalid.
    pub fn validate_static_constraints(&self) -> Result<(), String> {
        // tx.sender != zero address
        if self.sender == Address::zero() {
            return Err("tx.sender must not be zero address".to_string());
        }
        if self.frames.is_empty() || self.frames.len() > FRAME_TX_MAX_FRAMES {
            return Err(format!(
                "Frame count must be between 1 and {FRAME_TX_MAX_FRAMES}"
            ));
        }
        // Per EIP-8141, every versioned hash must carry the EIP-4844 KZG version
        // byte, and a transaction carrying no blobs must not name a blob fee.
        for (i, hash) in self.blob_versioned_hashes.iter().enumerate() {
            if hash.0.first() != Some(&VERSIONED_HASH_VERSION_KZG) {
                return Err(format!("Blob versioned hash {i}: wrong version byte"));
            }
        }
        if self.blob_versioned_hashes.is_empty() && !self.max_fee_per_blob_gas.is_zero() {
            return Err(
                "max_fee_per_blob_gas must be zero when the transaction carries no blobs"
                    .to_string(),
            );
        }
        // EIP-8141 signature list validation: scheme must be a known value; msg
        // must be empty or a non-zero 32-byte digest.
        for (i, sig) in self.signatures.iter().enumerate() {
            match sig.scheme {
                // ARBITRARY (0) carries no recoverable signer; per EIP-8141 the
                // signer MUST be empty.
                FRAME_SIG_SCHEME_ARBITRARY => {
                    if sig.signer.is_some() {
                        return Err(format!(
                            "Signature {i}: ARBITRARY signatures must not name a signer"
                        ));
                    }
                }
                FRAME_SIG_SCHEME_SECP256K1 | FRAME_SIG_SCHEME_P256 => {}
                other => {
                    return Err(format!("Signature {i}: unsupported scheme {other}"));
                }
            }
            match sig.msg.len() {
                0 => {}
                32 => {
                    if sig.msg.iter().all(|&b| b == 0) {
                        return Err(format!(
                            "Signature {i}: explicit msg must not be zero digest"
                        ));
                    }
                }
                other => {
                    return Err(format!(
                        "Signature {i}: msg must be empty or 32 bytes, got {other}"
                    ));
                }
            }
        }
        // Tracked as u128 so the running addition itself cannot overflow; the
        // bound below rejects tx-level totals that don't fit in signed i64.
        let mut total_frame_gas: u128 = 0;
        let mut expiry_frame_count: usize = 0;
        for (i, frame) in self.frames.iter().enumerate() {
            // Reject reserved execution modes (3-255)
            if frame.mode >= 3 {
                return Err(format!("Frame {i}: reserved execution mode {}", frame.mode));
            }
            // Reserved flag bits 3-7 must be zero
            if frame.flags >= 8 {
                return Err(format!(
                    "Frame {i}: reserved flag bits must be zero (flags={:#04x})",
                    frame.flags
                ));
            }
            // Expiry verifier frames (EIP-8141): VERIFY
            // frames targeting EXPIRY_VERIFIER must have flags == 0, value == 0
            // (already enforced by the non-SENDER value rule below), and exactly
            // EXPIRY_DATA_LENGTH bytes of data; at most one per transaction.
            if frame.is_expiry_verifier() {
                expiry_frame_count = expiry_frame_count.saturating_add(1);
                if expiry_frame_count > 1 {
                    return Err(format!("Frame {i}: more than one expiry verifier frame"));
                }
                if frame.flags != 0 {
                    return Err(format!(
                        "Frame {i}: expiry verifier frame must have flags == 0"
                    ));
                }
                if frame.data.len() != FRAME_TX_EXPIRY_DATA_LENGTH {
                    return Err(format!(
                        "Frame {i}: expiry verifier frame data must be {FRAME_TX_EXPIRY_DATA_LENGTH} bytes"
                    ));
                }
                // Per EIP-8141, an expiry verifier frame runs protocol code that
                // creates no state, so it must declare no state gas budget.
                if frame.gas_limits.state != 0 {
                    return Err(format!(
                        "Frame {i}: expiry verifier frame must have zero state gas"
                    ));
                }
            }
            // Per EIP-8141, only SENDER frames may carry a
            // non-zero value. DEFAULT and VERIFY frames with a non-zero
            // value are statically invalid.
            if frame.mode != FrameMode::Sender as u8 && !frame.value.is_zero() {
                return Err(format!(
                    "Frame {i}: non-zero value only allowed in SENDER mode (mode={}, value={})",
                    frame.mode, frame.value
                ));
            }
            // Intentional stricter-than-spec bound. EIP-8141 allows each budget
            // and the cumulative frame gas up to 2**64-1; ethrex caps both
            // at i64::MAX (2**63-1) so the state-gas dimension (tracked as i64) can
            // never overflow downstream. This is documented as a known divergence
            // in docs/eip-8141.md. It is effectively unreachable: any budget
            // >= 2**63 dwarfs every real block gas limit and is rejected by the
            // gas-limit-vs-block-limit check regardless.
            for (dimension, budget) in [
                ("execution", frame.gas_limits.execution),
                ("state", frame.gas_limits.state),
            ] {
                if budget > i64::MAX as u64 {
                    return Err(format!(
                        "Frame {i}: {dimension} gas limit {budget} exceeds 2**63-1"
                    ));
                }
            }
            // Per EIP-8141, the frames' total gas across both dimensions must fit
            // `u64`; the tighter `i64::MAX` bound is ethrex's own, as above.
            total_frame_gas = total_frame_gas
                .checked_add(frame.gas_limits.execution as u128)
                .and_then(|acc| acc.checked_add(frame.gas_limits.state as u128))
                .ok_or_else(|| format!("Frame {i}: cumulative gas limit overflow"))?;
            if total_frame_gas > i64::MAX as u128 {
                return Err(format!(
                    "Frame {i}: cumulative frame gas limit {total_frame_gas} exceeds 2**63-1"
                ));
            }
            // Per EIP-8141, approval of execution is only allowed when the
            // frame's target is empty or `tx.sender`.
            if frame.flags & APPROVE_EXECUTION != 0
                && frame.target.is_some_and(|target| target != self.sender)
            {
                return Err(format!(
                    "Frame {i}: APPROVE_EXECUTION requires an empty target or tx.sender"
                ));
            }
            // Per EIP-8141, the atomic batch flag (bit 2 of flags) is only valid
            // on a non-VERIFY frame, requires a subsequent frame to batch with,
            // and that frame must be non-VERIFY too: batches never contain
            // VERIFY frames.
            if frame.is_atomic_batch() {
                if frame.mode == FrameMode::Verify as u8 {
                    return Err(format!("Frame {i}: atomic batch flag on a VERIFY frame"));
                }
                match self.frames.get(i.saturating_add(1)) {
                    None => return Err(format!("Frame {i}: atomic batch flag on last frame")),
                    Some(next) if next.mode == FrameMode::Verify as u8 => {
                        return Err(format!(
                            "Frame {i}: atomic batch flag followed by a VERIFY frame"
                        ));
                    }
                    Some(_) => {}
                }
            }
            // Per EIP-8141, approval scope is disallowed on every frame of an
            // atomic batch, including its terminating frame. A frame belongs to a
            // batch when it or its predecessor carries the flag. Keeping the
            // approval context constant across a batch means unrolling one can
            // never withdraw an execution approval that later SENDER frames rely
            // on, and whether the transaction sets a payer never depends on a
            // batch outcome.
            let in_batch = frame.is_atomic_batch()
                || i.checked_sub(1)
                    .and_then(|prev| self.frames.get(prev))
                    .is_some_and(|prev| prev.is_atomic_batch());
            if in_batch && frame.scope_restriction() != 0 {
                return Err(format!(
                    "Frame {i}: atomic batch frames cannot carry approval scope"
                ));
            }
        }
        Ok(())
    }

    /// Identify and return the validation prefix of this frame transaction.
    ///
    /// The validation prefix is the minimal leading subsequence of frames (ignoring
    /// expiry-verifier frames) that establishes who pays for the transaction.
    /// Four shapes are recognized (per EIP-8141 §Mempool):
    ///
    /// - `SelfVerify`: one VERIFY frame targeting `tx.sender` with scope `APPROVE_EXECUTION_AND_PAYMENT`.
    /// - `DeploySelfVerify`: one DEFAULT frame (deploy) then one VERIFY frame as above.
    /// - `OnlyVerifyPay`: one VERIFY frame (only_verify, scope `APPROVE_EXECUTION`) +
    ///   one VERIFY frame (pay, scope `APPROVE_PAYMENT`).
    /// - `DeployOnlyVerifyPay`: DEFAULT deploy frame + OnlyVerifyPay pair.
    ///
    /// Expiry-verifier frames (see `Frame::is_expiry_verifier`) are transparent; they
    /// are skipped during shape matching but their indices are NOT included in
    /// `frame_indices` (which holds only the semantically meaningful prefix frames).
    pub fn validation_prefix(&self) -> Result<ValidationPrefix, FrameValidationError> {
        // Collect non-expiry frame indices in order.
        let non_expiry: Vec<usize> = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.is_expiry_verifier())
            .map(|(i, _)| i)
            .collect();

        // Helper to get a frame by its position in non_expiry.
        let frame = |pos: usize| -> Option<&Frame> {
            non_expiry.get(pos).and_then(|&idx| self.frames.get(idx))
        };

        let is_default = |pos: usize| -> bool {
            frame(pos).is_some_and(|f| f.execution_mode() == FrameMode::Default)
        };
        let is_verify = |pos: usize| -> bool {
            frame(pos).is_some_and(|f| f.execution_mode() == FrameMode::Verify)
        };
        let scope_of = |pos: usize| -> u8 { frame(pos).map_or(0, |f| f.scope_restriction()) };

        if non_expiry.is_empty() {
            return Err(FrameValidationError::UnrecognizedPrefix);
        }

        // Attempt to match each of the four shapes.
        //
        // Shape: DeployOnlyVerifyPay — DEFAULT + VERIFY(exec) + VERIFY(pay)
        if is_default(0)
            && is_verify(1)
            && scope_of(1) == APPROVE_EXECUTION
            && is_verify(2)
            && scope_of(2) == APPROVE_PAYMENT
        {
            return Ok(ValidationPrefix {
                shape: PrefixShape::DeployOnlyVerifyPay,
                frame_indices: vec![non_expiry[0], non_expiry[1], non_expiry[2]],
                deploy_index: Some(non_expiry[0]),
                pay_index: Some(non_expiry[2]),
            });
        }

        // Shape: DeploySelfVerify — DEFAULT + VERIFY(exec+pay)
        if is_default(0) && is_verify(1) && scope_of(1) == APPROVE_EXECUTION_AND_PAYMENT {
            return Ok(ValidationPrefix {
                shape: PrefixShape::DeploySelfVerify,
                frame_indices: vec![non_expiry[0], non_expiry[1]],
                deploy_index: Some(non_expiry[0]),
                pay_index: Some(non_expiry[1]),
            });
        }

        // Shape: OnlyVerifyPay — VERIFY(exec) + VERIFY(pay)
        if is_verify(0)
            && scope_of(0) == APPROVE_EXECUTION
            && is_verify(1)
            && scope_of(1) == APPROVE_PAYMENT
        {
            return Ok(ValidationPrefix {
                shape: PrefixShape::OnlyVerifyPay,
                frame_indices: vec![non_expiry[0], non_expiry[1]],
                deploy_index: None,
                pay_index: Some(non_expiry[1]),
            });
        }

        // Shape: SelfVerify — VERIFY(exec+pay)
        if is_verify(0) && scope_of(0) == APPROVE_EXECUTION_AND_PAYMENT {
            return Ok(ValidationPrefix {
                shape: PrefixShape::SelfVerify,
                frame_indices: vec![non_expiry[0]],
                deploy_index: None,
                pay_index: Some(non_expiry[0]),
            });
        }

        Err(FrameValidationError::UnrecognizedPrefix)
    }

    /// Validate structural rules for the identified validation prefix.
    ///
    /// Checks:
    /// - Deploy frame (if any) is at index 0 and uses DEFAULT execution mode.
    /// - At most one deploy frame exists in the prefix.
    /// - self_verify / only_verify / pay frames use VERIFY execution mode.
    /// - Resolved target of each VERIFY frame matches `tx.sender` (target == None
    ///   means sender; a non-None target must equal sender).
    /// - Scope restriction matches the frame's role:
    ///   self_verify → `APPROVE_EXECUTION_AND_PAYMENT`, only_verify → `APPROVE_EXECUTION`,
    ///   pay → `APPROVE_PAYMENT`.
    /// - No frame in the prefix has the atomic-batch flag set.
    /// - Gas budget, per dimension: Σ(prefix execution limits) +
    ///   signature_verification_cost() ≤ MAX_VERIFY_GAS, and Σ(prefix state limits)
    ///   ≤ MAX_VERIFY_STATE_GAS.
    pub fn validate_prefix_structure(
        &self,
        prefix: &ValidationPrefix,
    ) -> Result<(), FrameValidationError> {
        let mut deploy_count = 0usize;

        for &idx in &prefix.frame_indices {
            let frame = &self.frames[idx];

            if frame.is_atomic_batch() {
                return Err(FrameValidationError::AtomicBatchInPrefix { frame_index: idx });
            }

            match prefix.deploy_index {
                Some(deploy_idx) if deploy_idx == idx => {
                    // This is the deploy frame.
                    deploy_count += 1;
                    if deploy_count > 1 {
                        return Err(FrameValidationError::MultipleDeploys { frame_index: idx });
                    }
                    // The deploy must be first among prefix frames. `validation_prefix`
                    // structurally guarantees this, but the raw frame index can be
                    // non-zero when expiry-verifier frames precede the deploy — check
                    // against the first element of `frame_indices`, not the raw index.
                    if prefix.frame_indices.first() != Some(&idx) {
                        return Err(FrameValidationError::DeployNotFirst { frame_index: idx });
                    }
                    if frame.execution_mode() != FrameMode::Default {
                        return Err(FrameValidationError::DeployNotDefaultMode {
                            frame_index: idx,
                        });
                    }
                }
                _ => {
                    // VERIFY frame (self_verify, only_verify, or pay).
                    if frame.execution_mode() != FrameMode::Verify {
                        return Err(FrameValidationError::VerifyFrameNotVerifyMode {
                            frame_index: idx,
                        });
                    }

                    // Resolved target must be tx.sender (None means sender).
                    let target_ok = match frame.target {
                        None => true,
                        Some(addr) => addr == self.sender,
                    };
                    if !target_ok {
                        return Err(FrameValidationError::VerifyTargetNotSender {
                            frame_index: idx,
                        });
                    }

                    // Scope restriction must match role.
                    let expected_scope = match prefix.shape {
                        PrefixShape::SelfVerify | PrefixShape::DeploySelfVerify => {
                            APPROVE_EXECUTION_AND_PAYMENT
                        }
                        PrefixShape::OnlyVerifyPay | PrefixShape::DeployOnlyVerifyPay => {
                            // The only_verify frame comes before the pay frame.
                            if prefix.pay_index == Some(idx) {
                                APPROVE_PAYMENT
                            } else {
                                APPROVE_EXECUTION
                            }
                        }
                    };
                    if frame.scope_restriction() != expected_scope {
                        return Err(FrameValidationError::WrongScopeRestriction {
                            frame_index: idx,
                            expected: expected_scope,
                            actual: frame.scope_restriction(),
                        });
                    }
                }
            }
        }

        // Gas budget, per dimension: the prefix's execution budgets plus the
        // signature cost against `MAX_VERIFY_GAS`, and its state budgets against
        // `MAX_VERIFY_STATE_GAS`. The two caps are independent -- state gas does not
        // measure the node's simulation work, so it must not consume the budget that
        // bounds it.
        let mut prefix_execution_gas = 0u64;
        let mut prefix_state_gas = 0u64;
        for &i in &prefix.frame_indices {
            prefix_execution_gas =
                prefix_execution_gas.saturating_add(self.frames[i].gas_limits.execution);
            prefix_state_gas = prefix_state_gas.saturating_add(self.frames[i].gas_limits.state);
        }
        let total_verify_gas =
            prefix_execution_gas.saturating_add(self.signature_verification_cost());
        if total_verify_gas > FRAME_TX_MAX_VERIFY_GAS {
            return Err(FrameValidationError::VerifyGasBudgetExceeded {
                actual: total_verify_gas,
                limit: FRAME_TX_MAX_VERIFY_GAS,
            });
        }
        if prefix_state_gas > FRAME_TX_MAX_VERIFY_STATE_GAS {
            return Err(FrameValidationError::VerifyStateGasBudgetExceeded {
                actual: prefix_state_gas,
                limit: FRAME_TX_MAX_VERIFY_STATE_GAS,
            });
        }

        Ok(())
    }
}

/// The four recognized shapes of an EIP-8141 validation prefix (§Mempool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixShape {
    /// Single VERIFY frame: sender verifies + authorizes payment for itself.
    SelfVerify,
    /// DEFAULT (deploy) frame, then VERIFY frame that verifies + authorizes payment.
    DeploySelfVerify,
    /// VERIFY(exec) + VERIFY(pay): separate verifier and paymaster.
    OnlyVerifyPay,
    /// DEFAULT (deploy) + VERIFY(exec) + VERIFY(pay).
    DeployOnlyVerifyPay,
}

/// Identified validation prefix of an EIP-8141 frame transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationPrefix {
    /// Recognized shape of this prefix.
    pub shape: PrefixShape,
    /// Frame indices (into `FrameTransaction.frames`) that form the prefix,
    /// in order. Does not include expiry-verifier frames.
    pub frame_indices: Vec<usize>,
    /// Index of the deploy frame within `frames`, if this shape has one.
    pub deploy_index: Option<usize>,
    /// Index of the pay (or self_verify) frame within `frames`.
    pub pay_index: Option<usize>,
}

/// Errors produced by `FrameTransaction::validation_prefix` and
/// `FrameTransaction::validate_prefix_structure`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameValidationError {
    #[error("frame transaction validation prefix does not match any recognized shape")]
    UnrecognizedPrefix,
    #[error("frame {frame_index}: prefix has more than one DEFAULT deploy frame")]
    MultipleDeploys { frame_index: usize },
    #[error("frame {frame_index}: deploy frame must be at index 0")]
    DeployNotFirst { frame_index: usize },
    #[error("frame {frame_index}: deploy frame must use DEFAULT execution mode")]
    DeployNotDefaultMode { frame_index: usize },
    #[error("frame {frame_index}: prefix VERIFY frame does not use VERIFY execution mode")]
    VerifyFrameNotVerifyMode { frame_index: usize },
    #[error("frame {frame_index}: VERIFY frame target is not tx.sender")]
    VerifyTargetNotSender { frame_index: usize },
    #[error("frame {frame_index}: scope restriction is {actual:#04x}, expected {expected:#04x}")]
    WrongScopeRestriction {
        frame_index: usize,
        expected: u8,
        actual: u8,
    },
    #[error("frame {frame_index}: prefix frame has atomic-batch flag set")]
    AtomicBatchInPrefix { frame_index: usize },
    #[error("prefix gas budget exceeded: {actual} > {limit} (MAX_VERIFY_GAS)")]
    VerifyGasBudgetExceeded { actual: u64, limit: u64 },
    #[error("prefix state gas budget exceeded: {actual} > {limit} (MAX_VERIFY_STATE_GAS)")]
    VerifyStateGasBudgetExceeded { actual: u64, limit: u64 },
}

impl RLPEncode for FrameTransaction {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.sender)
            .encode_field(&self.frames)
            .encode_field(&self.signatures)
            .encode_field(&self.fees())
            .encode_field(&self.blob_versioned_hashes)
            .finish();
    }
}

impl RLPDecode for FrameTransaction {
    fn decode_unfinished(rlp: &[u8]) -> Result<(FrameTransaction, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (nonce, decoder) = decode_nonce_field(decoder)?;
        let (sender, decoder) = decoder.decode_field("sender")?;
        let (frames, decoder) = decoder.decode_field("frames")?;
        let (signatures, decoder) = decoder.decode_field("signatures")?;
        // EIP-8141 `fees`: one nested `[max_priority, max_fee, max_fee_per_blob_gas]`
        // list, not three consecutive scalars. The tuple decoder rejects a list of
        // any other length, so a payload of the pre-revision shape fails here.
        let ((max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas), decoder): (
            (U256, U256, U256),
            _,
        ) = decoder.decode_field("fees")?;
        let (blob_versioned_hashes, decoder) = decoder.decode_field("blob_versioned_hashes")?;
        let tx = FrameTransaction {
            chain_id,
            nonce,
            sender,
            frames,
            signatures,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            max_fee_per_blob_gas,
            blob_versioned_hashes,
            inner_hash: OnceCell::new(),
            cached_canonical: OnceCell::new(),
        };
        Ok((tx, decoder.finish()?))
    }
}

impl PayloadRLPEncode for FrameTransaction {
    fn encode_payload(&self, buf: &mut dyn bytes::BufMut) {
        buf.put_u8(TxType::Frame as u8);
        self.encode(buf);
    }
}

/// Canonical Transaction Encoding
/// Based on [EIP-2718]
/// Transactions can be encoded in the following formats:
/// A) `TransactionType || Transaction` (Where Transaction type is an 8-bit number between 0 and 0x7f, and Transaction is an rlp encoded transaction of type TransactionType)
/// B) `LegacyTransaction` (An rlp encoded LegacyTransaction)
mod canonic_encoding {
    use super::*;

    impl Transaction {
        /// Decodes a single transaction in canonical format
        /// Based on [EIP-2718]
        /// Transactions can be encoded in the following formats:
        /// A) `TransactionType || Transaction` (Where Transaction type is an 8-bit number between 0 and 0x7f, and Transaction is an rlp encoded transaction of type TransactionType)
        /// B) `LegacyTransaction` (An rlp encoded LegacyTransaction)
        pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RLPDecodeError> {
            // Look at the first byte to check if it corresponds to a TransactionType
            match bytes.first() {
                // First byte is a valid TransactionType
                Some(tx_type) if *tx_type < 0x7f => {
                    // Decode tx based on type. `from_type_byte` is the single gate for valid
                    // envelope types: it rejects 0x00 (legacy is the bare-list branch below) and
                    // any unassigned type byte.
                    let tx_bytes = &bytes[1..];
                    match EnvelopeTxType::from_type_byte(*tx_type)? {
                        EnvelopeTxType::EIP2930 => EIP2930Transaction::decode(tx_bytes)
                            .map(Transaction::EIP2930Transaction),
                        EnvelopeTxType::EIP1559 => EIP1559Transaction::decode(tx_bytes)
                            .map(Transaction::EIP1559Transaction),
                        EnvelopeTxType::EIP4844 => EIP4844Transaction::decode(tx_bytes)
                            .map(Transaction::EIP4844Transaction),
                        EnvelopeTxType::EIP7702 => EIP7702Transaction::decode(tx_bytes)
                            .map(Transaction::EIP7702Transaction),
                        EnvelopeTxType::Frame => {
                            FrameTransaction::decode(tx_bytes).map(Transaction::FrameTransaction)
                        }
                        EnvelopeTxType::FeeToken => FeeTokenTransaction::decode(tx_bytes)
                            .map(Transaction::FeeTokenTransaction),
                        EnvelopeTxType::Privileged => PrivilegedL2Transaction::decode(tx_bytes)
                            .map(Transaction::PrivilegedL2Transaction),
                    }
                }
                // LegacyTransaction
                _ => LegacyTransaction::decode(bytes).map(Transaction::LegacyTransaction),
            }
        }

        /// Encodes a transaction in canonical format
        /// Based on [EIP-2718]
        /// Transactions can be encoded in the following formats:
        /// A) `TransactionType || Transaction` (Where Transaction type is an 8-bit number between 0 and 0x7f, and Transaction is an rlp encoded transaction of type TransactionType)
        /// B) `LegacyTransaction` (An rlp encoded LegacyTransaction)
        pub fn encode_canonical(&self, buf: &mut dyn bytes::BufMut) {
            match self {
                // Legacy transactions don't have a prefix
                Transaction::LegacyTransaction(_) => {}
                _ => buf.put_u8(self.tx_type() as u8),
            }
            match self {
                Transaction::LegacyTransaction(t) => t.encode(buf),
                Transaction::EIP2930Transaction(t) => t.encode(buf),
                Transaction::EIP1559Transaction(t) => t.encode(buf),
                Transaction::EIP4844Transaction(t) => t.encode(buf),
                Transaction::EIP7702Transaction(t) => t.encode(buf),
                Transaction::FeeTokenTransaction(t) => t.encode(buf),
                Transaction::PrivilegedL2Transaction(t) => t.encode(buf),
                Transaction::FrameTransaction(t) => t.encode(buf),
            };
        }

        /// Encodes a transaction in canonical format into a newly created buffer
        /// Based on [EIP-2718]
        /// Transactions can be encoded in the following formats:
        /// A) `TransactionType || Transaction` (Where Transaction type is an 8-bit number between 0 and 0x7f, and Transaction is an rlp encoded transaction of type TransactionType)
        /// B) `LegacyTransaction` (An rlp encoded LegacyTransaction)
        pub fn encode_canonical_to_vec(&self) -> Vec<u8> {
            if let Some(cell) = self.cached_canonical_cell() {
                return cell
                    .get_or_init(|| {
                        let mut buf = Vec::new();
                        self.encode_canonical(&mut buf);
                        buf
                    })
                    .clone();
            }
            let mut buf = Vec::new();
            self.encode_canonical(&mut buf);
            buf
        }

        /// Canonical-encoded length without allocating a buffer. Counts the
        /// 1-byte type prefix for typed txs (EIP-2718) plus the inner RLP
        /// payload length. Use this when only the size is needed (e.g.
        /// admission-time size caps) to avoid `encode_canonical_to_vec().len()`.
        pub fn encode_canonical_len(&self) -> usize {
            let prefix_len = match self {
                Transaction::LegacyTransaction(_) => 0,
                _ => 1,
            };
            let inner_len = match self {
                Transaction::LegacyTransaction(t) => t.length(),
                Transaction::EIP2930Transaction(t) => t.length(),
                Transaction::EIP1559Transaction(t) => t.length(),
                Transaction::EIP4844Transaction(t) => t.length(),
                Transaction::EIP7702Transaction(t) => t.length(),
                Transaction::FeeTokenTransaction(t) => t.length(),
                Transaction::PrivilegedL2Transaction(t) => t.length(),
                Transaction::FrameTransaction(t) => t.length(),
            };
            prefix_len + inner_len
        }
    }

    impl P2PTransaction {
        pub fn tx_type(&self) -> TxType {
            match self {
                P2PTransaction::LegacyTransaction(_) => TxType::Legacy,
                P2PTransaction::EIP2930Transaction(_) => TxType::EIP2930,
                P2PTransaction::EIP1559Transaction(_) => TxType::EIP1559,
                P2PTransaction::EIP4844TransactionWithBlobs(_) => TxType::EIP4844,
                P2PTransaction::EIP7702Transaction(_) => TxType::EIP7702,
                P2PTransaction::FeeTokenTransaction(_) => TxType::FeeToken,
                P2PTransaction::FrameTransaction(_) => TxType::Frame,
            }
        }

        pub fn encode_canonical(&self, buf: &mut dyn bytes::BufMut) {
            match self {
                // Legacy transactions don't have a prefix
                P2PTransaction::LegacyTransaction(_) => {}
                _ => buf.put_u8(self.tx_type() as u8),
            }
            match self {
                P2PTransaction::LegacyTransaction(t) => t.encode(buf),
                P2PTransaction::EIP2930Transaction(t) => t.encode(buf),
                P2PTransaction::EIP1559Transaction(t) => t.encode(buf),
                P2PTransaction::EIP4844TransactionWithBlobs(t) => t.encode(buf),
                P2PTransaction::EIP7702Transaction(t) => t.encode(buf),
                P2PTransaction::FeeTokenTransaction(t) => t.encode(buf),
                P2PTransaction::FrameTransaction(t) => t.encode(buf),
            };
        }

        pub fn encode_canonical_to_vec(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            self.encode_canonical(&mut buf);
            buf
        }

        /// Canonical encoded length without allocating (mirrors
        /// [`P2PTransaction::encode_canonical`]); equals
        /// `encode_canonical_to_vec().len()`. For the blob variant this includes
        /// the full sidecar, since `EIP4844TransactionWithBlobs` encodes it.
        pub fn encode_canonical_len(&self) -> usize {
            let prefix_len = match self {
                P2PTransaction::LegacyTransaction(_) => 0,
                _ => 1,
            };
            let inner_len = match self {
                P2PTransaction::LegacyTransaction(t) => t.length(),
                P2PTransaction::EIP2930Transaction(t) => t.length(),
                P2PTransaction::EIP1559Transaction(t) => t.length(),
                P2PTransaction::EIP4844TransactionWithBlobs(t) => t.length(),
                P2PTransaction::EIP7702Transaction(t) => t.length(),
                P2PTransaction::FeeTokenTransaction(t) => t.length(),
                P2PTransaction::FrameTransaction(t) => t.length(),
            };
            prefix_len + inner_len
        }

        pub fn compute_hash(&self) -> H256 {
            match self {
                P2PTransaction::LegacyTransaction(t) => {
                    Transaction::LegacyTransaction(t.clone()).compute_hash(&NativeCrypto)
                }
                P2PTransaction::EIP2930Transaction(t) => {
                    Transaction::EIP2930Transaction(t.clone()).compute_hash(&NativeCrypto)
                }
                P2PTransaction::EIP1559Transaction(t) => {
                    Transaction::EIP1559Transaction(t.clone()).compute_hash(&NativeCrypto)
                }
                P2PTransaction::EIP4844TransactionWithBlobs(t) => {
                    Transaction::EIP4844Transaction(t.tx.clone()).compute_hash(&NativeCrypto)
                }
                P2PTransaction::EIP7702Transaction(t) => {
                    Transaction::EIP7702Transaction(t.clone()).compute_hash(&NativeCrypto)
                }
                P2PTransaction::FeeTokenTransaction(t) => {
                    Transaction::FeeTokenTransaction(t.clone()).compute_hash(&NativeCrypto)
                }
                P2PTransaction::FrameTransaction(t) => {
                    Transaction::FrameTransaction(t.clone()).compute_hash(&NativeCrypto)
                }
            }
        }
    }
}

// Serialization
// This is used for RPC messaging and passing data into a RISC-V zkVM

mod serde_impl {
    use ethereum_types::H160;
    use serde::Deserialize;
    use serde::{Deserializer, de::Error};
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};

    #[cfg(feature = "c-kzg")]
    use crate::types::BYTES_PER_BLOB;
    use crate::types::{AccessListItem, AuthorizationTuple, BlobsBundleError};

    use super::*;

    impl Serialize for TxKind {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                TxKind::Call(address) => serializer.serialize_str(&format!("{address:#x}")),
                TxKind::Create => serializer.serialize_none(),
            }
        }
    }

    impl<'de> Deserialize<'de> for TxKind {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let str_option = Option::<String>::deserialize(deserializer)?;
            match str_option {
                Some(str) if !str.is_empty() => Ok(TxKind::Call(
                    Address::from_str(str.trim_start_matches("0x")).map_err(|_| {
                        serde::de::Error::custom(format!("Failed to deserialize hex value {str}"))
                    })?,
                )),
                _ => Ok(TxKind::Create),
            }
        }
    }

    impl Serialize for TxType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&format!("{:#x}", *self as u8))
        }
    }

    impl<'de> Deserialize<'de> for TxType {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let str = String::deserialize(deserializer)?;
            let tx_num = u8::from_str_radix(str.trim_start_matches("0x"), 16).map_err(|_| {
                serde::de::Error::custom(format!("Failed to deserialize hex value {str}"))
            })?;
            TxType::from_u8(tx_num).ok_or_else(|| {
                serde::de::Error::custom(format!("Invalid transaction type {tx_num}"))
            })
        }
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct AccessListEntry {
        pub address: Address,
        pub storage_keys: Vec<H256>,
    }

    impl From<&AccessListItem> for AccessListEntry {
        fn from(value: &AccessListItem) -> AccessListEntry {
            AccessListEntry {
                address: value.0,
                storage_keys: value.1.clone(),
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct AuthorizationTupleEntry {
        pub chain_id: U256,
        pub address: Address,
        #[serde(default, with = "crate::serde_utils::u64::hex_str")]
        pub nonce: u64,
        pub y_parity: U256,
        pub r: U256,
        pub s: U256,
    }

    impl From<&AuthorizationTuple> for AuthorizationTupleEntry {
        fn from(value: &AuthorizationTuple) -> AuthorizationTupleEntry {
            AuthorizationTupleEntry {
                chain_id: value.chain_id,
                address: value.address,
                nonce: value.nonce,
                y_parity: value.y_parity,
                r: value.r_signature,
                s: value.s_signature,
            }
        }
    }

    impl From<AuthorizationTupleEntry> for AuthorizationTuple {
        fn from(entry: AuthorizationTupleEntry) -> AuthorizationTuple {
            AuthorizationTuple {
                chain_id: entry.chain_id,
                address: entry.address,
                nonce: entry.nonce,
                y_parity: entry.y_parity,
                r_signature: entry.r,
                s_signature: entry.s,
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct FrameEntry {
        #[serde(with = "crate::serde_utils::u64::hex_str")]
        pub mode: u64,
        #[serde(with = "crate::serde_utils::u64::hex_str")]
        pub flags: u64,
        pub to: Option<Address>,
        #[serde(with = "crate::serde_utils::u64::hex_str")]
        pub gas_limit: u64,
        /// EIP-8141 exposes a frame's two gas budgets separately; `gasLimit` is
        /// the execution dimension and `stateGasLimit` the state dimension.
        #[serde(with = "crate::serde_utils::u64::hex_str")]
        pub state_gas_limit: u64,
        #[serde(
            default,
            serialize_with = "serialize_u256_hex",
            deserialize_with = "crate::serde_utils::u256::deser_hex_str"
        )]
        pub value: U256,
        #[serde(with = "crate::serde_utils::bytes")]
        pub data: Bytes,
    }

    /// JSON shape of an EIP-8141 outer signature.
    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct SignatureEntry {
        #[serde(with = "crate::serde_utils::u64::hex_str")]
        pub scheme: u64,
        pub signer: Option<Address>,
        #[serde(with = "crate::serde_utils::bytes")]
        pub msg: Bytes,
        #[serde(with = "crate::serde_utils::bytes")]
        pub signature: Bytes,
    }

    impl From<&FrameSignature> for SignatureEntry {
        fn from(value: &FrameSignature) -> SignatureEntry {
            SignatureEntry {
                scheme: value.scheme as u64,
                signer: value.signer,
                msg: value.msg.clone(),
                signature: value.signature.clone(),
            }
        }
    }

    fn serialize_u256_hex<S: serde::Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{value:#x}"))
    }

    impl From<&Frame> for FrameEntry {
        fn from(value: &Frame) -> FrameEntry {
            FrameEntry {
                mode: value.mode as u64,
                flags: value.flags as u64,
                to: value.target,
                gas_limit: value.gas_limits.execution,
                state_gas_limit: value.gas_limits.state,
                value: value.value,
                data: value.data.clone(),
            }
        }
    }

    impl From<FrameEntry> for Frame {
        fn from(entry: FrameEntry) -> Frame {
            Frame {
                mode: entry.mode as u8,
                flags: entry.flags as u8,
                target: entry.to,
                gas_limits: GasLimits {
                    execution: entry.gas_limit,
                    state: entry.state_gas_limit,
                },
                value: entry.value,
                data: entry.data,
            }
        }
    }

    impl Serialize for LegacyTransaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("LegacyTransaction", 11)?;
            struct_serializer.serialize_field("type", &TxType::Legacy)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field("gasPrice", &format!("{:#x}", self.gas_price))?;
            struct_serializer.serialize_field(
                "chainId",
                &format!("{:#x}", derive_legacy_chain_id(self.v).unwrap_or_default()),
            )?;
            struct_serializer.serialize_field("v", &self.v)?;
            struct_serializer.serialize_field("r", &self.r)?;
            struct_serializer.serialize_field("s", &self.s)?;
            struct_serializer.end()
        }
    }

    impl Serialize for EIP2930Transaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("Eip2930Transaction", 12)?;
            struct_serializer.serialize_field("type", &TxType::EIP2930)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas_limit))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field("gasPrice", &format!("{:#x}", self.gas_price))?;
            struct_serializer.serialize_field(
                "accessList",
                &self
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            struct_serializer
                .serialize_field("yParity", &format!("{:#x}", self.signature_y_parity as u8))?;
            struct_serializer
                .serialize_field("v", &format!("{:#x}", self.signature_y_parity as u8))?; // added to match Hive tests
            struct_serializer.serialize_field("r", &self.signature_r)?;
            struct_serializer.serialize_field("s", &self.signature_s)?;
            struct_serializer.end()
        }
    }

    impl Serialize for EIP1559Transaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("Eip1559Transaction", 14)?;
            struct_serializer.serialize_field("type", &TxType::EIP1559)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas_limit))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field(
                "maxPriorityFeePerGas",
                &format!("{:#x}", self.max_priority_fee_per_gas),
            )?;
            struct_serializer
                .serialize_field("maxFeePerGas", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer
                .serialize_field("gasPrice", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer.serialize_field(
                "accessList",
                &self
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            struct_serializer
                .serialize_field("yParity", &format!("{:#x}", self.signature_y_parity as u8))?;
            struct_serializer
                .serialize_field("v", &format!("{:#x}", self.signature_y_parity as u8))?; // added to match Hive tests
            struct_serializer.serialize_field("r", &self.signature_r)?;
            struct_serializer.serialize_field("s", &self.signature_s)?;
            struct_serializer.end()
        }
    }

    impl Serialize for EIP4844Transaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("Eip4844Transaction", 15)?;
            struct_serializer.serialize_field("type", &TxType::EIP4844)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field(
                "maxPriorityFeePerGas",
                &format!("{:#x}", self.max_priority_fee_per_gas),
            )?;
            struct_serializer
                .serialize_field("maxFeePerGas", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer
                .serialize_field("gasPrice", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer.serialize_field(
                "maxFeePerBlobGas",
                &format!("{:#x}", self.max_fee_per_blob_gas),
            )?;
            struct_serializer.serialize_field(
                "accessList",
                &self
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer
                .serialize_field("blobVersionedHashes", &self.blob_versioned_hashes)?;
            struct_serializer.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            struct_serializer
                .serialize_field("yParity", &format!("{:#x}", self.signature_y_parity as u8))?;
            struct_serializer
                .serialize_field("v", &format!("{:#x}", self.signature_y_parity as u8))?; // added to match Hive tests
            struct_serializer.serialize_field("r", &self.signature_r)?;
            struct_serializer.serialize_field("s", &self.signature_s)?;
            struct_serializer.end()
        }
    }

    impl Serialize for EIP7702Transaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("Eip7702Transaction", 15)?;
            struct_serializer.serialize_field("type", &TxType::EIP7702)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas_limit))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field(
                "maxPriorityFeePerGas",
                &format!("{:#x}", self.max_priority_fee_per_gas),
            )?;
            struct_serializer
                .serialize_field("maxFeePerGas", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer
                .serialize_field("gasPrice", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer.serialize_field(
                "accessList",
                &self
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer.serialize_field(
                "authorizationList",
                &self
                    .authorization_list
                    .iter()
                    .map(AuthorizationTupleEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            struct_serializer
                .serialize_field("yParity", &format!("{:#x}", self.signature_y_parity as u8))?;
            struct_serializer
                .serialize_field("v", &format!("{:#x}", self.signature_y_parity as u8))?; // added to match Hive tests
            struct_serializer.serialize_field("r", &self.signature_r)?;
            struct_serializer.serialize_field("s", &self.signature_s)?;
            struct_serializer.end()
        }
    }

    impl Serialize for PrivilegedL2Transaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("Eip1559Transaction", 14)?;
            struct_serializer.serialize_field("type", &TxType::Privileged)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas_limit))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field(
                "maxPriorityFeePerGas",
                &format!("{:#x}", self.max_priority_fee_per_gas),
            )?;
            struct_serializer
                .serialize_field("maxFeePerGas", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer
                .serialize_field("gasPrice", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer.serialize_field(
                "accessList",
                &self
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            struct_serializer.serialize_field("sender", &self.from)?;
            struct_serializer.end()
        }
    }

    impl Serialize for FeeTokenTransaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut struct_serializer = serializer.serialize_struct("FeeTokenTransaction", 15)?;
            struct_serializer.serialize_field("type", &TxType::FeeToken)?;
            struct_serializer.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            struct_serializer.serialize_field("to", &self.to)?;
            struct_serializer.serialize_field("gas", &format!("{:#x}", self.gas_limit))?;
            struct_serializer.serialize_field("value", &self.value)?;
            struct_serializer.serialize_field("input", &format!("0x{:x}", self.data))?;
            struct_serializer.serialize_field(
                "maxPriorityFeePerGas",
                &format!("{:#x}", self.max_priority_fee_per_gas),
            )?;
            struct_serializer
                .serialize_field("maxFeePerGas", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer
                .serialize_field("gasPrice", &format!("{:#x}", self.max_fee_per_gas))?;
            struct_serializer.serialize_field(
                "accessList",
                &self
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            struct_serializer.serialize_field("feeToken", &format!("{:#x}", self.fee_token))?;
            struct_serializer.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            struct_serializer
                .serialize_field("yParity", &format!("{:#x}", self.signature_y_parity as u8))?;
            struct_serializer
                .serialize_field("v", &format!("{:#x}", self.signature_y_parity as u8))?;
            struct_serializer.serialize_field("r", &self.signature_r)?;
            struct_serializer.serialize_field("s", &self.signature_s)?;
            struct_serializer.end()
        }
    }

    impl Serialize for FrameTransaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut s = serializer.serialize_struct("FrameTransaction", 10)?;
            s.serialize_field("type", &TxType::Frame)?;
            s.serialize_field("chainId", &format!("{:#x}", self.chain_id))?;
            s.serialize_field("nonce", &format!("{:#x}", self.nonce))?;
            s.serialize_field("sender", &format!("{:#x}", self.sender))?;
            s.serialize_field(
                "frames",
                &self.frames.iter().map(FrameEntry::from).collect::<Vec<_>>(),
            )?;
            s.serialize_field(
                "signatures",
                &self
                    .signatures
                    .iter()
                    .map(SignatureEntry::from)
                    .collect::<Vec<_>>(),
            )?;
            s.serialize_field(
                "maxPriorityFeePerGas",
                &format!("{:#x}", self.max_priority_fee_per_gas),
            )?;
            s.serialize_field("maxFeePerGas", &format!("{:#x}", self.max_fee_per_gas))?;
            s.serialize_field("maxFeePerBlobGas", &self.max_fee_per_blob_gas)?;
            s.serialize_field("blobVersionedHashes", &self.blob_versioned_hashes)?;
            s.end()
        }
    }

    impl<'de> Deserialize<'de> for Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;
            let tx_type =
                serde_json::from_value::<TxType>(map.remove("type").unwrap_or(Value::default()))
                    .unwrap_or_else(|_| {
                        if map.contains_key("tx_type") {
                            return TxType::Privileged;
                        }
                        TxType::EIP1559
                    });

            let iter = map.into_iter();
            match tx_type {
                TxType::Legacy => {
                    LegacyTransaction::deserialize(serde::de::value::MapDeserializer::new(iter))
                        .map(Transaction::LegacyTransaction)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("Couldn't Deserialize Legacy {e}"))
                        })
                }
                TxType::EIP2930 => {
                    EIP2930Transaction::deserialize(serde::de::value::MapDeserializer::new(iter))
                        .map(Transaction::EIP2930Transaction)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("Couldn't Deserialize EIP2930 {e}"))
                        })
                }
                TxType::EIP1559 => {
                    EIP1559Transaction::deserialize(serde::de::value::MapDeserializer::new(iter))
                        .map(Transaction::EIP1559Transaction)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("Couldn't Deserialize EIP1559 {e}"))
                        })
                }
                TxType::EIP4844 => {
                    EIP4844Transaction::deserialize(serde::de::value::MapDeserializer::new(iter))
                        .map(Transaction::EIP4844Transaction)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("Couldn't Deserialize EIP4844 {e}"))
                        })
                }
                TxType::EIP7702 => {
                    EIP7702Transaction::deserialize(serde::de::value::MapDeserializer::new(iter))
                        .map(Transaction::EIP7702Transaction)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("Couldn't Deserialize EIP7702 {e}"))
                        })
                }
                TxType::Privileged => PrivilegedL2Transaction::deserialize(
                    serde::de::value::MapDeserializer::new(iter),
                )
                .map(Transaction::PrivilegedL2Transaction)
                .map_err(|e| {
                    serde::de::Error::custom(format!("Couldn't Deserialize Privileged: {e}"))
                }),
                TxType::FeeToken => {
                    FeeTokenTransaction::deserialize(serde::de::value::MapDeserializer::new(iter))
                        .map(Transaction::FeeTokenTransaction)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("Couldn't Deserialize FeeToken {e}"))
                        })
                }
                TxType::Frame => Err(serde::de::Error::custom(
                    "Frame transaction JSON deserialization not supported",
                )),
            }
        }
    }

    fn deserialize_input_field(
        map: &mut std::collections::HashMap<String, Value>,
    ) -> Result<Bytes, serde_json::Error> {
        let data_str: String = serde_json::from_value(
            map.remove("input")
                .ok_or_else(|| serde::de::Error::missing_field("input"))?,
        )
        .map_err(serde::de::Error::custom)?;
        if let Some(stripped) = data_str.strip_prefix("0x") {
            match hex::decode(stripped) {
                Ok(decoded_bytes) => Ok(Bytes::from(decoded_bytes)),
                Err(_) => Err(serde::de::Error::custom(
                    "Invalid hex format in 'input' field",
                ))?,
            }
        } else {
            Err(serde::de::Error::custom(
                "'input' field must start with '0x'",
            ))?
        }
    }

    fn deserialize_field<'de, T, D>(
        map: &mut HashMap<String, serde_json::Value>,
        key: &str,
    ) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: serde::de::DeserializeOwned,
    {
        map.remove(key)
            .ok_or_else(|| D::Error::custom(format!("Missing field: {key}")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|err| D::Error::custom(err.to_string()))
            })
    }

    fn deserialize_u64_field<'de, D>(
        map: &mut HashMap<String, serde_json::Value>,
        key: &str,
    ) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = deserialize_field::<U256, D>(map, key)?;
        u64::try_from(value).map_err(|_| D::Error::custom(format!("{key} value overflows u64")))
    }

    impl<'de> Deserialize<'de> for LegacyTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;

            Ok(LegacyTransaction {
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                gas_price: deserialize_field::<U256, D>(&mut map, "gasPrice")?,
                gas: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<TxKind, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                v: deserialize_field::<U256, D>(&mut map, "v")?,
                r: deserialize_field::<U256, D>(&mut map, "r")?,
                s: deserialize_field::<U256, D>(&mut map, "s")?,
                ..Default::default()
            })
        }
    }

    impl<'de> Deserialize<'de> for EIP2930Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;

            Ok(EIP2930Transaction {
                chain_id: deserialize_u64_field::<D>(&mut map, "chainId")?,
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                gas_price: deserialize_field::<U256, D>(&mut map, "gasPrice")?,
                gas_limit: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<TxKind, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                access_list: deserialize_field::<Vec<AccessListEntry>, D>(&mut map, "accessList")?
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                signature_y_parity: u8::from_str_radix(
                    deserialize_field::<String, D>(&mut map, "yParity")?.trim_start_matches("0x"),
                    16,
                )
                .map_err(serde::de::Error::custom)?
                    != 0,
                signature_r: deserialize_field::<U256, D>(&mut map, "r")?,
                signature_s: deserialize_field::<U256, D>(&mut map, "s")?,
                ..Default::default()
            })
        }
    }

    impl<'de> Deserialize<'de> for EIP1559Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;
            Ok(EIP1559Transaction {
                chain_id: deserialize_u64_field::<D>(&mut map, "chainId")?,
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                max_priority_fee_per_gas: deserialize_u64_field::<D>(
                    &mut map,
                    "maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: deserialize_u64_field::<D>(&mut map, "maxFeePerGas")?,
                gas_limit: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<TxKind, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                access_list: deserialize_field::<Vec<AccessListEntry>, D>(&mut map, "accessList")?
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                signature_y_parity: u8::from_str_radix(
                    deserialize_field::<String, D>(&mut map, "yParity")?.trim_start_matches("0x"),
                    16,
                )
                .map_err(serde::de::Error::custom)?
                    != 0,
                signature_r: deserialize_field::<U256, D>(&mut map, "r")?,
                signature_s: deserialize_field::<U256, D>(&mut map, "s")?,
                ..Default::default()
            })
        }
    }

    impl<'de> Deserialize<'de> for EIP4844Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;

            Ok(EIP4844Transaction {
                chain_id: deserialize_u64_field::<D>(&mut map, "chainId")?,
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                max_priority_fee_per_gas: deserialize_u64_field::<D>(
                    &mut map,
                    "maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: deserialize_u64_field::<D>(&mut map, "maxFeePerGas")?,
                gas: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<Address, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                access_list: deserialize_field::<Vec<AccessListEntry>, D>(&mut map, "accessList")?
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                max_fee_per_blob_gas: deserialize_field::<U256, D>(&mut map, "maxFeePerBlobGas")?,
                blob_versioned_hashes: deserialize_field::<Vec<H256>, D>(
                    &mut map,
                    "blobVersionedHashes",
                )?,
                signature_y_parity: u8::from_str_radix(
                    deserialize_field::<String, D>(&mut map, "yParity")?.trim_start_matches("0x"),
                    16,
                )
                .map_err(serde::de::Error::custom)?
                    != 0,
                signature_r: deserialize_field::<U256, D>(&mut map, "r")?,
                signature_s: deserialize_field::<U256, D>(&mut map, "s")?,
                ..Default::default()
            })
        }
    }

    impl<'de> Deserialize<'de> for EIP7702Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;

            Ok(EIP7702Transaction {
                chain_id: deserialize_u64_field::<D>(&mut map, "chainId")?,
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                max_priority_fee_per_gas: deserialize_u64_field::<D>(
                    &mut map,
                    "maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: deserialize_u64_field::<D>(&mut map, "maxFeePerGas")?,
                gas_limit: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<Address, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                access_list: deserialize_field::<Vec<AccessListEntry>, D>(&mut map, "accessList")?
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                authorization_list: deserialize_field::<Vec<AuthorizationTupleEntry>, D>(
                    &mut map,
                    "authorizationList",
                )?
                .into_iter()
                .map(AuthorizationTuple::from)
                .collect::<Vec<_>>(),
                signature_y_parity: u8::from_str_radix(
                    deserialize_field::<String, D>(&mut map, "yParity")?.trim_start_matches("0x"),
                    16,
                )
                .map_err(serde::de::Error::custom)?
                    != 0,
                signature_r: deserialize_field::<U256, D>(&mut map, "r")?,
                signature_s: deserialize_field::<U256, D>(&mut map, "s")?,
                ..Default::default()
            })
        }
    }

    impl<'de> Deserialize<'de> for PrivilegedL2Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;

            Ok(PrivilegedL2Transaction {
                chain_id: deserialize_u64_field::<D>(&mut map, "chainId")?,
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                max_priority_fee_per_gas: deserialize_u64_field::<D>(
                    &mut map,
                    "maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: deserialize_u64_field::<D>(&mut map, "maxFeePerGas")?,
                gas_limit: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<TxKind, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                access_list: deserialize_field::<Vec<AccessListEntry>, D>(&mut map, "accessList")?
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                from: deserialize_field::<Address, D>(&mut map, "sender")?,
                ..Default::default()
            })
        }
    }

    impl<'de> Deserialize<'de> for FeeTokenTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut map = <HashMap<String, serde_json::Value>>::deserialize(deserializer)?;

            Ok(FeeTokenTransaction {
                chain_id: deserialize_u64_field::<D>(&mut map, "chainId")?,
                nonce: deserialize_u64_field::<D>(&mut map, "nonce")?,
                max_priority_fee_per_gas: deserialize_u64_field::<D>(
                    &mut map,
                    "maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: deserialize_u64_field::<D>(&mut map, "maxFeePerGas")?,
                gas_limit: deserialize_u64_field::<D>(&mut map, "gas")?,
                to: deserialize_field::<TxKind, D>(&mut map, "to")?,
                value: deserialize_field::<U256, D>(&mut map, "value")?,
                data: deserialize_input_field(&mut map).map_err(serde::de::Error::custom)?,
                access_list: deserialize_field::<Vec<AccessListEntry>, D>(&mut map, "accessList")?
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                fee_token: deserialize_field::<Address, D>(&mut map, "feeToken")?,
                signature_y_parity: u8::from_str_radix(
                    deserialize_field::<String, D>(&mut map, "yParity")?.trim_start_matches("0x"),
                    16,
                )
                .map_err(serde::de::Error::custom)?
                    != 0,
                signature_r: deserialize_field::<U256, D>(&mut map, "r")?,
                signature_s: deserialize_field::<U256, D>(&mut map, "s")?,
                ..Default::default()
            })
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum GenericTransactionError {
        #[error("Invalid transaction type: {0}")]
        InvalidTxType(TxType),
        #[error("Blob bundle error: {0}")]
        BlobBundleError(#[from] BlobsBundleError),
        #[error("Missing field: {0}")]
        MissingField(String),
        #[error("Invalid field: {0}")]
        InvalidField(String),
    }

    /// Unsigned Transaction struct generic to all types which may not contain all required transaction fields
    /// Used to perform gas estimations and access list creation
    #[derive(Deserialize, Debug, PartialEq, Clone, Default)]
    #[serde(rename_all = "camelCase")]
    pub struct GenericTransaction {
        #[serde(default)]
        pub r#type: TxType,
        #[serde(default, with = "crate::serde_utils::u64::hex_str_opt")]
        pub nonce: Option<u64>,
        pub to: TxKind,
        #[serde(default)]
        pub from: Address,
        #[serde(default, with = "crate::serde_utils::u64::hex_str_opt")]
        pub gas: Option<u64>,
        #[serde(default)]
        pub value: U256,
        #[serde(default)]
        pub gas_price: U256,
        #[serde(default, with = "crate::serde_utils::u64::hex_str_opt")]
        pub max_priority_fee_per_gas: Option<u64>,
        #[serde(default, with = "crate::serde_utils::u64::hex_str_opt")]
        pub max_fee_per_gas: Option<u64>,
        pub max_fee_per_blob_gas: Option<U256>,
        #[serde(default)]
        pub access_list: Vec<AccessListEntry>,
        #[serde(default)]
        pub fee_token: Option<Address>,
        #[serde(default)]
        pub authorization_list: Option<Vec<AuthorizationTupleEntry>>,
        #[serde(default)]
        pub blob_versioned_hashes: Vec<H256>,
        pub wrapper_version: Option<u8>,
        #[serde(default, with = "crate::serde_utils::bytes::vec")]
        pub blobs: Vec<Bytes>,
        #[serde(default, with = "crate::serde_utils::u64::hex_str_opt")]
        pub chain_id: Option<u64>,
        // rename is needed here so we dont attempt to deserialize the `input` field rather than the remainder of the fields
        #[serde(
            flatten,
            rename = "input_or_data",
            deserialize_with = "deserialize_input",
            serialize_with = "crate::serde_utils::bytes::serialize"
        )]
        pub input: Bytes,
    }
    /// Custom deserialization function to parse either `data` or `input` fields, or both as long as they have the same value
    pub fn deserialize_input<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        // The input field can be named either input or data
        // In case we have both fields both should be named the same
        let variables = HashMap::<String, Value>::deserialize(deserializer)?;
        let data = variables.get("data");
        let input = variables.get("input");
        let value = match (data, input) {
            // This replaces `default` attribute for this custom implementation
            (None, None) => return Ok(Bytes::new()),
            (None, Some(val)) => val,
            (Some(val), None) => val,
            (Some(val_a), Some(val_b)) => {
                if val_a == val_b {
                    val_a
                } else {
                    return Err(D::Error::custom(
                        "Transaction has both `data` and `input` fields with different values",
                    ));
                }
            }
        };
        let value = String::deserialize(value).map_err(D::Error::custom)?;
        let bytes = hex::decode(value.trim_start_matches("0x"))
            .map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(Bytes::from(bytes))
    }

    impl From<EIP1559Transaction> for GenericTransaction {
        fn from(value: EIP1559Transaction) -> Self {
            Self {
                r#type: TxType::EIP1559,
                nonce: Some(value.nonce),
                to: value.to,
                gas: Some(value.gas_limit),
                value: value.value,
                input: value.data.clone(),
                gas_price: U256::from(value.max_fee_per_gas),
                max_priority_fee_per_gas: Some(value.max_priority_fee_per_gas),
                max_fee_per_gas: Some(value.max_fee_per_gas),
                max_fee_per_blob_gas: None,
                access_list: value
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect(),
                fee_token: None,
                authorization_list: None,
                blob_versioned_hashes: vec![],
                blobs: vec![],
                wrapper_version: None,
                chain_id: Some(value.chain_id),
                from: Address::default(),
            }
        }
    }

    impl TryFrom<GenericTransaction> for EIP1559Transaction {
        type Error = GenericTransactionError;

        fn try_from(value: GenericTransaction) -> Result<Self, Self::Error> {
            if value.r#type != TxType::EIP1559 {
                return Err(GenericTransactionError::InvalidTxType(value.r#type));
            }

            Ok(Self {
                nonce: value.nonce.unwrap_or_default(),
                to: value.to,
                gas_limit: value.gas.unwrap_or_default(),
                value: value.value,
                data: value.input.clone(),
                max_priority_fee_per_gas: value.max_priority_fee_per_gas.unwrap_or_default(),
                max_fee_per_gas: value.max_fee_per_gas.unwrap_or(
                    u64::try_from(value.gas_price).map_err(|_| {
                        GenericTransactionError::InvalidField("gas_price overflows u64".to_owned())
                    })?,
                ),
                access_list: value
                    .access_list
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                chain_id: value.chain_id.unwrap_or_default(),
                ..Default::default()
            })
        }
    }

    impl From<EIP4844Transaction> for GenericTransaction {
        fn from(value: EIP4844Transaction) -> Self {
            Self {
                r#type: TxType::EIP4844,
                nonce: Some(value.nonce),
                to: TxKind::Call(value.to),
                gas: Some(value.gas),
                value: value.value,
                input: value.data.clone(),
                gas_price: U256::from(value.max_fee_per_gas),
                max_priority_fee_per_gas: Some(value.max_priority_fee_per_gas),
                max_fee_per_gas: Some(value.max_fee_per_gas),
                max_fee_per_blob_gas: Some(value.max_fee_per_blob_gas),
                access_list: value
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect(),
                fee_token: None,
                authorization_list: None,
                blob_versioned_hashes: value.blob_versioned_hashes,
                blobs: vec![],
                wrapper_version: None,
                chain_id: Some(value.chain_id),
                from: Address::default(),
            }
        }
    }

    #[cfg(feature = "c-kzg")]
    impl TryFrom<GenericTransaction> for WrappedEIP4844Transaction {
        type Error = GenericTransactionError;

        fn try_from(value: GenericTransaction) -> Result<Self, Self::Error> {
            let blobs = value
                .blobs
                .iter()
                .map(|bytes| {
                    let slice = bytes.as_ref();
                    let mut blob = [0u8; BYTES_PER_BLOB];
                    blob.copy_from_slice(slice);
                    blob
                })
                .collect();

            let wrapper_version = value.wrapper_version;
            Ok(Self {
                tx: value.try_into()?,
                wrapper_version,
                blobs_bundle: BlobsBundle::create_from_blobs(&blobs, wrapper_version)?,
            })
        }
    }

    impl TryFrom<GenericTransaction> for EIP4844Transaction {
        type Error = GenericTransactionError;

        fn try_from(value: GenericTransaction) -> Result<Self, Self::Error> {
            if value.r#type != TxType::EIP4844 {
                return Err(GenericTransactionError::InvalidTxType(value.r#type));
            }
            Ok(Self {
                nonce: value.nonce.unwrap_or_default(),
                to: match value.to {
                    TxKind::Call(to) => to,
                    _ => H160::default(),
                },
                gas: value.gas.unwrap_or_default(),
                value: value.value,
                data: value.input.clone(),
                max_priority_fee_per_gas: value.max_priority_fee_per_gas.unwrap_or_default(),
                max_fee_per_gas: value.max_fee_per_gas.unwrap_or(
                    u64::try_from(value.gas_price).map_err(|_| {
                        GenericTransactionError::InvalidField("gas_price overflows u64".to_owned())
                    })?,
                ),
                max_fee_per_blob_gas: value.max_fee_per_blob_gas.unwrap_or_default(),
                access_list: value
                    .access_list
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                blob_versioned_hashes: value.blob_versioned_hashes,
                chain_id: value.chain_id.unwrap_or_default(),
                ..Default::default()
            })
        }
    }

    impl From<EIP7702Transaction> for GenericTransaction {
        fn from(value: EIP7702Transaction) -> Self {
            Self {
                r#type: TxType::EIP7702,
                nonce: Some(value.nonce),
                to: TxKind::Call(value.to),
                gas: Some(value.gas_limit),
                value: value.value,
                input: value.data.clone(),
                gas_price: U256::from(value.max_fee_per_gas),
                max_priority_fee_per_gas: Some(value.max_priority_fee_per_gas),
                max_fee_per_gas: Some(value.max_fee_per_gas),
                max_fee_per_blob_gas: None,
                access_list: value
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect(),
                fee_token: None,
                authorization_list: Some(
                    value
                        .authorization_list
                        .iter()
                        .map(AuthorizationTupleEntry::from)
                        .collect(),
                ),
                blob_versioned_hashes: vec![],
                blobs: vec![],
                wrapper_version: None,
                chain_id: Some(value.chain_id),
                from: Address::default(),
            }
        }
    }

    impl TryFrom<GenericTransaction> for EIP7702Transaction {
        type Error = GenericTransactionError;

        fn try_from(value: GenericTransaction) -> Result<Self, Self::Error> {
            if value.r#type != TxType::EIP7702 {
                return Err(GenericTransactionError::InvalidTxType(value.r#type));
            }
            let TxKind::Call(to) = value.to else {
                return Err(GenericTransactionError::MissingField("to".to_owned()));
            };
            Ok(Self {
                chain_id: value.chain_id.unwrap_or_default(),
                nonce: value.nonce.unwrap_or_default(),
                max_priority_fee_per_gas: value.max_priority_fee_per_gas.unwrap_or_default(),
                max_fee_per_gas: value.max_fee_per_gas.unwrap_or(
                    u64::try_from(value.gas_price).map_err(|_| {
                        GenericTransactionError::InvalidField("gas_price overflows u64".to_owned())
                    })?,
                ),
                gas_limit: value.gas.unwrap_or_default(),
                to,
                value: value.value,
                data: value.input,
                access_list: value
                    .access_list
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                authorization_list: value
                    .authorization_list
                    .unwrap_or_default()
                    .into_iter()
                    .map(AuthorizationTuple::from)
                    .collect(),
                ..Default::default()
            })
        }
    }

    impl From<PrivilegedL2Transaction> for GenericTransaction {
        fn from(value: PrivilegedL2Transaction) -> Self {
            Self {
                r#type: TxType::Privileged,
                nonce: Some(value.nonce),
                to: value.to,
                gas: Some(value.gas_limit),
                value: value.value,
                input: value.data.clone(),
                gas_price: U256::from(value.max_fee_per_gas),
                max_priority_fee_per_gas: Some(value.max_priority_fee_per_gas),
                max_fee_per_gas: Some(value.max_fee_per_gas),
                max_fee_per_blob_gas: None,
                access_list: value
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect(),
                fee_token: None,
                authorization_list: None,
                blob_versioned_hashes: vec![],
                blobs: vec![],
                wrapper_version: None,
                chain_id: Some(value.chain_id),
                from: value.from,
            }
        }
    }

    impl TryFrom<GenericTransaction> for PrivilegedL2Transaction {
        type Error = GenericTransactionError;

        fn try_from(value: GenericTransaction) -> Result<Self, Self::Error> {
            if value.r#type != TxType::Privileged {
                return Err(GenericTransactionError::InvalidTxType(value.r#type));
            }
            Ok(Self {
                nonce: value.nonce.unwrap_or_default(),
                to: value.to,
                gas_limit: value.gas.unwrap_or_default(),
                value: value.value,
                data: value.input.clone(),
                max_priority_fee_per_gas: value.max_priority_fee_per_gas.unwrap_or_default(),
                max_fee_per_gas: value.max_fee_per_gas.unwrap_or(
                    u64::try_from(value.gas_price).map_err(|_| {
                        GenericTransactionError::InvalidField("gas_price overflows u64".to_owned())
                    })?,
                ),
                access_list: value
                    .access_list
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                chain_id: value.chain_id.unwrap_or_default(),
                from: value.from,
                ..Default::default()
            })
        }
    }

    impl From<FeeTokenTransaction> for GenericTransaction {
        fn from(value: FeeTokenTransaction) -> Self {
            Self {
                r#type: TxType::FeeToken,
                nonce: Some(value.nonce),
                to: value.to,
                gas: Some(value.gas_limit),
                value: value.value,
                input: value.data.clone(),
                gas_price: U256::from(value.max_fee_per_gas),
                max_priority_fee_per_gas: Some(value.max_priority_fee_per_gas),
                max_fee_per_gas: Some(value.max_fee_per_gas),
                max_fee_per_blob_gas: None,
                access_list: value
                    .access_list
                    .iter()
                    .map(AccessListEntry::from)
                    .collect(),
                fee_token: Some(value.fee_token),
                authorization_list: None,
                blob_versioned_hashes: vec![],
                blobs: vec![],
                chain_id: Some(value.chain_id),
                from: Address::default(),
                wrapper_version: None,
            }
        }
    }

    impl TryFrom<GenericTransaction> for FeeTokenTransaction {
        type Error = GenericTransactionError;

        fn try_from(value: GenericTransaction) -> Result<Self, Self::Error> {
            if value.r#type != TxType::FeeToken {
                return Err(GenericTransactionError::InvalidTxType(value.r#type));
            }

            Ok(Self {
                nonce: value.nonce.unwrap_or_default(),
                to: value.to,
                gas_limit: value.gas.unwrap_or_default(),
                value: value.value,
                data: value.input.clone(),
                max_priority_fee_per_gas: value.max_priority_fee_per_gas.unwrap_or_default(),
                max_fee_per_gas: value.max_fee_per_gas.unwrap_or(
                    u64::try_from(value.gas_price).map_err(|_| {
                        GenericTransactionError::InvalidField("gas_price overflows u64".to_owned())
                    })?,
                ),
                access_list: value
                    .access_list
                    .into_iter()
                    .map(|v| (v.address, v.storage_keys))
                    .collect::<Vec<_>>(),
                fee_token: value
                    .fee_token
                    .ok_or(GenericTransactionError::MissingField(
                        "fee token".to_owned(),
                    ))?,
                chain_id: value.chain_id.unwrap_or_default(),
                ..Default::default()
            })
        }
    }

    impl From<LegacyTransaction> for GenericTransaction {
        fn from(value: LegacyTransaction) -> Self {
            Self {
                r#type: TxType::Legacy,
                nonce: Some(value.nonce),
                to: value.to,
                from: Address::default(),
                gas: Some(value.gas),
                value: value.value,
                gas_price: value.gas_price,
                max_priority_fee_per_gas: None,
                max_fee_per_gas: None,
                max_fee_per_blob_gas: None,
                access_list: vec![],
                fee_token: None,
                authorization_list: None,
                blob_versioned_hashes: vec![],
                blobs: vec![],
                wrapper_version: None,
                chain_id: None,
                input: value.data,
            }
        }
    }

    impl From<EIP2930Transaction> for GenericTransaction {
        fn from(value: EIP2930Transaction) -> Self {
            Self {
                r#type: TxType::EIP2930,
                nonce: Some(value.nonce),
                to: value.to,
                from: Address::default(),
                gas: Some(value.gas_limit),
                value: value.value,
                gas_price: value.gas_price,
                max_priority_fee_per_gas: None,
                max_fee_per_gas: None,
                max_fee_per_blob_gas: None,
                access_list: value
                    .access_list
                    .into_iter()
                    .map(|(address, storage_keys)| AccessListEntry {
                        address,
                        storage_keys,
                    })
                    .collect(),
                fee_token: None,
                authorization_list: None,
                blob_versioned_hashes: vec![],
                blobs: vec![],
                wrapper_version: None,
                chain_id: Some(value.chain_id),
                input: value.data,
            }
        }
    }

    impl From<Transaction> for GenericTransaction {
        fn from(value: Transaction) -> Self {
            match value {
                Transaction::LegacyTransaction(tx) => tx.into(),
                Transaction::EIP2930Transaction(tx) => tx.into(),
                Transaction::EIP1559Transaction(tx) => tx.into(),
                Transaction::EIP4844Transaction(tx) => tx.into(),
                Transaction::EIP7702Transaction(tx) => tx.into(),
                Transaction::PrivilegedL2Transaction(tx) => tx.into(),
                Transaction::FeeTokenTransaction(tx) => tx.into(),
                Transaction::FrameTransaction(tx) => tx.into(),
            }
        }
    }

    impl From<FrameTransaction> for GenericTransaction {
        fn from(value: FrameTransaction) -> Self {
            Self {
                r#type: TxType::Frame,
                nonce: Some(value.nonce),
                to: TxKind::Call(value.sender),
                from: value.sender,
                gas: Some(value.max_gas()),
                value: U256::zero(),
                gas_price: value.max_fee_per_gas,
                // `GenericTransaction` keeps these as `u64`, and `U256::as_u64`
                // panics rather than truncating, so saturate: this conversion feeds
                // RPC and simulation shapes, and a fee this large is unaffordable at
                // any balance, so the clamp cannot change an outcome.
                max_priority_fee_per_gas: Some(
                    u64::try_from(value.max_priority_fee_per_gas).unwrap_or(u64::MAX),
                ),
                max_fee_per_gas: Some(u64::try_from(value.max_fee_per_gas).unwrap_or(u64::MAX)),
                max_fee_per_blob_gas: if value.blob_versioned_hashes.is_empty() {
                    None
                } else {
                    Some(value.max_fee_per_blob_gas)
                },
                access_list: vec![],
                fee_token: None,
                authorization_list: None,
                blob_versioned_hashes: value.blob_versioned_hashes,
                blobs: vec![],
                wrapper_version: None,
                chain_id: Some(value.chain_id),
                input: Bytes::new(),
            }
        }
    }
}

mod mempool {
    use super::*;
    use std::{
        cmp::Ordering,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MempoolTransaction {
        // Unix timestamp (in microseconds) created once the transaction reached the MemPool
        timestamp: u128,
        sender: Address,
        inner: Arc<Transaction>,
    }

    impl MempoolTransaction {
        pub fn new(tx: Transaction, sender: Address) -> Self {
            Self {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Invalid system time")
                    .as_micros(),
                sender,
                inner: Arc::new(tx),
            }
        }
        pub fn time(&self) -> u128 {
            self.timestamp
        }

        pub fn sender(&self) -> Address {
            self.sender
        }

        pub fn transaction(&self) -> &Transaction {
            &self.inner
        }
    }

    impl RLPEncode for MempoolTransaction {
        fn encode(&self, buf: &mut dyn bytes::BufMut) {
            Encoder::new(buf)
                .encode_field(&self.timestamp)
                .encode_field(&*self.inner)
                .finish();
        }
    }

    impl RLPDecode for MempoolTransaction {
        fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
            let decoder = Decoder::new(rlp)?;
            let (timestamp, decoder) = decoder.decode_field("timestamp")?;
            let (sender, decoder) = decoder.decode_field("sender")?;
            let (inner, decoder) = decoder.decode_field("inner")?;
            Ok((
                Self {
                    timestamp,
                    sender,
                    inner: Arc::new(inner),
                },
                decoder.finish()?,
            ))
        }
    }

    impl std::ops::Deref for MempoolTransaction {
        type Target = Transaction;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    // Orders transactions by lowest nonce, if the nonce is equal, orders by highest timestamp
    impl Ord for MempoolTransaction {
        fn cmp(&self, other: &Self) -> Ordering {
            match (self.tx_type(), other.tx_type()) {
                (TxType::Privileged, TxType::Privileged) => {
                    return self.nonce().cmp(&other.nonce());
                }
                (TxType::Privileged, _) => return Ordering::Less,
                (_, TxType::Privileged) => return Ordering::Greater,
                _ => (),
            };
            match self.nonce().cmp(&other.nonce()) {
                Ordering::Equal => other.time().cmp(&self.time()),
                ordering => ordering,
            }
        }
    }

    impl PartialOrd for MempoolTransaction {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::{
        AuthorizationTuple, BlockBody, Receipt, compute_receipts_root, compute_transactions_root,
    };
    use ethereum_types::H160;
    use hex_literal::hex;
    use serde_impl::{AccessListEntry, GenericTransaction};
    use std::str::FromStr;

    #[test]
    fn is_blob_carrying_covers_frame_txs_with_blob_hashes() {
        // An EIP-8141 frame tx carries `max_fee_per_blob_gas` +
        // `blob_versioned_hashes` of its own, so blob-ness cannot be decided
        // by matching on `EIP4844Transaction` alone: a blob-bearing frame tx
        // would otherwise be treated as a plain tx by the mempool's
        // replacement rules and skip the blob-fee comparison entirely.
        let plain_frame = Transaction::FrameTransaction(FrameTransaction::default());
        assert!(!plain_frame.is_blob_carrying());

        let blob_frame = Transaction::FrameTransaction(FrameTransaction {
            max_fee_per_blob_gas: U256::from(7u64),
            blob_versioned_hashes: vec![H256::from_low_u64_be(1)],
            ..Default::default()
        });
        assert!(blob_frame.is_blob_carrying());

        let blob_tx = Transaction::EIP4844Transaction(EIP4844Transaction {
            blob_versioned_hashes: vec![H256::from_low_u64_be(1)],
            ..Default::default()
        });
        assert!(blob_tx.is_blob_carrying());

        let plain = Transaction::EIP1559Transaction(EIP1559Transaction::default());
        assert!(!plain.is_blob_carrying());
    }

    #[test]
    fn nonce_over_u64_max_maps_to_nonce_is_max() {
        // RLP list [ 0x010000000000000000 ] — nonce = 2**64 (9 significant bytes),
        // one past u64::MAX. EEST expects TransactionException.NONCE_IS_MAX here.
        let rlp = hex!("ca89010000000000000000");
        let decoder = Decoder::new(&rlp).unwrap();
        let err = decode_nonce_field(decoder).unwrap_err();
        assert!(
            err.to_string().contains("Nonce is max"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nonce_at_u64_max_decodes() {
        // RLP list [ 0xffffffffffffffff ] — nonce = u64::MAX (8 bytes), still valid.
        let rlp = hex!("c988ffffffffffffffff");
        let decoder = Decoder::new(&rlp).unwrap();
        let (nonce, _) = decode_nonce_field(decoder).unwrap();
        assert_eq!(nonce, u64::MAX);
    }

    #[test]
    fn legacy_chain_id_handles_out_of_range_v_without_underflow() {
        // A legacy transaction decodes `v` as an arbitrary U256, so a malformed tx can
        // carry any value. `derive_legacy_chain_id` must return None for the pre-EIP-155
        // values (27/28) and any v < 35 rather than underflowing `v - 35`, which panics
        // in debug and wraps to a bogus chain id in release. This is reachable on the
        // block-import path (every tx's chain id is now checked pre-execution).
        let legacy_chain_id = |v: u64| {
            Transaction::LegacyTransaction(LegacyTransaction {
                v: U256::from(v),
                ..Default::default()
            })
            .chain_id()
        };
        for v in [0u64, 1, 26, 27, 28, 34] {
            assert_eq!(legacy_chain_id(v), None, "v={v} must yield no chain id");
        }
        // EIP-155 values (v = chain_id * 2 + 35/36) still derive correctly.
        assert_eq!(legacy_chain_id(35), Some(0));
        assert_eq!(legacy_chain_id(36), Some(0));
        assert_eq!(legacy_chain_id(37), Some(1));
    }

    #[test]
    fn test_compute_transactions_root() {
        let mut body = BlockBody::empty();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: U256::from(0x0a),
            gas: 0x05f5e100,
            to: TxKind::Call(hex!("1000000000000000000000000000000000000000").into()),
            value: 0.into(),
            data: Default::default(),
            v: U256::from(0x1b),
            r: U256::from_big_endian(&hex!(
                "7e09e26678ed4fac08a249ebe8ed680bf9051a5e14ad223e4b2b9d26e0208f37"
            )),
            s: U256::from_big_endian(&hex!(
                "5f6e3f188e3e6eab7d7d3b6568f5eac7d687b08d307d3154ccd8c87b4630509b"
            )),
            ..Default::default()
        };
        body.transactions.push(Transaction::LegacyTransaction(tx));
        let expected_root =
            hex!("8151d548273f6683169524b66ca9fe338b9ce42bc3540046c828fd939ae23bcb");
        let result = compute_transactions_root(&body.transactions, &ethrex_crypto::NativeCrypto);

        assert_eq!(result, expected_root.into());
    }
    #[test]
    fn test_compute_hash() {
        // taken from Hive
        let tx_eip2930 = EIP2930Transaction {
            chain_id: 3503995874084926u64,
            nonce: 7,
            gas_price: U256::from(0x2dbf1f9a_u64),
            gas_limit: 0x186A0,
            to: TxKind::Call(hex!("7dcd17433742f4c0ca53122ab541d0ba67fc27df").into()),
            value: 2.into(),
            data: Bytes::from(&b"\xdbS\x06$\x8e\x03\x13\xe7emit"[..]),
            access_list: vec![(
                hex!("7dcd17433742f4c0ca53122ab541d0ba67fc27df").into(),
                vec![
                    hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
                    hex!("a3d07a7d68fbd49ec2f8e6befdd86c885f86c272819f6f345f365dec35ae6707").into(),
                ],
            )],
            signature_y_parity: false,
            signature_r: U256::from_dec_str(
                "75813812796588349127366022588733264074091236448495248199152066031778895768879",
            )
            .unwrap(),
            signature_s: U256::from_dec_str(
                "25476208226281085290728123165613764315157904411823916642262684106502155457829",
            )
            .unwrap(),
            ..Default::default()
        };
        let tx = Transaction::EIP2930Transaction(tx_eip2930);

        let expected_hash =
            hex!("a0762610d794acddd2dca15fb7c437ada3611c886f3bea675d53d8da8a6c41b2");
        let hash = tx.compute_hash(&NativeCrypto);
        assert_eq!(hash, expected_hash.into());
    }

    #[test]
    fn test_compute_receipts_root() {
        // example taken from
        // https://github.com/ethereum/go-ethereum/blob/f8aa62353666a6368fb3f1a378bd0a82d1542052/cmd/evm/testdata/1/exp.json#L18
        let tx_type = TxType::Legacy;
        let succeeded = true;
        let cumulative_gas_used = 0x5208;
        let logs = vec![];
        let receipt = Receipt::new(tx_type, succeeded, cumulative_gas_used, logs);

        let result = compute_receipts_root(&[receipt], &ethrex_crypto::NativeCrypto);
        let expected_root =
            hex!("056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2");
        assert_eq!(result, expected_root.into());
    }

    #[test]
    fn legacy_tx_rlp_decode() {
        let encoded_tx = "f86d80843baa0c4082f618946177843db3138ae69679a54b95cf345ed759450d870aa87bee538000808360306ba0151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65da064c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4";
        let encoded_tx_bytes = hex::decode(encoded_tx).unwrap();
        let tx = LegacyTransaction::decode(&encoded_tx_bytes).unwrap();
        let expected_tx = LegacyTransaction {
            nonce: 0,
            gas_price: U256::from(1001000000u64),
            gas: 63000,
            to: TxKind::Call(Address::from_slice(
                &hex::decode("6177843db3138ae69679A54b95cf345ED759450d").unwrap(),
            )),
            value: 3000000000000000_u64.into(),
            data: Bytes::new(),
            r: U256::from_str_radix(
                "151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65d",
                16,
            )
            .unwrap(),
            s: U256::from_str_radix(
                "64c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4",
                16,
            )
            .unwrap(),
            v: 6303851.into(),
            ..Default::default()
        };
        assert_eq!(tx, expected_tx);
    }

    #[test]
    fn eip1559_tx_rlp_decode() {
        let encoded_tx = "f86c8330182480114e82f618946177843db3138ae69679a54b95cf345ed759450d870aa87bee53800080c080a0151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65da064c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4";
        let encoded_tx_bytes = hex::decode(encoded_tx).unwrap();
        let tx = EIP1559Transaction::decode(&encoded_tx_bytes).unwrap();
        let expected_tx = EIP1559Transaction {
            nonce: 0,
            max_fee_per_gas: 78,
            max_priority_fee_per_gas: 17,
            to: TxKind::Call(Address::from_slice(
                &hex::decode("6177843db3138ae69679A54b95cf345ED759450d").unwrap(),
            )),
            value: 3000000000000000_u64.into(),
            data: Bytes::new(),
            signature_r: U256::from_str_radix(
                "151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65d",
                16,
            )
            .unwrap(),
            signature_s: U256::from_str_radix(
                "64c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4",
                16,
            )
            .unwrap(),
            signature_y_parity: false,
            chain_id: 3151908,
            gas_limit: 63000,
            access_list: vec![],
            ..Default::default()
        };
        assert_eq!(tx, expected_tx);
    }

    #[test]
    fn deserialize_tx_kind() {
        let tx_kind_create = r#""""#;
        let tx_kind_call = r#""0x6177843db3138ae69679A54b95cf345ED759450d""#;
        let deserialized_tx_kind_create = TxKind::Create;
        let deserialized_tx_kind_call = TxKind::Call(Address::from_slice(
            &hex::decode("6177843db3138ae69679A54b95cf345ED759450d").unwrap(),
        ));
        assert_eq!(
            deserialized_tx_kind_create,
            serde_json::from_str(tx_kind_create).unwrap()
        );
        assert_eq!(
            deserialized_tx_kind_call,
            serde_json::from_str(tx_kind_call).unwrap()
        )
    }

    #[test]
    fn deserialize_tx_type() {
        let tx_type_eip2930 = r#""0x01""#;
        let tx_type_eip1559 = r#""0x02""#;
        let deserialized_tx_type_eip2930 = TxType::EIP2930;
        let deserialized_tx_type_eip1559 = TxType::EIP1559;
        assert_eq!(
            deserialized_tx_type_eip2930,
            serde_json::from_str(tx_type_eip2930).unwrap()
        );
        assert_eq!(
            deserialized_tx_type_eip1559,
            serde_json::from_str(tx_type_eip1559).unwrap()
        )
    }

    #[test]
    fn deserialize_generic_transaction() {
        let generic_transaction = r#"{
            "type":"0x01",
            "nonce":"0x02",
            "to":"",
            "from":"0x6177843db3138ae69679A54b95cf345ED759450d",
            "gas":"0x5208",
            "value":"0x01",
            "input":"0x010203040506",
            "gasPrice":"0x07",
            "accessList": [
                {
                    "address": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02",
                    "storageKeys": [
                        "0x000000000000000000000000000000000000000000000000000000000000000c",
                        "0x000000000000000000000000000000000000000000000000000000000000200b"
                    ]
                }
            ]
        }"#;
        let deserialized_generic_transaction = GenericTransaction {
            r#type: TxType::EIP2930,
            nonce: Some(2),
            to: TxKind::Create,
            from: Address::from_slice(
                &hex::decode("6177843db3138ae69679A54b95cf345ED759450d").unwrap(),
            ),
            gas: Some(0x5208),
            value: U256::from(1),
            input: Bytes::from(hex::decode("010203040506").unwrap()),
            gas_price: U256::from(7),
            max_priority_fee_per_gas: Default::default(),
            max_fee_per_gas: Default::default(),
            max_fee_per_blob_gas: Default::default(),
            access_list: vec![AccessListEntry {
                address: Address::from_slice(
                    &hex::decode("000f3df6d732807ef1319fb7b8bb8522d0beac02").unwrap(),
                ),
                storage_keys: vec![H256::from_low_u64_be(12), H256::from_low_u64_be(8203)],
            }],
            fee_token: None,
            blob_versioned_hashes: Default::default(),
            blobs: Default::default(),
            wrapper_version: None,
            chain_id: Default::default(),
            authorization_list: None,
        };
        assert_eq!(
            deserialized_generic_transaction,
            serde_json::from_str(generic_transaction).unwrap()
        )
    }

    #[test]
    fn deserialize_generic_transaction_with_data_and_input_fields() {
        let generic_transaction = r#"{
            "type":"0x01",
            "nonce":"0x02",
            "to":"",
            "from":"0x6177843db3138ae69679A54b95cf345ED759450d",
            "gas":"0x5208",
            "value":"0x01",
            "input":"0x010203040506",
            "data":"0x010203040506",
            "gasPrice":"0x07",
            "accessList": [
                {
                    "address": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02",
                    "storageKeys": [
                        "0x000000000000000000000000000000000000000000000000000000000000000c",
                        "0x000000000000000000000000000000000000000000000000000000000000200b"
                    ]
                }
            ]
        }"#;
        let deserialized_generic_transaction = GenericTransaction {
            r#type: TxType::EIP2930,
            nonce: Some(2),
            to: TxKind::Create,
            from: Address::from_slice(
                &hex::decode("6177843db3138ae69679A54b95cf345ED759450d").unwrap(),
            ),
            gas: Some(0x5208),
            value: U256::from(1),
            input: Bytes::from(hex::decode("010203040506").unwrap()),
            gas_price: U256::from(7),
            max_priority_fee_per_gas: Default::default(),
            max_fee_per_gas: Default::default(),
            max_fee_per_blob_gas: Default::default(),
            access_list: vec![AccessListEntry {
                address: Address::from_slice(
                    &hex::decode("000f3df6d732807ef1319fb7b8bb8522d0beac02").unwrap(),
                ),
                storage_keys: vec![H256::from_low_u64_be(12), H256::from_low_u64_be(8203)],
            }],
            fee_token: None,
            blob_versioned_hashes: Default::default(),
            blobs: Default::default(),
            wrapper_version: None,
            chain_id: Default::default(),
            authorization_list: None,
        };
        assert_eq!(
            deserialized_generic_transaction,
            serde_json::from_str(generic_transaction).unwrap()
        )
    }

    #[test]
    fn deserialize_eip4844_transaction() {
        let eip4844_transaction = r#"{
            "chainId":"0x01",
            "nonce":"0x02",
            "maxPriorityFeePerGas":"0x01",
            "maxFeePerGas":"0x01",
            "gas":"0x5208",
            "to":"0x6177843db3138ae69679A54b95cf345ED759450d",
            "value":"0x01",
            "input":"0x3033",
            "accessList": [
                {
                    "address": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02",
                    "storageKeys": [
                        "0x000000000000000000000000000000000000000000000000000000000000000c",
                        "0x000000000000000000000000000000000000000000000000000000000000200b"
                    ]
                }
            ],
            "maxFeePerBlobGas":"0x03",
            "blobVersionedHashes": [
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
            ],
            "yParity":"0x0",
            "r": "0x01",
            "s": "0x02"
        }"#;
        let deserialized_eip4844_transaction = EIP4844Transaction {
            chain_id: 0x01,
            nonce: 0x02,
            to: Address::from_slice(
                &hex::decode("6177843db3138ae69679A54b95cf345ED759450d").unwrap(),
            ),
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            max_fee_per_blob_gas: U256::from(0x03),
            gas: 0x5208,
            value: U256::from(0x01),
            // 03 in hex is 0x3033, that's why the 'input' has that number.
            data: Bytes::from_static(b"03"),
            access_list: vec![(
                Address::from_slice(
                    &hex::decode("000f3df6d732807ef1319fb7b8bb8522d0beac02").unwrap(),
                ),
                vec![H256::from_low_u64_be(12), H256::from_low_u64_be(8203)],
            )],
            blob_versioned_hashes: vec![H256::from_low_u64_be(1), H256::from_low_u64_be(2)],
            signature_y_parity: false,
            signature_r: U256::from(0x01),
            signature_s: U256::from(0x02),
            ..Default::default()
        };

        assert_eq!(
            deserialized_eip4844_transaction,
            serde_json::from_str(eip4844_transaction).unwrap()
        )
    }

    #[test]
    fn serialize_deserialize_transaction() {
        let eip1559 = EIP1559Transaction {
            chain_id: 65536999,
            nonce: 1,
            max_priority_fee_per_gas: 1000,
            max_fee_per_gas: 2000,
            gas_limit: 21000,
            to: TxKind::Call(H160::from_str("0x000a52D537c4150ec274dcE3962a0d179B7E71B0").unwrap()),
            value: U256::from(100000),
            data: Bytes::from_static(b"03"),
            access_list: vec![(
                H160::from_str("0x000a52D537c4150ec274dcE3962a0d179B7E71B3").unwrap(),
                vec![H256::zero()],
            )],
            signature_y_parity: true,
            signature_r: U256::one(),
            signature_s: U256::zero(),
            ..Default::default()
        };
        let tx_to_serialize = Transaction::EIP1559Transaction(eip1559.clone());
        let serialized = serde_json::to_string(&tx_to_serialize).expect("Failed to serialize");

        let deserialized_tx: Transaction =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert!(deserialized_tx.tx_type() == TxType::EIP1559);

        if let Transaction::EIP1559Transaction(tx) = deserialized_tx {
            assert_eq!(tx, eip1559);
        }
    }

    #[test]
    fn serialize_deserialize_eip7702transaction() {
        let eip7702 = EIP7702Transaction {
            chain_id: 65536999,
            nonce: 1,
            max_priority_fee_per_gas: 1000,
            max_fee_per_gas: 2000,
            gas_limit: 21000,
            to: Address::from_str("0x000a52D537c4150ec274dcE3962a0d179B7E71B0").unwrap(),
            value: U256::from(100000),
            data: Bytes::from_static(b"03"),
            access_list: vec![],
            signature_y_parity: true,
            signature_r: U256::one(),
            signature_s: U256::zero(),
            authorization_list: vec![AuthorizationTuple {
                chain_id: U256::from(65536999),
                address: H160::from_str("0x000a52D537c4150ec274dcE3962a0d179B7E71B1").unwrap(),
                nonce: 2,
                y_parity: U256::one(),
                r_signature: U256::from(22),
                s_signature: U256::from(37),
            }],
            ..Default::default()
        };
        let tx_to_serialize = Transaction::EIP7702Transaction(eip7702.clone());
        let serialized = serde_json::to_string(&tx_to_serialize).expect("Failed to serialize");

        let deserialized_tx: Transaction =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert!(deserialized_tx.tx_type() == TxType::EIP7702);

        if let Transaction::EIP7702Transaction(tx) = deserialized_tx {
            assert_eq!(tx, eip7702);
        }
    }

    #[test]
    fn serialize_deserialize_privileged_l2_transaction() -> Result<(), RLPDecodeError> {
        let privileged_l2 = PrivilegedL2Transaction {
            chain_id: 65536999,
            nonce: 0,
            max_priority_fee_per_gas: 875000000,
            max_fee_per_gas: 875000000,
            gas_limit: 42000u64,
            to: TxKind::Call(
                Address::from_str("0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap(),
            ),
            value: U256::from(500000000000000000000000000u128),
            data: Bytes::new(),
            access_list: vec![],
            from: Address::from_str("0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap(),
            ..Default::default()
        };

        let encoded = PrivilegedL2Transaction::encode_to_vec(&privileged_l2);
        println!("encoded length: {}", encoded.len());
        assert_eq!(encoded.len(), privileged_l2.length());

        let deserialized_tx = PrivilegedL2Transaction::decode(&encoded)?;

        assert_eq!(deserialized_tx, privileged_l2);

        Ok(())
    }

    #[test]
    fn test_legacy_transaction_into_generic() {
        let legacy_tx = LegacyTransaction {
            nonce: 1,
            gas_price: U256::from(20_000_000_000u64),
            gas: 21000,
            to: TxKind::Call(
                Address::from_str("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").unwrap(),
            ),
            value: U256::from(1_000_000_000_000_000_000u64),
            data: Bytes::default(),
            v: U256::from(27),
            r: U256::from(1),
            s: U256::from(1),
            ..Default::default()
        };

        let generic_tx: GenericTransaction = legacy_tx.into();
        assert_eq!(generic_tx.r#type, TxType::Legacy);
        assert_eq!(generic_tx.nonce, Some(1));
        assert_eq!(generic_tx.gas_price, U256::from(20_000_000_000u64));
        assert_eq!(generic_tx.gas, Some(21000));
        assert_eq!(generic_tx.max_priority_fee_per_gas, None);
        assert_eq!(generic_tx.max_fee_per_gas, None);
        assert_eq!(generic_tx.access_list.len(), 0);
        assert_eq!(generic_tx.chain_id, None);
    }

    #[test]
    fn test_eip2930_transaction_into_generic() {
        let access_list = vec![(
            Address::from_str("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").unwrap(),
            vec![
                H256::from_str(
                    "0x1234567890123456789012345678901234567890123456789012345678901234",
                )
                .unwrap(),
            ],
        )];

        let eip2930_tx = EIP2930Transaction {
            chain_id: 1,
            nonce: 1,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: 21000,
            to: TxKind::Call(
                Address::from_str("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").unwrap(),
            ),
            value: U256::from(1_000_000_000_000_000_000u64),
            data: Bytes::default(),
            access_list: access_list.clone(),
            signature_y_parity: false,
            signature_r: U256::from(1),
            signature_s: U256::from(1),
            ..Default::default()
        };

        let generic_tx: GenericTransaction = eip2930_tx.into();
        assert_eq!(generic_tx.r#type, TxType::EIP2930);
        assert_eq!(generic_tx.nonce, Some(1));
        assert_eq!(generic_tx.gas_price, U256::from(20_000_000_000u64));
        assert_eq!(generic_tx.gas, Some(21000));
        assert_eq!(generic_tx.max_priority_fee_per_gas, None);
        assert_eq!(generic_tx.max_fee_per_gas, None);
        assert_eq!(generic_tx.chain_id, Some(1));
        assert_eq!(generic_tx.access_list.len(), 1);
        assert_eq!(generic_tx.access_list[0].address, access_list[0].0);
        assert_eq!(generic_tx.access_list[0].storage_keys, access_list[0].1);
    }

    #[test]
    fn recover_address_rejects_high_s_signatures() {
        use ethrex_crypto::NativeCrypto;
        use k256::ecdsa::SigningKey;

        let crypto = NativeCrypto;

        // 1. Setup: Create a signer and a message
        // A random private key for testing
        let private_key = hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        let signing_key = SigningKey::from_bytes(&private_key.into()).expect("Valid private key");

        // The message we want to sign
        let msg = b"Test message for high-s signature rejection";
        // Calculate the Keccak256 hash of the message (the payload)
        let payload = keccak(msg).to_fixed_bytes();

        // 2. Generate a valid low-s signature
        // k256's sign_prehash_recoverable produces canonical low-s signatures by default.
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&payload)
            .expect("Signing failed");

        // 3. Construct the signature bytes (r||s||v, 65 bytes)
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();

        // 4. Verify that the valid low-s signature recovers the correct address
        // Calculate the expected address from the public key
        let uncompressed_pub = signing_key.verifying_key().to_encoded_point(false);
        let pub_hash = ethrex_crypto::keccak::keccak_hash(&uncompressed_pub.as_bytes()[1..]);
        let expected_address = Address::from_slice(&pub_hash[12..]);

        let recovered = crypto
            .recover_signer(&sig_bytes, &payload)
            .expect("Valid low-s signature should recover successfully");
        assert_eq!(recovered, expected_address, "Recovered address mismatch");

        // 5. Create a high-s signature: s' = N - s
        // The curve order N for secp256k1
        let n = U256::from_big_endian(&hex!(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        let s = U256::from_big_endian(&sig_bytes[32..64]);

        // Ensure the generated signature was indeed low-s (standard requirement)
        let half_n = n / 2;
        assert!(
            s <= half_n,
            "Generated signature was not low-s, cannot test high-s rejection"
        );

        // Calculate high-s
        let s_high = n - s;

        let mut sig_high_bytes = sig_bytes;
        // Replace s with s_high
        sig_high_bytes[32..64].copy_from_slice(&s_high.to_big_endian());
        // When flipping s to -s mod N, we must also flip the recovery ID (v) to maintain validity of the point R
        sig_high_bytes[64] ^= 1;

        // 6. Verify that the high-s signature is rejected
        // EIP-2 requires rejecting s > N/2 to prevent malleability
        assert!(
            crypto.recover_signer(&sig_high_bytes, &payload).is_err(),
            "High-s signature should be rejected (EIP-2 compliance)"
        );
    }

    #[test]
    fn encode_decode_low_size_tx() {
        let tx = Transaction::EIP2930Transaction(EIP2930Transaction::default());
        // Encode a separate copy so the original's cached_canonical stays uninit,
        // avoiding a false PartialEq mismatch with the decoded (uncached) tx.
        let tx_to_encode = tx.clone();
        let encoded = tx_to_encode.encode_to_vec();
        let decoded_tx = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded_tx);
    }

    #[test]
    fn test_eip1559_simple_transfer_size() {
        let tx = Transaction::EIP1559Transaction(EIP1559Transaction::default());
        assert_eq!(tx.encode_to_vec().len(), EIP1559_DEFAULT_SERIALIZED_LENGTH);
    }

    // ── Frame Transaction (EIP-8141) tests ──

    fn make_test_frame_tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce: 42,
            sender: Address::from_low_u64_be(0xABCD),
            frames: vec![
                Frame {
                    mode: FrameMode::Verify as u8,
                    flags: 0x03, // APPROVE_PAYMENT_AND_EXECUTION
                    target: Some(Address::from_low_u64_be(0xABCD)),
                    gas_limits: GasLimits {
                        execution: 100_000,
                        state: 0,
                    },
                    value: U256::zero(),
                    data: Bytes::from_static(b"verify_data"),
                },
                Frame {
                    mode: FrameMode::Sender as u8,
                    flags: 0x00,
                    target: Some(Address::from_low_u64_be(0x1234)),
                    gas_limits: GasLimits {
                        execution: 200_000,
                        state: 0,
                    },
                    value: U256::zero(),
                    data: Bytes::from_static(b"call_data"),
                },
            ],
            signatures: vec![FrameSignature {
                scheme: FRAME_SIG_SCHEME_SECP256K1,
                signer: Some(Address::from_low_u64_be(0xABCD)),
                msg: Bytes::new(),
                signature: Bytes::from(vec![0u8; 65]),
            }],
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: vec![],
            inner_hash: OnceCell::new(),
            cached_canonical: OnceCell::new(),
        }
    }

    #[test]
    fn atomic_batch_flag_valid_on_default_and_sender_frames() {
        // Per EIP-8141 the atomic batch flag is valid on DEFAULT and SENDER
        // frames, and a batch never contains a VERIFY frame.
        let mut tx = make_test_frame_tx();
        tx.frames = vec![
            Frame {
                mode: FrameMode::Default as u8,
                flags: 0x04, // atomic batch
                target: Some(Address::from_low_u64_be(0xB0B)),
                gas_limits: GasLimits {
                    execution: 21_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::new(),
            },
            Frame {
                mode: FrameMode::Sender as u8,
                flags: 0x04, // atomic batch
                target: Some(Address::from_low_u64_be(0xB0B)),
                gas_limits: GasLimits {
                    execution: 21_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::new(),
            },
            Frame {
                mode: FrameMode::Sender as u8,
                flags: 0x00, // terminator: no flag
                target: Some(Address::from_low_u64_be(0xCAFE)),
                gas_limits: GasLimits {
                    execution: 21_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::new(),
            },
        ];
        assert!(tx.validate_static_constraints().is_ok());
    }

    #[test]
    fn atomic_batch_flag_on_last_frame_still_invalid() {
        let mut tx = make_test_frame_tx();
        tx.frames = vec![Frame {
            mode: FrameMode::Sender as u8,
            flags: 0x04,
            target: Some(Address::from_low_u64_be(0xCAFE)),
            gas_limits: GasLimits {
                execution: 21_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }];
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("atomic batch flag on last frame"), "{err}");
    }

    #[test]
    fn test_frame_rlp_roundtrip() {
        let frame = Frame {
            mode: FrameMode::Verify as u8,
            flags: 0x03,
            target: Some(Address::from_low_u64_be(0x1234)),
            gas_limits: GasLimits {
                execution: 50_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::from_static(b"hello"),
        };
        let encoded = frame.encode_to_vec();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_frame_null_target_rlp_roundtrip() {
        let frame = Frame {
            mode: FrameMode::Default as u8,
            flags: 0x00,
            target: None,
            gas_limits: GasLimits {
                execution: 10_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::from_static(b"deploy"),
        };
        let encoded = frame.encode_to_vec();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_frame_mode_with_flags_rlp_roundtrip() {
        // Test basic modes
        for mode_val in [0u8, 1, 2] {
            let frame = Frame {
                mode: mode_val,
                flags: if mode_val == 1 { 0x03 } else { 0x00 },
                target: Some(Address::from_low_u64_be(0x1234)),
                gas_limits: GasLimits {
                    execution: 50_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::new(),
            };
            let encoded = frame.encode_to_vec();
            let decoded = Frame::decode(&encoded).unwrap();
            assert_eq!(frame, decoded);
        }
        // Test mode with scope restriction (bits 0-1 of flags) and atomic batch (bit 2 of flags)
        let frame = Frame {
            mode: 2,            // SENDER
            flags: 0x01 | 0x04, // scope=1 + atomic_batch
            target: Some(Address::from_low_u64_be(0x1234)),
            gas_limits: GasLimits {
                execution: 50_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        };
        assert_eq!(frame.execution_mode(), FrameMode::Sender);
        assert_eq!(frame.scope_restriction(), 1);
        assert!(frame.is_atomic_batch());
        let encoded = frame.encode_to_vec();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn frame_rlp_roundtrip_preserves_value() {
        let frame = Frame {
            mode: FrameMode::Sender as u8,
            flags: 0x00,
            target: Some(Address::from_low_u64_be(0xCAFE)),
            gas_limits: GasLimits {
                execution: 100_000,
                state: 0,
            },
            value: U256::from(1_000_000_000_000_000u64), // 0.001 ETH
            data: Bytes::from_static(b"hello"),
        };
        let encoded = frame.encode_to_vec();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
        assert_eq!(decoded.value, U256::from(1_000_000_000_000_000u64));
    }

    #[test]
    fn test_frame_transaction_rlp_roundtrip() {
        let tx = make_test_frame_tx();
        let encoded = tx.encode_to_vec();
        let decoded = FrameTransaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_frame_transaction_canonical_roundtrip() {
        let tx = Transaction::FrameTransaction(make_test_frame_tx());
        let encoded = tx.encode_canonical_to_vec();
        let decoded = Transaction::decode_canonical(&encoded).unwrap();
        // Compare hashes since OnceCell cached state differs after encode
        assert_eq!(
            tx.hash(&ethrex_crypto::NativeCrypto),
            decoded.hash(&ethrex_crypto::NativeCrypto)
        );
        // Also verify core fields match
        assert_eq!(tx.tx_type(), decoded.tx_type());
        assert_eq!(tx.nonce(), decoded.nonce());
        assert_eq!(tx.chain_id(), decoded.chain_id());
    }

    #[test]
    fn test_frame_transaction_sig_hash_covers_all_frame_data() {
        // Updated for frame data is NO LONGER elided.
        let tx = make_test_frame_tx();
        let hash1 = tx.compute_sig_hash();

        // Changing VERIFY frame data now DOES change the sig_hash.
        let mut tx2 = tx.clone();
        tx2.frames[0].data = Bytes::from_static(b"completely_different_verify_data");
        let hash2 = tx2.compute_sig_hash();
        assert_ne!(hash1, hash2);

        // Changing SENDER frame data also produces a different hash.
        let mut tx3 = tx;
        tx3.frames[1].data = Bytes::from_static(b"different_call_data");
        let hash3 = tx3.compute_sig_hash();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_frame_transaction_accessor_methods() {
        let frame_tx = make_test_frame_tx();
        let tx = Transaction::FrameTransaction(frame_tx);

        assert_eq!(tx.tx_type(), TxType::Frame);
        assert_eq!(tx.nonce(), 42);
        assert_eq!(tx.chain_id(), Some(1));
        assert_eq!(tx.to(), TxKind::Call(Address::from_low_u64_be(0xABCD)));
        assert_eq!(tx.value(), U256::zero());
        assert_eq!(tx.data(), &Bytes::new());
        assert!(tx.access_list().is_empty());
        assert!(tx.authorization_list().is_none());
        assert_eq!(tx.max_priority_fee(), Some(U256::from(1_000_000_000u64)));
        assert_eq!(tx.max_fee_per_gas(), Some(U256::from(30_000_000_000u64)));
        assert_eq!(tx.max_fee_per_blob_gas(), None); // no blobs
        assert!(!tx.is_contract_creation());
        // sender returns explicit sender, no ECDSA
        assert_eq!(
            tx.sender(&ethrex_crypto::NativeCrypto).unwrap(),
            Address::from_low_u64_be(0xABCD)
        );
        // gas_limit = intrinsic + calldata_cost + sum(frame.gas_limit)
        assert!(tx.gas_limit() >= 300_000); // at least sum of frame gas limits
    }

    #[test]
    fn test_frame_transaction_hash_uses_oncecell() {
        let tx = Transaction::FrameTransaction(make_test_frame_tx());
        let h1 = tx.hash(&ethrex_crypto::NativeCrypto);
        let h2 = tx.hash(&ethrex_crypto::NativeCrypto);
        assert_eq!(h1, h2);
    }

    #[test]
    fn frame_transaction_rlp_roundtrip_preserves_fields() {
        let tx = make_test_frame_tx();
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let (decoded, rest) = FrameTransaction::decode_unfinished(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.chain_id, tx.chain_id);
        assert_eq!(decoded.nonce, tx.nonce);
        assert_eq!(decoded.sender, tx.sender);
    }

    #[test]
    fn frame_transaction_variant_is_exposed_on_transaction_enum() {
        let tx = Transaction::FrameTransaction(make_test_frame_tx());
        assert!(matches!(tx, Transaction::FrameTransaction(_)));
    }

    #[test]
    fn frame_transaction_serializes_signatures_as_array() {
        // RPC must expose the full signature objects, not just a count.
        let tx = make_test_frame_tx();
        let json = serde_json::to_value(&tx).unwrap();
        let sigs = json
            .get("signatures")
            .expect("signatures field present")
            .as_array()
            .expect("signatures serialized as an array");
        assert_eq!(sigs.len(), tx.signatures.len());
        assert_eq!(sigs[0].get("scheme").unwrap(), "0x1");
        assert!(sigs[0].get("signer").is_some());
        assert!(sigs[0].get("signature").is_some());
        assert!(sigs[0].get("msg").is_some());
    }

    fn make_frame_tx_with_gas_limits(limits: Vec<u64>) -> FrameTransaction {
        let frames = limits
            .into_iter()
            .map(|gl| Frame {
                mode: FrameMode::Sender as u8,
                flags: 0x00,
                target: Some(Address::from_low_u64_be(0x1234)),
                gas_limits: GasLimits {
                    execution: gl,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::new(),
            })
            .collect();
        FrameTransaction {
            chain_id: 1,
            nonce: 0,
            sender: Address::from_low_u64_be(0xABCD),
            frames,
            signatures: vec![],
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: vec![],
            inner_hash: OnceCell::new(),
            cached_canonical: OnceCell::new(),
        }
    }

    #[test]
    fn per_frame_gas_limit_above_i64_max_is_rejected() {
        let tx = make_frame_tx_with_gas_limits(vec![(i64::MAX as u64) + 1]);
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("exceeds 2**63-1"), "unexpected error: {err}");
    }

    #[test]
    fn cumulative_frame_gas_limit_above_i64_max_is_rejected() {
        let half = (i64::MAX as u64) / 2 + 1;
        let tx = make_frame_tx_with_gas_limits(vec![half, half]);
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("cumulative"), "unexpected error: {err}");
    }

    #[test]
    fn cumulative_frame_gas_limit_equal_to_i64_max_is_accepted() {
        let a = (i64::MAX as u64) / 2;
        let b = i64::MAX as u64 - a;
        let tx = make_frame_tx_with_gas_limits(vec![a, b]);
        tx.validate_static_constraints()
            .expect("exact i64::MAX total should be accepted");
    }

    #[test]
    fn empty_frames_list_is_rejected_by_count_check_not_gas_check() {
        // The frame-count check fires before the gas-limit accumulator runs,
        // so an empty frame list surfaces the count error, not a gas error.
        let tx = make_frame_tx_with_gas_limits(vec![]);
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("between 1 and"), "unexpected error: {err}");
    }

    #[test]
    fn sig_hash_covers_frame_value() {
        // Changing `value` on any frame (SENDER or VERIFY) must change the
        // canonical signature hash (all frame data covered).
        let tx = make_test_frame_tx();
        let baseline = tx.compute_sig_hash();

        let mut with_sender_value = tx.clone();
        with_sender_value.frames[1].value = U256::from(1u64);
        assert_ne!(
            baseline,
            with_sender_value.compute_sig_hash(),
            "sig_hash must change when a SENDER frame's value changes"
        );

        let mut with_verify_value = tx.clone();
        with_verify_value.frames[0].value = U256::from(1u64);
        assert_ne!(
            baseline,
            with_verify_value.compute_sig_hash(),
            "sig_hash must change when a VERIFY frame's value changes"
        );

        // VERIFY.data is now covered too (EIP-8141 removed elision).
        let mut with_verify_data = tx;
        with_verify_data.frames[0].data = Bytes::from_static(b"different_verify_data");
        assert_ne!(
            baseline,
            with_verify_data.compute_sig_hash(),
            "VERIFY.data is now covered by sig_hash (no longer elided)"
        );
    }

    #[test]
    fn validate_static_constraints_rejects_nonzero_value_on_non_sender_frames() {
        // VERIFY frame with non-zero value must be rejected.
        let verify_tx = FrameTransaction {
            chain_id: 1,
            nonce: 0,
            sender: Address::from_low_u64_be(0xABCD),
            frames: vec![Frame {
                mode: FrameMode::Verify as u8,
                flags: 0x01,
                target: None,
                gas_limits: GasLimits {
                    execution: 50_000,
                    state: 0,
                },
                value: U256::from(1u64),
                data: Bytes::new(),
            }],
            signatures: vec![],
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: vec![],
            inner_hash: OnceCell::new(),
            cached_canonical: OnceCell::new(),
        };
        let err = verify_tx.validate_static_constraints().unwrap_err();
        assert!(
            err.contains("non-zero value only allowed in SENDER mode"),
            "unexpected error for VERIFY: {err}"
        );

        // DEFAULT frame with non-zero value must be rejected.
        let default_tx = FrameTransaction {
            frames: vec![Frame {
                mode: FrameMode::Default as u8,
                flags: 0x00,
                target: Some(Address::from_low_u64_be(0x1234)),
                gas_limits: GasLimits {
                    execution: 50_000,
                    state: 0,
                },
                value: U256::from(1u64),
                data: Bytes::new(),
            }],
            ..verify_tx
        };
        let err = default_tx.validate_static_constraints().unwrap_err();
        assert!(
            err.contains("non-zero value only allowed in SENDER mode"),
            "unexpected error for DEFAULT: {err}"
        );

        // SENDER frame with a non-zero value must remain valid.
        let sender_tx = FrameTransaction {
            frames: vec![Frame {
                mode: FrameMode::Sender as u8,
                flags: 0x00,
                target: Some(Address::from_low_u64_be(0x1234)),
                gas_limits: GasLimits {
                    execution: 50_000,
                    state: 0,
                },
                value: U256::from(1u64),
                data: Bytes::new(),
            }],
            ..default_tx
        };
        sender_tx
            .validate_static_constraints()
            .expect("SENDER frames may carry non-zero value");
    }

    // ── EIP-8141 fork-gate predicate tests ──

    fn chain_config_with_hegota(hegota_time: Option<u64>) -> crate::types::ChainConfig {
        crate::types::ChainConfig {
            hegota_time,
            ..Default::default()
        }
    }

    #[test]
    fn test_frame_tx_pre_fork_chain_config_rejects() {
        let cfg = chain_config_with_hegota(None);
        assert!(!cfg.is_hegota_activated(0));
        assert!(!cfg.is_hegota_activated(u64::MAX));
    }

    #[test]
    fn test_frame_tx_post_fork_admits() {
        let cfg = chain_config_with_hegota(Some(1000));
        assert!(cfg.is_hegota_activated(2000));
    }

    #[test]
    fn test_frame_tx_fork_boundary_admits() {
        let activation_time = 1_700_000_000u64;
        let cfg = chain_config_with_hegota(Some(activation_time));
        assert!(cfg.is_hegota_activated(activation_time));
        assert!(!cfg.is_hegota_activated(activation_time - 1));
    }

    #[test]
    fn test_frame_tx_devnet_fork_epoch_zero_admits() {
        let cfg = chain_config_with_hegota(Some(0));
        assert!(cfg.is_hegota_activated(0));
        assert!(cfg.is_hegota_activated(1));
        assert!(cfg.is_hegota_activated(u64::MAX));
    }

    #[test]
    fn test_frame_tx_pre_fork_rlp_roundtrip_still_decodes() {
        // RLP decoding is fork-unaware and must stay lossless so validators surface
        // a FrameTxPreFork error downstream rather than a corrupt-RLP error.
        let tx = make_test_frame_tx();
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let (decoded, rest) = FrameTransaction::decode_unfinished(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.chain_id, tx.chain_id);
        assert_eq!(decoded.nonce, tx.nonce);
        assert_eq!(decoded.sender, tx.sender);
    }

    // ── EIP-8141 expiry verifier frame tests ──

    fn expiry_frame(deadline: u64) -> Frame {
        Frame {
            mode: FrameMode::Verify as u8,
            flags: 0x00,
            target: Some(frame_tx_expiry_verifier()),
            gas_limits: GasLimits {
                execution: 30_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::copy_from_slice(&deadline.to_be_bytes()),
        }
    }

    #[test]
    fn expiry_verifier_frame_passes_static_validation() {
        let mut tx = make_test_frame_tx();
        tx.frames.insert(0, expiry_frame(1_700_000_000));
        assert!(tx.validate_static_constraints().is_ok());
    }

    #[test]
    fn expiry_verifier_frame_rejects_bad_data_length() {
        let mut tx = make_test_frame_tx();
        let mut f = expiry_frame(0);
        f.data = Bytes::from_static(b"short");
        tx.frames.insert(0, f);
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("8 bytes"), "{err}");
    }

    #[test]
    fn expiry_verifier_frame_rejects_nonzero_flags() {
        let mut tx = make_test_frame_tx();
        let mut f = expiry_frame(0);
        f.flags = 0x01;
        tx.frames.insert(0, f);
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("flags == 0"), "{err}");
    }

    #[test]
    fn at_most_one_expiry_verifier_frame() {
        let mut tx = make_test_frame_tx();
        tx.frames.insert(0, expiry_frame(1));
        tx.frames.insert(0, expiry_frame(2));
        let err = tx.validate_static_constraints().unwrap_err();
        assert!(err.contains("more than one expiry"), "{err}");
    }

    #[test]
    fn verify_frame_with_zero_scope_is_now_statically_valid() {
        // EIP-8141 has no the VERIFY-needs-nonzero-scope rule.
        // make_test_frame_tx() frame[0] is VERIFY with flags=0x03 targeting sender;
        // setting flags to 0 makes it a zero-scope VERIFY (not an expiry frame,
        // since target is the sender address, not EXPIRY_VERIFIER).
        let mut tx = make_test_frame_tx();
        tx.frames[0].flags = 0x00;
        assert!(tx.validate_static_constraints().is_ok());
    }

    #[test]
    fn sig_hash_covers_expiry_deadline_and_all_verify_data() {
        // Updated for all frame data is now covered.
        let mut tx_a = make_test_frame_tx();
        tx_a.frames.insert(0, expiry_frame(100));
        let mut tx_b = make_test_frame_tx();
        tx_b.frames.insert(0, expiry_frame(200));
        // Different deadlines -> different sig hashes (expiry data covered).
        assert_ne!(tx_a.compute_sig_hash(), tx_b.compute_sig_hash());

        // Different NON-expiry VERIFY data -> different sig hash (no longer elided).
        let tx_c = make_test_frame_tx();
        let mut tx_d = make_test_frame_tx();
        tx_d.frames[0].data = Bytes::from_static(b"different_verify_data");
        assert_ne!(tx_c.compute_sig_hash(), tx_d.compute_sig_hash());
    }

    #[test]
    fn expiry_deadline_parses_or_none() {
        let mut tx = make_test_frame_tx();
        assert_eq!(tx.expiry_deadline(), None);
        tx.frames.insert(0, expiry_frame(1_700_000_123));
        assert_eq!(tx.expiry_deadline(), Some(1_700_000_123));
    }

    #[test]
    fn signature_rlp_roundtrip() {
        let sig = FrameSignature {
            scheme: FRAME_SIG_SCHEME_P256,
            signer: Some(Address::from_low_u64_be(0x1234)),
            msg: Bytes::from(vec![7u8; 32]),
            signature: Bytes::from(vec![9u8; 128]),
        };
        let mut buf = Vec::new();
        sig.encode(&mut buf);
        let (decoded, rest) = FrameSignature::decode_unfinished(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, sig);
    }

    #[test]
    fn frame_tx_with_signatures_rlp_roundtrip() {
        let tx = make_test_frame_tx();
        assert!(!tx.signatures.is_empty());
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let (decoded, rest) = FrameTransaction::decode_unfinished(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.signatures, tx.signatures);
        assert_eq!(decoded.frames, tx.frames);
        assert_eq!(decoded.nonce, tx.nonce);
    }

    #[test]
    fn p2p_frame_transaction_rlp_roundtrip() {
        // A frame tx (EIP-8141) must survive a full P2PTransaction RLP
        // encode/decode round-trip so it can be served over the wire on request.
        let ft = make_test_frame_tx();
        assert!(!ft.signatures.is_empty());
        assert!(!ft.frames.is_empty());
        let original = P2PTransaction::FrameTransaction(ft);

        let encoded = original.encode_to_vec();
        let (decoded, rest) = P2PTransaction::decode_unfinished(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, original);
        assert_eq!(decoded.tx_type(), TxType::Frame);

        // The decoded variant converts cleanly into a regular Transaction
        // (frame txs carry no blobs bundle).
        let as_tx: Transaction = decoded.try_into().unwrap();
        assert!(matches!(as_tx, Transaction::FrameTransaction(_)));
    }

    #[test]
    fn static_validation_rejects_unknown_scheme() {
        let mut tx = make_test_frame_tx();
        tx.signatures[0].scheme = 3;
        assert!(
            tx.validate_static_constraints()
                .unwrap_err()
                .contains("unsupported scheme"),
        );
    }

    #[test]
    fn static_validation_accepts_arbitrary_with_empty_signer() {
        let mut tx = make_test_frame_tx();
        // ARBITRARY (scheme 0) requires an empty signer and costs 100 verify gas.
        tx.signatures[0].scheme = FRAME_SIG_SCHEME_ARBITRARY;
        tx.signatures[0].signer = None;
        assert!(tx.validate_static_constraints().is_ok());
        assert_eq!(tx.signature_verification_cost(), 100);
    }

    #[test]
    fn static_validation_rejects_arbitrary_with_signer() {
        let mut tx = make_test_frame_tx();
        tx.signatures[0].scheme = FRAME_SIG_SCHEME_ARBITRARY;
        tx.signatures[0].signer = Some(Address::from_low_u64_be(0xABCD));
        assert!(
            tx.validate_static_constraints()
                .unwrap_err()
                .contains("ARBITRARY signatures must not name a signer"),
        );
    }

    #[test]
    fn static_validation_rejects_bad_msg_length() {
        let mut tx = make_test_frame_tx();
        tx.signatures[0].msg = Bytes::from(vec![1u8; 16]);
        assert!(
            tx.validate_static_constraints()
                .unwrap_err()
                .contains("32 bytes"),
        );
    }

    #[test]
    fn static_validation_rejects_zero_explicit_msg() {
        let mut tx = make_test_frame_tx();
        tx.signatures[0].msg = Bytes::from(vec![0u8; 32]);
        assert!(
            tx.validate_static_constraints()
                .unwrap_err()
                .contains("zero digest"),
        );
    }

    #[test]
    fn sig_hash_elides_empty_msg_signature_bytes() {
        let mut a = make_test_frame_tx();
        let mut b = make_test_frame_tx();
        // empty-msg signature: changing raw bytes must NOT change the hash.
        assert!(a.signatures[0].msg.is_empty());
        a.signatures[0].signature = Bytes::from(vec![1u8; 65]);
        b.signatures[0].signature = Bytes::from(vec![2u8; 65]);
        assert_eq!(a.compute_sig_hash(), b.compute_sig_hash());
    }

    #[test]
    fn sig_hash_covers_frame_data_now() {
        let mut a = make_test_frame_tx();
        let mut b = make_test_frame_tx();
        // frame 0 is a VERIFY frame; its data is now COVERED (not elided).
        a.frames[0].data = Bytes::from_static(b"aaaa");
        b.frames[0].data = Bytes::from_static(b"bbbb");
        assert_ne!(a.compute_sig_hash(), b.compute_sig_hash());
    }

    #[test]
    fn sig_hash_covers_explicit_msg_signature_bytes() {
        let mut a = make_test_frame_tx();
        let mut b = make_test_frame_tx();
        a.signatures[0].msg = Bytes::from(vec![9u8; 32]);
        b.signatures[0].msg = Bytes::from(vec![9u8; 32]);
        a.signatures[0].signature = Bytes::from(vec![1u8; 65]);
        b.signatures[0].signature = Bytes::from(vec![2u8; 65]);
        // explicit-msg signatures keep their bytes -> different hash.
        assert_ne!(a.compute_sig_hash(), b.compute_sig_hash());
    }

    #[test]
    fn max_gas_includes_signature_costs() {
        let mut tx = make_test_frame_tx();
        let base = tx.max_gas();
        // Add a P256 signature; cost must rise by at least 6700 + its calldata.
        tx.signatures.push(FrameSignature {
            scheme: FRAME_SIG_SCHEME_P256,
            signer: Some(Address::from_low_u64_be(1)),
            msg: Bytes::new(),
            signature: Bytes::from(vec![0u8; 128]),
        });
        assert!(tx.max_gas() >= base + 6700);
        assert_eq!(tx.signature_verification_cost(), 2800 + 6700);
    }

    #[test]
    fn golden_frame_tx_rlp_and_sig_hash() {
        // Regression lock for the EIP-8141 payload shape: seven top-level items
        // with the three fees nested as one list, and each frame's gas limits
        // nested as `[execution, state]`. Both nestings round-trip through this
        // crate's own encoder even if a level were dropped -- encoder and decoder
        // would simply agree on the flattened form -- so the assertions below are
        // byte vectors rather than round-trips. They are the RLP of the spec's
        // `FrameTransaction` and `Frame` field order, derived by hand; the hash is
        // keccak256 over `0x06` and the same payload with the empty-msg
        // signature's bytes elided.
        let tx = FrameTransaction {
            chain_id: 1,
            nonce: 7,
            sender: Address::from_low_u64_be(0xABCD),
            frames: vec![
                Frame {
                    mode: 1,
                    flags: 3,
                    target: None,
                    gas_limits: GasLimits {
                        execution: 0x5208,
                        state: 0,
                    },
                    value: U256::zero(),
                    data: Bytes::from_static(&[0x11, 0x22]),
                },
                Frame {
                    mode: 2,
                    flags: 0,
                    target: Some(Address::from_low_u64_be(0x1234)),
                    gas_limits: GasLimits {
                        execution: 0x9c40,
                        state: 0,
                    },
                    value: U256::zero(),
                    data: Bytes::new(),
                },
            ],
            signatures: vec![FrameSignature {
                scheme: FRAME_SIG_SCHEME_SECP256K1,
                signer: Some(Address::from_low_u64_be(0xABCD)),
                msg: Bytes::new(),
                signature: Bytes::from(vec![0x01u8; 65]),
            }],
            max_priority_fee_per_gas: U256::from(0x3b9aca00u64),
            max_fee_per_gas: U256::from(0x6fc23ac00u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: vec![],
            inner_hash: OnceCell::new(),
            cached_canonical: OnceCell::new(),
        };

        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let rlp_hex = hex::encode(&buf);
        assert_eq!(
            rlp_hex,
            "f8b0010794000000000000000000000000000000000000abcdeccc010380c48252088080821122de0280940000000000000000000000000000000000001234c4829c40808080f85cf85a0194000000000000000000000000000000000000abcd80b8410101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101cc843b9aca008506fc23ac0080c0"
        );

        // Round-trips losslessly.
        let (decoded, rest) = FrameTransaction::decode_unfinished(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, tx);

        let sig_hash = tx.compute_sig_hash();
        assert_eq!(
            format!("{:#x}", sig_hash),
            "0x650c2745cb56e514d74d8b3754d9265b92131e4ec7e0b8ea50671edb7b9255a3",
        );

        // Elision invariant: changing empty-msg signature bytes must NOT change sig_hash.
        let mut tx2 = tx.clone();
        tx2.signatures[0].signature = Bytes::from(vec![0x02u8; 65]);
        assert_eq!(
            tx.compute_sig_hash(),
            tx2.compute_sig_hash(),
            "sig_hash must be independent of empty-msg signature bytes",
        );
    }

    #[test]
    fn test_cost_without_base_fee_eip4844_includes_blob_gas() {
        // Regression test for mempool balance check: for EIP-4844 txs,
        // cost_without_base_fee() MUST include blob_gas_used * max_fee_per_blob_gas.
        // Every peer client (geth, reth, nethermind, erigon, besu) does this.
        use crate::constants::GAS_PER_BLOB;

        let max_fee_per_gas: u64 = 100;
        let gas: u64 = 21_000;
        let value = U256::from(7u64);
        let max_fee_per_blob_gas = U256::from(50u64);
        let blob_count: usize = 1;

        let tx = Transaction::EIP4844Transaction(EIP4844Transaction {
            max_fee_per_gas,
            gas,
            value,
            max_fee_per_blob_gas,
            blob_versioned_hashes: vec![H256::zero(); blob_count],
            ..Default::default()
        });

        let got = tx.cost_without_base_fee().expect("cost is computable");

        let gas_cost = U256::from(max_fee_per_gas) * U256::from(gas);
        let blob_gas = U256::from(GAS_PER_BLOB) * U256::from(blob_count as u64);
        let blob_cost = blob_gas * max_fee_per_blob_gas;
        let expected = gas_cost + blob_cost + value;

        assert_eq!(
            got, expected,
            "blob-gas term missing from cost_without_base_fee() for EIP-4844"
        );
    }
}
