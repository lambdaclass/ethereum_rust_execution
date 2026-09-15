//! SSZ containers for EIP-8025 (Optional Execution Proofs) and the
//! stateless validation flow used by native rollups.
//!
//! The first section mirrors the CL-side SSZ definitions used for
//! tree-hashing `NewPayloadRequest` and producing the `PublicInput`
//! committed to by execution proofs. The second section layers the
//! native-rollup types (`SszStatelessInput`, `SszStatelessValidationResult`,
//! `SszExecutionWitness`) on top of those.

use bytes::Bytes;
use libssz::{SszDecode, SszEncode};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_merkle::{
    HashTreeRoot, Node, Sha256Hasher, merkleize_progressive, mix_in_active_fields,
};
use libssz_types::{ProgressiveList, SszList, SszVector};

use super::requests::EncodedRequests;

// ============================================================================
// EIP-8025 containers
// ============================================================================

// ── Spec limits (Electra) ──────────────────────────────────────────

/// `MAX_EXTRA_DATA_BYTES`.
const MAX_EXTRA_DATA_BYTES: usize = 32;

// ── EIP-7685 request type prefixes ─────────────────────────────────

const DEPOSIT_REQUEST_TYPE: u8 = 0x00;
const WITHDRAWAL_REQUEST_TYPE: u8 = 0x01;
const CONSOLIDATION_REQUEST_TYPE: u8 = 0x02;
const BUILDER_DEPOSIT_REQUEST_TYPE: u8 = 0x03;
const BUILDER_EXIT_REQUEST_TYPE: u8 = 0x04;

// ── Bytes20 wrapper (address) ──────────────────────────────────────
//
// libssz implements `SszEncode`/`SszDecode` for `[u8; 20]` but NOT
// `HashTreeRoot`. Per the SSZ spec, a 20-byte basic value is
// right-padded with zeros to 32 bytes for its tree hash leaf.

/// A 20-byte value (e.g. an execution address) with SSZ + HTR support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Bytes20(pub [u8; 20]);

impl SszEncode for Bytes20 {
    fn is_fixed_size() -> bool {
        true
    }
    fn fixed_size() -> usize {
        20
    }
    fn encoded_len(&self) -> usize {
        20
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf);
    }
}

impl SszDecode for Bytes20 {
    fn is_fixed_size() -> bool {
        true
    }
    fn fixed_size() -> usize {
        20
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, libssz::DecodeError> {
        <[u8; 20]>::from_ssz_bytes(bytes).map(Self)
    }
}

impl HashTreeRoot for Bytes20 {
    fn hash_tree_root(&self, _hasher: &impl Sha256Hasher) -> libssz_merkle::Node {
        let mut node = [0u8; 32];
        node[..20].copy_from_slice(&self.0);
        node
    }
}

impl From<[u8; 20]> for Bytes20 {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl From<Bytes20> for [u8; 20] {
    fn from(b: Bytes20) -> Self {
        b.0
    }
}

// ── LogsBloom type alias ───────────────────────────────────────────
//
// `logs_bloom` is `ByteVector[BYTES_PER_LOGS_BLOOM]` in the CL spec —
// a fixed-length SSZ vector of 256 bytes.

/// `BYTES_PER_LOGS_BLOOM` from the CL spec.
pub const BYTES_PER_LOGS_BLOOM: usize = 256;

/// `ByteVector[256]` — the logs bloom as a fixed-size SSZ vector.
pub type LogsBloom = SszVector<u8, BYTES_PER_LOGS_BLOOM>;

// ── Sub-containers ─────────────────────────────────────────────────

/// SSZ `Withdrawal` container matching the CL spec.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: Bytes20,
    pub amount: u64,
}

/// SSZ `DepositRequest` container (EIP-6110).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DepositRequest {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
    pub index: u64,
}

/// SSZ `WithdrawalRequest` container (EIP-7002).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct WithdrawalRequest {
    pub source_address: Bytes20,
    pub validator_pubkey: [u8; 48],
    pub amount: u64,
}

/// SSZ `ConsolidationRequest` container (EIP-7251).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ConsolidationRequest {
    pub source_address: Bytes20,
    pub source_pubkey: [u8; 48],
    pub target_pubkey: [u8; 48],
}

/// SSZ `BuilderDepositRequest` container (EIP-8282).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BuilderDepositRequest {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
}

/// SSZ `BuilderExitRequest` container (EIP-8282).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BuilderExitRequest {
    pub source_address: Bytes20,
    pub pubkey: [u8; 48],
}

// ── ExecutionPayload ───────────────────────────────────────────────

/// SSZ container matching `SszExecutionPayload` at execution-specs `3c3b6f4af`
/// (#3248): a `ProgressiveContainer(active_fields=[1; 19])` whose transaction,
/// withdrawal and block-access-list fields are progressive lists.
///
/// `HashTreeRoot` is hand-written because `libssz-derive` has no progressive
/// support; encode/decode still derive, since nothing progressive changes the
/// wire layout (`ProgressiveList` delegates both to `Vec<T>`).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ExecutionPayload {
    pub parent_hash: [u8; 32],
    pub fee_recipient: Bytes20,
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: LogsBloom,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// `base_fee_per_gas` encoded as a 256-bit unsigned integer (little-endian).
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: [u8; 32],
    pub transactions: ProgressiveList<ProgressiveList<u8>>,
    pub withdrawals: ProgressiveList<Withdrawal>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    /// EIP-7928 block-level access list (full serialized BAL bytes).
    pub block_access_list: ProgressiveList<u8>,
    /// EIP-7843 slot number (Amsterdam+). Last field, matching the execution-specs
    /// `ExecutionPayloadV4` layout so the native path is byte-compatible with the
    /// spec-current payload. Provided by the L2 producer and carried to L1.
    pub slot_number: u64,
}

/// `ProgressiveContainer` merkleization, per EIP-7495/EIP-7916:
/// `mix_in_active_fields(merkleize_progressive(field_roots), active_fields)`.
///
/// Hand-written because `libssz-derive` has no progressive support.
///
/// The roots are verified against remerkleable by
/// `test/tests/common/progressive_ssz_tests.rs`. `libssz-merkle 0.2.2` had its
/// progressive subtree children reversed relative to the reference, which made
/// every root here wrong; the workspace pins 0.3.0, which fixes it, and those
/// tests are what hold that pin in place.
fn progressive_container_root<const N: usize>(
    hasher: &impl Sha256Hasher,
    field_roots: [Node; N],
) -> Node {
    let root = merkleize_progressive(hasher, &field_roots);
    mix_in_active_fields(hasher, &root, &[true; N])
}

impl HashTreeRoot for ExecutionPayload {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        // Destructured without `..` on purpose: this list is hand-maintained, so
        // a field added to the struct must fail to compile here rather than be
        // silently left out of the root and out of `active_fields`.
        // Declaration order is the SSZ field order; do not reorder.
        let Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
            blob_gas_used,
            excess_blob_gas,
            block_access_list,
            slot_number,
        } = self;
        progressive_container_root(
            hasher,
            [
                parent_hash.hash_tree_root(hasher),
                fee_recipient.hash_tree_root(hasher),
                state_root.hash_tree_root(hasher),
                receipts_root.hash_tree_root(hasher),
                logs_bloom.hash_tree_root(hasher),
                prev_randao.hash_tree_root(hasher),
                block_number.hash_tree_root(hasher),
                gas_limit.hash_tree_root(hasher),
                gas_used.hash_tree_root(hasher),
                timestamp.hash_tree_root(hasher),
                extra_data.hash_tree_root(hasher),
                base_fee_per_gas.hash_tree_root(hasher),
                block_hash.hash_tree_root(hasher),
                transactions.hash_tree_root(hasher),
                withdrawals.hash_tree_root(hasher),
                blob_gas_used.hash_tree_root(hasher),
                excess_blob_gas.hash_tree_root(hasher),
                block_access_list.hash_tree_root(hasher),
                slot_number.hash_tree_root(hasher),
            ],
        )
    }
}

// ── ExecutionRequests ──────────────────────────────────────────────

/// SSZ `ExecutionRequests` at execution-specs `3c3b6f4af`: a
/// `ProgressiveContainer(active_fields=[1; 5])` carrying the EIP-7685 bundle
/// including the EIP-8282 builder requests.
///
/// `HashTreeRoot` is hand-written; see [`ExecutionPayload`].
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ExecutionRequests {
    pub deposits: ProgressiveList<DepositRequest>,
    pub withdrawals: ProgressiveList<WithdrawalRequest>,
    pub consolidations: ProgressiveList<ConsolidationRequest>,
    pub builder_deposits: ProgressiveList<BuilderDepositRequest>,
    pub builder_exits: ProgressiveList<BuilderExitRequest>,
}

impl ExecutionRequests {
    /// Produce the EIP-7685 encoded form: five `EncodedRequests` entries,
    /// one per request type, each `[type_byte] ++ concat(ssz_encode(item))`.
    ///
    /// The five request types are all fixed-size SSZ containers, so their
    /// SSZ encoding is byte-for-byte the EL wire concatenation that
    /// `compute_requests_hash` expects.
    pub fn to_encoded_requests(&self) -> Vec<EncodedRequests> {
        fn encode<T: SszEncode>(
            type_byte: u8,
            items: impl IntoIterator<Item = T>,
        ) -> EncodedRequests {
            let mut buf = Vec::new();
            buf.push(type_byte);
            for item in items {
                item.ssz_append(&mut buf);
            }
            EncodedRequests(Bytes::from(buf))
        }

        vec![
            encode(DEPOSIT_REQUEST_TYPE, self.deposits.iter().cloned()),
            encode(WITHDRAWAL_REQUEST_TYPE, self.withdrawals.iter().cloned()),
            encode(
                CONSOLIDATION_REQUEST_TYPE,
                self.consolidations.iter().cloned(),
            ),
            encode(
                BUILDER_DEPOSIT_REQUEST_TYPE,
                self.builder_deposits.iter().cloned(),
            ),
            encode(
                BUILDER_EXIT_REQUEST_TYPE,
                self.builder_exits.iter().cloned(),
            ),
        ]
    }
}

impl HashTreeRoot for ExecutionRequests {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        // Destructured without `..` — see [`ExecutionPayload`].
        let Self {
            deposits,
            withdrawals,
            consolidations,
            builder_deposits,
            builder_exits,
        } = self;
        progressive_container_root(
            hasher,
            [
                deposits.hash_tree_root(hasher),
                withdrawals.hash_tree_root(hasher),
                consolidations.hash_tree_root(hasher),
                builder_deposits.hash_tree_root(hasher),
                builder_exits.hash_tree_root(hasher),
            ],
        )
    }
}

// ── NewPayloadRequest ──────────────────────────────────────────────

/// SSZ `NewPayloadRequest` — the key container whose `hash_tree_root` is
/// the public input committed to by an execution proof.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    pub versioned_hashes: ProgressiveList<[u8; 32]>,
    pub parent_beacon_block_root: [u8; 32],
    pub execution_requests: ExecutionRequests,
}

// ── PublicInput ────────────────────────────────────────────────────

/// The public input for an execution proof: the `hash_tree_root` of the
/// `NewPayloadRequest`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PublicInput {
    pub new_payload_request_root: [u8; 32],
}

impl NewPayloadRequest {
    /// Compute the `hash_tree_root` of this request — the value that
    /// becomes the execution proof's public input.
    pub fn public_input(&self, hasher: &impl Sha256Hasher) -> PublicInput {
        PublicInput {
            new_payload_request_root: self.hash_tree_root(hasher),
        }
    }
}

// ============================================================================
// Stateless validation containers (native rollups / EXECUTE precompile)
// ============================================================================

// ── Stateless validation limits ──────────────────────────────────

// `state`, `codes` and `public_keys` carry no element-count bound: #3356 made
// them `ProgressiveList`, which grows without a declared capacity, so the
// upstream `MAX_WITNESS_NODES` / `MAX_WITNESS_CODES` / `MAX_PUBLIC_KEYS`
// constants were deleted along with it. The per-element byte caps below stay,
// and `headers` keeps its count bound — it is deliberately still an `SszList`.

/// MAX_BYTES_PER_WITNESS_NODE — max size of a single witness node.
const MAX_BYTES_PER_WITNESS_NODE: usize = 1_048_576; // 2^20
/// MAX_BYTES_PER_CODE — max size of a single code preimage (EIP-7954).
const MAX_BYTES_PER_CODE: usize = 16_777_216; // 2^24
/// MAX_WITNESS_HEADERS — max RLP-encoded block headers in witness (up to 256).
const MAX_WITNESS_HEADERS: usize = 256;
/// MAX_BYTES_PER_HEADER — max size of a single RLP-encoded header.
const MAX_BYTES_PER_HEADER: usize = 1_024; // 2^10
/// PUBLIC_KEY_BYTES — an uncompressed secp256k1 public key is 65 bytes.
const PUBLIC_KEY_BYTES: usize = 65;

// ── Stateless validation types ───────────────────────────────────
//
// Mirror the definitions in execution-specs (projects/zkevm branch) at the
// commit EIP-8025 PR #11604 pins:
// https://github.com/ethereum/execution-specs/blob/85fc20ca5937719a854472a87cb48d01ef1dffca/src/ethereum/forks/amsterdam/stateless_ssz.py

/// Schema id of the stateless input wire format: `fork_index << 8 | revision`,
/// where fork `0x15` is Amsterdam and revision `0x01` is the current encoding.
///
/// The 2-byte big-endian prefix is how the fork reaches the guest at all — #3278
/// removed all chain configuration from the SSZ body — and it is echoed as a
/// public output field so a verifier can pin which rules were applied. Upstream
/// rejects any other id outright; so does ethrex.
///
/// Note that upstream keeps `0x1501` across incompatible body changes, so the id
/// does **not** identify the encoding. Three dialects have shipped under it:
/// `tests-zkevm@v0.6.2`, then #3248 + #3278, then #3356 (which moved `state`,
/// `codes` and `public_keys` to `ProgressiveList`). ethrex speaks the last one.
/// Releases since have only rearranged the Python that declares it, and SSZ
/// encoding is positional, so renames and module moves leave the wire alone;
/// which bundle is actually pinned lives in `tooling/ef_tests/.fixtures_url_zkevm`.
/// A bundle from an older dialect will not be caught by this prefix — it fails
/// later, in decode or on a mismatched root.
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Byte length of the big-endian [`STATELESS_INPUT_SCHEMA_ID`] prefix.
pub const STATELESS_INPUT_SCHEMA_ID_SIZE: usize = 2;

/// SSZ shape of `SszStatelessInput::public_keys`: one fixed-size 65-byte
/// uncompressed secp256k1 key per transaction.
///
/// Aliased so consumers can name the type without restating it here.
pub type SszPublicKeys = ProgressiveList<SszVector<u8, PUBLIC_KEY_BYTES>>;

/// SSZ `ExecutionWitness` container matching the execution-specs definition.
///
/// Contains all data needed for stateless execution:
/// - `state`: trie-node preimages
/// - `codes`: contract code preimages
/// - `headers`: RLP-encoded parent block headers (up to 256)
///
/// `state` and `codes` are `ProgressiveList` as of execution-specs #3356;
/// `headers` stays a bounded `SszList`, since execution only ever exposes the
/// previous 256 block hashes. The mixed shape is upstream's, not an oversight.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SszExecutionWitness {
    pub state: ProgressiveList<SszList<u8, MAX_BYTES_PER_WITNESS_NODE>>,
    pub codes: ProgressiveList<SszList<u8, MAX_BYTES_PER_CODE>>,
    pub headers: SszList<SszList<u8, MAX_BYTES_PER_HEADER>, MAX_WITNESS_HEADERS>,
}

/// SSZ `StatelessInput` — the top-level input to `verify_stateless_new_payload`.
///
/// Wraps a `NewPayloadRequest` together with the execution witness,
/// chain configuration, and (optionally) pre-recovered public keys.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SszStatelessInput {
    pub new_payload_request: NewPayloadRequest,
    pub witness: SszExecutionWitness,
    /// Chain identifier. #3278 removed `ChainConfig` from the wire: fork
    /// activation info and blob schedules are guest-internal, keyed by
    /// `(chain_id, fork)`, with the fork coming from the schema-id prefix.
    pub chain_id: u64,
    pub public_keys: SszPublicKeys,
}

/// SSZ `StatelessValidationResult` — the output of `verify_stateless_new_payload`.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SszStatelessValidationResult {
    pub new_payload_request_root: [u8; 32],
    pub successful_validation: bool,
    /// Chain identifier echoed from the input — real even when validation fails;
    /// only a decode failure yields the all-zero default.
    pub chain_id: u64,
    /// The full schema id the guest decoded (`0x1501` for Amsterdam revision 1).
    /// Public so a verifier can pin which fork rules and encoding were used, for
    /// forks that share a payload shape. Added by execution-specs #3278.
    pub schema_id: u16,
}

// ── Conversions to internal types ────────────────────────────────

impl SszExecutionWitness {
    /// Extract raw bytes from SSZ lists for codes.
    pub fn codes_as_vecs(&self) -> Vec<Vec<u8>> {
        self.codes.iter().map(|c| c.to_vec()).collect()
    }

    /// Extract raw bytes from SSZ lists for headers.
    pub fn headers_as_vecs(&self) -> Vec<Vec<u8>> {
        self.headers.iter().map(|h| h.to_vec()).collect()
    }

    /// Extract raw bytes from SSZ lists for state nodes.
    pub fn state_as_vecs(&self) -> Vec<Vec<u8>> {
        self.state.iter().map(|n| n.to_vec()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz_merkle::Sha2Hasher;

    const HASHER: Sha2Hasher = Sha2Hasher;

    // ── EIP-8025 helpers ─────────────────────────────────────────

    fn sample_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: [1u8; 32],
            fee_recipient: Bytes20([2u8; 20]),
            state_root: [3u8; 32],
            receipts_root: [4u8; 32],
            logs_bloom: vec![0u8; 256].try_into().expect("logs_bloom length"),
            prev_randao: [5u8; 32],
            block_number: 42,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: vec![0xAB, 0xCD].try_into().expect("extra_data fits"),
            base_fee_per_gas: {
                let mut b = [0u8; 32];
                b[0] = 7; // 7 in LE
                b
            },
            block_hash: [6u8; 32],
            transactions: vec![
                vec![0xDE, 0xAD, 0xBE, 0xEF]
                    .try_into()
                    .expect("tx bytes fit"),
            ]
            .try_into()
            .expect("txs fit"),
            withdrawals: vec![Withdrawal {
                index: 0,
                validator_index: 1,
                address: Bytes20([7u8; 20]),
                amount: 1_000_000,
            }]
            .try_into()
            .expect("withdrawals fit"),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: ProgressiveList::new(), // TODO(Plan 02): populate full BAL
            slot_number: 0,
        }
    }

    fn empty_requests() -> ExecutionRequests {
        ExecutionRequests {
            deposits: Vec::new().into(),
            withdrawals: Vec::new().into(),
            consolidations: Vec::new().into(),
            builder_deposits: Vec::new().into(),
            builder_exits: Vec::new().into(),
        }
    }

    fn sample_request() -> NewPayloadRequest {
        NewPayloadRequest {
            execution_payload: sample_payload(),
            versioned_hashes: Vec::new().into(),
            parent_beacon_block_root: [8u8; 32],
            execution_requests: empty_requests(),
        }
    }

    #[test]
    fn test_ssz_root_changes_with_different_data() {
        let request1 = sample_request();
        let mut request2 = sample_request();
        request2.execution_payload.block_number = 99;

        assert_ne!(
            request1.hash_tree_root(&HASHER),
            request2.hash_tree_root(&HASHER),
            "Different payloads must produce different roots"
        );
    }

    #[test]
    fn test_ssz_root_is_deterministic() {
        let request = sample_request();
        let root1 = request.hash_tree_root(&HASHER);
        let root2 = request.hash_tree_root(&HASHER);
        assert_eq!(root1, root2, "Same request must produce same root");
    }

    #[test]
    fn test_execution_requests_to_encoded_bytes() {
        let requests = ExecutionRequests {
            deposits: vec![DepositRequest {
                pubkey: [0x11; 48],
                withdrawal_credentials: [0x22; 32],
                amount: 32_000_000_000,
                signature: [0x33; 96],
                index: 7,
            }]
            .into(),
            withdrawals: vec![WithdrawalRequest {
                source_address: Bytes20([0x44; 20]),
                validator_pubkey: [0x55; 48],
                amount: 1_000_000,
            }]
            .into(),
            consolidations: vec![ConsolidationRequest {
                source_address: Bytes20([0x66; 20]),
                source_pubkey: [0x77; 48],
                target_pubkey: [0x88; 48],
            }]
            .into(),
            builder_deposits: ProgressiveList::new(),
            builder_exits: ProgressiveList::new(),
        };

        let encoded = requests.to_encoded_requests();
        // Five entries since EIP-8282: the two builder lists are empty here, and
        // `compute_requests_hash` skips entries of length <= 1, so an empty
        // builder list leaves the requests hash unchanged.
        assert_eq!(encoded.len(), 5, "must emit 5 EIP-7685 entries");

        // Deposit: [0x00] ++ 192 bytes
        assert_eq!(encoded[0].0[0], DEPOSIT_REQUEST_TYPE);
        assert_eq!(encoded[0].0.len(), 1 + 192);

        // Withdrawal: [0x01] ++ 76 bytes
        assert_eq!(encoded[1].0[0], WITHDRAWAL_REQUEST_TYPE);
        assert_eq!(encoded[1].0.len(), 1 + 76);

        // Consolidation: [0x02] ++ 116 bytes
        assert_eq!(encoded[2].0[0], CONSOLIDATION_REQUEST_TYPE);
        assert_eq!(encoded[2].0.len(), 1 + 116);
    }

    // ── Stateless helpers ────────────────────────────────────────

    fn list<T: SszEncode + SszDecode, const N: usize>(items: Vec<T>) -> SszList<T, N> {
        let mut list = SszList::new();
        for item in items {
            list.push(item).expect("test list capacity exceeded");
        }
        list
    }

    fn round_trip<T: SszEncode + SszDecode + PartialEq + std::fmt::Debug>(value: &T) {
        let mut buf = Vec::new();
        value.ssz_append(&mut buf);
        let decoded = T::from_ssz_bytes(&buf).expect("SSZ decode failed");
        assert_eq!(*value, decoded, "round-trip mismatch");
    }

    #[test]
    fn ssz_execution_witness_round_trip() {
        let witness = SszExecutionWitness {
            state: vec![list(vec![1u8, 2, 3]), list(vec![4u8, 5])].into(),
            codes: vec![list(vec![0x60u8, 0x00, 0x60, 0x00, 0xf3])].into(),
            headers: list(vec![list(vec![0xf9u8, 0x02, 0x11])]),
        };
        round_trip(&witness);
    }

    #[test]
    fn ssz_execution_witness_empty_round_trip() {
        let witness = SszExecutionWitness {
            state: ProgressiveList::new(),
            codes: ProgressiveList::new(),
            headers: SszList::new(),
        };
        round_trip(&witness);
    }

    #[test]
    fn ssz_execution_payload_has_block_access_list_round_trip() {
        let payload = ExecutionPayload {
            parent_hash: [0x11; 32],
            fee_recipient: Bytes20([0x22; 20]),
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: vec![0u8; 256].try_into().expect("logs_bloom length"),
            prev_randao: [0x55; 32],
            block_number: 7,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: list(vec![0xde, 0xad]),
            base_fee_per_gas: [0u8; 32],
            block_hash: [0x66; 32],
            transactions: ProgressiveList::new(),
            withdrawals: ProgressiveList::new(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: vec![0x01u8, 0x02, 0x03].into(),
            slot_number: 0,
        };
        round_trip(&payload);
        assert_eq!(payload.block_access_list.len(), 3);
    }

    #[test]
    fn ssz_public_keys_are_65_byte_vectors_round_trip() {
        let key: SszVector<u8, PUBLIC_KEY_BYTES> =
            vec![0x04u8; 65].try_into().expect("pubkey length");
        let mut keys: SszPublicKeys = ProgressiveList::new();
        keys.push(key);
        round_trip(&keys);
        assert_eq!(keys.first().unwrap().len(), 65);
    }

    #[test]
    fn ssz_stateless_validation_result_round_trip() {
        let result = SszStatelessValidationResult {
            new_payload_request_root: [0xab; 32],
            successful_validation: true,
            chain_id: 42,
            schema_id: 0x1501,
        };
        round_trip(&result);

        let result_false = SszStatelessValidationResult {
            new_payload_request_root: [0x00; 32],
            successful_validation: false,
            chain_id: 1,
            schema_id: 0x1501,
        };
        round_trip(&result_false);
    }

    // ── NativeRollup.sol SSZ offset cross-checks (I17) ───────────────
    //
    // These constants MUST equal NativeRollup.sol's SSZ offset constants
    // (crates/l2/contracts/src/nativeRollup/l1/NativeRollup.sol). If a container
    // field is reordered/resized, this test fails instead of advance() silently
    // reading the wrong bytes on L1.

    const SOL_RESULT_SUCCESS_OFFSET: usize = 32;
    // Since #3278 the result is entirely fixed-size (32 + 1 + 8 + 2 = 43 bytes):
    // chain_id is read directly at 33, schema_id at 41. There is no longer an
    // offset to dereference.
    const SOL_RESULT_CHAIN_ID_OFFSET: usize = 33;
    const SOL_RESULT_SCHEMA_ID_OFFSET: usize = 41;
    const SOL_RESULT_FIXED_LEN: usize = 43;
    const SOL_EP_STATE_ROOT_OFFSET: usize = 52;
    const SOL_EP_BLOCK_NUMBER_OFFSET: usize = 404;
    const SOL_EP_GAS_LIMIT_OFFSET: usize = 412;
    const SOL_EP_BLOCK_HASH_OFFSET: usize = 472;
    // block_access_list's offset slot sits at EP+528; slot_number (EIP-7843) is the
    // trailing fixed u64 at EP+532; the fixed prefix is 540.
    const SOL_EP_BAL_OFFSET_POS: usize = 528;
    const SOL_EP_SLOT_NUMBER_OFFSET: usize = 532;
    const SOL_EP_FIXED_PREFIX_LEN: usize = 540;

    fn u32_le(bytes: &[u8], off: usize) -> usize {
        (bytes[off] as usize)
            | ((bytes[off + 1] as usize) << 8)
            | ((bytes[off + 2] as usize) << 16)
            | ((bytes[off + 3] as usize) << 24)
    }

    fn sample_execution_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: [0x11; 32],
            fee_recipient: Bytes20([0x22; 20]),
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: vec![0u8; 256].try_into().expect("bloom"),
            prev_randao: [0x55; 32],
            block_number: 7,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: SszList::new(),
            base_fee_per_gas: [0u8; 32],
            block_hash: [0x66; 32],
            transactions: ProgressiveList::new(),
            withdrawals: ProgressiveList::new(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: ProgressiveList::new(),
            slot_number: 0x7843,
        }
    }

    #[test]
    fn nativerollup_sol_result_layout_matches() {
        // Encode a StatelessValidationResult and confirm the contract's fixed
        // offsets. Under #3278 every field is fixed-size, so all three are direct
        // reads and the total length is exactly 43 bytes.
        let result = SszStatelessValidationResult {
            new_payload_request_root: [0xAA; 32],
            successful_validation: true,
            chain_id: 0x1122334455667788,
            schema_id: 0x1501,
        };
        let mut buf = Vec::new();
        result.ssz_append(&mut buf);

        assert_eq!(
            buf.len(),
            SOL_RESULT_FIXED_LEN,
            "result must be exactly 43 fixed bytes; a variable tail means \
             ChainConfig is still in there"
        );
        assert_eq!(
            buf[SOL_RESULT_SUCCESS_OFFSET], 1,
            "successful_validation must be byte 32"
        );
        let chain_id = u64::from_le_bytes(
            buf[SOL_RESULT_CHAIN_ID_OFFSET..SOL_RESULT_CHAIN_ID_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            chain_id, 0x1122334455667788,
            "chain_id must be a direct u64 LE read at 33"
        );
        let schema_id = u16::from_le_bytes(
            buf[SOL_RESULT_SCHEMA_ID_OFFSET..SOL_RESULT_SCHEMA_ID_OFFSET + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(schema_id, 0x1501, "schema_id must be a u16 LE read at 41");
    }

    #[test]
    fn nativerollup_sol_ep_offsets_match() {
        // Encode a StatelessInput and confirm the ExecutionPayload fixed-field
        // offsets the contract reads (relative to the EP absolute offset).
        let ep = sample_execution_payload();
        let npr = NewPayloadRequest {
            execution_payload: ep,
            versioned_hashes: ProgressiveList::new(),
            parent_beacon_block_root: [0x00; 32],
            execution_requests: ExecutionRequests {
                deposits: ProgressiveList::new(),
                withdrawals: ProgressiveList::new(),
                consolidations: ProgressiveList::new(),
                builder_deposits: ProgressiveList::new(),
                builder_exits: ProgressiveList::new(),
            },
        };
        let input = SszStatelessInput {
            new_payload_request: npr,
            witness: SszExecutionWitness {
                state: ProgressiveList::new(),
                codes: ProgressiveList::new(),
                headers: SszList::new(),
            },
            chain_id: 1,
            public_keys: ProgressiveList::new(),
        };
        let mut buf = Vec::new();
        input.ssz_append(&mut buf);

        // StatelessInput fixed part = npr offset(4) + witness offset(4) +
        // chain_id(8) + public_keys offset(4) = 20 bytes. new_payload_request is
        // still field 0, so its offset is at byte 0 and the contract's dynamic
        // read there is unaffected.
        let npr_abs = u32_le(&buf, 0);
        // NewPayloadRequest fixed prefix: execution_payload offset @ npr_abs.
        let ep_abs = npr_abs + u32_le(&buf, npr_abs);
        // The EP fixed FIELD offsets the contract reads must land where expected:
        let actual_block_number = u64::from_le_bytes(
            buf[ep_abs + SOL_EP_BLOCK_NUMBER_OFFSET..ep_abs + SOL_EP_BLOCK_NUMBER_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            actual_block_number, 7,
            "block_number must be at EP offset 404, actual offset produces: {}",
            actual_block_number
        );
        let actual_gas_limit = u64::from_le_bytes(
            buf[ep_abs + SOL_EP_GAS_LIMIT_OFFSET..ep_abs + SOL_EP_GAS_LIMIT_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            actual_gas_limit, 30_000_000,
            "gas_limit must be at EP offset 412, actual offset produces: {}",
            actual_gas_limit
        );
        assert_eq!(
            &buf[ep_abs + SOL_EP_STATE_ROOT_OFFSET..ep_abs + SOL_EP_STATE_ROOT_OFFSET + 32],
            &[0x33; 32],
            "state_root @52"
        );
        assert_eq!(
            &buf[ep_abs + SOL_EP_BLOCK_HASH_OFFSET..ep_abs + SOL_EP_BLOCK_HASH_OFFSET + 32],
            &[0x66; 32],
            "block_hash @472"
        );
        // block_access_list's offset slot is at EP+528 (slot_number, a trailing fixed
        // u64, follows it at EP+532). SSZ offsets are container-relative, so with all
        // variable fields empty the block_access_list data starts at the fixed-prefix
        // length (540) — this pins NativeRollup.sol's EP_FIXED_PREFIX_LEN.
        assert_eq!(
            u32_le(&buf, ep_abs + SOL_EP_BAL_OFFSET_POS),
            SOL_EP_FIXED_PREFIX_LEN,
            "block_access_list offset slot @EP+528 must equal the EP fixed-prefix length (540)",
        );
        // slot_number (EIP-7843) round-trips as a trailing fixed LE u64 at EP+532.
        assert_eq!(
            u64::from_le_bytes(
                buf[ep_abs + SOL_EP_SLOT_NUMBER_OFFSET..ep_abs + SOL_EP_SLOT_NUMBER_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            0x7843,
            "slot_number must be readable at EP+532",
        );
    }
}
