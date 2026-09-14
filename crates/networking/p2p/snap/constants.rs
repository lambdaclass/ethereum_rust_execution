//! Snap Sync Protocol Constants
//!
//! This module centralizes all constants used in the snap sync implementation.
//! Constants are organized by their functional area.

use ethrex_common::H256;
use std::time::Duration;

// =============================================================================
// RESPONSE LIMITS
// =============================================================================

/// Maximum response size in bytes for snap protocol requests (512 KB).
///
/// This limits the amount of data a peer can return in a single response,
/// preventing memory exhaustion and ensuring reasonable response times.
pub const MAX_RESPONSE_BYTES: u64 = 512 * 1024;

/// Maximum number of accounts/items to request in a single snap request.
///
/// This magic number is not part of the protocol specification and is taken
/// from geth. See:
/// <https://github.com/ethereum/go-ethereum/blob/2585776aabbd4ae9b00050403b42afb0cee968ec/eth/downloader/downloader.go#L42-L43>
pub const SNAP_LIMIT: usize = 128;

// =============================================================================
// HASH BOUNDARIES
// =============================================================================

/// Maximum hash value (all bits set to 1).
///
/// Used as the upper bound when requesting the full range of accounts/storage.
pub const HASH_MAX: H256 = H256([0xFF; 32]);

// =============================================================================
// BATCH SIZES
// =============================================================================

/// Size of the in-memory buffer before flushing to disk during snap sync (64 MB).
///
/// During account range and storage range downloads, data is accumulated in memory
/// before being written to temporary files. This constant controls memory usage
/// during the initial snap sync phases.
pub const RANGE_FILE_CHUNK_SIZE: usize = 1024 * 1024 * 64;

/// Number of chunks to split the account range into for parallel downloading.
pub const ACCOUNT_RANGE_CHUNK_COUNT: usize = 800;

/// Number of storage accounts to process per batch during state healing.
pub const STORAGE_BATCH_SIZE: usize = 300;

/// Number of trie nodes to request per batch during state/storage healing.
pub const NODE_BATCH_SIZE: usize = 500;

/// Number of bytecodes to download per batch.
pub const BYTECODE_CHUNK_SIZE: usize = 50_000;

/// Buffer size for code hash collection before writing.
pub const CODE_HASH_WRITE_BUFFER_SIZE: usize = 100_000;

// =============================================================================
// REQUEST CONFIGURATION
// =============================================================================

/// Timeout for peer responses in snap sync operations.
pub const PEER_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of retry attempts when selecting a peer for a request.
pub const PEER_SELECT_RETRY_ATTEMPTS: u32 = 3;

/// Number of retry attempts for individual requests.
pub const REQUEST_RETRY_ATTEMPTS: u32 = 5;

/// Maximum number of concurrent in-flight requests during storage healing.
pub const MAX_IN_FLIGHT_REQUESTS: u32 = 77;

/// Number of `request_storage_ranges` rounds to run before the accounts whose
/// storage is still pending are handed over to storage healing.
///
/// A round is one pivot cycle: the counter only advances after a state heal, and
/// a round ends when the pivot goes stale. Accounts whose storage root reverted
/// to a value we already downloaded can never be served by peers, so retrying
/// them forever would stall snap sync; healing is the only way out for them.
pub const MAX_STORAGE_RANGE_REQUEST_ATTEMPTS: u64 = 5;

/// Number of still-pending accounts above which `MAX_STORAGE_RANGE_REQUEST_ATTEMPTS`
/// is ignored and storage ranges keep being downloaded.
///
/// Healing a storage trie is far more expensive than downloading its range:
/// healing walks the trie node by node against the current pivot, while a range
/// download fetches leaves in bulk. Handing a set this large to healing costs
/// more sync time than running further download rounds, so past this threshold
/// the attempt limit does not apply.
pub const MAX_PENDING_ACCOUNTS_FOR_HEALING_FALLBACK: usize = 300_000;

/// Soft limit on the number of entries in a healing pending-parents queue.
///
/// Shared by storage healing (`StorageHealingQueue`) and state healing
/// (`StateHealingQueue`). Both are `HashMap`s of nodes awaiting their missing
/// children; both are drained via `commit_node` cascades. The limit is sized
/// for the larger of the two (storage) and is therefore conservative for
/// state.
///
/// Storage per-entry cost, branch-dominated worst case:
/// - `NodeResponse.node`: a branch `Node` is a `Box<BranchNode>` with 16
///   `NodeRef` choices (~56 B each in the `Hash` variant) plus `ValueRLP`
///   header, ≈ 950 B on the heap.
/// - `NodeResponse.node_request`: three `Nibbles` (each a `Vec<u8>`, ~24 B
///   header + up to 64 B data) + one `H256`, ≈ 250 B inline+heap.
/// - `HashMap<(Nibbles, Nibbles), _>` key and bucket overhead, ≈ 100 B.
///
/// Total ≈ 1.3 KB per entry → 800_000 entries ≈ 1.0 GB. State entries omit
/// the extra `acc_path` `Nibbles` and use a single-`Nibbles` key, so they're
/// smaller — the same count uses less memory on that side. Leaf-dominated
/// entries are smaller still, so this is an upper-bound estimate. The limit
/// gates the pending-parents map only; the download queue is a separate
/// (smaller) allocation.
///
/// When exceeded, the dispatcher stops issuing new download requests and
/// waits for in-flight responses to drain the queue. The download queue is a
/// max-heap by depth, so in-flight work is the deepest available — which
/// frees pending parents fastest via `commit_node` cascades.
pub const HEALING_QUEUE_SOFT_LIMIT: usize = 800_000;

// =============================================================================
// BLOCK SYNC CONFIGURATION
// =============================================================================

/// Maximum number of block headers to fetch in a single request.
pub const MAX_HEADER_CHUNK: u64 = 500_000;

/// Maximum number of block bodies to request per request.
///
/// This value is taken from geth. Higher values may cause peer disconnections.
/// See:
/// <https://github.com/ethereum/go-ethereum/blob/2585776aabbd4ae9b00050403b42afb0cee968ec/eth/downloader/downloader.go#L42-L43>
pub const MAX_BLOCK_BODIES_TO_REQUEST: usize = 128;

/// Maximum *consecutive* failures before giving up on header downloads.
/// The counter resets on each successful response, so this only triggers
/// when no peer can serve headers at all.
pub const MAX_HEADER_FETCH_ATTEMPTS: u64 = 10;

/// Maximum attempts before giving up on a block-body download during full sync.
/// Mirrors the header-fetch policy; split out so the two can diverge if needed.
pub const MAX_BODY_FETCH_ATTEMPTS: u64 = MAX_HEADER_FETCH_ATTEMPTS;

// =============================================================================
// SNAP SYNC THRESHOLDS
// =============================================================================

/// Minimum number of blocks from the head to full sync during a snap sync.
///
/// After snap syncing state, we full sync at least this many recent blocks
/// to ensure we have complete execution history for recent blocks.
pub const MIN_FULL_BLOCKS: u64 = 10_000;

/// Number of blocks to execute in a single batch during full sync.
pub const EXECUTE_BATCH_SIZE_DEFAULT: usize = 1024;

/// Average time between blocks (used for timestamp-based calculations).
pub const SECONDS_PER_BLOCK: u64 = 12;

/// Assumed percentage of slots that are missing blocks.
///
/// This is used to adjust timestamp-based pivot updates and to find "safe"
/// blocks in the chain that are unlikely to be re-orged.
pub const MISSING_SLOTS_PERCENTAGE: f64 = 0.8;

// =============================================================================
// PROGRESS REPORTING
// =============================================================================

/// Interval between progress reports during healing operations.
pub const SHOW_PROGRESS_INTERVAL_DURATION: Duration = Duration::from_secs(2);
