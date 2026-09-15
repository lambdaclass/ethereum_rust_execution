//! # ethrex Blockchain
//!
//! Core blockchain logic for the ethrex Ethereum client.
//!
//! ## Overview
//!
//! This module implements the blockchain layer, which is responsible for:
//! - Block validation and execution
//! - State management and transitions
//! - Fork choice rule implementation
//! - Transaction mempool management
//! - Payload building for block production
//!
//! ## Key Components
//!
//! - [`Blockchain`]: Main interface for blockchain operations
//! - [`Mempool`]: Transaction pool for pending transactions
//! - [`fork_choice`]: Fork choice rule implementation
//! - [`payload`]: Block payload building for consensus
//!
//! ## Block Execution Flow
//!
//! ```text
//! 1. Receive block from consensus/P2P
//! 2. Validate block header (parent, timestamp, gas limit, etc.)
//! 3. Execute transactions in EVM
//! 4. Verify state root matches header
//! 5. Store block and update canonical chain
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use ethrex_blockchain::Blockchain;
//!
//! let blockchain = Blockchain::new(store, BlockchainOptions::default());
//!
//! // Add a block
//! blockchain.add_block(&block)?;
//!
//! // Add transaction to mempool
//! blockchain.add_transaction_to_mempool(tx).await?;
//! ```

pub mod constants;
pub mod error;
pub mod fork_choice;
pub mod mempool;
pub mod payload;
pub mod prewarm;
pub mod sampling;
pub mod simulate;
pub mod stateless;
pub mod tracing;
pub mod vm;

use ::tracing::{error, info, instrument, warn};
// Every `debug!` call site lives in the rayon warmer path, so the import is
// unused in any configuration that compiles that path out.
#[cfg(feature = "rayon")]
use ::tracing::debug;
use constants::{AMSTERDAM_MAX_INITCODE_SIZE, MAX_INITCODE_SIZE, POST_OSAKA_GAS_LIMIT_CAP};
use error::MempoolError;
use error::{ChainError, InvalidBlockError};
use ethrex_common::constants::{EMPTY_KECCAK_HASH, EMPTY_TRIE_HASH, MIN_BASE_FEE_PER_BLOB_GAS};

use crossbeam::channel::{self as cb, TryRecvError, select};
// Re-export stateless validation functions for backwards compatibility
use crate::vm::{OverlaidVmDatabase, StateOverride, precompile_moves};
#[cfg(feature = "c-kzg")]
use ethrex_common::types::EIP4844Transaction;
#[cfg(feature = "c-kzg")]
use ethrex_common::types::MAX_BLOB_TX_SIZE;
use ethrex_common::types::MAX_TX_SIZE;
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::block_execution_witness::ExecutionWitness;
use ethrex_common::types::fee_config::FeeConfig;
use ethrex_common::types::{
    AccountInfo, AccountState, AccountUpdate, BalSynthesisItem, Block, BlockHash, BlockHeader,
    BlockNumber, Code, Transaction, WrappedEIP4844Transaction, synthesize_bal_updates,
    validate_block_body,
};
use ethrex_common::types::{EIP7702_DELEGATED_CODE_LEN, is_eip7702_delegation};
use ethrex_common::types::{ELASTICITY_MULTIPLIER, P2PTransaction};
use ethrex_common::types::{Fork, MempoolTransaction};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, H256, U256};
pub use ethrex_common::{
    get_total_blob_gas, validate_block_access_list_hash, validate_block_pre_execution,
    validate_gas_used, validate_receipts_root_and_logs_bloom, validate_requests_hash,
};
use ethrex_crypto::NativeCrypto;
use ethrex_metrics::metrics;
use ethrex_rlp::constants::RLP_NULL;
use ethrex_rlp::decode::RLPDecode;
use ethrex_rlp::encode::RLPEncode;
use ethrex_storage::{
    AccountUpdatesList, DB_COMMIT_THRESHOLD, Store, UpdateBatch, error::StoreError, hash_address,
    hash_key,
};
use ethrex_trie::node::{BranchNode, ExtensionNode, LeafNode};
use ethrex_trie::{Nibbles, Node, NodeRef, Trie, TrieError, TrieLogger, TrieNode};
#[cfg(feature = "rayon")]
use ethrex_vm::backends::BLOATED_BATCH_THRESHOLD;
use ethrex_vm::backends::CachingDatabase;
use ethrex_vm::backends::VMType;
#[cfg(feature = "rayon")]
use ethrex_vm::backends::levm::LEVM;
use ethrex_vm::backends::levm::db::DatabaseLogger;
use ethrex_vm::{BlockExecutionResult, DynVmDatabase, Evm, EvmError, VmDatabase};
use mempool::{
    BalanceCheck, FRAME_CANONICAL_PAYMASTER_CODE_HASH, FramePaymasterReservation, Mempool,
    SenderAdmission, is_canonical_paymaster,
};
use payload::PayloadOrTask;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;
use std::sync::OnceLock;
use std::sync::mpsc::Sender;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{Receiver, channel},
};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

use vm::StoreVmDatabase;

#[cfg(feature = "metrics")]
use ethrex_metrics::bal::METRICS_BAL;
#[cfg(feature = "metrics")]
use ethrex_metrics::blocks::METRICS_BLOCKS;

#[cfg(feature = "c-kzg")]
use ethrex_common::types::BlobsBundle;

const MAX_PAYLOADS: usize = 10;
const MAX_MEMPOOL_SIZE_DEFAULT: usize = 10_000;
// Below this many touched storage slots the BFS prefetch's own overhead (one
// `multi_get` per trie level) isn't worth it; the serial insert loop's
// per-slot lazy resolution is cheap enough on its own. Shared by the Stage B
// worker, `serial_storage_root`, and `compute_sharded_storage_root`'s
// serial fallbacks.
const STORAGE_PREFETCH_THRESHOLD: usize = 64;
// Per-shard gate for the Stage C state-trie update. Each of the 16 shards holds
// ~1/16 of the block's touched accounts, so the threshold is scaled down like
// the storage shard path.
const STATE_SHARD_PREFETCH_THRESHOLD: usize = 4;
// Streaming merkleizer (`handle_subtrie`): a single storage trie's touched slots
// are sharded across the 16 workers by key nibble, so each worker holds only
// ~1/16 of them. The prefetch gate is therefore scaled down from
// `STORAGE_PREFETCH_THRESHOLD` by 16 (same reasoning as
// `STATE_SHARD_PREFETCH_THRESHOLD`): a trie with ~64 total touched slots then
// clears the gate on each of its shards. Used only on the BAL-less / pre-Amsterdam
// streaming path.
const STREAM_STORAGE_PREFETCH_THRESHOLD: usize = 4;
// Cap on the per-worker, per-trie slot buffer before an opportunistic mid-routing
// flush (one sorted `prefetch_sorted` + the inserts). Bounds transient memory for
// very heavy single-account blocks; smaller buffers just flush once at RoutingDone.
const STREAM_STORAGE_FLUSH_BATCH: usize = 1024;
/// Default mempool occupancy percentage (0-100) at which gapped-nonce
/// transaction admission is denied. Set to 100 to disable the check.
pub const DEFAULT_GAP_ADMIT_OCCUPANCY_THRESHOLD: u8 = 90;

/// Merkle write set for the trie-node prefetch: written storage slots and changed accounts.
#[cfg(feature = "rayon")]
type TriePrefetchInput = (Vec<(Address, H256)>, Vec<Address>);

/// Background thread for dropping large tree structures off the critical path.
/// Accepts any `Send` value and drops it on a dedicated thread, avoiding
/// recursive deallocation costs (~500us for state trie roots) on hot paths.
static DROP_SENDER: LazyLock<Sender<Box<dyn Send>>> = LazyLock::new(|| {
    let (tx, rx) = channel::<Box<dyn Send>>();
    std::thread::Builder::new()
        .name("drop_thread".to_string())
        .spawn(move || for _ in rx {})
        .expect("failed to spawn drop thread");
    tx
});

// Result type for execute_block_pipeline
type BlockExecutionPipelineResult = (
    BlockExecutionResult,
    AccountUpdatesList,
    Option<Vec<AccountUpdate>>,
    Option<BlockAccessList>, // produced BAL (Some on Amsterdam+ blocks)
    usize,                   // max queue length
    [Instant; 7],            // timing instants
    Duration,                // warmer duration
);

type AddBlockPipelineInnerResult = (
    Option<BlockAccessList>,
    Option<ExecutionWitness>,
    Result<(), ChainError>,
);

//TODO: Implement a struct Chain or BlockChain to encapsulate
//functionality and canonical chain state and config

/// Specifies whether the blockchain operates as L1 (mainnet/testnet) or L2 (rollup).
#[derive(Debug, Clone, Default)]
pub enum BlockchainType {
    /// Standard Ethereum L1 blockchain.
    #[default]
    L1,
    /// Layer 2 rollup with additional fee configuration.
    L2(L2Config),
}

/// Configuration for L2 rollup operation.
#[derive(Debug, Clone, Default)]
pub struct L2Config {
    /// Fee configuration for L2 transactions.
    ///
    /// Uses `RwLock` because the Watcher updates L1 fee config periodically.
    pub fee_config: Arc<RwLock<FeeConfig>>,
}

/// Core blockchain implementation for block validation and execution.
///
/// The `Blockchain` struct is the main entry point for all blockchain operations:
/// - Adding and validating blocks
/// - Managing the transaction mempool
/// - Building payloads for block production
/// - Handling fork choice updates
///
/// # Thread Safety
///
/// `Blockchain` uses interior mutability for thread-safe access to shared state.
/// The mempool and payload storage are protected by appropriate synchronization primitives.
///
/// # Example
///
/// ```ignore
/// let blockchain = Blockchain::new(store, BlockchainOptions::default());
///
/// // Validate and add a block
/// blockchain.add_block(&block)?;
///
/// // Check sync status
/// if blockchain.is_synced() {
///     // Process transactions from mempool
/// }
/// ```
#[derive(Debug)]
pub struct Blockchain {
    /// Underlying storage for blocks and state.
    storage: Store,
    /// Transaction mempool for pending transactions.
    pub mempool: Mempool,
    /// Whether the node has completed initial sync.
    ///
    /// Set to true after initial sync completes, never reset to false.
    /// Does not reflect whether an ongoing sync is in progress.
    is_synced: AtomicBool,
    /// Set while a deep-reorg apply pass is in flight. Concurrent
    /// FCUs from the engine API short-circuit to SYNCING while this is set,
    /// and journal pruning in `forkchoice_update_inner` defers until the apply
    /// pass clears it. Managed via [`enter_reorg`](Self::enter_reorg) which
    /// returns a [`ReorgGuard`] RAII that clears the flag on drop.
    reorg_in_progress: AtomicBool,
    /// Configuration options for blockchain behavior.
    pub options: BlockchainOptions,
    /// Cache of recently built payloads.
    ///
    /// Maps payload IDs to either completed payloads or in-progress build tasks.
    /// Kept around in case consensus requests the same payload twice.
    pub payloads: Arc<TokioMutex<Vec<(u64, PayloadOrTask)>>>,
    /// Persistent thread pool for merkleization workers.
    /// 17 threads: 16 shard workers + 1 watcher/coordination.
    ///
    /// Built on first merkleization, so a `Blockchain` that never merkleizes pays
    /// nothing; node startup seeds it eagerly via
    /// [`Self::preinitialize_merkle_pool`], and harnesses where every instance
    /// merkleizes seed a shared one via [`Self::for_test_harness_with_pool`].
    /// Use [`Self::merkle_pool`] to read it.
    merkle_pool: OnceLock<Arc<rayon::ThreadPool>>,
    /// Cache handoff slot from the mempool prewarmer to
    /// `execute_block_pipeline`; see `PrewarmedCache` and `crate::prewarm`.
    prewarmed: PrewarmedCache,
}

/// Newtype around the prewarmer's cache-handoff slot so `Blockchain` can keep
/// deriving `Debug` (`dyn LevmDatabase` has no `Debug` impl).
///
/// Alongside the parent hash, the slot carries the fork the prewarmer warmed
/// under: the precompile cache maps `(address, calldata) -> (output, gas)`
/// with no fork in the key, and precompile gas/outputs change at forks
/// (e.g. EIP-7883). A missed slot across a fork activation would otherwise
/// hand post-fork execution pre-fork entries and reject a valid block.
#[derive(Default)]
pub(crate) struct PrewarmedCache(pub(crate) std::sync::Mutex<Option<PrewarmedEntry>>);

/// Contents of the handoff slot.
pub(crate) struct PrewarmedEntry {
    /// Parent block the cache was built on.
    pub(crate) parent_hash: H256,
    /// Fork the cache was warmed under.
    pub(crate) fork: Fork,
    pub(crate) cache: Arc<dyn ethrex_vm::backends::LevmDatabase>,
}

impl std::fmt::Debug for PrewarmedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self.0.lock() {
            Ok(slot) => slot.as_ref().map(|entry| (entry.parent_hash, entry.fork)),
            Err(_) => None,
        };
        f.debug_tuple("PrewarmedCache").field(&state).finish()
    }
}

/// RAII guard that clears [`Blockchain::reorg_in_progress`] on drop. Returned by
/// [`Blockchain::enter_reorg`]. Ensures the flag is reset on every exit path of
/// the apply pass, including panics that unwind through the guard.
pub struct ReorgGuard<'a> {
    blockchain: &'a Blockchain,
}

impl Drop for ReorgGuard<'_> {
    fn drop(&mut self) {
        self.blockchain.storage.set_journal_pruning_paused(false);
        self.blockchain
            .reorg_in_progress
            .store(false, Ordering::Release);
    }
}

/// Default min-tip floor (wei). Matches geth's mempool `PriceLimit = 1 wei`.
/// Effectively just rejects zero-tip transactions at admission.
pub const DEFAULT_MIN_TIP_WEI: u64 = 1;

/// Configuration options for the blockchain.
#[derive(Debug, Clone)]
pub struct BlockchainOptions {
    /// Maximum number of transactions in the mempool.
    pub max_mempool_size: usize,
    /// Whether to emit performance logging.
    pub perf_logs_enabled: bool,
    /// Blockchain type (L1 or L2).
    pub r#type: BlockchainType,
    /// EIP-7872: User-configured maximum blobs per block for local building.
    /// If None, uses the protocol maximum for the current fork.
    pub max_blobs_per_block: Option<u32>,
    /// If true, computes execution witnesses upon receiving newPayload messages and stores them in local storage
    pub precompute_witnesses: bool,
    /// If true, transactions submitted via this node's RPC (e.g.
    /// `eth_sendRawTransaction`) are kept private: they enter the mempool and
    /// can be included in blocks built locally, but are not propagated to
    /// peers via `Transactions` / `NewPooledTransactionHashes`. Equivalent to
    /// reth's `--txpool.no-local-transactions-propagation`.
    /// P2P-received transactions are unaffected.
    pub private_mempool: bool,
    /// If true (default), per-block execution caches precompile results between the
    /// warmer thread and the executor. Set to false (via `--no-precompile-cache`) to
    /// disable the cache for benchmarking purposes.
    pub precompile_cache_enabled: bool,
    /// Minimum priority-fee *cap* (in wei) required for a transaction to be
    /// admitted into the mempool. Compared against the raw tip cap
    /// (`max_priority_fee_per_gas` for typed txs, `gas_price` for legacy), NOT
    /// the base-fee-dependent effective tip — matching geth's `PriceLimit`
    /// check on `tx.GasTipCap()`. Set to 0 to disable the floor.
    pub min_tip_wei: u64,
    /// Minimum fee-field bump (in percent) required to replace a non-blob
    /// transaction at the same `(sender, nonce)`. Matches the 10%
    /// default of every peer EL client.
    pub price_bump_percent: u64,
    /// Minimum fee-field bump (in percent) required to replace an EIP-4844
    /// blob transaction at the same `(sender, nonce)`. Matches the 100%
    /// default of every peer EL client. Blob replacements are deliberately
    /// expensive because blob sidecars are large to re-propagate.
    pub blob_price_bump_percent: u64,
    /// Maximum number of *queued* (future/nonce-gapped) transactions a single
    /// sender may hold in the mempool. Executable (contiguous-nonce) txs are NOT
    /// capped — mirroring geth's `AccountQueue` (a hard cap on the future/queued
    /// subpool only), so legitimate high-throughput single senders and the
    /// devp2p `LargeTxRequest` conformance case are unaffected. Only nonce-gapped
    /// parking spam is bounded.
    pub max_queued_txs_per_account: usize,
    /// If true (default), Amsterdam+ validation runs transactions in parallel
    /// using the header BAL to seed per-tx databases. Set to false (via
    /// `--no-bal-parallel-exec`) to fall back to sequential execution.
    pub bal_parallel_exec_enabled: bool,
    /// If true (default), Amsterdam+ validation spawns a warmer thread that
    /// prefetches accounts, storage slots, and codes listed in the header BAL.
    /// Set to false (via `--no-bal-prefetch`) to skip prefetching on the BAL path.
    pub bal_prefetch_enabled: bool,
    /// If true (default), Amsterdam+ validation merkleizes optimistically from
    /// `synthesize_bal_updates` in parallel with execution. Set to false (via
    /// `--no-bal-parallel-trie`) to fall back to streaming `AccountUpdate`s from
    /// the executor and merkleizing post-execution.
    pub bal_parallel_trie_enabled: bool,
    /// EIP-8070: when true, activate the sampler/provider state machine.
    /// When false (default), the node always acts as provider (p=1.0).
    pub blob_sampling_enabled: bool,
    /// EIP-8070: when true, always act as provider (p=1.0) regardless of role
    /// randomization, as block builders SHOULD (EIP-8070, "Execution clients ::
    /// Local block builders"). Enabled via `--blob-eager-provider`; a node that
    /// builds payloads latches it at runtime regardless. Only meaningful when
    /// `blob_sampling_enabled` is also true.
    pub blob_eager_provider: bool,
    /// Optional operator override for the maximum reorg depth. `None` ; cap is purely
    /// physical (layer-cache retention plus journal reach; bounded indirectly by finality
    /// because finality advances prune the journal). `Some(d)` ; reject reorgs of
    /// depth `> d` with `-38006 TooDeepReorg`. WARNING: `Some(0)` rejects EVERY reorg,
    /// including routine 1-2 block reorgs on a healthy network — it is NOT the old
    /// 128-block cap. Use a small positive value to approximate the pre-stack behavior.
    pub max_reorg_depth: Option<u64>,
    /// Mempool occupancy percentage (0-100) at or above which incoming
    /// transactions with a nonce gap relative to the sender's on-chain nonce
    /// are rejected. Setting to 100 disables the check.
    pub gap_admit_occupancy_threshold: u8,
    /// If true (default), a `Blockchain` driving block import may spawn a mempool
    /// prewarmer: an OS thread plus a rayon pool at half the available cores, both
    /// holding a strong reference to this `Blockchain`.
    ///
    /// Test harnesses set this to false. The prewarmer thread does exit on its own
    /// once its `PrewarmHandle` drops and closes the channel -- nothing is leaked
    /// -- but it is never joined, so a large test binary creates such threads
    /// faster than the OS reaps them. No test exercises prewarming, so not
    /// spawning it is both cheaper and simpler than plumbing a `JoinHandle`
    /// through `PrewarmHandle` to join it. See `for_test_harness`.
    pub mempool_prewarm_enabled: bool,
}

impl Default for BlockchainOptions {
    fn default() -> Self {
        Self {
            max_mempool_size: MAX_MEMPOOL_SIZE_DEFAULT,
            perf_logs_enabled: false,
            r#type: BlockchainType::default(),
            max_blobs_per_block: None,
            precompute_witnesses: false,
            private_mempool: false,
            precompile_cache_enabled: true,
            min_tip_wei: DEFAULT_MIN_TIP_WEI,
            price_bump_percent: DEFAULT_PRICE_BUMP_PERCENT,
            blob_price_bump_percent: DEFAULT_BLOB_PRICE_BUMP_PERCENT,
            max_queued_txs_per_account: DEFAULT_MAX_QUEUED_TXS_PER_ACCOUNT,
            bal_parallel_exec_enabled: true,
            bal_prefetch_enabled: true,
            bal_parallel_trie_enabled: true,
            blob_sampling_enabled: false,
            blob_eager_provider: false,
            max_reorg_depth: None,
            gap_admit_occupancy_threshold: DEFAULT_GAP_ADMIT_OCCUPANCY_THRESHOLD,
            mempool_prewarm_enabled: true,
        }
    }
}

/// Default 10% bump required for non-blob RBF replacements (matches geth
/// `PriceBump`, reth `default_price_bump`, nethermind `PriceBump`,
/// erigon `PriceBump`, besu `DEFAULT_PRICE_BUMP`).
pub const DEFAULT_PRICE_BUMP_PERCENT: u64 = 10;
/// Default 100% bump required for blob RBF replacements (matches geth
/// `blobpool.PriceBump`, reth `replace_blob_tx_price_bump`, nethermind
/// blob comparison, erigon `BlobPriceBump`, besu `DEFAULT_BLOB_PRICE_BUMP`).
pub const DEFAULT_BLOB_PRICE_BUMP_PERCENT: u64 = 100;

/// Default per-account *queued* (future-nonce) tx cap. Matches geth's
/// `AccountQueue` default (64) — a hard cap on the future/queued subpool only;
/// executable txs are uncapped.
pub const DEFAULT_MAX_QUEUED_TXS_PER_ACCOUNT: usize = 64;

#[derive(Debug, Clone)]
pub struct BatchBlockProcessingFailure {
    pub last_valid_hash: H256,
    pub failed_block_hash: H256,
}

fn log_batch_progress(batch_size: u32, current_block: u32) {
    let progress_needed = batch_size > 10;
    const PERCENT_MARKS: [u32; 4] = [20, 40, 60, 80];
    if progress_needed {
        PERCENT_MARKS.iter().for_each(|mark| {
            if (batch_size * mark) / 100 == current_block {
                info!("[SYNCING] {mark}% of batch processed");
            }
        });
    }
}

enum WorkerRequest {
    // From main thread (routed by account bucket)
    ProcessAccount {
        prefix: H256,
        info: Option<AccountInfo>,
        storage: FxHashMap<H256, U256>,
        removed: bool,
        removed_storage: bool,
    },
    // From main thread (broadcast to all workers)
    FinishRouting,
    MerklizeAccounts {
        accounts: Vec<H256>,
    },
    CollectState {
        tx: Sender<CollectedStateMsg>,
    },
    // Cross-worker storage messages (routed by storage key bucket)
    MerklizeStorage {
        prefix: H256,
        key: H256,
        value: U256,
        storage_root: H256,
    },
    DeleteStorage(H256),
    // Cross-worker: signals this worker finished routing all MerklizeStorage
    RoutingDone {
        from: u8,
    },
    // Cross-worker storage results (routed by account bucket)
    StorageShard {
        prefix: H256,
        index: u8,
        subroot: Box<BranchNode>,
        nodes: Vec<TrieNode>,
    },
}

struct CollectedStateMsg {
    index: u8,
    subroot: Box<BranchNode>,
    state_nodes: Vec<TrieNode>,
    storage_nodes: Vec<(H256, Vec<TrieNode>)>,
}

#[derive(Default)]
struct PreMerkelizedAccountState {
    storage_root: Option<Box<BranchNode>>,
    nodes: Vec<TrieNode>,
}

/// Work item for BAL state trie shard workers.
struct BalStateWorkItem {
    hashed_address: H256,
    nonce: Option<u64>,
    balance: Option<U256>,
    code_hash: Option<H256>,
    /// Pre-computed storage root from Stage B, or None to keep existing.
    storage_root: Option<H256>,
}

impl Blockchain {
    /// Build a fresh 17-thread merkleization pool.
    ///
    /// The size is load-bearing, not a tuning knob: 16 shard workers plus one
    /// watcher, and all 16 must be resident at once because they cross-communicate
    /// over channels. A smaller pool deadlocks rather than running slower.
    pub fn build_merkle_pool() -> Arc<rayon::ThreadPool> {
        Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(17)
                .thread_name(|i| format!("merkle-worker-{i}"))
                .build()
                .expect("Failed to create merkle thread pool"),
        )
    }

    /// This `Blockchain`'s merkleization pool, building it on first use.
    fn merkle_pool(&self) -> &rayon::ThreadPool {
        self.merkle_pool.get_or_init(Self::build_merkle_pool)
    }

    /// Builds the merkleization pool now, unless it is already seeded.
    ///
    /// Node startup calls this so a pool that cannot be created fails the process at
    /// boot, rather than panicking inside the merkleizer during the first block.
    pub fn preinitialize_merkle_pool(&self) {
        let _ = self.merkle_pool();
    }

    /// Whether the merkleization pool has been built yet.
    ///
    /// Exposed so tests can assert that a `Blockchain` which never merkleizes does
    /// not pay for the pool.
    pub fn merkle_pool_initialized(&self) -> bool {
        self.merkle_pool.get().is_some()
    }

    pub fn new(store: Store, blockchain_opts: BlockchainOptions) -> Self {
        let mempool = if blockchain_opts.blob_eager_provider {
            Mempool::new_with_eager_provider(blockchain_opts.max_mempool_size)
        } else if blockchain_opts.blob_sampling_enabled {
            Mempool::new_with_sampling(blockchain_opts.max_mempool_size)
        } else {
            Mempool::new(blockchain_opts.max_mempool_size)
        };
        Self {
            storage: store,
            mempool,
            is_synced: AtomicBool::new(false),
            reorg_in_progress: AtomicBool::new(false),
            payloads: Arc::new(TokioMutex::new(Vec::new())),
            options: blockchain_opts,
            merkle_pool: OnceLock::new(),
            prewarmed: PrewarmedCache::default(),
        }
    }

    /// `Blockchain` for a test harness that builds many short-lived instances.
    ///
    /// Keeps `BlockchainOptions::default()` but disables the mempool prewarmer,
    /// whose threads would otherwise outlive the test that created them. The
    /// merkleization pool is lazy (see the `merkle_pool` field), so an instance
    /// that never merkleizes costs no threads at all.
    ///
    /// Use [`Self::for_test_harness_with_pool`] instead in a harness where every
    /// instance *does* merkleize, so laziness saves nothing.
    pub fn for_test_harness(store: Store) -> Self {
        Self {
            storage: store,
            mempool: Mempool::new(MAX_MEMPOOL_SIZE_DEFAULT),
            is_synced: AtomicBool::new(false),
            reorg_in_progress: AtomicBool::new(false),
            payloads: Arc::new(TokioMutex::new(Vec::new())),
            options: BlockchainOptions {
                // No test exercises prewarming, and its threads would outlive the
                // test that created them.
                mempool_prewarm_enabled: false,
                ..Default::default()
            },
            merkle_pool: OnceLock::new(),
            prewarmed: PrewarmedCache::default(),
        }
    }

    /// Like [`Self::for_test_harness`], but seeds the merkleization pool with an
    /// externally-owned one rather than leaving it to be built on first use.
    ///
    /// For the ef_tests runners, which build one `Blockchain` per fixture and
    /// merkleize with every one, so a per-instance pool would spawn a pool per
    /// fixture. See their `thread_local!` pools for the accounting.
    ///
    /// SAFETY: the caller must ensure each pool has only one concurrent
    /// `in_place_scope` user at a time. The internal merkle protocol requires all
    /// 16 worker jobs to run concurrently (they cross-communicate via channels), so
    /// sharing a pool between simultaneous callers deadlocks rather than running
    /// slower. Keying the pool by `thread_local!` in the runner, and driving each
    /// pool's blocks from its own thread, is what gives that exclusivity.
    pub fn for_test_harness_with_pool(store: Store, pool: Arc<rayon::ThreadPool>) -> Self {
        let blockchain = Self::for_test_harness(store);
        if blockchain.merkle_pool.set(pool).is_err() {
            unreachable!("a freshly built Blockchain has an empty merkle pool cell");
        }
        blockchain
    }

    /// Test-permissive `Blockchain` constructor. Mirrors `BlockchainOptions::default`
    /// but disables admission-policy gates (e.g. the min-tip floor) so that
    /// unrelated tests don't need to set every mempool option explicitly.
    ///
    /// **Do not use in production.** Despite the name, this is not a "sensible
    /// default" constructor: it deliberately weakens mempool admission. Node
    /// startup builds its `BlockchainOptions` from the CLI instead (see
    /// `cmd/ethrex/initializers.rs`). Every current caller is a test harness.
    pub fn default_with_store(store: Store) -> Self {
        let options = BlockchainOptions {
            min_tip_wei: 0,
            // Every caller is a test harness, so match `for_test_harness`: the
            // prewarmer's threads would outlive the test that created them.
            mempool_prewarm_enabled: false,
            ..BlockchainOptions::default()
        };
        Self {
            storage: store,
            mempool: Mempool::new(MAX_MEMPOOL_SIZE_DEFAULT),
            is_synced: AtomicBool::new(false),
            reorg_in_progress: AtomicBool::new(false),
            payloads: Arc::new(TokioMutex::new(Vec::new())),
            options,
            merkle_pool: OnceLock::new(),
            prewarmed: PrewarmedCache::default(),
        }
    }

    /// L1 blocks must not contain L2-only transaction types (`FeeToken` 0x7d,
    /// `Privileged` 0x7e). Both are L2-only types unknown to other L1 clients, so
    /// accepting one on L1 diverges consensus. `Privileged` additionally takes its
    /// sender from an unsigned, caller-chosen `from` (no signature recovery), so it
    /// would also let a block forge a sender. On L2 these types are valid, so this
    /// check only applies to L1.
    fn validate_l1_transaction_types(&self, block: &Block) -> Result<(), ChainError> {
        if !matches!(self.options.r#type, BlockchainType::L1) {
            return Ok(());
        }
        for tx in &block.body.transactions {
            if tx.tx_type().is_l2_only() {
                return Err(ChainError::InvalidBlock(
                    InvalidBlockError::UnsupportedTransactionType(tx.tx_type() as u8),
                ));
            }
        }
        Ok(())
    }

    /// Returns a reference to the underlying [`Store`]. Used by the deep-reorg
    /// orchestrator to drive the storage-side primitives.
    pub fn store(&self) -> &Store {
        &self.storage
    }

    /// Returns `true` while a deep-reorg apply pass is in flight. Set by
    /// [`enter_reorg`](Self::enter_reorg); the engine API's FCU handler should
    /// short-circuit to SYNCING when this is `true`.
    pub fn is_reorg_in_progress(&self) -> bool {
        self.reorg_in_progress.load(Ordering::Acquire)
    }

    /// Attempts to mark the start of a deep-reorg apply pass. Returns a RAII
    /// guard that clears the flag on drop (success, error, or panic) if no other
    /// pass is in flight, or `None` if one already is. This is a test-and-set:
    /// the flag transition `false -> true` is atomic, so two concurrent FCUs
    /// that both reach the deep path can never both acquire the guard. The loser
    /// short-circuits to SYNCING and the CL retries. At most one apply pass runs
    /// at a time.
    pub fn enter_reorg(&self) -> Option<ReorgGuard<'_>> {
        self.reorg_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then(|| {
                // Also pause STATE_HISTORY pruning for the whole pass:
                // `Overlay::from_journal` reads entries with no snapshot
                // isolation, and syncer-driven forkchoice updates bypass this
                // mutex, so a concurrent finality advance could otherwise prune
                // the journal out from under overlay construction.
                self.storage.set_journal_pruning_paused(true);
                ReorgGuard { blockchain: self }
            })
    }

    /// Executes a block withing a new vm instance and state
    fn execute_block(
        &self,
        block: &Block,
    ) -> Result<(BlockExecutionResult, Vec<AccountUpdate>), ChainError> {
        // Validate if it can be the new head and find the parent
        let Ok(parent_header) = find_parent_header(&block.header, &self.storage) else {
            // If the parent is not present, we store it as pending.
            self.storage.add_pending_block(block.clone())?;
            return Err(ChainError::ParentNotFound);
        };

        let chain_config = self.storage.get_chain_config();

        // Validate the block pre-execution
        validate_block_pre_execution(block, &parent_header, &chain_config, ELASTICITY_MULTIPLIER)?;
        self.validate_l1_transaction_types(block)?;

        let vm_db = StoreVmDatabase::new(self.storage.clone(), parent_header)?;
        let mut vm = self.new_evm(vm_db)?;

        let (execution_result, bal) = vm.execute_block(block)?;
        let account_updates = vm.get_state_transitions()?;

        // Validate execution went alright
        if let Err(e) = validate_gas_used(execution_result.block_gas_used, &block.header) {
            ethrex_vm::log_gas_used_mismatch(
                &execution_result.tx_gas_breakdowns,
                block.header.number,
                execution_result.block_gas_used,
                block.header.gas_used,
            );
            return Err(e.into());
        }
        validate_receipts_root_and_logs_bloom(
            &block.header,
            &execution_result.receipts,
            &NativeCrypto,
        )?;
        validate_requests_hash(&block.header, &chain_config, &execution_result.requests)?;
        if let Some(bal) = &bal {
            validate_block_access_list_hash(
                &block.header,
                &chain_config,
                bal,
                block.body.transactions.len(),
                &NativeCrypto,
            )?;
        }

        Ok((execution_result, account_updates))
    }

    /// Generates Block Access List by re-executing a block.
    /// Returns None for pre-Amsterdam blocks.
    /// This is used by engine_getPayloadBodiesByHashV2 and engine_getPayloadBodiesByRangeV2.
    pub fn generate_bal_for_block(
        &self,
        block: &Block,
    ) -> Result<Option<BlockAccessList>, ChainError> {
        let chain_config = self.storage.get_chain_config();

        // Pre-Amsterdam blocks don't have BAL
        if !chain_config.is_amsterdam_activated(block.header.timestamp) {
            return Ok(None);
        }

        // Find parent header
        let parent_header = find_parent_header(&block.header, &self.storage)?;

        // Create VM and execute block with BAL recording
        let vm_db = StoreVmDatabase::new(self.storage.clone(), parent_header)?;
        let mut vm = self.new_evm(vm_db)?;

        let (_execution_result, bal) = vm.execute_block(block)?;

        Ok(bal)
    }

    /// Executes a block withing a new vm instance and state
    #[instrument(
        level = "trace",
        name = "Execute Block",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn execute_block_pipeline(
        &self,
        block: &Block,
        parent_header: &BlockHeader,
        vm: &mut Evm,
        bal: Option<Arc<BlockAccessList>>,
        collect_witness: bool,
    ) -> Result<BlockExecutionPipelineResult, ChainError> {
        let start_instant = Instant::now();

        let chain_config = self.storage.get_chain_config();

        // Validate the block pre-execution
        validate_block_pre_execution(block, parent_header, &chain_config, ELASTICITY_MULTIPLIER)?;
        self.validate_l1_transaction_types(block)?;
        validate_block_body(&block.header, &block.body, &NativeCrypto)
            .map_err(|e| ChainError::InvalidBlock(InvalidBlockError::InvalidBody(e)))?;
        let block_validated_instant = Instant::now();

        let exec_merkle_start = Instant::now();
        let queue_length = AtomicUsize::new(0);
        let queue_length_ref = &queue_length;
        let mut max_queue_length = 0;

        // Wrap the store with CachingDatabase so both warming and execution
        // can benefit from shared caching of state lookups. If the mempool
        // prewarmer published a cache built on this block's parent state,
        // seed execution with it when the parent hash and fork match (why
        // both must match: see `PrewarmedCache` and the `CachingDatabase`
        // invariant). Witness collection must start cold — pre-populated
        // entries would hide reads from the witness logger beneath the cache.
        let original_store = vm.db.store.clone();
        let prewarmed = (!collect_witness)
            .then(|| {
                self.prewarmed
                    .0
                    .lock()
                    .ok()
                    .and_then(|mut slot| slot.take())
            })
            .flatten()
            .and_then(|entry| {
                let block_fork = self.storage.get_chain_config().fork(block.header.timestamp);
                (entry.parent_hash == block.header.parent_hash && entry.fork == block_fork)
                    .then_some(entry.cache)
            });
        let caching_store: Arc<dyn ethrex_vm::backends::LevmDatabase> = match prewarmed {
            Some(cache) => cache,
            None => Arc::new(CachingDatabase::new(
                original_store,
                self.options.precompile_cache_enabled,
            )),
        };

        // Replace the VM's store with the caching version
        vm.db.store = caching_store.clone();

        let cancelled = AtomicBool::new(false);
        // Witness collection also forces sequential execution: parallel lanes
        // re-read in-block-created state (e.g. a code deployed by an earlier
        // tx) from the logged store, while sequential execution serves it from
        // VM caches — recording accesses the canonical execution never makes.
        let bal_parallel_exec_enabled = self.options.bal_parallel_exec_enabled && !collect_witness;

        // Synthesize BAL updates pre-scope so the merkleizer thread can start
        // trie work immediately, in parallel with execution.
        // `--no-bal-parallel-trie` opts out: leave `optimistic_updates = None` so
        // the merkleizer takes the streaming branch (fed by the EVM-side
        // `bal_to_account_updates` send over the channel below).
        // Witness collection forces the streaming branch too: the sequential
        // executor (see `bal_parallel_exec_enabled` below) streams per-tx
        // updates over the channel, which only the streaming merkleizer
        // consumes — the synthesized path would leave the receiver dropped.
        let optimistic_updates: Option<FxHashMap<Address, BalSynthesisItem>> =
            if self.options.bal_parallel_trie_enabled && !collect_witness {
                bal.as_deref().map(synthesize_bal_updates)
            } else {
                None
            };

        // Synchronously warm all BAL storage slots before the executor thread starts.
        //
        // The warmer and executor share one CachingDatabase; `prefetch_storage`
        // populates the cache only after its whole parallel fetch completes, so when
        // the warmer ran storage concurrently the executor raced it to the trie for
        // SSTORE original values and lost (~22% of CPU on cold-cache import-bench).
        // Doing the storage prefetch up front (parallel, on all cores) lets execution
        // run fully warm and removes the warmer's CPU/lock contention with it.
        //
        // Measured on bal-devnet-7-mainnet-mix-460 (import-bench --with-bal, vs main):
        //   - concurrent storage warming (any ordering/chunking): ~ -7% to -13%
        //   - this synchronous full-storage prefetch:             ~ -24%
        // DO NOT move storage back into the concurrent warmer; the race is the whole
        // problem. DO NOT add account prefetch here too: that regressed (~ +150 ms),
        // because account reads already overlap exec well and a synchronous pass both
        // adds serial latency and double-fetches against the warmer's Phase 1. Slots
        // are warmed in natural account order; an execution-order sort gave no benefit
        // once every slot is warm before exec.
        //
        // Live-node tradeoff: this prefetch is on the critical path before exec, no
        // longer overlapped with it. With a warm cache the reads hit and it is a
        // no-op; on a genuinely cold block (first slot after restart, account-heavy
        // block) it adds serial latency the old overlapped warmer would have hidden.
        // The benchmarks above are cold-cache batch import, not single-block live
        // tail latency; the tradeoff is deliberate and favors throughput.
        //
        // Gated by `--no-bal-prefetch`: when the operator disables BAL-driven
        // prefetching, skip the synchronous storage warm too. The warmer thread
        // below already honors the same toggle.
        // Flat-KV warm for execution (SLOAD and SSTORE original values). Uses the
        // full BAL access set, since execution genuinely reads every accessed slot.
        //
        // Witness collection records every read that reaches the store-backed
        // logger beneath the shared cache. The warmer's speculative reads would
        // be recorded as state accesses the canonical execution never makes,
        // polluting the witness (e.g. `engine_newPayloadWithWitnessV5`), so
        // warming is skipped entirely when a witness is being collected.
        #[cfg(feature = "rayon")]
        if self.options.bal_prefetch_enabled
            && !collect_witness
            && let Some(bal_ref) = bal.as_ref()
        {
            let slots = LEVM::bal_storage_slots(bal_ref);
            if !slots.is_empty() {
                let _ = caching_store.prefetch_storage(&slots);
            }
        }

        // Prepare the trie-node prefetch input: the MERKLE WRITE SET (changed
        // accounts + written slots), which is exactly what the merkleizer walks.
        // `optimistic_updates` (synthesize_bal_updates) already drops read-only
        // accesses and read-only slots, so warming is scoped to nodes the merkleizer
        // will actually read; using the access set instead regressed read-heavy
        // blocks (value-0 CALLs to existing accounts, bloated SLOADs). The prefetch
        // runs on its own thread inside the scope below (`trie_prefetch_handle`),
        // overlapping execution rather than preceding it. Gated so ordinary
        // merkle-light blocks skip the probe cost; the payoff is on blocks that WRITE
        // many distinct slots or modify many accounts, where merkle walks a large set
        // of scattered, cold nodes. See `BLOATED_BATCH_THRESHOLD`.
        //
        // Unlike the flat-KV warm above, this needs no `!collect_witness` guard:
        // `prefetch_trie_nodes` reads the trie-node CFs directly via
        // `backend.begin_read()`, bypassing the witness-recording caching layer, so
        // it cannot pollute the witness.
        #[cfg(feature = "rayon")]
        let trie_prefetch_input: Option<TriePrefetchInput> = if self.options.bal_prefetch_enabled
            && let Some(updates) = optimistic_updates.as_ref()
        {
            let mut write_slots: Vec<(Address, H256)> = Vec::new();
            for (addr, item) in updates {
                for slot in item.added_storage.keys() {
                    write_slots.push((*addr, *slot));
                }
            }
            let write_accounts: Vec<Address> = updates.keys().copied().collect();
            if write_slots.len() + write_accounts.len() >= BLOATED_BATCH_THRESHOLD {
                Some((write_slots, write_accounts))
            } else {
                None
            }
        } else {
            None
        };

        // Each thread that captures `bal` needs its own Arc clone (cheap pointer bump).
        #[cfg(feature = "rayon")]
        let bal_warmer = bal.clone();

        let (execution_result, merkleization_result, warmer_duration) = std::thread::scope(
            |s| -> Result<_, ChainError> {
                #[cfg(feature = "rayon")]
                let vm_type = vm.vm_type;
                let cancelled_ref = &cancelled;
                #[cfg(feature = "rayon")]
                let bal_prefetch_enabled = self.options.bal_prefetch_enabled;
                #[cfg(feature = "rayon")]
                let warm_handle = (!collect_witness)
                    .then(|| {
                        std::thread::Builder::new()
                            .name("block_executor_warmer".to_string())
                            .spawn_scoped(s, move || {
                                // Warming uses the same caching store, sharing cached state with execution.
                                // Precompile cache lives inside CachingDatabase, shared automatically.
                                let start = Instant::now();
                                if let Some(bal) = bal_warmer {
                                    if bal_prefetch_enabled {
                                        // Amsterdam+: BAL-based precise prefetching (no tx re-execution).
                                        if let Err(e) = LEVM::warm_block_from_bal(
                                            &bal,
                                            caching_store,
                                            cancelled_ref,
                                        ) {
                                            debug!("BAL warming failed (non-fatal): {e}");
                                        }
                                    } else if !bal_parallel_exec_enabled {
                                        // --no-bal-prefetch combined with --no-bal-parallel-exec:
                                        // mirror the pre-Amsterdam setup where a parallel speculative
                                        // warmer races ahead of the serial executor. With parallel
                                        // exec still on, we skip warming instead — two parallel passes
                                        // over the same txs would just fight for cores.
                                        // Warming is best-effort (non-fatal): a warm tx hitting the
                                        // EXECUTE precompile without a validator just fails and is
                                        // logged; the real execution path carries the validator.
                                        if let Err(e) = LEVM::warm_block(
                                            block,
                                            caching_store,
                                            vm_type,
                                            &NativeCrypto,
                                            cancelled_ref,
                                        ) {
                                            debug!("Block warming failed (non-fatal): {e}");
                                        }
                                    }
                                } else {
                                    // Pre-Amsterdam / P2P sync: speculative tx re-execution
                                    if let Err(e) = LEVM::warm_block(
                                        block,
                                        caching_store,
                                        vm_type,
                                        &NativeCrypto,
                                        cancelled_ref,
                                    ) {
                                        debug!("Block warming failed (non-fatal): {e}");
                                    }
                                }
                                start.elapsed()
                            })
                            .map_err(|e| {
                                ChainError::Custom(format!("Failed to spawn warmer thread: {e}"))
                            })
                    })
                    .transpose()?;

                // Warm the merkleizer's trie-node reads concurrently with execution
                // instead of up front. Touches different CFs than execution, so no
                // exec contention; as a high-queue-depth batch it races ahead of the
                // merkleizer's per-account walk so those reads land warm. Best-effort:
                // any node it misses is just cold-read by the walk. The scope joins it
                // before the block returns, but it shares the trie-node cold reads with
                // the merkleizer at higher aggregate queue depth, so it completes
                // within the exec/merkle window rather than extending it.
                #[cfg(feature = "rayon")]
                let trie_prefetch_handle = match trie_prefetch_input {
                    Some((slots, accounts)) => {
                        let storage = &self.storage;
                        std::thread::Builder::new()
                            .name("block_executor_trie_prefetch".to_string())
                            .spawn_scoped(s, move || {
                                // Result deliberately discarded: this is best-effort
                                // cache warming. A read error (or any node it fails to
                                // warm) just means the merkleizer cold-reads that node;
                                // it never affects block output, so a failure must not
                                // propagate into block processing.
                                let _ = storage.prefetch_trie_nodes(&slots, &accounts);
                            })
                            .inspect_err(|e| debug!("trie-node prefetch spawn failed: {e}"))
                            .ok()
                    }
                    None => None,
                };

                let max_queue_length_ref = &mut max_queue_length;
                // Channel is needed whenever the merkleizer takes the streaming
                // branch OR LEVM falls into the sequential path:
                // - sequential LEVM (`!bal_parallel_exec_enabled`) sends per-tx
                //   updates via `send_state_transitions_tx`; errors if Sender is None.
                // - streaming merkleizer (`!bal_parallel_trie_enabled` or no BAL)
                //   reads updates from `rx`.
                // Only the default `bal=Some && parallel_exec && parallel_trie` case
                // can skip both: parallel LEVM doesn't stream when its Sender is None,
                // and the merkleizer uses the synthesized optimistic map directly.
                let (tx, rx_for_merkle) =
                    if optimistic_updates.is_some() && bal_parallel_exec_enabled {
                        // Paired with the merkleizer's `rx_for_merkle.expect()` below:
                        // this is the only arm allowed to skip the channel. If a future
                        // refactor lets another branch reach here with `rx == None`, the
                        // merkleizer would panic instead of silently dropping updates.
                        (None, None)
                    } else {
                        let (tx, rx) = channel();
                        (Some(tx), Some(rx))
                    };

                let execution_handle = std::thread::Builder::new()
                    .name("block_executor_execution".to_string())
                    .spawn_scoped(s, move || -> Result<_, ChainError> {
                        // Cheap Arc pointer bump: `execute_block_pipeline` takes
                        // ownership, but the header-commitment check below still needs
                        // the input BAL on the parallel path (produced_bal == None).
                        let header_bal = bal.clone();
                        let result = vm.execute_block_pipeline(
                            block,
                            tx,
                            queue_length_ref,
                            bal,
                            bal_parallel_exec_enabled,
                        );
                        cancelled_ref.store(true, Ordering::Relaxed);
                        let (execution_result, produced_bal) = result?;

                        // Validate execution went alright
                        if let Err(e) =
                            validate_gas_used(execution_result.block_gas_used, &block.header)
                        {
                            ethrex_vm::log_gas_used_mismatch(
                                &execution_result.tx_gas_breakdowns,
                                block.header.number,
                                execution_result.block_gas_used,
                                block.header.gas_used,
                            );
                            return Err(e.into());
                        }
                        validate_receipts_root_and_logs_bloom(
                            &block.header,
                            &execution_result.receipts,
                            &NativeCrypto,
                        )?;
                        validate_requests_hash(
                            &block.header,
                            &chain_config,
                            &execution_result.requests,
                        )?;
                        // EIP-7928 block_access_list_hash commitment check.
                        //
                        // Sequential Amsterdam path: rebuilds a BAL and returns
                        // Some(produced_bal), so the full hash+index+size check runs here.
                        //
                        // Parallel Amsterdam path: uses the header BAL directly to drive
                        // execution and returns produced_bal = None. The header BAL's
                        // index/size are already validated inside execute_block_pipeline,
                        // and content-equivalence (unread_storage_reads /
                        // unaccessed_pure_accounts) plus the state_root comparison prove the
                        // header BAL is the canonical one. The one thing those checks do NOT
                        // bind is the header commitment itself, so we must compare
                        // keccak(rlp(header_bal)) against header.block_access_list_hash here;
                        // otherwise a block with a content-valid BAL but a forged commitment
                        // is accepted on this path while every spec-conformant client (and
                        // our own sequential/batch paths) rejects it. This is a pure hash
                        // compare on a BAL already in memory; the parallel exec optimization
                        // (no BAL rebuild) is preserved.
                        //
                        // Pre-Amsterdam blocks never record a BAL, so both arms are skipped.
                        if let Some(bal) = &produced_bal {
                            validate_block_access_list_hash(
                                &block.header,
                                &chain_config,
                                bal,
                                block.body.transactions.len(),
                                &NativeCrypto,
                            )?;
                        } else if let Some(header_bal) = header_bal.as_deref()
                            && chain_config.is_amsterdam_activated(block.header.timestamp)
                            && !header_bal.matches_commitment(
                                block.header.block_access_list_hash,
                                &NativeCrypto,
                            )
                        {
                            return Err(InvalidBlockError::BlockAccessListHashMismatch.into());
                        }

                        let exec_end_instant = Instant::now();
                        Ok((execution_result, produced_bal, exec_end_instant))
                    })
                    .map_err(|e| {
                        ChainError::Custom(format!("Failed to spawn execution thread: {e}"))
                    })?;
                let parent_header_ref = &parent_header; // Avoid moving to thread
                // Merkleizer returns (list, streaming witness or None on BAL path, merkle_start, merkle_end).
                type MerkleResult = Result<
                    (
                        AccountUpdatesList,
                        Option<Vec<AccountUpdate>>,
                        Instant,
                        Instant,
                    ),
                    StoreError,
                >;
                let merkleize_handle = std::thread::Builder::new()
                    .name("block_executor_merkleizer".to_string())
                    .spawn_scoped(s, move || -> MerkleResult {
                        let merkle_start_instant = Instant::now();
                        // Merkleizer behavior MUST match the channel-creation decision above:
                        // a channel is created (and execution streams per-tx updates into it via
                        // `send_state_transitions_tx`) in every case except `bal=Some &&
                        // parallel_exec`. So the optimistic synthesized-updates path is valid ONLY
                        // when no channel exists (`rx_for_merkle` is None); whenever a channel was
                        // created we must consume it. Taking the optimistic path while a channel is
                        // live drops `rx` mid-execution and races execution's later sends (the
                        // post-requests send especially), surfacing as "sending on a closed channel".
                        let (account_updates_list, streaming_witness) = match rx_for_merkle {
                            None => {
                                let prepared = optimistic_updates.expect(
                                    "optimistic updates are present when the streaming channel is absent",
                                );
                                let list = self.handle_merkleization_bal_from_updates(
                                    prepared,
                                    parent_header_ref,
                                )?;
                                // The merkleizer builds the trie from the BAL-synthesized
                                // updates and ignores the streaming channel. But sequential
                                // execution (`!bal_parallel_exec_enabled`) still streams per-tx
                                // updates over `rx_for_merkle`; if we drop the receiver before
                                // the executor's last send, that send fails with "sending on a
                                // closed channel", racing the real validation error. Drain the
                                // channel (the updates are redundant here — the BAL path is
                                // authoritative) so the executor always completes cleanly.
                                if let Some(rx) = rx_for_merkle {
                                    for _ in rx {}
                                }
                                (list, None)
                            }
                            Some(rx) => self.handle_merkleization(
                                rx,
                                parent_header_ref,
                                queue_length_ref,
                                max_queue_length_ref,
                                collect_witness,
                            )?,
                        };
                        let merkle_end_instant = Instant::now();
                        Ok((
                            account_updates_list,
                            streaming_witness,
                            merkle_start_instant,
                            merkle_end_instant,
                        ))
                    })
                    .map_err(|e| {
                        ChainError::Custom(format!("Failed to spawn merkleizer thread: {e}"))
                    })?;
                let execution_result = execution_handle.join().unwrap_or_else(|_| {
                    Err(ChainError::Custom("execution thread panicked".to_string()))
                });
                let merkleization_result = merkleize_handle.join().unwrap_or_else(|_| {
                    Err(StoreError::Custom(
                        "merkleization thread panicked".to_string(),
                    ))
                });
                #[cfg(feature = "rayon")]
                let warmer_duration = warm_handle
                    .map(|handle| {
                        handle
                            .join()
                            .inspect_err(|e| warn!("Warming thread error: {e:?}"))
                            .ok()
                            .unwrap_or(Duration::ZERO)
                    })
                    .unwrap_or(Duration::ZERO);
                #[cfg(not(feature = "rayon"))]
                let warmer_duration = Duration::ZERO;
                // Best-effort prefetch: join so the scope's borrows end cleanly.
                // The warming result is discarded, but surface a panic so a failing
                // prefetch (e.g. a RocksDB error) is observable rather than silent.
                #[cfg(feature = "rayon")]
                if let Some(h) = trie_prefetch_handle
                    && let Err(e) = h.join()
                {
                    warn!("trie-node prefetch thread panicked (best-effort, ignored): {e:?}");
                }
                Ok((execution_result, merkleization_result, warmer_duration))
            },
        )?;
        let (account_updates_list, streaming_witness, merkle_start_instant, merkle_end_instant) =
            merkleization_result?;
        let (execution_result, produced_bal, exec_end_instant) = execution_result?;

        // Witness collection forces the streaming merkleizer (synthesized
        // updates are disabled above), so the streaming witness is the only
        // possible source of accumulated updates.
        let accumulated_updates = streaming_witness;

        let exec_merkle_end_instant = Instant::now();

        Ok((
            execution_result,
            account_updates_list,
            accumulated_updates,
            produced_bal,
            max_queue_length,
            [
                start_instant,
                block_validated_instant,
                exec_merkle_start,
                merkle_start_instant,
                exec_end_instant,
                merkle_end_instant,
                exec_merkle_end_instant,
            ],
            warmer_duration,
        ))
    }

    #[instrument(
        level = "trace",
        name = "Trie update",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn handle_merkleization(
        &self,
        rx: Receiver<Vec<AccountUpdate>>,
        parent_header: &BlockHeader,
        queue_length: &AtomicUsize,
        max_queue_length: &mut usize,
        collect_witness: bool,
    ) -> Result<(AccountUpdatesList, Option<Vec<AccountUpdate>>), StoreError> {
        let parent_state_root = parent_header.state_root;

        // Create 16 worker channels (crossbeam for select! support)
        let mut workers_tx = Vec::with_capacity(16);
        let mut workers_rx = Vec::with_capacity(16);
        for _ in 0..16 {
            let (tx, rx) = cb::unbounded();
            workers_tx.push(tx);
            workers_rx.push(rx);
        }

        // Shutdown channel: dropping shutdown_tx signals all workers to exit.
        let (shutdown_tx, shutdown_rx) = cb::bounded::<()>(0);
        // Done channel: workers report completion status.
        let (done_tx, done_rx) = cb::unbounded::<Result<(), StoreError>>();

        // Run workers + coordination on the persistent pool.
        // Workers and watcher are spawned as pool tasks; the coordination logic
        // (dispatching messages, collecting results) runs on the calling thread
        // via in_place_scope, so it executes concurrently with the pool tasks.
        let watcher_error: Arc<std::sync::Mutex<Option<StoreError>>> = Default::default();
        let result = self.merkle_pool().in_place_scope(|s| {
            // Spawn 16 unified workers (each gets clone of all 16 senders)
            for (i, rx) in workers_rx.into_iter().enumerate() {
                let all_senders = workers_tx.clone();
                let storage_clone = self.storage.clone();
                let shutdown_rx = shutdown_rx.clone();
                let done_tx = done_tx.clone();
                s.spawn(move |_| {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_subtrie(
                            storage_clone,
                            rx,
                            parent_state_root,
                            i as u8,
                            all_senders,
                            shutdown_rx,
                        )
                    }));
                    let result = match result {
                        Ok(r) => r,
                        Err(_) => Err(StoreError::Custom(format!("shard worker {i} panicked"))),
                    };
                    if let Err(cb::SendError(Err(e))) = done_tx.send(result) {
                        error!("Failed to send worker {i} error to watcher: {e}");
                    }
                });
            }
            drop(done_tx); // Only workers hold senders
            drop(shutdown_rx); // Only workers hold receivers

            // Watcher task: drops shutdown_tx on first worker error to signal
            // all remaining workers, preventing deadlock on gatherer_rx.
            let watcher_error = watcher_error.clone();
            s.spawn(move |_| {
                let _shutdown = shutdown_tx;
                for result in done_rx {
                    if let Err(e) = result {
                        // Store error for the caller, then drop _shutdown to signal workers.
                        *watcher_error.lock().expect("watcher mutex poisoned") = Some(e);
                        return;
                    }
                }
            });

            // Coordination runs on the calling thread, concurrently with pool tasks.
            let mut code_updates: Vec<(H256, Code)> = vec![];
            let mut hashed_address_cache: FxHashMap<Address, H256> = Default::default();
            let mut has_storage: FxHashSet<H256> = Default::default();

            let mut accumulator: Option<FxHashMap<Address, AccountUpdate>> =
                collect_witness.then(FxHashMap::default);

            for updates in rx {
                let current_length = queue_length.fetch_sub(1, Ordering::Acquire);
                *max_queue_length = current_length.max(*max_queue_length);
                // Accumulate updates for witness generation if enabled
                if let Some(acc) = &mut accumulator {
                    for update in updates.clone() {
                        match acc.entry(update.address) {
                            Entry::Vacant(e) => {
                                e.insert(update);
                            }
                            Entry::Occupied(mut e) => {
                                e.get_mut().merge(update);
                            }
                        }
                    }
                }

                for update in updates {
                    let hashed_address = *hashed_address_cache
                        .entry(update.address)
                        .or_insert_with(|| keccak(update.address));

                    let (info, code, storage) = if update.removed {
                        (Some(Default::default()), None, Default::default())
                    } else {
                        (update.info, update.code, update.added_storage)
                    };

                    // Extract code for dispatcher-local collection
                    if let Some(ref info) = info
                        && let Some(code) = code
                    {
                        code_updates.push((info.code_hash, code));
                    }

                    if update.removed || update.removed_storage || !storage.is_empty() {
                        has_storage.insert(hashed_address);
                    }

                    let bucket = hashed_address.as_fixed_bytes()[0] >> 4;
                    workers_tx[bucket as usize]
                        .send(WorkerRequest::ProcessAccount {
                            prefix: hashed_address,
                            info,
                            storage,
                            removed: update.removed,
                            removed_storage: update.removed_storage,
                        })
                        .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
                }
            }

            // Send FinishRouting — workers self-synchronize via RoutingDone exchange.
            for tx in &workers_tx {
                tx.send(WorkerRequest::FinishRouting)
                    .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
            }

            // Send MerklizeAccounts for no-storage accounts.
            let mut early_batches: [Vec<H256>; 16] = Default::default();
            for hashed_account in hashed_address_cache.values() {
                if !has_storage.contains(hashed_account) {
                    let bucket = hashed_account.as_fixed_bytes()[0] >> 4;
                    early_batches[bucket as usize].push(*hashed_account);
                }
            }
            for (i, batch) in early_batches.into_iter().enumerate() {
                if !batch.is_empty() {
                    workers_tx[i]
                        .send(WorkerRequest::MerklizeAccounts { accounts: batch })
                        .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
                }
            }

            // Send CollectState immediately — workers defer until collection is done.
            let mut storage_updates: Vec<(H256, Vec<TrieNode>)> = Default::default();
            let (gatherer_tx, gatherer_rx) = channel();
            for tx in &workers_tx {
                tx.send(WorkerRequest::CollectState {
                    tx: gatherer_tx.clone(),
                })
                .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
            }
            drop(gatherer_tx);
            drop(workers_tx);

            let mut root = BranchNode::default();
            let mut state_updates = Vec::new();
            for CollectedStateMsg {
                index,
                subroot,
                state_nodes,
                storage_nodes,
            } in gatherer_rx
            {
                storage_updates.extend(storage_nodes);
                state_updates.extend(state_nodes);
                root.choices[index as usize] = subroot.choices[index as usize].clone();
            }

            let collapsed = self.collapse_root_node(parent_header, None, root)?;
            let state_trie_hash = if let Some(root) = collapsed {
                let mut root = NodeRef::from(root);
                let hash = root.commit(Nibbles::default(), &mut state_updates, &NativeCrypto);
                let _ = DROP_SENDER.send(Box::new(root));
                hash.finalize(&NativeCrypto)
            } else {
                state_updates.push((Nibbles::default(), vec![RLP_NULL]));
                *EMPTY_TRIE_HASH
            };

            let accumulated_updates = accumulator.map(|acc| acc.into_values().collect());

            Ok((
                AccountUpdatesList {
                    state_trie_hash,
                    state_updates,
                    storage_updates,
                    code_updates,
                },
                accumulated_updates,
            ))
        });

        // Surface any worker errors captured by the watcher task.
        if let Some(err) = watcher_error.lock().expect("watcher mutex poisoned").take() {
            return Err(err);
        }

        result
    }

    /// Validation path synthesizes `BalSynthesisItem`s from the input BAL pre-execution and
    /// merkleizes optimistically in parallel with EVM execution. Two gates guard the result:
    /// (1) the EIP-7928 `block_access_list_hash` commitment check, and
    /// (2) the downstream `state_root` comparison against the block header. The parallel
    /// path returns `produced_bal = None` (the header BAL drives execution rather than being
    /// rebuilt), so gate (1) compares `keccak(rlp(header_bal))` against the header commitment
    /// directly in the execution thread; the sequential path runs the same gate against the
    /// rebuilt BAL. On any mismatch the optimistic merkle output is discarded via `?` on the
    /// execution thread's join result.
    #[instrument(
        level = "trace",
        name = "Trie update (BAL)",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn handle_merkleization_bal_from_updates(
        &self,
        prepared: FxHashMap<Address, BalSynthesisItem>,
        parent_header: &BlockHeader,
    ) -> Result<AccountUpdatesList, StoreError> {
        const NUM_WORKERS: usize = 16;
        // Accounts with at least this many storage slot updates are sharded
        // across 16 workers inside `compute_sharded_storage_root` instead of
        // being handled by Stage B. When hot_indices is empty the Stage B path
        // is unchanged.
        const STORAGE_SHARD_THRESHOLD: usize = 2048;
        let parent_state_root = parent_header.state_root;

        // Build code updates and work items with pre-hashed addresses from the
        // pre-synthesized map. No Stage A drain needed: the synthesis happened
        // pre-scope at the call site.
        let mut code_updates: Vec<(H256, Code)> = Vec::new();
        let mut accounts: Vec<(H256, BalSynthesisItem)> = Vec::with_capacity(prepared.len());
        for (addr, item) in prepared {
            let hashed = keccak(addr);
            if let Some(ch) = item.code_hash
                && let Some(ref code) = item.code
            {
                code_updates.push((ch, code.clone()));
            }
            accounts.push((hashed, item));
        }

        // === Stage B: Parallel per-account storage root computation ===

        // Partition accounts: those with >= STORAGE_SHARD_THRESHOLD slots are
        // handled after Stage B via `compute_sharded_storage_root` (hot_indices).
        // The rest follow the normal Stage B greedy bin-packing path (normal_indices).
        // When hot_indices is empty the behavior is byte-identical to the previous code.
        let mut normal_indices: Vec<usize> = Vec::new();
        let mut hot_indices: Vec<usize> = Vec::new();
        for (i, (_, item)) in accounts.iter().enumerate() {
            if item.added_storage.len() >= STORAGE_SHARD_THRESHOLD {
                hot_indices.push(i);
            } else {
                normal_indices.push(i);
            }
        }

        // Sort by storage weight (descending) for greedy bin packing.
        // Every item with real Stage B work MUST have weight >= 1: the greedy
        // algorithm does `bin_weights[min] += weight`, so weight-0 items never
        // change the bin weight and `min_by_key` keeps returning the same bin,
        // piling ALL of them into a single worker.
        // Synthesis never sets `removed`/`removed_storage`, so weight is purely
        // based on storage slot count.
        let mut work_indices: Vec<(usize, usize)> = normal_indices
            .iter()
            .map(|&i| {
                let item = &accounts[i].1;
                let weight = if !item.added_storage.is_empty() {
                    1.max(item.added_storage.len())
                } else {
                    0
                };
                (i, weight)
            })
            .collect();
        work_indices.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        // Greedy bin packing into NUM_WORKERS bins
        let mut bins: Vec<Vec<usize>> = (0..NUM_WORKERS).map(|_| Vec::new()).collect();
        let mut bin_weights: Vec<usize> = vec![0; NUM_WORKERS];
        for (idx, weight) in work_indices {
            let min_bin = bin_weights
                .iter()
                .enumerate()
                .min_by_key(|(_, w)| **w)
                .expect("bin_weights is non-empty")
                .0;
            bins[min_bin].push(idx);
            bin_weights[min_bin] += weight;
        }

        // Compute storage roots in parallel
        let mut storage_roots: Vec<Option<H256>> = vec![None; accounts.len()];
        let mut storage_updates: Vec<(H256, Vec<TrieNode>)> = Vec::new();

        std::thread::scope(|s| -> Result<(), StoreError> {
            let accounts_ref = &accounts;
            let handles: Vec<_> = bins
                .into_iter()
                .enumerate()
                .filter_map(|(worker_id, bin)| {
                    if bin.is_empty() {
                        return None;
                    }
                    Some(
                        std::thread::Builder::new()
                            .name(format!("bal_storage_worker_{worker_id}"))
                            .spawn_scoped(
                                s,
                                move || -> Result<Vec<(usize, H256, Vec<TrieNode>)>, StoreError> {
                                    let mut results: Vec<(usize, H256, Vec<TrieNode>)> = Vec::new();
                                    // Open one state trie per worker for storage root lookups
                                    let state_trie =
                                        self.storage.open_state_trie(parent_state_root)?;
                                    for idx in bin {
                                        let (hashed_address, item) = &accounts_ref[idx];
                                        if item.added_storage.is_empty() {
                                            continue;
                                        }

                                        let storage_root = match state_trie
                                            .get(hashed_address.as_bytes())?
                                        {
                                            Some(rlp) => AccountState::decode(&rlp)?.storage_root,
                                            None => *EMPTY_TRIE_HASH,
                                        };
                                        let mut trie = self.storage.open_storage_trie(
                                            *hashed_address,
                                            parent_state_root,
                                            storage_root,
                                        )?;

                                        // Pre-hash and sort by trie path so per-slot inserts
                                        // walk the node arena in order, improving cache locality.
                                        let mut hashed_storage: Vec<(H256, U256)> = item
                                            .added_storage
                                            .iter()
                                            .map(|(k, v)| (keccak(k), *v))
                                            .collect();
                                        hashed_storage.sort_unstable_by(|a, b| a.0.cmp(&b.0));

                                        // Warm the touched subtrie breadth-first before the
                                        // serial insert/remove loop below, using the same
                                        // sorted key set/order the loop iterates. Hash-preserving
                                        // (see `Trie::prefetch_sorted`); does not affect the
                                        // resulting root or persisted node set.
                                        if hashed_storage.len() >= STORAGE_PREFETCH_THRESHOLD {
                                            let paths: Vec<Nibbles> = hashed_storage
                                                .iter()
                                                .map(|(k, _)| Nibbles::from_bytes(k.as_bytes()))
                                                .collect();
                                            trie.prefetch_sorted(&paths)?;
                                        }

                                        for (hashed_key, value) in &hashed_storage {
                                            if value.is_zero() {
                                                trie.remove(hashed_key.as_bytes())?;
                                            } else {
                                                trie.insert(
                                                    hashed_key.as_bytes().to_vec(),
                                                    value.encode_to_vec(),
                                                )?;
                                            }
                                        }

                                        let (root_hash, nodes) =
                                            trie.collect_changes_since_last_hash(&NativeCrypto);
                                        results.push((idx, root_hash, nodes));
                                    }
                                    Ok(results)
                                },
                            )
                            .map_err(|e| StoreError::Custom(format!("spawn failed: {e}"))),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;

            for handle in handles {
                let results = handle
                    .join()
                    .map_err(|_| StoreError::Custom("storage worker panicked".to_string()))??;
                for (idx, root_hash, nodes) in results {
                    storage_roots[idx] = Some(root_hash);
                    storage_updates.push((accounts_ref[idx].0, nodes));
                }
            }
            Ok(())
        })?;

        // === Stage B.5: Sharded storage root for hot accounts ===
        // Each call to compute_sharded_storage_root already saturates 16 cores,
        // so we process hot accounts sequentially. A parallel outer loop is a
        // future option if multi-hot-account blocks appear.
        // Skip the state-trie open entirely on the common path (no hot accounts).
        if !hot_indices.is_empty() {
            let state_trie = self.storage.open_state_trie(parent_state_root)?;
            for idx in &hot_indices {
                let idx = *idx;
                let (hashed_address, item) = &accounts[idx];
                let storage_root = match state_trie.get(hashed_address.as_bytes())? {
                    Some(rlp) => AccountState::decode(&rlp)?.storage_root,
                    None => *EMPTY_TRIE_HASH,
                };
                // Slots are sorted by hashed key inside compute_sharded_storage_root
                // to match Stage B's insert order (cache locality + identical node set).
                let hashed_storage: Vec<(H256, U256)> = item
                    .added_storage
                    .iter()
                    .map(|(k, v)| (keccak(k), *v))
                    .collect();
                let (root_hash, nodes) = compute_sharded_storage_root(
                    &self.storage,
                    parent_state_root,
                    *hashed_address,
                    storage_root,
                    &hashed_storage,
                )?;
                storage_roots[idx] = Some(root_hash);
                storage_updates.push((*hashed_address, nodes));
            }
        }

        // === Stage C: State trie update via 16 shard workers ===

        // Build per-shard work items
        let mut shards: Vec<Vec<BalStateWorkItem>> = (0..NUM_WORKERS).map(|_| Vec::new()).collect();
        for (idx, (hashed_address, item)) in accounts.iter().enumerate() {
            let bucket = (hashed_address.as_fixed_bytes()[0] >> 4) as usize;
            shards[bucket].push(BalStateWorkItem {
                hashed_address: *hashed_address,
                nonce: item.nonce,
                balance: item.balance,
                code_hash: item.code_hash,
                storage_root: storage_roots[idx],
            });
        }

        let mut root = BranchNode::default();
        let mut state_updates = Vec::new();

        // All 16 shard threads must run, even for empty shards: each worker
        // opens the parent state trie and returns its existing subtree so the
        // root can be correctly assembled via `collect_trie`. Skipping unchanged
        // shards (unlike Stage B's filter_map) would leave holes in the root.
        std::thread::scope(|s| -> Result<(), StoreError> {
            let handles: Vec<_> = shards
                .into_iter()
                .enumerate()
                .map(|(index, shard_items)| {
                    std::thread::Builder::new()
                        .name(format!("bal_state_shard_{index}"))
                        .spawn_scoped(
                            s,
                            move || -> Result<(Box<BranchNode>, Vec<TrieNode>), StoreError> {
                                let mut state_trie =
                                    self.storage.open_state_trie(parent_state_root)?;

                                // Breadth-first batch-prefetch the account-trie nodes for
                                // this shard's accounts before the serial get/insert loop,
                                // so cold state-trie reads are issued per level instead of
                                // one dependent read at a time. Sorted so adjacent paths
                                // share fetched nodes; warming only, root is unchanged.
                                if shard_items.len() >= STATE_SHARD_PREFETCH_THRESHOLD {
                                    let mut addrs: Vec<H256> =
                                        shard_items.iter().map(|i| i.hashed_address).collect();
                                    addrs.sort_unstable();
                                    let paths: Vec<Nibbles> = addrs
                                        .iter()
                                        .map(|a| Nibbles::from_bytes(a.as_bytes()))
                                        .collect();
                                    state_trie.prefetch_sorted(&paths)?;
                                }

                                for item in &shard_items {
                                    let path = item.hashed_address.as_bytes();

                                    // Load existing account state
                                    let mut account_state = match state_trie.get(path)? {
                                        Some(rlp) => {
                                            let state = AccountState::decode(&rlp)?;
                                            // Re-insert to materialize the trie path so
                                            // collect_changes_since_last_hash includes this
                                            // node in the diff (needed for both updates and
                                            // removals via collect_trie).
                                            state_trie.insert(path.to_vec(), rlp)?;
                                            state
                                        }
                                        None => AccountState::default(),
                                    };

                                    if let Some(n) = item.nonce {
                                        account_state.nonce = n;
                                    }
                                    if let Some(b) = item.balance {
                                        account_state.balance = b;
                                    }
                                    if let Some(ch) = item.code_hash {
                                        account_state.code_hash = ch;
                                    }
                                    if let Some(storage_root) = item.storage_root {
                                        account_state.storage_root = storage_root;
                                    }

                                    // EIP-161: remove empty accounts (zero nonce, zero balance,
                                    // empty code, empty storage) from the state trie.
                                    if account_state != AccountState::default() {
                                        state_trie
                                            .insert(path.to_vec(), account_state.encode_to_vec())?;
                                    } else {
                                        state_trie.remove(path)?;
                                    }
                                }

                                collect_trie(index as u8, state_trie)
                                    .map_err(|e| StoreError::Custom(format!("{e}")))
                            },
                        )
                        .map_err(|e| StoreError::Custom(format!("spawn failed: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;

            for (i, handle) in handles.into_iter().enumerate() {
                let (subroot, state_nodes) = handle
                    .join()
                    .map_err(|_| StoreError::Custom("state shard worker panicked".to_string()))??;
                state_updates.extend(state_nodes);
                root.choices[i] = subroot.choices[i].clone();
            }
            Ok(())
        })?;

        // === Stage D: Finalize root ===
        let state_trie_hash =
            if let Some(root) = self.collapse_root_node(parent_header, None, root)? {
                let mut root = NodeRef::from(root);
                let hash = root.commit(Nibbles::default(), &mut state_updates, &NativeCrypto);
                let _ = DROP_SENDER.send(Box::new(root));
                hash.finalize(&NativeCrypto)
            } else {
                state_updates.push((Nibbles::default(), vec![RLP_NULL]));
                *EMPTY_TRIE_HASH
            };

        Ok(AccountUpdatesList {
            state_trie_hash,
            state_updates,
            storage_updates,
            code_updates,
        })
    }

    fn collapse_root_node(
        &self,
        parent_header: &BlockHeader,
        prefix: Option<H256>,
        root: BranchNode,
    ) -> Result<Option<Node>, StoreError> {
        collapse_root_node(&self.storage, parent_header.state_root, prefix, root)
    }

    pub async fn generate_witness_for_blocks(
        &self,
        blocks: &[Block],
    ) -> Result<ExecutionWitness, ChainError> {
        self.generate_witness_for_blocks_with_fee_configs(blocks, None)
            .await
    }

    pub async fn generate_witness_for_blocks_with_fee_configs(
        &self,
        blocks: &[Block],
        fee_configs: Option<&[FeeConfig]>,
    ) -> Result<ExecutionWitness, ChainError> {
        let (witness, _bals) = self
            .generate_witness_and_bal_for_blocks_with_fee_configs(blocks, fee_configs)
            .await?;
        Ok(witness)
    }

    pub async fn generate_witness_and_bal_for_blocks_with_fee_configs(
        &self,
        blocks: &[Block],
        fee_configs: Option<&[FeeConfig]>,
    ) -> Result<(ExecutionWitness, Vec<Option<BlockAccessList>>), ChainError> {
        let first_block_header = &blocks
            .first()
            .ok_or(ChainError::WitnessGeneration(
                "Empty block batch".to_string(),
            ))?
            .header;

        // Get state at previous block
        let trie = self
            .storage
            .state_trie(first_block_header.parent_hash)
            .map_err(|_| ChainError::ParentStateNotFound)?
            .ok_or(ChainError::ParentStateNotFound)?;
        let initial_state_root = trie.hash_no_commit(&NativeCrypto);

        let (mut current_trie_witness, mut trie) = TrieLogger::open_trie(trie);

        // For each block, a new TrieLogger will be opened, each containing the
        // witness accessed during the block execution. We need to accumulate
        // all the nodes accessed during the entire batch execution.
        let mut accumulated_state_trie_witness = current_trie_witness
            .lock()
            .map_err(|_| {
                ChainError::WitnessGeneration("Failed to lock state trie witness".to_string())
            })?
            .clone();

        let mut touched_account_storage_slots = BTreeMap::new();
        // This will become the state trie + storage trie
        let mut used_trie_nodes = Vec::new();

        // Store the root node in case the block is empty and the witness does not record any nodes
        let root_node = trie.root_node().map_err(|_| {
            ChainError::WitnessGeneration("Failed to get root state node".to_string())
        })?;

        let mut blockhash_opcode_references = HashMap::new();
        let mut codes = Vec::new();
        let mut block_access_lists: Vec<Option<BlockAccessList>> = Vec::with_capacity(blocks.len());

        for (i, block) in blocks.iter().enumerate() {
            let parent_hash = block.header.parent_hash;
            let parent_header = self
                .storage
                .get_block_header_by_hash(parent_hash)
                .map_err(ChainError::StoreError)?
                .ok_or(ChainError::ParentNotFound)?;

            // This assumes that the user has the necessary state stored already,
            // so if the user only has the state previous to the first block, it
            // will fail in the second iteration of this for loop. To ensure this,
            // doesn't fail, later in this function we store the new state after
            // re-execution.
            let vm_db: DynVmDatabase =
                Box::new(StoreVmDatabase::new(self.storage.clone(), parent_header)?);

            let logger = Arc::new(DatabaseLogger::new(Arc::new(vm_db)));

            let mut vm = match self.options.r#type {
                BlockchainType::L1 => {
                    Evm::new_from_db_for_l1(logger.clone(), Arc::new(NativeCrypto))
                }
                BlockchainType::L2(_) => {
                    let l2_config = match fee_configs {
                        Some(fee_configs) => {
                            fee_configs.get(i).ok_or(ChainError::WitnessGeneration(
                                "FeeConfig not found for witness generation".to_string(),
                            ))?
                        }
                        None => Err(ChainError::WitnessGeneration(
                            "L2Config not found for witness generation".to_string(),
                        ))?,
                    };
                    Evm::new_from_db_for_l2(logger.clone(), *l2_config, Arc::new(NativeCrypto))
                }
            };
            // I2: witness-gen must attach the stateless validator too, so
            // re-executing an L1 block that itself contains an EXECUTE call
            // (native-rollup advance) does not fail with "requires a
            // StatelessValidator". Mirrors the sibling paths at the other
            // `new_from_db_for_l1` sites (block import + witness gen).
            attach_stateless_validator(&mut vm);

            // Re-execute block with logger
            let (execution_result, bal) = vm.execute_block(block)?;
            block_access_lists.push(bal);

            // Gather account updates
            let account_updates = vm.get_state_transitions()?;

            let mut state_accessed = logger
                .state_accessed
                .lock()
                .map_err(|_e| {
                    ChainError::WitnessGeneration("Failed to execute with witness".to_string())
                })?
                .clone();

            // Deduplicate storage keys while preserving access order
            for keys in state_accessed.values_mut() {
                let mut seen = HashSet::new();
                keys.retain(|k| seen.insert(*k));
            }

            for (account, acc_keys) in state_accessed.iter() {
                let slots: &mut Vec<H256> =
                    touched_account_storage_slots.entry(*account).or_default();
                slots.extend(acc_keys.iter().copied());
            }

            // Get the used block hashes from the logger
            let logger_block_hashes = logger
                .block_hashes_accessed
                .lock()
                .map_err(|_e| {
                    ChainError::WitnessGeneration("Failed to get block hashes".to_string())
                })?
                .clone();

            blockhash_opcode_references.extend(logger_block_hashes);

            // Access all the accounts needed for withdrawals
            if let Some(withdrawals) = block.body.withdrawals.as_ref() {
                for withdrawal in withdrawals {
                    trie.get(&hash_address(&withdrawal.address)).map_err(|_e| {
                        ChainError::Custom("Failed to access account from trie".to_string())
                    })?;
                }
            }

            let mut used_storage_tries = HashMap::new();

            // Access all the accounts from the initial trie
            // Record all the storage nodes for the initial state
            for (account, acc_keys) in state_accessed.iter() {
                // Access the account from the state trie to record the nodes used to access it
                trie.get(&hash_address(account)).map_err(|_e| {
                    ChainError::WitnessGeneration("Failed to access account from trie".to_string())
                })?;
                // Get storage trie at before updates
                if !acc_keys.is_empty()
                    && let Ok(Some(storage_trie)) = self.storage.storage_trie(parent_hash, *account)
                {
                    let (storage_trie_witness, storage_trie) = TrieLogger::open_trie(storage_trie);
                    // Access all the keys
                    for storage_key in acc_keys {
                        let hashed_key = hash_key(storage_key);
                        storage_trie.get(&hashed_key).map_err(|_e| {
                            ChainError::WitnessGeneration(
                                "Failed to access storage key".to_string(),
                            )
                        })?;
                    }
                    // Store the tries to reuse when applying account updates
                    used_storage_tries.insert(*account, (storage_trie_witness, storage_trie));
                }
            }

            // Store all the accessed evm bytecodes. `code_accessed` records one entry
            // per read, and a contract read for both its bytecode and its length is
            // recorded twice, so dedup before embedding: a repeated hash would put the
            // same (up to 24KB) bytecode in the witness more than once.
            let accessed_codes: Vec<H256> = {
                let accessed = logger.code_accessed.lock().map_err(|_e| {
                    ChainError::WitnessGeneration("Failed to gather used bytecodes".to_string())
                })?;
                let mut seen =
                    FxHashSet::with_capacity_and_hasher(accessed.len(), Default::default());
                accessed
                    .iter()
                    .copied()
                    .filter(|h| seen.insert(*h))
                    .collect()
            };
            for code_hash in &accessed_codes {
                let code = self
                    .storage
                    .get_account_code(*code_hash)
                    .map_err(|_e| {
                        ChainError::WitnessGeneration("Failed to get account code".to_string())
                    })?
                    .ok_or(ChainError::WitnessGeneration(
                        "Failed to get account code".to_string(),
                    ))?;
                codes.push(code.code().to_vec());
            }

            // Apply account updates to the trie recording all the necessary nodes to do so
            let (storage_tries_after_update, account_updates_list) =
                self.storage.apply_account_updates_from_trie_with_witness(
                    trie,
                    &account_updates,
                    used_storage_tries,
                )?;

            // We cannot ensure that the users of this function have the necessary
            // state stored, so in order for it to not assume anything, we update
            // the storage with the new state after re-execution
            self.store_block(block.clone(), account_updates_list, execution_result)?;

            for (address, (witness, _storage_trie)) in storage_tries_after_update {
                let mut witness = witness.lock().map_err(|_| {
                    ChainError::WitnessGeneration("Failed to lock storage trie witness".to_string())
                })?;
                let witness = std::mem::take(&mut *witness);
                let witness = witness.into_values().collect::<Vec<_>>();
                used_trie_nodes.extend_from_slice(&witness);
                touched_account_storage_slots.entry(address).or_default();
            }

            let (new_state_trie_witness, updated_trie) = TrieLogger::open_trie(
                self.storage
                    .state_trie(block.header.hash())
                    .map_err(|_| ChainError::ParentStateNotFound)?
                    .ok_or(ChainError::ParentStateNotFound)?,
            );

            // Use the updated state trie for the next block
            trie = updated_trie;

            for state_trie_witness in current_trie_witness
                .lock()
                .map_err(|_| {
                    ChainError::WitnessGeneration("Failed to lock state trie witness".to_string())
                })?
                .iter()
            {
                accumulated_state_trie_witness
                    .insert(*state_trie_witness.0, state_trie_witness.1.clone());
            }

            current_trie_witness = new_state_trie_witness;
        }

        used_trie_nodes.extend_from_slice(&Vec::from_iter(
            accumulated_state_trie_witness.into_values(),
        ));

        // If the witness is empty at least try to store the root
        if used_trie_nodes.is_empty()
            && let Some(root) = root_node
        {
            used_trie_nodes.push((*root).clone());
        }

        // - We now need necessary block headers, these go from the first block referenced (via BLOCKHASH or just the first block to execute) up to the parent of the last block to execute.
        let mut block_headers_bytes = Vec::new();

        let first_blockhash_opcode_number = blockhash_opcode_references.keys().min();
        let first_needed_block_hash = first_blockhash_opcode_number
            .and_then(|n| {
                (*n < first_block_header.number.saturating_sub(1))
                    .then(|| blockhash_opcode_references.get(n))?
                    .copied()
            })
            .unwrap_or(first_block_header.parent_hash);

        // At the beginning this is the header of the last block to execute.
        let mut current_header = blocks
            .last()
            .ok_or_else(|| ChainError::WitnessGeneration("Empty batch".to_string()))?
            .header
            .clone();

        // Headers from latest - 1 until we reach first block header we need.
        // We do it this way because we want to fetch headers by hash, not by number
        while current_header.hash() != first_needed_block_hash {
            let parent_hash = current_header.parent_hash;
            let current_number = current_header.number - 1;

            current_header = self
                .storage
                .get_block_header_by_hash(parent_hash)?
                .ok_or_else(|| {
                    ChainError::WitnessGeneration(format!(
                        "Failed to get block {current_number} header"
                    ))
                })?;

            block_headers_bytes.push(current_header.encode_to_vec());
        }

        // Get initial state trie root and embed the rest of the trie into it
        let nodes: BTreeMap<H256, Node> = used_trie_nodes
            .into_iter()
            .map(|node| {
                (
                    node.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                    node,
                )
            })
            .collect();
        let state_trie_root = if let NodeRef::Node(state_trie_root, _) =
            Trie::get_embedded_root(&nodes, initial_state_root)?
        {
            Some((*state_trie_root).clone())
        } else {
            None
        };

        // Get all initial storage trie roots and embed the rest of the trie into it
        let state_trie = if let Some(state_trie_root) = &state_trie_root {
            Trie::new_temp_with_root(state_trie_root.clone().into())
        } else {
            Trie::new_temp()
        };
        let mut storage_trie_roots = BTreeMap::new();
        for address in touched_account_storage_slots.keys() {
            let hashed_address = hash_address(address);
            let hashed_address_h256 = H256::from_slice(&hashed_address);
            let Some(encoded_account) = state_trie.get(&hashed_address)? else {
                continue; // empty account, doesn't have a storage trie
            };
            let storage_root_hash = AccountState::decode(&encoded_account)?.storage_root;
            if storage_root_hash == *EMPTY_TRIE_HASH {
                continue; // empty storage trie
            }
            if !nodes.contains_key(&storage_root_hash) {
                continue; // storage trie isn't relevant to this execution
            }
            let node = Trie::get_embedded_root(&nodes, storage_root_hash)?;
            let NodeRef::Node(node, _) = node else {
                return Err(ChainError::Custom(
                    "execution witness does not contain non-empty storage trie".to_string(),
                ));
            };
            storage_trie_roots.insert(hashed_address_h256, (*node).clone());
        }

        Ok((
            ExecutionWitness {
                codes,
                block_headers_bytes,
                first_block_number: first_block_header.number,
                chain_config: self.storage.get_chain_config(),
                state_trie_root,
                storage_trie_roots,
            },
            block_access_lists,
        ))
    }

    pub fn generate_witness_from_account_updates(
        &self,
        account_updates: Vec<AccountUpdate>,
        block: &Block,
        parent_header: BlockHeader,
        logger: &DatabaseLogger,
    ) -> Result<ExecutionWitness, ChainError> {
        // Get state at previous block
        let trie = self
            .storage
            .state_trie(parent_header.hash())
            .map_err(|_| ChainError::ParentStateNotFound)?
            .ok_or(ChainError::ParentStateNotFound)?;
        let initial_state_root = trie.hash_no_commit(&NativeCrypto);

        let (trie_witness, trie) = TrieLogger::open_trie(trie);

        let mut touched_account_storage_slots = BTreeMap::new();
        // This will become the state trie + storage trie
        let mut used_trie_nodes = Vec::new();

        // Store the root node in case the block is empty and the witness does not record any nodes
        let root_node = trie.root_node().map_err(|_| {
            ChainError::WitnessGeneration("Failed to get root state node".to_string())
        })?;

        let mut codes = Vec::new();

        for account_update in &account_updates {
            touched_account_storage_slots.insert(
                account_update.address,
                account_update
                    .added_storage
                    .keys()
                    .cloned()
                    .collect::<Vec<H256>>(),
            );
        }

        // Get the used block hashes from the logger
        let blockhash_opcode_references = logger
            .block_hashes_accessed
            .lock()
            .map_err(|_e| ChainError::WitnessGeneration("Failed to get block hashes".to_string()))?
            .clone();

        // Access all the accounts needed for withdrawals
        if let Some(withdrawals) = block.body.withdrawals.as_ref() {
            for withdrawal in withdrawals {
                trie.get(&hash_address(&withdrawal.address)).map_err(|_e| {
                    ChainError::Custom("Failed to access account from trie".to_string())
                })?;
            }
        }

        let mut used_storage_tries = HashMap::new();

        // Access all the accounts from the initial trie
        // Record all the storage nodes for the initial state
        for (account, acc_keys) in logger
            .state_accessed
            .lock()
            .map_err(|_e| {
                ChainError::WitnessGeneration("Failed to execute with witness".to_string())
            })?
            .iter()
        {
            // Access the account from the state trie to record the nodes used to access it
            trie.get(&hash_address(account)).map_err(|_e| {
                ChainError::WitnessGeneration("Failed to access account from trie".to_string())
            })?;
            // Get storage trie at before updates
            if !acc_keys.is_empty()
                && let Ok(Some(storage_trie)) =
                    self.storage.storage_trie(parent_header.hash(), *account)
            {
                let (storage_trie_witness, storage_trie) = TrieLogger::open_trie(storage_trie);
                // Access all the keys
                for storage_key in acc_keys {
                    let hashed_key = hash_key(storage_key);
                    storage_trie.get(&hashed_key).map_err(|_e| {
                        ChainError::WitnessGeneration("Failed to access storage key".to_string())
                    })?;
                }
                // Store the tries to reuse when applying account updates
                used_storage_tries.insert(*account, (storage_trie_witness, storage_trie));
            }
        }

        // Store all the accessed evm bytecodes. `code_accessed` records one entry
        // per read, and a contract read for both its bytecode and its length is
        // recorded twice, so dedup before embedding: a repeated hash would put the
        // same (up to 24KB) bytecode in the witness more than once.
        let accessed_codes: Vec<H256> = {
            let accessed = logger.code_accessed.lock().map_err(|_e| {
                ChainError::WitnessGeneration("Failed to gather used bytecodes".to_string())
            })?;
            let mut seen = FxHashSet::with_capacity_and_hasher(accessed.len(), Default::default());
            accessed
                .iter()
                .copied()
                .filter(|h| seen.insert(*h))
                .collect()
        };
        for code_hash in &accessed_codes {
            let code = self
                .storage
                .get_account_code(*code_hash)
                .map_err(|_e| {
                    ChainError::WitnessGeneration("Failed to get account code".to_string())
                })?
                .ok_or(ChainError::WitnessGeneration(
                    "Failed to get account code".to_string(),
                ))?;
            codes.push(code.code().to_vec());
        }

        // Apply account updates to the trie recording all the necessary nodes to do so
        let (storage_tries_after_update, _account_updates_list) =
            self.storage.apply_account_updates_from_trie_with_witness(
                trie,
                &account_updates,
                used_storage_tries,
            )?;

        for (address, (witness, _storage_trie)) in storage_tries_after_update {
            let mut witness = witness.lock().map_err(|_| {
                ChainError::WitnessGeneration("Failed to lock storage trie witness".to_string())
            })?;
            let witness = std::mem::take(&mut *witness);
            let witness = witness.into_values().collect::<Vec<_>>();
            used_trie_nodes.extend_from_slice(&witness);
            touched_account_storage_slots.entry(address).or_default();
        }

        used_trie_nodes.extend_from_slice(&Vec::from_iter(
            trie_witness
                .lock()
                .map_err(|_| {
                    ChainError::WitnessGeneration("Failed to lock state trie witness".to_string())
                })?
                .clone()
                .into_values(),
        ));

        // If the witness is empty at least try to store the root
        if used_trie_nodes.is_empty()
            && let Some(root) = root_node
        {
            used_trie_nodes.push((*root).clone());
        }

        // - We now need necessary block headers, these go from the first block referenced (via BLOCKHASH or just the first block to execute) up to the parent of the last block to execute.
        let mut block_headers_bytes = Vec::new();

        let first_blockhash_opcode_number = blockhash_opcode_references.keys().min();
        let first_needed_block_hash = first_blockhash_opcode_number
            .and_then(|n| {
                (*n < block.header.number.saturating_sub(1))
                    .then(|| blockhash_opcode_references.get(n))?
                    .copied()
            })
            .unwrap_or(block.header.parent_hash);

        let mut current_header = block.header.clone();

        // Headers from latest - 1 until we reach first block header we need.
        // We do it this way because we want to fetch headers by hash, not by number
        while current_header.hash() != first_needed_block_hash {
            let parent_hash = current_header.parent_hash;
            let current_number = current_header.number - 1;

            current_header = self
                .storage
                .get_block_header_by_hash(parent_hash)?
                .ok_or_else(|| {
                    ChainError::WitnessGeneration(format!(
                        "Failed to get block {current_number} header"
                    ))
                })?;

            block_headers_bytes.push(current_header.encode_to_vec());
        }

        // Get initial state trie root and embed the rest of the trie into it
        let nodes: BTreeMap<H256, Node> = used_trie_nodes
            .into_iter()
            .map(|node| {
                (
                    node.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                    node,
                )
            })
            .collect();
        let state_trie_root = if let NodeRef::Node(state_trie_root, _) =
            Trie::get_embedded_root(&nodes, initial_state_root)?
        {
            Some((*state_trie_root).clone())
        } else {
            None
        };

        // Get all initial storage trie roots and embed the rest of the trie into it
        let state_trie = if let Some(state_trie_root) = &state_trie_root {
            Trie::new_temp_with_root(state_trie_root.clone().into())
        } else {
            Trie::new_temp()
        };
        let mut storage_trie_roots = BTreeMap::new();
        for address in touched_account_storage_slots.keys() {
            let hashed_address = hash_address(address);
            let hashed_address_h256 = H256::from_slice(&hashed_address);
            let Some(encoded_account) = state_trie.get(&hashed_address)? else {
                continue; // empty account, doesn't have a storage trie
            };
            let storage_root_hash = AccountState::decode(&encoded_account)?.storage_root;
            if storage_root_hash == *EMPTY_TRIE_HASH {
                continue; // empty storage trie
            }
            if !nodes.contains_key(&storage_root_hash) {
                continue; // storage trie isn't relevant to this execution
            }
            let node = Trie::get_embedded_root(&nodes, storage_root_hash)?;
            let NodeRef::Node(node, _) = node else {
                return Err(ChainError::Custom(
                    "execution witness does not contain non-empty storage trie".to_string(),
                ));
            };
            storage_trie_roots.insert(hashed_address_h256, (*node).clone());
        }

        Ok(ExecutionWitness {
            codes,
            block_headers_bytes,
            first_block_number: parent_header.number,
            chain_config: self.storage.get_chain_config(),
            state_trie_root,
            storage_trie_roots,
        })
    }

    #[instrument(
        level = "trace",
        name = "Block DB update",
        skip_all,
        fields(namespace = "block_execution")
    )]
    pub fn store_block(
        &self,
        block: Block,
        account_updates_list: AccountUpdatesList,
        execution_result: BlockExecutionResult,
    ) -> Result<(), ChainError> {
        // Live path: commit by the canonical safe-commit gate (see `commit_depth`).
        self.store_block_with_depth(block, account_updates_list, execution_result, None)
    }

    /// Like [`Self::store_block`] but with an explicit trie-layer commit strategy.
    ///
    /// `commit_depth`:
    /// - `None`: live block-by-block execution (`newPayload`); commit by the canonical
    ///   `head - DB_COMMIT_THRESHOLD` safe-commit root so non-canonical state is never persisted.
    /// - `Some(depth)`: single-canonical-chain execution (batch import, full sync, startup
    ///   state regeneration); commit every layer deeper than `depth`, bounding in-memory layers.
    pub fn store_block_with_depth(
        &self,
        block: Block,
        account_updates_list: AccountUpdatesList,
        execution_result: BlockExecutionResult,
        commit_depth: Option<usize>,
    ) -> Result<(), ChainError> {
        // Check state root matches the one in block header
        validate_state_root(&block.header, account_updates_list.state_trie_hash)?;

        let update_batch = UpdateBatch {
            account_updates: account_updates_list.state_updates,
            storage_updates: account_updates_list.storage_updates,
            receipts: vec![(block.hash(), execution_result.receipts)],
            blocks: vec![block],
            code_updates: account_updates_list.code_updates,
            commit_depth,
            // Per-block path: ack after staging so the next block's execution overlaps this
            // block's flush. Memory is bounded by `commit_depth` and the persist channel.
            wait_for_flush: false,
        };

        self.storage
            .store_block_updates(update_batch)
            .map_err(|e| e.into())
    }

    pub fn add_block(&self, block: Block) -> Result<(), ChainError> {
        let since = Instant::now();
        let (res, updates) = self.execute_block(&block)?;
        let executed = Instant::now();

        // Apply the account updates over the last block's state and compute the new state root
        let account_updates_list = self
            .storage
            .apply_account_updates_batch(block.header.parent_hash, &updates)?
            .ok_or(ChainError::ParentStateNotFound)?;

        let (gas_used, gas_limit, block_number, transactions_count) = (
            block.header.gas_used,
            block.header.gas_limit,
            block.header.number,
            block.body.transactions.len(),
        );

        let merkleized = Instant::now();
        let result = self.store_block(block, account_updates_list, res);
        let stored = Instant::now();

        if self.options.perf_logs_enabled {
            Self::print_add_block_logs(
                gas_used,
                gas_limit,
                block_number,
                transactions_count,
                since,
                executed,
                merkleized,
                stored,
            );
        }
        result
    }

    pub fn add_block_pipeline(
        &self,
        block: Block,
        bal: Option<Arc<BlockAccessList>>,
    ) -> Result<(), ChainError> {
        let (_, _, result) = self.add_block_pipeline_inner(block, bal, false, None)?;
        result
    }

    /// Same as [`add_block_pipeline`] but for single-canonical-chain re-execution
    /// (startup state regeneration, full-sync block-by-block, block import): commits
    /// trie layers by depth (`commit_depth`) instead of the canonical safe-commit gate,
    /// bounding in-memory layers to ~`commit_depth`. Only sound because these paths extend
    /// a single canonical chain with no competing forks. Must NOT be used for live
    /// `newPayload`. Returns the BAL produced during execution (see
    /// [`add_block_pipeline_bal`]).
    pub fn add_block_pipeline_bounded(
        &self,
        block: Block,
        bal: Option<Arc<BlockAccessList>>,
        commit_depth: usize,
    ) -> Result<Option<BlockAccessList>, ChainError> {
        let (produced_bal, _, result) =
            self.add_block_pipeline_inner(block, bal, false, Some(commit_depth))?;
        result?;
        Ok(produced_bal)
    }

    /// Same as [`add_block_pipeline`] but also returns the BAL produced during execution.
    /// A BAL only exists from Amsterdam onward. On the parallel validation path the BAL
    /// comes from the header and drives execution rather than being rebuilt, so the
    /// returned value is `None`; the sequential path (block production or
    /// `--no-bal-parallel-exec`) rebuilds it and returns `Some(bal)`. Pre-Amsterdam blocks
    /// never record a BAL, so the returned value is always `None`.
    pub fn add_block_pipeline_bal(
        &self,
        block: Block,
        bal: Option<Arc<BlockAccessList>>,
    ) -> Result<Option<BlockAccessList>, ChainError> {
        let (produced_bal, _, result) = self.add_block_pipeline_inner(block, bal, false, None)?;
        result?;
        Ok(produced_bal)
    }

    /// Same as [`add_block_pipeline`] but returns the execution witness produced
    /// while importing the block.
    pub fn add_block_pipeline_with_witness(
        &self,
        block: Block,
        bal: Option<Arc<BlockAccessList>>,
    ) -> Result<ExecutionWitness, ChainError> {
        let (_, witness, result) = self.add_block_pipeline_inner(block, bal, true, None)?;
        result?;
        witness.ok_or_else(|| {
            ChainError::WitnessGeneration(
                "forced witness collection completed without producing a witness".to_string(),
            )
        })
    }

    /// Runs the full block pipeline (execute + merkleize + store).
    ///
    /// Returns a two-level Result:
    /// - Outer `Err`: pipeline couldn't start (e.g. parent header not found).
    /// - Inner `Result`: block storage outcome. The produced BAL is returned
    ///   even when storage fails, so callers like `add_block_pipeline_bal` can
    ///   retrieve it. Note: if *execution* itself fails (outer `Result`), the
    ///   BAL is not available.
    fn add_block_pipeline_inner(
        &self,
        block: Block,
        bal: Option<Arc<BlockAccessList>>,
        force_witness: bool,
        commit_depth: Option<usize>,
    ) -> Result<AddBlockPipelineInnerResult, ChainError> {
        // Validate if it can be the new head and find the parent
        let Ok(parent_header) = find_parent_header(&block.header, &self.storage) else {
            // If the parent is not present, we store it as pending.
            self.storage.add_pending_block(block)?;
            return Err(ChainError::ParentNotFound);
        };

        let should_store_witness = self.options.precompute_witnesses && self.is_synced();
        let collect_witness = should_store_witness || force_witness;

        let (mut vm, logger) = if collect_witness {
            // If witness pre-generation is enabled, we wrap the db with a logger
            // to track state access (block hashes, storage keys, codes) during execution
            // avoiding the need to re-execute the block later.
            let vm_db: DynVmDatabase = Box::new(StoreVmDatabase::new(
                self.storage.clone(),
                parent_header.clone(),
            )?);

            let logger = Arc::new(DatabaseLogger::new(Arc::new(vm_db)));

            let mut vm = match self.options.r#type.clone() {
                BlockchainType::L1 => {
                    Evm::new_from_db_for_l1(logger.clone(), Arc::new(NativeCrypto))
                }
                BlockchainType::L2(l2_config) => Evm::new_from_db_for_l2(
                    logger.clone(),
                    *l2_config.fee_config.read().map_err(|_| {
                        EvmError::Custom("Fee config lock was poisoned".to_string())
                    })?,
                    Arc::new(NativeCrypto),
                ),
            };
            attach_stateless_validator(&mut vm);
            (vm, Some(logger))
        } else {
            let vm_db = StoreVmDatabase::new(self.storage.clone(), parent_header.clone())?;
            let vm = self.new_evm(vm_db)?;
            (vm, None)
        };

        // Keep a copy of the input BAL Arc for the post-execution BAL store call below.
        // `execute_block_pipeline` takes ownership; this clone is a cheap pointer bump.
        let input_bal = bal.clone();
        let (
            res,
            account_updates_list,
            accumulated_updates,
            produced_bal,
            merkle_queue_length,
            instants,
            warmer_duration,
        ) = { self.execute_block_pipeline(&block, &parent_header, &mut vm, bal, collect_witness)? };

        let (gas_used, gas_limit, block_number, transactions_count) = (
            block.header.gas_used,
            block.header.gas_limit,
            block.header.number,
            block.body.transactions.len(),
        );
        let block_hash = block.hash();

        let mut witness = None;
        if let Some(logger) = logger
            && let Some(account_updates) = accumulated_updates
        {
            let block_hash = block.hash();
            let generated_witness = self.generate_witness_from_account_updates(
                account_updates,
                &block,
                parent_header,
                &logger,
            )?;
            match (should_store_witness, force_witness) {
                (true, true) => {
                    witness = Some(generated_witness.clone());
                    self.storage
                        .store_witness(block_hash, block_number, generated_witness)?;
                }
                (true, false) => {
                    self.storage
                        .store_witness(block_hash, block_number, generated_witness)?;
                }
                (false, true) => {
                    witness = Some(generated_witness);
                }
                (false, false) => {}
            }
        };

        // Store the block's BAL so peers can request it later without re-execution.
        // On the parallel Amsterdam validation path the BAL is supplied via the header
        // and `produced_bal` is None, so fall back to the validated incoming `bal`.
        // Pre-Amsterdam blocks have no BAL on either source, so nothing is stored.
        if let Some(bal) = produced_bal.as_ref().or(input_bal.as_deref())
            && let Err(err) = self.storage.store_block_access_list(block_hash, bal)
        {
            warn!("Failed to store block access list for block {block_hash}: {err}");
        }

        let result = self.store_block_with_depth(block, account_updates_list, res, commit_depth);

        let stored = Instant::now();

        let instants = std::array::from_fn(move |i| {
            if i < instants.len() {
                instants[i]
            } else {
                stored
            }
        });

        if self.options.perf_logs_enabled {
            Self::print_add_block_pipeline_logs(
                gas_used,
                gas_limit,
                block_number,
                block_hash,
                transactions_count,
                merkle_queue_length,
                warmer_duration,
                instants,
            );
        }

        metrics!(
            if let Some(bal_ref) = produced_bal.as_ref().or(input_bal.as_deref()) {
                let account_count = bal_ref.accounts().len() as u64;
                let slot_count = bal_ref.item_count().saturating_sub(account_count);
                let size_bytes = bal_ref.length() as f64;
                METRICS_BAL.blocks_total.inc();
                METRICS_BAL.size_bytes.set(size_bytes);
                METRICS_BAL.size_bytes_histogram.observe(size_bytes);
                METRICS_BAL.account_count.set(account_count as i64);
                METRICS_BAL.slot_count.set(slot_count as i64);
            }
        );

        Ok((produced_bal, witness, result))
    }

    #[allow(clippy::too_many_arguments)]
    fn print_add_block_logs(
        gas_used: u64,
        gas_limit: u64,
        block_number: u64,
        transactions_count: usize,
        since: Instant,
        executed: Instant,
        merkleized: Instant,
        stored: Instant,
    ) {
        let interval = stored.duration_since(since).as_millis() as f64;
        if interval != 0f64 {
            let as_gigas = gas_used as f64 / 10_f64.powf(9_f64);
            let throughput = as_gigas / interval * 1000_f64;

            metrics!(
                METRICS_BLOCKS.set_block_number(block_number);
                METRICS_BLOCKS.set_latest_gas_used(gas_used as f64);
                METRICS_BLOCKS.set_latest_block_gas_limit(gas_limit as f64);
                METRICS_BLOCKS.set_latest_gigagas(throughput);
                METRICS_BLOCKS.set_execution_ms(executed.duration_since(since).as_secs_f64() * 1000.0);
                METRICS_BLOCKS.set_merkle_ms(merkleized.duration_since(executed).as_secs_f64() * 1000.0);
                METRICS_BLOCKS.set_store_ms(stored.duration_since(merkleized).as_secs_f64() * 1000.0);
                METRICS_BLOCKS.set_transaction_count(transactions_count as i64);
            );

            let base_log = format!(
                "[METRIC] BLOCK EXECUTION THROUGHPUT ({}): {:.3} Ggas/s TIME SPENT: {:.0} ms. Gas Used: {:.3} ({:.0}%), #Txs: {}.",
                block_number,
                throughput,
                interval,
                as_gigas,
                (gas_used as f64 / gas_limit as f64) * 100.0,
                transactions_count
            );

            fn percentage(init: Instant, end: Instant, total: f64) -> f64 {
                (end.duration_since(init).as_millis() as f64 / total * 100.0).round()
            }
            let extra_log = if as_gigas > 0.0 {
                format!(
                    " exec: {}% merkle: {}% store: {}%",
                    percentage(since, executed, interval),
                    percentage(executed, merkleized, interval),
                    percentage(merkleized, stored, interval)
                )
            } else {
                "".to_string()
            };
            info!("{}{}", base_log, extra_log);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn print_add_block_pipeline_logs(
        gas_used: u64,
        gas_limit: u64,
        block_number: u64,
        block_hash: H256,
        transactions_count: usize,
        merkle_queue_length: usize,
        warmer_duration: Duration,
        [
            start_instant,
            block_validated_instant,
            exec_merkle_start,
            merkle_start_instant,
            exec_end_instant,
            merkle_end_instant,
            exec_merkle_end_instant,
            stored_instant,
        ]: [Instant; 8],
    ) {
        let total_ms = stored_instant.duration_since(start_instant).as_secs_f64() * 1000.0;
        if total_ms == 0.0 {
            return;
        }

        let as_mgas = gas_used as f64 / 1e6;
        let throughput = (gas_used as f64 / 1e9) / (total_ms / 1000.0);

        // Calculate phase durations in ms
        let validate_ms = block_validated_instant
            .duration_since(start_instant)
            .as_secs_f64()
            * 1000.0;
        let exec_ms = exec_end_instant
            .duration_since(exec_merkle_start)
            .as_secs_f64()
            * 1000.0;
        let store_ms = stored_instant
            .duration_since(exec_merkle_end_instant)
            .as_secs_f64()
            * 1000.0;
        let warmer_ms = warmer_duration.as_secs_f64() * 1000.0;

        // Calculate merkle breakdown
        // merkle_end_instant marks when merkle thread finished (may be before or after exec)
        // exec_merkle_end_instant marks when both exec and merkle are done
        let _merkle_total_ms = exec_merkle_end_instant
            .duration_since(exec_merkle_start)
            .as_secs_f64()
            * 1000.0;

        // Concurrent merkle time: the portion of merkle that ran while exec was running
        let merkle_concurrent_ms = (merkle_end_instant
            .duration_since(exec_merkle_start)
            .as_secs_f64()
            * 1000.0)
            .min(exec_ms);

        // Drain time: time spent finishing merkle after exec completed
        let merkle_drain_ms = exec_merkle_end_instant
            .saturating_duration_since(exec_end_instant)
            .as_secs_f64()
            * 1000.0;

        // Overlap percentage: how much of merkle work was done concurrently
        let actual_merkle_ms = merkle_concurrent_ms + merkle_drain_ms;
        let overlap_pct = if actual_merkle_ms > 0.0 {
            (merkle_concurrent_ms / actual_merkle_ms) * 100.0
        } else {
            0.0
        };

        // Calculate warmer effectiveness (positive = finished early)
        let warmer_early_ms = exec_ms - warmer_ms;

        // Determine bottleneck (effective time for each phase)
        // For merkle, only count the drain time (concurrent time overlaps with exec)
        let phases = [
            ("validate", validate_ms),
            ("exec", exec_ms),
            ("merkle", merkle_drain_ms),
            ("store", store_ms),
        ];
        let bottleneck = phases
            .iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(name, _)| *name)
            .unwrap_or("exec");

        // Helper for percentage
        let pct = |ms: f64| (ms / total_ms * 100.0).round() as u64;

        // Format output
        let header = format!(
            "[METRIC] BLOCK {} {:#x} | {:.3} Ggas/s | {:.2} ms | {} txs | {:.0} Mgas ({}%)",
            block_number,
            block_hash,
            throughput,
            total_ms,
            transactions_count,
            as_mgas,
            (gas_used as f64 / gas_limit as f64 * 100.0).round() as u64
        );

        let bottleneck_marker = |name: &str| {
            if name == bottleneck {
                " << BOTTLENECK"
            } else {
                ""
            }
        };

        let warmer_relation = if warmer_early_ms >= 0.0 {
            "before exec"
        } else {
            "after exec"
        };

        let merkle_start_delay_ms = merkle_start_instant
            .duration_since(exec_merkle_start)
            .as_secs_f64()
            * 1000.0;

        info!("{}", header);
        info!(
            "  |- validate: {:>7.2} ms  ({:>2}%){}",
            validate_ms,
            pct(validate_ms),
            bottleneck_marker("validate")
        );
        info!(
            "  |- exec:     {:>7.2} ms  ({:>2}%){}",
            exec_ms,
            pct(exec_ms),
            bottleneck_marker("exec")
        );
        info!(
            "  |- merkle:   {:>7.2} ms  ({:>2}%){}  [concurrent: {:.2} ms, drain: {:.2} ms, overlap: {:.0}%, queue: {}, start_delay: {:.2} ms]",
            merkle_drain_ms,
            pct(merkle_drain_ms),
            bottleneck_marker("merkle"),
            merkle_concurrent_ms,
            merkle_drain_ms,
            overlap_pct,
            merkle_queue_length,
            merkle_start_delay_ms,
        );
        info!(
            "  |- store:    {:>7.2} ms  ({:>2}%){}",
            store_ms,
            pct(store_ms),
            bottleneck_marker("store")
        );
        info!(
            "  `- warmer:   {:>7.2} ms         [finished: {:.2} ms {}]",
            warmer_ms,
            warmer_early_ms.abs(),
            warmer_relation,
        );

        // Set prometheus metrics
        metrics!(
            METRICS_BLOCKS.set_block_number(block_number);
            METRICS_BLOCKS.set_latest_gas_used(gas_used as f64);
            METRICS_BLOCKS.set_latest_block_gas_limit(gas_limit as f64);
            METRICS_BLOCKS.set_latest_gigagas(throughput);
            METRICS_BLOCKS.set_transaction_count(transactions_count as i64);
            METRICS_BLOCKS.set_validate_ms(validate_ms);
            METRICS_BLOCKS.set_execution_ms(exec_ms);
            METRICS_BLOCKS.set_merkle_concurrent_ms(merkle_concurrent_ms);
            METRICS_BLOCKS.set_merkle_drain_ms(merkle_drain_ms);
            METRICS_BLOCKS.set_merkle_ms(_merkle_total_ms);
            METRICS_BLOCKS.set_merkle_overlap_pct(overlap_pct);
            METRICS_BLOCKS.set_store_ms(store_ms);
            METRICS_BLOCKS.set_warmer_ms(warmer_ms);
            METRICS_BLOCKS.set_warmer_early_ms(warmer_early_ms);
        );
    }

    /// Adds multiple consecutive blocks in a batch during full sync.
    ///
    /// Each block is routed through the same per-block-validated pipeline that live blocks use
    /// (via [`add_block_pipeline_bounded`], the depth-gated entry point) instead of the bespoke
    /// "execute all, apply once, validate only the last state root" path. This:
    ///
    /// - closes the intermediate-state-root gap (every block's state root is validated),
    /// - reuses the pipeline's BAL-driven parallel execution + precompile cache and its per-block
    ///   BAL persistence for eth/71 serving, and
    /// - deletes the duplicated `execute_block_from_state`, manual VM/BLOCKHASH cache, and
    ///   peer-BAL-persistence code.
    ///
    /// This trades the single-trie-materialization amortization (one root for the whole batch) for
    /// per-block roots; trie layers commit by depth (`DB_COMMIT_THRESHOLD`) so the in-memory layer
    /// backlog stays bounded during bulk sync.
    ///
    /// If an error occurs, returns a tuple containing:
    /// - The error type ([`ChainError`]).
    /// - [`BatchBlockProcessingFailure`] (if the error was caused by block processing), carrying
    ///   the failed block hash and the last successfully-imported block hash.
    ///
    /// `bals` holds the per-block Block Access Lists fetched during sync, aligned by index with
    /// `blocks`. Pass an empty slice when no BALs are available (e.g. block import from RLP); the
    /// pipeline then rebuilds each BAL. Only a BAL matching its block's header commitment is used.
    pub async fn add_blocks_in_batch(
        &self,
        blocks: Vec<Block>,
        bals: &[Option<BlockAccessList>],
        cancellation_token: CancellationToken,
    ) -> Result<(), (ChainError, Option<BatchBlockProcessingFailure>)> {
        debug_assert!(
            bals.is_empty() || bals.len() == blocks.len(),
            "bals must be empty or aligned with blocks (bals={}, blocks={})",
            bals.len(),
            blocks.len(),
        );

        let mut last_valid_hash = H256::default();
        let blocks_len = blocks.len();
        let mut total_gas_used = 0u64;
        let mut transactions_count = 0usize;
        let mut last_block_number = 0u64;
        let mut last_block_gas_limit = 0u64;
        let interval = Instant::now();

        for (i, block) in blocks.into_iter().enumerate() {
            if cancellation_token.is_cancelled() {
                info!("Received shutdown signal, aborting");
                return Err((ChainError::Custom(String::from("shutdown signal")), None));
            }

            let block_hash = block.hash();
            let block_number = block.header.number;
            let block_gas_limit = block.header.gas_limit;
            let block_gas_used = block.header.gas_used;
            let block_tx_count = block.body.transactions.len();

            // Pass the peer-provided BAL only if it matches the header commitment: on the pipeline
            // path a matching BAL drives parallel execution and is persisted for eth/71 serving.
            // A missing/mismatched BAL yields `None`, and the pipeline rebuilds it.
            let bal = bals
                .get(i)
                .and_then(|bal| bal.as_ref())
                .filter(|bal| {
                    bal.matches_commitment(block.header.block_access_list_hash, &NativeCrypto)
                })
                .cloned()
                .map(Arc::new);

            // Single canonical chain: commit trie layers by depth so the in-memory backlog
            // stays bounded (~DB_COMMIT_THRESHOLD) instead of growing with the sync range.
            // The now per-block granularity is why this uses DB_COMMIT_THRESHOLD (128), not
            // the batch-layer threshold.
            if let Err(err) = self.add_block_pipeline_bounded(block, bal, DB_COMMIT_THRESHOLD) {
                return Err((
                    err,
                    Some(BatchBlockProcessingFailure {
                        failed_block_hash: block_hash,
                        last_valid_hash,
                    }),
                ));
            }

            last_valid_hash = block_hash;
            last_block_number = block_number;
            last_block_gas_limit = block_gas_limit;
            total_gas_used += block_gas_used;
            transactions_count += block_tx_count;

            log_batch_progress(blocks_len as u32, i as u32);
            tokio::task::yield_now().await;
        }

        let elapsed_seconds = interval.elapsed().as_secs_f64();
        let throughput = if elapsed_seconds > 0.0 && total_gas_used != 0 {
            (total_gas_used as f64 / 1e9) / elapsed_seconds
        } else {
            0.0
        };

        metrics!(
            METRICS_BLOCKS.set_block_number(last_block_number);
            METRICS_BLOCKS.set_latest_block_gas_limit(last_block_gas_limit as f64);
            METRICS_BLOCKS.set_latest_gas_used(if blocks_len > 0 {
                total_gas_used as f64 / blocks_len as f64
            } else {
                0.0
            });
            METRICS_BLOCKS.set_latest_gigagas(throughput);
        );

        if self.options.perf_logs_enabled {
            info!(
                "[METRICS] Executed and stored (unified pipeline): Range: {}, Last block num: {}, Last block gas limit: {}, Total transactions: {}, Total Gas: {}, Throughput: {} Gigagas/s",
                blocks_len,
                last_block_number,
                last_block_gas_limit,
                transactions_count,
                total_gas_used,
                throughput
            );
        }

        Ok(())
    }

    /// Add a blob transaction and its blobs bundle to the mempool checking that the transaction is valid.
    ///
    /// This is the P2P entry point: the transaction's hash is queued for
    /// broadcast to peers regardless of `BlockchainOptions::private_mempool`.
    /// For the local-RPC path that honors `private_mempool`, use
    /// [`Self::add_local_blob_transaction_to_pool`].
    #[cfg(feature = "c-kzg")]
    pub async fn add_blob_transaction_to_pool(
        &self,
        transaction: EIP4844Transaction,
        blobs_bundle: BlobsBundle,
    ) -> Result<H256, MempoolError> {
        self.add_blob_transaction_to_pool_inner(transaction, blobs_bundle, true)
            .await
    }

    /// Local-RPC counterpart of [`Self::add_blob_transaction_to_pool`].
    /// When `BlockchainOptions::private_mempool` is `true`, the transaction
    /// is added to the mempool but is NOT queued for P2P broadcast — it
    /// stays available only for blocks built locally.
    #[cfg(feature = "c-kzg")]
    pub async fn add_local_blob_transaction_to_pool(
        &self,
        transaction: EIP4844Transaction,
        blobs_bundle: BlobsBundle,
    ) -> Result<H256, MempoolError> {
        let broadcast = !self.options.private_mempool;
        self.add_blob_transaction_to_pool_inner(transaction, blobs_bundle, broadcast)
            .await
    }

    #[cfg(feature = "c-kzg")]
    async fn add_blob_transaction_to_pool_inner(
        &self,
        transaction: EIP4844Transaction,
        blobs_bundle: BlobsBundle,
        broadcast: bool,
    ) -> Result<H256, MempoolError> {
        let fork = self.current_fork()?;

        let transaction = Transaction::EIP4844Transaction(transaction);
        let hash = transaction.hash(&NativeCrypto);
        if self.mempool.contains_tx(hash)? {
            if !broadcast {
                warn!(%hash, "tx already public; --mempool.private cannot retroactively un-broadcast");
            }
            return Ok(hash);
        }

        // Wire-wrapper size cap for blob txs. Matches geth `txMaxSize = 1 MiB`
        // (blobpool) and nethermind `MaxBlobTxSize`, which both bound the
        // wire-wrapper form including the sidecar. ethrex stores the core tx
        // and the bundle in separate structs, so sum the two encoded sizes
        // (the ±few bytes of outer list framing are rounding error at this
        // scale).
        let wrapper_len = transaction.encode_canonical_len() + blobs_bundle.length();
        if wrapper_len > MAX_BLOB_TX_SIZE {
            return Err(MempoolError::TxSizeExceeded {
                actual: wrapper_len,
                limit: MAX_BLOB_TX_SIZE,
            });
        }

        // Validate blobs bundle after checking if it's already added.
        if let Transaction::EIP4844Transaction(transaction) = &transaction {
            // eth/72 elided bundles carry commitments + cell proofs but no blobs;
            // full KZG verification is deferred until cells are fetched via GetCells.
            if blobs_bundle.blobs.is_empty() && !blobs_bundle.commitments.is_empty() {
                blobs_bundle.validate_elided(transaction, fork)?;
            } else {
                blobs_bundle.validate(transaction, fork)?;
            }
        }

        let sender = transaction.sender(&NativeCrypto)?;

        // Validate transaction. The returned `sender_admission` carries the
        // per-sender gate inputs, re-checked atomically inside `add_transaction`,
        // which also removes any same-nonce tx being replaced under the same lock
        // (#6938) — so no separate pre-removal here.
        let (frame_reservation, sender_admission) =
            self.validate_transaction(&transaction, sender).await?;

        // Add blobs bundle before the transaction so that when add_transaction
        // notifies payload builders the blob data is already available.
        self.mempool.add_blobs_bundle(hash, blobs_bundle)?;
        // If the tx insert fails after the bundle was stored, roll back the
        // orphaned bundle so it isn't leaked in the pool. Best-effort: keep the
        // original error (a failing insert means the write lock is poisoned or
        // eviction failed, in which case the cleanup can't do better anyway).
        let mempool_tx = MempoolTransaction::new(transaction, sender);
        let inserted = if broadcast {
            self.mempool.add_transaction(
                hash,
                sender,
                mempool_tx,
                frame_reservation,
                sender_admission,
            )
        } else {
            self.mempool.add_transaction_no_broadcast(
                hash,
                sender,
                mempool_tx,
                frame_reservation,
                sender_admission,
            )
        };
        if let Err(e) = inserted {
            let _ = self.mempool.remove_blobs_bundle(&hash);
            return Err(e);
        }
        Ok(hash)
    }

    /// Add a transaction to the mempool checking that the transaction is valid.
    ///
    /// This is the P2P entry point: the transaction's hash is queued for
    /// broadcast to peers regardless of `BlockchainOptions::private_mempool`.
    /// For the local-RPC path that honors `private_mempool`, use
    /// [`Self::add_local_transaction_to_pool`].
    pub async fn add_transaction_to_pool(
        &self,
        transaction: Transaction,
    ) -> Result<H256, MempoolError> {
        self.add_transaction_to_pool_inner(transaction, true).await
    }

    /// Equivalent of `add_transaction_to_pool` for transactions submitted via
    /// this node's local RPC. When `BlockchainOptions::private_mempool` is
    /// `true`, the transaction is added to the mempool but is NOT queued for
    /// P2P broadcast — it stays available only for blocks built locally.
    pub async fn add_local_transaction_to_pool(
        &self,
        transaction: Transaction,
    ) -> Result<H256, MempoolError> {
        let broadcast = !self.options.private_mempool;
        self.add_transaction_to_pool_inner(transaction, broadcast)
            .await
    }

    async fn add_transaction_to_pool_inner(
        &self,
        transaction: Transaction,
        broadcast: bool,
    ) -> Result<H256, MempoolError> {
        // Blob transactions should be submitted via add_blob_transaction along with the corresponding blobs bundle
        if matches!(transaction, Transaction::EIP4844Transaction(_)) {
            return Err(MempoolError::BlobTxNoBlobsBundle);
        }
        // Wire size cap: run before sender recovery so oversized txs don't
        // force secp256k1 work. Matches geth's `txMaxSize` admission order
        // (size-checked at `ValidateTransaction` entry, well before any
        // crypto). The same check sits in `validate_transaction` so direct
        // callers (tests, L2 paths) keep the guarantee.
        let encoded_len = transaction.encode_canonical_len();
        if encoded_len > MAX_TX_SIZE {
            return Err(MempoolError::TxSizeExceeded {
                actual: encoded_len,
                limit: MAX_TX_SIZE,
            });
        }
        let hash = transaction.hash(&NativeCrypto);
        if self.mempool.contains_tx(hash)? {
            if !broadcast {
                warn!(%hash, "tx already public; --mempool.private cannot retroactively un-broadcast");
            }
            return Ok(hash);
        }
        let sender = transaction.sender(&NativeCrypto)?;
        // Validate transaction. The returned `sender_admission` carries the
        // per-sender gate inputs, re-checked atomically inside `add_transaction`,
        // which also removes whatever occupies the sender's nonce slot (any tx
        // type) under the same lock, so replacement detection, the gates, the
        // removal, and the insert are one atomic scope (#6938). For a frame tx
        // the removal happens only after the locked paymaster re-check, so a
        // rejected fee-bump leaves the original pending tx intact.
        let (frame_reservation, sender_admission) =
            self.validate_transaction(&transaction, sender).await?;

        // Add transaction to storage
        let mempool_tx = MempoolTransaction::new(transaction, sender);
        if broadcast {
            self.mempool.add_transaction(
                hash,
                sender,
                mempool_tx,
                frame_reservation,
                sender_admission,
            )?;
        } else {
            self.mempool.add_transaction_no_broadcast(
                hash,
                sender,
                mempool_tx,
                frame_reservation,
                sender_admission,
            )?;
        }

        Ok(hash)
    }

    /// Remove a transaction from the mempool
    pub fn remove_transaction_from_pool(&self, hash: &H256) -> Result<(), StoreError> {
        self.mempool.remove_transaction(hash)
    }

    /// Remove all transactions in the executed block from the pool (if we have them)
    pub fn remove_block_transactions_from_pool(&self, block: &Block) -> Result<(), StoreError> {
        for tx in &block.body.transactions {
            self.mempool.remove_transaction(&tx.hash(&NativeCrypto))?;
        }
        Ok(())
    }

    /// Drop blob txs with nonce below the sender's on-chain nonce at `head_hash`.
    /// Per-block pruning only covers the head block, so stale blob txs from
    /// non-head canonical blocks leak in and are never evicted (value/nonce
    /// eviction pins low nonces). Resetting against on-chain nonces clears them.
    pub async fn remove_stale_blob_txs(&self, head_hash: BlockHash) -> Result<(), StoreError> {
        let blob_txs = self.mempool.blob_txs()?;
        if blob_txs.is_empty() {
            return Ok(());
        }
        // Cache on-chain nonce per sender to avoid repeated state reads.
        let mut nonce_by_sender: HashMap<Address, u64> = HashMap::new();
        for (hash, sender, tx_nonce) in blob_txs {
            let state_nonce = match nonce_by_sender.entry(sender) {
                Entry::Occupied(e) => *e.get(),
                Entry::Vacant(e) => {
                    let nonce = self
                        .storage
                        .get_account_info_by_hash(head_hash, sender)?
                        .map(|info| info.nonce)
                        .unwrap_or(0);
                    *e.insert(nonce)
                }
            };
            if tx_nonce < state_nonce {
                self.mempool.remove_transaction(&hash)?;
            }
        }
        Ok(())
    }

    /// Re-simulate pending frame transactions (EIP-8141) whose validity may have
    /// changed because of a newly canonical `block`, evicting any that no longer
    /// pass. A local peer policy: it never affects consensus or block-building.
    ///
    /// Included frame txs are already released by
    /// `remove_block_transactions_from_pool`, so this only revisits txs that are
    /// still pending. To bound the work, it builds the set of accounts the block
    /// could have mutated (every tx's sender and `Call` target, the block's
    /// coinbase, and every withdrawal recipient) and re-simulates a pending frame
    /// tx only when its sender, one of its touched sender storage slots' owning
    /// account (the sender, since SLOAD/SSTORE are sender-restricted), or its
    /// referenced paymaster falls in that set. When no frame tx is pending the
    /// whole pass is a no-op.
    ///
    /// Evictions go through the normal removal path
    /// (`remove_transaction_with_lock`), which cleans every reservation map.
    ///
    /// Reorg re-add of reservations for re-queued txs is OUT OF SCOPE: txs from a
    /// re-orged-out block are not re-admitted here, so their reservations are not
    /// reconstructed (ties to existing TODO #797). A subsequent re-submission
    /// re-runs full admission and re-reserves.
    pub fn revalidate_frame_txs_after_block(&self, block: &Block) -> Result<(), StoreError> {
        let pending = self.mempool.pending_frame_txs()?;
        // No-op when no frame tx is pending.
        if pending.is_empty() {
            return Ok(());
        }

        // Re-simulate every pending frame tx against the new head. We do NOT try
        // to narrow the set to "accounts the block touched": a pending tx's
        // sender storage can change via an internal CALL from an unrelated block
        // tx, so a candidate set derived from tx envelopes (senders, Call
        // targets) would miss those and under-evict. Frame txs are bounded to
        // ~one per sender, so an unconditional rescan is cheap, and the policy's
        // invariant (never under-reject) takes precedence over the optimization.
        //
        // TODO: when frame-tx volume warrants it, replace the unconditional
        // rescan with a sound per-tx input-check: snapshot each tx's validation
        // read-set at admission (sender account, touched sender storage slots
        // with values, paymaster account) and here re-read only those at the new
        // head, re-simulating just the txs whose inputs changed. This needs the
        // validation observer to record slot values (not only keys). The block's
        // AccountUpdates are not available at this FCU hook (they are produced
        // during a prior newPayload execution), so an AccountUpdates-derived set
        // is not an option here without new per-block persistence.
        //
        // The head to simulate against is the just-applied block (its header
        // carries the post-execution state root). Build the read-through state
        // view once for the whole pass; `new_evm` gives each tx its own mutable
        // cache, so the per-tx simulations stay isolated. If the head state can't
        // be opened we keep the simulation step disabled (None) but still apply
        // the expiry and structural drops below, which don't need state.
        let vm_db = match StoreVmDatabase::new(self.storage.clone(), block.header.clone()) {
            Ok(vm_db) => Some(vm_db),
            Err(err) => {
                warn!("Failed to build head-state VM for frame-tx revalidation: {err}");
                None
            }
        };

        for (hash, _sender, paymaster) in pending {
            let Some(mempool_tx) = self.mempool.get_mempool_transaction_by_hash(hash)? else {
                continue;
            };
            let tx = mempool_tx.transaction().clone();
            let Transaction::FrameTransaction(frame_tx) = &tx else {
                continue;
            };

            // Drop a tx whose expiry deadline is now behind the new head.
            if frame_tx
                .expiry_deadline()
                .is_some_and(|deadline| deadline < block.header.timestamp)
            {
                self.mempool.remove_transaction(&hash)?;
                continue;
            }

            // Re-derive the prefix and re-simulate against the new head state.
            let prefix = match frame_tx.validation_prefix() {
                Ok(prefix) => prefix,
                Err(_) => {
                    // Structurally invalid against the current rules: evict.
                    self.mempool.remove_transaction(&hash)?;
                    continue;
                }
            };

            // Without a head-state view we cannot re-simulate; keep the tx
            // (don't under-reject on a transient state-read failure). The
            // expiry and structural drops above already ran.
            let Some(vm_db) = &vm_db else {
                continue;
            };
            let evict = match self.new_evm(vm_db.clone()) {
                Ok(mut vm) => {
                    match vm.simulate_frame_validation_prefix(&tx, &block.header, &prefix, None) {
                        // Simulation passed for this tx in isolation. The
                        // per-tx validation prefix only catches a single-tx
                        // drain (its own APPROVE underflows). N txs sharing one
                        // paymaster each simulate against the full post-block
                        // balance, so collectively they can exceed it; we must
                        // also re-check the aggregate availability invariant
                        // that admission enforces. Per tx the needed condition
                        // is `balance - (reserved - this_cost) >= this_cost`,
                        // i.e. `balance >= reserved_pending_cost(paymaster)`.
                        // Because evicting a tx decrements
                        // `reserved_pending_cost` (single removal path), the
                        // pass converges to `reserved <= balance` per paymaster
                        // and never under-evicts. (All paymasters are
                        // non-canonical today (OQ1); the per-paymaster pending
                        // COUNT limit cannot be exceeded by a block, so only
                        // the balance/reserved aggregate needs re-checking.)
                        Ok(outcome) if outcome.passed => {
                            // Best-effort post-block balance read. A read error
                            // is treated as "keep the tx" (consistent with the
                            // transient-failure handling above); never panic,
                            // never fail the FCU.
                            let balance = match vm_db.get_account_state(paymaster) {
                                Ok(Some(state)) => state.balance,
                                Ok(None) => U256::zero(),
                                Err(_) => {
                                    // Keep the tx on a transient read failure.
                                    continue;
                                }
                            };
                            // `reserved_pending_cost` is read live, not from the
                            // snapshot: a tx admitted after the snapshot can raise
                            // it above `balance` and over-evict a snapshotted tx.
                            // That is benign for a best-effort mempool policy (the
                            // newcomer passed its own locked availability check).
                            balance < self.mempool.reserved_pending_cost(paymaster)?
                        }
                        // Simulation passed flag is false: evict.
                        Ok(_) => true,
                        // A simulation error means the prefix can no longer be
                        // validated against the new state: evict (conservative).
                        Err(_) => true,
                    }
                }
                Err(_) => true,
            };

            if evict {
                self.mempool.remove_transaction(&hash)?;
            }
        }

        Ok(())
    }

    /*

    SOME VALIDATIONS THAT WE COULD INCLUDE
    Stateless validations
    1. This transaction is valid on current mempool
        -> Depends on mempool transaction filtering logic
    2. Ensure the maxPriorityFeePerGas is high enough to cover the requirement of the calling pool (the minimum to be included in)
        -> Depends on mempool transaction filtering logic
    3. Transaction's encoded size is smaller than maximum allowed
        -> I think that this is not in the spec, but it may be a good idea
    4. Make sure the transaction is signed properly
    5. Ensure a Blob Transaction comes with its sidecar (Done! - All blob validations have been moved to `common/types/blobs_bundle.rs`):
      1. Validate number of BlobHashes is positive (Done!)
      2. Validate number of BlobHashes is less than the maximum allowed per block,
         which may be computed as `maxBlobGasPerBlock / blobTxBlobGasPerBlob`
      3. Ensure number of BlobHashes is equal to:
        - The number of blobs (Done!)
        - The number of commitments (Done!)
        - The number of proofs (Done!)
      4. Validate that the hashes matches with the commitments, performing a `kzg4844` hash. (Done!)
      5. Verify the blob proofs with the `kzg4844` (Done!)
    Stateful validations
    1. Ensure transaction nonce is higher than the `from` address stored nonce
    2. Certain pools do not allow for nonce gaps. Ensure a gap is not produced (that is, the transaction nonce is exactly the following of the stored one)
    3. Ensure the transactor has enough funds to cover transaction cost:
        - Transaction cost is calculated as `(gas * gasPrice) + (blobGas * blobGasPrice) + value`
    4. In case of transaction reorg, ensure the transactor has enough funds to cover for transaction replacements without overdrafts.
    - This is done by comparing the total spent gas of the transactor from all pooled transactions, and accounting for the necessary gas spenditure if any of those transactions is replaced.
    5. Ensure the transactor is able to add a new transaction. The number of transactions sent by an account may be limited by a certain configured value

    */
    /// Returns the paymaster reservation to apply on insert for frame
    /// transactions (EIP-8141), plus the per-sender admission guard re-checked
    /// atomically inside `add_transaction`. The reservation is computed here but
    /// applied in the locked section of `add_transaction`, so a frame tx that
    /// fails any later admission check never leaks a reservation. Any same-nonce
    /// tx being replaced is detected and removed live under that write lock, so
    /// its hash is not returned here.
    pub async fn validate_transaction(
        &self,
        tx: &Transaction,
        sender: Address,
    ) -> Result<(Option<FramePaymasterReservation>, Option<SenderAdmission>), MempoolError> {
        let nonce = tx.nonce();

        // On an L1 node, reject L2-only transaction types (FeeToken 0x7d,
        // PrivilegedL2 0x7e). They are valid only on L2; admitting them to an L1
        // pool diverges from other L1 clients. The block-import path rejects them
        // via the same `is_l2_only()` guard (#6752); this is the mempool-ingress
        // side. Gated on L1 so the shared admission path still serves L2.
        if matches!(self.options.r#type, BlockchainType::L1) && tx.tx_type().is_l2_only() {
            return Err(MempoolError::L2OnlyTransactionType);
        }

        if matches!(tx, &Transaction::PrivilegedL2Transaction(_)) {
            return Ok((None, None));
        }

        // Frame transactions: skip balance/EOA checks (payer unknown until execution)
        let is_frame_tx = matches!(tx, Transaction::FrameTransaction(_));

        let header_no = self.storage.get_latest_block_number()?;
        let header = self
            .storage
            .get_block_header(header_no)?
            .ok_or(MempoolError::NoBlockHeaderError)?;
        let config = self.storage.get_chain_config();

        // EIP-8141 fork gating: reject frame transactions before Hegota activates.
        // Prevents FrameTransaction (type 0x06) from entering the mempool or being
        // forwarded over P2P on chains where EIP-8141 has not yet activated.
        if is_frame_tx && !config.is_hegota_activated(header.timestamp) {
            return Err(MempoolError::FrameTxPreFork);
        }

        // EIP-8141 expiry: drop frame txs whose expiry
        // verifier deadline is already behind the current head timestamp.
        // Boundary: deadline == timestamp is still valid (the verifier only
        // reverts when block.timestamp > deadline).
        if let Transaction::FrameTransaction(frame_tx) = tx
            && frame_tx
                .expiry_deadline()
                .is_some_and(|deadline| deadline < header.timestamp)
        {
            return Err(MempoolError::FrameTxExpired);
        }

        // Paymaster reservation to apply on insert (EIP-8141). Computed below for
        // frame txs after simulation + availability pass; `None` for every other
        // tx type and threaded to the locked insert in `add_transaction`.
        let mut frame_reservation: Option<FramePaymasterReservation> = None;

        if let Transaction::FrameTransaction(frame_tx) = tx {
            // EIP-8141 static constraints at admission (mirrors the VM check)
            // so malformed frame txs never occupy pool slots.
            frame_tx
                .validate_static_constraints()
                .map_err(MempoolError::InvalidFrameTransaction)?;

            // Interim policy: no sidecar transport exists for frame-tx blobs
            // yet, so a blob-carrying frame tx could never be included with data
            // availability. Reject at admission (local policy). Block IMPORT does
            // account for frame blobs (verify_blob_gas_usage counts them), but the
            // BUILD path does not yet add them to header.blob_gas_used — so this
            // admission gate is also what keeps the builder from ever producing
            // such a block. If this gate is lifted, the builder must route frame
            // blobs through blob accounting first (see payload.rs apply_transaction).
            if !frame_tx.blob_versioned_hashes.is_empty() {
                return Err(MempoolError::FrameTxBlobsUnsupported);
            }

            // Frame `data` size is bounded by the wire-size cap below
            // (MAX_TX_SIZE over encode_canonical_len), which covers the
            // frames' payloads since they are part of the canonical encoding.

            // EIP-8141 §Mempool (rule #6): signature validation counts against
            // MAX_VERIFY_GAS. Reject before any per-signature crypto runs when the
            // signature-verification cost alone exceeds the budget — such a tx can
            // never satisfy the validation-prefix gas limit, and this bounds the
            // crypto work done by validate_frame_signatures below. (The full
            // validation-prefix simulation runs below over a throwaway head-state
            // VM and is the authoritative gas-budget check.)
            if frame_tx.signature_verification_cost()
                > ethrex_common::types::FRAME_TX_MAX_VERIFY_GAS
            {
                return Err(MempoolError::FrameTxVerifyGasExceeded);
            }

            // Authenticate the signature list BEFORE admission: without this the
            // unauthenticated `sender` field lets fabricated senders flood the
            // pool for free (no balance is charged at admission).
            let sig_hash = frame_tx.compute_sig_hash();
            if !ethrex_vm::validate_frame_signatures(
                &frame_tx.signatures,
                sig_hash,
                frame_tx.sender,
                config.fork(header.timestamp),
                &NativeCrypto,
            ) {
                return Err(MempoolError::InvalidFrameSignature);
            }

            // EIP-8141 §Mempool: validate the prefix shape and structural rules.
            // The full gas-budget check (prefix frame gas limits + sig cost ≤
            // MAX_VERIFY_GAS) is the authoritative superset of the cheap
            // sig-cost pre-filter above; both are kept for defence-in-depth.
            let prefix = frame_tx.validation_prefix().map_err(MempoolError::from)?;
            frame_tx
                .validate_prefix_structure(&prefix)
                .map_err(MempoolError::from)?;
        }

        // Wire size cap for non-blob txs: peer-policy default, not consensus.
        // Matches geth `txMaxSize` (legacypool), reth `DEFAULT_MAX_TX_INPUT_BYTES`,
        // nethermind `MaxTxSize`. Blob txs are bounded by their own
        // wire-wrapper cap (`MAX_BLOB_TX_SIZE`) in `add_blob_transaction_to_pool`,
        // which sums the core tx and the sidecar to match geth/nethermind/erigon
        // scope.
        if !matches!(tx, Transaction::EIP4844Transaction(_)) {
            let encoded_len = tx.encode_canonical_len();
            if encoded_len > MAX_TX_SIZE {
                return Err(MempoolError::TxSizeExceeded {
                    actual: encoded_len,
                    limit: MAX_TX_SIZE,
                });
            }
        }

        // Check init code size
        // [EIP-7954] - Amsterdam increases the limit
        let max_initcode_size = if config.is_amsterdam_activated(header.timestamp) {
            AMSTERDAM_MAX_INITCODE_SIZE
        } else {
            MAX_INITCODE_SIZE
        };
        if config.is_shanghai_activated(header.timestamp)
            && tx.is_contract_creation()
            && tx.data().len() > max_initcode_size as usize
        {
            return Err(MempoolError::TxMaxInitCodeSizeError);
        }

        if config.is_osaka_activated(header.timestamp)
            && !config.is_amsterdam_activated(header.timestamp)
            && tx.gas_limit() > POST_OSAKA_GAS_LIMIT_CAP
        {
            // https://eips.ethereum.org/EIPS/eip-7825
            return Err(MempoolError::TxMaxGasLimitExceededError(
                tx.hash(&NativeCrypto),
                tx.gas_limit(),
            ));
        }

        // Check gas limit is less than header's gas limit
        if header.gas_limit < tx.gas_limit() {
            return Err(MempoolError::TxGasLimitExceededError);
        }

        // Check priority fee is less or equal than gas fee gap
        if tx.max_priority_fee().unwrap_or(0) > tx.max_fee_per_gas().unwrap_or(0) {
            return Err(MempoolError::TxTipAboveFeeCapError);
        }

        // Admission-time minimum tip floor. Compares the raw tip cap
        // (`max_priority_fee_per_gas` for typed txs, `gas_price` for legacy)
        // against `min_tip_wei`, matching geth's `PriceLimit` check on
        // `tx.GasTipCap()` and reth's check on `max_priority_fee_per_gas`.
        // Using the raw tip cap keeps the admission decision independent of
        // the current base fee, so a tx that paid the floor at admission
        // doesn't get reclassified as under-floor when base fee oscillates.
        // A floor of 0 disables the check.
        if self.options.min_tip_wei > 0 {
            // Saturate to u64::MAX on overflow: a U256 tip cap above u64::MAX
            // wei is astronomically larger than any sane floor, so clamping
            // (and therefore admitting) is the correct direction here. Do not
            // reuse this pattern where truncation would flip a comparison.
            let tip_cap = u64::try_from(tx.gas_tip_cap()).unwrap_or(u64::MAX);
            if tip_cap < self.options.min_tip_wei {
                return Err(MempoolError::TipBelowMinimum {
                    actual: tip_cap,
                    limit: self.options.min_tip_wei,
                });
            }
        }

        // EIP-7702 type-4 structural validation, mirroring LEVM's
        // `validate_type_4_tx` and ordered before the gas checks so the returned
        // error names the structural fault, not a downstream gas symptom. Reject
        // at admission so invalid type-4 txs never enter the pool.
        if let Transaction::EIP7702Transaction(eip7702) = tx {
            // Type-4 txs only exist from Prague onward.
            if !config.is_prague_activated(header.timestamp) {
                return Err(MempoolError::Eip7702TxPreFork);
            }
            // An empty authorization_list makes the tx invalid.
            if eip7702.authorization_list.is_empty() {
                return Err(MempoolError::EmptyAuthorizationList);
            }
        }

        // Check that the gas limit covers the gas needs for transaction metadata.
        if tx.gas_limit() < mempool::transaction_intrinsic_gas(tx, sender, &header, &config)? {
            return Err(MempoolError::TxIntrinsicGasCostAboveLimitError);
        }

        // Check that the specified blob gas fee is above the minimum value
        if let Some(fee) = tx.max_fee_per_blob_gas() {
            // Blob tx fee checks
            if fee < MIN_BASE_FEE_PER_BLOB_GAS.into() {
                return Err(MempoolError::TxBlobBaseFeeTooLowError);
            }
        };

        // Compute the new tx's cost once and reuse for both the single-tx
        // balance check and the cumulative-balance check below.
        let tx_cost = tx
            .cost_without_base_fee()
            .ok_or(MempoolError::InvalidTxGasvalues)?;

        let maybe_sender_acc_info = self.storage.get_account_info(header_no, sender).await?;
        // Sender's on-chain nonce, used for three things below: (1) folded into
        // the `SenderAdmission` guard so the per-account queued cap, gapped-nonce,
        // and cumulative-balance gates are re-checked *atomically* under the
        // insertion write lock (see `SenderAdmission`) rather than only via the
        // racy pre-filters here; (2) telling executable txs from future ones; and
        // (3) excluding obsoleted (already-mined but not-yet-pruned) txs from the
        // cumulative-balance sum.
        let sender_account_nonce = maybe_sender_acc_info.as_ref().map(|info| info.nonce);

        let sender_balance = if let Some(sender_acc_info) = maybe_sender_acc_info {
            if nonce < sender_acc_info.nonce || nonce == u64::MAX {
                return Err(MempoolError::NonceTooLow);
            }

            // EIP-3607: reject txs from senders with deployed code, unless
            // the code is an EIP-7702 delegation designation (the account is
            // still an EOA in spirit, just pointing at delegate code).
            //
            // Frame transactions are exempt: EIP-8141 ("Transaction
            // origination") explicitly does NOT apply the EIP-3607 restriction
            // to them, since a frame tx's `SENDER` frame legitimately
            // originates calls where `tx.sender` is a contract account.
            //
            // Length-based fast path: any code whose length isn't exactly
            // `EIP7702_DELEGATED_CODE_LEN` (23) cannot be a delegation, so
            // we reject without loading the bytecode. Only when the metadata
            // length matches do we fetch + verify the prefix. This avoids
            // pulling potentially large contract bytecode on every contract
            // sender that hits admission.
            if !is_frame_tx && sender_acc_info.code_hash != *EMPTY_KECCAK_HASH {
                let metadata_len = self
                    .storage
                    .get_code_metadata(sender_acc_info.code_hash)?
                    .map(|m| m.length);
                let is_delegation = if metadata_len == Some(EIP7702_DELEGATED_CODE_LEN as u64) {
                    // Metadata says the code is delegation-shaped; if the
                    // bytecode is then missing from the store, the DB is
                    // inconsistent — surface that as `StoreError` instead of
                    // silently treating the sender as a contract (which would
                    // wrongly reject a valid 7702-delegated EOA).
                    let code = self
                        .storage
                        .get_account_code(sender_acc_info.code_hash)?
                        .ok_or_else(|| {
                            StoreError::Custom(format!(
                                "code missing for hash {:?} despite present metadata",
                                sender_acc_info.code_hash
                            ))
                        })?;
                    is_eip7702_delegation(code.code())
                } else {
                    false
                };
                if !is_delegation {
                    return Err(MempoolError::SenderIsContract);
                }
            }

            // Skip the balance check for frame txs (payer unknown until execution).
            if !is_frame_tx && tx_cost > sender_acc_info.balance {
                return Err(MempoolError::NotEnoughBalance);
            }

            sender_acc_info.balance
        } else if !is_frame_tx {
            // An account that is not in the database cannot possibly have enough balance to cover the transaction cost
            return Err(MempoolError::NotEnoughBalance);
        } else {
            // Frame tx from a not-yet-existent sender. This is legitimate for
            // sponsored transactions, where a separate funded payer covers gas,
            // so we cannot reject on balance. The account's implied nonce is 0
            // (EIP-8141: `tx.nonce == state[tx.sender].nonce`), so apply the same
            // nonce sanity guard as the existing-account path instead of skipping
            // nonce validation entirely. `nonce < 0` is impossible for a u64, so
            // only the u64::MAX sentinel is rejectable here; a fresh sender's
            // nonce-0 tx still passes.
            if nonce == u64::MAX {
                return Err(MempoolError::NonceTooLow);
            }
            // Frame txs skip the cumulative balance check below, so this
            // sentinel is never read; it only satisfies the block's type.
            U256::zero()
        };

        // On-chain nonce for the gap-admission check below (0 for a
        // not-yet-existent sender, matching the implied EIP-8141 nonce).
        let sender_acc_nonce = sender_account_nonce.unwrap_or(0);

        // Check the nonce of pendings TXs in the mempool from the same sender
        // If it exists check if the new tx has higher fees
        let tx_to_replace_hash = self.mempool.find_tx_to_replace(
            sender,
            nonce,
            tx,
            self.options.price_bump_percent,
            self.options.blob_price_bump_percent,
        )?;

        // Cumulative balance check across this sender's pending transactions.
        // Without this, a sender at the per-sender slot cap can have only one
        // of their N pending txs be fundable, with the other N-1 being
        // guaranteed-fail spam wasting pool space.
        //
        // `sum_cost_for_sender` recomputes the sender total excluding the
        // tx being replaced (instead of subtracting after the fact) so a
        // `None`-cost or missing tx can't silently zero the total via
        // `MAX - MAX = 0`. It also fails closed on any inconsistency so the
        // gate can't be bypassed by an invariant violation. Obsoleted txs
        // (nonce below the sender's on-chain nonce — already mined but not yet
        // pruned) are excluded so they don't inflate the required balance.
        //
        // Skipped for frame txs: their payer is unknown until execution, so
        // (matching the single-tx balance check above) they are not gated on
        // the sender's balance.
        if !is_frame_tx {
            let existing_cost = self.mempool.sum_cost_for_sender(
                sender,
                sender_account_nonce.unwrap_or(0),
                tx_to_replace_hash,
            )?;
            let total = existing_cost
                .checked_add(tx_cost)
                .ok_or(MempoolError::InvalidTxGasvalues)?;
            if total > sender_balance {
                return Err(MempoolError::InsufficientCumulativeBalance {
                    required: total,
                    available: sender_balance,
                });
            }
        }

        if tx
            .chain_id()
            .is_some_and(|chain_id| chain_id != config.chain_id)
        {
            return Err(MempoolError::InvalidChainId(config.chain_id));
        }

        // When the mempool is heavily occupied, reject incoming transactions
        // whose nonce is not contiguous with the sender's on-chain nonce. This
        // prevents a flood of gapped-nonce spam txs from pinning pool budget
        // that productive txs could use. Replacements (same nonce as a tx
        // already in the pool) bypass this rule since they are not gapped.
        //
        // Read occupancy once and reuse it for both the gate check and the
        // error message — taking the read lock twice (a separate check plus a
        // re-read for the message) would allow TOCTOU drift where the reported
        // occupancy differs from the value the gate fired on.
        let threshold = self.options.gap_admit_occupancy_threshold;
        if tx_to_replace_hash.is_none() && nonce != sender_acc_nonce && threshold < 100 {
            let occupancy_pct = self.mempool.occupancy_pct()?;
            if occupancy_pct >= threshold {
                let nonce_gap = nonce.saturating_sub(sender_acc_nonce);
                return Err(MempoolError::GapAdmissionDeniedUnderPressure {
                    occupancy_pct,
                    nonce_gap,
                });
            }
        }

        // EIP-8141 §Mempool: run the validation-trace simulation + paymaster
        // availability accounting LAST, after the cheap stateless and nonce/fee
        // checks have passed, so a malformed nonce / fee / size never pays for an
        // EVM simulation.
        if let Transaction::FrameTransaction(frame_tx) = tx {
            // Re-derive the (pure) prefix; structural validity was already
            // checked above, so this cannot fail here.
            let prefix = frame_tx.validation_prefix().map_err(MempoolError::from)?;

            // Run the validation-trace simulation over a FRESH, throwaway
            // `StoreVmDatabase` at the canonical head (the same state source the
            // payload builder uses). This is a local peer policy: it never
            // touches consensus or block-building, may over-reject, and must
            // never under-reject. The observer enforces the ERC-7562-style trace
            // rules; the outcome reports whether the prefix established a payer
            // within the verify-gas budget and which sender slots / paymaster it
            // touched.
            let vm_db = StoreVmDatabase::new(self.storage.clone(), header.clone())
                .map_err(|err| MempoolError::FrameTxValidationFailed(err.to_string()))?;
            let mut vm = self
                .new_evm(vm_db)
                .map_err(|err| MempoolError::FrameTxValidationFailed(err.to_string()))?;
            // OQ1: no canonical paymaster bytecode is resolvable, so no canonical
            // code hash is passed (the canonical-pay-frame exemption never fires).
            let outcome = vm
                .simulate_frame_validation_prefix(tx, &header, &prefix, None)
                .map_err(|err| MempoolError::FrameTxValidationFailed(err.to_string()))?;
            if !outcome.passed {
                return Err(MempoolError::FrameTxValidationFailed(
                    outcome
                        .violation
                        .unwrap_or_else(|| "validation prefix did not pass".to_string()),
                ));
            }

            // Paymaster availability accounting (EIP-8141). The simulation
            // identified the payer (paymaster) and whether its code matched the
            // canonical paymaster hash (always false today, OQ1). Reserve an upper
            // bound on the tx's cost against the paymaster's head balance, summed
            // with all other pending reservations for that paymaster so
            // concurrently pending sponsored txs cannot collectively overdraw it.
            let max_cost = outcome.reservation_ceiling;
            if let Some((paymaster, code_is_canonical)) = outcome.accessed_paymaster {
                // OQ1: re-derive the canonical flag from the paymaster's head
                // code so the (currently always-false) determination lives in
                // one place. The storage read is skipped entirely until the
                // canonical bytecode hash is pinned upstream (the sentinel),
                // since `is_canonical_paymaster` can only return false until then.
                let is_canonical = if FRAME_CANONICAL_PAYMASTER_CODE_HASH == H256::zero() {
                    code_is_canonical
                } else {
                    let paymaster_code = self
                        .storage
                        .get_code_by_account_address(header_no, paymaster)
                        .await?
                        .map(|code| code.code_bytes())
                        .unwrap_or_default();
                    code_is_canonical || is_canonical_paymaster(&paymaster_code)
                };

                let paymaster_balance = self
                    .storage
                    .get_account_info(header_no, paymaster)
                    .await?
                    .map(|info| info.balance)
                    .unwrap_or_else(U256::zero);
                let reserved = self.mempool.reserved_pending_cost(paymaster)?;

                // Fee-bump exemption: a same-nonce replacement removes the old tx
                // (releasing its reservation and noncanonical slot) before the new
                // one is inserted. This UNLOCKED pre-filter still counts the old
                // tx's reservation, so it would falsely reject the bump on both
                // availability and the per-paymaster limit. Skip the whole
                // pre-filter for replacements; the locked re-check in
                // `add_transaction` runs AFTER the old tx is removed and is the
                // authoritative guard. The pre-filter only avoids running the EVM
                // simulation's downstream work for clearly-rejectable fresh txs.
                let is_fee_bump_replacement = tx_to_replace_hash.is_some();
                if !is_fee_bump_replacement {
                    if is_canonical {
                        // Canonical paymaster: balance minus reservations minus the
                        // pending withdrawal amount (OQ3: ethrex has no paymaster
                        // withdrawal queue, so the withdrawal amount is treated as
                        // 0) must cover the max cost.
                        let withdrawal_amount = U256::zero();
                        let available = paymaster_balance
                            .saturating_sub(reserved)
                            .saturating_sub(withdrawal_amount);
                        if available < max_cost {
                            return Err(MempoolError::FrameTxPaymasterUnderfunded);
                        }
                    } else {
                        // Non-canonical paymaster: balance minus reservations must
                        // cover the max cost, AND at most
                        // FRAME_TX_MAX_PENDING_NONCANONICAL_PAYMASTER pending txs
                        // may be sponsored by this paymaster.
                        let available = paymaster_balance.saturating_sub(reserved);
                        if available < max_cost {
                            return Err(MempoolError::FrameTxPaymasterUnderfunded);
                        }
                        if self.mempool.noncanonical_paymaster_pending(paymaster)?
                            >= ethrex_common::types::FRAME_TX_MAX_PENDING_NONCANONICAL_PAYMASTER
                        {
                            return Err(MempoolError::FrameTxNonCanonicalPaymasterLimit);
                        }
                    }
                }

                // Defer the increment to `add_transaction`, which re-checks
                // availability + the non-canonical limit under the write lock
                // (this unlocked check is a pre-filter). A tx failing any later
                // admission check must not leak a reservation.
                frame_reservation = Some(FramePaymasterReservation {
                    paymaster,
                    reserved_cost: max_cost,
                    is_canonical,
                    paymaster_balance,
                });
            }
        }

        // Build the per-sender admission guard so `add_transaction` can re-run
        // the queued-cap (#6603), gapped-nonce (#6609), and cumulative-balance
        // (#6606) gates atomically under the insertion write lock — the checks
        // above are an unlocked pre-filter (issue #6938). `None` when the sender
        // has no account (only frame txs reach here in that case, and they are
        // not per-sender rate-limited on nonce/balance).
        let sender_admission = sender_account_nonce.map(|account_nonce| SenderAdmission {
            account_nonce,
            queued_max: self.options.max_queued_txs_per_account,
            gap_threshold: self.options.gap_admit_occupancy_threshold,
            // Frame txs are not balance-gated (payer unknown until execution).
            balance_check: (!is_frame_tx).then_some(BalanceCheck {
                tx_cost,
                sender_balance,
            }),
        });

        Ok((frame_reservation, sender_admission))
    }

    /// Marks the node's chain as up to date with the current chain
    /// Once the initial sync has taken place, the node will be considered as sync
    pub fn set_synced(&self) {
        self.is_synced.store(true, Ordering::Relaxed);
    }

    /// Marks the node's chain as not up to date with the current chain.
    /// This will be used when the node is one batch or more behind the current chain.
    pub fn set_not_synced(&self) {
        self.is_synced.store(false, Ordering::Relaxed);
    }

    /// Returns whether the node's chain is up to date with the current chain
    /// This will be true if the initial sync has already taken place and does not reflect whether there is an ongoing sync process
    /// The node should accept incoming p2p transactions if this method returns true
    pub fn is_synced(&self) -> bool {
        self.is_synced.load(Ordering::Relaxed)
    }

    pub fn get_p2p_transaction_by_hash(&self, hash: &H256) -> Result<P2PTransaction, StoreError> {
        // --mempool.private: never serve private txs over P2P, even if a peer
        // somehow learned the hash. The spec for `GetPooledTransactions`
        // explicitly allows skipping unavailable transactions, so we mirror
        // the "not found" path the caller already handles.
        if self.mempool.is_private(*hash)? {
            return Err(StoreError::Custom(format!(
                "Hash {hash} is private and must not propagate",
            )));
        }
        let Some(tx) = self.mempool.get_transaction_by_hash(*hash)? else {
            return Err(StoreError::Custom(format!(
                "Hash {hash} not found in the mempool",
            )));
        };
        let result = match tx {
            Transaction::LegacyTransaction(itx) => P2PTransaction::LegacyTransaction(itx),
            Transaction::EIP2930Transaction(itx) => P2PTransaction::EIP2930Transaction(itx),
            Transaction::EIP1559Transaction(itx) => P2PTransaction::EIP1559Transaction(itx),
            Transaction::EIP4844Transaction(itx) => {
                let Some(bundle) = self.mempool.get_blobs_bundle(*hash)? else {
                    return Err(StoreError::Custom(format!(
                        "Blob transaction present without its bundle: hash {hash}",
                    )));
                };

                P2PTransaction::EIP4844TransactionWithBlobs(WrappedEIP4844Transaction {
                    tx: itx,
                    wrapper_version: (bundle.version != 0).then_some(bundle.version),
                    blobs_bundle: bundle,
                })
            }
            Transaction::EIP7702Transaction(itx) => P2PTransaction::EIP7702Transaction(itx),
            // Exclude privileged transactions as they are only created
            // by the lead sequencer. In the future, they might get gossiped
            // like the rest.
            Transaction::PrivilegedL2Transaction(_) => {
                return Err(StoreError::Custom(
                    "Privileged Transactions are not supported in P2P".to_string(),
                ));
            }
            Transaction::FeeTokenTransaction(itx) => P2PTransaction::FeeTokenTransaction(itx),
            // Frame transactions (EIP-8141) have no blobs bundle, so no bundle
            // lookup is needed; they are served on request like other typed txs.
            Transaction::FrameTransaction(itx) => P2PTransaction::FrameTransaction(itx),
        };

        Ok(result)
    }

    pub fn new_evm<D: VmDatabase + 'static>(&self, vm_db: D) -> Result<Evm, EvmError> {
        new_evm(&self.options.r#type, vm_db)
    }

    /// The [`VMType`] this chain executes with. Exposed so the RPC layer can answer
    /// fork-and-VM-dependent questions — whether an address is a precompile, say — without
    /// having to build an [`Evm`] first.
    pub fn vm_type(&self) -> Result<VMType, EvmError> {
        vm_type_for(&self.options.r#type)
    }

    /// [`Blockchain::new_evm`] for the RPC simulation paths that honor geth's State
    /// Override Set (`eth_call`, `eth_estimateGas`, `eth_createAccessList`,
    /// `debug_traceCall`).
    ///
    /// A State Override Set has two independent effects and they must be installed
    /// together: the per-account overlay ([`OverlaidVmDatabase`]) and the
    /// `movePrecompileToAddress` relocations, which live in the EVM rather than the
    /// database because they change dispatch, not state. This constructor is the only
    /// way to build the overlay, so the relocations can't be forgotten at a call site.
    ///
    /// `base_block_number` is the number of the real header the call is made against;
    /// see [`OverlaidVmDatabase::new`].
    pub fn new_overlaid_evm<D: VmDatabase + Clone + 'static>(
        &self,
        inner: D,
        overrides: Arc<BTreeMap<Address, StateOverride>>,
        base_block_number: BlockNumber,
    ) -> Result<Evm, EvmError> {
        let moves = precompile_moves(&overrides);
        let mut evm = self.new_evm(OverlaidVmDatabase::new(inner, overrides, base_block_number))?;
        evm.set_precompile_moves(moves);
        Ok(evm)
    }

    /// Get the current fork of the chain, based on the latest block's timestamp
    pub fn current_fork(&self) -> Result<Fork, StoreError> {
        let chain_config = self.storage.get_chain_config();
        let latest_block_number = self.storage.get_latest_block_number()?;
        let latest_block = self
            .storage
            .get_block_header(latest_block_number)?
            .ok_or(StoreError::Custom("Latest block not in DB".to_string()))?;
        Ok(chain_config.fork(latest_block.timestamp))
    }
}

/// Open a state trie or storage trie depending on whether `prefix` is given.
fn load_trie(
    storage: &Store,
    parent_state_root: H256,
    prefix: Option<H256>,
) -> Result<Trie, StoreError> {
    Ok(match prefix {
        Some(account_hash) => {
            let state_trie = storage.open_state_trie(parent_state_root)?;
            let storage_root = match state_trie.get(account_hash.as_bytes())? {
                Some(rlp) => AccountState::decode(&rlp)?.storage_root,
                None => *EMPTY_TRIE_HASH,
            };
            storage.open_storage_trie(account_hash, parent_state_root, storage_root)?
        }
        None => storage.open_state_trie(parent_state_root)?,
    })
}

/// Collapse a root branch node into an extension or leaf if it has only one valid child.
/// Returns `None` if there are no valid children.
fn collapse_root_node(
    storage: &Store,
    parent_state_root: H256,
    prefix: Option<H256>,
    root: BranchNode,
) -> Result<Option<Node>, StoreError> {
    let children: Vec<(usize, &NodeRef)> = root
        .choices
        .iter()
        .enumerate()
        .filter(|(_, choice)| choice.is_valid())
        .take(2)
        .collect();
    if children.len() > 1 {
        return Ok(Some(Node::Branch(Box::from(root))));
    }
    let Some((choice, only_child)) = children.first() else {
        return Ok(None);
    };
    let only_child = Arc::unwrap_or_clone(match only_child {
        NodeRef::Node(node, _) => node.clone(),
        noderef @ NodeRef::Hash(_) => {
            let trie = load_trie(storage, parent_state_root, prefix)?;
            let Some(node) = noderef.get_node(trie.db(), Nibbles::from_hex(vec![*choice as u8]))?
            else {
                return Ok(None);
            };
            node
        }
    });
    Ok(Some(match only_child {
        Node::Branch(_) => {
            ExtensionNode::new(Nibbles::from_hex(vec![*choice as u8]), only_child.into()).into()
        }
        Node::Extension(mut extension_node) => {
            extension_node.prefix.prepend(*choice as u8);
            extension_node.into()
        }
        Node::Leaf(mut leaf) => {
            leaf.partial.prepend(*choice as u8);
            leaf.into()
        }
    }))
}

/// Collect the state trie shard, merge pre-collected nodes, and send results.
fn collect_and_send(
    index: u8,
    state_trie: &mut Trie,
    pre_collected_state: &mut Vec<TrieNode>,
    storage_nodes: &mut Vec<(H256, Vec<TrieNode>)>,
    tx: Sender<CollectedStateMsg>,
) -> Result<(), StoreError> {
    let (subroot, mut state_nodes) = collect_trie(index, std::mem::take(state_trie))?;
    if !pre_collected_state.is_empty() {
        let mut pre = std::mem::take(pre_collected_state);
        pre.extend(state_nodes);
        state_nodes = pre;
    }
    tx.send(CollectedStateMsg {
        index,
        subroot,
        state_nodes,
        storage_nodes: std::mem::take(storage_nodes),
    })
    .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
    Ok(())
}

/// Open or get an existing storage trie for the given account prefix.
fn get_or_open_storage_trie<'a>(
    storage_tries: &'a mut FxHashMap<H256, Trie>,
    storage: &Store,
    parent_state_root: H256,
    prefix: H256,
    storage_root: H256,
) -> Result<&'a mut Trie, StoreError> {
    match storage_tries.entry(prefix) {
        Entry::Occupied(e) => Ok(e.into_mut()),
        Entry::Vacant(e) => {
            Ok(e.insert(storage.open_storage_trie(prefix, parent_state_root, storage_root)?))
        }
    }
}

/// Flush one storage trie's buffered slots (streaming merkleizer path). Opens the
/// trie if needed, breadth-first prefetches the touched nodes in one batch when
/// the slice clears the threshold, then applies the inserts/removes. Warming-only:
/// `prefetch_sorted` installs decoded nodes hash-preservingly, so the resulting
/// storage root is byte-identical to the per-slot path.
fn flush_storage_buffer(
    storage_tries: &mut FxHashMap<H256, Trie>,
    storage: &Store,
    parent_state_root: H256,
    prefix: H256,
    storage_root: H256,
    mut slots: Vec<(H256, U256)>,
) -> Result<(), StoreError> {
    let trie = get_or_open_storage_trie(
        storage_tries,
        storage,
        parent_state_root,
        prefix,
        storage_root,
    )?;
    // `prefetch_sorted` requires ascending paths; slots arrive in routing order.
    // H256 sorts bytewise, matching nibble order, so sorting by key gives the
    // order `Nibbles::from_bytes` needs. The sort MUST be stable: the streaming
    // path buffers per-tx updates, so the same slot can appear more than once
    // (written by successive txs in the block) and the last write must win, as it
    // does in the per-slot insert path. A stable sort keeps equal keys in arrival
    // (tx) order so the final insert below applies the latest value last. Use
    // `sort_by` (stable), NOT `sort_unstable_by`, or duplicate slots regress.
    if slots.len() >= STREAM_STORAGE_PREFETCH_THRESHOLD {
        slots.sort_by(|a, b| a.0.cmp(&b.0));
        let paths: Vec<Nibbles> = slots
            .iter()
            .map(|(k, _)| Nibbles::from_bytes(k.as_bytes()))
            .collect();
        trie.prefetch_sorted(&paths)?;
    }
    for (hashed_key, value) in slots {
        if value.is_zero() {
            trie.remove(hashed_key.as_bytes())?;
        } else {
            trie.insert(hashed_key.as_bytes().to_vec(), value.encode_to_vec())?;
        }
    }
    Ok(())
}

fn handle_subtrie(
    storage: Store,
    rx: cb::Receiver<WorkerRequest>,
    parent_state_root: H256,
    index: u8,
    worker_senders: Vec<cb::Sender<WorkerRequest>>,
    shutdown_rx: cb::Receiver<()>,
) -> Result<(), StoreError> {
    let mut state_trie = storage.open_state_trie(parent_state_root)?;
    let mut storage_nodes: Vec<(H256, Vec<TrieNode>)> = vec![];
    let mut accounts: FxHashMap<H256, AccountState> = Default::default();
    let mut expected_shards: FxHashMap<H256, u16> = Default::default();
    let mut storage_state: FxHashMap<H256, PreMerkelizedAccountState> = Default::default();
    let mut received_shards: FxHashMap<H256, u16> = Default::default();
    let mut pending_storage_accounts: usize = 0;
    let mut pending_collect_tx: Option<Sender<CollectedStateMsg>> = None;
    let mut pre_collected_state: Vec<TrieNode> = vec![];
    let mut storage_tries: FxHashMap<H256, Trie> = Default::default();
    let mut pre_collected_storage: FxHashMap<H256, Vec<TrieNode>> = Default::default();
    // Per storage trie, slots buffered until they can be flushed as a prefetched
    // batch (see `flush_storage_buffer`). Value is (storage_root, pending slots).
    // Cleared on delete; fully drained before storage collection begins.
    let mut storage_buffer: FxHashMap<H256, (H256, Vec<(H256, U256)>)> = Default::default();

    // Held until collection finishes to keep cross-worker channels open.
    let mut worker_senders: Option<Vec<cb::Sender<WorkerRequest>>> = Some(worker_senders);
    let mut dirty = false;
    // When active, we finalize one storage trie per loop iteration,
    // interleaving with incoming StorageShard messages.
    let mut collecting_storages = false;
    let mut routing_complete = false;
    let mut routing_done_mask: u16 = 0;
    let mut storage_to_collect: Vec<(H256, Trie)> = vec![];

    loop {
        // When collecting storages, finalize one trie per iteration so that
        // incoming StorageShard messages can be processed in between.
        if collecting_storages {
            if let Some((prefix, trie)) = storage_to_collect.pop() {
                let senders = worker_senders
                    .as_ref()
                    .expect("collecting after senders dropped");
                let (root, mut nodes) = collect_trie(index, trie)?;
                if let Some(mut pre_nodes) = pre_collected_storage.remove(&prefix) {
                    pre_nodes.extend(nodes);
                    nodes = pre_nodes;
                }
                let bucket = prefix.as_fixed_bytes()[0] >> 4;
                senders[bucket as usize]
                    .send(WorkerRequest::StorageShard {
                        prefix,
                        index,
                        subroot: root,
                        nodes,
                    })
                    .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
            } else {
                // All storage tries finalized
                worker_senders = None;
                collecting_storages = false;
                // Check if deferred collect can resolve now
                if pending_storage_accounts == 0
                    && let Some(tx) = pending_collect_tx.take()
                {
                    collect_and_send(
                        index,
                        &mut state_trie,
                        &mut pre_collected_state,
                        &mut storage_nodes,
                        tx,
                    )?;
                    break;
                }
            }
        }

        // When collecting or dirty, poll non-blocking so we can interleave.
        // When clean and not collecting, just block.
        let msg = if collecting_storages || dirty {
            match rx.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {
                    // Check for shutdown signal from watcher
                    if matches!(shutdown_rx.try_recv(), Err(TryRecvError::Disconnected)) {
                        return Err(StoreError::Custom("shard worker shutdown".into()));
                    }
                    if dirty {
                        // Pre-collect state trie — safe during storage
                        // collection too, since StorageShard resolution only
                        // dirties specific paths that get re-committed later.
                        let mut nodes = state_trie.commit_without_storing(&NativeCrypto);
                        nodes.retain(|(nib, _)| nib.as_ref().first() == Some(&index));
                        pre_collected_state.extend(nodes);
                        if !collecting_storages {
                            // Pre-collect storage tries (only when not draining)
                            for (prefix, trie) in storage_tries.iter_mut() {
                                let mut nodes = trie.commit_without_storing(&NativeCrypto);
                                nodes.retain(|(nib, _)| nib.as_ref().first() == Some(&index));
                                if !nodes.is_empty() {
                                    pre_collected_storage
                                        .entry(*prefix)
                                        .or_default()
                                        .extend(nodes);
                                }
                            }
                        }
                        dirty = false;
                    }
                    continue;
                }
            }
        } else {
            select! {
                recv(rx) -> msg => match msg {
                    Ok(msg) => msg,
                    Err(_) => break,
                },
                recv(shutdown_rx) -> _ => {
                    return Err(StoreError::Custom("shard worker shutdown".into()));
                }
            }
        };

        match msg {
            WorkerRequest::ProcessAccount {
                prefix,
                info,
                storage: account_storage,
                removed,
                removed_storage,
            } => {
                let senders = worker_senders
                    .as_ref()
                    .expect("ProcessAccount after collection started");

                // Always load account to warm state trie during execution overlap
                match accounts.entry(prefix) {
                    Entry::Occupied(_) => {}
                    Entry::Vacant(vacant_entry) => {
                        let account_state = match state_trie.get(prefix.as_bytes())? {
                            Some(rlp) => {
                                let state = AccountState::decode(&rlp)?;
                                state_trie.insert(prefix.as_bytes().to_vec(), rlp)?;
                                state
                            }
                            None => AccountState::default(),
                        };
                        vacant_entry.insert(account_state);
                    }
                }

                // Apply info immediately and insert into trie
                if let Some(info) = info {
                    let acct = accounts.get_mut(&prefix).expect("just loaded");
                    acct.nonce = info.nonce;
                    acct.balance = info.balance;
                    acct.code_hash = info.code_hash;
                    let path = prefix.as_bytes();
                    if *acct != AccountState::default() {
                        state_trie.insert(path.to_vec(), acct.encode_to_vec())?;
                    } else {
                        state_trie.remove(path)?;
                    }
                }

                if removed || removed_storage {
                    // Delete locally + send DeleteStorage to other 15 workers.
                    // Drop any slots buffered for this trie: the reset wipes them,
                    // exactly as the per-slot path's inserts would have been.
                    pre_collected_storage.remove(&prefix);
                    storage_buffer.remove(&prefix);
                    storage_tries.insert(prefix, Trie::new_temp());
                    for (i, tx) in senders.iter().enumerate() {
                        if i as u8 != index {
                            tx.send(WorkerRequest::DeleteStorage(prefix))
                                .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
                        }
                    }
                    accounts.get_mut(&prefix).expect("just loaded").storage_root = *EMPTY_TRIE_HASH;
                    if expected_shards.insert(prefix, 0xFFFF).is_none() {
                        pending_storage_accounts += 1;
                    }
                    if removed {
                        dirty = true;
                        continue;
                    }
                }

                if !account_storage.is_empty() {
                    let storage_root = accounts
                        .get(&prefix)
                        .map(|a| a.storage_root)
                        .unwrap_or(*EMPTY_TRIE_HASH);

                    let is_new = !expected_shards.contains_key(&prefix);
                    for (key, value) in account_storage {
                        let hashed_key = keccak(key);
                        let bucket = hashed_key.as_fixed_bytes()[0] >> 4;
                        *expected_shards.entry(prefix).or_insert(0u16) |= 1 << bucket;
                        if bucket == index {
                            // Local storage: buffer for a prefetched batch flush.
                            let buf = storage_buffer
                                .entry(prefix)
                                .or_insert_with(|| (storage_root, Vec::new()));
                            buf.1.push((hashed_key, value));
                            if buf.1.len() >= STREAM_STORAGE_FLUSH_BATCH {
                                let (root, slots) = storage_buffer
                                    .remove(&prefix)
                                    .expect("buffer just inserted");
                                flush_storage_buffer(
                                    &mut storage_tries,
                                    &storage,
                                    parent_state_root,
                                    prefix,
                                    root,
                                    slots,
                                )?;
                            }
                        } else {
                            senders[bucket as usize]
                                .send(WorkerRequest::MerklizeStorage {
                                    prefix,
                                    key: hashed_key,
                                    value,
                                    storage_root,
                                })
                                .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
                        }
                    }
                    if is_new {
                        pending_storage_accounts += 1;
                    }
                }
                dirty = true;
            }
            WorkerRequest::MerklizeStorage {
                prefix,
                key,
                value,
                storage_root,
            } => {
                // Buffer for a prefetched batch flush (see local-storage path).
                let buf = storage_buffer
                    .entry(prefix)
                    .or_insert_with(|| (storage_root, Vec::new()));
                buf.1.push((key, value));
                if buf.1.len() >= STREAM_STORAGE_FLUSH_BATCH {
                    let (root, slots) = storage_buffer
                        .remove(&prefix)
                        .expect("buffer just inserted");
                    flush_storage_buffer(
                        &mut storage_tries,
                        &storage,
                        parent_state_root,
                        prefix,
                        root,
                        slots,
                    )?;
                }
                dirty = true;
            }
            WorkerRequest::DeleteStorage(prefix) => {
                // Reset wipes any buffered slots for this trie (see ProcessAccount).
                pre_collected_storage.remove(&prefix);
                storage_buffer.remove(&prefix);
                storage_tries.insert(prefix, Trie::new_temp());
                dirty = true;
            }
            WorkerRequest::FinishRouting => {
                // Signal all workers that we're done routing MerklizeStorage.
                let senders = worker_senders
                    .as_ref()
                    .expect("FinishRouting after senders dropped");
                for i in 0..16u8 {
                    senders[i as usize]
                        .send(WorkerRequest::RoutingDone { from: index })
                        .map_err(|e| StoreError::Custom(format!("send error: {e}")))?;
                }
            }
            WorkerRequest::RoutingDone { from } => {
                routing_done_mask |= 1u16 << from;
                if routing_done_mask == 0xFFFF && !collecting_storages && !routing_complete {
                    // Routing is done: no more slots will arrive, so flush every
                    // remaining buffer into its storage trie before draining for
                    // collection. Missing this would silently drop buffered slots.
                    for (prefix, (root, slots)) in storage_buffer.drain() {
                        flush_storage_buffer(
                            &mut storage_tries,
                            &storage,
                            parent_state_root,
                            prefix,
                            root,
                            slots,
                        )?;
                    }
                    collecting_storages = true;
                    routing_complete = true;
                    storage_to_collect = storage_tries.drain().collect();
                }
            }
            WorkerRequest::MerklizeAccounts { accounts: batch } => {
                // Info already applied in ProcessAccount — just record empty storage nodes
                for hashed_account in batch {
                    storage_nodes.push((hashed_account, vec![]));
                }
            }
            WorkerRequest::StorageShard {
                prefix,
                index: shard_index,
                mut subroot,
                nodes,
            } => {
                let state = storage_state.entry(prefix).or_default();
                match &mut state.storage_root {
                    Some(root) => {
                        root.choices[shard_index as usize] =
                            std::mem::take(&mut subroot.choices[shard_index as usize]);
                    }
                    rootptr => {
                        *rootptr = Some(subroot);
                    }
                }
                state.nodes.extend(nodes);

                let received = received_shards.entry(prefix).or_insert(0u16);
                *received |= 1 << shard_index;
                if *received == expected_shards.get(&prefix).copied().unwrap_or(0) {
                    // All shards received — resolve storage root
                    let mut state = storage_state.remove(&prefix).expect("shard without state");
                    let new_storage_root = if let Some(mut root) = state.storage_root {
                        // Children from other shards need clear_hash to be re-committed.
                        root.choices.iter_mut().for_each(NodeRef::clear_hash);
                        let collapsed =
                            collapse_root_node(&storage, parent_state_root, Some(prefix), *root)?;
                        if let Some(root) = collapsed {
                            let mut root = NodeRef::from(root);
                            let hash =
                                root.commit(Nibbles::default(), &mut state.nodes, &NativeCrypto);
                            let _ = DROP_SENDER.send(Box::new(root));
                            hash.finalize(&NativeCrypto)
                        } else {
                            state.nodes.push((Nibbles::default(), vec![RLP_NULL]));
                            *EMPTY_TRIE_HASH
                        }
                    } else {
                        *EMPTY_TRIE_HASH
                    };
                    storage_nodes.push((prefix, state.nodes));

                    // Update account's storage root and re-insert into state trie
                    let old_state = accounts.get_mut(&prefix).expect("loaded in ProcessAccount");
                    old_state.storage_root = new_storage_root;
                    let path = prefix.as_bytes();
                    if *old_state != AccountState::default() {
                        state_trie.insert(path.to_vec(), old_state.encode_to_vec())?;
                    } else {
                        state_trie.remove(path)?;
                    }

                    dirty = true;
                    pending_storage_accounts -= 1;
                    if pending_storage_accounts == 0
                        && !collecting_storages
                        && routing_complete
                        && let Some(tx) = pending_collect_tx.take()
                    {
                        collect_and_send(
                            index,
                            &mut state_trie,
                            &mut pre_collected_state,
                            &mut storage_nodes,
                            tx,
                        )?;
                        break;
                    }
                }
            }
            WorkerRequest::CollectState { tx } => {
                if pending_storage_accounts == 0 && !collecting_storages && routing_complete {
                    collect_and_send(
                        index,
                        &mut state_trie,
                        &mut pre_collected_state,
                        &mut storage_nodes,
                        tx,
                    )?;
                    break;
                }
                // Defer until collection is done and all StorageShards resolved
                pending_collect_tx = Some(tx);
            }
        }
    }
    Ok(())
}

/// The [`VMType`] a given [`BlockchainType`] executes with.
pub fn vm_type_for(blockchain_type: &BlockchainType) -> Result<VMType, EvmError> {
    Ok(match blockchain_type {
        BlockchainType::L1 => VMType::L1,
        BlockchainType::L2(l2_config) => VMType::L2(
            *l2_config
                .fee_config
                .read()
                .map_err(|_| EvmError::Custom("Fee config lock was poisoned".to_string()))?,
        ),
    })
}

pub fn new_evm<D: VmDatabase + 'static>(
    blockchain_type: &BlockchainType,
    vm_db: D,
) -> Result<Evm, EvmError> {
    let mut evm = match blockchain_type {
        BlockchainType::L1 => Evm::new_for_l1(vm_db, Arc::new(NativeCrypto)),
        BlockchainType::L2(l2_config) => {
            let fee_config = *l2_config
                .fee_config
                .read()
                .map_err(|_| EvmError::Custom("Fee config lock was poisoned".to_string()))?;

            Evm::new_for_l2(vm_db, fee_config, Arc::new(NativeCrypto))?
        }
    };
    attach_stateless_validator(&mut evm);
    Ok(evm)
}

/// Attach the stateless validator to an `Evm` so its `EXECUTE` precompile
/// can delegate to `verify_stateless_new_payload` when processing native-rollup
/// `advance()` calls.
///
/// Lives here (not in `Evm`'s constructor) because `StatelessExecutor` is
/// implemented by the blockchain crate and calls back into `Evm::new_for_l1`
/// when verifying — an auto-inject in the constructor would recurse. Other
/// callers that build `Evm::new_for_l1` without blockchain access (the
/// guest-program crate, the stateless verifier itself, witness generation,
/// the prover backend) also rely on the constructor staying validator-less.
///
fn attach_stateless_validator(evm: &mut Evm) {
    evm.stateless_validator = Some(Arc::new(stateless::StatelessExecutor {
        crypto: Arc::new(NativeCrypto),
    }));
}

/// Performs post-execution checks
pub fn validate_state_root(
    block_header: &BlockHeader,
    new_state_root: H256,
) -> Result<(), ChainError> {
    // Compare state root
    if new_state_root == block_header.state_root {
        Ok(())
    } else {
        Err(ChainError::InvalidBlock(
            InvalidBlockError::StateRootMismatch,
        ))
    }
}

// Returns the hash of the head of the canonical chain (the latest valid hash).
pub fn latest_canonical_block_hash(storage: &Store) -> Result<H256, ChainError> {
    let latest_block_number = storage.get_latest_block_number()?;
    if let Some(latest_valid_header) = storage.get_block_header(latest_block_number)? {
        let latest_valid_hash = latest_valid_header.hash();
        return Ok(latest_valid_hash);
    }
    Err(ChainError::StoreError(StoreError::Custom(
        "Could not find latest valid hash".to_string(),
    )))
}

/// Searchs the header of the parent block header. If the parent header is missing,
/// Returns a ChainError::ParentNotFound. If the storage has an error it propagates it
pub fn find_parent_header(
    block_header: &BlockHeader,
    storage: &Store,
) -> Result<BlockHeader, ChainError> {
    match storage.get_block_header_by_hash(block_header.parent_hash)? {
        Some(parent_header) => Ok(parent_header),
        None => Err(ChainError::ParentNotFound),
    }
}

pub async fn is_canonical(
    store: &Store,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> Result<bool, StoreError> {
    match store.get_canonical_block_hash(block_number).await? {
        Some(hash) if hash == block_hash => Ok(true),
        _ => Ok(false),
    }
}

fn branchify(node: Node) -> Box<BranchNode> {
    match node {
        Node::Branch(branch_node) => branch_node,
        Node::Extension(extension_node) => {
            let index = extension_node.prefix.as_ref()[0];
            let noderef = if extension_node.prefix.len() == 1 {
                extension_node.child
            } else {
                let prefix = extension_node.prefix.offset(1);
                let node = ExtensionNode::new(prefix, extension_node.child);
                NodeRef::from(Arc::new(node.into()))
            };
            let mut choices = BranchNode::EMPTY_CHOICES;
            choices[index as usize] = noderef;
            Box::new(BranchNode::new(choices))
        }
        Node::Leaf(leaf_node) => {
            let index = leaf_node.partial.as_ref()[0];
            let node = LeafNode::new(leaf_node.partial.offset(1), leaf_node.value);
            let mut choices = BranchNode::EMPTY_CHOICES;
            choices[index as usize] = NodeRef::from(Arc::new(node.into()));
            Box::new(BranchNode::new(choices))
        }
    }
}

fn collect_trie(index: u8, mut trie: Trie) -> Result<(Box<BranchNode>, Vec<TrieNode>), TrieError> {
    let root = branchify(
        trie.root_node()?
            .map(Arc::unwrap_or_clone)
            .unwrap_or_else(|| Node::Branch(Box::default())),
    );
    trie.root = Node::Branch(root).into();
    let (_, mut nodes) = trie.collect_changes_since_last_hash(&NativeCrypto);
    nodes.retain(|(nib, _)| nib.as_ref().first() == Some(&index));

    let Some(Node::Branch(root)) = trie.root_node()?.map(Arc::unwrap_or_clone) else {
        return Err(TrieError::InvalidInput);
    };
    Ok((root, nodes))
}

/// Serial reference computation of an account's storage root + node diff,
/// identical to the per-account Stage B path. Used as a fallback for the
/// degenerate sharding cases (see `compute_sharded_storage_root`) where the
/// branchify/collapse reassembly, while producing the correct root, would emit
/// a different (extra/stale, always unreachable) node set than the canonical
/// serial path.
fn serial_storage_root(
    storage: &Store,
    parent_state_root: H256,
    hashed_address: H256,
    storage_root: H256,
    hashed_storage: &[(H256, U256)],
) -> Result<(H256, Vec<TrieNode>), StoreError> {
    let mut trie = storage.open_storage_trie(hashed_address, parent_state_root, storage_root)?;

    // Both call sites (`compute_sharded_storage_root`'s `occupied <= 1` and
    // "storage emptied" fallbacks) pass an already key-sorted slice, so it is
    // safe to reuse that order directly for prefetch.
    if hashed_storage.len() >= STORAGE_PREFETCH_THRESHOLD {
        let paths: Vec<Nibbles> = hashed_storage
            .iter()
            .map(|(k, _)| Nibbles::from_bytes(k.as_bytes()))
            .collect();
        trie.prefetch_sorted(&paths)?;
    }

    for (hashed_key, value) in hashed_storage {
        if value.is_zero() {
            trie.remove(hashed_key.as_bytes())?;
        } else {
            trie.insert(hashed_key.as_bytes().to_vec(), value.encode_to_vec())?;
        }
    }
    Ok(trie.collect_changes_since_last_hash(&NativeCrypto))
}

/// Compute the storage root for a single account by sharding its slots across
/// 16 nibble-keyed workers. The returned `(H256, Vec<TrieNode>)` is
/// drop-in compatible with `trie.collect_changes_since_last_hash`.
///
/// `hashed_storage` order does not matter (sharding and trie inserts are
/// order-independent). All 16 shard threads spawn even for empty buckets: an
/// empty thread opens the trie, performs no insertions, and returns
/// `collect_trie(nibble, trie)` so the reassembled root has no holes.
///
/// Exposed (hidden) for the `ethrex-test` crate's equivalence tests; not part
/// of the stable public API.
///
/// Load-bearing invariant: this relies on a **path-keyed** node DB, where a node
/// is reachable only via its trie path. On inserts/updates and the degenerate
/// fallbacks below the persisted node set is bit-identical to the serial path,
/// but the parallel removal path may emit a few redundant nodes that are
/// unreachable by path and therefore harmless (never read back, never GC'd).
/// This is why the `occupied <= 1` fallback is sufficient and why we do *not*
/// also fall back on the broader "removal collapses the trie post-bucketization"
/// case. If the storage backend ever moves to a content-addressed / hash-keyed
/// node DB, or grows reachability-based GC, the parallel-removal path could leak
/// unreachable-but-persistent nodes and this assumption must be revisited.
#[doc(hidden)]
pub fn compute_sharded_storage_root(
    storage: &Store,
    parent_state_root: H256,
    hashed_address: H256,
    storage_root: H256,
    hashed_storage: &[(H256, U256)],
) -> Result<(H256, Vec<TrieNode>), StoreError> {
    // Sort by hashed key, matching the serial Stage B path (the per-account
    // worker). The storage root is content-addressed so order is irrelevant to
    // correctness, but inserting in key order walks the node arena sequentially
    // (cache locality) and keeps the persisted node set bit-identical to Stage B.
    // Applies to both the sharded path below and the serial fallbacks: bucketing
    // by first nibble preserves the sorted order within each bucket.
    // Stable sort: production inputs (a map) have unique keys, but a stable order
    // preserves last-write-wins for any duplicate keys, matching sequential apply.
    let mut sorted = hashed_storage.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let hashed_storage = sorted.as_slice();

    // Split slots into 16 buckets by the first nibble of the hashed key.
    let mut buckets: [Vec<(H256, U256)>; 16] = Default::default();
    for &(key, value) in hashed_storage {
        let nibble = (key.as_fixed_bytes()[0] >> 4) as usize;
        buckets[nibble].push((key, value));
    }

    // A slot landing in the wrong nibble bucket would silently corrupt the
    // reassembled root (consensus failure), so guard the invariant in debug.
    #[cfg(debug_assertions)]
    for (nibble, bucket) in buckets.iter().enumerate() {
        for (key, _) in bucket {
            debug_assert_eq!(
                (key.as_fixed_bytes()[0] >> 4) as usize,
                nibble,
                "storage slot in wrong shard bucket"
            );
        }
    }

    // Degenerate case: with <=1 occupied bucket there is no parallelism to gain,
    // and the branchify/collapse reassembly of a single subtree would emit an
    // extra (unreachable) node vs the canonical serial diff. Compute serially so
    // the persisted node set is bit-identical to the non-sharded path.
    let occupied = buckets.iter().filter(|b| !b.is_empty()).count();
    if occupied <= 1 {
        return serial_storage_root(
            storage,
            parent_state_root,
            hashed_address,
            storage_root,
            hashed_storage,
        );
    }

    let mut root = BranchNode::default();
    let mut nodes: Vec<TrieNode> = Vec::new();

    // All 16 shard threads spawn even for empty buckets (same rationale as
    // Stage C comment): each thread opens the storage trie and returns the
    // existing subtree at its nibble so root reassembly has no holes.
    std::thread::scope(|s| -> Result<(), StoreError> {
        let handles: Vec<_> = buckets
            .into_iter()
            .enumerate()
            .map(|(nibble, bucket)| {
                std::thread::Builder::new()
                    .name(format!("storage_shard_{nibble}"))
                    .spawn_scoped(
                        s,
                        move || -> Result<(Box<BranchNode>, Vec<TrieNode>), StoreError> {
                            let mut trie = storage.open_storage_trie(
                                hashed_address,
                                parent_state_root,
                                storage_root,
                            )?;

                            // `bucket` is a nibble-filtered split of `hashed_storage`,
                            // which is sorted by the caller, so per-shard order is
                            // already ascending: reuse it directly for prefetch.
                            // Shard-scaled gate: each shard holds ~1/16 of the
                            // account's slots, so the whole-account 64 threshold
                            // would almost never fire here.
                            const SHARD_PREFETCH_THRESHOLD: usize = 4;
                            if bucket.len() >= SHARD_PREFETCH_THRESHOLD {
                                let paths: Vec<Nibbles> = bucket
                                    .iter()
                                    .map(|(k, _)| Nibbles::from_bytes(k.as_bytes()))
                                    .collect();
                                trie.prefetch_sorted(&paths)?;
                            }

                            for (hashed_key, value) in &bucket {
                                if value.is_zero() {
                                    trie.remove(hashed_key.as_bytes())?;
                                } else {
                                    trie.insert(
                                        hashed_key.as_bytes().to_vec(),
                                        value.encode_to_vec(),
                                    )?;
                                }
                            }
                            collect_trie(nibble as u8, trie)
                                .map_err(|e| StoreError::Custom(format!("{e}")))
                        },
                    )
                    .map_err(|e| StoreError::Custom(format!("spawn failed: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (i, handle) in handles.into_iter().enumerate() {
            let (subroot, shard_nodes) = handle
                .join()
                .map_err(|_| StoreError::Custom("storage shard worker panicked".to_string()))??;
            nodes.extend(shard_nodes);
            root.choices[i] = subroot.choices[i].clone();
        }
        Ok(())
    })?;

    // Finalize: collapse single-child branch, commit, return root hash.
    // prefix = Some(hashed_address) because this is a storage trie.
    let Some(root_node) =
        collapse_root_node(storage, parent_state_root, Some(hashed_address), root)?
    else {
        // The update emptied the storage trie. The sharded tombstone set differs
        // from the canonical serial diff (deletions of now-unreachable nodes), so
        // recompute serially for a bit-identical result. Rare (full storage clear).
        return serial_storage_root(
            storage,
            parent_state_root,
            hashed_address,
            storage_root,
            hashed_storage,
        );
    };

    let mut root_ref = NodeRef::from(root_node);
    let root_hash = root_ref.commit(Nibbles::default(), &mut nodes, &NativeCrypto);
    let _ = DROP_SENDER.send(Box::new(root_ref));

    Ok((root_hash.finalize(&NativeCrypto), nodes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{BuildPayloadArgs, create_payload};
    use bytes::Bytes;
    use ethrex_common::{
        H160, H256,
        types::{DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis},
    };
    use ethrex_storage::EngineType;
    use std::path::Path;

    async fn build_test_blockchain_with_one_block() -> (Blockchain, Vec<Block>) {
        let genesis_path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/genesis/execution-api.json"
        ));
        let genesis = Genesis::try_from(genesis_path).expect("Failed to load genesis");
        let mut store =
            Store::new("store.db", EngineType::InMemory).expect("Failed to build store");
        store
            .add_initial_state(genesis)
            .await
            .expect("Failed to add genesis");
        let blockchain = Blockchain::default_with_store(store.clone());
        let genesis_header = store.get_block_header(0).unwrap().unwrap();
        let args = BuildPayloadArgs {
            parent: genesis_header.hash(),
            timestamp: genesis_header.timestamp + 12,
            fee_recipient: H160::zero(),
            random: H256::zero(),
            withdrawals: Some(Vec::new()),
            beacon_root: Some(H256::zero()),
            slot_number: None,
            version: 1,
            elasticity_multiplier: ELASTICITY_MULTIPLIER,
            gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
        };
        let block_template = create_payload(&args, &store, Bytes::new()).unwrap();
        let result = blockchain.build_payload(block_template).unwrap();
        (blockchain, vec![result.payload])
    }

    #[tokio::test]
    async fn generate_witness_and_bal_returns_none_at_prague() {
        let (blockchain, blocks) = build_test_blockchain_with_one_block().await;

        let (_witness, bals) = blockchain
            .generate_witness_and_bal_for_blocks_with_fee_configs(&blocks, None)
            .await
            .expect("witness+bal generation");

        // One BAL slot per input block, aligned by index.
        assert_eq!(bals.len(), blocks.len());
        // Pre-Amsterdam: no BAL is produced.
        assert!(bals.iter().all(|b| b.is_none()));
    }
}

#[cfg(test)]
mod reorg_guard_tests {
    use super::*;
    use ethrex_storage::{EngineType, Store};

    fn make_blockchain() -> Blockchain {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path(), EngineType::InMemory).unwrap();
        Blockchain::default_with_store(store)
    }

    /// `enter_reorg` SHALL set the flag; the returned guard SHALL clear it on drop.
    #[test]
    fn reorg_guard_sets_and_clears_flag() {
        let blockchain = make_blockchain();
        assert!(!blockchain.is_reorg_in_progress(), "flag starts false");

        {
            let guard = blockchain.enter_reorg();
            assert!(guard.is_some(), "first enter_reorg must acquire the guard");
            assert!(
                blockchain.is_reorg_in_progress(),
                "flag must be set while guard is alive"
            );
            // A second attempt while the first guard is alive must fail the
            // test-and-set and return None.
            assert!(
                blockchain.enter_reorg().is_none(),
                "concurrent enter_reorg must not acquire a second guard"
            );
        }
        assert!(
            !blockchain.is_reorg_in_progress(),
            "flag must clear when guard drops"
        );
    }

    /// The guard SHALL clear the flag even when its scope ends via panic unwinding.
    #[test]
    fn reorg_guard_clears_flag_on_panic() {
        let blockchain = make_blockchain();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = blockchain.enter_reorg();
            assert!(blockchain.is_reorg_in_progress());
            panic!("simulated apply failure");
        }));
        // guard is dropped by the unwind; flag must be clear below.
        assert!(result.is_err(), "panic must propagate out of the scope");
        assert!(
            !blockchain.is_reorg_in_progress(),
            "flag must be cleared after a panicking guard scope"
        );
    }
}
