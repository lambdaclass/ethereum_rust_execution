use crate::{
    TransientStorage,
    account::LevmAccount,
    call_frame::{CallFrame, Stack},
    db::gen_db::GeneralizedDatabase,
    debug::DebugMode,
    environment::Environment,
    errors::{
        ContextResult, ExceptionalHalt, ExecutionReport, InternalError, OpcodeResult, TxResult,
        VMError,
    },
    gas_cost::{
        STATE_BYTES_PER_AUTH_BASE, STATE_BYTES_PER_NEW_ACCOUNT, STATE_BYTES_PER_STORAGE_SET,
        cost_per_state_byte as compute_cost_per_state_byte,
    },
    hooks::{
        backup_hook::BackupHook,
        hook::{Hook, get_hooks},
    },
    memory::Memory,
    opcode_tracer::LevmOpcodeTracer,
    opcodes::OpCodeFn,
    precompiles::{
        self, SIZE_PRECOMPILES_CANCUN, SIZE_PRECOMPILES_PRAGUE, SIZE_PRECOMPILES_PRE_CANCUN,
    },
    tracing::LevmCallTracer,
    validation_observer::ValidationObserver,
};
use bytes::Bytes;
use ethrex_common::{
    Address, BigEndianHash, H160, H256, U256,
    tracing::CallType,
    types::{
        AccessListEntry, Code, Fork, Frame, FrameMode, Log, Transaction, TxType,
        block_access_list::BlockAccessListCheckpoint, fee_config::FeeConfig,
    },
};
use ethrex_crypto::Crypto;
use rustc_hash::{FxHashMap, FxHashSet};
use std::{
    cell::{OnceCell, RefCell},
    collections::{BTreeMap, BTreeSet},
    mem,
    rc::Rc,
};

/// Storage mapping from slot key to value.
pub type Storage = FxHashMap<U256, H256>;

/// Specifies whether the VM operates in L1 or L2 mode.
#[derive(Debug, Clone, Copy, Default)]
pub enum VMType {
    /// Standard Ethereum L1 execution.
    #[default]
    L1,
    /// L2 rollup execution with additional fee handling.
    L2(FeeConfig),
}

/// Execution substate that tracks changes during transaction execution.
///
/// The substate maintains all information that may need to be reverted if a
/// call fails, including:
/// - Self-destructed accounts
/// - Accessed addresses and storage slots (for EIP-2929 gas accounting)
/// - Created accounts
/// - Gas refunds
/// - Transient storage (EIP-1153)
/// - Event logs
///
/// # Backup Mechanism
///
/// The substate supports checkpointing via [`push_backup`] and restoration via
/// [`revert_backup`] or commitment via [`commit_backup`]. This is used to handle
/// nested calls where inner calls may fail and need to be reverted.
///
/// Most fields are private by design. The backup mechanism only works correctly
/// if data modifications are append-only.
#[derive(Debug, Default)]
pub struct Substate {
    /// Parent checkpoint for reverting on failure.
    parent: Option<Box<Self>>,
    /// Fork of the enclosing transaction. Lets the warmth helpers treat precompile addresses as
    /// always-warm without occupying a hashset slot (EIP-2929). Constant for a tx, so it is
    /// carried forward across `push_backup` checkpoints.
    fork: Fork,
    /// Accounts marked for self-destruction (deleted at end of transaction).
    selfdestruct_set: FxHashSet<Address>,
    /// Addresses accessed during execution (for EIP-2929 warm/cold gas costs).
    /// Precompiles are NOT stored here; they are warm by construction (see `is_warm_precompile`).
    accessed_addresses: FxHashSet<Address>,
    /// Storage slots accessed per address (for EIP-2929 warm/cold gas costs).
    accessed_storage_slots: FxHashMap<Address, FxHashSet<H256>>,
    /// Accounts created during this transaction.
    created_accounts: FxHashSet<Address>,
    /// Accumulated gas refund (e.g., from storage clears).
    pub refunded_gas: u64,
    /// Transient storage (EIP-1153), cleared at end of transaction.
    transient_storage: TransientStorage,
    /// Event logs emitted during execution.
    logs: Vec<Log>,
}

impl Substate {
    pub fn from_accesses(
        fork: Fork,
        accessed_addresses: FxHashSet<Address>,
        accessed_storage_slots: FxHashMap<Address, FxHashSet<H256>>,
    ) -> Self {
        Self {
            parent: None,
            fork,
            selfdestruct_set: FxHashSet::default(),
            accessed_addresses,
            accessed_storage_slots,
            created_accounts: FxHashSet::default(),
            refunded_gas: 0,
            transient_storage: TransientStorage::default(),
            logs: Vec::new(),
        }
    }

    /// Whether `address` is a precompile that the EVM treats as warm from the start of the tx
    /// (EIP-2929), exactly matching the addresses `Substate::initialize` used to pre-seed.
    ///
    /// Replicates the pre-seed *precisely* — the contiguous range `0x01..=max_for_fork` plus the
    /// post-Osaka P256VERIFY address `0x100` — and is intentionally `vm_type`-independent, since
    /// the old pre-seed was too. (Using `precompiles::is_precompile`, which gates `0x100` on L2
    /// for any fork, would change L2 pre-Osaka warmth — a consensus difference, not an opt.)
    #[inline]
    fn is_warm_precompile(&self, address: &Address) -> bool {
        // Fast reject: every pre-seeded precompile has 18 leading zero bytes (max is `0x01_00`),
        // so real contract/EOA addresses bail out here, off the hot warmth path.
        if address.0[..18] != [0u8; 18] {
            return false;
        }
        let n = u16::from_be_bytes([address.0[18], address.0[19]]);
        let max_contiguous: u64 = match self.fork {
            f if f >= Fork::Prague => SIZE_PRECOMPILES_PRAGUE,
            f if f >= Fork::Cancun => SIZE_PRECOMPILES_CANCUN,
            _ => SIZE_PRECOMPILES_PRE_CANCUN,
        };
        (n >= 1 && u64::from(n) <= max_contiguous) || (n == 0x100 && self.fork >= Fork::Osaka)
    }

    /// Push a checkpoint that can be either reverted or committed. All data up to this point is
    /// still accessible.
    pub fn push_backup(&mut self) {
        let parent = mem::take(self);
        self.refunded_gas = parent.refunded_gas;
        // Carry the fork forward so child checkpoints keep the same precompile-warmth view.
        self.fork = parent.fork;
        self.parent = Some(Box::new(parent));
    }

    /// Pop and merge with the last backup.
    ///
    /// Does nothing if the substate has no backup.
    pub fn commit_backup(&mut self) {
        if let Some(parent) = self.parent.as_mut() {
            let mut delta = mem::take(parent);
            mem::swap(self, &mut delta);

            self.selfdestruct_set.extend(delta.selfdestruct_set);
            self.accessed_addresses.extend(delta.accessed_addresses);
            for (address, slot_set) in delta.accessed_storage_slots {
                self.accessed_storage_slots
                    .entry(address)
                    .or_default()
                    .extend(slot_set);
            }
            self.created_accounts.extend(delta.created_accounts);
            self.refunded_gas = delta.refunded_gas;
            self.transient_storage.extend(delta.transient_storage);
            self.logs.extend(delta.logs);
        }
    }

    /// Discard current changes and revert to last backup.
    ///
    /// Does nothing if the substate has no backup.
    pub fn revert_backup(&mut self) {
        if let Some(parent) = self.parent.as_mut() {
            *self = mem::take(parent);
        }
    }

    /// Return an iterator over all selfdestruct addresses.
    pub fn iter_selfdestruct(&self) -> impl Iterator<Item = &Address> {
        struct Iter<'a> {
            parent: Option<&'a Substate>,
            iter: std::collections::hash_set::Iter<'a, Address>,
        }

        impl<'a> Iterator for Iter<'a> {
            type Item = &'a Address;

            fn next(&mut self) -> Option<Self::Item> {
                let next_item = self.iter.next();
                if next_item.is_none()
                    && let Some(parent) = self.parent
                {
                    self.parent = parent.parent.as_deref();
                    self.iter = parent.selfdestruct_set.iter();

                    return self.next();
                }

                next_item
            }
        }

        Iter {
            parent: self.parent.as_deref(),
            iter: self.selfdestruct_set.iter(),
        }
    }

    /// Mark an address as selfdestructed and return whether is was already marked.
    pub fn add_selfdestruct(&mut self, address: Address) -> bool {
        if self.selfdestruct_set.contains(&address) {
            return true;
        }

        let is_present = self
            .parent
            .as_ref()
            .map(|parent| parent.is_selfdestruct(&address))
            .unwrap_or_default();

        is_present || !self.selfdestruct_set.insert(address)
    }

    /// Return whether an address is already marked as selfdestructed.
    pub fn is_selfdestruct(&self, address: &Address) -> bool {
        self.selfdestruct_set.contains(address)
            || self
                .parent
                .as_ref()
                .map(|parent| parent.is_selfdestruct(address))
                .unwrap_or_default()
    }

    /// Build an access list from all accessed storage slots.
    pub fn make_access_list(&self) -> Vec<AccessListEntry> {
        let mut entries = BTreeMap::<Address, BTreeSet<H256>>::new();

        let mut current = self;
        loop {
            for (address, slot_set) in &current.accessed_storage_slots {
                entries
                    .entry(*address)
                    .or_default()
                    .extend(slot_set.iter().copied());
            }

            current = match current.parent.as_deref() {
                Some(x) => x,
                None => break,
            };
        }

        entries
            .into_iter()
            .map(|(address, storage_keys)| AccessListEntry {
                address,
                storage_keys: storage_keys.into_iter().collect(),
            })
            .collect()
    }

    /// Mark an address as accessed and return whether the slot was cold.
    pub fn add_accessed_slot(&mut self, address: Address, key: H256) -> bool {
        if self
            .accessed_storage_slots
            .get(&address)
            .is_some_and(|set| set.contains(&key))
        {
            return false;
        }

        let is_present = self
            .parent
            .as_ref()
            .map(|parent| parent.is_slot_accessed(&address, &key))
            .unwrap_or_default();

        // Note: Do not simplify this expression, it uses `||` to avoid executing the right hand
        //   expression if not necessary.
        #[expect(clippy::nonminimal_bool, reason = "order of evaluation matters")]
        !(is_present
            || !self
                .accessed_storage_slots
                .entry(address)
                .or_default()
                .insert(key))
    }

    /// Return whether an address has already been accessed.
    pub fn is_slot_accessed(&self, address: &Address, key: &H256) -> bool {
        self.accessed_storage_slots
            .get(address)
            .map(|slot_set| slot_set.contains(key))
            .unwrap_or_default()
            || self
                .parent
                .as_ref()
                .map(|parent| parent.is_slot_accessed(address, key))
                .unwrap_or_default()
    }

    /// Returns all accessed storage slots for a given address.
    /// Used by SELFDESTRUCT to record storage reads in BAL per EIP-7928:
    /// "SELFDESTRUCT: Include modified/read storage keys as storage_read"
    pub fn get_accessed_storage_slots(&self, address: &Address) -> BTreeSet<H256> {
        let mut slots = BTreeSet::new();

        // Collect from current substate
        if let Some(slot_set) = self.accessed_storage_slots.get(address) {
            slots.extend(slot_set.iter().copied());
        }

        // Collect from parent substates recursively
        if let Some(parent) = self.parent.as_ref() {
            slots.extend(parent.get_accessed_storage_slots(address));
        }

        slots
    }

    /// Mark an address as accessed and return whether the address was cold.
    pub fn add_accessed_address(&mut self, address: Address) -> bool {
        // Precompiles are warm from tx start (EIP-2929) without occupying a hashset slot. Returns
        // `false` (not cold) so cold-access gas is never charged — identical to the old pre-seed.
        if self.is_warm_precompile(&address) {
            return false;
        }

        if self.accessed_addresses.contains(&address) {
            return false;
        }

        let is_present = self
            .parent
            .as_ref()
            .map(|parent| parent.is_address_accessed(&address))
            .unwrap_or_default();

        // Note: Do not simplify this expression, it uses `||` to avoid executing the right hand
        //   expression if not necessary.
        #[expect(clippy::nonminimal_bool, reason = "order of evaluation matters")]
        !(is_present || !self.accessed_addresses.insert(address))
    }

    /// Return whether an address has already been accessed.
    pub fn is_address_accessed(&self, address: &Address) -> bool {
        // Precompiles are always warm; the chain shares one `fork`, so this is consistent across
        // sub-frame substates.
        self.is_warm_precompile(address)
            || self.accessed_addresses.contains(address)
            || self
                .parent
                .as_ref()
                .map(|parent| parent.is_address_accessed(address))
                .unwrap_or_default()
    }

    /// Mark an address as a new account and return whether is was already marked.
    pub fn add_created_account(&mut self, address: Address) -> bool {
        if self.created_accounts.contains(&address) {
            return true;
        }

        let is_present = self
            .parent
            .as_ref()
            .map(|parent| parent.is_account_created(&address))
            .unwrap_or_default();

        is_present || !self.created_accounts.insert(address)
    }

    /// Return whether an address has already been marked as a new account.
    pub fn is_account_created(&self, address: &Address) -> bool {
        self.created_accounts.contains(address)
            || self
                .parent
                .as_ref()
                .map(|parent| parent.is_account_created(address))
                .unwrap_or_default()
    }

    /// Return the data associated with a transient storage entry, or zero if not present.
    pub fn get_transient(&self, to: &Address, key: &U256) -> U256 {
        self.transient_storage
            .get(&(*to, *key))
            .copied()
            .unwrap_or_else(|| {
                self.parent
                    .as_ref()
                    .map(|parent| parent.get_transient(to, key))
                    .unwrap_or_default()
            })
    }

    /// Return the data associated with a transient storage entry, or zero if not present.
    pub fn set_transient(&mut self, to: &Address, key: &U256, value: U256) {
        self.transient_storage.insert((*to, *key), value);
    }

    /// Clear all transient storage (used between frames in frame transactions).
    pub fn clear_transient_storage(&mut self) {
        self.transient_storage.clear();
    }

    /// Extract all logs in order.
    pub fn extract_logs(&self) -> Vec<Log> {
        fn inner(substrate: &Substate, target: &mut Vec<Log>) {
            if let Some(parent) = substrate.parent.as_deref() {
                inner(parent, target);
            }

            target.extend_from_slice(&substrate.logs);
        }

        let mut logs = Vec::new();
        inner(self, &mut logs);

        logs
    }

    /// Return a clone of the current sub-substate's logs only, excluding parent logs.
    /// Used by EIP-8141 frame execution to capture per-frame log deltas for
    /// `frame_receipts[i].logs`. Must be called after `push_backup()` and before
    /// `commit_backup()` to return only the logs emitted during the current scope.
    pub fn current_logs(&self) -> Vec<Log> {
        self.logs.clone()
    }

    /// Number of logs in the current scope, without cloning them. Used to slice
    /// out a single frame's logs after `run_execution` has already committed the
    /// frame's backup up into this scope.
    pub fn logs_len(&self) -> usize {
        self.logs.len()
    }

    /// Push a log record.
    pub fn add_log(&mut self, log: Log) {
        self.logs.push(log);
    }
}

/// The LEVM (Lambda EVM) execution engine.
///
/// The VM executes Ethereum transactions by processing EVM bytecode. It maintains
/// a call stack, memory, and tracks all state changes during execution.
///
/// # Execution Model
///
/// 1. Transaction is validated (nonce, balance, gas limit)
/// 2. Initial call frame is created with transaction data
/// 3. Opcodes are executed sequentially until completion or error
/// 4. State changes are committed or reverted based on success
///
/// # Call Stack
///
/// Nested calls (CALL, DELEGATECALL, etc.) push new frames onto `call_frames`.
/// Each frame has its own memory, stack, and execution context. The `current_call_frame`
/// is always the active frame being executed.
///
/// # Hooks
///
/// The VM supports hooks for extending functionality (e.g., tracing, debugging).
/// Hooks are called at various points during execution and implement pre/post-execution
/// logic. L2-specific behavior (such as fee handling) is implemented via hooks.
///
/// # Example
///
/// ```ignore
/// let mut vm = VM::new(env, db, &tx, tracer, vm_type, &NativeCrypto);
/// let report = vm.execute()?;
/// if report.is_success() {
///     println!("Gas used: {}, Output: {:?}", report.gas_used, report.output);
/// } else {
///     println!("Transaction reverted");
/// }
/// ```
/// EIP-8141 §Behavior: the top-level `frame.value` transfer
/// reverts the frame if the sender's balance is strictly less than the
/// amount being sent. Factored out so the decision can be unit-tested
/// without bringing up a full VM state.
pub fn frame_value_exceeds_balance(sender_balance: U256, frame_value: U256) -> bool {
    sender_balance < frame_value
}

/// Context for frame transaction (EIP-8141) execution.
/// This is set when executing a frame transaction and is used by
/// APPROVE, TXPARAM, FRAMEDATALOAD, and FRAMEDATACOPY opcodes.
#[derive(Debug, Clone)]
pub struct FrameTxContext {
    /// Whether the sender has approved (APPROVE scope `APPROVE_EXECUTION` or
    /// `APPROVE_EXECUTION_AND_PAYMENT`).
    pub sender_approved: bool,
    /// The address that approved payment, set by `APPROVE_PAYMENT` or
    /// `APPROVE_EXECUTION_AND_PAYMENT`. Per the latest EIP-8141 spec this is the
    /// single source of truth for whether payment has been approved: when this
    /// is `Some(_)`, the transaction has a `payer`; when `None`, it does not.
    pub payer_address: Option<Address>,
    /// Per-frame execution results (status, gas_used, logs).
    /// `status` is a `FRAME_RECEIPT_STATUS_*` code (0 = failure, 1 = success,
    /// 3 = skipped due to failed atomic batch).
    pub frame_results: Vec<(u8, u64, Vec<Log>)>,
    /// Index of the currently executing frame
    pub current_frame_index: usize,
    /// The sig_hash of the frame transaction
    pub sig_hash: H256,
    /// The full frame transaction (for TXPARAM access)
    pub tx: ethrex_common::types::FrameTransaction,
    /// Whether APPROVE was called in the current frame
    pub approve_called_in_current_frame: bool,
    /// Cached `FrameTransaction::max_gas()`. Computing it re-encodes every frame
    /// and signature, so it must not run per-opcode (TXPARAM 0x06,
    /// compute_tx_max_cost). Computed once at tx entry.
    pub max_gas: u64,
    /// The block's EIP-4844 blob base fee, captured at tx entry. `max_cost`
    /// collects the blob fee at this rate, not at `max_fee_per_blob_gas`
    /// (EIP-8141 §Gas accounting), and `load_tx_param` has no `Environment`
    /// handle to read it from.
    pub blob_base_fee: U256,
}

impl FrameTxContext {
    /// Capture the approval state at atomic-batch entry. A batch revert rolls
    /// back the payer's balance deduction and the sender nonce increment, so
    /// approvals granted inside the batch must be rolled back with it —
    /// otherwise a reverted APPROVE would leave the transaction authorized
    /// by a frame whose effects no longer exist.
    pub fn approval_snapshot(&self) -> (bool, Option<Address>) {
        (self.sender_approved, self.payer_address)
    }

    /// Restore the approval state captured by `approval_snapshot` when the
    /// enclosing atomic batch reverts. Approvals granted before the batch
    /// are unaffected (the snapshot includes them).
    pub fn restore_approvals(&mut self, snapshot: (bool, Option<Address>)) {
        let (sender_approved, payer_address) = snapshot;
        self.sender_approved = sender_approved;
        self.payer_address = payer_address;
    }
}

/// Snapshot of `call_frame_backup`'s key-space taken by [`VM::enter_prepare_region`]
/// at the start of the atomic prepare region (EIP-8037 auth + prepare-dispatch
/// charges). `original_accounts_info` / `original_account_storage_slots` are
/// first-write-wins maps keyed by address, so a plain entry-count marker can't
/// tell which keys are region-added; recording the pre-region key sets lets
/// [`VM::fail_prepare_region`] revert exactly the region's writes while leaving
/// the earlier sender nonce-bump / fee-deduction backup entries intact.
/// `inserted_code_hashes` is an append-only `Vec`, so its pre-region length is
/// enough to identify the region-added tail.
#[derive(Debug, Default)]
pub struct PrepareRegionBackupMarker {
    /// Addresses already backed up in `original_accounts_info` before the region.
    accounts: FxHashSet<Address>,
    /// Addresses already backed up in `original_account_storage_slots` before the region.
    storage: FxHashSet<Address>,
    /// Length of `inserted_code_hashes` before the region.
    code_hashes_len: usize,
    /// Region-entry state of every account already backed up before the region
    /// (notably the sender, post-fee/post-nonce). The marker excludes these from
    /// the region rollback to preserve their pre-region writes, but first-write-wins
    /// backup means an in-region write to one of them (e.g. a self-sponsored EIP-7702
    /// authorization on the sender) leaves no new backup entry. `fail_prepare_region`
    /// restores these to the captured state, reverting the in-region write while
    /// keeping the pre-region nonce bump / fee deduction.
    entry_state: FxHashMap<Address, LevmAccount>,
    /// BAL recorder checkpoint at region entry, so an applied-then-reverted
    /// delegation's code/nonce changes are discarded (demoted to an access-only
    /// touch) rather than leaking into the block access list.
    bal_checkpoint: Option<BlockAccessListCheckpoint>,
}

/// Result of [`VM::simulate_validation_prefix`] (EIP-8141 mempool simulation).
#[derive(Debug, Clone)]
pub struct PrefixSimResult {
    /// Whether any prefix frame reverted (fatal for validation).
    pub any_revert: bool,
    /// The payer established by the prefix, if any.
    pub payer_address: Option<Address>,
    /// Whether the sender was approved by a verify/pay frame.
    pub sender_approved: bool,
    /// Total simulated gas used across the prefix frames.
    pub total_gas_used: u64,
}

pub struct VM<'a> {
    /// Stack of parent call frames (for nested calls).
    pub call_frames: Vec<CallFrame>,
    /// The currently executing call frame.
    pub current_call_frame: CallFrame,
    /// Block and transaction environment.
    pub env: Environment,
    /// Execution substate (accessed addresses, logs, refunds, etc.).
    pub substate: Substate,
    /// Database for reading/writing account state.
    pub db: &'a mut GeneralizedDatabase,
    /// The transaction being executed. Borrowed for the VM's lifetime (the caller owns it for at
    /// least that long), avoiding a per-tx deep clone of the access/authorization lists.
    pub tx: &'a Transaction,
    /// Execution hooks for tracing and debugging.
    pub hooks: Vec<Rc<RefCell<dyn Hook>>>,
    /// Original storage values before transaction (for SSTORE gas calculation),
    /// keyed first by account to avoid hashing the full tuple on each access.
    pub storage_original_values: FxHashMap<Address, FxHashMap<H256, U256>>,
    /// Call tracer for execution tracing.
    pub tracer: LevmCallTracer,
    /// Opcode (EIP-3155) tracer.  Disabled by default; zero overhead when inactive.
    pub opcode_tracer: LevmOpcodeTracer,
    /// EIP-8141 mempool validation-trace observer. Disabled by default; active
    /// only during `simulate_frame_validation_prefix`. Read only behind
    /// `if self.validation_observer.active`, so an inactive observer adds one
    /// branch to the dispatch loop and nothing more (mirrors `opcode_tracer`).
    pub validation_observer: ValidationObserver,
    /// Debug mode for development diagnostics.
    pub debug_mode: DebugMode,
    /// Pool of reusable stacks to reduce allocations.
    pub stack_pool: Vec<Stack>,
    /// VM type (L1 or L2 with fee config).
    pub vm_type: VMType,
    /// Frame transaction context (EIP-8141). Set when executing a frame tx.
    pub frame_tx_context: Option<FrameTxContext>,

    /// Whether the top-level call-frame backup must be PRESERVED (deep-cloned) on the
    /// revert / invalid-tx paths because a `BackupHook` will read it in `finalize_execution`
    /// to build the tx-level undo snapshot. Derived from the installed `hooks` (via
    /// [`Hook::reads_top_level_backup`]) rather than from `vm_type`, so it stays correct if
    /// hook wiring changes; `add_hook` keeps it in sync for the `BackupHook` that
    /// `stateless_execute` installs after construction. False for normal L1 block execution
    /// (no `BackupHook`), where the backup is dead once the cache is restored and can be moved
    /// out instead of cloned.
    pub(crate) preserve_top_level_backup: bool,
    /// EIP-8037: Accumulated state gas for this transaction (Amsterdam+).
    /// Signed: goes negative when inline refunds exceed gross charges in the local frame
    /// (e.g. SSTORE 0→x→0 restoration matching an ancestor's charge).
    pub state_gas_used: i64,
    /// EIP-8037: State gas reservoir pre-funded from excess gas_limit (Amsterdam+).
    pub state_gas_reservoir: u64,
    /// EIP-8037: Initial reservoir at tx start (before any execution). Captured in
    /// add_intrinsic_gas so block-dimensional regular gas can be computed
    /// independently of mid-tx reservoir activity (auth refunds, SSTORE credits).
    pub state_gas_reservoir_initial: u64,
    /// EIP-8037: Cumulative state gas that spilled to regular gas during execution
    /// (when reservoir was insufficient). Subtracted when computing dimensional
    /// regular gas for block accounting — EELS charge_state_gas spills don't
    /// increment regular_gas_used.
    pub state_gas_spill: u64,
    /// EIP-8037: Dynamic cost per state byte (computed from block_gas_limit, Amsterdam+).
    pub cost_per_state_byte: u64,
    /// EIP-8037: State gas for new account creation (STATE_BYTES_PER_NEW_ACCOUNT * cost_per_state_byte).
    pub state_gas_new_account: u64,
    /// EIP-8037: State gas for storage slot creation (STATE_BYTES_PER_STORAGE_SET * cost_per_state_byte).
    pub state_gas_storage_set: u64,
    /// EIP-8037: State gas for the 23-byte EIP-7702 delegation indicator
    /// (STATE_BYTES_PER_AUTH_BASE * cost_per_state_byte). Charged in-region by
    /// `eip7702_set_access_code` (EELS `set_delegation`) once per authority when a
    /// net-new delegation indicator is written, and never credited back.
    pub state_gas_auth_base: u64,
    /// EIP-8037: intrinsic state gas (`tx_env.intrinsic_state_gas` in EELS). Captured at
    /// `add_intrinsic_gas` time. ethrex lumps intrinsic + execution into `state_gas_used`,
    /// so on top-level error this field is what we leave behind when refunding the
    /// execution portion to the reservoir — block accounting then bills the intrinsic
    /// (matches EELS `tx_state_gas = intrinsic_state_gas + tx_output.state_gas_used`).
    pub intrinsic_state_gas: u64,
    /// EIP-8037: set by `prepare_execution` when the in-region value-to-not-alive
    /// `NEW_ACCOUNT` charge fires (a value-bearing call to a not-yet-alive
    /// recipient). Consumed once, at the top of `run_execution`, to decide
    /// whether an Amsterdam precompile-halt must roll the charge back (the
    /// recipient never materializes on halt).
    pub value_new_account_charged: bool,
    /// EIP-8037: `current_call_frame.state_gas_used_at_entry` captured by
    /// `enter_prepare_region` right before the atomic prepare region (EIP-7702
    /// auth + prepare-dispatch charges) begins. `fail_prepare_region` rewinds the
    /// frame's `state_gas_used` back to this pre-region baseline on an internal OOG,
    /// mirroring EELS `restore_tx_state(prep_snapshot)`.
    pub prep_baseline_state_gas: i64,
    /// EIP-8037: `state_gas_reservoir` captured by `enter_prepare_region`. The
    /// `set_delegation` auth lock-in zeroes the frame spill, so `fail_prepare_region`
    /// cannot reconstruct the pre-region reservoir from `refill_frame_state_gas`
    /// arithmetic; it restores this captured value directly (EELS
    /// `message.state_gas_reservoir = prep_reservoir`).
    pub prep_baseline_reservoir: u64,
    /// EIP-8037: cumulative `state_gas_spill` captured by `enter_prepare_region`, so
    /// `fail_prepare_region` restores block-accounting spill to its pre-region value
    /// (the region's spilled state gas is fully rolled back / burned as regular).
    pub prep_baseline_state_gas_spill: u64,
    /// EIP-8037: pre-region key-space snapshot of `call_frame_backup`, recorded by
    /// `enter_prepare_region`. Lets `fail_prepare_region` revert only region-added
    /// writes, leaving the sender nonce-bump / fee-deduction entries intact.
    pub prep_region_backup_marker: PrepareRegionBackupMarker,
    /// EIP-8037: set by `fail_prepare_region` when an internal OOG rolls back the
    /// atomic prepare region. Consumed by `run_execution`, which turns it into a
    /// full-gas revert `ContextResult` (mirrors EELS depth-0
    /// `except ExceptionalHalt: evm.regular_gas_used += evm.gas_left; evm.gas_left = 0`)
    /// instead of a tx-level rejection `Err` that would wrongly invalidate the block.
    pub pending_prep_oog: bool,
    /// The opcode table mapping opcodes to opcode handlers for fast lookup.
    /// A shared `&'static` reference to a per-fork table that is `const`-built once for the
    /// whole process (immutable), so each VM holds only a pointer instead of a 2 KB inline copy.
    pub(crate) opcode_table: &'static [OpCodeFn; 256],
    /// Crypto provider for cryptographic operations.
    pub crypto: &'a dyn Crypto,
    /// Optional stateless validator for the EXECUTE precompile.
    /// `None` on VMs that never dispatch EXECUTE (guest program, witness
    /// generation, the stateless validator itself) — those paths can't supply
    /// one without a dependency cycle or recursion.
    pub stateless_validator: Option<&'a dyn crate::StatelessValidator>,
}

/// secp256k1 group order `n`.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// secp256k1 `n / 2`.
const SECP256K1_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];
/// P-256 (secp256r1) group order `n`.
const SECP256R1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
/// P-256 (secp256r1) `n / 2`.
const SECP256R1_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// True when the big-endian 32-byte scalar is in `(0, upper)`.
fn scalar_below(scalar: &[u8], upper: &[u8; 32]) -> bool {
    scalar.iter().any(|&b| b != 0) && scalar < &upper[..]
}

/// True when the big-endian 32-byte scalar is in `(0, upper]`.
fn scalar_at_most(scalar: &[u8], upper: &[u8; 32]) -> bool {
    scalar.iter().any(|&b| b != 0) && scalar <= &upper[..]
}

/// Validate every EIP-8141 outer signature against the canonical `sig_hash`.
/// Returns false if any signature is malformed or invalid. Verification gas is
/// intrinsic (already in `standard_gas_limit`), so a scratch budget is used for the
/// crypto precompiles and their deduction is ignored.
#[expect(
    clippy::indexing_slicing,
    reason = "signature length is checked before each fixed-offset slice"
)]
pub fn validate_frame_signatures(
    signatures: &[ethrex_common::types::FrameSignature],
    sig_hash: ethrex_common::H256,
    sender: ethrex_common::Address,
    fork: Fork,
    crypto: &dyn Crypto,
) -> bool {
    use ethrex_common::types::{
        FRAME_SIG_SCHEME_ARBITRARY, FRAME_SIG_SCHEME_P256, FRAME_SIG_SCHEME_SECP256K1,
    };
    for sig in signatures {
        // Resolve the signed message.
        let msg: [u8; 32] = match sig.msg.len() {
            0 => sig_hash.0,
            32 => {
                let mut m = [0u8; 32];
                m.copy_from_slice(&sig.msg);
                if m == [0u8; 32] {
                    return false;
                }
                m
            }
            _ => return false,
        };
        let mut scratch_gas = u64::MAX;
        match sig.scheme {
            FRAME_SIG_SCHEME_SECP256K1 => {
                if sig.signature.len() != 65 {
                    return false;
                }
                let v = sig.signature[0];
                let r = &sig.signature[1..33];
                let s = &sig.signature[33..65];
                // EIP-8141 requires a canonical signature: `v` is a bare recovery
                // id (0 or 1), `0 < r < n`, and low-s per EIP-2 (`0 < s <= n/2`),
                // so each signature has exactly one encoding.
                if v > 1 || !scalar_below(r, &SECP256K1_N) || !scalar_at_most(s, &SECP256K1_N_HALF)
                {
                    return false;
                }
                // The ecrecover precompile takes `v` in EVM form (27 or 28).
                let mut calldata = vec![0u8; 128];
                calldata[..32].copy_from_slice(&msg);
                calldata[63] = v.saturating_add(27);
                calldata[64..96].copy_from_slice(r);
                calldata[96..128].copy_from_slice(s);
                let Ok(result) = crate::precompiles::ecrecover(
                    &Bytes::from(calldata),
                    &mut scratch_gas,
                    fork,
                    crypto,
                ) else {
                    return false;
                };
                if result.len() != 32 {
                    return false;
                }
                let recovered = ethrex_common::Address::from_slice(&result[12..]);
                if recovered == ethrex_common::Address::zero() {
                    return false;
                }
                // Per EIP-8141, an absent signer resolves to tx.sender (used for
                // introspection too); the recovered key must equal the resolved signer.
                if recovered != sig.signer.unwrap_or(sender) {
                    return false;
                }
            }
            FRAME_SIG_SCHEME_P256 => {
                if sig.signature.len() != 128 {
                    return false;
                }
                let r = &sig.signature[0..32];
                let s = &sig.signature[32..64];
                let qx = &sig.signature[64..96];
                let qy = &sig.signature[96..128];
                // EIP-8141 requires `0 < r < n` and low-s (`0 < s <= n/2`) so each
                // signature has one encoding. P256VERIFY itself accepts high-s, so
                // signers must normalize `s` to `n - s` before use.
                if !scalar_below(r, &SECP256R1_N) || !scalar_at_most(s, &SECP256R1_N_HALF) {
                    return false;
                }
                // signer = keccak256(qx || qy)[12:]  (NO domain separator)
                let mut pk = Vec::with_capacity(64);
                pk.extend_from_slice(qx);
                pk.extend_from_slice(qy);
                let h = ethrex_crypto::keccak::keccak_hash(&pk);
                // Per EIP-8141, an absent signer resolves to tx.sender (used for
                // introspection too); the derived key must equal the resolved signer.
                if ethrex_common::Address::from_slice(&h[12..]) != sig.signer.unwrap_or(sender) {
                    return false;
                }
                let mut calldata = vec![0u8; 160];
                calldata[..32].copy_from_slice(&msg);
                calldata[32..64].copy_from_slice(r);
                calldata[64..96].copy_from_slice(s);
                calldata[96..128].copy_from_slice(qx);
                calldata[128..160].copy_from_slice(qy);
                let Ok(result) = crate::precompiles::p_256_verify(
                    &Bytes::from(calldata),
                    &mut scratch_gas,
                    fork,
                    crypto,
                ) else {
                    return false;
                };
                if result.len() != 32 || result[31] != 1 {
                    return false;
                }
            }
            FRAME_SIG_SCHEME_ARBITRARY => {
                // ARBITRARY: no protocol crypto; the signer must be empty. A
                // custom verifier reads the raw bytes via SIGPARAM 0x04.
                if sig.signer.is_some() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Find the end of the atomic batch containing `failed_idx`, per EIP-8141:
/// a batch is a maximal contiguous run of frames whose ATOMIC_BATCH_FLAG is
/// set, terminated by the first frame without the flag. Static validation
/// guarantees no VERIFY frame carries the flag or terminates a batch, so every
/// frame in the returned range is DEFAULT or SENDER. Returns the index of the
/// batch's terminating frame.
///
/// Exposed (hidden) for the `ethrex-test` crate's frame-batch unit tests; not
/// part of the stable public API.
#[doc(hidden)]
pub fn find_batch_end(frames: &[Frame], failed_idx: usize) -> usize {
    frames
        .get(failed_idx..)
        .and_then(|rest| rest.iter().position(|f| !f.is_atomic_batch()))
        .map(|offset| failed_idx.saturating_add(offset))
        .unwrap_or(failed_idx)
}

impl<'a> VM<'a> {
    /// Constructs a VM, allocating a fresh 32 KB root call-frame stack.
    ///
    /// Hot block execution should prefer [`VM::new_pooled`], which draws the root stack from a
    /// reusable pool instead of allocating + zeroing one per transaction.
    pub fn new(
        env: Environment,
        db: &'a mut GeneralizedDatabase,
        tx: &'a Transaction,
        tracer: LevmCallTracer,
        vm_type: VMType,
        crypto: &'a dyn Crypto,
        stateless_validator: Option<&'a dyn crate::StatelessValidator>,
    ) -> Result<Self, VMError> {
        Self::new_with_root_stack(
            env,
            db,
            tx,
            tracer,
            vm_type,
            crypto,
            stateless_validator,
            Stack::default(),
            Memory::default(),
        )
    }

    /// Like [`VM::new`], but draws the root call-frame stack from `stack_pool` (falling back to a
    /// fresh `Stack::default()` only when the pool is empty) and adopts the remaining pooled
    /// stacks for sub-call frames. This avoids the per-tx 32 KB stack alloc+zero on a warm pool —
    /// the dominant allocation for transfer-heavy blocks, where the root frame is the only frame.
    ///
    /// Pair with [`VM::reclaim_into`] after execution to return every stack (root + sub-frame)
    /// to `stack_pool` and the root memory buffer to `memory_pool` so the next tx reuses them.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pooled(
        env: Environment,
        db: &'a mut GeneralizedDatabase,
        tx: &'a Transaction,
        tracer: LevmCallTracer,
        vm_type: VMType,
        crypto: &'a dyn Crypto,
        stateless_validator: Option<&'a dyn crate::StatelessValidator>,
        stack_pool: &mut Vec<Stack>,
        memory_pool: &mut Vec<Memory>,
    ) -> Result<Self, VMError> {
        // Reuse a pooled stack for the root frame. `clear()` only resets the offset (no zeroing),
        // which is sound because the EVM never reads stack slots it didn't write — the same
        // invariant that already makes sub-frame pooling safe.
        let mut root_stack = stack_pool.pop().unwrap_or_default();
        root_stack.clear();
        // Reuse a pooled root memory buffer (capacity retained from a prior tx, contents dropped).
        // `reclaim_into` truncates it to length 0, so `resize`'s zero-fill invariant holds. Only
        // the root buffer is pooled: sub-frame memories are `Rc` clones of it (`next_memory`).
        let mut root_memory = memory_pool.pop().unwrap_or_default();
        root_memory.reset_for_reuse();
        let mut vm = Self::new_with_root_stack(
            env,
            db,
            tx,
            tracer,
            vm_type,
            crypto,
            stateless_validator,
            root_stack,
            root_memory,
        )?;
        // Adopt the caller's pooled stacks for sub-frames; returned via `reclaim_into`.
        mem::swap(&mut vm.stack_pool, stack_pool);
        Ok(vm)
    }

    /// Returns this VM's reusable buffers to the caller's pools so the next transaction reuses
    /// them instead of allocating: every stack (root call-frame stack plus any sub-frame stacks
    /// still pooled internally) to `stack_pool`, and the root memory buffer to `memory_pool`.
    /// Must run on both the success and error paths of [`VM::execute`].
    pub fn reclaim_into(mut self, stack_pool: &mut Vec<Stack>, memory_pool: &mut Vec<Memory>) {
        // Hand the internal sub-frame pool back to the caller first.
        mem::swap(&mut self.stack_pool, stack_pool);
        // Then reclaim the root frame's stack. Moving it out by value (VM/CallFrame have no Drop)
        // avoids leaving a fresh 32 KB `Stack::default()` placeholder behind — which a
        // `mem::take`/`mem::replace` against an empty pool would force, defeating the win on
        // exactly the transfer-only blocks (no sub-frames ever seed the pool) we target.
        let mut root_stack = self.current_call_frame.stack;
        root_stack.clear();
        stack_pool.push(root_stack);
        // Reclaim the root memory buffer with its grown capacity. `reset_for_reuse` truncates it
        // to length 0 (capacity kept) so the next tx's `resize` zero-fills correctly.
        //
        // Every call frame shares the same `Rc<RefCell<Vec<u8>>>` buffer, so on the error path the
        // ancestor frames left in `call_frames` (error propagation unwinds out of `execute` without
        // popping them) still hold clones. Drop them first so the buffer is `Rc`-unique on BOTH
        // paths before we clear it — otherwise the clear would propagate to a frame still holding a
        // reference. `CallFrame` has no `Drop` and these frames are never read again, so dropping
        // them early is free.
        self.call_frames.clear();
        let mut root_memory = self.current_call_frame.memory;
        debug_assert_eq!(
            Rc::strong_count(&root_memory.buffer),
            1,
            "root memory buffer must be Rc-unique at reclaim; a frame is still holding it and \
             would observe the reset_for_reuse clear",
        );
        root_memory.reset_for_reuse();
        memory_pool.push(root_memory);
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_root_stack(
        env: Environment,
        db: &'a mut GeneralizedDatabase,
        tx: &'a Transaction,
        tracer: LevmCallTracer,
        vm_type: VMType,
        crypto: &'a dyn Crypto,
        stateless_validator: Option<&'a dyn crate::StatelessValidator>,
        root_stack: Stack,
        root_memory: Memory,
    ) -> Result<Self, VMError> {
        db.tx_backup = None; // If BackupHook is enabled, it will contain backup at the end of tx execution.

        let mut substate = Substate::initialize(&env, tx)?;

        let (callee, is_create) = Self::get_tx_callee(tx, db, &env, &mut substate)?;

        let fork = env.config.fork;

        #[expect(
            clippy::arithmetic_side_effects,
            reason = "byte-count constants are small (<200) and cpsb is bounded by block_gas_limit/year formula"
        )]
        let (cpsb, state_gas_new_account, state_gas_storage_set, state_gas_auth_base) =
            if fork >= Fork::Amsterdam {
                let cpsb = compute_cost_per_state_byte(env.block_gas_limit);
                (
                    cpsb,
                    STATE_BYTES_PER_NEW_ACCOUNT * cpsb,
                    STATE_BYTES_PER_STORAGE_SET * cpsb,
                    STATE_BYTES_PER_AUTH_BASE * cpsb,
                )
            } else {
                (0, 0, 0, 0)
            };

        // Derive whether the top-level backup must be preserved from the installed hooks rather
        // than from `vm_type`. The flag's real meaning is "a hook reads the top-level backup in
        // `finalize_execution`," which today is the `BackupHook` on L2 / stateless. Deriving it
        // keeps the flag correct if hook wiring ever changes (e.g. a future `vm_type` that adds
        // `BackupHook`, or L2 dropping it), and `add_hook` keeps it in sync for the `BackupHook`
        // that `stateless_execute` installs after construction. L1 block execution installs no
        // `BackupHook` (see `l1_hooks`), so the backup is dead once the cache is restored.
        let hooks = get_hooks(&vm_type);
        let preserve_top_level_backup = hooks
            .iter()
            .any(|hook| hook.borrow().reads_top_level_backup());

        let mut vm = Self {
            call_frames: Vec::new(),
            substate,
            db,
            tx,
            hooks,
            storage_original_values: FxHashMap::default(),
            tracer,
            opcode_tracer: LevmOpcodeTracer::disabled(),
            validation_observer: ValidationObserver::disabled(),
            debug_mode: DebugMode::disabled(),
            stack_pool: Vec::new(),
            vm_type,
            preserve_top_level_backup,
            state_gas_used: 0,
            state_gas_reservoir: 0,
            state_gas_reservoir_initial: 0,
            state_gas_spill: 0,
            cost_per_state_byte: cpsb,
            state_gas_new_account,
            state_gas_storage_set,
            state_gas_auth_base,
            intrinsic_state_gas: 0,
            value_new_account_charged: false,
            prep_baseline_state_gas: 0,
            prep_baseline_reservoir: 0,
            prep_baseline_state_gas_spill: 0,
            prep_region_backup_marker: PrepareRegionBackupMarker::default(),
            pending_prep_oog: false,
            current_call_frame: CallFrame::new(
                env.origin,
                callee,
                Address::default(), // Will be assigned at the end of prepare_execution
                Code::default(),    // Will be assigned at the end of prepare_execution
                tx.value(),
                tx.data().clone(),
                false,
                env.gas_limit,
                0,
                true,
                is_create,
                0,
                0,
                root_stack,
                root_memory,
            ),
            env,
            frame_tx_context: None,
            opcode_table: VM::build_opcode_table(fork),
            crypto,
            stateless_validator,
        };

        let call_type = if is_create {
            CallType::CREATE
        } else {
            CallType::CALL
        };
        vm.tracer.enter(
            call_type,
            vm.env.origin,
            callee,
            vm.tx.value(),
            vm.env.gas_limit,
            vm.tx.data(),
        );

        #[cfg(feature = "debug")]
        {
            // Enable debug mode for printing in Solidity contracts.
            vm.debug_mode.enabled = true;
        }

        Ok(vm)
    }

    fn add_hook(&mut self, hook: impl Hook + 'static) {
        // Keep `preserve_top_level_backup` in sync: a hook added after construction (e.g. the
        // `BackupHook` in `stateless_execute`) may read the top-level backup in `finalize_execution`.
        self.preserve_top_level_backup |= hook.reads_top_level_backup();
        self.hooks.push(Rc::new(RefCell::new(hook)));
    }

    /// EIP-8037: Charge state gas, drawing from reservoir first, spilling to gas_remaining if exhausted.
    ///
    /// Must only be called for Amsterdam+ forks. All call sites must guard with
    /// `fork >= Fork::Amsterdam` before invoking this method.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "arithmetic proven safe by min()"
    )]
    pub fn increase_state_gas(&mut self, gas: u64) -> Result<(), VMError> {
        debug_assert!(
            self.env.config.fork >= Fork::Amsterdam,
            "increase_state_gas called pre-Amsterdam"
        );
        // Draw from reservoir first; only spill to gas_remaining if reservoir exhausted
        let from_reservoir = self.state_gas_reservoir.min(gas);
        // Safe: from_reservoir <= gas
        let spill = gas - from_reservoir;
        if spill > 0 {
            // Charge spill from gas_remaining first — if OOG, return early
            // without mutating reservoir or state_gas_used (matches EELS behavior)
            self.current_call_frame.increase_consumed_gas(spill)?;
        }
        // Safe: from_reservoir = min(reservoir, gas) so reservoir >= from_reservoir
        self.state_gas_reservoir -= from_reservoir;
        // Only increment state_gas_used AFTER the charge succeeds.
        // state_gas_used is i64; tx gas_limit caps charges well below i64::MAX.
        self.state_gas_used = self
            .state_gas_used
            .checked_add(i64::try_from(gas).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        // Track the spill for block-accounting: EELS charge_state_gas spills
        // don't count toward regular_gas_used for the regular dimension.
        self.state_gas_spill = self
            .state_gas_spill
            .checked_add(spill)
            .ok_or(InternalError::Overflow)?;
        // Per-frame spill: EELS charge_state_gas does `frame_state_gas_spilled += remainder`.
        // LIFO refund source; propagated to parent on child success.
        self.current_call_frame.frame_state_gas_spilled = self
            .current_call_frame
            .frame_state_gas_spilled
            .checked_add(spill)
            .ok_or(InternalError::Overflow)?;
        Ok(())
    }

    /// EIP-8037 `credit_state_gas_refund`: refund `amount` LIFO, mirroring EELS. The portion
    /// spilled past the reservoir into this frame's `gas_remaining` (`frame_state_gas_spilled`)
    /// is returned to `gas_remaining` first; only the remainder flows to the shared reservoir.
    /// `state_gas_used` drops by the full `amount` (may go negative when the matching charge lives
    /// in an ancestor frame). Block accounting: both spill counters drop by the
    /// `gas_remaining`-credited portion only, never the full `amount`. Amsterdam+ only.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "subtractions proven safe by min()"
    )]
    pub fn credit_state_gas_refund(&mut self, amount: u64) -> Result<(), VMError> {
        debug_assert!(
            self.env.config.fork >= Fork::Amsterdam,
            "credit_state_gas_refund called pre-Amsterdam"
        );
        // LIFO: drain the frame's spill (gas borrowed from gas_remaining) first.
        let from_gas_left = self.current_call_frame.frame_state_gas_spilled.min(amount);
        // Return the spilled portion to gas_remaining (i64).
        self.current_call_frame.gas_remaining = self
            .current_call_frame
            .gas_remaining
            .checked_add(i64::try_from(from_gas_left).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        // Safe: from_gas_left = min(spill, amount) <= frame_state_gas_spilled.
        self.current_call_frame.frame_state_gas_spilled -= from_gas_left;
        // Block accounting: the refilled spill is no longer regular gas.
        self.state_gas_spill = self
            .state_gas_spill
            .checked_sub(from_gas_left)
            .ok_or(InternalError::Underflow)?;
        // The remainder of the refund flows into the shared reservoir.
        // Safe: from_gas_left = min(spill, amount) <= amount.
        let to_reservoir = amount - from_gas_left;
        self.state_gas_reservoir = self
            .state_gas_reservoir
            .checked_add(to_reservoir)
            .ok_or(InternalError::Overflow)?;
        // state_gas_used always drops by the full amount (may go negative).
        self.state_gas_used = self
            .state_gas_used
            .checked_sub(i64::try_from(amount).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        Ok(())
    }

    /// Refund the EIP-8037 new-account state gas when `charged` is true. Used by the
    /// CALL paths where a value-bearing call to an empty account charged the new-account
    /// state gas but no account ends up created (insufficient balance, max depth, child
    /// revert / failed precompile).
    #[inline]
    pub fn refund_new_account_state_gas(&mut self, charged: bool) -> Result<(), VMError> {
        if charged {
            self.credit_state_gas_refund(self.state_gas_new_account)?;
        }
        Ok(())
    }

    /// EIP-8037 `repay_state_gas_spill` (EELS `incorporate_child`, success arm): once a
    /// successful child's gas has merged into this frame, the reservoir repays the spill
    /// still outstanding, up to what the reservoir holds.
    ///
    /// A refund can land in a different frame than the charge it undoes: the refunding
    /// frame's spill may be smaller than the refund, so the excess credits the reservoir
    /// even though the charge drew from `gas_remaining`. The merge is where the claim
    /// (this frame's spill) and the credit (the reservoir) first share a frame, so that
    /// is where the two pools settle between themselves.
    ///
    /// No state creation is undone, so `state_gas_used` does not move: the gas only
    /// crosses back between the pools it drifted across. Both settlements stay
    /// unchanged, which is what makes this repayment billing-neutral:
    /// - user gas (`gas_limit - gas_remaining - state_gas_reservoir`) is unchanged
    ///   because `gas_remaining` rises by exactly what the reservoir loses;
    /// - the EIP-7778 regular dimension subtracts the cumulative `state_gas_spill`, so
    ///   that counter drops by the repayment too — the reservoir (the state dimension)
    ///   covered the charge after all, so it must stop being billed as regular gas.
    ///
    /// A failed child repays nothing: its rollback already restored the state whose
    /// removal any refund credited.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "subtractions proven safe by min()"
    )]
    pub fn repay_state_gas_spill(&mut self) -> Result<(), VMError> {
        debug_assert!(
            self.env.config.fork >= Fork::Amsterdam,
            "repay_state_gas_spill called pre-Amsterdam"
        );
        let repayment = self
            .state_gas_reservoir
            .min(self.current_call_frame.frame_state_gas_spilled);
        if repayment == 0 {
            return Ok(());
        }
        self.current_call_frame.gas_remaining = self
            .current_call_frame
            .gas_remaining
            .checked_add(i64::try_from(repayment).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        // Safe: repayment = min(reservoir, frame spill) <= both.
        self.state_gas_reservoir -= repayment;
        self.current_call_frame.frame_state_gas_spilled -= repayment;
        // Block accounting: every frame spill is mirrored in the cumulative counter, so
        // it covers this repayment (`checked_sub` guards the invariant regardless).
        self.state_gas_spill = self
            .state_gas_spill
            .checked_sub(repayment)
            .ok_or(InternalError::Underflow)?;
        // EELS asserts the claim and the credit cannot both survive a repayment.
        debug_assert!(
            self.state_gas_reservoir == 0 || self.current_call_frame.frame_state_gas_spilled == 0
        );
        Ok(())
    }

    /// EIP-8037 `refill_frame_state_gas`: roll back this frame's state gas in LIFO
    /// order on revert or exceptional halt, mirroring EELS `refill_frame_state_gas`.
    ///
    /// `entry` is the value of `state_gas_used` when this frame began executing
    /// (`current_call_frame.state_gas_used_at_entry`). The frame's net charge is
    /// `frame_used = state_gas_used - entry`. Of that, `frame_state_gas_spilled` was
    /// drawn from `gas_remaining` (spilled past the reservoir) and the remainder came
    /// from the reservoir. LIFO refill returns the spilled portion to `gas_remaining`
    /// first and the rest to the reservoir, restoring the exact pools the charges drew
    /// from. `state_gas_used` is rolled back to `entry` and the per-frame spill counter
    /// is cleared.
    ///
    /// Revert-vs-halt equivalence (load-bearing): on revert, the spilled gas returns to
    /// `gas_remaining` (raising the sender refund / lowering raw_consumed) while
    /// `state_gas_spill` drops by the same amount, so the regular dimension in
    /// `refund_sender` (default_hook) drops by exactly the refilled spill. On exceptional
    /// halt the caller subsequently sets `gas_remaining = 0` and burns it to the regular
    /// dimension — but `state_gas_spill` was already decremented here, so the spilled gas
    /// stays counted as regular. Both paths are correct.
    ///
    /// Must only be called for Amsterdam+ forks.
    pub fn refill_frame_state_gas(&mut self, entry: i64) -> Result<(), VMError> {
        debug_assert!(
            self.env.config.fork >= Fork::Amsterdam,
            "refill_frame_state_gas called pre-Amsterdam"
        );
        // The frame's net state-gas charge since it began executing. May be
        // negative when the frame's inline refunds (e.g. an SSTORE clearing a
        // slot an ancestor set) exceeded its own gross charges.
        let frame_used = self
            .state_gas_used
            .checked_sub(entry)
            .ok_or(InternalError::Underflow)?;
        let spilled = self.current_call_frame.frame_state_gas_spilled;
        // LIFO invariant: any remaining spill is undrained own-charge, so it
        // implies frame_used >= 0. A net-negative frame_used only arises after
        // credit_state_gas_refund has already drained all spill (spilled == 0).
        debug_assert!(
            frame_used >= 0 || spilled == 0,
            "negative frame_used with positive spill violates LIFO invariant \
             (frame_used={frame_used}, spilled={spilled})"
        );
        // LIFO: return the spilled portion (borrowed from gas_remaining) first.
        self.current_call_frame.gas_remaining = self
            .current_call_frame
            .gas_remaining
            .checked_add(i64::try_from(spilled).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        // The remainder (drawn from the reservoir) flows back to the reservoir.
        let to_reservoir = frame_used
            .checked_sub(i64::try_from(spilled).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        // `to_reservoir` is negative in the cross-ancestor refund case
        // (frame_used < 0); clamp so the reservoir never goes negative.
        let reservoir_signed =
            i64::try_from(self.state_gas_reservoir).map_err(|_| InternalError::Overflow)?;
        self.state_gas_reservoir = u64::try_from(
            reservoir_signed
                .checked_add(to_reservoir)
                .ok_or(InternalError::Overflow)?
                .max(0),
        )
        .map_err(|_| InternalError::Overflow)?;
        // Roll back state_gas_used to the frame's entry baseline.
        self.state_gas_used = entry;
        // Block accounting: the refilled spill is no longer regular gas.
        self.state_gas_spill = self
            .state_gas_spill
            .checked_sub(spilled)
            .ok_or(InternalError::Underflow)?;
        self.current_call_frame.frame_state_gas_spilled = 0;
        Ok(())
    }

    /// EIP-8037: enters the atomic prepare region (EELS `interpreter.py`'s depth-0
    /// `try` around `set_delegation` + `prepare_dispatch`, `interpreter.py:353-375`).
    /// Must be called in `prepare_execution`, after the sender nonce bump and fee
    /// deduction (those survive a region rollback) but before the type-4 auth
    /// handling (the first region charge). Captures the pre-region state-gas
    /// baseline and the `call_frame_backup` key-space so `fail_prepare_region` can
    /// later undo exactly the region's writes.
    pub fn enter_prepare_region(&mut self) {
        self.prep_baseline_state_gas = self.current_call_frame.state_gas_used_at_entry;
        self.prep_baseline_reservoir = self.state_gas_reservoir;
        self.prep_baseline_state_gas_spill = self.state_gas_spill;
        let backup = &self.current_call_frame.call_frame_backup;
        let accounts: FxHashSet<Address> = backup.original_accounts_info.keys().copied().collect();
        let storage: FxHashSet<Address> = backup
            .original_account_storage_slots
            .keys()
            .copied()
            .collect();
        let code_hashes_len = backup.inserted_code_hashes.len();
        // Capture the region-entry state of every already-backed-up account so a
        // self-sponsored EIP-7702 authorization (or any in-region write to a
        // pre-region-touched account) can be reverted without disturbing its
        // pre-region nonce/fee writes. See `PrepareRegionBackupMarker::entry_state`.
        let entry_state: FxHashMap<Address, LevmAccount> = accounts
            .iter()
            .filter_map(|address| {
                self.db
                    .current_accounts_state
                    .get(address)
                    .map(|account| (*address, account.clone()))
            })
            .collect();
        let bal_checkpoint = self.db.bal_recorder.as_ref().map(|r| r.checkpoint());
        self.prep_region_backup_marker = PrepareRegionBackupMarker {
            accounts,
            storage,
            code_hashes_len,
            entry_state,
            bal_checkpoint,
        };
    }

    /// EIP-8037: rolls back the atomic prepare region on an internal OOG from any of
    /// its charges (7702 auth, CREATE/value `NEW_ACCOUNT`, recipient delegation-resolve).
    /// Restores every `call_frame_backup` entry added since `enter_prepare_region`
    /// (leaving the earlier sender nonce-bump / fee-deduction entries untouched),
    /// refills the frame's state gas back to the pre-region baseline, and sets
    /// `pending_prep_oog` so `run_execution` turns this into a full-gas revert
    /// instead of a tx-level rejection `Err` (which would wrongly invalidate the
    /// block). Mirrors EELS `restore_tx_state(prep_snapshot)` + `refill_frame_state_gas`
    /// (`interpreter.py:366-374`).
    pub fn fail_prepare_region(&mut self) {
        let marker = std::mem::take(&mut self.prep_region_backup_marker);
        let mut backup = std::mem::take(&mut self.current_call_frame.call_frame_backup);

        // Restore + drop every account backup entry added during the region.
        let region_accounts: Vec<Address> = backup
            .original_accounts_info
            .keys()
            .filter(|address| !marker.accounts.contains(*address))
            .copied()
            .collect();
        for address in region_accounts {
            if let Some(account) = backup.original_accounts_info.remove(&address)
                && let Some(current_account) = self.db.current_accounts_state.get_mut(&address)
            {
                current_account.info = account.info;
                current_account.status = account.status;
                current_account.has_storage = account.has_storage;
                current_account.exists = account.exists;
            }
        }

        // Restore + drop every storage backup entry added during the region.
        let region_storage: Vec<Address> = backup
            .original_account_storage_slots
            .keys()
            .filter(|address| !marker.storage.contains(*address))
            .copied()
            .collect();
        for address in region_storage {
            if let Some(slots) = backup.original_account_storage_slots.remove(&address)
                && let Some(current_account) = self.db.current_accounts_state.get_mut(&address)
            {
                for (key, value) in slots {
                    current_account.storage.insert(key, value);
                }
            }
        }

        // Evict codes the region inserted, mirroring `restore_cache_state`: a stale
        // by-hash cache entry would hide a later read of the same hash from the store.
        for code_hash in backup
            .inserted_code_hashes
            .split_off(marker.code_hashes_len)
        {
            self.db.codes.remove(&code_hash);
        }

        self.current_call_frame.call_frame_backup = backup;

        // Revert in-region writes to accounts that were already backed up before the
        // region (the marker filter above leaves these untouched to preserve their
        // pre-region nonce/fee writes, but first-write-wins backup means an in-region
        // write — e.g. a self-sponsored EIP-7702 authorization writing the sender's
        // delegation code + auth nonce bump — created no new backup entry). Restoring
        // to the region-entry snapshot undoes the in-region write while keeping the
        // pre-region writes baked into that snapshot. Mirrors EELS `restore_tx_state`.
        for (address, entry_account) in marker.entry_state {
            if let Some(current) = self.db.current_accounts_state.get_mut(&address) {
                current.info = entry_account.info;
                current.status = entry_account.status;
                current.has_storage = entry_account.has_storage;
                current.exists = entry_account.exists;
            }
        }

        // Roll back the BAL recorder to region entry so an applied-then-reverted
        // delegation's code/nonce changes are discarded (demoted to an access-only
        // touch, matching EELS `restore_tx_state`). `restore` preserves touched
        // addresses — including the pre-charge authority touches recorded during
        // `set_delegation` — so a reverted authority still appears as an access.
        if let Some(checkpoint) = marker.bal_checkpoint
            && let Some(recorder) = self.db.bal_recorder.as_mut()
        {
            recorder.restore(checkpoint);
        }

        // Rewind the state-gas machinery to the pre-region snapshot. The
        // `set_delegation` auth lock-in re-seeds `state_gas_used_at_entry` and zeroes
        // the frame spill, so `refill_frame_state_gas` (which derives the reservoir
        // credit from the frame spill) would leave the reservoir over-credited by the
        // locked-in auth state gas. Restore `state_gas_used`, the reservoir, and the
        // cumulative spill to the values captured by `enter_prepare_region`, and clear
        // the frame spill — this fully reverts the region's state charges (auth +
        // prepare-dispatch) regardless of the lock-in. Mirrors EELS
        // `restore_tx_state(prep_snapshot)` + `message.state_gas_reservoir = prep_reservoir`
        // (`interpreter.py:365-369`). `gas_remaining` is left as-is: the failing charge
        // already drove it negative, so `run_execution` burns all gas (EELS
        // `evm.regular_gas_used += evm.gas_left; evm.gas_left = 0`).
        self.state_gas_used = self.prep_baseline_state_gas;
        self.state_gas_reservoir = self.prep_baseline_reservoir;
        self.state_gas_spill = self.prep_baseline_state_gas_spill;
        self.current_call_frame.frame_state_gas_spilled = 0;
        self.pending_prep_oog = true;
    }

    /// Executes a whole external transaction. Performing validations at the beginning.
    pub fn execute(&mut self) -> Result<ExecutionReport, VMError> {
        // Detect frame transaction and branch to specialized execution
        if self.tx.tx_type() == TxType::Frame {
            return self.execute_frame_tx();
        }

        if let Err(e) = self.prepare_execution() {
            // Restore cache to state previous to this Tx execution because this Tx is invalid.
            // Consume the backup unless a `BackupHook` will read it (L2 / stateless); on L1 it
            // is dead once the cache is restored.
            if self.preserve_top_level_backup {
                self.restore_cache_state()?;
            } else {
                self.restore_cache_state_consuming()?;
            }
            return Err(e);
        }

        // Clear callframe backup so that changes made in prepare_execution are written in stone.
        // We want to apply these changes even if the Tx reverts. E.g. Incrementing sender nonce
        self.current_call_frame.call_frame_backup.clear();

        // Empty bytecode would only execute STOP; skip the dispatch loop.
        // The BAL checkpoint below is intentionally skipped: a codeless transfer cannot
        // fail past this point and has no inner calls, so there's nothing to roll back.
        if self.is_simple_transfer_fast_path() {
            // EIP-8037: no `refill_frame_state_gas` needed here — a codeless transfer always
            // succeeds, runs no opcodes, and charges no execution state gas, so the frame's
            // `frame_state_gas_spilled` is 0 and `state_gas_used` equals its entry baseline.
            #[expect(clippy::as_conversions, reason = "gas_remaining is non-negative here")]
            let gas_used = self
                .current_call_frame
                .gas_limit
                .checked_sub(self.current_call_frame.gas_remaining as u64)
                .ok_or(InternalError::Underflow)?;
            let context_result = ContextResult {
                result: TxResult::Success,
                gas_used,
                gas_spent: gas_used,
                output: Bytes::new(),
            };
            return self.finalize_execution(context_result);
        }

        // EIP-7928: Take a BAL checkpoint AFTER clearing the backup. This captures the state
        // after prepare_execution (nonce increment, etc.) but before actual execution.
        // When the top-level call fails, we restore to this checkpoint so that inner call
        // state changes (like value transfers) are reverted from the BAL.
        self.current_call_frame.call_frame_backup.bal_checkpoint =
            self.db.bal_recorder.as_ref().map(|r| r.checkpoint());

        // EIP-8037: skip the CREATE nonce bump / endowment / collision check when the
        // atomic prepare region OOG'd (`pending_prep_oog`). EELS raises in
        // `prepare_dispatch` before `process_create_message` runs, so the contract is
        // never created — `run_execution` below emits the full-gas revert. Bumping the
        // nonce here would leave a phantom nonce=1 the region rollback can't reach.
        if !self.pending_prep_oog && self.is_create()? {
            // Create contract, reverting the Tx if address is already occupied.
            if let Some(context_result) = self.handle_create_transaction()? {
                let report = self.finalize_execution(context_result)?;
                return Ok(report);
            }
        }

        self.substate.push_backup();
        let context_result = self.run_execution()?;

        let report = self.finalize_execution(context_result)?;

        Ok(report)
    }

    /// Execute a frame transaction (EIP-8141).
    /// This bypasses the normal prepare/finalize hooks and orchestrates per-frame execution.
    fn execute_frame_tx(&mut self) -> Result<ExecutionReport, VMError> {
        use crate::errors::TxResult;

        // EIP-8141 fork gating: reject frame transactions observed in a block or
        // submitted to any non-mempool entry point before Hegota activates.
        if self.env.config.fork < Fork::Hegota {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::FrameTxPreFork,
            ));
        }

        let frame_tx = match &self.tx {
            Transaction::FrameTransaction(ft) => ft.clone(),
            _ => unreachable!(),
        };

        // Simplified validation (skip balance deduction, nonce increment, value transfer, EOA check)
        // Keep: gas limit checks, fee validation, nonce mismatch check.
        // The EOA-check skip is required by EIP-8141 §Transaction origination:
        // EIP-3607 must not apply to frame transactions, so the sender may have
        // contract code (SENDER frames legitimately originate from contract
        // accounts).
        let sender = frame_tx.sender;

        // Validate static constraints (frame count, reserved modes, atomic batch flags)
        if let Err(_e) = frame_tx.validate_static_constraints() {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InvalidFrameTransaction,
            ));
        }

        // Check nonce matches
        let sender_info = self.db.get_account(sender)?.info.clone();
        if sender_info.nonce != frame_tx.nonce {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::NonceMismatch {
                    expected: sender_info.nonce,
                    actual: frame_tx.nonce,
                },
            ));
        }

        // Check priority fee <= max fee
        if frame_tx.max_priority_fee_per_gas > frame_tx.max_fee_per_gas {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::PriorityGreaterThanMaxFeePerGas {
                    priority_fee: U256::from(frame_tx.max_priority_fee_per_gas),
                    max_fee_per_gas: U256::from(frame_tx.max_fee_per_gas),
                },
            ));
        }

        // Check max_fee >= base_fee
        if U256::from(frame_tx.max_fee_per_gas) < self.env.base_fee_per_gas {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InsufficientMaxFeePerGas,
            ));
        }

        // EIP-4844 INSUFFICIENT_MAX_FEE_PER_BLOB_GAS: a blob-carrying tx whose
        // max_fee_per_blob_gas is below the block's base blob fee is invalid. The
        // frame path is self-contained and never runs the default hook's
        // validate_max_fee_per_blob_gas, so it is enforced here. APPROVE charges
        // the blob fee at the base rate unconditionally, so without this a frame tx
        // below the base blob fee would execute and silently overpay rather than be
        // rejected — a divergence from a conformant client that rejects it.
        if !frame_tx.blob_versioned_hashes.is_empty()
            && frame_tx.max_fee_per_blob_gas < self.env.base_blob_fee_per_gas
        {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InsufficientMaxFeePerBlobGas {
                    base_fee_per_blob_gas: self.env.base_blob_fee_per_gas,
                    tx_max_fee_per_blob_gas: frame_tx.max_fee_per_blob_gas,
                },
            ));
        }

        // Initialize FrameTxContext
        let sig_hash = frame_tx.compute_sig_hash();
        let max_gas = frame_tx.max_gas();
        self.frame_tx_context = Some(FrameTxContext {
            sender_approved: false,
            payer_address: None,
            frame_results: Vec::new(),
            current_frame_index: 0,
            sig_hash,
            tx: frame_tx.clone(),
            approve_called_in_current_frame: false,
            max_gas,
            blob_base_fee: self.env.base_blob_fee_per_gas,
        });

        // EIP-8141: every outer signature must validate
        // before any frame executes; otherwise the whole transaction is invalid.
        if !validate_frame_signatures(
            &frame_tx.signatures,
            sig_hash,
            frame_tx.sender,
            self.env.config.fork,
            self.crypto,
        ) {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InvalidFrameTransaction,
            ));
        }

        // Tx-level rollback accumulator: if the tx is later declared invalid
        // after frames committed, restore `db.current_accounts_state` so the
        // payload builder (which reuses the shared db across txs) sees no
        // residue — same Err contract as non-frame `execute()`. The per-frame
        // backup is cleared between independent frames (and at batch entry), so
        // each frame's original values are absorbed here (first-seen-wins)
        // before that clear destroys them. Substate is per-VM and discarded on
        // Err, so it needs no snapshot.
        let mut tx_level_backup = crate::call_frame::CallFrameBackup {
            bal_checkpoint: self.db.bal_recorder.as_ref().map(|r| r.checkpoint()),
            ..Default::default()
        };

        // ENTRY_POINT address used as caller for DEFAULT/VERIFY frames
        let entry_point = ethrex_common::types::frame_tx_entry_point();

        let mut all_logs: Vec<Log> = Vec::new();
        let sum_frame_gas_limits: u64 = frame_tx
            .frames
            .iter()
            .map(|f| f.gas_limit)
            .fold(0u64, |acc, g| acc.saturating_add(g));
        // The non-frame part of `standard_gas_limit`, not of `max_gas`: when the
        // calldata floor dominates, the extra reservation is not intrinsic gas and
        // is applied once at settlement instead.
        let intrinsic_gas = frame_tx
            .mandatory_gas()
            .saturating_add(frame_tx.data_cost());
        let mut total_gas_used: u64 = intrinsic_gas;
        let mut tx_invalid = false;

        // Atomic batching state: track whether we're inside a batch and
        // which frames belong to it so we can revert them all on failure.
        let mut in_atomic_batch = false;
        let mut batch_start_idx: usize = 0;
        let mut batch_logs_start: usize = 0;
        let mut batch_approval_snapshot: (bool, Option<Address>) = (false, None);
        let mut batch_bal_checkpoint: Option<BlockAccessListCheckpoint> = None;
        // EIP-8037: snapshot the shared `state_gas_used` at batch entry so a batch
        // revert (which unrolls every in-batch frame's state) also drops the state
        // gas those frames accumulated.
        let mut state_gas_used_at_batch_entry: i64 = 0;
        let mut skip_until_batch_end: Option<usize> = None; // skip remaining frames in a failed batch

        // Execute frames sequentially
        for (frame_idx, frame) in frame_tx.frames.iter().enumerate() {
            // If we're skipping frames due to an atomic batch revert, record
            // the frame with status SKIPPED. Per EIP-8141, the
            // gas allotted to skipped frames is refunded at the end of the
            // transaction, so we record `gas_used = 0` and do NOT add the
            // frame's `gas_limit` to `total_gas_used`.
            //
            // Note (EIP-8141): an expiry verifier frame has flags
            // == 0, so it can only be a batch TERMINATOR, never a flagged
            // member. A failed batch therefore skips a trailing expiry frame
            // and its deadline is not checked at execution time. This is
            // benign, not a bypass: `compute_sig_hash` commits to the full
            // frame layout (modes, flags incl. the atomic-batch flag, targets,
            // and the expiry deadline), and the VERIFY signature is recovered
            // over that hash — so no relayer/proposer can wrap a signed tx's
            // expiry frame in a failing batch. Only the sender can build this
            // layout, and doing so merely disarms their own expiry. The normal
            // pattern (a standalone expiry VERIFY frame, not batched) is fully
            // enforced. The skip itself is spec-mandated batch semantics; do
            // not change it unilaterally — that would be a consensus divergence.
            if let Some(end_idx) = skip_until_batch_end {
                if frame_idx <= end_idx {
                    let ctx = self.frame_tx_context.as_mut().ok_or(VMError::Internal(
                        InternalError::Custom("missing frame tx context".to_string()),
                    ))?;
                    ctx.current_frame_index = frame_idx;
                    ctx.frame_results.push((
                        ethrex_common::types::FRAME_RECEIPT_STATUS_SKIPPED,
                        0,
                        Vec::new(),
                    ));
                    if frame_idx == end_idx {
                        skip_until_batch_end = None;
                        in_atomic_batch = false;
                    }
                    continue;
                }
                skip_until_batch_end = None;
                in_atomic_batch = false;
            }

            // Clear the outer call-frame backup at the start of each independent
            // frame so that a later frame's failure-path `restore_cache_state()`
            // only reverts that frame's own effects — not APPROVE/state deltas
            // produced by earlier, already-successful frames. Inside an open
            // atomic batch we keep accumulating, since a batch revert needs to
            // undo every in-batch frame's effects together.
            if !in_atomic_batch {
                // Absorb this frame's originals into the tx-level accumulator
                // before clearing, so an invalid-tx exit can still roll back
                // every committed frame's state (see `tx_level_backup`).
                tx_level_backup.absorb(&self.current_call_frame.call_frame_backup);
                self.current_call_frame.call_frame_backup.clear();
            }

            // Start a new atomic batch if this frame has the batch flag
            // and we're not already in one.
            if !in_atomic_batch && frame.is_atomic_batch() {
                self.substate.push_backup(); // batch-level snapshot
                // EIP-7928: the batch's state changes must leave the block access
                // list as well when the batch unrolls, or the builder records
                // writes the block does not contain and the block fails its own
                // BAL validation on re-execution.
                batch_bal_checkpoint = self.db.bal_recorder.as_ref().map(|r| r.checkpoint());
                // The outer call-frame backup is already empty here: the
                // `!in_atomic_batch` block above absorbed it into
                // `tx_level_backup` and cleared it on entry to this frame, so
                // the batch starts accumulating a clean, self-contained set of
                // state changes that batch-revert can undo wholesale.
                in_atomic_batch = true;
                batch_start_idx = frame_idx;
                batch_logs_start = all_logs.len();
                state_gas_used_at_batch_entry = self.state_gas_used;
                // Snapshot approvals at batch entry: a batch revert must also
                // roll back approvals granted inside the batch (their balance
                // and nonce effects are reverted with the substate).
                batch_approval_snapshot = self
                    .frame_tx_context
                    .as_ref()
                    .map(|c| c.approval_snapshot())
                    .unwrap_or((false, None));
            }

            let ctx =
                self.frame_tx_context
                    .as_mut()
                    .ok_or(VMError::Internal(InternalError::Custom(
                        "missing frame tx context".to_string(),
                    )))?;
            ctx.current_frame_index = frame_idx;
            ctx.approve_called_in_current_frame = false;

            let target = frame.target.unwrap_or(sender);

            // Determine caller and static mode per frame mode
            let (caller, is_static) = match frame.execution_mode() {
                FrameMode::Default => (entry_point, false),
                FrameMode::Verify => (entry_point, true),
                FrameMode::Sender => {
                    // SENDER mode requires sender_approved
                    let ctx = self.frame_tx_context.as_ref().ok_or(VMError::Internal(
                        InternalError::Custom("missing frame tx context".to_string()),
                    ))?;
                    if !ctx.sender_approved {
                        tx_invalid = true;
                        break;
                    }
                    (sender, false)
                }
            };

            // Set env.origin for this frame (ORIGIN opcode reads this)
            self.env.origin = caller;

            // Resolve any EIP-7702 delegation at the resolved target. For a non-delegated
            // target this is equivalent to `db.get_account_code(target)`; for a delegated
            // target it follows the 0xef0100 || addr indicator and returns the delegatee's
            // bytecode plus the resolved code_address. EIP-8141 §Execution step 1 requires
            // delegated targets to execute the delegatee's code while keeping ADDRESS/storage
            // tied to the delegator — which is why `to` below stays `target` but the
            // CallFrame receives the resolved `code_address`. Mirrors the pattern used at
            // top-level tx entry in default_hook::set_bytecode_and_code_address.
            //
            // access_cost is intentionally discarded: this frame entry is analogous to a
            // top-level tx entry (a call from 0xaa / tx.sender, not a CALL opcode), and
            // default_hook.rs drops the same cost there. EIP-8141 §Execution is silent on
            // billing the 7702 access cost for `resolved_target`, so we keep frame-entry
            // behavior consistent with tx-entry behavior.
            let (is_delegation_7702, _access_cost, code_address, bytecode) =
                crate::utils::eip7702_get_code(
                    self.db,
                    &mut self.substate,
                    target,
                    self.env.config.fork,
                )?;

            // Mirror default_hook::set_bytecode_and_code_address: when delegation was
            // followed, record the delegatee (code_address) as touched in BAL so EIP-7928
            // reconstructors see the cross-address read.
            if is_delegation_7702 && let Some(recorder) = self.db.bal_recorder.as_mut() {
                recorder.record_touched_address(code_address);
            }

            // Log count of the scope this frame's backup will be committed into.
            // The CallFrame branch below relies on `run_execution` having already
            // committed the frame (merging its logs up into this scope), then
            // slices `[substate_logs_before..]` to recover exactly this frame's
            // logs without re-committing.
            let substate_logs_before = self.substate.logs_len();

            // Push substate backup for per-frame state isolation
            self.substate.push_backup();

            // EIP-8141 top-level value transfer: the outer
            // frame call owns CALLVALUE delivery. We only CHECK affordability
            // here; the actual transfer runs inside whichever branch executes
            // the frame, so it is recorded in the backup that branch restores on
            // failure (fixes the value-leak where a reverting contract-target
            // SENDER frame kept the funds). Static validation guarantees only
            // SENDER frames reach here with a non-zero value.
            let value_transfer_reverted = if !frame.value.is_zero() {
                let sender_balance = self.db.get_account(sender)?.info.balance;
                frame_value_exceeds_balance(sender_balance, frame.value)
            } else {
                false
            };

            // Performs the deferred SENDER-frame value transfer + EIP-7708 log.
            // Invoked in BOTH execution branches so the transfer is recorded in
            // the call_frame_backup that branch's failure path restores.
            macro_rules! do_frame_value_transfer {
                () => {
                    if !frame.value.is_zero() && !value_transfer_reverted {
                        self.transfer(sender, target, frame.value)?;
                        // EIP-7708 / traceTransfers log parity with
                        // default_hook::transfer_value: consensus logs are Amsterdam+ and
                        // exclude self-transfers, trace mode includes them. Both decisions
                        // live in `eth_transfer_log_address`.
                        if let Some(log_address) =
                            self.eth_transfer_log_address(sender, target, frame.value)
                        {
                            let log = crate::utils::create_eth_transfer_log(
                                log_address,
                                sender,
                                target,
                                frame.value,
                            );
                            self.substate.add_log(log);
                        }
                    }
                };
            }

            // EIP-8037: capture state-gas accounting before the frame runs so a
            // reverted frame (which commits no state) can be rolled back to
            // contribute zero state gas. The reservoir/spill are captured too:
            // each frame is gas-isolated, so an inline state-gas refund (e.g. an
            // SSTORE 0->N->0 clear, which credits the reservoir) inside one frame
            // must NOT carry over to a later frame's charges — the reservoir is
            // reset to this entry value after the frame completes.
            let state_gas_used_at_frame_entry = self.state_gas_used;
            let state_gas_reservoir_at_frame_entry = self.state_gas_reservoir;
            let state_gas_spill_at_frame_entry = self.state_gas_spill;

            let (frame_success, frame_gas_used, frame_logs) = if value_transfer_reverted {
                self.substate.revert_backup();
                self.restore_cache_state()?;
                (false, frame.gas_limit, Vec::new())
            } else if bytecode.is_empty() && !is_delegation_7702 {
                // Default code runs only when the target has NEITHER code NOR a delegation
                // indicator (EIP-8141 §Execution). After eip7702_get_code,
                // bytecode is the delegatee's code when delegated, so a delegation to an
                // empty delegatee still falls into the CallFrame branch below and returns
                // success without executing anything — NOT into the default-code path.
                // current_call_frame is the OUTER frame here; its backup is the
                // one this branch's failure path restores, so the deferred
                // transfer is correctly undone on a default-code revert.
                do_frame_value_transfer!();
                use crate::opcode_handlers::frame_tx::execute_default_code;
                match execute_default_code(self, frame, target) {
                    Ok((success, gas_used, logs)) => {
                        if success {
                            // Capture this frame's substate logs (incl. the
                            // EIP-7708 transfer log added by
                            // do_frame_value_transfer!) BEFORE commit_backup
                            // merges them into the parent — mirrors the
                            // CallFrame branch. execute_default_code returns its
                            // own logs separately, so include both.
                            let mut this_frame_logs = self.substate.current_logs();
                            this_frame_logs.extend(logs);
                            self.substate.commit_backup();
                            (true, gas_used, this_frame_logs)
                        } else {
                            self.substate.revert_backup();
                            self.restore_cache_state()?;
                            (false, gas_used, Vec::new())
                        }
                    }
                    Err(_) => {
                        self.substate.revert_backup();
                        self.restore_cache_state()?;
                        (false, frame.gas_limit, Vec::new())
                    }
                }
            } else {
                // Normal code execution via CallFrame. msg_value carries
                // `frame.value` so the contract sees the correct CALLVALUE
                // (EIP-8141 §Behavior), but `should_transfer_value` stays
                // false because the deferred `do_frame_value_transfer!()` below
                // (invoked after the frame swap) owns the transfer — the inner
                // CALL machinery must not move the funds a second time.
                let call_frame = CallFrame::new(
                    caller,                                    // msg_sender
                    target,                                    // to (delegator; ADDRESS/storage)
                    code_address,                              // code_address (delegatee when 7702)
                    bytecode,           // bytecode (delegatee's code when 7702)
                    frame.value,        // msg_value -- CALLVALUE
                    frame.data.clone(), // calldata
                    is_static,          // is_static
                    frame.gas_limit,    // gas_limit
                    0,                  // depth
                    false, // should_transfer_value (do_frame_value_transfer! handles it)
                    false, // is_create
                    0,     // ret_offset
                    0,     // ret_size
                    self.stack_pool.pop().unwrap_or_default(), // stack
                    Memory::default(), // memory
                );

                let saved_call_frame = mem::replace(&mut self.current_call_frame, call_frame);
                let saved_call_frames = mem::take(&mut self.call_frames);

                // current_call_frame is now the INNER frame, so the deferred
                // transfer records into the inner backup that the revert failure
                // path (self.substate.revert_backup + restore_cache_state)
                // restores — fixing the value-leak on a reverting SENDER frame.
                do_frame_value_transfer!();

                let frame_result = self.run_execution();

                let result = match frame_result {
                    Ok(ctx_result) => {
                        let gas_used = ctx_result.gas_used;
                        let success = ctx_result.is_success();

                        if success {
                            // The inner frame is the initial call frame (call_frames
                            // was emptied above), so `run_execution` already ran
                            // `handle_state_backup` and committed this frame's backup,
                            // merging its logs up into the scope measured by
                            // `substate_logs_before`. Recover exactly this frame's logs
                            // by slicing off everything that predated it — do NOT commit
                            // again (a second commit would collapse an extra backup
                            // level, breaking atomic-batch rollback) and do NOT read
                            // `current_logs()` wholesale (it now also holds prior frames'
                            // logs, which would duplicate them into frame_receipts[i]).
                            let mut merged_logs = self.substate.current_logs();
                            let this_frame_logs = merged_logs.split_off(substate_logs_before);
                            (true, gas_used, this_frame_logs)
                        } else {
                            // A normal EVM revert reaches `handle_state_backup` inside
                            // `run_execution`, which already reverted the backup and
                            // restored the cache for this frame; repeating it here would
                            // revert an extra level.
                            (false, gas_used, Vec::new())
                        }
                    }
                    Err(_e) => {
                        // A `VMError` propagates out of `run_execution` before it reaches
                        // `handle_state_backup`, so this frame's backup is still live and
                        // must be reverted (and the cache restored) here.
                        self.substate.revert_backup();
                        self.restore_cache_state()?;
                        (false, frame.gas_limit, Vec::new())
                    }
                };

                // Restore call frame state
                let finished_frame = mem::replace(&mut self.current_call_frame, saved_call_frame);
                self.call_frames = saved_call_frames;

                // When a frame succeeds inside an atomic batch, its state
                // changes must remain revertable at batch-revert time. Merge
                // the finished frame's backup into the outer call-frame backup
                // so that `restore_cache_state()` invoked by batch-revert can
                // undo them — and so the next clear-and-absorb folds them into
                // `tx_level_backup` too. Outside a batch, the finished frame's
                // backup never reaches the outer call frame, so absorb it
                // directly into `tx_level_backup` here; otherwise an invalid-tx
                // exit could not roll back this committed frame's state.
                if result.0 {
                    if in_atomic_batch {
                        self.merge_call_frame_backup_with_parent(
                            &finished_frame.call_frame_backup,
                        )?;
                    } else {
                        tx_level_backup.absorb(&finished_frame.call_frame_backup);
                    }
                }

                self.stack_pool.push(finished_frame.stack);

                result
            };

            // EIP-8037: a failed frame's state changes were reverted above, so it
            // creates no state and must contribute zero state gas. Roll the shared
            // `state_gas_used` back to this frame's entry value (the cache/substate
            // were already restored in the failure arms). Successful frames keep
            // their accumulated state gas.
            if !frame_success {
                self.state_gas_used = state_gas_used_at_frame_entry;
            }
            // EIP-8037: frames are gas-isolated, so the state-gas reservoir/spill
            // must not leak across the frame boundary. A reservoir credit from an
            // inline refund inside this frame (or a reverted frame's inflated
            // reservoir) would otherwise subsidize the next frame's state charges
            // (drawn before any spill to gas_remaining). Reset both to this frame's
            // entry value unconditionally — a successful frame already folded its
            // inline refund into `state_gas_used`, so the leftover reservoir credit
            // is spent and must be dropped.
            self.state_gas_reservoir = state_gas_reservoir_at_frame_entry;
            self.state_gas_spill = state_gas_spill_at_frame_entry;

            total_gas_used = total_gas_used
                .checked_add(frame_gas_used)
                .ok_or(VMError::Internal(InternalError::Overflow))?;
            all_logs.extend(frame_logs.clone());

            // Store frame result in context
            let ctx =
                self.frame_tx_context
                    .as_mut()
                    .ok_or(VMError::Internal(InternalError::Custom(
                        "missing frame tx context".to_string(),
                    )))?;
            let status_code = if frame_success {
                ethrex_common::types::FRAME_RECEIPT_STATUS_SUCCESS
            } else {
                ethrex_common::types::FRAME_RECEIPT_STATUS_FAILURE
            };
            ctx.frame_results
                .push((status_code, frame_gas_used, frame_logs));

            // Atomic batch: if a frame in the batch reverted, revert the
            // batch-level snapshot and skip remaining frames in the batch.
            if in_atomic_batch && !frame_success {
                self.substate.revert_backup(); // revert batch-level snapshot
                self.restore_cache_state()?;
                // EIP-7928: drop the batch's recorded changes. `restore` re-files a
                // freshly-written slot as a read and leaves `touched_addresses`
                // alone, so the accesses the batch made still appear -- only the
                // reverted changes go.
                if let Some(checkpoint) = batch_bal_checkpoint.take()
                    && let Some(recorder) = self.db.bal_recorder.as_mut()
                {
                    recorder.restore(checkpoint);
                }
                // EIP-8037: the whole batch unrolled, so none of its frames created
                // state — drop the state gas accumulated since batch entry.
                self.state_gas_used = state_gas_used_at_batch_entry;

                // EIP-8141: frames that executed before the failure retain their
                // execution status and gas used; only their logs are discarded,
                // together with the state changes the unroll drops. `total_gas_used`
                // therefore stands as executed, and the failing frame keeps the gas
                // the single-frame path already charged it (actual `gas_used` for a
                // `REVERT`, the full `gas_limit` for an exceptional halt).
                let ctx = self.frame_tx_context.as_mut().ok_or(VMError::Internal(
                    InternalError::Custom("missing frame tx context".to_string()),
                ))?;
                for result in ctx
                    .frame_results
                    .get_mut(batch_start_idx..=frame_idx)
                    .into_iter()
                    .flatten()
                {
                    result.2 = Vec::new();
                }
                // Roll back approvals granted inside the reverted batch.
                ctx.restore_approvals(batch_approval_snapshot);
                // Remove only logs from the batch, preserving pre-batch logs
                all_logs.truncate(batch_logs_start);

                // Spec: a reverted VERIFY frame invalidates the transaction even
                // inside an atomic batch. The batch unroll above already rolled
                // back state/approvals; validity is a tx-level decision. (The
                // failing `frame` here is the one that triggered the revert.)
                if frame.execution_mode() == FrameMode::Verify {
                    tx_invalid = true;
                    break;
                }

                // Find the end of this batch (the first frame at or after the
                // failing one without the flag)
                let batch_end = find_batch_end(&frame_tx.frames, frame_idx);

                if batch_end > frame_idx {
                    skip_until_batch_end = Some(batch_end);
                } else {
                    in_atomic_batch = false;
                }
                self.substate.clear_transient_storage();
                continue;
            }

            // If this is the last frame of a batch (a frame without the flag), commit the batch
            if in_atomic_batch && !frame.is_atomic_batch() {
                self.substate.commit_backup(); // commit batch-level snapshot
                in_atomic_batch = false;
            }

            // VERIFY frame enforcement: a reverted
            // VERIFY frame invalidates the transaction. A VERIFY frame that
            // succeeds WITHOUT calling APPROVE is valid (e.g. the expiry
            // verifier frame). A reverted VERIFY frame invalidates the tx;
            // batched VERIFY reverts are handled in the atomic-batch-revert
            // branch above (which also sets tx_invalid).
            if frame.execution_mode() == FrameMode::Verify && !frame_success {
                tx_invalid = true;
                break;
            }

            // Clear transient storage between frames
            self.substate.clear_transient_storage();
        }

        // Post-execution, per EIP-8141: "verify that `payer` has been set
        // (i.e. `payer != None`). If `payer` is set, refund any unpaid gas to
        // the payer. If it is not, the whole transaction is invalid."
        let ctx =
            self.frame_tx_context
                .as_ref()
                .ok_or(VMError::Internal(InternalError::Custom(
                    "missing frame tx context".to_string(),
                )))?;
        if ctx.payer_address.is_none() {
            tx_invalid = true;
        }

        if tx_invalid {
            // TX is invalid — Err must leave `db.current_accounts_state`
            // unchanged from before the tx (same contract as non-frame
            // `execute()`). Absorb the last live frame's backup (it has not
            // been cleared yet), then restore every absorbed frame's effects.
            // Substate is per-VM and discarded when this VM drops, so no
            // substate revert is needed.
            tx_level_backup.absorb(&self.current_call_frame.call_frame_backup);
            crate::utils::restore_cache_state(self.db, tx_level_backup)?;
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InvalidFrameTransaction,
            ));
        }

        // Take ownership of frame context
        let ctx = self
            .frame_tx_context
            .take()
            .ok_or(VMError::Internal(InternalError::Custom(
                "missing frame tx context".to_string(),
            )))?;
        let payer = ctx.payer_address.unwrap_or(sender);

        // EIP-8141 gas finalization. EIP-3529 storage refunds accumulate into a
        // single transaction-scoped counter across frames — `substate.refunded_gas`,
        // which a reverted frame or an unrolled atomic batch drops along with its
        // state changes — and are applied once here, capped at a fifth of the gas
        // used before refunds. The EIP-7623 calldata floor then applies to the frame
        // and signature data: the mandatory costs are always charged, and the data
        // cost is floored against what execution actually consumed.
        let mandatory_gas = frame_tx.mandatory_gas();
        let applied_refund = self
            .substate
            .refunded_gas
            .min(total_gas_used / crate::hooks::default_hook::MAX_REFUND_QUOTIENT);
        let data_and_execution = total_gas_used
            .saturating_sub(applied_refund)
            .saturating_sub(mandatory_gas);
        let total_gas_used =
            mandatory_gas.saturating_add(data_and_execution.max(frame_tx.calldata_floor_gas()));

        // Gas refunds: the payer was debited the transaction's `max_cost` at
        // APPROVE (`max_gas` at `max_fee_per_gas`, plus the blob cost already at
        // the base rate, `compute_tx_max_cost`, §Gas accounting). What the payer
        // owes is the effective-rate cost of the gas actually used plus the same
        // base-rate blob burn, so the blob terms cancel and the burn is collected
        // exactly once and never refunded. Everything above that is returned here.
        // Intrinsic gas is inside `total_gas_used`, so it stays non-refundable.
        // When max_fee == effective_gas_price this reduces exactly to the unused
        // -frame-gas refund: max·T + B − e·U − B = e·(T − U).
        let effective_gas_price = self.env.gas_price;
        let charged = crate::opcode_handlers::frame_tx::compute_tx_max_cost(&ctx)
            .map_err(|_| VMError::Internal(InternalError::Overflow))?;
        let blob_burn = crate::utils::calculate_blob_gas_cost(
            &ctx.tx.blob_versioned_hashes,
            self.env.base_blob_fee_per_gas,
        )?;
        let owed = effective_gas_price
            .checked_mul(U256::from(total_gas_used))
            .and_then(|gas_owed| gas_owed.checked_add(blob_burn))
            .ok_or(VMError::Internal(InternalError::Overflow))?;
        // charged >= owed always: effective <= max_fee (by construction of the
        // effective price), the blob terms are identical, and total_gas_used <=
        // max_gas (frames are bounded by their limits, and the floor is charged
        // on both sides).
        let refund_amount = charged
            .checked_sub(owed)
            .ok_or(VMError::Internal(InternalError::Underflow))?;

        self.increase_account_balance(payer, refund_amount)?;

        // Pay coinbase. Mirror `pay_coinbase` on the normal-tx path so a frame
        // transaction has the same coinbase BlockAccessList / witness footprint:
        // EIP-7928 requires the coinbase to appear in the BAL for any user tx even
        // when the priority fee is zero, and EELS reads the coinbase account
        // unconditionally during fee transfer (so EIP-8025 witnesses record its
        // trie path even at zero fee). A frame tx is always a user tx (non-zero
        // effective gas price), unlike a system call.
        let priority_fee = effective_gas_price.saturating_sub(self.env.base_fee_per_gas);
        let coinbase_fee = priority_fee
            .checked_mul(U256::from(total_gas_used))
            .ok_or(VMError::Internal(InternalError::Overflow))?;
        if !effective_gas_price.is_zero()
            && let Some(recorder) = self.db.bal_recorder.as_mut()
        {
            recorder.record_touched_address(self.env.coinbase);
        }
        if coinbase_fee.is_zero() {
            // Zero priority fee: still read the coinbase so its witness/BAL trie
            // path (incl. an exclusion proof if absent) is recorded.
            self.db.get_account(self.env.coinbase)?;
        } else {
            self.increase_account_balance(self.env.coinbase, coinbase_fee)?;
        }

        // EIP-8141: finalize self-destructs at tx end, mirroring the default
        // finalize hook ordering (refund -> coinbase -> delete). SELFDESTRUCT is
        // unrestricted during frame execution (the banned-opcode set only applies
        // to the mempool validation prefix), so a frame may mark same-tx-created
        // accounts for deletion (EIP-6780). Without this they leak into the
        // post-state. `iter_selfdestruct` walks the full substate chain, so a
        // single call here covers every committed frame. Any EIP-7708 burn logs
        // emitted (rare: only when a destroyed account later received ETH in the
        // same tx) are appended to the tx-level aggregate `all_logs`: the per-frame
        // consensus receipts have no slot for end-of-tx logs, but the header and
        // receipt blooms are derived from these aggregate logs (receipt.rs,
        // payload.rs), so they must be recorded there.
        //
        // KNOWN SPEC GAP (cross-client interop): these tx-end burn logs are in the
        // aggregate bloom but NOT in any per-frame consensus receipt, so a client
        // that re-derives the type-0x06 logs_bloom purely from the canonical
        // per-frame logs would compute a different bloom (part of the block hash).
        // ethrex producer and validator agree (both execute over the live
        // aggregate), so this is not an intra-client split; it only bites
        // cross-client and only for this rare destroy-after-receiving-ETH case.
        // EIP-7708 is silent on receipt placement and EIP-8141's frame receipt has
        // no tx-level logs slot, so the canonical home is genuinely undefined; do
        // not pin one (e.g. attribute to the last frame) unilaterally — confirm the
        // bloom-derivation rule against another client / the devnet first.
        let logs_before = self.substate.current_logs().len();
        crate::hooks::default_hook::delete_self_destruct_accounts(self)?;
        let mut logs_after = self.substate.current_logs();
        if logs_after.len() > logs_before {
            all_logs.extend(logs_after.split_off(logs_before));
        }

        // Frame txs short-circuit the hook/finalize path, so the BackupHook never
        // runs and `db.tx_backup` stays None on the success path. A block builder
        // can execute a frame tx successfully and then reject it (e.g. the EIP-8037
        // 2D-gas overflow post-check, or an L2 invalid cross-chain message), calling
        // `undo_last_tx` — which needs the top-level backup to roll the committed
        // state back; otherwise the excluded tx's mutations leak into later txs and
        // the built block's state root diverges from re-execution. Populate it here
        // exactly as `BackupHook::finalize_execution` would: `tx_level_backup` holds
        // every committed frame's originals, and the outer call-frame backup now also
        // holds the refund/coinbase/self-destruct originals. Gated on
        // `preserve_top_level_backup` so it is set only when a hook reads it (L2);
        // on L1 the field is never consulted.
        if self.preserve_top_level_backup {
            tx_level_backup.absorb(&self.current_call_frame.call_frame_backup);
            self.db.tx_backup = Some(tx_level_backup);
        }

        // Derive top-level status from ALL frames: the transaction succeeded
        // only if every executed frame succeeded; a reverted or skipped frame of
        // ANY mode (SENDER, DEFAULT, VERIFY) yields a failed top-level status
        // (analogous to status 0 in standard transactions). This MUST match the
        // consensus-receipt derivation in `Receipt` decoding (receipt.rs), which
        // re-derives `succeeded` from the per-frame statuses ALONE — the
        // consensus `frame_receipt` carries no frame mode, so an all-frames rule
        // is the only definition the encode side (here) and a wire/trie decode
        // can compute identically. Deriving from SENDER frames only would make a
        // freshly-executed receipt's `status` disagree with the same receipt
        // decoded from consensus bytes. (A reverted VERIFY frame already
        // invalidated the tx above via `tx_invalid`; this additionally covers
        // reverted SENDER/DEFAULT frames, which do not.)
        let any_frame_reverted = ctx
            .frame_results
            .iter()
            .any(|(status, _, _)| *status != ethrex_common::types::FRAME_RECEIPT_STATUS_SUCCESS);

        let result = if any_frame_reverted {
            TxResult::Revert(VMError::RevertOpcode)
        } else {
            TxResult::Success
        };

        // EIP-8037: report the transaction's net state gas (same formula as the
        // normal-tx path in default_hook). `total_gas_used` already includes the
        // state gas — it spilled into each frame's gas_remaining, exactly as for any
        // sub-TX_MAX_GAS_LIMIT transaction whose reservoir is 0 — so reporting
        // `state_gas_used` here lets the block-level regular/state split
        // (regular = gas_used - state_gas_used) attribute it to the state dimension
        // instead of billing the whole amount as regular gas.
        let state_gas_used =
            u64::try_from(self.state_gas_used.max(0)).map_err(|_| InternalError::Overflow)?;

        // Unused frame gas in GAS UNITS for the report — distinct from the wei
        // refund above (which also returns the max-vs-effective fee delta).
        let frame_gas_used = total_gas_used.saturating_sub(intrinsic_gas);
        let gas_refund = sum_frame_gas_limits.saturating_sub(frame_gas_used);

        let report = ExecutionReport {
            result,
            gas_used: total_gas_used,
            gas_spent: total_gas_used,
            gas_refunded: gas_refund,
            state_gas_used,
            output: Bytes::new(),
            logs: all_logs,
            payer_address: ctx.payer_address,
            frame_results: Some(ctx.frame_results),
        };

        Ok(report)
    }

    /// EIP-8141 mempool entry point: set up the frame-tx context and observer,
    /// then simulate the validation prefix.
    ///
    /// Performs the frame-tx preamble (static constraints, nonce, fee sanity,
    /// `FrameTxContext` init, outer-signature validation) — the same checks
    /// `execute_frame_tx` runs before any frame — then activates the
    /// [`ValidationObserver`](crate::validation_observer::ValidationObserver) for
    /// `sender` with the prefix's `deploy_index`, runs the prefix via
    /// [`VM::simulate_validation_prefix`], and returns the raw simulation
    /// result. Does NOT charge or refund gas. `canonical_paymaster_pay_frame`
    /// is the index of a canonical paymaster's pay frame (always `None` today,
    /// OQ1); when set, the access-restriction skip fires for that frame.
    pub fn run_frame_validation_prefix(
        &mut self,
        frame_indices: &[usize],
        deploy_index: Option<usize>,
        canonical_paymaster_pay_frame: Option<usize>,
    ) -> Result<PrefixSimResult, VMError> {
        use crate::validation_observer::ValidationObserver;

        if self.env.config.fork < Fork::Hegota {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::FrameTxPreFork,
            ));
        }

        let frame_tx = match &self.tx {
            Transaction::FrameTransaction(ft) => ft.clone(),
            _ => {
                return Err(VMError::Internal(InternalError::Custom(
                    "run_frame_validation_prefix called on non-frame tx".to_string(),
                )));
            }
        };

        let sender = frame_tx.sender;

        if frame_tx.validate_static_constraints().is_err() {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InvalidFrameTransaction,
            ));
        }

        let sender_info = self.db.get_account(sender)?.info.clone();
        if sender_info.nonce != frame_tx.nonce {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::NonceMismatch {
                    expected: sender_info.nonce,
                    actual: frame_tx.nonce,
                },
            ));
        }

        if frame_tx.max_priority_fee_per_gas > frame_tx.max_fee_per_gas {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::PriorityGreaterThanMaxFeePerGas {
                    priority_fee: U256::from(frame_tx.max_priority_fee_per_gas),
                    max_fee_per_gas: U256::from(frame_tx.max_fee_per_gas),
                },
            ));
        }

        if U256::from(frame_tx.max_fee_per_gas) < self.env.base_fee_per_gas {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InsufficientMaxFeePerGas,
            ));
        }

        let sig_hash = frame_tx.compute_sig_hash();
        let max_gas = frame_tx.max_gas();
        self.frame_tx_context = Some(FrameTxContext {
            sender_approved: false,
            payer_address: None,
            frame_results: Vec::new(),
            current_frame_index: 0,
            sig_hash,
            tx: frame_tx.clone(),
            approve_called_in_current_frame: false,
            max_gas,
            blob_base_fee: self.env.base_blob_fee_per_gas,
        });

        if !validate_frame_signatures(
            &frame_tx.signatures,
            sig_hash,
            frame_tx.sender,
            self.env.config.fork,
            self.crypto,
        ) {
            return Err(VMError::TxValidation(
                crate::errors::TxValidationError::InvalidFrameTransaction,
            ));
        }

        let expiry_verifier = ethrex_common::types::frame_tx_expiry_verifier();
        let mut observer = ValidationObserver::new(sender, deploy_index, expiry_verifier);
        observer.canonical_paymaster_pay_frame = canonical_paymaster_pay_frame;
        self.validation_observer = observer;

        self.simulate_validation_prefix(frame_indices)
    }

    /// EIP-8141 mempool validation-prefix simulation (local peer policy).
    ///
    /// Runs ONLY the validation-prefix frames (the verify/pay/deploy frames that
    /// must execute before the transaction's payer is established) of a frame
    /// transaction, under an active [`ValidationObserver`](crate::validation_observer::ValidationObserver),
    /// then stops as soon as the payer has been set. Reuses the real frame
    /// execution primitives (`eip7702_get_code`, `execute_default_code`,
    /// `run_execution`, substate backups, value transfer) over the DEFAULT/VERIFY
    /// subset that prefixes are restricted to (Phase 1 structural rules forbid
    /// SENDER and atomic-batch frames in the prefix), so it dispatches real
    /// opcodes through the real handlers — not a separate mini-EVM.
    ///
    /// `frame_indices` are the prefix frame indices (in order), as identified by
    /// `FrameTransaction::validation_prefix`; expiry-verifier frames interleaved
    /// in the prefix are run too (they may appear between prefix frames). The
    /// caller must have set `frame_tx_context` and activated the observer.
    ///
    /// Returns [`PrefixSimResult`] describing the outcome. Does NOT charge fees
    /// or refund gas (mempool simulation only); state changes accumulate in the
    /// shared `db` and are discarded by the caller (a fresh simulation database).
    pub fn simulate_validation_prefix(
        &mut self,
        frame_indices: &[usize],
    ) -> Result<PrefixSimResult, VMError> {
        let frame_tx = match &self.tx {
            Transaction::FrameTransaction(ft) => ft.clone(),
            _ => {
                return Err(VMError::Internal(InternalError::Custom(
                    "simulate_validation_prefix called on non-frame tx".to_string(),
                )));
            }
        };

        let sender = frame_tx.sender;
        let entry_point = ethrex_common::types::frame_tx_entry_point();

        let mut total_gas_used: u64 = 0;
        let mut any_revert = false;
        // The highest prefix-frame index we must run before stopping. We run the
        // prefix in source order, executing every frame from 0 up to and
        // including the last prefix index (covering interleaved expiry frames).
        let last_prefix_idx = frame_indices.iter().copied().max();

        for (frame_idx, frame) in frame_tx.frames.iter().enumerate() {
            // Stop once the whole prefix has run (and the payer break below).
            if let Some(stop) = last_prefix_idx {
                if frame_idx > stop {
                    break;
                }
            } else {
                break;
            }

            // Each independent prefix frame starts with a clean call-frame backup
            // so a later frame's failure only reverts its own effects.
            self.current_call_frame.call_frame_backup.clear();

            let ctx =
                self.frame_tx_context
                    .as_mut()
                    .ok_or(VMError::Internal(InternalError::Custom(
                        "missing frame tx context".to_string(),
                    )))?;
            ctx.current_frame_index = frame_idx;
            ctx.approve_called_in_current_frame = false;

            let target = frame.target.unwrap_or(sender);

            // Sync observer per-frame fields before the frame runs.
            self.validation_observer.current_frame_index = frame_idx;
            self.validation_observer.current_frame_mode = frame.mode;

            // Prefix frames are DEFAULT (deploy) or VERIFY only; both run with
            // ENTRY_POINT as caller (DEFAULT not static, VERIFY static).
            let (caller, is_static) = match frame.execution_mode() {
                FrameMode::Default => (entry_point, false),
                FrameMode::Verify => (entry_point, true),
                FrameMode::Sender => {
                    // Structural rules exclude SENDER frames from the prefix.
                    return Err(VMError::Internal(InternalError::Custom(
                        "SENDER frame in validation prefix".to_string(),
                    )));
                }
            };

            self.env.origin = caller;

            let (is_delegation_7702, _access_cost, code_address, bytecode) =
                crate::utils::eip7702_get_code(
                    self.db,
                    &mut self.substate,
                    target,
                    self.env.config.fork,
                )?;

            self.substate.push_backup();

            let value_transfer_reverted = if !frame.value.is_zero() {
                let sender_balance = self.db.get_account(sender)?.info.balance;
                frame_value_exceeds_balance(sender_balance, frame.value)
            } else {
                false
            };

            let (frame_success, frame_gas_used) = if value_transfer_reverted {
                self.substate.revert_backup();
                self.restore_cache_state()?;
                (false, frame.gas_limit)
            } else if bytecode.is_empty() && !is_delegation_7702 {
                // Default-code path (target has neither code nor a delegation).
                if !frame.value.is_zero() {
                    self.transfer(sender, target, frame.value)?;
                }
                use crate::opcode_handlers::frame_tx::execute_default_code;
                match execute_default_code(self, frame, target) {
                    Ok((success, gas_used, _logs)) => {
                        if success {
                            self.substate.commit_backup();
                            (true, gas_used)
                        } else {
                            self.substate.revert_backup();
                            self.restore_cache_state()?;
                            (false, gas_used)
                        }
                    }
                    Err(_) => {
                        self.substate.revert_backup();
                        self.restore_cache_state()?;
                        (false, frame.gas_limit)
                    }
                }
            } else {
                // Normal code execution via a child CallFrame.
                let call_frame = CallFrame::new(
                    caller,
                    target,
                    code_address,
                    bytecode,
                    frame.value,
                    frame.data.clone(),
                    is_static,
                    frame.gas_limit,
                    0,
                    false,
                    false,
                    0,
                    0,
                    self.stack_pool.pop().unwrap_or_default(),
                    Memory::default(),
                );

                let saved_call_frame = mem::replace(&mut self.current_call_frame, call_frame);
                let saved_call_frames = mem::take(&mut self.call_frames);

                if !frame.value.is_zero() {
                    self.transfer(sender, target, frame.value)?;
                }

                let frame_result = self.run_execution();

                let result = match frame_result {
                    Ok(ctx_result) => {
                        let gas_used = ctx_result.gas_used;
                        // The inner frame is the initial call frame, so `run_execution`
                        // already committed (success) or reverted + restored the cache
                        // (revert) this frame's backup via `handle_state_backup`. Only a
                        // `VMError` (the `Err` arm) leaves the backup live for us to undo.
                        (ctx_result.is_success(), gas_used)
                    }
                    Err(_e) => {
                        self.substate.revert_backup();
                        self.restore_cache_state()?;
                        (false, frame.gas_limit)
                    }
                };

                let finished_frame = mem::replace(&mut self.current_call_frame, saved_call_frame);
                self.call_frames = saved_call_frames;
                self.stack_pool.push(finished_frame.stack);

                result
            };

            total_gas_used = total_gas_used
                .checked_add(frame_gas_used)
                .ok_or(VMError::Internal(InternalError::Overflow))?;

            if !frame_success {
                any_revert = true;
            }

            // A reverted prefix frame is fatal: the transaction can never reach a
            // valid payer through a reverted verify/pay/deploy frame.
            if !frame_success {
                break;
            }

            self.substate.clear_transient_storage();

            // Stop as soon as the payer has been set (the prefix is complete).
            if self
                .frame_tx_context
                .as_ref()
                .and_then(|c| c.payer_address)
                .is_some()
            {
                break;
            }
        }

        let ctx =
            self.frame_tx_context
                .as_ref()
                .ok_or(VMError::Internal(InternalError::Custom(
                    "missing frame tx context".to_string(),
                )))?;

        Ok(PrefixSimResult {
            any_revert,
            payer_address: ctx.payer_address,
            sender_approved: ctx.sender_approved,
            total_gas_used,
        })
    }

    /// Must run after `prepare_execution` so EIP-7702 delegation is already resolved into
    /// `bytecode`.
    #[inline(always)]
    fn is_simple_transfer_fast_path(&self) -> bool {
        !self.current_call_frame.is_create
            && self.current_call_frame.bytecode.is_empty()
            // Privileged L2 txs can leave gas negative; let the slow path surface that as OOG.
            && self.current_call_frame.gas_remaining >= 0
            && self.tx.authorization_list().is_none()
            // Precompiles dispatch via run_execution even with empty bytecode.
            && !self.address_is_precompile(&self.current_call_frame.to)
    }

    /// [`precompiles::is_precompile`], honoring simulation-only relocations from
    /// `movePrecompileToAddress`. Identical to the plain check on consensus paths,
    /// where `db.precompile_moves` is `None`.
    pub(crate) fn address_is_precompile(&self, address: &Address) -> bool {
        precompiles::is_precompile_with_moves(
            address,
            self.env.config.fork,
            self.vm_type,
            self.db.precompile_moves.as_deref(),
        )
    }

    /// The address whose precompile implementation should execute for a call to
    /// `address` (identity mapping unless `address` is a relocation destination).
    pub(crate) fn effective_precompile_address(&self, address: Address) -> Address {
        precompiles::effective_precompile_address(address, self.db.precompile_moves.as_deref())
    }

    /// Main execution loop.
    pub fn run_execution(&mut self) -> Result<ContextResult, VMError> {
        // If gas is already exhausted (negative), fail immediately.
        // This can happen when intrinsic gas exceeds the gas limit in privileged L2 transactions.
        // Without this check, casting negative gas_remaining to u64 would wrap to a huge value.
        if self.current_call_frame.gas_remaining < 0 {
            return Ok(ContextResult {
                result: TxResult::Revert(ExceptionalHalt::OutOfGas.into()),
                gas_used: self.current_call_frame.gas_limit,
                gas_spent: self.current_call_frame.gas_limit,
                output: Bytes::new(),
            });
        }

        // EIP-8037: the atomic prepare region rolled back (one of its charges — 7702
        // auth, CREATE/value NEW_ACCOUNT, recipient delegation-resolve — OOG'd).
        // Burn all gas and revert the tx rather than rejecting it as invalid (which
        // would wrongly invalidate the block). Mirrors EELS depth-0
        // `except ExceptionalHalt: evm.regular_gas_used += evm.gas_left; evm.gas_left = 0`
        // (`interpreter.py:366-374`).
        if self.pending_prep_oog {
            return Ok(ContextResult {
                result: TxResult::Revert(ExceptionalHalt::OutOfGas.into()),
                gas_used: self.current_call_frame.gas_limit,
                gas_spent: self.current_call_frame.gas_limit,
                output: Bytes::new(),
            });
        }

        // A charged value-to-not-alive NEW_ACCOUNT means the recipient was not yet alive
        // at tx start and the tx transfers value. If the recipient is a precompile that
        // then exceptionally halts/reverts, the account is never materialized, so the
        // charge is rolled back in the precompile branch below (mirrors EELS
        // `refill_frame_state_gas`). Set in-region by `prepare_execution`.
        let top_frame_new_account_charged = self.value_new_account_charged;

        #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
        if self.address_is_precompile(&self.current_call_frame.to) {
            // `execute_precompile` itself never touches state gas (it only mutates
            // `gas_remaining`; it has no access to `state_gas_used` / `state_gas_reservoir` /
            // `state_gas_spill`) — the assert below guards that. The in-region EIP-2780
            // value-to-not-alive NEW_ACCOUNT charge (`prepare_execution`),
            // however, IS frame state gas, and on an exceptional halt/revert it must be
            // rolled back (see below). `self` is borrowed by field rather than via
            // `&mut self.current_call_frame` so the refund call, which needs `&mut self`,
            // can run after `execute_precompile`.
            let state_gas_used_before_precompile = self.state_gas_used;
            // Resolve a relocation destination back to the precompile it hosts.
            let code_address =
                self.effective_precompile_address(self.current_call_frame.code_address);
            let precompile_gas_limit = self.current_call_frame.gas_limit;
            let mut gas_remaining = self.current_call_frame.gas_remaining as u64;
            let result = Self::execute_precompile(
                code_address,
                &self.current_call_frame.calldata,
                precompile_gas_limit,
                &mut gas_remaining,
                self.env.config.fork,
                self.db.store.precompile_cache(),
                self.crypto,
                self.stateless_validator,
            );

            debug_assert_eq!(
                self.state_gas_used, state_gas_used_before_precompile,
                "precompile execution must not mutate state_gas_used"
            );

            // EIP-8037 Amsterdam 2D accounting recomputes `block_gas_used` from
            // `raw_consumed = gas_limit - gas_remaining` inside `refund_sender`. On a
            // top-level precompile exceptional halt, `handle_precompile_result` already
            // sets `ContextResult.gas_used = gas_limit`, but `gas_remaining` retains the
            // untouched forwarded amount — under Amsterdam that would make the block
            // report only the intrinsic portion. Zero it so the block matches the
            // `gas_used = gas_limit` contract from `handle_precompile_result`, and roll
            // back the in-region value NEW_ACCOUNT charge (the recipient is never materialized
            // on halt) so the burned gas counts entirely as regular gas, matching EELS
            // `refill_frame_state_gas`. Pre-Amsterdam reads `ctx_result.gas_used` directly
            // and is unaffected by this path either way.
            if self.env.config.fork >= Fork::Amsterdam
                && let Ok(ctx) = &result
                && !ctx.is_success()
            {
                gas_remaining = 0;
                self.refund_new_account_state_gas(top_frame_new_account_charged)?;
            }

            self.current_call_frame.gas_remaining = gas_remaining as i64;

            return result;
        }

        // Specialize the dispatch loop on whether a struct-log tracer is active.
        // The `!TRACED` variant compiles out every tracer branch and capture call,
        // leaving a minimal hot loop (the common, non-traced case).
        match (self.opcode_tracer.active, self.validation_observer.active) {
            (false, false) => self.run_dispatch::<false, false>(),
            (false, true) => self.run_dispatch::<false, true>(),
            (true, false) => self.run_dispatch::<true, false>(),
            (true, true) => self.run_dispatch::<true, true>(),
        }
    }

    /// Opcode dispatch loop, monomorphized over whether a struct-log tracer is
    /// active. With `TRACED = false` the compiler eliminates the tracer branches
    /// and the cold `trace_*_step` calls entirely, so the hot loop body stays
    /// minimal; the traced variant keeps the cold helpers out of line.
    fn run_dispatch<const TRACED: bool, const VALIDATING: bool>(
        &mut self,
    ) -> Result<ContextResult, VMError> {
        let mut error = OnceCell::<VMError>::new();

        #[cfg(feature = "perf_opcode_timings")]
        let mut timings = crate::timings::OPCODE_TIMINGS.lock().expect("poison");

        // Copy the `&'static` table pointer once; it doesn't borrow `self`, so dispatch can still
        // pass `self` mutably to the handler without reloading the pointer each iteration.
        let opcode_table = self.opcode_table;

        loop {
            // Capture pc BEFORE advance_pc() — this is the address of the current opcode.
            let pc_of_current_op = self.current_call_frame.pc;
            let opcode = self.current_call_frame.next_opcode();
            self.advance_pc();

            // EIP-8141 mempool validation-trace observer (single branch on the
            // fast path when inactive). Enforces the banned-opcode set and the
            // sequential `GAS`-before-`*CALL` rule before the handler runs.
            if VALIDATING {
                self.check_validation_banned_opcode(opcode);
            }

            // Struct-log pre-step capture (compiled out entirely when !TRACED).
            let gas_before_op = if TRACED {
                self.trace_pre_step(opcode, pc_of_current_op)
            } else {
                0
            };

            #[cfg(feature = "perf_opcode_timings")]
            let opcode_time_start = std::time::Instant::now();

            #[allow(clippy::indexing_slicing, clippy::as_conversions)]
            let op_result = opcode_table[opcode as usize].call(self, &mut error);

            #[cfg(feature = "perf_opcode_timings")]
            {
                let time = opcode_time_start.elapsed();
                timings.update(opcode, time);
            }

            // Struct-log post-step (compiled out entirely when !TRACED).
            if TRACED {
                self.trace_post_step(gas_before_op, &error);
            }

            let result = match op_result {
                OpcodeResult::Continue => continue,
                OpcodeResult::Halt => match error.take() {
                    None => self.handle_opcode_result()?,
                    Some(error) => self.handle_opcode_error(error)?,
                },
            };

            // Return the ExecutionReport if the executed callframe was the first one.
            if self.is_initial_call_frame() {
                // Consume the backup (move it out) unless a `BackupHook` will read it afterward
                // to build the tx-level undo snapshot (L2 / stateless). On L1 nothing reads it
                // once the cache is restored, so cloning it would be dead work.
                self.handle_state_backup(&result, !self.preserve_top_level_backup)?;
                return Ok(result);
            }

            // Handle interaction between child and parent callframe.
            self.handle_return(&result)?;
        }
    }

    /// EIP-8141 validation-trace banned-opcode check (mempool simulation only).
    ///
    /// Called once per dispatch-loop iteration, AFTER the opcode is fetched and
    /// BEFORE the handler runs, gated by `self.validation_observer.active`. Byte
    /// values are pinned against `opcodes.rs`.
    ///
    /// Static bans: `ORIGIN`, `GASPRICE`, `BLOCKHASH`, `COINBASE`, `TIMESTAMP`
    /// (except when the current frame's target is EXPIRY_VERIFIER), `NUMBER`,
    /// `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBHASH`, `BLOBBASEFEE`, `INVALID`,
    /// `SELFDESTRUCT`, `BALANCE`, `SELFBALANCE`, `TLOAD`, `TSTORE`, and `CALLCODE`
    /// in non-deploy prefix frames (ERC-7562 bans CALLCODE in validation;
    /// DELEGATECALL is allowed subject to the CALL-family trace rules in the
    /// handlers). `SSTORE`/`CREATE`/`CREATE2` are allowed only inside the deploy
    /// frame and are enforced in their handlers (state-write rules), not here.
    ///
    /// Sequential `GAS` rule: `GAS` is allowed only immediately before a
    /// `*CALL` (`CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL`). We detect this by
    /// remembering `last_opcode`: if the previous iteration was `GAS` and this
    /// opcode is NOT a `*CALL`, the prior `GAS` was illegal.
    pub fn check_validation_banned_opcode(&mut self, opcode: u8) {
        use crate::validation_observer::FrameSimViolation;

        // Opcode bytes, pinned against `opcodes.rs`. The literal values are
        // asserted equal to the `Opcode` enum discriminants by
        // `validation_observer_opcode_byte_pins` below (avoids a `const`-context
        // `as` cast, which the workspace clippy config denies).
        const ORIGIN: u8 = 0x32;
        const GASPRICE: u8 = 0x3A;
        const BLOCKHASH: u8 = 0x40;
        const COINBASE: u8 = 0x41;
        const TIMESTAMP: u8 = 0x42;
        const NUMBER: u8 = 0x43;
        const PREVRANDAO: u8 = 0x44;
        const GASLIMIT: u8 = 0x45;
        const BASEFEE: u8 = 0x48;
        const BLOBHASH: u8 = 0x49;
        const BLOBBASEFEE: u8 = 0x4A;
        const INVALID: u8 = 0xFE;
        const SELFDESTRUCT: u8 = 0xFF;
        const BALANCE: u8 = 0x31;
        const SELFBALANCE: u8 = 0x47;
        const TLOAD: u8 = 0x5C;
        const TSTORE: u8 = 0x5D;
        const GAS: u8 = 0x5A;
        const CALL: u8 = 0xF1;
        const CALLCODE: u8 = 0xF2;
        const DELEGATECALL: u8 = 0xF4;
        const STATICCALL: u8 = 0xFA;

        let is_call_family = matches!(opcode, CALL | CALLCODE | DELEGATECALL | STATICCALL);

        // Sequential GAS rule: a `GAS` on the previous iteration is only legal if
        // THIS opcode is a `*CALL`. Evaluate before updating `last_opcode`.
        if self.validation_observer.last_opcode == GAS && !is_call_family {
            self.validation_observer
                .record_violation(FrameSimViolation::BannedOpcode(GAS));
        }

        // Carry `GAS` forward for the next iteration's check; reset otherwise.
        self.validation_observer.last_opcode = if opcode == GAS { GAS } else { 0 };

        let banned = match opcode {
            ORIGIN | GASPRICE | BLOCKHASH | COINBASE | NUMBER | PREVRANDAO | GASLIMIT | BASEFEE
            | BLOBHASH | BLOBBASEFEE | INVALID | SELFDESTRUCT | BALANCE | SELFBALANCE | TLOAD
            | TSTORE => true,
            // TIMESTAMP is permitted only when the currently executing contract
            // IS the EXPIRY_VERIFIER predeploy (checked by code_address so the
            // rule tracks the executing contract at every call depth, not just the
            // top-level frame target). A nested call FROM an expiry frame INTO
            // another contract is correctly banned; a nested call INTO the
            // predeploy from any frame is correctly allowed.
            TIMESTAMP => {
                self.current_call_frame.code_address != self.validation_observer.expiry_verifier
            }
            // CALLCODE is banned in non-deploy prefix frames (ERC-7562).
            CALLCODE => !self.validation_observer.in_deploy_frame(),
            _ => false,
        };

        if banned {
            self.validation_observer
                .record_violation(FrameSimViolation::BannedOpcode(opcode));
        }
    }

    /// EIP-8141 validation-trace `SLOAD` check (mempool simulation only).
    ///
    /// `SLOAD` is allowed only when the storage owner (`address`, the executing
    /// frame's `to`) is the transaction sender. Records the touched slot for the
    /// admission-time revalidation affected-set.
    pub fn validation_check_sload(&mut self, address: Address, slot: H256) {
        use crate::validation_observer::FrameSimViolation;
        if self.validation_observer.in_canonical_pay_frame() {
            return;
        }
        if address == self.validation_observer.sender {
            self.validation_observer.touched_sender_slots.push(slot);
        } else {
            self.validation_observer
                .record_violation(FrameSimViolation::StorageReadNonSender);
        }
    }

    /// EIP-8141 validation-trace `SSTORE` check (mempool simulation only).
    ///
    /// `SSTORE` is allowed only inside the deploy frame AND only when the storage
    /// owner (`address`, the executing frame's `to`) is the transaction sender.
    pub fn validation_check_sstore(&mut self, address: Address, slot: H256) {
        use crate::validation_observer::FrameSimViolation;
        if self.validation_observer.in_canonical_pay_frame() {
            return;
        }
        if self.validation_observer.in_deploy_frame() && address == self.validation_observer.sender
        {
            self.validation_observer.touched_sender_slots.push(slot);
        } else {
            self.validation_observer
                .record_violation(FrameSimViolation::StateWriteOutsideDeploy);
        }
    }

    /// EIP-8141 validation-trace state-creation check for `CREATE`/`CREATE2`
    /// (mempool simulation only). Contract creation is a state write permitted
    /// only inside the deploy frame.
    pub fn validation_check_create(&mut self) {
        use crate::validation_observer::FrameSimViolation;
        if self.validation_observer.in_canonical_pay_frame() {
            return;
        }
        if !self.validation_observer.in_deploy_frame() {
            self.validation_observer
                .record_violation(FrameSimViolation::StateWriteOutsideDeploy);
        }
    }

    /// EIP-8141 validation-trace `CALL*`/`EXTCODE*` target check (mempool
    /// simulation only).
    ///
    /// The target must be an existing account or a precompile and must NOT be
    /// EIP-7702-delegated, except the sender running its own default code (the
    /// sender is exempt — its existence is a transaction precondition and it may
    /// have no code). `is_delegation_7702` is the flag already computed by
    /// `eip7702_get_code` in the CALL-family handlers, threaded in to avoid a
    /// second delegation resolution (and the `&mut VM` / `&mut db` borrow
    /// conflict a dispatch-loop stack-peek would create).
    pub fn validation_check_call_target(
        &mut self,
        target: Address,
        is_delegation_7702: bool,
    ) -> Result<(), VMError> {
        use crate::validation_observer::FrameSimViolation;
        if self.validation_observer.in_canonical_pay_frame() {
            return Ok(());
        }
        // The sender is always a legitimate target (its existence is a tx
        // precondition; it may legitimately have no code).
        if target == self.validation_observer.sender {
            return Ok(());
        }
        // A delegated target is disallowed in validation.
        if is_delegation_7702 {
            self.validation_observer
                .record_violation(FrameSimViolation::CallToNonexistentOrDelegated(target));
            return Ok(());
        }
        // Precompiles are always valid targets.
        if precompiles::is_precompile(&target, self.env.config.fork, self.vm_type) {
            return Ok(());
        }
        // Otherwise the target must be an existing (non-empty) account.
        if self.db.get_account(target)?.is_empty() {
            self.validation_observer
                .record_violation(FrameSimViolation::CallToNonexistentOrDelegated(target));
        }
        Ok(())
    }

    /// EIP-8141 validation-trace `EXTCODE*` target check (mempool simulation
    /// only). Like [`VM::validation_check_call_target`], but resolves the
    /// EIP-7702 delegation flag itself (the EXTCODE handlers do not call
    /// `eip7702_get_code`). The `substate.add_accessed_address` warming the
    /// EXTCODE gas already performed has happened; resolving here only follows a
    /// delegation indicator to read its flag, mirroring the CALL-family path.
    pub fn validation_check_extcode_target(&mut self, target: Address) -> Result<(), VMError> {
        if self.validation_observer.in_canonical_pay_frame()
            || target == self.validation_observer.sender
        {
            return Ok(());
        }
        let (is_delegation_7702, _access_cost, _code_address, _bytecode) =
            crate::utils::eip7702_get_code(
                self.db,
                &mut self.substate,
                target,
                self.env.config.fork,
            )?;
        self.validation_check_call_target(target, is_delegation_7702)
    }

    /// Struct-log pre-step capture, split out of the interpreter loop and kept
    /// cold + non-inlined so the hot dispatch loop stays small (this code is
    /// only reached when a struct-log tracer is active). Returns `gas_before`.
    #[cold]
    #[inline(never)]
    fn trace_pre_step(&mut self, opcode: u8, pc_of_current_op: usize) -> u64 {
        #[expect(
            clippy::as_conversions,
            reason = "gas_remaining is i64; clamp to 0 before converting to u64"
        )]
        let gas_before = self.current_call_frame.gas_remaining.max(0) as u64;
        #[expect(
            clippy::as_conversions,
            reason = "call depth bounded by STACK_LIMIT=1024, fits in u32"
        )]
        let depth = (self.call_frames.len() as u32).saturating_add(1);
        let refund = self.substate.refunded_gas;
        let stack_view = self.collect_stack_for_trace();
        let mem_view = self.collect_memory_for_trace();
        // mem_size always reflects actual memory size, regardless of enable_memory.
        #[expect(
            clippy::as_conversions,
            reason = "memory size is bounded by gas; fits in u64"
        )]
        let mem_size_for_trace = self.current_call_frame.memory.len() as u64;
        let storage_kv = self.read_storage_for_trace(opcode);
        let return_data = if self.opcode_tracer.cfg.enable_return_data {
            self.current_call_frame.sub_return_data.clone()
        } else {
            Bytes::new()
        };
        #[expect(
            clippy::as_conversions,
            reason = "pc is usize, fits in u64 on supported targets"
        )]
        let pc_u64 = pc_of_current_op as u64;
        self.opcode_tracer.pre_step_capture(
            pc_u64,
            opcode,
            gas_before,
            depth,
            refund,
            &stack_view,
            &mem_view,
            mem_size_for_trace,
            &return_data,
            storage_kv,
        );
        gas_before
    }

    /// Struct-log post-step: patch gas_cost, refund-after-op, and error into the
    /// buffered entry. Cold + non-inlined for the same reason as `trace_pre_step`.
    #[cold]
    #[inline(never)]
    fn trace_post_step(&mut self, gas_before_op: u64, error: &OnceCell<VMError>) {
        #[expect(
            clippy::as_conversions,
            reason = "gas_remaining is i64; clamp to 0 before converting to u64"
        )]
        let gas_after = self.current_call_frame.gas_remaining.max(0) as u64;
        // Prefer the explicit opcode-overhead cost written by CALL/CREATE handlers;
        // fall back to the gas diff for all other opcodes.
        let gas_cost = self
            .opcode_tracer
            .last_opcode_gas_cost
            .take()
            .unwrap_or_else(|| gas_before_op.saturating_sub(gas_after));
        // refund-after-op matches geth's structLogger timing: for SSTORE and
        // (pre-London) SELFDESTRUCT, the refund counter shown is the value
        // *after* the opcode's accounting applied.
        let refund_after = self.substate.refunded_gas;
        let err_str = error.get().map(|e| e.to_string());
        self.opcode_tracer
            .finalize_step(gas_cost, refund_after, err_str.as_deref());
    }

    /// Executes precompile and handles the output that it returns, generating a report.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_precompile(
        code_address: H160,
        calldata: &Bytes,
        gas_limit: u64,
        gas_remaining: &mut u64,
        fork: Fork,
        cache: Option<&precompiles::PrecompileCache>,
        crypto: &dyn Crypto,
        stateless_validator: Option<&dyn crate::StatelessValidator>,
    ) -> Result<ContextResult, VMError> {
        Self::handle_precompile_result(
            precompiles::execute_precompile(
                code_address,
                calldata,
                gas_remaining,
                fork,
                cache,
                crypto,
                stateless_validator,
            ),
            gas_limit,
            *gas_remaining,
        )
    }

    /// True if external transaction is a contract creation
    pub fn is_create(&self) -> Result<bool, InternalError> {
        Ok(self.current_call_frame.is_create)
    }

    /// The address an ETH-transfer log for `value` moving `from` → `to` should
    /// be emitted from, or `None` when no log applies.
    /// Amsterdam+ emits consensus EIP-7708 logs from SYSTEM_ADDRESS; the EIP
    /// excludes self-transfers. Pre-Amsterdam, `eth_simulateV1` traceTransfers
    /// emits informational logs from the TRACE_TRANSFER_ADDRESS sentinel;
    /// self-transfers are included there (the tracer reports gross movements).
    #[inline]
    pub fn eth_transfer_log_address(
        &self,
        from: Address,
        to: Address,
        value: U256,
    ) -> Option<Address> {
        if value.is_zero() {
            None
        } else if self.env.config.fork >= Fork::Amsterdam {
            (from != to).then_some(ethrex_common::constants::SYSTEM_ADDRESS)
        } else if self.env.trace_eth_transfers {
            Some(crate::constants::TRACE_TRANSFER_ADDRESS)
        } else {
            None
        }
    }

    /// Executes without making changes to the cache.
    pub fn stateless_execute(&mut self) -> Result<ExecutionReport, VMError> {
        // Add backup hook to restore state after execution. `add_hook` flips
        // `preserve_top_level_backup` on via `Hook::reads_top_level_backup`, so the backup is
        // cloned (not moved out) on the revert paths even though this VM was built with L1 `vm_type`.
        self.add_hook(BackupHook::default());
        let report = self.execute()?;
        // Restore cache to the state before execution.
        self.db.undo_last_transaction()?;
        Ok(report)
    }

    fn prepare_execution(&mut self) -> Result<(), VMError> {
        // Clone each hook's `Rc` (cheap refcount bump) so the borrow on `self.hooks` is released
        // and `self` can be passed mutably — without `self.hooks.clone()`'s per-tx `Vec` realloc.
        // `self.hooks` is not mutated during the loop, so `get(i)` is always `Some` in range.
        for i in 0..self.hooks.len() {
            if let Some(hook) = self.hooks.get(i).map(Rc::clone) {
                hook.borrow_mut().prepare_execution(self)?;
            }
        }

        Ok(())
    }

    fn finalize_execution(
        &mut self,
        mut ctx_result: ContextResult,
    ) -> Result<ExecutionReport, VMError> {
        // EIP-8037: On top-level tx failure (REVERT, ExceptionalHalt, or OOG), the
        // execution portion of state gas has already been refilled into the reservoir by
        // the top-frame `refill_frame_state_gas` (seeded at the post-intrinsic baseline in
        // `add_intrinsic_gas` and fired on revert/halt in `handle_opcode_error` /
        // `handle_opcode_result`). The intrinsic portion stays in `state_gas_used` so block
        // accounting bills it. No reservoir-move is performed here. A create-tx collision
        // rolls its own in-region `NEW_ACCOUNT` charge (if any) back to the frame's entry
        // baseline inside `handle_create_transaction`'s collision branch, so there is
        // nothing left to refill here either (see that function).
        //
        // EIP-8037: there is no longer a separate create-failure `NEW_ACCOUNT`
        // refund here. The charge itself (`prepare_execution`) is now
        // conditioned on `get_pre_state_account(created_addr) == EMPTY_ACCOUNT`, so it
        // simply never fires for an already-alive target (positive balance implies
        // non-empty pre-state) and is rolled back by `handle_create_transaction` on
        // collision — matching EELS v7, which drops the created-target-alive output flag
        // entirely because `prepare_dispatch` never runs for a colliding create.

        // See `prepare_execution`: per-hook `Rc::clone` avoids the `self.hooks.clone()` realloc.
        for i in 0..self.hooks.len() {
            if let Some(hook) = self.hooks.get(i).map(Rc::clone) {
                hook.borrow_mut()
                    .finalize_execution(self, &mut ctx_result)?;
            }
        }

        self.tracer.exit_context(&ctx_result, true)?;

        // Struct-log end-of-tx capture: record final output, gas used, and revert error.
        // gas matches geth's `executionResult.Gas` which is post-refund (`receipt.GasUsed`).
        if self.opcode_tracer.active {
            self.opcode_tracer.output = ctx_result.output.clone();
            self.opcode_tracer.gas_used = ctx_result.gas_spent;
            self.opcode_tracer.error = match ctx_result.result {
                TxResult::Revert(ref err) => Some(err.to_string()),
                _ => None,
            };
        }

        // Only include logs if transaction succeeded. When a transaction reverts,
        // no logs should be emitted (including EIP-7708 Transfer logs).
        let logs = if ctx_result.is_success() {
            self.substate.extract_logs()
        } else {
            Vec::new()
        };

        // EIP-8037: `state_gas_used` is already net (signed; credits decrement it
        // inline), so `tx_state_gas = intrinsic_state_gas + state_gas_used` exactly
        // (EELS `fork.py::process_transaction`, which no longer carries a separate
        // tx-level refund channel). Clamp at zero — `state_gas_used` may be negative when
        // inline refunds exceed gross charges.
        let net_state_gas_used: u64 =
            u64::try_from(self.state_gas_used.max(0)).map_err(|_| InternalError::Overflow)?;

        let report = ExecutionReport {
            result: ctx_result.result.clone(),
            gas_used: ctx_result.gas_used,
            gas_spent: ctx_result.gas_spent,
            gas_refunded: self.substate.refunded_gas,
            state_gas_used: net_state_gas_used,
            output: std::mem::take(&mut ctx_result.output),
            logs,
            payer_address: None,
            frame_results: None,
        };

        Ok(report)
    }

    // ── Struct-log helper methods ─────────────────────────────────────────────

    /// Collects the current stack in bottom-first order for struct-log emission.
    ///
    /// LEVM stack is top-first in memory (`values[offset]` = top), so we reverse
    /// the active slice to produce the bottom-first wire format geth uses.
    /// Returns an empty `Vec` when `cfg.disable_stack` is true.
    pub fn collect_stack_for_trace(&self) -> Vec<U256> {
        use crate::constants::STACK_LIMIT;
        if self.opcode_tracer.cfg.disable_stack {
            return Vec::new();
        }
        let s = &self.current_call_frame.stack;
        // offset <= STACK_LIMIT by stack invariant.
        s.values
            .get(s.offset..STACK_LIMIT)
            .map(|slice| slice.iter().rev().copied().collect())
            .unwrap_or_default()
    }

    /// Collects the live memory bytes for the current frame.
    ///
    /// Returns an empty `Vec` when `cfg.enable_memory` is false or memory is empty.
    pub fn collect_memory_for_trace(&self) -> Vec<u8> {
        if !self.opcode_tracer.cfg.enable_memory {
            return Vec::new();
        }
        self.current_call_frame.memory.live_bytes()
    }

    /// Pre-reads the storage key/value for the current SLOAD or SSTORE opcode.
    ///
    /// Returns `None` when:
    /// - `cfg.disable_storage` is set, or
    /// - `opcode` is not SLOAD (0x54) or SSTORE (0x55), or
    /// - the stack is empty (guard against underflow before the handler runs), or
    /// - the storage read fails for any reason (including `AccountNotFound` —
    ///   the trace omits the entry rather than emitting an ambiguous zero).
    ///
    /// For SLOAD: key = `stack.top`; value = the *current* stored value read from the DB.
    /// For SSTORE: key = `stack.top`, value = `stack[top-1]` (the new value being written).
    pub fn read_storage_for_trace(&mut self, opcode: u8) -> Option<(H256, H256)> {
        const SLOAD: u8 = 0x54;
        const SSTORE: u8 = 0x55;

        if self.opcode_tracer.cfg.disable_storage {
            return None;
        }
        if opcode != SLOAD && opcode != SSTORE {
            return None;
        }

        // Need at least one element on stack for SLOAD, two for SSTORE.
        use crate::constants::STACK_LIMIT;
        let offset = self.current_call_frame.stack.offset;
        if offset >= STACK_LIMIT {
            return None; // stack empty
        }

        // SLOAD/SSTORE operate on the call's storage context (`to`), not the code's
        // address. Under DELEGATECALL/CALLCODE these differ.
        let addr = self.current_call_frame.to;

        let stack_values = &self.current_call_frame.stack.values;
        let key_u256 = *stack_values.get(offset)?;
        let key = BigEndianHash::from_uint(&key_u256);

        if opcode == SLOAD {
            // Omit the entry on any read failure (incl. account not yet cached);
            // a zero value would be indistinguishable from a legitimate never-written slot.
            let v = self.get_storage_value(addr, key).ok()?;
            let value = BigEndianHash::from_uint(&v);
            Some((key, value))
        } else {
            // SSTORE: need two stack elements.
            let next_offset = offset.checked_add(1)?;
            if next_offset >= STACK_LIMIT {
                return None;
            }
            // values[offset+1] is the new value being written (second from top = stack[top-1]).
            let value_u256 = *self.current_call_frame.stack.values.get(next_offset)?;
            let value = BigEndianHash::from_uint(&value_u256);
            Some((key, value))
        }
    }
}

impl Substate {
    /// Initializes the VM substate, mainly adding addresses to the "accessed_addresses" field and the same with storage slots
    pub fn initialize(env: &Environment, tx: &Transaction) -> Result<Substate, VMError> {
        let fork = env.config.fork;

        // Add sender and recipient to accessed accounts [https://www.evm.codes/about#access_list]
        // Precompiles are NO LONGER inserted here — they are warm by construction (see
        // `is_warm_precompile`), removing the ~20-entry floor that used to dominate this set. The
        // remaining working set is small (sender + coinbase + recipient + access-list/touched
        // addresses; real p99 ~7), so a capacity of 8 covers most txs with little waste.
        let mut initial_accessed_addresses =
            FxHashSet::with_capacity_and_hasher(8, Default::default());
        // Storage slots are ~98% empty (p95 0, p99 4), so `default()` (alloc-free until first
        // insert) beats pre-sizing, which would tax the common empty case.
        let mut initial_accessed_storage_slots: FxHashMap<Address, FxHashSet<H256>> =
            FxHashMap::default();

        // Add Tx sender to accessed accounts
        initial_accessed_addresses.insert(env.origin);

        // [EIP-3651] - Add coinbase to accessed accounts after Shanghai
        if fork >= Fork::Shanghai {
            initial_accessed_addresses.insert(env.coinbase);
        }

        // Add access lists contents to accessed accounts and accessed storage slots.
        // Iterate by reference (`Address`/`H256` are `Copy`); the old `.clone()` deep-copied
        // the whole `Vec<(Address, Vec<H256>)>` per tx just to read it.
        for (address, keys) in tx.access_list() {
            initial_accessed_addresses.insert(*address);
            // Access lists can have different entries even for the same address, that's why we check if there's an existing set instead of considering it empty
            let warm_slots = initial_accessed_storage_slots.entry(*address).or_default();
            for slot in keys {
                warm_slots.insert(*slot);
            }
        }

        let substate = Substate::from_accesses(
            fork,
            initial_accessed_addresses,
            initial_accessed_storage_slots,
        );

        Ok(substate)
    }
}

// Test-support surface for the EIP-8037 state-gas reservoir/clamp-spill unit tests, which live
// in the `ethrex-test` crate (`test/tests/levm/eip8037_reservoir_tests.rs`) per the repo's
// test-location convention but must drive crate-private VM internals. Everything here is
// `#[doc(hidden)]` and exposes only what those tests touch: a fixture-free VM harness plus a
// handful of reservoir accessors. The harness builds the VM via struct literal to sidestep
// `VM::new`'s DB reads (which would pull `ethrex-storage`/`ethrex-blockchain` into levm and form
// a dependency cycle), keeping the two-pool arithmetic isolated.
#[doc(hidden)]
impl<'a> VM<'a> {
    /// Gas budget seeded into the harness top frame; large enough that spills never run it OOG.
    pub const STATE_GAS_HARNESS_FRAME_GAS: u64 = 1_000_000;

    /// Builds a fixture-free VM on `fork` with a single top frame and the given starting
    /// `state_gas_reservoir`. `db`/`tx`/`crypto` are borrowed for the VM's lifetime but never
    /// read (the frame is built directly, so no account/storage/code loads occur).
    pub fn new_state_gas_harness(
        fork: Fork,
        db: &'a mut GeneralizedDatabase,
        tx: &'a Transaction,
        crypto: &'a dyn Crypto,
        state_gas_reservoir: u64,
    ) -> VM<'a> {
        let env = Environment {
            config: crate::environment::EVMConfig::new(
                fork,
                crate::environment::EVMConfig::canonical_values(fork),
            ),
            gas_limit: Self::STATE_GAS_HARNESS_FRAME_GAS,
            block_gas_limit: Self::STATE_GAS_HARNESS_FRAME_GAS,
            ..Default::default()
        };
        let current_call_frame = CallFrame::new(
            Address::default(),
            Address::default(),
            Address::default(),
            Code::default(),
            U256::zero(),
            Bytes::new(),
            false,
            Self::STATE_GAS_HARNESS_FRAME_GAS,
            0,
            true,
            false,
            0,
            0,
            Stack::default(),
            Memory::default(),
        );
        VM {
            call_frames: Vec::new(),
            current_call_frame,
            env,
            substate: Substate::default(),
            db,
            tx,
            hooks: Vec::new(),
            storage_original_values: FxHashMap::default(),
            tracer: LevmCallTracer::disabled(),
            opcode_tracer: LevmOpcodeTracer::disabled(),
            debug_mode: DebugMode::disabled(),
            stack_pool: Vec::new(),
            vm_type: VMType::L1,
            preserve_top_level_backup: false,
            state_gas_used: 0,
            state_gas_reservoir,
            state_gas_reservoir_initial: state_gas_reservoir,
            state_gas_spill: 0,
            cost_per_state_byte: 0,
            state_gas_new_account: 0,
            state_gas_storage_set: 0,
            state_gas_auth_base: 0,
            intrinsic_state_gas: 0,
            value_new_account_charged: false,
            prep_baseline_state_gas: 0,
            prep_baseline_reservoir: 0,
            prep_baseline_state_gas_spill: 0,
            prep_region_backup_marker: PrepareRegionBackupMarker::default(),
            pending_prep_oog: false,
            opcode_table: VM::build_opcode_table(fork),
            crypto,
            stateless_validator: None,
            validation_observer: ValidationObserver::disabled(),
            frame_tx_context: None,
        }
    }

    pub fn state_gas_reservoir(&self) -> u64 {
        self.state_gas_reservoir
    }
    pub fn state_gas_used(&self) -> i64 {
        self.state_gas_used
    }
    pub fn state_gas_spill(&self) -> u64 {
        self.state_gas_spill
    }
    pub fn state_gas_new_account(&self) -> u64 {
        self.state_gas_new_account
    }
    pub fn set_state_gas_new_account(&mut self, v: u64) {
        self.state_gas_new_account = v;
    }
    /// Seeds the post-intrinsic baseline (mirrors `add_intrinsic_gas`): both the VM-level
    /// `state_gas_used` and the top frame's entry snapshot.
    pub fn seed_state_gas_baseline(&mut self, used: i64) {
        self.state_gas_used = used;
        self.current_call_frame.state_gas_used_at_entry = used;
    }
    pub fn frame_state_gas_used_at_entry(&self) -> i64 {
        self.current_call_frame.state_gas_used_at_entry
    }
    pub fn frame_gas_remaining(&self) -> i64 {
        self.current_call_frame.gas_remaining
    }
    pub fn set_frame_gas_remaining(&mut self, v: i64) {
        self.current_call_frame.gas_remaining = v;
    }
    pub fn frame_state_gas_spilled(&self) -> u64 {
        self.current_call_frame.frame_state_gas_spilled
    }
}
