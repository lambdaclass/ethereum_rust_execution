pub mod levm;
use ethrex_levm::precompiles::PrecompileMoves;
use levm::LEVM;

use crate::db::{DynVmDatabase, VmDatabase};
use crate::errors::{EvmError, SimulationTxError};
use crate::execution_result::ExecutionResult;
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::requests::Requests;
use ethrex_common::types::{
    AccessList, AccountUpdate, Block, BlockHeader, Fork, GenericTransaction, Receipt, Transaction,
    Withdrawal,
};
use ethrex_common::{Address, types::fee_config::FeeConfig};
use ethrex_crypto::Crypto;
pub use ethrex_levm::StatelessValidator;
pub use ethrex_levm::call_frame::CallFrameBackup;
use ethrex_levm::db::gen_db::GeneralizedDatabase;
pub use ethrex_levm::db::{BLOATED_BATCH_THRESHOLD, CachingDatabase, Database as LevmDatabase};
pub use ethrex_levm::errors::{self, InternalError, VMError};
use ethrex_levm::errors::{ExecutionReport, TxResult};
pub use ethrex_levm::vm::VMType;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::Sender;
use tracing::instrument;

#[derive(Clone)]
pub struct Evm {
    pub db: GeneralizedDatabase,
    pub vm_type: VMType,
    pub crypto: Arc<dyn Crypto>,
    pub stateless_validator: Option<Arc<dyn StatelessValidator>>,
}

/// Per-transaction knobs for `eth_simulateV1` execution
/// (see [`Evm::execute_tx_simulate`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct SimTxConfig {
    /// `validation` payload flag: when false the tx runs with `eth_call`-like
    /// relaxed checks (no nonce enforcement, zeroed unpriced blob fees).
    pub validate: bool,
    /// `traceTransfers` payload flag: emit informational ETH-transfer logs.
    pub trace_transfers: bool,
}

impl core::fmt::Debug for Evm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LEVM",)
    }
}

impl Evm {
    /// Install simulation-only precompile relocations (geth `movePrecompileToAddress`).
    ///
    /// RPC simulation paths only. Leaving this unset — every consensus path — keeps
    /// precompile dispatch bit-identical to the static table.
    pub fn set_precompile_moves(&mut self, moves: PrecompileMoves) {
        self.db.precompile_moves = (!moves.is_empty()).then(|| Arc::new(moves));
    }

    /// Creates a new EVM instance, but with block hash in zero, so if we want to execute a block or transaction we have to set it.
    pub fn new_for_l1(db: impl VmDatabase + 'static, crypto: Arc<dyn Crypto>) -> Self {
        let wrapped_db: DynVmDatabase = Box::new(db);
        Evm {
            db: GeneralizedDatabase::new(Arc::new(wrapped_db)),
            vm_type: VMType::L1,
            crypto,
            stateless_validator: None,
        }
    }

    pub fn new_for_l2(
        db: impl VmDatabase + 'static,
        fee_config: FeeConfig,
        crypto: Arc<dyn Crypto>,
    ) -> Result<Self, EvmError> {
        let wrapped_db: DynVmDatabase = Box::new(db);

        let evm = Evm {
            db: GeneralizedDatabase::new(Arc::new(wrapped_db)),
            vm_type: VMType::L2(fee_config),
            crypto,
            stateless_validator: None,
        };

        Ok(evm)
    }

    pub fn new_from_db_for_l1(
        store: Arc<impl LevmDatabase + 'static>,
        crypto: Arc<dyn Crypto>,
    ) -> Self {
        Self::_new_from_db(store, VMType::L1, crypto)
    }

    pub fn new_from_db_for_l2(
        store: Arc<impl LevmDatabase + 'static>,
        fee_config: FeeConfig,
        crypto: Arc<dyn Crypto>,
    ) -> Self {
        Self::_new_from_db(store, VMType::L2(fee_config), crypto)
    }

    fn _new_from_db(
        store: Arc<impl LevmDatabase + 'static>,
        vm_type: VMType,
        crypto: Arc<dyn Crypto>,
    ) -> Self {
        Evm {
            db: GeneralizedDatabase::new(store),
            vm_type,
            crypto,
            stateless_validator: None,
        }
    }

    /// Execute a block and return the execution result.
    ///
    /// Also records and returns the Block Access List (EIP-7928) for Amsterdam+ forks.
    /// The BAL will be `None` for pre-Amsterdam forks.
    pub fn execute_block(
        &mut self,
        block: &Block,
    ) -> Result<(BlockExecutionResult, Option<BlockAccessList>), EvmError> {
        LEVM::execute_block(
            block,
            &mut self.db,
            self.vm_type,
            self.crypto.as_ref(),
            self.stateless_validator.as_deref(),
        )
    }

    #[instrument(
        level = "trace",
        name = "Block execution",
        skip_all,
        fields(namespace = "block_execution")
    )]
    pub fn execute_block_pipeline(
        &mut self,
        block: &Block,
        merkleizer: Option<Sender<Vec<AccountUpdate>>>,
        queue_length: &AtomicUsize,
        bal: Option<Arc<BlockAccessList>>,
        bal_parallel_exec_enabled: bool,
    ) -> Result<(BlockExecutionResult, Option<BlockAccessList>), EvmError> {
        LEVM::execute_block_pipeline(
            block,
            &mut self.db,
            self.vm_type,
            merkleizer,
            queue_length,
            self.crypto.as_ref(),
            bal,
            bal_parallel_exec_enabled,
            self.stateless_validator.as_deref(),
        )
    }

    /// Wraps [LEVM::execute_tx].
    /// Updates `remaining_gas` (pre-refund) for block gas accounting and
    /// `cumulative_gas_spent` (post-refund) for receipt cumulative tracking.
    /// Returns (Receipt, gas_spent) where gas_spent is post-refund for block value calculation.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_tx(
        &mut self,
        tx: &Transaction,
        block_header: &BlockHeader,
        cumulative_gas_spent: &mut u64,
        sender: Address,
    ) -> Result<(Receipt, ExecutionReport), EvmError> {
        let mut execution_report = LEVM::execute_tx(
            tx,
            sender,
            block_header,
            &mut self.db,
            self.vm_type,
            self.crypto.as_ref(),
            self.stateless_validator.as_deref(),
        )?;

        // Track cumulative post-refund gas for receipt
        *cumulative_gas_spent += execution_report.gas_spent;

        let mut receipt = Receipt::new(
            tx.tx_type(),
            execution_report.is_success(),
            *cumulative_gas_spent,
            execution_report.logs.clone(),
        );

        // For frame transactions, populate payer and per-frame receipts
        if matches!(tx, Transaction::FrameTransaction(_)) {
            receipt.payer = execution_report.payer_address;
            receipt.frame_receipts = execution_report.frame_results.take().map(|results| {
                results
                    .into_iter()
                    .map(
                        |(status, gas_used, logs)| ethrex_common::types::FrameReceipt {
                            status,
                            gas_used,
                            logs,
                        },
                    )
                    .collect()
            });
        }

        Ok((receipt, execution_report))
    }

    /// Like [`Evm::execute_tx`] but for `eth_simulateV1`: validation failures
    /// are returned structured (see [`SimulationTxError`]) and the simulation
    /// relaxations from `config` are applied.
    pub fn execute_tx_simulate(
        &mut self,
        tx: &Transaction,
        block_header: &BlockHeader,
        cumulative_gas_spent: &mut u64,
        sender: Address,
        config: &SimTxConfig,
    ) -> Result<(Receipt, ExecutionReport), SimulationTxError> {
        let execution_report = LEVM::execute_tx_for_simulation(
            tx,
            sender,
            block_header,
            &mut self.db,
            self.vm_type,
            self.crypto.as_ref(),
            config.validate,
            config.trace_transfers,
        )?;

        *cumulative_gas_spent += execution_report.gas_spent;

        let receipt = Receipt::new(
            tx.tx_type(),
            execution_report.is_success(),
            *cumulative_gas_spent,
            execution_report.logs.clone(),
        );

        Ok((receipt, execution_report))
    }

    /// Current nonce for `address`, read through the live EVM cache so writes
    /// from previously executed transactions (same simulated block) are
    /// visible. Used by `eth_simulateV1` nonce auto-fill.
    pub fn get_account_nonce(&mut self, address: Address) -> Result<u64, EvmError> {
        Ok(self.db.get_account(address)?.info.nonce)
    }

    pub fn undo_last_tx(&mut self) -> Result<(), EvmError> {
        LEVM::undo_last_tx(&mut self.db)
    }

    /// Wraps [LEVM::beacon_root_contract_call], [LEVM::process_block_hash_history].
    /// This function is used to run/apply all the system contracts to the state.
    pub fn apply_system_calls(&mut self, block_header: &BlockHeader) -> Result<(), EvmError> {
        let chain_config = self.db.store.get_chain_config()?;
        let fork = chain_config.fork(block_header.timestamp);

        // EIP-8141: the expiry verifier predeploy must exist from Hegota
        // activation onward. Idempotent install for the
        // payload-build path; the block-import path is hooked in prepare_block.
        if fork >= Fork::Hegota && matches!(self.vm_type, VMType::L1) {
            LEVM::install_expiry_verifier_code(&mut self.db, self.crypto.as_ref())?;
        }

        if block_header.parent_beacon_block_root.is_some() && fork >= Fork::Cancun {
            LEVM::beacon_root_contract_call(
                block_header,
                &mut self.db,
                self.vm_type,
                self.crypto.as_ref(),
            )?;
        }

        if fork >= Fork::Prague {
            LEVM::process_block_hash_history(
                block_header,
                &mut self.db,
                self.vm_type,
                self.crypto.as_ref(),
            )?;
        }

        Ok(())
    }

    /// Wraps the [LEVM::get_state_transitions] which gathers the information from a [CacheDB].
    /// The output is `Vec<AccountUpdate>`.
    pub fn get_state_transitions(&mut self) -> Result<Vec<AccountUpdate>, EvmError> {
        LEVM::get_state_transitions(&mut self.db)
    }

    /// Wraps [LEVM::process_withdrawals].
    /// Applies the withdrawals to the state or the block_chache if using [LEVM].
    pub fn process_withdrawals(&mut self, withdrawals: &[Withdrawal]) -> Result<(), EvmError> {
        LEVM::process_withdrawals(&mut self.db, withdrawals)
    }

    pub fn extract_requests(
        &mut self,
        receipts: &[Receipt],
        header: &BlockHeader,
    ) -> Result<Vec<Requests>, EvmError> {
        levm::extract_all_requests_levm(
            receipts,
            &mut self.db,
            header,
            self.vm_type,
            self.crypto.as_ref(),
        )
    }

    /// Takes the Block Access List (BAL) from the database if recording was enabled.
    /// Returns `None` if BAL recording was not enabled.
    pub fn take_bal(&mut self) -> Option<BlockAccessList> {
        self.db.take_bal()
    }

    /// Enables BAL (Block Access List) recording for EIP-7928.
    pub fn enable_bal_recording(&mut self) {
        self.db.enable_bal_recording();
    }

    /// Sets the current block access index for BAL recording per EIP-7928 spec (uint32).
    pub fn set_bal_index(&mut self, index: u32) {
        self.db.set_bal_index(index);
    }

    pub fn simulate_tx_from_generic(
        &mut self,
        tx: &GenericTransaction,
        header: &BlockHeader,
    ) -> Result<ExecutionResult, EvmError> {
        LEVM::simulate_tx_from_generic(
            tx,
            header,
            &mut self.db,
            self.vm_type,
            self.crypto.as_ref(),
            self.stateless_validator.as_deref(),
        )
    }

    /// EIP-8141 mempool validation-prefix simulation (local peer policy).
    /// Wraps [`LEVM::simulate_frame_validation_prefix`].
    pub fn simulate_frame_validation_prefix(
        &mut self,
        tx: &Transaction,
        header: &BlockHeader,
        prefix: &ethrex_common::types::ValidationPrefix,
        canonical_paymaster_code_hash: Option<ethrex_common::H256>,
    ) -> Result<FrameValidationOutcome, EvmError> {
        LEVM::simulate_frame_validation_prefix(
            tx,
            header,
            &mut self.db,
            self.vm_type,
            self.crypto.as_ref(),
            prefix,
            canonical_paymaster_code_hash,
        )
    }

    pub fn create_access_list(
        &mut self,
        tx: &GenericTransaction,
        header: &BlockHeader,
    ) -> Result<(u64, AccessList, Option<String>), EvmError> {
        let result = {
            LEVM::create_access_list(
                tx.clone(),
                header,
                &mut self.db,
                self.vm_type,
                self.crypto.as_ref(),
            )?
        };

        match result {
            (
                ExecutionResult::Success {
                    gas_used,
                    gas_refunded: _,
                    logs: _,
                    output: _,
                },
                access_list,
            ) => Ok((gas_used, access_list, None)),
            (
                ExecutionResult::Revert {
                    gas_used,
                    output: _,
                },
                access_list,
            ) => Ok((
                gas_used,
                access_list,
                Some("Transaction Reverted".to_string()),
            )),
            (ExecutionResult::Halt { reason, gas_used }, access_list) => {
                Ok((gas_used, access_list, Some(reason)))
            }
        }
    }
}

/// Compute burned fees for a block (EIP-8079, LStar+).
///
/// Formula: `base_fee_per_gas * gas_spent + blob_base_fee * blob_gas_used`
///
/// `gas_spent` is the post-refund Σ gas_spent across all transactions (= the last
/// receipt's `cumulative_gas_used`).  Per EIP-8079 the fee basis is post-refund:
/// users receive EIP-3529 refunds, so only the net gas actually charged is burned.
/// Production and verification always compute the identical value because both paths
/// build identical receipts from the same transactions and initial state.
///
/// Uses saturating arithmetic; saturates at `u64::MAX` on overflow.
pub fn compute_burned_fees(
    base_fee_per_gas: u64,
    gas_spent: u64,
    blob_base_fee: u64,
    blob_gas_used: u64,
) -> u64 {
    base_fee_per_gas
        .saturating_mul(gas_spent)
        .saturating_add(blob_base_fee.saturating_mul(blob_gas_used))
}

/// Outcome of an EIP-8141 mempool validation-prefix simulation
/// ([`Evm::simulate_frame_validation_prefix`]). A local peer policy result, not
/// a consensus value.
#[derive(Clone, Debug)]
pub struct FrameValidationOutcome {
    /// Whether the validation prefix passed every trace rule and produced a
    /// payer without reverting within the verify-gas budget.
    pub passed: bool,
    /// The first validation-trace violation observed, if any (rendered to a
    /// string for the admission error). `None` when `passed` is true.
    pub violation: Option<String>,
    /// An upper bound on what the payer can be charged in any block that may
    /// include this transaction, used by the paymaster reservation accounting.
    /// Not the consensus `max_cost` of TXPARAM 0x06: see
    /// [`Evm::simulate_frame_validation_prefix`]'s reservation-ceiling helper for
    /// why the blob term is priced at `max_fee_per_blob_gas` here.
    pub reservation_ceiling: ethrex_common::U256,
    /// The paymaster accessed by the prefix and whether its code matched the
    /// canonical paymaster hash. `None` when no distinct paymaster was
    /// identified (e.g. self-funded self_verify).
    pub accessed_paymaster: Option<(Address, bool)>,
    /// Sender storage slots touched during the prefix, recorded for the
    /// admission-time revalidation affected-set (Phase 3).
    pub touched_sender_slots: Vec<ethrex_common::H256>,
}

#[derive(Clone, Debug)]
pub struct BlockExecutionResult {
    pub receipts: Vec<Receipt>,
    pub requests: Vec<Requests>,
    /// Block gas used (PRE-REFUND for Amsterdam+ per EIP-7778).
    /// This differs from receipt cumulative_gas_used which is POST-REFUND.
    pub block_gas_used: u64,
    /// Total base-fee + blob-base-fee burned in this block (EIP-8079, LStar+).
    /// `None` for pre-LStar forks.
    /// Formula: `base_fee_per_gas * Σgas_spent + blob_base_fee * blob_gas_used`,
    /// where `Σgas_spent` = `receipts.last().cumulative_gas_used` (post-refund; per EIP-8079).
    /// Uses saturating arithmetic; saturates at u64::MAX on extreme values.
    pub burned_fees: Option<u64>,
    /// Per-tx gas-dimension breakdown. Populated by `execute_block`; left empty by
    /// L2 producer / committer paths that build a `BlockExecutionResult` from
    /// re-derived data. Used by `validate_gas_used` mismatch logging to localize
    /// which tx and which dimension caused the divergence.
    pub tx_gas_breakdowns: Vec<TxGasBreakdown>,
}

/// Per-tx gas-dimension snapshot captured at the block-execution boundary.
/// All fields are pre-refund except `gas_spent` and `gas_refunded` which are
/// the user-pays (post-refund) values.
#[derive(Clone, Debug)]
pub struct TxGasBreakdown {
    pub tx_index: usize,
    pub tx_hash: ethrex_common::H256,
    pub status: TxStatus,
    /// Pre-refund gas used (block-level dimension under EIP-7778).
    pub gas_used: u64,
    /// Post-refund gas paid by the sender.
    pub gas_spent: u64,
    pub gas_refunded: u64,
    /// EIP-8037 state-gas portion of `gas_used` (Amsterdam+); 0 pre-Amsterdam.
    pub state_gas_used: u64,
    /// `gas_used - state_gas_used`. Saturating to avoid underflow on edge cases.
    pub regular_gas_used: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Success,
    Revert,
    Halt,
}

impl core::fmt::Display for TxStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxStatus::Success => f.write_str("success"),
            TxStatus::Revert => f.write_str("revert"),
            TxStatus::Halt => f.write_str("halt"),
        }
    }
}

impl TxGasBreakdown {
    pub fn from_report(
        tx_index: usize,
        tx_hash: ethrex_common::H256,
        report: &ExecutionReport,
    ) -> Self {
        let status = match &report.result {
            TxResult::Success => TxStatus::Success,
            TxResult::Revert(err) if err.is_revert_opcode() => TxStatus::Revert,
            TxResult::Revert(_) => TxStatus::Halt,
        };
        Self {
            tx_index,
            tx_hash,
            status,
            gas_used: report.gas_used,
            gas_spent: report.gas_spent,
            gas_refunded: report.gas_refunded,
            state_gas_used: report.state_gas_used,
            regular_gas_used: report.gas_used.saturating_sub(report.state_gas_used),
        }
    }
}

/// Emit a structured per-tx gas-dimension dump. Called from the block-validation
/// site when `block_gas_used` disagrees with `header.gas_used`. If `breakdowns` is
/// empty (paths that don't populate it, e.g. L2 producer), a one-liner is logged.
pub fn log_gas_used_mismatch(
    breakdowns: &[TxGasBreakdown],
    block_number: u64,
    actual: u64,
    expected: u64,
) {
    let delta = actual as i128 - expected as i128;
    if breakdowns.is_empty() {
        ::tracing::error!(
            block = block_number,
            actual,
            expected,
            delta,
            "block gas_used mismatch (no per-tx breakdown available on this path)",
        );
        return;
    }
    let sum_regular: u64 = breakdowns.iter().map(|b| b.regular_gas_used).sum();
    let sum_state: u64 = breakdowns.iter().map(|b| b.state_gas_used).sum();
    let sum_refunded: u64 = breakdowns.iter().map(|b| b.gas_refunded).sum();
    ::tracing::error!(
        block = block_number,
        actual,
        expected,
        delta,
        n_txs = breakdowns.len(),
        sum_regular,
        sum_state,
        max_dim = sum_regular.max(sum_state),
        sum_refunded,
        "block gas_used mismatch",
    );
    for b in breakdowns {
        ::tracing::error!(
            tx_idx = b.tx_index,
            tx_hash = %b.tx_hash,
            status = %b.status,
            gas_used = b.gas_used,
            regular = b.regular_gas_used,
            state = b.state_gas_used,
            gas_spent = b.gas_spent,
            gas_refunded = b.gas_refunded,
            "  tx breakdown",
        );
    }
}
