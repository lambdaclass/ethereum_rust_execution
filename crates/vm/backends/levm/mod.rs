pub mod db;
mod tracing;

use super::{BlockExecutionResult, FrameValidationOutcome, TxGasBreakdown, compute_burned_fees};
use crate::system_contracts::{
    AMSTERDAM_REQUEST_PREDEPLOYS, BEACON_ROOTS_ADDRESS, BUILDER_DEPOSIT_CONTRACT_ADDRESS,
    BUILDER_EXIT_CONTRACT_ADDRESS, CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
    EXPIRY_VERIFIER_PREDEPLOY, EXPIRY_VERIFIER_RUNTIME_BYTECODE, HISTORY_STORAGE_ADDRESS,
    PRAGUE_SYSTEM_CONTRACTS, SYSTEM_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
};
use crate::{EvmError, ExecutionResult, SimulationTxError};
use bytes::Bytes;
use ethrex_common::H256;
#[cfg(feature = "rayon")]
use ethrex_common::constants::EMPTY_KECCAK_HASH;
use ethrex_common::types::Code;
#[cfg(feature = "rayon")]
use ethrex_common::types::TxType;
use ethrex_common::types::block_access_list::BlockAccessList;
#[cfg(feature = "rayon")]
use ethrex_common::types::block_access_list::{
    BalAddressIndex, find_exact_change_balance, find_exact_change_code, find_exact_change_nonce,
    find_exact_change_storage, has_exact_change_balance, has_exact_change_code,
    has_exact_change_nonce, has_exact_change_storage,
};
use ethrex_common::types::fee_config::FeeConfig;
use ethrex_common::types::{AuthorizationTuple, EIP7702Transaction};
#[cfg(feature = "rayon")]
use ethrex_common::utils::u256_from_big_endian_const;
use ethrex_common::{
    Address, U256,
    types::{
        AccessList, AccountUpdate, Block, BlockHeader, EIP1559Transaction, Fork, FrameReceipt,
        GWEI_TO_WEI, GenericTransaction, INITIAL_BASE_FEE, Log, Receipt, Transaction, TxKind,
        Withdrawal, requests::Requests,
    },
};
#[cfg(feature = "rayon")]
use ethrex_common::{BigEndianHash, validate_block_access_list_size, validate_header_bal_indices};
use ethrex_crypto::Crypto;
use ethrex_levm::EVMConfig;
use ethrex_levm::StatelessValidator;
#[cfg(feature = "rayon")]
use ethrex_levm::account::{AccountStatus, LevmAccount};
use ethrex_levm::call_frame::Stack;
use ethrex_levm::constants::{
    POST_OSAKA_GAS_LIMIT_CAP, STACK_LIMIT, SYS_CALL_GAS_LIMIT, TX_MAX_GAS_LIMIT_AMSTERDAM,
};
use ethrex_levm::db::gen_db::GeneralizedDatabase;
#[cfg(feature = "rayon")]
use ethrex_levm::db::gen_db::{
    LazyBalCursor, code_from_bal, post_value_at_or_before, seed_one_address_info_from_bal,
};
#[cfg(feature = "rayon")]
use ethrex_levm::db::{Database, gen_db::CacheDB};
use ethrex_levm::errors::{InternalError, TxValidationError};
use ethrex_levm::memory::Memory;
#[cfg(feature = "perf_opcode_timings")]
use ethrex_levm::timings::{OPCODE_TIMINGS, PRECOMPILES_TIMINGS};
use ethrex_levm::tracing::LevmCallTracer;
use ethrex_levm::utils::get_base_fee_per_blob_gas;
use ethrex_levm::validation_observer::FrameSimViolation;
use ethrex_levm::vm::VMType;
use ethrex_levm::{
    Environment,
    errors::{ExecutionReport, TxResult, VMError},
    vm::VM,
};
#[cfg(feature = "rayon")]
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
#[cfg(feature = "rayon")]
use rustc_hash::{FxHashMap, FxHashSet};
use std::cmp::min;
use std::sync::Arc;
#[cfg(feature = "rayon")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;

/// EIP-8079 `burned_fees` for an LStar block: `base_fee · post_refund_gas +
/// blob_base_fee · blob_gas_used`. `post_refund_gas` is the block's post-refund
/// Σ gas_spent (the running `cumulative_gas_used`, equivalently the last
/// receipt's `cumulative_gas_used`). Callers gate this on `is_lstar` and wrap
/// the result in `Some`. Extracted so the production and verification paths
/// (`execute_block` and both `execute_block_pipeline` arms) derive the burn
/// identically.
fn lstar_burned_fees(
    chain_config: &ethrex_common::types::ChainConfig,
    header: &ethrex_common::types::BlockHeader,
    post_refund_gas: u64,
) -> u64 {
    let evm_cfg = EVMConfig::new_from_chain_config(chain_config, header);
    let blob_base_fee = get_base_fee_per_blob_gas(header.excess_blob_gas, &evm_cfg)
        .map(|v| u64::try_from(v).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let blob_gas_used = header.blob_gas_used.unwrap_or(0);
    compute_burned_fees(
        header.base_fee_per_gas.unwrap_or(0),
        // EIP-8079: burn basis is post-refund Σ gas_spent.
        post_refund_gas,
        blob_base_fee,
        blob_gas_used,
    )
}

/// The struct implements the following functions:
/// [LEVM::execute_block]
/// [LEVM::execute_tx]
/// [LEVM::get_state_transitions]
/// [LEVM::process_withdrawals]
#[derive(Debug)]
pub struct LEVM;

/// Build the per-frame receipts (EIP-8141) for a frame transaction from an
/// execution report's `frame_results`. Returns `None` when the report carries
/// no frame results.
fn frame_receipts_from(
    frame_results: Option<Vec<(u8, u64, Vec<Log>)>>,
) -> Option<Vec<FrameReceipt>> {
    frame_results.map(|results| {
        results
            .into_iter()
            .map(|(status, gas_used, logs)| FrameReceipt {
                status,
                gas_used,
                logs,
            })
            .collect()
    })
}

/// Checks that adding `tx_gas_limit` to `block_gas_used` doesn't exceed `block_gas_limit`.
fn check_gas_limit(
    block_gas_used: u64,
    tx_gas_limit: u64,
    block_gas_limit: u64,
) -> Result<(), EvmError> {
    if tx_gas_limit > block_gas_limit.saturating_sub(block_gas_used) {
        return Err(EvmError::Transaction(format!(
            "Gas allowance exceeded: \
             used {block_gas_used} + tx limit {tx_gas_limit} > block limit {block_gas_limit}"
        )));
    }
    Ok(())
}

/// EIP-8037 (Amsterdam+, execution-specs PR #2703) per-tx 2D inclusion check.
///
/// A tx is rejected (block invalid) if its worst-case contribution to either
/// dimension exceeds the remaining budget at tx inclusion time:
///
/// - regular dim: `min(TX_MAX_GAS_LIMIT, tx.gas) > block_gas_limit - block_regular_gas_used`
/// - state dim:   `tx.gas > block_gas_limit - block_state_gas_used`
///
/// The full `tx.gas` is used in both dimensions (only the regular dimension is
/// capped at `TX_MAX_GAS_LIMIT`); intrinsic underfunding is rejected separately
/// in transaction validation, not here. Mirrors
/// `src/ethereum/forks/amsterdam/fork.py` `check_transaction` at the
/// `tests-glamsterdam-devnet@v7.1.0` spec.
///
/// Note: `block_gas_used_regular` here equals EELS's `block_output.block_gas_used`
/// because our `report.gas_used` already reflects `max(raw_regular, calldata_floor)`
/// per-tx — i.e. the floor is applied before aggregation, not after. Keep this in
/// sync with the aggregation loop in [`execute_block_parallel`].
pub fn check_2d_gas_allowance(
    tx: &Transaction,
    block_gas_used_regular: u64,
    block_gas_used_state: u64,
    block_gas_limit: u64,
) -> Result<(), EvmError> {
    let tx_gas = tx.gas_limit();
    let regular_available = block_gas_limit.saturating_sub(block_gas_used_regular);
    let state_available = block_gas_limit.saturating_sub(block_gas_used_state);

    // Regular dim: worst-case regular contribution = full tx.gas, capped at
    // TX_MAX_GAS_LIMIT. The spec uses the full tx gas with no intrinsic
    // subtraction; intrinsic underfunding is rejected separately in transaction
    // validation, not by this inclusion check.
    let regular_contrib = tx_gas.min(TX_MAX_GAS_LIMIT_AMSTERDAM);
    if regular_contrib > regular_available {
        return Err(EvmError::Transaction(format!(
            "Gas allowance exceeded: regular dim worst-case {regular_contrib} > \
             available {regular_available} (block_gas_used_regular={block_gas_used_regular}, \
             block_gas_limit={block_gas_limit})"
        )));
    }

    // State dim: worst-case state contribution = full tx.gas.
    let state_contrib = tx_gas;
    if state_contrib > state_available {
        return Err(EvmError::Transaction(format!(
            "Gas allowance exceeded: state dim worst-case {state_contrib} > \
             available {state_available} (block_gas_used_state={block_gas_used_state}, \
             block_gas_limit={block_gas_limit})"
        )));
    }

    Ok(())
}

/// Error type for BAL validation failures, distinguishing state mismatches
/// from database errors.
///
/// Public so [`LEVM::validate_tx_execution`] is directly callable (and its
/// error variants inspectable) from unit tests outside this crate.
#[cfg(feature = "rayon")]
#[derive(Debug, thiserror::Error)]
pub enum BalValidationError {
    #[error("{0}")]
    Mismatch(String),
    #[error("{0}")]
    Database(String),
}

impl LEVM {
    /// Execute a block and return the execution result.
    ///
    /// Also records and returns the Block Access List (EIP-7928) for Amsterdam+ forks.
    /// The BAL will be `None` for pre-Amsterdam forks.
    pub fn execute_block(
        block: &Block,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
        stateless_validator: Option<&dyn StatelessValidator>,
    ) -> Result<(BlockExecutionResult, Option<BlockAccessList>), EvmError> {
        let chain_config = db.store.get_chain_config()?;
        let is_amsterdam = chain_config.is_amsterdam_activated(block.header.timestamp);
        // EIP-8079 (LStar+): compute burned fees
        let is_lstar = chain_config.is_lstar_activated(block.header.timestamp);

        // EIP-7928 BlockAccessIndex is uint32. Block validity forbids >= 2^32 txs
        // long before we'd reach this point, but guard the invariant explicitly
        // so any upstream bug that inflates tx counts panics in debug instead of
        // silently producing a `u32::MAX` index.
        debug_assert!(
            block.body.transactions.len() < u32::MAX as usize,
            "tx count overflows u32 BlockAccessIndex"
        );

        // Enable BAL recording for Amsterdam+ forks
        if is_amsterdam {
            db.enable_bal_recording();
            // Set index 0 for pre-execution phase (system contracts)
            db.set_bal_index(0);
        }

        Self::prepare_block(block, db, vm_type, crypto)?;

        // Block-invariant EVM config + chain id + base blob fee, computed once and
        // reused by every tx (mirrors `execute_block_pipeline`): avoids a per-tx
        // chain-config copy, fork/blob-schedule recompute, and `fake_exponential` call.
        let evm_config = EVMConfig::new_from_chain_config(&chain_config, &block.header);
        let chain_id = chain_config.chain_id;
        let base_blob_fee_per_gas =
            get_base_fee_per_blob_gas(block.header.excess_blob_gas, &evm_config)?;
        // Stack/memory buffer pools reused across txs (each tx draws one and reclaims it).
        let mut shared_stack_pool = Vec::with_capacity(STACK_LIMIT);
        let mut shared_memory_pool = Vec::with_capacity(1);

        let n_txs = block.body.transactions.len();
        let mut receipts = Vec::with_capacity(n_txs);
        let mut tx_gas_breakdowns: Vec<TxGasBreakdown> = Vec::with_capacity(n_txs);
        // Cumulative gas for receipts (POST-REFUND per EIP-7778)
        let mut cumulative_gas_used = 0_u64;
        // Block gas accounting (PRE-REFUND for Amsterdam+ per EIP-7778)
        let mut block_gas_used = 0_u64;
        // EIP-8037 (Amsterdam+): track regular and state gas separately for block-level max()
        let mut block_regular_gas_used = 0_u64;
        let mut block_state_gas_used = 0_u64;
        let transactions_with_sender =
            block
                .body
                .get_transactions_with_sender(crypto)
                .map_err(|error| {
                    EvmError::Transaction(format!("Couldn't recover addresses with error: {error}"))
                })?;

        for (tx_idx, (tx, tx_sender)) in transactions_with_sender.into_iter().enumerate() {
            // Pre-tx gas limit guard:
            // Pre-Amsterdam: reject tx if cumulative post-refund gas + tx.gas > block limit.
            // Amsterdam+: skip — EIP-8037's 2D gas model means cumulative gas (regular +
            // state) can legally exceed the block gas limit as long as
            // max(sum_regular, sum_state) stays within it. Block-level overflow is
            // detected post-execution.
            if !is_amsterdam {
                check_gas_limit(cumulative_gas_used, tx.gas_limit(), block.header.gas_limit)?;
            }

            // EIP-8037 (Amsterdam+, PR #2703): per-tx 2D inclusion check.
            if is_amsterdam {
                check_2d_gas_allowance(
                    tx,
                    block_regular_gas_used,
                    block_state_gas_used,
                    block.header.gas_limit,
                )?;
            }

            // Set BAL index for this transaction (1-indexed per EIP-7928)
            if is_amsterdam {
                let bal_index = u32::try_from(tx_idx + 1).unwrap_or(u32::MAX);
                db.set_bal_index(bal_index);

                // Record tx sender for BAL. The recipient is recorded when the prepare
                // region loads it (default_hook), per the EIP-7928 v7.1.0 update: an
                // EIP-7702 auth halt before the recipient load must exclude it.
                if let Some(recorder) = db.bal_recorder_mut() {
                    recorder.record_touched_address(tx_sender);
                }
            }

            let report = Self::execute_tx_in_block(
                tx,
                tx_sender,
                &block.header,
                db,
                vm_type,
                base_blob_fee_per_gas,
                &mut shared_stack_pool,
                &mut shared_memory_pool,
                false,
                crypto,
                evm_config,
                chain_id,
                stateless_validator,
            )?;

            tx_gas_breakdowns.push(TxGasBreakdown::from_report(
                tx_idx,
                tx.hash(crypto),
                &report,
            ));

            // EIP-7778: gas_spent (POST-REFUND) for receipt cumulative_gas_used
            cumulative_gas_used += report.gas_spent;

            // EIP-8037 (Amsterdam+): block_gas_used = max(sum_regular, sum_state)
            // For pre-Amsterdam, state_gas_used is always 0 so gas_used == regular_gas.
            let tx_state_gas = report.state_gas_used;
            let tx_regular_gas = report.gas_used.saturating_sub(tx_state_gas);
            block_regular_gas_used = block_regular_gas_used.saturating_add(tx_regular_gas);
            block_state_gas_used = block_state_gas_used.saturating_add(tx_state_gas);

            if is_amsterdam {
                // Amsterdam+: block gas = max(regular_sum, state_sum)
                block_gas_used = block_regular_gas_used.max(block_state_gas_used);
                ::tracing::debug!(
                    "EIP-8037 validate tx[{tx_idx}]: regular={tx_regular_gas} state={tx_state_gas} gas_used={} gas_spent={} block_regular={block_regular_gas_used} block_state={block_state_gas_used} block_max={block_gas_used}",
                    report.gas_used,
                    report.gas_spent,
                );

                // DoS protection: early exit if either regular or state gas exceeds the limit.
                // Since block_gas_used = max(regular, state), if either component exceeds
                // the limit, we know the block is invalid and can safely reject without
                // violating EIP-8037 semantics.
                if block_regular_gas_used > block.header.gas_limit
                    || block_state_gas_used > block.header.gas_limit
                {
                    return Err(EvmError::Transaction(format!(
                        "Gas allowance exceeded: Block gas used overflow: \
                         block_gas_used {block_gas_used} > block_gas_limit {}",
                        block.header.gas_limit
                    )));
                }
            } else {
                block_gas_used = block_gas_used.saturating_add(report.gas_used);
            }

            let mut receipt = Receipt::new(
                tx.tx_type(),
                matches!(report.result, TxResult::Success),
                cumulative_gas_used,
                report.logs,
            );

            // For frame transactions, propagate payer and per-frame receipts
            if matches!(tx, Transaction::FrameTransaction(_)) {
                receipt.payer = report.payer_address;
                receipt.frame_receipts = frame_receipts_from(report.frame_results);
            }

            receipts.push(receipt);
        }

        // EIP-7778 (Amsterdam+): block-level gas overflow check.
        // Per-tx checks are skipped for Amsterdam because block gas is computed
        // from pre-refund values; overflow can only be detected after execution.
        if is_amsterdam && block_gas_used > block.header.gas_limit {
            return Err(EvmError::Transaction(format!(
                "Gas allowance exceeded: Block gas used overflow: \
                 block_gas_used {block_gas_used} > block_gas_limit {}",
                block.header.gas_limit
            )));
        }

        // Set BAL index for post-execution phase (requests + withdrawals)
        // Order must match geth: requests (system calls) BEFORE withdrawals.
        if is_amsterdam {
            let post_tx_index =
                u32::try_from(block.body.transactions.len() + 1).unwrap_or(u32::MAX);
            db.set_bal_index(post_tx_index);

            // Record ALL withdrawal recipients for BAL per EIP-7928:
            // "Withdrawal recipients regardless of amount"
            // The amount filter only applies to balance_changes, not touched_addresses
            if let Some(withdrawals) = &block.body.withdrawals
                && let Some(recorder) = db.bal_recorder_mut()
            {
                recorder.extend_touched_addresses(withdrawals.iter().map(|w| w.address));
            }
        }

        // TODO: I don't like deciding the behavior based on the VMType here.
        // TODO2: Revise this, apparently extract_all_requests_levm is not called
        // in L2 execution, but its implementation behaves differently based on this.
        let requests = match vm_type {
            VMType::L1 => extract_all_requests_levm(&receipts, db, &block.header, vm_type, crypto)?,
            VMType::L2(_) => Default::default(),
        };

        if let Some(withdrawals) = &block.body.withdrawals {
            Self::process_withdrawals(db, withdrawals)?;
        }

        // Extract BAL if recording was enabled
        let bal = db.take_bal();

        Ok((
            BlockExecutionResult {
                receipts,
                requests,
                block_gas_used,
                // cumulative_gas_used is accumulated as += report.gas_spent (post-refund).
                burned_fees: is_lstar
                    .then(|| lstar_burned_fees(&chain_config, &block.header, cumulative_gas_used)),
                tx_gas_breakdowns,
            },
            bal,
        ))
    }

    /// `merkleizer` is `Some` on the streaming (non-BAL) path; the BAL validation path
    /// passes `None` because the caller merkleizes optimistically from the input BAL and
    /// the EVM-side `bal_to_account_updates` send is then redundant work.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_block_pipeline(
        block: &Block,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        merkleizer: Option<Sender<Vec<AccountUpdate>>>,
        queue_length: &AtomicUsize,
        crypto: &dyn Crypto,
        header_bal: Option<Arc<BlockAccessList>>,
        bal_parallel_exec_enabled: bool,
        stateless_validator: Option<&dyn StatelessValidator>,
    ) -> Result<(BlockExecutionResult, Option<BlockAccessList>), EvmError> {
        let chain_config = db.store.get_chain_config()?;
        let is_amsterdam = chain_config.is_amsterdam_activated(block.header.timestamp);
        let is_lstar = chain_config.is_lstar_activated(block.header.timestamp);
        // Block-invariant EVM config + chain id, computed once and reused by every tx
        // (avoids a per-tx chain-config dyn-dispatch copy + fork/blob-schedule recompute).
        let evm_config = EVMConfig::new_from_chain_config(&chain_config, &block.header);
        let chain_id = chain_config.chain_id;

        // EIP-7928 BlockAccessIndex invariant — see `execute_block` for rationale.
        debug_assert!(
            block.body.transactions.len() < u32::MAX as usize,
            "tx count overflows u32 BlockAccessIndex"
        );

        let transactions_with_sender =
            block
                .body
                .get_transactions_with_sender(crypto)
                .map_err(|error| {
                    EvmError::Transaction(format!("Couldn't recover addresses with error: {error}"))
                })?;

        #[cfg(not(feature = "rayon"))]
        // Without rayon there is no parallel BAL path, so these are unused.
        // Adding dummy let to avoid unused warnings.
        let _ = (header_bal, bal_parallel_exec_enabled);
        #[cfg(feature = "rayon")]
        // When BAL is provided (Amsterdam+ validation path): use parallel execution.
        // The `is_amsterdam` gate is required: `execute_block_parallel` (and the
        // optimistic merkleization it feeds) is only correct on Amsterdam+; a
        // pre-Amsterdam call here in release would skip the inner debug_assert.
        // `--no-bal-parallel-exec` opts out and falls through to the sequential pipeline below.
        if let Some(bal) = header_bal
            && is_amsterdam
            && bal_parallel_exec_enabled
        {
            // Validate header BAL structural properties before execution.
            // This catches index-out-of-bounds early, before wasting execution time.
            // Note: size cap validation is deferred until after transaction processing
            // so that transaction-level errors (e.g. gas allowance exceeded) take
            // priority, matching the reference implementation's validation order.
            validate_header_bal_indices(&bal, block.body.transactions.len())
                .map_err(|e| EvmError::Custom(e.to_string()))?;

            // Outer db has no BAL recorder: header BAL drives validation.
            // Per-tx tx_dbs enable a shadow recorder for accessed-entry checks.
            Self::prepare_block(block, db, vm_type, crypto)?;

            // Build validation index once — shared across parallel execution and post-exec seeding.
            let validation_index = Arc::new(bal.build_validation_index());

            // Validate supplied-BAL entries at the pre-execution index (0). The
            // per-tx (`validate_tx_execution`) and withdrawal
            // (`validate_bal_withdrawal_index`) validators never reach index 0,
            // so a spurious no-op entry there would otherwise pass the parallel
            // path (it leaves the state root unchanged). Must run before
            // `get_state_transitions_tx` drains `current_accounts_state`.
            Self::validate_bal_pre_exec_index(db, &bal, &validation_index)?;

            // Drain system call state and snapshot for per-tx db seeding
            LEVM::get_state_transitions_tx(db)?;
            let system_seed = Arc::new(std::mem::take(&mut db.initial_accounts_state));

            let parallel_result = Self::execute_block_parallel(
                block,
                &transactions_with_sender,
                db,
                vm_type,
                Arc::clone(&bal),
                merkleizer.as_ref(),
                queue_length,
                system_seed,
                crypto,
                Arc::clone(&validation_index),
                stateless_validator,
            );

            // If parallel execution failed (e.g. BAL validation), still check system
            // contracts — SystemContractCallFailed takes priority over BAL errors.
            // The BAL may be inconsistent for blocks that are fundamentally invalid
            // due to a failing system contract.
            let (
                receipts,
                block_gas_used,
                mut unread_storage_reads,
                mut unaccessed_pure_accounts,
                tx_gas_breakdowns,
            ) = match parallel_result {
                Ok(result) => result,
                Err(parallel_err) => {
                    let last_tx_idx =
                        u32::try_from(block.body.transactions.len()).unwrap_or(u32::MAX);
                    if Self::seed_db_from_bal(
                        db,
                        &bal,
                        last_tx_idx,
                        &validation_index.accounts_by_min_index,
                    )
                    .is_ok()
                        && let VMType::L1 = vm_type
                        && let Err(e @ EvmError::SystemContractCallFailed(_)) =
                            extract_all_requests_levm(&[], db, &block.header, vm_type, crypto)
                    {
                        return Err(e);
                    }
                    return Err(parallel_err);
                }
            };

            // Seed main db with post-tx state (excluding withdrawal effects) so
            // request extraction system calls see user-queued requests on predeploys.
            // Withdrawal index is n_txs+1 in BAL; we use n_txs to avoid double-applying
            // withdrawal balances (process_withdrawals handles those below).
            let last_tx_idx = u32::try_from(block.body.transactions.len()).unwrap_or(u32::MAX);
            // Eager seed retained: lazy_bal cursor is per-tx only; outer DB has no cursor.
            Self::seed_db_from_bal(
                db,
                &bal,
                last_tx_idx,
                &validation_index.accounts_by_min_index,
            )?;

            // Order must match geth: requests (system calls) BEFORE withdrawals.
            let requests = match vm_type {
                VMType::L1 => {
                    extract_all_requests_levm(&receipts, db, &block.header, vm_type, crypto)?
                }
                VMType::L2(_) => Default::default(),
            };

            if let Some(withdrawals) = &block.body.withdrawals {
                Self::process_withdrawals(db, withdrawals)?;
            }
            // State transitions for merkleizer come from bal_to_account_updates,
            // not from db — no need to call send_state_transitions_tx here.

            // Validate BAL entries at the withdrawal index against actual
            // post-withdrawal/request state. `saturating_add(1)` prevents a
            // release-build wrap if `n == u32::MAX` (debug_assert on tx count
            // catches this upstream, but belt-and-braces).
            let withdrawal_idx = u32::try_from(block.body.transactions.len())
                .map(|n| n.saturating_add(1))
                .unwrap_or(u32::MAX);
            Self::validate_bal_withdrawal_index(db, &bal, withdrawal_idx, &validation_index)?;

            // Mark storage_reads that occurred during the withdrawal/request phase.
            if !unread_storage_reads.is_empty() {
                for (addr, acct) in &db.current_accounts_state {
                    for key in acct.storage.keys() {
                        unread_storage_reads.remove(&(*addr, *key));
                    }
                }
            }

            // Mark pure-access accounts touched during the withdrawal/request phase.
            // All withdrawal recipients (including 0-amount) are marked because the
            // BAL recorder calls extend_touched_addresses for them, even though
            // process_withdrawals only calls get_account_mut for amount > 0.
            if !unaccessed_pure_accounts.is_empty() {
                if let Some(withdrawals) = &block.body.withdrawals {
                    for w in withdrawals {
                        unaccessed_pure_accounts.remove(&w.address);
                    }
                }
                for addr in db.current_accounts_state.keys() {
                    // EIP-7928: SYSTEM_ADDRESS in db state comes from pre-exec system
                    // calls and doesn't legitimize a bare BAL entry — the per-tx shadow
                    // recorder has already marked off user-tx touches.
                    if *addr == SYSTEM_ADDRESS {
                        continue;
                    }
                    unaccessed_pure_accounts.remove(addr);
                }
            }

            // Any remaining unread storage_reads are extraneous BAL entries.
            if let Some((addr, key)) = unread_storage_reads.iter().next() {
                let slot = ethrex_common::BigEndianHash::into_uint(key);
                return Err(EvmError::Custom(format!(
                    "BAL validation failed: storage_read for account {addr:?} slot \
                     {slot} was never actually read during block execution"
                )));
            }

            // Any remaining pure-access accounts were never accessed during execution.
            if let Some(addr) = unaccessed_pure_accounts.iter().next() {
                return Err(EvmError::Custom(format!(
                    "BAL validation failed: account {addr:?} has no mutations \
                     and no storage reads but was never accessed during block execution"
                )));
            }

            // EIP-7928 size cap: validated after execution so that transaction-level
            // errors (e.g. gas allowance exceeded) take priority.
            validate_block_access_list_size(&block.header, &chain_config, &bal)
                .map_err(|e| EvmError::Custom(e.to_string()))?;

            // EIP-8079: burn basis is post-refund Σ gas_spent.
            // Each receipt's cumulative_gas_used += report.gas_spent (post-refund);
            // the last receipt holds the block total. Compute before `receipts` is moved.
            let post_refund_gas = receipts.last().map(|r| r.cumulative_gas_used).unwrap_or(0);
            let burned_fees_par =
                is_lstar.then(|| lstar_burned_fees(&chain_config, &block.header, post_refund_gas));

            return Ok((
                BlockExecutionResult {
                    receipts,
                    requests,
                    block_gas_used,
                    burned_fees: burned_fees_par,
                    tx_gas_breakdowns,
                },
                None,
            ));
        }

        // Sequential path (existing code, for block production and non-Amsterdam).
        // The non-BAL caller always provides a Sender; the BAL path returned above.
        // Surface a missing Sender as a normal error instead of panicking, so a
        // future refactor that reshapes the BAL branch can't silently break the
        // contract and bring down the executor thread.
        let Some(merkleizer) = merkleizer else {
            return Err(EvmError::Custom(
                "sequential execution path called without a merkleizer Sender".to_string(),
            ));
        };
        if is_amsterdam {
            db.enable_bal_recording();
            // Set index 0 for pre-execution phase (system contracts)
            db.set_bal_index(0);
        }

        Self::prepare_block(block, db, vm_type, crypto)?;

        // Compute base blob fee once for the entire block (block-invariant).
        let base_blob_fee_per_gas =
            get_base_fee_per_blob_gas(block.header.excess_blob_gas, &evm_config)?;

        let mut shared_stack_pool = Vec::with_capacity(STACK_LIMIT);
        // Holds at most one root memory buffer at a time (each tx pops one and reclaims one).
        let mut shared_memory_pool = Vec::with_capacity(1);

        let n_txs = block.body.transactions.len();
        let mut receipts = Vec::with_capacity(n_txs);
        let mut tx_gas_breakdowns: Vec<TxGasBreakdown> = Vec::with_capacity(n_txs);
        // Cumulative gas for receipts (POST-REFUND per EIP-7778)
        let mut cumulative_gas_used = 0_u64;
        // Block gas accounting (PRE-REFUND for Amsterdam+ per EIP-7778)
        let mut block_gas_used = 0_u64;
        // EIP-8037 (Amsterdam+): track regular and state gas separately for block-level max()
        let mut block_regular_gas_used = 0_u64;
        let mut block_state_gas_used = 0_u64;
        // Starts at 2 to account for the two precompile calls done in `Self::prepare_block`.
        // The value itself can be safely changed.
        let mut tx_since_last_flush = 2;

        for (tx_idx, (tx, tx_sender)) in transactions_with_sender.into_iter().enumerate() {
            // Pre-tx gas limit guard:
            // Pre-Amsterdam: reject tx if cumulative post-refund gas + tx.gas > block limit.
            // Amsterdam+: skip — EIP-8037's 2D gas model means cumulative gas (regular +
            // state) can legally exceed the block gas limit as long as
            // max(sum_regular, sum_state) stays within it. Block-level overflow is
            // detected post-execution.
            if !is_amsterdam {
                check_gas_limit(cumulative_gas_used, tx.gas_limit(), block.header.gas_limit)?;
            }

            // EIP-8037 (Amsterdam+, PR #2703): per-tx 2D inclusion check.
            if is_amsterdam {
                check_2d_gas_allowance(
                    tx,
                    block_regular_gas_used,
                    block_state_gas_used,
                    block.header.gas_limit,
                )?;
            }

            // Set BAL index for this transaction (1-indexed per EIP-7928)
            if is_amsterdam {
                let bal_index = u32::try_from(tx_idx + 1).unwrap_or(u32::MAX);
                db.set_bal_index(bal_index);

                // Record tx sender for BAL. The recipient is recorded when the prepare
                // region loads it (default_hook), per the EIP-7928 v7.1.0 update: an
                // EIP-7702 auth halt before the recipient load must exclude it.
                if let Some(recorder) = db.bal_recorder_mut() {
                    recorder.record_touched_address(tx_sender);
                }
            }

            let report = Self::execute_tx_in_block(
                tx,
                tx_sender,
                &block.header,
                db,
                vm_type,
                base_blob_fee_per_gas,
                &mut shared_stack_pool,
                &mut shared_memory_pool,
                false,
                crypto,
                evm_config,
                chain_id,
                stateless_validator,
            )?;

            tx_gas_breakdowns.push(TxGasBreakdown::from_report(
                tx_idx,
                tx.hash(crypto),
                &report,
            ));

            if queue_length.load(Ordering::Relaxed) == 0 && tx_since_last_flush > 5 {
                LEVM::send_state_transitions_tx(&merkleizer, db, queue_length)?;
                tx_since_last_flush = 0;
            } else {
                tx_since_last_flush += 1;
            }

            // EIP-7778: gas_spent (POST-REFUND) for receipt cumulative_gas_used
            cumulative_gas_used += report.gas_spent;

            // EIP-8037 (Amsterdam+): block_gas_used = max(sum_regular, sum_state)
            // For pre-Amsterdam, state_gas_used is always 0 so gas_used == regular_gas.
            let tx_state_gas = report.state_gas_used;
            let tx_regular_gas = report.gas_used.saturating_sub(tx_state_gas);
            block_regular_gas_used = block_regular_gas_used.saturating_add(tx_regular_gas);
            block_state_gas_used = block_state_gas_used.saturating_add(tx_state_gas);

            if is_amsterdam {
                // Amsterdam+: block gas = max(regular_sum, state_sum)
                block_gas_used = block_regular_gas_used.max(block_state_gas_used);

                // DoS protection: early exit if either regular or state gas exceeds the limit.
                // Since block_gas_used = max(regular, state), if either component exceeds
                // the limit, we know the block is invalid and can safely reject without
                // violating EIP-8037 semantics.
                if block_regular_gas_used > block.header.gas_limit
                    || block_state_gas_used > block.header.gas_limit
                {
                    return Err(EvmError::Transaction(format!(
                        "Gas allowance exceeded: Block gas used overflow: \
                         block_gas_used {block_gas_used} > block_gas_limit {}",
                        block.header.gas_limit
                    )));
                }
            } else {
                block_gas_used = block_gas_used.saturating_add(report.gas_used);
            }

            let mut receipt = Receipt::new(
                tx.tx_type(),
                matches!(report.result, TxResult::Success),
                cumulative_gas_used,
                report.logs,
            );

            // For frame transactions, propagate payer and per-frame receipts
            if matches!(tx, Transaction::FrameTransaction(_)) {
                receipt.payer = report.payer_address;
                receipt.frame_receipts = frame_receipts_from(report.frame_results);
            }

            receipts.push(receipt);
        }

        // EIP-7778 (Amsterdam+): block-level gas overflow check.
        // Per-tx checks are skipped for Amsterdam because block gas is computed
        // from pre-refund values; overflow can only be detected after execution.
        if is_amsterdam && block_gas_used > block.header.gas_limit {
            return Err(EvmError::Transaction(format!(
                "Gas allowance exceeded: Block gas used overflow: \
                 block_gas_used {block_gas_used} > block_gas_limit {}",
                block.header.gas_limit
            )));
        }

        #[cfg(feature = "perf_opcode_timings")]
        {
            let mut timings = OPCODE_TIMINGS.lock().expect("poison");
            timings.inc_tx_count(receipts.len());
            timings.inc_block_count();
            ::tracing::info!("{}", timings.info_pretty());
            let precompiles_timings = PRECOMPILES_TIMINGS.lock().expect("poison");
            ::tracing::info!("{}", precompiles_timings.info_pretty());
        }

        if queue_length.load(Ordering::Relaxed) == 0 {
            LEVM::send_state_transitions_tx(&merkleizer, db, queue_length)?;
        }

        // Set BAL index for post-execution phase (requests + withdrawals)
        // Order must match geth: requests (system calls) BEFORE withdrawals.
        if is_amsterdam {
            let post_tx_index =
                u32::try_from(block.body.transactions.len() + 1).unwrap_or(u32::MAX);
            db.set_bal_index(post_tx_index);

            // Record ALL withdrawal recipients for BAL per EIP-7928
            if let Some(withdrawals) = &block.body.withdrawals
                && let Some(recorder) = db.bal_recorder_mut()
            {
                recorder.extend_touched_addresses(withdrawals.iter().map(|w| w.address));
            }
        }

        // TODO: I don't like deciding the behavior based on the VMType here.
        // TODO2: Revise this, apparently extract_all_requests_levm is not called
        // in L2 execution, but its implementation behaves differently based on this.
        let requests = match vm_type {
            VMType::L1 => extract_all_requests_levm(&receipts, db, &block.header, vm_type, crypto)?,
            VMType::L2(_) => Default::default(),
        };

        if let Some(withdrawals) = &block.body.withdrawals {
            Self::process_withdrawals(db, withdrawals)?;
        }
        LEVM::send_state_transitions_tx(&merkleizer, db, queue_length)?;

        // Extract BAL if recording was enabled
        let bal = db.take_bal();

        Ok((
            BlockExecutionResult {
                receipts,
                requests,
                block_gas_used,
                // cumulative_gas_used is accumulated as += report.gas_spent (post-refund).
                burned_fees: is_lstar
                    .then(|| lstar_burned_fees(&chain_config, &block.header, cumulative_gas_used)),
                tx_gas_breakdowns,
            },
            bal,
        ))
    }

    ///
    /// For each account in the BAL, extracts the **final** post-block state
    /// (highest `block_access_index` entry per field) and builds an AccountUpdate.
    /// State comes entirely from the BAL — no execution needed.
    #[cfg(feature = "rayon")]
    fn bal_to_account_updates(
        bal: &BlockAccessList,
        store: &dyn Database,
    ) -> Result<Vec<AccountUpdate>, EvmError> {
        use ethrex_common::types::AccountInfo;

        let mut updates = Vec::new();

        // Batch prefetch all accounts with writes so per-account lookups are cache hits
        let write_addrs: Vec<Address> = bal
            .accounts()
            .iter()
            .filter(|ac| {
                !ac.balance_changes.is_empty()
                    || !ac.nonce_changes.is_empty()
                    || !ac.code_changes.is_empty()
                    || !ac.storage_changes.is_empty()
            })
            .map(|ac| ac.address)
            .collect();
        // Best-effort: the loop below reads every account it needs through
        // `get_account_state`, so a failed warm costs cache hits and nothing else.
        // Propagating it here would let a prefetch turn into a block-processing error.
        let _ = store.prefetch_accounts(&write_addrs);

        for acct_changes in bal.accounts() {
            let addr = acct_changes.address;

            // Skip accounts with only reads and no writes
            let has_writes = !acct_changes.balance_changes.is_empty()
                || !acct_changes.nonce_changes.is_empty()
                || !acct_changes.code_changes.is_empty()
                || !acct_changes.storage_changes.is_empty();
            if !has_writes {
                continue;
            }

            // Load pre-state for unchanged fields (cache hit after prefetch)
            let prestate = store
                .get_account_state(addr)
                .map_err(|e| EvmError::Custom(format!("bal_to_account_updates: {e}")))?;

            // Final balance: last entry (highest index) or prestate
            let balance = acct_changes
                .balance_changes
                .last()
                .map(|c| c.post_balance)
                .unwrap_or(prestate.balance);

            // Final nonce: last entry or prestate
            let nonce = acct_changes
                .nonce_changes
                .last()
                .map(|c| c.post_nonce)
                .unwrap_or(prestate.nonce);

            // Final code: last entry or prestate
            let (code_hash, code) = if let Some(c) = acct_changes.code_changes.last() {
                code_from_bal(&c.new_code)
            } else {
                (prestate.code_hash, None)
            };

            // Storage: per slot, last entry (highest index)
            let mut added_storage = FxHashMap::with_capacity_and_hasher(
                acct_changes.storage_changes.len(),
                Default::default(),
            );
            for slot_change in &acct_changes.storage_changes {
                if let Some(last) = slot_change.slot_changes.last() {
                    let key = ethrex_common::utils::u256_to_h256(slot_change.slot);
                    added_storage.insert(key, last.post_value);
                }
            }

            // Detect account removal (EIP-161): post-state empty but pre-state existed
            let post_empty = balance.is_zero() && nonce == 0 && code_hash == *EMPTY_KECCAK_HASH;
            let pre_empty = prestate.balance.is_zero()
                && prestate.nonce == 0
                && prestate.code_hash == *EMPTY_KECCAK_HASH;
            let removed = post_empty && !pre_empty;

            let balance_changed = acct_changes
                .balance_changes
                .last()
                .is_some_and(|c| c.post_balance != prestate.balance);
            let nonce_changed = acct_changes
                .nonce_changes
                .last()
                .is_some_and(|c| c.post_nonce != prestate.nonce);
            let code_changed = acct_changes.code_changes.last().is_some();
            let acc_info_updated = balance_changed || nonce_changed || code_changed;

            if !removed && !acc_info_updated && added_storage.is_empty() {
                continue;
            }

            let info = if acc_info_updated {
                Some(AccountInfo {
                    code_hash,
                    balance,
                    nonce,
                })
            } else {
                None
            };

            let update = AccountUpdate {
                address: addr,
                removed,
                info,
                code,
                added_storage,
                // EIP-6780 restricts SELFDESTRUCT to the creation tx, so
                // cross-tx storage wipes can't happen. For the rare same-tx
                // destroy+recreate case at a reused address, EIP-7928 records
                // individual slot zeroing in storage_changes (each old slot → 0),
                // so `added_storage` already contains those zeroed entries and
                // the trie update is correct without setting removed_storage.
                removed_storage: false,
            };
            updates.push(update);
        }

        Ok(updates)
    }

    /// Eager BAL prefix seed — used only by the outer DB path (parallel-execution
    /// fallback recovery and post-tx outer seed before request extraction).
    /// Per-tx parallel execution uses `LazyBalCursor` in `execute_block_parallel`;
    /// see also `seed_one_address_info_from_bal` and `seed_one_storage_slot_from_bal`
    /// in `ethrex_levm::db::gen_db`.
    ///
    /// Pre-seed a GeneralizedDatabase with BAL-derived state for a specific tx.
    ///
    /// For each BAL-modified account, applies accumulated diffs with
    /// `block_access_index <= max_idx` on top of the loaded pre-block state.
    /// This matches geth's approach: each parallel tx sees the state as if
    /// all previous txs had already executed (via BAL intermediate values).
    ///
    /// `max_idx` is the BAL block_access_index of the last tx whose effects
    /// should be visible. BAL indexing: 0 = system calls, 1 = tx 0, 2 = tx 1, ...
    /// For tx at index `i`, pass `max_idx = i` (diffs with index <= i = system + txs 0..i-1).
    #[cfg(feature = "rayon")]
    fn seed_db_from_bal(
        db: &mut GeneralizedDatabase,
        bal: &BlockAccessList,
        max_idx: u32,
        accounts_by_min_index: &[(u32, usize)],
    ) -> Result<(), EvmError> {
        let end = accounts_by_min_index.partition_point(|(min_idx, _)| *min_idx <= max_idx);
        let bal_accounts = bal.accounts();
        for &(_, acct_idx) in &accounts_by_min_index[..end] {
            seed_one_address_info_from_bal(db, bal, acct_idx, max_idx)
                .map_err(|e| EvmError::Custom(format!("seed_db_from_bal: {e}")))?;

            let acct_changes = &bal_accounts[acct_idx];
            if acct_changes.storage_changes.is_empty() {
                continue;
            }
            let any_storage = acct_changes.storage_changes.iter().any(|sc| {
                sc.slot_changes
                    .first()
                    .is_some_and(|c| c.block_access_index <= max_idx)
            });
            if !any_storage {
                continue;
            }
            let addr = acct_changes.address;
            if !db.current_accounts_state.contains_key(&addr) {
                db.get_account(addr)
                    .map_err(|e| EvmError::Custom(format!("seed storage: {e}")))?;
            }
            let acc = db
                .get_account_mut(addr)
                .map_err(|e| EvmError::Custom(format!("seed storage mut: {e}")))?;
            for sc in &acct_changes.storage_changes {
                if let Some(value) = post_value_at_or_before(sc, max_idx) {
                    acc.storage
                        .insert(ethrex_common::utils::u256_to_h256(sc.slot), value);
                }
            }
        }
        Ok(())
    }

    /// Execute block transactions in parallel using BAL-derived state.
    /// Only called for Amsterdam+ blocks when the header BAL is available.
    ///
    /// Each tx runs independently on its own database pre-seeded with BAL
    /// intermediate state (geth-style). State for the merkleizer comes from
    /// `bal_to_account_updates`, not from tx execution.
    #[cfg(feature = "rayon")]
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn execute_block_parallel(
        block: &Block,
        txs_with_sender: &[(&Transaction, Address)],
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        bal: Arc<BlockAccessList>,
        merkleizer: Option<&Sender<Vec<AccountUpdate>>>,
        queue_length: &AtomicUsize,
        system_seed: Arc<CacheDB>,
        crypto: &dyn Crypto,
        validation_index: Arc<BalAddressIndex>,
        stateless_validator: Option<&dyn StatelessValidator>,
    ) -> Result<
        (
            Vec<Receipt>,
            u64,
            FxHashSet<(Address, H256)>,
            FxHashSet<Address>,
            Vec<TxGasBreakdown>,
        ),
        EvmError,
    > {
        let store = db.store.clone();
        let header = &block.header;
        let n_txs = txs_with_sender.len();
        // BAL-seeded parallel execution is only reachable on Amsterdam+ (callers
        // gate on is_amsterdam before providing a header BAL). We recompute the
        // flag here to gate the 2D inclusion check explicitly, keeping the
        // invariant checkable rather than implicit.
        let chain_config = store.get_chain_config()?;
        let is_amsterdam = chain_config.is_amsterdam_activated(header.timestamp);
        // Block-invariant EVM config + chain id, computed once and shared across the
        // parallel workers (both are `Copy` + `Send`/`Sync`).
        let evm_config = EVMConfig::new_from_chain_config(&chain_config, header);
        let chain_id = chain_config.chain_id;
        // Block-invariant base blob fee, computed once and shared across workers.
        let base_blob_fee_per_gas = get_base_fee_per_blob_gas(header.excess_blob_gas, &evm_config)?;
        debug_assert!(
            is_amsterdam,
            "execute_block_parallel invoked on non-Amsterdam block"
        );

        // 1. Convert BAL → AccountUpdates and send to merkleizer (single batch).
        // Skipped when the caller merkleizes optimistically from the input BAL; the
        // conversion is then redundant work (and does pre-state reads we don't need).
        if let Some(merkleizer) = merkleizer {
            let account_updates = Self::bal_to_account_updates(&bal, store.as_ref())?;
            merkleizer
                .send(account_updates)
                .map_err(|e| EvmError::Custom(format!("merkleizer send failed: {e}")))?;
            queue_length.fetch_add(1, Ordering::Relaxed);
        }

        // Build a checklist of all BAL storage_reads. Entries are removed as they
        // are actually read during execution phases. Anything left over is extraneous.
        let mut unread_storage_reads: FxHashSet<(Address, H256)> = FxHashSet::default();
        // Build a checklist of BAL "pure-access" accounts: entries with no mutations
        // and no storage reads. These must be accessed via load_account during execution.
        let mut unaccessed_pure_accounts: FxHashSet<Address> = FxHashSet::default();
        for acct in bal.accounts() {
            for &slot in &acct.storage_reads {
                let key = ethrex_common::utils::u256_to_h256(slot);
                unread_storage_reads.insert((acct.address, key));
            }
            let is_pure = acct.storage_changes.is_empty()
                && acct.storage_reads.is_empty()
                && acct.balance_changes.is_empty()
                && acct.nonce_changes.is_empty()
                && acct.code_changes.is_empty();
            if is_pure {
                unaccessed_pure_accounts.insert(acct.address);
            }
        }

        // Mark pure-access accounts that were touched during system calls.
        // EIP-7928: SYSTEM_ADDRESS is excluded from BAL entries created by system calls
        // (only user-tx touches legitimize it). Keep it in `unaccessed_pure_accounts` so a
        // BAL that carries a bare SYSTEM_ADDRESS entry without a corresponding user-tx
        // touch is rejected as extraneous.
        for addr in system_seed.keys() {
            if *addr == SYSTEM_ADDRESS {
                continue;
            }
            unaccessed_pure_accounts.remove(addr);
        }

        // Mark storage reads that occurred during system calls (prepare_block).
        unread_storage_reads.retain(|(addr, key)| {
            !system_seed
                .get(addr)
                .is_some_and(|a| a.storage.contains_key(key))
        });

        // Already-owned Arcs from the caller; per-thread/per-tx uses below are pointer clones.
        let arc_bal = bal;
        let arc_idx = validation_index;

        // 2. Execute all txs in parallel (embarrassingly parallel, BAL-seeded).
        //    BAL validation runs INSIDE the par_iter closure (parallel) but its
        //    errors are deferred via Option<EvmError> so the post-par_iter
        //    gas-limit check still takes priority (GAS_USED_OVERFLOW must beat
        //    BAL mismatch on blocks exceeding the gas limit; the BAL is built
        //    assuming rejected txs, so miner balance in the BAL won't match
        //    execution that ran all txs).
        //
        //    The closure also precomputes the small (Vec<(Address, H256)>,
        //    Vec<Address>) inputs needed to update the shared
        //    `unread_storage_reads` / `unaccessed_pure_accounts` sets, so the
        //    serial pass after par_iter is just hash-set ops; current_state
        //    and codes never cross the rayon boundary.
        type TxExecResult = (
            usize,
            TxType,
            ExecutionReport,
            FxHashSet<Address>,   // accessed_accounts tracker (coarse)
            Vec<(Address, H256)>, // reads_satisfied: (addr, slot) loaded during this tx
            Vec<Address>,         // destroyed: accounts selfdestructed during this tx
            Option<EvmError>,     // deferred BAL validation error
        );

        let exec_results: Result<Vec<TxExecResult>, EvmError> = (0..n_txs)
            .into_par_iter()
            .map(|tx_idx| -> Result<_, EvmError> {
                let (tx, sender) = &txs_with_sender[tx_idx];
                // Small capacity hint — per-tx DBs materialize only touched accounts via lazy_bal cursor.
                let mut tx_db = GeneralizedDatabase::new_with_shared_base_and_capacity(
                    store.clone(),
                    system_seed.clone(),
                    32,
                );
                tx_db.lazy_bal = Some(LazyBalCursor {
                    bal: arc_bal.clone(),
                    bal_index: u32::try_from(tx_idx + 1).unwrap_or(u32::MAX),
                    index: arc_idx.clone(),
                });
                // Small capacity: parallel txs rarely nest >8 call frames, and
                // over-allocating per-tx wastes memory across many rayon tasks.
                let mut stack_pool = Vec::with_capacity(8);
                // Holds at most one root memory buffer (popped + reclaimed per tx).
                let mut memory_pool = Vec::with_capacity(1);

                // Enable accessed_accounts tracker (coarse) for `unaccessed_pure_accounts`
                // diagnostics. Safe to over-report: used only to REMOVE entries from a
                // extraneous-entry checklist.
                tx_db.accessed_accounts =
                    Some(FxHashSet::with_capacity_and_hasher(16, Default::default()));

                // Enable a shadow BAL recorder on this per-tx db. The recorder is gated
                // at the same gas-check points as the builder path, giving us an exact
                // EIP-7928 access signal (missing-account and missing-storage-read
                // detection). Per-tx recorder — no cross-task contention.
                tx_db.enable_bal_recording();
                let bal_index = u32::try_from(tx_idx + 1).unwrap_or(u32::MAX);
                tx_db.set_bal_index(bal_index);
                // Record tx sender for BAL. The recipient is recorded when the prepare
                // region loads it (default_hook), per the EIP-7928 v7.1.0 update: an
                // EIP-7702 auth halt before the recipient load must exclude it.
                if let Some(recorder) = tx_db.bal_recorder_mut() {
                    recorder.record_touched_address(*sender);
                }

                let report = LEVM::execute_tx_in_block(
                    tx,
                    *sender,
                    header,
                    &mut tx_db,
                    vm_type,
                    base_blob_fee_per_gas,
                    &mut stack_pool,
                    &mut memory_pool,
                    false,
                    crypto,
                    evm_config,
                    chain_id,
                    stateless_validator,
                )?;

                let current_state = std::mem::take(&mut tx_db.current_accounts_state);
                let codes = std::mem::take(&mut tx_db.codes);
                let mut tracked = tx_db.accessed_accounts.take().unwrap_or_default();
                // `tx_initial` maps each genuinely-written slot to its start-of-tx
                // value (see `take_tx_initial_storage`). It serves the storage checks two
                // ways: its keys are the written slots, and its values are the seeded
                // pre-state the validator would otherwise re-read from the store. The
                // recorder already stores it as an `FxHashMap`, so it is moved out here
                // (no per-tx rebuild).
                let (shadow_touched, shadow_reads, tx_initial) = tx_db
                    .bal_recorder
                    .take()
                    .map(|mut r| {
                        (
                            r.take_touched_addresses(),
                            r.take_storage_reads(),
                            r.take_tx_initial_storage(),
                        )
                    })
                    .unwrap_or_default();
                // Genuine pure reads = observed reads minus written slots. A slot read
                // then written stays in `shadow_reads` (the recorder promotes it only in
                // `build()`, which the shadow path skips) and SSTORE always records an
                // implicit read — so this subtraction is required for correctness, not
                // just efficiency: without it a written slot would be treated as a pure
                // read and its BAL entry skipped. The execution->BAL check skips the
                // DB-backed seeded lookup for genuine reads: a read never diverges from
                // its pre-tx value, so there is nothing to validate.
                let pure_reads: FxHashSet<(Address, U256)> = shadow_reads
                    .iter()
                    .copied()
                    .filter(|k| !tx_initial.contains_key(k))
                    .collect();

                // Precompute the per-tx inputs the serial pass uses to update
                // the shared unread_storage_reads set. Selfdestruct clears
                // storage from the final state, so a destroyed account's
                // slots are no longer visible in `current_state`. That does
                // NOT mean every BAL storage_reads entry for the account is
                // legitimate: a phantom (never-read) declared read must
                // still be rejected. Only slots the shadow recorder actually
                // observed (`shadow_reads`, the EIP-7928 access authority)
                // are folded into `reads_satisfied` below, once `destroyed`
                // is populated.
                // Rough avg storage slots per touched account; over-allocation
                // is cheap compared to 2-3 reallocations on the hot path.
                let mut reads_satisfied: Vec<(Address, H256)> =
                    Vec::with_capacity(current_state.len() * 4);
                // `destroyed` stays empty on the typical block (selfdestruct
                // is rare post-EIP-6780), so `Vec::new()` (no allocation) is
                // optimal here.
                let mut destroyed: Vec<Address> = Vec::new();
                for (addr, acct) in &current_state {
                    if matches!(
                        acct.status,
                        AccountStatus::Destroyed | AccountStatus::DestroyedModified
                    ) {
                        destroyed.push(*addr);
                    } else {
                        for key in acct.storage.keys() {
                            reads_satisfied.push((*addr, *key));
                        }
                    }
                }
                // A destroyed account's genuinely-read slots (per the shadow
                // recorder) still satisfy their BAL storage_reads entry even
                // though the storage itself is gone from `current_state`. A
                // slot the BAL merely *declares* as read but this tx never
                // actually touched is deliberately left unsatisfied here: it
                // stays in `unread_storage_reads` and is rejected by the
                // leftover-reads check as a phantom read.
                for (addr, slot) in &shadow_reads {
                    if destroyed.contains(addr) {
                        reads_satisfied.push((*addr, ethrex_common::utils::u256_to_h256(*slot)));
                    }
                }

                // Run BAL validation inline. Errors are DEFERRED: stored in
                // Option<EvmError> so the serial gas-limit check below still
                // takes priority. Borrow current_state / codes during the
                // validation closure, then drop them before returning so
                // they don't cross the rayon boundary.
                let deferred_bal_err: Option<EvmError> = (|| -> Result<(), EvmError> {
                    let bal_idx = u32::try_from(tx_idx + 1).unwrap_or(u32::MAX);
                    let seed_idx = u32::try_from(tx_idx).unwrap_or(u32::MAX);
                    Self::validate_tx_execution(
                        bal_idx,
                        seed_idx,
                        &current_state,
                        &codes,
                        &arc_bal,
                        &arc_idx,
                        &system_seed,
                        &store,
                        &pure_reads,
                        &tx_initial,
                    )
                    .map_err(|e| match e {
                        // A store failure during validation is infrastructure, not a
                        // consensus mismatch — surface it as EvmError::DB so it isn't
                        // mislabelled "BAL validation failed".
                        BalValidationError::Database(msg) => {
                            EvmError::DB(format!("BAL validation for tx {tx_idx}: {msg}"))
                        }
                        BalValidationError::Mismatch(msg) => EvmError::Custom(format!(
                            "BAL validation failed for tx {tx_idx}: {msg}"
                        )),
                    })?;

                    // EIP-7928 (Group B): missing-access detection via shadow recorder.
                    for addr in &shadow_touched {
                        if !arc_idx.addr_to_idx.contains_key(addr) {
                            return Err(EvmError::Custom(format!(
                                "BAL validation failed for tx {tx_idx}: account {addr:?} was \
                                 accessed during execution but is missing from BAL"
                            )));
                        }
                    }
                    for (addr, slot) in &shadow_reads {
                        let Some(&bal_acct_idx) = arc_idx.addr_to_idx.get(addr) else {
                            // Already caught by the touched-address check above.
                            continue;
                        };
                        let acct = &arc_bal.accounts()[bal_acct_idx];
                        let in_changes = acct
                            .storage_changes
                            .binary_search_by(|sc| sc.slot.cmp(slot))
                            .is_ok();
                        // storage_reads is validated strictly-ascending, so binary search
                        // (matches storage_changes above) instead of a linear scan. The
                        // import path doesn't call `validate_ordering`, so assert the
                        // precondition in debug builds; `binary_search` fails closed on
                        // an unsorted list (it can only miss a present slot -> over-reject,
                        // never accept a missing one), so release stays sound regardless.
                        debug_assert!(
                            acct.storage_reads.windows(2).all(|w| w[0] < w[1]),
                            "storage_reads must be strictly ascending for binary_search"
                        );
                        let in_reads = acct.storage_reads.binary_search(slot).is_ok();
                        if !in_changes && !in_reads {
                            return Err(EvmError::Custom(format!(
                                "BAL validation failed for tx {tx_idx}: storage slot {slot} of \
                                 account {addr:?} was read during execution but is missing from \
                                 BAL (no storage_changes or storage_reads entry)"
                            )));
                        }
                    }
                    Ok(())
                })()
                .err();

                drop(current_state);
                drop(codes);

                // The shadow BAL recorder's touched addresses are ethrex's exact
                // EELS `account_reads` analog: an address is recorded here iff EELS
                // would add it to `account_reads` (e.g. a CREATE target read by
                // `is_account_alive` before an OOG state-gas charge). The coarse
                // `accessed_accounts` tracker only sees `load_account` calls, which
                // can miss such a target when the frame OOGs before materializing it.
                // Fold the recorder touches into `tracked` so the pure-access
                // checklist is reduced by everything ethrex legitimately accessed.
                tracked.extend(shadow_touched.iter().copied());

                Ok((
                    tx_idx,
                    tx.tx_type(),
                    report,
                    tracked,
                    reads_satisfied,
                    destroyed,
                    deferred_bal_err,
                ))
            })
            .collect();

        let mut exec_results = exec_results?;

        // `IndexedParallelIterator` (via `(0..n_txs).into_par_iter()`) preserves
        // source-index order through `.map().collect()`, so `exec_results` is
        // already sorted. The sort is kept as a defensive guard against a future
        // refactor swapping in an unordered iterator; `sort_unstable_by_key` on
        // an already-sorted slice is near-linear via pdqsort, so the cost is
        // negligible.
        exec_results.sort_unstable_by_key(|(idx, _, _, _, _, _, _)| *idx);

        // 3. Gas limit check — must happen BEFORE BAL validation errors so that
        //    blocks exceeding the gas limit produce GAS_USED_OVERFLOW instead of
        //    a BAL mismatch error. EIP-8037 PR #2703: also enforce the per-tx
        //    2D inclusion check against running block totals.
        let mut block_regular_gas_used = 0_u64;
        let mut block_state_gas_used = 0_u64;
        let mut tx_gas_breakdowns: Vec<TxGasBreakdown> = Vec::with_capacity(exec_results.len());
        for (tx_idx, _, report, _, _, _, _) in &exec_results {
            let (tx, _tx_sender) = txs_with_sender
                .get(*tx_idx)
                .ok_or_else(|| EvmError::Custom(format!("tx index {tx_idx} out of bounds")))?;
            if is_amsterdam {
                check_2d_gas_allowance(
                    tx,
                    block_regular_gas_used,
                    block_state_gas_used,
                    header.gas_limit,
                )?;
            }

            tx_gas_breakdowns.push(TxGasBreakdown::from_report(
                *tx_idx,
                tx.hash(crypto),
                report,
            ));

            let tx_state_gas = report.state_gas_used;
            let tx_regular_gas = report.gas_used.saturating_sub(tx_state_gas);
            block_regular_gas_used = block_regular_gas_used.saturating_add(tx_regular_gas);
            block_state_gas_used = block_state_gas_used.saturating_add(tx_state_gas);
        }
        let block_gas_used = block_regular_gas_used.max(block_state_gas_used);
        // EIP-7778: block-level overflow check using pre-refund gas.
        if block_gas_used > header.gas_limit {
            return Err(EvmError::Transaction(format!(
                "Gas allowance exceeded: Block gas used overflow: \
                 block_gas_used {block_gas_used} > block_gas_limit {}",
                header.gas_limit
            )));
        }

        // 4. Surface the first deferred BAL validation error (in tx order) now
        //    that the gas-limit check has passed.
        for (_, _, _, _, _, _, deferred) in &mut exec_results {
            if let Some(err) = deferred.take() {
                return Err(err);
            }
        }

        // 5. Apply per-tx reads_satisfied / tracked to the shared sets (cheap
        //    hash-set ops; preserves prior semantics). Note: this does NOT
        //    blanket-clear a destroyed account's entries — only slots it
        //    genuinely read (already folded into reads_satisfied above,
        //    including destroyed-account reads via shadow_reads) are
        //    removed. A phantom storage_reads entry declared on a destroyed
        //    account (never actually read) stays in unread_storage_reads and
        //    is rejected by the leftover-reads check below.
        for (_, _, _, tracked_accounts, reads_satisfied, _, _) in &exec_results {
            if !unread_storage_reads.is_empty() {
                for pair in reads_satisfied {
                    unread_storage_reads.remove(pair);
                }
            }
            // The coinbase is always accessed during fee finalization (geth's
            // readerTracker records it), even when the miner fee is zero and
            // ethrex skips the load_account call.
            if !unaccessed_pure_accounts.is_empty() {
                unaccessed_pure_accounts.remove(&header.coinbase);
                for addr in tracked_accounts {
                    unaccessed_pure_accounts.remove(addr);
                }
            }
        }

        // 6. Build receipts in tx order.
        let mut receipts = Vec::with_capacity(n_txs);
        let mut cumulative_gas_used = 0_u64;
        for (_, tx_type, report, _, _, _, _) in exec_results {
            cumulative_gas_used += report.gas_spent;
            let mut receipt = Receipt::new(
                tx_type,
                matches!(report.result, TxResult::Success),
                cumulative_gas_used,
                report.logs,
            );
            if tx_type == TxType::Frame {
                receipt.payer = report.payer_address;
                receipt.frame_receipts = frame_receipts_from(report.frame_results);
            }
            receipts.push(receipt);
        }

        Ok((
            receipts,
            block_gas_used,
            unread_storage_reads,
            unaccessed_pure_accounts,
            tx_gas_breakdowns,
        ))
    }

    /// Gets the seeded balance for an account at `seed_idx` from BAL, falling
    /// back to system_seed/store if no BAL entry exists before that index.
    #[cfg(feature = "rayon")]
    fn seeded_balance(
        seed_idx: u32,
        acct: &ethrex_common::types::block_access_list::AccountChanges,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
    ) -> Result<U256, BalValidationError> {
        let pos = acct
            .balance_changes
            .partition_point(|c| c.block_access_index <= seed_idx);
        if pos > 0 {
            Ok(acct.balance_changes[pos - 1].post_balance)
        } else if let Some(a) = system_seed.get(&acct.address) {
            Ok(a.info.balance)
        } else {
            store
                .get_account_state(acct.address)
                .map(|a| a.balance)
                .map_err(|e| {
                    BalValidationError::Database(format!(
                        "DB error reading balance for {:?}: {e}",
                        acct.address
                    ))
                })
        }
    }

    /// Gets the seeded code hash for an account at `seed_idx` from BAL, falling
    /// back to system_seed/store if no BAL entry exists before that index.
    #[cfg(feature = "rayon")]
    fn seeded_code_hash(
        seed_idx: u32,
        acct: &ethrex_common::types::block_access_list::AccountChanges,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
    ) -> Result<H256, BalValidationError> {
        let pos = acct
            .code_changes
            .partition_point(|c| c.block_access_index <= seed_idx);
        if pos > 0 {
            let seeded_code = &acct.code_changes[pos - 1].new_code;
            Ok(if seeded_code.is_empty() {
                *EMPTY_KECCAK_HASH
            } else {
                ethrex_common::utils::keccak(seeded_code)
            })
        } else if let Some(a) = system_seed.get(&acct.address) {
            Ok(a.info.code_hash)
        } else {
            store
                .get_account_state(acct.address)
                .map(|a| a.code_hash)
                .map_err(|e| {
                    BalValidationError::Database(format!(
                        "DB error reading account state for {:?}: {e}",
                        acct.address
                    ))
                })
        }
    }

    /// Gets the seeded nonce for an account at `seed_idx` from BAL, falling
    /// back to system_seed/store if no BAL entry exists before that index.
    #[cfg(feature = "rayon")]
    fn seeded_nonce(
        seed_idx: u32,
        acct: &ethrex_common::types::block_access_list::AccountChanges,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
    ) -> Result<u64, BalValidationError> {
        let pos = acct
            .nonce_changes
            .partition_point(|c| c.block_access_index <= seed_idx);
        if pos > 0 {
            Ok(acct.nonce_changes[pos - 1].post_nonce)
        } else if let Some(a) = system_seed.get(&acct.address) {
            Ok(a.info.nonce)
        } else {
            store
                .get_account_state(acct.address)
                .map(|a| a.nonce)
                .map_err(|e| {
                    BalValidationError::Database(format!(
                        "DB error reading nonce for {:?}: {e}",
                        acct.address
                    ))
                })
        }
    }

    /// Start-of-tx `(balance, nonce, code_hash)` for `acct`: each field resolves
    /// from its own BAL change history at or before `seed_idx`, then the
    /// pre-system-call snapshot, then a single shared store read for whatever
    /// remains. Semantically identical to calling `seeded_balance` +
    /// `seeded_nonce` + `seeded_code_hash`, but reads the store at most once — the
    /// PART A no-op checks need all three for the same account, and an account
    /// with no BAL history before this tx would otherwise read it three times.
    #[cfg(feature = "rayon")]
    fn seeded_account_triple(
        seed_idx: u32,
        acct: &ethrex_common::types::block_access_list::AccountChanges,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
    ) -> Result<(U256, u64, H256), BalValidationError> {
        let bpos = acct
            .balance_changes
            .partition_point(|c| c.block_access_index <= seed_idx);
        let npos = acct
            .nonce_changes
            .partition_point(|c| c.block_access_index <= seed_idx);
        let cpos = acct
            .code_changes
            .partition_point(|c| c.block_access_index <= seed_idx);

        let mut balance = (bpos > 0).then(|| acct.balance_changes[bpos - 1].post_balance);
        let mut nonce = (npos > 0).then(|| acct.nonce_changes[npos - 1].post_nonce);
        let mut code_hash = (cpos > 0).then(|| {
            let c = &acct.code_changes[cpos - 1].new_code;
            if c.is_empty() {
                *EMPTY_KECCAK_HASH
            } else {
                ethrex_common::utils::keccak(c)
            }
        });

        // Fields with no BAL history fall back to the pre-system-call snapshot.
        if let Some(a) = system_seed.get(&acct.address) {
            balance.get_or_insert(a.info.balance);
            nonce.get_or_insert(a.info.nonce);
            code_hash.get_or_insert(a.info.code_hash);
        }

        // Anything still unresolved comes from the store (read once).
        if balance.is_none() || nonce.is_none() || code_hash.is_none() {
            let s = store.get_account_state(acct.address).map_err(|e| {
                BalValidationError::Database(format!(
                    "DB error reading account state for {:?}: {e}",
                    acct.address
                ))
            })?;
            balance.get_or_insert(s.balance);
            nonce.get_or_insert(s.nonce);
            code_hash.get_or_insert(s.code_hash);
        }

        Ok((
            balance.unwrap_or_default(),
            nonce.unwrap_or_default(),
            code_hash.unwrap_or(*EMPTY_KECCAK_HASH),
        ))
    }

    /// Start-of-tx value for a slot with no BAL `slot_changes` history to consult:
    /// the recorder's `tx_initial` fast-path (a slot the EVM genuinely wrote this
    /// tx), else the pre-tx state (system_seed, then store). Used by the
    /// execution->BAL check for a slot absent from `storage_changes`.
    #[cfg(feature = "rayon")]
    fn seeded_storage_pre_value(
        addr: Address,
        key: H256,
        slot: U256,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
        tx_initial: &FxHashMap<(Address, U256), U256>,
    ) -> Result<U256, BalValidationError> {
        if let Some(v) = tx_initial.get(&(addr, slot)) {
            return Ok(*v);
        }
        Self::storage_from_seed_or_store(addr, key, slot, system_seed, store)
    }

    /// Pre-tx value for a slot from the in-memory snapshot, falling back to the
    /// store. Shared tail of the two `seeded_storage*` helpers.
    #[cfg(feature = "rayon")]
    fn storage_from_seed_or_store(
        addr: Address,
        key: H256,
        slot: U256,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
    ) -> Result<U256, BalValidationError> {
        if let Some(v) = system_seed
            .get(&addr)
            .and_then(|a| a.storage.get(&key))
            .copied()
        {
            Ok(v)
        } else {
            store.get_storage_value(addr, key).map_err(|e| {
                BalValidationError::Database(format!(
                    "DB error reading storage for {addr:?} slot {slot}: {e}"
                ))
            })
        }
    }

    /// Gets the seeded value for a storage slot at `seed_idx` from BAL, falling
    /// back to system_seed/store if no BAL entry exists before that index.
    ///
    /// Fast path: for a slot the EVM genuinely wrote this tx, `tx_initial` already
    /// holds the start-of-tx value it captured during execution — identical to what
    /// this function would otherwise recompute — so return it and skip the lookup.
    #[cfg(feature = "rayon")]
    fn seeded_storage(
        seed_idx: u32,
        sc: &ethrex_common::types::block_access_list::SlotChange,
        addr: Address,
        key: H256,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
        tx_initial: &FxHashMap<(Address, U256), U256>,
    ) -> Result<U256, BalValidationError> {
        if let Some(v) = tx_initial.get(&(addr, sc.slot)) {
            return Ok(*v);
        }
        let pos = sc
            .slot_changes
            .partition_point(|c| c.block_access_index <= seed_idx);
        if pos > 0 {
            Ok(sc.slot_changes[pos - 1].post_value)
        } else {
            Self::storage_from_seed_or_store(addr, key, sc.slot, system_seed, store)
        }
    }

    /// Validates that a tx's post-execution state matches BAL claims.
    ///
    /// Replaces the previous snapshot->diff->validate approach:
    /// - No HashMap clone needed (reconstructs seeded values from BAL)
    /// - Uses pre-built index for O(1) account lookups
    /// - Uses binary search on sorted change lists
    ///
    /// `bal_idx`: block_access_index for this tx (tx_idx + 1)
    /// `seed_idx`: max BAL index used for seeding (= tx_idx = bal_idx - 1)
    /// `current_state`: post-execution account state from per-tx DB
    /// `codes`: code cache from per-tx DB (for code change validation)
    /// `bal`: the block access list
    /// `index`: pre-built validation index
    /// `system_seed`: pre-system-call state snapshot (for extraneous entry detection)
    /// `store`: database (fallback for pre-state lookups)
    /// `pure_reads`: slots the shadow recorder observed as pure reads (never
    ///   written); the execution->BAL check skips the seeded pre-state lookup for these since a
    ///   genuine read cannot diverge from its pre-tx value. Pass an empty set to
    ///   validate every slot unconditionally (e.g. from unit tests).
    /// `tx_initial`: start-of-tx storage values the EVM already captured for
    ///   written slots (`(addr, slot) -> pre_value`); used as the storage seed
    ///   fast-path so `seeded_storage` avoids a store read. Pass an empty map to
    ///   force the store fallback (e.g. from unit tests).
    ///
    /// Exposed as `pub` (rather than crate-private) solely so the direct
    /// `validate_tx_execution` unit tests in the `ethrex-test` crate
    /// (`test/tests/blockchain/bal_validate_tx_execution_tests.rs`) can call it.
    #[cfg(feature = "rayon")]
    #[allow(clippy::too_many_arguments)]
    pub fn validate_tx_execution(
        bal_idx: u32,
        seed_idx: u32,
        current_state: &FxHashMap<Address, LevmAccount>,
        codes: &FxHashMap<H256, Code>,
        bal: &BlockAccessList,
        index: &BalAddressIndex,
        system_seed: &CacheDB,
        store: &Arc<dyn Database>,
        pure_reads: &FxHashSet<(Address, U256)>,
        tx_initial: &FxHashMap<(Address, U256), U256>,
    ) -> Result<(), BalValidationError> {
        // BAL -> execution: for each BAL account with changes at bal_idx,
        // verify execution produced the matching post-state (and that no
        // claimed change is a no-op equal to the start-of-tx value).
        if let Some(active_accounts) = index.tx_to_accounts.get(&bal_idx) {
            for &acct_inner_idx in active_accounts {
                let acct = &bal.accounts()[acct_inner_idx];
                let addr = acct.address;
                let actual = current_state.get(&addr);
                // Start-of-tx (balance, nonce, code_hash), computed once per account
                // and shared by the balance/nonce/code no-op checks below so an
                // account with no BAL history isn't read from the store three times.
                let mut seeded_info: Option<(U256, u64, H256)> = None;

                // Balance
                if let Some(expected) = find_exact_change_balance(&acct.balance_changes, bal_idx) {
                    match actual {
                        Some(a) if a.info.balance == expected => {
                            // No-op check: a BAL balance change is only canonical if
                            // it actually differs from the start-of-tx seeded balance
                            // (the builder MUST NOT record round-tripped balances).
                            if seeded_info.is_none() {
                                seeded_info = Some(Self::seeded_account_triple(
                                    seed_idx,
                                    acct,
                                    system_seed,
                                    store,
                                )?);
                            }
                            let seeded = seeded_info.unwrap_or_default().0;
                            if expected == seeded {
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} has spurious no-op BAL balance change \
                                     at index {bal_idx}: post==pre=={expected}"
                                )));
                            }
                        }
                        Some(a) => {
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} balance mismatch at index {bal_idx}: BAL={expected}, exec={} (diff={})",
                                a.info.balance,
                                describe_balance_diff(expected, a.info.balance),
                            )));
                        }
                        None => {
                            // Account absent from execution state, yet the BAL declares a
                            // balance change for it at this tx. Never canonical: either it
                            // differs from the start-of-tx seeded balance (a real mismatch)
                            // or equals it (a spurious no-op the builder must not record).
                            // Reject both to match the sequential path; the state root does
                            // NOT catch the no-op case (post==pre leaves the root unchanged).
                            let seeded = Self::seeded_balance(seed_idx, acct, system_seed, store)?;
                            if expected == seeded {
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} has spurious no-op BAL balance change \
                                     at index {bal_idx} for an account absent from execution \
                                     state: post==pre=={expected}"
                                )));
                            }
                            // Dump full BAL entry for diagnosis
                            let all_bal_indices: Vec<u32> = acct
                                .balance_changes
                                .iter()
                                .map(|c| c.block_access_index)
                                .collect();
                            let all_nonce_indices: Vec<u32> = acct
                                .nonce_changes
                                .iter()
                                .map(|c| c.block_access_index)
                                .collect();
                            let all_storage_indices: Vec<(u32, u64)> = acct
                                .storage_changes
                                .iter()
                                .flat_map(|sc| {
                                    sc.slot_changes
                                        .iter()
                                        .map(|c| (c.block_access_index, sc.slot.low_u64()))
                                })
                                .collect();
                            let code_indices: Vec<u32> = acct
                                .code_changes
                                .iter()
                                .map(|c| c.block_access_index)
                                .collect();
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} has BAL balance change at {bal_idx} \
                                 but not in execution state (expected={expected}, pre={seeded}, \
                                 all_bal_idx={all_bal_indices:?}, nonce_idx={all_nonce_indices:?}, \
                                 storage_idx={all_storage_indices:?}, code_idx={code_indices:?})"
                            )));
                        }
                    }
                }

                // Nonce
                if let Some(expected) = find_exact_change_nonce(&acct.nonce_changes, bal_idx) {
                    match actual {
                        Some(a) if a.info.nonce == expected => {
                            // No-op check: nonces are only ever recorded via a strict
                            // increment (or a one-time fixed-value predeploy install
                            // that also strictly increases), so a canonical BAL nonce
                            // change can never equal the start-of-tx seeded nonce.
                            if seeded_info.is_none() {
                                seeded_info = Some(Self::seeded_account_triple(
                                    seed_idx,
                                    acct,
                                    system_seed,
                                    store,
                                )?);
                            }
                            let seeded = seeded_info.unwrap_or_default().1;
                            if expected == seeded {
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} has spurious no-op BAL nonce change \
                                     at index {bal_idx}: post==pre=={expected}"
                                )));
                            }
                        }
                        Some(a) => {
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} nonce mismatch at index {bal_idx}: BAL={expected}, exec={}",
                                a.info.nonce
                            )));
                        }
                        None => {
                            // Account absent from execution state, yet the BAL declares a
                            // nonce change: reject the no-op (post==pre) and the mismatch
                            // alike (see the balance arm rationale).
                            let seeded = Self::seeded_nonce(seed_idx, acct, system_seed, store)?;
                            if expected == seeded {
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} has spurious no-op BAL nonce change \
                                     at index {bal_idx} for an account absent from execution \
                                     state: post==pre=={expected}"
                                )));
                            }
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} has BAL nonce change at {bal_idx} \
                                 but not in execution state (expected={expected}, pre={seeded})"
                            )));
                        }
                    }
                }

                // Code
                if let Some(expected_code) = find_exact_change_code(&acct.code_changes, bal_idx) {
                    match actual {
                        Some(a) => {
                            let actual_code = if let Some(c) = codes.get(&a.info.code_hash) {
                                c.code_bytes()
                            } else {
                                let c = store.get_account_code(a.info.code_hash).map_err(|e| {
                                    BalValidationError::Database(format!(
                                        "DB error reading account code for {addr:?}: {e}"
                                    ))
                                })?;
                                c.code_bytes()
                            };
                            if actual_code != *expected_code {
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} code mismatch at index {bal_idx}"
                                )));
                            }
                            // No-op check: a BAL code change is only canonical if
                            // it actually differs from the start-of-tx seeded code.
                            if seeded_info.is_none() {
                                seeded_info = Some(Self::seeded_account_triple(
                                    seed_idx,
                                    acct,
                                    system_seed,
                                    store,
                                )?);
                            }
                            let seeded_hash = seeded_info.unwrap_or_default().2;
                            if a.info.code_hash == seeded_hash {
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} has spurious no-op BAL code change \
                                     at index {bal_idx}"
                                )));
                            }
                        }
                        None => {
                            // No-op check: compare against pre-state code.
                            // Try system_seed + codes cache first, then fall
                            // back to store (consistent with balance/nonce).
                            let code_hash = if let Some(a) = system_seed.get(&addr) {
                                a.info.code_hash
                            } else {
                                store
                                    .get_account_state(addr)
                                    .map(|a| a.code_hash)
                                    .map_err(|e| {
                                        BalValidationError::Database(format!(
                                            "DB error reading account state for {addr:?}: {e}"
                                        ))
                                    })?
                            };
                            let pre_code = if let Some(c) = codes.get(&code_hash) {
                                c.code_bytes()
                            } else {
                                let c = store.get_account_code(code_hash).map_err(|e| {
                                    BalValidationError::Database(format!(
                                        "DB error reading account code for hash \
                                             {code_hash:?}: {e}"
                                    ))
                                })?;
                                c.code_bytes()
                            };
                            if *expected_code == pre_code {
                                // Spurious no-op: BAL code change equals pre-state code
                                // for an account absent from execution state. Reject to
                                // match the sequential path (the state root won't catch it).
                                return Err(BalValidationError::Mismatch(format!(
                                    "account {addr:?} has spurious no-op BAL code change \
                                     at index {bal_idx} for an account absent from execution state"
                                )));
                            }
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} has BAL code change at {bal_idx} \
                                 but not in execution state"
                            )));
                        }
                    }
                }

                // Storage
                for sc in &acct.storage_changes {
                    if let Some(expected_value) =
                        find_exact_change_storage(&sc.slot_changes, bal_idx)
                    {
                        let key = ethrex_common::utils::u256_to_h256(sc.slot);
                        let actual_value = actual.and_then(|a| a.storage.get(&key)).copied();
                        if actual_value != Some(expected_value) {
                            // Slot absent from execution state. Compare against the
                            // start-of-tx seeded value: an entry equal to it is a
                            // spurious no-op (post==pre) that the builder must not
                            // record. Reject it to match the sequential path — the
                            // state root won't catch it since the value is unchanged.
                            if actual.is_none() || actual_value.is_none() {
                                let seeded = Self::seeded_storage(
                                    seed_idx,
                                    sc,
                                    addr,
                                    key,
                                    system_seed,
                                    store,
                                    tx_initial,
                                )?;
                                if expected_value == seeded {
                                    return Err(BalValidationError::Mismatch(format!(
                                        "account {addr:?} has spurious no-op BAL storage \
                                         change for slot {} at index {bal_idx} for a slot \
                                         absent from execution state: post==pre=={expected_value}",
                                        sc.slot
                                    )));
                                }
                            }
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} storage slot {} mismatch at index {bal_idx}: \
                                 BAL={expected_value}, exec={actual_value:?}",
                                sc.slot
                            )));
                        }
                        // Matching arm: slot present in execution state and equal
                        // to expected. Reject spurious no-op entries (post == the
                        // start-of-tx seeded value).
                        let seeded = Self::seeded_storage(
                            seed_idx,
                            sc,
                            addr,
                            key,
                            system_seed,
                            store,
                            tx_initial,
                        )?;
                        if expected_value == seeded {
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} has spurious no-op BAL storage change for \
                                 slot {} at index {bal_idx}",
                                sc.slot
                            )));
                        }
                    }
                }
            }
        }

        // execution -> BAL: for each account modified by execution, verify every
        // mutation it produced is claimed by the BAL (no unrecorded change).
        for (addr, account) in current_state {
            if account.is_unmodified() {
                continue;
            }

            let Some(&bal_acct_idx) = index.addr_to_idx.get(addr) else {
                // Account is Modified but absent from BAL. Could be a warm-access
                // artifact (get_account_mut without value changes) or a genuine
                // missing entry. Compare with pre-execution state to distinguish.
                let pre = system_seed
                    .get(addr)
                    .map(|a| (a.info.balance, a.info.nonce, a.info.code_hash))
                    .or_else(|| {
                        store
                            .get_account_state(*addr)
                            .ok()
                            .map(|a| (a.balance, a.nonce, a.code_hash))
                    })
                    .unwrap_or_default();
                let post = (
                    account.info.balance,
                    account.info.nonce,
                    account.info.code_hash,
                );
                if pre != post {
                    return Err(BalValidationError::Mismatch(format!(
                        "account {addr:?} was modified by execution but is absent from BAL"
                    )));
                }
                continue;
            };

            let acct = &bal.accounts()[bal_acct_idx];

            // Balance: if BAL has no change at bal_idx, execution must not have changed it
            if !has_exact_change_balance(&acct.balance_changes, bal_idx) {
                let seeded = Self::seeded_balance(seed_idx, acct, system_seed, store)?;
                if account.info.balance != seeded {
                    return Err(BalValidationError::Mismatch(format!(
                        "account {addr:?} balance changed by execution ({}) but BAL has no \
                         balance change at index {bal_idx} (seeded={seeded})",
                        account.info.balance
                    )));
                }
            }

            // Nonce: same pattern
            if !has_exact_change_nonce(&acct.nonce_changes, bal_idx) {
                let seeded = Self::seeded_nonce(seed_idx, acct, system_seed, store)?;
                if account.info.nonce != seeded {
                    return Err(BalValidationError::Mismatch(format!(
                        "account {addr:?} nonce changed by execution ({}) but BAL has no \
                         nonce change at index {bal_idx} (seeded={seeded})",
                        account.info.nonce
                    )));
                }
            }

            // Code: same pattern — use keccak256 of the raw bytes directly to
            // avoid reconstructing a full Code object (seed_db_from_bal already
            // did that work; here we only need the hash for comparison).
            if !has_exact_change_code(&acct.code_changes, bal_idx) {
                let seeded_hash = Self::seeded_code_hash(seed_idx, acct, system_seed, store)?;
                if account.info.code_hash != seeded_hash {
                    return Err(BalValidationError::Mismatch(format!(
                        "account {addr:?} code changed by execution but BAL has no \
                         code change at index {bal_idx} (seeded_hash={seeded_hash:?})"
                    )));
                }
            }

            // Storage: for each slot in execution state, check it's expected
            for (key_h256, &value) in &account.storage {
                let slot_u256 = u256_from_big_endian_const(key_h256.0);
                // EIP-7928 requires storage_changes sorted by slot, so use binary search.
                let pos = acct
                    .storage_changes
                    .partition_point(|sc| sc.slot < slot_u256);
                if pos < acct.storage_changes.len() && acct.storage_changes[pos].slot == slot_u256 {
                    let sc = &acct.storage_changes[pos];
                    if !has_exact_change_storage(&sc.slot_changes, bal_idx) {
                        // Compare against the start-of-tx value. `seeded_storage` falls
                        // back to system_seed -> store when the slot has no BAL change
                        // at or before this tx (seeded_pos == 0), so a write at this tx
                        // whose BAL entry was omitted is still caught rather than skipped.
                        let seeded = Self::seeded_storage(
                            seed_idx,
                            sc,
                            *addr,
                            *key_h256,
                            system_seed,
                            store,
                            tx_initial,
                        )?;
                        if value != seeded {
                            return Err(BalValidationError::Mismatch(format!(
                                "account {addr:?} storage slot {slot_u256} changed by \
                                 execution ({value}) but BAL has no change at index \
                                 {bal_idx} (seeded={seeded})"
                            )));
                        }
                    }
                }
                // Slot not in BAL storage_changes (a slot is in at most one of
                // storage_changes/storage_reads per EIP-7928 ordering rules). A value
                // that diverges from the start-of-tx baseline means execution WROTE the
                // slot but the write was not recorded in storage_changes — non-canonical.
                // A genuine read leaves value == pre_value and passes. This catches both
                // an entirely-absent slot AND a real write mis-declared under
                // storage_reads: the shadow-reads check in execute_block_parallel only
                // verifies the slot is present in *some* list, never that a changed value
                // was recorded in the correct one.
                //
                // Fast path: the recorder proved this slot a pure read (writes are
                // excluded from `pure_reads`), so its value equals the pre-tx value by
                // construction — skip the DB-backed seeded lookup entirely.
                else if !pure_reads.contains(&(*addr, slot_u256)) {
                    // This slot has no `storage_changes` entry, so there is no BAL
                    // slot history to seed from; take the start-of-tx value straight
                    // from the recorder fast-path / pre-tx state. A written slot hits
                    // `tx_initial` and skips the store read.
                    let pre_value = Self::seeded_storage_pre_value(
                        *addr,
                        *key_h256,
                        slot_u256,
                        system_seed,
                        store,
                        tx_initial,
                    )?;
                    if value != pre_value {
                        let declared_as_read = acct.storage_reads.contains(&slot_u256);
                        return Err(BalValidationError::Mismatch(format!(
                            "account {addr:?} storage slot {slot_u256} was written by \
                             execution ({value}) but has no storage_changes entry at index \
                             {bal_idx} (pre_value={pre_value}, declared_as_read={declared_as_read})"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates BAL entries at the withdrawal index against actual post-withdrawal state.
    ///
    /// After `process_withdrawals` + `extract_all_requests_levm` run on the BAL-seeded
    /// DB, `current_accounts_state` reflects the actual state. Validation is bidirectional:
    ///
    /// BAL -> DB: every BAL claim at the withdrawal index must match the DB.
    /// DB -> BAL: every account modified during the withdrawal/request phase
    ///         must have a corresponding BAL entry. Without this reverse check, a
    ///         malicious builder could omit a withdrawal recipient from the BAL,
    ///         causing the BAL-derived state root to exclude the withdrawal balance
    ///         change.
    #[cfg(feature = "rayon")]
    fn validate_bal_withdrawal_index(
        db: &GeneralizedDatabase,
        bal: &BlockAccessList,
        withdrawal_idx: u32,
        index: &BalAddressIndex,
    ) -> Result<(), EvmError> {
        // BAL -> DB: For each BAL account with changes at the withdrawal index,
        //         verify the DB matches.
        for acct in bal.accounts() {
            let addr = acct.address;
            let actual = db.current_accounts_state.get(&addr);

            // Balance
            if let Some(expected) = find_exact_change_balance(&acct.balance_changes, withdrawal_idx)
            {
                match actual {
                    Some(a) if a.info.balance == expected => {}
                    Some(a) => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} balance \
                             mismatch at index {withdrawal_idx}: BAL={expected}, actual={}",
                            a.info.balance
                        )));
                    }
                    None => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} has \
                             balance change at index {withdrawal_idx} but was not touched \
                             by withdrawal/request phase"
                        )));
                    }
                }
            }

            // Nonce
            if let Some(expected) = find_exact_change_nonce(&acct.nonce_changes, withdrawal_idx) {
                match actual {
                    Some(a) if a.info.nonce == expected => {}
                    Some(a) => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} nonce \
                             mismatch at index {withdrawal_idx}: BAL={expected}, actual={}",
                            a.info.nonce
                        )));
                    }
                    None => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} has \
                             nonce change at index {withdrawal_idx} but was not touched \
                             by withdrawal/request phase"
                        )));
                    }
                }
            }

            // Code
            if let Some(expected_code) = find_exact_change_code(&acct.code_changes, withdrawal_idx)
            {
                let code_hash = if expected_code.is_empty() {
                    *EMPTY_KECCAK_HASH
                } else {
                    ethrex_common::utils::keccak(expected_code)
                };
                match actual {
                    Some(a) if a.info.code_hash == code_hash => {}
                    Some(_) => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} code \
                             mismatch at index {withdrawal_idx}"
                        )));
                    }
                    None => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} has \
                             code change at index {withdrawal_idx} but was not touched \
                             by withdrawal/request phase"
                        )));
                    }
                }
            }

            // Storage writes
            for sc in &acct.storage_changes {
                if let Some(expected_value) =
                    find_exact_change_storage(&sc.slot_changes, withdrawal_idx)
                {
                    let key = ethrex_common::utils::u256_to_h256(sc.slot);
                    let actual_value = actual.and_then(|a| a.storage.get(&key)).copied();
                    if actual_value != Some(expected_value) {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} storage \
                             slot {} mismatch at index {withdrawal_idx}: BAL={expected_value}, \
                             actual={actual_value:?}",
                            sc.slot
                        )));
                    }
                }
            }
        }

        // DB -> BAL: For each account modified during the withdrawal/request phase,
        //         verify it has a corresponding BAL entry claiming the change.
        for (addr, account) in &db.current_accounts_state {
            if account.is_unmodified() {
                continue;
            }

            let Some(&bal_acct_idx) = index.addr_to_idx.get(addr) else {
                // Account modified during withdrawal/request phase but absent
                // from BAL entirely. Compare with pre-state (store) to
                // distinguish genuine mutations from warm-access artifacts.
                let pre_state = db.store.get_account_state(*addr).map_err(|e| {
                    EvmError::Custom(format!(
                        "BAL validation failed for withdrawal: db error reading \
                         account {addr:?}: {e}"
                    ))
                })?;
                let pre = (pre_state.balance, pre_state.nonce, pre_state.code_hash);
                let post = (
                    account.info.balance,
                    account.info.nonce,
                    account.info.code_hash,
                );
                if pre != post {
                    return Err(EvmError::Custom(format!(
                        "BAL validation failed for withdrawal: account {addr:?} was modified \
                         during withdrawal/request phase but is absent from BAL"
                    )));
                }
                // Also check storage: if any slot differs from pre-state,
                // the account should have been in the BAL.
                for (key_h256, &value) in &account.storage {
                    let pre_value = db.store.get_storage_value(*addr, *key_h256).map_err(|e| {
                        EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: db error reading \
                                 storage {addr:?}[{}]: {e}",
                            u256_from_big_endian_const(key_h256.0)
                        ))
                    })?;
                    if value != pre_value {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} storage \
                             slot {} changed during withdrawal/request phase but is absent \
                             from BAL",
                            u256_from_big_endian_const(key_h256.0)
                        )));
                    }
                }
                continue;
            };

            let acct = &bal.accounts()[bal_acct_idx];

            // Balance: if BAL has no change at withdrawal_idx, the withdrawal
            // phase must not have changed it relative to the last BAL entry.
            if !has_exact_change_balance(&acct.balance_changes, withdrawal_idx) {
                let seeded = match acct.balance_changes.last() {
                    Some(c) => c.post_balance,
                    None => {
                        db.store
                            .get_account_state(*addr)
                            .map_err(|e| {
                                EvmError::Custom(format!(
                                    "BAL validation failed for withdrawal: db error reading \
                                 account {addr:?}: {e}"
                                ))
                            })?
                            .balance
                    }
                };
                if account.info.balance != seeded {
                    return Err(EvmError::Custom(format!(
                        "BAL validation failed for withdrawal: account {addr:?} balance \
                         changed during withdrawal/request phase ({}) but BAL has no \
                         balance change at index {withdrawal_idx} (last_bal={seeded})",
                        account.info.balance
                    )));
                }
            }

            // Nonce
            if !has_exact_change_nonce(&acct.nonce_changes, withdrawal_idx) {
                let seeded = match acct.nonce_changes.last() {
                    Some(c) => c.post_nonce,
                    None => {
                        db.store
                            .get_account_state(*addr)
                            .map_err(|e| {
                                EvmError::Custom(format!(
                                    "BAL validation failed for withdrawal: db error reading \
                                 account {addr:?}: {e}"
                                ))
                            })?
                            .nonce
                    }
                };
                if account.info.nonce != seeded {
                    return Err(EvmError::Custom(format!(
                        "BAL validation failed for withdrawal: account {addr:?} nonce \
                         changed during withdrawal/request phase ({}) but BAL has no \
                         nonce change at index {withdrawal_idx} (last_bal={seeded})",
                        account.info.nonce
                    )));
                }
            }

            // Code
            if !has_exact_change_code(&acct.code_changes, withdrawal_idx) {
                let seeded_hash = match acct.code_changes.last() {
                    Some(c) if c.new_code.is_empty() => *EMPTY_KECCAK_HASH,
                    Some(c) => ethrex_common::utils::keccak(&c.new_code),
                    None => {
                        db.store
                            .get_account_state(*addr)
                            .map_err(|e| {
                                EvmError::Custom(format!(
                                    "BAL validation failed for withdrawal: db error reading \
                                 account {addr:?}: {e}"
                                ))
                            })?
                            .code_hash
                    }
                };
                if account.info.code_hash != seeded_hash {
                    return Err(EvmError::Custom(format!(
                        "BAL validation failed for withdrawal: account {addr:?} code \
                         changed during withdrawal/request phase but BAL has no \
                         code change at index {withdrawal_idx} \
                         (actual={:?}, last_bal={seeded_hash:?})",
                        account.info.code_hash
                    )));
                }
            }

            // Storage: for each slot in the withdrawal/request-phase state,
            // verify the BAL has a corresponding entry or the value is unchanged.
            for (key_h256, &value) in &account.storage {
                let slot_u256 = u256_from_big_endian_const(key_h256.0);
                let pos = acct
                    .storage_changes
                    .partition_point(|sc| sc.slot < slot_u256);
                if pos < acct.storage_changes.len() && acct.storage_changes[pos].slot == slot_u256 {
                    let sc = &acct.storage_changes[pos];
                    if !has_exact_change_storage(&sc.slot_changes, withdrawal_idx) {
                        // No BAL entry at withdrawal_idx; compare against
                        // last BAL entry (the seeded value).
                        let seeded = match sc.slot_changes.last() {
                            Some(c) => c.post_value,
                            None => db.store.get_storage_value(*addr, *key_h256).map_err(|e| {
                                EvmError::Custom(format!(
                                    "BAL validation failed for withdrawal: db error reading \
                                     storage {addr:?}[{slot_u256}]: {e}"
                                ))
                            })?,
                        };
                        if value != seeded {
                            return Err(EvmError::Custom(format!(
                                "BAL validation failed for withdrawal: account {addr:?} \
                                 storage slot {slot_u256} changed during withdrawal/request \
                                 phase ({value}) but BAL has no change at index \
                                 {withdrawal_idx} (last_bal={seeded})"
                            )));
                        }
                    }
                } else {
                    // Slot not in BAL storage_changes at all: verify it
                    // wasn't actually mutated during the withdrawal/request phase.
                    let pre_value = db.store.get_storage_value(*addr, *key_h256).map_err(|e| {
                        EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: db error reading \
                             storage {addr:?}[{slot_u256}]: {e}"
                        ))
                    })?;
                    if value != pre_value {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for withdrawal: account {addr:?} \
                             storage slot {slot_u256} changed during withdrawal/request \
                             phase ({value}) but slot is absent from BAL storage_changes \
                             (pre={pre_value})"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates supplied-BAL entries at the pre-execution index (0) on the
    /// parallel import path. `validate_tx_execution` covers indices `1..=n` and
    /// `validate_bal_withdrawal_index` covers `n+1`, but index 0 — the pre-block
    /// system calls (EIP-2935 block-hash history, EIP-4788 beacon root) — had no
    /// validator. A spurious no-op entry at index 0 (`post == pre-block value`,
    /// e.g. a `balance: 0` change for an untouched empty account) leaves the
    /// BAL-derived state root unchanged, so it slipped past both the downstream
    /// `validate_state_root` check and content validation: the parallel path
    /// accepted a block the sequential/full-rebuild path rejects.
    ///
    /// Must run right after `prepare_block`, while `current_accounts_state` still
    /// holds the pre-exec changes (`get_state_transitions_tx` drains it). The
    /// check is BAL -> DB only: an index-0 entry for an account the pre-exec
    /// phase never touched, whose value diverges from the post-`prepare_block`
    /// state, or whose value equals the pre-block value (a no-op), is rejected.
    /// Omissions and genuine divergences change the state root and are already
    /// caught by `validate_state_root`; the no-op case is the one this closes.
    #[cfg(feature = "rayon")]
    fn validate_bal_pre_exec_index(
        db: &GeneralizedDatabase,
        bal: &BlockAccessList,
        index: &BalAddressIndex,
    ) -> Result<(), EvmError> {
        const PRE_EXEC_IDX: u32 = 0;
        let Some(active_accounts) = index.tx_to_accounts.get(&PRE_EXEC_IDX) else {
            return Ok(());
        };

        // Pre-block seed: index-0 changes have no BAL history before them, so the
        // start-of-block value comes straight from the store, which on the import
        // path is still the unmodified parent state. Returns (balance, nonce,
        // code_hash); absent accounts default to (0, 0, EMPTY_KECCAK_HASH).
        let pre_account = |addr: Address| -> Result<(U256, u64, H256), EvmError> {
            let s = db.store.get_account_state(addr).map_err(|e| {
                EvmError::Custom(format!(
                    "BAL validation failed for pre-exec: db error reading account {addr:?}: {e}"
                ))
            })?;
            Ok((s.balance, s.nonce, s.code_hash))
        };

        for &acct_inner_idx in active_accounts {
            let acct = &bal.accounts()[acct_inner_idx];
            let addr = acct.address;
            let actual = db.current_accounts_state.get(&addr);

            // Balance
            if let Some(expected) = find_exact_change_balance(&acct.balance_changes, PRE_EXEC_IDX) {
                match actual {
                    Some(a) if a.info.balance == expected => {
                        if expected == pre_account(addr)?.0 {
                            return Err(EvmError::Custom(format!(
                                "BAL validation failed for pre-exec: account {addr:?} has spurious \
                                 no-op balance change at index 0: post==pre=={expected}"
                            )));
                        }
                    }
                    Some(a) => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for pre-exec: account {addr:?} balance mismatch \
                             at index 0: BAL={expected}, actual={}",
                            a.info.balance
                        )));
                    }
                    None => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for pre-exec: account {addr:?} has balance \
                             change at index 0 but was not touched by the pre-exec phase"
                        )));
                    }
                }
            }

            // Nonce
            if let Some(expected) = find_exact_change_nonce(&acct.nonce_changes, PRE_EXEC_IDX) {
                match actual {
                    Some(a) if a.info.nonce == expected => {
                        if expected == pre_account(addr)?.1 {
                            return Err(EvmError::Custom(format!(
                                "BAL validation failed for pre-exec: account {addr:?} has spurious \
                                 no-op nonce change at index 0: post==pre=={expected}"
                            )));
                        }
                    }
                    Some(a) => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for pre-exec: account {addr:?} nonce mismatch \
                             at index 0: BAL={expected}, actual={}",
                            a.info.nonce
                        )));
                    }
                    None => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for pre-exec: account {addr:?} has nonce \
                             change at index 0 but was not touched by the pre-exec phase"
                        )));
                    }
                }
            }

            // Code
            if let Some(expected_code) = find_exact_change_code(&acct.code_changes, PRE_EXEC_IDX) {
                let expected_hash = if expected_code.is_empty() {
                    *EMPTY_KECCAK_HASH
                } else {
                    ethrex_common::utils::keccak(expected_code)
                };
                match actual {
                    Some(a) if a.info.code_hash == expected_hash => {
                        if expected_hash == pre_account(addr)?.2 {
                            return Err(EvmError::Custom(format!(
                                "BAL validation failed for pre-exec: account {addr:?} has spurious \
                                 no-op code change at index 0"
                            )));
                        }
                    }
                    Some(_) => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for pre-exec: account {addr:?} code mismatch \
                             at index 0"
                        )));
                    }
                    None => {
                        return Err(EvmError::Custom(format!(
                            "BAL validation failed for pre-exec: account {addr:?} has code \
                             change at index 0 but was not touched by the pre-exec phase"
                        )));
                    }
                }
            }

            // Storage
            for sc in &acct.storage_changes {
                let Some(expected_value) =
                    find_exact_change_storage(&sc.slot_changes, PRE_EXEC_IDX)
                else {
                    continue;
                };
                let key = ethrex_common::utils::u256_to_h256(sc.slot);
                let actual_value = actual.and_then(|a| a.storage.get(&key)).copied();
                if actual_value != Some(expected_value) {
                    return Err(EvmError::Custom(format!(
                        "BAL validation failed for pre-exec: account {addr:?} storage slot {} \
                         mismatch at index 0: BAL={expected_value}, actual={actual_value:?}",
                        sc.slot
                    )));
                }
                let pre_value = db.store.get_storage_value(addr, key).map_err(|e| {
                    EvmError::Custom(format!(
                        "BAL validation failed for pre-exec: db error reading storage {addr:?} \
                         slot {}: {e}",
                        sc.slot
                    ))
                })?;
                if expected_value == pre_value {
                    return Err(EvmError::Custom(format!(
                        "BAL validation failed for pre-exec: account {addr:?} has spurious no-op \
                         storage change for slot {} at index 0: post==pre=={expected_value}",
                        sc.slot
                    )));
                }
            }
        }

        Ok(())
    }

    /// Pre-warms state by executing all transactions in parallel, grouped by sender.
    ///
    /// The `store` parameter should be a `CachingDatabase`-wrapped store so that
    /// parallel workers can benefit from shared caching. The same cache should
    /// be used by the sequential execution phase.
    #[cfg(feature = "rayon")]
    pub fn warm_block(
        block: &Block,
        store: Arc<dyn Database>,
        vm_type: VMType,
        crypto: &dyn Crypto,
        cancelled: &AtomicBool,
    ) -> Result<(), EvmError> {
        let txs_with_sender = block
            .body
            .get_transactions_with_sender(crypto)
            .map_err(|error| {
                EvmError::Transaction(format!("Couldn't recover addresses with error: {error}"))
            })?;

        Self::warm_txs(
            &txs_with_sender,
            &block.header,
            store.clone(),
            vm_type,
            crypto,
            &|| cancelled.load(Ordering::Relaxed),
        )?;

        let mut db = GeneralizedDatabase::new(store.clone());

        if cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }

        for withdrawal in block
            .body
            .withdrawals
            .iter()
            .flatten()
            .filter(|withdrawal| withdrawal.amount > 0)
        {
            db.get_account_mut(withdrawal.address).map_err(|_| {
                EvmError::DB(format!(
                    "Withdrawal account {} not found",
                    withdrawal.address
                ))
            })?;
        }
        Ok(())
    }

    /// Speculatively executes an arbitrary transaction set against `header`'s
    /// parent state to warm shared caches (used by the mempool prewarmer and
    /// `warm_block`). Sequential within a sender group, parallel across groups.
    /// `should_stop` is polled before each sender group and again before each
    /// transaction, so cancellation latency is bounded by one transaction's
    /// execution. Execution results are discarded — only cache population
    /// matters.
    #[cfg(feature = "rayon")]
    pub fn warm_txs(
        txs_with_sender: &[(&Transaction, Address)],
        header: &BlockHeader,
        store: Arc<dyn Database>,
        vm_type: VMType,
        crypto: &dyn Crypto,
        should_stop: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), EvmError> {
        // Group by sender so nonce/balance changes propagate within a group
        // (inspired by Nethermind's per-sender prewarmer).
        let mut sender_groups: FxHashMap<Address, Vec<&Transaction>> = FxHashMap::default();
        for (tx, sender) in txs_with_sender {
            sender_groups.entry(*sender).or_default().push(tx);
        }

        // Block-invariant EVM config + chain id, computed once and shared (by copy)
        // across the parallel warming workers.
        let chain_config = store.get_chain_config()?;
        let evm_config = EVMConfig::new_from_chain_config(&chain_config, header);
        let chain_id = chain_config.chain_id;
        // Block-invariant base blob fee, computed once and shared across workers.
        let base_blob_fee_per_gas = get_base_fee_per_blob_gas(header.excess_blob_gas, &evm_config)?;

        // Parallel across sender groups, sequential within each group. The stack pool is reused
        // across all groups a worker handles (it is `Send`).
        sender_groups.into_par_iter().for_each_with(
            Vec::with_capacity(STACK_LIMIT),
            |stack_pool, (sender, txs)| {
                if should_stop() {
                    return;
                }
                // Memory holds an `Rc` (not `Send`), so its pool can't ride the `for_each_with`
                // init; keep it local to this group's run, where it still amortizes the buffer
                // alloc across the group's txs.
                let mut memory_pool = Vec::with_capacity(1);
                // Each sender group gets its own db instance for state propagation
                let mut group_db = GeneralizedDatabase::new(store.clone());
                for tx in txs {
                    if should_stop() {
                        return;
                    }
                    let _ = Self::execute_tx_in_block(
                        tx,
                        sender,
                        header,
                        &mut group_db,
                        vm_type,
                        base_blob_fee_per_gas,
                        stack_pool,
                        &mut memory_pool,
                        true,
                        crypto,
                        evm_config,
                        chain_id,
                        // Warming discards results; the EXECUTE precompile is not run
                        // here (the real execution path carries the validator).
                        None,
                    );
                }
            },
        );
        Ok(())
    }

    /// Flattened (address, slot) storage worklist for a BAL, in natural account
    /// order (slots grouped per account for storage-trie locality).
    #[cfg(feature = "rayon")]
    pub fn bal_storage_slots(bal: &BlockAccessList) -> Vec<(Address, H256)> {
        bal.accounts()
            .iter()
            .flat_map(|ac| {
                ac.all_storage_slots()
                    .map(move |slot| (ac.address, H256::from_uint(&slot)))
            })
            .collect()
    }

    /// Concurrent block warmer for the BAL path: prefetches account states and
    /// contract code while execution runs.
    ///
    /// Storage slots are deliberately NOT warmed here. They are prefetched
    /// synchronously before the executor starts (see `bal_storage_slots` and the
    /// call site in `blockchain.rs`); warming them concurrently here let the
    /// executor race the warmer to the trie for SSTORE original values and cost
    /// ~22% of CPU. Keep storage warming synchronous and up front.
    #[cfg(feature = "rayon")]
    pub fn warm_block_from_bal(
        bal: &BlockAccessList,
        store: Arc<dyn Database>,
        cancelled: &AtomicBool,
    ) -> Result<(), EvmError> {
        let accounts = bal.accounts();
        if accounts.is_empty() {
            return Ok(());
        }

        // Phase 1: Prefetch all account states — parallel inner fetch + single write-lock.
        // This warms the CachingDatabase account cache and the TrieLayerCache with
        // state trie nodes. Storage slots are prefetched synchronously before the
        // executor starts (see `bal_storage_slots` at the call site), so this warmer
        // only needs to cover account states and contract code, which overlap exec.
        let account_addresses: Vec<Address> = accounts.iter().map(|ac| ac.address).collect();
        store
            .prefetch_accounts(&account_addresses)
            .map_err(|e| EvmError::Custom(format!("prefetch_accounts: {e}")))?;

        if cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Phase 2: Code prefetch — collect code hashes from Phase 1 account states
        // (already cached after Phase 1 prefetch), then batch-fetch codes in parallel.
        // Uses par_iter for collection since blocks can have thousands of accounts.
        let code_hashes: Vec<ethrex_common::H256> = accounts
            .par_iter()
            .filter_map(|ac| {
                store
                    .get_account_state(ac.address)
                    .ok()
                    .filter(|s| s.code_hash != *EMPTY_KECCAK_HASH)
                    .map(|s| s.code_hash)
            })
            .collect();
        code_hashes.par_iter().for_each(|&h| {
            let _ = store.get_account_code(h);
        });

        Ok(())
    }

    fn send_state_transitions_tx(
        merkleizer: &Sender<Vec<AccountUpdate>>,
        db: &mut GeneralizedDatabase,
        queue_length: &AtomicUsize,
    ) -> Result<(), EvmError> {
        let transitions = LEVM::get_state_transitions_tx(db)?;
        merkleizer
            .send(transitions)
            .map_err(|e| EvmError::Custom(format!("send failed: {e}")))?;
        queue_length.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn setup_env(
        tx: &Transaction,
        tx_sender: Address,
        block_header: &BlockHeader,
        db: &GeneralizedDatabase,
        vm_type: VMType,
    ) -> Result<Environment, VMError> {
        // `chain_config` (a dyn-dispatch copy) and `EVMConfig`/fork/blob-schedule are
        // block-invariant; in a block loop, compute them once and use
        // `setup_env_with_config` instead. This single-tx entry point computes them here.
        let chain_config = db.store.get_chain_config()?;
        let config = EVMConfig::new_from_chain_config(&chain_config, block_header);
        let base_blob_fee_per_gas =
            get_base_fee_per_blob_gas(block_header.excess_blob_gas, &config)?;
        Self::setup_env_with_config(
            tx,
            tx_sender,
            block_header,
            config,
            chain_config.chain_id,
            vm_type,
            base_blob_fee_per_gas,
        )
    }

    /// Per-tx `Environment` builder that takes the block-invariant `EVMConfig` and
    /// `chain_id` precomputed once per block, avoiding a per-tx `get_chain_config()`
    /// dyn-dispatch `ChainConfig` copy + `fork`/blob-schedule recompute.
    fn setup_env_with_config(
        tx: &Transaction,
        tx_sender: Address,
        block_header: &BlockHeader,
        config: EVMConfig,
        chain_id: u64,
        vm_type: VMType,
        base_blob_fee_per_gas: U256,
    ) -> Result<Environment, VMError> {
        let gas_price: U256 = calculate_gas_price_for_tx(
            tx,
            block_header.base_fee_per_gas.unwrap_or_default(),
            &vm_type,
        )?;

        let block_excess_blob_gas = block_header.excess_blob_gas;
        let env = Environment {
            origin: tx_sender,
            gas_limit: tx.gas_limit(),
            config,
            block_number: block_header.number,
            coinbase: block_header.coinbase,
            timestamp: block_header.timestamp,
            prev_randao: Some(block_header.prev_randao),
            slot_number: block_header
                .slot_number
                .map(U256::from)
                .unwrap_or(U256::zero()),
            chain_id: chain_id.into(),
            base_fee_per_gas: block_header.base_fee_per_gas.unwrap_or_default().into(),
            base_blob_fee_per_gas,
            gas_price,
            block_excess_blob_gas,
            block_blob_gas_used: block_header.blob_gas_used,
            tx_blob_hashes: tx.blob_versioned_hashes(),
            tx_max_priority_fee_per_gas: tx.max_priority_fee().map(U256::from),
            tx_max_fee_per_gas: tx.max_fee_per_gas().map(U256::from),
            tx_max_fee_per_blob_gas: tx.max_fee_per_blob_gas(),
            tx_nonce: tx.nonce(),
            block_gas_limit: block_header.gas_limit,
            difficulty: block_header.difficulty,
            is_privileged: matches!(tx, Transaction::PrivilegedL2Transaction(_)),
            fee_token: tx.fee_token(),
            disable_balance_check: false,
            disable_nonce_check: false,
            trace_eth_transfers: false,
            disable_gas_allowance_check: false,
            disable_sender_eoa_check: false,
            is_system_call: false,
        };

        Ok(env)
    }

    pub fn execute_tx(
        // The transaction to execute.
        tx: &Transaction,
        // The transaction's recovered address
        tx_sender: Address,
        // The block header for the current block.
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
        stateless_validator: Option<&dyn StatelessValidator>,
    ) -> Result<ExecutionReport, EvmError> {
        let env = Self::setup_env(tx, tx_sender, block_header, db, vm_type)?;
        let mut vm = VM::new(
            env,
            db,
            tx,
            LevmCallTracer::disabled(),
            vm_type,
            crypto,
            stateless_validator,
        )?;

        vm.execute().map_err(VMError::into)
    }

    /// Like [`LEVM::execute_tx`] but for `eth_simulateV1`: validation failures
    /// come back as structured [`SimulationTxError::Validation`] (the caller
    /// maps each variant to its spec error code and aborts the request), and
    /// the simulation relaxations are applied to the environment.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_tx_for_simulation(
        tx: &Transaction,
        tx_sender: Address,
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
        validate: bool,
        trace_eth_transfers: bool,
    ) -> Result<ExecutionReport, SimulationTxError> {
        let mut env = Self::setup_env(tx, tx_sender, block_header, db, vm_type)?;
        // The sender-is-EOA check is always skipped in eth_simulateV1; nonce
        // enforcement only applies with `validation: true`.
        env.disable_sender_eoa_check = true;
        env.disable_nonce_check = !validate;
        env.trace_eth_transfers = trace_eth_transfers;
        // With `validation: false` blob fees are zeroed unless the call prices
        // them explicitly (mirrors `adjust_disabled_base_fee`'s blob branch).
        if !validate && tx.max_fee_per_blob_gas().unwrap_or_default().is_zero() {
            env.base_blob_fee_per_gas = U256::zero();
            env.block_excess_blob_gas = None;
        }
        // No stateless validator: simulation answers a query and produces no
        // EIP-8025 execution proof, matching every other simulation and tracing path.
        let mut vm = VM::new(
            env,
            db,
            tx,
            LevmCallTracer::disabled(),
            vm_type,
            crypto,
            None,
        )?;

        vm.execute().map_err(SimulationTxError::from)
    }

    // Like execute_tx but allows reusing the stack pool. Takes the block-invariant
    // `config`/`chain_id` precomputed once per block (see `setup_env_with_config`).
    #[allow(clippy::too_many_arguments)]
    fn execute_tx_in_block(
        // The transaction to execute.
        tx: &Transaction,
        // The transaction's recovered address
        tx_sender: Address,
        // The block header for the current block.
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        base_blob_fee_per_gas: U256,
        stack_pool: &mut Vec<Stack>,
        memory_pool: &mut Vec<Memory>,
        disable_balance_check: bool,
        crypto: &dyn Crypto,
        config: EVMConfig,
        chain_id: u64,
        stateless_validator: Option<&dyn StatelessValidator>,
    ) -> Result<ExecutionReport, EvmError> {
        let mut env = Self::setup_env_with_config(
            tx,
            tx_sender,
            block_header,
            config,
            chain_id,
            vm_type,
            base_blob_fee_per_gas,
        )?;
        env.disable_balance_check = disable_balance_check;
        // Draw the root frame's stack and memory buffer from the shared pools (and adopt the
        // stacks for sub-frames), then return them afterwards so the next tx reuses them instead
        // of allocating + zeroing a fresh 32 KB stack and a fresh memory buffer per transaction.
        let mut vm = VM::new_pooled(
            env,
            db,
            tx,
            LevmCallTracer::disabled(),
            vm_type,
            crypto,
            stateless_validator,
            stack_pool,
            memory_pool,
        )?;
        let result = vm.execute().map_err(VMError::into);
        // Runs on both success and error paths (execute borrowed `vm` mutably but left it intact).
        vm.reclaim_into(stack_pool, memory_pool);
        result
    }

    pub fn undo_last_tx(db: &mut GeneralizedDatabase) -> Result<(), EvmError> {
        db.undo_last_transaction()?;
        Ok(())
    }

    pub fn simulate_tx_from_generic(
        // The transaction to execute.
        tx: &GenericTransaction,
        // The block header for the current block.
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
        stateless_validator: Option<&dyn StatelessValidator>,
    ) -> Result<ExecutionResult, EvmError> {
        // `env_from_generic` already relaxes the admission-only validations for every
        // simulation RPC, the gas allowance included. `block_gas_limit` keeps the block's
        // real value there: the GASLIMIT opcode reads it, so overwriting it would make
        // 0x45 return a number that appears nowhere on chain.
        let mut env = env_from_generic(tx, block_header, db, vm_type)?;

        adjust_disabled_base_fee(&mut env);

        let converted_tx = generic_tx_to_transaction(tx)?;
        let mut vm = vm_from_generic(&converted_tx, env, db, vm_type, crypto, stateless_validator)?;

        vm.execute()
            .map(|value| value.into())
            .map_err(VMError::into)
    }

    /// EIP-8141 mempool validation-prefix simulation (local peer policy, never
    /// consensus). Builds a VM like [`LEVM::execute_tx`] over a fresh
    /// simulation database, activates the [`ValidationObserver`] for the
    /// transaction's sender, runs ONLY the validation-prefix frames, and applies
    /// the admission assertions:
    ///   - no prefix frame reverted;
    ///   - each verify/pay frame that must APPROVE did (the prefix established a
    ///     payer);
    ///   - the deploy frame (if any) left non-empty code at the sender;
    ///   - total simulated prefix gas <= MAX_VERIFY_GAS;
    ///   - no validation-trace rule was violated.
    ///
    /// `canonical_paymaster_code_hash` is the pinned canonical paymaster code
    /// hash, when known (always `None` today, OQ1).
    #[allow(clippy::too_many_arguments)]
    pub fn simulate_frame_validation_prefix(
        tx: &Transaction,
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
        prefix: &ethrex_common::types::ValidationPrefix,
        _canonical_paymaster_code_hash: Option<H256>,
    ) -> Result<FrameValidationOutcome, EvmError> {
        use ethrex_common::types::FRAME_TX_MAX_VERIFY_GAS;

        let frame_tx = match tx {
            Transaction::FrameTransaction(ft) => ft,
            _ => {
                return Err(EvmError::Custom(
                    "simulate_frame_validation_prefix requires a frame transaction".to_string(),
                ));
            }
        };
        let sender = frame_tx.sender;

        let env = Self::setup_env(tx, sender, block_header, db, vm_type)?;
        let mut vm = VM::new(
            env,
            db,
            tx,
            LevmCallTracer::disabled(),
            vm_type,
            crypto,
            None,
        )?;

        // OQ1: no canonical paymaster is resolvable, so the canonical pay-frame
        // exemption never fires (always `None`).
        let canonical_pay_frame: Option<usize> = None;

        let sim = match vm.run_frame_validation_prefix(
            &prefix.frame_indices,
            prefix.deploy_index,
            canonical_pay_frame,
        ) {
            Ok(sim) => sim,
            Err(err) => {
                // A preamble / VM error means the prefix cannot be validated;
                // treat it as a (conservative) rejection rather than failing the
                // whole admission pipeline.
                return Ok(FrameValidationOutcome {
                    passed: false,
                    violation: Some(EvmError::from(err).to_string()),
                    reservation_ceiling: Self::frame_tx_reservation_ceiling(frame_tx),
                    accessed_paymaster: None,
                    touched_sender_slots: Vec::new(),
                });
            }
        };

        let reservation_ceiling = Self::frame_tx_reservation_ceiling(frame_tx);
        let touched_sender_slots = vm.validation_observer.touched_sender_slots.clone();
        // The payer established by the prefix is the paymaster (OQ2: the
        // APPROVE-payment address is treated uniformly as "paymaster", including
        // the self-funded sender). Its canonical flag is always false (OQ1: no
        // canonical paymaster bytecode is resolvable), which is also why
        // `_canonical_paymaster_code_hash` is unused. The observer carries no
        // distinct paymaster, so derive it from the established payer.
        let accessed_paymaster = sim.payer_address.map(|payer| (payer, false));

        // Assertion: a recorded trace violation fails validation.
        if let Some(violation) = &vm.validation_observer.violation {
            return Ok(FrameValidationOutcome {
                passed: false,
                violation: Some(format!("{violation:?}")),
                reservation_ceiling,
                accessed_paymaster,
                touched_sender_slots,
            });
        }

        // Assertion: no prefix frame reverted.
        if sim.any_revert {
            return Ok(FrameValidationOutcome {
                passed: false,
                violation: Some("validation prefix frame reverted".to_string()),
                reservation_ceiling,
                accessed_paymaster,
                touched_sender_slots,
            });
        }

        // Assertion: the prefix established a payer (verify/pay frames must
        // APPROVE-payment; otherwise the transaction has no payer).
        if sim.payer_address.is_none() {
            return Ok(FrameValidationOutcome {
                passed: false,
                violation: Some("validation prefix did not establish a payer".to_string()),
                reservation_ceiling,
                accessed_paymaster,
                touched_sender_slots,
            });
        }

        // Assertion: a deploy frame must leave non-empty code at the sender.
        if prefix.deploy_index.is_some() {
            let code = vm.db.get_account_code(sender).map_err(VMError::from)?;
            if code.is_empty() {
                return Ok(FrameValidationOutcome {
                    passed: false,
                    violation: Some(format!("{:?}", FrameSimViolation::DeployInstalledNoCode)),
                    reservation_ceiling,
                    accessed_paymaster,
                    touched_sender_slots,
                });
            }
        }

        // Assertion: total simulated prefix gas within the verify-gas budget.
        if sim.total_gas_used > FRAME_TX_MAX_VERIFY_GAS {
            return Ok(FrameValidationOutcome {
                passed: false,
                violation: Some(format!(
                    "validation prefix gas {} exceeds MAX_VERIFY_GAS {}",
                    sim.total_gas_used, FRAME_TX_MAX_VERIFY_GAS
                )),
                reservation_ceiling,
                accessed_paymaster,
                touched_sender_slots,
            });
        }

        Ok(FrameValidationOutcome {
            passed: true,
            violation: None,
            reservation_ceiling,
            accessed_paymaster,
            touched_sender_slots,
        })
    }

    /// Mempool reservation ceiling for a frame transaction:
    /// `max_gas * max_fee_per_gas + len(blob_hashes) * 131072 * max_fee_per_blob_gas`,
    /// saturating.
    ///
    /// The consensus `max_cost` that APPROVE collects prices blobs at the
    /// including block's `blob_base_fee` (EIP-8141 §Gas Accounting, TXPARAM 0x06;
    /// `load_tx_param` 0x06 in `opcode_handlers/frame_tx.rs`). That rate is not
    /// known at admission — the simulation runs against the current head, while
    /// execution charges the base fee of whichever later block includes the
    /// transaction — and the blob base fee moves per block, so pricing the
    /// reservation at the head's rate could reserve less than the eventual charge.
    /// `max_fee_per_blob_gas >= blob_base_fee` is an inclusion condition
    /// (EIP-8141 §Blob handling), so the declared max rate bounds every block that
    /// can include the transaction and keeps this a true ceiling.
    ///
    /// Intentionally saturating (not checked): the TXPARAM 0x06 consensus handler
    /// uses checked_mul/checked_add and halts on overflow. Saturating to
    /// `U256::MAX` here only makes the reservation larger, never smaller.
    fn frame_tx_reservation_ceiling(frame_tx: &ethrex_common::types::FrameTransaction) -> U256 {
        let gas_cost =
            U256::from(frame_tx.max_fee_per_gas).saturating_mul(U256::from(frame_tx.max_gas()));
        let blob_cost = U256::from(frame_tx.blob_versioned_hashes.len())
            .saturating_mul(U256::from(131072u64))
            .saturating_mul(frame_tx.max_fee_per_blob_gas);
        gas_cost.saturating_add(blob_cost)
    }

    pub fn get_state_transitions(
        db: &mut GeneralizedDatabase,
    ) -> Result<Vec<AccountUpdate>, EvmError> {
        Ok(db.get_state_transitions()?)
    }

    pub fn get_state_transitions_tx(
        db: &mut GeneralizedDatabase,
    ) -> Result<Vec<AccountUpdate>, EvmError> {
        Ok(db.get_state_transitions_tx()?)
    }

    pub fn process_withdrawals(
        db: &mut GeneralizedDatabase,
        withdrawals: &[Withdrawal],
    ) -> Result<(), EvmError> {
        // For every withdrawal we increment the target account's balance
        for (address, increment) in withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.amount > 0)
            .map(|w| (w.address, u128::from(w.amount) * u128::from(GWEI_TO_WEI)))
        {
            let account = db
                .get_account_mut(address)
                .map_err(|_| EvmError::DB(format!("Withdrawal account {address} not found")))?;

            let initial_balance = account.info.balance;
            account.info.balance += increment.into();
            let new_balance = account.info.balance;

            // Record balance change for BAL (EIP-7928)
            if let Some(recorder) = db.bal_recorder_mut() {
                recorder.set_initial_balance(address, initial_balance);
                recorder.record_balance_change(address, new_balance);
            }
        }
        Ok(())
    }

    // SYSTEM CONTRACTS
    pub fn beacon_root_contract_call(
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<(), EvmError> {
        if let VMType::L2(_) = vm_type {
            return Err(EvmError::InvalidEVM(
                "beacon_root_contract_call should not be called for L2 VM".to_string(),
            ));
        }

        let beacon_root = block_header.parent_beacon_block_root.ok_or_else(|| {
            EvmError::Header("parent_beacon_block_root field is missing".to_string())
        })?;

        generic_system_contract_levm(
            block_header,
            Bytes::copy_from_slice(beacon_root.as_bytes()),
            db,
            BEACON_ROOTS_ADDRESS.address,
            SYSTEM_ADDRESS,
            vm_type,
            crypto,
        )?;
        Ok(())
    }

    pub fn process_block_hash_history(
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<(), EvmError> {
        if let VMType::L2(_) = vm_type {
            return Err(EvmError::InvalidEVM(
                "process_block_hash_history should not be called for L2 VM".to_string(),
            ));
        }

        generic_system_contract_levm(
            block_header,
            Bytes::copy_from_slice(block_header.parent_hash.as_bytes()),
            db,
            HISTORY_STORAGE_ADDRESS.address,
            SYSTEM_ADDRESS,
            vm_type,
            crypto,
        )?;
        Ok(())
    }

    /// Install the canonical EIP-8141 expiry verifier runtime code at
    /// EXPIRY_VERIFIER on Hegota activation (EIP-8141: "At
    /// activation, clients must install..."). Idempotent: writes only when
    /// the existing code differs, so exactly one account update is produced
    /// (at the first Hegota block) and none afterwards.
    pub fn install_expiry_verifier_code(
        db: &mut GeneralizedDatabase,
        crypto: &dyn Crypto,
    ) -> Result<(), EvmError> {
        // Predeploy convention (matches the genesis predeploys 4788/2935/7002/7251).
        const PREDEPLOY_NONCE: u64 = 1;

        let current = db.get_account_code(EXPIRY_VERIFIER_PREDEPLOY.address)?;
        if current.code() == EXPIRY_VERIFIER_RUNTIME_BYTECODE.as_slice() {
            return Ok(());
        }
        let code = Code::from_bytecode(
            Bytes::from_static(&EXPIRY_VERIFIER_RUNTIME_BYTECODE),
            crypto,
        );
        let code_hash = code.hash;
        // Record BAL code/nonce changes if recording is active, so a BAL
        // reconstructor reproduces the same post-state (it takes nonce from
        // prestate otherwise).
        if let Some(recorder) = db.bal_recorder_mut() {
            recorder.record_code_change(EXPIRY_VERIFIER_PREDEPLOY.address, code.code_bytes());
            recorder.record_nonce_change(EXPIRY_VERIFIER_PREDEPLOY.address, PREDEPLOY_NONCE);
        }
        let acc = db
            .get_account_mut(EXPIRY_VERIFIER_PREDEPLOY.address)
            .map_err(EvmError::from)?;
        acc.info.code_hash = code_hash;
        acc.info.nonce = PREDEPLOY_NONCE;
        db.codes.entry(code_hash).or_insert(code);
        Ok(())
    }

    pub(crate) fn read_withdrawal_requests(
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<ExecutionReport, EvmError> {
        if let VMType::L2(_) = vm_type {
            return Err(EvmError::InvalidEVM(
                "read_withdrawal_requests should not be called for L2 VM".to_string(),
            ));
        }

        let report = generic_system_contract_levm(
            block_header,
            Bytes::new(),
            db,
            WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address,
            SYSTEM_ADDRESS,
            vm_type,
            crypto,
        )?;

        match report.result {
            TxResult::Success => Ok(report),
            // EIP-7002 specifies that a failed system call invalidates the entire block.
            TxResult::Revert(vm_error) => Err(EvmError::SystemContractCallFailed(format!(
                "REVERT when reading withdrawal requests with error: {vm_error:?}. According to EIP-7002, the revert of this system call invalidates the block.",
            ))),
        }
    }

    pub(crate) fn dequeue_consolidation_requests(
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<ExecutionReport, EvmError> {
        if let VMType::L2(_) = vm_type {
            return Err(EvmError::InvalidEVM(
                "dequeue_consolidation_requests should not be called for L2 VM".to_string(),
            ));
        }

        let report = generic_system_contract_levm(
            block_header,
            Bytes::new(),
            db,
            CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS.address,
            SYSTEM_ADDRESS,
            vm_type,
            crypto,
        )?;

        match report.result {
            TxResult::Success => Ok(report),
            // EIP-7251 specifies that a failed system call invalidates the entire block.
            TxResult::Revert(vm_error) => Err(EvmError::SystemContractCallFailed(format!(
                "REVERT when dequeuing consolidation requests with error: {vm_error:?}. According to EIP-7251, the revert of this system call invalidates the block.",
            ))),
        }
    }

    pub(crate) fn read_builder_deposit_requests(
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<ExecutionReport, EvmError> {
        if let VMType::L2(_) = vm_type {
            return Err(EvmError::InvalidEVM(
                "read_builder_deposit_requests should not be called for L2 VM".to_string(),
            ));
        }

        let report = generic_system_contract_levm(
            block_header,
            Bytes::new(),
            db,
            BUILDER_DEPOSIT_CONTRACT_ADDRESS.address,
            SYSTEM_ADDRESS,
            vm_type,
            crypto,
        )?;

        match report.result {
            TxResult::Success => Ok(report),
            // EIP-8282 specifies that a failed system call invalidates the entire block.
            TxResult::Revert(vm_error) => Err(EvmError::SystemContractCallFailed(format!(
                "REVERT when reading builder deposit requests with error: {vm_error:?}. According to EIP-8282, the revert of this system call invalidates the block.",
            ))),
        }
    }

    pub(crate) fn dequeue_builder_exit_requests(
        block_header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<ExecutionReport, EvmError> {
        if let VMType::L2(_) = vm_type {
            return Err(EvmError::InvalidEVM(
                "dequeue_builder_exit_requests should not be called for L2 VM".to_string(),
            ));
        }

        let report = generic_system_contract_levm(
            block_header,
            Bytes::new(),
            db,
            BUILDER_EXIT_CONTRACT_ADDRESS.address,
            SYSTEM_ADDRESS,
            vm_type,
            crypto,
        )?;

        match report.result {
            TxResult::Success => Ok(report),
            // EIP-8282 specifies that a failed system call invalidates the entire block.
            TxResult::Revert(vm_error) => Err(EvmError::SystemContractCallFailed(format!(
                "REVERT when dequeuing builder exit requests with error: {vm_error:?}. According to EIP-8282, the revert of this system call invalidates the block.",
            ))),
        }
    }

    pub fn create_access_list(
        mut tx: GenericTransaction,
        header: &BlockHeader,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<(ExecutionResult, AccessList), VMError> {
        let mut env = env_from_generic(&tx, header, db, vm_type)?;

        adjust_disabled_base_fee(&mut env);

        let converted_tx = generic_tx_to_transaction(&tx)?;
        let mut vm = vm_from_generic(&converted_tx, env.clone(), db, vm_type, crypto, None)?;

        vm.stateless_execute()?;

        // Execute the tx again, now with the created access list.
        tx.access_list = vm.substate.make_access_list();
        let converted_tx = generic_tx_to_transaction(&tx)?;
        let mut vm = vm_from_generic(&converted_tx, env, db, vm_type, crypto, None)?;

        let report = vm.stateless_execute()?;

        Ok((
            report.into(),
            tx.access_list
                .into_iter()
                .map(|x| (x.address, x.storage_keys))
                .collect(),
        ))
    }

    pub fn prepare_block(
        block: &Block,
        db: &mut GeneralizedDatabase,
        vm_type: VMType,
        crypto: &dyn Crypto,
    ) -> Result<(), EvmError> {
        let chain_config = db.store.get_chain_config()?;
        let block_header = &block.header;
        let fork = chain_config.fork(block_header.timestamp);

        // TODO: I don't like deciding the behavior based on the VMType here.
        if let VMType::L2(_) = vm_type {
            return Ok(());
        }

        // EIP-8141: the expiry verifier predeploy must exist from Hegota
        // activation onward. Idempotent install; also
        // hooked in apply_system_calls for the payload-build path.
        if fork >= Fork::Hegota {
            Self::install_expiry_verifier_code(db, crypto)?;
        }

        if block_header.parent_beacon_block_root.is_some() && fork >= Fork::Cancun {
            Self::beacon_root_contract_call(block_header, db, vm_type, crypto)?;
        }

        if fork >= Fork::Prague {
            //eip 2935: stores parent block hash in system contract
            Self::process_block_hash_history(block_header, db, vm_type, crypto)?;
        }
        Ok(())
    }
}

pub fn generic_system_contract_levm(
    block_header: &BlockHeader,
    calldata: Bytes,
    db: &mut GeneralizedDatabase,
    contract_address: Address,
    system_address: Address,
    vm_type: VMType,
    crypto: &dyn Crypto,
) -> Result<ExecutionReport, EvmError> {
    let chain_config = db.store.get_chain_config()?;
    let config = EVMConfig::new_from_chain_config(&chain_config, block_header);
    let env = Environment {
        origin: system_address,
        // EIPs 2935, 4788, 7002 and 7251 dictate that the system calls have a gas
        // limit of 30 million and they do not use intrinsic gas. EELS
        // (process_unchecked_system_transaction) builds the message with
        // intrinsic_regular_gas=0 and gas=SYSTEM_TRANSACTION_GAS, so the contract
        // gets the full SYS_CALL_GAS_LIMIT. We match that by NOT padding the limit
        // here and by zeroing the intrinsic for system calls in the default hook.
        // (A previous `+ TX_BASE_COST` buffer assumed the flat 21000 Prague
        // intrinsic; EIP-2780 lowered Amsterdam's intrinsic to 15000, so the buffer
        // over-funded the frame by 6000 and let an OOG-by-1 system contract avoid
        // running out of gas.)
        gas_limit: SYS_CALL_GAS_LIMIT,
        block_number: block_header.number,
        coinbase: block_header.coinbase,
        timestamp: block_header.timestamp,
        prev_randao: Some(block_header.prev_randao),
        base_fee_per_gas: U256::zero(),
        gas_price: U256::zero(),
        block_excess_blob_gas: block_header.excess_blob_gas,
        block_blob_gas_used: block_header.blob_gas_used,
        // Use the actual block's gas_limit so EIP-8037 cost_per_state_byte is correct.
        // The gas-allowance check is bypassed via `is_system_call` below; feeding
        // i64::MAX here would make cpsb astronomically large and OOG any SSTORE
        // that charges state gas (e.g. EIP-2935, EIP-4788 new-slot writes).
        block_gas_limit: block_header.gas_limit,
        is_system_call: true,
        config,
        ..Default::default()
    };

    // Invariant: with a zero gas price (and `is_system_call` making the hook
    // skip the sender path entirely) a system call leaves no SYSTEM_ADDRESS
    // state behind — no nonce bump, no balance change, not even a read. If
    // this ever becomes non-zero, the hook's system-call branches must be
    // revisited.
    debug_assert!(
        env.gas_price.is_zero() && env.base_fee_per_gas.is_zero(),
        "system calls must run with a zero gas price"
    );

    // This check is not necessary in practice, since contract deployment has succesfully happened in all relevant testnets and mainnet
    // However, it's necessary to pass some of the Hive tests related to system contract deployment, which is why we have it
    // The error that should be returned for the relevant contracts is indicated in the following:
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7002.md#empty-code-failure
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7251.md#empty-code-failure
    // EIP-8282 applies the same empty-code-failure rule to the builder deposit/exit predeploys.
    // No extra fork guard is needed here: builder predeploy addresses only reach this function via
    // extract_all_requests_levm, which gates them on fork >= Amsterdam, so a Prague/Osaka block
    // never passes a builder address to this check.
    if PRAGUE_SYSTEM_CONTRACTS
        .iter()
        .chain(AMSTERDAM_REQUEST_PREDEPLOYS.iter())
        .any(|contract| contract.address == contract_address)
        && db.get_account_code(contract_address)?.is_empty()
    {
        return Err(EvmError::SystemContractCallFailed(format!(
            "System contract: {contract_address} has no code after deployment"
        )));
    };

    let tx = &Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(contract_address),
        value: U256::zero(),
        data: calldata,
        ..Default::default()
    });
    // EIP-7928: Mark BAL recorder as in system call mode to filter SYSTEM_ADDRESS changes
    if let Some(recorder) = db.bal_recorder.as_mut() {
        recorder.enter_system_call();
    }

    let result = VM::new(
        env,
        db,
        tx,
        LevmCallTracer::disabled(),
        vm_type,
        crypto,
        None,
    )
    .and_then(|mut vm| vm.execute())
    .map_err(EvmError::from);

    // EIP-7928: Exit system call mode before restoring accounts (must run even on error)
    if let Some(recorder) = db.bal_recorder.as_mut() {
        recorder.exit_system_call();
    }

    result
}

#[allow(unreachable_code)]
#[allow(unused_variables)]
pub fn extract_all_requests_levm(
    receipts: &[Receipt],
    db: &mut GeneralizedDatabase,
    header: &BlockHeader,
    vm_type: VMType,
    crypto: &dyn Crypto,
) -> Result<Vec<Requests>, EvmError> {
    if let VMType::L2(_) = vm_type {
        return Err(EvmError::InvalidEVM(
            "extract_all_requests_levm should not be called for L2 VM".to_string(),
        ));
    }

    let chain_config = db.store.get_chain_config()?;
    let fork = chain_config.fork(header.timestamp);

    if fork < Fork::Prague {
        return Ok(Default::default());
    }

    let withdrawals_data: Vec<u8> = LEVM::read_withdrawal_requests(header, db, vm_type, crypto)?
        .output
        .into();
    let consolidation_data: Vec<u8> =
        LEVM::dequeue_consolidation_requests(header, db, vm_type, crypto)?
            .output
            .into();

    let deposits = Requests::from_deposit_receipts(chain_config.deposit_contract_address, receipts)
        .ok_or(EvmError::InvalidDepositRequest)?;
    let withdrawals = Requests::from_withdrawals_data(withdrawals_data);
    let consolidation = Requests::from_consolidation_data(consolidation_data);

    let mut requests = vec![deposits, withdrawals, consolidation];

    // EIP-8282 (Amsterdam): builder deposit (0x03) and builder exit (0x04) requests.
    // Prague (18) < Amsterdam (25), so this needs a separate explicit gate; appending
    // unconditionally after the Prague early-return above would emit these on Prague/Osaka blocks.
    if fork >= Fork::Amsterdam {
        // Grow to exactly 5 once, avoiding a realloc on each of the two pushes below.
        requests.reserve_exact(2);
        let builder_deposit_data: Vec<u8> =
            LEVM::read_builder_deposit_requests(header, db, vm_type, crypto)?
                .output
                .into();
        let builder_exit_data: Vec<u8> =
            LEVM::dequeue_builder_exit_requests(header, db, vm_type, crypto)?
                .output
                .into();
        requests.push(Requests::from_builder_deposit_data(builder_deposit_data));
        requests.push(Requests::from_builder_exit_data(builder_exit_data));
    }

    Ok(requests)
}

/// Calculating gas_price according to EIP-1559 rules
/// See https://github.com/ethereum/go-ethereum/blob/7ee9a6e89f59cee21b5852f5f6ffa2bcfc05a25f/internal/ethapi/transaction_args.go#L430
pub fn calculate_gas_price_for_generic(tx: &GenericTransaction, basefee: u64) -> U256 {
    if !tx.gas_price.is_zero() {
        // Legacy gas field was specified, use it
        tx.gas_price
    } else {
        // Backfill the legacy gas price for EVM execution, (zero if max_fee_per_gas is zero)
        min(
            tx.max_priority_fee_per_gas.unwrap_or(0) + basefee,
            tx.max_fee_per_gas.unwrap_or(0),
        )
        .into()
    }
}

pub fn calculate_gas_price_for_tx(
    tx: &Transaction,
    mut fee_per_gas: u64,
    vm_type: &VMType,
) -> Result<U256, VMError> {
    let Some(max_priority_fee) = tx.max_priority_fee() else {
        // Legacy transaction
        return Ok(tx.gas_price());
    };

    let max_fee_per_gas = tx.max_fee_per_gas().ok_or(VMError::TxValidation(
        TxValidationError::InsufficientMaxFeePerGas,
    ))?;

    if let VMType::L2(fee_config) = vm_type
        && let Some(operator_fee_config) = &fee_config.operator_fee_config
    {
        fee_per_gas += operator_fee_config.operator_fee_per_gas;
    }

    if fee_per_gas > max_fee_per_gas {
        return Err(VMError::TxValidation(
            TxValidationError::InsufficientMaxFeePerGas,
        ));
    }

    Ok(min(max_priority_fee + fee_per_gas, max_fee_per_gas).into())
}

/// When basefee tracking is disabled  (ie. env.disable_base_fee = true; env.disable_block_gas_limit = true;)
/// and no gas prices were specified, lower the basefee to 0 to avoid breaking EVM invariants (basefee < feecap)
/// See https://github.com/ethereum/go-ethereum/blob/00294e9d28151122e955c7db4344f06724295ec5/core/vm/evm.go#L137
pub(crate) fn adjust_disabled_base_fee(env: &mut Environment) {
    if env.gas_price == U256::zero() {
        env.base_fee_per_gas = U256::zero();
    }
    // Same for the blob fee: a call object that opts out by passing `maxFeePerBlobGas: 0`
    // must not be rejected for undercutting the block's blob base fee.
    // `base_blob_fee_per_gas` is the field the validation and the up-front cost both read
    // (`validate_max_fee_per_blob_gas`, `deduct_caller`), and it is computed in
    // `env_from_generic` before this runs, so it is what has to be lowered. Clearing
    // `block_excess_blob_gas` instead had no effect: nothing reads that field, and the
    // blob base fee derived from a zero excess still has a floor of 1, which a zero fee
    // cap undercuts just the same.
    if env
        .tx_max_fee_per_blob_gas
        .is_some_and(|v| v == U256::zero())
    {
        env.base_blob_fee_per_gas = U256::zero();
    }
}

/// When l2 fees are disabled (ie. env.gas_price = 0), set fee configs to None to avoid breaking failing fee deductions
fn adjust_disabled_l2_fees(env: &Environment, vm_type: VMType) -> VMType {
    if env.gas_price == U256::zero()
        && let VMType::L2(fee_config) = vm_type
    {
        // Don't deduct fees if no gas price is set
        return VMType::L2(FeeConfig {
            operator_fee_config: None,
            l1_fee_config: None,
            ..fee_config
        });
    }
    vm_type
}

pub(crate) fn env_from_generic(
    tx: &GenericTransaction,
    header: &BlockHeader,
    db: &GeneralizedDatabase,
    vm_type: VMType,
) -> Result<Environment, VMError> {
    let chain_config = db.store.get_chain_config()?;
    let gas_price =
        calculate_gas_price_for_generic(tx, header.base_fee_per_gas.unwrap_or(INITIAL_BASE_FEE));
    let block_excess_blob_gas = header.excess_blob_gas;
    let config = EVMConfig::new_from_chain_config(&chain_config, header);

    // slot_number: default a missing value to zero exactly like
    // `setup_env_with_config` (the block-execution env builder) does, rather
    // than erroring on Amsterdam+. A canonical Amsterdam header always carries
    // a slot — `validate_prague_header_fields` rejects one that doesn't, the
    // genesis builder fills in Some(0), and engine_newPayloadV5 requires the
    // field — so this branch is not reachable on a well-formed chain. It is
    // defense in depth, and it belongs on the execution side (where a missing
    // slot would be a consensus fault) rather than in simulation, whose job is
    // to predict what execution does: a header the executor would happily run
    // with SLOTNUM reading 0 must not make eth_call fail. That divergence is
    // reachable if a devnet's fork timestamps are moved so that Amsterdam
    // retroactively covers already-stored pre-Amsterdam headers.
    // For L2 chains, slot_number is always 0.
    let slot_number = if let VMType::L2(_) = vm_type {
        U256::zero()
    } else {
        header.slot_number.map(U256::from).unwrap_or(U256::zero())
    };

    Ok(Environment {
        origin: tx.from.0.into(),
        gas_limit: tx
            .gas
            .unwrap_or(get_max_allowed_gas_limit(header.gas_limit, config.fork)), // Ensure tx doesn't fail due to gas limit
        config,
        block_number: header.number,
        coinbase: header.coinbase,
        timestamp: header.timestamp,
        prev_randao: Some(header.prev_randao),
        slot_number,
        chain_id: chain_config.chain_id.into(),
        base_fee_per_gas: header.base_fee_per_gas.unwrap_or_default().into(),
        base_blob_fee_per_gas: get_base_fee_per_blob_gas(block_excess_blob_gas, &config)?,
        gas_price,
        block_excess_blob_gas,
        block_blob_gas_used: header.blob_gas_used,
        tx_blob_hashes: tx.blob_versioned_hashes.clone(),
        tx_max_priority_fee_per_gas: tx.max_priority_fee_per_gas.map(U256::from),
        tx_max_fee_per_gas: tx.max_fee_per_gas.map(U256::from),
        tx_max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
        tx_nonce: tx.nonce.unwrap_or_default(),
        block_gas_limit: header.gas_limit,
        difficulty: header.difficulty,
        is_privileged: false,
        fee_token: tx.fee_token,
        disable_balance_check: false,
        // Every `env_from_generic` caller is a simulation RPC (eth_call,
        // eth_estimateGas, eth_createAccessList, debug_traceCall). Those run
        // relaxed messages with no nonce enforcement: a call object without
        // `nonce` defaults `tx_nonce` to 0 above, which the hook would otherwise
        // reject for any sender whose nonce is nonzero.
        disable_nonce_check: true,
        // Same reasoning: a caller passing a `gas` above the block allowance or above the
        // EIP-7825 per-transaction cap still expects an answer, because nothing is being
        // submitted. `eth_createAccessList` enforced both until now, which rejected call
        // objects that the other simulation RPCs answered, and which tools that pass the
        // block gas limit as `gas` hit routinely.
        disable_gas_allowance_check: true,
        // Same reasoning: a simulated call carries no signature, so EIP-3607 has nothing
        // to protect, and a contract as `from` is a normal thing to simulate.
        disable_sender_eoa_check: true,
        // The eth_call family emits no traceTransfers logs; that relaxation exists for
        // `eth_simulateV1`, which builds its environment through `setup_env` and opts
        // in there.
        trace_eth_transfers: false,
        is_system_call: false,
    })
}

/// Build a synthetic `Transaction` from a `GenericTransaction` for simulation paths.
///
/// Split out from `vm_from_generic` so the caller owns the resulting `Transaction` for at least
/// the VM's lifetime — `VM` now borrows its tx (`&'a Transaction`) instead of cloning it.
///
/// The envelope fields are carried over even though execution reads almost none of them,
/// because the L2 prices its L1 data fee from `Transaction::length()` — the RLP-encoded byte
/// count — and reserves that as gas before execution. Leaving them at their defaults made a
/// simulated transaction encode up to ~104 bytes shorter than the signed one it stands for
/// (a zero `U256` is one RLP byte, a real signature component is 33), so `eth_estimateGas`
/// under-reserved the L1 fee and the transaction it was estimating ran out of gas. The
/// signature is stamped at full width for the same reason, and deliberately at the maximum:
/// a real component can be shorter after leading-zero trimming, and over-reserving the L1
/// fee is safe where under-reserving is not.
fn generic_tx_to_transaction(tx: &GenericTransaction) -> Result<Transaction, VMError> {
    // Not read during execution — the sender comes from `env.origin` — so this only has to
    // encode to the same width as a real signature.
    let (signature_r, signature_s) = (U256::MAX, U256::MAX);
    let nonce = tx.nonce.unwrap_or_default();
    let gas_limit = tx.gas.unwrap_or_default();
    let max_fee_per_gas = tx.max_fee_per_gas.unwrap_or_default();
    let max_priority_fee_per_gas = tx.max_priority_fee_per_gas.unwrap_or_default();
    let chain_id = tx.chain_id.unwrap_or_default();

    Ok(match &tx.authorization_list {
        Some(authorization_list) => Transaction::EIP7702Transaction(EIP7702Transaction {
            to: match tx.to {
                TxKind::Call(to) => to,
                TxKind::Create => {
                    return Err(InternalError::msg("Generic Tx cannot be create type").into());
                }
            },
            value: tx.value,
            data: tx.input.clone(),
            access_list: tx
                .access_list
                .iter()
                .map(|list| (list.address, list.storage_keys.clone()))
                .collect(),
            authorization_list: authorization_list
                .iter()
                .map(|auth| Into::<AuthorizationTuple>::into(auth.clone()))
                .collect(),
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            chain_id,
            signature_r,
            signature_s,
            ..Default::default()
        }),
        None => Transaction::EIP1559Transaction(EIP1559Transaction {
            to: tx.to.clone(),
            value: tx.value,
            data: tx.input.clone(),
            access_list: tx
                .access_list
                .iter()
                .map(|list| (list.address, list.storage_keys.clone()))
                .collect(),
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            chain_id,
            signature_r,
            signature_s,
            ..Default::default()
        }),
    })
}

fn vm_from_generic<'a>(
    tx: &'a Transaction,
    env: Environment,
    db: &'a mut GeneralizedDatabase,
    vm_type: VMType,
    crypto: &'a dyn Crypto,
    stateless_validator: Option<&'a dyn StatelessValidator>,
) -> Result<VM<'a>, VMError> {
    let vm_type = adjust_disabled_l2_fees(&env, vm_type);
    VM::new(
        env,
        db,
        tx,
        LevmCallTracer::disabled(),
        vm_type,
        crypto,
        stateless_validator,
    )
}

pub fn get_max_allowed_gas_limit(block_gas_limit: u64, fork: Fork) -> u64 {
    // EIP-7825 imposes a flat per-tx gas cap (POST_OSAKA_GAS_LIMIT_CAP) from
    // Osaka through the BPO forks. Amsterdam supersedes it with the EIP-8037 2D
    // gas model: tx.gas may exceed the flat cap (the excess funds the state-gas
    // reservoir) and is instead bounded by block_gas_limit on the state
    // dimension, so capping the estimateGas ceiling at the flat value would
    // prevent convergence for state-heavy creations. Mirror the Osaka-only
    // gating used at the other cap sites (block validation, default_hook).
    if fork >= Fork::Osaka && fork < Fork::Amsterdam {
        POST_OSAKA_GAS_LIMIT_CAP
    } else {
        block_gas_limit
    }
}

/// Format a balance diff (signed wei) and try to identify it as a multiple of
/// well-known EIP-8037 state-gas constants (NEW_ACCOUNT, STORAGE_SET, AUTH_*),
/// scaled by a plausible gas_price. Best-effort hint to triage gas-accounting
/// drifts at a glance.
///
/// `dead_code` allowed: only reached via the L1 BAL-validation path, which is
/// not exercised in the L2 build profile so the per-crate analysis flags it.
#[allow(dead_code)]
fn describe_balance_diff(expected: U256, actual: U256) -> String {
    let (sign, mag) = if expected >= actual {
        ("+", expected - actual)
    } else {
        ("-", actual - expected)
    };
    let Ok(mag_u128) = u128::try_from(mag) else {
        return format!("{sign}{mag}");
    };
    if mag_u128 == 0 {
        return "0".to_string();
    }
    let cpsb: u128 = 1530;
    // EIP-8037 state-byte constants
    let consts = [
        ("NEW_ACCOUNT", 120u128),
        ("STORAGE_SET", 64),
        ("AUTH_BASE", 23),
        ("AUTH_TOTAL", 143),
    ];
    // Try common test gas_prices first, then 1 wei/gas as fallback.
    for &gp in &[10u128, 1, 7, 100, 1000, 1_000_000_000] {
        if !mag_u128.is_multiple_of(gp) {
            continue;
        }
        let gas = mag_u128 / gp;
        if !gas.is_multiple_of(cpsb) {
            continue;
        }
        let bytes = gas / cpsb;
        for (name, c) in consts {
            if bytes.is_multiple_of(c) {
                let n = bytes / c;
                return format!(
                    "{sign}{mag_u128} wei (= {gas} gas at {gp} wei/gas = {n}× {name}_state_gas)"
                );
            }
        }
    }
    format!("{sign}{mag_u128} wei")
}

// Exercises the rayon-parallel-BAL execution path (and shares its
// `rayon`-gated imports), so it only builds when that feature is on.
#[cfg(all(test, feature = "rayon"))]
mod bal_tests {
    use super::*;
    use ethrex_common::H256;
    use ethrex_common::types::AccountState;
    use ethrex_common::types::block_access_list::{
        AccountChanges, BalanceChange, NonceChange, SlotChange, StorageChange,
    };
    use ethrex_levm::errors::DatabaseError;

    fn addr(byte: u8) -> Address {
        let mut a = Address::zero();
        a.0[19] = byte;
        a
    }

    /// Minimal in-memory store for testing bal_to_account_updates.
    struct MockStore {
        accounts: FxHashMap<Address, AccountState>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                accounts: FxHashMap::default(),
            }
        }

        fn with_account(mut self, address: Address, state: AccountState) -> Self {
            self.accounts.insert(address, state);
            self
        }
    }

    impl Database for MockStore {
        fn get_account_state(&self, address: Address) -> Result<AccountState, DatabaseError> {
            Ok(self.accounts.get(&address).copied().unwrap_or_default())
        }
        fn get_storage_value(&self, _: Address, _: H256) -> Result<U256, DatabaseError> {
            Ok(U256::zero())
        }
        fn get_block_hash(&self, _: u64) -> Result<H256, DatabaseError> {
            Ok(H256::zero())
        }
        fn get_chain_config(&self) -> Result<ethrex_common::types::ChainConfig, DatabaseError> {
            Err(DatabaseError::Custom("not implemented".into()))
        }
        fn get_account_code(&self, _: H256) -> Result<ethrex_common::types::Code, DatabaseError> {
            Ok(ethrex_common::types::Code::from_bytecode(
                Bytes::new(),
                &ethrex_crypto::NativeCrypto,
            ))
        }
        fn get_code_metadata(
            &self,
            _: H256,
        ) -> Result<ethrex_common::types::CodeMetadata, DatabaseError> {
            Ok(ethrex_common::types::CodeMetadata { length: 0 })
        }
    }

    #[test]
    fn test_bal_to_account_updates_basic() {
        // Account with balance + nonce + storage changes → correct AccountUpdate
        let address = addr(1);
        let store = MockStore::new().with_account(
            address,
            AccountState {
                balance: U256::from(100),
                nonce: 5,
                code_hash: *EMPTY_KECCAK_HASH,
                storage_root: H256::zero(),
            },
        );

        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(address)
                .with_balance_changes(vec![
                    BalanceChange::new(1, U256::from(90)),
                    BalanceChange::new(2, U256::from(80)),
                ])
                .with_nonce_changes(vec![NonceChange::new(1, 6)])
                .with_storage_changes(vec![SlotChange::with_changes(
                    U256::from(42),
                    vec![StorageChange::new(1, U256::from(999))],
                )]),
        ]);

        let updates = LEVM::bal_to_account_updates(&bal, &store).unwrap();
        assert_eq!(updates.len(), 1);
        let u = &updates[0];
        assert_eq!(u.address, address);
        assert!(!u.removed);
        let info = u.info.as_ref().unwrap();
        // Last balance entry wins
        assert_eq!(info.balance, U256::from(80));
        assert_eq!(info.nonce, 6);
        assert_eq!(info.code_hash, *EMPTY_KECCAK_HASH);
        // Storage
        let key = ethrex_common::utils::u256_to_h256(U256::from(42));
        assert_eq!(*u.added_storage.get(&key).unwrap(), U256::from(999));
    }

    #[test]
    fn test_bal_to_account_updates_highest_index_wins() {
        // Multiple changes per field: the last entry (highest index) wins.
        let address = addr(2);
        let store = MockStore::new().with_account(
            address,
            AccountState {
                balance: U256::from(1000),
                nonce: 0,
                code_hash: *EMPTY_KECCAK_HASH,
                storage_root: H256::zero(),
            },
        );

        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(address).with_balance_changes(vec![
                BalanceChange::new(1, U256::from(900)),
                BalanceChange::new(2, U256::from(800)),
                BalanceChange::new(3, U256::from(700)),
            ]),
        ]);

        let updates = LEVM::bal_to_account_updates(&bal, &store).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].info.as_ref().unwrap().balance, U256::from(700));
    }

    #[test]
    fn test_bal_to_account_updates_reads_only_skipped() {
        // Account with only storage_reads and no writes → no AccountUpdate.
        let address = addr(3);
        let store = MockStore::new();

        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(address).with_storage_reads(vec![U256::from(1)]),
        ]);

        let updates = LEVM::bal_to_account_updates(&bal, &store).unwrap();
        assert!(updates.is_empty());
    }

    #[test]
    fn test_bal_to_account_updates_removal() {
        // Account removal (EIP-161): post-state empty but pre-state existed.
        let address = addr(4);
        let store = MockStore::new().with_account(
            address,
            AccountState {
                balance: U256::from(50),
                nonce: 1,
                code_hash: *EMPTY_KECCAK_HASH,
                storage_root: H256::zero(),
            },
        );

        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(address)
                .with_balance_changes(vec![BalanceChange::new(1, U256::zero())])
                .with_nonce_changes(vec![NonceChange::new(1, 0)]),
        ]);

        let updates = LEVM::bal_to_account_updates(&bal, &store).unwrap();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].removed);
    }

    #[test]
    fn test_bal_to_account_updates_storage_zero() {
        // Storage slot set to 0 → included in added_storage (valid trie deletion).
        let address = addr(5);
        let store = MockStore::new();

        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(address).with_storage_changes(vec![SlotChange::with_changes(
                U256::from(7),
                vec![StorageChange::new(1, U256::zero())],
            )]),
        ]);

        let updates = LEVM::bal_to_account_updates(&bal, &store).unwrap();
        assert_eq!(updates.len(), 1);
        let key = ethrex_common::utils::u256_to_h256(U256::from(7));
        assert_eq!(*updates[0].added_storage.get(&key).unwrap(), U256::zero());
    }

    #[test]
    fn test_bal_to_account_updates_code_deployment() {
        // Code deployment → correct code_hash computed.
        let address = addr(6);
        let store = MockStore::new();
        let code = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xf3]); // PUSH0 PUSH0 RETURN
        let expected_hash =
            ethrex_common::types::Code::from_bytecode(code.clone(), &ethrex_crypto::NativeCrypto)
                .hash;

        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(address)
                .with_code_changes(vec![
                    ethrex_common::types::block_access_list::CodeChange::new(1, code.clone()),
                ])
                .with_nonce_changes(vec![NonceChange::new(1, 1)]),
        ]);

        let updates = LEVM::bal_to_account_updates(&bal, &store).unwrap();
        assert_eq!(updates.len(), 1);
        let u = &updates[0];
        assert_eq!(u.info.as_ref().unwrap().code_hash, expected_hash);
        assert_eq!(u.code.as_ref().unwrap().code(), &code[..]);
    }
}

#[cfg(test)]
mod system_call_coinbase_tests {
    //! Regression tests for the system-call coinbase collision. When a block's
    //! fee recipient (coinbase) equals the system contract being called,
    //! `generic_system_contract_levm`'s post-call coinbase restore must NOT clobber
    //! the storage write the system call just made; otherwise the write is dropped
    //! from the emitted state updates and the state root diverges from other clients.
    use super::*;
    use ethrex_common::types::{AccountState, AccountUpdate, ChainConfig, Code, CodeMetadata};
    use ethrex_crypto::NativeCrypto;
    use ethrex_levm::db::Database;
    use ethrex_levm::errors::DatabaseError;
    use std::sync::Arc;

    // EIP-2935 history-contract runtime bytecode.
    const HISTORY_RUNTIME_CODE: &str = concat!(
        "3373fffffffffffffffffffffffffffffffffffffffe1460465760203603604257",
        "5f35600143038111604257611fff81430311604257611fff900654",
        "5f5260205ff35b5f5ffd5b5f35611fff60014303065500",
    );

    struct Store {
        chain_config: ChainConfig,
        history_code: Code,
    }

    impl Database for Store {
        fn get_account_state(&self, address: Address) -> Result<AccountState, DatabaseError> {
            if address == HISTORY_STORAGE_ADDRESS.address {
                return Ok(AccountState {
                    nonce: 1,
                    code_hash: self.history_code.hash,
                    ..Default::default()
                });
            }
            Ok(AccountState::default())
        }
        fn get_storage_value(&self, _: Address, _: H256) -> Result<U256, DatabaseError> {
            Ok(U256::zero())
        }
        fn get_block_hash(&self, _: u64) -> Result<H256, DatabaseError> {
            Ok(H256::zero())
        }
        fn get_chain_config(&self) -> Result<ChainConfig, DatabaseError> {
            Ok(self.chain_config)
        }
        fn get_account_code(&self, code_hash: H256) -> Result<Code, DatabaseError> {
            if code_hash == self.history_code.hash {
                return Ok(self.history_code.clone());
            }
            Ok(Code::default())
        }
        fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, DatabaseError> {
            let length = if code_hash == self.history_code.hash {
                self.history_code.len() as u64
            } else {
                0
            };
            Ok(CodeMetadata { length })
        }
    }

    fn history_code() -> Code {
        let bytes = hex::decode(HISTORY_RUNTIME_CODE).expect("history runtime code is valid hex");
        Code::from_bytecode(Bytes::from(bytes), &NativeCrypto)
    }

    fn prague_db() -> GeneralizedDatabase {
        GeneralizedDatabase::new(Arc::new(Store {
            chain_config: ChainConfig {
                prague_time: Some(0),
                ..Default::default()
            },
            history_code: history_code(),
        }))
    }

    fn parent_hash_value(parent_hash: H256) -> U256 {
        U256::from_big_endian(parent_hash.as_bytes())
    }

    fn history_slot(block_number: u64) -> H256 {
        H256::from_low_u64_be((block_number - 1) % 8191)
    }

    /// Run the EIP-2935 system call for block 42 with the given fee recipient and
    /// return (slot value cached on the history contract, emitted state updates,
    /// parent hash).
    fn run_history_update(coinbase: Address) -> (Option<U256>, Vec<AccountUpdate>, H256) {
        let mut db = prague_db();
        let parent_hash = H256::from_low_u64_be(0x2935);
        let block_number = 42;
        let header = BlockHeader {
            parent_hash,
            coinbase,
            number: block_number,
            timestamp: 1,
            ..Default::default()
        };

        LEVM::process_block_hash_history(&header, &mut db, VMType::L1, &NativeCrypto)
            .expect("history system call executes");

        let slot = history_slot(block_number);
        let stored_value = db
            .current_accounts_state
            .get(&HISTORY_STORAGE_ADDRESS.address)
            .and_then(|account| account.storage.get(&slot).copied());
        let updates =
            LEVM::get_state_transitions(&mut db).expect("state transitions are generated");

        (stored_value, updates, parent_hash)
    }

    fn assert_history_write_emitted(coinbase: Address) {
        let (stored_value, updates, parent_hash) = run_history_update(coinbase);
        let slot = history_slot(42);
        assert_eq!(
            stored_value,
            Some(parent_hash_value(parent_hash)),
            "history storage must hold the parent hash after the system call"
        );
        assert!(
            updates.iter().any(|update| {
                update.address == HISTORY_STORAGE_ADDRESS.address
                    && update.added_storage.get(&slot) == Some(&parent_hash_value(parent_hash))
            }),
            "the history-contract storage write must be emitted as a state update"
        );
    }

    #[test]
    fn ordinary_coinbase_preserves_history_storage_write() {
        assert_history_write_emitted(Address::from_low_u64_be(0xbeef));
    }

    /// Regression: a fee recipient equal to the EIP-2935 history contract must not
    /// cause the system call's storage write to be dropped by the coinbase restore.
    #[test]
    fn history_address_coinbase_preserves_history_storage_write() {
        assert_history_write_emitted(HISTORY_STORAGE_ADDRESS.address);
    }
}

/// Tests for EIP-8079 burned_fees computation in execute_block (LStar-gated).
///
/// Shares the non-guest execution path's `rayon`-gated imports
/// (`EMPTY_KECCAK_HASH`, `FxHashMap`, `Database`), so it only builds with rayon.
#[cfg(all(test, feature = "rayon"))]
mod burned_fees_tests {
    use super::*;
    use ethrex_common::{
        constants::{DEFAULT_OMMERS_HASH, DEFAULT_REQUESTS_HASH},
        types::{AccountState, Block, BlockBody, BlockHeader, ChainConfig, Code, CodeMetadata},
        utils::keccak,
    };
    use ethrex_crypto::NativeCrypto;
    use ethrex_levm::errors::DatabaseError;
    use ethrex_rlp::encode::PayloadRLPEncode;

    // ── helpers ─────────────────────────────────────────────────────────────

    fn lstar_chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            homestead_block: Some(0),
            eip150_block: Some(0),
            eip155_block: Some(0),
            eip158_block: Some(0),
            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            berlin_block: Some(0),
            london_block: Some(0),
            terminal_total_difficulty: Some(0),
            terminal_total_difficulty_passed: true,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            amsterdam_time: Some(0),
            lstar_time: Some(0),
            ..Default::default()
        }
    }

    fn amsterdam_chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            homestead_block: Some(0),
            eip150_block: Some(0),
            eip155_block: Some(0),
            eip158_block: Some(0),
            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            berlin_block: Some(0),
            london_block: Some(0),
            terminal_total_difficulty: Some(0),
            terminal_total_difficulty_passed: true,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            amsterdam_time: Some(0),
            lstar_time: None, // no LStar → burned_fees must be None
            ..Default::default()
        }
    }

    // ── mock database ────────────────────────────────────────────────────────

    struct MockDB {
        chain_config: ChainConfig,
        accounts: FxHashMap<Address, (AccountState, Bytes)>,
        /// Pre-set storage values (address, slot) → value.
        storage: FxHashMap<(Address, H256), U256>,
    }

    impl MockDB {
        fn new(chain_config: ChainConfig) -> Self {
            Self {
                chain_config,
                accounts: FxHashMap::default(),
                storage: FxHashMap::default(),
            }
        }

        fn with_account(mut self, address: Address, balance: U256, code: Option<Bytes>) -> Self {
            let code_bytes = code.unwrap_or_default();
            let code_hash = if code_bytes.is_empty() {
                *EMPTY_KECCAK_HASH
            } else {
                keccak(&code_bytes)
            };
            let state = AccountState {
                nonce: 0,
                balance,
                storage_root: H256::zero(),
                code_hash,
            };
            self.accounts.insert(address, (state, code_bytes));
            self
        }

        fn with_storage(mut self, address: Address, slot: H256, value: U256) -> Self {
            self.storage.insert((address, slot), value);
            self
        }
    }

    impl Database for MockDB {
        fn get_account_state(&self, address: Address) -> Result<AccountState, DatabaseError> {
            Ok(self
                .accounts
                .get(&address)
                .map(|(s, _)| *s)
                .unwrap_or_default())
        }

        fn get_storage_value(&self, address: Address, slot: H256) -> Result<U256, DatabaseError> {
            Ok(self
                .storage
                .get(&(address, slot))
                .copied()
                .unwrap_or_default())
        }

        fn get_block_hash(&self, _: u64) -> Result<H256, DatabaseError> {
            Ok(H256::zero())
        }

        fn get_chain_config(&self) -> Result<ChainConfig, DatabaseError> {
            Ok(self.chain_config)
        }

        fn get_account_code(&self, code_hash: H256) -> Result<Code, DatabaseError> {
            let crypto = NativeCrypto;
            for (state, bytecode) in self.accounts.values() {
                if state.code_hash == code_hash && !bytecode.is_empty() {
                    return Ok(Code::from_bytecode(bytecode.clone(), &crypto));
                }
            }
            Ok(Code::from_bytecode(Bytes::new(), &crypto))
        }

        fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, DatabaseError> {
            for (state, bytecode) in self.accounts.values() {
                if state.code_hash == code_hash {
                    return Ok(CodeMetadata {
                        length: bytecode.len() as u64,
                    });
                }
            }
            Ok(CodeMetadata { length: 0 })
        }
    }

    // ── signing ──────────────────────────────────────────────────────────────

    const PRIVATE_KEY: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];

    fn sender_address() -> Address {
        use k256::ecdsa::SigningKey;
        let signing_key = SigningKey::from_bytes(&PRIVATE_KEY.into()).expect("valid key");
        let uncompressed_pub = signing_key.verifying_key().to_encoded_point(false);
        let pub_hash = keccak(&uncompressed_pub.as_bytes()[1..]);
        Address::from_slice(&pub_hash.0[12..])
    }

    /// Build a signed EIP-1559 ETH transfer.
    /// base_fee = BASE_FEE, gas_limit = 21_000 → gas_spent = 21_000 (no refunds).
    fn signed_eth_transfer(to: Address, nonce: u64, base_fee: u64) -> Transaction {
        use k256::ecdsa::SigningKey;

        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: base_fee + 10,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: U256::zero(),
            ..Default::default()
        };

        // Signing hash: [0x02] || RLP(chain_id, nonce, max_priority, max_fee, gas, to, value, data, access_list)
        let mut buf = vec![0x02u8];
        tx.encode_payload(&mut buf);
        let hash = keccak(&buf);

        let signing_key = SigningKey::from_bytes(&PRIVATE_KEY.into()).expect("valid key");
        let (sig, rid) = signing_key
            .sign_prehash_recoverable(&hash.0)
            .expect("sign ok");
        let sig_bytes = sig.to_bytes();

        Transaction::EIP1559Transaction(EIP1559Transaction {
            signature_r: U256::from_big_endian(&sig_bytes[..32]),
            signature_s: U256::from_big_endian(&sig_bytes[32..]),
            signature_y_parity: rid.to_byte() != 0,
            ..tx
        })
    }

    // STOP opcode: system contracts need non-empty code (EIP-7002/7251 check).
    const STOP_BYTECODE: &[u8] = &[0x00];

    fn make_block_with_tx(tx: Transaction, base_fee: u64) -> Block {
        let header = BlockHeader {
            parent_hash: H256::zero(),
            ommers_hash: *DEFAULT_OMMERS_HASH,
            number: 1,
            gas_limit: 1_000_000,
            timestamp: 1,
            base_fee_per_gas: Some(base_fee),
            withdrawals_root: Some(H256::zero()),
            requests_hash: Some(*DEFAULT_REQUESTS_HASH),
            // No parent_beacon_block_root → skip beacon-root system call.
            parent_beacon_block_root: None,
            ..Default::default()
        };
        let body = BlockBody {
            transactions: vec![tx],
            ommers: vec![],
            withdrawals: Some(vec![]),
        };
        Block::new(header, body)
    }

    fn make_gen_db(chain_config: ChainConfig) -> GeneralizedDatabase {
        let sender = sender_address();
        let stop = Bytes::from_static(STOP_BYTECODE);
        let mock = MockDB::new(chain_config)
            // Fund the sender with enough ETH to pay for gas + priority fee.
            .with_account(sender, U256::from(1_000_000_000u64), None)
            // Prague system contracts require non-empty code (EIP-7002/7251).
            .with_account(
                WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address,
                U256::zero(),
                Some(stop.clone()),
            )
            .with_account(
                CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS.address,
                U256::zero(),
                Some(stop.clone()),
            )
            // EIP-8282 (Amsterdam) builder predeploys require non-empty code.
            .with_account(
                BUILDER_DEPOSIT_CONTRACT_ADDRESS.address,
                U256::zero(),
                Some(stop.clone()),
            )
            .with_account(
                BUILDER_EXIT_CONTRACT_ADDRESS.address,
                U256::zero(),
                Some(stop),
            );
        GeneralizedDatabase::new(Arc::new(mock))
    }

    // Contract bytecode: PUSH1 0x00, PUSH1 0x00, SSTORE, STOP
    // Clears storage slot 0.  When the slot's initial value is non-zero, the
    // EIP-3529 "SSTORE_CLEARS_SCHEDULE" refund of 4800 gas is applied, making
    // gas_used > gas_spent so block_gas_used ≠ cumulative_gas_used.
    const SSTORE_CLEAR_BYTECODE: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0x55, 0x00];

    /// Build a signed EIP-1559 call to `to` with an explicit gas limit.
    fn signed_call_tx(to: Address, nonce: u64, base_fee: u64, gas_limit: u64) -> Transaction {
        use k256::ecdsa::SigningKey;

        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: base_fee + 10,
            gas_limit,
            to: TxKind::Call(to),
            value: U256::zero(),
            ..Default::default()
        };

        let mut buf = vec![0x02u8];
        tx.encode_payload(&mut buf);
        let hash = keccak(&buf);

        let signing_key = SigningKey::from_bytes(&PRIVATE_KEY.into()).expect("valid key");
        let (sig, rid) = signing_key
            .sign_prehash_recoverable(&hash.0)
            .expect("sign ok");
        let sig_bytes = sig.to_bytes();

        Transaction::EIP1559Transaction(EIP1559Transaction {
            signature_r: U256::from_big_endian(&sig_bytes[..32]),
            signature_s: U256::from_big_endian(&sig_bytes[32..]),
            signature_y_parity: rid.to_byte() != 0,
            ..tx
        })
    }

    /// DB with SSTORE_CLEAR_BYTECODE deployed at `contract_addr` and slot 0 = 1.
    /// The sender has extra ETH to cover the higher gas_limit in the call tx.
    fn make_gen_db_sstore_clear(
        chain_config: ChainConfig,
        contract_addr: Address,
    ) -> GeneralizedDatabase {
        let sender = sender_address();
        let stop = Bytes::from_static(STOP_BYTECODE);
        let mock = MockDB::new(chain_config)
            .with_account(sender, U256::from(100_000_000_000u64), None)
            .with_account(
                WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address,
                U256::zero(),
                Some(stop.clone()),
            )
            .with_account(
                CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS.address,
                U256::zero(),
                Some(stop.clone()),
            )
            // EIP-8282 (Amsterdam) builder predeploys require non-empty code.
            .with_account(
                BUILDER_DEPOSIT_CONTRACT_ADDRESS.address,
                U256::zero(),
                Some(stop.clone()),
            )
            .with_account(
                BUILDER_EXIT_CONTRACT_ADDRESS.address,
                U256::zero(),
                Some(stop),
            )
            .with_account(
                contract_addr,
                U256::zero(),
                Some(Bytes::from_static(SSTORE_CLEAR_BYTECODE)),
            )
            // Slot 0 = 1 so SSTORE(0, 0) transitions 1→0, triggering EIP-3529 refund.
            .with_storage(contract_addr, H256::zero(), U256::one());
        GeneralizedDatabase::new(Arc::new(mock))
    }

    // ── tests ────────────────────────────────────────────────────────────────

    #[test]
    fn test_burned_fees_block_aggregate() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::mpsc;

        const BASE_FEE: u64 = 10;
        // Simple ETH transfer, no blobs (blob_gas_used = 0, blob_base_fee = 0).
        // The exact gas charged depends on the active fork's gas model, so this test
        // verifies the burned_fees FORMULA against the block's actual post-refund gas
        // (rather than a hardcoded amount) plus the execute_block ↔ execute_block_pipeline
        // cross-path consistency and the LStar gate. The refund-sensitive case lives in
        // test_burned_fees_post_refund_discriminating.

        let recipient = Address::from_low_u64_be(0xBEEF);
        let tx = signed_eth_transfer(recipient, 0, BASE_FEE);
        let block = make_block_with_tx(tx, BASE_FEE);
        let crypto = NativeCrypto;

        // (a) execute_block path
        let mut db1 = make_gen_db(lstar_chain_config());
        let (result, _bal) = LEVM::execute_block(&block, &mut db1, VMType::L1, &crypto, None)
            .expect("execute_block succeeded");
        let cumulative = result
            .receipts
            .last()
            .map(|r| r.cumulative_gas_used)
            .unwrap_or(0);
        let expected = compute_burned_fees(BASE_FEE, cumulative, 0, 0);
        assert_eq!(
            result.burned_fees,
            Some(expected),
            "execute_block: burned_fees must equal base_fee * post-refund gas ({cumulative})"
        );

        // (b) execute_block_pipeline path (sequential: no BAL provided)
        let mut db2 = make_gen_db(lstar_chain_config());
        let (tx_sender, _rx) = mpsc::channel();
        let queue_len = AtomicUsize::new(0);
        let tx2 = signed_eth_transfer(recipient, 0, BASE_FEE);
        let block2 = make_block_with_tx(tx2, BASE_FEE);
        let (result_pipeline, _bal) = LEVM::execute_block_pipeline(
            &block2,
            &mut db2,
            VMType::L1,
            Some(tx_sender),
            &queue_len,
            &crypto,
            None, // no BAL → sequential path
            false,
            None,
        )
        .expect("execute_block_pipeline succeeded");
        assert_eq!(
            result_pipeline.burned_fees, result.burned_fees,
            "execute_block_pipeline: burned_fees must match execute_block (production/verification consistency)"
        );

        // (c) pre-LStar → None
        let tx3 = signed_eth_transfer(recipient, 0, BASE_FEE);
        let block3 = make_block_with_tx(tx3, BASE_FEE);
        let mut db3 = make_gen_db(amsterdam_chain_config());
        let (result_pre_lstar, _) =
            LEVM::execute_block(&block3, &mut db3, VMType::L1, &crypto, None)
                .expect("pre-LStar execute_block succeeded");
        assert_eq!(
            result_pre_lstar.burned_fees, None,
            "pre-LStar: burned_fees must be None"
        );
    }

    /// Discriminating test: a transaction with an EIP-3529 SSTORE refund makes
    /// `block_gas_used` (pre-refund) differ from `cumulative_gas_used` (post-refund).
    /// The correct `burned_fees` uses post-refund gas; using `block_gas_used` would
    /// over-count by `base_fee * refund_amount`.
    ///
    /// Gas analysis (Prague + Amsterdam era):
    ///   intrinsic = 21 000
    ///   PUSH1 + PUSH1 = 6
    ///   SSTORE cold (original=1, new=0): cold-access 2100 + warm-reset 2900 = 5 000
    ///     refund = SSTORE_CLEARS_SCHEDULE = 4 800 (≤ 26 006 / 5 = 5 201, so full refund)
    ///   gas_used = 26 006, gas_spent = 21 206
    ///
    /// With the wrong code (block_gas_used = 26 006):
    ///   burned_fees = 10 * 26 006 = 260 060  ← test FAILS
    /// After the fix (cumulative_gas_used = 21 206):
    ///   burned_fees = 10 * 21 206 = 212 060  ← test PASSES
    #[test]
    fn test_burned_fees_post_refund_discriminating() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::mpsc;

        const BASE_FEE: u64 = 10;
        // Gas limit must exceed gas_used (26 006); 100 000 is ample.
        const TX_GAS_LIMIT: u64 = 100_000;

        let contract_addr = Address::from_low_u64_be(0xC0DEBEEF);
        let crypto = NativeCrypto;

        // ── (a) execute_block path (site 1) ───────────────────────────────────
        let tx_a = signed_call_tx(contract_addr, 0, BASE_FEE, TX_GAS_LIMIT);
        let block_a = make_block_with_tx(tx_a, BASE_FEE);
        let mut db_a = make_gen_db_sstore_clear(lstar_chain_config(), contract_addr);
        let (result_a, _) = LEVM::execute_block(&block_a, &mut db_a, VMType::L1, &crypto, None)
            .expect("execute_block with SSTORE clear succeeded");

        let cumulative_a = result_a.receipts[0].cumulative_gas_used;
        // Discriminating guard: the refund must have happened.
        assert!(
            result_a.block_gas_used > cumulative_a,
            "SSTORE refund must cause block_gas_used ({}) > cumulative_gas_used ({})",
            result_a.block_gas_used,
            cumulative_a,
        );
        // Correct burned_fees uses post-refund cumulative_gas_used, not block_gas_used.
        assert_eq!(
            result_a.burned_fees,
            Some(BASE_FEE * cumulative_a),
            "execute_block: burned_fees must use post-refund gas (cumulative={}, block_gas_used={})",
            cumulative_a,
            result_a.block_gas_used,
        );

        // ── (b) execute_block_pipeline sequential path (site 3, no BAL) ──────
        let tx_b = signed_call_tx(contract_addr, 0, BASE_FEE, TX_GAS_LIMIT);
        let block_b = make_block_with_tx(tx_b, BASE_FEE);
        let mut db_b = make_gen_db_sstore_clear(lstar_chain_config(), contract_addr);
        let (tx_sender_b, _rx_b) = mpsc::channel();
        let queue_len_b = AtomicUsize::new(0);
        let (result_b, _) = LEVM::execute_block_pipeline(
            &block_b,
            &mut db_b,
            VMType::L1,
            Some(tx_sender_b),
            &queue_len_b,
            &crypto,
            None, // no BAL → sequential path (site 3)
            false,
            None,
        )
        .expect("execute_block_pipeline sequential with SSTORE clear succeeded");

        let cumulative_b = result_b.receipts[0].cumulative_gas_used;
        assert!(
            result_b.block_gas_used > cumulative_b,
            "sequential pipeline: SSTORE refund must be present",
        );
        assert_eq!(
            result_b.burned_fees,
            Some(BASE_FEE * cumulative_b),
            "execute_block_pipeline (sequential): burned_fees must use post-refund gas",
        );

        // ── (c) execute_block_pipeline parallel path (site 2, with BAL) ──────
        // Generate BAL via execute_block, then re-execute using that BAL.
        let tx_c = signed_call_tx(contract_addr, 0, BASE_FEE, TX_GAS_LIMIT);
        let block_c = make_block_with_tx(tx_c, BASE_FEE);
        let mut db_c1 = make_gen_db_sstore_clear(lstar_chain_config(), contract_addr);
        let (_, bal_c) = LEVM::execute_block(&block_c, &mut db_c1, VMType::L1, &crypto, None)
            .expect("BAL generation succeeded");
        let bal_c = bal_c.expect("LStar must produce a BAL");

        let mut db_c2 = make_gen_db_sstore_clear(lstar_chain_config(), contract_addr);
        let (tx_sender_c, _rx_c) = mpsc::channel();
        let queue_len_c = AtomicUsize::new(0);
        let (result_c, _) = LEVM::execute_block_pipeline(
            &block_c,
            &mut db_c2,
            VMType::L1,
            Some(tx_sender_c),
            &queue_len_c,
            &crypto,
            Some(std::sync::Arc::new(bal_c)), // ← parallel path (site 2)
            true,
            None,
        )
        .expect("execute_block_pipeline parallel with SSTORE clear succeeded");

        let cumulative_c = result_c.receipts[0].cumulative_gas_used;
        assert!(
            result_c.block_gas_used > cumulative_c,
            "parallel pipeline: SSTORE refund must be present",
        );
        assert_eq!(
            result_c.burned_fees,
            Some(BASE_FEE * cumulative_c),
            "execute_block_pipeline (parallel): burned_fees must use post-refund gas",
        );

        // ── cross-path consistency ─────────────────────────────────────────────
        assert_eq!(
            result_a.burned_fees, result_b.burned_fees,
            "execute_block vs sequential pipeline: burned_fees must match",
        );
        assert_eq!(
            result_a.burned_fees, result_c.burned_fees,
            "execute_block vs parallel pipeline: burned_fees must match",
        );

        // ── (d) pre-LStar → None ──────────────────────────────────────────────
        let tx_d = signed_call_tx(contract_addr, 0, BASE_FEE, TX_GAS_LIMIT);
        let block_d = make_block_with_tx(tx_d, BASE_FEE);
        let mut db_d = make_gen_db_sstore_clear(amsterdam_chain_config(), contract_addr);
        let (result_d, _) = LEVM::execute_block(&block_d, &mut db_d, VMType::L1, &crypto, None)
            .expect("pre-LStar with SSTORE clear succeeded");
        assert_eq!(
            result_d.burned_fees, None,
            "pre-LStar: burned_fees must be None"
        );
    }
}

#[cfg(test)]
mod simulated_tx_encoding_tests {
    //! The L2 prices its L1 data fee from `Transaction::length()` and reserves that
    //! as gas before execution, so a simulated transaction must never encode shorter
    //! than the signed one it stands for — otherwise `eth_estimateGas` reserves less
    //! L1 fee gas than the transaction it is estimating will need, and that
    //! transaction runs out of gas at exactly the estimate.
    //!
    //! This was reached through the L2 fee-token integration test, which submits the
    //! estimate verbatim. It only surfaced once the estimate became exact; the search's
    //! former 1.5% tolerance had been absorbing the shortfall.
    use super::*;
    use ethrex_common::types::GenericTransaction;
    use ethrex_rlp::encode::RLPEncode;

    /// The transaction the SDK signs and sends after estimating, with signature
    /// components at the width secp256k1 actually produces.
    fn signed_equivalent(gas_limit: u64, data: Bytes) -> Transaction {
        Transaction::EIP1559Transaction(EIP1559Transaction {
            chain_id: 9_999,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit,
            to: TxKind::Create,
            value: U256::from(1u64),
            data,
            access_list: vec![],
            signature_y_parity: true,
            signature_r: U256::MAX,
            signature_s: U256::MAX,
            ..Default::default()
        })
    }

    fn generic(gas_limit: u64, data: Bytes) -> GenericTransaction {
        GenericTransaction {
            to: TxKind::Create,
            value: U256::from(1u64),
            input: data,
            nonce: Some(42),
            gas: Some(gas_limit),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            chain_id: Some(9_999),
            ..Default::default()
        }
    }

    #[test]
    fn simulated_tx_never_encodes_shorter_than_the_signed_one() {
        for (gas_limit, data) in [
            (21_000u64, Bytes::new()),
            (150_000, Bytes::from_static(&[0x60, 0x00, 0x60, 0x00])),
            (5_000_000, Bytes::from(vec![0xab; 4_096])),
        ] {
            let simulated = generic_tx_to_transaction(&generic(gas_limit, data.clone()))
                .expect("conversion should succeed");
            let signed = signed_equivalent(gas_limit, data.clone());
            assert!(
                simulated.length() >= signed.length(),
                "simulated tx encodes {} bytes, signed one {} — the L2 would under-reserve \
                 the L1 fee by the difference (gas_limit {gas_limit}, {} data bytes)",
                simulated.length(),
                signed.length(),
                data.len(),
            );
        }
    }
}
