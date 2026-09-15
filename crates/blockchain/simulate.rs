//! `eth_simulateV1` simulation engine.
//!
//! Executes a chain of simulated blocks on top of a base block without
//! committing anything: state chains across blocks through a cumulative
//! [`SimulationOverlay`], per-block state roots are derived by re-applying the
//! cumulative account updates onto the base block's trie, and each simulated
//! block is assembled with real transaction/receipt roots so the response
//! matches `eth_getBlockByHash` output.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use ethrex_common::{
    Address, U256,
    constants::{DEFAULT_OMMERS_HASH, DEFAULT_REQUESTS_HASH, GAS_PER_BLOB},
    types::{
        AccountInfo, AccountUpdate, Block, BlockBody, BlockHeader, ChainConfig, EIP1559Transaction,
        EIP4844Transaction, EIP7702Transaction, ELASTICITY_MULTIPLIER, Fork, GenericTransaction,
        LegacyTransaction, Log, Receipt, Transaction, TxKind, Withdrawal, bloom_from_logs,
        calc_excess_blob_gas, calculate_base_fee_per_gas, compute_receipts_root,
        compute_transactions_root, compute_withdrawals_root, requests::compute_requests_hash,
        tx_fields::AuthorizationTuple,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_vm::{
    SimTxConfig, SimulationTxError, TRACE_TRANSFER_ADDRESS, TxResult, TxValidationError,
    backends::levm::get_max_allowed_gas_limit,
};
use thiserror::Error;

use crate::{
    Blockchain, BlockchainType,
    vm::{
        SimulationOverlay, SimulationVmDatabase, StateOverride, StorageMode, StoreVmDatabase,
        precompile_moves,
    },
};

/// Maximum simulated block height above the base block (geth's
/// `maxSimulateBlocks`). Also the `BLOCKHASH` window, so every simulated block
/// can resolve every other one.
pub const MAX_SIMULATE_BLOCKS: u64 = 256;
/// Cumulative gas allowance across all simulated blocks (geth's `RPCGasCap`
/// default). TODO: wire to a node option once RPC exposes a gas-cap setting.
pub const SIMULATION_GAS_CAP: u64 = 50_000_000;
/// Timestamp increment for blocks without an explicit `time` override.
const SIMULATED_BLOCK_TIME: u64 = 12;

/// One entry of `blockStateCalls`, with overrides already converted to
/// engine-level types by the RPC layer.
#[derive(Clone, Debug, Default)]
pub struct SimulationBlockSpec {
    pub overrides: SimBlockOverrides,
    pub state_overrides: BTreeMap<Address, StateOverride>,
    pub calls: Vec<GenericTransaction>,
}

/// Block overrides for one simulated block. `blobBaseFee` arrives already
/// inverted into `excess_blob_gas` (the RPC layer owns that conversion).
#[derive(Clone, Debug, Default)]
pub struct SimBlockOverrides {
    pub number: Option<u64>,
    pub time: Option<u64>,
    pub gas_limit: Option<u64>,
    pub coinbase: Option<Address>,
    pub prev_randao: Option<ethrex_common::H256>,
    pub base_fee_per_gas: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub difficulty: Option<U256>,
    pub withdrawals: Vec<Withdrawal>,
    /// EIP-4788 parent beacon block root. Honored rather than refused because this
    /// engine runs the block's system calls, so the value is written into the
    /// beacon-roots ring buffer and is observable from a simulated contract.
    pub beacon_root: Option<ethrex_common::H256>,
}

#[derive(Clone, Debug)]
pub struct SimulationRequest {
    /// Resolved base block header (its state must be present in the store).
    pub base: BlockHeader,
    pub blocks: Vec<SimulationBlockSpec>,
    pub validation: bool,
    pub trace_transfers: bool,
}

/// One simulated block plus its per-call results. `calls` and `senders` are
/// index-aligned with `block.body.transactions`.
#[derive(Clone, Debug)]
pub struct SimulatedBlock {
    pub block: Block,
    /// Receipts with trace-transfer logs already filtered out.
    pub receipts: Vec<Receipt>,
    pub calls: Vec<SimulatedCallResult>,
    /// Call senders; tx objects carry zeroed signatures, so the sender cannot
    /// be recovered from them.
    pub senders: Vec<Address>,
}

#[derive(Clone, Debug)]
pub struct SimulatedCallResult {
    pub success: bool,
    /// Empty on revert; revert data travels in [`SimulatedCallError::Revert`].
    pub return_data: Bytes,
    /// Post-refund gas, what the caller pays (`gasUsed` in the response).
    pub gas_used: u64,
    /// Pre-refund gas (`maxUsedGas` in the response). geth (`settleGas`'s
    /// `peakUsed`) and reth both report `max(pre-refund gas, EIP-7623 calldata
    /// floor)` -- the name is misleading, neither tracks an in-flight peak. This
    /// omits the floor term, so it agrees with both unless the floor binds, where
    /// it over-reports by up to the refund. Amsterdam folds the floor into
    /// `gas_used` already; pre-Amsterdam the report carries no pre-refund figure
    /// (`gas_used == gas_spent`), so closing it needs one surfaced.
    pub max_used_gas: u64,
    /// Interleaved execution + trace-transfer logs; empty for failed calls.
    pub logs: Vec<Log>,
    pub error: Option<SimulatedCallError>,
}

#[derive(Clone, Debug)]
pub enum SimulatedCallError {
    /// REVERT opcode: `output` is the ABI-encoded revert data.
    Revert { output: Bytes },
    /// Any other halt (out of gas, invalid opcode, ...).
    Halt { reason: String },
}

#[derive(Debug, Error)]
pub enum SimulationError {
    #[error("too many blocks")]
    TooManyBlocks,
    #[error("block numbers must be in order: {given} <= {prev}")]
    BlockNumberNotAscending { given: u64, prev: u64 },
    #[error("block timestamps must be in order: {given} <= {prev}")]
    TimestampNotAscending { given: u64, prev: u64 },
    #[error("block gas limit reached: {requested} > {remaining}")]
    BlockGasLimitReached { requested: u64, remaining: u64 },
    #[error("invalid transaction: {0}")]
    InvalidTx(TxValidationError),
    #[error("{0}")]
    InvalidParams(String),
    #[error("internal error: {0}")]
    Internal(String),
}

fn internal(err: impl std::fmt::Display) -> SimulationError {
    SimulationError::Internal(err.to_string())
}

/// A block spec with number and timestamp resolved by [`sanitize_blocks`].
#[derive(Debug)]
struct SanitizedBlock {
    spec: SimulationBlockSpec,
    number: u64,
    timestamp: u64,
}

/// Resolve block numbers/timestamps, validate ordering and fill gaps with
/// empty blocks (which are part of the response), mirroring geth's
/// `sanitizeChain`.
fn sanitize_blocks(
    base: &BlockHeader,
    specs: Vec<SimulationBlockSpec>,
) -> Result<Vec<SanitizedBlock>, SimulationError> {
    let mut out = Vec::with_capacity(specs.len());
    let mut prev_number = base.number;
    let mut prev_timestamp = base.timestamp;
    for spec in specs {
        let number = spec.overrides.number.unwrap_or_else(|| prev_number + 1);
        if number <= prev_number {
            return Err(SimulationError::BlockNumberNotAscending {
                given: number,
                prev: prev_number,
            });
        }
        if number - base.number > MAX_SIMULATE_BLOCKS {
            return Err(SimulationError::TooManyBlocks);
        }
        // Fill the gap with empty blocks.
        for gap_number in (prev_number + 1)..number {
            let timestamp = prev_timestamp + SIMULATED_BLOCK_TIME;
            out.push(SanitizedBlock {
                spec: SimulationBlockSpec::default(),
                number: gap_number,
                timestamp,
            });
            prev_timestamp = timestamp;
        }
        let timestamp = match spec.overrides.time {
            Some(time) => {
                if time <= prev_timestamp {
                    return Err(SimulationError::TimestampNotAscending {
                        given: time,
                        prev: prev_timestamp,
                    });
                }
                time
            }
            None => prev_timestamp + SIMULATED_BLOCK_TIME,
        };
        prev_number = number;
        prev_timestamp = timestamp;
        out.push(SanitizedBlock {
            spec,
            number,
            timestamp,
        });
    }
    Ok(out)
}

/// Build a simulated block header from its (possibly simulated) parent.
///
/// Defaults mirror geth's `makeHeaders`/`processBlock`: coinbase, gas limit
/// and difficulty are inherited from the parent (difficulty is zero post-merge
/// anyway), prevRandao defaults to zero, the base fee is computed per EIP-1559
/// only with `validation: true` (zero otherwise, so zero-priced calls run like
/// `eth_call`), and the blob fee market rolls forward in both modes.
fn make_sim_header(
    parent: &BlockHeader,
    sanitized: &SanitizedBlock,
    chain_config: &ChainConfig,
    validation: bool,
) -> BlockHeader {
    let overrides = &sanitized.spec.overrides;
    let number = sanitized.number;
    let timestamp = sanitized.timestamp;
    let fork = chain_config.fork(timestamp);
    let gas_limit = overrides.gas_limit.unwrap_or(parent.gas_limit);

    let base_fee_per_gas = match overrides.base_fee_per_gas {
        Some(base_fee) => Some(base_fee),
        None if parent.base_fee_per_gas.is_some() => {
            if validation {
                // The parent's own gas limit neutralizes the child-vs-parent
                // gas-limit bound check, which geth does not apply here.
                calculate_base_fee_per_gas(
                    parent.gas_limit,
                    parent.gas_limit,
                    parent.gas_used,
                    parent.base_fee_per_gas.unwrap_or_default(),
                    ELASTICITY_MULTIPLIER,
                )
            } else {
                Some(0)
            }
        }
        None => None,
    };

    let excess_blob_gas = if chain_config.is_cancun_activated(timestamp) {
        Some(overrides.excess_blob_gas.unwrap_or_else(|| {
            if parent.excess_blob_gas.is_some() {
                chain_config
                    .get_fork_blob_schedule(timestamp)
                    .map(|schedule| calc_excess_blob_gas(parent, schedule, fork))
                    .unwrap_or_default()
            } else {
                0
            }
        }))
    } else {
        None
    };

    BlockHeader {
        parent_hash: parent.hash(),
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: overrides.coinbase.unwrap_or(parent.coinbase),
        // state/transactions/receipts roots, bloom and gas_used are filled in
        // after execution.
        state_root: parent.state_root,
        transactions_root: compute_transactions_root(&[], &NativeCrypto),
        receipts_root: compute_receipts_root(&[], &NativeCrypto),
        difficulty: overrides.difficulty.unwrap_or_default(),
        number,
        gas_limit,
        gas_used: 0,
        timestamp,
        prev_randao: overrides.prev_randao.unwrap_or_default(),
        nonce: 0,
        base_fee_per_gas,
        withdrawals_root: chain_config
            .is_shanghai_activated(timestamp)
            .then(|| compute_withdrawals_root(&overrides.withdrawals, &NativeCrypto)),
        blob_gas_used: chain_config.is_cancun_activated(timestamp).then_some(0),
        excess_blob_gas,
        parent_beacon_block_root: chain_config
            .is_cancun_activated(timestamp)
            .then(|| overrides.beacon_root.unwrap_or_default()),
        requests_hash: chain_config
            .is_prague_activated(timestamp)
            .then_some(*DEFAULT_REQUESTS_HASH),
        slot_number: parent.slot_number.map(|slot| slot + 1),
        ..Default::default()
    }
}

/// Materialize a user state override as an [`AccountUpdate`], reading the
/// current effective state through `pre_db` so partial overrides (e.g. only
/// `balance`) keep the other account fields. Overrides become part of the
/// simulated state roots, matching geth (overrides are plain state writes).
fn state_override_to_update(
    address: Address,
    override_: StateOverride,
    pre_db: &SimulationVmDatabase<StoreVmDatabase>,
) -> Result<AccountUpdate, SimulationError> {
    use ethrex_vm::VmDatabase;
    let current = pre_db
        .get_account_state(address)
        .map_err(internal)?
        .unwrap_or_default();
    let mut update = AccountUpdate::new(address);
    let code_hash = override_
        .code
        .as_ref()
        .map(|(hash, _)| *hash)
        .unwrap_or(current.code_hash);
    update.info = Some(AccountInfo {
        balance: override_.balance.unwrap_or(current.balance),
        nonce: override_.nonce.unwrap_or(current.nonce),
        code_hash,
    });
    update.code = override_.code.map(|(_, code)| code);
    match override_.storage_mode {
        StorageMode::None => {}
        StorageMode::Replace(map) => {
            update.removed_storage = true;
            update.added_storage = map.into_iter().collect();
        }
        StorageMode::Diff(map) => {
            update.added_storage = map.into_iter().collect();
        }
    }
    Ok(update)
}

/// Build the real [`Transaction`] for one simulate call, with spec defaults:
/// the variant is chosen by which fields are present (EIP-1559 when nothing
/// disambiguates), the nonce is auto-filled from the live simulated state,
/// missing gas gets the remaining block gas, and the signature is zeroed (the
/// sender is carried out-of-band). Returns `(tx, sender, gas_capped)`;
/// Running per-block gas totals.
///
/// EIP-8037 splits a block's allowance into a regular and a state dimension, each bounded
/// by the block gas limit *independently*. That makes the room left for the next call
/// `min(limit - regular, limit - state)`, which is strictly more than the pre-Amsterdam
/// `limit - total` once both dimensions are non-zero — so the single running total is not
/// enough to decide inclusion, and using it refuses calls a real Amsterdam block includes.
#[derive(Clone, Copy, Default)]
struct BlockGasTally {
    /// Σ `report.gas_used`: the pre-Amsterdam single budget.
    total: u64,
    regular: u64,
    state: u64,
}

impl BlockGasTally {
    /// Accumulate one executed call, splitting it exactly as the payload builder does so a
    /// simulated block's gas matches what building the same block would report.
    fn add(&mut self, report_gas_used: u64, state_gas_used: u64) {
        self.total = self.total.saturating_add(report_gas_used);
        self.state = self.state.saturating_add(state_gas_used);
        self.regular = self
            .regular
            .saturating_add(report_gas_used.saturating_sub(state_gas_used));
    }

    /// The block's `gasUsed` header value: `max(Σregular, Σstate)` from Amsterdam on
    /// (mirroring `PayloadBuildContext::gas_used`), the plain sum before it.
    fn block_gas_used(&self, fork: Fork) -> u64 {
        if fork >= Fork::Amsterdam {
            self.regular.max(self.state)
        } else {
            self.total
        }
    }

    /// Gas available to the next call, per dimension from Amsterdam on.
    fn remaining(&self, gas_limit: u64, fork: Fork) -> u64 {
        if fork >= Fork::Amsterdam {
            self.regular_available(gas_limit)
                .min(self.state_available(gas_limit))
        } else {
            gas_limit.saturating_sub(self.total)
        }
    }

    fn regular_available(&self, gas_limit: u64) -> u64 {
        gas_limit.saturating_sub(self.regular)
    }

    fn state_available(&self, gas_limit: u64) -> u64 {
        gas_limit.saturating_sub(self.state)
    }
}

/// `gas_capped` marks calls whose gas was clamped by the request-wide cap.
fn build_sim_transaction(
    call: &GenericTransaction,
    header: &BlockHeader,
    chain_id: u64,
    fork: Fork,
    gas_tally: &BlockGasTally,
    budget_remaining: u64,
    evm: &mut ethrex_vm::Evm,
) -> Result<(Transaction, Address, bool), SimulationError> {
    if let Some(call_chain_id) = call.chain_id
        && call_chain_id != chain_id
    {
        return Err(SimulationError::InvalidParams(format!(
            "invalid chain id: got {call_chain_id}, want {chain_id}"
        )));
    }
    let sender = call.from;
    let nonce = match call.nonce {
        Some(nonce) => nonce,
        None => evm.get_account_nonce(sender).map_err(internal)?,
    };
    let remaining_block_gas = gas_tally.remaining(header.gas_limit, fork);
    let (gas_limit, gas_capped) = match call.gas {
        Some(gas) => {
            // Mirrors `ethrex_vm::check_2d_gas_allowance`, which cannot be called here: it
            // takes a built `Transaction`, and the gas limit being derived is what would go
            // into one. The regular dimension's worst case is the whole tx gas, capped by
            // EIP-7825; the state dimension has no such cap.
            let exceeds = if fork >= Fork::Amsterdam {
                let regular_contrib = gas.min(get_max_allowed_gas_limit(header.gas_limit, fork));
                regular_contrib > gas_tally.regular_available(header.gas_limit)
                    || gas > gas_tally.state_available(header.gas_limit)
            } else {
                gas > remaining_block_gas
            };
            if exceeds {
                return Err(SimulationError::BlockGasLimitReached {
                    requested: gas,
                    remaining: remaining_block_gas,
                });
            }
            (gas.min(budget_remaining), gas > budget_remaining)
        }
        None => {
            let auto = remaining_block_gas.min(get_max_allowed_gas_limit(header.gas_limit, fork));
            (auto.min(budget_remaining), auto > budget_remaining)
        }
    };

    let access_list = call
        .access_list
        .iter()
        .map(|entry| (entry.address, entry.storage_keys.clone()))
        .collect();
    let require_to = |what: &str| match call.to {
        TxKind::Call(to) => Ok(to),
        TxKind::Create => Err(SimulationError::InvalidParams(format!(
            "{what} transactions cannot create contracts"
        ))),
    };

    let tx = if let Some(authorization_list) = &call.authorization_list {
        Transaction::EIP7702Transaction(EIP7702Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: call.max_priority_fee_per_gas.unwrap_or_default(),
            max_fee_per_gas: call.max_fee_per_gas.unwrap_or_default(),
            gas_limit,
            to: require_to("EIP-7702")?,
            value: call.value,
            data: call.input.clone(),
            access_list,
            authorization_list: authorization_list
                .iter()
                .map(|auth| Into::<AuthorizationTuple>::into(auth.clone()))
                .collect(),
            ..Default::default()
        })
    } else if !call.blob_versioned_hashes.is_empty() || call.max_fee_per_blob_gas.is_some() {
        Transaction::EIP4844Transaction(EIP4844Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: call.max_priority_fee_per_gas.unwrap_or_default(),
            max_fee_per_gas: call.max_fee_per_gas.unwrap_or_default(),
            gas: gas_limit,
            to: require_to("blob")?,
            value: call.value,
            data: call.input.clone(),
            access_list,
            max_fee_per_blob_gas: call.max_fee_per_blob_gas.unwrap_or_default(),
            blob_versioned_hashes: call.blob_versioned_hashes.clone(),
            ..Default::default()
        })
    } else if !call.gas_price.is_zero()
        && call.max_fee_per_gas.is_none()
        && call.max_priority_fee_per_gas.is_none()
    {
        Transaction::LegacyTransaction(LegacyTransaction {
            nonce,
            gas_price: call.gas_price,
            gas: gas_limit,
            to: call.to.clone(),
            value: call.value,
            data: call.input.clone(),
            ..Default::default()
        })
    } else {
        // Spec default: type 0x2.
        Transaction::EIP1559Transaction(EIP1559Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: call.max_priority_fee_per_gas.unwrap_or_default(),
            max_fee_per_gas: call.max_fee_per_gas.unwrap_or_default(),
            gas_limit,
            to: call.to.clone(),
            value: call.value,
            data: call.input.clone(),
            access_list,
            ..Default::default()
        })
    };
    Ok((tx, sender, gas_capped))
}

impl Blockchain {
    /// Execute an `eth_simulateV1` request: simulate a chain of blocks on top
    /// of `request.base`, chaining state across blocks, without committing
    /// anything to the store.
    pub fn simulate_v1(
        &self,
        request: SimulationRequest,
    ) -> Result<Vec<SimulatedBlock>, SimulationError> {
        let base = request.base;
        let base_hash = base.hash();
        let chain_config = self.storage.get_chain_config();
        let is_l1 = matches!(self.options.r#type, BlockchainType::L1);
        let sim_config = SimTxConfig {
            validate: request.validation,
            trace_transfers: request.trace_transfers,
        };

        let blocks = sanitize_blocks(&base, request.blocks)?;
        let store_db =
            StoreVmDatabase::new(self.storage.clone(), base.clone()).map_err(internal)?;
        let mut overlay = SimulationOverlay::new(base.number);
        let mut budget_remaining = SIMULATION_GAS_CAP;
        let mut parent = base;
        let mut results = Vec::with_capacity(blocks.len());

        for sanitized in blocks {
            let mut header =
                make_sim_header(&parent, &sanitized, &chain_config, request.validation);
            let fork = chain_config.fork(header.timestamp);

            // State overrides are applied prior to execution of the block and
            // become part of the overlay (and thus the state root).
            if !sanitized.spec.state_overrides.is_empty() {
                let pre_db = SimulationVmDatabase::new(store_db.clone(), Arc::new(overlay.clone()));
                for (address, override_) in sanitized.spec.state_overrides.clone() {
                    if override_.is_noop() {
                        continue;
                    }
                    overlay.merge_update(state_override_to_update(address, override_, &pre_db)?);
                }
            }

            let sim_db = SimulationVmDatabase::new(store_db.clone(), Arc::new(overlay.clone()));
            let mut evm = self.new_evm(sim_db).map_err(internal)?;
            // The other half of a State Override Set: the account overlay above feeds
            // reads, while `movePrecompileToAddress` changes precompile *dispatch*, which
            // is EVM configuration rather than state. Installed per block, matching geth,
            // which derives a fresh active-precompile set for each simulated block instead
            // of carrying relocations forward.
            evm.set_precompile_moves(precompile_moves(&sanitized.spec.state_overrides));

            // EIP-7928: an Amsterdam block commits to its Block Access List, so a
            // simulated one has to record it. Enabled *before* the pre-execution system
            // calls, as the payload builder does, so the EIP-4788/2935 writes land in the
            // BAL: index 0 is the pre-execution phase, transaction i takes i + 1, and the
            // post-execution phase takes call_count + 1. Recorded per block, matching
            // geth and reth, which both build a fresh BAL for each simulated block.
            let records_bal = is_l1 && fork >= Fork::Amsterdam;
            if records_bal {
                evm.enable_bal_recording();
                evm.set_bal_index(0);
            }

            // Pre-execution system calls (EIP-4788 beacon root, EIP-2935 block
            // hash history) run for every simulated block, gap-filled ones
            // included; the history writes are what make BLOCKHASH work.
            if is_l1 {
                evm.apply_system_calls(&header).map_err(internal)?;
            }

            let call_count = sanitized.spec.calls.len();
            let mut transactions = Vec::with_capacity(call_count);
            let mut senders = Vec::with_capacity(call_count);
            let mut receipts = Vec::with_capacity(call_count);
            let mut calls = Vec::with_capacity(call_count);
            let mut block_logs: Vec<Log> = Vec::new();
            let mut gas_tally = BlockGasTally::default();
            let mut blob_gas_used: u64 = 0;
            let mut cumulative_gas_spent: u64 = 0;

            for (call_index, call) in sanitized.spec.calls.iter().enumerate() {
                // Set before the transaction is built, so the nonce read below is
                // attributed to this transaction rather than to the previous one.
                if records_bal {
                    evm.set_bal_index(u32::try_from(call_index + 1).unwrap_or(u32::MAX));
                }
                let (tx, sender, gas_capped) = build_sim_transaction(
                    call,
                    &header,
                    chain_config.chain_id,
                    fork,
                    &gas_tally,
                    budget_remaining,
                    &mut evm,
                )?;
                let (_, report) = match evm.execute_tx_simulate(
                    &tx,
                    &header,
                    &mut cumulative_gas_spent,
                    sender,
                    &sim_config,
                ) {
                    Ok(result) => result,
                    // Validation failures abort the whole request; reverts and
                    // halts below are per-call results with the tx included.
                    Err(SimulationTxError::Validation(validation_error)) => {
                        return Err(SimulationError::InvalidTx(validation_error));
                    }
                    Err(SimulationTxError::Evm(evm_error)) => return Err(internal(evm_error)),
                };

                gas_tally.add(report.gas_used, report.state_gas_used);
                budget_remaining = budget_remaining.saturating_sub(report.gas_used);
                blob_gas_used += (tx.blob_versioned_hashes().len() * GAS_PER_BLOB as usize) as u64;

                // Trace-transfer logs go to the per-call results but must stay
                // out of receipts, the logs bloom and request extraction.
                let real_logs: Vec<Log> = if request.trace_transfers {
                    report
                        .logs
                        .iter()
                        .filter(|log| log.address != TRACE_TRANSFER_ADDRESS)
                        .cloned()
                        .collect()
                } else {
                    report.logs.clone()
                };
                let receipt = Receipt::new(
                    tx.tx_type(),
                    report.is_success(),
                    cumulative_gas_spent,
                    real_logs.clone(),
                );

                // Pre-EIP-7778 `gas_used` is already post-refund, so the
                // pre-refund figure is reconstructed from the refund counter.
                let max_used_gas = if fork >= Fork::Amsterdam {
                    report.gas_used
                } else {
                    report.gas_spent + report.gas_refunded
                };
                let call_result = match &report.result {
                    TxResult::Success => SimulatedCallResult {
                        success: true,
                        return_data: report.output.clone(),
                        gas_used: report.gas_spent,
                        max_used_gas,
                        logs: report.logs.clone(),
                        error: None,
                    },
                    TxResult::Revert(vm_error) => {
                        let error = if vm_error.is_revert_opcode() {
                            SimulatedCallError::Revert {
                                output: report.output.clone(),
                            }
                        } else {
                            let mut reason = vm_error.to_string();
                            if gas_capped {
                                reason +=
                                    " (gas limit was capped by the RPC server's global gas cap)";
                            }
                            SimulatedCallError::Halt { reason }
                        };
                        SimulatedCallResult {
                            success: false,
                            return_data: Bytes::new(),
                            gas_used: report.gas_spent,
                            max_used_gas,
                            logs: Vec::new(),
                            error: Some(error),
                        }
                    }
                };

                if call_result.success {
                    block_logs.extend(real_logs);
                }
                transactions.push(tx);
                senders.push(sender);
                receipts.push(receipt);
                calls.push(call_result);
            }

            header.gas_used = gas_tally.block_gas_used(fork);
            if header.blob_gas_used.is_some() {
                header.blob_gas_used = Some(blob_gas_used);
            }

            // Post-execution phase (withdrawals, EIP-7685 request system calls).
            if records_bal {
                evm.set_bal_index(u32::try_from(call_count + 1).unwrap_or(u32::MAX));
            }

            if !sanitized.spec.overrides.withdrawals.is_empty() {
                evm.process_withdrawals(&sanitized.spec.overrides.withdrawals)
                    .map_err(internal)?;
            }

            // EIP-7685 request system calls (withdrawal/consolidation queues).
            if is_l1 && chain_config.is_prague_activated(header.timestamp) {
                let requests = evm.extract_requests(&receipts, &header).map_err(internal)?;
                let encoded: Vec<_> = requests.iter().map(|request| request.encode()).collect();
                header.requests_hash = Some(compute_requests_hash(&encoded));
            }

            // Taken once every phase has been recorded; `None` before Amsterdam, which
            // leaves the header field unset as a pre-fork block requires.
            header.block_access_list_hash =
                evm.take_bal().map(|bal| bal.compute_hash(&NativeCrypto));

            for update in evm.get_state_transitions().map_err(internal)? {
                overlay.merge_update(update);
            }

            // The state root derives from the *cumulative* updates applied to
            // the base block's trie: storage tries must be opened at committed
            // roots, so incremental application on top of uncommitted roots is
            // not an option.
            let updates = overlay.updates_vec();
            let updates_list = self
                .storage
                .apply_account_updates_batch(base_hash, &updates)
                .map_err(internal)?
                .ok_or_else(|| {
                    SimulationError::Internal("base block state not found".to_string())
                })?;
            header.state_root = updates_list.state_trie_hash;
            header.transactions_root = compute_transactions_root(&transactions, &NativeCrypto);
            header.receipts_root = compute_receipts_root(&receipts, &NativeCrypto);
            header.logs_bloom = bloom_from_logs(&block_logs, &NativeCrypto);

            let body = BlockBody {
                transactions,
                ommers: Vec::new(),
                withdrawals: chain_config
                    .is_shanghai_activated(header.timestamp)
                    .then(|| sanitized.spec.overrides.withdrawals.clone()),
            };
            let block = Block::new(header, body);
            let block_hash = block.header.hash();
            overlay.insert_block_hash(block.header.number, block_hash);
            parent = block.header.clone();
            results.push(SimulatedBlock {
                block,
                receipts,
                calls,
                senders,
            });
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header(number: u64, timestamp: u64) -> BlockHeader {
        BlockHeader {
            number,
            timestamp,
            gas_limit: 30_000_000,
            ..Default::default()
        }
    }

    fn spec_with(number: Option<u64>, time: Option<u64>) -> SimulationBlockSpec {
        SimulationBlockSpec {
            overrides: SimBlockOverrides {
                number,
                time,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn sanitize_defaults_number_and_timestamp() {
        let base = base_header(100, 1000);
        let blocks =
            sanitize_blocks(&base, vec![spec_with(None, None), spec_with(None, None)]).unwrap();
        assert_eq!(
            blocks
                .iter()
                .map(|b| (b.number, b.timestamp))
                .collect::<Vec<_>>(),
            vec![(101, 1012), (102, 1024)]
        );
    }

    #[test]
    fn sanitize_fills_gaps_with_empty_blocks() {
        let base = base_header(100, 1000);
        let blocks = sanitize_blocks(&base, vec![spec_with(Some(104), None)]).unwrap();
        assert_eq!(
            blocks
                .iter()
                .map(|b| (b.number, b.timestamp))
                .collect::<Vec<_>>(),
            vec![(101, 1012), (102, 1024), (103, 1036), (104, 1048)]
        );
        assert!(blocks[0].spec.calls.is_empty());
    }

    #[test]
    fn sanitize_rejects_non_ascending_numbers() {
        let base = base_header(100, 1000);
        let err = sanitize_blocks(
            &base,
            vec![spec_with(Some(110), None), spec_with(Some(105), None)],
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SimulationError::BlockNumberNotAscending {
                    given: 105,
                    prev: 110
                }
            ),
            "unexpected error: {err:?}"
        );
        // Equal numbers are rejected too (this is how "more blocks than fit
        // between two explicit numbers" surfaces).
        let err = sanitize_blocks(
            &base,
            vec![
                spec_with(Some(101), None),
                spec_with(None, None),
                spec_with(Some(102), None),
            ],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SimulationError::BlockNumberNotAscending {
                given: 102,
                prev: 102
            }
        ));
    }

    #[test]
    fn sanitize_rejects_non_increasing_timestamps() {
        let base = base_header(100, 1000);
        let err = sanitize_blocks(
            &base,
            vec![spec_with(None, Some(1100)), spec_with(None, Some(1100))],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SimulationError::TimestampNotAscending {
                given: 1100,
                prev: 1100
            }
        ));
    }

    #[test]
    fn sanitize_rejects_more_than_256_blocks_above_base() {
        let base = base_header(100, 1000);
        let err = sanitize_blocks(&base, vec![spec_with(Some(100 + 257), None)]).unwrap_err();
        assert!(matches!(err, SimulationError::TooManyBlocks));
        // Exactly 256 above the base is allowed.
        assert!(sanitize_blocks(&base, vec![spec_with(Some(100 + 256), None)]).is_ok());
    }

    #[test]
    fn sanitize_timestamp_continues_across_gap_blocks() {
        let base = base_header(100, 1000);
        // Gap blocks advance the timestamp; the explicit block must beat them.
        let err = sanitize_blocks(&base, vec![spec_with(Some(103), Some(1020))]).unwrap_err();
        assert!(matches!(
            err,
            SimulationError::TimestampNotAscending {
                given: 1020,
                prev: 1024
            }
        ));
    }

    #[test]
    fn header_defaults_inherit_and_zero_base_fee_without_validation() {
        let chain_config = ChainConfig::default();
        let mut parent = base_header(100, 1000);
        parent.coinbase = Address::repeat_byte(0xab);
        parent.base_fee_per_gas = Some(1_000_000_000);
        let sanitized = SanitizedBlock {
            spec: SimulationBlockSpec::default(),
            number: 101,
            timestamp: 1012,
        };
        let header = make_sim_header(&parent, &sanitized, &chain_config, false);
        assert_eq!(header.coinbase, parent.coinbase);
        assert_eq!(header.gas_limit, parent.gas_limit);
        assert_eq!(header.base_fee_per_gas, Some(0));
        assert_eq!(header.number, 101);
        assert_eq!(header.timestamp, 1012);
        assert_eq!(header.parent_hash, parent.hash());

        let validated = make_sim_header(&parent, &sanitized, &chain_config, true);
        // Parent used exactly its gas target (0 used of 30M) so the base fee
        // decreases; what matters here is that it is EIP-1559-derived, not 0.
        assert!(validated.base_fee_per_gas.unwrap() > 0);
    }

    #[test]
    fn header_respects_overrides() {
        let chain_config = ChainConfig::default();
        let parent = base_header(100, 1000);
        let sanitized = SanitizedBlock {
            spec: SimulationBlockSpec {
                overrides: SimBlockOverrides {
                    gas_limit: Some(10_000_000),
                    coinbase: Some(Address::repeat_byte(0x01)),
                    base_fee_per_gas: Some(7),
                    difficulty: Some(U256::from(5)),
                    ..Default::default()
                },
                ..Default::default()
            },
            number: 101,
            timestamp: 1012,
        };
        let header = make_sim_header(&parent, &sanitized, &chain_config, false);
        assert_eq!(header.gas_limit, 10_000_000);
        assert_eq!(header.coinbase, Address::repeat_byte(0x01));
        assert_eq!(header.base_fee_per_gas, Some(7));
        assert_eq!(header.difficulty, U256::from(5));
    }
}
