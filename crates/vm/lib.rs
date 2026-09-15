mod db;
mod errors;
mod execution_result;
pub mod tracing;
mod witness_db;

pub mod backends;

/// EIP-8037 (Amsterdam+, PR #2703) per-tx 2D inclusion check. Re-exported so the
/// payload builder can enforce it with identical semantics to the validator.
pub use backends::levm::check_2d_gas_allowance;
pub use backends::{
    BlockExecutionResult, Evm, SimTxConfig, TxGasBreakdown, TxStatus, compute_burned_fees,
    log_gas_used_mismatch,
};
pub use db::{DynVmDatabase, VmDatabase};
pub use errors::{EvmError, SimulationTxError};
pub use ethrex_levm::StatelessValidator;
/// Sentinel emitter address for `eth_simulateV1` traceTransfers logs,
/// re-exported so callers can filter them out of receipts/blooms.
pub use ethrex_levm::constants::TRACE_TRANSFER_ADDRESS;
/// Structured tx-validation failures, re-exported so `eth_simulateV1` can map
/// each variant to its spec error code.
pub use ethrex_levm::errors::TxValidationError;
/// Per-tx execution outcome types, re-exported for `eth_simulateV1` call
/// result classification.
pub use ethrex_levm::errors::{ExecutionReport, TxResult};
pub use ethrex_levm::errors::{InternalError, PrecompileError, VMError};
pub use ethrex_levm::precompiles::{
    PrecompileCache, PrecompileMoves, is_precompile, precompiles_for_fork,
};
/// EIP-8037 intrinsic gas split `(regular, state)` for a transaction.
/// Re-exported for mempool / payload-builder use.
pub use ethrex_levm::utils::intrinsic_gas_dimensions;
/// EIP-7623/7976/7981 floor gas for a transaction. Re-exported so the mempool
/// can match the VM's `validate_min_gas_limit` check at admission time.
pub use ethrex_levm::utils::intrinsic_gas_floor;
pub use ethrex_levm::vm::validate_frame_signatures;
pub use execution_result::ExecutionResult;
pub use witness_db::GuestProgramStateWrapper;
pub mod system_contracts;
