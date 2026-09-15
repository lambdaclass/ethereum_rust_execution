use ethrex_levm::errors::{
    DatabaseError as LevmDatabaseError, InternalError, TxValidationError, VMError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvmError {
    #[error("Invalid Transaction: {0}")]
    Transaction(String),
    #[error("Invalid Header: {0}")]
    Header(String),
    #[error("DB error: {0}")]
    DB(String),
    #[error("{0}")]
    Precompile(String),
    #[error("Invalid EVM or EVM not supported: {0}")]
    InvalidEVM(String),
    #[error("{0}")]
    Custom(String),
    #[error("Invalid deposit request layout")]
    InvalidDepositRequest,
    #[error("System call failed: {0}")]
    SystemContractCallFailed(String),
}

impl From<VMError> for EvmError {
    fn from(value: VMError) -> Self {
        if value.should_propagate() {
            EvmError::Custom(value.to_string())
        } else {
            // If an error is not internal it means it is a transaction validation error.
            EvmError::Transaction(value.to_string())
        }
    }
}

/// Error type for `eth_simulateV1` transaction execution. Unlike
/// [`From<VMError> for EvmError`], it keeps validation failures structured so
/// the RPC layer can map each [`TxValidationError`] variant to its spec error
/// code (nonce too low/high, base fee too low, insufficient funds, ...).
#[derive(Debug, Error)]
pub enum SimulationTxError {
    #[error("Invalid transaction: {0}")]
    Validation(TxValidationError),
    #[error(transparent)]
    Evm(EvmError),
}

impl From<VMError> for SimulationTxError {
    fn from(value: VMError) -> Self {
        match value {
            VMError::TxValidation(validation) => SimulationTxError::Validation(validation),
            other => SimulationTxError::Evm(other.into()),
        }
    }
}

impl From<EvmError> for SimulationTxError {
    fn from(value: EvmError) -> Self {
        SimulationTxError::Evm(value)
    }
}

impl From<LevmDatabaseError> for EvmError {
    fn from(value: LevmDatabaseError) -> Self {
        EvmError::DB(value.to_string())
    }
}

impl From<InternalError> for EvmError {
    fn from(value: InternalError) -> Self {
        match value {
            InternalError::Database(err) => err.into(),
            other => EvmError::Custom(other.to_string()),
        }
    }
}
