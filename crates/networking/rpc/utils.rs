//! Utility types and error handling for JSON-RPC.
//!
//! This module provides common types used across all RPC handlers:
//! - [`RpcErr`]: Error type for RPC failures with proper JSON-RPC error codes
//! - [`RpcRequest`]: Parsed JSON-RPC request
//! - [`RpcNamespace`]: RPC method namespace (eth, engine, debug, etc.)
//! - Response types for success and error cases

use ethrex_common::U256;
use ethrex_storage::error::StoreError;
use ethrex_vm::EvmError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{authentication::AuthenticationError, clients::EthClientError};
use ethrex_blockchain::error::MempoolError;

/// Error type for JSON-RPC method failures.
///
/// Each variant maps to a specific JSON-RPC error code when serialized:
/// - `-32601`: Method not found
/// - `-32602`: Invalid params
/// - `-32603`: Internal error
/// - `-32000`: Generic server error
/// - `-38001` to `-38006`: Engine API specific errors
/// - `3`: Execution reverted/halted
#[derive(Debug, thiserror::Error)]
pub enum RpcErr {
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    /// Also `-32601`, but for a method this build *does* implement and this
    /// endpoint does not serve: its namespace is off the `--http.api` allowlist,
    /// or it belongs to the other RPC port. The reason travels in the message so
    /// callers stop reading a bare "Method not found" as "ethrex has not
    /// implemented this method".
    #[error("Method not found: {method} ({reason})")]
    MethodNotServedHere { method: String, reason: String },
    #[error("Wrong parameter: {0}")]
    WrongParam(String),
    #[error("Invalid params: {0}")]
    BadParams(String),
    /// Spec-compliant invalid params error (-32602). The message is used
    /// verbatim, with no "Invalid params: " prefix, so error strings can
    /// match other clients exactly. `BadParams`/`WrongParam` map to -32000.
    #[error("{0}")]
    InvalidParams(String),
    #[error("Missing parameter: {0}")]
    MissingParam(String),
    #[error("Too large request")]
    TooLargeRequest,
    #[error("Bad hex format: {0}")]
    BadHexFormat(u64),
    #[error("Unsupported fork: {0}")]
    UnsupportedFork(String),
    #[error("Internal Error: {0}")]
    Internal(String),
    #[error("Vm execution error: {0}")]
    Vm(String),
    #[error("execution reverted: data={data}")]
    Revert { data: String },
    #[error("execution halted: reason={reason}, gas_used={gas_used}")]
    Halt { reason: String, gas_used: u64 },
    #[error("Authentication error: {0:?}")]
    AuthenticationError(AuthenticationError),
    /// JSON-RPC 2.0 §5.1: the JSON sent is not a valid Request object. Used
    /// for malformed bodies on the auth port (e.g. empty batches) where we
    /// also drop the request id (per spec, id MUST be null when it cannot
    /// be detected).
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),
    #[error("Invalid forkchoice state: {0}")]
    InvalidForkChoiceState(String),
    #[error("Invalid payload attributes: {0}")]
    InvalidPayloadAttributes(String),
    #[error("Too deep reorg: {0}")]
    TooDeepReorg(String),
    #[error("Unknown payload: {0}")]
    UnknownPayload(String),
    // EIP-8025 proof errors (-39001 .. -39004)
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),
    #[error("Invalid header format: {0}")]
    InvalidHeaderFormat(String),
    #[error("Invalid payload: {0}")]
    InvalidPayload(String),
    #[error("Proof generation unavailable: {0}")]
    ProofGenerationUnavailable(String),
    /// `eth_simulateV1` request-level failure. Carries its JSON-RPC code
    /// verbatim: the method has its own spec error-code table
    /// (-38010..-38026 plus the standard -32xxx ones), so the variant stays
    /// code-agnostic instead of enumerating them.
    #[error("{message}")]
    EthSimulate {
        code: i32,
        message: String,
        data: Option<String>,
    },
    /// `-32001: Resource not found`, e.g. a block-access-list getter asked
    /// about a block that predates the Amsterdam fork (execution-apis#851).
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    /// `4444: Pruned history unavailable`: the block is known but the data to
    /// answer was pruned. The code was introduced across the eth/debug getters
    /// by execution-apis#636 (EIP-4444 history expiry left the RPC behaviour
    /// out of scope), and execution-apis#851 requires it for the
    /// block-access-list getters.
    #[error("Pruned history unavailable: {0}")]
    PrunedHistoryUnavailable(String),
}

impl From<RpcErr> for RpcErrorMetadata {
    fn from(value: RpcErr) -> Self {
        match value {
            RpcErr::MethodNotFound(bad_method) => RpcErrorMetadata {
                code: -32601,
                data: None,
                message: format!("Method not found: {bad_method}"),
            },
            RpcErr::MethodNotServedHere { method, reason } => RpcErrorMetadata {
                code: -32601,
                data: None,
                message: format!("Method not found: {method} ({reason})"),
            },
            RpcErr::WrongParam(field) => RpcErrorMetadata {
                code: -32602,
                data: None,
                message: format!("Field '{field}' is incorrect or has an unknown format"),
            },
            RpcErr::BadParams(context) => RpcErrorMetadata {
                code: -32000,
                data: None,
                message: format!("Invalid params: {context}"),
            },
            RpcErr::InvalidParams(context) => RpcErrorMetadata {
                code: -32602,
                data: None,
                message: context,
            },
            RpcErr::InvalidRequest(context) => RpcErrorMetadata {
                code: -32600,
                data: None,
                message: format!("Invalid Request: {context}"),
            },
            RpcErr::MissingParam(parameter_name) => RpcErrorMetadata {
                code: -32000,
                data: None,
                message: format!("Expected parameter: {parameter_name} is missing"),
            },
            RpcErr::TooLargeRequest => RpcErrorMetadata {
                code: -38004,
                data: None,
                message: "Too large request".to_string(),
            },
            RpcErr::UnsupportedFork(context) => RpcErrorMetadata {
                code: -38005,
                data: None,
                message: format!("Unsupported fork: {context}"),
            },
            RpcErr::BadHexFormat(arg_number) => RpcErrorMetadata {
                code: -32602,
                data: None,
                message: format!("invalid argument {arg_number} : hex string without 0x prefix"),
            },
            RpcErr::Internal(context) => RpcErrorMetadata {
                code: -32603,
                data: None,
                message: format!("Internal Error: {context}"),
            },
            RpcErr::Vm(context) => RpcErrorMetadata {
                code: -32015,
                data: None,
                message: format!("Vm execution error: {context}"),
            },
            RpcErr::Revert { data } => RpcErrorMetadata {
                // This code (3) was hand-picked to match hive tests.
                // Could not find proper documentation about it.
                code: 3,
                data: Some(data.clone()),
                message: format!(
                    "execution reverted: {}",
                    get_message_from_revert_data(&data).unwrap_or_else(|err| format!(
                        "tried to decode error from abi but failed: {err}"
                    ))
                ),
            },
            RpcErr::Halt { reason, gas_used } => RpcErrorMetadata {
                // Just copy the `Revert` error code.
                // Haven't found an example of this one yet.
                code: 3,
                data: None,
                message: format!("execution halted: reason={reason}, gas_used={gas_used}"),
            },
            RpcErr::AuthenticationError(auth_error) => match auth_error {
                AuthenticationError::InvalidIssuedAtClaim => RpcErrorMetadata {
                    code: -32000,
                    data: None,
                    message: "Auth failed: Invalid iat claim".to_string(),
                },
                AuthenticationError::TokenDecodingError => RpcErrorMetadata {
                    code: -32000,
                    data: None,
                    message: "Auth failed: Invalid or missing token".to_string(),
                },
                AuthenticationError::MissingAuthentication => RpcErrorMetadata {
                    code: -32000,
                    data: None,
                    message: "Auth failed: Missing authentication header".to_string(),
                },
            },
            RpcErr::EthSimulate {
                code,
                message,
                data,
            } => RpcErrorMetadata {
                code,
                data,
                message,
            },
            RpcErr::InvalidForkChoiceState(data) => RpcErrorMetadata {
                code: -38002,
                data: Some(data),
                message: "Invalid forkchoice state".to_string(),
            },
            RpcErr::InvalidPayloadAttributes(data) => RpcErrorMetadata {
                code: -38003,
                data: Some(data),
                message: "Invalid payload attributes".to_string(),
            },
            RpcErr::TooDeepReorg(data) => RpcErrorMetadata {
                code: -38006,
                data: Some(data),
                message: "Too deep reorg".to_string(),
            },
            RpcErr::UnknownPayload(context) => RpcErrorMetadata {
                code: -38001,
                data: None,
                message: format!("Unknown payload: {context}"),
            },
            // EIP-8025 proof error codes
            RpcErr::InvalidProofFormat(context) => RpcErrorMetadata {
                code: -39001,
                data: None,
                message: format!("Invalid proof format: {context}"),
            },
            RpcErr::InvalidHeaderFormat(context) => RpcErrorMetadata {
                code: -39002,
                data: None,
                message: format!("Invalid header format: {context}"),
            },
            RpcErr::InvalidPayload(context) => RpcErrorMetadata {
                code: -39003,
                data: None,
                message: format!("Invalid payload: {context}"),
            },
            RpcErr::ProofGenerationUnavailable(context) => RpcErrorMetadata {
                code: -39004,
                data: None,
                message: format!("Proof generation unavailable: {context}"),
            },
            RpcErr::ResourceNotFound(context) => RpcErrorMetadata {
                code: -32001,
                data: Some(context),
                message: "Resource not found".to_string(),
            },
            RpcErr::PrunedHistoryUnavailable(context) => RpcErrorMetadata {
                code: 4444,
                data: Some(context),
                message: "Pruned history unavailable".to_string(),
            },
        }
    }
}

impl From<serde_json::Error> for RpcErr {
    fn from(error: serde_json::Error) -> Self {
        Self::BadParams(error.to_string())
    }
}

// TODO: Actually return different errors for each case
// here we are returning a BadParams error
impl From<MempoolError> for RpcErr {
    fn from(err: MempoolError) -> Self {
        match err {
            MempoolError::StoreError(err) => Self::Internal(err.to_string()),
            other_err => Self::BadParams(other_err.to_string()),
        }
    }
}

impl From<ethrex_crypto::CryptoError> for RpcErr {
    fn from(err: ethrex_crypto::CryptoError) -> Self {
        Self::Internal(format!("Cryptography error: {err}"))
    }
}

/// JSON-RPC method namespace.
///
/// Methods are namespaced by prefix (e.g., `eth_getBalance` is in the `Eth` namespace).
/// Different namespaces may have different authentication requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcNamespace {
    /// Engine API methods for consensus client communication (requires JWT auth).
    Engine,
    /// Standard Ethereum methods for querying state and sending transactions.
    Eth,
    /// Node administration methods.
    Admin,
    /// Debugging and tracing methods.
    Debug,
    /// Web3 utility methods.
    Web3,
    /// Network information methods.
    Net,
    /// Transaction pool inspection methods (exposed as `txpool_*`).
    Mempool,
    /// Testing-only methods for fixture generation (exposed as `testing_*`).
    /// Disabled by default; must never be exposed on public-facing RPC APIs.
    Testing,
}

impl RpcNamespace {
    /// Renders the namespace back to its CLI/method-prefix form, the inverse of
    /// [`RpcNamespace::from_prefix`]. Error messages use this so operators see
    /// the exact string they would pass to `--http.api` (`txpool`, not
    /// `Mempool`).
    pub fn as_prefix(self) -> &'static str {
        match self {
            RpcNamespace::Engine => "engine",
            RpcNamespace::Eth => "eth",
            RpcNamespace::Admin => "admin",
            RpcNamespace::Debug => "debug",
            RpcNamespace::Web3 => "web3",
            RpcNamespace::Net => "net",
            RpcNamespace::Mempool => "txpool",
            RpcNamespace::Testing => "testing",
        }
    }

    /// Parses a namespace name from its CLI/method-prefix form.
    pub fn from_prefix(s: &str) -> Option<Self> {
        match s {
            "engine" => Some(RpcNamespace::Engine),
            "eth" => Some(RpcNamespace::Eth),
            "admin" => Some(RpcNamespace::Admin),
            "debug" => Some(RpcNamespace::Debug),
            "web3" => Some(RpcNamespace::Web3),
            "net" => Some(RpcNamespace::Net),
            "txpool" => Some(RpcNamespace::Mempool),
            "testing" => Some(RpcNamespace::Testing),
            _ => None,
        }
    }
}

/// JSON-RPC request identifier.
///
/// Per the JSON-RPC 2.0 spec, request IDs can be either numbers or strings.
/// The same ID must be returned in the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcRequestId {
    /// Numeric request ID.
    Number(u64),
    /// String request ID.
    String(String),
}

/// A parsed JSON-RPC 2.0 request.
///
/// # Example
///
/// ```json
/// {
///     "jsonrpc": "2.0",
///     "id": 1,
///     "method": "eth_getBalance",
///     "params": ["0x...", "latest"]
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RpcRequest {
    /// Request identifier, echoed back in the response.
    pub id: RpcRequestId,
    /// JSON-RPC version, must be "2.0".
    pub jsonrpc: String,
    /// Method name (e.g., "eth_getBalance").
    pub method: String,
    /// Optional array of method parameters.
    pub params: Option<Vec<Value>>,
}

impl RpcRequest {
    pub fn namespace(&self) -> Result<RpcNamespace, RpcErr> {
        let mut parts = self.method.split('_');
        let Some(namespace) = parts.next() else {
            return Err(RpcErr::MethodNotFound(self.method.clone()));
        };
        resolve_namespace(namespace, self.method.clone())
    }

    pub fn new(method: &str, params: Option<Vec<Value>>) -> Self {
        RpcRequest {
            id: RpcRequestId::Number(1),
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        }
    }
}

pub fn resolve_namespace(maybe_namespace: &str, method: String) -> Result<RpcNamespace, RpcErr> {
    RpcNamespace::from_prefix(maybe_namespace).ok_or(RpcErr::MethodNotFound(method))
}

impl Default for RpcRequest {
    fn default() -> Self {
        RpcRequest {
            id: RpcRequestId::Number(1),
            jsonrpc: "2.0".to_string(),
            method: "".to_string(),
            params: None,
        }
    }
}

/// Error metadata for JSON-RPC error responses.
///
/// Contains the error code, message, and optional additional data.
/// Error codes follow the JSON-RPC 2.0 and Ethereum conventions.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RpcErrorMetadata {
    /// Numeric error code (negative for standard errors).
    pub code: i32,
    /// Optional additional error data (e.g., revert reason).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Human-readable error message.
    pub message: String,
}

/// A successful JSON-RPC 2.0 response.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcSuccessResponse {
    /// Request identifier from the original request.
    pub id: RpcRequestId,
    /// JSON-RPC version, always "2.0".
    pub jsonrpc: String,
    /// The result value returned by the method.
    pub result: Value,
}

/// An error JSON-RPC 2.0 response.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcErrorResponse {
    /// Request identifier from the original request.
    pub id: RpcRequestId,
    /// JSON-RPC version, always "2.0".
    pub jsonrpc: String,
    /// Error details including code and message.
    pub error: RpcErrorMetadata,
}

/// A JSON-RPC 2.0 response, either success or error.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum RpcResponse {
    Success(RpcSuccessResponse),
    Error(RpcErrorResponse),
}

/// Failure to read from DB will always constitute an internal error
impl From<StoreError> for RpcErr {
    fn from(value: StoreError) -> Self {
        RpcErr::Internal(value.to_string())
    }
}

impl From<EvmError> for RpcErr {
    fn from(value: EvmError) -> Self {
        RpcErr::Vm(value.to_string())
    }
}

pub fn get_message_from_revert_data(data: &str) -> Result<String, EthClientError> {
    if data == "0x" {
        Ok("Execution reverted without a reason string.".to_owned())
    // 4 byte function signature 0xXXXXXXXX
    } else if data.len() == 10 {
        Ok(data.to_owned())
    } else {
        let abi_decoded_error_data =
            hex::decode(data.strip_prefix("0x").ok_or(EthClientError::Custom(
                "Failed to strip_prefix when getting message from revert data".to_owned(),
            ))?)
            .map_err(|_| {
                EthClientError::Custom(
                    "Failed to hex::decode when getting message from revert data".to_owned(),
                )
            })?;
        let string_length = U256::from_big_endian(abi_decoded_error_data.get(36..68).ok_or(
            EthClientError::Custom(
                "Failed to slice index abi_decoded_error_data when getting message from revert data".to_owned(),
            ),
        )?);
        let string_len = usize::try_from(string_length).map_err(|_| {
            EthClientError::Custom(
                "Failed to convert string_length to usize when getting message from revert data"
                    .to_owned(),
            )
        })?;
        let string_data = abi_decoded_error_data
            .get(68..68 + string_len)
            .ok_or(EthClientError::Custom(
            "Failed to slice index abi_decoded_error_data when getting message from revert data"
                .to_owned(),
        ))?;
        String::from_utf8(string_data.to_vec()).map_err(|_| {
            EthClientError::Custom(
                "Failed to String::from_utf8 when getting message from revert data".to_owned(),
            )
        })
    }
}

pub fn parse_json_hex(hex: &serde_json::Value) -> Result<u64, String> {
    if let Value::String(maybe_hex) = hex {
        let trimmed = maybe_hex.trim_start_matches("0x");
        let maybe_parsed = u64::from_str_radix(trimmed, 16);
        maybe_parsed.map_err(|_| format!("Could not parse given hex {maybe_hex}"))
    } else {
        Err(format!("Could not parse given hex {hex}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `as_prefix` feeds `--http.api` advice in error messages, so it must stay
    /// the exact inverse of the parser operators' input goes through. Drift would
    /// tell someone to enable a namespace under a name the CLI rejects.
    #[test]
    fn namespace_prefix_round_trips() {
        for namespace in [
            RpcNamespace::Engine,
            RpcNamespace::Eth,
            RpcNamespace::Admin,
            RpcNamespace::Debug,
            RpcNamespace::Web3,
            RpcNamespace::Net,
            RpcNamespace::Mempool,
            RpcNamespace::Testing,
        ] {
            let prefix = namespace.as_prefix();
            assert_eq!(
                RpcNamespace::from_prefix(prefix),
                Some(namespace),
                "{namespace:?} renders as {prefix:?}, which does not parse back"
            );
        }
    }

    /// The `txpool_*` methods live under the `Mempool` variant, so the CLI name
    /// and the variant name genuinely differ. Error messages must use the former.
    #[test]
    fn mempool_renders_as_its_cli_name() {
        assert_eq!(RpcNamespace::Mempool.as_prefix(), "txpool");
    }
}
