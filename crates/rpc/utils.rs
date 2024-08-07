use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub enum RpcErr {
    MethodNotFound,
    BadParams,
    UnsuportedFork,
    Internal,
}

impl From<RpcErr> for RpcErrorMetadata {
    fn from(value: RpcErr) -> Self {
        match value {
            RpcErr::MethodNotFound => RpcErrorMetadata {
                code: -32601,
                message: "Method not found".to_string(),
            },
            RpcErr::BadParams => RpcErrorMetadata {
                code: -32602,
                message: "Invalid params".to_string(),
            },
            RpcErr::UnsuportedFork => RpcErrorMetadata {
                code: -38005,
                message: "Unsupported fork".to_string(),
            },
            RpcErr::Internal => RpcErrorMetadata {
                code: -32603,
                message: "Internal Error".to_string(),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcRequest {
    pub id: i32,
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Vec<Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcErrorMetadata {
    pub code: i32,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcSuccessResponse {
    pub id: i32,
    pub jsonrpc: String,
    pub result: Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcErrorResponse {
    pub id: i32,
    pub jsonrpc: String,
    pub error: RpcErrorMetadata,
}

pub fn rpc_response<E>(id: i32, res: Result<Value, E>) -> Json<Value>
where
    E: Into<RpcErrorMetadata>,
{
    match res {
        Ok(result) => Json(
            serde_json::to_value(RpcSuccessResponse {
                id,
                jsonrpc: "2.0".to_string(),
                result,
            })
            .unwrap(),
        ),
        Err(error) => Json(
            serde_json::to_value(RpcErrorResponse {
                id,
                jsonrpc: "2.0".to_string(),
                error: error.into(),
            })
            .unwrap(),
        ),
    }
}
