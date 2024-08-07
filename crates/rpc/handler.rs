use crate::engine::{self, ExchangeCapabilitiesRequest, NewPayloadV3Request};
use crate::eth::{
    account::{self, GetBalanceRequest, GetCodeRequest, GetStorageAtRequest},
    block::{
        self, GetBlockByHashRequest, GetBlockByNumberRequest, GetBlockReceiptsRequest,
        GetBlockTransactionCountByNumberRequest, GetTransactionByBlockHashAndIndexRequest,
        GetTransactionByBlockNumberAndIndexRequest, GetTransactionByHashRequest,
        GetTransactionReceiptRequest,
    },
    client,
};
use axum::{extract::State, Json};
use ethereum_rust_storage::Store;
use serde_json::Value;

use crate::{admin, utils::*};

pub async fn handle_authrpc_request(State(storage): State<Store>, body: String) -> Json<Value> {
    let req: RpcRequest = serde_json::from_str(&body).unwrap();
    let res = match map_internal_requests(&req, storage.clone()) {
        Err(RpcErr::MethodNotFound) => map_requests(&req, storage),
        res => res,
    };
    rpc_response(req.id, res)
}

pub async fn handle_http_request(State(storage): State<Store>, body: String) -> Json<Value> {
    let req: RpcRequest = serde_json::from_str(&body).unwrap();
    let res = map_requests(&req, storage);
    rpc_response(req.id, res)
}

/// Handle requests that can come from either clients or other users
pub fn map_requests(req: &RpcRequest, storage: Store) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "engine_exchangeCapabilities" => {
            let capabilities: ExchangeCapabilitiesRequest = req
                .params
                .as_ref()
                .ok_or(RpcErr::BadParams)?
                .first()
                .ok_or(RpcErr::BadParams)
                .and_then(|v| serde_json::from_value(v.clone()).map_err(|_| RpcErr::BadParams))?;
            engine::exchange_capabilities(&capabilities)
        }
        "eth_chainId" => client::chain_id(),
        "eth_syncing" => client::syncing(),
        "eth_getBlockByNumber" => {
            let request = GetBlockByNumberRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            block::get_block_by_number(&request, storage)
        }
        "eth_getBlockByHash" => {
            let request = GetBlockByHashRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            block::get_block_by_hash(&request, storage)
        }
        "eth_getBalance" => {
            let request = GetBalanceRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            account::get_balance(&request, storage)
        }
        "eth_getCode" => {
            let request = GetCodeRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            account::get_code(&request, storage)
        }
        "eth_getStorageAt" => {
            let request = GetStorageAtRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            account::get_storage_at(&request, storage)
        }
        "eth_getBlockTransactionCountByNumber" => {
            let request = GetBlockTransactionCountByNumberRequest::parse(&req.params)
                .ok_or(RpcErr::BadParams)?;
            block::get_block_transaction_count_by_number(&request, storage)
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            let request = GetTransactionByBlockNumberAndIndexRequest::parse(&req.params)
                .ok_or(RpcErr::BadParams)?;
            block::get_transaction_by_block_number_and_index(&request, storage)
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            let request = GetTransactionByBlockHashAndIndexRequest::parse(&req.params)
                .ok_or(RpcErr::BadParams)?;
            block::get_transaction_by_block_hash_and_index(&request, storage)
        }
        "eth_getBlockReceipts" => {
            let request = GetBlockReceiptsRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            block::get_block_receipts(&request, storage)
        }
        "eth_getTransactionByHash" => {
            let request =
                GetTransactionByHashRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            block::get_transaction_by_hash(&request, storage)
        }
        "eth_getTransactionReceipt" => {
            let request =
                GetTransactionReceiptRequest::parse(&req.params).ok_or(RpcErr::BadParams)?;
            block::get_transaction_receipt(&request, storage)
        }
        "engine_forkchoiceUpdatedV3" => engine::forkchoice_updated_v3(),
        "engine_newPayloadV3" => {
            let request: NewPayloadV3Request =
                parse_new_payload_v3_request(req.params.as_ref().ok_or(RpcErr::BadParams)?)?;
            Ok(serde_json::to_value(engine::new_payload_v3(request)?).unwrap())
        }
        "admin_nodeInfo" => admin::node_info(),
        _ => Err(RpcErr::MethodNotFound),
    }
}

/// Handle requests from other clients
pub fn map_internal_requests(_req: &RpcRequest, _storage: Store) -> Result<Value, RpcErr> {
    Err(RpcErr::MethodNotFound)
}

fn parse_new_payload_v3_request(params: &[Value]) -> Result<NewPayloadV3Request, RpcErr> {
    if params.len() != 3 {
        return Err(RpcErr::BadParams);
    }
    let payload = serde_json::from_value(params[0].clone()).map_err(|_| RpcErr::BadParams)?;
    let expected_blob_versioned_hashes =
        serde_json::from_value(params[1].clone()).map_err(|_| RpcErr::BadParams)?;
    let parent_beacon_block_root =
        serde_json::from_value(params[2].clone()).map_err(|_| RpcErr::BadParams)?;
    Ok(NewPayloadV3Request {
        payload,
        expected_blob_versioned_hashes,
        parent_beacon_block_root,
    })
}
