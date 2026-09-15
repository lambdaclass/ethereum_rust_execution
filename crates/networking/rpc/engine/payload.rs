use bytes::Bytes;
use ethrex_blockchain::error::ChainError;
use ethrex_blockchain::payload::PayloadBuildResult;
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::block_execution_witness::{
    ExecutionWitness, ExtWitness, RpcExecutionWitness,
};
use ethrex_common::types::payload::PayloadBundle;
use ethrex_common::types::requests::{EncodedRequests, compute_requests_hash};
use ethrex_common::types::{Block, BlockBody, BlockHash, BlockHeader, BlockNumber, Fork};
use ethrex_common::{H256, U256};
use ethrex_crypto::NativeCrypto;
use ethrex_p2p::sync::SyncMode;
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode, error::RLPDecodeError};
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::rpc::{RpcApiContext, RpcHandler};
use crate::types::payload::{
    ExecutionPayload, ExecutionPayloadBody, ExecutionPayloadBodyV2, ExecutionPayloadResponse,
    PayloadStatus,
};
use crate::utils::RpcErr;
use crate::utils::{RpcRequest, parse_json_hex};

// The Engine API (Shanghai) only mandates supporting request sizes of at least 32 blocks.
// Cap at MAX_REQUEST_BLOCKS = 1024, the largest request a conforming consensus client makes.
// -> https://github.com/ethereum/consensus-specs/blob/a84880a47a88700d8dfa451c2a7cd4b3f309bd0d/specs/phase0/p2p-interface.md#configuration
const GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE: u64 = 1024;

// NewPayload V1-V2-V3 implementations
pub struct NewPayloadV1Request {
    pub payload: ExecutionPayload,
}

impl RpcHandler for NewPayloadV1Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(NewPayloadV1Request {
            payload: parse_execution_payload(params)?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        validate_execution_payload_v1(&self.payload)?;
        let block = match get_block_from_payload(&self.payload, None, None, None) {
            Ok(block) => block,
            Err(err) => {
                return Ok(serde_json::to_value(PayloadStatus::invalid_with_err(
                    &err.to_string(),
                ))?);
            }
        };
        let payload_status =
            handle_new_payload_v1_v2(&self.payload, block, context, None, false).await?;
        serde_json::to_value(payload_status).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct NewPayloadV2Request {
    pub payload: ExecutionPayload,
}

impl RpcHandler for NewPayloadV2Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(NewPayloadV2Request {
            payload: parse_execution_payload(params)?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let chain_config = &context.storage.get_chain_config();
        if chain_config.is_shanghai_activated(self.payload.timestamp) {
            validate_execution_payload_v2(&self.payload)?;
        } else {
            // Behave as a v1
            validate_execution_payload_v1(&self.payload)?;
        }
        let block = match get_block_from_payload(&self.payload, None, None, None) {
            Ok(block) => block,
            Err(err) => {
                return Ok(serde_json::to_value(PayloadStatus::invalid_with_err(
                    &err.to_string(),
                ))?);
            }
        };
        let payload_status =
            handle_new_payload_v1_v2(&self.payload, block, context, None, false).await?;
        serde_json::to_value(payload_status).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct NewPayloadV3Request {
    pub payload: ExecutionPayload,
    pub expected_blob_versioned_hashes: Vec<H256>,
    pub parent_beacon_block_root: H256,
}

impl From<NewPayloadV3Request> for RpcRequest {
    fn from(val: NewPayloadV3Request) -> Self {
        RpcRequest {
            method: "engine_newPayloadV3".to_string(),
            params: Some(vec![
                serde_json::json!(val.payload),
                serde_json::json!(val.expected_blob_versioned_hashes),
                serde_json::json!(val.parent_beacon_block_root),
            ]),
            ..Default::default()
        }
    }
}

impl RpcHandler for NewPayloadV3Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 3 {
            return Err(RpcErr::BadParams("Expected 3 params".to_owned()));
        }
        Ok(NewPayloadV3Request {
            payload: serde_json::from_value(params[0].clone())
                .map_err(|_| RpcErr::WrongParam("payload".to_string()))?,
            expected_blob_versioned_hashes: serde_json::from_value(params[1].clone())
                .map_err(|_| RpcErr::WrongParam("expected_blob_versioned_hashes".to_string()))?,
            parent_beacon_block_root: serde_json::from_value(params[2].clone())
                .map_err(|_| RpcErr::WrongParam("parent_beacon_block_root".to_string()))?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let block = match get_block_from_payload(
            &self.payload,
            Some(self.parent_beacon_block_root),
            None,
            None,
        ) {
            Ok(block) => block,
            Err(err) => {
                return Ok(serde_json::to_value(PayloadStatus::invalid_with_err(
                    &err.to_string(),
                ))?);
            }
        };
        validate_fork(&block, Fork::Cancun, &context)?;
        validate_execution_payload_v3(&self.payload)?;
        let payload_status = handle_new_payload_v3(
            &self.payload,
            context,
            block,
            self.expected_blob_versioned_hashes.clone(),
            None,
            false,
        )
        .await?;
        serde_json::to_value(payload_status).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct NewPayloadV4Request {
    pub payload: ExecutionPayload,
    pub expected_blob_versioned_hashes: Vec<H256>,
    pub parent_beacon_block_root: H256,
    pub execution_requests: Vec<EncodedRequests>,
}

impl From<NewPayloadV4Request> for RpcRequest {
    fn from(val: NewPayloadV4Request) -> Self {
        RpcRequest {
            method: "engine_newPayloadV4".to_string(),
            params: Some(vec![
                serde_json::json!(val.payload),
                serde_json::json!(val.expected_blob_versioned_hashes),
                serde_json::json!(val.parent_beacon_block_root),
                serde_json::json!(val.execution_requests),
            ]),
            ..Default::default()
        }
    }
}

impl RpcHandler for NewPayloadV4Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 4 {
            return Err(RpcErr::BadParams("Expected 4 params".to_owned()));
        }
        Ok(NewPayloadV4Request {
            payload: serde_json::from_value(params[0].clone())
                .map_err(|_| RpcErr::WrongParam("payload".to_string()))?,
            expected_blob_versioned_hashes: serde_json::from_value(params[1].clone())
                .map_err(|_| RpcErr::WrongParam("expected_blob_versioned_hashes".to_string()))?,
            parent_beacon_block_root: serde_json::from_value(params[2].clone())
                .map_err(|_| RpcErr::WrongParam("parent_beacon_block_root".to_string()))?,
            execution_requests: serde_json::from_value(params[3].clone())
                .map_err(|_| RpcErr::WrongParam("execution_requests".to_string()))?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        // EIP-7928 / Amsterdam: V4 payloads MUST NOT include the BAL field — that
        // field belongs to V5. Per engine-API spec, structurally-invalid payloads
        // return JSON-RPC -32602 (Invalid params), not PayloadStatus.INVALID.
        if self.payload.block_access_list.is_some() {
            return Err(RpcErr::WrongParam(
                "block_access_list not allowed in engine_newPayloadV4".to_string(),
            ));
        }

        // validate the received requests
        validate_execution_requests(&self.execution_requests)?;

        let requests_hash = compute_requests_hash(&self.execution_requests);
        let block = match get_block_from_payload(
            &self.payload,
            Some(self.parent_beacon_block_root),
            Some(requests_hash),
            None,
        ) {
            Ok(block) => block,
            Err(err) => {
                return Ok(serde_json::to_value(PayloadStatus::invalid_with_err(
                    &err.to_string(),
                ))?);
            }
        };

        let chain_config = context.storage.get_chain_config();

        // Amsterdam-active timestamps must use V5, not V4. Per engine-API spec
        // (amsterdam.md): "Client software MUST return -38005: Unsupported fork
        // if the timestamp of payload is greater than or equal to the Amsterdam
        // activation timestamp."
        if chain_config.is_amsterdam_activated(block.header.timestamp) {
            return Err(RpcErr::UnsupportedFork(format!(
                "{:?}",
                chain_config.get_fork(block.header.timestamp)
            )));
        }

        if !chain_config.is_prague_activated(block.header.timestamp) {
            return Err(RpcErr::UnsupportedFork(format!(
                "{:?}",
                chain_config.get_fork(block.header.timestamp)
            )));
        }

        // A pre-Amsterdam header that carries block_access_list_hash produces a
        // block_hash that won't match the one ethrex reconstructs (the field is
        // omitted from the V4 header schema). That mismatch is surfaced as
        // PayloadStatus.INVALID via the normal block-hash check, matching the EELS
        // fixture test_invalid_pre_fork_block_with_bal_hash_field
        // [fork_BPO2ToAmsterdamAtTime15k-blockchain_test_engine] (INVALID_BLOCK_HASH,
        // no engine API error code).

        // We use v3 since the execution payload remains the same.
        validate_execution_payload_v3(&self.payload)?;
        let payload_status = handle_new_payload_v3(
            &self.payload,
            context,
            block,
            self.expected_blob_versioned_hashes.clone(),
            None,
            false,
        )
        .await?;
        serde_json::to_value(payload_status).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct NewPayloadV5Request {
    pub payload: ExecutionPayload,
    pub expected_blob_versioned_hashes: Vec<H256>,
    pub parent_beacon_block_root: H256,
    pub execution_requests: Vec<EncodedRequests>,
    /// The BAL hash computed from the raw RLP bytes as received (no re-encoding/sorting).
    /// This preserves the exact encoding from the payload for block hash validation.
    pub raw_bal_hash: Option<H256>,
    /// Set when `blockAccessList` was present as well-formed DATA (0x-prefixed hex)
    /// whose bytes are not a valid RLP encoding of the block access list. The engine
    /// spec mandates `{status: INVALID, latestValidHash: null}` for this — not a
    /// -32602 error, which is reserved for a missing or schema-invalid field
    /// (execution-apis amsterdam.md, engine_newPayloadV5 spec 3).
    pub undecodable_bal: bool,
}

impl From<NewPayloadV5Request> for RpcRequest {
    fn from(val: NewPayloadV5Request) -> Self {
        RpcRequest {
            method: "engine_newPayloadV5".to_string(),
            params: Some(vec![
                serde_json::json!(val.payload),
                serde_json::json!(val.expected_blob_versioned_hashes),
                serde_json::json!(val.parent_beacon_block_root),
                serde_json::json!(val.execution_requests),
            ]),
            ..Default::default()
        }
    }
}

impl RpcHandler for NewPayloadV5Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 4 {
            return Err(RpcErr::BadParams("Expected 4 params".to_owned()));
        }

        // Extract the raw BAL hash from the JSON payload before deserialization.
        // We hash the raw RLP bytes as-received to preserve the exact encoding
        // (including any ordering) for accurate block hash validation.
        let mut payload_value = params[0].clone();
        let mut undecodable_bal = false;
        let raw_bal_hash = payload_value
            .get("blockAccessList")
            .map(|v| {
                let hex_str = v
                    .as_str()
                    .ok_or(RpcErr::WrongParam("blockAccessList".to_string()))?;
                // EIP-7928 blockAccessList is a DATA field: the `0x` prefix is
                // mandatory. Reject an unprefixed value rather than trimming it.
                let hex_body = hex_str
                    .strip_prefix("0x")
                    .ok_or(RpcErr::WrongParam("blockAccessList".to_string()))?;
                let bytes = hex::decode(hex_body)
                    .map_err(|_| RpcErr::WrongParam("blockAccessList".to_string()))?;
                // Well-formed DATA whose bytes don't RLP-decode into a BAL must yield
                // `{status: INVALID}`, not -32602. Flag it here (the decision belongs
                // to `handle`, which can return a status) rather than failing parse.
                if BlockAccessList::decode(&bytes).is_err() {
                    undecodable_bal = true;
                }
                Ok::<_, RpcErr>(ethrex_common::utils::keccak(bytes))
            })
            .transpose()?;
        if undecodable_bal {
            // `ExecutionPayload`'s serde RLP-decodes the field and would fail the
            // whole params parse with -32602; drop it so deserialization succeeds
            // and `handle` can answer with the mandated INVALID status.
            if let Some(obj) = payload_value.as_object_mut() {
                obj.remove("blockAccessList");
            }
        }

        Ok(Self {
            payload: serde_json::from_value(payload_value)
                .map_err(|_| RpcErr::WrongParam("payload".to_string()))?,
            expected_blob_versioned_hashes: serde_json::from_value(params[1].clone())
                .map_err(|_| RpcErr::WrongParam("expected_blob_versioned_hashes".to_string()))?,
            parent_beacon_block_root: serde_json::from_value(params[2].clone())
                .map_err(|_| RpcErr::WrongParam("parent_beacon_block_root".to_string()))?,
            execution_requests: serde_json::from_value(params[3].clone())
                .map_err(|_| RpcErr::WrongParam("execution_requests".to_string()))?,
            raw_bal_hash,
            undecodable_bal,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        self.handle_with_witness(context, false).await
    }
}

impl NewPayloadV5Request {
    async fn handle_with_witness(
        &self,
        context: RpcApiContext,
        make_witness: bool,
    ) -> Result<Value, RpcErr> {
        // The block-level `[METRIC] BLOCK` line covers execution only. On a chain
        // of near-empty blocks the work this handler does around it ; decoding the
        // payload into a block and the pre-execution checks ; is the same order of
        // magnitude as the execution itself, and was previously unmeasured.
        let handler_start = Instant::now();
        // Must precede every other check: a present-but-undecodable BAL answers
        // `{status: INVALID, latestValidHash: null}` (engine spec, amsterdam.md
        // newPayloadV5 spec 3). The field was dropped from `self.payload` at parse
        // time, so falling through would misreport it as missing (-32602).
        if self.undecodable_bal {
            // Wording matters: EEST's ethrex exception mapper resolves
            // BlockException.INVALID_BLOCK_ACCESS_LIST by matching the substring
            // "Failed to RLP decode BAL" (the serde-layer message this path
            // predates). Keep it as the prefix so consume-engine attributes the
            // INVALID status to the right exception.
            return Ok(serde_json::to_value(PayloadStatus::invalid_with_err(
                "Failed to RLP decode BAL: blockAccessList is not a valid RLP \
                 encoding of the block access list",
            ))?);
        }
        validate_execution_payload_v5(&self.payload)?;

        // validate the received requests
        validate_execution_requests(&self.execution_requests)?;

        let requests_hash = compute_requests_hash(&self.execution_requests);
        // Use the hash computed from the raw RLP bytes as-received.
        // This preserves the exact encoding (including any ordering) from the payload,
        // so the block hash check correctly detects BAL corruption.
        let block_access_list_hash = self.raw_bal_hash;

        let decode_start = Instant::now();
        let block = match get_block_from_payload(
            &self.payload,
            Some(self.parent_beacon_block_root),
            Some(requests_hash),
            block_access_list_hash,
        ) {
            Ok(block) => block,
            Err(err) => {
                return Ok(serde_json::to_value(PayloadStatus::invalid_with_err(
                    &err.to_string(),
                ))?);
            }
        };
        let decode_elapsed = decode_start.elapsed();

        let chain_config = context.storage.get_chain_config();

        // Pre-Amsterdam timestamps must use V4, not V5. Per engine-API spec
        // (amsterdam.md): "Client software MUST return -38005: Unsupported fork
        // if the timestamp of the payload does not fall within the time frame of
        // the Amsterdam activation." Symmetric with the V4+Amsterdam case above.
        if !chain_config.is_amsterdam_activated(block.header.timestamp) {
            return Err(RpcErr::UnsupportedFork(format!(
                "{:?}",
                chain_config.get_fork(block.header.timestamp)
            )));
        }

        // EIP-7928 fork-boundary detector: V5 requires block_access_list_hash in
        // the header. If the payload's block_hash matches what a V4-style header
        // (without the field) would produce, the sender used the wrong API
        // version; reject with -32602 (InvalidParams) to match the EELS fixture
        // test_invalid_post_fork_block_without_bal_hash_field
        // [fork_BPO2ToAmsterdamAtTime15k-blockchain_test_engine]. Real
        // value-mismatch tests don't match this alternate and fall through to
        // PayloadStatus.INVALID.
        if block.hash() != self.payload.block_hash {
            let mut alt_header = block.header.clone();
            alt_header.block_access_list_hash = None;
            let alt_hash = alt_header.compute_block_hash(&ethrex_crypto::NativeCrypto);
            if alt_hash == self.payload.block_hash {
                return Err(RpcErr::WrongParam(
                    "engine_newPayloadV5 received header missing block_access_list_hash field"
                        .to_string(),
                ));
            }
        }

        let bal = self.payload.block_access_list.clone();
        let block_number = block.header.number;
        let tx_count = block.body.transactions.len();
        let execute_start = Instant::now();
        let payload_status = handle_new_payload_v4(
            &self.payload,
            context,
            block,
            self.expected_blob_versioned_hashes.clone(),
            bal,
            make_witness,
        )
        .await?;
        let execute_elapsed = execute_start.elapsed();
        let total_elapsed = handler_start.elapsed();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        // Whatever is neither payload decoding nor execution: the payload, request
        // and BAL-ordering validations plus the two block-hash comparisons.
        let checks_ms = (ms(total_elapsed) - ms(decode_elapsed) - ms(execute_elapsed)).max(0.0);
        info!(
            "[METRIC] NEWPAYLOAD {block_number} | {:.2} ms total | decode {:.2} ms | checks {:.2} ms | execute {:.2} ms | {tx_count} txs",
            ms(total_elapsed),
            ms(decode_elapsed),
            checks_ms,
            ms(execute_elapsed),
        );
        serde_json::to_value(payload_status).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct NewPayloadWithWitnessV5Request(pub NewPayloadV5Request);

impl From<NewPayloadWithWitnessV5Request> for RpcRequest {
    fn from(val: NewPayloadWithWitnessV5Request) -> Self {
        RpcRequest {
            method: "engine_newPayloadWithWitnessV5".to_string(),
            params: Some(vec![
                serde_json::json!(val.0.payload),
                serde_json::json!(val.0.expected_blob_versioned_hashes),
                serde_json::json!(val.0.parent_beacon_block_root),
                serde_json::json!(val.0.execution_requests),
            ]),
            ..Default::default()
        }
    }
}

impl RpcHandler for NewPayloadWithWitnessV5Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        NewPayloadV5Request::parse(params).map(Self)
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        self.0.handle_with_witness(context, true).await
    }
}

// GetPayload V1-V2-V3 implementations
pub struct GetPayloadV1Request {
    pub payload_id: u64,
}

impl RpcHandler for GetPayloadV1Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let payload_id = parse_get_payload_request(params)?;
        Ok(Self { payload_id })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let payload_bundle = get_payload(self.payload_id, &context).await?;
        // NOTE: This validation is actually not required to run Hive tests. Not sure if it's
        // necessary
        validate_payload_v1_v2(&payload_bundle.block, &context)?;

        // V1 doesn't support BAL (pre-EIP-7928)
        let response = ExecutionPayload::from_block(payload_bundle.block, None);

        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct GetPayloadV2Request {
    pub payload_id: u64,
}

impl RpcHandler for GetPayloadV2Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let payload_id = parse_get_payload_request(params)?;
        Ok(Self { payload_id })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let payload_bundle = get_payload(self.payload_id, &context).await?;
        validate_payload_v1_v2(&payload_bundle.block, &context)?;

        // V2 doesn't support BAL (pre-EIP-7928)
        let response = ExecutionPayloadResponse {
            execution_payload: ExecutionPayload::from_block(payload_bundle.block, None),
            block_value: payload_bundle.block_value,
            blobs_bundle: None,
            should_override_builder: None,
            execution_requests: None,
        };

        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct GetPayloadV3Request {
    pub payload_id: u64,
}

impl From<GetPayloadV3Request> for RpcRequest {
    fn from(val: GetPayloadV3Request) -> Self {
        RpcRequest {
            method: "engine_getPayloadV3".to_string(),
            params: Some(vec![serde_json::json!(U256::from(val.payload_id))]),
            ..Default::default()
        }
    }
}

impl RpcHandler for GetPayloadV3Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let payload_id = parse_get_payload_request(params)?;
        Ok(Self { payload_id })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let payload_bundle = get_payload(self.payload_id, &context).await?;
        validate_fork(&payload_bundle.block, Fork::Cancun, &context)?;

        // V3 doesn't support BAL (Cancun fork, pre-EIP-7928)
        let response = ExecutionPayloadResponse {
            execution_payload: ExecutionPayload::from_block(payload_bundle.block, None),
            block_value: payload_bundle.block_value,
            blobs_bundle: Some(payload_bundle.blobs_bundle),
            should_override_builder: Some(false),
            execution_requests: None,
        };

        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct GetPayloadV4Request {
    pub payload_id: u64,
}

impl From<GetPayloadV4Request> for RpcRequest {
    fn from(val: GetPayloadV4Request) -> Self {
        RpcRequest {
            method: "engine_getPayloadV4".to_string(),
            params: Some(vec![serde_json::json!(U256::from(val.payload_id))]),
            ..Default::default()
        }
    }
}

impl RpcHandler for GetPayloadV4Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let payload_id = parse_get_payload_request(params)?;
        Ok(Self { payload_id })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let payload_bundle = get_payload(self.payload_id, &context).await?;
        let chain_config = &context.storage.get_chain_config();

        if !chain_config.is_prague_activated(payload_bundle.block.header.timestamp) {
            return Err(RpcErr::UnsupportedFork(format!(
                "{:?}",
                chain_config.get_fork(payload_bundle.block.header.timestamp)
            )));
        }
        if chain_config.is_osaka_activated(payload_bundle.block.header.timestamp) {
            return Err(RpcErr::UnsupportedFork(format!("{:?}", Fork::Osaka)));
        }

        // V4 doesn't support BAL (Prague fork, pre-EIP-7928)
        let response = ExecutionPayloadResponse {
            execution_payload: ExecutionPayload::from_block(payload_bundle.block, None),
            block_value: payload_bundle.block_value,
            blobs_bundle: Some(payload_bundle.blobs_bundle),
            should_override_builder: Some(false),
            execution_requests: Some(
                payload_bundle
                    .requests
                    .into_iter()
                    .filter(|r| !r.is_empty())
                    .collect(),
            ),
        };

        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct GetPayloadV5Request {
    pub payload_id: u64,
}

impl From<GetPayloadV5Request> for RpcRequest {
    fn from(val: GetPayloadV5Request) -> Self {
        RpcRequest {
            method: "engine_getPayloadV5".to_string(),
            params: Some(vec![serde_json::json!(U256::from(val.payload_id))]),
            ..Default::default()
        }
    }
}

impl RpcHandler for GetPayloadV5Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let payload_id = parse_get_payload_request(params)?;
        Ok(Self { payload_id })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let payload_bundle = get_payload(self.payload_id, &context).await?;
        let chain_config = &context.storage.get_chain_config();

        if !chain_config.is_osaka_activated(payload_bundle.block.header.timestamp)
            || chain_config.is_amsterdam_activated(payload_bundle.block.header.timestamp)
        {
            return Err(RpcErr::UnsupportedFork(format!(
                "{:?}",
                chain_config.get_fork(payload_bundle.block.header.timestamp)
            )));
        }

        // V5 supports BAL before Amsterdam (EIP-7928)
        let response = ExecutionPayloadResponse {
            execution_payload: ExecutionPayload::from_block(
                payload_bundle.block,
                payload_bundle.block_access_list,
            ),
            block_value: payload_bundle.block_value,
            blobs_bundle: Some(payload_bundle.blobs_bundle),
            should_override_builder: Some(false),
            execution_requests: Some(
                payload_bundle
                    .requests
                    .into_iter()
                    .filter(|r| !r.is_empty())
                    .collect(),
            ),
        };

        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct GetPayloadV6Request {
    pub payload_id: u64,
}

impl From<GetPayloadV6Request> for RpcRequest {
    fn from(val: GetPayloadV6Request) -> Self {
        RpcRequest {
            method: "engine_getPayloadV6".to_string(),
            params: Some(vec![serde_json::json!(U256::from(val.payload_id))]),
            ..Default::default()
        }
    }
}

impl RpcHandler for GetPayloadV6Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let payload_id = parse_get_payload_request(params)?;
        Ok(Self { payload_id })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let payload_bundle = get_payload(self.payload_id, &context).await?;
        let chain_config = &context.storage.get_chain_config();

        if !chain_config.is_amsterdam_activated(payload_bundle.block.header.timestamp) {
            return Err(RpcErr::UnsupportedFork(format!(
                "{:?}",
                chain_config.get_fork(payload_bundle.block.header.timestamp)
            )));
        }

        // V6 supports BAL (Amsterdam EL fork / Glamsterdam, EIP-7928)
        let response = ExecutionPayloadResponse {
            execution_payload: ExecutionPayload::from_block(
                payload_bundle.block,
                payload_bundle.block_access_list,
            ),
            block_value: payload_bundle.block_value,
            blobs_bundle: Some(payload_bundle.blobs_bundle),
            should_override_builder: Some(false),
            execution_requests: Some(
                payload_bundle
                    .requests
                    .into_iter()
                    .filter(|r| !r.is_empty())
                    .collect(),
            ),
        };

        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

pub struct GetPayloadBodiesByHashV1Request {
    pub hashes: Vec<BlockHash>,
}

impl RpcHandler for GetPayloadBodiesByHashV1Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 1 {
            return Err(RpcErr::BadParams("Expected 1 param".to_owned()));
        };

        Ok(GetPayloadBodiesByHashV1Request {
            hashes: serde_json::from_value(params[0].clone())?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        if self.hashes.len() as u64 > GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE {
            return Err(RpcErr::TooLargeRequest);
        }
        let mut bodies = Vec::new();
        for hash in self.hashes.iter() {
            bodies.push(context.storage.get_block_body_by_hash(*hash).await?)
        }
        build_payload_body_response(bodies)
    }
}

pub struct GetPayloadBodiesByRangeV1Request {
    start: BlockNumber,
    count: u64,
}

impl RpcHandler for GetPayloadBodiesByRangeV1Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 2 {
            return Err(RpcErr::BadParams("Expected 1 param".to_owned()));
        };
        let start = parse_json_hex(&params[0]).map_err(|_| RpcErr::BadHexFormat(0))?;
        let count = parse_json_hex(&params[1]).map_err(|_| RpcErr::BadHexFormat(1))?;
        if start < 1 {
            return Err(RpcErr::WrongParam("start".to_owned()));
        }
        if count < 1 {
            return Err(RpcErr::WrongParam("count".to_owned()));
        }
        Ok(GetPayloadBodiesByRangeV1Request { start, count })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        if self.count > GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE {
            return Err(RpcErr::TooLargeRequest);
        }
        let latest_block_number = context.storage.get_latest_block_number()?;
        // NOTE: we truncate the range because the spec says we "MUST NOT return trailing
        // null values if the request extends past the current latest known block"
        let last = latest_block_number.min(self.start + self.count - 1);
        let bodies = context.storage.get_block_bodies(self.start, last).await?;
        build_payload_body_response(bodies)
    }
}

fn build_payload_body_response(bodies: Vec<Option<BlockBody>>) -> Result<Value, RpcErr> {
    let response: Vec<Option<ExecutionPayloadBody>> = bodies
        .into_iter()
        .map(|body| body.map(Into::into))
        .collect();
    serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
}

/// Returns the block's BAL for V2 payload-body responses.
///
/// Reads the persisted BAL first; only when it is absent (pre-Amsterdam blocks,
/// or Amsterdam blocks processed before BAL persistence was added) does it fall
/// back to regenerating via re-execution, which requires the parent state trie
/// and fails on snap-synced nodes that don't hold that historical state.
fn bal_for_block(
    context: &RpcApiContext,
    block: &Block,
) -> Result<Option<BlockAccessList>, RpcErr> {
    let block_hash = block.hash();
    let commitment = block.header.block_access_list_hash;
    if let Some(bal) = context.storage.get_block_access_list(block_hash)? {
        // EIP-8159: never serve a BAL that doesn't match the header commitment.
        // A stale/empty entry (e.g. from a prior regeneration against state that
        // was later pruned) must degrade to "unavailable" rather than a wrong BAL.
        if bal.matches_commitment(commitment, &NativeCrypto) {
            return Ok(Some(bal));
        }
        warn!("Stored BAL for {block_hash} does not match header commitment; ignoring it");
    }
    let generated = context
        .blockchain
        .generate_bal_for_block(block)
        .map_err(|e| RpcErr::Internal(e.to_string()))?;
    // Only persist/serve a regenerated BAL if it matches the header commitment.
    // Regeneration re-executes against the parent state; if that state is gone
    // or stale the result can be empty/wrong, so guard before writing it back.
    let regenerated = generated.is_some();
    let Some(bal) = generated.filter(|bal| bal.matches_commitment(commitment, &NativeCrypto))
    else {
        // A successful regeneration whose hash doesn't match the commitment means
        // the block was re-executed against wrong/incomplete state; don't serve or
        // persist it. (Absent regeneration just means the state is unavailable.)
        if regenerated {
            warn!("Regenerated BAL for {block_hash} does not match header commitment; discarding");
        }
        return Ok(None);
    };
    // Write back so subsequent requests for this block are served from the
    // store instead of re-executing every time.
    if let Err(err) = context.storage.store_block_access_list(block_hash, &bal) {
        warn!("Failed to persist regenerated block access list for {block_hash}: {err}");
    }
    Ok(Some(bal))
}

// ==================== V2 Body Methods (EIP-7928) ====================

pub struct GetPayloadBodiesByHashV2Request {
    pub hashes: Vec<BlockHash>,
}

impl RpcHandler for GetPayloadBodiesByHashV2Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 1 {
            return Err(RpcErr::BadParams("Expected 1 param".to_owned()));
        };

        Ok(GetPayloadBodiesByHashV2Request {
            hashes: serde_json::from_value(params[0].clone())?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        if self.hashes.len() as u64 > GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE {
            return Err(RpcErr::TooLargeRequest);
        }

        let mut bodies: Vec<Option<ExecutionPayloadBodyV2>> = Vec::new();
        for hash in &self.hashes {
            let block = context.storage.get_block_by_hash(*hash).await?;
            let result = match block {
                Some(block) => {
                    let bal = bal_for_block(&context, &block)?;
                    Some(ExecutionPayloadBodyV2::from_body_with_bal(block.body, bal))
                }
                None => None,
            };
            bodies.push(result);
        }

        serde_json::to_value(bodies).map_err(|e| RpcErr::Internal(e.to_string()))
    }
}

pub struct GetPayloadBodiesByRangeV2Request {
    start: BlockNumber,
    count: u64,
}

impl RpcHandler for GetPayloadBodiesByRangeV2Request {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 2 {
            return Err(RpcErr::BadParams("Expected 2 params".to_owned()));
        };
        let start = parse_json_hex(&params[0]).map_err(|_| RpcErr::BadHexFormat(0))?;
        let count = parse_json_hex(&params[1]).map_err(|_| RpcErr::BadHexFormat(1))?;
        if start < 1 {
            return Err(RpcErr::WrongParam("start".to_owned()));
        }
        if count < 1 {
            return Err(RpcErr::WrongParam("count".to_owned()));
        }
        Ok(GetPayloadBodiesByRangeV2Request { start, count })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        if self.count > GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE {
            return Err(RpcErr::TooLargeRequest);
        }
        let latest_block_number = context.storage.get_latest_block_number()?;
        // NOTE: we truncate the range because the spec says we "MUST NOT return trailing
        // null values if the request extends past the current latest known block"
        let last = latest_block_number.min(self.start + self.count - 1);

        // Bulk fetch bodies (like V1)
        let block_bodies = context.storage.get_block_bodies(self.start, last).await?;

        let mut bodies: Vec<Option<ExecutionPayloadBodyV2>> = Vec::new();
        for (i, body_opt) in block_bodies.into_iter().enumerate() {
            let block_number = self.start + i as u64;
            let result = match body_opt {
                Some(body) => {
                    // Get header for this block
                    let header =
                        context
                            .storage
                            .get_block_header(block_number)?
                            .ok_or_else(|| {
                                RpcErr::Internal(format!(
                                    "Header not found for block {block_number}"
                                ))
                            })?;
                    let block = Block { header, body };

                    let bal = bal_for_block(&context, &block)?;
                    Some(ExecutionPayloadBodyV2::from_body_with_bal(block.body, bal))
                }
                None => None,
            };
            bodies.push(result);
        }

        serde_json::to_value(bodies).map_err(|e| RpcErr::Internal(e.to_string()))
    }
}

fn parse_execution_payload(params: &Option<Vec<Value>>) -> Result<ExecutionPayload, RpcErr> {
    let params = params
        .as_ref()
        .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
    if params.len() != 1 {
        return Err(RpcErr::BadParams("Expected 1 param".to_owned()));
    }
    serde_json::from_value(params[0].clone()).map_err(|_| RpcErr::WrongParam("payload".to_string()))
}

/// The Amsterdam payload fields (EIP-7928 block access list, EIP-7843 slot number) must be
/// absent from every pre-Amsterdam payload version.
fn reject_amsterdam_payload_fields(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    if payload.block_access_list.is_some() {
        return Err(RpcErr::WrongParam("block_access_list".to_string()));
    }
    if payload.slot_number.is_some() {
        return Err(RpcErr::WrongParam("slot_number".to_string()));
    }

    Ok(())
}

fn validate_execution_payload_v1(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    // Validate that only the required arguments are present
    if payload.withdrawals.is_some() {
        return Err(RpcErr::WrongParam("withdrawals".to_string()));
    }
    if payload.blob_gas_used.is_some() {
        return Err(RpcErr::WrongParam("blob_gas_used".to_string()));
    }
    if payload.excess_blob_gas.is_some() {
        return Err(RpcErr::WrongParam("excess_blob_gas".to_string()));
    }

    reject_amsterdam_payload_fields(payload)
}

fn validate_execution_payload_v2(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    // Validate that only the required arguments are present
    if payload.withdrawals.is_none() {
        return Err(RpcErr::WrongParam("withdrawals".to_string()));
    }
    if payload.blob_gas_used.is_some() {
        return Err(RpcErr::WrongParam("blob_gas_used".to_string()));
    }
    if payload.excess_blob_gas.is_some() {
        return Err(RpcErr::WrongParam("excess_blob_gas".to_string()));
    }

    reject_amsterdam_payload_fields(payload)
}

/// Fields shared by every payload version from Cancun onwards.
fn validate_execution_payload_cancun_fields(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    if payload.withdrawals.is_none() {
        return Err(RpcErr::WrongParam("withdrawals".to_string()));
    }
    if payload.blob_gas_used.is_none() {
        return Err(RpcErr::WrongParam("blob_gas_used".to_string()));
    }
    if payload.excess_blob_gas.is_none() {
        return Err(RpcErr::WrongParam("excess_blob_gas".to_string()));
    }

    Ok(())
}

/// Shared by `engine_newPayloadV3` and `engine_newPayloadV4`, both of which predate Amsterdam.
fn validate_execution_payload_v3(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    // Validate that only the required arguments are present
    validate_execution_payload_cancun_fields(payload)?;

    reject_amsterdam_payload_fields(payload)
}

#[inline]
fn validate_execution_payload_v4(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    // The Amsterdam payload shape: the Cancun fields plus a block access list. Reached only
    // through `validate_execution_payload_v5`, so the Amsterdam fields are required here
    // rather than rejected.

    if payload.block_access_list.is_none() {
        return Err(RpcErr::WrongParam("block_access_list".to_string()));
    }

    validate_execution_payload_cancun_fields(payload)?;

    Ok(())
}

#[inline]
fn validate_execution_payload_v5(payload: &ExecutionPayload) -> Result<(), RpcErr> {
    validate_execution_payload_v4(payload)?;

    if payload.slot_number.is_none() {
        return Err(RpcErr::WrongParam("slot_number".to_string()));
    }

    Ok(())
}

fn validate_payload_v1_v2(block: &Block, context: &RpcApiContext) -> Result<(), RpcErr> {
    let chain_config = &context.storage.get_chain_config();
    if chain_config.is_cancun_activated(block.header.timestamp) {
        return Err(RpcErr::UnsupportedFork(
            "Cancun payload received".to_string(),
        ));
    }
    Ok(())
}

// This function is used to make sure neither the current block nor its parent have been invalidated
async fn validate_ancestors(
    block: &Block,
    context: &RpcApiContext,
) -> Result<Option<PayloadStatus>, RpcErr> {
    // Check if the block has already been invalidated
    if let Some(latest_valid_hash) = context
        .storage
        .get_latest_valid_ancestor(block.hash())
        .await?
    {
        return Ok(Some(PayloadStatus::invalid_with(
            latest_valid_hash,
            "Header has been previously invalidated.".into(),
        )));
    }

    // Check if the parent block has already been invalidated
    if let Some(latest_valid_hash) = context
        .storage
        .get_latest_valid_ancestor(block.header.parent_hash)
        .await?
    {
        // Invalidate child too
        context
            .storage
            .set_latest_valid_ancestor(block.header.hash(), latest_valid_hash)
            .await?;
        return Ok(Some(PayloadStatus::invalid_with(
            latest_valid_hash,
            "Parent header has been previously invalidated.".into(),
        )));
    }

    Ok(None)
}

async fn handle_new_payload_v1_v2(
    payload: &ExecutionPayload,
    block: Block,
    context: RpcApiContext,
    bal: Option<BlockAccessList>,
    make_witness: bool,
) -> Result<PayloadStatus, RpcErr> {
    let Some(syncer) = &context.syncer else {
        return Err(RpcErr::Internal(
            "New payload requested but syncer is not initialized".to_string(),
        ));
    };
    // Validate block hash
    if let Err(RpcErr::Internal(error_msg)) = validate_block_hash(payload, &block) {
        return Ok(PayloadStatus::invalid_with_err(&error_msg));
    }

    // Check for invalid ancestors
    if let Some(status) = validate_ancestors(&block, &context).await? {
        return Ok(status);
    }

    // We have validated ancestors, the parent is correct
    let latest_valid_hash = block.header.parent_hash;

    if syncer.sync_mode() == SyncMode::Snap {
        debug!("Snap sync in progress, skipping new payload validation");
        return Ok(PayloadStatus::syncing());
    }

    // All checks passed, execute payload
    let payload_status =
        try_execute_payload(block, &context, latest_valid_hash, bal, make_witness).await?;
    Ok(payload_status)
}

async fn handle_new_payload_v3(
    payload: &ExecutionPayload,
    context: RpcApiContext,
    block: Block,
    expected_blob_versioned_hashes: Vec<H256>,
    bal: Option<BlockAccessList>,
    make_witness: bool,
) -> Result<PayloadStatus, RpcErr> {
    // V3 specific: validate blob hashes
    let blob_versioned_hashes: Vec<H256> = block
        .body
        .transactions
        .iter()
        .flat_map(|tx| tx.blob_versioned_hashes())
        .collect();

    if expected_blob_versioned_hashes != blob_versioned_hashes {
        return Ok(PayloadStatus::invalid_with_err(
            "Invalid blob_versioned_hashes",
        ));
    }

    handle_new_payload_v1_v2(payload, block, context, bal, make_witness).await
}

async fn handle_new_payload_v4(
    payload: &ExecutionPayload,
    context: RpcApiContext,
    block: Block,
    expected_blob_versioned_hashes: Vec<H256>,
    bal: Option<BlockAccessList>,
    make_witness: bool,
) -> Result<PayloadStatus, RpcErr> {
    if let Some(bal) = &bal
        && let Err(err) = bal.validate_ordering()
    {
        return Ok(PayloadStatus::invalid_with_err(&err));
    }
    handle_new_payload_v3(
        payload,
        context,
        block,
        expected_blob_versioned_hashes,
        bal,
        make_witness,
    )
    .await
}

// Elements of the list MUST be ordered by request_type in ascending order.
// Elements with empty request_data MUST be excluded from the list.
fn validate_execution_requests(execution_requests: &[EncodedRequests]) -> Result<(), RpcErr> {
    let mut last_type: i32 = -1;
    for requests in execution_requests {
        if requests.0.len() < 2 {
            return Err(RpcErr::WrongParam("Empty requests data.".to_string()));
        }
        let request_type = requests.0[0] as i32;
        if last_type >= request_type {
            return Err(RpcErr::WrongParam("Invalid requests order.".to_string()));
        }
        last_type = request_type;
    }
    Ok(())
}

fn get_block_from_payload(
    payload: &ExecutionPayload,
    parent_beacon_block_root: Option<H256>,
    requests_hash: Option<H256>,
    block_access_list_hash: Option<H256>,
) -> Result<Block, RLPDecodeError> {
    let block_hash = payload.block_hash;
    let block_number = payload.block_number;
    debug!(%block_hash, %block_number, "Received new payload");

    payload.clone().into_block(
        parent_beacon_block_root,
        requests_hash,
        block_access_list_hash,
    )
}

fn validate_block_hash(payload: &ExecutionPayload, block: &Block) -> Result<(), RpcErr> {
    let block_hash = payload.block_hash;
    let actual_block_hash = block.hash();
    if block_hash != actual_block_hash {
        return Err(RpcErr::Internal(format!(
            "Invalid block hash. Expected {actual_block_hash:#x}, got {block_hash:#x}"
        )));
    }
    Ok(())
}

pub async fn add_block(
    ctx: &RpcApiContext,
    block: Block,
    bal: Option<BlockAccessList>,
    make_witness: bool,
) -> Result<Option<ExecutionWitness>, ChainError> {
    let (notify_send, notify_recv) = oneshot::channel();
    ctx.block_worker_channel
        .send((notify_send, block, bal, make_witness))
        .map_err(|e| {
            ChainError::Custom(format!(
                "failed to send block execution request to worker: {e}"
            ))
        })?;
    notify_recv
        .await
        .map_err(|e| ChainError::Custom(format!("failed to receive block execution result: {e}")))?
}

async fn try_execute_payload(
    block: Block,
    context: &RpcApiContext,
    latest_valid_hash: H256,
    bal: Option<BlockAccessList>,
    make_witness: bool,
) -> Result<PayloadStatus, RpcErr> {
    let Some(syncer) = &context.syncer else {
        return Err(RpcErr::Internal(
            "New payload requested but syncer is not initialized".to_string(),
        ));
    };
    let block_hash = block.hash();
    let block_number = block.header.number;
    let storage = &context.storage;
    // A deep-reorg apply pass swaps the layer cache and replays the side chain
    // through `add_block` directly. Executing a payload concurrently can enqueue
    // a `PersistMessage::Block` whose phase1 RCU-reads the pre-swap cache and
    // writes back after the swap, clobbering the freshly installed overlay —
    // replay reads would then fall through to old-chain disk state. Defer to
    // SYNCING (the CL retries) for the duration of the pass.
    if context.blockchain.is_reorg_in_progress() {
        return Ok(PayloadStatus::syncing());
    }
    // Fast path: if we already have this block's header AND its state is reachable,
    // we know it has been fully validated previously and can reply VALID (with a
    // witness if requested) without re-execution.
    //
    // The historical version of this check only inspected the header (issue
    // https://github.com/lambdaclass/ethrex/issues/1766) so that snap-sync
    // pre-pivot blocks ; whose bodies aren't downloaded locally ; could still be
    // marked VALID without trying to execute them. That fast path is preserved
    // below: when the state isn't materialized AND the parent state isn't
    // reachable either (the snap-sync condition), we still return VALID. The
    // only behavior change is that we fall through to re-execution when the
    // header is known but our local state was evicted (e.g. a deep-reorg
    // overlay install wiped the layer cache), as long as the parent state IS
    // reachable so the re-execution can succeed. This rebuilds the layer and
    // prevents subsequent FCUs from looping back into `reorg_apply_deep`.
    if let Some(known_header) = storage.get_block_header_by_hash(block_hash)? {
        let state_materialized = storage.is_state_in_layer_cache(known_header.state_root)?
            || storage.has_state_root(known_header.state_root)?;
        if state_materialized {
            return payload_status_for_existing_block(&block, context, make_witness).await;
        }
        // Header known but our state was evicted. Only re-execute when we can:
        // the parent state must be reachable (cache, disk, or overlay-backed)
        // for execution to make progress. Otherwise preserve the legacy
        // snap-sync fast-path and reply VALID without re-execution.
        let parent_reachable = match storage.get_block_header_by_hash(block.header.parent_hash)? {
            Some(parent) => {
                storage.is_state_in_layer_cache(parent.state_root)?
                    || storage.has_state_root(parent.state_root)?
            }
            None => false,
        };
        if !parent_reachable {
            return payload_status_for_existing_block(&block, context, make_witness).await;
        }
        // Fall through ; `add_block` below will re-execute and rebuild the layer.
    }

    // A payload whose parent block is known but whose parent *state* is not
    // reachable (neither on disk nor via the layer cache / overlay) must NOT be
    // executed here: execution would fail with `EvmError::DB("state root
    // missing")` and be mapped to INVALID, wrongly poisoning the CL's view of a
    // valid block. It is handled by the ACCEPTED-stash below, which stores the
    // block without executing and lets a later forkchoiceUpdated drive the
    // deep-reorg apply. (Previously a SYNCING guard here short-circuited this
    // exact case and returned SYNCING *without storing the block*, which
    // shadowed the stash entirely and left the deep-reorg replay with no blocks
    // to reorg to. `has_state_root` already cascades through the layer cache, so
    // that guard fired on precisely the stash's condition.) A parent block that
    // is entirely absent still falls through to `add_block` below and is
    // reported as `SYNCING` via `ParentNotFound`.

    // Defer eager execution when the parent block is known but its state is
    // not currently materialized (parent state neither in the layer cache nor
    // on disk). Stash the block in HEADERS+BODIES and return ACCEPTED; a later
    // forkchoiceUpdated pointing at this block (or a descendant) will drive
    // the deep-reorg apply path. Matches geth's `eth/catalyst/api.go` behavior
    // with the `HasBlockAndState` predicate.
    //
    // If the parent is itself unknown, fall through to `add_block` which
    // returns `ChainError::ParentNotFound` and stashes the block; handled
    // below as `SYNCING`, preserving existing behavior.
    if let Some(parent_header) = storage.get_block_header_by_hash(block.header.parent_hash)? {
        let parent_state = parent_header.state_root;
        let in_cache = storage.is_state_in_layer_cache(parent_state)?;
        let on_disk = !in_cache && storage.has_state_root(parent_state)?;
        if !in_cache && !on_disk {
            debug!(
                %block_hash,
                %block_number,
                parent_hash = %block.header.parent_hash,
                "Parent state not materialized; stashing payload as ACCEPTED"
            );
            storage.add_block(block).await?;
            return Ok(PayloadStatus::accepted());
        }
    }

    // Execute and store the block
    debug!(%block_hash, %block_number, "Executing payload");

    // Retain a copy so we can record it via `debug_getBadBlocks` if it turns out
    // to be invalid. `add_block` consumes the block, so we must clone beforehand;
    // this happens once per newPayload and is negligible next to block execution.
    let bad_block_candidate = block.clone();

    match add_block(context, block, bal, make_witness).await {
        Err(ChainError::ParentNotFound) => {
            // Start sync
            syncer.sync_to_head(block_hash);
            Ok(PayloadStatus::syncing())
        }
        // Parent block is present but its state isn't available yet (e.g. state
        // regeneration after a restart hasn't reached the CL head). This is a
        // SYNCING condition, not an error and not INVALID: trigger a sync and
        // report SYNCING so the CL keeps the (valid) block.
        Err(ChainError::ParentStateNotFound) => {
            debug!(%block_hash, "Parent state not found, returning SYNCING and triggering sync");
            syncer.sync_to_head(block_hash);
            Ok(PayloadStatus::syncing())
        }
        Err(ChainError::InvalidBlock(error)) => {
            warn!(%block_hash, %block_number, "Error executing block: {error}");
            context
                .storage
                .set_latest_valid_ancestor(block_hash, latest_valid_hash)
                .await?;
            context.storage.add_bad_block(bad_block_candidate).await?;
            Ok(PayloadStatus::invalid_with(
                latest_valid_hash,
                error.to_string(),
            ))
        }
        Err(ChainError::EvmError(error)) => {
            warn!(%block_hash, %block_number, "Error executing block: {error}");
            context
                .storage
                .set_latest_valid_ancestor(block_hash, latest_valid_hash)
                .await?;
            context.storage.add_bad_block(bad_block_candidate).await?;
            Ok(PayloadStatus::invalid_with(
                latest_valid_hash,
                error.to_string(),
            ))
        }
        Err(ChainError::StoreError(error)) => {
            warn!(%block_hash, %block_number, "Error storing block: {error}");
            Err(RpcErr::Internal(error.to_string()))
        }
        Err(e) => {
            error!("{e} for block {block_hash}");
            Err(RpcErr::Internal(e.to_string()))
        }
        Ok(witness) => {
            debug!("Block with hash {block_hash} executed and added to storage successfully");
            let mut status = PayloadStatus::valid_with_hash(block_hash);
            if make_witness {
                let witness = witness.ok_or_else(|| {
                    RpcErr::Internal("Payload executed without producing a witness".to_string())
                })?;
                status.witness = Some(encode_witness_for_engine_rpc(witness)?);
            }
            Ok(status)
        }
    }
}

async fn payload_status_for_existing_block(
    block: &Block,
    context: &RpcApiContext,
    make_witness: bool,
) -> Result<PayloadStatus, RpcErr> {
    let block_hash = block.hash();
    let mut status = PayloadStatus::valid_with_hash(block_hash);

    if make_witness {
        status.witness = Some(witness_for_existing_block(block, context).await?);
    }

    Ok(status)
}

async fn witness_for_existing_block(
    block: &Block,
    context: &RpcApiContext,
) -> Result<Bytes, RpcErr> {
    let block_hash = block.hash();
    if let Some(json_bytes) = context
        .storage
        .get_witness_json_bytes(block.header.number, block_hash)?
    {
        let rpc_witness = serde_json::from_slice(&json_bytes).map_err(|error| {
            RpcErr::Internal(format!("Failed to parse cached witness: {error}"))
        })?;
        return encode_rpc_witness_for_engine_rpc(rpc_witness);
    }

    let witness = context
        .blockchain
        .generate_witness_for_blocks(std::slice::from_ref(block))
        .await
        .map_err(|error| RpcErr::Internal(format!("Failed to build execution witness: {error}")))?;
    encode_witness_for_engine_rpc(witness)
}

fn encode_witness_for_engine_rpc(witness: ExecutionWitness) -> Result<Bytes, RpcErr> {
    let rpc_witness = RpcExecutionWitness::try_from(witness).map_err(|error| {
        RpcErr::Internal(format!("Failed to encode execution witness: {error}"))
    })?;
    encode_rpc_witness_for_engine_rpc(rpc_witness)
}

/// Encodes the witness in geth's opaque `engine_newPayloadWithWitness*` shape.
///
/// Format: geth returns `rlp.EncodeToBytes(proofs)` from `newPayload`, and
/// `stateless.Witness::EncodeRLP` delegates to [`ExtWitness`] — see its docs
/// for the shape and geth references.
/// Additional references:
/// https://github.com/ethereum/go-ethereum/blob/4daaaadfc4706b0a49d4dfde3559de7be968c28a/core/stateless/encoding.go#L92-L98
/// https://github.com/ethereum/go-ethereum/blob/4daaaadfc4706b0a49d4dfde3559de7be968c28a/eth/catalyst/api.go#L915-L920
fn encode_rpc_witness_for_engine_rpc(rpc_witness: RpcExecutionWitness) -> Result<Bytes, RpcErr> {
    let mut headers = rpc_witness
        .headers
        .iter()
        .map(|header| BlockHeader::decode(header.as_ref()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| RpcErr::Internal(format!("Failed to decode witness header: {error}")))?;
    headers.sort_by_key(|header| header.number);
    let mut codes = rpc_witness.codes;
    codes.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let mut state = rpc_witness.state;
    state.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let mut keys = rpc_witness.keys;
    keys.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let ext_witness = ExtWitness {
        headers,
        codes,
        state,
        keys,
    };
    Ok(Bytes::from(ext_witness.encode_to_vec()))
}

fn parse_get_payload_request(params: &Option<Vec<Value>>) -> Result<u64, RpcErr> {
    let params = params
        .as_ref()
        .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
    if params.len() != 1 {
        return Err(RpcErr::BadParams("Expected 1 param".to_owned()));
    };
    let Ok(hex_str) = serde_json::from_value::<String>(params[0].clone()) else {
        return Err(RpcErr::BadParams(
            "Expected param to be a string".to_owned(),
        ));
    };
    // Check that the hex string is 0x prefixed
    let Some(hex_str) = hex_str.strip_prefix("0x") else {
        return Err(RpcErr::BadHexFormat(0));
    };
    // Parse hex string
    let Ok(payload_id) = u64::from_str_radix(hex_str, 16) else {
        return Err(RpcErr::BadHexFormat(0));
    };
    Ok(payload_id)
}

fn validate_fork(block: &Block, fork: Fork, context: &RpcApiContext) -> Result<(), RpcErr> {
    // Check timestamp matches valid fork
    let chain_config = &context.storage.get_chain_config();
    let current_fork = chain_config.get_fork(block.header.timestamp);

    if current_fork != fork {
        return Err(RpcErr::UnsupportedFork(format!("{current_fork:?}")));
    }
    Ok(())
}

async fn get_payload(payload_id: u64, context: &RpcApiContext) -> Result<PayloadBundle, RpcErr> {
    info!(
        id = %format!("{:#018x}", payload_id),
        "Requested payload with"
    );
    let (blobs_bundle, requests, block_value, block, block_access_list) = {
        let PayloadBuildResult {
            blobs_bundle,
            block_value,
            requests,
            payload,
            block_access_list,
            ..
        } = context
            .blockchain
            .get_payload(payload_id)
            .await
            .map_err(|err| match err {
                ChainError::UnknownPayload => {
                    RpcErr::UnknownPayload(format!("Payload with id {payload_id:#018x} not found",))
                }
                err => RpcErr::Internal(err.to_string()),
            })?;
        (
            blobs_bundle,
            requests,
            block_value,
            payload,
            block_access_list,
        )
    };

    let new_payload = PayloadBundle {
        block,
        block_value,
        blobs_bundle,
        requests,
        block_access_list,
    };

    Ok(new_payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestContext, default_context_with_storage};
    use ethrex_common::types::ChainConfig;
    use ethrex_rlp::encode::RLPEncode;
    use ethrex_storage::{EngineType, Store};

    fn header(number: u64) -> BlockHeader {
        BlockHeader {
            number,
            ..Default::default()
        }
    }

    fn v5_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: H256::zero(),
            fee_recipient: Default::default(),
            state_root: H256::zero(),
            receipts_root: H256::zero(),
            logs_bloom: Default::default(),
            prev_randao: H256::zero(),
            block_number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::new(),
            base_fee_per_gas: 1,
            block_hash: H256::zero(),
            transactions: vec![],
            withdrawals: Some(vec![]),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            slot_number: Some(0),
            block_access_list: Some(BlockAccessList::default()),
            burned_fees: None,
        }
    }

    #[test]
    fn new_payload_with_witness_v5_parses_like_v5() {
        let params = Some(vec![
            serde_json::json!(v5_payload()),
            serde_json::json!(Vec::<H256>::new()),
            serde_json::json!(H256::zero()),
            serde_json::json!(Vec::<EncodedRequests>::new()),
        ]);

        let request = NewPayloadWithWitnessV5Request::parse(&params).unwrap();

        assert_eq!(request.0.payload.slot_number, Some(0));
        assert!(request.0.raw_bal_hash.is_some());
    }

    #[test]
    fn new_payload_v5_rejects_missing_slot_number() {
        let mut payload = v5_payload();
        payload.slot_number = None;

        let err = validate_execution_payload_v5(&payload).unwrap_err();

        assert!(matches!(err, RpcErr::WrongParam(param) if param == "slot_number"));
    }

    #[test]
    fn engine_witness_encoding_matches_geth_ext_witness_shape() {
        let header_1 = header(1);
        let header_2 = header(2);
        let witness = RpcExecutionWitness {
            headers: vec![
                header_2.encode_to_vec().into(),
                header_1.encode_to_vec().into(),
            ],
            codes: vec![
                Bytes::from_static(&[0x02]),
                Bytes::from_static(&[0x01, 0xff]),
                Bytes::from_static(&[0x01]),
            ],
            state: vec![
                Bytes::from_static(&[0xff]),
                Bytes::from_static(&[0x00]),
                Bytes::from_static(&[0x7f]),
            ],
            keys: vec![Bytes::from_static(&[0x03]), Bytes::from_static(&[0x02])],
        };

        let encoded = encode_rpc_witness_for_engine_rpc(witness).unwrap();

        let expected_headers = vec![header_1, header_2];
        let expected_codes = vec![
            Bytes::from_static(&[0x01]),
            Bytes::from_static(&[0x01, 0xff]),
            Bytes::from_static(&[0x02]),
        ];
        let expected_state = vec![
            Bytes::from_static(&[0x00]),
            Bytes::from_static(&[0x7f]),
            Bytes::from_static(&[0xff]),
        ];
        let expected_keys = vec![Bytes::from_static(&[0x02]), Bytes::from_static(&[0x03])];
        let expected = (
            expected_headers,
            expected_codes,
            expected_state,
            expected_keys,
        )
            .encode_to_vec();

        assert_eq!(encoded.as_ref(), expected.as_slice());
    }

    #[test]
    fn engine_witness_encoding_from_execution_witness_matches_expected_bytes() {
        let header_1 = header(1);
        let header_2 = header(2);
        let witness = ExecutionWitness {
            codes: vec![vec![0x02], vec![0x01]],
            block_headers_bytes: vec![header_2.encode_to_vec(), header_1.encode_to_vec()],
            first_block_number: 1,
            chain_config: ChainConfig::default(),
            state_trie_root: None,
            storage_trie_roots: Default::default(),
        };

        let encoded = encode_witness_for_engine_rpc(witness).unwrap();

        let expected = (
            vec![header_1, header_2],
            vec![Bytes::from_static(&[0x01]), Bytes::from_static(&[0x02])],
            Vec::<Bytes>::new(),
            Vec::<Bytes>::new(),
        )
            .encode_to_vec();
        assert_eq!(encoded.as_ref(), expected.as_slice());
    }

    async fn test_context() -> TestContext {
        let storage = Store::new("test-payload-bodies", EngineType::InMemory)
            .expect("Failed to create test store");
        default_context_with_storage(storage).await
    }

    #[tokio::test]
    async fn get_payload_bodies_by_hash_v1_accepts_exactly_max_size() {
        // Spec: clients MUST support request sizes of at least the max constant, so
        // exactly MAX must be served, not rejected.
        let request = GetPayloadBodiesByHashV1Request {
            hashes: vec![BlockHash::default(); GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE as usize],
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(!matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_hash_v1_rejects_above_max_size() {
        let request = GetPayloadBodiesByHashV1Request {
            hashes: vec![BlockHash::default(); GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE as usize + 1],
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_range_v1_accepts_exactly_max_size() {
        let request = GetPayloadBodiesByRangeV1Request {
            start: 1,
            count: GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE,
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(!matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_range_v1_rejects_above_max_size() {
        let request = GetPayloadBodiesByRangeV1Request {
            start: 1,
            count: GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE + 1,
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_hash_v2_accepts_exactly_max_size() {
        let request = GetPayloadBodiesByHashV2Request {
            hashes: vec![BlockHash::default(); (GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE) as usize],
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(!matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_hash_v2_rejects_above_max_size() {
        let request = GetPayloadBodiesByHashV2Request {
            hashes: vec![BlockHash::default(); (GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE + 1) as usize],
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_range_v2_accepts_exactly_max_size() {
        let request = GetPayloadBodiesByRangeV2Request {
            start: 1,
            count: GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE,
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(!matches!(result, Err(RpcErr::TooLargeRequest)));
    }

    #[tokio::test]
    async fn get_payload_bodies_by_range_v2_rejects_above_max_size() {
        let request = GetPayloadBodiesByRangeV2Request {
            start: 1,
            count: GET_PAYLOAD_BODIES_REQUEST_MAX_SIZE + 1,
        };
        let result = request.handle(test_context().await.clone()).await;
        assert!(matches!(result, Err(RpcErr::TooLargeRequest)));
    }
}
