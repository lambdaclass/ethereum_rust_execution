//! `eth_simulateV1`: simulate a chain of blocks with per-block state/block
//! overrides and call lists (execution-apis `ethSimulate`).
//!
//! Request parsing and response serialization live here; the execution engine
//! is [`ethrex_blockchain::simulate`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain,
    simulate::{
        MAX_SIMULATE_BLOCKS, SimBlockOverrides, SimulatedBlock, SimulatedCallError,
        SimulationBlockSpec, SimulationError, SimulationRequest,
    },
};
use ethrex_common::types::{ChainConfig, GenericTransaction};
use ethrex_common::{H256, serde_utils};
use ethrex_crypto::NativeCrypto;
use ethrex_vm::TxValidationError;
use ethrex_vm::backends::VMType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use ethrex_rlp::encode::RLPEncode;

use crate::{
    rpc::{RpcApiContext, RpcHandler},
    types::{
        block::{BlockBodyWrapper, FullBlockBody, RpcBlock},
        block_identifier::{BlockIdentifier, BlockIdentifierOrHash},
        block_override::BlockOverrideSet,
        receipt::RpcLog,
        state_override::StateOverrideSet,
        transaction::RpcTransaction,
    },
    utils::RpcErr,
};

/// Wall-clock budget for the whole simulation (mirrors the `debug_traceCall`
/// timeout; geth's `--rpc.evmtimeout` defaults to 5s as well).
const SIMULATE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct EthSimulateRequest {
    pub payload: SimulatePayload,
    /// Second param: the base block to simulate on. Defaults to `latest`.
    pub block: BlockIdentifierOrHash,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulatePayload {
    pub block_state_calls: Vec<BlockStateCall>,
    #[serde(default)]
    pub trace_transfers: bool,
    #[serde(default)]
    pub validation: bool,
    #[serde(default)]
    pub return_full_transactions: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockStateCall {
    #[serde(default)]
    pub block_overrides: Option<BlockOverrideSet>,
    #[serde(default)]
    pub state_overrides: Option<StateOverrideSet>,
    #[serde(default)]
    pub calls: Vec<GenericTransaction>,
}

/// One simulated block in the response: the `eth_getBlockByHash` shape
/// extended with per-call results.
///
/// Serialize-only: flattening `RpcBlock` (which itself flattens an untagged
/// body enum) is only fragile in the Deserialize direction, so this type must
/// never derive `Deserialize`.
#[derive(Debug, Serialize)]
pub struct RpcSimulatedBlock {
    #[serde(flatten)]
    pub block: RpcBlock,
    pub calls: Vec<SimulateCallResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateCallResult {
    /// "0x1" success / "0x0" failure.
    #[serde(with = "serde_utils::bool")]
    pub status: bool,
    #[serde(with = "serde_utils::bytes")]
    pub return_data: Bytes,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub gas_used: u64,
    /// Gas consumed before refunds.
    #[serde(with = "serde_utils::u64::hex_str")]
    pub max_used_gas: u64,
    /// Always serialized; empty for failed calls.
    pub logs: Vec<RpcLog>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SimulateCallErrorJson>,
}

#[derive(Debug, Serialize)]
pub struct SimulateCallErrorJson {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl RpcHandler for EthSimulateRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<EthSimulateRequest, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.is_empty() || params.len() > 2 {
            return Err(RpcErr::BadParams(format!(
                "Expected one or two params, got {}",
                params.len()
            )));
        }
        // The method's spec pins invalid payloads to -32602; the blanket
        // serde_json conversion would yield BadParams (-32000).
        let payload: SimulatePayload = serde_json::from_value(params[0].clone())
            .map_err(|error| invalid_params(format!("invalid simulate payload: {error}")))?;
        if payload.block_state_calls.is_empty() {
            return Err(invalid_params(
                "empty input: blockStateCalls must not be empty".to_string(),
            ));
        }
        if payload.block_state_calls.len() as u64 > MAX_SIMULATE_BLOCKS {
            return Err(RpcErr::EthSimulate {
                code: -38026,
                message: format!(
                    "client limit exceeded: too many blocks: {} > {MAX_SIMULATE_BLOCKS}",
                    payload.block_state_calls.len()
                ),
                data: None,
            });
        }
        let block = match params.get(1) {
            Some(value) if !value.is_null() => BlockIdentifierOrHash::parse(value.clone(), 1)?,
            _ => BlockIdentifierOrHash::Identifier(BlockIdentifier::default()),
        };
        Ok(EthSimulateRequest { payload, block })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let base_header = match self.block.resolve_block_header(&context.storage).await? {
            Some(header) => header,
            // The result schema is an array, so eth_call's `Null` convention
            // does not apply; unresolvable base blocks are an error.
            None => return Err(RpcErr::BadParams("header not found".to_owned())),
        };
        let chain_config = context.storage.get_chain_config();
        let vm_type = context.blockchain.vm_type()?;
        let request = SimulationRequest {
            blocks: self
                .payload
                .block_state_calls
                .iter()
                .cloned()
                .map(|entry| block_state_call_to_spec(entry, &base_header, &chain_config, vm_type))
                .collect::<Result<Vec<_>, _>>()?,
            base: base_header,
            validation: self.payload.validation,
            trace_transfers: self.payload.trace_transfers,
        };
        let blockchain: Arc<Blockchain> = context.blockchain.clone();
        let return_full_transactions = self.payload.return_full_transactions;

        let operation = move || -> Result<Value, RpcErr> {
            let simulated = blockchain
                .simulate_v1(request)
                .map_err(simulation_error_to_rpc)?;
            let blocks = simulated
                .into_iter()
                .map(|block| build_simulated_block(block, return_full_transactions))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(serde_json::to_value(blocks)?)
        };
        // Up to 256 blocks of EVM execution: run off the async runtime, with
        // a wall-clock cap.
        tokio::time::timeout(SIMULATE_TIMEOUT, tokio::task::spawn_blocking(operation))
            .await
            .map_err(|_| RpcErr::Internal("eth_simulateV1 timeout".to_string()))?
            .map_err(|_| RpcErr::Internal("Unexpected runtime error".to_string()))?
    }
}

fn invalid_params(message: String) -> RpcErr {
    RpcErr::EthSimulate {
        code: -32602,
        message,
        data: None,
    }
}

/// Convert one JSON `blockStateCalls` entry into the engine's spec type.
///
/// This is the only place a `blockStateCalls` entry's override sets are consumed, so it is
/// also where the block-override fields this method cannot honor are refused. The
/// `eth_call` family gets those refusals from [`BlockOverrideSet::apply_to`], which this
/// path deliberately does not use: it builds a whole block rather than overlaying one
/// header, so it honors `withdrawals`, which `apply_to` rejects.
fn block_state_call_to_spec(
    entry: BlockStateCall,
    base_header: &ethrex_common::types::BlockHeader,
    chain_config: &ChainConfig,
    vm_type: VMType,
) -> Result<SimulationBlockSpec, RpcErr> {
    let block_overrides = entry.block_overrides.unwrap_or_default();
    // Every field is mapped across by hand below, so anything left unmapped would parse
    // and then be silently ignored, answering with a plausible-looking but wrong result.
    // `blockHash` is the one field that cannot be honored, so it is refused with a reason.
    // `beaconRoot` *is* honored here, unlike on the `eth_call` family's `apply_to` path:
    // this engine runs the block's system calls, so the value reaches the EIP-4788 ring
    // buffer rather than just sitting on the header.
    if block_overrides.block_hash.is_some() {
        return Err(invalid_params(
            "blockHash is not supported: it is a reth/alloy extension, not part of the \
             eth_simulateV1 or geth Block Override Set"
                .to_string(),
        ));
    }
    // Fork-schedule hint for the blobBaseFee inversion: the resolved block
    // timestamp is not known until the engine sanitizes the chain, so the
    // override (or the base-relative default) approximates it. Only matters
    // for simulations crossing a blob-schedule fork boundary.
    let timestamp_hint = block_overrides
        .time
        .unwrap_or(base_header.timestamp.saturating_add(12));
    let excess_blob_gas = block_overrides.resolved_excess_blob_gas(chain_config, timestamp_hint);
    // Precompile-ness depends on the fork, and a `time` override can cross a fork
    // boundary, so resolve it against the effective timestamp rather than the base
    // header's — same reasoning as `convert_state_overrides` on the eth_call path.
    let fork = chain_config.fork(timestamp_hint);
    let state_overrides = entry
        .state_overrides
        .map(|set| set.into_overrides(fork, vm_type))
        .transpose()?
        .unwrap_or_default();
    Ok(SimulationBlockSpec {
        overrides: SimBlockOverrides {
            number: block_overrides.number,
            time: block_overrides.time,
            gas_limit: block_overrides.gas_limit,
            coinbase: block_overrides.coinbase,
            prev_randao: block_overrides.random,
            base_fee_per_gas: block_overrides.base_fee_per_gas,
            excess_blob_gas,
            difficulty: block_overrides.difficulty,
            withdrawals: block_overrides.withdrawals.unwrap_or_default(),
            beacon_root: block_overrides.beacon_root,
        },
        state_overrides,
        calls: entry.calls,
    })
}

/// Hydrate one engine result into its response shape: the block serialized
/// like `eth_getBlockByHash` plus per-call results with fully-qualified logs
/// (per-block `logIndex`, tx hash/index, block hash/number/timestamp).
fn build_simulated_block(
    simulated: SimulatedBlock,
    return_full_transactions: bool,
) -> Result<RpcSimulatedBlock, RpcErr> {
    let block_hash = simulated.block.header.hash();
    let block_number = simulated.block.header.number;
    let block_timestamp = simulated.block.header.timestamp;
    let tx_hashes: Vec<H256> = simulated
        .block
        .body
        .transactions
        .iter()
        .map(|tx| tx.hash(&NativeCrypto))
        .collect();

    let mut log_index: u64 = 0;
    let calls = simulated
        .calls
        .into_iter()
        .enumerate()
        .map(|(tx_index, call)| {
            let logs = call
                .logs
                .into_iter()
                .map(|log| {
                    let rpc_log = RpcLog {
                        log: log.into(),
                        log_index,
                        removed: false,
                        transaction_hash: tx_hashes.get(tx_index).copied().unwrap_or_default(),
                        transaction_index: tx_index as u64,
                        block_hash,
                        block_number,
                        block_timestamp,
                    };
                    log_index += 1;
                    rpc_log
                })
                .collect();
            SimulateCallResult {
                status: call.success,
                return_data: call.return_data,
                gas_used: call.gas_used,
                max_used_gas: call.max_used_gas,
                logs,
                error: call.error.map(|error| match error {
                    SimulatedCallError::Revert { output } => {
                        let data = format!("0x{}", hex::encode(&output));
                        SimulateCallErrorJson {
                            code: 3,
                            message: "execution reverted".to_string(),
                            data: Some(data),
                        }
                    }
                    SimulatedCallError::Halt { reason } => SimulateCallErrorJson {
                        code: -32015,
                        message: reason,
                        data: None,
                    },
                }),
            }
        })
        .collect();

    let block = if return_full_transactions {
        // RpcBlock::build recovers senders from signatures, which are zeroed
        // in simulated transactions — build the full body from the engine's
        // out-of-band senders instead.
        let transactions = simulated
            .block
            .body
            .transactions
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                RpcTransaction::build_with_sender(
                    tx.clone(),
                    Some(block_number),
                    Some(block_hash),
                    Some(index),
                    simulated.senders.get(index).copied().unwrap_or_default(),
                )
            })
            .collect();
        let size = simulated.block.length() as u64;
        RpcBlock {
            hash: block_hash,
            size,
            header: simulated.block.header,
            body: BlockBodyWrapper::Full(FullBlockBody {
                transactions,
                uncles: Vec::new(),
                withdrawals: simulated.block.body.withdrawals.unwrap_or_default(),
            }),
        }
    } else {
        RpcBlock::build(
            simulated.block.header,
            simulated.block.body,
            block_hash,
            false,
        )?
    };
    Ok(RpcSimulatedBlock { block, calls })
}

fn simulation_error_to_rpc(error: SimulationError) -> RpcErr {
    let message = error.to_string();
    let code = match &error {
        SimulationError::TooManyBlocks => -38026,
        SimulationError::BlockNumberNotAscending { .. } => -38020,
        SimulationError::TimestampNotAscending { .. } => -38021,
        SimulationError::BlockGasLimitReached { .. } => -38015,
        SimulationError::InvalidTx(validation_error) => validation_error_code(validation_error),
        SimulationError::InvalidParams(_) => -32602,
        SimulationError::Internal(_) => -32603,
    };
    RpcErr::EthSimulate {
        code,
        message,
        data: None,
    }
}

/// Spec error codes for transaction validation failures (geth
/// `internal/ethapi/errors.go` `txValidationError`).
fn validation_error_code(error: &TxValidationError) -> i32 {
    match error {
        TxValidationError::NonceMismatch { expected, actual } => {
            if actual < expected {
                -38010 // nonce too low
            } else {
                -38011 // nonce too high
            }
        }
        TxValidationError::NonceIsMax => -38011,
        TxValidationError::InsufficientMaxFeePerGas
        | TxValidationError::InsufficientMaxFeePerBlobGas { .. } => -38012,
        TxValidationError::IntrinsicGasTooLow
        | TxValidationError::IntrinsicGasBelowFloorGasCost => -38013,
        TxValidationError::InsufficientAccountFunds
        | TxValidationError::GasLimitPriceProductOverflow => -38014,
        TxValidationError::SenderNotEOA(_) => -38024,
        TxValidationError::InitcodeSizeExceeded { .. } => -38025,
        TxValidationError::PriorityGreaterThanMaxFeePerGas { .. }
        | TxValidationError::Type3TxPreFork
        | TxValidationError::Type3TxZeroBlobs
        | TxValidationError::Type3TxInvalidBlobVersionedHash
        | TxValidationError::Type3TxBlobCountExceeded { .. }
        | TxValidationError::Type3TxContractCreation
        | TxValidationError::Type4TxPreFork
        | TxValidationError::Type4TxAuthorizationListIsEmpty
        | TxValidationError::Type4TxContractCreation => -32602,
        _ => -32603,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::RpcErrorMetadata;
    use ethrex_common::Address;
    use ethrex_common::types::{Block, BlockBody, BlockHeader, Log, Receipt, TxKind};
    use serde_json::json;

    fn parse(params: Vec<Value>) -> Result<EthSimulateRequest, RpcErr> {
        EthSimulateRequest::parse(&Some(params))
    }

    fn error_code(err: RpcErr) -> i32 {
        RpcErrorMetadata::from(err).code
    }

    #[test]
    fn parse_defaults_block_to_latest_and_flags_to_false() {
        let is_latest = |request: &EthSimulateRequest| {
            matches!(
                request.block,
                BlockIdentifierOrHash::Identifier(BlockIdentifier::Tag(_))
            )
        };
        let request = parse(vec![json!({"blockStateCalls": [{}]})]).unwrap();
        assert!(is_latest(&request));
        assert!(!request.payload.trace_transfers);
        assert!(!request.payload.validation);
        assert!(!request.payload.return_full_transactions);
        // Explicit null block param behaves like a missing one.
        let request = parse(vec![json!({"blockStateCalls": [{}]}), Value::Null]).unwrap();
        assert!(is_latest(&request));
    }

    #[test]
    fn parse_accepts_tag_number_and_hash_block_params() {
        for block in [
            json!("latest"),
            json!("0x10"),
            json!("0x1234567890123456789012345678901234567890123456789012345678901234"),
            json!({"blockNumber": "0x10"}),
        ] {
            parse(vec![json!({"blockStateCalls": [{}]}), block]).unwrap();
        }
    }

    #[test]
    fn parse_rejects_wrong_arity() {
        assert!(parse(vec![]).is_err());
        assert!(
            parse(vec![
                json!({"blockStateCalls": [{}]}),
                json!("latest"),
                json!("extra")
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_maps_payload_errors_to_invalid_params() {
        // Missing blockStateCalls.
        assert_eq!(error_code(parse(vec![json!({})]).unwrap_err()), -32602);
        // Empty blockStateCalls.
        assert_eq!(
            error_code(parse(vec![json!({"blockStateCalls": []})]).unwrap_err()),
            -32602
        );
        // Unknown payload key.
        assert_eq!(
            error_code(parse(vec![json!({"blockStateCalls": [{}], "bogus": true})]).unwrap_err()),
            -32602
        );
        // Unknown blockStateCall key.
        assert_eq!(
            error_code(parse(vec![json!({"blockStateCalls": [{"bogus": true}]})]).unwrap_err()),
            -32602
        );
    }

    #[test]
    fn parse_rejects_too_many_block_state_calls() {
        let entries: Vec<Value> = (0..257).map(|_| json!({})).collect();
        let err = parse(vec![json!({"blockStateCalls": entries})]).unwrap_err();
        assert_eq!(error_code(err), -38026);
    }

    #[test]
    fn parse_call_objects_with_missing_fields() {
        // `{}` and from-only call objects are valid; missing `to` is a create.
        let request = parse(vec![json!({"blockStateCalls": [{"calls": [
            {},
            {"from": "0xc000000000000000000000000000000000000000"},
            {"input": "0x00"},
            {"data": "0x00"},
        ]}]})])
        .unwrap();
        let calls = &request.payload.block_state_calls[0].calls;
        assert_eq!(calls.len(), 4);
        assert!(matches!(calls[0].to, TxKind::Create));
        assert_eq!(calls[0].from, Address::zero());
        assert_eq!(calls[2].input, calls[3].input);
    }

    #[test]
    fn simulate_error_codes_map_to_spec() {
        assert_eq!(
            error_code(simulation_error_to_rpc(SimulationError::TooManyBlocks)),
            -38026
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(
                SimulationError::BlockNumberNotAscending { given: 1, prev: 2 }
            )),
            -38020
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(
                SimulationError::TimestampNotAscending { given: 1, prev: 2 }
            )),
            -38021
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(
                SimulationError::BlockGasLimitReached {
                    requested: 2,
                    remaining: 1
                }
            )),
            -38015
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(SimulationError::InvalidTx(
                TxValidationError::NonceMismatch {
                    expected: 5,
                    actual: 1
                }
            ))),
            -38010
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(SimulationError::InvalidTx(
                TxValidationError::NonceMismatch {
                    expected: 1,
                    actual: 5
                }
            ))),
            -38011
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(SimulationError::InvalidTx(
                TxValidationError::InsufficientMaxFeePerGas
            ))),
            -38012
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(SimulationError::InvalidTx(
                TxValidationError::IntrinsicGasTooLow
            ))),
            -38013
        );
        assert_eq!(
            error_code(simulation_error_to_rpc(SimulationError::InvalidTx(
                TxValidationError::InsufficientAccountFunds
            ))),
            -38014
        );
    }

    /// Exact-JSON tripwire for the `#[serde(flatten)]` of `RpcBlock` (which
    /// itself flattens header + untagged body): a change in the serialized
    /// shape of simulate results should fail here, not in hive.
    #[test]
    fn serialize_simulated_block_shape() {
        use ethrex_blockchain::simulate::SimulatedCallResult;

        let header = BlockHeader {
            number: 101,
            timestamp: 1012,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        let body = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: None,
        };
        let block = Block::new(header, body);
        let hash = block.header.hash();
        let simulated = SimulatedBlock {
            block,
            receipts: Vec::<Receipt>::new(),
            calls: vec![
                SimulatedCallResult {
                    success: true,
                    return_data: Bytes::new(),
                    gas_used: 21000,
                    max_used_gas: 21000,
                    logs: vec![Log {
                        address: Address::repeat_byte(0xee),
                        topics: vec![H256::zero()],
                        data: Bytes::from_static(&[0x01]),
                    }],
                    error: None,
                },
                SimulatedCallResult {
                    success: false,
                    return_data: Bytes::new(),
                    gas_used: 30000,
                    max_used_gas: 30000,
                    logs: vec![],
                    error: Some(SimulatedCallError::Revert {
                        output: Bytes::from_static(&[0xab, 0xcd]),
                    }),
                },
            ],
            senders: vec![Address::zero(), Address::zero()],
        };
        let value = serde_json::to_value(build_simulated_block(simulated, false).unwrap()).unwrap();

        // Block fields are flattened at the top level.
        assert_eq!(value["number"], json!("0x65"));
        assert_eq!(value["hash"], json!(format!("{hash:#x}")));
        assert!(value["transactions"].is_array());
        // Success call: status/gas/maxUsedGas/logs with blockTimestamp.
        let success = &value["calls"][0];
        assert_eq!(success["status"], json!("0x1"));
        assert_eq!(success["gasUsed"], json!("0x5208"));
        assert_eq!(success["maxUsedGas"], json!("0x5208"));
        assert_eq!(success["returnData"], json!("0x"));
        assert!(success.get("error").is_none());
        let log = &success["logs"][0];
        assert_eq!(log["logIndex"], json!("0x0"));
        assert_eq!(log["transactionIndex"], json!("0x0"));
        assert_eq!(log["blockNumber"], json!("0x65"));
        assert_eq!(log["blockTimestamp"], json!("0x3f4"));
        assert_eq!(log["removed"], json!(false));
        // Failed call: status 0x0, empty logs, revert error with data.
        let failure = &value["calls"][1];
        assert_eq!(failure["status"], json!("0x0"));
        assert_eq!(failure["logs"], json!([]));
        assert_eq!(failure["error"]["code"], json!(3));
        assert_eq!(failure["error"]["data"], json!("0xabcd"));
    }

    #[test]
    fn block_override_aliases_parse() {
        let set: BlockOverrideSet = serde_json::from_value(json!({
            "feeRecipient": "0x000000000000000000000000000000000000beef",
            "prevRandao": "0x000000000000000000000000000000000000000000000000000000000000dead",
            "blobBaseFee": "0x100",
            "withdrawals": [],
        }))
        .unwrap();
        assert!(set.coinbase.is_some());
        assert!(set.random.is_some());
        assert!(set.blob_base_fee_per_gas.is_some());
        assert_eq!(set.withdrawals.as_deref(), Some(&[][..]));
        assert!(!set.is_empty());
    }
}

/// End-to-end scenarios ported from the execution-apis `eth_simulateV1` `.io`
/// corpus, adapted to the `fixtures/genesis/l1.json` in-memory chain (the
/// hive fixtures use a pre-merge genesis ethrex cannot import, so responses
/// are asserted by JSON path rather than whole-body equality).
#[cfg(test)]
mod integration_tests {
    use crate::rpc::map_http_requests;
    use crate::test_utils::{default_context_with_storage, setup_store};
    use crate::utils::{RpcErr, RpcErrorMetadata, RpcRequest};
    use serde_json::{Value, json};

    /// Funded EOA from fixtures/genesis/l1.json (10^9 ETH).
    const RICH: &str = "0x00000a8d3f37af8def18832962ee008d8dca4f7b";
    /// Fresh addresses with no genesis state.
    const FRESH_A: &str = "0xc000000000000000000000000000000000000000";
    const FRESH_B: &str = "0xc100000000000000000000000000000000000000";

    /// Runs against the Amsterdam-activated genesis, for EIP-8037 / EIP-7928 behaviour.
    async fn simulate_amsterdam(params: Value) -> Result<Value, RpcErr> {
        let storage = crate::test_utils::setup_store_amsterdam().await;
        let context = default_context_with_storage(storage).await;
        let request: RpcRequest = serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_simulateV1", "params": params,
        }))
        .unwrap();
        map_http_requests(&request, context.clone()).await
    }

    /// Two calls that both create state: one writes a fresh storage slot, one creates a
    /// fresh account. Used to compare the block's `gasUsed` against the naive sum.
    fn state_creating_calls() -> Value {
        json!([{
            "blockStateCalls": [{
                // SSTORE(key=2, value=1): creates a storage slot, so state gas > 0.
                "stateOverrides": { FRESH_A: { "code": "0x6001600255" } },
                "calls": [
                    {"from": RICH, "to": FRESH_A, "gas": "0x100000"},
                    {"from": RICH, "to": FRESH_B, "value": "0x1", "gas": "0x100000"},
                ],
            }],
        }, "latest"])
    }

    /// Two calls under a 400_000 block gas limit, sized so the second fits the two
    /// EIP-8037 dimensions but not the pre-Amsterdam single budget.
    fn two_call_budget_request() -> Value {
        json!([{
            "blockStateCalls": [{
                "blockOverrides": { "gasLimit": "0x61a80" },
                "stateOverrides": { FRESH_A: { "code": "0x6001600255" } },
                "calls": [
                    {"from": RICH, "to": FRESH_A, "gas": "0x30d40"},
                    {"from": RICH, "to": FRESH_B, "value": "0x1", "gas": "0x46cd0"},
                ],
            }],
        }, "latest"])
    }

    fn block_and_call_gas(result: &Value) -> (u64, u64) {
        let block = &result.as_array().unwrap()[0];
        let hex = |v: &Value| {
            u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let block_gas = hex(&block["gasUsed"]);
        let call_sum = block["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| hex(&c["gasUsed"]))
            .sum();
        (block_gas, call_sum)
    }

    async fn simulate(params: Value) -> Result<Value, RpcErr> {
        let storage = setup_store().await;
        let context = default_context_with_storage(storage).await;
        let request: RpcRequest = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_simulateV1",
            "params": params,
        }))
        .unwrap();
        map_http_requests(&request, context.clone()).await
    }

    fn error_code(err: RpcErr) -> i32 {
        RpcErrorMetadata::from(err).code
    }

    /// Bytecode clearing storage slots 1..=n (`PUSH1 0; PUSH1 s; SSTORE` each, then
    /// STOP), with those slots pre-set to 1 by a state override. Mirrors geth's
    /// `clearSlots` helper in `core/eip8037_test.go`, so the gas figures below can be
    /// compared against the assertions geth makes on its own implementation.
    fn clear_slots(n: u8) -> (String, Value) {
        let mut code = String::from("0x");
        let mut state = serde_json::Map::new();
        for slot in 1..=n {
            // PUSH1 0x00; PUSH1 slot; SSTORE
            code.push_str(&format!("600060{slot:02x}55"));
            state.insert(format!("0x{slot:064x}"), json!(format!("0x{:064x}", 1)));
        }
        code.push_str("00"); // STOP
        (code, Value::Object(state))
    }

    /// `maxUsedGas` is the pre-refund figure, so a refunded call must report more of it
    /// than `gasUsed`, and with the refund hitting the EIP-3529 cap the two are related
    /// exactly by that cap. This is geth's own `TestRefundCappedAt20Percent` assertion
    /// (`core/eip8037_test.go`) applied through `eth_simulateV1`, and it pins the
    /// pre-Amsterdam reconstruction `gas_spent + gas_refunded` -- the report carries no
    /// pre-refund field before EIP-7778, so that sum is the only route to it.
    #[tokio::test]
    async fn max_used_gas_is_the_pre_refund_figure() {
        let (code, state) = clear_slots(3);
        let result = simulate(json!([{
            "blockStateCalls": [{
                "stateOverrides": { FRESH_A: { "code": code, "state": state } },
                "calls": [{"from": RICH, "to": FRESH_A, "gas": "0x100000"}],
            }],
        }, "latest"]))
        .await
        .unwrap();
        let call = &result.as_array().unwrap()[0]["calls"][0];
        let hex = |v: &Value| {
            u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let (gas_used, max_used) = (hex(&call["gasUsed"]), hex(&call["maxUsedGas"]));
        assert!(
            max_used > gas_used,
            "a refunded call must report maxUsedGas {max_used} above gasUsed {gas_used}"
        );
        // EIP-3529: refund is capped at a fifth of the pre-refund gas, and 3 cleared
        // slots (3 x 4800) exceed that cap, so the cap is what is applied.
        assert_eq!(
            gas_used,
            max_used - max_used / 5,
            "gasUsed should be maxUsedGas less the capped refund"
        );
    }

    /// The EIP-7623 calldata floor case, where ethrex and geth/reth part company.
    /// geth reports `max(pre_refund, floor)` (`settleGas`'s `peakUsed`) and reth
    /// `total_gas_spent().max(floor_gas())`; ethrex reconstructs `gas_spent +
    /// gas_refunded`, and once the floor binds `gas_spent` is the floor, so the refund
    /// is added on top of it instead of being absorbed by it.
    ///
    /// Pinned rather than fixed: before EIP-7778 the report sets `gas_used ==
    /// gas_spent`, so the pre-refund figure is not recoverable here at all once the
    /// floor has replaced it. Closing this needs that figure surfaced on
    /// `ExecutionReport`. The assertion below is the current behaviour; if it starts
    /// failing because `maxUsedGas` dropped to the floor, that gap was closed and this
    /// test should become an equality against `floor`.
    #[tokio::test]
    async fn max_used_gas_over_reports_when_the_calldata_floor_binds() {
        let (code, state) = clear_slots(1);
        // 1000 zero calldata bytes: EIP-7623 floor = 21000 + 10 * 1000 tokens = 31000,
        // which exceeds what this cheap call spends after its refund.
        let data = format!("0x{}", "00".repeat(1000));
        let result = simulate(json!([{
            "blockStateCalls": [{
                "stateOverrides": { FRESH_A: { "code": code, "state": state } },
                "calls": [{"from": RICH, "to": FRESH_A, "gas": "0x100000", "input": data}],
            }],
        }, "latest"]))
        .await
        .unwrap();
        let call = &result.as_array().unwrap()[0]["calls"][0];
        let hex = |v: &Value| {
            u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let (gas_used, max_used) = (hex(&call["gasUsed"]), hex(&call["maxUsedGas"]));
        const FLOOR: u64 = 21_000 + 10 * 1_000;
        const SSTORE_CLEAR_REFUND: u64 = 4_800;
        assert_eq!(
            gas_used, FLOOR,
            "the EIP-7623 floor should have replaced the post-refund gas"
        );
        // This call's pre-refund gas (~30_006) is under the floor, so geth's
        // `max(pre_refund, floor)` and reth's `total_gas_spent().max(floor_gas())`
        // both come out at FLOOR. ethrex adds the refund on top of the floor instead.
        assert_eq!(
            max_used,
            FLOOR + SSTORE_CLEAR_REFUND,
            "known divergence: geth and reth both report {FLOOR} here"
        );
    }

    #[tokio::test]
    async fn simple_transfer_with_balance_override() {
        // `ethSimulate-simple.io`: fund a fresh account via stateOverrides,
        // then transfer out of it.
        let result = simulate(json!([{
            "blockStateCalls": [{
                "stateOverrides": {FRESH_A: {"balance": "0xde0b6b3a7640000"}},
                "calls": [{"from": FRESH_A, "to": FRESH_B, "value": "0x1"}],
            }],
        }, "latest"]))
        .await
        .unwrap();
        let blocks = result.as_array().unwrap();
        assert_eq!(blocks.len(), 1);
        // Genesis is block 0, so the simulated block is 1.
        assert_eq!(blocks[0]["number"], json!("0x1"));
        let call = &blocks[0]["calls"][0];
        assert_eq!(call["status"], json!("0x1"));
        assert_eq!(call["gasUsed"], json!("0x5208"));
        assert_eq!(call["maxUsedGas"], json!("0x5208"));
        assert_eq!(call["returnData"], json!("0x"));
        assert_eq!(call["logs"], json!([]));
        // Hash-only transactions by default.
        assert!(blocks[0]["transactions"][0].is_string());
    }

    #[tokio::test]
    async fn empty_block_state_call_produces_empty_block() {
        // `ethSimulate-empty.io`.
        let result = simulate(json!([{"blockStateCalls": [{}]}, "latest"]))
            .await
            .unwrap();
        let blocks = result.as_array().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0]["calls"], json!([]));
        assert_eq!(blocks[0]["transactions"], json!([]));
        assert_eq!(blocks[0]["gasUsed"], json!("0x0"));
    }

    #[tokio::test]
    async fn block_numbers_must_ascend() {
        // `ethSimulate-block-num-order-38020.io`.
        let err = simulate(json!([{
            "blockStateCalls": [
                {"blockOverrides": {"number": "0x10"}},
                {"blockOverrides": {"number": "0x5"}},
            ],
        }, "latest"]))
        .await
        .unwrap_err();
        assert_eq!(error_code(err), -38020);
    }

    #[tokio::test]
    async fn timestamps_must_increase() {
        // `ethSimulate-block-timestamp-order-38021.io`: equal timestamps are
        // rejected too.
        let err = simulate(json!([{
            "blockStateCalls": [
                {"blockOverrides": {"time": "0x6668e112"}},
                {"blockOverrides": {"time": "0x6668e112"}},
            ],
        }, "latest"]))
        .await
        .unwrap_err();
        assert_eq!(error_code(err), -38021);
    }

    #[tokio::test]
    async fn explicit_gas_above_block_limit_aborts() {
        // `ethSimulate-run-out-of-gas-in-block-38015.io` (adapted): a small
        // gasLimit override plus an explicit call gas beyond it.
        let err = simulate(json!([{
            "blockStateCalls": [{
                "blockOverrides": {"gasLimit": "0x5208"},
                "calls": [{"from": RICH, "to": FRESH_B, "gas": "0x10000"}],
            }],
        }, "latest"]))
        .await
        .unwrap_err();
        assert_eq!(error_code(err), -38015);
    }

    #[tokio::test]
    async fn validation_requires_base_fee() {
        // `ethSimulate-basefee-too-low-with-validation-38012.io`: with
        // validation the block keeps a real base fee, so zero-fee calls fail.
        let err = simulate(json!([{
            "validation": true,
            "blockStateCalls": [{
                "calls": [{"from": RICH, "to": FRESH_B, "value": "0x1"}],
            }],
        }, "latest"]))
        .await
        .unwrap_err();
        assert_eq!(error_code(err), -38012);
    }

    #[tokio::test]
    async fn insufficient_funds_aborts() {
        // `ethSimulate-simple-no-funds.io`: value transfers from an unfunded
        // account fail the balance check in both validation modes.
        let err = simulate(json!([{
            "blockStateCalls": [{
                "calls": [{"from": FRESH_A, "to": FRESH_B, "value": "0x1"}],
            }],
        }, "latest"]))
        .await
        .unwrap_err();
        assert_eq!(error_code(err), -38014);
    }

    /// A nonce-gapped call (explicit nonce above the account nonce) under
    /// `validation: true` — the sender is funded and the fees cover the real
    /// base fee, so the nonce check is the one that fires.
    fn gapped_nonce_call(validation: bool) -> Value {
        json!([{
            "validation": validation,
            "blockStateCalls": [{
                "calls": [{
                    "from": RICH,
                    "to": FRESH_B,
                    "nonce": "0x5",
                    "gas": "0x5208",
                    "maxFeePerGas": "0x77359400",
                }],
            }],
        }, "latest"])
    }

    #[tokio::test]
    async fn validation_enforces_nonce_too_high() {
        // Unlike lax simulators, a gapped nonce must abort the request with
        // -38011 under validation, matching geth.
        let err = simulate(gapped_nonce_call(true)).await.unwrap_err();
        assert_eq!(error_code(err), -38011);
    }

    #[tokio::test]
    async fn validation_enforces_nonce_too_low() {
        // Account nonce raised to 0xa via override; explicit nonce 0x1 is
        // stale -> -38010 under validation.
        let err = simulate(json!([{
            "validation": true,
            "blockStateCalls": [{
                "stateOverrides": {RICH: {"nonce": "0xa"}},
                "calls": [{
                    "from": RICH,
                    "to": FRESH_B,
                    "nonce": "0x1",
                    "gas": "0x5208",
                    "maxFeePerGas": "0x77359400",
                }],
            }],
        }, "latest"]))
        .await
        .unwrap_err();
        assert_eq!(error_code(err), -38010);
    }

    #[tokio::test]
    async fn validation_accepts_correct_nonce() {
        // Same call with the right nonce sanity-checks that validation mode
        // does not over-reject.
        let result = simulate(json!([{
            "validation": true,
            "blockStateCalls": [{
                "calls": [{
                    "from": RICH,
                    "to": FRESH_B,
                    "nonce": "0x0",
                    "gas": "0x5208",
                    "maxFeePerGas": "0x77359400",
                }],
            }],
        }, "latest"]))
        .await
        .unwrap();
        assert_eq!(result[0]["calls"][0]["status"], json!("0x1"));
    }

    #[tokio::test]
    async fn gapped_nonce_passes_without_validation() {
        // `ethSimulate-transaction-too-high-nonce.io`: without validation the
        // explicit gapped nonce is ignored, like eth_call.
        let result = simulate(gapped_nonce_call(false)).await.unwrap();
        assert_eq!(result[0]["calls"][0]["status"], json!("0x1"));
    }

    #[tokio::test]
    async fn trace_transfers_emits_synthetic_log() {
        // `ethSimulate-eth-send-should-produce-logs.io`.
        let result = simulate(json!([{
            "traceTransfers": true,
            "blockStateCalls": [{
                "calls": [{"from": RICH, "to": FRESH_B, "value": "0x7b"}],
            }],
        }, "latest"]))
        .await
        .unwrap();
        let call = &result[0]["calls"][0];
        assert_eq!(call["status"], json!("0x1"));
        let log = &call["logs"][0];
        assert_eq!(
            log["address"],
            json!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        );
        assert_eq!(
            log["topics"][0],
            json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
        );
        // Topics 1/2 are the padded from/to addresses; data is the value.
        assert_eq!(
            log["topics"][1],
            json!(format!("0x000000000000000000000000{}", &RICH[2..]))
        );
        assert_eq!(
            log["data"],
            json!("0x000000000000000000000000000000000000000000000000000000000000007b")
        );
        assert_eq!(log["logIndex"], json!("0x0"));
        assert_eq!(log["removed"], json!(false));
        assert!(log["blockTimestamp"].is_string());
        // The synthetic log stays out of the block's logs bloom.
        assert_eq!(
            result[0]["logsBloom"],
            json!(format!("0x{}", "0".repeat(512)))
        );
    }

    #[tokio::test]
    async fn state_carries_across_simulated_blocks() {
        // `ethSimulate-transfer-over-BlockStateCalls.io` (adapted): block 1
        // funds FRESH_A from the rich account; block 2 spends from FRESH_A.
        let result = simulate(json!([{
            "blockStateCalls": [
                {"calls": [{"from": RICH, "to": FRESH_A, "value": "0xde0b6b3a7640000"}]},
                {"calls": [{"from": FRESH_A, "to": FRESH_B, "value": "0x1"}]},
            ],
        }, "latest"]))
        .await
        .unwrap();
        let blocks = result.as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["calls"][0]["status"], json!("0x1"));
        assert_eq!(blocks[1]["calls"][0]["status"], json!("0x1"));
        assert_eq!(blocks[0]["number"], json!("0x1"));
        assert_eq!(blocks[1]["number"], json!("0x2"));
        // Chained parent hash: block 2's parentHash is block 1's hash.
        assert_eq!(blocks[1]["parentHash"], blocks[0]["hash"]);
        // State roots differ (both blocks mutate state).
        assert_ne!(blocks[0]["stateRoot"], blocks[1]["stateRoot"]);
    }

    #[tokio::test]
    async fn gap_blocks_are_included_in_response() {
        // `ethSimulate-blocknumber-increment.io` (adapted): jumping to
        // base+3 yields the two gap blocks as well.
        let result = simulate(json!([{
            "blockStateCalls": [{"blockOverrides": {"number": "0x3"}}],
        }, "latest"]))
        .await
        .unwrap();
        let blocks = result.as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        let numbers: Vec<&Value> = blocks.iter().map(|b| &b["number"]).collect();
        assert_eq!(numbers, vec![&json!("0x1"), &json!("0x2"), &json!("0x3")]);
        // Timestamps advance by 12 per block.
        let ts: Vec<u64> = blocks
            .iter()
            .map(|b| {
                u64::from_str_radix(
                    b["timestamp"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(ts[1] - ts[0], 12);
        assert_eq!(ts[2] - ts[1], 12);
    }

    #[tokio::test]
    async fn return_full_transactions() {
        // `ethSimulate-simple-validation-fulltx.io` (adapted, without
        // validation): transactions come back as objects.
        let result = simulate(json!([{
            "returnFullTransactions": true,
            "blockStateCalls": [{
                "calls": [{"from": RICH, "to": FRESH_B, "value": "0x1"}],
            }],
        }, "latest"]))
        .await
        .unwrap();
        let tx = &result[0]["transactions"][0];
        assert!(tx.is_object());
        // Spec default tx type is EIP-1559 (0x2).
        assert_eq!(tx["type"], json!("0x2"));
        assert_eq!(tx["nonce"], json!("0x0"));
        assert!(tx["hash"].is_string());
    }

    #[tokio::test]
    async fn block_overrides_reflect_in_result_header() {
        // `ethSimulate-override-block-num.io` (adapted) + simulate-spelled
        // field names (feeRecipient/prevRandao).
        let result = simulate(json!([{
            "blockStateCalls": [{
                "blockOverrides": {
                    "number": "0x5",
                    "time": "0x6668e200",
                    "gasLimit": "0x1000000",
                    "feeRecipient": "0x000000000000000000000000000000000000beef",
                    "baseFeePerGas": "0x7",
                },
            }],
        }, "latest"]))
        .await
        .unwrap();
        let block = result.as_array().unwrap().last().unwrap().clone();
        assert_eq!(block["number"], json!("0x5"));
        assert_eq!(block["timestamp"], json!("0x6668e200"));
        assert_eq!(block["gasLimit"], json!("0x1000000"));
        assert_eq!(
            block["miner"],
            json!("0x000000000000000000000000000000000000beef")
        );
        assert_eq!(block["baseFeePerGas"], json!("0x7"));
    }

    /// `beaconRoot` and `blockHash` are modelled on `BlockOverrideSet` only so they can be
    /// refused with a reason. This handler maps block-override fields across by hand
    /// rather than going through `BlockOverrideSet::apply_to`, so the refusal has to be
    /// enforced here too: without it both fields parse and are then ignored, and the
    /// response looks plausible while disregarding what was asked.
    #[tokio::test]
    async fn unsupported_block_overrides_are_refused() {
        let value =
            json!({"0x1": "0x00000000000000000000000000000000000000000000000000000000000000ff"});
        let err = simulate(json!([{
            "blockStateCalls": [{ "blockOverrides": { "blockHash": value } }],
        }, "latest"]))
        .await
        .expect_err("an override that cannot be honored must not be silently dropped");
        let message = err.to_string();
        assert!(
            message.contains("blockHash"),
            "the refusal should name the field, got: {message}"
        );
        assert_eq!(error_code(err), -32602);
    }

    /// EIP-4788 beacon-roots predeploy, present in `fixtures/genesis/l1.json` with its
    /// canonical code. Called with a 32-byte timestamp it returns the root stored for
    /// that timestamp, which is how a simulated contract would observe the override.
    const BEACON_ROOTS: &str = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02";
    /// A timestamp after the base block's, used as both the `time` override and the
    /// beacon-roots lookup key.
    const BEACON_TIME: &str = "0x6668e200";
    /// [`BEACON_TIME`] as the 32-byte big-endian word the predeploy expects.
    const BEACON_TIME_WORD: &str =
        "0x000000000000000000000000000000000000000000000000000000006668e200";
    const BEACON_ROOT: &str = "0x00000000000000000000000000000000000000000000000000000000000000ff";

    /// A call that supplies no `gas` is granted the block's remaining gas, which from
    /// Amsterdam on is the per-dimension budget. The callee reads `GAS` and returns it, so
    /// the granted limit is observable: anything above the single-budget 274_974 can only
    /// come from the per-dimension 302_080, since what the callee sees is strictly less
    /// than what it was granted.
    ///
    /// This is the half of the rule the explicit-gas tests do not reach — they exercise
    /// the rejection, this exercises the budget the inferred limit is drawn from.
    #[tokio::test]
    async fn amsterdam_inferred_gas_limit_uses_the_per_dimension_budget() {
        // GAS, MSTORE(0), RETURN(0, 32).
        const GAS_PROBE_CODE: &str = "0x5a60005260206000f3";
        const GAS_PROBE: &str = "0xc200000000000000000000000000000000000000";
        let result = simulate_amsterdam(json!([{
            "blockStateCalls": [{
                "blockOverrides": { "gasLimit": "0x61a80" },
                "stateOverrides": {
                    FRESH_A: { "code": "0x6001600255" },
                    GAS_PROBE: { "code": GAS_PROBE_CODE },
                },
                "calls": [
                    {"from": RICH, "to": FRESH_A, "gas": "0x30d40"},
                    {"from": RICH, "to": GAS_PROBE},
                ],
            }],
        }, "latest"]))
        .await
        .expect("the gas-probing call should run");
        let call = &result.as_array().unwrap()[0]["calls"][1];
        let gas_seen = u64::from_str_radix(
            call["returnData"]
                .as_str()
                .expect("the probe returns a word")
                .trim_start_matches("0x"),
            16,
        )
        .expect("the probe returns a gas value");
        assert!(
            gas_seen > 274_974,
            "a call supplying no gas should draw on the per-dimension budget (302_080), \
             not the single budget (274_974); the callee saw only {gas_seen}"
        );
    }

    /// EIP-8037 inclusion is per dimension: the room left for the next call is
    /// `min(limit - sum_regular, limit - sum_state)`, which is *more* than the
    /// pre-Amsterdam `limit - sum_total`. Applying the 1D rule on Amsterdam refuses calls
    /// a real Amsterdam block would include. reth gates the same rule on the fork
    /// (`enable_amsterdam_eip8037`) rather than on `validation`, so this holds in the
    /// default relaxed mode too.
    ///
    /// Block limit 400_000. The first call spends regular 97_920 / state 27_106
    /// (125_026 together). The second asks 290_000: over the 1D remainder of 274_974,
    /// but inside both dimensions (302_080 regular, 372_894 state). Its gas limit also
    /// has to cover the call itself — a transfer creating a fresh account costs ~204_600
    /// on Amsterdam, since account creation is charged to the state dimension.
    #[tokio::test]
    async fn amsterdam_inclusion_uses_per_dimension_budgets() {
        let result = simulate_amsterdam(two_call_budget_request())
            .await
            .expect("the second call fits both gas dimensions");
        let calls = result.as_array().unwrap()[0]["calls"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[1]["status"],
            json!("0x1"),
            "second call failed: {}",
            calls[1]
        );
    }

    /// Control for the test above: widening the budget to two dimensions must not amount
    /// to removing the check. 320_000 still exceeds the *regular* dimension's 302_080
    /// while fitting the state dimension's 372_894, so it has to be refused — which also
    /// proves the regular dimension is the one being consulted, not just the looser of
    /// the two.
    #[tokio::test]
    async fn amsterdam_inclusion_still_refuses_a_call_over_one_dimension() {
        let err = simulate_amsterdam(json!([{
            "blockStateCalls": [{
                "blockOverrides": { "gasLimit": "0x61a80" },
                "stateOverrides": { FRESH_A: { "code": "0x6001600255" } },
                "calls": [
                    {"from": RICH, "to": FRESH_A, "gas": "0x30d40"},
                    {"from": RICH, "to": FRESH_B, "value": "0x1", "gas": "0x4e200"},
                ],
            }],
        }, "latest"]))
        .await
        .expect_err("320_000 exceeds the regular dimension's remaining 302_080");
        assert_eq!(error_code(err), -38015);
    }

    /// EIP-7928: an Amsterdam block commits to its Block Access List, so a simulated
    /// Amsterdam block must carry a `blockAccessListHash`. geth builds a construction BAL
    /// in `simulate.go` and assembles the block with it; reth enables a per-block BAL
    /// builder in `simulate_v1`, Amsterdam-gated. (nethermind deliberately does not, for
    /// an implementation reason of its own.)
    #[tokio::test]
    async fn amsterdam_simulated_block_commits_to_its_access_list() {
        let result = simulate_amsterdam(state_creating_calls()).await.unwrap();
        let block = &result.as_array().unwrap()[0];
        let hash = block["blockAccessListHash"]
            .as_str()
            .unwrap_or_else(|| panic!("no blockAccessListHash on an Amsterdam block: {block}"));
        assert_ne!(hash, "0x", "blockAccessListHash must be a real commitment");
    }

    /// The commitment has to be derived from what the block actually touched, not a
    /// constant empty-BAL hash: a block whose call writes storage must not share its
    /// commitment with one that runs no calls at all.
    #[tokio::test]
    async fn access_list_commitment_reflects_what_the_block_touched() {
        let with_calls = simulate_amsterdam(state_creating_calls()).await.unwrap();
        let without_calls = simulate_amsterdam(json!([{
            "blockStateCalls": [{}],
        }, "latest"]))
        .await
        .unwrap();
        let hash_of = |r: &Value| {
            r.as_array().unwrap()[0]["blockAccessListHash"]
                .as_str()
                .map(str::to_owned)
        };
        let touched = hash_of(&with_calls).expect("commitment on the block with calls");
        let empty = hash_of(&without_calls).expect("commitment on the empty block");
        assert_ne!(
            touched, empty,
            "the commitment does not depend on the block's accesses"
        );
    }

    /// The BAL must include the pre-execution system calls, which is only true if
    /// recording is enabled *before* they run — the ordering the payload builder uses
    /// (`vm.enable_bal_recording()` then `set_bal_index(0)`, both ahead of the system
    /// calls). Two blocks differing only in `beaconRoot` write different values into the
    /// EIP-4788 ring buffer, so their commitments must differ. Enable recording after the
    /// system calls instead and both come out identical.
    #[tokio::test]
    async fn access_list_commitment_includes_the_pre_execution_system_calls() {
        async fn commitment(beacon_root: &str) -> String {
            let result = simulate_amsterdam(json!([{
                "blockStateCalls": [{
                    "blockOverrides": { "time": BEACON_TIME, "beaconRoot": beacon_root },
                }],
            }, "latest"]))
            .await
            .expect("simulation should succeed");
            result.as_array().unwrap()[0]["blockAccessListHash"]
                .as_str()
                .expect("an Amsterdam block commits to its access list")
                .to_owned()
        }
        let one =
            commitment("0x0000000000000000000000000000000000000000000000000000000000000001").await;
        let two =
            commitment("0x0000000000000000000000000000000000000000000000000000000000000002").await;
        assert_ne!(
            one, two,
            "the commitment omits the EIP-4788 system-call writes, so recording starts \
             too late to cover the pre-execution phase"
        );
    }

    /// Control: pre-Amsterdam there is no such commitment, so the field must be absent
    /// rather than zero — which is also what pins the two tests above to the fork gate.
    #[tokio::test]
    async fn pre_amsterdam_block_has_no_access_list_commitment() {
        let result = simulate(state_creating_calls()).await.unwrap();
        let block = &result.as_array().unwrap()[0];
        assert!(
            block.get("blockAccessListHash").is_none(),
            "pre-Amsterdam blocks must not carry a blockAccessListHash: {block}"
        );
    }

    /// EIP-8037: a block's gas is `max(sum_regular, sum_state)`, not the sum of the two
    /// dimensions (`PayloadBuildContext::gas_used`). So once calls create state, the
    /// block's `gasUsed` must come out *below* the naive sum of the per-call figures.
    /// reth applies the same rule in simulation, gated on the fork rather than on
    /// `validation`.
    #[tokio::test]
    async fn amsterdam_block_gas_is_the_max_of_both_dimensions() {
        let result = simulate_amsterdam(state_creating_calls()).await.unwrap();
        let (block_gas, call_sum) = block_and_call_gas(&result);
        assert!(
            block_gas < call_sum,
            "EIP-8037 block gas should be max(regular, state), so below the naive sum \
             {call_sum}; got {block_gas}"
        );
    }

    /// Control for the rule above: pre-Amsterdam a block's gas *is* the sum, so the same
    /// calls must produce equality. This is what pins the assertion above to the fork
    /// gate rather than to some unrelated gas change.
    #[tokio::test]
    async fn pre_amsterdam_block_gas_is_the_sum() {
        let result = simulate(state_creating_calls()).await.unwrap();
        let (block_gas, call_sum) = block_and_call_gas(&result);
        assert_eq!(
            block_gas, call_sum,
            "pre-Amsterdam the block's gas is the plain sum of its transactions"
        );
    }

    /// A `beaconRoot` override must reach the header of the simulated block.
    #[tokio::test]
    async fn beacon_root_override_reaches_the_simulated_header() {
        let result = simulate(json!([{
            "blockStateCalls": [{
                "blockOverrides": { "time": BEACON_TIME, "beaconRoot": BEACON_ROOT },
            }],
        }, "latest"]))
        .await
        .expect("a beaconRoot override should be honored");
        let block = result.as_array().unwrap().last().unwrap();
        assert_eq!(block["parentBeaconBlockRoot"], json!(BEACON_ROOT));
    }

    /// The override must also be *written into the EIP-4788 ring buffer*, not merely
    /// stamped on the header. This is what separates `eth_simulateV1` from the
    /// `eth_call` family: the engine runs the block's system calls, so a simulated
    /// contract reading `BEACON_ROOTS_ADDRESS` observes the overridden root. On the
    /// `eth_call` path nothing runs system contracts, which is exactly why
    /// `BlockOverrideSet::apply_to` refuses the field there.
    #[tokio::test]
    async fn beacon_root_override_is_observable_through_the_predeploy() {
        let result = simulate(json!([{
            "blockStateCalls": [{
                "blockOverrides": { "time": BEACON_TIME, "beaconRoot": BEACON_ROOT },
                "calls": [{"from": RICH, "to": BEACON_ROOTS, "input": BEACON_TIME_WORD}],
            }],
        }, "latest"]))
        .await
        .expect("a beaconRoot override should be honored");
        let call = &result.as_array().unwrap()[0]["calls"][0];
        assert_eq!(call["status"], json!("0x1"), "the read reverted: {call}");
        assert_eq!(
            call["returnData"],
            json!(BEACON_ROOT),
            "the beacon-roots predeploy did not return the overridden root: {call}"
        );
    }

    /// Identity / datacopy precompile: it echoes its calldata, so a relocation either
    /// dispatched it (output == input) or it did not (output empty), with no ambiguous
    /// middle ground.
    const IDENTITY: &str = "0x0000000000000000000000000000000000000004";
    /// Where these tests relocate it to.
    const RELOCATED: &str = "0x0000000000000000000000000000000000000aaa";
    const PAYLOAD: &str = "0x11223344";

    /// One simulated block with `state_overrides`, calling `to` with [`PAYLOAD`].
    async fn simulate_call_to(to: &str, state_overrides: Value) -> Value {
        let result = simulate(json!([{
            "blockStateCalls": [{
                "stateOverrides": state_overrides,
                "calls": [{"from": RICH, "to": to, "input": PAYLOAD}],
            }],
        }, "latest"]))
        .await
        .expect("the simulation itself should succeed");
        result.as_array().unwrap()[0]["calls"][0].clone()
    }

    /// A relocated precompile must dispatch at its destination inside a simulated block,
    /// as it already does on the `eth_call` path. The engine builds its own `Evm`, so the
    /// relocations have to be installed there too.
    #[tokio::test]
    async fn moved_precompile_executes_at_destination() {
        let call = simulate_call_to(
            RELOCATED,
            json!({ IDENTITY: { "movePrecompileToAddress": RELOCATED } }),
        )
        .await;
        assert_eq!(call["status"], json!("0x1"), "call failed: {call}");
        assert!(
            call["returnData"]
                .as_str()
                .is_some_and(|data| data.contains("11223344")),
            "the identity precompile did not run at the relocated address; got: {call}"
        );
    }

    /// Control for the test above: with no relocation the destination is an empty
    /// account, so the echo cannot be coming from anywhere but the move.
    #[tokio::test]
    async fn destination_without_relocation_returns_no_data() {
        let call = simulate_call_to(RELOCATED, json!({})).await;
        assert_eq!(call["returnData"], json!("0x"), "got: {call}");
    }

    /// The vacated address stops behaving as a precompile: geth drops any overridden
    /// address from the active set, turning 0x04 into a regular (here, empty) account,
    /// so the call succeeds returning nothing.
    #[tokio::test]
    async fn vacated_precompile_address_is_a_normal_account() {
        let call = simulate_call_to(
            IDENTITY,
            json!({ IDENTITY: { "movePrecompileToAddress": RELOCATED } }),
        )
        .await;
        assert_eq!(
            call["returnData"],
            json!("0x"),
            "0x04 still echoed after being overridden: {call}"
        );
    }

    /// Relocations are per block, not cumulative. geth derives a fresh active-precompile
    /// set for each simulated block, whereas the *account* overlay deliberately does
    /// accumulate — so this pins the one of the two that is easy to get wrong. Block 2
    /// sends no overrides, so 0x04 must dispatch as a precompile again and the
    /// destination must be an empty account.
    ///
    /// Fails if the relocations are installed once outside the per-block loop, or unioned
    /// across blocks the way the account overlay is.
    #[tokio::test]
    async fn relocations_do_not_carry_into_later_simulated_blocks() {
        let echoes = |call: &Value| {
            call["returnData"]
                .as_str()
                .is_some_and(|data| data.contains("11223344"))
        };
        let result = simulate(json!([{
            "blockStateCalls": [
                {
                    "stateOverrides": { IDENTITY: { "movePrecompileToAddress": RELOCATED } },
                    "calls": [{"from": RICH, "to": RELOCATED, "input": PAYLOAD}],
                },
                {
                    "calls": [
                        {"from": RICH, "to": RELOCATED, "input": PAYLOAD},
                        {"from": RICH, "to": IDENTITY, "input": PAYLOAD},
                    ],
                },
            ],
        }, "latest"]))
        .await
        .expect("the simulation itself should succeed");
        let blocks = result.as_array().unwrap();

        let relocated_in_block_1 = &blocks[0]["calls"][0];
        assert!(
            echoes(relocated_in_block_1),
            "the relocation should hold in the block that requested it; got: \
             {relocated_in_block_1}"
        );

        let relocated_in_block_2 = &blocks[1]["calls"][0];
        assert_eq!(
            relocated_in_block_2["returnData"],
            json!("0x"),
            "the relocation leaked into a block that did not request it: \
             {relocated_in_block_2}"
        );

        let identity_in_block_2 = &blocks[1]["calls"][1];
        assert!(
            echoes(identity_in_block_2),
            "0x04 should be a precompile again once no override suppresses it; got: \
             {identity_in_block_2}"
        );
    }
}
