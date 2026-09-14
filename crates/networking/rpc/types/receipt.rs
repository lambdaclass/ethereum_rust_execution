use ethrex_common::{
    Address, Bloom, Bytes, H256,
    constants::GAS_PER_BLOB,
    evm::calculate_create_address,
    serde_utils,
    types::{
        BlockHash, BlockHeader, BlockNumber, FrameReceipt, Log, Receipt, Transaction, TxKind,
        TxType, bloom_from_logs,
    },
};
use ethrex_crypto::NativeCrypto;

use serde::{Deserialize, Serialize};

use crate::utils::RpcErr;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReceipt {
    #[serde(flatten)]
    pub receipt: RpcReceiptInfo,
    pub logs: Vec<RpcLog>,
    #[serde(flatten)]
    pub tx_info: RpcReceiptTxInfo,
    #[serde(flatten)]
    pub block_info: RpcReceiptBlockInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_receipts: Option<Vec<RpcFrameReceipt>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcFrameReceipt {
    /// EIP-8141 frame status code: 0 = failure, 1 = success, 2 = skipped
    /// (atomic-batch failure). Serialized as a hex-encoded byte.
    #[serde(with = "serde_utils::u8::hex_str")]
    pub status: u8,
    /// EIP-8141 exposes a frame's gas usage per dimension: `gasUsed` is the
    /// execution gas its meter consumed and `stateGasUsed` the state gas
    /// attributed to it.
    #[serde(with = "serde_utils::u64::hex_str")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub state_gas_used: u64,
    pub logs: Vec<RpcLogInfo>,
}

impl From<FrameReceipt> for RpcFrameReceipt {
    fn from(fr: FrameReceipt) -> Self {
        Self {
            status: fr.status,
            gas_used: fr.gas_used.execution,
            state_gas_used: fr.gas_used.state,
            logs: fr.logs.into_iter().map(RpcLogInfo::from).collect(),
        }
    }
}

impl RpcReceipt {
    pub fn new(
        receipt: Receipt,
        tx_info: RpcReceiptTxInfo,
        block_info: RpcReceiptBlockInfo,
        init_log_index: u64,
        block_timestamp: u64,
    ) -> Self {
        let mut logs = vec![];
        let mut log_index = init_log_index;
        for log in receipt.logs.clone() {
            logs.push(RpcLog::new(
                log,
                log_index,
                &tx_info,
                &block_info,
                block_timestamp,
            ));
            log_index += 1;
        }
        let payer = receipt.payer;
        let frame_receipts = receipt
            .frame_receipts
            .clone()
            .map(|frs| frs.into_iter().map(RpcFrameReceipt::from).collect());
        Self {
            receipt: receipt.into(),
            logs,
            tx_info,
            block_info,
            payer,
            frame_receipts,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReceiptInfo {
    #[serde(rename = "type")]
    pub tx_type: TxType,
    #[serde(with = "serde_utils::bool")]
    pub status: bool,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub cumulative_gas_used: u64,
    pub logs_bloom: Bloom,
}

impl From<Receipt> for RpcReceiptInfo {
    fn from(receipt: Receipt) -> Self {
        Self {
            tx_type: receipt.tx_type,
            status: receipt.succeeded,
            cumulative_gas_used: receipt.cumulative_gas_used,
            logs_bloom: bloom_from_logs(&receipt.logs, &ethrex_crypto::NativeCrypto),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RpcLog {
    #[serde(flatten)]
    pub log: RpcLogInfo,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub log_index: u64,
    pub removed: bool,
    pub transaction_hash: H256,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub transaction_index: u64,
    pub block_hash: BlockHash,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub block_number: BlockNumber,
    /// Timestamp of the block this log was emitted in. Optional in the
    /// execution-apis `Log` schema, but every other client populates it, and
    /// indexers that read it off the log would otherwise need a separate block
    /// lookup per receipt. Passed in rather than taken from
    /// `RpcReceiptBlockInfo`, which is flattened into `RpcReceipt` and so must
    /// not gain a serialized field: `blockTimestamp` belongs on the log object
    /// only, not alongside the receipt's own keys.
    ///
    /// Defaulted on the way in: the schema marks it optional, so a peer that
    /// omits it must still decode rather than fail the whole response.
    #[serde(with = "serde_utils::u64::hex_str", default)]
    pub block_timestamp: u64,
}

impl RpcLog {
    pub fn new(
        log: Log,
        log_index: u64,
        tx_info: &RpcReceiptTxInfo,
        block_info: &RpcReceiptBlockInfo,
        block_timestamp: u64,
    ) -> RpcLog {
        Self {
            log: log.into(),
            log_index,
            removed: false,
            transaction_hash: tx_info.transaction_hash,
            transaction_index: tx_info.transaction_index,
            block_hash: block_info.block_hash,
            block_number: block_info.block_number,
            block_timestamp,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RpcLogInfo {
    pub address: Address,
    pub topics: Vec<H256>,
    #[serde(with = "serde_utils::bytes")]
    pub data: Bytes,
}

impl From<Log> for RpcLogInfo {
    fn from(log: Log) -> Self {
        Self {
            address: log.address,
            topics: log.topics,
            data: log.data,
        }
    }
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReceiptBlockInfo {
    pub block_hash: BlockHash,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub block_number: BlockNumber,
}

impl RpcReceiptBlockInfo {
    pub fn from_block_header(block_header: BlockHeader) -> Self {
        RpcReceiptBlockInfo {
            block_hash: block_header.hash(),
            block_number: block_header.number,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReceiptTxInfo {
    pub transaction_hash: H256,
    #[serde(with = "ethrex_common::serde_utils::u64::hex_str")]
    pub transaction_index: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub contract_address: Option<Address>,
    #[serde(with = "ethrex_common::serde_utils::u64::hex_str")]
    pub gas_used: u64,
    #[serde(with = "ethrex_common::serde_utils::u64::hex_str")]
    pub effective_gas_price: u64,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::u64::hex_str_opt",
        default = "Option::default"
    )]
    pub blob_gas_price: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::u64::hex_str_opt",
        default = "Option::default"
    )]
    pub blob_gas_used: Option<u64>,
}

impl RpcReceiptTxInfo {
    pub fn from_transaction(
        transaction: Transaction,
        index: u64,
        gas_used: u64,
        block_blob_gas_price: u64,
        base_fee_per_gas: Option<u64>,
    ) -> Result<Self, RpcErr> {
        let nonce = transaction.nonce();
        let from = transaction.sender(&NativeCrypto)?;
        let transaction_hash = transaction.hash(&NativeCrypto);
        let effective_gas_price =
            u64::try_from(transaction.effective_gas_price(base_fee_per_gas).ok_or(
                RpcErr::Internal("Could not get effective gas price from tx".into()),
            )?)
            .map_err(|_| RpcErr::Internal("effective gas price overflows u64".into()))?;
        let transaction_index = index;
        let (blob_gas_price, blob_gas_used) = match &transaction {
            Transaction::EIP4844Transaction(tx) => (
                Some(block_blob_gas_price),
                Some(tx.blob_versioned_hashes.len() as u64 * GAS_PER_BLOB as u64),
            ),
            _ => (None, None),
        };
        let (contract_address, to) = match transaction.to() {
            TxKind::Create => (Some(calculate_create_address(from, nonce)), None),
            TxKind::Call(addr) => (None, Some(addr)),
        };
        Ok(Self {
            transaction_hash,
            transaction_index,
            from,
            to,
            contract_address,
            gas_used,
            effective_gas_price,
            blob_gas_price,
            blob_gas_used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{
        Bytes,
        types::{Log, TxType},
    };
    use hex_literal::hex;

    #[test]
    fn serialize_receipt() {
        let receipt = RpcReceipt::new(
            Receipt {
                tx_type: TxType::EIP4844,
                succeeded: true,
                cumulative_gas_used: 147,
                logs: vec![Log {
                    address: Address::zero(),
                    topics: vec![],
                    data: Bytes::from_static(b"strawberry"),
                }],
                payer: None,
                frame_receipts: None,
            },
            RpcReceiptTxInfo {
                transaction_hash: H256::zero(),
                transaction_index: 1,
                from: Address::zero(),
                to: Some(Address::from(hex!(
                    "7435ed30a8b4aeb0877cef0c6e8cffe834eb865f"
                ))),
                contract_address: None,
                gas_used: 147,
                effective_gas_price: 157,
                blob_gas_price: None,
                blob_gas_used: None,
            },
            RpcReceiptBlockInfo {
                block_hash: BlockHash::zero(),
                block_number: 3,
            },
            0,
            1786901200,
        );
        let expected = r#"{"type":"0x3","status":"0x1","cumulativeGasUsed":"0x93","logsBloom":"0x00000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","logs":[{"address":"0x0000000000000000000000000000000000000000","topics":[],"data":"0x73747261776265727279","logIndex":"0x0","removed":false,"transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionIndex":"0x1","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x3","blockTimestamp":"0x6a81f2d0"}],"transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionIndex":"0x1","from":"0x0000000000000000000000000000000000000000","to":"0x7435ed30a8b4aeb0877cef0c6e8cffe834eb865f","contractAddress":null,"gasUsed":"0x93","effectiveGasPrice":"0x9d","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x3"}"#;
        assert_eq!(serde_json::to_string(&receipt).unwrap(), expected);
    }

    /// `blockTimestamp` belongs on the log object and nowhere else. Every other
    /// client populates it there, and indexers reading it off a receipt's logs
    /// otherwise need a separate block lookup per receipt. The placement half
    /// matters just as much: `RpcReceiptBlockInfo` is `#[serde(flatten)]`-ed into
    /// `RpcReceipt`, so sourcing the timestamp from it would also emit a
    /// receipt-level `blockTimestamp` that no other client sends.
    #[test]
    fn block_timestamp_is_on_the_log_and_not_on_the_receipt() {
        let receipt = RpcReceipt::new(
            Receipt {
                tx_type: TxType::EIP1559,
                succeeded: true,
                cumulative_gas_used: 21_000,
                logs: vec![Log {
                    address: Address::zero(),
                    topics: vec![],
                    data: Bytes::new(),
                }],
                payer: None,
                frame_receipts: None,
            },
            RpcReceiptTxInfo {
                transaction_hash: H256::zero(),
                transaction_index: 0,
                from: Address::zero(),
                to: None,
                contract_address: None,
                gas_used: 21_000,
                effective_gas_price: 1,
                blob_gas_price: None,
                blob_gas_used: None,
            },
            RpcReceiptBlockInfo {
                block_hash: BlockHash::zero(),
                block_number: 3,
            },
            0,
            1786901200,
        );

        let json = serde_json::to_value(&receipt).expect("serialize");
        let obj = json.as_object().expect("receipt is an object");
        assert!(
            !obj.contains_key("blockTimestamp"),
            "receipt-level keys must stay byte-for-byte what they were"
        );
        let log = json["logs"][0].as_object().expect("log is an object");
        assert_eq!(
            log.get("blockTimestamp").and_then(|v| v.as_str()),
            Some("0x6a81f2d0"),
            "each log must carry the block's timestamp"
        );
    }
}
