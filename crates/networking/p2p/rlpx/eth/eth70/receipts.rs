use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress},
};
use bytes::BufMut;
use ethrex_common::types::{BlockHash, Receipt};
use ethrex_rlp::{
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};

/// Soft response size limit for Receipts messages (10 MiB).
/// Per EIP-7975, complete block receipt lists may exceed the devp2p 10 MiB
/// message size limit at higher gas limits, so responses should be capped.
pub const SOFT_RESPONSE_LIMIT: usize = 10 * 1024 * 1024;

// https://eips.ethereum.org/EIPS/eip-7975
// GetReceipts (eth/70): [request-id: P, firstBlockReceiptIndex: P, [blockhash₁: B_32, ...]]
#[derive(Debug, Clone)]
pub struct GetReceipts70 {
    pub id: u64,
    pub first_block_receipt_index: u64,
    pub block_hashes: Vec<BlockHash>,
}

impl GetReceipts70 {
    pub fn new(id: u64, first_block_receipt_index: u64, block_hashes: Vec<BlockHash>) -> Self {
        Self {
            id,
            first_block_receipt_index,
            block_hashes,
        }
    }
}

impl RLPxMessage for GetReceipts70 {
    const CODE: u8 = 0x0F;

    fn encode(&self, buf: &mut dyn BufMut) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.first_block_receipt_index)
            .encode_field(&self.block_hashes)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.put_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (first_block_receipt_index, decoder): (u64, _) =
            decoder.decode_field("firstBlockReceiptIndex")?;
        let (block_hashes, _): (Vec<BlockHash>, _) = decoder.decode_field("blockHashes")?;

        Ok(Self::new(id, first_block_receipt_index, block_hashes))
    }
}

// Receipts (eth/70): [request-id: P, lastBlockIncomplete: {0,1}, [[receipt₁, receipt₂], ...]]
#[derive(Debug, Clone)]
pub struct Receipts70 {
    pub id: u64,
    pub last_block_incomplete: bool,
    pub receipts: Vec<Vec<Receipt>>,
}

impl Receipts70 {
    pub fn new(id: u64, last_block_incomplete: bool, receipts: Vec<Vec<Receipt>>) -> Self {
        Self {
            id,
            last_block_incomplete,
            receipts,
        }
    }
}

impl RLPxMessage for Receipts70 {
    const CODE: u8 = 0x10;

    fn encode(&self, buf: &mut dyn BufMut) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.last_block_incomplete)
            .encode_field(&self.receipts)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.put_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (last_block_incomplete, decoder): (bool, _) =
            decoder.decode_field("lastBlockIncomplete")?;
        let (receipts, _): (Vec<Vec<Receipt>>, _) = decoder.decode_field("receipts")?;

        Ok(Self::new(id, last_block_incomplete, receipts))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use ethereum_types::{Address, H256};
    use ethrex_common::types::{Log, TxType};

    use super::*;

    fn make_receipt(gas: u64, num_logs: usize) -> Receipt {
        let logs: Vec<Log> = (0..num_logs)
            .map(|i| Log {
                address: Address::from_low_u64_be(i as u64),
                topics: vec![H256::from_low_u64_be(i as u64)],
                data: Bytes::from(vec![0xab; 32]),
            })
            .collect();
        Receipt::new(TxType::EIP1559, true, gas, logs)
    }

    // ── GetReceipts70 roundtrip tests ──

    #[test]
    fn get_receipts70_roundtrip_empty() {
        let msg = GetReceipts70::new(1, 0, vec![]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = GetReceipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 1);
        assert_eq!(decoded.first_block_receipt_index, 0);
        assert!(decoded.block_hashes.is_empty());
    }

    #[test]
    fn get_receipts70_roundtrip_with_offset() {
        let hashes = vec![BlockHash::from([1; 32]), BlockHash::from([2; 32])];
        let msg = GetReceipts70::new(42, 5, hashes.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = GetReceipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.first_block_receipt_index, 5);
        assert_eq!(decoded.block_hashes, hashes);
    }

    #[test]
    fn get_receipts70_roundtrip_large_index() {
        let hashes = vec![BlockHash::from([0xff; 32])];
        let msg = GetReceipts70::new(0, u64::MAX, hashes.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = GetReceipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 0);
        assert_eq!(decoded.first_block_receipt_index, u64::MAX);
        assert_eq!(decoded.block_hashes, hashes);
    }

    #[test]
    fn get_receipts70_roundtrip_many_hashes() {
        let hashes: Vec<BlockHash> = (0..100)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                BlockHash::from(h)
            })
            .collect();
        let msg = GetReceipts70::new(999, 10, hashes.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = GetReceipts70::decode(&buf).unwrap();
        assert_eq!(decoded.block_hashes.len(), 100);
        assert_eq!(decoded.block_hashes, hashes);
    }

    // ── Receipts70 roundtrip tests ──

    #[test]
    fn receipts70_roundtrip_empty() {
        let msg = Receipts70::new(1, false, vec![]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 1);
        assert!(!decoded.last_block_incomplete);
        assert!(decoded.receipts.is_empty());
    }

    #[test]
    fn receipts70_roundtrip_complete_with_receipts() {
        let receipts = vec![
            vec![make_receipt(21000, 1), make_receipt(42000, 2)],
            vec![make_receipt(100000, 0)],
        ];
        let msg = Receipts70::new(10, false, receipts.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 10);
        assert!(!decoded.last_block_incomplete);
        assert_eq!(decoded.receipts.len(), 2);
        assert_eq!(decoded.receipts[0].len(), 2);
        assert_eq!(decoded.receipts[1].len(), 1);
        assert_eq!(decoded.receipts, receipts);
    }

    #[test]
    fn receipts70_roundtrip_incomplete_with_receipts() {
        let receipts = vec![vec![make_receipt(21000, 3)]];
        let msg = Receipts70::new(7, true, receipts.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 7);
        assert!(decoded.last_block_incomplete);
        assert_eq!(decoded.receipts.len(), 1);
        assert_eq!(decoded.receipts[0].len(), 1);
        assert_eq!(decoded.receipts, receipts);
    }

    #[test]
    fn receipts70_roundtrip_incomplete_empty_block() {
        // Incomplete flag with an empty inner list (block with no fitted receipts)
        let msg = Receipts70::new(7, true, vec![vec![]]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert_eq!(decoded.id, 7);
        assert!(decoded.last_block_incomplete);
        assert_eq!(decoded.receipts.len(), 1);
        assert!(decoded.receipts[0].is_empty());
    }

    #[test]
    fn receipts70_roundtrip_multiple_blocks_complete() {
        let receipts = vec![
            vec![make_receipt(21000, 0)],
            vec![make_receipt(50000, 2), make_receipt(75000, 1)],
            vec![make_receipt(100000, 5)],
        ];
        let msg = Receipts70::new(0, false, receipts.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert!(!decoded.last_block_incomplete);
        assert_eq!(decoded.receipts, receipts);
    }

    #[test]
    fn receipts70_roundtrip_preserves_receipt_fields() {
        let log = Log {
            address: Address::from_low_u64_be(0xdead),
            topics: vec![H256::from_low_u64_be(1), H256::from_low_u64_be(2)],
            data: Bytes::from(vec![1, 2, 3, 4, 5]),
        };
        let receipt = Receipt::new(TxType::EIP1559, true, 63000, vec![log]);
        let msg = Receipts70::new(42, false, vec![vec![receipt]]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        let decoded_receipt = &decoded.receipts[0][0];
        assert_eq!(decoded_receipt.tx_type, TxType::EIP1559);
        assert!(decoded_receipt.succeeded);
        assert_eq!(decoded_receipt.cumulative_gas_used, 63000);
        assert_eq!(decoded_receipt.logs.len(), 1);
        assert_eq!(
            decoded_receipt.logs[0].address,
            Address::from_low_u64_be(0xdead)
        );
        assert_eq!(decoded_receipt.logs[0].topics.len(), 2);
        assert_eq!(
            decoded_receipt.logs[0].data,
            Bytes::from(vec![1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn receipts70_roundtrip_different_tx_types() {
        let receipts = vec![vec![
            Receipt::new(TxType::Legacy, false, 21000, vec![]),
            Receipt::new(TxType::EIP2930, true, 42000, vec![]),
            Receipt::new(TxType::EIP1559, true, 63000, vec![]),
            Receipt::new(TxType::EIP4844, true, 84000, vec![]),
        ]];
        let msg = Receipts70::new(1, false, receipts.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert_eq!(decoded.receipts, receipts);
    }

    /// EIP-8141 §Networking: in the `Receipts` message of the protocol version
    /// carrying the fork, a frame receipt is encoded mirroring its consensus
    /// `ReceiptPayload`, i.e. `[tx-type, cumulative-gas, payer, [[status,
    /// [execution-gas, state-gas], logs], ...]]` with the type INSIDE the
    /// list. Hegota rides eth/70 and eth/71, both of which serve `Receipts70`.
    #[test]
    fn receipts70_frame_receipt_matches_the_eip8141_wire_form() {
        use ethrex_common::types::{FrameReceipt, GasUsed};
        use ethrex_rlp::encode::RLPEncode as _;
        use ethrex_rlp::structs::Encoder as RlpEncoder;

        let payer = Address::from_low_u64_be(0xBEEF);
        let frame_receipts = vec![
            FrameReceipt {
                status: ethrex_common::types::FRAME_RECEIPT_STATUS_SUCCESS,
                gas_used: GasUsed {
                    execution: 21_000,
                    state: 0,
                },
                logs: vec![Log {
                    address: Address::from_low_u64_be(0xAA),
                    topics: vec![H256::from_low_u64_be(1)],
                    data: Bytes::from_static(b"frame"),
                }],
            },
            FrameReceipt {
                status: ethrex_common::types::FRAME_RECEIPT_STATUS_SKIPPED,
                gas_used: GasUsed {
                    execution: 0,
                    state: 0,
                },
                logs: vec![],
            },
        ];
        let receipt = Receipt {
            tx_type: TxType::Frame,
            // Derived on decode from the per-frame statuses, so a SKIPPED frame
            // makes this false.
            succeeded: false,
            cumulative_gas_used: 123_456,
            logs: vec![],
            payer: Some(payer),
            frame_receipts: Some(frame_receipts.clone()),
        };

        // The wire item must be exactly the spec's list, type first.
        let mut expected = Vec::new();
        RlpEncoder::new(&mut expected)
            .encode_field(&(TxType::Frame as u8))
            .encode_field(&123_456u64)
            .encode_field(&payer)
            .encode_field(&frame_receipts)
            .finish();
        let mut actual = Vec::new();
        receipt.encode(&mut actual);
        assert_eq!(
            actual, expected,
            "frame receipt wire item must mirror the consensus ReceiptPayload"
        );

        // And it survives a full message round-trip with payer and per-frame
        // results intact.
        let msg = Receipts70::new(9, false, vec![vec![receipt.clone()]]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts70::decode(&buf).unwrap();
        assert_eq!(decoded.receipts, vec![vec![receipt]]);
    }

    // ── Cross-type code consistency ──

    #[test]
    fn get_receipts70_and_receipts70_share_no_code_collision() {
        // Both use different message codes even though they're in the same module
        assert_eq!(GetReceipts70::CODE, 0x0F);
        assert_eq!(Receipts70::CODE, 0x10);
        assert_ne!(GetReceipts70::CODE, Receipts70::CODE);
    }
}
