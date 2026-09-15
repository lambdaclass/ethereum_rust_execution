use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress},
};
use bytes::Bytes;
use ethrex_common::types::{Receipt, TxType};
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};

#[derive(Debug, Clone)]
pub struct Receipts68 {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub receipts: Vec<Vec<Receipt>>,
}

/// Per-receipt wire wrapper for the eth/68 `Receipts` message.
///
/// eth/68 serves receipts *with* the bloom filter (unlike eth/69, which dropped
/// it). Each receipt is encoded as its EIP-2718 consensus byte form
/// (`tx_type || rlp(payload)` for typed, `rlp(payload)` for legacy) wrapped in
/// an RLP byte-string for typed receipts. This reproduces the historical
/// `ReceiptWithBloom` wire bytes for every non-frame receipt while letting frame
/// receipts carry their EIP-8141 `[cumulative_gas_used, payer, [frame_receipt]]`
/// payload, so an eth/68 peer reconstructs the same bytes the receipts trie was
/// built from.
#[derive(Debug, Clone)]
struct ReceiptItem68(Receipt);

impl RLPEncode for ReceiptItem68 {
    /// Mirrors `ReceiptWithBloom`'s wire encoding:
    /// A) Legacy receipts: `rlp(payload)` (raw list, no Bytes wrap).
    /// B) Non-legacy receipts: `rlp(Bytes(tx_type || rlp(payload)))`.
    fn encode(&self, buf: &mut Vec<u8>) {
        let inner = self.0.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);
        match self.0.tx_type {
            TxType::Legacy => buf.extend_from_slice(&inner),
            _ => Bytes::from(inner).encode(buf),
        }
    }
}

impl RLPDecode for ReceiptItem68 {
    /// Inverse of [`ReceiptItem68`]'s encoding:
    /// A) Legacy receipts: `rlp(payload)`.
    /// B) Non-legacy receipts: `rlp(Bytes(tx_type || rlp(payload)))`.
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        // A non-legacy (typed) receipt is encoded as an RLP byte-string wrapping
        // `tx_type || rlp(payload)`; a legacy receipt is encoded as the raw RLP
        // list `rlp(payload)`. Distinguish by RLP item kind (string vs list).
        // NOTE: the `is_encoded_as_bytes` heuristic used elsewhere only matches
        // long strings (0xb8..=0xbf); it is unsafe here because frame receipts
        // carry no 256-byte bloom and can be short enough to use a short-string
        // prefix. Inspecting the item kind is robust for any size.
        let (is_list, payload, item_rest) = ethrex_rlp::decode::decode_rlp_item(rlp)?;
        if is_list {
            // Legacy: `decode_inner_with_bloom` expects the full RLP list
            // including its header, so decode from the original slice.
            let (receipt, rest) = Receipt::decode_inner_with_bloom(rlp)?;
            Ok((ReceiptItem68(receipt), rest))
        } else {
            // Typed: `payload` is exactly `tx_type || rlp(payload)`, bounded to
            // the byte-string's declared length; `item_rest` is the correct
            // remainder for the surrounding list decoder.
            let (receipt, inner_rest) = Receipt::decode_inner_with_bloom(payload)?;
            if !inner_rest.is_empty() {
                return Err(RLPDecodeError::Custom(
                    "trailing bytes in eth/68 receipt item".to_string(),
                ));
            }
            Ok((ReceiptItem68(receipt), item_rest))
        }
    }
}

impl Receipts68 {
    pub fn new(id: u64, receipts: Vec<Vec<Receipt>>) -> Self {
        Self { id, receipts }
    }

    pub fn get_receipts(&self) -> Vec<Vec<Receipt>> {
        self.receipts.clone()
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }
}

impl RLPxMessage for Receipts68 {
    const CODE: u8 = 0x10;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let wire_receipts: Vec<Vec<ReceiptItem68>> = self
            .receipts
            .iter()
            .map(|block| block.iter().cloned().map(ReceiptItem68).collect())
            .collect();
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&wire_receipts)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (wire_receipts, _): (Vec<Vec<ReceiptItem68>>, _) = decoder.decode_field("receipts")?;
        let receipts = wire_receipts
            .into_iter()
            .map(|block| block.into_iter().map(|item| item.0).collect())
            .collect();

        Ok(Receipts68 { id, receipts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::types::{FRAME_RECEIPT_STATUS_SUCCESS, FrameReceipt, Log, ReceiptWithBloom};
    use ethrex_common::{Address, Bytes as CommonBytes};

    fn sample_nonframe_receipts() -> Vec<Vec<Receipt>> {
        vec![
            vec![
                Receipt {
                    tx_type: TxType::Legacy,
                    succeeded: true,
                    cumulative_gas_used: 21000,
                    logs: vec![Log {
                        address: Address::from_low_u64_be(0xaa),
                        topics: vec![],
                        data: CommonBytes::from_static(b"legacy"),
                    }],
                    payer: None,
                    frame_receipts: None,
                },
                Receipt {
                    tx_type: TxType::EIP1559,
                    succeeded: false,
                    cumulative_gas_used: 42000,
                    logs: vec![],
                    payer: None,
                    frame_receipts: None,
                },
            ],
            vec![Receipt {
                tx_type: TxType::EIP4844,
                succeeded: true,
                cumulative_gas_used: 100000,
                logs: vec![Log {
                    address: Address::from_low_u64_be(0xbb),
                    topics: vec![],
                    data: CommonBytes::from_static(b"blob"),
                }],
                payer: None,
                frame_receipts: None,
            }],
        ]
    }

    /// The eth/68 wire bytes for non-frame receipts must be IDENTICAL to the
    /// historical `Vec<Vec<ReceiptWithBloom>>` encoding, so existing eth/68 peers
    /// keep round-tripping. This builds the message the new way and the old way
    /// and asserts byte equality.
    #[test]
    fn nonframe_wire_bytes_match_legacy_receipt_with_bloom() {
        let receipts = sample_nonframe_receipts();

        // New path: Receipts68 stores Vec<Vec<Receipt>> and encodes via ReceiptItem68.
        let new_msg = Receipts68::new(7, receipts.clone());
        let mut new_buf = Vec::new();
        new_msg.encode(&mut new_buf).unwrap();

        // Old path: Vec<Vec<ReceiptWithBloom>> encoded directly, then snappy.
        let old_wire: Vec<Vec<ReceiptWithBloom>> = receipts
            .iter()
            .map(|block| block.iter().map(ReceiptWithBloom::from).collect())
            .collect();
        let mut old_encoded = Vec::new();
        Encoder::new(&mut old_encoded)
            .encode_field(&7u64)
            .encode_field(&old_wire)
            .finish();
        let old_buf = snappy_compress(old_encoded).unwrap();

        assert_eq!(new_buf, old_buf);
    }

    /// A single non-frame receipt wire item equals `Bytes(encode_inner_with_bloom(&ethrex_crypto::NativeCrypto))`
    /// for typed receipts, confirming the per-item wrap is unchanged.
    #[test]
    fn nonframe_item_wire_equals_bytes_inner_with_bloom() {
        let receipt = Receipt {
            tx_type: TxType::EIP1559,
            succeeded: true,
            cumulative_gas_used: 12345,
            logs: vec![],
            payer: None,
            frame_receipts: None,
        };
        let mut item_buf = Vec::new();
        ReceiptItem68(receipt.clone()).encode(&mut item_buf);

        let mut expected = Vec::new();
        Bytes::from(receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto))
            .encode(&mut expected);

        assert_eq!(item_buf, expected);
    }

    /// Full message round-trip for non-frame receipts.
    #[test]
    fn nonframe_message_roundtrips() {
        let receipts = sample_nonframe_receipts();
        let msg = Receipts68::new(3, receipts.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts68::decode(&buf).unwrap();
        assert_eq!(decoded.get_id(), 3);
        assert_eq!(decoded.get_receipts(), receipts);
    }

    /// Frame receipts now survive eth/68 with payer + frame_receipts intact, and
    /// their wire item carries the EIP-8141 consensus payload (matching the trie).
    #[test]
    fn frame_receipt_roundtrips_over_eth68() {
        let frame = Receipt {
            tx_type: TxType::Frame,
            succeeded: true,
            cumulative_gas_used: 250000,
            logs: vec![],
            payer: Some(Address::from_low_u64_be(0x1234)),
            frame_receipts: Some(vec![
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: 100000,
                    logs: vec![],
                },
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: 150000,
                    logs: vec![Log {
                        address: Address::from_low_u64_be(0xbeef),
                        topics: vec![],
                        data: CommonBytes::from_static(b"frame"),
                    }],
                },
            ]),
        };
        let receipts = vec![vec![frame.clone()]];
        let msg = Receipts68::new(9, receipts);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts68::decode(&buf).unwrap();
        let decoded_frame = &decoded.get_receipts()[0][0];

        assert_eq!(decoded_frame.tx_type, TxType::Frame);
        assert_eq!(decoded_frame.payer, frame.payer);
        assert_eq!(decoded_frame.frame_receipts, frame.frame_receipts);
        assert_eq!(decoded_frame.cumulative_gas_used, 250000);

        // The per-item wire bytes equal the consensus / trie bytes wrapped as an
        // RLP byte-string (frame is typed, prefix 0x06).
        let mut item_buf = Vec::new();
        ReceiptItem68(frame.clone()).encode(&mut item_buf);
        let mut expected = Vec::new();
        Bytes::from(frame.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto))
            .encode(&mut expected);
        assert_eq!(item_buf, expected);
    }

    /// Mixed block (non-frame + frame receipts) round-trips, exercising the
    /// per-item length tracking in the list decoder.
    #[test]
    fn mixed_receipts_roundtrip() {
        let nonframe = Receipt {
            tx_type: TxType::EIP1559,
            succeeded: true,
            cumulative_gas_used: 21000,
            logs: vec![Log {
                address: Address::from_low_u64_be(1),
                topics: vec![],
                data: CommonBytes::from_static(b"x"),
            }],
            payer: None,
            frame_receipts: None,
        };
        let frame = Receipt {
            tx_type: TxType::Frame,
            succeeded: true,
            cumulative_gas_used: 50000,
            logs: vec![],
            payer: Some(Address::from_low_u64_be(2)),
            frame_receipts: Some(vec![FrameReceipt {
                status: FRAME_RECEIPT_STATUS_SUCCESS,
                gas_used: 29000,
                logs: vec![],
            }]),
        };
        let legacy = Receipt {
            tx_type: TxType::Legacy,
            succeeded: false,
            cumulative_gas_used: 100,
            logs: vec![],
            payer: None,
            frame_receipts: None,
        };
        let receipts = vec![vec![nonframe.clone(), frame.clone(), legacy.clone()]];
        let msg = Receipts68::new(11, receipts);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = Receipts68::decode(&buf).unwrap();
        let block = &decoded.get_receipts()[0];
        assert_eq!(block.len(), 3);
        assert_eq!(block[0], nonframe);
        assert_eq!(block[1], frame);
        assert_eq!(block[2], legacy);
    }
}
