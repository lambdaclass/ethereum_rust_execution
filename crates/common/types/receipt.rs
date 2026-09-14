use bytes::Bytes;
use ethereum_types::{Address, Bloom, BloomInput, H256};
use ethrex_crypto::Crypto;
use ethrex_rlp::{
    decode::{RLPDecode, get_rlp_bytes_item_payload, is_encoded_as_bytes},
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use serde::{Deserialize, Serialize};

use crate::types::TxType;
pub type Index = u64;

/// Frame receipt status codes (EIP-8141).
/// `0x2` is reserved for frames skipped due to a failed atomic batch.
pub const FRAME_RECEIPT_STATUS_FAILURE: u8 = 0;
pub const FRAME_RECEIPT_STATUS_SUCCESS: u8 = 1;
pub const FRAME_RECEIPT_STATUS_SKIPPED: u8 = 2;

/// A frame's gas usage, one entry per gas dimension of EIP-8037 (EIP-8141).
/// Encoded as the nested two-element list `[execution, state]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct GasUsed {
    /// Execution gas the frame's meter consumed.
    pub execution: u64,
    /// State gas attributed to the frame: its declared budget less what remained
    /// in its pool at frame exit. Not final until the transaction ends — a later
    /// frame's cross-frame refill lowers the owning frame's entry in place, and an
    /// atomic-batch unroll zeroes the state gas of the frames it unrolls.
    pub state: u64,
}

impl GasUsed {
    /// The frame's total gas usage across both dimensions.
    pub fn total(&self) -> u64 {
        self.execution.saturating_add(self.state)
    }
}

impl RLPEncode for GasUsed {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.execution)
            .encode_field(&self.state)
            .finish();
    }
}

impl RLPDecode for GasUsed {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (execution, decoder) = decoder.decode_field("execution")?;
        let (state, decoder) = decoder.decode_field("state")?;
        Ok((GasUsed { execution, state }, decoder.finish()?))
    }
}

/// Per-frame execution result within a frame transaction (EIP-8141)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FrameReceipt {
    pub status: u8,
    pub gas_used: GasUsed,
    pub logs: Vec<Log>,
}

impl RLPEncode for FrameReceipt {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.status)
            .encode_field(&self.gas_used)
            .encode_field(&self.logs)
            .finish();
    }
}

impl RLPDecode for FrameReceipt {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (status, decoder) = decoder.decode_field("status")?;
        let (gas_used, decoder) = decoder.decode_field("gas_used")?;
        let (logs, decoder) = decoder.decode_field("logs")?;
        Ok((
            FrameReceipt {
                status,
                gas_used,
                logs,
            },
            decoder.finish()?,
        ))
    }
}

/// Result of a transaction
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Receipt {
    pub tx_type: TxType,
    pub succeeded: bool,
    /// Cumulative gas used by this and all previous transactions in the block.
    /// This is always post-refund gas.
    /// Note: Block-level gas accounting (pre-refund for EIP-7778) uses BlockExecutionResult::block_gas_used.
    pub cumulative_gas_used: u64,
    pub logs: Vec<Log>,
    /// For frame transactions: the address that paid for gas (set by APPROVE)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<Address>,
    /// For frame transactions: per-frame execution results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_receipts: Option<Vec<FrameReceipt>>,
}

impl Receipt {
    pub fn new(tx_type: TxType, succeeded: bool, cumulative_gas_used: u64, logs: Vec<Log>) -> Self {
        Self {
            tx_type,
            succeeded,
            cumulative_gas_used,
            logs,
            payer: None,
            frame_receipts: None,
        }
    }

    pub fn encode_inner(&self) -> Vec<u8> {
        let mut encoded_data = vec![];
        let tx_type: u8 = self.tx_type as u8;
        if self.tx_type == TxType::Frame {
            // EIP-8141 receipt: [tx_type, cumulative_gas_used, payer, [frame_receipt, ...]]
            // No top-level succeeded or logs fields.
            let empty_frame_receipts = Vec::new();
            Encoder::new(&mut encoded_data)
                .encode_field(&tx_type)
                .encode_field(&self.cumulative_gas_used)
                .encode_field(&self.payer.unwrap_or_default())
                .encode_field(
                    self.frame_receipts
                        .as_ref()
                        .unwrap_or(&empty_frame_receipts),
                )
                .finish();
        } else {
            Encoder::new(&mut encoded_data)
                .encode_field(&tx_type)
                .encode_field(&self.succeeded)
                .encode_field(&self.cumulative_gas_used)
                .encode_field(&self.logs)
                .finish();
        }
        encoded_data
    }

    /// Full-fidelity INTERNAL storage encoding. NOT a wire/consensus format:
    /// the receipts trie uses `encode_inner_with_bloom` and P2P uses the
    /// `RLPEncode` impl (`encode_inner`). For frame receipts this additionally
    /// persists `succeeded` and the aggregated top-level `logs` (needed by
    /// eth_getLogs / eth_getTransactionReceipt), which the consensus layout
    /// intentionally omits. Non-frame receipts reuse the existing layout so
    /// databases written before this change stay readable.
    pub fn encode_storage(&self) -> Vec<u8> {
        if self.tx_type == TxType::Frame {
            let mut buf = vec![];
            let empty_frame_receipts = Vec::new();
            Encoder::new(&mut buf)
                .encode_field(&(self.tx_type as u8))
                .encode_field(&self.succeeded)
                .encode_field(&self.cumulative_gas_used)
                .encode_field(&self.logs)
                .encode_field(&self.payer.unwrap_or_default())
                .encode_field(
                    self.frame_receipts
                        .as_ref()
                        .unwrap_or(&empty_frame_receipts),
                )
                .finish();
            buf
        } else {
            self.encode_inner()
        }
    }

    /// Inverse of `encode_storage`.
    pub fn decode_storage(rlp: &[u8]) -> Result<Receipt, RLPDecodeError> {
        // Peek the tx-type (first field) to choose the layout.
        let (tx_type_byte, _): (u8, _) = Decoder::new(rlp)?.decode_field("tx-type")?;
        if TxType::from_u8(tx_type_byte) != Some(TxType::Frame) {
            // Non-frame receipts use the standard consensus decode (unchanged
            // layout) — old databases remain readable.
            return Receipt::decode(rlp);
        }
        let decoder = Decoder::new(rlp)?;
        let (_, decoder): (u8, _) = decoder.decode_field("tx-type")?;
        let (succeeded, decoder) = decoder.decode_field("succeeded")?;
        let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
        let (logs, decoder) = decoder.decode_field("logs")?;
        let (payer, decoder): (Address, _) = decoder.decode_field("payer")?;
        let (frame_receipts, decoder): (Vec<FrameReceipt>, _) =
            decoder.decode_field("frame_receipts")?;
        decoder.finish()?;
        Ok(Receipt {
            tx_type: TxType::Frame,
            succeeded,
            cumulative_gas_used,
            logs,
            payer: if payer == Address::zero() {
                None
            } else {
                Some(payer)
            },
            frame_receipts: Some(frame_receipts),
        })
    }

    pub fn encode_inner_with_bloom(&self, crypto: &dyn Crypto) -> Vec<u8> {
        self.encode_inner_with_precomputed_bloom(bloom_from_logs(&self.logs, crypto))
    }

    /// Like [`Self::encode_inner_with_bloom`] but takes an already-computed bloom, so
    /// callers that also need the bloom for other purposes (e.g. the aggregate header
    /// `logs_bloom`) don't recompute it.
    pub fn encode_inner_with_precomputed_bloom(&self, bloom: Bloom) -> Vec<u8> {
        // Bloom is already 256 bytes, so we preallocate at least that much plus some,
        // to avoid multiple small allocations.
        let mut encode_buf = Vec::with_capacity(512);
        if self.tx_type != TxType::Legacy {
            encode_buf.push(self.tx_type as u8);
        }
        if self.tx_type == TxType::Frame {
            // EIP-8141 ReceiptPayload:
            // [cumulative_gas_used, payer, [frame_receipt, ...]]
            // No succeeded, no bloom, no top-level logs.
            let empty_frame_receipts = Vec::new();
            Encoder::new(&mut encode_buf)
                .encode_field(&self.cumulative_gas_used)
                .encode_field(&self.payer.unwrap_or_default())
                .encode_field(
                    self.frame_receipts
                        .as_ref()
                        .unwrap_or(&empty_frame_receipts),
                )
                .finish();
        } else {
            Encoder::new(&mut encode_buf)
                .encode_field(&self.succeeded)
                .encode_field(&self.cumulative_gas_used)
                .encode_field(&bloom)
                .encode_field(&self.logs)
                .finish();
        }
        encode_buf
    }

    /// Inverse of [`Receipt::encode_inner_with_bloom`].
    ///
    /// Parses a receipt from its consensus / trie byte form, i.e. the raw
    /// `tx_type || rlp(payload)` (typed) or `rlp(payload)` (legacy) produced by
    /// `encode_inner_with_bloom`. Returns the decoded receipt and the remaining
    /// bytes after the consumed payload.
    ///
    /// For non-frame receipts the layout is `[succeeded, cumulative_gas_used,
    /// bloom, logs]`; the bloom is dropped because [`Receipt`] does not store it.
    /// For frame receipts (tx_type 0x06) the layout is the EIP-8141
    /// `[cumulative_gas_used, payer, [frame_receipt, ...]]`: there is no
    /// top-level `succeeded` (it is derived from the frame statuses, identical
    /// to the `RLPDecode for Receipt` frame branch) and no top-level `logs`.
    pub fn decode_inner_with_bloom(rlp: &[u8]) -> Result<(Receipt, &[u8]), RLPDecodeError> {
        // Determine the tx type from the optional 1-byte type prefix. A leading
        // byte < 0x7f denotes the EIP-2718 type; otherwise it is a legacy
        // receipt (whose payload starts directly with an RLP list header).
        let (tx_type, payload) = match rlp.first() {
            Some(byte) if *byte < 0x7f => {
                let Some(tx_type) = TxType::from_u8(*byte) else {
                    return Err(RLPDecodeError::Custom(format!(
                        "Invalid transaction type: {byte}"
                    )));
                };
                (tx_type, &rlp[1..])
            }
            _ => (TxType::Legacy, rlp),
        };

        if tx_type == TxType::Frame {
            let decoder = Decoder::new(payload)?;
            let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
            let (payer, decoder): (Address, _) = decoder.decode_field("payer")?;
            let (frame_receipts, decoder): (Vec<FrameReceipt>, _) =
                decoder.decode_field("frame_receipts")?;
            let remaining = decoder.finish_unchecked();
            let payer = if payer == Address::zero() {
                None
            } else {
                Some(payer)
            };
            // Derive succeeded from frame receipts: true iff every frame's status
            // is SUCCESS (same rule as `RLPDecode for Receipt`).
            let succeeded = frame_receipts
                .iter()
                .all(|fr| fr.status == FRAME_RECEIPT_STATUS_SUCCESS);
            Ok((
                Receipt {
                    tx_type,
                    succeeded,
                    cumulative_gas_used,
                    logs: Vec::new(),
                    payer,
                    frame_receipts: Some(frame_receipts),
                },
                remaining,
            ))
        } else {
            let decoder = Decoder::new(payload)?;
            let (succeeded, decoder) = decoder.decode_field("succeeded")?;
            let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
            // Decode and discard the bloom: it is derivable from the logs and is
            // not stored on `Receipt`.
            let (_bloom, decoder): (Bloom, _) = decoder.decode_field("bloom")?;
            let (logs, decoder) = decoder.decode_field("logs")?;
            let remaining = decoder.finish_unchecked();
            Ok((
                Receipt {
                    tx_type,
                    succeeded,
                    cumulative_gas_used,
                    logs,
                    payer: None,
                    frame_receipts: None,
                },
                remaining,
            ))
        }
    }
}

pub fn bloom_from_logs(logs: &[Log], crypto: &dyn Crypto) -> Bloom {
    let mut bloom = Bloom::zero();
    for log in logs {
        let address_hash = crypto.keccak256(log.address.as_bytes());
        bloom.accrue(BloomInput::Hash(&address_hash));
        for topic in log.topics.iter() {
            let topic_hash = crypto.keccak256(topic.as_bytes());
            bloom.accrue(BloomInput::Hash(&topic_hash));
        }
    }
    bloom
}

impl RLPEncode for Receipt {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        let encoded_inner = self.encode_inner();
        buf.put_slice(&encoded_inner);
    }
}

impl RLPDecode for Receipt {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (tx_type, decoder): (u8, _) = decoder.decode_field("tx-type")?;

        let Some(tx_type) = TxType::from_u8(tx_type) else {
            return Err(RLPDecodeError::Custom(
                "Invalid transaction type".to_string(),
            ));
        };

        if tx_type == TxType::Frame {
            // EIP-8141 receipt: [tx_type, cumulative_gas_used, payer, [frame_receipt, ...]]
            let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
            let (payer, decoder): (Address, _) = decoder.decode_field("payer")?;
            let (frame_receipts, decoder): (Vec<FrameReceipt>, _) =
                decoder.decode_field("frame_receipts")?;
            let payer = if payer == Address::zero() {
                None
            } else {
                Some(payer)
            };
            // Derive succeeded from frame receipts: true iff every frame's status is SUCCESS.
            // Any FAILURE or SKIPPED frame disqualifies the transaction from `succeeded`.
            let succeeded = frame_receipts
                .iter()
                .all(|fr| fr.status == FRAME_RECEIPT_STATUS_SUCCESS);
            Ok((
                Receipt {
                    tx_type,
                    succeeded,
                    cumulative_gas_used,
                    logs: Vec::new(),
                    payer,
                    frame_receipts: Some(frame_receipts),
                },
                decoder.finish()?,
            ))
        } else {
            let (succeeded, decoder) = decoder.decode_field("succeeded")?;
            let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
            let (logs, decoder) = decoder.decode_field("logs")?;
            Ok((
                Receipt {
                    tx_type,
                    succeeded,
                    cumulative_gas_used,
                    logs,
                    payer: None,
                    frame_receipts: None,
                },
                decoder.finish()?,
            ))
        }
    }
}

/// Result of a transaction
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReceiptWithBloom {
    pub tx_type: TxType,
    pub succeeded: bool,
    /// Cumulative gas used by this and all previous transactions in the block.
    /// This is always post-refund gas.
    /// Note: Block-level gas accounting (pre-refund for EIP-7778) uses BlockExecutionResult::block_gas_used.
    pub cumulative_gas_used: u64,
    pub bloom: Bloom,
    pub logs: Vec<Log>,
}

impl ReceiptWithBloom {
    pub fn new(tx_type: TxType, succeeded: bool, cumulative_gas_used: u64, logs: Vec<Log>) -> Self {
        Self {
            tx_type,
            succeeded,
            cumulative_gas_used,
            bloom: bloom_from_logs(&logs, &ethrex_crypto::NativeCrypto),
            logs,
        }
    }

    // By reading the typed transactions EIP, and some geth code:
    // - https://eips.ethereum.org/EIPS/eip-2718
    // - https://github.com/ethereum/go-ethereum/blob/330190e476e2a2de4aac712551629a4134f802d5/core/types/receipt.go#L143
    // We've noticed the are some subtleties around encoding receipts and transactions.
    // First, `encode_inner` will encode a receipt according
    // to the RLP of its fields, if typed, the RLP of the fields
    // is padded with the byte representing this type.
    // For P2P messages, receipts are re-encoded as bytes
    // (see the `encode` implementation for receipt).
    // For debug and computing receipt roots, the expected
    // RLP encodings are the ones returned by `encode_inner`.
    // On some documentations, this is also called the `consensus-encoding`
    // for a receipt.

    /// Encodes Receipts in the following formats:
    /// A) Legacy receipts: rlp(receipt)
    /// B) Non legacy receipts: tx_type | rlp(receipt).
    pub fn encode_inner(&self) -> Vec<u8> {
        let mut encode_buff = match self.tx_type {
            TxType::Legacy => {
                vec![]
            }
            _ => {
                vec![self.tx_type as u8]
            }
        };
        Encoder::new(&mut encode_buff)
            .encode_field(&self.succeeded)
            .encode_field(&self.cumulative_gas_used)
            .encode_field(&self.bloom)
            .encode_field(&self.logs)
            .finish();
        encode_buff
    }

    /// Decodes Receipts in the following formats:
    /// A) Legacy receipts: rlp(receipt)
    /// B) Non legacy receipts: tx_type | rlp(receipt).
    pub fn decode_inner(rlp: &[u8]) -> Result<Self, RLPDecodeError> {
        // Obtain TxType
        let (tx_type, rlp) = match rlp.first() {
            Some(tx_type) if *tx_type < 0x7f => {
                let tx_type = match tx_type {
                    0x0 => TxType::Legacy,
                    0x1 => TxType::EIP2930,
                    0x2 => TxType::EIP1559,
                    0x3 => TxType::EIP4844,
                    0x4 => TxType::EIP7702,
                    0x6 => TxType::Frame,
                    0x7d => TxType::FeeToken,
                    0x7e => TxType::Privileged,
                    ty => {
                        return Err(RLPDecodeError::Custom(format!(
                            "Invalid transaction type: {ty}"
                        )));
                    }
                };
                (tx_type, &rlp[1..])
            }
            _ => (TxType::Legacy, rlp),
        };
        let decoder = Decoder::new(rlp)?;
        let (succeeded, decoder) = decoder.decode_field("succeeded")?;
        let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
        let (bloom, decoder) = decoder.decode_field("bloom")?;
        let (logs, decoder) = decoder.decode_field("logs")?;
        decoder.finish()?;

        Ok(Self {
            tx_type,
            succeeded,
            cumulative_gas_used,
            bloom,
            logs,
        })
    }
}

impl RLPEncode for ReceiptWithBloom {
    /// Receipts can be encoded in the following formats:
    /// A) Legacy receipts: rlp(receipt)
    /// B) Non legacy receipts: rlp(Bytes(tx_type | rlp(receipt))).
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        match self.tx_type {
            TxType::Legacy => {
                let legacy_encoded = self.encode_inner();
                buf.put_slice(&legacy_encoded);
            }
            _ => {
                let typed_recepipt_encoded = self.encode_inner();
                let bytes = Bytes::from(typed_recepipt_encoded);
                bytes.encode(buf);
            }
        };
    }
}

impl RLPDecode for ReceiptWithBloom {
    /// Receipts can be encoded in the following formats:
    /// A) Legacy receipts: rlp(receipt)
    /// B) Non legacy receipts: rlp(Bytes(tx_type | rlp(receipt))).
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        // The minimum size for a ReceiptWithBloom is > 256 bytes (due to the Bloom type field) meaning that it is safe
        // to check for bytes prefix to diferenticate between legacy receipts and non-legacy receipt payloads
        let (tx_type, rlp) = if is_encoded_as_bytes(rlp)? {
            let payload = get_rlp_bytes_item_payload(rlp)?;
            let tx_type = match payload.first().ok_or(RLPDecodeError::InvalidLength)? {
                0x0 => TxType::Legacy,
                0x1 => TxType::EIP2930,
                0x2 => TxType::EIP1559,
                0x3 => TxType::EIP4844,
                0x4 => TxType::EIP7702,
                0x6 => TxType::Frame,
                0x7d => TxType::FeeToken,
                0x7e => TxType::Privileged,
                ty => {
                    return Err(RLPDecodeError::Custom(format!(
                        "Invalid transaction type: {ty}"
                    )));
                }
            };
            (tx_type, &payload[1..])
        } else {
            (TxType::Legacy, rlp)
        };

        let decoder = Decoder::new(rlp)?;
        let (succeeded, decoder) = decoder.decode_field("succeeded")?;
        let (cumulative_gas_used, decoder) = decoder.decode_field("cumulative_gas_used")?;
        let (bloom, decoder) = decoder.decode_field("bloom")?;
        let (logs, decoder) = decoder.decode_field("logs")?;

        Ok((
            ReceiptWithBloom {
                tx_type,
                succeeded,
                cumulative_gas_used,
                bloom,
                logs,
            },
            decoder.finish()?,
        ))
    }
}

impl From<&Receipt> for ReceiptWithBloom {
    fn from(receipt: &Receipt) -> Self {
        Self {
            tx_type: receipt.tx_type,
            succeeded: receipt.succeeded,
            cumulative_gas_used: receipt.cumulative_gas_used,
            bloom: bloom_from_logs(&receipt.logs, &ethrex_crypto::NativeCrypto),
            logs: receipt.logs.clone(),
        }
    }
}

impl From<&ReceiptWithBloom> for Receipt {
    fn from(receipt: &ReceiptWithBloom) -> Self {
        Self {
            tx_type: receipt.tx_type,
            succeeded: receipt.succeeded,
            cumulative_gas_used: receipt.cumulative_gas_used,
            logs: receipt.logs.clone(),
            payer: None,
            frame_receipts: None,
        }
    }
}

/// Data record produced during the execution of a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
}

impl RLPEncode for Log {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.address)
            .encode_field(&self.topics)
            .encode_field(&self.data)
            .finish();
    }
}

impl RLPDecode for Log {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (address, decoder) = decoder.decode_field("address")?;
        let (topics, decoder) = decoder.decode_field("topics")?;
        let (data, decoder) = decoder.decode_field("data")?;
        let log = Log {
            address,
            topics,
            data,
        };
        Ok((log, decoder.finish()?))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn h256_from_hex(s: &str) -> H256 {
        H256::from_slice(&hex::decode(s).unwrap())
    }

    /// Before Byzantium (EIP-658) a receipt's first field is a 32-byte post-state
    /// root, not a status flag. `Receipt` has no field for it, so such a receipt
    /// cannot be decoded — the `bool` decode of field 0 rejects the 32-byte
    /// string. This is why history backfill clamps its floor at the Byzantium
    /// block instead of descending to genesis: pre-Byzantium receipts can never be
    /// fetched, and trying would fail every request and penalize honest peers.
    ///
    /// If this test ever starts passing, `Receipt` has gained a representation for
    /// the pre-EIP-658 form and that clamp can be revisited.
    #[test]
    fn pre_byzantium_receipt_cannot_be_decoded() {
        // rlp([post_state_root(32B), cumulative_gas_used, bloom(256B), logs]) —
        // the pre-EIP-658 consensus form.
        // Two receipts identical except for field 0: a post-Byzantium status flag
        // versus a pre-Byzantium 32-byte post-state root. Encoding both and
        // decoding each isolates the failure to that field, without inspecting
        // error text.
        fn encode_with_first_field<T: RLPEncode>(first: &T) -> Vec<u8> {
            let mut buf = Vec::new();
            Encoder::new(&mut buf)
                .encode_field(first)
                .encode_field(&21_000u64)
                .encode_field(&Bloom::zero())
                .encode_field(&Vec::<Log>::new())
                .finish();
            buf
        }

        let post_byzantium = encode_with_first_field(&true);
        assert!(
            Receipt::decode_inner_with_bloom(&post_byzantium).is_ok(),
            "a status-flag (post-Byzantium) receipt must decode"
        );

        let pre_byzantium = encode_with_first_field(&H256::from([0x11u8; 32]));
        assert!(
            Receipt::decode_inner_with_bloom(&pre_byzantium).is_err(),
            "a post-state-root (pre-Byzantium) receipt must not decode"
        );
    }

    #[test]
    fn test_encode_decode_receipt_legacy() {
        let receipt = Receipt {
            tx_type: TxType::Legacy,
            succeeded: true,
            cumulative_gas_used: 1200,
            logs: vec![Log {
                address: Address::random(),
                topics: vec![],
                data: Bytes::from_static(b"foo"),
            }],
            payer: None,
            frame_receipts: None,
        };
        let encoded_receipt = receipt.encode_to_vec();
        assert_eq!(receipt, Receipt::decode(&encoded_receipt).unwrap())
    }

    #[test]
    fn test_encode_decode_receipt_non_legacy() {
        let receipt = Receipt {
            tx_type: TxType::EIP4844,
            succeeded: true,
            cumulative_gas_used: 1500,
            logs: vec![Log {
                address: Address::random(),
                topics: vec![],
                data: Bytes::from_static(b"bar"),
            }],
            payer: None,
            frame_receipts: None,
        };
        let encoded_receipt = receipt.encode_to_vec();
        assert_eq!(receipt, Receipt::decode(&encoded_receipt).unwrap())
    }

    #[test]
    fn test_encode_decode_inner_receipt_legacy() {
        let receipt = ReceiptWithBloom {
            tx_type: TxType::Legacy,
            succeeded: true,
            cumulative_gas_used: 1200,
            bloom: Bloom::random(),
            logs: vec![Log {
                address: Address::random(),
                topics: vec![],
                data: Bytes::from_static(b"foo"),
            }],
        };
        let encoded_receipt = receipt.encode_inner();
        assert_eq!(
            receipt,
            ReceiptWithBloom::decode_inner(&encoded_receipt).unwrap()
        )
    }

    #[test]
    fn test_encode_decode_receipt_inner_non_legacy() {
        let receipt = ReceiptWithBloom {
            tx_type: TxType::EIP4844,
            succeeded: true,
            cumulative_gas_used: 1500,
            bloom: Bloom::random(),
            logs: vec![Log {
                address: Address::random(),
                topics: vec![],
                data: Bytes::from_static(b"bar"),
            }],
        };
        let encoded_receipt = receipt.encode_inner();
        assert_eq!(
            receipt,
            ReceiptWithBloom::decode_inner(&encoded_receipt).unwrap()
        )
    }

    #[test]
    fn test_encode_receipt_with_bloom() {
        let receipt = Receipt {
            tx_type: TxType::EIP1559,
            succeeded: true,
            cumulative_gas_used: 1500,
            logs: vec![Log {
                address: Address::random(),
                topics: vec![
                    h256_from_hex(
                        "e70c0d1060ffbafc84e0e18d028245de3deeb0f41ecbade6562fa657d85ae945",
                    ),
                    h256_from_hex(
                        "e7e9cd61c8c6cb313324d785aa130fe50a7b9885e4d1d7700a327c5e9ae4e183",
                    ),
                    h256_from_hex(
                        "666d827b9db958c08f7186f127e3d9ea6a97288bcc4b527951ce493f6e2b76c4",
                    ),
                    h256_from_hex(
                        "28b4366544dccafad7b61138e9ada51706e85bb217a20cfa1c86e2648f8f369a",
                    ),
                    h256_from_hex(
                        "85cf9717f65c70d71cc6175f653512c13ce7b6a9bc5d9c2b9c49b2d2d6cb9536",
                    ),
                ],
                data: Bytes::from_static(b"bar"),
            }],
            payer: None,
            frame_receipts: None,
        };
        let encoded_receipt = receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);

        let correct_bloom = {
            let mut bloom = Bloom::zero();
            for log in receipt.logs {
                bloom.accrue(BloomInput::Raw(log.address.as_ref()));
                for topic in log.topics.iter() {
                    bloom.accrue(BloomInput::Raw(topic.as_ref()));
                }
            }
            bloom
        };
        let receipt_with_bloom = ReceiptWithBloom::decode_inner(&encoded_receipt).unwrap();
        assert_eq!(receipt_with_bloom.bloom, correct_bloom);
    }

    #[test]
    fn test_frame_receipt_rlp_roundtrip() {
        let fr = FrameReceipt {
            status: FRAME_RECEIPT_STATUS_SUCCESS,
            gas_used: GasUsed {
                execution: 21000,
                state: 0,
            },
            logs: vec![Log {
                address: Address::random(),
                topics: vec![],
                data: Bytes::from_static(b"test"),
            }],
        };
        let encoded = fr.encode_to_vec();
        let decoded = FrameReceipt::decode(&encoded).unwrap();
        assert_eq!(fr, decoded);
    }

    #[test]
    fn test_frame_receipt_skipped_status_rlp_roundtrip() {
        // EIP-8141 `FrameStatus.SKIPPED` is 2, and marks only frames that never
        // ran because an earlier frame of their atomic batch failed.
        let fr = FrameReceipt {
            status: FRAME_RECEIPT_STATUS_SKIPPED,
            gas_used: GasUsed {
                execution: 0,
                state: 0,
            },
            logs: vec![],
        };
        let encoded = fr.encode_to_vec();
        let decoded = FrameReceipt::decode(&encoded).unwrap();
        assert_eq!(fr, decoded);
        assert_eq!(decoded.status, FRAME_RECEIPT_STATUS_SKIPPED);
    }

    #[test]
    fn test_receipt_with_frame_fields_rlp_roundtrip() {
        // Frame receipts encode as [cumulative_gas_used, payer, [frame_receipts]]
        // without top-level succeeded or logs. On decode, succeeded is derived
        // from frame receipts and logs is empty.
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: true,
            cumulative_gas_used: 315000,
            logs: vec![],
            payer: Some(Address::from_low_u64_be(0x1234)),
            frame_receipts: Some(vec![
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 100000,
                        state: 0,
                    },
                    logs: vec![],
                },
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 200000,
                        state: 0,
                    },
                    logs: vec![Log {
                        address: Address::from_low_u64_be(0xbeef),
                        topics: vec![],
                        data: Bytes::from_static(b"frame2"),
                    }],
                },
            ]),
        };
        let encoded = receipt.encode_to_vec();
        let decoded = Receipt::decode(&encoded).unwrap();
        assert_eq!(decoded.tx_type, TxType::Frame);
        assert_eq!(decoded.cumulative_gas_used, 315000);
        assert_eq!(decoded.payer, Some(Address::from_low_u64_be(0x1234)));
        assert!(decoded.succeeded); // derived: all frame receipts succeeded
        assert!(decoded.logs.is_empty()); // top-level logs not encoded for frame txs
        assert_eq!(decoded.frame_receipts, receipt.frame_receipts);
    }

    #[test]
    fn test_frame_receipt_succeeded_derived_from_frames() {
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: true, // will be overridden on decode
            cumulative_gas_used: 100000,
            logs: vec![],
            payer: Some(Address::from_low_u64_be(0x1)),
            frame_receipts: Some(vec![
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 50000,
                        state: 0,
                    },
                    logs: vec![],
                },
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_FAILURE,
                    gas_used: GasUsed {
                        execution: 50000,
                        state: 0,
                    },
                    logs: vec![],
                },
            ]),
        };
        let encoded = receipt.encode_to_vec();
        let decoded = Receipt::decode(&encoded).unwrap();
        assert!(!decoded.succeeded); // one frame failed
    }

    #[test]
    fn test_frame_receipt_skipped_disqualifies_succeeded() {
        // A SKIPPED frame must not count as success: spec implies the tx outcome
        // is not fully successful when any atomic batch failed.
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: false,
            cumulative_gas_used: 100000,
            logs: vec![],
            payer: Some(Address::from_low_u64_be(0x1)),
            frame_receipts: Some(vec![
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 50000,
                        state: 0,
                    },
                    logs: vec![],
                },
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SKIPPED,
                    gas_used: GasUsed {
                        execution: 0,
                        state: 0,
                    },
                    logs: vec![],
                },
            ]),
        };
        let encoded = receipt.encode_to_vec();
        let decoded = Receipt::decode(&encoded).unwrap();
        assert!(!decoded.succeeded);
    }

    #[test]
    fn frame_receipt_storage_roundtrip_preserves_logs_and_status() {
        let log = Log {
            address: Address::from_low_u64_be(1),
            topics: vec![],
            data: Bytes::from(vec![1u8]),
        };
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: true, // VM rule: no SENDER frame reverted
            cumulative_gas_used: 50_000,
            logs: vec![log.clone()], // aggregated frame logs
            payer: Some(Address::from_low_u64_be(2)),
            frame_receipts: Some(vec![
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_FAILURE,
                    gas_used: GasUsed {
                        execution: 1000,
                        state: 0,
                    },
                    logs: vec![],
                }, // a DEFAULT frame failed
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 2000,
                        state: 0,
                    },
                    logs: vec![log],
                },
            ]),
        };
        // succeeded=true coexists with a FAILURE frame -> the old derive-rule would
        // have flipped it to false; storage must keep it verbatim.
        let decoded = Receipt::decode_storage(&receipt.encode_storage()).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn nonframe_receipt_storage_roundtrip_unchanged() {
        let r = Receipt::new(TxType::EIP1559, true, 21000, vec![]);
        assert_eq!(Receipt::decode_storage(&r.encode_storage()).unwrap(), r);
        // and that encode_storage matches the legacy encode_inner for non-frame:
        assert_eq!(r.encode_storage(), r.encode_inner());
    }

    /// Golden byte vector for the EIP-8141 two-dimensional `gas_used`. Every other
    /// test in this file builds its expectation with the same encoder, so none of
    /// them would notice the nested `[execution, state]` list flattening back to a
    /// scalar; only the spec-test fixtures would, through the receipts root. This
    /// pins the layout without them.
    #[test]
    fn frame_receipt_gas_used_encodes_as_a_nested_pair() {
        // [21000, 0] -> c4 82 52 08 80
        assert_eq!(
            GasUsed {
                execution: 21_000,
                state: 0,
            }
            .encode_to_vec(),
            vec![0xc4, 0x82, 0x52, 0x08, 0x80]
        );
        // [status, [execution, state], logs] -> c7 01 c4 82 52 08 80 c0
        assert_eq!(
            FrameReceipt {
                status: FRAME_RECEIPT_STATUS_SUCCESS,
                gas_used: GasUsed {
                    execution: 21_000,
                    state: 0,
                },
                logs: Vec::new(),
            }
            .encode_to_vec(),
            vec![0xc7, 0x01, 0xc4, 0x82, 0x52, 0x08, 0x80, 0xc0]
        );
    }

    #[test]
    fn frame_receipt_trie_encoding_is_eip8141_payload() {
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: true,
            cumulative_gas_used: 100_000,
            logs: Vec::new(),
            payer: Some(Address::from_low_u64_be(0xBEEF)),
            frame_receipts: Some(vec![FrameReceipt {
                status: FRAME_RECEIPT_STATUS_SUCCESS,
                gas_used: GasUsed {
                    execution: 21_000,
                    state: 0,
                },
                logs: Vec::new(),
            }]),
        };
        let encoded = receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);
        // EIP-2718 type prefix
        assert_eq!(encoded[0], 0x06);
        // Spec ReceiptPayload: [cumulative_gas_used, payer, [frame_receipt, ...]]
        let mut expected_payload = Vec::new();
        Encoder::new(&mut expected_payload)
            .encode_field(&100_000u64)
            .encode_field(&Address::from_low_u64_be(0xBEEF))
            .encode_field(receipt.frame_receipts.as_ref().unwrap())
            .finish();
        assert_eq!(&encoded[1..], &expected_payload[..]);
    }

    #[test]
    fn decode_inner_with_bloom_roundtrips_nonframe() {
        // Non-frame: encode_inner_with_bloom carries a bloom that
        // decode_inner_with_bloom drops. Compare every field except the dropped
        // bloom — i.e. the decoded receipt must equal the original Receipt.
        let receipt = Receipt {
            tx_type: TxType::EIP1559,
            succeeded: true,
            cumulative_gas_used: 54321,
            logs: vec![Log {
                address: Address::from_low_u64_be(0xabcd),
                topics: vec![h256_from_hex(
                    "e70c0d1060ffbafc84e0e18d028245de3deeb0f41ecbade6562fa657d85ae945",
                )],
                data: Bytes::from_static(b"hello"),
            }],
            payer: None,
            frame_receipts: None,
        };
        let encoded = receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);
        let (decoded, rest) = Receipt::decode_inner_with_bloom(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn decode_inner_with_bloom_roundtrips_legacy() {
        let receipt = Receipt {
            tx_type: TxType::Legacy,
            succeeded: false,
            cumulative_gas_used: 100,
            logs: vec![],
            payer: None,
            frame_receipts: None,
        };
        let encoded = receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);
        let (decoded, rest) = Receipt::decode_inner_with_bloom(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn decode_inner_with_bloom_roundtrips_frame_preserving_payer_and_frames() {
        // Frame: payer and frame_receipts MUST survive the roundtrip. succeeded
        // is derived from the frame statuses and logs is empty by construction.
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: true,
            cumulative_gas_used: 315000,
            logs: vec![],
            payer: Some(Address::from_low_u64_be(0x1234)),
            frame_receipts: Some(vec![
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 100000,
                        state: 0,
                    },
                    logs: vec![],
                },
                FrameReceipt {
                    status: FRAME_RECEIPT_STATUS_SUCCESS,
                    gas_used: GasUsed {
                        execution: 200000,
                        state: 0,
                    },
                    logs: vec![Log {
                        address: Address::from_low_u64_be(0xbeef),
                        topics: vec![],
                        data: Bytes::from_static(b"frame2"),
                    }],
                },
            ]),
        };
        let encoded = receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);
        let (decoded, rest) = Receipt::decode_inner_with_bloom(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.tx_type, TxType::Frame);
        assert_eq!(decoded.cumulative_gas_used, 315000);
        assert_eq!(decoded.payer, Some(Address::from_low_u64_be(0x1234)));
        assert_eq!(decoded.frame_receipts, receipt.frame_receipts);
        assert!(decoded.succeeded); // derived: all frame receipts succeeded
        assert!(decoded.logs.is_empty());
        // Full equality: the whole receipt round-trips.
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn decode_inner_with_bloom_frame_zero_payer_maps_to_none() {
        let receipt = Receipt {
            tx_type: TxType::Frame,
            succeeded: true,
            cumulative_gas_used: 21000,
            logs: vec![],
            payer: None,
            frame_receipts: Some(vec![FrameReceipt {
                status: FRAME_RECEIPT_STATUS_SUCCESS,
                gas_used: GasUsed {
                    execution: 21000,
                    state: 0,
                },
                logs: vec![],
            }]),
        };
        let encoded = receipt.encode_inner_with_bloom(&ethrex_crypto::NativeCrypto);
        let (decoded, _) = Receipt::decode_inner_with_bloom(&encoded).unwrap();
        assert_eq!(decoded.payer, None);
        assert_eq!(decoded, receipt);
    }
}
