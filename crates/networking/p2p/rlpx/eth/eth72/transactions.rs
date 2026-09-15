use std::collections::HashSet;

use crate::rlpx::{
    eth::transactions::{MAX_POOLED_TRANSACTIONS_BYTES, POOLED_TX_SIZE_TOLERANCE},
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress, snappy_decompress_bounded},
};
use crate::types::Node;
use bytes::Bytes;
use ethrex_blockchain::Blockchain;
use ethrex_blockchain::error::MempoolError;
use ethrex_common::types::{Fork, P2PTransaction, WrappedEIP4844Transaction};
use ethrex_common::{H256, types::Transaction};
use ethrex_crypto::NativeCrypto;
use ethrex_rlp::{
    encode::RLPEncode,
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};
use ethrex_storage::error::StoreError;
use tracing::debug;

/// Convert u128 to the `B_16` (uint128) `cell_mask` wire array per EIP-8070.
///
/// The internal convention is column index `i` == bit `i` of the u128
/// (`1u128 << i`). Little-endian byte order therefore places column `i` at
/// byte `i/8`, bit `i%8` (LSB-first), which is the canonical layout used by
/// geth's `types.CustodyBitmap` (`[16]byte`, little-endian:
/// `result[i/8] |= 1 << (i % 8)`). Matching it is required for eth/72 interop.
pub fn u128_to_b16(v: u128) -> [u8; 16] {
    v.to_le_bytes()
}

/// Decode a `B_16` `cell_mask` wire array back to u128 (little-endian, geth
/// `CustodyBitmap`-compatible; see `u128_to_b16`).
pub fn b16_to_u128(b: [u8; 16]) -> u128 {
    u128::from_le_bytes(b)
}

/// Encode `cell_mask: Option<u128>` as RLP bytes:
/// - None  → empty bytes (RLP nil, 0x80)
/// - Some  → 16-byte little-endian (B_16, geth CustodyBitmap layout)
fn cell_mask_to_bytes(mask: Option<u128>) -> Bytes {
    match mask {
        None => Bytes::new(),
        Some(v) => Bytes::from(u128_to_b16(v).to_vec()),
    }
}

/// Decode RLP bytes back to `cell_mask`:
/// - empty bytes → None
/// - 16 bytes    → Some(u128)
/// - other       → error
pub(crate) fn bytes_to_cell_mask(b: &Bytes) -> Result<Option<u128>, RLPDecodeError> {
    if b.is_empty() {
        Ok(None)
    } else if b.len() == 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok(Some(b16_to_u128(arr)))
    } else {
        Err(RLPDecodeError::Custom(
            "cell_mask must be empty (nil) or exactly 16 bytes".to_string(),
        ))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#newpooledtransactionhashes-0x08
// eth/72 variant — adds cell_mask field (EIP-8070).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NewPooledTransactionHashes72 {
    pub transaction_types: Bytes,
    pub transaction_sizes: Vec<usize>,
    pub transaction_hashes: Vec<H256>,
    /// 128-bit bitmask indicating which cells are held for blob txs.
    /// None encodes to RLP nil (0x80) and MUST be nil when no type-3 tx is
    /// announced.
    pub cell_mask: Option<u128>,
}

impl NewPooledTransactionHashes72 {
    pub fn new(
        transactions: Vec<Transaction>,
        blockchain: &Blockchain,
    ) -> Result<Self, StoreError> {
        let transactions_len = transactions.len();
        let mut transaction_types = Vec::with_capacity(transactions_len);
        let mut transaction_sizes = Vec::with_capacity(transactions_len);
        let mut transaction_hashes = Vec::with_capacity(transactions_len);
        let mut has_blob_tx = false;

        for transaction in transactions {
            let tx_type = transaction.tx_type();
            let transaction_hash = transaction.hash(&NativeCrypto);
            let transaction_size = match transaction {
                Transaction::EIP4844Transaction(eip4844_tx) => {
                    // See `NewPooledTransactionHashes::new`: a blob tx whose bundle is no
                    // longer in the pool cannot be served, so it must not be announced.
                    // An empty bundle would announce ~162 bytes for a ~137 KB transaction.
                    let Some(tx_blobs_bundle) =
                        blockchain.mempool.get_blobs_bundle(transaction_hash)?
                    else {
                        continue;
                    };
                    let p2p_tx =
                        P2PTransaction::EIP4844TransactionWithBlobs(WrappedEIP4844Transaction {
                            tx: eip4844_tx,
                            wrapper_version: (tx_blobs_bundle.version != 0)
                                .then_some(tx_blobs_bundle.version),
                            blobs_bundle: tx_blobs_bundle,
                        });
                    p2p_tx.encode_canonical_len()
                }
                _ => transaction.encode_canonical_len(),
            };
            if tx_type as u8 == 3 {
                has_blob_tx = true;
            }
            transaction_types.push(tx_type as u8);
            transaction_hashes.push(transaction_hash);
            transaction_sizes.push(transaction_size);
        }

        // cell_mask MUST be nil when no type-3 tx is announced (EIP-8070, devp2p
        // changes to `NewPooledTransactionHashes`).
        // When blob txs are present, compute the AND of available_cell_mask over
        // every type-3 hash: this is the set of columns available for ALL of them,
        // so receivers know we can serve every requested column for the whole batch.
        // u128::MAX is advertised when we hold the full blob payload (all 128
        // columns derivable); otherwise the sampled-cells mask is used.
        let cell_mask = if has_blob_tx {
            let mask = transaction_hashes
                .iter()
                .zip(transaction_types.iter())
                .filter(|&(_, &ty)| ty == 3)
                .fold(u128::MAX, |acc, (hash, _)| {
                    acc & blockchain.mempool.available_cell_mask(*hash)
                });
            Some(mask)
        } else {
            None
        };

        Ok(Self {
            transaction_types: transaction_types.into(),
            transaction_sizes,
            transaction_hashes,
            cell_mask,
        })
    }

    pub fn get_transactions_to_request(
        &self,
        blockchain: &Blockchain,
        announcer: H256,
    ) -> Result<Vec<H256>, StoreError> {
        blockchain.mempool.reserve_unknown_hashes(
            &self.transaction_hashes,
            &self.transaction_types,
            &self.transaction_sizes,
            announcer,
        )
    }

    /// Whether this announcement carries a blob (type 3) transaction.
    ///
    /// devp2p `caps/eth.md` ("NewPooledTransactionHashes (0x08)") types `cells` as
    /// `B_16` and says it "is only relevant for those entries that refer to blob
    /// transactions, and can be ignored when no blob transactions are announced";
    /// EIP-8070 instead says the field is nil in that case. A peer following devp2p
    /// therefore sends 16 zero bytes on every non-blob announcement, so the mask
    /// carries an availability claim only when this returns true.
    pub fn announces_blob_tx(&self) -> bool {
        self.transaction_types.contains(&3)
    }

    /// Build from pre-computed raw fields.
    pub fn from_raw(
        transaction_types: Bytes,
        transaction_sizes: Vec<usize>,
        transaction_hashes: Vec<H256>,
        cell_mask: Option<u128>,
    ) -> Self {
        Self {
            transaction_types,
            transaction_sizes,
            transaction_hashes,
            cell_mask,
        }
    }

    /// Convert from a v71 announcement (no cell_mask).
    ///
    /// No `Blockchain` handle is available here, so we cannot look up
    /// `available_cell_mask`. We conservatively advertise 0 for blob txs
    /// (signaling no cells held) rather than u128::MAX. This is safe: sampler
    /// peers will simply not request cells from us for this announcement.
    /// Callers with access to the blockchain should prefer `new()` instead.
    pub fn from_v71(
        transaction_types: Bytes,
        transaction_sizes: Vec<usize>,
        transaction_hashes: Vec<H256>,
    ) -> Self {
        let has_blob_tx = transaction_types.contains(&3);
        // Conservative: no blockchain handle → advertise 0 (no cells available).
        let cell_mask = has_blob_tx.then_some(0u128);
        Self {
            transaction_types,
            transaction_sizes,
            transaction_hashes,
            cell_mask,
        }
    }

    /// Convert into a v71-compatible announcement (drops cell_mask).
    pub fn into_v71(self) -> (Bytes, Vec<usize>, Vec<H256>) {
        (
            self.transaction_types,
            self.transaction_sizes,
            self.transaction_hashes,
        )
    }

    /// Return a new announcement containing only the hashes in `requested`,
    /// preserving their original type and size metadata. The `cell_mask` is
    /// preserved from the original announcement.
    pub fn filter_to(&self, requested: &[H256]) -> Self {
        let mut types = Vec::with_capacity(requested.len());
        let mut sizes = Vec::with_capacity(requested.len());
        let mut hashes = Vec::with_capacity(requested.len());
        for &hash in requested {
            if let Some(pos) = self.transaction_hashes.iter().position(|h| *h == hash) {
                types.push(self.transaction_types[pos]);
                sizes.push(self.transaction_sizes[pos]);
                hashes.push(hash);
            }
        }
        Self {
            transaction_types: types.into(),
            transaction_sizes: sizes,
            transaction_hashes: hashes,
            cell_mask: self.cell_mask,
        }
    }
}

impl RLPxMessage for NewPooledTransactionHashes72 {
    const CODE: u8 = 0x08;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        let mask_bytes = cell_mask_to_bytes(self.cell_mask);
        Encoder::new(&mut encoded_data)
            .encode_field(&self.transaction_types)
            .encode_field(&self.transaction_sizes)
            .encode_field(&self.transaction_hashes)
            .encode_field(&mask_bytes)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (transaction_types, decoder): (Bytes, _) = decoder.decode_field("transactionTypes")?;
        let (transaction_sizes, decoder): (Vec<usize>, _) =
            decoder.decode_field("transactionSizes")?;
        let (transaction_hashes, decoder): (Vec<H256>, _) =
            decoder.decode_field("transactionHashes")?;
        let (mask_bytes, _): (Bytes, _) = decoder.decode_field("cellMask")?;
        let cell_mask = bytes_to_cell_mask(&mask_bytes)?;

        if transaction_hashes.len() == transaction_sizes.len()
            && transaction_sizes.len() == transaction_types.len()
        {
            Ok(Self {
                transaction_types,
                transaction_sizes,
                transaction_hashes,
                cell_mask,
            })
        } else {
            Err(RLPDecodeError::Custom(
                "transaction_hashes, transaction_sizes and transaction_types must have the same length"
                    .to_string(),
            ))
        }
    }
}

/// Build the elided canonical encoding for a blob tx in eth/72:
/// `0x03 || rlp([tx, wrapper_version?, [], commitments, proofs])`
/// The blobs list is empty instead of the full blobs.
pub fn encode_elided_canonical(wrapped: &WrappedEIP4844Transaction) -> Vec<u8> {
    let empty_blobs: Vec<Vec<u8>> = vec![];
    let mut inner = vec![];
    Encoder::new(&mut inner)
        .encode_field(&wrapped.tx)
        .encode_optional_field(&wrapped.wrapper_version)
        .encode_field(&empty_blobs)
        .encode_field(&wrapped.blobs_bundle.commitments)
        .encode_field(&wrapped.blobs_bundle.proofs)
        .finish();
    let mut out = vec![0x03u8];
    out.extend_from_slice(&inner);
    out
}

/// A transaction as it appears in an eth/72 `PooledTransactions`: an RLP byte
/// string holding the canonical encoding, with the blob payload elided for type 3.
struct Elided<'a>(&'a P2PTransaction);

impl RLPEncode for Elided<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self.0 {
            P2PTransaction::EIP4844TransactionWithBlobs(wrapped) => {
                <[u8] as RLPEncode>::encode(&encode_elided_canonical(wrapped), buf)
            }
            // A legacy transaction is emitted as its bare RLP list, never wrapped
            // in a byte string — mirrors `P2PTransaction`'s canonical encoding.
            // Wrapping it would double-encode and no conforming peer could decode
            // the element.
            P2PTransaction::LegacyTransaction(tx) => tx.encode(buf),
            other => <[u8] as RLPEncode>::encode(&other.encode_canonical_to_vec(), buf),
        }
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#pooledtransactions-0x0a
// eth/72 variant: blob transactions encoded with ELIDED blob payload.
#[derive(Debug, Clone)]
pub struct PooledTransactions72 {
    pub id: u64,
    pub pooled_transactions: Vec<P2PTransaction>,
}

impl PooledTransactions72 {
    pub fn new(id: u64, pooled_transactions: Vec<P2PTransaction>) -> Self {
        Self {
            pooled_transactions,
            id,
        }
    }

    /// Validates that received txs match the request.
    /// Size check is skipped for blob txs since announced size reflects full blobs
    /// while eth/72 uses elided encoding.
    pub fn validate_requested(
        &self,
        requested: &NewPooledTransactionHashes72,
        _fork: Fork,
    ) -> Result<(), MempoolError> {
        // A well-formed response contains each requested tx at most once; reject duplicates
        // before any per-tx work so a peer echoing one tx N times can't balloon the response
        // (mirrors the eth/71 path in `PooledTransactions::validate_requested`).
        let mut seen = HashSet::with_capacity(self.pooled_transactions.len());
        for tx in &self.pooled_transactions {
            let tx_hash = tx.compute_hash();
            if !seen.insert(tx_hash) {
                return Err(MempoolError::DuplicatePooledTx);
            }
            let Some(pos) = requested
                .transaction_hashes
                .iter()
                .position(|&hash| hash == tx_hash)
            else {
                return Err(MempoolError::RequestedPooledTxNotFound);
            };

            let expected_type = requested.transaction_types[pos];
            if tx.tx_type() as u8 != expected_type {
                return Err(MempoolError::InvalidPooledTxType(expected_type));
            }
            // Size validation skipped for blob txs: announced size reflects full-blob
            // encoding while eth/72 elided encoding is smaller.
            if tx.tx_type() as u8 != 3 {
                let expected_size = requested.transaction_sizes[pos];
                let tx_size = tx.encode_canonical_len();
                // Same tolerance as the eth/71 path: geth's tx fetcher allows up to 8 bytes
                // of skew between the announced and actual size before treating it as a
                // protocol violation.
                if tx_size.abs_diff(expected_size) > POOLED_TX_SIZE_TOLERANCE {
                    return Err(MempoolError::InvalidPooledTxSize);
                }
            }
        }
        Ok(())
    }

    /// Stores transactions; blob txs are stored with commitments+proofs, blobs elided.
    pub async fn handle(
        self,
        node: &Node,
        blockchain: &Blockchain,
        is_l2_mode: bool,
    ) -> Result<(), MempoolError> {
        for tx in self.pooled_transactions {
            if let P2PTransaction::EIP4844TransactionWithBlobs(itx) = tx {
                if is_l2_mode {
                    debug!(
                        peer=%node,
                        "Rejecting blob transaction in L2 mode",
                    );
                    continue;
                }
                // Blobs are elided in eth/72; store commitments+proofs.
                // Full KZG validation deferred until blobs are fetched via GetCells.
                if let Err(e) = blockchain
                    .add_blob_transaction_to_pool(itx.tx, itx.blobs_bundle)
                    .await
                {
                    if matches!(e, MempoolError::BlobsBundleError(_)) {
                        return Err(e);
                    }
                    debug!(
                        peer=%node,
                        error=%e,
                        "Error adding blob transaction",
                    );
                    continue;
                }
            } else {
                let regular_tx = tx
                    .try_into()
                    .map_err(|error| MempoolError::StoreError(StoreError::Custom(error)))?;
                if let Err(e) = blockchain.add_transaction_to_pool(regular_tx).await {
                    debug!(
                        peer=%node,
                        error=%e,
                        "Error adding transaction",
                    );
                    continue;
                }
            }
        }
        Ok(())
    }
}

impl RLPxMessage for PooledTransactions72 {
    const CODE: u8 = 0x0A;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let elided: Vec<Elided<'_>> = self.pooled_transactions.iter().map(Elided).collect();
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&elided)
            .finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        // Bound the declared decompressed length before materializing the tx list, as the
        // eth/71 `PooledTransactions` path does. Elided blob payloads make an eth/72 response
        // strictly smaller than its eth/71 equivalent, so the same cap applies.
        let decompressed_data = snappy_decompress_bounded(msg_data, MAX_POOLED_TRANSACTIONS_BYTES)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (pooled_transactions, _): (Vec<P2PTransaction>, _) =
            decoder.decode_field("pooledTransactions")?;

        Ok(Self::new(id, pooled_transactions))
    }
}
