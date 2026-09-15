use std::collections::HashSet;

use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress, snappy_decompress_bounded},
};
use crate::types::Node;
use bytes::Bytes;
use ethrex_blockchain::Blockchain;
use ethrex_blockchain::error::MempoolError;
use ethrex_common::types::Fork;
use ethrex_common::types::P2PTransaction;
use ethrex_common::types::WrappedEIP4844Transaction;
use ethrex_common::{H256, types::Transaction};
use ethrex_crypto::NativeCrypto;
use ethrex_rlp::{
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};
use ethrex_storage::error::StoreError;
use tracing::debug;

/// Allowed skew between a peer's announced pooled-transaction size and the size we compute
/// from the received transaction. The announced size is a soft hint that varies slightly
/// between clients (e.g. geth's `Transaction.Size()` omits the v1 blob-sidecar wrapper
/// version byte), so we tolerate a few bytes before treating it as a protocol violation.
/// Matches go-ethereum's tx fetcher (`eth/fetcher/tx_fetcher.go`).
pub(crate) const POOLED_TX_SIZE_TOLERANCE: usize = 8;

/// Upper bound on the decompressed size of a `PooledTransactions` response, enforced before
/// decompression so an oversized reply is rejected without materializing it. Tighter than the
/// global frame/snappy cap (`MAX_SNAPPY_DECOMPRESSED_LEN`, ~16 MiB): go-ethereum soft-limits a
/// response to `softResponseLimit` (2 MiB) and stops after the first tx that crosses it, so a
/// well-behaved reply is at most ~2 MiB plus one max-size tx (~1 MiB blob wrapper). 4 MiB clears
/// that with margin while staying 4× below the frame cap.
pub(crate) const MAX_POOLED_TRANSACTIONS_BYTES: usize = 4 * 1024 * 1024;

/// Target maximum size of a `PooledTransactions` response we *serve*, matching go-ethereum's
/// `softResponseLimit` (2 MiB). We stop before a transaction would push the response over this,
/// so what we emit stays well under any peer's inbound decode cap
/// ([`MAX_POOLED_TRANSACTIONS_BYTES`]). Partial responses are protocol-legal — the requester
/// re-requests whatever it still needs.
const MAX_POOLED_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#transactions-0x02
// Broadcast message
#[derive(Debug, Clone)]
pub struct Transactions {
    pub transactions: Vec<Transaction>,
}

impl Transactions {
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self { transactions }
    }
}

impl RLPxMessage for Transactions {
    const CODE: u8 = 0x02;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        let mut encoder = Encoder::new(&mut encoded_data);
        let txs_iter = self.transactions.iter();
        for tx in txs_iter {
            encoder = encoder.encode_field(tx)
        }
        encoder.finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let mut decoder = Decoder::new(&decompressed_data)?;
        let mut transactions: Vec<Transaction> = vec![];
        // This is done like this because the blanket Vec<T> implementation
        // gets confused since a legacy transaction is actually a list,
        // or so it seems.
        while let Ok((tx, updated_decoder)) = decoder.decode_field::<Transaction>("p2p transaction")
        {
            decoder = updated_decoder;
            transactions.push(tx);
        }
        Ok(Self::new(transactions))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#newpooledtransactionhashes-0x08
// Broadcast message
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NewPooledTransactionHashes {
    pub transaction_types: Bytes,
    pub transaction_sizes: Vec<usize>,
    pub transaction_hashes: Vec<H256>,
}

impl NewPooledTransactionHashes {
    /// Build from pre-computed raw fields (used when constructing trimmed announcements).
    pub fn from_raw(
        transaction_types: Bytes,
        transaction_sizes: Vec<usize>,
        transaction_hashes: Vec<H256>,
    ) -> Self {
        Self {
            transaction_types,
            transaction_sizes,
            transaction_hashes,
        }
    }

    pub fn new(
        transactions: Vec<Transaction>,
        blockchain: &Blockchain,
    ) -> Result<Self, StoreError> {
        let transactions_len = transactions.len();
        let mut transaction_types = Vec::with_capacity(transactions_len);
        let mut transaction_sizes = Vec::with_capacity(transactions_len);
        let mut transaction_hashes = Vec::with_capacity(transactions_len);
        for transaction in transactions {
            let transaction_type = transaction.tx_type();
            let transaction_hash = transaction.hash(&NativeCrypto);
            // size is defined as the len of the canonical encoding of the transaction
            // as it would appear in a PooledTransactions response.
            // https://eips.ethereum.org/EIPS/eip-2718
            let transaction_size = match transaction {
                // Blob transactions use the network (wrapped) representation
                // which includes the blobs bundle.
                // https://eips.ethereum.org/EIPS/eip-4844#networking
                Transaction::EIP4844Transaction(eip4844_tx) => {
                    // If the bundle is gone (the tx was evicted or pulled into a payload
                    // between the broadcaster's snapshot and now) we cannot serve this tx
                    // either: `Blockchain::get_p2p_transaction_by_hash` errors out on a
                    // blob tx with no bundle, so `GetPooledTransactions` skips it. Skip it
                    // here too. Substituting an empty bundle would announce ~162 bytes for
                    // a ~137 KB transaction, and peers that check the announced size
                    // against the delivered one (geth's tx fetcher, and our own
                    // `validate_requested` below, both with an 8-byte tolerance) will
                    // disconnect us for the mismatch.
                    let Some(tx_blobs_bundle) =
                        blockchain.mempool.get_blobs_bundle(transaction_hash)?
                    else {
                        continue;
                    };
                    // A tx ingested over eth/72 may hold an elided bundle (commitments
                    // and proofs, no blobs; cells travel separately). This pre-72
                    // announcement promises a full-blob delivery, but the serve path
                    // drops elided txs from pre-72 responses (`GetPooledTransactions`
                    // arm in `connection/server.rs`), so we would announce a hash we
                    // never deliver — and with a size no full-blob delivery can match.
                    // geth's tx fetcher checks a delivered tx against every peer that
                    // announced its hash, so when another peer delivers the full tx the
                    // mismatch is charged to us. Skip it, mirroring the serve path.
                    if tx_blobs_bundle.blobs.len() != tx_blobs_bundle.commitments.len() {
                        continue;
                    }
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
            transaction_types.push(transaction_type as u8);
            transaction_hashes.push(transaction_hash);
            transaction_sizes.push(transaction_size);
        }
        Ok(Self {
            transaction_types: transaction_types.into(),
            transaction_sizes,
            transaction_hashes,
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

    /// Extract only the entries for the given `requested` hashes from this announcement.
    /// Returns a trimmed announcement containing just those hashes with their types and sizes.
    pub fn filter_to(&self, requested: &[H256]) -> NewPooledTransactionHashes {
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
        NewPooledTransactionHashes {
            transaction_types: types.into(),
            transaction_sizes: sizes,
            transaction_hashes: hashes,
        }
    }
}

impl RLPxMessage for NewPooledTransactionHashes {
    const CODE: u8 = 0x08;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.transaction_types)
            .encode_field(&self.transaction_sizes)
            .encode_field(&self.transaction_hashes)
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
        // The announcement is exactly three fields until eth/72 adds `cell_mask`
        // (EIP-8070). Reject a longer list instead of ignoring the extra fields,
        // so a peer encoding a newer shape on this session is caught here.
        decoder.finish()?;

        if transaction_hashes.len() == transaction_sizes.len()
            && transaction_sizes.len() == transaction_types.len()
        {
            Ok(Self {
                transaction_types,
                transaction_sizes,
                transaction_hashes,
            })
        } else {
            Err(RLPDecodeError::Custom(
                "transaction_hashes, transaction_sizes and transaction_types must have the same length"
                    .to_string(),
            ))
        }
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#getpooledtransactions-0x09
#[derive(Debug, Clone)]
pub struct GetPooledTransactions {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub transaction_hashes: Vec<H256>,
}

impl GetPooledTransactions {
    pub fn new(id: u64, transaction_hashes: Vec<H256>) -> Self {
        Self {
            transaction_hashes,
            id,
        }
    }

    pub fn handle(&self, blockchain: &Blockchain) -> Result<PooledTransactions, StoreError> {
        // TODO(#1615): get transactions in batch instead of iterating over them.
        let mut pooled_transactions = Vec::new();
        let mut seen = HashSet::with_capacity(self.transaction_hashes.len());
        let mut bytes_used = 0usize;
        for hash in &self.transaction_hashes {
            // Serve each requested hash at most once: a peer padding the request with duplicates
            // must not amplify the response or force repeated mempool lookups (the lookup is
            // skipped for a repeat, so an all-duplicate request costs one probe, not N).
            if !seen.insert(*hash) {
                continue;
            }
            // As per the spec, skipping unavailable transactions is perfectly acceptable,
            // for example if a transaction was taken out of the mempool due to payload
            // building after being advertised.
            let Ok(tx) = blockchain.get_p2p_transaction_by_hash(hash) else {
                continue;
            };
            // Cap the response size (geth `softResponseLimit`): stop before a tx would push the
            // response over the budget so we never emit more than a peer's inbound cap accepts.
            // Always serve at least one tx so a lone oversized (blob) tx still goes out.
            let tx_size = tx.encode_canonical_len();
            if !pooled_transactions.is_empty() && bytes_used + tx_size > MAX_POOLED_RESPONSE_BYTES {
                break;
            }
            bytes_used += tx_size;
            pooled_transactions.push(tx);
        }

        Ok(PooledTransactions {
            id: self.id,
            pooled_transactions,
        })
    }
}

impl RLPxMessage for GetPooledTransactions {
    const CODE: u8 = 0x09;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.transaction_hashes)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (transaction_hashes, _): (Vec<H256>, _) = decoder.decode_field("transactionHashes")?;

        Ok(Self::new(id, transaction_hashes))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#pooledtransactions-0x0a
#[derive(Debug, Clone)]
pub struct PooledTransactions {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub pooled_transactions: Vec<P2PTransaction>,
}

impl PooledTransactions {
    pub fn new(id: u64, pooled_transactions: Vec<P2PTransaction>) -> Self {
        Self {
            pooled_transactions,
            id,
        }
    }

    /// validates if the received TXs match the request
    pub fn validate_requested(
        &self,
        requested: &NewPooledTransactionHashes,
        fork: Fork,
    ) -> Result<(), MempoolError> {
        // A well-formed response contains each requested tx at most once. Track seen hashes so
        // a peer can't send duplicates (or more txs than requested) — each would otherwise pass
        // the per-tx checks below, letting a response balloon to the frame cap regardless of
        // how little we asked for.
        let mut seen = HashSet::with_capacity(self.pooled_transactions.len());
        for tx in &self.pooled_transactions {
            // Reject duplicates before any per-tx work (blob validation, hash lookup) so a peer
            // echoing the same tx N times can't force N rounds of that work — fail fast.
            let tx_hash = tx.compute_hash();
            if !seen.insert(tx_hash) {
                return Err(MempoolError::DuplicatePooledTx);
            }
            if let P2PTransaction::EIP4844TransactionWithBlobs(itx) = tx {
                itx.blobs_bundle.validate_cheap(&itx.tx, fork)?;
            }
            let Some(pos) = requested
                .transaction_hashes
                .iter()
                .position(|&hash| hash == tx_hash)
            else {
                return Err(MempoolError::RequestedPooledTxNotFound);
            };

            let expected_type = requested.transaction_types[pos];
            let expected_size = requested.transaction_sizes[pos];
            if tx.tx_type() as u8 != expected_type {
                return Err(MempoolError::InvalidPooledTxType(expected_type));
            }
            // The announced size is a soft hint, not an exact value. geth's
            // `Transaction.Size()` under-counts a v1 (EIP-7594 cell-proof) blob sidecar by
            // one byte — it omits the wrapper version byte — so a strict equality check
            // would disconnect geth peers on every v1 blob-tx announcement. Match geth's tx
            // fetcher, which tolerates up to 8 bytes of skew before treating it as a
            // violation (go-ethereum eth/fetcher/tx_fetcher.go).
            let tx_size = tx.encode_canonical_len();
            if tx_size.abs_diff(expected_size) > POOLED_TX_SIZE_TOLERANCE {
                return Err(MempoolError::InvalidPooledTxSize);
            }
        }
        Ok(())
    }

    /// Saves every incoming pooled transaction to the mempool.
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
                        "Rejecting blob transaction in L2 mode - blob transactions are not supported in L2",
                    );
                    continue;
                }
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
                        "Error adding transaction"
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
                        "Error adding transaction"
                    );
                    continue;
                }
            }
        }
        Ok(())
    }
}

impl RLPxMessage for PooledTransactions {
    const CODE: u8 = 0x0A;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.pooled_transactions)
            .finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        // Reject an oversized response by its declared decompressed length before allocating and
        // materializing the transaction list (which for blob txs pulls large sidecars into
        // memory). See `MAX_POOLED_TRANSACTIONS_BYTES`.
        let decompressed_data = snappy_decompress_bounded(msg_data, MAX_POOLED_TRANSACTIONS_BYTES)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (pooled_transactions, _): (Vec<P2PTransaction>, _) =
            decoder.decode_field("pooledTransactions")?;

        Ok(Self::new(id, pooled_transactions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::types::EIP1559Transaction;

    fn p2p_tx(nonce: u64) -> P2PTransaction {
        P2PTransaction::EIP1559Transaction(EIP1559Transaction {
            nonce,
            ..Default::default()
        })
    }

    fn announcement_for(txs: &[P2PTransaction]) -> NewPooledTransactionHashes {
        NewPooledTransactionHashes::from_raw(
            txs.iter()
                .map(|t| t.tx_type() as u8)
                .collect::<Vec<_>>()
                .into(),
            txs.iter().map(|t| t.encode_canonical_len()).collect(),
            txs.iter().map(|t| t.compute_hash()).collect(),
        )
    }

    #[test]
    fn validate_requested_accepts_each_requested_tx_once() {
        let txs = vec![p2p_tx(0), p2p_tx(1)];
        let announced = announcement_for(&txs);
        let response = PooledTransactions::new(0, txs);
        assert!(
            response
                .validate_requested(&announced, Fork::Cancun)
                .is_ok()
        );
    }

    #[test]
    fn validate_requested_rejects_duplicate_tx() {
        // We requested one tx; the peer echoes it twice. Both copies pass the per-tx type/size
        // checks, so without the duplicate guard the response could balloon past what we asked.
        let announced = announcement_for(&[p2p_tx(0)]);
        let response = PooledTransactions::new(0, vec![p2p_tx(0), p2p_tx(0)]);
        assert!(matches!(
            response.validate_requested(&announced, Fork::Cancun),
            Err(MempoolError::DuplicatePooledTx)
        ));
    }
}
