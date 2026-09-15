use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress_bounded},
};
use ethrex_blockchain::mempool::Mempool;
use ethrex_common::{
    H256,
    types::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB, MAX_BLOB_COUNT},
};
use ethrex_rlp::{
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};

use super::eth72::transactions::{b16_to_u128, u128_to_b16};

/// A single PeerDAS cell: 2048 bytes (BYTES_PER_CELL = 64 field elements * 32 bytes each).
pub type Cell = [u8; BYTES_PER_CELL];

/// Upper bound on transaction hashes accepted in a single GetCells/Cells message.
/// Caps allocation from a malicious peer; mirrors the GetBlockBodies-style limits.
pub const MAX_CELL_REQUEST_HASHES: usize = 256;

/// Recommended soft limit for a `GetCells` request, per devp2p `caps/eth.md`
/// ("GetCells (0x14)"). We never ask for more in one message; a peer may enforce
/// an arbitrary limit on the response, which is not a protocol violation.
pub const GET_CELLS_SOFT_LIMIT_HASHES: usize = 64;

/// Upper bound on cells per transaction in a `Cells` message: at most
/// `MAX_BLOB_COUNT` blobs * `CELLS_PER_EXT_BLOB` columns. Bounds the per-tx
/// inner-vec allocation at decode time.
pub const MAX_CELLS_PER_TX: usize = MAX_BLOB_COUNT * CELLS_PER_EXT_BLOB;

/// Upper bound on the decompressed size of a `GetCells` request: a request id, at
/// most [`MAX_CELL_REQUEST_HASHES`] 32-byte hashes (33 bytes each once RLP-tagged)
/// and a 16-byte mask, with slack for the list headers. Rejects an oversized frame
/// by its declared length, before the hash-count check can run on decoded data.
const MAX_GET_CELLS_BYTES: usize = MAX_CELL_REQUEST_HASHES * 33 + 256;

/// Recommended soft limit for a `Cells` response, per devp2p `caps/eth.md`
/// ("Cells (0x15)"). Bounds what one `GetCells` can pull out of us.
const MAX_CELLS_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Upper bound on the decompressed size of a `Cells` response, enforced before
/// decompression so an oversized reply is rejected without materializing it.
/// Twice the soft serve limit, leaving room for a peer that overshoots by a
/// transaction, the same headroom the `PooledTransactions` path allows.
const MAX_CELLS_BYTES: usize = 2 * MAX_CELLS_RESPONSE_BYTES;

/// Cell budget for a `Cells` response we *serve*, derived from
/// [`MAX_CELLS_RESPONSE_BYTES`]. We stop before a transaction would push the
/// response past it. devp2p `caps/eth.md` lets a peer "omit entire transactions
/// from the list [...] if they are unavailable or constrained", so a partial
/// response is protocol-legal.
pub const MAX_CELLS_SERVED: usize = MAX_CELLS_RESPONSE_BYTES / BYTES_PER_CELL;

/// Worst-case cells one requested hash can pull, used to size a `GetCells`
/// request so a peer applying [`MAX_CELLS_SERVED`] can answer it in full.
pub const fn cells_per_hash(cell_mask: u128) -> usize {
    let columns = cell_mask.count_ones() as usize;
    if columns == 0 {
        1
    } else {
        columns * MAX_BLOB_COUNT
    }
}

// https://eips.ethereum.org/EIPS/eip-8070#getcells-0x14
//
// Note: the EIP schema lines show `[[hashes], cell_mask]` without a request id,
// but that is the usual eth/66+ shorthand (the schemas omit the request_id
// wrapper). EIP-8070's rationale confirms the wrapper is intended: the
// "devp2p message schema choices" section accounts for "one uint64 request_id
// and one uint8 message_type" of per-message overhead. The leading `id` field
// is therefore correct and matches the eth/66+ request/response framing.
#[derive(Debug, Clone)]
pub struct GetCells {
    pub id: u64,
    pub transaction_hashes: Vec<H256>,
    /// Bitmask of which cells are requested (128 bits, one per column index 0..127).
    pub cell_mask: u128,
}

impl GetCells {
    pub fn new(id: u64, transaction_hashes: Vec<H256>, cell_mask: u128) -> Self {
        Self {
            id,
            transaction_hashes,
            cell_mask,
        }
    }
}

impl RLPxMessage for GetCells {
    const CODE: u8 = 0x14;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        use bytes::Bytes;
        let mut encoded_data = vec![];
        let mask_bytes = Bytes::from(u128_to_b16(self.cell_mask).to_vec());
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.transaction_hashes)
            .encode_field(&mask_bytes)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        use bytes::Bytes;
        // A well-formed request is a request id, at most MAX_CELL_REQUEST_HASHES
        // hashes and a 16-byte mask; bound the declared length so an oversized
        // frame is rejected before it is materialized.
        let decompressed_data = snappy_decompress_bounded(msg_data, MAX_GET_CELLS_BYTES)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (transaction_hashes, decoder): (Vec<H256>, _) =
            decoder.decode_field("transactionHashes")?;
        let (mask_bytes, _): (Bytes, _) = decoder.decode_field("cellMask")?;

        if transaction_hashes.len() > MAX_CELL_REQUEST_HASHES {
            return Err(RLPDecodeError::Custom(
                "GetCells: too many transaction hashes".to_string(),
            ));
        }
        if mask_bytes.len() != 16 {
            return Err(RLPDecodeError::Custom(
                "GetCells cell_mask must be exactly 16 bytes".to_string(),
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&mask_bytes);
        let cell_mask = b16_to_u128(arr);

        Ok(Self {
            id,
            transaction_hashes,
            cell_mask,
        })
    }
}

// https://eips.ethereum.org/EIPS/eip-8070#cells-0x15
#[derive(Debug, Clone)]
pub struct Cells {
    pub id: u64,
    pub transaction_hashes: Vec<H256>,
    /// Cells for each requested transaction; inner vec length equals popcount(cell_mask).
    pub cells: Vec<Vec<Cell>>,
    /// Bitmask echoing which cells are provided.
    pub cell_mask: u128,
}

impl Cells {
    pub fn new(
        id: u64,
        transaction_hashes: Vec<H256>,
        cells: Vec<Vec<Cell>>,
        cell_mask: u128,
    ) -> Self {
        Self {
            id,
            transaction_hashes,
            cells,
            cell_mask,
        }
    }

    /// Check this response against the `GetCells` request it claims to answer.
    ///
    /// devp2p `caps/eth.md` lets a peer omit whole transactions or clear indices
    /// when it can't serve them, but never add: the `cells` bitmap "must be a
    /// subset of the corresponding request's bitmap", and a peer "sending invalid
    /// or not requested element must be disconnected". Returns `Err` with the
    /// reason so the caller can log it before dropping the peer.
    pub fn validate_requested(
        &self,
        requested_hashes: &[H256],
        requested_mask: u128,
    ) -> Result<(), CellsResponseError> {
        if self.cell_mask & !requested_mask != 0 {
            return Err(CellsResponseError::UnrequestedCellIndices);
        }
        if self
            .transaction_hashes
            .iter()
            .any(|hash| !requested_hashes.contains(hash))
        {
            return Err(CellsResponseError::UnrequestedTransaction);
        }
        Ok(())
    }
}

/// Why a `Cells` response failed validation against its request.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CellsResponseError {
    #[error("Cells response carries cell indices that were not requested")]
    UnrequestedCellIndices,
    #[error("Cells response carries a transaction hash that was not requested")]
    UnrequestedTransaction,
    #[error("Cells response does not answer any outstanding GetCells request")]
    UnknownRequestId,
}

impl RLPxMessage for Cells {
    const CODE: u8 = 0x15;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        use bytes::Bytes;
        let mut encoded_data = vec![];
        let mask_bytes = Bytes::from(u128_to_b16(self.cell_mask).to_vec());
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.transaction_hashes)
            .encode_field(&self.cells)
            .encode_field(&mask_bytes)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        use bytes::Bytes;
        // Reject an oversized response by its declared decompressed length before
        // materializing the cell matrix, as the `PooledTransactions` path does.
        // See `MAX_CELLS_BYTES`.
        let decompressed_data = snappy_decompress_bounded(msg_data, MAX_CELLS_BYTES)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (transaction_hashes, decoder): (Vec<H256>, _) =
            decoder.decode_field("transactionHashes")?;
        let (cells, decoder): (Vec<Vec<Cell>>, _) = decoder.decode_field("cells")?;
        let (mask_bytes, _): (Bytes, _) = decoder.decode_field("cellMask")?;

        if transaction_hashes.len() > MAX_CELL_REQUEST_HASHES {
            return Err(RLPDecodeError::Custom(
                "Cells: too many transaction hashes".to_string(),
            ));
        }
        // One cell vec per requested tx.
        if cells.len() != transaction_hashes.len() {
            return Err(RLPDecodeError::Custom(
                "Cells: cells count must equal transaction_hashes count".to_string(),
            ));
        }
        // Bound per-tx cell count to MAX_BLOB_COUNT blobs * CELLS_PER_EXT_BLOB columns
        // so a peer can't force a multi-hundred-MB allocation before snappy limits.
        if cells.iter().any(|v| v.len() > MAX_CELLS_PER_TX) {
            return Err(RLPDecodeError::Custom(
                "Cells: too many cells per transaction".to_string(),
            ));
        }
        if mask_bytes.len() != 16 {
            return Err(RLPDecodeError::Custom(
                "Cells cell_mask must be exactly 16 bytes".to_string(),
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&mask_bytes);
        let cell_mask = b16_to_u128(arr);

        Ok(Self {
            id,
            transaction_hashes,
            cells,
            cell_mask,
        })
    }
}

impl GetCells {
    /// Serve cells we hold for the requested hashes.
    ///
    /// A `Cells` message carries a single `cell_mask` covering all txs, so we
    /// serve a uniform column set: the requested columns we hold for EVERY
    /// requested tx. The response `cell_mask` is set to that served set (the EIP
    /// permits truncation), keeping it consistent with the packed cells so the
    /// receiver can reconstruct column indices unambiguously.
    ///
    /// `available_cell_mask` is used to compute the served intersection: when a
    /// tx has a full blob payload (blobs non-empty), all 128 columns are available
    /// and we compute cells on demand via `cells_for_columns`. When only sampled
    /// cells are held, the TxCells mask is used.
    ///
    /// Consequence of the uniform mask: if ANY requested hash is unknown, private
    /// or we hold no cells for it, the intersection collapses and we serve zero cells
    /// for the whole batch. This is a protocol-level limitation of the single
    /// per-message `cell_mask`, not a bug; callers should request hashes they
    /// expect us to hold together.
    ///
    /// The response is capped at [`MAX_CELLS_SERVED`] cells: an unbounded reply would
    /// let a peer pull `MAX_CELL_REQUEST_HASHES * MAX_CELLS_PER_TX` cells (~384 MiB)
    /// per request. Trailing hashes that no longer fit are dropped from the response
    /// entirely, which EIP-8070 permits ("the responder MAY truncate its `Cells`
    /// response depending on its current capacity") and which a requester sizing its
    /// batch with [`cells_per_hash`] never triggers.
    pub fn handle(&self, mempool: &Mempool) -> Cells {
        // Use available_cell_mask (real availability) for the intersection, so a
        // full-payload provider with u128::MAX availability actually serves all
        // requested columns.
        let mut served = self.cell_mask;
        for &tx_hash in &self.transaction_hashes {
            // A private tx never propagates, so its blob data is treated as
            // unavailable here, exactly like an unknown hash.
            if mempool.is_private(tx_hash).unwrap_or(true) {
                served = 0;
                break;
            }
            served &= mempool.available_cell_mask(tx_hash);
        }
        let mut served_hashes: Vec<H256> = Vec::with_capacity(self.transaction_hashes.len());
        let mut all_cells: Vec<Vec<Cell>> = Vec::with_capacity(self.transaction_hashes.len());
        let mut budget = MAX_CELLS_SERVED;
        for &tx_hash in &self.transaction_hashes {
            let cells = get_cells_for_tx(mempool, tx_hash, served);
            if cells.len() > budget {
                break;
            }
            budget -= cells.len();
            served_hashes.push(tx_hash);
            all_cells.push(cells);
        }
        Cells::new(self.id, served_hashes, all_cells, served)
    }
}

/// Retrieve cells for `tx_hash` and the given `served_mask`.
///
/// When the tx has a full blob payload (non-empty blobs), compute cells from
/// the bundle on demand (requires `c-kzg`). Otherwise fall back to the stored
/// sampled cells.
fn get_cells_for_tx(mempool: &Mempool, tx_hash: H256, served_mask: u128) -> Vec<Cell> {
    if served_mask == 0 {
        return Vec::new();
    }
    // Try to serve from full blob payload (c-kzg only).
    #[cfg(feature = "c-kzg")]
    if let Some(bundle) = mempool.get_blobs_bundle(tx_hash).unwrap_or(None)
        && !bundle.blobs.is_empty()
        && let Ok(blob_cells) = bundle.cells_for_columns(served_mask)
    {
        // `cells_for_columns` returns one Vec per blob (each ordered by ascending
        // column). Transpose to the index-major wire order devp2p mandates for
        // `Cells`: all blobs at the lowest served column, then the next column, ...
        let col_count = served_mask.count_ones() as usize;
        let mut result = Vec::with_capacity(blob_cells.len() * col_count);
        for col_pos in 0..col_count {
            for blob_col_cells in &blob_cells {
                if let Some(cell) = blob_col_cells.get(col_pos) {
                    result.push(*cell);
                }
            }
        }
        return result;
    }
    // Fall back to stored sampled cells.
    mempool.get_tx_cells_for_mask(tx_hash, served_mask)
}
