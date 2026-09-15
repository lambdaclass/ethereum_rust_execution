use crate::rlpx::error::PeerConnectionError;
use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress},
};
use ethrex_common::types::BlockHash;
use ethrex_rlp::{
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};
use ethrex_storage::Store;

#[derive(Debug, Clone)]
pub struct BlockRangeUpdate {
    pub earliest_block: u64,
    pub latest_block: u64,
    pub latest_block_hash: BlockHash,
}

impl BlockRangeUpdate {
    pub async fn new(storage: &Store) -> Result<Self, PeerConnectionError> {
        // See StatusDataPost68::new — this is the ongoing half of the same
        // advertisement, so it must track the earliest block as it moves.
        let earliest_block = storage.get_earliest_block_number().await?;
        let latest_block = storage.get_latest_block_number()?;
        let block_header =
            storage
                .get_block_header(latest_block)?
                .ok_or(PeerConnectionError::NotFound(format!(
                    "Block {latest_block}"
                )))?;
        let latest_block_hash = block_header.hash();

        Ok(Self {
            earliest_block,
            latest_block,
            latest_block_hash,
        })
    }

    /// Validates an incoming BlockRangeUpdate from a peer
    pub fn validate(&self) -> Result<(), PeerConnectionError> {
        if self.earliest_block > self.latest_block || self.latest_block_hash.is_zero() {
            return Err(PeerConnectionError::InvalidBlockRangeUpdate);
        }
        Ok(())
    }
}

impl RLPxMessage for BlockRangeUpdate {
    const CODE: u8 = 0x11;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.earliest_block)
            .encode_field(&self.latest_block)
            .encode_field(&self.latest_block_hash)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (earliest_block, decoder): (u64, _) = decoder.decode_field("earliestBlock")?;
        let (latest_block, decoder): (u64, _) = decoder.decode_field("latestBlock")?;
        let (latest_block_hash, decoder): (BlockHash, _) = decoder.decode_field("latestHash")?;
        // Implementations must ignore any additional list elements
        let _padding = decoder.finish_unchecked();

        Ok(Self {
            earliest_block,
            latest_block,
            latest_block_hash,
        })
    }
}
