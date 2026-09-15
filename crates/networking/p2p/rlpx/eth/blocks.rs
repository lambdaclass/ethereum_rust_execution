use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress},
};
use ethrex_common::types::{BlockBody, BlockHash, BlockHeader, BlockNumber};
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};
use ethrex_storage::{Store, error::StoreError};
use tracing::{error, trace};

pub const HASH_FIRST_BYTE_DECODER: u8 = 160;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashOrNumber {
    Hash(BlockHash),
    Number(BlockNumber),
}

impl core::fmt::Display for HashOrNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HashOrNumber::Hash(hash) => write!(f, "{hash:#x}"),
            HashOrNumber::Number(number) => write!(f, "{number}"),
        }
    }
}

impl RLPEncode for HashOrNumber {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            HashOrNumber::Hash(hash) => hash.encode(buf),
            HashOrNumber::Number(number) => number.encode(buf),
        }
    }

    fn length(&self) -> usize {
        match self {
            HashOrNumber::Hash(hash) => hash.length(),
            HashOrNumber::Number(number) => number.length(),
        }
    }
}

impl From<BlockHash> for HashOrNumber {
    fn from(value: BlockHash) -> Self {
        Self::Hash(value)
    }
}

impl RLPDecode for HashOrNumber {
    fn decode_unfinished(buf: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let first_byte = buf.first().ok_or(RLPDecodeError::InvalidLength)?;
        // https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
        // hashes are 32 bytes long, so they enter in the 0-55 bytes range for rlp. This means the first byte
        // is the value 0x80 + len, where len = 32 (0x20). so we get the result of 0xa0 which is 160 in decimal
        if *first_byte == HASH_FIRST_BYTE_DECODER {
            let (hash, rest) = BlockHash::decode_unfinished(buf)?;
            return Ok((Self::Hash(hash), rest));
        }

        let (number, rest) = u64::decode_unfinished(buf)?;
        Ok((Self::Number(number), rest))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#getblockheaders-0x03
#[derive(Debug, Clone)]
pub struct GetBlockHeaders {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub startblock: HashOrNumber,
    pub limit: u64,
    pub skip: u64,
    pub reverse: bool,
}

// Limit taken from here: https://github.com/ethereum/go-ethereum/blob/20bf543a64d7c2a590b18a1e1d907cae65707013/eth/protocols/eth/handler.go#L40
pub const BLOCK_HEADER_LIMIT: u64 = 1024;

impl GetBlockHeaders {
    pub fn new(id: u64, startblock: HashOrNumber, limit: u64, skip: u64, reverse: bool) -> Self {
        Self {
            id,
            startblock,
            limit,
            skip,
            reverse,
        }
    }

    pub async fn fetch_headers(&self, storage: &Store) -> Vec<BlockHeader> {
        // According to the spec, we don't need to service non-canonical headers,
        // but geth does, and it helps in reorg scenarios, so we handle that case.
        let start_block = match self.startblock {
            // Only translate a hash to a block number when that hash is the
            // canonical block at its height. Translating a non-canonical (or
            // not-yet-canonical) hash to a number and then reading by number
            // would return a DIFFERENT, canonical block at that height, so the
            // response would not start at the requested hash and the requesting
            // peer would reject the whole batch. For those, keep the hash and
            // serve it directly (walking parents for reverse requests in the
            // loop below), which is exactly what a syncing peer asking for a
            // fork/sync head needs.
            HashOrNumber::Hash(block_hash) => match storage.get_block_number(block_hash).await {
                Ok(Some(block_number))
                    if storage
                        .get_canonical_block_hash(block_number)
                        .await
                        .ok()
                        .flatten()
                        == Some(block_hash) =>
                {
                    HashOrNumber::Number(block_number)
                }
                _ => self.startblock,
            },
            // Don't check if the block number is available
            // because if it it's not, the loop below will
            // break early and return an empty vec.
            HashOrNumber::Number(_) => self.startblock,
        };

        let mut headers = vec![];

        let mut current_block = start_block;

        let block_skip = if self.reverse {
            -((self.skip + 1) as i64)
        } else {
            (self.skip + 1) as i64
        };

        let limit = if self.limit > BLOCK_HEADER_LIMIT {
            BLOCK_HEADER_LIMIT
        } else {
            self.limit
        };

        for _ in 0..limit {
            let block_header_opt = match get_block_header(storage, current_block) {
                Ok(block_header) => block_header,
                Err(err) => {
                    error!(%err, block_ref=%current_block, "Error accessing DB while building header response for peer");
                    break;
                }
            };
            let Some(block_header) = block_header_opt else {
                trace!(block_ref=%current_block, "Block header not found");
                break;
            };
            // Compute the next block to fetch before moving `block_header`.
            let next_block = match current_block {
                // By hash we only walk descending (reverse) with no skip, by
                // following parent hashes. This serves a non-canonical chain
                // (e.g. a syncing peer's fork/sync head) that cannot be addressed
                // by number. Ascending is not addressable from a hash without
                // knowing the child; skipping (`skip > 0`) reverse-by-hash could
                // be served by walking `skip + 1` parent links per emitted header
                // (as geth's GetAncestor does) but is not implemented here — the
                // syncing peers that use reverse-by-hash all request `skip == 0`.
                // Per spec, serving fewer headers than requested is allowed, so we
                // stop after the single header rather than returning wrong ones.
                HashOrNumber::Hash(_) => (self.reverse && self.skip == 0)
                    .then_some(HashOrNumber::Hash(block_header.parent_hash)),
                HashOrNumber::Number(number) => (number as i64 + block_skip)
                    .try_into()
                    .ok()
                    .map(HashOrNumber::Number),
            };

            headers.push(block_header);

            match next_block {
                Some(next) => current_block = next,
                None => break,
            }
        }
        headers
    }
}

fn get_block_header(
    storage: &Store,
    block_ref: HashOrNumber,
) -> Result<Option<BlockHeader>, StoreError> {
    match block_ref {
        HashOrNumber::Hash(block_hash) => storage.get_block_header_by_hash(block_hash),
        HashOrNumber::Number(block_number) => storage.get_block_header(block_number),
    }
}

impl RLPxMessage for GetBlockHeaders {
    const CODE: u8 = 0x03;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        let limit = self.limit;
        let skip = self.skip;
        let reverse = self.reverse as u8;
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&(self.startblock, limit, skip, reverse))
            .finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let ((start_block, limit, skip, reverse), _): ((HashOrNumber, u64, u64, bool), _) =
            decoder.decode_field("get headers request params")?;
        Ok(Self::new(id, start_block, limit, skip, reverse))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#blockheaders-0x04
#[derive(Debug, Clone)]
pub struct BlockHeaders {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub block_headers: Vec<BlockHeader>,
}

impl BlockHeaders {
    pub fn new(id: u64, block_headers: Vec<BlockHeader>) -> Self {
        Self { block_headers, id }
    }
}

impl RLPxMessage for BlockHeaders {
    const CODE: u8 = 0x04;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        // Each message is encoded with its own
        // message identifier (code).
        // Go ethereum reference: https://github.com/ethereum/go-ethereum/blob/20bf543a64d7c2a590b18a1e1d907cae65707013/p2p/transport.go#L94
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.block_headers)
            .finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (block_headers, _): (Vec<BlockHeader>, _) = decoder.decode_field("headers")?;

        Ok(Self::new(id, block_headers))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#getblockbodies-0x05
#[derive(Debug, Clone)]
pub struct GetBlockBodies {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub block_hashes: Vec<BlockHash>,
}

// Limit taken from here:
// https://github.com/ethereum/go-ethereum/blob/a1093d98eb3260f2abf340903c2d968b2b891c11/eth/protocols/eth/handler.go#L45
pub const BLOCK_BODY_LIMIT: usize = 1024;

impl GetBlockBodies {
    pub fn new(id: u64, block_hashes: Vec<BlockHash>) -> Self {
        Self { block_hashes, id }
    }
    pub async fn fetch_blocks(&self, storage: &Store) -> Vec<BlockBody> {
        let mut block_bodies = vec![];
        for block_hash in &self.block_hashes {
            match storage.get_block_body_by_hash(*block_hash).await {
                Ok(Some(block)) => {
                    block_bodies.push(block);
                    if block_bodies.len() >= BLOCK_BODY_LIMIT {
                        break;
                    }
                }
                Ok(None) => {
                    continue;
                }
                Err(err) => {
                    error!(
                        "Error accessing DB while building block bodies response for peer: {err}"
                    );
                    return vec![];
                }
            }
        }
        block_bodies
    }
}

impl RLPxMessage for GetBlockBodies {
    const CODE: u8 = 0x05;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.block_hashes)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (block_hashes, _): (Vec<BlockHash>, _) = decoder.decode_field("blockHashes")?;

        Ok(Self::new(id, block_hashes))
    }
}

// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#blockbodies-0x06
#[derive(Debug, Clone)]
pub struct BlockBodies {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub block_bodies: Vec<BlockBody>,
}

impl BlockBodies {
    pub fn new(id: u64, block_bodies: Vec<BlockBody>) -> Self {
        Self { block_bodies, id }
    }
}

impl RLPxMessage for BlockBodies {
    const CODE: u8 = 0x06;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.block_bodies)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (block_bodies, _): (Vec<BlockBody>, _) = decoder.decode_field("blockBodies")?;

        Ok(Self::new(id, block_bodies))
    }
}
