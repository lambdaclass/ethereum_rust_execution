use crate::rlpx::{
    error::PeerConnectionError,
    eth::status::StatusMessage,
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress},
};
use ethrex_common::{
    U256,
    types::{BlockHash, ForkId},
};
use ethrex_rlp::{
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};
use ethrex_storage::Store;

#[derive(Debug, Clone)]
pub struct StatusMessage68 {
    pub eth_version: u8,
    pub network_id: u64,
    pub total_difficulty: U256,
    pub block_hash: BlockHash,
    pub genesis: BlockHash,
    pub fork_id: ForkId,
}

impl RLPxMessage for StatusMessage68 {
    const CODE: u8 = 0x00;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.eth_version)
            .encode_field(&self.network_id)
            .encode_field(&self.total_difficulty)
            .encode_field(&self.block_hash)
            .encode_field(&self.genesis)
            .encode_field(&self.fork_id)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (eth_version, decoder): (u32, _) = decoder.decode_field("protocolVersion")?;

        if eth_version != 68 {
            return Err(RLPDecodeError::IncompatibleProtocol(format!(
                "Received message is encoded in eth version {} when negotiated eth version was 68",
                eth_version
            )));
        }

        let (network_id, decoder): (u64, _) = decoder.decode_field("networkId")?;
        let (total_difficulty, decoder): (U256, _) = decoder.decode_field("totalDifficulty")?;
        let (block_hash, decoder): (BlockHash, _) = decoder.decode_field("blockHash")?;
        let (genesis, decoder): (BlockHash, _) = decoder.decode_field("genesis")?;
        let (fork_id, decoder): (ForkId, _) = decoder.decode_field("forkId")?;
        // Implementations must ignore any additional list elements
        let _padding = decoder.finish_unchecked();

        Ok(Self {
            eth_version: eth_version as u8,
            network_id,
            total_difficulty,
            block_hash,
            genesis,
            fork_id,
        })
    }
}

impl StatusMessage68 {
    pub fn new(storage: &Store) -> Result<Self, PeerConnectionError> {
        let chain_config = storage.get_chain_config();
        let total_difficulty =
            U256::from(chain_config.terminal_total_difficulty.unwrap_or_default());
        let network_id = chain_config.chain_id;

        // These blocks must always be available
        let genesis_header = storage
            .get_block_header(0)?
            .ok_or(PeerConnectionError::NotFound("Genesis Block".to_string()))?;
        let latest_block = storage.get_latest_block_number()?;
        let block_header =
            storage
                .get_block_header(latest_block)?
                .ok_or(PeerConnectionError::NotFound(format!(
                    "Block {latest_block}"
                )))?;

        let genesis = genesis_header.hash();
        let latest_block_hash = block_header.hash();
        let fork_id = ForkId::new(
            chain_config,
            genesis_header,
            block_header.timestamp,
            latest_block,
        );

        Ok(StatusMessage68 {
            eth_version: 68,
            network_id,
            total_difficulty,
            block_hash: latest_block_hash,
            genesis,
            fork_id,
        })
    }
}

impl StatusMessage for StatusMessage68 {
    fn get_network_id(&self) -> u64 {
        self.network_id
    }

    fn get_eth_version(&self) -> u8 {
        self.eth_version
    }

    fn get_fork_id(&self) -> ForkId {
        self.fork_id.clone()
    }

    fn get_genesis(&self) -> BlockHash {
        self.genesis
    }
}
