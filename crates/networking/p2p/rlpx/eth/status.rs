pub use super::eth68::status::StatusMessage68;
pub use super::eth69::status::StatusMessage69;
pub use super::eth70::status::StatusMessage70;
pub use super::eth71::status::StatusMessage71;
use crate::rlpx::{
    error::PeerConnectionError,
    utils::{snappy_compress, snappy_decompress},
};
use ethrex_common::types::{BlockHash, ForkId};
use ethrex_rlp::{
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};
use ethrex_storage::Store;

pub trait StatusMessage {
    fn get_network_id(&self) -> u64;

    fn get_eth_version(&self) -> u8;

    fn get_fork_id(&self) -> ForkId;

    fn get_genesis(&self) -> BlockHash;
}

/// Shared status data for eth/69+ protocols (eth/69, eth/70, eth/71, ...).
/// The wire format is identical; only the version field differs.
#[derive(Debug, Clone)]
pub struct StatusDataPost68 {
    pub eth_version: u8,
    pub network_id: u64,
    pub genesis: BlockHash,
    pub fork_id: ForkId,
    pub earliest_block: u64,
    pub latest_block: u64,
    pub latest_block_hash: BlockHash,
}

impl StatusDataPost68 {
    pub async fn new(eth_version: u8, storage: &Store) -> Result<Self, PeerConnectionError> {
        let chain_config = storage.get_chain_config();
        let network_id = chain_config.chain_id;

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

        // The earliest block we can actually serve. Advertising 0 unconditionally
        // claims history from genesis, which is already untrue on any snap-synced
        // node (earliest is the pivot) and becomes materially wrong once history
        // pruning lands: peers select us for ranges we cannot answer.
        let earliest_block = storage.get_earliest_block_number().await?;

        let genesis = genesis_header.hash();
        let latest_block_hash = block_header.hash();
        let fork_id = ForkId::new(
            chain_config,
            genesis_header,
            block_header.timestamp,
            latest_block,
        );

        Ok(Self {
            eth_version,
            network_id,
            genesis,
            fork_id,
            earliest_block,
            latest_block,
            latest_block_hash,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.eth_version)
            .encode_field(&self.network_id)
            .encode_field(&self.genesis)
            .encode_field(&self.fork_id)
            .encode_field(&self.earliest_block)
            .encode_field(&self.latest_block)
            .encode_field(&self.latest_block_hash)
            .finish();

        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    pub fn decode(msg_data: &[u8], expected_version: u8) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (eth_version, decoder): (u32, _) = decoder.decode_field("protocolVersion")?;

        if eth_version != expected_version as u32 {
            return Err(RLPDecodeError::IncompatibleProtocol(format!(
                "Received message is encoded in eth version {} when negotiated eth version was {}",
                eth_version, expected_version
            )));
        }

        let (network_id, decoder): (u64, _) = decoder.decode_field("networkId")?;
        let (genesis, decoder): (BlockHash, _) = decoder.decode_field("genesis")?;
        let (fork_id, decoder): (ForkId, _) = decoder.decode_field("forkId")?;
        let (earliest_block, decoder): (u64, _) = decoder.decode_field("earliestBlock")?;
        let (latest_block, decoder): (u64, _) = decoder.decode_field("latestBlock")?;
        let (latest_block_hash, decoder): (BlockHash, _) = decoder.decode_field("latestHash")?;
        let _padding = decoder.finish_unchecked();

        Ok(Self {
            eth_version: eth_version as u8,
            network_id,
            genesis,
            fork_id,
            earliest_block,
            latest_block,
            latest_block_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rlpx::eth::update::BlockRangeUpdate;
    use ethrex_storage::EngineType;

    /// An in-memory store whose earliest retained block has been moved off zero,
    /// which is the shape a snap-synced (and, later, a pruned) node presents.
    async fn store_with_earliest(earliest: u64) -> Store {
        let mut store = Store::new("", EngineType::InMemory).expect("in-memory store");
        store
            .add_initial_state(ethrex_common::types::Genesis::default())
            .await
            .expect("load genesis");
        store
            .update_earliest_block_number(earliest)
            .await
            .expect("set earliest");
        store
    }

    /// Advertising 0 unconditionally tells peers we hold history from genesis. That
    /// is already false on a snap-synced node, and peers use the advertised range to
    /// decide what to ask us for.
    #[tokio::test]
    async fn status_advertises_the_real_earliest_block() {
        let store = store_with_earliest(12_345).await;
        for eth_version in [69, 70, 71] {
            let status = StatusDataPost68::new(eth_version, &store)
                .await
                .expect("build status");
            assert_eq!(
                status.earliest_block, 12_345,
                "eth/{eth_version} status must advertise the earliest retained block"
            );
        }
    }

    /// The ongoing half of the same advertisement: the handshake value goes stale as
    /// the barrier moves, so BlockRangeUpdate has to track it too. Only genesis is
    /// stored here, so the only earliest consistent with `validate`'s
    /// `earliest <= latest` invariant is 0 — this pins that the field is read from
    /// the store rather than hardcoded, without manufacturing an impossible range.
    #[tokio::test]
    async fn block_range_update_reads_earliest_from_the_store() {
        let store = store_with_earliest(0).await;
        let update = BlockRangeUpdate::new(&store).await.expect("build update");
        assert_eq!(update.earliest_block, 0);
        update.validate().expect("a consistent range must validate");
    }

    /// Genesis-synced nodes must keep advertising 0, so the change is a no-op for them.
    #[tokio::test]
    async fn a_full_history_node_still_advertises_zero() {
        let store = store_with_earliest(0).await;
        let status = StatusDataPost68::new(69, &store).await.expect("status");
        assert_eq!(status.earliest_block, 0);
    }
}
