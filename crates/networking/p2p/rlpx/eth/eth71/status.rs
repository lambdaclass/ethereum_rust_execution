use crate::rlpx::{
    error::PeerConnectionError,
    eth::status::{StatusDataPost68, StatusMessage},
    message::RLPxMessage,
};
use ethrex_common::types::{BlockHash, ForkId};
use ethrex_rlp::error::{RLPDecodeError, RLPEncodeError};
use ethrex_storage::Store;

#[derive(Debug, Clone)]
pub struct StatusMessage71(pub(crate) StatusDataPost68);

impl RLPxMessage for StatusMessage71 {
    const CODE: u8 = 0x00;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        self.0.encode(buf)
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        StatusDataPost68::decode(msg_data, 71).map(Self)
    }
}

impl StatusMessage71 {
    pub async fn new(storage: &Store) -> Result<Self, PeerConnectionError> {
        StatusDataPost68::new(71, storage).await.map(Self)
    }
}

impl StatusMessage for StatusMessage71 {
    fn get_network_id(&self) -> u64 {
        self.0.network_id
    }

    fn get_eth_version(&self) -> u8 {
        self.0.eth_version
    }

    fn get_fork_id(&self) -> ForkId {
        self.0.fork_id.clone()
    }

    fn get_genesis(&self) -> BlockHash {
        self.0.genesis
    }
}
