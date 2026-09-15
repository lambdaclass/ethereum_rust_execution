use crate::{
    discovery::lookup::IterativeLookup,
    discv4::messages::{Message, Packet},
    utils::node_id,
};
use ethrex_common::{H256, H512};
use std::{collections::HashMap, net::SocketAddr, time::Instant};

pub const EXPIRATION_SECONDS: u64 = 20;

/// Discv4-specific state held within the unified DiscoveryServer.
#[derive(Debug, Default)]
pub struct Discv4State {
    /// Tracks pending FindNode requests by node_id -> sent_at.
    /// Used to reject unsolicited Neighbors responses.
    pub pending_find_node: HashMap<H256, Instant>,
    /// Currently active iterative lookups, each with its cached signed FindNode message.
    pub active_lookups: Vec<(IterativeLookup, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct Discv4Message {
    pub(crate) from: SocketAddr,
    pub(crate) message: Message,
    pub(crate) hash: H256,
    pub(crate) sender_public_key: H512,
}

impl Discv4Message {
    pub fn from(packet: Packet, from: SocketAddr) -> Self {
        Self {
            from,
            message: packet.get_message().clone(),
            hash: packet.get_hash(),
            sender_public_key: packet.get_public_key(),
        }
    }

    pub fn get_node_id(&self) -> H256 {
        node_id(&self.sender_public_key)
    }
}
