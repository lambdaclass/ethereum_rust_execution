use crate::{
    discovery::ip_predictor::IpPredictor,
    discv4::{
        messages::Packet as Discv4Packet,
        server::{Discv4Message, Discv4State},
    },
    discv5::{
        messages::{Packet as Discv5Packet, PacketCodecError},
        server::{Discv5Message, Discv5State, update_local_ip},
    },
    peer_filter::PeerFilter,
    types::{Node, NodeRecord, SharedLocalNode},
};
use bytes::BytesMut;
use ethrex_common::H256;
use ethrex_common::types::ForkId;
use ethrex_common::utils::keccak;
use futures::StreamExt;
use secp256k1::SecretKey;
use spawned_concurrency::{
    actor,
    error::ActorError,
    protocol,
    tasks::{
        Actor, ActorRef, ActorStart as _, Context, Handler, Response, send_after, send_interval,
        send_message_on, spawn_listener,
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, info, trace, warn};

use super::{
    DiscoveryConfig, codec::DiscriminatingCodec, contact_table::ContactTable,
    contact_table::DiscoveryProtocol, contact_table::PeerEvent, lookup_interval_function,
};
use std::sync::OnceLock;

/// Minimum packet size for a valid discv4 packet.
/// hash (32) + signature (65) + type (1) = 98 bytes
const DISCV4_MIN_PACKET_SIZE: usize = 98;

// Shared constants
const REVALIDATION_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const PRUNE_INTERVAL: Duration = Duration::from_secs(5);

/// Lookup interval bounds for iterative lookups. Each iterative lookup
/// generates ~16 FindNode messages (vs 1 in the old approach), so we use
/// longer intervals to produce similar per-second traffic.
const ITERATIVE_LOOKUP_INITIAL_MS: f64 = 500.0; // 6 FindNode/sec at startup (alpha=3 × 2 ticks/sec)
const ITERATIVE_LOOKUP_INTERVAL_MS: f64 = 10_000.0; // ~6 lookups/min at steady-state

#[derive(Debug, Error)]
pub enum DiscoveryServerError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Failed to decode discv4 packet")]
    Discv4Decode(#[from] crate::discv4::messages::PacketDecodeErr),
    #[error("Failed to decode discv5 packet")]
    Discv5Decode(#[from] crate::discv5::messages::PacketCodecError),
    #[error("Only partial message was sent")]
    PartialMessageSent,
    #[error("Unknown or invalid contact")]
    InvalidContact,
    #[error(transparent)]
    Actor(#[from] ActorError),
    #[error("Internal error {0}")]
    InternalError(String),
    #[error("Cryptography Error {0}")]
    CryptographyError(String),
    #[error(transparent)]
    RlpDecode(#[from] ethrex_rlp::error::RLPDecodeError),
}

#[protocol]
pub trait DiscoveryServerProtocol: Send + Sync {
    fn raw_packet(&self, data: BytesMut, from: SocketAddr) -> Result<(), ActorError>;
    /// Report something that happened to the consumer's relationship with a
    /// peer. See [`PeerEvent`] for what each variant does.
    fn record_peer_event(&self, node_id: H256, event: PeerEvent) -> Result<(), ActorError>;
    fn revalidate_v4(&self) -> Result<(), ActorError>;
    fn revalidate_v5(&self) -> Result<(), ActorError>;
    fn lookup_v4(&self) -> Result<(), ActorError>;
    fn lookup_v5(&self) -> Result<(), ActorError>;
    fn enr_lookup(&self) -> Result<(), ActorError>;
    fn prune(&self) -> Result<(), ActorError>;
    fn shutdown(&self) -> Result<(), ActorError>;

    /// The next node worth dialing, or `None` when nothing in the pool is
    /// eligible right now.
    fn next_dial_candidate(&self) -> Response<Option<Node>>;
}

/// The consumer's handle on a discovery server.
///
/// Discovery is started after the context that reaches it, and is not started
/// at all when p2p is disabled, so the handle is filled in once the server is
/// up and is inert until then.
///
/// Every message across this boundary but one is a cast. Discovery never calls
/// back into its consumer, which is what keeps two actors with sequential
/// mailboxes from deadlocking on each other.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryHandle(Arc<OnceLock<ActorRef<DiscoveryServer>>>);

impl DiscoveryHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish the running server to every clone of this handle. A second call
    /// is ignored, and reported as `false`.
    pub fn set(&self, server: ActorRef<DiscoveryServer>) -> bool {
        self.0.set(server).is_ok()
    }

    /// Casts are dropped on the floor while discovery is down: there is no
    /// contact table to record them in, and no later moment at which replaying
    /// them would mean anything.
    fn server(&self) -> Option<&ActorRef<DiscoveryServer>> {
        self.0.get()
    }

    /// Report something that happened to a peer. See [`PeerEvent`]: these are
    /// events, not a state machine, and `Rejected` is only ever reported for an
    /// attempt that never became a connection.
    pub fn record_peer_event(&self, node_id: H256, event: PeerEvent) {
        if let Some(server) = self.server() {
            let _ = server.record_peer_event(node_id, event);
        }
    }

    /// Ask discovery to drop the contacts it has written off, so replacements
    /// waiting in the k-buckets get promoted.
    pub fn prune(&self) {
        if let Some(server) = self.server() {
            let _ = server.prune();
        }
    }

    /// The next node discovery thinks is worth dialing. `None` when discovery
    /// is down, has nothing eligible, or the request failed.
    pub async fn next_dial_candidate(&self) -> Option<Node> {
        let server = self.server()?;
        server
            .next_dial_candidate()
            .await
            .inspect_err(|e| debug!(err=?e, "Failed to ask discovery for a dial candidate"))
            .ok()
            .flatten()
    }
}

pub struct DiscoveryServer {
    pub local_node: Node,
    pub local_node_record: NodeRecord,
    pub(crate) signer: SecretKey,
    pub(crate) udp_socket: Arc<UdpSocket>,
    /// Everything known about nodes we have merely heard of. Plain state: the
    /// handlers below all run inside this actor, so they reach it directly.
    pub(crate) contacts: ContactTable,
    pub(crate) config: DiscoveryConfig,
    pub discv4: Option<Discv4State>,
    pub discv5: Option<Discv5State>,
    /// Shared IP predictor fed by both discv4 and discv5 PONGs.
    pub ip_predictor: IpPredictor,
    /// When true the user supplied `--nat extip:<addr>` and we must not override it.
    pub(crate) ip_override_locked: bool,
    /// Live-updated local node identity shared with the RPC layer.
    pub shared_local_node: SharedLocalNode,
    /// Current EIP-2124 fork id, published by the network layer. `None` inside the
    /// channel means the chain could not supply one yet.
    ///
    /// Discovery does not read this from storage: the network layer decides what this
    /// node announces about itself, and discovery only republishes. Without a refresh
    /// the `eth` ENR entry goes stale the moment the chain crosses a fork, and geth's
    /// dial-candidate filter (`NewNodeFilter`) drops us outright.
    pub(crate) fork_id: watch::Receiver<Option<ForkId>>,
}

impl std::fmt::Debug for DiscoveryServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryServer")
            .field("local_node", &self.local_node)
            .field("contacts", &self.contacts)
            .field("discv4_enabled", &self.discv4.is_some())
            .field("discv5_enabled", &self.discv5.is_some())
            .field("ip_predictor", &self.ip_predictor)
            .field("ip_override_locked", &self.ip_override_locked)
            .finish()
    }
}

#[actor(protocol = DiscoveryServerProtocol)]
impl DiscoveryServer {
    ////// Starts the discovery actor, advertising `local_node_record` as this
    /// node's ENR, and returns a handle on the running server.
    ///
    /// `filter` is what this consumer requires of a discovered peer: every ENR
    /// discovery sees is judged by it. A contact discovered without an ENR is
    /// never screened and stays dialable, so bootnodes are usable before they
    /// have published anything.
    #[expect(
        clippy::too_many_arguments,
        reason = "caller-supplied values; bundling them would only hide the call site"
    )]
    pub async fn spawn(
        local_node: Node,
        local_node_record: NodeRecord,
        signer: SecretKey,
        udp_socket: Arc<UdpSocket>,
        filter: Box<dyn PeerFilter>,
        bootnodes: Vec<Node>,
        config: DiscoveryConfig,
        shared_local_node: SharedLocalNode,
        fork_id: watch::Receiver<Option<ForkId>>,
    ) -> Result<ActorRef<DiscoveryServer>, DiscoveryServerError> {
        debug!("Starting discovery server");

        let mut contacts = ContactTable::new(local_node.node_id(), config.target_peers, filter);

        let discv4 = if config.discv4_enabled {
            info!(
                protocol = "discv4",
                count = bootnodes.len(),
                "Adding bootnodes"
            );
            contacts
                .new_contacts(bootnodes.clone(), DiscoveryProtocol::Discv4)
                .await;
            Some(Discv4State::default())
        } else {
            None
        };

        let discv5 = if config.discv5_enabled {
            info!(
                protocol = "discv5",
                count = bootnodes.len(),
                "Adding bootnodes"
            );
            contacts
                .new_contacts(bootnodes.clone(), DiscoveryProtocol::Discv5)
                .await;
            Some(Discv5State::default())
        } else {
            None
        };

        let ip_override_locked = config.nat_extip_set;
        let mut server = Self {
            local_node: local_node.clone(),
            local_node_record,
            signer,
            udp_socket: udp_socket.clone(),
            contacts,
            ip_predictor: IpPredictor::default(),
            ip_override_locked,
            config,
            discv4,
            discv5,
            shared_local_node,
            fork_id,
        };

        // Ping discv4 bootnodes
        if server.discv4.is_some() {
            for bootnode in &bootnodes {
                server.discv4_send_ping(bootnode).await?;
            }
        }

        Ok(server.start())
    }

    #[started]
    async fn started(&mut self, ctx: &Context<Self>) {
        let local_addr = self.udp_socket.local_addr();
        info!(
            local_addr=?local_addr,
            discv4_enabled=self.config.discv4_enabled,
            discv5_enabled=self.config.discv5_enabled,
            "Discovery server started, listening for UDP packets"
        );

        // Set up UDP listener
        let stream = UdpFramed::new(self.udp_socket.clone(), DiscriminatingCodec::new());
        spawn_listener(
            ctx.clone(),
            stream.filter_map(|result| async move {
                match result {
                    Ok((data, from)) => Some(discovery_server_protocol::RawPacket { data, from }),
                    Err(e) => {
                        debug!(error=?e, "Error receiving packet in discovery server");
                        None
                    }
                }
            }),
        );

        // Discv4 timers
        if self.discv4.is_some() {
            send_interval(
                REVALIDATION_CHECK_INTERVAL,
                ctx.clone(),
                discovery_server_protocol::RevalidateV4,
            );
            let _ = ctx.send(discovery_server_protocol::LookupV4);
            let _ = ctx.send(discovery_server_protocol::EnrLookup);
        }

        // Discv5 timers
        if self.discv5.is_some() {
            send_interval(
                REVALIDATION_CHECK_INTERVAL,
                ctx.clone(),
                discovery_server_protocol::RevalidateV5,
            );
            let _ = ctx.send(discovery_server_protocol::LookupV5);
        }

        // Shared prune timer
        send_interval(
            PRUNE_INTERVAL,
            ctx.clone(),
            discovery_server_protocol::Prune,
        );

        // Shutdown handler
        send_message_on(
            ctx.clone(),
            tokio::signal::ctrl_c(),
            discovery_server_protocol::Shutdown,
        );
    }

    #[send_handler]
    async fn handle_raw_packet(
        &mut self,
        msg: discovery_server_protocol::RawPacket,
        _ctx: &Context<Self>,
    ) {
        self.route_packet(&msg.data, msg.from).await;
    }

    #[send_handler]
    async fn handle_revalidate_v4(
        &mut self,
        _msg: discovery_server_protocol::RevalidateV4,
        _ctx: &Context<Self>,
    ) {
        trace!(protocol = "discv4", received = "Revalidate");
        let _ = self.discv4_revalidate().await.inspect_err(
            |e| error!(protocol = "discv4", err=?e, "Error revalidating discovered peers"),
        );
    }

    #[send_handler]
    async fn handle_revalidate_v5(
        &mut self,
        _msg: discovery_server_protocol::RevalidateV5,
        _ctx: &Context<Self>,
    ) {
        trace!(protocol = "discv5", received = "Revalidate");
        let _ = self.discv5_revalidate().await.inspect_err(
            |e| error!(protocol = "discv5", err=?e, "Error revalidating discovered peers"),
        );
    }

    #[send_handler]
    async fn handle_lookup_v4(
        &mut self,
        _msg: discovery_server_protocol::LookupV4,
        ctx: &Context<Self>,
    ) {
        trace!(protocol = "discv4", received = "Lookup");
        let _ = self.discv4_lookup().await.inspect_err(
            |e| error!(protocol = "discv4", err=?e, "Error performing Discovery lookup"),
        );
        let interval = self.get_lookup_interval();
        send_after(interval, ctx.clone(), discovery_server_protocol::LookupV4);
    }

    #[send_handler]
    async fn handle_lookup_v5(
        &mut self,
        _msg: discovery_server_protocol::LookupV5,
        ctx: &Context<Self>,
    ) {
        trace!(protocol = "discv5", received = "Lookup");
        let _ = self.discv5_lookup().await.inspect_err(
            |e| error!(protocol = "discv5", err=?e, "Error performing Discovery lookup"),
        );
        let interval = self.get_lookup_interval();
        send_after(interval, ctx.clone(), discovery_server_protocol::LookupV5);
    }

    #[send_handler]
    async fn handle_enr_lookup(
        &mut self,
        _msg: discovery_server_protocol::EnrLookup,
        ctx: &Context<Self>,
    ) {
        trace!(protocol = "discv4", received = "EnrLookup");
        let _ = self.discv4_enr_lookup().await.inspect_err(
            |e| error!(protocol = "discv4", err=?e, "Error performing Discovery lookup"),
        );
        let interval = self.get_lookup_interval();
        send_after(interval, ctx.clone(), discovery_server_protocol::EnrLookup);
    }

    #[send_handler]
    async fn handle_prune(&mut self, _msg: discovery_server_protocol::Prune, _ctx: &Context<Self>) {
        trace!(received = "Prune");
        let _ = self
            .prune()
            .await
            .inspect_err(|e| error!(err=?e, "Error Pruning peer table"));
    }

    #[send_handler]
    async fn handle_record_peer_event(
        &mut self,
        msg: discovery_server_protocol::RecordPeerEvent,
        _ctx: &Context<Self>,
    ) {
        self.contacts.record_peer_event(msg.node_id, msg.event);
    }

    #[request_handler]
    async fn handle_next_dial_candidate(
        &mut self,
        _msg: discovery_server_protocol::NextDialCandidate,
        _ctx: &Context<Self>,
    ) -> Option<Node> {
        self.contacts.next_dial_candidate()
    }

    #[send_handler]
    async fn handle_shutdown(
        &mut self,
        _msg: discovery_server_protocol::Shutdown,
        ctx: &Context<Self>,
    ) {
        ctx.stop();
    }

    // --- Shared logic ---

    async fn route_packet(&mut self, data: &[u8], from: SocketAddr) {
        if is_discv4_packet(data) {
            self.route_to_discv4(data, from).await;
        } else {
            self.route_to_discv5(data, from).await;
        }
    }

    async fn route_to_discv4(&mut self, data: &[u8], from: SocketAddr) {
        if self.discv4.is_none() {
            return;
        }
        match Discv4Packet::decode(data) {
            Ok(packet) => {
                let msg = Discv4Message::from(packet, from);
                let _ = self.discv4_process_message(msg).await.inspect_err(
                    |e| error!(protocol = "discv4", err=?e, "Error handling discovery message"),
                );
            }
            Err(e) => {
                debug!(error=?e, "Failed to decode discv4 packet");
            }
        }
    }

    async fn route_to_discv5(&mut self, data: &[u8], from: SocketAddr) {
        if self.discv5.is_none() {
            return;
        }
        match Discv5Packet::decode(&self.local_node.node_id(), data) {
            Ok(packet) => {
                let msg = Discv5Message::from(packet, from);
                let _ = self.discv5_handle_packet(msg).await.inspect_err(
                    |e| trace!(protocol = "discv5", err=?e, "Error handling discovery message"),
                );
            }
            Err(
                PacketCodecError::InvalidProtocol(_)
                | PacketCodecError::InvalidHeader
                | PacketCodecError::InvalidSize
                | PacketCodecError::CipherError(_),
            ) => {
                trace!(from=?from, "Dropping unrecognized UDP packet");
            }
            Err(e) => {
                debug!(error=?e, "Failed to decode discv5 packet");
            }
        }
    }

    async fn prune(&mut self) -> Result<(), DiscoveryServerError> {
        self.contacts.prune();
        if let Some(discv4) = &mut self.discv4 {
            let expiration = Duration::from_secs(crate::discv4::server::EXPIRATION_SECONDS);
            discv4
                .pending_find_node
                .retain(|_, sent_at| sent_at.elapsed() < expiration);
        }
        if let Some(discv5) = &mut self.discv5 {
            discv5.cleanup_stale_entries();
        }
        self.refresh_fork_id();
        if let Some(ip) = self.ip_predictor.check_timeout() {
            self.apply_predicted_ip(ip, "timeout");
        }
        Ok(())
    }

    /// `source` names the protocol/path that produced the winning vote
    /// ("discv4", "discv5", or "timeout"), purely for the convergence log line.
    pub fn apply_predicted_ip(&mut self, winning_ip: IpAddr, source: &str) {
        // `winning_ip` is already routability-filtered upstream: `record_ip_vote`
        // drops only unroutable addresses (loopback/link-local/unspecified) via
        // `is_unroutable_ip`. RFC1918 / IPv6 unique-local are intentionally kept
        // and may be advertised — on a flat private network (e.g. a kurtosis
        // enclave) the private IP is the address peers actually reach us at, and
        // a public winner still takes precedence when one reaches quorum (see
        // a49c779cc). Do not add an `is_private_ip` guard here.
        if self.ip_override_locked {
            return;
        }
        if winning_ip == self.local_node.ip {
            return;
        }
        if winning_ip.is_ipv4() != self.local_node.ip.is_ipv4() {
            warn!(
                predicted_ip = %winning_ip,
                local_ip = %self.local_node.ip,
                "Predicted external IP has different address family than local IP, ignoring"
            );
            return;
        }
        info!(
            source,
            old_ip = %self.local_node.ip,
            new_ip = %winning_ip,
            "External IP detected via PONG voting, updating local ENR"
        );
        update_local_ip(
            &mut self.local_node,
            &mut self.local_node_record,
            &self.signer,
            winning_ip,
        );
        // Propagate to the shared Arc so RPC and shutdown see the current identity.
        let mut guard = self
            .shared_local_node
            .write()
            .expect("shared_local_node poisoned");
        guard.node = self.local_node.clone();
        guard.record = self.local_node_record.clone();
    }

    pub(crate) fn get_lookup_interval(&self) -> Duration {
        let peer_completion = self.contacts.peer_completion();
        lookup_interval_function(
            peer_completion,
            ITERATIVE_LOOKUP_INITIAL_MS,
            ITERATIVE_LOOKUP_INTERVAL_MS,
        )
    }
    /// Republish the ENR when the network layer reports a new fork id.
    ///
    /// `has_changed` is only true once per send, so a steady chain costs a flag check
    /// per tick. A closed channel means the network layer is gone, which is shutdown,
    /// not an error worth logging every tick. A `None` in the channel is the seed for
    /// a chain that could not supply a fork id at startup; there is nothing to
    /// republish until the publisher replaces it.
    fn refresh_fork_id(&mut self) {
        if !self.fork_id.has_changed().unwrap_or(false) {
            return;
        }
        let Some(fork_id) = self.fork_id.borrow_and_update().clone() else {
            return;
        };
        match self.local_node_record.set_fork_id(fork_id, &self.signer) {
            Ok(()) => {
                info!(
                    seq = self.local_node_record.seq,
                    "Chain crossed a fork; republished the local ENR with the new fork id"
                );
                // Mirror the re-signed record into the shared identity, as
                // apply_predicted_ip does: RPC serves the record from there, and
                // without this it would keep answering with the pre-fork ENR.
                let mut guard = self
                    .shared_local_node
                    .write()
                    .expect("shared_local_node poisoned");
                guard.record = self.local_node_record.clone();
            }
            // A record we cannot sign is worth surfacing: peers that require an `eth`
            // entry keep skipping us until this succeeds.
            Err(e) => warn!(error = ?e, "Could not set the new fork id on the local ENR"),
        }
    }
}

/// Check if a packet is a discv4 packet by verifying the hash.
pub fn is_discv4_packet(data: &[u8]) -> bool {
    if data.len() < DISCV4_MIN_PACKET_SIZE {
        return false;
    }
    let packet_hash = &data[0..32];
    let computed_hash = keccak(&data[32..]);
    packet_hash == computed_hash.as_bytes()
}

#[cfg(any(test, feature = "test-utils"))]
impl DiscoveryServer {
    /// The contact table this server owns, so a test can seed it before driving
    /// the handlers by hand.
    pub fn contacts_mut(&mut self) -> &mut ContactTable {
        &mut self.contacts
    }

    /// Builds a DiscoveryServer suitable for unit tests of discv5 handlers.
    /// Only discv5 state is initialized; discv4 is disabled.
    /// Uses a dummy initial lookup interval.
    pub fn new_for_discv5_test(
        local_node: Node,
        local_node_record: NodeRecord,
        signer: SecretKey,
        udp_socket: Arc<UdpSocket>,
        filter: Box<dyn PeerFilter>,
    ) -> Self {
        use crate::types::LocalNode;
        use std::sync::{Arc, RwLock};

        let local_node_id = local_node.node_id();
        let shared_local_node = Arc::new(RwLock::new(LocalNode {
            node: local_node.clone(),
            record: local_node_record.clone(),
        }));
        Self {
            local_node,
            local_node_record,
            signer,
            udp_socket,
            contacts: ContactTable::new(local_node_id, 10, filter),
            config: DiscoveryConfig {
                discv4_enabled: false,
                discv5_enabled: true,
                target_peers: 10,
                nat_extip_set: false,
            },
            discv4: None,
            discv5: Some(Discv5State::default()),
            ip_predictor: IpPredictor::default(),
            ip_override_locked: false,
            shared_local_node,
            // Tests drive the ENR directly; there is no publisher to listen to. The
            // sender is dropped, so `has_changed` errs and the refresh is a no-op.
            fork_id: watch::channel(None).1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        peer_filter::AcceptAllFilter,
        peer_table::TARGET_PEERS,
        types::{INITIAL_ENR_SEQ, LocalNode},
    };
    use ethrex_common::H256;
    use secp256k1::SecretKey;
    use std::{
        net::Ipv4Addr,
        sync::{Arc, RwLock},
    };
    use tokio::net::UdpSocket;

    async fn make_server(ip: IpAddr, ip_override_locked: bool) -> DiscoveryServer {
        let signer = SecretKey::new(&mut rand::rngs::OsRng);
        let pubkey = crate::utils::public_key_from_signing_key(&signer);
        let local_node = Node::new(ip, 30303, 30303, pubkey);
        let local_node_id = local_node.node_id();
        let local_node_record =
            NodeRecord::from_node(&local_node, INITIAL_ENR_SEQ, &signer).unwrap();
        let shared_local_node = Arc::new(RwLock::new(LocalNode {
            node: local_node.clone(),
            record: local_node_record.clone(),
        }));
        let udp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        DiscoveryServer {
            local_node,
            local_node_record,
            signer,
            udp_socket,
            contacts: ContactTable::new(local_node_id, TARGET_PEERS, Box::new(AcceptAllFilter)),
            config: DiscoveryConfig {
                discv4_enabled: false,
                discv5_enabled: false,
                target_peers: TARGET_PEERS,
                nat_extip_set: ip_override_locked,
            },
            discv4: None,
            discv5: None,
            ip_predictor: IpPredictor::default(),
            ip_override_locked,
            // No publisher in these tests; the dropped sender makes refresh a no-op.
            fork_id: tokio::sync::watch::channel(None).1,
            shared_local_node,
        }
    }

    #[tokio::test]
    async fn an_unpublished_handle_is_inert() {
        // Every consumer holds this handle from the moment the P2P context is
        // built, which is before discovery starts and forever if p2p runs
        // without it. Casts must be dropped quietly and the one request must
        // answer `None` rather than wait for a server that may never arrive.
        let handle = DiscoveryHandle::new();

        for event in [
            PeerEvent::Connected,
            PeerEvent::Disconnected,
            PeerEvent::Rejected,
        ] {
            handle.record_peer_event(H256::repeat_byte(1), event);
        }
        handle.prune();

        assert!(handle.next_dial_candidate().await.is_none());
    }

    /// apply_predicted_ip from unspecified -> public must update local_node, bump ENR seq,
    /// and propagate the new identity into the shared Arc.
    #[tokio::test]
    async fn apply_predicted_ip_updates_shared_arc() {
        let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let public_ip: IpAddr = "1.2.3.4".parse().unwrap();

        let mut server = make_server(unspecified, false).await;
        let original_seq = server.local_node_record.seq;

        server.apply_predicted_ip(public_ip, "test");

        assert_eq!(
            server.local_node.ip, public_ip,
            "local_node.ip must be updated"
        );
        assert!(
            server.local_node_record.seq > original_seq,
            "ENR seq must be bumped"
        );

        let guard = server.shared_local_node.read().unwrap();
        assert_eq!(
            guard.node.ip, public_ip,
            "shared Arc node.ip must be updated"
        );
        assert_eq!(
            guard.record.seq, server.local_node_record.seq,
            "shared Arc record.seq must match"
        );
    }

    /// With ip_override_locked=true (--nat.extip set), apply_predicted_ip is a no-op.
    #[tokio::test]
    async fn apply_predicted_ip_noop_when_locked() {
        let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let public_ip: IpAddr = "1.2.3.4".parse().unwrap();

        let mut server = make_server(unspecified, true).await;
        let original_seq = server.local_node_record.seq;

        server.apply_predicted_ip(public_ip, "test");

        assert_eq!(
            server.local_node.ip, unspecified,
            "local_node.ip must not change when locked"
        );
        assert_eq!(
            server.local_node_record.seq, original_seq,
            "ENR seq must not change when locked"
        );

        let guard = server.shared_local_node.read().unwrap();
        assert_eq!(
            guard.node.ip, unspecified,
            "shared Arc must not be updated when locked"
        );
    }
}
