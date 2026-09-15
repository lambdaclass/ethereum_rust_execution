//! The peers this node is connected to over RLPx, and how well each is serving us.
//!
//! Strictly the live side of the network: a node reaches this table only once a
//! connection is established, and leaves it when the connection drops. What
//! discovery knows about nodes it has merely heard of lives in
//! [`ContactTable`](crate::discovery::ContactTable), owned by the discovery
//! server, which knows nothing about RLPx.
//!
//! Peers are scored (`record_success` / `record_failure`) and their in-flight
//! request count tracked, so selection can spread load across peers that are
//! actually answering. A selected peer comes back with a [`RequestPermit`]
//! holding its slot for as long as the request is outstanding.

use crate::{
    rlpx::{connection::server::PeerConnection, p2p::Capability},
    types::{Node, NodeRecord},
};
use ethrex_common::H256;
use indexmap::IndexMap;
use rand::distributions::WeightedIndex;
use rand::prelude::Distribution;
use spawned_concurrency::{
    actor,
    error::ActorError,
    protocol,
    tasks::{Actor, ActorRef, ActorStart as _, Context, Handler, Response, send_message_on},
};
use std::net::IpAddr;

const MAX_SCORE: i64 = 50;
const MIN_SCORE: i64 = -50;
/// Score assigned to peers who are acting maliciously (e.g., returning a node with wrong hash)
const MIN_SCORE_CRITICAL: i64 = MIN_SCORE * 3;
/// Score weight for the load balancing function.
const SCORE_WEIGHT: i64 = 1;
/// Weight for amount of requests being handled by the peer for the load balancing function.
const REQUESTS_WEIGHT: i64 = 1;
/// Max amount of ongoing requests per peer.
const MAX_CONCURRENT_REQUESTS_PER_PEER: i64 = 100;
/// The target number of RLPx connections to reach.
pub const TARGET_PEERS: usize = 100;

#[derive(Debug, Clone)]
pub struct PeerData {
    pub node: Node,
    pub record: Option<NodeRecord>,
    pub supported_capabilities: Vec<Capability>,
    /// The eth version in force for this session: the highest version both sides
    /// advertised. Message shapes on the wire must be chosen from this and never
    /// from `supported_capabilities`, which is only what the peer offered and may
    /// name versions we did not advertise back.
    pub negotiated_eth: Option<Capability>,
    /// Set to true if the connection is inbound (aka the connection was started by the peer and not by this node)
    /// It is only valid as long as is_connected is true
    pub is_connection_inbound: bool,
    /// communication channels between the peer data and its active connection
    pub connection: Option<PeerConnection>,
    /// This tracks the score of a peer
    score: i64,
    /// Track the amount of concurrent requests this peer is handling
    requests: i64,
    /// Timestamp (seconds since UNIX epoch) of the last successful response from this peer
    pub last_response_time: Option<u64>,
}

impl PeerData {
    pub fn new(
        node: Node,
        record: Option<NodeRecord>,
        connection: Option<PeerConnection>,
        capabilities: Vec<Capability>,
        negotiated_eth: Option<Capability>,
    ) -> Self {
        Self {
            node,
            record,
            supported_capabilities: capabilities,
            negotiated_eth,
            is_connection_inbound: false,
            connection,
            score: Default::default(),
            requests: Default::default(),
            last_response_time: None,
        }
    }
}

/// Diagnostic snapshot of a peer's state, used by admin RPC endpoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerDiagnostics {
    pub peer_id: H256,
    pub score: i64,
    pub inflight_requests: i64,
    pub eligible: bool,
    pub capabilities: Vec<String>,
    pub ip: IpAddr,
    pub client_version: String,
    pub connection_direction: String,
    pub last_response_time: Option<u64>,
}

/// Reservation handle for a peer request slot.
///
/// **Contract:** when a `RequestPermit` exists, the `requests` counter for
/// its peer has been incremented by one. Dropping the permit releases the
/// slot via a fire-and-forget `DecRequests` message. The handler that
/// returns the permit also bumps the counter atomically under `&mut self`,
/// so selection and reservation cannot be observed out of order.
///
/// The permit must travel with whatever code owns the outstanding request —
/// move it into spawned tasks, send it through channels alongside results,
/// etc. Dropping early releases the slot early.
#[must_use = "dropping this permit immediately releases the peer's request slot"]
pub struct RequestPermit {
    peer_table: PeerTable,
    peer_id: H256,
}

/// A peer picked for one request: its node id, a live connection, the permit
/// holding its request slot, and the capabilities it advertised — the last so
/// callers can derive the negotiated protocol version where the wire format
/// depends on it (receipts differ between eth/69 and eth/70).
pub type SelectedPeer = (H256, PeerConnection, RequestPermit, Vec<Capability>);

impl RequestPermit {
    pub(crate) fn new(peer_table: PeerTable, peer_id: H256) -> Self {
        Self {
            peer_table,
            peer_id,
        }
    }
}

impl std::fmt::Debug for RequestPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestPermit")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        // Fire-and-forget. If the actor mailbox is closed, p2p is already
        // shutting down — the lost decrement is a non-issue.
        let _ = self.peer_table.dec_requests(self.peer_id);
    }
}

#[protocol]
pub trait PeerTableServerProtocol: Send + Sync {
    // Send (cast) methods

    fn remove_peer(&self, node_id: H256) -> Result<(), ActorError>;
    fn dec_requests(&self, node_id: H256) -> Result<(), ActorError>;
    fn record_success(&self, node_id: H256) -> Result<(), ActorError>;
    fn record_failure(&self, node_id: H256) -> Result<(), ActorError>;
    fn record_critical_failure(&self, node_id: H256) -> Result<(), ActorError>;
    fn shutdown(&self) -> Result<(), ActorError>;

    // Request (call) methods

    /// Claim the slot for this peer, returning whether it was granted.
    ///
    /// `false` means we already hold a connection to this node id and the
    /// caller lost a race, so it should hang up rather than register. The
    /// check and the insert both happen in this actor's message loop, which is
    /// what makes the claim atomic between two connection actors.
    fn new_connected_peer(
        &self,
        node: Node,
        connection: PeerConnection,
        capabilities: Vec<Capability>,
        negotiated_eth: Option<Capability>,
        is_inbound: bool,
    ) -> Response<bool>;
    fn peer_count(&self) -> Response<usize>;
    fn peer_count_by_capabilities(&self, capabilities: Vec<Capability>) -> Response<usize>;
    fn target_peers_reached(&self) -> Response<bool>;
    fn target_peers_completion(&self) -> Response<f64>;
    fn get_best_peer(
        &self,
        capabilities: Vec<Capability>,
    ) -> Response<Option<(H256, PeerConnection, RequestPermit)>>;
    fn get_best_peer_excluding(
        &self,
        capabilities: Vec<Capability>,
        excluded: Vec<H256>,
    ) -> Response<Option<(H256, PeerConnection, RequestPermit)>>;
    fn get_best_n_peers(
        &self,
        capabilities: Vec<Capability>,
        n: usize,
    ) -> Response<Vec<(H256, PeerConnection, RequestPermit)>>;
    /// Read-only predicate: is there any eligible peer matching `capabilities`?
    /// Does not reserve a slot; use for capacity/rotation probes only.
    fn has_eligible_peer(&self, capabilities: Vec<Capability>) -> Response<bool>;
    fn get_score(&self, node_id: H256) -> Response<i64>;
    fn get_connected_nodes(&self) -> Response<Vec<Node>>;
    /// Every connected peer with the eth version negotiated for its session.
    fn get_connected_peers(&self) -> Response<Vec<(H256, PeerConnection, Option<Capability>)>>;
    fn get_peers_data(&self) -> Response<Vec<PeerData>>;
    fn get_random_peer(&self, capabilities: Vec<Capability>) -> Response<Option<SelectedPeer>>;
    fn get_peer_diagnostics(&self) -> Response<Vec<PeerDiagnostics>>;
    fn get_peer_connection(&self, peer_id: H256) -> Response<Option<PeerConnection>>;
}

pub struct PeerTableServer {
    peers: IndexMap<H256, PeerData>,
    /// How many connections this node wants. Discovery keeps its own copy to
    /// pace its lookups, fed from the same config value.
    target_peers: usize,
}

impl std::fmt::Debug for PeerTableServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerTableServer")
            .field("peers", &self.peers)
            .field("target_peers", &self.target_peers)
            .finish()
    }
}

#[actor(protocol = PeerTableServerProtocol)]
impl PeerTableServer {
    pub fn spawn(target_peers: usize) -> PeerTable {
        PeerTableServer::new(target_peers).start()
    }

    pub(crate) fn new(target_peers: usize) -> Self {
        Self {
            peers: Default::default(),
            target_peers,
        }
    }

    #[started]
    async fn started(&mut self, ctx: &Context<Self>) {
        send_message_on(
            ctx.clone(),
            tokio::signal::ctrl_c(),
            peer_table_server_protocol::Shutdown,
        );
    }

    // === Send handlers ===

    #[request_handler]
    async fn handle_new_connected_peer(
        &mut self,
        msg: peer_table_server_protocol::NewConnectedPeer,
        _ctx: &Context<Self>,
    ) -> bool {
        self.do_new_connected_peer(
            msg.node,
            Some(msg.connection),
            msg.capabilities,
            msg.negotiated_eth,
            msg.is_inbound,
        )
    }

    #[send_handler]
    async fn handle_remove_peer(
        &mut self,
        msg: peer_table_server_protocol::RemovePeer,
        _ctx: &Context<Self>,
    ) {
        self.peers.swap_remove(&msg.node_id);
    }

    #[send_handler]
    async fn handle_dec_requests(
        &mut self,
        msg: peer_table_server_protocol::DecRequests,
        _ctx: &Context<Self>,
    ) {
        self.peers.entry(msg.node_id).and_modify(|peer_data| {
            if peer_data.requests <= 0 {
                // Expected under the reconnect race (stale permit fires
                // after remove_peer + new_connected_peer), self-heals.
                // Otherwise points to a bookkeeping bug worth chasing.
                tracing::debug!(
                    peer_id = ?msg.node_id,
                    requests = peer_data.requests,
                    "dec_requests with counter already <= 0",
                );
            }
            peer_data.requests = peer_data.requests.saturating_sub(1).max(0)
        });
    }

    #[send_handler]
    async fn handle_record_success(
        &mut self,
        msg: peer_table_server_protocol::RecordSuccess,
        _ctx: &Context<Self>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.peers.entry(msg.node_id).and_modify(|peer_data| {
            peer_data.score = (peer_data.score + 1).min(MAX_SCORE);
            peer_data.last_response_time = Some(now);
        });
    }

    #[send_handler]
    async fn handle_record_failure(
        &mut self,
        msg: peer_table_server_protocol::RecordFailure,
        _ctx: &Context<Self>,
    ) {
        self.peers
            .entry(msg.node_id)
            .and_modify(|peer_data| peer_data.score = (peer_data.score - 1).max(MIN_SCORE));
    }

    #[send_handler]
    async fn handle_record_critical_failure(
        &mut self,
        msg: peer_table_server_protocol::RecordCriticalFailure,
        _ctx: &Context<Self>,
    ) {
        self.peers
            .entry(msg.node_id)
            .and_modify(|peer_data| peer_data.score = MIN_SCORE_CRITICAL);
    }

    #[send_handler]
    async fn handle_shutdown(
        &mut self,
        _msg: peer_table_server_protocol::Shutdown,
        ctx: &Context<Self>,
    ) {
        ctx.stop();
    }

    // === Request handlers ===

    #[request_handler]
    async fn handle_peer_count(
        &mut self,
        _msg: peer_table_server_protocol::PeerCount,
        _ctx: &Context<Self>,
    ) -> usize {
        self.peers.len()
    }

    #[request_handler]
    async fn handle_peer_count_by_capabilities(
        &mut self,
        msg: peer_table_server_protocol::PeerCountByCapabilities,
        _ctx: &Context<Self>,
    ) -> usize {
        self.do_peer_count_by_capabilities(msg.capabilities)
    }

    #[request_handler]
    async fn handle_target_peers_reached(
        &mut self,
        _msg: peer_table_server_protocol::TargetPeersReached,
        _ctx: &Context<Self>,
    ) -> bool {
        self.peers.len() >= self.target_peers
    }

    #[request_handler]
    async fn handle_target_peers_completion(
        &mut self,
        _msg: peer_table_server_protocol::TargetPeersCompletion,
        _ctx: &Context<Self>,
    ) -> f64 {
        if self.target_peers == 0 {
            return 1.0;
        }
        self.peers.len() as f64 / self.target_peers as f64
    }

    #[request_handler]
    async fn handle_get_best_peer(
        &mut self,
        msg: peer_table_server_protocol::GetBestPeer,
        ctx: &Context<Self>,
    ) -> Option<(H256, PeerConnection, RequestPermit)> {
        let (peer_id, conn) = self.do_get_best_peer(&msg.capabilities)?;
        self.peers
            .get_mut(&peer_id)
            .expect("peer returned by do_get_best_peer must be present in self.peers")
            .requests += 1;
        Some((peer_id, conn, RequestPermit::new(ctx.actor_ref(), peer_id)))
    }

    #[request_handler]
    async fn handle_get_best_peer_excluding(
        &mut self,
        msg: peer_table_server_protocol::GetBestPeerExcluding,
        ctx: &Context<Self>,
    ) -> Option<(H256, PeerConnection, RequestPermit)> {
        let (peer_id, conn) = self.do_get_best_peer_excluding(&msg.capabilities, &msg.excluded)?;
        self.peers
            .get_mut(&peer_id)
            .expect("peer returned by do_get_best_peer_excluding must be present in self.peers")
            .requests += 1;
        Some((peer_id, conn, RequestPermit::new(ctx.actor_ref(), peer_id)))
    }

    #[request_handler]
    async fn handle_get_best_n_peers(
        &mut self,
        msg: peer_table_server_protocol::GetBestNPeers,
        ctx: &Context<Self>,
    ) -> Vec<(H256, PeerConnection, RequestPermit)> {
        let picks = self.do_get_best_n_peers(&msg.capabilities, msg.n);
        let mut out = Vec::with_capacity(picks.len());
        for (peer_id, conn) in picks {
            self.peers
                .get_mut(&peer_id)
                .expect("peer returned by do_get_best_n_peers must be present in self.peers")
                .requests += 1;
            out.push((peer_id, conn, RequestPermit::new(ctx.actor_ref(), peer_id)));
        }
        out
    }

    #[request_handler]
    async fn handle_has_eligible_peer(
        &mut self,
        msg: peer_table_server_protocol::HasEligiblePeer,
        _ctx: &Context<Self>,
    ) -> bool {
        self.peers.values().any(|peer_data| {
            peer_data.connection.is_some()
                && self.can_try_more_requests(&peer_data.score, &peer_data.requests)
                && msg
                    .capabilities
                    .iter()
                    .any(|cap| peer_data.supported_capabilities.contains(cap))
        })
    }

    #[request_handler]
    async fn handle_get_score(
        &mut self,
        msg: peer_table_server_protocol::GetScore,
        _ctx: &Context<Self>,
    ) -> i64 {
        self.peers
            .get(&msg.node_id)
            .map(|peer_data| peer_data.score)
            .unwrap_or_default()
    }

    #[request_handler]
    async fn handle_get_connected_nodes(
        &mut self,
        _msg: peer_table_server_protocol::GetConnectedNodes,
        _ctx: &Context<Self>,
    ) -> Vec<Node> {
        self.peers
            .values()
            .map(|peer_data| peer_data.node.clone())
            .collect()
    }

    #[request_handler]
    async fn handle_get_connected_peers(
        &mut self,
        _msg: peer_table_server_protocol::GetConnectedPeers,
        _ctx: &Context<Self>,
    ) -> Vec<(H256, PeerConnection, Option<Capability>)> {
        self.peers
            .iter()
            .filter_map(|(peer_id, peer_data)| {
                peer_data
                    .connection
                    .clone()
                    .map(|connection| (*peer_id, connection, peer_data.negotiated_eth.clone()))
            })
            .collect()
    }

    #[request_handler]
    async fn handle_get_peers_data(
        &mut self,
        _msg: peer_table_server_protocol::GetPeersData,
        _ctx: &Context<Self>,
    ) -> Vec<PeerData> {
        self.peers.values().cloned().collect()
    }

    #[request_handler]
    async fn handle_get_random_peer(
        &mut self,
        msg: peer_table_server_protocol::GetRandomPeer,
        ctx: &Context<Self>,
    ) -> Option<SelectedPeer> {
        let (peer_id, conn, capabilities) = self.do_get_random_peer(msg.capabilities)?;
        self.peers
            .get_mut(&peer_id)
            .expect("peer returned by do_get_random_peer must be present in self.peers")
            .requests += 1;
        Some((
            peer_id,
            conn,
            RequestPermit::new(ctx.actor_ref(), peer_id),
            capabilities,
        ))
    }

    #[request_handler]
    async fn handle_get_peer_connection(
        &mut self,
        msg: peer_table_server_protocol::GetPeerConnection,
        _ctx: &Context<Self>,
    ) -> Option<PeerConnection> {
        self.peers
            .get(&msg.peer_id)
            .and_then(|peer_data| peer_data.connection.clone())
    }

    #[request_handler]
    async fn handle_get_peer_diagnostics(
        &mut self,
        _msg: peer_table_server_protocol::GetPeerDiagnostics,
        _ctx: &Context<Self>,
    ) -> Vec<PeerDiagnostics> {
        self.peers
            .iter()
            .map(|(id, peer_data)| PeerDiagnostics {
                peer_id: *id,
                score: peer_data.score,
                inflight_requests: peer_data.requests,
                eligible: self.can_try_more_requests(&peer_data.score, &peer_data.requests),
                capabilities: peer_data
                    .supported_capabilities
                    .iter()
                    .map(|c| format!("{}/{}", c.protocol(), c.version))
                    .collect(),
                ip: peer_data.node.ip,
                client_version: peer_data.node.version.clone().unwrap_or_default(),
                connection_direction: if peer_data.is_connection_inbound {
                    "inbound".to_string()
                } else {
                    "outbound".to_string()
                },
                last_response_time: peer_data.last_response_time,
            })
            .collect()
    }

    // === Private helper methods ===

    // --- Peer selection ---

    /// Claim the slot for `node`, returning whether it was granted.
    ///
    /// Refuses rather than overwrites. Two connection actors can reach this
    /// point for one node id (crossing dials, or a peer opening a second
    /// socket), and overwriting let the second silently displace the first: the
    /// displaced connection stayed open but became invisible to peer selection,
    /// and whichever actor stopped first then removed the survivor's entry on
    /// its way out.
    fn do_new_connected_peer(
        &mut self,
        node: Node,
        connection: Option<PeerConnection>,
        capabilities: Vec<Capability>,
        negotiated_eth: Option<Capability>,
        is_inbound: bool,
    ) -> bool {
        let new_peer_id = node.node_id();
        if self.peers.contains_key(&new_peer_id) {
            return false;
        }
        let mut new_peer = PeerData::new(node, None, connection, capabilities, negotiated_eth);
        new_peer.is_connection_inbound = is_inbound;
        self.peers.insert(new_peer_id, new_peer);
        true
    }

    fn weight_peer(&self, score: &i64, requests: &i64) -> i64 {
        score * SCORE_WEIGHT - requests * REQUESTS_WEIGHT
    }

    fn can_try_more_requests(&self, score: &i64, requests: &i64) -> bool {
        let score_ratio = (score - MIN_SCORE) as f64 / (MAX_SCORE - MIN_SCORE) as f64;
        let max_requests = (MAX_CONCURRENT_REQUESTS_PER_PEER as f64 * score_ratio).max(1.0);
        (*requests as f64) < max_requests
    }

    fn do_get_best_peer(&self, capabilities: &[Capability]) -> Option<(H256, PeerConnection)> {
        self.do_get_best_peer_excluding(capabilities, &[])
    }

    /// Like `do_get_best_peer`, but excludes specific peers from selection.
    /// Used by `update_pivot` to rotate through peers on repeated failures.
    fn do_get_best_peer_excluding(
        &self,
        capabilities: &[Capability],
        excluded: &[H256],
    ) -> Option<(H256, PeerConnection)> {
        self.peers
            .iter()
            .filter_map(|(id, peer_data)| {
                if excluded.contains(id)
                    || !self.can_try_more_requests(&peer_data.score, &peer_data.requests)
                    || !capabilities
                        .iter()
                        .any(|cap| peer_data.supported_capabilities.contains(cap))
                {
                    None
                } else {
                    let connection = peer_data.connection.clone()?;
                    Some((*id, peer_data.score, peer_data.requests, connection))
                }
            })
            .max_by_key(|(_, score, reqs, _)| self.weight_peer(score, reqs))
            .map(|(k, _, _, v)| (k, v))
    }

    /// Returns up to `n` best peers with capability overlap, sorted by weight
    /// descending. Excludes peers at capacity. Does NOT mutate state — caller
    /// is responsible for incrementing `requests` on each returned peer. The
    /// sort uses a pre-increment snapshot: later picks don't see earlier
    /// picks' bumps, which is fine for small `n`.
    fn do_get_best_n_peers(
        &self,
        capabilities: &[Capability],
        n: usize,
    ) -> Vec<(H256, PeerConnection)> {
        let mut candidates: Vec<(H256, i64, i64, PeerConnection)> = self
            .peers
            .iter()
            .filter_map(|(id, peer_data)| {
                if !self.can_try_more_requests(&peer_data.score, &peer_data.requests)
                    || !capabilities
                        .iter()
                        .any(|cap| peer_data.supported_capabilities.contains(cap))
                {
                    None
                } else {
                    let connection = peer_data.connection.clone()?;
                    Some((*id, peer_data.score, peer_data.requests, connection))
                }
            })
            .collect();

        candidates.sort_by_key(|(_, score, reqs, _)| -self.weight_peer(score, reqs));
        candidates
            .into_iter()
            .take(n)
            .map(|(id, _, _, conn)| (id, conn))
            .collect()
    }

    fn do_peer_count_by_capabilities(&self, capabilities: Vec<Capability>) -> usize {
        self.peers
            .values()
            .filter(|peer_data| {
                capabilities
                    .iter()
                    .any(|cap| peer_data.supported_capabilities.contains(cap))
            })
            .count()
    }

    /// Picks a random connected peer advertising any of `capabilities`, weighted by
    /// score. Also returns the peer's advertised capabilities so callers can derive
    /// the negotiated protocol version (needed where the wire format differs between
    /// versions, e.g. receipts across eth/69 and eth/70).
    fn do_get_random_peer(
        &self,
        capabilities: Vec<Capability>,
    ) -> Option<(H256, PeerConnection, Vec<Capability>)> {
        let peers: Vec<(H256, &PeerConnection, i64, &Vec<Capability>)> = self
            .peers
            .iter()
            .filter_map(|(node_id, peer_data)| {
                if !capabilities
                    .iter()
                    .any(|cap| peer_data.supported_capabilities.contains(cap))
                {
                    return None;
                }
                peer_data.connection.as_ref().map(|connection| {
                    (
                        *node_id,
                        connection,
                        peer_data.score,
                        &peer_data.supported_capabilities,
                    )
                })
            })
            .collect();
        if peers.is_empty() {
            return None;
        }
        // Weight by score: maps [-150, 50] to [1, 201] so bad peers are unlikely but not excluded
        let weights: Vec<u64> = peers
            .iter()
            .map(|(_, _, score, _)| {
                (score.max(&MIN_SCORE_CRITICAL) - MIN_SCORE_CRITICAL + 1) as u64
            })
            .collect();
        let dist = WeightedIndex::new(&weights).ok()?;
        let idx = dist.sample(&mut rand::rngs::OsRng);
        Some((peers[idx].0, peers[idx].1.clone(), peers[idx].3.clone()))
    }
}

pub type PeerTable = ActorRef<PeerTableServer>;

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::H512;
    use std::net::Ipv4Addr;

    fn node(seed: u8) -> Node {
        Node::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, seed)),
            30303,
            30303,
            H512::from_low_u64_be(seed as u64 + 1),
        )
    }

    /// Registration with no live connection behind it, and no negotiated `eth`
    /// version: enough to exercise the claim, which only ever looks at the node id.
    fn claim(table: &mut PeerTableServer, node: Node) -> bool {
        table.do_new_connected_peer(node, None, vec![], None, false)
    }

    #[test]
    fn a_second_connection_to_the_same_peer_is_refused() {
        // Two connection actors can reach registration for one node id, and the
        // loser has to find out so it can hang up. Overwriting instead left two
        // live sockets and one table entry, so the first actor to stop evicted
        // the other's connection.
        let mut table = PeerTableServer::new(10);

        assert!(
            claim(&mut table, node(1)),
            "first connection claims the slot"
        );
        assert!(!claim(&mut table, node(1)), "the second is refused");
        assert_eq!(table.peers.len(), 1, "and did not displace the first");
    }

    #[test]
    fn a_different_peer_is_unaffected() {
        let mut table = PeerTableServer::new(10);

        assert!(claim(&mut table, node(1)));
        assert!(claim(&mut table, node(2)), "the claim is per node id");
        assert_eq!(table.peers.len(), 2);
    }

    #[test]
    fn a_peer_can_register_again_after_disconnecting() {
        // The claim must not outlive the connection, or a reconnecting peer
        // would be turned away for the life of the process.
        let mut table = PeerTableServer::new(10);

        assert!(claim(&mut table, node(3)));
        table.peers.swap_remove(&node(3).node_id());

        assert!(
            claim(&mut table, node(3)),
            "a reconnect is granted the slot"
        );
    }
}
