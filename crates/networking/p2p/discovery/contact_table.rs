//! The contacts discovery knows about, and the Kademlia routing table over them.
//!
//! Owned outright by [`DiscoveryServer`](super::DiscoveryServer) as plain state:
//! every discv4 and discv5 handler runs inside that actor's message loop, so
//! they reach the table by `&mut self` rather than paying a message hop per
//! inbound packet.
//!
//! Nothing here knows what RLPx is. A consumer that only wants discovery says
//! what makes a peer worth keeping through a [`PeerFilter`], and learns which
//! of them are worth dialing through [`ContactTable::next_dial_candidate`].
//! Whoever does dial reports back with [`ContactTable::mark_connected`] and
//! [`ContactTable::mark_disconnected`], which is all the table needs to keep
//! its candidates and its lookup pacing honest.
//!
//! The table is protocol-agnostic across the two discovery protocols. The key
//! abstraction is using `Bytes` for ping identifiers:
//! - discv4: converts H256 ping hash to Bytes
//! - discv5: already uses Bytes for req_id
//!
//! Each contact is tagged with the protocol that discovered it, allowing
//! protocol-specific lookups to only query compatible contacts.

use crate::{
    metrics::METRICS,
    peer_filter::PeerFilter,
    types::{Node, NodeRecord},
    utils::distance,
};
use bytes::Bytes;
use ethrex_common::{H256, U256};
use indexmap::IndexMap;
use rand::seq::{IteratorRandom, SliceRandom};
use rustc_hash::{FxHashMap, FxHashSet};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::discv5::server::SESSION_TTL;
/// Session information for discv5 protocol.
/// Contains symmetric keys derived from ECDH for message encryption/decryption.
pub use crate::discv5::session::Session;
/// Maximum number of ENRs to return in a FindNode response (discv4 compatible).
pub(crate) const MAX_NODES_IN_NEIGHBORS_PACKET: usize = 16;
/// Maximum number of ENRs to return in a discv5 FindNode response.
const MAX_ENRS_PER_FINDNODE_RESPONSE: usize = 16;

/// Number of k-buckets in the Kademlia routing table (one per bit of the 256-bit node ID).
const NUMBER_OF_BUCKETS: usize = 256;
/// Maximum number of contacts per k-bucket (Kademlia k parameter).
pub const MAX_NODES_PER_BUCKET: usize = 16;
/// Maximum number of replacement entries per k-bucket.
const MAX_REPLACEMENTS_PER_BUCKET: usize = 10;
/// Maximum number of entries in the flat connection candidate pool.
/// This pool is separate from the k-bucket routing table and retains
/// more contacts for RLPx connection initiation than the k-bucket
/// structure allows (256 × 16 = 4,096 vs this larger capacity).
/// 10K matches what Reth and Nethermind use for their candidate pools.
const MAX_CONNECTION_POOL_SIZE: usize = 10_000;

/// A single k-bucket in the Kademlia routing table.
/// Each bucket stores contacts at a specific XOR distance range from the local node.
#[derive(Debug, Clone, Default)]
pub struct KBucket {
    pub(crate) contacts: Vec<(H256, Contact)>,
    pub(crate) replacements: Vec<(H256, Contact)>,
}

impl KBucket {
    /// Find a contact by node ID in the main list.
    fn get(&self, node_id: &H256) -> Option<&Contact> {
        self.contacts
            .iter()
            .find(|(id, _)| id == node_id)
            .map(|(_, c)| c)
    }

    /// Find a contact by node ID in either the main or replacement list.
    fn get_any(&self, node_id: &H256) -> Option<&Contact> {
        self.get(node_id).or_else(|| {
            self.replacements
                .iter()
                .find(|(id, _)| id == node_id)
                .map(|(_, c)| c)
        })
    }

    /// Find a mutable reference to a contact by node ID (main or replacement list).
    fn get_mut(&mut self, node_id: &H256) -> Option<&mut Contact> {
        if let Some((_, c)) = self.contacts.iter_mut().find(|(id, _)| id == node_id) {
            return Some(c);
        }
        self.replacements
            .iter_mut()
            .find(|(id, _)| id == node_id)
            .map(|(_, c)| c)
    }

    /// Check if a contact exists in this bucket (main or replacement list).
    fn contains(&self, node_id: &H256) -> bool {
        self.contacts.iter().any(|(id, _)| id == node_id)
            || self.replacements.iter().any(|(id, _)| id == node_id)
    }

    /// Insert a contact into the bucket. Returns true if inserted into main list.
    /// If the bucket is full, the contact is added to the replacement list instead.
    fn insert(&mut self, node_id: H256, contact: Contact) -> bool {
        if self.contacts.len() < MAX_NODES_PER_BUCKET {
            self.contacts.push((node_id, contact));
            true
        } else {
            self.insert_replacement(node_id, contact);
            false
        }
    }

    /// Add a contact to the replacement list, evicting the oldest if full.
    fn insert_replacement(&mut self, node_id: H256, contact: Contact) {
        if self.replacements.len() >= MAX_REPLACEMENTS_PER_BUCKET {
            self.replacements.remove(0);
        }
        self.replacements.push((node_id, contact));
    }

    /// Remove a contact from the main list and promote a replacement if available.
    /// Returns the promoted replacement's node ID, if any.
    fn remove_and_promote(&mut self, node_id: &H256) -> Option<H256> {
        let idx = self.contacts.iter().position(|(id, _)| id == node_id)?;
        self.contacts.remove(idx);
        if !self.replacements.is_empty() {
            let (replacement_id, replacement) = self.replacements.remove(0);
            self.contacts.push((replacement_id, replacement));
            Some(replacement_id)
        } else {
            None
        }
    }
}

/// Computes the bucket index for a node relative to the local node.
/// Uses XOR distance: bucket = floor(log2(XOR(local, remote))), i.e. the
/// position of the highest set bit minus 1.
/// Returns None for the local node itself (XOR = 0).
fn bucket_index(local_node_id: &H256, node_id: &H256) -> Option<usize> {
    let xor = *local_node_id ^ *node_id;
    let dist = U256::from_big_endian(xor.as_bytes());
    if dist.is_zero() {
        None
    } else {
        Some(dist.bits() - 1)
    }
}

/// Computes the raw XOR distance between two node IDs.
/// Used for comparing relative closeness: a is closer to target than b
/// iff xor_distance(target, a) < xor_distance(target, b).
pub(crate) fn xor_distance(a: &H256, b: &H256) -> H256 {
    *a ^ *b
}

/// Identifies which discovery protocol was used to find a contact.
/// This allows protocol-specific lookups to only query compatible contacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryProtocol {
    /// Contact discovered via discv4 protocol
    Discv4,
    /// Contact discovered via discv5 protocol
    Discv5,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub node: Node,
    /// Whether this contact is reachable via discv4 protocol.
    pub is_discv4: bool,
    /// Whether this contact is reachable via discv5 protocol.
    pub is_discv5: bool,
    /// The timestamp when the contact was last sent a ping.
    /// If None, the contact has never been pinged.
    pub validation_timestamp: Option<Instant>,
    /// The identifier of the last unacknowledged ping sent to this contact, or
    /// None if no ping was sent yet or it was already acknowledged.
    /// - discv4: H256 hash converted to Bytes
    /// - discv5: request ID as Bytes
    pub ping_id: Option<Bytes>,

    /// The hash of the last unacknowledged ENRRequest sent to this contact, or
    /// None if no request was sent yet or it was already acknowledged.
    pub enr_request_hash: Option<H256>,

    /// ENR associated with this contact, if it was provided by the peer.
    pub record: Option<NodeRecord>,
    /// This contact failed to respond our Ping.
    pub disposable: bool,
    /// Set to true after we send a successful ENRResponse to it.
    pub knows_us: bool,
    /// This is a known-bad peer (on another network, no matching capabilities, etc)
    pub unwanted: bool,
    /// Whether this contact's last known ENR made it through the consumer's
    /// [`PeerFilter`], or `None` while it has never been filtered.
    ///
    /// Unfiltered stays dialable: a contact discovered without an ENR never
    /// reaches the filter at all, and treating that as a rejection would leave
    /// it permanently untriable. That is why bootnodes, which arrive as bare
    /// endpoints, are dialable before they have published anything.
    pub passes_filter: Option<bool>,
}

impl Contact {
    pub fn was_validated(&self) -> bool {
        self.validation_timestamp.is_some() && !self.has_pending_ping()
    }

    pub fn has_pending_ping(&self) -> bool {
        self.ping_id.is_some()
    }

    pub fn record_ping_sent(&mut self, ping_id: Bytes) {
        self.validation_timestamp = Some(Instant::now());
        self.ping_id = Some(ping_id);
    }

    pub fn record_enr_request_sent(&mut self, request_hash: H256) {
        self.enr_request_hash = Some(request_hash);
    }

    /// Stores `record` if it answers the ENR request we have outstanding.
    ///
    /// Returns whether it was stored, so the caller knows whether the contact's
    /// cached [`Self::passes_filter`] still describes the record it holds. A
    /// response whose hash does not match is ignored outright: letting it
    /// through would let a peer restate its own standing from a record we
    /// refused to keep.
    pub fn record_enr_response_received(&mut self, request_hash: H256, record: NodeRecord) -> bool {
        if self
            .enr_request_hash
            .take_if(|h| *h == request_hash)
            .is_some()
        {
            self.record = Some(record);
            return true;
        }
        false
    }

    pub fn has_pending_enr_request(&self) -> bool {
        self.enr_request_hash.is_some()
    }
}

impl Contact {
    pub fn new(node: Node, protocol: DiscoveryProtocol) -> Self {
        Self {
            node,
            is_discv4: protocol == DiscoveryProtocol::Discv4,
            is_discv5: protocol == DiscoveryProtocol::Discv5,
            validation_timestamp: None,
            ping_id: None,
            enr_request_hash: None,
            record: None,
            disposable: false,
            knows_us: true,
            unwanted: false,
            passes_filter: None,
        }
    }

    /// Check if this contact supports the given protocol.
    pub fn supports_protocol(&self, protocol: DiscoveryProtocol) -> bool {
        match protocol {
            DiscoveryProtocol::Discv4 => self.is_discv4,
            DiscoveryProtocol::Discv5 => self.is_discv5,
        }
    }

    /// Mark this contact as supporting the given protocol.
    pub fn add_protocol(&mut self, protocol: DiscoveryProtocol) {
        match protocol {
            DiscoveryProtocol::Discv4 => self.is_discv4 = true,
            DiscoveryProtocol::Discv5 => self.is_discv5 = true,
        }
    }
}

/// Something that happened to the consumer's relationship with a peer.
///
/// Events, not states, and named as such: nothing here describes a peer's
/// standing condition, so no variant can be read as subsuming another. A
/// standing "we do not want this peer" would imply not being connected to it,
/// which is why the verdict is spelled [`Self::Rejected`], the moment we turned
/// an attempt away, rather than after the `unwanted` flag it happens to set.
///
/// The three are also disjoint in practice, which the old naming obscured:
/// [`Self::Rejected`] is only ever reported for an attempt that never became a
/// connection, since a handshake is refused before the connection is
/// registered. It is not a transition out of [`Self::Connected`].
///
/// [`Self::Rejected`] deliberately leaves the connected set alone: it is a
/// verdict about whether to dial a peer in future, not a statement that the
/// current connection is over.
///
/// There is no variant for `disposable`. That flag means a contact did not
/// answer us over UDP, which only discovery is in a position to observe, so it
/// is set internally rather than reported. The sync layer used to reach for it
/// to mean "stop using this peer", which is not what it does: it deletes the
/// peer's routing-table entry, leaves the connection up, and is erased by the
/// next prune. Scoring the peer down is the mechanism for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvent {
    /// A connection was established: stop offering this peer as a dial
    /// candidate, and count it towards how hard discovery looks for more.
    Connected,
    /// An established connection ended, for any reason. Carries no judgement,
    /// and does not disturb one already recorded.
    Disconnected,
    /// A connection attempt was turned away, because the peer is on another
    /// network or advertises no capability the consumer wants. Sets the
    /// contact's `unwanted` flag, so it is never dialed again.
    ///
    /// Ignored for a peer that is currently connected; see
    /// [`ContactTable::record_peer_event`].
    Rejected,
}

/// Result of contact validation.
#[derive(Debug, Clone)]
pub enum ContactValidation {
    Valid(Box<Contact>),
    InvalidContact,
    UnknownContact,
    IpMismatch,
}

/// Everything discovery knows about the nodes it has found.
///
/// Four stores, deliberately kept apart:
/// - `buckets`, the Kademlia routing table, answering the protocol's own
///   "who is near this id" questions.
/// - `connection_pool`, a much larger flat pool of dialable nodes. The
///   k-buckets cap out at 256 x 16 = 4,096 and evict by distance, which is the
///   right policy for routing and the wrong one for finding someone to talk to.
/// - `sessions`, discv5's symmetric keys, kept independently of contacts so a
///   session survives a node whose ENR we cannot yet parse.
/// - `connected`, the ids the consumer has told us it is talking to.
pub struct ContactTable {
    local_node_id: H256,
    buckets: Vec<KBucket>,
    /// Flat pool of discovered contacts for connection initiation.
    /// Decoupled from the k-bucket routing table so that connection initiation
    /// has access to a much larger candidate pool than the k-bucket structure
    /// allows (k-buckets: 256 x 16 = 4,096 max; this pool: up to 10,000).
    /// K-buckets are still used for all Kademlia protocol operations.
    connection_pool: IndexMap<H256, Node>,
    /// Standalone session store, independent of contacts. Allows a session to be stored
    /// before the contact's ENR is known or parseable, which is why it cannot simply live
    /// on the contact.
    ///
    /// Each entry carries when it was last used, because a remote peer decides how many
    /// of these we hold: every handshake inserts one, and nothing about a handshake
    /// obliges the peer to ever come back. [`Self::prune`] evicts entries left idle for
    /// [`SESSION_TTL`], so the store is bounded by the peers still talking to us rather
    /// than by every peer that ever handshaked.
    sessions: FxHashMap<H256, (Session, Instant)>,
    /// What this consumer requires of a discovered peer. Judged as each ENR
    /// arrives, over either discovery protocol; the answer is cached on the
    /// contact as [`Contact::passes_filter`].
    filter: Box<dyn PeerFilter>,
    /// Nodes the consumer has reported as connected. Kept here rather than read
    /// back from the consumer, so that discovery never has to call into it:
    /// every message across that boundary travels inward.
    connected: FxHashSet<H256>,
    /// Nodes already offered to the dialer this cycle, cleared once the pool is
    /// exhausted so failed dials get another turn.
    already_tried_peers: FxHashSet<H256>,
    /// How many connections the consumer wants, used only to pace lookups.
    target_peers: usize,
}

// Hand-written because `Box<dyn PeerFilter>` is not `Debug`, and requiring that
// of every consumer's filter buys less than keeping the table printable.
impl std::fmt::Debug for ContactTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactTable")
            .field("local_node_id", &self.local_node_id)
            .field("connection_pool", &self.connection_pool)
            .field("sessions", &self.sessions)
            .field("connected", &self.connected)
            .field("already_tried_peers", &self.already_tried_peers)
            .field("target_peers", &self.target_peers)
            .finish_non_exhaustive()
    }
}

impl ContactTable {
    pub fn new(local_node_id: H256, target_peers: usize, filter: Box<dyn PeerFilter>) -> Self {
        Self {
            local_node_id,
            buckets: vec![KBucket::default(); NUMBER_OF_BUCKETS],
            connection_pool: IndexMap::with_capacity(MAX_CONNECTION_POOL_SIZE),
            sessions: Default::default(),
            filter,
            connected: Default::default(),
            already_tried_peers: Default::default(),
            target_peers,
        }
    }

    // --- Consumer lifecycle ---

    /// Record something that happened to the consumer's relationship with a peer.
    ///
    /// The single door through which the consumer reports anything about a
    /// peer; see [`PeerEvent`] for what each variant does and, more
    /// importantly, what it deliberately does not touch.
    pub fn record_peer_event(&mut self, node_id: H256, event: PeerEvent) {
        match event {
            PeerEvent::Connected => self.mark_connected(node_id),
            PeerEvent::Disconnected => self.mark_disconnected(&node_id),
            // A peer we are connected to is, demonstrably, wanted. This report
            // can only reach us for one while a second connection attempt to the
            // same node fails its handshake, and nothing dedupes those: a
            // transient error on the redundant attempt would otherwise mark a
            // peer we are happily syncing from as never-dial-again, permanently
            // and invisibly. The live connection is the better evidence.
            PeerEvent::Rejected if self.connected.contains(&node_id) => {
                tracing::debug!(
                    peer = %node_id,
                    "Ignoring rejection of a peer we are connected to"
                );
            }
            PeerEvent::Rejected => self.set_unwanted(&node_id),
        }
    }

    /// Record that the consumer is now connected to `node_id`, so it stops
    /// being offered as a dial candidate and counts towards lookup pacing.
    pub(crate) fn mark_connected(&mut self, node_id: H256) {
        self.connected.insert(node_id);
    }

    /// Record that the consumer's connection to `node_id` is gone.
    ///
    /// Deliberately leaves the discv5 session alone. The consumer's connection
    /// and the discovery session are separate conversations with the same node:
    /// an RLPx attempt that is rejected for having no capability we want says
    /// nothing about the discv5 keys, and tearing them down there would force a
    /// WHOAREYOU round trip to talk to a node we are still perfectly able to
    /// reach. Sessions go when the contact does, in [`Self::prune`].
    pub(crate) fn mark_disconnected(&mut self, node_id: &H256) {
        self.connected.remove(node_id);
    }

    /// How far along the consumer is towards the connection count it wants.
    /// Feeds the lookup interval: a node with no peers looks hard, a full one
    /// coasts.
    pub fn peer_completion(&self) -> f64 {
        if self.target_peers == 0 {
            return 1.0;
        }
        self.connected.len() as f64 / self.target_peers as f64
    }

    /// Backdates the last use of every stored session by `by`, so a test can drive the
    /// idle sweep in [`Self::prune`] without waiting out a real hour.
    #[cfg(test)]
    pub(crate) fn age_sessions_for_test(&mut self, by: Duration) {
        for (_, last_used) in self.sessions.values_mut() {
            *last_used -= by;
        }
    }

    // --- Sessions ---

    /// The discv5 session for a node, if one was ever negotiated.
    ///
    /// The standalone store is the only place a session lives. Contacts used to
    /// keep a second copy, which nothing needed and which outlived the
    /// disconnect cleanup below, so a session was never actually dropped for a
    /// node that still had a contact.
    pub fn session(&self, node_id: &H256) -> Option<Session> {
        self.sessions
            .get(node_id)
            .map(|(session, _)| session.clone())
    }

    /// Store a session, stamped as used now.
    ///
    /// The stamp is what [`Self::prune`] ages out. A re-handshake restamps it, and so
    /// does ordinary use through [`Self::touch_session`].
    pub fn set_session(&mut self, node_id: H256, session: Session) {
        self.sessions.insert(node_id, (session, Instant::now()));
    }

    /// Extend a session's life: it was just used to decrypt a packet that arrived from
    /// the address the session was established from.
    ///
    /// Only inbound, verified use counts. A send proves only that we still want the
    /// peer, so refreshing on one would keep alive the sessions of peers that never
    /// answer, which is the population the TTL exists to bound.
    ///
    /// Callers must refresh the matching `session_ips` entry in the same breath: keys
    /// that outlive their guard silently drop the IP-rebinding check in
    /// `discv5_handle_ordinary`, where a missing entry reads as nothing to compare
    /// against. Does nothing for a node with no stored session, so a packet racing
    /// [`Self::prune`] cannot resurrect one.
    pub fn touch_session(&mut self, node_id: &H256) {
        if let Some((_, last_used)) = self.sessions.get_mut(node_id) {
            *last_used = Instant::now();
        }
    }

    // --- Contact flags ---

    /// Mark a contact as one we should stop keeping: it failed to answer a ping,
    /// or the consumer found it useless. Pruned on the next [`Self::prune`].
    pub(crate) fn set_disposable(&mut self, node_id: &H256) {
        if let Some(contact) = self.get_contact_mut(node_id) {
            contact.disposable = true;
        }
    }

    /// Mark a contact as known-bad: on another network, no matching
    /// capabilities, or otherwise rejected by the consumer. Never dialed again.
    pub(crate) fn set_unwanted(&mut self, node_id: &H256) {
        if let Some(contact) = self.get_contact_mut(node_id) {
            contact.unwanted = true;
        }
    }

    /// Record that we answered this contact's ENR request, so it has a bond
    /// with us and is worth dialing.
    pub fn mark_knows_us(&mut self, node_id: &H256) {
        if let Some(contact) = self.get_contact_mut(node_id) {
            contact.knows_us = true;
        }
    }

    pub fn record_ping_sent(&mut self, node_id: &H256, ping_id: Bytes) {
        if let Some(contact) = self.get_contact_mut(node_id) {
            contact.record_ping_sent(ping_id);
        }
    }

    /// Clear the outstanding ping if `ping_id` is the one we are waiting on.
    pub fn record_pong_received(&mut self, node_id: &H256, ping_id: &Bytes) {
        if let Some(contact) = self.get_contact_mut(node_id)
            && contact
                .ping_id
                .as_ref()
                .map(|value| value == ping_id)
                .unwrap_or(false)
        {
            contact.ping_id = None;
        }
    }

    /// Insert a node discovered over `protocol`, returning whether it was new.
    ///
    /// Returns true for any genuinely new node, even if it overflows to the
    /// replacement list. This ensures the caller sends a reciprocal ping
    /// which establishes the bond needed for FindNode validation.
    pub async fn insert_if_new(&mut self, node: Node, protocol: DiscoveryProtocol) -> bool {
        let node_id = node.node_id();
        // Always add to the connection pool
        self.insert_to_connection_pool(node_id, node.clone());
        if self.contact_exists(&node_id) {
            return false;
        }
        let contact = Contact::new(node, protocol);
        self.insert_contact(node_id, contact);
        METRICS.record_new_discovery().await;
        true
    }

    // --- K-bucket accessors ---

    /// Get the bucket index for a node ID, or None if it's the local node.
    fn bucket_for(&self, node_id: &H256) -> Option<usize> {
        bucket_index(&self.local_node_id, node_id)
    }

    /// Look up a contact by node ID in main or replacement list (O(K) within the bucket).
    pub fn get_contact(&self, node_id: &H256) -> Option<&Contact> {
        let idx = self.bucket_for(node_id)?;
        self.buckets[idx].get_any(node_id)
    }

    /// Look up a mutable reference to a contact by node ID.
    pub(crate) fn get_contact_mut(&mut self, node_id: &H256) -> Option<&mut Contact> {
        let idx = self.bucket_for(node_id)?;
        self.buckets[idx].get_mut(node_id)
    }

    /// Check if a contact exists in any bucket (main or replacement list).
    fn contact_exists(&self, node_id: &H256) -> bool {
        let Some(idx) = self.bucket_for(node_id) else {
            return false;
        };
        self.buckets[idx].contains(node_id)
    }

    /// Insert a contact into the appropriate k-bucket. Returns true if inserted
    /// into the main list, false if the node went to the replacement list or is
    /// the local node.
    fn insert_contact(&mut self, node_id: H256, contact: Contact) -> bool {
        #[cfg(feature = "metrics")]
        let start = std::time::Instant::now();

        let Some(idx) = self.bucket_for(&node_id) else {
            return false;
        };
        let result = self.buckets[idx].insert(node_id, contact);

        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.observe_insert_contact_duration(start.elapsed().as_secs_f64());
        }

        result
    }

    /// Insert a node into the flat connection pool for RLPx initiation.
    /// Evicts the oldest entry when the pool is at capacity.
    fn insert_to_connection_pool(&mut self, node_id: H256, node: Node) {
        if self.connection_pool.contains_key(&node_id) {
            return;
        }
        if self.connection_pool.len() >= MAX_CONNECTION_POOL_SIZE {
            self.connection_pool.shift_remove_index(0);
        }
        self.connection_pool.insert(node_id, node);
    }

    /// Look up a contact by node ID in either the main or replacement list.
    fn get_contact_or_replacement(&self, node_id: &H256) -> Option<&Contact> {
        let idx = self.bucket_for(node_id)?;
        self.buckets[idx].get_any(node_id)
    }

    /// Look up a mutable reference in either the main or replacement list.
    fn get_contact_or_replacement_mut(&mut self, node_id: &H256) -> Option<&mut Contact> {
        let idx = self.bucket_for(node_id)?;
        let bucket = &mut self.buckets[idx];
        // Search main list first, then replacement list.
        // Done inline to avoid borrow-checker issues with or_else closures.
        if let Some(pos) = bucket.contacts.iter().position(|(id, _)| id == node_id) {
            return Some(&mut bucket.contacts[pos].1);
        }
        if let Some(pos) = bucket.replacements.iter().position(|(id, _)| id == node_id) {
            return Some(&mut bucket.replacements[pos].1);
        }
        None
    }

    /// Iterate over all contacts across all buckets (main and replacement lists).
    fn iter_contacts(&self) -> impl Iterator<Item = (&H256, &Contact)> {
        self.buckets.iter().flat_map(|bucket| {
            bucket
                .contacts
                .iter()
                .chain(bucket.replacements.iter())
                .map(|(id, c)| (id, c))
        })
    }

    // --- Contact operations ---

    /// Prune disposable contacts from both main and replacement lists.
    /// When a main contact is removed, a replacement is automatically promoted.
    /// Pruned contacts remain in the connection pool so they can be retried
    /// later: the consumer will reject them on connecting if they are truly bad.
    ///
    /// Dropping a contact drops its discv5 session too, and any session left unused for
    /// [`SESSION_TTL`] goes with it.
    ///
    /// The idle sweep is what actually bounds the store. Pruning by contact is not
    /// enough on its own: a contact can leave the table without ever being marked
    /// disposable (evicted from a replacement queue, or simply never pruned because
    /// it was only ever marked `unwanted`), and a session can be stored for a node
    /// whose ENR never parsed into a contact at all. Both leave an entry that the
    /// contact-driven path can no longer reach, and a peer can create them as fast
    /// as the WHOAREYOU rate limit allows.
    pub fn prune(&mut self) {
        let mut pruned: Vec<H256> = Vec::new();
        for bucket in &mut self.buckets {
            // Collect disposable contacts from main list
            let main_disposable: Vec<H256> = bucket
                .contacts
                .iter()
                .filter(|(_, c)| c.disposable)
                .map(|(id, _)| *id)
                .collect();

            // Remove from main list and promote replacements
            for node_id in main_disposable {
                bucket.remove_and_promote(&node_id);
                pruned.push(node_id);
            }

            // Remove disposable contacts from replacement list
            // (these don't get promoted, just removed)
            bucket.replacements.retain(|(id, c)| {
                if c.disposable {
                    pruned.push(*id);
                }
                !c.disposable
            });
        }
        for node_id in pruned {
            self.sessions.remove(&node_id);
        }

        let now = Instant::now();
        self.sessions
            .retain(|_, (_, last_used)| now.saturating_duration_since(*last_used) < SESSION_TTL);
    }

    /// Pick the next node to hand to the RLPx dialer, or `None` when the pool
    /// holds nothing worth trying right now.
    ///
    /// Draws from the flat connection pool using O(1) random index probing:
    /// pick a random start index and scan forward (wrapping) until an eligible
    /// candidate turns up or the pool is exhausted.
    ///
    /// Skips anything already connected, anything tried since the last reset,
    /// and any contact that is unwanted, does not know us, or failed the
    /// consumer's [`PeerFilter`].
    pub fn next_dial_candidate(&mut self) -> Option<Node> {
        let pool_len = self.connection_pool.len();
        if pool_len == 0 {
            return None;
        }

        let start = rand::random::<usize>() % pool_len;
        for offset in 0..pool_len {
            let idx = (start + offset) % pool_len;
            let Some((node_id, pool_node)) = self.connection_pool.get_index(idx) else {
                continue;
            };
            let node_id = *node_id;

            // Two set lookups before the bucket walk: on the pass that clears
            // `already_tried_peers` every entry is rejected here, and doing the
            // O(k) bucket scan first would turn that into a full walk of the pool
            // inside the loop that also has to drain UDP.
            if self.connected.contains(&node_id) || self.already_tried_peers.contains(&node_id) {
                continue;
            }

            let contact = self.get_contact_or_replacement(&node_id);
            if contact
                .map(|c| !c.knows_us || c.unwanted || c.passes_filter == Some(false))
                .unwrap_or(false)
            {
                continue;
            }

            // The contact's endpoint wins over the pool's. A pool entry is
            // written on first sight and never refreshed, so for a node first
            // heard of over an unauthenticated discv4 Neighbors packet it can
            // hold a wrong or zero TCP port forever, while the contact tracks
            // whatever the newest signed ENR says. Falls back to the pool for
            // an id the k-buckets have already evicted.
            let node = contact.map_or_else(|| pool_node.clone(), |c| c.node.clone());
            self.already_tried_peers.insert(node_id);
            return Some(node);
        }

        // Exhausted all candidates — reset tried set for next cycle.
        tracing::trace!("Resetting list of tried peers.");
        self.already_tried_peers.clear();
        None
    }

    /// Get the `count` closest nodes from the connection pool, sorted by XOR distance to `target`.
    pub fn closest_from_pool(&self, target: H256, count: usize) -> Vec<(H256, Node)> {
        let mut nodes: Vec<(H256, Node, H256)> = Vec::with_capacity(count);

        for (node_id, node) in &self.connection_pool {
            let dist = xor_distance(&target, node_id);
            if nodes.len() < count {
                nodes.push((*node_id, node.clone(), dist));
            } else if let Some((farthest_idx, _)) =
                nodes.iter().enumerate().max_by_key(|(_, (_, _, d))| *d)
                && dist < nodes[farthest_idx].2
            {
                nodes[farthest_idx] = (*node_id, node.clone(), dist);
            }
        }

        nodes.sort_by(|a, b| a.2.cmp(&b.2));
        nodes.into_iter().map(|(id, node, _)| (id, node)).collect()
    }

    /// Get contact for ENR lookup (discv4 only)
    pub fn contact_for_enr_lookup(&mut self) -> Option<Contact> {
        self.iter_contacts()
            .filter(|(_, c)| {
                c.is_discv4
                    && c.was_validated()
                    && !c.has_pending_enr_request()
                    && c.record.is_none()
                    && !c.disposable
            })
            .map(|(_, c)| c)
            .collect::<Vec<_>>()
            .choose(&mut rand::rngs::OsRng)
            .cloned()
            .cloned()
    }

    pub fn contact_to_revalidate(
        &self,
        revalidation_interval: Duration,
        protocol: DiscoveryProtocol,
    ) -> Option<Box<Contact>> {
        self.iter_contacts()
            .filter(|(_, c)| {
                c.supports_protocol(protocol)
                    && Self::is_validation_needed(c, revalidation_interval)
            })
            .map(|(_, c)| c)
            .choose(&mut rand::rngs::OsRng)
            .cloned()
            .map(Box::new)
    }

    pub fn validate_contact(&self, node_id: H256, sender_ip: IpAddr) -> ContactValidation {
        let Some(contact) = self.get_contact(&node_id) else {
            return ContactValidation::UnknownContact;
        };
        if !contact.was_validated() {
            return ContactValidation::InvalidContact;
        }

        // Check that the IP address from which we receive the request matches the one we have stored
        // to prevent amplification attacks.
        if sender_ip != contact.node.ip {
            return ContactValidation::IpMismatch;
        }
        ContactValidation::Valid(Box::new(contact.clone()))
    }

    /// Get closest nodes using raw XOR distance for accurate ordering.
    pub fn closest_nodes(&self, node_id: H256) -> Vec<Node> {
        #[cfg(feature = "metrics")]
        let scan_start = std::time::Instant::now();

        let mut nodes: Vec<(Node, H256)> = vec![];

        for (contact_id, contact) in self.iter_contacts() {
            let dist = xor_distance(&node_id, contact_id);
            if nodes.len() < MAX_NODES_IN_NEIGHBORS_PACKET {
                nodes.push((contact.node.clone(), dist));
            } else if let Some((farthest_idx, _)) =
                nodes.iter().enumerate().max_by_key(|(_, (_, d))| *d)
                && dist < nodes[farthest_idx].1
            {
                nodes[farthest_idx] = (contact.node.clone(), dist);
            }
        }

        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.observe_iter_contacts_duration(scan_start.elapsed().as_secs_f64());
        }

        nodes.into_iter().map(|(node, _)| node).collect()
    }

    /// Get nodes at distances for discv5 (returns Vec<NodeRecord>).
    /// Uses the discv5 spec log-distance: `floor(log2(XOR))` for non-zero XOR.
    /// Distance 0 is reserved for the local node itself (handled by the caller),
    /// so contacts start at distance >= 1.
    pub fn nodes_at_distances(&self, distances: &[u32]) -> Vec<NodeRecord> {
        self.iter_contacts()
            .filter_map(|(contact_id, contact)| {
                let dist = distance(&self.local_node_id, contact_id) as u32;
                if distances.contains(&dist) {
                    contact.record.clone()
                } else {
                    None
                }
            })
            .take(MAX_ENRS_PER_FINDNODE_RESPONSE)
            .collect()
    }

    pub async fn new_contacts(&mut self, nodes: Vec<Node>, protocol: DiscoveryProtocol) {
        for node in nodes {
            let node_id = node.node_id();
            if node_id == self.local_node_id {
                continue;
            }
            #[cfg(feature = "metrics")]
            let insert_start = std::time::Instant::now();

            // Always add to the connection pool (regardless of k-bucket capacity)
            self.insert_to_connection_pool(node_id, node.clone());

            if self.contact_exists(&node_id) {
                // Contact already exists (main or replacement list), update protocol
                if let Some(contact) = self.get_contact_or_replacement_mut(&node_id) {
                    contact.add_protocol(protocol);
                }
            } else {
                let contact = Contact::new(node, protocol);
                self.insert_contact(node_id, contact);
                METRICS.record_new_discovery().await;
            }

            #[cfg(feature = "metrics")]
            {
                use ethrex_metrics::p2p::METRICS_P2P;
                METRICS_P2P.observe_insert_contact_duration(insert_start.elapsed().as_secs_f64());
            }
        }
    }

    pub fn record_enr_request_sent(&mut self, node_id: H256, request_hash: H256) {
        if let Some(contact) = self.get_contact_mut(&node_id) {
            contact.record_enr_request_sent(request_hash);
        }
    }

    pub fn record_enr_response_received(
        &mut self,
        node_id: H256,
        request_hash: H256,
        record: NodeRecord,
    ) {
        // Filtered here, before the mutable borrow, so a record that reaches us
        // over discv4 is judged by the same filter as one that arrives over
        // discv5. The verdict is recorded only if the record was actually
        // stored, so it always describes the record the contact holds.
        let passes_filter = self.filter.accepts(&record);
        if let Some(contact) = self.get_contact_mut(&node_id)
            && contact.record_enr_response_received(request_hash, record)
        {
            contact.passes_filter = Some(passes_filter);
        }
    }

    pub async fn new_contact_records(&mut self, node_records: Vec<NodeRecord>) {
        for node_record in node_records {
            if !node_record.verify_signature() {
                continue;
            }
            if let Ok(node) = Node::from_enr(&node_record) {
                let node_id = node.node_id();
                if node_id == self.local_node_id {
                    continue;
                }

                // Always add to the connection pool (regardless of k-bucket capacity)
                self.insert_to_connection_pool(node_id, node.clone());

                if self.contact_exists(&node_id) {
                    // Check if we need to evaluate fork_id before taking
                    // the mutable borrow.
                    let should_update = self
                        .get_contact_or_replacement(&node_id)
                        .map(|c| match c.record.as_ref() {
                            None => true,
                            Some(r) => node_record.seq > r.seq,
                        })
                        .unwrap_or(false);
                    // Filtered here, before the mutable borrow, and only when
                    // the record is newer than the one we already hold.
                    let passes_filter = should_update.then(|| self.filter.accepts(&node_record));
                    if let Some(contact) = self.get_contact_or_replacement_mut(&node_id) {
                        contact.add_protocol(DiscoveryProtocol::Discv5);
                        if should_update {
                            if contact.node.ip != node.ip || contact.node.udp_port != node.udp_port
                            {
                                contact.validation_timestamp = None;
                                contact.ping_id = None;
                            }
                            contact.node = node;
                            contact.record = Some(node_record);
                            contact.passes_filter = passes_filter;
                        }
                    }
                } else {
                    let passes_filter = self.filter.accepts(&node_record);
                    let mut contact = Contact::new(node, DiscoveryProtocol::Discv5);
                    contact.passes_filter = Some(passes_filter);
                    contact.record = Some(node_record);
                    self.insert_contact(node_id, contact);
                    METRICS.record_new_discovery().await;
                }
            }
        }
    }

    fn is_validation_needed(contact: &Contact, revalidation_interval: Duration) -> bool {
        if contact.disposable {
            return false;
        }

        let sent_ping_ttl = Duration::from_secs(30);

        if contact.has_pending_ping() {
            // Outstanding ping — only re-ping if it timed out (stale).
            contact
                .validation_timestamp
                .map(|ts| Instant::now().saturating_duration_since(ts) > sent_ping_ttl)
                .unwrap_or(false)
        } else {
            // No pending ping — check if never validated or validation expired.
            !contact.was_validated()
                || contact
                    .validation_timestamp
                    .map(|ts| Instant::now().saturating_duration_since(ts) > revalidation_interval)
                    .unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeRecordPairs;
    use ethrex_common::H512;
    use std::net::Ipv4Addr;

    /// Helper: build a dummy contact with a unique node derived from `seed`.
    fn dummy_contact(seed: u8) -> (H256, Contact) {
        let pk = H512::from_low_u64_be(seed as u64 + 1);
        let node = Node::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, seed)), 30303, 30303, pk);
        let node_id = node.node_id();
        let contact = Contact::new(node, DiscoveryProtocol::Discv4);
        (node_id, contact)
    }

    /// A filter with a fixed answer, so peer-table behaviour can be exercised
    /// without a storage engine or a real chain behind it.
    struct FixedAnswer(bool);

    impl PeerFilter for FixedAnswer {
        fn accepts(&self, _record: &NodeRecord) -> bool {
            self.0
        }
    }

    fn table_with(filter: impl PeerFilter + 'static) -> ContactTable {
        ContactTable::new(H256::zero(), 10, Box::new(filter))
    }

    /// Session keys whose values are irrelevant; only presence is asserted.
    fn session() -> Session {
        Session {
            outbound_key: [1; 16],
            inbound_key: [2; 16],
        }
    }

    /// A signed record for `seed`'s node at sequence number `seq`.
    fn record_for(seed: u8, seq: u64) -> (H256, NodeRecord) {
        let signer = secp256k1::SecretKey::from_slice(&[seed.max(1); 32]).unwrap();
        let record = NodeRecord::from_pairs(
            seq,
            &signer,
            NodeRecordPairs {
                ip: Some(Ipv4Addr::new(127, 0, 0, seed)),
                udp_port: Some(30303),
                ..Default::default()
            },
        )
        .unwrap();
        (Node::from_enr(&record).unwrap().node_id(), record)
    }

    // --- the filter decides which contacts are dialable ---

    #[tokio::test]
    async fn an_arriving_record_is_run_through_the_filter() {
        let mut table = table_with(FixedAnswer(false));
        let (node_id, record) = record_for(1, 1);

        table.new_contact_records(vec![record]).await;

        let contact = table.get_contact(&node_id).expect("contact inserted");
        assert_eq!(contact.passes_filter, Some(false));
    }

    #[tokio::test]
    async fn a_rejected_contact_is_never_offered_for_dialing() {
        let mut table = table_with(FixedAnswer(false));
        let (node_id, record) = record_for(2, 1);

        table.new_contact_records(vec![record]).await;
        assert!(table.get_contact(&node_id).is_some(), "contact is present");

        assert!(
            table.next_dial_candidate().is_none(),
            "a rejected contact must not be handed out to dial"
        );
    }

    #[tokio::test]
    async fn an_accepted_contact_is_offered_for_dialing() {
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(3, 1);

        table.new_contact_records(vec![record]).await;

        // Asserting the stored answer too, not just dialability: `None` is also
        // dialable, so `is_some()` alone would pass even if the filter never ran.
        assert_eq!(
            table.get_contact(&node_id).unwrap().passes_filter,
            Some(true)
        );
        assert!(table.next_dial_candidate().is_some());
    }

    #[tokio::test]
    async fn a_contact_discovered_without_a_record_is_never_filtered() {
        // Bootnodes and discv4 neighbours arrive as bare endpoints. They have
        // published nothing to judge, so they must stay dialable rather than be
        // written off by a filter that never saw them.
        let mut table = table_with(FixedAnswer(false));
        let (node_id, record) = record_for(6, 1);
        let node = Node::from_enr(&record).unwrap();

        table
            .new_contacts(vec![node], DiscoveryProtocol::Discv4)
            .await;

        assert_eq!(table.get_contact(&node_id).unwrap().passes_filter, None);
        assert!(table.next_dial_candidate().is_some());
    }

    #[tokio::test]
    async fn a_discv4_enr_response_is_run_through_the_filter() {
        // The discv4 path used to bypass the filter entirely and write a
        // hardcoded fork-id verdict into the same field, so a consumer's own
        // policy was overridden depending on which protocol found the peer.
        let mut table = table_with(FixedAnswer(false));
        let (node_id, record) = record_for(7, 1);
        let node = Node::from_enr(&record).unwrap();
        let request_hash = H256::repeat_byte(0xab);

        table
            .new_contacts(vec![node], DiscoveryProtocol::Discv4)
            .await;
        table.record_enr_request_sent(node_id, request_hash);
        table.record_enr_response_received(node_id, request_hash, record);

        assert_eq!(
            table.get_contact(&node_id).unwrap().passes_filter,
            Some(false)
        );
    }

    #[tokio::test]
    async fn an_unsolicited_enr_response_does_not_set_the_verdict() {
        // The record is not stored when the hash does not match, so recording a
        // verdict from it would let a peer restate its own standing from a
        // record the table refused to keep.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(8, 1);
        let node = Node::from_enr(&record).unwrap();

        table
            .new_contacts(vec![node], DiscoveryProtocol::Discv4)
            .await;
        table.record_enr_request_sent(node_id, H256::repeat_byte(0x01));
        table.record_enr_response_received(node_id, H256::repeat_byte(0x02), record);

        let contact = table.get_contact(&node_id).unwrap();
        assert_eq!(contact.passes_filter, None);
        assert!(contact.record.is_none(), "the record must not be stored");
    }

    /// Rejects the first record it is shown and accepts every later one, so a
    /// test can tell whether a second record was filtered at all.
    #[derive(Default)]
    struct AcceptsFromTheSecondRecordOn(std::sync::atomic::AtomicUsize);

    impl PeerFilter for AcceptsFromTheSecondRecordOn {
        fn accepts(&self, _record: &NodeRecord) -> bool {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
        }
    }

    #[tokio::test]
    async fn a_rejection_is_reconsidered_on_a_newer_record() {
        // The reason a rejection is stored rather than acted on once: the peer
        // republishes and we look again, instead of writing it off for the life
        // of the process over a fork id read against a head we had not synced.
        let mut table = table_with(AcceptsFromTheSecondRecordOn::default());
        let (node_id, first) = record_for(4, 1);
        let (_, newer) = record_for(4, 2);

        table.new_contact_records(vec![first]).await;
        assert_eq!(
            table.get_contact(&node_id).unwrap().passes_filter,
            Some(false)
        );

        table.new_contact_records(vec![newer]).await;
        assert_eq!(
            table.get_contact(&node_id).unwrap().passes_filter,
            Some(true),
            "a higher-seq record must get a fresh hearing"
        );
    }

    #[tokio::test]
    async fn an_older_record_does_not_re_filter_the_contact() {
        // `should_update` false means the record has nothing new to say, so the
        // answer already on the contact has to survive it.
        let mut table = table_with(AcceptsFromTheSecondRecordOn::default());
        let (node_id, first) = record_for(5, 2);
        let (_, older) = record_for(5, 1);

        table.new_contact_records(vec![first]).await;
        table.new_contact_records(vec![older]).await;

        assert_eq!(
            table.get_contact(&node_id).unwrap().passes_filter,
            Some(false),
            "a stale record must not overwrite the answer we hold"
        );
    }

    // --- Consumer lifecycle ---

    #[tokio::test]
    async fn a_connected_contact_is_not_offered_for_dialing_again() {
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(9, 1);

        table.new_contact_records(vec![record]).await;
        table.mark_connected(node_id);

        assert!(
            table.next_dial_candidate().is_none(),
            "a node the consumer is already connected to must not be dialed again"
        );
    }

    #[tokio::test]
    async fn a_disconnected_contact_becomes_dialable_again() {
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(10, 1);

        table.new_contact_records(vec![record]).await;
        table.mark_connected(node_id);
        table.mark_disconnected(&node_id);

        assert_eq!(
            table.next_dial_candidate().map(|n| n.node_id()),
            Some(node_id)
        );
    }

    #[tokio::test]
    async fn disconnecting_leaves_the_discv5_session_alone() {
        // An RLPx teardown is not a discovery event. Dropping the keys here
        // would force a WHOAREYOU round trip on a node we can still reach, and
        // it fires on connections that were rejected before they ever carried
        // traffic.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(11, 1);

        table.new_contact_records(vec![record]).await;
        table.set_session(node_id, session());

        table.mark_disconnected(&node_id);

        assert!(table.session(&node_id).is_some());
    }

    #[tokio::test]
    async fn pruning_a_contact_drops_its_discv5_session() {
        // What actually bounds the session store: without this it grows by one
        // entry per handshake for the life of the process.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(14, 1);

        table.new_contact_records(vec![record]).await;
        table.set_session(node_id, session());
        table.set_disposable(&node_id);

        table.prune();

        assert!(table.get_contact(&node_id).is_none(), "contact is pruned");
        assert!(
            table.session(&node_id).is_none(),
            "its session goes with it"
        );
    }

    #[tokio::test]
    async fn a_session_outlives_neither_its_ttl_nor_a_node_it_was_never_matched_to() {
        // The store's real bound. A session can be reached by neither the
        // contact-driven path nor anything else: this one belongs to a node id
        // that never became a contact at all, which is the documented reason the
        // store is standalone. Only age can reclaim it.
        let mut table = table_with(FixedAnswer(true));
        let orphan = H256::repeat_byte(0x5e);

        table.set_session(orphan, session());
        table.prune();
        assert!(
            table.session(&orphan).is_some(),
            "a fresh session must survive a prune"
        );

        table.age_sessions_for_test(SESSION_TTL);
        table.prune();

        assert!(
            table.session(&orphan).is_none(),
            "an aged session is reaped"
        );
    }

    #[tokio::test]
    async fn using_a_session_keeps_it_out_of_the_idle_sweep() {
        // Why the sweep is idle-based: a peer we are still talking to must not be
        // made to re-handshake mid-conversation. That costs a WHOAREYOU round trip
        // and loses the message that triggered it if the exchange is slow.
        let mut table = table_with(FixedAnswer(true));
        let node_id = H256::repeat_byte(0x7a);

        table.set_session(node_id, session());
        table.age_sessions_for_test(SESSION_TTL);
        table.touch_session(&node_id);
        table.prune();

        assert!(
            table.session(&node_id).is_some(),
            "a session used inside the TTL survives the sweep"
        );
    }

    #[tokio::test]
    async fn touching_a_reaped_session_does_not_resurrect_it() {
        // `touch_session` runs for every packet that decrypts, which includes one
        // that raced `prune`. Inserting here would defeat the bound entirely, since
        // the keys are gone and nothing could decrypt with the entry anyway.
        let mut table = table_with(FixedAnswer(true));
        let node_id = H256::repeat_byte(0x7b);

        table.touch_session(&node_id);

        assert!(table.session(&node_id).is_none());
    }

    #[tokio::test]
    async fn pruning_reaches_a_contact_in_the_replacement_list() {
        // The replacement half of `prune` had no coverage: dropping the
        // `pruned.push` inside `retain` left every test green.
        let mut table = table_with(FixedAnswer(true));

        // Fill one bucket's main list so the next arrival becomes a replacement.
        let (target_id, _) = dummy_contact(1);
        let bucket = bucket_index(&table.local_node_id, &target_id).expect("not the local node");
        let mut overflow = Vec::new();
        for seed in 0..u8::MAX {
            let (id, contact) = dummy_contact(seed);
            if bucket_index(&table.local_node_id, &id) == Some(bucket) {
                overflow.push(id);
                table.insert_contact(id, contact);
                if overflow.len() > MAX_NODES_PER_BUCKET {
                    break;
                }
            }
        }
        let replacement = *overflow.last().expect("a contact overflowed the bucket");
        assert!(
            table.buckets[bucket]
                .replacements
                .iter()
                .any(|(id, _)| *id == replacement),
            "the last insert landed in the replacement list"
        );

        table.set_session(replacement, session());
        table.set_disposable(&replacement);
        table.prune();

        assert!(table.get_contact(&replacement).is_none());
        assert!(
            table.session(&replacement).is_none(),
            "a replacement-list contact takes its session with it"
        );
    }

    #[tokio::test]
    async fn a_pooled_node_with_no_contact_is_still_dialable() {
        // The fallback arm of `next_dial_candidate`. Contacts get pruned out of the
        // buckets while their pool entry stays, and those nodes must still be
        // offered, or a prune would quietly retire them.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(16, 1);

        table.new_contact_records(vec![record]).await;
        table.set_disposable(&node_id);
        table.prune();
        assert!(table.get_contact(&node_id).is_none(), "contact is gone");

        assert_eq!(
            table.next_dial_candidate().map(|n| n.node_id()),
            Some(node_id),
            "the pool entry is the fallback, and it is still dialable"
        );
    }

    #[tokio::test]
    async fn a_dial_candidate_uses_the_endpoint_from_the_newest_record() {
        // The connection pool is written on first sight and never refreshed, so
        // a node first heard of over an unauthenticated discv4 Neighbors packet
        // sits there with whatever port that packet claimed. Dialing the pool
        // entry rather than the contact would keep hammering that address after
        // the node published a signed ENR correcting it.
        let mut table = table_with(FixedAnswer(true));
        let signer = secp256k1::SecretKey::from_slice(&[15; 32]).unwrap();
        let record = NodeRecord::from_pairs(
            2,
            &signer,
            NodeRecordPairs {
                ip: Some(Ipv4Addr::new(127, 0, 0, 15)),
                udp_port: Some(30303),
                tcp_port: Some(30303),
                ..Default::default()
            },
        )
        .unwrap();
        let announced = Node::from_enr(&record).unwrap();
        let node_id = announced.node_id();

        // First sighting: a bare endpoint with the wrong TCP port.
        let stale = Node::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 15)),
            30303,
            0,
            announced.public_key,
        );
        table
            .new_contacts(vec![stale], DiscoveryProtocol::Discv4)
            .await;
        // Then the signed record, which corrects it.
        table.new_contact_records(vec![record]).await;

        let candidate = table.next_dial_candidate().expect("a candidate");
        assert_eq!(candidate.node_id(), node_id);
        assert_eq!(
            candidate.tcp_port, 30303,
            "the dialer must get the endpoint from the newest record, not the first sighting"
        );
    }

    #[tokio::test]
    async fn a_candidate_is_offered_once_per_cycle() {
        // `already_tried_peers` is what stops a failed dial from being retried
        // immediately, and it has to clear once the pool is exhausted or a peer
        // that failed once would never be tried again.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(12, 1);

        table.new_contact_records(vec![record]).await;

        assert_eq!(
            table.next_dial_candidate().map(|n| n.node_id()),
            Some(node_id)
        );
        assert!(
            table.next_dial_candidate().is_none(),
            "the same candidate must not be handed out twice in one cycle"
        );
        assert_eq!(
            table.next_dial_candidate().map(|n| n.node_id()),
            Some(node_id),
            "the exhausted cycle resets, so the candidate comes back around"
        );
    }

    #[tokio::test]
    async fn a_connected_peer_is_never_rejected() {
        // Connected-and-rejected is a contradiction, and it was reachable: two
        // connection actors can race for one node id, and a transient handshake
        // error on the loser would permanently retire a peer the winner is
        // syncing from. The live connection outranks the verdict.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(17, 1);

        table.new_contact_records(vec![record]).await;
        table.record_peer_event(node_id, PeerEvent::Connected);
        table.record_peer_event(node_id, PeerEvent::Rejected);

        assert_eq!(table.peer_completion(), 0.1, "still connected");
        table.record_peer_event(node_id, PeerEvent::Disconnected);
        assert_eq!(
            table.next_dial_candidate().map(|n| n.node_id()),
            Some(node_id),
            "and still dialable once it disconnects: the verdict never landed"
        );
    }

    #[tokio::test]
    async fn a_rejection_lands_when_the_peer_is_not_connected() {
        // The guard must not swallow the rejection it exists to record.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(19, 1);

        table.new_contact_records(vec![record]).await;
        table.record_peer_event(node_id, PeerEvent::Rejected);

        assert!(
            table.next_dial_candidate().is_none(),
            "a peer rejected while disconnected is never dialed"
        );
    }

    #[tokio::test]
    async fn disconnecting_leaves_earlier_verdicts_standing() {
        // The other half of the same rule: verdicts accumulate, so a later
        // disconnection must not quietly rehabilitate a peer we rejected.
        let mut table = table_with(FixedAnswer(true));
        let (node_id, record) = record_for(18, 1);

        // The verdict has to be recorded while disconnected, since a connected
        // peer's verdict is ignored outright.
        table.new_contact_records(vec![record]).await;
        table.record_peer_event(node_id, PeerEvent::Rejected);
        table.record_peer_event(node_id, PeerEvent::Connected);
        table.record_peer_event(node_id, PeerEvent::Disconnected);

        assert_eq!(table.peer_completion(), 0.0, "no longer connected");
        assert!(
            table.next_dial_candidate().is_none(),
            "but still unwanted, so still never dialed"
        );
    }

    #[test]
    fn peer_completion_tracks_the_connected_count() {
        let mut table = table_with(FixedAnswer(true));
        assert_eq!(table.peer_completion(), 0.0);

        for seed in 0..5u8 {
            table.mark_connected(H256::from_low_u64_be(seed as u64 + 1));
        }

        // `table_with` targets 10 peers.
        assert_eq!(table.peer_completion(), 0.5);
    }

    #[test]
    fn peer_completion_is_complete_when_nothing_is_wanted() {
        // A consumer that asks for no peers is always done, and must not divide
        // by zero to find that out.
        let table = ContactTable::new(H256::zero(), 0, Box::new(FixedAnswer(true)));
        assert_eq!(table.peer_completion(), 1.0);
    }

    // --- KBucket::insert ---

    #[test]
    fn insert_into_empty_bucket() {
        let mut bucket = KBucket::default();
        let (id, contact) = dummy_contact(1);
        assert!(bucket.insert(id, contact));
        assert_eq!(bucket.contacts.len(), 1);
        assert!(bucket.replacements.is_empty());
    }

    #[test]
    fn insert_fills_bucket_then_goes_to_replacements() {
        let mut bucket = KBucket::default();

        // Fill the main list to capacity.
        for i in 0..MAX_NODES_PER_BUCKET as u8 {
            let (id, contact) = dummy_contact(i);
            assert!(bucket.insert(id, contact), "contact {i} should go to main");
        }
        assert_eq!(bucket.contacts.len(), MAX_NODES_PER_BUCKET);

        // The next insert should go to the replacement list.
        let (id, contact) = dummy_contact(200);
        assert!(!bucket.insert(id, contact));
        assert_eq!(bucket.contacts.len(), MAX_NODES_PER_BUCKET);
        assert_eq!(bucket.replacements.len(), 1);
    }

    // --- KBucket::contains ---

    #[test]
    fn contains_checks_main_and_replacement() {
        let mut bucket = KBucket::default();

        let (id_main, contact_main) = dummy_contact(1);
        bucket.insert(id_main, contact_main);
        assert!(bucket.contains(&id_main));

        // Fill bucket so next goes to replacement.
        for i in 2..=(MAX_NODES_PER_BUCKET as u8) {
            let (id, c) = dummy_contact(i);
            bucket.insert(id, c);
        }
        let (id_repl, contact_repl) = dummy_contact(100);
        bucket.insert(id_repl, contact_repl);

        assert!(bucket.contains(&id_repl));
        assert!(!bucket.contains(&H256::zero()));
    }

    // --- KBucket::get / get_any ---

    #[test]
    fn get_returns_main_list_only() {
        let mut bucket = KBucket::default();
        let (id, contact) = dummy_contact(1);
        bucket.insert(id, contact);
        assert!(bucket.get(&id).is_some());
        assert!(bucket.get(&H256::zero()).is_none());
    }

    #[test]
    fn get_any_returns_from_replacement() {
        let mut bucket = KBucket::default();
        // Fill main list.
        for i in 0..MAX_NODES_PER_BUCKET as u8 {
            let (id, c) = dummy_contact(i);
            bucket.insert(id, c);
        }
        // Insert into replacements.
        let (id_repl, c_repl) = dummy_contact(200);
        bucket.insert(id_repl, c_repl);

        assert!(bucket.get(&id_repl).is_none()); // not in main
        assert!(bucket.get_any(&id_repl).is_some()); // found via replacement
    }

    // --- KBucket::remove_and_promote ---

    #[test]
    fn remove_and_promote_with_replacement() {
        let mut bucket = KBucket::default();

        // Fill main list.
        let mut main_ids = Vec::new();
        for i in 0..MAX_NODES_PER_BUCKET as u8 {
            let (id, c) = dummy_contact(i);
            main_ids.push(id);
            bucket.insert(id, c);
        }

        // Add a replacement.
        let (repl_id, repl_contact) = dummy_contact(200);
        bucket.insert(repl_id, repl_contact);

        // Remove a main contact — the replacement should be promoted.
        let promoted = bucket.remove_and_promote(&main_ids[0]);
        assert_eq!(promoted, Some(repl_id));
        assert_eq!(bucket.contacts.len(), MAX_NODES_PER_BUCKET);
        assert!(bucket.replacements.is_empty());
        assert!(!bucket.contains(&main_ids[0]));
        assert!(bucket.contains(&repl_id));
    }

    #[test]
    fn remove_and_promote_without_replacement() {
        let mut bucket = KBucket::default();
        let (id, c) = dummy_contact(1);
        bucket.insert(id, c);

        let promoted = bucket.remove_and_promote(&id);
        assert!(promoted.is_none());
        assert!(bucket.contacts.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut bucket = KBucket::default();
        assert!(bucket.remove_and_promote(&H256::zero()).is_none());
    }

    // --- Replacement eviction ---

    #[test]
    fn replacement_list_evicts_oldest_when_full() {
        let mut bucket = KBucket::default();
        // Fill main list.
        for i in 0..MAX_NODES_PER_BUCKET as u8 {
            let (id, c) = dummy_contact(i);
            bucket.insert(id, c);
        }

        // Fill replacement list beyond capacity.
        let mut repl_ids = Vec::new();
        for i in 0..(MAX_REPLACEMENTS_PER_BUCKET + 2) as u8 {
            let seed = 100 + i;
            let (id, c) = dummy_contact(seed);
            repl_ids.push(id);
            bucket.insert(id, c);
        }

        assert_eq!(bucket.replacements.len(), MAX_REPLACEMENTS_PER_BUCKET);
        // The oldest two should have been evicted.
        assert!(!bucket.contains(&repl_ids[0]));
        assert!(!bucket.contains(&repl_ids[1]));
        // The most recent ones should still be there.
        assert!(bucket.contains(repl_ids.last().unwrap()));
    }

    // --- bucket_index ---

    #[test]
    fn bucket_index_self_is_none() {
        let id = H256::random();
        assert_eq!(bucket_index(&id, &id), None);
    }

    #[test]
    fn bucket_index_minimal_distance() {
        let local = H256::zero();
        // XOR distance = 1 → highest bit is bit 0 → bucket 0
        let mut remote = H256::zero();
        remote.0[31] = 1;
        assert_eq!(bucket_index(&local, &remote), Some(0));
    }

    #[test]
    fn bucket_index_maximal_distance() {
        let local = H256::zero();
        // XOR distance has highest bit at position 255 → bucket 255
        let mut remote = H256::zero();
        remote.0[0] = 0x80;
        assert_eq!(bucket_index(&local, &remote), Some(255));
    }
}
