use crate::discovery::lookup::IterativeLookup;
use crate::discv5::messages::Message;
use crate::{
    discv5::messages::Packet,
    types::{Node, NodeRecord},
};
use bytes::Bytes;
use ethrex_common::H256;
use lru::LruCache;
use rand::RngCore;
use rustc_hash::FxHashMap;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZero,
    time::{Duration, Instant},
};
use tracing::trace;

/// Maximum number of entries in the per-IP WHOAREYOU rate limit cache.
pub const MAX_WHOAREYOU_RATE_LIMIT_ENTRIES: usize = 10_000;
/// Timeout for pending messages awaiting WhoAreYou response.
const MESSAGE_CACHE_TIMEOUT: Duration = Duration::from_secs(2);
/// Max time a discv5 session may sit unused before it is evicted. Bounds both halves of
/// a session: the symmetric keys in the contact table and the `session_ips` entry that
/// guards them. Both are inserted per handshake, by a remote peer's schedule, so without
/// this neither is ever removed for a node we do not keep as a peer.
///
/// Idle rather than absolute, so a peer we are still talking to is never made to
/// re-handshake mid-conversation: that costs a WHOAREYOU round trip and drops the message
/// that triggered it if the exchange outruns `MESSAGE_CACHE_TIMEOUT`. The
/// handshake-once-and-vanish population this exists to bound is unaffected, since nothing
/// refreshes those.
///
/// Shared rather than duplicated: when the keys outlive their `session_ips` entry, the
/// IP-rebinding check in `discv5_handle_ordinary` silently stops applying to a session
/// that still decrypts. Both halves are refreshed together, for that same reason.
pub const SESSION_TTL: Duration = Duration::from_secs(3600);
/// How long an outstanding FINDNODE stays eligible to be answered. Generous
/// enough for a multi-packet NODES response over a slow link, short enough that
/// a request id cannot be replayed against us much later.
const PENDING_FINDNODE_TIMEOUT: Duration = Duration::from_secs(10);

/// Source IP a discv5 session was established from, paired with when the session was last
/// used so idle entries can be evicted (see `SESSION_TTL`).
///
/// The IP itself is never refreshed, only the timestamp: rebinding is still detected for
/// the whole life of the session.
#[derive(Debug, Clone)]
pub struct SessionSource {
    pub ip: IpAddr,
    pub last_used: Instant,
}

/// Discv5-specific state held within the unified DiscoveryServer.
#[derive(Debug)]
pub struct Discv5State {
    /// Outgoing message count, used for nonce generation as per the spec.
    pub counter: u32,
    /// Pending outgoing messages awaiting WhoAreYou response, keyed by nonce.
    pub pending_by_nonce: FxHashMap<[u8; 12], (Node, Message, Instant)>,
    /// Pending WhoAreYou challenges awaiting Handshake response, keyed by src_id.
    /// Tuple: (challenge_data, timestamp, encoded_packet_bytes).
    pub pending_challenges: FxHashMap<H256, (Vec<u8>, Instant, Vec<u8>)>,
    /// Tracks last WHOAREYOU send time per (source IP, node ID) to prevent amplification attacks.
    pub whoareyou_rate_limit: LruCache<(IpAddr, H256), Instant>,
    /// Global WHOAREYOU rate limit: count of packets sent in the current second.
    pub whoareyou_global_count: u32,
    /// Start of the current global rate limit window.
    pub whoareyou_global_window_start: Instant,
    /// Tracks the source IP that each session was established from, with the time the
    /// session was last used so idle entries can be evicted (see `SESSION_TTL`).
    pub session_ips: FxHashMap<H256, SessionSource>,
    /// Currently active iterative lookups.
    pub active_lookups: Vec<IterativeLookup>,
    /// FINDNODE requests we sent and have not yet timed out, keyed by
    /// (peer node id, request id). A NODES response is only accepted if it
    /// matches one of these: without the check, any peer with a session can
    /// push arbitrary ENRs into the peer table by sending an unsolicited
    /// NODES, and we then serve them back from our own FINDNODE responses.
    /// Entries are not removed on first use, because a single response may be
    /// split across up to `total` packets sharing one request id; they expire
    /// via `PENDING_FINDNODE_TIMEOUT` instead.
    pub pending_findnodes: FxHashMap<(H256, Bytes), Instant>,
}

impl Default for Discv5State {
    fn default() -> Self {
        Self {
            counter: 0,
            pending_by_nonce: Default::default(),
            pending_challenges: Default::default(),
            pending_findnodes: Default::default(),
            whoareyou_rate_limit: LruCache::new(
                NonZero::new(MAX_WHOAREYOU_RATE_LIMIT_ENTRIES)
                    .expect("MAX_WHOAREYOU_RATE_LIMIT_ENTRIES must be non-zero"),
            ),
            whoareyou_global_count: 0,
            whoareyou_global_window_start: Instant::now(),
            session_ips: Default::default(),
            active_lookups: Vec::new(),
        }
    }
}

impl Discv5State {
    /// Generates a 96-bit AES-GCM nonce.
    /// Encodes the current outgoing message count into the first 32 bits
    /// and fills the remaining 64 bits with random data.
    pub fn next_nonce<R: RngCore>(&mut self, rng: &mut R) -> [u8; 12] {
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&counter.to_be_bytes());
        rng.fill_bytes(&mut nonce[4..]);
        nonce
    }

    /// Remove stale entries from pending caches.
    pub fn cleanup_stale_entries(&mut self) {
        let now = Instant::now();

        let before_messages = self.pending_by_nonce.len();
        self.pending_by_nonce
            .retain(|_nonce, (_node, _message, timestamp)| {
                now.duration_since(*timestamp) < MESSAGE_CACHE_TIMEOUT
            });
        let removed_messages = before_messages - self.pending_by_nonce.len();

        self.pending_findnodes
            .retain(|_key, timestamp| now.duration_since(*timestamp) < PENDING_FINDNODE_TIMEOUT);

        let before_challenges = self.pending_challenges.len();
        self.pending_challenges
            .retain(|_src_id, (_challenge_data, timestamp, _raw)| {
                now.duration_since(*timestamp) < MESSAGE_CACHE_TIMEOUT
            });
        let removed_challenges = before_challenges - self.pending_challenges.len();

        let before_sessions = self.session_ips.len();
        self.session_ips
            .retain(|_node_id, source| now.duration_since(source.last_used) < SESSION_TTL);
        let removed_sessions = before_sessions - self.session_ips.len();

        let total_removed = removed_messages + removed_challenges + removed_sessions;
        if total_removed > 0 {
            trace!(
                protocol = "discv5",
                "Cleaned up {} stale entries ({} messages, {} challenges)",
                total_removed,
                removed_messages,
                removed_challenges,
            );
        }
    }
}

/// Points `local_node` and its ENR at `new_ip`, bumping `seq` once and re-signing.
///
/// Sets whichever of the record's `ip`/`ip6` entries matches `new_ip` and clears
/// the other. ENRs may carry both, but a [`Node`] holds a single [`IpAddr`], so
/// the record ethrex owns describes one address and a leftover entry from the
/// family we just moved away from would send peers to an address we dropped.
/// Every other entry is left as it is.
///
/// [`NodeRecord::edit`] commits only once the new signature is in hand, so a
/// failed re-sign leaves both the node and the record untouched.
pub(crate) fn update_local_ip(
    local_node: &mut Node,
    local_node_record: &mut NodeRecord,
    signer: &secp256k1::SecretKey,
    new_ip: IpAddr,
) {
    let edited = local_node_record.edit(signer, |pairs| match new_ip.to_canonical() {
        IpAddr::V4(ip) => {
            pairs.ip = Some(ip);
            pairs.ip6 = None;
        }
        IpAddr::V6(ip) => {
            pairs.ip6 = Some(ip);
            pairs.ip = None;
        }
    });
    if let Err(err) = edited {
        tracing::error!(%new_ip, %err, "Failed to re-sign ENR for IP update");
        return;
    }

    local_node.ip = new_ip;
}

#[derive(Debug, Clone)]
pub struct Discv5Message {
    pub(crate) from: SocketAddr,
    pub(crate) packet: Packet,
}

impl Discv5Message {
    pub fn from(packet: Packet, from: SocketAddr) -> Self {
        Self { from, packet }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::public_key_from_signing_key;
    use ethrex_common::types::ForkId;
    use rand::{SeedableRng, rngs::StdRng};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NEW_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const QUIC_PORT: u16 = 9001;

    /// A local identity whose record advertises `quic`, an entry
    /// [`NodeRecord::from_node`] cannot derive and an IP update must not destroy.
    fn local_identity(eth: Option<ForkId>) -> (Node, NodeRecord, secp256k1::SecretKey) {
        let signer = secp256k1::SecretKey::from_slice(&[
            16, 125, 177, 238, 167, 212, 168, 215, 239, 165, 77, 224, 199, 143, 55, 205, 9, 194,
            87, 139, 92, 46, 30, 191, 74, 37, 68, 242, 38, 225, 104, 246,
        ])
        .unwrap();
        let node = Node::new(
            IpAddr::from(Ipv4Addr::LOCALHOST),
            30303,
            30303,
            public_key_from_signing_key(&signer),
        );
        let mut record = NodeRecord::from_node(&node, 1, &signer).unwrap();
        record
            .edit(&signer, |pairs| {
                pairs.eth = eth;
                assert!(pairs.set_extra_int(b"quic", QUIC_PORT.into()));
            })
            .unwrap();
        (node, record, signer)
    }

    #[test]
    fn update_local_ip_preserves_entries_it_does_not_touch() {
        // Rebuilding the record from the `Node` carries only what `from_node`
        // knows how to derive, so a `quic` entry the caller added separately was
        // silently dropped the first time discv5's IP voting fired.
        let (mut node, mut record, signer) = local_identity(None);

        update_local_ip(&mut node, &mut record, &signer, NEW_IP);

        assert_eq!(node.ip, NEW_IP);
        assert_eq!(record.pairs().ip, Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(
            record.pairs().extra_int::<u16>(b"quic"),
            Some(QUIC_PORT),
            "an entry the update never mentions must survive it"
        );
        assert!(
            record.verify_signature(),
            "must be re-signed after the edit"
        );
    }

    #[test]
    fn update_local_ip_bumps_seq_exactly_once() {
        // With a fork id present the rebuild path bumped twice: once for the
        // record built at `seq + 1`, then again inside `set_fork_id`. Every extra
        // bump is a wasted signature and a spurious re-gossip.
        let fork_id = ForkId {
            fork_hash: ethrex_common::H32::from_low_u64_be(0xdead_beef),
            fork_next: 42,
        };
        let (mut node, mut record, signer) = local_identity(Some(fork_id.clone()));
        let seq_before = record.seq;

        update_local_ip(&mut node, &mut record, &signer, NEW_IP);

        assert_eq!(record.seq, seq_before + 1);
        assert_eq!(record.get_fork_id(), Some(&fork_id));
    }

    #[test]
    fn update_local_ip_clears_the_address_family_it_moves_away_from() {
        // The only case where clearing the other entry is load-bearing: both
        // tests above start from an `ip`-only record, so `pairs.ip6 = None` runs
        // but can never be seen to change anything. Left behind, the stale `ip6`
        // would keep pointing peers at an address we no longer answer on.
        let (mut node, mut record, signer) = local_identity(None);
        let old_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        record
            .edit(&signer, |pairs| {
                pairs.ip = None;
                pairs.ip6 = Some(old_ipv6);
            })
            .unwrap();
        assert_eq!(record.pairs().ip6, Some(old_ipv6));

        update_local_ip(&mut node, &mut record, &signer, NEW_IP);

        assert_eq!(record.pairs().ip, Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(record.pairs().ip6, None, "the stale entry must be cleared");
        assert!(record.verify_signature());
    }

    #[tokio::test]
    async fn test_next_nonce_counter() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut state = Discv5State::default();

        let n1 = state.next_nonce(&mut rng);
        let n2 = state.next_nonce(&mut rng);

        assert_eq!(&n1[..4], &[0, 0, 0, 0]);
        assert_eq!(&n2[..4], &[0, 0, 0, 1]);
        assert_ne!(&n1[4..], &n2[4..]);
    }
}
