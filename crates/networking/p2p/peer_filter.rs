//! Which of the peers discovery finds are worth handing to a consumer.
//!
//! Discovery itself does not know what makes a peer worth dialing. An L1 node
//! wants an EIP-2124 fork id compatible with its chain; another consumer of
//! the same discovery stack judges a record by entirely different entries.
//! Rather than teach discovery every such rule, a consumer supplies a
//! [`PeerFilter`] and discovery runs each contact's ENR through it as that
//! record arrives.

use crate::backend;
use crate::types::NodeRecord;
use ethrex_storage::Store;
use tracing::debug;

/// Which of the peers discovery finds a consumer will accept.
///
/// Consulted for every contact that arrives with a record, over discv4 and
/// discv5 alike. A contact discovered without an ENR is never filtered and stays
/// dialable.
///
/// Implementations run inside the discovery server's message loop, so a slow
/// `accepts` stalls inbound UDP, revalidation, lookups, and the dial-candidate
/// request the initiator is waiting on. A remote peer decides how often this runs:
/// an unsolicited discv5 NODES message is filtered per ENR it carries. Keep it to
/// work proportional to the record, and cache anything expensive at construction.
///
/// `accepts` is synchronous, which states that requirement in the type rather
/// than in this comment. It also keeps the trait object-safe without boxing a
/// future for every contact discovery hands over.
///
/// `Send` because the peer table owns the filter and its state is moved into an
/// actor task. Not `Sync`: only that task ever touches it. `'static` in
/// practice, since the table stores it as a `Box<dyn PeerFilter>` that outlives
/// every caller.
pub trait PeerFilter: Send {
    /// Whether this peer is worth dialing, judged from the ENR it published.
    ///
    /// A `false` is never final: the peer table runs the contact through the
    /// filter again as soon as the peer publishes a higher-`seq` record, so a
    /// filter may reject on facts that later change, such as a fork id read
    /// against a head we have not synced to yet.
    ///
    /// A filter that finds nothing it recognises in the record must still
    /// decide. Answer `true` where indifference should not cost a dial, and
    /// `false` where the absence itself disqualifies the peer, as a missing
    /// `eth` entry does for an execution client.
    fn accepts(&self, record: &NodeRecord) -> bool;
}

/// Ethereum's own requirement: the peer's EIP-2124 `eth` entry must be
/// compatible with our chain, judged against the current head.
pub struct EthForkIdFilter {
    store: Store,
}

impl EthForkIdFilter {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl PeerFilter for EthForkIdFilter {
    fn accepts(&self, record: &NodeRecord) -> bool {
        // A record that never mentions `eth` is rejected rather than left
        // unjudged: the discv5 DHT is shared with nodes running protocols this
        // client does not speak, and those are not peers it can talk to. This
        // mirrors the `Option<bool>` field it replaces, where a missing entry
        // was `Some(false)`.
        let Some(remote_fork_id) = record.get_fork_id() else {
            debug!(
                peer = ?record.pairs().secp256k1,
                "Rejecting peer: ENR carries no eth entry"
            );
            return false;
        };

        match backend::is_fork_id_valid(&self.store, remote_fork_id) {
            Ok(true) => true,
            Ok(false) => {
                // Our own fork id is deliberately not logged alongside:
                // `is_fork_id_valid` already derives it and throws it away, and
                // naming it here would mean a second genesis and head read for
                // every record we turn down.
                debug!(
                    peer = ?record.pairs().secp256k1,
                    %remote_fork_id,
                    "Rejecting peer: fork id is not compatible with our chain"
                );
                false
            }
            // Reading our own chain failed, which says nothing about the peer.
            // The `.ok().or(Some(false))` this replaces rejected here, punishing
            // a peer for our unreadable DB and then not reconsidering until it
            // happened to republish its ENR.
            //
            // Failing open is safe because this check is an optimisation, not a
            // boundary: `backend::validate_status` re-checks the fork id during
            // the RLPx handshake and `rlpx` marks the peer unwanted if it
            // fails. The cost of being wrong here is one dial.
            Err(err) => {
                debug!(%err, "Could not evaluate remote fork id");
                true
            }
        }
    }
}

/// Accepts every peer discovery finds.
///
/// What a consumer that only wants the discovery stack passes: it has no
/// requirement of its own to express, and screening on our behalf would only
/// throw away peers it might want.
pub struct AcceptAllFilter;

impl PeerFilter for AcceptAllFilter {
    fn accepts(&self, _record: &NodeRecord) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeRecordPairs;
    use ethrex_common::types::ForkId;
    use ethrex_storage::EngineType;
    use std::{net::Ipv4Addr, path::Path};

    const GENESIS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../fixtures/genesis/l1.json"
    );

    /// A store holding the L1 genesis, so our own fork id is computable.
    async fn store_at_genesis() -> Store {
        Store::new_from_genesis(Path::new(""), EngineType::InMemory, GENESIS)
            .await
            .unwrap()
    }

    fn record_with_fork_id(eth: Option<ForkId>) -> NodeRecord {
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        NodeRecord::from_pairs(
            1,
            &signer,
            NodeRecordPairs {
                ip: Some(Ipv4Addr::LOCALHOST),
                udp_port: Some(30303),
                eth,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn foreign_fork_id() -> ForkId {
        ForkId {
            fork_hash: ethrex_common::H32::from_low_u64_be(0xdeadbeef),
            fork_next: 0,
        }
    }

    #[tokio::test]
    async fn our_own_fork_id_is_accepted() {
        let store = store_at_genesis().await;
        let ours = store.get_fork_id().await.unwrap();

        assert!(EthForkIdFilter::new(store).accepts(&record_with_fork_id(Some(ours))));
    }

    #[tokio::test]
    async fn a_fork_id_from_another_chain_is_rejected() {
        let filter = EthForkIdFilter::new(store_at_genesis().await);

        assert!(!filter.accepts(&record_with_fork_id(Some(foreign_fork_id()))));
    }

    #[tokio::test]
    async fn a_record_without_an_eth_entry_is_rejected() {
        let filter = EthForkIdFilter::new(store_at_genesis().await);

        assert!(!filter.accepts(&record_with_fork_id(None)));
    }
}
