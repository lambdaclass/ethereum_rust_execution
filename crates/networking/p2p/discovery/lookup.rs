use crate::discovery::contact_table::xor_distance;
use crate::types::Node;
use ethrex_common::H256;
use rustc_hash::FxHashSet;
use std::time::{Duration, Instant};

/// Number of concurrent queries per iteration round.
pub const LOOKUP_ALPHA: usize = 3;
/// Maximum entries in the result set (Kademlia k parameter).
pub const LOOKUP_BUCKET_SIZE: usize = 16;
/// Maximum duration before a lookup is considered timed out.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);

/// A single entry in the iterative lookup result set.
#[derive(Debug, Clone)]
pub struct LookupEntry {
    pub node_id: H256,
    pub node: Node,
    pub distance: H256,
    pub queried: bool,
}

/// Iterative convergence lookup (geth-style).
///
/// Generates a random target, seeds with closest known nodes, queries alpha=3
/// closest not-yet-asked nodes, feeds responses back, and iterates until
/// convergence (no more unqueried entries closer than what we have, or timeout).
#[derive(Debug)]
pub struct IterativeLookup {
    pub target: H256,
    result: Vec<LookupEntry>,
    seen: FxHashSet<H256>,
    queries_in_flight: usize,
    started_at: Instant,
}

impl IterativeLookup {
    /// Create a new iterative lookup seeded with the given nodes.
    pub fn new(target: H256, seed_nodes: Vec<(H256, Node)>) -> Self {
        let mut seen = FxHashSet::default();
        let mut result: Vec<LookupEntry> = Vec::with_capacity(LOOKUP_BUCKET_SIZE);

        for (node_id, node) in seed_nodes {
            if seen.insert(node_id) {
                let distance = xor_distance(&target, &node_id);
                result.push(LookupEntry {
                    node_id,
                    node,
                    distance,
                    queried: false,
                });
            }
        }

        // Sort by distance (ascending) and truncate to bucket size
        result.sort_by(|a, b| a.distance.cmp(&b.distance));
        result.truncate(LOOKUP_BUCKET_SIZE);

        Self {
            target,
            result,
            seen,
            queries_in_flight: 0,
            started_at: Instant::now(),
        }
    }

    /// Returns up to `count` closest unqueried entries, marks them as queried,
    /// and increments the in-flight counter.
    pub fn next_to_query(&mut self, count: usize) -> Vec<(H256, Node)> {
        let mut out = Vec::with_capacity(count);
        for entry in &mut self.result {
            if out.len() >= count {
                break;
            }
            if !entry.queried {
                entry.queried = true;
                self.queries_in_flight += 1;
                out.push((entry.node_id, entry.node.clone()));
            }
        }
        out
    }

    /// Feed response nodes into the lookup. Inserts new nodes if they are
    /// closer than the farthest entry (or the result set is not full yet).
    /// Deduplicates via the `seen` set.
    pub fn feed_results(&mut self, nodes: Vec<(H256, Node)>) {
        for (node_id, node) in nodes {
            if !self.seen.insert(node_id) {
                continue;
            }
            let distance = xor_distance(&self.target, &node_id);

            if self.result.len() < LOOKUP_BUCKET_SIZE {
                self.result.push(LookupEntry {
                    node_id,
                    node,
                    distance,
                    queried: false,
                });
            } else if let Some(farthest) = self.result.last()
                && distance < farthest.distance
            {
                // Replace the farthest entry
                let last_idx = self.result.len() - 1;
                self.result[last_idx] = LookupEntry {
                    node_id,
                    node,
                    distance,
                    queried: false,
                };
            } else {
                continue;
            }

            // Re-sort after insertion
            self.result.sort_by(|a, b| a.distance.cmp(&b.distance));
        }
    }

    /// Record that a response was received (decrements in-flight counter).
    pub fn record_response(&mut self) {
        self.queries_in_flight = self.queries_in_flight.saturating_sub(1);
    }

    /// Record that a query timed out (same as record_response).
    pub fn record_timeout(&mut self) {
        self.queries_in_flight = self.queries_in_flight.saturating_sub(1);
    }

    /// Returns true if the lookup has converged:
    /// - All entries in the result set have been queried (don't wait for
    ///   stragglers — late responses still get processed via handle_neighbors
    ///   and feed into the connection pool / next lookup), OR
    /// - The lookup has timed out.
    pub fn is_finished(&self) -> bool {
        if self.started_at.elapsed() >= LOOKUP_TIMEOUT {
            return true;
        }
        !self.result.iter().any(|e| !e.queried)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::H512;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_node(seed: u8) -> (H256, Node) {
        let pk = H512::from_low_u64_be(seed as u64 + 1);
        let node = Node::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, seed)), 30303, 30303, pk);
        (node.node_id(), node)
    }

    #[test]
    fn new_sorts_by_distance_and_truncates() {
        let target = H256::zero();
        let seeds: Vec<_> = (1..=20).map(make_node).collect();
        let lookup = IterativeLookup::new(target, seeds);

        assert!(lookup.result.len() <= LOOKUP_BUCKET_SIZE);
        for w in lookup.result.windows(2) {
            assert!(w[0].distance <= w[1].distance);
        }
    }

    #[test]
    fn next_to_query_returns_alpha_entries() {
        let target = H256::zero();
        let seeds: Vec<_> = (1..=10).map(make_node).collect();
        let mut lookup = IterativeLookup::new(target, seeds);

        let batch = lookup.next_to_query(LOOKUP_ALPHA);
        assert_eq!(batch.len(), LOOKUP_ALPHA);
        assert_eq!(lookup.queries_in_flight, LOOKUP_ALPHA);
    }

    #[test]
    fn feed_results_deduplicates() {
        let target = H256::zero();
        let seeds: Vec<_> = (1..=3).map(make_node).collect();
        let mut lookup = IterativeLookup::new(target, seeds.clone());

        let initial_len = lookup.result.len();
        // Feed the same nodes again
        lookup.feed_results(seeds);
        assert_eq!(lookup.result.len(), initial_len);
    }

    #[test]
    fn is_finished_when_all_queried() {
        let target = H256::zero();
        let seeds: Vec<_> = (1..=2).map(make_node).collect();
        let mut lookup = IterativeLookup::new(target, seeds);

        assert!(!lookup.is_finished());

        let _ = lookup.next_to_query(10);
        // Finished once all entries are queried (don't wait for in-flight)
        assert!(lookup.is_finished());
    }
}
