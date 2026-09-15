#![cfg_attr(not(feature = "std"), no_std)]
// In no_std builds the per-node hash cache (`OnceLock`) is a non-atomic, `!Sync`
// cell (see `node::OnceLock`), which makes `Node` `!Sync` and trips
// `arc_with_non_send_sync` on the `Arc<Node>` in `NodeRef`. The `Arc` is
// deliberate: the type is shared with the std build, where `Node` is `Send + Sync`
// and nodes are handed across rayon workers during parallel merkleization. The
// single-threaded no_std consumer (the zkVM guest) never shares across threads, so
// the atomic refcount is harmless here and keeps a single unified node type across
// both builds.
#![cfg_attr(not(feature = "std"), allow(clippy::arc_with_non_send_sync))]

#[macro_use]
extern crate alloc;

pub mod db;
pub mod error;

// Witness recording (Arc<Mutex>) is host-only; the guest verifies against a witness.
#[cfg(feature = "std")]
pub mod logger;
mod nibbles;
pub mod node;
mod node_hash;
pub mod rkyv_utils;
mod rlp;
#[cfg(test)]
mod test_utils;
// Parallel merkleization (std threads + crossbeam) is host-only.
#[cfg(feature = "std")]
pub mod threadpool;
mod trie_iter;
#[cfg(feature = "std")]
pub mod trie_sorted;
mod verify_range;
pub mod witness_codec;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
use ethereum_types::H256;
use ethrex_crypto::{Crypto, NativeCrypto};
use ethrex_rlp::constants::RLP_NULL;
use ethrex_rlp::encode::RLPEncode;

#[cfg(feature = "std")]
use rustc_hash::FxHashSet;
// `FxHashMap` is part of the public API (`get_embedded_root_committed`). Its concrete
// type is build-dependent, so callers that build this crate `no_std` (e.g. the guest
// via `ethrex-common`) must name it through this re-export to stay type-compatible.
#[cfg(feature = "std")]
pub use rustc_hash::FxHashMap;
// rustc-hash's map/set aliases require std; use hashbrown with the Fx hasher otherwise.
#[cfg(not(feature = "std"))]
pub type FxHashMap<K, V> = hashbrown::HashMap<K, V, rustc_hash::FxBuildHasher>;
#[cfg(not(feature = "std"))]
type FxHashSet<K> = hashbrown::HashSet<K, rustc_hash::FxBuildHasher>;

pub use self::db::{InMemoryTrieDB, TrieDB};
#[cfg(feature = "std")]
pub use self::logger::{TrieLogger, TrieWitness};
pub use self::nibbles::Nibbles;
#[cfg(feature = "std")]
pub use self::threadpool::ThreadPool;
pub use self::verify_range::verify_range;
pub use self::{
    node::{Node, NodeRef, OnceLock},
    node_hash::NodeHash,
};

pub use self::error::{ExtensionNodeErrorData, InconsistentTreeError, TrieError};
use self::{node::LeafNode, trie_iter::TrieIterator};

use ethrex_rlp::decode::RLPDecode;

/// Hash of an empty trie: `keccak256(RLP_NULL)`, a well-known Ethereum constant.
/// Hardcoded so it needs no lazy initialization, works in `const` contexts, and
/// pulls no lazy-cell dependency into `no_std` builds. The
/// `empty_trie_hash_matches_keccak` test pins it to the computed value.
pub const EMPTY_TRIE_HASH: H256 = H256([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);

/// RLP-encoded trie path
pub type PathRLP = Vec<u8>;
/// RLP-encoded trie value
pub type ValueRLP = Vec<u8>;
/// RLP-encoded trie node
pub type NodeRLP = Vec<u8>;
/// Represents a node in the Merkle Patricia Trie.
pub type TrieNode = (Nibbles, NodeRLP);

/// Ethereum-compatible Merkle Patricia Trie
pub struct Trie {
    db: Box<dyn TrieDB>,
    pub root: NodeRef,
    pending_removal: FxHashSet<Nibbles>,
    dirty: FxHashSet<Nibbles>,
}

// `Default` builds an in-memory (InMemoryTrieDB) trie.
impl Default for Trie {
    fn default() -> Self {
        Self::new_temp()
    }
}

impl Trie {
    /// Creates a new Trie from a clean DB
    pub fn new(db: Box<dyn TrieDB>) -> Self {
        Self {
            db,
            root: NodeRef::default(),
            pending_removal: Default::default(),
            dirty: Default::default(),
        }
    }

    /// Creates a trie from an already-initialized DB and sets root as the root node of the trie
    pub fn open(db: Box<dyn TrieDB>, root: H256) -> Self {
        Self {
            db,
            root: if root != EMPTY_TRIE_HASH {
                NodeHash::from(root).into()
            } else {
                Default::default()
            },
            pending_removal: Default::default(),
            dirty: Default::default(),
        }
    }

    /// Return a reference to the internal database.
    ///
    /// Warning: All changes made to the db will bypass the trie and may cause the trie to suddenly
    ///   become inconsistent.
    pub fn db(&self) -> &dyn TrieDB {
        self.db.as_ref()
    }

    /// Retrieve an RLP-encoded value from the trie given its RLP-encoded path.
    pub fn get(&self, pathrlp: &[u8]) -> Result<Option<ValueRLP>, TrieError> {
        let path = Nibbles::from_bytes(pathrlp);

        if !self.dirty.contains(&path) && self.db().flatkeyvalue_computed(path.clone()) {
            let Some(value_rlp) = self.db.get(path)? else {
                return Ok(None);
            };
            if value_rlp.is_empty() {
                return Ok(None);
            }
            return Ok(Some(value_rlp));
        }

        Ok(match self.root {
            NodeRef::Node(ref node, _) => node.get(self.db.as_ref(), path)?,
            NodeRef::Hash(hash) if hash.is_valid() => {
                Node::decode(&self.db.get(Nibbles::default())?.ok_or_else(|| {
                    TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFound(
                        hash.finalize(&NativeCrypto),
                    )))
                })?)
                .map_err(TrieError::RLPDecode)?
                .get(self.db.as_ref(), path)?
            }
            _ => None,
        })
    }

    /// Insert an RLP-encoded value into the trie.
    pub fn insert(&mut self, path: PathRLP, value: ValueRLP) -> Result<(), TrieError> {
        let path = Nibbles::from_bytes(&path);
        self.pending_removal.remove(&path);
        self.dirty.insert(path.clone());

        if self.root.is_valid() {
            // If the trie is not empty, call the root node's insertion logic.
            self.root
                .get_node_mut(self.db.as_ref(), Nibbles::default())?
                .ok_or_else(|| {
                    TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFoundNoHash))
                })?
                .insert(self.db.as_ref(), path, value)?
        } else {
            // If the trie is empty, just add a leaf.
            self.root = Node::from(LeafNode::new(path, value)).into()
        };
        self.root.clear_hash();

        Ok(())
    }

    /// Pre-resolves, via breadth-first batched reads, every trie node that the
    /// upcoming serial `insert`/`remove` loop over `sorted_paths` would
    /// otherwise resolve one at a time (one `db.get` per level per key).
    ///
    /// Nodes are installed into the in-memory arena exactly the way lazy
    /// resolution does it (see [`NodeRef::get_node_mut`]): the decoded node
    /// replaces the `NodeRef::Hash` with a `NodeRef::Node` that keeps the SAME
    /// memoized hash (`OnceLock::from(hash)`). This is purely a caching step:
    /// it never modifies any node's content, never marks anything dirty, and
    /// is therefore transparent to the resulting root hash and to the
    /// persisted node set produced by `collect_changes_since_last_hash`
    /// (verified by the `trie_prefetch` equivalence test). Prefetching extra
    /// nodes for keys that later diverge during insert is safe for the same
    /// reason: an unmodified, hash-preserved node is never re-emitted.
    ///
    /// No-op if `sorted_paths` is empty or if the trie's root isn't a
    /// `NodeRef::Hash(NodeHash::Hashed(_))` (empty trie, inline root, or a
    /// root that's already resolved — nothing left to batch).
    pub fn prefetch_sorted(&mut self, sorted_paths: &[Nibbles]) -> Result<(), TrieError> {
        if sorted_paths.is_empty() {
            return Ok(());
        }
        if !matches!(self.root, NodeRef::Hash(NodeHash::Hashed(_))) {
            return Ok(());
        }

        // Resolve the root itself first, exactly like the first `insert`
        // would (a single `db.get`).
        if self
            .root
            .get_node_mut(self.db.as_ref(), Nibbles::default())?
            .is_none()
        {
            // Root hash points to a node that isn't in the DB. Let the real
            // insert/remove loop hit (and report) this inconsistency;
            // prefetching can't fix it and shouldn't hide it.
            return Ok(());
        }

        let all_indices: Vec<usize> = (0..sorted_paths.len()).collect();
        // Defensive guard against a malformed/cyclic trie: legitimate paths
        // are at most 65 nibbles (64 nibbles + leaf terminator) deep.
        const MAX_LEVELS: usize = 68;

        for _ in 0..MAX_LEVELS {
            // Clone the root's Arc (cheap refcount bump) so the following
            // immutable scan doesn't hold a borrow of `self.root`, freeing it
            // up for the later mutable install pass without any `&mut`
            // reference held across the `multi_get` call in between.
            let root_node = match &self.root {
                NodeRef::Node(node, _) => node.clone(),
                _ => break,
            };

            let mut to_fetch: Vec<Nibbles> = Vec::new();
            collect_prefetch_targets(
                &root_node,
                &Nibbles::default(),
                &all_indices,
                sorted_paths,
                &mut to_fetch,
            );
            // Release the extra strong ref to the root before the mutable
            // install pass, so `Arc::make_mut` below sees strong count 1 (the
            // common single-owner case) and does not clone the resolved path.
            drop(root_node);
            if to_fetch.is_empty() {
                break;
            }

            let mut results = self.db.multi_get(&to_fetch).into_iter();

            let NodeRef::Node(root_arc, _) = &mut self.root else {
                break;
            };
            let root_mut = Arc::make_mut(root_arc);
            install_prefetch_targets(
                root_mut,
                &Nibbles::default(),
                &all_indices,
                sorted_paths,
                &mut results,
            )?;
        }

        Ok(())
    }

    /// Remove a value from the trie given its RLP-encoded path.
    /// Returns the value if it was succesfully removed or None if it wasn't part of the trie
    pub fn remove(&mut self, path: &[u8]) -> Result<Option<ValueRLP>, TrieError> {
        self.dirty.insert(Nibbles::from_bytes(path));
        if !self.root.is_valid() {
            return Ok(None);
        }
        self.pending_removal.insert(Nibbles::from_bytes(path));

        // If the trie is not empty, call the root node's removal logic.
        let (is_trie_empty, value) = self
            .root
            .get_node_mut(self.db.as_ref(), Nibbles::default())?
            .ok_or_else(|| {
                TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFoundNoHash))
            })?
            .remove(self.db.as_ref(), Nibbles::from_bytes(path))?;
        if is_trie_empty {
            self.root = NodeRef::default();
        } else {
            self.root.clear_hash();
        }

        Ok(value)
    }

    /// Return the hash of the trie's root node.
    /// Returns keccak(RLP_NULL) if the trie is empty
    /// Also commits changes to the DB
    pub fn hash(&mut self, crypto: &dyn Crypto) -> Result<H256, TrieError> {
        self.commit(crypto)?;
        Ok(self.hash_no_commit(crypto))
    }

    /// Return the hash of the trie's root node.
    /// Returns keccak(RLP_NULL) if the trie is empty
    pub fn hash_no_commit(&self, crypto: &dyn Crypto) -> H256 {
        if self.root.is_valid() {
            // 512 is the maximum size of an encoded node
            let mut buf = Vec::with_capacity(512);
            self.root
                .compute_hash_no_alloc(&mut buf, crypto)
                .finalize(crypto)
        } else {
            EMPTY_TRIE_HASH
        }
    }

    pub fn get_root_node(&self, path: Nibbles) -> Result<Arc<Node>, TrieError> {
        self.root
            .get_node_checked(self.db.as_ref(), path)?
            .ok_or_else(|| {
                TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFound(
                    self.root
                        .compute_hash(&NativeCrypto)
                        .finalize(&NativeCrypto),
                )))
            })
    }

    /// Returns a list of changes in a TrieNode format since last root hash processed.
    ///
    /// # Returns
    ///
    /// A tuple containing the hash and the list of changes.
    pub fn collect_changes_since_last_hash(
        &mut self,
        crypto: &dyn Crypto,
    ) -> (H256, Vec<TrieNode>) {
        let updates = self.commit_without_storing(crypto);
        let ret_hash = self.hash_no_commit(crypto);
        (ret_hash, updates)
    }

    /// Compute the hash of the root node and flush any changes into the database.
    ///
    /// This method will also compute the hash of all internal nodes indirectly. It will not clear
    /// the cached nodes.
    pub fn commit(&mut self, crypto: &dyn Crypto) -> Result<(), TrieError> {
        let acc = self.commit_without_storing(crypto);
        self.db.put_batch(acc)?;

        // Commit the underlying transaction
        self.db.commit()?;

        Ok(())
    }

    /// Computes the nodes that would be added if updating the trie.
    /// Nodes are given with their hash pre-calculated.
    pub fn commit_without_storing(&mut self, crypto: &dyn Crypto) -> Vec<TrieNode> {
        let mut acc = Vec::new();
        if self.root.is_valid() {
            self.root.commit(Nibbles::default(), &mut acc, crypto);
        }
        if self.root.compute_hash(crypto) == NodeHash::Hashed(EMPTY_TRIE_HASH) {
            acc.push((Nibbles::default(), vec![RLP_NULL]))
        }
        acc.extend(self.pending_removal.drain().map(|nib| (nib, vec![])));

        acc
    }

    /// Obtain a merkle proof for the given path.
    /// The proof will contain all the encoded nodes traversed until reaching the node where the path is stored (including this last node).
    /// The proof will still be constructed even if the path is not stored in the trie, proving its absence.
    ///
    /// Note: This method has a different behavior in regard to non-existent trie root nodes. Normal
    ///   behavior is to return `Err(InconsistentTrie)`, but this method will return
    ///   `Ok(Vec::new())` instead.
    pub fn get_proof(&self, path: &[u8]) -> Result<Vec<NodeRLP>, TrieError> {
        if self.root.is_valid() {
            let hash = self.root.compute_hash(&NativeCrypto);

            let mut node_path = Vec::new();
            if let NodeHash::Inline((data, len)) = hash {
                node_path.push(data[..len as usize].to_vec());
            }

            let root = match self
                .root
                .get_node_checked(self.db.as_ref(), Nibbles::default())?
            {
                Some(x) => x,
                None => return Ok(Vec::new()),
            };
            root.get_path(self.db.as_ref(), Nibbles::from_bytes(path), &mut node_path)?;

            Ok(node_path)
        } else {
            Ok(Vec::new())
        }
    }

    /// Obtains all encoded nodes traversed until reaching the node where every path is stored.
    /// The list doesn't include the root node, this is returned separately.
    /// Will still be constructed even if some path is not stored in the trie.
    pub fn get_proofs(
        &self,
        paths: &[PathRLP],
    ) -> Result<(Option<NodeRLP>, Vec<NodeRLP>), TrieError> {
        if self.root.is_valid() {
            let encoded_root = self.get_root_node(Nibbles::default())?.encode_to_vec();

            let mut node_path: FxHashSet<_> = Default::default();
            for path in paths {
                let mut nodes = self.get_proof(path)?;
                nodes.swap_remove(0);
                node_path.extend(nodes);
            }

            Ok((Some(encoded_root), node_path.into_iter().collect()))
        } else {
            Ok((None, Vec::new()))
        }
    }

    #[cfg(feature = "std")]
    pub fn empty_in_memory() -> Self {
        Self::new(Box::new(InMemoryTrieDB::new(Arc::new(
            std::sync::Mutex::new(BTreeMap::new()),
        ))))
    }

    /// Gets node with embedded references to child nodes, all in just one `Node`.
    pub fn get_embedded_root(
        all_nodes: &BTreeMap<H256, Node>,
        root_hash: H256,
    ) -> Result<NodeRef, TrieError> {
        // If the root hash is of the empty trie then we can get away by setting the NodeRef to default
        if root_hash == EMPTY_TRIE_HASH {
            return Ok(NodeRef::default());
        }

        let root_rlp = all_nodes.get(&root_hash).ok_or_else(|| {
            TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFound(root_hash)))
        })?;

        fn get_embedded_node(
            all_nodes: &BTreeMap<H256, Node>,
            cur_node: &Node,
        ) -> Result<Node, TrieError> {
            Ok(match cur_node.clone() {
                Node::Branch(mut node) => {
                    for choice in &mut node.choices {
                        let NodeRef::Hash(hash) = *choice else {
                            continue;
                        };

                        if hash.is_valid() {
                            *choice = match all_nodes.get(&hash.finalize(&NativeCrypto)) {
                                Some(node) => get_embedded_node(all_nodes, node)?.into(),
                                None => hash.into(),
                            };
                        }
                    }

                    (*node).into()
                }
                Node::Extension(mut node) => {
                    let NodeRef::Hash(hash) = node.child else {
                        return Ok(node.into());
                    };

                    node.child = match all_nodes.get(&hash.finalize(&NativeCrypto)) {
                        Some(node) => get_embedded_node(all_nodes, node)?.into(),
                        None => hash.into(),
                    };

                    node.into()
                }
                Node::Leaf(node) => node.into(),
            })
        }

        let root = get_embedded_node(all_nodes, root_rlp)?;
        Ok(root.into())
    }

    /// Gets node with embedded references to child nodes, all in just one `Node`.
    ///
    /// Note that this method caches the hash of each node, so it assumes the provided `all_nodes` are well-formed.
    pub fn get_embedded_root_committed(
        all_nodes: &FxHashMap<H256, Node>,
        root_hash: H256,
        crypto: &dyn Crypto,
    ) -> Result<NodeRef, TrieError> {
        // If the root hash is of the empty trie then we can get away by setting the NodeRef to default
        if root_hash == EMPTY_TRIE_HASH {
            return Ok(NodeRef::default());
        }

        let root_rlp = all_nodes.get(&root_hash).ok_or_else(|| {
            TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFound(root_hash)))
        })?;

        /// Creates an embedded node reference with its hash slot pre-seeded.
        ///
        /// The caller must guarantee that `hash` is the hash of the referenced
        /// node, for example because the node was just resolved by looking that
        /// hash up. Seeding lets later hash computations over the subtree reuse
        /// the known value instead of re-encoding and re-hashing it.
        fn node_with_hash(node: Node, hash: NodeHash) -> NodeRef {
            NodeRef::Node(Arc::new(node), OnceLock::from(hash))
        }

        fn get_embedded_node_committed(
            all_nodes: &FxHashMap<H256, Node>,
            cur_node: &Node,
            crypto: &dyn Crypto,
        ) -> Result<Node, TrieError> {
            Ok(match cur_node.clone() {
                Node::Branch(mut node) => {
                    for choice in &mut node.choices {
                        let NodeRef::Hash(hash) = *choice else {
                            continue;
                        };

                        if hash.is_valid() {
                            *choice = match all_nodes.get(&hash.finalize(crypto)) {
                                Some(node) => node_with_hash(
                                    get_embedded_node_committed(all_nodes, node, crypto)?,
                                    hash,
                                ),
                                None => hash.into(),
                            };
                        }
                    }

                    (*node).into()
                }
                Node::Extension(mut node) => {
                    let NodeRef::Hash(hash) = node.child else {
                        return Ok(node.into());
                    };

                    node.child = match all_nodes.get(&hash.finalize(crypto)) {
                        Some(node) => node_with_hash(
                            get_embedded_node_committed(all_nodes, node, crypto)?,
                            hash,
                        ),
                        None => hash.into(),
                    };

                    node.into()
                }
                Node::Leaf(node) => node.into(),
            })
        }

        let root = get_embedded_node_committed(all_nodes, root_rlp, crypto)?;
        Ok(node_with_hash(root, NodeHash::Hashed(root_hash)))
    }

    /// Builds a trie from a set of nodes with an empty InMemoryTrieDB as a backend because the nodes are embedded in the root.
    ///
    /// Note: This method will not ensure that all node references are valid. Invalid references
    ///   will cause other methods (including, but not limited to `Trie::get`, `Trie::insert` and
    ///   `Trie::remove`) to return `Err(InconsistentTrie)`.
    /// Note: This method will ignore any dangling nodes. All nodes that are not accessible from the
    ///   root node are considered dangling.
    #[cfg(feature = "std")]
    pub fn from_nodes(
        root_hash: H256,
        state_nodes: &BTreeMap<H256, Node>,
    ) -> Result<Self, TrieError> {
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::default()));
        let root = Self::get_embedded_root(state_nodes, root_hash)?;
        trie.root = root;

        Ok(trie)
    }

    /// Builds an in-memory trie from the given elements and returns its hash
    pub fn compute_hash_from_unsorted_iter(
        iter: impl Iterator<Item = (PathRLP, ValueRLP)>,
        crypto: &dyn Crypto,
    ) -> H256 {
        let mut trie = Trie::stateless();
        for (path, value) in iter {
            // Unwraping here won't panic as our in_memory trie DB won't fail
            trie.insert(path, value).unwrap();
        }

        trie.hash_no_commit(crypto)
    }

    /// Creates a new stateless trie. This trie won't be able to store any nodes so all data will be lost after calculating the hash
    /// Only use it for proof verification or computing a hash from an iterator
    pub(crate) fn stateless() -> Trie {
        // We will only be using the trie's cache so we don't need a working DB
        struct NullTrieDB;

        impl TrieDB for NullTrieDB {
            fn get(&self, _key: Nibbles) -> Result<Option<Vec<u8>>, TrieError> {
                Ok(None)
            }

            fn put_batch(&self, _key_values: Vec<TrieNode>) -> Result<(), TrieError> {
                Ok(())
            }
        }

        Trie::new(Box::new(NullTrieDB))
    }

    /// Obtain the encoded node given its path.
    /// Allows usage of full paths (byte slice of 32 bytes) or compact-encoded nibble slices (with length lower than 32)
    pub fn get_node(&self, partial_path: &PathRLP) -> Result<Vec<u8>, TrieError> {
        // Convert compact-encoded nibbles into a byte slice if necessary
        let partial_path = match partial_path.len() {
            // Compact-encoded nibbles
            n if n < 32 => Nibbles::decode_compact(partial_path),
            // Full path (No conversion needed)
            32 => Nibbles::from_bytes(partial_path),
            // We won't handle paths with length over 32
            _ => return Ok(vec![]),
        };

        fn get_node_inner(
            db: &dyn TrieDB,
            current_path: Nibbles,
            node: &Node,
            mut partial_path: Nibbles,
        ) -> Result<Vec<u8>, TrieError> {
            // If we reached the end of the partial path, return the current node
            if partial_path.is_empty() {
                return Ok(node.encode_to_vec());
            }
            match node {
                Node::Branch(branch_node) => match partial_path.next_choice() {
                    Some(idx) => {
                        let child_ref = &branch_node.choices[idx];
                        if child_ref.is_valid() {
                            let child_path = current_path.append_new(idx as u8);
                            let child_node = child_ref
                                .get_node_checked(db, child_path.clone())?
                                .ok_or_else(|| {
                                    TrieError::InconsistentTree(Box::new(
                                        InconsistentTreeError::NodeNotFoundOnBranchNode(
                                            child_ref
                                                .compute_hash(&NativeCrypto)
                                                .finalize(&NativeCrypto),
                                            branch_node
                                                .compute_hash(&NativeCrypto)
                                                .finalize(&NativeCrypto),
                                            child_path.clone(),
                                        ),
                                    ))
                                })?;
                            get_node_inner(db, child_path, &child_node, partial_path)
                        } else {
                            Ok(vec![])
                        }
                    }
                    _ => Ok(vec![]),
                },
                Node::Extension(extension_node) => {
                    if partial_path.skip_prefix(&extension_node.prefix)
                        && extension_node.child.is_valid()
                    {
                        let child_path = partial_path.concat(&extension_node.prefix);
                        let child_node = extension_node
                            .child
                            .get_node_checked(db, child_path.clone())?
                            .ok_or_else(|| {
                                TrieError::InconsistentTree(Box::new(
                                    InconsistentTreeError::ExtensionNodeChildNotFound(
                                        ExtensionNodeErrorData {
                                            node_hash: extension_node
                                                .child
                                                .compute_hash(&NativeCrypto)
                                                .finalize(&NativeCrypto),
                                            extension_node_hash: extension_node
                                                .compute_hash(&NativeCrypto)
                                                .finalize(&NativeCrypto),
                                            extension_node_prefix: extension_node.prefix.clone(),
                                            node_path: child_path.clone(),
                                        },
                                    ),
                                ))
                            })?;
                        get_node_inner(db, child_path, &child_node, partial_path)
                    } else {
                        Ok(vec![])
                    }
                }
                Node::Leaf(_) => Ok(vec![]),
            }
        }

        // Fetch node
        if self.root.is_valid() {
            let root_node = self.get_root_node(Default::default())?;
            get_node_inner(
                self.db.as_ref(),
                Default::default(),
                &root_node,
                partial_path,
            )
        } else {
            Ok(Vec::new())
        }
    }

    pub fn root_node(&self) -> Result<Option<Arc<Node>>, TrieError> {
        if self.root.is_valid() {
            self.root.get_node(self.db.as_ref(), Nibbles::default())
        } else {
            Ok(None)
        }
    }

    /// Creates a new Trie based on a temporary InMemory DB
    pub fn new_temp() -> Self {
        let db = InMemoryTrieDB::new(Default::default());
        Trie::new(Box::new(db))
    }

    /// Creates a new Trie based on a temporary InMemory DB, with a specified root
    ///
    /// This is usually used to create a Trie from a root that was embedded with the rest of the nodes.
    pub fn new_temp_with_root(root: NodeRef) -> Self {
        let db = InMemoryTrieDB::new(Default::default());
        let mut trie = Trie::new(Box::new(db));
        trie.root = root;
        trie
    }

    /// Validates that the Trie isn't missing any nodes expected in the branches
    ///
    /// This is used internally with debug assertions to check the status of the trie
    /// after syncing operations.
    /// Note: this operation validates the hashes because the iterator uses
    /// get_node_checked. We shouldn't downgrade that to the unchecked version
    pub fn validate(self) -> Result<(), TrieError> {
        let mut expected_count = if self.root.is_valid() { 1 } else { 0 };
        for (_, node) in self.into_iter() {
            expected_count -= 1;
            match node {
                Node::Branch(branch_node) => {
                    expected_count += branch_node
                        .choices
                        .iter()
                        .filter(|child| child.is_valid())
                        .count();
                }
                Node::Extension(_) => {
                    expected_count += 1;
                }
                Node::Leaf(_) => {}
            }
        }
        if expected_count != 0 {
            return Err(TrieError::Verify(format!(
                "Node count mismatch, expected {expected_count} more"
            )));
        }
        Ok(())
    }

    /// Validate the trie structure in parallel by splitting at the root branch node.
    /// Each of the root's 16 subtrees is validated independently using rayon.
    #[cfg(feature = "std")]
    pub fn validate_parallel(self) -> Result<(), TrieError> {
        use rayon::prelude::*;

        if !self.root.is_valid() {
            return Ok(());
        }

        let db = &*self.db;
        let root_node = self
            .root
            .get_node_checked(db, Nibbles::default())?
            .ok_or_else(|| TrieError::Verify("Root node not found".to_string()))?;

        match &*root_node {
            Node::Branch(branch_node) => {
                let children: Vec<(Nibbles, NodeRef)> = branch_node
                    .choices
                    .iter()
                    .enumerate()
                    .filter(|(_, child)| child.is_valid())
                    .map(|(i, child)| {
                        let path = Nibbles::default().append_new(i as u8);
                        (path, child.clone())
                    })
                    .collect();

                children.par_iter().try_for_each(|(start_path, start_ref)| {
                    validate_subtree(db, start_path.clone(), start_ref.clone())
                })
            }
            _ => {
                // Non-branch root (rare): validate sequentially
                validate_subtree(db, Nibbles::default(), self.root.clone())
            }
        }
    }
}

/// Immutable BFS-boundary scan used by [`Trie::prefetch_sorted`]: given an
/// already-resolved node and the set of key indices routed to it, finds every
/// `NodeRef::Hash` child that lies on the path of at least one of those keys,
/// stopping the recursion at the first unresolved node in each branch
/// (already-resolved descendants, if any, are explored further in the same
/// call). Mirrors the descent performed by `Node::get`/`BranchNode::insert`/
/// `ExtensionNode::insert`.
fn collect_prefetch_targets(
    node: &Node,
    path: &Nibbles,
    key_indices: &[usize],
    sorted_paths: &[Nibbles],
    out: &mut Vec<Nibbles>,
) {
    match node {
        Node::Branch(branch) => {
            let depth = path.len();
            let mut buckets: [Vec<usize>; 16] = core::array::from_fn(|_| Vec::new());
            for &i in key_indices {
                let p = sorted_paths[i].as_ref();
                if depth >= p.len() {
                    continue;
                }
                let nibble = p[depth];
                if nibble < 16 {
                    buckets[nibble as usize].push(i);
                }
            }
            for (nibble, indices) in buckets.iter().enumerate() {
                if indices.is_empty() {
                    continue;
                }
                let child_path = path.append_new(nibble as u8);
                match &branch.choices[nibble] {
                    NodeRef::Hash(NodeHash::Hashed(_)) => out.push(child_path),
                    NodeRef::Node(child, _) => {
                        collect_prefetch_targets(child, &child_path, indices, sorted_paths, out)
                    }
                    // Inline (embedded, no separate disk node) or invalid/empty: nothing to fetch.
                    _ => {}
                }
            }
        }
        Node::Extension(ext) => {
            let depth = path.len();
            let prefix = ext.prefix.as_ref();
            let matched: Vec<usize> = key_indices
                .iter()
                .copied()
                .filter(|&i| {
                    let p = sorted_paths[i].as_ref();
                    depth + prefix.len() <= p.len() && &p[depth..depth + prefix.len()] == prefix
                })
                .collect();
            if matched.is_empty() {
                // No key continues through this prefix: they diverge and will
                // cause the extension to be restructured on insert; nothing
                // to prefetch here.
                return;
            }
            let child_path = path.concat(&ext.prefix);
            match &ext.child {
                NodeRef::Hash(NodeHash::Hashed(_)) => out.push(child_path),
                NodeRef::Node(child, _) => {
                    collect_prefetch_targets(child, &child_path, &matched, sorted_paths, out)
                }
                _ => {}
            }
        }
        // Terminal: leaves have no children to prefetch.
        Node::Leaf(_) => {}
    }
}

/// Mutable counterpart to [`collect_prefetch_targets`] used by
/// [`Trie::prefetch_sorted`]: repeats the identical descent/routing so it
/// visits `NodeRef::Hash` children in the exact same order, installing the
/// corresponding (same-order) `multi_get` result into the arena
/// hash-preservingly, exactly as `NodeRef::get_node_mut` installs a single
/// resolved node. On a `None`/empty result the ref is left untouched (absent
/// path); the subsequent `insert` will create it.
fn install_prefetch_targets(
    node: &mut Node,
    path: &Nibbles,
    key_indices: &[usize],
    sorted_paths: &[Nibbles],
    results: &mut alloc::vec::IntoIter<Result<Option<Vec<u8>>, TrieError>>,
) -> Result<(), TrieError> {
    match node {
        Node::Branch(branch) => {
            let depth = path.len();
            let mut buckets: [Vec<usize>; 16] = core::array::from_fn(|_| Vec::new());
            for &i in key_indices {
                let p = sorted_paths[i].as_ref();
                if depth >= p.len() {
                    continue;
                }
                let nibble = p[depth];
                if nibble < 16 {
                    buckets[nibble as usize].push(i);
                }
            }
            for (nibble, indices) in buckets.iter().enumerate() {
                if indices.is_empty() {
                    continue;
                }
                let child_path = path.append_new(nibble as u8);
                let slot = &mut branch.choices[nibble];
                match slot {
                    NodeRef::Hash(hash @ NodeHash::Hashed(_)) => {
                        let hash = *hash;
                        let bytes = results.next().ok_or_else(|| {
                            TrieError::DbError(anyhow::anyhow!(
                                "prefetch_sorted: multi_get returned fewer results than requested"
                            ))
                        })??;
                        if let Some(bytes) = bytes.filter(|b| !b.is_empty()) {
                            let decoded = Node::decode(&bytes).map_err(TrieError::RLPDecode)?;
                            *slot = NodeRef::Node(Arc::new(decoded), OnceLock::from(hash));
                        }
                    }
                    NodeRef::Node(child, _) => {
                        let child_mut = Arc::make_mut(child);
                        install_prefetch_targets(
                            child_mut,
                            &child_path,
                            indices,
                            sorted_paths,
                            results,
                        )?;
                    }
                    _ => {}
                }
            }
        }
        Node::Extension(ext) => {
            let depth = path.len();
            let prefix = ext.prefix.as_ref();
            let matched: Vec<usize> = key_indices
                .iter()
                .copied()
                .filter(|&i| {
                    let p = sorted_paths[i].as_ref();
                    depth + prefix.len() <= p.len() && &p[depth..depth + prefix.len()] == prefix
                })
                .collect();
            if matched.is_empty() {
                return Ok(());
            }
            let child_path = path.concat(&ext.prefix);
            let slot = &mut ext.child;
            match slot {
                NodeRef::Hash(hash @ NodeHash::Hashed(_)) => {
                    let hash = *hash;
                    let bytes = results.next().ok_or_else(|| {
                        TrieError::DbError(anyhow::anyhow!(
                            "prefetch_sorted: multi_get returned fewer results than requested"
                        ))
                    })??;
                    if let Some(bytes) = bytes.filter(|b| !b.is_empty()) {
                        let decoded = Node::decode(&bytes).map_err(TrieError::RLPDecode)?;
                        *slot = NodeRef::Node(Arc::new(decoded), OnceLock::from(hash));
                    }
                }
                NodeRef::Node(child, _) => {
                    let child_mut = Arc::make_mut(child);
                    install_prefetch_targets(
                        child_mut,
                        &child_path,
                        &matched,
                        sorted_paths,
                        results,
                    )?;
                }
                _ => {}
            }
        }
        Node::Leaf(_) => {}
    }
    Ok(())
}

/// Validate a subtree rooted at `start_ref`, checking that all referenced nodes exist
/// and their hashes match.
#[cfg(feature = "std")]
fn validate_subtree(
    db: &dyn TrieDB,
    start_path: Nibbles,
    start_ref: NodeRef,
) -> Result<(), TrieError> {
    let mut expected_count: isize = 1;
    let mut stack = vec![(start_path, start_ref)];

    while let Some((path, node_ref)) = stack.pop() {
        let node = node_ref
            .get_node_checked(db, path.clone())?
            .ok_or_else(|| TrieError::Verify(format!("Missing node at path {path:?}")))?;

        expected_count -= 1;
        match &*node {
            Node::Branch(branch) => {
                for (choice, child) in branch.choices.iter().enumerate().rev() {
                    if child.is_valid() {
                        expected_count += 1;
                        stack.push((path.append_new(choice as u8), child.clone()));
                    }
                }
            }
            Node::Extension(ext) => {
                expected_count += 1;
                stack.push((path.concat(&ext.prefix), ext.child.clone()));
            }
            Node::Leaf(_) => {}
        }
    }

    if expected_count != 0 {
        return Err(TrieError::Verify(format!(
            "Node count mismatch in subtree, expected {expected_count} more"
        )));
    }
    Ok(())
}

impl IntoIterator for Trie {
    type Item = (Nibbles, Node);

    type IntoIter = TrieIterator;

    fn into_iter(self) -> Self::IntoIter {
        TrieIterator::new(self)
    }
}

pub struct ProofTrie(Trie);

impl ProofTrie {
    pub fn insert(
        &mut self,
        partial_path: Nibbles,
        external_ref: NodeHash,
    ) -> Result<(), TrieError> {
        if self.0.root.is_valid() {
            // If the trie is not empty, call the root node's insertion logic.
            self.0
                .root
                .get_node_mut(self.0.db.as_ref(), Nibbles::default())?
                .ok_or_else(|| {
                    TrieError::InconsistentTree(Box::new(InconsistentTreeError::RootNotFoundNoHash))
                })?
                .insert(self.0.db.as_ref(), partial_path, external_ref)?;
            self.0.root.clear_hash();
        } else {
            self.0.root = external_ref.into();
        };

        Ok(())
    }

    pub fn hash(&self, crypto: &dyn Crypto) -> H256 {
        self.0.hash_no_commit(crypto)
    }
}

impl From<Trie> for ProofTrie {
    fn from(value: Trie) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_crypto::keccak::keccak_hash;

    // Pins the hardcoded `EMPTY_TRIE_HASH` to `keccak256(RLP_NULL)` so a typo in the
    // byte literal can't silently diverge from the computed value.
    #[test]
    fn empty_trie_hash_matches_keccak() {
        assert_eq!(EMPTY_TRIE_HASH, H256(keccak_hash([RLP_NULL])));
    }
}
