mod branch;
mod extension;
mod leaf;

use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
pub use std::sync::OnceLock;

/// Non-atomic `OnceLock` replacement used on `no_std` builds — which include the
/// single-threaded zkVM guest (see the crate's dependency wiring in
/// `ethrex-common`, which builds this crate without the `std` feature).
///
/// `std::sync::OnceLock`'s atomics are pure overhead in the single-threaded zkVM
/// guest, so this mirrors `once_cell::unsync::OnceCell`: interior mutability
/// through a plain `UnsafeCell`, no atomics.
///
/// It is deliberately **not** `Sync` — there is no `unsafe impl Sync`, so the
/// `UnsafeCell` makes the type `!Sync` and the compiler forbids sharing it across
/// threads. That keeps it sound without assuming `no_std` implies a single thread:
/// a multi-threaded `no_std` consumer fails to compile instead of racing on the
/// cell.
#[cfg(not(feature = "std"))]
pub struct OnceLock<T>(core::cell::UnsafeCell<Option<T>>);

#[cfg(not(feature = "std"))]
impl<T> OnceLock<T> {
    #[inline]
    fn new() -> Self {
        Self(core::cell::UnsafeCell::new(None))
    }

    #[inline]
    fn get(&self) -> Option<&T> {
        unsafe { &*self.0.get() }.as_ref()
    }

    #[inline]
    fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
        match self.get_or_try_init(|| Ok::<T, core::convert::Infallible>(f())) {
            Ok(val) => val,
            Err(e) => match e {},
        }
    }

    #[inline]
    fn get_or_try_init<E>(&self, f: impl FnOnce() -> Result<T, E>) -> Result<&T, E> {
        if let Some(val) = self.get() {
            return Ok(val);
        }
        self.try_init(f)
    }

    #[inline]
    fn set(&self, value: T) -> Result<(), T> {
        match self.try_insert(value) {
            Ok(_) => Ok(()),
            Err((_, value)) => Err(value),
        }
    }

    #[inline]
    fn try_insert(&self, value: T) -> Result<&T, (&T, T)> {
        if let Some(old) = self.get() {
            return Err((old, value));
        }
        let slot = unsafe { &mut *self.0.get() };
        Ok(slot.insert(value))
    }

    #[inline]
    fn try_init<E>(&self, f: impl FnOnce() -> Result<T, E>) -> Result<&T, E> {
        let val = f()?;
        let slot = unsafe { &mut *self.0.get() };
        debug_assert!(slot.is_none());
        Ok(slot.insert(val))
    }

    #[inline]
    fn take(&mut self) -> Option<T> {
        self.0.get_mut().take()
    }
}

#[cfg(not(feature = "std"))]
impl<T: PartialEq> PartialEq for OnceLock<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

#[cfg(not(feature = "std"))]
impl<T> Default for OnceLock<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "std"))]
impl<T: Eq> Eq for OnceLock<T> {}

#[cfg(not(feature = "std"))]
impl<T: Clone> Clone for OnceLock<T> {
    #[inline]
    fn clone(&self) -> OnceLock<T> {
        match self.get() {
            Some(value) => OnceLock::from(value.clone()),
            None => OnceLock::new(),
        }
    }
}

#[cfg(not(feature = "std"))]
impl<T: core::fmt::Debug> core::fmt::Debug for OnceLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_tuple("OnceLock");
        match self.get() {
            Some(v) => d.field(v),
            None => d.field(&format_args!("<uninit>")),
        };
        d.finish()
    }
}

#[cfg(not(feature = "std"))]
impl<T> From<T> for OnceLock<T> {
    #[inline]
    fn from(value: T) -> Self {
        OnceLock(core::cell::UnsafeCell::new(Some(value)))
    }
}

pub use branch::BranchNode;
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};
pub use extension::ExtensionNode;
pub use leaf::LeafNode;
use rkyv::{
    de::Pooling,
    rancor::Source,
    ser::{Allocator, Sharing, Writer},
    validation::{ArchiveContext, SharedContext},
    with::Skip,
};

use ethrex_crypto::{Crypto, NativeCrypto};

use crate::{NodeRLP, TrieDB, error::TrieError, nibbles::Nibbles};

use super::{ValueRLP, node_hash::NodeHash};

/// A reference to a node.
///
/// Explicit rkyv bounds are needed because this is a recursive type, whose
/// bounds can't be automatically resolved.
#[derive(
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
#[rkyv(serialize_bounds(__S: Writer + Allocator + Sharing, __S::Error: Source))]
#[rkyv(deserialize_bounds(__D: Pooling, __D::Error: Source))]
#[rkyv(bytecheck(bounds(__C: ArchiveContext + SharedContext)))]
pub enum NodeRef {
    /// The node is embedded within the reference.
    Node(
        #[rkyv(omit_bounds)] Arc<Node>,
        #[rkyv(with = Skip)]
        #[serde(skip)]
        OnceLock<NodeHash>,
    ),
    /// The node is in the database, referenced by its hash.
    Hash(NodeHash),
}

impl NodeRef {
    /// Gets a shared reference to the inner node.
    /// Requires that the trie is in a consistent state, ie that all leaves being pointed are in the database.
    /// Outside of snapsync this should always be the case.
    pub fn get_node(&self, db: &dyn TrieDB, path: Nibbles) -> Result<Option<Arc<Node>>, TrieError> {
        match self {
            NodeRef::Node(node, _) => Ok(Some(node.clone())),
            NodeRef::Hash(hash @ NodeHash::Inline(_)) => {
                Ok(Some(Arc::new(Node::decode(hash.as_ref())?)))
            }
            NodeRef::Hash(_) => db
                .get(path)?
                .filter(|rlp| !rlp.is_empty())
                .map(|rlp| Ok(Arc::new(Node::decode(&rlp)?)))
                .transpose(),
        }
    }

    /// Gets a shared reference to the inner node, checking its hash.
    /// Returns `Ok(None)` if the hash is invalid.
    ///
    /// Uses `NativeCrypto` directly because this function is only reachable from
    /// native storage/sync paths (`get_root_node`, `get_proof`, `validate`,
    /// `verify_range`, trie iterator) — never from the guest program path, which
    /// traverses via `Node::get()`.
    pub fn get_node_checked(
        &self,
        db: &dyn TrieDB,
        path: Nibbles,
    ) -> Result<Option<Arc<Node>>, TrieError> {
        match self {
            NodeRef::Node(node, _) => Ok(Some(node.clone())),
            NodeRef::Hash(hash @ NodeHash::Inline(_)) => {
                Ok(Some(Arc::new(Node::decode(hash.as_ref())?)))
            }
            NodeRef::Hash(hash @ NodeHash::Hashed(_)) => {
                db.get(path)?
                    .filter(|rlp| !rlp.is_empty())
                    .and_then(|rlp| match Node::decode(&rlp) {
                        Ok(node) => (node.compute_hash(&NativeCrypto) == *hash)
                            .then_some(Ok(Arc::new(node))),
                        Err(err) => Some(Err(TrieError::RLPDecode(err))),
                    })
                    .transpose()
            }
        }
    }

    /// Gets a mutable shared reference to the inner node.
    ///
    /// # Caution
    ///
    /// 1. If more than one strong reference exists to this node, it will be cloned (see `Arc::make_mut`).
    /// 2. Mutating the inner node without updating parents can lead to trie inconsistencies.
    pub(crate) fn get_node_mut(
        &mut self,
        db: &dyn TrieDB,
        path: Nibbles,
    ) -> Result<Option<&mut Node>, TrieError> {
        match self {
            NodeRef::Node(node, _) => Ok(Some(Arc::make_mut(node))),
            NodeRef::Hash(hash @ NodeHash::Inline(_)) => {
                let node = Node::decode(hash.as_ref())?;
                *self = NodeRef::Node(Arc::new(node), OnceLock::from(*hash));
                self.get_node_mut(db, path)
            }
            NodeRef::Hash(hash @ NodeHash::Hashed(_)) => {
                let Some(node) = db
                    .get(path.clone())?
                    .filter(|rlp| !rlp.is_empty())
                    .map(|rlp| Node::decode(&rlp).map_err(TrieError::RLPDecode))
                    .transpose()?
                else {
                    return Ok(None);
                };
                *self = NodeRef::Node(Arc::new(node), OnceLock::from(*hash));
                self.get_node_mut(db, path)
            }
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            NodeRef::Node(_, _) => true,
            NodeRef::Hash(hash) => hash.is_valid(),
        }
    }

    pub fn commit(
        &mut self,
        path: Nibbles,
        acc: &mut Vec<(Nibbles, Vec<u8>)>,
        crypto: &dyn Crypto,
    ) -> NodeHash {
        match *self {
            NodeRef::Node(ref mut node, ref mut hash) => {
                if let Some(hash) = hash.get() {
                    return *hash;
                }
                match Arc::make_mut(node) {
                    Node::Branch(node) => {
                        for (choice, node) in &mut node.choices.iter_mut().enumerate() {
                            node.commit(path.append_new(choice as u8), acc, crypto);
                        }
                    }
                    Node::Extension(node) => {
                        node.child.commit(path.concat(&node.prefix), acc, crypto);
                    }
                    Node::Leaf(_) => {}
                }
                let mut buf = Vec::new();
                node.encode(&mut buf);
                let hash = *hash.get_or_init(|| NodeHash::from_encoded(&buf, crypto));
                if let Node::Leaf(leaf) = node.as_ref() {
                    acc.push((path.concat(&leaf.partial), leaf.value.clone()));
                }
                acc.push((path, buf));

                hash
            }
            NodeRef::Hash(hash) => hash,
        }
    }

    pub fn compute_hash(&self, crypto: &dyn Crypto) -> NodeHash {
        *self.compute_hash_ref(crypto)
    }

    pub fn compute_hash_ref(&self, crypto: &dyn Crypto) -> &NodeHash {
        match self {
            NodeRef::Node(node, hash) => hash.get_or_init(|| node.compute_hash(crypto)),
            NodeRef::Hash(hash) => hash,
        }
    }

    pub fn compute_hash_no_alloc(&self, buf: &mut Vec<u8>, crypto: &dyn Crypto) -> &NodeHash {
        match self {
            NodeRef::Node(node, hash) => {
                hash.get_or_init(|| node.compute_hash_no_alloc(buf, crypto))
            }
            NodeRef::Hash(hash) => hash,
        }
    }

    /// Memoizes this reference's subtrie hash, if there is anything to do.
    ///
    /// The guard is deliberately split from the recursive body. A branch node
    /// visits all 16 of its children, but the vast majority of child references
    /// are `NodeRef::Hash` or empty slots with nothing to memoize (measured on a
    /// mainnet block witness: ~93%). Because the body is recursive LLVM will not
    /// inline it, so keeping the guard in a separate `#[inline]` shell makes the
    /// overwhelmingly common no-op case a load and a branch at the call site
    /// instead of a full call.
    #[inline]
    pub fn memoize_hashes(&self, buf: &mut Vec<u8>, crypto: &dyn Crypto) {
        if let NodeRef::Node(node, hash) = &self
            && hash.get().is_none()
        {
            Self::memoize_hashes_uncached(node, hash, buf, crypto);
        }
    }

    /// Cold path of [`Self::memoize_hashes`]: this reference is an embedded node
    /// whose hash is not memoized yet, so descend into it and compute it.
    fn memoize_hashes_uncached(
        node: &Arc<Node>,
        hash: &OnceLock<NodeHash>,
        buf: &mut Vec<u8>,
        crypto: &dyn Crypto,
    ) {
        node.memoize_hashes(buf, crypto);
        let _ = hash.set(node.compute_hash_no_alloc(buf, crypto));
    }

    /// Resets the memoized hash of this Node
    ///
    /// This is used when mutating a node in place, in which case the memoized hash
    /// is not valid anymore.
    pub fn clear_hash(&mut self) {
        if let NodeRef::Node(_, hash) = self {
            hash.take();
        }
    }
}

impl Default for NodeRef {
    fn default() -> Self {
        Self::Hash(NodeHash::default())
    }
}

impl From<Node> for NodeRef {
    fn from(value: Node) -> Self {
        Self::Node(Arc::new(value), OnceLock::new())
    }
}

impl From<NodeHash> for NodeRef {
    fn from(value: NodeHash) -> Self {
        Self::Hash(value)
    }
}

impl From<Arc<Node>> for NodeRef {
    fn from(value: Arc<Node>) -> Self {
        Self::Node(value, OnceLock::new())
    }
}

impl PartialEq for NodeRef {
    fn eq(&self, other: &Self) -> bool {
        let mut buf = Vec::new();
        self.compute_hash_no_alloc(&mut buf, &NativeCrypto)
            == other.compute_hash_no_alloc(&mut buf, &NativeCrypto)
    }
}

pub enum ValueOrHash {
    Value(ValueRLP),
    Hash(NodeHash),
}

impl From<ValueRLP> for ValueOrHash {
    fn from(value: ValueRLP) -> Self {
        Self::Value(value)
    }
}

impl From<NodeHash> for ValueOrHash {
    fn from(value: NodeHash) -> Self {
        Self::Hash(value)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Deserialize,
    rkyv::Serialize,
    rkyv::Archive,
)]
/// A Node in an Ethereum Compatible Patricia Merkle Trie
pub enum Node {
    Branch(Box<BranchNode>),
    Extension(ExtensionNode),
    Leaf(LeafNode),
}

impl Default for Node {
    fn default() -> Self {
        // empty leaf node as a placeholder
        Self::Leaf(LeafNode {
            partial: Nibbles::from_bytes(&[]),
            value: Vec::new(),
        })
    }
}

impl From<Box<BranchNode>> for Node {
    fn from(val: Box<BranchNode>) -> Self {
        Node::Branch(val)
    }
}

impl From<BranchNode> for Node {
    fn from(val: BranchNode) -> Self {
        Node::Branch(Box::new(val))
    }
}

impl From<ExtensionNode> for Node {
    fn from(val: ExtensionNode) -> Self {
        Node::Extension(val)
    }
}

impl From<LeafNode> for Node {
    fn from(val: LeafNode) -> Self {
        Node::Leaf(val)
    }
}

impl Node {
    /// Retrieves a value from the subtrie originating from this node given its path
    pub fn get(&self, db: &dyn TrieDB, path: Nibbles) -> Result<Option<ValueRLP>, TrieError> {
        match self {
            Node::Branch(n) => n.get(db, path),
            Node::Extension(n) => n.get(db, path),
            Node::Leaf(n) => n.get(path),
        }
    }

    /// Inserts a value into the subtrie originating from this node.
    pub fn insert(
        &mut self,
        db: &dyn TrieDB,
        path: Nibbles,
        value: impl Into<ValueOrHash>,
    ) -> Result<(), TrieError> {
        let new_node = match self {
            Node::Branch(n) => {
                n.insert(db, path, value.into())?;
                Ok(None)
            }
            Node::Extension(n) => n.insert(db, path, value.into()),
            Node::Leaf(n) => n.insert(path, value.into()),
        };
        if let Some(new_node) = new_node? {
            *self = new_node;
        }
        Ok(())
    }

    /// Removes a value from the subtrie originating from this node given its path
    /// Returns a bool indicating if the new subtrie is empty, and the removed value if it existed in the subtrie
    pub fn remove(
        &mut self,
        db: &dyn TrieDB,
        path: Nibbles,
    ) -> Result<(bool, Option<ValueRLP>), TrieError> {
        let (new_root, value) = match self {
            Node::Branch(n) => n.remove(db, path),
            Node::Extension(n) => n.remove(db, path),
            Node::Leaf(n) => n.remove(path),
        }?;

        let is_trie_empty = new_root.is_none();
        if let Some(NodeRemoveResult::New(new_root)) = new_root {
            *self = new_root;
        }
        Ok((is_trie_empty, value))
    }

    /// Traverses own subtrie until reaching the node containing `path`
    /// Appends all encoded nodes traversed to `node_path` (including self)
    /// Only nodes with encoded len over or equal to 32 bytes are included
    pub fn get_path(
        &self,
        db: &dyn TrieDB,
        path: Nibbles,
        node_path: &mut Vec<Vec<u8>>,
    ) -> Result<(), TrieError> {
        match self {
            Node::Branch(n) => n.get_path(db, path, node_path),
            Node::Extension(n) => n.get_path(db, path, node_path),
            Node::Leaf(n) => n.get_path(node_path),
        }
    }

    /// Computes the node's hash
    pub fn compute_hash(&self, crypto: &dyn Crypto) -> NodeHash {
        let mut buf = Vec::new();
        self.memoize_hashes(&mut buf, crypto);
        match self {
            Node::Branch(n) => n.compute_hash_no_alloc(&mut buf, crypto),
            Node::Extension(n) => n.compute_hash_no_alloc(&mut buf, crypto),
            Node::Leaf(n) => n.compute_hash_no_alloc(&mut buf, crypto),
        }
    }

    /// Computes the node's hash
    pub fn compute_hash_no_alloc(&self, buf: &mut Vec<u8>, crypto: &dyn Crypto) -> NodeHash {
        self.memoize_hashes(buf, crypto);
        match self {
            Node::Branch(n) => n.compute_hash_no_alloc(buf, crypto),
            Node::Extension(n) => n.compute_hash_no_alloc(buf, crypto),
            Node::Leaf(n) => n.compute_hash_no_alloc(buf, crypto),
        }
    }

    /// Recursively memoizes the hashes of all nodes of the subtrie that has
    /// `self` as root (post-order traversal)
    pub fn memoize_hashes(&self, buf: &mut Vec<u8>, crypto: &dyn Crypto) {
        match self {
            Node::Branch(n) => {
                for child in &n.choices {
                    child.memoize_hashes(buf, crypto);
                }
            }
            Node::Extension(n) => n.child.memoize_hashes(buf, crypto),
            _ => {}
        }
    }

    /// Recursively encodes all embedded nodes of the subtrie that has
    /// `self` as root.
    ///
    /// This won't encode nodes which are not embedded in `self`.
    pub fn encode_subtrie(&self, encoded: &mut Vec<NodeRLP>) -> Result<(), TrieError> {
        match self {
            Node::Branch(node) => {
                for choice in &node.choices {
                    if let NodeRef::Node(choice, _) = choice {
                        choice.encode_subtrie(encoded)?;
                    }
                }
            }
            Node::Extension(node) => {
                if let NodeRef::Node(child, _) = &node.child {
                    child.encode_subtrie(encoded)?;
                }
            }
            Node::Leaf(_) => {}
        };

        encoded.push(self.encode_to_vec());
        Ok(())
    }
}

/// Used as return type for `Node` remove operations that may resolve into either:
/// - a mutation of the `Node`
/// - a new `Node`
pub enum NodeRemoveResult {
    Mutated,
    New(Node),
}
