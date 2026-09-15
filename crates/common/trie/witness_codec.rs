//! Compact witness wire format for trie nodes.
//!
//! Each witness node travels as one self-contained record:
//!
//! ```text
//! record := [version=0x01 u8][tag u8][hash 32B][payload]
//! tag: 0 = leaf, 1 = extension, 2 = branch
//! leaf payload:      [path_len u8][path compact bytes][value_len u16 LE][value]
//! extension payload: [path_len u8][path compact bytes][child ref]
//! branch payload:    [16 × child ref][value_len u16 LE][value]
//! child ref := [kind u8]
//!   kind 0: empty
//!   kind 1: hashed reference -> [hash 32B]
//!   kind 2: inline node      -> [len u8 (<32)][RLP bytes]
//! ```
//!
//! The format exists for zkVM guests: decoding is field extraction at fixed
//! offsets — no RLP parsing, no per-node allocation patterns driven by input
//! shape — and the node hash travels with the record, so the consumer does not
//! need to keccak the preimage to key or seed the node. See
//! [`decode_witness_node`] for the trust implications of the shipped hash.

use alloc::boxed::Box;
use alloc::vec::Vec;

use ethereum_types::H256;
use ethrex_crypto::NativeCrypto;

use crate::ValueRLP;
use crate::nibbles::Nibbles;
use crate::node::{BranchNode, ExtensionNode, LeafNode, Node, NodeRef};
use crate::node_hash::NodeHash;

const VERSION: u8 = 1;
const TAG_LEAF: u8 = 0;
const TAG_EXTENSION: u8 = 1;
const TAG_BRANCH: u8 = 2;

const REF_EMPTY: u8 = 0;
const REF_HASHED: u8 = 1;
const REF_INLINE: u8 = 2;
/// The child subtree follows in the stream (DFS pre-order): the parent's hash
/// for the child travels inline in this entry and the child's own record is the
/// next one in DFS order.
const REF_SUBTREE: u8 = 3;

const HEADER_LEN: usize = 2 + 32;

/// Encode one trie node as a witness record, appending to `out`.
///
/// `hash` must be the node's own hash (`NodeRef::compute_hash(..).finalize(..)`
/// of the reference pointing at this node); the caller computes it so this
/// function stays branch-free. Embedded (`NodeRef::Node`) children are
/// normalized to hash references via `NativeCrypto`, which is also how their
/// `OnceLock` hash slots get populated as a side effect.
pub fn encode_witness_node(node: &Node, hash: &H256, out: &mut Vec<u8>) {
    out.push(VERSION);
    let tag = match node {
        Node::Leaf(_) => TAG_LEAF,
        Node::Extension(_) => TAG_EXTENSION,
        Node::Branch(_) => TAG_BRANCH,
    };
    out.push(tag);
    out.extend_from_slice(hash.as_bytes());
    match node {
        Node::Leaf(leaf) => {
            push_nibbles(&leaf.partial, out);
            push_bytes(&leaf.value, out);
        }
        Node::Extension(ext) => {
            push_nibbles(&ext.prefix, out);
            push_ref(&ext.child, out);
        }
        Node::Branch(branch) => {
            for choice in &branch.choices {
                push_ref(choice, out);
            }
            push_bytes(&branch.value, out);
        }
    }
}

fn push_nibbles(nibbles: &Nibbles, out: &mut Vec<u8>) {
    // Host-side only; `encode_compact` allocates, which is fine here.
    let compact = nibbles.encode_compact();
    out.push(compact.len() as u8);
    out.extend_from_slice(&compact);
}

fn push_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn push_ref(child: &NodeRef, out: &mut Vec<u8>) {
    let hash = match child {
        NodeRef::Hash(hash) => Some(*hash),
        NodeRef::Node(_, _) if child.is_valid() => Some(child.compute_hash(&NativeCrypto)),
        _ => None,
    };
    match hash {
        None => out.push(REF_EMPTY),
        Some(NodeHash::Hashed(h)) => {
            out.push(REF_HASHED);
            out.extend_from_slice(h.as_bytes());
        }
        Some(NodeHash::Inline((data, len))) => {
            out.push(REF_INLINE);
            out.push(len);
            out.extend_from_slice(&data[..len as usize]);
        }
    }
}

/// Decode one witness record into `(shipped_hash, node)`.
///
/// # Trust model of the shipped hash
///
/// The record's hash is **not** recomputed from the payload here — that is the
/// whole point of the format (the guest avoids one keccak + one RLP encode per
/// node). Consumers key and hash-seed nodes by the shipped value, so a
/// malicious producer can attach wrong contents to a correct hash. This is
/// contained by the anchors of the stateless validation flow: the tries are
/// resolved by hash linkage starting from the *real* parent-header state root,
/// every read of witness state flows through those tries, and the
/// post-execution state root plus receipts root are checked against the block
/// header — so any content fake that influences the execution's public outputs
/// breaks those anchors. Contents of nodes the execution never touches carry
/// no consequence for the transition verdict. If a deployment wants strict
/// per-node binding, re-encode the decoded node and compare `keccak(rlp)`
/// against the shipped hash before use.
pub fn decode_witness_node(bytes: &[u8]) -> Result<(H256, Node), WitnessNodeError> {
    if bytes.len() < HEADER_LEN || bytes[0] != VERSION {
        return Err(WitnessNodeError::BadHeader);
    }
    let tag = bytes[1];
    let hash = H256::from_slice(&bytes[2..34]);
    let payload = &bytes[HEADER_LEN..];
    let (node, rest) = match tag {
        TAG_LEAF => {
            let (partial, rest) = take_nibbles(payload)?;
            let (value, rest) = take_bytes(rest)?;
            (Node::Leaf(LeafNode::new(partial, value)), rest)
        }
        TAG_EXTENSION => {
            let (prefix, rest) = take_nibbles(payload)?;
            let (child, rest) = take_ref(rest)?;
            (Node::Extension(ExtensionNode::new(prefix, child)), rest)
        }
        TAG_BRANCH => {
            let mut rest = payload;
            let mut choices = BranchNode::EMPTY_CHOICES;
            for choice in &mut choices {
                let (child, r) = take_ref(rest)?;
                *choice = child;
                rest = r;
            }
            let (value, rest) = take_bytes(rest)?;
            (
                Node::Branch(Box::new(BranchNode::new_with_value(choices, value))),
                rest,
            )
        }
        _ => return Err(WitnessNodeError::BadTag(tag)),
    };
    if !rest.is_empty() {
        return Err(WitnessNodeError::TrailingBytes);
    }
    Ok((hash, node))
}

fn take_nibbles(bytes: &[u8]) -> Result<(Nibbles, &[u8]), WitnessNodeError> {
    let (&len, rest) = bytes.split_first().ok_or(WitnessNodeError::Truncated)?;
    let len = len as usize;
    if rest.len() < len {
        return Err(WitnessNodeError::Truncated);
    }
    Ok((Nibbles::decode_compact(&rest[..len]), &rest[len..]))
}

fn take_bytes(bytes: &[u8]) -> Result<(ValueRLP, &[u8]), WitnessNodeError> {
    if bytes.len() < 2 {
        return Err(WitnessNodeError::Truncated);
    }
    let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let rest = &bytes[2..];
    if rest.len() < len {
        return Err(WitnessNodeError::Truncated);
    }
    Ok((rest[..len].to_vec(), &rest[len..]))
}

fn take_ref(bytes: &[u8]) -> Result<(NodeRef, &[u8]), WitnessNodeError> {
    let (&kind, rest) = bytes.split_first().ok_or(WitnessNodeError::Truncated)?;
    match kind {
        REF_EMPTY => Ok((NodeRef::default(), rest)),
        REF_HASHED => {
            if rest.len() < 32 {
                return Err(WitnessNodeError::Truncated);
            }
            Ok((
                NodeRef::Hash(NodeHash::Hashed(H256::from_slice(&rest[..32]))),
                &rest[32..],
            ))
        }
        REF_INLINE => {
            let (&len, rest) = rest.split_first().ok_or(WitnessNodeError::Truncated)?;
            let len = len as usize;
            if len >= 32 || rest.len() < len {
                return Err(WitnessNodeError::Truncated);
            }
            let mut data = [0u8; 31];
            data[..len].copy_from_slice(&rest[..len]);
            Ok((
                NodeRef::Hash(NodeHash::Inline((data, len as u8))),
                &rest[len..],
            ))
        }
        // A subtree-linked entry carries the same hash as a plain hashed
        // reference; only the stream-order consumer recurses on it.
        REF_SUBTREE => {
            if rest.len() < 32 {
                return Err(WitnessNodeError::Truncated);
            }
            Ok((
                NodeRef::Hash(NodeHash::Hashed(H256::from_slice(&rest[..32]))),
                &rest[32..],
            ))
        }
        _ => Err(WitnessNodeError::BadRefKind(kind)),
    }
}

// ── DFS stream emission (host side) ─────────────────────────────────────────

/// Write one child reference into `record`; embedded children are appended to
/// `subtrees` so the caller emits their records right after, in DFS order.
fn push_child_ref<'n>(
    child: &'n NodeRef,
    record: &mut Vec<u8>,
    subtrees: &mut Vec<(&'n Node, H256)>,
) {
    match child {
        NodeRef::Node(child_node, _) => match child.compute_hash(&NativeCrypto) {
            NodeHash::Hashed(h) => {
                record.push(REF_SUBTREE);
                record.extend_from_slice(h.as_bytes());
                subtrees.push((child_node.as_ref(), h));
            }
            NodeHash::Inline((data, len)) => {
                record.push(REF_INLINE);
                record.push(len);
                record.extend_from_slice(&data[..len as usize]);
            }
        },
        NodeRef::Hash(NodeHash::Hashed(h)) => {
            record.push(REF_HASHED);
            record.extend_from_slice(h.as_bytes());
        }
        NodeRef::Hash(NodeHash::Inline((data, len))) => {
            record.push(REF_INLINE);
            record.push(*len);
            record.extend_from_slice(&data[..*len as usize]);
        }
    }
}

/// Emit `root` and every embedded descendant as witness records in DFS
/// pre-order: each record is followed, contiguously and in child order, by the
/// records of its embedded subtrees. Children still referenced by hash (not
/// embedded in `root`) are written as terminal [`REF_HASHED`] entries and have
/// no records of their own. This is the order [`decode_subtree_records`]
/// consumes.
///
/// `root_hash` is the hash of `root` itself; embedded children's hashes are
/// taken from their (already seeded, or here memoized) hash slots.
pub fn encode_subtree_records(root: &Node, root_hash: &H256, records: &mut Vec<Vec<u8>>) {
    fn rec(node: &Node, hash: &H256, records: &mut Vec<Vec<u8>>) {
        let mut record = Vec::new();
        record.push(VERSION);
        record.push(match node {
            Node::Leaf(_) => TAG_LEAF,
            Node::Extension(_) => TAG_EXTENSION,
            Node::Branch(_) => TAG_BRANCH,
        });
        record.extend_from_slice(hash.as_bytes());

        // Embedded children whose subtrees must be emitted right after this
        // record, in order.
        let mut subtrees: Vec<(&Node, H256)> = Vec::new();
        match node {
            Node::Leaf(leaf) => {
                push_nibbles(&leaf.partial, &mut record);
                push_bytes(&leaf.value, &mut record);
            }
            Node::Extension(ext) => {
                push_nibbles(&ext.prefix, &mut record);
                push_child_ref(&ext.child, &mut record, &mut subtrees);
            }
            Node::Branch(branch) => {
                for choice in &branch.choices {
                    push_child_ref(choice, &mut record, &mut subtrees);
                }
                push_bytes(&branch.value, &mut record);
            }
        }
        records.push(record);
        for (child_node, child_hash) in subtrees {
            rec(child_node, &child_hash, records);
        }
    }
    rec(root, root_hash, records);
}

// ── DFS stream decoding (guest side) ────────────────────────────────────────

/// Rebuild one trie from records in DFS pre-order (as emitted by
/// [`encode_subtree_records`]), starting at `*pos` and advancing it past every
/// record consumed. Returns the root reference — with its hash slot pre-seeded
/// from the shipped hashes — and the shipped root hash. When `collect_leaves`
/// is set, every leaf's full path and value is also pushed to `leaves` (used
/// to discover accounts and their storage roots while building the state
/// trie).
///
/// Every `NodeRef` produced is seeded with the node's shipped hash, so a
/// `Trie` built from the result needs no upfront `hash_no_commit`. The parent
/// entry's hash for each child is checked against the child record's own
/// shipped hash, so the stream's structure is self-consistent; the caller is
/// expected to anchor the returned root hash (e.g. against the parent header's
/// state root). See [`decode_witness_node`] for the trust model.
pub fn decode_subtree_records(
    records: &[Vec<u8>],
    pos: &mut usize,
    path: &Nibbles,
    mut leaves: Option<&mut Vec<(Nibbles, ValueRLP)>>,
) -> Result<(NodeRef, H256), WitnessNodeError> {
    use alloc::sync::Arc;

    use crate::node::OnceLock;

    fn parse_node(
        bytes: &[u8],
    ) -> Result<
        (
            H256,
            u8,
            &[u8], // payload after the header
        ),
        WitnessNodeError,
    > {
        if bytes.len() < HEADER_LEN || bytes[0] != VERSION {
            return Err(WitnessNodeError::BadHeader);
        }
        Ok((
            H256::from_slice(&bytes[2..34]),
            bytes[1],
            &bytes[HEADER_LEN..],
        ))
    }

    fn build(
        records: &[Vec<u8>],
        pos: &mut usize,
        path: &Nibbles,
        leaves: &mut Option<&mut Vec<(Nibbles, ValueRLP)>>,
        expected_hash: Option<&H256>,
    ) -> Result<(NodeRef, H256), WitnessNodeError> {
        let record = records.get(*pos).ok_or(WitnessNodeError::Truncated)?;
        *pos += 1;
        let (hash, tag, payload) = parse_node(record)?;
        if let Some(expected) = expected_hash
            && expected != &hash
        {
            return Err(WitnessNodeError::HashMismatch);
        }
        let seeded =
            |node: Node, hash: NodeHash| NodeRef::Node(Arc::new(node), OnceLock::from(hash));
        match tag {
            TAG_LEAF => {
                let (partial, rest) = take_nibbles(payload)?;
                let (value, rest) = take_bytes(rest)?;
                if !rest.is_empty() {
                    return Err(WitnessNodeError::TrailingBytes);
                }
                if let Some(leaves) = leaves {
                    let full_path = path.concat(&partial);
                    leaves.push((full_path, value.clone()));
                }
                Ok((
                    seeded(
                        Node::Leaf(LeafNode::new(partial, value)),
                        NodeHash::Hashed(hash),
                    ),
                    hash,
                ))
            }
            TAG_EXTENSION => {
                let (prefix, rest) = take_nibbles(payload)?;
                let (child, rest) =
                    take_ref_or_subtree(records, pos, &path.concat(&prefix), leaves, rest)?;
                if !rest.is_empty() {
                    return Err(WitnessNodeError::TrailingBytes);
                }
                Ok((
                    seeded(
                        Node::Extension(ExtensionNode::new(prefix, child)),
                        NodeHash::Hashed(hash),
                    ),
                    hash,
                ))
            }
            TAG_BRANCH => {
                let mut rest = payload;
                let mut choices = BranchNode::EMPTY_CHOICES;
                for (i, choice) in choices.iter_mut().enumerate() {
                    let (child, r) =
                        take_ref_or_subtree(records, pos, &path.append_new(i as u8), leaves, rest)?;
                    *choice = child;
                    rest = r;
                }
                let (value, rest) = take_bytes(rest)?;
                if !rest.is_empty() {
                    return Err(WitnessNodeError::TrailingBytes);
                }
                Ok((
                    seeded(
                        Node::Branch(Box::new(BranchNode::new_with_value(choices, value))),
                        NodeHash::Hashed(hash),
                    ),
                    hash,
                ))
            }
            _ => Err(WitnessNodeError::BadTag(tag)),
        }
    }

    fn take_ref_or_subtree<'a>(
        records: &[Vec<u8>],
        pos: &mut usize,
        child_path: &Nibbles,
        leaves: &mut Option<&mut Vec<(Nibbles, ValueRLP)>>,
        bytes: &'a [u8],
    ) -> Result<(NodeRef, &'a [u8]), WitnessNodeError> {
        let (&kind, rest) = bytes.split_first().ok_or(WitnessNodeError::Truncated)?;
        match kind {
            REF_SUBTREE => {
                if rest.len() < 32 {
                    return Err(WitnessNodeError::Truncated);
                }
                let child_hash = H256::from_slice(&rest[..32]);
                let (child, _) = build(records, pos, child_path, leaves, Some(&child_hash))?;
                Ok((child, &rest[32..]))
            }
            _ => take_ref(bytes),
        }
    }

    build(records, pos, path, &mut leaves, None)
}

#[derive(Debug, PartialEq, Eq)]
pub enum WitnessNodeError {
    BadHeader,
    BadTag(u8),
    BadRefKind(u8),
    Truncated,
    TrailingBytes,
    HashMismatch,
}

impl core::fmt::Display for WitnessNodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadHeader => write!(f, "bad witness node header"),
            Self::BadTag(tag) => write!(f, "bad witness node tag {tag}"),
            Self::BadRefKind(kind) => write!(f, "bad witness child ref kind {kind}"),
            Self::Truncated => write!(f, "truncated witness node record"),
            Self::TrailingBytes => write!(f, "trailing bytes in witness node record"),
            Self::HashMismatch => {
                write!(f, "child record hash does not match the parent's reference")
            }
        }
    }
}

impl core::error::Error for WitnessNodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    fn hash_of(node: &Node) -> H256 {
        NodeRef::from(node.clone())
            .compute_hash(&NativeCrypto)
            .finalize(&NativeCrypto)
    }

    #[test]
    fn roundtrip_leaf() {
        let node = Node::Leaf(LeafNode::new(
            Nibbles::from_bytes(&[0xab, 0xcd]),
            vec![0xde, 0xad, 0xbe, 0xef],
        ));
        let hash = hash_of(&node);
        let mut record = Vec::new();
        encode_witness_node(&node, &hash, &mut record);
        let (decoded_hash, decoded) = decode_witness_node(&record).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded, node);
    }

    #[test]
    fn roundtrip_extension_hashed_child() {
        let child = NodeRef::Hash(NodeHash::Hashed(H256::repeat_byte(0x11)));
        let node = Node::Extension(ExtensionNode::new(Nibbles::from_bytes(&[0x01]), child));
        let hash = hash_of(&node);
        let mut record = Vec::new();
        encode_witness_node(&node, &hash, &mut record);
        let (decoded_hash, decoded) = decode_witness_node(&record).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded, node);
    }

    #[test]
    fn roundtrip_branch_mixed_children() {
        let mut choices = BranchNode::EMPTY_CHOICES;
        choices[0] = NodeRef::Hash(NodeHash::Hashed(H256::repeat_byte(0x22)));
        let mut inline = [0u8; 31];
        inline[..3].copy_from_slice(&[0xc0, 0x01, 0x02]);
        choices[5] = NodeRef::Hash(NodeHash::Inline((inline, 3)));
        let node = Node::Branch(Box::new(BranchNode::new_with_value(choices, Vec::new())));
        let hash = hash_of(&node);
        let mut record = Vec::new();
        encode_witness_node(&node, &hash, &mut record);
        let (decoded_hash, decoded) = decode_witness_node(&record).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded, node);
    }

    #[test]
    fn rejects_truncation_and_garbage() {
        assert_eq!(decode_witness_node(&[]), Err(WitnessNodeError::BadHeader));
        let mut truncated = vec![VERSION, TAG_LEAF];
        truncated.extend_from_slice(&[0xaa; 32]);
        assert!(matches!(
            decode_witness_node(&truncated),
            Err(WitnessNodeError::Truncated)
        ));
        let mut record = vec![VERSION, 9];
        record.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            decode_witness_node(&record),
            Err(WitnessNodeError::BadTag(9))
        );
    }

    #[test]
    fn subtree_stream_roundtrip_with_seeds() {
        use alloc::sync::Arc;

        let leaf = |nibble: u8, value: u8| {
            Node::Leaf(LeafNode::new(
                Nibbles::from_bytes(&[nibble]),
                vec![value; 40],
            ))
        };
        let hash_of = |node: &Node| {
            NodeRef::from(node.clone())
                .compute_hash(&NativeCrypto)
                .finalize(&NativeCrypto)
        };

        let leaf_a = leaf(0x01, 0xaa);
        let leaf_b = leaf(0x02, 0xbb);
        let hash_a = hash_of(&leaf_a);
        let hash_b = hash_of(&leaf_b);

        let mut choices = BranchNode::EMPTY_CHOICES;
        choices[3] = NodeRef::Node(Arc::new(leaf_a.clone()), Default::default());
        choices[7] = NodeRef::Hash(NodeHash::Hashed(hash_b));
        let branch = Node::Branch(Box::new(BranchNode::new(choices)));
        let branch_hash = hash_of(&branch);

        let mut records = Vec::new();
        encode_subtree_records(&branch, &branch_hash, &mut records);
        // Root + the one embedded child; the hash-terminal child has no record.
        assert_eq!(records.len(), 2);

        let mut pos = 0;
        let mut leaves = Vec::new();
        let (root_ref, root_hash) =
            decode_subtree_records(&records, &mut pos, &Nibbles::default(), Some(&mut leaves))
                .unwrap();
        assert_eq!(pos, records.len());
        assert_eq!(root_hash, branch_hash);
        assert_eq!(leaves.len(), 1);

        // The root seed matches the shipped hash, and the embedded child was
        // rebuilt as a Node with its own seed; the terminal child stayed a
        // hash reference.
        let NodeRef::Node(root_node, root_seed) = root_ref else {
            panic!("expected embedded root");
        };
        assert_eq!(root_seed.into_inner(), Some(NodeHash::Hashed(branch_hash)));
        let Node::Branch(decoded_branch) = root_node.as_ref() else {
            panic!("expected branch");
        };
        assert!(
            matches!(&decoded_branch.choices[3], NodeRef::Node(node, seed) if node.as_ref() == &leaf_a && seed.get() == Some(&NodeHash::Hashed(hash_a)))
        );
        assert!(
            matches!(&decoded_branch.choices[7], NodeRef::Hash(NodeHash::Hashed(h)) if *h == hash_b)
        );
    }
}
