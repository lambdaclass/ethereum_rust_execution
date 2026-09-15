#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec::Vec};
use core::array;

// Contains RLP encoding and decoding implementations for Trie Nodes
// This encoding is only used to store the nodes in the DB, it is not the encoding used for hash computation
use ethrex_rlp::{
    constants::RLP_NULL,
    decode::{RLPDecode, decode_bytes},
    encode::{RLPEncode, encode_list_prefix},
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

use ethrex_crypto::NativeCrypto;

use super::node::{BranchNode, ExtensionNode, LeafNode, Node};
use crate::{Nibbles, NodeHash};

// SAFETY: `NativeCrypto` is used here instead of a `&dyn Crypto` parameter because
// `RLPEncode` is a fixed trait signature that cannot accept extra parameters.
// This is safe in the `commit()` path: `NodeRef::commit()` recursively populates
// child `OnceLock` hashes before calling `encode()`, so `compute_hash_ref` returns
// cached values without invoking keccak. If `encode()` were called on uncommitted
// nodes (e.g. from `put_batch_no_alloc`), `NativeCrypto` would be used and the
// result stored in the `OnceLock` — but this only happens in native storage paths
// where `NativeCrypto` is the correct provider.
impl RLPEncode for BranchNode {
    fn encode(&self, buf: &mut Vec<u8>) {
        let value_len = <[u8] as RLPEncode>::length(&self.value);
        let payload_len = self.choices.iter().fold(value_len, |acc, child| {
            acc + RLPEncode::length(child.compute_hash_ref(&NativeCrypto))
        });

        encode_list_prefix(payload_len, buf);
        for child in self.choices.iter() {
            match child.compute_hash_ref(&NativeCrypto) {
                NodeHash::Hashed(hash) => hash.0.encode(buf),
                NodeHash::Inline((_, 0)) => buf.push(RLP_NULL),
                NodeHash::Inline((encoded, len)) => {
                    buf.extend_from_slice(&encoded[..*len as usize])
                }
            }
        }
        <[u8] as RLPEncode>::encode(&self.value, buf);
    }

    // Duplicated to prealloc the buffer and avoid calculating the payload length twice
    fn encode_to_vec(&self) -> Vec<u8> {
        let value_len = <[u8] as RLPEncode>::length(&self.value);
        let choices_len = self.choices.iter().fold(0, |acc, child| {
            acc + RLPEncode::length(child.compute_hash_ref(&NativeCrypto))
        });
        let payload_len = choices_len + value_len;

        let mut buf: Vec<u8> = Vec::with_capacity(payload_len + 3); // 3 byte prefix headroom

        encode_list_prefix(payload_len, &mut buf);
        for child in self.choices.iter() {
            match child.compute_hash_ref(&NativeCrypto) {
                NodeHash::Hashed(hash) => hash.0.encode(&mut buf),
                NodeHash::Inline((_, 0)) => buf.push(RLP_NULL),
                NodeHash::Inline((encoded, len)) => {
                    buf.extend_from_slice(&encoded[..*len as usize])
                }
            }
        }
        <[u8] as RLPEncode>::encode(&self.value, &mut buf);

        buf
    }
}

impl RLPEncode for ExtensionNode {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut encoder = Encoder::new(buf).encode_bytes(&self.prefix.encode_compact());
        encoder = self.child.compute_hash(&NativeCrypto).encode(encoder);
        encoder.finish();
    }
}

impl RLPEncode for LeafNode {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_bytes(&self.partial.encode_compact())
            .encode_bytes(&self.value)
            .finish()
    }
}

impl RLPEncode for Node {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Node::Branch(n) => n.encode(buf),
            Node::Extension(n) => n.encode(buf),
            Node::Leaf(n) => n.encode(buf),
        }
    }
}

impl RLPDecode for Node {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let mut rlp_items_len = 0;
        let mut rlp_items: [Option<&[u8]>; 17] = Default::default();
        let mut decoder = Decoder::new(rlp)?;
        let mut item;
        // Get encoded fields

        // Check if we reached the end or if we decoded more items than the ones we need
        while !decoder.is_done() && rlp_items_len < 17 {
            (item, decoder) = decoder.get_encoded_item_ref()?;
            rlp_items[rlp_items_len] = Some(item);
            rlp_items_len += 1;
        }
        if !decoder.is_done() {
            return Err(RLPDecodeError::Custom(
                "Invalid arg count for Node, expected 2 or 17, got more than 17".to_string(),
            ));
        }
        // Deserialize into node depending on the available fields
        let node = match rlp_items_len {
            // Leaf or Extension Node
            2 => {
                let (path, _) = decode_bytes(rlp_items[0].expect("we already checked the length"))?;
                let path = Nibbles::decode_compact(path);
                if path.is_leaf() {
                    // Decode as Leaf
                    let (value, _) =
                        decode_bytes(rlp_items[1].expect("we already checked the length"))?;
                    LeafNode {
                        partial: path,
                        value: value.to_vec(),
                    }
                    .into()
                } else {
                    // Decode as Extension
                    ExtensionNode {
                        prefix: path,
                        child: decode_child(rlp_items[1].expect("we already checked the length"))
                            .into(),
                    }
                    .into()
                }
            }
            // Branch Node
            17 => {
                let choices = array::from_fn(|i| {
                    decode_child(rlp_items[i].expect("we already checked the length")).into()
                });
                let (value, _) =
                    decode_bytes(rlp_items[16].expect("we already checked the length"))?;
                BranchNode {
                    choices,
                    value: value.to_vec(),
                }
                .into()
            }
            n => {
                return Err(RLPDecodeError::Custom(format!(
                    "Invalid arg count for Node, expected 2 or 17, got {n}"
                )));
            }
        };
        Ok((node, decoder.finish()?))
    }
}

fn decode_child(rlp: &[u8]) -> NodeHash {
    match decode_bytes(rlp) {
        Ok((hash, &[])) if hash.len() == 32 => NodeHash::from_slice(hash),
        Ok((&[], &[])) => NodeHash::default(),
        _ => NodeHash::from_slice(rlp),
    }
}
