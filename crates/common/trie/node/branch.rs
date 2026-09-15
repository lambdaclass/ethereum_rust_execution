#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::mem;

use ethrex_crypto::{Crypto, NativeCrypto};
use ethrex_rlp::encode::RLPEncode;

use crate::{
    InconsistentTreeError, TrieDB, ValueRLP, error::TrieError, nibbles::Nibbles,
    node::NodeRemoveResult, node_hash::NodeHash,
};

use super::{ExtensionNode, LeafNode, Node, NodeRef, ValueOrHash};

/// Branch Node of an an Ethereum Compatible Patricia Merkle Trie
/// Contains the node's value and the hash of its children nodes
#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct BranchNode {
    pub choices: [NodeRef; 16],
    pub value: ValueRLP,
}

impl BranchNode {
    const EMPTY_REF: NodeRef = NodeRef::Hash(NodeHash::Inline(([0; 31], 0)));

    /// Empty choice array for more convenient node-building
    pub const EMPTY_CHOICES: [NodeRef; 16] = [Self::EMPTY_REF; 16];

    /// Creates a new branch node given its children, without any stored value
    pub fn new(choices: [NodeRef; 16]) -> Self {
        Self {
            choices,
            value: Default::default(),
        }
    }

    /// Creates a new branch node given its children and value
    pub const fn new_with_value(choices: [NodeRef; 16], value: ValueRLP) -> Self {
        Self { choices, value }
    }

    /// Updates the node's path and value
    pub fn update(&mut self, new_value: ValueRLP) {
        self.value = new_value;
    }

    /// Retrieves a value from the subtrie originating from this node given its path
    pub fn get(&self, db: &dyn TrieDB, mut path: Nibbles) -> Result<Option<ValueRLP>, TrieError> {
        // If path is at the end, return to its own value if present.
        // Otherwise, check the corresponding choice and delegate accordingly if present.
        if let Some(choice) = path.next_choice() {
            // Delegate to children if present
            let child_ref = &self.choices[choice];
            if child_ref.is_valid() {
                let child_node = child_ref.get_node(db, path.current())?.ok_or_else(|| {
                    TrieError::InconsistentTree(Box::new(
                        InconsistentTreeError::NodeNotFoundOnBranchNode(
                            child_ref
                                .compute_hash(&NativeCrypto)
                                .finalize(&NativeCrypto),
                            self.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                            path.current(),
                        ),
                    ))
                })?;
                child_node.get(db, path)
            } else {
                Ok(None)
            }
        } else {
            // Return internal value if present.
            Ok((!self.value.is_empty()).then_some(self.value.clone()))
        }
    }

    /// Inserts a value into the subtrie originating from this node
    pub fn insert(
        &mut self,
        db: &dyn TrieDB,
        mut path: Nibbles,
        value: ValueOrHash,
    ) -> Result<(), TrieError> {
        // If path is at the end, insert or replace its own value.
        // Otherwise, check the corresponding choice and insert or delegate accordingly.
        if let Some(choice) = path.next_choice() {
            match (&mut self.choices[choice], value) {
                // Create new child (leaf node)
                (choice_ref, ValueOrHash::Value(value)) if !choice_ref.is_valid() => {
                    let new_leaf = LeafNode::new(path, value);
                    *choice_ref = Node::from(new_leaf).into()
                }
                // Insert into existing child and then update it
                (choice_ref, ValueOrHash::Value(value)) => {
                    let Some(choice_node) = choice_ref.get_node_mut(db, path.current())? else {
                        return Err(TrieError::InconsistentTree(Box::new(
                            InconsistentTreeError::NodeNotFoundOnBranchNode(
                                choice_ref
                                    .compute_hash(&NativeCrypto)
                                    .finalize(&NativeCrypto),
                                self.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                                path.current(),
                            ),
                        )));
                    };

                    choice_node.insert(db, path, value)?;
                    choice_ref.clear_hash();
                }
                // Insert external node hash if there are no overrides.
                (choice_ref, value @ ValueOrHash::Hash(hash)) => {
                    if !choice_ref.is_valid() {
                        *choice_ref = hash.into();
                    } else if path.is_empty() {
                        return Err(TrieError::Verify(
                            "attempt to override proof node with external hash".to_string(),
                        ));
                    } else {
                        let Some(choice_node) = choice_ref.get_node_mut(db, path.current())? else {
                            return Err(TrieError::InconsistentTree(Box::new(
                                InconsistentTreeError::NodeNotFoundOnBranchNode(
                                    choice_ref
                                        .compute_hash(&NativeCrypto)
                                        .finalize(&NativeCrypto),
                                    self.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                                    path.current(),
                                ),
                            )));
                        };
                        choice_node.insert(db, path, value)?;
                        choice_ref.clear_hash();
                    }
                }
            }
        } else if let ValueOrHash::Value(value) = value {
            // Insert into self
            self.update(value);
        } else {
            // Value in branches don't happen in our use-case.
            todo!("handle override case (error?)")
        }

        Ok(())
    }

    /// Removes a value from the subtrie originating from this node given its path
    /// Returns the new root of the subtrie (or a `Mutated` variant if the new root is `self`)
    /// and the removed value if it existed in the subtrie.
    pub fn remove(
        &mut self,
        db: &dyn TrieDB,
        mut path: Nibbles,
    ) -> Result<(Option<NodeRemoveResult>, Option<ValueRLP>), TrieError> {
        /* Possible flow paths:
            Step 1: Removal
                Branch { [ ... ] Value } -> Branch { [...], None, None } (remove from self)
                Branch { [ childA, ... ], Value } -> Branch { [childA', ... ], Value } (remove from child)

            Step 2: Restructure
                [0 children]
                Branch { [], Value } -> Leaf { Value } (no children, with value)
                Branch { [], None } -> Branch { [], None } (no children, no value)
                [1 child]
                Branch { [ ExtensionChild], _ , _ } -> Extension { ChoiceIndex+ExtensionChildPrefx, ExtensionChildChild }
                Branch { [ BranchChild ], None } -> Extension { ChoiceIndex, BranchChild }
                Branch { [ LeafChild], None } -> LeafChild
                Branch { [LeafChild], Value } -> Branch { [ LeafChild ], Value }
                [+1 children]
                Branch { [childA, childB, ... ], None } ->   Branch { [childA, childB, ... ], None }
        */
        let base_path = path.clone();

        // Step 1: Remove value
        // Check if the value is located in a child subtrie
        let value = if let Some(choice_index) = path.next_choice() {
            if self.choices[choice_index].is_valid() {
                let Some(child_node) =
                    self.choices[choice_index].get_node_mut(db, path.current())?
                else {
                    return Err(TrieError::InconsistentTree(Box::new(
                        InconsistentTreeError::NodeNotFoundOnBranchNode(
                            self.choices[choice_index]
                                .compute_hash(&NativeCrypto)
                                .finalize(&NativeCrypto),
                            self.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                            path.current(),
                        ),
                    )));
                };

                // Remove value from child node
                let (empty_trie, old_value) = child_node.remove(db, path.clone())?;
                if empty_trie {
                    // Remove child hash if the child subtrie was removed in the process
                    self.choices[choice_index] = NodeHash::default().into();
                }
                self.choices[choice_index].clear_hash();
                old_value
            } else {
                None
            }
        } else {
            // Remove own value (if it has one) and return it
            if !self.value.is_empty() {
                Some(mem::take(&mut self.value))
            } else {
                None
            }
        };

        // Step 2: Restructure self
        let mut children = self
            .choices
            .iter_mut()
            .enumerate()
            .filter(|(_, child)| child.is_valid())
            .collect::<Vec<_>>();
        let new_node = match (children.len(), !self.value.is_empty()) {
            // If this node still has a value but no longer has children, convert it into a leaf node
            (0, true) => NodeRemoveResult::New(
                LeafNode::new(Nibbles::from_hex(vec![16]), mem::take(&mut self.value)).into(),
            ),
            // If this node doesn't have a value and has only one child, replace it with its child node
            (1, false) => {
                let (choice_index, child_ref) = children.get_mut(0).unwrap();
                let Some(child) = child_ref
                    .get_node_mut(db, base_path.current().append_new(*choice_index as u8))?
                else {
                    return Err(TrieError::InconsistentTree(Box::new(
                        InconsistentTreeError::NodeNotFoundOnBranchNode(
                            child_ref
                                .compute_hash(&NativeCrypto)
                                .finalize(&NativeCrypto),
                            self.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                            base_path.current(),
                        ),
                    )));
                };

                let node = match child {
                    // Replace self with an extension node leading to the child
                    Node::Branch(_) => ExtensionNode::new(
                        Nibbles::from_hex(vec![*choice_index as u8]),
                        child_ref.clone(),
                    )
                    .into(),
                    // Replace self with the child extension node, updating its path in the process
                    Node::Extension(extension_node) => {
                        let mut extension_node = extension_node.take();
                        extension_node.prefix.prepend(*choice_index as u8);
                        extension_node.into()
                    }
                    Node::Leaf(leaf) => {
                        let mut leaf = leaf.take();
                        leaf.partial.prepend(*choice_index as u8);
                        leaf.into()
                    }
                };
                NodeRemoveResult::New(node)
            }
            // Return the updated node
            _ => NodeRemoveResult::Mutated,
        };
        Ok((Some(new_node), value))
    }

    /// Computes the node's hash
    pub fn compute_hash(&self, crypto: &dyn Crypto) -> NodeHash {
        self.compute_hash_no_alloc(&mut vec![], crypto)
    }

    /// Computes the node's hash, using the provided buffer
    pub fn compute_hash_no_alloc(&self, buf: &mut Vec<u8>, crypto: &dyn Crypto) -> NodeHash {
        buf.clear();
        RLPEncode::encode(self, buf);
        let hash = NodeHash::from_encoded(buf, crypto);
        buf.clear();
        hash
    }

    /// Traverses own subtrie until reaching the node containing `path`
    /// Appends all encoded nodes traversed to `node_path` (including self)
    /// Only nodes with encoded len over or equal to 32 bytes are included
    pub fn get_path(
        &self,
        db: &dyn TrieDB,
        mut path: Nibbles,
        node_path: &mut Vec<Vec<u8>>,
    ) -> Result<(), TrieError> {
        // Add self to node_path (if not inlined in parent)
        let encoded = self.encode_to_vec();
        if encoded.len() >= 32 {
            node_path.push(encoded);
        };
        // Check the corresponding choice and delegate accordingly if present.
        if let Some(choice) = path.next_choice() {
            // Continue to child
            let child_ref = &self.choices[choice];
            if child_ref.is_valid() {
                let child_node = child_ref.get_node(db, path.current())?.ok_or_else(|| {
                    TrieError::InconsistentTree(Box::new(
                        InconsistentTreeError::NodeNotFoundOnBranchNode(
                            child_ref
                                .compute_hash(&NativeCrypto)
                                .finalize(&NativeCrypto),
                            self.compute_hash(&NativeCrypto).finalize(&NativeCrypto),
                            path.current(),
                        ),
                    ))
                })?;
                child_node.get_path(db, path, node_path)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ethereum_types::H256;
    use ethrex_crypto::NativeCrypto;
    use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};

    use super::*;

    use crate::{Trie, pmt_node};

    #[test]
    fn new() {
        let node = BranchNode::new({
            let mut choices = BranchNode::EMPTY_CHOICES;

            choices[2] = NodeHash::Hashed(H256([2; 32])).into();
            choices[5] = NodeHash::Hashed(H256([5; 32])).into();

            choices
        });

        assert_eq!(
            node.choices,
            [
                Default::default(),
                Default::default(),
                NodeHash::Hashed(H256([2; 32])).into(),
                Default::default(),
                Default::default(),
                NodeHash::Hashed(H256([5; 32])).into(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
            ],
        );
    }

    #[test]
    fn get_some() {
        let trie = Trie::new_temp();
        let node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0,16] => vec![0x12, 0x34, 0x56, 0x78] },
                1 => leaf { vec![0,16] => vec![0x34, 0x56, 0x78, 0x9A] },
            }
        };

        assert_eq!(
            node.get(trie.db.as_ref(), Nibbles::from_bytes(&[0x00]))
                .unwrap(),
            Some(vec![0x12, 0x34, 0x56, 0x78]),
        );
        assert_eq!(
            node.get(trie.db.as_ref(), Nibbles::from_bytes(&[0x10]))
                .unwrap(),
            Some(vec![0x34, 0x56, 0x78, 0x9A]),
        );
    }

    #[test]
    fn get_none() {
        let trie = Trie::new_temp();
        let node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0,16] => vec![0x12, 0x34, 0x56, 0x78] },
                1 => leaf { vec![0,16] => vec![0x34, 0x56, 0x78, 0x9A] },
            }
        };

        assert_eq!(
            node.get(trie.db.as_ref(), Nibbles::from_bytes(&[0x20]))
                .unwrap(),
            None,
        );
    }

    #[test]
    fn insert_self() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x12, 0x34, 0x56, 0x78] },
                1 => leaf { vec![0, 16] => vec![0x34, 0x56, 0x78, 0x9A] },
            }
        };
        let path = Nibbles::from_bytes(&[2]);
        let value = vec![0x3];

        node.insert(trie.db.as_ref(), path.clone(), value.clone().into())
            .unwrap();

        assert_eq!(node.get(trie.db.as_ref(), path).unwrap(), Some(value));
    }

    #[test]
    fn insert_choice() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x12, 0x34, 0x56, 0x78] },
                1 => leaf { vec![0, 16] => vec![0x34, 0x56, 0x78, 0x9A] },
            }
        };

        let path = Nibbles::from_bytes(&[0x20]);
        let value = vec![0x21];

        node.insert(trie.db.as_ref(), path.clone(), value.clone().into())
            .unwrap();

        assert_eq!(node.get(trie.db.as_ref(), path).unwrap(), Some(value));
    }

    #[test]
    fn insert_passthrough() {
        let trie = Trie::new_temp();
        let node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x12, 0x34, 0x56, 0x78] },
                1 => leaf { vec![0, 16] => vec![0x34, 0x56, 0x78, 0x9A] },
            }
        };

        // The extension node is ignored since it's irrelevant in this test.
        let path = Nibbles::from_bytes(&[0x00]).offset(2);
        let value = vec![0x1];

        let mut new_node = node.clone();
        new_node
            .insert(trie.db.as_ref(), path, value.clone().into())
            .unwrap();

        assert_eq!(new_node.choices, node.choices);
        assert_eq!(new_node.value, value);
    }

    #[test]
    fn remove_choice_into_inner() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x00] },
                1 => leaf { vec![0, 16] => vec![0x10] },
            }
        };

        let (node, value) = node
            .remove(trie.db.as_ref(), Nibbles::from_bytes(&[0x00]))
            .unwrap();

        assert!(matches!(node, Some(NodeRemoveResult::New(Node::Leaf(_)))));
        assert_eq!(value, Some(vec![0x00]));
    }

    #[test]
    fn remove_choice() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x00] },
                1 => leaf { vec![0, 16] => vec![0x10] },
                2 => leaf { vec![0, 16] => vec![0x10] },
            }
        };

        let (node, value) = node
            .remove(trie.db.as_ref(), Nibbles::from_bytes(&[0x00]))
            .unwrap();

        assert!(matches!(node, Some(NodeRemoveResult::Mutated)));
        assert_eq!(value, Some(vec![0x00]));
    }

    #[test]
    fn remove_choice_into_value() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x00] },
            } with_leaf { &[0x01] => vec![0xFF] }
        };

        let (node, value) = node
            .remove(trie.db.as_ref(), Nibbles::from_bytes(&[0x00]))
            .unwrap();

        assert!(matches!(node, Some(NodeRemoveResult::New(Node::Leaf(_)))));
        assert_eq!(value, Some(vec![0x00]));
    }

    #[test]
    fn remove_value_into_inner() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x00] },
            } with_leaf { &[0x1] => vec![0xFF] }
        };

        let (node, value) = node
            .remove(trie.db.as_ref(), Nibbles::from_bytes(&[]))
            .unwrap();

        assert!(matches!(node, Some(NodeRemoveResult::New(Node::Leaf(_)))));
        assert_eq!(value, Some(vec![0xFF]));
    }

    #[test]
    fn remove_value() {
        let trie = Trie::new_temp();
        let mut node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x00] },
                1 => leaf { vec![0, 16] => vec![0x10] },
            } with_leaf { &[0x1] => vec![0xFF] }
        };

        let (node, value) = node
            .remove(trie.db.as_ref(), Nibbles::from_bytes(&[]))
            .unwrap();

        assert!(matches!(node, Some(NodeRemoveResult::Mutated)));
        assert_eq!(value, Some(vec![0xFF]));
    }

    #[test]
    fn compute_hash_two_choices() {
        let node = pmt_node! { @(trie)
            branch {
                2 => leaf { vec![0, 16] => vec![0x20] },
                4 => leaf { vec![0, 16] => vec![0x40] },
            }
        };

        assert_eq!(
            node.compute_hash(&NativeCrypto).as_ref(),
            &[
                0xD5, 0x80, 0x80, 0xC2, 0x30, 0x20, 0x80, 0xC2, 0x30, 0x40, 0x80, 0x80, 0x80, 0x80,
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
        );
    }

    #[test]
    fn compute_hash_all_choices() {
        let node = pmt_node! { @(trie)
            branch {
                0x0 => leaf { vec![0, 16] => vec![0x00] },
                0x1 => leaf { vec![0, 16] => vec![0x10] },
                0x2 => leaf { vec![0, 16] => vec![0x20] },
                0x3 => leaf { vec![0, 16] => vec![0x30] },
                0x4 => leaf { vec![0, 16] => vec![0x40] },
                0x5 => leaf { vec![0, 16] => vec![0x50] },
                0x6 => leaf { vec![0, 16] => vec![0x60] },
                0x7 => leaf { vec![0, 16] => vec![0x70] },
                0x8 => leaf { vec![0, 16] => vec![0x80] },
                0x9 => leaf { vec![0, 16] => vec![0x90] },
                0xA => leaf { vec![0, 16] => vec![0xA0] },
                0xB => leaf { vec![0, 16] => vec![0xB0] },
                0xC => leaf { vec![0, 16] => vec![0xC0] },
                0xD => leaf { vec![0, 16] => vec![0xD0] },
                0xE => leaf { vec![0, 16] => vec![0xE0] },
                0xF => leaf { vec![0, 16] => vec![0xF0] },
            }
        };

        assert_eq!(
            node.compute_hash(&NativeCrypto).as_ref(),
            &[
                0x0A, 0x3C, 0x06, 0x2D, 0x4A, 0xE3, 0x61, 0xEC, 0xC4, 0x82, 0x07, 0xB3, 0x2A, 0xDB,
                0x6A, 0x3A, 0x3F, 0x3E, 0x98, 0x33, 0xC8, 0x9C, 0x9A, 0x71, 0x66, 0x3F, 0x4E, 0xB5,
                0x61, 0x72, 0xD4, 0x9D,
            ],
        );
    }

    #[test]
    fn compute_hash_one_choice_with_value() {
        let node = pmt_node! { @(trie)
            branch {
                2 => leaf { vec![0, 16] => vec![0x20] },
                4 => leaf { vec![0, 16] => vec![0x40] },
            } with_leaf { &[0x1] => vec![0x1] }
        };

        assert_eq!(
            node.compute_hash(&NativeCrypto).as_ref(),
            &[
                0xD5, 0x80, 0x80, 0xC2, 0x30, 0x20, 0x80, 0xC2, 0x30, 0x40, 0x80, 0x80, 0x80, 0x80,
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
            ],
        );
    }

    #[test]
    fn compute_hash_all_choices_with_value() {
        let node = pmt_node! { @(trie)
            branch {
                0x0 => leaf { vec![0, 16] => vec![0x00] },
                0x1 => leaf { vec![0, 16] => vec![0x10] },
                0x2 => leaf { vec![0, 16] => vec![0x20] },
                0x3 => leaf { vec![0, 16] => vec![0x30] },
                0x4 => leaf { vec![0, 16] => vec![0x40] },
                0x5 => leaf { vec![0, 16] => vec![0x50] },
                0x6 => leaf { vec![0, 16] => vec![0x60] },
                0x7 => leaf { vec![0, 16] => vec![0x70] },
                0x8 => leaf { vec![0, 16] => vec![0x80] },
                0x9 => leaf { vec![0, 16] => vec![0x90] },
                0xA => leaf { vec![0, 16] => vec![0xA0] },
                0xB => leaf { vec![0, 16] => vec![0xB0] },
                0xC => leaf { vec![0, 16] => vec![0xC0] },
                0xD => leaf { vec![0, 16] => vec![0xD0] },
                0xE => leaf { vec![0, 16] => vec![0xE0] },
                0xF => leaf { vec![0, 16] => vec![0xF0] },
            } with_leaf { &[0x1] => vec![0x1] }
        };

        assert_eq!(
            node.compute_hash(&NativeCrypto).as_ref(),
            &[
                0x2A, 0x85, 0x67, 0xC5, 0x63, 0x4A, 0x87, 0xBA, 0x19, 0x6F, 0x2C, 0x65, 0x15, 0x16,
                0x66, 0x37, 0xE0, 0x9A, 0x34, 0xE6, 0xC9, 0xB0, 0x4D, 0xA5, 0x6F, 0xC4, 0x70, 0x4E,
                0x38, 0x61, 0x7D, 0x8E
            ],
        );
    }

    #[test]
    fn symmetric_encoding_a() {
        let node: Node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0,16] => vec![0x12, 0x34, 0x56, 0x78] },
                1 => leaf { vec![0,16] => vec![0x34, 0x56, 0x78, 0x9A] },
            }
        }
        .into();
        assert_eq!(Node::decode(&node.encode_to_vec()).unwrap(), node)
    }

    #[test]
    fn symmetric_encoding_b() {
        let node: Node = pmt_node! { @(trie)
            branch {
                0 => leaf { vec![0, 16] => vec![0x00] },
                1 => leaf { vec![0, 16] => vec![0x10] },
                3 => extension { [0], branch {
                    0 => leaf { vec![16] => vec![0x01, 0x00] },
                    1 => leaf { vec![16] => vec![0x01, 0x01] },
                } },
            }
        }
        .into();
        assert_eq!(Node::decode(&node.encode_to_vec()).unwrap(), node)
    }

    #[test]
    fn symmetric_encoding_c() {
        let node: Node = pmt_node! { @(trie)
            branch {
                0x0 => leaf { vec![0, 16] => vec![0x00] },
                0x1 => leaf { vec![0, 16] => vec![0x10] },
                0x2 => leaf { vec![0, 16] => vec![0x20] },
                0x3 => leaf { vec![0, 16] => vec![0x30] },
                0x4 => leaf { vec![0, 16] => vec![0x40] },
                0x5 => leaf { vec![0, 16] => vec![0x50] },
                0x6 => leaf { vec![0, 16] => vec![0x60] },
                0x7 => leaf { vec![0, 16] => vec![0x70] },
                0x8 => leaf { vec![0, 16] => vec![0x80] },
                0x9 => leaf { vec![0, 16] => vec![0x90] },
                0xA => leaf { vec![0, 16] => vec![0xA0] },
                0xB => leaf { vec![0, 16] => vec![0xB0] },
                0xC => leaf { vec![0, 16] => vec![0xC0] },
                0xD => leaf { vec![0, 16] => vec![0xD0] },
                0xE => leaf { vec![0, 16] => vec![0xE0] },
                0xF => leaf { vec![0, 16] => vec![0xF0] },
            } with_leaf { &[0x1] => vec![0x1] }
        }
        .into();
        assert_eq!(Node::decode(&node.encode_to_vec()).unwrap(), node)
    }
}
