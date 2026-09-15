#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};
use ethereum_types::H256;
use ethrex_rlp::error::RLPDecodeError;
use thiserror::Error;

use crate::Nibbles;

#[derive(Debug, Error)]
pub enum TrieError {
    #[error(transparent)]
    RLPDecode(#[from] RLPDecodeError),
    #[error("Verification Error: {0}")]
    Verify(String),
    #[error("Inconsistent internal tree structure: {0}")]
    InconsistentTree(Box<InconsistentTreeError>),
    // Box was added to make the error smaller since the InconsistentTreeError variants size vary up to more than 168 bytes.
    #[error("Lock Error: Panicked when trying to acquire a lock")]
    LockError,
    #[error("Database error: {0}")]
    DbError(anyhow::Error),
    #[error("Invalid trie input")]
    InvalidInput,
    #[error("Witness node codec error: {0}")]
    WitnessNode(#[from] crate::witness_codec::WitnessNodeError),
}

#[derive(Debug, Error)]
pub enum InconsistentTreeError {
    #[error("Child node of {0}, differs from expected")]
    ExtensionNodeChildDiffers(ExtensionNodeErrorData),
    #[error("No Child Node found of {0}")]
    ExtensionNodeChildNotFound(ExtensionNodeErrorData),
    #[error("Node with hash {0:#x} not found in Branch Node with hash {1:#x} using path {2:?}")]
    NodeNotFoundOnBranchNode(H256, H256, Nibbles),
    #[error("Root node with hash {0:#x} not found")]
    RootNotFound(H256),
    #[error("Root node not found")]
    RootNotFoundNoHash,
}

#[derive(Debug)]
pub struct ExtensionNodeErrorData {
    pub node_hash: H256,
    pub extension_node_hash: H256,
    pub extension_node_prefix: Nibbles,
    pub node_path: Nibbles,
}

impl core::fmt::Display for ExtensionNodeErrorData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Node with hash {:#x}, child of the Extension Node (hash {:#x}, prefix {:?}) on path {:?}",
            self.node_hash, self.extension_node_hash, self.extension_node_hash, self.node_path
        )
    }
}
