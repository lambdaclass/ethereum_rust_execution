#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use ethereum_types::H256;
use ethrex_crypto::Crypto;
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode, error::RLPDecodeError, structs::Encoder};

use crate::rkyv_utils::H256Wrapper;

/// Struct representing a trie node hash
/// If the encoded node is less than 32 bits, contains the encoded node itself
// TODO: Check if we can omit the Inline variant, as nodes will always be bigger than 32 bits in our use case
// TODO: Check if making this `Copy` can make the code less verbose at a reasonable performance cost
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub enum NodeHash {
    Hashed(#[rkyv(with=H256Wrapper)] H256),
    // Inline is always len < 32. We need to store the length of the data, a u8 is enough.
    Inline(([u8; 31], u8)),
}

impl AsRef<[u8]> for NodeHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            NodeHash::Inline((slice, len)) => &slice[0..(*len as usize)],
            NodeHash::Hashed(x) => x.as_bytes(),
        }
    }
}

impl NodeHash {
    /// Returns the `NodeHash` of an encoded node (encoded using the NodeEncoder)
    pub fn from_encoded(encoded: &[u8], crypto: &dyn Crypto) -> NodeHash {
        if encoded.len() >= 32 {
            let hash = crypto.keccak256(encoded);
            NodeHash::Hashed(H256::from_slice(&hash))
        } else {
            NodeHash::from_slice(encoded)
        }
    }

    /// Converts a slice of an already hashed data (in case it's not inlineable) to a NodeHash.
    /// Panics if the slice is over 32 bytes
    /// If you need to hash it in case its len >= 32 see `from_encoded`
    pub(crate) fn from_slice(slice: &[u8]) -> NodeHash {
        match slice.len() {
            0..32 => {
                let mut buffer = [0; 31];
                buffer[0..slice.len()].copy_from_slice(slice);
                NodeHash::Inline((buffer, slice.len() as u8))
            }
            _ => NodeHash::Hashed(H256::from_slice(slice)),
        }
    }

    /// Returns the finalized hash
    /// NOTE: This will hash smaller nodes, only use to get the final root hash, not for intermediate node hashes
    pub fn finalize(self, crypto: &dyn Crypto) -> H256 {
        match self {
            NodeHash::Inline(_) => H256(crypto.keccak256(self.as_ref())),
            NodeHash::Hashed(x) => x,
        }
    }

    /// Returns true if the hash is valid
    /// The hash will only be considered invalid if it is empty
    /// Aka if it has a default value instead of being a product of hash computation
    pub fn is_valid(&self) -> bool {
        !matches!(self, NodeHash::Inline(v) if v.1 == 0)
    }

    /// Encodes this NodeHash with the given encoder.
    pub fn encode<'a>(&self, mut encoder: Encoder<'a>) -> Encoder<'a> {
        match self {
            NodeHash::Inline(_) => {
                encoder = encoder.encode_raw(self.as_ref());
            }
            NodeHash::Hashed(_) => {
                encoder = encoder.encode_bytes(self.as_ref());
            }
        }
        encoder
    }

    pub fn len(&self) -> usize {
        match self {
            NodeHash::Hashed(h256) => h256.as_bytes().len(),
            NodeHash::Inline(value) => value.1 as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            NodeHash::Hashed(h256) => h256.as_bytes().is_empty(),
            NodeHash::Inline(value) => value.1 == 0,
        }
    }
}

impl From<H256> for NodeHash {
    fn from(value: H256) -> Self {
        NodeHash::Hashed(value)
    }
}

impl From<NodeHash> for Vec<u8> {
    fn from(val: NodeHash) -> Self {
        val.as_ref().to_vec()
    }
}

impl From<&NodeHash> for Vec<u8> {
    fn from(val: &NodeHash) -> Self {
        val.as_ref().to_vec()
    }
}

impl Default for NodeHash {
    fn default() -> Self {
        NodeHash::Inline(([0; 31], 0))
    }
}

// Encoded as Vec<u8>
impl RLPEncode for NodeHash {
    fn encode(&self, buf: &mut Vec<u8>) {
        RLPEncode::encode(&Into::<Vec<u8>>::into(self), buf)
    }

    fn length(&self) -> usize {
        match self {
            NodeHash::Hashed(_) => 33,                   // 1 byte prefix + 32 bytes
            NodeHash::Inline((_, 0)) => 1,               // if empty then it's encoded to RLP_NULL
            NodeHash::Inline((_, len)) => *len as usize, // already encoded
        }
    }
}

impl RLPDecode for NodeHash {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let (hash, rest): (Vec<u8>, &[u8]);
        (hash, rest) = RLPDecode::decode_unfinished(rlp)?;
        if hash.len() > 32 {
            return Err(RLPDecodeError::InvalidLength);
        }
        let hash = NodeHash::from_slice(&hash);
        Ok((hash, rest))
    }
}
