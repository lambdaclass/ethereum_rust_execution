use std::collections::HashMap;

use bytes::Bytes;
use ethereum_types::{H256, U256};
use patricia_merkle_tree::PatriciaMerkleTree;
use sha3::{Digest as _, Keccak256};

use crate::rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

use super::GenesisAccount;
use lazy_static::lazy_static;

lazy_static! {
    // Keccak256(""), represents the code hash for an account without code
    pub static ref EMPTY_KECCACK_HASH: H256 = H256::from_slice(&hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap());
}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub info: AccountInfo,
    pub code: Bytes,
    pub storage: HashMap<H256, U256>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountInfo {
    pub code_hash: H256,
    pub balance: U256,
    pub nonce: u64,
}

#[derive(Debug, PartialEq)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

impl Default for AccountInfo {
    fn default() -> Self {
        Self {
            code_hash: *EMPTY_KECCACK_HASH,
            balance: Default::default(),
            nonce: Default::default(),
        }
    }
}

impl From<GenesisAccount> for Account {
    fn from(genesis: GenesisAccount) -> Self {
        Self {
            info: AccountInfo {
                code_hash: code_hash(&genesis.code),
                balance: genesis.balance,
                nonce: genesis.nonce,
            },
            code: genesis.code,
            storage: genesis.storage,
        }
    }
}

pub fn code_hash(code: &Bytes) -> H256 {
    keccak_hash::keccak(code.as_ref())
}

impl RLPEncode for AccountInfo {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.code_hash)
            .encode_field(&self.balance)
            .encode_field(&self.nonce)
            .finish();
    }
}

impl RLPDecode for AccountInfo {
    fn decode_unfinished(rlp: &[u8]) -> Result<(AccountInfo, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (code_hash, decoder) = decoder.decode_field("code_hash")?;
        let (balance, decoder) = decoder.decode_field("balance")?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let account_info = AccountInfo {
            code_hash,
            balance,
            nonce,
        };
        Ok((account_info, decoder.finish()?))
    }
}

impl RLPEncode for AccountState {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.nonce)
            .encode_field(&self.balance)
            .encode_field(&self.storage_root)
            .encode_field(&self.code_hash)
            .finish();
    }
}

impl RLPDecode for AccountState {
    fn decode_unfinished(rlp: &[u8]) -> Result<(AccountState, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let (balance, decoder) = decoder.decode_field("balance")?;
        let (storage_root, decoder) = decoder.decode_field("storage_root")?;
        let (code_hash, decoder) = decoder.decode_field("code_hash")?;
        let state = AccountState {
            nonce,
            balance,
            storage_root,
            code_hash,
        };
        Ok((state, decoder.finish()?))
    }
}

pub fn compute_storage_root(storage: &HashMap<H256, U256>) -> H256 {
    let mut storage_trie = PatriciaMerkleTree::<Vec<u8>, Vec<u8>, Keccak256>::new();

    for (k, v) in storage.iter() {
        let mut v_buf = vec![];
        let k_buf = Keccak256::new_with_prefix(k).finalize().to_vec();
        v.encode(&mut v_buf);
        // zero values are removed from the trie
        if !v.is_zero() {
            storage_trie.insert(k_buf, v_buf);
        }
    }

    // TODO check if sorting by key and using this is more efficient:
    // let root =
    //    PatriciaMerkleTree::<_, _, Keccak256>::compute_hash_from_sorted_iter(rlp_storage.iter());

    let &root = storage_trie.compute_hash();
    H256(root.into())
}

impl AccountState {
    pub fn from_info_and_storage(
        info: &AccountInfo,
        storage: &HashMap<H256, U256>,
    ) -> AccountState {
        AccountState {
            nonce: info.nonce,
            balance: info.balance,
            storage_root: compute_storage_root(storage),
            code_hash: info.code_hash,
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_code_hash() {
        let empty_code = Bytes::new();
        let hash = code_hash(&empty_code);
        assert_eq!(
            hash,
            H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
        )
    }
}
