use ethereum_types::{Address, H256, U256};
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode, error::RLPDecodeError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetDiff {
    pub token_l1: Address,
    pub token_src_l2: Address,
    pub token_dst_l2: Address,
    pub value: U256,
}

/// Represents the amount of balance to transfer to the bridge contract for a specific chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalanceDiff {
    pub chain_id: U256,
    pub value: U256,
    pub value_per_token: Vec<AssetDiff>,
    pub message_hashes: Vec<H256>,
}

impl RLPEncode for BalanceDiff {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.chain_id.encode(buf);
        self.value.encode(buf);
        self.value_per_token.encode(buf);
        self.message_hashes.encode(buf);
    }
}

impl RLPDecode for BalanceDiff {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let (chain_id, rlp) = U256::decode_unfinished(rlp)?;
        let (value, rlp) = U256::decode_unfinished(rlp)?;
        let (value_per_token, rlp) = Vec::<AssetDiff>::decode_unfinished(rlp)?;
        let (message_hashes, rlp) = Vec::<H256>::decode_unfinished(rlp)?;
        Ok((
            BalanceDiff {
                chain_id,
                value,
                value_per_token,
                message_hashes,
            },
            rlp,
        ))
    }
}

impl RLPEncode for AssetDiff {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.token_l1.encode(buf);
        self.token_src_l2.encode(buf);
        self.token_dst_l2.encode(buf);
        self.value.encode(buf);
    }
}

impl RLPDecode for AssetDiff {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let (token_l1, rlp) = Address::decode_unfinished(rlp)?;
        let (token_src_l2, rlp) = Address::decode_unfinished(rlp)?;
        let (token_dst_l2, rlp) = Address::decode_unfinished(rlp)?;
        let (value, rlp) = U256::decode_unfinished(rlp)?;
        Ok((
            AssetDiff {
                token_l1,
                token_src_l2,
                token_dst_l2,
                value,
            },
            rlp,
        ))
    }
}
