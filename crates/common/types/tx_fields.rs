use crate::{Address, H256, U256};
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use rkyv::{Archive, Deserialize as RDeserialize, Serialize as RSerialize};
use serde::{Deserialize, Serialize};
/// A list of addresses and storage keys that the transaction plans to access.
/// See [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)
pub type AccessList = Vec<AccessListItem>;
pub type AccessListItem = (Address, Vec<H256>);

/// Used in Type-4 transactions. Added in [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)
pub type AuthorizationList = Vec<AuthorizationTuple>;
#[derive(
    Debug,
    Clone,
    Default,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    RSerialize,
    RDeserialize,
    Archive,
)]
#[serde(rename_all = "camelCase")]
/// Used in Type-4 transactions. Added in [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)
pub struct AuthorizationTuple {
    #[rkyv(with = crate::rkyv_utils::U256Wrapper)]
    pub chain_id: U256,
    #[rkyv(with = crate::rkyv_utils::H160Wrapper)]
    pub address: Address,
    #[serde(
        default,
        deserialize_with = "crate::serde_utils::u64::deser_hex_or_dec_str"
    )]
    pub nonce: u64,
    #[rkyv(with = crate::rkyv_utils::U256Wrapper)]
    pub y_parity: U256,
    #[serde(rename = "r")]
    #[rkyv(with = crate::rkyv_utils::U256Wrapper)]
    pub r_signature: U256,
    #[serde(rename = "s")]
    #[rkyv(with = crate::rkyv_utils::U256Wrapper)]
    pub s_signature: U256,
}

impl RLPEncode for AuthorizationTuple {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.chain_id)
            .encode_field(&self.address)
            .encode_field(&self.nonce)
            .encode_field(&self.y_parity)
            .encode_field(&self.r_signature)
            .encode_field(&self.s_signature)
            .finish();
    }
}

impl RLPDecode for AuthorizationTuple {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (chain_id, decoder) = decoder.decode_field("chain_id")?;
        let (address, decoder) = decoder.decode_field("address")?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let (y_parity, decoder) = decoder.decode_field("y_parity")?;
        // EIP-7702 bounds y_parity to < 2**8 (geth models it as a u8). Reject
        // out-of-range values at decode so a type-4 tx carrying one is rejected on L1
        // as it is by other clients. The field stays U256 to keep the JSON-RPC and
        // rkyv wire formats unchanged.
        if y_parity > U256::from(u8::MAX) {
            return Err(RLPDecodeError::Custom(
                "EIP-7702 authorization y_parity must be < 2**8".to_string(),
            ));
        }
        let (r_signature, decoder) = decoder.decode_field("r_signature")?;
        let (s_signature, decoder) = decoder.decode_field("s_signature")?;
        let rest = decoder.finish()?;
        Ok((
            AuthorizationTuple {
                chain_id,
                address,
                nonce,
                y_parity,
                r_signature,
                s_signature,
            },
            rest,
        ))
    }
}
