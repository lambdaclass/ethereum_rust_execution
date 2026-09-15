use crate::rlpx::{
    message::RLPxMessage,
    utils::{snappy_compress, snappy_decompress},
};
use ethrex_common::types::BlockHash;
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::{RLPDecodeError, RLPEncodeError},
    structs::{Decoder, Encoder},
};

/// Maximum number of BALs to serve per request (same as block bodies limit in geth).
pub const BLOCK_ACCESS_LIST_LIMIT: usize = 1024;

/// Wrapper for optional BAL in eth/71 protocol messages.
///
/// Per EIP-8159 §"BlockAccessLists (0x13)": "The RLP empty string (`0x80`)
/// is returned for blocks where the BAL is unavailable." An empty list
/// (`0xc0`) is a valid BAL encoding (block with no state changes), so the
/// empty string is the only sentinel that can never alias a real BAL.
/// `Some(bal)` is encoded as the BAL's normal RLP list encoding.
///
/// INVARIANT: `BlockAccessList` always encodes as an RLP list (first byte is
/// `0xc0` or greater), so `0x80` is unambiguously the `None` sentinel; keep
/// this true if `BlockAccessList`'s encoding is ever refactored.
///
/// Public so the byte-level sentinel encoding can be asserted from the test
/// crate (`test/tests/p2p/rlpx/block_access_lists_tests.rs`); message-level
/// roundtrips run the bytes through snappy and can't see the raw `0x80`.
#[derive(Debug, Clone)]
pub struct OptionalBal(pub Option<BlockAccessList>);

impl RLPEncode for OptionalBal {
    fn encode(&self, buf: &mut Vec<u8>) {
        match &self.0 {
            None => buf.push(0x80),
            Some(bal) => bal.encode(buf),
        }
    }

    fn length(&self) -> usize {
        match &self.0 {
            None => 1, // empty string = 0x80 per EIP-8159
            Some(bal) => bal.length(),
        }
    }
}

impl RLPDecode for OptionalBal {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        if rlp.first() == Some(&0x80) {
            return Ok((OptionalBal(None), &rlp[1..]));
        }
        let (bal, rest) = BlockAccessList::decode_unfinished(rlp)?;
        Ok((OptionalBal(Some(bal)), rest))
    }
}

// https://eips.ethereum.org/EIPS/eip-8159 (eth/71 BAL exchange)
#[derive(Debug, Clone)]
pub struct GetBlockAccessLists {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    pub block_hashes: Vec<BlockHash>,
}

impl GetBlockAccessLists {
    pub fn new(id: u64, block_hashes: Vec<BlockHash>) -> Self {
        Self { id, block_hashes }
    }
}

impl RLPxMessage for GetBlockAccessLists {
    const CODE: u8 = 0x12;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&self.block_hashes)
            .finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (block_hashes, decoder): (Vec<BlockHash>, _) = decoder.decode_field("blockHashes")?;
        decoder.finish()?;
        Ok(Self::new(id, block_hashes))
    }
}

// https://eips.ethereum.org/EIPS/eip-8159 (eth/71 BAL exchange)
#[derive(Debug, Clone)]
pub struct BlockAccessLists {
    // id is a u64 chosen by the requesting peer, the responding peer must mirror the value for the response
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#protocol-messages
    pub id: u64,
    /// One entry per requested block hash. `None` means the BAL is unavailable for that block.
    pub block_access_lists: Vec<Option<BlockAccessList>>,
}

impl BlockAccessLists {
    pub fn new(id: u64, block_access_lists: Vec<Option<BlockAccessList>>) -> Self {
        Self {
            id,
            block_access_lists,
        }
    }
}

impl RLPxMessage for BlockAccessLists {
    const CODE: u8 = 0x13;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        let bals: Vec<OptionalBal> = self
            .block_access_lists
            .iter()
            .cloned()
            .map(OptionalBal)
            .collect();
        Encoder::new(&mut encoded_data)
            .encode_field(&self.id)
            .encode_field(&bals)
            .finish();
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        let decompressed_data = snappy_decompress(msg_data)?;
        let decoder = Decoder::new(&decompressed_data)?;
        let (id, decoder): (u64, _) = decoder.decode_field("request-id")?;
        let (bals, decoder): (Vec<OptionalBal>, _) = decoder.decode_field("blockAccessLists")?;
        decoder.finish()?;
        let block_access_lists = bals.into_iter().map(|b| b.0).collect();
        Ok(Self::new(id, block_access_lists))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::Address;
    use ethrex_common::types::block_access_list::{AccountChanges, BalanceChange};

    fn sample_bal() -> BlockAccessList {
        let account = AccountChanges::new(Address::from_low_u64_be(1))
            .with_balance_changes(vec![BalanceChange::new(0, 100.into())]);
        BlockAccessList::from_accounts(vec![account])
    }

    #[test]
    fn get_block_access_lists_empty() {
        let msg = GetBlockAccessLists::new(42, vec![]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = GetBlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.id, 42);
        assert!(decoded.block_hashes.is_empty());
    }

    #[test]
    fn get_block_access_lists_roundtrip() {
        let hashes = vec![BlockHash::from([1; 32]), BlockHash::from([2; 32])];
        let msg = GetBlockAccessLists::new(7, hashes.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = GetBlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.block_hashes, hashes);
    }

    #[test]
    fn block_access_lists_empty() {
        let msg = BlockAccessLists::new(1, vec![]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = BlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.id, 1);
        assert!(decoded.block_access_lists.is_empty());
    }

    #[test]
    fn block_access_lists_all_none() {
        let msg = BlockAccessLists::new(5, vec![None, None, None]);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = BlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.id, 5);
        assert_eq!(decoded.block_access_lists, vec![None, None, None]);
    }

    #[test]
    fn block_access_lists_mixed() {
        let bal = sample_bal();
        let bals = vec![Some(bal.clone()), None, Some(bal)];
        let msg = BlockAccessLists::new(99, bals.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = BlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.id, 99);
        assert_eq!(decoded.block_access_lists, bals);
    }

    #[test]
    fn block_access_lists_all_some() {
        let bal = sample_bal();
        let bals = vec![Some(bal.clone()), Some(bal)];
        let msg = BlockAccessLists::new(10, bals.clone());
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = BlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.id, 10);
        assert_eq!(decoded.block_access_lists, bals);
    }

    /// Simulates the server-side truncation logic: when a peer requests more
    /// than BLOCK_ACCESS_LIST_LIMIT hashes, the response is capped.
    #[test]
    fn response_truncated_at_limit() {
        let request_count = BLOCK_ACCESS_LIST_LIMIT + 100;
        let hashes: Vec<BlockHash> = (0..request_count)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&(i as u64).to_be_bytes());
                BlockHash::from(h)
            })
            .collect();

        // Reproduce the server-side loop (storage always returns None here)
        let mut block_access_lists: Vec<Option<BlockAccessList>> = Vec::new();
        for _hash in &hashes {
            block_access_lists.push(None);
            if block_access_lists.len() >= BLOCK_ACCESS_LIST_LIMIT {
                break;
            }
        }

        assert_eq!(block_access_lists.len(), BLOCK_ACCESS_LIST_LIMIT);

        // Verify the truncated response roundtrips correctly
        let msg = BlockAccessLists::new(1, block_access_lists);
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = BlockAccessLists::decode(&buf).unwrap();
        assert_eq!(decoded.block_access_lists.len(), BLOCK_ACCESS_LIST_LIMIT);
    }
}
