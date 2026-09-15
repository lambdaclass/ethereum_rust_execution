use ethrex_rlp::error::{RLPDecodeError, RLPEncodeError};
use std::fmt::Display;

use crate::rlpx::snap::{
    AccountRange, ByteCodes, GetAccountRange, GetByteCodes, GetStorageRanges, GetTrieNodes,
    StorageRanges, TrieNodes,
};

use super::eth::block_access_lists::{BlockAccessLists, GetBlockAccessLists};
use super::eth::blocks::{BlockBodies, BlockHeaders, GetBlockBodies, GetBlockHeaders};
use super::eth::cells::{Cells, GetCells};
use super::eth::eth72::status::StatusMessage72;
use super::eth::eth72::transactions::{NewPooledTransactionHashes72, PooledTransactions72};
use super::eth::receipts::{
    GetReceipts68, GetReceipts69, GetReceipts70, Receipts68, Receipts69, Receipts70,
};
use super::eth::status::{StatusMessage68, StatusMessage69, StatusMessage70, StatusMessage71};
use super::eth::transactions::{
    GetPooledTransactions, NewPooledTransactionHashes, PooledTransactions, Transactions,
};
use super::eth::update::BlockRangeUpdate;
#[cfg(feature = "l2")]
use super::l2::messages::{BatchSealed, L2Message, NewBlock};
#[cfg(feature = "l2")]
use super::l2::{self, messages};
use super::p2p::{DisconnectMessage, HelloMessage, PingMessage, PongMessage};

use ethrex_rlp::encode::RLPEncode;

const ETH_CAPABILITY_OFFSET: u8 = 0x10;
const SNAP_CAPABILITY_OFFSET_ETH_68: u8 = 0x21;
const SNAP_CAPABILITY_OFFSET_ETH_69: u8 = 0x22;
// eth/70 (EIP-7975) reuses the same message codes as eth/69 — it only changes the
// format of GetReceipts (0x0F) and Receipts (0x10), so offsets are identical.
// GetReceipts68 and GetReceipts69 are type aliases for the same struct (identical wire format).
const SNAP_CAPABILITY_OFFSET_ETH_70: u8 = 0x22;
const SNAP_CAPABILITY_OFFSET_ETH_71: u8 = 0x24;
// eth/72 (EIP-8070) adds GetCells (0x14) and Cells (0x15) in the eth namespace,
// so the snap offset moves from 0x24 to 0x26.
const SNAP_CAPABILITY_OFFSET_ETH_72: u8 = 0x26;
const BASED_CAPABILITY_OFFSET_ETH_68: u8 = 0x30;
const BASED_CAPABILITY_OFFSET_ETH_69: u8 = 0x31;
const BASED_CAPABILITY_OFFSET_ETH_70: u8 = 0x31;
const BASED_CAPABILITY_OFFSET_ETH_71: u8 = 0x33;
const BASED_CAPABILITY_OFFSET_ETH_72: u8 = 0x35;

#[derive(Debug, Clone, Copy, Default)]
pub enum EthCapVersion {
    #[default]
    V68,
    V69,
    V70,
    V71,
    V72,
}

impl EthCapVersion {
    pub const fn eth_capability_offset(&self) -> u8 {
        ETH_CAPABILITY_OFFSET
    }

    pub const fn snap_capability_offset(&self) -> u8 {
        match self {
            EthCapVersion::V68 => SNAP_CAPABILITY_OFFSET_ETH_68,
            EthCapVersion::V69 => SNAP_CAPABILITY_OFFSET_ETH_69,
            EthCapVersion::V70 => SNAP_CAPABILITY_OFFSET_ETH_70,
            EthCapVersion::V71 => SNAP_CAPABILITY_OFFSET_ETH_71,
            EthCapVersion::V72 => SNAP_CAPABILITY_OFFSET_ETH_72,
        }
    }

    pub const fn based_capability_offset(&self) -> u8 {
        match self {
            EthCapVersion::V68 => BASED_CAPABILITY_OFFSET_ETH_68,
            EthCapVersion::V69 => BASED_CAPABILITY_OFFSET_ETH_69,
            EthCapVersion::V70 => BASED_CAPABILITY_OFFSET_ETH_70,
            EthCapVersion::V71 => BASED_CAPABILITY_OFFSET_ETH_71,
            EthCapVersion::V72 => BASED_CAPABILITY_OFFSET_ETH_72,
        }
    }
}

pub trait RLPxMessage: Sized {
    const CODE: u8;

    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError>;

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError>;
}
#[derive(Debug, Clone)]
pub enum Message {
    Hello(HelloMessage),
    Disconnect(DisconnectMessage),
    Ping(PingMessage),
    Pong(PongMessage),
    Status68(StatusMessage68),
    Status69(StatusMessage69),
    Status70(StatusMessage70),
    Status71(StatusMessage71),
    Status72(StatusMessage72),
    // eth capability
    // https://github.com/ethereum/devp2p/blob/master/caps/eth.md
    GetBlockHeaders(GetBlockHeaders),
    BlockHeaders(BlockHeaders),
    Transactions(Transactions),
    GetBlockBodies(GetBlockBodies),
    BlockBodies(BlockBodies),
    NewPooledTransactionHashes(NewPooledTransactionHashes),
    GetPooledTransactions(GetPooledTransactions),
    PooledTransactions(PooledTransactions),
    // eth/72 (EIP-8070) variants
    NewPooledTransactionHashes72(NewPooledTransactionHashes72),
    PooledTransactions72(PooledTransactions72),
    GetCells(GetCells),
    Cells(Cells),
    GetReceipts68(GetReceipts68),
    GetReceipts69(GetReceipts69),
    GetReceipts70(GetReceipts70),
    Receipts68(Receipts68),
    Receipts69(Receipts69),
    Receipts70(Receipts70),
    BlockRangeUpdate(BlockRangeUpdate),
    GetBlockAccessLists(GetBlockAccessLists),
    BlockAccessLists(BlockAccessLists),
    // snap capability
    // https://github.com/ethereum/devp2p/blob/master/caps/snap.md
    GetAccountRange(GetAccountRange),
    AccountRange(AccountRange),
    GetStorageRanges(GetStorageRanges),
    StorageRanges(StorageRanges),
    GetByteCodes(GetByteCodes),
    ByteCodes(ByteCodes),
    GetTrieNodes(GetTrieNodes),
    TrieNodes(TrieNodes),
    // based capability
    #[cfg(feature = "l2")]
    L2(messages::L2Message),
}

impl Message {
    pub const fn code(&self, eth_version: EthCapVersion) -> u8 {
        match self {
            Message::Hello(_) => HelloMessage::CODE,
            Message::Disconnect(_) => DisconnectMessage::CODE,
            Message::Ping(_) => PingMessage::CODE,
            Message::Pong(_) => PongMessage::CODE,

            // eth capability
            Message::Status68(_) => eth_version.eth_capability_offset() + StatusMessage68::CODE,
            Message::Status69(_) => eth_version.eth_capability_offset() + StatusMessage69::CODE,
            Message::Status70(_) => eth_version.eth_capability_offset() + StatusMessage70::CODE,
            Message::Status71(_) => eth_version.eth_capability_offset() + StatusMessage71::CODE,
            Message::Status72(_) => eth_version.eth_capability_offset() + StatusMessage72::CODE,
            Message::Transactions(_) => eth_version.eth_capability_offset() + Transactions::CODE,
            Message::GetBlockHeaders(_) => {
                eth_version.eth_capability_offset() + GetBlockHeaders::CODE
            }
            Message::BlockHeaders(_) => eth_version.eth_capability_offset() + BlockHeaders::CODE,
            Message::GetBlockBodies(_) => {
                eth_version.eth_capability_offset() + GetBlockBodies::CODE
            }
            Message::BlockBodies(_) => eth_version.eth_capability_offset() + BlockBodies::CODE,
            Message::NewPooledTransactionHashes(_) => {
                eth_version.eth_capability_offset() + NewPooledTransactionHashes::CODE
            }
            Message::GetPooledTransactions(_) => {
                eth_version.eth_capability_offset() + GetPooledTransactions::CODE
            }
            Message::PooledTransactions(_) => {
                eth_version.eth_capability_offset() + PooledTransactions::CODE
            }
            Message::NewPooledTransactionHashes72(_) => {
                eth_version.eth_capability_offset() + NewPooledTransactionHashes72::CODE
            }
            Message::PooledTransactions72(_) => {
                eth_version.eth_capability_offset() + PooledTransactions72::CODE
            }
            Message::GetCells(_) => eth_version.eth_capability_offset() + GetCells::CODE,
            Message::Cells(_) => eth_version.eth_capability_offset() + Cells::CODE,
            Message::GetReceipts68(_) => eth_version.eth_capability_offset() + GetReceipts68::CODE,
            Message::GetReceipts69(_) => eth_version.eth_capability_offset() + GetReceipts69::CODE,
            Message::GetReceipts70(_) => eth_version.eth_capability_offset() + GetReceipts70::CODE,
            Message::Receipts68(_) => eth_version.eth_capability_offset() + Receipts68::CODE,
            Message::Receipts69(_) => eth_version.eth_capability_offset() + Receipts69::CODE,
            Message::Receipts70(_) => eth_version.eth_capability_offset() + Receipts70::CODE,
            Message::BlockRangeUpdate(_) => {
                eth_version.eth_capability_offset() + BlockRangeUpdate::CODE
            }
            Message::GetBlockAccessLists(_) => {
                eth_version.eth_capability_offset() + GetBlockAccessLists::CODE
            }
            Message::BlockAccessLists(_) => {
                eth_version.eth_capability_offset() + BlockAccessLists::CODE
            }
            // snap capability
            Message::GetAccountRange(_) => {
                eth_version.snap_capability_offset() + GetAccountRange::CODE
            }
            Message::AccountRange(_) => eth_version.snap_capability_offset() + AccountRange::CODE,
            Message::GetStorageRanges(_) => {
                eth_version.snap_capability_offset() + GetStorageRanges::CODE
            }
            Message::StorageRanges(_) => eth_version.snap_capability_offset() + StorageRanges::CODE,
            Message::GetByteCodes(_) => eth_version.snap_capability_offset() + GetByteCodes::CODE,
            Message::ByteCodes(_) => eth_version.snap_capability_offset() + ByteCodes::CODE,
            Message::GetTrieNodes(_) => eth_version.snap_capability_offset() + GetTrieNodes::CODE,
            Message::TrieNodes(_) => eth_version.snap_capability_offset() + TrieNodes::CODE,

            #[cfg(feature = "l2")]
            // based capability
            Message::L2(l2_msg) => {
                eth_version.based_capability_offset() + {
                    match l2_msg {
                        L2Message::NewBlock(_) => NewBlock::CODE,
                        L2Message::BatchSealed(_) => BatchSealed::CODE,
                    }
                }
            }
        }
    }
    pub fn decode(
        msg_id: u8,
        data: &[u8],
        eth_version: EthCapVersion,
    ) -> Result<Message, RLPDecodeError> {
        if msg_id < eth_version.eth_capability_offset() {
            match msg_id {
                HelloMessage::CODE => Ok(Message::Hello(HelloMessage::decode(data)?)),
                DisconnectMessage::CODE => {
                    Ok(Message::Disconnect(DisconnectMessage::decode(data)?))
                }
                PingMessage::CODE => Ok(Message::Ping(PingMessage::decode(data)?)),
                PongMessage::CODE => Ok(Message::Pong(PongMessage::decode(data)?)),
                _ => Err(RLPDecodeError::MalformedData),
            }
        } else if msg_id < eth_version.snap_capability_offset() {
            // eth capability
            match msg_id - eth_version.eth_capability_offset() {
                StatusMessage68::CODE if matches!(eth_version, EthCapVersion::V68) => {
                    Ok(Message::Status68(StatusMessage68::decode(data)?))
                }
                StatusMessage69::CODE if matches!(eth_version, EthCapVersion::V69) => {
                    Ok(Message::Status69(StatusMessage69::decode(data)?))
                }
                StatusMessage70::CODE if matches!(eth_version, EthCapVersion::V70) => {
                    Ok(Message::Status70(StatusMessage70::decode(data)?))
                }
                StatusMessage71::CODE if matches!(eth_version, EthCapVersion::V71) => {
                    Ok(Message::Status71(StatusMessage71::decode(data)?))
                }
                StatusMessage72::CODE if matches!(eth_version, EthCapVersion::V72) => {
                    Ok(Message::Status72(StatusMessage72::decode(data)?))
                }
                Transactions::CODE => Ok(Message::Transactions(Transactions::decode(data)?)),
                GetBlockHeaders::CODE => {
                    Ok(Message::GetBlockHeaders(GetBlockHeaders::decode(data)?))
                }
                BlockHeaders::CODE => Ok(Message::BlockHeaders(BlockHeaders::decode(data)?)),
                GetBlockBodies::CODE => Ok(Message::GetBlockBodies(GetBlockBodies::decode(data)?)),
                BlockBodies::CODE => Ok(Message::BlockBodies(BlockBodies::decode(data)?)),
                NewPooledTransactionHashes::CODE if !matches!(eth_version, EthCapVersion::V72) => {
                    Ok(Message::NewPooledTransactionHashes(
                        NewPooledTransactionHashes::decode(data)?,
                    ))
                }
                NewPooledTransactionHashes72::CODE if matches!(eth_version, EthCapVersion::V72) => {
                    Ok(Message::NewPooledTransactionHashes72(
                        NewPooledTransactionHashes72::decode(data)?,
                    ))
                }
                GetPooledTransactions::CODE => Ok(Message::GetPooledTransactions(
                    GetPooledTransactions::decode(data)?,
                )),
                PooledTransactions::CODE if !matches!(eth_version, EthCapVersion::V72) => Ok(
                    Message::PooledTransactions(PooledTransactions::decode(data)?),
                ),
                PooledTransactions72::CODE if matches!(eth_version, EthCapVersion::V72) => Ok(
                    Message::PooledTransactions72(PooledTransactions72::decode(data)?),
                ),
                GetCells::CODE if matches!(eth_version, EthCapVersion::V72) => {
                    Ok(Message::GetCells(GetCells::decode(data)?))
                }
                Cells::CODE if matches!(eth_version, EthCapVersion::V72) => {
                    Ok(Message::Cells(Cells::decode(data)?))
                }
                GetReceipts68::CODE if matches!(eth_version, EthCapVersion::V68) => {
                    Ok(Message::GetReceipts68(GetReceipts68::decode(data)?))
                }
                GetReceipts69::CODE if matches!(eth_version, EthCapVersion::V69) => {
                    Ok(Message::GetReceipts69(GetReceipts69::decode(data)?))
                }
                // eth/71 (EIP-8159) and eth/72 (EIP-8070) build on the eth/70 receipt layout.
                GetReceipts70::CODE
                    if matches!(
                        eth_version,
                        EthCapVersion::V70 | EthCapVersion::V71 | EthCapVersion::V72
                    ) =>
                {
                    Ok(Message::GetReceipts70(GetReceipts70::decode(data)?))
                }
                Receipts68::CODE if matches!(eth_version, EthCapVersion::V68) => {
                    Ok(Message::Receipts68(Receipts68::decode(data)?))
                }
                Receipts69::CODE if matches!(eth_version, EthCapVersion::V69) => {
                    Ok(Message::Receipts69(Receipts69::decode(data)?))
                }
                Receipts70::CODE
                    if matches!(
                        eth_version,
                        EthCapVersion::V70 | EthCapVersion::V71 | EthCapVersion::V72
                    ) =>
                {
                    Ok(Message::Receipts70(Receipts70::decode(data)?))
                }
                BlockRangeUpdate::CODE => {
                    Ok(Message::BlockRangeUpdate(BlockRangeUpdate::decode(data)?))
                }
                GetBlockAccessLists::CODE
                    if matches!(eth_version, EthCapVersion::V71 | EthCapVersion::V72) =>
                {
                    Ok(Message::GetBlockAccessLists(GetBlockAccessLists::decode(
                        data,
                    )?))
                }
                BlockAccessLists::CODE
                    if matches!(eth_version, EthCapVersion::V71 | EthCapVersion::V72) =>
                {
                    Ok(Message::BlockAccessLists(BlockAccessLists::decode(data)?))
                }
                _ => Err(RLPDecodeError::MalformedData),
            }
        } else if msg_id < eth_version.based_capability_offset() {
            // snap capability
            match msg_id - eth_version.snap_capability_offset() {
                GetAccountRange::CODE => {
                    Ok(Message::GetAccountRange(GetAccountRange::decode(data)?))
                }
                AccountRange::CODE => Ok(Message::AccountRange(AccountRange::decode(data)?)),
                GetStorageRanges::CODE => {
                    Ok(Message::GetStorageRanges(GetStorageRanges::decode(data)?))
                }
                StorageRanges::CODE => Ok(Message::StorageRanges(StorageRanges::decode(data)?)),
                GetByteCodes::CODE => Ok(Message::GetByteCodes(GetByteCodes::decode(data)?)),
                ByteCodes::CODE => Ok(Message::ByteCodes(ByteCodes::decode(data)?)),
                GetTrieNodes::CODE => Ok(Message::GetTrieNodes(GetTrieNodes::decode(data)?)),
                TrieNodes::CODE => Ok(Message::TrieNodes(TrieNodes::decode(data)?)),
                _ => Err(RLPDecodeError::MalformedData),
            }
        } else {
            // based capability
            #[cfg(feature = "l2")]
            return Ok(Message::L2(
                match msg_id - eth_version.based_capability_offset() {
                    messages::NewBlock::CODE => {
                        let decoded = l2::messages::NewBlock::decode(data)?;
                        L2Message::NewBlock(decoded)
                    }
                    BatchSealed::CODE => {
                        let decoded = l2::messages::BatchSealed::decode(data)?;
                        L2Message::BatchSealed(decoded)
                    }
                    _ => return Err(RLPDecodeError::MalformedData),
                },
            ));

            #[cfg(not(feature = "l2"))]
            Err(RLPDecodeError::MalformedData)
        }
    }

    pub fn encode(
        &self,
        buf: &mut Vec<u8>,
        eth_version: EthCapVersion,
    ) -> Result<(), RLPEncodeError> {
        self.code(eth_version).encode(buf);
        match self {
            Message::Hello(msg) => msg.encode(buf),
            Message::Disconnect(msg) => msg.encode(buf),
            Message::Ping(msg) => msg.encode(buf),
            Message::Pong(msg) => msg.encode(buf),
            Message::Status68(msg) => msg.encode(buf),
            Message::Status69(msg) => msg.encode(buf),
            Message::Status70(msg) => msg.encode(buf),
            Message::Status71(msg) => msg.encode(buf),
            Message::Status72(msg) => msg.encode(buf),
            Message::Transactions(msg) => msg.encode(buf),
            Message::GetBlockHeaders(msg) => msg.encode(buf),
            Message::BlockHeaders(msg) => msg.encode(buf),
            Message::GetBlockBodies(msg) => msg.encode(buf),
            Message::BlockBodies(msg) => msg.encode(buf),
            Message::NewPooledTransactionHashes(msg) => msg.encode(buf),
            Message::GetPooledTransactions(msg) => msg.encode(buf),
            Message::PooledTransactions(msg) => msg.encode(buf),
            Message::NewPooledTransactionHashes72(msg) => msg.encode(buf),
            Message::PooledTransactions72(msg) => msg.encode(buf),
            Message::GetCells(msg) => msg.encode(buf),
            Message::Cells(msg) => msg.encode(buf),
            Message::GetReceipts68(msg) => msg.encode(buf),
            Message::GetReceipts69(msg) => msg.encode(buf),
            Message::GetReceipts70(msg) => msg.encode(buf),
            Message::Receipts68(msg) => msg.encode(buf),
            Message::Receipts69(msg) => msg.encode(buf),
            Message::Receipts70(msg) => msg.encode(buf),
            Message::BlockRangeUpdate(msg) => msg.encode(buf),
            Message::GetBlockAccessLists(msg) => msg.encode(buf),
            Message::BlockAccessLists(msg) => msg.encode(buf),
            Message::GetAccountRange(msg) => msg.encode(buf),
            Message::AccountRange(msg) => msg.encode(buf),
            Message::GetStorageRanges(msg) => msg.encode(buf),
            Message::StorageRanges(msg) => msg.encode(buf),
            Message::GetByteCodes(msg) => msg.encode(buf),
            Message::ByteCodes(msg) => msg.encode(buf),
            Message::GetTrieNodes(msg) => msg.encode(buf),
            Message::TrieNodes(msg) => msg.encode(buf),
            #[cfg(feature = "l2")]
            Message::L2(l2_msg) => match l2_msg {
                L2Message::BatchSealed(msg) => msg.encode(buf),
                L2Message::NewBlock(msg) => msg.encode(buf),
            },
        }
    }

    pub fn request_id(&self) -> Option<u64> {
        match self {
            Message::GetBlockHeaders(message) => Some(message.id),
            Message::GetBlockBodies(message) => Some(message.id),
            Message::GetPooledTransactions(message) => Some(message.id),
            Message::GetReceipts68(message) => Some(message.id),
            Message::GetReceipts69(message) => Some(message.id),
            Message::GetReceipts70(message) => Some(message.id),
            Message::GetAccountRange(message) => Some(message.id),
            Message::GetStorageRanges(message) => Some(message.id),
            Message::GetByteCodes(message) => Some(message.id),
            Message::GetTrieNodes(message) => Some(message.id),
            Message::BlockHeaders(message) => Some(message.id),
            Message::BlockBodies(message) => Some(message.id),
            Message::PooledTransactions(message) => Some(message.id),
            Message::Receipts68(message) => Some(message.id),
            Message::Receipts69(message) => Some(message.id),
            Message::Receipts70(message) => Some(message.id),
            Message::AccountRange(message) => Some(message.id),
            Message::StorageRanges(message) => Some(message.id),
            Message::ByteCodes(message) => Some(message.id),
            Message::TrieNodes(message) => Some(message.id),
            Message::GetBlockAccessLists(message) => Some(message.id),
            Message::BlockAccessLists(message) => Some(message.id),
            Message::GetCells(message) => Some(message.id),
            Message::Cells(message) => Some(message.id),
            Message::PooledTransactions72(message) => Some(message.id),
            // The rest of the message types does not have a request id.
            Message::Hello(_)
            | Message::Disconnect(_)
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::Status68(_)
            | Message::Status69(_)
            | Message::Status70(_)
            | Message::Status71(_)
            | Message::Status72(_)
            | Message::Transactions(_)
            | Message::NewPooledTransactionHashes(_)
            | Message::NewPooledTransactionHashes72(_)
            | Message::BlockRangeUpdate(_) => None,
            #[cfg(feature = "l2")]
            Message::L2(_) => None,
        }
    }
}

impl Message {
    /// Returns a short, stable label suitable for use as a Prometheus metric label value.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Message::Hello(_) => "Hello",
            Message::Disconnect(_) => "Disconnect",
            Message::Ping(_) => "Ping",
            Message::Pong(_) => "Pong",
            Message::Status68(_) => "Status",
            Message::Status69(_) => "Status",
            Message::Status70(_) => "Status",
            Message::Status71(_) => "Status",
            Message::Status72(_) => "Status",
            Message::GetBlockHeaders(_) => "GetBlockHeaders",
            Message::BlockHeaders(_) => "BlockHeaders",
            Message::Transactions(_) => "Transactions",
            Message::GetBlockBodies(_) => "GetBlockBodies",
            Message::BlockBodies(_) => "BlockBodies",
            Message::NewPooledTransactionHashes(_) => "NewPooledTransactionHashes",
            Message::GetPooledTransactions(_) => "GetPooledTransactions",
            Message::PooledTransactions(_) => "PooledTransactions",
            Message::NewPooledTransactionHashes72(_) => "NewPooledTransactionHashes",
            Message::PooledTransactions72(_) => "PooledTransactions",
            Message::GetCells(_) => "GetCells",
            Message::Cells(_) => "Cells",
            Message::GetReceipts68(_) => "GetReceipts",
            Message::GetReceipts69(_) => "GetReceipts",
            Message::GetReceipts70(_) => "GetReceipts",
            Message::Receipts68(_) => "Receipts",
            Message::Receipts69(_) => "Receipts",
            Message::Receipts70(_) => "Receipts",
            Message::BlockRangeUpdate(_) => "BlockRangeUpdate",
            Message::GetBlockAccessLists(_) => "GetBlockAccessLists",
            Message::BlockAccessLists(_) => "BlockAccessLists",
            Message::GetAccountRange(_) => "GetAccountRange",
            Message::AccountRange(_) => "AccountRange",
            Message::GetStorageRanges(_) => "GetStorageRanges",
            Message::StorageRanges(_) => "StorageRanges",
            Message::GetByteCodes(_) => "GetByteCodes",
            Message::ByteCodes(_) => "ByteCodes",
            Message::GetTrieNodes(_) => "GetTrieNodes",
            Message::TrieNodes(_) => "TrieNodes",
            #[cfg(feature = "l2")]
            Message::L2(l2_msg) => match l2_msg {
                L2Message::NewBlock(_) => "L2NewBlock",
                L2Message::BatchSealed(_) => "L2BatchSealed",
            },
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Hello(_) => "p2p:Hello".fmt(f),
            Message::Disconnect(_) => "p2p:Disconnect".fmt(f),
            Message::Ping(_) => "p2p:Ping".fmt(f),
            Message::Pong(_) => "p2p:Pong".fmt(f),
            Message::Status68(_) => "eth:Status(68)".fmt(f),
            Message::Status69(_) => "eth:Status(69)".fmt(f),
            Message::Status70(_) => "eth:Status(70)".fmt(f),
            Message::Status71(_) => "eth:Status(71)".fmt(f),
            Message::Status72(_) => "eth:Status(72)".fmt(f),
            Message::GetBlockHeaders(_) => "eth:getBlockHeaders".fmt(f),
            Message::BlockHeaders(_) => "eth:BlockHeaders".fmt(f),
            Message::BlockBodies(_) => "eth:BlockBodies".fmt(f),
            Message::NewPooledTransactionHashes(_) => "eth:NewPooledTransactionHashes".fmt(f),
            Message::GetPooledTransactions(_) => "eth::GetPooledTransactions".fmt(f),
            Message::PooledTransactions(_) => "eth::PooledTransactions".fmt(f),
            Message::NewPooledTransactionHashes72(_) => "eth:NewPooledTransactionHashes(72)".fmt(f),
            Message::PooledTransactions72(_) => "eth::PooledTransactions(72)".fmt(f),
            Message::GetCells(_) => "eth:GetCells(72)".fmt(f),
            Message::Cells(_) => "eth:Cells(72)".fmt(f),
            Message::Transactions(_) => "eth:TransactionsMessage".fmt(f),
            Message::GetBlockBodies(_) => "eth:GetBlockBodies".fmt(f),
            Message::GetReceipts68(_) => "eth:GetReceipts(68)".fmt(f),
            Message::GetReceipts69(_) => "eth:GetReceipts(69)".fmt(f),
            Message::GetReceipts70(_) => "eth:GetReceipts(70)".fmt(f),
            Message::Receipts68(_) => "eth:Receipts(68)".fmt(f),
            Message::Receipts69(_) => "eth:Receipts(69)".fmt(f),
            Message::Receipts70(_) => "eth:Receipts(70)".fmt(f),
            Message::BlockRangeUpdate(_) => "eth:BlockRangeUpdate".fmt(f),
            Message::GetBlockAccessLists(_) => "eth:GetBlockAccessLists".fmt(f),
            Message::BlockAccessLists(_) => "eth:BlockAccessLists".fmt(f),
            Message::GetAccountRange(_) => "snap:GetAccountRange".fmt(f),
            Message::AccountRange(_) => "snap:AccountRange".fmt(f),
            Message::GetStorageRanges(_) => "snap:GetStorageRanges".fmt(f),
            Message::StorageRanges(_) => "snap:StorageRanges".fmt(f),
            Message::GetByteCodes(_) => "snap:GetByteCodes".fmt(f),
            Message::ByteCodes(_) => "snap:ByteCodes".fmt(f),
            Message::GetTrieNodes(_) => "snap:GetTrieNodes".fmt(f),
            Message::TrieNodes(_) => "snap:TrieNodes".fmt(f),
            #[cfg(feature = "l2")]
            Message::L2(l2_msg) => match l2_msg {
                L2Message::BatchSealed(_) => "based:BatchSealed".fmt(f),
                L2Message::NewBlock(_) => "based:NewBlock".fmt(f),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EthCapVersion, Message, RLPxMessage};
    use crate::rlpx::eth::receipts::{GetReceipts, GetReceipts70, Receipts70};
    use ethrex_common::types::BlockHash;

    /// Which `GetReceipts` wire form each eth version expects. eth/70 (EIP-7975)
    /// introduced the paginated form and eth/71 (EIP-8159, `requires: [7928,
    /// 7975]`) builds on it, so only eth/68 and eth/69 take the simple form.
    /// Sending the wrong form to a peer is undetectable locally — it just fails to
    /// decode on their side — so pin the mapping here.
    #[test]
    fn get_receipts_wire_form_per_version() {
        for version in [EthCapVersion::V68, EthCapVersion::V69] {
            let request = GetReceipts::new(7, vec![BlockHash::from([1; 32])]);
            let mut encoded = Vec::new();
            request.encode(&mut encoded).unwrap();
            let decoded = Message::decode(
                version.eth_capability_offset() + GetReceipts::CODE,
                &encoded,
                version,
            )
            .unwrap_or_else(|e| panic!("{version:?} must decode the simple form: {e:?}"));
            assert!(
                matches!(
                    decoded,
                    Message::GetReceipts68(_) | Message::GetReceipts69(_)
                ),
                "{version:?} must use the simple GetReceipts form, got {decoded:?}"
            );
        }

        for version in [EthCapVersion::V70, EthCapVersion::V71] {
            let request = GetReceipts70::new(7, 0, vec![BlockHash::from([1; 32])]);
            let mut encoded = Vec::new();
            request.encode(&mut encoded).unwrap();
            let decoded = Message::decode(
                version.eth_capability_offset() + GetReceipts70::CODE,
                &encoded,
                version,
            )
            .unwrap_or_else(|e| panic!("{version:?} must decode the paginated form: {e:?}"));
            assert!(
                matches!(decoded, Message::GetReceipts70(_)),
                "{version:?} must use the paginated GetReceipts form, got {decoded:?}"
            );
        }
    }

    /// The mirror of the above for responses: an eth/70+ peer answers with
    /// `Receipts70`, which a client that only matches `Receipts68`/`Receipts69`
    /// would drop as unexpected.
    #[test]
    fn receipts_wire_form_per_version() {
        for version in [EthCapVersion::V70, EthCapVersion::V71] {
            let response = Receipts70::new(7, false, vec![]);
            let mut encoded = Vec::new();
            response.encode(&mut encoded).unwrap();
            let decoded = Message::decode(
                version.eth_capability_offset() + Receipts70::CODE,
                &encoded,
                version,
            )
            .unwrap_or_else(|e| panic!("{version:?} must decode Receipts70: {e:?}"));
            assert!(
                matches!(decoded, Message::Receipts70(_)),
                "{version:?} must answer with the paginated Receipts form, got {decoded:?}"
            );
        }
    }

    #[test]
    fn decodes_eth71_get_receipts_with_eth70_format() {
        let request = GetReceipts70::new(7, 3, vec![BlockHash::from([1; 32])]);
        let mut encoded = Vec::new();
        request.encode(&mut encoded).unwrap();

        let decoded = Message::decode(
            EthCapVersion::V71.eth_capability_offset() + GetReceipts70::CODE,
            &encoded,
            EthCapVersion::V71,
        )
        .unwrap();

        let Message::GetReceipts70(decoded) = decoded else {
            panic!("expected eth/70 GetReceipts message");
        };
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.first_block_receipt_index, 3);
        assert_eq!(decoded.block_hashes, vec![BlockHash::from([1; 32])]);
    }

    #[test]
    fn decodes_eth71_receipts_with_eth70_format() {
        let response = Receipts70::new(7, true, vec![]);
        let mut encoded = Vec::new();
        response.encode(&mut encoded).unwrap();

        let decoded = Message::decode(
            EthCapVersion::V71.eth_capability_offset() + Receipts70::CODE,
            &encoded,
            EthCapVersion::V71,
        )
        .unwrap();

        let Message::Receipts70(decoded) = decoded else {
            panic!("expected eth/70 Receipts message");
        };
        assert_eq!(decoded.id, 7);
        assert!(decoded.last_block_incomplete);
        assert!(decoded.receipts.is_empty());
    }
}
