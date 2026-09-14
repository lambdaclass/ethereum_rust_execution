use bytes::Bytes;
use ethrex_common::types::{
    Account as ethrexAccount, AccountInfo, Block as CoreBlock, BlockBody, Code, EIP1559Transaction,
    EIP2930Transaction, EIP4844Transaction, EIP7702Transaction, Frame, FrameSignature,
    FrameTransaction, GasLimits, LegacyTransaction, Transaction as ethrexTransaction, TxKind,
    code_hash,
};
use ethrex_common::types::{Genesis, GenesisAccount, Withdrawal};
use ethrex_common::{Address, Bloom, H64, H256, U256, types::BlockHeader};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::deserialize::{deserialize_block_expected_exception, deserialize_empty_as_none_address};
use crate::fork::Fork;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestUnit {
    #[serde(default, rename = "_info")]
    pub info: Info,
    pub blocks: Vec<BlockWithRLP>,
    pub genesis_block_header: Header,
    #[serde(rename = "genesisRLP", with = "ethrex_common::serde_utils::bytes")]
    pub genesis_rlp: Bytes,
    pub lastblockhash: H256,
    pub network: Fork,
    pub post_state: Option<HashMap<Address, Account>>,
    pub post_state_hash: Option<H256>,
    pub pre: HashMap<Address, Account>,
    pub seal_engine: serde_json::Value,
    pub config: Option<FixtureConfig>,
}

/// General information about the test. Matches the `_info` field in the `.json` file.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Info {
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(rename = "filling-rpc-server", default)]
    pub filling_rpc_server: Option<String>,
    #[serde(rename = "filling-tool-version", default)]
    pub filling_tool_version: Option<String>,
    #[serde(rename = "generatedTestHash", default)]
    pub generated_test_hash: Option<H256>,
    #[serde(default)]
    pub labels: Option<HashMap<u64, String>>,
    #[serde(default)]
    pub lllcversion: Option<String>,
    #[serde(default)]
    pub solidity: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(rename = "sourceHash", default)]
    pub source_hash: Option<H256>,
    // These fields are implemented in the new version of the test vectors (Prague).
    #[serde(rename = "hash", default)]
    pub hash: Option<String>,
    #[serde(rename = "filling-transition-tool", default)]
    pub filling_transition_tool: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(rename = "fixture_format", default)]
    pub fixture_format: Option<String>,
    #[serde(rename = "reference-spec", default)]
    pub reference_spec: Option<String>,
    #[serde(rename = "reference-spec-version", default)]
    pub reference_spec_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureConfig {
    pub blob_schedule: Option<BlobSchedule>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ForkBlobSchedule {
    #[serde(default, with = "ethrex_common::serde_utils::u32::hex_str")]
    pub target: u32,
    #[serde(default, with = "ethrex_common::serde_utils::u32::hex_str")]
    pub max: u32,
    #[serde(default, with = "ethrex_common::serde_utils::u64::hex_str")]
    pub base_fee_update_fraction: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BlobSchedule {
    pub cancun: Option<ForkBlobSchedule>,
    pub prague: Option<ForkBlobSchedule>,
    pub osaka: Option<ForkBlobSchedule>,
    #[serde(rename = "BPO1")]
    pub bpo1: Option<ForkBlobSchedule>,
    #[serde(rename = "BPO2")]
    pub bpo2: Option<ForkBlobSchedule>,
    #[serde(rename = "BPO3")]
    pub bpo3: Option<ForkBlobSchedule>,
    #[serde(rename = "BPO4")]
    pub bpo4: Option<ForkBlobSchedule>,
    #[serde(rename = "BPO5")]
    pub bpo5: Option<ForkBlobSchedule>,
    pub amsterdam: Option<ForkBlobSchedule>,
}

impl From<BlobSchedule> for ethrex_common::types::BlobSchedule {
    fn from(val: BlobSchedule) -> Self {
        let mut blob_schedule = ethrex_common::types::BlobSchedule::default();
        if let Some(cancun_schedule) = val.cancun {
            blob_schedule.cancun = cancun_schedule.into()
        }
        if let Some(prague_schedule) = val.prague {
            blob_schedule.prague = prague_schedule.into()
        }
        if let Some(osaka_schedule) = val.osaka {
            blob_schedule.osaka = osaka_schedule.into()
        }
        if let Some(bpo1_schedule) = val.bpo1 {
            blob_schedule.bpo1 = bpo1_schedule.into()
        }
        if let Some(bpo2_schedule) = val.bpo2 {
            blob_schedule.bpo2 = bpo2_schedule.into()
        }
        if let Some(bpo3_schedule) = val.bpo3 {
            blob_schedule.bpo3 = Some(bpo3_schedule.into())
        }
        if let Some(bpo4_schedule) = val.bpo4 {
            blob_schedule.bpo4 = Some(bpo4_schedule.into())
        }
        if let Some(bpo5_schedule) = val.bpo5 {
            blob_schedule.bpo5 = Some(bpo5_schedule.into())
        }
        if let Some(amsterdam_schedule) = val.amsterdam {
            blob_schedule.amsterdam = Some(amsterdam_schedule.into())
        }
        blob_schedule
    }
}

impl From<ForkBlobSchedule> for ethrex_common::types::ForkBlobSchedule {
    fn from(val: ForkBlobSchedule) -> Self {
        ethrex_common::types::ForkBlobSchedule {
            target: val.target,
            max: val.max,
            base_fee_update_fraction: val.base_fee_update_fraction,
        }
    }
}

impl TestUnit {
    /// Checks whether a test has a block where the inner_block is none.
    /// These tests only check for failures in decoding invalid rlp and expect an exception.
    pub fn is_rlp_only_test(&self) -> bool {
        let mut is_rlp_only = false;
        for block in self.blocks.iter() {
            is_rlp_only = is_rlp_only || block.block().is_none();
        }
        is_rlp_only
    }

    pub fn get_genesis(&self) -> Genesis {
        let mut config = *self.network.chain_config();
        // Overwrite default blob schedule with test's blob schedule
        if let Some(test_config) = &self.config
            && let Some(ref schedule) = test_config.blob_schedule
        {
            config.blob_schedule = schedule.clone().into();
        }
        Genesis {
            config,
            alloc: self
                .pre
                .clone()
                .into_iter()
                .map(|(key, val)| (key, val.into()))
                .collect(),
            coinbase: self.genesis_block_header.coinbase,
            difficulty: self.genesis_block_header.difficulty,
            extra_data: self.genesis_block_header.extra_data.clone(),
            gas_limit: self.genesis_block_header.gas_limit.try_into().unwrap(),
            nonce: self.genesis_block_header.nonce.to_low_u64_be(),
            mix_hash: self.genesis_block_header.mix_hash,
            timestamp: self.genesis_block_header.timestamp.try_into().unwrap(),
            base_fee_per_gas: self
                .genesis_block_header
                .base_fee_per_gas
                .map(|v| v.try_into().unwrap()),
            blob_gas_used: self
                .genesis_block_header
                .blob_gas_used
                .map(|v| v.try_into().unwrap()),
            excess_blob_gas: self
                .genesis_block_header
                .excess_blob_gas
                .map(|v| v.try_into().unwrap()),
            requests_hash: self.genesis_block_header.requests_hash,
            block_access_list_hash: self.genesis_block_header.block_access_list_hash,
            slot_number: self
                .genesis_block_header
                .slot_number
                .map(|v| v.try_into().unwrap()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Account {
    pub balance: U256,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub code: Bytes,
    pub nonce: U256,
    pub storage: HashMap<U256, U256>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Env {
    pub current_coinbase: Address,
    pub current_difficulty: U256,
    pub current_gas_limit: U256,
    pub current_number: U256,
    pub current_timestamp: U256,
    pub current_base_fee: Option<U256>,
    pub previous_hash: Option<H256>,
    pub current_random: Option<H256>,
    pub current_beacon_root: Option<H256>,
    pub current_withdrawals_root: Option<H256>,
    pub parent_blob_gas_used: Option<U256>,
    pub parent_excess_blob_gas: Option<U256>,
    pub current_excess_blob_gas: Option<U256>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}
pub type AccessList = Vec<AccessListItem>;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationListItem {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: U256,
    pub v: U256,
    pub r: U256,
    pub s: U256,
    pub signer: Option<Address>,
}
pub type AuthorizationList = Vec<AuthorizationListItem>;

/// One entry of an EIP-8141 frame transaction's `frames` list. `target` is
/// absent for a frame that targets `tx.sender` implicitly.
#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FrameItem {
    pub mode: U256,
    pub flags: U256,
    #[serde(default, deserialize_with = "deserialize_empty_as_none_address")]
    pub target: Option<Address>,
    /// EIP-8141 exposes a frame's two gas budgets separately: `gasLimit` is the
    /// execution dimension and `stateGasLimit` the state dimension.
    pub gas_limit: U256,
    pub state_gas_limit: U256,
    pub value: U256,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub data: Bytes,
}

/// One entry of an EIP-8141 frame transaction's `signatures` list. `signer` is
/// absent for an `ARBITRARY` entry, which the protocol assigns no signer.
#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FrameSignatureItem {
    pub scheme: U256,
    #[serde(default, deserialize_with = "deserialize_empty_as_none_address")]
    pub signer: Option<Address>,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub msg: Bytes,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub signature: Bytes,
}

pub type FrameList = Vec<FrameItem>;
pub type FrameSignatureList = Vec<FrameSignatureItem>;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub bloom: Bloom,
    pub coinbase: Address,
    pub difficulty: U256,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub hash: H256,
    pub mix_hash: H256,
    pub nonce: H64,
    pub number: U256,
    pub parent_hash: H256,
    pub receipt_trie: H256,
    pub state_root: H256,
    pub timestamp: U256,
    pub transactions_trie: H256,
    pub uncle_hash: H256,
    pub base_fee_per_gas: Option<U256>,
    pub withdrawals_root: Option<H256>,
    pub blob_gas_used: Option<U256>,
    pub excess_blob_gas: Option<U256>,
    pub parent_beacon_block_root: Option<H256>,
    pub requests_hash: Option<H256>,
    // Amsterdam fork fields (EIP-7928)
    pub block_access_list_hash: Option<H256>,
    pub slot_number: Option<U256>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockWithRLP {
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub rlp: Bytes,
    #[serde(flatten)]
    inner: Option<BlockInner>,
    #[serde(
        rename = "expectException",
        default,
        deserialize_with = "deserialize_block_expected_exception"
    )]
    pub expect_exception: Option<Vec<BlockChainExpectedException>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(untagged)]
pub enum BlockInner {
    Block(Block),
    DecodedRLP(DecodedRLPBlock),
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
pub struct DecodedRLPBlock {
    rlp_decoded: Block,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub block_header: Header,
    #[serde(default)]
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub uncle_headers: Vec<Header>,
    pub withdrawals: Option<Vec<Withdrawal>>,
    /// Execution witness from zkevm fixtures (standard format: state/codes/headers).
    #[serde(default, rename = "executionWitness")]
    pub execution_witness: Option<serde_json::Value>,
    /// Reference-encoded stateless input bytes from zkevm fixtures.
    #[serde(default, rename = "statelessInputBytes")]
    pub stateless_input_bytes: Option<String>,
    /// Expected stateless output bytes from zkevm fixtures.
    #[serde(default, rename = "statelessOutputBytes")]
    pub stateless_output_bytes: Option<String>,
    /// Block access list from zkevm fixtures.
    #[serde(default, rename = "blockAccessList")]
    pub block_access_list_data: Option<serde_json::Value>,
    /// Transaction receipts from zkevm fixtures.
    #[serde(default, rename = "receipts")]
    pub receipts: Option<serde_json::Value>,
}

impl BlockWithRLP {
    pub fn block(&self) -> Option<&Block> {
        match self.inner {
            Some(BlockInner::Block(ref block)) => Some(block),
            Some(BlockInner::DecodedRLP(ref decoded)) => Some(&decoded.rlp_decoded),
            None => None,
        }
    }
}
impl From<Block> for CoreBlock {
    fn from(val: Block) -> Self {
        CoreBlock::new(
            val.block_header.into(),
            BlockBody {
                transactions: val.transactions.iter().map(|t| t.clone().into()).collect(),
                ommers: val.uncle_headers.iter().map(|h| h.clone().into()).collect(),
                withdrawals: val.withdrawals,
            },
        )
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(rename = "type")]
    pub transaction_type: Option<U256>,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    pub data: Bytes,
    pub gas_limit: U256,
    pub gas_price: Option<U256>,
    pub nonce: U256,
    pub r: U256,
    pub s: U256,
    pub v: U256,
    pub value: U256,
    pub chain_id: Option<U256>,
    pub access_list: Option<AccessList>,
    pub authorization_list: Option<AuthorizationList>,
    pub max_fee_per_gas: Option<U256>,
    pub max_fee_per_blob_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub blob_versioned_hashes: Option<Vec<H256>>,
    pub hash: Option<H256>,
    pub sender: Option<Address>,
    pub to: TxKind,
    /// EIP-8141 only: a type-0x06 transaction carries frames and an outer
    /// signature list in place of a single ECDSA signature.
    pub frames: Option<FrameList>,
    pub signatures: Option<FrameSignatureList>,
}

// Conversions between EFtests & ethrex types
impl From<Header> for BlockHeader {
    fn from(val: Header) -> Self {
        BlockHeader {
            parent_hash: val.parent_hash,
            ommers_hash: val.uncle_hash,
            coinbase: val.coinbase,
            state_root: val.state_root,
            transactions_root: val.transactions_trie,
            receipts_root: val.receipt_trie,
            logs_bloom: val.bloom,
            difficulty: val.difficulty,
            number: val.number.try_into().unwrap(),
            gas_limit: val.gas_limit.try_into().unwrap(),
            gas_used: val.gas_used.try_into().unwrap(),
            timestamp: val.timestamp.try_into().unwrap(),
            extra_data: val.extra_data,
            prev_randao: val.mix_hash,
            nonce: val.nonce.to_low_u64_be(),
            base_fee_per_gas: val.base_fee_per_gas.map(|v| v.try_into().unwrap()),
            withdrawals_root: val.withdrawals_root,
            blob_gas_used: val.blob_gas_used.map(|x| x.try_into().unwrap()),
            excess_blob_gas: val.excess_blob_gas.map(|x| x.try_into().unwrap()),
            parent_beacon_block_root: val.parent_beacon_block_root,
            requests_hash: val.requests_hash,
            block_access_list_hash: val.block_access_list_hash,
            slot_number: val.slot_number.map(|x| x.try_into().unwrap()),
            ..Default::default()
        }
    }
}

impl From<Transaction> for ethrexTransaction {
    fn from(val: Transaction) -> Self {
        match val.transaction_type {
            Some(tx_type) => match tx_type.try_into().unwrap() {
                0 => ethrexTransaction::LegacyTransaction(val.into()),
                1 => ethrexTransaction::EIP2930Transaction(val.into()),
                2 => ethrexTransaction::EIP1559Transaction(val.into()),
                3 => ethrexTransaction::EIP4844Transaction(val.into()),
                4 => ethrexTransaction::EIP7702Transaction(val.into()),
                6 => ethrexTransaction::FrameTransaction(val.into()),
                _ => unimplemented!(),
            },
            None => ethrexTransaction::LegacyTransaction(val.into()),
        }
    }
}

impl From<Transaction> for EIP1559Transaction {
    fn from(val: Transaction) -> Self {
        EIP1559Transaction {
            // Note: gas_price is not used in this conversion as it is not part of EIP1559Transaction, this could be a problem
            chain_id: val
                .chain_id
                .map(|id| id.try_into().unwrap())
                .unwrap_or(1 /*mainnet*/), // TODO: Consider converting this into Option
            nonce: val.nonce.try_into().unwrap(),
            max_priority_fee_per_gas: val
                .max_priority_fee_per_gas
                .unwrap_or_default()
                .try_into()
                .unwrap(), // TODO: Consider converting this into Option
            max_fee_per_gas: val
                .max_fee_per_gas
                .unwrap_or(val.gas_price.unwrap_or_default())
                .try_into()
                .unwrap(), // TODO: Consider converting this into Option
            gas_limit: val.gas_limit.try_into().unwrap(),
            // to: match val.to {
            //     zero if zero == H160::zero() => TxKind::Create,
            //     _ => TxKind::Call(val.to),
            // },
            to: val.to,
            value: val.value,
            data: val.data,
            access_list: val
                .access_list
                .unwrap_or_default()
                .into_iter()
                .map(|item| (item.address, item.storage_keys))
                .collect(),
            signature_y_parity: !val.v.is_zero(),
            signature_r: val.r,
            signature_s: val.s,
            ..Default::default()
        }
    }
}

impl From<Transaction> for EIP4844Transaction {
    fn from(val: Transaction) -> Self {
        EIP4844Transaction {
            chain_id: val
                .chain_id
                .map(|id: U256| id.try_into().unwrap())
                .unwrap_or(1), // TODO: Consider converting this into Option
            nonce: val.nonce.try_into().unwrap(),
            max_priority_fee_per_gas: val
                .max_priority_fee_per_gas
                .unwrap_or_default()
                .try_into()
                .unwrap(), // TODO: Consider converting this into Option
            max_fee_per_gas: val
                .max_fee_per_gas
                .unwrap_or(val.gas_price.unwrap_or_default())
                .try_into()
                .unwrap(),
            gas: val.gas_limit.try_into().unwrap(),
            to: match val.to {
                TxKind::Call(address) => address,
                TxKind::Create => panic!("EIP4844Transaction cannot be contract creation"),
            },
            value: val.value,
            data: val.data,
            access_list: val
                .access_list
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.address, a.storage_keys))
                .collect(),
            max_fee_per_blob_gas: val.max_fee_per_blob_gas.unwrap(),
            blob_versioned_hashes: val.blob_versioned_hashes.unwrap_or_default(),
            signature_y_parity: !val.v.is_zero(),
            signature_r: val.r,
            signature_s: val.s,
            ..Default::default()
        }
    }
}

impl From<Transaction> for EIP7702Transaction {
    fn from(val: Transaction) -> Self {
        EIP7702Transaction {
            chain_id: val
                .chain_id
                .map(|id: U256| id.try_into().unwrap())
                .unwrap_or(1), // TODO: Consider converting this into Option
            nonce: val.nonce.try_into().unwrap(),
            max_priority_fee_per_gas: val
                .max_priority_fee_per_gas
                .unwrap_or_default()
                .try_into()
                .unwrap(), // TODO: Consider converting this into Option
            max_fee_per_gas: val
                .max_fee_per_gas
                .unwrap_or(val.gas_price.unwrap_or_default())
                .try_into()
                .unwrap(),
            gas_limit: val.gas_limit.try_into().unwrap(),
            to: match val.to {
                TxKind::Call(address) => address,
                TxKind::Create => panic!("EIP7702Transaction cannot be contract creation"),
            },
            value: val.value,
            data: val.data,
            access_list: val
                .access_list
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.address, a.storage_keys))
                .collect(),
            authorization_list: val
                .authorization_list
                .unwrap_or_default()
                .into_iter()
                .map(|a| ethrex_common::types::AuthorizationTuple {
                    chain_id: a.chain_id,
                    address: a.address,
                    nonce: a.nonce.try_into().unwrap(),
                    y_parity: a.v,
                    r_signature: a.r,
                    s_signature: a.s,
                })
                .collect(),
            signature_y_parity: !val.v.is_zero(),
            signature_r: val.r,
            signature_s: val.s,
            ..Default::default()
        }
    }
}

impl From<Transaction> for FrameTransaction {
    fn from(val: Transaction) -> Self {
        // A frame transaction has no top-level recipient: `to` in the fixture is
        // the ENTRY_POINT the caller-side fields are shaped around, and the real
        // sender is the explicit `sender` field, not a recovered signature.
        //
        // The scalars saturate rather than panic: a fixture may carry a chain
        // id, nonce, frame gas limit, mode, flags or signature scheme past the
        // width of the field ethrex holds it in -- deliberately, to assert the
        // transaction is rejected for it -- and this `From` has to stay total to
        // get there. Saturating cannot hide such a fixture: the block is rebuilt
        // from these fields and validated against the header the fixture ships,
        // so a field that changed under conversion fails the transactions root.
        // The fee fields need no such handling: they are `U256` on both sides
        // and pass through as they are.
        FrameTransaction {
            chain_id: val
                .chain_id
                .map(|id| id.try_into().unwrap_or(u64::MAX))
                .unwrap_or(1),
            nonce: val.nonce.try_into().unwrap_or(u64::MAX),
            sender: val.sender.unwrap_or_default(),
            frames: val
                .frames
                .unwrap_or_default()
                .into_iter()
                .map(|f| Frame {
                    mode: f.mode.try_into().unwrap_or(u8::MAX),
                    flags: f.flags.try_into().unwrap_or(u8::MAX),
                    target: f.target,
                    gas_limits: GasLimits {
                        execution: f.gas_limit.try_into().unwrap_or(u64::MAX),
                        state: f.state_gas_limit.try_into().unwrap_or(u64::MAX),
                    },
                    value: f.value,
                    data: f.data,
                })
                .collect(),
            signatures: val
                .signatures
                .unwrap_or_default()
                .into_iter()
                .map(|s| FrameSignature {
                    scheme: s.scheme.try_into().unwrap_or(u8::MAX),
                    signer: s.signer,
                    msg: s.msg,
                    signature: s.signature,
                })
                .collect(),
            max_priority_fee_per_gas: val.max_priority_fee_per_gas.unwrap_or_default(),
            max_fee_per_gas: val
                .max_fee_per_gas
                .unwrap_or(val.gas_price.unwrap_or_default()),
            max_fee_per_blob_gas: val.max_fee_per_blob_gas.unwrap_or_default(),
            blob_versioned_hashes: val.blob_versioned_hashes.unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<Transaction> for LegacyTransaction {
    fn from(val: Transaction) -> Self {
        LegacyTransaction {
            nonce: val.nonce.try_into().unwrap(),
            gas_price: val.gas_price.unwrap_or_default(), // TODO: Consider converting this into Option
            gas: val.gas_limit.try_into().unwrap(),
            // to: match val.to {
            //     zero if zero == H160::zero() => TxKind::Create,
            //     _ => TxKind::Call(val.to),
            // },
            to: val.to,
            value: val.value,
            data: val.data,
            v: val.v,
            r: val.r,
            s: val.s,
            ..Default::default()
        }
    }
}

impl From<Transaction> for EIP2930Transaction {
    fn from(val: Transaction) -> Self {
        EIP2930Transaction {
            chain_id: val
                .chain_id
                .map(|id: U256| id.try_into().unwrap())
                .unwrap_or(1),
            nonce: val.nonce.try_into().unwrap(),
            gas_price: val.gas_price.unwrap_or_default(),
            gas_limit: val.gas_limit.try_into().unwrap(),
            // to: match val.to {
            //     zero if zero == H160::zero() => TxKind::Create,
            //     _ => TxKind::Call(val.to),
            // },
            to: val.to,
            value: val.value,
            data: val.data,
            access_list: val
                .access_list
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.address, a.storage_keys))
                .collect(),
            signature_y_parity: !val.v.is_zero(),
            signature_r: val.r,
            signature_s: val.s,
            ..Default::default()
        }
    }
}

impl From<Account> for ethrexAccount {
    fn from(val: Account) -> Self {
        ethrexAccount {
            info: AccountInfo {
                code_hash: code_hash(&val.code, &ethrex_crypto::NativeCrypto),
                balance: val.balance,
                nonce: val.nonce.try_into().unwrap(),
            },
            code: Code::from_bytecode(val.code, &ethrex_crypto::NativeCrypto),
            storage: val
                .storage
                .into_iter()
                .map(|(k, v)| (H256(k.to_big_endian()), v))
                .collect(),
        }
    }
}

impl From<Account> for GenesisAccount {
    fn from(val: Account) -> Self {
        GenesisAccount {
            code: val.code,
            storage: val.storage.into_iter().collect(),
            balance: val.balance,
            nonce: val.nonce.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum BlockChainExpectedException {
    TxtException(String),
    BlockException(BlockExpectedException),
    RLPException,
    /// A malformed transaction signature (out-of-range legacy `v`, non-bool typed
    /// `y_parity`, or out-of-range `r`/`s`). Depending on tx type this surfaces either
    /// at block RLP decoding (typed tx with a non-bool `y_parity` byte) or during
    /// execution (legacy tx sender recovery rejects the signature).
    InvalidSignature,
    /// EIP-8141: a type-0x06 fee field of 2^256 or more, beyond the bound the
    /// EIP puts on a frame transaction's fees, which does not fit the `U256`
    /// fee fields. Rejected while decoding rather than at validation.
    FeeOverflow,
    /// EIP-8141: a type-0x06 transaction whose frame list breaks a structural
    /// rule (frame count, reserved mode or flag bits, a target a frame's mode
    /// forbids). ethrex enforces some of these in the RLP decoder and the
    /// rest when the frame executes, so this surfaces either at block
    /// decoding or at block execution.
    InvalidFrameFormat,
    Other,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum BlockExpectedException {
    RLPStructuresEncoding,
    IncorrectBlobGasUsed,
    BlobGasUsedAboveLimit,
    IncorrectExcessBlobGas,
    IncorrectBlockFormat,
    InvalidRequest,
    SystemContractCallFailed,
    RlpBlockLimitExceeded,
    Other, //TODO: Implement exceptions
}
