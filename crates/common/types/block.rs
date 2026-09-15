use super::{
    BASE_FEE_MAX_CHANGE_DENOMINATOR, ChainConfig, Fork, ForkBlobSchedule,
    GAS_LIMIT_ADJUSTMENT_FACTOR, GAS_LIMIT_MINIMUM, INITIAL_BASE_FEE,
};
use crate::{
    Address, H256, U256,
    constants::{
        BLOB_BASE_COST, DEFAULT_OMMERS_HASH, EMPTY_WITHDRAWALS_HASH, GAS_PER_BLOB,
        MIN_BASE_FEE_PER_BLOB_GAS,
    },
    types::{Receipt, Transaction},
};
use bytes::Bytes;
use ethereum_types::Bloom;
use ethrex_crypto::{Crypto, CryptoError, NativeCrypto};
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use ethrex_trie::Trie;
#[cfg(feature = "rayon")]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rkyv::{Archive, Deserialize as RDeserialize, Serialize as RSerialize};
use serde::{Deserialize, Serialize};

use std::cmp::{Ordering, max};

pub type BlockNumber = u64;
pub type BlockHash = H256;

#[cfg(all(feature = "zisk", target_arch = "riscv64"))]
use super::unsync_cell::OnceCell;
#[cfg(not(all(feature = "zisk", target_arch = "riscv64")))]
use once_cell::sync::OnceCell;

#[derive(
    PartialEq, Eq, Debug, Clone, Deserialize, Serialize, Default, RSerialize, RDeserialize, Archive,
)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl Block {
    pub fn new(header: BlockHeader, body: BlockBody) -> Block {
        Block { header, body }
    }

    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }
}

impl RLPEncode for Block {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.header)
            .encode_field(&self.body.transactions)
            .encode_field(&self.body.ommers)
            .encode_optional_field(&self.body.withdrawals)
            .finish();
    }
}

impl RLPDecode for Block {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (header, decoder) = decoder.decode_field("header")?;
        let (transactions, decoder) = decoder.decode_field("transactions")?;
        let (ommers, decoder) = decoder.decode_field("ommers")?;
        let (withdrawals, decoder) = decoder.decode_optional_field();
        let remaining = decoder.finish()?;
        let body = BlockBody {
            transactions,
            ommers,
            withdrawals,
        };
        let block = Block::new(header, body);
        Ok((block, remaining))
    }
}

/// Header part of a block on the chain.
#[derive(Clone, Debug, Serialize, Default, Deserialize, RSerialize, RDeserialize, Archive, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    #[serde(skip)]
    #[rkyv(with=rkyv::with::Skip)]
    pub hash: OnceCell<BlockHash>,
    #[rkyv(with=crate::rkyv_utils::H256Wrapper)]
    pub parent_hash: H256,
    #[serde(rename = "sha3Uncles")]
    #[rkyv(with=crate::rkyv_utils::H256Wrapper)]
    pub ommers_hash: H256, // ommer = uncle
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    #[serde(rename = "miner")]
    pub coinbase: Address,
    #[rkyv(with=crate::rkyv_utils::H256Wrapper)]
    pub state_root: H256,
    #[rkyv(with=crate::rkyv_utils::H256Wrapper)]
    pub transactions_root: H256,
    #[rkyv(with=crate::rkyv_utils::H256Wrapper)]
    pub receipts_root: H256,
    #[rkyv(with=crate::rkyv_utils::BloomWrapper)]
    pub logs_bloom: Bloom,
    #[serde(default)]
    #[rkyv(with=crate::rkyv_utils::U256Wrapper)]
    pub difficulty: U256,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub number: BlockNumber,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub gas_used: u64,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub timestamp: u64,
    #[serde(with = "crate::serde_utils::bytes")]
    #[rkyv(with= crate::rkyv_utils::BytesWrapper)]
    pub extra_data: Bytes,
    #[serde(rename = "mixHash")]
    #[rkyv(with=crate::rkyv_utils::H256Wrapper)]
    pub prev_randao: H256,
    #[serde(with = "crate::serde_utils::u64::hex_str_padding")]
    pub nonce: u64,
    #[serde(default, with = "crate::serde_utils::u64::hex_str_opt")]
    pub base_fee_per_gas: Option<u64>,
    #[rkyv(with=crate::rkyv_utils::OptionH256Wrapper)]
    pub withdrawals_root: Option<H256>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::u64::hex_str_opt",
        default = "Option::default"
    )]
    pub blob_gas_used: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::u64::hex_str_opt",
        default = "Option::default"
    )]
    pub excess_blob_gas: Option<u64>,
    #[rkyv(with=crate::rkyv_utils::OptionH256Wrapper)]
    pub parent_beacon_block_root: Option<H256>,
    #[serde(skip_serializing_if = "Option::is_none", default = "Option::default")]
    #[rkyv(with=crate::rkyv_utils::OptionH256Wrapper)]
    pub requests_hash: Option<H256>,
    // Amsterdam fork fields (EIP-7928)
    #[serde(skip_serializing_if = "Option::is_none", default = "Option::default")]
    #[rkyv(with=crate::rkyv_utils::OptionH256Wrapper)]
    pub block_access_list_hash: Option<H256>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::u64::hex_str_opt",
        default = "Option::default"
    )]
    pub slot_number: Option<u64>,
    // LStar fork fields (EIP-8079)
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::u64::hex_str_opt",
        default = "Option::default"
    )]
    pub burned_fees: Option<u64>,
}

// Needs a explicit impl due to the hash OnceLock.
impl PartialEq for BlockHeader {
    fn eq(&self, other: &Self) -> bool {
        let BlockHeader {
            hash: _,
            parent_hash,
            ommers_hash,
            coinbase,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            prev_randao,
            nonce,
            base_fee_per_gas,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
            requests_hash,
            block_access_list_hash,
            slot_number,
            burned_fees,
        } = self;

        parent_hash == &other.parent_hash
            && number == &other.number
            && timestamp == &other.timestamp
            && nonce == &other.nonce
            && gas_used == &other.gas_used
            && gas_limit == &other.gas_limit
            && base_fee_per_gas == &other.base_fee_per_gas
            && blob_gas_used == &other.blob_gas_used
            && excess_blob_gas == &other.excess_blob_gas
            && parent_beacon_block_root == &other.parent_beacon_block_root
            && prev_randao == &other.prev_randao
            && coinbase == &other.coinbase
            && state_root == &other.state_root
            && transactions_root == &other.transactions_root
            && receipts_root == &other.receipts_root
            && withdrawals_root == &other.withdrawals_root
            && difficulty == &other.difficulty
            && ommers_hash == &other.ommers_hash
            && requests_hash == &other.requests_hash
            && block_access_list_hash == &other.block_access_list_hash
            && slot_number == &other.slot_number
            && burned_fees == &other.burned_fees
            && logs_bloom == &other.logs_bloom
            && extra_data == &other.extra_data
    }
}

impl RLPEncode for BlockHeader {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.parent_hash)
            .encode_field(&self.ommers_hash)
            .encode_field(&self.coinbase)
            .encode_field(&self.state_root)
            .encode_field(&self.transactions_root)
            .encode_field(&self.receipts_root)
            .encode_field(&self.logs_bloom)
            .encode_field(&self.difficulty)
            .encode_field(&self.number)
            .encode_field(&self.gas_limit)
            .encode_field(&self.gas_used)
            .encode_field(&self.timestamp)
            .encode_field(&self.extra_data)
            .encode_field(&self.prev_randao)
            .encode_field(&self.nonce.to_be_bytes())
            .encode_optional_field(&self.base_fee_per_gas)
            .encode_optional_field(&self.withdrawals_root)
            .encode_optional_field(&self.blob_gas_used)
            .encode_optional_field(&self.excess_blob_gas)
            .encode_optional_field(&self.parent_beacon_block_root)
            .encode_optional_field(&self.requests_hash)
            .encode_optional_field(&self.block_access_list_hash)
            .encode_optional_field(&self.slot_number)
            .encode_optional_field(&self.burned_fees)
            .finish();
    }
}

impl RLPDecode for BlockHeader {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (parent_hash, decoder) = decoder.decode_field("parent_hash")?;
        let (ommers_hash, decoder) = decoder.decode_field("ommers_hash")?;
        let (coinbase, decoder) = decoder.decode_field("coinbase")?;
        let (state_root, decoder) = decoder.decode_field("state_root")?;
        let (transactions_root, decoder) = decoder.decode_field("transactions_root")?;
        let (receipts_root, decoder) = decoder.decode_field("receipts_root")?;
        let (logs_bloom, decoder) = decoder.decode_field("logs_bloom")?;
        let (difficulty, decoder) = decoder.decode_field("difficulty")?;
        let (number, decoder) = decoder.decode_field("number")?;
        let (gas_limit, decoder) = decoder.decode_field("gas_limit")?;
        let (gas_used, decoder) = decoder.decode_field("gas_used")?;
        let (timestamp, decoder) = decoder.decode_field("timestamp")?;
        let (extra_data, decoder) = decoder.decode_field("extra_data")?;
        let (prev_randao, decoder) = decoder.decode_field("prev_randao")?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let nonce = u64::from_be_bytes(nonce);
        let (base_fee_per_gas, decoder) = decoder.decode_optional_field();
        let (withdrawals_root, decoder) = decoder.decode_optional_field();
        let (blob_gas_used, decoder) = decoder.decode_optional_field();
        let (excess_blob_gas, decoder) = decoder.decode_optional_field();
        let (parent_beacon_block_root, decoder) = decoder.decode_optional_field();
        let (requests_hash, decoder) = decoder.decode_optional_field();
        let (block_access_list_hash, decoder) = decoder.decode_optional_field();
        let (slot_number, decoder) = decoder.decode_optional_field();
        let (burned_fees, decoder) = decoder.decode_optional_field();

        Ok((
            BlockHeader {
                hash: OnceCell::new(),
                parent_hash,
                ommers_hash,
                coinbase,
                state_root,
                transactions_root,
                receipts_root,
                logs_bloom,
                difficulty,
                number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                prev_randao,
                nonce,
                base_fee_per_gas,
                withdrawals_root,
                blob_gas_used,
                excess_blob_gas,
                parent_beacon_block_root,
                requests_hash,
                block_access_list_hash,
                slot_number,
                burned_fees,
            },
            decoder.finish()?,
        ))
    }
}

// The body of a block on the chain
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default, RSerialize, RDeserialize, Archive,
)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    // TODO: ommers list is always empty, so we can remove it
    #[serde(rename = "uncles")]
    pub ommers: Vec<BlockHeader>,
    pub withdrawals: Option<Vec<Withdrawal>>,
}

impl BlockBody {
    pub const fn empty() -> Self {
        Self {
            transactions: Vec::new(),
            ommers: Vec::new(),
            withdrawals: Some(Vec::new()),
        }
    }

    pub fn get_transactions_with_sender(
        &self,
        crypto: &dyn Crypto,
    ) -> Result<Vec<(&Transaction, Address)>, CryptoError> {
        // Recovering addresses is computationally expensive.
        // Computing them in parallel greatly reduces execution time.
        // Without rayon, use sequential iteration
        #[cfg(feature = "rayon")]
        return self
            .transactions
            .par_iter()
            .map(|tx| Ok((tx, tx.sender(crypto)?)))
            .collect::<Result<Vec<(&Transaction, Address)>, CryptoError>>();

        #[cfg(not(feature = "rayon"))]
        self.transactions
            .iter()
            .map(|tx| Ok((tx, tx.sender(crypto)?)))
            .collect::<Result<Vec<(&Transaction, Address)>, CryptoError>>()
    }
}

pub fn compute_transactions_root(transactions: &[Transaction], crypto: &dyn Crypto) -> H256 {
    let iter = transactions.iter().enumerate().map(|(idx, tx)| {
        // Key: RLP(tx_index)
        // Value: tx_type || RLP(tx)  if tx_type != 0
        //                   RLP(tx)  else
        (idx.encode_to_vec(), tx.encode_canonical_to_vec())
    });
    Trie::compute_hash_from_unsorted_iter(iter, crypto)
}

pub fn compute_receipts_root(receipts: &[Receipt], crypto: &dyn Crypto) -> H256 {
    let iter = receipts
        .iter()
        .enumerate()
        .map(|(idx, receipt)| (idx.encode_to_vec(), receipt.encode_inner_with_bloom(crypto)));
    Trie::compute_hash_from_unsorted_iter(iter, crypto)
}

/// Computes the receipts root and the aggregate header `logs_bloom` in a single pass,
/// hashing each receipt's bloom only once (it feeds both the receipts trie and the
/// OR-ed header bloom). Validation paths need both, so this avoids the duplicate
/// `bloom_from_logs` keccak work — relevant in the zkVM guest where it is cycle-counted.
pub fn compute_receipts_root_and_logs_bloom(
    receipts: &[Receipt],
    crypto: &dyn Crypto,
) -> (H256, Bloom) {
    let mut logs_bloom = Bloom::zero();
    let iter = receipts.iter().enumerate().map(|(idx, receipt)| {
        let bloom = crate::types::bloom_from_logs(&receipt.logs, crypto);
        logs_bloom |= bloom;
        (
            idx.encode_to_vec(),
            receipt.encode_inner_with_precomputed_bloom(bloom),
        )
    });
    let receipts_root = Trie::compute_hash_from_unsorted_iter(iter, crypto);
    (receipts_root, logs_bloom)
}

// See [EIP-4895](https://eips.ethereum.org/EIPS/eip-4895)
pub fn compute_withdrawals_root(withdrawals: &[Withdrawal], crypto: &dyn Crypto) -> H256 {
    let iter = withdrawals
        .iter()
        .enumerate()
        .map(|(idx, withdrawal)| (idx.encode_to_vec(), withdrawal.encode_to_vec()));
    Trie::compute_hash_from_unsorted_iter(iter, crypto)
}

impl RLPEncode for BlockBody {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.transactions)
            .encode_field(&self.ommers)
            .encode_optional_field(&self.withdrawals)
            .finish();
    }
}

impl RLPDecode for BlockBody {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (transactions, decoder) = decoder.decode_field("transactions")?;
        let (ommers, decoder) = decoder.decode_field("ommers")?;
        let (withdrawals, decoder) = decoder.decode_optional_field();
        Ok((
            BlockBody {
                transactions,
                ommers,
                withdrawals,
            },
            decoder.finish()?,
        ))
    }
}

impl BlockHeader {
    pub fn compute_block_hash(&self, crypto: &dyn Crypto) -> H256 {
        let mut buf = vec![];
        self.encode(&mut buf);
        H256(crypto.keccak256(&buf))
    }

    pub fn hash(&self) -> H256 {
        *self
            .hash
            .get_or_init(|| self.compute_block_hash(&NativeCrypto))
    }

    /// Returns `self` with `burned_fees` set and the hash cache cleared.
    ///
    /// After `execute_blocks`, the header's `OnceCell` may already hold a stale
    /// hash that was computed before `burned_fees` was known (e.g. during
    /// `initialize_block_header_hashes`).  Taking ownership and clearing the
    /// cache guarantees that the next call to `hash()` reflects the injected
    /// value — without any extra `once_cell` dependency at the call site.
    pub fn into_with_burned_fees(mut self, burned_fees: Option<u64>) -> Self {
        self.burned_fees = burned_fees;
        let _ = self.hash.take(); // clear stale cached hash
        self
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, Deserialize, Serialize, RSerialize, RDeserialize, Archive,
)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub index: u64,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub validator_index: u64,
    #[rkyv(with=crate::rkyv_utils::H160Wrapper)]
    pub address: Address,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub amount: u64,
}

impl RLPEncode for Withdrawal {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.index)
            .encode_field(&self.validator_index)
            .encode_field(&self.address)
            .encode_field(&self.amount)
            .finish();
    }
}

impl RLPDecode for Withdrawal {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (index, decoder) = decoder.decode_field("index")?;
        let (validator_index, decoder) = decoder.decode_field("validator_index")?;
        let (address, decoder) = decoder.decode_field("address")?;
        let (amount, decoder) = decoder.decode_field("amount")?;
        Ok((
            Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            decoder.finish()?,
        ))
    }
}

// Checks that the gas_limit fits the gas bounds set by its parent block
fn check_gas_limit(gas_limit: u64, parent_gas_limit: u64) -> bool {
    let max_adjustment_delta = parent_gas_limit / GAS_LIMIT_ADJUSTMENT_FACTOR;

    gas_limit < parent_gas_limit + max_adjustment_delta
        && gas_limit > parent_gas_limit - max_adjustment_delta
        && gas_limit >= GAS_LIMIT_MINIMUM
}

/// Calculates the base fee per blob gas for the current block based on
/// it's parent excess blob gas and the update fraction, which depends on the fork.
pub fn calculate_base_fee_per_blob_gas(parent_excess_blob_gas: u64, update_fraction: u64) -> U256 {
    if update_fraction == 0 {
        return U256::zero();
    }

    fake_exponential(
        U256::from(MIN_BASE_FEE_PER_BLOB_GAS),
        U256::from(parent_excess_blob_gas),
        update_fraction,
    )
    .unwrap_or_default()
}

/// Approximates factor * e ** (numerator / denominator) using Taylor expansion
/// https://eips.ethereum.org/EIPS/eip-4844#helpers
/// 400_000_000 numerator is the limit for this operation to work with U256,
/// it will overflow with a larger numerator
pub fn fake_exponential(
    factor: U256,
    numerator: U256,
    denominator: u64,
) -> Result<U256, FakeExponentialError> {
    if denominator == 0 {
        return Err(FakeExponentialError::DenominatorIsZero);
    }

    if numerator.is_zero() {
        return Ok(factor);
    }

    let mut output: U256 = U256::zero();
    let denominator_u256: U256 = denominator.into();

    // Initial multiplication: factor * denominator
    let mut numerator_accum = factor
        .checked_mul(denominator_u256)
        .ok_or(FakeExponentialError::CheckedMul)?;

    let mut denominator_by_i = denominator_u256;

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "division can't overflow since denominator is not 0"
    )]
    {
        while !numerator_accum.is_zero() {
            // Safe addition to output
            output = output
                .checked_add(numerator_accum)
                .ok_or(FakeExponentialError::CheckedAdd)?;

            // Safe multiplication and division within loop
            numerator_accum = numerator_accum
                .checked_mul(numerator)
                .ok_or(FakeExponentialError::CheckedMul)?
                / denominator_by_i;

            // denominator comes from a u64 value, will never overflow before other variables.
            denominator_by_i += denominator_u256;
        }

        output
            .checked_div(denominator.into())
            .ok_or(FakeExponentialError::CheckedDiv)
    }
}

#[derive(Debug, thiserror::Error, Serialize, Clone, PartialEq, Deserialize, Eq)]
pub enum FakeExponentialError {
    #[error("FakeExponentialError: Denominator cannot be zero.")]
    DenominatorIsZero,
    #[error("FakeExponentialError: Checked div failed is None.")]
    CheckedDiv,
    #[error("FakeExponentialError: Checked mul failed is None.")]
    CheckedMul,
    #[error("FakeExponentialError: Checked add failed is None.")]
    CheckedAdd,
}

// Calculates the base fee for the current block based on its gas_limit and parent's gas and fee
// Returns None if the block gas limit is not valid in relation to its parent's gas limit
pub fn calculate_base_fee_per_gas(
    block_gas_limit: u64,
    parent_gas_limit: u64,
    parent_gas_used: u64,
    parent_base_fee_per_gas: u64,
    elasticity_multiplier: u64,
) -> Option<u64> {
    // Check gas limit, if the check passes we can also rest assured that none of the
    // following divisions will have zero as a divider
    if !check_gas_limit(block_gas_limit, parent_gas_limit) {
        return None;
    }

    let parent_gas_target = parent_gas_limit / elasticity_multiplier;

    match parent_gas_used.cmp(&parent_gas_target) {
        Ordering::Equal => Some(parent_base_fee_per_gas),
        Ordering::Greater => {
            let gas_used_delta = parent_gas_used - parent_gas_target;

            let parent_fee_gas_delta =
                u128::from(parent_base_fee_per_gas) * u128::from(gas_used_delta);
            let target_fee_gas_delta = parent_fee_gas_delta / u128::from(parent_gas_target);

            let base_fee_per_gas_delta =
                max(target_fee_gas_delta / BASE_FEE_MAX_CHANGE_DENOMINATOR, 1);

            (u128::from(parent_base_fee_per_gas) + base_fee_per_gas_delta)
                .try_into()
                .ok()
        }
        Ordering::Less => {
            let gas_used_delta = parent_gas_target - parent_gas_used;

            let parent_fee_gas_delta =
                u128::from(parent_base_fee_per_gas) * u128::from(gas_used_delta);
            let target_fee_gas_delta = parent_fee_gas_delta / u128::from(parent_gas_target);

            let base_fee_per_gas_delta = target_fee_gas_delta / BASE_FEE_MAX_CHANGE_DENOMINATOR;

            (u128::from(parent_base_fee_per_gas) - base_fee_per_gas_delta)
                .try_into()
                .ok()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidBlockHeaderError {
    #[error("Gas used is greater than gas limit")]
    GasUsedGreaterThanGasLimit,
    #[error("Gas limit changed more than allowed from the parent")]
    GasLimitTooFarFromParent,
    #[error("Base fee per gas is incorrect")]
    BaseFeePerGasIncorrect,
    #[error("Timestamp is not greater than parent timestamp")]
    TimestampNotGreaterThanParent,
    #[error("Block number is not one greater than parent number")]
    BlockNumberNotOneGreater,
    #[error("Extra data is too long")]
    ExtraDataTooLong,
    #[error("Difficulty is not zero")]
    DifficultyNotZero,
    #[error("Nonce is not zero")]
    NonceNotZero,
    #[error("Ommers hash is not the default")]
    OmmersHashNotDefault,
    #[error("Parent hash is incorrect")]
    ParentHashIncorrect,
    // Cancun fork errors
    #[error("Excess blob gas is not present")]
    ExcessBlobGasNotPresent,
    #[error("Blob gas used is not present")]
    BlobGasUsedNotPresent,
    #[error("Excess blob gas is incorrect")]
    ExcessBlobGasIncorrect,
    #[error("Parent beacon block root is not present")]
    ParentBeaconBlockRootNotPresent,
    #[error("Requests hash is not present")]
    RequestsHashNotPresent,
    // Other fork errors
    #[error("Excess blob gas is present")]
    ExcessBlobGasPresent,
    #[error("Blob gas used is present")]
    BlobGasUsedPresent,
    #[error("Parent beacon block root is present")]
    ParentBeaconBlockRootPresent,
    #[error("Requests hash is present")]
    RequestsHashPresent,
    #[error("Block access list hash is not present")]
    BlockAccessListHashNotPresent,
    #[error("Block access list hash is present")]
    BlockAccessListHashPresent,
    #[error("Slot number is not present")]
    SlotNumberNotPresent,
    #[error("Slot number is present")]
    SlotNumberPresent,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidBlockBodyError {
    #[error("Withdrawals root does not match")]
    WithdrawalsRootNotMatch,
    #[error("Transactions root does not match")]
    TransactionsRootNotMatch,
    #[error("Ommers is not empty")]
    OmmersIsNotEmpty,
}

/// Validates that the header fields are correct in reference to the parent_header
pub fn validate_block_header(
    header: &BlockHeader,
    parent_header: &BlockHeader,
    elasticity_multiplier: u64,
) -> Result<(), InvalidBlockHeaderError> {
    if header.gas_used > header.gas_limit {
        return Err(InvalidBlockHeaderError::GasUsedGreaterThanGasLimit);
    }

    let expected_base_fee_per_gas = if let Some(base_fee) = calculate_base_fee_per_gas(
        header.gas_limit,
        parent_header.gas_limit,
        parent_header.gas_used,
        parent_header.base_fee_per_gas.unwrap_or(INITIAL_BASE_FEE),
        elasticity_multiplier,
    ) {
        base_fee
    } else {
        return Err(InvalidBlockHeaderError::GasLimitTooFarFromParent);
    };

    if expected_base_fee_per_gas != header.base_fee_per_gas.unwrap_or(INITIAL_BASE_FEE) {
        return Err(InvalidBlockHeaderError::BaseFeePerGasIncorrect);
    }

    if header.timestamp <= parent_header.timestamp {
        return Err(InvalidBlockHeaderError::TimestampNotGreaterThanParent);
    }

    if header.number != parent_header.number + 1 {
        return Err(InvalidBlockHeaderError::BlockNumberNotOneGreater);
    }

    if header.extra_data.len() > 32 {
        return Err(InvalidBlockHeaderError::ExtraDataTooLong);
    }

    if !header.difficulty.is_zero() {
        return Err(InvalidBlockHeaderError::DifficultyNotZero);
    }

    if header.nonce != 0 {
        return Err(InvalidBlockHeaderError::NonceNotZero);
    }

    if header.ommers_hash != *DEFAULT_OMMERS_HASH {
        return Err(InvalidBlockHeaderError::OmmersHashNotDefault);
    }

    if header.parent_hash != parent_header.hash() {
        return Err(InvalidBlockHeaderError::ParentHashIncorrect);
    }

    Ok(())
}

/// Validates that the body matches with the header
pub fn validate_block_body(
    block_header: &BlockHeader,
    block_body: &BlockBody,
    crypto: &dyn Crypto,
) -> Result<(), InvalidBlockBodyError> {
    // Validates that:
    //  - Transactions root and withdrawals root matches with the header
    //  - Ommers is empty -> https://eips.ethereum.org/EIPS/eip-3675
    let computed_tx_root = compute_transactions_root(&block_body.transactions, crypto);

    if block_header.transactions_root != computed_tx_root {
        return Err(InvalidBlockBodyError::TransactionsRootNotMatch);
    }

    if !block_body.ommers.is_empty() {
        return Err(InvalidBlockBodyError::OmmersIsNotEmpty);
    }

    match (block_header.withdrawals_root, &block_body.withdrawals) {
        (Some(withdrawals_root), Some(withdrawals)) => {
            let computed_withdrawals_root = compute_withdrawals_root(withdrawals, crypto);
            if withdrawals_root != computed_withdrawals_root {
                return Err(InvalidBlockBodyError::WithdrawalsRootNotMatch);
            }
        }
        // Post-Shanghai, the withdrawals field must be present in the body even when
        // empty. A body that omits it is malformed, regardless of the header's
        // withdrawals_root — geth ("missing withdrawals in block body"), reth,
        // nethermind, erigon and besu all reject this shape.
        (None, None) => {}
        _ => return Err(InvalidBlockBodyError::WithdrawalsRootNotMatch),
    }

    Ok(())
}

/// Normalizes a legacy post-Shanghai body shape produced by older ethrex versions,
/// which omitted the `withdrawals` field while the header committed to the
/// empty-withdrawals root. `validate_block_body` rejects that shape (reference
/// clients treat it as malformed on the wire), but blocks already sitting in a
/// node's store or in batch blobs published to L1 are immutable history. When the
/// header's withdrawals_root is exactly the empty-list root, `Some(vec![])` is the
/// provably-equivalent canonical body; any other root leaves the body untouched, and
/// validation rejects it exactly as before.
///
/// Only call this on bodies read from trusted local history (store re-execution,
/// blob reconstruction) — never on bodies received from the network.
pub fn normalize_legacy_withdrawals(header: &BlockHeader, body: &mut BlockBody) {
    if body.withdrawals.is_none() && header.withdrawals_root == Some(*EMPTY_WITHDRAWALS_HASH) {
        tracing::debug!(
            block = header.number,
            "Normalizing legacy omitted-withdrawals block body from trusted history"
        );
        body.withdrawals = Some(Vec::new());
    }
}

/// Validates that only the required field are present for a Prague block
/// Also validates excess_blob_gas value against parent's header
pub fn validate_prague_header_fields(
    header: &BlockHeader,
    parent_header: &BlockHeader,
    chain_config: &ChainConfig,
) -> Result<(), InvalidBlockHeaderError> {
    if header.excess_blob_gas.is_none() {
        return Err(InvalidBlockHeaderError::ExcessBlobGasNotPresent);
    }
    if header.blob_gas_used.is_none() {
        return Err(InvalidBlockHeaderError::BlobGasUsedNotPresent);
    }
    validate_excess_blob_gas(header, parent_header, chain_config)?;

    if header.parent_beacon_block_root.is_none() {
        return Err(InvalidBlockHeaderError::ParentBeaconBlockRootNotPresent);
    }
    if header.requests_hash.is_none() {
        return Err(InvalidBlockHeaderError::RequestsHashNotPresent);
    }
    if chain_config.is_amsterdam_activated(header.timestamp) {
        // EIP-7928: BAL hash and EIP-7843: slot_number are both mandatory
        // trailing header fields on Amsterdam. A header omitting either is
        // schema-invalid and must be rejected to match conformant clients.
        if header.block_access_list_hash.is_none() {
            return Err(InvalidBlockHeaderError::BlockAccessListHashNotPresent);
        }
        if header.slot_number.is_none() {
            return Err(InvalidBlockHeaderError::SlotNumberNotPresent);
        }
    } else {
        if header.block_access_list_hash.is_some() {
            return Err(InvalidBlockHeaderError::BlockAccessListHashPresent);
        }
        if header.slot_number.is_some() {
            return Err(InvalidBlockHeaderError::SlotNumberPresent);
        }
    }
    Ok(())
}

/// Validates that only the required field are present for a Cancun block
/// Also validates excess_blob_gas value against parent's header
pub fn validate_cancun_header_fields(
    header: &BlockHeader,
    parent_header: &BlockHeader,
    chain_config: &ChainConfig,
) -> Result<(), InvalidBlockHeaderError> {
    if header.excess_blob_gas.is_none() {
        return Err(InvalidBlockHeaderError::ExcessBlobGasNotPresent);
    }
    if header.blob_gas_used.is_none() {
        return Err(InvalidBlockHeaderError::BlobGasUsedNotPresent);
    }
    validate_excess_blob_gas(header, parent_header, chain_config)?;
    if header.parent_beacon_block_root.is_none() {
        return Err(InvalidBlockHeaderError::ParentBeaconBlockRootNotPresent);
    }
    if header.requests_hash.is_some() {
        return Err(InvalidBlockHeaderError::RequestsHashPresent);
    }
    if header.block_access_list_hash.is_some() {
        return Err(InvalidBlockHeaderError::BlockAccessListHashPresent);
    }
    if header.slot_number.is_some() {
        return Err(InvalidBlockHeaderError::SlotNumberPresent);
    }
    Ok(())
}

/// Validates that only the required field are present for a pre Cancun block
/// Also validates excess_blob_gas value against parent's header
pub fn validate_pre_cancun_header_fields(
    header: &BlockHeader,
) -> Result<(), InvalidBlockHeaderError> {
    if header.excess_blob_gas.is_some() {
        return Err(InvalidBlockHeaderError::ExcessBlobGasPresent);
    }
    if header.blob_gas_used.is_some() {
        return Err(InvalidBlockHeaderError::BlobGasUsedPresent);
    }
    if header.parent_beacon_block_root.is_some() {
        return Err(InvalidBlockHeaderError::ParentBeaconBlockRootPresent);
    }
    if header.requests_hash.is_some() {
        return Err(InvalidBlockHeaderError::RequestsHashPresent);
    }
    if header.block_access_list_hash.is_some() {
        return Err(InvalidBlockHeaderError::BlockAccessListHashPresent);
    }
    if header.slot_number.is_some() {
        return Err(InvalidBlockHeaderError::SlotNumberPresent);
    }
    Ok(())
}

fn validate_excess_blob_gas(
    header: &BlockHeader,
    parent_header: &BlockHeader,
    chain_config: &ChainConfig,
) -> Result<(), InvalidBlockHeaderError> {
    let expected_excess_blob_gas = chain_config
        .get_fork_blob_schedule(header.timestamp)
        .map(|schedule| {
            calc_excess_blob_gas(parent_header, schedule, chain_config.fork(header.timestamp))
        })
        .unwrap_or_default();
    if header
        .excess_blob_gas
        .is_none_or(|header_excess_blob_gas| header_excess_blob_gas != expected_excess_blob_gas)
    {
        return Err(InvalidBlockHeaderError::ExcessBlobGasIncorrect);
    }
    Ok(())
}

pub fn calc_excess_blob_gas(parent: &BlockHeader, schedule: ForkBlobSchedule, fork: Fork) -> u64 {
    let parent_blob_gas_used = parent.blob_gas_used.unwrap_or_default();
    let parent_base_fee_per_gas = parent.base_fee_per_gas.unwrap_or_default();
    let parent_excess_blob_gas = parent.excess_blob_gas.unwrap_or_default();

    let excess_blob_gas = parent_excess_blob_gas + parent_blob_gas_used;
    let target_blob_gas_per_block = (schedule.target * GAS_PER_BLOB) as u64;
    if excess_blob_gas < target_blob_gas_per_block {
        return 0;
    }

    if fork >= Fork::Osaka
        && U256::from(BLOB_BASE_COST) * U256::from(parent_base_fee_per_gas)
            > (U256::from(GAS_PER_BLOB))
                * calculate_base_fee_per_blob_gas(
                    parent_excess_blob_gas,
                    schedule.base_fee_update_fraction,
                )
    {
        return parent_excess_blob_gas
            + parent_blob_gas_used * (schedule.max as u64 - schedule.target as u64)
                / schedule.max as u64;
    }

    excess_blob_gas - target_blob_gas_per_block
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::EMPTY_KECCAK_HASH;
    use crate::types::{BLOB_BASE_FEE_UPDATE_FRACTION, ELASTICITY_MULTIPLIER, INITIAL_BASE_FEE};
    use ethereum_types::H160;
    use hex_literal::hex;
    use std::str::FromStr;

    #[test]
    fn test_compute_withdrawals_root() {
        // Source: https://github.com/ethereum/tests/blob/9760400e667eba241265016b02644ef62ab55de2/BlockchainTests/EIPTests/bc4895-withdrawals/amountIs0.json
        // "withdrawals" : [
        //             {
        //                 "address" : "0xc94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        //                 "amount" : "0x00",
        //                 "index" : "0x00",
        //                 "validatorIndex" : "0x00"
        //             }
        //         ]
        // "withdrawalsRoot" : "0x48a703da164234812273ea083e4ec3d09d028300cd325b46a6a75402e5a7ab95"
        let withdrawals = vec![Withdrawal {
            index: 0x00,
            validator_index: 0x00,
            address: H160::from_slice(&hex!("c94f5374fce5edbc8e2a8697c15331677e6ebf0b")),
            amount: 0x00_u64,
        }];
        let expected_root = H256::from_slice(&hex!(
            "48a703da164234812273ea083e4ec3d09d028300cd325b46a6a75402e5a7ab95"
        ));
        let root = compute_withdrawals_root(&withdrawals, &ethrex_crypto::NativeCrypto);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_validate_block_header() {
        let parent_block = BlockHeader {
            parent_hash: H256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            ommers_hash: H256::from_str(
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            )
            .unwrap(),
            coinbase: Address::zero(),
            state_root: H256::from_str(
                "0x590245a249decc317041b8dc7141cec0559c533efb82221e4e0a30a6456acf8b",
            )
            .unwrap(),
            transactions_root: H256::from_str(
                "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            )
            .unwrap(),
            receipts_root: H256::from_str(
                "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            )
            .unwrap(),
            logs_bloom: Bloom::from([0; 256]),
            difficulty: U256::zero(),
            number: 0,
            gas_limit: 0x016345785d8a0000,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::new(),
            prev_randao: H256::zero(),
            nonce: 0x0000000000000000,
            base_fee_per_gas: Some(0x07),
            withdrawals_root: Some(
                H256::from_str(
                    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                )
                .unwrap(),
            ),
            blob_gas_used: Some(0x00),
            excess_blob_gas: Some(0x00),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(*EMPTY_KECCAK_HASH),
            ..Default::default()
        };
        let block = BlockHeader {
            parent_hash: H256::from_str(
                "0x48e29e7357408113a4166e04e9f1aeff0680daa2b97ba93df6512a73ddf7a154",
            )
            .unwrap(),
            ommers_hash: H256::from_str(
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            )
            .unwrap(),
            coinbase: Address::from_str("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba").unwrap(),
            state_root: H256::from_str(
                "0x9de6f95cb4ff4ef22a73705d6ba38c4b927c7bca9887ef5d24a734bb863218d9",
            )
            .unwrap(),
            transactions_root: H256::from_str(
                "0x578602b2b7e3a3291c3eefca3a08bc13c0d194f9845a39b6f3bcf843d9fed79d",
            )
            .unwrap(),
            receipts_root: H256::from_str(
                "0x035d56bac3f47246c5eed0e6642ca40dc262f9144b582f058bc23ded72aa72fa",
            )
            .unwrap(),
            logs_bloom: Bloom::from([0; 256]),
            difficulty: U256::zero(),
            number: 1,
            gas_limit: 0x016345785d8a0000,
            gas_used: 0xa8de,
            timestamp: 0x03e8,
            extra_data: Bytes::new(),
            prev_randao: H256::zero(),
            nonce: 0x0000000000000000,
            base_fee_per_gas: Some(0x07),
            withdrawals_root: Some(
                H256::from_str(
                    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                )
                .unwrap(),
            ),
            blob_gas_used: Some(0x00),
            excess_blob_gas: Some(0x00),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(*EMPTY_KECCAK_HASH),
            ..Default::default()
        };
        assert!(validate_block_header(&block, &parent_block, ELASTICITY_MULTIPLIER).is_ok());
        assert_eq!(parent_block.encode_to_vec().len(), parent_block.length());
        assert_eq!(block.encode_to_vec().len(), block.length());
    }

    #[test]
    fn test_compute_transactions_root() {
        let encoded_transactions = [
            "0x01f8d68330182404842daf517a830186a08080b880c1597f3c842558e64df52c3e0f0973067577c030c0c6578dbb2eef63155a21106fd4426057527f296b2ecdfabc81e34ffc82e89dec20f6b7c41fa1969d3c3bc44262c86f08b5b76077527fb7ece918787c50c878052c30a8b1d4abc07331e6d14b8ded52bbc58a6e9992b76097527f0110937c38cc13b914f201fc09dc6f7a80c001a09930cb92b4a27dce971c697a8c47fa34c98d076abc7b36e1239d6abcfc7c8403a041b35118447fe77c38c0b3a92a2dd3ecba4a9e4b35cc6534cd787f56c0cf2e21",
            "0xf86e81fa843127403882f61894db8d964741c53e55df9c2d4e9414c6c96482874e870aa87bee538000808360306ca03aa421df67a101c45ff9cb06ce28f518a5d8d8dbb76a79361280071909650a27a05a447ff053c4ae601cfe81859b58d5603f2d0a73481c50f348089032feb0b073",
            "0x02f8ef83301824048413f157f8842daf517a830186a094000000000000000000000000000000000000000080b8807a0a600060a0553db8600060c855c77fb29ecd7661d8aefe101a0db652a728af0fded622ff55d019b545d03a7532932a60ad52604260cd5360bf60ce53609460cf53603e60d05360f560d153bc596000609e55600060c6556000601f556000609155535660556057536055605853606e60595360e7605a5360d0605b5360eb60c080a03acb03b1fc20507bc66210f7e18ff5af65038fb22c626ae488ad9513d9b6debca05d38459e9d2a221eb345b0c2761b719b313d062ff1ea3d10cf5b8762c44385a6",
            "0x01f8ea8330182402842daf517a830186a094000000000000000000000000000000000000000080b880bdb30d976000604e557145600060a155d67fe7e473caf6e33cba341136268fc1189ba07837ef8a266570289ff53afc43436260c7527f333dfe837f4838f6053e5e46e4151aeec28f356ec39a2db9769f36ec92e3e3f660e7527f0b261608674300d4621eff679096a6ed786591aca69f2b22a3ea6949621daade610107527f3cc080a01f3f906540fb56b0576c51b3ffa86df213fd1f407378c9441cfdd9d5f3c1df3da035691b16c053b68ec74683ae020293cbc6a47ac773dc8defb96cb680c576e5a3",
        ];
        let transactions: Vec<Transaction> = encoded_transactions
            .iter()
            .map(|hex| {
                Transaction::decode_canonical(&hex::decode(hex.trim_start_matches("0x")).unwrap())
                    .unwrap()
            })
            .collect();
        let transactions_root =
            compute_transactions_root(&transactions, &ethrex_crypto::NativeCrypto);
        let expected_root = H256::from_slice(
            &hex::decode("adf0387d2303fe80aeca23bf6828c979b44d8a8fe4a1ba1d3511bc1567ca80de")
                .unwrap(),
        );
        assert_eq!(transactions_root, expected_root);
    }

    #[test]
    // The values for this test were taken from sepolia testnet block number 6029872
    // Where a silent overflow within base fee calculations led to the wrong expected base fee
    fn test_calculate_base_fee_per_gas_big_numbers() {
        let expected_base_fee = Some(1317727380375);
        let block_gas_limit = 30000000;
        let parent_gas_limit = 30000000;
        let parent_gas_used = 1981764;
        let parent_base_fee_per_gas = 1478077008012;
        let calc_base_fee = calculate_base_fee_per_gas(
            block_gas_limit,
            parent_gas_limit,
            parent_gas_used,
            parent_base_fee_per_gas,
            ELASTICITY_MULTIPLIER,
        );
        assert_eq!(calc_base_fee, expected_base_fee)
    }

    #[test]
    fn test_calc_blob_fee_post_osaka_bpo1() {
        let parent = BlockHeader {
            excess_blob_gas: Some(5149252),
            blob_gas_used: Some(1310720),
            base_fee_per_gas: Some(30),
            ..Default::default()
        };
        let schedule = ForkBlobSchedule {
            target: 9,
            max: 14,
            base_fee_update_fraction: 8832827,
        };
        let fork = Fork::Osaka;

        let res = calc_excess_blob_gas(&parent, schedule, fork);
        assert_eq!(res, 5617366)
    }

    #[test]
    fn test_calc_blob_fee_post_osaka_bpo3() {
        let parent = BlockHeader {
            excess_blob_gas: Some(19251039),
            blob_gas_used: Some(2490368),
            base_fee_per_gas: Some(50),
            ..Default::default()
        };
        let schedule = ForkBlobSchedule {
            target: 21,
            max: 32,
            base_fee_update_fraction: 20609697,
        };
        let fork = Fork::Osaka;
        let res = calc_excess_blob_gas(&parent, schedule, fork);
        assert_eq!(res, 20107103)
    }

    #[test]
    fn test_calc_blob_fee_post_osaka_bpo1_ef() {
        let parent = BlockHeader {
            excess_blob_gas: Some(0x360000),
            blob_gas_used: Some(0),
            base_fee_per_gas: Some(0x11),
            ..Default::default()
        };
        let schedule = ForkBlobSchedule {
            target: 9,
            max: 14,
            base_fee_update_fraction: 0x86c73b,
        };
        let fork = Fork::Osaka;

        let res = calc_excess_blob_gas(&parent, schedule, fork);
        assert_eq!(res, 3538944)
    }

    #[test]
    fn test_calc_excess_blob_gas_at_amsterdam_inherits_bpo1_target() {
        // Amsterdam carries no blob params of its own, so a chain that scheduled BPO1
        // and never scheduled BPO2 keeps BPO1's target of 10 and max of 15 across the
        // Amsterdam boundary. A parent that spent 12 blobs is above that target, so the
        // EIP-7918 reserve-price branch raises the excess by `used * (max - target) / max`.
        // Resolving the schedule from an unscheduled BPO2 (target 14) instead would put
        // the parent below target and wrongly return 0.
        let parent = BlockHeader {
            excess_blob_gas: Some(0),
            blob_gas_used: Some(12 * GAS_PER_BLOB as u64),
            base_fee_per_gas: Some(INITIAL_BASE_FEE),
            ..Default::default()
        };
        let config = ChainConfig {
            osaka_time: Some(0),
            bpo1_time: Some(0),
            amsterdam_time: Some(100),
            ..Default::default()
        };

        let schedule = config
            .get_fork_blob_schedule(100)
            .expect("Amsterdam must resolve a blob schedule");
        assert_eq!(schedule.target, 10);
        assert_eq!(schedule.max, 15);

        let res = calc_excess_blob_gas(&parent, schedule, config.fork(100));
        assert_eq!(res, 4 * GAS_PER_BLOB as u64);
    }

    #[test]
    fn test_fake_exponential_overflow() {
        // With u64 this overflows
        assert!(fake_exponential(57532635.into(), 3145728.into(), 3338477).is_ok());
    }

    #[test]
    fn test_fake_exponential_bounds_overflow() {
        // Making sure the limit we state in the documentation of 400_000_000 works
        let thing = fake_exponential(
            MIN_BASE_FEE_PER_BLOB_GAS.into(),
            400_000_000.into(),
            BLOB_BASE_FEE_UPDATE_FRACTION,
        );
        // With u64 this overflows
        assert!(thing.is_ok());
    }

    #[test]
    fn burned_fees_header_roundtrip_and_hash() {
        // For a correct round-trip, all preceding optional fields must be Some so the
        // positional/trailing RLP decoder can attribute burned_fees correctly.
        // This mirrors a real LStar-era block header.
        let h = BlockHeader {
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(H256::zero()),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(H256::zero()),
            block_access_list_hash: Some(H256::zero()),
            slot_number: Some(1),
            burned_fees: Some(12345),
            ..Default::default()
        };
        let encoded = h.encode_to_vec();
        let decoded = BlockHeader::decode(&encoded).expect("decode");
        assert_eq!(decoded.burned_fees, Some(12345));
        // None round-trips as None (pre-LStar).
        let h_none = BlockHeader {
            burned_fees: None,
            ..Default::default()
        };
        assert_eq!(
            BlockHeader::decode(&h_none.encode_to_vec())
                .unwrap()
                .burned_fees,
            None
        );
        // burned_fees participates in the block hash: same base state, only burned_fees differs.
        let h_with = BlockHeader {
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(H256::zero()),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(H256::zero()),
            block_access_list_hash: Some(H256::zero()),
            slot_number: Some(1),
            burned_fees: Some(12345),
            ..Default::default()
        };
        let h_without = BlockHeader {
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(H256::zero()),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(H256::zero()),
            block_access_list_hash: Some(H256::zero()),
            slot_number: Some(1),
            burned_fees: None,
            ..Default::default()
        };
        assert_ne!(h_with.hash(), h_without.hash());
    }

    /// Verify that `into_with_burned_fees` clears the OnceCell so the resulting
    /// hash reflects the injected value and not any previously cached hash.
    ///
    /// This is the TDD anchor for the Task-4 verify-flow reorder: after
    /// `execute_blocks` caches the block hash (burned_fees=None), we must be
    /// able to inject the recomputed `burned_fees` and still get the correct hash.
    #[test]
    fn into_with_burned_fees_clears_stale_cache() {
        use crate::NativeCrypto;

        // Build a default header (burned_fees = None).
        let header_none = BlockHeader::default();

        // Force the hash cache to populate with burned_fees=None value.
        let hash_stale = header_none.hash();

        // Build a reference header with burned_fees=Some(42) from scratch (fresh OnceCell).
        let header_some_fresh = BlockHeader {
            burned_fees: Some(42),
            ..BlockHeader::default()
        };
        let hash_expected = header_some_fresh.compute_block_hash(&NativeCrypto);

        // The two hashes must differ — burned_fees is RLP-encoded in the header.
        assert_ne!(
            hash_stale, hash_expected,
            "burned_fees=None and burned_fees=Some(42) must produce different block hashes"
        );

        // Now inject Some(42) via into_with_burned_fees, starting from the stale-cached header.
        let fresh_header = header_none.into_with_burned_fees(Some(42));
        let hash_fresh = fresh_header.hash();

        // Must match the reference hash, NOT the stale one.
        assert_eq!(
            hash_fresh, hash_expected,
            "into_with_burned_fees must yield a hash identical to building a fresh header with the same burned_fees"
        );
        assert_ne!(
            hash_fresh, hash_stale,
            "OnceCell must have been cleared: fresh hash must differ from the stale cached hash"
        );
    }

    /// Verify the Amsterdam (pre-LStar) no-op: injecting None into a header
    /// whose hash was cached with burned_fees=None yields the same hash.
    ///
    /// This is the primary correctness requirement for Task 4: the reordered
    /// verify-flow must not regress the current Amsterdam path.
    #[test]
    fn into_with_burned_fees_none_is_idempotent() {
        let header = BlockHeader::default();
        let hash_before = header.hash(); // populate cache with burned_fees=None

        // Inject None (Amsterdam: burned_fees is None both before and after execution).
        let header_after = header.into_with_burned_fees(None);
        let hash_after = header_after.hash();

        assert_eq!(
            hash_before, hash_after,
            "injecting None must not change the block hash (Amsterdam no-op)"
        );
    }

    #[test]
    fn test_validate_block_body_rejects_missing_withdrawals_field() {
        use crate::constants::EMPTY_WITHDRAWALS_HASH;

        let crypto = NativeCrypto;
        let header = BlockHeader {
            transactions_root: compute_transactions_root(&[], &crypto),
            withdrawals_root: Some(*EMPTY_WITHDRAWALS_HASH),
            ..Default::default()
        };

        // A post-Shanghai body that OMITS the withdrawals field is malformed and
        // must be rejected even when the header commits to the empty-withdrawals
        // root (geth: "missing withdrawals in block body"; reth, nethermind,
        // erigon and besu reject this shape as well).
        let body_missing = BlockBody {
            withdrawals: None,
            ..BlockBody::empty()
        };
        assert!(matches!(
            validate_block_body(&header, &body_missing, &crypto),
            Err(InvalidBlockBodyError::WithdrawalsRootNotMatch)
        ));

        // An explicit empty withdrawals list is valid for the same header.
        assert!(validate_block_body(&header, &BlockBody::empty(), &crypto).is_ok());

        // A withdrawals field without a header root (pre-Shanghai shape) is rejected.
        let pre_shanghai_header = BlockHeader {
            transactions_root: compute_transactions_root(&[], &crypto),
            ..Default::default()
        };
        assert!(matches!(
            validate_block_body(&pre_shanghai_header, &BlockBody::empty(), &crypto),
            Err(InvalidBlockBodyError::WithdrawalsRootNotMatch)
        ));
        // Neither field present is valid.
        let body_no_withdrawals = BlockBody {
            withdrawals: None,
            ..BlockBody::empty()
        };
        assert!(validate_block_body(&pre_shanghai_header, &body_no_withdrawals, &crypto).is_ok());
    }

    #[test]
    fn test_normalize_legacy_withdrawals() {
        use crate::constants::EMPTY_WITHDRAWALS_HASH;

        let crypto = NativeCrypto;

        // Legacy shape from trusted history: omitted field + empty-withdrawals
        // header root normalizes to the canonical Some(vec![]), and the
        // normalized body passes validation.
        let header = BlockHeader {
            transactions_root: compute_transactions_root(&[], &crypto),
            withdrawals_root: Some(*EMPTY_WITHDRAWALS_HASH),
            ..Default::default()
        };
        let mut body = BlockBody {
            withdrawals: None,
            ..BlockBody::empty()
        };
        normalize_legacy_withdrawals(&header, &mut body);
        assert_eq!(body.withdrawals, Some(Vec::new()));
        assert!(validate_block_body(&header, &body, &crypto).is_ok());

        // An omitted field under a NON-empty withdrawals root is not the legacy
        // shape: the body stays untouched and validation still rejects it.
        let bad_header = BlockHeader {
            transactions_root: compute_transactions_root(&[], &crypto),
            withdrawals_root: Some(H256::repeat_byte(0xAB)),
            ..Default::default()
        };
        let mut bad_body = BlockBody {
            withdrawals: None,
            ..BlockBody::empty()
        };
        normalize_legacy_withdrawals(&bad_header, &mut bad_body);
        assert_eq!(bad_body.withdrawals, None);
        assert!(validate_block_body(&bad_header, &bad_body, &crypto).is_err());

        // Pre-Shanghai shape (no header root, no field) stays untouched.
        let pre_shanghai_header = BlockHeader {
            transactions_root: compute_transactions_root(&[], &crypto),
            ..Default::default()
        };
        let mut pre_shanghai_body = BlockBody {
            withdrawals: None,
            ..BlockBody::empty()
        };
        normalize_legacy_withdrawals(&pre_shanghai_header, &mut pre_shanghai_body);
        assert_eq!(pre_shanghai_body.withdrawals, None);

        // An already-canonical body is left as-is.
        let mut canonical = BlockBody::empty();
        let before = canonical.withdrawals.clone();
        normalize_legacy_withdrawals(&header, &mut canonical);
        assert_eq!(canonical.withdrawals, before);
    }
}
