use ethrex_common::{
    Address, H256, U256,
    types::{BlockHeader, ChainConfig, Fork, ForkBlobSchedule},
};

use crate::constants::{
    BLOB_BASE_FEE_UPDATE_FRACTION, BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE, MAX_BLOB_COUNT,
    MAX_BLOB_COUNT_ELECTRA, TARGET_BLOB_GAS_PER_BLOCK, TARGET_BLOB_GAS_PER_BLOCK_PECTRA,
};

use rustc_hash::FxHashMap;
/// [EIP-1153]: https://eips.ethereum.org/EIPS/eip-1153#reference-implementation
pub type TransientStorage = FxHashMap<(Address, U256), U256>;

#[derive(Debug, Default, Clone)]
/// Environmental information that the execution agent must provide.
pub struct Environment {
    /// The sender address of the external transaction.
    pub origin: Address,
    /// Gas limit of the Transaction
    pub gas_limit: u64,
    pub config: EVMConfig,
    pub block_number: u64,
    /// Coinbase is the block's beneficiary - the address that receives the block rewards and fees.
    pub coinbase: Address,
    pub timestamp: u64,
    pub prev_randao: Option<H256>,
    pub difficulty: U256,
    pub slot_number: U256,
    pub chain_id: U256,
    pub base_fee_per_gas: U256,
    pub base_blob_fee_per_gas: U256,
    pub gas_price: U256, // Effective gas price
    pub block_excess_blob_gas: Option<u64>,
    pub block_blob_gas_used: Option<u64>,
    pub tx_blob_hashes: Vec<H256>,
    pub tx_max_priority_fee_per_gas: Option<U256>,
    pub tx_max_fee_per_gas: Option<U256>,
    pub tx_max_fee_per_blob_gas: Option<U256>,
    pub tx_nonce: u64,
    pub block_gas_limit: u64,
    pub is_privileged: bool,
    pub fee_token: Option<Address>,
    /// When true, skip balance deduction in `deduct_caller`. Used by the prewarmer
    /// to avoid early reverts on insufficient balance so that warming touches more storage.
    pub disable_balance_check: bool,
    /// When true, skip the sender nonce-mismatch validation. Used by the simulation
    /// RPCs (eth_call, eth_estimateGas, eth_createAccessList): call objects may omit
    /// the nonce, and no client enforces it there. The account nonce still increments
    /// during execution. `debug_traceCall` relies on it too (geth's
    /// `ToMessage(_, skipNonceCheck=true)`): the synthetic call may run on top of a
    /// mid-block state (`txIndex`) whose nonce differs from the value the caller
    /// supplied, so enforcing the check would spuriously reject the trace.
    /// `eth_simulateV1` sets it when `validation: false`, the mode in which the
    /// method behaves like `eth_call`.
    pub disable_nonce_check: bool,
    /// When true, emit informational ETH-transfer logs from the
    /// `TRACE_TRANSFER_ADDRESS` sentinel (`eth_simulateV1` traceTransfers).
    /// On Amsterdam+ forks the consensus EIP-7708 logs take precedence.
    pub trace_eth_transfers: bool,
    /// When true, skip the gas limits that gate a transaction's *admission* rather than
    /// its execution: the block-level gas allowance and the EIP-7825 per-transaction cap.
    /// Used by every simulation RPC (eth_call, eth_estimateGas, eth_createAccessList,
    /// debug_traceCall), whose callers routinely pass a `gas` above either bound — tools
    /// commonly pass the block gas limit — and still expect an answer, since nothing is
    /// being submitted.
    /// This exists so `block_gas_limit` can keep the block's real value: that field is
    /// observable through the GASLIMIT opcode and feeds the EIP-8037 cost-per-state-byte
    /// formula, so raising it to bypass the allowance corrupts both.
    pub disable_gas_allowance_check: bool,
    /// When true, skip the EIP-3607 validation that rejects a sender carrying code.
    /// Used by every simulation RPC (eth_call, eth_estimateGas, eth_createAccessList,
    /// debug_traceCall). EIP-3607 exists because a contract has no private key, so no
    /// valid signature should exist for its address; a simulated call carries no
    /// signature at all and its `from` is just an assertion by the caller, so the rule
    /// has nothing to protect there. Enforcing it breaks the common practice of
    /// simulating a call whose sender is a contract, such as a smart contract wallet
    /// previewing its own transaction. Transaction admission keeps enforcing it: the
    /// mempool rejects such a sender outright, and block execution never sets this flag.
    pub disable_sender_eoa_check: bool,
    /// When true, the tx is a pre-execution system contract call (EIP-2935, EIP-4788,
    /// EIP-7002, EIP-7251 etc.). Skips the block-level gas-allowance check since system
    /// calls are allowed to exceed `block_gas_limit` (their 30M cap is a separate rule).
    pub is_system_call: bool,
}

/// This struct holds special configuration variables specific to the
/// EVM. In most cases, at least at the time of writing (February
/// 2025), you want to use the default blob_schedule values for the
/// specified Fork. The "intended" way to do this is by using the `EVMConfig::canonical_values(fork: Fork)` function.
///
/// However, that function should NOT be used IF you want to use a
/// custom `ForkBlobSchedule`, like it's described in [EIP-7840](https://eips.ethereum.org/EIPS/eip-7840)
/// Values are determined by [EIP-7691](https://eips.ethereum.org/EIPS/eip-7691#specification)
#[derive(Debug, Clone, Copy)]
pub struct EVMConfig {
    pub fork: Fork,
    pub blob_schedule: ForkBlobSchedule,
}

impl EVMConfig {
    pub fn new(fork: Fork, blob_schedule: ForkBlobSchedule) -> EVMConfig {
        EVMConfig {
            fork,
            blob_schedule,
        }
    }

    pub fn new_from_chain_config(chain_config: &ChainConfig, block_header: &BlockHeader) -> Self {
        let fork = chain_config.fork(block_header.timestamp);

        let blob_schedule = chain_config
            .get_fork_blob_schedule(block_header.timestamp)
            .unwrap_or_else(|| EVMConfig::canonical_values(fork));

        EVMConfig::new(fork, blob_schedule)
    }

    /// This function is used for running the EF tests. If you don't
    /// have acces to a EVMConfig (mainly in the form of a
    /// genesis.json file) you can use this function to get the
    /// "Default" ForkBlobSchedule for that specific Fork.
    /// NOTE: This function could potentially be expanded to include
    /// other types of "default"s.
    pub fn canonical_values(fork: Fork) -> ForkBlobSchedule {
        let max_blobs_per_block = Self::max_blobs_per_block(fork);
        let target = Self::get_target_blob_gas_per_block_(fork);
        let base_fee_update_fraction: u64 = Self::get_blob_base_fee_update_fraction_value(fork);

        ForkBlobSchedule {
            target,
            max: max_blobs_per_block,
            base_fee_update_fraction,
        }
    }

    fn max_blobs_per_block(fork: Fork) -> u32 {
        if fork >= Fork::Prague {
            MAX_BLOB_COUNT_ELECTRA
        } else {
            MAX_BLOB_COUNT
        }
    }

    fn get_blob_base_fee_update_fraction_value(fork: Fork) -> u64 {
        if fork >= Fork::Prague {
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
        } else {
            BLOB_BASE_FEE_UPDATE_FRACTION
        }
    }

    fn get_target_blob_gas_per_block_(fork: Fork) -> u32 {
        if fork >= Fork::Prague {
            TARGET_BLOB_GAS_PER_BLOCK_PECTRA
        } else {
            TARGET_BLOB_GAS_PER_BLOCK
        }
    }
}

impl Default for EVMConfig {
    /// The default EVMConfig depends on the default Fork.
    fn default() -> Self {
        let fork = core::default::Default::default();
        EVMConfig {
            fork,
            blob_schedule: Self::canonical_values(fork),
        }
    }
}
