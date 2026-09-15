use ethrex_common::{Address, H160, H256, U256};
use std::sync::LazyLock;

pub const WORD_SIZE_IN_BYTES_USIZE: usize = 32;
pub const WORD_SIZE_IN_BYTES_U64: u64 = 32;

pub const SUCCESS: U256 = U256::one();
pub const FAIL: U256 = U256::zero();
pub const WORD_SIZE: usize = 32;

pub const STACK_LIMIT: usize = 1024;

pub const EMPTY_CODE_HASH: H256 = H256([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

pub const MEMORY_EXPANSION_QUOTIENT: u64 = 512;

// Dedicated gas limit for system calls according to EIPs 2935, 4788, 7002 and 7251
pub const SYS_CALL_GAS_LIMIT: u64 = 30000000;

// EIP-8037: system transactions
// receive an extra state-gas reservoir of
// `STATE_BYTES_PER_STORAGE_SET * cost_per_state_byte * SYSTEM_MAX_SSTORES_PER_CALL`
// on top of `SYS_CALL_GAS_LIMIT`, so SSTORE-heavy system contracts (EIP-2935,
// EIP-4788) cannot OOG on state-gas growth alone.
pub const SYSTEM_MAX_SSTORES_PER_CALL: u64 = 16;

// Transaction costs in gas
pub const TX_BASE_COST: u64 = 21000;
// EIP-2780 (merged EIPs#11645) — ECDSA recovery + sender account access + write.
// At Amsterdam the flat 21000 base is decomposed into resource-based charges;
// this is the sender-side base (recovery + sender access + write).
pub const TX_BASE_COST_AMSTERDAM: u64 = 12000;

// https://eips.ethereum.org/EIPS/eip-7825
pub use ethrex_common::constants::POST_OSAKA_GAS_LIMIT_CAP;
pub use ethrex_common::constants::TX_MAX_GAS_LIMIT_AMSTERDAM;

pub const MAX_CODE_SIZE: u64 = 0x6000;
pub const INIT_CODE_MAX_SIZE: usize = 49152;
// EIP-7954 (Amsterdam): increase code size to 64 KiB and initcode to 128 KiB
pub const AMSTERDAM_MAX_CODE_SIZE: u64 = 0x10000;
#[allow(clippy::as_conversions)]
pub const AMSTERDAM_INIT_CODE_MAX_SIZE: usize = 2 * AMSTERDAM_MAX_CODE_SIZE as usize;

// https://eips.ethereum.org/EIPS/eip-3541
pub const EOF_PREFIX: u8 = 0xef;

pub mod create_opcode {
    use ethrex_common::U256;

    pub const INIT_CODE_WORD_COST: U256 = U256([2, 0, 0, 0]);
    pub const CODE_DEPOSIT_COST: U256 = U256([200, 0, 0, 0]);
    pub const CREATE_BASE_COST: U256 = U256([32000, 0, 0, 0]);
}

pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

// Blob constants
pub const TARGET_BLOB_GAS_PER_BLOCK: u32 = 393216; // TARGET_BLOB_NUMBER_PER_BLOCK * GAS_PER_BLOB
pub const TARGET_BLOB_GAS_PER_BLOCK_PECTRA: u32 = 786432; // TARGET_BLOB_NUMBER_PER_BLOCK * GAS_PER_BLOB

pub const MIN_BASE_FEE_PER_BLOB_GAS: u64 = 1;

// WARNING: Do _not_ use the BLOB_BASE_FEE_UPDATE_FRACTION_* family of
// constants as is. Use the `get_blob_base_fee_update_fraction_value`
// function instead
pub const BLOB_BASE_FEE_UPDATE_FRACTION: u64 = 3338477;
pub const BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE: u64 = 5007716; // Defined in [EIP-7691](https://eips.ethereum.org/EIPS/eip-7691)

// WARNING: Do _not_ use the MAX_BLOB_COUNT_* family of constants as
// is. Use the `max_blobs_per_block` function instead
pub const MAX_BLOB_COUNT: u32 = 6;
pub const MAX_BLOB_COUNT_ELECTRA: u32 = 9;
// Max blob count per tx (introduced by Osaka fork)
pub const MAX_BLOB_COUNT_TX: usize = 6;

pub const VALID_BLOB_PREFIXES: [u8; 1] = [VERSIONED_HASH_VERSION_KZG];

// Block constants
pub const LAST_AVAILABLE_BLOCK_LIMIT: u64 = 256;

// EIP7702 - EOA Load Code
// secp256k1 curve order: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub static SECP256K1_ORDER: LazyLock<U256> = LazyLock::new(|| {
    U256::from_big_endian(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ])
});
pub static SECP256K1_ORDER_OVER2: std::sync::LazyLock<U256> =
    LazyLock::new(|| *SECP256K1_ORDER / U256::from(2));
pub const MAGIC: u8 = 0x05;
pub const SET_CODE_DELEGATION_BYTES: [u8; 3] = [0xef, 0x01, 0x00];
// Set the code of authority to be 0xef0100 || address. This is a delegation designation.
// len(SET_CODE_DELEGATION_BYTES) == 3 + len(Address) == 20 -> 23
pub const EIP7702_DELEGATED_CODE_LEN: usize = 23;
pub const PER_AUTH_BASE_COST: u64 = 7500;
pub const PER_EMPTY_ACCOUNT_COST: u64 = 25000;
// EIP-7702: refund per existing authority (pre-Amsterdam)
pub const REFUND_AUTH_PER_EXISTING_ACCOUNT: u64 = 12500;

/// EIP-7708: keccak256('Transfer(address,address,uint256)')
pub const TRANSFER_EVENT_TOPIC: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

/// EIP-7708: keccak256('Burn(address,uint256)')
pub const BURN_EVENT_TOPIC: H256 = H256([
    0xcc, 0x16, 0xf5, 0xdb, 0xb4, 0x87, 0x32, 0x80, 0x81, 0x5c, 0x1e, 0xe0, 0x9d, 0xbd, 0x06, 0x73,
    0x6c, 0xff, 0xcc, 0x18, 0x44, 0x12, 0xcf, 0x7a, 0x71, 0xa0, 0xfd, 0xb7, 0x5d, 0x39, 0x7c, 0xa5,
]);

/// `eth_simulateV1` traceTransfers: sentinel emitter address for informational
/// ETH-transfer logs (execution-apis spec), 0xeeee...eeee.
pub const TRACE_TRANSFER_ADDRESS: Address = H160([0xee; 20]);
