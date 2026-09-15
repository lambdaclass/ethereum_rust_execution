//! Tests for L2 gas reservation: reserving L1 DA fee gas upfront in prepare_execution.
//!
//! The reservation approach consumes l1_gas from gas_remaining during prepare_execution,
//! so execution physically cannot use the L1 fee portion. This guarantees the L1 fee vault
//! always receives the full l1_gas payment, eliminating the griefing vector where a user
//! sends a transaction with gas_limit = intrinsic_gas.

use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    constants::GAS_PER_BLOB,
    types::{
        Account, AccountState, ChainConfig, Code, CodeMetadata, EIP1559Transaction, Fork,
        SAFE_BYTES_PER_BLOB, Transaction, TxKind,
        fee_config::{FeeConfig, L1FeeConfig},
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    db::{Database, gen_db::GeneralizedDatabase},
    environment::{EVMConfig, Environment},
    errors::{DatabaseError, TxValidationError, VMError},
    tracing::LevmCallTracer,
    vm::{VM, VMType},
};
use ethrex_rlp::encode::RLPEncode;
use rustc_hash::FxHashMap;
use std::sync::Arc;

// ==================== Test Database ====================

struct TestDatabase;

impl Database for TestDatabase {
    fn get_account_state(&self, _address: Address) -> Result<AccountState, DatabaseError> {
        Ok(AccountState::default())
    }

    fn get_storage_value(&self, _address: Address, _key: H256) -> Result<U256, DatabaseError> {
        Ok(U256::zero())
    }

    fn get_block_hash(&self, _block_number: u64) -> Result<H256, DatabaseError> {
        Ok(H256::zero())
    }

    fn get_chain_config(&self) -> Result<ChainConfig, DatabaseError> {
        Ok(ChainConfig::default())
    }

    fn get_account_code(&self, _code_hash: H256) -> Result<Code, DatabaseError> {
        Ok(Code::default())
    }

    fn get_code_metadata(&self, _code_hash: H256) -> Result<CodeMetadata, DatabaseError> {
        Ok(CodeMetadata { length: 0 })
    }
}

// ==================== Constants ====================

const GAS_PRICE: u64 = 1000;
const L1_FEE_PER_BLOB_GAS: u64 = 10_000;
const SENDER: u64 = 0x1000;
const RECIPIENT: u64 = 0x2000;
const L1_FEE_VAULT: u64 = 0xAA00;
const CONTRACT: u64 = 0x3000;
const SENDER_BALANCE: u64 = 10_000_000_000;

// ==================== Helpers ====================

fn sender_addr() -> Address {
    Address::from_low_u64_be(SENDER)
}

fn recipient_addr() -> Address {
    Address::from_low_u64_be(RECIPIENT)
}

fn contract_addr() -> Address {
    Address::from_low_u64_be(CONTRACT)
}

fn l1_fee_vault_addr() -> Address {
    Address::from_low_u64_be(L1_FEE_VAULT)
}

fn fee_config() -> FeeConfig {
    FeeConfig {
        base_fee_vault: None,
        operator_fee_config: None,
        l1_fee_config: Some(L1FeeConfig {
            l1_fee_vault: l1_fee_vault_addr(),
            l1_fee_per_blob_gas: L1_FEE_PER_BLOB_GAS,
        }),
    }
}

fn make_tx(gas_limit: u64) -> Transaction {
    make_tx_to(gas_limit, recipient_addr())
}

fn make_tx_to(gas_limit: u64, to: Address) -> Transaction {
    make_tx_with_calldata(gas_limit, to, Bytes::new())
}

fn make_tx_with_calldata(gas_limit: u64, to: Address, data: Bytes) -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: GAS_PRICE,
        gas_limit,
        to: TxKind::Call(to),
        value: U256::zero(),
        data,
        ..Default::default()
    })
}

/// Computes l1_gas for a given transaction using the same formula as calculate_l1_fee_gas.
fn compute_l1_gas(tx: &Transaction) -> u64 {
    let tx_size = tx.length();
    let l1_fee_per_blob: u64 = L1_FEE_PER_BLOB_GAS * u64::from(GAS_PER_BLOB);
    let l1_fee_per_blob_byte = l1_fee_per_blob / SAFE_BYTES_PER_BLOB as u64;
    let l1_fee = l1_fee_per_blob_byte * tx_size as u64;
    let l1_gas = l1_fee / GAS_PRICE;
    if l1_gas == 0 && l1_fee > 0 { 1 } else { l1_gas }
}

fn make_env(gas_limit: u64) -> Environment {
    let fork = Fork::Prague;
    let blob_schedule = EVMConfig::canonical_values(fork);
    Environment {
        origin: sender_addr(),
        gas_limit,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase: Address::from_low_u64_be(0xCCC),
        timestamp: 1000,
        prev_randao: Some(H256::zero()),
        difficulty: U256::zero(),
        slot_number: U256::zero(),
        chain_id: U256::from(1),
        base_fee_per_gas: U256::from(GAS_PRICE),
        base_blob_fee_per_gas: U256::from(1),
        gas_price: U256::from(GAS_PRICE),
        block_excess_blob_gas: None,
        block_blob_gas_used: None,
        tx_blob_hashes: vec![],
        tx_max_priority_fee_per_gas: Some(U256::zero()),
        tx_max_fee_per_gas: Some(U256::from(GAS_PRICE)),
        tx_max_fee_per_blob_gas: None,
        tx_nonce: 0,
        block_gas_limit: gas_limit * 2,
        is_privileged: false,
        fee_token: None,
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    }
}

fn make_db(sender_balance: U256) -> GeneralizedDatabase {
    make_db_with_accounts(sender_balance, vec![])
}

fn make_db_with_accounts(
    sender_balance: U256,
    extra_accounts: Vec<(Address, Account)>,
) -> GeneralizedDatabase {
    let mut accounts: FxHashMap<Address, Account> = [(
        sender_addr(),
        Account::new(sender_balance, Code::default(), 0, FxHashMap::default()),
    )]
    .into_iter()
    .collect();

    for (addr, acc) in extra_accounts {
        accounts.insert(addr, acc);
    }

    GeneralizedDatabase::new_with_account_state(Arc::new(TestDatabase), accounts)
}

// ==================== Tests ====================

/// A transaction with gas_limit = intrinsic_gas (21000) should be rejected upfront
/// when L1 fee config is set, because there's no room for l1_gas after intrinsic gas.
///
/// The variant must be `L1GasReservationTooLow`, not `IntrinsicGasTooLow`: the
/// shortfall is against the reserved `l1_gas`, which tracks L1 fees and the block's
/// gas price, so the same tx can succeed in a later block. The payload builders
/// evict on `IntrinsicGasTooLow`, so conflating the two would drop recoverable txs
/// from the mempool.
#[test]
fn test_insufficient_gas_for_l1_fee_rejected() {
    let gas_limit = 21_000;
    let tx = make_tx(gas_limit);

    // Sanity: l1_gas should be > 0 with our fee config
    let l1_gas = compute_l1_gas(&tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    let env = make_env(gas_limit);
    let mut db = make_db(U256::from(SENDER_BALANCE));

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let result = vm.execute();
    assert!(
        matches!(
            result,
            Err(VMError::TxValidation(
                TxValidationError::L1GasReservationTooLow
            ))
        ),
        "Expected L1GasReservationTooLow, got {result:?}"
    );
}

/// A transaction with gas_limit exactly covering intrinsic_gas + l1_gas should succeed.
/// The execution gas budget is 0, but for a simple EOA transfer that's fine.
#[test]
fn test_gas_limit_exactly_covers_intrinsic_plus_l1() {
    // Build the tx once, compute l1_gas, then rebuild with the exact gas_limit.
    // One iteration is enough since a small gas_limit change barely affects RLP size.
    let tx = make_tx(22_000);
    let l1_gas = compute_l1_gas(&tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    let gas_limit = 21_000 + l1_gas;
    let tx = make_tx(gas_limit);
    assert_eq!(compute_l1_gas(&tx), l1_gas, "l1_gas should be stable");

    let env = make_env(gas_limit);
    let mut db = make_db(U256::from(SENDER_BALANCE));

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let report = vm.execute().expect("Execution should succeed");
    assert!(
        report.is_success(),
        "Transaction should succeed when gas_limit covers intrinsic + l1_gas"
    );
}

/// With L1 fee disabled, gas_limit = 21000 (intrinsic gas) is enough for a simple transfer.
#[test]
fn test_no_l1_fee_config_21000_is_enough() {
    let gas_limit = 21_000;
    let tx = make_tx(gas_limit);

    let no_l1_fee_config = FeeConfig {
        base_fee_vault: None,
        operator_fee_config: None,
        l1_fee_config: None,
    };

    let env = make_env(gas_limit);
    let mut db = make_db(U256::from(SENDER_BALANCE));

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(no_l1_fee_config),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let report = vm.execute().expect("Execution should succeed");
    assert!(
        report.is_success(),
        "Transaction with gas_limit=21000 should succeed when L1 fee is disabled"
    );
}

/// A transaction with ample gas_limit should succeed and the L1 fee vault should
/// receive the correct payment.
#[test]
fn test_l1_fee_vault_receives_full_payment() {
    let gas_limit = 100_000;
    let tx = make_tx(gas_limit);
    let l1_gas = compute_l1_gas(&tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    let env = make_env(gas_limit);
    let mut db = make_db(U256::from(SENDER_BALANCE));

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let report = vm.execute().expect("Execution should succeed");
    assert!(report.is_success(), "Transaction should succeed");

    // Verify L1 fee vault received the correct payment: l1_gas * gas_price
    let l1_vault_balance = vm.db.get_account(l1_fee_vault_addr()).unwrap().info.balance;
    let expected_l1_fee = U256::from(l1_gas) * U256::from(GAS_PRICE);
    assert_eq!(
        l1_vault_balance, expected_l1_fee,
        "L1 fee vault should receive exactly l1_gas * gas_price"
    );
}

/// A transaction calling a contract that consumes execution gas should succeed
/// and correctly separate execution gas from reserved l1_gas in finalize.
/// The L1 fee vault must still receive the full l1_gas payment.
#[test]
fn test_contract_execution_with_l1_gas_reservation() {
    // Contract bytecode: runs a loop burning ~5000 gas, then STOPs.
    // PUSH1 20 (loop count)  -- 60 14
    // JUMPDEST              -- 5b        (offset 2)
    // PUSH1 1               -- 60 01
    // SWAP1                 -- 90
    // SUB                   -- 03
    // DUP1                  -- 80
    // PUSH1 2               -- 60 02
    // JUMPI                 -- 57
    // STOP                  -- 00
    let bytecode = Bytes::from(vec![
        0x60, 0x14, // PUSH1 20
        0x5b, // JUMPDEST
        0x60, 0x01, // PUSH1 1
        0x90, // SWAP1
        0x03, // SUB
        0x80, // DUP1
        0x60, 0x02, // PUSH1 2 (JUMPDEST offset)
        0x57, // JUMPI
        0x00, // STOP
    ]);
    let contract_account = Account::new(
        U256::zero(),
        Code::from_bytecode(bytecode, &NativeCrypto),
        1,
        FxHashMap::default(),
    );

    let gas_limit = 100_000;
    let tx = make_tx_to(gas_limit, contract_addr());
    let l1_gas = compute_l1_gas(&tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    let env = make_env(gas_limit);
    let mut db = make_db_with_accounts(
        U256::from(SENDER_BALANCE),
        vec![(contract_addr(), contract_account)],
    );

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let report = vm.execute().expect("Execution should succeed");
    assert!(report.is_success(), "Contract call should succeed");

    // gas_used should be > intrinsic_gas + l1_gas (contract consumed execution gas)
    assert!(
        report.gas_used > 21_000 + l1_gas,
        "Contract should have consumed execution gas beyond intrinsic + l1"
    );

    // L1 fee vault must still receive the full l1_gas payment
    let l1_vault_balance = vm.db.get_account(l1_fee_vault_addr()).unwrap().info.balance;
    let expected_l1_fee = U256::from(l1_gas) * U256::from(GAS_PRICE);
    assert_eq!(
        l1_vault_balance, expected_l1_fee,
        "L1 fee vault should receive full l1_gas * gas_price even with contract execution"
    );
}

/// A contract call that runs out of execution gas should revert, but the
/// L1 fee vault must still receive the full l1_gas payment thanks to the
/// upfront reservation.
#[test]
fn test_oog_revert_still_pays_l1_fee_vault() {
    // Contract bytecode: infinite loop that always runs out of gas.
    // JUMPDEST  -- 5b  (offset 0)
    // PUSH1 0   -- 60 00
    // JUMP      -- 56
    let bytecode = Bytes::from(vec![
        0x5b, // JUMPDEST
        0x60, 0x00, // PUSH1 0
        0x56, // JUMP
    ]);
    let contract_account = Account::new(
        U256::zero(),
        Code::from_bytecode(bytecode, &NativeCrypto),
        1,
        FxHashMap::default(),
    );

    // Use a gas_limit that covers intrinsic + l1_gas + a small execution budget,
    // but the infinite loop will exhaust it.
    let preliminary_tx = make_tx_to(30_000, contract_addr());
    let l1_gas = compute_l1_gas(&preliminary_tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    let gas_limit = 21_000 + l1_gas + 100; // only 100 gas for execution
    let tx = make_tx_to(gas_limit, contract_addr());

    let env = make_env(gas_limit);
    let mut db = make_db_with_accounts(
        U256::from(SENDER_BALANCE),
        vec![(contract_addr(), contract_account)],
    );

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let report = vm
        .execute()
        .expect("Execution should complete (revert, not error)");
    assert!(
        !report.is_success(),
        "Transaction should revert due to out-of-gas"
    );

    // L1 fee vault must still receive the full l1_gas payment
    let l1_vault_balance = vm.db.get_account(l1_fee_vault_addr()).unwrap().info.balance;
    let expected_l1_fee = U256::from(l1_gas) * U256::from(GAS_PRICE);
    assert_eq!(
        l1_vault_balance, expected_l1_fee,
        "L1 fee vault should receive full l1_gas * gas_price even when execution reverts"
    );
}

// ==================== EIP-7623 floor + L1 gas tests ====================

// EIP-7623 constants (mirrored from gas_cost.rs)
const TX_BASE_COST: u64 = 21000;
const TOTAL_COST_FLOOR_PER_TOKEN: u64 = 10;
const TOKENS_PER_NONZERO_BYTE: u64 = 4; // 16 / STANDARD_TOKEN_COST(4)
const CALLDATA_COST_PER_NONZERO_BYTE: u64 = 16;

/// Computes the EIP-7623 gas floor for a given number of non-zero calldata bytes.
fn compute_floor(num_nonzero_bytes: u64) -> u64 {
    TX_BASE_COST + TOTAL_COST_FLOOR_PER_TOKEN * TOKENS_PER_NONZERO_BYTE * num_nonzero_bytes
}

/// Computes intrinsic gas for a simple call with non-zero calldata bytes.
fn compute_intrinsic(num_nonzero_bytes: u64) -> u64 {
    TX_BASE_COST + CALLDATA_COST_PER_NONZERO_BYTE * num_nonzero_bytes
}

/// On Prague+, EIP-7623 imposes a gas floor that can exceed intrinsic_gas for
/// transactions with heavy calldata. Since finalize computes:
///   actual_gas_used = max(execution_gas, floor) + l1_gas
/// a tx where gas_limit >= intrinsic + l1_gas but gas_limit < floor + l1_gas
/// would underflow in refund_sender. The reserve_l1_gas check must reject
/// such transactions upfront.
#[test]
fn test_eip7623_floor_plus_l1_gas_rejected_when_insufficient() {
    let num_nonzero_bytes: u64 = 100;
    let calldata = Bytes::from(vec![0xFF; num_nonzero_bytes as usize]);

    let floor = compute_floor(num_nonzero_bytes); // 25000
    let intrinsic = compute_intrinsic(num_nonzero_bytes); // 22600
    assert!(
        floor > intrinsic,
        "Test precondition: floor ({floor}) must exceed intrinsic ({intrinsic})"
    );

    // Use a preliminary tx to compute l1_gas (tx size affects l1_gas).
    let preliminary_tx = make_tx_with_calldata(floor + 5000, recipient_addr(), calldata.clone());
    let l1_gas = compute_l1_gas(&preliminary_tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    // Set gas_limit between (intrinsic + l1_gas) and (floor + l1_gas).
    // This passes intrinsic + l1_gas check but NOT floor + l1_gas check.
    let gas_limit = floor + l1_gas - 1;
    assert!(
        gas_limit >= intrinsic + l1_gas,
        "Test precondition: gas_limit ({gas_limit}) must cover intrinsic + l1_gas ({})",
        intrinsic + l1_gas
    );
    assert!(
        gas_limit < floor + l1_gas,
        "Test precondition: gas_limit ({gas_limit}) must be below floor + l1_gas ({})",
        floor + l1_gas
    );

    let tx = make_tx_with_calldata(gas_limit, recipient_addr(), calldata);

    let env = make_env(gas_limit);
    let mut db = make_db(U256::from(SENDER_BALANCE));

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let result = vm.execute();
    assert!(
        matches!(
            result,
            Err(VMError::TxValidation(
                TxValidationError::L1GasReservationTooLow
            ))
        ),
        "Expected L1GasReservationTooLow when gas_limit < floor + l1_gas, got {result:?}"
    );
}

/// When gas_limit exactly covers floor + l1_gas, the tx should succeed.
/// The L1 fee vault must still receive the full l1_gas payment.
#[test]
fn test_eip7623_floor_plus_l1_gas_exactly_covered_succeeds() {
    let num_nonzero_bytes: u64 = 100;
    let calldata = Bytes::from(vec![0xFF; num_nonzero_bytes as usize]);

    let floor = compute_floor(num_nonzero_bytes); // 25000

    // Use a preliminary tx to compute l1_gas.
    let preliminary_tx = make_tx_with_calldata(floor + 5000, recipient_addr(), calldata.clone());
    let l1_gas = compute_l1_gas(&preliminary_tx);
    assert!(l1_gas > 0, "l1_gas should be positive for this test");

    let gas_limit = floor + l1_gas;
    let tx = make_tx_with_calldata(gas_limit, recipient_addr(), calldata);

    let env = make_env(gas_limit);
    let mut db = make_db(U256::from(SENDER_BALANCE));

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    let report = vm.execute().expect("Execution should succeed");
    assert!(
        report.is_success(),
        "Transaction should succeed when gas_limit = floor + l1_gas"
    );

    // L1 fee vault must receive the full l1_gas payment
    let l1_vault_balance = vm.db.get_account(l1_fee_vault_addr()).unwrap().info.balance;
    let expected_l1_fee = U256::from(l1_gas) * U256::from(GAS_PRICE);
    assert_eq!(
        l1_vault_balance, expected_l1_fee,
        "L1 fee vault should receive full l1_gas * gas_price"
    );
}
