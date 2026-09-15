//! Tests for L2 Hook: fee token storage rollback, nonatomic finalization regression,
//! and privileged transaction handling.

use super::test_db::TestDatabase;
use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    types::{
        Account, Code, EIP1559Transaction, Fork, PrivilegedL2Transaction, Transaction, TxKind,
        fee_config::{FeeConfig, OperatorFeeConfig},
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    db::gen_db::GeneralizedDatabase,
    environment::{EVMConfig, Environment},
    hooks::l2_hook::{
        COMMON_BRIDGE_L2_ADDRESS, FEE_TOKEN_RATIO_ADDRESS, FEE_TOKEN_REGISTRY_ADDRESS,
    },
    tracing::LevmCallTracer,
    vm::{VM, VMType},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

// ==================== Constants ====================

const SENDER: u64 = 0x1000;
const RECIPIENT: u64 = 0x2000;
const COINBASE: u64 = 0xCCC;

// ==================== Helpers ====================

fn eoa(balance: U256) -> Account {
    Account::new(balance, Code::default(), 0, FxHashMap::default())
}

/// Contract that immediately REVERTs with empty return data.
/// Bytecode: PUSH1 0x00, PUSH1 0x00, REVERT
fn reverting_contract() -> Account {
    Account::new(
        U256::zero(),
        Code::from_bytecode(
            Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xfd]),
            &NativeCrypto,
        ),
        1,
        FxHashMap::default(),
    )
}

/// Contract that always returns 1 as a 32-byte word.
/// Used for FEE_TOKEN_REGISTRY (isFeeToken→true) and FEE_TOKEN_RATIO (ratio→1).
/// Bytecode: PUSH1 0x01, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
fn returns_one_contract() -> Account {
    Account::new(
        U256::zero(),
        Code::from_bytecode(
            Bytes::from(vec![
                0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            ]),
            &NativeCrypto,
        ),
        1,
        FxHashMap::default(),
    )
}

/// Fee token contract that modifies storage on every call.
/// Writes 0xBEEF to storage slot 0, then returns 1.
///
/// ```text
/// PUSH2 0xBEEF  PUSH1 0x00  SSTORE       // slot[0] = 0xBEEF
/// PUSH1 0x01    PUSH1 0x00  MSTORE        // mem[0] = 1
/// PUSH1 0x20    PUSH1 0x00  RETURN        // return(0, 32)
/// ```
fn fee_token_sstore_contract(initial_storage: FxHashMap<H256, U256>) -> Account {
    #[rustfmt::skip]
    let bytecode = vec![
        0x61, 0xBE, 0xEF,  // PUSH2 0xBEEF
        0x60, 0x00,         // PUSH1 0x00
        0x55,               // SSTORE
        0x60, 0x01,         // PUSH1 0x01
        0x60, 0x00,         // PUSH1 0x00
        0x52,               // MSTORE
        0x60, 0x20,         // PUSH1 0x20
        0x60, 0x00,         // PUSH1 0x00
        0xf3,               // RETURN
    ];
    Account::new(
        U256::zero(),
        Code::from_bytecode(Bytes::from(bytecode), &NativeCrypto),
        1,
        initial_storage,
    )
}

/// Fee token contract: succeeds for lockFee (0x899c86e2), reverts for everything
/// else (including payFee 0x72746eaf).
///
/// ```text
/// PUSH1 0x00    CALLDATALOAD    PUSH1 0xe0    SHR       // selector
/// PUSH4 0x899c86e2  EQ  PUSH1 0x14  JUMPI              // if lockFee → success
/// PUSH1 0x00  PUSH1 0x00  REVERT                        // else revert
/// JUMPDEST                                               // offset 0x14 = 20
/// PUSH1 0x01  PUSH1 0x00  MSTORE  PUSH1 0x20  PUSH1 0x00  RETURN
/// ```
fn fee_token_lock_only_contract() -> Account {
    #[rustfmt::skip]
    let bytecode = vec![
        0x60, 0x00,                         // PUSH1 0x00
        0x35,                               // CALLDATALOAD
        0x60, 0xe0,                         // PUSH1 0xe0
        0x1c,                               // SHR
        0x63, 0x89, 0x9c, 0x86, 0xe2,      // PUSH4 lockFee selector
        0x14,                               // EQ
        0x60, 0x14,                         // PUSH1 20 (jump target)
        0x57,                               // JUMPI
        0x60, 0x00,                         // PUSH1 0x00
        0x60, 0x00,                         // PUSH1 0x00
        0xfd,                               // REVERT
        0x5b,                               // JUMPDEST (offset 20)
        0x60, 0x01,                         // PUSH1 0x01
        0x60, 0x00,                         // PUSH1 0x00
        0x52,                               // MSTORE
        0x60, 0x20,                         // PUSH1 0x20
        0x60, 0x00,                         // PUSH1 0x00
        0xf3,                               // RETURN
    ];
    Account::new(
        U256::zero(),
        Code::from_bytecode(Bytes::from(bytecode), &NativeCrypto),
        1,
        FxHashMap::default(),
    )
}

/// Standard non-privileged, non-fee-token L2 Environment on Prague.
/// Derives tx fee bounds from `gas_price`/`base_fee_per_gas`. Remaining fields
/// use `Default::default()` (zeros / None / empty) which is fine for these tests.
fn non_privileged_l2_env(
    sender: Address,
    coinbase: Address,
    gas_limit: u64,
    base_fee_per_gas: u64,
    gas_price: u64,
) -> Environment {
    let fork = Fork::Prague;
    let blob_schedule = EVMConfig::canonical_values(fork);
    Environment {
        origin: sender,
        gas_limit,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase,
        timestamp: 1000,
        prev_randao: Some(H256::zero()),
        chain_id: U256::from(1),
        base_fee_per_gas: U256::from(base_fee_per_gas),
        base_blob_fee_per_gas: U256::from(1),
        gas_price: U256::from(gas_price),
        tx_max_priority_fee_per_gas: Some(U256::from(gas_price.saturating_sub(base_fee_per_gas))),
        tx_max_fee_per_gas: Some(U256::from(gas_price)),
        block_gas_limit: gas_limit * 2,
        ..Default::default()
    }
}

// ==================== Tests ====================

/// Regression test for PR #6045 / audit finding: fee token storage rollback.
///
/// When `prepare_execution_fee_token` deducts fees via `lockFee` (which calls
/// `transfer_fee_token`), the fee token contract's storage is modified. If a
/// subsequent validation check fails (here: priority_fee > max_fee_per_gas),
/// `restore_cache_state()` must revert those storage changes.
///
/// Before the fix (PR #6330), `transfer_fee_token` used `vm.db.get_account_mut`
/// directly without backing up storage slots, so `restore_cache_state()` could
/// not revert fee token storage — leaving tokens locked without being paid out.
#[test]
fn fee_token_storage_rolled_back_on_validation_failure() {
    let sender = Address::from_low_u64_be(SENDER);
    let coinbase = Address::from_low_u64_be(COINBASE);
    let fee_token_addr = Address::from_low_u64_be(0xEE00);

    let gas_limit: u64 = 100_000;
    let gas_price = 1000u64;

    // Fee token contract starts with slot 0 = 42.
    // The lockFee call will SSTORE 0xBEEF into slot 0.
    // If rollback works, slot 0 should remain 42 after the failed tx.
    let initial_slot = H256::zero();
    let initial_value = U256::from(42);
    let fee_token_storage: FxHashMap<H256, U256> =
        [(initial_slot, initial_value)].into_iter().collect();

    let accounts: FxHashMap<Address, Account> = [
        // Sender needs ETH for value=0, gas is paid in fee token
        (sender, eoa(U256::zero())),
        (coinbase, eoa(U256::zero())),
        (fee_token_addr, fee_token_sstore_contract(fee_token_storage)),
        (FEE_TOKEN_REGISTRY_ADDRESS, returns_one_contract()),
        (FEE_TOKEN_RATIO_ADDRESS, returns_one_contract()),
        (COMMON_BRIDGE_L2_ADDRESS, eoa(U256::zero())),
    ]
    .into_iter()
    .collect();

    let test_db = TestDatabase::new();
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts);

    let fork = Fork::Prague;
    let blob_schedule = EVMConfig::canonical_values(fork);
    let env = Environment {
        origin: sender,
        gas_limit,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase,
        timestamp: 1000,
        prev_randao: Some(H256::zero()),
        difficulty: U256::zero(),
        slot_number: U256::zero(),
        chain_id: U256::from(1),
        base_fee_per_gas: U256::from(gas_price),
        base_blob_fee_per_gas: U256::from(1),
        gas_price: U256::from(gas_price),
        block_excess_blob_gas: None,
        block_blob_gas_used: None,
        tx_blob_hashes: vec![],
        // priority > max_fee triggers PriorityGreaterThanMaxFeePerGas AFTER fee deduction
        tx_max_priority_fee_per_gas: Some(U256::from(2000)),
        tx_max_fee_per_gas: Some(U256::from(gas_price)),
        tx_max_fee_per_blob_gas: None,
        tx_nonce: 0,
        block_gas_limit: gas_limit * 2,
        is_privileged: false,
        fee_token: Some(fee_token_addr),
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    };

    let fee_config = FeeConfig {
        base_fee_vault: None,
        operator_fee_config: None,
        l1_fee_config: None,
    };

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0x9999)),
        value: U256::zero(),
        data: Bytes::new(),
        gas_limit,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: 2000, // > max_fee_per_gas → will fail validation
        ..Default::default()
    });

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config),
        &NativeCrypto,
        None,
    )
    .unwrap();

    // Execute — should fail because priority_fee > max_fee_per_gas
    let result = vm.execute();
    assert!(
        result.is_err(),
        "Expected execute to fail due to PriorityGreaterThanMaxFeePerGas, got: {result:?}"
    );

    // The critical assertion: fee token storage must be rolled back.
    // Before the fix, transfer_fee_token wrote storage without backup,
    // so slot 0 would be 0xBEEF (from the lockFee simulation) instead of 42.
    let fee_token_slot_0 = db
        .get_account(fee_token_addr)
        .unwrap()
        .storage
        .get(&initial_slot)
        .copied()
        .unwrap_or_default();
    assert_eq!(
        fee_token_slot_0,
        initial_value,
        "Fee token storage slot 0 should be rolled back to {initial_value} after failed validation, \
         but was {fee_token_slot_0} (0xBEEF = {:#x} means rollback failed)",
        U256::from(0xBEEF)
    );
}

/// Regression test for audit finding C: atomic finalize mutations.
///
/// Sets up an L2 transaction where `pay_operator_fee` will overflow because the
/// operator fee vault already holds `U256::MAX`. Before the fix, earlier mutations
/// (pay_coinbase, refund_sender, etc.) would persist despite the error. With the fix,
/// `restore_cache_state()` reverts everything, leaving balances unchanged.
#[test]
fn finalize_mutation_failure_reverts_all_changes() {
    let sender = Address::from_low_u64_be(SENDER);
    let coinbase = Address::from_low_u64_be(COINBASE);
    let operator_fee_vault = Address::from_low_u64_be(0xFEE);

    let gas_limit: u64 = 100_000;
    let base_fee_per_gas = 1000u64;
    // gas_price > base_fee to leave room for operator_fee_per_gas in priority fee
    let gas_price = 1002u64;
    let operator_fee_per_gas = 1u64;

    let accounts: FxHashMap<Address, Account> = [
        (sender, eoa(U256::from(gas_price) * U256::from(gas_limit))),
        (coinbase, eoa(U256::zero())),
        (operator_fee_vault, eoa(U256::MAX)),
    ]
    .into_iter()
    .collect();

    let test_db = TestDatabase::new();
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts);

    let env = non_privileged_l2_env(sender, coinbase, gas_limit, base_fee_per_gas, gas_price);

    let fee_config = FeeConfig {
        base_fee_vault: None,
        operator_fee_config: Some(OperatorFeeConfig {
            operator_fee_vault,
            operator_fee_per_gas,
        }),
        l1_fee_config: None,
    };

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0x9999)),
        value: U256::zero(),
        data: Bytes::new(),
        gas_limit,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price - base_fee_per_gas,
        ..Default::default()
    });

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config),
        &NativeCrypto,
        None,
    )
    .unwrap();

    // Execute — should fail because pay_operator_fee overflows (U256::MAX + fee)
    let result = vm.execute();
    assert!(
        result.is_err(),
        "Expected execute to fail due to operator fee vault overflow, got: {result:?}"
    );

    // Verify rollback: coinbase should still be 0 (pay_coinbase was reverted)
    let coinbase_balance = db.get_account(coinbase).unwrap().info.balance;
    assert_eq!(
        coinbase_balance,
        U256::zero(),
        "Coinbase balance should be 0 after rollback, but was {coinbase_balance}"
    );

    // Verify rollback: operator fee vault should still be U256::MAX (no partial payment)
    let vault_balance = db.get_account(operator_fee_vault).unwrap().info.balance;
    assert_eq!(
        vault_balance,
        U256::MAX,
        "Operator fee vault balance should be U256::MAX after rollback, but was {vault_balance}"
    );
}

/// Fee token variant: the fee token contract reverts on `payFee` calls during
/// finalization, triggering rollback of Phase 2 mutations only.
///
/// Flow:
/// 1. prepare_execution_fee_token: lockFee succeeds, value transferred to contract
/// 2. Execution: called contract REVERTs
/// 3. Finalize: undo_value_transfer runs, then backup is cleared (checkpoint after undo)
/// 4. apply_finalize_mutations → refund_sender_fee_token → pay_fee_token → REVERT
/// 5. restore_cache_state undoes only Phase 2 mutations (undo_value_transfer preserved)
///
/// Assertions verify the contract has 0 balance (value returned to sender, not rolled back).
#[test]
fn fee_token_revert_during_finalize_triggers_rollback() {
    let sender = Address::from_low_u64_be(SENDER);
    let coinbase = Address::from_low_u64_be(COINBASE);
    let contract_addr = Address::from_low_u64_be(0x9999);
    let fee_token_addr = Address::from_low_u64_be(0xEE00);

    let gas_limit: u64 = 100_000;
    let base_fee_per_gas = 1000u64;
    let gas_price = 1002u64;
    let tx_value = U256::from(1000);

    // Sender needs ETH for value only (gas paid via fee token).
    // deduct_caller_fee_token deducts value, then transfer_value increases contract.
    let sender_balance = tx_value;
    let accounts: FxHashMap<Address, Account> = [
        (sender, eoa(sender_balance)),
        (coinbase, eoa(U256::zero())),
        (contract_addr, reverting_contract()),
        (fee_token_addr, fee_token_lock_only_contract()),
        (FEE_TOKEN_REGISTRY_ADDRESS, returns_one_contract()),
        (FEE_TOKEN_RATIO_ADDRESS, returns_one_contract()),
        (COMMON_BRIDGE_L2_ADDRESS, eoa(U256::zero())),
    ]
    .into_iter()
    .collect();

    let test_db = TestDatabase::new();
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts);

    let fork = Fork::Prague;
    let blob_schedule = EVMConfig::canonical_values(fork);
    let env = Environment {
        origin: sender,
        gas_limit,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase,
        timestamp: 1000,
        prev_randao: Some(H256::zero()),
        difficulty: U256::zero(),
        slot_number: U256::zero(),
        chain_id: U256::from(1),
        base_fee_per_gas: U256::from(base_fee_per_gas),
        base_blob_fee_per_gas: U256::from(1),
        gas_price: U256::from(gas_price),
        block_excess_blob_gas: None,
        block_blob_gas_used: None,
        tx_blob_hashes: vec![],
        tx_max_priority_fee_per_gas: Some(U256::from(gas_price - base_fee_per_gas)),
        tx_max_fee_per_gas: Some(U256::from(gas_price)),
        tx_max_fee_per_blob_gas: None,
        tx_nonce: 0,
        block_gas_limit: gas_limit * 2,
        is_privileged: false,
        fee_token: Some(fee_token_addr),
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    };

    let fee_config = FeeConfig {
        base_fee_vault: None,
        operator_fee_config: None,
        l1_fee_config: None,
    };

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(contract_addr),
        value: tx_value,
        data: Bytes::new(),
        gas_limit,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price - base_fee_per_gas,
        ..Default::default()
    });

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config),
        &NativeCrypto,
        None,
    )
    .unwrap();

    // Execute — contract REVERTs, then fee token reverts on payFee during finalize
    let result = vm.execute();
    assert!(
        result.is_err(),
        "Expected execute to fail due to fee token revert on payFee, got: {result:?}"
    );

    // Verify rollback: coinbase should still be 0 (pay_coinbase never completed)
    let coinbase_balance = db.get_account(coinbase).unwrap().info.balance;
    assert_eq!(
        coinbase_balance,
        U256::zero(),
        "Coinbase balance should be 0 after rollback, but was {coinbase_balance}"
    );

    // Verify that undo_value_transfer is preserved: the contract should have
    // 0 balance because the tx reverted and value was returned to the sender.
    let contract_balance = db.get_account(contract_addr).unwrap().info.balance;
    assert_eq!(
        contract_balance,
        U256::zero(),
        "Contract should not hold value after tx revert + rollback"
    );
}

/// Privileged tx with intrinsic gas failure must not lose sender funds.
///
/// Scenario: A non-bridge privileged tx has value > 0, sufficient sender balance,
/// but gas_limit < intrinsic gas (21000). The old code debits the sender's balance
/// before validation and then zeroes msg_value on failure, making the refund in
/// finalize_execution a no-op — permanently burning the sender's ETH.
#[test]
fn privileged_tx_intrinsic_gas_failure_preserves_sender_balance() {
    let sender = Address::from_low_u64_be(SENDER);
    let recipient = Address::from_low_u64_be(RECIPIENT);
    let coinbase = Address::from_low_u64_be(COINBASE);

    let initial_balance = U256::from(1_000_000);
    let transfer_value = U256::from(500_000);
    // Gas limit of 100 is well below intrinsic gas (21000 base cost)
    let gas_limit: u64 = 100;

    let test_db = TestDatabase::new();
    let accounts: FxHashMap<Address, Account> = vec![
        (sender, eoa(initial_balance)),
        (recipient, eoa(U256::zero())),
        (coinbase, eoa(U256::zero())),
    ]
    .into_iter()
    .collect();
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts);

    let fork = Fork::Prague;
    let blob_schedule = EVMConfig::canonical_values(fork);
    let env = Environment {
        origin: sender,
        gas_limit,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase,
        timestamp: 1000,
        prev_randao: Some(H256::zero()),
        difficulty: U256::zero(),
        slot_number: U256::zero(),
        chain_id: U256::from(1),
        base_fee_per_gas: U256::from(1000),
        base_blob_fee_per_gas: U256::from(1),
        gas_price: U256::from(1000),
        block_excess_blob_gas: None,
        block_blob_gas_used: None,
        tx_blob_hashes: vec![],
        tx_max_priority_fee_per_gas: None,
        tx_max_fee_per_gas: Some(U256::from(1000)),
        tx_max_fee_per_blob_gas: None,
        tx_nonce: 0,
        block_gas_limit: gas_limit * 100,
        is_privileged: true,
        fee_token: None,
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    };

    let tx = Transaction::PrivilegedL2Transaction(PrivilegedL2Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1000,
        max_fee_per_gas: 1000,
        gas_limit,
        to: TxKind::Call(recipient),
        value: transfer_value,
        data: Bytes::new(),
        access_list: vec![],
        from: sender,
        inner_hash: Default::default(),
        sender_cache: Default::default(),
        cached_canonical: Default::default(),
    });

    let fee_config = FeeConfig {
        base_fee_vault: None,
        operator_fee_config: None,
        l1_fee_config: None,
    };

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config),
        &NativeCrypto,
        None,
    )
    .expect("VM creation should succeed");

    let report = vm
        .execute()
        .expect("Privileged tx execution should not error");

    // The tx should revert (INVALID opcode) because intrinsic gas was too low
    assert!(
        !report.is_success(),
        "Tx should revert due to intrinsic gas failure"
    );

    // The sender's balance must be fully preserved — no funds should be burned.
    let sender_balance_after = db.get_account(sender).unwrap().info.balance;
    assert_eq!(
        sender_balance_after,
        initial_balance,
        "Sender balance must be preserved after failed privileged tx. \
         Expected {initial_balance}, got {sender_balance_after}. \
         Difference (lost funds): {}",
        initial_balance - sender_balance_after
    );

    // The recipient should NOT have received any funds
    let recipient_balance_after = db.get_account(recipient).unwrap().info.balance;
    assert_eq!(
        recipient_balance_after,
        U256::zero(),
        "Recipient should not receive funds from a reverted privileged tx"
    );
}

/// Regression test: undo_last_transaction must restore storage slots.
///
/// The L2Hook's finalize_execution used to clear the call_frame_backup
/// (which contains SSTORE rollback data) before BackupHook could save it
/// into tx_backup. This meant undo_last_transaction restored account info
/// (balances, nonces) but silently lost all storage changes.
///
/// This is critical for the Credible Layer integration where transactions
/// are executed speculatively and then undone if the sidecar rejects them.
#[test]
fn undo_last_transaction_restores_storage_slots() {
    let sender = Address::from_low_u64_be(SENDER);
    let coinbase = Address::from_low_u64_be(COINBASE);
    let contract = Address::from_low_u64_be(0x3000);

    let gas_limit: u64 = 100_000;
    let gas_price = 1000u64;

    // Contract that writes 0xDEAD to storage slot 0, then returns.
    //
    // ```text
    // PUSH2 0xDEAD  PUSH1 0x00  SSTORE       // slot[0] = 0xDEAD
    // PUSH1 0x00    PUSH1 0x00  RETURN        // return(0, 0)
    // ```
    #[rustfmt::skip]
    let sstore_bytecode = vec![
        0x61, 0xDE, 0xAD,  // PUSH2 0xDEAD
        0x60, 0x00,         // PUSH1 0x00
        0x55,               // SSTORE
        0x60, 0x00,         // PUSH1 0x00
        0x60, 0x00,         // PUSH1 0x00
        0xf3,               // RETURN
    ];

    let initial_slot = H256::zero();
    let initial_value = U256::from(42);
    let contract_storage: FxHashMap<H256, U256> =
        [(initial_slot, initial_value)].into_iter().collect();

    let accounts: FxHashMap<Address, Account> = [
        (sender, eoa(U256::from(10_000_000_000u64))),
        (coinbase, eoa(U256::zero())),
        (
            contract,
            Account::new(
                U256::zero(),
                Code::from_bytecode(Bytes::from(sstore_bytecode), &NativeCrypto),
                1,
                contract_storage,
            ),
        ),
    ]
    .into_iter()
    .collect();

    let test_db = TestDatabase::new();
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts);

    // priority fee = 0 (base_fee == gas_price), no operator fee
    let env = non_privileged_l2_env(sender, coinbase, gas_limit, gas_price, gas_price);

    let fee_config = FeeConfig {
        base_fee_vault: None,
        operator_fee_config: None,
        l1_fee_config: None,
    };

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: gas_price,
        gas_limit,
        to: TxKind::Call(contract),
        value: U256::zero(),
        data: Bytes::new(),
        ..Default::default()
    });

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(fee_config),
        &NativeCrypto,
        None,
    )
    .unwrap();

    // Execute the transaction — it should succeed and write 0xDEAD to slot 0
    let result = vm.execute();
    assert!(
        result.is_ok(),
        "Transaction should succeed, got: {result:?}"
    );

    // Verify storage was modified by the tx
    let slot_after_exec = db
        .get_account(contract)
        .unwrap()
        .storage
        .get(&initial_slot)
        .copied()
        .unwrap_or_default();
    assert_eq!(
        slot_after_exec,
        U256::from(0xDEAD),
        "Storage slot 0 should be 0xDEAD after execution"
    );

    // Undo the transaction
    db.undo_last_transaction()
        .expect("undo_last_transaction should succeed");

    // The critical assertion: storage must be restored to the original value
    let slot_after_undo = db
        .get_account(contract)
        .unwrap()
        .storage
        .get(&initial_slot)
        .copied()
        .unwrap_or_default();
    assert_eq!(
        slot_after_undo,
        initial_value,
        "Storage slot 0 should be restored to {initial_value} after undo_last_transaction, \
         but was {slot_after_undo} (0xDEAD = {:#x} means storage backup was lost)",
        U256::from(0xDEAD)
    );
}
