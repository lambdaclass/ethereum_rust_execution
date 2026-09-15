//! EIP-8038 PRELIMINARY Amsterdam repricing tests.
//!
//! Phase 1 verifies the Amsterdam-gated access / storage / access-list constant
//! repricing through the public `gas_cost` selectors and the standalone
//! `intrinsic_gas_dimensions` helper. Pre-Amsterdam behavior must be
//! byte-identical to before, so each case pins an Osaka control to the exact
//! legacy literal (2600 / 2100 / 2400 / 1900) alongside the Amsterdam values
//! (3000 account access, 2100 storage access).
//!
//! Phase 2 verifies the SSTORE regular-gas + refund reformulation by EXECUTING
//! SSTORE sequences through a full VM and asserting the observable pre-refund
//! regular gas and net regular refund (`gas_refunded`) for each row of the
//! EIP-8038 SSTORE table, with `Fork::Osaka` controls proving pre-Amsterdam
//! accounting is byte-identical.
//!
//! Expected values follow the EELS Amsterdam reference at the fixture tag
//! `tests-glamsterdam-devnet@v8.1.0`
//! (ethereum/execution-specs `amsterdam/vm/instructions/storage.py::sstore`):
//! the first change to a slot charges the access cost (cold XOR warm) plus a
//! flat `STORAGE_WRITE` (= 10000) surcharge, and a restore-to-original refunds
//! the full `STORAGE_WRITE` (= 10000) charged on that first change.

use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    types::{Account, Code, EIP1559Transaction, Fork, Transaction, TxKind},
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    db::gen_db::GeneralizedDatabase,
    environment::{EVMConfig, Environment},
    errors::{ExceptionalHalt, TxResult, VMError},
    gas_cost,
    tracing::LevmCallTracer,
    utils::intrinsic_gas_dimensions,
    vm::{VM, VMType},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

use crate::levm::test_db::TestDatabase;

// ===== Cold SLOAD =====

#[test]
fn test_cold_sload_amsterdam_is_2100() {
    // EIP-8038 leaves COLD_STORAGE_ACCESS at 2100; only account access is raised.
    let cost = gas_cost::sload(true, Fork::Amsterdam).expect("sload");
    assert_eq!(cost, 2100, "cold SLOAD at Amsterdam must be 2100");
}

#[test]
fn test_cold_sload_osaka_control_is_2100() {
    // Same value pre-Amsterdam, from the unrepriced constant.
    let cost = gas_cost::sload(true, Fork::Osaka).expect("sload");
    assert_eq!(cost, 2100, "cold SLOAD at Osaka must stay 2100");
}

#[test]
fn test_warm_sload_unchanged_across_forks() {
    // Warm cost is untouched by this phase.
    assert_eq!(gas_cost::sload(false, Fork::Amsterdam).expect("sload"), 100);
    assert_eq!(gas_cost::sload(false, Fork::Osaka).expect("sload"), 100);
}

// ===== Cold account access (BALANCE / EXTCODEHASH) =====

#[test]
fn test_cold_account_access_amsterdam_is_3000() {
    // BALANCE and EXTCODEHASH of a cold address both cost 3000 at Amsterdam.
    assert_eq!(
        gas_cost::balance(true, Fork::Amsterdam).expect("balance"),
        3000,
        "cold BALANCE at Amsterdam must be 3000"
    );
    assert_eq!(
        gas_cost::extcodehash(true, Fork::Amsterdam).expect("extcodehash"),
        3000,
        "cold EXTCODEHASH at Amsterdam must be 3000"
    );
}

#[test]
fn test_cold_account_access_osaka_control_is_2600() {
    // Byte-identical pre-Amsterdam: cold account access remains 2600.
    assert_eq!(
        gas_cost::balance(true, Fork::Osaka).expect("balance"),
        2600,
        "cold BALANCE at Osaka must stay 2600"
    );
    assert_eq!(
        gas_cost::extcodehash(true, Fork::Osaka).expect("extcodehash"),
        2600,
        "cold EXTCODEHASH at Osaka must stay 2600"
    );
}

#[test]
fn test_warm_account_access_unchanged_across_forks() {
    // Warm cost is untouched by this phase.
    assert_eq!(
        gas_cost::balance(false, Fork::Amsterdam).expect("balance"),
        100
    );
    assert_eq!(gas_cost::balance(false, Fork::Osaka).expect("balance"), 100);
}

// ===== Access-list intrinsic per-entry constants =====

#[test]
fn test_access_list_selectors() {
    // The fork selectors expose the repriced per-entry constants directly.
    // Each is the cold access minus WARM_ACCESS, so prepaying is gas neutral.
    assert_eq!(gas_cost::access_list_address_cost(Fork::Amsterdam), 2900);
    assert_eq!(
        gas_cost::access_list_storage_key_cost(Fork::Amsterdam),
        2000
    );
    // Osaka controls: legacy literals.
    assert_eq!(gas_cost::access_list_address_cost(Fork::Osaka), 2400);
    assert_eq!(gas_cost::access_list_storage_key_cost(Fork::Osaka), 1900);
}

/// Builds a value-free, calldata-free CALL tx carrying the given access list.
fn access_list_tx(access_list: Vec<(Address, Vec<H256>)>) -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to: TxKind::Call(Address::from_low_u64_be(0xBEEF)),
        value: U256::zero(),
        data: Bytes::new(),
        access_list,
        ..Default::default()
    })
}

#[test]
fn test_access_list_intrinsic_per_address_amsterdam() {
    // Recover the pure per-address constant from the intrinsic regular-gas
    // delta by subtracting the EIP-7981 access-list data-byte contribution
    // (20 bytes -> 80 tokens -> 80 * 16 = 1280 at Amsterdam).
    let block_gas_limit = 30_000_000;
    let base = intrinsic_gas_dimensions(
        &access_list_tx(vec![]),
        Address::zero(),
        Fork::Amsterdam,
        block_gas_limit,
    )
    .expect("intrinsic base")
    .0;
    let with_addr = intrinsic_gas_dimensions(
        &access_list_tx(vec![(Address::from_low_u64_be(0x11), vec![])]),
        Address::zero(),
        Fork::Amsterdam,
        block_gas_limit,
    )
    .expect("intrinsic with address")
    .0;
    let eip7981_addr_data = 20 * 4 * 16; // bytes * STANDARD_TOKEN_COST * floor(16)
    assert_eq!(
        with_addr - base - eip7981_addr_data,
        2900,
        "per-address access-list constant at Amsterdam must be 2900"
    );
}

#[test]
fn test_access_list_intrinsic_per_key_amsterdam() {
    // Per-key constant: delta between one address with one key and one address
    // with zero keys, minus the EIP-7981 contribution of the extra 32 bytes
    // (32 -> 128 tokens -> 128 * 16 = 2048).
    let block_gas_limit = 30_000_000;
    let addr = Address::from_low_u64_be(0x11);
    let zero_keys = intrinsic_gas_dimensions(
        &access_list_tx(vec![(addr, vec![])]),
        Address::zero(),
        Fork::Amsterdam,
        block_gas_limit,
    )
    .expect("intrinsic zero keys")
    .0;
    let one_key = intrinsic_gas_dimensions(
        &access_list_tx(vec![(addr, vec![H256::from_low_u64_be(1)])]),
        Address::zero(),
        Fork::Amsterdam,
        block_gas_limit,
    )
    .expect("intrinsic one key")
    .0;
    let eip7981_key_data = 32 * 4 * 16;
    assert_eq!(
        one_key - zero_keys - eip7981_key_data,
        2000,
        "per-key access-list constant at Amsterdam must be 2000"
    );
}

#[test]
fn test_access_list_intrinsic_osaka_control() {
    // Pre-Amsterdam: no EIP-7981 data-byte fold, so the intrinsic deltas equal
    // the legacy per-entry constants exactly (2400 / 1900).
    let block_gas_limit = 30_000_000;
    let addr = Address::from_low_u64_be(0x11);
    let base = intrinsic_gas_dimensions(
        &access_list_tx(vec![]),
        Address::zero(),
        Fork::Osaka,
        block_gas_limit,
    )
    .expect("intrinsic base")
    .0;
    let with_addr = intrinsic_gas_dimensions(
        &access_list_tx(vec![(addr, vec![])]),
        Address::zero(),
        Fork::Osaka,
        block_gas_limit,
    )
    .expect("intrinsic with address")
    .0;
    assert_eq!(
        with_addr - base,
        2400,
        "per-address access-list constant at Osaka must stay 2400"
    );
    let one_key = intrinsic_gas_dimensions(
        &access_list_tx(vec![(addr, vec![H256::from_low_u64_be(1)])]),
        Address::zero(),
        Fork::Osaka,
        block_gas_limit,
    )
    .expect("intrinsic one key")
    .0;
    assert_eq!(
        one_key - with_addr,
        1900,
        "per-key access-list constant at Osaka must stay 1900"
    );
}

// ===========================================================================
// Phase 2: SSTORE regular-gas + refund reformulation (VM-execution tests)
// ===========================================================================

const SENDER: Address = Address::repeat_byte(0x10);
const CONTRACT: Address = Address::repeat_byte(0xC0);
/// The single storage slot every sequence writes to. As an H256 big-endian key
/// this is key 0x01; pushed onto the stack via `PUSH1 0x01`.
const SLOT_KEY: u8 = 0x01;

/// Builds the L1 execution environment for `fork` with zero gas price and
/// balance checks disabled, so only opcode/intrinsic gas accounting matters.
fn sstore_env(fork: Fork) -> Environment {
    let blob_schedule = EVMConfig::canonical_values(fork);
    Environment {
        origin: SENDER,
        gas_limit: 1_000_000,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase: Address::from_low_u64_be(0xCCC),
        timestamp: 1000,
        prev_randao: Some(H256::zero()),
        difficulty: U256::zero(),
        slot_number: U256::zero(),
        chain_id: U256::from(1),
        base_fee_per_gas: U256::zero(),
        base_blob_fee_per_gas: U256::from(1),
        gas_price: U256::zero(),
        block_excess_blob_gas: None,
        block_blob_gas_used: None,
        tx_blob_hashes: vec![],
        tx_max_priority_fee_per_gas: None,
        tx_max_fee_per_gas: Some(U256::zero()),
        tx_max_fee_per_blob_gas: None,
        tx_nonce: 0,
        block_gas_limit: 30_000_000,
        is_privileged: false,
        fee_token: None,
        disable_balance_check: true,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    }
}

/// Builds a DB with a funded sender and a contract whose code is `bytecode` and
/// whose slot 0x01 is pre-seeded to `slot_original` (the tx-start "O" value).
fn sstore_db(bytecode: Vec<u8>, slot_original: U256) -> GeneralizedDatabase {
    let mut storage = FxHashMap::default();
    if !slot_original.is_zero() {
        storage.insert(H256::from_low_u64_be(SLOT_KEY as u64), slot_original);
    }
    let contract = Account::new(
        U256::zero(),
        Code::from_bytecode(Bytes::from(bytecode), &NativeCrypto),
        1,
        storage,
    );
    let sender = Account::new(
        U256::from(10u64).pow(18.into()),
        Code::default(),
        0,
        FxHashMap::default(),
    );
    let mut accounts: FxHashMap<Address, Account> = FxHashMap::default();
    accounts.insert(SENDER, sender);
    accounts.insert(CONTRACT, contract.clone());

    let mut db = TestDatabase::new();
    db.accounts.insert(SENDER, accounts[&SENDER].clone());
    db.accounts.insert(CONTRACT, contract);

    GeneralizedDatabase::new_with_account_state(Arc::new(db), accounts)
}

/// A no-value, no-calldata, no-access-list CALL to the contract.
fn sstore_tx() -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to: TxKind::Call(CONTRACT),
        value: U256::zero(),
        data: Bytes::new(),
        access_list: Default::default(),
        ..Default::default()
    })
}

/// A self-contained gas-burning countdown loop. It burns on the order of ~80k
/// regular gas so the EIP-3529 refund cap (`gas_used / 5`) never binds and the
/// raw net refund counter is observable. Its exact gas cost does not matter: the
/// probe (`probe_regular`) runs the identical prefix and is subtracted out.
///
///   PUSH2 0x0C80   ; loop counter (3200)
///   JUMPDEST (off 3)
///   PUSH1 1
///   SWAP1
///   SUB
///   DUP1
///   PUSH2 0x0003   ; JUMPDEST offset
///   JUMPI
///   POP
fn burn_prefix() -> Vec<u8> {
    vec![
        0x61, 0x0C, 0x80, // PUSH2 0x0C80
        0x5b, // JUMPDEST (offset 3)
        0x60, 0x01, // PUSH1 1
        0x90, // SWAP1
        0x03, // SUB
        0x80, // DUP1
        0x61, 0x00, 0x03, // PUSH2 0x0003 (JUMPDEST offset)
        0x57, // JUMPI
        0x50, // POP
    ]
}

/// Pre-refund regular gas for a finished tx, computed in a fork-uniform way.
///
///   - Amsterdam+: `report.gas_used` already equals `effective_regular + state`
///     where `effective_regular` is pre-refund regular (refunds apply to
///     `gas_spent`, not to this field). Subtracting `state_gas_used` isolates the
///     pre-refund regular dimension.
///   - Pre-Amsterdam: `report.gas_used` is the post-refund total and there is no
///     state dimension, so adding back the (uncapped) `gas_refunded` recovers the
///     pre-refund regular gas.
fn pre_refund_regular(fork: Fork, report: &ethrex_levm::errors::ExecutionReport) -> u64 {
    if fork >= Fork::Amsterdam {
        report
            .gas_used
            .checked_sub(report.state_gas_used)
            .expect("gas_used < state_gas_used")
    } else {
        report
            .gas_used
            .checked_add(report.gas_refunded)
            .expect("pre-refund regular overflow")
    }
}

/// Runs `body` (prefixed by `burn_prefix`) against a contract whose slot 0x01
/// starts at `slot_original`, and returns `(sstore_regular_gas, regular_refund)`:
///   - `sstore_regular_gas` = pre-refund regular of the full run, minus the
///     pre-refund regular of an identical burn-only probe, minus the `PUSH1`
///     costs of `body` (`body_pushes * 3`). This leaves exactly the regular gas
///     charged by the SSTOREs (access components + STORAGE_WRITE surcharges),
///     because the burn prefix and intrinsic cancel against the probe.
///   - `regular_refund` = `report.gas_refunded`, the net refund counter. The burn
///     prefix guarantees `gas_used / 5` exceeds every table refund, so this value
///     is the raw uncapped net refund.
///
/// `body_pushes` counts only the `PUSH1` opcodes inside `body` (not the prefix).
fn run_sstore(fork: Fork, body: Vec<u8>, body_pushes: u64, slot_original: U256) -> (u64, u64) {
    // Probe: identical burn prefix then STOP, no SSTOREs. No refund, no state gas.
    let probe_regular = {
        let mut code = burn_prefix();
        code.push(0x00); // STOP
        let env = sstore_env(fork);
        let mut db = sstore_db(code, U256::zero());
        let tx = sstore_tx();
        let mut vm = VM::new(
            env,
            &mut db,
            &tx,
            LevmCallTracer::disabled(),
            VMType::L1,
            &NativeCrypto,
            None,
        )
        .expect("VM::new (probe)");
        let report = vm.execute().expect("probe execute");
        assert!(report.is_success(), "burn probe must succeed: {report:?}");
        assert_eq!(report.gas_refunded, 0, "probe must not refund");
        pre_refund_regular(fork, &report)
    };

    let mut code = burn_prefix();
    code.extend_from_slice(&body);
    let env = sstore_env(fork);
    let mut db = sstore_db(code, slot_original);
    let tx = sstore_tx();
    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L1,
        &NativeCrypto,
        None,
    )
    .expect("VM::new");
    let report = vm.execute().expect("execute");
    assert!(
        report.is_success(),
        "sstore sequence must succeed: {report:?}"
    );

    // The burn prefix must dominate so the refund cap never binds.
    assert!(
        report.gas_used / 5 >= 11616,
        "burn prefix too small: gas_used={} cannot uncap a 11616 refund",
        report.gas_used
    );

    let push_gas = body_pushes.checked_mul(3).expect("push gas");
    let sstore_regular = pre_refund_regular(fork, &report)
        .checked_sub(probe_regular)
        .and_then(|g| g.checked_sub(push_gas))
        .expect("sstore regular gas underflow");
    (sstore_regular, report.gas_refunded)
}

/// `PUSH1 value` then `PUSH1 SLOT_KEY` then `SSTORE`. Each call to this adds 2
/// PUSH1 opcodes (caller must total `body_pushes`).
fn sstore_seq(value: u8) -> Vec<u8> {
    vec![0x60, value, 0x60, SLOT_KEY, 0x55]
}

// ----- Table row: (0, 0, x) new slot, cold -> 2100 + 10000, no refund -----

#[test]
fn test_sstore_new_slot_cold_amsterdam() {
    // O=0, C=0, N=5, slot cold: COLD_STORAGE_ACCESS(2100) + STORAGE_WRITE(10000).
    let (regular, refund) = run_sstore(Fork::Amsterdam, sstore_seq(5), 2, U256::zero());
    assert_eq!(regular, 2100 + 10000, "cold new-slot regular at Amsterdam");
    assert_eq!(refund, 0, "no refund for a plain new-slot write");
}

#[test]
fn test_sstore_new_slot_cold_osaka_control() {
    // Pre-Amsterdam byte-identical: COLD(2100) + CREATION(20000).
    let (regular, refund) = run_sstore(Fork::Osaka, sstore_seq(5), 2, U256::zero());
    assert_eq!(regular, 2100 + 20000, "cold new-slot regular at Osaka");
    assert_eq!(refund, 0, "no refund for a plain new-slot write");
}

// ----- Table row: (0, 0, x) new slot, warm -> 100 + 10000, no refund -----
//
// The access component is always charged, so a warm first change pays
// `WARM_ACCESS + STORAGE_WRITE` (EIP-8038 SSTORE table, warm new-slot row).

#[test]
fn test_sstore_new_slot_warm_amsterdam() {
    // Warm the slot first via SLOAD (PUSH1 key; SLOAD; POP), then SSTORE 0->5.
    // PUSH1 key(3) + SLOAD(cold 2100) + POP(2) + PUSH1 v + PUSH1 key + SSTORE(warm).
    // The SSTORE itself sees a warm slot: warm access (100) + STORAGE_WRITE (10000)
    // = 10100.
    let mut code = vec![0x60, SLOT_KEY, 0x54, 0x50]; // PUSH1 key; SLOAD; POP
    code.extend_from_slice(&sstore_seq(5));
    // 3 PUSH1 total; SLOAD cold (2100) and POP (2) are not PUSHes, so subtract
    // them from the SSTORE-attributable figure explicitly here.
    let (regular_incl_sload, refund) = run_sstore(Fork::Amsterdam, code, 3, U256::zero());
    let sstore_regular = regular_incl_sload - 2100 /* cold SLOAD */ - 2 /* POP */;
    assert_eq!(
        sstore_regular,
        100 + 10000,
        "warm new-slot SSTORE regular at Amsterdam (warm access + STORAGE_WRITE)"
    );
    assert_eq!(refund, 0, "no refund for a plain new-slot write");
}

// ----- Table row: (0, x, 0) set-then-clear-in-tx, net STORAGE_WRITE refunded -

#[test]
fn test_sstore_set_then_clear_in_tx_amsterdam() {
    // O=0; write 0->5 (cold first change: 2100+10000); write 5->0 (warm: 100).
    // Net regular charged = 2100 + 10000 + 100 = 12200.
    // Net refund = STORAGE_WRITE = 10000 (restore-to-original refunds the full
    // STORAGE_WRITE per EELS; the state-gas STORAGE_SET is credited separately).
    let mut code = sstore_seq(5);
    code.extend_from_slice(&sstore_seq(0));
    let (regular, refund) = run_sstore(Fork::Amsterdam, code, 4, U256::zero());
    assert_eq!(
        regular,
        2100 + 10000 + 100,
        "set-then-clear regular at Amsterdam"
    );
    assert_eq!(
        refund, 10000,
        "set-then-clear net refund (full STORAGE_WRITE) must be 10000"
    );
}

#[test]
fn test_sstore_set_then_clear_in_tx_osaka_control() {
    // Pre-Amsterdam: 0->5 cold first change (2100 + 20000), 5->0 warm (100).
    // Net refund = RESTORE_EMPTY_SLOT_COST = 19900 (byte-identical legacy).
    let mut code = sstore_seq(5);
    code.extend_from_slice(&sstore_seq(0));
    let (regular, refund) = run_sstore(Fork::Osaka, code, 4, U256::zero());
    assert_eq!(
        regular,
        2100 + 20000 + 100,
        "set-then-clear regular at Osaka"
    );
    assert_eq!(
        refund, 19900,
        "set-then-clear net refund at Osaka must stay 19900"
    );
}

// ----- Table row: (x, x, 0) clear a slot non-zero at tx start, refund 11616 ---

#[test]
fn test_sstore_clear_original_nonzero_amsterdam() {
    // O=7, C=7, N=0, cold first change: COLD(2100) + STORAGE_WRITE(10000).
    // Refund = STORAGE_CLEAR_REFUND(11616).
    let (regular, refund) = run_sstore(Fork::Amsterdam, sstore_seq(0), 2, U256::from(7u64));
    assert_eq!(regular, 2100 + 10000, "clear-original regular at Amsterdam");
    assert_eq!(
        refund, 11616,
        "clear of tx-start-nonzero slot must refund 11616"
    );
}

#[test]
fn test_sstore_clear_original_nonzero_osaka_control() {
    // Pre-Amsterdam: cold first change MODIFICATION (2100 + 2900), refund 4800.
    let (regular, refund) = run_sstore(Fork::Osaka, sstore_seq(0), 2, U256::from(7u64));
    assert_eq!(regular, 2100 + 2900, "clear-original regular at Osaka");
    assert_eq!(
        refund, 4800,
        "clear-original refund at Osaka must stay 4800"
    );
}

// ----- Table row: (x, y, x) reset-to-original, refund 10000 -----------------

#[test]
fn test_sstore_reset_to_original_amsterdam() {
    // O=7; write 7->9 (cold first change: 2100+10000); write 9->7 (warm: 100).
    // Net regular = 2100 + 10000 + 100 = 12200.
    // Net refund = STORAGE_WRITE = 10000. Per EELS Amsterdam storage.py, restoring a
    // slot to its original value refunds the full STORAGE_WRITE charged on the
    // first-time change; the access component (cold/warm) is charged separately.
    let mut code = sstore_seq(9);
    code.extend_from_slice(&sstore_seq(7));
    let (regular, refund) = run_sstore(Fork::Amsterdam, code, 4, U256::from(7u64));
    assert_eq!(
        regular,
        2100 + 10000 + 100,
        "reset-to-original regular at Amsterdam"
    );
    assert_eq!(
        refund, 10000,
        "reset-to-original net refund (full STORAGE_WRITE) must be 10000"
    );
}

#[test]
fn test_sstore_reset_to_original_osaka_control() {
    // Pre-Amsterdam: 7->9 cold first change (2100 + 2900), 9->7 warm (100).
    // Net refund = RESTORE_SLOT_COST = 2800 (byte-identical legacy).
    let mut code = sstore_seq(9);
    code.extend_from_slice(&sstore_seq(7));
    let (regular, refund) = run_sstore(Fork::Osaka, code, 4, U256::from(7u64));
    assert_eq!(
        regular,
        2100 + 2900 + 100,
        "reset-to-original regular at Osaka"
    );
    assert_eq!(
        refund, 2800,
        "reset-to-original refund at Osaka must stay 2800"
    );
}

// ----- Table row: (x, y, z) dirty-write-again, only warm access ------------

#[test]
fn test_sstore_dirty_write_again_amsterdam() {
    // O=7; write 7->9 (cold first change: 2100+10000); write 9->4 (warm: 100, no surcharge).
    // The second write is "written again" (C != O) so only the warm access is charged.
    let mut code = sstore_seq(9);
    code.extend_from_slice(&sstore_seq(4));
    let (regular, refund) = run_sstore(Fork::Amsterdam, code, 4, U256::from(7u64));
    assert_eq!(
        regular,
        2100 + 10000 + 100,
        "dirty-write-again regular at Amsterdam"
    );
    assert_eq!(refund, 0, "dirty write to a new value yields no refund");
}

#[test]
fn test_sstore_dirty_write_again_osaka_control() {
    // Pre-Amsterdam: 7->9 cold first change (2100 + 2900), 9->4 warm (100), no refund.
    let mut code = sstore_seq(9);
    code.extend_from_slice(&sstore_seq(4));
    let (regular, refund) = run_sstore(Fork::Osaka, code, 4, U256::from(7u64));
    assert_eq!(
        regular,
        2100 + 2900 + 100,
        "dirty-write-again regular at Osaka"
    );
    assert_eq!(refund, 0, "dirty write to a new value yields no refund");
}

// ----- Cross-check: (x, 0, x) clear-then-restore -> net refund 10000 --------

#[test]
fn test_sstore_clear_then_restore_amsterdam() {
    // O=7; write 7->0 (cold first change clear: 2100 + 10000, +11616 clear refund);
    // write 0->7 (warm: 100, -11616 reverse clear, +10000 restore). Net refund = 10000.
    let mut code = sstore_seq(0);
    code.extend_from_slice(&sstore_seq(7));
    let (regular, refund) = run_sstore(Fork::Amsterdam, code, 4, U256::from(7u64));
    assert_eq!(
        regular,
        2100 + 10000 + 100,
        "clear-then-restore regular at Amsterdam"
    );
    assert_eq!(
        refund, 10000,
        "clear-then-restore net refund must be the full STORAGE_WRITE = 10000"
    );
}

#[test]
fn test_sstore_clear_then_restore_osaka_control() {
    // Pre-Amsterdam: 7->0 cold first change clear (2100 + 2900, +4800 clear refund);
    // 0->7 warm (100, -4800 reverse, +2800 restore). Net refund = 2800 (byte-identical).
    let mut code = sstore_seq(0);
    code.extend_from_slice(&sstore_seq(7));
    let (regular, refund) = run_sstore(Fork::Osaka, code, 4, U256::from(7u64));
    assert_eq!(
        regular,
        2100 + 2900 + 100,
        "clear-then-restore regular at Osaka"
    );
    assert_eq!(
        refund, 2800,
        "clear-then-restore net refund at Osaka must stay 2800"
    );
}

// ----- Stipend-sentry boundary -------------------------------------------
//
// EIP-8038 leaves COLD_STORAGE_ACCESS at 2100, below the 2300 EIP-2200
// stipend, so the stipend remains the binding pre-state gate at Amsterdam. An
// SSTORE that trips it must OOG before the slot is marked accessed or recorded
// to the BAL (EIP-7928: "If pre-state validation fails, the target is never
// accessed and must not appear in BAL").

#[test]
fn test_sstore_stipend_sentry_amsterdam_no_bal_read_on_oog() {
    let fork = Fork::Amsterdam;

    // Probe: STOP-only code measures the exact intrinsic gas for this tx shape
    // (a plain CALL to CONTRACT, zero value, no calldata).
    let intrinsic_gas = {
        let env = sstore_env(fork);
        let mut db = sstore_db(vec![0x00], U256::zero());
        let tx = sstore_tx();
        let mut vm = VM::new(
            env,
            &mut db,
            &tx,
            LevmCallTracer::disabled(),
            VMType::L1,
            &NativeCrypto,
            None,
        )
        .expect("VM::new (intrinsic probe)");
        let report = vm.execute().expect("probe execute");
        assert!(report.is_success(), "probe must succeed: {report:?}");
        assert_eq!(report.gas_refunded, 0, "probe must not refund");
        report.gas_used
    };

    // PUSH1 value (3) + PUSH1 SLOT_KEY (3) + SSTORE. Size `gas_limit` so exactly
    // 2000 gas remains when the SSTORE gate runs: below both the 2300 stipend
    // and the Amsterdam cold access cost (2100).
    const REMAINING_AT_SSTORE_GATE: u64 = 2000;
    const PUSH_GAS: u64 = 6;
    let code = sstore_seq(5);
    let gas_limit = intrinsic_gas
        .checked_add(PUSH_GAS)
        .and_then(|g| g.checked_add(REMAINING_AT_SSTORE_GATE))
        .expect("gas_limit overflow");

    // The top-level call frame's gas budget comes from `Environment::gas_limit`,
    // not `Transaction::gas_limit` (only used for cap/floor validation), so it
    // must be trimmed here to land exactly on the boundary under test.
    let mut env = sstore_env(fork);
    env.gas_limit = gas_limit;
    let mut db = sstore_db(code, U256::zero());
    db.enable_bal_recording();
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit,
        to: TxKind::Call(CONTRACT),
        value: U256::zero(),
        data: Bytes::new(),
        access_list: Default::default(),
        ..Default::default()
    });
    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L1,
        &NativeCrypto,
        None,
    )
    .expect("VM::new");
    let report = vm.execute().expect("execute");

    assert_eq!(
        report.result,
        TxResult::Revert(VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas)),
        "cold Amsterdam SSTORE below the stipend must OOG on the pre-state \
         gate: {report:?}"
    );

    let bal = db.take_bal().expect("BAL recording was enabled");
    if let Some(changes) = bal.accounts().iter().find(|a| a.address == CONTRACT) {
        assert!(
            changes.storage_reads.is_empty(),
            "slot must not appear as a BAL read when the op OOGs on the \
             pre-state gate: {changes:?}"
        );
        assert!(
            changes.storage_changes.is_empty(),
            "slot must not appear as a BAL write when the op OOGs on the \
             pre-state gate: {changes:?}"
        );
    }
}

// ===========================================================================
// Phase 3: EIP-8038 behavioral opcode changes
//
//   1. CALL / CALLCODE positive-value upfront cost: 9000 -> 11300 at Amsterdam
//      (`CALL_VALUE_AMSTERDAM`). The 2300 stipend forwarded to the callee
//      (`CALL_POSITIVE_VALUE_STIPEND`) is a SEPARATE code path and is UNCHANGED.
//   2. EXTCODESIZE / EXTCODECOPY: charged an ADDITIONAL WARM_ACCESS (100) on top
//      of their existing access cost at Amsterdam (two DB reads). EXTCODEHASH and
//      BALANCE do NOT get this surcharge.
//   3. SELFDESTRUCT: an additional ACCOUNT_WRITE (9000) of REGULAR gas when a
//      positive balance is sent to an EIP-161-empty account at Amsterdam, in
//      addition to the EIP-8037 state-gas new-account charge.
//
// The numeric values are EIP-8038's own parameter table: CALL_VALUE is
// ACCOUNT_WRITE + CALL_STIPEND = 11300, EXTCODESIZE / EXTCODECOPY pay one extra
// WARM_ACCESS for their second database read, and SELFDESTRUCT pays
// ACCOUNT_WRITE = 9000 in regular gas when it funds an EIP-161-empty account.
// ===========================================================================

// ----- 1. CALL / CALLCODE upfront positive-value cost ----------------------

#[test]
fn test_call_positive_value_selector_amsterdam_is_11300() {
    // EIP-8038: upfront positive-value cost becomes CALL_VALUE_AMSTERDAM (11300).
    assert_eq!(
        gas_cost::call_positive_value_cost(Fork::Amsterdam),
        11300,
        "CALL/CALLCODE upfront positive-value cost at Amsterdam must be 11300"
    );
}

#[test]
fn test_call_positive_value_selector_osaka_control_is_9000() {
    // Byte-identical pre-Amsterdam: upfront positive-value cost stays 9000.
    assert_eq!(
        gas_cost::call_positive_value_cost(Fork::Osaka),
        9000,
        "CALL/CALLCODE upfront positive-value cost at Osaka must stay 9000"
    );
}

/// Recovers the upfront positive-value component of a CALL/CALLCODE gas fn by
/// subtracting the value-zero cost from the value-positive cost with all other
/// inputs (memory, access) held identical. `gas_cost::call` / `callcode` return
/// `(gas_cost, gas_limit)`; the upfront value charge lives in `gas_cost` (`.0`),
/// while the 2300 stipend lives only in the forwarded `gas_limit` (`.1`).
fn call_upfront_value_component(fork: Fork) -> u64 {
    // Warm target, no memory expansion, forward gas_from_stack = 0 so the
    // forwarded `gas_limit` carries ONLY the stipend.
    let warm = false; // address_was_cold = false (warm)
    let gas_left = 1_000_000;
    let with_value = gas_cost::call(0, 0, warm, false, U256::one(), U256::zero(), gas_left, fork)
        .expect("call with value")
        .0;
    let without_value = gas_cost::call(
        0,
        0,
        warm,
        false,
        U256::zero(),
        U256::zero(),
        gas_left,
        fork,
    )
    .expect("call no value")
    .0;
    with_value - without_value
}

fn callcode_upfront_value_component(fork: Fork) -> u64 {
    let warm = false;
    let gas_left = 1_000_000;
    let with_value = gas_cost::callcode(0, 0, warm, U256::one(), U256::zero(), gas_left, fork)
        .expect("callcode with value")
        .0;
    let without_value = gas_cost::callcode(0, 0, warm, U256::zero(), U256::zero(), gas_left, fork)
        .expect("callcode no value")
        .0;
    with_value - without_value
}

#[test]
fn test_call_upfront_value_amsterdam_is_11300() {
    assert_eq!(
        call_upfront_value_component(Fork::Amsterdam),
        11300,
        "CALL upfront value charge at Amsterdam must be 11300"
    );
    assert_eq!(
        callcode_upfront_value_component(Fork::Amsterdam),
        11300,
        "CALLCODE upfront value charge at Amsterdam must be 11300"
    );
}

#[test]
fn test_call_upfront_value_osaka_control_is_9000() {
    assert_eq!(
        call_upfront_value_component(Fork::Osaka),
        9000,
        "CALL upfront value charge at Osaka must stay 9000"
    );
    assert_eq!(
        callcode_upfront_value_component(Fork::Osaka),
        9000,
        "CALLCODE upfront value charge at Osaka must stay 9000"
    );
}

#[test]
fn test_call_stipend_forwarding_unchanged_across_forks() {
    // The 2300 stipend is the EXTRA gas forwarded to the callee on a positive-value
    // call (`gas_limit` minus the requested `gas_from_stack`). It is a SEPARATE
    // code path from the upfront value cost and EIP-8038 leaves it UNCHANGED.
    // With gas_from_stack = 0, the forwarded `gas_limit` equals exactly the stipend.
    for fork in [Fork::Amsterdam, Fork::Osaka] {
        let (_cost, gas_limit) = gas_cost::call(
            0,
            0,
            false,
            false,
            U256::one(),
            U256::zero(),
            1_000_000,
            fork,
        )
        .expect("call");
        assert_eq!(
            gas_limit, 2300,
            "CALL stipend forwarded to callee must stay 2300 at {fork:?}"
        );
        let (_cost, gas_limit) =
            gas_cost::callcode(0, 0, false, U256::one(), U256::zero(), 1_000_000, fork)
                .expect("callcode");
        assert_eq!(
            gas_limit, 2300,
            "CALLCODE stipend forwarded to callee must stay 2300 at {fork:?}"
        );
    }
}

/// Builds a DB with a caller contract whose code is `caller_code` and an
/// optional callee at `CALLEE` whose code is `callee_code`. Both are funded.
fn call_db(caller_code: Vec<u8>, callee_code: Option<Vec<u8>>) -> GeneralizedDatabase {
    let caller = Account::new(
        U256::from(10u64).pow(18.into()),
        Code::from_bytecode(Bytes::from(caller_code), &NativeCrypto),
        1,
        FxHashMap::default(),
    );
    let sender = Account::new(
        U256::from(10u64).pow(18.into()),
        Code::default(),
        0,
        FxHashMap::default(),
    );
    let mut accounts: FxHashMap<Address, Account> = FxHashMap::default();
    accounts.insert(SENDER, sender);
    accounts.insert(CONTRACT, caller);
    if let Some(code) = callee_code {
        let callee = Account::new(
            U256::zero(),
            Code::from_bytecode(Bytes::from(code), &NativeCrypto),
            1,
            FxHashMap::default(),
        );
        accounts.insert(CALLEE, callee);
    }

    let mut db = TestDatabase::new();
    for (addr, acc) in &accounts {
        db.accounts.insert(*addr, acc.clone());
    }
    GeneralizedDatabase::new_with_account_state(Arc::new(db), accounts)
}

/// The callee address used by CALL-family VM tests.
const CALLEE: Address = Address::repeat_byte(0xCA);
/// An EIP-161-empty beneficiary used by SELFDESTRUCT tests (no code, no nonce,
/// no balance — absent from the DB).
const EMPTY_BENEFICIARY: Address = Address::repeat_byte(0xEE);

/// Runs `caller_code` (optionally with a `callee_code` contract at `CALLEE`)
/// through a full VM and returns the finished `ExecutionReport`.
fn run_call(
    fork: Fork,
    caller_code: Vec<u8>,
    callee_code: Option<Vec<u8>>,
) -> ethrex_levm::errors::ExecutionReport {
    let env = sstore_env(fork);
    let mut db = call_db(caller_code, callee_code);
    let tx = sstore_tx();
    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L1,
        &NativeCrypto,
        None,
    )
    .expect("VM::new");
    vm.execute().expect("execute")
}

#[test]
fn test_call_with_value_forwards_stipend_full_vm() {
    // Caller does CALL(gas=0, to=CALLEE, value=1). Because gas_from_stack = 0 and
    // the call carries value, the callee receives ONLY the 2300 stipend. The
    // callee returns its gas-at-entry; the caller (which has plenty of gas) then
    // copies the returndata into memory and SSTOREs it to its own slot 0. Reading
    // CONTRACT's slot 0 yields the gas the callee saw at entry, proving exactly the
    // stipend was forwarded (and that EIP-8038 left the 2300 stipend unchanged).
    //
    // Callee: GAS; PUSH1 0; MSTORE; PUSH1 0x20; PUSH1 0; RETURN.
    // This fits comfortably inside 2300 gas (GAS 2 + 2*PUSH1 6 + MSTORE 3 + mem 3
    // + 2*PUSH1 6 = ~20 gas), so the callee succeeds and the stored value is the
    // entry gas minus the few opcodes before GAS (none) — i.e. <= 2300.
    let callee_code = vec![
        0x5a, // GAS
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN
    ];

    // Caller: CALL(gas=0, addr=CALLEE, value=1, argsOff=0, argsLen=0, retOff=0,
    // retLen=32); then MLOAD(0); then SSTORE to slot 0.
    // Stack order for CALL (top first popped): gas, addr, value, argsOff, argsLen,
    // retOff, retLen. Push in reverse so `gas` ends on top.
    let mut caller_code = vec![
        0x60, 0x20, // PUSH1 32  retLen
        0x60, 0x00, // PUSH1 0   retOff
        0x60, 0x00, // PUSH1 0   argsLen
        0x60, 0x00, // PUSH1 0   argsOff
        0x60, 0x01, // PUSH1 1   value
    ];
    caller_code.push(0x73); // PUSH20 CALLEE
    caller_code.extend_from_slice(CALLEE.as_bytes());
    caller_code.extend_from_slice(&[
        0x60, 0x00, // PUSH1 0   gas
        0xf1, // CALL
        0x50, // POP (call success flag)
        0x60, 0x00, // PUSH1 0
        0x51, // MLOAD (callee's returned gas-at-entry)
        0x60, 0x00, // PUSH1 0   slot key
        0x55, // SSTORE
        0x00, // STOP
    ]);

    for fork in [Fork::Amsterdam, Fork::Osaka] {
        let env = sstore_env(fork);
        let mut db = call_db(caller_code.clone(), Some(callee_code.clone()));
        let tx = sstore_tx();
        let mut vm = VM::new(
            env,
            &mut db,
            &tx,
            LevmCallTracer::disabled(),
            VMType::L1,
            &NativeCrypto,
            None,
        )
        .expect("VM::new");
        let report = vm.execute().expect("execute");
        assert!(
            report.is_success(),
            "{fork:?} call must succeed: {report:?}"
        );
        // Read the caller's stored value (the callee's gas-at-entry) from slot 0.
        let stored = db
            .current_accounts_state
            .get(&CONTRACT)
            .and_then(|acc| acc.storage.get(&H256::zero()).copied())
            .unwrap_or_default();
        assert!(
            stored > U256::zero() && stored <= U256::from(2300u64),
            "{fork:?}: callee must see only the 2300 stipend, saw {stored}"
        );
    }
}

// ----- 2. EXTCODESIZE / EXTCODECOPY extra WARM_ACCESS -----------------------

#[test]
fn test_extcodesize_amsterdam_adds_warm_access() {
    // Warm: legacy warm access (100) + extra WARM_ACCESS (100) = 200.
    assert_eq!(
        gas_cost::extcodesize(false, Fork::Amsterdam).expect("extcodesize"),
        100 + 100,
        "warm EXTCODESIZE at Amsterdam = access(100) + extra(100)"
    );
    // Cold: cold access (3000) + extra WARM_ACCESS (100) = 3100.
    assert_eq!(
        gas_cost::extcodesize(true, Fork::Amsterdam).expect("extcodesize"),
        3000 + 100,
        "cold EXTCODESIZE at Amsterdam = cold access(3000) + extra(100)"
    );
}

#[test]
fn test_extcodesize_osaka_control_no_extra() {
    // Pre-Amsterdam byte-identical: warm 100, cold 2600, no extra.
    assert_eq!(
        gas_cost::extcodesize(false, Fork::Osaka).expect("extcodesize"),
        100,
        "warm EXTCODESIZE at Osaka must stay 100"
    );
    assert_eq!(
        gas_cost::extcodesize(true, Fork::Osaka).expect("extcodesize"),
        2600,
        "cold EXTCODESIZE at Osaka must stay 2600"
    );
}

#[test]
fn test_extcodecopy_amsterdam_adds_warm_access() {
    // size=0, no memory expansion: copy cost is 0. Warm access(100) + extra(100) = 200.
    assert_eq!(
        gas_cost::extcodecopy(0, 0, 0, false, Fork::Amsterdam).expect("extcodecopy"),
        100 + 100,
        "warm EXTCODECOPY at Amsterdam = access(100) + extra(100)"
    );
    // Cold access(3000) + extra(100) = 3100.
    assert_eq!(
        gas_cost::extcodecopy(0, 0, 0, true, Fork::Amsterdam).expect("extcodecopy"),
        3000 + 100,
        "cold EXTCODECOPY at Amsterdam = cold access(3000) + extra(100)"
    );
}

#[test]
fn test_extcodecopy_osaka_control_no_extra() {
    assert_eq!(
        gas_cost::extcodecopy(0, 0, 0, false, Fork::Osaka).expect("extcodecopy"),
        100,
        "warm EXTCODECOPY at Osaka must stay 100"
    );
    assert_eq!(
        gas_cost::extcodecopy(0, 0, 0, true, Fork::Osaka).expect("extcodecopy"),
        2600,
        "cold EXTCODECOPY at Osaka must stay 2600"
    );
}

#[test]
fn test_extcodehash_and_balance_no_warm_access_surcharge_amsterdam() {
    // EIP-8038 explicitly excludes EXTCODEHASH and BALANCE from the extra
    // WARM_ACCESS surcharge: they do a single DB read. Their Amsterdam costs are
    // the plain repriced access (warm 100, cold 3000), with NO extra 100.
    assert_eq!(
        gas_cost::extcodehash(false, Fork::Amsterdam).expect("extcodehash"),
        100,
        "warm EXTCODEHASH at Amsterdam must be 100 (no extra surcharge)"
    );
    assert_eq!(
        gas_cost::extcodehash(true, Fork::Amsterdam).expect("extcodehash"),
        3000,
        "cold EXTCODEHASH at Amsterdam must be 3000 (no extra surcharge)"
    );
    assert_eq!(
        gas_cost::balance(false, Fork::Amsterdam).expect("balance"),
        100,
        "warm BALANCE at Amsterdam must be 100 (no extra surcharge)"
    );
    assert_eq!(
        gas_cost::balance(true, Fork::Amsterdam).expect("balance"),
        3000,
        "cold BALANCE at Amsterdam must be 3000 (no extra surcharge)"
    );
}

#[test]
fn test_extcodesize_full_vm_warm_charges_extra_100() {
    // Full-VM cross-check via probe subtraction: warm the target with EXTCODEHASH
    // first (cold access paid by the EXTCODEHASH), then run EXTCODESIZE warm. The
    // probe runs the identical EXTCODEHASH prefix then STOP. The delta is exactly
    // the warm EXTCODESIZE cost: 200 at Amsterdam (100 access + 100 extra), 100 at
    // Osaka. (PUSH20 + POP costs cancel against the probe since both run them.)
    //
    // Layout: PUSH20 CONTRACT; EXTCODEHASH; POP; [probe: STOP] | [test: PUSH20 CONTRACT; EXTCODESIZE; POP; STOP]
    // EIP-2780 lowers the Amsterdam intrinsic base to 12000, and the calldata
    // floor (EIP-7976) re-anchors on `12000 + recipient_regular_gas + tokens*16`
    // (here: no calldata, distinct cold recipient, value=0 -> 12000 + 3000 =
    // 15000), so a short probe would fall below that floor and report the floor
    // instead of raw regular, breaking the probe subtraction. Prepend the
    // gas-burning prefix so both probe and full clear the floor; it cancels in
    // the subtraction.
    fn prefix() -> Vec<u8> {
        let mut c = burn_prefix();
        c.push(0x73);
        c.extend_from_slice(CONTRACT.as_bytes()); // PUSH20 self (warms it)
        c.push(0x3f); // EXTCODEHASH
        c.push(0x50); // POP
        c
    }
    for (fork, expected) in [(Fork::Amsterdam, 200u64), (Fork::Osaka, 100u64)] {
        let probe = {
            let mut code = prefix();
            code.push(0x00); // STOP
            let report = run_call(fork, code, None);
            assert!(report.is_success(), "{fork:?} probe: {report:?}");
            pre_refund_regular(fork, &report)
        };
        let full = {
            let mut code = prefix();
            code.push(0x73);
            code.extend_from_slice(CONTRACT.as_bytes()); // PUSH20 self (now warm)
            code.push(0x3b); // EXTCODESIZE
            code.push(0x50); // POP
            code.push(0x00); // STOP
            let report = run_call(fork, code, None);
            assert!(report.is_success(), "{fork:?} full: {report:?}");
            pre_refund_regular(fork, &report)
        };
        // Subtract the extra PUSH20(3) + POP(2) that `full` runs beyond `probe`.
        let extcodesize_cost = full - probe - 3 - 2;
        assert_eq!(
            extcodesize_cost, expected,
            "{fork:?}: warm EXTCODESIZE full-VM cost"
        );
    }
}

// ----- 3. SELFDESTRUCT extra ACCOUNT_WRITE ----------------------------------

#[test]
fn test_selfdestruct_amsterdam_adds_account_write_regular() {
    // Positive balance to an EIP-161-empty account at Amsterdam: base(5000) +
    // ACCOUNT_WRITE(9000) of REGULAR gas. (Beneficiary warm -> no cold access.)
    assert_eq!(
        gas_cost::selfdestruct(false, true, U256::one(), Fork::Amsterdam).expect("selfdestruct"),
        5000 + 9000,
        "SELFDESTRUCT to empty w/ value at Amsterdam = base(5000) + ACCOUNT_WRITE(9000)"
    );
    // Zero balance: no surcharge even if target empty.
    assert_eq!(
        gas_cost::selfdestruct(false, true, U256::zero(), Fork::Amsterdam).expect("selfdestruct"),
        5000,
        "SELFDESTRUCT to empty w/ zero value at Amsterdam = base only"
    );
    // Non-empty target with value: no surcharge.
    assert_eq!(
        gas_cost::selfdestruct(false, false, U256::one(), Fork::Amsterdam).expect("selfdestruct"),
        5000,
        "SELFDESTRUCT to non-empty at Amsterdam = base only"
    );
}

#[test]
fn test_selfdestruct_osaka_control_no_account_write() {
    // Pre-Amsterdam byte-identical: positive balance to empty = base(5000) +
    // SELFDESTRUCT_DYNAMIC(25000); no ACCOUNT_WRITE.
    assert_eq!(
        gas_cost::selfdestruct(false, true, U256::one(), Fork::Osaka).expect("selfdestruct"),
        5000 + 25000,
        "SELFDESTRUCT to empty w/ value at Osaka = base(5000) + 25000"
    );
    assert_eq!(
        gas_cost::selfdestruct(false, false, U256::one(), Fork::Osaka).expect("selfdestruct"),
        5000,
        "SELFDESTRUCT to non-empty at Osaka = base only"
    );
}

#[test]
fn test_selfdestruct_full_vm_positive_balance_to_empty() {
    // A contract with a positive balance SELFDESTRUCTs to a cold, EIP-161-empty
    // beneficiary. At Amsterdam this charges base(5000) + cold access(3000, EIP-8038
    // repriced via `cold_account_access_cost`) + ACCOUNT_WRITE(9000) of REGULAR gas,
    // AND a separate state-gas new-account charge (> 0). At Osaka it charges
    // base(5000) + cold access(2600) + 25000 of regular gas, with NO state gas.
    //
    // The caller (CONTRACT) is given a positive balance in `call_db`. Its code is
    // burn_prefix; PUSH20 EMPTY_BENEFICIARY; SELFDESTRUCT.
    //
    // EIP-2780 lowers the Amsterdam intrinsic base to 12000, and the calldata
    // floor (EIP-7976) re-anchors on `12000 + recipient_regular_gas + tokens*16`
    // (here: no calldata, distinct cold recipient, value=0 -> 12000 + 3000 =
    // 15000), so a STOP-only probe would fall below that floor and report the
    // floor instead of raw regular, breaking the probe subtraction. Prepend the
    // gas-burning prefix to BOTH the run and the probe so both clear the floor;
    // the burn cancels in the subtraction.
    let mut code = burn_prefix();
    code.push(0x73);
    code.extend_from_slice(EMPTY_BENEFICIARY.as_bytes());
    code.push(0xff); // SELFDESTRUCT

    // Amsterdam: regular = 5000 + 3000 (cold, EIP-8038) + 9000 = 17000; state gas > 0.
    let report_a = run_call(Fork::Amsterdam, code.clone(), None);
    assert!(report_a.is_success(), "amsterdam: {report_a:?}");
    let regular_a = pre_refund_regular(Fork::Amsterdam, &report_a);
    // Subtract the PUSH20 (3) that precedes SELFDESTRUCT and the intrinsic.
    // Compare against an empty (STOP-only) probe to cancel intrinsic + PUSH.
    let probe_a = {
        let mut c = burn_prefix();
        c.push(0x73);
        c.extend_from_slice(EMPTY_BENEFICIARY.as_bytes());
        c.push(0x00); // STOP
        let r = run_call(Fork::Amsterdam, c, None);
        assert!(r.is_success(), "amsterdam probe: {r:?}");
        pre_refund_regular(Fork::Amsterdam, &r)
    };
    let selfdestruct_regular_a = regular_a - probe_a;
    assert_eq!(
        selfdestruct_regular_a,
        5000 + 3000 + 9000,
        "amsterdam SELFDESTRUCT regular = base + cold(3000) + ACCOUNT_WRITE"
    );
    assert!(
        report_a.state_gas_used > 0,
        "amsterdam SELFDESTRUCT to empty must charge state gas (EIP-8037), saw {}",
        report_a.state_gas_used
    );

    // Osaka control: regular = 5000 + 2600 + 25000; no state gas.
    let report_o = run_call(Fork::Osaka, code.clone(), None);
    assert!(report_o.is_success(), "osaka: {report_o:?}");
    let regular_o = pre_refund_regular(Fork::Osaka, &report_o);
    let probe_o = {
        let mut c = burn_prefix();
        c.push(0x73);
        c.extend_from_slice(EMPTY_BENEFICIARY.as_bytes());
        c.push(0x00); // STOP
        let r = run_call(Fork::Osaka, c, None);
        assert!(r.is_success(), "osaka probe: {r:?}");
        pre_refund_regular(Fork::Osaka, &r)
    };
    let selfdestruct_regular_o = regular_o - probe_o;
    assert_eq!(
        selfdestruct_regular_o,
        5000 + 2600 + 25000,
        "osaka SELFDESTRUCT regular = base + cold + 25000 (no ACCOUNT_WRITE)"
    );
    assert_eq!(
        report_o.state_gas_used, 0,
        "osaka SELFDESTRUCT must not charge state gas"
    );
}
