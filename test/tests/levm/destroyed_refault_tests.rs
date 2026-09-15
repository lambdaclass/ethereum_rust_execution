//! Regression tests for storage reads against `DestroyedModified` accounts that
//! were drained back into `initial_accounts_state` by the streaming executor.
//!
//! The streaming pipeline drains `current_accounts_state` into
//! `initial_accounts_state` every few txs (`get_state_transitions_tx`). A
//! destroyed-and-recreated account is folded back wholesale, keeping its
//! `DestroyedModified` status *and* its committed in-block storage. On the next
//! tx that touches it, `load_account` re-faults it from `initial`. With the
//! info-only clone optimization, `current.storage` starts empty, so an `SLOAD`
//! of a committed slot must still resolve to the committed value, not `0`.

use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    constants::EMPTY_KECCAK_HASH,
    types::{Account, AccountInfo, Code, EIP1559Transaction, Fork, Transaction, TxKind},
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    account::{AccountStatus, LevmAccount},
    db::gen_db::GeneralizedDatabase,
    environment::{EVMConfig, Environment},
    tracing::LevmCallTracer,
    vm::{VM, VMType},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

use super::test_db::TestDatabase;

const ORIGIN: u64 = 0x1000;
const RECIPIENT: u64 = 0xBEEF;
/// Address of the destroyed-and-recreated contract under test.
const TARGET: u64 = 0xDEAD;

/// The slot SLOADed by the later tx and its committed in-block value.
fn slot() -> H256 {
    H256::from_low_u64_be(0x42)
}
fn committed_value() -> U256 {
    U256::from(0x2222u64)
}
/// A different, now-invalid value sitting in the trie/store for the same slot.
/// A `DestroyedModified` account must never surface it.
fn stale_store_value() -> U256 {
    U256::from(0x1111u64)
}

/// Backing store whose `TARGET` account carries the *stale* (pre-destruction)
/// slot value, so any read that reaches the store is distinguishable from the
/// committed in-block value.
fn store_with_stale_slot() -> TestDatabase {
    let mut db = TestDatabase::new();
    let mut storage = FxHashMap::default();
    storage.insert(slot(), stale_store_value());
    db.accounts.insert(
        Address::from_low_u64_be(TARGET),
        Account::new(U256::zero(), Code::default(), 1, storage),
    );
    db
}

/// Only the origin is seeded into the cache so `VM::new` succeeds; the target is
/// injected into `initial_accounts_state` afterwards to model the post-drain state.
fn db_with_origin(store: TestDatabase) -> GeneralizedDatabase {
    let mut accounts: FxHashMap<Address, Account> = FxHashMap::default();
    accounts.insert(
        Address::from_low_u64_be(ORIGIN),
        Account::new(
            U256::from(10u64).pow(18.into()),
            Code::default(),
            0,
            FxHashMap::default(),
        ),
    );
    GeneralizedDatabase::new_with_account_state(Arc::new(store), accounts)
}

fn env(fork: Fork) -> Environment {
    let blob_schedule = EVMConfig::canonical_values(fork);
    Environment {
        origin: Address::from_low_u64_be(ORIGIN),
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

fn dummy_tx() -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to: TxKind::Call(Address::from_low_u64_be(RECIPIENT)),
        value: U256::zero(),
        data: Bytes::new(),
        access_list: Default::default(),
        ..Default::default()
    })
}

/// A `DestroyedModified` account holding only the slots written after recreation,
/// as the per-flush drain-back leaves it in `initial_accounts_state`.
fn destroyed_modified_with(slot: H256, value: U256) -> LevmAccount {
    let mut storage = FxHashMap::default();
    storage.insert(slot, value);
    LevmAccount {
        info: AccountInfo {
            code_hash: *EMPTY_KECCAK_HASH,
            balance: U256::zero(),
            nonce: 1,
        },
        storage,
        // Trie storage was wiped on destruction; only in-block writes are valid.
        has_storage: false,
        status: AccountStatus::DestroyedModified,
        exists: true,
    }
}

/// A later tx SLOADs a slot of a destroyed-and-recreated account that survived a
/// mid-block flush. The committed in-block value must be returned, not `0`.
#[test]
fn sload_after_flush_returns_committed_value_for_destroyed_modified() {
    let mut db = db_with_origin(store_with_stale_slot());
    let tx = dummy_tx();
    let mut vm = VM::new(
        env(Fork::Prague),
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L1,
        &NativeCrypto,
        None,
    )
    .expect("VM::new");

    let target = Address::from_low_u64_be(TARGET);

    // Post-drain state: the destroyed-recreated account lives in `initial` with its
    // committed slot, and was drained out of `current`.
    vm.db
        .initial_accounts_state
        .insert(target, destroyed_modified_with(slot(), committed_value()));
    vm.db.current_accounts_state.remove(&target);

    // Later tx touches the account: `load_account` re-faults it from `initial`.
    vm.db.get_account(target).expect("load target account");

    let value = vm
        .get_storage_value(target, slot())
        .expect("get_storage_value");

    assert_eq!(
        value,
        committed_value(),
        "SLOAD of a committed slot on a re-faulted DestroyedModified account returned \
         the wrong value (got {value:#x}); the DestroyedModified early-return shadowed the \
         committed in-block value held in initial_accounts_state"
    );
}

/// Guard: within the same tx, a destroyed-and-recreated account whose slot was NOT
/// rewritten must read `0`, never the stale pre-destruction value left in `initial`.
/// This is why the `DestroyedModified` early-return must precede the `initial` fallback
/// (the fix full-clones on re-fault rather than reordering these checks).
#[test]
fn sload_unwritten_slot_on_destroyed_modified_reads_zero_not_stale_initial() {
    let mut db = db_with_origin(store_with_stale_slot());
    let tx = dummy_tx();
    let mut vm = VM::new(
        env(Fork::Prague),
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L1,
        &NativeCrypto,
        None,
    )
    .expect("VM::new");

    let target = Address::from_low_u64_be(TARGET);

    // `initial` still holds the pre-destruction committed value for this slot...
    vm.db.initial_accounts_state.insert(
        target,
        destroyed_modified_with(slot(), U256::from(0x3333u64)),
    );
    // ...but `current` is the live destroyed-recreated account with the slot unwritten.
    let mut live = destroyed_modified_with(slot(), U256::zero());
    live.storage.clear();
    vm.db.current_accounts_state.insert(target, live);

    let value = vm
        .get_storage_value(target, slot())
        .expect("get_storage_value");

    assert_eq!(
        value,
        U256::zero(),
        "unwritten slot of a destroyed-and-recreated account must read 0, not the stale \
         pre-destruction value in initial_accounts_state (got {value:#x})"
    );
}
