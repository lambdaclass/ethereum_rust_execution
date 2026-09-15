//! EIP-2780 resource-based intrinsic transaction gas.
//!
//! At Amsterdam the flat 21000 intrinsic base is decomposed into resource-based
//! charges:
//!   - sender base: TX_BASE_COST_AMSTERDAM = 12000
//!   - recipient access:
//!       * self-transfer (sender == to): 0
//!       * contract-creation: CREATE_ACCESS_AMSTERDAM = 12000 regular + new-account state gas
//!       * else: cold_account_access_cost = 3000
//!   - value transfer:
//!       * zero value, self-transfer, or contract-creation: 0
//!       * else: TX_VALUE_COST_AMSTERDAM = 6000
//!
//! These tests assert the intrinsic regular-gas decomposition at Amsterdam, the
//! pre-Amsterdam (Osaka) control (byte-identical 21000-base), parity between
//! `VM::get_intrinsic_gas` and the standalone `intrinsic_gas_dimensions`, and the
//! top-level post-7702 charge for a 7702-delegated recipient.

use bytes::Bytes;
use ethrex_blockchain::vm::StoreVmDatabase;
use ethrex_common::{
    Address, H256, U256,
    constants::EMPTY_TRIE_HASH,
    types::{
        Account, AccountState, BlockHeader, ChainConfig, Code, CodeMetadata, EIP1559Transaction,
        EIP2930Transaction, Fork, LegacyTransaction, Transaction, TxKind,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    EVMConfig, Environment,
    constants::SET_CODE_DELEGATION_BYTES,
    db::{Database, gen_db::GeneralizedDatabase},
    errors::DatabaseError,
    tracing::LevmCallTracer,
    utils::intrinsic_gas_dimensions,
    vm::{VM, VMType},
};
use ethrex_storage::Store;
use ethrex_vm::DynVmDatabase;
use once_cell::sync::OnceCell;
use rustc_hash::FxHashMap;
use std::sync::Arc;

// Resource-based constants under test.
const TX_BASE_COST_AMSTERDAM: u64 = 12000;
const CREATE_ACCESS_AMSTERDAM: u64 = 12000;
const COLD_ACCOUNT_ACCESS_AMSTERDAM: u64 = 3000;
const TX_VALUE_COST_AMSTERDAM: u64 = 6000;
// Pre-Amsterdam base for the Osaka control.
const TX_BASE_COST: u64 = 21000;
const CREATE_BASE_COST: u64 = 32000;

const SENDER: u64 = 0x1000;

// ===========================================================================
// Intrinsic-gas harness (mirrors the eip8037 parity harness).
// ===========================================================================

struct TestDb;

impl Database for TestDb {
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

fn intrinsic_db() -> GeneralizedDatabase {
    let mut accounts: FxHashMap<Address, Account> = FxHashMap::default();
    accounts.insert(
        Address::from_low_u64_be(SENDER),
        Account::new(
            U256::from(10u64).pow(18.into()),
            Code::default(),
            0,
            FxHashMap::default(),
        ),
    );
    GeneralizedDatabase::new_with_account_state(Arc::new(TestDb), accounts)
}

fn intrinsic_env(fork: Fork) -> Environment {
    let blob_schedule = EVMConfig::canonical_values(fork);
    Environment {
        origin: Address::from_low_u64_be(SENDER),
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

/// Returns the `(regular, state)` intrinsic split from `VM::get_intrinsic_gas`,
/// asserting it agrees with the standalone `intrinsic_gas_dimensions` helper.
fn intrinsic_with_parity(fork: Fork, tx: &Transaction) -> (u64, u64) {
    let env = intrinsic_env(fork);
    let sender = env.origin;
    let block_gas_limit = env.block_gas_limit;

    let standalone = intrinsic_gas_dimensions(tx, sender, fork, block_gas_limit)
        .expect("intrinsic_gas_dimensions");

    let mut db = intrinsic_db();
    let vm = VM::new(
        env,
        &mut db,
        tx,
        LevmCallTracer::disabled(),
        VMType::L1,
        &NativeCrypto,
        None,
    )
    .expect("VM::new");
    let intrinsic = vm.get_intrinsic_gas().expect("get_intrinsic_gas");
    let from_vm = (intrinsic.regular, intrinsic.state);

    assert_eq!(
        standalone, from_vm,
        "intrinsic_gas_dimensions and VM::get_intrinsic_gas diverged for fork {fork:?}: \
         standalone={standalone:?}, vm={from_vm:?}"
    );

    from_vm
}

fn call_tx(to: TxKind, value: U256) -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to,
        value,
        data: Bytes::new(),
        access_list: Default::default(),
        ..Default::default()
    })
}

// ===========================================================================
// Acceptance cases — intrinsic regular gas at Amsterdam.
// ===========================================================================

#[test]
fn test_intrinsic_self_transfer_amsterdam() {
    // sender == to: only the sender base, no recipient/value charge.
    let tx = call_tx(
        TxKind::Call(Address::from_low_u64_be(SENDER)),
        U256::from(1u64),
    );
    let (regular, state) = intrinsic_with_parity(Fork::Amsterdam, &tx);
    assert_eq!(regular, TX_BASE_COST_AMSTERDAM, "self-transfer regular gas");
    assert_eq!(state, 0, "self-transfer state gas");
}

#[test]
fn test_intrinsic_zero_value_to_account_amsterdam() {
    // zero value to a distinct account: base + cold access.
    let tx = call_tx(TxKind::Call(Address::from_low_u64_be(0xBEEF)), U256::zero());
    let (regular, state) = intrinsic_with_parity(Fork::Amsterdam, &tx);
    assert_eq!(
        regular,
        TX_BASE_COST_AMSTERDAM + COLD_ACCOUNT_ACCESS_AMSTERDAM,
        "zero-value call regular gas (12000 + 3000)"
    );
    assert_eq!(state, 0, "zero-value call state gas");
}

#[test]
fn test_intrinsic_eth_transfer_to_existing_eoa_amsterdam() {
    // non-zero value to a distinct account: base + cold access + value cost.
    let tx = call_tx(
        TxKind::Call(Address::from_low_u64_be(0xBEEF)),
        U256::from(1u64),
    );
    let (regular, state) = intrinsic_with_parity(Fork::Amsterdam, &tx);
    assert_eq!(
        regular,
        TX_BASE_COST_AMSTERDAM + COLD_ACCOUNT_ACCESS_AMSTERDAM + TX_VALUE_COST_AMSTERDAM,
        "ETH transfer regular gas (12000 + 3000 + 6000 = 21000)"
    );
    assert_eq!(
        regular, 21000,
        "ETH transfer regular gas must equal the legacy 21000 base"
    );
    assert_eq!(state, 0, "ETH transfer state gas");
}

#[test]
fn test_intrinsic_create_zero_value_amsterdam() {
    // contract-creation, value=0: base + CREATE_ACCESS. The NEW_ACCOUNT state gas is
    // no longer part of the intrinsic (Task 4.1): it is charged IN-REGION by
    // `prepare_execution` (EELS `prepare_dispatch` create branch), conditioned on
    // `get_pre_state_account(created_addr) == EMPTY_ACCOUNT`, not unconditionally at
    // intrinsic time.
    let tx = call_tx(TxKind::Create, U256::zero());
    let (regular, state) = intrinsic_with_parity(Fork::Amsterdam, &tx);
    assert_eq!(
        regular,
        TX_BASE_COST_AMSTERDAM + CREATE_ACCESS_AMSTERDAM,
        "create value=0 regular gas (12000 + 12000 = 24000)"
    );
    assert_eq!(regular, 24000, "create value=0 regular gas must be 24000");
    assert_eq!(
        state, 0,
        "create intrinsic state gas is 0 (NEW_ACCOUNT moved in-region)"
    );
}

#[test]
fn test_intrinsic_create_nonzero_value_amsterdam() {
    // contract-creation, value>0: base + CREATE_ACCESS. No value charge — the recipient
    // balance write is already covered by CREATE_ACCESS.
    // As above, the NEW_ACCOUNT state gas is charged in-region, not at intrinsic time.
    let tx = call_tx(TxKind::Create, U256::from(1u64));
    let (regular, state) = intrinsic_with_parity(Fork::Amsterdam, &tx);
    assert_eq!(
        regular,
        TX_BASE_COST_AMSTERDAM + CREATE_ACCESS_AMSTERDAM,
        "create value>0 regular gas (12000 + 12000 = 24000)"
    );
    assert_eq!(regular, 24000, "create value>0 regular gas must be 24000");
    assert_eq!(
        state, 0,
        "create intrinsic state gas is 0 (NEW_ACCOUNT moved in-region)"
    );
}

// ===========================================================================
// Pre-Amsterdam (Osaka) control: byte-identical 21000-base decomposition.
// ===========================================================================

#[test]
fn test_intrinsic_osaka_control_transfer() {
    // Osaka: flat 21000 base, no resource-based decomposition.
    let tx = call_tx(
        TxKind::Call(Address::from_low_u64_be(0xBEEF)),
        U256::from(1u64),
    );
    let (regular, state) = intrinsic_with_parity(Fork::Osaka, &tx);
    assert_eq!(regular, TX_BASE_COST, "Osaka transfer regular gas (21000)");
    assert_eq!(state, 0, "Osaka state gas must be 0");
}

#[test]
fn test_intrinsic_osaka_control_self_transfer() {
    // Osaka has no self-transfer rule: still the flat 21000 base.
    let tx = call_tx(
        TxKind::Call(Address::from_low_u64_be(SENDER)),
        U256::from(1u64),
    );
    let (regular, state) = intrinsic_with_parity(Fork::Osaka, &tx);
    assert_eq!(
        regular, TX_BASE_COST,
        "Osaka self-transfer regular gas (21000)"
    );
    assert_eq!(state, 0, "Osaka state gas must be 0");
}

#[test]
fn test_intrinsic_osaka_control_create() {
    // Osaka: 21000 base + 32000 CREATE_BASE_COST, no state gas.
    let tx = call_tx(TxKind::Create, U256::zero());
    let (regular, state) = intrinsic_with_parity(Fork::Osaka, &tx);
    assert_eq!(
        regular,
        TX_BASE_COST + CREATE_BASE_COST,
        "Osaka create regular gas (21000 + 32000 = 53000)"
    );
    assert_eq!(state, 0, "Osaka create state gas must be 0");
}

// ===========================================================================
// Top-level post-7702 charge: no-transfer to a 7702-delegated recipient.
// ===========================================================================

/// Creates EIP-7702 delegation bytecode: 0xef0100 || address
fn create_delegation_code(target: Address) -> Bytes {
    let mut code = SET_CODE_DELEGATION_BYTES.to_vec();
    code.extend_from_slice(target.as_bytes());
    Bytes::from(code)
}

fn store_db(accounts: FxHashMap<Address, Account>) -> GeneralizedDatabase {
    let in_memory_db = Store::new("", ethrex_storage::EngineType::InMemory).unwrap();
    let header = BlockHeader {
        state_root: *EMPTY_TRIE_HASH,
        ..Default::default()
    };
    let store: DynVmDatabase = Box::new(StoreVmDatabase::new(in_memory_db, header).unwrap());
    GeneralizedDatabase::new_with_account_state(Arc::new(store), accounts)
}

fn amsterdam_env(sender: Address, gas_limit: u64) -> Environment {
    Environment {
        origin: sender,
        gas_limit,
        gas_price: U256::from(1),
        block_gas_limit: u64::MAX,
        config: EVMConfig::new(
            Fork::Amsterdam,
            EVMConfig::canonical_values(Fork::Amsterdam),
        ),
        ..Default::default()
    }
}

fn legacy_call(nonce: u64, gas: u64, to: Address, value: U256) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        nonce,
        gas_price: U256::from(1),
        gas,
        to: TxKind::Call(to),
        value,
        data: Bytes::new(),
        v: U256::zero(),
        r: U256::zero(),
        s: U256::zero(),
        inner_hash: OnceCell::new(),
        sender_cache: OnceCell::new(),
    })
}

/// Gas-burning bytecode: MLOAD at offset 0x10000 forces memory expansion to
/// 65568 bytes (~14347 gas), then POP/STOP. Used so raw regular consumption
/// clears the EIP-7623 calldata floor (21000) in both the delegated and the
/// plain-contract control, exposing the +3000 top-level delegation charge that
/// would otherwise be masked by the floor.
fn gas_burn_code() -> Bytes {
    Bytes::from(vec![
        0x62, 0x01, 0x00, 0x00, // PUSH3 0x010000 (offset 65536)
        0x51, // MLOAD
        0x50, // POP
        0x00, // STOP
    ])
}

fn run_amsterdam_call(recipient: Address, accounts: FxHashMap<Address, Account>) -> u64 {
    let sender = Address::from_low_u64_be(0x100);
    let mut db = store_db(accounts);
    let gas_limit = 1_000_000u64;
    let env = amsterdam_env(sender, gas_limit);
    let tx = legacy_call(0, gas_limit, recipient, U256::zero());

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

    let result = vm.execute().expect("execution");
    assert!(result.is_success(), "call should succeed");
    result.gas_used
}

fn sender_account() -> (Address, Account) {
    (
        Address::from_low_u64_be(0x100),
        Account {
            info: ethrex_common::types::AccountInfo {
                balance: U256::from(10u64).pow(18.into()),
                nonce: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

fn code_account(code: Bytes) -> Account {
    let code = Code::from_bytecode(code, &NativeCrypto);
    Account {
        info: ethrex_common::types::AccountInfo {
            code_hash: code.hash,
            ..Default::default()
        },
        code,
        ..Default::default()
    }
}

#[test]
fn test_no_transfer_to_7702_delegated_amsterdam() {
    // A zero-value call to a 7702-delegated recipient pays:
    //   intrinsic: 12000 base + 3000 cold access (distinct, value=0) = 15000
    //   top-level: + 3000 cold access for the delegation = 18000 total regular.
    //
    // The EIP-7976 calldata floor (`12000 + recipient_regular_gas + tokens*16`;
    // here: no calldata, distinct cold recipient, value=0 -> 12000 + 3000 =
    // 15000) masks the raw 18000 at the receipt level, so we isolate the +3000
    // top-level delegation charge by differencing two executions that run
    // IDENTICAL target code:
    //   * recipient A: 7702-delegated to target B (runs B's code via delegation)
    //   * recipient C: a plain contract carrying the same code as B
    // The gas-burning target pushes raw consumption above the floor in both, so
    // the receipt reflects raw consumption and the delta is exactly the 3000
    // top-level delegation charge.
    let delegated_account = Address::from_low_u64_be(0x200);
    let target_account = Address::from_low_u64_be(0x300);
    let plain_contract = Address::from_low_u64_be(0x400);

    // Delegated path.
    let mut delegated_accounts = FxHashMap::default();
    let (sender_addr, sender_acc) = sender_account();
    delegated_accounts.insert(sender_addr, sender_acc);
    delegated_accounts.insert(
        delegated_account,
        code_account(create_delegation_code(target_account)),
    );
    delegated_accounts.insert(target_account, code_account(gas_burn_code()));
    let delegated_gas = run_amsterdam_call(delegated_account, delegated_accounts);

    // Plain-contract control (same executed bytecode, no delegation).
    let mut plain_accounts = FxHashMap::default();
    let (sender_addr, sender_acc) = sender_account();
    plain_accounts.insert(sender_addr, sender_acc);
    plain_accounts.insert(plain_contract, code_account(gas_burn_code()));
    let plain_gas = run_amsterdam_call(plain_contract, plain_accounts);

    // Both clear the EIP-7976 floor (15000, see above), so the receipt
    // reflects raw consumption. The >21000 bound below is a conservative
    // margin (the legacy pre-Amsterdam flat base), well above the actual
    // 15000 floor, chosen so this assertion stays robust to floor-formula
    // changes.
    assert!(
        delegated_gas > 21000 && plain_gas > 21000,
        "both executions must clear the 21000 floor (delegated={delegated_gas}, plain={plain_gas})"
    );

    // The delta is the EIP-2780 top-level delegation charge: COLD access (3000).
    assert_eq!(
        delegated_gas - plain_gas,
        COLD_ACCOUNT_ACCESS_AMSTERDAM,
        "7702-delegated recipient must pay an extra 3000 top-level cold access"
    );

    // The plain-contract raw regular is 12000 base + 3000 cold access + exec;
    // the delegated raw regular adds the 3000 top-level charge. So the composed
    // intrinsic+top-level regular for the delegated case is 18000 + exec_gas,
    // i.e. exactly 3000 above the plain case's 15000 + exec_gas.
    let exec_gas = plain_gas - (TX_BASE_COST_AMSTERDAM + COLD_ACCOUNT_ACCESS_AMSTERDAM);
    assert_eq!(
        delegated_gas,
        18000 + exec_gas,
        "delegated regular gas must be 12000 + 2x3000 + exec_gas"
    );
}

/// Access-list-bearing (EIP-2930) call, so a warmed delegation target can be tested.
fn access_list_call(
    nonce: u64,
    gas: u64,
    to: Address,
    value: U256,
    access_list: Vec<(Address, Vec<H256>)>,
) -> Transaction {
    Transaction::EIP2930Transaction(EIP2930Transaction {
        chain_id: 1,
        nonce,
        gas_price: U256::from(1),
        gas_limit: gas,
        to: TxKind::Call(to),
        value,
        data: Bytes::new(),
        access_list,
        ..Default::default()
    })
}

fn run_amsterdam_call_al(
    recipient: Address,
    accounts: FxHashMap<Address, Account>,
    access_list: Vec<(Address, Vec<H256>)>,
) -> u64 {
    let sender = Address::from_low_u64_be(0x100);
    let mut db = store_db(accounts);
    let gas_limit = 1_000_000u64;
    let env = amsterdam_env(sender, gas_limit);
    let tx = access_list_call(0, gas_limit, recipient, U256::zero(), access_list);

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

    let result = vm.execute().expect("execution");
    assert!(result.is_success(), "call should succeed");
    result.gas_used
}

#[test]
fn test_no_transfer_to_7702_delegated_warm_amsterdam() {
    // Same as `test_no_transfer_to_7702_delegated_amsterdam`, but the delegation
    // TARGET is pre-warmed via the tx access list, so the in-region
    // `prepare_dispatch` delegation-resolve charges WARM_ACCESS (100) instead of
    // COLD (3000) — EELS `prepare_dispatch` delegation branch. Differencing against a
    // plain-contract control that carries the IDENTICAL access list cancels the
    // access-list intrinsic cost, isolating the +100 warm delegation-resolve charge.
    const WARM_ACCESS: u64 = 100;
    let delegated_account = Address::from_low_u64_be(0x200);
    let target_account = Address::from_low_u64_be(0x300);
    let plain_contract = Address::from_low_u64_be(0x400);
    // Warm the delegation target at tx start.
    let access_list = vec![(target_account, Vec::<H256>::new())];

    // Delegated path (target warmed by the access list).
    let mut delegated_accounts = FxHashMap::default();
    let (sender_addr, sender_acc) = sender_account();
    delegated_accounts.insert(sender_addr, sender_acc);
    delegated_accounts.insert(
        delegated_account,
        code_account(create_delegation_code(target_account)),
    );
    delegated_accounts.insert(target_account, code_account(gas_burn_code()));
    let delegated_gas =
        run_amsterdam_call_al(delegated_account, delegated_accounts, access_list.clone());

    // Plain-contract control (same executed bytecode + same access list, no delegation).
    let mut plain_accounts = FxHashMap::default();
    let (sender_addr, sender_acc) = sender_account();
    plain_accounts.insert(sender_addr, sender_acc);
    plain_accounts.insert(plain_contract, code_account(gas_burn_code()));
    let plain_gas = run_amsterdam_call_al(plain_contract, plain_accounts, access_list);

    // Delta is the warm delegation-resolve charge only (access-list cost cancels).
    assert_eq!(
        delegated_gas - plain_gas,
        WARM_ACCESS,
        "7702-delegated recipient with a warmed target must pay only +100 warm access"
    );
}
