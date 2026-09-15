//! Tests for EIP-8246: Remove SELFDESTRUCT Burn
//!
//! EIP-8246 (Amsterdam+): When SELFDESTRUCT executes in the same transaction the contract was
//! created AND the beneficiary == executing account, balance is no longer burned. At tx
//! finalization, selfdestruct-marked accounts have their nonce zeroed, code cleared, and storage
//! cleared, but balance is preserved. If the resulting balance is zero the account is removed via
//! EIP-161. Pre-Amsterdam (Cancun/EIP-6780) behavior is byte-for-byte preserved.

use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    constants::{EMPTY_KECCAK_HASH, EMPTY_TRIE_HASH, SYSTEM_ADDRESS},
    evm::calculate_create_address,
    types::{
        Account, AccountState, ChainConfig, Code, CodeMetadata, EIP1559Transaction, Fork, Log,
        Transaction, TxKind,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    constants::{BURN_EVENT_TOPIC, TRANSFER_EVENT_TOPIC},
    db::{Database, gen_db::GeneralizedDatabase},
    environment::{EVMConfig, Environment},
    errors::{DatabaseError, ExecutionReport},
    tracing::LevmCallTracer,
    vm::{VM, VMType},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

// ==================== Test Database ====================

struct TestDb {
    accounts: FxHashMap<Address, Account>,
}

impl TestDb {
    fn new() -> Self {
        Self {
            accounts: FxHashMap::default(),
        }
    }
}

impl Database for TestDb {
    fn get_account_state(&self, address: Address) -> Result<AccountState, DatabaseError> {
        Ok(self
            .accounts
            .get(&address)
            .map(|acc| AccountState {
                nonce: acc.info.nonce,
                balance: acc.info.balance,
                storage_root: *EMPTY_TRIE_HASH,
                code_hash: acc.info.code_hash,
            })
            .unwrap_or_default())
    }

    fn get_storage_value(&self, address: Address, key: H256) -> Result<U256, DatabaseError> {
        Ok(self
            .accounts
            .get(&address)
            .and_then(|acc| acc.storage.get(&key).copied())
            .unwrap_or_default())
    }

    fn get_block_hash(&self, _block_number: u64) -> Result<H256, DatabaseError> {
        Ok(H256::zero())
    }

    fn get_chain_config(&self) -> Result<ChainConfig, DatabaseError> {
        Ok(ChainConfig::default())
    }

    fn get_account_code(&self, code_hash: H256) -> Result<Code, DatabaseError> {
        for acc in self.accounts.values() {
            if acc.info.code_hash == code_hash {
                return Ok(acc.code.clone());
            }
        }
        Ok(Code::default())
    }

    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, DatabaseError> {
        for acc in self.accounts.values() {
            if acc.info.code_hash == code_hash {
                return Ok(CodeMetadata {
                    length: acc.code.len() as u64,
                });
            }
        }
        Ok(CodeMetadata { length: 0 })
    }
}

// ==================== Constants ====================

const DEFAULT_BALANCE: u64 = 10_000_000_000;
const GAS_LIMIT: u64 = 1_000_000;

const SENDER: u64 = 0x1000;
const FACTORY: u64 = 0x3000;
const BENEFICIARY: u64 = 0x4000;

// ==================== Account builders ====================

fn eoa(balance: U256) -> Account {
    Account::new(balance, Code::default(), 0, FxHashMap::default())
}

fn contract_funded(balance: U256, code: Bytes, nonce: u64) -> Account {
    Account::new(
        balance,
        Code::from_bytecode(code, &NativeCrypto),
        nonce,
        FxHashMap::default(),
    )
}

// ==================== Bytecode helpers ====================

/// PUSH20 beneficiary, SELFDESTRUCT
fn selfdestruct_bytecode(beneficiary: Address) -> Bytes {
    let mut code = Vec::new();
    code.push(0x73); // PUSH20
    code.extend_from_slice(beneficiary.as_bytes());
    code.push(0xff); // SELFDESTRUCT
    Bytes::from(code)
}

/// Init code that immediately SELFDESTRUCTs to the given beneficiary.
fn selfdestruct_init_code(beneficiary: Address) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0x73); // PUSH20
    code.extend_from_slice(beneficiary.as_bytes());
    code.push(0xff); // SELFDESTRUCT
    code
}

/// Factory bytecode: store init_code, CREATE with value, STOP.
fn create_with_value_bytecode(init_code: &[u8], value: U256) -> Bytes {
    let mut bytecode = Vec::new();
    for (i, byte) in init_code.iter().enumerate() {
        bytecode.extend_from_slice(&[0x60, *byte, 0x60, i as u8, 0x53]); // MSTORE8
    }
    bytecode.extend_from_slice(&[0x60, init_code.len() as u8, 0x60, 0x00]); // size, offset
    bytecode.push(0x7f); // PUSH32 value
    bytecode.extend_from_slice(&value.to_big_endian());
    bytecode.push(0xf0); // CREATE
    bytecode.push(0x50); // POP
    bytecode.push(0x00); // STOP
    Bytes::from(bytecode)
}

/// Factory bytecode: CREATE child, store address, CALL child with value, STOP.
fn create_then_call_bytecode(init_code: &[u8], create_value: U256, call_value: U256) -> Bytes {
    let mut bytecode = Vec::new();

    // Store init_code in memory byte by byte
    for (i, byte) in init_code.iter().enumerate() {
        bytecode.extend_from_slice(&[0x60, *byte, 0x60, i as u8, 0x53]);
    }

    // CREATE
    bytecode.extend_from_slice(&[0x60, init_code.len() as u8, 0x60, 0x00]); // size, offset
    bytecode.push(0x7f); // PUSH32 create_value
    bytecode.extend_from_slice(&create_value.to_big_endian());
    bytecode.push(0xf0); // CREATE — child address on stack

    // Store address at memory offset 200
    bytecode.extend_from_slice(&[0x60, 200, 0x52]); // MSTORE

    // CALL child with call_value
    bytecode.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00]); // ret/args
    bytecode.push(0x7f); // PUSH32 call_value
    bytecode.extend_from_slice(&call_value.to_big_endian());
    bytecode.extend_from_slice(&[0x60, 200, 0x51]); // MLOAD address
    bytecode.push(0x5a); // GAS
    bytecode.push(0xf1); // CALL
    bytecode.push(0x50); // POP
    bytecode.push(0x00); // STOP

    Bytes::from(bytecode)
}

// ==================== Execution harness ====================

/// Execute a transaction calling `to` on the given fork, returning the `ExecutionReport` and the
/// modified database so callers can inspect post-execution account state.
fn execute_call(
    fork: Fork,
    accounts: Vec<(Address, Account)>,
    sender: Address,
    to: Address,
    value: U256,
) -> (ExecutionReport, GeneralizedDatabase) {
    let test_db = TestDb::new();
    let accounts_map: FxHashMap<Address, Account> = accounts.into_iter().collect();
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts_map);

    let blob_schedule = EVMConfig::canonical_values(fork);
    let env = Environment {
        origin: sender,
        gas_limit: GAS_LIMIT,
        config: EVMConfig::new(fork, blob_schedule),
        block_number: 1,
        coinbase: Address::from_low_u64_be(0xCCC),
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
        block_gas_limit: GAS_LIMIT * 2,
        is_privileged: false,
        fee_token: None,
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    };

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(to),
        value,
        data: Bytes::new(),
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: 1000,
        max_priority_fee_per_gas: 1,
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
    .unwrap();

    let report = vm.execute().unwrap();
    (report, db)
}

// ==================== Log assertion helpers ====================

fn assert_transfer_log(log: &Log, from: Address, to: Address, value: U256) {
    assert_eq!(
        log.address, SYSTEM_ADDRESS,
        "log address must be SYSTEM_ADDRESS"
    );
    assert_eq!(log.topics.len(), 3, "Transfer log must have 3 topics");
    assert_eq!(
        log.topics[0], TRANSFER_EVENT_TOPIC,
        "first topic must be Transfer"
    );

    let mut from_bytes = [0u8; 32];
    from_bytes[12..].copy_from_slice(from.as_bytes());
    assert_eq!(
        log.topics[1],
        H256::from(from_bytes),
        "second topic must be from-address"
    );

    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(to.as_bytes());
    assert_eq!(
        log.topics[2],
        H256::from(to_bytes),
        "third topic must be to-address"
    );

    assert_eq!(
        U256::from_big_endian(&log.data),
        value,
        "data must encode value"
    );
}

fn assert_no_burn_log(logs: &[Log]) {
    for log in logs {
        assert_ne!(
            log.topics.first().copied().unwrap_or_default(),
            BURN_EVENT_TOPIC,
            "found unexpected Burn log: {log:?}"
        );
    }
}

// ==================== Tests ====================

/// EIP-8246 (Amsterdam+): same-tx create-then-selfdestruct to self preserves balance.
/// The account must have nonce=0, code=empty, balance unchanged, and not be removed.
/// `create_would_collide()` must be false (no nonce/code/storage).
#[test]
fn same_tx_create_selfdestruct_to_self_preserves_balance_amsterdam() {
    let sender = Address::from_low_u64_be(SENDER);
    let factory = Address::from_low_u64_be(FACTORY);
    let factory_nonce = 1u64;
    let child = calculate_create_address(factory, factory_nonce);
    let create_value = U256::from(5000);

    // Init code: the child selfdestructs to itself
    let init_code = selfdestruct_init_code(child);

    let (report, mut db) = execute_call(
        Fork::Amsterdam,
        vec![
            (sender, eoa(U256::from(DEFAULT_BALANCE))),
            (
                factory,
                contract_funded(
                    U256::from(100_000),
                    create_with_value_bytecode(&init_code, create_value),
                    factory_nonce,
                ),
            ),
        ],
        sender,
        factory,
        U256::zero(),
    );

    assert!(report.is_success(), "transaction must succeed");

    // EIP-8246: balance is preserved (not burned)
    let child_account = db
        .get_account(child)
        .expect("child account must exist in DB");
    assert_eq!(
        child_account.info.balance, create_value,
        "child balance must be preserved (not burned) under EIP-8246"
    );

    // Nonce must be 0 (cleared by selfdestruct finalization)
    assert_eq!(
        child_account.info.nonce, 0,
        "child nonce must be 0 after selfdestruct"
    );

    // Code hash must be EMPTY_KECCAK_HASH (code cleared)
    assert_eq!(
        child_account.info.code_hash, *EMPTY_KECCAK_HASH,
        "child code must be cleared after selfdestruct"
    );

    // Storage must be cleared
    assert!(
        child_account.storage.is_empty(),
        "child storage must be empty after selfdestruct"
    );
    assert!(
        !child_account.has_storage,
        "has_storage must be false after selfdestruct"
    );

    // create_would_collide must be false: nonce=0, code=empty, no storage
    assert!(
        !child_account.create_would_collide(),
        "create_would_collide must be false: no nonce, code, or storage remains"
    );

    // No burn log
    assert_no_burn_log(&report.logs);
}

/// Pre-Amsterdam (Cancun/EIP-6780): same-tx selfdestruct-to-self burns the balance.
/// This verifies backward compatibility with pre-EIP-8246 behavior.
#[test]
fn same_tx_create_selfdestruct_to_self_burns_pre_amsterdam() {
    let sender = Address::from_low_u64_be(SENDER);
    let factory = Address::from_low_u64_be(FACTORY);
    let factory_nonce = 1u64;
    let child = calculate_create_address(factory, factory_nonce);
    let create_value = U256::from(5000);

    let init_code = selfdestruct_init_code(child);

    let (report, mut db) = execute_call(
        Fork::Cancun,
        vec![
            (sender, eoa(U256::from(DEFAULT_BALANCE))),
            (
                factory,
                contract_funded(
                    U256::from(100_000),
                    create_with_value_bytecode(&init_code, create_value),
                    factory_nonce,
                ),
            ),
        ],
        sender,
        factory,
        U256::zero(),
    );

    assert!(report.is_success(), "transaction must succeed");

    // Pre-Amsterdam (EIP-6780): balance is zeroed (burned)
    let child_account = db.get_account(child).expect("child account exists");
    assert_eq!(
        child_account.info.balance,
        U256::zero(),
        "child balance must be zero (burned) under pre-Amsterdam EIP-6780"
    );
}

/// EIP-8246 (Amsterdam+): same-tx selfdestruct to OTHER address then receive value.
/// The value received after selfdestruct is KEPT; nonce=0, code=empty.
#[test]
fn same_tx_selfdestruct_to_other_then_call_value_back_amsterdam() {
    let sender = Address::from_low_u64_be(SENDER);
    let factory = Address::from_low_u64_be(FACTORY);
    let beneficiary = Address::from_low_u64_be(BENEFICIARY);
    let factory_nonce = 1u64;
    let child = calculate_create_address(factory, factory_nonce);

    let create_value = U256::from(1000);
    let call_back_value = U256::from(500);

    // Init code: child selfdestructs to beneficiary (different address → balance transferred)
    let init_code = selfdestruct_init_code(beneficiary);

    // Factory: CREATE child with 1000, then CALL child with 500 (child has 0 balance at this point
    // because it transferred to beneficiary, but receives 500 from the CALL)
    let factory_code = create_then_call_bytecode(&init_code, create_value, call_back_value);

    let (report, mut db) = execute_call(
        Fork::Amsterdam,
        vec![
            (sender, eoa(U256::from(DEFAULT_BALANCE))),
            (
                factory,
                contract_funded(U256::from(200_000), factory_code, factory_nonce),
            ),
            (beneficiary, eoa(U256::zero())),
        ],
        sender,
        factory,
        U256::zero(),
    );

    assert!(report.is_success(), "transaction must succeed");

    // Child received 500 after selfdestruct: EIP-8246 preserves it
    let child_account = db.get_account(child).expect("child account must exist");
    assert_eq!(
        child_account.info.balance, call_back_value,
        "child must retain the value received after selfdestruct under EIP-8246"
    );

    // Nonce must be 0
    assert_eq!(child_account.info.nonce, 0, "child nonce must be 0");

    // Code cleared
    assert_eq!(
        child_account.info.code_hash, *EMPTY_KECCAK_HASH,
        "child code must be cleared"
    );

    // No burn log emitted
    assert_no_burn_log(&report.logs);
}

/// EIP-8246 (Amsterdam+): same-tx selfdestruct-to-self with zero balance → account deleted (EIP-161).
#[test]
fn same_tx_selfdestruct_zero_balance_account_deleted_amsterdam() {
    let sender = Address::from_low_u64_be(SENDER);
    let factory = Address::from_low_u64_be(FACTORY);
    let factory_nonce = 1u64;
    let child = calculate_create_address(factory, factory_nonce);

    // CREATE with 0 value so child has zero balance when it selfdestructs
    let create_value = U256::zero();
    let init_code = selfdestruct_init_code(child);

    let (report, mut db) = execute_call(
        Fork::Amsterdam,
        vec![
            (sender, eoa(U256::from(DEFAULT_BALANCE))),
            (
                factory,
                contract_funded(
                    U256::from(100_000),
                    create_with_value_bytecode(&init_code, create_value),
                    factory_nonce,
                ),
            ),
        ],
        sender,
        factory,
        U256::zero(),
    );

    assert!(report.is_success(), "transaction must succeed");

    // EIP-161: zero final balance → account removed
    let child_account = db.get_account(child).expect("get_account should not error");
    // The account is either empty (all-zero fields) or removed; either way balance must be zero.
    assert_eq!(
        child_account.info.balance,
        U256::zero(),
        "zero-balance account must have zero balance"
    );

    // Verify via get_state_transitions that 'removed' is set (EIP-161 deletion)
    let updates = db
        .get_state_transitions()
        .expect("get_state_transitions must succeed");
    // The child was created and destroyed within this same tx, so it never existed
    // in the pre-block trie. With a zero final balance it ends empty, so the correct
    // outcome is that it is NOT persisted as a live account: either no update is
    // emitted at all, or an update with `removed == true`. It must never appear as a
    // live (non-removed) account.
    let child_update = updates.iter().find(|u| u.address == child);
    assert!(
        child_update.is_none_or(|u| u.removed),
        "zero-balance selfdestruct account must not persist as a live account (got {child_update:?})"
    );
}

/// EIP-8246 (Amsterdam+): selfdestruct-to-self emits NO burn log.
#[test]
fn selfdestruct_to_self_no_burn_log_amsterdam() {
    let sender = Address::from_low_u64_be(SENDER);
    let factory = Address::from_low_u64_be(FACTORY);
    let factory_nonce = 1u64;
    let child = calculate_create_address(factory, factory_nonce);
    let create_value = U256::from(1000);

    let init_code = selfdestruct_init_code(child);

    let (report, _db) = execute_call(
        Fork::Amsterdam,
        vec![
            (sender, eoa(U256::from(DEFAULT_BALANCE))),
            (
                factory,
                contract_funded(
                    U256::from(100_000),
                    create_with_value_bytecode(&init_code, create_value),
                    factory_nonce,
                ),
            ),
        ],
        sender,
        factory,
        U256::zero(),
    );

    assert!(report.is_success(), "transaction must succeed");
    assert_no_burn_log(&report.logs);

    // The only log should be the CREATE Transfer (factory → child)
    assert_eq!(
        report.logs.len(),
        1,
        "only the CREATE transfer log expected"
    );
    assert_eq!(
        report.logs[0].topics[0], TRANSFER_EVENT_TOPIC,
        "log must be Transfer"
    );
}

/// EIP-8246 (Amsterdam+): selfdestruct to a DIFFERENT address emits one EIP-7708 Transfer log.
/// This is identical to Cancun behavior for the transfer log itself.
#[test]
fn selfdestruct_to_other_emits_transfer_log_amsterdam() {
    let sender = Address::from_low_u64_be(SENDER);
    let factory = Address::from_low_u64_be(FACTORY);
    let beneficiary = Address::from_low_u64_be(BENEFICIARY);
    let factory_nonce = 1u64;
    let child = calculate_create_address(factory, factory_nonce);
    let create_value = U256::from(1000);

    // Child selfdestructs to beneficiary (different address)
    let init_code = selfdestruct_init_code(beneficiary);

    let (report, _db) = execute_call(
        Fork::Amsterdam,
        vec![
            (sender, eoa(U256::from(DEFAULT_BALANCE))),
            (
                factory,
                contract_funded(
                    U256::from(100_000),
                    create_with_value_bytecode(&init_code, create_value),
                    factory_nonce,
                ),
            ),
            (beneficiary, eoa(U256::zero())),
        ],
        sender,
        factory,
        U256::zero(),
    );

    assert!(report.is_success(), "transaction must succeed");

    // Expect exactly 2 Transfer logs: CREATE (factory→child) + SELFDESTRUCT (child→beneficiary)
    assert_eq!(report.logs.len(), 2, "must have exactly 2 Transfer logs");
    assert_eq!(
        report.logs[0].topics[0], TRANSFER_EVENT_TOPIC,
        "first log must be Transfer"
    );
    assert_transfer_log(&report.logs[0], factory, child, create_value);
    assert_eq!(
        report.logs[1].topics[0], TRANSFER_EVENT_TOPIC,
        "second log must be Transfer"
    );
    assert_transfer_log(&report.logs[1], child, beneficiary, create_value);

    // No burn log at all
    assert_no_burn_log(&report.logs);
}

/// Pre-existing (DB-loaded) contract selfdestructs to other: behavior is identical on Amsterdam
/// and Cancun. Under EIP-6780 (Cancun+), SELFDESTRUCT still transfers the balance to the
/// beneficiary, but the contract is NOT added to the selfdestruct set (it survives with 0 balance).
/// EIP-8246 (Amsterdam+) does not change this case: the contract is still not destroyed, and ETH
/// still flows to the beneficiary. Amsterdam adds an EIP-7708 Transfer log for the ETH movement.
#[test]
fn not_same_tx_selfdestruct_unchanged() {
    let sender = Address::from_low_u64_be(SENDER);
    let contract_addr = Address::from_low_u64_be(FACTORY);
    let beneficiary = Address::from_low_u64_be(BENEFICIARY);
    let contract_balance = U256::from(5000);

    // The contract was NOT created in this tx (pre-existing, nonce=1)
    let code = selfdestruct_bytecode(beneficiary);

    for fork in [Fork::Cancun, Fork::Amsterdam] {
        let (report, mut db) = execute_call(
            fork,
            vec![
                (sender, eoa(U256::from(DEFAULT_BALANCE))),
                (
                    contract_addr,
                    contract_funded(contract_balance, code.clone(), 1),
                ),
                (beneficiary, eoa(U256::zero())),
            ],
            sender,
            contract_addr,
            U256::zero(),
        );

        assert!(report.is_success(), "transaction must succeed on {fork:?}");

        // EIP-6780: balance IS transferred to beneficiary even for pre-existing contracts.
        // The contract is NOT added to the selfdestruct set, so it survives with 0 balance.
        let (contract_balance_after, contract_nonce) = {
            let acc = db.get_account(contract_addr).expect("contract must exist");
            (acc.info.balance, acc.info.nonce)
        };
        assert_eq!(
            contract_balance_after,
            U256::zero(),
            "pre-existing contract balance transferred to beneficiary on {fork:?}"
        );

        let beneficiary_balance = db
            .get_account(beneficiary)
            .expect("beneficiary must exist")
            .info
            .balance;
        assert_eq!(
            beneficiary_balance, contract_balance,
            "beneficiary must receive contract balance on {fork:?}"
        );

        // The contract retains its code and nonce (NOT in selfdestruct set)
        assert_eq!(
            contract_nonce, 1,
            "pre-existing contract nonce must be unchanged on {fork:?}"
        );

        // No Burn log: EIP-8246 never emits Burn logs, and Cancun has no EIP-7708 logs.
        assert_no_burn_log(&report.logs);

        // Amsterdam: EIP-7708 emits a Transfer log for the ETH movement (contract → beneficiary)
        // Cancun: no logs (EIP-7708 not active pre-Amsterdam)
        if fork >= Fork::Amsterdam {
            let has_transfer = report
                .logs
                .iter()
                .any(|l| l.topics.first() == Some(&TRANSFER_EVENT_TOPIC));
            assert!(
                has_transfer,
                "Amsterdam must emit Transfer log for selfdestruct ETH movement"
            );
            assert_eq!(
                report.logs.len(),
                1,
                "Amsterdam must emit exactly one log (Transfer), no spurious burn/extra logs"
            );
        } else {
            assert!(
                report.logs.is_empty(),
                "Cancun must emit no logs for pre-existing contract selfdestruct"
            );
        }
    }
}
