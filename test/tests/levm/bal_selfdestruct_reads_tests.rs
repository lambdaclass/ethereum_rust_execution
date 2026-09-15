//! EIP-7928: SELFDESTRUCT must not record warm-but-unread storage slots as BAL reads.
//!
//! Regression for a consensus gap: on SELFDESTRUCT ethrex used to fold the whole
//! warm access set (`get_accessed_storage_slots`) into the BAL as storage reads.
//! That set includes EIP-2930 access-list slots that were never actually read,
//! which the spec (`get_storage`-only recording) excludes — diverging the
//! `block_access_list_hash` from conformant clients. Reads must come only from
//! genuine SLOAD/SSTORE access.

use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    constants::EMPTY_TRIE_HASH,
    types::{
        Account, AccountState, ChainConfig, Code, CodeMetadata, EIP1559Transaction, Fork,
        Transaction, TxKind,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    db::{Database, gen_db::GeneralizedDatabase},
    environment::{EVMConfig, Environment},
    errors::DatabaseError,
    tracing::LevmCallTracer,
    vm::{VM, VMType},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

const GAS_LIMIT: u64 = 1_000_000;
const SENDER: u64 = 0x1000;
const CONTRACT: u64 = 0xC000;
const BENEFICIARY: u64 = 0x4000;

const WARM_SLOT: u64 = 0x05; // warmed via access list, never read
const READ_SLOT: u64 = 0x07; // genuinely SLOAD'd in the contract code

struct TestDb {
    accounts: FxHashMap<Address, Account>,
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

/// PUSH1 READ_SLOT; SLOAD; POP; PUSH20 beneficiary; SELFDESTRUCT
fn sload_then_selfdestruct(beneficiary: Address) -> Bytes {
    let mut code = vec![0x60, READ_SLOT as u8, 0x54, 0x50, 0x73];
    code.extend_from_slice(beneficiary.as_bytes());
    code.push(0xff); // SELFDESTRUCT
    Bytes::from(code)
}

fn eoa(balance: U256) -> Account {
    Account::new(balance, Code::default(), 0, FxHashMap::default())
}

#[test]
fn selfdestruct_does_not_record_warm_unread_slots_as_bal_reads() {
    let sender = Address::from_low_u64_be(SENDER);
    let contract = Address::from_low_u64_be(CONTRACT);
    let beneficiary = Address::from_low_u64_be(BENEFICIARY);

    // Contract with both slots pre-populated, but its code only SLOADs READ_SLOT.
    let mut storage = FxHashMap::default();
    storage.insert(H256::from_low_u64_be(WARM_SLOT), U256::from(0xAA));
    storage.insert(H256::from_low_u64_be(READ_SLOT), U256::from(0xBB));
    let contract_acct = Account::new(
        U256::zero(),
        Code::from_bytecode(sload_then_selfdestruct(beneficiary), &NativeCrypto),
        1,
        storage,
    );

    let accounts_map: FxHashMap<Address, Account> = [
        (sender, eoa(U256::from(10_000_000_000u64))),
        (contract, contract_acct),
    ]
    .into_iter()
    .collect();

    let test_db = TestDb {
        accounts: FxHashMap::default(),
    };
    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts_map);
    // Enable the BAL recorder so SELFDESTRUCT's recording path runs.
    db.enable_bal_recording();
    db.set_bal_index(1);

    let fork = Fork::Amsterdam;
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

    // Access list warms WARM_SLOT (and the contract). WARM_SLOT is never read.
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(contract),
        value: U256::zero(),
        data: Bytes::new(),
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: 1000,
        max_priority_fee_per_gas: 1,
        access_list: vec![(contract, vec![H256::from_low_u64_be(WARM_SLOT)])],
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
    assert!(report.is_success(), "selfdestruct tx must succeed");

    let bal = db.take_bal().expect("BAL recording was enabled");
    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == contract)
        .expect("contract must appear in the BAL (it was touched)");

    let read_slots: Vec<U256> = contract_changes.storage_reads.clone();
    // The genuinely-SLOAD'd slot is recorded...
    assert!(
        read_slots.contains(&U256::from(READ_SLOT)),
        "genuinely-read slot {READ_SLOT:#x} must be a BAL read, got {read_slots:?}"
    );
    // ...but the warm-but-unread access-list slot must NOT be.
    assert!(
        !read_slots.contains(&U256::from(WARM_SLOT)),
        "warm-but-unread slot {WARM_SLOT:#x} must NOT be a BAL read, got {read_slots:?}"
    );
}
