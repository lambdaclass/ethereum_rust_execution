//! Regression tests for fee-token lock ordering (Audit Finding L).
//!
//! Issue: `deduct_caller_fee_token` mutates fee-token contract storage via
//! `db.get_account_mut()` (bypassing call-frame backup) before later validation
//! steps that can still fail. If validation fails, the fee-token lock persists.

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
    hooks::l2_hook::{
        COMMON_BRIDGE_L2_ADDRESS, FEE_TOKEN_RATIO_ADDRESS, FEE_TOKEN_REGISTRY_ADDRESS,
    },
    tracing::LevmCallTracer,
    vm::{VM, VMType},
};
use rustc_hash::FxHashMap;
use std::sync::Arc;

// ==================== Test Database ====================

struct TestDatabase {
    accounts: FxHashMap<Address, Account>,
}

impl TestDatabase {
    fn new() -> Self {
        Self {
            accounts: FxHashMap::default(),
        }
    }
}

impl Database for TestDatabase {
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

// ==================== Helpers ====================

fn eoa(balance: U256, nonce: u64) -> Account {
    Account::new(balance, Code::default(), nonce, FxHashMap::default())
}

fn contract_account(code: Bytes) -> Account {
    Account::new(
        U256::zero(),
        Code::from_bytecode(code, &NativeCrypto),
        0,
        FxHashMap::default(),
    )
}

/// EVM bytecode: PUSH1 1, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
/// Returns a 32-byte word with value 1 (used for isFeeToken → true, and ratio → 1).
fn return_one_bytecode() -> Bytes {
    Bytes::from(vec![
        0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ])
}

/// EVM bytecode for the fee-token contract: stores the `amount` parameter at slot 0.
///   PUSH1 0x24, CALLDATALOAD  → loads amount (calldata[36..68])
///   PUSH1 0x00, SSTORE        → stores at slot 0
///   STOP
fn fee_token_bytecode() -> Bytes {
    Bytes::from(vec![0x60, 0x24, 0x35, 0x60, 0x00, 0x55, 0x00])
}

/// Regression test: fee-token lock must be reverted when a later validation step fails.
///
/// Setup: sender has nonce=5, but tx_nonce=0 → nonce mismatch after fee lock.
/// The fee-token contract writes the locked amount to storage slot 0.
/// After the fix, `restore_cache_state` should undo this storage write.
#[test]
fn fee_token_lock_reverted_on_validation_failure() {
    let sender = Address::from_low_u64_be(0x1000);
    let fee_token = Address::from_low_u64_be(0x7001);
    let gas_limit: u64 = 100_000;
    let gas_price: u64 = 1000;

    let test_db = TestDatabase::new();
    let accounts: FxHashMap<Address, Account> = [
        // Sender: nonce=5 so tx_nonce=0 will mismatch at validation step (7)/(nonce check)
        (sender, eoa(U256::from(10_000_000_000u64), 5)),
        // Fee token registry: returns true for isFeeToken
        (
            FEE_TOKEN_REGISTRY_ADDRESS,
            contract_account(return_one_bytecode()),
        ),
        // Fee token ratio: returns U256(1)
        (
            FEE_TOKEN_RATIO_ADDRESS,
            contract_account(return_one_bytecode()),
        ),
        // Fee token contract: stores locked amount at slot 0
        (fee_token, contract_account(fee_token_bytecode())),
        // Common bridge needs to exist for simulate_common_bridge_call
        (COMMON_BRIDGE_L2_ADDRESS, eoa(U256::zero(), 0)),
    ]
    .into_iter()
    .collect();

    let mut db = GeneralizedDatabase::new_with_account_state(Arc::new(test_db), accounts);

    let blob_schedule = EVMConfig::canonical_values(Fork::Prague);
    let env = Environment {
        origin: sender,
        gas_limit,
        config: EVMConfig::new(Fork::Prague, blob_schedule),
        block_number: 1,
        coinbase: Address::from_low_u64_be(0xCCC),
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
        tx_max_priority_fee_per_gas: Some(U256::from(1)),
        tx_max_fee_per_gas: Some(U256::from(gas_price)),
        tx_max_fee_per_blob_gas: None,
        tx_nonce: 0, // Mismatches sender nonce (5)
        block_gas_limit: gas_limit * 2,
        is_privileged: false,
        fee_token: Some(fee_token),
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    };

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0x2000)),
        value: U256::zero(),
        data: Bytes::new(),
        gas_limit,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: 1,
        ..Default::default()
    });

    let mut vm = VM::new(
        env,
        &mut db,
        &tx,
        LevmCallTracer::disabled(),
        VMType::L2(Default::default()),
        &NativeCrypto,
        None,
    )
    .unwrap();

    // Execute: should fail due to nonce mismatch (sender nonce=5, tx nonce=0)
    let result = vm.execute();
    assert!(
        result.is_err(),
        "Expected validation failure due to nonce mismatch"
    );

    // The fee-token contract's storage slot 0 should be zero after rollback.
    // Before the fix, the lock_fee_token mutation persists because it bypasses
    // the call-frame backup mechanism (uses db.get_account_mut directly).
    let fee_token_storage_slot_0 = db
        .get_account(fee_token)
        .map(|acc| acc.storage.get(&H256::zero()).copied().unwrap_or_default())
        .unwrap_or_default();

    assert_eq!(
        fee_token_storage_slot_0,
        U256::zero(),
        "Fee-token storage slot 0 should be zero after validation failure rollback, \
         but found {fee_token_storage_slot_0}. This means the fee-token lock was not reverted."
    );
}
