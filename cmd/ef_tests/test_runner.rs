use std::{collections::HashMap, path::Path};

use crate::types::{Account, TestUnit};
use ethereum_rust_core::{
    rlp::{decode::RLPDecode, encode::RLPEncode},
    types::{Account as CoreAccount, Block as CoreBlock, Transaction as CoreTransaction},
    Address, U256,
};
use ethereum_rust_evm::{
    apply_state_transitions, beacon_root_contract_call, evm_state, execute_tx, EvmState, SpecId,
};
use ethereum_rust_storage::{EngineType, Store};

pub fn execute_test(test_key: &str, test: &TestUnit) {
    // Build pre state
    let mut evm_state = build_evm_state_from_prestate(&test.pre);
    let blocks = test.blocks.clone();
    // Execute all txs in the test unit
    for block in blocks.iter() {
        // Call beacon root contract
        let block_header = block.block_header.clone().unwrap();
        let fork_timestamp = U256::from_dec_str("1710338135").unwrap();
        if !block.block_header.as_ref().unwrap().number.is_zero() /*&& block_header.timestamp >= fork_timestamp*/ {
            if let Some(parent_beacon_root) = block_header.parent_beacon_block_root {
                beacon_root_contract_call(
                    &mut evm_state,
                    parent_beacon_root,
                    &block_header.clone().into(),
                    SpecId::CANCUN,
                )
                .expect("Beacn root contract call error");
            }
        }
        let transactions = block.transactions.as_ref().unwrap();
        for transaction in transactions.iter() {
            assert_eq!(
                transaction.clone().sender,
                CoreTransaction::from(transaction.clone()).sender(),
                "Expected sender address differs from derived sender address on test: {}",
                test_key
            );
            assert!(
                execute_tx(
                    &transaction.clone().into(),
                    &block_header.clone().into(),
                    &mut evm_state,
                    SpecId::CANCUN,
                )
                .is_ok(), //TODO: Assert ExecutionResult depending on test case
                "Transaction execution failed on test: {}",
                test_key
            );
        }
    }
    // Apply state transitions
    apply_state_transitions(&mut evm_state).expect("Failed to update DB state");
    // Check post state
    check_poststate_against_db(&test.post_state, evm_state.database())
}

pub fn parse_test_file(path: &Path) -> HashMap<String, TestUnit> {
    let s: String = std::fs::read_to_string(path).expect("Unable to read file");
    let tests: HashMap<String, TestUnit> = serde_json::from_str(&s).expect("Unable to parse JSON");
    tests
}

//TODO: We shouldn't skip validating the tests with the field expect_exception.
//      We should run them and assert that those return the specified exception.
//      From the vectors/cancun tests, only tests in eip4844_blobs expect exceptions.
pub fn validate_test(test: &TestUnit) {
    // check that the decoded genesis block header matches the deserialized one
    let genesis_rlp = test.genesis_rlp.clone();
    let decoded_block = CoreBlock::decode(&genesis_rlp).unwrap();
    assert_eq!(
        decoded_block.header,
        test.genesis_block_header.clone().into()
    );

    // check that blocks can be decoded
    for block in &test.blocks {
        // skip the blocks with exceptions expected
        if block.expect_exception.is_some() {
            continue;
        }

        match CoreBlock::decode(block.rlp.as_ref()) {
            Ok(decoded_block) => {
                // check that the decoded block matches the deserialized one
                assert_eq!(decoded_block, (block.clone()).into());
                let mut rlp_block = Vec::new();
                // check that encoding the decoded block matches the rlp field
                decoded_block.encode(&mut rlp_block);
                assert_eq!(rlp_block, block.rlp.to_vec());
            }
            Err(_) => assert!(block.expect_exception.is_some()),
        }
    }
}

/// Creates an in-memory DB for evm execution and loads the prestate accounts
pub fn build_evm_state_from_prestate(pre: &HashMap<Address, Account>) -> EvmState {
    let mut store =
        Store::new("store.db", EngineType::InMemory).expect("Failed to build DB for testing");
    for (address, account) in pre {
        let account: CoreAccount = account.clone().into();
        store
            .add_account(*address, account)
            .expect("Failed to write to test DB")
    }
    evm_state(store)
}

/// Checks that all accounts in the post-state are present and have the correct values in the DB
/// Panics if any comparison fails
fn check_poststate_against_db(post: &HashMap<Address, Account>, db: &Store) {
    for (addr, account) in post {
        let expected_account: CoreAccount = account.clone().into();
        // Check info
        let db_account_info = db
            .get_account_info(*addr)
            .expect("Failed to read from DB")
            .expect(&format!("Account info for address {addr} not found in DB"));
        assert_eq!(
            db_account_info, expected_account.info,
            "Mismatched account info for address {addr}"
        );
        // Check code
        let code_hash = expected_account.info.code_hash;
        let db_account_code = db
            .get_account_code(code_hash)
            .expect("Failed to read from DB")
            .expect(&format!(
                "Account code for code hash {code_hash} not found in DB"
            ));
        assert_eq!(
            db_account_code, expected_account.code,
            "Mismatched account code for code hash {code_hash}"
        );
        // Check storage
        for (key, value) in expected_account.storage {
            let db_storage_value = db
                .get_storage_at(*addr, key)
                .expect("Failed to read from DB")
                .expect(&format!(
                    "Storage missing for address {addr} key {key} in DB"
                ));
            assert_eq!(
                db_storage_value, value,
                "Mismatched storage value for address {addr}, key {key}"
            );
        }
    }
}
