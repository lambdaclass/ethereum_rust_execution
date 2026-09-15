use std::sync::Arc;

use crate::{
    runner::{
        EFTestRunnerError, InternalError,
        revm_db::{RevmState, revm_state},
    },
    types::{EFTest, EFTestTransaction},
};
use ethrex_blockchain::vm::StoreVmDatabase;
use ethrex_common::{
    Address, H256, U256,
    types::{AccountState, ChainConfig, Code, CodeMetadata, Genesis},
    utils::keccak,
};
use ethrex_levm::db::gen_db::GeneralizedDatabase;
use ethrex_storage::{EngineType, Store};
use ethrex_vm::{DynVmDatabase, EvmError, VmDatabase};

/// `VmDatabase` for state tests that mirrors the EEST convention for `BLOCKHASH`:
/// the hash of block `n` is `keccak256(decimal(n))` (e.g. `BLOCKHASH(0) == keccak256("0")`).
/// The in-memory store only holds the genesis block, so every other field delegates to the
/// wrapped `StoreVmDatabase` while `get_block_hash` follows the synthetic convention.
#[derive(Clone)]
struct StateTestVmDatabase {
    inner: StoreVmDatabase,
}

impl VmDatabase for StateTestVmDatabase {
    fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
        self.inner.get_account_state(address)
    }
    fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
        self.inner.get_storage_slot(address, key)
    }
    fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
        Ok(keccak(block_number.to_string().as_bytes()))
    }
    fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
        self.inner.get_chain_config()
    }
    fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
        self.inner.get_account_code(code_hash)
    }
    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
        self.inner.get_code_metadata(code_hash)
    }
    fn code_cache_budget_bytes(&self) -> u64 {
        self.inner.code_cache_budget_bytes()
    }
}

/// Loads initial state, used for REVM as it contains RevmState.
pub async fn load_initial_state_revm(test: &EFTest) -> (RevmState, H256, Store) {
    let genesis = Genesis::from(test);

    let mut storage = Store::new("./temp", EngineType::InMemory).expect("Failed to create Store");
    storage.add_initial_state(genesis.clone()).await.unwrap();

    let vm_db: DynVmDatabase = Box::new(StateTestVmDatabase {
        inner: StoreVmDatabase::new(storage.clone(), genesis.get_block().header).unwrap(),
    });

    (revm_state(vm_db), genesis.get_block().hash(), storage)
}

/// Loads initial state, function for LEVM as it does not require RevmState
pub async fn load_initial_state_levm(test: &EFTest) -> GeneralizedDatabase {
    let genesis = Genesis::from(test);

    let mut storage = Store::new("./temp", EngineType::InMemory).expect("Failed to create Store");
    storage.add_initial_state(genesis.clone()).await.unwrap();

    let store: DynVmDatabase = Box::new(StateTestVmDatabase {
        inner: StoreVmDatabase::new(storage, genesis.get_block().header).unwrap(),
    });

    GeneralizedDatabase::new(Arc::new(store))
}

// If gas price is not provided, calculate it with current base fee and priority fee
pub fn effective_gas_price(
    test: &EFTest,
    tx: &&EFTestTransaction,
) -> Result<U256, EFTestRunnerError> {
    match tx.gas_price {
        None => {
            let current_base_fee = test
                .env
                .current_base_fee
                .ok_or(EFTestRunnerError::Internal(
                    InternalError::FirstRunInternal("current_base_fee not found".to_string()),
                ))?;
            let priority_fee = tx
                .max_priority_fee_per_gas
                .ok_or(EFTestRunnerError::Internal(
                    InternalError::FirstRunInternal(
                        "max_priority_fee_per_gas not found".to_string(),
                    ),
                ))?;
            let max_fee_per_gas = tx.max_fee_per_gas.ok_or(EFTestRunnerError::Internal(
                InternalError::FirstRunInternal("max_fee_per_gas not found".to_string()),
            ))?;

            Ok(std::cmp::min(
                max_fee_per_gas,
                current_base_fee + priority_fee,
            ))
        }
        Some(price) => Ok(price),
    }
}
