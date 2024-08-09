mod db;
mod errors;
mod execution_result;

use db::StoreWrapper;

use ethereum_rust_core::{
    types::{
        AccountInfo, Block, BlockHeader, GenericTransaction, Transaction, TxKind, Withdrawal,
        GWEI_TO_WEI,
    },
    Address, BigEndianHash, H256, U256,
};
use ethereum_rust_storage::{error::StoreError, Store};
use lazy_static::lazy_static;
use revm::{
    db::states::bundle_state::BundleRetention,
    inspector_handle_register,
    inspectors::TracerEip3155,
    precompile::{PrecompileSpecId, Precompiles},
    primitives::{BlockEnv, TxEnv, B256, U256 as RevmU256},
    Database, DatabaseCommit, Evm,
};
use revm_inspectors::access_list::AccessListInspector;
// Rename imported types for clarity
use revm::primitives::{Address as RevmAddress, TxKind as RevmTxKind};
use revm_primitives::{AccessList as RevmAccessList, AccessListItem as RevmAccessListItem};
// Export needed types
pub use errors::EvmError;
pub use execution_result::*;
pub use revm::primitives::SpecId;

type AccessList = Vec<(Address, Vec<H256>)>;

/// State used when running the EVM
// Encapsulates state behaviour to be agnostic to the evm implementation for crate users
pub struct EvmState(revm::db::State<StoreWrapper>);

impl EvmState {
    /// Get a reference to inner `Store` database
    pub fn database(&self) -> &Store {
        &self.0.database.0
    }
}

/// Executes all transactions in a block and performs the state transition on the database
pub fn execute_block(block: &Block, state: &mut EvmState, spec_id: SpecId) -> Result<(), EvmError> {
    let block_header = &block.header;
    //eip 4788: execute beacon_root_contract_call before block transactions
    if block_header.parent_beacon_block_root.is_some() && spec_id == SpecId::CANCUN {
        beacon_root_contract_call(state, block_header, spec_id)?;
    }

    for transaction in block.body.transactions.iter() {
        execute_tx(transaction, block_header, state, spec_id)?;
    }

    apply_state_transitions(state)?;
    if let Some(withdrawals) = &block.body.withdrawals {
        process_withdrawals(state, withdrawals)?;
    }
    apply_state_transitions(state)?;
    Ok(())
}

// Executes a single tx, doesn't perform state transitions
pub fn execute_tx(
    tx: &Transaction,
    header: &BlockHeader,
    state: &mut EvmState,
    spec_id: SpecId,
) -> Result<ExecutionResult, EvmError> {
    let block_env = block_env(header);
    let tx_env = tx_env(tx);
    run_evm(tx_env, block_env, state, spec_id)
}

/// Runs EVM, doesn't perform state transitions, but stores them
fn run_evm(
    tx_env: TxEnv,
    block_env: BlockEnv,
    state: &mut EvmState,
    spec_id: SpecId,
) -> Result<ExecutionResult, EvmError> {
    let tx_result = {
        let chain_id = state.database().get_chain_id()?.map(|ci| ci.low_u64());
        let mut evm = Evm::builder()
            .with_db(&mut state.0)
            .with_block_env(block_env)
            .with_tx_env(tx_env)
            .modify_cfg_env(|cfg| {
                if let Some(chain_id) = chain_id {
                    cfg.chain_id = chain_id
                }
            })
            .with_spec_id(spec_id)
            .reset_handler()
            .with_external_context(
                TracerEip3155::new(Box::new(std::io::stderr())).without_summary(),
            )
            .build();
        evm.transact_commit().map_err(EvmError::from)?
    };
    Ok(tx_result.into())
}

/// Runs the transaction and returns the access list and estimated gas use (when running the tx with said access list)
pub fn create_access_list(
    tx: &GenericTransaction,
    header: &BlockHeader,
    state: &mut EvmState,
    spec_id: SpecId,
) -> Result<(ExecutionResult, AccessList), EvmError> {
    let mut tx_env = tx_env_from_generic(tx);
    let block_env = block_env(header);
    // Run tx with access list inspector
    let (execution_result, access_list) =
        create_access_list_inner(tx_env.clone(), block_env.clone(), state, spec_id)?;
    // Run the tx with the resulting access list and estimate its gas used
    let execution_result = if execution_result.is_success() {
        tx_env.access_list.extend(access_list.0.iter().map(|item| {
            (
                item.address,
                item.storage_keys
                    .iter()
                    .map(|b| RevmU256::from_be_slice(b.as_slice()))
                    .collect(),
            )
        }));
        estimate_gas(tx_env, block_env, state, spec_id)?
    } else {
        execution_result
    };
    let access_list: Vec<(Address, Vec<H256>)> = access_list
        .iter()
        .map(|item| {
            (
                Address::from_slice(item.address.0.as_slice()),
                item.storage_keys
                    .iter()
                    .map(|v| H256::from_slice(v.as_slice()))
                    .collect(),
            )
        })
        .collect();
    Ok((execution_result, access_list))
}

/// Runs the transaction and returns the access list for it
fn create_access_list_inner(
    tx_env: TxEnv,
    block_env: BlockEnv,
    state: &mut EvmState,
    spec_id: SpecId,
) -> Result<(ExecutionResult, RevmAccessList), EvmError> {
    let mut access_list_inspector = access_list_inspector(&tx_env, state, spec_id)?;
    let tx_result = {
        let mut evm = Evm::builder()
            .with_db(&mut state.0)
            .with_block_env(block_env)
            .with_tx_env(tx_env)
            .with_spec_id(spec_id)
            .modify_cfg_env(|env| {
                env.disable_base_fee = true;
                env.disable_block_gas_limit = true
            })
            .with_external_context(&mut access_list_inspector)
            .append_handler_register(inspector_handle_register)
            .build();
        evm.transact().map_err(EvmError::from)?
    };

    let access_list = access_list_inspector.into_access_list();
    Ok((tx_result.result.into(), access_list))
}

/// Runs the transaction and returns the estimated gas
fn estimate_gas(
    tx_env: TxEnv,
    block_env: BlockEnv,
    state: &mut EvmState,
    spec_id: SpecId,
) -> Result<ExecutionResult, EvmError> {
    let tx_result = {
        let mut evm = Evm::builder()
            .with_db(&mut state.0)
            .with_block_env(block_env)
            .with_tx_env(tx_env)
            .with_spec_id(spec_id)
            .modify_cfg_env(|env| {
                env.disable_base_fee = true;
                env.disable_block_gas_limit = true
            })
            .build();
        evm.transact().map_err(EvmError::from)?
    };
    Ok(tx_result.result.into())
}

// Merges transitions stored when executing transactions and applies the resulting changes to the DB
pub fn apply_state_transitions(state: &mut EvmState) -> Result<(), StoreError> {
    state.0.merge_transitions(BundleRetention::PlainState);
    let bundle = state.0.take_bundle();
    // Update accounts
    for (address, account) in bundle.state() {
        if account.status.is_not_modified() {
            continue;
        }
        let address = Address::from_slice(address.0.as_slice());
        // Remove account from DB if destroyed
        if account.status.was_destroyed() {
            state.database().remove_account(address)?;
        }

        // If account is empty, do not add to the database
        if account
            .account_info()
            .is_some_and(|acc_info| acc_info.is_empty())
        {
            continue;
        }

        // Apply account changes to DB
        // If the account was changed then both original and current info will be present in the bundle account
        if account.is_info_changed() {
            // Update account info in DB
            if let Some(new_acc_info) = account.account_info() {
                let code_hash = H256::from_slice(new_acc_info.code_hash.as_slice());
                let account_info = AccountInfo {
                    code_hash,
                    balance: U256::from_little_endian(new_acc_info.balance.as_le_slice()),
                    nonce: new_acc_info.nonce,
                };
                state.database().add_account_info(address, account_info)?;

                if account.is_contract_changed() {
                    // Update code in db
                    if let Some(code) = new_acc_info.code {
                        state
                            .database()
                            .add_account_code(code_hash, code.original_bytes().clone().0)?;
                    }
                }
            }
        }
        // Update account storage in DB
        for (key, slot) in account.storage.iter() {
            if slot.is_changed() {
                // TODO check if we need to remove the value from our db when value is zero
                // if slot.present_value().is_zero() {
                //     state.database().remove_account_storage(address)
                // }
                state.database().add_storage_at(
                    address,
                    H256::from_uint(&U256::from_little_endian(key.as_le_slice())),
                    U256::from_little_endian(slot.present_value().as_le_slice()),
                )?;
            }
        }
    }
    Ok(())
}

/// Processes a block's withdrawals, updating the account balances in the state
pub fn process_withdrawals(
    state: &mut EvmState,
    withdrawals: &[Withdrawal],
) -> Result<(), StoreError> {
    //balance_increments is a vector of tuples (Address, increment as u128)
    let balance_increments = withdrawals
        .iter()
        .filter(|withdrawal| withdrawal.amount > 0)
        .map(|withdrawal| {
            (
                RevmAddress::from_slice(withdrawal.address.as_bytes()),
                (withdrawal.amount as u128 * GWEI_TO_WEI as u128),
            )
        })
        .collect::<Vec<_>>();

    state.0.increment_balances(balance_increments)?;
    Ok(())
}

/// Builds EvmState from a Store
pub fn evm_state(store: Store) -> EvmState {
    EvmState(
        revm::db::State::builder()
            .with_database(StoreWrapper(store))
            .with_bundle_update()
            .without_state_clear()
            .build(),
    )
}

/// Calls the eip4788 beacon block root system call contract
/// As of the Cancun hard-fork, parent_beacon_block_root needs to be present in the block header.
pub fn beacon_root_contract_call(
    state: &mut EvmState,
    header: &BlockHeader,
    spec_id: SpecId,
) -> Result<ExecutionResult, EvmError> {
    lazy_static! {
        static ref SYSTEM_ADDRESS: RevmAddress = RevmAddress::from_slice(
            &hex::decode("fffffffffffffffffffffffffffffffffffffffe").unwrap()
        );
        static ref CONTRACT_ADDRESS: RevmAddress = RevmAddress::from_slice(
            &hex::decode("000F3df6D732807Ef1319fB7B8bB8522d0Beac02").unwrap(),
        );
    };
    let beacon_root = match header.parent_beacon_block_root {
        None => {
            return Err(EvmError::Header(
                "parent_beacon_block_root field is missing".to_string(),
            ))
        }
        Some(beacon_root) => beacon_root,
    };

    let tx_env = TxEnv {
        caller: *SYSTEM_ADDRESS,
        transact_to: RevmTxKind::Call(*CONTRACT_ADDRESS),
        gas_limit: 30_000_000,
        data: revm::primitives::Bytes::copy_from_slice(beacon_root.as_bytes()),
        ..Default::default()
    };
    let mut block_env = block_env(header);
    block_env.basefee = RevmU256::ZERO;
    block_env.gas_limit = RevmU256::from(30_000_000);

    let mut evm = Evm::builder()
        .with_db(&mut state.0)
        .with_block_env(block_env)
        .with_tx_env(tx_env)
        .with_spec_id(spec_id)
        .reset_handler()
        .with_external_context(TracerEip3155::new(Box::new(std::io::stderr())).without_summary())
        .build();

    let transaction_result = evm.transact()?;
    let mut result_state = transaction_result.state;
    result_state.remove(&*SYSTEM_ADDRESS);
    result_state.remove(&evm.block().coinbase);

    evm.context.evm.db.commit(result_state);

    Ok(transaction_result.result.into())
}

fn block_env(header: &BlockHeader) -> BlockEnv {
    BlockEnv {
        number: RevmU256::from(header.number),
        coinbase: RevmAddress(header.coinbase.0.into()),
        timestamp: RevmU256::from(header.timestamp),
        gas_limit: RevmU256::from(header.gas_limit),
        basefee: RevmU256::from(header.base_fee_per_gas),
        difficulty: RevmU256::from_limbs(header.difficulty.0),
        prevrandao: Some(header.prev_randao.as_fixed_bytes().into()),
        ..Default::default()
    }
}

fn tx_env(tx: &Transaction) -> TxEnv {
    let mut max_fee_per_blob_gas_bytes: [u8; 32] = [0; 32];
    let max_fee_per_blob_gas = match tx.max_fee_per_blob_gas() {
        Some(x) => {
            x.to_big_endian(&mut max_fee_per_blob_gas_bytes);
            Some(RevmU256::from_be_bytes(max_fee_per_blob_gas_bytes))
        }
        None => None,
    };
    TxEnv {
        caller: RevmAddress(tx.sender().0.into()),
        gas_limit: tx.gas_limit(),
        gas_price: RevmU256::from(tx.gas_price()),
        transact_to: match tx.to() {
            TxKind::Call(address) => RevmTxKind::Call(address.0.into()),
            TxKind::Create => RevmTxKind::Create,
        },
        value: RevmU256::from_limbs(tx.value().0),
        data: tx.data().clone().into(),
        nonce: Some(tx.nonce()),
        chain_id: tx.chain_id(),
        access_list: tx
            .access_list()
            .into_iter()
            .map(|(addr, list)| {
                (
                    RevmAddress(addr.0.into()),
                    list.into_iter()
                        .map(|a| RevmU256::from_be_bytes(a.0))
                        .collect(),
                )
            })
            .collect(),
        gas_priority_fee: tx.max_priority_fee().map(RevmU256::from),
        blob_hashes: tx
            .blob_versioned_hashes()
            .into_iter()
            .map(|hash| B256::from(hash.0))
            .collect(),
        max_fee_per_blob_gas,
    }
}

// Used to estimate gas and create access lists
fn tx_env_from_generic(tx: &GenericTransaction) -> TxEnv {
    TxEnv {
        caller: RevmAddress(tx.from.0.into()),
        gas_limit: tx.gas.unwrap_or(u64::MAX), // Ensure tx doesn't fail due to gas limit
        gas_price: RevmU256::from(tx.gas_price),
        transact_to: match tx.to {
            TxKind::Call(address) => RevmTxKind::Call(address.0.into()),
            TxKind::Create => RevmTxKind::Create,
        },
        value: RevmU256::from_limbs(tx.value.0),
        data: tx.input.clone().into(),
        nonce: Some(tx.nonce),
        chain_id: tx.chain_id,
        access_list: tx
            .access_list
            .iter()
            .map(|entry| {
                (
                    RevmAddress(entry.address.0.into()),
                    entry
                        .storage_keys
                        .iter()
                        .map(|a| RevmU256::from_be_bytes(a.0))
                        .collect(),
                )
            })
            .collect(),
        gas_priority_fee: tx.max_priority_fee_per_gas.map(RevmU256::from),
        blob_hashes: tx
            .blob_versioned_hashes
            .iter()
            .map(|hash| B256::from(hash.0))
            .collect(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas.map(RevmU256::from),
    }
}

// Creates an AccessListInspector that will collect the accesses used by the evm execution
fn access_list_inspector(
    tx_env: &TxEnv,
    state: &mut EvmState,
    spec_id: SpecId,
) -> Result<AccessListInspector, EvmError> {
    // Access list provided by the transaction
    let current_access_list = RevmAccessList(
        tx_env
            .access_list
            .iter()
            .map(|(addr, list)| RevmAccessListItem {
                address: *addr,
                storage_keys: list.iter().map(|v| B256::from(v.to_be_bytes())).collect(),
            })
            .collect(),
    );
    // Addresses accessed when using precompiles
    let precompile_addresses = Precompiles::new(PrecompileSpecId::from_spec_id(spec_id))
        .addresses()
        .cloned();
    // Address that is either called or created by the transaction
    let to = match tx_env.transact_to {
        RevmTxKind::Call(address) => address,
        RevmTxKind::Create => {
            let nonce = state
                .0
                .basic(tx_env.caller)?
                .map(|info| info.nonce)
                .unwrap_or_default();
            tx_env.caller.create(nonce)
        }
    };
    Ok(AccessListInspector::new(
        current_access_list,
        tx_env.caller,
        to,
        precompile_addresses,
    ))
}
