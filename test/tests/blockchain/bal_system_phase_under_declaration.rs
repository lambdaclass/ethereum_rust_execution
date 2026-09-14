//! Regression tests for #7109: the parallel import path accepted a BAL that misstates
//! what the pre-block system calls or the post-block request/withdrawal phase did.
//! Each test edits one entry, recomputes the header commitments the edit invalidates,
//! and asserts the parallel path rejects the block.
use std::{fs::File, io::BufReader, path::PathBuf, sync::Arc};

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain, BlockchainOptions,
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{
    H160, H256, U256,
    types::{
        Block, DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis, Withdrawal,
        block_access_list::{BlockAccessList, NonceChange, StorageChange},
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_storage::{EngineType, Store};
use ethrex_vm::system_contracts::{
    BEACON_ROOTS_ADDRESS, EXPIRY_VERIFIER_PREDEPLOY, HISTORY_STORAGE_ADDRESS, SYSTEM_ADDRESS,
};

use super::bal_content_validation_tests::forge_state_root;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

async fn setup_store() -> Store {
    let file = File::open(workspace_root().join("fixtures/genesis/l1-bal.json"))
        .expect("open l1-bal genesis");
    let genesis: Genesis =
        serde_json::from_reader(BufReader::new(file)).expect("parse l1-bal genesis");
    let mut store = Store::new("store.db", EngineType::InMemory).expect("build in-memory store");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// Produce a fully-valid empty Amsterdam block on top of genesis and the
/// canonical BAL the producer recorded for it.
async fn build_valid_amsterdam_block(store: &Store) -> (Block, BlockAccessList) {
    build_amsterdam_block_with_withdrawals(store, Vec::new()).await
}

/// As above, with an explicit withdrawal list.
async fn build_amsterdam_block_with_withdrawals(
    store: &Store,
    withdrawals: Vec<Withdrawal>,
) -> (Block, BlockAccessList) {
    let genesis_header = store.get_block_header(0).unwrap().unwrap();
    build_block_on(store, &genesis_header, withdrawals, 1).await
}

/// As above, on an explicit parent.
async fn build_block_on(
    store: &Store,
    parent: &ethrex_common::types::BlockHeader,
    withdrawals: Vec<Withdrawal>,
    slot_number: u64,
) -> (Block, BlockAccessList) {
    let bc = Blockchain::new(store.clone(), BlockchainOptions::default());
    let genesis_header = parent.clone();
    let args = BuildPayloadArgs {
        parent: genesis_header.hash(),
        timestamp: genesis_header.timestamp + 12,
        fee_recipient: H160::zero(),
        random: H256::zero(),
        withdrawals: Some(withdrawals),
        beacon_root: Some(H256::zero()),
        slot_number: Some(slot_number),
        version: 1,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
    };
    let payload = create_payload(&args, store, Bytes::new()).unwrap();
    let result = bc.build_payload(payload).unwrap();
    let bal = result
        .block_access_list
        .expect("amsterdam block must produce a BAL");
    (result.payload, bal)
}

/// Index of the first entry that only records reads, so removing it moves neither
/// `state_root` nor gas. On the `l1-bal` genesis this is the EIP-7002 predeploy,
/// so the test using it covers the post-block phase.
fn first_read_only(bal: &BlockAccessList) -> usize {
    bal.accounts()
        .iter()
        .position(|a| {
            a.storage_changes.is_empty()
                && a.balance_changes.is_empty()
                && a.nonce_changes.is_empty()
                && a.code_changes.is_empty()
                && !a.storage_reads.is_empty()
        })
        .expect("block should record at least one read-only account")
}

#[tokio::test]
async fn parallel_path_rejects_bal_missing_a_system_phase_read() {
    let build_store = setup_store().await;
    let (mut block, bal) = build_valid_amsterdam_block(&build_store).await;

    let control_block = block.clone();
    let control_bal = Arc::new(bal.clone());

    let victim = first_read_only(&bal);
    let dropped = bal.accounts()[victim].clone();

    let mut kept = bal.accounts().to_vec();
    kept.remove(victim);
    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));

    let trimmed_hash = trimmed.compute_hash(&NativeCrypto);
    assert_ne!(trimmed_hash, bal.compute_hash(&NativeCrypto));
    block.header.block_access_list_hash = Some(trimmed_hash);

    let control_store = setup_store().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let control = control_bc.add_block_pipeline_bal(control_block, Some(control_bal));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified block, got: {control:?}"
    );

    // The sequential path regenerates the BAL and byte-compares.
    let seq_store = setup_store().await;
    let seq_bc = Blockchain::new(
        seq_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: false,
            ..Default::default()
        },
    );
    let seq = seq_bc.add_block_pipeline_bal(block.clone(), Some(trimmed.clone()));
    assert!(
        seq.is_err(),
        "sequential path must reject a BAL missing {:?}, got: {seq:?}",
        dropped.address
    );

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(&format!(
        "parallel path accepted a block whose BAL omits {:?} ({} storage_reads), \
         which the sequential path and geth/reth/erigon all reject",
        dropped.address,
        dropped.storage_reads.len()
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("BAL validation failed") && msg.contains("missing from BAL"),
        "rejected for the wrong reason: {msg}"
    );
}

/// Pre-block counterpart of the test above, pinned to beacon roots so it can't drift
/// onto a post-block predeploy.
#[tokio::test]
async fn parallel_path_rejects_bal_missing_a_pre_block_system_call_read() {
    let build_store = setup_store().await;
    let (mut block, bal) = build_valid_amsterdam_block(&build_store).await;

    let address = BEACON_ROOTS_ADDRESS.address;
    let victim = bal
        .accounts()
        .iter()
        .position(|a| a.address == address)
        .expect("block should record the beacon-roots contract");
    assert!(
        !bal.accounts()[victim].storage_changes.is_empty()
            && !bal.accounts()[victim].storage_reads.is_empty(),
        "beacon-roots entry must have both writes and reads for this trim to be read-only"
    );

    let mut kept = bal.accounts().to_vec();
    kept[victim].storage_reads.clear();
    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(trimmed.compute_hash(&NativeCrypto));

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(&format!(
        "parallel path accepted a block whose BAL drops the storage_reads of {address:?}"
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("BAL validation failed") && msg.contains("missing from BAL"),
        "rejected for the wrong reason: {msg}"
    );
}

/// EIP-7928 records withdrawal recipients regardless of amount, but a 0-amount
/// recipient is never loaded, so it never enters the cache.
#[tokio::test]
async fn parallel_path_rejects_bal_missing_a_zero_amount_withdrawal_recipient() {
    let recipient = H160::from_low_u64_be(0xdeadbeef);
    let withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: recipient,
        amount: 0,
    }];

    let build_store = setup_store().await;
    let (mut block, bal) =
        build_amsterdam_block_with_withdrawals(&build_store, withdrawals.clone()).await;

    let victim = bal
        .accounts()
        .iter()
        .position(|a| a.address == recipient)
        .expect("canonical BAL must record a 0-amount withdrawal recipient");

    let control_store = setup_store().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let (control_block, control_bal) =
        build_amsterdam_block_with_withdrawals(&build_store, withdrawals).await;
    let control = control_bc.add_block_pipeline_bal(control_block, Some(Arc::new(control_bal)));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified block, got: {control:?}"
    );

    let mut kept = bal.accounts().to_vec();
    kept.remove(victim);
    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(trimmed.compute_hash(&NativeCrypto));

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(
        "parallel path accepted a block whose BAL omits a 0-amount withdrawal recipient",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("withdrawal recipient") && msg.contains("missing from BAL"),
        "rejected for the wrong reason: {msg}"
    );
}

/// Whole-account omission at index 0. Dropping the EIP-2935 entry moves the state
/// root, but the parallel merkleizer derives it from the BAL, so both are forged.
#[tokio::test]
async fn parallel_path_rejects_bal_missing_a_pre_block_system_contract() {
    let build_store = setup_store().await;
    let (mut block, bal) = build_valid_amsterdam_block(&build_store).await;
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();

    let control_block = block.clone();
    let control_bal = Arc::new(bal.clone());

    let address = HISTORY_STORAGE_ADDRESS.address;
    let victim = bal
        .accounts()
        .iter()
        .position(|a| a.address == address)
        .expect("block should record the history-storage contract");
    assert!(
        !bal.accounts()[victim].storage_changes.is_empty(),
        "history-storage entry must carry the ring-buffer write for this trim to be the \
         whole-account case"
    );

    let mut kept = bal.accounts().to_vec();
    kept.remove(victim);
    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));

    block.header.block_access_list_hash = Some(trimmed.compute_hash(&NativeCrypto));
    block.header.state_root = forge_state_root(&build_store, &genesis_header, &trimmed);

    let control_store = setup_store().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let control = control_bc.add_block_pipeline_bal(control_block, Some(control_bal));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified block, got: {control:?}"
    );

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(&format!(
        "parallel path accepted a block whose BAL omits {address:?} entirely, with both \
         commitments recomputed over the trimmed BAL"
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("was accessed during system calls") && msg.contains("missing from BAL"),
        "rejected for the wrong reason: {msg}"
    );
}

/// As `setup_store`, with the beacon-roots predeploy's code stripped. Only the
/// request predeploys are guarded against empty code, so the call still runs.
async fn setup_store_with_codeless_beacon_roots() -> Store {
    let file = File::open(workspace_root().join("fixtures/genesis/l1-bal.json"))
        .expect("open l1-bal genesis");
    let mut raw: serde_json::Value =
        serde_json::from_reader(BufReader::new(file)).expect("parse l1-bal genesis");
    let alloc = raw
        .get_mut("alloc")
        .and_then(|a| a.as_object_mut())
        .expect("genesis must have an alloc");
    let wanted = hex::encode(BEACON_ROOTS_ADDRESS.address.as_bytes());
    let key = alloc
        .keys()
        .find(|k| k.trim_start_matches("0x").eq_ignore_ascii_case(&wanted))
        .cloned()
        .expect("genesis must prefund the beacon-roots predeploy");
    alloc
        .get_mut(&key)
        .and_then(|a| a.as_object_mut())
        .expect("alloc entry must be an object")
        .remove("code");
    let genesis: Genesis = serde_json::from_value(raw).expect("re-parse patched genesis");
    let mut store = Store::new("store.db", EngineType::InMemory).expect("build in-memory store");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// A call to a codeless contract records the target but writes nothing, so the
/// canonical BAL has a bare entry while the cache holds only an info-only load.
#[tokio::test]
async fn parallel_path_rejects_bal_missing_a_codeless_system_contract() {
    let build_store = setup_store_with_codeless_beacon_roots().await;
    let (mut block, bal) = build_valid_amsterdam_block(&build_store).await;

    let control_block = block.clone();
    let control_bal = Arc::new(bal.clone());

    let address = BEACON_ROOTS_ADDRESS.address;
    let victim = bal
        .accounts()
        .iter()
        .position(|a| a.address == address)
        .expect("canonical BAL must record the codeless call target");
    let dropped = bal.accounts()[victim].clone();
    assert!(
        dropped.storage_changes.is_empty()
            && dropped.storage_reads.is_empty()
            && dropped.balance_changes.is_empty()
            && dropped.nonce_changes.is_empty()
            && dropped.code_changes.is_empty(),
        "a codeless system call must leave a bare entry, else this test is not \
         exercising the pure-touch case: {dropped:?}"
    );

    let mut kept = bal.accounts().to_vec();
    kept.remove(victim);
    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(trimmed.compute_hash(&NativeCrypto));

    let control_store = setup_store_with_codeless_beacon_roots().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let control = control_bc.add_block_pipeline_bal(control_block, Some(control_bal));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified codeless-predeploy block, got: {control:?}"
    );

    let par_store = setup_store_with_codeless_beacon_roots().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(&format!(
        "parallel path accepted a block whose BAL omits the bare entry of codeless {address:?}"
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("was accessed during system calls") && msg.contains("missing from BAL"),
        "rejected for the wrong reason: {msg}"
    );
}

/// Demotes EIP-2935's index-0 write to a read: the slot stays in the entry, so only
/// a by-value check sees the write is gone.
#[tokio::test]
async fn parallel_path_rejects_bal_demoting_a_pre_block_write_to_a_read() {
    let build_store = setup_store().await;
    let (mut block, bal) = build_valid_amsterdam_block(&build_store).await;
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();

    let control_block = block.clone();
    let control_bal = Arc::new(bal.clone());

    let address = HISTORY_STORAGE_ADDRESS.address;
    let victim = bal
        .accounts()
        .iter()
        .position(|a| a.address == address)
        .expect("block should record the history-storage contract");

    let mut kept = bal.accounts().to_vec();
    let acct = &mut kept[victim];
    let mut demoted = Vec::new();
    acct.storage_changes.retain(|sc| {
        if sc.slot_changes.iter().any(|c| c.block_access_index == 0) {
            demoted.push(sc.slot);
            false
        } else {
            true
        }
    });
    assert!(
        !demoted.is_empty(),
        "history contract must write at index 0 for this demotion to be the case under test"
    );
    acct.storage_reads.extend(demoted.iter().copied());
    acct.storage_reads.sort_unstable();
    acct.storage_reads.dedup();

    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(trimmed.compute_hash(&NativeCrypto));
    block.header.state_root = forge_state_root(&build_store, &genesis_header, &trimmed);

    let control_store = setup_store().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let control = control_bc.add_block_pipeline_bal(control_block, Some(control_bal));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified block, got: {control:?}"
    );

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(&format!(
        "parallel path accepted a block whose BAL demotes the index-0 write of \
         {address:?} to a bare read"
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("was written during system calls") && msg.contains("index 0"),
        "rejected for the wrong reason: {msg}"
    );
}

/// Two index-0 changes for one slot, canonical first and forged last: validation reads
/// the first, synthesis merkleizes the last.
#[tokio::test]
async fn parallel_path_rejects_bal_with_duplicate_pre_block_changes() {
    let build_store = setup_store().await;
    let (mut block, bal) = build_valid_amsterdam_block(&build_store).await;
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();

    let address = HISTORY_STORAGE_ADDRESS.address;
    let victim = bal
        .accounts()
        .iter()
        .position(|a| a.address == address)
        .expect("block should record the history-storage contract");

    let mut kept = bal.accounts().to_vec();
    let slot_change = kept[victim]
        .storage_changes
        .iter_mut()
        .find(|sc| sc.slot_changes.iter().any(|c| c.block_access_index == 0))
        .expect("history contract must write at index 0");
    let canonical = slot_change
        .slot_changes
        .iter()
        .find(|c| c.block_access_index == 0)
        .expect("index-0 change")
        .post_value;
    let forged = canonical + U256::one();
    slot_change.slot_changes.push(StorageChange::new(0, forged));

    let trimmed = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(trimmed.compute_hash(&NativeCrypto));
    block.header.state_root = forge_state_root(&build_store, &genesis_header, &trimmed);

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(trimmed));
    let err = par.expect_err(
        "parallel path accepted a BAL carrying two index-0 changes for one slot, \
         validating the first and merkleizing the second",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("BAL validation failed"),
        "rejected for the wrong reason: {msg}"
    );
}

/// As `setup_store`, with Hegota active from genesis.
async fn setup_hegota_store() -> Store {
    let file = File::open(workspace_root().join("fixtures/genesis/l1-bal.json"))
        .expect("open l1-bal genesis");
    let mut raw: serde_json::Value =
        serde_json::from_reader(BufReader::new(file)).expect("parse l1-bal genesis");
    raw.get_mut("config")
        .and_then(|c| c.as_object_mut())
        .expect("genesis must have a config")
        .insert("hegotaTime".to_string(), serde_json::json!(0));
    let genesis: Genesis = serde_json::from_value(raw).expect("re-parse patched genesis");
    let mut store = Store::new("store.db", EngineType::InMemory).expect("build in-memory store");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// After the install, the EIP-8141 probe loads its predeploy without recording it, so a
/// bare entry for it must stay on the unaccessed checklist.
#[tokio::test]
async fn parallel_path_rejects_a_bare_bal_entry_for_an_unrecorded_probe() {
    let address = EXPIRY_VERIFIER_PREDEPLOY.address;
    let build_store = setup_hegota_store().await;

    // Block 1 records the install; only block 2 reaches the unrecorded probe.
    let (block1, bal1) = build_valid_amsterdam_block(&build_store).await;
    let installer = bal1.accounts().iter().find(|a| a.address == address);
    assert!(
        installer.is_some_and(|a| !a.code_changes.is_empty()),
        "block 1 must record the expiry-verifier install, else this test is not \
         exercising the already-installed path"
    );
    let bc = Blockchain::new(
        build_store.clone(),
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    bc.add_block_pipeline_bal(block1.clone(), Some(Arc::new(bal1)))
        .expect("block 1 must import");

    let (mut block, bal) = build_block_on(&build_store, &block1.header, Vec::new(), 2).await;
    assert!(
        !bal.accounts().iter().any(|a| a.address == address),
        "the canonical BAL of block 2 must NOT mention the predeploy, else the probe \
         is being recorded and there is nothing to over-declare"
    );

    let mut kept = bal.accounts().to_vec();
    kept.push(ethrex_common::types::block_access_list::AccountChanges::new(address));
    // Canonical ordering is by address.
    kept.sort_by_key(|a| a.address);
    let forged = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(forged.compute_hash(&NativeCrypto));

    let par_bc = Blockchain::new(
        setup_hegota_store().await,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    par_bc
        .add_block_pipeline_bal(block1, None)
        .expect("block 1 must import into the victim store");
    let par = par_bc.add_block_pipeline_bal(block, Some(forged));
    let err = par.expect_err(&format!(
        "parallel path accepted a bare BAL entry for {address:?}, which the phase \
         never recorded"
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("BAL validation failed"),
        "rejected for the wrong reason: {msg}"
    );
}

/// An added no-op change at the post-block index matches the cache, so
/// `validate_bal_withdrawal_index` alone accepts it.
#[tokio::test]
async fn parallel_path_rejects_an_extra_change_at_the_post_block_index() {
    let recipient = H160::from_low_u64_be(0xfeed);
    let withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: recipient,
        amount: 1,
    }];

    let build_store = setup_store().await;
    let (mut block, bal) =
        build_amsterdam_block_with_withdrawals(&build_store, withdrawals.clone()).await;

    let control_block = block.clone();
    let control_bal = Arc::new(bal.clone());

    // n_txs + 1, with no transactions.
    let post_idx = 1u32;
    let mut kept = bal.accounts().to_vec();
    let victim = kept
        .iter()
        .position(|a| a.address == recipient)
        .expect("canonical BAL must record the withdrawal recipient");
    let real_balance = find_post_balance(&kept[victim], post_idx)
        .expect("recipient must have a balance change at the post-block index");

    assert!(!real_balance.is_zero(), "withdrawal must move a balance");
    assert!(
        kept[victim].nonce_changes.is_empty(),
        "recipient must have no canonical nonce change for this to be an addition"
    );
    kept[victim]
        .nonce_changes
        .push(NonceChange::new(post_idx, 0));

    let forged = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(forged.compute_hash(&NativeCrypto));

    let control_store = setup_store().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let control = control_bc.add_block_pipeline_bal(control_block, Some(control_bal));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified block, got: {control:?}"
    );

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(forged));
    let err = par.expect_err(
        "parallel path accepted a BAL declaring a post-block change the phase never made",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("BAL validation failed"),
        "rejected for the wrong reason: {msg}"
    );
}

/// Post-balance an account's BAL entry declares at `idx`, if any.
fn find_post_balance(
    acct: &ethrex_common::types::block_access_list::AccountChanges,
    idx: u32,
) -> Option<U256> {
    acct.balance_changes
        .iter()
        .find(|c| c.block_access_index == idx)
        .map(|c| c.post_balance)
}

/// As above, aimed at `SYSTEM_ADDRESS`, which a withdrawal legitimately puts in the
/// post-block cache.
#[tokio::test]
async fn parallel_path_rejects_an_extra_system_address_change_at_the_post_block_index() {
    let withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: SYSTEM_ADDRESS,
        amount: 1,
    }];

    let build_store = setup_store().await;
    let (mut block, bal) =
        build_amsterdam_block_with_withdrawals(&build_store, withdrawals.clone()).await;

    let control_block = block.clone();
    let control_bal = Arc::new(bal.clone());

    let post_idx = 1u32;
    let mut kept = bal.accounts().to_vec();
    let victim = kept
        .iter()
        .position(|a| a.address == SYSTEM_ADDRESS)
        .expect(
            "a withdrawal to SYSTEM_ADDRESS must still be recorded: the recorder \
                 only drops it inside a system call",
        );
    assert!(
        kept[victim].nonce_changes.is_empty(),
        "SYSTEM_ADDRESS must have no canonical nonce change for this to be an addition"
    );
    kept[victim]
        .nonce_changes
        .push(NonceChange::new(post_idx, 0));

    let forged = Arc::new(BlockAccessList::from_accounts(kept));
    block.header.block_access_list_hash = Some(forged.compute_hash(&NativeCrypto));

    let control_store = setup_store().await;
    let control_bc = Blockchain::new(
        control_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let control = control_bc.add_block_pipeline_bal(control_block, Some(control_bal));
    assert!(
        control.is_ok(),
        "parallel path must accept the unmodified block, got: {control:?}"
    );

    let par_store = setup_store().await;
    let par_bc = Blockchain::new(
        par_store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            ..Default::default()
        },
    );
    let par = par_bc.add_block_pipeline_bal(block, Some(forged));
    let err = par.expect_err(
        "parallel path accepted a forged SYSTEM_ADDRESS change at the post-block index",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("BAL validation failed"),
        "rejected for the wrong reason: {msg}"
    );
}
