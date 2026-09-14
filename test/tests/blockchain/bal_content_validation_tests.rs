//! Regression tests binding the EIP-7928 supplied-BAL *content* validation
//! gaps closed on the default parallel block-import path (`validate_tx_execution`
//! in `crates/vm/backends/levm/mod.rs` and the selfdestruct reconciliation in
//! `execute_block_parallel`):
//!
//! - a spurious no-op BAL entry (post-value == start-of-tx seeded value) must
//!   be rejected even when it happens to match the actual post-execution value
//!   (the "matching arm" case, not just the mismatch arm) — covered for all
//!   four fields (balance, nonce, code, storage), plus a genuine (non-no-op)
//!   control for a declared-read-only storage slot;
//! - a storage slot execution actually wrote, declared in neither the BAL's
//!   storage_changes nor storage_reads, must be rejected;
//! - a phantom (never actually read) BAL storage_reads entry on a
//!   selfdestructed account must still be rejected, while a genuinely-read-
//!   then-destroyed slot must still be accepted;
//! - a CREATE whose supplied BAL omits the code_changes entry must be
//!   rejected (already-fixed finding, locked here against regression).
//!
//! Harness pattern follows `bal_hash_parallel_skip.rs`: build a fully-valid
//! Amsterdam block + BAL, mutate the BAL to introduce exactly one of the
//! anomalies above, forge the header commitments the mutation invalidates
//! (`block_access_list_hash` always; `state_root` too when the mutation
//! changes what the parallel path's BAL-driven merkleization would produce),
//! and import down the parallel path. The content-validation error must be
//! what triggers rejection, not an incidental root/hash mismatch.

use std::{fs::File, io::BufReader, path::PathBuf, sync::Arc};

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain, BlockchainOptions,
    error::ChainError,
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{
    Address, H160, H256, U256,
    evm::calculate_create_address,
    types::{
        AccountInfo, AccountUpdate, Block, BlockHeader, DEFAULT_BUILDER_GAS_CEIL,
        EIP1559Transaction, ELASTICITY_MULTIPLIER, Genesis, Receipt, Transaction, TxKind,
        block_access_list::{
            AccountChanges, BalanceChange, BlockAccessList, CodeChange, NonceChange, SlotChange,
            StorageChange, synthesize_bal_updates,
        },
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use ethrex_storage::{EngineType, Store};
use ethrex_vm::EvmError;
use secp256k1::SecretKey;

/// Test private key from fixtures/keys/private_keys_tests.txt (line 1). Rich
/// account, already funded in `l1-bal-content.json` (inherited from
/// `l1-bal.json`'s rich-accounts alloc). Used as tx sender.
const SENDER_PRIVATE_KEY: &str = "850643a0224065ecce3882673c21f56bcf6eef86274cc21cadff15930b59fc8c";
/// A second, distinct rich account from the same alloc (private key line 2:
/// `0x180ba7fc7455b07afdf408722b32945e018ed2d5b6865915c185c733ab1f3459`,
/// address `0x000b59AeD48ADCd6c36Ae5f437AbB9CA730a2c43`). Used as a 0-value
/// transfer recipient so it gets touched (loaded into execution state)
/// without its balance actually changing.
const RECIPIENT_ADDRESS: Address = H160([
    0x00, 0x0b, 0x59, 0xae, 0xd4, 0x8a, 0xdc, 0xd6, 0xc3, 0x6a, 0xe5, 0xf4, 0x37, 0xab, 0xb9, 0xca,
    0x73, 0x0a, 0x2c, 0x43,
]);
/// SSTORE contract predeployed in `l1-bal-content.json`: `PUSH1 1 PUSH1 0
/// SSTORE STOP` — writes storage slot 0 from its genesis value (0) to 1.
const SSTORE_CONTRACT_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x55, 0x0c,
]);
/// Read-only contract predeployed in `l1-bal-content.json`: `PUSH1 0 SLOAD POP
/// STOP` — reads storage slot 0 (pre-seeded to 7) without writing anything.
const READER_CONTRACT_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x55, 0x11,
]);
const TEST_MAX_FEE_PER_GAS: u64 = 10_000_000_000;
const TEST_GAS_LIMIT: u64 = 5_000_000;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&hex::decode(SENDER_PRIVATE_KEY).unwrap()).unwrap()
}

fn sender_address() -> Address {
    LocalSigner::new(test_secret_key()).address
}

/// Loads `l1-bal-content.json` (Amsterdam-activated genesis with a funded
/// rich-account alloc plus a predeployed SSTORE contract) into a fresh
/// in-memory store. Returns the store and its chain id.
async fn setup_store() -> (Store, u64) {
    let file = File::open(workspace_root().join("fixtures/genesis/l1-bal-content.json"))
        .expect("open l1-bal-content genesis");
    let genesis: Genesis =
        serde_json::from_reader(BufReader::new(file)).expect("parse l1-bal-content genesis");
    let chain_id = genesis.config.chain_id;
    let mut store = Store::new("store.db", EngineType::InMemory).expect("build in-memory store");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    (store, chain_id)
}

/// Builds a block on top of `parent_header` from whatever is currently in the
/// mempool, together with the canonical BAL the producer recorded for it.
async fn build_block_with_txs(
    store: &Store,
    blockchain: &Blockchain,
    parent_header: &BlockHeader,
) -> (Block, BlockAccessList, Vec<Receipt>) {
    let args = BuildPayloadArgs {
        parent: parent_header.hash(),
        timestamp: parent_header.timestamp + 12,
        fee_recipient: H160::zero(),
        random: H256::zero(),
        withdrawals: Some(Vec::new()),
        beacon_root: Some(H256::zero()),
        // EIP-7843: Amsterdam headers must carry a slot_number, else header
        // validation rejects the block before the BAL content check under test.
        slot_number: Some(1),
        version: 1,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
    };
    let payload = create_payload(&args, store, Bytes::new()).unwrap();
    let result = blockchain.build_payload(payload).unwrap();
    let bal = result
        .block_access_list
        .expect("amsterdam block must produce a BAL");
    (result.payload, bal, result.receipts)
}

/// Recomputes the state root the parallel path's BAL-driven optimistic
/// merkleization would derive from `bal` alone, starting from `parent_header`.
/// This mirrors `Blockchain::handle_merkleization_bal_from_updates` (same
/// `synthesize_bal_updates` synthesis, same account-update application) minus
/// its sharded-worker performance optimization: the resulting Merkle root is a
/// pure function of the final account states, so this single-threaded replay
/// via public `Store` APIs reproduces the identical value production computes.
pub(crate) fn forge_state_root(
    store: &Store,
    parent_header: &BlockHeader,
    bal: &BlockAccessList,
) -> H256 {
    let synthesis = synthesize_bal_updates(bal);
    let updates: Vec<AccountUpdate> = synthesis
        .into_iter()
        .map(|(address, item)| {
            let prestate = store
                .get_account_state_by_root(parent_header.state_root, address)
                .expect("read prestate")
                .unwrap_or_default();
            let mut update = AccountUpdate::new(address);
            if item.balance.is_some() || item.nonce.is_some() || item.code_hash.is_some() {
                update.info = Some(AccountInfo {
                    balance: item.balance.unwrap_or(prestate.balance),
                    nonce: item.nonce.unwrap_or(prestate.nonce),
                    code_hash: item.code_hash.unwrap_or(prestate.code_hash),
                });
            }
            update.code = item.code;
            update.added_storage = item.added_storage;
            update
        })
        .collect();
    store
        .apply_account_updates_batch(parent_header.hash(), &updates)
        .expect("apply account updates")
        .expect("parent block must be in store")
        .state_trie_hash
}

/// Asserts `result` is an `Err` produced by the BAL content-validation path
/// (`EvmError::Custom`, the deferred `BalValidationError` wrapper), and that
/// its message contains `needle` (loosely pins down *which* check fired).
fn assert_content_rejected(result: &Result<Option<BlockAccessList>, ChainError>, needle: &str) {
    match result {
        Err(ChainError::EvmError(EvmError::Custom(msg))) => {
            assert!(
                msg.contains(needle),
                "expected rejection message to contain {needle:?}, got: {msg}"
            );
        }
        other => panic!("expected a content-validation EvmError::Custom, got: {other:?}"),
    }
}

fn parallel_blockchain(store: Store) -> Blockchain {
    Blockchain::new(
        store,
        BlockchainOptions {
            bal_parallel_exec_enabled: true,
            // These tests exercise BAL content validation, not mempool
            // admission policy, and their fixtures submit zero-tip txs
            // (`eip1559_tx` sets `max_priority_fee_per_gas: 0`). Opt out of the
            // min-tip floor so they stay decoupled from admission defaults —
            // raising the fixture's tip instead would change gas payment and
            // perturb the exact balance deltas these tests assert on.
            min_tip_wei: 0,
            ..Default::default()
        },
    )
}

/// Deploys and immediately self-destructs (EIP-6780 same-tx destruction) a
/// contract whose init code reads storage slot 0 (always 0 pre-deploy) before
/// selfdestructing. The genuine `SLOAD` gives the recorder a real storage_reads
/// entry for this destroyed account to exercise Phase 3's reconciliation.
fn create_sload_then_selfdestruct_init_code(beneficiary: Address) -> Bytes {
    let mut code = Vec::with_capacity(24);
    code.push(0x60); // PUSH1
    code.push(0x00); // 0
    code.push(0x54); // SLOAD
    code.push(0x50); // POP
    code.push(0x73); // PUSH20
    code.extend_from_slice(beneficiary.as_bytes());
    code.push(0xFF); // SELFDESTRUCT
    Bytes::from(code)
}

async fn sign(mut tx: Transaction, signer: &Signer) -> Transaction {
    tx.sign_inplace(signer).await.unwrap();
    tx
}

fn eip1559_tx(chain_id: u64, nonce: u64, to: TxKind, value: U256, data: Bytes) -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: TEST_MAX_FEE_PER_GAS,
        gas_limit: TEST_GAS_LIMIT,
        to,
        value,
        data,
        ..Default::default()
    })
}

// --- 4.4: no-op balance entry (Phase 1, finding #3/#4) ---

#[tokio::test]
async fn parallel_path_rejects_noop_balance_entry() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    // Build the valid block: a 0-value transfer from sender to RECIPIENT_ADDRESS.
    // RECIPIENT_ADDRESS gets touched (loaded into execution state) but its
    // balance is unaffected — a canonical recorder emits no balance_changes
    // entry for it (net-zero filtered).
    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(RECIPIENT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");
    assert_eq!(
        block.body.transactions.len(),
        1,
        "block must include the transfer tx"
    );

    let recipient_balance = build_store
        .get_account_state_by_root(genesis_header.state_root, RECIPIENT_ADDRESS)
        .unwrap()
        .expect("recipient must be prefunded in genesis")
        .balance;

    // Inject a spurious no-op BalanceChange for RECIPIENT_ADDRESS at bal_idx=1
    // (tx 0's index), claiming a "change" to exactly its pre-block balance.
    let mut accounts = bal.accounts().to_vec();
    if let Some(acc) = accounts.iter_mut().find(|a| a.address == RECIPIENT_ADDRESS) {
        acc.balance_changes = vec![BalanceChange::new(1, recipient_balance)];
    } else {
        accounts.push(
            AccountChanges::new(RECIPIENT_ADDRESS)
                .with_balance_changes(vec![BalanceChange::new(1, recipient_balance)]),
        );
    }
    let mutated_bal = Arc::new(BlockAccessList::from_accounts(accounts));

    // Root is unaffected: the injected entry's value equals the account's
    // existing (unchanged) balance, so the BAL-driven merkleization produces
    // the same trie leaf. Only the header BAL-hash commitment needs forging.
    let mut mutated_block = block.clone();
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(mutated_bal));
    assert_content_rejected(&par, "spurious no-op BAL balance change");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

// --- pre-exec (index 0) spurious entry: closes the gap @ilitteri flagged ---
//
// Index 0 carries the pre-block system calls (EIP-2935 block-hash history,
// EIP-4788 beacon root). It is validated by neither the per-tx path (indices
// 1..=n, `validate_tx_execution`) nor the withdrawal path (n+1,
// `validate_bal_withdrawal_index`). A spurious entry there for an account the
// pre-exec phase never touched leaves the BAL-derived state root unchanged (a
// no-op leaf), so before `validate_bal_pre_exec_index` the parallel path
// accepted it while the sequential/full-rebuild path rejects the same block.
#[tokio::test]
async fn parallel_path_rejects_pre_exec_entry_for_untouched_account() {
    // Untouched, unfunded address — never loaded during the pre-exec system
    // calls, so its pre-block balance is 0 and a `balance: 0` entry at index 0
    // is a no-op that does not move the state root.
    const SPURIOUS_ADDRESS: Address = H160([0x42; 20]);

    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    // Build a valid block (a 0-value transfer) + its canonical BAL, which
    // carries the genuine EIP-2935/4788 index-0 system-contract changes.
    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(RECIPIENT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");

    // Inject a spurious no-op balance change at the pre-exec index (0) for an
    // account the pre-exec phase never touched.
    let mut accounts = bal.accounts().to_vec();
    accounts.push(
        AccountChanges::new(SPURIOUS_ADDRESS)
            .with_balance_changes(vec![BalanceChange::new(0, U256::zero())]),
    );
    let mutated_bal = Arc::new(BlockAccessList::from_accounts(accounts));

    // Root unaffected (balance 0 for an empty account is a no-op leaf), so only
    // the header BAL-hash commitment needs forging.
    let mut mutated_block = block.clone();
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(mutated_bal));
    assert_content_rejected(&par, "was not touched by the pre-exec phase");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

// --- 4.1: no-op nonce entry (Phase 1) ---

#[tokio::test]
async fn parallel_path_rejects_noop_nonce_entry() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    // Same 0-value-transfer setup as the balance no-op test: RECIPIENT_ADDRESS
    // gets touched (loaded into execution state, nonce included) without
    // anything about it actually changing.
    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(RECIPIENT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");

    let recipient_nonce = build_store
        .get_account_state_by_root(genesis_header.state_root, RECIPIENT_ADDRESS)
        .unwrap()
        .expect("recipient must be prefunded in genesis")
        .nonce;

    // Inject a spurious no-op NonceChange for RECIPIENT_ADDRESS at bal_idx=1,
    // claiming a "change" to exactly its pre-block nonce.
    let mut accounts = bal.accounts().to_vec();
    if let Some(acc) = accounts.iter_mut().find(|a| a.address == RECIPIENT_ADDRESS) {
        acc.nonce_changes = vec![NonceChange::new(1, recipient_nonce)];
    } else {
        accounts.push(
            AccountChanges::new(RECIPIENT_ADDRESS)
                .with_nonce_changes(vec![NonceChange::new(1, recipient_nonce)]),
        );
    }
    let mutated_bal = Arc::new(BlockAccessList::from_accounts(accounts));

    // Root is unaffected (same reasoning as the balance no-op test): only the
    // header BAL-hash commitment needs forging.
    let mut mutated_block = block.clone();
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(mutated_bal));
    assert_content_rejected(&par, "spurious no-op BAL nonce change");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

// --- 4.1: no-op code entry (Phase 1) ---

#[tokio::test]
async fn parallel_path_rejects_noop_code_entry() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();
    let sstore_contract_code = Bytes::from_static(&[0x60, 0x01, 0x60, 0x00, 0x55, 0x00]);

    // A plain call to the (already-deployed) SSTORE contract loads its
    // existing code into execution state without changing it.
    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(SSTORE_CONTRACT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");

    // Inject a spurious no-op CodeChange for SSTORE_CONTRACT_ADDRESS at
    // bal_idx=1, claiming a "change" to exactly its pre-existing bytecode.
    let mut accounts = bal.accounts().to_vec();
    accounts
        .iter_mut()
        .find(|a| a.address == SSTORE_CONTRACT_ADDRESS)
        .expect("SSTORE contract must appear in the BAL")
        .code_changes = vec![CodeChange::new(1, sstore_contract_code)];
    let mutated_bal = Arc::new(BlockAccessList::from_accounts(accounts));

    // Root is unaffected: the injected code is byte-identical to the existing
    // deployed code, so the BAL-driven merkleization produces the same leaf.
    let mut mutated_block = block.clone();
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(mutated_bal));
    assert_content_rejected(&par, "spurious no-op BAL code change");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

// --- 4.1/4.2: no-op storage entry (Phase 1, matching arm) + genuine
//     read-only-slot control (Phase 2 cheap-skip path) ---

#[tokio::test]
async fn parallel_path_rejects_noop_storage_entry() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    // A call to READER_CONTRACT_ADDRESS SLOADs slot 0 (pre-seeded to 7)
    // without writing it: the slot ends up in execution state unchanged.
    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(READER_CONTRACT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");

    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == READER_CONTRACT_ADDRESS)
        .expect("reader contract must appear in the BAL");
    assert!(
        contract_changes.storage_reads.contains(&U256::zero()),
        "canonical BAL must record the genuine SLOAD(0) as a storage_reads entry, got: {contract_changes:?}"
    );
    assert!(
        contract_changes.storage_changes.is_empty(),
        "canonical BAL must NOT record a storage_changes entry for a pure read, got: {contract_changes:?}"
    );

    // Inject a spurious no-op StorageChange for slot 0 at bal_idx=1, claiming
    // a "change" to exactly its pre-block value (7).
    let mut accounts = bal.accounts().to_vec();
    accounts
        .iter_mut()
        .find(|a| a.address == READER_CONTRACT_ADDRESS)
        .unwrap()
        .storage_changes = vec![SlotChange::with_changes(
        U256::zero(),
        vec![StorageChange::new(1, U256::from(7))],
    )];
    let mutated_bal = Arc::new(BlockAccessList::from_accounts(accounts));

    // Root is unaffected: the injected value equals the slot's existing
    // (unchanged) value, so the BAL-driven merkleization produces the same leaf.
    let mut mutated_block = block.clone();
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(mutated_bal));
    assert_content_rejected(&par, "spurious no-op BAL storage change");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

#[tokio::test]
async fn parallel_path_accepts_read_only_slot_not_in_changes() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(READER_CONTRACT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");

    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == READER_CONTRACT_ADDRESS)
        .expect("reader contract must appear in the BAL");
    assert!(
        contract_changes.storage_reads.contains(&U256::zero()),
        "canonical BAL must record the genuine SLOAD(0) as a storage_reads entry, got: {contract_changes:?}"
    );
    assert!(
        contract_changes.storage_changes.is_empty(),
        "canonical BAL must NOT record a storage_changes entry for a pure read, got: {contract_changes:?}"
    );

    // Unmutated BAL: slot 0 is declared solely via storage_reads (genuinely
    // read, never written). Must be accepted via the cheap-skip path.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept a declared-read-only slot absent from storage_changes, got: {ok:?}"
    );
}

// --- 4.5: missing storage-write omission (Phase 2, finding #5) ---

/// Removing the SSTORE contract's entire slot-0 `storage_changes` entry from
/// the BAL is ALSO independently caught by the pre-existing "Group B"
/// shadow-reads check in `execute_block_parallel` (SSTORE unconditionally
/// records an implicit read for gas-refund accounting via
/// `record_storage_slot_to_bal`, so the shadow recorder sees this slot as
/// accessed regardless of Phase 2). `validate_tx_execution` (Phase 2) runs
/// FIRST in the deferred-error closure and short-circuits before Group B via
/// `?`, so on the real pipeline Phase 2's specific error is what actually
/// surfaces — asserted below via its exact message. This test still binds
/// Phase 2 (verified: with Phase 2 reverted, THIS assertion fails because
/// that exact message no longer appears — the block is still rejected, but
/// via Group B's differently-worded error instead). A real single-tx SSTORE
/// always trips Group B's implicit-read tracking, so a scenario where Phase 2
/// is the *sole* guard (no real transaction can omit a write from BOTH
/// storage_changes and storage_reads without the shadow recorder also having
/// logged the implicit read) could not be constructed with genuine EVM
/// execution; this e2e test instead locks in the real pipeline's end-to-end
/// rejection and specific error path for this malformed BAL.
#[tokio::test]
async fn parallel_path_rejects_omitted_storage_write() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(SSTORE_CONTRACT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");
    assert_eq!(
        block.body.transactions.len(),
        1,
        "block must include the SSTORE call"
    );

    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == SSTORE_CONTRACT_ADDRESS)
        .expect("SSTORE contract must appear in the BAL");
    assert!(
        contract_changes
            .storage_changes
            .iter()
            .any(|sc| sc.slot == U256::zero() && !sc.slot_changes.is_empty()),
        "canonical BAL must record the slot-0 write, got: {contract_changes:?}"
    );

    // Remove the storage_changes entry for slot 0 entirely — no storage_reads
    // entry either, so execution's write is declared nowhere in the BAL.
    let mut accounts = bal.accounts().to_vec();
    {
        let acc = accounts
            .iter_mut()
            .find(|a| a.address == SSTORE_CONTRACT_ADDRESS)
            .unwrap();
        acc.storage_changes.retain(|sc| sc.slot != U256::zero());
        assert!(!acc.storage_reads.contains(&U256::zero()));
    }
    let mutated_bal = BlockAccessList::from_accounts(accounts);

    // Omitting the write changes what the BAL-driven merkleization computes
    // (slot 0 stays at its pre-block value of 0 instead of 1): forge both
    // commitments so rejection comes from content validation.
    let mut mutated_block = block.clone();
    mutated_block.header.state_root = forge_state_root(&build_store, &genesis_header, &mutated_bal);
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(Arc::new(mutated_bal)));
    assert_content_rejected(&par, "has no storage_changes entry");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

/// Moving the SSTORE contract's slot-0 write from `storage_changes` into
/// `storage_reads` (mis-declaring a real write as a read) must be rejected on
/// the parallel path. Because SSTORE also records an implicit read, the shadow
/// recorder sees the slot as read AND written; the execution->BAL check must
/// subtract writes from the observed reads before deciding a slot is skippable,
/// otherwise this slot would be treated as a pure read, skipped, and then wave
/// through Group B (which only checks the slot is present in *some* list). Binds
/// that write-subtraction end-to-end.
#[tokio::test]
async fn parallel_path_rejects_write_misdeclared_as_read() {
    let signer: Signer = LocalSigner::new(test_secret_key()).into();

    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Call(SSTORE_CONTRACT_ADDRESS),
            U256::zero(),
            Bytes::new(),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");

    // Move slot 0 from storage_changes into storage_reads: the real write is
    // now mis-declared as a read.
    let mut accounts = bal.accounts().to_vec();
    {
        let acc = accounts
            .iter_mut()
            .find(|a| a.address == SSTORE_CONTRACT_ADDRESS)
            .unwrap();
        acc.storage_changes.retain(|sc| sc.slot != U256::zero());
        acc.storage_reads.push(U256::zero());
        acc.storage_reads.sort_unstable();
        acc.storage_reads.dedup();
    }
    let mutated_bal = BlockAccessList::from_accounts(accounts);

    // Same effect on merkleization as omitting the write (slot 0 stays at its
    // pre-block value of 0), so forge both commitments.
    let mut mutated_block = block.clone();
    mutated_block.header.state_root = forge_state_root(&build_store, &genesis_header, &mutated_bal);
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(Arc::new(mutated_bal)));
    assert_content_rejected(&par, "declared_as_read=true");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

// --- 4.5: selfdestruct phantom-read fix (Phase 3, finding #2) + control ---

#[tokio::test]
async fn parallel_path_rejects_phantom_read_on_selfdestruct() {
    let sender = sender_address();
    let signer: Signer = LocalSigner::new(test_secret_key()).into();
    let beneficiary = Address::from_low_u64_be(0xBEEF);
    let contract_address = calculate_create_address(sender, 0);

    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Create,
            U256::zero(),
            create_sload_then_selfdestruct_init_code(beneficiary),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");
    assert_eq!(
        block.body.transactions.len(),
        1,
        "block must include the create+selfdestruct tx"
    );

    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == contract_address)
        .expect("selfdestructed contract must appear in the BAL");
    assert!(
        contract_changes.storage_reads.contains(&U256::zero()),
        "canonical BAL must record the genuine SLOAD(0) as a storage_reads entry, got: {contract_changes:?}"
    );

    // Add a phantom storage_reads entry (slot 1) that this tx never actually
    // read. storage_reads doesn't feed the BAL-driven merkleization, so the
    // state root is unaffected — only the BAL-hash commitment needs forging.
    let mut accounts = bal.accounts().to_vec();
    accounts
        .iter_mut()
        .find(|a| a.address == contract_address)
        .unwrap()
        .storage_reads
        .push(U256::one());
    let mutated_bal = BlockAccessList::from_accounts(accounts);

    let mut mutated_block = block.clone();
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(Arc::new(mutated_bal)));
    assert_content_rejected(&par, "was never actually read");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}

#[tokio::test]
async fn parallel_path_accepts_real_read_on_selfdestruct() {
    let sender = sender_address();
    let signer: Signer = LocalSigner::new(test_secret_key()).into();
    let beneficiary = Address::from_low_u64_be(0xBEEF);
    let contract_address = calculate_create_address(sender, 0);

    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(
            chain_id,
            0,
            TxKind::Create,
            U256::zero(),
            create_sload_then_selfdestruct_init_code(beneficiary),
        ),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");
    assert_eq!(
        block.body.transactions.len(),
        1,
        "block must include the create+selfdestruct tx"
    );

    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == contract_address)
        .expect("selfdestructed contract must appear in the BAL");
    assert!(
        contract_changes.storage_reads.contains(&U256::zero()),
        "canonical BAL must record the genuine SLOAD(0) as a storage_reads entry, got: {contract_changes:?}"
    );

    // Unmutated BAL: the destroyed account's storage_reads entry (slot 0) was
    // genuinely read before selfdestruct. Must be accepted.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept a genuinely-read-then-destroyed slot, got: {ok:?}"
    );
}

// --- 4.6: missing code-change omission on CREATE (already-fixed finding #1) ---

#[tokio::test]
async fn parallel_path_rejects_missing_code_change() {
    let sender = sender_address();
    let signer: Signer = LocalSigner::new(test_secret_key()).into();
    let contract_address = calculate_create_address(sender, 0);
    // Deploys a 1-byte runtime (a single STOP, 0x00): init code CODECOPYs the
    // trailing byte into memory and RETURNs it. A RETURN of *empty* code would
    // be a legitimate code no-op (pre/post code_hash both EMPTY_KECCAK_HASH,
    // correctly filtered by Phase 1) — this must actually deploy non-empty
    // code so the canonical BAL's code_changes entry is a genuine change.
    let init_code = Bytes::from(vec![
        0x60, 0x01, // PUSH1 1 (runtime len)
        0x60, 0x0c, // PUSH1 12 (offset of runtime bytes within this init code)
        0x60, 0x00, // PUSH1 0 (dest memory offset)
        0x39, // CODECOPY
        0x60, 0x01, // PUSH1 1 (return len)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        0x00, // runtime: STOP
    ]);

    let (build_store, chain_id) = setup_store().await;
    let build_blockchain = parallel_blockchain(build_store.clone());
    let genesis_header = build_store.get_block_header(0).unwrap().unwrap();
    let tx = sign(
        eip1559_tx(chain_id, 0, TxKind::Create, U256::zero(), init_code),
        &signer,
    )
    .await;
    build_blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("tx should enter pool");
    let (block, bal, receipts) =
        build_block_with_txs(&build_store, &build_blockchain, &genesis_header).await;
    assert!(receipts[0].succeeded, "tx must succeed, got: {receipts:?}");
    assert_eq!(
        block.body.transactions.len(),
        1,
        "block must include the CREATE tx"
    );

    let contract_changes = bal
        .accounts()
        .iter()
        .find(|a| a.address == contract_address)
        .expect("created contract must appear in the BAL");
    assert!(
        !contract_changes.code_changes.is_empty(),
        "canonical BAL must record the deployed code, got: {contract_changes:?}"
    );

    // Remove the code_changes entry entirely: the BAL now claims the created
    // account has no code, while execution actually deployed some.
    let mut accounts = bal.accounts().to_vec();
    accounts
        .iter_mut()
        .find(|a| a.address == contract_address)
        .unwrap()
        .code_changes
        .clear();
    let mutated_bal = BlockAccessList::from_accounts(accounts);

    // Omitting the code changes what the BAL-driven merkleization computes
    // (code_hash reverts to empty instead of the deployed contract's hash):
    // forge both commitments so rejection comes from content validation.
    let mut mutated_block = block.clone();
    mutated_block.header.state_root = forge_state_root(&build_store, &genesis_header, &mutated_bal);
    mutated_block.header.block_access_list_hash = Some(mutated_bal.compute_hash(&NativeCrypto));

    let (store_par, _) = setup_store().await;
    let bc_par = parallel_blockchain(store_par);
    let par = bc_par.add_block_pipeline_bal(mutated_block, Some(Arc::new(mutated_bal)));
    assert_content_rejected(&par, "code changed by execution but BAL has no code change");

    // Positive control: the unmutated block must still import.
    let (store_ok, _) = setup_store().await;
    let bc_ok = parallel_blockchain(store_ok);
    let ok = bc_ok.add_block_pipeline_bal(block, Some(Arc::new(bal)));
    assert!(
        ok.is_ok(),
        "parallel path must accept the unmutated block, got: {ok:?}"
    );
}
