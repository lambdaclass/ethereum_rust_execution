//! Test utilities for the ethrex-rpc crate.
//!
//! This module provides helper functions and test fixtures for testing RPC functionality.
//! It is primarily intended for use in integration tests.

#![allow(clippy::unwrap_used)]

use crate::{
    eth::gas_tip_estimator::GasTipEstimator,
    rpc::{
        ClientVersion, NodeData, RpcApiContext, handle_authrpc_request, handle_http_request,
        start_api, start_block_executor,
    },
    utils::RpcNamespace,
};
use axum::extract::State;
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use bytes::Bytes;
use ethrex_blockchain::Blockchain;
use ethrex_common::{
    Address, Bloom, H256, H512, U256,
    constants::DEFAULT_REQUESTS_HASH,
    types::{
        Block, BlockBody, BlockHeader, DEFAULT_BUILDER_GAS_CEIL, EIP1559Transaction, Genesis,
        LegacyTransaction, Transaction, TxKind,
    },
};
use ethrex_p2p::{
    network::P2PContext,
    peer_handler::PeerHandler,
    peer_table::{PeerTable, PeerTableServer, TARGET_PEERS},
    rlpx::initiator::RLPxInitiator,
    sync::{BackfillConfig, HistoryChain, SyncMode},
    sync_manager::SyncManager,
    types::{LocalNode, NetworkConfig, Node, NodeRecord, SharedLocalNode},
};
use ethrex_storage::{EngineType, Store};
use hex_literal::hex;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use secp256k1::SecretKey;
use serde_json::Value;
use spawned_concurrency::tasks::ActorRef;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashSet, net::SocketAddr, str::FromStr};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
// Base price for each test transaction.
pub const BASE_PRICE_IN_WEI: u64 = 10_u64.pow(9);
pub const TEST_GENESIS: &str = include_str!("../../../fixtures/genesis/l1.json");

fn test_header(block_num: u64) -> BlockHeader {
    BlockHeader {
        parent_hash: H256::from_str(
            "0x1ac1bf1eef97dc6b03daba5af3b89881b7ae4bc1600dc434f450a9ec34d44999",
        )
        .unwrap(),
        ommers_hash: H256::from_str(
            "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        )
        .unwrap(),
        coinbase: Address::from_str("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba").unwrap(),
        state_root: H256::from_str(
            "0x9de6f95cb4ff4ef22a73705d6ba38c4b927c7bca9887ef5d24a734bb863218d9",
        )
        .unwrap(),
        transactions_root: H256::from_str(
            "0x578602b2b7e3a3291c3eefca3a08bc13c0d194f9845a39b6f3bcf843d9fed79d",
        )
        .unwrap(),
        receipts_root: H256::from_str(
            "0x035d56bac3f47246c5eed0e6642ca40dc262f9144b582f058bc23ded72aa72fa",
        )
        .unwrap(),
        logs_bloom: Bloom::from([0; 256]),
        difficulty: U256::zero(),
        number: block_num,
        gas_limit: 0x016345785d8a0000,
        gas_used: 0xa8de,
        timestamp: 0x03e8,
        extra_data: Bytes::new(),
        prev_randao: H256::zero(),
        nonce: 0x0000000000000000,
        base_fee_per_gas: Some(BASE_PRICE_IN_WEI),
        withdrawals_root: Some(
            H256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                .unwrap(),
        ),
        blob_gas_used: Some(0x00),
        excess_blob_gas: Some(0x00),
        parent_beacon_block_root: Some(H256::zero()),
        requests_hash: Some(*DEFAULT_REQUESTS_HASH),
        ..Default::default()
    }
}

async fn add_blocks_with_transactions(
    storage: &Store,
    block_count: u64,
    txs_per_block: Vec<Transaction>,
) {
    let mut new_canonical_blocks = vec![];
    for block_num in 1..=block_count {
        let block_body = BlockBody {
            transactions: txs_per_block.clone(),
            ommers: Default::default(),
            withdrawals: Default::default(),
        };
        let block_header = test_header(block_num);
        let block = Block::new(block_header.clone(), block_body);
        storage.add_block(block).await.unwrap();
        new_canonical_blocks.push((block_num, block_header.hash()));
    }
    let Some((last_number, last_hash)) = new_canonical_blocks.pop() else {
        return;
    };
    storage
        .forkchoice_update(new_canonical_blocks, last_number, last_hash, None, None)
        .await
        .unwrap();
}

fn legacy_tx_for_test(nonce: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        nonce,
        gas_price: U256::from(nonce) * U256::from(BASE_PRICE_IN_WEI),
        gas: 10000,
        to: TxKind::Create,
        value: 100.into(),
        data: Default::default(),
        v: U256::from(0x1b),
        r: U256::from_big_endian(&hex!(
            "7e09e26678ed4fac08a249ebe8ed680bf9051a5e14ad223e4b2b9d26e0208f37"
        )),
        s: U256::from_big_endian(&hex!(
            "5f6e3f188e3e6eab7d7d3b6568f5eac7d687b08d307d3154ccd8c87b4630509b"
        )),
        ..Default::default()
    })
}
fn eip1559_tx_for_test(nonce: u64) -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce,
        max_fee_per_gas: nonce * BASE_PRICE_IN_WEI,
        // This is less than gas_price in legacy txs because we should add base_fee to it
        // base_fee is 10^9, so (nonce - 1) * 10^9 + base_fee equals the legacy gas_price
        // for the same nonce. For consistency, we use the same value here.
        max_priority_fee_per_gas: (nonce - 1) * BASE_PRICE_IN_WEI,
        gas_limit: 10000,
        to: TxKind::Create,
        value: 100.into(),
        data: Default::default(),
        access_list: vec![],
        signature_y_parity: true,
        signature_r: U256::default(),
        signature_s: U256::default(),
        ..Default::default()
    })
}

/// A store on the Amsterdam-activated genesis, for tests that need EIP-7928 (BAL) or
/// EIP-8037 (2D gas) behaviour. Flipping `amsterdam_time` on [`setup_store`]'s genesis is
/// not enough: that fixture lacks the Amsterdam system predeploys, so the first
/// pre-execution system call fails with "has no code after deployment".
pub async fn setup_store_amsterdam() -> Store {
    let genesis: &str = include_str!("../../../fixtures/genesis/l1-bal.json");
    let genesis: Genesis = serde_json::from_str(genesis).expect("Fatal: test config is invalid");
    let mut store =
        Store::new("test-store", EngineType::InMemory).expect("Fail to create in-memory db test");
    store.add_initial_state(genesis).await.unwrap();
    store
}

pub async fn setup_store() -> Store {
    let genesis: &str = include_str!("../../../fixtures/genesis/l1.json");
    let genesis: Genesis = serde_json::from_str(genesis).expect("Fatal: test config is invalid");
    let mut store =
        Store::new("test-store", EngineType::InMemory).expect("Fail to create in-memory db test");
    store.add_initial_state(genesis).await.unwrap();
    store
}

pub async fn add_legacy_tx_blocks(storage: &Store, block_count: u64, tx_count: u64) {
    for block_num in 1..=block_count {
        let mut txs = vec![];
        for nonce in 1..=tx_count {
            txs.push(legacy_tx_for_test(nonce));
        }
        add_blocks_with_transactions(storage, block_num, txs).await;
    }
}

pub async fn add_eip1559_tx_blocks(storage: &Store, block_count: u64, tx_count: u64) {
    for block_num in 1..=block_count {
        let mut txs = vec![];
        for nonce in 1..=tx_count {
            txs.push(eip1559_tx_for_test(nonce));
        }
        add_blocks_with_transactions(storage, block_num, txs).await;
    }
}

pub async fn add_mixed_tx_blocks(storage: &Store, block_count: u64, tx_count: u64) {
    for block_num in 1..=block_count {
        let mut txs = vec![];
        for nonce in 1..=tx_count {
            if nonce % 2 == 0 {
                txs.push(legacy_tx_for_test(nonce));
            } else {
                txs.push(eip1559_tx_for_test(nonce));
            }
        }
        add_blocks_with_transactions(storage, block_num, txs).await;
    }
}

pub async fn add_empty_blocks(storage: &Store, block_count: u64) {
    for block_num in 1..=block_count {
        add_blocks_with_transactions(storage, block_num, vec![]).await;
    }
}

pub fn example_p2p_node() -> Node {
    let public_key_1 = H512::from_str("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666").unwrap();
    Node::new("127.0.0.1".parse().unwrap(), 30303, 30303, public_key_1)
}

pub fn example_local_node_record() -> NodeRecord {
    let public_key_1 = H512::from_str("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666").unwrap();
    let node = Node::new("127.0.0.1".parse().unwrap(), 30303, 30303, public_key_1);
    let signer = SecretKey::new(&mut rand::rngs::OsRng);

    NodeRecord::from_node(&node, 1, &signer).unwrap()
}

pub fn example_shared_local_node() -> SharedLocalNode {
    let node = example_p2p_node();
    let record = example_local_node_record();
    Arc::new(RwLock::new(LocalNode { node, record }))
}

// Util to start an api for testing on ports 8500 and 8501,
// mostly for when hive is missing some endpoints to test
// like eth_uninstallFilter.
// Here's how you would use it:
// ```
// let server_handle = start_stest_api().await;
// ...
// assert!(something_that_needs_the_server);
// ...
// server_handle.abort();
// ```
pub async fn start_test_api() -> tokio::task::JoinHandle<()> {
    let http_addr: SocketAddr = "127.0.0.1:8500".parse().unwrap();
    let authrpc_addr: SocketAddr = "127.0.0.1:8501".parse().unwrap();
    let mut storage =
        Store::new("", EngineType::InMemory).expect("Failed to create in-memory storage");
    storage
        .add_initial_state(serde_json::from_str(TEST_GENESIS).unwrap())
        .await
        .expect("Failed to build test genesis");
    let blockchain = Arc::new(Blockchain::for_test_harness(storage.clone()));
    let jwt_secret = Default::default();
    let shared_local_node = example_shared_local_node();
    tokio::spawn(async move {
        start_api(
            http_addr,
            None,
            authrpc_addr,
            storage.clone(),
            blockchain.clone(),
            jwt_secret,
            shared_local_node,
            dummy_sync_manager().await,
            dummy_peer_handler(storage).await,
            ClientVersion::new(
                "ethrex".to_string(),
                "0.1.0".to_string(),
                "test".to_string(),
                "abcd1234".to_string(),
                "x86_64-unknown-linux".to_string(),
                "1.70.0".to_string(),
            ),
            None,
            DEFAULT_BUILDER_GAS_CEIL,
            String::new(),
            all_namespaces_for_tests(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap()
    })
}

/// All known namespaces, used in tests so handlers from any namespace can be exercised.
pub fn all_namespaces_for_tests() -> HashSet<RpcNamespace> {
    HashSet::from([
        RpcNamespace::Eth,
        RpcNamespace::Net,
        RpcNamespace::Web3,
        RpcNamespace::Debug,
        RpcNamespace::Admin,
        RpcNamespace::Mempool,
        RpcNamespace::Testing,
    ])
}

/// An [`RpcApiContext`] that reclaims its threads when it drops.
///
/// A context owns a `block_executor` OS thread, and that thread holds a strong
/// reference to the `Blockchain` (and so to any merkleization pool it built). The
/// thread does exit once every sender is dropped, but asynchronously: a full
/// test-binary run creates threads faster than the OS reaps them, and the backlog
/// can cross the macOS runner's per-task thread cap, aborting the whole process
/// with `libc++abi: terminating`.
///
/// Dropping this guard is synchronous instead: it releases the context (dropping
/// the last sender) and then joins the executor thread, so a test's threads are
/// gone before the next test starts.
///
/// Derefs to [`RpcApiContext`], so field access and method calls work unchanged.
/// Note that cloning the inner context out and storing it past the guard's own
/// lifetime keeps a sender alive; the join is bounded by
/// [`TEARDOWN_JOIN_TIMEOUT`] so that mistake panics with an explanation instead
/// of hanging the test with no output.
pub struct TestContext {
    /// `Option` so `Drop` can release the context strictly before joining.
    context: Option<RpcApiContext>,
    executor: Option<std::thread::JoinHandle<()>>,
}

impl TestContext {
    /// Consume the guard and return the inner context, leaving the
    /// `block_executor` thread detached.
    ///
    /// For the rare test that must *own* an [`RpcApiContext`] by value — e.g. to
    /// embed it in another struct — where holding the guard alongside it would
    /// mean depending on drop order to avoid a hang. Teardown reverts to being
    /// asynchronous here, so prefer holding the guard wherever a test can.
    pub fn into_detached(mut self) -> RpcApiContext {
        // Dropping the handle detaches the thread; `Drop` then has nothing to join.
        self.executor = None;
        self.context
            .take()
            .expect("TestContext is only taken apart in Drop")
    }
}

impl std::ops::Deref for TestContext {
    type Target = RpcApiContext;

    fn deref(&self) -> &RpcApiContext {
        self.context
            .as_ref()
            .expect("TestContext is only taken apart in Drop")
    }
}

impl std::ops::DerefMut for TestContext {
    fn deref_mut(&mut self) -> &mut RpcApiContext {
        self.context
            .as_mut()
            .expect("TestContext is only taken apart in Drop")
    }
}

/// How long [`TestContext`]'s drop waits for the `block_executor` thread before
/// giving up and reporting a leaked context.
///
/// An idle executor exits as soon as its last sender drops, so the normal wait is
/// microseconds; this only has to be longer than the slowest in-flight block
/// import in the suite. Generous, because the cost is paid only when a test is
/// already broken.
pub const TEARDOWN_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl Drop for TestContext {
    fn drop(&mut self) {
        // Order matters: the executor loop ends when its last sender goes away, so
        // the context has to be released before the join can return.
        drop(self.context.take());
        let Some(executor) = self.executor.take() else {
            return;
        };
        // An unbounded `join` here is a hang, not a failure: a surviving clone of the
        // inner `RpcApiContext` holds a `block_worker_channel` sender open, so the
        // executor loop never ends. On the default single-threaded `#[tokio::test]`
        // runtime it can never end, because a spawned task holding that clone cannot
        // be polled while this thread blocks. Bound the wait so the mistake reports
        // itself with a diagnosis instead of a silent timeout.
        let deadline = std::time::Instant::now() + TEARDOWN_JOIN_TIMEOUT;
        while !executor.is_finished() {
            if std::time::Instant::now() >= deadline {
                // Already unwinding: a second panic would abort the process and bury
                // the failure the test was actually reporting. Leave the thread
                // detached and let the real error through.
                if std::thread::panicking() {
                    return;
                }
                panic!(
                    "TestContext teardown timed out after {TEARDOWN_JOIN_TIMEOUT:?}: the \
                     block_executor thread is still alive, so a clone of the inner \
                     RpcApiContext outlived the guard and is holding its \
                     block_worker_channel sender open. Keep the guard alive for the whole \
                     test, or call `into_detached()` if the context must be owned by value."
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // A panicking executor thread is reported by whatever test awaited its
        // result; failing here would mask that with a teardown panic.
        let _ = executor.join();
    }
}

pub async fn default_context_with_storage(storage: Store) -> TestContext {
    let blockchain = Arc::new(Blockchain::for_test_harness(storage.clone()));
    let (block_worker_channel, executor) = start_block_executor(blockchain.clone());
    let context = RpcApiContext {
        storage: storage.clone(),
        blockchain: blockchain.clone(),
        active_filters: Default::default(),
        syncer: Some(Arc::new(dummy_sync_manager().await)),
        peer_handler: Some(dummy_peer_handler(storage).await),
        node_data: NodeData {
            jwt_secret: Default::default(),
            shared_local_node: example_shared_local_node(),
            client_version: ClientVersion::new(
                "ethrex".to_string(),
                "0.1.0".to_string(),
                "test".to_string(),
                "abcd1234".to_string(),
                "x86_64-unknown-linux".to_string(),
                "1.70.0".to_string(),
            ),
            extra_data: Bytes::new(),
        },
        gas_tip_estimator: Arc::new(TokioMutex::new(GasTipEstimator::new())),
        log_filter_handler: None,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
        block_worker_channel,
        ws: None,
        allowed_namespaces: Arc::new(all_namespaces_for_tests()),
    };
    TestContext {
        context: Some(context),
        executor: Some(executor),
    }
}

/// Creates a dummy SyncManager for tests where syncing is not needed
/// This should only be used in tests as it won't be able to connect to the p2p network
pub async fn dummy_sync_manager() -> SyncManager {
    let store = Store::new("", EngineType::InMemory).expect("Failed to start Store Engine");
    let blockchain = Arc::new(Blockchain::for_test_harness(store.clone()));
    SyncManager::new(
        dummy_peer_handler(store).await,
        &SyncMode::Full,
        CancellationToken::new(),
        blockchain,
        Store::new("temp.db", ethrex_storage::EngineType::InMemory)
            .expect("Failed to start Storage Engine"),
        ".".into(),
        BackfillConfig {
            mode: HistoryChain::Off,
            tx_index_horizon: 0,
        },
        TaskTracker::new(),
    )
    .await
}

/// Creates a dummy PeerHandler for tests where interacting with peers is not needed
/// This should only be used in tests as it won't be able to interact with the node's connected peers
pub async fn dummy_peer_handler(store: Store) -> PeerHandler {
    let peer_table = PeerTableServer::spawn(H256::random(), TARGET_PEERS, store);
    PeerHandler::new(peer_table.clone(), dummy_actor(peer_table).await)
}

/// Creates a dummy RLPx initiator actor for tests
/// This should only be used in tests
pub async fn dummy_actor(peer_table: PeerTable) -> ActorRef<RLPxInitiator> {
    RLPxInitiator::spawn_on_thread(dummy_p2p_context(peer_table).await)
}

/// Creates a dummy P2PContext for tests
/// This should only be used in tests as it won't be able to connect to the p2p network
pub async fn dummy_p2p_context(peer_table: PeerTable) -> P2PContext {
    let local_node = Node::from_enode_url(
        "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    ).expect("Bad enode url");
    let network_config = NetworkConfig::from_node(&local_node);
    let storage = Store::new("./temp", EngineType::InMemory).expect("Failed to create Store");

    P2PContext::new(
        local_node,
        network_config,
        TaskTracker::default(),
        SecretKey::from_byte_array(&[0xcd; 32]).expect("32 bytes, within curve order"),
        peer_table,
        storage.clone(),
        Arc::new(Blockchain::for_test_harness(storage)),
        "".to_string(),
        None,
        1000,
        100.0,
    )
    .unwrap()
}

/// Mint a valid bearer header for the given context's JWT secret, with a
/// fresh `iat` claim. For integration tests of the engine RPC port.
pub fn jwt_auth_header_for(context: &RpcApiContext) -> Option<TypedHeader<Authorization<Bearer>>> {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({ "iat": iat }),
        &EncodingKey::from_secret(&context.node_data.jwt_secret),
    )
    .unwrap();
    Some(TypedHeader(Authorization::bearer(&token).unwrap()))
}

/// Drive the auth RPC handler without needing axum extractor types at the
/// call site.
pub async fn call_authrpc(
    context: &RpcApiContext,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    body: String,
) -> Value {
    handle_authrpc_request(State(context.clone()), auth_header, body)
        .await
        .expect("handle_authrpc_request should not return a status code error")
        .0
}

/// Drive the public HTTP RPC handler without needing axum extractor types at
/// the call site.
pub async fn call_http(context: &RpcApiContext, body: String) -> Value {
    handle_http_request(State(context.clone()), body)
        .await
        .expect("handle_http_request should not return a status code error")
        .0
}

// ── eth/72 (EIP-8070) internal-fn shims ─────────────────────────────────────
//
// These re-expose crate-private parsing/handling internals to the integration
// test crate WITHOUT widening the production public API: the whole `test_utils`
// module is compiled only under `#[cfg(any(test, feature = "test-utils"))]`, so
// these shims do not exist in a normal build.
use crate::engine::blobs::BlobsV4Request;
use crate::types::fork_choice::{ForkChoiceState, PayloadAttributesV4};
use crate::utils::RpcErr;

/// Max blob hashes per `engine_getBlobs*` request (mirror of the crate-private const).
pub const GET_BLOBS_V1_REQUEST_MAX_SIZE: usize =
    crate::engine::blobs::GET_BLOBS_V1_REQUEST_MAX_SIZE;

/// Shim over the crate-private `engine::fork_choice::parse_v4`.
pub fn parse_v4(
    params: &Option<Vec<Value>>,
) -> Result<(ForkChoiceState, Option<PayloadAttributesV4>, Option<u128>), RpcErr> {
    crate::engine::fork_choice::parse_v4(params)
}

/// Shim over the crate-private `engine::fork_choice::parse_custody_columns`.
pub fn parse_custody_columns(value: &Value) -> Result<Option<u128>, RpcErr> {
    crate::engine::fork_choice::parse_custody_columns(value)
}

/// Shim over the crate-private `engine::fork_choice::apply_custody_update`.
pub fn apply_custody_update(context: &RpcApiContext, custody_columns: Option<u128>) {
    crate::engine::fork_choice::apply_custody_update(context, custody_columns)
}

/// Shim over the crate-private `engine::blobs::parse_indices_bitarray`.
pub fn parse_indices_bitarray(value: &Value) -> Result<u128, RpcErr> {
    crate::engine::blobs::parse_indices_bitarray(value)
}

/// Construct a `BlobsV4Request` from its parts (the struct fields are crate-private).
pub fn blobs_v4_request(
    versioned_blob_hashes: Vec<H256>,
    indices_bitarray: u128,
) -> BlobsV4Request {
    BlobsV4Request {
        versioned_blob_hashes,
        indices_bitarray,
    }
}
