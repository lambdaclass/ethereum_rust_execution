//! Regression tests for the FCU/newPayload ordering race in sync scheduling.
//!
//! Post-ePBS consensus clients move their forkchoice head to a payload hash they
//! learned from a bid before the payload itself reaches the EL through
//! `engine_newPayload` (envelope gossip lags the block). A node that was following
//! the tip and receives such an FCU must not pay for a peer-download sync cycle:
//! peers do not have the block yet either, and the payload arrives through the
//! engine moments later (measured 10-13s on glamsterdam-devnet-7, 132 out of 132
//! occurrences over 6h — each of which burned a 12-17s sync cycle that ended up
//! re-downloading and re-executing what `engine_newPayload` had already applied).
//!
//! The fix is two-layered and these tests pin both:
//! - the sync manager waits (bounded) for the head to arrive through the engine
//!   before starting a cycle, but only when the node was recently at the tip;
//! - a sync cycle that does start ends as soon as the head is executed locally
//!   (`sync_head_executed` checked at entry and between peer retries).

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain,
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{
    H160, H256,
    types::{Block, BlockHeader, DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis},
};
use ethrex_p2p::sync::{BackfillConfig, HistoryChain, SyncMode, sync_head_executed};
use ethrex_p2p::sync_manager::SyncManager;
use ethrex_rpc::test_utils::dummy_peer_handler;
use ethrex_storage::{EngineType, Store};
use ethrex_trie::EMPTY_TRIE_HASH;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn store_with_genesis() -> Store {
    let genesis_file = include_bytes!("../../../fixtures/genesis/l1.json");
    let genesis: Genesis = serde_json::from_slice(genesis_file).unwrap();
    let mut store = Store::new("", EngineType::InMemory).unwrap();
    store.add_initial_state(genesis).await.unwrap();
    store
}

/// Builds (but does not import) an empty block on `parent` with the given timestamp.
fn build_child_block(
    blockchain: &Blockchain,
    store: &Store,
    parent: &BlockHeader,
    timestamp: u64,
) -> Block {
    let args = BuildPayloadArgs {
        parent: parent.hash(),
        timestamp,
        fee_recipient: H160::random(),
        random: parent.prev_randao,
        withdrawals: Some(Vec::new()),
        beacon_root: Some(H256::random()),
        slot_number: None,
        version: 3,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
    };
    let payload = create_payload(&args, store, Bytes::new()).unwrap();
    blockchain.build_payload(payload).unwrap().payload
}

/// Store + blockchain whose canonical tip is a freshly-timestamped block 1, so the
/// node qualifies as "recently at the tip" for the pre-cycle heal wait.
async fn chain_at_fresh_tip() -> (Store, Arc<Blockchain>, BlockHeader) {
    let store = store_with_genesis().await;
    let blockchain = Arc::new(Blockchain::default_with_store(store.clone()));
    let genesis_header = store.get_block_header(0).unwrap().unwrap();
    let block1 = build_child_block(&blockchain, &store, &genesis_header, now_secs());
    let block1_hash = block1.hash();
    blockchain.add_block(block1).unwrap();
    store
        .forkchoice_update(vec![(1, block1_hash)], 1, block1_hash, None, None)
        .await
        .unwrap();
    let tip = store.get_block_header(1).unwrap().unwrap();
    (store, blockchain, tip)
}

async fn sync_manager_for(store: &Store, blockchain: Arc<Blockchain>) -> SyncManager {
    SyncManager::new(
        dummy_peer_handler().await,
        &SyncMode::Full,
        CancellationToken::new(),
        blockchain,
        store.clone(),
        ".".into(),
        // This test exercises the FCU/newPayload heal wait, not backfill.
        BackfillConfig {
            mode: HistoryChain::Off,
            tx_index_horizon: 0,
        },
        TaskTracker::new(),
    )
    .await
}

#[tokio::test]
async fn sync_head_executed_reflects_local_state() {
    let store = Store::new("", EngineType::InMemory).unwrap();
    // Unknown hash: not executed.
    assert!(!sync_head_executed(&store, H256::random()).unwrap());
    // Header known, state absent: not executed.
    let stateless = BlockHeader {
        number: 1,
        state_root: H256::from_low_u64_be(0xdead),
        ..Default::default()
    };
    // Header known, state present (the empty trie root always "exists"): executed.
    let stateful = BlockHeader {
        number: 2,
        state_root: EMPTY_TRIE_HASH,
        ..Default::default()
    };
    store
        .add_block_headers(vec![stateless.clone(), stateful.clone()])
        .await
        .unwrap();
    assert!(!sync_head_executed(&store, stateless.hash()).unwrap());
    assert!(sync_head_executed(&store, stateful.hash()).unwrap());
}

/// The production race: a node at the tip gets an FCU for a head whose payload
/// arrives through `engine_newPayload` about a second later. No sync cycle may
/// start — the head heals locally during the manager's bounded wait.
#[tokio::test(flavor = "multi_thread")]
async fn fcu_before_newpayload_race_starts_no_sync_cycle() {
    let (store, blockchain, tip) = chain_at_fresh_tip().await;
    let sync_manager = sync_manager_for(&store, blockchain.clone()).await;

    // The CL announces a head we have never seen (payload still in flight).
    let block2 = build_child_block(&blockchain, &store, &tip, tip.timestamp + 12);
    sync_manager.sync_to_head(block2.hash());

    // The payload arrives through the engine shortly after, as measured on the devnet.
    tokio::time::sleep(Duration::from_secs(1)).await;
    blockchain.add_block(block2).unwrap();

    // Give the manager time to notice the heal (poll interval is 500ms).
    tokio::time::sleep(Duration::from_secs(3)).await;
    let cycles = sync_manager
        .get_sync_diagnostics()
        .await
        .sync_cycles_started;
    assert_eq!(
        cycles, 0,
        "a head that arrived via engine_newPayload must not cost a sync cycle"
    );
}

/// A cold node (nothing executed beyond genesis) must not be delayed by the heal
/// wait: an unknown head starts a sync cycle immediately.
#[tokio::test(flavor = "multi_thread")]
async fn cold_node_starts_sync_cycle_without_heal_delay() {
    let store = store_with_genesis().await;
    let blockchain = Arc::new(Blockchain::default_with_store(store.clone()));
    let sync_manager = sync_manager_for(&store, blockchain).await;

    sync_manager.sync_to_head(H256::random());

    // Well under NEWPAYLOAD_HEAL_WAIT: the cycle must already have started.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if sync_manager
            .get_sync_diagnostics()
            .await
            .sync_cycles_started
            >= 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cold node should start a sync cycle immediately (heal wait must not apply)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A head that never arrives through the engine must still be synced from peers:
/// the heal wait is bounded, after which a real cycle starts.
#[tokio::test(flavor = "multi_thread")]
async fn missing_head_still_starts_sync_cycle_after_heal_wait() {
    let (store, blockchain, _tip) = chain_at_fresh_tip().await;
    let sync_manager = sync_manager_for(&store, blockchain).await;

    sync_manager.sync_to_head(H256::random());

    // NEWPAYLOAD_HEAL_WAIT is 15s; poll a little past it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if sync_manager
            .get_sync_diagnostics()
            .await
            .sync_cycles_started
            >= 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the heal wait must be bounded: a genuinely missing head still syncs"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
