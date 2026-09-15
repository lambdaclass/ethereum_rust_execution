use crate::cli::Options as L1Options;
use crate::initializers::{
    self, get_authrpc_socket_addr, get_http_socket_addr, get_local_node_record, get_local_p2p_node,
    get_network, get_signer, get_ws_socket_addr, init_blockchain, init_network, init_store,
    init_store_with_config,
};
use crate::l2::{L2Options, SequencerOptions};
use crate::utils::{
    NodeConfigFile, get_channel, get_client_version, get_client_version_string, init_datadir,
    read_jwtsecret_file, store_node_config_file,
};
use ethrex_blockchain::{Blockchain, BlockchainType, L2Config};
use ethrex_common::Address;
use ethrex_common::fd_limit::raise_fd_limit;
use ethrex_common::types::fee_config::{FeeConfig, L1FeeConfig, OperatorFeeConfig};
use ethrex_l2::sequencer::block_producer::{self, block_producer_protocol};
use ethrex_l2::sequencer::l1_committer::{self, l1_committer_protocol, regenerate_state};
use ethrex_p2p::{
    network::P2PContext,
    peer_handler::PeerHandler,
    peer_table::PeerTableServer,
    rlpx::{initiator::RLPxInitiator, l2::l2_connection::P2PBasedContext},
    sync::{BackfillConfig, HistoryChain},
    sync_manager::SyncManager,
    types::{LocalNode, SharedLocalNode},
};
use ethrex_rpc::{SubscriptionManager, WebSocketConfig};
use ethrex_storage::{Store, StoreConfig};
use ethrex_storage_rollup::{EngineTypeRollup, StoreRollup};
use eyre::OptionExt;
use secp256k1::SecretKey;

use spawned_concurrency::tasks::ActorRef;
use std::{
    fs::read_to_string,
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, reload};
use tui_logger::{LevelFilter, TuiTracingSubscriberLayer};
use url::Url;

#[allow(clippy::too_many_arguments)]
async fn init_rpc_api(
    opts: &L1Options,
    l2_opts: &L2Options,
    peer_handler: Option<PeerHandler>,
    shared_local_node: SharedLocalNode,
    store: Store,
    blockchain: Arc<Blockchain>,
    syncer: Option<Arc<SyncManager>>,
    tracker: TaskTracker,
    rollup_store: StoreRollup,
    log_filter_handler: Option<reload::Handle<EnvFilter, Registry>>,
    l2_gas_limit: u64,
    ws: Option<WebSocketConfig>,
    cancel_token: CancellationToken,
) -> eyre::Result<()> {
    init_datadir(&opts.datadir);

    let allowed_namespaces: std::collections::HashSet<_> = opts.http_api.iter().copied().collect();
    let ethrex_namespace_allowed = l2_opts.http_api_ethrex;

    // Reject conflicting listener addresses at config time, before anything binds. The L2
    // node binds no Auth-RPC listener, so only HTTP and WebSocket can conflict.
    initializers::validate_rpc_addrs(
        get_http_socket_addr(opts),
        None,
        ws.as_ref().map(|ws| ws.addr),
    )?;

    // Bind in the foreground so a bind failure aborts node startup with an actionable
    // error instead of being swallowed by a detached task; serve in the background.
    let bound = ethrex_l2_rpc::bind_api(
        cancel_token.clone(),
        get_http_socket_addr(opts),
        ws,
        get_authrpc_socket_addr(opts),
        store,
        blockchain,
        read_jwtsecret_file(&opts.authrpc_jwtsecret),
        shared_local_node,
        syncer,
        peer_handler,
        get_client_version(),
        get_valid_delegation_addresses(l2_opts),
        l2_opts.sponsor_private_key,
        rollup_store,
        log_filter_handler,
        l2_gas_limit,
        l2_opts.sponsored_gas_limit,
        allowed_namespaces,
        ethrex_namespace_allowed,
    )
    .await?;

    // Fatal: if the L2 RPC server dies, cancel the sequencer token so the node shuts down
    // (rather than run on without RPC). The token is the sequencer's, so the L2 `select!`
    // observes the cancellation and tears the sequencer down too.
    initializers::spawn_fatal(&tracker, cancel_token, "L2 RPC server", bound.serve());
    Ok(())
}

fn get_valid_delegation_addresses(l2_opts: &L2Options) -> Vec<Address> {
    let Some(ref path) = l2_opts.sponsorable_addresses_file_path else {
        warn!("No valid addresses provided, ethrex_SendTransaction will always fail");
        return Vec::new();
    };
    let addresses: Vec<Address> = read_to_string(path)
        .unwrap_or_else(|_| panic!("Failed to load file {path}"))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.to_string().parse::<Address>())
        .filter_map(Result::ok)
        .collect();
    if addresses.is_empty() {
        warn!("No valid addresses provided, ethrex_SendTransaction will always fail");
    }
    addresses
}

pub async fn init_rollup_store(datadir: &Path) -> StoreRollup {
    #[cfg(feature = "l2-sql")]
    let engine_type = EngineTypeRollup::SQL;
    #[cfg(not(feature = "l2-sql"))]
    let engine_type = EngineTypeRollup::InMemory;
    let rollup_store =
        StoreRollup::new(datadir, engine_type).expect("Failed to create StoreRollup");
    rollup_store
        .init()
        .await
        .expect("Failed to init rollup store");
    rollup_store
}

fn init_metrics(opts: &L1Options, network: &str, tracker: TaskTracker) {
    // Initialize node version metrics
    ethrex_metrics::node::MetricsNode::init(
        env!("CARGO_PKG_VERSION"),
        env!("VERGEN_GIT_SHA"),
        &get_channel(),
        env!("VERGEN_RUSTC_SEMVER"),
        env!("VERGEN_RUSTC_HOST_TRIPLE"),
        network,
    );

    tracing::info!(
        "Starting metrics server on {}:{}",
        opts.metrics_addr,
        opts.metrics_port
    );
    let metrics_api = ethrex_metrics::l2::api::start_prometheus_metrics_api(
        opts.metrics_addr.clone(),
        opts.metrics_port.clone(),
    );
    // Metrics is a non-fatal sidecar: its failure is logged loudly but must not down the node.
    initializers::spawn_logged(&tracker, "metrics server", metrics_api);
}

pub fn init_tracing(
    opts: &L2Options,
) -> (
    Option<reload::Handle<EnvFilter, Registry>>,
    Option<tracing_appender::non_blocking::WorkerGuard>,
) {
    if !opts.sequencer_opts.no_monitor {
        let default_filter = "info,reqwest_tracing=off,hyper=off,libsql=off,ethrex::initializers=off,ethrex::l2::initializers=off,ethrex::l2::command=off";
        let level_filter = EnvFilter::builder().parse_lossy(
            std::env::var("RUST_LOG")
                .as_deref()
                .unwrap_or(default_filter),
        );
        let subscriber = tracing_subscriber::registry()
            .with(TuiTracingSubscriberLayer)
            .with(level_filter);
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
        tui_logger::init_logger(LevelFilter::max()).expect("Failed to initialize tui_logger");

        // Monitor already registers all log levels
        (None, None)
    } else {
        let (handle, guard) = initializers::init_tracing(&opts.node_opts);
        (Some(handle), guard)
    }
}

async fn shutdown_sequencer_handles(
    committer_handle: Option<ActorRef<l1_committer::L1Committer>>,
    block_producer_handle: Option<ActorRef<block_producer::BlockProducer>>,
) {
    // Sending Abort triggers ctx.stop() and lets the actor unwind cleanly.
    if let Some(handle) = committer_handle {
        handle
            .send(l1_committer_protocol::Abort)
            .inspect_err(|err| warn!("Failed to send committer abort: {err:?}"))
            .ok();
    }
    if let Some(handle) = block_producer_handle {
        handle
            .send(block_producer_protocol::Abort)
            .inspect_err(|err| warn!("Failed to send block producer abort: {err:?}"))
            .ok();
    }
}

pub async fn init_l2(
    opts: L2Options,
    log_filter_handler: Option<reload::Handle<EnvFilter, Registry>>,
) -> eyre::Result<()> {
    raise_fd_limit()?;
    let datadir = opts.node_opts.datadir.clone();
    init_datadir(&opts.node_opts.datadir);

    let rollup_store_dir = datadir.join("rollup_store");

    // Checkpoints are stored in the main datadir
    let checkpoints_dir = datadir.clone();

    let network = get_network(&opts.node_opts);

    let genesis = network.get_genesis()?;
    // An explicit size skips memory detection entirely; the default path runs
    // it once and logs the derivation.
    let store_config = opts
        .node_opts
        .rocksdb_block_cache_size
        .map(StoreConfig::with_rocksdb_block_cache_size)
        .unwrap_or_default();
    let store = init_store_with_config(&datadir, genesis.clone(), store_config).await?;
    let rollup_store = init_rollup_store(&rollup_store_dir).await;

    let operator_fee_config = get_operator_fee_config(&opts.sequencer_opts)?;
    let l1_fee_config = get_l1_fee_config(&opts.sequencer_opts);

    let fee_config = FeeConfig {
        base_fee_vault: opts
            .sequencer_opts
            .block_producer_opts
            .base_fee_vault_address,
        operator_fee_config,
        l1_fee_config,
    };

    // We wrap fee_config in an Arc<RwLock> to let the watcher
    // update the L1 fee periodically.
    let l2_config = L2Config {
        fee_config: Arc::new(std::sync::RwLock::new(fee_config)),
    };

    let blockchain_opts = ethrex_blockchain::BlockchainOptions {
        max_mempool_size: opts.node_opts.mempool_max_size,
        r#type: BlockchainType::L2(l2_config),
        perf_logs_enabled: true,
        max_blobs_per_block: None, // L2 doesn't support blob transactions
        blob_sampling_enabled: false, // L2 rejects blob txs; no eth/72 sampling
        blob_eager_provider: false,
        precompute_witnesses: opts.node_opts.precompute_witnesses,
        private_mempool: opts.node_opts.mempool_private,
        precompile_cache_enabled: true,
        min_tip_wei: opts.node_opts.mempool_min_tip,
        price_bump_percent: opts.node_opts.mempool_price_bump,
        blob_price_bump_percent: opts.node_opts.mempool_blob_price_bump,
        max_queued_txs_per_account: opts.node_opts.mempool_max_queued_txs_per_account,
        bal_parallel_exec_enabled: true,
        bal_prefetch_enabled: true,
        bal_parallel_trie_enabled: true,
        max_reorg_depth: opts.node_opts.max_reorg_depth,
        gap_admit_occupancy_threshold: opts.node_opts.mempool_gap_admit_occupancy_threshold,
        mempool_prewarm_enabled: true,
    };

    let blockchain = init_blockchain(store.clone(), blockchain_opts.clone());

    regenerate_state(&store, &rollup_store, &blockchain, None).await?;

    let signer = get_signer(&datadir);

    let (local_p2p_node, network_config) = get_local_p2p_node(&opts.node_opts, &signer);

    let local_node_record = get_local_node_record(&datadir, &local_p2p_node, &signer);

    // Build the shared live identity Arc once; threaded into RPC, discovery, and shutdown.
    let shared_local_node: SharedLocalNode = Arc::new(RwLock::new(LocalNode {
        node: local_p2p_node.clone(),
        record: local_node_record,
    }));

    // TODO: Check every module starts properly.
    let tracker = TaskTracker::new();
    let mut join_set = JoinSet::new();

    let cancel_token = tokio_util::sync::CancellationToken::new();

    let (peer_handler, syncer) = if !opts.node_opts.p2p_disabled {
        if !opts.sequencer_opts.based {
            blockchain.set_synced();
        }
        let peer_table = PeerTableServer::spawn(opts.node_opts.target_peers);
        let p2p_context = P2PContext::new(
            local_p2p_node.clone(),
            network_config,
            tracker.clone(),
            signer,
            peer_table.clone(),
            store.clone(),
            blockchain.clone(),
            get_client_version_string(),
            #[cfg(feature = "l2")]
            Some(P2PBasedContext {
                store_rollup: rollup_store.clone(),
                // TODO: The Web3Signer refactor introduced a limitation where the committer key cannot be accessed directly because the signer could be either Local or Remote.
                // The Signer enum cannot be used in the P2PBasedContext struct due to cyclic dependencies between the l2-rpc and p2p crates.
                // As a temporary solution, a dummy committer key is used until a proper mechanism to utilize the Signer enum is implemented.
                // This should be replaced with the Signer enum once the refactor is complete.
                committer_key: Arc::new(
                    SecretKey::from_slice(
                        &hex::decode(
                            "385c546456b6a603a1cfcaa9ec9494ba4832da08dd6bcf4de9a71e4a01b74924",
                        )
                        .expect("Invalid committer key"),
                    )
                    .expect("Failed to create committer key"),
                ),
            }),
            opts.node_opts.tx_broadcasting_time_interval,
            opts.node_opts.lookup_interval,
        )
        .expect("P2P context could not be created");
        let initiator = RLPxInitiator::spawn(p2p_context.clone());
        let peer_handler = PeerHandler::new(peer_table, initiator, p2p_context.discovery.clone());

        // Create SyncManager
        let syncer = SyncManager::new(
            peer_handler.clone(),
            &opts.node_opts.syncmode,
            cancel_token.clone(),
            blockchain.clone(),
            store.clone(),
            opts.node_opts.datadir.clone(),
            // L2 nodes do not backfill L1 historical chain data.
            BackfillConfig {
                mode: HistoryChain::Off,
                tx_index_horizon: 0,
            },
            tracker.clone(),
        )
        .await;

        // TODO: This should be handled differently, the current problem
        // with using opts.node_opts.p2p_disabled is that with the removal
        // of the l2 feature flag, p2p_disabled is set to false by default
        // prioritizing the L1 UX.
        init_network(
            &opts.node_opts,
            &network,
            &datadir,
            peer_handler.clone(),
            tracker.clone(),
            blockchain.clone(),
            p2p_context,
            shared_local_node.clone(),
        )
        .await;
        (Some(peer_handler), Some(Arc::new(syncer)))
    } else {
        (None, None)
    };

    let l2_gas_limit = ethrex_l2::sequencer::utils::get_l2_gas_limit(
        opts.sequencer_opts.eth_opts.rpc_url.clone(),
        opts.sequencer_opts
            .watcher_opts
            .bridge_address
            .ok_or_else(|| eyre::eyre!("Bridge address required to fetch L2 gas limit"))?,
    )
    .await?;

    // Create WebSocket config when WS is enabled.
    let ws_config = if opts.node_opts.ws_enabled {
        Some(WebSocketConfig {
            addr: get_ws_socket_addr(&opts.node_opts),
            subscription_manager: SubscriptionManager::spawn(),
        })
    } else {
        None
    };

    // Created before the RPC starts so the same token drives both the RPC graceful
    // shutdown and the sequencer `select!` below (avoids a split-brain shutdown).
    let sequencer_cancellation_token = CancellationToken::new();

    init_rpc_api(
        &opts.node_opts,
        &opts,
        peer_handler.clone(),
        shared_local_node.clone(),
        store.clone(),
        blockchain.clone(),
        syncer,
        tracker.clone(),
        rollup_store.clone(),
        log_filter_handler,
        l2_gas_limit,
        ws_config.clone(),
        sequencer_cancellation_token.clone(),
    )
    .await?;

    // Initialize metrics if enabled
    if opts.node_opts.metrics_enabled {
        init_metrics(&opts.node_opts, &network.to_string(), tracker.clone());
        initializers::spawn_rocksdb_metrics_collector(
            store.clone(),
            &tracker,
            sequencer_cancellation_token.clone(),
        );
    }

    let l2_url = Url::parse(&format!(
        "http://{}:{}",
        opts.node_opts.http_addr, opts.node_opts.http_port
    ))
    .map_err(|err| eyre::eyre!("Failed to parse L2 RPC URL: {err}"))?;
    let (committer_handle, block_producer_handle, l2_sequencer) = ethrex_l2::start_l2(
        store,
        rollup_store,
        blockchain,
        opts.sequencer_opts.try_into()?,
        sequencer_cancellation_token.clone(),
        l2_url,
        genesis,
        checkpoints_dir,
        l2_gas_limit,
        ws_config.as_ref().map(|ws| ws.subscription_manager.clone()),
    )
    .await?;
    join_set.spawn(l2_sequencer);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            shutdown_sequencer_handles(
                committer_handle.clone(),
                block_producer_handle.clone()
            ).await;
            join_set.abort_all();
        }
        _ = sequencer_cancellation_token.cancelled() => {
            shutdown_sequencer_handles(committer_handle.clone(), block_producer_handle.clone()).await;
        }
    }
    info!("Server shut down started...");
    let node_config_path = datadir.join("node_config.json");
    info!(path = %node_config_path.display(), "Storing node config");
    cancel_token.cancel();
    if !opts.node_opts.p2p_disabled {
        let peer_handler = peer_handler.ok_or_eyre("Peer handler not initialized")?;
        // Clone the current (possibly updated) record out and drop the guard.
        let record = {
            let guard = shared_local_node
                .read()
                .expect("shared_local_node poisoned");
            guard.record.clone()
        };
        let node_config = NodeConfigFile::new(peer_handler.peer_table, record).await;
        store_node_config_file(node_config, node_config_path);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    info!("Server shutting down!");
    // A shutdown initiated by a failing subsystem exits non-zero so orchestrators can tell
    // a crashed node from a clean signal-triggered stop.
    if let Some(cause) = initializers::fatal_shutdown_cause() {
        return Err(eyre::eyre!(
            "node shut down after a fatal subsystem failure: {cause}"
        ));
    }
    Ok(())
}

pub async fn init_native_rollup_l2(
    opts: L2Options,
    log_filter_handler: Option<reload::Handle<EnvFilter, Registry>>,
) -> eyre::Result<()> {
    use ethrex_l2::NativeRollupConfig;
    use ethrex_l2_rpc::signer::LocalSigner;

    raise_fd_limit()?;
    let datadir = opts.node_opts.datadir.clone();
    init_datadir(&opts.node_opts.datadir);

    let network = get_network(&opts.node_opts);
    let genesis = network.get_genesis()?;
    let store = init_store(&datadir, genesis).await?;

    // Native rollup L2 uses BlockchainType::L1 because the whole point of native
    // rollups is that L2 blocks run through an unmodified L1 execution environment
    // (the EXECUTE precompile). The L2 must produce blocks that the L1 VM can
    // re-execute identically, so the L2 node uses the same precompile set and
    // execution rules as L1.
    let blockchain_opts = ethrex_blockchain::BlockchainOptions {
        max_mempool_size: opts.node_opts.mempool_max_size,
        r#type: BlockchainType::L1,
        perf_logs_enabled: true,
        max_blobs_per_block: None,
        blob_sampling_enabled: false, // L2 rejects blob txs; no eth/72 sampling
        blob_eager_provider: false,
        precompute_witnesses: opts.node_opts.precompute_witnesses,
        precompile_cache_enabled: true,
        max_queued_txs_per_account: opts.node_opts.mempool_max_queued_txs_per_account,
        bal_parallel_exec_enabled: true,
        bal_prefetch_enabled: true,
        bal_parallel_trie_enabled: true,
        max_reorg_depth: opts.node_opts.max_reorg_depth,
        gap_admit_occupancy_threshold: opts.node_opts.mempool_gap_admit_occupancy_threshold,
        private_mempool: opts.node_opts.mempool_private,
        price_bump_percent: opts.node_opts.mempool_price_bump,
        blob_price_bump_percent: opts.node_opts.mempool_blob_price_bump,
        min_tip_wei: opts.node_opts.mempool_min_tip,
        mempool_prewarm_enabled: true,
    };

    let blockchain = init_blockchain(store.clone(), blockchain_opts);
    blockchain.set_synced();

    let signer = get_signer(&datadir);
    let (local_p2p_node, _network_config) = get_local_p2p_node(&opts.node_opts, &signer);
    let local_node_record = get_local_node_record(&datadir, &local_p2p_node, &signer);
    // No discovery runs on this devnet path, so the shared identity never changes
    // after construction; RPC still reads it through the same Arc as the full node.
    let shared_local_node: SharedLocalNode = Arc::new(RwLock::new(LocalNode {
        node: local_p2p_node,
        record: local_node_record,
    }));

    let tracker = TaskTracker::new();

    // Init a minimal rollup store (needed for RPC)
    let rollup_store_dir = datadir.join("rollup_store");
    let rollup_store = init_rollup_store(&rollup_store_dir).await;

    let native_opts = &opts.sequencer_opts.native_rollup_opts;
    let contract_address = native_opts
        .contract_address
        .ok_or_else(|| eyre::eyre!("--native-rollups.contract-address is required"))?;

    let l1_rpc_urls = opts.sequencer_opts.eth_opts.rpc_url.clone();

    let block_gas_limit =
        ethrex_l2::sequencer::utils::get_l2_gas_limit(l1_rpc_urls.clone(), contract_address)
            .await?;

    // Fresh token: this native-rollup devnet RPC path has no graceful-shutdown
    // wiring, so the token is never cancelled (matches prior behavior).
    let cancel_token = CancellationToken::new();
    init_rpc_api(
        &opts.node_opts,
        &opts,
        None, // no p2p peer handler
        shared_local_node,
        store.clone(),
        blockchain.clone(),
        None, // no syncer
        tracker,
        rollup_store,
        log_filter_handler,
        block_gas_limit,
        None, // no websocket for the native rollup devnet RPC
        cancel_token,
    )
    .await?;

    let relayer_private_key = native_opts
        .relayer_private_key
        .ok_or_else(|| eyre::eyre!("--native-rollups.relayer-pk is required"))?;
    let l1_private_key = native_opts
        .l1_private_key
        .ok_or_else(|| eyre::eyre!("--native-rollups.l1-pk is required"))?;
    let relayer_signer: ethrex_l2_rpc::signer::Signer =
        LocalSigner::new(relayer_private_key).into();
    let l1_signer: ethrex_l2_rpc::signer::Signer = LocalSigner::new(l1_private_key).into();

    let config = NativeRollupConfig {
        l1_rpc_urls,
        contract_address,
        block_time_ms: native_opts.block_time_ms,
        watch_interval_ms: opts.sequencer_opts.watcher_opts.watch_interval_ms,
        advance_interval_ms: native_opts.advance_interval_ms,
        max_block_step: opts.sequencer_opts.watcher_opts.max_block_step,
        coinbase: relayer_signer.address(),
        block_gas_limit,
        chain_id: store.get_chain_config().chain_id,
        relayer_signer,
        l1_signer,
    };

    let (_watcher_handle, _producer_handle, _advancer_handle) =
        ethrex_l2::start_native_rollup_l2(store, blockchain, config)
            .map_err(|e| eyre::eyre!("Failed to start native rollup L2: {e}"))?;

    info!("Native Rollup L2 started, press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;

    info!("Shutting down Native Rollup L2...");
    Ok(())
}

pub fn get_l1_fee_config(sequencer_opts: &SequencerOptions) -> Option<L1FeeConfig> {
    if sequencer_opts.based {
        // If based is enabled, skip L1 fee configuration
        return None;
    }

    sequencer_opts
        .block_producer_opts
        .l1_fee_vault_address
        .map(|addr| L1FeeConfig {
            l1_fee_vault: addr,
            l1_fee_per_blob_gas: 0, // This is set by the L1 watcher
        })
}

pub fn get_operator_fee_config(
    sequencer_opts: &SequencerOptions,
) -> eyre::Result<Option<OperatorFeeConfig>> {
    if sequencer_opts.based {
        // If based is enabled, skip operator fee configuration
        return Ok(None);
    }

    let fee = sequencer_opts.block_producer_opts.operator_fee_per_gas;

    let address = sequencer_opts
        .block_producer_opts
        .operator_fee_vault_address;

    let operator_fee_config =
        if let (Some(operator_fee_vault), Some(operator_fee_per_gas)) = (address, fee) {
            Some(OperatorFeeConfig {
                operator_fee_vault,
                operator_fee_per_gas,
            })
        } else {
            None
        };
    Ok(operator_fee_config)
}
