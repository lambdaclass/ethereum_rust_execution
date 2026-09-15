#[cfg(feature = "l2")]
use crate::rlpx::l2::l2_connection::P2PBasedContext;
#[cfg(not(feature = "l2"))]
#[derive(Clone, Debug)]
pub struct P2PBasedContext;
use crate::{
    discovery::{DiscoveryConfig, DiscoveryHandle, DiscoveryServer, DiscoveryServerError},
    metrics::{CurrentStepValue, METRICS},
    peer_filter::EthForkIdFilter,
    peer_table::{PeerData, PeerTable, PeerTableServerProtocol as _},
    rlpx::{
        connection::server::{PeerConnBroadcastSender, PeerConnection},
        message::Message,
        p2p::SUPPORTED_SNAP_CAPABILITIES,
    },
    tx_broadcaster::{TxBroadcaster, TxBroadcasterError},
    types::{INITIAL_ENR_SEQ, NetworkConfig, Node, NodeError, NodeRecord, SharedLocalNode},
};
use ethrex_blockchain::Blockchain;
use ethrex_common::H256;
use ethrex_common::types::ForkId;
use ethrex_storage::Store;
use secp256k1::SecretKey;
use spawned_concurrency::tasks::ActorRef;
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::sync::watch;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info};

pub const MAX_MESSAGES_TO_BROADCAST: usize = 100000;

#[derive(Clone, Debug)]
pub struct P2PContext {
    pub tracker: TaskTracker,
    pub signer: SecretKey,
    pub table: PeerTable,
    /// Reaches the discovery server, once one is running. Inert when p2p runs
    /// without discovery.
    pub discovery: DiscoveryHandle,
    pub storage: Store,
    pub blockchain: Arc<Blockchain>,
    pub(crate) broadcast: PeerConnBroadcastSender,
    /// Startup copy of the local node identity used only as the self-connection guard.
    /// Not live-updated; use SharedLocalNode for the current identity.
    pub local_node: Node,
    /// Network addressing configuration: bind vs. external addresses.
    pub network_config: NetworkConfig,
    pub client_version: String,
    #[cfg(feature = "l2")]
    pub based_context: Option<P2PBasedContext>,
    pub tx_broadcaster: ActorRef<TxBroadcaster>,
    pub initial_lookup_interval: f64,
    /// Caps concurrent INBOUND connections (including pre-handshake) so a flood of inbound
    /// dials can't accumulate connection actors/sockets without bound. Each inbound connection
    /// actor holds a permit for its lifetime; the permit is released when the actor is dropped.
    pub(crate) inbound_admission: Arc<tokio::sync::Semaphore>,
}

/// Max concurrent inbound connections (peer_table TARGET_PEERS = 100, plus headroom for
/// pre-handshake churn and short-lived overlap).
const MAX_INBOUND_CONNECTIONS: usize = 150;

impl P2PContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_node: Node,
        network_config: NetworkConfig,
        tracker: TaskTracker,
        signer: SecretKey,
        peer_table: PeerTable,
        storage: Store,
        blockchain: Arc<Blockchain>,
        client_version: String,
        based_context: Option<P2PBasedContext>,
        tx_broadcasting_time_interval: u64,
        lookup_interval: f64,
    ) -> Result<Self, NetworkError> {
        let (channel_broadcast_send_end, _) = tokio::sync::broadcast::channel::<(
            tokio::task::Id,
            Arc<Message>,
        )>(MAX_MESSAGES_TO_BROADCAST);

        let tx_broadcaster = TxBroadcaster::spawn(
            peer_table.clone(),
            blockchain.clone(),
            tx_broadcasting_time_interval,
        )
        .inspect_err(|e| {
            error!("Failed to start Tx Broadcaster: {e}");
        })?;

        #[cfg(not(feature = "l2"))]
        let _ = &based_context;

        Ok(P2PContext {
            local_node,
            network_config,
            tracker,
            signer,
            table: peer_table,
            discovery: DiscoveryHandle::new(),
            storage,
            blockchain,
            broadcast: channel_broadcast_send_end,
            client_version,
            #[cfg(feature = "l2")]
            based_context,
            tx_broadcaster,
            initial_lookup_interval: lookup_interval,
            inbound_admission: Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_CONNECTIONS)),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Failed to start discovery server: {0}")]
    DiscoveryError(#[from] DiscoveryServerError),
    #[error("Failed to start Tx Broadcaster: {0}")]
    TxBroadcasterError(#[from] TxBroadcasterError),
    #[error("Failed to bind UDP socket: {0}")]
    UdpSocketError(std::io::Error),
    #[error("Failed to build the local node record: {0}")]
    LocalNodeRecordError(#[from] NodeError),
}

/// The ENR this node publishes: whatever `local_node` advertises, plus our own
/// EIP-2124 fork id.
///
/// Built here rather than inside discovery, which has no say in what this node
/// announces about itself.
///
/// A chain that cannot supply a fork id leaves the entry out instead of failing
/// startup. The record is still usable for discovery, and a peer that requires
/// `eth` simply passes us over until we republish with it. A record we cannot
/// sign is different, and is reported.
///
/// Also returns the fork id the record was built with, so the refresh channel can
/// be seeded with the exact value the ENR advertises: seeding from a second
/// storage read could straddle a fork crossing, and a seed the ENR never carried
/// is a change the refresh would never see.
async fn build_local_node_record(
    context: &P2PContext,
) -> Result<(NodeRecord, Option<ForkId>), NodeError> {
    let mut record = NodeRecord::from_node(&context.local_node, INITIAL_ENR_SEQ, &context.signer)?;
    let fork_id = context.storage.get_fork_id().await.ok();
    if let Some(fork_id) = fork_id.clone() {
        record.set_fork_id(fork_id, &context.signer)?;
    }
    Ok((record, fork_id))
}

pub async fn start_network(
    context: P2PContext,
    bootnodes: Vec<Node>,
    config: DiscoveryConfig,
    shared_local_node: SharedLocalNode,
) -> Result<(), NetworkError> {
    let udp_socket = Arc::new(
        UdpSocket::bind(context.network_config.bind_udp_addr())
            .await
            .map_err(NetworkError::UdpSocketError)?,
    );

    let (local_node_record, initial_fork_id) = build_local_node_record(&context).await?;

    // The ENR's `eth` entry is only correct for the fork the chain is on. Nothing
    // recomputed it after startup, so once the chain crossed a fork we kept
    // advertising the old fork id and geth's dial-candidate filter
    // (`NewNodeFilter`) dropped us. Publish it on a channel instead: this layer
    // decides what the node announces, discovery only republishes.
    let fork_id_rx = spawn_fork_id_publisher(&context, initial_fork_id);

    let discovery = DiscoveryServer::spawn(
        context.local_node.clone(),
        local_node_record,
        context.signer,
        udp_socket,
        Box::new(EthForkIdFilter::new(context.storage.clone())),
        bootnodes,
        config,
        shared_local_node,
        fork_id_rx,
    )
    .await
    .inspect_err(|e| {
        error!("Failed to start discovery server: {e}");
    })?;

    // Publishes the server to every clone of the context, which is what lets the
    // initiator ask for dial candidates and connections report their lifecycle.
    if !context.discovery.set(discovery) {
        error!("Discovery server was already set on this context");
    }

    context.tracker.spawn(serve_p2p_requests(context.clone()));

    Ok(())
}

pub(crate) async fn serve_p2p_requests(context: P2PContext) {
    let tcp_addr = context.network_config.bind_tcp_addr();
    let external_tcp_addr = context.local_node.tcp_addr();
    let listener = match listener(tcp_addr) {
        Ok(result) => result,
        Err(e) => {
            error!("Error opening tcp socket at {tcp_addr}: {e}. Stopping p2p server");
            return;
        }
    };
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                error!("Error receiving data from tcp socket {tcp_addr}: {e}. Stopping p2p server");
                return;
            }
        };

        if external_tcp_addr == peer_addr {
            // Ignore connections from self
            continue;
        }

        // Bound concurrent inbound connections: if we're at capacity, drop this one instead
        // of letting connection actors/sockets accumulate. The permit is moved into the
        // connection actor and released when the actor is dropped.
        let permit = match context.inbound_admission.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::debug!(peer = %peer_addr, "Inbound connection cap reached, dropping connection");
                continue;
            }
        };

        let _ = PeerConnection::spawn_as_receiver(context.clone(), peer_addr, stream, permit);
    }
}

fn listener(tcp_addr: SocketAddr) -> Result<TcpListener, io::Error> {
    let tcp_socket = match tcp_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;
    tcp_socket.set_reuseport(true).ok();
    tcp_socket.set_reuseaddr(true).ok();
    tcp_socket.bind(tcp_addr)?;

    tcp_socket.listen(50)
}

pub async fn periodically_show_peer_stats(blockchain: Arc<Blockchain>, peer_table: PeerTable) {
    periodically_show_peer_stats_during_syncing(blockchain, &peer_table).await;
    periodically_show_peer_stats_after_sync(&peer_table).await;
}

/// Tracks metric values at phase start and from the previous interval for rate calculations
#[derive(Default, Clone, Copy)]
struct PhaseCounters {
    headers: u64,
    accounts: u64,
    accounts_inserted: u64,
    storage: u64,
    storage_inserted: u64,
    healed_accounts: u64,
    healed_storage: u64,
    bytecodes: u64,
}

impl PhaseCounters {
    fn capture_current() -> Self {
        Self {
            headers: METRICS.downloaded_headers.get(),
            accounts: METRICS.downloaded_account_tries.load(Ordering::Relaxed),
            accounts_inserted: METRICS.account_tries_inserted.load(Ordering::Relaxed),
            storage: METRICS.storage_leaves_downloaded.get(),
            storage_inserted: METRICS.storage_leaves_inserted.get(),
            healed_accounts: METRICS
                .global_state_trie_leafs_healed
                .load(Ordering::Relaxed),
            healed_storage: METRICS
                .global_storage_tries_leafs_healed
                .load(Ordering::Relaxed),
            bytecodes: METRICS.downloaded_bytecodes.load(Ordering::Relaxed),
        }
    }
}

pub async fn periodically_show_peer_stats_during_syncing(
    blockchain: Arc<Blockchain>,
    peer_table: &PeerTable,
) {
    let start = std::time::Instant::now();
    let mut previous_step = CurrentStepValue::None;
    let mut phase_start_time = std::time::Instant::now();
    let mut sync_started_logged = false;

    // Track metrics at phase start for phase summaries
    let mut phase_start = PhaseCounters::default();
    // Track metrics from previous interval for rate calculations
    let mut prev_interval = PhaseCounters::default();

    loop {
        if blockchain.is_synced() {
            if !sync_started_logged {
                info!("Node already has state; following chain via full sync");
                return;
            }
            // Log sync complete summary
            let total_elapsed = format_duration(start.elapsed());
            let headers_downloaded = METRICS.downloaded_headers.get();
            let accounts_downloaded = METRICS.downloaded_account_tries.load(Ordering::Relaxed);
            let storage_downloaded = METRICS.storage_leaves_downloaded.get();
            let bytecodes_downloaded = METRICS.downloaded_bytecodes.load(Ordering::Relaxed);
            let healed_accounts = METRICS
                .global_state_trie_leafs_healed
                .load(Ordering::Relaxed);
            let healed_storage = METRICS
                .global_storage_tries_leafs_healed
                .load(Ordering::Relaxed);

            info!("");
            info!(
                "╭──────────────────────────────────────────────────────────────────────────────╮"
            );
            info!(
                "│ SNAP SYNC COMPLETE                                                           │"
            );
            info!(
                "├──────────────────────────────────────────────────────────────────────────────┤"
            );
            info!("│ {:<76}│", format!("Total time: {}", total_elapsed));
            info!(
                "├──────────────────────────────────────────────────────────────────────────────┤"
            );
            info!(
                "│ Data summary:                                                                │"
            );
            let headers_accounts = format!(
                "  Headers: {:<14} │  Accounts: {}",
                format_thousands(headers_downloaded),
                format_thousands(accounts_downloaded)
            );
            info!("│ {:<76}│", headers_accounts);
            let storage_bytecodes = format!(
                "  Storage: {:<14} │  Bytecodes: {}",
                format_thousands(storage_downloaded),
                format_thousands(bytecodes_downloaded)
            );
            info!("│ {:<76}│", storage_bytecodes);
            let healed = format!(
                "  Healed: {} state paths + {} storage accounts",
                format_thousands(healed_accounts),
                format_thousands(healed_storage)
            );
            info!("│ {:<76}│", healed);
            info!(
                "╰──────────────────────────────────────────────────────────────────────────────╯"
            );
            return;
        }

        let metrics_enabled = *METRICS.enabled.lock().await;
        if !metrics_enabled {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let current_step = METRICS.current_step.get();
        let peer_number = peer_table.peer_count().await.unwrap_or(0);

        // Log sync started banner when we have valid sync head data
        if !sync_started_logged && current_step != CurrentStepValue::None {
            let sync_head_block = METRICS.sync_head_block.load(Ordering::Relaxed);
            let sync_head_hash = *METRICS.sync_head_hash.lock().await;

            // Only show banner when sync_head data is populated (not genesis/default)
            if sync_head_block > 0 && sync_head_hash != H256::zero() {
                let head_short = format!("{:x}", sync_head_hash);
                let head_short = &head_short[..8.min(head_short.len())];

                info!("");
                info!("╭─────────────────────────────────────────────────────────────╮");
                info!("│ {:<59} │", "SNAP SYNC STARTED");
                let target_content = format!(
                    "Target: {}... (block #{})",
                    head_short,
                    format_thousands(sync_head_block)
                );
                info!("│ {:<59} │", target_content);
                info!("│ {:<59} │", format!("Peers: {}", peer_number));
                info!("╰─────────────────────────────────────────────────────────────╯");
                sync_started_logged = true;
            }
        }

        // Only show phase progress after the SNAP SYNC STARTED banner
        if !sync_started_logged {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Detect phase transition
        if current_step != previous_step && current_step != CurrentStepValue::None {
            // Log completion of previous phase (if any)
            if previous_step != CurrentStepValue::None {
                // Force a final progress print so the bar doesn't look incomplete
                let phase_elapsed = phase_start_time.elapsed();
                let total_elapsed = format_duration(start.elapsed());
                log_phase_progress(
                    previous_step,
                    phase_elapsed,
                    &total_elapsed,
                    peer_number,
                    &prev_interval,
                )
                .await;

                let phase_elapsed_str = format_duration(phase_start_time.elapsed());
                log_phase_completion(
                    previous_step,
                    phase_elapsed_str,
                    &phase_metrics(previous_step, &phase_start).await,
                );

                // Emit final metrics for completed phase
                #[cfg(feature = "metrics")]
                push_sync_prometheus_metrics(previous_step);
            }

            // Start new phase
            phase_start_time = std::time::Instant::now();

            // Record phase start timestamp for Grafana elapsed panels
            #[cfg(feature = "metrics")]
            {
                let (_, phase_name) = phase_info(current_step);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                ethrex_metrics::sync::METRICS_SYNC
                    .phase_start_timestamp
                    .with_label_values(&[phase_name])
                    .set(now as i64);
            }

            // Capture metrics at phase start
            phase_start = PhaseCounters::capture_current();
            prev_interval = phase_start;

            log_phase_separator(current_step);
            previous_step = current_step;
        }

        // Log phase-specific progress update
        let phase_elapsed = phase_start_time.elapsed();
        let total_elapsed = format_duration(start.elapsed());

        log_phase_progress(
            current_step,
            phase_elapsed,
            &total_elapsed,
            peer_number,
            &prev_interval,
        )
        .await;

        // Push progress + peer health to Prometheus
        #[cfg(feature = "metrics")]
        {
            push_sync_prometheus_metrics(current_step);
            let diag = peer_table.get_peer_diagnostics().await.unwrap_or_default();
            let snap_peers = diag
                .iter()
                .filter(|p| p.capabilities.iter().any(|c| c.starts_with("snap/")))
                .count();
            let eligible = diag.iter().filter(|p| p.eligible).count();
            let inflight: i64 = diag.iter().map(|p| p.inflight_requests).sum();
            ethrex_metrics::sync::METRICS_SYNC.set_snap_peers(snap_peers as i64);
            ethrex_metrics::sync::METRICS_SYNC.set_eligible_peers(eligible as i64);
            ethrex_metrics::sync::METRICS_SYNC.set_inflight_requests(inflight);
        }

        // Update previous interval counters for next rate calculation
        prev_interval = PhaseCounters::capture_current();

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Returns (phase_number, phase_name) for the current step
fn phase_info(step: CurrentStepValue) -> (u8, &'static str) {
    match step {
        CurrentStepValue::DownloadingHeaders => (1, "BLOCK HEADERS"),
        CurrentStepValue::RequestingAccountRanges => (2, "ACCOUNT RANGES"),
        CurrentStepValue::InsertingAccountRanges | CurrentStepValue::InsertingAccountRangesNoDb => {
            (3, "ACCOUNT INSERTION")
        }
        CurrentStepValue::RequestingStorageRanges => (4, "STORAGE RANGES"),
        CurrentStepValue::InsertingStorageRanges => (5, "STORAGE INSERTION"),
        CurrentStepValue::HealingState => (6, "STATE HEALING"),
        CurrentStepValue::HealingStorage => (7, "STORAGE HEALING"),
        CurrentStepValue::RequestingBytecodes => (8, "BYTECODES"),
        CurrentStepValue::None => (0, "UNKNOWN"),
    }
}

fn log_phase_separator(step: CurrentStepValue) {
    let (phase_num, phase_name) = phase_info(step);
    let header = format!("── PHASE {}/8: {} ", phase_num, phase_name);
    let header_width = header.chars().count();
    let padding_width = 80usize.saturating_sub(header_width);
    let padding = "─".repeat(padding_width);
    info!("");
    info!("{}{}", header, padding);
}

fn log_phase_completion(step: CurrentStepValue, elapsed: String, summary: &str) {
    let (_, phase_name) = phase_info(step);
    info!("✓ {} complete: {} in {}", phase_name, summary, elapsed);
}

async fn phase_metrics(step: CurrentStepValue, phase_start: &PhaseCounters) -> String {
    match step {
        CurrentStepValue::DownloadingHeaders => {
            let downloaded = METRICS
                .downloaded_headers
                .get()
                .saturating_sub(phase_start.headers);
            format!("{} headers", format_thousands(downloaded))
        }
        CurrentStepValue::RequestingAccountRanges => {
            let downloaded = METRICS
                .downloaded_account_tries
                .load(Ordering::Relaxed)
                .saturating_sub(phase_start.accounts);
            format!("{} accounts", format_thousands(downloaded))
        }
        CurrentStepValue::InsertingAccountRanges | CurrentStepValue::InsertingAccountRangesNoDb => {
            let inserted = METRICS
                .account_tries_inserted
                .load(Ordering::Relaxed)
                .saturating_sub(phase_start.accounts_inserted);
            format!("{} accounts inserted", format_thousands(inserted))
        }
        CurrentStepValue::RequestingStorageRanges => {
            let downloaded = METRICS
                .storage_leaves_downloaded
                .get()
                .saturating_sub(phase_start.storage);
            format!("{} storage slots", format_thousands(downloaded))
        }
        CurrentStepValue::InsertingStorageRanges => {
            let inserted = METRICS
                .storage_leaves_inserted
                .get()
                .saturating_sub(phase_start.storage_inserted);
            format!("{} storage slots inserted", format_thousands(inserted))
        }
        CurrentStepValue::HealingState => {
            let healed = METRICS
                .global_state_trie_leafs_healed
                .load(Ordering::Relaxed)
                .saturating_sub(phase_start.healed_accounts);
            format!("{} state paths healed", format_thousands(healed))
        }
        CurrentStepValue::HealingStorage => {
            let healed = METRICS
                .global_storage_tries_leafs_healed
                .load(Ordering::Relaxed)
                .saturating_sub(phase_start.healed_storage);
            format!("{} storage accounts healed", format_thousands(healed))
        }
        CurrentStepValue::RequestingBytecodes => {
            let downloaded = METRICS
                .downloaded_bytecodes
                .load(Ordering::Relaxed)
                .saturating_sub(phase_start.bytecodes);
            format!("{} bytecodes", format_thousands(downloaded))
        }
        CurrentStepValue::None => String::new(),
    }
}

/// Interval in seconds between progress updates
const PROGRESS_INTERVAL_SECS: u64 = 30;

async fn log_phase_progress(
    step: CurrentStepValue,
    phase_elapsed: Duration,
    total_elapsed: &str,
    peer_count: usize,
    prev_interval: &PhaseCounters,
) {
    let phase_elapsed_str = format_duration(phase_elapsed);

    // Use consistent column widths: left column 40 chars, then │, then right column
    let col1_width = 40;

    match step {
        CurrentStepValue::DownloadingHeaders => {
            let headers_to_download = METRICS.sync_head_block.load(Ordering::Relaxed);
            let headers_downloaded =
                u64::min(METRICS.downloaded_headers.get(), headers_to_download);
            let interval_downloaded = headers_downloaded.saturating_sub(prev_interval.headers);
            let percentage = if headers_to_download == 0 {
                0.0
            } else {
                (headers_downloaded as f64 / headers_to_download as f64) * 100.0
            };
            let rate = interval_downloaded / PROGRESS_INTERVAL_SECS;

            let progress = progress_bar(percentage, 40);
            info!("  {} {:>5.1}%", progress, percentage);
            info!("");
            let col1 = format!(
                "Headers: {} / {}",
                format_thousands(headers_downloaded),
                format_thousands(headers_to_download)
            );
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} headers/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::RequestingAccountRanges => {
            let accounts_downloaded = METRICS.downloaded_account_tries.load(Ordering::Relaxed);
            let interval_downloaded = accounts_downloaded.saturating_sub(prev_interval.accounts);
            let rate = interval_downloaded / PROGRESS_INTERVAL_SECS;

            info!("");
            let col1 = format!(
                "Accounts fetched: {}",
                format_thousands(accounts_downloaded)
            );
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} accounts/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::InsertingAccountRanges | CurrentStepValue::InsertingAccountRangesNoDb => {
            let accounts_to_insert = METRICS.downloaded_account_tries.load(Ordering::Relaxed);
            let accounts_inserted = METRICS.account_tries_inserted.load(Ordering::Relaxed);
            let interval_inserted =
                accounts_inserted.saturating_sub(prev_interval.accounts_inserted);
            let percentage = if accounts_to_insert == 0 {
                0.0
            } else {
                (accounts_inserted as f64 / accounts_to_insert as f64) * 100.0
            };
            let rate = interval_inserted / PROGRESS_INTERVAL_SECS;

            let progress = progress_bar(percentage, 40);
            info!("  {} {:>5.1}%", progress, percentage);
            info!("");
            let col1 = format!(
                "Accounts: {} / {}",
                format_thousands(accounts_inserted),
                format_thousands(accounts_to_insert)
            );
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} accounts/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::RequestingStorageRanges => {
            let storage_downloaded = METRICS.storage_leaves_downloaded.get();
            let interval_downloaded = storage_downloaded.saturating_sub(prev_interval.storage);
            let rate = interval_downloaded / PROGRESS_INTERVAL_SECS;

            info!("");
            let col1 = format!(
                "Storage slots fetched: {}",
                format_thousands(storage_downloaded)
            );
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} slots/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::InsertingStorageRanges => {
            let storage_inserted = METRICS.storage_leaves_inserted.get();
            let interval_inserted = storage_inserted.saturating_sub(prev_interval.storage_inserted);
            let rate = interval_inserted / PROGRESS_INTERVAL_SECS;

            info!("");
            let col1 = format!(
                "Storage slots inserted: {}",
                format_thousands(storage_inserted)
            );
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} slots/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::HealingState => {
            let healed = METRICS
                .global_state_trie_leafs_healed
                .load(Ordering::Relaxed);
            let interval_healed = healed.saturating_sub(prev_interval.healed_accounts);
            let rate = interval_healed / PROGRESS_INTERVAL_SECS;

            info!("");
            let col1 = format!("State paths healed: {}", format_thousands(healed));
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} paths/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::HealingStorage => {
            let healed = METRICS
                .global_storage_tries_leafs_healed
                .load(Ordering::Relaxed);
            let interval_healed = healed.saturating_sub(prev_interval.healed_storage);
            let rate = interval_healed / PROGRESS_INTERVAL_SECS;

            info!("");
            let col1 = format!("Storage accounts healed: {}", format_thousands(healed));
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} accounts/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::RequestingBytecodes => {
            let bytecodes_to_download = METRICS.bytecodes_to_download.load(Ordering::Relaxed);
            let bytecodes_downloaded = METRICS.downloaded_bytecodes.load(Ordering::Relaxed);
            let interval_downloaded = bytecodes_downloaded.saturating_sub(prev_interval.bytecodes);
            let percentage = if bytecodes_to_download == 0 {
                0.0
            } else {
                (bytecodes_downloaded as f64 / bytecodes_to_download as f64) * 100.0
            };
            let rate = interval_downloaded / PROGRESS_INTERVAL_SECS;

            let progress = progress_bar(percentage, 40);
            info!("  {} {:>5.1}%", progress, percentage);
            info!("");
            let col1 = format!(
                "Bytecodes: {} / {}",
                format_thousands(bytecodes_downloaded),
                format_thousands(bytecodes_to_download)
            );
            info!("  {:<col1_width$} │  Elapsed: {}", col1, phase_elapsed_str);
            let col1 = format!("Rate: {} codes/s", format_thousands(rate));
            info!("  {:<col1_width$} │  Peers: {}", col1, peer_count);
            info!("  Total time: {}", total_elapsed);
        }
        CurrentStepValue::None => {}
    }
}

/// Push snap sync progress to Prometheus gauges (from METRICS atomics).
/// Called each polling cycle. Rates are NOT computed here — use rate() in Grafana.
#[cfg(feature = "metrics")]
fn push_sync_prometheus_metrics(step: CurrentStepValue) {
    use ethrex_metrics::sync::METRICS_SYNC;
    use std::sync::atomic::Ordering::Relaxed;

    let (phase_num, _) = phase_info(step);
    METRICS_SYNC.stage.set(phase_num as i64);
    METRICS_SYNC
        .pivot_block
        .set(METRICS.sync_head_block.load(Relaxed) as i64);

    // Push raw pivot timestamp — Grafana computes age via time() - timestamp
    let pivot_ts = METRICS.pivot_timestamp.load(Relaxed);
    if pivot_ts > 0 {
        METRICS_SYNC.pivot_timestamp.set(pivot_ts as i64);
    }
    // Also update pivot_age_seconds for RPC/peer_top consumers
    if pivot_ts > 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        METRICS_SYNC
            .pivot_age_seconds
            .set(now.saturating_sub(pivot_ts) as i64);
    }

    match step {
        CurrentStepValue::DownloadingHeaders => {
            let total = METRICS.sync_head_block.load(Relaxed);
            let downloaded = u64::min(METRICS.downloaded_headers.get(), total);
            METRICS_SYNC.headers_downloaded.set(downloaded as i64);
            METRICS_SYNC.headers_total.set(total as i64);
        }
        CurrentStepValue::RequestingAccountRanges => {
            let downloaded = METRICS.downloaded_account_tries.load(Relaxed);
            METRICS_SYNC.accounts_downloaded.set(downloaded as i64);
        }
        CurrentStepValue::InsertingAccountRanges | CurrentStepValue::InsertingAccountRangesNoDb => {
            let total = METRICS.downloaded_account_tries.load(Relaxed);
            let inserted = METRICS.account_tries_inserted.load(Relaxed);
            METRICS_SYNC.accounts_downloaded.set(total as i64);
            METRICS_SYNC.accounts_inserted.set(inserted as i64);
        }
        CurrentStepValue::RequestingStorageRanges => {
            let downloaded = METRICS.storage_leaves_downloaded.get();
            METRICS_SYNC.storage_downloaded.set(downloaded as i64);
        }
        CurrentStepValue::InsertingStorageRanges => {
            let inserted = METRICS.storage_leaves_inserted.get();
            METRICS_SYNC.storage_inserted.set(inserted as i64);
        }
        CurrentStepValue::HealingState => {
            let healed = METRICS.global_state_trie_leafs_healed.load(Relaxed);
            METRICS_SYNC.state_leaves_healed.set(healed as i64);
        }
        CurrentStepValue::HealingStorage => {
            let healed = METRICS.global_storage_tries_leafs_healed.load(Relaxed);
            METRICS_SYNC.storage_leaves_healed.set(healed as i64);
        }
        CurrentStepValue::RequestingBytecodes => {
            let total = METRICS.bytecodes_to_download.load(Relaxed);
            let downloaded = METRICS.downloaded_bytecodes.load(Relaxed);
            METRICS_SYNC.bytecodes_downloaded.set(downloaded as i64);
            METRICS_SYNC.bytecodes_total.set(total as i64);
        }
        CurrentStepValue::None => {}
    }
}

fn progress_bar(percentage: f64, width: usize) -> String {
    let clamped_percentage = percentage.clamp(0.0, 100.0);
    let filled = ((clamped_percentage / 100.0) * width as f64) as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);
    format!("{}{}", "▓".repeat(filled), "░".repeat(empty))
}

fn format_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Shows the amount of connected peers, active peers, and peers suitable for snap sync on a set interval
pub async fn periodically_show_peer_stats_after_sync(peer_table: &PeerTable) {
    const INTERVAL_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(60);
    let mut interval = tokio::time::interval(INTERVAL_DURATION);
    loop {
        // clone peers to keep the lock short
        let peers: Vec<PeerData> = peer_table.get_peers_data().await.unwrap_or(Vec::new());
        let active_peers = peers
            .iter()
            .filter(|peer| -> bool { peer.connection.as_ref().is_some() })
            .count();
        let snap_active_peers = peers
            .iter()
            .filter(|peer| -> bool {
                peer.connection.as_ref().is_some()
                    && SUPPORTED_SNAP_CAPABILITIES
                        .iter()
                        .any(|cap| peer.supported_capabilities.contains(cap))
            })
            .count();
        info!("Peers: {active_peers} (snap-capable: {snap_active_peers})");
        interval.tick().await;
    }
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// How often to re-derive the fork id. A fork boundary is a timestamp, so the ENR
/// can lag a crossing by at most this long; cheap enough to keep tight.
const FORK_ID_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Publishes the current fork id, re-deriving it periodically.
///
/// `initial` is the fork id the initial ENR was built with — the channel must be
/// seeded with what the record actually advertises, not a fresh storage read, or a
/// fork crossed between the two reads would never register as a change. `None`
/// (the chain could not supply one at startup) still spawns the publisher: the
/// first successful derivation then counts as a change and gives the ENR its
/// `eth` entry, instead of a transient startup failure disabling refresh for good.
fn spawn_fork_id_publisher(
    context: &P2PContext,
    initial: Option<ForkId>,
) -> watch::Receiver<Option<ForkId>> {
    let storage = context.storage.clone();
    let (tx, rx) = watch::channel(initial);
    context.tracker.spawn(async move {
        let mut interval = tokio::time::interval(FORK_ID_REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            match storage.get_fork_id().await {
                // `send_if_modified` keeps the receiver's change flag clean when the
                // chain has not moved across a fork, so discovery does no work.
                Ok(fork_id) => {
                    tx.send_if_modified(|current| {
                        if current.as_ref() == Some(&fork_id) {
                            false
                        } else {
                            *current = Some(fork_id);
                            true
                        }
                    });
                }
                // Transient: the next tick retries. Logging every 30s would be noise.
                Err(e) => debug!(error = ?e, "Could not derive the fork id for the local ENR"),
            }
        }
    });
    rx
}
