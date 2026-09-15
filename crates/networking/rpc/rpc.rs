use crate::authentication::authenticate;
use crate::debug::bad_blocks::GetBadBlocksRequest;
use crate::debug::chain_config::ChainConfigRequest;
use crate::debug::execution_witness::ExecutionWitnessRequest;
use crate::debug::execution_witness_by_hash::ExecutionWitnessByBlockHashRequest;
use crate::debug::set_head::SetHeadRequest;
use crate::engine::blobs::{BlobsV2Request, BlobsV3Request, BlobsV4Request};
use crate::engine::client_version::GetClientVersionV1Request;
use crate::engine::payload::{
    GetPayloadV5Request, GetPayloadV6Request, NewPayloadV5Request, NewPayloadWithWitnessV5Request,
};
use crate::engine::{
    ExchangeCapabilitiesRequest,
    blobs::BlobsV1Request,
    exchange_transition_config::ExchangeTransitionConfigV1Req,
    fork_choice::{
        ForkChoiceUpdatedV1, ForkChoiceUpdatedV2, ForkChoiceUpdatedV3, ForkChoiceUpdatedV4,
    },
    payload::{
        GetPayloadBodiesByHashV1Request, GetPayloadBodiesByHashV2Request,
        GetPayloadBodiesByRangeV1Request, GetPayloadBodiesByRangeV2Request, GetPayloadV1Request,
        GetPayloadV2Request, GetPayloadV3Request, GetPayloadV4Request, NewPayloadV1Request,
        NewPayloadV2Request, NewPayloadV3Request, NewPayloadV4Request,
    },
};
use crate::eth::client::Config;
use crate::eth::{
    account::{
        GetBalanceRequest, GetCodeRequest, GetProofRequest, GetStorageAtRequest,
        GetTransactionCountRequest,
    },
    block::{
        BlockNumberRequest, GetBlobBaseFee, GetBlockByHashRequest, GetBlockByNumberRequest,
        GetBlockReceiptsRequest, GetBlockTransactionCountRequest, GetRawBlockRequest,
        GetRawHeaderRequest, GetRawReceipts, GetUncleCountRequest,
    },
    block_access_list::{BlockAccessListRequest, RawBlockAccessListRequest},
    client::{ChainId, Syncing},
    fee_market::FeeHistoryRequest,
    filter::{
        self, ActiveFilters, DeleteFilterRequest, FilterChangesRequest, NewBlockFilterRequest,
        NewFilterRequest,
    },
    gas_price::GasPrice,
    gas_tip_estimator::GasTipEstimator,
    logs::LogsFilter,
    simulate::EthSimulateRequest,
    transaction::{
        CallRequest, CreateAccessListRequest, EstimateGasRequest, GetRawTransaction,
        GetRawTransactionByBlockAndIndex, GetTransactionByBlockHashAndIndexRequest,
        GetTransactionByBlockNumberAndIndexRequest, GetTransactionByHashRequest,
        GetTransactionReceiptRequest,
    },
};
use crate::subscription_manager::{SubscriptionManager, SubscriptionManagerProtocol};
use crate::testing::BuildBlockV1Request;
use crate::tracing::{
    TraceBlockByHashRequest, TraceBlockByNumberRequest, TraceCallRequest, TraceTransactionRequest,
};
use crate::types::transaction::SendRawTransactionRequest;
use crate::utils::{
    RpcErr, RpcErrorMetadata, RpcErrorResponse, RpcNamespace, RpcRequest, RpcRequestId,
    RpcSuccessResponse,
};
use crate::{admin, net};
use crate::{eth, mempool};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{DefaultBodyLimit, State, WebSocketUpgrade};
use axum::{Json, Router, http::StatusCode, routing::post};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use bytes::Bytes;
use ethrex_blockchain::Blockchain;
use ethrex_blockchain::error::ChainError;
use ethrex_common::types::Block;
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::block_execution_witness::ExecutionWitness;
use ethrex_metrics::rpc::{RpcOutcome, record_async_duration, record_rpc_outcome};
use ethrex_p2p::peer_handler::PeerHandler;
use ethrex_p2p::sync_manager::SyncManager;
use ethrex_p2p::types::SharedLocalNode;
use ethrex_storage::Store;
use serde::Deserialize;
use serde_json::Value;
use spawned_concurrency::tasks::ActorRef;
use std::{
    collections::{HashMap, HashSet},
    future::IntoFuture,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio::sync::{
    Mutex as TokioMutex,
    mpsc::{UnboundedSender, unbounded_channel},
    oneshot,
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, Registry, reload};

#[cfg(all(feature = "jemalloc_profiling", target_os = "linux"))]
use axum::response::IntoResponse;
// only works on linux
#[cfg(all(feature = "jemalloc_profiling", target_os = "linux"))]
pub async fn handle_get_heap() -> Result<impl IntoResponse, (StatusCode, String)> {
    let Some(mutex) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "jemalloc profiling is not available".into(),
        ));
    };
    let mut prof_ctl = mutex.lock().await;
    require_profiling_activated(&prof_ctl)?;
    let pprof = prof_ctl
        .dump_pprof()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(pprof)
}

/// Checks whether jemalloc profiling is activated an returns an error response if not.
#[cfg(all(feature = "jemalloc_profiling", target_os = "linux"))]
fn require_profiling_activated(
    prof_ctl: &jemalloc_pprof::JemallocProfCtl,
) -> Result<(), (StatusCode, String)> {
    if prof_ctl.activated() {
        Ok(())
    } else {
        Err((
            axum::http::StatusCode::FORBIDDEN,
            "heap profiling not activated".into(),
        ))
    }
}

#[cfg(all(feature = "jemalloc_profiling", target_os = "linux"))]
pub async fn handle_get_heap_flamegraph() -> Result<impl IntoResponse, (StatusCode, String)> {
    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Response;

    let Some(mutex) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "jemalloc profiling is not available".into(),
        ));
    };
    let mut prof_ctl = mutex.lock().await;
    require_profiling_activated(&prof_ctl)?;
    let svg = prof_ctl
        .dump_flamegraph()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Response::builder()
        .header(CONTENT_TYPE, "image/svg+xml")
        .body(Body::from(svg))
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

// Feature-disabled stubs (no dependency on jemalloc_pprof)
#[cfg(not(all(feature = "jemalloc_profiling", target_os = "linux")))]
pub async fn handle_get_heap() -> Result<(), (StatusCode, String)> {
    Err((
        StatusCode::NOT_IMPLEMENTED,
        "jemalloc profiling is not available (build with `ethrex-rpc/jemalloc_profiling`, it only works on linux)".into(),
    ))
}

#[cfg(not(all(feature = "jemalloc_profiling", target_os = "linux")))]
pub async fn handle_get_heap_flamegraph() -> Result<(), (StatusCode, String)> {
    Err((
        StatusCode::NOT_IMPLEMENTED,
        "jemalloc profiling is not available (build with `ethrex-rpc/jemalloc_profiling`, it only works on linux)".into(),
    ))
}

/// Wrapper for JSON-RPC requests that can be either single or batched.
///
/// According to the JSON-RPC 2.0 specification, clients may send either a single
/// request object or an array of request objects (batch request).
#[derive(Deserialize)]
#[serde(untagged)]
pub enum RpcRequestWrapper {
    /// A single JSON-RPC request.
    Single(RpcRequest),
    /// A batch of JSON-RPC requests to be processed together.
    Multiple(Vec<RpcRequest>),
}

/// Channel message type for the block executor worker thread.
type BlockWorkerMessage = (
    oneshot::Sender<Result<Option<ExecutionWitness>, ChainError>>,
    Block,
    Option<BlockAccessList>,
    bool,
);

/// This struct contains all the dependencies that RPC handlers need to process requests,
/// including storage access, blockchain state, P2P networking, and configuration.
///
/// The context is cloned for each request, with most fields being cheap `Arc` references.
#[derive(Clone)]
pub struct RpcApiContext {
    /// Database storage for blocks, transactions, and state.
    pub storage: Store,
    /// Blockchain instance for block validation and execution.
    pub blockchain: Arc<Blockchain>,
    /// Active log filters for `eth_newFilter` / `eth_getFilterChanges` endpoints.
    pub active_filters: ActiveFilters,
    /// Sync manager for coordinating block synchronization (None for L2 nodes).
    pub syncer: Option<Arc<SyncManager>>,
    /// Peer handler for P2P network operations (None for L2 nodes).
    pub peer_handler: Option<PeerHandler>,
    /// Node identity and configuration data.
    pub node_data: NodeData,
    /// Gas tip estimator for `eth_gasPrice` and `eth_maxPriorityFeePerGas`.
    pub gas_tip_estimator: Arc<TokioMutex<GasTipEstimator>>,
    /// Handler for dynamically changing log filter levels via `admin_setLogLevel`.
    pub log_filter_handler: Option<reload::Handle<EnvFilter, Registry>>,
    /// Maximum gas limit for blocks (used in payload building).
    pub gas_ceil: u64,
    /// Channel for sending blocks to the block executor worker thread.
    pub block_worker_channel: UnboundedSender<BlockWorkerMessage>,
    /// WebSocket configuration. `None` when the WS server is disabled.
    pub ws: Option<WebSocketConfig>,
    /// Set of RPC namespaces that are allowed over the public HTTP/WS endpoints.
    ///
    /// Methods belonging to namespaces not in this set return `MethodNotFound`.
    /// The `engine` namespace is always served via the authenticated RPC port
    /// and is not gated here.
    pub allowed_namespaces: Arc<HashSet<RpcNamespace>>,
}

/// Configuration for the WebSocket RPC server.
#[derive(Clone)]
pub struct WebSocketConfig {
    /// Socket address the WS server listens on.
    pub addr: SocketAddr,
    /// Actor handle for managing `eth_subscribe` / `eth_unsubscribe` connections.
    pub subscription_manager: ActorRef<SubscriptionManager>,
}

impl std::fmt::Debug for RpcApiContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("RpcApiContext");
        s.field("storage", &self.storage)
            .field("blockchain", &self.blockchain)
            .field("syncer", &self.syncer.as_ref().map(|_| ".."))
            .field("peer_handler", &self.peer_handler.as_ref().map(|_| ".."))
            .field("gas_ceil", &self.gas_ceil);
        s.finish()
    }
}

/// Client version information used for identification in the Engine API and P2P.
///
/// This struct contains the individual components of the client version, which are
/// used by `engine_getClientVersionV1` and other identification endpoints.
///
/// Implements `Display` to return the pre-formatted version string.
#[derive(Debug, Clone)]
pub struct ClientVersion {
    /// Client name (e.g., "ethrex").
    pub name: String,
    /// Semantic version (e.g., "0.1.0").
    pub version: String,
    /// Git branch name (e.g., "main").
    pub branch: String,
    /// Git commit hash (full SHA).
    pub commit: String,
    /// OS and architecture (e.g., "x86_64-apple-darwin").
    pub os_arch: String,
    /// Rust compiler version (e.g., "1.70.0").
    pub rustc_version: String,
    /// Pre-formatted version string for efficient Display.
    formatted: String,
}

impl ClientVersion {
    /// Creates a new ClientVersion with all fields and a pre-formatted string.
    pub fn new(
        name: String,
        version: String,
        branch: String,
        commit: String,
        os_arch: String,
        rustc_version: String,
    ) -> Self {
        let formatted = format!(
            "{}/v{}-{}-{}/{}/rustc-v{}",
            name, version, branch, commit, os_arch, rustc_version
        );
        Self {
            name,
            version,
            branch,
            commit,
            os_arch,
            rustc_version,
            formatted,
        }
    }
}

impl std::fmt::Display for ClientVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.formatted)
    }
}

/// Node identity and configuration information.
///
/// Contains the node's cryptographic identity, network endpoints, and metadata
/// used for P2P discovery and RPC responses.
#[derive(Debug, Clone)]
pub struct NodeData {
    /// JWT secret for authenticating Engine API requests from consensus clients.
    pub jwt_secret: Bytes,
    /// Live-updated local node identity (public key, address, and ENR).
    /// Guarded by a std RwLock; callers must clone values out and drop the guard
    /// before any `.await` to avoid holding a !Send guard across await points.
    pub shared_local_node: SharedLocalNode,
    /// Client version information.
    pub client_version: ClientVersion,
    /// Extra data included in mined blocks.
    pub extra_data: Bytes,
}

/// Trait for implementing JSON-RPC method handlers.
///
/// Each RPC method (e.g., `eth_getBalance`, `engine_newPayloadV3`) is implemented
/// as a struct that implements this trait. The trait provides a standard pattern
/// for parsing parameters and handling requests.
///
/// # Example
///
/// ```ignore
/// struct GetBalanceRequest {
///     address: Address,
///     block: BlockId,
/// }
///
/// impl RpcHandler for GetBalanceRequest {
///     fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
///         let params = params.as_ref().ok_or(RpcErr::MissingParam("params"))?;
///         Ok(Self {
///             address: serde_json::from_value(params[0].clone())?,
///             block: serde_json::from_value(params[1].clone())?,
///         })
///     }
///
///     async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
///         let balance = context.storage.get_balance(self.address, self.block)?;
///         Ok(serde_json::to_value(balance)?)
///     }
/// }
/// ```
#[allow(async_fn_in_trait)]
pub trait RpcHandler: Sized {
    /// Parse JSON-RPC parameters into the handler struct.
    ///
    /// Returns an error if required parameters are missing or have invalid types.
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr>;

    /// Entry point for handling an RPC request.
    ///
    /// This method parses the request, records metrics, and delegates to `handle()`.
    /// Most implementations should not override this method.
    async fn call(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
        let request = Self::parse(&req.params)?;
        let namespace = match req.namespace() {
            Ok(RpcNamespace::Engine) => "engine",
            _ => "rpc",
        };
        let method = req.method.as_str();

        let result =
            record_async_duration(
                namespace,
                method,
                async move { request.handle(context).await },
            )
            .await;

        let outcome = match &result {
            Ok(_) => RpcOutcome::Success,
            Err(err) => RpcOutcome::Error(get_error_kind(err)),
        };
        record_rpc_outcome(namespace, method, outcome);

        result
    }

    /// Handle the RPC request and return a JSON response.
    ///
    /// This is where the actual business logic for the RPC method lives.
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr>;
}

fn get_error_kind(err: &RpcErr) -> &'static str {
    match err {
        RpcErr::MethodNotFound(_) => "MethodNotFound",
        RpcErr::MethodNotServedHere { .. } => "MethodNotServedHere",
        RpcErr::WrongParam(_) => "WrongParam",
        RpcErr::BadParams(_) => "BadParams",
        RpcErr::InvalidParams(_) => "InvalidParams",
        RpcErr::InvalidRequest(_) => "InvalidRequest",
        RpcErr::MissingParam(_) => "MissingParam",
        RpcErr::TooLargeRequest => "TooLargeRequest",
        RpcErr::BadHexFormat(_) => "BadHexFormat",
        RpcErr::UnsupportedFork(_) => "UnsupportedFork",
        RpcErr::Internal(_) => "Internal",
        RpcErr::Vm(_) => "Vm",
        RpcErr::Revert { .. } => "Revert",
        RpcErr::Halt { .. } => "Halt",
        RpcErr::AuthenticationError(_) => "AuthenticationError",
        RpcErr::InvalidForkChoiceState(_) => "InvalidForkChoiceState",
        RpcErr::InvalidPayloadAttributes(_) => "InvalidPayloadAttributes",
        RpcErr::TooDeepReorg(_) => "TooDeepReorg",
        RpcErr::UnknownPayload(_) => "UnknownPayload",
        RpcErr::InvalidProofFormat(_) => "InvalidProofFormat",
        RpcErr::InvalidHeaderFormat(_) => "InvalidHeaderFormat",
        RpcErr::InvalidPayload(_) => "InvalidPayload",
        RpcErr::ProofGenerationUnavailable(_) => "ProofGenerationUnavailable",
        RpcErr::EthSimulate { .. } => "EthSimulate",
        RpcErr::ResourceNotFound(_) => "ResourceNotFound",
        RpcErr::PrunedHistoryUnavailable(_) => "PrunedHistoryUnavailable",
    }
}

/// Duration after which inactive filters are cleaned up.
///
/// Filters created via `eth_newFilter` are automatically removed if not
/// accessed within this duration. In tests, this is set to 1 second for
/// faster test execution.
pub const FILTER_DURATION: Duration = {
    if cfg!(test) {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(5 * 60)
    }
};

/// Spawns a dedicated thread for sequential block execution.
///
/// Blocks received from the consensus client via `engine_newPayload` are sent
/// to this worker thread for execution. This ensures blocks are processed
/// sequentially and prevents the async runtime from being blocked by CPU-intensive
/// block execution.
///
/// Also spawns the mempool prewarmer when enabled (see
/// `ethrex_blockchain::prewarm`): the executor cancels any in-flight warming
/// pass before each import and triggers a new one after each cleanly
/// imported block, when synced and idle.
///
/// # Returns
///
/// An unbounded channel sender for submitting blocks (each submission includes
/// a oneshot channel for receiving the execution result), plus the executor
/// thread's `JoinHandle`.
///
/// The thread runs until every sender is dropped. Long-lived callers (the node)
/// drop the handle and leave it detached; callers that must reclaim the thread
/// deterministically drop the sender first and then join, which is what
/// `test_utils::TestContext` does so a test's threads do not outlive it.
///
/// # Panics
///
/// Panics if the worker thread cannot be spawned.
pub fn start_block_executor(
    blockchain: Arc<Blockchain>,
) -> (
    UnboundedSender<BlockWorkerMessage>,
    std::thread::JoinHandle<()>,
) {
    let (block_worker_channel, mut block_receiver) = unbounded_channel::<BlockWorkerMessage>();
    let prewarmer = ethrex_blockchain::prewarm::MempoolPrewarmer::spawn(blockchain.clone());
    let executor = std::thread::Builder::new()
        .name("block_executor".to_string())
        .spawn(move || {
            while let Some((notify, block, bal, make_witness)) = block_receiver.blocking_recv() {
                // Kill any in-flight warming before touching the executor's
                // resources.
                if let Some(handle) = &prewarmer {
                    handle.cancel_current();
                }
                let imported_header = prewarmer.as_ref().map(|_| block.header.clone());
                let result = (|| {
                    let bal = bal.map(Arc::new);
                    if make_witness {
                        let witness = blockchain.add_block_pipeline_with_witness(block, bal)?;
                        Ok(Some(witness))
                    } else {
                        blockchain.add_block_pipeline(block, bal)?;
                        Ok(None)
                    }
                })();
                // One pass per cleanly imported block, only when synced and
                // idle (no queued blocks): warm the child of the new head.
                if let (Some(handle), Some(header), true) =
                    (&prewarmer, imported_header, result.is_ok())
                    && blockchain.is_synced()
                    && block_receiver.is_empty()
                {
                    handle.trigger(header);
                }
                let _ = notify
                    .send(result)
                    .inspect_err(|_| tracing::error!("failed to notify caller"));
            }
        })
        .expect("Falied to spawn block_executor thread");
    (block_worker_channel, executor)
}

/// Binds the JSON-RPC API listeners and returns them ready to serve.
///
/// This function only **binds** — nothing is served until the returned [`BoundRpc`] is
/// driven with [`BoundRpc::serve`]. Binding in the foreground lets a failure (e.g. a port
/// collision) surface as a typed [`RpcStartupError`] so callers can fail fast and abort
/// the node, instead of silently dropping already-bound listeners from a detached task.
///
/// Up to three endpoints are bound:
///
/// 1. **HTTP** (`http_addr`): Public JSON-RPC endpoint for standard Ethereum methods
///    (`eth_*`, `debug_*`, `net_*`, `admin_*`, `web3_*`, `txpool_*`).
///
/// 2. **WebSocket** (`ws`): Optional endpoint that serves the same methods as HTTP plus
///    the subscription methods `eth_subscribe` / `eth_unsubscribe` (currently only
///    `"newHeads"` is supported). Enabled by passing a [`WebSocketConfig`] containing
///    the listen address and the [`SubscriptionManager`] actor handle. When its address
///    equals `http_addr`, no separate listener is bound: both protocols share the HTTP
///    listener (`POST` → JSON-RPC, `GET` + `Upgrade` → WebSocket).
///
/// 3. **Auth RPC** (`authrpc_addr`): JWT-authenticated endpoint for Engine API methods
///    (`engine_*`) used by consensus clients. Never shares a listener with the public
///    endpoints — it alone carries the 256 MB engine body limit.
///
/// # Arguments
///
/// * `cancel_token` - Node-wide cancellation token; captured by [`BoundRpc::serve`] for
///   graceful shutdown of the servers and their background tasks
/// * `http_addr` - Socket address for the HTTP server (e.g., `127.0.0.1:8545`)
/// * `ws` - Optional [`WebSocketConfig`] with the WS listen address and the
///   [`SubscriptionManager`] actor handle. `None` disables the WebSocket server.
/// * `authrpc_addr` - Socket address for authenticated Engine API (e.g., `127.0.0.1:8551`)
/// * `storage` - Database storage instance
/// * `blockchain` - Blockchain instance for block operations
/// * `jwt_secret` - JWT secret for Engine API authentication
/// * `shared_local_node` - Live-updated local node identity (public key, address, and ENR)
/// * `syncer` - Sync manager for block synchronization
/// * `peer_handler` - Handler for P2P peer operations
/// * `client_version` - Client version information for `web3_clientVersion` and `engine_getClientVersionV1`
/// * `log_filter_handler` - Optional handler for dynamic log level changes
/// * `gas_ceil` - Maximum gas limit for payload building
/// * `extra_data` - Extra data to include in mined blocks
///
/// # Errors
///
/// Returns [`RpcStartupError`] — naming the endpoint role, address, and the CLI flag to
/// change — if any listener fails to bind. Validating the configuration for duplicate or
/// wildcard-overlapping addresses is the caller's responsibility (the node CLI does so
/// before calling).
#[allow(clippy::too_many_arguments)]
pub async fn bind_api(
    cancel_token: CancellationToken,
    http_addr: SocketAddr,
    ws: Option<WebSocketConfig>,
    authrpc_addr: SocketAddr,
    storage: Store,
    blockchain: Arc<Blockchain>,
    jwt_secret: Bytes,
    shared_local_node: SharedLocalNode,
    syncer: SyncManager,
    peer_handler: PeerHandler,
    client_version: ClientVersion,
    log_filter_handler: Option<reload::Handle<EnvFilter, Registry>>,
    gas_ceil: u64,
    extra_data: String,
    allowed_namespaces: HashSet<RpcNamespace>,
) -> Result<BoundRpc, RpcStartupError> {
    // TODO: Refactor how filters are handled,
    // filters are used by the filters endpoints (eth_newFilter, eth_getFilterChanges, ...etc)
    let active_filters = Arc::new(Mutex::new(HashMap::new()));
    // The node runs for the lifetime of the process, so the executor thread is
    // left detached; only test harnesses join it (see `test_utils::TestContext`).
    let (block_worker_channel, _executor) = start_block_executor(blockchain.clone());
    let service_context = RpcApiContext {
        storage,
        blockchain,
        active_filters: active_filters.clone(),
        syncer: Some(Arc::new(syncer)),
        peer_handler: Some(peer_handler),
        node_data: NodeData {
            jwt_secret,
            shared_local_node,
            client_version,
            extra_data: extra_data.into(),
        },
        gas_tip_estimator: Arc::new(TokioMutex::new(GasTipEstimator::new())),
        log_filter_handler,
        gas_ceil,
        block_worker_channel,
        ws: ws.clone(),
        allowed_namespaces: Arc::new(allowed_namespaces),
    };

    // Periodically clean up the active filters for the filters endpoints.
    let filter_cancel = cancel_token.clone();
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(FILTER_DURATION);
        let filters = active_filters.clone();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tracing::debug!("Running filter clean task");
                    filter::clean_outdated_filters(filters.clone(), FILTER_DURATION);
                    tracing::debug!("Filter clean task complete");
                }
                _ = filter_cancel.cancelled() => break,
            }
        }
    });

    // All request headers allowed.
    // All methods allowed.
    // All origins allowed.
    // All headers exposed.
    let cors = CorsLayer::permissive();

    // Serve WebSocket on the HTTP listener when both resolve to the same address, matching
    // geth/reth/nethermind. Merging requires exact SocketAddr equality. Conflicting
    // configurations (duplicate or wildcard-overlapping addresses) are the caller's job to
    // validate up front — the node CLI does so before calling — and a genuine collision
    // still fails the corresponding bind below with a typed error.
    let merged = ws.as_ref().is_some_and(|w| w.addr == http_addr);

    // Root method-router: POST is JSON-RPC; when merged, a GET carrying the WebSocket
    // upgrade is routed to the WS handler on the same listener.
    let root = if merged {
        post(handle_http_request).get(ws_upgrade_handler)
    } else {
        post(handle_http_request)
    };
    let http_router = Router::new()
        .route("/debug/pprof/allocs", axum::routing::get(handle_get_heap))
        .route(
            "/debug/pprof/allocs/flamegraph",
            axum::routing::get(handle_get_heap_flamegraph),
        )
        .route("/", root)
        .layer(cors.clone())
        .with_state(service_context.clone());

    // Consensus-liveness channel: the sender lives in the Auth-RPC handler state (so it
    // drops when the servers stop); the receiver is handed to `serve` to spawn the monitor.
    let (timer_sender, timer_receiver) = tokio::sync::watch::channel(());
    let authrpc_handler = move |ctx, auth, body| async move {
        let _ = timer_sender.send(());
        handle_authrpc_request(ctx, auth, body).await
    };
    let authrpc_router = Router::new()
        .route("/", post(authrpc_handler))
        .with_state(service_context.clone())
        // Bump the body limit for the engine API to 256MB. This stays scoped to Auth-RPC:
        // it is never applied to the public HTTP/WS endpoints (which keep axum's default).
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024));

    // Bind everything up front. The first failure aborts with an actionable error naming
    // the role, address, and flag; no listener is announced unless it actually bound.
    let http_listener = bind_listener(RpcRole::Http, http_addr).await?;
    if merged {
        info!("HTTP-RPC + WebSocket server listening on {http_addr}");
    } else {
        info!("HTTP-RPC server listening on {http_addr}");
    }

    let authrpc_listener = bind_listener(RpcRole::AuthRpc, authrpc_addr).await?;
    info!("Auth-RPC server listening on {authrpc_addr}");

    let ws_bound = match &ws {
        Some(ws_config) if !merged => {
            let ws_router = Router::new()
                .route("/", axum::routing::any(ws_upgrade_handler))
                .layer(cors)
                .with_state(service_context);
            let ws_listener = bind_listener(RpcRole::Ws, ws_config.addr).await?;
            info!("WebSocket server listening on {}", ws_config.addr);
            Some((ws_listener, ws_router))
        }
        _ => None,
    };

    Ok(BoundRpc {
        http: (http_listener, http_router),
        authrpc: (authrpc_listener, authrpc_router),
        ws: ws_bound,
        consensus_receiver: timer_receiver,
        cancel_token,
    })
}

/// RPC listeners bound and ready to serve. Produced by [`bind_api`] and consumed by
/// [`BoundRpc::serve`]. Splitting bind from serve lets a bind failure be surfaced and fail
/// fast in the foreground, before any server task is spawned.
pub struct BoundRpc {
    http: (TcpListener, Router),
    authrpc: (TcpListener, Router),
    /// Present only when WebSocket runs on its own listener (i.e. not merged onto HTTP).
    ws: Option<(TcpListener, Router)>,
    /// Receiver for the consensus-liveness monitor; its sender lives in the Auth-RPC
    /// handler state and drops when the servers stop.
    consensus_receiver: tokio::sync::watch::Receiver<()>,
    /// Observed by graceful shutdown and the background tasks so a node-wide cancellation
    /// (Ctrl+C or a fatal subsystem) tears the RPC servers down cleanly.
    cancel_token: CancellationToken,
}

impl BoundRpc {
    /// Serves every bound listener until graceful shutdown, returning the first serve
    /// error so the caller can treat a runtime serve failure as fatal.
    pub async fn serve(self) -> Result<(), RpcErr> {
        // Warn when the consensus layer goes silent; stop cleanly (no busy-loop) once the
        // Auth-RPC handler's sender drops at shutdown.
        let cancel_token = self.cancel_token;
        let mut timer_receiver = self.consensus_receiver;
        let consensus_cancel = cancel_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = timeout(Duration::from_secs(30), timer_receiver.changed()) => {
                        match result {
                            Err(_elapsed) => {
                                warn!(
                                    "No messages from the consensus layer. Is the consensus client running?"
                                );
                            }
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => break,
                        }
                    }
                    _ = consensus_cancel.cancelled() => break,
                }
            }
        });

        let (http_listener, http_router) = self.http;
        let http_server = axum::serve(http_listener, http_router)
            .with_graceful_shutdown(shutdown_signal(cancel_token.clone()))
            .into_future();

        let (authrpc_listener, authrpc_router) = self.authrpc;
        let authrpc_server = axum::serve(authrpc_listener, authrpc_router)
            .with_graceful_shutdown(shutdown_signal(cancel_token.clone()))
            .into_future();

        if let Some((ws_listener, ws_router)) = self.ws {
            let ws_server = axum::serve(ws_listener, ws_router)
                .with_graceful_shutdown(shutdown_signal(cancel_token.clone()))
                .into_future();
            tokio::try_join!(authrpc_server, http_server, ws_server)
                .map_err(|e| RpcErr::Internal(e.to_string()))?;
        } else {
            tokio::try_join!(authrpc_server, http_server)
                .map_err(|e| RpcErr::Internal(e.to_string()))?;
        }
        Ok(())
    }
}

/// Binds and serves the RPC API until shutdown. Compatibility wrapper over [`bind_api`] +
/// [`BoundRpc::serve`] for embedders; the node itself uses `bind_api` directly so a bind
/// failure fails fast in the foreground.
///
/// # Shutdown
///
/// The servers shut down when `cancel_token` is cancelled or on SIGINT (Ctrl+C); see
/// [`shutdown_signal`]. `bind_api` gives finer control (typed bind errors, deferred serve).
#[allow(clippy::too_many_arguments)]
pub async fn start_api(
    http_addr: SocketAddr,
    ws: Option<WebSocketConfig>,
    authrpc_addr: SocketAddr,
    storage: Store,
    blockchain: Arc<Blockchain>,
    jwt_secret: Bytes,
    shared_local_node: SharedLocalNode,
    syncer: SyncManager,
    peer_handler: PeerHandler,
    client_version: ClientVersion,
    log_filter_handler: Option<reload::Handle<EnvFilter, Registry>>,
    gas_ceil: u64,
    extra_data: String,
    allowed_namespaces: HashSet<RpcNamespace>,
    cancel_token: CancellationToken,
) -> Result<(), RpcErr> {
    bind_api(
        cancel_token,
        http_addr,
        ws,
        authrpc_addr,
        storage,
        blockchain,
        jwt_secret,
        shared_local_node,
        syncer,
        peer_handler,
        client_version,
        log_filter_handler,
        gas_ceil,
        extra_data,
        allowed_namespaces,
    )
    .await?
    .serve()
    .await
}

/// Role of an RPC listener, used to produce actionable startup diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcRole {
    Http,
    Ws,
    AuthRpc,
}

impl std::fmt::Display for RpcRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RpcRole::Http => "HTTP-RPC server",
            RpcRole::Ws => "WebSocket server",
            RpcRole::AuthRpc => "Auth-RPC server",
        })
    }
}

impl RpcRole {
    /// CLI flags an operator can change to resolve a bind conflict for this role.
    pub fn flags(&self) -> &'static str {
        match self {
            RpcRole::Http => "--http.port (or --http.addr)",
            RpcRole::Ws => "--ws.port (or --ws.addr)",
            RpcRole::AuthRpc => "--authrpc.port (or --authrpc.addr)",
        }
    }
}

/// A fatal error binding an RPC listener at startup. Deliberately distinct from [`RpcErr`]:
/// startup/bind failures are process-level and must not be rendered through the per-request
/// JSON-RPC error machinery, nor leak an `io::Error` into a JSON-RPC response.
#[derive(Debug, thiserror::Error)]
#[error("failed to bind {role} to {addr}: {source}. {hint}")]
pub struct RpcStartupError {
    pub role: RpcRole,
    pub addr: SocketAddr,
    #[source]
    pub source: std::io::Error,
    pub hint: String,
}

impl From<RpcStartupError> for RpcErr {
    fn from(err: RpcStartupError) -> Self {
        // Only used by the `start_api` compatibility wrapper; the fail-fast path keeps the
        // typed `RpcStartupError` all the way to the top-level handler.
        RpcErr::Internal(err.to_string())
    }
}

/// Binds a TCP listener for the given role, mapping any failure to an actionable
/// [`RpcStartupError`] that names the role, the address, and the flag to change.
pub async fn bind_listener(
    role: RpcRole,
    addr: SocketAddr,
) -> Result<TcpListener, RpcStartupError> {
    TcpListener::bind(addr)
        .await
        .map_err(|source| RpcStartupError {
            role,
            addr,
            source,
            hint: format!("Change {} to a free port.", role.flags()),
        })
}

/// WebSocket upgrade handler. Shared by the merged HTTP listener (as the `GET` route) and
/// the standalone WebSocket listener. A `GET` without a valid upgrade is rejected by
/// [`WebSocketUpgrade`] with a 4xx status (`400` for missing/invalid upgrade headers).
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(ctx): State<RpcApiContext>,
) -> axum::response::Response {
    ws.on_upgrade(|mut socket| async move {
        handle_websocket(&mut socket, &ctx, |req| {
            let c = ctx.clone();
            async move { map_http_requests(&req, c).await }
        })
        .await;
    })
}

/// Graceful-shutdown future for the RPC servers: completes on SIGINT (Ctrl+C) or when
/// `cancel_token` is cancelled.
///
/// `server_shutdown` cancels the token on both SIGINT and SIGTERM, so keying on the token
/// (not just Ctrl+C) is what makes the servers — the Engine API in particular — stop
/// accepting requests on SIGTERM (e.g. `docker stop`) before the store is flushed, and lets
/// a fatal subsystem abort the node.
pub async fn shutdown_signal(cancel_token: CancellationToken) {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                // Installing the Ctrl+C handler failed (rare). Do NOT panic here: a panic
                // in a spawned server task could be misread as a serve failure. Fall back
                // to cancellation-driven shutdown only. The select! has already resolved
                // (its cancelled() arm was dropped), so await the token again here rather
                // than park on a pending future.
                warn!(
                    "Failed to install Ctrl+C handler: {error}; relying on the cancellation token"
                );
                cancel_token.cancelled().await;
            }
        }
        _ = cancel_token.cancelled() => {}
    }
}

/// Maximum number of requests accepted in a single JSON-RPC batch on either
/// the public HTTP port or the engine auth port. Matches geth's
/// `--engine.batchitemlimit` default. Larger batches are rejected up front
/// with `-32600 InvalidRequest` before any per-request work runs.
const MAX_BATCH_SIZE: usize = 1000;

/// JSON-RPC 2.0 §5.1: when the request body is not a valid Request object the
/// response id MUST be null. Build these transport-level errors directly so we
/// don't have to encode "no id" through `RpcRequestId`.
fn null_id_error(err: RpcErr) -> Value {
    let meta: RpcErrorMetadata = err.into();
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": meta,
    })
}

/// Validate a batch envelope. Returns `Some(error_value)` for empty or
/// oversize batches (short-circuits dispatch), `None` if the request is
/// ok to process.
fn validate_batch(wrapper: &RpcRequestWrapper) -> Option<Value> {
    let RpcRequestWrapper::Multiple(requests) = wrapper else {
        return None;
    };
    if requests.is_empty() {
        return Some(null_id_error(RpcErr::InvalidRequest(
            "empty batch is not a valid Request".to_string(),
        )));
    }
    if requests.len() > MAX_BATCH_SIZE {
        return Some(null_id_error(RpcErr::InvalidRequest(format!(
            "batch too large: {} > {MAX_BATCH_SIZE}",
            requests.len()
        ))));
    }
    None
}

pub(crate) async fn handle_http_request(
    State(service_context): State<RpcApiContext>,
    body: String,
) -> Result<Json<Value>, StatusCode> {
    let wrapper: RpcRequestWrapper = match serde_json::from_str(&body) {
        Ok(w) => w,
        Err(_) => {
            return Ok(Json(
                rpc_response(
                    RpcRequestId::String("".to_string()),
                    Err(RpcErr::BadParams("Invalid request body".to_string())),
                )
                .map_err(|_| StatusCode::BAD_REQUEST)?,
            ));
        }
    };

    if let Some(err) = validate_batch(&wrapper) {
        return Ok(Json(err));
    }

    let res = match wrapper {
        RpcRequestWrapper::Single(request) => {
            let res = map_http_requests(&request, service_context).await;
            rpc_response(request.id, res).map_err(|_| StatusCode::BAD_REQUEST)?
        }
        RpcRequestWrapper::Multiple(requests) => {
            let mut responses = Vec::with_capacity(requests.len());
            for req in requests {
                let res = map_http_requests(&req, service_context.clone()).await;
                responses.push(rpc_response(req.id, res).map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            serde_json::to_value(responses).map_err(|_| StatusCode::BAD_REQUEST)?
        }
    };
    Ok(Json(res))
}

pub async fn handle_authrpc_request(
    State(service_context): State<RpcApiContext>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    body: String,
) -> Result<Json<Value>, StatusCode> {
    let wrapper: RpcRequestWrapper = match serde_json::from_str(&body) {
        Ok(w) => w,
        Err(_) => {
            return Ok(Json(null_id_error(RpcErr::InvalidRequest(
                "could not parse JSON-RPC request body".to_string(),
            ))));
        }
    };

    // Reject empty / oversize batches before any auth or dispatch work so a
    // 100k-request body can't burn JWT crypto or memory.
    if let Some(err) = validate_batch(&wrapper) {
        return Ok(Json(err));
    }

    if let Err(error) = authenticate(&service_context.node_data.jwt_secret, auth_header) {
        // Auth failed: respond before dispatching anything. For batches, mirror
        // the batch shape and emit one error response per request so clients
        // can still correlate by id.
        let error_meta: RpcErrorMetadata = error.into();
        let res = match wrapper {
            RpcRequestWrapper::Single(req) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": error_meta,
            }),
            RpcRequestWrapper::Multiple(requests) => {
                let mut responses = Vec::with_capacity(requests.len());
                for req in requests {
                    responses.push(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": req.id,
                        "error": error_meta.clone(),
                    }));
                }
                serde_json::to_value(responses).map_err(|_| StatusCode::BAD_REQUEST)?
            }
        };
        return Ok(Json(res));
    }

    let res = match wrapper {
        RpcRequestWrapper::Single(req) => {
            let res = map_authrpc_requests(&req, service_context).await;
            rpc_response(req.id, res).map_err(|_| StatusCode::BAD_REQUEST)?
        }
        RpcRequestWrapper::Multiple(requests) => {
            let mut responses = Vec::with_capacity(requests.len());
            for req in requests {
                let res = map_authrpc_requests(&req, service_context.clone()).await;
                responses.push(rpc_response(req.id, res).map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            serde_json::to_value(responses).map_err(|_| StatusCode::BAD_REQUEST)?
        }
    };
    Ok(Json(res))
}

/// Handle a WebSocket connection.
///
/// Supports eth_subscribe / eth_unsubscribe for "newHeads" in addition to
/// regular JSON-RPC request-response calls that work the same as over HTTP.
///
/// The `route_request` closure handles non-subscription JSON-RPC methods.
/// L1 passes its own `map_http_requests`; L2 passes its variant so that
/// L2-specific methods (e.g. `ethrexL2_*`) are reachable over WebSocket.
pub async fn handle_websocket<F, Fut, E>(
    socket: &mut WebSocket,
    context: &RpcApiContext,
    route_request: F,
) where
    F: Fn(RpcRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Value, E>>,
    E: Into<RpcErrorMetadata>,
{
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(
        crate::subscription_manager::SUBSCRIBER_CHANNEL_CAPACITY,
    );
    // Currently only "newHeads" subscriptions are supported. When additional
    // subscription types (e.g., "logs", "newPendingTransactions") are added,
    // the subscription tracking below will need per-type handling.
    let mut subscription_ids: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            msg = socket.recv() => {
                let Some(msg) = msg else { break };
                let body = match msg {
                    Ok(Message::Text(text)) => text.to_string(),
                    Ok(Message::Close(_)) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                };

                let response = handle_ws_request(
                    &body, context, &out_tx, &mut subscription_ids, &route_request,
                ).await;
                if let Some(resp) = response
                    && socket.send(Message::Text(resp.into())).await.is_err()
                {
                    break;
                }
            }

            Some(msg) = out_rx.recv() => {
                if socket.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(ws) = &context.ws {
        for id in subscription_ids {
            let _ = ws.subscription_manager.unsubscribe(id).await;
        }
    }
}

async fn handle_ws_request<F, Fut, E>(
    body: &str,
    context: &RpcApiContext,
    out_tx: &tokio::sync::mpsc::Sender<String>,
    subscription_ids: &mut Vec<String>,
    route_request: &F,
) -> Option<String>
where
    F: Fn(RpcRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Value, E>>,
    E: Into<RpcErrorMetadata>,
{
    // Parse as raw JSON first so we can distinguish between:
    //   -32700 Parse error (malformed JSON)
    //   -32600 Invalid Request (valid JSON, but not a valid JSON-RPC request object)
    let parsed: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Some(ws_error_response(None, -32700, "Parse error")),
    };

    // Accept both a single request and a batch (array), matching HTTP behavior.
    let wrapper: RpcRequestWrapper = match serde_json::from_value(parsed) {
        Ok(w) => w,
        Err(_) => return Some(ws_error_response(None, -32600, "Invalid Request")),
    };

    match wrapper {
        RpcRequestWrapper::Single(req) => {
            let resp =
                process_ws_request(req, context, out_tx, subscription_ids, route_request).await?;
            Some(resp.to_string())
        }
        RpcRequestWrapper::Multiple(reqs) => {
            // Per JSON-RPC 2.0 spec, an empty batch is an invalid request.
            if reqs.is_empty() {
                return Some(ws_error_response(None, -32600, "Invalid Request"));
            }
            let mut responses = Vec::with_capacity(reqs.len());
            for req in reqs {
                if let Some(resp) =
                    process_ws_request(req, context, out_tx, subscription_ids, route_request).await
                {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                None
            } else {
                serde_json::to_string(&responses).ok()
            }
        }
    }
}

async fn process_ws_request<F, Fut, E>(
    req: RpcRequest,
    context: &RpcApiContext,
    out_tx: &tokio::sync::mpsc::Sender<String>,
    subscription_ids: &mut Vec<String>,
    route_request: &F,
) -> Option<Value>
where
    F: Fn(RpcRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Value, E>>,
    E: Into<RpcErrorMetadata>,
{
    match req.method.as_str() {
        "eth_subscribe" | "eth_unsubscribe" => {
            // Subscriptions are part of the `eth` namespace and must obey the
            // same `--http.api` allowlist as regular `eth_*` requests; otherwise
            // a node started with e.g. `--http.api web3` would still expose
            // `eth_subscribe("newHeads")` over WS.
            if !context.allowed_namespaces.contains(&RpcNamespace::Eth) {
                let err: Result<Value, RpcErr> =
                    Err(namespace_not_enabled(&req.method, RpcNamespace::Eth));
                return rpc_response(req.id, err).ok();
            }
            let result = if req.method == "eth_subscribe" {
                handle_eth_subscribe(&req, context, out_tx, subscription_ids).await
            } else {
                handle_eth_unsubscribe(&req, context, subscription_ids).await
            };
            rpc_response(req.id, result).ok()
        }
        _ => {
            let id = req.id.clone();
            let res = route_request(req).await;
            rpc_response(id, res).ok()
        }
    }
}

/// Build a JSON-RPC 2.0 error response. Used for transport-level errors
/// (parse error, invalid request) where the request ID is unknown.
fn ws_error_response(id: Option<RpcRequestId>, code: i32, message: &str) -> String {
    let id = match id {
        Some(id) => serde_json::to_value(id).unwrap_or(Value::Null),
        None => Value::Null,
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

/// Handle `eth_subscribe`.
///
/// Only `"newHeads"` is supported. Registers this connection with the
/// `SubscriptionManager` actor and returns the subscription ID.
pub async fn handle_eth_subscribe(
    req: &crate::utils::RpcRequest,
    context: &RpcApiContext,
    out_tx: &tokio::sync::mpsc::Sender<String>,
    subscription_ids: &mut Vec<String>,
) -> Result<Value, RpcErr> {
    use crate::subscription_manager::MAX_SUBSCRIPTIONS_PER_CONNECTION;

    let params = req.params.as_deref().unwrap_or(&[]);
    let sub_type = params.first().and_then(|v| v.as_str()).ok_or_else(|| {
        RpcErr::BadParams("eth_subscribe requires a subscription type parameter".to_string())
    })?;

    if subscription_ids.len() >= MAX_SUBSCRIPTIONS_PER_CONNECTION {
        return Err(RpcErr::BadParams(format!(
            "Too many subscriptions (max {MAX_SUBSCRIPTIONS_PER_CONNECTION})"
        )));
    }

    match sub_type {
        "newHeads" => {
            let ws = context
                .ws
                .as_ref()
                .ok_or_else(|| RpcErr::Internal("WebSocket server not enabled".to_string()))?;

            let id = ws
                .subscription_manager
                .subscribe(out_tx.clone())
                .await
                .map_err(|e| RpcErr::Internal(format!("Subscription failed: {e}")))?
                .ok_or_else(|| RpcErr::Internal("Global subscription cap reached".to_string()))?;

            subscription_ids.push(id.clone());
            Ok(Value::String(id))
        }
        other => Err(RpcErr::BadParams(format!(
            "Unsupported subscription type: {other}"
        ))),
    }
}

/// Handle `eth_unsubscribe`.
///
/// Delegates to the [`SubscriptionManager`] actor and returns `true` if the
/// subscription was found and removed, `false` otherwise.
pub async fn handle_eth_unsubscribe(
    req: &crate::utils::RpcRequest,
    context: &RpcApiContext,
    subscription_ids: &mut Vec<String>,
) -> Result<Value, RpcErr> {
    let params = req.params.as_deref().unwrap_or(&[]);
    let sub_id = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcErr::BadParams("eth_unsubscribe requires a subscription ID parameter".to_string())
        })?
        .to_string();

    // Only unsubscribe if the requested ID belongs to this connection.
    let Some(pos) = subscription_ids.iter().position(|id| id == &sub_id) else {
        return Ok(Value::Bool(false));
    };

    let removed = if let Some(ref ws) = context.ws {
        ws.subscription_manager
            .unsubscribe(sub_id)
            .await
            .unwrap_or(false)
    } else {
        false
    };

    if removed {
        subscription_ids.swap_remove(pos);
    }

    Ok(Value::Bool(removed))
}

/// `-32601` for a method whose namespace ethrex implements but this endpoint is
/// not configured to serve. Naming the namespace and the flag keeps a disabled
/// allowlist from reading like an unimplemented method.
fn namespace_not_enabled(method: &str, namespace: RpcNamespace) -> RpcErr {
    RpcErr::MethodNotServedHere {
        method: method.to_string(),
        reason: format!(
            "the '{}' namespace is not enabled on this endpoint; add it to --http.api",
            namespace.as_prefix()
        ),
    }
}

/// `-32601` for `engine_*` reaching the public HTTP port. Distinct from
/// [`namespace_not_enabled`]: `--http.api` refuses `engine` outright, so telling
/// the caller to add it there would send them down a dead end.
fn engine_not_on_http(method: &str) -> RpcErr {
    RpcErr::MethodNotServedHere {
        method: method.to_string(),
        reason: "the 'engine' namespace is served on the authenticated RPC port \
                 (--authrpc.port), not on the public HTTP port"
            .to_string(),
    }
}

/// Handle requests that can come from either clients or other users
pub async fn map_http_requests(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
    let namespace = match req.namespace() {
        Ok(ns) => ns,
        Err(rpc_err) => return Err(rpc_err),
    };
    // Engine is served on the authenticated port only. The CLI parser already
    // rejects `--http.api engine`, but `allowed_namespaces` can also be built
    // programmatically (e.g. in tests or future call sites), so HTTP dispatch
    // must refuse Engine even if it ends up in the set. This runs *before* the
    // allowlist check because `engine` is never in the allowlist on a real node:
    // otherwise every `engine_*` call over HTTP would be told to add `engine` to
    // a flag that rejects it.
    if namespace == RpcNamespace::Engine {
        return Err(engine_not_on_http(&req.method));
    }
    if !context.allowed_namespaces.contains(&namespace) {
        return Err(namespace_not_enabled(&req.method, namespace));
    }
    match namespace {
        RpcNamespace::Eth => map_eth_requests(req, context).await,
        RpcNamespace::Admin => map_admin_requests(req, context).await,
        RpcNamespace::Debug => map_debug_requests(req, context).await,
        RpcNamespace::Web3 => map_web3_requests(req, context),
        RpcNamespace::Net => map_net_requests(req, context).await,
        RpcNamespace::Mempool => map_mempool_requests(req, context),
        RpcNamespace::Testing => map_testing_requests(req, context).await,
        // Unreachable: the guard above already returned. Kept so the match stays
        // exhaustive without a catch-all arm that would silently route a
        // namespace added later.
        RpcNamespace::Engine => Err(engine_not_on_http(&req.method)),
    }
}

/// Handle requests from consensus client
pub async fn map_authrpc_requests(
    req: &RpcRequest,
    context: RpcApiContext,
) -> Result<Value, RpcErr> {
    match req.namespace() {
        Ok(RpcNamespace::Engine) => map_engine_requests(req, context).await,
        Ok(RpcNamespace::Eth) => map_eth_requests(req, context).await,
        // A known namespace that this port does not serve is not the same as an
        // unparseable method name, which `namespace()` already rejects.
        Ok(_) => Err(RpcErr::MethodNotServedHere {
            method: req.method.clone(),
            reason: "the authenticated RPC port only serves the 'engine' and 'eth' namespaces"
                .to_string(),
        }),
        Err(rpc_err) => Err(rpc_err),
    }
}

/// Routes `eth_*` namespace requests to their handlers.
///
/// Handles all standard Ethereum JSON-RPC methods including:
/// - Account queries: `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_getTransactionCount`
/// - Block queries: `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_blockNumber`
/// - Transaction operations: `eth_sendRawTransaction`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`
/// - Gas estimation: `eth_estimateGas`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`
/// - Filters: `eth_newFilter`, `eth_getFilterChanges`, `eth_uninstallFilter`, `eth_getLogs`
/// - Misc: `eth_chainId`, `eth_syncing`, `eth_createAccessList`, `eth_getProof`
pub async fn map_eth_requests(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "eth_chainId" => ChainId::call(req, context).await,
        "eth_syncing" => Syncing::call(req, context).await,
        "eth_getBlockByNumber" => GetBlockByNumberRequest::call(req, context).await,
        "eth_getBlockByHash" => GetBlockByHashRequest::call(req, context).await,
        "eth_getBalance" => GetBalanceRequest::call(req, context).await,
        "eth_getCode" => GetCodeRequest::call(req, context).await,
        "eth_getStorageAt" => GetStorageAtRequest::call(req, context).await,
        "eth_getBlockTransactionCountByNumber" => {
            GetBlockTransactionCountRequest::call(req, context).await
        }
        "eth_getBlockTransactionCountByHash" => {
            GetBlockTransactionCountRequest::call(req, context).await
        }
        "eth_getUncleCountByBlockNumber" => GetUncleCountRequest::call(req, context).await,
        "eth_getUncleCountByBlockHash" => GetUncleCountRequest::call(req, context).await,
        // `eth_`-namespace spellings of the raw-transaction getters. geth,
        // nethermind, reth and erigon all serve these; only the `debug_` form
        // existed here, so tooling probing the `eth_` names saw them as missing.
        "eth_getRawTransactionByHash" => GetRawTransaction::call(req, context).await,
        "eth_getRawTransactionByBlockHashAndIndex" => {
            GetRawTransactionByBlockAndIndex::call(req, context).await
        }
        "eth_getRawTransactionByBlockNumberAndIndex" => {
            GetRawTransactionByBlockAndIndex::call(req, context).await
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            GetTransactionByBlockNumberAndIndexRequest::call(req, context).await
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            GetTransactionByBlockHashAndIndexRequest::call(req, context).await
        }
        "eth_getBlockReceipts" => GetBlockReceiptsRequest::call(req, context).await,
        "eth_getBlockAccessList" => BlockAccessListRequest::call(req, context).await,
        "eth_getTransactionByHash" => GetTransactionByHashRequest::call(req, context).await,
        "eth_getTransactionReceipt" => GetTransactionReceiptRequest::call(req, context).await,
        "eth_createAccessList" => CreateAccessListRequest::call(req, context).await,
        "eth_blockNumber" => BlockNumberRequest::call(req, context).await,
        "eth_call" => CallRequest::call(req, context).await,
        "eth_simulateV1" => EthSimulateRequest::call(req, context).await,
        "eth_blobBaseFee" => GetBlobBaseFee::call(req, context).await,
        "eth_getTransactionCount" => GetTransactionCountRequest::call(req, context).await,
        "eth_feeHistory" => FeeHistoryRequest::call(req, context).await,
        "eth_estimateGas" => EstimateGasRequest::call(req, context).await,
        "eth_getLogs" => LogsFilter::call(req, context).await,
        "eth_newFilter" => {
            NewFilterRequest::stateful_call(req, context.storage, context.active_filters).await
        }
        "eth_newBlockFilter" => {
            NewBlockFilterRequest::stateful_call(req, context.storage, context.active_filters).await
        }
        "eth_uninstallFilter" => {
            DeleteFilterRequest::stateful_call(req, context.storage, context.active_filters)
        }
        "eth_getFilterChanges" => {
            FilterChangesRequest::stateful_call(req, context.storage, context.active_filters).await
        }
        "eth_sendRawTransaction" => SendRawTransactionRequest::call(req, context).await,
        "eth_getProof" => GetProofRequest::call(req, context).await,
        "eth_gasPrice" => GasPrice::call(req, context).await,
        "eth_maxPriorityFeePerGas" => {
            eth::max_priority_fee::MaxPriorityFee::call(req, context).await
        }
        "eth_config" => Config::call(req, context).await,
        unknown_eth_method => Err(RpcErr::MethodNotFound(unknown_eth_method.to_owned())),
    }
}

/// Routes `testing_*` namespace requests to their handlers.
///
/// Testing-only methods for fixture generation. This namespace is disabled by
/// default and must never be exposed on public-facing RPC APIs.
pub async fn map_testing_requests(
    req: &RpcRequest,
    context: RpcApiContext,
) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "testing_buildBlockV1" => BuildBlockV1Request::call(req, context).await,
        unknown_testing_method => Err(RpcErr::MethodNotFound(unknown_testing_method.to_owned())),
    }
}

/// Routes `debug_*` namespace requests to their handlers.
///
/// Handles debugging and introspection methods:
/// - Raw data: `debug_getRawHeader`, `debug_getRawBlock`, `debug_getRawTransaction`, `debug_getRawReceipts`, `debug_getRawBlockAccessList`
/// - Execution witness: `debug_executionWitness` (for stateless validation)
/// - Tracing: `debug_traceTransaction`, `debug_traceBlockByNumber`, `debug_traceBlockByHash`, `debug_traceCall`
pub async fn map_debug_requests(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "debug_getRawHeader" => GetRawHeaderRequest::call(req, context).await,
        "debug_getRawBlock" => GetRawBlockRequest::call(req, context).await,
        "debug_getRawTransaction" => GetRawTransaction::call(req, context).await,
        "debug_getRawReceipts" => GetRawReceipts::call(req, context).await,
        "debug_getRawBlockAccessList" => RawBlockAccessListRequest::call(req, context).await,
        "debug_executionWitness" => ExecutionWitnessRequest::call(req, context).await,
        "debug_executionWitnessByBlockHash" => {
            ExecutionWitnessByBlockHashRequest::call(req, context).await
        }
        "debug_chainConfig" => ChainConfigRequest::call(req, context).await,
        "debug_getBadBlocks" => GetBadBlocksRequest::call(req, context).await,
        "debug_setHead" => SetHeadRequest::call(req, context).await,
        "debug_traceTransaction" => TraceTransactionRequest::call(req, context).await,
        "debug_traceBlockByNumber" => TraceBlockByNumberRequest::call(req, context).await,
        "debug_traceBlockByHash" => TraceBlockByHashRequest::call(req, context).await,
        "debug_traceCall" => TraceCallRequest::call(req, context).await,
        unknown_debug_method => Err(RpcErr::MethodNotFound(unknown_debug_method.to_owned())),
    }
}

/// Routes `engine_*` namespace requests to their handlers.
///
/// These are Engine API methods used by consensus clients (e.g., Lighthouse, Prysm)
/// to communicate with the execution layer. All methods require JWT authentication.
///
/// Handles:
/// - Fork choice: `engine_forkchoiceUpdatedV1/V2/V3`
/// - Payload submission: `engine_newPayloadV1/V2/V3/V4/V5`, `engine_newPayloadWithWitnessV5`
/// - Payload retrieval: `engine_getPayloadV1/V2/V3/V4/V5/V6`
/// - Payload bodies: `engine_getPayloadBodiesByHashV1`, `engine_getPayloadBodiesByRangeV1`
/// - Blob retrieval: `engine_getBlobsV1/V2/V3/V4`
/// - Capabilities: `engine_exchangeCapabilities`, `engine_exchangeTransitionConfigurationV1`
pub async fn map_engine_requests(
    req: &RpcRequest,
    context: RpcApiContext,
) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "engine_exchangeCapabilities" => ExchangeCapabilitiesRequest::call(req, context).await,
        "engine_forkchoiceUpdatedV1" => Box::pin(ForkChoiceUpdatedV1::call(req, context)).await,
        "engine_forkchoiceUpdatedV2" => Box::pin(ForkChoiceUpdatedV2::call(req, context)).await,
        "engine_forkchoiceUpdatedV3" => Box::pin(ForkChoiceUpdatedV3::call(req, context)).await,
        "engine_forkchoiceUpdatedV4" => Box::pin(ForkChoiceUpdatedV4::call(req, context)).await,
        // The newPayload handlers carry the largest futures of any engine arm
        // (block execution + optional witness collection). Because this `match`
        // awaits each arm inline, the future of `map_engine_requests` is sized to
        // its largest arm and shared by every engine request. Box these arms so
        // they live on the heap instead of inflating the stack frame that even a
        // lightweight `forkchoiceUpdated` poll must reserve — otherwise a single
        // poll overflows the 2 MB tokio worker stack in unoptimized debug builds.
        "engine_newPayloadWithWitnessV5" => {
            Box::pin(NewPayloadWithWitnessV5Request::call(req, context)).await
        }
        "engine_newPayloadV5" => Box::pin(NewPayloadV5Request::call(req, context)).await,
        "engine_newPayloadV4" => Box::pin(NewPayloadV4Request::call(req, context)).await,
        "engine_newPayloadV3" => Box::pin(NewPayloadV3Request::call(req, context)).await,
        "engine_newPayloadV2" => NewPayloadV2Request::call(req, context).await,
        "engine_newPayloadV1" => NewPayloadV1Request::call(req, context).await,
        "engine_exchangeTransitionConfigurationV1" => {
            ExchangeTransitionConfigV1Req::call(req, context).await
        }
        "engine_getPayloadV6" => GetPayloadV6Request::call(req, context).await,
        "engine_getPayloadV5" => GetPayloadV5Request::call(req, context).await,
        "engine_getPayloadV4" => GetPayloadV4Request::call(req, context).await,
        "engine_getPayloadV3" => GetPayloadV3Request::call(req, context).await,
        "engine_getPayloadV2" => GetPayloadV2Request::call(req, context).await,
        "engine_getPayloadV1" => GetPayloadV1Request::call(req, context).await,
        "engine_getPayloadBodiesByHashV1" => {
            GetPayloadBodiesByHashV1Request::call(req, context).await
        }
        "engine_getPayloadBodiesByRangeV1" => {
            GetPayloadBodiesByRangeV1Request::call(req, context).await
        }
        "engine_getPayloadBodiesByHashV2" => {
            GetPayloadBodiesByHashV2Request::call(req, context).await
        }
        "engine_getPayloadBodiesByRangeV2" => {
            GetPayloadBodiesByRangeV2Request::call(req, context).await
        }
        "engine_getBlobsV1" => BlobsV1Request::call(req, context).await,
        "engine_getBlobsV2" => BlobsV2Request::call(req, context).await,
        "engine_getBlobsV3" => BlobsV3Request::call(req, context).await,
        "engine_getBlobsV4" => BlobsV4Request::call(req, context).await,
        "engine_getClientVersionV1" => GetClientVersionV1Request::call(req, context).await,
        unknown_engine_method => Err(RpcErr::MethodNotFound(unknown_engine_method.to_owned())),
    }
}

pub async fn map_admin_requests(
    req: &RpcRequest,
    mut context: RpcApiContext,
) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "admin_nodeInfo" => admin::node_info(context.storage, &context.node_data).await,
        "admin_peers" => admin::peers(&mut context).await,
        "admin_peerScores" => admin::peer_scores(&mut context).await,
        "admin_syncStatus" => admin::sync_status(&mut context).await,
        "admin_setLogLevel" => admin::set_log_level(req, &context.log_filter_handler),
        "admin_addPeer" => admin::add_peer(&mut context, req).await,
        unknown_admin_method => Err(RpcErr::MethodNotFound(unknown_admin_method.to_owned())),
    }
}

pub fn map_web3_requests(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "web3_clientVersion" => Ok(Value::String(context.node_data.client_version.to_string())),
        unknown_web3_method => Err(RpcErr::MethodNotFound(unknown_web3_method.to_owned())),
    }
}

pub async fn map_net_requests(req: &RpcRequest, contex: RpcApiContext) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "net_version" => net::version(req, contex),
        "net_listening" => net::listening(req, contex),
        "net_peerCount" => net::peer_count(req, contex).await,
        unknown_net_method => Err(RpcErr::MethodNotFound(unknown_net_method.to_owned())),
    }
}

pub fn map_mempool_requests(req: &RpcRequest, contex: RpcApiContext) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        // TODO: The endpoint name matches geth's endpoint for compatibility, consider changing it in the future
        "txpool_content" => mempool::content(contex),
        "txpool_contentFrom" => mempool::content_from(&req.params, contex),
        "txpool_status" => mempool::status(contex),
        "txpool_inspect" => mempool::inspect(contex),
        unknown_mempool_method => Err(RpcErr::MethodNotFound(unknown_mempool_method.to_owned())),
    }
}

/// Formats a handler result into a JSON-RPC 2.0 response.
///
/// Wraps the result in either a success response (with `result` field) or
/// an error response (with `error` field containing code and message).
///
/// # Arguments
///
/// * `id` - The request ID to include in the response (must match the request)
/// * `res` - The handler result, either success value or error
///
/// # Returns
///
/// A JSON value representing the complete JSON-RPC 2.0 response object.
pub fn rpc_response<E>(id: RpcRequestId, res: Result<Value, E>) -> Result<Value, RpcErr>
where
    E: Into<RpcErrorMetadata>,
{
    Ok(match res {
        Ok(result) => serde_json::to_value(RpcSuccessResponse {
            id,
            jsonrpc: "2.0".to_string(),
            result,
        }),
        Err(error) => serde_json::to_value(RpcErrorResponse {
            id,
            jsonrpc: "2.0".to_string(),
            error: error.into(),
        }),
    }?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::default_context_with_storage;
    use ethrex_common::{
        H160,
        types::{BlockHeader, ChainConfig, Genesis},
    };
    use ethrex_crypto::keccak::keccak_hash;
    use ethrex_storage::{EngineType, Store};
    use std::io::BufReader;
    use std::str::FromStr;
    use std::{fs::File, path::Path};

    /// With the default `--http.api` allowlist (`eth,net,web3`), requests for
    /// disabled namespaces like `debug_*` must be refused before the handler and
    /// must say *why*: a bare "Method not found" reads as "ethrex does not
    /// implement `debug_traceTransaction`", which is what operators kept
    /// concluding.
    #[tokio::test]
    async fn http_api_allowlist_blocks_debug_namespace_by_default() {
        let body = r#"{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x0"],"id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let mut context = default_context_with_storage(storage).await;
        context.allowed_namespaces = Arc::new(crate::DEFAULT_HTTP_API.iter().copied().collect());

        let result = map_http_requests(&request, context.clone()).await;
        match result {
            Err(RpcErr::MethodNotServedHere { method, reason }) => {
                assert_eq!(method, "debug_traceTransaction");
                assert!(reason.contains("'debug'"), "names the namespace: {reason}");
                assert!(reason.contains("--http.api"), "names the flag: {reason}");
            }
            other => panic!("expected MethodNotServedHere, got {other:?}"),
        }
    }

    /// The reason must reach the wire under the spec's `-32601`, so a client that
    /// keys on the code is unaffected while a human (or an agent) reading the
    /// message learns the method exists.
    #[test]
    fn namespace_not_enabled_serializes_as_method_not_found() {
        let meta: RpcErrorMetadata =
            namespace_not_enabled("txpool_content", RpcNamespace::Mempool).into();
        assert_eq!(meta.code, -32601);
        assert!(
            meta.message.contains("txpool_content"),
            "names the method: {}",
            meta.message
        );
        // The CLI spelling, not the enum variant name: `--http.api txpool`.
        assert!(
            meta.message.contains("'txpool'"),
            "names the CLI namespace: {}",
            meta.message
        );
        assert!(
            meta.message.contains("--http.api"),
            "names the flag: {}",
            meta.message
        );
    }

    /// A bind conflict must surface as a typed `RpcStartupError` naming the role and the
    /// exact flag to change — the diagnostic that was missing during the port-collision
    /// incident (a swallowed `EADDRINUSE`).
    #[tokio::test]
    async fn bind_listener_reports_conflict_with_role_and_flag() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = occupied.local_addr().unwrap();

        let err = bind_listener(RpcRole::Ws, addr)
            .await
            .expect_err("binding an already-occupied port must fail");
        assert_eq!(err.role, RpcRole::Ws);
        assert_eq!(err.addr, addr);
        let msg = err.to_string();
        assert!(msg.contains("WebSocket server"), "names the role: {msg}");
        assert!(msg.contains("--ws.port"), "names the flag: {msg}");
    }

    /// The default allowlist must keep `eth_*`, `net_*`, and `web3_*` reachable.
    #[tokio::test]
    async fn http_api_allowlist_default_routes_standard_namespaces() {
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let mut context = default_context_with_storage(storage).await;
        context.allowed_namespaces = Arc::new(crate::DEFAULT_HTTP_API.iter().copied().collect());

        for method in ["eth_chainId", "net_version", "web3_clientVersion"] {
            let body = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":[],"id":1}}"#);
            let request: RpcRequest = serde_json::from_str(&body).unwrap();
            let result = map_http_requests(&request, context.clone()).await;
            assert!(
                !matches!(
                    result,
                    Err(RpcErr::MethodNotFound(_) | RpcErr::MethodNotServedHere { .. })
                ),
                "default allowlist should route {method}, got {result:?}"
            );
        }
    }

    /// WebSocket subscriptions live in the `eth` namespace and must obey the
    /// same `--http.api` allowlist as regular `eth_*` requests. A node started
    /// without `eth` in the allowlist must not serve `eth_subscribe` over WS.
    #[tokio::test]
    async fn ws_subscribe_blocked_when_eth_namespace_disabled() {
        let body = r#"{"jsonrpc":"2.0","method":"eth_subscribe","params":["newHeads"],"id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let mut context = default_context_with_storage(storage).await;
        // Allow everything except `eth` so the WS path is the only thing under test.
        let mut without_eth: HashSet<RpcNamespace> = crate::test_utils::all_namespaces_for_tests();
        without_eth.remove(&RpcNamespace::Eth);
        context.allowed_namespaces = Arc::new(without_eth);

        let (out_tx, _out_rx) = tokio::sync::mpsc::channel::<String>(1);
        let mut subscription_ids: Vec<String> = Vec::new();
        let route_request = |_req: RpcRequest| async move {
            panic!(
                "route_request must not be called for eth_subscribe when the namespace is disabled"
            );
            #[allow(unreachable_code)]
            Ok::<Value, RpcErr>(Value::Null)
        };

        let response = process_ws_request(
            request,
            &context,
            &out_tx,
            &mut subscription_ids,
            &route_request,
        )
        .await
        .expect("process_ws_request should return an error response");

        let err = response.get("error").expect("expected error field");
        assert_eq!(
            err.get("code").and_then(|v| v.as_i64()),
            Some(-32601),
            "expected MethodNotFound (-32601), got {response}"
        );
        assert!(
            subscription_ids.is_empty(),
            "no subscription should have been registered"
        );
    }

    /// On a normally-configured node `engine` is simply absent from the
    /// allowlist, so this is the path every real `engine_*` call over HTTP takes.
    /// It must point at the authenticated port rather than at `--http.api`, which
    /// refuses `engine`.
    #[tokio::test]
    async fn engine_namespace_on_http_points_at_the_authenticated_port() {
        let body = r#"{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV3","params":[],"id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let mut context = default_context_with_storage(storage).await;
        context.allowed_namespaces = Arc::new(crate::DEFAULT_HTTP_API.iter().copied().collect());

        let result = map_http_requests(&request, context.clone()).await;
        match result {
            Err(RpcErr::MethodNotServedHere { method, reason }) => {
                assert_eq!(method, "engine_forkchoiceUpdatedV3");
                assert!(
                    reason.contains("--authrpc.port"),
                    "points at the authenticated port: {reason}"
                );
                assert!(
                    !reason.contains("--http.api"),
                    "must not send the caller to a flag that rejects `engine`: {reason}"
                );
            }
            other => panic!("expected MethodNotServedHere, got {other:?}"),
        }
    }

    /// The Engine namespace must never be served over the public HTTP endpoint,
    /// even if an operator passes `engine` to `--http.api` (the CLI rejects it,
    /// but defense-in-depth: the dispatcher still refuses).
    #[tokio::test]
    async fn engine_namespace_rejected_on_http() {
        let body = r#"{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV3","params":[],"id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let mut context = default_context_with_storage(storage).await;
        let mut all_with_engine: HashSet<RpcNamespace> =
            crate::test_utils::all_namespaces_for_tests();
        all_with_engine.insert(RpcNamespace::Engine);
        context.allowed_namespaces = Arc::new(all_with_engine);

        let result = map_http_requests(&request, context.clone()).await;
        match result {
            Err(RpcErr::MethodNotServedHere { method, reason }) => {
                assert_eq!(method, "engine_forkchoiceUpdatedV3");
                assert!(
                    reason.contains("--authrpc.port"),
                    "points at the authenticated port: {reason}"
                );
            }
            other => panic!("expected MethodNotServedHere, got {other:?}"),
        }
    }

    // Maps string rpc response to RpcSuccessResponse as serde Value
    // This is used to avoid failures due to field order and allow easier string comparisons for responses
    fn to_rpc_response_success_value(str: &str) -> serde_json::Value {
        serde_json::to_value(serde_json::from_str::<RpcSuccessResponse>(str).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn admin_nodeinfo_request() {
        let body = r#"{"jsonrpc":"2.0", "method":"admin_nodeInfo", "params":[], "id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let context = default_context_with_storage(storage).await;
        let (local_p2p_node, enr_url) = {
            let guard = context.node_data.shared_local_node.read().unwrap();
            let node = guard.node.clone();
            let enr_url = guard.record.enr_url().unwrap();
            (node, enr_url)
        };
        let result = map_http_requests(&request, context.clone()).await;
        let rpc_response = rpc_response(request.id, result).unwrap();
        let blob_schedule = serde_json::json!({
            "cancun": { "baseFeeUpdateFraction": 3338477, "max": 6, "target": 3,  },
            "prague": { "baseFeeUpdateFraction": 5007716, "max": 9, "target": 6,  },
            "osaka": { "baseFeeUpdateFraction": 5007716, "max": 9, "target": 6,  },
            "bpo1": { "baseFeeUpdateFraction": 8346193, "max": 15, "target": 10,  },
            "bpo2": { "baseFeeUpdateFraction": 11684671, "max": 21, "target": 14,  },
        });
        // Both genesis and head resolve to the default BlockHeader (number 0).
        let default_hash = BlockHeader::default().hash();
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "enode": "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@127.0.0.1:30303",
                "enr": enr_url,
                "id": hex::encode(keccak_hash(local_p2p_node.public_key)),
                "ip": "127.0.0.1",
                "listenAddr": "127.0.0.1:30303",
                "name": "ethrex/v0.1.0-test-abcd1234/x86_64-unknown-linux/rustc-v1.70.0",
                "ports": {
                    "discovery": 30303,
                    "listener": 30303
                },
                "protocols": {
                    "eth": {
                        "network": 3151908,
                        "genesis": default_hash,
                        "config": {
                            "chainId": 3151908,
                            "homesteadBlock": 0,
                            "daoForkBlock": null,
                            "daoForkSupport": false,
                            "eip150Block": 0,
                            "eip155Block": 0,
                            "eip158Block": 0,
                            "byzantiumBlock": 0,
                            "constantinopleBlock": 0,
                            "petersburgBlock": 0,
                            "istanbulBlock": 0,
                            "muirGlacierBlock": null,
                            "berlinBlock": 0,
                            "londonBlock": 0,
                            "arrowGlacierBlock": null,
                            "grayGlacierBlock": null,
                            "mergeNetsplitBlock": 0,
                            "shanghaiTime": 0,
                            "cancunTime": 0,
                            "pragueTime": 1718232101,
                            "verkleTime": null,
                            "osakaTime": null,
                            "bpo1Time": null,
                            "bpo2Time": null,
                            "bpo3Time": null,
                            "bpo4Time": null,
                            "bpo5Time": null,
                            "amsterdamTime": null,
                            "hegotaTime": null,
                            "lstarTime": null,
                            "terminalTotalDifficulty": "0x0",
                            "terminalTotalDifficultyPassed": true,
                            "blobSchedule": blob_schedule,
                            "depositContractAddress": H160::from_str("0x00000000219ab540356cbb839cbe05303d7705fa").unwrap(),
                            "enableVerkleAtGenesis": false,
                        },
                        "head": default_hash,
                    }
                },
            }
        });
        let expected_response = to_rpc_response_success_value(&json.to_string());
        assert_eq!(rpc_response.to_string(), expected_response.to_string())
    }

    // Reads genesis file taken from https://github.com/ethereum/execution-apis/blob/main/tests/genesis.json
    fn read_execution_api_genesis_file() -> Genesis {
        let file = File::open("../../../fixtures/genesis/execution-api.json")
            .expect("Failed to open genesis file");
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).expect("Failed to deserialize genesis file")
    }

    #[tokio::test]
    async fn create_access_list_simple_transfer() {
        // Create Request
        // Request taken from https://github.com/ethereum/execution-apis/blob/main/tests/eth_createAccessList/create-al-value-transfer.io
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_createAccessList","params":[{"from":"0x0c2c51a0990aee1d73c1228de158688341557508","nonce":"0x0","to":"0x0100000000000000000000000000000000000000","value":"0xa"},"0x00"]}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        // Setup initial storage
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        let genesis = read_execution_api_genesis_file();
        storage
            .add_initial_state(genesis)
            .await
            .expect("Failed to add genesis block to DB");
        // Process request
        let context = default_context_with_storage(storage).await;
        let result = map_http_requests(&request, context.clone()).await;
        let response = rpc_response(request.id, result).unwrap();
        let expected_response = to_rpc_response_success_value(
            r#"{"jsonrpc":"2.0","id":1,"result":{"accessList":[],"gasUsed":"0x5208"}}"#,
        );
        assert_eq!(response.to_string(), expected_response.to_string());
    }

    fn example_chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 3151908_u64,
            homestead_block: Some(0),
            eip150_block: Some(0),
            eip155_block: Some(0),
            eip158_block: Some(0),
            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            berlin_block: Some(0),
            london_block: Some(0),
            merge_netsplit_block: Some(0),
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(1718232101),
            terminal_total_difficulty: Some(0),
            terminal_total_difficulty_passed: true,
            deposit_contract_address: H160::from_str("0x00000000219ab540356cbb839cbe05303d7705fa")
                .unwrap(),
            ..Default::default()
        }
    }

    /// Tests that admin_nodeInfo doesn't fail when terminal_total_difficulty
    /// exceeds u64::MAX. Before the fix, serde_json::to_value() would return
    /// "number out of range" because Value::Number can only hold u64/i64/f64.
    #[tokio::test]
    async fn admin_nodeinfo_large_terminal_total_difficulty() {
        // Mainnet's terminal_total_difficulty: 58_750_000_000_000_000_000_000
        // This exceeds u64::MAX (~1.8e19) and triggers the bug with serde_json::to_value().
        let mainnet_ttd: u128 = 58_750_000_000_000_000_000_000;

        let body = r#"{"jsonrpc":"2.0", "method":"admin_nodeInfo", "params":[], "id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        let mut config = example_chain_config();
        config.terminal_total_difficulty = Some(mainnet_ttd);
        storage.set_chain_config(&config).await.unwrap();
        let context = default_context_with_storage(storage).await;

        let result = map_http_requests(&request, context.clone()).await;
        assert!(
            result.is_ok(),
            "admin_nodeInfo should not fail with large terminal_total_difficulty"
        );

        let value = result.unwrap();
        let ttd = value
            .pointer("/protocols/eth/config/terminalTotalDifficulty")
            .expect("terminalTotalDifficulty should be present in response");
        // Serialized as a hex string to avoid serde_json Value::Number u64 limitation.
        assert_eq!(ttd.as_str().unwrap(), "0xc70d808a128d7380000");
    }

    #[tokio::test]
    async fn net_version_test() {
        let body = r#"{"jsonrpc":"2.0","method":"net_version","params":[],"id":67}"#;
        let request: RpcRequest = serde_json::from_str(body).expect("serde serialization failed");
        // Setup initial storage
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let chain_id = storage.get_chain_config().chain_id.to_string();
        let context = default_context_with_storage(storage).await;
        // Process request
        let result = map_http_requests(&request, context.clone()).await;
        let response = rpc_response(request.id, result).unwrap();
        let expected_response_string =
            format!(r#"{{"id":67,"jsonrpc": "2.0","result": "{chain_id}"}}"#);
        let expected_response = to_rpc_response_success_value(&expected_response_string);
        assert_eq!(response.to_string(), expected_response.to_string());
    }

    #[tokio::test]
    async fn net_listening_test() {
        let body = r#"{"jsonrpc":"2.0","method":"net_listening","params":[],"id":67}"#;
        let request: RpcRequest = serde_json::from_str(body).expect("serde serialization failed");
        let mut storage =
            Store::new("temp.db", EngineType::InMemory).expect("Failed to create test DB");
        storage
            .set_chain_config(&example_chain_config())
            .await
            .unwrap();
        let context = default_context_with_storage(storage).await;
        let result = map_http_requests(&request, context.clone()).await;
        let response = rpc_response(request.id, result).unwrap();
        let expected_response =
            to_rpc_response_success_value(r#"{"id":67,"jsonrpc": "2.0","result": true}"#);
        assert_eq!(response.to_string(), expected_response.to_string());
    }

    #[tokio::test]
    async fn eth_config_request_cancun_with_prague_scheduled() {
        let body = r#"{"jsonrpc":"2.0", "method":"eth_config", "params":[], "id":1}"#;
        let request: RpcRequest = serde_json::from_str(body).unwrap();
        let storage = Store::new_from_genesis(
            Path::new("temp.db"),
            EngineType::InMemory,
            "../../../cmd/ethrex/networks/hoodi/genesis.json",
        )
        .await
        .expect("Failed to create test DB");
        let context = default_context_with_storage(storage).await;
        let result = map_http_requests(&request, context.clone()).await;
        let rpc_response = rpc_response(request.id, result).unwrap();
        let json = serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "current": {
                    "activationTime": 0,
                    "blobSchedule": {
                        "baseFeeUpdateFraction": 3338477,
                        "max": 6,
                        "target": 3
                    },
                    "chainId": "0x88bb0",
                    "forkId": "0xbef71d30",
                    "precompiles": {
                        "BLAKE2F": "0x0000000000000000000000000000000000000009",
                        "BN254_ADD": "0x0000000000000000000000000000000000000006",
                        "BN254_MUL": "0x0000000000000000000000000000000000000007",
                        "BN254_PAIRING": "0x0000000000000000000000000000000000000008",
                        "ECREC": "0x0000000000000000000000000000000000000001",
                        "ID": "0x0000000000000000000000000000000000000004",
                        "KZG_POINT_EVALUATION": "0x000000000000000000000000000000000000000a",
                        "MODEXP": "0x0000000000000000000000000000000000000005",
                        "RIPEMD160": "0x0000000000000000000000000000000000000003",
                        "SHA256": "0x0000000000000000000000000000000000000002"
                    },
                    "systemContracts": {
                        "BEACON_ROOTS_ADDRESS": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02"
                    }
                },
                "next": {
                    "activationTime": 1742999832,
                    "blobSchedule": {
                        "baseFeeUpdateFraction": 5007716,
                        "max": 9,
                        "target": 6
                    },
                    "chainId": "0x88bb0",
                    "forkId": "0x0929e24e",
                    "precompiles": {
                        "BLAKE2F": "0x0000000000000000000000000000000000000009",
                        "BLS12_G1ADD": "0x000000000000000000000000000000000000000b",
                        "BLS12_G1MSM": "0x000000000000000000000000000000000000000c",
                        "BLS12_G2ADD": "0x000000000000000000000000000000000000000d",
                        "BLS12_G2MSM": "0x000000000000000000000000000000000000000e",
                        "BLS12_MAP_FP2_TO_G2": "0x0000000000000000000000000000000000000011",
                        "BLS12_MAP_FP_TO_G1": "0x0000000000000000000000000000000000000010",
                        "BLS12_PAIRING_CHECK": "0x000000000000000000000000000000000000000f",
                        "BN254_ADD": "0x0000000000000000000000000000000000000006",
                        "BN254_MUL": "0x0000000000000000000000000000000000000007",
                        "BN254_PAIRING": "0x0000000000000000000000000000000000000008",
                        "ECREC": "0x0000000000000000000000000000000000000001",
                        "ID": "0x0000000000000000000000000000000000000004",
                        "KZG_POINT_EVALUATION": "0x000000000000000000000000000000000000000a",
                        "MODEXP": "0x0000000000000000000000000000000000000005",
                        "RIPEMD160": "0x0000000000000000000000000000000000000003",
                        "SHA256": "0x0000000000000000000000000000000000000002"
                    },
                    "systemContracts": {
                        "BEACON_ROOTS_ADDRESS": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02",
                        "CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS": "0x0000bbddc7ce488642fb579f8b00f3a590007251",
                        "DEPOSIT_CONTRACT_ADDRESS": "0x00000000219ab540356cbb839cbe05303d7705fa",
                        "HISTORY_STORAGE_ADDRESS": "0x0000f90827f1c53a10cb7a02335b175320002935",
                        "WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS": "0x00000961ef480eb55e80d19ad83579a64c007002"
                    }
                },
                "last": {
                    "activationTime": 1762955544,
                    "blobSchedule": {
                        "baseFeeUpdateFraction": 11684671,
                        "max": 21,
                        "target": 14,
                    },
                    "chainId": "0x88bb0",
                    "forkId": "0x23aa1351",
                    "precompiles": {
                        "BLAKE2F": "0x0000000000000000000000000000000000000009",
                        "BLS12_G1ADD": "0x000000000000000000000000000000000000000b",
                        "BLS12_G1MSM": "0x000000000000000000000000000000000000000c",
                        "BLS12_G2ADD": "0x000000000000000000000000000000000000000d",
                        "BLS12_G2MSM": "0x000000000000000000000000000000000000000e",
                        "BLS12_MAP_FP2_TO_G2": "0x0000000000000000000000000000000000000011",
                        "BLS12_MAP_FP_TO_G1": "0x0000000000000000000000000000000000000010",
                        "BLS12_PAIRING_CHECK": "0x000000000000000000000000000000000000000f",
                        "BN254_ADD": "0x0000000000000000000000000000000000000006",
                        "BN254_MUL": "0x0000000000000000000000000000000000000007",
                        "BN254_PAIRING": "0x0000000000000000000000000000000000000008",
                        "ECREC": "0x0000000000000000000000000000000000000001",
                        "ID": "0x0000000000000000000000000000000000000004",
                        "KZG_POINT_EVALUATION": "0x000000000000000000000000000000000000000a",
                        "MODEXP": "0x0000000000000000000000000000000000000005",
                        "P256VERIFY":"0x0000000000000000000000000000000000000100",
                        "RIPEMD160": "0x0000000000000000000000000000000000000003",
                        "SHA256": "0x0000000000000000000000000000000000000002"
                    },
                    "systemContracts": {
                        "BEACON_ROOTS_ADDRESS": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02",
                        "CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS": "0x0000bbddc7ce488642fb579f8b00f3a590007251",
                        "DEPOSIT_CONTRACT_ADDRESS": "0x00000000219ab540356cbb839cbe05303d7705fa",
                        "HISTORY_STORAGE_ADDRESS": "0x0000f90827f1c53a10cb7a02335b175320002935",
                        "WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS": "0x00000961ef480eb55e80d19ad83579a64c007002"
                    }
                },
            }
        });
        let expected_response = to_rpc_response_success_value(&json.to_string());
        assert_eq!(rpc_response.to_string(), expected_response.to_string())
    }
}
