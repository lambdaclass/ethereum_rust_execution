use std::{
    fmt::Display,
    fs::{File, metadata, read_dir},
    io::{self, Write},
    mem,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use clap::{ArgAction, Parser as ClapParser, Subcommand as ClapSubcommand};
use ethrex_blockchain::{
    BlockchainOptions, BlockchainType, DEFAULT_BLOB_PRICE_BUMP_PERCENT,
    DEFAULT_GAP_ADMIT_OCCUPANCY_THRESHOLD, DEFAULT_MAX_QUEUED_TXS_PER_ACCOUNT, DEFAULT_MIN_TIP_WEI,
    DEFAULT_PRICE_BUMP_PERCENT, L2Config,
    error::{ChainError, InvalidBlockError},
};
use ethrex_common::types::{Block, DEFAULT_BUILDER_GAS_CEIL, Genesis, validate_block_body};
use ethrex_p2p::{
    discovery::INITIAL_LOOKUP_INTERVAL_MS,
    peer_table::TARGET_PEERS,
    sync::{HistoryChain, SyncMode},
    tx_broadcaster::BROADCAST_INTERVAL_MS,
    types::Node,
};
use ethrex_rlp::encode::RLPEncode;
use ethrex_storage::{DB_COMMIT_THRESHOLD, error::StoreError, has_valid_db};
use tokio_util::sync::CancellationToken;
use tracing::{Level, error, info, warn};

use crate::{
    initializers::{
        get_network, init_blockchain, init_store, init_tracing, load_store, regenerate_head_state,
    },
    utils::{
        self, default_datadir, get_client_version, get_client_version_string,
        get_minimal_client_version, init_datadir, is_memory_datadir,
    },
};

pub const DB_ETHREX_DEV_L1: &str = "dev_ethrex_l1";

#[cfg(feature = "l2")]
pub const DB_ETHREX_DEV_L2: &str = "dev_ethrex_l2";
use ethrex_config::networks::Network;

/// Computes the effective datadir by appending a network-specific suffix.
/// In-memory datadirs are returned as-is. Dev mode uses a "dev" suffix.
/// Public networks use their name as suffix (e.g. "mainnet", "sepolia").
pub fn compute_effective_datadir(base: &Path, network: &Network, dev: bool) -> PathBuf {
    if is_memory_datadir(base) {
        return base.to_path_buf();
    }
    if dev && cfg!(feature = "dev") {
        base.join("dev")
    } else if let Some(suffix) = network.datadir_suffix() {
        base.join(suffix)
    } else {
        base.to_path_buf()
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(ClapParser)]
#[command(name="ethrex", author = "Lambdaclass", version=get_client_version_string(), about = "ethrex Execution client", args_override_self = true)]
pub struct CLI {
    #[command(flatten)]
    pub opts: Options,
    #[command(subcommand)]
    pub command: Option<Subcommand>,
}

#[derive(ClapParser, Debug, Clone)]
pub struct Options {
    #[arg(
        long = "network",
        value_name = "GENESIS_FILE_PATH",
        help = "Receives a `Genesis` struct in json format. You can look at some example genesis files at `fixtures/genesis/*`.",
        long_help = "Alternatively, the name of a known network can be provided instead to use its preset genesis file and include its preset bootnodes. The networks currently supported include sepolia, hoodi, plataberget and mainnet. If not specified, defaults to mainnet.",
        help_heading = "Node options",
        env = "ETHREX_NETWORK",
        value_parser = clap::value_parser!(Network),
    )]
    pub network: Option<Network>,
    #[arg(long = "bootnodes", value_parser = clap::value_parser!(Node), value_name = "BOOTNODE_LIST", value_delimiter = ',', num_args = 1.., help = "Comma separated enode URLs for P2P discovery bootstrap.", help_heading = "P2P options", env = "ETHREX_BOOTNODES")]
    pub bootnodes: Vec<Node>,
    #[arg(
        long = "datadir",
        value_name = "DATABASE_DIRECTORY",
        default_value = default_datadir().into_os_string(),
        help = "Base directory for the database. A network-specific subdirectory (e.g. mainnet, sepolia) is appended automatically for public networks.",
        long_help = "Base directory for the database. For public networks a subdirectory named after the network is appended (e.g. ~/.local/share/ethrex/mainnet). If the value is `memory`, the InMemory Engine is used instead.",
        help_heading = "Node options",
        env = "ETHREX_DATADIR"
    )]
    pub datadir: PathBuf,
    #[arg(
        long = "force",
        help = "Force remove the database",
        long_help = "Delete the database without confirmation.",
        action = clap::ArgAction::SetTrue,
        help_heading = "Node options"
    )]
    pub force: bool,
    #[arg(
        long = "rocksdb.block-cache-size",
        value_name = "BYTES",
        help = "RocksDB shared block cache size in bytes, the effective ceiling on RocksDB's \
                resident memory. Defaults to 40% of the memory available to the process \
                (physical or cgroup limit, whichever is lower), clamped to 512 MiB..=12 GiB; \
                where no limit can be detected (no readable /proc, e.g. outside Linux) it \
                defaults to the 12 GiB ceiling.",
        help_heading = "Storage options",
        env = "ETHREX_ROCKSDB_BLOCK_CACHE_SIZE"
    )]
    pub rocksdb_block_cache_size: Option<usize>,
    #[arg(long = "syncmode", default_value = "snap", value_name = "SYNC_MODE", value_parser = utils::parse_sync_mode, help = "The way in which the node will sync its state.", long_help = "Can be either \"full\" or \"snap\" with \"snap\" as default value.", help_heading = "P2P options", env = "ETHREX_SYNCMODE")]
    pub syncmode: SyncMode,
    #[arg(
        long = "history.chain",
        default_value = "off",
        value_name = "HISTORY_CHAIN",
        value_parser = utils::parse_history_chain,
        help = "Backfill historical chain data (bodies + receipts) below the snap pivot.",
        long_help = "Optionally backfill historical block bodies and receipts after snap sync so \
                     the node can serve historical block, transaction, receipt and log queries. \
                     One of \"off\" (default: headers-only below the pivot), \"postmerge\" \
                     (backfill down to the merge block), \"all\" (as far back as receipts are \
                     decodable — down to the Byzantium block, not genesis — best-effort as many \
                     peers no longer serve pre-merge history), or an explicit BLOCK NUMBER \
                     to backfill down to only that block — use this to keep a recent slice of \
                     history instead of everything back to the merge. A block number below the \
                     merge block is honoured but is best-effort like \"all\", and anything below \
                     Byzantium is clamped up to it. Enabling this adds substantial disk usage. \
                     It does not enable historical state queries (this is not an archive node).",
        help_heading = "P2P options",
        env = "ETHREX_HISTORY_CHAIN",
    )]
    pub history_chain: HistoryChain,
    #[arg(
        long = "history.transactions",
        default_value = "0",
        value_name = "BLOCKS",
        help = "Blocks of backfilled history to keep the transaction index for (0 = the entire backfilled range).",
        help_heading = "P2P options",
        env = "ETHREX_HISTORY_TRANSACTIONS"
    )]
    pub history_transactions: u64,
    #[arg(
        long = "metrics.addr",
        value_name = "ADDRESS",
        default_value = "0.0.0.0",
        help_heading = "Node options",
        env = "ETHREX_METRICS_ADDR"
    )]
    pub metrics_addr: String,
    #[arg(
        long = "metrics.port",
        value_name = "PROMETHEUS_METRICS_PORT",
        default_value = "9090", // Default Prometheus port (https://prometheus.io/docs/tutorials/getting_started/#show-me-how-it-is-done).
        help_heading = "Node options",
        env = "ETHREX_METRICS_PORT"
    )]
    pub metrics_port: String,
    #[arg(
        long = "metrics",
        action = ArgAction::SetTrue,
        help = "Enable metrics collection and exposition",
        help_heading = "Node options",
        env = "ETHREX_METRICS"
    )]
    pub metrics_enabled: bool,
    #[arg(
        long = "dev",
        action = ArgAction::SetTrue,
        help = "Used to create blocks without requiring a Consensus Client",
        long_help = "If set it will be considered as `true`. If `--network` is not specified, it will default to a custom local devnet. The Binary has to be built with the `dev` feature enabled.",
        help_heading = "Node options",
        env = "ETHREX_DEV"
    )]
    pub dev: bool,
    #[arg(
        long = "log.level",
        default_value_t = Level::INFO,
        value_name = "LOG_LEVEL",
        env = "ETHREX_LOG_LEVEL",
        help = "The verbosity level used for logs.",
        long_help = "Possible values: info, debug, trace, warn, error",
        help_heading = "Node options")]
    pub log_level: Level,
    #[arg(
        long = "log.color",
        default_value_t = LogColor::Auto,
        help = "Output logs with ANSI color codes.",
        long_help = "Possible values: auto, always, never",
        help_heading = "Node options",
        env = "ETHREX_LOG_COLOR"
    )]
    pub log_color: LogColor,
    #[arg(
        long = "no-migrate",
        action = ArgAction::SetTrue,
        help = "Do not migrate an existing database to the network-specific subdirectory.",
        help_heading = "Node options",
        env = "ETHREX_NO_MIGRATE"
    )]
    pub no_migrate: bool,
    #[arg(
        long = "skip-genesis-validation",
        action = ArgAction::SetTrue,
        help = "Trust a pre-existing datadir's genesis instead of recomputing the genesis state root from the genesis alloc. Use only when booting against a database produced out-of-band (e.g. by a state generator) whose state root you vouch for; has no effect on a fresh datadir.",
        help_heading = "Node options",
        env = "ETHREX_SKIP_GENESIS_VALIDATION"
    )]
    pub skip_genesis_validation: bool,
    #[arg(
        long = "no-precompile-cache",
        action = ArgAction::SetTrue,
        help = "Disable the per-block precompile result cache (benchmarking only).",
        help_heading = "Node options",
        env = "ETHREX_NO_PRECOMPILE_CACHE"
    )]
    pub no_precompile_cache: bool,
    #[arg(
        long = "no-bal-parallel-exec",
        action = ArgAction::SetTrue,
        help = "Disable BAL-driven parallel transaction execution on Amsterdam+ blocks (falls back to sequential).",
        help_heading = "Node options",
        env = "ETHREX_NO_BAL_PARALLEL_EXEC"
    )]
    pub no_bal_parallel_exec: bool,
    #[arg(
        long = "no-bal-prefetch",
        action = ArgAction::SetTrue,
        help = "Disable the BAL-driven state prefetch warmer thread on Amsterdam+ blocks.",
        help_heading = "Node options",
        env = "ETHREX_NO_BAL_PREFETCH"
    )]
    pub no_bal_prefetch: bool,
    #[arg(
        long = "no-bal-parallel-trie",
        action = ArgAction::SetTrue,
        help = "Disable BAL-driven optimistic trie merkleization on Amsterdam+ blocks (falls back to streaming AccountUpdates from the executor).",
        help_heading = "Node options",
        env = "ETHREX_NO_BAL_PARALLEL_TRIE"
    )]
    pub no_bal_parallel_trie: bool,
    #[arg(
        long = "log.dir",
        value_name = "LOG_DIR",
        help = "Directory to store log files.",
        help_heading = "Node options",
        env = "ETHREX_LOG_DIR"
    )]
    pub log_dir: Option<PathBuf>,
    #[arg(
        help = "Maximum size of the mempool in number of transactions",
        long = "mempool.maxsize",
        default_value_t = 10_000,
        value_name = "MEMPOOL_MAX_SIZE",
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_MAX_SIZE"
    )]
    pub mempool_max_size: usize,
    #[arg(
        help = "Minimum priority-fee cap (in wei) required for a transaction to be admitted into the mempool. Compared against the raw tip cap: `max_priority_fee_per_gas` for typed transactions, `gas_price` for legacy transactions (independent of current base fee, so admission stays stable as base fee oscillates). Set to 0 to disable the floor.",
        long = "mempool.min-tip",
        default_value_t = DEFAULT_MIN_TIP_WEI,
        value_name = "MIN_TIP_WEI",
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_MIN_TIP"
    )]
    pub mempool_min_tip: u64,
    #[arg(
        long = "mempool.private",
        default_value_t = false,
        action = ArgAction::SetTrue,
        help = "Node-level config (not a protocol/EIP behavior): keep RPC-submitted transactions private. They enter the mempool and may be included in blocks built locally, but are not propagated to peers. P2P-received transactions are unaffected.",
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_PRIVATE"
    )]
    pub mempool_private: bool,
    #[arg(
        help = "Minimum fee bump (in percent) required to replace a non-blob pooled transaction at the same (sender, nonce).",
        long = "mempool.price-bump",
        default_value_t = DEFAULT_PRICE_BUMP_PERCENT,
        value_name = "PERCENT",
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_PRICE_BUMP"
    )]
    pub mempool_price_bump: u64,
    #[arg(
        help = "Minimum fee bump (in percent) required to replace an EIP-4844 blob pooled transaction.",
        long = "mempool.blob-price-bump",
        default_value_t = DEFAULT_BLOB_PRICE_BUMP_PERCENT,
        value_name = "PERCENT",
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_BLOB_PRICE_BUMP"
    )]
    pub mempool_blob_price_bump: u64,
    #[arg(
        help = "Mempool occupancy percentage (0-100) at or above which incoming transactions with a nonce gap relative to the sender's on-chain nonce are rejected. Setting to 100 disables the check.",
        long = "mempool.gap-admit-occupancy-threshold",
        default_value_t = DEFAULT_GAP_ADMIT_OCCUPANCY_THRESHOLD,
        value_name = "PERCENTAGE",
        value_parser = clap::value_parser!(u8).range(0..=100),
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_GAP_ADMIT_OCCUPANCY_THRESHOLD"
    )]
    pub mempool_gap_admit_occupancy_threshold: u8,
    #[arg(
        help = "Maximum number of queued (future/nonce-gapped) transactions a single sender may hold in the mempool. Executable (contiguous-nonce) txs are not capped (geth AccountQueue-style).",
        long = "mempool.max-queued-txs-per-account",
        default_value_t = DEFAULT_MAX_QUEUED_TXS_PER_ACCOUNT,
        value_name = "MAX_QUEUED_TXS_PER_ACCOUNT",
        help_heading = "Node options",
        env = "ETHREX_MEMPOOL_MAX_QUEUED_TXS_PER_ACCOUNT"
    )]
    pub mempool_max_queued_txs_per_account: usize,
    #[arg(
        long = "http.addr",
        default_value = "127.0.0.1",
        value_name = "ADDRESS",
        help = "Listening address for the http rpc server.",
        long_help = "Listening address for the HTTP JSON-RPC server. Defaults to 127.0.0.1 so the endpoint is only reachable from localhost; pass 0.0.0.0 to bind on all interfaces (only recommended when the node sits behind a trusted firewall or reverse proxy).",
        help_heading = "RPC options",
        env = "ETHREX_HTTP_ADDR"
    )]
    pub http_addr: String,
    #[arg(
        long = "http.port",
        default_value = "8545",
        value_name = "PORT",
        help = "Listening port for the http rpc server.",
        help_heading = "RPC options",
        env = "ETHREX_HTTP_PORT"
    )]
    pub http_port: String,
    #[arg(
        long = "http.api",
        default_value = "eth,net,web3",
        value_name = "NAMESPACES",
        value_delimiter = ',',
        value_parser = utils::parse_http_namespace,
        help = "Comma-separated JSON-RPC namespaces enabled over HTTP/WS.",
        long_help = "Comma-separated list of JSON-RPC namespaces exposed on the public HTTP and WebSocket endpoints. Defaults to `eth,net,web3`. Enable `admin`, `debug`, `txpool` or `testing` only when needed; the `engine` namespace is served on the authenticated RPC port and cannot be toggled here.",
        help_heading = "RPC options",
        env = "ETHREX_HTTP_API"
    )]
    pub http_api: Vec<ethrex_rpc::RpcNamespace>,
    #[arg(
        long = "ws.enabled",
        default_value = "false",
        help = "Enable websocket rpc server. Disabled by default.",
        help_heading = "RPC options",
        env = "ETHREX_ENABLE_WS"
    )]
    pub ws_enabled: bool,
    #[arg(
        long = "ws.addr",
        value_name = "ADDRESS",
        requires = "ws_enabled",
        help = "Listening address for the websocket rpc server. Defaults to the http.addr value.",
        long_help = "Listening address for the WebSocket JSON-RPC server. When unset it inherits `--http.addr` (loopback by default). Set it equal to the HTTP address to serve HTTP and WebSocket on a single listener.",
        help_heading = "RPC options",
        env = "ETHREX_WS_ADDR"
    )]
    pub ws_addr: Option<String>,
    #[arg(
        long = "ws.port",
        value_name = "PORT",
        requires = "ws_enabled",
        help = "Listening port for the websocket rpc server. Defaults to the http.port value.",
        long_help = "Listening port for the WebSocket JSON-RPC server. When unset it inherits `--http.port`, so an enabled WebSocket shares the HTTP listener unless a different port is given.",
        help_heading = "RPC options",
        env = "ETHREX_WS_PORT"
    )]
    pub ws_port: Option<String>,
    #[arg(
        long = "authrpc.addr",
        default_value = "127.0.0.1",
        value_name = "ADDRESS",
        help = "Listening address for the authenticated rpc server.",
        help_heading = "RPC options",
        env = "ETHREX_AUTHRPC_ADDR"
    )]
    pub authrpc_addr: String,
    #[arg(
        long = "authrpc.port",
        default_value = "8551",
        value_name = "PORT",
        help = "Listening port for the authenticated rpc server.",
        help_heading = "RPC options",
        env = "ETHREX_AUTHRPC_PORT"
    )]
    pub authrpc_port: String,
    #[arg(
        long = "authrpc.jwtsecret",
        default_value = "jwt.hex",
        value_name = "JWTSECRET_PATH",
        help = "Receives the jwt secret used for authenticated rpc requests.",
        help_heading = "RPC options",
        env = "ETHREX_AUTHRPC_JWTSECRET_PATH"
    )]
    pub authrpc_jwtsecret: String,
    #[arg(long = "p2p.disabled", default_value = "false", value_name = "P2P_DISABLED", action = ArgAction::SetTrue, help_heading = "P2P options", env = "ETHREX_P2P_DISABLED")]
    pub p2p_disabled: bool,
    #[arg(
        long = "p2p.addr",
        value_name = "ADDRESS",
        help = "Bind address for the P2P protocol (UDP discovery and TCP RLPx).",
        long_help = "The address to bind P2P sockets to. Defaults to the local IP. Use 0.0.0.0 (IPv4) or :: (IPv6) to listen on all interfaces. See also --nat.extip to announce a different external address.",
        help_heading = "P2P options",
        env = "ETHREX_P2P_ADDR"
    )]
    pub p2p_addr: Option<String>,
    #[arg(
        long = "nat.extip",
        value_name = "IP",
        help = "External IP address to announce to peers.",
        long_help = "The IP address advertised to other nodes via discovery and ENR. Use this when the node is behind NAT and --p2p.addr is a private/unspecified address. Defaults to the value of --p2p.addr (or the auto-detected local IP if neither is set).",
        help_heading = "P2P options",
        env = "ETHREX_P2P_NAT_EXTIP"
    )]
    pub nat_extip: Option<String>,
    #[arg(
        long = "p2p.port",
        default_value = "30303",
        value_name = "PORT",
        help = "TCP port for the P2P protocol.",
        help_heading = "P2P options",
        env = "ETHREX_P2P_PORT"
    )]
    pub p2p_port: String,
    #[arg(
        long = "discovery.port",
        default_value = "30303",
        value_name = "PORT",
        help = "UDP port for P2P discovery.",
        help_heading = "P2P options",
        env = "ETHREX_P2P_DISCOVERY_PORT"
    )]
    pub discovery_port: String,
    #[arg(
        long = "p2p.discv4",
        default_value_t = true,
        action = ArgAction::Set,
        help = "Enable discv4 discovery.",
        help_heading = "P2P options"
    )]
    pub discv4_enabled: bool,
    #[arg(
        long = "p2p.discv5",
        default_value_t = true,
        action = ArgAction::Set,
        help = "Enable discv5 discovery.",
        help_heading = "P2P options"
    )]
    pub discv5_enabled: bool,
    #[arg(
        long = "p2p.tx-broadcasting-interval",
        default_value_t = BROADCAST_INTERVAL_MS,
        value_name = "INTERVAL_MS",
        help = "Transaction Broadcasting Time Interval (ms) for batching transactions before broadcasting them.",
        help_heading = "P2P options",
        env = "ETHREX_P2P_TX_BROADCASTING_INTERVAL"
    )]
    pub tx_broadcasting_time_interval: u64,
    #[arg(
        long = "p2p.target-peers",
        default_value_t = TARGET_PEERS,
        value_name = "MAX_PEERS",
        help = "Max amount of connected peers.",
        help_heading = "P2P options",
        env = "ETHREX_P2P_TARGET_PEERS"
    )]
    pub target_peers: usize,
    #[arg(
        long = "p2p.lookup-interval",
        default_value_t = INITIAL_LOOKUP_INTERVAL_MS,
        value_name = "INITIAL_LOOKUP_INTERVAL",
        help = "Initial time interval (ms) between RLPx connection attempts. Widens towards 600ms as the target peer count is approached.",
        help_heading = "P2P options",
        env = "ETHREX_P2P_LOOKUP_INTERVAL"
    )]
    pub lookup_interval: f64,
    #[arg(
        long = "builder.extra-data",
        default_value = get_minimal_client_version(),
        value_name = "EXTRA_DATA",
        help = "Block extra data message.",
        help_heading = "Block building options",
        env = "ETHREX_BUILDER_EXTRA_DATA"
    )]
    pub extra_data: String,
    #[arg(
        long = "builder.gas-limit",
        default_value_t = DEFAULT_BUILDER_GAS_CEIL,
        value_name = "GAS_LIMIT",
        help = "Target block gas limit.",
        help_heading = "Block building options",
        env = "ETHREX_BUILDER_GAS_LIMIT"
    )]
    pub gas_limit: u64,
    #[arg(
        long = "builder.max-blobs",
        value_name = "MAX_BLOBS",
        help = "EIP-7872: Maximum blobs per block for local building. Minimum of 1. Defaults to protocol max.",
        help_heading = "Block building options",
        env = "ETHREX_BUILDER_MAX_BLOBS",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub max_blobs_per_block: Option<u32>,
    #[arg(
        long = "precompute-witnesses",
        action = ArgAction::SetTrue,
        default_value = "false",
        help = "Once synced, computes execution witnesses upon receiving newPayload messages and stores them in local storage",
        help_heading = "Node options",
        env = "ETHREX_PRECOMPUTE_WITNESSES"
    )]
    pub precompute_witnesses: bool,
    #[arg(
        long = "blob-sampling",
        action = ArgAction::SetTrue,
        default_value = "false",
        help = "Enable EIP-8070 PeerDAS blob sampling (sampler/provider state machine). Disabled by default; when off the node always acts as provider (p=1.0).",
        help_heading = "P2P options",
        env = "ETHREX_BLOB_SAMPLING"
    )]
    pub blob_sampling: bool,
    #[arg(
        long = "blob-eager-provider",
        action = ArgAction::SetTrue,
        default_value = "false",
        help = "EIP-8070: always act as provider (p=1.0) for every blob tx, bypassing the pseudo-random role decision. Implies --blob-sampling. Not needed for validators: eager mode latches on permanently the first time the CL requests a payload build.",
        help_heading = "P2P options",
        env = "ETHREX_BLOB_EAGER_PROVIDER"
    )]
    pub blob_eager_provider: bool,
    #[arg(
        long = "max-reorg-depth",
        value_name = "MAX_REORG_DEPTH",
        help = "Optional operator override for the maximum reorg depth. Omit for finality-bounded cap. Set to 0 to disable deep reorgs entirely. Set to d to reject reorgs of depth > d.",
        help_heading = "Node options",
        env = "ETHREX_MAX_REORG_DEPTH"
    )]
    pub max_reorg_depth: Option<u64>,
}

impl Options {
    pub fn default_l1() -> Self {
        Self {
            network: Some(Network::LocalDevnet),
            datadir: DB_ETHREX_DEV_L1.into(),
            dev: true,
            http_addr: "127.0.0.1".to_string(),
            http_port: "8545".to_string(),
            authrpc_port: "8551".to_string(),
            metrics_port: "9090".to_string(),
            authrpc_addr: "localhost".to_string(),
            authrpc_jwtsecret: "jwt.hex".to_string(),
            p2p_port: "30303".into(),
            discovery_port: "30303".into(),
            discv4_enabled: true,
            discv5_enabled: true,
            mempool_max_size: 10_000,
            ..Default::default()
        }
    }

    #[cfg(feature = "l2")]
    pub fn default_l2() -> Self {
        Self {
            network: Some(Network::LocalDevnetL2),
            datadir: DB_ETHREX_DEV_L2.into(),
            metrics_port: "3702".into(),
            metrics_enabled: true,
            dev: true,
            http_addr: "127.0.0.1".into(),
            http_port: "1729".into(),
            authrpc_addr: "localhost".into(),
            authrpc_port: "8551".into(),
            authrpc_jwtsecret: "jwt.hex".into(),
            p2p_port: "30303".into(),
            discovery_port: "30303".into(),
            discv4_enabled: true,
            discv5_enabled: true,
            mempool_max_size: 10_000,
            ..Default::default()
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            http_addr: Default::default(),
            http_port: Default::default(),
            http_api: ethrex_rpc::DEFAULT_HTTP_API.to_vec(),
            ws_enabled: false,
            ws_addr: Default::default(),
            ws_port: Default::default(),
            log_level: Level::INFO,
            log_color: Default::default(),
            log_dir: None,
            authrpc_addr: Default::default(),
            authrpc_port: Default::default(),
            authrpc_jwtsecret: Default::default(),
            p2p_disabled: Default::default(),
            p2p_addr: None,
            nat_extip: None,
            p2p_port: Default::default(),
            discovery_port: Default::default(),
            discv4_enabled: true,
            discv5_enabled: true,
            network: Default::default(),
            bootnodes: Default::default(),
            datadir: Default::default(),
            rocksdb_block_cache_size: None,
            syncmode: Default::default(),
            history_chain: Default::default(),
            history_transactions: Default::default(),
            metrics_addr: "0.0.0.0".to_owned(),
            metrics_port: Default::default(),
            metrics_enabled: Default::default(),
            dev: Default::default(),
            force: false,
            mempool_max_size: Default::default(),
            mempool_min_tip: DEFAULT_MIN_TIP_WEI,
            mempool_private: false,
            mempool_price_bump: DEFAULT_PRICE_BUMP_PERCENT,
            mempool_blob_price_bump: DEFAULT_BLOB_PRICE_BUMP_PERCENT,
            mempool_gap_admit_occupancy_threshold: DEFAULT_GAP_ADMIT_OCCUPANCY_THRESHOLD,
            mempool_max_queued_txs_per_account: DEFAULT_MAX_QUEUED_TXS_PER_ACCOUNT,
            tx_broadcasting_time_interval: Default::default(),
            target_peers: Default::default(),
            lookup_interval: INITIAL_LOOKUP_INTERVAL_MS,
            extra_data: get_minimal_client_version(),
            gas_limit: DEFAULT_BUILDER_GAS_CEIL,
            max_blobs_per_block: None,
            precompute_witnesses: false,
            no_migrate: false,
            skip_genesis_validation: false,
            no_precompile_cache: false,
            no_bal_parallel_exec: false,
            no_bal_prefetch: false,
            no_bal_parallel_trie: false,
            blob_sampling: false,
            blob_eager_provider: false,
            max_reorg_depth: None,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(ClapSubcommand)]
pub enum Subcommand {
    #[command(name = "removedb", about = "Remove the database")]
    RemoveDB {
        #[arg(long = "datadir", value_name = "DATABASE_DIRECTORY", default_value = default_datadir().into_os_string(), required = false)]
        datadir: PathBuf,
        #[arg(long = "force", help = "Force remove the database without confirmation", action = clap::ArgAction::SetTrue)]
        force: bool,
    },
    #[command(name = "import", about = "Import blocks to the database")]
    Import {
        #[arg(
            required = true,
            value_name = "FILE_PATH/FOLDER",
            help = "Path to a RLP chain file or a folder containing files with individual Blocks"
        )]
        path: String,
        #[arg(long = "removedb", action = ArgAction::SetTrue)]
        removedb: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        l2: bool,
    },
    #[command(
        name = "import-bench",
        about = "Import blocks to the database for benchmarking"
    )]
    ImportBench {
        #[arg(
            required = true,
            value_name = "FILE_PATH/FOLDER",
            help = "Path to a RLP chain file or a folder containing files with individual Blocks"
        )]
        path: String,
        #[arg(long = "removedb", action = ArgAction::SetTrue)]
        removedb: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        l2: bool,
        #[arg(
            long = "export-bal",
            value_name = "FILE",
            help = "Export BALs produced during sequential execution to a single RLP file (concatenated, one per block). All BALs are buffered in memory before writing; suitable for benchmark-sized runs, not 100k+ block exports."
        )]
        export_bal: Option<String>,
        #[arg(
            long = "with-bal",
            value_name = "FILE",
            help = "Load BALs from a single RLP file and use the parallel execution path. The entire file is decoded into memory upfront; suitable for benchmark-sized runs, not 100k+ blocks.",
            conflicts_with = "export_bal"
        )]
        with_bal: Option<String>,
    },
    #[command(
        name = "export",
        about = "Export blocks in the current chain into a file in rlp encoding"
    )]
    Export {
        #[arg(
            required = true,
            value_name = "FILE_PATH",
            help = "Path to the file where the rlp blocks will be written to"
        )]
        path: String,
        #[arg(
            long = "first",
            value_name = "NUMBER",
            help = "First block number to export"
        )]
        first: Option<u64>,
        #[arg(
            long = "last",
            value_name = "NUMBER",
            help = "Last block number to export"
        )]
        last: Option<u64>,
    },
    #[command(
        name = "compute-state-root",
        about = "Compute the state root from a genesis file"
    )]
    ComputeStateRoot {
        #[arg(
            required = true,
            long = "path",
            value_name = "GENESIS_FILE_PATH",
            help = "Path to the genesis json file"
        )]
        genesis_path: PathBuf,
    },
    #[command(name = "repl", about = "Interactive REPL for Ethereum JSON-RPC")]
    Repl {
        /// JSON-RPC endpoint URL
        #[arg(short = 'e', long, default_value = "http://localhost:8545")]
        endpoint: String,

        /// Authenticated RPC endpoint URL (for engine namespace)
        #[arg(long = "authrpc.endpoint", default_value = "http://localhost:8551")]
        authrpc_endpoint: String,

        /// Path to JWT secret file for authenticated RPC (hex-encoded)
        #[arg(long = "authrpc.jwtsecret")]
        authrpc_jwtsecret: Option<String>,

        /// Path to command history file
        #[arg(long, default_value = "~/.ethrex/history")]
        history_file: String,

        /// Execute a single command and exit
        #[arg(short = 'x', long)]
        execute: Option<String>,
    },
    #[cfg(feature = "l2")]
    #[command(name = "l2")]
    L2(crate::l2::L2Command),
}

impl Subcommand {
    pub async fn run(self, opts: &Options) -> eyre::Result<()> {
        // L2 has its own init_tracing because of the ethrex monitor
        let _guard = match &self {
            #[cfg(feature = "l2")]
            Self::L2(_) => None,
            _ => {
                let (_, guard) = init_tracing(opts);
                guard
            }
        };

        let network = get_network(opts);
        let effective_datadir = compute_effective_datadir(&opts.datadir, &network, opts.dev);

        // For subcommands that use the store, migrate from the old
        // unsuffixed datadir layout if applicable.
        match &self {
            Subcommand::Import { .. }
            | Subcommand::ImportBench { .. }
            | Subcommand::Export { .. } => {
                crate::initializers::migrate_datadir_if_needed(
                    &opts.datadir,
                    &effective_datadir,
                    &network,
                    opts.no_migrate,
                );
            }
            _ => {}
        }

        match self {
            Subcommand::RemoveDB { datadir, force } => {
                let effective = compute_effective_datadir(&datadir, &network, opts.dev);
                if effective != datadir && has_valid_db(&datadir) && !has_valid_db(&effective) {
                    warn!(
                        "Database found at old location {datadir:?} but removedb targets {effective:?}. \
                         Run with --datadir {datadir:?} or migrate first.",
                    );
                }
                remove_db(&effective, force);
            }
            Subcommand::Import { path, removedb, l2 } => {
                if removedb {
                    remove_db(&effective_datadir, opts.force);
                }

                let genesis = network.get_genesis()?;
                let blockchain_type = if l2 {
                    BlockchainType::L2(L2Config::default())
                } else {
                    BlockchainType::L1
                };
                import_blocks(
                    &path,
                    &effective_datadir,
                    genesis,
                    BlockchainOptions {
                        max_mempool_size: opts.mempool_max_size,
                        r#type: blockchain_type,
                        ..Default::default()
                    },
                )
                .await?;
            }
            Subcommand::ImportBench {
                path,
                removedb,
                l2,
                export_bal,
                with_bal,
            } => {
                if removedb {
                    remove_db(&effective_datadir, opts.force);
                }
                info!("ethrex version: {}", get_client_version());

                let genesis = network.get_genesis()?;
                let blockchain_type = if l2 {
                    BlockchainType::L2(L2Config::default())
                } else {
                    BlockchainType::L1
                };
                import_blocks_bench(
                    &path,
                    &effective_datadir,
                    genesis,
                    BlockchainOptions {
                        r#type: blockchain_type,
                        perf_logs_enabled: true,
                        precompile_cache_enabled: !opts.no_precompile_cache,
                        bal_parallel_exec_enabled: !opts.no_bal_parallel_exec,
                        bal_prefetch_enabled: !opts.no_bal_prefetch,
                        bal_parallel_trie_enabled: !opts.no_bal_parallel_trie,
                        ..Default::default()
                    },
                    export_bal.as_deref(),
                    with_bal.as_deref(),
                )
                .await?;
            }
            Subcommand::Export { path, first, last } => {
                export_blocks(&path, &effective_datadir, first, last).await
            }
            Subcommand::ComputeStateRoot { genesis_path } => {
                let genesis = Network::from(genesis_path).get_genesis()?;
                let state_root = genesis.compute_state_root();
                println!("{state_root:#x}");
            }
            Subcommand::Repl {
                endpoint,
                authrpc_endpoint,
                authrpc_jwtsecret,
                history_file,
                execute,
            } => {
                ethrex_repl::run(
                    endpoint,
                    authrpc_endpoint,
                    authrpc_jwtsecret,
                    history_file,
                    execute,
                )
                .await;
            }
            #[cfg(feature = "l2")]
            Subcommand::L2(command) => command.run().await?,
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum LogColor {
    #[default]
    Auto,
    Always,
    Never,
}

impl Display for LogColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogColor::Auto => write!(f, "auto"),
            LogColor::Always => write!(f, "always"),
            LogColor::Never => write!(f, "never"),
        }
    }
}

impl FromStr for LogColor {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(LogColor::Auto),
            "always" => Ok(LogColor::Always),
            "never" => Ok(LogColor::Never),
            _ => Err(format!(
                "Invalid log color '{}'. Expected: auto, always, or never",
                s
            )),
        }
    }
}

pub fn remove_db(datadir: &Path, force: bool) {
    init_datadir(datadir);

    if datadir.exists() {
        if force {
            std::fs::remove_dir_all(datadir).expect("Failed to remove data directory");
            info!("Database removed successfully.");
        } else {
            print!("Are you sure you want to remove the database? (y/n): ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().eq_ignore_ascii_case("y") {
                std::fs::remove_dir_all(datadir).expect("Failed to remove data directory");
                println!("Database removed successfully.");
            } else {
                println!("Operation canceled.");
            }
        }
    } else {
        warn!("Data directory does not exist: {datadir:?}");
    }
}

pub async fn import_blocks(
    path: &str,
    datadir: &Path,
    genesis: Genesis,
    blockchain_opts: BlockchainOptions,
) -> Result<(), ChainError> {
    const IMPORT_BATCH_SIZE: usize = 1024;
    // This value is higher than the spec (128) as the latter block's state nodes will be kept in memory and not committed when using rocksdb
    // This means we need to run some extra-blocks to ensure we commit their state and don't need to regenerate the full block range upon node restart
    const MIN_FULL_BLOCKS: usize = 132;
    let start_time = Instant::now();
    init_datadir(datadir);
    let store = init_store(datadir, genesis).await?;
    let blockchain = init_blockchain(store.clone(), blockchain_opts);
    // Re-execute any blocks above the last committed state root so the in-memory diff
    // layers are populated before this import appends. Required for per-file imports
    // (e.g. EEST consume-rlp fork-transition fixtures) where each invocation's tail
    // layers are dropped on process exit and the next file's parent state would
    // otherwise be unreachable.
    // Offline import: no syncer will run, so an unreachable state is fatal here.
    crate::initializers::regenerate_head_state(&store, &blockchain, false)
        .await
        .map_err(|e| ChainError::Custom(format!("regenerate_head_state failed: {e}")))?;
    let path_metadata = metadata(path).expect("Failed to read path");

    // If it's an .rlp file it will be just one chain, but if it's a directory there can be multiple chains.
    let chains: Vec<Vec<Block>> = if path_metadata.is_dir() {
        info!(path = %path, "Importing blocks from directory");
        let mut entries: Vec<_> = read_dir(path)
            .expect("Failed to read blocks directory")
            .map(|res| res.expect("Failed to open file in directory").path())
            .collect();

        // Sort entries to process files in order (e.g., 1.rlp, 2.rlp, ...)
        entries.sort();

        entries
            .iter()
            .map(|entry| {
                let path_str = entry.to_str().expect("Couldn't convert path to string");
                info!(path = %path_str, "Importing blocks from file");
                utils::read_chain_file(path_str)
            })
            .collect()
    } else {
        info!(path = %path, "Importing blocks from file");
        vec![utils::read_chain_file(path)]
    };

    let mut total_blocks_imported = 0;
    for blocks in chains {
        let mut block_batch = vec![];
        let size = blocks.len();
        let mut numbers_and_hashes = blocks
            .iter()
            .map(|b| (b.header.number, b.hash()))
            .collect::<Vec<_>>();
        // Execute block by block
        let mut last_progress_log = Instant::now();
        for (index, block) in blocks.into_iter().enumerate() {
            let hash = block.hash();
            let number = block.header.number;

            // Log progress every 10 seconds
            if last_progress_log.elapsed() >= Duration::from_secs(10) {
                let processed = index + 1;
                let percent = (((processed as f64 / size as f64) * 100.0) * 10.0).round() / 10.0;
                info!(processed, total = size, percent, "Import progress");
                last_progress_log = Instant::now();
            }

            // Check if the block is already in the blockchain, if it is do nothing, if not add it
            let block_number = store.get_block_number(hash).await.map_err(|_e| {
                ChainError::Custom(String::from(
                    "Couldn't check if block is already in the blockchain",
                ))
            })?;

            if block_number.is_some() {
                info!("Block {} is already in the blockchain", block.hash());
                continue;
            }

            validate_block_body(&block.header, &block.body, &ethrex_crypto::NativeCrypto)
                .map_err(InvalidBlockError::InvalidBody)?;

            if index + MIN_FULL_BLOCKS < size {
                block_batch.push(block);
                if block_batch.len() >= IMPORT_BATCH_SIZE || index + MIN_FULL_BLOCKS + 1 == size {
                    blockchain
                        .add_blocks_in_batch(
                            mem::take(&mut block_batch),
                            &[],
                            CancellationToken::new(),
                        )
                        .await
                        .map_err(|(err, _)| err)?;
                }
            } else {
                // We need to have the state of the latest 128 blocks
                blockchain
                .add_block_pipeline_bounded(block, None, DB_COMMIT_THRESHOLD)
                .inspect_err(|err| match err {
                    // Block number 1's parent not found, the chain must not belong to the same network as the genesis file
                    ChainError::ParentNotFound if number == 1 => warn!("The chain file is not compatible with the genesis file. Are you sure you selected the correct network?"),
                    _ => warn!("Failed to add block {number} with hash {hash:#x}"),
                })?;
            }
        }

        // Make head canonical and label all special blocks correctly.
        if let Some((head_number, head_hash)) = numbers_and_hashes.pop() {
            store
                .forkchoice_update(
                    numbers_and_hashes,
                    head_number,
                    head_hash,
                    Some(head_number),
                    Some(head_number),
                )
                .await?;
        }

        total_blocks_imported += size;
    }

    let total_duration = start_time.elapsed();
    info!(
        blocks = total_blocks_imported,
        seconds = total_duration.as_secs_f64(),
        "Import completed"
    );
    Ok(())
}

pub async fn import_blocks_bench(
    path: &str,
    datadir: &Path,
    genesis: Genesis,
    blockchain_opts: BlockchainOptions,
    export_bal_path: Option<&str>,
    with_bal_path: Option<&str>,
) -> Result<(), ChainError> {
    let start_time = Instant::now();
    init_datadir(datadir);
    let store = init_store(datadir, genesis).await?;
    let blockchain = init_blockchain(store.clone(), blockchain_opts);
    regenerate_head_state(&store, &blockchain, false)
        .await
        .unwrap();
    let path_metadata =
        metadata(path).unwrap_or_else(|e| panic!("failed to stat path {path:?}: {e}"));

    if let Some(bal_path) = export_bal_path {
        info!(path = %bal_path, "Will export BALs to file");
    }

    // If it's an .rlp file it will be just one chain, but if it's a directory there can be multiple chains.
    let chains: Vec<Vec<Block>> = if path_metadata.is_dir() {
        info!(path = %path, "Importing blocks from directory");
        let mut entries: Vec<_> = read_dir(path)
            .expect("Failed to read blocks directory")
            .map(|res| res.expect("Failed to open file in directory").path())
            .collect();

        // Sort entries to process files in order (e.g., 1.rlp, 2.rlp, ...)
        entries.sort();

        entries
            .iter()
            .map(|entry| {
                let path_str = entry.to_str().expect("Couldn't convert path to string");
                info!(path = %path_str, "Importing blocks from file");
                utils::read_chain_file(path_str)
            })
            .collect()
    } else {
        info!(path = %path, "Importing blocks from file");
        vec![utils::read_chain_file(path)]
    };

    // Pre-load all BALs into memory upfront to avoid per-block I/O during benchmark.
    // Done after chain loading so we can validate the count matches the number of
    // Amsterdam+ blocks across all chains and fail fast on truncated BAL files.
    let preloaded_bals = if let Some(bal_path) = with_bal_path {
        info!(path = %bal_path, "Loading BALs from file (parallel path)");
        use ethrex_common::types::block_access_list::BlockAccessList;
        use ethrex_rlp::decode::RLPDecode as _;
        use std::sync::Arc;
        let data = std::fs::read(bal_path)
            .unwrap_or_else(|e| panic!("failed to read BAL file at {bal_path:?}: {e}"));
        let mut remaining = data.as_slice();
        let mut bals: Vec<Arc<BlockAccessList>> = Vec::new();
        while !remaining.is_empty() {
            let (bal, rest) = BlockAccessList::decode_unfinished(remaining)
                .unwrap_or_else(|e| panic!("failed to decode BAL from {bal_path:?}: {e}"));
            bals.push(Arc::new(bal));
            remaining = rest;
        }
        let amsterdam_blocks = chains
            .iter()
            .flatten()
            .filter(|b| b.header.block_access_list_hash.is_some())
            .count();
        assert_eq!(
            bals.len(),
            amsterdam_blocks,
            "--with-bal file at {bal_path:?} has {} entries but chain has {} Amsterdam+ blocks (block_access_list_hash set). \
             Mismatched BAL files would silently fall through to sequential execution and produce misleading benchmark numbers.",
            bals.len(),
            amsterdam_blocks,
        );
        info!(count = bals.len(), "Loaded BALs into memory");
        Some(bals)
    } else {
        None
    };

    let mut exported_bals = Vec::new();
    let mut total_blocks_imported = 0;
    // Shared across chains: a directory import processes multiple chain files
    // sequentially and the preloaded BAL list spans all Amsterdam+ blocks across
    // all chains, so the cursor must persist between chains.
    let mut bal_index = 0usize;
    for blocks in chains {
        let size = blocks.len();
        let mut numbers_and_hashes = blocks
            .iter()
            .map(|b| (b.header.number, b.hash()))
            .collect::<Vec<_>>();
        // Execute block by block
        let mut last_progress_log = Instant::now();
        for (index, block) in blocks.into_iter().enumerate() {
            let hash = block.hash();
            let number = block.header.number;

            // Log progress every 10 seconds
            if last_progress_log.elapsed() >= Duration::from_secs(10) {
                let processed = index + 1;
                let percent = (((processed as f64 / size as f64) * 100.0) * 10.0).round() / 10.0;
                info!(processed, total = size, percent, "Import progress");
                last_progress_log = Instant::now();
            }

            // Check if the block is already in the blockchain, if it is do nothing, if not add it
            let block_number = store.get_block_number(hash).await.map_err(|_e| {
                ChainError::Custom(String::from(
                    "Couldn't check if block is already in the blockchain",
                ))
            })?;

            if block_number.is_some() {
                info!("Block {} is already in the blockchain", block.hash());
                continue;
            }

            validate_block_body(&block.header, &block.body, &ethrex_crypto::NativeCrypto)
                .map_err(InvalidBlockError::InvalidBody)?;

            // Look up preloaded BAL for this block (if --with-bal was provided).
            // BALs are only produced for Amsterdam+ blocks, so use a separate counter
            // that only advances for blocks that have a BAL hash in the header.
            let bal = if block.header.block_access_list_hash.is_some() {
                let b = preloaded_bals
                    .as_ref()
                    .and_then(|bals| bals.get(bal_index))
                    .cloned();
                bal_index += 1;
                b
            } else {
                None
            };

            if export_bal_path.is_some() {
                // Sequential path: execute and capture the produced BAL
                let produced_bal = blockchain
                    .add_block_pipeline_bounded(block, None, DB_COMMIT_THRESHOLD)
                    .inspect_err(|err| match err {
                        ChainError::ParentNotFound if number == 1 => warn!("The chain file is not compatible with the genesis file. Are you sure you selected the correct network?"),
                        _ => warn!("Failed to add block {number} with hash {hash:#x}"),
                    })?;

                if let Some(bal) = produced_bal {
                    exported_bals.push(bal);
                }
            } else {
                // Normal path (or parallel if BAL was loaded)
                blockchain
                    .add_block_pipeline_bounded(block, bal, DB_COMMIT_THRESHOLD)
                    .inspect_err(|err| match err {
                        ChainError::ParentNotFound if number == 1 => warn!("The chain file is not compatible with the genesis file. Are you sure you selected the correct network?"),
                        _ => warn!("Failed to add block {number} with hash {hash:#x}"),
                    })?;
            }

            // Wait for the persist worker to drain the block just applied: its
            // trie diff-layer build, the disk flush and the in-memory eviction.
            // Keeps the next block's per-block timer from absorbing the previous
            // block's background persistence cost.
            store.wait_for_persistence_idle().await?;
        }

        // Make head canonical and label all special blocks correctly.
        if let Some((head_number, head_hash)) = numbers_and_hashes.pop() {
            store
                .forkchoice_update(
                    numbers_and_hashes,
                    head_number,
                    head_hash,
                    Some(head_number),
                    Some(head_number),
                )
                .await?;
        }

        total_blocks_imported += size;
    }

    // Write all exported BALs to a single file
    if let Some(bal_path) = export_bal_path {
        let mut buf = Vec::new();
        for bal in &exported_bals {
            bal.encode(&mut buf);
        }
        std::fs::write(bal_path, &buf)
            .unwrap_or_else(|e| panic!("failed to write BAL file at {bal_path:?}: {e}"));
        info!(count = exported_bals.len(), "Exported BALs to file");
    }

    let total_duration = start_time.elapsed();
    info!(
        blocks = total_blocks_imported,
        seconds = total_duration.as_secs_f64(),
        "Import completed"
    );
    Ok(())
}

pub async fn export_blocks(
    path: &str,
    datadir: &Path,
    first_number: Option<u64>,
    last_number: Option<u64>,
) {
    init_datadir(datadir);
    let store = match load_store(datadir).await {
        Err(err) => {
            error!("Failed to load Store due to: {err}");
            return;
        }
        Ok(store) => store,
    };
    let start = first_number.unwrap_or_default();

    // If we have no latest block then we don't have any blocks to export
    let latest_number = match store.get_latest_block_number() {
        Ok(number) => number,
        Err(StoreError::MissingLatestBlockNumber) => {
            warn!("No blocks in the current chain, nothing to export!");
            return;
        }
        Err(_) => panic!("Internal DB Error"),
    };

    // Get the earliest available block number to detect pruned blocks
    let earliest_number = match store.get_earliest_block_number().await {
        Ok(number) => number,
        Err(StoreError::MissingEarliestBlockNumber) => {
            // No earliest block set means everything from genesis is available
            0
        }
        Err(err) => {
            error!("Failed to get earliest block number: {err}");
            return;
        }
    };

    // Check that the requested range doesn't exceed our current chain length
    if last_number.is_some_and(|number| number > latest_number) {
        warn!(
            "The requested block range exceeds the current amount of blocks in the chain {latest_number}"
        );
        return;
    }
    let end = last_number.unwrap_or(latest_number);

    // Check if start is before earliest available block (pruned data)
    let adjusted_start = if start < earliest_number {
        warn!(
            requested_start = start,
            earliest_available = earliest_number,
            "Requested start block has been pruned, adjusting to earliest available block"
        );
        earliest_number
    } else {
        start
    };

    // Check that the requested range makes sense
    if adjusted_start > end {
        warn!("Cannot export block range [{adjusted_start}..{end}], please input a valid range");
        return;
    }

    // Fetch blocks from the store and export them to the file
    let mut file = File::create(path).expect("Failed to open file");
    let mut buffer = vec![];
    let mut last_output = Instant::now();
    let mut exported_count: u64 = 0;

    // Denominator for percent completed; avoid division by zero
    let denom = end.saturating_sub(adjusted_start) + 1;
    for n in adjusted_start..=end {
        let block = match store.get_block_by_number(n).await {
            Ok(Some(block)) => block,
            Ok(None) => {
                error!(
                    block_number = n,
                    earliest_available = earliest_number,
                    latest_available = latest_number,
                    "Block is missing within the available range - this indicates database corruption or unexpected state"
                );
                return;
            }
            Err(err) => {
                error!(block_number = n, error = %err, "Failed to read block from DB");
                return;
            }
        };
        block.encode(&mut buffer);
        file.write_all(&buffer).expect("Failed to write to file");
        buffer.clear();
        exported_count += 1;

        // Exporting the whole chain can take a while, so we need to show some output in the meantime
        if last_output.elapsed() > Duration::from_secs(5) {
            let percent = (exported_count * 100) / denom;
            info!(
                current_block = n,
                end_block = end,
                percent_complete = percent,
                blocks_exported = exported_count,
                "Exporting blocks"
            );
            last_output = Instant::now();
        }
    }

    info!(
        blocks_exported = exported_count,
        blocks_requested = end.saturating_sub(start) + 1,
        path = %path,
        "Exported blocks to file"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ethrex_rpc::RpcNamespace;

    /// `--http.addr` must default to `127.0.0.1` so a fresh install on a public
    /// host is not exposed to the open internet.
    #[test]
    fn http_addr_defaults_to_loopback() {
        let cli = CLI::parse_from(["ethrex"]);
        assert_eq!(cli.opts.http_addr, "127.0.0.1");
    }

    /// `--ws.addr`/`--ws.port` inherit the HTTP address/port when unset, so an enabled
    /// WebSocket defaults to a single listener on the (loopback) HTTP endpoint — matching
    /// geth/reth/nethermind and keeping WS off public interfaces by default.
    #[test]
    fn ws_defaults_to_http_endpoint() {
        let cli = CLI::parse_from(["ethrex", "--ws.enabled"]);
        assert!(cli.opts.ws_addr.is_none());
        assert!(cli.opts.ws_port.is_none());
        let http = crate::initializers::get_http_socket_addr(&cli.opts);
        let ws = crate::initializers::get_ws_socket_addr(&cli.opts);
        assert!(
            ws.ip().is_loopback(),
            "WS must default to loopback like HTTP"
        );
        assert_eq!(
            ws, http,
            "WS must share the HTTP endpoint by default (single listener)"
        );
    }

    /// `--http.api` must default to `eth,net,web3`. Operators have to opt in
    /// explicitly to expose `admin`, `debug` or `txpool`.
    #[test]
    fn http_api_defaults_to_safe_namespaces() {
        let cli = CLI::parse_from(["ethrex"]);
        assert_eq!(
            cli.opts.http_api,
            vec![RpcNamespace::Eth, RpcNamespace::Net, RpcNamespace::Web3]
        );
    }

    #[test]
    fn http_api_parses_comma_separated_values() {
        let cli = CLI::parse_from(["ethrex", "--http.api", "eth,debug,admin"]);
        assert_eq!(
            cli.opts.http_api,
            vec![RpcNamespace::Eth, RpcNamespace::Debug, RpcNamespace::Admin]
        );
    }

    #[test]
    fn http_api_parses_testing_namespace() {
        let cli = CLI::parse_from(["ethrex", "--http.api", "eth,testing"]);
        assert_eq!(
            cli.opts.http_api,
            vec![RpcNamespace::Eth, RpcNamespace::Testing]
        );
    }

    #[test]
    fn http_api_rejects_engine_namespace() {
        let result = CLI::try_parse_from(["ethrex", "--http.api", "eth,engine"]);
        assert!(result.is_err(), "engine must not be allowed on --http.api");
    }

    #[test]
    fn http_api_rejects_unknown_namespace() {
        let result = CLI::try_parse_from(["ethrex", "--http.api", "eth,bogus"]);
        assert!(result.is_err());
    }

    #[test]
    fn history_chain_defaults_to_off() {
        let cli = CLI::parse_from(["ethrex"]);
        assert_eq!(cli.opts.history_chain, HistoryChain::Off);
    }

    #[test]
    fn history_chain_parses_keywords() {
        for (arg, expected) in [
            ("off", HistoryChain::Off),
            ("postmerge", HistoryChain::PostMerge),
            ("all", HistoryChain::All),
        ] {
            let cli = CLI::parse_from(["ethrex", "--history.chain", arg]);
            assert_eq!(
                cli.opts.history_chain, expected,
                "for --history.chain {arg}"
            );
        }
    }

    /// Operators who want only a recent slice of history pass an explicit floor
    /// block instead of `postmerge`/`all`.
    #[test]
    fn history_chain_parses_a_floor_block_number() {
        let cli = CLI::parse_from(["ethrex", "--history.chain", "22000000"]);
        assert_eq!(cli.opts.history_chain, HistoryChain::Block(22_000_000));
    }

    #[test]
    fn history_chain_rejects_invalid_values() {
        for arg in ["bogus", "-1", "22_000_000", "1.5", ""] {
            let result = CLI::try_parse_from(["ethrex", "--history.chain", arg]);
            assert!(result.is_err(), "--history.chain {arg:?} must be rejected");
        }
    }

    /// Flags hardcoded by external launchers (kurtosis ethereum-package, docker
    /// compose, etc.) must be overridable from `el_extra_params`. Without
    /// `overrides_with`, clap errors on a duplicate scalar flag and the node
    /// fails to start.
    #[test]
    fn scalar_launch_flags_allow_last_wins_override() {
        let cli = CLI::parse_from([
            "ethrex",
            "--syncmode=full",
            "--syncmode=snap",
            "--log.level=debug",
            "--log.level=trace",
            "--http.addr=0.0.0.0",
            "--http.addr=127.0.0.2",
            "--http.port=8545",
            "--http.port=9000",
            "--authrpc.addr=0.0.0.0",
            "--authrpc.addr=127.0.0.3",
            "--authrpc.port=8551",
            "--authrpc.port=9551",
            "--authrpc.jwtsecret=a.hex",
            "--authrpc.jwtsecret=b.hex",
            "--p2p.port=30303",
            "--p2p.port=30304",
            "--discovery.port=30303",
            "--discovery.port=30305",
            "--metrics.addr=0.0.0.0",
            "--metrics.addr=127.0.0.4",
            "--metrics.port=9090",
            "--metrics.port=9091",
            "--builder.gas-limit=30000000",
            "--builder.gas-limit=45000000",
        ]);
        assert!(matches!(cli.opts.syncmode, SyncMode::Snap));
        assert_eq!(cli.opts.log_level, Level::TRACE);
        assert_eq!(cli.opts.http_addr, "127.0.0.2");
        assert_eq!(cli.opts.http_port, "9000");
        assert_eq!(cli.opts.authrpc_addr, "127.0.0.3");
        assert_eq!(cli.opts.authrpc_port, "9551");
        assert_eq!(cli.opts.authrpc_jwtsecret, "b.hex");
        assert_eq!(cli.opts.p2p_port, "30304");
        assert_eq!(cli.opts.discovery_port, "30305");
        assert_eq!(cli.opts.metrics_addr, "127.0.0.4");
        assert_eq!(cli.opts.metrics_port, "9091");
        assert_eq!(cli.opts.gas_limit, 45000000);
    }

    /// `--http.api` should accumulate across repeated invocations (union) so
    /// operators can extend whatever a launcher passed without restating it.
    #[test]
    fn http_api_repeated_flags_accumulate() {
        let cli = CLI::parse_from([
            "ethrex",
            "--http.api=eth,net,web3",
            "--http.api=debug,admin",
        ]);
        assert_eq!(
            cli.opts.http_api,
            vec![
                RpcNamespace::Eth,
                RpcNamespace::Net,
                RpcNamespace::Web3,
                RpcNamespace::Debug,
                RpcNamespace::Admin,
            ]
        );
    }
}
