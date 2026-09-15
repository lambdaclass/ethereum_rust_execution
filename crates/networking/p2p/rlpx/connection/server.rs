#[cfg(feature = "l2")]
use crate::rlpx::l2::{
    PERIODIC_BATCH_BROADCAST_INTERVAL, PERIODIC_BLOCK_BROADCAST_INTERVAL,
    l2_connection::{
        self, L2Cast, L2ConnState, handle_based_capability_message, handle_l2_broadcast,
    },
};
use crate::utils::{node_id, public_key_from_signing_key};
use crate::{
    backend,
    discovery::{DiscoveryHandle, PeerEvent},
    metrics::METRICS,
    network::P2PContext,
    peer_table::{PeerTable, PeerTableServerProtocol as _},
    rlpx::{
        Message,
        connection::{codec::RLPxCodec, handshake},
        error::PeerConnectionError,
        eth::{
            block_access_lists::{BlockAccessLists, GetBlockAccessLists},
            blocks::{BlockBodies, BlockHeaders},
            cells::{
                CellsResponseError, GET_CELLS_SOFT_LIMIT_HASHES, GetCells, MAX_CELLS_SERVED,
                cells_per_hash,
            },
            eth72::{
                status::StatusMessage72,
                transactions::{NewPooledTransactionHashes72, PooledTransactions72},
            },
            receipts::{
                GetReceipts68, GetReceipts70, Receipts68, Receipts69, Receipts70,
                SOFT_RESPONSE_LIMIT,
            },
            status::{StatusMessage68, StatusMessage69, StatusMessage70, StatusMessage71},
            transactions::{GetPooledTransactions, NewPooledTransactionHashes},
            update::BlockRangeUpdate,
        },
        message::EthCapVersion,
        p2p::{
            self, Capability, DisconnectMessage, DisconnectReason, PingMessage, PongMessage,
            SUPPORTED_ETH_CAPABILITIES, SUPPORTED_SNAP_CAPABILITIES,
        },
        snap::TrieNodes,
    },
    snap::{
        process_account_range_request, process_byte_codes_request, process_storage_ranges_request,
        process_trie_nodes_request,
    },
    tx_broadcaster::{TxBroadcaster, TxBroadcasterProtocol as _, send_tx_hashes},
    types::Node,
};
use ethrex_blockchain::{
    Blockchain,
    sampling::{is_provider_role, pick_random_extra_column},
};
use ethrex_common::H256;
#[cfg(feature = "l2")]
use ethrex_common::types::Transaction;
use ethrex_common::types::{P2PTransaction, Receipt};
use ethrex_crypto::NativeCrypto;
use ethrex_rlp::encode::RLPEncode;
use ethrex_storage::{Store, error::StoreError};
use ethrex_trie::TrieError;
use futures::{SinkExt as _, Stream, stream::SplitSink};
use rand::random;
use rustc_hash::FxHashMap;
use secp256k1::{PublicKey, SecretKey};
use spawned_concurrency::{
    actor,
    error::ActorError,
    protocol,
    tasks::{Actor, ActorRef, ActorStart as _, Context, Handler, send_interval, spawn_listener},
};
use spawned_rt::tasks::BroadcastStream;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{broadcast, oneshot},
    task::{self, Id},
};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{debug, error, trace, warn};

const PING_INTERVAL: Duration = Duration::from_secs(10);
const BLOCK_RANGE_UPDATE_INTERVAL: Duration = Duration::from_secs(60);
const INFLIGHT_TX_SWEEP_INTERVAL: Duration = Duration::from_secs(15);
const INFLIGHT_TX_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time a single outbound frame may take to flush to a peer's socket before we
/// consider the peer wedged and drop it. Without this bound, a slow/half-dead peer
/// (TCP send window full, never draining) blocks the connection actor's serial drain
/// indefinitely while its unbounded mailbox keeps growing — the timer/broadcast
/// producers below enqueue regardless of drain progress — leaking memory that is
/// never reclaimed (the actor cannot be stopped while a handler is wedged in `.await`).
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time the RLPx handshake may take before we abandon the connection. Without
/// this, an inbound peer that opens TCP and then stalls before/at the auth read
/// parks a connection actor + socket indefinitely (the handshake runs inside
/// `started()` with no timeout), so established sockets accumulate far beyond the
/// peer target.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// If a peer fails to answer this many consecutive pings, consider it dead and drop it.
/// Catches application-dead-but-TCP-alive peers that would otherwise never be removed.
const MAX_MISSED_PONGS: u8 = 3;
/// Capacity of the per-connection bounded outbound queue. The writer task drains this into
/// the socket; if a peer can't keep up the queue fills and the peer is dropped, so outbound
/// buffering per connection is bounded to this many messages instead of growing unbounded.
const OUTBOUND_QUEUE_CAP: usize = 1024;
/// How often to flush buffered transaction hash requests into a single
/// batched GetPooledTransactions message.
const TX_REQUEST_BATCH_INTERVAL: Duration = Duration::from_millis(50);
/// Fixed (tumbling) time window for incoming request rate limiting.
const SERVE_REQUEST_WINDOW: Duration = Duration::from_secs(60);
/// Maximum number of data-serving requests allowed per peer within the rate-limit window.
const MAX_SERVE_REQUESTS_PER_WINDOW: u64 = 500;
/// Number of transactions sent to a peer before checking for leeching behaviour.
const LEECH_TX_SENT_THRESHOLD: u64 = 10_000;

pub(crate) type PeerConnBroadcastSender = broadcast::Sender<(tokio::task::Id, Arc<Message>)>;

#[protocol]
pub trait PeerConnectionServerProtocol: Send + Sync {
    fn incoming_message(&self, message: Message) -> Result<(), ActorError>;
    fn outgoing_message(&self, message: Message) -> Result<(), ActorError>;
    fn outgoing_request(
        &self,
        message: Message,
        sender: Arc<oneshot::Sender<Message>>,
    ) -> Result<(), ActorError>;
    fn request_timeout(&self, id: u64) -> Result<(), ActorError>;
    fn send_ping(&self) -> Result<(), ActorError>;
    fn block_range_update(&self) -> Result<(), ActorError>;
    fn broadcast_message(&self, task_id: Id, msg: Arc<Message>) -> Result<(), ActorError>;
    fn sweep_inflight_txs(&self) -> Result<(), ActorError>;
    fn flush_pending_tx_requests(&self) -> Result<(), ActorError>;
    fn enqueue_tx_requests(
        &self,
        announcement: NewPooledTransactionHashes,
        hashes: Vec<H256>,
    ) -> Result<(), ActorError>;
}

#[cfg(feature = "l2")]
#[derive(Clone)]
pub struct L2Message {
    pub msg: L2Cast,
}

#[cfg(feature = "l2")]
impl spawned_concurrency::message::Message for L2Message {
    type Result = ();
}

#[derive(Clone, Debug)]
pub struct PeerConnection {
    handle: ActorRef<PeerConnectionServer>,
}

impl PeerConnection {
    pub fn spawn_as_receiver(
        context: P2PContext,
        peer_addr: SocketAddr,
        stream: TcpStream,
        admission_permit: tokio::sync::OwnedSemaphorePermit,
    ) -> PeerConnection {
        let state = ConnectionState::Receiver(Receiver {
            context,
            peer_addr,
            stream: Arc::new(stream),
        });
        let connection = PeerConnectionServer {
            state,
            _admission_permit: Some(admission_permit),
        };
        Self {
            handle: connection.start(),
        }
    }

    pub fn spawn_as_initiator(context: P2PContext, node: &Node) -> PeerConnection {
        let state = ConnectionState::Initiator(Initiator {
            context,
            node: node.clone(),
        });
        // Outbound dials are not admission-capped (we initiate them); inbound is the attack surface.
        let connection = PeerConnectionServer {
            state,
            _admission_permit: None,
        };
        Self {
            handle: connection.start(),
        }
    }

    pub async fn outgoing_message(&mut self, message: Message) -> Result<(), PeerConnectionError> {
        self.handle
            .outgoing_message(message)
            .map_err(|err| PeerConnectionError::InternalError(err.to_string()))
    }

    /// Queue tx hashes (with the originating announcement metadata) to be
    /// requested on the next flush tick. Used as a fallback when an in-flight
    /// request on another peer fails.
    pub fn enqueue_tx_requests(
        &self,
        announcement: NewPooledTransactionHashes,
        hashes: Vec<H256>,
    ) -> Result<(), PeerConnectionError> {
        self.handle
            .enqueue_tx_requests(announcement, hashes)
            .map_err(|err| PeerConnectionError::InternalError(err.to_string()))
    }

    pub async fn outgoing_request(
        &mut self,
        message: Message,
        timeout: Duration,
    ) -> Result<Message, PeerConnectionError> {
        let id = message
            .request_id()
            .expect("Cannot wait on request without id");
        let (oneshot_tx, oneshot_rx) = oneshot::channel::<Message>();

        self.handle
            .outgoing_request(message, Arc::new(oneshot_tx))
            .map_err(|err| PeerConnectionError::InternalError(err.to_string()))?;

        // Wait for the response or timeout. This blocks the calling task (and not the ConnectionServer task)
        match tokio::time::timeout(timeout, oneshot_rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(PeerConnectionError::RecvError(error.to_string())),
            Err(_timeout) => {
                // Notify timeout on request id
                self.handle
                    .request_timeout(id)
                    .map_err(|err| PeerConnectionError::InternalError(err.to_string()))?;
                // Return timeout error
                Err(PeerConnectionError::Timeout)
            }
        }
    }
}

#[derive(Debug)]
pub struct Initiator {
    pub(crate) context: P2PContext,
    pub(crate) node: Node,
}

#[derive(Debug)]
pub struct Receiver {
    pub(crate) context: P2PContext,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) stream: Arc<TcpStream>,
}

/// One announced transaction as flattened for an eth/72 `GetPooledTransactions`:
/// hash, type, announced size and the availability its announcer claimed.
type AnnouncedTx = (H256, u8, usize, Option<u128>);

/// EIP-8070 role this node took for the hashes in one `GetPooledTransactions`
/// request, deciding what happens once the bodies arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobFetchRole {
    /// Full blob payload is fetched alongside the body, so nothing follows.
    Provider,
    /// Body only; custody-aligned cells are requested once the body validates.
    Sampler,
}

#[derive(Debug)]
pub struct Established {
    pub(crate) signer: SecretKey,
    // Bounded outbound queue to the per-connection writer task (which owns the socket sink).
    // A bounded queue + dropping the peer on overflow keeps per-connection outbound buffering
    // bounded instead of letting the actor mailbox grow when a peer can't keep up. The receiving
    // part of the TcpStream is owned by the stream listen loop task. See `spawn_outbound_writer`.
    pub(crate) outbound_tx: tokio::sync::mpsc::Sender<Message>,
    /// Set by the writer task when it exits because a single send exceeded `OUTBOUND_SEND_TIMEOUT`
    /// (a wedged peer), so `send` can surface `OutboundSendTimeout` once the bounded queue closes.
    pub(crate) outbound_writer_timed_out: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) node: Node,
    // Whether the remote peer initiated this connection (we acted as Receiver).
    // `false` when we initiated it (we acted as Initiator).
    pub(crate) is_inbound: bool,
    pub(crate) storage: Store,
    pub(crate) blockchain: Arc<Blockchain>,
    pub(crate) capabilities: Vec<Capability>,
    pub(crate) negotiated_eth_capability: Option<Capability>,
    pub(crate) negotiated_snap_capability: Option<Capability>,
    pub(crate) last_block_range_update_block: u64,
    /// Maps request ID to (original announcement, actually requested hashes, request time).
    /// The announcement is kept for response validation; the hashes track in-flight state.
    pub(crate) requested_pooled_txs: HashMap<u64, (NewPooledTransactionHashes, Vec<H256>, Instant)>,
    /// eth/72 variant of requested_pooled_txs, also carrying the EIP-8070 role we
    /// took for the requested hashes.
    pub(crate) requested_pooled_txs_72: HashMap<
        u64,
        (
            NewPooledTransactionHashes72,
            Vec<H256>,
            BlobFetchRole,
            Instant,
        ),
    >,
    /// Buffered transaction requests waiting to be flushed as a single batch.
    /// Accumulated between flush ticks (TX_REQUEST_BATCH_INTERVAL).
    pub(crate) pending_tx_requests: Vec<(NewPooledTransactionHashes, Vec<H256>)>,
    /// eth/72 variant of pending_tx_requests.
    pub(crate) pending_tx_requests_72:
        Vec<(NewPooledTransactionHashes72, Vec<H256>, BlobFetchRole)>,
    /// EIP-8070: buffered cell requests (tx_hashes, cell_mask) waiting to be
    /// flushed as a single batched GetCells message.
    pub(crate) pending_cell_requests: Vec<(Vec<H256>, u128)>,
    /// EIP-8070: in-flight `GetCells` requests, keyed by request id, holding the
    /// hashes and cell mask we asked for plus the request time. devp2p requires a
    /// `Cells` response to answer an outstanding request, with a hash set and cell
    /// bitmap that are subsets of what was requested; anything else is a
    /// subprotocol violation. Swept on the same tick as the tx requests.
    pub(crate) requested_cells: HashMap<u64, (Vec<H256>, u128, Instant)>,
    /// EIP-8070: last custody generation this connection acted on. When the
    /// mempool's custody generation advances (Engine API FCU v4 changed the
    /// custody set), the sweep re-samples pending blob txs for the new columns.
    pub(crate) last_custody_generation: u64,
    pub(crate) client_version: String,
    //// Send end of the channel used to broadcast messages
    //// to other connected peers, is ok to have it here,
    //// since internally it's an Arc.
    //// The ID is to ignore the message sent from the same task.
    //// This is used both to send messages and to received broadcasted
    //// messages from other connections (sent from other peers).
    //// The receive end is instantiated after the handshake is completed
    //// under `handle_peer`.
    /// TODO: Improve this mechanism
    /// See https://github.com/lambdaclass/ethrex/issues/3388
    pub(crate) connection_broadcast_send: PeerConnBroadcastSender,
    pub(crate) peer_table: PeerTable,
    /// Reports this connection's lifecycle back to discovery, so a node we are
    /// talking to stops being offered as a dial candidate.
    pub(crate) discovery: DiscoveryHandle,
    #[cfg(feature = "l2")]
    pub(crate) l2_state: L2ConnState,
    pub(crate) tx_broadcaster: ActorRef<TxBroadcaster>,
    pub(crate) current_requests: HashMap<u64, (String, oneshot::Sender<Message>)>,
    // We store the disconnection reason to handle it in the teardown
    pub(crate) disconnect_reason: Option<DisconnectReason>,
    // Indicates if the peer has been validated (ie. the connection was established successfully)
    pub(crate) is_validated: bool,
    /// Whether this actor holds the peer table's slot for this node id. Only the
    /// actor that claimed it may release it: a duplicate connection that lost
    /// the race must leave the winner's registration alone on its way out.
    pub(crate) registered: bool,
    // Rate limiting: start of the current incoming-request window
    pub(crate) serve_request_window_start: Instant,
    // Rate limiting: number of data-serving requests received in the current window
    pub(crate) serve_requests_in_window: u64,
    // Leech detection: total transactions sent to this peer via GetPooledTransactions responses
    pub(crate) txs_sent_to_peer: u64,
    // Leech detection: whether we have received any transactions from this peer
    pub(crate) received_txs_from_peer: bool,
    // Liveness: consecutive pings sent without a matching pong. Reset to 0 on every Pong,
    // incremented on each Ping we send; at MAX_MISSED_PONGS the peer is considered dead
    // and dropped (catches application-dead-but-TCP-alive peers that otherwise linger).
    pub(crate) missed_pongs: u8,
}

impl Established {
    async fn teardown(&mut self) {
        // Clear any in-flight transaction hashes so other connections can re-request them,
        // then try to re-issue each pending request to an alternate announcer.
        // Order matters: clear first so the alternate's reserve_unknown_hashes sees the
        // hashes as free; otherwise the actor handler can race with clear_in_flight_txs
        // and silently no-op the retry while consuming an alternates slot.
        for (_, (_announced, requested_hashes, _)) in self.requested_pooled_txs.drain() {
            if let Err(e) = self
                .blockchain
                .mempool
                .clear_in_flight_txs(&requested_hashes)
            {
                warn!(error = %e, "Failed to clear in-flight transaction tracking during peer teardown");
            }
            retry_on_alternates(&self.blockchain, &self.peer_table, &requested_hashes).await;
        }
        for (_, (_announced, requested_hashes, _, _)) in self.requested_pooled_txs_72.drain() {
            if let Err(e) = self
                .blockchain
                .mempool
                .clear_in_flight_txs(&requested_hashes)
            {
                warn!(error = %e, "clear_in_flight_txs failed during teardown");
            }
            retry_on_alternates(&self.blockchain, &self.peer_table, &requested_hashes).await;
        }
        // Also clear hashes that were buffered but not yet sent.
        for (_announced, pending_hashes) in self.pending_tx_requests.drain(..) {
            if let Err(e) = self.blockchain.mempool.clear_in_flight_txs(&pending_hashes) {
                warn!(error = %e, "Failed to clear in-flight transaction tracking during peer teardown");
            }
            retry_on_alternates(&self.blockchain, &self.peer_table, &pending_hashes).await;
        }
        for (_announced, pending_hashes, _) in self.pending_tx_requests_72.drain(..) {
            if let Err(e) = self.blockchain.mempool.clear_in_flight_txs(&pending_hashes) {
                warn!(error = %e, "clear_in_flight_txs failed during teardown");
            }
            retry_on_alternates(&self.blockchain, &self.peer_table, &pending_hashes).await;
        }
        // EIP-8070: forget this peer's advertised cell availability so the map
        // does not grow unbounded across reconnects.
        if let Err(e) = self
            .blockchain
            .mempool
            .clear_peer_cell_availability(self.node.node_id())
        {
            warn!(error = %e, "clear_peer_cell_availability failed during teardown");
        }
        // The socket sink is owned by the per-connection writer task (`spawn_outbound_writer`),
        // which closes it when this `Established` is dropped (its `outbound_tx` is the only sender).
    }
}

#[derive(Debug)]
pub enum ConnectionState {
    HandshakeFailed,
    Initiator(Initiator),
    Receiver(Receiver),
    Established(Box<Established>),
}

#[derive(Debug)]
pub struct PeerConnectionServer {
    state: ConnectionState,
    /// Inbound-admission permit (Some for inbound connections, None for outbound dials we
    /// initiate). Held for the actor's lifetime and released when the actor is dropped, so the
    /// inbound connection count stays bounded. See `P2PContext::inbound_admission`.
    _admission_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

#[actor(protocol = PeerConnectionServerProtocol)]
impl PeerConnectionServer {
    #[started]
    async fn started(&mut self, ctx: &Context<Self>) {
        // Set a default eth version that we can update after we negotiate peer capabilities
        // This eth version will only be used to encode & decode the initial `Hello` messages.
        let eth_version = Arc::new(RwLock::new(EthCapVersion::default()));
        // Take ownership of the state, replacing with HandshakeFailed as placeholder
        let state = std::mem::replace(&mut self.state, ConnectionState::HandshakeFailed);
        // Bound the handshake: a peer that opens TCP and then stalls must not park this
        // actor + socket forever (otherwise established sockets accumulate above the peer
        // target). On timeout the handshake future is dropped, closing the socket.
        let handshake_result = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake::perform(state, eth_version.clone()),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                debug!("Handshake timed out on RLPx connection");
                self.state = ConnectionState::HandshakeFailed;
                ctx.stop();
                return;
            }
        };
        match handshake_result {
            Ok((mut established_state, stream)) => {
                trace!(peer=%established_state.node, "Starting RLPx connection");
                if let Err(reason) =
                    initialize_connection(ctx, &mut established_state, stream, eth_version).await
                {
                    match &reason {
                        PeerConnectionError::NoMatchingCapabilities
                        | PeerConnectionError::HandshakeError(_) => {
                            established_state.discovery.record_peer_event(
                                established_state.node.node_id(),
                                PeerEvent::Rejected,
                            );
                        }
                        _ => {}
                    }
                    connection_failed(
                        &mut established_state,
                        "Failed to initialize RLPx connection",
                        &reason,
                    )
                    .await;

                    METRICS.record_new_rlpx_conn_failure(reason).await;

                    self.state = ConnectionState::Established(Box::new(established_state));
                    ctx.stop();
                } else {
                    METRICS
                        .record_new_rlpx_conn_established(
                            &established_state
                                .node
                                .version
                                .clone()
                                .unwrap_or("Unknown".to_string()),
                        )
                        .await;
                    established_state.is_validated = true;
                    // New state
                    self.state = ConnectionState::Established(Box::new(established_state));
                }
            }
            Err(err) => {
                // Handshake failed, just log a debug message.
                // No connection was established so no need to perform any other action
                debug!("Failed Handshake on RLPx connection {err}");
                self.state = ConnectionState::HandshakeFailed;
                ctx.stop();
            }
        }
    }

    #[stopped]
    async fn stopped(&mut self, _ctx: &Context<Self>) {
        match std::mem::replace(&mut self.state, ConnectionState::HandshakeFailed) {
            ConnectionState::Established(mut established_state) => {
                trace!(peer=%established_state.node, "Closing connection with established peer");
                if established_state.is_validated {
                    // If its validated the peer was connected, so we record the disconnection.
                    let reason = established_state
                        .disconnect_reason
                        .unwrap_or(DisconnectReason::NetworkError);
                    METRICS
                        .record_new_rlpx_conn_disconnection(
                            &established_state
                                .node
                                .version
                                .clone()
                                .unwrap_or("Unknown".to_string()),
                            reason,
                        )
                        .await;
                }
                // Gated on `registered`: an actor that lost the claim never put
                // anything in these tables, and releasing on its way out would
                // evict the connection that won.
                if established_state.registered {
                    if let Err(e) = established_state
                        .peer_table
                        .remove_peer(established_state.node.node_id())
                    {
                        debug!("Failed to remove peer from table: {e}");
                    }
                    // Pairs with the `Connected` report in `initialize_connection`. This is
                    // the only teardown an established connection takes, and it still runs
                    // when a message handler panics, because the actor loop catches the
                    // unwind before falling through to `stopped()`.
                    //
                    // It does not cover a panic inside `started()` itself, which cancels the
                    // actor and returns without running this hook. `Connected` is reported
                    // from there, so that window can strand an id in discovery's connected
                    // set. `remove_peer` above is lost to the same window, leaving the peer
                    // table's own map equally stale, so the two stores at least agree.
                    established_state.discovery.record_peer_event(
                        established_state.node.node_id(),
                        PeerEvent::Disconnected,
                    );
                    // Free the peer's tx-broadcaster index (and clear its bit across known txs) so
                    // the broadcaster's per-peer index map / PeerMask widths stay bounded to live peers.
                    if let Err(e) = established_state
                        .tx_broadcaster
                        .remove_peer(established_state.node.node_id())
                    {
                        debug!("Failed to remove peer from tx broadcaster: {e}");
                    }
                }
                established_state.teardown().await;
            }
            _ => {
                // Nothing to do if the connection was not established
            }
        };
    }

    #[send_handler]
    async fn handle_incoming_message(
        &mut self,
        msg: peer_connection_server_protocol::IncomingMessage,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            trace!(
                peer=%established_state.node,
                message=%msg.message,
                "Received incoming message",
            );
            let result = handle_incoming_message(established_state, msg.message).await;
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    #[send_handler]
    async fn handle_outgoing_message(
        &mut self,
        msg: peer_connection_server_protocol::OutgoingMessage,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            trace!(
                peer=%established_state.node,
                message=%msg.message,
                "Received outgoing request",
            );
            let result = handle_outgoing_message(established_state, msg.message).await;
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    #[send_handler]
    async fn handle_outgoing_request(
        &mut self,
        msg: peer_connection_server_protocol::OutgoingRequest,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            trace!(
                peer=%established_state.node,
                message=%msg.message,
                "Received outgoing request",
            );
            let Some(sender) = Arc::<oneshot::Sender<Message>>::into_inner(msg.sender) else {
                debug!("Could not obtain sender channel: Arc has multiple references");
                return;
            };
            let result = handle_outgoing_request(established_state, msg.message, sender).await;
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    #[send_handler]
    async fn handle_request_timeout(
        &mut self,
        msg: peer_connection_server_protocol::RequestTimeout,
        _ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            // Discard the request from current requests
            if let Some((msg_type, _)) = established_state.current_requests.remove(&msg.id) {
                debug!(
                    peer=%established_state.node,
                    %msg_type,
                    id=%msg.id,
                    "Request timedout",
                );
            }
        } else {
            debug!("Connection not yet established");
        }
    }

    #[send_handler]
    async fn handle_send_ping(
        &mut self,
        _msg: peer_connection_server_protocol::SendPing,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            // Liveness: if the peer hasn't answered the last MAX_MISSED_PONGS pings, treat it
            // as dead and drop it instead of pinging a corpse (and keeping its actor) forever.
            if established_state.missed_pongs >= MAX_MISSED_PONGS {
                debug!(peer=%established_state.node, missed=MAX_MISSED_PONGS, "Peer missed max pongs, dropping");
                // Attribute the drop as `PingTimeout` so an unresponsive-peer drop is
                // distinguishable from a generic `NetworkError` in `ethrex_p2p_disconnections`.
                established_state.disconnect_reason = Some(DisconnectReason::PingTimeout);
                ctx.stop();
                return;
            }
            established_state.missed_pongs = established_state.missed_pongs.saturating_add(1);
            let result = send(established_state, Message::Ping(PingMessage {})).await;
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    #[send_handler]
    async fn handle_block_range_update(
        &mut self,
        _msg: peer_connection_server_protocol::BlockRangeUpdate,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            trace!(
                peer=%established_state.node,
                "Block Range Update"
            );
            let result = handle_block_range_update(established_state).await;
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    #[send_handler]
    async fn handle_sweep_inflight_txs(
        &mut self,
        _msg: peer_connection_server_protocol::SweepInflightTxs,
        _ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut state) = self.state {
            let now = Instant::now();
            let stale_ids: Vec<u64> = state
                .requested_pooled_txs
                .iter()
                .filter(|(_, (_, _, ts))| now.duration_since(*ts) > INFLIGHT_TX_TIMEOUT)
                .map(|(id, _)| *id)
                .collect();
            for id in stale_ids {
                if let Some((_announced, hashes, _)) = state.requested_pooled_txs.remove(&id) {
                    // Clear in-flight before retry so the alternate's reserve_unknown_hashes
                    // doesn't race against still-in-flight state and silently no-op.
                    if let Err(e) = state.blockchain.mempool.clear_in_flight_txs(&hashes) {
                        warn!(error = %e, "Failed to clear in-flight transaction tracking while sweeping stale requests");
                    }
                    retry_on_alternates(&state.blockchain, &state.peer_table, &hashes).await;
                }
            }
            // Sweep eth/72 in-flight requests.
            let stale_ids_72: Vec<u64> = state
                .requested_pooled_txs_72
                .iter()
                .filter(|(_, (_, _, _, ts))| now.duration_since(*ts) > INFLIGHT_TX_TIMEOUT)
                .map(|(id, _)| *id)
                .collect();
            for id in stale_ids_72 {
                if let Some((_announced, hashes, _, _)) = state.requested_pooled_txs_72.remove(&id)
                {
                    if let Err(e) = state.blockchain.mempool.clear_in_flight_txs(&hashes) {
                        warn!(error = %e, "clear_in_flight_txs failed while sweeping stale v72 requests");
                    }
                    retry_on_alternates(&state.blockchain, &state.peer_table, &hashes).await;
                }
            }
            // EIP-8070: drop in-flight GetCells entries the peer never answered, so
            // the map can't grow unbounded on a peer that silently ignores requests.
            // Unlike tx requests there is nothing to retry: the sampler re-requests
            // cells on the next announcement or custody change.
            state
                .requested_cells
                .retain(|_, (_, _, ts)| now.duration_since(*ts) <= INFLIGHT_TX_TIMEOUT);
            // EIP-8070: prune cell entries for txs that left the pool.
            if let Err(e) = state.blockchain.mempool.prune_cells() {
                warn!(error = %e, "prune_cells failed during sweep");
            }
            if let Err(e) = state
                .blockchain
                .mempool
                .prune_alternates(INFLIGHT_TX_TIMEOUT)
            {
                warn!(error = %e, "prune_alternates failed during sweep");
            }
            // EIP-8070: when the custody set changed (Engine API FCU v4) or eager
            // mode latched on, fetch the now-wanted columns this peer can serve for
            // pending blob txs. Inert unless sampling is enabled, and only ever
            // asked of an eth/72 peer.
            if state.blockchain.mempool.blob_sampling_enabled && supports_eth72(state) {
                let generation = state.blockchain.mempool.custody_generation();
                if generation != state.last_custody_generation {
                    state.last_custody_generation = generation;
                    // Unknown availability => assume the peer can serve any column
                    // (matches the sampler-fetch default).
                    let peer_available = state
                        .blockchain
                        .mempool
                        .peer_cell_mask(state.node.node_id())
                        .unwrap_or(None)
                        .unwrap_or(u128::MAX);
                    match state.blockchain.mempool.blob_txs_missing_cells() {
                        Ok(missing_list) => {
                            for (tx_hash, missing) in missing_list {
                                let fetch_mask = missing & peer_available;
                                if fetch_mask != 0 {
                                    state
                                        .pending_cell_requests
                                        .push((vec![tx_hash], fetch_mask));
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "blob_txs_missing_cells failed during sweep")
                        }
                    }
                }
            }
        }
    }

    #[send_handler]
    async fn handle_flush_pending_tx_requests(
        &mut self,
        _msg: peer_connection_server_protocol::FlushPendingTxRequests,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            let result = flush_pending_tx_requests(established_state).await;
            let result72 = flush_pending_tx_requests_72(established_state).await;
            let result_cells = flush_pending_cell_requests(established_state).await;
            Self::process_cast_error(&self.state, result, ctx);
            Self::process_cast_error(&self.state, result72, ctx);
            Self::process_cast_error(&self.state, result_cells, ctx);
        }
    }

    #[send_handler]
    async fn handle_enqueue_tx_requests(
        &mut self,
        msg: peer_connection_server_protocol::EnqueueTxRequests,
        _ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut state) = self.state {
            // Re-reserve in-flight against this peer. If any hashes are already
            // in-flight (race), drop them; we don't want duplicate requests.
            let to_request: Vec<H256> = match state.blockchain.mempool.reserve_unknown_hashes(
                &msg.announcement.transaction_hashes,
                &msg.announcement.transaction_types,
                &msg.announcement.transaction_sizes,
                state.node.node_id(),
            ) {
                Ok(unknown) => unknown,
                Err(_) => return,
            };
            if to_request.is_empty() {
                return;
            }
            let trimmed = msg.announcement.filter_to(&to_request);
            state.pending_tx_requests.push((trimmed, to_request));
        }
    }

    #[send_handler]
    async fn handle_broadcast_message(
        &mut self,
        msg: peer_connection_server_protocol::BroadcastMessage,
        ctx: &Context<Self>,
    ) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            trace!(
                peer=%established_state.node,
                message=%msg.msg,
                "Received broadcasted message",
            );
            let result = handle_broadcast(established_state, (msg.task_id, msg.msg)).await;
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    #[cfg(feature = "l2")]
    #[send_handler]
    async fn handle_l2_message(&mut self, msg: L2Message, ctx: &Context<Self>) {
        if let ConnectionState::Established(ref mut established_state) = self.state {
            let peer_supports_l2 = established_state.l2_state.connection_state().is_ok();
            let result = if peer_supports_l2 {
                trace!(
                    peer=%established_state.node,
                    message=?msg.msg,
                    "Handling cast for L2 msg"
                );
                match msg.msg {
                    L2Cast::BatchBroadcast => {
                        let res = l2_connection::send_sealed_batch(established_state).await;
                        res.and(l2_connection::process_batches_on_queue(established_state).await)
                    }
                    L2Cast::BlockBroadcast => {
                        let res = l2_connection::send_new_block(established_state).await;
                        res.and(l2_connection::process_blocks_on_queue(established_state).await)
                    }
                }
            } else {
                Err(PeerConnectionError::MessageNotHandled(
                    "Unknown message or capability not handled".to_string(),
                ))
            };
            Self::process_cast_error(&self.state, result, ctx);
        } else {
            debug!("Connection not yet established");
        }
    }

    fn process_cast_error(
        state: &ConnectionState,
        result: Result<(), PeerConnectionError>,
        ctx: &Context<Self>,
    ) {
        if let Err(e) = result
            && let ConnectionState::Established(established_state) = state
        {
            match e {
                PeerConnectionError::Disconnected
                | PeerConnectionError::DisconnectReceived(_)
                | PeerConnectionError::DisconnectSent(_)
                | PeerConnectionError::HandshakeError(_)
                | PeerConnectionError::NoMatchingCapabilities
                | PeerConnectionError::InvalidPeerId
                | PeerConnectionError::InvalidMessageLength
                | PeerConnectionError::StateError(_)
                | PeerConnectionError::InvalidRecoveryId
                | PeerConnectionError::OutboundSendTimeout
                | PeerConnectionError::OutboundQueueFull => {
                    trace!(peer=%established_state.node, error=e.to_string(), "Peer connection error");
                    ctx.stop();
                }
                PeerConnectionError::IoError(ref io_e)
                    if io_e.kind() == std::io::ErrorKind::BrokenPipe =>
                {
                    // TODO: we need to check if this message is ocurring commonly due to a problem
                    // with our concurrency model
                    debug!(peer=%established_state.node, "Broken pipe with peer, disconnected");
                    ctx.stop();
                }
                PeerConnectionError::StoreError(StoreError::Trie(TrieError::InconsistentTree(
                    _,
                ))) => {
                    if established_state.blockchain.is_synced() {
                        // If we're responding with inconsistent trie while synced, our trie may be broken
                        // If this error is non sporadic we should investigate
                        error!(
                            peer=%established_state.node,
                            error=%e,
                            "Inconsistent trie while serving peer request; local state may be corrupted",
                        );
                    } else {
                        // If we're not synced, we expect to have inconsistent trie errors
                        trace!(
                            peer=%established_state.node,
                            error=%e,
                            "Error handling cast message",
                        );
                    }
                }
                _ => {
                    // We should check why we're failling to handle the cast message
                    debug!(
                        peer=%established_state.node,
                        capabilities=?established_state.capabilities,
                        error=%e,
                        "Error handling cast message",
                    );
                }
            }
        }
    }
}

async fn initialize_connection<S>(
    ctx: &Context<PeerConnectionServer>,
    state: &mut Established,
    mut stream: S,
    eth_version: Arc<RwLock<EthCapVersion>>,
) -> Result<(), PeerConnectionError>
where
    S: Unpin + Send + Stream<Item = Result<Message, PeerConnectionError>> + 'static,
{
    if state.peer_table.target_peers_reached().await? {
        debug!(peer=%state.node, "Reached target peer connections, discarding.");
        return Err(PeerConnectionError::TooManyPeers);
    }
    exchange_hello_messages(state, &mut stream).await?;

    // Update eth capability version to the negotiated version for further message decoding
    let version = match &state.negotiated_eth_capability {
        Some(cap) if cap == &Capability::eth(68) => EthCapVersion::V68,
        Some(cap) if cap == &Capability::eth(69) => EthCapVersion::V69,
        Some(cap) if cap == &Capability::eth(70) => EthCapVersion::V70,
        Some(cap) if cap == &Capability::eth(71) => EthCapVersion::V71,
        Some(cap) if cap == &Capability::eth(72) => EthCapVersion::V72,
        _ => EthCapVersion::default(),
    };
    *eth_version
        .write()
        .map_err(|err| PeerConnectionError::InternalError(err.to_string()))? = version;

    init_capabilities(state, &mut stream).await?;

    let mut connection = PeerConnection {
        handle: ctx.actor_ref(),
    };

    // Claim the slot before telling anyone we have this peer. Losing means
    // another actor already holds a connection to the same node id, so we hang
    // up with the reason devp2p expects and touch neither table.
    let claimed = state
        .peer_table
        .new_connected_peer(
            state.node.clone(),
            connection.clone(),
            state.capabilities.clone(),
            state.negotiated_eth_capability.clone(),
            state.is_inbound,
        )
        .await?;
    if !claimed {
        return Err(PeerConnectionError::DisconnectSent(
            DisconnectReason::AlreadyConnected,
        ));
    }
    state.registered = true;
    state
        .discovery
        .record_peer_event(state.node.node_id(), PeerEvent::Connected);

    trace!(peer=%state.node, "Peer connection initialized.");

    // Send transactions transaction hashes from mempool at connection start
    send_all_pooled_tx_hashes(state, &mut connection).await?;

    // Periodic Pings repeated events.
    send_interval(
        PING_INTERVAL,
        ctx.clone(),
        peer_connection_server_protocol::SendPing,
    );

    // Periodic block range update.
    send_interval(
        BLOCK_RANGE_UPDATE_INTERVAL,
        ctx.clone(),
        peer_connection_server_protocol::BlockRangeUpdate,
    );

    // Periodic sweep of stale in-flight transaction requests.
    send_interval(
        INFLIGHT_TX_SWEEP_INTERVAL,
        ctx.clone(),
        peer_connection_server_protocol::SweepInflightTxs,
    );

    // Periodic flush of buffered transaction requests.
    send_interval(
        TX_REQUEST_BATCH_INTERVAL,
        ctx.clone(),
        peer_connection_server_protocol::FlushPendingTxRequests,
    );

    #[cfg(feature = "l2")]
    // Periodic L2 messages events.
    if state.l2_state.connection_state().is_ok() {
        send_interval(
            PERIODIC_BLOCK_BROADCAST_INTERVAL,
            ctx.clone(),
            L2Message {
                msg: L2Cast::BlockBroadcast,
            },
        );
        send_interval(
            PERIODIC_BATCH_BROADCAST_INTERVAL,
            ctx.clone(),
            L2Message {
                msg: L2Cast::BatchBroadcast,
            },
        );
    }

    spawn_listener(
        ctx.clone(),
        stream.filter_map(|result| match result {
            Ok(msg) => Some(peer_connection_server_protocol::IncomingMessage { message: msg }),
            Err(e) => {
                debug!(error=?e, "Error receiving RLPx message");
                // Skipping invalid data
                None
            }
        }),
    );

    if state.negotiated_eth_capability.is_some() {
        let stream: BroadcastStream<(Id, Arc<Message>)> =
            BroadcastStream::new(state.connection_broadcast_send.subscribe());
        let message_stream = stream.filter_map(|result| {
            result.ok().map(
                |(id, msg)| peer_connection_server_protocol::BroadcastMessage { task_id: id, msg },
            )
        });
        spawn_listener(ctx.clone(), message_stream);
    }

    Ok(())
}

async fn send_all_pooled_tx_hashes(
    state: &mut Established,
    connection: &mut PeerConnection,
) -> Result<(), PeerConnectionError> {
    // --mempool.private: locally-submitted private txs MUST NOT be
    // disclosed via the new-peer pooled-hashes dump.
    let txs = state.blockchain.mempool.get_txs_for_new_peer_dump()?;
    if !txs.is_empty() {
        state
            .tx_broadcaster
            .add_txs(
                txs.iter().map(|tx| tx.hash(&NativeCrypto)).collect(),
                state.node.node_id(),
            )
            .map_err(|e| PeerConnectionError::BroadcastError(e.to_string()))?;
        send_tx_hashes(
            txs,
            state.negotiated_eth_capability.clone(),
            connection,
            state.node.node_id(),
            &state.blockchain,
        )
        .await
        .map_err(|e| PeerConnectionError::SendMessage(e.to_string()))?;
    }
    Ok(())
}

async fn send_block_range_update(state: &mut Established) -> Result<(), PeerConnectionError> {
    // BlockRangeUpdate was introduced in eth/69
    if state
        .negotiated_eth_capability
        .as_ref()
        .is_some_and(|eth| eth.version >= 69)
    {
        trace!(peer=%state.node, "Sending BlockRangeUpdate");
        let update = BlockRangeUpdate::new(&state.storage).await?;
        let latest_block = update.latest_block;
        send(state, Message::BlockRangeUpdate(update)).await?;
        state.last_block_range_update_block = latest_block - (latest_block % 32);
    }
    Ok(())
}

fn should_send_block_range_update(state: &Established) -> Result<bool, PeerConnectionError> {
    let latest_block = state.storage.get_latest_block_number()?;
    if latest_block < state.last_block_range_update_block
        || latest_block - state.last_block_range_update_block >= 32
    {
        return Ok(true);
    }
    Ok(false)
}

async fn init_capabilities<S>(
    state: &mut Established,
    stream: &mut S,
) -> Result<(), PeerConnectionError>
where
    S: Unpin + Stream<Item = Result<Message, PeerConnectionError>>,
{
    // Sending eth Status if peer supports it
    if let Some(eth) = state.negotiated_eth_capability.clone() {
        let status = match eth.version {
            68 => Message::Status68(StatusMessage68::new(&state.storage)?),
            69 => Message::Status69(StatusMessage69::new(&state.storage).await?),
            70 => Message::Status70(StatusMessage70::new(&state.storage).await?),
            71 => Message::Status71(StatusMessage71::new(&state.storage).await?),
            72 => Message::Status72(StatusMessage72::new(&state.storage).await?),
            ver => {
                return Err(PeerConnectionError::HandshakeError(format!(
                    "Invalid eth version {ver}"
                )));
            }
        };
        trace!(peer=%state.node, "Sending status");
        send(state, status).await?;
        // The next immediate message in the ETH protocol is the
        // status, reference here:
        // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#status-0x00
        let msg = match receive(stream).await {
            Some(msg) => msg?,
            None => return Err(PeerConnectionError::Disconnected),
        };
        match msg {
            Message::Status68(msg_data) => {
                trace!(peer=%state.node, "Received Status(68)");
                backend::validate_status(msg_data, &state.storage, &eth)?
            }
            Message::Status69(msg_data) => {
                trace!(peer=%state.node, "Received Status(69)");
                backend::validate_status(msg_data, &state.storage, &eth)?
            }
            Message::Status70(msg_data) => {
                trace!(peer=%state.node, "Received Status(70)");
                backend::validate_status(msg_data, &state.storage, &eth)?
            }
            Message::Status71(msg_data) => {
                trace!(peer=%state.node, "Received Status(71)");
                backend::validate_status(msg_data, &state.storage, &eth)?
            }
            Message::Status72(msg_data) => {
                trace!(peer=%state.node, "Received Status(72)");
                backend::validate_status(msg_data, &state.storage, &eth)?
            }
            Message::Disconnect(disconnect) => {
                return Err(PeerConnectionError::HandshakeError(format!(
                    "Peer disconnected due to: {}",
                    disconnect.reason()
                )));
            }
            _ => {
                return Err(PeerConnectionError::HandshakeError(
                    "Expected a Status message".to_string(),
                ));
            }
        }
    }
    Ok(())
}

async fn send_disconnect_message(state: &mut Established, reason: Option<DisconnectReason>) {
    send(state, Message::Disconnect(DisconnectMessage { reason }))
        .await
        .unwrap_or_else(|_| {
            debug!(
                peer=%state.node,
                ?reason,
                "Could not send Disconnect message",
            );
        });
}

async fn connection_failed(state: &mut Established, error_text: &str, error: &PeerConnectionError) {
    debug!(
        peer=%state.node,
        %error_text,
        %error,
        "connection failure"
    );

    // Send disconnect message only if error is different than RLPxError::DisconnectRequested
    // because if it is a DisconnectRequested error it means that the peer requested the disconnection, not us.
    if !matches!(error, PeerConnectionError::DisconnectReceived(_)) {
        send_disconnect_message(state, match_disconnect_reason(error)).await;
    }

    // Discard peer from kademlia table in some cases
    match error {
        // already connected, don't discard it
        PeerConnectionError::DisconnectReceived(DisconnectReason::AlreadyConnected)
        | PeerConnectionError::DisconnectSent(DisconnectReason::AlreadyConnected) => {
            debug!(
                peer=%state.node,
                %error_text,
                %error,
                "Peer already connected, don't replace it"
            );
        }
        _ => {
            debug!(
                peer=%state.node,
                %error_text,
                %error,
                remote_public_key=%state.node.public_key,
                "discarding peer",
            );
        }
    }
}

fn match_disconnect_reason(error: &PeerConnectionError) -> Option<DisconnectReason> {
    match error {
        PeerConnectionError::DisconnectSent(reason) => Some(*reason),
        PeerConnectionError::DisconnectReceived(reason) => Some(*reason),
        PeerConnectionError::RLPDecodeError(_) => Some(DisconnectReason::NetworkError),
        PeerConnectionError::TooManyPeers => Some(DisconnectReason::TooManyPeers),
        // TODO build a proper matching between error types and disconnection reasons
        _ => None,
    }
}

async fn exchange_hello_messages<S>(
    state: &mut Established,
    stream: &mut S,
) -> Result<(), PeerConnectionError>
where
    S: Unpin + Stream<Item = Result<Message, PeerConnectionError>>,
{
    // eth/72 (EIP-8070) is only safe to negotiate when blob sampling is enabled:
    // it always elides blob payloads in PooledTransactions, and a node that does
    // not run the sampler/provider cell-fetch loop would receive blob txs it can
    // never reconstruct. With sampling off we cap at eth/71 so default nodes keep
    // full-blob propagation unchanged. The EIP's Backwards Compatibility section
    // explicitly supports this gradual, version-gated rollout.
    let offer_eth72 = state.blockchain.mempool.blob_sampling_enabled;
    // This allow is because in l2 we mut the capabilities
    // to include the l2 cap
    #[allow(unused_mut)]
    let mut supported_capabilities: Vec<Capability> = SUPPORTED_ETH_CAPABILITIES
        .iter()
        .filter(|cap| offer_eth72 || cap.version < 72)
        .chain(SUPPORTED_SNAP_CAPABILITIES.iter())
        .cloned()
        .collect();
    #[cfg(feature = "l2")]
    if state.l2_state.is_supported() {
        supported_capabilities.push(crate::rlpx::l2::SUPPORTED_BASED_CAPABILITIES[0].clone());
    }
    let hello_msg = Message::Hello(p2p::HelloMessage::new(
        supported_capabilities,
        PublicKey::from_secret_key(secp256k1::SECP256K1, &state.signer),
        state.client_version.clone(),
    ));

    send(state, hello_msg).await?;

    // Receive Hello message
    let msg = match receive(stream).await {
        Some(msg) => msg?,
        None => return Err(PeerConnectionError::Disconnected),
    };

    match msg {
        Message::Hello(hello_message) => {
            let mut negotiated_eth_version = 0;
            let mut negotiated_snap_version = 0;

            trace!(
                peer=%state.node,
                capabilities=?hello_message.capabilities,
                "Hello message capabilities",
            );

            // Check if we have any capability in common and store the highest version
            for cap in &hello_message.capabilities {
                match cap.protocol() {
                    "eth" => {
                        // Don't negotiate a version we didn't advertise: eth/72 is
                        // only offered when blob sampling is enabled (see above).
                        if SUPPORTED_ETH_CAPABILITIES.contains(cap)
                            && (offer_eth72 || cap.version < 72)
                            && cap.version > negotiated_eth_version
                        {
                            negotiated_eth_version = cap.version;
                        }
                    }
                    "snap" => {
                        if SUPPORTED_SNAP_CAPABILITIES.contains(cap)
                            && cap.version > negotiated_snap_version
                        {
                            negotiated_snap_version = cap.version;
                        }
                    }
                    #[cfg(feature = "l2")]
                    "based" if state.l2_state.is_supported() => {
                        state.l2_state.set_established()?;
                    }
                    _ => {}
                }
            }

            state.capabilities = hello_message.capabilities;

            if negotiated_eth_version == 0 {
                return Err(PeerConnectionError::NoMatchingCapabilities);
            }
            debug!("Negotiated eth version: eth/{}", negotiated_eth_version);
            state.negotiated_eth_capability = Some(Capability::eth(negotiated_eth_version));

            if negotiated_snap_version != 0 {
                debug!("Negotiated snap version: snap/{}", negotiated_snap_version);
                state.negotiated_snap_capability = Some(Capability::snap(negotiated_snap_version));
            }

            state.node.version = Some(hello_message.client_id);

            Ok(())
        }
        Message::Disconnect(disconnect) => {
            Err(PeerConnectionError::DisconnectReceived(disconnect.reason()))
        }
        _ => {
            // Fail if it is not a hello message
            Err(PeerConnectionError::BadRequest(
                "Expected Hello message".to_string(),
            ))
        }
    }
}

pub(crate) async fn send(
    state: &mut Established,
    message: Message,
) -> Result<(), PeerConnectionError> {
    #[cfg(feature = "metrics")]
    {
        use ethrex_metrics::p2p::METRICS_P2P;
        METRICS_P2P.inc_outgoing_message(message.metric_label());
    }
    // Hand off to the per-connection writer task via a BOUNDED queue (non-blocking). This
    // decouples the actor's serial drain from the network write, so a slow/wedged peer can
    // never back up the (unbounded) actor mailbox. If the bounded queue is full the peer
    // can't keep up: surface OutboundQueueFull so `process_cast_error` drops it.
    match state.outbound_tx.try_send(message) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            // The peer can't drain our outbound fast enough. Attribute the drop as `UselessPeer`
            // so it is distinguishable from a generic `NetworkError` in `ethrex_p2p_disconnections`
            // (a spike here flags slow peers or our own over-sending, rather than hiding it).
            state
                .disconnect_reason
                .get_or_insert(DisconnectReason::UselessPeer);
            Err(PeerConnectionError::OutboundQueueFull)
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // The writer task is gone. If it exited because a single send exceeded
            // `OUTBOUND_SEND_TIMEOUT`, the peer was wedged: surface `OutboundSendTimeout` and
            // attribute it likewise; otherwise the socket simply closed (`Disconnected`).
            if state
                .outbound_writer_timed_out
                .load(std::sync::atomic::Ordering::Acquire)
            {
                state
                    .disconnect_reason
                    .get_or_insert(DisconnectReason::UselessPeer);
                Err(PeerConnectionError::OutboundSendTimeout)
            } else {
                Err(PeerConnectionError::Disconnected)
            }
        }
    }
}

/// Spawns the per-connection writer task that owns the `sink` and drains a bounded outbound
/// queue into it. Keeping the network write off the actor thread means the actor's mailbox is
/// never gated on a slow peer; the only outbound buffer is this bounded channel (capacity
/// `OUTBOUND_QUEUE_CAP`). The task exits — closing the socket — when the connection is dropped
/// (all senders gone), when a send errors, or when a single send exceeds `OUTBOUND_SEND_TIMEOUT`
/// (a wedged peer). Once it exits, further `send()`s observe a closed queue and the peer is dropped.
pub(crate) fn spawn_outbound_writer(
    mut sink: SplitSink<Framed<TcpStream, RLPxCodec>, Message>,
) -> (
    tokio::sync::mpsc::Sender<Message>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(OUTBOUND_QUEUE_CAP);
    // Set when the writer exits because a single send exceeded `OUTBOUND_SEND_TIMEOUT` (a wedged
    // peer), so `send` can surface `OutboundSendTimeout` instead of a generic `Disconnected` once
    // the bounded queue closes.
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_timed_out = timed_out.clone();
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            match tokio::time::timeout(OUTBOUND_SEND_TIMEOUT, sink.send(message)).await {
                Ok(Ok(())) => {}
                // Send error: the socket is gone; let the closed queue surface as `Disconnected`.
                Ok(Err(_)) => break,
                // The send itself timed out: the peer is wedged. Flag it so the drop is attributed.
                Err(_) => {
                    writer_timed_out.store(true, std::sync::atomic::Ordering::Release);
                    break;
                }
            }
        }
        let _ = sink.close().await;
    });
    (tx, timed_out)
}

/// Reads from the frame until a frame is available.
///
/// Returns `None` when the stream buffer is 0. This could indicate that the client has disconnected,
/// but we cannot safely assume an EOF, as per the Tokio documentation.
///
/// If the handshake has not been established, it is reasonable to terminate the connection.
///
/// For an established connection, [`check_periodic_task`] will detect actual disconnections
/// while sending pings and you should not assume a disconnection.
///
/// See [`Framed::new`] for more details.
async fn receive<S>(stream: &mut S) -> Option<Result<Message, PeerConnectionError>>
where
    S: Unpin + Stream<Item = Result<Message, PeerConnectionError>>,
{
    stream.next().await
}

/// Returns true if the peer is within its rate limit for data-serving requests, false if exceeded.
/// Resets the window counter when the window duration has elapsed.
fn check_serve_request_rate(state: &mut Established) -> bool {
    let now = Instant::now();
    if now.duration_since(state.serve_request_window_start) >= SERVE_REQUEST_WINDOW {
        state.serve_request_window_start = now;
        state.serve_requests_in_window = 0;
    }
    state.serve_requests_in_window += 1;
    state.serve_requests_in_window <= MAX_SERVE_REQUESTS_PER_WINDOW
}

async fn handle_incoming_message(
    state: &mut Established,
    message: Message,
) -> Result<(), PeerConnectionError> {
    #[cfg(feature = "metrics")]
    {
        use ethrex_metrics::p2p::METRICS_P2P;
        METRICS_P2P.inc_incoming_message(message.metric_label());
    }

    // Rate-limit incoming data-serving requests to prevent resource exhaustion.
    let is_data_request = matches!(
        message,
        Message::GetBlockHeaders(_)
            | Message::GetBlockBodies(_)
            | Message::GetReceipts68(_)
            | Message::GetReceipts69(_)
            | Message::GetReceipts70(_)
            | Message::GetPooledTransactions(_)
            | Message::GetAccountRange(_)
            | Message::GetStorageRanges(_)
            | Message::GetByteCodes(_)
            | Message::GetTrieNodes(_)
            | Message::GetCells(_)
    );
    if is_data_request && !check_serve_request_rate(state) {
        debug!(
            peer = %state.node,
            window_requests = state.serve_requests_in_window,
            "Disconnecting peer: exceeded incoming request rate limit",
        );
        send_disconnect_message(state, Some(DisconnectReason::UselessPeer)).await;
        return Err(PeerConnectionError::DisconnectSent(
            DisconnectReason::UselessPeer,
        ));
    }

    let peer_supports_eth = state.negotiated_eth_capability.is_some();
    #[cfg(feature = "l2")]
    let peer_supports_l2 = state.l2_state.connection_state().is_ok();
    match message {
        Message::Disconnect(msg_data) => {
            let reason = msg_data.reason();
            trace!(
                peer=%state.node,
                ?reason,
                "Received Disconnect"
            );
            state.disconnect_reason = Some(reason);

            // TODO handle the disconnection request

            return Err(PeerConnectionError::DisconnectReceived(reason));
        }
        Message::Ping(_) => {
            trace!(peer=%state.node, "Sending pong message");
            send(state, Message::Pong(PongMessage {})).await?;
        }
        Message::Pong(_) => {
            // Liveness: the peer answered our ping; reset the missed-pong counter.
            state.missed_pongs = 0;
        }
        Message::Status68(msg_data) => {
            if let Some(eth) = &state.negotiated_eth_capability {
                backend::validate_status(msg_data, &state.storage, eth)?
            };
        }
        Message::Status69(msg_data) => {
            if let Some(eth) = &state.negotiated_eth_capability {
                backend::validate_status(msg_data, &state.storage, eth)?
            };
        }
        Message::Status70(msg_data) => {
            if let Some(eth) = &state.negotiated_eth_capability {
                backend::validate_status(msg_data, &state.storage, eth)?
            };
        }
        Message::Status71(msg_data) => {
            if let Some(eth) = &state.negotiated_eth_capability {
                backend::validate_status(msg_data, &state.storage, eth)?
            };
        }
        Message::Status72(msg_data) => {
            if let Some(eth) = &state.negotiated_eth_capability {
                backend::validate_status(msg_data, &state.storage, eth)?
            };
        }
        Message::GetAccountRange(req) => {
            let response = process_account_range_request(req, state.storage.clone()).await?;
            send(state, Message::AccountRange(response)).await?
        }
        Message::Transactions(txs) if peer_supports_eth => {
            // https://github.com/ethereum/devp2p/blob/master/caps/eth.md#transactions-0x02
            if !txs.transactions.is_empty() {
                state.received_txs_from_peer = true;
            }
            if state.blockchain.is_synced() {
                let tx_hashes: Vec<_> = txs
                    .transactions
                    .iter()
                    .map(|tx| tx.hash(&NativeCrypto))
                    .collect();

                // Offload pool insertion to a background task so we don't block
                // the ConnectionServer (validation + signature recovery are expensive).
                let blockchain = state.blockchain.clone();
                let peer = state.node.to_string();
                #[cfg(feature = "l2")]
                let is_l2_mode = state.l2_state.is_supported();
                tokio::spawn(async move {
                    for tx in txs.transactions {
                        #[cfg(feature = "l2")]
                        if (is_l2_mode && matches!(tx, Transaction::EIP4844Transaction(_)))
                            || tx.is_privileged()
                        {
                            let tx_type = tx.tx_type();
                            debug!(peer=%peer, "Rejecting transaction in L2 mode - {tx_type} transactions are not broadcasted in L2");
                            continue;
                        }

                        if let Err(e) = blockchain.add_transaction_to_pool(tx).await {
                            debug!(
                                peer=%peer,
                                error=%e,
                                "Error adding transaction"
                            );
                        }
                    }
                });

                // Notify the broadcaster immediately — it only tracks hashes
                // to avoid re-broadcasting to the sender. The actual broadcast
                // happens on a periodic timer that queries the mempool directly.
                state
                    .tx_broadcaster
                    .add_txs(tx_hashes, state.node.node_id())
                    .map_err(|e| PeerConnectionError::BroadcastError(e.to_string()))?;
            }
        }
        Message::GetBlockHeaders(msg_data) if peer_supports_eth => {
            let response = BlockHeaders {
                id: msg_data.id,
                block_headers: msg_data.fetch_headers(&state.storage).await,
            };
            send(state, Message::BlockHeaders(response)).await?;
        }
        Message::GetBlockBodies(msg_data) if peer_supports_eth => {
            let response = BlockBodies {
                id: msg_data.id,
                block_bodies: msg_data.fetch_blocks(&state.storage).await,
            };
            send(state, Message::BlockBodies(response)).await?;
        }
        Message::GetBlockAccessLists(GetBlockAccessLists { id, block_hashes })
            if peer_supports_eth =>
        {
            use crate::rlpx::eth::block_access_lists::BLOCK_ACCESS_LIST_LIMIT;
            let mut block_access_lists =
                Vec::with_capacity(block_hashes.len().min(BLOCK_ACCESS_LIST_LIMIT));
            for hash in &block_hashes {
                // EIP-8159: only serve a BAL that matches the block header's
                // commitment. A stored BAL that doesn't hash to the header's
                // `block_access_list_hash` (e.g. a stale/empty entry from a prior
                // regeneration) must be reported as unavailable (`0x80`) rather
                // than served as a wrong BAL, which receiving peers would reject.
                let bal = match state.storage.get_block_access_list(*hash) {
                    Ok(Some(bal)) => {
                        let commitment = match state.storage.get_block_header_by_hash(*hash) {
                            Ok(Some(header)) => header.block_access_list_hash,
                            Ok(None) => None,
                            Err(err) => {
                                // Don't serve an unverified BAL: degrade to 0x80
                                // (unavailable), but log so an operator can tell a
                                // committed BAL was refused due to a DB error.
                                warn!(
                                    "Failed to read header for BAL commitment check (hash {hash:#x}): {err}; reporting BAL unavailable"
                                );
                                None
                            }
                        };
                        bal.matches_commitment(commitment, &NativeCrypto)
                            .then_some(bal)
                    }
                    Ok(None) => None,
                    Err(err) => {
                        error!("Error accessing DB while building BAL response for peer: {err}");
                        None
                    }
                };
                block_access_lists.push(bal);
                if block_access_lists.len() >= BLOCK_ACCESS_LIST_LIMIT {
                    break;
                }
            }
            let response = BlockAccessLists::new(id, block_access_lists);
            send(state, Message::BlockAccessLists(response)).await?;
        }
        Message::GetReceipts68(GetReceipts68 { id, block_hashes }) if peer_supports_eth => {
            let mut receipts = Vec::new();
            for hash in block_hashes.iter() {
                receipts.push(state.storage.get_receipts_for_block(hash).await?);
            }
            send(state, Message::Receipts68(Receipts68::new(id, receipts))).await?;
        }
        Message::GetReceipts69(GetReceipts68 { id, block_hashes }) if peer_supports_eth => {
            let mut receipts = Vec::new();
            for hash in block_hashes.iter() {
                receipts.push(state.storage.get_receipts_for_block(hash).await?);
            }
            send(state, Message::Receipts69(Receipts69::new(id, receipts))).await?;
        }
        // EIP-7975: eth/70 partial receipt requests
        Message::GetReceipts70(GetReceipts70 {
            id,
            first_block_receipt_index,
            block_hashes,
        }) if peer_supports_eth => {
            let block_hashes = &block_hashes[..block_hashes.len().min(256)];
            let mut all_receipts: Vec<Vec<Receipt>> = Vec::new();
            let mut total_size: usize = 0;
            let mut last_block_incomplete = false;

            for (i, hash) in block_hashes.iter().enumerate() {
                let start_index = if i == 0 { first_block_receipt_index } else { 0 };
                let block_receipts = state
                    .storage
                    .get_receipts_for_block_from_index(hash, start_index, None)
                    .await?;

                let mut block_receipt_list = Vec::new();
                let mut hit_limit = false;
                for receipt in block_receipts {
                    let receipt_size = receipt.length();
                    if total_size + receipt_size > SOFT_RESPONSE_LIMIT
                        && (!block_receipt_list.is_empty() || !all_receipts.is_empty())
                    {
                        hit_limit = true;
                        // Only mark incomplete when the current block actually
                        // has a partial receipt list. When the limit is hit
                        // before any receipt from this block fits, the previous
                        // block is complete — setting the flag would cause the
                        // peer to re-request an already-complete block.
                        if !block_receipt_list.is_empty() {
                            last_block_incomplete = true;
                        }
                        break;
                    }
                    total_size += receipt_size;
                    block_receipt_list.push(receipt);
                }

                // Don't push an empty list when the limit was hit before any
                // receipt from this block could be included — an empty trailing
                // list would mislead the peer into thinking the block has no
                // transactions.
                if !block_receipt_list.is_empty() || !hit_limit {
                    all_receipts.push(block_receipt_list);
                }

                if hit_limit {
                    break;
                }
            }

            let response =
                Message::Receipts70(Receipts70::new(id, last_block_incomplete, all_receipts));
            send(state, response).await?;
        }
        Message::BlockRangeUpdate(update) => {
            trace!(
                peer=%state.node,
                range_from=update.earliest_block,
                range_to=update.latest_block,
                "Block range update",
            );
            // We will only validate the incoming update, we may decide to store and use this information in the future
            if let Err(err) = update.validate() {
                debug!(
                    peer=%state.node,
                    reason=%err,
                    "Disconnecting peer: invalid block range update",
                );
                send_disconnect_message(state, Some(DisconnectReason::SubprotocolError)).await;
                return Err(PeerConnectionError::DisconnectSent(
                    DisconnectReason::SubprotocolError,
                ));
            }
        }
        Message::NewPooledTransactionHashes(new_pooled_transaction_hashes) if peer_supports_eth => {
            // Don't request transactions if we're not synced — we won't be building blocks soon.
            if state.blockchain.is_synced() {
                let hashes = new_pooled_transaction_hashes
                    .get_transactions_to_request(&state.blockchain, state.node.node_id())?;
                if !hashes.is_empty() {
                    // Buffer hashes for batched requesting instead of sending immediately.
                    // The periodic flush_pending_tx_requests handler will send them.
                    state
                        .pending_tx_requests
                        .push((new_pooled_transaction_hashes, hashes));
                }
            }
        }
        // eth/72 (EIP-8070): provider/sampler split based on blob_sampling_enabled.
        Message::NewPooledTransactionHashes72(announcement) if peer_supports_eth => {
            if state.blockchain.is_synced() {
                let peer_id = state.node.node_id();
                // Record peer cell availability from the announced mask, but only when
                // the announcement carries a blob tx: otherwise a peer sending an
                // all-zero mask on a non-blob announcement would overwrite its real
                // availability with an empty set and stop us sampling from it for good.
                // See `NewPooledTransactionHashes72::announces_blob_tx`.
                if announcement.announces_blob_tx()
                    && let Some(mask) = announcement.cell_mask
                    && let Err(e) = state
                        .blockchain
                        .mempool
                        .record_peer_cell_availability(peer_id, mask)
                {
                    warn!(error = %e, "record_peer_cell_availability failed");
                }

                let hashes =
                    announcement.get_transactions_to_request(&state.blockchain, peer_id)?;

                if !hashes.is_empty() {
                    if !state.blockchain.mempool.blob_sampling_enabled {
                        // Sampling disabled: always provider — request everything.
                        // Trim to the truly-requested subset so the flush does not
                        // re-request hashes already in-flight from another peer.
                        state.pending_tx_requests_72.push((
                            announcement.filter_to(&hashes),
                            hashes,
                            BlobFetchRole::Provider,
                        ));
                    } else {
                        // Sampling enabled: decide per-hash whether we are provider or sampler.
                        let epoch_seed = match state.storage.get_latest_block_number() {
                            Ok(n) => n / 32,
                            Err(e) => {
                                warn!(error = %e, "eth/72: head block unavailable; using epoch 0 for role split");
                                0
                            }
                        };

                        // Compute the local node id once per announcement (per-node entropy).
                        let local_pubkey = public_key_from_signing_key(&state.signer);
                        let local_node_id = node_id(&local_pubkey);
                        let eager = state.blockchain.mempool.is_eager_provider();

                        let mut provider_hashes: Vec<H256> = Vec::new();
                        let mut sampler_hashes: Vec<H256> = Vec::new();

                        for &hash in &hashes {
                            // Check if this is a blob tx (has a bit in cell_mask or
                            // was in a type-3 announcement). We use cell_mask presence
                            // as the signal — non-blob txs always go through provider flow.
                            let is_blob = announcement.cell_mask.is_some()
                                && announcement
                                    .transaction_types
                                    .iter()
                                    .zip(announcement.transaction_hashes.iter())
                                    .any(|(&ty, &h)| h == hash && ty == 3);

                            // provider path only when is_provider_role AND peer advertised
                            // full availability (all-ones mask). Otherwise sampler path.
                            let peer_is_full_provider = announcement.cell_mask == Some(u128::MAX);
                            if !is_blob
                                || (peer_is_full_provider
                                    && is_provider_role(local_node_id, hash, epoch_seed, eager))
                            {
                                provider_hashes.push(hash);
                            } else {
                                sampler_hashes.push(hash);
                            }
                        }

                        // Provider hashes: request full tx (and cells at u128::MAX).
                        if !provider_hashes.is_empty() {
                            let trimmed = announcement.filter_to(&provider_hashes);
                            // For provider role, request cells with all-ones mask.
                            let provider_ann = NewPooledTransactionHashes72::from_raw(
                                trimmed.transaction_types.clone(),
                                trimmed.transaction_sizes.clone(),
                                trimmed.transaction_hashes,
                                Some(u128::MAX),
                            );
                            state.pending_tx_requests_72.push((
                                provider_ann,
                                provider_hashes,
                                BlobFetchRole::Provider,
                            ));
                        }

                        // Sampler hashes: record the announcing peer as a provider
                        // ONLY if it signaled full availability (all-ones mask);
                        // a partially-available peer is not a provider observation.
                        // if recording this provider hits the threshold and we already
                        // have the tx body, retrigger cell-fetch immediately rather than
                        // waiting for the tx-body response path.
                        if announcement.cell_mask == Some(u128::MAX) {
                            let mempool = &state.blockchain.mempool;
                            for &hash in &sampler_hashes {
                                let count = match mempool
                                    .record_provider_announcement(hash, peer_id)
                                {
                                    Ok(n) => n,
                                    Err(e) => {
                                        warn!(error = %e, "record_provider_announcement failed");
                                        continue;
                                    }
                                };
                                // retrigger: threshold just reached and tx body already known.
                                if count
                                    == ethrex_blockchain::mempool::MIN_PROVIDERS_BEFORE_SAMPLING
                                    && mempool.contains_tx(hash).unwrap_or(false)
                                {
                                    let custody = match mempool.get_custody_columns() {
                                        Ok(c) => c,
                                        Err(e) => {
                                            warn!(error = %e, "get_custody_columns failed (D6b)");
                                            continue;
                                        }
                                    };
                                    // only add C_extra when this peer is a provider.
                                    let mut target = custody;
                                    if let Some(extra_col) =
                                        pick_random_extra_column(custody, local_node_id, hash)
                                    {
                                        target |= 1u128 << extra_col;
                                    }
                                    // A provider holds every column, so the whole
                                    // target can be requested from it.
                                    if target != 0 {
                                        state.pending_cell_requests.push((vec![hash], target));
                                    }
                                }
                            }
                        }
                        if !sampler_hashes.is_empty() {
                            // Request the tx body (no cells) from this peer.
                            let trimmed = announcement.filter_to(&sampler_hashes);
                            // No cell_mask: a sampler request carries no availability claim.
                            let sampler_ann = NewPooledTransactionHashes72::from_raw(
                                trimmed.transaction_types,
                                trimmed.transaction_sizes,
                                trimmed.transaction_hashes,
                                None,
                            );
                            state.pending_tx_requests_72.push((
                                sampler_ann,
                                sampler_hashes,
                                BlobFetchRole::Sampler,
                            ));
                        }
                    }
                }
            }
        }
        Message::GetPooledTransactions(msg) => {
            let response = msg.handle(&state.blockchain)?;
            let batch_size = response.pooled_transactions.len() as u64;
            // Leech detection: disconnect peers that drain transactions but never contribute any.
            if state.txs_sent_to_peer + batch_size > LEECH_TX_SENT_THRESHOLD
                && !state.received_txs_from_peer
            {
                debug!(
                    peer = %state.node,
                    txs_sent = state.txs_sent_to_peer,
                    "Disconnecting peer: leech detected (sent many txs but received none)",
                );
                send_disconnect_message(state, Some(DisconnectReason::UselessPeer)).await;
                return Err(PeerConnectionError::DisconnectSent(
                    DisconnectReason::UselessPeer,
                ));
            }
            // eth/72: respond with PooledTransactions72 (elided blob payload).
            let is_eth72 = state
                .negotiated_eth_capability
                .as_ref()
                .is_some_and(|cap| cap.version == 72);
            if is_eth72 {
                let response72 =
                    PooledTransactions72::new(response.id, response.pooled_transactions);
                send(state, Message::PooledTransactions72(response72)).await?;
            } else {
                // A blob tx ingested over eth/72 may sit in the pool with an
                // empty bundle (cells fetched separately). Pre-72 responses
                // carry blob txs with their full payload, and a wrapper whose
                // blob count disagrees with its commitments is a protocol
                // violation the peer disconnects us for — skip those instead,
                // which `GetPooledTransactions` explicitly allows.
                let mut response = response;
                response.pooled_transactions.retain(|tx| match tx {
                    P2PTransaction::EIP4844TransactionWithBlobs(wrapped) => {
                        wrapped.blobs_bundle.blobs.len() == wrapped.blobs_bundle.commitments.len()
                    }
                    _ => true,
                });
                send(state, Message::PooledTransactions(response)).await?;
            }
            state.txs_sent_to_peer += batch_size;
        }
        Message::PooledTransactions(msg) if peer_supports_eth => {
            if !msg.pooled_transactions.is_empty() {
                state.received_txs_from_peer = true;
            }
            // Always clear in-flight tracking for this response, regardless of sync status,
            // so other connections can re-request these hashes if needed.
            let removed_request = state.requested_pooled_txs.remove(&msg.id);
            if let Some((_, ref requested_hashes, _)) = removed_request {
                state
                    .blockchain
                    .mempool
                    .clear_in_flight_txs(requested_hashes)?;
            }
            // If we receive a blob transaction without blobs or with blobs that don't match the versioned hashes we must disconnect from the peer
            for tx in &msg.pooled_transactions {
                if let P2PTransaction::EIP4844TransactionWithBlobs(itx) = tx
                    && (itx.blobs_bundle.is_empty()
                        || itx
                            .blobs_bundle
                            .validate_blob_commitment_hashes(&itx.tx.blob_versioned_hashes)
                            .is_err())
                {
                    debug!(
                        peer=%state.node,
                        "Disconnecting peer: invalid or missing blobs",
                    );
                    if let Some((_announced, requested_hashes, _)) = &removed_request {
                        retry_on_alternates(&state.blockchain, &state.peer_table, requested_hashes)
                            .await;
                    }
                    send_disconnect_message(state, Some(DisconnectReason::SubprotocolError)).await;
                    return Err(PeerConnectionError::DisconnectSent(
                        DisconnectReason::SubprotocolError,
                    ));
                }
            }
            if state.blockchain.is_synced() {
                if let Some((announced, requested_hashes, _)) = &removed_request {
                    let fork = state.blockchain.current_fork()?;
                    if let Err(error) = msg.validate_requested(announced, fork) {
                        debug!(
                            peer=%state.node,
                            reason=%error,
                            "Disconnecting peer: invalid pooled transactions response",
                        );
                        retry_on_alternates(&state.blockchain, &state.peer_table, requested_hashes)
                            .await;
                        send_disconnect_message(state, Some(DisconnectReason::SubprotocolError))
                            .await;
                        return Err(PeerConnectionError::DisconnectSent(
                            DisconnectReason::SubprotocolError,
                        ));
                    }
                }
                #[cfg(feature = "l2")]
                let is_l2_mode = state.l2_state.is_supported();

                #[cfg(not(feature = "l2"))]
                let is_l2_mode = false;
                if let Err(error) = msg.handle(&state.node, &state.blockchain, is_l2_mode).await {
                    if matches!(
                        error,
                        ethrex_blockchain::error::MempoolError::BlobsBundleError(_)
                    ) {
                        debug!(
                            peer=%state.node,
                            reason=%error,
                            "Disconnecting peer: invalid pooled transactions response",
                        );
                        if let Some((_announced, requested_hashes, _)) = &removed_request {
                            retry_on_alternates(
                                &state.blockchain,
                                &state.peer_table,
                                requested_hashes,
                            )
                            .await;
                        }
                        send_disconnect_message(state, Some(DisconnectReason::SubprotocolError))
                            .await;
                        return Err(PeerConnectionError::DisconnectSent(
                            DisconnectReason::SubprotocolError,
                        ));
                    }
                    return Err(error.into());
                }
            }
        }
        // eth/72 (EIP-8070): PooledTransactions72 handler.
        // Blob txs arrive with elided blobs — do NOT trigger the missing-blob disconnect.
        Message::PooledTransactions72(msg) if peer_supports_eth => {
            if !msg.pooled_transactions.is_empty() {
                state.received_txs_from_peer = true;
            }
            let removed_request = state.requested_pooled_txs_72.remove(&msg.id);
            if let Some((_, ref requested_hashes, _, _)) = removed_request {
                state
                    .blockchain
                    .mempool
                    .clear_in_flight_txs(requested_hashes)?;
            }
            if state.blockchain.is_synced() {
                if let Some((announced, requested_hashes, _, _)) = &removed_request {
                    let fork = state.blockchain.current_fork()?;
                    if let Err(error) = msg.validate_requested(announced, fork) {
                        warn!(
                            peer=%state.node,
                            reason=%error,
                            "disconnected from peer (eth/72 PooledTransactions72)",
                        );
                        retry_on_alternates(&state.blockchain, &state.peer_table, requested_hashes)
                            .await;
                        send_disconnect_message(state, Some(DisconnectReason::SubprotocolError))
                            .await;
                        return Err(PeerConnectionError::DisconnectSent(
                            DisconnectReason::SubprotocolError,
                        ));
                    }
                }
                #[cfg(feature = "l2")]
                let is_l2_mode = state.l2_state.is_supported();
                #[cfg(not(feature = "l2"))]
                let is_l2_mode = false;
                if let Err(error) = msg.handle(&state.node, &state.blockchain, is_l2_mode).await {
                    if matches!(
                        error,
                        ethrex_blockchain::error::MempoolError::BlobsBundleError(_)
                    ) {
                        warn!(
                            peer=%state.node,
                            reason=%error,
                            "disconnected from peer (eth/72 blob error)",
                        );
                        if let Some((_announced, requested_hashes, _, _)) = &removed_request {
                            retry_on_alternates(
                                &state.blockchain,
                                &state.peer_table,
                                requested_hashes,
                            )
                            .await;
                        }
                        send_disconnect_message(state, Some(DisconnectReason::SubprotocolError))
                            .await;
                        return Err(PeerConnectionError::DisconnectSent(
                            DisconnectReason::SubprotocolError,
                        ));
                    }
                    return Err(error.into());
                }
                // EIP-8070 sampler: after tx validation, check if we have enough provider
                // announcements to start fetching cells.
                if state.blockchain.mempool.blob_sampling_enabled {
                    let peer_id = state.node.node_id();
                    let mempool = &state.blockchain.mempool;
                    let local_pubkey = public_key_from_signing_key(&state.signer);
                    let local_node_id = node_id(&local_pubkey);
                    if let Some((announced, requested_hashes, role, _)) = &removed_request {
                        // Provider role: the eth/72 PooledTransactions response is
                        // always elided, so the blobs never arrive with the body.
                        // A provider must end up holding the full payload (EIP-8070),
                        // and the only way to obtain it on an eth/72 connection is
                        // GetCells — request every column from this peer, which
                        // advertised full availability. Cells already held are
                        // subtracted at flush time.
                        if *role == BlobFetchRole::Provider {
                            let blob_hashes: Vec<H256> = announced
                                .transaction_types
                                .iter()
                                .zip(announced.transaction_hashes.iter())
                                .filter(|&(&ty, hash)| ty == 3 && requested_hashes.contains(hash))
                                .map(|(_, &hash)| hash)
                                .collect();
                            if !blob_hashes.is_empty() {
                                state.pending_cell_requests.push((blob_hashes, u128::MAX));
                            }
                        }
                        if *role == BlobFetchRole::Sampler {
                            for &tx_hash in requested_hashes.iter() {
                                // Providers were recorded at announce time (provider-gated);
                                // here we only read the distinct-provider count to decide
                                // whether the 2-provider sampling threshold is met.
                                let count = match mempool.provider_announcer_count(tx_hash) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        warn!(error = %e, "provider_announcer_count failed");
                                        continue;
                                    }
                                };
                                if count
                                    >= ethrex_blockchain::mempool::MIN_PROVIDERS_BEFORE_SAMPLING
                                {
                                    // Compute target columns = custody | extra.
                                    let custody = match mempool.get_custody_columns() {
                                        Ok(c) => c,
                                        Err(e) => {
                                            warn!(error = %e, "get_custody_columns failed");
                                            continue;
                                        }
                                    };
                                    // C_extra is only added when the target peer
                                    // is a provider (advertised full availability).
                                    let peer_mask = mempool
                                        .peer_cell_mask(peer_id)
                                        .unwrap_or(None)
                                        .unwrap_or(u128::MAX);
                                    let mut target = custody;
                                    if peer_mask == u128::MAX
                                        && let Some(extra_col) = pick_random_extra_column(
                                            custody,
                                            local_node_id,
                                            tx_hash,
                                        )
                                    {
                                        target |= 1u128 << extra_col;
                                    }
                                    let fetch_mask = target & peer_mask;
                                    if fetch_mask != 0 {
                                        state
                                            .pending_cell_requests
                                            .push((vec![tx_hash], fetch_mask));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // eth/72 (EIP-8070): GetCells handler — serve cells we hold.
        Message::GetCells(req) if peer_supports_eth => {
            let response = req.handle(&state.blockchain.mempool);
            send(state, Message::Cells(response)).await?;
        }
        // eth/72 (EIP-8070): Cells ingest — verify received cells against the
        // sidecar KZG proofs (carried in the elided PooledTransactions72), then
        // store. Cells that fail verification, or lack a matching sidecar proof,
        // cause a disconnect: accepting unverified cells would defeat DAS.
        ref message @ Message::Cells(_) if peer_supports_eth => {
            #[allow(unused_mut)]
            let mut verify_failed = false;
            // devp2p `caps/eth.md`: a `Cells` response must answer an outstanding
            // `GetCells`, and both its hash list and its `cells` bitmap must be
            // subsets of that request's. A peer sending unrequested elements must be
            // disconnected — unlike a KZG failure this is checkable without c-kzg,
            // and it stops a peer from pushing cells we never asked for.
            if let Message::Cells(cells_msg) = message {
                let outcome = match state.requested_cells.remove(&cells_msg.id) {
                    Some((requested_hashes, requested_mask, _)) => {
                        cells_msg.validate_requested(&requested_hashes, requested_mask)
                    }
                    None => Err(CellsResponseError::UnknownRequestId),
                };
                if let Err(error) = outcome {
                    debug!(
                        peer = %state.node,
                        id = cells_msg.id,
                        %error,
                        "Rejecting Cells response",
                    );
                    verify_failed = true;
                }
            }
            // Skip the KZG pass when the response already failed the framing checks:
            // nothing from an unrequested response should reach the cell store.
            #[cfg(feature = "c-kzg")]
            if let Message::Cells(cells_msg) = message
                && !verify_failed
            {
                use ethrex_common::types::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB, Commitment, Proof};
                use ethrex_crypto::kzg::verify_cell_kzg_proof_batch_partial;
                let mempool = &state.blockchain.mempool;
                // Columns carried in this response (ascending order of set bits).
                let cols: Vec<u64> = (0..CELLS_PER_EXT_BLOB as u64)
                    .filter(|bit| (cells_msg.cell_mask >> bit) & 1 == 1)
                    .collect();

                'txs: for (tx_idx, tx_hash) in cells_msg.transaction_hashes.iter().enumerate() {
                    let Some(bundle) = mempool.get_blobs_bundle(*tx_hash).unwrap_or(None) else {
                        continue;
                    };
                    // Cells are packed index-major per devp2p `caps/eth.md`:
                    // [col0 over blobs, col1 over blobs, ...].
                    let tx_cells = cells_msg.cells.get(tx_idx).cloned().unwrap_or_default();
                    let blob_count = bundle.commitments.len();

                    let mut to_store: Vec<(usize, usize, Box<[u8; BYTES_PER_CELL]>)> = Vec::new();
                    let mut v_commitments: Vec<Commitment> = Vec::new();
                    let mut v_cols: Vec<u64> = Vec::new();
                    let mut v_cells: Vec<[u8; BYTES_PER_CELL]> = Vec::new();
                    let mut v_proofs: Vec<Proof> = Vec::new();

                    for blob_idx in 0..blob_count {
                        for (col_pos, &col) in cols.iter().enumerate() {
                            let cell_pos = col_pos * blob_count + blob_idx;
                            let Some(&cell) = tx_cells.get(cell_pos) else {
                                continue;
                            };
                            // Sidecar cell proof for (blob_idx, col).
                            let proof_idx = blob_idx * CELLS_PER_EXT_BLOB + col as usize;
                            match (
                                bundle.proofs.get(proof_idx),
                                bundle.commitments.get(blob_idx),
                            ) {
                                (Some(&proof), Some(&commitment)) => {
                                    v_commitments.push(commitment);
                                    v_cols.push(col);
                                    v_cells.push(cell);
                                    v_proofs.push(proof);
                                    to_store.push((blob_idx, col as usize, Box::new(cell)));
                                }
                                // A received cell with no matching sidecar proof can't be trusted.
                                _ => {
                                    verify_failed = true;
                                    break 'txs;
                                }
                            }
                        }
                    }

                    if v_cells.is_empty() {
                        continue;
                    }
                    match verify_cell_kzg_proof_batch_partial(
                        &v_commitments,
                        &v_cols,
                        &v_cells,
                        &v_proofs,
                    ) {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            verify_failed = true;
                            break;
                        }
                    }
                    if let Err(e) = mempool.store_cells(*tx_hash, blob_count, to_store) {
                        warn!(error = %e, "store_cells failed");
                    }
                }
            }
            if verify_failed {
                warn!(peer=%state.node, "disconnected: invalid cell KZG proofs");
                if let Message::Cells(c) = message {
                    let hashes = c.transaction_hashes.clone();
                    retry_on_alternates(&state.blockchain, &state.peer_table, &hashes).await;
                }
                send_disconnect_message(state, Some(DisconnectReason::SubprotocolError)).await;
                return Err(PeerConnectionError::DisconnectSent(
                    DisconnectReason::SubprotocolError,
                ));
            }
        }
        Message::GetStorageRanges(req) => {
            let response = process_storage_ranges_request(req, state.storage.clone()).await?;
            send(state, Message::StorageRanges(response)).await?
        }
        Message::GetByteCodes(req) => {
            let storage_clone = state.storage.clone();
            let response = process_byte_codes_request(req, storage_clone)
                .await
                .map_err(|_| {
                    PeerConnectionError::InternalError(
                        "Failed to execute bytecode retrieval task".to_string(),
                    )
                })?;
            send(state, Message::ByteCodes(response)).await?
        }
        Message::GetTrieNodes(req) => {
            let id = req.id;
            match process_trie_nodes_request(req, state.storage.clone()).await {
                Ok(response) => send(state, Message::TrieNodes(response)).await?,
                Err(_) => send(state, Message::TrieNodes(TrieNodes { id, nodes: vec![] })).await?,
            }
        }
        #[cfg(feature = "l2")]
        Message::L2(req) if peer_supports_l2 => {
            handle_based_capability_message(state, req).await?;
        }
        // Send response messages to the backend
        message @ Message::AccountRange(_)
        | message @ Message::StorageRanges(_)
        | message @ Message::ByteCodes(_)
        | message @ Message::TrieNodes(_)
        | message @ Message::BlockBodies(_)
        | message @ Message::BlockHeaders(_)
        | message @ Message::Receipts68(_)
        | message @ Message::Receipts69(_)
        | message @ Message::Receipts70(_)
        | message @ Message::BlockAccessLists(_) => {
            if let Some((_, tx)) = message
                .request_id()
                .and_then(|id| state.current_requests.remove(&id))
            {
                tx.send(message)
                    .map_err(|e| PeerConnectionError::SendMessage(e.to_string()))?
            } else {
                return Err(PeerConnectionError::ExpectedRequestId(format!("{message}")));
            }
        }
        // TODO: Add new message types and handlers as they are implemented
        message => return Err(PeerConnectionError::MessageNotHandled(format!("{message}"))),
    };
    Ok(())
}

async fn handle_outgoing_message(
    state: &mut Established,
    message: Message,
) -> Result<(), PeerConnectionError> {
    trace!(
        peer=%state.node,
        %message,
        "Sending message"
    );
    send(state, message).await?;
    Ok(())
}

async fn handle_outgoing_request(
    state: &mut Established,
    message: Message,
    sender: oneshot::Sender<Message>,
) -> Result<(), PeerConnectionError> {
    // Insert the request in the request map if it supports a request id.
    message.request_id().and_then(|id| {
        state
            .current_requests
            .insert(id, (format!("{message}"), sender))
    });
    trace!(
        peer=%state.node,
        %message,
        "Sending request"
    );
    send(state, message).await?;
    Ok(())
}

async fn handle_broadcast(
    state: &mut Established,
    (id, broadcasted_msg): (task::Id, Arc<Message>),
) -> Result<(), PeerConnectionError> {
    if id != tokio::task::id() {
        match broadcasted_msg.as_ref() {
            #[cfg(feature = "l2")]
            l2_msg @ Message::L2(_) => {
                handle_l2_broadcast(state, l2_msg).await?;
            }
            msg => {
                error!(
                    peer=%state.node,
                    message=%msg,
                    "Non-supported message broadcasted"
                );
                let error_message = format!("Non-supported message broadcasted: {msg}");
                return Err(PeerConnectionError::BroadcastError(error_message));
            }
        }
    }
    Ok(())
}

async fn handle_block_range_update(state: &mut Established) -> Result<(), PeerConnectionError> {
    if should_send_block_range_update(state)? {
        send_block_range_update(state).await
    } else {
        Ok(())
    }
}

/// Drains the pending transaction request buffer and sends batched
/// GetPooledTransactions requests, respecting the 256-hash-per-request
/// limit from the devp2p ETH spec.
async fn flush_pending_tx_requests(state: &mut Established) -> Result<(), PeerConnectionError> {
    if state.pending_tx_requests.is_empty() {
        return Ok(());
    }

    let pending = std::mem::take(&mut state.pending_tx_requests);

    // Build a trimmed announcement containing only the hashes we're actually requesting,
    // with their original types and sizes for response validation.
    let mut all_hashes: Vec<H256> = Vec::new();
    let mut all_types: Vec<u8> = Vec::new();
    let mut all_sizes: Vec<usize> = Vec::new();

    for (announcement, hashes) in &pending {
        let trimmed = announcement.filter_to(hashes);
        all_hashes.extend_from_slice(&trimmed.transaction_hashes);
        all_types.extend_from_slice(&trimmed.transaction_types);
        all_sizes.extend(trimmed.transaction_sizes);
    }

    // Send in chunks of MAX_HASHES_PER_REQUEST per the devp2p spec.
    const MAX_HASHES_PER_REQUEST: usize = 256;
    for (i, chunk) in all_hashes.chunks(MAX_HASHES_PER_REQUEST).enumerate() {
        let offset = i * MAX_HASHES_PER_REQUEST;
        let chunk_types = &all_types[offset..offset + chunk.len()];
        let chunk_sizes = &all_sizes[offset..offset + chunk.len()];

        let announcement = NewPooledTransactionHashes::from_raw(
            chunk_types.to_vec().into(),
            chunk_sizes.to_vec(),
            chunk.to_vec(),
        );
        let request = GetPooledTransactions::new(random(), chunk.to_vec());
        let request_id = request.id;
        // Send first, only register in requested_pooled_txs on success.
        // This ensures we never track hashes for messages that were not transmitted.
        if let Err(e) = send(state, Message::GetPooledTransactions(request)).await {
            // Clear in-flight for the current chunk (failed to send) and all remaining chunks,
            // then try alternate announcers. Order matters: clear first so the alternate's
            // reserve_unknown_hashes sees the hashes as free.
            // Build an announcement covering every unsent hash (later chunks too) so the
            // alternate can validate its response against the original type/size metadata.
            let unsent = &all_hashes[offset..];
            if !unsent.is_empty() {
                if let Err(clear_err) = state.blockchain.mempool.clear_in_flight_txs(unsent) {
                    warn!(error = %clear_err, "Failed to clear in-flight transaction tracking after send error");
                }
                retry_on_alternates(&state.blockchain, &state.peer_table, unsent).await;
            }
            return Err(e);
        }
        state
            .requested_pooled_txs
            .insert(request_id, (announcement, chunk.to_vec(), Instant::now()));
    }

    Ok(())
}

/// eth/72 variant of flush_pending_tx_requests.
/// Sends GetPooledTransactions for v72 announcements and stores them in
/// requested_pooled_txs_72 for validation when PooledTransactions72 arrives.
///
/// Hashes are grouped by [`BlobFetchRole`] before chunking: the role decides
/// whether cells are fetched once the bodies arrive, so provider and sampler
/// hashes must never share a request.
///
/// Per-announcement cell_mask tracking: each hash carries the availability its
/// announcer claimed. When hashes are chunked across multiple requests, each
/// chunk's mask is the union of only the masks relevant to the hashes in that
/// chunk (not a global OR across all announcements).
async fn flush_pending_tx_requests_72(state: &mut Established) -> Result<(), PeerConnectionError> {
    if state.pending_tx_requests_72.is_empty() {
        return Ok(());
    }

    let pending = std::mem::take(&mut state.pending_tx_requests_72);

    // Flatten per-hash metadata into one run per role.
    let mut by_role: Vec<(BlobFetchRole, Vec<AnnouncedTx>)> = vec![
        (BlobFetchRole::Provider, Vec::new()),
        (BlobFetchRole::Sampler, Vec::new()),
    ];
    for (announcement, _hashes, role) in &pending {
        let Some((_, entries)) = by_role.iter_mut().find(|(r, _)| r == role) else {
            continue;
        };
        for (i, hash) in announcement.transaction_hashes.iter().enumerate() {
            entries.push((
                *hash,
                announcement.transaction_types[i],
                announcement.transaction_sizes[i],
                announcement.cell_mask,
            ));
        }
    }

    // Every hash still to be sent, in send order, so a failed write can release the
    // in-flight reservation for all of them and not just the current role's tail.
    let mut unsent: Vec<H256> = by_role
        .iter()
        .flat_map(|(_, entries)| entries.iter().map(|(hash, ..)| *hash))
        .collect();

    const MAX_HASHES_PER_REQUEST: usize = 256;
    for (role, entries) in &by_role {
        for chunk in entries.chunks(MAX_HASHES_PER_REQUEST) {
            let chunk_hashes: Vec<H256> = chunk.iter().map(|(hash, ..)| *hash).collect();
            // Compute the mask for this chunk only: OR of masks for hashes in this chunk.
            let chunk_cell_mask: Option<u128> =
                chunk
                    .iter()
                    .fold(None, |acc, (.., mask)| match (acc, mask) {
                        (None, None) => None,
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(*b),
                        (Some(a), Some(b)) => Some(a | b),
                    });

            let announcement = NewPooledTransactionHashes72::from_raw(
                chunk
                    .iter()
                    .map(|(_, ty, ..)| *ty)
                    .collect::<Vec<_>>()
                    .into(),
                chunk.iter().map(|(_, _, size, _)| *size).collect(),
                chunk_hashes.clone(),
                chunk_cell_mask,
            );
            let request = GetPooledTransactions::new(random(), chunk_hashes.clone());
            let request_id = request.id;
            if let Err(e) = send(state, Message::GetPooledTransactions(request)).await {
                if !unsent.is_empty() {
                    if let Err(clear_err) = state.blockchain.mempool.clear_in_flight_txs(&unsent) {
                        warn!(error = %clear_err, "clear_in_flight_txs failed after send error (v72)");
                    }
                    retry_on_alternates(&state.blockchain, &state.peer_table, &unsent).await;
                }
                return Err(e);
            }
            // Chunks are emitted in the order `unsent` was built, so the sent ones
            // are always its prefix.
            unsent.drain(..chunk_hashes.len());
            state.requested_pooled_txs_72.insert(
                request_id,
                (announcement, chunk_hashes, *role, Instant::now()),
            );
        }
    }

    Ok(())
}

/// EIP-8070: flush buffered cell requests as batched GetCells messages.
/// Mirrors flush_pending_tx_requests_72 but sends GetCells instead of
/// GetPooledTransactions.
async fn flush_pending_cell_requests(state: &mut Established) -> Result<(), PeerConnectionError> {
    if state.pending_cell_requests.is_empty() {
        return Ok(());
    }
    let pending = std::mem::take(&mut state.pending_cell_requests);
    // GetCells (0x14) only exists in eth/72; on an older negotiated version that
    // message id lands outside the eth range and the peer drops the connection.
    if !supports_eth72(state) {
        return Ok(());
    }

    // Merge all pending requests into a flat list of hashes with their masks,
    // dropping the columns already held: requests are queued from several
    // triggers (announce retrigger, tx-body response, custody sweep) and by
    // every connection, so without this the same cells are re-requested after
    // another peer already delivered them.
    let mut all_hashes: Vec<H256> = Vec::new();
    let mut all_masks: Vec<u128> = Vec::new();
    for (hashes, mask) in &pending {
        for &h in hashes {
            let missing = mask & !state.blockchain.mempool.available_cell_mask(h);
            if missing != 0 {
                all_hashes.push(h);
                all_masks.push(missing);
            }
        }
    }
    if all_hashes.is_empty() {
        return Ok(());
    }

    // Stay under the devp2p `caps/eth.md` soft limit of 64 hashes per GetCells, and
    // tighten it further so a peer applying the `MAX_CELLS_SERVED` budget can answer
    // in full: it omits trailing transactions, and an omitted tail is not re-requested
    // until the next announcement or custody change. The widest mask in the batch
    // bounds every chunk's mask, so this is conservative.
    let widest_mask = all_masks.iter().fold(0u128, |acc, &m| acc | m);
    let hashes_per_request =
        (MAX_CELLS_SERVED / cells_per_hash(widest_mask)).clamp(1, GET_CELLS_SOFT_LIMIT_HASHES);
    for (i, chunk) in all_hashes.chunks(hashes_per_request).enumerate() {
        let offset = i * hashes_per_request;
        let chunk_len = chunk.len();
        let chunk_masks = &all_masks[offset..offset + chunk_len];
        // Merge masks for this chunk.
        let merged_mask = chunk_masks.iter().fold(0u128, |acc, &m| acc | m);
        let id = random();
        let request = GetCells::new(id, chunk.to_vec(), merged_mask);
        send(state, Message::GetCells(request)).await?;
        // Register only after a successful send, so a failed write doesn't leave a
        // phantom in-flight entry (mirrors `flush_pending_tx_requests`).
        state
            .requested_cells
            .insert(id, (chunk.to_vec(), merged_mask, Instant::now()));
    }
    Ok(())
}

/// EIP-8070 messages (`GetCells`, `Cells`) exist only in eth/72, so they may only
/// be sent once eth/72 is the negotiated version for this connection.
fn supports_eth72(state: &Established) -> bool {
    state
        .negotiated_eth_capability
        .as_ref()
        .is_some_and(|cap| cap.version >= 72)
}

/// For each hash that has a remaining alternate announcer, look up that
/// peer's connection and enqueue the request there. Each alternate carries
/// the (type, size) metadata it originally announced, so the retry request
/// is built from the alternate's own announcement rather than the failing
/// peer's; otherwise validation against the failing peer's sizes would
/// reject the alternate's response when the two announcements differ (e.g.
/// bare blob tx vs full sidecar).
///
/// If a popped alternate is no longer reachable, keep popping until a live
/// peer is found or alternates for that hash are exhausted, so a disconnected
/// alternate doesn't burn the only fallback slot.
async fn retry_on_alternates(
    blockchain: &Arc<Blockchain>,
    peer_table: &PeerTable,
    hashes: &[H256],
) {
    if hashes.is_empty() {
        return;
    }
    // Group hashes by chosen live alternate, carrying their own type/size.
    // We walk per-hash so a dead alternate for hash X doesn't consume the
    // slot that hash Y could use. The `PeerConnection` handle from the
    // liveness probe is stashed in `by_peer` and reused at enqueue time,
    // so there's no second lookup (and no race where the connection drops
    // between probe and use).
    type AltGroup = (PeerConnection, Vec<(H256, u8, usize)>);
    let mut by_peer: FxHashMap<H256, AltGroup> = FxHashMap::default();
    for hash in hashes {
        loop {
            let alt = match blockchain.mempool.pop_alternate(*hash) {
                Ok(Some(a)) => a,
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "pop_alternate failed");
                    break;
                }
            };
            // Reuse the connection we already grabbed for this peer.
            if let Some((_, list)) = by_peer.get_mut(&alt.peer_id) {
                list.push((*hash, alt.tx_type, alt.tx_size));
                break;
            }
            match peer_table.get_peer_connection(alt.peer_id).await {
                Ok(Some(conn)) => {
                    by_peer.insert(alt.peer_id, (conn, vec![(*hash, alt.tx_type, alt.tx_size)]));
                    break;
                }
                Ok(None) => continue, // dead peer, try next alternate
                Err(e) => {
                    warn!(error = %e, "get_peer_connection failed");
                    break;
                }
            }
        }
    }

    for (_, (conn, entries)) in by_peer {
        let mut types = Vec::with_capacity(entries.len());
        let mut sizes = Vec::with_capacity(entries.len());
        let mut hash_list = Vec::with_capacity(entries.len());
        for (h, t, s) in &entries {
            hash_list.push(*h);
            types.push(*t);
            sizes.push(*s);
        }
        let announcement =
            NewPooledTransactionHashes::from_raw(types.into(), sizes, hash_list.clone());
        if let Err(e) = conn.enqueue_tx_requests(announcement, hash_list) {
            debug!(error = %e, "Failed to enqueue tx requests on alternate peer");
        }
    }
}
