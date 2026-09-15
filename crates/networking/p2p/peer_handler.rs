use crate::discovery::DiscoveryHandle;
use crate::rlpx::initiator::RLPxInitiator;
use crate::{
    metrics::{CurrentStepValue, METRICS},
    peer_table::{
        PeerData, PeerDiagnostics, PeerTable, PeerTableServerProtocol as _, RequestPermit,
        SelectedPeer,
    },
    rlpx::{
        connection::server::PeerConnection,
        error::PeerConnectionError,
        eth::{
            block_access_lists::{BlockAccessLists, GetBlockAccessLists},
            blocks::{
                BLOCK_HEADER_LIMIT, BlockBodies, BlockHeaders, GetBlockBodies, GetBlockHeaders,
                HashOrNumber,
            },
            receipts::{GetReceipts, GetReceipts70},
        },
        message::Message as RLPxMessage,
        p2p::{Capability, SUPPORTED_ETH_CAPABILITIES},
    },
};
use ethrex_common::{
    H256,
    types::{
        BlockBody, BlockHeader, Receipt, block_access_list::BlockAccessList, compute_receipts_root,
        validate_block_body,
    },
};
use ethrex_crypto::NativeCrypto;
use spawned_concurrency::{error::ActorError, tasks::ActorRef};
use std::{
    collections::{HashSet, VecDeque},
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, trace, warn};

// Re-export constants from snap::constants for backward compatibility
pub use crate::snap::constants::{
    HASH_MAX, MAX_BLOCK_BODIES_TO_REQUEST, MAX_HEADER_CHUNK, MAX_RESPONSE_BYTES,
    PEER_REPLY_TIMEOUT, PEER_SELECT_RETRY_ATTEMPTS, RANGE_FILE_CHUNK_SIZE, REQUEST_RETRY_ATTEMPTS,
    SNAP_LIMIT,
};

// Re-export snap client types for backward compatibility
pub use crate::snap::{DumpError, RequestMetadata, RequestStorageTrieNodesError, SnapError};

/// An abstraction over the [Kademlia] containing logic to make requests to peers
#[derive(Debug, Clone)]
pub struct PeerHandler {
    pub peer_table: PeerTable,
    /// Reports peers that turned out to be useless back to discovery, and asks
    /// it to prune. Inert when discovery is not running.
    pub discovery: DiscoveryHandle,
    pub initiator: ActorRef<RLPxInitiator>,
}

pub enum BlockRequestOrder {
    OldToNew,
    NewToOld,
}

/// Result of a block-header request, distinguishing why no headers came back so sync
/// diagnostics can tell a connectivity problem from peers withholding data.
#[derive(Debug)]
pub enum HeaderFetchOutcome {
    /// Headers were obtained from a peer.
    Headers(Vec<BlockHeader>),
    /// No suitable peer was available to send the request to (e.g. no eth-capable peer
    /// connected, or all are busy / penalized).
    NoPeerAvailable,
    /// A peer was queried but returned no usable response (timeout, empty, or unchained).
    PeerFailed,
}

impl HeaderFetchOutcome {
    /// A short, log-friendly reason for a non-`Headers` outcome.
    pub fn failure_reason(&self) -> &'static str {
        match self {
            HeaderFetchOutcome::Headers(_) => "headers received",
            HeaderFetchOutcome::NoPeerAvailable => {
                "no eth-capable peer with a live connection to query (peers may be connecting or recently dropped)"
            }
            HeaderFetchOutcome::PeerFailed => "peer(s) queried but did not serve headers",
        }
    }
}

/// Highest eth version we would negotiate with a peer advertising `capabilities`.
///
/// Mirrors the handshake rule in `rlpx::connection::server` (the highest version
/// supported by both sides wins), so callers can pick the wire format the
/// connection actually uses. Returns `None` if we share no eth version with the
/// peer.
fn negotiated_eth_version(capabilities: &[Capability]) -> Option<u8> {
    capabilities
        .iter()
        .filter(|cap| SUPPORTED_ETH_CAPABILITIES.contains(cap))
        .map(|cap| cap.version)
        .max()
}

/// Asks a single already-selected peer for the block number at `sync_head`.
/// Consumes a `RequestPermit`; the permit drops on return, releasing the slot.
async fn ask_peer_head_number(
    peer_id: H256,
    connection: &mut PeerConnection,
    _permit: RequestPermit,
    sync_head: H256,
    retries: i32,
) -> Result<u64, PeerHandlerError> {
    // TODO: Better error handling
    trace!("Sync Log 11: Requesting sync head block number from peer {peer_id}");
    let request_id = rand::random();
    let request = RLPxMessage::GetBlockHeaders(GetBlockHeaders {
        id: request_id,
        startblock: HashOrNumber::Hash(sync_head),
        limit: 1,
        skip: 0,
        reverse: false,
    });

    debug!("(Retry {retries}) Requesting sync head {sync_head:?} to peer {peer_id}");

    match connection
        .outgoing_request(request, PEER_REPLY_TIMEOUT)
        .await
    {
        Ok(RLPxMessage::BlockHeaders(BlockHeaders {
            id: _,
            block_headers,
        })) => {
            if !block_headers.is_empty() {
                let sync_head_number = block_headers
                    .last()
                    .ok_or(PeerHandlerError::BlockHeaders)?
                    .number;
                trace!(
                    "Sync Log 12: Received sync head block headers from peer {peer_id}, sync head number {sync_head_number}"
                );
                Ok(sync_head_number)
            } else {
                Err(PeerHandlerError::EmptyResponseFromPeer(peer_id))
            }
        }
        Ok(_other_msgs) => Err(PeerHandlerError::UnexpectedResponseFromPeer(peer_id)),
        Err(PeerConnectionError::Timeout) => {
            Err(PeerHandlerError::ReceiveMessageFromPeerTimeout(peer_id))
        }
        Err(_other_err) => Err(PeerHandlerError::ReceiveMessageFromPeer(peer_id)),
    }
}

impl PeerHandler {
    pub fn new(
        peer_table: PeerTable,
        initiator: ActorRef<RLPxInitiator>,
        discovery: DiscoveryHandle,
    ) -> PeerHandler {
        Self {
            peer_table,
            discovery,
            initiator,
        }
    }

    /// Returns a random node id and the channel ends to an active peer connection that supports the given capability
    /// It doesn't guarantee that the selected peer is not currently busy
    async fn get_random_peer(
        &mut self,
        capabilities: &[Capability],
    ) -> Result<Option<SelectedPeer>, PeerHandlerError> {
        Ok(self
            .peer_table
            .get_random_peer(capabilities.to_vec())
            .await?)
    }

    /// Number of peers known to the table that advertise the eth capabilities used for sync.
    /// NOTE: this counts eth-capable peers regardless of whether they currently have a live
    /// connection, so it can be greater than the number actually queryable via
    /// `get_random_peer` (which requires a live connection). Used only for diagnostics; logged
    /// as `eth_capable_peers`. Returns 0 on any peer-table error.
    pub async fn eth_capable_peer_count(&self) -> usize {
        self.peer_table
            .peer_count_by_capabilities(SUPPORTED_ETH_CAPABILITIES.to_vec())
            .await
            .unwrap_or(0)
    }

    /// Requests block headers from any suitable peer, starting from the `start` block hash towards either older or newer blocks depending on the order
    /// Returns the block headers or None if:
    /// - There are no available peers (the node just started up or was rejected by all other nodes)
    /// - No peer returned a valid response in the given time and retry limits
    pub async fn request_block_headers(
        &mut self,
        start: u64,
        sync_head: H256,
    ) -> Result<Option<Vec<BlockHeader>>, PeerHandlerError> {
        let start_time = SystemTime::now();
        METRICS
            .current_step
            .set(CurrentStepValue::DownloadingHeaders);

        let mut ret = Vec::<BlockHeader>::new();

        let mut sync_head_number = 0_u64;

        let sync_head_number_retrieval_start = SystemTime::now();

        debug!("Retrieving sync head block number from peers");

        let mut retries = 1;

        // Ask up to MAX_PEERS_TO_ASK peers per retry (no point asking 40+
        // peers sequentially with a 15s timeout each).
        const MAX_PEERS_TO_ASK: usize = 5;
        const MAX_RETRIES: i32 = 3;

        while sync_head_number == 0 {
            if retries > MAX_RETRIES {
                // sync_head is unknown to our peers
                return Ok(None);
            }
            let peers = self
                .peer_table
                .get_best_n_peers(SUPPORTED_ETH_CAPABILITIES.to_vec(), MAX_PEERS_TO_ASK)
                .await?;

            let selected_peers: Vec<_> = peers.iter().map(|(id, _, _)| *id).collect();
            debug!(
                retry = retries,
                peers_selected = ?selected_peers,
                "request_block_headers: resolving sync head with peers"
            );
            for (peer_id, mut connection, permit) in peers {
                match ask_peer_head_number(peer_id, &mut connection, permit, sync_head, retries)
                    .await
                {
                    Ok(number) => {
                        sync_head_number = number;
                        if number != 0 {
                            #[cfg(feature = "metrics")]
                            ethrex_metrics::sync::METRICS_SYNC.inc_header_resolution("found");
                            break;
                        }
                        #[cfg(feature = "metrics")]
                        ethrex_metrics::sync::METRICS_SYNC.inc_header_resolution("unknown");
                    }
                    Err(err) => {
                        #[cfg(feature = "metrics")]
                        ethrex_metrics::sync::METRICS_SYNC.inc_header_resolution("timeout");
                        debug!(
                            "Sync Log 13: Failed to retrieve sync head block number from peer {peer_id}: {err}"
                        );
                    }
                }
            }

            retries += 1;
        }
        METRICS
            .sync_head_block
            .store(sync_head_number, Ordering::Relaxed);
        sync_head_number = sync_head_number.min(start + MAX_HEADER_CHUNK);

        let sync_head_number_retrieval_elapsed = sync_head_number_retrieval_start
            .elapsed()
            .unwrap_or_default();

        debug!("Sync head block number retrieved");

        *METRICS.time_to_retrieve_sync_head_block.lock().await =
            Some(sync_head_number_retrieval_elapsed);
        *METRICS.sync_head_hash.lock().await = sync_head;

        let block_count = sync_head_number + 1 - start;
        let chunk_count = if block_count < 800_u64 { 1 } else { 800_u64 };

        // 2) partition the amount of headers in `K` tasks
        let chunk_limit = block_count / chunk_count;

        // list of tasks to be executed
        let mut tasks_queue_not_started = VecDeque::<(u64, u64)>::new();

        for i in 0..chunk_count {
            tasks_queue_not_started.push_back((i * chunk_limit + start, chunk_limit));
        }

        // Push the reminder
        if !block_count.is_multiple_of(chunk_count) {
            tasks_queue_not_started
                .push_back((chunk_count * chunk_limit + start, block_count % chunk_count));
        }

        let mut downloaded_count = 0_u64;

        // channel to send the tasks to the peers
        let (task_sender, mut task_receiver) =
            tokio::sync::mpsc::channel::<(Vec<BlockHeader>, H256, PeerConnection, u64, u64)>(1000);

        let mut current_show = 0;

        // 3) create tasks that will request a chunk of headers from a peer

        debug!("Starting to download block headers from peers");

        *METRICS.headers_download_start_time.lock().await = Some(SystemTime::now());

        let mut logged_no_free_peers_count = 0;

        loop {
            if let Ok((headers, peer_id, _connection, startblock, previous_chunk_limit)) =
                task_receiver.try_recv()
            {
                trace!("We received a download chunk from peer");
                if headers.is_empty() {
                    self.peer_table.record_failure(peer_id)?;

                    debug!("Failed to download chunk from peer. Downloader {peer_id} freed");

                    // reinsert the task to the queue
                    tasks_queue_not_started.push_back((startblock, previous_chunk_limit));

                    continue; // Retry with the next peer
                }

                downloaded_count += headers.len() as u64;

                METRICS.downloaded_headers.inc_by(headers.len() as u64);

                let batch_show = downloaded_count / 10_000;

                if current_show < batch_show {
                    debug!(
                        "Downloaded {} headers from peer {} (current count: {downloaded_count})",
                        headers.len(),
                        peer_id
                    );
                    current_show += 1;
                }
                // store headers!!!!
                ret.extend_from_slice(&headers);

                let downloaded_headers = headers.len() as u64;

                // reinsert the task to the queue if it was not completed
                if downloaded_headers < previous_chunk_limit {
                    let new_start = startblock + headers.len() as u64;

                    let new_chunk_limit = previous_chunk_limit - headers.len() as u64;

                    debug!(
                        "Task for ({startblock}, {new_chunk_limit}) was not completed, re-adding to the queue, {new_chunk_limit} remaining headers"
                    );

                    tasks_queue_not_started.push_back((new_start, new_chunk_limit));
                }

                self.peer_table.record_success(peer_id)?;
                debug!("Downloader {peer_id} freed");
            }
            let Some((peer_id, mut connection, permit)) = self
                .peer_table
                .get_best_peer(SUPPORTED_ETH_CAPABILITIES.to_vec())
                .await?
            else {
                // Log ~ once every 10 seconds
                if logged_no_free_peers_count == 0 {
                    trace!("We are missing peers in request_block_headers");
                    logged_no_free_peers_count = 1000;
                }
                logged_no_free_peers_count -= 1;
                // Sleep a bit to avoid busy polling
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };

            let Some((startblock, chunk_limit)) = tasks_queue_not_started.pop_front() else {
                if downloaded_count >= block_count {
                    debug!("All headers downloaded successfully");
                    break;
                }

                let batch_show = downloaded_count / 10_000;

                if current_show < batch_show {
                    current_show += 1;
                }

                // Queue drained but in-flight tasks haven't returned yet.
                // Drop the permit we just acquired (end of scope) and yield
                // so the result receive path gets a chance to run.
                tokio::task::yield_now().await;
                continue;
            };
            let tx = task_sender.clone();
            debug!("Downloader {peer_id} is now busy");

            tokio::spawn(async move {
                trace!(
                    "Sync Log 5: Requesting block headers from peer {peer_id}, chunk_limit: {chunk_limit}"
                );
                let headers = Self::download_chunk_from_peer(
                    peer_id,
                    &mut connection,
                    permit,
                    startblock,
                    chunk_limit,
                )
                .await
                .inspect_err(|err| trace!("Sync Log 6: {peer_id} failed to download chunk: {err}"))
                .unwrap_or_default();

                tx.send((headers, peer_id, connection, startblock, chunk_limit))
                    .await
                    .inspect_err(|err| {
                        error!("Failed to send headers result through channel. Error: {err}")
                    })
            });
        }

        let elapsed = start_time.elapsed().unwrap_or_default();

        debug!(
            "Downloaded all headers ({}) in {} seconds",
            ret.len(),
            format_duration(elapsed)
        );

        {
            let downloaded_headers = ret.len();
            let unique_headers = ret.iter().map(|h| h.hash()).collect::<HashSet<_>>();

            debug!(
                "Downloaded {} headers, unique: {}, duplicates: {}",
                downloaded_headers,
                unique_headers.len(),
                downloaded_headers - unique_headers.len()
            );

            match downloaded_headers.cmp(&unique_headers.len()) {
                std::cmp::Ordering::Equal => {
                    debug!("All downloaded headers are unique");
                }
                std::cmp::Ordering::Greater => {
                    debug!(
                        "Downloaded headers contain duplicates, {} duplicates found",
                        downloaded_headers - unique_headers.len()
                    );
                }
                std::cmp::Ordering::Less => {
                    debug!(
                        "Downloaded headers are less than unique headers, this should not happen"
                    );
                }
            }
        }

        ret.sort_by(|x, y| x.number.cmp(&y.number));
        Ok(Some(ret))
    }

    /// Requests block headers from any suitable peer, starting from the `start` block hash towards either older or newer blocks depending on the order
    /// - No peer returned a valid response in the given time and retry limits
    ///   Since request_block_headers brought problems in cases of reorg seen in this pr https://github.com/lambdaclass/ethrex/pull/4028, we have this other function to request block headers only for full sync.
    pub async fn request_block_headers_from_hash(
        &mut self,
        start: H256,
        order: BlockRequestOrder,
    ) -> Result<HeaderFetchOutcome, PeerHandlerError> {
        let request_id = rand::random();
        let request = RLPxMessage::GetBlockHeaders(GetBlockHeaders {
            id: request_id,
            startblock: start.into(),
            limit: BLOCK_HEADER_LIMIT,
            skip: 0,
            reverse: matches!(order, BlockRequestOrder::NewToOld),
        });
        match self.get_random_peer(&SUPPORTED_ETH_CAPABILITIES).await? {
            None => Ok(HeaderFetchOutcome::NoPeerAvailable),
            Some((peer_id, mut connection, permit, _caps)) => {
                let response = connection
                    .outgoing_request(request, PEER_REPLY_TIMEOUT)
                    .await;
                drop(permit);
                if let Ok(RLPxMessage::BlockHeaders(BlockHeaders {
                    id: _,
                    block_headers,
                })) = response
                {
                    if block_headers.is_empty() {
                        // Empty response is valid per eth spec (peer may not have these blocks),
                        // so apply only a soft score penalty (`record_failure`) rather than
                        // ejecting the peer (`set_disposable`): a spec-conformant peer that simply
                        // lacks a fork's blocks shouldn't be permanently dropped from rotation.
                        // Genuine misbehavior below (unchained / wrong-chain-start) uses the same
                        // soft tier, so the distinction stays consistent.
                        debug!(
                            "[SYNCING] Received empty headers from peer {peer_id}, trying another"
                        );
                        self.peer_table.record_failure(peer_id)?;
                        return Ok(HeaderFetchOutcome::PeerFailed);
                    }
                    if are_block_headers_chained(&block_headers, &order) {
                        // Pin the response to the requested `start` hash. `are_block_headers_chained`
                        // only verifies internal parent-hash linkage, not that the sequence actually
                        // begins at `start`. A peer on a fork/minority chain can return an internally
                        // consistent run of headers from its own chain that does NOT start at `start`;
                        // accepting it derails the sync walk onto the wrong chain — it never reconciles
                        // to our canonical head and walks all the way to genesis. Reject the mismatch and
                        // penalize the peer so the caller re-rolls `get_random_peer` and keeps trying until
                        // it lands a peer actually serving `start`'s chain (whose ancestry is hash-linked
                        // and therefore bridges down to our canonical head). General hardening, not
                        // devnet-specific.
                        if block_headers[0].hash() != start {
                            warn!(
                                "[SYNCING] Peer {peer_id} returned headers not starting at the requested hash {start:#x}, penalizing peer"
                            );
                            self.peer_table.record_failure(peer_id)?;
                            return Ok(HeaderFetchOutcome::PeerFailed);
                        }
                        self.peer_table.record_success(peer_id)?;
                        return Ok(HeaderFetchOutcome::Headers(block_headers));
                    }
                    // Non-empty but unchained headers is a protocol violation
                    debug!(
                        "Received invalid (unchained) headers from peer, penalizing peer {peer_id}"
                    );
                    self.peer_table.record_failure(peer_id)?;
                    return Ok(HeaderFetchOutcome::PeerFailed);
                }
                // Timeout or invalid response - mark peer as disposable
                debug!("Didn't receive block headers from peer, penalizing peer {peer_id}");
                self.peer_table.record_failure(peer_id)?;
                Ok(HeaderFetchOutcome::PeerFailed)
            }
        }
    }

    /// Given a peer id, a chunk start and a chunk limit, requests the block headers from the peer.
    /// Releases the peer slot as soon as the wire response is in; validation
    /// below is pure computation.
    async fn download_chunk_from_peer(
        peer_id: H256,
        connection: &mut PeerConnection,
        permit: RequestPermit,
        startblock: u64,
        chunk_limit: u64,
    ) -> Result<Vec<BlockHeader>, PeerHandlerError> {
        debug!("Requesting block headers from peer {peer_id}");
        let request_id = rand::random();
        let request = RLPxMessage::GetBlockHeaders(GetBlockHeaders {
            id: request_id,
            startblock: HashOrNumber::Number(startblock),
            limit: chunk_limit,
            skip: 0,
            reverse: false,
        });
        let response = connection
            .outgoing_request(request, PEER_REPLY_TIMEOUT)
            .await;
        drop(permit);
        if let Ok(RLPxMessage::BlockHeaders(BlockHeaders {
            id: _,
            block_headers,
        })) = response
        {
            if are_block_headers_chained(&block_headers, &BlockRequestOrder::OldToNew) {
                Ok(block_headers)
            } else {
                debug!("Received invalid headers from peer: {peer_id}");
                Err(PeerHandlerError::InvalidHeaders)
            }
        } else {
            Err(PeerHandlerError::BlockHeaders)
        }
    }

    /// Internal method to request block bodies from any suitable peer given their block hashes
    /// Returns the block bodies or None if:
    /// - There are no available peers (the node just started up or was rejected by all other nodes)
    /// - The requested peer did not return a valid response in the given time limit
    async fn request_block_bodies_inner(
        &mut self,
        block_hashes: &[H256],
    ) -> Result<Option<(Vec<BlockBody>, H256)>, PeerHandlerError> {
        let block_hashes_len = block_hashes.len();
        let request_id = rand::random();
        let request = RLPxMessage::GetBlockBodies(GetBlockBodies {
            id: request_id,
            block_hashes: block_hashes.to_vec(),
        });
        match self.get_random_peer(&SUPPORTED_ETH_CAPABILITIES).await? {
            None => Ok(None),
            Some((peer_id, mut connection, permit, _caps)) => {
                let response = connection
                    .outgoing_request(request, PEER_REPLY_TIMEOUT)
                    .await;
                drop(permit);
                if let Ok(RLPxMessage::BlockBodies(BlockBodies {
                    id: _,
                    block_bodies,
                })) = response
                {
                    if block_bodies.len() > block_hashes_len {
                        // More bodies than hashes requested: a protocol violation, so
                        // bottom out its score rather than just nudging it down.
                        debug!(
                            %peer_id,
                            got = block_bodies.len(),
                            requested = block_hashes_len,
                            "Peer returned more block bodies than requested, disposing"
                        );
                        self.peer_table.record_critical_failure(peer_id)?;
                        return Ok(None);
                    }
                    if !block_bodies.is_empty() {
                        // Success is recorded by the caller, once the bodies have
                        // actually been validated against their headers.
                        return Ok(Some((block_bodies, peer_id)));
                    }
                }
                // An empty response is spec-conformant for a peer that holds none of
                // the requested range (geth's `ServiceGetBlockBodiesQuery` appends only
                // what it finds), which post-history-expiry is the common case rather
                // than the adversarial one. Score it down, but keep it in the table.
                debug!(%peer_id, "No block bodies received, applying a soft penalty");
                self.peer_table.record_failure(peer_id)?;
                Ok(None)
            }
        }
    }

    /// Requests block bodies from any suitable peer given their block headers and validates them
    /// Returns the requested block bodies or None if:
    /// - There are no available peers (the node just started up or was rejected by all other nodes)
    /// - No peer returned a valid response in the given time and retry limits
    /// - The block bodies are invalid given the block headers
    pub async fn request_block_bodies(
        &mut self,
        block_headers: &[BlockHeader],
    ) -> Result<Option<Vec<BlockBody>>, PeerHandlerError> {
        let block_hashes: Vec<H256> = block_headers.iter().map(|h| h.hash()).collect();

        for _ in 0..REQUEST_RETRY_ATTEMPTS {
            let Some((block_bodies, peer_id)) =
                self.request_block_bodies_inner(&block_hashes).await?
            else {
                continue; // Retry on empty response
            };
            // Keep the longest leading run of bodies that validates against its
            // header, and stop at the first that doesn't.
            //
            // A response is not necessarily aligned with the request: a peer holding
            // only part of the range omits the hashes it lacks rather than truncating
            // (geth's `ServiceGetBlockBodiesQuery` appends only what it finds), so the
            // list can be compacted rather than a prefix. That is expected from peers
            // with partially expired history and must not be punished. A body that
            // matches *no* requested header is a different thing entirely: the peer
            // made it up, and that still earns a critical failure.
            let mut valid_upto = 0usize;
            let mut mismatch = None;
            for (idx, body) in block_bodies.iter().enumerate() {
                if let Err(err) = validate_block_body(&block_headers[idx], body, &NativeCrypto) {
                    mismatch = Some((idx, err));
                    break;
                }
                valid_upto = idx + 1;
            }

            if let Some((idx, err)) = &mismatch {
                // Does this body belong to some later header we asked for? If so the
                // response is compacted, not fabricated.
                let compacted = block_headers[idx + 1..].iter().any(|header| {
                    validate_block_body(header, &block_bodies[*idx], &NativeCrypto).is_ok()
                });
                if compacted {
                    debug!(
                        %peer_id,
                        block_number = block_headers[*idx].number,
                        bodies_kept = valid_upto,
                        "Peer skipped requested blocks it does not have; keeping the bodies verified so far"
                    );
                } else {
                    debug!(
                        %peer_id,
                        err = %err,
                        block_number = block_headers[*idx].number,
                        bodies_kept = valid_upto,
                        "Block body matches no requested header, discarding peer"
                    );
                    self.peer_table.record_critical_failure(peer_id)?;
                }
            }

            if valid_upto > 0 {
                let mut res = block_bodies;
                res.truncate(valid_upto);
                self.peer_table.record_success(peer_id)?;
                return Ok(Some(res));
            }
            // Nothing usable. A fabricated body was already charged above; anything
            // else (e.g. a peer whose whole response was for other blocks) gets a
            // soft penalty before re-rolling onto another peer.
            if mismatch.is_none() {
                self.peer_table.record_failure(peer_id)?;
            }
        }
        Ok(None)
    }

    /// Internal method to request receipts for the given block hashes from a
    /// random eth peer (any supported version; the wire form follows the
    /// version the connection negotiated).
    ///
    /// Returns the per-block receipt lists (aligned with the leading
    /// `block_hashes`) and the responding peer id, or `None` if there is no
    /// suitable peer or the response is missing/empty/oversized.
    ///
    /// The request form depends on the version the connection negotiated, because
    /// eth/70 (EIP-7975) changed the `GetReceipts` wire format to a paginated one
    /// carrying `firstBlockReceiptIndex`, and eth/71 (EIP-8159, `requires: [7928,
    /// 7975]`) builds on eth/70 rather than skipping it. Sending the eth/68 form to
    /// an eth/70+ peer would fail to decode on their side, so the version is
    /// derived from the peer's advertised capabilities.
    async fn request_receipts_inner(
        &mut self,
        block_hashes: &[H256],
    ) -> Result<Option<(Vec<Vec<Receipt>>, H256)>, PeerHandlerError> {
        let block_hashes_len = block_hashes.len();
        let request_id = rand::random();
        match self.get_random_peer(&SUPPORTED_ETH_CAPABILITIES).await? {
            None => Ok(None),
            Some((peer_id, mut connection, permit, capabilities)) => {
                // eth/70+ uses the paginated form; always start at receipt 0 of the
                // first block, since backfill wants whole blocks.
                let paginated = negotiated_eth_version(&capabilities).is_some_and(|v| v >= 70);
                let request = if paginated {
                    RLPxMessage::GetReceipts70(GetReceipts70::new(
                        request_id,
                        0,
                        block_hashes.to_vec(),
                    ))
                } else {
                    RLPxMessage::GetReceipts68(GetReceipts::new(request_id, block_hashes.to_vec()))
                };
                let response = connection
                    .outgoing_request(request, PEER_REPLY_TIMEOUT)
                    .await;
                drop(permit);
                // The peer replies with the `Receipts` variant matching its own
                // negotiated eth version; all of them decode to `Vec<Vec<Receipt>>`.
                let receipts = match response {
                    Ok(RLPxMessage::Receipts68(msg)) if msg.get_id() == request_id => msg.receipts,
                    Ok(RLPxMessage::Receipts69(msg)) if msg.get_id() == request_id => msg.receipts,
                    Ok(RLPxMessage::Receipts70(msg)) if msg.id == request_id => {
                        let mut receipts = msg.receipts;
                        // A truncated trailing list holds only part of that block's
                        // receipts, so its root can't be checked. Drop it and treat
                        // the response as a shorter prefix — the caller already
                        // handles short prefixes, so every stored block stays
                        // root-verified without a separate validation path.
                        if msg.last_block_incomplete {
                            receipts.pop();
                        }
                        receipts
                    }
                    _ => {
                        debug!("Didn't receive receipts from peer, penalizing peer {peer_id}");
                        self.peer_table.record_critical_failure(peer_id)?;
                        return Ok(None);
                    }
                };
                // An empty response is spec-conformant for a peer that holds
                // none of the requested range — the norm for old history after
                // the history-expiry rollout — so it earns only a soft penalty:
                // the peer may still be valuable for head-following. An
                // oversized response is a protocol violation and makes the peer
                // disposable.
                if receipts.is_empty() {
                    debug!("Received empty receipts from peer {peer_id}, penalizing softly");
                    self.peer_table.record_failure(peer_id)?;
                    return Ok(None);
                }
                if receipts.len() > block_hashes_len {
                    debug!("Received oversized receipts from peer {peer_id}, penalizing");
                    self.peer_table.record_critical_failure(peer_id)?;
                    return Ok(None);
                }
                // Success is recorded by the caller, once the receipts have been
                // validated against their headers' roots.
                Ok(Some((receipts, peer_id)))
            }
        }
    }

    /// Requests receipts for the given block headers from any eth peer and
    /// validates them against each header's `receipts_root`.
    ///
    /// Returns the per-block receipts (aligned with the leading `block_headers`,
    /// possibly a shorter prefix if the peer truncated the response) or `None` if
    /// no peer returned a valid, root-matching response within the retry limit.
    ///
    /// The root is recomputed from the receipts' logs, so the per-receipt bloom
    /// omitted from eth/69 onward is reconstructed as part of validation. The
    /// request form follows the peer's negotiated version (see
    /// `request_receipts_inner`).
    pub async fn request_receipts(
        &mut self,
        block_headers: &[BlockHeader],
    ) -> Result<Option<Vec<Vec<Receipt>>>, PeerHandlerError> {
        let block_hashes: Vec<H256> = block_headers.iter().map(|h| h.hash()).collect();

        for _ in 0..REQUEST_RETRY_ATTEMPTS {
            let Some((receipts, peer_id)) = self.request_receipts_inner(&block_hashes).await?
            else {
                continue; // retry on no-peer / empty response
            };
            // As with bodies, keep the longest leading run whose receipts root
            // matches its header and stop at the first that doesn't, since a peer
            // holding only part of the range answers with a compacted list rather
            // than a prefix.
            let mut verified = 0usize;
            for (header, block_receipts) in block_headers[..receipts.len()].iter().zip(&receipts) {
                let computed = compute_receipts_root(block_receipts, &NativeCrypto);
                if computed != header.receipts_root {
                    debug!(
                        "Receipts root mismatch for block {} (computed {computed:?}, expected {:?}); keeping the {verified} verified before it",
                        header.number, header.receipts_root
                    );
                    break;
                }
                verified += 1;
            }
            let mut receipts = receipts;
            receipts.truncate(verified);
            if verified > 0 {
                self.peer_table.record_success(peer_id)?;
                return Ok(Some(receipts));
            }
            // Nothing usable: penalize and re-roll onto another peer.
            self.peer_table.record_failure(peer_id)?;
        }
        Ok(None)
    }

    /// Requests block access lists from a peer that supports eth/71.
    /// Returns a vector of optional BALs (one per requested block hash) or None if:
    /// - There are no available eth/71 peers
    /// - The peer did not respond in time
    pub async fn request_block_access_lists(
        &mut self,
        block_hashes: &[H256],
    ) -> Result<Option<Vec<Option<BlockAccessList>>>, PeerHandlerError> {
        let request_id = rand::random();
        let request = RLPxMessage::GetBlockAccessLists(GetBlockAccessLists {
            id: request_id,
            block_hashes: block_hashes.to_vec(),
        });
        match self.get_random_peer(&[Capability::eth(71)]).await? {
            None => Ok(None),
            Some((peer_id, mut connection, permit, _caps)) => {
                let response = connection
                    .outgoing_request(request, PEER_REPLY_TIMEOUT)
                    .await;
                drop(permit);
                match response {
                    Ok(RLPxMessage::BlockAccessLists(BlockAccessLists {
                        id,
                        block_access_lists,
                    })) if id == request_id => {
                        self.peer_table.record_success(peer_id)?;
                        Ok(Some(block_access_lists))
                    }
                    _ => {
                        debug!("Didn't receive block access lists from peer {peer_id}");
                        self.peer_table.record_failure(peer_id)?;
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Returns diagnostic snapshots for all connected peers (scores, requests, eligibility).
    pub async fn read_peer_diagnostics(&self) -> Vec<PeerDiagnostics> {
        self.peer_table
            .get_peer_diagnostics()
            .await
            .unwrap_or_default()
    }

    /// Returns the PeerData for each connected Peer
    pub async fn read_connected_peers(&mut self) -> Vec<PeerData> {
        self.peer_table
            .get_peers_data()
            .await
            // Proper error handling
            .unwrap_or(Vec::new())
    }

    pub async fn count_total_peers(&mut self) -> Result<usize, PeerHandlerError> {
        Ok(self.peer_table.peer_count().await?)
    }

    /// Requests a single block header by number from an already-selected peer.
    /// Consumes a `RequestPermit` reserved by the caller at peer selection
    /// time; the permit drops when this function returns, releasing the slot.
    pub async fn get_block_header(
        &mut self,
        connection: &mut PeerConnection,
        _permit: RequestPermit,
        block_number: u64,
    ) -> Result<Option<BlockHeader>, PeerHandlerError> {
        let request_id = rand::random();
        let request = RLPxMessage::GetBlockHeaders(GetBlockHeaders {
            id: request_id,
            startblock: HashOrNumber::Number(block_number),
            limit: 1,
            skip: 0,
            reverse: false,
        });
        debug!("get_block_header: requesting header with number {block_number}");
        match connection
            .outgoing_request(request, PEER_REPLY_TIMEOUT)
            .await
        {
            Ok(RLPxMessage::BlockHeaders(BlockHeaders {
                id: _,
                block_headers,
            })) => {
                if !block_headers.is_empty() {
                    return Ok(Some(
                        block_headers
                            .last()
                            .ok_or(PeerHandlerError::BlockHeaders)?
                            .clone(),
                    ));
                }
            }
            Ok(_other_msgs) => {
                debug!("Received unexpected message from peer");
            }
            Err(PeerConnectionError::Timeout) => {
                debug!("Timeout while waiting for sync head from peer");
            }
            // TODO: we need to check, this seems a scenario where the peer channel does teardown
            // after we sent the backend message
            Err(_) => {
                debug!("Peer connection closed while waiting for response");
            }
        }

        Ok(None)
    }
}

/// Validates the block headers received from a peer by checking that the parent hash of each header
/// matches the hash of the previous one, i.e. the headers are chained
fn are_block_headers_chained(block_headers: &[BlockHeader], order: &BlockRequestOrder) -> bool {
    block_headers.windows(2).all(|headers| match order {
        BlockRequestOrder::OldToNew => headers[1].parent_hash == headers[0].hash(),
        BlockRequestOrder::NewToOld => headers[0].parent_hash == headers[1].hash(),
    })
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    format!("{hours:02}h {minutes:02}m {seconds:02}s")
}

#[derive(thiserror::Error, Debug)]
pub enum PeerHandlerError {
    #[error("Failed to send message to peer: {0}")]
    SendMessageToPeer(String),
    #[error("Failed to receive block headers")]
    BlockHeaders,
    #[error("Received unexpected response from peer {0}")]
    UnexpectedResponseFromPeer(H256),
    #[error("Received an empty response from peer {0}")]
    EmptyResponseFromPeer(H256),
    #[error("Failed to receive message from peer {0}")]
    ReceiveMessageFromPeer(H256),
    #[error("Timeout while waiting for message from peer {0}")]
    ReceiveMessageFromPeerTimeout(H256),
    #[error("Received invalid headers")]
    InvalidHeaders,
    #[error("Storage Full")]
    StorageFull,
    #[error("No response from peer")]
    NoResponseFromPeer,
    #[error("Error in Peer Table: {0}")]
    PeerTableError(#[from] ActorError),
    #[error("Snap error: {0}")]
    Snap(#[from] SnapError),
}

impl PeerHandlerError {
    /// Transient errors caused by individual peer interactions (bad/slow/absent
    /// responses) or actor-request timeouts that should trigger a retry.
    /// Storage/snap failures and stopped actors indicate a more fundamental
    /// problem and should be surfaced as fatal.
    pub fn is_recoverable(&self) -> bool {
        match self {
            PeerHandlerError::SendMessageToPeer(_)
            | PeerHandlerError::BlockHeaders
            | PeerHandlerError::UnexpectedResponseFromPeer(_)
            | PeerHandlerError::EmptyResponseFromPeer(_)
            | PeerHandlerError::ReceiveMessageFromPeer(_)
            | PeerHandlerError::ReceiveMessageFromPeerTimeout(_)
            | PeerHandlerError::InvalidHeaders
            | PeerHandlerError::NoResponseFromPeer => true,
            // A timed-out actor request is transient (mailbox pressure or a
            // slow handler — requests use spawned-concurrency's 5s default
            // timeout); a stopped actor means p2p is shutting down and must
            // stay fatal.
            PeerHandlerError::PeerTableError(ActorError::RequestTimeout) => true,
            PeerHandlerError::PeerTableError(ActorError::ActorStopped) => false,
            PeerHandlerError::StorageFull | PeerHandlerError::Snap(_) => false,
        }
    }
}
