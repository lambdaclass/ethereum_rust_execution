//! Full sync implementation
//!
//! This module contains the logic for full synchronization mode where all blocks
//! are fetched via p2p eth requests and executed to rebuild the state.

use std::cmp::min;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ethrex_blockchain::{BatchBlockProcessingFailure, Blockchain, error::ChainError};
use ethrex_common::{
    H256,
    types::{Block, BlockBody, BlockHeader, block_access_list::BlockAccessList},
};
use ethrex_storage::{DB_COMMIT_THRESHOLD, Store};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::peer_handler::{BlockRequestOrder, HeaderFetchOutcome, PeerHandler};
use crate::snap::constants::{
    MAX_BLOCK_BODIES_TO_REQUEST, MAX_BODY_FETCH_ATTEMPTS, MAX_HEADER_FETCH_ATTEMPTS,
};

use super::{EXECUTE_BATCH_SIZE, SyncDiagnostics, SyncError};

/// Forkchoice heads older than this (in seconds) trigger a "consensus is behind"
/// warning during sync. A synced consensus client always advertises a head only
/// a few seconds old, so a large age means the consensus client itself is lagging
/// chain head and is the sync bottleneck.
const STALE_FORKCHOICE_HEAD_SECS: u64 = 1800;

/// Distance (in blocks) below which the node is considered to be following head.
/// Below this we suppress the per-cycle sync-target logging to avoid noise on an
/// already-synced node, which runs a sync cycle on every slot.
const FOLLOW_DISTANCE: u64 = 8;

/// Render a duration in seconds as a compact human string, e.g. "13d 4h".
fn humanize_secs(secs: u64) -> String {
    if secs < 60 {
        return "< 1m".to_string();
    }
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

/// Request block bodies for `headers`, retrying with backoff when peers don't serve them.
///
/// Mirrors the header-fetch resilience loop: peers transiently failing to return bodies
/// (a `None` from `request_block_bodies`) is not a fatal condition, especially on a
/// degraded network. Returns `Ok(None)` only after all attempts are exhausted, signalling
/// the caller to stop the cycle gracefully and wait for a fresh sync head rather than
/// aborting the whole cycle with an error (which would discard the downloaded headers and
/// re-walk them from scratch on every retry).
async fn request_bodies_with_retry(
    peers: &mut PeerHandler,
    headers: &[BlockHeader],
) -> Result<Option<Vec<BlockBody>>, SyncError> {
    for attempt in 1..=MAX_BODY_FETCH_ATTEMPTS {
        if let Some(bodies) = peers.request_block_bodies(headers).await? {
            return Ok(Some(bodies));
        }
        // On the final attempt don't log "retrying" or sleep: the loop is about to give up.
        // The caller emits the "bodies unavailable after retries" message. Mirrors the
        // header-fetch loop, which checks the limit before sleeping.
        if attempt == MAX_BODY_FETCH_ATTEMPTS {
            break;
        }
        let from = headers.first().map(|h| h.number).unwrap_or_default();
        let to = headers.last().map(|h| h.number).unwrap_or_default();
        let eth_capable_peers = peers.eth_capable_peer_count().await;
        warn!(
            eth_capable_peers,
            from,
            to,
            "Failed to fetch block bodies (attempt {attempt}/{MAX_BODY_FETCH_ATTEMPTS}), retrying in 2s"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(None)
}

/// A block is a valid full-sync resume point only if it is canonical AND its post-state is
/// present on disk. Canonical-but-stateless blocks (e.g. a head canonicalized by an FCU
/// before its state was computed; see `apply_fork_choice`) are NOT resume points: building
/// on them fails forever with `state root missing`, so full sync must keep and re-execute
/// them rather than skip them as "already canonical".
pub fn is_resume_point(store: &Store, header: &BlockHeader) -> Result<bool, SyncError> {
    Ok(store.is_canonical_sync(header.hash())? && store.has_state_root(header.state_root)?)
}

/// Whether the forkchoice head is already executed locally: its header is known and its
/// post-state is on disk. When true there is nothing left for a full-sync cycle to do —
/// the block arrived through `engine_newPayload`, typically racing the FCU that triggered
/// the cycle. Post-ePBS consensus clients move their forkchoice head to a payload hash
/// learned from a bid before the payload itself is delivered to the EL, so this race is a
/// steady-state occurrence, not a corner case. Canonicality is deliberately not required:
/// right after `engine_newPayload` executes the block, the follow-up FCU that would
/// canonicalize it has not been applied yet.
pub fn sync_head_executed(store: &Store, sync_head: H256) -> Result<bool, SyncError> {
    match store.get_block_header_by_hash(sync_head)? {
        Some(header) => Ok(store.has_state_root(header.state_root)?),
        None => Ok(false),
    }
}

/// The forkchoice head's block number when it is canonical for us and at or below our own
/// head, meaning there is nothing left to sync; `None` otherwise.
///
/// A consensus client that has fallen behind its own chain keeps pointing at such a head:
/// post-ePBS it will not import a payload envelope optimistically while we answer SYNCING, so
/// its head stops advancing while ours does not.
///
/// [`sync_head_executed`] does not cover this. The state trie is a single-version path store,
/// so only the newest committed root is on disk and `has_state_root` is false for every
/// canonical block below our head, however recently it was executed. Without this check the
/// walk in [`sync_cycle_full`] starts from a head that is behind us and descends looking for a
/// stateful parent it can never find, reaches genesis, and reports the state unrecoverable —
/// escalating to a snap sync with nothing to do and leaving the node answering SYNCING forever.
///
/// Canonicality is what makes skipping the cycle safe: a reorg target is not canonical for us,
/// so it does not take this path and still syncs normally.
pub fn sync_head_not_ahead(store: &Store, sync_head: H256) -> Result<Option<u64>, SyncError> {
    let Some(header) = store.get_block_header_by_hash(sync_head)? else {
        return Ok(None);
    };
    if header.number <= store.get_latest_block_number()? && store.is_canonical_sync(sync_head)? {
        return Ok(Some(header.number));
    }
    Ok(None)
}

/// Index of the first resume point in a single newest->oldest header batch, or `None` if the
/// batch contains none. The headers before that index are the missing blocks to execute; the
/// header at that index is our executed/state head. State is retained only for a recent window
/// down from the executed head (the layered store prunes older layers), so scanning newest->oldest
/// the first canonical+stateful header is exactly that head — the stateless prefix above it is the
/// not-yet-executed blocks, and everything below it within the retained window is also stateful.
///
/// Scanning the batch *interior* — rather than only checking the parent of the batch's oldest
/// header — is what stops the walk-back overshooting its own stateful head down to genesis when
/// that head sits in the middle of a batch (the batch's oldest block can be a canonical-but-
/// pruned block below the retained-state window, which is not a resume point).
///
/// Gated to batches whose oldest block is at/below `local_head`: a batch entirely above our head
/// is all unexecuted and cannot contain a resume point, so the per-header state lookups are
/// skipped for it, keeping the deep-sync walk cheap.
///
/// Cost: up to O(N) `has_state_root` probes for a batch of length N (256-1024 in production), but
/// typically 2-5 — the scan terminates at the state head, which sits at or just below the
/// not-yet-executed prefix. The pathological full-batch walk only happens when the state head is
/// far below the batch's newest header (a long canonical-but-stateless gap from an FCU-ahead-of-
/// execution window); each probe is a single MPT root lookup.
pub fn first_resume_point_in_batch(
    store: &Store,
    block_headers: &[BlockHeader],
    local_head: u64,
) -> Result<Option<usize>, SyncError> {
    let Some(oldest) = block_headers.last() else {
        return Ok(None);
    };
    if oldest.number > local_head {
        return Ok(None);
    }
    for (index, header) in block_headers.iter().enumerate() {
        if is_resume_point(store, header)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Performs full sync cycle - fetches and executes all blocks between current head and sync head
///
/// # Returns
///
/// Returns an error if the sync fails at any given step and aborts all active processes
pub async fn sync_cycle_full(
    peers: &mut PeerHandler,
    blockchain: Arc<Blockchain>,
    cancel_token: CancellationToken,
    mut sync_head: H256,
    store: Store,
    diagnostics: &Arc<RwLock<SyncDiagnostics>>,
) -> Result<(), SyncError> {
    let local_head = store.get_latest_block_number()?;
    let eth_capable_peers = peers.eth_capable_peer_count().await;
    info!(
        local_head,
        eth_capable_peers,
        ?sync_head,
        "Starting full sync cycle"
    );

    // The forkchoice head this cycle was started for. `sync_head` itself is rebound as the
    // cycle walks back through pending blocks and header batches, so keep the original for
    // the executed-locally checks below.
    let fcu_head_hash = sync_head;
    // The head may have been executed between the FCU that triggered this cycle and now
    // (`engine_newPayload` racing the FCU). If so the cycle has nothing to do.
    if sync_head_executed(&store, fcu_head_hash)? {
        info!(
            ?fcu_head_hash,
            "Sync head already executed locally; nothing to sync"
        );
        return Ok(());
    }

    // The forkchoice head can also be a block we already have on our canonical chain, at or
    // below our own head. A consensus client that has fallen behind its own chain keeps
    // pointing at such a head: post-ePBS it will not import a payload envelope optimistically
    // while we answer SYNCING, so its head stops advancing while ours does not.
    //
    // `sync_head_executed` above does not catch this. The state trie is a single-version path
    // store, so only the newest committed root is on disk: `has_state_root` is false for every
    // canonical block below our head, however recently it was executed. The walk below would
    // then start from a head that is *behind* us and descend looking for a stateful parent it
    // can never find, reach genesis, and report the state unrecoverable — which escalates to a
    // snap sync that has nothing to do, and leaves the node stuck answering SYNCING forever.
    //
    // Canonicality is what makes this safe: a reorg target is not canonical for us, so it does
    // not take this path and still syncs normally.
    if let Some(sync_head_number) = sync_head_not_ahead(&store, fcu_head_hash)? {
        info!(
            ?fcu_head_hash,
            sync_head_number,
            local_head,
            "Sync head is canonical at or below our head; nothing to sync"
        );
        return Ok(());
    }

    // Check if the sync_head is a pending block, if so, gather all pending blocks belonging to its chain
    let mut pending_blocks = vec![];
    while let Some(block) = store.get_pending_block(sync_head).await? {
        if store.is_canonical_sync(block.hash())? {
            // Ignore canonical blocks still in pending
            break;
        }
        sync_head = block.header.parent_hash;
        pending_blocks.insert(0, block);
    }

    // If the gap to the forkchoice head is entirely covered by pending blocks (delivered
    // via engine_newPayload), the rewound sync_head is already on our canonical chain with
    // its post-state on disk: no peer data is needed. Skip the header/body download and
    // execute the pending blocks directly. Without this, a node that receives every block
    // through newPayload stalls behind head whenever peers don't serve headers: the
    // header-fetch abort below returns without executing `pending_blocks`, each retry runs
    // against a head that has moved further ahead, and the node trails the chain
    // indefinitely, never reporting synced and answering every newPayload with SYNCING.
    if !pending_blocks.is_empty() && store.is_canonical_sync(sync_head)? {
        let parent_has_state = match store.get_block_header_by_hash(sync_head)? {
            Some(parent) => store.has_state_root(parent.state_root)?,
            None => false,
        };
        if parent_has_state {
            info!(
                "Executing {} pending blocks for full sync (gap fully covered by blocks from the consensus client, no peer download needed). First block hash: {:#?} Last block hash: {:#?}",
                pending_blocks.len(),
                pending_blocks.first().ok_or(SyncError::NoBlocks)?.hash(),
                pending_blocks.last().ok_or(SyncError::NoBlocks)?.hash()
            );
            add_blocks_in_batch(
                blockchain.clone(),
                cancel_token.clone(),
                pending_blocks,
                true,
                store.clone(),
                peers,
            )
            .await?;
            store.clear_fullsync_headers().await?;
            return Ok(());
        }
    }

    // The consensus-provided forkchoice head, captured before `sync_head` is rewound
    // over the pending blocks above. Used for sync-target diagnostics so we report the
    // actual head rather than the rewound ancestor we end up requesting headers from.
    let fcu_head = pending_blocks
        .last()
        .map(|block| (block.header.number, block.header.timestamp));

    // Request all block headers between the sync head and our local chain
    // We will begin from the sync head so that we download the latest state first, ensuring we follow the correct chain
    // This step is not parallelized
    let mut start_block_number;
    let mut end_block_number = 0;
    let mut headers = vec![];
    let mut single_batch = true;

    let mut attempts = 0;

    // Tracks whether this cycle started meaningfully behind the consensus-provided
    // head, so we can log progress and a final "caught up" message without spamming
    // a synced node. Set on the first batch of headers we fetch.
    let mut started_behind = false;
    let mut sync_target_logged = false;

    // Request and store all block headers from the advertised sync head
    loop {
        // Re-check between peer round-trips: when the FCU raced its payload's
        // `engine_newPayload`, peers may not have the block either (the payload has not
        // propagated anywhere yet), and the head routinely arrives through newPayload
        // while this loop retries. Stop instead of re-downloading and re-executing what
        // the engine already applied.
        if sync_head_executed(&store, fcu_head_hash)? {
            info!(
                ?fcu_head_hash,
                "Sync head executed via engine_newPayload during header fetch; ending sync cycle"
            );
            return Ok(());
        }
        let outcome = peers
            .request_block_headers_from_hash(sync_head, BlockRequestOrder::NewToOld)
            .await?;
        let mut block_headers = match outcome {
            HeaderFetchOutcome::Headers(headers) => headers,
            // No headers this round: `reason` (from `HeaderFetchOutcome::failure_reason`) says
            // whether we couldn't find a peer to query or a peer was queried but didn't serve, so
            // operators can tell connectivity apart from peers withholding data.
            other => {
                let reason = other.failure_reason();
                let eth_capable_peers = peers.eth_capable_peer_count().await;
                if attempts >= MAX_HEADER_FETCH_ATTEMPTS {
                    warn!(
                        eth_capable_peers,
                        reason,
                        ?sync_head,
                        "Sync failed to find target block header after {attempts} attempts, aborting to wait for a newer sync head"
                    );
                    return Ok(());
                }
                attempts += 1;
                warn!(
                    eth_capable_peers,
                    reason,
                    "Failed to fetch headers for sync head (attempt {attempts}/{MAX_HEADER_FETCH_ATTEMPTS}), retrying in 2s"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        debug!("Sync Log 9: Received {} block headers", block_headers.len());
        // Reset failure counter on success so it tracks consecutive failures
        attempts = 0;

        let first_header = block_headers.first().ok_or(SyncError::NoBlocks)?;
        let last_header = block_headers.last().ok_or(SyncError::NoBlocks)?;

        debug!(
            "Received {} block headers | First Number: {} Last Number: {}",
            block_headers.len(),
            first_header.number,
            last_header.number,
        );

        // On the first batch, report the distance to the consensus-provided head and
        // warn if that head is stale (a strong signal the consensus client is behind).
        if !sync_target_logged {
            sync_target_logged = true;
            let (target, target_ts) =
                fcu_head.unwrap_or((first_header.number, first_header.timestamp));
            let local_head = store.get_latest_block_number()?;
            let behind = target.saturating_sub(local_head);
            if behind > FOLLOW_DISTANCE {
                started_behind = true;
                info!(
                    "Sync target from consensus forkchoice: block {target} ({behind} blocks ahead of local head {local_head})"
                );
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age = now.saturating_sub(target_ts);
                if age > STALE_FORKCHOICE_HEAD_SECS {
                    warn!(
                        "Consensus forkchoice head (block {target}) is {} old. This can happen while the consensus client is still catching up to chain head; \
                         if so, execution will only advance as fast as it does. If sync seems slow, it may be worth checking the consensus client's sync status.",
                        humanize_secs(age)
                    );
                }
            }
        }

        end_block_number = end_block_number.max(first_header.number);
        // This batch's newest block number, captured before `block_headers` is drained.
        // `start_block_number` is finalized in the break branch below.
        let batch_newest_number = first_header.number;

        sync_head = last_header.parent_hash;
        // We can only resume execution from a block whose post-state is actually on disk.
        // `is_canonical_sync` alone is insufficient: an FCU can canonicalize a head before
        // its state is computed (`apply_fork_choice` gates only on the branch link block),
        // so the canonical chain can extend past the executed-state head. Anchoring on such
        // a canonical-but-stateless block makes execution fail forever with `state root
        // missing`. A block is a valid resume point only if it is canonical AND stateful;
        // canonical-but-stateless blocks are kept and re-executed to backfill their state.
        let parent_is_resume_point = match store.get_block_header_by_hash(sync_head)? {
            Some(parent) => is_resume_point(&store, &parent)?,
            None => false,
        };
        // The batch may itself straddle our executed/state head — the walk has reached down
        // into the region we have state for. Checking only `parent_is_resume_point` (the parent
        // of the batch's OLDEST header) misses this: when our stateful head sits in the MIDDLE of
        // a batch the parent check is false, so the walk blew past our own local head and kept
        // descending all the way to genesis (the issue #9 overshoot). Scan the batch interior too.
        let batch_resume_index = first_resume_point_in_batch(&store, &block_headers, local_head)?;
        if parent_is_resume_point || batch_resume_index.is_some() || sync_head.is_zero() {
            // Incoming chain merged with our executed state.
            // Drop only the already-executed (canonical + stateful) prefix; keep any
            // canonical-but-stateless blocks so they get re-executed. State is retained for a
            // recent window down from the executed head, so the first canonical+stateful header
            // scanning newest->oldest is exactly that state head.
            let first_skippable = batch_resume_index.unwrap_or(block_headers.len());
            block_headers.drain(first_skippable..block_headers.len());
            match block_headers.last() {
                Some(last_header) => start_block_number = last_header.number,
                // Whole batch was already executed; the blocks we keep (if any) live in
                // newer, already-stored batches that start one above this batch's newest.
                None => start_block_number = batch_newest_number.saturating_add(1),
            }
            // Guard against resuming onto a base whose post-state is gone. Execution begins at
            // `start_block_number`, whose parent (`start_block_number - 1`) must have its post-state
            // on disk. That holds when we broke on a stateful resume point (the normal catch-up and
            // the FCU-ahead backfill cases, where the parent is the executed/state head). It does NOT
            // hold when the walk bottomed out at genesis (`sync_head.is_zero()`) after reconciling the
            // consensus sync head only to a canonical block whose state was already pruned: the layered
            // store keeps state for a recent window and drops genesis-era layers as the head advances
            // (see `TrieLayerCache`), so a fork/deep-reorg head that diverges below that window has no
            // stateful resume point and the walk descends to block 0. Re-executing from such a pruned
            // base fails forever with `state root missing for block {parent}`. Detect it and pause the
            // cycle gracefully (Ok) — mirroring the body-fetch exhaustion path — until a forkchoice head
            // reconciles to a block whose state we still retain. (Pre-#6803 the walk anchored on the
            // pruned canonical block and failed at block N; the stateful-resume-point gate now walks
            // past it to genesis, so this guard is required to avoid a doomed re-exec from block 0.)
            let resume_parent_number = start_block_number.saturating_sub(1);
            let resume_parent_has_state = match store.get_block_header(resume_parent_number)? {
                Some(parent) => store.has_state_root(parent.state_root)?,
                None => false,
            };
            if !resume_parent_has_state {
                let local_head = store.get_latest_block_number()?;
                warn!(
                    resume_parent_number,
                    local_head,
                    "Full sync cannot resume: post-state for block {resume_parent_number} is absent \
                     (pruned from the layered store, or never executed). The consensus sync head does \
                     not reconcile to a block whose state we retain, so there is nothing to execute \
                     on top of; handing over to snap sync to rebuild state from a recent pivot."
                );
                store.clear_fullsync_headers().await?;
                // Returning Ok here would pause the cycle and wait for a forkchoice head that
                // reconciles to state we retain. When the walk has already bottomed out at
                // genesis no such head exists — the state is gone, not merely unreferenced —
                // so the wait never ends and the node stops following the chain entirely.
                // Report it so the caller can escalate to snap sync.
                return Err(SyncError::StateUnrecoverable);
            }
            // If we are resuming at or below the canonical head, the canonical chain extends
            // past the executed-state head: an FCU canonicalized blocks before their state
            // was computed. Surface it explicitly; these canonical-but-stateless blocks are
            // re-executed below, and the warning flags the underlying gap for investigation.
            let canonical_head = store.get_latest_block_number()?;
            // `start_block_number - 1` is the highest block whose post-state is on
            // disk (the executed/state head). Record it so `eth_syncing` reports real
            // progress instead of the canonical pointer, which an FCU may have advanced
            // past the executed state.
            let state_head = start_block_number.saturating_sub(1);
            diagnostics.write().await.executed_head = state_head;
            if start_block_number <= canonical_head {
                warn!(
                    state_head,
                    canonical_head,
                    gap = canonical_head
                        .saturating_add(1)
                        .saturating_sub(start_block_number),
                    "Full sync resuming below canonical head: re-executing canonical-but-stateless blocks (FCU canonicalized past executed state)"
                );
            }
            // If the fullsync consists of a single batch of headers we can just keep them in memory instead of writing them to Store
            if single_batch {
                headers = block_headers.into_iter().rev().collect();
            } else {
                store.add_fullsync_batch(block_headers).await?;
            }
            break;
        }
        store.add_fullsync_batch(block_headers).await?;
        single_batch = false;
    }
    // Last chance before paying for body downloads and execution: the head having
    // post-state means the whole chain below it is executed too, so the work this
    // cycle was about to do already happened through the engine.
    if sync_head_executed(&store, fcu_head_hash)? {
        info!(
            ?fcu_head_hash,
            "Sync head executed via engine_newPayload during header fetch; ending sync cycle"
        );
        return Ok(());
    }
    end_block_number += 1;
    start_block_number = start_block_number.max(1);

    // Pipeline: download block bodies in a background task while the main loop executes.
    // This overlaps network I/O with block execution for better throughput.
    let (body_tx, mut body_rx) =
        tokio::sync::mpsc::channel::<Result<(Vec<Block>, bool), SyncError>>(2);

    // Clone resources for the background download task
    let mut download_peers = peers.clone();
    let download_store = store.clone();

    let download_task = tokio::spawn(async move {
        // If single_batch, we already have headers in memory — send them as the one and only batch.
        if single_batch {
            let final_batch = true;
            let mut batch_headers = headers;
            let mut blocks = Vec::new();
            while !batch_headers.is_empty() {
                let end = min(MAX_BLOCK_BODIES_TO_REQUEST, batch_headers.len());
                let header_batch = &batch_headers[..end];
                match request_bodies_with_retry(&mut download_peers, header_batch).await {
                    Ok(Some(bodies)) => {
                        debug!("Obtained: {} block bodies", bodies.len());
                        let block_batch = batch_headers
                            .drain(..bodies.len())
                            .zip(bodies)
                            .map(|(header, body)| Block { header, body });
                        blocks.extend(block_batch);
                    }
                    Ok(None) => {
                        // Bodies unavailable after retries: stop gracefully (drop the sender)
                        // so the executor finishes what it has and the cycle ends without an
                        // error. The next forkchoice head will trigger a fresh attempt.
                        let eth_capable_peers = download_peers.eth_capable_peer_count().await;
                        warn!(
                            eth_capable_peers,
                            "Block bodies unavailable from peers after retries; pausing full sync until a new forkchoice head arrives"
                        );
                        return;
                    }
                    Err(e) => {
                        let _ = body_tx.send(Err(e)).await;
                        return;
                    }
                }
            }
            if !blocks.is_empty() {
                let _ = body_tx.send(Ok((blocks, final_batch))).await;
            }
            return;
        }

        // Multi-batch path: iterate through all batches, download bodies, and send them.
        for start in (start_block_number..end_block_number).step_by(*EXECUTE_BATCH_SIZE) {
            let batch_size = EXECUTE_BATCH_SIZE.min((end_block_number - start) as usize);
            let final_batch = end_block_number == start + batch_size as u64;

            let batch_headers = match download_store
                .read_fullsync_batch(start, batch_size as u64)
                .await
            {
                Ok(h) => h,
                Err(e) => {
                    let _ = body_tx.send(Err(e.into())).await;
                    return;
                }
            };
            let mut batch_headers: Vec<_> = match batch_headers
                .into_iter()
                .map(|opt| opt.ok_or(SyncError::MissingFullsyncBatch))
                .collect()
            {
                Ok(h) => h,
                Err(e) => {
                    let _ = body_tx.send(Err(e)).await;
                    return;
                }
            };

            let mut blocks = Vec::new();
            while !batch_headers.is_empty() {
                let end = min(MAX_BLOCK_BODIES_TO_REQUEST, batch_headers.len());
                let header_batch = &batch_headers[..end];
                match request_bodies_with_retry(&mut download_peers, header_batch).await {
                    Ok(Some(bodies)) => {
                        debug!("Obtained: {} block bodies", bodies.len());
                        let block_batch = batch_headers
                            .drain(..bodies.len())
                            .zip(bodies)
                            .map(|(header, body)| Block { header, body });
                        blocks.extend(block_batch);
                    }
                    Ok(None) => {
                        // Bodies unavailable after retries: stop gracefully (drop the sender)
                        // so the executor finishes what it has and the cycle ends without an
                        // error. The next forkchoice head will trigger a fresh attempt.
                        let eth_capable_peers = download_peers.eth_capable_peer_count().await;
                        warn!(
                            eth_capable_peers,
                            "Block bodies unavailable from peers after retries; pausing full sync until a new forkchoice head arrives"
                        );
                        return;
                    }
                    Err(e) => {
                        let _ = body_tx.send(Err(e)).await;
                        return;
                    }
                }
            }
            if !blocks.is_empty() && body_tx.send(Ok((blocks, final_batch))).await.is_err() {
                // Receiver dropped (execution loop stopped), stop downloading
                return;
            }
        }
    });

    // Main loop: receive downloaded batches and execute them. `reached_target` records
    // whether we executed the final batch; if body downloads gave up early (the task
    // returns without sending the final batch), it stays false so we don't falsely report
    // catching up to the consensus head below.
    let mut reached_target = false;
    while let Some(result) = body_rx.recv().await {
        let (blocks, final_batch) = result?;
        debug!(
            "Executing {} blocks for full sync. First block hash: {:#?} Last block hash: {:#?}",
            blocks.len(),
            blocks.first().ok_or(SyncError::NoBlocks)?.hash(),
            blocks.last().ok_or(SyncError::NoBlocks)?.hash()
        );
        add_blocks_in_batch(
            blockchain.clone(),
            cancel_token.clone(),
            blocks,
            final_batch,
            store.clone(),
            peers,
        )
        .await?;
        if final_batch {
            reached_target = true;
        }
    }

    // Ensure the download task completes and propagate any panics
    download_task.await?;

    // Execute pending blocks, but only if the downloaded chain they build on was fully
    // executed first. The oldest pending block's parent is the rewound `sync_head`, i.e. the
    // newest downloaded header; if body downloads gave up early its post-state is absent and
    // executing the pending blocks would fail with `state root missing`. Gate on actual state
    // presence rather than `reached_target`: the common follow-head case has no gap to download
    // (nothing is sent, so `reached_target` stays false) yet the parent state is already on disk.
    if let Some(oldest_pending) = pending_blocks.first() {
        let parent_has_state =
            match store.get_block_header_by_hash(oldest_pending.header.parent_hash)? {
                Some(parent) => store.has_state_root(parent.state_root)?,
                None => false,
            };
        if !parent_has_state {
            let local_head = store.get_latest_block_number()?;
            warn!(
                local_head,
                "Skipping {} pending block(s): the downloaded chain they build on was not fully executed (parent state absent); will retry on the next forkchoice update",
                pending_blocks.len()
            );
        } else {
            info!(
                "Executing {} blocks for full sync. First block hash: {:#?} Last block hash: {:#?}",
                pending_blocks.len(),
                pending_blocks.first().ok_or(SyncError::NoBlocks)?.hash(),
                pending_blocks.last().ok_or(SyncError::NoBlocks)?.hash()
            );
            add_blocks_in_batch(
                blockchain.clone(),
                cancel_token.clone(),
                pending_blocks,
                true,
                store.clone(),
                peers,
            )
            .await?;
            reached_target = true;
        }
    }

    // If this cycle started behind, report the outcome so the operator can tell idle-waiting
    // from a hang. Only claim we caught up if we actually executed through to the target;
    // if body downloads gave up early we say so instead of falsely reporting success.
    if started_behind {
        let local_head = store.get_latest_block_number()?;
        if reached_target {
            info!(
                "Reached consensus-provided head at block {local_head}. Waiting for the next forkchoice update from the consensus client."
            );
        } else {
            warn!(
                local_head,
                "Full sync paused before reaching the consensus-provided head (data unavailable from peers); will resume on the next forkchoice update"
            );
        }
    }

    store.clear_fullsync_headers().await?;
    Ok(())
}

async fn add_blocks_in_batch(
    blockchain: Arc<Blockchain>,
    cancel_token: CancellationToken,
    blocks: Vec<Block>,
    final_batch: bool,
    store: Store,
    peers: &mut PeerHandler,
) -> Result<(), SyncError> {
    let execution_start = Instant::now();
    // Copy some values for later
    let blocks_len = blocks.len();
    let numbers_and_hashes = blocks
        .iter()
        .map(|b| (b.header.number, b.hash()))
        .collect::<Vec<_>>();
    let (last_block_number, last_block_hash) = numbers_and_hashes
        .last()
        .cloned()
        .ok_or(SyncError::InvalidRangeReceived)?;
    let (first_block_number, first_block_hash) = numbers_and_hashes
        .first()
        .cloned()
        .ok_or(SyncError::InvalidRangeReceived)?;

    let blocks_hashes = blocks.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let chain_config = store.get_chain_config();
    let bals: Vec<Option<BlockAccessList>> = {
        // Fetch BALs for every Amsterdam batch (not just the final one): both the
        // batch path and `run_blocks_pipeline` now persist them, so peers can serve
        // these blocks over eth/71 later without regenerating against pruned state.
        let any_amsterdam = blocks
            .iter()
            .any(|b| chain_config.is_amsterdam_activated(b.header.timestamp));
        if any_amsterdam {
            match peers.request_block_access_lists(&blocks_hashes).await {
                Ok(Some(bals)) if bals.len() == blocks.len() => bals,
                _ => {
                    debug!("BAL fetch unavailable or failed, proceeding without BALs");
                    vec![None; blocks.len()]
                }
            }
        } else {
            vec![None; blocks.len()]
        }
    };
    // Run the batch
    if let Err((err, batch_failure)) =
        add_blocks(blockchain.clone(), blocks, bals, final_batch, cancel_token).await
    {
        if let Some(batch_failure) = batch_failure {
            warn!("Failed to add block during FullSync: {err}");
            // Since running the batch failed we set the failing block and its descendants
            // with having an invalid ancestor on the following cases.
            if let ChainError::InvalidBlock(_) = err {
                let mut block_hashes_with_invalid_ancestor: Vec<H256> = vec![];
                if let Some(index) = blocks_hashes
                    .iter()
                    .position(|x| x == &batch_failure.failed_block_hash)
                {
                    block_hashes_with_invalid_ancestor = blocks_hashes[index..].to_vec();
                }

                for hash in block_hashes_with_invalid_ancestor {
                    store
                        .set_latest_valid_ancestor(hash, batch_failure.last_valid_hash)
                        .await?;
                }
            }
        }
        return Err(err.into());
    }

    store
        .forkchoice_update(
            numbers_and_hashes,
            last_block_number,
            last_block_hash,
            None,
            None,
        )
        .await?;

    let execution_time: f64 = execution_start.elapsed().as_millis() as f64 / 1000.0;
    let blocks_per_second = blocks_len as f64 / execution_time;

    info!(
        "Executed and stored {} blocks in {:.3} seconds ({:.3} blocks/s). First block: {} ({}). Last block: {} ({}).",
        blocks_len,
        execution_time,
        blocks_per_second,
        first_block_number,
        first_block_hash,
        last_block_number,
        last_block_hash
    );
    Ok(())
}

/// Executes the given blocks and stores them.
///
/// Both paths execute block-by-block through the same validated pipeline
/// (`add_block_pipeline_bounded`), which builds fresh per-block VM state. When the sync
/// head is found the blocks run sequentially on a blocking thread; otherwise
/// `add_blocks_in_batch` runs them with BAL fetching, progress logging and cancellation.
async fn add_blocks(
    blockchain: Arc<Blockchain>,
    blocks: Vec<Block>,
    bals: Vec<Option<BlockAccessList>>,
    sync_head_found: bool,
    cancel_token: CancellationToken,
) -> Result<(), (ChainError, Option<BatchBlockProcessingFailure>)> {
    if sync_head_found {
        return run_blocks_pipeline(blockchain, blocks, bals).await;
    }
    blockchain
        .add_blocks_in_batch(blocks, &bals, cancel_token)
        .await
}

async fn run_blocks_pipeline(
    blockchain: Arc<Blockchain>,
    blocks: Vec<Block>,
    bals: Vec<Option<BlockAccessList>>,
) -> Result<(), (ChainError, Option<BatchBlockProcessingFailure>)> {
    tokio::task::spawn_blocking(move || {
        let mut last_valid_hash = H256::default();
        for (block, bal) in blocks.into_iter().zip(bals.into_iter()) {
            let block_hash = block.hash();
            blockchain
                .add_block_pipeline_bounded(block, bal.map(Arc::new), DB_COMMIT_THRESHOLD)
                .map(|_| ())
                .map_err(|e| {
                    (
                        e,
                        Some(BatchBlockProcessingFailure {
                            last_valid_hash,
                            failed_block_hash: block_hash,
                        }),
                    )
                })?;
            last_valid_hash = block_hash;
        }
        Ok(())
    })
    .await
    .map_err(|e| (ChainError::Custom(e.to_string()), None))?
}

#[cfg(test)]
mod sync_head_not_ahead_tests {
    use super::*;
    use ethrex_storage::EngineType;

    /// Canonical headers `0..=head`, with `head` as the canonical head. Bodies and state are
    /// irrelevant here: the predicate reads only the header, the canonical mapping and the
    /// latest block number.
    async fn store_with_canonical_chain(head: u64) -> (Store, Vec<BlockHeader>) {
        let store = Store::new("", EngineType::InMemory).expect("in-memory store");
        let headers: Vec<BlockHeader> = (0..=head)
            .map(|number| BlockHeader {
                number,
                ..Default::default()
            })
            .collect();
        store.add_block_headers(headers.clone()).await.unwrap();
        let canonical: Vec<_> = headers.iter().map(|h| (h.number, h.hash())).collect();
        store
            .forkchoice_update(canonical, head, headers[head as usize].hash(), None, None)
            .await
            .unwrap();
        (store, headers)
    }

    /// The case that deadlocked a node: the consensus client stopped advancing and keeps
    /// pointing at a canonical block below our head. Without this the cycle walks to genesis
    /// and reports the state unrecoverable.
    #[tokio::test]
    async fn reports_a_canonical_head_below_ours() {
        let (store, headers) = store_with_canonical_chain(20).await;
        let behind = headers[12].hash();
        assert_eq!(sync_head_not_ahead(&store, behind).unwrap(), Some(12));
    }

    /// Equal heads are also nothing to sync: we already have that block canonically.
    #[tokio::test]
    async fn reports_a_canonical_head_equal_to_ours() {
        let (store, headers) = store_with_canonical_chain(20).await;
        let same = headers[20].hash();
        assert_eq!(sync_head_not_ahead(&store, same).unwrap(), Some(20));
    }

    /// A head we have a header for but which is not on our canonical chain is a reorg target:
    /// it must still sync, however low its number.
    #[tokio::test]
    async fn ignores_a_known_but_non_canonical_head() {
        let (store, headers) = store_with_canonical_chain(20).await;
        let sibling = BlockHeader {
            number: 12,
            gas_limit: 1234, // diverge from the canonical header at the same height
            ..Default::default()
        };
        store
            .add_block_header(sibling.hash(), sibling.clone())
            .await
            .unwrap();
        assert_ne!(sibling.hash(), headers[12].hash());
        assert_eq!(sync_head_not_ahead(&store, sibling.hash()).unwrap(), None);
    }

    /// The ordinary case: the consensus client is ahead, so the cycle must run.
    #[tokio::test]
    async fn ignores_a_head_above_ours() {
        let (store, _) = store_with_canonical_chain(20).await;
        let ahead = BlockHeader {
            number: 25,
            ..Default::default()
        };
        store
            .add_block_header(ahead.hash(), ahead.clone())
            .await
            .unwrap();
        assert_eq!(sync_head_not_ahead(&store, ahead.hash()).unwrap(), None);
    }

    /// A head we have never seen is the normal deep-sync case.
    #[tokio::test]
    async fn ignores_an_unknown_head() {
        let (store, _) = store_with_canonical_chain(20).await;
        assert_eq!(
            sync_head_not_ahead(&store, H256::repeat_byte(0xab)).unwrap(),
            None
        );
    }
}
