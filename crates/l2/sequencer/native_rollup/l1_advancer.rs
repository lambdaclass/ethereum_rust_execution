//! NativeL1Advancer GenServer — reads produced L2 blocks from the Store,
//! generates an execution witness, and submits them to the NativeRollup.sol
//! contract via advance(uint16 l1MessagesCount, bytes sszStatelessInput).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ethrex_blockchain::Blockchain;
use ethrex_common::types::{Block, BlockHeader, TxType};
use ethrex_common::{Address, H256, U256};
use ethrex_crypto::NativeCrypto;
use ethrex_l2_common::calldata::Value;
use ethrex_l2_rpc::signer::Signer;
use ethrex_l2_sdk::{
    build_generic_tx, calldata::encode_calldata, get_native_rollup_block_number,
    send_tx_bump_gas_exponential_backoff,
};
use ethrex_rpc::clients::Overrides;
use ethrex_rpc::clients::eth::EthClient;
use ethrex_storage::Store;
use spawned_concurrency::{
    actor,
    error::ActorError,
    protocol,
    tasks::{Actor, ActorRef, ActorStart as _, Context, Handler, send_after},
};
use tracing::{debug, error, info};

const ADVANCE_FUNCTION_SIGNATURE: &str = "advance(uint16,bytes)";

#[protocol]
pub trait NativeL1AdvancerProtocol: Send + Sync {
    fn advance(&self) -> Result<(), ActorError>;
}

#[derive(Debug, thiserror::Error)]
pub enum NativeL1AdvancerError {
    #[error("EthClient error: {0}")]
    EthClient(#[from] ethrex_rpc::clients::eth::errors::EthClientError),
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Internal error: {0}")]
    Internal(#[from] spawned_concurrency::error::ActorError),
    #[error("Signer error: {0}")]
    Signer(String),
    #[error("Store error: {0}")]
    Store(#[from] ethrex_storage::error::StoreError),
    #[error("Chain error: {0}")]
    Chain(#[from] ethrex_blockchain::error::ChainError),
    #[error("advance() reverted on L1: {0}")]
    RevertedAdvance(String),
}

pub struct NativeL1Advancer {
    eth_client: EthClient,
    contract_address: Address,
    signer: Signer,
    store: Store,
    blockchain: Arc<Blockchain>,
    relayer_address: Address,
    advance_interval_ms: u64,
}

impl NativeL1Advancer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        eth_client: EthClient,
        contract_address: Address,
        signer: Signer,
        store: Store,
        blockchain: Arc<Blockchain>,
        relayer_address: Address,
        advance_interval_ms: u64,
    ) -> Self {
        Self {
            eth_client,
            contract_address,
            signer,
            store,
            blockchain,
            relayer_address,
            advance_interval_ms,
        }
    }

    /// Determine the next block to advance and submit it to L1.
    async fn advance_next_block(&mut self) -> Result<(), NativeL1AdvancerError> {
        // 1. Query the on-chain block number from NativeRollup.sol
        let on_chain_block_number =
            get_native_rollup_block_number(&self.eth_client, self.contract_address).await?;

        let next_block = on_chain_block_number + 1;

        // 2. Fetch block from Store
        let block_header = match self.store.get_block_header(next_block)? {
            Some(h) => h,
            None => {
                debug!(
                    "NativeL1Advancer: block {} not produced yet, skipping",
                    next_block
                );
                return Ok(());
            }
        };

        let block_body = match self.store.get_block_body(next_block).await? {
            Some(b) => b,
            None => {
                debug!(
                    "NativeL1Advancer: block {} body not found, skipping",
                    next_block
                );
                return Ok(());
            }
        };

        let block = Block {
            header: block_header.clone(),
            body: block_body.clone(),
        };

        // 3. Re-execute the block to produce the execution witness and BAL.
        //    Native blocks are persisted via store_block, which does not write
        //    the witness cache (only add_block_pipeline_inner / store_witness
        //    does). The cache is therefore never populated on this path, so
        //    the witness is always generated on demand here.
        //    The parent_beacon_block_root carries the L1 messages Merkle root.
        //    The EIP-4788 system contract writes it during block processing,
        //    so the witness must include the beacon roots contract state.
        //    Amsterdam+ blocks also return a BAL alongside the witness.
        // BlockchainType::L1 — None is correct for fee_configs.
        let (witness, bals) = self
            .blockchain
            .generate_witness_and_bal_for_blocks_with_fee_configs(&[block], None)
            .await?;
        let (witness, bal): (
            ethrex_common::types::block_execution_witness::ExecutionWitness,
            Option<ethrex_common::types::block_access_list::BlockAccessList>,
        ) = (witness, bals.into_iter().next().flatten());

        // 4. Count L1 messages by counting relayer txs.
        let l1_messages_count: u16 = block_body
            .transactions
            .iter()
            .filter(|tx| tx.sender(&NativeCrypto).ok() == Some(self.relayer_address))
            .count()
            .try_into()
            .map_err(|_| {
                NativeL1AdvancerError::Encoding("l1 messages count exceeds u16::MAX".into())
            })?;

        // 5. Build SSZ StatelessInput
        let ssz_input =
            build_ssz_stateless_input(&block_header, &block_body, &witness, bal.as_ref())
                .map_err(|e| NativeL1AdvancerError::Encoding(format!("SSZ encoding: {e}")))?;

        // 6. Send advance() tx (gas driven by the L2 block's gas limit — see send_advance)
        let tx_hash = self
            .send_advance(&ssz_input, l1_messages_count, block_header.gas_limit)
            .await?;

        info!(
            "NativeL1Advancer: advanced block {} on L1 (state_root={:?}, l1_msgs={}, tx={:?})",
            next_block, block_header.state_root, l1_messages_count, tx_hash
        );

        Ok(())
    }

    /// Build and send the advance() transaction to NativeRollup.sol.
    ///
    /// `l2_block_gas_limit` is the gas limit of the L2 block being settled. It
    /// drives the tx gas limit: advance() STATICCALLs the EXECUTE precompile,
    /// which charges `l2_block_gas_limit + calldata*16` up front to re-execute
    /// the whole L2 block. Because of the 63/64 call-gas rule plus advance()'s
    /// own overhead, the tx must carry well more than that, and gas *estimation*
    /// underestimates it (the precompile's up-front charge isn't modeled), so we
    /// set an explicit generous limit instead of relying on `build_generic_tx`'s
    /// estimate. Kept below the L1 block gas limit.
    async fn send_advance(
        &self,
        ssz_input: &[u8],
        l1_messages_count: u16,
        l2_block_gas_limit: u64,
    ) -> Result<H256, NativeL1AdvancerError> {
        let calldata = encode_calldata(
            ADVANCE_FUNCTION_SIGNATURE,
            &[
                Value::Uint(U256::from(l1_messages_count)),
                Value::Bytes(Bytes::from(ssz_input.to_vec())),
            ],
        )
        .map_err(|e| NativeL1AdvancerError::Encoding(e.to_string()))?;

        let calldata_gas = u64::try_from(ssz_input.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(16);
        let advance_gas_limit = l2_block_gas_limit
            .saturating_mul(2)
            .saturating_add(calldata_gas)
            .saturating_add(3_000_000);

        let tx = build_generic_tx(
            &self.eth_client,
            TxType::EIP1559,
            self.contract_address,
            self.signer.address(),
            Bytes::from(calldata),
            Overrides {
                from: Some(self.signer.address()),
                gas_limit: Some(advance_gas_limit),
                ..Default::default()
            },
        )
        .await
        .map_err(NativeL1AdvancerError::EthClient)?;

        let tx_hash = send_tx_bump_gas_exponential_backoff(&self.eth_client, tx, &self.signer)
            .await
            .map_err(NativeL1AdvancerError::EthClient)?;

        // `send_tx_bump_gas_exponential_backoff` returns as soon as a receipt EXISTS; it
        // never inspects `receipt.status`. A reverted advance() (bad witness, root/chain_id
        // mismatch, "Not enough L1 messages", …) has a valid receipt with status=false, so
        // without this check it would be reported as success — the caller would log
        // "advanced block N" while the chain stayed put and re-execute + resubmit the same
        // doomed tx every interval (silent L1 gas drain). Surface it as an error instead.
        let receipt = self
            .eth_client
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(NativeL1AdvancerError::EthClient)?
            .ok_or_else(|| {
                NativeL1AdvancerError::RevertedAdvance(format!(
                    "advance() tx {tx_hash:#x} has no receipt"
                ))
            })?;
        if !receipt.receipt.status {
            return Err(NativeL1AdvancerError::RevertedAdvance(format!(
                "advance() tx {tx_hash:#x} reverted on L1"
            )));
        }

        Ok(tx_hash)
    }
}

/// Encode a Block Access List (EIP-7928) into the SSZ `ExecutionPayload`
/// `block_access_list` field. Uses ethrex's RLP encoding, which is the
/// preimage of `block_access_list_hash` (see `BlockAccessList::compute_hash`),
/// so the guest-program reconstruction can decode it and recompute the same
/// hash. `None` (pre-Amsterdam) → empty list.
///
/// Infallible since execution-specs #3248 made the field a `ProgressiveList<u8>`,
/// which carries no length bound.
pub fn bal_to_ssz_block_access_list(
    bal: Option<&ethrex_common::types::block_access_list::BlockAccessList>,
) -> libssz_types::ProgressiveList<u8> {
    use ethrex_rlp::encode::RLPEncode;
    match bal {
        Some(bal) => bal.encode_to_vec().into(),
        None => libssz_types::ProgressiveList::new(),
    }
}

/// Build SSZ-encoded StatelessInput from block data and execution witness.
///
/// Converts internal types to SSZ containers and serializes the full
/// `StatelessInput` structure that the EXECUTE precompile expects.
pub fn build_ssz_stateless_input(
    header: &BlockHeader,
    body: &ethrex_common::types::BlockBody,
    witness: &ethrex_common::types::block_execution_witness::ExecutionWitness,
    bal: Option<&ethrex_common::types::block_access_list::BlockAccessList>,
) -> Result<Vec<u8>, String> {
    use ethrex_common::types::stateless_ssz::*;
    use libssz::SszEncode;
    use libssz_types::{ProgressiveList, SszList, SszVector};

    // 1. Convert Block → SSZ ExecutionPayload
    // Both levels are progressive lists since #3248, so neither can overflow a
    // bound and the conversions are infallible.
    let transactions: Vec<ProgressiveList<u8>> = body
        .transactions
        .iter()
        .map(|tx| tx.encode_canonical_to_vec().into())
        .collect();
    let ssz_transactions: ProgressiveList<ProgressiveList<u8>> = transactions.into();

    // One uncompressed secp256k1 key per transaction, in transaction order, so the
    // consumer can check senders without running `ecrecover` (#6716). Every
    // transaction here is signature-bearing — the EXECUTE precompile rejects the
    // signature-less variants — so a `None` is a real inconsistency, not a case to
    // skip; skipping would shorten the list and fail the length check anyway.
    let public_keys = body
        .transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let key = tx
                .public_key(&NativeCrypto)
                .map_err(|e| format!("failed to recover public key for transaction {i}: {e}"))?
                .ok_or_else(|| {
                    format!("transaction {i} carries no signature to recover a public key from")
                })?;
            SszVector::try_from(key.to_vec())
                .map_err(|e| format!("public key for transaction {i} is not 65 bytes: {e:?}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let ssz_public_keys: SszPublicKeys = ProgressiveList::from(public_keys);

    let ssz_withdrawals = ProgressiveList::new(); // Empty for L2

    // base_fee_per_gas as LE uint256
    let mut base_fee_bytes = [0u8; 32];
    if let Some(base_fee) = header.base_fee_per_gas {
        base_fee_bytes[..8].copy_from_slice(&base_fee.to_le_bytes());
    }

    // logs_bloom as SszVector<u8, 256>
    let bloom_vec: Vec<u8> = header.logs_bloom.0.to_vec();
    let logs_bloom: LogsBloom = bloom_vec
        .try_into()
        .map_err(|_| "logs_bloom conversion failed")?;

    // extra_data
    let extra_data = SszList::try_from(header.extra_data.to_vec())
        .map_err(|e| format!("extra_data exceeds MAX_EXTRA_DATA_BYTES: {e:?}"))?;

    // block_hash
    let block_hash = header.compute_block_hash(&NativeCrypto);

    let execution_payload = ExecutionPayload {
        parent_hash: header.parent_hash.0,
        fee_recipient: Bytes20(header.coinbase.0),
        state_root: header.state_root.0,
        receipts_root: header.receipts_root.0,
        logs_bloom,
        prev_randao: header.prev_randao.0,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data,
        base_fee_per_gas: base_fee_bytes,
        block_hash: block_hash.0,
        transactions: ssz_transactions,
        withdrawals: ssz_withdrawals,
        blob_gas_used: header.blob_gas_used.unwrap_or(0),
        excess_blob_gas: header.excess_blob_gas.unwrap_or(0),
        block_access_list: bal_to_ssz_block_access_list(bal),
        // EIP-7843: carry the header's slot number into the SSZ payload so L1 can
        // read it and the reconstructed block hash matches.
        slot_number: header.slot_number.unwrap_or(0),
    };

    // 2. Build SSZ NewPayloadRequest
    let parent_beacon_block_root = header
        .parent_beacon_block_root
        .map(|h| h.0)
        .unwrap_or([0u8; 32]);

    // L2 blocks never carry EIP-7685 requests.
    let execution_requests = ExecutionRequests {
        deposits: ProgressiveList::new(),
        withdrawals: ProgressiveList::new(),
        consolidations: ProgressiveList::new(),
        builder_deposits: ProgressiveList::new(),
        builder_exits: ProgressiveList::new(),
    };

    let new_payload_request = NewPayloadRequest {
        execution_payload,
        versioned_hashes: ProgressiveList::new(), // Empty for L2
        parent_beacon_block_root,
        execution_requests,
    };

    // 3. Convert internal ExecutionWitness → SSZ ExecutionWitness
    let ssz_witness = internal_witness_to_ssz(witness)?;

    // 4. Assemble StatelessInput
    let stateless_input = SszStatelessInput {
        new_payload_request,
        witness: ssz_witness,
        // #3278: only the chain id crosses the wire. The consumer derives the rest
        // from (chain_id, fork), with the fork coming from the schema-id prefix.
        chain_id: witness.chain_config.chain_id,
        public_keys: ssz_public_keys,
    };

    // 5. Serialize to schema-prefixed SSZ bytes. The 2-byte big-endian schema id
    // goes first, making this byte-identical to the spec's `statelessInputBytes`;
    // since #3278 it is the only carrier of the fork, not optional framing.
    let mut buf = ethrex_common::types::stateless_ssz::STATELESS_INPUT_SCHEMA_ID
        .to_be_bytes()
        .to_vec();
    stateless_input.ssz_append(&mut buf);
    Ok(buf)
}

/// Convert internal ExecutionWitness to SSZ format.
///
/// The internal witness carries trie nodes as compact witness records
/// (see `ethrex_trie::witness_codec`); the SSZ wire wants standard node RLP
/// preimages, canonicalized (sorted, deduplicated).
fn internal_witness_to_ssz(
    witness: &ethrex_common::types::block_execution_witness::ExecutionWitness,
) -> Result<ethrex_common::types::stateless_ssz::SszExecutionWitness, String> {
    use ethrex_common::types::stateless_ssz::SszExecutionWitness;
    use ethrex_rlp::encode::RLPEncode;
    use libssz_types::SszList;

    let mut state_preimages: Vec<Vec<u8>> = witness
        .state_nodes
        .iter()
        .filter_map(|record| {
            let (_, node) = ethrex_trie::witness_codec::decode_witness_node(record).ok()?;
            Some(node.encode_to_vec())
        })
        .collect();
    state_preimages.sort();
    state_preimages.dedup();
    let state_nodes = state_preimages
        .into_iter()
        .enumerate()
        .map(|(i, preimage)| {
            SszList::try_from(preimage)
                .map_err(|e| format!("witness state[{i}] exceeds MAX_WITNESS_NODE_SIZE: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // `ProgressiveList` since execution-specs #3356: no element-count bound to
    // exceed, so only the per-node byte cap above can fail.
    let state = libssz_types::ProgressiveList::from(state_nodes);

    let codes = witness
        .codes
        .iter()
        .enumerate()
        .map(|(i, code)| {
            SszList::try_from(code.to_vec())
                .map_err(|e| format!("witness codes[{i}] exceeds MAX_WITNESS_CODE_SIZE: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let codes = libssz_types::ProgressiveList::from(codes);

    let headers = witness
        .block_headers_bytes
        .iter()
        .enumerate()
        .map(|(i, header_bytes)| {
            SszList::try_from(header_bytes.to_vec())
                .map_err(|e| format!("witness headers[{i}] exceeds MAX_WITNESS_HEADER_SIZE: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let headers = SszList::try_from(headers)
        .map_err(|e| format!("witness headers exceed MAX_WITNESS_HEADERS: {e:?}"))?;

    Ok(SszExecutionWitness {
        state,
        codes,
        headers,
    })
}

#[actor(protocol = NativeL1AdvancerProtocol)]
impl NativeL1Advancer {
    pub fn spawn(
        eth_client: EthClient,
        contract_address: Address,
        signer: Signer,
        store: Store,
        blockchain: Arc<Blockchain>,
        relayer_address: Address,
        advance_interval_ms: u64,
    ) -> ActorRef<NativeL1Advancer> {
        let advancer = Self::new(
            eth_client,
            contract_address,
            signer,
            store,
            blockchain,
            relayer_address,
            advance_interval_ms,
        );
        advancer.start()
    }

    #[started]
    async fn started(&mut self, ctx: &Context<Self>) {
        let _ = ctx
            .send(native_l1_advancer_protocol::Advance)
            .inspect_err(|e| error!("NativeL1Advancer: failed to send initial Advance: {e}"));
    }

    #[send_handler]
    async fn handle_advance(
        &mut self,
        _msg: native_l1_advancer_protocol::Advance,
        ctx: &Context<Self>,
    ) {
        let _ = self
            .advance_next_block()
            .await
            .inspect_err(|e| error!("NativeL1Advancer error: {e}"));

        send_after(
            Duration::from_millis(self.advance_interval_ms),
            ctx.clone(),
            native_l1_advancer_protocol::Advance,
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod devnet_tests {
    use super::*;

    #[test]
    fn bal_to_ssz_roundtrips_encoding() {
        use ethrex_common::Address;
        use ethrex_common::types::block_access_list::{AccountChanges, BlockAccessList};
        use ethrex_rlp::encode::RLPEncode;

        // None → empty SSZ list (pre-Amsterdam).
        let empty = bal_to_ssz_block_access_list(None);
        assert_eq!(empty.len(), 0);

        // Some(bal) → the SSZ bytes equal the BAL's RLP encoding, so that
        // decode-then-compute_hash on the consumer reproduces block_access_list_hash.
        let bal =
            BlockAccessList::from_accounts(vec![AccountChanges::new(Address::from([0x11u8; 20]))]);
        let expected = bal.encode_to_vec();
        let got = bal_to_ssz_block_access_list(Some(&bal));
        let got_bytes: Vec<u8> = got.iter().copied().collect();
        assert_eq!(got_bytes, expected);
        assert!(!got_bytes.is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ethrex_common::H256;
    use ethrex_common::types::block_access_list::{AccountChanges, BlockAccessList};
    use ethrex_common::types::block_execution_witness::ExecutionWitness;
    use ethrex_common::types::{Block, BlockBody, BlockHeader};
    use ethrex_crypto::NativeCrypto;
    use std::sync::Arc;

    /// Test that Block → SSZ → Block round-trip preserves the block hash.
    ///
    /// This catches mismatches in field encoding (wrong defaults, missing
    /// fields, different formats) that cause `verify_stateless_new_payload`
    /// to reject the block with "block_hash mismatch".
    #[test]
    fn test_block_ssz_roundtrip_preserves_hash() {
        let crypto = Arc::new(NativeCrypto);

        // Build a minimal L2-like block (Shanghai, no txs, empty body)
        let parent_hash = H256::zero();
        let header = BlockHeader {
            parent_hash,
            ommers_hash: *ethrex_common::constants::DEFAULT_OMMERS_HASH,
            coinbase: ethrex_common::Address::zero(),
            state_root: H256::from_low_u64_be(0x1234),
            transactions_root: ethrex_common::types::compute_transactions_root(&[], &NativeCrypto),
            receipts_root: ethrex_common::types::compute_receipts_root(&[], &NativeCrypto),
            logs_bloom: Default::default(),
            number: 1,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1000,
            base_fee_per_gas: Some(7),
            prev_randao: H256::zero(),
            extra_data: bytes::Bytes::new(),
            // Shanghai fields
            withdrawals_root: Some(ethrex_common::types::compute_withdrawals_root(
                &[],
                &NativeCrypto,
            )),
            // Cancun fields (present in L2 blocks even though chain is Shanghai)
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(H256::zero()),
            // Prague fields
            requests_hash: Some(ethrex_common::types::requests::compute_requests_hash(&[])),
            // EIP-7843: Amsterdam+ blocks carry a slot number; must survive round-trip.
            slot_number: Some(42),
            ..Default::default()
        };
        let body = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: Some(vec![]),
        };
        let block = Block::new(header.clone(), body.clone());
        let original_hash = block.hash();

        // Build a minimal witness (empty, just enough for the SSZ encoding)
        // chain_config must have Prague activated (Cancun+) — chain_config_to_ssz
        // requires at least Cancun; Paris and earlier are not supported.
        let witness = ExecutionWitness {
            codes: vec![],
            block_headers_bytes: vec![],
            first_block_number: 1,
            chain_config: ethrex_common::types::ChainConfig {
                chain_id: 1,
                cancun_time: Some(0),
                prague_time: Some(0),
                ..Default::default()
            },
            state_nodes: vec![],
        };

        // Block → SSZ (no BAL for pre-Amsterdam test block)
        let ssz_bytes = build_ssz_stateless_input(&header, &body, &witness, None)
            .expect("SSZ encoding should succeed");

        // SSZ → deserialize → reconstruct Block
        let input = ethrex_guest_program::l1::decode_stateless_input(&ssz_bytes)
            .expect("SSZ deserialization should succeed");

        let reconstructed_block = ethrex_guest_program::l1::new_payload_request_to_block(
            &input.new_payload_request,
            crypto.as_ref(),
        )
        .expect("Block reconstruction should succeed");

        let reconstructed_hash = reconstructed_block.hash();

        // Compare field by field to make debugging easier
        assert_eq!(
            header.parent_hash, reconstructed_block.header.parent_hash,
            "parent_hash mismatch"
        );
        assert_eq!(
            header.coinbase, reconstructed_block.header.coinbase,
            "coinbase mismatch"
        );
        assert_eq!(
            header.state_root, reconstructed_block.header.state_root,
            "state_root mismatch"
        );
        assert_eq!(
            header.transactions_root, reconstructed_block.header.transactions_root,
            "transactions_root mismatch"
        );
        assert_eq!(
            header.receipts_root, reconstructed_block.header.receipts_root,
            "receipts_root mismatch"
        );
        assert_eq!(
            header.number, reconstructed_block.header.number,
            "number mismatch"
        );
        assert_eq!(
            header.gas_limit, reconstructed_block.header.gas_limit,
            "gas_limit mismatch"
        );
        assert_eq!(
            header.gas_used, reconstructed_block.header.gas_used,
            "gas_used mismatch"
        );
        assert_eq!(
            header.timestamp, reconstructed_block.header.timestamp,
            "timestamp mismatch"
        );
        assert_eq!(
            header.base_fee_per_gas, reconstructed_block.header.base_fee_per_gas,
            "base_fee_per_gas mismatch"
        );
        assert_eq!(
            header.prev_randao, reconstructed_block.header.prev_randao,
            "prev_randao mismatch"
        );
        assert_eq!(
            header.extra_data, reconstructed_block.header.extra_data,
            "extra_data mismatch"
        );
        assert_eq!(
            header.withdrawals_root, reconstructed_block.header.withdrawals_root,
            "withdrawals_root mismatch"
        );
        assert_eq!(
            header.blob_gas_used, reconstructed_block.header.blob_gas_used,
            "blob_gas_used mismatch"
        );
        assert_eq!(
            header.excess_blob_gas, reconstructed_block.header.excess_blob_gas,
            "excess_blob_gas mismatch"
        );
        assert_eq!(
            header.parent_beacon_block_root, reconstructed_block.header.parent_beacon_block_root,
            "parent_beacon_block_root mismatch"
        );
        assert_eq!(
            header.requests_hash, reconstructed_block.header.requests_hash,
            "requests_hash mismatch"
        );
        assert_eq!(
            header.logs_bloom, reconstructed_block.header.logs_bloom,
            "logs_bloom mismatch"
        );
        assert_eq!(
            header.difficulty, reconstructed_block.header.difficulty,
            "difficulty mismatch"
        );
        assert_eq!(
            header.nonce, reconstructed_block.header.nonce,
            "nonce mismatch"
        );
        assert_eq!(
            header.ommers_hash, reconstructed_block.header.ommers_hash,
            "ommers_hash mismatch"
        );

        // The final check: block hash must match
        assert_eq!(
            original_hash, reconstructed_hash,
            "Block hash mismatch after SSZ round-trip!\n  original:      {original_hash:?}\n  reconstructed: {reconstructed_hash:?}"
        );
    }

    /// Test that an Amsterdam block with a non-empty BAL round-trips correctly
    /// through SSZ: the reconstructed block_access_list_hash matches the
    /// original, so block.hash() is preserved end-to-end.
    ///
    /// This is the activation proof for Task 4 (feat/unify-stateless-validation-v2):
    /// once native_l2.json carries amsterdamTime:0, every produced block lands
    /// here and advance() can verify the hash.
    #[test]
    fn test_amsterdam_block_with_bal_roundtrip_preserves_hash() {
        let crypto = Arc::new(NativeCrypto);

        // Build a minimal BAL with one account entry.
        let bal = BlockAccessList::from_accounts(vec![AccountChanges::new(
            ethrex_common::Address::from([0xABu8; 20]),
        )]);
        let bal_hash = bal.compute_hash(&ethrex_crypto::NativeCrypto);

        // Build an Amsterdam block header: same as the Prague test but with
        // block_access_list_hash set to Some(bal_hash).
        let header = BlockHeader {
            parent_hash: H256::zero(),
            ommers_hash: *ethrex_common::constants::DEFAULT_OMMERS_HASH,
            coinbase: ethrex_common::Address::zero(),
            state_root: H256::from_low_u64_be(0xabcd),
            transactions_root: ethrex_common::types::compute_transactions_root(&[], &NativeCrypto),
            receipts_root: ethrex_common::types::compute_receipts_root(&[], &NativeCrypto),
            logs_bloom: Default::default(),
            number: 2,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 2000,
            base_fee_per_gas: Some(7),
            prev_randao: H256::zero(),
            extra_data: bytes::Bytes::new(),
            withdrawals_root: Some(ethrex_common::types::compute_withdrawals_root(
                &[],
                &NativeCrypto,
            )),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(ethrex_common::types::requests::compute_requests_hash(&[])),
            // Amsterdam field — set to the BAL hash we'll encode in the SSZ payload.
            block_access_list_hash: Some(bal_hash),
            // EIP-7843: Amsterdam+ blocks carry a slot number; must survive round-trip.
            slot_number: Some(42),
            ..Default::default()
        };
        let body = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: Some(vec![]),
        };
        let block = Block::new(header.clone(), body.clone());
        let original_hash = block.hash();

        // The witness chain_config must have Amsterdam active so chain_config_to_ssz
        // encodes it correctly.
        let witness = ExecutionWitness {
            codes: vec![],
            block_headers_bytes: vec![],
            first_block_number: 2,
            chain_config: ethrex_common::types::ChainConfig {
                chain_id: 1,
                cancun_time: Some(0),
                prague_time: Some(0),
                amsterdam_time: Some(0),
                ..Default::default()
            },
            state_nodes: vec![],
        };

        // Block → SSZ with the real BAL passed through.
        let ssz_bytes = build_ssz_stateless_input(&header, &body, &witness, Some(&bal))
            .expect("SSZ encoding should succeed for Amsterdam block with BAL");

        // SSZ → deserialize → reconstruct Block
        let input = ethrex_guest_program::l1::decode_stateless_input(&ssz_bytes)
            .expect("SSZ deserialization should succeed");

        let reconstructed_block = ethrex_guest_program::l1::new_payload_request_to_block(
            &input.new_payload_request,
            crypto.as_ref(),
        )
        .expect("Block reconstruction should succeed for Amsterdam block");

        // The reconstructed header must carry the same block_access_list_hash.
        assert_eq!(
            reconstructed_block.header.block_access_list_hash,
            Some(bal_hash),
            "block_access_list_hash must be reconstructed from the SSZ BAL payload"
        );

        // The final check: full block hash must match end-to-end.
        assert_eq!(
            original_hash,
            reconstructed_block.hash(),
            "Amsterdam block hash mismatch after BAL SSZ round-trip!\n  original:      {original_hash:?}\n  reconstructed: {:?}",
            reconstructed_block.hash()
        );
    }
}
