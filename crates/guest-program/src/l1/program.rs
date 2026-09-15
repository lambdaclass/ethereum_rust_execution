use std::sync::Arc;

use ethrex_common::types::ELASTICITY_MULTIPLIER;
use ethrex_common::types::stateless_ssz::{
    STATELESS_INPUT_SCHEMA_ID, SszPublicKeys, SszStatelessInput, SszStatelessValidationResult,
};
use ethrex_crypto::Crypto;
use ethrex_vm::Evm;
use libssz_merkle::{HashTreeRoot, Sha256Hasher};

use crate::common::ExecutionError;
use crate::common::execute_blocks;
use crate::l1::input::decode_stateless_input;

/// Wrapper to bridge `ethrex_crypto::Crypto` to `libssz_merkle::Sha256Hasher`,
/// so `hash_tree_root` is computed via crypto precompiles in the zkVM.
/// Required because the orphan rule prevents a direct impl on `Arc<dyn Crypto>`.
struct CryptoWrapper(Arc<dyn Crypto>);

impl Sha256Hasher for CryptoWrapper {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        self.0.sha256(data)
    }
}

fn base_fee_per_gas_from_le_bytes(bytes: &[u8; 32]) -> Result<u64, String> {
    if bytes[8..].iter().any(|&b| b != 0) {
        return Err("base_fee_per_gas exceeds u64 (non-zero upper bytes)".to_string());
    }
    Ok(u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| "base_fee_per_gas conversion")?,
    ))
}

/// Transform an SSZ `NewPayloadRequest` into a `Block`.
/// Validate that the blob versioned hashes in the `NewPayloadRequest` match
/// the blob commitments in the block's transactions.
fn validate_versioned_hashes<'a>(
    block: &ethrex_common::types::Block,
    versioned_hashes: impl IntoIterator<Item = &'a [u8; 32]>,
) -> Result<(), ExecutionError> {
    use ethrex_common::H256;

    // Collect all versioned hashes from blob transactions in order
    let tx_hashes: Vec<H256> = block
        .body
        .transactions
        .iter()
        .flat_map(|tx| tx.blob_versioned_hashes())
        .collect();

    let req_hashes: Vec<H256> = versioned_hashes
        .into_iter()
        .map(|h| H256::from_slice(h))
        .collect();

    if tx_hashes != req_hashes {
        return Err(ExecutionError::Internal(
            "versioned hashes mismatch between NewPayloadRequest and transactions".to_string(),
        ));
    }

    Ok(())
}

/// Transform an SSZ `NewPayloadRequest` into a `Block`. Shared by the EXECUTE
/// precompile path, the L2 advancer, and [`verify_stateless_block`].
pub fn new_payload_request_to_block(
    req: &ethrex_common::types::stateless_ssz::NewPayloadRequest,
    crypto: &dyn Crypto,
) -> Result<ethrex_common::types::Block, String> {
    use bytes::Bytes;
    use ethrex_common::constants::DEFAULT_OMMERS_HASH;
    use ethrex_common::types::requests::compute_requests_hash_with_crypto;
    use ethrex_common::types::{
        Block, BlockBody, BlockHeader, Transaction, Withdrawal, compute_transactions_root,
        compute_withdrawals_root,
    };
    use ethrex_common::{Address, Bloom, H256};

    let payload = &req.execution_payload;

    // Decode transactions from raw bytes
    let transactions: Vec<Transaction> = payload
        .transactions
        .iter()
        .map(|tx_bytes| {
            let raw: Vec<u8> = tx_bytes.iter().copied().collect();
            Transaction::decode_canonical(&raw).map_err(|e| format!("tx decode: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Convert SSZ withdrawals to ethrex Withdrawals
    let withdrawals: Vec<Withdrawal> = payload
        .withdrawals
        .iter()
        .map(|w| Withdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: Address::from_slice(&w.address.0),
            amount: w.amount,
        })
        .collect();

    // Build execution_requests from the SSZ typed ExecutionRequests field
    let execution_requests = req.execution_requests.to_encoded_requests();
    let requests_hash = compute_requests_hash_with_crypto(&execution_requests, crypto);

    // Convert base_fee_per_gas from [u8; 32] LE uint256 to u64. The helper rejects
    // non-zero upper bytes so a single block maps to a single hash_tree_root (see
    // `base_fee_per_gas_from_le_bytes`).
    let base_fee_per_gas = base_fee_per_gas_from_le_bytes(&payload.base_fee_per_gas)?;

    // Build logs_bloom from SszVector<u8, 256>
    let bloom_bytes: Vec<u8> = payload.logs_bloom.iter().copied().collect();
    let logs_bloom = Bloom::from_slice(&bloom_bytes);

    let body = BlockBody {
        transactions: transactions.clone(),
        ommers: vec![],
        withdrawals: Some(withdrawals.clone()),
    };

    let mut header = BlockHeader {
        parent_hash: H256::from_slice(&payload.parent_hash),
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: Address::from_slice(&payload.fee_recipient.0),
        state_root: H256::from_slice(&payload.state_root),
        transactions_root: compute_transactions_root(&body.transactions, crypto),
        receipts_root: H256::from_slice(&payload.receipts_root),
        logs_bloom,
        difficulty: 0.into(),
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::from(payload.extra_data.iter().copied().collect::<Vec<u8>>()),
        prev_randao: H256::from_slice(&payload.prev_randao),
        nonce: 0,
        base_fee_per_gas: Some(base_fee_per_gas),
        withdrawals_root: Some(compute_withdrawals_root(&withdrawals, crypto)),
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        parent_beacon_block_root: Some(H256::from_slice(&req.parent_beacon_block_root)),
        requests_hash: Some(requests_hash),
        // EIP-7843: reconstruct the slot number carried in the SSZ payload so the
        // computed block hash matches the producer's. Native-rollup blocks are
        // Amsterdam+, where slot_number is always present.
        slot_number: Some(payload.slot_number),
        ..Default::default()
    };

    // EIP-7928: when the payload carries a Block Access List, derive the header
    // commitment from it. ethrex encodes the BAL as RLP (the preimage of
    // block_access_list_hash), so decode-then-compute_hash reproduces the exact
    // hash the producer set — honoring the empty-BAL special case. An empty
    // field means pre-Amsterdam: leave block_access_list_hash as None.
    if !payload.block_access_list.is_empty() {
        use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};
        let bal_bytes: Vec<u8> = payload.block_access_list.iter().copied().collect();
        let bal = ethrex_common::types::block_access_list::BlockAccessList::decode(&bal_bytes)
            .map_err(|e| format!("block_access_list decode: {e}"))?;
        // Decoding preserves the wire order while encoding sorts by address, and
        // `compute_hash` re-encodes — so without these two checks a permuted or
        // otherwise non-canonical BAL canonicalizes away and still produces the
        // expected hash. `engine_newPayloadV5` hashes the raw bytes for the same
        // reason (`rpc/engine/payload.rs`); the guest has to reject explicitly.
        bal.validate_ordering()
            .map_err(|e| format!("block_access_list ordering: {e}"))?;
        if bal.encode_to_vec() != bal_bytes {
            return Err("block access list is not canonically encoded".to_string());
        }
        header.block_access_list_hash = Some(bal.compute_hash(crypto));
    }

    Ok(Block::new(header, body))
}

/// Validate the per-transaction public keys carried by a stateless input.
///
/// The spec's `StatelessInput` supplies one uncompressed secp256k1 key per
/// transaction so a guest can skip `ecrecover`; a key that does not derive to the
/// recovered sender must reject the payload (#6716). Called from
/// [`verify_stateless_block`] — the single point both the zkVM guest and the
/// EXECUTE precompile pass through — so neither path can drop it.
///
/// Upstream `build_stateless_input` skips keys for undecodable or bad-signature
/// transactions, so a short `public_keys` is possible; such payloads are invalid
/// on both sides, and the length is checked before any zip so a short list fails
/// cleanly rather than panicking.
pub fn validate_public_keys(
    public_keys: &SszPublicKeys,
    block: &ethrex_common::types::Block,
    crypto: &dyn Crypto,
) -> Result<(), ExecutionError> {
    if public_keys.len() != block.body.transactions.len() {
        return Err(ExecutionError::Internal(format!(
            "Found {} public keys in the stateless input, but there are {} transactions",
            public_keys.len(),
            block.body.transactions.len()
        )));
    }
    for (public_key, tx) in public_keys.iter().zip(block.body.transactions.iter()) {
        // SSZ decode fixes the length at 65; uncompressed secp256k1 is 0x04 || X || Y.
        let pk_bytes: &[u8] = public_key;
        let Some((tag, xy)) = pk_bytes.split_first() else {
            return Err(ExecutionError::Internal(
                "Stateless input public key is empty".to_string(),
            ));
        };
        if *tag != 0x04 {
            return Err(ExecutionError::Internal(
                "Stateless input public key is not a 65-byte uncompressed secp256k1 key"
                    .to_string(),
            ));
        }
        let hashed = ethrex_common::utils::keccak(xy);
        let derived = ethrex_common::Address::from_slice(&hashed[12..]);
        let recovered = tx.sender(crypto).map_err(|e| {
            ExecutionError::Internal(format!("failed to recover transaction sender: {e}"))
        })?;
        if recovered != derived {
            return Err(ExecutionError::Internal(
                "Stateless input public key does not match recovered transaction sender"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Stateless validation of a single payload, shared by every entrypoint: the
/// zkVM guests via [`run_stateless_guest`], and the EXECUTE precompile via
/// `verify_inner` in `ethrex-blockchain`. Everything a payload must satisfy
/// belongs here rather than in a caller — see [`validate_public_keys`] for what
/// splitting it cost.
///
/// Implements `verify_stateless_new_payload` from execution-specs: reconstruct
/// block → check the supplied public keys → validate versioned hashes → execute
/// statelessly (which validates the recomputed block access list hash on
/// Amsterdam+) → inject recomputed `burned_fees` → verify `block_hash`.
pub fn verify_stateless_block(
    new_payload_request: &ethrex_common::types::stateless_ssz::NewPayloadRequest,
    public_keys: &SszPublicKeys,
    execution_witness: ethrex_common::types::block_execution_witness::ExecutionWitness,
    crypto: Arc<dyn Crypto>,
) -> Result<(), ExecutionError> {
    // Transform SSZ NewPayloadRequest → Block.
    // Do NOT call block.hash() here — burned_fees is not yet known so any
    // cached value would be stale.
    let block = new_payload_request_to_block(new_payload_request, crypto.as_ref())
        .map_err(|e| ExecutionError::Internal(format!("payload conversion: {e}")))?;

    // Check the supplied keys against the recovered senders before committing to
    // execution, so a mismatched key rejects without paying for a block.
    validate_public_keys(public_keys, &block, crypto.as_ref())?;

    // Keep block in a fixed-size array so we can reclaim it after execute_blocks
    // (which borrows it as &[Block] without consuming it).
    let blocks = [block];

    // Validate blob versioned hashes (does not touch block.hash())
    validate_versioned_hashes(&blocks[0], new_payload_request.versioned_hashes.iter())?;

    // Execute statelessly — burned_fees and BAL are recomputed from actual execution.
    let result = execute_blocks(
        &blocks,
        execution_witness,
        ELASTICITY_MULTIPLIER,
        |db, _| Ok(Evm::new_for_l1(db.clone(), crypto.clone())),
        crypto.clone(),
    )?;

    // Inject recomputed burned_fees into the header, then check block_hash.
    //
    // Safety: execute_blocks calls initialize_block_header_hashes which
    // populates block.header.hash via OnceCell — but with burned_fees=None
    // (pre-execution value).  into_with_burned_fees() takes ownership, sets
    // burned_fees, and calls OnceCell::take() to clear the stale cache, so
    // the next hash() call reflects the injected value.
    //
    // At Amsterdam (pre-LStar), burned_fees is None both here and in the
    // original header, so the hash is unchanged — no regression on the
    // current path.
    let recomputed_burned_fees = result.burned_fees.first().copied().flatten();
    let [block] = blocks;
    let verified_header = block.header.into_with_burned_fees(recomputed_burned_fees);

    // No BAL validation here: `execute_blocks` already ran
    // `validate_block_access_list_hash` on this block, and re-running it would
    // be a second full traversal plus another RLP-encode-and-keccak of the
    // whole access list inside the zkVM. The check reads only `timestamp`,
    // `gas_limit` and `block_access_list_hash`, none of which
    // `into_with_burned_fees` touches, so a second call cannot reach a
    // different verdict.

    let computed_hash = verified_header.compute_block_hash(crypto.as_ref());
    let expected_hash =
        ethrex_common::H256::from_slice(&new_payload_request.execution_payload.block_hash);
    if computed_hash != expected_hash {
        return Err(ExecutionError::Internal(format!(
            "block_hash mismatch: expected {expected_hash:?}, got {computed_hash:?}"
        )));
    }

    Ok(())
}

/// Per-stage instrumentation for [`run_stateless_guest_traced`].
///
/// Every method defaults to a no-op, so [`run_stateless_guest`] pays nothing for
/// it — `print` takes `fmt::Arguments` so its message is never formatted unless a
/// trace consumes it. The zkVM guests supply their platform's cycle scopes; the
/// scope names appear in ZisK profiling output, so keep them stable.
pub trait GuestTrace {
    fn scope<T>(_name: &str, f: impl FnOnce() -> T) -> T {
        f()
    }
    fn print(_message: core::fmt::Arguments<'_>) {}
}

/// The [`GuestTrace`] used by the uninstrumented entrypoint.
pub struct NoTrace;
impl GuestTrace for NoTrace {}

/// Run the stateless validation guest: `statelessInputBytes` in,
/// `statelessOutputBytes` out.
///
/// Never panics and never returns an error, mirroring `run_stateless_guest` in
/// `stateless_guest.py`. A **decode** failure commits the all-zero default. A
/// decodable input commits the real payload-request root, `chain_id` and
/// `schema_id` **even when validation fails** — zero sentinels are the
/// decode-failure signal only, and the root is computed before validation runs.
pub fn run_stateless_guest(input_bytes: &[u8], crypto: Arc<dyn Crypto>) -> Vec<u8> {
    run_stateless_guest_traced::<NoTrace>(input_bytes, crypto)
}

/// [`run_stateless_guest`] with per-stage instrumentation. One implementation
/// serves both, so an instrumented guest cannot drift from the plain one.
pub fn run_stateless_guest_traced<T: GuestTrace>(
    input_bytes: &[u8],
    crypto: Arc<dyn Crypto>,
) -> Vec<u8> {
    use libssz::SszEncode;

    let Ok(input) = T::scope("deserialize_input", || decode_stateless_input(input_bytes)) else {
        let mut out = Vec::new();
        SszStatelessValidationResult::default().ssz_append(&mut out);
        return out;
    };

    let new_payload_request_root = T::scope("new_payload_request_root", || {
        input
            .new_payload_request
            .hash_tree_root(&CryptoWrapper(crypto.clone()))
    });
    let chain_id = input.chain_id;

    // No `validate_chain_config` scope: #3278 removed all chain configuration
    // from the wire, so the fork comes from the schema id and the config is
    // derived inside the validation.
    let successful_validation = T::scope("run_validation", || {
        validate_stateless_execution(&input, crypto)
            .inspect_err(|err| T::print(format_args!("Validation failed: {err}\n")))
    })
    .is_ok();

    T::scope("serialize_output", || {
        let mut out = Vec::new();
        SszStatelessValidationResult {
            new_payload_request_root,
            successful_validation,
            chain_id,
            schema_id: STATELESS_INPUT_SCHEMA_ID,
        }
        .ssz_append(&mut out);
        out
    })
}

/// Validate a decoded stateless input: rebuild the `ExecutionWitness`, derive the
/// `ChainConfig` from `(chain_id, Amsterdam)`, and hand off to
/// [`verify_stateless_block`], which checks the public keys and executes.
pub fn validate_stateless_execution(
    input: &SszStatelessInput,
    crypto: Arc<dyn Crypto>,
) -> Result<(), ExecutionError> {
    let execution_witness =
        ethrex_common::types::block_execution_witness::ExecutionWitness::from_ssz(
            input,
            crypto.as_ref(),
        )
        .map_err(|e| ExecutionError::Internal(format!("witness rebuild: {e}")))?;

    verify_stateless_block(
        &input.new_payload_request,
        &input.public_keys,
        execution_witness,
        crypto,
    )
}

/// Validate blocks statelessly against an in-memory witness.
///
/// The spec entrypoint is [`run_stateless_guest`]; this exists for callers that
/// hold a witness they generated themselves — the ef_tests witness-sufficiency
/// checks — rather than spec wire bytes. It commits to nothing.
pub fn validate_blocks_statelessly(
    blocks: &[ethrex_common::types::Block],
    execution_witness: ethrex_common::types::block_execution_witness::ExecutionWitness,
    crypto: Arc<dyn Crypto>,
) -> Result<(), ExecutionError> {
    execute_blocks(
        blocks,
        execution_witness,
        ELASTICITY_MULTIPLIER,
        |db, _| Ok(Evm::new_for_l1(db.clone(), crypto.clone())),
        crypto.clone(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NativeCrypto;
    use libssz::SszEncode;

    fn default_result_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        SszStatelessValidationResult::default().ssz_append(&mut out);
        out
    }

    /// A guest must never panic on hostile input, and a decode failure commits the
    /// all-zero result rather than a partially-filled one.
    #[test]
    fn malformed_input_yields_default_result() {
        let crypto = Arc::new(NativeCrypto);
        let expected = default_result_bytes();

        for bytes in [
            vec![],                       // no schema id at all
            vec![0x15],                   // half a schema id
            vec![0x15, 0x01],             // right id, empty body
            vec![0x15, 0x02, 0x00],       // right fork, wrong revision
            vec![0x16, 0x01, 0x00],       // wrong fork index
            vec![0x15, 0x01, 0xde, 0xad], // right id, garbage body
        ] {
            assert_eq!(
                run_stateless_guest(&bytes, crypto.clone()),
                expected,
                "input {bytes:?} must produce the default result"
            );
        }
    }

    /// The output is fully fixed-size under #3278: 32 + 1 + 8 + 2.
    #[test]
    fn default_result_is_43_zero_bytes() {
        let encoded = default_result_bytes();
        assert_eq!(encoded.len(), 43, "result must be fixed-size");
        assert!(
            encoded.iter().all(|b| *b == 0),
            "a decode failure commits all zeros, including schema_id"
        );
    }

    /// Only `0x1501` decodes — the guest's entire fork check, so the one
    /// rejection that must not regress.
    #[test]
    fn only_amsterdam_schema_id_decodes() {
        assert_eq!(STATELESS_INPUT_SCHEMA_ID, 0x1501);
        for id in [0x1401u16, 0x1502, 0x1601, 0x0000] {
            let mut bytes = id.to_be_bytes().to_vec();
            bytes.extend_from_slice(&[0u8; 8]);
            assert!(
                decode_stateless_input(&bytes).is_err(),
                "schema id {id:#06x} must be rejected"
            );
        }
    }
}
