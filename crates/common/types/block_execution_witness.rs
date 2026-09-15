use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;

use crate::rkyv_utils::H256Wrapper;
use crate::serde_utils;
use crate::types::{Block, Code, CodeMetadata};
use crate::{
    constants::EMPTY_KECCAK_HASH,
    types::{AccountState, AccountUpdate, BlockHeader, ChainConfig},
};
use ethereum_types::{Address, H256, U256};
use ethrex_crypto::Crypto;
use ethrex_rlp::error::RLPDecodeError;
use ethrex_rlp::structs::{Decoder, Encoder};
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};
use ethrex_trie::{EMPTY_TRIE_HASH, FxHashMap, Nibbles, Node, NodeRef, Trie, TrieError};
use rkyv::with::{Identity, MapKV};
use serde::{Deserialize, Serialize};

/// State produced by the guest program execution inside the zkVM. It is
/// essentially built from the `ExecutionWitness`.
/// This state is used during the stateless validation of the zkVM execution.
/// Some data is prepared before the stateless validation, and some data is
/// built on-demand during the stateless validation.
/// This struct must be instantiated, filled, and consumed inside the zkVM.
pub struct GuestProgramState {
    /// Map of code hashes to their corresponding bytecode.
    /// This is computed during guest program execution inside the zkVM,
    /// before the stateless validation.
    pub codes_hashed: BTreeMap<H256, Code>,
    /// Map of block numbers to their corresponding block headers.
    /// The block headers are pushed to the zkVM RLP-encoded, and then
    /// decoded and stored in this map during guest program execution,
    /// inside the zkVM.
    pub block_headers: BTreeMap<u64, BlockHeader>,
    /// The accounts state trie containing the necessary state for the guest
    /// program execution.
    pub state_trie: Trie,
    /// The parent block header of the first block in the batch.
    pub parent_block_header: BlockHeader,
    /// The block number of the first block in the batch.
    pub first_block_number: u64,
    /// The chain configuration.
    pub chain_config: ChainConfig,
    /// Map of hashed addresses to their corresponding storage tries.
    pub storage_tries: BTreeMap<H256, Trie>,
    /// Map of account addresses to their corresponding hashed addresses.
    /// This is a convenience map to avoid recomputing the hashed address
    /// multiple times during guest program execution.
    /// It is built on-demand during guest program execution, inside the zkVM.
    pub account_hashes_by_address: BTreeMap<Address, H256>,
    /// Map of hashed addresses to booleans, indicating whose account's storage tries were
    /// verified.
    /// Verification is done by hashing the trie and comparing the root hash with the account's storage root.
    pub verified_storage_roots: BTreeMap<H256, bool>,
}

/// Witness data produced by the client and consumed by the guest program
/// inside the zkVM.
///
/// It is essentially an `RpcExecutionWitness` but it also contains `ChainConfig`,
/// and `first_block_number`.
#[derive(
    Default, Serialize, Deserialize, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Clone,
)]
pub struct ExecutionWitness {
    // Contract bytecodes needed for stateless execution.
    #[rkyv(with = crate::rkyv_utils::VecVecWrapper)]
    pub codes: Vec<Vec<u8>>,
    /// RLP-encoded block headers needed for stateless execution.
    #[rkyv(with = crate::rkyv_utils::VecVecWrapper)]
    pub block_headers_bytes: Vec<Vec<u8>>,
    /// The block number of the first block
    pub first_block_number: u64,
    // The chain config.
    pub chain_config: ChainConfig,
    /// Root node embedded with the rest of the trie's nodes
    pub state_trie_root: Option<Node>,
    /// Root nodes per account storage embedded with the rest of the trie's nodes,
    /// keyed by the keccak256 hash of the account address.
    #[rkyv(with = MapKV<H256Wrapper, Identity>)]
    pub storage_trie_roots: BTreeMap<H256, Node>,
}

/// RPC-friendly representation of an execution witness.
///
/// This is the format returned by the `debug_executionWitness` RPC method.
/// The trie nodes are pre-serialized (via `encode_subtrie`) to avoid
/// expensive traversal on every RPC request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcExecutionWitness {
    #[serde(
        serialize_with = "serde_utils::bytes::vec::serialize",
        deserialize_with = "serde_utils::bytes::vec::deserialize"
    )]
    pub state: Vec<Bytes>,
    #[serde(
        default,
        serialize_with = "serde_utils::bytes::vec::serialize",
        deserialize_with = "serde_utils::bytes::vec::deserialize"
    )]
    pub keys: Vec<Bytes>,
    #[serde(
        serialize_with = "serde_utils::bytes::vec::serialize",
        deserialize_with = "serde_utils::bytes::vec::deserialize"
    )]
    pub codes: Vec<Bytes>,
    #[serde(
        serialize_with = "serde_utils::bytes::vec::serialize",
        deserialize_with = "serde_utils::bytes::vec::deserialize"
    )]
    pub headers: Vec<Bytes>,
}

impl TryFrom<ExecutionWitness> for RpcExecutionWitness {
    type Error = TrieError;

    fn try_from(value: ExecutionWitness) -> Result<Self, Self::Error> {
        let mut nodes = Vec::new();
        if let Some(state_trie_root) = value.state_trie_root {
            state_trie_root.encode_subtrie(&mut nodes)?;
        }
        for node in value.storage_trie_roots.values() {
            node.encode_subtrie(&mut nodes)?;
        }
        // Canonical witness ordering (EIP-8025, geth `ExtWitness`): state nodes
        // and codes sorted lexicographically and deduplicated (identical
        // storage subtries would otherwise emit identical nodes twice); headers
        // ascending by block number and deduplicated (the same ancestor header
        // can be referenced by more than one block).
        nodes.sort();
        nodes.dedup();
        let mut codes = value.codes;
        codes.sort();
        codes.dedup();
        let mut headers = value.block_headers_bytes;
        headers.sort_by_cached_key(|bytes| {
            // Undecodable headers sort last; consumers reject them on decode anyway.
            BlockHeader::decode(bytes)
                .map(|header| header.number)
                .unwrap_or(u64::MAX)
        });
        // Identical headers share a block number, so they are now adjacent.
        headers.dedup();
        Ok(Self {
            state: nodes.into_iter().map(Bytes::from).collect(),
            keys: Vec::new(),
            codes: codes.into_iter().map(Bytes::from).collect(),
            headers: headers.into_iter().map(Bytes::from).collect(),
        })
    }
}

/// Geth's `ExtWitness` wire shape, returned by
/// `engine_newPayloadWithWitness*`: an RLP list of
/// `(headers, codes, state, keys)`, with headers ascending by block number
/// and code/state byte lists sorted lexicographically. Geth currently emits
/// empty `keys`, but the trailing field is part of the RLP shape.
/// Reference:
/// https://github.com/ethereum/go-ethereum/blob/4daaaadfc4706b0a49d4dfde3559de7be968c28a/core/stateless/encoding.go#L30-L52
#[derive(Debug, Clone)]
pub struct ExtWitness {
    pub headers: Vec<BlockHeader>,
    pub codes: Vec<Bytes>,
    pub state: Vec<Bytes>,
    pub keys: Vec<Bytes>,
}

impl RLPEncode for ExtWitness {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.headers)
            .encode_field(&self.codes)
            .encode_field(&self.state)
            .encode_field(&self.keys)
            .finish();
    }
}

impl RLPDecode for ExtWitness {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (headers, decoder) = decoder.decode_field("headers")?;
        let (codes, decoder) = decoder.decode_field("codes")?;
        let (state, decoder) = decoder.decode_field("state")?;
        let (keys, decoder) = decoder.decode_field("keys")?;
        let remaining = decoder.finish()?;
        Ok((
            ExtWitness {
                headers,
                codes,
                state,
                keys,
            },
            remaining,
        ))
    }
}

impl RpcExecutionWitness {
    /// Convert an RPC execution witness into the internal [`ExecutionWitness`]
    /// format by rebuilding trie structures from the flat node list.
    /// `decoded_headers` is reused (typically from [`decode_witness_headers`])
    /// to avoid a second RLP decode.
    pub fn into_execution_witness(
        self,
        chain_config: ChainConfig,
        first_block_number: u64,
        decoded_headers: &[BlockHeader],
        crypto: &dyn Crypto,
    ) -> Result<ExecutionWitness, GuestProgramStateError> {
        let initial_state_root = find_parent_state_root(decoded_headers, first_block_number)?;
        // Drop the `0x80` Null-node sentinel some `debug_executionWitness` producers emit.
        // Undecodable/unused nodes are dropped per EELS
        // `test_validation_state_extra_unused_trie_node`; missing needed nodes surface
        // later as `RootNotFound` from `get_embedded_root_committed`.
        let nodes: FxHashMap<H256, Node> = self
            .state
            .into_iter()
            .filter_map(|b| {
                if b == Bytes::from_static(&[0x80]) {
                    return None;
                }
                let node = Node::decode(&b).ok()?;
                Some((H256(crypto.keccak256(&b)), node))
            })
            .collect();

        // get state trie root and embed the rest of the trie into it
        let state_trie_root = if let NodeRef::Node(state_trie_root, _) =
            Trie::get_embedded_root_committed(&nodes, initial_state_root, crypto)?
        {
            Some((*state_trie_root).clone())
        } else {
            None
        };

        // Walk the state trie to discover accounts and their storage roots,
        // instead of relying on the keys field which is being removed from the RPC spec.
        let mut storage_trie_roots = BTreeMap::new();
        if let Some(state_trie_root) = &state_trie_root {
            let mut accounts = Vec::new();
            collect_accounts_from_trie(
                state_trie_root,
                Nibbles::from_raw(&[], false),
                &mut accounts,
                &nodes,
                crypto,
            );

            for (hashed_address, storage_root_hash) in accounts {
                if storage_root_hash == EMPTY_TRIE_HASH {
                    continue;
                }
                if !nodes.contains_key(&storage_root_hash) {
                    continue;
                }
                let node = Trie::get_embedded_root_committed(&nodes, storage_root_hash, crypto)?;
                let NodeRef::Node(node, _) = node else {
                    return Err(GuestProgramStateError::Custom(
                        "execution witness does not contain non-empty storage trie".to_string(),
                    ));
                };
                storage_trie_roots.insert(hashed_address, (*node).clone());
            }
        }

        Ok(ExecutionWitness {
            codes: self.codes.into_iter().map(|b| b.to_vec()).collect(),
            chain_config,
            first_block_number,
            block_headers_bytes: self.headers.into_iter().map(|b| b.to_vec()).collect(),
            state_trie_root,
            storage_trie_roots,
        })
    }
}

impl ExecutionWitness {
    /// Build an `ExecutionWitness` from an SSZ stateless input. Used by the
    /// stateless validator (EXECUTE precompile and zkVM guest program).
    ///
    /// `first_block_number` is taken from the payload's block number, and
    /// `initial_state_root` is recovered by finding the parent header
    /// (`number == first_block_number - 1`) among the witness headers — same
    /// convention as `RpcExecutionWitness::into_execution_witness`.
    ///
    /// The `ChainConfig` is derived from the input's `chain_id` alone via
    /// [`amsterdam_chain_config`]; #3278 removed chain configuration from the
    /// wire, so the fork comes from the schema-id prefix instead.
    pub fn from_ssz(
        input: &crate::types::stateless_ssz::SszStatelessInput,
        crypto: &dyn Crypto,
    ) -> Result<Self, GuestProgramStateError> {
        let first_block_number = input.new_payload_request.execution_payload.block_number;

        // In wire order, before any sort or dedup: reordering hides violations.
        // Without this a witness whose headers do not form a chain is accepted,
        // and a guest that accepts a payload the spec rejects can prove an
        // invalid state transition (`test_validation_headers_non_contiguous_chain`).
        // Extracted once and reused: `headers_as_vecs` copies every header out of
        // the SSZ list (up to `MAX_WITNESS_HEADERS`), and the same bytes are also
        // what `block_headers_bytes` below is built from.
        let block_headers_bytes = input.witness.headers_as_vecs();
        let headers = decode_witness_headers(&block_headers_bytes)?;
        validate_witness_headers_chain(&headers, crypto)?;

        let initial_state_root = find_parent_state_root(&headers, first_block_number)?;

        let (state_trie_root, storage_trie_roots) = rebuild_state_and_storage_tries(
            input.witness.state_as_vecs(),
            initial_state_root,
            crypto,
        )?;

        Ok(Self {
            codes: input.witness.codes_as_vecs(),
            block_headers_bytes,
            first_block_number,
            chain_config: amsterdam_chain_config(input.chain_id),
            state_trie_root,
            storage_trie_roots,
        })
    }
}

/// Rebuild the embedded state trie and per-account storage tries from a flat
/// list of trie-node preimages (same format as `debug_executionWitness.state`
/// and SSZ `ExecutionWitness.state`).
fn rebuild_state_and_storage_tries<I, B>(
    state_bytes: I,
    initial_state_root: H256,
    crypto: &dyn Crypto,
) -> Result<(Option<Node>, BTreeMap<H256, Node>), GuestProgramStateError>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    // `crypto`, not the free `keccak`: on RISC-V the latter falls through to the
    // software `tiny_keccak` (see `ethrex_crypto::keccak`), so hashing every witness
    // node here would bypass the zkVM's accelerated keccak in the guest.
    let nodes: FxHashMap<H256, Node> = state_bytes
        .into_iter()
        .filter_map(|b| {
            let bytes = b.as_ref();
            // An entry that does not decode as a trie node is skipped rather
            // than rejected. Witnesses legitimately carry such entries: the
            // `Null` node (single byte 0x80) some `debug_executionWitness`
            // implementations emit, and unused nodes the spec explicitly
            // tolerates (`test_validation_state_extra_unused_trie_node`).
            //
            // Skipping is safe because it only makes a node unavailable. If the
            // trie walk actually needs it, `get_embedded_root` fails there — the
            // correct place to reject — and the post-execution state-root check
            // still binds the result either way. Hard-failing here rejected
            // witnesses the spec accepts.
            Some((H256(crypto.keccak256(bytes)), Node::decode(bytes).ok()?))
        })
        .collect();

    // `_committed` pre-seeds each node's hash slot, so later hashing of the subtree
    // reuses the known value instead of re-encoding and re-hashing the whole trie.
    // Sound here because `nodes` is keyed by the hash of the very bytes it decodes.
    let state_trie_root = if let NodeRef::Node(state_trie_root, _) =
        Trie::get_embedded_root_committed(&nodes, initial_state_root, crypto)?
    {
        Some((*state_trie_root).clone())
    } else {
        None
    };

    // Walk the state trie to discover accounts and their storage roots,
    // instead of relying on the keys field which is being removed from the
    // RPC spec.
    let mut storage_trie_roots = BTreeMap::new();
    if let Some(root) = &state_trie_root {
        let accounts = collect_accounts_from_embedded_trie(root, &nodes, crypto);
        for (hashed_address, storage_root_hash) in accounts {
            if storage_root_hash == EMPTY_TRIE_HASH || !nodes.contains_key(&storage_root_hash) {
                continue;
            }
            let node = Trie::get_embedded_root_committed(&nodes, storage_root_hash, crypto)?;
            let NodeRef::Node(node, _) = node else {
                return Err(GuestProgramStateError::Custom(
                    "execution witness does not contain non-empty storage trie".to_string(),
                ));
            };
            storage_trie_roots.insert(hashed_address, (*node).clone());
        }
    }

    Ok((state_trie_root, storage_trie_roots))
}

/// RLP-decode the raw header byte slices into a `Vec<BlockHeader>`.
pub fn decode_witness_headers<B: AsRef<[u8]>>(
    headers_bytes: &[B],
) -> Result<Vec<BlockHeader>, GuestProgramStateError> {
    headers_bytes
        .iter()
        .map(|b| BlockHeader::decode(b.as_ref()).map_err(GuestProgramStateError::from))
        .collect()
}

/// Locate the parent block's state root from a slice of decoded headers.
/// Returns an error if `first_block_number == 0` (no parent possible) or if the
/// parent header is not in the slice.
fn find_parent_state_root(
    headers: &[BlockHeader],
    first_block_number: u64,
) -> Result<H256, GuestProgramStateError> {
    let parent_number = first_block_number
        .checked_sub(1)
        .ok_or(GuestProgramStateError::Custom(
            "first_block_number must be > 0 (need parent header)".to_string(),
        ))?;
    headers
        .iter()
        .find(|h| h.number == parent_number)
        .map(|h| h.state_root)
        .ok_or_else(|| {
            GuestProgramStateError::Custom(format!("header for block {parent_number} not found"))
        })
}

/// Check that `headers[1..]` link via `parent_hash == keccak(RLP(prev))` AND
/// `number == prev.number + 1`, in input order. The first header is
/// intentionally unanchored here; the parent end is bound by the post-execution
/// state-root check in `execute_blocks`.
///
/// Call before any sort/dedup, since reordering hides violations.
pub fn validate_witness_headers_chain(
    headers: &[BlockHeader],
    crypto: &dyn Crypto,
) -> Result<(), GuestProgramStateError> {
    for pair in headers.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if prev.number.checked_add(1) != Some(next.number)
            || next.parent_hash != prev.compute_block_hash(crypto)
        {
            return Err(GuestProgramStateError::NoncontiguousBlockHeaders);
        }
    }
    Ok(())
}

/// Recursively walks an embedded state trie node and collects
/// `(hashed_address, storage_root)` pairs from leaf nodes.
fn collect_accounts_from_trie(
    node: &Node,
    path: Nibbles,
    accounts: &mut Vec<(H256, H256)>,
    nodes: &FxHashMap<H256, Node>,
    crypto: &dyn Crypto,
) {
    match node {
        Node::Branch(branch) => {
            for (i, child) in branch.choices.iter().enumerate() {
                let child_node: Option<&Node> = match child {
                    NodeRef::Node(n, _) => Some(n),
                    NodeRef::Hash(hash) if hash.is_valid() => nodes.get(&hash.finalize(crypto)),
                    _ => None,
                };
                if let Some(child_node) = child_node {
                    collect_accounts_from_trie(
                        child_node,
                        path.append_new(i as u8),
                        accounts,
                        nodes,
                        crypto,
                    );
                }
            }
        }
        Node::Extension(ext) => {
            let child_node: Option<&Node> = match &ext.child {
                NodeRef::Node(n, _) => Some(n),
                NodeRef::Hash(hash) if hash.is_valid() => nodes.get(&hash.finalize(crypto)),
                _ => None,
            };
            if let Some(child_node) = child_node {
                collect_accounts_from_trie(
                    child_node,
                    path.concat(&ext.prefix),
                    accounts,
                    nodes,
                    crypto,
                );
            }
        }
        Node::Leaf(leaf) => {
            let full_path = path.concat(&leaf.partial);
            let path_bytes = full_path.to_bytes();
            if path_bytes.len() == 32 {
                let hashed_address = H256::from_slice(&path_bytes);
                match AccountState::decode(&leaf.value) {
                    Ok(account_state) => {
                        accounts.push((hashed_address, account_state.storage_root));
                    }
                    Err(e) => {
                        tracing::debug!(
                            ?hashed_address,
                            error = %e,
                            "Skipping leaf with un-decodable account state"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    path_len = path_bytes.len(),
                    "Skipping leaf with unexpected path length (expected 32)"
                );
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GuestProgramStateError {
    #[error("Failed to rebuild tries: {0}")]
    RebuildTrie(String),
    #[error("Failed to apply account updates {0}")]
    ApplyAccountUpdates(String),
    #[error("DB error: {0}")]
    Database(String),
    #[error("No block headers stored, should at least store parent header")]
    NoBlockHeaders,
    #[error("Parent block header of block {0} was not found")]
    MissingParentHeaderOf(u64),
    #[error("Non-contiguous block headers")]
    NoncontiguousBlockHeaders,
    #[error("Bytecode for code hash {0} was not found in witness")]
    MissingBytecode(H256),
    #[error("Trie error: {0}")]
    Trie(#[from] TrieError),
    #[error("RLP Decode: {0}")]
    RLPDecode(#[from] RLPDecodeError),
    #[error("Unreachable code reached: {0}")]
    Unreachable(String),
    #[error("Custom error: {0}")]
    Custom(String),
}

impl GuestProgramState {
    pub fn from_witness(
        value: ExecutionWitness,
        crypto: &dyn Crypto,
    ) -> Result<Self, GuestProgramStateError> {
        let block_headers: BTreeMap<u64, BlockHeader> = value
            .block_headers_bytes
            .into_iter()
            .map(|bytes| BlockHeader::decode(bytes.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                GuestProgramStateError::Custom(format!("Failed to decode block headers: {}", e))
            })?
            .into_iter()
            .map(|header| (header.number, header))
            .collect();

        let parent_number =
            value
                .first_block_number
                .checked_sub(1)
                .ok_or(GuestProgramStateError::Custom(
                    "First block number cannot be zero".to_string(),
                ))?;

        let parent_header = block_headers.get(&parent_number).cloned().ok_or(
            GuestProgramStateError::MissingParentHeaderOf(value.first_block_number),
        )?;

        // hash state trie nodes
        let state_trie = if let Some(state_trie_root) = value.state_trie_root {
            Trie::new_temp_with_root(state_trie_root.into())
        } else {
            Trie::new_temp()
        };
        state_trie.hash_no_commit(crypto);

        let mut storage_tries = BTreeMap::new();
        for (hashed_address, storage_trie_root) in value.storage_trie_roots {
            // hash storage trie nodes
            let storage_trie = Trie::new_temp_with_root(storage_trie_root.into());
            storage_trie.hash_no_commit(crypto);
            storage_tries.insert(hashed_address, storage_trie);
        }

        // hash codes
        // TODO: codes here probably needs to be Vec<Code>, rather than recomputing here. This requires rkyv implementation.
        let codes_hashed = value
            .codes
            .into_iter()
            .map(|code| {
                let code = Code::from_bytecode(code.into(), crypto);
                (code.hash, code)
            })
            .collect();

        Ok(GuestProgramState {
            codes_hashed,
            state_trie,
            storage_tries,
            block_headers,
            parent_block_header: parent_header,
            first_block_number: value.first_block_number,
            chain_config: value.chain_config,
            account_hashes_by_address: BTreeMap::new(),
            verified_storage_roots: BTreeMap::new(),
        })
    }
}

impl GuestProgramState {
    /// Helper function to apply account updates to the execution witness
    /// It updates the state trie and storage tries with the given account updates
    /// Returns an error if the updates cannot be applied
    pub fn apply_account_updates(
        &mut self,
        account_updates: &[AccountUpdate],
        crypto: &dyn Crypto,
    ) -> Result<(), GuestProgramStateError> {
        for update in account_updates.iter() {
            let hashed_address = *self
                .account_hashes_by_address
                .entry(update.address)
                .or_insert_with(|| hash_address(&update.address, crypto));

            if update.removed {
                // Remove account from trie
                self.state_trie.remove(hashed_address.as_bytes())?;
            } else {
                // Add or update AccountState in the trie
                // Fetch current state or create a new state to be inserted
                let mut account_state = match self.state_trie.get(hashed_address.as_bytes())? {
                    Some(encoded_state) => AccountState::decode(&encoded_state)?,
                    None => AccountState::default(),
                };
                if update.removed_storage {
                    account_state.storage_root = EMPTY_TRIE_HASH;
                }
                if let Some(info) = &update.info {
                    account_state.nonce = info.nonce;
                    account_state.balance = info.balance;
                    account_state.code_hash = info.code_hash;
                    // Store updated code in DB
                    if let Some(code) = &update.code {
                        self.codes_hashed.insert(info.code_hash, code.clone());
                    }
                }
                // Store the added storage in the account's storage trie and compute its new root
                if !update.added_storage.is_empty() {
                    let storage_trie = self.storage_tries.entry(hashed_address).or_default();

                    // Inserts must come before deletes, otherwise deletes might require extra nodes
                    // Example:
                    // If I have a branch node [A, B] and want to delete A and insert C
                    // I will need to have B only if the deletion happens first
                    let (deletes, inserts): (Vec<_>, Vec<_>) = update
                        .added_storage
                        .iter()
                        .map(|(k, v)| (hash_key(k, crypto), v))
                        .partition(|(_k, v)| v.is_zero());

                    for (hashed_key, storage_value) in inserts {
                        storage_trie.insert(hashed_key, storage_value.encode_to_vec())?;
                    }

                    for (hashed_key, _) in deletes {
                        storage_trie.remove(&hashed_key)?;
                    }

                    let storage_root = storage_trie.hash_no_commit(crypto);
                    account_state.storage_root = storage_root;
                }

                self.state_trie.insert(
                    hashed_address.as_bytes().to_vec(),
                    account_state.encode_to_vec(),
                )?;
            }
        }
        Ok(())
    }

    /// Returns the root hash of the state trie
    /// Returns an error if the state trie is not built yet
    pub fn state_trie_root(&self, crypto: &dyn Crypto) -> Result<H256, GuestProgramStateError> {
        Ok(self.state_trie.hash_no_commit(crypto))
    }

    /// Returns Some(block_number) if the hash for block_number is not the parent
    /// hash of block_number + 1. None if there's no such hash.
    ///
    /// Keep in mind that the last block hash (which is a batch's parent hash)
    /// can't be validated against the next header, because it has no successor.
    pub fn get_first_invalid_block_hash(
        &self,
        crypto: &dyn Crypto,
    ) -> Result<Option<u64>, GuestProgramStateError> {
        // Enforces there's at least one block header, so windows() call doesn't panic.
        if self.block_headers.is_empty() {
            return Err(GuestProgramStateError::NoBlockHeaders);
        };

        // Sort in ascending order
        let mut block_headers: Vec<_> = self.block_headers.iter().collect();
        block_headers.sort_by_key(|(number, _)| *number);

        // Validate hashes
        for window in block_headers.windows(2) {
            let (Some((number, header)), Some((next_number, next_header))) =
                (window.first().cloned(), window.get(1).cloned())
            else {
                // windows() returns an empty iterator in this case.
                return Err(GuestProgramStateError::Unreachable(
                    "block header window len is < 2".to_string(),
                ));
            };
            if *next_number != *number + 1 {
                return Err(GuestProgramStateError::NoncontiguousBlockHeaders);
            }

            if next_header.parent_hash != header.compute_block_hash(crypto) {
                return Ok(Some(*number));
            }
        }

        Ok(None)
    }

    /// Retrieves the parent block header for the specified block number
    /// Searches within `self.block_headers`
    pub fn get_block_parent_header(
        &self,
        block_number: u64,
    ) -> Result<&BlockHeader, GuestProgramStateError> {
        self.block_headers
            .get(&block_number.saturating_sub(1))
            .ok_or(GuestProgramStateError::MissingParentHeaderOf(block_number))
    }

    /// Retrieves the account state from the state trie.
    /// Returns an error if decoding the account state fails.
    pub fn get_account_state(
        &mut self,
        address: Address,
        crypto: &dyn Crypto,
    ) -> Result<Option<AccountState>, GuestProgramStateError> {
        let hashed_address = *self
            .account_hashes_by_address
            .entry(address)
            .or_insert_with(|| hash_address(&address, crypto));

        let encoded_state = match self.state_trie.get(hashed_address.as_bytes()) {
            // The witness proves the account is absent.
            Ok(None) => return Ok(None),
            Ok(Some(encoded_state)) => encoded_state,
            // A missing trie node means the witness lacks the proof needed to
            // resolve this account. Surface it as an error rather than silently
            // treating the account as absent, otherwise a read of an unmodified
            // account (e.g. a failed CALL's target) would pass replay against an
            // incomplete witness (EIP-8025 `witness_validation_state` tests).
            Err(e) => return Err(GuestProgramStateError::Database(e.to_string())),
        };
        let state = AccountState::decode(&encoded_state).map_err(|_| {
            GuestProgramStateError::Database("Failed to get decode account from trie".to_string())
        })?;

        Ok(Some(state))
    }

    /// Fetches the block hash for a specific block number.
    /// Looks up `self.block_headers` and computes the hash if it is not already computed.
    pub fn get_block_hash(
        &self,
        block_number: u64,
        crypto: &dyn Crypto,
    ) -> Result<H256, GuestProgramStateError> {
        self.block_headers
            .get(&block_number)
            .map(|header| header.compute_block_hash(crypto))
            .ok_or_else(|| {
                GuestProgramStateError::Database(format!(
                    "Block hash not found for block number {block_number}"
                ))
            })
    }

    /// Retrieves a storage slot value for an account in its storage trie.
    pub fn get_storage_slot(
        &mut self,
        address: Address,
        key: H256,
        crypto: &dyn Crypto,
    ) -> Result<Option<U256>, GuestProgramStateError> {
        let hashed_key = hash_key(&key, crypto);
        let Some(storage_trie) = self.get_valid_storage_trie(address, crypto)? else {
            return Ok(None);
        };
        if let Some(encoded_key) = storage_trie
            .get(&hashed_key)
            .map_err(|e| GuestProgramStateError::Database(e.to_string()))?
        {
            U256::decode(&encoded_key)
                .map_err(|_| {
                    GuestProgramStateError::Database("failed to read storage from trie".to_string())
                })
                .map(Some)
        } else {
            Ok(None)
        }
    }

    /// Retrieves the chain configuration for the execution witness.
    pub fn get_chain_config(&self) -> Result<ChainConfig, GuestProgramStateError> {
        Ok(self.chain_config)
    }

    /// Retrieves the account code for a specific account.
    ///
    /// A missing code hash is always an error: ethrex's own witness producers
    /// include every byte of code the VM reads, and EIP-8025 stateless
    /// validation requires the same.
    pub fn get_account_code(&self, code_hash: H256) -> Result<Code, GuestProgramStateError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(Code::default());
        }
        self.codes_hashed
            .get(&code_hash)
            .cloned()
            .ok_or(GuestProgramStateError::MissingBytecode(code_hash))
    }

    /// Retrieves code metadata (length) for a specific code hash.
    /// This is an optimized path for EXTCODESIZE opcode.
    pub fn get_code_metadata(
        &self,
        code_hash: H256,
    ) -> Result<CodeMetadata, GuestProgramStateError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(CodeMetadata { length: 0 });
        }
        self.codes_hashed
            .get(&code_hash)
            .map(|code| CodeMetadata {
                length: code.len() as u64,
            })
            .ok_or(GuestProgramStateError::MissingBytecode(code_hash))
    }

    /// When executing multiple blocks in the L2 it happens that the headers in block_headers correspond to the same block headers that we have in the blocks array. The main goal is to hash these only once and set them in both places.
    /// We also initialize the remaining block headers hashes. If they are set, we check their validity.
    pub fn initialize_block_header_hashes(
        &self,
        blocks: &[Block],
        crypto: &dyn Crypto,
    ) -> Result<(), GuestProgramStateError> {
        let mut block_numbers_in_common = BTreeSet::new();
        for block in blocks {
            let hash = block.header.compute_block_hash(crypto);
            set_hash_or_validate(&block.header, hash)?;

            let number = block.header.number;
            if let Some(header) = self.block_headers.get(&number) {
                block_numbers_in_common.insert(number);
                set_hash_or_validate(header, hash)?;
            }
        }

        for header in self.block_headers.values() {
            if block_numbers_in_common.contains(&header.number) {
                // We have already set this hash in the previous step
                continue;
            }
            let hash = header.compute_block_hash(crypto);
            set_hash_or_validate(header, hash)?;
        }

        Ok(())
    }

    pub fn get_valid_storage_trie(
        &mut self,
        address: Address,
        crypto: &dyn Crypto,
    ) -> Result<Option<&Trie>, GuestProgramStateError> {
        let hashed_address = *self
            .account_hashes_by_address
            .entry(address)
            .or_insert_with(|| hash_address(&address, crypto));

        let is_storage_verified = *self
            .verified_storage_roots
            .get(&hashed_address)
            .unwrap_or(&false);
        if is_storage_verified {
            Ok(self.storage_tries.get(&hashed_address))
        } else {
            let Some(storage_root) = self
                .get_account_state(address, crypto)?
                .map(|a| a.storage_root)
            else {
                // empty account
                return Ok(None);
            };
            let storage_trie = match self.storage_tries.get(&hashed_address) {
                None if storage_root == EMPTY_TRIE_HASH => return Ok(None),
                Some(trie) if trie.hash_no_commit(crypto) == storage_root => trie,
                _ => {
                    return Err(GuestProgramStateError::Custom(format!(
                        "invalid storage trie for account {address}"
                    )));
                }
            };
            self.verified_storage_roots.insert(hashed_address, true);
            Ok(Some(storage_trie))
        }
    }
}

/// Walk an embedded state trie and collect `(hashed_address, storage_root)` pairs
/// from leaf nodes. Resolves `NodeRef::Hash` references using the flat `nodes` map.
///
/// BTreeMap-based counterpart of the `FxHashMap`-based `collect_accounts_from_trie`
/// used by `into_execution_witness`; this one backs the SSZ `from_ssz` path.
pub fn collect_accounts_from_embedded_trie(
    root: &Node,
    nodes: &FxHashMap<H256, Node>,
    crypto: &dyn Crypto,
) -> Vec<(H256, H256)> {
    let mut accounts = Vec::new();
    collect_accounts_from_node(root, Nibbles::default(), &mut accounts, nodes, crypto);
    accounts
}

fn collect_accounts_from_node(
    node: &Node,
    path: ethrex_trie::Nibbles,
    accounts: &mut Vec<(H256, H256)>,
    nodes: &FxHashMap<H256, Node>,
    crypto: &dyn Crypto,
) {
    use ethrex_trie::NodeRef;

    match node {
        Node::Branch(branch) => {
            for (i, child) in branch.choices.iter().enumerate() {
                let child_node: Option<&Node> = match child {
                    NodeRef::Node(n, _) => Some(n),
                    NodeRef::Hash(hash) if hash.is_valid() => nodes.get(&hash.finalize(crypto)),
                    _ => None,
                };
                if let Some(child_node) = child_node {
                    collect_accounts_from_node(
                        child_node,
                        path.append_new(i as u8),
                        accounts,
                        nodes,
                        crypto,
                    );
                }
            }
        }
        Node::Extension(ext) => {
            let child_node: Option<&Node> = match &ext.child {
                NodeRef::Node(n, _) => Some(n),
                NodeRef::Hash(hash) if hash.is_valid() => nodes.get(&hash.finalize(crypto)),
                _ => None,
            };
            if let Some(child_node) = child_node {
                collect_accounts_from_node(
                    child_node,
                    path.concat(&ext.prefix),
                    accounts,
                    nodes,
                    crypto,
                );
            }
        }
        Node::Leaf(leaf) => {
            let full_path = path.concat(&leaf.partial);
            let path_bytes = full_path.to_bytes();
            if path_bytes.len() == 32 {
                let hashed_address = H256::from_slice(&path_bytes);
                match AccountState::decode(&leaf.value) {
                    Ok(account_state) => {
                        accounts.push((hashed_address, account_state.storage_root));
                    }
                    Err(e) => {
                        tracing::debug!(
                            ?hashed_address,
                            error = %e,
                            "Skipping leaf with un-decodable account state"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    path_len = path_bytes.len(),
                    "Skipping leaf with unexpected path length (expected 32)"
                );
            }
        }
    }
}

fn hash_address(address: &Address, crypto: &dyn Crypto) -> H256 {
    H256(crypto.keccak256(&address.to_fixed_bytes()))
}

pub fn hash_key(key: &H256, crypto: &dyn Crypto) -> Vec<u8> {
    crypto.keccak256(&key.to_fixed_bytes()).to_vec()
}

/// Initializes hash of header or validates the hash is correct in case it's already set
/// Note that header doesn't need to be mutable because the hash is a OnceCell
fn set_hash_or_validate(header: &BlockHeader, hash: H256) -> Result<(), GuestProgramStateError> {
    // If it's already set the .set() method will return the current value
    if let Err(prev_hash) = header.hash.set(hash)
        && prev_hash != hash
    {
        return Err(GuestProgramStateError::Custom(format!(
            "Block header hash was previously set for {} with the wrong value. It should be set correctly or left unset.",
            header.number
        )));
    }
    Ok(())
}

/// Build the `ChainConfig` for a stateless input, from its `chain_id` alone.
///
/// execution-specs #3278 removed `ChainConfig` from the wire: activation info and
/// blob schedules are guest-internal knowledge, keyed by `(chain_id, fork)`, with
/// the fork fixed by the schema-id prefix — always Amsterdam (`0x1501`) at that
/// pin, since `deserialize_stateless_input` rejects every other id.
///
/// Every fork up to and including Amsterdam is activated at 0 and no
/// payload-timestamp-versus-activation check is performed. That mirrors EEST,
/// which ships one implementation per fork and therefore skips the check — and
/// matching it is what keeps ethrex byte-identical to the conformance vectors
/// generated from the reference.
///
/// TODO(upstream): `verify_stateless_new_payload` in `stateless.py` comments that
/// "a real implementation MUST do these checks", but #3278 leaves no activation
/// data on the wire to check against. Revisit if upstream reintroduces one, or
/// specifies where a real client should source it. See
/// https://github.com/ethereum/execution-specs/pull/3278
pub fn amsterdam_chain_config(chain_id: u64) -> ChainConfig {
    ChainConfig {
        chain_id,
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
        terminal_total_difficulty: Some(0),
        terminal_total_difficulty_passed: true,
        shanghai_time: Some(0),
        cancun_time: Some(0),
        prague_time: Some(0),
        osaka_time: Some(0),
        // The BPO forks must be activated too, not just the named ones. EIP-7892
        // gives named forks no blob params of their own: `get_fork_blob_schedule`
        // walks the BPO chain and Amsterdam inherits the highest activated entry.
        // Leaving these `None` made that walk fall through to Osaka's schedule
        // (target 6 / max 9 / fraction 5007716) instead of BPO2's (14 / 21 /
        // 11684671), so the guest recomputed a different `excess_blob_gas` than
        // the header carried and rejected valid blob-bearing blocks with
        // `ExcessBlobGasIncorrect`.
        //
        // Only BPO1 and BPO2, matching the `AMSTERDAM_CONFIG` these fixtures are
        // filled against. BPO3-5 have no default `blob_schedule` entry, and a BPO
        // time set without one is rejected as invalid genesis config
        // (`genesis.rs`), so activating them would be both wrong and unresolvable.
        // `hegota`/`lstar` stay unset: they are later than Amsterdam.
        bpo1_time: Some(0),
        bpo2_time: Some(0),
        amsterdam_time: Some(0),
        // NOT `Default` (which is `Address::zero()`). `Requests::from_deposit_receipts`
        // selects deposit logs by `log.address == deposit_contract_address`, so a zero
        // address matches nothing: every deposit in the block is dropped, the recomputed
        // `requests_hash` disagrees with the header's, and a valid block is committed as
        // `successful_validation = false`. The conformance set is
        // `eip8025_optional_proofs`, which carries no deposit case, so no fixture covers
        // this — see `amsterdam_chain_config_sets_deposit_contract` below.
        //
        // #3278 leaves only `chain_id` on the wire, so this cannot be chain-specific.
        // Mainnet's address is used, which is also what EEST fills against
        // (`tooling/ef_tests/blockchain/fork.rs`).
        deposit_contract_address: crate::constants::MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        ..Default::default()
    }
}

#[cfg(test)]
mod amsterdam_chain_config_tests {
    use super::*;

    #[test]
    fn activates_every_fork_through_amsterdam_at_zero() {
        let cfg = amsterdam_chain_config(1);
        assert_eq!(cfg.chain_id, 1);
        for (name, v) in [
            ("shanghai", cfg.shanghai_time),
            ("cancun", cfg.cancun_time),
            ("prague", cfg.prague_time),
            ("osaka", cfg.osaka_time),
            ("amsterdam", cfg.amsterdam_time),
        ] {
            assert_eq!(v, Some(0), "{name} must be active from 0");
        }
        assert!(cfg.terminal_total_difficulty_passed);
    }

    /// Forks past Amsterdam must stay unscheduled: the schema id pins Amsterdam,
    /// so activating a later fork would apply rules the input never asked for.
    #[test]
    fn leaves_post_amsterdam_forks_unscheduled() {
        let cfg = amsterdam_chain_config(1);
        assert_eq!(cfg.hegota_time, None);
        assert_eq!(cfg.lstar_time, None);
    }

    /// Amsterdam must resolve to BPO2's blob schedule, not Osaka's.
    ///
    /// EIP-7892 gives named forks no blob params of their own, so
    /// `get_fork_blob_schedule` walks the BPO chain and Amsterdam inherits the
    /// highest activated entry. When `bpo1_time`/`bpo2_time` were left `None`
    /// here that walk fell through to Osaka, and the guest recomputed
    /// `excess_blob_gas` against target 6 instead of 14 — rejecting valid
    /// blob-bearing blocks with `ExcessBlobGasIncorrect` while the stateful path,
    /// which gets a config with the BPO times set, accepted them. It cost 18
    /// fixture files in the stateless EF run.
    #[test]
    fn resolves_the_bpo2_blob_schedule_at_amsterdam() {
        let cfg = amsterdam_chain_config(1);
        let schedule = cfg
            .get_fork_blob_schedule(0)
            .expect("Amsterdam must resolve a blob schedule");
        let bpo2 = crate::types::BlobSchedule::default().bpo2;
        assert_eq!(
            schedule, bpo2,
            "Amsterdam must inherit BPO2's blob schedule; falling through to \
             Osaka's changes target/max and the base-fee update fraction"
        );
    }

    #[test]
    fn carries_the_chain_id_through() {
        assert_eq!(amsterdam_chain_config(u64::MAX).chain_id, u64::MAX);
    }

    /// A zero `deposit_contract_address` silently drops every deposit in a block:
    /// `Requests::from_deposit_receipts` filters logs by that address, so the
    /// recomputed `requests_hash` disagrees with the header's and the guest commits
    /// `successful_validation = false` for a valid block. The
    /// `eip8025_optional_proofs` conformance set has no deposit case, so this test
    /// is the only thing standing between that and a silent regression.
    #[test]
    fn amsterdam_chain_config_sets_deposit_contract() {
        let config = amsterdam_chain_config(1);
        assert_ne!(
            config.deposit_contract_address,
            crate::Address::zero(),
            "a zero deposit contract address makes every deposit-bearing block invalid"
        );
        assert_eq!(
            config.deposit_contract_address,
            crate::constants::MAINNET_DEPOSIT_CONTRACT_ADDRESS
        );
    }
}
