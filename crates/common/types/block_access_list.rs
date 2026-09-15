use bytes::Bytes;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use ethrex_rlp::{
    decode::RLPDecode,
    encode::{RLPEncode, backpatch_list_prefix},
    structs,
};
use indexmap::{IndexMap, IndexSet};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::constants::{EMPTY_BLOCK_ACCESS_LIST_HASH, SYSTEM_ADDRESS};
use crate::types::Code;
use crate::utils::{keccak, u256_to_h256};

/// Encode a slice of items in sorted order without cloning.
fn encode_sorted_by<T, K, F>(items: &[T], buf: &mut Vec<u8>, key_fn: F)
where
    T: RLPEncode,
    K: Ord,
    F: Fn(&T) -> K,
{
    if items.is_empty() {
        buf.push(0xc0);
        return;
    }
    let mut indices: Vec<usize> = (0..items.len()).collect();
    indices.sort_by(|&i, &j| key_fn(&items[i]).cmp(&key_fn(&items[j])));

    // Encode the payload first and fill the prefix in afterwards. The
    // `length()` pre-pass this replaces re-encoded every item, and for the
    // types in this module `length()` is the allocating default.
    let start = buf.len();
    for &i in &indices {
        items[i].encode(buf);
    }
    backpatch_list_prefix(buf, start);
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct StorageChange {
    /// Block access index per EIP-7928 spec (uint32).
    pub block_access_index: u32,
    pub post_value: U256,
}

impl StorageChange {
    /// Creates a new storage change with the given block access index and post value.
    pub fn new(block_access_index: u32, post_value: U256) -> Self {
        Self {
            block_access_index,
            post_value,
        }
    }
}

impl RLPEncode for StorageChange {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.block_access_index)
            .encode_field(&self.post_value)
            .finish();
    }
}

impl RLPDecode for StorageChange {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let decoder = structs::Decoder::new(rlp)?;
        let (block_access_index, decoder) = decoder.decode_field("block_access_index")?;
        let (post_value, decoder) = decoder.decode_field("post_value")?;
        let remaining = decoder.finish()?;
        Ok((
            Self {
                block_access_index,
                post_value,
            },
            remaining,
        ))
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SlotChange {
    pub slot: U256,
    pub slot_changes: Vec<StorageChange>,
}

impl SlotChange {
    /// Creates a new slot change for the given slot.
    pub fn new(slot: U256) -> Self {
        Self {
            slot,
            slot_changes: Vec::new(),
        }
    }

    /// Creates a new slot change with the given slot and changes.
    pub fn with_changes(slot: U256, changes: Vec<StorageChange>) -> Self {
        Self {
            slot,
            slot_changes: changes,
        }
    }

    /// Adds a storage change to this slot.
    pub fn add_change(&mut self, change: StorageChange) {
        self.slot_changes.push(change);
    }
}

impl RLPEncode for SlotChange {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        self.slot.encode(buf);
        encode_sorted_by(&self.slot_changes, buf, |s| s.block_access_index);
        backpatch_list_prefix(buf, start);
    }
}

impl RLPDecode for SlotChange {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let decoder = structs::Decoder::new(rlp)?;
        let (slot, decoder) = decoder.decode_field("slot")?;
        let (slot_changes, decoder) = decoder.decode_field("slot_changes")?;
        let remaining = decoder.finish()?;
        Ok((Self { slot, slot_changes }, remaining))
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct BalanceChange {
    /// Block access index per EIP-7928 spec (uint32).
    pub block_access_index: u32,
    pub post_balance: U256,
}

impl BalanceChange {
    /// Creates a new balance change with the given block access index and post balance.
    pub fn new(block_access_index: u32, post_balance: U256) -> Self {
        Self {
            block_access_index,
            post_balance,
        }
    }
}

impl RLPEncode for BalanceChange {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.block_access_index)
            .encode_field(&self.post_balance)
            .finish();
    }
}

impl RLPDecode for BalanceChange {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let decoder = structs::Decoder::new(rlp)?;
        let (block_access_index, decoder) = decoder.decode_field("block_access_index")?;
        let (post_balance, decoder) = decoder.decode_field("post_balance")?;
        let remaining = decoder.finish()?;
        Ok((
            Self {
                block_access_index,
                post_balance,
            },
            remaining,
        ))
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct NonceChange {
    /// Block access index per EIP-7928 spec (uint32).
    pub block_access_index: u32,
    pub post_nonce: u64,
}

impl NonceChange {
    /// Creates a new nonce change with the given block access index and post nonce.
    pub fn new(block_access_index: u32, post_nonce: u64) -> Self {
        Self {
            block_access_index,
            post_nonce,
        }
    }
}

impl RLPEncode for NonceChange {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.block_access_index)
            .encode_field(&self.post_nonce)
            .finish();
    }
}

impl RLPDecode for NonceChange {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let decoder = structs::Decoder::new(rlp)?;
        let (block_access_index, decoder) = decoder.decode_field("block_access_index")?;
        let (post_nonce, decoder) = decoder.decode_field("post_nonce")?;
        let remaining = decoder.finish()?;
        Ok((
            Self {
                block_access_index,
                post_nonce,
            },
            remaining,
        ))
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CodeChange {
    /// Block access index per EIP-7928 spec (uint32).
    pub block_access_index: u32,
    pub new_code: Bytes,
}

impl CodeChange {
    /// Creates a new code change with the given block access index and new code.
    pub fn new(block_access_index: u32, new_code: Bytes) -> Self {
        Self {
            block_access_index,
            new_code,
        }
    }
}

impl RLPEncode for CodeChange {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.block_access_index)
            .encode_field(&self.new_code)
            .finish();
    }
}

impl RLPDecode for CodeChange {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let decoder = structs::Decoder::new(rlp)?;
        let (block_access_index, decoder) = decoder.decode_field("block_access_index")?;
        let (new_code, decoder) = decoder.decode_field("new_code")?;
        let remaining = decoder.finish()?;
        Ok((
            Self {
                block_access_index,
                new_code,
            },
            remaining,
        ))
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AccountChanges {
    pub address: Address,
    pub storage_changes: Vec<SlotChange>,
    pub storage_reads: Vec<U256>,
    pub balance_changes: Vec<BalanceChange>,
    pub nonce_changes: Vec<NonceChange>,
    pub code_changes: Vec<CodeChange>,
}

impl AccountChanges {
    /// Creates a new account changes struct for the given address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            storage_changes: Vec::new(),
            storage_reads: Vec::new(),
            balance_changes: Vec::new(),
            nonce_changes: Vec::new(),
            code_changes: Vec::new(),
        }
    }

    pub fn with_storage_changes(mut self, changes: Vec<SlotChange>) -> Self {
        self.storage_changes = changes;
        self
    }

    pub fn with_storage_reads(mut self, reads: Vec<U256>) -> Self {
        self.storage_reads = reads;
        self
    }

    pub fn with_balance_changes(mut self, changes: Vec<BalanceChange>) -> Self {
        self.balance_changes = changes;
        self
    }

    pub fn with_nonce_changes(mut self, changes: Vec<NonceChange>) -> Self {
        self.nonce_changes = changes;
        self
    }

    pub fn with_code_changes(mut self, changes: Vec<CodeChange>) -> Self {
        self.code_changes = changes;
        self
    }

    /// Adds a slot change (storage write) to this account.
    pub fn add_storage_change(&mut self, slot_change: SlotChange) {
        self.storage_changes.push(slot_change);
    }

    /// Adds a storage read (slot that was only read, not written) to this account.
    pub fn add_storage_read(&mut self, slot: U256) {
        self.storage_reads.push(slot);
    }

    /// Adds a balance change to this account.
    pub fn add_balance_change(&mut self, change: BalanceChange) {
        self.balance_changes.push(change);
    }

    /// Adds a nonce change to this account.
    pub fn add_nonce_change(&mut self, change: NonceChange) {
        self.nonce_changes.push(change);
    }

    /// Adds a code change to this account.
    pub fn add_code_change(&mut self, change: CodeChange) {
        self.code_changes.push(change);
    }

    /// Returns an iterator over all storage slots that need prefetching
    /// (both reads and writes need their pre-state loaded).
    pub fn all_storage_slots(&self) -> impl Iterator<Item = U256> + '_ {
        self.storage_reads
            .iter()
            .copied()
            .chain(self.storage_changes.iter().map(|sc| sc.slot))
    }

    /// Returns whether this account has any changes or reads.
    pub fn is_empty(&self) -> bool {
        self.storage_changes.is_empty()
            && self.storage_reads.is_empty()
            && self.balance_changes.is_empty()
            && self.nonce_changes.is_empty()
            && self.code_changes.is_empty()
    }
}

impl RLPEncode for AccountChanges {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        self.address.encode(buf);
        encode_sorted_by(&self.storage_changes, buf, |s| s.slot);
        encode_sorted_by(&self.storage_reads, buf, |s| *s);
        encode_sorted_by(&self.balance_changes, buf, |b| b.block_access_index);
        encode_sorted_by(&self.nonce_changes, buf, |n| n.block_access_index);
        encode_sorted_by(&self.code_changes, buf, |c| c.block_access_index);
        backpatch_list_prefix(buf, start);
    }
}

impl RLPDecode for AccountChanges {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let decoder = structs::Decoder::new(rlp)?;
        let (address, decoder) = decoder.decode_field("address")?;
        let (storage_changes, decoder) = decoder.decode_field("storage_changes")?;
        let (storage_reads, decoder) = decoder.decode_field("storage_reads")?;
        let (balance_changes, decoder) = decoder.decode_field("balance_changes")?;
        let (nonce_changes, decoder) = decoder.decode_field("nonce_changes")?;
        let (code_changes, decoder) = decoder.decode_field("code_changes")?;
        let remaining = decoder.finish()?;
        Ok((
            Self {
                address,
                storage_changes,
                storage_reads,
                balance_changes,
                nonce_changes,
                code_changes,
            },
            remaining,
        ))
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct BlockAccessList {
    inner: Vec<AccountChanges>,
}

impl BlockAccessList {
    /// Creates a new empty block access list.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Creates a block access list from a vector of account changes.
    pub fn from_accounts(accounts: Vec<AccountChanges>) -> Self {
        Self { inner: accounts }
    }

    /// Creates a new block access list with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Adds an account changes entry to the block access list.
    pub fn add_account_changes(&mut self, changes: AccountChanges) {
        self.inner.push(changes);
    }

    /// Returns true if the BAL is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns an iterator over account changes.
    pub fn accounts(&self) -> &[AccountChanges] {
        &self.inner
    }

    /// Computes the number of BAL items per EIP-7928 size cap.
    /// bal_items = addresses + storage_slots (unique slots, not individual operations)
    pub fn item_count(&self) -> u64 {
        let mut count: u64 = 0;
        for account in &self.inner {
            count += 1; // address
            count += account.storage_reads.len() as u64;
            count += account.storage_changes.len() as u64;
        }
        count
    }

    /// Validates that the BAL has canonical ordering per EIP-7928.
    /// - Accounts must be in strictly ascending order by address.
    /// - Within each account: storage_changes by slot, storage_reads by slot value,
    ///   slot_changes/balance_changes/nonce_changes/code_changes by block_access_index.
    ///
    /// Returns an error string describing the first violation found.
    pub fn validate_ordering(&self) -> Result<(), String> {
        let mut prev_addr = None;
        for account in &self.inner {
            if let Some(prev) = prev_addr
                && prev >= account.address
            {
                return Err(format!(
                    "Block access list accounts not in strictly ascending order: \
                     {:#x} >= {:#x}",
                    prev, account.address
                ));
            }
            prev_addr = Some(account.address);

            for window in account.storage_changes.windows(2) {
                if window[0].slot >= window[1].slot {
                    return Err(format!(
                        "Block access list storage_changes not in strictly ascending order \
                         for account {:#x}: {:#x} >= {:#x}",
                        account.address, window[0].slot, window[1].slot
                    ));
                }
            }
            for slot_change in &account.storage_changes {
                // EIP-7928: a slot listed in storage_changes must carry at least one
                // change; an empty slot_changes set is a malformed (no-op) entry.
                if slot_change.slot_changes.is_empty() {
                    return Err(format!(
                        "Block access list storage_changes slot {:#x} for account {:#x} \
                         has an empty change set",
                        slot_change.slot, account.address
                    ));
                }
                for window in slot_change.slot_changes.windows(2) {
                    if window[0].block_access_index >= window[1].block_access_index {
                        return Err(format!(
                            "Block access list slot_changes not in strictly ascending order \
                             for account {:#x} slot {:#x}: {} >= {}",
                            account.address,
                            slot_change.slot,
                            window[0].block_access_index,
                            window[1].block_access_index
                        ));
                    }
                }
            }
            for window in account.storage_reads.windows(2) {
                if window[0] >= window[1] {
                    return Err(format!(
                        "Block access list storage_reads not in strictly ascending order \
                         for account {:#x}: {:#x} >= {:#x}",
                        account.address, window[0], window[1]
                    ));
                }
            }
            // Check no slot is in both storage_changes and storage_reads
            for sr_slot in &account.storage_reads {
                let pos = account
                    .storage_changes
                    .partition_point(|sc| sc.slot < *sr_slot);
                if pos < account.storage_changes.len()
                    && account.storage_changes[pos].slot == *sr_slot
                {
                    return Err(format!(
                        "Block access list slot {:#x} is in both storage_changes and \
                         storage_reads for account {:#x}",
                        sr_slot, account.address
                    ));
                }
            }
            for window in account.balance_changes.windows(2) {
                if window[0].block_access_index >= window[1].block_access_index {
                    return Err(format!(
                        "Block access list balance_changes not in strictly ascending order \
                         for account {:#x}: {} >= {}",
                        account.address, window[0].block_access_index, window[1].block_access_index
                    ));
                }
            }
            for window in account.nonce_changes.windows(2) {
                if window[0].block_access_index >= window[1].block_access_index {
                    return Err(format!(
                        "Block access list nonce_changes not in strictly ascending order \
                         for account {:#x}: {} >= {}",
                        account.address, window[0].block_access_index, window[1].block_access_index
                    ));
                }
            }
            for window in account.code_changes.windows(2) {
                if window[0].block_access_index >= window[1].block_access_index {
                    return Err(format!(
                        "Block access list code_changes not in strictly ascending order \
                         for account {:#x}: {} >= {}",
                        account.address, window[0].block_access_index, window[1].block_access_index
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns true if this BAL matches the header's EIP-8159 commitment
    /// (`block_access_list_hash`). Used to gate persisting/serving a BAL so a
    /// stale or regenerated-against-wrong-state BAL is never handed to peers as
    /// if it were authoritative; callers degrade to the `0x80` "unavailable"
    /// sentinel on a `false` here.
    pub fn matches_commitment(
        &self,
        commitment: Option<H256>,
        crypto: &dyn ethrex_crypto::Crypto,
    ) -> bool {
        commitment == Some(self.compute_hash(crypto))
    }

    /// Computes the hash of the block access list (sorts accounts by address per EIP-7928).
    /// Use this when hashing a BAL constructed locally from execution.
    pub fn compute_hash(&self, crypto: &dyn ethrex_crypto::Crypto) -> H256 {
        if self.inner.is_empty() {
            return *EMPTY_BLOCK_ACCESS_LIST_HASH;
        }

        let buf = self.encode_to_vec();
        H256(crypto.keccak256(&buf))
    }

    /// Builds a validation index for fast per-tx BAL verification.
    /// Call once per block before parallel execution.
    pub fn build_validation_index(&self) -> BalAddressIndex {
        // Cap the capacity hints derived from attacker-controlled lengths in a
        // supplied BAL. These are only pre-allocation hints — the collections
        // still grow to whatever a genuine block needs — but bounding them stops
        // a BAL padded with millions of (empty) accounts from forcing a huge
        // up-front allocation here, before the per-account and size-cap checks
        // downstream reject it. The block's own account count is far below this.
        const PREALLOC_CAP: usize = 8192;
        let mut addr_to_idx = FxHashMap::with_capacity_and_hasher(
            self.inner.len().min(PREALLOC_CAP),
            Default::default(),
        );
        let mut tx_to_accounts: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
        let mut accounts_by_min_index: Vec<(u32, usize)> = Vec::new();
        let mut slot_idx_by_account: Vec<FxHashMap<H256, usize>> =
            Vec::with_capacity(self.inner.len().min(PREALLOC_CAP));

        for (i, acct) in self.inner.iter().enumerate() {
            addr_to_idx.insert(acct.address, i);

            // Collect all block_access_indices where this account has changes
            let mut seen_indices = BTreeSet::new();
            for bc in &acct.balance_changes {
                seen_indices.insert(bc.block_access_index);
            }
            for nc in &acct.nonce_changes {
                seen_indices.insert(nc.block_access_index);
            }
            for cc in &acct.code_changes {
                seen_indices.insert(cc.block_access_index);
            }
            for sc in &acct.storage_changes {
                for change in &sc.slot_changes {
                    seen_indices.insert(change.block_access_index);
                }
            }

            if let Some(&min_idx) = seen_indices.iter().next() {
                accounts_by_min_index.push((min_idx, i));
            }

            for idx in seen_indices {
                tx_to_accounts.entry(idx).or_default().push(i);
            }

            // Per-account slot → storage_changes index map for O(1) lookup on
            // lazy-cursor cache miss. Empty for accounts with no storage writes.
            let mut slot_map: FxHashMap<H256, usize> = FxHashMap::with_capacity_and_hasher(
                acct.storage_changes.len().min(PREALLOC_CAP),
                Default::default(),
            );
            for (sc_idx, sc) in acct.storage_changes.iter().enumerate() {
                slot_map.insert(u256_to_h256(sc.slot), sc_idx);
            }
            slot_idx_by_account.push(slot_map);
        }

        accounts_by_min_index.sort_unstable_by_key(|(min_idx, _)| *min_idx);

        BalAddressIndex {
            addr_to_idx,
            tx_to_accounts,
            accounts_by_min_index,
            slot_idx_by_account,
        }
    }
}

/// Pre-computed index for fast per-tx BAL validation lookups.
/// Built once per block, shared read-only across parallel tx validations.
#[derive(Clone)]
pub struct BalAddressIndex {
    /// Maps each address in the BAL to its index in `BlockAccessList.inner`.
    pub addr_to_idx: FxHashMap<Address, usize>,
    /// For each block_access_index, the BAL-inner indices with changes at that index.
    pub tx_to_accounts: FxHashMap<u32, Vec<usize>>,
    /// BAL-inner indices sorted by their minimum block_access_index.
    /// Used by `seed_db_from_bal` to skip accounts with no changes at indices <= max_idx.
    /// Only includes accounts that have at least one mutation (balance/nonce/code/storage write).
    pub accounts_by_min_index: Vec<(u32, usize)>,
    /// Per-account slot → `storage_changes` index map. Lets `seed_one_storage_slot_from_bal`
    /// resolve a slot key to its `SlotChange` in O(1) instead of a linear scan. Indexed by
    /// the same `acct_idx` used by `addr_to_idx`; empty inner map for accounts with no
    /// storage writes. Slot uniqueness is enforced by canonical-ordering validation.
    pub slot_idx_by_account: Vec<FxHashMap<H256, usize>>,
}

/// Binary search for exact match at `idx` in balance changes (sorted by block_access_index).
pub fn find_exact_change_balance(changes: &[BalanceChange], idx: u32) -> Option<U256> {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    if pos < changes.len() && changes[pos].block_access_index == idx {
        Some(changes[pos].post_balance)
    } else {
        None
    }
}

/// Returns true if there is a balance change exactly at `idx`.
pub fn has_exact_change_balance(changes: &[BalanceChange], idx: u32) -> bool {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    pos < changes.len() && changes[pos].block_access_index == idx
}

/// Binary search for exact match at `idx` in nonce changes.
pub fn find_exact_change_nonce(changes: &[NonceChange], idx: u32) -> Option<u64> {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    if pos < changes.len() && changes[pos].block_access_index == idx {
        Some(changes[pos].post_nonce)
    } else {
        None
    }
}

/// Returns true if there is a nonce change exactly at `idx`.
pub fn has_exact_change_nonce(changes: &[NonceChange], idx: u32) -> bool {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    pos < changes.len() && changes[pos].block_access_index == idx
}

/// Binary search for exact match at `idx` in code changes.
pub fn find_exact_change_code(changes: &[CodeChange], idx: u32) -> Option<&Bytes> {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    if pos < changes.len() && changes[pos].block_access_index == idx {
        Some(&changes[pos].new_code)
    } else {
        None
    }
}

/// Returns true if there is a code change exactly at `idx`.
pub fn has_exact_change_code(changes: &[CodeChange], idx: u32) -> bool {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    pos < changes.len() && changes[pos].block_access_index == idx
}

/// Binary search for exact match at `idx` in storage changes.
pub fn find_exact_change_storage(changes: &[StorageChange], idx: u32) -> Option<U256> {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    if pos < changes.len() && changes[pos].block_access_index == idx {
        Some(changes[pos].post_value)
    } else {
        None
    }
}

/// Returns true if there is a storage change exactly at `idx`.
pub fn has_exact_change_storage(changes: &[StorageChange], idx: u32) -> bool {
    let pos = changes.partition_point(|c| c.block_access_index < idx);
    pos < changes.len() && changes[pos].block_access_index == idx
}

impl RLPEncode for BlockAccessList {
    fn encode(&self, buf: &mut Vec<u8>) {
        encode_sorted_by(&self.inner, buf, |a| a.address);
    }
}

impl RLPDecode for BlockAccessList {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), ethrex_rlp::error::RLPDecodeError> {
        let (inner, remaining) = RLPDecode::decode_unfinished(rlp)?;
        Ok((Self { inner }, remaining))
    }
}

/// A checkpoint of the BAL recorder state that can be restored on revert.
///
/// Per EIP-7928: "State changes from reverted calls are discarded, but all accessed
/// addresses must be included." This checkpoint captures the state change data
/// (storage, balance, nonce, code changes) but NOT touched_addresses, which persist
/// across reverts.
///
/// Implementation: each push to `balance_changes` / `nonce_changes` / `code_changes`
/// / `storage_writes` / `reads_promoted_to_writes` also appends a (addr, prev_len)
/// entry to a parallel journal Vec on the recorder. A checkpoint is an O(1) snapshot
/// of those journal lengths. Restore walks `journal[checkpoint_len..]` in reverse,
/// truncating each affected per-address Vec back to its `prev_len`. Cost is
/// O(reverted_entries), not O(total_writes_in_block) as the previous BTreeMap-clone
/// design.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockAccessListCheckpoint {
    balance_changes_journal_len: usize,
    nonce_changes_journal_len: usize,
    code_changes_journal_len: usize,
    storage_writes_journal_len: usize,
    reads_promoted_journal_len: usize,
}

/// Tx-level checkpoint for fully undoing a rejected transaction during block building.
///
/// Unlike [`BlockAccessListCheckpoint`] (for inner-call reverts), this captures the
/// full recorder state including touched addresses and storage reads, enabling complete
/// rollback without cloning the entire recorder.
#[derive(Debug)]
pub struct TxCheckpoint {
    inner: BlockAccessListCheckpoint,
    current_index: u32,
    touched_addresses_len: usize,
    storage_reads_lens: IndexMap<Address, usize>,
    initial_balances_len: usize,
    addresses_with_initial_code_len: usize,
}

/// Containers that support length-based truncation. Lets `walk_journal_simple`
/// work for both `Vec<_>` (change lists) and `IndexSet<_>` (promoted-reads
/// dedup set) without duplicating the journal walk.
trait TruncatableEmpty {
    fn truncate(&mut self, len: usize);
    fn is_empty(&self) -> bool;
}

impl<T> TruncatableEmpty for Vec<T> {
    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

impl<T: std::hash::Hash + Eq> TruncatableEmpty for IndexSet<T> {
    fn truncate(&mut self, len: usize) {
        IndexSet::truncate(self, len);
    }
    fn is_empty(&self) -> bool {
        IndexSet::is_empty(self)
    }
}

/// Records state accesses during block execution to build a Block Access List (EIP-7928).
///
/// The recorder accumulates all storage reads/writes, balance changes, nonce changes,
/// and code changes during execution. At the end, it can be converted into a `BlockAccessList`.
///
/// # Block Access Index Semantics
/// - 0: System contracts (pre-execution phase)
/// - 1..n: Transaction indices (1-indexed)
/// - n+1: Post-execution phase (withdrawals)
// Per-(address, slot) ordered list of writes recorded during execution.
type StorageWritesMap = BTreeMap<Address, BTreeMap<U256, Vec<(u32, U256)>>>;

#[derive(Debug, Default, Clone)]
pub struct BlockAccessListRecorder {
    /// Current block access index per EIP-7928 spec (uint32).
    /// 0=pre-exec, 1..n=tx indices, n+1=post-exec.
    current_index: u32,
    /// All addresses that must be in BAL (touched during execution).
    /// IndexSet for O(1) insert/lookup and length-based tx-level checkpoint/restore.
    touched_addresses: IndexSet<Address>,
    /// Storage reads per address (slot -> set of slots read but not written).
    /// IndexMap/IndexSet for length-based tx-level checkpoint/restore.
    storage_reads: IndexMap<Address, IndexSet<U256>>,
    /// Storage writes per address (slot -> list of (index, post_value) pairs).
    storage_writes: StorageWritesMap,
    /// Initial balances for detecting balance round-trips.
    /// IndexMap for length-based tx-level checkpoint/restore.
    initial_balances: IndexMap<Address, U256>,
    /// Per-transaction initial storage values for net-zero filtering.
    /// Per EIP-7928: "If a storage slot's value is changed but its post-transaction value
    /// is equal to its pre-transaction value, the slot MUST NOT be recorded as modified."
    /// Key is (address, slot), value is the pre-transaction value.
    /// Unordered: the only consumer (`filter_net_zero_storage`) does keyed
    /// lookups, and parallel BAL validation consumes it as an `FxHashMap`, so
    /// there is no ordering requirement.
    tx_initial_storage: FxHashMap<(Address, U256), U256>,
    /// Per-transaction initial code for net-zero filtering.
    /// Per EIP-7928: similar to storage, if code changes but post-transaction code equals
    /// pre-transaction code (e.g., delegate then reset), it MUST NOT be recorded.
    tx_initial_code: BTreeMap<Address, Bytes>,
    /// Balance changes per address (list of (index, post_balance) pairs).
    balance_changes: BTreeMap<Address, Vec<(u32, U256)>>,
    /// Nonce changes per address (list of (index, post_nonce) pairs).
    nonce_changes: BTreeMap<Address, Vec<(u32, u64)>>,
    /// Code changes per address (list of (index, new_code) pairs).
    code_changes: BTreeMap<Address, Vec<(u32, Bytes)>>,
    /// Addresses that had non-empty code at the start (before any code changes).
    /// IndexSet for length-based tx-level checkpoint/restore.
    addresses_with_initial_code: IndexSet<Address>,
    /// Tracks reads that were promoted to writes, in insertion order per address.
    /// Used for efficient checkpoint/restore without cloning storage_reads.
    /// On restore, we truncate this set and the slots go back to being reads.
    /// `IndexSet` gives O(1) membership for the dedup check in
    /// `record_storage_write` while keeping insertion-ordered truncation.
    reads_promoted_to_writes: BTreeMap<Address, IndexSet<U256>>,
    /// When true, SYSTEM_ADDRESS balance/nonce/touch changes are filtered out.
    /// Set during system contract calls (EIP-2935, EIP-4788, etc.) where the
    /// system address account is backed up and restored, so changes are transient.
    in_system_call: bool,

    // Journals supporting O(1) checkpoint() / O(reverted_entries) restore().
    // Each push to a change map appends one entry recording the address (and slot,
    // for storage_writes) plus the length of that per-address vec BEFORE the push,
    // so restore can walk the journal in reverse and truncate each affected vec.
    //
    // Journals are cleared in `set_block_access_index` between txs because
    // `filter_net_zero_*` mutates the change maps at that boundary, which would
    // make outstanding journal entries stale. No checkpoint can outlive a tx
    // boundary in practice — checkpoints are taken on CALL/CREATE frames and
    // `tx_checkpoint` is consumed (or not) before the next index advance.
    balance_changes_journal: Vec<(Address, usize)>,
    nonce_changes_journal: Vec<(Address, usize)>,
    code_changes_journal: Vec<(Address, usize)>,
    storage_writes_journal: Vec<(Address, U256, usize)>,
    reads_promoted_journal: Vec<(Address, usize)>,
}

impl BlockAccessListRecorder {
    /// Creates a new empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the current block access index per EIP-7928 spec (uint32).
    /// Call this before each transaction (index 1..n) and for withdrawals (n+1).
    ///
    /// Filters net-zero storage writes and code changes for the current transaction
    /// before switching to a new transaction index.
    pub fn set_block_access_index(&mut self, index: u32) {
        // Filter net-zero changes and clear per-transaction initial values when switching transactions
        if self.current_index != index {
            // Filter net-zero storage writes and code changes for the current transaction before switching
            self.filter_net_zero_storage();
            self.filter_net_zero_code();
            self.tx_initial_storage.clear();
            self.tx_initial_code.clear();
            // Clear restore journals: filter_net_zero_* mutates the change maps so
            // any outstanding journal entries are now stale. This is safe because no
            // checkpoint can outlive a tx boundary: inner-call `checkpoint`s are
            // consumed within the tx (success commits them, revert restores them);
            // `tx_checkpoint`s are consumed before the next `set_block_access_index`
            // call (success commits the tx, failure calls `tx_restore`).
            self.balance_changes_journal.clear();
            self.nonce_changes_journal.clear();
            self.code_changes_journal.clear();
            self.storage_writes_journal.clear();
            self.reads_promoted_journal.clear();
        }
        self.current_index = index;
    }

    /// Filters net-zero storage writes for the current transaction.
    /// Per EIP-7928: "If a storage slot's value is changed but its post-transaction value
    /// is equal to its pre-transaction value, the slot MUST NOT be recorded as modified."
    /// Net-zero writes are converted to reads instead.
    fn filter_net_zero_storage(&mut self) {
        let current_idx = self.current_index;

        // Collect slots that need to be converted from writes to reads
        let mut slots_to_convert: Vec<(Address, U256)> = Vec::new();

        for ((addr, slot), pre_value) in &self.tx_initial_storage {
            // Check if there are writes for this slot in the current transaction
            if let Some(slots) = self.storage_writes.get(addr)
                && let Some(changes) = slots.get(slot)
            {
                // Find the final value for this transaction
                // (last entry with current_idx, or no entry means no change in this tx)
                let final_value = changes
                    .iter()
                    .rfind(|(idx, _)| *idx == current_idx)
                    .map(|(_, val)| *val);

                if let Some(final_val) = final_value
                    && final_val == *pre_value
                {
                    // Net-zero: final value equals pre-transaction value
                    slots_to_convert.push((*addr, *slot));
                }
            }
        }

        // Convert net-zero writes to reads
        for (addr, slot) in slots_to_convert {
            // Remove the write entries for the current transaction
            if let Some(slots) = self.storage_writes.get_mut(&addr) {
                if let Some(changes) = slots.get_mut(&slot) {
                    changes.retain(|(idx, _)| *idx != current_idx);
                    // If no changes remain for this slot, remove the slot entry
                    if changes.is_empty() {
                        slots.remove(&slot);
                    }
                }
                // If no slots remain for this address, remove the address entry
                if slots.is_empty() {
                    self.storage_writes.remove(&addr);
                }
            }

            // If this slot was promoted from read to write, undo the promotion
            // so build() doesn't skip it from storage_reads.
            if let Some(promoted) = self.reads_promoted_to_writes.get_mut(&addr) {
                promoted.retain(|s| *s != slot);
                if promoted.is_empty() {
                    self.reads_promoted_to_writes.remove(&addr);
                }
            }

            // Add as a read instead
            self.storage_reads.entry(addr).or_default().insert(slot);
        }
    }

    /// Filters net-zero code changes for the current transaction.
    /// Per EIP-7928: similar to storage, if code changes but post-transaction code equals
    /// pre-transaction code (e.g., delegate then reset in same tx), it should not be recorded.
    fn filter_net_zero_code(&mut self) {
        let current_idx = self.current_index;

        // Collect addresses with net-zero code changes
        let mut addrs_to_remove: Vec<Address> = Vec::new();

        for (addr, pre_code) in &self.tx_initial_code {
            // Check if there are code changes for this address in the current transaction
            if let Some(changes) = self.code_changes.get(addr) {
                // Find the final code for this transaction
                let final_code = changes
                    .iter()
                    .filter(|(idx, _)| *idx == current_idx)
                    .last()
                    .map(|(_, code)| code);

                if let Some(final_code) = final_code
                    && final_code == pre_code
                {
                    // Net-zero: final code equals pre-transaction code
                    addrs_to_remove.push(*addr);
                }
            }
        }

        // Remove net-zero code changes
        for addr in addrs_to_remove {
            if let Some(changes) = self.code_changes.get_mut(&addr) {
                changes.retain(|(idx, _)| *idx != current_idx);
                // If no changes remain for this address, remove the address entry
                if changes.is_empty() {
                    self.code_changes.remove(&addr);
                }
            }
        }
    }

    /// Returns the current block access index per EIP-7928 spec (uint32).
    pub fn current_index(&self) -> u32 {
        self.current_index
    }

    /// Marks the recorder as being inside a system contract call.
    /// While in this mode, SYSTEM_ADDRESS balance/nonce/touch changes are filtered out
    /// because system calls backup and restore the system address account state.
    pub fn enter_system_call(&mut self) {
        self.in_system_call = true;
    }

    /// Marks the recorder as no longer inside a system contract call.
    pub fn exit_system_call(&mut self) {
        self.in_system_call = false;
    }

    /// Consumes and returns the touched-addresses set.
    /// Used by parallel BAL validation (shadow recorder) to diff against the header BAL.
    pub fn take_touched_addresses(&mut self) -> Vec<Address> {
        std::mem::take(&mut self.touched_addresses)
            .into_iter()
            .collect()
    }

    /// Consumes and returns recorded storage reads as `(address, slot)` pairs.
    /// Note: a slot that was read and then written stays in this set (promotion
    /// filtering only happens in `build()`); callers needing genuine pure reads
    /// must subtract the written slots (the keys of
    /// [`take_tx_initial_storage`](Self::take_tx_initial_storage)).
    pub fn take_storage_reads(&mut self) -> Vec<(Address, U256)> {
        let reads = std::mem::take(&mut self.storage_reads);
        let mut out = Vec::new();
        for (addr, slots) in reads {
            for slot in slots {
                out.push((addr, slot));
            }
        }
        out
    }

    /// Consumes and returns the per-tx captured start-of-tx storage values as a
    /// `(address, slot) -> pre_value` map. An entry is recorded (first-write-wins,
    /// via `capture_pre_storage`) the first time a slot's value genuinely changes
    /// during the tx, so `pre_value` is the value at the start of the tx and
    /// survives any intra-tx call-frame revert (`restore` never touches this map).
    /// It is cleared only when the whole tx is switched away from or aborted
    /// (`set_block_access_index` / `tx_restore`), so callers must consume it
    /// before the tx boundary.
    ///
    /// Parallel BAL validation uses this two ways: its keys are exactly the slots
    /// genuinely written (so `reads - keys` yields the pure reads), and the values
    /// are the start-of-tx seed for those slots — letting the validator reuse a
    /// value the EVM already computed instead of re-reading it from the store.
    pub fn take_tx_initial_storage(&mut self) -> FxHashMap<(Address, U256), U256> {
        std::mem::take(&mut self.tx_initial_storage)
    }

    /// Records an address as touched during execution.
    /// The address will appear in the BAL even if it has no state changes.
    ///
    /// Note: SYSTEM_ADDRESS is excluded during system contract calls.
    pub fn record_touched_address(&mut self, address: Address) {
        if address == SYSTEM_ADDRESS && self.in_system_call {
            return;
        }
        self.touched_addresses.insert(address);
    }

    /// Records multiple addresses as touched during execution.
    /// More efficient than calling `record_touched_address` in a loop.
    ///
    /// Note: SYSTEM_ADDRESS is filtered out during system contract calls.
    pub fn extend_touched_addresses(&mut self, addresses: impl Iterator<Item = Address>) {
        if self.in_system_call {
            self.touched_addresses
                .extend(addresses.filter(|addr| *addr != SYSTEM_ADDRESS));
        } else {
            self.touched_addresses.extend(addresses);
        }
    }

    /// Records a storage slot read.
    /// If the slot is later written, the read will be removed (it becomes a write).
    pub fn record_storage_read(&mut self, address: Address, slot: U256) {
        // Don't record as a read if it's already been written
        if self
            .storage_writes
            .get(&address)
            .is_some_and(|slots| slots.contains_key(&slot))
        {
            return;
        }
        self.storage_reads.entry(address).or_default().insert(slot);
        // Also mark the address as touched
        self.touched_addresses.insert(address);
    }

    /// Records a storage slot write.
    /// If the slot was previously recorded as a read, it is tracked as promoted
    /// (for efficient checkpoint/restore) but kept in storage_reads until build().
    ///
    /// Per EIP-7928: Multiple writes to the same slot within the same transaction
    /// (same block_access_index) only keep the final value.
    pub fn record_storage_write(&mut self, address: Address, slot: U256, post_value: U256) {
        // Track if this read is being promoted to a write (for checkpoint/restore)
        // We don't remove from storage_reads here - filtering happens in build()
        if self
            .storage_reads
            .get(&address)
            .is_some_and(|reads| reads.contains(&slot))
        {
            // Only track promotion if not already tracked. `IndexSet::insert`
            // returns true iff the slot is new, giving us O(1) dedup.
            let promoted = self.reads_promoted_to_writes.entry(address).or_default();
            let prev_len = promoted.len();
            if promoted.insert(slot) {
                self.reads_promoted_journal.push((address, prev_len));
            }
        }

        // Always push a new entry instead of updating in-place.
        // This is necessary for correct checkpoint/restore semantics:
        // restore() truncates the vector by length, so in-place updates
        // would corrupt values that should be preserved after a revert.
        let changes = self
            .storage_writes
            .entry(address)
            .or_default()
            .entry(slot)
            .or_default();

        let prev_len = changes.len();
        changes.push((self.current_index, post_value));
        self.storage_writes_journal.push((address, slot, prev_len));
        // Mark address as touched (include SYSTEM_ADDRESS for actual state changes)
        self.touched_addresses.insert(address);
    }

    /// Captures the pre-storage value for net-zero filtering.
    /// Should be called BEFORE writing to a storage slot, with the current value.
    /// Uses first-write-wins semantics: only the first call for a given (address, slot)
    /// within a transaction will be recorded.
    pub fn capture_pre_storage(&mut self, address: Address, slot: U256, value: U256) {
        // First-write-wins: only capture if not already captured for this transaction
        self.tx_initial_storage
            .entry((address, slot))
            .or_insert(value);
    }

    /// Records a balance change.
    /// Should be called after every balance modification.
    /// Per EIP-7928, only the final balance per (address, block_access_index) is recorded.
    /// If multiple balance changes occur within the same transaction, only the last one matters.
    /// Note: SYSTEM_ADDRESS balance changes are excluded during system contract calls
    /// (system calls backup/restore the system address account state).
    ///
    /// IMPORTANT: We always push new entries (never update in-place) to support checkpoint/restore.
    /// The checkpoint mechanism captures lengths, not values. If we updated in-place, the restored
    /// value would be the updated one, not the original at checkpoint time.
    /// At build() time, we take only the last entry per transaction for each address.
    pub fn record_balance_change(&mut self, address: Address, post_balance: U256) {
        // SYSTEM_ADDRESS balance changes from system contract calls should not be recorded
        // (system calls backup and restore SYSTEM_ADDRESS state)
        if address == SYSTEM_ADDRESS && self.in_system_call {
            return;
        }

        // Always push new entries to support checkpoint/restore.
        // The last entry for each transaction will be used in build().
        let changes = self.balance_changes.entry(address).or_default();
        let prev_len = changes.len();
        changes.push((self.current_index, post_balance));
        self.balance_changes_journal.push((address, prev_len));

        // Mark address as touched
        self.touched_addresses.insert(address);
    }

    /// Sets the initial balance for an address before any changes.
    /// This should be called when first accessing an account to enable round-trip detection.
    ///
    /// Per EIP-7928: "If an account's balance changes during a transaction, but its
    /// post-transaction balance is equal to its pre-transaction balance, then the
    /// change MUST NOT be recorded." The initial balance is used in build() to detect
    /// such round-trips on a per-transaction basis.
    pub fn set_initial_balance(&mut self, address: Address, balance: U256) {
        self.initial_balances.entry(address).or_insert(balance);
    }

    /// Records a nonce change.
    /// Per EIP-7928, only record nonces for:
    /// - EOA senders
    /// - Contracts performing CREATE/CREATE2
    /// - Deployed contracts
    /// - EIP-7702 authorities
    ///
    /// Note: SYSTEM_ADDRESS nonce changes from system calls are excluded.
    pub fn record_nonce_change(&mut self, address: Address, post_nonce: u64) {
        // SYSTEM_ADDRESS nonce changes from system contract calls should not be recorded
        if address == SYSTEM_ADDRESS && self.in_system_call {
            return;
        }
        let changes = self.nonce_changes.entry(address).or_default();
        let prev_len = changes.len();
        changes.push((self.current_index, post_nonce));
        self.nonce_changes_journal.push((address, prev_len));
        // Mark address as touched
        self.touched_addresses.insert(address);
    }

    /// Records a code change (contract deployment or EIP-7702 delegation).
    /// Marks that an address has non-empty code at the start (before any code changes).
    /// This is used to distinguish:
    /// - CREATE with empty code: no initial code → empty = no change (skip)
    /// - Delegation clear: had code → empty = actual change (record)
    pub fn capture_initial_code_presence(&mut self, address: Address, has_code: bool) {
        if has_code {
            self.addresses_with_initial_code.insert(address);
        }
    }

    /// Captures the initial code for an address before any code changes in the current transaction.
    /// Used for net-zero code change detection (e.g., delegate then reset in same tx).
    /// Only the first call per address per transaction is stored.
    pub fn set_initial_code(&mut self, address: Address, code: Bytes) {
        self.tx_initial_code.entry(address).or_insert(code);
    }

    /// Records a code change (contract deployment or EIP-7702 delegation).
    /// Per EIP-7928:
    /// - Empty code on CREATE (no initial code → empty) is NOT recorded (test_bal_create_transaction_empty_code)
    /// - Empty code on delegation clear (had code → empty) IS recorded (test_bal_7702_delegation_clear)
    pub fn record_code_change(&mut self, address: Address, new_code: Bytes) {
        // If new code is empty, only record if the address had initial code
        // (i.e., this is an actual code change like delegation clear, not just CREATE empty)
        // No initial code and setting to empty = no change, skip
        // Had initial code and setting to empty = delegation clear, record it
        if new_code.is_empty() && !self.addresses_with_initial_code.contains(&address) {
            self.touched_addresses.insert(address);
            return;
        }

        let changes = self.code_changes.entry(address).or_default();
        let prev_len = changes.len();
        changes.push((self.current_index, new_code));
        self.code_changes_journal.push((address, prev_len));
        // Mark address as touched (include SYSTEM_ADDRESS for actual state changes)
        self.touched_addresses.insert(address);
    }

    /// Merges additional touched addresses from an iterator.
    pub fn merge_touched_addresses(&mut self, addresses: impl Iterator<Item = Address>) {
        for address in addresses {
            self.record_touched_address(address);
        }
    }

    /// Builds the final BlockAccessList from accumulated data.
    ///
    /// This method:
    /// 1. Filters net-zero storage writes for the current transaction
    /// 2. Filters out balance changes per-transaction where the final balance equals the initial balance
    /// 3. Creates AccountChanges entries for all touched addresses
    /// 4. Includes addresses even if they have no state changes (per EIP-7928)
    ///
    /// Per EIP-7928: "If an account's balance changes during a transaction, but its
    /// post-transaction balance is equal to its pre-transaction balance, then the
    /// change MUST NOT be recorded."
    pub fn build(mut self) -> BlockAccessList {
        // Filter net-zero storage writes and code changes for the current (last) transaction
        self.filter_net_zero_storage();
        self.filter_net_zero_code();
        let mut bal = BlockAccessList::with_capacity(self.touched_addresses.len());

        // Sort addresses for canonical BAL ordering (IndexSet preserves insertion order,
        // but BAL requires ascending address order).
        let mut sorted_addresses: Vec<_> = self.touched_addresses.iter().copied().collect();
        sorted_addresses.sort();

        // Process all touched addresses
        for address in &sorted_addresses {
            let mut account_changes = AccountChanges::new(*address);

            // Add storage writes (slot changes)
            // Deduplicate entries per block_access_index (keep last per idx),
            // since record_storage_write always pushes for correct checkpoint/restore.
            if let Some(slots) = self.storage_writes.get(address) {
                for (slot, changes) in slots {
                    let mut slot_change = SlotChange::new(*slot);
                    let mut deduped: BTreeMap<u32, U256> = BTreeMap::new();
                    for (index, post_value) in changes {
                        deduped.insert(*index, *post_value);
                    }
                    for (index, post_value) in deduped {
                        slot_change.add_change(StorageChange::new(index, post_value));
                    }
                    account_changes.add_storage_change(slot_change);
                }
            }

            // Add storage reads (excluding slots that were promoted to writes
            // or that already exist in storage_writes from any transaction).
            // Sort for canonical BAL ordering (IndexSet preserves insertion order).
            if let Some(reads) = self.storage_reads.get(address) {
                let promoted = self.reads_promoted_to_writes.get(address);
                let writes = self.storage_writes.get(address);
                let mut sorted_reads: Vec<_> = reads
                    .iter()
                    .filter(|slot| !promoted.is_some_and(|p| p.contains(*slot)))
                    .filter(|slot| !writes.is_some_and(|w| w.contains_key(slot)))
                    .copied()
                    .collect();
                sorted_reads.sort();
                for slot in sorted_reads {
                    account_changes.add_storage_read(slot);
                }
            }

            // Add balance changes (filtered for round-trips per-transaction)
            // Per EIP-7928: "If an account's balance changes during a transaction, but its
            // post-transaction balance is equal to its pre-transaction balance, then the
            // change MUST NOT be recorded."
            if let Some(changes) = self.balance_changes.get(address) {
                // Group balance changes by transaction index
                let mut changes_by_tx: BTreeMap<u32, Vec<U256>> = BTreeMap::new();
                for (index, post_balance) in changes {
                    changes_by_tx.entry(*index).or_default().push(*post_balance);
                }

                // For each transaction, check if balance round-tripped
                // Per EIP-7928: only the FINAL balance per transaction is recorded
                let mut prev_balance = self.initial_balances.get(address).copied();
                for (index, tx_changes) in &changes_by_tx {
                    let initial_for_tx = prev_balance;
                    let final_for_tx = tx_changes.last().copied();

                    // Check if this transaction's balance round-tripped
                    let is_round_trip = match (initial_for_tx, final_for_tx) {
                        (Some(initial), Some(final_bal)) => initial == final_bal,
                        _ => false, // Include if we can't determine
                    };

                    // Only include the FINAL balance change if NOT a round-trip
                    if !is_round_trip && let Some(final_balance) = final_for_tx {
                        account_changes
                            .add_balance_change(BalanceChange::new(*index, final_balance));
                    }

                    // Update prev_balance for next transaction
                    prev_balance = final_for_tx;
                }
            }

            // Add nonce changes (only FINAL nonce per transaction)
            // Per EIP-7928, similar to balance changes, we only record the final nonce per tx.
            if let Some(changes) = self.nonce_changes.get(address) {
                // Group nonce changes by transaction index
                let mut changes_by_tx: BTreeMap<u32, u64> = BTreeMap::new();
                for (index, post_nonce) in changes {
                    // Only keep the final nonce for each transaction (last write wins)
                    changes_by_tx.insert(*index, *post_nonce);
                }

                for (index, post_nonce) in changes_by_tx {
                    account_changes.add_nonce_change(NonceChange::new(index, post_nonce));
                }
            }

            // Add code changes (only FINAL code per transaction)
            // Per EIP-7928, similar to nonce/balance, we only record the final code per tx.
            if let Some(changes) = self.code_changes.get(address) {
                // Group code changes by transaction index, keeping only the final one
                let mut changes_by_tx: BTreeMap<u32, Bytes> = BTreeMap::new();
                for (index, new_code) in changes {
                    // Only keep the final code for each transaction (last write wins)
                    changes_by_tx.insert(*index, new_code.clone());
                }

                for (index, new_code) in changes_by_tx {
                    account_changes.add_code_change(CodeChange::new(index, new_code));
                }
            }

            // Add account to BAL (even if empty - per EIP-7928, touched addresses must appear)
            bal.add_account_changes(account_changes);
        }

        bal
    }

    /// Returns true if the recorder has no recorded data.
    pub fn is_empty(&self) -> bool {
        self.touched_addresses.is_empty()
            && self.storage_reads.is_empty()
            && self.storage_writes.is_empty()
            && self.balance_changes.is_empty()
            && self.nonce_changes.is_empty()
            && self.code_changes.is_empty()
    }

    /// Creates a checkpoint of the current state (excluding touched_addresses which persist).
    ///
    /// Per EIP-7928: "State changes from reverted calls are discarded, but all accessed
    /// addresses must be included." The checkpoint captures state change data so it can
    /// be restored on revert, while touched_addresses are preserved.
    ///
    /// O(1): just snapshots the current journal lengths.
    pub fn checkpoint(&self) -> BlockAccessListCheckpoint {
        BlockAccessListCheckpoint {
            balance_changes_journal_len: self.balance_changes_journal.len(),
            nonce_changes_journal_len: self.nonce_changes_journal.len(),
            code_changes_journal_len: self.code_changes_journal.len(),
            storage_writes_journal_len: self.storage_writes_journal.len(),
            reads_promoted_journal_len: self.reads_promoted_journal.len(),
        }
    }

    /// Restores state to a checkpoint, keeping touched_addresses intact.
    ///
    /// Per EIP-7928: "State changes from reverted calls are discarded, but all accessed
    /// addresses must be included." This means:
    /// - Storage reads from reverted calls PERSIST (reads are accesses, not state changes)
    /// - Storage writes from reverted calls become READS (slot was accessed but value unchanged)
    /// - Balance/nonce/code changes are discarded
    ///
    /// Walks each journal in reverse from its current length down to the checkpoint's
    /// recorded length, truncating each affected per-address Vec back to its `prev_len`.
    /// Storage-write slots that become empty (fresh writes, `prev_len == 0`) are
    /// promoted to `storage_reads` to preserve the access for EIP-7928.
    pub fn restore(&mut self, checkpoint: BlockAccessListCheckpoint) {
        // Same invariant as `tx_restore`: journals can only grow between
        // checkpoint and restore. `set_block_access_index` clears them, so
        // inner-call checkpoints can never span a tx boundary.
        debug_assert!(
            self.balance_changes_journal.len() >= checkpoint.balance_changes_journal_len
                && self.nonce_changes_journal.len() >= checkpoint.nonce_changes_journal_len
                && self.code_changes_journal.len() >= checkpoint.code_changes_journal_len
                && self.storage_writes_journal.len() >= checkpoint.storage_writes_journal_len
                && self.reads_promoted_journal.len() >= checkpoint.reads_promoted_journal_len,
            "BAL recorder journal shrank between checkpoint and restore — \
             likely a set_block_access_index call in between"
        );
        // reads_promoted_to_writes: walk in reverse, truncate. No read-promotion concern.
        Self::walk_journal_simple(
            &mut self.reads_promoted_journal,
            checkpoint.reads_promoted_journal_len,
            &mut self.reads_promoted_to_writes,
        );

        // storage_writes: walk in reverse. When a slot's vec becomes empty, the
        // entry was a fresh write since the checkpoint — promote to storage_reads.
        while self.storage_writes_journal.len() > checkpoint.storage_writes_journal_len {
            // SAFETY: while-condition guarantees non-empty.
            let (addr, slot, prev_len) = self
                .storage_writes_journal
                .pop()
                .expect("checked non-empty");
            let Some(slots) = self.storage_writes.get_mut(&addr) else {
                continue;
            };
            let promote_to_read = if let Some(changes) = slots.get_mut(&slot) {
                changes.truncate(prev_len);
                changes.is_empty()
            } else {
                false
            };
            if promote_to_read {
                slots.remove(&slot);
                self.storage_reads.entry(addr).or_default().insert(slot);
            }
            if slots.is_empty() {
                self.storage_writes.remove(&addr);
            }
        }

        Self::walk_journal_simple(
            &mut self.balance_changes_journal,
            checkpoint.balance_changes_journal_len,
            &mut self.balance_changes,
        );
        Self::walk_journal_simple(
            &mut self.nonce_changes_journal,
            checkpoint.nonce_changes_journal_len,
            &mut self.nonce_changes,
        );
        Self::walk_journal_simple(
            &mut self.code_changes_journal,
            checkpoint.code_changes_journal_len,
            &mut self.code_changes,
        );

        // Note: touched_addresses is intentionally NOT restored - per EIP-7928,
        // accessed addresses must be included even from reverted calls
    }

    /// Walk a per-address journal in reverse from its current length down to
    /// `target_len`, truncating each affected `map[addr]` container to its
    /// `prev_len`. Removes addresses whose container becomes empty.
    ///
    /// Used by `restore` / `tx_restore` for `balance_changes`, `nonce_changes`,
    /// `code_changes`, and `reads_promoted_to_writes` (which all key on `Address`
    /// alone, unlike `storage_writes` which keys on `(Address, U256)`). The
    /// `TruncatableEmpty` bound lets the helper work for both `Vec<_>` (the
    /// change-list maps) and `IndexSet<U256>` (`reads_promoted_to_writes`).
    fn walk_journal_simple<C: TruncatableEmpty>(
        journal: &mut Vec<(Address, usize)>,
        target_len: usize,
        map: &mut BTreeMap<Address, C>,
    ) {
        while journal.len() > target_len {
            // SAFETY: while-condition guarantees non-empty.
            let (addr, prev_len) = journal.pop().expect("checked non-empty");
            let remove = if let Some(changes) = map.get_mut(&addr) {
                changes.truncate(prev_len);
                changes.is_empty()
            } else {
                false
            };
            if remove {
                map.remove(&addr);
            }
        }
    }

    /// Like the storage_writes walk in `restore`, but does NOT promote
    /// emptied slots to `storage_reads`. Used by `tx_restore` where a rejected
    /// tx should leave no trace at all.
    ///
    /// Cleanup of `reads_promoted_to_writes` for the rejected tx is delegated
    /// to the caller (`tx_restore` walks `reads_promoted_journal` separately
    /// before invoking this helper).
    fn walk_storage_writes_journal_no_promote(
        journal: &mut Vec<(Address, U256, usize)>,
        target_len: usize,
        storage_writes: &mut StorageWritesMap,
    ) {
        while journal.len() > target_len {
            let (addr, slot, prev_len) = journal.pop().expect("checked non-empty");
            // Address may already have been removed by a prior iteration of
            // this same loop (last slot emptied → address entry pruned below).
            let Some(slots) = storage_writes.get_mut(&addr) else {
                continue;
            };
            let remove_slot = if let Some(changes) = slots.get_mut(&slot) {
                changes.truncate(prev_len);
                changes.is_empty()
            } else {
                false
            };
            if remove_slot {
                slots.remove(&slot);
            }
            if slots.is_empty() {
                storage_writes.remove(&addr);
            }
        }
    }

    /// Creates a tx-level checkpoint that captures the full recorder state.
    ///
    /// Unlike [`checkpoint`] (for inner-call reverts where touched addresses persist),
    /// this captures everything needed to fully undo a rejected transaction during
    /// block building. Uses length-based snapshots on IndexSet/IndexMap fields for
    /// efficiency instead of cloning the entire recorder.
    pub fn tx_checkpoint(&self) -> TxCheckpoint {
        TxCheckpoint {
            inner: self.checkpoint(),
            current_index: self.current_index,
            touched_addresses_len: self.touched_addresses.len(),
            storage_reads_lens: self
                .storage_reads
                .iter()
                .map(|(addr, slots)| (*addr, slots.len()))
                .collect(),
            initial_balances_len: self.initial_balances.len(),
            addresses_with_initial_code_len: self.addresses_with_initial_code.len(),
        }
    }

    /// Restores the recorder to a tx-level checkpoint, fully undoing a rejected transaction.
    ///
    /// Unlike [`restore`] (which preserves touched addresses and converts writes to reads),
    /// this completely removes all traces of the rejected tx — addresses, reads, writes, and
    /// all state changes.
    pub fn tx_restore(&mut self, checkpoint: TxCheckpoint) {
        // Invariant: `tx_checkpoint` must be called AFTER `set_block_access_index`,
        // not before. `set_block_access_index` clears all journals; if a caller
        // checkpoints at journal_len=N and then advances the index, the cleared
        // journal can never grow back to N, so the walk-back-to-N becomes a no-op
        // and post-advance pushes aren't undone. This assert catches that misuse.
        debug_assert!(
            self.balance_changes_journal.len() >= checkpoint.inner.balance_changes_journal_len
                && self.nonce_changes_journal.len() >= checkpoint.inner.nonce_changes_journal_len
                && self.code_changes_journal.len() >= checkpoint.inner.code_changes_journal_len
                && self.storage_writes_journal.len() >= checkpoint.inner.storage_writes_journal_len
                && self.reads_promoted_journal.len() >= checkpoint.inner.reads_promoted_journal_len,
            "BAL recorder journal shrank between tx_checkpoint and tx_restore — \
             likely a set_block_access_index call in between"
        );
        self.current_index = checkpoint.current_index;

        // Truncate append-only IndexSet/IndexMap fields to their checkpoint lengths
        self.touched_addresses
            .truncate(checkpoint.touched_addresses_len);
        self.initial_balances
            .truncate(checkpoint.initial_balances_len);
        self.addresses_with_initial_code
            .truncate(checkpoint.addresses_with_initial_code_len);

        // Truncate storage_reads: remove new addresses, truncate existing inner sets.
        // INVARIANT: storage_reads is append-only (entries never removed or reordered).
        // checkpoint.storage_reads_lens.len() is the number of addresses present at
        // checkpoint time, which are exactly the first N entries by insertion order.
        self.storage_reads
            .truncate(checkpoint.storage_reads_lens.len());
        for (addr, slots) in &mut self.storage_reads {
            if let Some(&len) = checkpoint.storage_reads_lens.get(addr) {
                slots.truncate(len);
            } else {
                // Address was not in checkpoint — should not happen after outer truncate,
                // but defensive clear to avoid stale state.
                slots.clear();
            }
        }

        // Clear per-tx state
        self.tx_initial_storage.clear();
        self.tx_initial_code.clear();

        // Truncate writes/changes via journal walks. Rejected txs leave no trace,
        // so storage_writes does NOT promote emptied slots to storage_reads.
        Self::walk_journal_simple(
            &mut self.reads_promoted_journal,
            checkpoint.inner.reads_promoted_journal_len,
            &mut self.reads_promoted_to_writes,
        );
        Self::walk_storage_writes_journal_no_promote(
            &mut self.storage_writes_journal,
            checkpoint.inner.storage_writes_journal_len,
            &mut self.storage_writes,
        );
        Self::walk_journal_simple(
            &mut self.balance_changes_journal,
            checkpoint.inner.balance_changes_journal_len,
            &mut self.balance_changes,
        );
        Self::walk_journal_simple(
            &mut self.nonce_changes_journal,
            checkpoint.inner.nonce_changes_journal_len,
            &mut self.nonce_changes,
        );
        Self::walk_journal_simple(
            &mut self.code_changes_journal,
            checkpoint.inner.code_changes_journal_len,
            &mut self.code_changes,
        );
    }

    /// Handles BAL cleanup for a self-destructed account per EIP-7928/EIP-6780.
    /// Called after destroy_account for contracts created and destroyed in the same tx.
    /// Removes nonce/code changes, converts storage writes to reads.
    /// Matches EELS `track_selfdestruct` in state_tracker.py:315.
    ///
    /// INVARIANT: must be called only at top-level tx finalization, with no
    /// outstanding `checkpoint()` pending restore. The `retain` calls below
    /// mutate the change maps WITHOUT pushing journal entries, so any later
    /// `restore()` against an older checkpoint would observe a journal whose
    /// `prev_len`s no longer match the underlying map and silently produce
    /// incorrect results. Caller is `LEVM::finalize_execution`, which runs
    /// after every nested call frame has already committed or restored.
    pub fn track_selfdestruct(&mut self, address: Address, preserve_balance: bool) {
        let idx = self.current_index;

        // 1. Remove nonce changes for this address at current tx index
        if let Some(changes) = self.nonce_changes.get_mut(&address) {
            changes.retain(|(i, _)| *i != idx);
            if changes.is_empty() {
                self.nonce_changes.remove(&address);
            }
        }

        // 2. Balance handling depends on the fork:
        // - Pre-Amsterdam (EIP-6780): the account is fully wiped, so its post-tx balance is
        //   0. Collapse intermediate changes to a single (idx, 0), or drop entirely if the
        //   pre-tx balance was also 0 (net-zero round-trip, EIP-7928). EELS derives BAL
        //   balance changes by diffing pre-tx vs final post-tx state, so only the final 0
        //   matters.
        // - Amsterdam+ (EIP-8246): SELFDESTRUCT no longer burns ETH; the account keeps its
        //   balance and becomes a plain account (delete_self_destruct_accounts preserves it).
        //   The recorded balance changes already reflect the preserved post-tx balance, so
        //   they are kept as-is (the create-time value transfer is a genuine 0→balance
        //   change, not a net-zero round-trip).
        if !preserve_balance {
            // If initial_balance was never set, treat it as 0 (contract created with no value).
            let pre_balance = self
                .initial_balances
                .get(&address)
                .copied()
                .unwrap_or_default();
            if let Some(changes) = self.balance_changes.get_mut(&address) {
                // Drop all intermediate balance changes recorded for this tx.
                changes.retain(|(i, _)| *i != idx);
                // Record the final post-tx balance of 0 unless it equals the pre-tx balance.
                if !pre_balance.is_zero() {
                    changes.push((idx, U256::zero()));
                }
                if changes.is_empty() {
                    self.balance_changes.remove(&address);
                }
            }
        }

        // 3. Remove code changes for this address at current tx index
        if let Some(changes) = self.code_changes.get_mut(&address) {
            changes.retain(|(i, _)| *i != idx);
            if changes.is_empty() {
                self.code_changes.remove(&address);
            }
        }

        // 4. Convert storage writes from current tx to reads
        if let Some(slots) = self.storage_writes.get_mut(&address) {
            let mut slots_to_read: Vec<U256> = Vec::new();
            for (slot, changes) in slots.iter_mut() {
                if changes.iter().any(|(i, _)| *i == idx) {
                    slots_to_read.push(*slot);
                }
                changes.retain(|(i, _)| *i != idx);
            }
            slots.retain(|_, changes| !changes.is_empty());
            if slots.is_empty() {
                self.storage_writes.remove(&address);
            }

            for slot in slots_to_read {
                self.storage_reads.entry(address).or_default().insert(slot);
                // Undo read-to-write promotion for these slots
                if let Some(promoted) = self.reads_promoted_to_writes.get_mut(&address) {
                    promoted.retain(|s| *s != slot);
                    if promoted.is_empty() {
                        self.reads_promoted_to_writes.remove(&address);
                    }
                }
            }
        }
    }
}

/// Per-field delta for a single account, synthesized directly from a [`BlockAccessList`].
///
/// Each optional field is `Some` only when the BAL records a change for that field.
/// Fields absent from the BAL are left as `None` so that Stage C writes only the
/// deltas it knows about, without fabricating defaults for unchanged state.
#[derive(Debug, Clone, Default)]
pub struct BalSynthesisItem {
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    pub code_hash: Option<H256>,
    pub code: Option<Code>,
    pub added_storage: FxHashMap<H256, U256>,
}

/// Converts a [`BlockAccessList`] into a per-account map of field-level deltas.
///
/// Accounts that appear only via `storage_reads` (no balance/nonce/code/storage
/// changes) are omitted: Stage B weight is 0, Stage C field writes all no-op,
/// and the witness builder captures them from `logger.state_accessed`.
pub fn synthesize_bal_updates(bal: &BlockAccessList) -> FxHashMap<Address, BalSynthesisItem> {
    let mut result = FxHashMap::default();

    for account in bal.accounts() {
        // Skip accounts with no actual changes (storage_reads only).
        if account.balance_changes.is_empty()
            && account.nonce_changes.is_empty()
            && account.code_changes.is_empty()
            && account.storage_changes.is_empty()
        {
            continue;
        }

        let balance = account.balance_changes.last().map(|c| c.post_balance);
        let nonce = account.nonce_changes.last().map(|c| c.post_nonce);
        let code = account.code_changes.last().map(|c| {
            let hash = keccak(&c.new_code);
            Code::from_bytecode_unchecked(c.new_code.clone(), hash)
        });
        let code_hash = code.as_ref().map(|c| c.hash);

        let mut added_storage: FxHashMap<H256, U256> = FxHashMap::default();
        for sc in &account.storage_changes {
            // Canonical BAL ordering requires `slot_changes` to be non-empty, but
            // wire-format decoding is permissive. Defensively skip empty entries
            // rather than panic; structural validation belongs upstream.
            let Some(last) = sc.slot_changes.last() else {
                continue;
            };
            let key = H256::from_uint(&sc.slot);
            added_storage.insert(key, last.post_value);
        }

        result.insert(
            account.address,
            BalSynthesisItem {
                balance,
                nonce,
                code_hash,
                code,
                added_storage,
            },
        );
    }

    result
}

#[cfg(test)]
mod decode_tests {
    use super::*;
    use std::str::FromStr;

    /// Sanity check that our RLP decoder produces the same `post_balance` for
    /// the sender as the bytes literally encode in
    /// `test_call_value_to_self_destructed_same_tx_account` at tests-bal@v7.1.0.
    ///
    /// If this passes, our decoder is correct and any mismatch observed during
    /// hive runs comes from the BAL the test harness sends (not the fixture's
    /// on-disk bytes). If it fails, the bug is local to this decoder.
    #[test]
    fn decode_v7_1_0_sender_balance_change() {
        // Sender's entry only, manually trimmed from the v7.1.0 fixture's
        // `engineNewPayloads[0].params[0].blockAccessList` field at
        // `eip8037_state_creation_gas_cost_increase/state_gas_call/call_value_to_self_destructed_same_tx_account.json`.
        // Wrapped in a single-element list (`0xee`) so it decodes as a full BAL.
        // 0xee = list, 46 bytes follow:
        //   0xed = AccountChanges list, 45 bytes follow:
        //     0x94 + 20 byte address  (= 21 bytes)
        //     0xc0                    storageReads empty list
        //     0xc0                    storageChanges empty list
        //     0xcc 0xcb 0x01 0x89 <9-byte post_balance>  balanceChanges (= 14 bytes)
        //     0xc3 0xc2 0x01 0x01                       nonceChanges (= 4 bytes)
        //     0xc0                    codeChanges empty list
        //   total inner len = 21 + 1 + 1 + 14 + 4 + 1 = 42 bytes
        // Outer 0xee covers 1-byte AccountChanges header + 42 bytes = 43 bytes
        // Wait, let me recount the inner: 0xed is header (1 byte) for 42-byte payload.
        //   AccountChanges total wire: 1 + 42 = 43 bytes.
        //   Outer list (BlockAccessList) wraps that: 0x... + 43 bytes.
        //   Outer header for a 43-byte payload: 0xc0 + 43 = 0xeb.
        // Byte counts (carefully):
        //   inner BalanceChange list:  [01, 89, 9_bytes] = 11 bytes  → header cb
        //   inner balanceChanges:      [<12_byte_change>] = 12 bytes → header cc
        //   inner NonceChange list:    [01, 01]           = 2 bytes  → header c2
        //   inner nonceChanges:        [<3_byte_change>]  = 3 bytes  → header c3
        //   AccountChanges payload:    addr(21) + c0 + c0 + bal(13) + nonce(4) + c0 = 41 bytes
        //   AccountChanges total wire: e9 + 41 = 42 bytes
        //   BAL payload:               42 bytes → header ea
        let hex_str = concat!(
            "ea", // outer list, 42 bytes follow
            "e9", // AccountChanges list, 41 bytes follow
            "94",
            "1ad9bc24818784172ff393bb6f89f094d4d2ca29", // address (20 bytes)
            "c0",                                       // storage_changes = []
            "c0",                                       // storage_reads = []
            "cc",                                       // balanceChanges list, 12 bytes follow
            "cb",                                       // single change, 11 bytes follow
            "01",                                       // block_access_index = 1
            "89",
            "3635c9adc5de6de476", // post_balance = 9-byte big-endian uint
            "c3",                 // nonceChanges list, 3 bytes follow
            "c2",                 // single change, 2 bytes follow
            "01",                 // block_access_index = 1
            "01",                 // post_nonce = 1
            "c0",                 // codeChanges = []
        );

        let bytes = hex::decode(hex_str).expect("hex");
        let bal = BlockAccessList::decode(&bytes).expect("BAL decode");

        let accts = bal.accounts();
        assert_eq!(accts.len(), 1, "expected exactly one account in the BAL");

        let acct = &accts[0];
        assert_eq!(
            acct.address,
            Address::from_str("0x1ad9bc24818784172ff393bb6f89f094d4d2ca29").unwrap(),
            "address mismatch",
        );
        assert_eq!(acct.balance_changes.len(), 1, "expected one balance change");
        let change = &acct.balance_changes[0];
        assert_eq!(change.block_access_index, 1, "block_access_index");

        // 0x3635c9adc5de6de476 = 999_999_999_999_996_716_150
        // = 10^21 − 3_283_850 (= 328_385 gas × 10 gas_price)
        let expected = U256::from_dec_str("999999999999996716150").expect("post_balance decimal");
        assert_eq!(
            change.post_balance, expected,
            "RLP decoder produced wrong post_balance: got {}, expected {}",
            change.post_balance, expected,
        );
    }
}

#[cfg(test)]
mod recorder_tests {
    use super::*;
    use ethereum_types::Address;

    /// A slot written only inside a reverted call becomes a read on restore, yet
    /// `tx_initial_storage` must still hold its true start-of-tx value. The
    /// parallel BAL validator seeds storage from this map, so a stale/missing
    /// pre-value here would mis-validate a reverted-write slot.
    #[test]
    fn tx_initial_storage_retains_prevalue_for_reverted_fresh_write() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        let a = Address::zero();
        let slot = U256::from(9);

        let cp = r.checkpoint();
        // Fresh write inside the (soon-reverted) call: capture pre=3, then write 4.
        r.capture_pre_storage(a, slot, U256::from(3));
        r.record_storage_write(a, slot, U256::from(4));
        r.restore(cp);

        // The reverted fresh write is reclassified as a read...
        let reads = r.take_storage_reads();
        assert!(
            reads.contains(&(a, slot)),
            "a reverted fresh write must be recorded as a read"
        );
        // ...but the captured start-of-tx value survives the revert unchanged.
        let ti = r.take_tx_initial_storage();
        assert_eq!(
            ti.get(&(a, slot)),
            Some(&U256::from(3)),
            "tx_initial_storage must retain the true start-of-tx value after revert"
        );
    }

    /// First-write-wins: a second write in the same tx must not overwrite the
    /// captured start-of-tx value.
    #[test]
    fn tx_initial_storage_is_first_write_wins() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        let a = Address::zero();
        let slot = U256::from(1);

        r.capture_pre_storage(a, slot, U256::from(10));
        r.record_storage_write(a, slot, U256::from(20));
        // Second write in the same tx re-captures, but or_insert keeps the first.
        r.capture_pre_storage(a, slot, U256::from(20));
        r.record_storage_write(a, slot, U256::from(30));

        let ti = r.take_tx_initial_storage();
        assert_eq!(ti.get(&(a, slot)), Some(&U256::from(10)));
    }
}

#[cfg(test)]
mod synthesize_tests {
    use super::*;
    use bytes::Bytes;
    use ethereum_types::Address;

    fn addr(b: u8) -> Address {
        let mut a = Address::zero();
        a.0[19] = b;
        a
    }

    fn make_bal(account: AccountChanges) -> BlockAccessList {
        BlockAccessList::from_accounts(vec![account])
    }

    /// Accounts with only `storage_reads` must be skipped entirely.
    #[test]
    fn synthesize_skips_read_only_account() {
        let mut account = AccountChanges::new(addr(1));
        account.storage_reads = vec![U256::from(42)];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        assert!(
            result.is_empty(),
            "expected empty map for read-only account"
        );
    }

    /// A single storage write with no other deltas.
    #[test]
    fn synthesize_pure_storage_write() {
        let sc =
            SlotChange::with_changes(U256::from(5), vec![StorageChange::new(0, U256::from(42))]);
        let mut account = AccountChanges::new(addr(2));
        account.storage_changes = vec![sc];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(2)).expect("expected entry");
        assert!(item.balance.is_none());
        assert!(item.nonce.is_none());
        assert!(item.code_hash.is_none());
        assert!(item.code.is_none());
        let key = H256::from_uint(&U256::from(5));
        assert_eq!(item.added_storage.get(&key), Some(&U256::from(42)));
    }

    /// Balance-only change: nonce, code, and storage must be None/empty.
    /// Regression case for partial-info corruption (Blocker 1).
    #[test]
    fn synthesize_balance_only_no_nonce_no_code() {
        let mut account = AccountChanges::new(addr(3));
        account.balance_changes = vec![BalanceChange::new(2, U256::from(100))];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(3)).expect("expected entry");
        assert_eq!(item.balance, Some(U256::from(100)));
        assert!(item.nonce.is_none());
        assert!(item.code_hash.is_none());
        assert!(item.code.is_none());
        assert!(item.added_storage.is_empty());
    }

    /// Nonce-only change.
    #[test]
    fn synthesize_nonce_only() {
        let mut account = AccountChanges::new(addr(4));
        account.nonce_changes = vec![NonceChange::new(2, 7)];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(4)).expect("expected entry");
        assert!(item.balance.is_none());
        assert_eq!(item.nonce, Some(7));
        assert!(item.code_hash.is_none());
        assert!(item.code.is_none());
        assert!(item.added_storage.is_empty());
    }

    /// Code-only change: code_hash must equal keccak of the bytecode.
    #[test]
    fn synthesize_code_only() {
        let bytecode = Bytes::from_static(b"\xff\x00");
        let mut account = AccountChanges::new(addr(5));
        account.code_changes = vec![CodeChange::new(2, bytecode.clone())];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(5)).expect("expected entry");
        assert!(item.balance.is_none());
        assert!(item.nonce.is_none());
        let expected_hash = keccak(&bytecode);
        assert_eq!(item.code_hash, Some(expected_hash));
        assert!(item.code.is_some());
        assert_eq!(item.code.as_ref().unwrap().code(), &bytecode[..]);
        assert!(item.added_storage.is_empty());
    }

    /// When multiple balance changes exist, the last one wins.
    #[test]
    fn synthesize_takes_last_balance() {
        let mut account = AccountChanges::new(addr(6));
        account.balance_changes = vec![
            BalanceChange::new(1, U256::from(50)),
            BalanceChange::new(5, U256::from(200)),
        ];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(6)).expect("expected entry");
        assert_eq!(item.balance, Some(U256::from(200)));
    }

    /// When multiple nonce changes exist, the last one wins.
    #[test]
    fn synthesize_takes_last_nonce() {
        let mut account = AccountChanges::new(addr(7));
        account.nonce_changes = vec![NonceChange::new(1, 3), NonceChange::new(5, 9)];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(7)).expect("expected entry");
        assert_eq!(item.nonce, Some(9));
    }

    /// When multiple code changes exist, the last one determines code_hash and code.
    #[test]
    fn synthesize_takes_last_code_and_hashes() {
        let first = Bytes::from_static(b"\x60\x00");
        let last = Bytes::from_static(b"\xff\x00");
        let mut account = AccountChanges::new(addr(8));
        account.code_changes = vec![CodeChange::new(1, first), CodeChange::new(5, last.clone())];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(8)).expect("expected entry");
        let expected_hash = keccak(&last);
        assert_eq!(item.code_hash, Some(expected_hash));
        assert_eq!(item.code.as_ref().unwrap().code(), &last[..]);
    }

    /// When a slot has multiple StorageChanges, the last post_value wins.
    #[test]
    fn synthesize_slot_last_post_value() {
        let sc = SlotChange::with_changes(
            U256::from(10),
            vec![
                StorageChange::new(0, U256::from(1)),
                StorageChange::new(7, U256::from(99)),
            ],
        );
        let mut account = AccountChanges::new(addr(9));
        account.storage_changes = vec![sc];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(9)).expect("expected entry");
        let key = H256::from_uint(&U256::from(10));
        assert_eq!(item.added_storage.get(&key), Some(&U256::from(99)));
    }

    /// A storage write ending in zero must be kept (Stage B routes to trie.remove).
    #[test]
    fn synthesize_zero_storage_kept() {
        let sc = SlotChange::with_changes(U256::from(3), vec![StorageChange::new(0, U256::zero())]);
        let mut account = AccountChanges::new(addr(10));
        account.storage_changes = vec![sc];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(10)).expect("expected entry");
        let key = H256::from_uint(&U256::from(3));
        assert_eq!(
            item.added_storage.get(&key),
            Some(&U256::zero()),
            "zero-value storage must be present so Stage B can call trie.remove"
        );
    }

    /// A SlotChange with empty slot_changes is canonically forbidden but
    /// reachable via permissive wire-format decoding; synthesis must skip it
    /// without panicking and without polluting `added_storage`.
    #[test]
    fn synthesize_skips_when_slot_changes_empty() {
        let empty_sc = SlotChange::new(U256::from(1));
        let mut account = AccountChanges::new(addr(11));
        account.storage_changes = vec![empty_sc];
        // Add a balance change so the account itself is not skipped.
        account.balance_changes = vec![BalanceChange::new(1, U256::from(5))];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(11)).expect("expected outer entry");
        let key = H256::from_uint(&U256::from(1));
        assert!(
            !item.added_storage.contains_key(&key),
            "slot with empty slot_changes must not appear in added_storage"
        );
    }

    /// Account creation: all four optionals populated, code_hash matches keccak.
    #[test]
    fn synthesize_creation() {
        let bytecode = Bytes::from_static(b"\x60\x80\x60\x40");
        let mut account = AccountChanges::new(addr(12));
        account.balance_changes = vec![BalanceChange::new(1, U256::from(1000))];
        account.nonce_changes = vec![NonceChange::new(1, 1)];
        account.code_changes = vec![CodeChange::new(1, bytecode.clone())];
        let sc =
            SlotChange::with_changes(U256::from(0), vec![StorageChange::new(2, U256::from(7))]);
        account.storage_changes = vec![sc];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(12)).expect("expected entry");
        assert_eq!(item.balance, Some(U256::from(1000)));
        assert_eq!(item.nonce, Some(1));
        let expected_hash = keccak(&bytecode);
        assert_eq!(item.code_hash, Some(expected_hash));
        assert!(item.code.is_some());
        assert_eq!(item.code.as_ref().unwrap().code(), &bytecode[..]);
        let key = H256::from_uint(&U256::zero());
        assert_eq!(item.added_storage.get(&key), Some(&U256::from(7)));
    }

    /// EIP-6780 same-tx-created selfdestruct: only balance=0 is recorded.
    /// Stage C writes balance=0 and leaves pre-state nonce/code intact.
    /// EIP-161 removes the account only if pre-state nonce was 0 and code was empty
    /// (i.e. a fresh account created in the same block). Otherwise trie keeps the
    /// entry with balance=0 + original nonce/code, matching the streaming flow.
    #[test]
    fn synthesize_selfdestruct_collapses() {
        let mut account = AccountChanges::new(addr(13));
        account.balance_changes = vec![BalanceChange::new(5, U256::zero())];
        let bal = make_bal(account);
        let result = synthesize_bal_updates(&bal);
        let item = result.get(&addr(13)).expect("expected entry");
        assert_eq!(item.balance, Some(U256::zero()));
        assert!(item.nonce.is_none());
        assert!(item.code_hash.is_none());
        assert!(item.code.is_none());
        assert!(item.added_storage.is_empty());
    }
}

#[cfg(test)]
mod checkpoint_restore_tests {
    //! Tests for the journal-based checkpoint/restore implementation.
    //!
    //! The semantics under test:
    //! - `restore()` undoes balance/nonce/code/storage_write pushes after a
    //!   checkpoint, leaving `touched_addresses` and `storage_reads` intact.
    //!   Storage writes whose vec becomes empty (fresh writes since checkpoint)
    //!   are promoted to `storage_reads` per EIP-7928.
    //! - `tx_restore()` undoes the same plus `touched_addresses` /
    //!   `storage_reads` / `initial_balances` / `addresses_with_initial_code`.
    //!   Does NOT promote emptied writes to reads.
    //! - `set_block_access_index` clears journals on advance (filter_net_zero
    //!   mutates change maps; outstanding journal entries would be stale).

    use super::*;
    use bytes::Bytes;
    use ethereum_types::Address;

    fn addr(b: u8) -> Address {
        let mut a = Address::zero();
        a.0[19] = b;
        a
    }

    #[test]
    fn checkpoint_then_restore_with_no_changes_is_noop() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_balance_change(addr(1), U256::from(100));
        let cp = r.checkpoint();
        r.restore(cp);
        // Pre-checkpoint change still present.
        assert_eq!(r.balance_changes.get(&addr(1)).map(|v| v.len()), Some(1));
    }

    #[test]
    fn restore_undoes_balance_pushed_after_checkpoint() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_balance_change(addr(1), U256::from(100));
        let cp = r.checkpoint();
        r.record_balance_change(addr(1), U256::from(200));
        r.record_balance_change(addr(2), U256::from(50));
        assert_eq!(r.balance_changes[&addr(1)].len(), 2);
        assert_eq!(r.balance_changes[&addr(2)].len(), 1);
        r.restore(cp);
        assert_eq!(r.balance_changes[&addr(1)].len(), 1);
        assert_eq!(r.balance_changes[&addr(1)][0].1, U256::from(100));
        assert!(
            !r.balance_changes.contains_key(&addr(2)),
            "addr(2)'s vec became empty → addr removed"
        );
        // touched_addresses NOT restored — both still present
        assert!(r.touched_addresses.contains(&addr(1)));
        assert!(r.touched_addresses.contains(&addr(2)));
    }

    #[test]
    fn restore_undoes_nonce_and_code_changes() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        let cp = r.checkpoint();
        r.record_nonce_change(addr(1), 5);
        // Need addresses_with_initial_code to keep non-empty record_code_change semantics
        r.capture_initial_code_presence(addr(2), true);
        r.record_code_change(addr(2), Bytes::from_static(b"\x60\x00"));
        assert!(r.nonce_changes.contains_key(&addr(1)));
        assert!(r.code_changes.contains_key(&addr(2)));
        r.restore(cp);
        assert!(!r.nonce_changes.contains_key(&addr(1)));
        assert!(!r.code_changes.contains_key(&addr(2)));
    }

    #[test]
    fn restore_promotes_fresh_storage_write_to_read() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        let cp = r.checkpoint();
        r.record_storage_write(addr(1), U256::from(7), U256::from(42));
        assert!(r.storage_writes.contains_key(&addr(1)));
        r.restore(cp);
        // Write reverted; slot promoted to reads per EIP-7928.
        assert!(!r.storage_writes.contains_key(&addr(1)));
        assert!(r.storage_reads[&addr(1)].contains(&U256::from(7)));
    }

    #[test]
    fn restore_keeps_prior_writes_does_not_promote() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        // Pre-checkpoint write to the slot.
        r.record_storage_write(addr(1), U256::from(7), U256::from(11));
        let cp = r.checkpoint();
        // Post-checkpoint write to the same slot.
        r.record_storage_write(addr(1), U256::from(7), U256::from(22));
        assert_eq!(r.storage_writes[&addr(1)][&U256::from(7)].len(), 2);
        r.restore(cp);
        // Slot still has the pre-checkpoint write; NOT promoted to reads.
        assert_eq!(r.storage_writes[&addr(1)][&U256::from(7)].len(), 1);
        assert_eq!(
            r.storage_writes[&addr(1)][&U256::from(7)][0].1,
            U256::from(11)
        );
        assert!(
            r.storage_reads
                .get(&addr(1))
                .map(|s| !s.contains(&U256::from(7)))
                .unwrap_or(true),
            "slot must not appear in both writes and reads"
        );
    }

    #[test]
    fn restore_keeps_promotion_when_second_write_after_checkpoint() {
        // Slot is read, then promoted by a pre-checkpoint write. A second
        // write to the same slot after the checkpoint must NOT add a new
        // promotion-journal entry (IndexSet dedup is the whole point of the
        // O(1) change). On restore the pre-checkpoint write must remain and
        // the slot must stay in `reads_promoted_to_writes` so `build()`
        // continues to filter it out of the BAL `storage_reads` section.
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_storage_read(addr(1), U256::from(5));
        r.record_storage_write(addr(1), U256::from(5), U256::from(11));
        assert!(r.reads_promoted_to_writes[&addr(1)].contains(&U256::from(5)));
        assert_eq!(r.reads_promoted_journal.len(), 1);

        let cp = r.checkpoint();
        // Second write to the already-promoted slot — `IndexSet::insert`
        // returns false, so no new journal entry.
        r.record_storage_write(addr(1), U256::from(5), U256::from(22));
        assert_eq!(r.storage_writes[&addr(1)][&U256::from(5)].len(), 2);
        assert_eq!(r.reads_promoted_journal.len(), 1, "dedup: no new entry");

        r.restore(cp);
        // Pre-checkpoint write survives; promotion is preserved.
        assert_eq!(r.storage_writes[&addr(1)][&U256::from(5)].len(), 1);
        assert_eq!(
            r.storage_writes[&addr(1)][&U256::from(5)][0].1,
            U256::from(11)
        );
        assert!(r.reads_promoted_to_writes[&addr(1)].contains(&U256::from(5)));
        // `storage_reads` still carries the original read entry — the dedup
        // happens at `build()` time via the `reads_promoted_to_writes` and
        // `storage_writes` filters, not by mutating `storage_reads` here.
    }

    #[test]
    fn restore_handles_multiple_writes_same_slot_after_checkpoint() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        let cp = r.checkpoint();
        r.record_storage_write(addr(1), U256::from(7), U256::from(1));
        r.record_storage_write(addr(1), U256::from(7), U256::from(2));
        r.record_storage_write(addr(1), U256::from(7), U256::from(3));
        assert_eq!(r.storage_writes[&addr(1)][&U256::from(7)].len(), 3);
        r.restore(cp);
        assert!(!r.storage_writes.contains_key(&addr(1)));
        assert!(r.storage_reads[&addr(1)].contains(&U256::from(7)));
    }

    #[test]
    fn nested_checkpoints_restore_innermost_only() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_balance_change(addr(1), U256::from(10));
        let outer = r.checkpoint();
        r.record_balance_change(addr(1), U256::from(20));
        let inner = r.checkpoint();
        r.record_balance_change(addr(1), U256::from(30));
        assert_eq!(r.balance_changes[&addr(1)].len(), 3);
        r.restore(inner);
        assert_eq!(r.balance_changes[&addr(1)].len(), 2);
        assert_eq!(r.balance_changes[&addr(1)][1].1, U256::from(20));
        // Outer restore still works after inner restore.
        r.restore(outer);
        assert_eq!(r.balance_changes[&addr(1)].len(), 1);
        assert_eq!(r.balance_changes[&addr(1)][0].1, U256::from(10));
    }

    #[test]
    fn read_promoted_to_write_unpromoted_on_restore() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        // First, slot is read.
        r.record_storage_read(addr(1), U256::from(5));
        assert!(r.storage_reads[&addr(1)].contains(&U256::from(5)));
        let cp = r.checkpoint();
        // Then it's promoted to a write.
        r.record_storage_write(addr(1), U256::from(5), U256::from(99));
        assert!(r.reads_promoted_to_writes[&addr(1)].contains(&U256::from(5)));
        r.restore(cp);
        // Promotion undone — slot still in reads, no longer in writes.
        assert!(r.storage_reads[&addr(1)].contains(&U256::from(5)));
        assert!(!r.reads_promoted_to_writes.contains_key(&addr(1)));
        assert!(!r.storage_writes.contains_key(&addr(1)));
    }

    #[test]
    fn tx_restore_undoes_everything_including_touched_addresses() {
        let mut r = BlockAccessListRecorder::new();
        // Tx 1 commits.
        r.set_block_access_index(1);
        r.record_balance_change(addr(99), U256::from(5));
        // Tx 2 starts: real flow is set_bal_index THEN tx_checkpoint, so the
        // checkpoint sees empty journals (set_bal_index just cleared them).
        r.set_block_access_index(2);
        let tx_cp = r.tx_checkpoint();
        r.record_balance_change(addr(1), U256::from(100));
        r.record_storage_write(addr(2), U256::from(7), U256::from(42));
        r.record_nonce_change(addr(1), 1);
        r.record_storage_read(addr(3), U256::from(0));
        assert!(r.touched_addresses.contains(&addr(1)));
        assert!(r.touched_addresses.contains(&addr(2)));
        assert!(r.touched_addresses.contains(&addr(3)));
        r.tx_restore(tx_cp);
        // All traces of tx 2 removed.
        assert!(!r.balance_changes.contains_key(&addr(1)));
        assert!(!r.nonce_changes.contains_key(&addr(1)));
        assert!(!r.storage_writes.contains_key(&addr(2)));
        // Fresh writes NOT promoted to reads on tx_restore.
        assert!(
            r.storage_reads
                .get(&addr(2))
                .map(|s| !s.contains(&U256::from(7)))
                .unwrap_or(true)
        );
        // touched_addresses truncated back.
        assert!(!r.touched_addresses.contains(&addr(1)));
        assert!(!r.touched_addresses.contains(&addr(2)));
        assert!(!r.touched_addresses.contains(&addr(3)));
        // Tx 1's committed change preserved.
        assert!(r.balance_changes.contains_key(&addr(99)));
        // current_index rewound to tx 2's start (= tx 2's index).
        assert_eq!(r.current_index, 2);
    }

    #[test]
    fn set_block_access_index_clears_journals() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_balance_change(addr(1), U256::from(10));
        assert_eq!(r.balance_changes_journal.len(), 1);
        r.set_block_access_index(2);
        // Journal cleared on advance — stale entries would point past filter_net_zero
        // mutations.
        assert_eq!(r.balance_changes_journal.len(), 0);
        assert_eq!(r.storage_writes_journal.len(), 0);
        assert_eq!(r.nonce_changes_journal.len(), 0);
        assert_eq!(r.code_changes_journal.len(), 0);
        assert_eq!(r.reads_promoted_journal.len(), 0);
    }

    #[test]
    fn checkpoint_after_set_block_access_index_isolates_tx() {
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_balance_change(addr(1), U256::from(10)); // committed tx 1
        r.set_block_access_index(2);
        let cp = r.checkpoint();
        r.record_balance_change(addr(2), U256::from(20));
        r.restore(cp);
        // Tx 1's change preserved, tx 2's change reverted.
        assert!(r.balance_changes.contains_key(&addr(1)));
        assert!(!r.balance_changes.contains_key(&addr(2)));
    }

    #[test]
    fn restore_walks_journal_in_correct_order() {
        // Stress: multiple addresses interleaved.
        let mut r = BlockAccessListRecorder::new();
        r.set_block_access_index(1);
        r.record_balance_change(addr(1), U256::from(10));
        r.record_balance_change(addr(2), U256::from(20));
        let cp = r.checkpoint();
        r.record_balance_change(addr(1), U256::from(11));
        r.record_balance_change(addr(2), U256::from(21));
        r.record_balance_change(addr(3), U256::from(30));
        r.record_balance_change(addr(1), U256::from(12));
        r.restore(cp);
        // Each address restored to exactly its pre-checkpoint state.
        assert_eq!(r.balance_changes[&addr(1)].len(), 1);
        assert_eq!(r.balance_changes[&addr(1)][0].1, U256::from(10));
        assert_eq!(r.balance_changes[&addr(2)].len(), 1);
        assert_eq!(r.balance_changes[&addr(2)][0].1, U256::from(20));
        assert!(!r.balance_changes.contains_key(&addr(3)));
    }
}
