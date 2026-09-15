use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    constants::{EMPTY_KECCAK_HASH, EMPTY_TRIE_HASH},
    types::{
        AccountState, AccountUpdate, BlockHash, BlockHeader, BlockNumber, ChainConfig, Code,
        CodeMetadata,
    },
};
use ethrex_crypto::keccak::keccak_hash;
use ethrex_storage::Store;
use ethrex_vm::{EvmError, PrecompileMoves, VmDatabase};
use rustc_hash::FxHashMap;
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
};
use tracing::instrument;

/// Per-address overlay applied by [`OverlaidVmDatabase`].
///
/// Each field is independently overridable. `storage_mode` is mutually exclusive
/// per geth semantics: an address picks `Replace` (entire storage replaced; missing
/// slots read zero) or `Diff` (overlay on real storage; missing slots fall through)
/// or `None`.
#[derive(Clone, Debug, Default)]
pub struct StateOverride {
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    /// Override bytecode together with its precomputed `keccak256(code)` hash.
    pub code: Option<(H256, Code)>,
    pub storage_mode: StorageMode,
    /// `movePrecompileToAddress`: caller of `address` executes the precompile at `target`.
    pub move_precompile_to: Option<Address>,
}

impl StateOverride {
    /// True if this override carries no effective change.
    pub fn is_noop(&self) -> bool {
        self.balance.is_none()
            && self.nonce.is_none()
            && self.code.is_none()
            && matches!(self.storage_mode, StorageMode::None)
            && self.move_precompile_to.is_none()
    }
}

/// Storage override mode. `Replace` short-circuits inner reads; `Diff` overlays.
#[derive(Clone, Debug, Default)]
pub enum StorageMode {
    #[default]
    None,
    /// Replace storage entirely. Slots not in the map read as zero.
    Replace(BTreeMap<H256, U256>),
    /// Overlay on inner storage. Slots not in the map fall through to the inner DB.
    Diff(BTreeMap<H256, U256>),
}

/// `VmDatabase` decorator that applies a set of [`StateOverride`]s on top of an
/// inner database. Used by RPC simulation paths (`eth_call`, `eth_estimateGas`,
/// `eth_createAccessList`, `debug_traceCall`) to honor geth's State Override Set.
///
/// `base_block_number` is the number of the real header the call is being made against.
/// A Block Override Set may synthesize a header at some other height, and `BLOCKHASH`
/// must not answer from beyond the real one: geth builds its hash function from the real
/// header before applying the overrides and returns zero for any number at or above it
/// (`core/vm.GetHashFn`, `ref.Number.Uint64() <= n`). LEVM's own 256-block window is
/// measured against the *synthetic* number, exactly as geth's `opBlockhash` measures its
/// window against the overridden `BlockNumber`, so this is the second of the two gates
/// geth applies, not a replacement for it.
#[derive(Clone)]
pub struct OverlaidVmDatabase<Inner> {
    inner: Inner,
    overrides: Arc<BTreeMap<Address, StateOverride>>,
    base_block_number: BlockNumber,
}

impl<Inner> OverlaidVmDatabase<Inner> {
    /// `overrides` arrives shared rather than owned: `eth_estimateGas` builds one
    /// overlay per binary-search step, and copying the map — with a storage map inside
    /// every entry — on each of them is pure waste.
    pub fn new(
        inner: Inner,
        overrides: Arc<BTreeMap<Address, StateOverride>>,
        base_block_number: BlockNumber,
    ) -> Self {
        Self {
            inner,
            overrides,
            base_block_number,
        }
    }

    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    pub fn overrides(&self) -> &BTreeMap<Address, StateOverride> {
        &self.overrides
    }
}

impl<Inner: VmDatabase + Clone> VmDatabase for OverlaidVmDatabase<Inner> {
    // The batch methods are deliberately left to their trait defaults, which loop the
    // single-key ones above — the only place the overrides are applied. Forwarding them to
    // the inner database would read straight past the overlay. One consequence to know
    // before wiring them anywhere: the default `get_account_codes_batch` maps a missing
    // hash to `Err`, where `StoreVmDatabase`'s own batch deliberately reports `Ok(None)`.
    // Nothing reaches it today, since the override paths build no `CachingDatabase` and
    // `prefetch_codes` has no callers.
    fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
        let base = self.inner.get_account_state(address)?;
        let Some(ov) = self.overrides.get(&address) else {
            return Ok(base);
        };
        if ov.is_noop() {
            return Ok(base);
        }
        // Synthesize an account if the address is unknown on chain but the override
        // gives it state. Other overrides keep the account absent, and deliberately:
        //
        // - `movePrecompileToAddress` changes dispatch, not state, so it has no account
        //   to give.
        // - A `state`/`stateDiff`-only override leaves the account absent while
        //   `get_storage_slot` below still answers from the overlay. geth's `SetStorage`
        //   does create a state object, and `StateOverride.Apply` finishes with
        //   `Finalise(false)`, which does not prune it — but that object is `empty()`, and
        //   both clients gate what is observable on emptiness rather than on presence:
        //   geth's `EXTCODEHASH` returns zero for an empty account, and here
        //   `LevmAccount::from(AccountState)` derives `exists` from the state differing
        //   from the default, so synthesizing `AccountState::default()` would not change
        //   what the EVM sees either. Storage is reachable both ways because
        //   `GeneralizedDatabase::get_storage_value` reads through to the database
        //   without consulting `exists`.
        let mut state = match base {
            Some(s) => s,
            None if ov.balance.is_some() || ov.nonce.is_some() || ov.code.is_some() => {
                AccountState::default()
            }
            None => return Ok(None),
        };
        if let Some(b) = ov.balance {
            state.balance = b;
        }
        if let Some(n) = ov.nonce {
            state.nonce = n;
        }
        if let Some((h, _)) = &ov.code {
            state.code_hash = *h;
        }
        // `storage_root` has to follow the storage override, even though no slot read
        // goes through it. `LevmAccount::from` turns it into `has_storage`
        // (`crates/vm/levm/src/account.rs:78`) and folds it into `exists`, and
        // `create_would_collide` reads `has_storage` — so passing the real root through
        // let a `state` override that empties an account still abort a simulated CREATE2
        // on it with `AddressAlreadyOccupied`, while every slot read zero. geth does not:
        // `SetStorage` installs a fresh object built by `NewEmptyStateAccount`, whose
        // `Root` is `EmptyRootHash`, so its collision check sees no storage either.
        //
        // The non-empty answer is a sentinel, never a real root; nothing on this path may
        // commit it or compare it to one. Only its emptiness is ever read.
        state.storage_root = match &ov.storage_mode {
            // No storage override: the account keeps whatever the chain says.
            StorageMode::None => state.storage_root,
            // `state`: a closed world. The account has storage only if this map gives it
            // some, exactly as geth's replacement object does.
            StorageMode::Replace(map) => storage_root_for(map.values().any(|v| !v.is_zero())),
            // `stateDiff`: an overlay. Real storage survives underneath, so the account
            // has storage if it already did or if the overlay adds a non-zero slot.
            StorageMode::Diff(map) => {
                if state.storage_root != *EMPTY_TRIE_HASH {
                    state.storage_root
                } else {
                    storage_root_for(map.values().any(|v| !v.is_zero()))
                }
            }
        };
        Ok(Some(state))
    }

    fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
        let Some(ov) = self.overrides.get(&address) else {
            return self.inner.get_storage_slot(address, key);
        };
        match &ov.storage_mode {
            StorageMode::None => self.inner.get_storage_slot(address, key),
            // Replace: missing slots read as zero. Short-circuit; never touch inner.
            StorageMode::Replace(map) => Ok(Some(map.get(&key).copied().unwrap_or_default())),
            // Diff: overlay. Missing slots fall through.
            StorageMode::Diff(map) => match map.get(&key) {
                Some(v) => Ok(Some(*v)),
                None => self.inner.get_storage_slot(address, key),
            },
        }
    }

    fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
        // geth returns zero for BLOCKHASH(n) once n reaches the number of the real
        // header the call is made against, however far ahead a `number` override moved
        // the synthetic block. Clamping at the chain tip instead would answer with real
        // canonical hashes for the blocks between the two.
        if block_number >= self.base_block_number {
            return Ok(H256::zero());
        }
        self.inner.get_block_hash(block_number)
    }

    fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
        self.inner.get_chain_config()
    }

    fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(Code::default());
        }
        // Synthetic-code lookup. The number of overrides per call is small (tens at
        // most), so a linear scan is cheaper than maintaining a parallel map.
        for ov in self.overrides.values() {
            if let Some((h, code)) = &ov.code
                && *h == code_hash
            {
                return Ok(code.clone());
            }
        }
        self.inner.get_account_code(code_hash)
    }

    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(CodeMetadata { length: 0 });
        }
        for ov in self.overrides.values() {
            if let Some((h, code)) = &ov.code
                && *h == code_hash
            {
                return Ok(CodeMetadata {
                    length: code.len() as u64,
                });
            }
        }
        self.inner.get_code_metadata(code_hash)
    }

    fn code_cache_budget_bytes(&self) -> u64 {
        // The overlay holds no bytecode cache of its own, so this is the inner
        // backend's budget. Reporting the trait default instead would have the
        // simulation paths warm against a figure the backend never agreed to.
        self.inner.code_cache_budget_bytes()
    }
}

/// Stand-in `storage_root` for an account that has storage without this layer
/// materialising a trie for it: one the replay wrote to, or one a State Override Set gave
/// slots to.
///
/// **Not a real trie root.** On this path `storage_root` feeds two things downstream:
/// `LevmAccount::has_storage` (`crates/vm/levm/src/account.rs:78`, the EIP-7610
/// create-collision check), which asks only whether the root differs from
/// `EMPTY_TRIE_HASH`; and, less directly, `LevmAccount::exists`
/// (`crates/vm/levm/src/account.rs:83`), via `state == AccountState::default()` — a
/// stale non-empty root can flip `exists` from `false` to `true` for an account with
/// zero nonce, zero balance and no code, changing `EXTCODEHASH` for that account from
/// `0` to `keccak("")`. Both are still fail-closed, and both are effectively
/// unreachable: the `exists` case needs that pre-EIP-161 relic shape. Computing the
/// true root would mean hashing a storage trie for a value nothing on this path needs
/// precisely.
///
/// Never commit this value, and never compare it to a real root — a warning that also
/// covers a case that never produces the sentinel itself: when `removed_storage` is
/// false and the base root is non-empty, `get_account_state` below returns that base
/// root unchanged regardless of `added_storage`. That stale value is just as
/// uncommittable, and worse, in that it looks exactly like a real trie root.
const UNMATERIALISED_STORAGE_ROOT: H256 = H256([0xff; 32]);

/// The `storage_root` to report for an account whose storage this layer knows only as a
/// map: the sentinel when it holds anything, the empty-trie root when it does not. Only
/// the distinction between the two is ever read — see [`UNMATERIALISED_STORAGE_ROOT`].
fn storage_root_for(has_storage: bool) -> H256 {
    if has_storage {
        UNMATERIALISED_STORAGE_ROOT
    } else {
        *EMPTY_TRIE_HASH
    }
}

/// `VmDatabase` decorator that layers a finished block replay over the state that replay
/// started from, so the replay can be read as a database.
///
/// `debug_traceCall` with `txIndex`, or against a block whose post-state is not stored,
/// has to rebuild state by re-executing blocks. That replay must not observe a State
/// Override Set: the block's own transactions really happened and have to execute against
/// the state they really saw. Materialising the replay here lets the override decorator
/// sit *above* it, which is geth's ordering — `StateAtTransaction` first,
/// `StateOverride.Apply` second. See [`OverlaidVmDatabase`], the layer that goes on top.
///
/// `updates` come from `Evm::get_state_transitions`, the same value the commit path writes
/// to the trie. Hence the invariant this type owes its callers: a read here must match
/// what a [`StoreVmDatabase`] opened on `apply_account_updates(inner, updates)` returns.
#[derive(Clone)]
pub struct ReplayedVmDatabase<Inner> {
    inner: Inner,
    updates: Arc<FxHashMap<Address, AccountUpdate>>,
}

impl<Inner> ReplayedVmDatabase<Inner> {
    /// `updates` must carry at most one entry per address, as
    /// `Evm::get_state_transitions` guarantees. A second update for the same address
    /// overwrites the first rather than merging with it — see `AccountUpdate::merge`
    /// (`crates/common/types/account_update.rs:38-50`) if a caller needs that instead.
    pub fn new(inner: Inner, updates: Vec<AccountUpdate>) -> Self {
        Self {
            inner,
            updates: Arc::new(updates.into_iter().map(|u| (u.address, u)).collect()),
        }
    }
}

impl<Inner: VmDatabase + Clone> VmDatabase for ReplayedVmDatabase<Inner> {
    // Same as `OverlaidVmDatabase`: the batch methods keep their trait defaults so they
    // loop the single-key ones and see the replay, rather than the state it started from.
    fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
        let Some(update) = self.updates.get(&address) else {
            return self.inner.get_account_state(address);
        };
        if update.removed {
            return Ok(None);
        }
        let base = self.inner.get_account_state(address)?;
        // `storage_root` feeds `LevmAccount::has_storage` (the EIP-7610 create-collision
        // check) and, less directly, `LevmAccount::exists` — see the caveat on
        // `UNMATERIALISED_STORAGE_ROOT` above. `AccountUpdate` carries no root, so serve
        // one that answers those questions the way the committed state would.
        //
        // Ground truth is `apply_account_updates_from_trie_batch`
        // (`crates/storage/store.rs:2734-2762`): `removed_storage` resets the root to
        // empty, and a non-empty `added_storage` then rebuilds the trie on top of that
        // reset — inserting non-zero values, removing zero ones — and overwrites the
        // root. So the committed root is non-empty exactly when the resulting trie is.
        //
        // One residual over-report is accepted: if the base trie is non-empty and
        // `added_storage` zeroes every slot in it, the true root is empty and this still
        // reports non-empty. Detecting that needs the real trie, which this layer
        // deliberately does not open, and over-reporting a collision is the safe
        // direction to be wrong in.
        let storage_root = |base_root: H256| {
            let root_after_wipe = if update.removed_storage {
                *EMPTY_TRIE_HASH
            } else {
                base_root
            };
            if root_after_wipe != *EMPTY_TRIE_HASH {
                root_after_wipe
            } else if update.added_storage.values().any(|v| !v.is_zero()) {
                UNMATERIALISED_STORAGE_ROOT
            } else {
                *EMPTY_TRIE_HASH
            }
        };
        // No `info` means a storage-only update: the account itself is unchanged, and an
        // `added_storage` entry alone must never bring an absent account into existence.
        let Some(info) = &update.info else {
            return Ok(base.map(|mut state| {
                state.storage_root = storage_root(state.storage_root);
                state
            }));
        };
        let mut state = base.unwrap_or_default();
        state.balance = info.balance;
        state.nonce = info.nonce;
        state.code_hash = info.code_hash;
        state.storage_root = storage_root(state.storage_root);
        Ok(Some(state))
    }

    fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
        let Some(update) = self.updates.get(&address) else {
            return self.inner.get_storage_slot(address, key);
        };
        // Closed world, checked ahead of `added_storage`: the commit path never
        // consults `added_storage` for a removed account
        // (`apply_account_updates_from_trie_batch`, `crates/storage/store.rs:2727-2731`,
        // removes the account from the trie and moves on to the next update).
        if update.removed {
            return Ok(Some(U256::zero()));
        }
        if let Some(value) = update.added_storage.get(&key) {
            return Ok(Some(*value));
        }
        // `removed_storage` wipes the storage of a destroyed-then-recreated account,
        // whose `added_storage` above *is* its new storage — this check has to stay
        // below the lookup. A slot the replay did not write reads zero, never the
        // stale trie value.
        if update.removed_storage {
            return Ok(Some(U256::zero()));
        }
        self.inner.get_storage_slot(address, key)
    }

    fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(Code::default());
        }
        // `get_state_transitions` clears the replay's `codes` map, so these updates are
        // the only record of bytecode the replay deployed. Linear scan for the same
        // reason `OverlaidVmDatabase` does: one block's modified-account set is small.
        for update in self.updates.values() {
            if let Some(code) = &update.code
                && code.hash == code_hash
            {
                return Ok(code.clone());
            }
        }
        self.inner.get_account_code(code_hash)
    }

    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(CodeMetadata { length: 0 });
        }
        for update in self.updates.values() {
            if let Some(code) = &update.code
                && code.hash == code_hash
            {
                return Ok(CodeMetadata {
                    length: code.len() as u64,
                });
            }
        }
        self.inner.get_code_metadata(code_hash)
    }

    fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
        self.inner.get_block_hash(block_number)
    }

    fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
        self.inner.get_chain_config()
    }

    fn code_cache_budget_bytes(&self) -> u64 {
        self.inner.code_cache_budget_bytes()
    }
}

/// Derive the precompile-dispatch changes a set of overrides implies, in the form LEVM
/// consumes.
///
/// Both halves come from the same map, matching geth's `StateOverride.Apply`: the
/// `movePrecompileToAddress` relocations, and the suppression of **every** overridden
/// address (geth's `delete(precompiles, addr)`), so overriding a precompile address at all
/// takes it out of the active set.
///
/// Validation of the moves themselves — that the source is a precompile, and that the
/// destination is not itself overridden — happens at the RPC layer, where the active fork
/// is known and the failure can be reported as a bad parameter.
pub fn precompile_moves(overrides: &BTreeMap<Address, StateOverride>) -> PrecompileMoves {
    PrecompileMoves::from_parts(
        overrides
            .iter()
            .filter_map(|(source, ov)| ov.move_precompile_to.map(|dest| (*source, dest))),
        overrides.keys().copied(),
    )
}

/// Helper to compute the synthetic code hash for an override `code` blob.
///
/// Exposed so RPC code can build [`StateOverride::code`] without re-importing
/// the crypto crate.
pub fn synthetic_code(bytecode: Bytes) -> (H256, Code) {
    let hash = H256(keccak_hash(bytecode.as_ref()));
    let code = Code::from_bytecode_unchecked(bytecode, hash);
    (hash, code)
}

/// Accumulated state of an `eth_simulateV1` run: everything that changed since
/// the base block, across all simulated blocks executed so far (state
/// overrides materialized as [`AccountUpdate`]s plus each block's execution
/// results). It is the single source of truth for both reads (via
/// [`SimulationVmDatabase`]) and per-block state roots (re-applying
/// `updates_vec()` onto the base block's trie).
#[derive(Clone, Debug, Default)]
pub struct SimulationOverlay {
    /// Cumulative per-address changes, merged with [`Self::merge_update`].
    updates: BTreeMap<Address, AccountUpdate>,
    /// Bytecode for overridden and simulation-deployed accounts, by code hash.
    codes: FxHashMap<H256, Code>,
    /// Hashes of previously simulated blocks, for `BLOCKHASH`.
    block_hashes: BTreeMap<BlockNumber, BlockHash>,
    /// Height of the base (real) block the simulation runs on.
    base_block_number: BlockNumber,
}

impl SimulationOverlay {
    pub fn new(base_block_number: BlockNumber) -> Self {
        SimulationOverlay {
            base_block_number,
            ..Default::default()
        }
    }

    /// Merge one more [`AccountUpdate`] into the accumulated set.
    ///
    /// [`AccountUpdate::merge`] is not usable here: it neither clears
    /// accumulated `added_storage` on an incoming `removed`/`removed_storage`
    /// nor handles re-creation over a destroyed account. Re-creation must not
    /// keep `removed: true` — the trie application
    /// (`apply_account_updates_from_trie_batch`) short-circuits on `removed`
    /// and would drop the new `info` — so it is folded into
    /// `removed_storage: true` + `info` instead.
    pub fn merge_update(&mut self, update: AccountUpdate) {
        if let (Some(info), Some(code)) = (&update.info, &update.code) {
            self.codes.insert(info.code_hash, code.clone());
        }
        let entry = self
            .updates
            .entry(update.address)
            .or_insert_with(|| AccountUpdate::new(update.address));
        if update.removed {
            // Destruction voids everything accumulated for the address.
            *entry = AccountUpdate::removed(update.address);
        }
        if update.removed_storage {
            entry.added_storage.clear();
            entry.removed_storage = true;
        }
        if let Some(info) = update.info {
            if entry.removed {
                // Re-created over a tombstone: the account exists again with
                // its old storage cleared.
                entry.removed = false;
                entry.removed_storage = true;
                entry.added_storage.clear();
            }
            entry.info = Some(info);
        }
        if let Some(code) = update.code {
            entry.code = Some(code);
        }
        entry.added_storage.extend(update.added_storage);
    }

    /// Snapshot of the cumulative updates, for state-root computation against
    /// the base block's trie.
    pub fn updates_vec(&self) -> Vec<AccountUpdate> {
        self.updates.values().cloned().collect()
    }

    /// Record a finalized simulated block's hash so later blocks resolve it
    /// via `BLOCKHASH`.
    pub fn insert_block_hash(&mut self, number: BlockNumber, hash: BlockHash) {
        self.block_hashes.insert(number, hash);
    }

    pub fn block_hash(&self, number: BlockNumber) -> Option<BlockHash> {
        self.block_hashes.get(&number).copied()
    }

    pub fn get_update(&self, address: &Address) -> Option<&AccountUpdate> {
        self.updates.get(address)
    }
}

/// `VmDatabase` for `eth_simulateV1` block chains: reads go through the
/// cumulative [`SimulationOverlay`] first and fall back to the inner database,
/// which is opened at the base (real) block. This is how simulated block N+1
/// observes block N's execution results without committing anything.
#[derive(Clone)]
pub struct SimulationVmDatabase<Inner> {
    inner: Inner,
    overlay: Arc<SimulationOverlay>,
}

impl<Inner> SimulationVmDatabase<Inner> {
    pub fn new(inner: Inner, overlay: Arc<SimulationOverlay>) -> Self {
        Self { inner, overlay }
    }
}

impl<Inner: VmDatabase + Clone> VmDatabase for SimulationVmDatabase<Inner> {
    fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
        let Some(update) = self.overlay.get_update(&address) else {
            return self.inner.get_account_state(address);
        };
        if update.removed {
            return Ok(None);
        }
        let base = self.inner.get_account_state(address)?;
        let Some(info) = &update.info else {
            // Storage-only change: account identity is whatever the base says.
            return Ok(base);
        };
        // `info` is the full final state of the account (LEVM emits complete
        // `AccountInfo`s), so it replaces the base wholesale.
        let mut state = base.unwrap_or_default();
        state.balance = info.balance;
        state.nonce = info.nonce;
        state.code_hash = info.code_hash;
        // storage_root is left untouched: the wrapper intercepts
        // get_storage_slot directly, so the EVM never observes it.
        Ok(Some(state))
    }

    fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
        let Some(update) = self.overlay.get_update(&address) else {
            return self.inner.get_storage_slot(address, key);
        };
        if let Some(value) = update.added_storage.get(&key) {
            return Ok(Some(*value));
        }
        if update.removed || update.removed_storage {
            // Storage was cleared; slots not re-written read zero.
            return Ok(Some(U256::zero()));
        }
        self.inner.get_storage_slot(address, key)
    }

    fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
        if let Some(hash) = self.overlay.block_hash(block_number) {
            return Ok(hash);
        }
        if block_number <= self.overlay.base_block_number {
            return self.inner.get_block_hash(block_number);
        }
        // Past the head and not simulated (e.g. a gap the caller didn't fill):
        // zero, mirroring OverlaidVmDatabase.
        Ok(H256::zero())
    }

    fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
        self.inner.get_chain_config()
    }

    fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(Code::default());
        }
        if let Some(code) = self.overlay.codes.get(&code_hash) {
            return Ok(code.clone());
        }
        self.inner.get_account_code(code_hash)
    }

    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(CodeMetadata { length: 0 });
        }
        if let Some(code) = self.overlay.codes.get(&code_hash) {
            return Ok(CodeMetadata {
                length: code.len() as u64,
            });
        }
        self.inner.get_code_metadata(code_hash)
    }

    fn code_cache_budget_bytes(&self) -> u64 {
        // Same as `OverlaidVmDatabase`: this layer holds no bytecode cache, so the
        // budget is the inner backend's. Nothing reads it on the simulation path yet;
        // this keeps the fourth wrapper consistent with the other three, so a future
        // bounded warm cannot silently get the 64 MiB trait default here — which would
        // override an inner backend reporting zero to stop warming.
        self.inner.code_cache_budget_bytes()
    }
}

#[derive(Clone, Copy)]
struct AccountStateCacheEntry {
    state: AccountState,
    hashed_address: H256,
}

type AccountStateCache = FxHashMap<Address, Option<AccountStateCacheEntry>>;

#[derive(Clone)]
pub struct StoreVmDatabase {
    pub store: Store,
    pub block_hash: BlockHash,
    // Used to store known block hashes during execution as we look them up when executing BLOCKHASH opcode
    // We will also pre-load this when executing blocks in batches, as we will only add the blocks at the end
    // and may need to access hashes of blocks previously executed in the batch
    pub block_hash_cache: Arc<Mutex<BTreeMap<BlockNumber, BlockHash>>>,
    /// Memoized account states and hashed addresses for storage reads.
    /// This avoids repeated state-trie account decodes when reading many slots
    /// from the same account during execution.
    account_state_cache: Arc<RwLock<AccountStateCache>>,
    pub state_root: H256,
}

impl StoreVmDatabase {
    pub fn new(store: Store, block_header: BlockHeader) -> Result<Self, EvmError> {
        // If we don't have the state for the base, we want to fail in a clear way
        // instead of eventually erroring due to one of the several errors that may
        // happen as a result of executing from the wrong state
        // This lets one easily tell apart an inconsistent state from a syncing issue
        if !store
            .has_state_root(block_header.state_root)
            .map_err(|e| EvmError::DB(e.to_string()))?
        {
            return Err(EvmError::DB(format!(
                "state root missing for block {} (state_root {:#x})",
                block_header.number, block_header.state_root
            )));
        }
        Ok(StoreVmDatabase {
            store,
            block_hash: block_header.hash(),
            block_hash_cache: Arc::new(Mutex::new(BTreeMap::new())),
            account_state_cache: Arc::new(RwLock::new(FxHashMap::default())),
            state_root: block_header.state_root,
        })
    }

    pub fn new_with_block_hash_cache(
        store: Store,
        block_header: BlockHeader,
        block_hash_cache: BTreeMap<BlockNumber, BlockHash>,
    ) -> Result<Self, EvmError> {
        // Fail clearly if prestate is missing. See `StoreVmDatabase::new` for details on why we want this
        if !store
            .has_state_root(block_header.state_root)
            .map_err(|e| EvmError::DB(e.to_string()))?
        {
            return Err(EvmError::DB(format!(
                "state root missing for block {} (state_root {:#x})",
                block_header.number, block_header.state_root
            )));
        }
        Ok(StoreVmDatabase {
            store,
            block_hash: block_header.hash(),
            block_hash_cache: Arc::new(Mutex::new(block_hash_cache)),
            account_state_cache: Arc::new(RwLock::new(FxHashMap::default())),
            state_root: block_header.state_root,
        })
    }

    /// Build a `StoreVmDatabase` for a given `store` without checking that the
    /// state root exists.  For testing only — the test may not have a real
    /// state but still needs to exercise the code-read path.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_test(store: Store) -> Self {
        StoreVmDatabase {
            store,
            block_hash: H256::zero(),
            block_hash_cache: Arc::new(Mutex::new(BTreeMap::new())),
            account_state_cache: Arc::new(RwLock::new(FxHashMap::default())),
            state_root: H256::zero(),
        }
    }

    fn get_cached_account_state_entry(
        &self,
        address: Address,
    ) -> Result<Option<AccountStateCacheEntry>, EvmError> {
        if let Some(entry) = self
            .account_state_cache
            .read()
            .map_err(|_| EvmError::Custom("LockError".to_string()))?
            .get(&address)
            .copied()
        {
            return Ok(entry);
        }

        let loaded = self
            .store
            .get_account_state_by_root(self.state_root, address)
            .map_err(|e| EvmError::DB(e.to_string()))?;
        let cached = loaded.map(|state| AccountStateCacheEntry {
            state,
            hashed_address: H256::from(keccak_hash(address.to_fixed_bytes())),
        });
        self.account_state_cache
            .write()
            .map_err(|_| EvmError::Custom("LockError".to_string()))?
            .insert(address, cached);
        Ok(cached)
    }
}

impl VmDatabase for StoreVmDatabase {
    fn code_cache_budget_bytes(&self) -> u64 {
        self.store.code_cache_budget_bytes()
    }

    #[instrument(
        level = "trace",
        name = "Account read",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
        Ok(self
            .get_cached_account_state_entry(address)?
            .map(|entry| entry.state))
    }

    #[instrument(
        level = "trace",
        name = "Account read batch",
        skip_all,
        fields(namespace = "block_execution", n = addresses.len())
    )]
    fn get_account_states_batch(
        &self,
        addresses: &[Address],
    ) -> Result<Vec<Option<AccountState>>, EvmError> {
        // Split into cached / uncached so the rocksdb multi_get only fires for
        // addresses we haven't memoized yet on this StoreVmDatabase.
        let mut results: Vec<Option<AccountState>> = vec![None; addresses.len()];
        let mut miss_idx: Vec<usize> = Vec::new();
        let mut miss_addrs: Vec<Address> = Vec::new();
        {
            let cache = self
                .account_state_cache
                .read()
                .map_err(|_| EvmError::Custom("LockError".to_string()))?;
            for (i, addr) in addresses.iter().enumerate() {
                match cache.get(addr) {
                    Some(Some(entry)) => results[i] = Some(entry.state),
                    Some(None) => results[i] = None,
                    None => {
                        miss_idx.push(i);
                        miss_addrs.push(*addr);
                    }
                }
            }
        }

        if miss_addrs.is_empty() {
            return Ok(results);
        }

        let fetched = self
            .store
            .get_account_states_batch_by_root(self.state_root, &miss_addrs)
            .map_err(|e| EvmError::DB(e.to_string()))?;

        // Populate the per-DB cache and assemble results. `insert` (vs `or_insert`)
        // is intentional: `state_root` is fixed for this `StoreVmDatabase`, so a
        // concurrent populator can only have written the same value for the same
        // address — overwriting is a no-op, and the unconditional insert avoids
        // the extra `entry`-API lookup.
        let mut cache = self
            .account_state_cache
            .write()
            .map_err(|_| EvmError::Custom("LockError".to_string()))?;
        for ((slot, addr), state) in miss_idx
            .iter()
            .zip(miss_addrs.iter())
            .zip(fetched.into_iter())
        {
            let cached = state.map(|state| AccountStateCacheEntry {
                state,
                hashed_address: H256::from(keccak_hash(addr.to_fixed_bytes())),
            });
            cache.insert(*addr, cached);
            results[*slot] = cached.map(|e| e.state);
        }

        Ok(results)
    }

    #[instrument(
        level = "trace",
        name = "Storage read",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
        let Some(entry) = self.get_cached_account_state_entry(address)? else {
            return Ok(None);
        };
        self.store
            .get_storage_at_root_with_known_storage_root(
                self.state_root,
                entry.hashed_address,
                entry.state.storage_root,
                key,
            )
            .map_err(|e| EvmError::DB(e.to_string()))
    }

    #[instrument(
        level = "trace",
        name = "Storage read batch",
        skip_all,
        fields(namespace = "block_execution", n = keys.len())
    )]
    fn get_storage_slots_batch(
        &self,
        keys: &[(Address, H256)],
    ) -> Result<Vec<Option<U256>>, EvmError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        // Resolve the account state (hashed address + storage root) for each
        // distinct address. This mirrors the per-slot `get_storage_slot` path,
        // which opens the storage trie from the cached account entry. Slots for
        // a non-existent account resolve to `None`, exactly as the single-get
        // path returns `None` when the account entry is missing.
        let mut entries: FxHashMap<Address, Option<AccountStateCacheEntry>> = FxHashMap::default();
        for &(addr, _) in keys {
            if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(addr) {
                slot.insert(self.get_cached_account_state_entry(addr)?);
            }
        }

        // Build the store-batch input for slots whose account exists, remembering
        // the original index so results can be scattered back in input order.
        let mut results: Vec<Option<U256>> = vec![None; keys.len()];
        let mut batch_idx: Vec<usize> = Vec::with_capacity(keys.len());
        let mut batch: Vec<(H256, H256, H256)> = Vec::with_capacity(keys.len());
        for (i, &(addr, key)) in keys.iter().enumerate() {
            if let Some(Some(entry)) = entries.get(&addr) {
                batch_idx.push(i);
                batch.push((entry.hashed_address, entry.state.storage_root, key));
            }
        }

        if batch.is_empty() {
            return Ok(results);
        }

        let fetched = self
            .store
            .get_storage_values_batch_by_root(self.state_root, &batch)
            .map_err(|e| EvmError::DB(e.to_string()))?;
        for (i, value) in batch_idx.into_iter().zip(fetched.into_iter()) {
            results[i] = value;
        }

        Ok(results)
    }

    #[instrument(
        level = "trace",
        name = "Block hash read",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
        let mut block_hash_cache = self
            .block_hash_cache
            .lock()
            .map_err(|_| EvmError::Custom("LockError".to_string()))?;
        // Check if we have it cached
        if let Some(block_hash) = block_hash_cache.get(&block_number) {
            return Ok(*block_hash);
        }
        // First check if our block is canonical, if it is then it's ancestor will also be canonical and we can look it up directly
        if self
            .store
            .is_canonical_sync(self.block_hash)
            .map_err(|err| EvmError::DB(err.to_string()))?
        {
            if let Some(hash) = self
                .store
                .get_canonical_block_hash_sync(block_number)
                .map_err(|err| EvmError::DB(err.to_string()))?
            {
                block_hash_cache.insert(block_number, hash);
                return Ok(hash);
            }
        // If our block is not canonical then we must look for the target in our block's ancestors
        } else {
            // Find the oldest known hash after the target block to shortcut the lookup
            let oldest_succesor = block_hash_cache
                .iter()
                .find_map(|(key, hash)| (*key > block_number).then_some(*hash))
                .unwrap_or(self.block_hash);
            for ancestor_res in self.store.ancestors(oldest_succesor) {
                let (hash, ancestor) = ancestor_res.map_err(|e| EvmError::DB(e.to_string()))?;
                block_hash_cache.insert(ancestor.number, hash);
                match ancestor.number.cmp(&block_number) {
                    Ordering::Greater => continue,
                    Ordering::Equal => return Ok(hash),
                    Ordering::Less => {
                        return Err(EvmError::DB(format!(
                            "Block number requested {block_number} is higher than the current block number {}",
                            ancestor.number
                        )));
                    }
                }
            }
        }
        // Block not found
        Err(EvmError::DB(format!(
            "Block hash not found for block number {block_number}"
        )))
    }

    fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
        Ok(self.store.get_chain_config())
    }

    #[instrument(
        level = "trace",
        name = "Account code read",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(Code::default());
        }
        match self.store.get_account_code(code_hash) {
            Ok(Some(code)) => Ok(code),
            Ok(None) => Err(EvmError::DB(format!(
                "Code not found for hash: {code_hash:?}",
            ))),
            Err(e) => Err(EvmError::DB(e.to_string())),
        }
    }

    #[instrument(
        level = "trace",
        name = "Account codes batch read",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn get_account_codes_batch(&self, code_hashes: &[H256]) -> Result<Vec<Option<Code>>, EvmError> {
        // The empty hash is answered here rather than sent to the store, matching
        // `get_account_code`, so a batch containing EOAs does not fault on it.
        let to_read: Vec<H256> = code_hashes
            .iter()
            .copied()
            .filter(|h| *h != *EMPTY_KECCAK_HASH)
            .collect();
        let read = self
            .store
            .get_account_codes_batch(&to_read)
            .map_err(|e| EvmError::DB(e.to_string()))?;

        let mut by_hash: FxHashMap<H256, Code> = FxHashMap::default();
        for (hash, code) in to_read.iter().zip(read.into_iter()) {
            if let Some(code) = code {
                by_hash.insert(*hash, code);
            }
        }

        Ok(code_hashes
            .iter()
            .map(|h| {
                if *h == *EMPTY_KECCAK_HASH {
                    Some(Code::default())
                } else {
                    by_hash.get(h).cloned()
                }
            })
            .collect())
    }

    #[instrument(
        level = "trace",
        name = "Code metadata read",
        skip_all,
        fields(namespace = "block_execution")
    )]
    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
        use ethrex_common::constants::EMPTY_KECCAK_HASH;

        if code_hash == *EMPTY_KECCAK_HASH {
            return Ok(CodeMetadata { length: 0 });
        }
        match self.store.get_code_metadata(code_hash) {
            Ok(Some(metadata)) => Ok(metadata),
            Ok(None) => Err(EvmError::DB(format!(
                "Code metadata not found for hash: {code_hash:?}",
            ))),
            Err(e) => Err(EvmError::DB(e.to_string())),
        }
    }
}

/// Minimal in-memory `VmDatabase` and helpers shared by the overlay/simulation
/// wrapper tests.
#[cfg(test)]
mod test_mock_db {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    pub(super) struct MockDb {
        pub(super) accounts: Arc<Mutex<BTreeMap<Address, AccountState>>>,
        pub(super) storage: Arc<Mutex<BTreeMap<(Address, H256), U256>>>,
        pub(super) codes: Arc<Mutex<BTreeMap<H256, Code>>>,
        pub(super) block_hashes: Arc<Mutex<BTreeMap<u64, H256>>>,
    }

    /// Deliberately not the 64 MiB trait default, so a wrapper that forwards
    /// `code_cache_budget_bytes` is distinguishable from one that does not.
    pub(super) const MOCK_CODE_CACHE_BUDGET: u64 = 7 * 1024 * 1024;

    impl VmDatabase for MockDb {
        fn code_cache_budget_bytes(&self) -> u64 {
            MOCK_CODE_CACHE_BUDGET
        }

        fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
            Ok(self.accounts.lock().unwrap().get(&address).copied())
        }
        fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
            Ok(self.storage.lock().unwrap().get(&(address, key)).copied())
        }
        fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
            self.block_hashes
                .lock()
                .unwrap()
                .get(&block_number)
                .copied()
                .ok_or_else(|| EvmError::DB(format!("no hash for block {block_number}")))
        }
        fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
            Ok(ChainConfig::default())
        }
        fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
            self.codes
                .lock()
                .unwrap()
                .get(&code_hash)
                .cloned()
                .ok_or_else(|| EvmError::DB(format!("no code for {code_hash:?}")))
        }
        fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
            self.codes
                .lock()
                .unwrap()
                .get(&code_hash)
                .map(|c| CodeMetadata {
                    length: c.len() as u64,
                })
                .ok_or_else(|| EvmError::DB(format!("no code for {code_hash:?}")))
        }
    }

    pub(super) fn addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from(bytes)
    }

    pub(super) fn slot(byte: u8) -> H256 {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        H256::from(bytes)
    }
}

#[cfg(test)]
mod simulation_db_tests {
    use super::test_mock_db::{MOCK_CODE_CACHE_BUDGET, MockDb, addr, slot};
    use super::*;
    use ethrex_common::types::AccountInfo;

    fn info(balance: u64, nonce: u64, code_hash: H256) -> AccountInfo {
        AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash,
        }
    }

    fn update_with_info(address: Address, balance: u64, nonce: u64) -> AccountUpdate {
        AccountUpdate {
            address,
            info: Some(info(balance, nonce, *EMPTY_KECCAK_HASH)),
            ..Default::default()
        }
    }

    #[test]
    fn info_update_replaces_base_wholesale() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(1),
            AccountState {
                balance: U256::from(10),
                nonce: 7,
                ..Default::default()
            },
        );
        let mut overlay = SimulationOverlay::new(0);
        overlay.merge_update(update_with_info(addr(1), 999, 8));
        let db = SimulationVmDatabase::new(mock, Arc::new(overlay));
        let state = db.get_account_state(addr(1)).unwrap().unwrap();
        assert_eq!(state.balance, U256::from(999));
        assert_eq!(state.nonce, 8);
    }

    #[test]
    fn storage_only_update_keeps_base_identity() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(1),
            AccountState {
                nonce: 3,
                ..Default::default()
            },
        );
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(1), slot(1)), U256::from(11));
        let mut overlay = SimulationOverlay::new(0);
        overlay.merge_update(AccountUpdate {
            address: addr(1),
            added_storage: [(slot(2), U256::from(22))].into_iter().collect(),
            ..Default::default()
        });
        let db = SimulationVmDatabase::new(mock, Arc::new(overlay));
        assert_eq!(db.get_account_state(addr(1)).unwrap().unwrap().nonce, 3);
        // Overlaid slot hits the overlay; untouched slot falls through.
        assert_eq!(
            db.get_storage_slot(addr(1), slot(2)).unwrap(),
            Some(U256::from(22))
        );
        assert_eq!(
            db.get_storage_slot(addr(1), slot(1)).unwrap(),
            Some(U256::from(11))
        );
    }

    #[test]
    fn removed_account_reads_absent_and_zero_storage() {
        let mock = MockDb::default();
        mock.accounts
            .lock()
            .unwrap()
            .insert(addr(1), AccountState::default());
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(1), slot(1)), U256::from(11));
        let mut overlay = SimulationOverlay::new(0);
        // Accumulate some state first; destruction must void it.
        overlay.merge_update(AccountUpdate {
            address: addr(1),
            info: Some(info(5, 1, *EMPTY_KECCAK_HASH)),
            added_storage: [(slot(2), U256::from(22))].into_iter().collect(),
            ..Default::default()
        });
        overlay.merge_update(AccountUpdate::removed(addr(1)));
        let db = SimulationVmDatabase::new(mock, Arc::new(overlay.clone()));
        assert!(db.get_account_state(addr(1)).unwrap().is_none());
        assert_eq!(
            db.get_storage_slot(addr(1), slot(1)).unwrap(),
            Some(U256::zero())
        );
        assert_eq!(
            db.get_storage_slot(addr(1), slot(2)).unwrap(),
            Some(U256::zero())
        );
        // The cumulative update must be a plain tombstone for the trie.
        let update = overlay.get_update(&addr(1)).unwrap();
        assert!(update.removed && update.info.is_none() && update.added_storage.is_empty());
    }

    #[test]
    fn recreation_over_tombstone_folds_into_removed_storage() {
        let mock = MockDb::default();
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(1), slot(1)), U256::from(11));
        let mut overlay = SimulationOverlay::new(0);
        overlay.merge_update(AccountUpdate::removed(addr(1)));
        overlay.merge_update(update_with_info(addr(1), 100, 1));
        // `removed` must not survive re-creation: the trie application
        // short-circuits on it and would drop the new info.
        let update = overlay.get_update(&addr(1)).unwrap();
        assert!(!update.removed && update.removed_storage);
        let db = SimulationVmDatabase::new(mock, Arc::new(overlay));
        let state = db.get_account_state(addr(1)).unwrap().unwrap();
        assert_eq!(state.balance, U256::from(100));
        // Pre-destruction storage stays cleared.
        assert_eq!(
            db.get_storage_slot(addr(1), slot(1)).unwrap(),
            Some(U256::zero())
        );
    }

    #[test]
    fn removed_storage_clears_accumulated_slots() {
        let mut overlay = SimulationOverlay::new(0);
        overlay.merge_update(AccountUpdate {
            address: addr(1),
            added_storage: [(slot(1), U256::from(11))].into_iter().collect(),
            ..Default::default()
        });
        overlay.merge_update(AccountUpdate {
            address: addr(1),
            removed_storage: true,
            added_storage: [(slot(2), U256::from(22))].into_iter().collect(),
            ..Default::default()
        });
        let db = SimulationVmDatabase::new(MockDb::default(), Arc::new(overlay));
        assert_eq!(
            db.get_storage_slot(addr(1), slot(1)).unwrap(),
            Some(U256::zero())
        );
        assert_eq!(
            db.get_storage_slot(addr(1), slot(2)).unwrap(),
            Some(U256::from(22))
        );
    }

    #[test]
    fn block_hashes_resolve_real_simulated_and_gap() {
        let mock = MockDb::default();
        let real = H256::repeat_byte(0xaa);
        mock.block_hashes.lock().unwrap().insert(90, real);
        let mut overlay = SimulationOverlay::new(100);
        let simulated = H256::repeat_byte(0xbb);
        overlay.insert_block_hash(101, simulated);
        let db = SimulationVmDatabase::new(mock, Arc::new(overlay));
        assert_eq!(db.get_block_hash(90).unwrap(), real);
        assert_eq!(db.get_block_hash(101).unwrap(), simulated);
        assert_eq!(db.get_block_hash(102).unwrap(), H256::zero());
    }

    #[test]
    fn deployed_code_resolves_by_hash() {
        let (hash, code) = synthetic_code(Bytes::from_static(&[0x60, 0x00]));
        let mut overlay = SimulationOverlay::new(0);
        overlay.merge_update(AccountUpdate {
            address: addr(1),
            info: Some(info(0, 1, hash)),
            code: Some(code.clone()),
            ..Default::default()
        });
        let db = SimulationVmDatabase::new(MockDb::default(), Arc::new(overlay));
        assert_eq!(
            db.get_account_code(hash).unwrap().code_bytes(),
            code.code_bytes()
        );
        assert_eq!(db.get_code_metadata(hash).unwrap().length, 2);
    }

    /// The simulation layer holds no bytecode cache, so the budget has to come from
    /// the backend underneath it. Nothing consumes the value yet, which is exactly why
    /// this is pinned here: a regression would otherwise be invisible until a bounded
    /// warm starts reading it, and the default would silently override an inner
    /// backend reporting zero to stop warming.
    #[test]
    fn code_cache_budget_is_the_inner_backend_s() {
        let db = SimulationVmDatabase::new(MockDb::default(), Arc::new(SimulationOverlay::new(0)));
        assert_eq!(db.code_cache_budget_bytes(), MOCK_CODE_CACHE_BUDGET);
        // Without the forward this would be the trait default instead.
        assert_ne!(db.code_cache_budget_bytes(), 64 * 1024 * 1024);
    }
}

#[cfg(test)]
mod overlaid_db_tests {
    use super::test_mock_db::{MockDb, addr, slot};
    use super::*;

    #[test]
    fn balance_override_returns_synthetic_balance() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(1),
            AccountState {
                balance: U256::from(10),
                ..Default::default()
            },
        );
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(1),
            StateOverride {
                balance: Some(U256::from(999)),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        let state = wrapper.get_account_state(addr(1)).unwrap().unwrap();
        assert_eq!(state.balance, U256::from(999));
    }

    #[test]
    fn nonce_override_returns_synthetic_nonce() {
        let mock = MockDb::default();
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(2),
            StateOverride {
                nonce: Some(42),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        // Address has no real state — wrapper should synthesize.
        let state = wrapper.get_account_state(addr(2)).unwrap().unwrap();
        assert_eq!(state.nonce, 42);
    }

    #[test]
    fn missing_account_with_only_move_precompile_is_still_absent() {
        let mock = MockDb::default();
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(3),
            StateOverride {
                move_precompile_to: Some(addr(0xaa)),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        // movePrecompileToAddress alone doesn't materialize an account.
        assert!(wrapper.get_account_state(addr(3)).unwrap().is_none());
        assert_eq!(
            precompile_moves(wrapper.overrides()).source_for(&addr(0xaa)),
            Some(addr(3))
        );
    }

    /// geth's `StateOverride.Apply` does `delete(precompiles, addr)` for **any** overridden
    /// address, not only the source of a move: overriding a precompile address at all takes
    /// it out of the active precompile set.
    #[test]
    fn overriding_a_precompile_address_at_all_vacates_it() {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(4),
            StateOverride {
                balance: Some(U256::one()),
                ..Default::default()
            },
        );
        let moves = precompile_moves(&overrides);
        assert!(
            moves.is_suppressed(&addr(4)),
            "a balance override on a precompile address must vacate it"
        );
        assert_eq!(moves.source_for(&addr(4)), None, "nothing was relocated");
    }

    #[test]
    fn code_override_synthesizes_hash_and_returns_code() {
        let mock = MockDb::default();
        let (hash, code) = synthetic_code(Bytes::from_static(&[0x60, 0x01, 0x60, 0x01, 0x52]));
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(4),
            StateOverride {
                code: Some((hash, code.clone())),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        let state = wrapper.get_account_state(addr(4)).unwrap().unwrap();
        assert_eq!(state.code_hash, hash);
        let fetched = wrapper.get_account_code(hash).unwrap();
        assert_eq!(fetched, code);
        let meta = wrapper.get_code_metadata(hash).unwrap();
        assert_eq!(meta.length as usize, code.len());
    }

    #[test]
    fn replace_mode_short_circuits_missing_slots_to_zero() {
        let mock = MockDb::default();
        // Inner has slot(0) = 0xff at addr(5)
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(5), slot(0)), U256::from(0xff));
        let mut state = BTreeMap::new();
        state.insert(slot(1), U256::from(0xaa));
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(5),
            StateOverride {
                storage_mode: StorageMode::Replace(state),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        // Slot 0 should NOT see the inner 0xff because Replace mode erases it.
        assert_eq!(
            wrapper.get_storage_slot(addr(5), slot(0)).unwrap(),
            Some(U256::zero())
        );
        // Slot 1 sees the override value.
        assert_eq!(
            wrapper.get_storage_slot(addr(5), slot(1)).unwrap(),
            Some(U256::from(0xaa))
        );
    }

    #[test]
    fn diff_mode_overlays_and_falls_through() {
        let mock = MockDb::default();
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(6), slot(0)), U256::from(0xff));
        let mut diff = BTreeMap::new();
        diff.insert(slot(1), U256::from(0xaa));
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(6),
            StateOverride {
                storage_mode: StorageMode::Diff(diff),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        // Diff mode: real slot 0 is preserved.
        assert_eq!(
            wrapper.get_storage_slot(addr(6), slot(0)).unwrap(),
            Some(U256::from(0xff))
        );
        // Diff mode: override slot 1 wins.
        assert_eq!(
            wrapper.get_storage_slot(addr(6), slot(1)).unwrap(),
            Some(U256::from(0xaa))
        );
    }

    /// The cutoff is the base block's own number, not the chain tip: geth's hash
    /// function is built from the real header before the block overrides are applied, so
    /// it answers zero from that height upwards. A tip-based cutoff would serve the real
    /// hashes of blocks 100..=tip to a call whose synthetic number sits past them.
    /// A `state` override that empties an account has to empty its `storage_root` too.
    ///
    /// No slot read consults the root, but `LevmAccount::from` turns it into
    /// `has_storage`, and `create_would_collide` reads that — so a stale real root made a
    /// simulated CREATE2 abort on an account the EVM could see was empty in every other
    /// way. geth's `SetStorage` installs an object whose `Root` is `EmptyRootHash`, so it
    /// does not collide either.
    #[test]
    fn replace_mode_empties_the_storage_root_when_it_empties_the_account() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(8),
            AccountState {
                // A real, non-empty root: this account has storage on chain.
                storage_root: H256::from_low_u64_be(0xbeef),
                ..Default::default()
            },
        );
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(8),
            StateOverride {
                storage_mode: StorageMode::Replace(BTreeMap::new()),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        let state = wrapper.get_account_state(addr(8)).unwrap().unwrap();
        assert_eq!(
            state.storage_root, *EMPTY_TRIE_HASH,
            "an emptied account must not keep a root that reads as having storage"
        );
    }

    /// The other direction: `state` with values, and `stateDiff` adding one, must report
    /// storage even though no trie was built for either.
    #[test]
    fn an_override_that_gives_storage_reports_a_non_empty_root() {
        for mode in [
            StorageMode::Replace(BTreeMap::from([(slot(1), U256::from(5))])),
            StorageMode::Diff(BTreeMap::from([(slot(1), U256::from(5))])),
        ] {
            let mut overrides = BTreeMap::new();
            overrides.insert(
                addr(9),
                StateOverride {
                    balance: Some(U256::one()),
                    storage_mode: mode,
                    ..Default::default()
                },
            );
            let wrapper = OverlaidVmDatabase::new(MockDb::default(), Arc::new(overrides), 0);
            let state = wrapper.get_account_state(addr(9)).unwrap().unwrap();
            assert_ne!(
                state.storage_root, *EMPTY_TRIE_HASH,
                "an override that gives an account slots must report storage"
            );
        }
    }

    /// `stateDiff` is an overlay, so the real storage underneath still counts even when
    /// the overlay itself only zeroes slots.
    #[test]
    fn diff_mode_keeps_a_real_root_it_did_not_empty() {
        let mock = MockDb::default();
        let real_root = H256::from_low_u64_be(0xbeef);
        mock.accounts.lock().unwrap().insert(
            addr(10),
            AccountState {
                storage_root: real_root,
                ..Default::default()
            },
        );
        let mut overrides = BTreeMap::new();
        overrides.insert(
            addr(10),
            StateOverride {
                storage_mode: StorageMode::Diff(BTreeMap::from([(slot(1), U256::zero())])),
                ..Default::default()
            },
        );
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        let state = wrapper.get_account_state(addr(10)).unwrap().unwrap();
        assert_eq!(
            state.storage_root, real_root,
            "a diff that zeroes one slot does not empty the storage underneath it"
        );
    }

    #[test]
    fn block_hash_at_or_past_the_base_block_returns_zero() {
        let mock = MockDb::default();
        for number in [50u64, 100, 150] {
            mock.block_hashes
                .lock()
                .unwrap()
                .insert(number, H256::from_low_u64_be(0xdead));
        }
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(BTreeMap::new()), 100);
        // Below the base block: delegates.
        assert_eq!(
            wrapper.get_block_hash(50).unwrap(),
            H256::from_low_u64_be(0xdead)
        );
        // The base block itself, and anything above it: zero, even though the inner
        // database holds a hash for both.
        assert_eq!(wrapper.get_block_hash(100).unwrap(), H256::zero());
        assert_eq!(wrapper.get_block_hash(150).unwrap(), H256::zero());
    }

    #[test]
    fn noop_override_passes_through_inner_state() {
        let mock = MockDb::default();
        let original = AccountState {
            balance: U256::from(7),
            nonce: 3,
            ..Default::default()
        };
        mock.accounts.lock().unwrap().insert(addr(7), original);
        let mut overrides = BTreeMap::new();
        overrides.insert(addr(7), StateOverride::default());
        let wrapper = OverlaidVmDatabase::new(mock, Arc::new(overrides), 0);
        let state = wrapper.get_account_state(addr(7)).unwrap().unwrap();
        assert_eq!(state.balance, U256::from(7));
        assert_eq!(state.nonce, 3);
    }
}

#[cfg(test)]
mod replayed_db_tests {
    use super::test_mock_db::{MockDb, addr, slot};
    use super::*;
    use ethrex_common::types::AccountInfo;

    fn update(address: Address) -> AccountUpdate {
        AccountUpdate {
            address,
            ..Default::default()
        }
    }

    fn info(balance: u64, nonce: u64) -> AccountInfo {
        AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash: *EMPTY_KECCAK_HASH,
        }
    }

    #[test]
    fn untouched_account_falls_through_to_inner() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(1),
            AccountState {
                balance: U256::from(10),
                ..Default::default()
            },
        );
        let db = ReplayedVmDatabase::new(mock, vec![]);
        let state = db.get_account_state(addr(1)).unwrap().unwrap();
        assert_eq!(state.balance, U256::from(10));
    }

    #[test]
    fn replayed_info_replaces_base_info() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(1),
            AccountState {
                balance: U256::from(10),
                nonce: 1,
                ..Default::default()
            },
        );
        let db = ReplayedVmDatabase::new(
            mock,
            vec![AccountUpdate {
                info: Some(info(999, 7)),
                ..update(addr(1))
            }],
        );
        let state = db.get_account_state(addr(1)).unwrap().unwrap();
        assert_eq!(state.balance, U256::from(999));
        assert_eq!(state.nonce, 7);
    }

    #[test]
    fn account_created_by_the_replay_is_synthesized() {
        let db = ReplayedVmDatabase::new(
            MockDb::default(),
            vec![AccountUpdate {
                info: Some(info(5, 1)),
                ..update(addr(2))
            }],
        );
        let state = db.get_account_state(addr(2)).unwrap().unwrap();
        assert_eq!(state.nonce, 1);
        // A fresh account owns no storage.
        assert_eq!(state.storage_root, *EMPTY_TRIE_HASH);
    }

    #[test]
    fn storage_only_update_never_creates_an_absent_account() {
        // An update carrying only `added_storage` must NOT bring an absent account into
        // existence. Mirrors `OverlaidVmDatabase`'s gate on balance/nonce/code.
        let mut added = FxHashMap::default();
        added.insert(slot(1), U256::from(42));
        let db = ReplayedVmDatabase::new(
            MockDb::default(),
            vec![AccountUpdate {
                added_storage: added,
                ..update(addr(3))
            }],
        );
        assert!(db.get_account_state(addr(3)).unwrap().is_none());
    }

    #[test]
    fn removed_account_is_absent_and_reads_zero_storage() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(4),
            AccountState {
                balance: U256::from(10),
                ..Default::default()
            },
        );
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(4), slot(1)), U256::from(7));
        let db = ReplayedVmDatabase::new(
            mock,
            vec![AccountUpdate {
                removed: true,
                ..update(addr(4))
            }],
        );
        assert!(db.get_account_state(addr(4)).unwrap().is_none());
        assert_eq!(
            db.get_storage_slot(addr(4), slot(1)).unwrap(),
            Some(U256::zero())
        );
    }

    #[test]
    fn changed_slot_wins_and_unchanged_slot_falls_through() {
        let mock = MockDb::default();
        mock.accounts
            .lock()
            .unwrap()
            .insert(addr(5), AccountState::default());
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(5), slot(1)), U256::from(1));
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(5), slot(2)), U256::from(2));
        let mut added = FxHashMap::default();
        added.insert(slot(1), U256::from(111));
        let db = ReplayedVmDatabase::new(
            mock,
            vec![AccountUpdate {
                added_storage: added,
                ..update(addr(5))
            }],
        );
        assert_eq!(
            db.get_storage_slot(addr(5), slot(1)).unwrap(),
            Some(U256::from(111))
        );
        assert_eq!(
            db.get_storage_slot(addr(5), slot(2)).unwrap(),
            Some(U256::from(2))
        );
    }

    #[test]
    fn removed_storage_closes_the_world() {
        // Destroyed-and-recreated: slots not in `added_storage` read zero, never the
        // stale trie value. This is the same closed-world rule geth's `fakeStorage` gives.
        let mock = MockDb::default();
        mock.accounts
            .lock()
            .unwrap()
            .insert(addr(6), AccountState::default());
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(6), slot(2)), U256::from(2));
        let mut added = FxHashMap::default();
        added.insert(slot(1), U256::from(111));
        let db = ReplayedVmDatabase::new(
            mock,
            vec![AccountUpdate {
                added_storage: added,
                removed_storage: true,
                info: Some(info(0, 1)),
                ..update(addr(6))
            }],
        );
        assert_eq!(
            db.get_storage_slot(addr(6), slot(1)).unwrap(),
            Some(U256::from(111))
        );
        assert_eq!(
            db.get_storage_slot(addr(6), slot(2)).unwrap(),
            Some(U256::zero())
        );
        // The account was destroyed and repopulated, so it has storage again — the
        // committed root would be the rebuilt trie's, not empty.
        let state = db.get_account_state(addr(6)).unwrap().unwrap();
        assert_ne!(state.storage_root, *EMPTY_TRIE_HASH);
    }

    #[test]
    fn code_deployed_by_the_replay_is_served() {
        let (hash, code) = synthetic_code(bytes::Bytes::from_static(&[0x60, 0x00]));
        let db = ReplayedVmDatabase::new(
            MockDb::default(),
            vec![AccountUpdate {
                info: Some(AccountInfo {
                    balance: U256::zero(),
                    nonce: 1,
                    code_hash: hash,
                }),
                code: Some(code),
                ..update(addr(7))
            }],
        );
        assert_eq!(db.get_account_code(hash).unwrap().len(), 2);
        assert_eq!(db.get_code_metadata(hash).unwrap().length, 2);
        assert_eq!(
            db.get_account_state(addr(7)).unwrap().unwrap().code_hash,
            hash
        );
    }

    // --- The composition claim (spec §7): the overlay sits ABOVE the replay layer. ---
    //
    // This is where `StorageMode::Replace` earns its billing as ethrex's `fakeStorage`
    // equivalent: it must hide not only the trie value but the replay's own write to that
    // account. Tested here rather than through a trace because the claim is purely about
    // layer order, and the two decorators compose without an EVM.

    fn replay_wrote(address: Address, key: H256, value: U256) -> Vec<AccountUpdate> {
        let mut added = FxHashMap::default();
        added.insert(key, value);
        vec![AccountUpdate {
            address,
            added_storage: added,
            ..Default::default()
        }]
    }

    #[test]
    fn replace_mode_hides_the_replays_own_write() {
        let mock = MockDb::default();
        mock.accounts
            .lock()
            .unwrap()
            .insert(addr(8), AccountState::default());
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(8), slot(1)), U256::from(1));
        // The replay wrote slot 1 = 500.
        let replayed =
            ReplayedVmDatabase::new(mock, replay_wrote(addr(8), slot(1), U256::from(500)));
        // A `state` override that mentions only slot 2 closes the world for this account.
        let mut overrides = BTreeMap::new();
        let mut replacement = BTreeMap::new();
        replacement.insert(slot(2), U256::from(7));
        overrides.insert(
            addr(8),
            StateOverride {
                storage_mode: StorageMode::Replace(replacement),
                ..Default::default()
            },
        );
        let db = OverlaidVmDatabase::new(replayed, Arc::new(overrides), 0);
        assert_eq!(
            db.get_storage_slot(addr(8), slot(2)).unwrap(),
            Some(U256::from(7))
        );
        // Neither the trie's 1 nor the replay's 500: closed world means zero.
        assert_eq!(
            db.get_storage_slot(addr(8), slot(1)).unwrap(),
            Some(U256::zero())
        );
    }

    #[test]
    fn diff_mode_falls_through_to_the_replays_write() {
        let mock = MockDb::default();
        mock.accounts
            .lock()
            .unwrap()
            .insert(addr(9), AccountState::default());
        mock.storage
            .lock()
            .unwrap()
            .insert((addr(9), slot(1)), U256::from(1));
        let replayed =
            ReplayedVmDatabase::new(mock, replay_wrote(addr(9), slot(1), U256::from(500)));
        let mut overrides = BTreeMap::new();
        let mut diff = BTreeMap::new();
        diff.insert(slot(2), U256::from(7));
        overrides.insert(
            addr(9),
            StateOverride {
                storage_mode: StorageMode::Diff(diff),
                ..Default::default()
            },
        );
        let db = OverlaidVmDatabase::new(replayed, Arc::new(overrides), 0);
        assert_eq!(
            db.get_storage_slot(addr(9), slot(2)).unwrap(),
            Some(U256::from(7))
        );
        // Not in the diff => the replay's value wins over the trie's.
        assert_eq!(
            db.get_storage_slot(addr(9), slot(1)).unwrap(),
            Some(U256::from(500))
        );
    }

    #[test]
    fn empty_code_hash_is_served_without_touching_inner() {
        // The inner MockDb has no codes at all, so a fall-through would error.
        let db = ReplayedVmDatabase::new(MockDb::default(), vec![]);
        assert_eq!(db.get_account_code(*EMPTY_KECCAK_HASH).unwrap().len(), 0);
        assert_eq!(db.get_code_metadata(*EMPTY_KECCAK_HASH).unwrap().length, 0);
    }

    #[test]
    fn destroyed_account_with_nothing_written_back_reports_no_storage() {
        let mock = MockDb::default();
        mock.accounts.lock().unwrap().insert(
            addr(10),
            AccountState {
                storage_root: H256::from([0xab; 32]),
                ..Default::default()
            },
        );
        let db = ReplayedVmDatabase::new(
            mock,
            vec![AccountUpdate {
                removed_storage: true,
                info: Some(info(0, 1)),
                ..update(addr(10))
            }],
        );
        let state = db.get_account_state(addr(10)).unwrap().unwrap();
        assert_eq!(state.storage_root, *EMPTY_TRIE_HASH);
    }

    #[test]
    fn storage_added_to_a_storageless_account_reports_storage() {
        // Base trie is empty; the replay writes a non-zero slot. The committed root would
        // be non-empty, so `has_storage` must be true.
        let mock = MockDb::default();
        mock.accounts
            .lock()
            .unwrap()
            .insert(addr(11), AccountState::default());
        let mut added = FxHashMap::default();
        added.insert(slot(1), U256::from(1));
        let db = ReplayedVmDatabase::new(
            mock,
            vec![AccountUpdate {
                added_storage: added,
                ..update(addr(11))
            }],
        );
        let state = db.get_account_state(addr(11)).unwrap().unwrap();
        assert_ne!(state.storage_root, *EMPTY_TRIE_HASH);
    }
}
