use crate::{
    EVMConfig, Environment,
    account::{AccountStatus, LevmAccount},
    call_frame::CallFrameBackup,
    constants::*,
    db::gen_db::GeneralizedDatabase,
    errors::{ExceptionalHalt, InternalError, TxValidationError, VMError},
    gas_cost::{
        self, ACCOUNT_WRITE_AMSTERDAM, BLOB_GAS_PER_BLOB, CREATE_BASE_COST,
        PER_AUTH_BASE_COST_AMSTERDAM, STANDARD_TOKEN_COST, WARM_ADDRESS_ACCESS_COST,
        cold_account_access_cost, floor_tokens_in_access_list, total_cost_floor_per_token,
        tx_base_cost,
    },
    vm::{Substate, VM},
};
use ExceptionalHalt::OutOfGas;
use bytes::Bytes;
use ethrex_common::types::Log;
use ethrex_common::{
    Address, H256, U256,
    evm::calculate_create_address,
    types::{Account, Code, Fork, Transaction, fake_exponential, tx_fields::*},
    utils::{keccak, u256_to_big_endian},
};
use ethrex_common::{types::TxKind, utils::u256_from_big_endian_const};
use ethrex_rlp;
use rustc_hash::{FxHashMap, FxHashSet};
pub type Storage = FxHashMap<U256, H256>;

// ================== Address related functions ======================
/// Converts address (H160) to word (U256)
pub fn address_to_word(address: Address) -> U256 {
    let mut word = [0u8; 32];

    for (word_byte, address_byte) in word.iter_mut().skip(12).zip(address.as_bytes().iter()) {
        *word_byte = *address_byte;
    }

    u256_from_big_endian_const(word)
}

/// Calculates the address of a new contract using the CREATE2 opcode as follows
///
/// initialization_code = memory[offset:offset+size]
///
/// address = keccak256(0xff || sender_address || salt || keccak256(initialization_code))[12:]
pub fn calculate_create2_address(
    sender_address: Address,
    initialization_code: &Bytes,
    salt: U256,
) -> Result<Address, InternalError> {
    let init_code_hash = keccak(initialization_code);

    let generated_address = Address::from_slice(
        keccak(
            [
                &[0xff],
                sender_address.as_bytes(),
                &salt.to_big_endian(),
                init_code_hash.as_bytes(),
            ]
            .concat(),
        )
        .as_bytes()
        .get(12..)
        .ok_or(InternalError::Slicing)?,
    );
    Ok(generated_address)
}

// ================== Backup related functions =======================

/// Restore the state of the cache to the state it in the callframe backup.
/// Also restores BAL recorder state changes (but not touched_addresses) per EIP-7928.
pub fn restore_cache_state(
    db: &mut GeneralizedDatabase,
    callframe_backup: CallFrameBackup,
) -> Result<(), VMError> {
    for (address, account) in callframe_backup.original_accounts_info {
        if let Some(current_account) = db.current_accounts_state.get_mut(&address) {
            current_account.info = account.info;
            current_account.status = account.status;
            current_account.has_storage = account.has_storage;
            current_account.exists = account.exists;
        }
    }

    for (address, storage) in callframe_backup.original_account_storage_slots {
        // This call to `get_account_mut` should never return None, because we are looking up accounts
        // that had their storage modified, which means they should be in the cache. That's why
        // we return an internal error in case we haven't found it.
        let account = db
            .current_accounts_state
            .get_mut(&address)
            .ok_or(InternalError::AccountNotFound)?;

        for (key, value) in storage {
            account.storage.insert(key, value);
        }
    }

    // Evict codes the reverted frame(s) deployed: a stale by-hash cache entry
    // would serve a later read of the same hash (from a pre-existing account)
    // without hitting the store, hiding the read from execution-witness
    // recording (EIP-8025). Only hashes that were NOT cached before the frame
    // are tracked, so committed or store-loaded codes are never evicted.
    for code_hash in callframe_backup.inserted_code_hashes {
        db.codes.remove(&code_hash);
    }

    // Restore BAL recorder to checkpoint (but keep touched_addresses per EIP-7928)
    if let Some(checkpoint) = callframe_backup.bal_checkpoint
        && let Some(recorder) = db.bal_recorder.as_mut()
    {
        recorder.restore(checkpoint);
    }

    Ok(())
}

// ================= Blob hash related functions =====================
pub fn get_base_fee_per_blob_gas(
    block_excess_blob_gas: Option<u64>,
    evm_config: &EVMConfig,
) -> Result<U256, VMError> {
    let base_fee_update_fraction = evm_config.blob_schedule.base_fee_update_fraction;
    let excess_blob_gas = block_excess_blob_gas.unwrap_or_default();

    fake_exponential(
        MIN_BASE_FEE_PER_BLOB_GAS.into(),
        excess_blob_gas.into(),
        base_fee_update_fraction,
    )
    .map_err(|err| VMError::Internal(InternalError::FakeExponentialError(err)))
}

/// Gets the max blob gas cost for a transaction that a user is
/// willing to pay.
pub fn get_max_blob_gas_price(
    tx_blob_hashes: &[H256],
    tx_max_fee_per_blob_gas: Option<U256>,
) -> Result<U256, VMError> {
    let blobhash_amount: u64 = tx_blob_hashes
        .len()
        .try_into()
        .map_err(|_| InternalError::TypeConversion)?;

    let blob_gas_used: u64 = blobhash_amount
        .checked_mul(BLOB_GAS_PER_BLOB)
        .unwrap_or_default();

    let max_blob_gas_cost = tx_max_fee_per_blob_gas
        .unwrap_or_default()
        .checked_mul(blob_gas_used.into())
        .ok_or(InternalError::Overflow)?;

    Ok(max_blob_gas_cost)
}
/// Calculate the actual blob gas cost.
pub fn calculate_blob_gas_cost(
    tx_blob_hashes: &[H256],
    base_blob_fee_per_gas: U256,
) -> Result<U256, VMError> {
    let blobhash_amount: u64 = tx_blob_hashes
        .len()
        .try_into()
        .map_err(|_| InternalError::TypeConversion)?;

    let blob_gas_used: u64 = blobhash_amount
        .checked_mul(BLOB_GAS_PER_BLOB)
        .unwrap_or_default();

    let blob_gas_used: U256 = blob_gas_used.into();
    let blob_fee: U256 = blob_gas_used
        .checked_mul(base_blob_fee_per_gas)
        .ok_or(InternalError::Overflow)?;

    Ok(blob_fee)
}

// ==================== Word related functions =======================
pub fn word_to_address(word: U256) -> Address {
    Address::from_slice(&u256_to_big_endian(word)[12..])
}

// ================== EIP-7702 related functions =====================

pub fn code_has_delegation(code: &[u8]) -> Result<bool, VMError> {
    // Delegate to the canonical predicate in `ethrex-common` so the
    // EIP-7702 designation check (`0xef0100 || address`, exactly 23 bytes)
    // has a single source of truth. Signature kept as `&[u8]` for callers.
    Ok(ethrex_common::types::is_eip7702_delegation(code))
}

/// Gets the address inside the bytecode if it has been
/// delegated as the EIP7702 determines.
pub fn get_authorized_address_from_code(code: &[u8]) -> Result<Address, VMError> {
    if code_has_delegation(code)? {
        let address_bytes = &code
            .get(SET_CODE_DELEGATION_BYTES.len()..)
            .ok_or(InternalError::Slicing)?;
        // It shouldn't panic when doing Address::from_slice()
        // because the length is checked inside the code_has_delegation() function
        let address = Address::from_slice(address_bytes);
        Ok(address)
    } else {
        // if we end up here, it means that the address wasn't previously delegated.
        Err(InternalError::AccountNotDelegated.into())
    }
}

pub fn eip7702_recover_address(
    auth_tuple: &AuthorizationTuple,
    crypto: &dyn ethrex_crypto::Crypto,
) -> Result<Option<Address>, VMError> {
    use ethrex_rlp::encode::RLPEncode;

    if auth_tuple.s_signature > *SECP256K1_ORDER_OVER2 || U256::zero() >= auth_tuple.s_signature {
        return Ok(None);
    }
    if auth_tuple.r_signature > *SECP256K1_ORDER || U256::zero() >= auth_tuple.r_signature {
        return Ok(None);
    }
    if auth_tuple.y_parity != U256::one() && auth_tuple.y_parity != U256::zero() {
        return Ok(None);
    }

    let mut rlp_buf = Vec::with_capacity(128);
    rlp_buf.push(MAGIC);
    (auth_tuple.chain_id, auth_tuple.address, auth_tuple.nonce).encode(&mut rlp_buf);
    let msg = crypto.keccak256(&rlp_buf);

    let y_parity: u8 =
        TryInto::<u8>::try_into(auth_tuple.y_parity).map_err(|_| InternalError::TypeConversion)?;

    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&auth_tuple.r_signature.to_big_endian());
    sig[32..64].copy_from_slice(&auth_tuple.s_signature.to_big_endian());
    sig[64] = y_parity;

    match crypto.recover_signer(&sig, &msg) {
        Ok(address) => Ok(Some(address)),
        Err(_) => Ok(None),
    }
}

/// Gets code of an account, returning early if it's not a delegated account, otherwise
/// Returns tuple (is_delegated, eip7702_cost, code_address, code).
/// Notice that it also inserts the delegated account to the "accessed accounts" set.
///
/// Where:
/// - `is_delegated`: True if account is a delegated account.
/// - `eip7702_cost`: Cost of accessing the delegated account (if any)
/// - `code_address`: Code address (if delegated, returns the delegated address)
/// - `code`: Bytecode of the code_address, what the EVM will execute.
pub fn eip7702_get_code(
    db: &mut GeneralizedDatabase,
    accrued_substate: &mut Substate,
    address: Address,
    fork: Fork,
) -> Result<(bool, u64, Address, Code), VMError> {
    let (bytecode, delegation) = eip7702_peek_delegation(db, accrued_substate, address, fork)?;
    let Some((auth_address, access_cost)) = delegation else {
        return Ok((false, 0, address, bytecode));
    };

    accrued_substate.add_accessed_address(auth_address);
    let authorized_bytecode = db.get_account_code(auth_address)?.clone();

    Ok((true, access_cost, auth_address, authorized_bytecode))
}

/// First half of [`eip7702_get_code`]: read `address`'s code and detect a
/// delegation designation WITHOUT touching the delegate account.
///
/// Returns `address`'s code and, when delegated, the delegate address with
/// its warm/cold access cost (computed from the current substate, not
/// recorded). CALL-family opcodes use this to gas-check the delegation
/// access cost before reading the delegate (EELS order); reading it earlier
/// would leak the delegate account into execution witnesses on OOG.
pub fn eip7702_peek_delegation(
    db: &mut GeneralizedDatabase,
    substate: &Substate,
    address: Address,
    fork: Fork,
) -> Result<(Code, Option<(Address, u64)>), VMError> {
    let bytecode = db.get_account_code(address)?.clone();
    if !code_has_delegation(bytecode.code())? {
        return Ok((bytecode, None));
    }
    let auth_address = get_authorized_address_from_code(bytecode.code())?;
    let access_cost = if substate.is_address_accessed(&auth_address) {
        WARM_ADDRESS_ACCESS_COST
    } else {
        // EIP-8038 (glamsterdam-devnet-6): cold account access is repriced
        // 2600 -> 3000 at Amsterdam, so the 7702 delegate-access cost must be
        // fork-dependent rather than the flat COLD_ADDRESS_ACCESS_COST.
        cold_account_access_cost(fork)
    };
    Ok((bytecode, Some((auth_address, access_cost))))
}

/// Precomputed intrinsic-gas components for a transaction.
///
/// Computed once per tx in the prepare-execution hook and reused by
/// [`VM::validate_min_gas_limit`](crate::hooks::default_hook::validate_min_gas_limit)
/// and [`VM::add_intrinsic_gas`]. Previously the full calldata / access-list /
/// auth-list walk ran 2-3x per tx (once in each function, plus the pre-Amsterdam
/// floor's own `tx_calldata`).
#[derive(Clone, Copy, Debug)]
pub struct IntrinsicGas {
    /// Regular (EIP-8037) intrinsic-gas arm.
    pub regular: u64,
    /// State (EIP-8037, Amsterdam+) intrinsic-gas arm; always 0 pre-Amsterdam.
    pub state: u64,
    /// `gas_cost::tx_calldata` over `current_call_frame.calldata`. Reused by the
    /// pre-Amsterdam floor check (same byte string, same point in execution).
    pub calldata_cost: u64,
}

impl<'a> VM<'a> {
    /// Applies the EIP-7702 authorizations and charges their state-dependent costs at
    /// the top frame, mirroring EELS `set_delegation`
    /// (`amsterdam/vm/eoa_delegation.py::set_delegation`).
    ///
    /// Amsterdam+ (EIP-8037/8038): the per-auth intrinsic regular charge is only
    /// `REGULAR_PER_AUTH_BASE_COST`; the state-dependent charges are levied here, in the
    /// atomic prepare region (so an OOG rolls the whole region back and burns all gas
    /// rather than rejecting the tx). Per valid authorization, in EELS order:
    /// - `NEW_ACCOUNT` (state) when the authority's account leaf does not yet exist;
    /// - `ACCOUNT_WRITE` (regular) when this is the transaction's first write to
    ///   the authority's leaf (the sender's leaf was written at inclusion, and the
    ///   recipient's when `value > 0`, so those pay nothing here — a self-sponsored
    ///   authority and repeated authorizations on one authority pay `ACCOUNT_WRITE` at
    ///   most once);
    /// - `AUTH_BASE` (state) when a net-new delegation indicator is written (the
    ///   authority was not delegated before the tx and none was set for it earlier in
    ///   the tx). Charged at most once per authority and never credited back.
    ///
    /// On any `OutOfGas` from a charge, `fail_prepare_region` rolls back the region and
    /// this returns `Ok` (the full-gas revert is emitted by `run_execution`); it never
    /// propagates an `Err` (that would wrongly invalidate the block).
    ///
    /// Pre-Amsterdam keeps the legacy per-auth model: `PER_EMPTY_ACCOUNT_COST` was
    /// charged at intrinsic and `REFUND_AUTH_PER_EXISTING_ACCOUNT` is credited here for
    /// an authority that already exists in the trie.
    pub fn eip7702_set_access_code(&mut self) -> Result<(), VMError> {
        let amsterdam = self.env.config.fork >= Fork::Amsterdam;

        // Pre-Amsterdam existing-authority refund accumulator.
        let mut refunded_gas: u64 = 0;

        // EELS `delegated_before_tx`: whether each authority was already delegated at
        // tx start. The first time an authority is seen its code is still the pre-tx
        // code (auth processing runs before execution), so we cache it then.
        let mut delegated_before_tx: FxHashMap<Address, bool> = FxHashMap::default();

        // EELS `set_delegation` bookkeeping (Amsterdam+ only):
        // - `written_accounts`: leaves this tx has already written. The sender's leaf
        //   was written at inclusion (nonce bump + fee deduction); the recipient's when
        //   value is transferred. An authority already in this set pays no ACCOUNT_WRITE.
        // - `delegation_set_for`: authorities a delegation indicator was set for earlier
        //   in this tx (so AUTH_BASE is charged at most once per authority).
        let mut written_accounts: FxHashSet<Address> = FxHashSet::default();
        let mut delegation_set_for: FxHashSet<Address> = FxHashSet::default();
        if amsterdam {
            written_accounts.insert(self.env.origin);
            if !self.tx.value().is_zero() {
                written_accounts.insert(self.current_call_frame.to);
            }
        }

        // IMPORTANT:
        // If any of the below steps fail, immediately stop processing that tuple and continue to the next tuple in the list. It will in the case of multiple tuples for the same authority, set the code using the address in the last valid occurrence.
        // If transaction execution results in failure (any exceptional condition or code reverting), setting delegation designations is not rolled back (unless the atomic prepare region OOGs, which rolls back everything).
        for auth_tuple in self.tx.authorization_list().cloned().unwrap_or_default() {
            let chain_id_not_equals_this_chain_id = auth_tuple.chain_id != self.env.chain_id;
            let chain_id_not_zero = !auth_tuple.chain_id.is_zero();

            // 1. Verify the chain id is either 0 or the chain’s current ID.
            if chain_id_not_zero && chain_id_not_equals_this_chain_id {
                continue;
            }

            // 2. Verify the nonce is less than 2**64 - 1.
            // NOTE: nonce is a u64, it's always less than or equal to u64::MAX
            if auth_tuple.nonce == u64::MAX {
                continue;
            }

            // 3. authority = ecrecover(keccak(MAGIC || rlp([chain_id, address, nonce])), y_parity, r, s)
            //      s value must be less than or equal to secp256k1n/2, as specified in EIP-2.
            let Some(authority_address) = eip7702_recover_address(&auth_tuple, self.crypto)? else {
                continue;
            };

            // 4. Add authority to accessed_addresses (as defined in EIP-2929).
            let authority_account = self.db.get_account(authority_address)?;
            let authority_exists = authority_account.exists;
            let authority_info = authority_account.info.clone();
            let authority_code = self.db.get_code(authority_info.code_hash)?;
            self.substate.add_accessed_address(authority_address);

            // 5. Verify the code of authority is either empty or already delegated.
            // Check this BEFORE recording to BAL so we can release the borrow on authority_code.
            let authority_code_is_empty = authority_code.is_empty();
            let delegated_now = code_has_delegation(authority_code.code())?;
            let empty_or_delegated = authority_code_is_empty || delegated_now;
            // First sighting of an authority captures its pre-tx delegation state
            // (EELS `delegated_before_tx` from `get_pre_state_account`).
            let pre_delegated = *delegated_before_tx
                .entry(authority_address)
                .or_insert(delegated_now);

            // Record authority as touched for BAL per EIP-7928, even if validation fails later.
            // This ensures authority appears in BAL with empty change set when:
            // - Authority was loaded (above)
            // - But validation fails (checks below)
            if let Some(recorder) = self.db.bal_recorder.as_mut() {
                recorder.record_touched_address(authority_address);
            }

            if !empty_or_delegated {
                continue;
            }

            // 6. Verify the nonce of authority is equal to nonce. In case authority does not exist in the trie, verify that nonce is equal to 0.
            // If it doesn't exist, it means the nonce is zero. The get_account() function will return Account::default()
            // If it has nonce, the account.info.nonce should equal auth_tuple.nonce
            if authority_info.nonce != auth_tuple.nonce {
                continue;
            }

            if amsterdam {
                // EELS `set_delegation` charges, in order:
                // (a) NEW_ACCOUNT (state) when the authority leaf is absent. Uses `exists`
                //     (EELS `account_exists`), NOT `!is_empty()`; a repeated authority
                //     that a prior tuple already materialized reads `exists == true`.
                if !authority_exists && self.increase_state_gas(self.state_gas_new_account).is_err()
                {
                    self.fail_prepare_region();
                    return Ok(());
                }

                // (b) ACCOUNT_WRITE (regular) on the first write to the authority leaf.
                if !written_accounts.contains(&authority_address) {
                    if self
                        .current_call_frame
                        .increase_consumed_gas(ACCOUNT_WRITE_AMSTERDAM)
                        .is_err()
                    {
                        self.fail_prepare_region();
                        return Ok(());
                    }
                    written_accounts.insert(authority_address);
                }

                // (c) AUTH_BASE (state) when a net-new delegation indicator is written:
                //     setting a non-null delegation, the authority was not delegated
                //     before the tx, and none was set for it earlier this tx.
                if auth_tuple.address != Address::zero() {
                    if !pre_delegated
                        && !delegation_set_for.contains(&authority_address)
                        && self.increase_state_gas(self.state_gas_auth_base).is_err()
                    {
                        self.fail_prepare_region();
                        return Ok(());
                    }
                    delegation_set_for.insert(authority_address);
                }
            } else if authority_exists {
                // Pre-Amsterdam: existing authority refund (legacy model).
                refunded_gas = refunded_gas
                    .checked_add(REFUND_AUTH_PER_EXISTING_ACCOUNT)
                    .ok_or(InternalError::Overflow)?;
            }

            // 8. Set the code of authority to be 0xef0100 || address. This is a delegation designation.
            let delegation_bytes = [
                &SET_CODE_DELEGATION_BYTES[..],
                auth_tuple.address.as_bytes(),
            ]
            .concat();

            // As a special case, if address is 0x0000000000000000000000000000000000000000 do not write the designation.
            // Clear the account’s code and reset the account’s code hash to the empty hash.
            let code = if auth_tuple.address != Address::zero() {
                delegation_bytes.into()
            } else {
                Bytes::new()
            };
            self.update_account_bytecode(
                authority_address,
                Code::from_bytecode(code, self.crypto),
            )?;

            // 9. Increase the nonce of authority by one.
            self.increment_account_nonce(authority_address)
                .map_err(|_| TxValidationError::NonceIsMax)?;
        }

        // Pre-Amsterdam legacy refund channel (Amsterdam+ leaves `refunded_gas` at 0).
        if refunded_gas > 0 {
            self.substate.refunded_gas = self
                .substate
                .refunded_gas
                .checked_add(refunded_gas)
                .ok_or(InternalError::Overflow)?;
        }

        // EELS `auth_state_gas_used` lock-in (`interpreter.py`: after `set_delegation`,
        // `evm.auth_state_gas_used = frame_state_gas_used(evm)`,
        // `message.state_gas_reservoir = evm.state_gas_left`, `evm.state_gas_spilled = 0`).
        // Re-seed the frame's state-gas baseline past the committed auth state gas so a
        // later *execution* revert's `refill_frame_state_gas` cannot credit auth state
        // gas back, and zero the frame spill so the auth spill stays consumed. The
        // subsequent prepare-dispatch (create/value/delegation-resolve) charges sit above
        // this baseline and stay refillable on an execution revert. The prep-OOG path
        // instead refills to `prep_baseline_state_gas` (pre-region), so it fully rolls
        // auth back too. Skipped if the auth loop already OOG'd (early return above).
        if amsterdam {
            self.current_call_frame.state_gas_used_at_entry = self.state_gas_used;
            self.current_call_frame.frame_state_gas_spilled = 0;
        }

        Ok(())
    }

    pub fn add_intrinsic_gas(&mut self, intrinsic: &IntrinsicGas) -> Result<(), VMError> {
        // Intrinsic gas is the gas consumed by the transaction before the execution of the opcodes. Section 6.2 in the Yellow Paper.

        let regular_gas = intrinsic.regular;
        let state_gas = intrinsic.state;

        let total_gas = regular_gas.checked_add(state_gas).ok_or(OutOfGas)?;

        self.current_call_frame
            .increase_consumed_gas(total_gas)
            .map_err(|_| TxValidationError::IntrinsicGasTooLow)?;

        // state_gas_used is i64; intrinsic state gas is bounded by tx gas limit (< i64::MAX).
        self.state_gas_used = self
            .state_gas_used
            .checked_add(i64::try_from(state_gas).map_err(|_| InternalError::Overflow)?)
            .ok_or(InternalError::Overflow)?;
        // Remember the intrinsic split so we can leave it in state_gas_used on top-level
        // error (matches EELS `tx_env.intrinsic_state_gas`, which is kept separate from
        // `tx_output.state_gas_used` and never refunded).
        debug_assert_eq!(self.intrinsic_state_gas, 0, "intrinsic_state_gas set twice");
        self.intrinsic_state_gas = state_gas;

        // EIP-8037 (Amsterdam+): compute state gas reservoir from excess gas_limit.
        // execution_gas = what remains after all intrinsic gas; regular_gas_budget = how much
        // regular execution gas is allowed (capped at TX_MAX_GAS_LIMIT_AMSTERDAM); the difference becomes
        // the reservoir for drawing state gas without consuming regular gas_remaining.
        if self.env.config.fork >= Fork::Amsterdam {
            if self.env.is_system_call {
                // EIP-8037: system
                // transactions get a dedicated state-gas reservoir of
                // `state_gas_storage_set * SYSTEM_MAX_SSTORES_PER_CALL` ON TOP of
                // the full SYS_CALL_GAS_LIMIT regular budget — so SSTORE-heavy
                // system contracts (EIP-2935, EIP-4788) cannot OOG on state-gas
                // growth alone. Skip the regular reservoir computation so we don't
                // pre-consume `gas_remaining`; EELS sets `intrinsic_regular_gas=0`
                // and `gas=SYSTEM_TRANSACTION_GAS` for the message
                // (amsterdam/fork.py::process_unchecked_system_transaction).
                let sys_reservoir = self
                    .state_gas_storage_set
                    .saturating_mul(SYSTEM_MAX_SSTORES_PER_CALL);
                self.state_gas_reservoir = sys_reservoir;
                self.state_gas_reservoir_initial = sys_reservoir;
            } else {
                let gas_limit = self.tx.gas_limit();
                let execution_gas = gas_limit.saturating_sub(total_gas);
                let regular_gas_budget = TX_MAX_GAS_LIMIT_AMSTERDAM.saturating_sub(regular_gas);
                let gas_left = regular_gas_budget.min(execution_gas);
                let reservoir = execution_gas.saturating_sub(gas_left);
                if reservoir > 0 {
                    // Pre-consume reservoir from gas_remaining so GAS opcode returns <= TX_MAX_GAS_LIMIT_AMSTERDAM
                    let reservoir_i64 =
                        i64::try_from(reservoir).map_err(|_| InternalError::Overflow)?;
                    self.current_call_frame.gas_remaining = self
                        .current_call_frame
                        .gas_remaining
                        .checked_sub(reservoir_i64)
                        .ok_or(InternalError::Overflow)?;
                    self.state_gas_reservoir = reservoir;
                }
                // Capture initial reservoir for block-dimensional regular gas computation.
                self.state_gas_reservoir_initial = reservoir;
            }

            // EIP-8037: seed the top frame's state-gas entry baseline to the post-intrinsic
            // value of `state_gas_used` (the intrinsic state gas was already added above).
            // A top-level revert/halt refill (`refill_frame_state_gas`) then rolls back only
            // the execution portion and preserves the intrinsic state gas (which EELS keeps
            // separate as `tx_env.intrinsic_state_gas` and never refunds).
            self.current_call_frame.state_gas_used_at_entry = self.state_gas_used;
        }

        Ok(())
    }

    // ==================== Gas related functions =======================
    /// Returns `(regular_gas, state_gas)` intrinsic gas for the transaction.
    /// For Amsterdam+, state_gas is the EIP-8037 state portion.
    /// For pre-Amsterdam, state_gas is always 0.
    pub fn get_intrinsic_gas(&self) -> Result<IntrinsicGas, VMError> {
        // Intrinsic Gas = Calldata cost + Create cost + Base cost + Access list cost
        let mut regular_gas: u64 = 0;
        // Amsterdam+ intrinsic state gas is 0 (CREATE/value NEW_ACCOUNT and all EIP-7702
        // auth state charges are levied in the atomic prepare region). Pre-Amsterdam has
        // no state dimension. Kept as a named binding for the `IntrinsicGas` result.
        let state_gas: u64 = 0;
        let fork = self.env.config.fork;

        // Calldata Cost
        // 4 gas for each zero byte in the transaction data 16 gas for each non-zero byte in the transaction.
        let calldata_cost = gas_cost::tx_calldata(&self.current_call_frame.calldata)?;

        regular_gas = regular_gas.checked_add(calldata_cost).ok_or(OutOfGas)?;

        let is_create = self.is_create()?;

        if fork >= Fork::Amsterdam {
            // EIP-2780 (merged EIPs#11645): resource-based intrinsic gas.
            // The flat 21000 base is decomposed into a sender base + recipient
            // access charge + value-transfer charge. These tx-level sender/to
            // charges are ALWAYS the cold rate; access lists do NOT warm
            // tx-level accounts. Because the intrinsic uses fixed constants
            // (not substate warmth), the cold rate is applied automatically.
            let sender = self.env.origin;
            let to = self.tx.to();

            // Sender base: always TX_BASE_COST_AMSTERDAM (12000).
            regular_gas = regular_gas
                .checked_add(tx_base_cost(fork))
                .ok_or(OutOfGas)?;

            // tx.to + tx.value recipient charge (EELS `calculate_intrinsic_cost`
            // items 2-3), shared with `intrinsic_gas_dimensions` and the
            // calldata-floor anchor via `recipient_regular_gas`.
            regular_gas = regular_gas
                .checked_add(gas_cost::recipient_regular_gas(
                    &to,
                    self.tx.value(),
                    sender,
                    fork,
                ))
                .ok_or(OutOfGas)?;

            // Contract-creation: NEW_ACCOUNT state gas is charged in-region by
            // `prepare_execution` (EELS `prepare_dispatch` create branch), not
            // at intrinsic time. Amsterdam+ create intrinsic state is 0.
        } else {
            // Base Cost
            regular_gas = regular_gas.checked_add(TX_BASE_COST).ok_or(OutOfGas)?;

            // Create Cost
            if is_create {
                // https://eips.ethereum.org/EIPS/eip-2#specification
                regular_gas = regular_gas.checked_add(CREATE_BASE_COST).ok_or(OutOfGas)?;
            }
        }

        // EIP-3860 init code words (Shanghai+), unchanged by EIP-2780.
        if is_create && fork >= Fork::Shanghai {
            let number_of_words = &self.current_call_frame.calldata.len().div_ceil(WORD_SIZE);
            let double_number_of_words: u64 = number_of_words
                .checked_mul(2)
                .ok_or(OutOfGas)?
                .try_into()
                .map_err(|_| InternalError::TypeConversion)?;

            regular_gas = regular_gas
                .checked_add(double_number_of_words)
                .ok_or(OutOfGas)?;
        }

        // Access List Cost
        let mut access_lists_cost: u64 = 0;
        for (_, keys) in self.tx.access_list() {
            access_lists_cost = access_lists_cost
                .checked_add(gas_cost::access_list_address_cost(fork))
                .ok_or(OutOfGas)?;
            for _ in keys {
                access_lists_cost = access_lists_cost
                    .checked_add(gas_cost::access_list_storage_key_cost(fork))
                    .ok_or(OutOfGas)?;
            }
        }

        // EIP-7981 (Amsterdam+): access-list data bytes also contribute to the regular arm.
        // access_list_cost += floor_tokens_in_access_list * total_cost_floor_per_token
        // = access_list_bytes * STANDARD_TOKEN_COST * total_cost_floor_per_token
        // Effective: +1280 per address, +2048 per storage key.
        if fork >= Fork::Amsterdam {
            let al_floor_tokens = floor_tokens_in_access_list(self.tx.access_list());
            let al_data_cost = al_floor_tokens
                .checked_mul(total_cost_floor_per_token(fork))
                .ok_or(InternalError::Overflow)?;
            access_lists_cost = access_lists_cost
                .checked_add(al_data_cost)
                .ok_or(InternalError::Overflow)?;
        }

        regular_gas = regular_gas.checked_add(access_lists_cost).ok_or(OutOfGas)?;

        // Authorization List Cost
        // `unwrap_or_default` will return an empty vec when the `authorization_list` field is None.
        // If the vec is empty, the len will be 0, thus the authorization_list_cost is 0.
        let amount_of_auth_tuples: u64 = match self.tx.authorization_list() {
            None => 0,
            Some(list) => list
                .len()
                .try_into()
                .map_err(|_| InternalError::TypeConversion)?,
        };

        if fork >= Fork::Amsterdam {
            // EIP-8038 (EELS `calculate_intrinsic_cost`): the per-auth intrinsic regular
            // charge is only `REGULAR_PER_AUTH_BASE_COST` (`PER_AUTH_BASE_COST_AMSTERDAM`,
            // 7816). The ACCOUNT_WRITE (regular) and NEW_ACCOUNT / AUTH_BASE (state)
            // charges are state-dependent and levied in-region by
            // `eip7702_set_access_code` (EELS `set_delegation`), not at intrinsic time.
            // Amsterdam auth intrinsic state is 0.
            let regular_auth_cost = PER_AUTH_BASE_COST_AMSTERDAM
                .checked_mul(amount_of_auth_tuples)
                .ok_or(InternalError::Overflow)?;
            regular_gas = regular_gas.checked_add(regular_auth_cost).ok_or(OutOfGas)?;
        } else {
            let authorization_list_cost = PER_EMPTY_ACCOUNT_COST
                .checked_mul(amount_of_auth_tuples)
                .ok_or(InternalError::Overflow)?;
            regular_gas = regular_gas
                .checked_add(authorization_list_cost)
                .ok_or(OutOfGas)?;
        }

        Ok(IntrinsicGas {
            regular: regular_gas,
            state: state_gas,
            calldata_cost,
        })
    }

    /// Calculates the minimum gas to be consumed in the transaction.
    pub fn get_min_gas_used(&self) -> Result<u64, VMError> {
        let fork = self.env.config.fork;

        // If the transaction is a CREATE transaction, the calldata is emptied and the bytecode is assigned.
        let calldata = if self.is_create()? {
            self.current_call_frame.bytecode.code()
        } else {
            self.current_call_frame.calldata.as_ref()
        };

        // EIP-7976 floor tokens: for the floor arm, all calldata bytes count unweighted.
        // floor_tokens_in_calldata = (zero_bytes + nonzero_bytes) * STANDARD_TOKEN_COST
        // Pre-Amsterdam uses the weighted EIP-7623 formula: (nonzero * 16 + zero * 4) / 4
        let mut tokens_in_calldata: u64 = if fork >= Fork::Amsterdam {
            // EIP-7976: floor tokens = total_bytes * STANDARD_TOKEN_COST (unweighted).
            let total_bytes: u64 = calldata
                .len()
                .try_into()
                .map_err(|_| InternalError::TypeConversion)?;
            total_bytes
                .checked_mul(STANDARD_TOKEN_COST)
                .ok_or(InternalError::Overflow)?
        } else {
            // Pre-Amsterdam: weighted EIP-7623 token count.
            gas_cost::tx_calldata(calldata)? / STANDARD_TOKEN_COST
        };

        // EIP-7981 (Amsterdam+): access-list data bytes fold into the floor-token count.
        // floor_tokens_in_access_list = access_list_bytes * STANDARD_TOKEN_COST
        // where access_list_bytes = 20 * address_count + 32 * storage_key_count.
        if fork >= Fork::Amsterdam {
            let al_floor_tokens = floor_tokens_in_access_list(self.tx.access_list());
            tokens_in_calldata = tokens_in_calldata
                .checked_add(al_floor_tokens)
                .ok_or(InternalError::Overflow)?;
        }

        // EELS `data_floor_gas_cost = total_floor_tokens * TX_DATA_TOKEN_FLOOR + base_regular_gas`
        // where `base_regular_gas = TX_BASE + recipient_regular_gas`. Pre-Amsterdam the floor
        // base stays anchored on bare `tx_base_cost(fork)` (21000); Amsterdam+ (EIP-2780) folds
        // in the recipient/value regular-gas contribution via `recipient_regular_gas`.
        let mut min_gas_used: u64 = tokens_in_calldata
            .checked_mul(total_cost_floor_per_token(fork))
            .ok_or(InternalError::Overflow)?;

        let floor_base = if fork >= Fork::Amsterdam {
            tx_base_cost(fork)
                .checked_add(gas_cost::recipient_regular_gas(
                    &self.tx.to(),
                    self.tx.value(),
                    self.env.origin,
                    fork,
                ))
                .ok_or(InternalError::Overflow)?
        } else {
            tx_base_cost(fork)
        };

        min_gas_used = min_gas_used
            .checked_add(floor_base)
            .ok_or(InternalError::Overflow)?;

        Ok(min_gas_used)
    }

    /// Gets transaction callee, calculating create address if it's a "Create" transaction.
    /// Bool indicates whether it is a `create` transaction or not.
    pub fn get_tx_callee(
        tx: &Transaction,
        db: &mut GeneralizedDatabase,
        env: &Environment,
        substate: &mut Substate,
    ) -> Result<(Address, bool), VMError> {
        match tx.to() {
            TxKind::Call(address_to) => {
                substate.add_accessed_address(address_to);

                Ok((address_to, false))
            }

            TxKind::Create => {
                let sender_nonce = db.get_account(env.origin)?.info.nonce;

                let created_address = calculate_create_address(env.origin, sender_nonce);

                substate.add_accessed_address(created_address);
                substate.add_created_account(created_address);

                Ok((created_address, true))
            }
        }
    }
}

/// Compute `(regular, state)` intrinsic gas for a transaction without needing
/// a full VM instance. Mirrors `VM::get_intrinsic_gas` but operates on the raw
/// transaction and fork. Amsterdam+ intrinsic state gas is 0 — CREATE/value
/// `NEW_ACCOUNT` and all EIP-7702 auth state charges are levied in the atomic
/// prepare region, not at intrinsic time — so this returns `(regular, 0)` for
/// every fork.
///
/// Used by the block executor to perform the EIP-8037 (PR #2703) per-tx 2D
/// inclusion check before the tx runs.
///
/// `sender` is the transaction's recovered sender; it is required for the
/// EIP-2780 (Amsterdam+) self-transfer rule, which zeroes the recipient and
/// value charges when `sender == tx.to`. The parameter is taken
/// unconditionally so this function stays byte-identical with
/// `VM::get_intrinsic_gas` across every tx shape (guarded by
/// `test_intrinsic_parity_*`). A type-3/type-4 tx can never carry `to == sender`
/// in practice, but the parameter is still threaded through for parity.
pub fn intrinsic_gas_dimensions(
    tx: &Transaction,
    sender: Address,
    fork: Fork,
    _block_gas_limit: u64,
) -> Result<(u64, u64), VMError> {
    let mut regular_gas: u64 = 0;
    let state_gas: u64 = 0;

    // Calldata cost (EIP-2028 weighted)
    let calldata_cost = gas_cost::tx_calldata(tx.data())?;
    regular_gas = regular_gas.checked_add(calldata_cost).ok_or(OutOfGas)?;

    let to = tx.to();
    let is_create = matches!(to, TxKind::Create);

    if fork >= Fork::Amsterdam {
        // EIP-2780 (merged EIPs#11645): resource-based intrinsic gas.
        // Mirror of `VM::get_intrinsic_gas`. These tx-level sender/to charges
        // are ALWAYS the cold rate; access lists do NOT warm tx-level accounts.

        // Sender base: always TX_BASE_COST_AMSTERDAM (12000).
        regular_gas = regular_gas
            .checked_add(tx_base_cost(fork))
            .ok_or(OutOfGas)?;

        // tx.to + tx.value recipient charge (EELS `calculate_intrinsic_cost`
        // items 2-3), shared with `VM::get_intrinsic_gas` and the
        // calldata-floor anchor via `recipient_regular_gas`.
        regular_gas = regular_gas
            .checked_add(gas_cost::recipient_regular_gas(
                &to,
                tx.value(),
                sender,
                fork,
            ))
            .ok_or(OutOfGas)?;

        // Contract-creation: NEW_ACCOUNT state gas is charged in-region by
        // `prepare_execution` (EELS `prepare_dispatch` create branch), not
        // at intrinsic time. Amsterdam+ create intrinsic state is 0.
    } else {
        // Base cost
        regular_gas = regular_gas.checked_add(TX_BASE_COST).ok_or(OutOfGas)?;

        if is_create {
            regular_gas = regular_gas.checked_add(CREATE_BASE_COST).ok_or(OutOfGas)?;
        }
    }

    // EIP-3860 init code words (Shanghai+), unchanged by EIP-2780.
    if is_create && fork >= Fork::Shanghai {
        let words = tx.data().len().div_ceil(WORD_SIZE);
        let double_words: u64 = words
            .checked_mul(2)
            .ok_or(OutOfGas)?
            .try_into()
            .map_err(|_| InternalError::TypeConversion)?;
        regular_gas = regular_gas.checked_add(double_words).ok_or(OutOfGas)?;
    }

    // Access list cost
    let mut access_lists_cost: u64 = 0;
    for (_, keys) in tx.access_list() {
        access_lists_cost = access_lists_cost
            .checked_add(gas_cost::access_list_address_cost(fork))
            .ok_or(OutOfGas)?;
        for _ in keys {
            access_lists_cost = access_lists_cost
                .checked_add(gas_cost::access_list_storage_key_cost(fork))
                .ok_or(OutOfGas)?;
        }
    }

    // EIP-7981 (Amsterdam+): access-list data bytes fold into regular gas
    if fork >= Fork::Amsterdam {
        let al_floor_tokens = floor_tokens_in_access_list(tx.access_list());
        let al_data_cost = al_floor_tokens
            .checked_mul(total_cost_floor_per_token(fork))
            .ok_or(InternalError::Overflow)?;
        access_lists_cost = access_lists_cost
            .checked_add(al_data_cost)
            .ok_or(InternalError::Overflow)?;
    }
    regular_gas = regular_gas.checked_add(access_lists_cost).ok_or(OutOfGas)?;

    // Authorization list cost
    let amount_of_auth_tuples: u64 = match tx.authorization_list() {
        None => 0,
        Some(list) => list
            .len()
            .try_into()
            .map_err(|_| InternalError::TypeConversion)?,
    };

    if fork >= Fork::Amsterdam {
        // EIP-8038 (EELS `calculate_intrinsic_cost`): per-auth intrinsic regular is only
        // `REGULAR_PER_AUTH_BASE_COST` (`PER_AUTH_BASE_COST_AMSTERDAM`, 7816). The
        // ACCOUNT_WRITE / NEW_ACCOUNT / AUTH_BASE charges move to `set_delegation`
        // (in-region). Amsterdam auth intrinsic state is 0. Mirrors `VM::get_intrinsic_gas`.
        let regular_auth_cost = PER_AUTH_BASE_COST_AMSTERDAM
            .checked_mul(amount_of_auth_tuples)
            .ok_or(InternalError::Overflow)?;
        regular_gas = regular_gas.checked_add(regular_auth_cost).ok_or(OutOfGas)?;
    } else {
        let auth_cost = PER_EMPTY_ACCOUNT_COST
            .checked_mul(amount_of_auth_tuples)
            .ok_or(InternalError::Overflow)?;
        regular_gas = regular_gas.checked_add(auth_cost).ok_or(OutOfGas)?;
    }

    Ok((regular_gas, state_gas))
}

/// Standalone EIP-7623/7976/7981 floor gas for a transaction. Mirrors
/// [`VM::get_min_gas_used`] but operates on the raw transaction + fork, so it
/// can be called by mempool admission / the payload builder without needing a
/// VM instance. Returns `TX_BASE_COST + floor_rate * total_floor_tokens`.
///
/// Amsterdam+ uses the unweighted EIP-7976 floor (16 gas/token = 64 gas/byte)
/// and folds EIP-7981 access-list data bytes into the token count. Pre-
/// Amsterdam uses the weighted EIP-7623 formula.
///
/// `sender` is the transaction's recovered sender; it feeds the Amsterdam+
/// floor-base anchor (`tx_base_cost(fork) + recipient_regular_gas(...)`, see
/// EIP-2780), which needs the sender for the self-transfer zero-rule. Unused
/// pre-Amsterdam.
///
/// A mismatch between this and `VM::get_min_gas_used` would cause mempool
/// admission to drift from VM rejection; keep the two in sync. The
/// `test_intrinsic_parity_*` suite also guards this.
pub fn intrinsic_gas_floor(tx: &Transaction, sender: Address, fork: Fork) -> Result<u64, VMError> {
    // EIP-7976: floor tokens count ALL calldata bytes unweighted. For CREATE
    // txs the calldata is the init code. Mirrors `get_min_gas_used`.
    let calldata = tx.data();

    let mut tokens_in_calldata: u64 = if fork >= Fork::Amsterdam {
        let total_bytes: u64 = calldata
            .len()
            .try_into()
            .map_err(|_| InternalError::TypeConversion)?;
        total_bytes
            .checked_mul(STANDARD_TOKEN_COST)
            .ok_or(InternalError::Overflow)?
    } else {
        gas_cost::tx_calldata(calldata)? / STANDARD_TOKEN_COST
    };

    if fork >= Fork::Amsterdam {
        let al_floor_tokens = floor_tokens_in_access_list(tx.access_list());
        tokens_in_calldata = tokens_in_calldata
            .checked_add(al_floor_tokens)
            .ok_or(InternalError::Overflow)?;
    }

    // Floor base: Amsterdam+ anchors on `tx_base_cost(fork) + recipient_regular_gas(...)`
    // (EIP-2780); pre-Amsterdam stays anchored on bare `tx_base_cost(fork)` (21000).
    // Mirrors `get_min_gas_used`.
    let floor_base = if fork >= Fork::Amsterdam {
        tx_base_cost(fork)
            .checked_add(gas_cost::recipient_regular_gas(
                &tx.to(),
                tx.value(),
                sender,
                fork,
            ))
            .ok_or(InternalError::Overflow)?
    } else {
        tx_base_cost(fork)
    };

    tokens_in_calldata
        .checked_mul(total_cost_floor_per_token(fork))
        .ok_or(InternalError::Overflow)?
        .checked_add(floor_base)
        .ok_or(InternalError::Overflow.into())
}

/// Converts Account to LevmAccount
/// The problem with this is that we don't have the storage root.
pub fn account_to_levm_account(account: Account) -> (LevmAccount, Code) {
    (
        LevmAccount {
            info: account.info,
            has_storage: !account.storage.is_empty(), // This is used in scenarios in which the storage is already all in the account. For the Levm Runner
            storage: account.storage,
            status: AccountStatus::Unmodified,
            exists: true,
        },
        account.code,
    )
}

/// Converts a U256 value into usize, returning an error if the value is over 32 bits
/// This is generally used for memory offsets and sizes, 32 bits is more than enough for this purpose.
#[expect(clippy::as_conversions)]
pub fn u256_to_usize(val: U256) -> Result<usize, VMError> {
    // OR the three high limbs into one branch instead of a 4-way `||` chain,
    // then a single magnitude check — fewer branches on this hot conversion
    // (MLOAD/MSTORE/MCOPY/CALLDATACOPY/RETURN/... offsets all pass through here).
    if (val.0[1] | val.0[2] | val.0[3]) != 0 || val.0[0] > u32::MAX as u64 {
        return Err(VMError::ExceptionalHalt(ExceptionalHalt::VeryLargeNumber));
    }
    Ok(val.0[0] as usize)
}

/// Converts U256 size and offset to usize.
/// If the size is zero, the offset will be zero regardless of its original value as it is not relevant
pub fn size_offset_to_usize(size: U256, offset: U256) -> Result<(usize, usize), VMError> {
    if size.is_zero() {
        // Offset is irrelevant
        Ok((0, 0))
    } else {
        Ok((u256_to_usize(size)?, u256_to_usize(offset)?))
    }
}

// ==================== EIP-7708 Helper Functions ====================

/// Creates a Transfer log (LOG3) for an ETH transfer, emitted from
/// `log_address`: SYSTEM_ADDRESS for consensus EIP-7708 logs (Amsterdam+) or
/// TRACE_TRANSFER_ADDRESS for `eth_simulateV1` traceTransfers. Callers decide
/// via `VM::eth_transfer_log_address`.
#[inline]
pub fn create_eth_transfer_log(
    log_address: Address,
    from: Address,
    to: Address,
    value: U256,
) -> Log {
    let mut from_topic = [0u8; 32];
    from_topic[12..].copy_from_slice(from.as_bytes());

    let mut to_topic = [0u8; 32];
    to_topic[12..].copy_from_slice(to.as_bytes());

    let data = value.to_big_endian();

    Log {
        address: log_address,
        topics: vec![
            TRANSFER_EVENT_TOPIC,
            H256::from(from_topic),
            H256::from(to_topic),
        ],
        data: Bytes::from(data.to_vec()),
    }
}
