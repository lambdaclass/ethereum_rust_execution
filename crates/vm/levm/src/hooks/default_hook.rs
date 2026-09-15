use crate::{
    account::LevmAccount,
    constants::*,
    errors::{ContextResult, ExceptionalHalt, InternalError, TxValidationError, VMError},
    gas_cost::{
        STANDARD_TOKEN_COST, WARM_ADDRESS_ACCESS_COST, cold_account_access_cost,
        floor_tokens_in_access_list, recipient_regular_gas, total_cost_floor_per_token,
        tx_base_cost,
    },
    hooks::hook::Hook,
    utils::*,
    vm::VM,
};

use ethrex_common::{
    Address, H256, U256,
    constants::EMPTY_KECCAK_HASH,
    types::{Code, Fork},
};

pub const MAX_REFUND_QUOTIENT: u64 = 5;

pub struct DefaultHook;

impl Hook for DefaultHook {
    /// ## Description
    /// This method performs validations and returns an error if any of these fail.
    /// It also makes pre-execution changes:
    /// - It increases sender nonce
    /// - It substracts up-front-cost from sender balance.
    /// - It adds value to receiver balance.
    /// - It calculates and adds intrinsic gas to the 'gas used' of callframe and environment.
    ///   See 'docs' for more information about validations.
    fn prepare_execution(&mut self, vm: &mut VM<'_>) -> Result<(), VMError> {
        // System calls (EELS `process_unchecked_system_transaction`) have no
        // sender semantics: no validation, no nonce bump, no fee deduction.
        // EELS never reads the SYSTEM_ADDRESS account, so skip the whole
        // sender path to keep the read out of execution witnesses (EIP-8025).
        if vm.env.is_system_call {
            // EELS `process_unchecked_system_transaction` builds the message with
            // intrinsic_regular_gas=0 and intrinsic_state_gas=0: a system call gets
            // the full SYS_CALL_GAS_LIMIT with no intrinsic deducted. We still call
            // `add_intrinsic_gas` (with a zeroed intrinsic) so the Amsterdam state-gas
            // reservoir is set up, but charge no intrinsic — otherwise the frame
            // budget would fall below SYS_CALL_GAS_LIMIT and diverge from EELS (a
            // system contract engineered to consume exactly SYS_CALL_GAS_LIMIT+1
            // would then fail to run out of gas).
            let mut intrinsic = vm.get_intrinsic_gas()?;
            intrinsic.regular = 0;
            intrinsic.state = 0;
            vm.add_intrinsic_gas(&intrinsic)?;
            transfer_value(vm)?;
            set_bytecode_and_code_address(vm)?;
            return Ok(());
        }

        let sender_address = vm.env.origin;
        let sender_info = vm.db.get_account(sender_address)?.info.clone();

        // Compute intrinsic gas once and reuse it for both the min-gas-limit
        // validation and `add_intrinsic_gas` below (nothing in between mutates the
        // calldata / access-list / auth-list it depends on).
        let intrinsic = vm.get_intrinsic_gas()?;

        if vm.env.config.fork >= Fork::Prague {
            validate_min_gas_limit(vm, &intrinsic)?;
            // EIP-7825 (Osaka to pre-Amsterdam): reject tx if gas_limit > POST_OSAKA_GAS_LIMIT_CAP.
            // Amsterdam removes this restriction (EIP-8037 reservoir model).
            if !vm.env.disable_gas_allowance_check
                && vm.env.config.fork >= Fork::Osaka
                && vm.env.config.fork < Fork::Amsterdam
                && vm.tx.gas_limit() > POST_OSAKA_GAS_LIMIT_CAP
            {
                return Err(VMError::TxValidation(
                    TxValidationError::TxMaxGasLimitExceeded {
                        tx_hash: vm.tx.hash(vm.crypto),
                        tx_gas_limit: vm.tx.gas_limit(),
                    },
                ));
            }
        }

        // (1) GASLIMIT_PRICE_PRODUCT_OVERFLOW
        let gaslimit_price_product = vm
            .env
            .gas_price
            .checked_mul(vm.env.gas_limit.into())
            .ok_or(TxValidationError::GasLimitPriceProductOverflow)?;

        validate_sender_balance(vm, sender_info.balance)?;

        // (2) INSUFFICIENT_MAX_FEE_PER_BLOB_GAS
        if let Some(tx_max_fee_per_blob_gas) = vm.env.tx_max_fee_per_blob_gas {
            validate_max_fee_per_blob_gas(vm, tx_max_fee_per_blob_gas)?;
        }

        // (3) INSUFFICIENT_ACCOUNT_FUNDS
        deduct_caller(vm, gaslimit_price_product, sender_address)?;

        // (4) INSUFFICIENT_MAX_FEE_PER_GAS
        validate_sufficient_max_fee_per_gas(vm)?;

        // (5) INITCODE_SIZE_EXCEEDED
        if vm.is_create()? {
            validate_init_code_size(vm)?;
        }

        // (6) INTRINSIC_GAS_TOO_LOW
        vm.add_intrinsic_gas(&intrinsic)?;

        // (7) NONCE_IS_MAX
        vm.increment_account_nonce(sender_address)
            .map_err(|_| TxValidationError::NonceIsMax)?;

        // check for nonce mismatch
        if !vm.env.disable_nonce_check && sender_info.nonce != vm.env.tx_nonce {
            return Err(TxValidationError::NonceMismatch {
                expected: sender_info.nonce,
                actual: vm.env.tx_nonce,
            }
            .into());
        }

        // (8) PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS
        if let (Some(tx_max_priority_fee), Some(tx_max_fee_per_gas)) = (
            vm.env.tx_max_priority_fee_per_gas,
            vm.env.tx_max_fee_per_gas,
        ) && tx_max_priority_fee > tx_max_fee_per_gas
        {
            return Err(TxValidationError::PriorityGreaterThanMaxFeePerGas {
                priority_fee: tx_max_priority_fee,
                max_fee_per_gas: tx_max_fee_per_gas,
            }
            .into());
        }

        // (9) SENDER_NOT_EOA
        if !vm.env.disable_sender_eoa_check {
            let code = vm.db.get_code(sender_info.code_hash)?;
            validate_sender(sender_address, code.code())?;
        }

        // (10) GAS_ALLOWANCE_EXCEEDED
        validate_gas_allowance(vm)?;

        // Transaction is type 3 if tx_max_fee_per_blob_gas is Some
        if vm.env.tx_max_fee_per_blob_gas.is_some() {
            validate_4844_tx(vm)?;
        }

        // EIP-8037: enter the atomic prepare region (EELS `interpreter.py`'s depth-0
        // `try` around `set_delegation` + `prepare_dispatch`). Taken after the sender
        // nonce bump (7) and fee deduction (3) above so both survive a region
        // rollback, and before the type-4 auth handling below (the first region
        // charge). See `VM::enter_prepare_region` / `VM::fail_prepare_region`.
        vm.enter_prepare_region();

        // [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702
        // Transaction is type 4 if authorization_list is Some
        if vm.tx.authorization_list().is_some() {
            validate_type_4_tx(vm)?;
        }

        // EIP-8037 (atomic prepare region): EELS `prepare_dispatch` create/value
        // branch (interpreter.py:277-291). The CREATE / value-to-not-alive
        // `NEW_ACCOUNT` charge is evaluated IN-REGION via `increase_state_gas`: an
        // insufficient reservoir/gas rolls back the whole region
        // (`vm.fail_prepare_region()`) and burns all gas, rather than rejecting the
        // tx (which would wrongly invalidate the block). Applied AFTER EIP-7702
        // authorizations are set (so recipient emptiness / delegation reflect the
        // post-auth state) and BEFORE the value transfer.
        if vm.env.config.fork >= Fork::Amsterdam && !vm.pending_prep_oog {
            if vm.is_create()? {
                // EELS `prepare_dispatch`: `get_pre_state_account(message.current_target)
                // == EMPTY_ACCOUNT`. The created address cannot have been touched by
                // this tx's fee deduction / nonce bump (those only touch the sender),
                // and a create transaction can never carry an authorization list
                // (`validate_type_4_tx` rejects `to == None`), so the current DB read
                // already equals the pre-tx state for this address.
                let created_addr = vm.current_call_frame.to;
                // EIP-7928: record the created address in the BAL now that the prepare
                // region has read its pre-state (EELS `prepare_dispatch`
                // `get_pre_state_account(current_target)`), so a create that OOGs on the
                // in-region NEW_ACCOUNT charge still lists the address — the access record
                // survives the region rollback. Without this, a create that halts before
                // dispatch (which is where `handle_create_transaction` records the address)
                // would drop it and fork on the BAL hash.
                if let Some(recorder) = vm.db.bal_recorder.as_mut() {
                    recorder.record_touched_address(created_addr);
                }
                if vm.db.get_account(created_addr)?.is_empty() {
                    let charge = vm.state_gas_new_account;
                    if vm.increase_state_gas(charge).is_err() {
                        vm.fail_prepare_region();
                    }
                }
            } else {
                let to = vm.current_call_frame.to;
                let recipient = vm.db.get_account(to)?;
                let recipient_is_empty = recipient.is_empty();
                let recipient_code_hash = recipient.info.code_hash;
                // EIP-7928 (tests-glamsterdam-devnet@v7.1.0): record the recipient in the
                // BAL at its load point — mirroring EELS `prepare_dispatch`, which loads
                // the recipient (`get_account`) at the START of dispatch, BEFORE the
                // value NEW_ACCOUNT / delegation-access charges below. Recording here (not
                // after the region) means a subsequent in-region OOG on those charges
                // still lists the recipient (it was already loaded), while an earlier
                // EIP-7702 auth halt — which skips this whole block via the
                // `!vm.pending_prep_oog` guard above — correctly excludes it.
                if let Some(recorder) = vm.db.bal_recorder.as_mut() {
                    recorder.record_touched_address(to);
                }
                // Resolve a 7702-delegated recipient's target address (EELS
                // `prepare_dispatch`: `get_delegated_code_address(recipient_code)`),
                // evaluated post-auth so an auth on `tx.to` this tx is reflected.
                let recipient_delegated_target: Option<Address> =
                    if recipient_code_hash == *EMPTY_KECCAK_HASH {
                        None
                    } else {
                        let code = vm.db.get_code(recipient_code_hash)?.code_bytes();
                        if code_has_delegation(&code)? {
                            Some(get_authorized_address_from_code(&code)?)
                        } else {
                            None
                        }
                    };

                // If the recipient is EIP-161-empty and the tx transfers value, the
                // value transfer will materialize a new account: charge the
                // new-account state gas IN-REGION (EELS `prepare_dispatch` value
                // branch: `is_account_alive`). Skipped if a 7702 auth already
                // materialized the recipient this tx, since emptiness is evaluated
                // post-auth. EIP-2780 (EELS PR #3048): no precompile carve-out.
                // EIP-161/EIP-2780 define emptiness structurally, so an empty
                // (unfunded) precompile receiving value is created like any other
                // account and pays NEW_ACCOUNT. A pre-funded precompile is
                // non-empty, so `recipient_is_empty` is already false and it stays
                // exempt.
                if recipient_is_empty && !vm.tx.value().is_zero() {
                    let charge = vm.state_gas_new_account;
                    if vm.increase_state_gas(charge).is_err() {
                        vm.fail_prepare_region();
                    } else {
                        // Signal so a subsequent Amsterdam precompile-halt in
                        // `run_execution` rolls this charge back (the recipient
                        // never materializes on halt).
                        vm.value_new_account_charged = true;
                    }
                }

                // EIP-8037 (atomic prepare region): EELS `prepare_dispatch` delegation
                // branch. If the recipient is 7702-delegated, charge the account access
                // for resolving the delegation target IN-REGION via `increase_consumed_gas`
                // (regular gas): WARM if the target is already accessed, else COLD (and
                // mark it accessed). Charged AFTER the value NEW_ACCOUNT state charge, so
                // an OOG here rolls back the whole region (auth + value) and burns all gas
                // rather than rejecting the tx.
                if !vm.pending_prep_oog
                    && let Some(target) = recipient_delegated_target
                {
                    let is_warm = vm.substate.is_address_accessed(&target);
                    let charge = if is_warm {
                        WARM_ADDRESS_ACCESS_COST
                    } else {
                        cold_account_access_cost(vm.env.config.fork)
                    };
                    if vm.current_call_frame.increase_consumed_gas(charge).is_err() {
                        vm.fail_prepare_region();
                    } else if !is_warm {
                        vm.substate.add_accessed_address(target);
                    }
                }
            }
        }

        // EIP-8037: the atomic prepare region rolled back (one of its charges OOG'd)
        // and burned all gas; `run_execution` turns `pending_prep_oog` into a full-gas
        // revert `ContextResult` (not a tx-level `Err`, which would wrongly invalidate
        // the block). In that case the top-frame dispatch never happens, so its
        // recipient-touching steps (`transfer_value`, `set_bytecode_and_code_address`,
        // which read `tx.to` via `increase_account_balance` / `eip7702_get_code`) must
        // be skipped for EVERY tx kind, not just CREATE. EELS `prepare_dispatch` loads
        // the recipient only at dispatch, which a prepare-region halt precedes — so a
        // spurious recipient read here would be invisible under full-state execution but
        // break witness sufficiency under EIP-8025 stateless validation (the recipient's
        // trie node isn't in the witness). `undo_value_transfer` correspondingly skips
        // the recipient debit on this path (there was no transfer to reverse), so the
        // sender's upfront value debit is still returned with no recipient underflow.
        if vm.pending_prep_oog {
            return Ok(());
        }

        transfer_value(vm)?;

        set_bytecode_and_code_address(vm)?;

        Ok(())
    }

    /// ## Changes post execution
    /// 1. Undo value transfer if the transaction was reverted
    /// 2. Return unused gas + gas refunds to the sender.
    /// 3. Pay coinbase fee
    /// 4. Destruct addresses in selfdestruct set.
    fn finalize_execution(
        &mut self,
        vm: &mut VM<'_>,
        ctx_result: &mut ContextResult,
    ) -> Result<(), VMError> {
        // System calls (EELS `process_unchecked_system_transaction`) have no
        // sender or fee semantics: there is nothing to undo, refund, or pay
        // (the value and gas price are zero), so skip straight to the
        // self-destruct cleanup. Callers ignore the gas accounting fields for
        // system calls.
        if vm.env.is_system_call {
            delete_self_destruct_accounts(vm)?;
            return Ok(());
        }

        if !ctx_result.is_success() {
            undo_value_transfer(vm)?;
        }

        // EIP-8037 (Amsterdam+): CREATE-tx address collision.
        // Per EELS process_message_call (interpreter.py:120-145), `prepare_dispatch`
        // never runs for a colliding create (the collision check short-circuits before
        // `process_create_message`/`process_message`), so `state_gas_used=0` and the
        // reservoir is PRESERVED (not burned): `state_gas_left = message.state_gas_reservoir`.
        // tx_state_gas collapses to 0, tx_regular_gas = max(intrinsic_regular +
        // message.gas, calldata_floor). The user does NOT lose the whole gas_limit.
        //
        // ethrex's in-region CREATE NEW_ACCOUNT charge runs before the
        // collision check and is rolled back to the frame's entry baseline by
        // `handle_create_transaction` on collision (see that function), so
        // `state_gas_used` is already net zero here.
        if vm.env.config.fork >= Fork::Amsterdam && ctx_result.is_collision() {
            let gas_limit = vm.env.gas_limit;
            // state_gas_used is already net (signed, inline refunds applied); clamp at zero.
            let state_gas: u64 =
                u64::try_from(vm.state_gas_used.max(0)).map_err(|_| InternalError::Overflow)?;
            let floor = vm.get_min_gas_used()?;
            // Regular gas = gas_limit - state_gas_left, where state_gas_left =
            // reservoir (PRESERVED across collision in EELS, with new_account_refund
            // already folded in by vm.finalize_execution above). Mirrors EELS
            // tx_gas_used_before_refund = tx.gas - gas_left(=0) - state_gas_left.
            let regular_gas = gas_limit.saturating_sub(vm.state_gas_reservoir);
            let effective_regular = regular_gas.max(floor);
            ctx_result.gas_used = effective_regular
                .checked_add(state_gas)
                .ok_or(InternalError::Overflow)?;
            // User pays only the effective regular (post-floor); coinbase gets the
            // same; remainder returns to sender.
            ctx_result.gas_spent = effective_regular;
            pay_coinbase(vm, effective_regular)?;
            let gas_to_return = gas_limit
                .checked_sub(effective_regular)
                .ok_or(InternalError::Underflow)?;
            let wei_return_amount = vm
                .env
                .gas_price
                .checked_mul(U256::from(gas_to_return))
                .ok_or(InternalError::Overflow)?;
            vm.increase_account_balance(vm.env.origin, wei_return_amount)?;
            return Ok(());
        }

        // EIP-8037 (Amsterdam+): unused reservoir is always returned to sender.
        // Per EELS, state_gas_left is preserved even on exceptional halt — only
        // regular gas_left is burned.  The user does NOT pay for unspent reservoir.
        if vm.env.config.fork >= Fork::Amsterdam {
            ctx_result.gas_used = ctx_result.gas_used.saturating_sub(vm.state_gas_reservoir);
        }

        // Save pre-refund gas for EIP-7778 block accounting
        let gas_used_pre_refund = ctx_result.gas_used;

        // Note: compute_gas_refunded caps at gas_used / MAX_REFUND_QUOTIENT, where
        // gas_used already has the reservoir subtracted (line above). This matches
        // EELS, which applies the refund cap after reservoir removal but before the
        // regular/state gas split.
        let gas_refunded: u64 = compute_gas_refunded(vm, ctx_result)?;
        let gas_spent = compute_actual_gas_used(vm, gas_refunded, gas_used_pre_refund)?;

        refund_sender(vm, ctx_result, gas_refunded, gas_spent)?;

        pay_coinbase(vm, gas_spent)?;

        delete_self_destruct_accounts(vm)?;

        Ok(())
    }
}

pub fn undo_value_transfer(vm: &mut VM<'_>) -> Result<(), VMError> {
    // In a create if Tx was reverted the account won't even exist by this point.
    // On a prepare-region OOG (`pending_prep_oog`) `prepare_execution` skipped
    // `transfer_value`, so the recipient was never credited (nor loaded) — debiting
    // it here would both underflow and spuriously read `tx.to` out of the witness.
    // The sender is still re-credited its upfront value debit below.
    if !vm.is_create()? && !vm.pending_prep_oog {
        vm.decrease_account_balance(vm.current_call_frame.to, vm.current_call_frame.msg_value)?;
    }

    vm.increase_account_balance(vm.env.origin, vm.current_call_frame.msg_value)?;

    Ok(())
}

/// Refunds unused gas to the sender. The user pays `gas_spent` (post-refund);
/// for Amsterdam+, block-level accounting is recomputed dimensionally from VM
/// fields, not from a pre-refund total.
pub fn refund_sender(
    vm: &mut VM<'_>,
    ctx_result: &mut ContextResult,
    refunded_gas: u64,
    gas_spent: u64,
) -> Result<(), VMError> {
    vm.substate.refunded_gas = refunded_gas;

    // EIP-7778: Separate block vs user gas accounting for Amsterdam+
    // Block header gas_used = max(regular_dimension, state_dimension) per EIP-7778.
    // Receipt cumulative_gas_used = post-refund total (what user pays).
    if vm.env.config.fork >= Fork::Amsterdam {
        // EIP-8037: state_gas_used is already net (signed, credits applied inline);
        // clamp at zero. There is no separate tx-level refund channel — EELS
        // `process_transaction` sets `tx_state_gas = intrinsic_state_gas + state_gas_used`
        // directly.
        let state_gas: u64 =
            u64::try_from(vm.state_gas_used.max(0)).map_err(|_| InternalError::Overflow)?;
        // Compute raw consumption from scratch (gas_limit minus gas_remaining)
        // to avoid interference from any reservoir-current subtraction baked
        // into the caller's pre-refund number.
        #[expect(clippy::as_conversions, reason = "gas_remaining is >= 0 here")]
        let gas_remaining = vm.current_call_frame.gas_remaining.max(0) as u64;
        let raw_consumed = vm.env.gas_limit.saturating_sub(gas_remaining);
        // Subtract intrinsic_state (pre-consumed from gas_remaining as part of total intrinsic),
        // the initial reservoir (pre-consumed from gas_remaining), and state-gas spills
        // (EELS charge_state_gas spills don't count as regular_gas_used).
        let regular_gas = raw_consumed
            .saturating_sub(vm.intrinsic_state_gas)
            .saturating_sub(vm.state_gas_reservoir_initial)
            .saturating_sub(vm.state_gas_spill);
        // EIP-8037 (glamsterdam-devnet-7 v7.2.0, EIPs#11908): the calldata floor
        // binds the block-level regular gas dimension. Each tx contributes
        // `max(pre_refund_gas - state_gas, calldata_floor)` to block gas, so
        // state-gas spending cannot discount the floor. `regular_gas` here is
        // `pre_refund_gas - state_gas`; flooring it matches EELS `tx_regular_gas`.
        // The refund still applies only to the user payment (`gas_spent`), not
        // block gas_used.
        let floor = vm.get_min_gas_used()?;
        ctx_result.gas_used = regular_gas
            .max(floor)
            .checked_add(state_gas)
            .ok_or(InternalError::Overflow)?;
        // User pays post-refund gas (with floor)
        ctx_result.gas_spent = gas_spent;
    } else {
        // Pre-Amsterdam: both use post-refund value
        ctx_result.gas_used = gas_spent;
        ctx_result.gas_spent = gas_spent;
    }

    // Return unspent gas to the sender (based on what user pays)
    let gas_to_return = vm
        .env
        .gas_limit
        .checked_sub(gas_spent)
        .ok_or(InternalError::Underflow)?;

    let wei_return_amount = vm
        .env
        .gas_price
        .checked_mul(U256::from(gas_to_return))
        .ok_or(InternalError::Overflow)?;

    vm.increase_account_balance(vm.env.origin, wei_return_amount)?;

    Ok(())
}

// [EIP-3529](https://eips.ethereum.org/EIPS/eip-3529)
pub fn compute_gas_refunded(vm: &VM<'_>, ctx_result: &ContextResult) -> Result<u64, VMError> {
    Ok(vm
        .substate
        .refunded_gas
        .min(ctx_result.gas_used / MAX_REFUND_QUOTIENT))
}

// Calculate actual gas used in the whole transaction. Since Prague there is a base minimum to be consumed.
pub fn compute_actual_gas_used(
    vm: &mut VM<'_>,
    refunded_gas: u64,
    gas_used_without_refunds: u64,
) -> Result<u64, VMError> {
    let exec_gas_consumed = gas_used_without_refunds
        .checked_sub(refunded_gas)
        .ok_or(InternalError::Underflow)?;

    if vm.env.config.fork >= Fork::Prague {
        Ok(exec_gas_consumed.max(vm.get_min_gas_used()?))
    } else {
        Ok(exec_gas_consumed)
    }
}

pub fn pay_coinbase(vm: &mut VM<'_>, gas_to_pay: u64) -> Result<(), VMError> {
    let priority_fee_per_gas = vm
        .env
        .gas_price
        .checked_sub(vm.env.base_fee_per_gas)
        .ok_or(InternalError::Underflow)?;

    let coinbase_fee = U256::from(gas_to_pay)
        .checked_mul(priority_fee_per_gas)
        .ok_or(InternalError::Overflow)?;

    // Per EIP-7928: Coinbase must appear in BAL when there's a user transaction,
    // even if the priority fee is zero. System contract calls have gas_price = 0,
    // so we use this to distinguish them from user transactions.
    if !vm.env.gas_price.is_zero()
        && let Some(recorder) = vm.db.bal_recorder.as_mut()
    {
        recorder.record_touched_address(vm.env.coinbase);
    }

    // Only pay coinbase if there's actually a fee to pay.
    if !coinbase_fee.is_zero() {
        vm.increase_account_balance(vm.env.coinbase, coinbase_fee)?;
    } else if !vm.env.is_system_call {
        // The spec reads the coinbase account unconditionally during user-tx
        // fee transfer (EELS `process_transaction` calls `get_account` before
        // deciding whether to credit), but system contract calls never touch
        // the coinbase. Keep the read observable for zero-fee user txs
        // (including gas-price-zero txs on zero-base-fee chains) so execution
        // witnesses (EIP-8025) record the coinbase trie path, including its
        // exclusion proof when it doesn't exist.
        vm.db.get_account(vm.env.coinbase)?;
    }

    Ok(())
}

// In Cancun the only addresses destroyed are contracts created in this transaction
pub fn delete_self_destruct_accounts(vm: &mut VM<'_>) -> Result<(), VMError> {
    // EIP-8246 (Amsterdam+): SELFDESTRUCT no longer burns ETH.
    // Accounts in the selfdestruct set have nonce reset to 0, code cleared, and storage cleared,
    // but balance is preserved. If the resulting balance is zero, EIP-161 removes the account.
    //
    // Pre-Amsterdam (EIP-6780 / Cancun): accounts are fully wiped (LevmAccount::default()).
    //
    // Note: the pre-Amsterdam Amsterdam+ burn-log loop has been removed because under EIP-8246
    // no ETH is ever burned by SELFDESTRUCT, so no Burn log is emitted at finalization.

    let addresses: Vec<Address> = vm.substate.iter_selfdestruct().copied().collect();

    for address in &addresses {
        // Backup must be taken before mark_modified flips `exists` to true.
        let account_snapshot = vm.db.get_account(*address)?;
        vm.current_call_frame
            .call_frame_backup
            .backup_account_info(*address, account_snapshot)?;

        if vm.env.config.fork >= Fork::Amsterdam {
            // EIP-8246: preserve balance; clear nonce, code, and storage.
            let account = vm.db.get_account_mut(*address)?;
            let preserved_balance = account.info.balance;
            account.info.nonce = 0;
            account.info.code_hash = *EMPTY_KECCAK_HASH;
            account.storage.clear();
            account.has_storage = false;
            account.info.balance = preserved_balance;
            // Reach DestroyedModified so get_state_transitions emits removed_storage=true
            // and correctly computes acc_info_updated (nonce/code_hash changed).
            account.mark_destroyed();
            account.mark_modified();
        } else {
            let account = vm.db.get_account_mut(*address)?;
            *account = LevmAccount::default();
            account.mark_destroyed();
        }

        // EIP-7928: Clean up BAL for selfdestructed account. Under EIP-8246 (Amsterdam+)
        // the balance is preserved (no burn), so the BAL keeps its balance changes; pre-
        // Amsterdam the account is wiped and its balance collapses to 0.
        let preserve_balance = vm.env.config.fork >= Fork::Amsterdam;
        if let Some(recorder) = vm.db.bal_recorder.as_mut() {
            recorder.track_selfdestruct(*address, preserve_balance);
        }
    }

    Ok(())
}

pub fn validate_min_gas_limit(vm: &mut VM<'_>, intrinsic: &IntrinsicGas) -> Result<(), VMError> {
    // check for gas limit is grater or equal than the minimum required
    let regular_gas = intrinsic.regular;
    let state_gas = intrinsic.state;
    let intrinsic_gas: u64 = regular_gas
        .checked_add(state_gas)
        .ok_or(ExceptionalHalt::OutOfGas)?;

    if vm.current_call_frame.gas_limit < intrinsic_gas {
        return Err(TxValidationError::IntrinsicGasTooLow.into());
    }

    let fork = vm.env.config.fork;

    // EIP-7976 floor tokens: for the floor arm, all calldata bytes count unweighted.
    // floor_tokens_in_calldata = (zero_bytes + nonzero_bytes) * STANDARD_TOKEN_COST
    // Pre-Amsterdam uses the weighted EIP-7623 formula: (nonzero * 16 + zero * 4) / 4
    let mut tokens_in_calldata: u64 = if fork >= Fork::Amsterdam {
        // EIP-7976: floor tokens = total_bytes * STANDARD_TOKEN_COST (unweighted).
        let total_bytes: u64 = vm
            .current_call_frame
            .calldata
            .len()
            .try_into()
            .map_err(|_| InternalError::TypeConversion)?;
        total_bytes
            .checked_mul(STANDARD_TOKEN_COST)
            .ok_or(InternalError::Overflow)?
    } else {
        // Pre-Amsterdam: weighted EIP-7623 token count. Reuse the calldata cost already
        // computed in `intrinsic` (same byte string) instead of re-walking the calldata.
        intrinsic.calldata_cost / STANDARD_TOKEN_COST
    };

    // EIP-7981 (Amsterdam+): access-list data bytes fold into the floor-token count.
    // floor_tokens_in_access_list = access_list_bytes * STANDARD_TOKEN_COST
    // where access_list_bytes = 20 * address_count + 32 * storage_key_count.
    if fork >= Fork::Amsterdam {
        let al_floor_tokens = floor_tokens_in_access_list(vm.tx.access_list());
        tokens_in_calldata = tokens_in_calldata
            .checked_add(al_floor_tokens)
            .ok_or(InternalError::Overflow)?;
    }

    // floor_cost_by_tokens = base_regular_gas + total_cost_floor_per_token(fork) * tokens
    // EIP-7976 (Amsterdam+) raises the floor multiplier from 10 to 16.
    // The floor base is `tx_base_cost(fork)`: 21000 pre-Amsterdam, unchanged.
    // Amsterdam+ (EIP-2780) anchors on `tx_base_cost(fork) + recipient_regular_gas(...)`
    // (12000 base + the recipient/value regular-gas contribution), mirroring EELS
    // `data_floor_gas_cost = total_floor_tokens * TX_DATA_TOKEN_FLOOR + base_regular_gas`.
    let floor_base = if fork >= Fork::Amsterdam {
        tx_base_cost(fork)
            .checked_add(recipient_regular_gas(
                &vm.tx.to(),
                vm.tx.value(),
                vm.env.origin,
                fork,
            ))
            .ok_or(InternalError::Overflow)?
    } else {
        tx_base_cost(fork)
    };

    let floor_cost_by_tokens = tokens_in_calldata
        .checked_mul(total_cost_floor_per_token(fork))
        .ok_or(InternalError::Overflow)?
        .checked_add(floor_base)
        .ok_or(InternalError::Overflow)?;

    // EIP-8037 (Amsterdam+): Regular gas is capped at TX_MAX_GAS_LIMIT — reject if
    // intrinsic regular gas or calldata floor exceeds the cap (no amount of gas_limit
    // can make the TX valid since excess gas_limit becomes state gas reservoir).
    // Must be checked before the floor check so the correct error is returned.
    // NOTE: We use IntrinsicGasTooLow (not TxMaxGasLimitExceeded) intentionally —
    // this matches the EELS exception mapping for this specific case.
    if vm.env.config.fork >= Fork::Amsterdam
        && regular_gas.max(floor_cost_by_tokens) > TX_MAX_GAS_LIMIT_AMSTERDAM
    {
        return Err(TxValidationError::IntrinsicGasTooLow.into());
    }

    if vm.current_call_frame.gas_limit < floor_cost_by_tokens {
        return Err(TxValidationError::IntrinsicGasBelowFloorGasCost.into());
    }

    Ok(())
}

pub fn validate_max_fee_per_blob_gas(
    vm: &mut VM<'_>,
    tx_max_fee_per_blob_gas: U256,
) -> Result<(), VMError> {
    let base_fee_per_blob_gas = vm.env.base_blob_fee_per_gas;
    if tx_max_fee_per_blob_gas < base_fee_per_blob_gas {
        return Err(TxValidationError::InsufficientMaxFeePerBlobGas {
            base_fee_per_blob_gas,
            tx_max_fee_per_blob_gas,
        }
        .into());
    }

    Ok(())
}

pub fn validate_init_code_size(vm: &mut VM<'_>) -> Result<(), VMError> {
    // [EIP-3860] - INITCODE_SIZE_EXCEEDED
    // [EIP-7954] - Amsterdam increases the limit
    let code_size = vm.current_call_frame.calldata.len();
    let max_size = if vm.env.config.fork >= Fork::Amsterdam {
        AMSTERDAM_INIT_CODE_MAX_SIZE
    } else {
        INIT_CODE_MAX_SIZE
    };
    if code_size > max_size && vm.env.config.fork >= Fork::Shanghai {
        return Err(TxValidationError::InitcodeSizeExceeded {
            max_size,
            actual_size: code_size,
        }
        .into());
    }
    Ok(())
}

pub fn validate_sufficient_max_fee_per_gas(vm: &mut VM<'_>) -> Result<(), TxValidationError> {
    if vm.env.tx_max_fee_per_gas.unwrap_or(vm.env.gas_price) < vm.env.base_fee_per_gas {
        return Err(TxValidationError::InsufficientMaxFeePerGas);
    }
    Ok(())
}

pub fn validate_4844_tx(vm: &mut VM<'_>) -> Result<(), VMError> {
    // (11) TYPE_3_TX_PRE_FORK
    if vm.env.config.fork < Fork::Cancun {
        return Err(TxValidationError::Type3TxPreFork.into());
    }

    let blob_hashes = &vm.env.tx_blob_hashes;

    // (12) TYPE_3_TX_ZERO_BLOBS
    if blob_hashes.is_empty() {
        return Err(TxValidationError::Type3TxZeroBlobs.into());
    }

    // (13) TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH
    for blob_hash in blob_hashes {
        let blob_hash = blob_hash.as_bytes();
        if blob_hash
            .first()
            .is_some_and(|first_byte| !VALID_BLOB_PREFIXES.contains(first_byte))
        {
            return Err(TxValidationError::Type3TxInvalidBlobVersionedHash.into());
        }
    }

    // (14) TYPE_3_TX_BLOB_COUNT_EXCEEDED
    let max_blob_count = vm
        .env
        .config
        .blob_schedule
        .max
        .try_into()
        .map_err(|_| InternalError::TypeConversion)?;
    let blob_count = blob_hashes.len();
    if blob_count > max_blob_count {
        return Err(TxValidationError::Type3TxBlobCountExceeded {
            max_blob_count,
            actual_blob_count: blob_count,
        }
        .into());
    }
    if vm.env.config.fork >= Fork::Osaka && blob_count > MAX_BLOB_COUNT_TX {
        return Err(TxValidationError::Type3TxBlobCountExceeded {
            max_blob_count: MAX_BLOB_COUNT_TX,
            actual_blob_count: blob_count,
        }
        .into());
    }

    // (15) TYPE_3_TX_CONTRACT_CREATION
    // NOTE: This will never happen, since the EIP-4844 tx (type 3) does not have a TxKind field
    // only supports an Address which must be non-empty.
    // If a type 3 tx has the field `to` as null (signaling create), it will raise an exception on RLP decoding,
    // it won't reach this point.
    // For more information, please check the following thread:
    // - https://github.com/lambdaclass/ethrex/pull/2425/files/819825516dc633275df56b2886b921061c4d7681#r2035611105
    if vm.is_create()? {
        return Err(TxValidationError::Type3TxContractCreation.into());
    }

    Ok(())
}

pub fn validate_type_4_tx(vm: &mut VM<'_>) -> Result<(), VMError> {
    let Some(auth_list) = vm.tx.authorization_list() else {
        // vm.authorization_list should be Some at this point.
        return Err(InternalError::Custom("Auth list not found".to_string()).into());
    };

    // (16) TYPE_4_TX_PRE_FORK
    if vm.env.config.fork < Fork::Prague {
        return Err(TxValidationError::Type4TxPreFork.into());
    }

    // (17) TYPE_4_TX_CONTRACT_CREATION
    // From the EIP docs: a null destination is not valid.
    // NOTE: This will never happen, since the EIP-7702 tx (type 4) does not have a TxKind field
    // only supports an Address which must be non-empty.
    // If a type 4 tx has the field `to` as null (signaling create), it will raise an exception on RLP decoding,
    // it won't reach this point.
    // For more information, please check the following thread:
    // - https://github.com/lambdaclass/ethrex/pull/2425/files/819825516dc633275df56b2886b921061c4d7681#r2035611105
    if vm.is_create()? {
        return Err(TxValidationError::Type4TxContractCreation.into());
    }

    // (18) TYPE_4_TX_LIST_EMPTY
    // From the EIP docs: The transaction is considered invalid if the length of authorization_list is zero.
    if auth_list.is_empty() {
        return Err(TxValidationError::Type4TxAuthorizationListIsEmpty.into());
    }

    vm.eip7702_set_access_code()
}

pub fn validate_sender(sender_address: Address, code: &[u8]) -> Result<(), VMError> {
    if !code.is_empty() && !code_has_delegation(code)? {
        return Err(TxValidationError::SenderNotEOA(sender_address).into());
    }
    Ok(())
}

pub fn validate_gas_allowance(vm: &mut VM<'_>) -> Result<(), TxValidationError> {
    // System contract calls (EIP-2935, EIP-4788, EIP-7002, EIP-7251) bypass the
    // block-level gas-allowance check — their 30M gas budget is a protocol rule
    // independent of `block_gas_limit`.
    if vm.env.is_system_call || vm.env.disable_gas_allowance_check {
        return Ok(());
    }
    if vm.env.gas_limit > vm.env.block_gas_limit {
        return Err(TxValidationError::GasAllowanceExceeded {
            block_gas_limit: vm.env.block_gas_limit,
            tx_gas_limit: vm.env.gas_limit,
        });
    }
    Ok(())
}

pub fn validate_sender_balance(vm: &mut VM<'_>, sender_balance: U256) -> Result<(), VMError> {
    if vm.env.disable_balance_check {
        return Ok(());
    }

    // Up front cost is the maximum amount of wei that a user is willing to pay for. Gaslimit * gasprice + value + blob_gas_cost
    let value = vm.current_call_frame.msg_value;

    // blob gas cost = max fee per blob gas * blob gas used
    // https://eips.ethereum.org/EIPS/eip-4844
    let max_blob_gas_cost =
        get_max_blob_gas_price(&vm.env.tx_blob_hashes, vm.env.tx_max_fee_per_blob_gas)?;

    // For the transaction to be valid the sender account has to have a balance >= gas_price * gas_limit + value if tx is type 0 and 1
    // balance >= max_fee_per_gas * gas_limit + value + blob_gas_cost if tx is type 2 or 3
    let gas_fee_for_valid_tx = vm
        .env
        .tx_max_fee_per_gas
        .unwrap_or(vm.env.gas_price)
        .checked_mul(vm.env.gas_limit.into())
        .ok_or(TxValidationError::GasLimitPriceProductOverflow)?;

    let balance_for_valid_tx = gas_fee_for_valid_tx
        .checked_add(value)
        .ok_or(TxValidationError::InsufficientAccountFunds)?
        .checked_add(max_blob_gas_cost)
        .ok_or(TxValidationError::InsufficientAccountFunds)?;

    if sender_balance < balance_for_valid_tx {
        return Err(TxValidationError::InsufficientAccountFunds.into());
    }

    Ok(())
}

pub fn deduct_caller(
    vm: &mut VM<'_>,
    gas_limit_price_product: U256,
    sender_address: Address,
) -> Result<(), VMError> {
    if vm.env.disable_balance_check {
        return Ok(());
    }

    // Up front cost is the maximum amount of wei that a user is willing to pay for. Gaslimit * gasprice + value + blob_gas_cost
    let value = vm.current_call_frame.msg_value;

    let blob_gas_cost =
        calculate_blob_gas_cost(&vm.env.tx_blob_hashes, vm.env.base_blob_fee_per_gas)?;

    // The real cost to deduct is calculated as effective_gas_price * gas_limit + value + blob_gas_cost
    let up_front_cost = gas_limit_price_product
        .checked_add(value)
        .ok_or(TxValidationError::InsufficientAccountFunds)?
        .checked_add(blob_gas_cost)
        .ok_or(TxValidationError::InsufficientAccountFunds)?;
    // There is no error specified for overflow in up_front_cost
    // in ef_tests. We went for "InsufficientAccountFunds" simply
    // because if the upfront cost is bigger than U256, then,
    // technically, the sender will not be able to pay it.

    vm.decrease_account_balance(sender_address, up_front_cost)
        .map_err(|_| TxValidationError::InsufficientAccountFunds)?;

    Ok(())
}

/// Transfer msg_value to transaction recipient
pub fn transfer_value(vm: &mut VM<'_>) -> Result<(), VMError> {
    if !vm.is_create()? {
        let value = vm.current_call_frame.msg_value;
        let to = vm.current_call_frame.to;

        vm.increase_account_balance(to, value)?;

        // EIP-7708 / traceTransfers: emit transfer log for nonzero-value transactions.
        // Self-transfers (origin == to) do NOT emit consensus logs per the EIP spec;
        // trace mode includes them (see `eth_transfer_log_address`).
        let from = vm.env.origin;
        if let Some(log_address) = vm.eth_transfer_log_address(from, to, value) {
            let log = create_eth_transfer_log(log_address, from, to, value);
            vm.substate.add_log(log);
        }
    }
    Ok(())
}

/// Sets bytecode and code_address to CallFrame
pub fn set_bytecode_and_code_address(vm: &mut VM<'_>) -> Result<(), VMError> {
    // Get bytecode and code_address for assigning those values to the callframe.
    let (bytecode, code_address) = if vm.is_create()? {
        // Here bytecode is the calldata and the code_address is just the created contract address.
        let calldata = std::mem::take(&mut vm.current_call_frame.calldata);
        (
            // SAFETY: we don't need the hash for the initcode
            Code::from_bytecode_unchecked(calldata, H256::zero()),
            vm.current_call_frame.to,
        )
    } else {
        // Here bytecode and code_address could be either from the account or from the delegated account.
        let to = vm.current_call_frame.to;

        // Record tx.to as touched in BAL (the target of message call transaction).
        // EIP-7928 (tests-glamsterdam-devnet@v7.1.0): skipped when the atomic prepare
        // region rolled back (`pending_prep_oog`). EELS v7.1.0 stopped loading the
        // recipient at inclusion (`prepare_message`) and now loads it only in the
        // top-frame `prepare_dispatch`, which an EIP-7702 auth halt precedes — so a
        // tx that OOGs during authorization processing must not touch the recipient.
        if !vm.pending_prep_oog
            && let Some(recorder) = vm.db.bal_recorder.as_mut()
        {
            recorder.record_touched_address(to);
        }

        let (is_delegation, _eip7702_gas_consumed, code_address, bytecode) =
            eip7702_get_code(vm.db, &mut vm.substate, to, vm.env.config.fork)?;

        // If EIP-7702 delegation, also record the delegation target (code source) in BAL.
        // Skipped when the atomic prepare region rolled back (`pending_prep_oog`): EELS
        // `prepare_dispatch` resolves and reads the delegated address (`get_account`,
        // which feeds `account_reads`) only AFTER its warm/cold access charge succeeds.
        // When that charge OOGs — or an earlier in-region charge (auth / value
        // NEW_ACCOUNT) OOGs before the delegation is reached — EELS never records the
        // target, so neither may ethrex, or the BAL would carry a spurious touch.
        if is_delegation
            && !vm.pending_prep_oog
            && let Some(recorder) = vm.db.bal_recorder.as_mut()
        {
            recorder.record_touched_address(code_address);
        }

        (bytecode, code_address)
    };

    // Assign code and code_address to callframe
    vm.current_call_frame.code_address = code_address;
    vm.current_call_frame.set_code(bytecode)?;

    Ok(())
}
