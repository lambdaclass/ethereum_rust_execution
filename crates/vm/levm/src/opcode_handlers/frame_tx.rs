//! # EIP-8141 Frame Transaction opcodes
//!
//! Includes:
//!   - `APPROVE` (0xAA)
//!   - `TXPARAM` (0xB0)
//!   - `FRAMEDATALOAD` (0xB1)
//!   - `FRAMEDATACOPY` (0xB2)
//!   - `FRAMEPARAM` (0xB3)
//!   - `SIGPARAM` (0xB4)
//!   - `SIGDATACOPY` (0xB5)
//!   - Default code for EOAs: `VERIFY` has the signature-check behavior;
//!     `SENDER` and `DEFAULT` return successfully as if calling empty code
//!     (EIP-8141 §"Default code").

use crate::{
    errors::{ExceptionalHalt, InternalError, OpcodeResult, VMError},
    gas_cost,
    memory::calculate_memory_size,
    opcode_handlers::OpcodeHandler,
    utils::size_offset_to_usize,
    vm::VM,
};
use ethrex_common::{Address, U256, types::FrameMode, types::Log};

/// Convert a u64 index to usize, returning InvalidOpcode on overflow.
fn index_to_usize(val: u64) -> Result<usize, VMError> {
    usize::try_from(val).map_err(|_| ExceptionalHalt::InvalidOpcode.into())
}

/// Convert a U256 offset to usize, returning None when the value does not fit
/// in usize on the current target. Used by FRAMEDATALOAD and FRAMEDATACOPY so
/// out-of-range offsets are treated as past-the-end rather than as an
/// exceptional halt (per the EIP-8141 spec the load returns zero and the copy
/// writes zero bytes).
pub fn u256_to_offset(value: U256) -> Option<usize> {
    if value.0[1] != 0 || value.0[2] != 0 || value.0[3] != 0 {
        return None;
    }
    usize::try_from(value.0[0]).ok()
}

/// Compute the transaction's MAXIMUM cost (EIP-8141 §Gas Accounting: APPROVE must
/// "collect the transaction's maximum cost from payer"):
/// `max_cost = max_fee_per_gas * max_gas
///           + len(blob_hashes) * 131072 * blob_base_fee`.
/// This is the single definition of "maximum cost": APPROVE (scopes 0x1/0x3)
/// debits it from the payer, TXPARAM(0x06) reports it, and the
/// mempool paymaster reservation reserves it. The end-of-tx refund returns
/// `max_cost - effective_gas_price * total_gas_used - base-rate blob burn`, so
/// the payer nets the effective-rate cost of the gas actually used plus the
/// EIP-4844 blob burn (intrinsic gas is inside `total_gas_used`, so it stays
/// non-refundable).
pub(crate) fn compute_tx_max_cost(ctx: &crate::vm::FrameTxContext) -> Result<U256, VMError> {
    let gas_cost = ctx
        .tx
        .max_fee_per_gas
        .checked_mul(U256::from(ctx.max_gas))
        .ok_or(ExceptionalHalt::InvalidOpcode)?;
    let blob_cost = U256::from(ctx.tx.blob_versioned_hashes.len())
        .checked_mul(U256::from(131072u64))
        .ok_or(ExceptionalHalt::InvalidOpcode)?
        .checked_mul(ctx.blob_base_fee)
        .ok_or(ExceptionalHalt::InvalidOpcode)?;
    gas_cost
        .checked_add(blob_cost)
        .ok_or(ExceptionalHalt::InvalidOpcode.into())
}

/// Apply APPROVE side effects for the given scope.
/// This is shared between OpApproveHandler and (future) default code.
pub fn apply_approve(
    vm: &mut VM<'_>,
    scope: u64,
    frame_target: ethrex_common::Address,
) -> Result<(), VMError> {
    match scope {
        0x1 => {
            // APPROVE_PAYMENT: increment nonce, deduct max cost, record payer.
            // Per spec, the single transaction-scoped variable `payer` is
            // set on success; `payer.is_some()` is the source of truth for
            // "payment has been approved".
            let ctx = vm
                .frame_tx_context
                .as_ref()
                .ok_or(ExceptionalHalt::InvalidOpcode)?;
            if ctx.payer_address.is_some() {
                return Err(VMError::RevertOpcode);
            }
            // EIP-8141: payment approval must not precede the sender's execution
            // approval. Per the spec's APPROVE_PAYMENT rules, revert the frame
            // while sender_approved == false (the sender authorizes execution
            // first; only then may a payer be bound and the max cost collected).
            if !ctx.sender_approved {
                return Err(VMError::RevertOpcode);
            }
            let tx_cost = compute_tx_max_cost(ctx)?;
            let sender = ctx.tx.sender;

            // The payer must be able to cover the transaction's maximum cost.
            // Checked before any write: a refusal reverts the requesting call
            // frame and must leave nothing behind.
            if vm.db.get_account(frame_target)?.info.balance < tx_cost {
                return Err(VMError::RevertOpcode);
            }
            charge_approve_sender_creation(vm, sender)?;
            vm.increment_account_nonce(sender)?;
            // Payer balance underflow is a frame-level revert, not a consensus
            // fault: the outer restore_cache_state() path rolls back the nonce
            // increment above when RevertOpcode propagates.
            match vm.decrease_account_balance(frame_target, tx_cost) {
                Ok(()) => {}
                Err(InternalError::Underflow) => return Err(VMError::RevertOpcode),
                Err(e) => return Err(VMError::Internal(e)),
            }

            let ctx = vm
                .frame_tx_context
                .as_mut()
                .ok_or(ExceptionalHalt::InvalidOpcode)?;
            ctx.payer_address = Some(frame_target);
        }
        0x2 => {
            // APPROVE_EXECUTION: set sender_approved (requires frame_target == tx.sender)
            let ctx = vm
                .frame_tx_context
                .as_ref()
                .ok_or(ExceptionalHalt::InvalidOpcode)?;
            if ctx.sender_approved {
                return Err(VMError::RevertOpcode);
            }
            if frame_target != ctx.tx.sender {
                return Err(VMError::RevertOpcode);
            }
            let ctx = vm
                .frame_tx_context
                .as_mut()
                .ok_or(ExceptionalHalt::InvalidOpcode)?;
            ctx.sender_approved = true;
        }
        0x3 => {
            // APPROVE_EXECUTION_AND_PAYMENT: both, in one atomic step.
            let ctx = vm
                .frame_tx_context
                .as_ref()
                .ok_or(ExceptionalHalt::InvalidOpcode)?;
            if ctx.sender_approved || ctx.payer_address.is_some() {
                return Err(VMError::RevertOpcode);
            }
            if frame_target != ctx.tx.sender {
                return Err(VMError::RevertOpcode);
            }
            let tx_cost = compute_tx_max_cost(ctx)?;
            let sender = ctx.tx.sender;

            if vm.db.get_account(frame_target)?.info.balance < tx_cost {
                return Err(VMError::RevertOpcode);
            }
            charge_approve_sender_creation(vm, sender)?;
            vm.increment_account_nonce(sender)?;
            // See scope 0x1 above for the Underflow → RevertOpcode rationale.
            match vm.decrease_account_balance(frame_target, tx_cost) {
                Ok(()) => {}
                Err(InternalError::Underflow) => return Err(VMError::RevertOpcode),
                Err(e) => return Err(VMError::Internal(e)),
            }

            let ctx = vm
                .frame_tx_context
                .as_mut()
                .ok_or(ExceptionalHalt::InvalidOpcode)?;
            ctx.sender_approved = true;
            ctx.payer_address = Some(frame_target);
        }
        _ => {
            // A scope of zero, or one carrying bits beyond the approval mask,
            // grants nothing and reverts the requesting call frame.
            return Err(VMError::RevertOpcode);
        }
    }
    Ok(())
}

/// EIP-8141: incrementing the sender's nonce at `APPROVE` can create the sender
/// account, and the creation is charged from the executing frame's state gas pool
/// immediately before the increment. A pool that cannot cover the charge halts the
/// current call frame exceptionally -- the halt's rollback discards every approval
/// effect, including an execution approval this same call already recorded.
fn charge_approve_sender_creation(
    vm: &mut VM<'_>,
    sender: ethrex_common::Address,
) -> Result<(), VMError> {
    if vm.env.config.fork >= ethrex_common::types::Fork::Amsterdam
        && vm.db.get_account(sender)?.is_empty()
    {
        vm.increase_state_gas(vm.state_gas_new_account)?;
    }
    Ok(())
}

/// APPROVE (0xAA) -- Frame transaction approval opcode.
///
/// Pops [offset, length, scope] from the stack.
/// - scope 0x1 (APPROVE_PAYMENT): increment nonce, deduct tx cost, record payer
/// - scope 0x2 (APPROVE_EXECUTION): set sender_approved (requires resolved_target == tx.sender)
/// - scope 0x3 (APPROVE_EXECUTION_AND_PAYMENT): both, in one atomic step
///
/// A refused approval -- an `ADDRESS` other than the frame's resolved target, a
/// scope outside the frame's allowed flags, or a failed precondition -- reverts
/// the CURRENT CALL FRAME, not the whole frame: a caller that handles the revert
/// carries on. Only the memory expansion is charged before the refusal, following
/// `RETURN` semantics for the designated return-data region.
///
/// The approval's writes deliberately bypass the `VERIFY` static restriction: only
/// `APPROVE` may mutate state there.
///
/// On success, copies memory[offset..offset+length] to output and halts the frame.
pub struct OpApproveHandler;
impl OpcodeHandler for OpApproveHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, length, scope] = *vm.current_call_frame.stack.pop()?;
        let (length, offset) = size_offset_to_usize(length, offset)?;

        // Charge the memory expansion first, as `RETURN` does: the caller pays for
        // the region it designated whether or not the approval is granted.
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::exit_opcode(
                calculate_memory_size(offset, length)?,
                vm.current_call_frame.memory.len(),
            )?)?;

        // Must be in a frame transaction context
        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        // The executing contract must be the frame's target
        let current_frame = ctx
            .tx
            .frames
            .get(ctx.current_frame_index)
            .ok_or(ExceptionalHalt::InvalidOpcode)?;
        let frame_target = current_frame.target.unwrap_or(ctx.tx.sender);
        if vm.current_call_frame.to != frame_target {
            return Err(VMError::RevertOpcode);
        }

        // The requested scope must be a non-zero subset of the frame's allowed
        // scope (flags bits 0-1). An allowed scope of zero grants nothing, so no
        // approval can be granted in the frame at all. Every refusal reverts the
        // requesting call frame.
        let allowed_scope = current_frame.scope_restriction();
        let scope_val = u64::try_from(scope).unwrap_or(u64::MAX);
        if scope_val == 0 || scope_val > 3 || (scope_val & u64::from(allowed_scope)) != scope_val {
            return Err(VMError::RevertOpcode);
        }

        apply_approve(vm, scope_val, frame_target)?;

        let ctx = vm
            .frame_tx_context
            .as_mut()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;
        ctx.approve_called_in_current_frame = true;

        // Copy memory to output (like RETURN)
        if length != 0 {
            vm.current_call_frame.output =
                vm.current_call_frame.memory.load_range(offset, length)?;
        }

        Ok(OpcodeResult::Halt)
    }
}

/// TXPARAM (0xB0) -- Load a transaction parameter as a 32-byte word.
/// Gas cost: 2
pub struct OpTxParamHandler;
impl OpcodeHandler for OpTxParamHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [param_id] = *vm.current_call_frame.stack.pop()?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::TXPARAM)?;

        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        let param_id = u64::try_from(param_id).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        // The executing frame's state gas pool lives on the VM, not the context, so
        // 0x0C is read here and handed to `load_tx_param`.
        let state_gas_left = vm.frame_state_gas_pool.unwrap_or(0);
        let result = load_tx_param(ctx, param_id, state_gas_left)?;
        vm.current_call_frame.stack.push(result)?;

        Ok(OpcodeResult::Continue)
    }
}

/// FRAMEDATALOAD (0xB1) -- Load one 32-byte word from a frame's data.
/// Stack: [offset, frameIndex] with offset on top (popped first); frameIndex is
/// the deeper operand. Gas cost: 3.
pub struct OpFrameDataLoadHandler;
impl OpcodeHandler for OpFrameDataLoadHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, frame_index] = *vm.current_call_frame.stack.pop()?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::FRAMEDATALOAD)?;

        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        let frame_index = u64::try_from(frame_index).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let idx = index_to_usize(frame_index)?;
        let frame = ctx
            .tx
            .frames
            .get(idx)
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        // Out-of-usize offsets are past-the-end: the word stays zero-filled.
        let mut word = [0u8; 32];
        if let Some(byte_offset) = u256_to_offset(offset) {
            let data = &frame.data;
            let available = data.len().saturating_sub(byte_offset);
            let copy_len = available.min(32);
            if copy_len > 0
                && let Some(src) = data.get(byte_offset..byte_offset.saturating_add(copy_len))
            {
                // copy_len <= 32 == word.len(), so this slice is in bounds.
                if let Some(dst) = word.get_mut(..copy_len) {
                    dst.copy_from_slice(src);
                }
            }
        }

        vm.current_call_frame
            .stack
            .push(U256::from_big_endian(&word))?;

        Ok(OpcodeResult::Continue)
    }
}

/// FRAMEDATACOPY (0xB2) -- Copy frame data into memory.
/// Takes [memOffset, dataOffset, length, frameIndex] from the stack.
/// Gas cost matches CALLDATACOPY.
pub struct OpFrameDataCopyHandler;
impl OpcodeHandler for OpFrameDataCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [mem_offset, data_offset, length, frame_index] = *vm.current_call_frame.stack.pop()?;
        let (length, mem_offset) = size_offset_to_usize(length, mem_offset)?;
        // Out-of-usize data_offset is past-the-end: destination stays zero-filled.
        let data_offset_opt = u256_to_offset(data_offset);

        let new_memory_size = calculate_memory_size(mem_offset, length)?;
        let current_memory_size = vm.current_call_frame.memory.len();
        // Charging memory-expansion gas before the frame-context guard below is
        // intentional: the caller pays for the memory growth it requested even
        // when the opcode then halts for running outside a frame tx.
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::framedatacopy(
                new_memory_size,
                current_memory_size,
                length,
            )?)?;

        // Frame-context and frame_index checks precede the zero-length early
        // return: an out-of-bounds frameIndex halts exceptionally even when
        // length == 0 (EIP-8141 §FRAMEDATACOPY, consensus parity with FRAMEDATALOAD).
        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        let frame_index = u64::try_from(frame_index).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let idx = index_to_usize(frame_index)?;
        let frame = ctx
            .tx
            .frames
            .get(idx)
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        if length == 0 {
            return Ok(OpcodeResult::Continue);
        }

        let data = &frame.data;
        let mut buf = vec![0u8; length];
        if let Some(data_offset) = data_offset_opt {
            let available = data.len().saturating_sub(data_offset);
            let copy_len = length.min(available);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(..copy_len),
                data.get(data_offset..data_offset.saturating_add(copy_len)),
            ) {
                dst.copy_from_slice(src);
            }
        }

        vm.current_call_frame.memory.store_data(mem_offset, &buf)?;

        Ok(OpcodeResult::Continue)
    }
}

/// FRAMEPARAM (0xB3) -- Load a frame parameter as a 32-byte word.
/// Stack: [param, frameIndex] with frameIndex on top (matches SIGPARAM). Gas cost: 2.
pub struct OpFrameParamHandler;
impl OpcodeHandler for OpFrameParamHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [frame_index, param_id] = *vm.current_call_frame.stack.pop()?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::FRAMEPARAM)?;

        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        let frame_index = u64::try_from(frame_index).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let idx = index_to_usize(frame_index)?;
        let frame = ctx
            .tx
            .frames
            .get(idx)
            .ok_or(ExceptionalHalt::InvalidOpcode)?;

        let param_id = u64::try_from(param_id).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let result: U256 = match param_id {
            0x00 => {
                // target
                address_to_u256(frame.target.unwrap_or(ctx.tx.sender))
            }
            0x01 => {
                // execution gas limit
                U256::from(frame.gas_limits.execution)
            }
            0x02 => {
                // mode
                U256::from(frame.mode)
            }
            0x03 => {
                // flags
                U256::from(frame.flags)
            }
            0x04 => {
                // len(data)
                U256::from(frame.data.len())
            }
            0x05 => {
                // status -- exceptional halt if current/future frame.
                // Returns the EIP-8141 status code: 0 = failure, 1 = success,
                // 2 = skipped (atomic-batch failure).
                if idx >= ctx.current_frame_index {
                    return Err(ExceptionalHalt::InvalidOpcode.into());
                }
                let (status, _, _) = ctx
                    .frame_results
                    .get(idx)
                    .ok_or(ExceptionalHalt::InvalidOpcode)?;
                U256::from(*status)
            }
            0x06 => {
                // allowed_scope (flags & 0x03)
                U256::from(frame.scope_restriction())
            }
            0x07 => {
                // atomic_batch ((flags >> 2) & 1, returns 0 or 1)
                U256::from(u8::from(frame.is_atomic_batch()))
            }
            0x08 => {
                // value -- EIP-8141 FRAMEPARAM table
                frame.value
            }
            0x09 => {
                // state gas limit -- the second dimension of the frame's budget
                U256::from(frame.gas_limits.state)
            }
            0x0A | 0x0B => {
                // Gas usage per dimension, read from the frame's receipt: 0x0A the
                // execution gas its meter consumed, 0x0B the state gas attributed to
                // it. A receipt exists only once the frame has completed, so
                // requesting either for the current or a subsequent frame halts
                // exceptionally. The values are live, not final -- a completed frame's
                // state gas usage decreases when a later frame refills a state charge
                // attributed to it, and is restored when that refill rolls back.
                if idx >= ctx.current_frame_index {
                    return Err(ExceptionalHalt::InvalidOpcode.into());
                }
                let (_, gas_used, _) = ctx
                    .frame_results
                    .get(idx)
                    .ok_or(ExceptionalHalt::InvalidOpcode)?;
                if param_id == 0x0A {
                    U256::from(gas_used.execution)
                } else {
                    U256::from(gas_used.state)
                }
            }
            _ => return Err(ExceptionalHalt::InvalidOpcode.into()),
        };

        vm.current_call_frame.stack.push(result)?;

        Ok(OpcodeResult::Continue)
    }
}

/// SIGPARAM (0xB4) -- signature-scoped metadata (EIP-8141).
///
/// Stack `[param, signatureIndex]` with `signatureIndex` on top; gas 2; returns
/// one word (0x00 resolved signer, 0x01 scheme, 0x02 msg, 0x03 len(signature)).
/// Static arity: the parameter range is 0x00-0x03 and the operand count never
/// varies with it. Copying an `ARBITRARY` entry's raw bytes is `SIGDATACOPY`'s job.
///
/// Each scheme family withholds the metadata the protocol does not define for it:
/// the resolved signer is available only for protocol-validated entries, to which
/// the protocol assigns one, and the signature byte length only for `ARBITRARY`
/// entries -- the raw signature bytes of a protocol-validated scheme, their length
/// included, are not introspectable.
pub struct OpSigParamHandler;
impl OpcodeHandler for OpSigParamHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [signature_index, param] = *vm.current_call_frame.stack.pop()?;
        let param = u64::try_from(param).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let signature_index =
            u64::try_from(signature_index).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let idx = index_to_usize(signature_index)?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::SIGPARAM)?;
        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;
        let sig = ctx
            .tx
            .signatures
            .get(idx)
            .ok_or(ExceptionalHalt::InvalidOpcode)?;
        let is_arbitrary = sig.scheme == ethrex_common::types::FRAME_SIG_SCHEME_ARBITRARY;
        let result = match param {
            // Resolved signer: an absent signer resolves to tx.sender. EIP-8141
            // assigns no resolved signer to ARBITRARY entries, so asking for one
            // is an exceptional halt.
            0x00 => {
                if is_arbitrary {
                    return Err(ExceptionalHalt::InvalidOpcode.into());
                }
                address_to_u256(sig.signer.unwrap_or(ctx.tx.sender))
            }
            0x01 => U256::from(sig.scheme),
            0x02 => {
                // msg: 0 when empty (canonical sig_hash case), else the 32-byte digest.
                if sig.msg.is_empty() {
                    U256::zero()
                } else {
                    U256::from_big_endian(&sig.msg)
                }
            }
            0x03 => {
                // The signature byte length is defined only for ARBITRARY entries:
                // a protocol-validated scheme's bytes are not introspectable, and
                // neither is their length.
                if !is_arbitrary {
                    return Err(ExceptionalHalt::InvalidOpcode.into());
                }
                U256::from(sig.signature.len())
            }
            _ => return Err(ExceptionalHalt::InvalidOpcode.into()),
        };
        vm.current_call_frame.stack.push(result)?;
        Ok(OpcodeResult::Continue)
    }
}

/// SIGDATACOPY (0xB5) -- copy a portion of the chosen signature entry's raw
/// signature bytes to memory (EIP-8141).
///
/// Stack `[signatureIndex, length, dataOffset, memOffset]` with `memOffset` on top
/// (popped first), matching `CALLDATACOPY`'s operand order. The copy is defined
/// only for `ARBITRARY` entries, whose bytes the protocol does not validate; the
/// raw signature bytes of a protocol-validated scheme are intentionally not
/// accessible. Semantics and gas match `CALLDATACOPY`: bytes past the end of the
/// signature read as zero and the memory is expanded as needed.
pub struct OpSigDataCopyHandler;
impl OpcodeHandler for OpSigDataCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [mem_offset, data_offset, length, signature_index] =
            *vm.current_call_frame.stack.pop()?;
        let signature_index =
            u64::try_from(signature_index).map_err(|_| ExceptionalHalt::InvalidOpcode)?;
        let idx = index_to_usize(signature_index)?;
        let (length, mem_offset) = size_offset_to_usize(length, mem_offset)?;
        let data_offset_opt = u256_to_offset(data_offset);

        let new_memory_size = calculate_memory_size(mem_offset, length)?;
        let current_memory_size = vm.current_call_frame.memory.len();
        // Charge the copy and memory-expansion gas before the context/scheme
        // guards: the caller pays for the growth it requested even if the opcode
        // halts.
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::framedatacopy(
                new_memory_size,
                current_memory_size,
                length,
            )?)?;

        let ctx = vm
            .frame_tx_context
            .as_ref()
            .ok_or(ExceptionalHalt::InvalidOpcode)?;
        let sig = ctx
            .tx
            .signatures
            .get(idx)
            .ok_or(ExceptionalHalt::InvalidOpcode)?;
        if sig.scheme != ethrex_common::types::FRAME_SIG_SCHEME_ARBITRARY {
            return Err(ExceptionalHalt::InvalidOpcode.into());
        }
        if length == 0 {
            return Ok(OpcodeResult::Continue);
        }
        let data = &sig.signature;
        let mut buf = vec![0u8; length];
        if let Some(data_offset) = data_offset_opt {
            let available = data.len().saturating_sub(data_offset);
            let copy_len = length.min(available);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(..copy_len),
                data.get(data_offset..data_offset.saturating_add(copy_len)),
            ) {
                dst.copy_from_slice(src);
            }
        }
        vm.current_call_frame.memory.store_data(mem_offset, &buf)?;
        Ok(OpcodeResult::Continue)
    }
}

// -- Helper functions --

pub fn load_tx_param(
    ctx: &crate::vm::FrameTxContext,
    param_id: u64,
    state_gas_left: u64,
) -> Result<U256, VMError> {
    match param_id {
        0x00 => Ok(U256::from(0x06u8)), // tx_type (EIP-8141 = type 6)
        0x01 => Ok(U256::from(ctx.tx.nonce)),
        0x02 => Ok(address_to_u256(ctx.tx.sender)),
        0x03 => Ok(ctx.tx.max_priority_fee_per_gas),
        0x04 => Ok(ctx.tx.max_fee_per_gas),
        0x05 => Ok(ctx.tx.max_fee_per_blob_gas),
        0x06 => compute_tx_max_cost(ctx),
        0x07 => Ok(U256::from(ctx.tx.blob_versioned_hashes.len())),
        0x08 => {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(ctx.sig_hash.as_bytes());
            Ok(U256::from_big_endian(&bytes))
        }
        0x09 => Ok(U256::from(ctx.tx.frames.len())),
        0x0A => Ok(U256::from(ctx.current_frame_index)),
        0x0B => Ok(U256::from(ctx.tx.signatures.len())),
        // State gas remaining in the executing frame's pool. Every call depth
        // within a frame draws from the same pool, so this is frame-scoped, not
        // call-scoped.
        0x0C => Ok(U256::from(state_gas_left)),
        _ => Err(ExceptionalHalt::InvalidOpcode.into()),
    }
}

pub fn address_to_u256(addr: ethrex_common::Address) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(addr.as_bytes());
    U256::from_big_endian(&bytes)
}

// -- Default code for EOAs (EIP-8141) --

/// Execute default code for an EOA target in a frame transaction.
///
/// When a frame targets an address with no deployed code (an EOA), the protocol
/// runs built-in "default code" instead of executing a normal CALL. `VERIFY`
/// runs the signature-check logic; `SENDER` and `DEFAULT` return successfully
/// as if calling empty code (EIP-8141 §"Default code").
///
/// Returns `(success, gas_used, logs)`.
pub fn execute_default_code(
    vm: &mut VM<'_>,
    frame: &ethrex_common::types::Frame,
    target: Address,
) -> Result<(bool, u64, Vec<Log>), VMError> {
    match frame.execution_mode() {
        FrameMode::Verify => execute_default_verify(vm, frame, target),
        // EIP-8141 §"Default code": a SENDER or DEFAULT frame whose target has no code "returns
        // successfully as if calling empty code" — this is what makes a plain
        // ETH transfer to an EOA work (spec §EOA support / Example 1).
        // Consumes no execution gas (the frame's value transfer is handled by
        // the caller's deferred transfer).
        FrameMode::Sender | FrameMode::Default => Ok((true, 0, Vec::new())),
    }
}

fn execute_default_verify(
    vm: &mut VM<'_>,
    frame: &ethrex_common::types::Frame,
    target: Address,
) -> Result<(bool, u64, Vec<Log>), VMError> {
    let ctx = vm
        .frame_tx_context
        .as_ref()
        .ok_or(ExceptionalHalt::InvalidOpcode)?;

    // Read allowed scope from flags bits 0-1
    let allowed_scope = u64::from(frame.scope_restriction());
    if allowed_scope == 0 {
        return Ok((false, 0, Vec::new()));
    }

    // If scope includes APPROVE_EXECUTION and resolved_target != tx.sender, revert
    if (allowed_scope & 0x02) != 0 && target != ctx.tx.sender {
        return Ok((false, 0, Vec::new()));
    }

    // EIP-8141: the default account approves only if the signature at a specific
    // index — 0 when the allowed scope includes APPROVE_EXECUTION, else 1 (the
    // payment-only case, where index 0 belongs to the sender's own verify frame)
    // — is a SECP256K1 signature over the canonical sig_hash (empty msg) whose
    // resolved signer is the resolved target. An absent signer resolves to
    // tx.sender. Signatures were already validated in execute_frame_tx, so a
    // match here is sufficient — no in-frame crypto.
    let sig_index = if (allowed_scope & 0x02) != 0 { 0 } else { 1 };
    let sender_sig_ok = ctx.tx.signatures.get(sig_index).is_some_and(|s| {
        s.scheme == ethrex_common::types::FRAME_SIG_SCHEME_SECP256K1
            && s.msg.is_empty()
            && s.signer.unwrap_or(ctx.tx.sender) == target
    });
    if !sender_sig_ok {
        return Ok((false, 0, Vec::new()));
    }

    apply_approve(vm, allowed_scope, target)?;

    let ctx = vm
        .frame_tx_context
        .as_mut()
        .ok_or(ExceptionalHalt::InvalidOpcode)?;
    ctx.approve_called_in_current_frame = true;

    Ok((true, 0, Vec::new()))
}

#[cfg(test)]
mod max_cost_tests {
    use super::{compute_tx_max_cost, load_tx_param};
    use crate::vm::FrameTxContext;
    use ethrex_common::{H256, U256, types::FrameTransaction};

    fn ctx(max_fee: u64, blobs: usize, blob_base_fee: u64, max_gas: u64) -> FrameTxContext {
        let tx = FrameTransaction {
            max_fee_per_gas: U256::from(max_fee),
            // Deliberately far above the base fee: `max_fee_per_blob_gas` bounds
            // inclusion only and must not reach `max_cost`.
            max_fee_per_blob_gas: U256::from(blob_base_fee).saturating_mul(U256::from(1_000u64)),
            blob_versioned_hashes: vec![H256::zero(); blobs],
            ..Default::default()
        };
        FrameTxContext {
            sender_approved: false,
            payer_address: None,
            frame_results: Vec::new(),
            current_frame_index: 0,
            sig_hash: H256::zero(),
            tx,
            approve_called_in_current_frame: false,
            max_gas,
            blob_base_fee: U256::from(blob_base_fee),
            outstanding_charge_owners: Default::default(),
        }
    }

    #[test]
    fn max_cost_is_max_fee_times_limit_plus_base_rate_blob_cost() {
        // 10 * 100_000 + 2 * 131072 * 5 = 1_000_000 + 1_310_720
        let c = ctx(10, 2, 5, 100_000);
        assert_eq!(compute_tx_max_cost(&c).unwrap(), U256::from(2_310_720u64));
        // No blobs: just max_fee * max_gas.
        let c = ctx(7, 0, 999, 21_000);
        assert_eq!(compute_tx_max_cost(&c).unwrap(), U256::from(147_000u64));
    }

    #[test]
    fn txparam_0x06_reports_the_same_maximum_cost_approve_debits() {
        // TXPARAM(0x06) and the APPROVE debit must stay one definition of
        // "maximum cost"; a split between them is a consensus bug.
        let c = ctx(10, 2, 5, 100_000);
        assert_eq!(
            load_tx_param(&c, 0x06, 0).unwrap(),
            compute_tx_max_cost(&c).unwrap()
        );
    }
}
