//! # Control flow and memory operations
//!
//! Includes the following opcodes:
//!   - `POP`
//!   - `GAS`
//!   - `PC`
//!   - `MLOAD`
//!   - `MSTORE`
//!   - `MSTORE8`
//!   - `MCOPY`
//!   - `MSIZE`
//!   - `TLOAD`
//!   - `TSTORE`
//!   - `SLOAD`
//!   - `SSTORE`
//!   - `JUMPDEST`
//!   - `JUMP`
//!   - `JUMPI`

use crate::{
    constants::WORD_SIZE_IN_BYTES_USIZE,
    errors::{ExceptionalHalt, InternalError, OpcodeResult, VMError},
    gas_cost::{self, SSTORE_DEFAULT_DYNAMIC, SSTORE_STIPEND, STORAGE_CLEAR_REFUND_AMSTERDAM},
    memory::calculate_memory_size,
    opcode_handlers::OpcodeHandler,
    opcodes::Opcode,
    utils::{size_offset_to_usize, u256_to_usize},
    vm::VM,
};
use ethrex_common::{BigEndianHash, H256, U256, types::Fork};
use std::{mem, slice};

/// Implementation for the `POP` opcode.
pub struct OpPopHandler;
impl OpcodeHandler for OpPopHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame.increase_consumed_gas(gas_cost::POP)?;

        vm.current_call_frame.stack.pop1()?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `GAS` opcode.
pub struct OpGasHandler;
impl OpcodeHandler for OpGasHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame.increase_consumed_gas(gas_cost::GAS)?;

        vm.current_call_frame
            .stack
            .push(vm.current_call_frame.gas_remaining.into())?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `PC` opcode.
pub struct OpPcHandler;
impl OpcodeHandler for OpPcHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame.increase_consumed_gas(gas_cost::PC)?;

        // Note: Since the PC has been preincremented, subtracting 1 from it to get the operation's
        //   offset will never cause an underflow condition.
        vm.current_call_frame
            .stack
            .push(vm.current_call_frame.pc.wrapping_sub(1).into())?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `MLOAD` opcode.
pub struct OpMLoadHandler;
impl OpcodeHandler for OpMLoadHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        // Stack-neutral: replace the top (the offset) with the loaded word in place.
        let offset = u256_to_usize(*vm.current_call_frame.stack.top_mut()?)?;
        let new_size = calculate_memory_size(offset, WORD_SIZE_IN_BYTES_USIZE)?;
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::mload(
                new_size,
                vm.current_call_frame.memory.len(),
            )?)?;

        let word = vm
            .current_call_frame
            .memory
            .load_word_prerounded(offset, new_size)?;
        // MLOAD is stack-neutral: the top was validated by the `top_mut()?` read
        // above and the depth is unchanged, so skip the redundant bounds check.
        #[expect(unsafe_code, reason = "top validated above; MLOAD is stack-neutral")]
        unsafe {
            vm.current_call_frame.stack.set_top_unchecked(word);
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `MSTORE` opcode.
pub struct OpMStoreHandler;
impl OpcodeHandler for OpMStoreHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, value] = *vm.current_call_frame.stack.pop()?;

        // Handle debug text printing for solidity contracts that enable it.
        if vm.debug_mode.enabled && vm.debug_mode.handle_debug(offset, value)? {
            return Ok(OpcodeResult::Continue);
        }

        let offset = u256_to_usize(offset)?;
        // Round the new memory size up to a word once, then reuse it for both the
        // gas charge and the store (store_word would otherwise re-round it).
        let new_size = calculate_memory_size(offset, WORD_SIZE_IN_BYTES_USIZE)?;
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::mstore(
                new_size,
                vm.current_call_frame.memory.len(),
            )?)?;

        vm.current_call_frame
            .memory
            .store_word_prerounded(offset, value, new_size)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `MSTORE8` opcode.
pub struct OpMStore8Handler;
impl OpcodeHandler for OpMStore8Handler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, value] = *vm.current_call_frame.stack.pop()?;
        let offset = u256_to_usize(offset)?;
        let value = value.byte(0);

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::mstore8(
                calculate_memory_size(offset, size_of::<u8>())?,
                vm.current_call_frame.memory.len(),
            )?)?;

        vm.current_call_frame
            .memory
            .store_data(offset, slice::from_ref(&value))?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `MCOPY` opcode.
pub struct OpMCopyHandler;
impl OpcodeHandler for OpMCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [dst_offset, src_offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, dst_offset) = size_offset_to_usize(len, dst_offset)?;
        let src_offset = u256_to_usize(src_offset).unwrap_or(usize::MAX);

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::mcopy(
                calculate_memory_size(src_offset.max(dst_offset), len)?,
                vm.current_call_frame.memory.len(),
                len,
            )?)?;

        vm.current_call_frame
            .memory
            .copy_within(src_offset, dst_offset, len)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `MSIZE` opcode.
pub struct OpMSizeHandler;
impl OpcodeHandler for OpMSizeHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::MSIZE)?;

        vm.current_call_frame
            .stack
            .push(vm.current_call_frame.memory.len().into())?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `TLOAD` opcode.
pub struct OpTLoadHandler;
impl OpcodeHandler for OpTLoadHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::TLOAD)?;

        let key = vm.current_call_frame.stack.pop1()?;
        vm.current_call_frame
            .stack
            .push(vm.substate.get_transient(&vm.current_call_frame.to, &key))?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `TSTORE` opcode.
pub struct OpTStoreHandler;
impl OpcodeHandler for OpTStoreHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        if vm.current_call_frame.is_static {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::TSTORE)?;

        let [key, value] = *vm.current_call_frame.stack.pop()?;
        vm.substate
            .set_transient(&vm.current_call_frame.to, &key, value);

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `SLOAD` opcode.
pub struct OpSLoadHandler;
impl OpcodeHandler for OpSLoadHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let storage_slot_key = vm.current_call_frame.stack.pop1()?;
        let address = vm.current_call_frame.to;
        let key = {
            #[expect(unsafe_code)]
            unsafe {
                let mut hash = mem::transmute::<U256, H256>(storage_slot_key);
                hash.0.reverse();
                hash
            }
        };

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::sload(
                vm.substate.add_accessed_slot(address, key),
                vm.env.config.fork,
            )?)?;

        // Record to BAL AFTER gas check passes per EIP-7928
        vm.record_storage_slot_to_bal(address, storage_slot_key);

        // EIP-8141 mempool validation-trace: SLOAD restricted to the sender's storage.
        if vm.validation_observer.active {
            vm.validation_check_sload(address, key);
        }

        let value = vm.get_storage_value(address, key)?;
        vm.current_call_frame.stack.push(value)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `SSTORE` opcode.
pub struct OpSStoreHandler;
impl OpcodeHandler for OpSStoreHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        if vm.current_call_frame.is_static {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        let fork = vm.env.config.fork;

        // EIP-2200. Pre-Amsterdam, COLD_STORAGE_ACCESS (2100) never exceeds the
        // 2300 stipend, so gating on the flat stipend alone is sufficient.
        if fork < Fork::Amsterdam && vm.current_call_frame.gas_remaining <= SSTORE_STIPEND {
            return Err(ExceptionalHalt::OutOfGas.into());
        }

        let [storage_slot_key, value] = *vm.current_call_frame.stack.pop()?;
        let to = vm.current_call_frame.to;
        #[expect(unsafe_code)]
        let key = unsafe {
            let mut hash = mem::transmute::<U256, H256>(storage_slot_key);
            hash.0.reverse();
            hash
        };

        if fork >= Fork::Amsterdam {
            // EIP-8038 prices the cold storage access independently of the 2300
            // stipend, so the flat pre-Amsterdam gate above no longer suffices
            // as the EIP-2200 sentry. Peek warmth WITHOUT
            // marking the slot accessed, gate on
            // `max(access_cost, SSTORE_STIPEND + 1)` per EELS `check_gas`
            // (amsterdam/vm/instructions/storage.py::sstore), and only mark the
            // slot accessed / record the BAL read once this gate passes.
            let is_cold = !vm.substate.is_slot_accessed(&to, &key);
            let access_cost = if is_cold {
                gas_cost::cold_storage_access_cost(fork)
            } else {
                SSTORE_DEFAULT_DYNAMIC
            };
            let sstore_stipend_floor = u64::try_from(SSTORE_STIPEND)
                .map_err(|_| InternalError::TypeConversion)?
                .checked_add(1)
                .ok_or(InternalError::Overflow)?;
            vm.current_call_frame
                .check_gas(access_cost.max(sstore_stipend_floor))?;
        }

        let (current_value, original_value, storage_slot_was_cold) =
            vm.access_storage_slot_for_sstore(to, key)?;

        // Record storage read to BAL AFTER the stipend/access-cost gate passes,
        // BEFORE the main gas check. Per EIP-7928: if SSTORE passes that gate
        // but fails the main gas charge, the slot MUST appear as a read
        // because the implicit SLOAD has already happened.
        vm.record_storage_slot_to_bal(to, storage_slot_key);

        // EIP-8141 mempool validation-trace: SSTORE allowed only inside the
        // deploy frame and only against the sender's own storage.
        if vm.validation_observer.active {
            vm.validation_check_sstore(to, key);
        }

        // EIP-8037 (Amsterdam+): check if state gas is needed for new storage slot (0 -> nonzero),
        // but charge it AFTER regular gas per EELS ordering (ethereum/EIPs#11421).
        // Regular gas OOG must not consume state gas that would inflate the parent's reservoir.
        let needs_state_gas = fork >= Fork::Amsterdam
            && value != current_value
            && current_value == original_value
            && original_value.is_zero()
            && !value.is_zero();

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::sstore(
                original_value,
                current_value,
                value,
                storage_slot_was_cold,
                fork,
            )?)?;

        if needs_state_gas {
            // EIP-8141 attributes the charge to the frame that paid it, so a later
            // frame clearing the slot refills that frame rather than its own pool.
            vm.charge_storage_set_state_gas(to, H256::from_uint(&storage_slot_key))?;
        }
        // EIP-8037 (Amsterdam+) 0→N→0: the slot was created in this tx (original == 0),
        // dirtied to N (current_value != 0), and now being reset to 0 (value == original == 0).
        // The creation state gas is refunded via clamp-and-spill, not the regular refund counter.
        let is_zero_to_n_to_zero_amsterdam = fork >= Fork::Amsterdam
            && value != current_value
            && current_value != original_value
            && value == original_value
            && original_value.is_zero();

        if value != current_value {
            // Net refund deltas accumulated across a tx's SSTOREs, matching EELS
            // (execution-specs amsterdam/vm/instructions/storage.py::sstore): +clear-refund on a
            // first-time clear, -clear-refund when that clear is reversed, and +STORAGE_WRITE when
            // a slot is restored to its original value (access is charged separately). EIP-8037
            // state gas is handled via the reservoir, not these regular deltas.
            let (remove_slot_cost, restore_empty_slot_cost, restore_slot_cost): (i64, i64, i64) =
                if fork >= Fork::Amsterdam {
                    // Amsterdam: both restore deltas are the full STORAGE_WRITE.
                    (STORAGE_CLEAR_REFUND_AMSTERDAM, 10000, 10000)
                } else {
                    // EIP-2929
                    (4800, 19900, 2800)
                };

            // The operations on `delta` cannot overflow.
            let mut delta = 0i64;
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "delta additions are bounded by known constants"
            )]
            if current_value == original_value {
                if !original_value.is_zero() && value.is_zero() {
                    delta += remove_slot_cost;
                }
            } else {
                if !original_value.is_zero() {
                    if current_value.is_zero() {
                        delta -= remove_slot_cost;
                    } else if value.is_zero() {
                        delta += remove_slot_cost;
                    }
                }

                if value == original_value {
                    if original_value.is_zero() {
                        delta += restore_empty_slot_cost;
                    } else {
                        delta += restore_slot_cost;
                    }
                }
            }

            // Update refunded gas after checking for overflow or underflow.
            match vm.substate.refunded_gas.checked_add_signed(delta) {
                Some(refunded_gas) => vm.substate.refunded_gas = refunded_gas,
                None if delta < 0 => return Err(InternalError::Underflow.into()),
                None => return Err(InternalError::Overflow.into()),
            }
        }

        // EIP-8037: credit the state gas refund via clamp-and-spill (after regular gas processing).
        if is_zero_to_n_to_zero_amsterdam {
            vm.refill_storage_set_state_gas(to, H256::from_uint(&storage_slot_key))?;
        }

        if value != current_value {
            vm.update_account_storage(to, key, storage_slot_key, value, current_value)?;
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `JUMPDEST` opcode.
pub struct OpJumpDestHandler;
impl OpcodeHandler for OpJumpDestHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::JUMPDEST)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `JUMP` opcode.
pub struct OpJumpHandler;
impl OpcodeHandler for OpJumpHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::JUMP)?;

        let target = vm.current_call_frame.stack.pop1()?;
        jump(vm, target.try_into().unwrap_or(usize::MAX), gas_cost::JUMP)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `JUMPI` opcode.
pub struct OpJumpIHandler;
impl OpcodeHandler for OpJumpIHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::JUMPI)?;

        let [target, condition] = *vm.current_call_frame.stack.pop()?;
        if !condition.is_zero() {
            jump(vm, target.try_into().unwrap_or(usize::MAX), gas_cost::JUMPI)?;
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Validate and take a jump. Fuses the destination JUMPDEST (advances PC past
/// it and charges its 1 gas inline) to save a dispatch cycle on the hot path.
///
/// When the tracer is active we keep the fusion for performance and *synthesize*
/// a JUMPDEST entry in the trace log: `parent_gas_cost` is recorded as the
/// override for the parent JUMP/JUMPI step (so its `gasCost` doesn't absorb the
/// JUMPDEST charge), and the JUMPDEST step is pushed directly via
/// `synthesize_step` after the gas is charged.
fn jump(vm: &mut VM<'_>, target: usize, parent_gas_cost: u64) -> Result<(), VMError> {
    // Check target address validity: the target has to be a JUMPDEST that is not part
    // of a literal (aka. a PUSH immediate). Both are answered by the bitmap, which only
    // has bits set for JUMPDESTs reached by the opcode walk.
    if vm.current_call_frame.bytecode.is_valid_jumpdest(target) {
        if vm.opcode_tracer.active {
            // Override the parent JUMP/JUMPI's gasCost so the dispatch loop
            // doesn't roll the upcoming JUMPDEST charge into it.
            vm.opcode_tracer.last_opcode_gas_cost = Some(parent_gas_cost);

            // Capture the synthetic JUMPDEST step's state BEFORE charging its gas.
            let synth = build_jumpdest_step(vm, target);

            // Fuse: charge JUMPDEST + advance PC past it.
            vm.current_call_frame.pc = target.wrapping_add(1);
            vm.current_call_frame
                .increase_consumed_gas(gas_cost::JUMPDEST)?;

            vm.opcode_tracer.synthesize_step(synth);
        } else {
            // Hot path: fuse JUMP/JUMPI + JUMPDEST without any trace bookkeeping.
            vm.current_call_frame.pc = target.wrapping_add(1);
            vm.current_call_frame
                .increase_consumed_gas(gas_cost::JUMPDEST)?;
        }
        Ok(())
    } else {
        // Target address is invalid.
        Err(ExceptionalHalt::InvalidJump.into())
    }
}

/// Builds a synthetic JUMPDEST trace entry. Captures gas/stack/memory/return-data
/// state at the moment of the call (i.e. *before* the JUMPDEST gas has been
/// charged) and hands them to the shared [`opcode_tracer::build_step`] so the
/// cfg-driven conditionals (disable_stack, enable_memory, enable_return_data)
/// live in exactly one place.
#[expect(
    clippy::as_conversions,
    reason = "pc/depth/mem_size bounded; fit in target types"
)]
fn build_jumpdest_step(vm: &VM<'_>, target: usize) -> ethrex_common::tracing::OpcodeStep {
    use crate::opcode_tracer::build_step;
    use bytes::Bytes;

    let cfg = &vm.opcode_tracer.cfg;
    let gas = vm.current_call_frame.gas_remaining.max(0) as u64;
    let depth = (vm.call_frames.len() as u32).saturating_add(1);
    let refund = vm.substate.refunded_gas;
    let mem_size = vm.current_call_frame.memory.len() as u64;

    let stack_view = if cfg.disable_stack {
        Vec::new()
    } else {
        vm.collect_stack_for_trace()
    };
    let mem_view = if cfg.enable_memory {
        vm.collect_memory_for_trace()
    } else {
        Vec::new()
    };
    let return_data = if cfg.enable_return_data {
        vm.current_call_frame.sub_return_data.clone()
    } else {
        Bytes::new()
    };

    build_step(
        cfg,
        target as u64,
        Opcode::JUMPDEST as u8,
        gas,
        gas_cost::JUMPDEST,
        depth,
        refund,
        &stack_view,
        &mem_view,
        mem_size,
        &return_data,
        None,
    )
}
