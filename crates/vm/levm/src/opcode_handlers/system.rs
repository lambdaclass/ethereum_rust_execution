//! # System operations
//!
//! Includes the following opcodes:
//!   - `CALL`
//!   - `CALLCODE`
//!   - `DELEGATECALL`
//!   - `STATICCALL`
//!   - `RETURN`
//!   - `CREATE`
//!   - `CREATE2`
//!   - `SELFDESTRUCT`
//!   - `REVERT`

use crate::{
    call_frame::CallFrame,
    constants::{AMSTERDAM_INIT_CODE_MAX_SIZE, FAIL, INIT_CODE_MAX_SIZE, SUCCESS},
    errors::{ContextResult, ExceptionalHalt, InternalError, OpcodeResult, TxResult, VMError},
    gas_cost,
    memory::{self, calculate_memory_size},
    opcode_handlers::OpcodeHandler,
    utils::{address_to_word, create_eth_transfer_log, word_to_address, *},
    vm::VM,
};
use bytes::Bytes;
use ethrex_common::{Address, H256, U256, evm::calculate_create_address, types::Fork};
use ethrex_common::{tracing::CallType, types::Code};

pub struct OpCallHandler;
impl OpcodeHandler for OpCallHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [
            gas,
            callee,
            value,
            args_offset,
            args_len,
            return_offset,
            return_len,
        ] = *vm.current_call_frame.stack.pop()?;
        let callee = word_to_address(callee);
        let (args_len, args_offset) = size_offset_to_usize(args_len, args_offset)?;
        let (return_len, return_offset) = size_offset_to_usize(return_len, return_offset)?;

        // Validations.
        if vm.current_call_frame.is_static && !value.is_zero() {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        let value_cost = if !value.is_zero() {
            gas_cost::call_positive_value_cost(vm.env.config.fork)
        } else {
            0
        };
        let (new_memory_size, address_was_cold, static_cost) = vm.check_call_static_gas(
            args_offset,
            args_len,
            return_offset,
            return_len,
            callee,
            value_cost,
        )?;

        vm.substate.add_accessed_address(callee);
        // `address_is_empty` only feeds gates that also require `value != 0`,
        // so skip the read entirely when value is zero (matches EELS' gating
        // of `is_account_alive` on `value != 0`).
        let address_is_empty = if value.is_zero() {
            false
        } else {
            vm.db.get_account(callee)?.is_empty()
        };
        // Detect a 7702 delegation without reading the delegate account: per
        // EELS the delegate access cost is gas-checked first, so an OOG must
        // not leak the delegate read into execution witnesses (EIP-8025).
        let (callee_code, delegation) =
            eip7702_peek_delegation(vm.db, &vm.substate, callee, vm.env.config.fork)?;
        let is_delegation_7702 = delegation.is_some();
        let (eip7702_gas_consumed, code_address) = match delegation {
            Some((auth_address, access_cost)) => (access_cost, auth_address),
            None => (0, callee),
        };

        // EIP-8141 mempool validation-trace: the CALL target must be an existing
        // account or precompile and not EIP-7702-delegated (sender exempt).
        if vm.validation_observer.active {
            vm.validation_check_call_target(callee, is_delegation_7702)?;
        }

        let create_cost = if address_is_empty {
            gas_cost::CALL_TO_EMPTY_ACCOUNT
        } else {
            0
        };

        // BAL touches the target before the delegation gas check, so a failed
        // delegate-access check still leaves the target recorded.
        vm.record_bal_call_touch(
            callee,
            code_address,
            is_delegation_7702,
            eip7702_gas_consumed,
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            value_cost,
            create_cost,
        );

        // `create_cost` is EIP-8037 state gas (charged via `increase_state_gas`
        // below) and must not appear in the regular-gas check.
        let bytecode = if let Some((auth_address, access_cost)) = delegation {
            vm.current_call_frame.check_gas(
                static_cost
                    .checked_add(access_cost)
                    .ok_or(ExceptionalHalt::OutOfGas)?,
            )?;
            vm.substate.add_accessed_address(auth_address);
            vm.db.get_account_code(auth_address)?.clone()
        } else {
            callee_code
        };

        let fork = vm.env.config.fork;

        // Compute gas_left after eip7702 consumption (without modifying gas_remaining yet).
        #[expect(clippy::as_conversions, reason = "safe")]
        let gas_left = (vm.current_call_frame.gas_remaining as u64)
            .checked_sub(eip7702_gas_consumed)
            .ok_or(ExceptionalHalt::OutOfGas)?;

        // EIP-8037 (Amsterdam+): account for state gas spill in child gas computation,
        // but charge state gas AFTER regular gas per EIPs#11421.
        // Regular gas OOG must not consume state gas that would inflate the parent's
        // reservoir on frame failure.
        let needs_state_gas = fork >= Fork::Amsterdam && address_is_empty;
        let gas_left = if needs_state_gas {
            let state_gas_new_account = vm.state_gas_new_account;
            let from_reservoir = vm.state_gas_reservoir.min(state_gas_new_account);
            // Safe: from_reservoir = min(reservoir, state_gas_new_account) <= state_gas_new_account
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "from_reservoir <= state_gas_new_account"
            )]
            let spill = state_gas_new_account - from_reservoir;
            gas_left
                .checked_sub(spill)
                .ok_or(ExceptionalHalt::OutOfGas)?
        } else {
            gas_left
        };

        let (gas_cost, gas_limit) = gas_cost::call(
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            address_is_empty,
            value,
            gas,
            gas_left,
            fork,
        )?;

        // Charge regular gas first (before state gas, per EIPs#11421).
        vm.current_call_frame.increase_consumed_gas(
            gas_cost
                .checked_add(eip7702_gas_consumed)
                .ok_or(ExceptionalHalt::OutOfGas)?,
        )?;

        // Then charge state gas for new account creation.
        if needs_state_gas {
            vm.increase_state_gas(vm.state_gas_new_account)?;
        }

        // Struct-log: record the geth-compatible CALL gasCost.
        // Geth's gasCost for CALL family = intrinsic_overhead + callGasTemp (forwarded gas
        // WITHOUT stipend). LEVM's `gas_cost` already equals `call_gas_costs + gas_forwarded`,
        // i.e. `intrinsic + callGasTemp`. Stipend is added later inside the child frame, after
        // the tracer fires, so it is NOT part of the reported gasCost.
        if vm.opcode_tracer.active {
            let geth_cost = gas_cost.saturating_add(eip7702_gas_consumed);
            vm.opcode_tracer.last_opcode_gas_cost = Some(geth_cost);
        }

        // Resize memory: this is necessary for multiple reasons:
        //   - Make sure the memory is expanded.
        //   - When there is return data, preallocate it because it won't be possible while the next
        //     call frame is active.
        vm.current_call_frame.memory.resize(new_memory_size)?;

        // Trace CALL operation.
        let data = vm.get_calldata(args_offset, args_len)?;
        vm.tracer.enter(
            CallType::CALL,
            vm.current_call_frame.to,
            callee,
            value,
            gas_limit,
            &data,
        );

        // Generic call.
        vm.generic_call(
            gas_limit,
            value,
            vm.current_call_frame.to,
            callee,
            code_address,
            true,
            vm.current_call_frame.is_static,
            data,
            return_offset,
            return_len,
            bytecode,
            is_delegation_7702,
            needs_state_gas,
        )
    }
}

pub struct OpCallCodeHandler;
impl OpcodeHandler for OpCallCodeHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [
            gas,
            address,
            value,
            args_offset,
            args_len,
            return_offset,
            return_len,
        ] = *vm.current_call_frame.stack.pop()?;
        let address = word_to_address(address);
        let (args_len, args_offset) = size_offset_to_usize(args_len, args_offset)?;
        let (return_len, return_offset) = size_offset_to_usize(return_len, return_offset)?;

        let value_cost = if !value.is_zero() {
            gas_cost::call_positive_value_cost(vm.env.config.fork)
        } else {
            0
        };
        let (new_memory_size, address_was_cold, static_cost) = vm.check_call_static_gas(
            args_offset,
            args_len,
            return_offset,
            return_len,
            address,
            value_cost,
        )?;

        vm.substate.add_accessed_address(address);
        // Detect a 7702 delegation without reading the delegate account: per
        // EELS the delegate access cost is gas-checked first, so an OOG must
        // not leak the delegate read into execution witnesses (EIP-8025).
        let (target_code, delegation) =
            eip7702_peek_delegation(vm.db, &vm.substate, address, vm.env.config.fork)?;
        let is_delegation_7702 = delegation.is_some();
        let (eip7702_gas_consumed, code_address) = match delegation {
            Some((auth_address, access_cost)) => (access_cost, auth_address),
            None => (0, address),
        };

        // EIP-8141 mempool validation-trace: CALLCODE target check (CALLCODE
        // itself is banned in non-deploy prefix frames; this also guards the
        // deploy-frame case).
        if vm.validation_observer.active {
            vm.validation_check_call_target(address, is_delegation_7702)?;
        }

        // BAL touches the target before the delegation gas check.
        vm.record_bal_call_touch(
            address,
            code_address,
            is_delegation_7702,
            eip7702_gas_consumed,
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            value_cost,
            0,
        );

        let bytecode = if let Some((auth_address, access_cost)) = delegation {
            vm.current_call_frame.check_gas(
                static_cost
                    .checked_add(access_cost)
                    .ok_or(ExceptionalHalt::OutOfGas)?,
            )?;
            vm.substate.add_accessed_address(auth_address);
            vm.db.get_account_code(auth_address)?.clone()
        } else {
            target_code
        };

        #[expect(clippy::as_conversions, reason = "safe")]
        let gas_left = (vm.current_call_frame.gas_remaining as u64)
            .checked_sub(eip7702_gas_consumed)
            .ok_or(ExceptionalHalt::OutOfGas)?;
        let (gas_cost, gas_limit) = gas_cost::callcode(
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            value,
            gas,
            gas_left,
            vm.env.config.fork,
        )?;
        vm.current_call_frame.increase_consumed_gas(
            gas_cost
                .checked_add(eip7702_gas_consumed)
                .ok_or(ExceptionalHalt::OutOfGas)?,
        )?;

        // Struct-log: geth-compatible CALLCODE gasCost (intrinsic + forwarded, no stipend).
        if vm.opcode_tracer.active {
            let geth_cost = gas_cost.saturating_add(eip7702_gas_consumed);
            vm.opcode_tracer.last_opcode_gas_cost = Some(geth_cost);
        }

        // Resize memory: this is necessary for multiple reasons:
        //   - Make sure the memory is expanded.
        //   - When there is return data, preallocate it because it won't be possible while the next
        //     call frame is active.
        vm.current_call_frame.memory.resize(new_memory_size)?;

        // Trace CALL operation.
        let data = vm.get_calldata(args_offset, args_len)?;
        vm.tracer.enter(
            CallType::CALLCODE,
            vm.current_call_frame.to,
            code_address,
            value,
            gas_limit,
            &data,
        );

        // Generic call.
        vm.generic_call(
            gas_limit,
            value,
            vm.current_call_frame.to,
            vm.current_call_frame.to,
            code_address,
            true,
            vm.current_call_frame.is_static,
            data,
            return_offset,
            return_len,
            bytecode,
            is_delegation_7702,
            false,
        )
    }
}

pub struct OpDelegateCallHandler;
impl OpcodeHandler for OpDelegateCallHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [
            gas,
            address,
            args_offset,
            args_len,
            return_offset,
            return_len,
        ] = *vm.current_call_frame.stack.pop()?;
        let address = word_to_address(address);
        let (args_len, args_offset) = size_offset_to_usize(args_len, args_offset)?;
        let (return_len, return_offset) = size_offset_to_usize(return_len, return_offset)?;

        let (new_memory_size, address_was_cold, static_cost) =
            vm.check_call_static_gas(args_offset, args_len, return_offset, return_len, address, 0)?;

        vm.substate.add_accessed_address(address);
        // Detect a 7702 delegation without reading the delegate account: per
        // EELS the delegate access cost is gas-checked first, so an OOG must
        // not leak the delegate read into execution witnesses (EIP-8025).
        let (target_code, delegation) =
            eip7702_peek_delegation(vm.db, &vm.substate, address, vm.env.config.fork)?;
        let is_delegation_7702 = delegation.is_some();
        let (eip7702_gas_consumed, code_address) = match delegation {
            Some((auth_address, access_cost)) => (access_cost, auth_address),
            None => (0, address),
        };

        // EIP-8141 mempool validation-trace: the call target must be an existing
        // account or precompile and not EIP-7702-delegated (sender exempt).
        if vm.validation_observer.active {
            vm.validation_check_call_target(address, is_delegation_7702)?;
        }

        // BAL touches the target before the delegation gas check.
        vm.record_bal_call_touch(
            address,
            code_address,
            is_delegation_7702,
            eip7702_gas_consumed,
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            0,
            0,
        );

        let bytecode = if let Some((auth_address, access_cost)) = delegation {
            vm.current_call_frame.check_gas(
                static_cost
                    .checked_add(access_cost)
                    .ok_or(ExceptionalHalt::OutOfGas)?,
            )?;
            vm.substate.add_accessed_address(auth_address);
            vm.db.get_account_code(auth_address)?.clone()
        } else {
            target_code
        };

        #[expect(clippy::as_conversions, reason = "safe")]
        let gas_left = (vm.current_call_frame.gas_remaining as u64)
            .checked_sub(eip7702_gas_consumed)
            .ok_or(ExceptionalHalt::OutOfGas)?;
        let (gas_cost, gas_limit) = gas_cost::delegatecall(
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            gas,
            gas_left,
            vm.env.config.fork,
        )?;
        vm.current_call_frame.increase_consumed_gas(
            gas_cost
                .checked_add(eip7702_gas_consumed)
                .ok_or(ExceptionalHalt::OutOfGas)?,
        )?;

        // Struct-log: geth-compatible DELEGATECALL gasCost (intrinsic + forwarded).
        if vm.opcode_tracer.active {
            let geth_cost = gas_cost.saturating_add(eip7702_gas_consumed);
            vm.opcode_tracer.last_opcode_gas_cost = Some(geth_cost);
        }

        // Resize memory: this is necessary for multiple reasons:
        //   - Make sure the memory is expanded.
        //   - When there is return data, preallocate it because it won't be possible while the next
        //     call frame is available.
        vm.current_call_frame.memory.resize(new_memory_size)?;

        // Trace CALL operation.
        let data = vm.get_calldata(args_offset, args_len)?;
        // In this trace the `from` is the current contract, we don't want the `from` to be,
        // for example, the EOA that sent the transaction.
        vm.tracer.enter(
            CallType::DELEGATECALL,
            vm.current_call_frame.to,
            code_address,
            vm.current_call_frame.msg_value,
            gas_limit,
            &data,
        );

        // Generic call.
        vm.generic_call(
            gas_limit,
            vm.current_call_frame.msg_value,
            vm.current_call_frame.msg_sender,
            vm.current_call_frame.to,
            code_address,
            false,
            vm.current_call_frame.is_static,
            data,
            return_offset,
            return_len,
            bytecode,
            is_delegation_7702,
            false,
        )
    }
}

pub struct OpStaticCallHandler;
impl OpcodeHandler for OpStaticCallHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [
            gas,
            address,
            args_offset,
            args_len,
            return_offset,
            return_len,
        ] = *vm.current_call_frame.stack.pop()?;
        let address = word_to_address(address);
        let (args_len, args_offset) = size_offset_to_usize(args_len, args_offset)?;
        let (return_len, return_offset) = size_offset_to_usize(return_len, return_offset)?;

        let (new_memory_size, address_was_cold, static_cost) =
            vm.check_call_static_gas(args_offset, args_len, return_offset, return_len, address, 0)?;

        vm.substate.add_accessed_address(address);
        // Detect a 7702 delegation without reading the delegate account: per
        // EELS the delegate access cost is gas-checked first, so an OOG must
        // not leak the delegate read into execution witnesses (EIP-8025).
        let (target_code, delegation) =
            eip7702_peek_delegation(vm.db, &vm.substate, address, vm.env.config.fork)?;
        let is_delegation_7702 = delegation.is_some();
        let (eip7702_gas_consumed, code_address) = match delegation {
            Some((auth_address, access_cost)) => (access_cost, auth_address),
            None => (0, address),
        };

        // EIP-8141 mempool validation-trace: the call target must be an existing
        // account or precompile and not EIP-7702-delegated (sender exempt).
        if vm.validation_observer.active {
            vm.validation_check_call_target(address, is_delegation_7702)?;
        }

        // BAL touches the target before the delegation gas check.
        vm.record_bal_call_touch(
            address,
            code_address,
            is_delegation_7702,
            eip7702_gas_consumed,
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            0,
            0,
        );

        let bytecode = if let Some((auth_address, access_cost)) = delegation {
            vm.current_call_frame.check_gas(
                static_cost
                    .checked_add(access_cost)
                    .ok_or(ExceptionalHalt::OutOfGas)?,
            )?;
            vm.substate.add_accessed_address(auth_address);
            vm.db.get_account_code(auth_address)?.clone()
        } else {
            target_code
        };

        #[expect(clippy::as_conversions, reason = "safe")]
        let gas_left = (vm.current_call_frame.gas_remaining as u64)
            .checked_sub(eip7702_gas_consumed)
            .ok_or(ExceptionalHalt::OutOfGas)?;
        let (gas_cost, gas_limit) = gas_cost::staticcall(
            new_memory_size,
            vm.current_call_frame.memory.len(),
            address_was_cold,
            gas,
            gas_left,
            vm.env.config.fork,
        )?;
        vm.current_call_frame.increase_consumed_gas(
            gas_cost
                .checked_add(eip7702_gas_consumed)
                .ok_or(ExceptionalHalt::OutOfGas)?,
        )?;

        // Struct-log: geth-compatible STATICCALL gasCost (intrinsic + forwarded).
        if vm.opcode_tracer.active {
            let geth_cost = gas_cost.saturating_add(eip7702_gas_consumed);
            vm.opcode_tracer.last_opcode_gas_cost = Some(geth_cost);
        }

        // Resize memory: this is necessary for multiple reasons:
        //   - Make sure the memory is expanded.
        //   - When there is return data, preallocate it because it won't be possible while the next
        //     call frame is active.
        vm.current_call_frame.memory.resize(new_memory_size)?;

        // Trace CALL operation.
        let data = vm.get_calldata(args_offset, args_len)?;
        vm.tracer.enter(
            CallType::STATICCALL,
            vm.current_call_frame.to,
            address,
            U256::zero(),
            gas_limit,
            &data,
        );

        // Generic call.
        vm.generic_call(
            gas_limit,
            U256::zero(),
            vm.current_call_frame.to,
            address,
            address,
            true,
            true,
            data,
            return_offset,
            return_len,
            bytecode,
            is_delegation_7702,
            false,
        )
    }
}

pub struct OpReturnHandler;
impl OpcodeHandler for OpReturnHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, offset) = size_offset_to_usize(len, offset)?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::exit_opcode(
                calculate_memory_size(offset, len)?,
                vm.current_call_frame.memory.len(),
            )?)?;

        if len != 0 {
            vm.current_call_frame.output = vm.current_call_frame.memory.load_range(offset, len)?;
        }

        Ok(OpcodeResult::Halt)
    }
}

pub struct OpCreateHandler;
impl OpcodeHandler for OpCreateHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        // EIP-8037 (Amsterdam+): is_static check before stack pops and gas charging,
        // consistent with SSTORE, CALL, and SELFDESTRUCT.
        if vm.env.config.fork >= Fork::Amsterdam && vm.current_call_frame.is_static {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        let [value_in_wei, code_offset, code_len] = *vm.current_call_frame.stack.pop()?;
        let (code_len, code_offset) = size_offset_to_usize(code_len, code_offset)?;

        let create_gas = gas_cost::create(
            calculate_memory_size(code_offset, code_len)?,
            vm.current_call_frame.memory.len(),
            code_len,
            vm.env.config.fork,
        )?;
        vm.current_call_frame.increase_consumed_gas(create_gas)?;

        // Struct-log: record the opcode-level gas before generic_create charges forwarded gas.
        if vm.opcode_tracer.active {
            vm.opcode_tracer.last_opcode_gas_cost = Some(create_gas);
        }

        // EIP-8141 mempool validation-trace: contract creation is a state write
        // permitted only inside the deploy frame.
        if vm.validation_observer.active {
            vm.validation_check_create();
        }

        vm.generic_create(value_in_wei, code_offset, code_len, None)
    }
}

pub struct OpCreate2Handler;
impl OpcodeHandler for OpCreate2Handler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        // EIP-8037 (Amsterdam+): is_static check before stack pops and gas charging,
        // consistent with SSTORE, CALL, and SELFDESTRUCT.
        if vm.env.config.fork >= Fork::Amsterdam && vm.current_call_frame.is_static {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        let [value_in_wei, code_offset, code_len, salt] = *vm.current_call_frame.stack.pop()?;
        let (code_len, code_offset) = size_offset_to_usize(code_len, code_offset)?;

        let create2_gas = gas_cost::create_2(
            calculate_memory_size(code_offset, code_len)?,
            vm.current_call_frame.memory.len(),
            code_len,
            vm.env.config.fork,
        )?;
        vm.current_call_frame.increase_consumed_gas(create2_gas)?;

        // Struct-log: record the opcode-level gas before generic_create charges forwarded gas.
        if vm.opcode_tracer.active {
            vm.opcode_tracer.last_opcode_gas_cost = Some(create2_gas);
        }

        // EIP-8141 mempool validation-trace: contract creation is a state write
        // permitted only inside the deploy frame.
        if vm.validation_observer.active {
            vm.validation_check_create();
        }

        vm.generic_create(value_in_wei, code_offset, code_len, Some(salt))
    }
}

pub struct OpSelfDestructHandler;
impl OpcodeHandler for OpSelfDestructHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        if vm.current_call_frame.is_static {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        let beneficiary = word_to_address(vm.current_call_frame.stack.pop1()?);
        let to = vm.current_call_frame.to;

        let target_account_is_cold = vm.substate.add_accessed_address(beneficiary);

        // EELS (Amsterdam) checks the base cost (SELFDESTRUCT + cold access)
        // BEFORE the beneficiary/self state reads: an OOG here must not leak
        // those reads into execution witnesses (EIP-8025).
        if vm.env.config.fork >= Fork::Amsterdam {
            let base_cost =
                gas_cost::selfdestruct_base(target_account_is_cold, vm.env.config.fork)?;
            // Phase 1: Check base cost is available (without charging)
            #[expect(clippy::as_conversions, reason = "base_cost fits in i64")]
            if vm.current_call_frame.gas_remaining < (base_cost as i64) {
                return Err(ExceptionalHalt::OutOfGas.into());
            }
        }

        let target_account_is_empty = vm.db.get_account(beneficiary)?.is_empty();
        let balance = vm.db.get_account(to)?.info.balance;

        // EIP-7928 (Amsterdam): Two-phase gas check for SELFDESTRUCT.
        // Base cost was checked above before state access; now record BAL
        // tracking, then charge the full cost including NEW_ACCOUNT. This
        // ensures the beneficiary is recorded in BAL even when the full
        // selfdestruct cost (with NEW_ACCOUNT) would cause OOG.
        if vm.env.config.fork >= Fork::Amsterdam {
            // State access: record BAL tracking between the two gas phases.
            // Only the touched addresses (and initial balance) are recorded
            // here; storage slots are NOT. Per EIP-7928 the BAL records a slot
            // read only on an actual `get_storage` access (spec state_tracker
            // `get_storage`), which ethrex already captures on SLOAD/SSTORE via
            // `record_storage_slot_to_bal`. Recording the whole warm access set
            // here would inject prewarmed-but-unread (EIP-2930) slots as reads,
            // diverging the block_access_list_hash from conformant clients.
            if let Some(recorder) = vm.db.bal_recorder.as_mut() {
                recorder.record_touched_address(beneficiary);
                recorder.record_touched_address(to);
                if balance > U256::zero() {
                    recorder.set_initial_balance(to, balance);
                }
            }

            // Phase 2: Charge the full cost (base only for Amsterdam+; NEW_ACCOUNT moved to state gas)
            vm.current_call_frame
                .increase_consumed_gas(gas_cost::selfdestruct(
                    target_account_is_cold,
                    target_account_is_empty,
                    balance,
                    vm.env.config.fork,
                )?)?;

            // EIP-8037 (Amsterdam+): charge state gas for new account creation via SELFDESTRUCT
            if target_account_is_empty && balance > U256::zero() {
                vm.increase_state_gas(vm.state_gas_new_account)?;
            }
        } else {
            vm.current_call_frame
                .increase_consumed_gas(gas_cost::selfdestruct(
                    target_account_is_cold,
                    target_account_is_empty,
                    balance,
                    vm.env.config.fork,
                )?)?;

            // Record beneficiary and destroyed account for BAL per EIP-7928.
            // Storage slots are intentionally not recorded here (see the
            // Amsterdam branch above): reads are captured on actual SLOAD/SSTORE
            // access, never from the warm access-list set.
            if let Some(recorder) = vm.db.bal_recorder.as_mut() {
                recorder.record_touched_address(beneficiary);
                recorder.record_touched_address(to);
                if balance > U256::zero() {
                    recorder.set_initial_balance(to, balance);
                }
            }
        }

        // [EIP-6780] - SELFDESTRUCT only in same transaction from CANCUN
        if vm.env.config.fork >= Fork::Cancun {
            // [EIP-8246] (Amsterdam+): a selfdestruct-to-self moves no ETH (balance is
            // preserved at finalization). Skip the self-transfer so it doesn't fire
            // spurious BAL balance events that overwrite the recorded initial balance.
            // For `to != beneficiary` the transfer still runs (balance moves out).
            if !(vm.env.config.fork >= Fork::Amsterdam && to == beneficiary) {
                vm.transfer(to, beneficiary, balance)?;
            }

            // Selfdestruct is executed in the same transaction as the contract was created
            if vm.substate.is_account_created(&to) {
                // [EIP-8246] (Amsterdam+): balance is NOT burned; nonce/code/storage are cleared
                // at finalization while balance is preserved. Pre-Amsterdam (EIP-6780): Ether is
                // burned when to == beneficiary.
                if vm.env.config.fork < Fork::Amsterdam {
                    vm.get_account_mut(to)?.info.balance = U256::zero();

                    // Record balance change to zero for destroyed account in BAL
                    if let Some(recorder) = vm.db.bal_recorder.as_mut() {
                        recorder.record_balance_change(to, U256::zero());
                    }
                }

                vm.substate.add_selfdestruct(to);
            }

            // EIP-7708 / traceTransfers: emit appropriate log for ETH movement.
            // EIP-8246 (Amsterdam+): no burn log for same-tx selfdestruct-to-self; no ETH
            // burned, and no consensus log for to == beneficiary (trace mode includes it).
            if let Some(log_address) = vm.eth_transfer_log_address(to, beneficiary, balance) {
                let log = create_eth_transfer_log(log_address, to, beneficiary, balance);
                vm.substate.add_log(log);
                // No burn log under EIP-8246: selfdestruct-to-self preserves balance.
            }
        } else {
            vm.increase_account_balance(beneficiary, balance)?;
            vm.get_account_mut(to)?.info.balance = U256::zero();

            // Record balance change to zero for destroyed account in BAL
            if let Some(recorder) = vm.db.bal_recorder.as_mut() {
                recorder.record_balance_change(to, U256::zero());
            }

            vm.substate.add_selfdestruct(to);

            // traceTransfers: pre-Cancun selfdestructs move the balance too.
            if let Some(log_address) = vm.eth_transfer_log_address(to, beneficiary, balance) {
                let log = create_eth_transfer_log(log_address, to, beneficiary, balance);
                vm.substate.add_log(log);
            }
        }

        vm.tracer.enter(
            CallType::SELFDESTRUCT,
            vm.current_call_frame.to,
            beneficiary,
            balance,
            0,
            &Default::default(),
        );
        vm.tracer.exit_early(0, None)?;

        Ok(OpcodeResult::Halt)
    }
}

pub struct OpRevertHandler;
impl OpcodeHandler for OpRevertHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, offset) = size_offset_to_usize(len, offset)?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::exit_opcode(
                calculate_memory_size(offset, len)?,
                vm.current_call_frame.memory.len(),
            )?)?;

        if len != 0 {
            vm.current_call_frame.output = vm.current_call_frame.memory.load_range(offset, len)?;
        }

        Err(VMError::RevertOpcode)
    }
}

impl<'a> VM<'a> {
    /// Common behavior for CREATE and CREATE2 opcodes
    pub fn generic_create(
        &mut self,
        value: U256,
        code_offset_in_memory: usize,
        code_size_in_memory: usize,
        salt: Option<U256>,
    ) -> Result<OpcodeResult, VMError> {
        // [EIP-3860] / [EIP-7954] - Cant exceed init code max size
        let init_code_max = if self.env.config.fork >= Fork::Amsterdam {
            AMSTERDAM_INIT_CODE_MAX_SIZE
        } else {
            INIT_CODE_MAX_SIZE
        };
        if code_size_in_memory > init_code_max && self.env.config.fork >= Fork::Shanghai {
            return Err(ExceptionalHalt::OutOfGas.into());
        }

        let current_call_frame = &mut self.current_call_frame;

        // Pre-Amsterdam: is_static check happens here, before gas reservation
        if self.env.config.fork < Fork::Amsterdam && current_call_frame.is_static {
            return Err(ExceptionalHalt::OpcodeNotAllowedInStaticContext.into());
        }

        // Clear callframe subreturn data
        current_call_frame.sub_return_data = Bytes::new();

        // Load code from memory
        let code = self
            .current_call_frame
            .memory
            .load_range(code_offset_in_memory, code_size_in_memory)?;

        // Get account info of deployer
        let deployer = self.current_call_frame.to;
        let (deployer_balance, deployer_nonce) = {
            let deployer_account = self.db.get_account(deployer)?;
            (deployer_account.info.balance, deployer_account.info.nonce)
        };

        // Calculate create address
        let new_address = match salt {
            Some(salt) => calculate_create2_address(deployer, &code, salt)?,
            None => calculate_create_address(deployer, deployer_nonce),
        };

        let call_type = match salt {
            Some(_) => CallType::CREATE2,
            None => CallType::CREATE,
        };

        let new_depth = self
            .current_call_frame
            .depth
            .checked_add(1)
            .ok_or(InternalError::Overflow)?;

        // Validations that push 0 (FAIL) to the stack. Per EELS `generic_create`
        // these run BEFORE the target address is accessed
        // (`accessed_addresses.add` / `is_account_alive`) and BEFORE the
        // NEW_ACCOUNT state-gas charge, so no account is touched and no gas is
        // reserved or charged on this early exit (EELS `push(0); return`).
        // 1. Sender doesn't have enough balance to send value.
        // 2. Depth limit has been reached
        // 3. Sender nonce is max.
        let checks = [
            (deployer_balance < value, "OutOfFund"),
            (new_depth > 1024, "MaxDepth"),
            (deployer_nonce == u64::MAX, "MaxNonce"),
        ];
        for (condition, reason) in checks {
            if condition {
                // Child gas preview for the tracer only; no gas is reserved on this
                // path (mirrors EELS `push(0); return`).
                let preview_gas = gas_cost::max_message_call_gas(&self.current_call_frame)?;
                self.tracer
                    .enter(call_type, deployer, new_address, value, preview_gas, &code);
                self.current_call_frame.stack.push(FAIL)?;
                self.tracer.exit_early(0, Some(reason.to_string()))?;
                return Ok(OpcodeResult::Continue);
            }
        }

        // Add new contract to accessed addresses (after early checks pass, per reference)
        self.substate.add_accessed_address(new_address);

        // Record address touch for BAL (after early checks pass per EIP-7928 reference).
        // EELS records the target via `is_account_alive(contract_address)` in
        // `generic_create` BEFORE charging the NEW_ACCOUNT state gas, so the target
        // stays listed as accessed in the BAL even when the state-gas charge OOGs.
        if let Some(recorder) = self.db.bal_recorder.as_mut() {
            recorder.record_touched_address(new_address);
        }

        // EIP-8037 (#3002): read the create target BEFORE charging, mirroring EELS
        // `generic_create` `new_account_charged = not is_account_alive(contract_address)`
        // (evaluated just before `charge_state_gas`). Reading it here also records the
        // target access into `accessed_accounts` for the BAL pure-access checklist.
        // `is_account_alive` == exists && non-empty; a nonexistent target reads as an
        // empty account, so `!is_empty()` is exactly `is_account_alive`.
        let target_alive = !self.get_account_mut(new_address)?.is_empty();

        // EIP-8037 (Amsterdam+): charge the NEW_ACCOUNT state gas only when the
        // target leaf does not yet exist (`new_account_charged = !target_alive`).
        // Charging conditionally — rather than the previous charge-then-refund —
        // keeps `gas_left` untouched for an alive/colliding target, so the child-gas
        // split below matches EELS on a spilling reservoir (EELS never charges, hence
        // never spills, for an alive target). The charge follows the target read and
        // the BAL record, so an OOG here still leaves the target in the access set,
        // and — since it precedes the child-gas reservation below — its spill into
        // `gas_left` is reflected by `max_message_call_gas`.
        if self.env.config.fork >= Fork::Amsterdam && !target_alive {
            self.increase_state_gas(self.state_gas_new_account)?;
        }

        // Reserve gas for subcall (EELS `max_message_call_gas` after `charge_state_gas`).
        let gas_limit = gas_cost::max_message_call_gas(&self.current_call_frame)?;
        self.current_call_frame.increase_consumed_gas(gas_limit)?;

        // Log CREATE in tracer (success path) with the reserved child gas.
        self.tracer
            .enter(call_type, deployer, new_address, value, gas_limit, &code);

        // Increment sender nonce (irreversible change)
        self.increment_account_nonce(deployer)?;

        // Deployment will fail (consuming all gas) if the contract already exists.
        let new_account = self.get_account_mut(new_address)?;
        if new_account.create_would_collide() {
            // Per EELS: on collision, regular gas stays consumed (not returned).
            // The NEW_ACCOUNT state gas is refunded only if it was charged (target
            // not alive) — EELS `if new_account_charged: credit_state_gas_refund`.
            if self.env.config.fork >= Fork::Amsterdam && !target_alive {
                self.credit_state_gas_refund(self.state_gas_new_account)?;
            }
            self.current_call_frame.stack.push(FAIL)?;
            self.tracer
                .exit_early(gas_limit, Some("CreateAccExists".to_string()))?;
            return Ok(OpcodeResult::Continue);
        }

        // Create BAL checkpoint before entering create call for potential revert per EIP-7928
        let bal_checkpoint = self.db.bal_recorder.as_ref().map(|r| r.checkpoint());

        let mut stack = self.stack_pool.pop().unwrap_or_default();
        stack.clear();

        let next_memory = self.current_call_frame.memory.next_memory();

        let mut new_call_frame = CallFrame::new(
            deployer,
            new_address,
            new_address,
            // SAFETY: init code hash is never used
            Code::from_bytecode_unchecked(code, H256::zero()),
            value,
            Bytes::new(),
            false,
            gas_limit,
            new_depth,
            true,
            true,
            0,
            0,
            stack,
            next_memory,
        );
        // Store BAL checkpoint in the call frame's backup for restoration on revert
        new_call_frame.call_frame_backup.bal_checkpoint = bal_checkpoint;
        // Snapshot AFTER the CREATE account state-gas charge has landed in
        // `vm.state_gas_used`, so the revert restore in `handle_return_create`
        // keeps the parent's pre-CREATE intrinsic without re-refunding it.
        new_call_frame.state_gas_used_at_entry = self.state_gas_used;
        // EIP-8037 (#3002): thread the pre-mutation target-alive flag to the
        // success arm of `handle_return_create`.
        new_call_frame.target_alive = target_alive;

        self.add_callframe(new_call_frame);

        // Changes that revert in case the Create fails.
        self.increment_account_nonce(new_address)?; // 0 -> 1
        self.transfer(deployer, new_address, value)?;

        self.substate.push_backup();
        self.substate.add_created_account(new_address); // Mostly for SELFDESTRUCT during initcode.

        // EIP-7708 / traceTransfers: emit transfer log for nonzero-value CREATE/CREATE2
        // Must be after push_backup() so the log reverts if the child context reverts
        if let Some(log_address) = self.eth_transfer_log_address(deployer, new_address, value) {
            let log = create_eth_transfer_log(log_address, deployer, new_address, value);
            self.substate.add_log(log);
        }

        Ok(OpcodeResult::Continue)
    }

    /// Static gas prelude for CALL/CALLCODE/DELEGATECALL/STATICCALL: compute
    /// `(new_memory_size, address_was_cold, static_cost)` and `check_gas` it
    /// before any state read, mirroring EELS' `# check static gas before state
    /// access`. `value_cost` is the per-opcode positive-value cost (0 when
    /// none).
    fn check_call_static_gas(
        &mut self,
        args_offset: usize,
        args_len: usize,
        return_offset: usize,
        return_len: usize,
        address: Address,
        value_cost: u64,
    ) -> Result<(usize, bool, u64), VMError> {
        let new_memory_size = calculate_memory_size(args_offset, args_len)?
            .max(calculate_memory_size(return_offset, return_len)?);
        let address_was_cold = !self.substate.is_address_accessed(&address);
        let memory_expansion_cost =
            memory::expansion_cost(new_memory_size, self.current_call_frame.memory.len())?;
        let access_gas_cost = if address_was_cold {
            gas_cost::cold_account_access_cost(self.env.config.fork)
        } else {
            gas_cost::WARM_ADDRESS_ACCESS_COST
        };
        let static_cost = memory_expansion_cost
            .checked_add(access_gas_cost)
            .ok_or(ExceptionalHalt::OutOfGas)?
            .checked_add(value_cost)
            .ok_or(ExceptionalHalt::OutOfGas)?;
        self.current_call_frame.check_gas(static_cost)?;
        Ok((new_memory_size, address_was_cold, static_cost))
    }

    /// Record BAL touched addresses for CALL-family opcodes per EIP-7928.
    /// Gated on intermediate gas checks matching the EELS reference.
    #[expect(
        clippy::too_many_arguments,
        reason = "matches EIP-7928 EELS reference parameters"
    )]
    fn record_bal_call_touch(
        &mut self,
        target: Address,
        code_address: Address,
        is_delegation_7702: bool,
        eip7702_gas_consumed: u64,
        new_memory_size: usize,
        current_memory_size: usize,
        address_was_cold: bool,
        value_cost: u64,
        create_cost: u64,
    ) {
        let Some(recorder) = self.db.bal_recorder.as_mut() else {
            return;
        };
        // Safe: expansion_cost only fails on usize→u64 overflow, which is infallible
        // (usize ≤ 64 bits). If it somehow did, u64::MAX makes the gas check fail
        // conservatively, skipping the BAL touch — a non-consensus recording path.
        let mem_cost =
            memory::expansion_cost(new_memory_size, current_memory_size).unwrap_or(u64::MAX);
        let access_cost = if address_was_cold {
            gas_cost::cold_account_access_cost(self.env.config.fork)
        } else {
            gas_cost::WARM_ADDRESS_ACCESS_COST
        };
        let basic_cost = mem_cost
            .saturating_add(access_cost)
            .saturating_add(value_cost);
        let gas_remaining = self.current_call_frame.gas_remaining;

        if gas_remaining >= i64::try_from(basic_cost).unwrap_or(i64::MAX) {
            recorder.record_touched_address(target);

            if is_delegation_7702 {
                let delegation_check = basic_cost
                    .saturating_add(create_cost)
                    .saturating_add(eip7702_gas_consumed);
                if gas_remaining >= i64::try_from(delegation_check).unwrap_or(i64::MAX) {
                    recorder.record_touched_address(code_address);
                }
            }
        }
    }

    /// This (should) be the only function where gas is used as a
    /// U256. This is because we have to use the values that are
    /// pushed to the stack.
    ///
    // Force inline, due to lot of arguments, inlining must be forced, and it is actually beneficial
    // because passing so much data is costly. Verified with samply.
    #[expect(
        clippy::too_many_arguments,
        reason = "inlined for performance, many args needed"
    )]
    #[inline(always)]
    pub fn generic_call(
        &mut self,
        gas_limit: u64,
        value: U256,
        msg_sender: Address,
        to: Address,
        code_address: Address,
        should_transfer_value: bool,
        is_static: bool,
        calldata: Bytes,
        ret_offset: usize,
        ret_size: usize,
        bytecode: Code,
        is_delegation_7702: bool,
        new_account_charged: bool,
    ) -> Result<OpcodeResult, VMError> {
        // Clear callframe subreturn data
        self.current_call_frame.sub_return_data.clear();

        // Validate sender has enough value
        if should_transfer_value && !value.is_zero() {
            let sender_balance = self.db.get_account(msg_sender)?.info.balance;
            if sender_balance < value {
                // EIP-8037: no account is created, refund the new-account state gas.
                self.refund_new_account_state_gas(new_account_charged)?;
                self.early_revert_message_call(gas_limit, "OutOfFund".to_string())?;
                return Ok(OpcodeResult::Continue);
            }
        }

        // Validate max depth has not been reached yet.
        let new_depth = self
            .current_call_frame
            .depth
            .checked_add(1)
            .ok_or(InternalError::Overflow)?;
        if new_depth > 1024 {
            self.refund_new_account_state_gas(new_account_charged)?;
            self.early_revert_message_call(gas_limit, "MaxDepth".to_string())?;
            return Ok(OpcodeResult::Continue);
        }

        if self.address_is_precompile(&code_address) && !is_delegation_7702 {
            // Record precompile address touch for BAL per EIP-7928
            if let Some(recorder) = self.db.bal_recorder.as_mut() {
                recorder.record_touched_address(code_address);
            }

            let mut gas_remaining = gas_limit;
            let ctx_result = Self::execute_precompile(
                // Resolve a relocation destination back to the precompile it hosts.
                self.effective_precompile_address(code_address),
                &calldata,
                gas_limit,
                &mut gas_remaining,
                self.env.config.fork,
                self.db.store.precompile_cache(),
                self.crypto,
                self.stateless_validator,
            )?;

            let call_frame = &mut self.current_call_frame;

            // Return gas left from subcontext
            #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
            if ctx_result.is_success() {
                call_frame.gas_remaining = (call_frame.gas_remaining as u64)
                    .checked_add(
                        gas_limit
                            .checked_sub(ctx_result.gas_used)
                            .ok_or(InternalError::Underflow)?,
                    )
                    .ok_or(InternalError::Overflow)?
                    as i64;
            }

            // Store return data of sub-context
            call_frame.memory.store_data(
                ret_offset,
                if ctx_result.output.len() >= ret_size {
                    ctx_result
                        .output
                        .get(..ret_size)
                        .ok_or(ExceptionalHalt::OutOfBounds)?
                } else {
                    &ctx_result.output
                },
            )?;
            call_frame.sub_return_data = ctx_result.output.clone();

            // What to do, depending on TxResult
            call_frame.stack.push(match &ctx_result.result {
                TxResult::Success => SUCCESS,
                TxResult::Revert(_) => FAIL,
            })?;

            // EIP-8037: a failed precompile call transfers no value, so no account is
            // created — refund the new-account state gas (EELS `generic_call`
            // `credit_state_gas_refund(NEW_ACCOUNT)` on child error).
            self.refund_new_account_state_gas(new_account_charged && !ctx_result.is_success())?;

            // Transfer value from caller to callee.
            if should_transfer_value && ctx_result.is_success() {
                self.transfer(msg_sender, to, value)?;

                // EIP-7708 / traceTransfers: emit transfer log for nonzero-value CALL.
                // Consensus logs exclude all self-transfers (which covers CALLCODE, where
                // to == msg_sender); trace mode includes CALL-to-self but still excludes
                // CALLCODE since its value never leaves the caller's account.
                let is_callcode = to == msg_sender && code_address != to && !is_delegation_7702;
                if !is_callcode
                    && let Some(log_address) = self.eth_transfer_log_address(msg_sender, to, value)
                {
                    let log = create_eth_transfer_log(log_address, msg_sender, to, value);
                    self.substate.add_log(log);
                }
            }

            self.tracer.exit_context(&ctx_result, false)?;
        } else {
            // Create BAL checkpoint before entering nested call for potential revert per EIP-7928
            let bal_checkpoint = self.db.bal_recorder.as_ref().map(|r| r.checkpoint());

            let mut stack = self.stack_pool.pop().unwrap_or_default();
            stack.clear();

            let next_memory = self.current_call_frame.memory.next_memory();

            let mut new_call_frame = CallFrame::new(
                msg_sender,
                to,
                code_address,
                bytecode,
                value,
                calldata,
                is_static,
                gas_limit,
                new_depth,
                should_transfer_value,
                false,
                ret_offset,
                ret_size,
                stack,
                next_memory,
            );
            // Store BAL checkpoint in the call frame's backup for restoration on revert
            new_call_frame.call_frame_backup.bal_checkpoint = bal_checkpoint;
            new_call_frame.state_gas_used_at_entry = self.state_gas_used;
            new_call_frame.new_account_state_gas_charged = new_account_charged;

            self.add_callframe(new_call_frame);

            // Transfer value from caller to callee.
            if should_transfer_value {
                self.transfer(msg_sender, to, value)?;
            }

            self.substate.push_backup();

            // EIP-7708 / traceTransfers: emit transfer log for nonzero-value CALL.
            // Must be after push_backup() so the log reverts if the child context reverts.
            // Consensus logs exclude all self-transfers (which covers CALLCODE, where
            // to == msg_sender); trace mode includes CALL-to-self but still excludes
            // CALLCODE since its value never leaves the caller's account.
            let is_callcode = to == msg_sender && code_address != to && !is_delegation_7702;
            if should_transfer_value
                && !is_callcode
                && let Some(log_address) = self.eth_transfer_log_address(msg_sender, to, value)
            {
                let log = create_eth_transfer_log(log_address, msg_sender, to, value);
                self.substate.add_log(log);
            }
        }

        Ok(OpcodeResult::Continue)
    }

    /// Pop backup from stack and restore substate and cache if transaction reverted.
    ///
    /// `consume_backup` lets the caller move the frame's backup out (no clone) on the
    /// revert path when nothing reads it afterward; see [`VM::restore_cache_state_consuming`].
    /// The top-level call passes `true` for normal L1 execution and `false` when a
    /// `BackupHook` is installed (L2 / stateless), since that hook reads the backup in
    /// `finalize_execution` (gated on `VM::preserve_top_level_backup`).
    pub fn handle_state_backup(
        &mut self,
        ctx_result: &ContextResult,
        consume_backup: bool,
    ) -> Result<(), VMError> {
        if ctx_result.is_success() {
            self.substate.commit_backup();
        } else {
            self.substate.revert_backup();
            if consume_backup {
                self.restore_cache_state_consuming()?;
            } else {
                self.restore_cache_state()?;
            }
        }

        Ok(())
    }

    /// Handles case in which callframe was initiated by another callframe (with CALL or CREATE family opcodes)
    ///
    /// Returns the pc increment.
    pub fn handle_return(&mut self, ctx_result: &ContextResult) -> Result<(), VMError> {
        // The frame is popped immediately below and its backup is not read again on
        // the revert path, so move it out instead of cloning.
        self.handle_state_backup(ctx_result, true)?;
        let executed_call_frame = self.pop_call_frame()?;

        // Here happens the interaction between child (executed) and parent (caller) callframe.
        if executed_call_frame.is_create {
            self.handle_return_create(executed_call_frame, ctx_result)?;
        } else {
            self.handle_return_call(executed_call_frame, ctx_result)?;
        }

        Ok(())
    }

    #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
    pub fn handle_return_call(
        &mut self,
        executed_call_frame: CallFrame,
        ctx_result: &ContextResult,
    ) -> Result<(), VMError> {
        let CallFrame {
            gas_limit,
            ret_offset,
            ret_size,
            memory: old_callframe_memory,
            frame_state_gas_spilled: child_frame_state_gas_spilled,
            call_frame_backup,
            stack,
            new_account_state_gas_charged,
            ..
        } = executed_call_frame;

        #[cfg(not(target_arch = "riscv64"))]
        old_callframe_memory.clean_from_base();

        #[cfg(target_arch = "riscv64")]
        old_callframe_memory.truncate_to_base();

        let parent_call_frame = &mut self.current_call_frame;

        // Return gas left from subcontext
        let child_unused_gas = gas_limit
            .checked_sub(ctx_result.gas_used)
            .ok_or(InternalError::Underflow)?;
        parent_call_frame.gas_remaining = parent_call_frame
            .gas_remaining
            .checked_add(child_unused_gas as i64)
            .ok_or(InternalError::Overflow)?;

        // Store return data of sub-context
        parent_call_frame.memory.store_data(
            ret_offset,
            if ctx_result.output.len() >= ret_size {
                ctx_result
                    .output
                    .get(..ret_size)
                    .ok_or(ExceptionalHalt::OutOfBounds)?
            } else {
                &ctx_result.output
            },
        )?;

        parent_call_frame.sub_return_data = ctx_result.output.clone();

        // What to do, depending on TxResult
        match &ctx_result.result {
            TxResult::Success => {
                self.current_call_frame.stack.push(SUCCESS)?;
                self.merge_call_frame_backup_with_parent(&call_frame_backup)?;
                // EIP-8037: on success, child's state_gas_used is already
                // accumulated into the VM-level field (signed sum handles refunds).
                // No pending flush needed — credits were applied inline.
                // Propagate the child's per-frame spill to the parent so a later
                // parent revert/halt refills it LIFO (EELS `incorporate_child_on_success`).
                self.current_call_frame.frame_state_gas_spilled = self
                    .current_call_frame
                    .frame_state_gas_spilled
                    .checked_add(child_frame_state_gas_spilled)
                    .ok_or(InternalError::Overflow)?;
                // EIP-8037 (execution-specs#3478): with the child's gas merged in, the
                // reservoir repays whatever spill is still outstanding in this frame —
                // EELS calls `repay_state_gas_spill` here, on the success arm only.
                if self.env.config.fork >= Fork::Amsterdam {
                    self.repay_state_gas_spill()?;
                }
            }
            TxResult::Revert(_) => {
                // EIP-8037: the child already self-refilled its execution state gas via
                // `refill_frame_state_gas` in `handle_opcode_error`. The parent-charged
                // new-account state gas (value transfer to an empty account) is separate
                // and refunded here on child failure, mirroring EELS `generic_call`
                // `credit_state_gas_refund(NEW_ACCOUNT)`.
                self.refund_new_account_state_gas(new_account_state_gas_charged)?;
                self.current_call_frame.stack.push(FAIL)?;
            }
        };

        self.tracer.exit_context(ctx_result, false)?;

        let mut stack = stack;
        stack.clear();
        self.stack_pool.push(stack);

        Ok(())
    }

    #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
    pub fn handle_return_create(
        &mut self,
        executed_call_frame: CallFrame,
        ctx_result: &ContextResult,
    ) -> Result<(), VMError> {
        let CallFrame {
            gas_limit,
            to,
            call_frame_backup,
            memory: old_callframe_memory,
            frame_state_gas_spilled: child_frame_state_gas_spilled,
            target_alive,
            stack,
            ..
        } = executed_call_frame;

        #[cfg(not(target_arch = "riscv64"))]
        old_callframe_memory.clean_from_base();

        #[cfg(target_arch = "riscv64")]
        old_callframe_memory.truncate_to_base();

        // Return unused gas
        let unused_gas = gas_limit
            .checked_sub(ctx_result.gas_used)
            .ok_or(InternalError::Underflow)?;
        self.current_call_frame.gas_remaining = self
            .current_call_frame
            .gas_remaining
            .checked_add(unused_gas as i64)
            .ok_or(InternalError::Overflow)?;

        // What to do, depending on TxResult
        match ctx_result.result.clone() {
            TxResult::Success => {
                self.current_call_frame.stack.push(address_to_word(to))?;
                self.merge_call_frame_backup_with_parent(&call_frame_backup)?;
                // EIP-8037: on success, child's state_gas_used is already
                // accumulated into the VM-level field (signed sum handles refunds).
                // No pending flush needed — credits were applied inline.
                // Propagate the child's per-frame spill to the parent so a later
                // parent revert/halt refills it LIFO (EELS `incorporate_child_on_success`).
                self.current_call_frame.frame_state_gas_spilled = self
                    .current_call_frame
                    .frame_state_gas_spilled
                    .checked_add(child_frame_state_gas_spilled)
                    .ok_or(InternalError::Overflow)?;
                // EIP-8037 (execution-specs#3478): with the child's gas merged in, the
                // reservoir repays whatever spill is still outstanding in this frame —
                // EELS calls `repay_state_gas_spill` here, on the success arm only.
                if self.env.config.fork >= Fork::Amsterdam {
                    self.repay_state_gas_spill()?;
                }
                // EIP-8037 (#3002): the parent charged the NEW_ACCOUNT state gas only
                // when the target was NOT alive (`new_account_charged = !target_alive`),
                // exactly as EELS `generic_create`. On child success EELS does not
                // refund it (`incorporate_child_on_success` keeps the charge — a new
                // account leaf was created), and when the target was alive nothing was
                // charged, so there is nothing to refund here in either case.
            }
            TxResult::Revert(err) => {
                // EIP-8037: the child already self-refilled its state gas via
                // `refill_frame_state_gas` in `handle_opcode_error`, so no parent-side
                // state-gas reabsorption is needed here.

                // EIP-8037: CREATE's account state gas was charged in the parent
                // before the child frame began ONLY when the target was not alive
                // (`new_account_charged = !target_alive`). On child error EELS refunds
                // it only in that case: `if new_account_charged: credit_state_gas_refund`.
                if self.env.config.fork >= Fork::Amsterdam && !target_alive {
                    self.credit_state_gas_refund(self.state_gas_new_account)?;
                }

                // Return data is only propagated on REVERT opcode, not on ExceptionalHalt.
                if err.is_revert_opcode() {
                    self.current_call_frame.sub_return_data = ctx_result.output.clone();
                }

                self.current_call_frame.stack.push(FAIL)?;
            }
        };

        self.tracer.exit_context(ctx_result, false)?;

        let mut stack = stack;
        stack.clear();
        self.stack_pool.push(stack);

        Ok(())
    }

    fn get_calldata(&mut self, offset: usize, size: usize) -> Result<Bytes, VMError> {
        self.current_call_frame.memory.load_range(offset, size)
    }

    #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
    fn early_revert_message_call(&mut self, gas_limit: u64, reason: String) -> Result<(), VMError> {
        let callframe = &mut self.current_call_frame;

        // Return gas_limit to callframe.
        callframe.gas_remaining = callframe
            .gas_remaining
            .checked_add(gas_limit as i64)
            .ok_or(InternalError::Overflow)?;
        callframe.stack.push(FAIL)?; // It's the same as revert for CREATE

        self.tracer.exit_early(0, Some(reason))?;
        Ok(())
    }
}
