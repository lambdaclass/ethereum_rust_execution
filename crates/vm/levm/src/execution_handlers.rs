use crate::{
    constants::*,
    errors::{ContextResult, ExceptionalHalt, InternalError, TxResult, VMError},
    gas_cost::{CODE_DEPOSIT_COST, CODE_DEPOSIT_REGULAR_COST_PER_WORD},
    utils::create_eth_transfer_log,
    vm::VM,
};

use bytes::Bytes;
use ethrex_common::types::{Code, Fork};

impl<'a> VM<'a> {
    pub fn handle_precompile_result(
        precompile_result: Result<Bytes, VMError>,
        gas_limit: u64,
        gas_remaining: u64,
    ) -> Result<ContextResult, VMError> {
        match precompile_result {
            Ok(output) => {
                let gas_used = gas_limit
                    .checked_sub(gas_remaining)
                    .ok_or(InternalError::Underflow)?;
                Ok(ContextResult {
                    result: TxResult::Success,
                    gas_used,
                    gas_spent: gas_used, // Will be updated in finalize_execution
                    output,
                })
            }
            Err(error) => {
                if error.should_propagate() {
                    return Err(error);
                }

                Ok(ContextResult {
                    result: TxResult::Revert(error),
                    gas_used: gas_limit,
                    gas_spent: gas_limit, // Will be updated in finalize_execution
                    output: Bytes::new(),
                })
            }
        }
    }

    #[cold] // used in the hot path loop, called only really once.
    pub fn handle_opcode_result(&mut self) -> Result<ContextResult, VMError> {
        // On successful create check output validity
        if self.is_create()? {
            let validate_create = self.validate_contract_creation();

            if let Err(error) = validate_create {
                if error.should_propagate() {
                    return Err(error);
                }

                // EIP-8037 (Amsterdam+): roll back this frame's state gas in LIFO order
                // BEFORE zeroing gas. Mirrors EELS `process_create_message`'s
                // `refill_frame_state_gas` on the code-deposit ExceptionalHalt path.
                // Must run before the `&mut self.current_call_frame` borrow below.
                if self.env.config.fork >= Fork::Amsterdam {
                    let entry = self.current_call_frame.state_gas_used_at_entry;
                    self.refill_frame_state_gas(entry)?;
                }

                // Consume all gas because error was exceptional.
                let callframe = &mut self.current_call_frame;
                callframe.gas_remaining = 0;

                #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
                let gas_used = callframe
                    .gas_limit
                    .checked_sub(callframe.gas_remaining as u64)
                    .ok_or(InternalError::Underflow)?;
                return Ok(ContextResult {
                    result: TxResult::Revert(error),
                    gas_used,
                    gas_spent: gas_used, // Will be updated in finalize_execution
                    output: Bytes::new(),
                });
            }

            // Set bytecode to the newly created contract.
            let contract_address = self.current_call_frame.to;
            let code = self.current_call_frame.output.clone();
            self.update_account_bytecode(contract_address, Code::from_bytecode(code, self.crypto))?;
        }

        #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
        let gas_used = {
            let callframe = &mut self.current_call_frame;
            callframe
                .gas_limit
                .checked_sub(callframe.gas_remaining as u64)
                .ok_or(InternalError::Underflow)?
        };
        Ok(ContextResult {
            result: TxResult::Success,
            gas_used,
            gas_spent: gas_used, // Will be updated in finalize_execution
            output: std::mem::take(&mut self.current_call_frame.output),
        })
    }

    #[cold] // used in the hot path loop, called only really once.
    pub fn handle_opcode_error(&mut self, error: VMError) -> Result<ContextResult, VMError> {
        if error.should_propagate() {
            return Err(error);
        }

        // EIP-8037 (Amsterdam+): roll back this frame's state gas in LIFO order BEFORE
        // zeroing gas on exceptional halt. Covers both revert and exceptional-halt paths
        // (mirrors EELS `process_message`'s `refill_frame_state_gas` on Revert/ExceptionalHalt).
        // Must run before the `&mut self.current_call_frame` borrow below since refill needs `&mut self`.
        if self.env.config.fork >= Fork::Amsterdam {
            let entry = self.current_call_frame.state_gas_used_at_entry;
            self.refill_frame_state_gas(entry)?;
        }

        let callframe = &mut self.current_call_frame;

        // Unless error is caused by Revert Opcode, consume all gas left.
        if !error.is_revert_opcode() {
            callframe.gas_remaining = 0;
        }

        #[expect(clippy::as_conversions, reason = "remaining gas conversion")]
        let gas_used = callframe
            .gas_limit
            .checked_sub(callframe.gas_remaining as u64)
            .ok_or(InternalError::Underflow)?;
        Ok(ContextResult {
            result: TxResult::Revert(error),
            gas_used,
            gas_spent: gas_used, // Will be updated in finalize_execution
            output: std::mem::take(&mut callframe.output),
        })
    }

    /// Handles external create transaction.
    pub fn handle_create_transaction(&mut self) -> Result<Option<ContextResult>, VMError> {
        let new_contract_address = self.current_call_frame.to;

        // EIP-7928: Record contract address in BAL before collision check.
        // Per EELS reference, the address is tracked even when the create collides.
        if let Some(recorder) = self.db.bal_recorder.as_mut() {
            recorder.record_touched_address(new_contract_address);
        }

        let new_account = self.get_account_mut(new_contract_address)?;

        if new_account.create_would_collide() {
            // EIP-8037: `prepare_execution`'s in-region CREATE `NEW_ACCOUNT` charge
            // runs before this collision check and fires whenever the
            // target's pre-state was EMPTY_ACCOUNT — which can be true even for a
            // colliding target in the EELS-documented "highly unlikely" case of a
            // zero-nonce/zero-code/zero-balance address that nonetheless has storage
            // (`create_would_collide` also considers storage; `is_empty()` doesn't).
            //
            // Known near-unreachable divergence (code review, accepted): if the
            // reservoir/gas cannot cover that in-region NEW_ACCOUNT charge for such a
            // storage-only colliding target, ethrex takes the region-OOG path (burns all
            // gas) whereas EELS — which checks `account_deployable()` before
            // `prepare_dispatch` — never charges and preserves the reservoir. This
            // requires deriving a CREATE address that already holds storage with zero
            // nonce/code/balance AND under-funding it, which is not reachable via real
            // CREATE/CREATE2 address derivation; documented rather than guarded.
            //
            // Roll that charge back to the frame's entry baseline: EELS never runs
            // `prepare_dispatch` for a colliding create (`process_message_call`
            // short-circuits on `account_deployable() == False` before calling
            // `process_create_message`), so a collision must leave `state_gas_used`
            // (and any state-gas spill) net zero. No opcodes have run yet, so
            // `frame_used = state_gas_used - entry` is exactly this charge, if any.
            if self.env.config.fork >= Fork::Amsterdam {
                let entry = self.current_call_frame.state_gas_used_at_entry;
                self.refill_frame_state_gas(entry)?;
            }

            // Per EIP-684: a tx-level CREATE collision burns the
            // full forwarded execution gas as `regular_gas_used`. Zero `gas_remaining`
            // so `raw_consumed = gas_limit` for the downstream regular-gas formula in
            // `default_hook::refund_sender`; otherwise the post-intrinsic leftover
            // leaks back to the sender and never reaches the regular dimension.
            self.current_call_frame.gas_remaining = 0;
            return Ok(Some(ContextResult {
                result: TxResult::Revert(ExceptionalHalt::AddressAlreadyOccupied.into()),
                gas_used: self.env.gas_limit,
                gas_spent: self.env.gas_limit, // Will be updated in finalize_execution
                output: Bytes::new(),
            }));
        }

        let value = self.current_call_frame.msg_value;
        self.increase_account_balance(new_contract_address, value)?;

        // EIP-7708 / traceTransfers: emit transfer log for nonzero-value contract
        // creation transactions. Origin is sender, new_contract_address is the recipient.
        if let Some(log_address) =
            self.eth_transfer_log_address(self.env.origin, new_contract_address, value)
        {
            let log =
                create_eth_transfer_log(log_address, self.env.origin, new_contract_address, value);
            self.substate.add_log(log);
        }

        self.increment_account_nonce(new_contract_address)?;

        Ok(None)
    }

    /// Validates that the contract creation was successful, otherwise it returns an ExceptionalHalt.
    fn validate_contract_creation(&mut self) -> Result<(), VMError> {
        let fork = self.env.config.fork;
        let code = &self.current_call_frame.output;

        let code_length: u64 = code
            .len()
            .try_into()
            .map_err(|_| InternalError::TypeConversion)?;

        // 1. If the first byte of code is 0xEF
        if code.first().is_some_and(|v| v == &EOF_PREFIX) {
            return Err(ExceptionalHalt::InvalidContractPrefix.into());
        }

        // EIP-8037 (Amsterdam+): Per EELS process_create_message (bal@v5.4.0):
        // 1. Size check first (reject oversized before any gas charges)
        // 2. Keccak hash cost (regular gas)
        // 3. State gas for code deposit
        if fork >= Fork::Amsterdam {
            // Size check BEFORE gas charges
            if code_length > AMSTERDAM_MAX_CODE_SIZE {
                return Err(ExceptionalHalt::ContractOutputTooBig.into());
            }

            let words = code_length.div_ceil(32);
            let regular = words
                .checked_mul(CODE_DEPOSIT_REGULAR_COST_PER_WORD)
                .ok_or(InternalError::Overflow)?;
            let state = code_length
                .checked_mul(self.cost_per_state_byte)
                .ok_or(InternalError::Overflow)?;

            // Regular gas (keccak hash cost) before state gas
            self.current_call_frame.increase_consumed_gas(regular)?;
            if state > 0 {
                self.increase_state_gas(state)?;
            }
        } else {
            // Pre-Amsterdam: size check first, then regular gas charge
            if code_length > MAX_CODE_SIZE {
                return Err(ExceptionalHalt::ContractOutputTooBig.into());
            }
            let regular = code_length
                .checked_mul(CODE_DEPOSIT_COST)
                .ok_or(InternalError::Overflow)?;
            self.current_call_frame.increase_consumed_gas(regular)?;
        }

        Ok(())
    }
}
