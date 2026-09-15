use crate::{
    report::{EFTestReport, EFTestReportForkResult, TestVector},
    runner::{EFTestRunnerError, InternalError},
    types::{EFTest, TransactionExpectedException},
    utils::{self, effective_gas_price},
};
use ethrex_common::utils::keccak;
use ethrex_common::{
    H256, U256,
    types::{
        AccountUpdate, EIP1559Transaction, EIP7702Transaction, Fork, Transaction, TxKind,
        tx_fields::*,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    EVMConfig, Environment,
    db::gen_db::GeneralizedDatabase,
    errors::{ExecutionReport, TxValidationError, VMError},
    tracing::LevmCallTracer,
    utils::get_base_fee_per_blob_gas,
    vm::{VM, VMType},
};
use ethrex_rlp::encode::RLPEncode;
use ethrex_vm::backends;

pub async fn run_ef_test(test: &EFTest) -> Result<EFTestReport, EFTestRunnerError> {
    // There are some tests that don't have a hash, unwrap will panic
    let hash = test
        ._info
        .generated_test_hash
        .or(test._info.hash)
        .unwrap_or_default();

    let mut ef_test_report = EFTestReport::new(
        test.name.clone(),
        test.dir.clone(),
        test._info.clone(),
        hash,
    );

    for fork in test.post.forks.keys() {
        let mut ef_test_report_fork = EFTestReportForkResult::new();

        for (vector, _tx) in test.transactions.iter() {
            // This is because there are some test vectors that are not valid for the current fork.
            if !test.post.has_vector_for_fork(vector, *fork) {
                continue;
            }
            match run_ef_test_tx(vector, test, fork).await {
                Ok(_) => continue,
                Err(EFTestRunnerError::VMInitializationFailed(reason)) => {
                    ef_test_report_fork.register_vm_initialization_failure(reason, *vector);
                }
                Err(EFTestRunnerError::FailedToEnsurePreState(reason)) => {
                    ef_test_report_fork.register_pre_state_validation_failure(reason, *vector);
                }
                Err(EFTestRunnerError::ExecutionFailedUnexpectedly(error)) => {
                    ef_test_report_fork.register_unexpected_execution_failure(error, *vector);
                }
                Err(EFTestRunnerError::FailedToEnsurePostState(
                    transaction_report,
                    reason,
                    levm_cache,
                )) => {
                    ef_test_report_fork.register_post_state_validation_failure(
                        *transaction_report,
                        reason,
                        *vector,
                        levm_cache,
                    );
                }
                Err(EFTestRunnerError::VMExecutionMismatch(_)) => {
                    return Err(EFTestRunnerError::Internal(InternalError::FirstRunInternal(
                        format!("VM execution mismatch errors should only happen when running with revm. This failed during levm's execution. LEVM runner {}",line!())
                            .to_owned(),
                    )));
                }
                Err(EFTestRunnerError::ExpectedExceptionDoesNotMatchReceived(reason)) => {
                    ef_test_report_fork
                        .register_post_state_validation_error_mismatch(reason, *vector);
                }
                Err(EFTestRunnerError::FailedToRevertLEVMState(reason)) => {
                    ef_test_report_fork.register_error_on_reverting_levm_state(reason, *vector);
                }
                Err(EFTestRunnerError::Internal(reason)) => {
                    return Err(EFTestRunnerError::Internal(reason));
                }
                Err(EFTestRunnerError::EIP7702ShouldNotBeCreateType) => {
                    return Err(EFTestRunnerError::Internal(InternalError::Custom(
                        format!("This case should not happen. LEVM Runner {}.", line!()).to_owned(),
                    )));
                }
                Err(EFTestRunnerError::TestsFailed) => {
                    unreachable!(
                        "An EFTestRunnerError::TestsFailed can't happen at this point. This error is only thrown in run_ef_tests under the summary flag. LEVM Runner {}.",
                        line!()
                    )
                }
            }
        }
        ef_test_report.register_fork_result(*fork, ef_test_report_fork);
    }
    Ok(ef_test_report)
}

pub async fn run_ef_test_tx(
    vector: &TestVector,
    test: &EFTest,
    fork: &Fork,
) -> Result<(), EFTestRunnerError> {
    let test_tx = test
        .transactions
        .get(vector)
        .ok_or(EFTestRunnerError::Internal(
            InternalError::FirstRunInternal(format!(
                "Failed to get transaction in run_ef_test_tx(). LEVM runner, line: {}.",
                line!()
            )),
        ))?;

    // Some transaction-validation failures are encoded only in the signed `post[].txbytes` and
    // cannot be reconstructed from the `transaction` fields: an invalid signature (no `secretKey`,
    // since no key produces a bad one) or a wrong chain id (the `transaction` object has no
    // `chainId`). The VM receives the sender/chain pre-resolved, so we validate those directly
    // from the signed bytes instead of executing.
    let expected = test
        .post
        .vector_post_value(vector, *fork)
        .expect_exception
        .unwrap_or_default();
    let needs_txbytes_validation = test_tx.secret_key.is_none()
        || expected.iter().any(|e| {
            matches!(
                e,
                TransactionExpectedException::InvalidSignatureVrs
                    | TransactionExpectedException::InvalidChainId
            )
        });
    if needs_txbytes_validation {
        return validate_from_txbytes(vector, test, fork);
    }

    let mut db = utils::load_initial_state_levm(test).await;
    // Build the tx first so it outlives the VM (the VM borrows it). The Type-4-create edge case
    // is detected here, before the VM exists, just as it was inside the old `prepare_vm_for_tx`.
    let levm_execution_result = match build_tx_for_vector(vector, test) {
        Err(EFTestRunnerError::EIP7702ShouldNotBeCreateType) => Err(VMError::TxValidation(
            TxValidationError::Type4TxContractCreation,
        )),
        Err(error) => return Err(error),
        Ok(tx) => match prepare_vm_for_tx(&tx, vector, test, fork, &mut db) {
            Err(error) => return Err(error),
            Ok(mut levm) => {
                ensure_pre_state(&levm, test)?;
                levm.execute()
            }
        },
    };

    ensure_post_state(&levm_execution_result, vector, test, fork, &mut db).await?;
    Ok(())
}

/// Validates a transaction whose invalidity lives only in the signed `post[].txbytes` —
/// a bad signature (`INVALID_SIGNATURE_VRS`) or a wrong chain id (`INVALID_CHAINID`). The tx is
/// decoded and checked directly: `Transaction::sender` enforces the EIP-2 low-s rule and r/s
/// range checks, and `chain_id()` is compared against the network id (1). A detected fault that
/// matches the fixture's expected exception is a pass.
fn validate_from_txbytes(
    vector: &TestVector,
    test: &EFTest,
    fork: &Fork,
) -> Result<(), EFTestRunnerError> {
    let post = test.post.vector_post_value(vector, *fork);
    let expected = post.expect_exception.unwrap_or_default();

    // Detect why the signed transaction is invalid. An undecodable payload counts as a bad
    // signature/encoding (its malformed fields can't be recovered).
    let (signature_bad, chain_id_bad) = match Transaction::decode_canonical(&post.txbytes) {
        Err(_) => (true, false),
        Ok(tx) => (
            tx.sender(&NativeCrypto).is_err(),
            tx.chain_id().is_some_and(|chain_id| chain_id != 1),
        ),
    };

    let matched = expected.iter().any(|e| match e {
        TransactionExpectedException::InvalidSignatureVrs => signature_bad,
        TransactionExpectedException::InvalidChainId => chain_id_bad,
        TransactionExpectedException::Other => signature_bad || chain_id_bad,
        _ => false,
    });

    if matched {
        Ok(())
    } else {
        Err(EFTestRunnerError::ExpectedExceptionDoesNotMatchReceived(
            format!(
                "txbytes validation found no matching fault (signature_bad={signature_bad}, chain_id_bad={chain_id_bad}); expected {expected:?}"
            ),
        ))
    }
}

/// Builds the concrete `Transaction` for a test vector. Split out from `prepare_vm_for_tx` so the
/// caller owns it for the VM's lifetime (`VM` borrows `&'a Transaction` rather than cloning).
pub fn build_tx_for_vector(
    vector: &TestVector,
    test: &EFTest,
) -> Result<Transaction, EFTestRunnerError> {
    let test_tx = test
        .transactions
        .get(vector)
        .ok_or(EFTestRunnerError::Internal(
            InternalError::FirstRunInternal(
                format!(
                    "Failed to get transaction in build_tx_for_vector(). LEVM runner, line: {}.",
                    line!()
                )
                .to_owned(),
            ),
        ))?;

    let access_list = test_tx
        .access_list
        .iter()
        .map(|arg| (arg.address, arg.storage_keys.clone()))
        .collect();

    // Check if the tx has the authorization_lists field implemented by eip7702.
    let authorization_list = test_tx.authorization_list.clone().map(|list| {
        list.iter()
            .map(|auth_tuple| AuthorizationTuple {
                chain_id: auth_tuple.chain_id,
                address: auth_tuple.address,
                nonce: auth_tuple.nonce,
                y_parity: auth_tuple.v,
                r_signature: auth_tuple.r,
                s_signature: auth_tuple.s,
            })
            .collect::<Vec<AuthorizationTuple>>()
    });

    let tx = match authorization_list {
        Some(list) => Transaction::EIP7702Transaction(EIP7702Transaction {
            to: match test_tx.to {
                TxKind::Call(to) => to,
                TxKind::Create => return Err(EFTestRunnerError::EIP7702ShouldNotBeCreateType),
            },
            value: test_tx.value,
            data: test_tx.data.clone(),
            access_list,
            authorization_list: list,
            gas_limit: test_tx.gas_limit,
            ..Default::default()
        }),
        None => Transaction::EIP1559Transaction(EIP1559Transaction {
            to: test_tx.to.clone(),
            value: test_tx.value,
            data: test_tx.data.clone(),
            access_list,
            gas_limit: test_tx.gas_limit,
            ..Default::default()
        }),
    };
    Ok(tx)
}

pub fn prepare_vm_for_tx<'a>(
    tx: &'a Transaction,
    vector: &TestVector,
    test: &EFTest,
    fork: &Fork,
    db: &'a mut GeneralizedDatabase,
) -> Result<VM<'a>, EFTestRunnerError> {
    let test_tx = test
        .transactions
        .get(vector)
        .ok_or(EFTestRunnerError::Internal(
            InternalError::FirstRunInternal(
                format!(
                    "Failed to get transaction in prepare_vm_for_tx(). LEVM runner, line: {}.",
                    line!()
                )
                .to_owned(),
            ),
        ))?;

    let blob_schedule = EVMConfig::canonical_values(*fork);
    let config = EVMConfig::new(*fork, blob_schedule);

    let base_blob_fee_per_gas = get_base_fee_per_blob_gas(
        test.env
            .current_excess_blob_gas
            .map(|x| x.try_into().unwrap()),
        &config,
    )
    .map_err(|e| {
        EFTestRunnerError::FailedToEnsurePreState(format!("Failed to calculate base blob fee: {e}"))
    })?;

    VM::new(
        Environment {
            origin: test_tx.sender,
            gas_limit: test_tx.gas_limit,
            config,
            block_number: test.env.current_number.try_into().unwrap(),
            coinbase: test.env.current_coinbase,
            timestamp: test.env.current_timestamp.try_into().unwrap(),
            prev_randao: test.env.current_random,
            difficulty: test.env.current_difficulty,
            slot_number: test.env.slot_number.unwrap_or_default(),
            chain_id: U256::from(1),
            base_fee_per_gas: test.env.current_base_fee.unwrap_or_default(),
            base_blob_fee_per_gas,
            gas_price: effective_gas_price(test, &test_tx)?,
            block_excess_blob_gas: test
                .env
                .current_excess_blob_gas
                .map(|x| x.try_into().unwrap()),
            block_blob_gas_used: None,
            tx_blob_hashes: test_tx.blob_versioned_hashes.clone(),
            tx_max_priority_fee_per_gas: test_tx.max_priority_fee_per_gas,
            tx_max_fee_per_gas: test_tx.max_fee_per_gas,
            tx_max_fee_per_blob_gas: test_tx.max_fee_per_blob_gas,
            tx_nonce: test_tx.nonce,
            block_gas_limit: test.env.current_gas_limit,
            is_privileged: false,
            fee_token: None,
            disable_balance_check: false,
            disable_nonce_check: false,
            trace_eth_transfers: false,
            disable_gas_allowance_check: false,
            disable_sender_eoa_check: false,
            is_system_call: false,
        },
        db,
        tx,
        LevmCallTracer::disabled(),
        VMType::L1, // TODO: Should we run the EF tests with L2?
        &NativeCrypto,
        None,
    )
    .map_err(|e| EFTestRunnerError::FailedToEnsurePreState(format!("Failed to initialize VM: {e}")))
}

pub fn ensure_pre_state(evm: &VM, test: &EFTest) -> Result<(), EFTestRunnerError> {
    let world_state = &evm.db.store;
    for (address, pre_value) in &test.pre.0 {
        let account_info = world_state.get_account_state(*address).map_err(|e| {
            EFTestRunnerError::Internal(InternalError::Custom(format!(
                "Failed to read account {address:#x} from world state: {e}",
            )))
        })?;
        ensure_pre_state_condition(
            account_info.nonce == pre_value.nonce,
            format!(
                "Nonce mismatch for account {address:#x}: expected {}, got {}",
                pre_value.nonce, account_info.nonce
            ),
        )?;
        ensure_pre_state_condition(
            account_info.balance == pre_value.balance,
            format!(
                "Balance mismatch for account {address:#x}: expected {}, got {}",
                pre_value.balance, account_info.balance
            ),
        )?;
        for (k, v) in &pre_value.storage {
            let storage_slot = world_state
                .get_storage_value(*address, H256::from_slice(&k.to_big_endian()))
                .unwrap();
            ensure_pre_state_condition(
                &storage_slot == v,
                format!(
                    "Storage slot mismatch for account {address:#x} at key {k:?}: expected {v}, got {storage_slot}",
                ),
            )?;
        }
        ensure_pre_state_condition(
            account_info.code_hash == keccak(pre_value.code.as_ref()),
            format!(
                "Code hash mismatch for account {address:#x}: expected {}, got {}",
                keccak(pre_value.code.as_ref()),
                account_info.code_hash
            ),
        )?;
    }
    Ok(())
}

fn ensure_pre_state_condition(
    condition: bool,
    error_reason: String,
) -> Result<(), EFTestRunnerError> {
    if !condition {
        return Err(EFTestRunnerError::FailedToEnsurePreState(error_reason));
    }
    Ok(())
}

// Exceptions not covered: RlpInvalidValue
fn exception_is_expected(
    expected_exceptions: Vec<TransactionExpectedException>,
    returned_error: VMError,
) -> bool {
    expected_exceptions.iter().any(|exception| {
        matches!(
            (exception, &returned_error),
            (
                TransactionExpectedException::IntrinsicGasTooLow,
                VMError::TxValidation(TxValidationError::IntrinsicGasTooLow)
            ) | (
                TransactionExpectedException::IntrinsicGasBelowFloorGasCost,
                VMError::TxValidation(TxValidationError::IntrinsicGasBelowFloorGasCost)
            ) | (
                // The spec raises a single InsufficientTransactionGasError for both the
                // intrinsic-gas and calldata-floor insufficiency cases (amsterdam
                // transactions.py: `Insufficient intrinsic gas` / `Insufficient calldata
                // floor`), so the TooLow vs BelowFloor distinction is finer than the spec
                // defines. Accept either spec-faithful rejection for the other's label.
                TransactionExpectedException::IntrinsicGasTooLow,
                VMError::TxValidation(TxValidationError::IntrinsicGasBelowFloorGasCost)
            ) | (
                TransactionExpectedException::IntrinsicGasBelowFloorGasCost,
                VMError::TxValidation(TxValidationError::IntrinsicGasTooLow)
            ) | (
                TransactionExpectedException::InsufficientAccountFunds,
                VMError::TxValidation(TxValidationError::InsufficientAccountFunds)
            ) | (
                TransactionExpectedException::PriorityGreaterThanMaxFeePerGas,
                VMError::TxValidation(TxValidationError::PriorityGreaterThanMaxFeePerGas {
                    priority_fee: _,
                    max_fee_per_gas: _
                })
            ) | (
                TransactionExpectedException::GasLimitPriceProductOverflow,
                VMError::TxValidation(TxValidationError::GasLimitPriceProductOverflow)
            ) | (
                TransactionExpectedException::SenderNotEoa,
                VMError::TxValidation(TxValidationError::SenderNotEOA(_))
            ) | (
                TransactionExpectedException::InsufficientMaxFeePerGas,
                VMError::TxValidation(TxValidationError::InsufficientMaxFeePerGas)
            ) | (
                TransactionExpectedException::NonceIsMax,
                VMError::TxValidation(TxValidationError::NonceIsMax)
            ) | (
                TransactionExpectedException::GasAllowanceExceeded,
                VMError::TxValidation(TxValidationError::GasAllowanceExceeded {
                    block_gas_limit: _,
                    tx_gas_limit: _
                })
            ) | (
                TransactionExpectedException::Type3TxPreFork,
                VMError::TxValidation(TxValidationError::Type3TxPreFork)
            ) | (
                TransactionExpectedException::Type3TxBlobCountExceeded,
                VMError::TxValidation(TxValidationError::Type3TxBlobCountExceeded {
                    max_blob_count: _,
                    actual_blob_count: _
                })
            ) | (
                TransactionExpectedException::Type3TxZeroBlobs,
                VMError::TxValidation(TxValidationError::Type3TxZeroBlobs)
            ) | (
                TransactionExpectedException::Type3TxContractCreation,
                VMError::TxValidation(TxValidationError::Type3TxContractCreation)
            ) | (
                TransactionExpectedException::Type3TxInvalidBlobVersionedHash,
                VMError::TxValidation(TxValidationError::Type3TxInvalidBlobVersionedHash)
            ) | (
                TransactionExpectedException::InsufficientMaxFeePerBlobGas,
                VMError::TxValidation(TxValidationError::InsufficientMaxFeePerBlobGas {
                    base_fee_per_blob_gas: _,
                    tx_max_fee_per_blob_gas: _,
                })
            ) | (
                TransactionExpectedException::InitcodeSizeExceeded,
                VMError::TxValidation(TxValidationError::InitcodeSizeExceeded {
                    max_size: _,
                    actual_size: _
                })
            ) | (
                TransactionExpectedException::Type4TxContractCreation,
                VMError::TxValidation(TxValidationError::Type4TxContractCreation)
            ) | (
                TransactionExpectedException::TxMaxGasLimitExceeded,
                VMError::TxValidation(TxValidationError::TxMaxGasLimitExceeded {
                    tx_hash: _,
                    tx_gas_limit: _
                })
            ) | (
                TransactionExpectedException::Other,
                VMError::TxValidation(_) //TODO: Decide whether to support more specific errors, I think this is enough.
            )
        )
    })
}

pub async fn ensure_post_state(
    levm_execution_result: &Result<ExecutionReport, VMError>,
    vector: &TestVector,
    test: &EFTest,
    fork: &Fork,
    db: &mut GeneralizedDatabase,
) -> Result<(), EFTestRunnerError> {
    let cache = db.current_accounts_state.clone();
    match levm_execution_result {
        Ok(execution_report) => {
            match test.post.vector_post_value(vector, *fork).expect_exception {
                // Execution result was successful but an exception was expected.
                Some(expected_exceptions) => {
                    let error_reason = format!("Expected exception: {expected_exceptions:?}");
                    return Err(EFTestRunnerError::FailedToEnsurePostState(
                        Box::new(execution_report.clone()),
                        error_reason,
                        cache.into_iter().collect(),
                    ));
                }
                // Execution result was successful and no exception was expected.
                None => {
                    let levm_account_updates = backends::levm::LEVM::get_state_transitions(db)
                        .map_err(|_| {
                            InternalError::Custom(
                                format!("Error at LEVM::get_state_transitions in ensure_post_state(). LEVM runner, line:{}",line!())
                                    .to_owned(),
                            )
                        })?;
                    let vector_post_value = test.post.vector_post_value(vector, *fork);

                    // 1. Compare the post-state root hash with the expected post-state root hash
                    if vector_post_value.hash != post_state_root(&levm_account_updates, test).await
                    {
                        return Err(EFTestRunnerError::FailedToEnsurePostState(
                            Box::new(execution_report.clone()),
                            format!("Post-state root mismatch. LEVM runner, line:{}", line!()),
                            cache.into_iter().collect(),
                        ));
                    }

                    // 2. Compare keccak of logs with test's expected logs hash.

                    // Do keccak of the RLP of logs
                    let keccak_logs = {
                        let logs = execution_report.logs.clone();
                        let mut encoded_logs = Vec::new();
                        logs.encode(&mut encoded_logs);
                        keccak(encoded_logs)
                    };

                    if keccak_logs != vector_post_value.logs {
                        return Err(EFTestRunnerError::FailedToEnsurePostState(
                            Box::new(execution_report.clone()),
                            format!("Logs mismatch. LEVM runner, line:{}", line!()),
                            cache.into_iter().collect(),
                        ));
                    }
                }
            }
        }
        Err(err) => {
            match test.post.vector_post_value(vector, *fork).expect_exception {
                // Execution result was unsuccessful and an exception was expected.
                Some(expected_exceptions) => {
                    if !exception_is_expected(expected_exceptions.clone(), err.clone()) {
                        let error_reason = format!(
                            "Returned exception {err:?} does not match expected {expected_exceptions:?}",
                        );
                        return Err(EFTestRunnerError::ExpectedExceptionDoesNotMatchReceived(
                            error_reason,
                        ));
                    }

                    let levm_account_updates = backends::levm::LEVM::get_state_transitions(db)
                        .map_err(|_| {
                            InternalError::Custom(
                                format!("Error at LEVM::get_state_transitions in ensure_post_state(). LEVM runner, line:{}", line!())
                                    .to_owned(),
                            )
                        })?;
                    let vector_post_value = test.post.vector_post_value(vector, *fork);

                    // Compare the post-state root hash with the expected post-state root hash to ensure levm state is correct (was reverted)
                    if vector_post_value.hash != post_state_root(&levm_account_updates, test).await
                    {
                        return Err(EFTestRunnerError::FailedToRevertLEVMState(format!(
                            "Failed to revert LEVM state. LEVM runner, line:{}",
                            line!()
                        )));
                    }
                }
                // Execution result was unsuccessful but no exception was expected.
                None => {
                    return Err(EFTestRunnerError::ExecutionFailedUnexpectedly(err.clone()));
                }
            }
        }
    };
    Ok(())
}

pub async fn post_state_root(account_updates: &[AccountUpdate], test: &EFTest) -> H256 {
    let (_initial_state, block_hash, store) = utils::load_initial_state_revm(test).await;
    let ret_account_updates_batch = store
        .apply_account_updates_batch(block_hash, account_updates)
        .unwrap()
        .unwrap();
    ret_account_updates_batch.state_trie_hash
}
