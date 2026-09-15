use colored::Colorize;
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use secp256k1::SecretKey;

use ethrex_common::{
    U256,
    types::{
        EIP1559Transaction, EIP2930Transaction, EIP4844Transaction, EIP7702Transaction,
        LegacyTransaction, Transaction, TxKind,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_levm::{
    EVMConfig, Environment, tracing::LevmCallTracer, utils::get_base_fee_per_blob_gas, vm::VM,
    vm::VMType,
};

use crate::modules::{
    error::RunnerError,
    report::{add_test_to_report, ensure_reports_dir},
    result_check::{PostCheckResult, check_test_case_results},
    types::{Env, Test, TestCase, TransactionExpectedException},
    utils::{effective_gas_price, load_initial_state},
};

/// Runs all the tests that have been parsed.
pub async fn run_tests(tests: Vec<Test>) -> Result<(), RunnerError> {
    // Ensure reports directory exists
    ensure_reports_dir()?;
    let mut passing_tests = 0;
    let mut failing_tests = 0;
    let mut total_run = 0;

    //Test with the Fusaka tests that should pass. TODO: Once we've implemented all the Fusaka EIPs this should be removed
    //EIPs should be added as strings in the format 'eip-XXXX'
    let fusaka_eips_to_test: Vec<&str> =
        vec!["eip-7594", "eip-7939", "eip-7918", "eip-7892", "eip-7883"];

    for test in tests {
        // Fusaka EIP allowlist only applies when `_info.reference_spec` is
        // present. Fixtures without it (e.g. goevmlab-generated) bypass the
        // filter so they aren't silently dropped just because we can't read
        // the EIP list.
        if test.path.to_str().unwrap().contains("osaka")
            && let Some(spec) = test
                ._info
                .as_ref()
                .and_then(|info| info.reference_spec.as_deref())
            && !fusaka_eips_to_test.iter().any(|eip| spec.contains(eip))
        {
            continue;
        }
        run_test(
            &test,
            &mut passing_tests,
            &mut failing_tests,
            &mut total_run,
        )
        .await?;
    }
    Ok(())
}

/// Runs each individual test case (combination of <fork, transaction, post-state>) of a specific test.
pub async fn run_test(
    test: &Test,
    passing_tests: &mut usize,
    failing_tests: &mut usize,
    total_run: &mut usize,
) -> Result<(), RunnerError> {
    let mut failing_test_cases = Vec::new();
    for test_case in &test.test_cases {
        // Some transaction-validation failures are encoded only in the signed `post[].txbytes`
        // and cannot be reconstructed from the `transaction` fields: an invalid signature (no
        // `secretKey`, since no key produces a bad one) or a wrong chain id (the `transaction`
        // object has no `chainId`). The VM receives the sender/chain pre-resolved, so we validate
        // those directly from the signed bytes instead of executing.
        let expected = test_case
            .post
            .expected_exceptions
            .clone()
            .unwrap_or_default();
        let needs_txbytes_validation = test_case.secret_key.is_none()
            || expected.iter().any(|e| {
                matches!(
                    e,
                    TransactionExpectedException::InvalidSignatureVrs
                        | TransactionExpectedException::InvalidChainId
                )
            });
        if needs_txbytes_validation {
            let checks_result = validate_from_txbytes(test_case);
            if checks_result.passed {
                *passing_tests += 1;
            } else {
                failing_test_cases.push(checks_result);
                *failing_tests += 1;
            }
            *total_run += 1;
            continue;
        }

        // Setup VM for transaction.
        let (mut db, initial_block_hash, storage, genesis) =
            load_initial_state(test, &test_case.fork, true).await;
        let env = get_vm_env_for_test(test.env, test_case)?;
        let tx = get_tx_from_test_case(test_case).await?;
        let tracer = LevmCallTracer::disabled();
        let mut vm = VM::new(env, &mut db, &tx, tracer, VMType::L1, &NativeCrypto, None)
            .map_err(RunnerError::VMError)?;

        // Execute transaction with VM.
        let execution_result = vm.execute();

        // Verify transaction execution results where the ones expected by the test case.
        let checks_result = check_test_case_results(
            &mut vm,
            initial_block_hash,
            storage,
            test_case,
            execution_result,
            genesis,
        )
        .await?;

        // If test case did not pass the checks, add it to failing test cases record (for future reporting)
        if !checks_result.passed {
            failing_test_cases.push(checks_result);
            *failing_tests += 1;
        } else {
            *passing_tests += 1;
        }
        *total_run += 1;

        print!(
            "\rTotal tests ran: {} - Total passed: {} - Total failed: {}",
            format!("{}", total_run).blue(),
            format!("{}", passing_tests).green(),
            format!("{}", failing_tests).red()
        );
    }
    add_test_to_report((test, failing_test_cases))?;

    Ok(())
}

/// Validates a transaction whose invalidity lives only in the signed `post[].txbytes` —
/// a bad signature (`INVALID_SIGNATURE_VRS`) or a wrong chain id (`INVALID_CHAINID`). The tx is
/// decoded and checked directly: `Transaction::sender` enforces the EIP-2 low-s rule and r/s
/// range checks, and `chain_id()` is compared against the network id (1). A detected fault that
/// matches the fixture's expected exception is a pass.
fn validate_from_txbytes(test_case: &TestCase) -> PostCheckResult {
    let expected = test_case
        .post
        .expected_exceptions
        .clone()
        .unwrap_or_default();

    let (signature_bad, chain_id_bad) = match Transaction::decode_canonical(&test_case.tx_bytes) {
        Err(_) => (true, false),
        Ok(tx) => (
            tx.sender(&NativeCrypto).is_err(),
            tx.chain_id().is_some_and(|chain_id| chain_id != 1),
        ),
    };

    let passed = expected.iter().any(|e| match e {
        TransactionExpectedException::InvalidSignatureVrs => signature_bad,
        TransactionExpectedException::InvalidChainId => chain_id_bad,
        TransactionExpectedException::Other => signature_bad || chain_id_bad,
        _ => false,
    });

    PostCheckResult {
        fork: test_case.fork,
        vector: test_case.vector,
        passed,
        exception_diff: (!passed).then_some((expected, None)),
        ..Default::default()
    }
}

/// Gets the enviroment needed to prepare the VM for a transaction.
pub fn get_vm_env_for_test(
    test_env: Env,
    test_case: &TestCase,
) -> Result<Environment, RunnerError> {
    let blob_schedule = EVMConfig::canonical_values(test_case.fork);
    let config = EVMConfig::new(test_case.fork, blob_schedule);
    let gas_price = effective_gas_price(&test_env, test_case)?;
    let base_blob_fee_per_gas = get_base_fee_per_blob_gas(
        test_env
            .current_excess_blob_gas
            .map(|x| x.try_into().unwrap()),
        &config,
    )
    .map_err(|e| RunnerError::Custom(format!("Failed to get blob base fee: {e}")))?;
    Ok(Environment {
        origin: test_case.sender,
        gas_limit: test_case.gas,
        config,
        block_number: test_env.current_number.try_into().unwrap(),
        coinbase: test_env.current_coinbase,
        timestamp: test_env.current_timestamp.try_into().unwrap(),
        prev_randao: test_env.current_random,
        difficulty: test_env.current_difficulty,
        slot_number: test_env.slot_number.unwrap_or_default(),
        chain_id: U256::from(1),
        base_fee_per_gas: test_env.current_base_fee.unwrap_or_default(),
        base_blob_fee_per_gas,
        gas_price,
        block_excess_blob_gas: test_env
            .current_excess_blob_gas
            .map(|x| x.try_into().unwrap()),
        block_blob_gas_used: None,
        tx_blob_hashes: test_case.blob_versioned_hashes.clone(),
        tx_max_priority_fee_per_gas: test_case.max_priority_fee_per_gas,
        tx_max_fee_per_gas: test_case.max_fee_per_gas,
        tx_max_fee_per_blob_gas: test_case.max_fee_per_blob_gas,
        tx_nonce: test_case.nonce,
        block_gas_limit: test_env.current_gas_limit,
        is_privileged: false,
        fee_token: None,
        disable_balance_check: false,
        disable_nonce_check: false,
        trace_eth_transfers: false,
        disable_gas_allowance_check: false,
        disable_sender_eoa_check: false,
        is_system_call: false,
    })
}

/// Constructs the transaction that will be executed in a specific test case.
pub async fn get_tx_from_test_case(test_case: &TestCase) -> Result<Transaction, RunnerError> {
    // Transaction-validation tests (no `secretKey`) carry the already-signed transaction —
    // including its deliberately invalid signature — only in `tx_bytes`. Decode it directly
    // instead of rebuilding and re-signing from the `transaction` fields.
    if test_case.secret_key.is_none() {
        return Transaction::decode_canonical(&test_case.tx_bytes)
            .map_err(|e| RunnerError::Custom(format!("failed to decode txbytes: {e:?}")));
    }

    let value = test_case.value;
    let data = test_case.data.clone();
    let nonce = test_case.nonce;
    let to = test_case.to.clone();
    let chain_id = 1; // It's actually in the test config but it's always 1 I believe.
    let access_list = test_case
        .access_list
        .iter()
        .map(|list_item| (list_item.address, list_item.storage_keys.clone()))
        .collect();

    let mut tx = if let Some(list) = &test_case.authorization_list {
        Transaction::EIP7702Transaction(EIP7702Transaction {
            to: match to {
                TxKind::Call(to) => to,
                TxKind::Create => return Err(RunnerError::EIP7702ShouldNotBeCreateType),
            },
            value,
            data,
            access_list,
            authorization_list: list
                .iter()
                .map(|auth_tuple| auth_tuple.clone().into_authorization_tuple())
                .collect(),
            chain_id,
            nonce,
            max_priority_fee_per_gas: test_case
                .max_priority_fee_per_gas
                .unwrap()
                .try_into()
                .unwrap(),
            max_fee_per_gas: test_case.max_fee_per_gas.unwrap().try_into().unwrap(),
            gas_limit: test_case.gas,
            ..Default::default()
        })
    } else if let Some(max_fee_per_blob_gas) = test_case.max_fee_per_blob_gas {
        Transaction::EIP4844Transaction(EIP4844Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: test_case
                .max_priority_fee_per_gas
                .unwrap()
                .try_into()
                .unwrap(),
            max_fee_per_gas: test_case.max_fee_per_gas.unwrap().try_into().unwrap(),
            gas: test_case.gas,
            to: match to {
                TxKind::Call(to) => to,
                TxKind::Create => return Err(RunnerError::EIP7702ShouldNotBeCreateType), //TODO: See what to do with this. Maybe we want to get rid of the error and skip the test.
            },
            value,
            data,
            access_list,
            max_fee_per_blob_gas,
            blob_versioned_hashes: test_case.blob_versioned_hashes.clone(),
            ..Default::default()
        })
    } else if let (Some(max_priority_fee_per_gas), Some(max_fee_per_gas)) = (
        test_case.max_priority_fee_per_gas,
        test_case.max_fee_per_gas,
    ) {
        Transaction::EIP1559Transaction(EIP1559Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority_fee_per_gas.try_into().unwrap(),
            max_fee_per_gas: max_fee_per_gas.try_into().unwrap(),
            gas_limit: test_case.gas,
            to,
            value,
            data,
            access_list,
            ..Default::default()
        })
    } else if !test_case.access_list.is_empty() {
        // TODO: This will work, ideally Vec<something> should be Option<Vec<something>> so that we can tell if the field exists or not...
        Transaction::EIP2930Transaction(EIP2930Transaction {
            chain_id,
            nonce,
            gas_price: test_case.gas_price.unwrap(),
            gas_limit: test_case.gas,
            to,
            value,
            data,
            access_list,
            ..Default::default()
        })
    } else {
        Transaction::LegacyTransaction(LegacyTransaction {
            nonce,
            gas_price: test_case.gas_price.unwrap(),
            gas: test_case.gas,
            to,
            value,
            data,
            ..Default::default()
        })
    };

    // Sign transaction using sender's private key. Callers only reach this for tests that
    // provide a `secretKey`; signature-validation tests are handled by `check_signature_only`.
    let secret_key = test_case
        .secret_key
        .expect("get_tx_from_test_case requires a secretKey");
    let sk = SecretKey::from_slice(secret_key.as_bytes()).unwrap();
    let signer = Signer::Local(LocalSigner::new(sk));
    tx.sign_inplace(&signer)
        .await
        .expect("Signing shouldn't fail");
    Ok(tx)
}
