use std::{collections::HashMap, path::Path, sync::Arc};

use crate::{
    fork::Fork,
    types::{BlockChainExpectedException, BlockExpectedException, BlockWithRLP, TestUnit},
};
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidBlockError},
    fork_choice::apply_fork_choice,
};
#[cfg(not(feature = "stateless"))]
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::block_execution_witness::ExecutionWitness;
#[cfg(feature = "stateless")]
use ethrex_common::types::block_execution_witness::RpcExecutionWitness;
use ethrex_common::{
    constants::EMPTY_KECCAK_HASH,
    types::{
        Account as CoreAccount, Block as CoreBlock, BlockHeader as CoreBlockHeader,
        InvalidBlockHeaderError,
    },
};
use ethrex_rlp::decode::RLPDecode;
use ethrex_storage::{EngineType, Store};
use ethrex_vm::EvmError;
use regex::Regex;

thread_local! {
    /// Per-OS-thread merkleization pool, lazily built on first use. Mirrors the
    /// pattern used by `tooling/ef_tests/engine` so the ~10k+ blockchain tests
    /// don't each spawn a fresh 17-thread rayon pool of their own.
    /// The merkle protocol's 16 worker jobs cross-communicate via channels, so
    /// each pool may have only one concurrent `in_place_scope` caller; keying by
    /// `thread_local!` makes the calling test-runner thread the natural
    /// exclusive owner.
    static MERKLE_POOL: std::cell::OnceCell<Arc<rayon::ThreadPool>> =
        const { std::cell::OnceCell::new() };
}

fn merkle_pool() -> Arc<rayon::ThreadPool> {
    MERKLE_POOL.with(|cell| cell.get_or_init(Blockchain::build_merkle_pool).clone())
}

pub fn parse_and_execute(
    path: &Path,
    skipped_tests: Option<&[&str]>,
    run_stateless: bool,
) -> datatest_stable::Result<()> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tests = parse_tests(path);

    let mut failures = Vec::new();
    let mut executed = 0usize;
    let mut skipped_by_name = 0usize;
    let parsed = tests.len();

    for (test_key, test) in tests {
        let named = skipped_tests
            .map(|skipped| skipped.iter().any(|s| test_key.contains(s)))
            .unwrap_or(false);
        if named {
            skipped_by_name += 1;
            continue;
        }
        if test.network < Fork::Merge {
            continue;
        }
        executed += 1;

        let result = rt.block_on(run_ef_test(&test_key, &test, run_stateless));

        if let Err(e) = result {
            eprintln!("Test {test_key} failed: {e:?}");
            failures.push(format!("{test_key}: {e:?}"));
        }
    }

    // A stateless fixture file that runs nothing, and was not deliberately named
    // in the skip list, is a failure rather than a pass. A blanket fork-based skip
    // once silenced the entire stateless run — 23,946 fixtures, all of them
    // `network: Amsterdam` — and it stayed green the whole time. Named skips are
    // exempt because they are a recorded decision; a structural skip is not. Not
    // applied to the levm run, where `vectors/legacy/` is legitimately pre-Merge.
    if run_stateless && parsed > 0 && executed == 0 && skipped_by_name == 0 {
        return Err(format!(
            "{}: all {parsed} stateless fixture(s) were skipped structurally, so this file \
             tested nothing",
            path.display()
        )
        .into());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        // \n doesn't print new lines on terminal, so this alternative is for making it readable
        Err(failures.join("     -------     ").into())
    }
}

pub async fn run_ef_test(
    test_key: &str,
    test: &TestUnit,
    run_stateless: bool,
) -> Result<(), String> {
    // check that the decoded genesis block header matches the deserialized one
    let genesis_rlp = test.genesis_rlp.clone();
    let decoded_block = match CoreBlock::decode(&genesis_rlp) {
        Ok(block) => block,
        Err(e) => return Err(format!("Failed to decode genesis RLP: {e}")),
    };
    let genesis_block_header = CoreBlockHeader::from(test.genesis_block_header.clone());
    if decoded_block.header != genesis_block_header {
        return Err("Decoded genesis header does not match expected header".to_string());
    }

    let store = build_store_for_test(test).await;

    // Check world_state
    check_prestate_against_db(test_key, test, &store);

    // Blockchain EF tests are meant for L1.
    let blockchain = Blockchain::for_test_harness_with_pool(store.clone(), merkle_pool());

    // Early return if the exception is in the rlp decoding of the block
    for bf in &test.blocks {
        if bf.expect_exception.is_some() && exception_in_rlp_decoding(bf) {
            return Ok(());
        }
    }

    run(test_key, test, &blockchain, &store).await?;

    // For Amsterdam tests, exercise the parallel BAL execution path as a correctness check.
    // Two-pass approach: pass 1 collects the BAL produced by sequential execution, pass 2
    // re-executes using that BAL to drive parallel (BAL-warmed) execution and verifies the
    // same final state is reached.
    // Not exercised under `stateless`: the stateless harness runs the guest program directly
    // and doesn't drive `add_block_pipeline`, and BAL-warmed parallel execution gives no
    // benefit in single-threaded zkVM guest builds. The non-stateless runs are the right
    // home for this check.
    #[cfg(not(feature = "stateless"))]
    if test.network >= Fork::Amsterdam {
        run_two_pass_parallel(test_key, test).await?;
    }

    // Run stateless if backend was specified for this.
    // TODO: See if we can run stateless without needing a previous run. We can't easily do it for now. #4142
    // The `stateless_backend` option now only selects *whether* to run stateless
    // validation, not which backend: the in-memory paths go through
    // `validate_blocks_statelessly` and the wire path through the guest
    // entrypoint, neither of which is backend-dispatched.
    if run_stateless {
        // Use the fixture's witness when present (either `executionWitness` or
        // `statelessInputBytes`); otherwise regenerate by re-running execution.
        #[cfg(feature = "stateless")]
        {
            let has_fixture_witness = test.blocks.iter().any(|bf| {
                bf.block().is_some_and(|b| {
                    b.execution_witness.is_some() || b.stateless_input_bytes.is_some()
                })
            });
            if has_fixture_witness {
                run_stateless_from_fixture(test, test_key).await?;
                check_witness_generation_against_fixture(&blockchain, test, test_key).await?;
                return Ok(());
            }
        }
        re_run_stateless(blockchain, test, test_key).await?;
    };

    Ok(())
}

// Helper: run the EF test blocks and verify poststate
async fn run(
    test_key: &str,
    test: &TestUnit,
    blockchain: &Blockchain,
    store: &Store,
) -> Result<(), String> {
    // Execute all blocks in test
    for block_fixture in test.blocks.iter() {
        let expects_exception = block_fixture.expect_exception.is_some();

        // Won't panic because test has been validated
        let block: CoreBlock = block_fixture.block().unwrap().clone().into();
        let hash = block.hash();

        // Attempt to add the block as the head of the chain
        let chain_result = blockchain.add_block_pipeline(block.clone(), None);

        match chain_result {
            Err(error) => {
                if !expects_exception {
                    return Err(format!(
                        "Transaction execution unexpectedly failed on test: {test_key}, with error {error:?}",
                    ));
                }
                let expected_exception = block_fixture.expect_exception.clone().unwrap();
                if !exception_is_expected(expected_exception.clone(), &error) {
                    eprintln!(
                        "Warning: Returned exception {error:?} does not match expected {expected_exception:?}",
                    );
                }
                // Expected exception matched — block was rejected, but the test may
                // still expect subsequent blocks to be processed (e.g. fork-transition
                // tests where a block at the pre-fork timestamp fails and a block at
                // the post-fork timestamp succeeds, both built on the same parent).
                // Continue with the next block in the fixture.
                continue;
            }
            Ok(_) => {
                if expects_exception {
                    return Err(format!(
                        "Expected transaction execution to fail in test: {test_key} with error: {:?}",
                        block_fixture.expect_exception.clone()
                    ));
                }
                // Advance fork choice to the new head
                apply_fork_choice(store, hash, hash, hash, None)
                    .await
                    .unwrap();
            }
        }
    }

    // Final post-state verification
    check_poststate_against_db(test_key, test, store).await;
    Ok(())
}

/// Two-pass parallel execution check for Amsterdam tests.
///
/// Pass 1 (sequential): runs every block with `add_block_pipeline_bal` to collect the
/// BAL that each block produces.  Pass 2 (parallel): creates a fresh chain and re-runs every
/// block passing the corresponding BAL so the BAL-warmed parallel path is exercised.  The final
/// post-state of pass 2 must match the expected post-state.
#[cfg(not(feature = "stateless"))]
async fn run_two_pass_parallel(test_key: &str, test: &TestUnit) -> Result<(), String> {
    // ---- Pass 1: sequential, collect BALs ----
    let store1 = build_store_for_test(test).await;
    let blockchain1 = Blockchain::for_test_harness_with_pool(store1.clone(), merkle_pool());

    let mut bals: Vec<Arc<BlockAccessList>> = Vec::with_capacity(test.blocks.len());

    for block_fixture in test.blocks.iter() {
        // Skip fixtures that expect an exception — the normal run() already verified them.
        if block_fixture.expect_exception.is_some() {
            return Ok(());
        }

        let block: CoreBlock = block_fixture.block().unwrap().clone().into();
        let hash = block.hash();

        let produced_bal = blockchain1
            .add_block_pipeline_bal(block, None)
            .map_err(|e| format!("Two-pass pass-1 failed for test {test_key}: {e:?}"))?;

        apply_fork_choice(&store1, hash, hash, hash, None)
            .await
            .map_err(|e| {
                format!("Two-pass pass-1 fork choice failed for test {test_key}: {e:?}")
            })?;

        // If execution produced no BAL (non-Amsterdam block in a transition test), skip pass 2.
        match produced_bal {
            Some(bal) => bals.push(Arc::new(bal)),
            None => return Ok(()),
        }
    }

    // ---- Pass 2: parallel (BAL-driven), verify post-state ----
    let store2 = build_store_for_test(test).await;
    let blockchain2 = Blockchain::for_test_harness_with_pool(store2.clone(), merkle_pool());

    for (block_fixture, bal) in test.blocks.iter().zip(bals.iter()) {
        let block: CoreBlock = block_fixture.block().unwrap().clone().into();
        let hash = block.hash();

        blockchain2
            .add_block_pipeline(block, Some(Arc::clone(bal)))
            .map_err(|e| format!("Two-pass pass-2 (parallel) failed for test {test_key}: {e:?}"))?;

        apply_fork_choice(&store2, hash, hash, hash, None)
            .await
            .map_err(|e| {
                format!("Two-pass pass-2 fork choice failed for test {test_key}: {e:?}")
            })?;
    }

    // Verify post-state matches expected
    check_poststate_against_db(test_key, test, &store2).await;
    Ok(())
}

fn exception_is_expected(
    expected_exceptions: Vec<BlockChainExpectedException>,
    returned_error: &ChainError,
) -> bool {
    expected_exceptions.iter().any(|exception| {
        if let (
            BlockChainExpectedException::TxtException(expected_error_msg),
            ChainError::EvmError(EvmError::Transaction(error_msg))
            | ChainError::InvalidBlock(InvalidBlockError::InvalidTransaction(error_msg)),
        ) = (exception, returned_error)
        {
            return (expected_error_msg.to_lowercase() == error_msg.to_lowercase())
                || match_expected_regex(expected_error_msg, error_msg);
        }
        matches!(
            (exception, &returned_error),
            (
                BlockChainExpectedException::BlockException(
                    BlockExpectedException::IncorrectBlobGasUsed
                ),
                ChainError::InvalidBlock(InvalidBlockError::BlobGasUsedMismatch)
            ) | (
                BlockChainExpectedException::BlockException(
                    BlockExpectedException::BlobGasUsedAboveLimit
                ),
                ChainError::InvalidBlock(InvalidBlockError::InvalidHeader(
                    InvalidBlockHeaderError::GasUsedGreaterThanGasLimit
                ))
            ) | (
                BlockChainExpectedException::BlockException(
                    BlockExpectedException::IncorrectExcessBlobGas
                ),
                ChainError::InvalidBlock(InvalidBlockError::InvalidHeader(
                    InvalidBlockHeaderError::ExcessBlobGasIncorrect
                ))
            ) | (
                BlockChainExpectedException::BlockException(
                    BlockExpectedException::IncorrectBlockFormat
                ),
                ChainError::InvalidBlock(_)
            ) | (
                BlockChainExpectedException::BlockException(BlockExpectedException::InvalidRequest),
                ChainError::InvalidBlock(InvalidBlockError::RequestsHashMismatch)
            ) | (
                BlockChainExpectedException::BlockException(
                    BlockExpectedException::SystemContractCallFailed
                ),
                ChainError::EvmError(EvmError::SystemContractCallFailed(_))
            ) | (
                BlockChainExpectedException::BlockException(
                    BlockExpectedException::RlpBlockLimitExceeded
                ),
                ChainError::InvalidBlock(InvalidBlockError::MaximumRlpSizeExceeded(_, _))
            ) | (
                // Legacy tx with out-of-range `v` (or out-of-range `r`/`s`): sender
                // recovery rejects the signature during execution.
                BlockChainExpectedException::InvalidSignature,
                ChainError::EvmError(EvmError::Transaction(_))
                    | ChainError::InvalidBlock(InvalidBlockError::InvalidTransaction(_))
            ) | (
                BlockChainExpectedException::Other,
                _ //TODO: Decide whether to support more specific errors.
            ),
        )
    })
}

fn match_expected_regex(expected_error_regex: &str, error_msg: &str) -> bool {
    let Ok(regex) = Regex::new(expected_error_regex) else {
        return false;
    };
    regex.is_match(error_msg)
}

/// Tests the rlp decoding of a block
fn exception_in_rlp_decoding(block_fixture: &BlockWithRLP) -> bool {
    // NOTE: There is a test which validates that an EIP-7702 transaction is not allowed to
    // have the "to" field set to null (create).
    // This test expects an exception to be thrown AFTER the Block RLP decoding, when the
    // transaction is validated. This would imply allowing the "to" field of the
    // EIP-7702 transaction to be null and validating it on the `prepare_execution` LEVM hook.
    //
    // Instead, this approach is taken, which allows for the exception to be thrown on
    // RLPDecoding, so the data type EIP7702Transaction correctly describes the requirement of
    // "to" field to be an Address
    // For more information, please read:
    // - https://eips.ethereum.org/EIPS/eip-7702
    // - https://github.com/lambdaclass/ethrex/pull/2425
    //
    // There is another test which validates the same exact thing, but for an EIP-4844 tx.
    // That test also allows for a "BlockException.RLP_..." error to happen, and that's what is being
    // caught.

    // Decoding_exception_cases = [
    // "BlockException.RLP_",
    // "TransactionException.TYPE_4_TX_CONTRACT_CREATION", ];

    let expects_rlp_exception = block_fixture
        .expect_exception
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|case| matches!(case, BlockChainExpectedException::RLPException));

    // A typed transaction whose `y_parity` byte isn't a valid bool (0/1) is rejected
    // at RLP decoding (MalformedBoolean), so `INVALID_SIGNATURE_VRS` is a legitimate
    // reason for the block to fail decoding as well.
    let expects_invalid_signature = block_fixture
        .expect_exception
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|case| matches!(case, BlockChainExpectedException::InvalidSignature));

    // A transaction nonce of 2^64 or greater does not fit ethrex's `u64` nonce field
    // (the nonce is a `u64` per the yellow paper / EIP-2681), so it is rejected at RLP
    // decoding with an `InvalidLength` error rather than at validation. EEST's
    // `NONCE_IS_MAX` fixtures (e.g. `tx_max_nonce`, nonce = 2^64) therefore fail decoding
    // here — a legitimate reason for the block to be rejected. (`create_transaction_high_nonce`
    // uses nonce = 2^64-1, which fits `u64`, decodes fine, and is caught later at validation.)
    let expects_nonce_too_high = block_fixture
        .expect_exception
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|case| matches!(case, BlockChainExpectedException::TxtException(msg) if msg == "Nonce is max"));

    // EIP-8141 structural frame rules (frame count, reserved modes, forbidden
    // flag/target combinations): ethrex enforces some in the type-0x06 decoder
    // and the rest at frame execution, so failing to decode is one legitimate
    // outcome for a fixture expecting an invalid frame format.
    let expects_invalid_frame_format = block_fixture
        .expect_exception
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|case| matches!(case, BlockChainExpectedException::InvalidFrameFormat));

    // A fee field of 2^256 or more does not fit a transaction's `U256` fee
    // fields, so the fixtures carrying 33-byte fees fail here. Fees below that
    // bound always decode — legacy `gas_price` is `U256` as well — so the
    // `gas_limit * price` product-overflow fixtures (a 31-byte legacy price, a
    // 2^255 frame fee) decode fine and are rejected later at execution without
    // consulting this arm — the same split as the nonce cases above.
    let expects_fee_overflow = block_fixture
        .expect_exception
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|case| matches!(case, BlockChainExpectedException::FeeOverflow));

    match CoreBlock::decode(block_fixture.rlp.as_ref()) {
        Ok(_) => {
            assert!(!expects_rlp_exception);
            false
        }
        Err(_) => {
            assert!(
                expects_rlp_exception
                    || expects_invalid_signature
                    || expects_nonce_too_high
                    || expects_invalid_frame_format
                    || expects_fee_overflow
            );
            true
        }
    }
}

pub fn parse_tests(path: &Path) -> HashMap<String, TestUnit> {
    let mut all_tests = HashMap::new();

    if path.is_file() {
        let file_tests = parse_json_file(path);
        all_tests.extend(file_tests);
    } else if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("Failed to read directory") {
            let entry = entry.expect("Failed to get DirEntry");
            let path = entry.path();
            if path.is_dir() {
                let sub_tests = parse_tests(&path); // recursion
                all_tests.extend(sub_tests);
            } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let file_tests = parse_json_file(&path);
                all_tests.extend(file_tests);
            }
        }
    } else {
        panic!("Invalid path: not a file or directory");
    }

    all_tests
}

fn parse_json_file(path: &Path) -> HashMap<String, TestUnit> {
    let s = std::fs::read_to_string(path).expect("Unable to read file");
    serde_json::from_str(&s).expect("Unable to parse JSON")
}

/// Creates a new in-memory store and adds the genesis state.
pub async fn build_store_for_test(test: &TestUnit) -> Store {
    let mut store =
        Store::new("store.db", EngineType::InMemory).expect("Failed to build DB for testing");
    let genesis = test.get_genesis();
    store
        .add_initial_state(genesis)
        .await
        .expect("Failed to add genesis state");
    store
}

/// Builds the blocks and a self-generated execution witness for a blockchain
/// test, using ethrex's own execution machinery instead of any witness the
/// fixture might carry. This is the ethrex-native counterpart to the
/// external eth-act `witness-generator-cli` path: it turns a plain EEST
/// `blockchain_test` (genesis/`pre` state + blocks, no embedded witness)
/// into a `(blocks, ExecutionWitness)` pair usable for stateless-execution
/// benchmarking.
///
/// Every block is first driven through `add_block_pipeline` (mirroring
/// `run()`), so that for multi-block tests the parent state of block
/// `i > 0` is already committed to the store before
/// `generate_witness_for_blocks` re-executes every block with a
/// `TrieLogger`. `generate_witness_for_blocks` only has the state at the
/// *first* block's parent available for free (from `build_store_for_test`);
/// its own doc comment notes it otherwise fails on the second block of a
/// batch.
///
/// A test whose blocks include an expected exception (invalid-block test) or
/// that decodes to zero blocks is rejected with an `Err` rather than
/// silently producing a partial/incorrect fixture, so batch callers (e.g.
/// `generate-stress`) can skip it and continue.
pub async fn blocks_and_witness_for_test(
    test: &TestUnit,
) -> Result<(Vec<CoreBlock>, ExecutionWitness), String> {
    let store = build_store_for_test(test).await;
    let blockchain = Blockchain::for_test_harness_with_pool(store.clone(), merkle_pool());

    let mut blocks: Vec<CoreBlock> = Vec::with_capacity(test.blocks.len());
    for block_fixture in test.blocks.iter() {
        if block_fixture.expect_exception.is_some() {
            return Err(
                "test has a block expecting an exception; not a witness-generation target"
                    .to_string(),
            );
        }
        let block_data = block_fixture
            .block()
            .ok_or_else(|| "block fixture has no decodable block (RLP-only test)".to_string())?;
        let block: CoreBlock = block_data.clone().into();
        let hash = block.hash();

        blockchain
            .add_block_pipeline(block.clone(), None)
            .map_err(|e| {
                format!(
                    "add_block_pipeline failed for block {}: {e:?}",
                    block.header.number
                )
            })?;
        apply_fork_choice(&store, hash, hash, hash, None)
            .await
            .map_err(|e| {
                format!(
                    "apply_fork_choice failed for block {}: {e:?}",
                    block.header.number
                )
            })?;

        blocks.push(block);
    }

    if blocks.is_empty() {
        return Err("no blocks".to_string());
    }

    let witness = blockchain
        .generate_witness_for_blocks(&blocks)
        .await
        .map_err(|e| format!("witness gen: {e}"))?;

    Ok((blocks, witness))
}

/// Checks db is correct after setting up initial state
/// Panics if any comparison fails
fn check_prestate_against_db(test_key: &str, test: &TestUnit, db: &Store) {
    let block_number = test.genesis_block_header.number.low_u64();
    let db_block_header = db.get_block_header(block_number).unwrap().unwrap();
    let computed_genesis_block_hash = db_block_header.hash();
    // Check genesis block hash
    assert_eq!(test.genesis_block_header.hash, computed_genesis_block_hash);
    // Check genesis state root
    let test_state_root = test.genesis_block_header.state_root;
    assert_eq!(
        test_state_root, db_block_header.state_root,
        "Mismatched genesis state root for database, test: {test_key}"
    );
    assert!(db.has_state_root(test_state_root).unwrap());
}

/// Checks that all accounts in the post-state are present and have the correct values in the DB
/// Panics if any comparison fails
/// Tests that previously failed the validation stage shouldn't be executed with this function.
async fn check_poststate_against_db(test_key: &str, test: &TestUnit, db: &Store) {
    let latest_block_number = db.get_latest_block_number().unwrap();
    if let Some(post_state) = &test.post_state {
        for (addr, account) in post_state {
            let expected_account: CoreAccount = account.clone().into();
            // Check info
            let db_account_info = db
                .get_account_info(latest_block_number, *addr)
                .await
                .expect("Failed to read from DB")
                .unwrap_or_else(|| {
                    panic!("Account info for address {addr} not found in DB, test:{test_key}")
                });
            assert_eq!(
                db_account_info, expected_account.info,
                "Mismatched account info for address {addr} test:{test_key}"
            );
            // Check code
            let code_hash = expected_account.info.code_hash;
            if code_hash != *EMPTY_KECCAK_HASH {
                // We don't want to get account code if there's no code.
                let db_account_code = db
                    .get_account_code(code_hash)
                    .expect("Failed to read from DB")
                    .unwrap_or_else(|| {
                        panic!(
                            "Account code for code hash {code_hash} not found in DB test:{test_key}"
                        )
                    });
                assert_eq!(
                    db_account_code, expected_account.code,
                    "Mismatched account code for code hash {code_hash} test:{test_key}"
                );
            }
            // Check storage
            for (key, value) in expected_account.storage {
                let db_storage_value = db
                    .get_storage_at(latest_block_number, *addr, key)
                    .expect("Failed to read from DB")
                    .unwrap_or_else(|| {
                        panic!("Storage missing for address {addr} key {key} in DB test:{test_key}")
                    });
                assert_eq!(
                    db_storage_value, value,
                    "Mismatched storage value for address {addr}, key {key} test:{test_key}"
                );
            }
        }
    }
    // Check lastblockhash is in store
    let last_block_number = db.get_latest_block_number().unwrap();
    let last_block_header = db.get_block_header(last_block_number).unwrap().unwrap();
    let last_block_hash = last_block_header.hash();
    assert_eq!(
        test.lastblockhash, last_block_hash,
        "Last block number does not match"
    );

    // State root was already validated by `add_block`.
}

async fn re_run_stateless(
    blockchain: Blockchain,
    test: &TestUnit,
    test_key: &str,
) -> Result<(), String> {
    let blocks = test
        .blocks
        .iter()
        .map(|block_fixture| block_fixture.block().unwrap().clone().into())
        .collect::<Vec<CoreBlock>>();

    let test_should_fail = test.blocks.iter().any(|t| t.expect_exception.is_some());

    let witness = blockchain.generate_witness_for_blocks(&blocks).await;
    if test_should_fail {
        // The normal run() already verified this test fails correctly.
        // The stateless prover proves valid block execution, not invalid block rejection.
        return Ok(());
    } else if let Err(err) = witness {
        return Err(format!(
            "Failed to create witness for a test that should not fail: {err}"
        ));
    }
    // At this point witness is guaranteed to be Ok
    let execution_witness = witness.unwrap();

    // A generated witness has no spec wire bytes, so this cannot go through the
    // byte entrypoint; `ExecBackend` was also the only backend able to run an
    // in-memory witness, so the dispatch is gone with it.
    let execute_result = ethrex_guest_program::l1::validate_blocks_statelessly(
        &blocks,
        execution_witness,
        std::sync::Arc::new(ethrex_crypto::NativeCrypto),
    );

    if let Err(e) = execute_result {
        if !test_should_fail {
            return Err(format!(
                "Expected test: {test_key} to succeed but failed with {e}"
            ));
        }
    } else if test_should_fail {
        return Err(format!("Expected test: {test_key} to fail but succeeded"));
    }
    Ok(())
}

/// Run stateless execution using the execution witness provided directly in the
/// zkevm fixture, instead of generating one from blockchain execution.
///
/// Each block in the fixture has its own `executionWitness` containing the state
/// trie nodes, codes, and ancestor headers needed for that specific block.
/// Following the spec, we execute each block
/// independently with its own witness.
#[cfg(feature = "stateless")]
async fn run_stateless_from_fixture(test: &TestUnit, test_key: &str) -> Result<(), String> {
    let chain_config = test.network.chain_config();

    for block_fixture in test.blocks.iter() {
        // Skip blocks that expect exceptions — those are already validated by the normal path.
        if block_fixture.expect_exception.is_some() {
            continue;
        }

        let Some(block_data) = block_fixture.block() else {
            continue;
        };

        let block: CoreBlock = block_data.clone().into();
        let block_number = block.header.number;

        // Absent bytes means "expected to succeed"; malformed bytes are a hard error.
        let expected_valid = match block_data.stateless_output_bytes.as_deref() {
            None => true,
            Some(bytes) => parse_expected_valid_flag(bytes).map_err(|e| {
                format!("Malformed statelessOutputBytes for {test_key} block {block_number}: {e}")
            })?,
        };

        // Prefer the spec wire path — the same entrypoint the released guest ELF
        // runs — and compare the whole 43-byte result rather than peeking at the
        // validity byte. Only blocks that carry BOTH the input and the expected
        // output can go this way; the rest fall through to the witness route
        // below, which is why `parse_expected_valid_flag` is still needed.
        if let (Some(input_hex), Some(output_hex)) = (
            block_data.stateless_input_bytes.as_deref(),
            block_data.stateless_output_bytes.as_deref(),
        ) {
            run_stateless_from_input_bytes(test_key, block_number, input_hex, output_hex)?;
            continue;
        }

        let Some(witness_json) = block_data.execution_witness.as_ref() else {
            continue;
        };

        // Parse and conversion errors must always fail; only the execution outcome is
        // matched against `expected_valid` so the (false, Err(_)) arm below cannot
        // absorb regressions in deserialization or witness conversion.
        let rpc_witness: RpcExecutionWitness = serde_json::from_value(witness_json.clone())
            .map_err(|e| {
                format!("executionWitness parse failed for {test_key} block {block_number}: {e}")
            })?;
        let decoded_headers =
            ethrex_common::types::block_execution_witness::decode_witness_headers(
                &rpc_witness.headers,
            )
            .map_err(|e| {
                format!("witness header decode failed for {test_key} block {block_number}: {e}")
            })?;
        let execution_witness = rpc_witness
            .into_execution_witness(
                *chain_config,
                block_number,
                &decoded_headers,
                &ethrex_crypto::NativeCrypto,
            )
            .map_err(|e| {
                format!("witness conversion failed for {test_key} block {block_number}: {e}")
            })?;

        let exec_result = ethrex_guest_program::l1::validate_blocks_statelessly(
            std::slice::from_ref(&block),
            execution_witness,
            std::sync::Arc::new(ethrex_crypto::NativeCrypto),
        );

        match (expected_valid, exec_result) {
            (true, Ok(_)) | (false, Err(_)) => {}
            (true, Err(e)) => {
                return Err(format!(
                    "Stateless execution from fixture failed for {test_key} block {block_number}: {e}"
                ));
            }
            (false, Ok(_)) => {
                return Err(format!(
                    "Stateless execution from fixture succeeded for {test_key} block \
                     {block_number} but fixture expected it to fail (invalid executionWitness)"
                ));
            }
        }
    }

    Ok(())
}

/// Check the witness *generation* side: for every valid block carrying an
/// `executionWitness`, generate ethrex's own witness from the (already
/// executed) chain and diff its state/codes/headers sections against the
/// fixture's expected witness. `run_stateless_from_fixture` only proves the
/// fixture witness suffices for stateless execution; this proves ethrex
/// would have produced the canonical witness itself.
///
/// Blocks whose `statelessOutputBytes` mark the fixture witness as invalid
/// are skipped — their witness is deliberately corrupted and not a
/// generation target.
#[cfg(feature = "stateless")]
async fn check_witness_generation_against_fixture(
    blockchain: &Blockchain,
    test: &TestUnit,
    test_key: &str,
) -> Result<(), String> {
    use std::collections::BTreeSet;

    const MAX_REPORTED_ITEMS: usize = 8;

    // `errors` fail the test; `differences` are reported only. See the note at
    // the comparison below for why a witness need not equal the fixture's.
    let mut errors: Vec<String> = Vec::new();
    let mut differences: Vec<String> = Vec::new();
    for block_fixture in test.blocks.iter() {
        if block_fixture.expect_exception.is_some() {
            continue;
        }
        let Some(block_data) = block_fixture.block() else {
            continue;
        };
        let Some(witness_json) = block_data.execution_witness.as_ref() else {
            continue;
        };
        let expected_valid = match block_data.stateless_output_bytes.as_deref() {
            None => true,
            Some(bytes) => parse_expected_valid_flag(bytes)?,
        };
        if !expected_valid {
            continue;
        }

        let expected: RpcExecutionWitness = serde_json::from_value(witness_json.clone())
            .map_err(|e| format!("executionWitness parse failed for {test_key}: {e}"))?;

        let block: CoreBlock = block_data.clone().into();
        let block_number = block.header.number;
        let generated_witness = blockchain
            .generate_witness_for_blocks(std::slice::from_ref(&block))
            .await
            .map_err(|e| {
                format!("witness generation failed for {test_key} block {block_number}: {e}")
            })?;

        // Sufficiency: the generated witness must support stateless re-execution
        // of the block on its own, independent of how close it is to canonical.
        let exec_result = ethrex_guest_program::l1::validate_blocks_statelessly(
            std::slice::from_ref(&block),
            generated_witness.clone(),
            std::sync::Arc::new(ethrex_crypto::NativeCrypto),
        );
        if let Err(e) = exec_result {
            errors.push(format!(
                "{test_key} block {block_number}: generated witness INSUFFICIENT for \
                 stateless execution: {e}"
            ));
        }

        let generated = RpcExecutionWitness::try_from(generated_witness).map_err(|e| {
            format!("witness conversion failed for {test_key} block {block_number}: {e}")
        })?;

        for (section, got, exp) in [
            ("state", &generated.state, &expected.state),
            ("codes", &generated.codes, &expected.codes),
            ("headers", &generated.headers, &expected.headers),
        ] {
            // Order-insensitive comparison: canonical ordering is enforced at
            // serialization (`RpcExecutionWitness::try_from`), and some
            // fixtures (witness_validation `*_unsorted_but_complete`)
            // deliberately ship non-canonical order to test consumer leniency.
            let mut got_sorted: Vec<&[u8]> = got.iter().map(|b| b.as_ref()).collect();
            let mut exp_sorted: Vec<&[u8]> = exp.iter().map(|b| b.as_ref()).collect();
            got_sorted.sort();
            exp_sorted.sort();
            if got_sorted == exp_sorted {
                continue;
            }
            let got_set: BTreeSet<&[u8]> = got_sorted.iter().copied().collect();
            let exp_set: BTreeSet<&[u8]> = exp_sorted.iter().copied().collect();
            let missing: Vec<&&[u8]> = exp_set.difference(&got_set).collect();
            let extra: Vec<&&[u8]> = got_set.difference(&exp_set).collect();
            if missing.is_empty() && extra.is_empty() {
                differences.push(format!(
                    "{test_key} block {block_number} {section}: same item set but \
                     different multiplicity (generated {}, fixture {})",
                    got.len(),
                    exp.len()
                ));
                continue;
            }
            let fmt_items = |items: &[&&[u8]]| {
                let shown: Vec<String> = items
                    .iter()
                    .take(MAX_REPORTED_ITEMS)
                    .map(|b| describe_witness_item(section, b))
                    .collect();
                let suffix = if items.len() > MAX_REPORTED_ITEMS {
                    format!(" …and {} more", items.len() - MAX_REPORTED_ITEMS)
                } else {
                    String::new()
                };
                format!("{}{}", shown.join(", "), suffix)
            };
            let mut msg = format!(
                "{test_key} block {block_number} {section}: generated {} items, fixture {}.",
                got.len(),
                exp.len()
            );
            if !missing.is_empty() {
                msg.push_str(&format!(
                    " missing from generated: [{}]",
                    fmt_items(&missing)
                ));
            }
            if !extra.is_empty() {
                msg.push_str(&format!(" extra in generated: [{}]", fmt_items(&extra)));
            }
            // Reported, not failed. A witness only has to be *sufficient*, which
            // is asserted above by re-executing with it; it does not have to
            // equal the fixture's. EEST ships `validation_codes_extra_unused_bytecode`
            // (and the `state`/`headers` equivalents) precisely to pin that a
            // witness carrying extra unused items is valid, so neither direction
            // of this difference is a defect. Upstream bundles differ in policy
            // too: the zkevm conformance set excludes bytecode created inside the
            // block, while the zkevm-benchmark set includes it, so requiring
            // equality fails whichever one the client does not happen to mirror.
            differences.push(msg);
        }
    }

    if !differences.is_empty() {
        eprintln!(
            "note: {test_key} witness differs from the fixture's (both valid; the \
             generated one is proven sufficient above):\n{}",
            differences.join("\n")
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "generated witness is not usable for stateless execution:\n{}",
            errors.join("\n")
        ))
    }
}

/// Render a witness item for mismatch reports: headers decode to their block
/// number, other sections show a hex prefix and length.
#[cfg(feature = "stateless")]
fn describe_witness_item(section: &str, bytes: &[u8]) -> String {
    if section == "headers"
        && let Ok(header) = CoreBlockHeader::decode(bytes)
    {
        return format!("header #{} ({} bytes)", header.number, bytes.len());
    }
    let prefix = hex::encode(&bytes[..bytes.len().min(8)]);
    format!("0x{prefix}… ({} bytes)", bytes.len())
}

/// Run a fixture's `statelessInputBytes` (2-byte BE schema-id followed by
/// SSZ-encoded `SszStatelessInput`) through the canonical-input path the
/// production guest binary uses.
#[cfg(feature = "stateless")]
fn run_stateless_from_input_bytes(
    test_key: &str,
    block_number: u64,
    input_hex: &str,
    expected_output_hex: &str,
) -> Result<(), String> {
    use ethrex_guest_program::l1::run_stateless_guest;

    let decode = |label: &str, hex_str: &str| {
        let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(trimmed).map_err(|e| {
            format!("{label} hex decode failed for {test_key} block {block_number}: {e}")
        })
    };

    let input = decode("statelessInputBytes", input_hex)?;
    let expected = decode("statelessOutputBytes", expected_output_hex)?;

    let actual = run_stateless_guest(&input, std::sync::Arc::new(ethrex_crypto::NativeCrypto));

    if actual != expected {
        return Err(format!(
            "statelessOutputBytes mismatch for {test_key} block {block_number}:\n  \
             expected 0x{}\n  actual   0x{}",
            hex::encode(&expected),
            hex::encode(&actual),
        ));
    }
    Ok(())
}

/// Decode the `valid` byte (index 32) from a zkevm-fixture `statelessOutputBytes` hex
/// string, encoded as `new_payload_request_root (32 B) ++ valid (1 B) ++ padding`.
#[cfg(feature = "stateless")]
fn parse_expected_valid_flag(hex: &str) -> Result<bool, String> {
    let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
    let byte_hex = trimmed.get(64..66).ok_or_else(|| {
        format!(
            "expected at least 33 bytes (66 hex chars), got {} hex chars",
            trimmed.len()
        )
    })?;
    let byte = u8::from_str_radix(byte_hex, 16)
        .map_err(|e| format!("invalid hex at byte 32 ({byte_hex:?}): {e}"))?;
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(format!(
            "invalid validity byte 0x{n:02x} (expected 0x00 or 0x01)"
        )),
    }
}
