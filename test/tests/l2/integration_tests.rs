#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use anyhow::{Context, Result};
use bytes::Bytes;
use ethrex_common::constants::GAS_PER_BLOB;
use ethrex_common::types::{
    EIP1559_DEFAULT_SERIALIZED_LENGTH, EIP1559Transaction, FeeTokenTransaction,
    SAFE_BYTES_PER_BLOB, Transaction, TxKind, TxType,
};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, H160, H256, U256};
use ethrex_l2::monitor::widget::l2_to_l1_messages::{L2ToL1MessageKind, L2ToL1MessageStatus};
use ethrex_l2::monitor::widget::{L2ToL1MessagesTable, l2_to_l1_messages::L2ToL1MessageRow};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_common::messages::L1MessageProof;
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_l2_rpc::clients::{
    get_base_fee_vault_address, get_l1_blob_base_fee_per_gas, get_l1_fee_vault_address,
    get_operator_fee, get_operator_fee_vault_address,
};
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_l2_sdk::{
    COMMON_BRIDGE_L2_ADDRESS, bridge_address, calldata::encode_calldata, claim_erc20withdraw,
    claim_withdraw, compile_contract, create_deploy, deposit_erc20, get_address_alias,
    get_erc1967_slot, git_clone, wait_for_transaction_receipt,
};
use ethrex_l2_sdk::{
    FEE_TOKEN_REGISTRY_ADDRESS, L1ToL2TransactionData, L2_WITHDRAW_SIGNATURE,
    REGISTER_FEE_TOKEN_SIGNATURE, SET_FEE_TOKEN_RATIO_SIGNATURE, build_generic_tx,
    get_fee_token_ratio, get_l2_gas_limit, get_last_verified_batch, send_generic_transaction,
    wait_for_l1_message_proof, wait_for_l2_deposit_receipt,
};

use ethrex_rlp::encode::RLPEncode;
use ethrex_rpc::{
    clients::eth::{EthClient, Overrides},
    types::{
        block_identifier::{BlockIdentifier, BlockTag},
        receipt::RpcReceipt,
    },
};
use hex::FromHexError;
use reqwest::Url;
use secp256k1::SecretKey;
use std::cmp::min;
use std::ops::{Add, AddAssign};
use std::time::Duration;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};
use tokio::task::JoinSet;

use super::utils::{read_env_file_by_config, workspace_root};

/// Test the full flow of depositing, depositing with contract call, transferring, and withdrawing funds
/// from L1 to L2 and back.
/// The test can be configured with the following environment variables
///
/// RPC urls:
/// INTEGRATION_TEST_L1_RPC: The url of the l1 rpc server
/// INTEGRATION_TEST_L2_RPC: The url of the l2 rpc server
///
/// Accounts private keys:
/// ETHREX_DEPLOYER_PRIVATE_KEYS_FILE_PATH: The path to a file with pks that are rich accounts in the l2
/// INTEGRATION_TEST_PRIVATE_KEYS_FILE_PATH: The path to a file with pks that are used in the tests. (subset of the rich accounts)
/// INTEGRATION_TEST_BRIDGE_OWNER_PRIVATE_KEY: The private key of the l1 bridge owner
///
/// Contract addresses:
/// ETHREX_WATCHER_BRIDGE_ADDRESS: The address of the l1 bridge contract
/// INTEGRATION_TEST_PROPOSER_COINBASE_ADDRESS: The address of the l2 coinbase
///
/// Test parameters:
///
/// INTEGRATION_TEST_DEPOSIT_VALUE: amount in wei to deposit from L1_RICH_WALLET_PRIVATE_KEY to the l2, this amount will be deposited 3 times over the course of the test
/// INTEGRATION_TEST_TRANSFER_VALUE: amount in wei to transfer to INTEGRATION_TEST_RETURN_TRANSFER_PRIVATE_KEY, this amount will be returned to the account
/// INTEGRATION_TEST_WITHDRAW_VALUE: amount in wei to withdraw from the l2 back to the l1 from L1_RICH_WALLET_PRIVATE_KEY this will be done INTEGRATION_TEST_WITHDRAW_COUNT times
/// INTEGRATION_TEST_WITHDRAW_COUNT: amount of withdraw transactions to send
/// INTEGRATION_TEST_SKIP_TEST_TOTAL_ETH: if set the integration test will not check for total eth in the chain, only to be used if we don't know all the accounts that exist in l2
const DEFAULT_L1_RPC: &str = "http://localhost:8545";
const DEFAULT_L2_RPC: &str = "http://localhost:1729";

// 0x941e103320615d394a55708be13e45994c7d93b932b064dbcb2b511fe3254e2e
const DEFAULT_BRIDGE_OWNER_PRIVATE_KEY: H256 = H256([
    0x94, 0x1e, 0x10, 0x33, 0x20, 0x61, 0x5d, 0x39, 0x4a, 0x55, 0x70, 0x8b, 0xe1, 0x3e, 0x45, 0x99,
    0x4c, 0x7d, 0x93, 0xb9, 0x32, 0xb0, 0x64, 0xdb, 0xcb, 0x2b, 0x51, 0x1f, 0xe3, 0x25, 0x4e, 0x2e,
]);

// 0x0007a881CD95B1484fca47615B64803dad620C8d
const DEFAULT_PROPOSER_COINBASE_ADDRESS: Address = H160([
    0x00, 0x07, 0xa8, 0x81, 0xcd, 0x95, 0xb1, 0x48, 0x4f, 0xca, 0x47, 0x61, 0x5b, 0x64, 0x80, 0x3d,
    0xad, 0x62, 0x0c, 0x8d,
]);

// 0xfbec3aae8b688f85ad2d8fc10a118358254ca11d
const DEFAULT_ON_CHAIN_PROPOSER_ADDRESS: Address = H160([
    0xfb, 0xec, 0x3a, 0xae, 0x8b, 0x68, 0x8f, 0x85, 0xad, 0x2d, 0x8f, 0xc1, 0x0a, 0x11, 0x83, 0x58,
    0x25, 0x4c, 0xa1, 0x1d,
]);

const DEFAULT_RICH_KEYS_FILE_PATH: &str = "fixtures/keys/private_keys_l1.txt";
const DEFAULT_TEST_KEYS_FILE_PATH: &str = "fixtures/keys/private_keys_tests.txt";

const PREFUNDING_POLL_INTERVAL: Duration = Duration::from_secs(2);
const PREFUNDING_MAX_ATTEMPTS: u32 = 60;

#[tokio::test]
async fn l2_integration_test() -> Result<(), Box<dyn std::error::Error>> {
    read_env_file_by_config();
    let mut private_keys = get_tests_private_keys();

    let l1_client = l1_client();
    let l2_client = l2_client();

    let withdrawals_count = std::env::var("INTEGRATION_TEST_WITHDRAW_COUNT")
        .map(|amount| amount.parse().expect("Invalid withdrawal amount value"))
        .unwrap_or(5);

    wait_for_prefunded_accounts(&l2_client, &private_keys).await?;

    // Not thread-safe (fee vault and bridge balance checks).
    test_deposit(&l1_client, &l2_client, &private_keys.pop().unwrap()).await?;

    let coinbase_balance_before_tests = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let base_fee_vault = base_fee_vault(&l2_client).await;
    let base_fee_vault_balance_before_tests =
        get_fee_vault_balance(&l2_client, base_fee_vault).await;

    let operator_fee_vault = operator_fee_vault(&l2_client).await;
    let operator_fee_vault_balance_before_tests =
        get_fee_vault_balance(&l2_client, operator_fee_vault).await;

    let l1_fee_vault = l1_fee_vault(&l2_client).await;
    let l1_fee_vault_balance_before_tests = get_fee_vault_balance(&l2_client, l1_fee_vault).await;

    let mut acc_priority_fees = 0;
    let mut acc_base_fees = 0;
    let mut acc_operator_fee = 0;
    let mut acc_l1_fees = 0;

    // Non thread-safe uses owner address
    let fee_token_fees = test_fee_token(
        l2_client.clone(),
        private_keys.pop().unwrap(),
        private_keys.pop().unwrap(),
    )
    .await?;
    acc_priority_fees += fee_token_fees.priority_fees;
    acc_base_fees += fee_token_fees.base_fees;
    acc_operator_fee += fee_token_fees.operator_fees;
    acc_l1_fees += fee_token_fees.l1_fees;

    let mut set = JoinSet::new();

    set.spawn(test_upgrade(l1_client.clone(), l2_client.clone()));

    set.spawn(test_transfer(
        l2_client.clone(),
        private_keys.pop().unwrap(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_privileged_tx_with_contract_call(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_privileged_tx_with_contract_call_revert(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    // this test should go before the withdrawal ones
    // it's failure case is making a batch invalid due to invalid privileged transactions
    set.spawn(test_privileged_spammer(
        l1_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_transfer_with_privileged_tx(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_gas_burning(
        l1_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_privileged_tx_not_enough_balance(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_aliasing(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_erc20_failed_deposit(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_forced_withdrawal(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_erc20_roundtrip(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_erc20_withdraw_l1_address_mismatch(
        l1_client.clone(),
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_ecmul_precompile(
        l2_client.clone(),
        private_keys.pop().unwrap(),
    ));

    set.spawn(test_send_to_l2_exceeding_gas_limit(
        l1_client.clone(),
        private_keys.pop().unwrap(),
    ));

    while let Some(res) = set.join_next().await {
        let fees_details = res??;
        acc_priority_fees += fees_details.priority_fees;
        acc_base_fees += fees_details.base_fees;
        acc_operator_fee += fees_details.operator_fees;
        acc_l1_fees += fees_details.l1_fees;
    }

    let coinbase_balance_after_tests = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let base_fee_vault_balance_after_tests =
        get_fee_vault_balance(&l2_client, base_fee_vault).await;

    let operator_fee_vault_balance_after_tests =
        get_fee_vault_balance(&l2_client, operator_fee_vault).await;

    let l1_fee_vault_balance_after_tests = get_fee_vault_balance(&l2_client, l1_fee_vault).await;

    println!("Checking coinbase, base and operator fee vault balances");

    assert_eq!(
        coinbase_balance_after_tests,
        coinbase_balance_before_tests + acc_priority_fees,
        "Coinbase is not correct after tests"
    );

    if base_fee_vault.is_some() {
        assert_eq!(
            base_fee_vault_balance_after_tests,
            base_fee_vault_balance_before_tests + acc_base_fees,
            "Base fee vault is not correct after tests"
        );
    }

    assert_eq!(
        operator_fee_vault_balance_after_tests,
        operator_fee_vault_balance_before_tests + acc_operator_fee,
        "Operator fee vault is not correct after tests"
    );

    assert_eq!(
        l1_fee_vault_balance_after_tests,
        l1_fee_vault_balance_before_tests + acc_l1_fees,
        "L1 fee vault is not correct after tests"
    );

    // Not thread-safe (coinbase and bridge balance checks)
    test_n_withdraws(
        &l1_client,
        &l2_client,
        &private_keys.pop().unwrap(),
        withdrawals_count,
    )
    .await?;

    if std::env::var("INTEGRATION_TEST_SKIP_TEST_TOTAL_ETH").is_err() {
        test_total_eth_l2(&l1_client, &l2_client).await?;
    }

    clean_contracts_dir();

    println!("l2_integration_test is done");
    Ok(())
}

/// Test upgrading the CommonBridgeL2 contract
/// 1. Compiles the CommonBridgeL2 contract
/// 2. Deploys the new implementation on L2
/// 3. Calls the upgrade function on the L1 bridge contract
/// 4. Checks that the implementation address has changed
async fn test_upgrade(l1_client: EthClient, l2_client: EthClient) -> Result<FeesDetails> {
    println!("Testing upgrade");
    let bridge_owner_private_key = bridge_owner_private_key();
    println!("test_upgrade: Downloading openzeppelin contracts");

    let contracts_path = workspace_root().join("crates/l2/contracts");
    get_contract_dependencies(&contracts_path);
    let remappings = [(
        "@openzeppelin/contracts",
        contracts_path
            .join("lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts"),
    )];

    println!("test_upgrade: Compiling CommonBridgeL2 contract");
    compile_contract(
        &contracts_path,
        &contracts_path.join("src/l2/CommonBridgeL2.sol"),
        false,
        false,
        Some(&remappings),
        &[&contracts_path],
        None,
    )?;

    let bridge_code = hex::decode(std::fs::read(
        contracts_path.join("solc_out/CommonBridgeL2.bin"),
    )?)?;

    println!("test_upgrade: Deploying CommonBridgeL2 contract");
    let (deploy_address, fees_details) = test_deploy(
        &l2_client,
        &bridge_code,
        &bridge_owner_private_key,
        "test_upgrade",
    )
    .await?;

    let impl_slot = get_erc1967_slot("eip1967.proxy.implementation");
    let initial_impl = l2_client
        .get_storage_at(
            COMMON_BRIDGE_L2_ADDRESS,
            impl_slot,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    println!("test_upgrade: Upgrading CommonBridgeL2 contract");
    let tx_receipt = test_send(
        &l1_client,
        &bridge_owner_private_key,
        bridge_address()?,
        "upgradeL2Contract(address,address,uint256,bytes)",
        &[
            Value::Address(COMMON_BRIDGE_L2_ADDRESS),
            Value::Address(deploy_address),
            Value::Uint(U256::from(100_000)),
            Value::Bytes(Bytes::new()),
        ],
        "test_upgrade",
    )
    .await?;

    assert!(
        tx_receipt.receipt.status,
        "test_upgrade: Upgrade transaction failed"
    );

    let _ = wait_for_l2_deposit_receipt(&tx_receipt, &l1_client, &l2_client).await?;
    let final_impl = l2_client
        .get_storage_at(
            COMMON_BRIDGE_L2_ADDRESS,
            impl_slot,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;
    println!("test upgrade: upgraded {initial_impl:#x} -> {final_impl:#x}");
    assert_ne!(initial_impl, final_impl);
    Ok(fees_details)
}

/// In this test we deploy a contract on L2 and call it from L1 using the CommonBridge contract.
/// We call the contract by making a deposit from L1 to L2 with the recipient being the rich account.
/// The deposit will trigger the call to the contract.
async fn test_privileged_tx_with_contract_call(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    // pragma solidity ^0.8.27;
    // contract Test {
    //     event NumberSet(uint256 indexed number);
    //     function emitNumber(uint256 _number) public {
    //         emit NumberSet(_number);
    //     }
    // }
    let init_code = hex::decode(
        "6080604052348015600e575f5ffd5b506101008061001c5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c8063f15d140b14602a575b5f5ffd5b60406004803603810190603c919060a4565b6042565b005b807f9ec8254969d1974eac8c74afb0c03595b4ffe0a1d7ad8a7f82ed31b9c854259160405160405180910390a250565b5f5ffd5b5f819050919050565b6086816076565b8114608f575f5ffd5b50565b5f81359050609e81607f565b92915050565b5f6020828403121560b65760b56072565b5b5f60c1848285016092565b9150509291505056fea26469706673582212206f6d360696127c56e2d2a456f3db4a61e30eae0ea9b3af3c900c81ea062e8fe464736f6c634300081c0033",
    )?;

    println!("ptx_with_contract_call: Deploying contract on L2");

    let (deployed_contract_address, fees_details) = test_deploy(
        &l2_client,
        &init_code,
        &rich_wallet_private_key,
        "ptx_with_contract_call",
    )
    .await?;

    let number_to_emit = U256::from(424242);
    let calldata_to_contract: Bytes =
        encode_calldata("emitNumber(uint256)", &[Value::Uint(number_to_emit)])?.into();

    // We need to get the block number before the deposit to search for logs later.
    let first_block = l2_client.get_block_number().await?;

    println!("ptx_with_contract_call: Calling contract with deposit");

    test_call_to_contract_with_deposit(
        &l1_client,
        &l2_client,
        deployed_contract_address,
        calldata_to_contract,
        &rich_wallet_private_key,
        "ptx_with_contract_call",
    )
    .await?;

    println!("ptx_with_contract_call: Waiting for event to be emitted");

    let mut block_number = first_block;

    let topic = keccak(b"NumberSet(uint256)");

    while l2_client
        .get_logs(
            U256::from(first_block),
            U256::from(block_number),
            deployed_contract_address,
            vec![topic],
        )
        .await
        .is_ok_and(|logs| logs.is_empty())
    {
        println!("ptx_with_contract_call: Waiting for the event to be built");
        block_number += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    println!("ptx_with_contract_call: Event found in block {block_number}");

    let logs = l2_client
        .get_logs(
            U256::from(first_block),
            U256::from(block_number),
            deployed_contract_address,
            vec![topic],
        )
        .await?;

    let number_emitted = U256::from_big_endian(
        &logs
            .first()
            .unwrap()
            .log
            .topics
            .get(1)
            .unwrap()
            .to_fixed_bytes(),
    );

    assert_eq!(
        number_emitted, number_to_emit,
        "ptx_with_contract_call: Event emitted with wrong value. Expected 424242, got {number_emitted}"
    );

    Ok(fees_details)
}

/// Test the deployment of a contract on L2 and call it from L1 using the CommonBridge contract.
/// The call to the contract should revert but the deposit should be successful.
async fn test_privileged_tx_with_contract_call_revert(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    // pragma solidity ^0.8.27;
    // contract RevertTest {
    //     function revert_call() public {
    //         revert("Reverted");
    //     }
    // }
    let init_code = hex::decode(
        "6080604052348015600e575f5ffd5b506101138061001c5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c806311ebce9114602a575b5f5ffd5b60306032565b005b6040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160629060c1565b60405180910390fd5b5f82825260208201905092915050565b7f52657665727465640000000000000000000000000000000000000000000000005f82015250565b5f60ad600883606b565b915060b682607b565b602082019050919050565b5f6020820190508181035f83015260d68160a3565b905091905056fea2646970667358221220903f571921ce472f979989f9135b8637314b68e080fd70d0da6ede87ad8b5bd564736f6c634300081c0033",
    )?;

    println!("ptx_with_contract_call_revert: Deploying contract on L2");

    let (deployed_contract_address, fees_details) = test_deploy(
        &l2_client,
        &init_code,
        &rich_wallet_private_key,
        "ptx_with_contract_call_revert",
    )
    .await?;

    let calldata_to_contract: Bytes = encode_calldata("revert_call()", &[])?.into();

    println!("ptx_with_contract_call_revert: Calling contract with deposit");

    test_call_to_contract_with_deposit(
        &l1_client,
        &l2_client,
        deployed_contract_address,
        calldata_to_contract,
        &rich_wallet_private_key,
        "ptx_with_contract_call_revert",
    )
    .await?;

    Ok(fees_details)
}

/// Test that the ECMUL precompile result is stored on-chain correctly.
/// Deploys a contract that calls the ECMUL precompile (0x07) and writes
/// the result to storage. This makes the precompile output affect the
/// state root, so if the prover guest computes a different result than
/// the sequencer (e.g. Jacobian vs affine coordinates), the proof will
/// fail with a state root mismatch.
async fn test_ecmul_precompile(
    l2_client: EthClient,
    deployer_pk: SecretKey,
) -> Result<FeesDetails> {
    let contracts_path = workspace_root().join("crates/l2/contracts/src/example");

    println!("test_ecmul_precompile: Compiling EcmulStore contract");

    compile_contract(
        &contracts_path,
        &contracts_path.join("EcmulStore.sol"),
        false,
        false,
        None,
        &[],
        None,
    )?;

    let init_code = hex::decode(std::fs::read(
        contracts_path.join("solc_out/EcmulStore.bin"),
    )?)?;

    println!("test_ecmul_precompile: Deploying EcmulStore contract on L2");

    let (contract_address, mut fees_details) = test_deploy(
        &l2_client,
        &init_code,
        &deployer_pk,
        "test_ecmul_precompile",
    )
    .await?;

    // Call ecmulAndStore(1, 2, 7) — BN254 G1 generator (1, 2) * scalar 7
    let calldata: Bytes = encode_calldata(
        "ecmulAndStore(uint256,uint256,uint256)",
        &[
            Value::Uint(U256::one()),
            Value::Uint(U256::from(2)),
            Value::Uint(U256::from(7)),
        ],
    )?
    .into();

    println!("test_ecmul_precompile: Calling ecmulAndStore(1, 2, 7)");

    let signer: Signer = LocalSigner::new(deployer_pk).into();

    let tx = build_generic_tx(
        &l2_client,
        TxType::EIP1559,
        contract_address,
        signer.address(),
        calldata.clone(),
        Overrides::default(),
    )
    .await?;

    let tx_hash = send_generic_transaction(&l2_client, tx, &signer).await?;
    let tx_receipt = wait_for_transaction_receipt(tx_hash, &l2_client, 50).await?;

    assert!(
        tx_receipt.receipt.status,
        "test_ecmul_precompile: ecmulAndStore transaction failed"
    );

    let call_tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(contract_address),
        data: calldata,
        ..Default::default()
    });
    let transaction_size: u64 = call_tx.encode_to_vec().len().try_into().unwrap();
    fees_details += get_fees_details_l2(&tx_receipt, &l2_client, transaction_size).await?;

    // Read stored results from contract storage
    let stored_x = l2_client
        .get_storage_at(
            contract_address,
            U256::zero(), // slot 0: storedX
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    let stored_y = l2_client
        .get_storage_at(
            contract_address,
            U256::one(), // slot 1: storedY
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert!(
        !stored_x.is_zero(),
        "test_ecmul_precompile: storedX is zero — ECMUL returned the point at infinity"
    );
    assert!(
        !stored_y.is_zero(),
        "test_ecmul_precompile: storedY is zero — ECMUL returned the point at infinity"
    );

    println!("test_ecmul_precompile: ECMUL result stored — x={stored_x:#x}, y={stored_y:#x}");

    Ok(fees_details)
}

async fn find_withdrawal_with_widget(
    bridge_address: Address,
    l2tx: H256,
    l2_client: &EthClient,
    l1_client: &EthClient,
) -> Option<L2ToL1MessageRow> {
    let mut widget = L2ToL1MessagesTable::new(bridge_address);
    widget.on_tick(l1_client, l2_client).await.unwrap();
    widget
        .items
        .iter()
        .find(|row| row.l2_tx_hash == l2tx)
        .cloned()
}

/// Tests the full roundtrip of an ERC20 token from L1 to L2 and back
/// 1. Deploys an ERC20 token on L1
/// 2. Deploys an ERC20 token on L2 that points to the L1 token
/// 3. Mints some tokens on L1
/// 4. Deposits the tokens to L2 through the bridge
/// 5. Withdraws the tokens back to L1
/// 6. Checks that the balances are correct at each step
/// 7. Checks that the withdrawal is correctly recorded in the L2ToL1MessagesTable widget
async fn test_erc20_roundtrip(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    let token_amount: U256 = U256::from(100);

    let rich_wallet_signer: Signer = LocalSigner::new(rich_wallet_private_key).into();
    let rich_address = rich_wallet_signer.address();

    let init_code_l1 = hex::decode(std::fs::read(
        workspace_root().join("fixtures/contracts/ERC20/ERC20.bin/TestToken.bin"),
    )?)?;

    println!("test_erc20_roundtrip: Deploying ERC20 token on L1");
    let token_l1 = test_deploy_l1(&l1_client, &init_code_l1, &rich_wallet_private_key).await?;

    let contracts_path = workspace_root().join("crates/l2/contracts");
    let compile_output_path = contracts_path.join("test_erc20_roundtrip");

    get_contract_dependencies(&contracts_path);
    let remappings = [(
        "@openzeppelin/contracts",
        contracts_path
            .join("lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts"),
    )];
    compile_contract(
        &compile_output_path,
        &contracts_path.join("src/example/L2ERC20.sol"),
        false,
        false,
        Some(&remappings),
        &[&contracts_path],
        None,
    )?;
    let init_code_l2_inner = hex::decode(String::from_utf8(std::fs::read(
        compile_output_path.join("solc_out/TestTokenL2.bin"),
    )?)?)?;
    let init_code_l2 = [
        init_code_l2_inner,
        vec![0u8; 12],
        token_l1.to_fixed_bytes().to_vec(),
    ]
    .concat();

    let (token_l2, deploy_fees) = test_deploy(
        &l2_client,
        &init_code_l2,
        &rich_wallet_private_key,
        "test_erc20_roundtrip",
    )
    .await?;

    println!("test_erc20_roundtrip: token l1={token_l1:x}, l2={token_l2:x}");
    test_send(
        &l1_client,
        &rich_wallet_private_key,
        token_l1,
        "freeMint()",
        &[],
        "test_erc20_roundtrip",
    )
    .await?;
    test_send(
        &l1_client,
        &rich_wallet_private_key,
        token_l1,
        "approve(address,uint256)",
        &[Value::Address(bridge_address()?), Value::Uint(token_amount)],
        "test_erc20_roundtrip",
    )
    .await?;

    println!("test_erc20_roundtrip: Depositing ERC20 token from L1 to L2");
    let initial_balance = test_balance_of(&l1_client, token_l1, rich_address).await;
    let deposit_tx = deposit_erc20(
        token_l1,
        token_l2,
        token_amount,
        rich_address,
        &rich_wallet_signer,
        &l1_client,
    )
    .await
    .unwrap();

    println!("test_erc20_roundtrip: Waiting for deposit transaction receipt on L1");
    let res = wait_for_transaction_receipt(deposit_tx, &l1_client, 10)
        .await
        .unwrap();

    assert!(res.receipt.status);

    println!("test_erc20_roundtrip: Waiting for deposit transaction receipt on L2");

    let l2_receipt = wait_for_l2_deposit_receipt(&res, &l1_client, &l2_client)
        .await
        .unwrap();

    assert!(l2_receipt.receipt.status);

    let remaining_l1_balance = test_balance_of(&l1_client, token_l1, rich_address).await;
    let l2_balance = test_balance_of(&l2_client, token_l2, rich_address).await;
    assert_eq!(initial_balance - remaining_l1_balance, token_amount);
    assert_eq!(l2_balance, token_amount);

    println!("test_erc20_roundtrip: Withdrawing ERC20 token from L2 to L1");

    let signature = "approve(address,uint256)";
    let data = [
        Value::Address(COMMON_BRIDGE_L2_ADDRESS),
        Value::Uint(token_amount),
    ];

    let approve_receipt = test_send(
        &l2_client,
        &rich_wallet_private_key,
        token_l2,
        signature,
        &data,
        "test_erc20_roundtrip 1",
    )
    .await?;

    let transaction_size = calculate_transaction_size(encode_calldata(signature, &data)?.into());
    let approve_fees = get_fees_details_l2(&approve_receipt, &l2_client, transaction_size).await?;

    let signature = "withdrawERC20(address,address,address,uint256)";
    let data = [
        Value::Address(token_l1),
        Value::Address(token_l2),
        Value::Address(rich_address),
        Value::Uint(token_amount),
    ];

    let withdraw_receipt = test_send(
        &l2_client,
        &rich_wallet_private_key,
        COMMON_BRIDGE_L2_ADDRESS,
        signature,
        &data,
        "test_erc20_roundtrip 2",
    )
    .await?;

    let transaction_size = calculate_transaction_size(encode_calldata(signature, &data)?.into());
    let withdraw_fees =
        get_fees_details_l2(&withdraw_receipt, &l2_client, transaction_size).await?;

    let withdrawal_tx_hash = withdraw_receipt.tx_info.transaction_hash;
    assert_eq!(
        find_withdrawal_with_widget(
            bridge_address()?,
            withdrawal_tx_hash,
            &l2_client,
            &l1_client,
        )
        .await
        .unwrap(),
        L2ToL1MessageRow {
            status: L2ToL1MessageStatus::WithdrawalInitiated,
            kind: L2ToL1MessageKind::ERC20Withdraw,
            receiver: rich_address,
            token_l1,
            token_l2,
            value: token_amount,
            l2_tx_hash: withdrawal_tx_hash
        }
    );

    let proof = wait_for_verified_proof(
        &l1_client,
        &l2_client,
        withdraw_receipt.tx_info.transaction_hash,
    )
    .await;

    println!("test_erc20_roundtrip: Claiming withdrawal on L1");

    let withdraw_claim_tx = claim_erc20withdraw(
        token_l1,
        token_l2,
        token_amount,
        &rich_wallet_signer,
        &l1_client,
        &proof,
    )
    .await
    .expect("error while claiming");
    wait_for_transaction_receipt(withdraw_claim_tx, &l1_client, 5).await?;
    assert_eq!(
        find_withdrawal_with_widget(
            bridge_address()?,
            withdrawal_tx_hash,
            &l2_client,
            &l1_client,
        )
        .await
        .unwrap(),
        L2ToL1MessageRow {
            status: L2ToL1MessageStatus::WithdrawalClaimed,
            kind: L2ToL1MessageKind::ERC20Withdraw,
            receiver: rich_address,
            token_l1,
            token_l2,
            value: token_amount,
            l2_tx_hash: withdrawal_tx_hash
        }
    );

    let l1_final_balance = test_balance_of(&l1_client, token_l1, rich_address).await;
    let l2_final_balance = test_balance_of(&l2_client, token_l2, rich_address).await;
    assert_eq!(initial_balance, l1_final_balance);
    assert!(l2_final_balance.is_zero());
    Ok(deploy_fees + approve_fees + withdraw_fees)
}

/// Tests that withdrawERC20 reverts when the provided L1 address doesn't match the token's l1Address()
/// 1. Deploys an ERC20 token on L1 and L2
/// 2. Deposits tokens from L1 to L2
/// 3. Attempts to withdraw with a mismatched L1 address
/// 4. Verifies that the transaction reverts
async fn test_erc20_withdraw_l1_address_mismatch(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    let token_amount: U256 = U256::from(100);

    let rich_wallet_signer: Signer = LocalSigner::new(rich_wallet_private_key).into();
    let rich_address = rich_wallet_signer.address();

    let init_code_l1 = hex::decode(std::fs::read(
        workspace_root().join("fixtures/contracts/ERC20/ERC20.bin/TestToken.bin"),
    )?)?;

    println!("test_erc20_withdraw_l1_address_mismatch: Deploying ERC20 token on L1");
    let token_l1 = test_deploy_l1(&l1_client, &init_code_l1, &rich_wallet_private_key).await?;

    let contracts_path = workspace_root().join("crates/l2/contracts");
    let compile_output_path = contracts_path.join("test_erc20_mismatch");

    get_contract_dependencies(&contracts_path);
    let remappings = [(
        "@openzeppelin/contracts",
        contracts_path
            .join("lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts"),
    )];
    compile_contract(
        &compile_output_path,
        &contracts_path.join("src/example/L2ERC20.sol"),
        false,
        false,
        Some(&remappings),
        &[&contracts_path],
        None,
    )?;
    let init_code_l2_inner = hex::decode(String::from_utf8(std::fs::read(
        compile_output_path.join("solc_out/TestTokenL2.bin"),
    )?)?)?;
    let init_code_l2 = [
        init_code_l2_inner,
        vec![0u8; 12],
        token_l1.to_fixed_bytes().to_vec(),
    ]
    .concat();

    let (token_l2, deploy_fees) = test_deploy(
        &l2_client,
        &init_code_l2,
        &rich_wallet_private_key,
        "test_erc20_withdraw_l1_address_mismatch",
    )
    .await?;

    println!("test_erc20_withdraw_l1_address_mismatch: token l1={token_l1:x}, l2={token_l2:x}");

    // Approve tokens on L1 (tokens already minted during deployment)
    test_send(
        &l1_client,
        &rich_wallet_private_key,
        token_l1,
        "approve(address,uint256)",
        &[Value::Address(bridge_address()?), Value::Uint(token_amount)],
        "test_erc20_withdraw_l1_address_mismatch",
    )
    .await?;

    println!("test_erc20_withdraw_l1_address_mismatch: Depositing ERC20 token from L1 to L2");
    let deposit_tx = deposit_erc20(
        token_l1,
        token_l2,
        token_amount,
        rich_address,
        &rich_wallet_signer,
        &l1_client,
    )
    .await
    .unwrap();

    let res = wait_for_transaction_receipt(deposit_tx, &l1_client, 10)
        .await
        .unwrap();
    assert!(res.receipt.status);

    let l2_receipt = wait_for_l2_deposit_receipt(&res, &l1_client, &l2_client)
        .await
        .unwrap();
    assert!(l2_receipt.receipt.status);

    let l2_balance = test_balance_of(&l2_client, token_l2, rich_address).await;
    assert_eq!(l2_balance, token_amount);

    println!("test_erc20_withdraw_l1_address_mismatch: Approving L2 bridge to spend tokens");
    let approve_receipt = test_send(
        &l2_client,
        &rich_wallet_private_key,
        token_l2,
        "approve(address,uint256)",
        &[
            Value::Address(COMMON_BRIDGE_L2_ADDRESS),
            Value::Uint(token_amount),
        ],
        "test_erc20_withdraw_l1_address_mismatch",
    )
    .await?;

    let transaction_size = calculate_transaction_size(
        encode_calldata(
            "approve(address,uint256)",
            &[
                Value::Address(COMMON_BRIDGE_L2_ADDRESS),
                Value::Uint(token_amount),
            ],
        )?
        .into(),
    );
    let approve_fees = get_fees_details_l2(&approve_receipt, &l2_client, transaction_size).await?;

    // Use a wrong L1 address (not matching token_l2's l1Address())
    let wrong_token_l1 = Address::random();
    println!(
        "test_erc20_withdraw_l1_address_mismatch: Attempting withdrawal with wrong L1 address {wrong_token_l1:x}"
    );

    let signature = "withdrawERC20(address,address,address,uint256)";
    let data = [
        Value::Address(wrong_token_l1), // Wrong L1 address
        Value::Address(token_l2),
        Value::Address(rich_address),
        Value::Uint(token_amount),
    ];

    // Verify the revert reason using eth_call before sending the transaction
    let calldata: Bytes = encode_calldata(signature, &data)?.into();
    // Get the current nonce for the eth_call
    let nonce = l2_client
        .get_nonce(rich_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    let call_result = l2_client
        .call(
            COMMON_BRIDGE_L2_ADDRESS,
            calldata.clone(),
            Overrides {
                from: Some(rich_address),
                nonce: Some(nonce),
                ..Default::default()
            },
        )
        .await;
    assert!(
        call_result.is_err(),
        "Expected eth_call to fail due to L1 address mismatch"
    );
    let error_message = call_result.unwrap_err().to_string();
    assert!(
        error_message.contains("L1 address mismatch"),
        "Expected revert reason to contain 'L1 address mismatch', got: {error_message}"
    );

    // Send the transaction with a fixed gas limit (gas estimation fails for reverting txs)
    let withdraw_tx = build_generic_tx(
        &l2_client,
        TxType::EIP1559,
        COMMON_BRIDGE_L2_ADDRESS,
        rich_address,
        calldata.clone(),
        Overrides {
            gas_limit: Some(500_000),
            ..Default::default()
        },
    )
    .await?;
    let withdraw_tx_hash =
        send_generic_transaction(&l2_client, withdraw_tx, &rich_wallet_signer).await?;
    let withdraw_receipt =
        ethrex_l2_sdk::wait_for_transaction_receipt(withdraw_tx_hash, &l2_client, 1000).await?;

    // The transaction should revert
    assert!(
        !withdraw_receipt.receipt.status,
        "Expected withdrawal to revert due to L1 address mismatch, but it succeeded"
    );

    // Calculate withdraw fees (reverted txs still pay gas)
    let transaction_size = calculate_transaction_size(calldata);
    let withdraw_fees =
        get_fees_details_l2(&withdraw_receipt, &l2_client, transaction_size).await?;

    // Verify that the user's L2 balance is unchanged (tokens were not burned)
    let l2_balance_after = test_balance_of(&l2_client, token_l2, rich_address).await;
    assert_eq!(
        l2_balance_after, token_amount,
        "L2 balance should be unchanged after failed withdrawal"
    );

    println!("test_erc20_withdraw_l1_address_mismatch: Withdrawal correctly reverted");
    Ok(deploy_fees + approve_fees + withdraw_fees)
}

/// Tests that the aliasing is done correctly when calling from L1 to L2
/// 1. Deploys a contract on L1 that will call the CommonBridge contract sendToL2 function
/// 2. Calls the contract to send a message to L2
/// 3. Checks that the message was sent from the aliased address
async fn test_aliasing(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!("Testing aliasing");
    let init_code_l1 = hex::decode(std::fs::read(
        workspace_root().join("fixtures/contracts/caller/Caller.bin"),
    )?)?;
    let caller_l1 = test_deploy_l1(&l1_client, &init_code_l1, &rich_wallet_private_key).await?;
    let send_to_l2_calldata = encode_calldata(
        "sendToL2((address,uint256,uint256,bytes))",
        &[Value::Tuple(vec![
            Value::Address(H160::zero()),
            Value::Uint(U256::from(100_000)),
            Value::Uint(U256::zero()),
            Value::Bytes(Bytes::new()),
        ])],
    )?;

    println!("test_aliasing: Sending call to L2");
    let receipt_l1 = test_send(
        &l1_client,
        &rich_wallet_private_key,
        caller_l1,
        "doCall(address,bytes)",
        &[
            Value::Address(bridge_address()?),
            Value::Bytes(send_to_l2_calldata.into()),
        ],
        "test_aliasing",
    )
    .await?;

    assert!(receipt_l1.receipt.status);

    let receipt_l2 = wait_for_l2_deposit_receipt(&receipt_l1, &l1_client, &l2_client)
        .await
        .unwrap();
    println!(
        "test_aliasing: alising {:#x} to {:#x}",
        get_address_alias(caller_l1),
        receipt_l2.tx_info.from
    );
    assert_eq!(receipt_l2.tx_info.from, get_address_alias(caller_l1));
    Ok(FeesDetails::default())
}

/// Tests that a failed deposit can be withdrawn back to L1
/// 1. Deploys an ERC20 token on L1
/// 2. Attempts to deposit the token to an invalid address on L2
/// 3. Claims the withdrawal on L1
async fn test_erc20_failed_deposit(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    let token_amount: U256 = U256::from(100);

    let rich_wallet_signer: Signer = LocalSigner::new(rich_wallet_private_key).into();
    let rich_address = rich_wallet_signer.address();

    let init_code_l1 = hex::decode(std::fs::read(
        workspace_root().join("fixtures/contracts/ERC20/ERC20.bin/TestToken.bin"),
    )?)?;

    println!("test_erc20_failed_deposit: Deploying ERC20 token on L1");
    let token_l1 = test_deploy_l1(&l1_client, &init_code_l1, &rich_wallet_private_key).await?;
    let token_l2 = Address::random(); // will cause deposit to fail

    println!("test_erc20_failed_deposit: token l1={token_l1:x}, l2={token_l2:x}");

    test_send(
        &l1_client,
        &rich_wallet_private_key,
        token_l1,
        "freeMint()",
        &[],
        "test_erc20_failed_deposit",
    )
    .await?;
    test_send(
        &l1_client,
        &rich_wallet_private_key,
        token_l1,
        "approve(address,uint256)",
        &[Value::Address(bridge_address()?), Value::Uint(token_amount)],
        "test_erc20_failed_deposit",
    )
    .await?;

    println!("test_erc20_failed_deposit: Depositing ERC20 token from L1 to L2");

    let initial_balance = test_balance_of(&l1_client, token_l1, rich_address).await;
    let deposit_tx = deposit_erc20(
        token_l1,
        token_l2,
        token_amount,
        rich_address,
        &rich_wallet_signer,
        &l1_client,
    )
    .await
    .unwrap();

    println!("test_erc20_failed_deposit: Waiting for deposit transaction receipt on L1");

    let res = wait_for_transaction_receipt(deposit_tx, &l1_client, 10)
        .await
        .unwrap();

    assert!(res.receipt.status);

    println!("test_erc20_failed_deposit: Waiting for deposit transaction receipt on L2");

    let res = wait_for_l2_deposit_receipt(&res, &l1_client, &l2_client)
        .await
        .unwrap();

    let proof = wait_for_verified_proof(&l1_client, &l2_client, res.tx_info.transaction_hash).await;

    println!("test_erc20_failed_deposit: Claiming withdrawal on L1");

    let withdraw_claim_tx = claim_erc20withdraw(
        token_l1,
        token_l2,
        token_amount,
        &rich_wallet_signer,
        &l1_client,
        &proof,
    )
    .await
    .expect("error while claiming");
    wait_for_transaction_receipt(withdraw_claim_tx, &l1_client, 5).await?;
    let l1_final_balance = test_balance_of(&l1_client, token_l1, rich_address).await;
    assert_eq!(initial_balance, l1_final_balance);
    Ok(FeesDetails::default())
}

/// Tests that a withdrawal can be triggered by a privileged transaction
/// This ensures the sequencer can't censor withdrawals without stopping the network
async fn test_forced_withdrawal(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!("forced_withdrawal: Testing forced withdrawal");
    let rich_address = get_address_from_secret_key(&rich_wallet_private_key.secret_bytes())
        .expect("Failed to get address");
    let l1_initial_balance = l1_client
        .get_balance(rich_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    let l2_initial_balance = l2_client
        .get_balance(rich_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    let transfer_value = U256::from(100);
    let mut l1_gas_costs = 0;

    let calldata = encode_calldata("withdraw(address)", &[Value::Address(rich_address)])?;

    println!("forced_withdrawal: Sending L1 to L2 transaction");

    let l1_to_l2_tx_hash = ethrex_l2_sdk::send_l1_to_l2_tx(
        rich_address,
        Some(0),
        None,
        L1ToL2TransactionData::new(
            COMMON_BRIDGE_L2_ADDRESS,
            21000 * 5,
            transfer_value,
            Bytes::from(calldata),
        ),
        &rich_wallet_private_key,
        bridge_address()?,
        &l1_client,
    )
    .await?;

    println!("forced_withdrawal: Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt = wait_for_transaction_receipt(l1_to_l2_tx_hash, &l1_client, 5).await?;

    assert!(l1_to_l2_tx_receipt.receipt.status);

    l1_gas_costs +=
        l1_to_l2_tx_receipt.tx_info.gas_used * l1_to_l2_tx_receipt.tx_info.effective_gas_price;
    println!("forced_withdrawal: Waiting for L1 to L2 transaction receipt on L2");

    let res = wait_for_l2_deposit_receipt(&l1_to_l2_tx_receipt, &l1_client, &l2_client).await?;

    let withdrawal_tx_hash = res.tx_info.transaction_hash;
    assert_eq!(
        find_withdrawal_with_widget(
            bridge_address()?,
            withdrawal_tx_hash,
            &l2_client,
            &l1_client,
        )
        .await
        .unwrap(),
        L2ToL1MessageRow {
            status: L2ToL1MessageStatus::WithdrawalInitiated,
            kind: L2ToL1MessageKind::ETHWithdraw,
            receiver: rich_address,
            token_l1: Default::default(),
            token_l2: Default::default(),
            value: transfer_value,
            l2_tx_hash: withdrawal_tx_hash
        }
    );

    let l2_final_balance = l2_client
        .get_balance(rich_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("forced_withdrawal: Waiting for withdrawal proof on L2");
    let proof = wait_for_verified_proof(&l1_client, &l2_client, res.tx_info.transaction_hash).await;

    println!("forced_withdrawal: Claiming withdrawal on L1");

    let withdraw_claim_tx = claim_withdraw(
        transfer_value,
        rich_address,
        rich_wallet_private_key,
        &l1_client,
        &proof,
    )
    .await
    .expect("forced_withdrawal: error while claiming");
    let res = wait_for_transaction_receipt(withdraw_claim_tx, &l1_client, 5).await?;
    l1_gas_costs += res.tx_info.gas_used * res.tx_info.effective_gas_price;
    assert_eq!(
        find_withdrawal_with_widget(
            bridge_address()?,
            withdrawal_tx_hash,
            &l2_client,
            &l1_client
        )
        .await
        .unwrap(),
        L2ToL1MessageRow {
            status: L2ToL1MessageStatus::WithdrawalClaimed,
            kind: L2ToL1MessageKind::ETHWithdraw,
            receiver: rich_address,
            token_l1: Default::default(),
            token_l2: Default::default(),
            value: transfer_value,
            l2_tx_hash: withdrawal_tx_hash
        }
    );

    let l1_final_balance = l1_client
        .get_balance(rich_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    assert_eq!(
        l1_initial_balance + transfer_value - l1_gas_costs,
        l1_final_balance
    );
    assert_eq!(l2_initial_balance - transfer_value, l2_final_balance);
    Ok(FeesDetails::default())
}

async fn test_balance_of(client: &EthClient, token: Address, user: Address) -> U256 {
    let res = client
        .call(
            token,
            encode_calldata("balanceOf(address)", &[Value::Address(user)])
                .unwrap()
                .into(),
            Default::default(),
        )
        .await
        .unwrap();
    U256::from_str_radix(res.trim_start_matches("0x"), 16).unwrap()
}

async fn test_balance_of_optional(
    client: &EthClient,
    token: Address,
    user: Option<Address>,
) -> U256 {
    if let Some(user) = user {
        test_balance_of(client, token, user).await
    } else {
        U256::zero()
    }
}

async fn test_send(
    client: &EthClient,
    private_key: &SecretKey,
    to: Address,
    signature: &str,
    data: &[Value],
    test: &str,
) -> Result<RpcReceipt> {
    let signer: Signer = LocalSigner::new(*private_key).into();
    let calldata = encode_calldata(signature, data).unwrap().into();
    let mut tx = build_generic_tx(
        client,
        TxType::EIP1559,
        to,
        signer.address(),
        calldata,
        Default::default(),
    )
    .await
    .with_context(|| format!("Failed to build tx for {test}"))?;
    tx.gas = tx.gas.map(|g| g * 6 / 5); // (+20%) tx reverts in some cases otherwise
    let tx_hash = send_generic_transaction(client, tx, &signer).await.unwrap();
    ethrex_l2_sdk::wait_for_transaction_receipt(tx_hash, client, 1000)
        .await
        .with_context(|| format!("Failed to get receipt for {test}"))
}

/// Test depositing ETH from L1 to L2
/// 1. Fetch initial balances of depositor on L1, recipient on L2, bridge on L1 and coinbase, base and operator fee vault on L2
/// 2. Perform deposit from L1 to L2
/// 3. Check final balances.
async fn test_deposit(
    l1_client: &EthClient,
    l2_client: &EthClient,
    rich_wallet_private_key: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("test_deposit: Fetching initial balances on L1 and L2");
    let rich_wallet_address = get_address_from_secret_key(&rich_wallet_private_key.secret_bytes())
        .expect("Failed to get address from l1 rich wallet pk");

    let deposit_value = std::env::var("INTEGRATION_TEST_DEPOSIT_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid deposit value"))
        .unwrap_or(U256::from(1000000000000000000000u128));

    let depositor_l1_initial_balance = l1_client
        .get_balance(rich_wallet_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        depositor_l1_initial_balance >= deposit_value,
        "L1 depositor doesn't have enough balance to deposit"
    );

    let deposit_recipient_l2_initial_balance = l2_client
        .get_balance(rich_wallet_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!(
        "test_deposit: rich_wallet_address={rich_wallet_address:#x}, initial L2 balance={deposit_recipient_l2_initial_balance} wei"
    );

    let bridge_initial_balance = l1_client
        .get_balance(bridge_address()?, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let coinbase_balance_before_deposit = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let base_fee_vault = base_fee_vault(l2_client).await;
    let base_fee_vault_balance_before_deposit =
        get_fee_vault_balance(l2_client, base_fee_vault).await;

    let operator_fee_vault = operator_fee_vault(l2_client).await;
    let operator_fee_vault_balance_before_deposit =
        get_fee_vault_balance(l2_client, operator_fee_vault).await;

    println!("test_deposit: Depositing funds from L1 to L2");

    let deposit_tx_hash = ethrex_l2_sdk::deposit_through_transfer(
        deposit_value,
        rich_wallet_address,
        rich_wallet_private_key,
        l1_client,
    )
    .await?;

    println!("test_deposit: Waiting for L1 deposit transaction receipt");

    let deposit_tx_receipt =
        ethrex_l2_sdk::wait_for_transaction_receipt(deposit_tx_hash, l1_client, 50).await?;

    let gas_used = deposit_tx_receipt.tx_info.gas_used;

    assert!(
        deposit_tx_receipt.receipt.status,
        "Deposit transaction failed. Gas used: {gas_used}",
    );

    let depositor_l1_balance_after_deposit = l1_client
        .get_balance(rich_wallet_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        depositor_l1_balance_after_deposit,
        depositor_l1_initial_balance
            - deposit_value
            - deposit_tx_receipt.tx_info.gas_used * deposit_tx_receipt.tx_info.effective_gas_price,
        "Depositor L1 balance didn't decrease as expected after deposit"
    );

    let bridge_balance_after_deposit = l1_client
        .get_balance(bridge_address()?, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        bridge_balance_after_deposit,
        bridge_initial_balance + deposit_value,
        "Bridge balance didn't increase as expected after deposit"
    );

    println!("test_deposit: Waiting for L2 deposit tx receipt");

    let l2_receipt = wait_for_l2_deposit_receipt(&deposit_tx_receipt, l1_client, l2_client).await?;
    assert!(l2_receipt.receipt.status, "L2 deposit transaction failed.");

    let deposit_recipient_l2_balance_after_deposit = l2_client
        .get_balance(rich_wallet_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        deposit_recipient_l2_balance_after_deposit,
        deposit_recipient_l2_initial_balance + deposit_value,
        "Deposit recipient L2 balance didn't increase as expected after deposit"
    );

    let coinbase_balance_after_deposit = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let base_fee_vault_balance_after_deposit =
        get_fee_vault_balance(l2_client, base_fee_vault).await;

    let operator_fee_vault_balance_after_deposit =
        get_fee_vault_balance(l2_client, operator_fee_vault).await;

    assert_eq!(
        coinbase_balance_after_deposit, coinbase_balance_before_deposit,
        "Coinbase balance should not change after deposit"
    );

    assert_eq!(
        base_fee_vault_balance_after_deposit, base_fee_vault_balance_before_deposit,
        "Base fee vault balance should not change after deposit"
    );

    assert_eq!(
        operator_fee_vault_balance_after_deposit, operator_fee_vault_balance_before_deposit,
        "Operator vault balance should not change after deposit"
    );

    Ok(())
}

async fn test_privileged_spammer(
    l1_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    let init_code_l1 = hex::decode(std::fs::read(
        workspace_root().join("fixtures/contracts/deposit_spammer/DepositSpammer.bin"),
    )?)?;
    let caller_l1 = test_deploy_l1(&l1_client, &init_code_l1, &rich_wallet_private_key).await?;
    for _ in 0..50 {
        test_send(
            &l1_client,
            &rich_wallet_private_key,
            caller_l1,
            "spam(address,uint256)",
            &[Value::Address(bridge_address()?), Value::Uint(5.into())],
            "test_privileged_spammer",
        )
        .await?;
    }
    Ok(FeesDetails::default())
}

/// Test transferring ETH on L2
/// 1. Fetch initial balances of transferer and returner on L2.
/// 2. Perform transfer from transferer to returner.
/// 3. Perform return transfer from returner to transferer.
/// 4. Check final balances.
async fn test_transfer(
    l2_client: EthClient,
    transferer_private_key: SecretKey,
    returnerer_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!("test_transfer: Transferring funds on L2");
    let transferer_address =
        get_address_from_secret_key(&transferer_private_key.secret_bytes()).unwrap();
    let returner_address =
        get_address_from_secret_key(&returnerer_private_key.secret_bytes()).unwrap();

    println!(
        "test_transfer: Performing transfer from {transferer_address:#x} to {returner_address:#x}"
    );

    let mut fees_details = perform_transfer(
        &l2_client,
        &transferer_private_key,
        returner_address,
        transfer_value(),
        "test_transfer",
    )
    .await?;

    println!("test_transfer: Calculating return amount for return transfer");
    // Only return 99% of the transfer, other amount is for fees
    let return_amount = (transfer_value() * 99) / 100;

    println!(
        "test_transfer: Performing return transfer from {returner_address:#x} to {transferer_address:#x} with amount {return_amount}"
    );

    fees_details += perform_transfer(
        &l2_client,
        &returnerer_private_key,
        transferer_address,
        return_amount,
        "test_transfer",
    )
    .await?;

    Ok(fees_details)
}

/// Test transferring ETH on L2 through a privileged transaction (deposit from L1)
/// 1. Fetch initial balance of receiver on L2.
/// 2. Perform transfer through a deposit.
/// 3. Check final balance of receiver on L2.
async fn test_transfer_with_privileged_tx(
    l1_client: EthClient,
    l2_client: EthClient,
    transferer_private_key: SecretKey,
    receiver_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!("transfer_with_ptx: Transferring funds on L2 through a deposit");
    let transferer_address =
        get_address_from_secret_key(&transferer_private_key.secret_bytes()).unwrap();
    let receiver_address =
        get_address_from_secret_key(&receiver_private_key.secret_bytes()).unwrap();

    println!("transfer_with_ptx: Fetching receiver's initial balance on L2");

    let receiver_balance_before = l2_client
        .get_balance(receiver_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!(
        "transfer_with_ptx: Performing transfer through deposit from {transferer_address:#x} to {receiver_address:#x}."
    );

    let l1_to_l2_tx_hash = ethrex_l2_sdk::send_l1_to_l2_tx(
        transferer_address,
        Some(0),
        None,
        L1ToL2TransactionData::new(receiver_address, 21000 * 5, transfer_value(), Bytes::new()),
        &transferer_private_key,
        bridge_address()?,
        &l1_client,
    )
    .await?;

    println!("transfer_with_ptx: Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt =
        wait_for_transaction_receipt(l1_to_l2_tx_hash, &l1_client, 50).await?;

    assert!(
        l1_to_l2_tx_receipt.receipt.status,
        "Transfer transaction failed"
    );

    println!("transfer_with_ptx: Waiting for L1 to L2 transaction receipt on L2");

    let _ = wait_for_l2_deposit_receipt(&l1_to_l2_tx_receipt, &l1_client, &l2_client).await?;

    println!("transfer_with_ptx: Checking balances after transfer");

    let receiver_balance_after = l2_client
        .get_balance(receiver_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    assert_eq!(
        receiver_balance_after,
        receiver_balance_before + transfer_value()
    );
    Ok(FeesDetails::default())
}

/// Test that gas is burned from the L1 account when making a deposit with a specified L2 gas limit.
/// 1. Perform deposit with specified L2 gas limit.
/// 2. Check that the gas used on L1 is within expected range.
async fn test_gas_burning(
    l1_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!("test_gas_burning: Transferring funds on L2 through a deposit");
    let rich_address =
        get_address_from_secret_key(&rich_wallet_private_key.secret_bytes()).unwrap();
    let l2_gas_limit = 2_000_000;
    let l1_extra_gas_limit = 400_000;

    let l1_to_l2_tx_hash = ethrex_l2_sdk::send_l1_to_l2_tx(
        rich_address,
        Some(0),
        Some(l2_gas_limit + l1_extra_gas_limit),
        L1ToL2TransactionData::new(rich_address, l2_gas_limit, U256::zero(), Bytes::new()),
        &rich_wallet_private_key,
        bridge_address()?,
        &l1_client,
    )
    .await?;

    println!("test_gas_burning: Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt =
        wait_for_transaction_receipt(l1_to_l2_tx_hash, &l1_client, 50).await?;

    assert!(l1_to_l2_tx_receipt.receipt.status);
    assert!(l1_to_l2_tx_receipt.tx_info.gas_used > l2_gas_limit);
    assert!(l1_to_l2_tx_receipt.tx_info.gas_used < l2_gas_limit + l1_extra_gas_limit);
    Ok(FeesDetails::default())
}

/// Test that sendToL2 reverts on L1 when the requested gasLimit exceeds the on-chain l2GasLimit.
/// 1. Send a sendToL2 transaction with gasLimit = l2GasLimit + 1 (just over the allowed limit).
/// 2. Verify that the L1 transaction reverts (receipt status is false).
async fn test_send_to_l2_exceeding_gas_limit(
    l1_client: EthClient,
    rich_wallet_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!(
        "test_send_to_l2_exceeding_gas_limit: Testing that sendToL2 reverts when gasLimit exceeds l2GasLimit"
    );
    let rich_address =
        get_address_from_secret_key(&rich_wallet_private_key.secret_bytes()).unwrap();
    let bridge = bridge_address()?;

    // Fetch the current on-chain l2GasLimit
    let on_chain_gas_limit = get_l2_gas_limit(&l1_client, bridge).await.unwrap();
    println!("test_send_to_l2_exceeding_gas_limit: on-chain l2GasLimit = {on_chain_gas_limit}");

    // Use gasLimit = on_chain_gas_limit + 1 to exceed the limit
    let excessive_gas_limit = on_chain_gas_limit + 1;

    // We must set a high L1 gas limit explicitly to avoid gas estimation failure
    // (eth_estimateGas would fail because the tx reverts).
    let l1_gas_limit = 500_000;

    let l1_to_l2_tx_hash = ethrex_l2_sdk::send_l1_to_l2_tx(
        rich_address,
        Some(0),
        Some(l1_gas_limit),
        L1ToL2TransactionData::new(
            rich_address,
            excessive_gas_limit,
            U256::zero(),
            Bytes::new(),
        ),
        &rich_wallet_private_key,
        bridge,
        &l1_client,
    )
    .await?;

    let receipt = wait_for_transaction_receipt(l1_to_l2_tx_hash, &l1_client, 50).await?;

    assert!(
        !receipt.receipt.status,
        "test_send_to_l2_exceeding_gas_limit: sendToL2 should revert when gasLimit exceeds l2GasLimit"
    );

    println!("test_send_to_l2_exceeding_gas_limit: sendToL2 correctly reverted");
    Ok(FeesDetails::default())
}

/// Test transferring ETH on L2 through a privileged transaction (deposit from L1) with insufficient balance
/// 1. Fetch initial balance of receiver on L2.
/// 2. Perform transfer through a deposit with value greater than sender's balance.
/// 3. Check final balance of receiver on L2 (should be unchanged).
async fn test_privileged_tx_not_enough_balance(
    l1_client: EthClient,
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
    receiver_private_key: SecretKey,
) -> Result<FeesDetails> {
    println!(
        "ptx_not_enough_balance: Starting test for privileged transaction with insufficient balance"
    );
    let rich_address =
        get_address_from_secret_key(&rich_wallet_private_key.secret_bytes()).unwrap();
    let receiver_address =
        get_address_from_secret_key(&receiver_private_key.secret_bytes()).unwrap();

    println!("ptx_not_enough_balance: Fetching initial balances on L1 and L2");

    let balance_sender = l2_client
        .get_balance(rich_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    let balance_before = l2_client
        .get_balance(receiver_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let transfer_value = balance_sender + U256::one();

    println!(
        "ptx_not_enough_balance: Attempting to transfer {transfer_value} from {rich_address:#x} to {receiver_address:#x}"
    );

    let l1_to_l2_tx_hash = ethrex_l2_sdk::send_l1_to_l2_tx(
        rich_address,
        Some(0),
        None,
        L1ToL2TransactionData::new(receiver_address, 21000 * 5, transfer_value, Bytes::new()),
        &rich_wallet_private_key,
        bridge_address()?,
        &l1_client,
    )
    .await?;

    println!("ptx_not_enough_balance: Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt =
        wait_for_transaction_receipt(l1_to_l2_tx_hash, &l1_client, 50).await?;

    assert!(
        l1_to_l2_tx_receipt.receipt.status,
        "Transfer transaction failed"
    );

    println!("ptx_not_enough_balance: Waiting for L1 to L2 transaction receipt on L2");

    let _ = wait_for_l2_deposit_receipt(&l1_to_l2_tx_receipt, &l1_client, &l2_client).await?;

    println!("ptx_not_enough_balance: Checking balances after transfer");

    let balance_after = l2_client
        .get_balance(receiver_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    assert_eq!(balance_after, balance_before);
    Ok(FeesDetails::default())
}

/// Test helper
/// 1. Fetch initial balances of transferer and recipient on L2.
/// 2. Perform transfer on L2
/// 3. Check final balances.
async fn perform_transfer(
    l2_client: &EthClient,
    transferer_private_key: &SecretKey,
    transfer_recipient_address: Address,
    transfer_value: U256,
    test: &str,
) -> Result<FeesDetails> {
    let transferer_address =
        get_address_from_secret_key(&transferer_private_key.secret_bytes()).unwrap();

    let transferer_initial_l2_balance = l2_client
        .get_balance(transferer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        transferer_initial_l2_balance >= transfer_value,
        "L2 transferer doesn't have enough balance to transfer"
    );

    let transfer_recipient_initial_balance = l2_client
        .get_balance(
            transfer_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    let transfer_tx_hash = ethrex_l2_sdk::transfer(
        transfer_value,
        transferer_address,
        transfer_recipient_address,
        transferer_private_key,
        l2_client,
    )
    .await?;

    let transfer_tx_receipt =
        ethrex_l2_sdk::wait_for_transaction_receipt(transfer_tx_hash, l2_client, 10000).await?;

    assert!(
        transfer_tx_receipt.receipt.status,
        "Transfer transaction failed"
    );

    let transfer_fees = get_fees_details_l2(
        &transfer_tx_receipt,
        l2_client,
        u64::try_from(EIP1559_DEFAULT_SERIALIZED_LENGTH).unwrap(),
    )
    .await?;
    let total_fees = transfer_fees.total();

    println!("{test}: Checking balances on L2 after transfer");

    let transferer_l2_balance_after_transfer = l2_client
        .get_balance(transferer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        transferer_initial_l2_balance - transfer_value - total_fees,
        transferer_l2_balance_after_transfer,
        "{test}: L2 transferer balance didn't decrease as expected after transfer. Gas costs were {total_fees}",
    );

    let transfer_recipient_l2_balance_after_transfer = l2_client
        .get_balance(
            transfer_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    println!("{test}: Checking recipient balance on L2 after transfer");

    assert_eq!(
        transfer_recipient_l2_balance_after_transfer,
        transfer_recipient_initial_balance + transfer_value,
        "L2 transfer recipient balance didn't increase as expected after transfer"
    );
    println!("{test}: Transfer successful");

    Ok(transfer_fees)
}

async fn test_n_withdraws(
    l1_client: &EthClient,
    l2_client: &EthClient,
    withdrawer_private_key: &SecretKey,
    n: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("test_n_withdraws: Withdrawing funds from L2 to L1");
    let withdrawer_address = get_address_from_secret_key(&withdrawer_private_key.secret_bytes())?;
    let withdraw_value = std::env::var("INTEGRATION_TEST_WITHDRAW_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid withdraw value"))
        .unwrap_or(U256::from(100000000000000000000u128));

    println!("test_n_withdraws: Checking balances on L1 and L2 before withdrawal");

    let withdrawer_l2_balance_before_withdrawal = l2_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        withdrawer_l2_balance_before_withdrawal >= withdraw_value,
        "L2 withdrawer doesn't have enough balance to withdraw"
    );

    let bridge_balance_before_withdrawal = l1_client
        .get_balance(bridge_address()?, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        bridge_balance_before_withdrawal >= withdraw_value,
        "L1 bridge doesn't have enough balance to withdraw"
    );

    let withdrawer_l1_balance_before_withdrawal = l1_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let coinbase_balance_before_withdrawal = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let base_fee_vault = base_fee_vault(l2_client).await;
    let base_fee_vault_balance_before_withdrawal =
        get_fee_vault_balance(l2_client, base_fee_vault).await;

    let operator_fee_vault = operator_fee_vault(l2_client).await;
    let operator_fee_vault_balance_before_withdrawal =
        get_fee_vault_balance(l2_client, operator_fee_vault).await;

    let l1_fee_vault = l1_fee_vault(l2_client).await;
    let l1_fee_vault_balance_before_withdrawal =
        get_fee_vault_balance(l2_client, l1_fee_vault).await;

    println!("test_n_withdraws: Withdrawing funds from L2 to L1");

    let mut withdraw_txs = vec![];
    let mut receipts = vec![];

    let account_nonce = l2_client
        .get_nonce(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    for x in 1..n + 1 {
        println!("test_n_withdraws: Sending withdraw {x}/{n}");
        let withdraw_tx = ethrex_l2_sdk::withdraw(
            withdraw_value,
            withdrawer_address,
            *withdrawer_private_key,
            l2_client,
            Some(account_nonce + x - 1),
            Some(21000 * 10),
        )
        .await?;
        withdraw_txs.push(withdraw_tx);
    }

    for (i, tx) in withdraw_txs.iter().enumerate() {
        println!("test_n_withdraws: Waiting receipt {}/{n} ({tx:x})", i + 1);
        let r = ethrex_l2_sdk::wait_for_transaction_receipt(*tx, l2_client, 10000)
            .await
            .expect("Withdraw tx receipt not found");
        receipts.push(r);
    }

    println!("test_n_withdraws: Checking balances on L1 and L2 after withdrawal");

    let withdrawer_l2_balance_after_withdrawal = l2_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    // Compute actual total L2 gas paid by the withdrawer from receipts
    let mut total_withdraw_fees_l2 = FeesDetails::default();

    // Calculate transaction size for withdrawals
    let transaction_size = calculate_transaction_size(
        encode_calldata(L2_WITHDRAW_SIGNATURE, &[Value::Address(Address::random())])?.into(),
    );

    for receipt in &receipts {
        total_withdraw_fees_l2 += get_fees_details_l2(receipt, l2_client, transaction_size).await?;
    }

    // Now assert exact balance movement on L2: value + gas
    let expected_l2_after = withdrawer_l2_balance_before_withdrawal
        - (withdraw_value * n)
        - total_withdraw_fees_l2.total();

    assert_eq!(
        withdrawer_l2_balance_after_withdrawal, expected_l2_after,
        "Withdrawer L2 balance didn't decrease by value + gas as expected"
    );

    let withdrawer_l1_balance_after_withdrawal = l1_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        withdrawer_l1_balance_after_withdrawal, withdrawer_l1_balance_before_withdrawal,
        "Withdrawer L1 balance should not change after withdrawal"
    );

    let coinbase_balance_after_withdrawal = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let base_fee_vault_balance_after_withdrawal =
        get_fee_vault_balance(l2_client, base_fee_vault).await;

    let operator_fee_vault_balance_after_withdrawal =
        get_fee_vault_balance(l2_client, operator_fee_vault).await;

    let l1_fee_vault_balance_after_withdrawal =
        get_fee_vault_balance(l2_client, l1_fee_vault).await;

    assert_eq!(
        coinbase_balance_after_withdrawal,
        coinbase_balance_before_withdrawal + total_withdraw_fees_l2.priority_fees,
        "Coinbase balance didn't increase as expected after withdrawal"
    );

    if base_fee_vault.is_some() {
        assert_eq!(
            base_fee_vault_balance_after_withdrawal,
            base_fee_vault_balance_before_withdrawal + total_withdraw_fees_l2.base_fees,
            "Base fee vault balance didn't increase as expected after withdrawal"
        );
    }

    assert_eq!(
        operator_fee_vault_balance_after_withdrawal,
        operator_fee_vault_balance_before_withdrawal + total_withdraw_fees_l2.operator_fees,
        "Operator balance didn't increase as expected after withdrawal"
    );

    assert_eq!(
        l1_fee_vault_balance_after_withdrawal,
        l1_fee_vault_balance_before_withdrawal + total_withdraw_fees_l2.l1_fees,
        "L1 fee vault balance didn't increase as expected after withdrawal"
    );

    // We need to wait for all the txs to be included in some batch
    let mut proofs = vec![];
    for (i, tx) in withdraw_txs.iter().enumerate() {
        println!(
            "test_n_withdraws: Getting proof for withdrawal {}/{} ({:x})",
            i + 1,
            n,
            tx
        );
        proofs.push(wait_for_verified_proof(l1_client, l2_client, *tx).await);
    }

    let mut withdraw_claim_txs_receipts = vec![];
    for (x, proof) in proofs.iter().enumerate() {
        println!(
            "test_n_withdraws: Claiming withdrawal on L1 {}/{}",
            x + 1,
            n
        );
        let withdraw_claim_tx = ethrex_l2_sdk::claim_withdraw(
            withdraw_value,
            withdrawer_address,
            *withdrawer_private_key,
            l1_client,
            proof,
        )
        .await?;
        let withdraw_claim_tx_receipt =
            wait_for_transaction_receipt(withdraw_claim_tx, l1_client, 50).await?;
        withdraw_claim_txs_receipts.push(withdraw_claim_tx_receipt);
    }

    println!("test_n_withdraws: Checking balances on L1 and L2 after claim");

    let withdrawer_l1_balance_after_claim = l1_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let gas_used_value: u64 = withdraw_claim_txs_receipts
        .iter()
        .map(|x| x.tx_info.gas_used * x.tx_info.effective_gas_price)
        .sum();

    assert_eq!(
        withdrawer_l1_balance_after_claim,
        withdrawer_l1_balance_after_withdrawal + withdraw_value * n - gas_used_value,
        "Withdrawer L1 balance wasn't updated as expected after claim"
    );

    let withdrawer_l2_balance_after_claim = l2_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        withdrawer_l2_balance_after_claim, withdrawer_l2_balance_after_withdrawal,
        "Withdrawer L2 balance should not change after claim"
    );

    let bridge_balance_after_withdrawal = l1_client
        .get_balance(bridge_address()?, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        bridge_balance_after_withdrawal,
        bridge_balance_before_withdrawal - withdraw_value * n,
        "Bridge balance didn't decrease as expected after withdrawal"
    );

    Ok(())
}

async fn test_total_eth_l2(
    l1_client: &EthClient,
    l2_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking total ETH on L2");

    println!("Fetching rich accounts balance on L2");
    let rich_accounts_balance = get_rich_accounts_balance(l2_client)
        .await
        .expect("Failed to get rich accounts balance");

    let coinbase_balance = l2_client
        .get_balance(coinbase(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Coinbase balance: {coinbase_balance}");

    let base_fee_vault = base_fee_vault(l2_client).await;
    let base_fee_vault_balance = get_fee_vault_balance(l2_client, base_fee_vault).await;

    println!("Base fee vault balance: {base_fee_vault_balance}");

    let operator_fee_vault = operator_fee_vault(l2_client).await;
    let operator_fee_vault_balance = get_fee_vault_balance(l2_client, operator_fee_vault).await;

    println!("Operator fee vault balance: {operator_fee_vault_balance}");

    let l1_fee_vault = l1_fee_vault(l2_client).await;
    let l1_fee_vault_balance = get_fee_vault_balance(l2_client, l1_fee_vault).await;

    println!("L1 fee vault balance: {l1_fee_vault_balance}");

    let total_balance_on_l2 = rich_accounts_balance
        + coinbase_balance
        + base_fee_vault_balance
        + operator_fee_vault_balance
        + l1_fee_vault_balance;

    println!(
        "Total balance on L2: {rich_accounts_balance} + {coinbase_balance} + {base_fee_vault_balance} + {operator_fee_vault_balance} + {l1_fee_vault_balance} = {total_balance_on_l2}"
    );
    println!("Checking native tokens locked on CommonBridge");

    let bridge_address = bridge_address()?;
    let bridge_locked_eth = l1_client
        .get_balance(bridge_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Bridge locked ETH: {bridge_locked_eth}");

    if base_fee_vault.is_some() {
        assert!(
            total_balance_on_l2 == bridge_locked_eth,
            "Total balance on L2 ({total_balance_on_l2}) differs from bridge native locked ({bridge_locked_eth})"
        );
    } else {
        assert!(
            total_balance_on_l2 < bridge_locked_eth,
            "Total balance on L2 ({total_balance_on_l2}) is greater than the assets locked by the bridge ({bridge_locked_eth})"
        );
    }

    Ok(())
}

/// Test deploying a contract on L2
/// 1. Fetch initial balances of deployer on L2.
/// 2. Perform deploy on L2.
/// 3. Check final balances.
async fn test_deploy(
    l2_client: &EthClient,
    init_code: &[u8],
    deployer_private_key: &SecretKey,
    test_name: &str,
) -> Result<(Address, FeesDetails)> {
    println!("{test_name}: Deploying contract on L2");

    let deployer: Signer = LocalSigner::new(*deployer_private_key).into();

    let deployer_balance_before_deploy = l2_client
        .get_balance(deployer.address(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let (deploy_tx_hash, contract_address) = create_deploy(
        l2_client,
        &deployer,
        init_code.to_vec().into(),
        Overrides::default(),
    )
    .await?;

    let deploy_tx_receipt =
        ethrex_l2_sdk::wait_for_transaction_receipt(deploy_tx_hash, l2_client, 50).await?;

    assert!(
        deploy_tx_receipt.receipt.status,
        "{test_name}: Deploy transaction failed"
    );

    // Calculate transaction size
    let deploy_tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Create,
        data: init_code.to_vec().into(),
        ..Default::default()
    });

    let transaction_size: u64 = deploy_tx.encode_to_vec().len().try_into().unwrap();

    let deploy_fees = get_fees_details_l2(&deploy_tx_receipt, l2_client, transaction_size).await?;

    let deployer_balance_after_deploy = l2_client
        .get_balance(deployer.address(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let total_fees = deploy_fees.total();

    assert_eq!(
        deployer_balance_after_deploy,
        deployer_balance_before_deploy - total_fees,
        "{test_name}: Deployer L2 balance didn't decrease as expected after deploy"
    );

    let deployed_contract_balance = l2_client
        .get_balance(contract_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        deployed_contract_balance.is_zero(),
        "{test_name}: Deployed contract balance should be zero after deploy"
    );

    Ok((contract_address, deploy_fees))
}

async fn test_deploy_l1(
    client: &EthClient,
    init_code: &[u8],
    private_key: &SecretKey,
) -> Result<Address> {
    let deployer_signer: Signer = LocalSigner::new(*private_key).into();

    let (deploy_tx_hash, contract_address) = create_deploy(
        client,
        &deployer_signer,
        init_code.to_vec().into(),
        Overrides::default(),
    )
    .await?;

    ethrex_l2_sdk::wait_for_transaction_receipt(deploy_tx_hash, client, 50).await?;

    Ok(contract_address)
}

/// Coinbase must be 0
async fn test_call_to_contract_with_deposit(
    l1_client: &EthClient,
    l2_client: &EthClient,
    deployed_contract_address: Address,
    calldata_to_contract: Bytes,
    caller_private_key: &SecretKey,
    test: &str,
) -> Result<()> {
    let caller_address = get_address_from_secret_key(&caller_private_key.secret_bytes())
        .expect("Failed to get address");

    println!("{test}: Checking balances before call");

    let caller_l1_balance_before_call = l1_client
        .get_balance(caller_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let deployed_contract_balance_before_call = l2_client
        .get_balance(
            deployed_contract_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    println!("{test}: Calling contract on L2 with deposit");

    let l1_to_l2_tx_hash = ethrex_l2_sdk::send_l1_to_l2_tx(
        caller_address,
        Some(0),
        None,
        L1ToL2TransactionData::new(
            deployed_contract_address,
            21000 * 5,
            U256::zero(),
            calldata_to_contract.clone(),
        ),
        caller_private_key,
        bridge_address()?,
        l1_client,
    )
    .await?;

    println!("{test}: Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt = wait_for_transaction_receipt(l1_to_l2_tx_hash, l1_client, 50).await?;

    assert!(l1_to_l2_tx_receipt.receipt.status);

    println!("{test}: Waiting for L1 to L2 transaction receipt on L2");

    let _ = wait_for_l2_deposit_receipt(&l1_to_l2_tx_receipt, l1_client, l2_client).await?;

    println!("{test}: Checking balances after call");

    let caller_l1_balance_after_call = l1_client
        .get_balance(caller_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        caller_l1_balance_after_call,
        caller_l1_balance_before_call
            - l1_to_l2_tx_receipt.tx_info.gas_used
                * l1_to_l2_tx_receipt.tx_info.effective_gas_price,
        "{test}: Caller L1 balance didn't decrease as expected after call"
    );

    let deployed_contract_balance_after_call = l2_client
        .get_balance(
            deployed_contract_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert_eq!(
        deployed_contract_balance_after_call, deployed_contract_balance_before_call,
        "{test}: Deployed contract increased unexpectedly after call"
    );

    Ok(())
}

const OWNER_L1_GAS_LIMIT: u64 = 21000 * 20;

// Sends a bridge owner transaction on L1 and returns the receipt.
async fn send_owner_bridge_call(
    l1_client: &EthClient,
    owner_signer: &Signer,
    bridge_address: Address,
    signature: &str,
    args: &[Value],
) -> RpcReceipt {
    let calldata = encode_calldata(signature, args).unwrap();
    let tx = build_generic_tx(
        l1_client,
        TxType::EIP1559,
        bridge_address,
        owner_signer.address(),
        calldata.into(),
        Overrides {
            gas_limit: Some(OWNER_L1_GAS_LIMIT),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tx_hash = send_generic_transaction(l1_client, tx, owner_signer)
        .await
        .unwrap();
    wait_for_transaction_receipt(tx_hash, l1_client, 1000)
        .await
        .unwrap()
}

async fn test_fee_token(
    l2_client: EthClient,
    rich_wallet_private_key: SecretKey,
    recipient_private_key: SecretKey,
) -> Result<FeesDetails> {
    let test = "test_fee_token";
    let rich_wallet_address =
        get_address_from_secret_key(&rich_wallet_private_key.secret_bytes()).unwrap();
    let l1_client = l1_client();
    println!("{test}: Rich wallet address: {rich_wallet_address:#x}");

    let contracts_path = workspace_root().join("crates/l2/contracts");
    get_contract_dependencies(&contracts_path);

    let fee_token_path = workspace_root().join("crates/l2/contracts/src/example");
    let interfaces_path = workspace_root().join("crates/l2/contracts/src/l2");
    let remappings = [(
        "@openzeppelin/contracts",
        contracts_path
            .join("lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts"),
    )];
    let allow_paths: [&Path; 3] = [&fee_token_path, &interfaces_path, &contracts_path];

    compile_contract(
        &fee_token_path,
        &fee_token_path.join("FeeToken.sol"),
        false,
        false,
        Some(&remappings),
        &allow_paths,
        None,
    )?;

    let mut fee_token_contract =
        hex::decode(std::fs::read(fee_token_path.join("solc_out/FeeToken.bin"))?)?;
    fee_token_contract.extend_from_slice(&[0u8; 32]); // constructor argument: address(0), we don't want now an L1 fee token
    let (fee_token_address, deploy_fees) = test_deploy(
        &l2_client,
        &fee_token_contract,
        &rich_wallet_private_key,
        "test_fee_token",
    )
    .await?;

    let owner_pk = bridge_owner_private_key();
    let owner_signer: Signer = LocalSigner::new(owner_pk).into();
    let bridge_addr = bridge_address().unwrap();

    // Register fee token contract
    let register_tx_receipt = send_owner_bridge_call(
        &l1_client,
        &owner_signer,
        bridge_addr,
        REGISTER_FEE_TOKEN_SIGNATURE,
        &[Value::Address(fee_token_address)],
    )
    .await;
    let _ = wait_for_l2_deposit_receipt(&register_tx_receipt, &l1_client, &l2_client).await?;

    // Set fee token ratio
    let ratio_value = U256::from(2u8);
    let set_ratio_tx_receipt = send_owner_bridge_call(
        &l1_client,
        &owner_signer,
        bridge_addr,
        SET_FEE_TOKEN_RATIO_SIGNATURE,
        &[Value::Address(fee_token_address), Value::Uint(ratio_value)],
    )
    .await;
    let _ = wait_for_l2_deposit_receipt(&set_ratio_tx_receipt, &l1_client, &l2_client).await?;

    let sender_balance_before_transfer = l2_client
        .get_balance(rich_wallet_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    let sender_token_balance_before_transfer =
        test_balance_of(&l2_client, fee_token_address, rich_wallet_address).await;
    println!("{test}: Fee token address: {fee_token_address:#x}");
    println!("{test}: Sender balance before transfer: {sender_balance_before_transfer}");
    println!("{test}: Sender fee balance before transfer: {sender_token_balance_before_transfer}");

    let recipient_address =
        get_address_from_secret_key(&recipient_private_key.secret_bytes()).unwrap();
    let recipient_balance_before_transfer = l2_client
        .get_balance(recipient_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("{test}: Recipient address: {recipient_address:#x}");
    println!("{test}: Recipient balance before transfer: {recipient_balance_before_transfer}");

    let coinbase_address = coinbase();
    let coinbase_token_balance_before_transfer =
        test_balance_of(&l2_client, fee_token_address, coinbase_address).await;
    println!(
        "{test}: Coinbase address fee token balance before transfer: {coinbase_token_balance_before_transfer}"
    );

    // This may not be configured
    let fee_vault = base_fee_vault(&l2_client).await;
    let fee_vault_address_token_balance_before_transfer =
        test_balance_of_optional(&l2_client, fee_token_address, fee_vault).await;
    println!(
        "{test}: Fee vault address fee token balance before transfer: {fee_vault_address_token_balance_before_transfer}"
    );

    let operator_fee_vault = operator_fee_vault(&l2_client).await;
    let operator_fee_vault_token_balance_before_transfer =
        test_balance_of_optional(&l2_client, fee_token_address, operator_fee_vault).await;
    println!(
        "{test}: Operator fee vault address fee token balance before transfer: {operator_fee_vault_token_balance_before_transfer}"
    );

    let l1_fee_vault = l1_fee_vault(&l2_client).await;
    let l1_fee_vault_token_balance_before_transfer =
        test_balance_of_optional(&l2_client, fee_token_address, l1_fee_vault).await;
    println!(
        "{test}: L1 fee vault address fee token balance before transfer: {l1_fee_vault_token_balance_before_transfer}"
    );

    // Validate registry state on the L2
    let cd = encode_calldata("isFeeToken(address)", &[Value::Address(fee_token_address)]).unwrap();
    let expected = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let registry_state = l2_client
        .call(FEE_TOKEN_REGISTRY_ADDRESS, cd.into(), Overrides::default())
        .await
        .unwrap();
    assert_eq!(registry_state, expected, "{test}: fee token not registered");

    let fee_token_ratio = get_fee_token_ratio(&fee_token_address, &l2_client)
        .await
        .unwrap();
    assert_eq!(
        fee_token_ratio, 2,
        "{test}: fee token ratio not set in contract"
    );
    let value_to_transfer = 100_000;
    let mut generic_tx = build_generic_tx(
        &l2_client,
        TxType::FeeToken,
        recipient_address,
        rich_wallet_address,
        Bytes::new(),
        Overrides {
            fee_token: Some(fee_token_address),
            value: Some(U256::from(value_to_transfer)),
            ..Default::default()
        },
    )
    .await?;

    let signer = Signer::Local(LocalSigner::new(rich_wallet_private_key));
    generic_tx.gas = generic_tx.gas.map(|g| g * 2); // tx reverts in some cases otherwise
    let tx_hash = send_generic_transaction(&l2_client, generic_tx, &signer).await?;
    let transfer_receipt =
        ethrex_l2_sdk::wait_for_transaction_receipt(tx_hash, &l2_client, 1000).await?;

    let sender_balance_after_transfer = l2_client
        .get_balance(rich_wallet_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    println!("{test}: Sender balance after transfer: {sender_balance_after_transfer}");
    let recipient_balance_after_transfer = l2_client
        .get_balance(recipient_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    println!("{test}: Recipient balance after transfer: {recipient_balance_after_transfer}");

    assert_eq!(
        sender_balance_after_transfer,
        sender_balance_before_transfer - value_to_transfer,
        "Sender balance did not decrease"
    );

    println!("{test}: Sender balance decrease correctly");

    assert_eq!(
        recipient_balance_after_transfer,
        recipient_balance_before_transfer + value_to_transfer,
        "Recipient balance did not increase"
    );
    println!("{test}: Recipient balance increased correctly");

    let sender_token_balance_after_transfer =
        test_balance_of(&l2_client, fee_token_address, rich_wallet_address).await;
    println!(
        "{test}: Sender fee token balance after transfer: {sender_token_balance_after_transfer}"
    );

    let tx = Transaction::FeeTokenTransaction(FeeTokenTransaction {
        data: Bytes::new(),
        ..Default::default()
    });
    let tx_size = tx.encode_canonical_len().try_into().unwrap();
    let transfer_fees = get_fees_details_l2(&transfer_receipt, &l2_client, tx_size).await?;

    let sender_fee_token_spent = sender_token_balance_before_transfer
        .checked_sub(sender_token_balance_after_transfer)
        .expect("Sender fee token balance increased unexpectedly");
    assert_eq!(
        sender_fee_token_spent,
        U256::from(transfer_fees.total()) * fee_token_ratio,
        "{test}: Sender fee token spend mismatch"
    );

    let coinbase_token_balance_after_transfer =
        test_balance_of(&l2_client, fee_token_address, coinbase_address).await;
    let coinbase_delta = coinbase_token_balance_after_transfer
        .checked_sub(coinbase_token_balance_before_transfer)
        .expect("Coinbase fee token balance decreased");
    assert_eq!(
        coinbase_delta,
        U256::from(transfer_fees.priority_fees) * fee_token_ratio,
        "{test}: Priority fee mismatch"
    );

    if let Some(fee_vault) = base_fee_vault(&l2_client).await {
        let fee_vault_address_token_balance_after_transfer =
            test_balance_of(&l2_client, fee_token_address, fee_vault).await;
        println!(
            "{test}: Fee vault address fee token balance after transfer: {fee_vault_address_token_balance_after_transfer}"
        );
        let base_fee_vault_delta = fee_vault_address_token_balance_after_transfer
            .checked_sub(fee_vault_address_token_balance_before_transfer)
            .expect("Base fee vault balance decreased");
        assert_eq!(
            base_fee_vault_delta,
            U256::from(transfer_fees.base_fees) * fee_token_ratio,
            "{test}: Base fee vault mismatch"
        );
    }
    let operator_fee_vault_address_token_balance_after_transfer =
        test_balance_of_optional(&l2_client, fee_token_address, operator_fee_vault).await;
    println!(
        "{test}: Operator fee vault address fee token balance after transfer: {operator_fee_vault_address_token_balance_after_transfer}"
    );
    let l1_fee_vault_address_token_balance_after_transfer =
        test_balance_of_optional(&l2_client, fee_token_address, l1_fee_vault).await;
    println!(
        "{test}: L1 fee vault address fee token balance after transfer: {l1_fee_vault_address_token_balance_after_transfer}"
    );

    let operator_fee_vault_delta = operator_fee_vault_address_token_balance_after_transfer
        .checked_sub(operator_fee_vault_token_balance_before_transfer)
        .expect("Operator fee vault balance decreased");
    assert_eq!(
        operator_fee_vault_delta,
        U256::from(transfer_fees.operator_fees) * fee_token_ratio,
        "{test}: Operator fee vault mismatch"
    );

    let l1_fee_vault_delta = l1_fee_vault_address_token_balance_after_transfer
        .checked_sub(l1_fee_vault_token_balance_before_transfer)
        .expect("L1 fee vault balance decreased");
    assert_eq!(
        l1_fee_vault_delta,
        U256::from(transfer_fees.l1_fees) * fee_token_ratio,
        "{test}: L1 fee vault mismatch"
    );

    Ok(deploy_fees)
}

fn bridge_owner_private_key() -> SecretKey {
    let l1_rich_wallet_pk = std::env::var("INTEGRATION_TEST_BRIDGE_OWNER_PRIVATE_KEY")
        .map(|pk| pk.parse().expect("Invalid l1 rich wallet pk"))
        .unwrap_or(DEFAULT_BRIDGE_OWNER_PRIVATE_KEY);
    SecretKey::from_slice(l1_rich_wallet_pk.as_bytes()).unwrap()
}

#[derive(Debug, Default)]
struct FeesDetails {
    base_fees: u64,
    priority_fees: u64,
    operator_fees: u64,
    l1_fees: u64,
}

impl FeesDetails {
    fn total(&self) -> u64 {
        self.base_fees + self.priority_fees + self.operator_fees + self.l1_fees
    }
}

impl Add for FeesDetails {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            base_fees: self.base_fees + other.base_fees,
            priority_fees: self.priority_fees + other.priority_fees,
            operator_fees: self.operator_fees + other.operator_fees,
            l1_fees: self.l1_fees + other.l1_fees,
        }
    }
}

impl AddAssign for FeesDetails {
    fn add_assign(&mut self, other: Self) {
        self.base_fees += other.base_fees;
        self.priority_fees += other.priority_fees;
        self.operator_fees += other.operator_fees;
        self.l1_fees += other.l1_fees;
    }
}

fn calculate_tx_gas_price(
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    base_fee_per_gas: u64,
    operator_fee_per_gas: u64,
) -> u64 {
    let fee_per_gas = base_fee_per_gas + operator_fee_per_gas;
    min(max_priority_fee_per_gas + fee_per_gas, max_fee_per_gas)
}

async fn get_fees_details_l2(
    tx_receipt: &RpcReceipt,
    l2_client: &EthClient,
    tx_account_diff_size: u64,
) -> Result<FeesDetails> {
    let rpc_tx = l2_client
        .get_transaction_by_hash(tx_receipt.tx_info.transaction_hash)
        .await
        .unwrap()
        .unwrap();
    let tx_gas_used = tx_receipt.tx_info.gas_used;
    // The shared accessors are `U256` because EIP-8141 bounds a frame
    // transaction's fee fields at 2**256; the fee arithmetic below is `u64`, and
    // an L2 EIP-1559 transaction this test signs itself never exceeds that.
    let max_fee_per_gas = u64::try_from(rpc_tx.tx.max_fee_per_gas().unwrap()).unwrap();
    let max_priority_fee_per_gas = u64::try_from(rpc_tx.tx.max_priority_fee().unwrap()).unwrap();
    let block_number = tx_receipt.block_info.block_number;

    let l1_blob_base_fee_per_gas = get_l1_blob_base_fee_per_gas(l2_client, block_number).await?;
    let l1_fee_per_blob: u64 = l1_blob_base_fee_per_gas * u64::from(GAS_PER_BLOB);
    let l1_fee_per_blob_byte = l1_fee_per_blob / u64::try_from(SAFE_BYTES_PER_BLOB).unwrap();
    let calculated_l1_fee = l1_fee_per_blob_byte * tx_account_diff_size;

    let base_fee_per_gas = l2_client
        .get_block_by_number(
            BlockIdentifier::Number(tx_receipt.block_info.block_number),
            false,
        )
        .await
        .unwrap()
        .header
        .base_fee_per_gas
        .unwrap();

    let operator_fee_per_gas: u64 = get_operator_fee(
        l2_client,
        BlockIdentifier::Number(tx_receipt.block_info.block_number),
    )
    .await
    .unwrap()
    .try_into()
    .unwrap();

    let gas_price = calculate_tx_gas_price(
        max_fee_per_gas,
        max_priority_fee_per_gas,
        base_fee_per_gas,
        operator_fee_per_gas,
    );

    let mut l1_gas = calculated_l1_fee / gas_price;

    if l1_gas == 0 && calculated_l1_fee > 0 {
        l1_gas = 1;
    }

    let actual_gas_used = tx_gas_used - l1_gas;

    let priority_fees = min(
        max_priority_fee_per_gas,
        max_fee_per_gas - base_fee_per_gas - operator_fee_per_gas,
    ) * actual_gas_used;

    let operator_fees = operator_fee_per_gas * actual_gas_used;
    let base_fees = base_fee_per_gas * actual_gas_used;
    let l1_fees = l1_gas * gas_price;

    Ok(FeesDetails {
        base_fees,
        priority_fees,
        operator_fees,
        l1_fees,
    })
}

/// Calculates the encoded transaction size for fee calculation purposes.
/// Takes calldata bytes and returns the encoded size of a dummy EIP1559 transaction.
fn calculate_transaction_size(data: Bytes) -> u64 {
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        data,
        ..Default::default()
    });
    tx.encode_to_vec().len().try_into().unwrap()
}

fn l1_client() -> EthClient {
    EthClient::new(
        std::env::var("INTEGRATION_TEST_L1_RPC")
            .map(|val| Url::parse(&val).expect("Error parsing URL (INTEGRATION_TEST_L1_RPC)"))
            .unwrap_or(Url::parse(DEFAULT_L1_RPC).unwrap()),
    )
    .unwrap()
}

fn l2_client() -> EthClient {
    EthClient::new(
        std::env::var("INTEGRATION_TEST_L2_RPC")
            .map(|val| Url::parse(&val).expect("Error parsing URL (INTEGRATION_TEST_L2_RPC)"))
            .unwrap_or(Url::parse(DEFAULT_L2_RPC).unwrap()),
    )
    .unwrap()
}

fn coinbase() -> Address {
    std::env::var("INTEGRATION_TEST_PROPOSER_COINBASE_ADDRESS")
        .map(|address| address.parse().expect("Invalid proposer coinbase address"))
        .unwrap_or(DEFAULT_PROPOSER_COINBASE_ADDRESS)
}

async fn base_fee_vault(l2_client: &EthClient) -> Option<Address> {
    get_base_fee_vault_address(l2_client, BlockIdentifier::Tag(BlockTag::Latest))
        .await
        .unwrap()
}

async fn operator_fee_vault(l2_client: &EthClient) -> Option<Address> {
    get_operator_fee_vault_address(l2_client, BlockIdentifier::Tag(BlockTag::Latest))
        .await
        .unwrap()
}

async fn l1_fee_vault(l2_client: &EthClient) -> Option<Address> {
    get_l1_fee_vault_address(l2_client, BlockIdentifier::Tag(BlockTag::Latest))
        .await
        .unwrap()
}

async fn get_fee_vault_balance(l2_client: &EthClient, vault_address: Option<Address>) -> U256 {
    let Some(addr) = vault_address else {
        return U256::zero();
    };
    l2_client
        .get_balance(addr, BlockIdentifier::Tag(BlockTag::Latest))
        .await
        .unwrap()
}

fn get_tests_private_keys() -> Vec<SecretKey> {
    let private_keys_file_path = test_private_keys_path();
    let pks =
        read_to_string(private_keys_file_path).expect("Failed to read tests private keys file");
    let private_keys: Vec<String> = pks
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();

    private_keys
        .iter()
        .map(|pk| parse_private_key(pk).expect("Failed to parse private key"))
        .collect()
}

async fn get_rich_accounts_balance(
    l2_client: &EthClient,
) -> Result<U256, Box<dyn std::error::Error>> {
    let mut total_balance = U256::zero();
    let private_keys_file_path = rich_keys_file_path();

    let pks = read_to_string(private_keys_file_path)?;
    let private_keys: Vec<String> = pks
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();

    for pk in private_keys.iter() {
        let secret_key = parse_private_key(pk)?;
        let address = get_address_from_secret_key(&secret_key.secret_bytes())?;
        let get_balance = l2_client
            .get_balance(address, BlockIdentifier::Tag(BlockTag::Latest))
            .await?;
        total_balance += get_balance;
    }
    Ok(total_balance)
}

// Path to the file containing private keys for integration tests.
// These keys must be a subset of the deployer private keys,
// but they must not be used for anything other than these tests.
fn test_private_keys_path() -> PathBuf {
    match std::env::var("INTEGRATION_TEST_PRIVATE_KEYS_FILE_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            println!(
                "INTEGRATION_TEST_PRIVATE_KEYS_FILE_PATH not set, using default: {DEFAULT_TEST_KEYS_FILE_PATH}",
            );
            workspace_root().join(DEFAULT_TEST_KEYS_FILE_PATH)
        }
    }
}

fn rich_keys_file_path() -> PathBuf {
    match std::env::var("ETHREX_DEPLOYER_PRIVATE_KEYS_FILE_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            println!(
                "ETHREX_DEPLOYER_PRIVATE_KEYS_FILE_PATH not set, using default: {DEFAULT_RICH_KEYS_FILE_PATH}",
            );
            workspace_root().join(DEFAULT_RICH_KEYS_FILE_PATH)
        }
    }
}

pub fn parse_private_key(s: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    Ok(SecretKey::from_slice(&parse_hex(s)?)?)
}

pub fn parse_hex(s: &str) -> Result<Bytes, FromHexError> {
    match s.strip_prefix("0x") {
        Some(s) => hex::decode(s).map(Into::into),
        None => hex::decode(s).map(Into::into),
    }
}

fn get_contract_dependencies(contracts_path: &Path) {
    std::fs::create_dir_all(contracts_path.join("lib")).expect("Failed to create contracts/lib");
    git_clone(
        "https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git",
        contracts_path
            .join("lib/openzeppelin-contracts-upgradeable")
            .to_str()
            .expect("Failed to convert path to str"),
        Some("release-v5.4"),
        true,
    )
    .unwrap();
}

// Removes the contracts/lib, contracts/solc_out, and contracts/src/example/solc_out
// directories generated by the tests.
fn clean_contracts_dir() {
    let contracts_base = workspace_root().join("crates/l2/contracts");
    let paths_to_clean = [
        contracts_base.join("lib"),
        contracts_base.join("solc_out"),
        contracts_base.join("src/example/solc_out"),
    ];

    for path in &paths_to_clean {
        let _ = std::fs::remove_dir_all(path).inspect_err(|e| {
            println!("Failed to remove {}: {e}", path.display());
        });
    }

    let cleaned_paths = paths_to_clean
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!("Cleaned up: {cleaned_paths}");
}

fn transfer_value() -> U256 {
    std::env::var("INTEGRATION_TEST_TRANSFER_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid transfer value"))
        .unwrap_or(U256::from(10_000_000_000u128))
}

fn on_chain_proposer_address() -> Address {
    std::env::var("ETHREX_COMMITTER_ON_CHAIN_PROPOSER_ADDRESS")
        .map(|address| address.parse().expect("Invalid proposer address"))
        .unwrap_or(DEFAULT_ON_CHAIN_PROPOSER_ADDRESS)
}

/// Waits until every test account has been credited on L2.
///
/// A node started with `--dev` funds the rich accounts by depositing through the
/// bridge, and the deployer only awaits the L1 receipts. The credits reach L2
/// asynchronously through the L1 watcher, a batch or more after the RPC starts
/// answering, so a balance read before that returns zero and every balance-delta
/// assertion below it is off by the pre-funded amount.
async fn wait_for_prefunded_accounts(
    l2_client: &EthClient,
    private_keys: &[SecretKey],
) -> Result<(), Box<dyn std::error::Error>> {
    for private_key in private_keys {
        let address = get_address_from_secret_key(&private_key.secret_bytes())?;

        for attempt in 1..=PREFUNDING_MAX_ATTEMPTS {
            let balance = l2_client
                .get_balance(address, BlockIdentifier::Tag(BlockTag::Latest))
                .await?;

            if !balance.is_zero() {
                break;
            }

            assert!(
                attempt < PREFUNDING_MAX_ATTEMPTS,
                "L2 balance of test account {address:#x} is still zero after \
                 {PREFUNDING_MAX_ATTEMPTS} attempts; the --dev pre-funding deposits never landed"
            );

            println!("Waiting for the L2 pre-funding of {address:#x} (attempt {attempt})");
            tokio::time::sleep(PREFUNDING_POLL_INTERVAL).await;
        }
    }

    Ok(())
}

/// Waits until the batch containing L2->L1 message is verified on L1, and returns the proof for that message
async fn wait_for_verified_proof(
    l1_client: &EthClient,
    l2_client: &EthClient,
    tx: H256,
) -> L1MessageProof {
    let proof = wait_for_l1_message_proof(l2_client, tx, 10000).await;
    let proof = proof.unwrap().into_iter().next().expect("proof not found");

    loop {
        let latest = get_last_verified_batch(l1_client, on_chain_proposer_address())
            .await
            .unwrap();

        if latest >= proof.batch_number {
            break;
        }

        println!(
            "Withdrawal is not verified yet. Latest verified batch: {}, waiting for: {}",
            latest, proof.batch_number
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    proof
}
