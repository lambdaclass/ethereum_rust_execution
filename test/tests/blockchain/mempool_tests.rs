use std::collections::BTreeMap;
use std::{fs::File, io::BufReader, path::PathBuf};

use ethrex_blockchain::constants::MAX_INITCODE_SIZE;
use ethrex_blockchain::constants::{
    TX_ACCESS_LIST_ADDRESS_GAS, TX_ACCESS_LIST_STORAGE_KEY_GAS, TX_CREATE_GAS_COST,
    TX_DATA_NON_ZERO_GAS_EIP2028, TX_DATA_ZERO_GAS_COST, TX_GAS_COST, TX_INIT_CODE_WORD_GAS_COST,
};
use ethrex_blockchain::error::MempoolError;
use ethrex_blockchain::mempool::{
    FramePaymasterReservation, Mempool, is_canonical_paymaster, transaction_intrinsic_gas,
};
use ethrex_blockchain::{Blockchain, BlockchainOptions};
use ethrex_crypto::NativeCrypto;
use rustc_hash::FxHashMap;

use ethrex_common::types::{
    APPROVE_EXECUTION_AND_PAYMENT, AuthorizationTuple, BYTES_PER_BLOB, BlobsBundle, Block,
    BlockBody, BlockHeader, ChainConfig, EIP1559Transaction, EIP4844Transaction,
    EIP7702Transaction, FRAME_SIG_SCHEME_P256, FRAME_SIG_SCHEME_SECP256K1,
    FRAME_TX_EXPIRY_DATA_LENGTH, FRAME_TX_MAX_VERIFY_GAS, FeeTokenTransaction, Frame, FrameMode,
    FrameSignature, FrameTransaction, GasLimits, Genesis, GenesisAccount, MAX_TX_SIZE,
    MempoolTransaction, PrivilegedL2Transaction, Transaction, TxKind, frame_tx_expiry_verifier,
    kzg_commitment_to_versioned_hash,
};
use ethrex_common::{Address, Bytes, H160, H256, U256};
use ethrex_storage::error::StoreError;
use ethrex_storage::{EngineType, Store};

const MEMPOOL_MAX_SIZE_TEST: usize = 10_000;

async fn setup_storage(config: ChainConfig, header: BlockHeader) -> Result<Store, StoreError> {
    let mut store = Store::new("test", EngineType::InMemory)?;
    let block_number = header.number;
    let block_hash = header.hash();
    store.add_block_header(block_hash, header).await?;
    store
        .forkchoice_update(vec![], block_number, block_hash, None, None)
        .await?;
    store.set_chain_config(&config).await?;
    Ok(store)
}

fn build_basic_config_and_header(
    istanbul_active: bool,
    shanghai_active: bool,
) -> (ChainConfig, BlockHeader) {
    let config = ChainConfig {
        shanghai_time: Some(if shanghai_active { 1 } else { 10 }),
        istanbul_block: Some(if istanbul_active { 1 } else { 10 }),
        ..Default::default()
    };

    let header = BlockHeader {
        number: 5,
        timestamp: 5,
        gas_limit: 100_000_000,
        gas_used: 0,
        ..Default::default()
    };

    (config, header)
}

#[test]
fn normal_transaction_intrinsic_gas() {
    let (config, header) = build_basic_config_and_header(false, false);

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: TxKind::Call(Address::from_low_u64_be(1)), // Normal tx
        value: U256::zero(),                           // Value zero
        data: Bytes::default(),                        // No data
        access_list: Default::default(),               // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let expected_gas_cost = TX_GAS_COST;
    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("Intrinsic gas");
    assert_eq!(intrinsic_gas, expected_gas_cost);
}

#[test]
fn create_transaction_intrinsic_gas() {
    let (config, header) = build_basic_config_and_header(false, false);

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: TxKind::Create,              // Create tx
        value: U256::zero(),             // Value zero
        data: Bytes::default(),          // No data
        access_list: Default::default(), // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let expected_gas_cost = TX_CREATE_GAS_COST;
    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("Intrinsic gas");
    assert_eq!(intrinsic_gas, expected_gas_cost);
}

/// EIP-2780 (PRELIMINARY EIPs#11645): Amsterdam CREATE tx intrinsic must match
/// the VM charge, not the legacy `TX_CREATE_GAS_COST = 53000`. The regular
/// portion is the resource-based decomposition
/// `TX_BASE_COST_AMSTERDAM (12000) + CREATE_ACCESS_AMSTERDAM (12000) = 24000`
/// (no value transfer here). The state portion is 0: the `NEW_ACCOUNT` charge
/// is not part of the intrinsic — it is charged IN-REGION
/// by `prepare_execution` (EELS `prepare_dispatch` create branch), conditioned
/// on `get_pre_state_account(created_addr) == EMPTY_ACCOUNT`, so mempool
/// admission cannot know it upfront without simulating the tx. Mempool
/// admission must return the (now purely regular) intrinsic so txs whose
/// `gas_limit` is below the VM intrinsic are rejected before they enter the
/// pool, and txs above it aren't spuriously rejected.
#[test]
fn amsterdam_create_intrinsic_matches_vm_dimensions() {
    use ethrex_levm::gas_cost::CREATE_ACCESS_AMSTERDAM;
    const TX_BASE_COST_AMSTERDAM: u64 = 12000;

    let (mut config, header) = build_basic_config_and_header(true, true);
    // Activate Amsterdam at genesis. Intermediate forks must also be active
    // so `config.fork(timestamp)` returns Amsterdam, not an earlier variant.
    config.cancun_time = Some(0);
    config.prague_time = Some(0);
    config.osaka_time = Some(0);
    config.bpo1_time = Some(0);
    config.bpo2_time = Some(0);
    config.amsterdam_time = Some(0);

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to: TxKind::Create,
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        ..Default::default()
    });

    let expected = TX_BASE_COST_AMSTERDAM + CREATE_ACCESS_AMSTERDAM;

    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("intrinsic gas");
    assert_eq!(
        intrinsic_gas, expected,
        "Amsterdam CREATE intrinsic must be TX_BASE_COST_AMSTERDAM + \
         CREATE_ACCESS_AMSTERDAM (state portion moved in-region), not the legacy 53000"
    );
    // Guard against regression to the legacy 53000 constant.
    assert_ne!(
        intrinsic_gas, TX_CREATE_GAS_COST,
        "Amsterdam CREATE must NOT use legacy TX_CREATE_GAS_COST"
    );
}

#[test]
fn transaction_intrinsic_data_gas_post_istanbul() {
    let (config, header) = build_basic_config_and_header(true, false);

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: TxKind::Call(Address::from_low_u64_be(1)), // Normal tx
        value: U256::zero(),                           // Value zero
        data: Bytes::from(vec![0x0, 0x1, 0x1, 0x0, 0x1, 0x1]), // 6 bytes of data
        access_list: Default::default(),               // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let expected_gas_cost =
        TX_GAS_COST + 2 * TX_DATA_ZERO_GAS_COST + 4 * TX_DATA_NON_ZERO_GAS_EIP2028;
    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("Intrinsic gas");
    assert_eq!(intrinsic_gas, expected_gas_cost);
}

#[test]
fn transaction_create_intrinsic_gas_pre_shanghai() {
    let (config, header) = build_basic_config_and_header(false, false);

    let n_words: u64 = 10;
    let n_bytes: u64 = 32 * n_words - 3; // Test word rounding

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: TxKind::Create,                                // Create tx
        value: U256::zero(),                               // Value zero
        data: Bytes::from(vec![0x1_u8; n_bytes as usize]), // Bytecode data
        access_list: Default::default(),                   // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let expected_gas_cost = TX_CREATE_GAS_COST + n_bytes * TX_DATA_NON_ZERO_GAS_EIP2028;
    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("Intrinsic gas");
    assert_eq!(intrinsic_gas, expected_gas_cost);
}

#[test]
fn transaction_create_intrinsic_gas_post_shanghai() {
    let (config, header) = build_basic_config_and_header(false, true);

    let n_words: u64 = 10;
    let n_bytes: u64 = 32 * n_words - 3; // Test word rounding

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: TxKind::Create,                                // Create tx
        value: U256::zero(),                               // Value zero
        data: Bytes::from(vec![0x1_u8; n_bytes as usize]), // Bytecode data
        access_list: Default::default(),                   // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let expected_gas_cost = TX_CREATE_GAS_COST
        + n_bytes * TX_DATA_NON_ZERO_GAS_EIP2028
        + n_words * TX_INIT_CODE_WORD_GAS_COST;
    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("Intrinsic gas");
    assert_eq!(intrinsic_gas, expected_gas_cost);
}

#[test]
fn transaction_intrinsic_gas_access_list() {
    let (config, header) = build_basic_config_and_header(false, false);

    let access_list = vec![
        (Address::zero(), vec![H256::default(); 10]),
        (Address::zero(), vec![]),
        (Address::zero(), vec![H256::default(); 5]),
    ];

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: TxKind::Call(Address::from_low_u64_be(1)), // Normal tx
        value: U256::zero(),                           // Value zero
        data: Bytes::default(),                        // No data
        access_list,
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let expected_gas_cost =
        TX_GAS_COST + 3 * TX_ACCESS_LIST_ADDRESS_GAS + 15 * TX_ACCESS_LIST_STORAGE_KEY_GAS;
    let intrinsic_gas = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("Intrinsic gas");
    assert_eq!(intrinsic_gas, expected_gas_cost);
}

#[tokio::test]
async fn transaction_with_big_init_code_in_shanghai_fails() {
    let (config, header) = build_basic_config_and_header(false, true);

    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 99_000_000,
        to: TxKind::Create,                                           // Create tx
        value: U256::zero(),                                          // Value zero
        data: Bytes::from(vec![0x1; MAX_INITCODE_SIZE as usize + 1]), // Large init code
        access_list: Default::default(),                              // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let validation = blockchain.validate_transaction(&tx, Address::random());
    assert!(matches!(
        validation.await,
        Err(MempoolError::TxMaxInitCodeSizeError)
    ));
}

#[tokio::test]
async fn transaction_with_gas_limit_higher_than_of_the_block_should_fail() {
    let (config, header) = build_basic_config_and_header(false, false);

    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000_001,
        to: TxKind::Call(Address::from_low_u64_be(1)), // Normal tx
        value: U256::zero(),                           // Value zero
        data: Bytes::default(),                        // No data
        access_list: Default::default(),               // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let validation = blockchain.validate_transaction(&tx, Address::random());
    assert!(matches!(
        validation.await,
        Err(MempoolError::TxGasLimitExceededError)
    ));
}

#[tokio::test]
async fn transaction_with_priority_fee_higher_than_gas_fee_should_fail() {
    let (config, header) = build_basic_config_and_header(false, false);

    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 101,
        max_fee_per_gas: 100,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)), // Normal tx
        value: U256::zero(),                           // Value zero
        data: Bytes::default(),                        // No data
        access_list: Default::default(),               // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let validation = blockchain.validate_transaction(&tx, Address::random());
    assert!(matches!(
        validation.await,
        Err(MempoolError::TxTipAboveFeeCapError)
    ));
}

#[tokio::test]
async fn transaction_with_gas_limit_lower_than_intrinsic_gas_should_fail() {
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);
    let intrinsic_gas_cost = TX_GAS_COST;

    let tx = EIP1559Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: intrinsic_gas_cost - 1,
        to: TxKind::Call(Address::from_low_u64_be(1)), // Normal tx
        value: U256::zero(),                           // Value zero
        data: Bytes::default(),                        // No data
        access_list: Default::default(),               // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP1559Transaction(tx);
    let validation = blockchain.validate_transaction(&tx, Address::random());
    assert!(matches!(
        validation.await,
        Err(MempoolError::TxIntrinsicGasCostAboveLimitError)
    ));
}

#[tokio::test]
async fn transaction_with_blob_base_fee_below_min_should_fail() {
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = EIP4844Transaction {
        nonce: 3,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        max_fee_per_blob_gas: 0.into(),
        gas: 15_000_000,
        to: Address::from_low_u64_be(1), // Normal tx
        value: U256::zero(),             // Value zero
        data: Bytes::default(),          // No data
        access_list: Default::default(), // No access list
        ..Default::default()
    };

    let tx = Transaction::EIP4844Transaction(tx);
    let validation = blockchain.validate_transaction(&tx, Address::random());
    assert!(matches!(
        validation.await,
        Err(MempoolError::TxBlobBaseFeeTooLowError)
    ));
}

#[tokio::test]
async fn validate_transaction_rejects_oversize_non_blob() {
    // EIP-1559 tx with serialized RLP > MAX_TX_SIZE must be rejected at
    // admission with `TxSizeExceeded`. The size cap is the first
    // size-themed check; it runs before init-code, intrinsic gas, and
    // balance lookups, so an unsigned tx with no sender state is enough.
    use ethrex_common::types::MAX_TX_SIZE;

    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    // Pad calldata above MAX_TX_SIZE so the *encoded* tx is also oversized.
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        data: Bytes::from(vec![0u8; MAX_TX_SIZE + 1]),
        ..Default::default()
    });

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    match res {
        Err(MempoolError::TxSizeExceeded { actual, limit }) => {
            assert!(actual > limit);
            assert_eq!(limit, MAX_TX_SIZE);
        }
        other => panic!("expected TxSizeExceeded, got {:?}", other),
    }
}

#[test]
fn test_filter_mempool_transactions() {
    let plain_tx_decoded = Transaction::decode_canonical(&hex::decode("f86d80843baa0c4082f618946177843db3138ae69679a54b95cf345ed759450d870aa87bee538000808360306ba0151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65da064c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4").unwrap()).unwrap();
    let plain_tx_sender = plain_tx_decoded.sender(&NativeCrypto).unwrap();
    let plain_tx = MempoolTransaction::new(plain_tx_decoded, plain_tx_sender);
    let blob_tx_decoded = Transaction::decode_canonical(&hex::decode("03f88f0780843b9aca008506fc23ac00830186a09400000000000000000000000000000000000001008080c001e1a0010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c44401401a0840650aa8f74d2b07f40067dc33b715078d73422f01da17abdbd11e02bbdfda9a04b2260f6022bf53eadb337b3e59514936f7317d872defb891a708ee279bdca90").unwrap()).unwrap();
    let blob_tx_sender = blob_tx_decoded.sender(&NativeCrypto).unwrap();
    let blob_tx = MempoolTransaction::new(blob_tx_decoded, blob_tx_sender);
    let plain_tx_hash = plain_tx.hash(&NativeCrypto);
    let blob_tx_hash = blob_tx.hash(&NativeCrypto);
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
    let filter = |tx: &Transaction| -> bool { matches!(tx, Transaction::EIP4844Transaction(_)) };
    mempool
        .add_transaction(blob_tx_hash, blob_tx_sender, blob_tx.clone(), None, None)
        .unwrap();
    mempool
        .add_transaction(plain_tx_hash, plain_tx_sender, plain_tx, None, None)
        .unwrap();
    let txs = mempool.filter_transactions_with_filter_fn(&filter).unwrap();
    assert_eq!(
        txs,
        FxHashMap::from_iter([(blob_tx.sender(), vec![blob_tx])])
    );
}

#[test]
fn blobs_bundle_loadtest() {
    // Write a bundle of 6 blobs 10 times
    // If this test fails please adjust the max_size in the DB config
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
    for i in 0..300 {
        let blobs = [[i as u8; BYTES_PER_BLOB]; 6];
        let commitments = [[i as u8; 48]; 6];
        let proofs = [[i as u8; 48]; 6];
        let bundle = BlobsBundle {
            blobs: blobs.to_vec(),
            commitments: commitments.to_vec(),
            proofs: proofs.to_vec(),
            version: 0,
        };
        mempool.add_blobs_bundle(H256::random(), bundle).unwrap();
    }
}

// ---------------------------------------------------------------------------
// EIP-8141 frame transaction mempool admission tests
// ---------------------------------------------------------------------------

/// The address used as the sender by [`minimal_valid_frame_tx`]. Genesis seeds
/// it with APPROVE(scope=3) code so its `self_verify` validation prefix
/// establishes a payer (itself, OQ2) during admission simulation.
const FRAME_TX_SELF_SENDER: u64 = 0xABCD;

/// APPROVE(scope) then STOP: `PUSH1 scope; PUSH1 0; PUSH1 0; APPROVE; STOP`.
/// A VERIFY frame whose target runs this code calls APPROVE with the given
/// scope, which is what the validation-prefix simulation requires to recognize
/// a payer (an empty/codeless target would establish none and be rejected).
fn approve_code(scope: u8) -> Bytes {
    Bytes::from(vec![0x60, scope, 0x60, 0x00, 0x60, 0x00, 0xAA, 0x00])
}

/// In-memory store whose genesis head has the Hegota fork active (so frame txs
/// pass the FrameTxPreFork gate) and a real state trie root (so account lookups
/// during admission succeed instead of erroring on a missing trie root). The
/// `minimal_valid_frame_tx` sender is seeded with APPROVE(3) code so its
/// `self_verify` prefix simulation establishes a payer and is admitted.
async fn setup_hegota_store() -> Store {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            Address::from_low_u64_be(FRAME_TX_SELF_SENDER),
            GenesisAccount {
                code: approve_code(APPROVE_EXECUTION_AND_PAYMENT),
                storage: BTreeMap::new(),
                balance: U256::zero(),
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store = Store::new("hegota-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// A minimal, statically-valid 1-frame transaction with an empty signature list.
fn minimal_valid_frame_tx() -> FrameTransaction {
    let sender = Address::from_low_u64_be(0xABCD);
    FrameTransaction {
        chain_id: 0, // matches ChainConfig::default().chain_id
        nonce: 0,
        sender,
        // A single `self_verify` frame: VERIFY mode, targets the sender, and
        // approves both execution and payment. This is the smallest frame
        // structure that matches a recognized mempool validation prefix (a lone
        // DEFAULT frame sets no payer and is correctly rejected).
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(sender),
            // Small per-frame gas so max_gas() stays below the legacy
            // 21000 intrinsic floor: this tx is only admitted once the frame-tx
            // intrinsic-gas fix prices it correctly.
            gas_limits: GasLimits {
                execution: 100,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    }
}

/// Raise the first frame's gas limit so the transaction reserves its EIP-7623
/// calldata floor. The minimal fixture carries no data, so tests that add frame
/// data or signatures need the extra headroom to stay otherwise-valid.
fn reserve_calldata_floor(tx: &mut FrameTransaction) {
    let floor = tx.calldata_floor_gas();
    if let Some(frame) = tx.frames.first_mut() {
        frame.gas_limits.execution = frame.gas_limits.execution.max(floor);
    }
}

#[tokio::test]
async fn mempool_rejects_frame_tx_with_invalid_signature() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    let mut frame_tx = minimal_valid_frame_tx();
    // One secp256k1 signature with the right length (65 bytes) but garbage bytes:
    // ecrecover will not recover the claimed signer, so admission must reject it.
    frame_tx.signatures = vec![FrameSignature {
        scheme: FRAME_SIG_SCHEME_SECP256K1,
        signer: Some(Address::from_low_u64_be(0xABCD)),
        msg: Bytes::new(),
        signature: Bytes::from(vec![0xAB; 65]),
    }];

    reserve_calldata_floor(&mut frame_tx);

    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(matches!(
        validation.await,
        Err(MempoolError::InvalidFrameSignature)
    ));
}

#[tokio::test]
async fn mempool_rejects_frame_tx_violating_static_constraints() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    let mut frame_tx = minimal_valid_frame_tx();
    // mode 5 is reserved (modes 3-255 are invalid) -> static-constraint failure.
    frame_tx.frames[0].mode = 5;

    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(matches!(
        validation.await,
        Err(MempoolError::InvalidFrameTransaction(_))
    ));
}

#[tokio::test]
async fn mempool_accepts_small_frame_tx() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    // Empty signature list passes signature validation (nothing to reject), and
    // the tx otherwise satisfies static constraints + nonce/fee checks.
    let frame_tx = minimal_valid_frame_tx();
    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(
        validation.await.is_ok(),
        "minimal valid frame tx should be admitted"
    );
}

#[test]
fn frame_tx_reservation_maps_clear_after_add_and_remove() {
    // EIP-8141 task 3.2: a frame tx's reservation must be fully accounted on
    // insert across ALL four tracking maps, and the single removal path must
    // clean every one of them (no leak, no double-decrement). Drive the
    // `Mempool` directly so we can assert the map sizes before and after.
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
    let frame_tx = minimal_valid_frame_tx();
    let sender = frame_tx.sender;
    let paymaster = sender; // self-funded self_verify: payer == sender (OQ2)
    let tx = Transaction::FrameTransaction(frame_tx);
    let hash = tx.hash(&NativeCrypto);

    // Every map starts empty.
    assert_eq!(
        mempool.frame_tracking_map_sizes().unwrap(),
        (0, 0, 0, 0),
        "frame tracking maps must start empty"
    );

    let reservation = FramePaymasterReservation {
        paymaster,
        reserved_cost: U256::from(1_000u64),
        is_canonical: false,
        paymaster_balance: U256::from(1_000_000u64),
    };
    mempool
        .add_transaction(
            hash,
            sender,
            MempoolTransaction::new(tx, sender),
            Some(reservation),
            None,
        )
        .expect("add frame tx with reservation");

    // After insert all four maps carry exactly one entry.
    assert_eq!(
        mempool.frame_tracking_map_sizes().unwrap(),
        (1, 1, 1, 1),
        "all four frame tracking maps must record the pending frame tx"
    );
    assert_eq!(
        mempool.reserved_pending_cost(paymaster).unwrap(),
        U256::from(1_000u64)
    );
    assert_eq!(
        mempool.noncanonical_paymaster_pending(paymaster).unwrap(),
        1
    );

    // Removal through the single removal path cleans every map.
    mempool.remove_transaction(&hash).expect("remove frame tx");
    assert_eq!(
        mempool.frame_tracking_map_sizes().unwrap(),
        (0, 0, 0, 0),
        "all four frame tracking maps must return to empty after removal"
    );
    assert_eq!(
        mempool.reserved_pending_cost(paymaster).unwrap(),
        U256::zero()
    );
    assert_eq!(
        mempool.noncanonical_paymaster_pending(paymaster).unwrap(),
        0
    );
}

#[test]
fn is_canonical_paymaster_is_false_for_all_codes_oq1_interim() {
    // OQ1 interim: no canonical paymaster bytecode is pinned, so every paymaster
    // is treated as non-canonical. This guards the documented interim until the
    // canonical code hash is resolved upstream.
    assert!(!is_canonical_paymaster(&[]));
    assert!(!is_canonical_paymaster(&[0x60, 0x00]));
    assert!(!is_canonical_paymaster(&[0xAA; 64]));
}

#[tokio::test]
async fn mempool_rejects_oversized_frame_data() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    let mut frame_tx = minimal_valid_frame_tx();
    // Frame data whose length reaches the 128KB wire cap; tx.data() is empty
    // for frame txs, but the frames' payloads count toward the canonical
    // encoding that MAX_TX_SIZE bounds. The payload rides a trailing SENDER
    // frame, as a real transaction's would: the validation prefix stays inside
    // MAX_VERIFY_GAS while that frame reserves the EIP-7623 calldata floor.
    let payload = Bytes::from(vec![0u8; MAX_TX_SIZE]);
    frame_tx.frames.push(Frame {
        mode: FrameMode::Sender as u8,
        flags: 0x00,
        target: Some(Address::from_low_u64_be(0xCAFE)),
        gas_limits: GasLimits {
            execution: 0,
            state: 0,
        },
        value: U256::zero(),
        data: payload,
    });
    let floor = frame_tx.calldata_floor_gas();
    frame_tx.frames[1].gas_limits.execution = floor;

    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    let result = validation.await;
    assert!(
        matches!(result, Err(MempoolError::TxSizeExceeded { .. })),
        "got {result:?}"
    );
}

#[tokio::test]
async fn mempool_rejects_frame_tx_with_blobs() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    let mut frame_tx = minimal_valid_frame_tx();
    // Add a blob versioned hash; no sidecar transport exists for frame-tx
    // blobs yet, so admission must reject such txs as unsupported.
    let mut hash = [0xAB; 32];
    hash[0] = 0x01; // valid KZG version byte, so the unsupported-blobs check is what fires
    frame_tx.blob_versioned_hashes = vec![H256::from(hash)];

    reserve_calldata_floor(&mut frame_tx);

    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(matches!(
        validation.await,
        Err(MempoolError::FrameTxBlobsUnsupported)
    ));
}

#[tokio::test]
async fn mempool_rejects_frame_tx_exceeding_max_verify_gas() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    // EIP-8141 §Mempool rule #6: signature validation counts against
    // MAX_VERIFY_GAS (100_000). P256 sigs cost 6700 each, so 15 sigs cost
    // 100_500 > MAX_VERIFY_GAS and the tx must be rejected at admission BEFORE
    // any per-signature crypto runs. The signature bytes need not be valid:
    // the cap rejects first. Static constraints only require a known scheme and
    // an empty-or-32-byte msg, which these satisfy.
    let n_sigs = (FRAME_TX_MAX_VERIFY_GAS / 6700) as usize + 1; // 15
    let mut frame_tx = minimal_valid_frame_tx();
    frame_tx.signatures = (0..n_sigs)
        .map(|_| FrameSignature {
            scheme: FRAME_SIG_SCHEME_P256,
            signer: Some(Address::from_low_u64_be(0xABCD)),
            msg: Bytes::new(),
            signature: Bytes::from(vec![0u8; 128]),
        })
        .collect();
    assert!(frame_tx.signature_verification_cost() > FRAME_TX_MAX_VERIFY_GAS);

    reserve_calldata_floor(&mut frame_tx);

    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(matches!(
        validation.await,
        Err(MempoolError::FrameTxVerifyGasExceeded)
    ));
}

#[tokio::test]
async fn mempool_rejects_frame_tx_from_unknown_sender_with_sentinel_nonce() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    // Sender 0xABCD does not exist in the genesis state. A frame tx from a
    // not-yet-existent sender is legitimate (sponsored txs fund gas via a
    // separate payer), but its implied nonce is 0, so the u64::MAX sentinel can
    // never match and must be rejected — not skipped as it was before.
    let mut frame_tx = minimal_valid_frame_tx();
    frame_tx.nonce = u64::MAX;

    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(matches!(validation.await, Err(MempoolError::NonceTooLow)));
}

#[tokio::test]
async fn mempool_accepts_frame_tx_from_unknown_sender_with_zero_nonce() {
    let store = setup_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    // Regression guard for the sponsored-tx use case: a fresh (non-existent)
    // sender with nonce 0 must still be admitted after the nonce hardening —
    // the new guard only rejects sub-current / sentinel nonces.
    let frame_tx = minimal_valid_frame_tx(); // sender 0xABCD (absent), nonce 0
    let tx = Transaction::FrameTransaction(frame_tx);
    let validation = blockchain.validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap());
    assert!(
        validation.await.is_ok(),
        "fresh sponsored sender with nonce 0 should still be admitted"
    );
}

// ---------------------------------------------------------------------------
// EIP-8141 fork gate and expiry gate tests
// ---------------------------------------------------------------------------

/// Store where Hegota is NOT active: hegota_time is None, so frame txs must be
/// rejected with FrameTxPreFork regardless of their content.
async fn setup_pre_hegota_store() -> Store {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: None, // Hegota never activates
            ..Default::default()
        },
        gas_limit: 100_000_000,
        ..Default::default()
    };
    let mut store = Store::new("pre-hegota-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// Store where Hegota IS active (hegota_time == 0) and the head block has a
/// non-zero timestamp (1000), so expiry tests can use deadlines below that.
async fn setup_hegota_store_ts1000() -> Store {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        timestamp: 1000, // head.timestamp == 1000
        alloc: [
            (
                Address::from_low_u64_be(FRAME_TX_SELF_SENDER),
                GenesisAccount {
                    code: approve_code(APPROVE_EXECUTION_AND_PAYMENT),
                    storage: BTreeMap::new(),
                    balance: U256::zero(),
                    nonce: 0,
                },
            ),
            (
                frame_tx_expiry_verifier(),
                GenesisAccount {
                    // Canonical EIP-8141 expiry verifier runtime bytecode:
                    // reverts unless calldata is exactly 8 bytes and the 8-byte
                    // BE deadline is >= block.timestamp.
                    // Seeded so the interleaved expiry-verifier frame executes
                    // (instead of hitting codeless default code) during the
                    // admission simulation.
                    code: Bytes::from_static(&[
                        0x60, 0x08, 0x36, 0x14, 0x60, 0x0a, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x5f,
                        0x35, 0x60, 0xc0, 0x1c, 0x42, 0x11, 0x60, 0x16, 0x57, 0x00, 0x5b, 0x5f,
                        0x5f, 0xfd,
                    ]),
                    storage: BTreeMap::new(),
                    balance: U256::zero(),
                    nonce: 0,
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store = Store::new("hegota-ts1000-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// Build a minimal frame tx carrying an expiry verifier frame with the given
/// `deadline`, followed by a `self_verify` frame. The expiry frame is a VERIFY
/// frame targeting the expiry verifier address with exactly 8 bytes of
/// big-endian deadline data and flags == 0. Expiry verifier frames are skipped
/// for prefix matching, so the recognized prefix is the trailing `self_verify`.
fn frame_tx_with_expiry(deadline: u64) -> FrameTransaction {
    let sender = Address::from_low_u64_be(0xABCD);
    let mut data = [0u8; FRAME_TX_EXPIRY_DATA_LENGTH];
    data.copy_from_slice(&deadline.to_be_bytes());
    FrameTransaction {
        chain_id: 0,
        nonce: 0,
        sender,
        frames: vec![
            Frame {
                mode: FrameMode::Verify as u8,
                flags: 0x00,
                target: Some(frame_tx_expiry_verifier()),
                // Enough to reserve the EIP-7623 floor of the 8-byte deadline.
                gas_limits: GasLimits {
                    execution: 1_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::from(data.to_vec()),
            },
            Frame {
                mode: FrameMode::Verify as u8,
                flags: APPROVE_EXECUTION_AND_PAYMENT,
                target: Some(sender),
                gas_limits: GasLimits {
                    execution: 100,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::new(),
            },
        ],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    }
}

#[tokio::test]
async fn mempool_rejects_frame_tx_before_hegota() {
    // With hegota_time == None the fork gate must fire before any other check.
    let store = setup_pre_hegota_store().await;
    let blockchain = Blockchain::default_with_store(store);

    let frame_tx = minimal_valid_frame_tx();
    let tx = Transaction::FrameTransaction(frame_tx);
    let result = blockchain
        .validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap())
        .await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxPreFork)),
        "expected FrameTxPreFork, got {result:?}"
    );
}

#[tokio::test]
async fn mempool_rejects_expired_frame_tx() {
    // Head timestamp == 1000. A deadline of 999 is strictly less than 1000,
    // so the expiry gate must fire.
    let store = setup_hegota_store_ts1000().await;
    let blockchain = Blockchain::default_with_store(store);

    let frame_tx = frame_tx_with_expiry(999);
    let tx = Transaction::FrameTransaction(frame_tx);
    let result = blockchain
        .validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap())
        .await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxExpired)),
        "expected FrameTxExpired for deadline 999 < head.timestamp 1000, got {result:?}"
    );
}

#[tokio::test]
async fn mempool_accepts_frame_tx_with_deadline_at_head_timestamp() {
    // Head timestamp == 1000. A deadline of exactly 1000 is the boundary:
    // the on-chain verifier only reverts when block.timestamp > deadline, so
    // deadline == timestamp is still valid at mempool admission time.
    let store = setup_hegota_store_ts1000().await;
    let blockchain = Blockchain::default_with_store(store);

    let frame_tx = frame_tx_with_expiry(1000);
    let tx = Transaction::FrameTransaction(frame_tx);
    let result = blockchain
        .validate_transaction(&tx, tx.sender(&NativeCrypto).unwrap())
        .await;
    assert!(
        result.is_ok(),
        "frame tx with deadline == head.timestamp must be admitted; got {result:?}"
    );
}

#[test]
fn blobs_bundle_insert_and_remove() {
    // Insert two bundles with 2 blobs, and where both bundles contain one specific blob.
    // Then remove one bundle making sure that blob-version-hash to tx-hash cache still points to
    // the other txn. And finally remove second bundle as well.
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
    let (blob, commitment, proof) = ([255u8; BYTES_PER_BLOB], [255u8; 48], [255u8; 48]);
    let versioned_hash = kzg_commitment_to_versioned_hash(&commitment);
    let mut txn_hash = vec![];

    for i in 1..=2 {
        let blobs = [blob, [i as u8; BYTES_PER_BLOB]];
        let commitments = [commitment, [i as u8; 48]];
        let proofs = [proof, [i as u8; 48]];
        let bundle = BlobsBundle {
            blobs: blobs.to_vec(),
            commitments: commitments.to_vec(),
            proofs: proofs.to_vec(),
            version: 0,
        };
        let tx = EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: Address::from_low_u64_be(1), // Normal tx
            ..Default::default()
        };

        let tx = Transaction::EIP4844Transaction(tx);
        let sender = H160::random();
        let hash = H256::random();
        txn_hash.push(hash);
        mempool
            .add_blobs_bundle(txn_hash[i as usize - 1], bundle)
            .unwrap();

        mempool
            .add_transaction(
                hash,
                sender,
                MempoolTransaction::new(tx, sender),
                None,
                None,
            )
            .expect("Failed to add blob transaction");
    }

    // When a txn is removed it should not remove the associated bundle as another txn also has the same bundle.
    for txn_hash in txn_hash.into_iter() {
        assert_eq!(
            mempool
                .get_blobs_data_by_versioned_hashes(&[versioned_hash])
                .expect("should return a bundle")
                .len(),
            1
        );

        mempool
            .remove_transaction(&txn_hash)
            .expect("should remove blob bundle by txn_hash");
    }

    // Once both transactions are removed it should remove the bundle as well.
    assert_eq!(
        mempool
            .get_blobs_data_by_versioned_hashes(&[versioned_hash])
            .expect("should return empty"),
        vec![None]
    );
}

// --- min-tip floor admission tests ----------------------------------------

/// Builds a blockchain configured with `min_tip_wei` as the admission floor
/// (everything else permissive for tests).
fn blockchain_with_min_tip(store: Store, min_tip_wei: u64) -> Blockchain {
    let mut bc = Blockchain::default_with_store(store);
    let mut opts = bc.options.clone();
    opts.min_tip_wei = min_tip_wei;
    bc.options = opts;
    bc
}

#[tokio::test]
async fn zero_tip_eip1559_rejected_under_default_floor() {
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, 1_000_000);

    let tx = EIP1559Transaction {
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 1_000_000,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    };
    let tx = Transaction::EIP1559Transaction(tx);

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(matches!(
        res,
        Err(MempoolError::TipBelowMinimum {
            actual: 0,
            limit: 1_000_000,
        }),
    ));
}

#[tokio::test]
async fn at_floor_eip1559_passes_tip_check() {
    // Tip at the floor passes the min-tip check. The random sender has no
    // funds, so the tx fails later with `NotEnoughBalance`; that's the only
    // accepted post-tip-check outcome. Asserting the specific downstream
    // error guards against a future refactor that accidentally skips the
    // tip check (where a different error would still satisfy a `!matches!`
    // negative assertion).
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, 1_000_000);

    let tx = EIP1559Transaction {
        max_priority_fee_per_gas: 1_000_000,
        max_fee_per_gas: 1_000_000,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    };
    let tx = Transaction::EIP1559Transaction(tx);

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    // The tip check itself must not fire; the downstream account-lookup
    // (state root or balance) is what should fail in this minimal setup.
    // Asserting on the concrete next-stage error keeps the test honest if
    // a future refactor accidentally skips the tip check.
    assert!(
        matches!(
            res,
            Err(MempoolError::NotEnoughBalance) | Err(MempoolError::StoreError(_))
        ),
        "expected the tip check to pass and an account-lookup error to fire next, got {res:?}",
    );
}

#[tokio::test]
async fn floor_uses_raw_tip_cap_not_base_fee_adjusted_effective_tip() {
    // Pins the deliberate semantic: the floor is compared against the RAW tip
    // cap, not the base-fee-dependent effective tip
    // `min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas)`.
    //
    // Here `max_fee_per_gas == base_fee_per_gas`, so the actually-payable tip
    // is 0 — under an "effective tip" reading this tx would be rejected. It
    // must NOT be: geth's `PriceLimit` compares `tx.GasTipCap()` (raw), and
    // keying on the effective tip would make admission depend on the current
    // base fee, so the same tx could be admitted at block N and rejected at
    // N+1 as the base fee drifts. Admission decisions must be stable.
    let (config, mut header) = build_basic_config_and_header(false, false);
    header.base_fee_per_gas = Some(1_000_000);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, 1_000_000);

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        // Raw tip cap is exactly at the floor …
        max_priority_fee_per_gas: 1_000_000,
        // … but the fee cap leaves no room above base fee, so the effective
        // tip is 0.
        max_fee_per_gas: 1_000_000,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    });

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(
        !matches!(res, Err(MempoolError::TipBelowMinimum { .. })),
        "min-tip floor must compare the raw tip cap, not the base-fee-adjusted \
         effective tip; got {res:?}",
    );
    // As with the other floor tests, the unfunded random sender means the
    // account-lookup stage is the expected next failure.
    assert!(
        matches!(
            res,
            Err(MempoolError::NotEnoughBalance) | Err(MempoolError::StoreError(_))
        ),
        "expected an account-lookup error after the tip check passed, got {res:?}",
    );
}

#[tokio::test]
async fn floor_of_zero_admits_zero_tip() {
    // Operators can disable the floor with --mempool.min-tip 0. Same
    // structure as `at_floor_eip1559_passes_tip_check`: we want a specific
    // downstream error (the balance check) to fire, NOT just "any error
    // other than TipBelowMinimum".
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, 0);

    let tx = EIP1559Transaction {
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    };
    let tx = Transaction::EIP1559Transaction(tx);

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(
        matches!(
            res,
            Err(MempoolError::NotEnoughBalance) | Err(MempoolError::StoreError(_))
        ),
        "expected the tip check to skip (floor=0) and an account-lookup error to fire next, got {res:?}",
    );
}

#[tokio::test]
async fn legacy_gas_price_below_floor_rejected() {
    // Legacy tx: `gas_tip_cap()` returns `gas_price` so the floor applies to
    // the raw gas price for legacy txs (geth applies `PriceLimit` to
    // `tx.GasTipCap()` which is `gas_price` for legacy).
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, 1_000_000);

    let tx = ethrex_common::types::LegacyTransaction {
        gas_price: U256::from(999_999u64), // 1 wei below floor
        gas: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    };
    let tx = Transaction::LegacyTransaction(tx);

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(matches!(
        res,
        Err(MempoolError::TipBelowMinimum {
            actual: 999_999,
            limit: 1_000_000,
        }),
    ));
}

#[tokio::test]
async fn options_field_is_used_in_validate_transaction() {
    // Smoke test that BlockchainOptions::min_tip_wei is consulted (not
    // accidentally ignored if the option-plumbing breaks).
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");

    let mut bc = Blockchain::default_with_store(store);
    bc.options = BlockchainOptions {
        min_tip_wei: 5_000_000_000, // 5 gwei
        ..BlockchainOptions::default()
    };

    let tx = EIP1559Transaction {
        max_priority_fee_per_gas: 1_000_000_000, // 1 gwei (below 5 gwei)
        max_fee_per_gas: 5_000_000_000,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    };
    let tx = Transaction::EIP1559Transaction(tx);

    let res = bc.validate_transaction(&tx, Address::random()).await;
    assert!(matches!(
        res,
        Err(MempoolError::TipBelowMinimum {
            actual: 1_000_000_000,
            limit: 5_000_000_000,
        }),
    ));
}

#[tokio::test]
async fn shipped_default_floor_rejects_zero_tip_admits_one() {
    // Pin the actual shipped default (`DEFAULT_MIN_TIP_WEI = 1`, matching
    // geth's `PriceLimit = 1 wei`). Without this test the default could
    // silently regress to 0 (admit-everything) or to the old 1 Mwei value.
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, ethrex_blockchain::DEFAULT_MIN_TIP_WEI);

    // tip = 0 → rejected
    let zero = Transaction::EIP1559Transaction(EIP1559Transaction {
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 1,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    });
    assert!(matches!(
        blockchain
            .validate_transaction(&zero, Address::random())
            .await,
        Err(MempoolError::TipBelowMinimum {
            actual: 0,
            limit: 1
        }),
    ));

    // tip = 1 → passes the tip check; sender has no funds so the next
    // failure is `NotEnoughBalance`. Assert that specifically rather than
    // "not TipBelowMinimum" so the test catches accidental skip of the
    // tip check in future refactors.
    let one = Transaction::EIP1559Transaction(EIP1559Transaction {
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1,
        gas_limit: 50_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    });
    let res = blockchain
        .validate_transaction(&one, Address::random())
        .await;
    // The tip check itself must not fire; the downstream account-lookup
    // (state root or balance) is what should fail in this minimal setup.
    // Asserting on the concrete next-stage error keeps the test honest if
    // a future refactor accidentally skips the tip check.
    assert!(
        matches!(
            res,
            Err(MempoolError::NotEnoughBalance) | Err(MempoolError::StoreError(_))
        ),
        "expected the tip check to pass and an account-lookup error to fire next, got {res:?}",
    );
}

#[tokio::test]
async fn blob_tx_under_floor_rejected() {
    // EIP-4844 path uses the same `gas_tip_cap()` accessor. Confirm an
    // under-floor blob tx is also rejected so a regression in the per-type
    // dispatch wouldn't slip through.
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = blockchain_with_min_tip(store, 1_000_000);

    let tx = Transaction::EIP4844Transaction(EIP4844Transaction {
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 1_000_000,
        max_fee_per_blob_gas: 1.into(),
        gas: 50_000_000,
        to: Address::from_low_u64_be(1),
        ..Default::default()
    });

    assert!(matches!(
        blockchain
            .validate_transaction(&tx, Address::random())
            .await,
        Err(MempoolError::TipBelowMinimum {
            actual: 0,
            limit: 1_000_000,
        }),
    ));
}

#[test]
fn blob_txs_are_not_evicted_by_regular_tx_flood() {
    // Regression: blob txs live in a dedicated sub-pool, so a flood of regular
    // txs that fills (and evicts from) the regular pool must not reduce the set
    // of retained blob txs. Pre-fix, blob txs shared the regular FIFO and were
    // flushed out by regular-tx pressure, starving block building of blobs.
    let regular_cap = 4;
    let mempool = Mempool::new(regular_cap);

    // Insert more blob txs than the regular cap, so the blob set can only be
    // fully retained if blobs are NOT bound by the regular cap (bundle inserted
    // first, mirroring add_blob_transaction_to_pool).
    let blob_count = regular_cap + 2;
    let mut blob_hashes = Vec::new();
    for i in 0..blob_count {
        let bundle = BlobsBundle {
            blobs: vec![[i as u8; BYTES_PER_BLOB]],
            commitments: vec![[i as u8; 48]],
            proofs: vec![[i as u8; 48]],
            version: 0,
        };
        let blob_tx = Transaction::EIP4844Transaction(EIP4844Transaction {
            gas: 21_000,
            to: Address::from_low_u64_be(1),
            ..Default::default()
        });
        let blob_hash = H256::random();
        let blob_sender = H160::random();
        mempool.add_blobs_bundle(blob_hash, bundle).unwrap();
        mempool
            .add_transaction(
                blob_hash,
                blob_sender,
                MempoolTransaction::new(blob_tx, blob_sender),
                None,
                None,
            )
            .expect("Failed to add blob transaction");
        blob_hashes.push(blob_hash);
    }

    // Flood with regular txs far beyond the regular cap, tracking the first one
    // so we can confirm the flood actually triggered regular-tx eviction.
    let first_regular_hash = H256::random();
    for i in 0..(regular_cap * 10) {
        let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
            to: TxKind::Call(Address::from_low_u64_be(2)),
            ..Default::default()
        });
        let sender = H160::random();
        let hash = if i == 0 {
            first_regular_hash
        } else {
            H256::random()
        };
        mempool
            .add_transaction(
                hash,
                sender,
                MempoolTransaction::new(tx, sender),
                None,
                None,
            )
            .expect("Failed to add regular transaction");
    }

    // The flood must have evicted regular txs (proving it exceeded the cap that
    // pre-fix would also have flushed blobs).
    assert!(
        !mempool
            .contains_tx(first_regular_hash)
            .expect("contains_tx should succeed"),
        "regular-tx flood did not evict regular txs; test is not exercising eviction"
    );

    // Despite the eviction, every blob tx must still be retained (100% blob
    // retention vs a capped regular pool).
    for blob_hash in blob_hashes {
        assert!(
            mempool
                .contains_tx(blob_hash)
                .expect("contains_tx should succeed"),
            "blob tx {blob_hash:?} was evicted by a regular-tx flood"
        );
    }
}

// Inserts a 1-blob tx straight into the pool (bypassing validation) with the
// given nonce and blob fee; returns its hash.
fn add_blob_tx(mempool: &Mempool, nonce: u64, blob_fee: u64) -> H256 {
    let bundle = BlobsBundle {
        blobs: vec![[0u8; BYTES_PER_BLOB]],
        commitments: vec![[0u8; 48]],
        proofs: vec![[0u8; 48]],
        version: 0,
    };
    let tx = Transaction::EIP4844Transaction(EIP4844Transaction {
        nonce,
        gas: 21_000,
        max_fee_per_blob_gas: blob_fee.into(),
        to: Address::from_low_u64_be(1),
        ..Default::default()
    });
    let hash = H256::random();
    let sender = H160::random();
    mempool.add_blobs_bundle(hash, bundle).unwrap();
    mempool
        .add_transaction(
            hash,
            sender,
            MempoolTransaction::new(tx, sender),
            None,
            None,
        )
        .expect("Failed to add blob transaction");
    hash
}

// Like `add_blob_tx` but with an explicit sender; returns its hash.
fn add_blob_tx_with_sender(mempool: &Mempool, sender: Address, nonce: u64) -> H256 {
    let bundle = BlobsBundle {
        blobs: vec![[0u8; BYTES_PER_BLOB]],
        commitments: vec![[0u8; 48]],
        proofs: vec![[0u8; 48]],
        version: 0,
    };
    let tx = Transaction::EIP4844Transaction(EIP4844Transaction {
        nonce,
        gas: 21_000,
        max_fee_per_blob_gas: 1.into(),
        to: Address::from_low_u64_be(1),
        ..Default::default()
    });
    let hash = H256::random();
    mempool.add_blobs_bundle(hash, bundle).unwrap();
    mempool
        .add_transaction(
            hash,
            sender,
            MempoolTransaction::new(tx, sender),
            None,
            None,
        )
        .expect("Failed to add blob transaction");
    hash
}

#[test]
fn blob_txs_lists_only_blob_txs_with_sender_and_nonce() {
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
    let sender = H160::random();
    let blob0 = add_blob_tx_with_sender(&mempool, sender, 0);
    let blob1 = add_blob_tx_with_sender(&mempool, sender, 1);

    // A regular tx must not appear in the blob listing.
    let plain = Transaction::EIP1559Transaction(EIP1559Transaction {
        nonce: 0,
        gas_limit: 21_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        ..Default::default()
    });
    let plain_hash = plain.hash(&NativeCrypto);
    mempool
        .add_transaction(
            plain_hash,
            sender,
            MempoolTransaction::new(plain, sender),
            None,
            None,
        )
        .unwrap();

    let mut got = mempool.blob_txs().unwrap();
    got.sort_by_key(|(_, _, nonce)| *nonce);
    assert_eq!(got, vec![(blob0, sender, 0), (blob1, sender, 1)]);
}

#[test]
fn blob_eviction_keeps_includable_low_nonce_tx() {
    // When the blob sub-pool is over its cap, eviction must drop the least
    // includable blob tx (highest nonce), not the earliest-inserted one. A FIFO
    // would evict the first-added low-nonce tx (which is the includable one);
    // the value/nonce-ordered policy keeps it.
    let blob_cap = 4;
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST).with_max_blob_mempool_size(blob_cap);

    // Insert FIRST (oldest): an includable low-nonce, high-fee blob tx.
    let keep = add_blob_tx(&mempool, 0, 1000);

    // Then flood the blob sub-pool past its cap with higher-nonce, low-fee txs.
    for n in 0..(blob_cap as u64 + 4) {
        add_blob_tx(&mempool, 100 + n, 1);
    }

    // FIFO would have evicted `keep` (oldest); the new policy must keep it.
    assert!(
        mempool
            .contains_tx(keep)
            .expect("contains_tx should succeed"),
        "includable low-nonce blob tx was evicted in favor of high-nonce ones"
    );
}

#[test]
fn blob_eviction_offset_is_per_sender_not_cross_sender() {
    // Regression: eviction ranks by nonce offset *within a sender*, not by raw
    // cross-sender nonce. A high-throughput sender (e.g. a rollup sequencer)
    // accumulates large on-wire nonces while staying perfectly includable; a
    // raw cross-sender comparison would evict its txs first. The deepest-in-its-
    // own-queue blob must be dropped instead.
    let blob_cap = 4;
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST).with_max_blob_mempool_size(blob_cap);

    // Sequencer: a single blob at a very high nonce (offset 0 from its own min).
    let sequencer = H160::random();
    let seq_tx = add_blob_tx_with_sender(&mempool, sequencer, 1_000_000);

    // A backlogged sender with a deep, contiguous queue (offsets 0..=4).
    let backlogged = H160::random();
    let deep: Vec<H256> = (0..=4)
        .map(|n| add_blob_tx_with_sender(&mempool, backlogged, n))
        .collect();

    // 6 blobs, cap 4 ⇒ 2 backlogged blobs evicted. The sequencer's high-nonce
    // tx must survive: under the old cross-sender nonce key it had the globally
    // highest nonce and would have been the first evicted.
    assert!(
        mempool.contains_tx(seq_tx).unwrap(),
        "high-nonce sequencer blob was wrongly evicted by cross-sender nonce"
    );
    // Its lowest-offset (nonce 0) blob is the most includable and must stay.
    assert!(
        mempool.contains_tx(deep[0]).unwrap(),
        "includable nonce-0 blob must stay"
    );
    let present_deep = deep
        .iter()
        .filter(|h| mempool.contains_tx(**h).unwrap())
        .count();
    assert_eq!(
        present_deep, 3,
        "two of the backlogged sender's blobs evicted"
    );
}

// ---------------------------------------------------------------------------
// EIP-8141 Phase 4 admission and revalidation tests
// ---------------------------------------------------------------------------

/// Like `setup_hegota_store` but the sender has a generous balance so it can
/// cover a frame tx with positive fees. Any frame tx whose `max_cost` is at
/// most 1 ETH (10^18 wei) will pass the paymaster availability check.
async fn setup_hegota_store_funded() -> Store {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            Address::from_low_u64_be(FRAME_TX_SELF_SENDER),
            GenesisAccount {
                code: approve_code(APPROVE_EXECUTION_AND_PAYMENT),
                storage: BTreeMap::new(),
                balance: U256::from(10u64).pow(U256::from(18u64)),
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store = Store::new("hegota-funded-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

/// A frame tx that looks like `minimal_valid_frame_tx()` but with positive fees
/// so `max_cost = gas_limit * max_fee_per_gas > 0`. The sender must be seeded
/// with enough balance to cover it (use `setup_hegota_store_funded`).
fn funded_frame_tx(max_fee_per_gas: u64, max_priority_fee_per_gas: u64) -> FrameTransaction {
    let (max_fee_per_gas, max_priority_fee_per_gas) = (
        U256::from(max_fee_per_gas),
        U256::from(max_priority_fee_per_gas),
    );
    let sender = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);
    FrameTransaction {
        chain_id: 0,
        nonce: 0,
        sender,
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(sender),
            gas_limits: GasLimits {
                execution: 100,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas,
        max_fee_per_gas,
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    }
}

#[tokio::test]
async fn mempool_admits_funded_sponsored_frame_tx() {
    // A frame tx whose sender has enough balance to cover the tx max_cost must
    // be admitted via `add_transaction_to_pool` (Ok) and the hash returned.
    let store = setup_hegota_store_funded().await;
    let blockchain = Blockchain::default_with_store(store);

    let frame_tx = funded_frame_tx(1_000_000_000, 1_000_000_000);
    let tx = Transaction::FrameTransaction(frame_tx);
    let result = blockchain.add_transaction_to_pool(tx).await;
    assert!(
        result.is_ok(),
        "funded self_verify frame tx must be admitted; got {result:?}"
    );
}

#[tokio::test]
async fn mempool_rejects_underfunded_paymaster() {
    // The post-simulation availability check (`available < max_cost`, where
    // `available = paymaster_balance - reserved_pending_cost`) must reject a
    // frame tx with FrameTxPaymasterUnderfunded.
    //
    // Note: since APPROVE now collects the tx's MAXIMUM cost during the
    // validation-prefix simulation (max_fee_per_gas * max_gas), a payer
    // that cannot cover max_cost reverts *inside* the simulation
    // (FrameTxValidationFailed), never reaching this check. The availability
    // check is therefore only reachable when the payer covers a single tx's
    // max_cost but PRIOR pending reservations for the same paymaster leave less
    // than max_cost available. We reproduce that by seeding the paymaster with
    // exactly one max_cost (so simulation passes, balance exactly exhausted),
    // then phantom-injecting a pending reservation of max_cost against it.
    //
    // Setup mirrors mempool_enforces_noncanonical_paymaster_limit; the underfunded
    // check (`available < max_cost`) is evaluated before the non-canonical
    // pending-slot limit, so it is the error that fires here.
    let max_fee_per_gas = 2_000_000_000u64;
    let max_priority_fee_per_gas = 1_000_000_000u64;
    let frame_tx = funded_frame_tx(max_fee_per_gas, max_priority_fee_per_gas);
    let total_gas = frame_tx.max_gas();
    let max_cost = U256::from(max_fee_per_gas) * U256::from(total_gas);

    let paymaster = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            paymaster,
            GenesisAccount {
                code: approve_code(APPROVE_EXECUTION_AND_PAYMENT),
                storage: BTreeMap::new(),
                // Exactly one tx's max cost: simulation's APPROVE (which deducts
                // max_cost) passes, but any prior reservation makes availability
                // fall below max_cost.
                balance: max_cost,
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store =
        Store::new("hegota-underfunded-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    let blockchain = Blockchain::default_with_store(store);

    // Phantom-inject a pending reservation of max_cost against the paymaster from a
    // DIFFERENT sender (no nonce / sender-pending collision with the real tx). This
    // drives reserved_pending_cost(paymaster) to max_cost so the real tx sees zero
    // available balance.
    let phantom_sender = Address::from_low_u64_be(0xDEAD_BEEF);
    let phantom_frame_tx = FrameTransaction {
        chain_id: 0,
        nonce: 99,
        sender: phantom_sender,
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(phantom_sender),
            gas_limits: GasLimits {
                execution: 100,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    };
    let phantom_tx = Transaction::FrameTransaction(phantom_frame_tx);
    let phantom_hash = phantom_tx.hash(&NativeCrypto);
    blockchain
        .mempool
        .add_transaction(
            phantom_hash,
            phantom_sender,
            MempoolTransaction::new(phantom_tx, phantom_sender),
            Some(FramePaymasterReservation {
                paymaster,
                reserved_cost: max_cost,
                is_canonical: false,
                paymaster_balance: max_cost,
            }),
            None,
        )
        .expect("phantom reservation must be directly inserted");

    let real_tx = Transaction::FrameTransaction(frame_tx);
    let result = blockchain.add_transaction_to_pool(real_tx).await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxPaymasterUnderfunded)),
        "payer covering one max_cost but with prior reservations exhausting its \
         balance must yield FrameTxPaymasterUnderfunded; got {result:?}"
    );
}

#[tokio::test]
async fn mempool_enforces_noncanonical_paymaster_limit() {
    // EIP-8141 OQ1: all paymasters are non-canonical; the per-paymaster pending
    // limit is MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER = 1.
    //
    // In the current implementation `validate_prefix_structure` requires all
    // VERIFY frames to target `tx.sender`, which means every sender is their own
    // paymaster (there is no shape where an external paymaster address is shared
    // between two senders). `FrameTxNonCanonicalPaymasterLimit` is therefore
    // exercised by pre-filling the paymaster's non-canonical slot via a direct
    // `Mempool::add_transaction` call (bypassing simulation), then submitting a
    // real frame tx from the SAME sender via `add_transaction_to_pool`.
    //
    // Steps:
    // 1. Directly insert a frame tx from a PHANTOM sender into the mempool,
    //    carrying a `FramePaymasterReservation` that names FRAME_TX_SELF_SENDER
    //    as the paymaster. This increments `noncanonical_paymaster_pending[sender]`
    //    to 1 without going through validation.
    // 2. Call `add_transaction_to_pool` for a real frame tx from
    //    FRAME_TX_SELF_SENDER (valid simulation, funded sender, paymaster == self).
    //    The unlocked pre-filter in `validate_transaction` sees
    //    `noncanonical_paymaster_pending[sender] == 1 >= 1` and rejects with
    //    `FrameTxNonCanonicalPaymasterLimit`.
    let funded_balance = U256::from(10u64).pow(U256::from(18u64));
    let store = setup_hegota_store_funded().await;
    let blockchain = Blockchain::default_with_store(store);

    let paymaster = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);

    // Build a phantom frame tx (nonce=99, different sender so no nonce conflict)
    // and inject it directly to consume the paymaster's non-canonical slot.
    let phantom_sender = Address::from_low_u64_be(0xDEAD_BEEF);
    let phantom_frame_tx = FrameTransaction {
        chain_id: 0,
        nonce: 99,
        sender: phantom_sender,
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(phantom_sender),
            gas_limits: GasLimits {
                execution: 100,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    };
    let phantom_tx = Transaction::FrameTransaction(phantom_frame_tx);
    let phantom_hash = phantom_tx.hash(&NativeCrypto);
    blockchain
        .mempool
        .add_transaction(
            phantom_hash,
            phantom_sender,
            MempoolTransaction::new(phantom_tx, phantom_sender),
            Some(FramePaymasterReservation {
                paymaster, // names FRAME_TX_SELF_SENDER as paymaster
                reserved_cost: U256::from(1u64),
                is_canonical: false,
                paymaster_balance: funded_balance,
            }),
            None,
        )
        .expect("phantom frame tx must be directly inserted to fill paymaster slot");

    // Verify the non-canonical slot is consumed.
    assert_eq!(
        blockchain
            .mempool
            .noncanonical_paymaster_pending(paymaster)
            .unwrap(),
        1,
        "paymaster slot must be filled after phantom insertion"
    );

    // A real frame tx from FRAME_TX_SELF_SENDER (paymaster == self) must now
    // be rejected because the noncanonical slot is saturated.
    let real_tx = Transaction::FrameTransaction(funded_frame_tx(1_000_000_000, 1_000_000_000));
    let result = blockchain.add_transaction_to_pool(real_tx).await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxNonCanonicalPaymasterLimit)),
        "frame tx must be rejected when non-canonical paymaster slot is full; got {result:?}"
    );
}

#[tokio::test]
async fn mempool_rejects_second_frame_tx_same_sender_new_nonce() {
    // The one-pending-frame-tx-per-sender policy must reject a second frame tx
    // from the same sender at a DIFFERENT nonce with FrameTxSenderAlreadyPending.
    //
    // The VM simulation checks that `frame_tx.nonce == sender's on-chain nonce`,
    // so a frame tx at nonce=1 cannot pass simulation when the on-chain nonce is
    // 0. To trigger the different-nonce path without a nonce-mismatch simulation
    // failure, we inject a frame tx at nonce=1 DIRECTLY into the mempool
    // (bypassing simulation), then submit a valid frame tx at nonce=0 via
    // `add_transaction_to_pool`. The nonce=0 tx passes simulation (on-chain
    // nonce == 0), and `check_frame_tx_sender_pending` sees an existing entry at
    // nonce=1 with incoming nonce=0, triggering FrameTxSenderAlreadyPending.
    let store = setup_hegota_store_funded().await;
    let blockchain = Blockchain::default_with_store(store);

    let sender = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);

    // Directly insert a frame tx at nonce=1 (bypasses simulation nonce check).
    let nonce1_frame_tx = FrameTransaction {
        chain_id: 0,
        nonce: 1,
        sender,
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(sender),
            gas_limits: GasLimits {
                execution: 100,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    };
    let nonce1_tx = Transaction::FrameTransaction(nonce1_frame_tx);
    let nonce1_hash = nonce1_tx.hash(&NativeCrypto);
    blockchain
        .mempool
        .add_transaction(
            nonce1_hash,
            sender,
            MempoolTransaction::new(nonce1_tx, sender),
            None,
            None,
        )
        .expect("direct insert of nonce=1 frame tx must succeed");

    // Now submit a valid nonce=0 frame tx via `add_transaction_to_pool`.
    // Simulation passes (on-chain nonce=0 == tx nonce=0), but
    // `check_frame_tx_sender_pending` detects the existing nonce=1 entry and
    // rejects with FrameTxSenderAlreadyPending.
    let nonce0_tx = Transaction::FrameTransaction(funded_frame_tx(1_000_000_000, 1_000_000_000));
    let result = blockchain.add_transaction_to_pool(nonce0_tx).await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxSenderAlreadyPending)),
        "frame tx at nonce=0 must be rejected when nonce=1 is already pending; got {result:?}"
    );
}

#[tokio::test]
async fn mempool_fee_bump_replaces_pending_frame_tx() {
    // Admit a frame tx at nonce 0 with moderate fees, then submit the SAME
    // nonce with strictly higher max_fee_per_gas and max_priority_fee_per_gas.
    // The fee-bump path in `find_tx_to_replace` must accept the replacement
    // (Ok) and the old hash must no longer be in the pool.
    let store = setup_hegota_store_funded().await;
    let blockchain = Blockchain::default_with_store(store);

    let low_fee_tx = Transaction::FrameTransaction(funded_frame_tx(100_000_000, 100_000_000));
    let old_hash = blockchain
        .add_transaction_to_pool(low_fee_tx)
        .await
        .expect("low-fee frame tx must be admitted");

    // Higher fees on the same nonce: must replace.
    let high_fee_tx = Transaction::FrameTransaction(funded_frame_tx(200_000_000, 200_000_000));
    let new_hash = blockchain.add_transaction_to_pool(high_fee_tx).await;
    assert!(
        new_hash.is_ok(),
        "fee-bump replacement must be admitted; got {new_hash:?}"
    );
    let new_hash = new_hash.unwrap();
    assert_ne!(old_hash, new_hash, "hashes must differ after fee bump");

    // Old tx must be gone from the pool.
    let old_still_present = blockchain
        .mempool
        .contains_tx(old_hash)
        .expect("contains_tx");
    assert!(
        !old_still_present,
        "old hash must be evicted after fee-bump replacement"
    );
}

#[tokio::test]
async fn mempool_frame_tx_replaces_same_nonce_non_frame_tx() {
    // Regression for the EIP-8141 review fix: a frame tx that replaces a
    // same-(sender, nonce) NON-frame tx must evict the predecessor, not orphan
    // it. `find_tx_to_replace` (used during admission) matches any tx type and
    // validated the fee bump, but the locked removal in `add_transaction`
    // previously only consulted `check_frame_tx_sender_pending`, which sees frame
    // predecessors only — so a same-nonce legacy/EIP-1559 tx survived in the pool
    // while its (sender, nonce) index slot was overwritten by the frame tx.
    let store = setup_hegota_store_funded().await;
    let blockchain = Blockchain::default_with_store(store);

    let sender = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);

    // Directly insert a low-fee NON-frame tx at nonce 0 under the same sender.
    // Direct insertion lets us pin the tracked sender without needing the
    // sender's private key (a regular tx's sender is signature-derived).
    let regular_tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 0,
        nonce: 0,
        max_priority_fee_per_gas: 100_000_000,
        max_fee_per_gas: 100_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(Address::from_low_u64_be(0x1234)),
        value: U256::zero(),
        data: Bytes::new(),
        access_list: vec![],
        ..Default::default()
    });
    let regular_hash = regular_tx.hash(&NativeCrypto);
    blockchain
        .mempool
        .add_transaction(
            regular_hash,
            sender,
            MempoolTransaction::new(regular_tx, sender),
            None,
            None,
        )
        .expect("direct insert of non-frame tx must succeed");

    // Submit a frame tx at the same nonce with strictly higher fees: a valid
    // fee-bump replacement of the non-frame predecessor.
    let frame_tx = Transaction::FrameTransaction(funded_frame_tx(200_000_000, 200_000_000));
    let frame_hash = blockchain
        .add_transaction_to_pool(frame_tx)
        .await
        .expect("frame tx must be admitted as a same-nonce fee-bump replacement");

    // The non-frame predecessor must be evicted, not orphaned.
    assert!(
        !blockchain
            .mempool
            .contains_tx(regular_hash)
            .expect("contains_tx"),
        "same-nonce non-frame tx must be evicted when replaced by a frame tx"
    );
    assert!(
        blockchain
            .mempool
            .contains_tx(frame_hash)
            .expect("contains_tx"),
        "replacing frame tx must be present in the pool"
    );
}

/// Like `setup_hegota_store_funded` but with a caller-chosen sender balance, for
/// tight-balance assertions.
async fn setup_hegota_store_with_balance(balance: U256) -> Store {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            Address::from_low_u64_be(FRAME_TX_SELF_SENDER),
            GenesisAccount {
                code: approve_code(APPROVE_EXECUTION_AND_PAYMENT),
                storage: BTreeMap::new(),
                balance,
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store = Store::new("hegota-balance-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    store
}

#[tokio::test]
async fn mempool_fee_bump_not_blocked_by_own_stale_reservation() {
    // Regression: the unlocked availability pre-filter must not count the old
    // tx's still-live reservation against its own same-nonce fee-bump. Balance
    // funds the bumped tx alone but not the old and new reservations together;
    // the bump must still be admitted because the locked re-check releases the
    // old reservation before re-validating availability.
    let low_fee = 100_000_000u64;
    let high_fee = 200_000_000u64;
    let gas = funded_frame_tx(high_fee, high_fee).max_gas();
    // Exactly covers the bumped tx (high_fee * gas), but not old + new together.
    let balance = U256::from(high_fee) * U256::from(gas);
    let store = setup_hegota_store_with_balance(balance).await;
    let blockchain = Blockchain::default_with_store(store);

    let low_tx = Transaction::FrameTransaction(funded_frame_tx(low_fee, low_fee));
    blockchain
        .add_transaction_to_pool(low_tx)
        .await
        .expect("low-fee frame tx must be admitted");

    let high_tx = Transaction::FrameTransaction(funded_frame_tx(high_fee, high_fee));
    let result = blockchain.add_transaction_to_pool(high_tx).await;
    assert!(
        result.is_ok(),
        "fee-bump must not be falsely rejected by the old tx's own reservation; got {result:?}"
    );
}

#[tokio::test]
async fn mempool_fee_bump_rejected_leaves_original_intact() {
    // Atomicity (review fix 2): when a same-nonce fee-bump fails the locked
    // paymaster re-check, the old tx must NOT have been removed; the sender is
    // left with the original pending tx, never with neither.
    //
    // Setup: balance covers exactly one high-fee tx. The low-fee tx is admitted
    // first (reserving low_fee * gas). A COMPETING reservation for the SAME
    // paymaster is then injected directly (a phantom sender, so no nonce
    // conflict) to push `reserved_pending_cost` up. The fee-bump's adjusted
    // re-check only excludes the OLD same-nonce tx's reservation, not the
    // competing one, so availability fails and the bump is rejected. The
    // injected reservation is marked canonical so it does not consume a
    // non-canonical slot, isolating the AVAILABILITY rejection from the limit.
    let low_fee = 100_000_000u64;
    let high_fee = 200_000_000u64;
    let gas = funded_frame_tx(high_fee, high_fee).max_gas();
    // Exactly covers one high-fee tx (high_fee * gas).
    let balance = U256::from(high_fee) * U256::from(gas);
    let store = setup_hegota_store_with_balance(balance).await;
    let blockchain = Blockchain::default_with_store(store);

    let paymaster = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);

    // 1. Admit the low-fee tx normally.
    let low_tx = Transaction::FrameTransaction(funded_frame_tx(low_fee, low_fee));
    let old_hash = blockchain
        .add_transaction_to_pool(low_tx)
        .await
        .expect("low-fee frame tx must be admitted");

    // 2. Inject a competing reservation for the SAME paymaster (canonical, so it
    //    adds to `reserved_pending_cost` without touching the non-canonical
    //    slot). reserved_cost = 1 is enough: with the old tx's reservation
    //    excluded, the adjusted reserved is this 1 wei, and
    //    `balance - 1 < high_fee * gas` fails.
    let phantom_sender = Address::from_low_u64_be(0xCAFE_F00D);
    let phantom_frame_tx = FrameTransaction {
        chain_id: 0,
        nonce: 7,
        sender: phantom_sender,
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(phantom_sender),
            gas_limits: GasLimits {
                execution: 100,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    };
    let phantom_tx = Transaction::FrameTransaction(phantom_frame_tx);
    let phantom_hash = phantom_tx.hash(&NativeCrypto);
    blockchain
        .mempool
        .add_transaction(
            phantom_hash,
            phantom_sender,
            MempoolTransaction::new(phantom_tx, phantom_sender),
            Some(FramePaymasterReservation {
                paymaster,
                reserved_cost: U256::from(1u64),
                is_canonical: true,
                paymaster_balance: balance,
            }),
            None,
        )
        .expect("phantom reservation must be directly inserted");

    // 3. Submit the same-nonce fee-bump. The adjusted re-check excludes the old
    //    tx's reservation but NOT the competing one, so availability fails.
    let high_tx = Transaction::FrameTransaction(funded_frame_tx(high_fee, high_fee));
    let result = blockchain.add_transaction_to_pool(high_tx).await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxPaymasterUnderfunded)),
        "fee-bump that does not fit must be rejected with FrameTxPaymasterUnderfunded; got {result:?}"
    );

    // 4. The original pending tx must still be in the pool (rejection was
    //    atomic: the old tx was not removed).
    let old_still_present = blockchain
        .mempool
        .contains_tx(old_hash)
        .expect("contains_tx");
    assert!(
        old_still_present,
        "original pending tx must remain after a rejected fee-bump"
    );
}

#[tokio::test]
async fn mempool_rejects_frame_tx_with_banned_opcode() {
    // Task 4.2: a frame tx whose VERIFY prefix frame executes TIMESTAMP (0x42)
    // outside the expiry-verifier context must be rejected with
    // FrameTxValidationFailed (banned opcode detected by ValidationObserver).
    //
    // The sender is seeded with `[0x42, 0xAA, 0x00, ...]` bytecode: TIMESTAMP
    // pushes a value, then APPROVE(0) (scope 0) is called, then STOP. The
    // TIMESTAMP fires before APPROVE, so the observer records BannedOpcode(0x42)
    // and the simulation fails even though APPROVE is reached.
    //
    // `approve_code(scope)` = PUSH1 scope, PUSH1 0, PUSH1 0, APPROVE(0xAA), STOP.
    // We build code that first executes TIMESTAMP (0x42) then falls through to
    // APPROVE so the payer IS established but the violation fires first.
    //
    // Code layout (10 bytes):
    //   0x42       TIMESTAMP (banned; pushes block.timestamp on stack)
    //   0x50       POP (clean up the extra stack value)
    //   0x60 0x03  PUSH1 3 (APPROVE_EXECUTION_AND_PAYMENT scope)
    //   0x60 0x00  PUSH1 0 (gas hint low)
    //   0x60 0x00  PUSH1 0 (gas hint high)
    //   0xAA       APPROVE
    //   0x00       STOP
    let timestamp_then_approve = Bytes::from(vec![
        0x42, // TIMESTAMP (banned)
        0x50, // POP (remove extra stack item from TIMESTAMP)
        0x60, 0x03, // PUSH1 3
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xAA, // APPROVE
        0x00, // STOP
    ]);

    let sender = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            sender,
            GenesisAccount {
                code: timestamp_then_approve,
                storage: BTreeMap::new(),
                balance: U256::from(10u64).pow(U256::from(18u64)),
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store =
        Store::new("hegota-banned-opcode-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    let blockchain = Blockchain::default_with_store(store);

    let frame_tx = funded_frame_tx(1_000_000_000, 1_000_000_000);
    let tx = Transaction::FrameTransaction(frame_tx);
    let result = blockchain.add_transaction_to_pool(tx).await;
    assert!(
        matches!(result, Err(MempoolError::FrameTxValidationFailed(_))),
        "frame tx executing TIMESTAMP in VERIFY prefix must yield FrameTxValidationFailed; got {result:?}"
    );
}

#[tokio::test]
async fn mempool_revalidation_evicts_invalid_frame_tx() {
    // Task 4.3: exercises the revalidation eviction path via the expiry trigger.
    //
    // Setup: use `setup_hegota_store_ts1000` (head.timestamp == 1000) plus a
    // funded sender balance. The expiry-verifier predeploy is already seeded.
    // A frame tx with deadline 2000 (future relative to head) plus positive fees
    // passes admission. After admission the reservation maps are non-empty.
    //
    // Revalidation: construct a minimal Block whose header.timestamp == 2001
    // (strictly greater than deadline 2000). The expiry-eviction branch in
    // `revalidate_frame_txs_after_block` fires before any state simulation,
    // evicting the tx and cleaning every reservation map.
    //
    // This exercises the revalidation eviction + reservation-cleanup path via
    // the expiry trigger. A balance/state-change trigger uses the same removal
    // path (`remove_transaction_with_lock` -> all four maps cleared).
    let funded_balance = U256::from(10u64).pow(U256::from(18u64));
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        timestamp: 1000, // head.timestamp == 1000
        alloc: [
            (
                Address::from_low_u64_be(FRAME_TX_SELF_SENDER),
                GenesisAccount {
                    code: approve_code(APPROVE_EXECUTION_AND_PAYMENT),
                    storage: BTreeMap::new(),
                    balance: funded_balance,
                    nonce: 0,
                },
            ),
            (
                frame_tx_expiry_verifier(),
                GenesisAccount {
                    code: Bytes::from_static(&[
                        0x60, 0x08, 0x36, 0x14, 0x60, 0x0a, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x5f,
                        0x35, 0x60, 0xc0, 0x1c, 0x42, 0x11, 0x60, 0x16, 0x57, 0x00, 0x5b, 0x5f,
                        0x5f, 0xfd,
                    ]),
                    storage: BTreeMap::new(),
                    balance: U256::zero(),
                    nonce: 0,
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store =
        Store::new("hegota-revalidation-test", EngineType::InMemory).expect("Storage setup");
    store
        .add_initial_state(genesis)
        .await
        .expect("add genesis state");
    let blockchain = Blockchain::default_with_store(store);

    // Build a frame tx with an expiry deadline of 2000 and positive fees.
    let deadline: u64 = 2000;
    let sender = Address::from_low_u64_be(FRAME_TX_SELF_SENDER);
    let mut expiry_tx = frame_tx_with_expiry(deadline);
    expiry_tx.max_fee_per_gas = U256::from(1_000_000_000u64);
    expiry_tx.max_priority_fee_per_gas = U256::from(1_000_000_000u64);
    let tx = Transaction::FrameTransaction(expiry_tx);
    let tx_hash = blockchain
        .add_transaction_to_pool(tx)
        .await
        .expect("funded expiry frame tx must be admitted");

    // Verify the reservation was recorded (non-zero reserved cost or maps filled).
    let (sz1, sz2, sz3, sz4) = blockchain
        .mempool
        .frame_tracking_map_sizes()
        .expect("frame_tracking_map_sizes");
    assert!(
        sz1 > 0 || sz2 > 0 || sz3 > 0 || sz4 > 0,
        "at least one tracking map must be non-empty after admission"
    );

    // Construct a minimal Block with timestamp 2001 (> deadline 2000).
    // We do NOT need to apply it to the store; the expiry-eviction branch in
    // `revalidate_frame_txs_after_block` checks `deadline < block.header.timestamp`
    // and fires before any state-simulation code.
    let eviction_block = Block::new(
        BlockHeader {
            number: 1,
            timestamp: 2001,
            gas_limit: 100_000_000,
            parent_hash: H256::zero(),
            ..Default::default()
        },
        BlockBody::empty(),
    );

    blockchain
        .revalidate_frame_txs_after_block(&eviction_block)
        .expect("revalidate_frame_txs_after_block must not error");

    // The tx must be evicted.
    let still_present = blockchain
        .mempool
        .get_mempool_transaction_by_hash(tx_hash)
        .expect("get_mempool_transaction_by_hash")
        .is_some();
    assert!(
        !still_present,
        "frame tx must be evicted after its expiry deadline passes revalidation"
    );

    // Every reservation map must be empty (reservation cleanup ran).
    assert_eq!(
        blockchain
            .mempool
            .frame_tracking_map_sizes()
            .expect("frame_tracking_map_sizes"),
        (0, 0, 0, 0),
        "all four frame tracking maps must be empty after eviction"
    );

    // The sender's reserved cost must be zero.
    let reserved = blockchain
        .mempool
        .reserved_pending_cost(sender)
        .expect("reserved_pending_cost");
    assert_eq!(
        reserved,
        U256::zero(),
        "reserved_pending_cost must be zero after eviction"
    );
}

mod alternates {
    use super::*;
    use ethrex_blockchain::mempool::MAX_ALTERNATES_PER_HASH;
    use std::time::Duration;

    fn h(n: u8) -> H256 {
        let mut b = [0u8; 32];
        b[31] = n;
        H256::from(b)
    }

    /// Helper that reserves `hashes` with synthetic per-hash (type, size)
    /// metadata. Tests that don't care about the metadata can use this.
    fn reserve(mp: &Mempool, hashes: &[H256], announcer: H256) -> Vec<H256> {
        let types = vec![0u8; hashes.len()];
        let sizes = vec![0usize; hashes.len()];
        mp.reserve_unknown_hashes(hashes, &types, &sizes, announcer)
            .unwrap()
    }

    #[test]
    fn primary_requester_is_not_an_alternate() {
        let mp = Mempool::new(64);
        let peer_a = h(1);
        let tx = h(0xa);

        // peer_a is the first announcer: it becomes the primary requester
        // (returned in `unknown`), so no alternates entry should be created.
        let unknown = reserve(&mp, &[tx], peer_a);
        assert_eq!(unknown, vec![tx]);
        assert!(mp.pop_alternate(tx).unwrap().is_none());
    }

    #[test]
    fn second_announcer_recorded_as_alternate() {
        let mp = Mempool::new(64);
        let peer_a = h(1);
        let peer_b = h(2);
        let tx_a = h(0xa);
        let tx_b = h(0xb);

        let unknown = reserve(&mp, &[tx_a, tx_b], peer_a);
        assert_eq!(unknown, vec![tx_a, tx_b]);

        // peer_b sees the same hashes already in-flight from peer_a, so it
        // should be filed as an alternate for each hash.
        let unknown = reserve(&mp, &[tx_a, tx_b], peer_b);
        assert!(unknown.is_empty());

        let alt_a = mp.pop_alternate(tx_a).unwrap().expect("alt for tx_a");
        let alt_b = mp.pop_alternate(tx_b).unwrap().expect("alt for tx_b");
        assert_eq!(alt_a.peer_id, peer_b);
        assert_eq!(alt_b.peer_id, peer_b);
    }

    #[test]
    fn alternate_carries_per_hash_type_and_size() {
        let mp = Mempool::new(64);
        let primary = h(1);
        let alt_peer = h(2);
        let tx = h(0xa);

        // primary announces with one (type, size); alt announces with another.
        // The stored alternate must carry the alt peer's metadata, not the
        // primary's, so a later retry validates the alt peer's response
        // against the alt's own announcement.
        mp.reserve_unknown_hashes(&[tx], &[0x03], &[42], primary)
            .unwrap();
        mp.reserve_unknown_hashes(&[tx], &[0x03], &[131072], alt_peer)
            .unwrap();

        let popped = mp.pop_alternate(tx).unwrap().expect("alt present");
        assert_eq!(popped.peer_id, alt_peer);
        assert_eq!(popped.tx_type, 0x03);
        assert_eq!(popped.tx_size, 131072);
    }

    #[test]
    fn pop_alternates_is_fifo_and_drains() {
        let mp = Mempool::new(64);
        let tx = h(0xab);
        let primary = h(99);
        let p1 = h(1);
        let p2 = h(2);
        let p3 = h(3);

        reserve(&mp, &[tx], primary);
        reserve(&mp, &[tx], p1);
        reserve(&mp, &[tx], p2);
        reserve(&mp, &[tx], p3);

        assert_eq!(mp.pop_alternate(tx).unwrap().unwrap().peer_id, p1);
        assert_eq!(mp.pop_alternate(tx).unwrap().unwrap().peer_id, p2);
        assert_eq!(mp.pop_alternate(tx).unwrap().unwrap().peer_id, p3);
        assert!(mp.pop_alternate(tx).unwrap().is_none());
    }

    #[test]
    fn alternates_capped() {
        let mp = Mempool::new(64);
        let tx = h(0xcd);
        let primary = h(0xff);
        reserve(&mp, &[tx], primary);
        for i in 0..(MAX_ALTERNATES_PER_HASH + 4) {
            reserve(&mp, &[tx], h(i as u8 + 1));
        }
        let mut count = 0;
        while mp.pop_alternate(tx).unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, MAX_ALTERNATES_PER_HASH);
    }

    #[test]
    fn duplicate_announcer_not_double_counted() {
        let mp = Mempool::new(64);
        let tx = h(0xef);
        let primary = h(0xff);
        let peer = h(42);
        reserve(&mp, &[tx], primary);
        reserve(&mp, &[tx], peer);
        reserve(&mp, &[tx], peer);
        reserve(&mp, &[tx], peer);
        let popped = mp.pop_alternate(tx).unwrap().expect("alt present");
        assert_eq!(popped.peer_id, peer);
        assert!(mp.pop_alternate(tx).unwrap().is_none());
    }

    #[test]
    fn prune_alternates_drops_stale_entries() {
        let mp = Mempool::new(64);
        let tx = h(0xaa);
        reserve(&mp, &[tx], h(1));
        reserve(&mp, &[tx], h(2));
        // Sleep well past the TTL so a loaded CI scheduler that gives us a
        // shorter-than-asked sleep still observes the entries as stale.
        std::thread::sleep(Duration::from_millis(20));
        mp.prune_alternates(Duration::from_millis(5)).unwrap();
        assert!(mp.pop_alternate(tx).unwrap().is_none());
    }
}

// `mempool-calldata-floor-gas-gap` (issue #6889): on Prague (the active fork)
// mempool admission must compute intrinsic gas the same way LEVM does at
// execution, and must reject empty EIP-7702 authorization lists. Otherwise txs
// that the VM will reject at inclusion are admitted, polluting the pool.

/// Prague config (Amsterdam NOT active); `config.fork(timestamp)` resolves to
/// Prague, so `intrinsic_gas_dimensions` exercises its pre-Amsterdam sub-path
/// (flat EIP-7702 auth-list cost + EIP-7623 calldata floor).
fn prague_config_and_header() -> (ChainConfig, BlockHeader) {
    let config = ChainConfig {
        istanbul_block: Some(0),
        shanghai_time: Some(0),
        cancun_time: Some(0),
        prague_time: Some(0),
        ..Default::default()
    };
    let header = BlockHeader {
        number: 5,
        timestamp: 5,
        gas_limit: 100_000_000,
        gas_used: 0,
        ..Default::default()
    };
    (config, header)
}

/// EIP-7702: each authorization tuple costs `PER_EMPTY_ACCOUNT_COST` (25000) of
/// intrinsic gas (LEVM charges it in `intrinsic_gas_dimensions`). Mempool
/// admission must charge it too. Unfixed mempool omits the auth-list cost
/// entirely on the pre-Amsterdam path.
#[test]
fn prague_eip7702_intrinsic_includes_auth_list_cost() {
    use ethrex_levm::constants::PER_EMPTY_ACCOUNT_COST;

    let (config, header) = prague_config_and_header();

    let auth = AuthorizationTuple::default();
    let tx = Transaction::EIP7702Transaction(EIP7702Transaction {
        chain_id: 0,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to: Address::from_low_u64_be(1),
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        authorization_list: vec![auth, auth], // 2 tuples
        ..Default::default()
    });

    let expected = TX_GAS_COST + 2 * PER_EMPTY_ACCOUNT_COST; // 21000 + 50000
    let got = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("intrinsic gas");
    assert_eq!(
        got, expected,
        "Prague type-4 mempool intrinsic must include PER_EMPTY_ACCOUNT_COST per \
         auth tuple (matches LEVM); unfixed mempool omits it"
    );
}

/// EIP-7623: a tx whose calldata floor exceeds its execution intrinsic must be
/// charged the floor. 1000 zero-bytes → legacy intrinsic 25000, floor 31000.
/// Unfixed mempool returns the sub-floor 25000 and admits a tx the VM rejects.
#[test]
fn prague_intrinsic_applies_eip7623_calldata_floor() {
    let (config, header) = prague_config_and_header();

    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        to: TxKind::Call(Address::from_low_u64_be(1)),
        value: U256::zero(),
        data: Bytes::from(vec![0u8; 1000]),
        access_list: Default::default(),
        ..Default::default()
    });

    // floor = TX_BASE_COST + 1000 tokens * 10 = 31000; legacy intrinsic = 25000.
    let expected_floor = 31_000;
    let got = transaction_intrinsic_gas(&tx, Address::default(), &header, &config)
        .expect("intrinsic gas");
    assert_eq!(
        got, expected_floor,
        "Prague mempool intrinsic must apply the EIP-7623 calldata floor (matches \
         LEVM); unfixed mempool returns the sub-floor legacy value 25000"
    );
}

/// EIP-7702: an empty `authorization_list` makes a type-4 tx invalid
/// (`validate_type_4_tx` rejects it). Mempool admission must reject it too.
/// Unfixed mempool admits it (sender is funded so the balance check passes).
#[tokio::test]
async fn validate_transaction_rejects_empty_auth_list() {
    let sender = Address::from_low_u64_be(0x1234);
    let mut alloc = BTreeMap::new();
    alloc.insert(
        sender,
        GenesisAccount {
            code: Bytes::new(),
            storage: BTreeMap::new(),
            balance: U256::from(10).pow(U256::from(20)), // 100 ETH
            nonce: 0,
        },
    );
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 1,
            homestead_block: Some(0),
            eip150_block: Some(0),
            eip155_block: Some(0),
            eip158_block: Some(0),
            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            berlin_block: Some(0),
            london_block: Some(0),
            merge_netsplit_block: Some(0),
            terminal_total_difficulty: Some(0),
            terminal_total_difficulty_passed: true,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            ..Default::default()
        },
        alloc,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(0),
        ..Default::default()
    };

    let mut store = Store::new("", EngineType::InMemory).expect("open in-memory store");
    store
        .add_initial_state(genesis)
        .await
        .expect("initialize genesis");
    let blockchain = Blockchain::default_with_store(store);

    let tx = Transaction::EIP7702Transaction(EIP7702Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: Address::from_low_u64_be(1),
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        authorization_list: vec![], // EMPTY — invalid per EIP-7702
        ..Default::default()
    });

    let res = blockchain.validate_transaction(&tx, sender).await;
    assert!(
        matches!(res, Err(MempoolError::EmptyAuthorizationList)),
        "type-4 tx with an empty authorization_list must be rejected at admission \
         with EmptyAuthorizationList; unfixed mempool admits it (got {res:?})"
    );
}

/// The empty-auth-list check must run before the intrinsic-gas check, so a
/// type-4 tx that is both empty-auth and under-gassed reports the structural
/// fault (`EmptyAuthorizationList`) rather than the downstream gas symptom —
/// matching LEVM's `validate_type_4_tx` ordering.
#[tokio::test]
async fn validate_transaction_empty_auth_reported_before_intrinsic() {
    let (config, header) = prague_config_and_header();
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = Transaction::EIP7702Transaction(EIP7702Transaction {
        chain_id: 0,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000, // below the 21000 intrinsic
        to: Address::from_low_u64_be(1),
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        authorization_list: vec![], // empty — the structural fault
        ..Default::default()
    });

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(
        matches!(res, Err(MempoolError::EmptyAuthorizationList)),
        "empty auth-list must be reported before the intrinsic-gas check (got {res:?})"
    );
}

/// EIP-7702 (type-4) txs only exist from Prague onward; LEVM rejects them with
/// `Type4TxPreFork` otherwise. Mempool admission must mirror that gate so a
/// pre-Prague node does not pool a type-4 tx that execution will reject.
#[tokio::test]
async fn validate_transaction_rejects_pre_prague_eip7702() {
    // Cancun active, Prague NOT active.
    let config = ChainConfig {
        istanbul_block: Some(0),
        shanghai_time: Some(0),
        cancun_time: Some(0),
        ..Default::default()
    };
    let header = BlockHeader {
        number: 5,
        timestamp: 5,
        gas_limit: 100_000_000,
        gas_used: 0,
        ..Default::default()
    };
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = Transaction::EIP7702Transaction(EIP7702Transaction {
        chain_id: 0,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 100_000,
        to: Address::from_low_u64_be(1),
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        authorization_list: vec![AuthorizationTuple::default()], // non-empty
        ..Default::default()
    });

    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(
        matches!(res, Err(MempoolError::Eip7702TxPreFork)),
        "pre-Prague type-4 tx must be rejected with Eip7702TxPreFork (got {res:?})"
    );
}

// ----------------------------------------------------------------------------
// Gap-admission tests
// ----------------------------------------------------------------------------
//
// These tests exercise the rule that, when the mempool is heavily occupied,
// incoming transactions with a nonce gap relative to the sender's on-chain
// nonce are rejected. Replacements (same nonce as a tx already in the pool)
// must bypass this rule, since they are not gapped.

const GAP_TEST_MEMPOOL_MAX: usize = 10;
const GAP_TEST_THRESHOLD_PCT: u8 = 90;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

async fn setup_funded_store(sender: Address) -> (Store, u64) {
    let file = File::open(workspace_root().join("fixtures/genesis/execution-api.json"))
        .expect("Failed to open genesis file");
    let reader = BufReader::new(file);
    let mut genesis: ethrex_common::types::Genesis =
        serde_json::from_reader(reader).expect("Failed to deserialize genesis file");

    let chain_id = genesis.config.chain_id;

    genesis.alloc.insert(
        sender,
        GenesisAccount {
            balance: U256::from(10).pow(U256::from(20)),
            code: Bytes::new(),
            storage: Default::default(),
            nonce: 0,
        },
    );

    let mut store =
        Store::new("store.db", EngineType::InMemory).expect("Failed to build DB for testing");

    store
        .add_initial_state(genesis)
        .await
        .expect("Failed to add genesis state");

    (store, chain_id)
}

/// Build a non-blob tx with the given nonce. The signature is dummy — the tests
/// here exercise `validate_transaction`, which never inspects the signature.
fn build_tx(chain_id: u64, nonce: u64) -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(Address::from_low_u64_be(0xABBA)),
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        ..Default::default()
    })
}

/// Inject `count` dummy transactions from random senders directly into the
/// mempool, bypassing validation. Used to push occupancy above a threshold.
fn fill_mempool(mempool: &Mempool, count: usize) {
    for i in 0..count {
        let sender = Address::from_low_u64_be(0x1000 + i as u64);
        let hash = H256::from_low_u64_be(0x1000 + i as u64);
        let tx = build_tx(1, 0);
        mempool
            .add_transaction(
                hash,
                sender,
                MempoolTransaction::new(tx, sender),
                None,
                None,
            )
            .expect("Failed to add transaction");
    }
}

fn blockchain_with_threshold(store: Store, threshold_pct: u8) -> Blockchain {
    Blockchain::new(
        store,
        BlockchainOptions {
            max_mempool_size: GAP_TEST_MEMPOOL_MAX,
            gap_admit_occupancy_threshold: threshold_pct,
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn gap_admission_rejected_when_pool_above_threshold() {
    let sender = Address::from_low_u64_be(0xAAA);
    let (store, chain_id) = setup_funded_store(sender).await;
    let blockchain = blockchain_with_threshold(store, GAP_TEST_THRESHOLD_PCT);

    // Push occupancy to 100% (10/10) — well above 90%.
    fill_mempool(&blockchain.mempool, GAP_TEST_MEMPOOL_MAX);

    // On-chain nonce is 0; submitting nonce=5 introduces a gap.
    let gapped_tx = build_tx(chain_id, 5);
    let result = blockchain.validate_transaction(&gapped_tx, sender).await;
    assert!(
        matches!(
            result,
            Err(MempoolError::GapAdmissionDeniedUnderPressure { .. })
        ),
        "expected GapAdmissionDeniedUnderPressure, got {result:?}"
    );
}

#[tokio::test]
async fn gap_admission_accepted_when_pool_below_threshold() {
    let sender = Address::from_low_u64_be(0xAAB);
    let (store, chain_id) = setup_funded_store(sender).await;
    let blockchain = blockchain_with_threshold(store, GAP_TEST_THRESHOLD_PCT);

    // Push occupancy to 50% — below 90%.
    fill_mempool(&blockchain.mempool, GAP_TEST_MEMPOOL_MAX / 2);

    let gapped_tx = build_tx(chain_id, 5);
    let result = blockchain.validate_transaction(&gapped_tx, sender).await;
    assert!(
        result.is_ok(),
        "expected gapped tx to be accepted under low pressure, got {result:?}"
    );
}

#[tokio::test]
async fn gap_admission_disabled_at_threshold_100() {
    let sender = Address::from_low_u64_be(0xAAC);
    let (store, chain_id) = setup_funded_store(sender).await;
    // Threshold of 100 disables the check entirely.
    let blockchain = blockchain_with_threshold(store, 100);

    // Fill to 100% to make the pool maximally occupied.
    fill_mempool(&blockchain.mempool, GAP_TEST_MEMPOOL_MAX);

    let gapped_tx = build_tx(chain_id, 5);
    let result = blockchain.validate_transaction(&gapped_tx, sender).await;
    assert!(
        result.is_ok(),
        "expected gapped tx to be accepted when threshold is 100, got {result:?}"
    );
}

#[tokio::test]
async fn contiguous_nonce_tx_accepted_under_high_occupancy() {
    let sender = Address::from_low_u64_be(0xAAD);
    let (store, chain_id) = setup_funded_store(sender).await;
    let blockchain = blockchain_with_threshold(store, GAP_TEST_THRESHOLD_PCT);

    fill_mempool(&blockchain.mempool, GAP_TEST_MEMPOOL_MAX);

    // On-chain nonce is 0; submitting nonce=0 is contiguous.
    let contiguous_tx = build_tx(chain_id, 0);
    let result = blockchain
        .validate_transaction(&contiguous_tx, sender)
        .await;
    assert!(
        result.is_ok(),
        "expected contiguous tx to be accepted under high pressure, got {result:?}"
    );
}

// `fee-token-l1-tx` (mempool-ingress side): an L1 node must reject L2-only tx
// types (FeeToken 0x7d, PrivilegedL2 0x7e) at admission — they are valid only on
// L2 and unknown to other L1 clients. `Blockchain::default_with_store` is an L1
// node (`BlockchainType::L1`). The L2 acceptance path is covered by the L2
// integration tests.

#[tokio::test]
async fn l1_validate_transaction_rejects_fee_token() {
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = Transaction::FeeTokenTransaction(FeeTokenTransaction::default());
    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(
        matches!(res, Err(MempoolError::L2OnlyTransactionType)),
        "an L1 node must reject FeeToken (0x7d) at admission (got {res:?})"
    );
}

#[tokio::test]
async fn replacement_at_existing_nonce_bypasses_gap_admission() {
    let sender = Address::from_low_u64_be(0xAAE);
    let (store, chain_id) = setup_funded_store(sender).await;
    let blockchain = blockchain_with_threshold(store, GAP_TEST_THRESHOLD_PCT);

    // First, add a gapped tx while the pool has plenty of room.
    let original_tx = build_tx(chain_id, 5);
    let original_hash = original_tx.hash(&NativeCrypto);
    blockchain
        .mempool
        .add_transaction(
            original_hash,
            sender,
            MempoolTransaction::new(original_tx, sender),
            None,
            None,
        )
        .expect("Failed to seed the pool with a tx at nonce 5");

    // Now push the pool above the threshold.
    fill_mempool(&blockchain.mempool, GAP_TEST_MEMPOOL_MAX.saturating_sub(1));

    // Build a replacement at the same nonce with strictly higher fees so that
    // `find_tx_to_replace` returns Some(_), bypassing the gap-admission rule.
    let replacement_tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id,
        nonce: 5,
        max_priority_fee_per_gas: 2,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(Address::from_low_u64_be(0xABBA)),
        value: U256::zero(),
        data: Bytes::default(),
        access_list: Default::default(),
        ..Default::default()
    });

    let result = blockchain
        .validate_transaction(&replacement_tx, sender)
        .await;
    // A fresh gapped tx here would hit `GapAdmissionDeniedUnderPressure`; the
    // replacement is exempt, so validation passes.
    assert!(
        result.is_ok(),
        "expected replacement to bypass gap-admission rule, got {result:?}"
    );
}

#[tokio::test]
async fn l1_validate_transaction_rejects_privileged_l2() {
    let (config, header) = build_basic_config_and_header(false, false);
    let store = setup_storage(config, header).await.expect("Storage setup");
    let blockchain = Blockchain::default_with_store(store);

    let tx = Transaction::PrivilegedL2Transaction(PrivilegedL2Transaction::default());
    let res = blockchain
        .validate_transaction(&tx, Address::random())
        .await;
    assert!(
        matches!(res, Err(MempoolError::L2OnlyTransactionType)),
        "an L1 node must reject PrivilegedL2 (0x7e) at admission (got {res:?})"
    );
}

// ==================== Relocated from crates/blockchain/blockchain.rs ====================
// A pooled frame transaction (EIP-8141) must be served over P2P as a
// `P2PTransaction::FrameTransaction` instead of being rejected.
mod p2p_serve_tests {
    use ethrex_blockchain::Blockchain;
    use ethrex_common::types::{
        FRAME_SIG_SCHEME_SECP256K1, Frame, FrameMode, FrameSignature, FrameTransaction, GasLimits,
        MempoolTransaction, P2PTransaction, Transaction,
    };
    use ethrex_common::{Address, U256};
    use ethrex_crypto::NativeCrypto;
    use ethrex_storage::{EngineType, Store};

    fn make_frame_tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce: 7,
            sender: Address::from_low_u64_be(0xABCD),
            frames: vec![Frame {
                mode: FrameMode::Sender as u8,
                flags: 0x00,
                target: Some(Address::from_low_u64_be(0x1234)),
                gas_limits: GasLimits {
                    execution: 100_000,
                    state: 0,
                },
                value: U256::zero(),
                data: bytes::Bytes::from_static(b"call_data"),
            }],
            signatures: vec![FrameSignature {
                scheme: FRAME_SIG_SCHEME_SECP256K1,
                signer: Some(Address::from_low_u64_be(0xABCD)),
                msg: bytes::Bytes::new(),
                signature: bytes::Bytes::from(vec![0u8; 65]),
            }],
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn get_p2p_transaction_by_hash_serves_frame_tx() {
        let store = Store::new("", EngineType::InMemory).expect("failed to create in-memory store");
        let blockchain = Blockchain::default_with_store(store);

        let ftx = make_frame_tx();
        let tx = Transaction::FrameTransaction(ftx);
        let sender = Address::from_low_u64_be(0xABCD);
        let hash = tx.hash(&NativeCrypto);

        // Insert directly into the mempool (bypassing validation) so we
        // exercise only the P2P serve path.
        blockchain
            .mempool
            .add_transaction(
                hash,
                sender,
                MempoolTransaction::new(tx, sender),
                None,
                None,
            )
            .expect("failed to add frame tx to mempool");

        let served = blockchain
            .get_p2p_transaction_by_hash(&hash)
            .expect("frame tx should be served over P2P");
        assert!(matches!(served, P2PTransaction::FrameTransaction(_)));
        assert_eq!(served.compute_hash(), hash);
    }
}

// Cumulative per-sender balance check: `Mempool::sum_cost_for_sender`. Relocated
// here from an inline `#[cfg(test)]` module in `crates/blockchain/mempool.rs`.
mod cumulative_balance_tests {
    use super::*;

    fn build_tx(nonce: u64, max_fee_per_gas: u64, gas_limit: u64, value: U256) -> Transaction {
        Transaction::EIP1559Transaction(EIP1559Transaction {
            nonce,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas,
            gas_limit,
            to: TxKind::Call(Address::from_low_u64_be(1)),
            value,
            ..Default::default()
        })
    }

    fn insert_tx(mempool: &Mempool, sender: Address, tx: Transaction) -> H256 {
        let hash = H256::random();
        mempool
            .add_transaction(
                hash,
                sender,
                MempoolTransaction::new(tx, sender),
                None,
                None,
            )
            .expect("add_transaction");
        hash
    }

    #[test]
    fn sum_cost_for_sender_empty_pool_is_zero() {
        let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
        let sender = Address::random();

        let total = mempool.sum_cost_for_sender(sender, 0, None).expect("sum");
        assert_eq!(total, U256::zero());
    }

    #[test]
    fn sum_cost_for_sender_sums_multiple_nonces() {
        let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
        let sender = Address::random();

        let tx0 = build_tx(0, 10, 21_000, U256::from(100u64));
        let tx1 = build_tx(1, 20, 21_000, U256::from(200u64));
        let tx2 = build_tx(2, 30, 21_000, U256::from(300u64));

        let expected = tx0.cost_without_base_fee().unwrap()
            + tx1.cost_without_base_fee().unwrap()
            + tx2.cost_without_base_fee().unwrap();

        insert_tx(&mempool, sender, tx0);
        insert_tx(&mempool, sender, tx1);
        insert_tx(&mempool, sender, tx2);

        let total = mempool.sum_cost_for_sender(sender, 0, None).expect("sum");
        assert_eq!(total, expected);
    }

    #[test]
    fn sum_cost_for_sender_ignores_other_senders() {
        let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
        let sender_a = Address::random();
        let sender_b = Address::random();

        let tx_a = build_tx(0, 10, 21_000, U256::from(100u64));
        let tx_b = build_tx(0, 50, 21_000, U256::from(999u64));

        let expected_a = tx_a.cost_without_base_fee().unwrap();

        insert_tx(&mempool, sender_a, tx_a);
        insert_tx(&mempool, sender_b, tx_b);

        let total_a = mempool
            .sum_cost_for_sender(sender_a, 0, None)
            .expect("sum a");
        assert_eq!(total_a, expected_a);
    }

    #[test]
    fn sum_cost_for_sender_after_remove_drops_that_tx() {
        let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
        let sender = Address::random();

        let tx0 = build_tx(0, 10, 21_000, U256::from(100u64));
        let tx1 = build_tx(1, 10, 21_000, U256::from(200u64));
        let expected_after = tx1.cost_without_base_fee().unwrap();

        let hash0 = insert_tx(&mempool, sender, tx0);
        insert_tx(&mempool, sender, tx1);

        mempool.remove_transaction(&hash0).expect("remove");

        let total = mempool.sum_cost_for_sender(sender, 0, None).expect("sum");
        assert_eq!(total, expected_after);
    }

    // Obsoleted txs (nonce below the sender's on-chain nonce — already mined but
    // not yet pruned) must NOT count toward the cumulative-balance sum.
    #[test]
    fn sum_cost_for_sender_excludes_obsoleted_nonces() {
        let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
        let sender = Address::random();

        let tx0 = build_tx(0, 10, 21_000, U256::from(100u64));
        let tx1 = build_tx(1, 20, 21_000, U256::from(200u64));
        let tx2 = build_tx(2, 30, 21_000, U256::from(300u64));
        let expected = tx2.cost_without_base_fee().unwrap();

        insert_tx(&mempool, sender, tx0);
        insert_tx(&mempool, sender, tx1);
        insert_tx(&mempool, sender, tx2);

        // On-chain nonce advanced to 2: nonces 0 and 1 are obsoleted and excluded.
        let total = mempool.sum_cost_for_sender(sender, 2, None).expect("sum");
        assert_eq!(total, expected);
    }
}

/// `add_transaction` queues the tx for P2P broadcast (the default path).
/// `add_transaction_no_broadcast` does not, modeling the private-mempool
/// flag's effect on RPC-submitted transactions: they're available locally
/// but never appear in `get_txs_for_broadcast`.
#[test]
fn add_transaction_no_broadcast_keeps_tx_out_of_broadcast_pool() {
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);

    // Public tx — goes through the standard path, ends up in broadcast pool.
    let public_decoded = Transaction::decode_canonical(&hex::decode(
        "f86d80843baa0c4082f618946177843db3138ae69679a54b95cf345ed759450d870aa87bee538000808360306ba0151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65da064c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4",
    ).unwrap()).unwrap();
    let public_sender = public_decoded.sender(&NativeCrypto).unwrap();
    let public_tx = MempoolTransaction::new(public_decoded, public_sender);
    let public_hash = public_tx.hash(&NativeCrypto);

    // Private tx — goes through `add_transaction_no_broadcast`, only
    // distinguishable from `public_tx` by sender (so the per-sender-nonce
    // index doesn't collide).
    let private_decoded = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(H160::from_low_u64_be(0xBEEF)),
        value: U256::zero(),
        ..Default::default()
    });
    // Using a synthetic sender so we don't need a signed tx for this test.
    let private_sender = Address::from_low_u64_be(0xCAFE);
    let private_hash = private_decoded.hash(&NativeCrypto);
    let private_tx = MempoolTransaction::new(private_decoded, private_sender);

    mempool
        .add_transaction(public_hash, public_sender, public_tx, None, None)
        .expect("public tx should land in broadcast pool");
    mempool
        .add_transaction_no_broadcast(private_hash, private_sender, private_tx, None, None)
        .expect("private tx should land in mempool but not broadcast pool");

    // Both txs are queryable from the mempool itself.
    assert!(mempool.contains_tx(public_hash).unwrap());
    assert!(mempool.contains_tx(private_hash).unwrap());

    // Only the public one is returned for broadcast.
    let broadcast: Vec<H256> = mempool
        .get_txs_for_broadcast()
        .unwrap()
        .iter()
        .map(|tx| tx.hash(&NativeCrypto))
        .collect();
    assert!(broadcast.contains(&public_hash));
    assert!(
        !broadcast.contains(&private_hash),
        "private tx must not appear in get_txs_for_broadcast"
    );

    // After remove_broadcasted_txs clears the public hash, the private tx
    // remains absent (proving the broadcast pool never contained it).
    mempool.remove_broadcasted_txs(&[public_hash]).unwrap();
    let broadcast_after: Vec<H256> = mempool
        .get_txs_for_broadcast()
        .unwrap()
        .iter()
        .map(|tx| tx.hash(&NativeCrypto))
        .collect();
    assert!(broadcast_after.is_empty());
}

/// Private-mempool leak guard: a tx admitted via
/// `add_transaction_no_broadcast` MUST be flagged via `is_private()` so the
/// P2P paths (new-peer pooled-hashes dump in `send_all_pooled_tx_hashes`,
/// and `GetPooledTransactions` responses via
/// `Blockchain::get_p2p_transaction_by_hash`) can refuse to disclose it.
#[test]
fn add_transaction_no_broadcast_marks_tx_as_private_for_p2p_filters() {
    let mempool = Mempool::new(MEMPOOL_MAX_SIZE_TEST);
    let public_decoded = Transaction::decode_canonical(&hex::decode(
        "f86d80843baa0c4082f618946177843db3138ae69679a54b95cf345ed759450d870aa87bee538000808360306ba0151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65da064c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4",
    ).unwrap()).unwrap();
    let public_sender = public_decoded.sender(&NativeCrypto).unwrap();
    let public_tx = MempoolTransaction::new(public_decoded, public_sender);
    let public_hash = public_tx.hash(&NativeCrypto);

    let private_decoded = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(H160::from_low_u64_be(0xBEEF)),
        value: U256::zero(),
        ..Default::default()
    });
    let private_sender = Address::from_low_u64_be(0xCAFE);
    let private_hash = private_decoded.hash(&NativeCrypto);
    let private_tx = MempoolTransaction::new(private_decoded, private_sender);

    mempool
        .add_transaction(public_hash, public_sender, public_tx, None, None)
        .unwrap();
    mempool
        .add_transaction_no_broadcast(private_hash, private_sender, private_tx, None, None)
        .unwrap();

    // Public tx is not private; private tx is.
    assert!(!mempool.is_private(public_hash).unwrap());
    assert!(mempool.is_private(private_hash).unwrap());

    // Removal clears the private flag (so a re-added hash isn't misclassified).
    mempool.remove_transaction(&private_hash).unwrap();
    assert!(!mempool.is_private(private_hash).unwrap());

    // Hashes that were never in the pool are also not private.
    assert!(!mempool.is_private(H256::random()).unwrap());
}
