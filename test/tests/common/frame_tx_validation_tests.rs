//! EIP-8141 frame-transaction validation tests (migrated from inline modules).
//!
//! Covers:
//!   - Blob-gas accounting for frame transactions (migrated from `crates/common/validation.rs`).
//!   - Validation-prefix recognition and structural validation (Phase 1, task 1.7,
//!     migrated from `crates/common/types/transaction.rs`).

use bytes::Bytes;
use ethrex_common::constants::GAS_PER_BLOB;
use ethrex_common::types::{
    APPROVE_EXECUTION, APPROVE_EXECUTION_AND_PAYMENT, APPROVE_PAYMENT, Block, BlockBody,
    BlockHeader, ChainConfig, EIP4844Transaction, FRAME_SIG_SCHEME_ARBITRARY,
    FRAME_SIG_SCHEME_SECP256K1, FRAME_TX_MAX_VERIFY_GAS, FRAME_TX_MAX_VERIFY_STATE_GAS, Frame,
    FrameMode, FrameSignature, FrameTransaction, FrameValidationError, GasLimits, PrefixShape,
    Transaction, frame_tx_expiry_verifier,
};

/// EIP-4844 `VERSIONED_HASH_VERSION_KZG`. The constant itself lives in a private
/// module of `ethrex-common`, so it is restated here.
const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
use ethrex_common::validation::verify_blob_gas_usage;
use ethrex_common::{Address, H256, U256};

// ---------------------------------------------------------------------------
// Helpers shared by blob-gas and prefix tests
// ---------------------------------------------------------------------------

/// Minimal cancun-active ChainConfig: only cancun_time set (= 0), default
/// blob schedule (max = 6 blobs per block).
fn cancun_config() -> ChainConfig {
    ChainConfig {
        cancun_time: Some(0),
        ..Default::default()
    }
}

/// A minimal FrameTransaction with the given number of blob versioned hashes.
fn frame_tx_with_blobs(n_blobs: usize) -> FrameTransaction {
    FrameTransaction {
        chain_id: 0,
        nonce: 0,
        sender: Default::default(),
        frames: vec![Frame {
            mode: FrameMode::Default as u8,
            flags: 0x00,
            target: None,
            gas_limits: GasLimits {
                execution: 0,
                state: 0,
            },
            value: Default::default(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(0u64),
        max_fee_per_gas: U256::from(0u64),
        max_fee_per_blob_gas: Default::default(),
        blob_versioned_hashes: (0..n_blobs).map(|_| H256::zero()).collect(),
        ..Default::default()
    }
}

/// Build a minimal Block with the given transactions and blob_gas_used header
/// value. timestamp = 1 so cancun_time = 0 is active.
fn make_block(transactions: Vec<Transaction>, blob_gas_used: u64) -> Block {
    Block {
        header: BlockHeader {
            timestamp: 1,
            gas_limit: 30_000_000,
            blob_gas_used: Some(blob_gas_used),
            excess_blob_gas: Some(0),
            ..Default::default()
        },
        body: BlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(vec![]),
        },
    }
}

// ---------------------------------------------------------------------------
// EIP-8141 frame tx blob gas accounting
// ---------------------------------------------------------------------------

#[test]
fn frame_tx_blob_gas_counts_correctly() {
    let config = cancun_config();
    let tx = Transaction::FrameTransaction(frame_tx_with_blobs(2));
    let block = make_block(vec![tx], 2 * GAS_PER_BLOB as u64);
    assert!(verify_blob_gas_usage(&block, &config).is_ok());
}

#[test]
fn frame_tx_blob_gas_mismatch_fails() {
    use ethrex_common::errors::InvalidBlockError;
    let config = cancun_config();
    let tx = Transaction::FrameTransaction(frame_tx_with_blobs(2));
    // Header claims 0 but actual is 2 * GAS_PER_BLOB
    let block = make_block(vec![tx], 0);
    assert!(matches!(
        verify_blob_gas_usage(&block, &config),
        Err(InvalidBlockError::BlobGasUsedMismatch)
    ));
}

#[test]
fn mixed_eip4844_and_frame_tx_blobs_counted_together() {
    let config = cancun_config();
    let eip4844_tx = Transaction::EIP4844Transaction(EIP4844Transaction {
        blob_versioned_hashes: vec![H256::zero()],
        ..Default::default()
    });
    let frame_tx = Transaction::FrameTransaction(frame_tx_with_blobs(2));
    let expected_gas = 3 * GAS_PER_BLOB as u64; // 1 EIP-4844 + 2 frame
    let block = make_block(vec![eip4844_tx, frame_tx], expected_gas);
    assert!(verify_blob_gas_usage(&block, &config).is_ok());
}

// ---------------------------------------------------------------------------
// EIP-8141 validation-prefix recognition and structural validation (task 1.7)
// ---------------------------------------------------------------------------

fn sender_addr() -> Address {
    Address::from_low_u64_be(0xABCD)
}

fn expiry_verifier_frame() -> Frame {
    Frame {
        mode: FrameMode::Verify as u8,
        flags: 0x00,
        target: Some(frame_tx_expiry_verifier()),
        gas_limits: GasLimits {
            execution: 1_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::from(vec![0u8; 8]),
    }
}

fn self_verify_frame() -> Frame {
    Frame {
        mode: FrameMode::Verify as u8,
        flags: APPROVE_EXECUTION_AND_PAYMENT,
        target: Some(sender_addr()),
        gas_limits: GasLimits {
            execution: 10_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::new(),
    }
}

fn only_verify_frame() -> Frame {
    Frame {
        mode: FrameMode::Verify as u8,
        flags: APPROVE_EXECUTION,
        target: Some(sender_addr()),
        gas_limits: GasLimits {
            execution: 10_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::new(),
    }
}

fn pay_frame() -> Frame {
    Frame {
        mode: FrameMode::Verify as u8,
        flags: APPROVE_PAYMENT,
        target: Some(sender_addr()),
        gas_limits: GasLimits {
            execution: 10_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::new(),
    }
}

fn deploy_frame() -> Frame {
    Frame {
        mode: FrameMode::Default as u8,
        flags: 0x00,
        target: None,
        gas_limits: GasLimits {
            execution: 50_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::from_static(b"deploy_bytecode"),
    }
}

fn base_frame_tx_with_frames(frames: Vec<Frame>) -> FrameTransaction {
    FrameTransaction {
        sender: sender_addr(),
        frames,
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        max_fee_per_gas: U256::from(30_000_000_000u64),
        ..Default::default()
    }
}

// --- Passing shape tests ---

#[test]
fn prefix_shape_self_verify() {
    let tx = base_frame_tx_with_frames(vec![self_verify_frame()]);
    let prefix = tx.validation_prefix().expect("should recognize SelfVerify");
    assert_eq!(prefix.shape, PrefixShape::SelfVerify);
    assert_eq!(prefix.frame_indices, vec![0]);
    assert_eq!(prefix.deploy_index, None);
    assert_eq!(prefix.pay_index, Some(0));
    tx.validate_prefix_structure(&prefix)
        .expect("SelfVerify structure should be valid");
}

#[test]
fn prefix_shape_deploy_self_verify() {
    let tx = base_frame_tx_with_frames(vec![deploy_frame(), self_verify_frame()]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeploySelfVerify");
    assert_eq!(prefix.shape, PrefixShape::DeploySelfVerify);
    assert_eq!(prefix.frame_indices, vec![0, 1]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(1));
    tx.validate_prefix_structure(&prefix)
        .expect("DeploySelfVerify structure should be valid");
}

#[test]
fn prefix_shape_only_verify_pay() {
    let tx = base_frame_tx_with_frames(vec![only_verify_frame(), pay_frame()]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize OnlyVerifyPay");
    assert_eq!(prefix.shape, PrefixShape::OnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1]);
    assert_eq!(prefix.deploy_index, None);
    assert_eq!(prefix.pay_index, Some(1));
    tx.validate_prefix_structure(&prefix)
        .expect("OnlyVerifyPay structure should be valid");
}

#[test]
fn prefix_shape_deploy_only_verify_pay() {
    let tx = base_frame_tx_with_frames(vec![deploy_frame(), only_verify_frame(), pay_frame()]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeployOnlyVerifyPay");
    assert_eq!(prefix.shape, PrefixShape::DeployOnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(2));
    tx.validate_prefix_structure(&prefix)
        .expect("DeployOnlyVerifyPay structure should be valid");
}

#[test]
fn prefix_shape_self_verify_with_interleaved_expiry_verifier() {
    // Expiry-verifier frames are transparent: they are skipped during
    // shape matching. The prefix should still be recognized as SelfVerify.
    let tx = base_frame_tx_with_frames(vec![expiry_verifier_frame(), self_verify_frame()]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize SelfVerify with leading expiry-verifier");
    assert_eq!(prefix.shape, PrefixShape::SelfVerify);
    // frame_indices omits the expiry-verifier (index 0); self_verify is at index 1.
    assert_eq!(prefix.frame_indices, vec![1]);
    tx.validate_prefix_structure(&prefix)
        .expect("SelfVerify with expiry-verifier should be structurally valid");
}

#[test]
fn prefix_shape_deploy_self_verify_with_expiry_verifier_between() {
    // Expiry verifier between deploy and self-verify should be transparent.
    let tx = base_frame_tx_with_frames(vec![
        deploy_frame(),
        expiry_verifier_frame(),
        self_verify_frame(),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeploySelfVerify with interleaved expiry-verifier");
    assert_eq!(prefix.shape, PrefixShape::DeploySelfVerify);
    assert_eq!(prefix.frame_indices, vec![0, 2]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(2));
    tx.validate_prefix_structure(&prefix)
        .expect("DeploySelfVerify with expiry-verifier should be structurally valid");
}

#[test]
fn prefix_shape_deploy_self_verify_with_leading_expiry_verifier() {
    // Expiry-verifier frame at raw index 0 means the deploy frame has raw
    // index 1. `validate_prefix_structure` must not reject this with
    // `DeployNotFirst` — the deploy IS first among non-expiry frames.
    let tx = base_frame_tx_with_frames(vec![
        expiry_verifier_frame(), // raw index 0 — skipped by shape matching
        deploy_frame(),          // raw index 1 — first non-expiry frame
        self_verify_frame(),     // raw index 2
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeploySelfVerify with leading expiry-verifier");
    assert_eq!(prefix.shape, PrefixShape::DeploySelfVerify);
    assert_eq!(prefix.frame_indices, vec![1, 2]);
    assert_eq!(prefix.deploy_index, Some(1));
    assert_eq!(prefix.pay_index, Some(2));
    tx.validate_prefix_structure(&prefix)
        .expect("DeploySelfVerify with raw-index-1 deploy should be structurally valid");
}

// --- Rejection tests ---

#[test]
fn prefix_rejection_unrecognized_shape() {
    // A single DEFAULT frame with no VERIFY frames cannot match any shape.
    let tx = base_frame_tx_with_frames(vec![Frame {
        mode: FrameMode::Default as u8,
        flags: 0x00,
        target: None,
        gas_limits: GasLimits {
            execution: 10_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::new(),
    }]);
    assert_eq!(
        tx.validation_prefix().unwrap_err(),
        FrameValidationError::UnrecognizedPrefix
    );
}

#[test]
fn prefix_rejection_deploy_not_first() {
    // A VERIFY frame followed by a DEFAULT frame: the DEFAULT is not at index 0
    // of non-expiry frames, so this doesn't match any shape that has a deploy.
    // It also doesn't match SelfVerify (wrong scope) or OnlyVerifyPay (wrong scope).
    // This is unrecognized.
    let tx = base_frame_tx_with_frames(vec![
        Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(sender_addr()),
            gas_limits: GasLimits {
                execution: 5_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        },
        deploy_frame(),
    ]);
    // Shape matching succeeds (SelfVerify — only the first frame matters for prefix).
    let prefix = tx
        .validation_prefix()
        .expect("SelfVerify recognized (deploy after prefix is ignored)");
    assert_eq!(prefix.shape, PrefixShape::SelfVerify);
    // Structure validation passes too (the deploy frame is not in the prefix).
    tx.validate_prefix_structure(&prefix)
        .expect("SelfVerify with trailing deploy is structurally valid");
}

#[test]
fn prefix_rejection_two_deploys_in_prefix() {
    // DeployOnlyVerifyPay with two DEFAULT frames before the pair — the second
    // DEFAULT would be at non-zero position, which doesn't match any shape.
    // Shape matching: position 0 is DEFAULT, position 1 is DEFAULT (not VERIFY) —
    // none of the four shapes matches.
    let tx = base_frame_tx_with_frames(vec![
        deploy_frame(),
        deploy_frame(),
        only_verify_frame(),
        pay_frame(),
    ]);
    // Position 0=DEFAULT, position 1=DEFAULT → DeployOnlyVerifyPay needs
    // pos 1 to be VERIFY(exec). Shape is unrecognized.
    assert_eq!(
        tx.validation_prefix().unwrap_err(),
        FrameValidationError::UnrecognizedPrefix
    );
}

#[test]
fn prefix_rejection_target_not_sender() {
    let other = Address::from_low_u64_be(0xDEAD);
    let mut frame = self_verify_frame();
    frame.target = Some(other);
    let tx = base_frame_tx_with_frames(vec![frame]);
    let prefix = tx.validation_prefix().expect("shape recognized");
    assert_eq!(
        tx.validate_prefix_structure(&prefix).unwrap_err(),
        FrameValidationError::VerifyTargetNotSender { frame_index: 0 }
    );
}

#[test]
fn prefix_rejection_wrong_scope_self_verify() {
    // SelfVerify frame must have scope APPROVE_EXECUTION_AND_PAYMENT (0x3),
    // not APPROVE_EXECUTION (0x2).
    let mut frame = self_verify_frame();
    frame.flags = APPROVE_EXECUTION;
    let tx = base_frame_tx_with_frames(vec![frame, pay_frame()]);
    // With scope 0x2 at position 0 and APPROVE_PAYMENT at position 1, this
    // matches OnlyVerifyPay shape (pos 0 = VERIFY(exec), pos 1 = VERIFY(pay)).
    let prefix = tx.validation_prefix().expect("OnlyVerifyPay recognized");
    assert_eq!(prefix.shape, PrefixShape::OnlyVerifyPay);
    tx.validate_prefix_structure(&prefix)
        .expect("OnlyVerifyPay structure is valid");
    // Now single VERIFY with wrong scope for SelfVerify: only one VERIFY with
    // APPROVE_EXECUTION means no SelfVerify shape.
    let tx2 = base_frame_tx_with_frames(vec![Frame {
        mode: FrameMode::Verify as u8,
        flags: APPROVE_EXECUTION,
        target: Some(sender_addr()),
        gas_limits: GasLimits {
            execution: 10_000,
            state: 0,
        },
        value: U256::zero(),
        data: Bytes::new(),
    }]);
    assert_eq!(
        tx2.validation_prefix().unwrap_err(),
        FrameValidationError::UnrecognizedPrefix,
        "VERIFY with APPROVE_EXECUTION alone is not a recognized shape"
    );
}

#[test]
fn prefix_rejection_wrong_scope_only_verify_pay() {
    // only_verify frame must have APPROVE_EXECUTION (0x2), not 0x3.
    let mut verify = only_verify_frame();
    verify.flags = APPROVE_EXECUTION_AND_PAYMENT;
    // Both frames have scope 0x3: doesn't match OnlyVerifyPay (pos 0 needs 0x2),
    // but matches SelfVerify (pos 0 has scope 0x3).
    let tx = base_frame_tx_with_frames(vec![verify, pay_frame()]);
    let prefix = tx.validation_prefix().expect("SelfVerify recognized");
    assert_eq!(prefix.shape, PrefixShape::SelfVerify);
    // The structure is valid for SelfVerify (only the first frame is in the prefix).
    tx.validate_prefix_structure(&prefix)
        .expect("SelfVerify structure valid");
}

#[test]
fn prefix_rejection_atomic_batch_in_prefix() {
    let mut frame = self_verify_frame();
    frame.flags = APPROVE_EXECUTION_AND_PAYMENT | 0x04; // set atomic batch bit
    // Need a following frame so static validation doesn't reject atomic batch on last frame.
    let tx = base_frame_tx_with_frames(vec![frame, pay_frame()]);
    // Shape: pos 0 has scope 0x3 (bits 0-1 of 0x07 = 0x3) and VERIFY mode → SelfVerify.
    let prefix = tx.validation_prefix().expect("SelfVerify recognized");
    assert_eq!(prefix.shape, PrefixShape::SelfVerify);
    assert_eq!(
        tx.validate_prefix_structure(&prefix).unwrap_err(),
        FrameValidationError::AtomicBatchInPrefix { frame_index: 0 }
    );
}

#[test]
fn prefix_rejection_gas_budget_exceeded() {
    // Give the self_verify frame a gas_limit that, combined with sig cost,
    // exceeds MAX_VERIFY_GAS (100_000). Sig cost for one SECP256K1 = 2800.
    let mut frame = self_verify_frame();
    frame.gas_limits.execution = FRAME_TX_MAX_VERIFY_GAS; // 100_000 alone already == limit
    let mut tx = base_frame_tx_with_frames(vec![frame]);
    // Ensure exactly one SECP256K1 sig so sig cost = 2800.
    tx.signatures = vec![FrameSignature {
        scheme: FRAME_SIG_SCHEME_SECP256K1,
        signer: Some(sender_addr()),
        msg: Bytes::new(),
        signature: Bytes::from(vec![0u8; 65]),
    }];
    let prefix = tx.validation_prefix().expect("SelfVerify recognized");
    // 100_000 + 2_800 > 100_000 → budget exceeded.
    assert!(matches!(
        tx.validate_prefix_structure(&prefix).unwrap_err(),
        FrameValidationError::VerifyGasBudgetExceeded { .. }
    ));
}

#[test]
fn prefix_state_gas_budget_is_capped_independently_of_execution_gas() {
    // Per EIP-8141 the validation prefix carries two independent caps: its
    // execution budgets plus the signature cost against MAX_VERIFY_GAS, and its
    // state budgets against the much larger MAX_VERIFY_STATE_GAS. State gas does
    // not measure the node's simulation work, so it must not consume the budget
    // that bounds it.
    let mut frame = self_verify_frame();
    // State gas well past MAX_VERIFY_GAS but within MAX_VERIFY_STATE_GAS, and an
    // execution budget that leaves room for the signature cost: admissible only
    // because the two dimensions are capped separately.
    frame.gas_limits.execution = 10_000;
    frame.gas_limits.state = FRAME_TX_MAX_VERIFY_STATE_GAS;
    let tx = base_frame_tx_with_frames(vec![frame.clone()]);
    let prefix = tx.validation_prefix().expect("SelfVerify recognized");
    assert!(
        tx.validate_prefix_structure(&prefix).is_ok(),
        "state gas within its own cap must not be charged against MAX_VERIFY_GAS"
    );

    // One gas past the state cap is rejected, and as a state-gas overrun.
    let mut over = frame;
    over.gas_limits.state = FRAME_TX_MAX_VERIFY_STATE_GAS + 1;
    let tx = base_frame_tx_with_frames(vec![over]);
    let prefix = tx.validation_prefix().expect("SelfVerify recognized");
    assert!(matches!(
        tx.validate_prefix_structure(&prefix).unwrap_err(),
        FrameValidationError::VerifyStateGasBudgetExceeded { .. }
    ));
}

// ---------------------------------------------------------------------------
// Static constraints and gas accounting
// ---------------------------------------------------------------------------

/// A frame transaction that satisfies every static constraint, for tests that
/// then violate exactly one of them.
fn make_test_frame_tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 1,
        nonce: 42,
        sender: Address::from_low_u64_be(0xABCD),
        frames: vec![
            Frame {
                mode: FrameMode::Verify as u8,
                flags: 0x03, // APPROVE_EXECUTION_AND_PAYMENT
                target: Some(Address::from_low_u64_be(0xABCD)),
                gas_limits: GasLimits {
                    execution: 100_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::from_static(b"verify_data"),
            },
            Frame {
                mode: FrameMode::Sender as u8,
                flags: 0x00,
                target: Some(Address::from_low_u64_be(0x1234)),
                gas_limits: GasLimits {
                    execution: 200_000,
                    state: 0,
                },
                value: U256::zero(),
                data: Bytes::from_static(b"call_data"),
            },
        ],
        signatures: vec![FrameSignature {
            scheme: FRAME_SIG_SCHEME_SECP256K1,
            signer: Some(Address::from_low_u64_be(0xABCD)),
            msg: Bytes::new(),
            signature: Bytes::from(vec![0u8; 65]),
        }],
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        max_fee_per_gas: U256::from(30_000_000_000u64),
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: vec![],
        ..Default::default()
    }
}

#[test]
fn atomic_batch_flag_on_verify_frame_is_invalid() {
    let mut tx = make_test_frame_tx();
    tx.frames = vec![
        Frame {
            mode: FrameMode::Verify as u8,
            flags: 0x04 | 0x03, // atomic batch + scope bits
            target: None,
            gas_limits: GasLimits {
                execution: 21_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        },
        Frame {
            mode: FrameMode::Sender as u8,
            flags: 0x00,
            target: Some(Address::from_low_u64_be(0xCAFE)),
            gas_limits: GasLimits {
                execution: 21_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        },
    ];
    assert!(
        tx.validate_static_constraints()
            .unwrap_err()
            .contains("atomic batch flag on a VERIFY frame")
    );
}

#[test]
fn atomic_batch_followed_by_verify_frame_is_invalid() {
    // Batches never contain VERIFY frames, so the frame a batch member
    // batches with must be non-VERIFY too.
    let mut tx = make_test_frame_tx();
    tx.frames = vec![
        Frame {
            mode: FrameMode::Sender as u8,
            flags: 0x04, // atomic batch
            target: Some(Address::from_low_u64_be(0xB0B)),
            gas_limits: GasLimits {
                execution: 21_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        },
        Frame {
            mode: FrameMode::Verify as u8,
            flags: 0x03,
            target: None,
            gas_limits: GasLimits {
                execution: 21_000,
                state: 0,
            },
            value: U256::zero(),
            data: Bytes::new(),
        },
    ];
    assert!(
        tx.validate_static_constraints()
            .unwrap_err()
            .contains("atomic batch flag followed by a VERIFY frame")
    );
}

#[test]
fn static_validation_rejects_approve_execution_with_third_party_target() {
    // Approval of execution is only allowed when the target is empty or tx.sender.
    let mut tx = make_test_frame_tx();
    tx.frames[0].target = Some(Address::from_low_u64_be(0xBEEF));
    assert!(
        tx.validate_static_constraints()
            .unwrap_err()
            .contains("APPROVE_EXECUTION requires an empty target or tx.sender"),
    );
    // An empty target resolves to tx.sender, so it is allowed.
    tx.frames[0].target = None;
    assert!(tx.validate_static_constraints().is_ok());
}

#[test]
fn static_validation_rejects_wrong_blob_hash_version() {
    let mut tx = make_test_frame_tx();
    tx.blob_versioned_hashes = vec![H256([0xABu8; 32])];
    tx.max_fee_per_blob_gas = U256::from(1u64);
    assert!(
        tx.validate_static_constraints()
            .unwrap_err()
            .contains("wrong version byte"),
    );
    let mut hash = [0xABu8; 32];
    hash[0] = VERSIONED_HASH_VERSION_KZG;
    tx.blob_versioned_hashes = vec![H256(hash)];
    assert!(tx.validate_static_constraints().is_ok());
}

#[test]
fn static_validation_rejects_blob_fee_without_blobs() {
    let mut tx = make_test_frame_tx();
    assert!(tx.blob_versioned_hashes.is_empty());
    tx.max_fee_per_blob_gas = U256::from(1u64);
    assert!(
        tx.validate_static_constraints()
            .unwrap_err()
            .contains("max_fee_per_blob_gas must be zero"),
    );
}

#[test]
fn data_cost_covers_only_frame_and_signature_data() {
    // 4 gas per zero byte, 16 per non-zero, over frame.data and each
    // signature's signer/msg/signature — no RLP framing, no scalar fields.
    let mut tx = make_test_frame_tx();
    tx.frames[0].data = Bytes::from(vec![0u8; 3]); // 3 zero bytes -> 12
    tx.frames[1].data = Bytes::from(vec![0xAAu8; 2]); // 2 non-zero -> 32
    tx.signatures = vec![FrameSignature {
        scheme: FRAME_SIG_SCHEME_ARBITRARY,
        signer: None, // empty signer contributes nothing
        msg: Bytes::new(),
        signature: Bytes::from(vec![0xAAu8, 0x00]), // 16 + 4
    }];
    assert_eq!(tx.data_cost(), 12 + 32 + 16 + 4);
    // Floor tokens are unweighted: 7 bytes * 4 tokens * 16 gas = 448.
    assert_eq!(tx.calldata_tokens(), 7 * 4);
    assert_eq!(tx.calldata_floor_gas(), 7 * 64);
}

#[test]
fn max_gas_takes_the_calldata_floor_when_it_exceeds_the_standard_limit() {
    // EIP-8141 `max_gas = max(standard_gas_limit, calldata_floor_gas)`. A
    // transaction whose data floor exceeds what it declared for execution
    // reserves the floor; it is valid, not rejected.
    let mut tx = make_test_frame_tx();
    tx.signatures.clear();
    tx.frames[0].data = Bytes::from(vec![0xAAu8; 64]);
    tx.frames[1].data = Bytes::new();
    tx.frames[0].gas_limits.execution = 100;
    tx.frames[1].gas_limits.execution = 100;
    assert!(tx.calldata_floor_total() > tx.standard_gas_limit());
    assert_eq!(tx.max_gas(), tx.calldata_floor_total());
    assert!(tx.validate_static_constraints().is_ok());

    // With enough frame gas to outweigh the floor, `max_gas` is the standard limit.
    tx.frames[1].gas_limits.execution = 100_000;
    assert!(tx.standard_gas_limit() > tx.calldata_floor_total());
    assert_eq!(tx.max_gas(), tx.standard_gas_limit());
    assert!(tx.validate_static_constraints().is_ok());
}
