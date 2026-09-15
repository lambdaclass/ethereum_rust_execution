//! Test that Block → SSZ StatelessInput → Block round-trip preserves the block hash.
//!
//! This catches encoding mismatches between `build_ssz_stateless_input` (advancer)
//! and `new_payload_request_to_block` (verify_stateless_new_payload).

#![allow(clippy::unwrap_used)]

use bytes::Bytes;
use ethrex_common::types::block_execution_witness::ExecutionWitness;
use ethrex_common::types::stateless_ssz::{
    STATELESS_INPUT_SCHEMA_ID, STATELESS_INPUT_SCHEMA_ID_SIZE, SszStatelessInput,
};
use ethrex_common::types::{BlockBody, BlockHeader};
use ethrex_common::{Address, H256};
use ethrex_common::{U256, types::EIP1559Transaction, types::Transaction, types::TxType};
use ethrex_crypto::NativeCrypto;
use ethrex_guest_program::l1::{new_payload_request_to_block, validate_public_keys};
use ethrex_l2::sequencer::native_rollup::l1_advancer::build_ssz_stateless_input;
use libssz::SszDecode;

/// Build a minimal L2-style block (Shanghai chain, empty txs).
fn make_test_block() -> (BlockHeader, BlockBody) {
    let header = BlockHeader {
        parent_hash: H256::zero(),
        ommers_hash: *ethrex_common::constants::DEFAULT_OMMERS_HASH,
        coinbase: Address::zero(),
        state_root: H256::from_low_u64_be(0xabcd),
        transactions_root: ethrex_common::types::compute_transactions_root(&[], &NativeCrypto),
        receipts_root: H256::from_low_u64_be(0x1234),
        number: 1,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1000,
        base_fee_per_gas: Some(7),
        prev_randao: H256::zero(),
        extra_data: Bytes::new(),
        // Shanghai fields
        withdrawals_root: Some(ethrex_common::types::compute_withdrawals_root(
            &[],
            &NativeCrypto,
        )),
        // Cancun fields (present in L2 blocks even on Shanghai chain)
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(H256::from_low_u64_be(0xbeef)),
        // Prague fields
        requests_hash: Some(ethrex_common::types::requests::compute_requests_hash(&[])),
        // EIP-7843: native-rollup (Amsterdam+) blocks carry a slot number; it must
        // survive the SSZ round-trip (reconstruction sets it from the payload).
        slot_number: Some(42),
        ..Default::default()
    };

    let body = BlockBody {
        transactions: vec![],
        ommers: vec![],
        withdrawals: Some(vec![]),
    };

    (header, body)
}

#[test]
fn block_to_ssz_to_block_preserves_hash() {
    let (header, body) = make_test_block();
    let original_hash = header.compute_block_hash(&NativeCrypto);

    // Create a minimal witness (empty — we only care about header round-trip).
    // chain_config_to_ssz requires Cancun+ (Paris has no stateless spec fork index);
    // the block carries Prague fields so activate both at genesis time.
    let witness = ExecutionWitness {
        codes: vec![],
        block_headers_bytes: vec![],
        first_block_number: 0,
        chain_config: ethrex_common::types::ChainConfig {
            chain_id: 1,
            cancun_time: Some(0),
            prague_time: Some(0),
            ..Default::default()
        },
        state_nodes: vec![],
    };

    // Block → SSZ
    let ssz_bytes =
        build_ssz_stateless_input(&header, &body, &witness, None).expect("SSZ encoding failed");

    // SSZ → deserialize. `build_ssz_stateless_input` emits schema-prefixed
    // `statelessInputBytes` since execution-specs #3278, so strip and check the
    // 2-byte schema id before decoding the body — the same order the EXECUTE
    // precompile uses.
    let (schema_bytes, body_bytes) = ssz_bytes
        .split_first_chunk::<STATELESS_INPUT_SCHEMA_ID_SIZE>()
        .expect("input carries a schema-id prefix");
    assert_eq!(
        u16::from_be_bytes(*schema_bytes),
        STATELESS_INPUT_SCHEMA_ID,
        "producer must emit the Amsterdam schema id"
    );
    let input = SszStatelessInput::from_ssz_bytes(body_bytes).expect("SSZ decoding failed");

    // SSZ → Block
    let reconstructed_block =
        new_payload_request_to_block(&input.new_payload_request, &NativeCrypto)
            .expect("block reconstruction failed");

    let reconstructed_hash = reconstructed_block.hash();

    // Compare all header fields for debugging
    assert_eq!(
        header.parent_hash, reconstructed_block.header.parent_hash,
        "parent_hash mismatch"
    );
    assert_eq!(
        header.coinbase, reconstructed_block.header.coinbase,
        "coinbase mismatch"
    );
    assert_eq!(
        header.state_root, reconstructed_block.header.state_root,
        "state_root mismatch"
    );
    assert_eq!(
        header.transactions_root, reconstructed_block.header.transactions_root,
        "transactions_root mismatch"
    );
    assert_eq!(
        header.receipts_root, reconstructed_block.header.receipts_root,
        "receipts_root mismatch"
    );
    assert_eq!(
        header.number, reconstructed_block.header.number,
        "number mismatch"
    );
    assert_eq!(
        header.gas_limit, reconstructed_block.header.gas_limit,
        "gas_limit mismatch"
    );
    assert_eq!(
        header.gas_used, reconstructed_block.header.gas_used,
        "gas_used mismatch"
    );
    assert_eq!(
        header.timestamp, reconstructed_block.header.timestamp,
        "timestamp mismatch"
    );
    assert_eq!(
        header.base_fee_per_gas, reconstructed_block.header.base_fee_per_gas,
        "base_fee_per_gas mismatch"
    );
    assert_eq!(
        header.prev_randao, reconstructed_block.header.prev_randao,
        "prev_randao mismatch"
    );
    assert_eq!(
        header.extra_data, reconstructed_block.header.extra_data,
        "extra_data mismatch"
    );
    assert_eq!(
        header.logs_bloom, reconstructed_block.header.logs_bloom,
        "logs_bloom mismatch"
    );
    assert_eq!(
        header.difficulty, reconstructed_block.header.difficulty,
        "difficulty mismatch"
    );
    assert_eq!(
        header.nonce, reconstructed_block.header.nonce,
        "nonce mismatch"
    );
    assert_eq!(
        header.ommers_hash, reconstructed_block.header.ommers_hash,
        "ommers_hash mismatch"
    );
    assert_eq!(
        header.withdrawals_root, reconstructed_block.header.withdrawals_root,
        "withdrawals_root mismatch"
    );
    assert_eq!(
        header.blob_gas_used, reconstructed_block.header.blob_gas_used,
        "blob_gas_used mismatch"
    );
    assert_eq!(
        header.excess_blob_gas, reconstructed_block.header.excess_blob_gas,
        "excess_blob_gas mismatch"
    );
    assert_eq!(
        header.parent_beacon_block_root, reconstructed_block.header.parent_beacon_block_root,
        "parent_beacon_block_root mismatch"
    );
    assert_eq!(
        header.requests_hash, reconstructed_block.header.requests_hash,
        "requests_hash mismatch"
    );
    assert_eq!(
        header.slot_number, reconstructed_block.header.slot_number,
        "slot_number mismatch"
    );

    // Final hash check
    assert_eq!(
        original_hash, reconstructed_hash,
        "Block hash mismatch after SSZ round-trip"
    );
}

/// A signed EIP-1559 transaction plus the address that signed it.
///
/// Signed with raw secp256k1 rather than through `ethrex-rpc`'s `Signer`, whose
/// `sign_inplace` is async — the payload construction here is the same one
/// `impl Signable for EIP1559Transaction` uses (`0x02 || rlp_payload`).
fn signed_eip1559_tx(secret_bytes: [u8; 32], nonce: u64) -> (Transaction, Address) {
    use ethrex_rlp::encode::PayloadRLPEncode as _;

    let secp = secp256k1::Secp256k1::new();
    let secret = secp256k1::SecretKey::from_byte_array(&secret_bytes).unwrap();

    let mut tx = EIP1559Transaction {
        chain_id: 1,
        nonce,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 10,
        gas_limit: 21_000,
        to: ethrex_common::types::TxKind::Call(Address::from_low_u64_be(0x1234)),
        value: U256::from(1),
        data: Bytes::new(),
        access_list: vec![],
        signature_y_parity: false,
        signature_r: U256::zero(),
        signature_s: U256::zero(),
        ..Default::default()
    };

    let mut payload = vec![TxType::EIP1559 as u8];
    payload.append(&mut tx.encode_payload_to_vec());
    let msg = ethrex_common::utils::keccak(&payload);

    let (recovery_id, sig) = secp
        .sign_ecdsa_recoverable(&secp256k1::Message::from_digest(msg.0), &secret)
        .serialize_compact();
    tx.signature_r = U256::from_big_endian(&sig[..32]);
    tx.signature_s = U256::from_big_endian(&sig[32..]);
    tx.signature_y_parity = i32::from(recovery_id) != 0;

    let public_key = secret.public_key(&secp);
    let hashed = ethrex_common::utils::keccak(&public_key.serialize_uncompressed()[1..]);
    let address = Address::from_slice(&hashed[12..]);

    (Transaction::EIP1559Transaction(tx), address)
}

/// The producer must emit one public key per transaction, in transaction order,
/// and each must be the uncompressed key of that transaction's signer.
///
/// This is the producer half of the check the consumer performs in
/// `validate_public_keys` (#6716): before this, `build_ssz_stateless_input` sent
/// the list empty, so the consumer could not enforce the check at all. Two
/// transactions from *different* keys, so a swapped or repeated entry fails.
#[test]
fn producer_emits_one_matching_public_key_per_transaction() {
    let (tx_a, addr_a) = signed_eip1559_tx([0x11; 32], 0);
    let (tx_b, addr_b) = signed_eip1559_tx([0x22; 32], 0);
    assert_ne!(
        addr_a, addr_b,
        "the two transactions must have distinct signers"
    );

    let (mut header, mut body) = make_test_block();
    body.transactions = vec![tx_a, tx_b];
    header.transactions_root =
        ethrex_common::types::compute_transactions_root(&body.transactions, &NativeCrypto);

    let witness = ExecutionWitness {
        codes: vec![],
        block_headers_bytes: vec![],
        first_block_number: 0,
        chain_config: ethrex_common::types::ChainConfig {
            chain_id: 1,
            cancun_time: Some(0),
            prague_time: Some(0),
            ..Default::default()
        },
        state_nodes: vec![],
    };

    let ssz_bytes =
        build_ssz_stateless_input(&header, &body, &witness, None).expect("SSZ encoding failed");
    let input =
        ethrex_guest_program::l1::decode_stateless_input(&ssz_bytes).expect("SSZ decoding failed");

    assert_eq!(input.public_keys.len(), 2, "one public key per transaction");
    for (expected, key) in [addr_a, addr_b].iter().zip(input.public_keys.iter()) {
        let bytes: &[u8] = key;
        assert_eq!(bytes.len(), 65, "keys are uncompressed secp256k1");
        assert_eq!(bytes[0], 0x04, "uncompressed keys are tagged 0x04");
        let hashed = ethrex_common::utils::keccak(&bytes[1..]);
        assert_eq!(
            Address::from_slice(&hashed[12..]),
            *expected,
            "key must derive to the transaction's signer"
        );
    }

    // The consumer's check must accept what the producer emits. Reconstructing the
    // block from the payload (rather than reusing `body`) is what the consumer
    // actually does, so this exercises the real pair.
    let block = new_payload_request_to_block(&input.new_payload_request, &NativeCrypto)
        .expect("block reconstruction failed");
    validate_public_keys(&input.public_keys, &block, &NativeCrypto)
        .expect("producer output must satisfy the consumer's public-key check");

    // And it must reject a tampered list, so the acceptance above is meaningful.
    let mut swapped: Vec<_> = input.public_keys.iter().cloned().collect();
    swapped.swap(0, 1);
    let swapped = libssz_types::ProgressiveList::from(swapped);
    validate_public_keys(&swapped, &block, &NativeCrypto)
        .expect_err("swapped public keys must be rejected");
}
