use aes_gcm::{Aes128Gcm, KeyInit, aead::AeadMutInPlace};
use bytes::Bytes;
use ethrex_common::{H256, H264, H512};
use ethrex_p2p::discv5::{
    messages::{
        FindNodeMessage, Handshake, Message, NodesMessage, Ordinary, Packet, PacketTrait as _,
        PingMessage, PongMessage, TalkReqMessage, TalkResMessage, TicketMessage, WhoAreYou,
    },
    session::{build_challenge_data, create_id_signature, derive_session_keys},
};
use ethrex_p2p::rlpx::utils::compress_pubkey;
use ethrex_p2p::types::{NodeRecord, NodeRecordPairs};
use ethrex_p2p::utils::{node_id, public_key_from_signing_key};
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};
use hex_literal::hex;
use secp256k1::SecretKey;
use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

/// Ping message packet (flag 0) from https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
#[test]
fn decode_ping_packet() {
    let node_a_key = SecretKey::from_byte_array(&hex!(
        "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    ))
    .unwrap();
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();

    let src_id = node_id(&public_key_from_signing_key(&node_a_key));
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc"
    );
    let packet = Packet::decode(&dest_id, encoded).unwrap();
    assert_eq!([0; 16], packet.masking_iv);
    assert_eq!(0x00, packet.header.flag);
    assert_eq!(hex!("ffffffffffffffffffffffff"), packet.header.nonce);

    let read_key = [0; 16];

    let decoded_message = Ordinary::decode(&packet, &read_key).unwrap();

    let expected_message = Ordinary {
        src_id,
        message: Message::Ping(PingMessage {
            req_id: Bytes::from(hex!("00000001").as_slice()),
            enr_seq: 2,
        }),
    };

    assert_eq!(decoded_message, expected_message);
}

#[test]
fn encode_ping_packet() {
    let node_a_key = SecretKey::from_byte_array(&hex!(
        "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    ))
    .unwrap();
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();

    let src_id = node_id(&public_key_from_signing_key(&node_a_key));
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let message = Ordinary {
        src_id,
        message: Message::Ping(PingMessage {
            req_id: Bytes::from(hex!("00000001").as_slice()),
            enr_seq: 2,
        }),
    };

    let masking_iv = [0; 16];
    let nonce = hex!("ffffffffffffffffffffffff");
    let encrypt_key = [0; 16];

    let packet = message.encode(&nonce, masking_iv, &encrypt_key).unwrap();

    let expected_encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc"
    );

    let mut buf = Vec::new();
    packet.encode(&mut buf, &dest_id).unwrap();

    assert_eq!(buf.to_vec(), expected_encoded);
}

#[test]
fn decode_whoareyou_packet() {
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();

    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let encoded = &hex!(
        "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d"
    );

    let packet = Packet::decode(&dest_id, encoded).unwrap();
    assert_eq!([0; 16], packet.masking_iv);
    assert_eq!(0x01, packet.header.flag);
    assert_eq!(hex!("0102030405060708090a0b0c"), packet.header.nonce);

    let challenge_data = build_challenge_data(
        &packet.masking_iv,
        &packet.header.static_header,
        &packet.header.authdata,
    );

    let expected_challenge_data = &hex!(
        "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
    );
    assert_eq!(challenge_data, expected_challenge_data);
    let decoded_message = WhoAreYou::decode(&packet).unwrap();

    let expected_message = WhoAreYou {
        id_nonce: u128::from_be_bytes(
            hex!("0102030405060708090a0b0c0d0e0f10")
                .to_vec()
                .try_into()
                .unwrap(),
        ),
        enr_seq: 0,
    };

    assert_eq!(decoded_message, expected_message);
}

#[test]
fn encode_whoareyou_packet() {
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();

    let who_are_you = WhoAreYou {
        id_nonce: u128::from_be_bytes(
            hex!("0102030405060708090a0b0c0d0e0f10")
                .to_vec()
                .try_into()
                .unwrap(),
        ),
        enr_seq: 0,
    };

    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let masking_iv = [0; 16];
    let nonce = hex!("0102030405060708090a0b0c");

    let packet = who_are_you.encode(&nonce, masking_iv, &[]).unwrap();

    let expected_encoded = &hex!(
        "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d"
    );

    let mut buf = Vec::new();
    packet.encode(&mut buf, &dest_id).unwrap();

    assert_eq!(buf.to_vec(), expected_encoded);
}

#[test]
fn encode_ping_handshake_packet() {
    let node_a_key = SecretKey::from_byte_array(&hex!(
        "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    ))
    .unwrap();
    let src_id = node_id(&public_key_from_signing_key(&node_a_key));
    let expected_src_id = H256::from_slice(&hex!(
        "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
    ));
    assert_eq!(src_id, expected_src_id);

    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();
    let dest_pub_key = public_key_from_signing_key(&node_b_key);
    let dest_pubkey = compress_pubkey(dest_pub_key).unwrap();
    let dest_id = node_id(&dest_pub_key);

    let message = Message::Ping(PingMessage {
        req_id: Bytes::from(hex!("00000001").as_slice()),
        enr_seq: 1,
    });

    let challenge_data = hex!("000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001").to_vec();

    let ephemeral_key = SecretKey::from_byte_array(&hex!(
        "0288ef00023598499cb6c940146d050d2b1fb914198c327f76aad590bead68b6"
    ))
    .unwrap();
    let expected_ephemeral_pubkey =
        hex!("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5");

    let ephemeral_pubkey = ephemeral_key.public_key(secp256k1::SECP256K1).serialize();

    assert_eq!(ephemeral_pubkey, expected_ephemeral_pubkey);

    let session = derive_session_keys(
        &ephemeral_key,
        &dest_pubkey,
        &src_id,
        &dest_id,
        &challenge_data,
        true,
    );

    let expected_read_key = hex!("4f9fac6de7567d1e3b1241dffe90f662");
    assert_eq!(session.outbound_key, expected_read_key);

    let signature = create_id_signature(&node_a_key, &challenge_data, &ephemeral_pubkey, &dest_id);

    let handshake = Handshake {
        src_id,
        id_signature: signature.serialize_compact().to_vec(),
        eph_pubkey: ephemeral_pubkey.to_vec(),
        record: None,
        message,
    };

    let masking_iv = [0; 16];
    let nonce = hex!("ffffffffffffffffffffffff");

    let packet = handshake
        .encode(&nonce, masking_iv, &session.outbound_key)
        .unwrap();

    let expected_encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8"
    );

    let mut buf = Vec::new();
    packet.encode(&mut buf, &dest_id).unwrap();

    assert_eq!(buf.to_vec(), expected_encoded);
}

#[test]
fn decode_ping_handshake_packet_with_enr() {
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let encoded_packet = &hex!(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be98562fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b21481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb12a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b139471"
    );
    let read_key = hex!("53b1c075f41876423154e157470c2f48");

    let packet = Packet::decode(&dest_id, encoded_packet).unwrap();
    assert_eq!([0; 16], packet.masking_iv);
    assert_eq!(0x02, packet.header.flag);
    assert_eq!(hex!("ffffffffffffffffffffffff"), packet.header.nonce);

    let handshake = Handshake::decode(&packet, &read_key).unwrap();

    assert_eq!(
        handshake.src_id,
        H256::from_slice(&hex!(
            "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
        ))
    );
    assert_eq!(
        handshake.eph_pubkey,
        hex!("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5").to_vec()
    );
    assert_eq!(
        handshake.message,
        Message::Ping(PingMessage {
            req_id: Bytes::from(hex!("00000001").as_slice()),
            enr_seq: 1,
        })
    );

    let record = handshake.record.expect("expected ENR record");
    let pairs = record.pairs();
    assert_eq!(pairs.id.as_deref(), Some("v4"));
    assert!(pairs.secp256k1.is_some());
}

#[test]
fn encode_ping_handshake_packet_with_enr() {
    let node_a_key = SecretKey::from_byte_array(&hex!(
        "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    ))
    .unwrap();
    let src_id = node_id(&public_key_from_signing_key(&node_a_key));
    let expected_src_id = H256::from_slice(&hex!(
        "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
    ));
    assert_eq!(src_id, expected_src_id);

    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();
    let dest_pub_key = public_key_from_signing_key(&node_b_key);
    let dest_pubkey = compress_pubkey(dest_pub_key).unwrap();
    let dest_id: H256 = node_id(&dest_pub_key);

    let message = Message::Ping(PingMessage {
        req_id: Bytes::from(hex!("00000001").as_slice()),
        enr_seq: 1,
    });

    let challenge_data = hex!("000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000").to_vec();

    let ephemeral_key = SecretKey::from_byte_array(&hex!(
        "0288ef00023598499cb6c940146d050d2b1fb914198c327f76aad590bead68b6"
    ))
    .unwrap();
    let expected_ephemeral_pubkey =
        hex!("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5");

    let ephemeral_pubkey = ephemeral_key.public_key(secp256k1::SECP256K1).serialize();

    assert_eq!(ephemeral_pubkey, expected_ephemeral_pubkey);

    let session = derive_session_keys(
        &ephemeral_key,
        &dest_pubkey,
        &src_id,
        &dest_id,
        &challenge_data,
        true,
    );

    let expected_read_key = hex!("53b1c075f41876423154e157470c2f48");
    assert_eq!(session.outbound_key, expected_read_key);

    let signature = create_id_signature(&node_a_key, &challenge_data, &ephemeral_pubkey, &dest_id);

    let sig = "17e1b073918da32d640642c762c0e2781698e4971f8ab39a77746adad83f01e76ffc874c5924808bbe7c50890882c2b8a01287a0b08312d1d53a17d517f5eb27";
    let key = "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9";

    let record = NodeRecord::new(
        H512::from_str(sig).unwrap(),
        1,
        NodeRecordPairs {
            id: Some("v4".to_owned()),
            ip: Some(Ipv4Addr::new(127, 0, 0, 1)),
            ip6: None,
            tcp_port: None,
            udp_port: None,
            secp256k1: Some(H264::from_str(key).unwrap()),
            ..Default::default()
        },
    );

    let handshake = Handshake {
        src_id,
        id_signature: signature.serialize_compact().to_vec(),
        eph_pubkey: ephemeral_pubkey.to_vec(),
        record: Some(record),
        message,
    };

    let masking_iv = [0; 16];
    let nonce = hex!("ffffffffffffffffffffffff");

    let packet = handshake
        .encode(&nonce, masking_iv, &session.outbound_key)
        .unwrap();

    let expected_encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be98562fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b21481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb12a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b139471"
    );

    let mut buf = Vec::new();
    packet.encode(&mut buf, &dest_id).unwrap();

    assert_eq!(buf.to_vec(), expected_encoded);
}

#[test]
fn aes_gcm_vector() {
    let key = hex!("9f2d77db7004bf8a1a85107ac686990b");
    let nonce = hex!("27b5af763c446acd2749fe8e");
    let ad = hex!("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903");
    let mut pt = hex!("01c20101").to_vec();

    let mut cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    cipher
        .encrypt_in_place(nonce.as_slice().into(), &ad, &mut pt)
        .unwrap();

    assert_eq!(
        pt,
        hex!("a5d12a2d94b8ccb3ba55558229867dc13bfa3648").to_vec()
    );
}

#[test]
fn handshake_packet_roundtrip() {
    let node_a_key = SecretKey::from_byte_array(&hex!(
        "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    ))
    .unwrap();
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();

    let src_id = node_id(&public_key_from_signing_key(&node_a_key));
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let handshake = Handshake {
        src_id,
        id_signature: vec![1; 64],
        eph_pubkey: vec![2; 33],
        record: None,
        message: Message::Ping(PingMessage {
            req_id: Bytes::from_static(&[3]),
            enr_seq: 4,
        }),
    };

    let key = [0x10; 16];
    let nonce = hex!("000102030405060708090a0b");
    let mut buf = Vec::new();

    let masking_iv = [0; 16];
    let packet = handshake.encode(&nonce, masking_iv, &key).unwrap();
    packet.encode(&mut buf, &dest_id).unwrap();

    let decoded = Packet::decode(&dest_id, &buf).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn handshake_packet_vector_roundtrip() {
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8"
    );
    let read_key = hex!("4f9fac6de7567d1e3b1241dffe90f662");

    let packet = Packet::decode(&dest_id, encoded).unwrap();
    let handshake = Handshake::decode(&packet, &read_key).unwrap();

    assert_eq!(
        handshake.src_id,
        H256::from_slice(&hex!(
            "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
        ))
    );
    assert_eq!(handshake.record, None);
    assert_eq!(
        handshake.eph_pubkey,
        hex!("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5").to_vec()
    );
    assert_eq!(
        handshake.message,
        Message::Ping(PingMessage {
            req_id: Bytes::from(hex!("00000001").as_slice()),
            enr_seq: 1,
        })
    );

    let masking_iv = encoded[..16].try_into().unwrap();
    let nonce = hex!("ffffffffffffffffffffffff");
    let mut buf = Vec::new();
    let packet = handshake.encode(&nonce, masking_iv, &read_key).unwrap();
    packet.encode(&mut buf, &dest_id).unwrap();

    assert_eq!(buf, encoded.to_vec());
}

#[test]
fn handshake_packet_with_enr_vector_roundtrip() {
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be98562fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b21481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb12a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b139471"
    );
    let nonce = hex!("ffffffffffffffffffffffff");
    let read_key = hex!("53b1c075f41876423154e157470c2f48");

    let packet = Packet::decode(&dest_id, encoded).unwrap();
    let handshake = Handshake::decode(&packet, &read_key).unwrap();

    assert_eq!(
        handshake.src_id,
        H256::from_slice(&hex!(
            "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
        ))
    );
    assert_eq!(
        handshake.eph_pubkey,
        hex!("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5").to_vec()
    );
    assert_eq!(
        handshake.message,
        Message::Ping(PingMessage {
            req_id: Bytes::from(hex!("00000001").as_slice()),
            enr_seq: 1,
        })
    );

    let record = handshake.record.clone().expect("expected ENR record");
    let pairs = record.pairs();
    assert_eq!(pairs.id.as_deref(), Some("v4"));
    assert!(pairs.secp256k1.is_some());

    let masking_iv = encoded[..16].try_into().unwrap();
    let mut buf = Vec::new();

    let packet = handshake.encode(&nonce, masking_iv, &read_key).unwrap();
    packet.encode(&mut buf, &dest_id).unwrap();

    assert_eq!(buf, encoded.to_vec());
}

#[test]
fn ordinary_ping_packet_vector_roundtrip() {
    let node_b_key = SecretKey::from_byte_array(&hex!(
        "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
    ))
    .unwrap();
    let dest_id = node_id(&public_key_from_signing_key(&node_b_key));

    let encoded = &hex!(
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc"
    );
    let nonce = hex!("ffffffffffffffffffffffff");
    let read_key = [0; 16];

    let packet = Packet::decode(&dest_id, encoded).unwrap();
    let message = Ordinary {
        src_id: H256::from_slice(&hex!(
            "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
        )),
        message: Message::Ping(PingMessage {
            req_id: Bytes::from(hex!("00000001").as_slice()),
            enr_seq: 2,
        }),
    };
    let masking_iv = [0; 16];
    let expected = message.encode(&nonce, masking_iv, &read_key).unwrap();

    assert_eq!(packet, expected);

    let mut buf = Vec::new();
    packet.encode(&mut buf, &dest_id).unwrap();
    assert_eq!(buf, encoded.to_vec());
}

#[test]
fn ping_packet_codec_roundtrip() {
    let pkt = PingMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        enr_seq: 4321,
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(PingMessage::decode(&buf).unwrap(), pkt);
}

#[test]
fn pong_packet_codec_roundtrip() {
    let pkt = PongMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        enr_seq: 4321,
        recipient_addr: SocketAddr::new(Ipv4Addr::BROADCAST.into(), 30303),
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(PongMessage::decode(&buf).unwrap(), pkt);
}

#[test]
fn findnode_packet_codec_roundtrip() {
    let pkt = FindNodeMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        distances: vec![0],
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(FindNodeMessage::decode(&buf).unwrap(), pkt);
}

#[test]
fn nodes_packet_codec_roundtrip() {
    let pairs = NodeRecordPairs {
        id: Some("id".to_string()),
        ..Default::default()
    };

    let pkt = NodesMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        total: 2,
        nodes: vec![NodeRecord::new(H512::random(), 4321, pairs)],
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(NodesMessage::decode(&buf).unwrap(), pkt);
}

#[test]
fn talkreq_packet_codec_roundtrip() {
    let pkt = TalkReqMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        protocol: Bytes::from_static(&[1, 2, 3, 4]),
        request: Bytes::from_static(&[1, 2, 3, 4]),
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(TalkReqMessage::decode(&buf).unwrap(), pkt);
}

#[test]
fn talk_res_packet_codec_roundtrip() {
    let pkt = TalkResMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        response: b"\x00\x01\x02\x03".into(),
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(TalkResMessage::decode(&buf).unwrap(), pkt);
}

#[test]
fn ticket_packet_codec_roundtrip() {
    let pkt = TicketMessage {
        req_id: Bytes::from_static(&[1, 2, 3, 4]),
        ticket: Bytes::from_static(&[1, 2, 3, 4]),
        wait_time: 5,
    };

    let buf = pkt.encode_to_vec();
    assert_eq!(TicketMessage::decode(&buf).unwrap(), pkt);
}
