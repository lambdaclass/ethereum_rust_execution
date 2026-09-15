use std::net::IpAddr;

use ethereum_types::{Address, U256};
use ethrex_rlp::constants::{RLP_EMPTY_LIST, RLP_NULL};
use ethrex_rlp::encode::{RLPEncode, backpatch_list_prefix, encode_list_prefix};
use hex_literal::hex;

#[test]
fn can_encode_booleans() {
    let mut encoded = Vec::new();
    true.encode(&mut encoded);
    assert_eq!(encoded, vec![0x01]);

    let mut encoded = Vec::new();
    false.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL]);
}

#[test]
fn can_encode_u32() {
    let mut encoded = Vec::new();
    0u32.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL]);
    assert_eq!(encoded.len(), 0u32.length());

    let mut encoded = Vec::new();
    1u32.encode(&mut encoded);
    assert_eq!(encoded, vec![0x01]);
    assert_eq!(encoded.len(), 1u32.length());

    let mut encoded = Vec::new();
    0x7Fu32.encode(&mut encoded);
    assert_eq!(encoded, vec![0x7f]);
    assert_eq!(encoded.len(), 0x7Fu32.length());

    let mut encoded = Vec::new();
    0x80u32.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x80]);
    assert_eq!(encoded.len(), 0x80u32.length());

    let mut encoded = Vec::new();
    0x90u32.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x90]);
    assert_eq!(encoded.len(), 0x90u32.length());
}

#[test]
fn can_encode_u16() {
    let mut encoded = Vec::new();
    0u16.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL]);
    assert_eq!(encoded.len(), 0u16.length());

    let mut encoded = Vec::new();
    1u16.encode(&mut encoded);
    assert_eq!(encoded, vec![0x01]);
    assert_eq!(encoded.len(), 1u16.length());

    let mut encoded = Vec::new();
    0x7Fu16.encode(&mut encoded);
    assert_eq!(encoded, vec![0x7f]);
    assert_eq!(encoded.len(), 0x7Fu16.length());

    let mut encoded = Vec::new();
    0x80u16.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x80]);
    assert_eq!(encoded.len(), 0x80u16.length());

    let mut encoded = Vec::new();
    0x90u16.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x90]);
    assert_eq!(encoded.len(), 0x90u16.length());
}

#[test]
fn u16_length_matches() {
    let mut encoded = Vec::new();
    0x0100u16.encode(&mut encoded);
    assert_eq!(encoded.len(), 0x0100u16.length(),);
}

#[test]
fn u256_length_matches() {
    let value = U256::from(0x0100u64);
    let mut encoded = Vec::new();
    value.encode(&mut encoded);
    assert_eq!(encoded.len(), value.length(),);
}

#[test]
fn u64_lengths_match() {
    for n in 0u64..=10_000 {
        let mut encoded = Vec::new();
        n.encode(&mut encoded);
        assert_eq!(
            encoded.len(),
            n.length(),
            "u64 length mismatch at value {n}"
        );
    }
}

#[test]
fn can_encode_u8() {
    let mut encoded = Vec::new();
    0u8.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL]);
    assert_eq!(encoded.len(), 0u8.length());

    let mut encoded = Vec::new();
    1u8.encode(&mut encoded);
    assert_eq!(encoded, vec![0x01]);
    assert_eq!(encoded.len(), 1u8.length());

    let mut encoded = Vec::new();
    0x7Fu8.encode(&mut encoded);
    assert_eq!(encoded, vec![0x7f]);
    assert_eq!(encoded.len(), 0x7Fu8.length());

    let mut encoded = Vec::new();
    0x80u8.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x80]);
    assert_eq!(encoded.len(), 0x80u8.length());

    let mut encoded = Vec::new();
    0x90u8.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x90]);
    assert_eq!(encoded.len(), 0x90u8.length());
}

#[test]
fn can_encode_u64() {
    let mut encoded = Vec::new();
    0u64.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL]);
    assert_eq!(encoded.len(), 0u64.length());

    let mut encoded = Vec::new();
    1u64.encode(&mut encoded);
    assert_eq!(encoded, vec![0x01]);
    assert_eq!(encoded.len(), 1u64.length());

    let mut encoded = Vec::new();
    0x7Fu64.encode(&mut encoded);
    assert_eq!(encoded, vec![0x7f]);
    assert_eq!(encoded.len(), 0x7Fu64.length());

    let mut encoded = Vec::new();
    0x80u64.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x80]);
    assert_eq!(encoded.len(), 0x80u64.length());

    let mut encoded = Vec::new();
    0x90u64.encode(&mut encoded);
    assert_eq!(encoded, vec![RLP_NULL + 1, 0x90]);
    assert_eq!(encoded.len(), 0x90u64.length());
}

#[test]
fn can_encode_usize() {
    let mut encoded = Vec::new();
    0usize.encode(&mut encoded);
    assert_eq!(encoded, vec![0x80]);
    assert_eq!(encoded.len(), 0usize.length());

    let mut encoded = Vec::new();
    1usize.encode(&mut encoded);
    assert_eq!(encoded, vec![0x01]);
    assert_eq!(encoded.len(), 1usize.length());

    let mut encoded = Vec::new();
    0x7Fusize.encode(&mut encoded);
    assert_eq!(encoded, vec![0x7f]);
    assert_eq!(encoded.len(), 0x7Fusize.length());

    let mut encoded = Vec::new();
    0x80usize.encode(&mut encoded);
    assert_eq!(encoded, vec![0x80 + 1, 0x80]);
    assert_eq!(encoded.len(), 0x80usize.length());

    let mut encoded = Vec::new();
    0x90usize.encode(&mut encoded);
    assert_eq!(encoded, vec![0x80 + 1, 0x90]);
    assert_eq!(encoded.len(), 0x90usize.length());
}

#[test]
fn can_encode_bytes() {
    // encode byte 0x00
    let message: [u8; 1] = [0x00];
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    assert_eq!(encoded, vec![0x00]);
    assert_eq!(encoded.len(), message.length());

    // encode byte 0x0f
    let message: [u8; 1] = [0x0f];
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    assert_eq!(encoded, vec![0x0f]);
    assert_eq!(encoded.len(), message.length());

    // encode bytes '\x04\x00'
    let message: [u8; 2] = [0x04, 0x00];
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    assert_eq!(encoded, vec![RLP_NULL + 2, 0x04, 0x00]);
    assert_eq!(encoded.len(), message.length());
}

#[test]
fn can_encode_strings() {
    // encode dog
    let message = "dog";
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    let expected: [u8; 4] = [RLP_NULL + 3, b'd', b'o', b'g'];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), message.length());

    // encode empty string
    let message = "";
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    let expected: [u8; 1] = [RLP_NULL];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), message.length());
}

#[test]
fn can_encode_lists_of_str() {
    // encode ["cat", "dog"]
    let message = vec!["cat", "dog"];
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    let expected: [u8; 9] = [0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), message.length());

    // encode empty list
    let message: Vec<&str> = vec![];
    let encoded = {
        let mut buf = vec![];
        message.encode(&mut buf);
        buf
    };
    let expected: [u8; 1] = [RLP_EMPTY_LIST];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), message.length());
}

#[test]
fn can_encode_ip() {
    // encode an IPv4 address
    let message = "192.168.0.1";
    let ip: IpAddr = message.parse().unwrap();
    let encoded = {
        let mut buf = vec![];
        ip.encode(&mut buf);
        buf
    };
    let expected: [u8; 5] = [RLP_NULL + 4, 192, 168, 0, 1];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), ip.length());

    // encode an IPv6 address
    let message = "2001:0000:130F:0000:0000:09C0:876A:130B";
    let ip: IpAddr = message.parse().unwrap();
    let encoded = {
        let mut buf = vec![];
        ip.encode(&mut buf);
        buf
    };
    let expected: [u8; 17] = [
        0x90, 0x20, 0x01, 0x00, 0x00, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a,
        0x13, 0x0b,
    ];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), ip.length());
}

#[test]
fn can_encode_addresses() {
    let address = Address::from(hex!("ef2d6d194084c2de36e0dabfce45d046b37d1106"));
    let encoded = {
        let mut buf = vec![];
        address.encode(&mut buf);
        buf
    };
    let expected = hex!("94ef2d6d194084c2de36e0dabfce45d046b37d1106");
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), address.length());
}

#[test]
fn can_encode_u256() {
    let mut encoded = Vec::new();
    U256::from(1).encode(&mut encoded);
    assert_eq!(encoded, vec![1]);
    assert_eq!(encoded.len(), U256::from(1).length());

    let mut encoded = Vec::new();
    U256::from(128).encode(&mut encoded);
    assert_eq!(encoded, vec![0x80 + 1, 128]);
    assert_eq!(encoded.len(), U256::from(128).length());

    let mut encoded = Vec::new();
    U256::max_value().encode(&mut encoded);
    let bytes = [0xff; 32];
    let mut expected: Vec<u8> = bytes.into();
    expected.insert(0, 0x80 + 32);
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), U256::max_value().length());
}

#[test]
fn can_encode_tuple() {
    // TODO: check if works for tuples with total length greater than 55 bytes
    let tuple: (u8, u8) = (0x01, 0x02);
    let mut encoded = Vec::new();
    tuple.encode(&mut encoded);
    let expected = vec![0xc0 + 2, 0x01, 0x02];
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), tuple.length());
}

/// `Encoder::finish` and `Vec<T>::encode` write the list prefix *after* the
/// payload, so the prefix arithmetic has to hold at every size boundary and the
/// payload has to survive being shifted right to make room.
///
/// The expected prefixes are spelled out from the RLP spec rather than derived
/// from `encode_list_prefix`: both paths share one helper, so comparing them to each
/// other would not catch a bug in the helper.
#[test]
fn backpatched_prefix_matches_the_spec() {
    // 55/56 is the short/long form boundary; the rest are where the encoded
    // length itself gains a byte.
    let cases: &[(usize, &[u8])] = &[
        (0, &[0xc0]),
        (1, &[0xc1]),
        (55, &[0xf7]),
        (56, &[0xf8, 56]),
        (57, &[0xf8, 57]),
        (255, &[0xf8, 0xff]),
        (256, &[0xf9, 0x01, 0x00]),
        (257, &[0xf9, 0x01, 0x01]),
        (65535, &[0xf9, 0xff, 0xff]),
        (65536, &[0xfa, 0x01, 0x00, 0x00]),
        (70000, &[0xfa, 0x01, 0x11, 0x70]),
    ];

    for (payload_len, expected_prefix) in cases {
        let payload: Vec<u8> = (0..*payload_len).map(|i| (i % 251) as u8).collect();

        let mut backpatched = payload.clone();
        backpatch_list_prefix(&mut backpatched, 0);

        let mut expected = expected_prefix.to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(
            backpatched, expected,
            "backpatched prefix wrong for payload_len {payload_len}"
        );

        // The write-ahead path has to agree with it, since both encode the same
        // header.
        let mut written_ahead = Vec::new();
        encode_list_prefix(*payload_len, &mut written_ahead);
        assert_eq!(
            written_ahead, *expected_prefix,
            "encode_list_prefix disagrees for payload_len {payload_len}"
        );
    }
}

/// The prefix is inserted at `start`, not at the front of the buffer, so
/// whatever was already there must be left untouched.
#[test]
fn backpatched_prefix_preserves_preceding_bytes() {
    let preceding = vec![0xde, 0xad, 0xbe, 0xef];
    for payload_len in [0usize, 55, 56, 300] {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();

        let mut buf = preceding.clone();
        let start = buf.len();
        buf.extend_from_slice(&payload);
        backpatch_list_prefix(&mut buf, start);

        assert_eq!(&buf[..start], &preceding[..]);

        let mut expected_tail = Vec::new();
        encode_list_prefix(payload_len, &mut expected_tail);
        expected_tail.extend_from_slice(&payload);
        assert_eq!(&buf[start..], &expected_tail[..]);
    }
}

/// A list long enough to need the long-form prefix, which `can_encode_tuple`
/// explicitly left uncovered.
#[test]
fn can_encode_long_list() {
    let items: Vec<u64> = (0..100).collect();
    let mut encoded = Vec::new();
    items.encode(&mut encoded);

    let payload_len: usize = items.iter().map(|i| i.length()).sum();
    assert!(payload_len > 55, "expected the long form");

    let mut expected = Vec::new();
    encode_list_prefix(payload_len, &mut expected);
    for item in &items {
        item.encode(&mut expected);
    }
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), items.length());
}
