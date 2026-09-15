use ethrex_rlp::decode::RLPDecode;
use ethrex_rlp::encode::{RLPEncode, encode_list_prefix};
use ethrex_rlp::structs::{Decoder, Encoder};

#[derive(Debug, PartialEq, Eq)]
struct Simple {
    pub a: u8,
    pub b: u16,
}

#[test]
fn test_decoder_simple_struct() {
    let expected = Simple { a: 61, b: 75 };
    let mut buf = Vec::new();
    (expected.a, expected.b).encode(&mut buf);

    let decoder = Decoder::new(&buf).unwrap();
    let (a, decoder) = decoder.decode_field("a").unwrap();
    let (b, decoder) = decoder.decode_field("b").unwrap();
    let rest = decoder.finish().unwrap();

    assert!(rest.is_empty());
    let got = Simple { a, b };
    assert_eq!(got, expected);

    // Decoding the struct as a tuple should give the same result
    let tuple_decode = <(u8, u16) as RLPDecode>::decode(&buf).unwrap();
    assert_eq!(tuple_decode, (a, b));
}

#[test]
fn test_encoder_simple_struct() {
    let input = Simple { a: 61, b: 75 };
    let mut buf = Vec::new();

    Encoder::new(&mut buf)
        .encode_field(&input.a)
        .encode_field(&input.b)
        .finish();

    assert_eq!(buf, vec![0xc2, 61, 75]);

    // Encoding the struct from a tuple should give the same result
    let mut tuple_encoded = Vec::new();
    (input.a, input.b).encode(&mut tuple_encoded);
    assert_eq!(buf, tuple_encoded);
}

/// `Encoder` writes fields straight into the output buffer and inserts the list
/// prefix in `finish`, so an outer `finish` shifts inner lists that have
/// already been prefixed. Cover more than one level, and a payload long enough
/// that the outer prefix grows while the inner ones stay short.
#[test]
fn nested_encoders_backpatch_correctly() {
    struct Inner {
        a: u64,
        b: Vec<u8>,
    }

    impl RLPEncode for Inner {
        fn encode(&self, buf: &mut Vec<u8>) {
            Encoder::new(buf)
                .encode_field(&self.a)
                .encode_bytes(&self.b)
                .finish();
        }
    }

    struct Outer {
        head: u8,
        inners: Vec<Inner>,
    }

    impl RLPEncode for Outer {
        fn encode(&self, buf: &mut Vec<u8>) {
            let mut encoder = Encoder::new(buf).encode_field(&self.head);
            for inner in &self.inners {
                encoder = encoder.encode_field(inner);
            }
            encoder.finish();
        }
    }

    // Each inner is short-form; together they push the outer past 55 bytes so
    // the outer prefix is long-form and the shift is more than one byte.
    let outer = Outer {
        head: 0x7f,
        inners: (0..6)
            .map(|i| Inner {
                a: 0x0102_0304_0506_0700 + i,
                b: vec![i as u8; 8],
            })
            .collect(),
    };

    let mut encoded = Vec::new();
    outer.encode(&mut encoded);

    // Rebuild the expected bytes bottom-up, computing every prefix from the
    // payload it actually precedes.
    let mut expected_payload = Vec::new();
    outer.head.encode(&mut expected_payload);
    for inner in &outer.inners {
        let mut inner_payload = Vec::new();
        inner.a.encode(&mut inner_payload);
        <[u8] as RLPEncode>::encode(&inner.b, &mut inner_payload);
        encode_list_prefix(inner_payload.len(), &mut expected_payload);
        expected_payload.extend_from_slice(&inner_payload);
    }
    let mut expected = Vec::new();
    encode_list_prefix(expected_payload.len(), &mut expected);
    expected.extend_from_slice(&expected_payload);

    assert!(
        expected_payload.len() > 55,
        "expected a long-form outer prefix"
    );
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), outer.length());

    // The same value encoded twice into one buffer must produce two independent
    // lists; the second one starts at a non-zero offset.
    let mut twice = Vec::new();
    outer.encode(&mut twice);
    outer.encode(&mut twice);
    assert_eq!(twice.len(), encoded.len() * 2);
    assert_eq!(&twice[..encoded.len()], &encoded[..]);
    assert_eq!(&twice[encoded.len()..], &encoded[..]);
}

/// Dropping an `Encoder` without calling `finish` closes the list anyway, so
/// an early return leaves well-formed RLP rather than a payload with no prefix
/// in front of it. The two paths must agree byte for byte, and `finish` must
/// not write the prefix twice.
#[test]
fn dropped_encoder_closes_its_list() {
    let input = Simple { a: 61, b: 75 };

    let mut finished = Vec::new();
    Encoder::new(&mut finished)
        .encode_field(&input.a)
        .encode_field(&input.b)
        .finish();

    let mut dropped = Vec::new();
    {
        let encoder = Encoder::new(&mut dropped)
            .encode_field(&input.a)
            .encode_field(&input.b);
        drop(encoder);
    }

    assert_eq!(finished, vec![0xc2, 61, 75]);
    assert_eq!(dropped, finished);
}

/// The prefix must wrap only what the encoder itself wrote, whichever way the
/// list is closed, and a dropped inner encoder must nest correctly inside an
/// outer one.
#[test]
fn dropped_encoder_nests_and_preserves_existing_bytes() {
    let mut buf = vec![0xff];
    {
        let outer = Encoder::new(&mut buf);
        let outer = outer.encode_field(&61u8);
        // Inner list closed by drop, not by an explicit `finish`.
        drop(outer);
    }
    assert_eq!(buf, vec![0xff, 0xc1, 61]);

    let mut nested = Vec::new();
    {
        let outer = Encoder::new(&mut nested);
        drop(outer);
    }
    // An encoder that wrote nothing still closes as the empty list.
    assert_eq!(nested, vec![0xc0]);
}
