use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ethereum_types::U256;

use super::constants::RLP_NULL;

/// Function for encoding a value to RLP.
/// For encoding the value into a buffer directly, use [`RLPEncode::encode`].
pub fn encode<T: RLPEncode>(value: T) -> Vec<u8> {
    let mut buf = Vec::new();
    value.encode(&mut buf);
    buf
}

/// Calculates the encoded length of the given integer bit width (ilog2 value) and lsb
#[inline(always)]
const fn impl_length_integers(bits: u32, lsb: u8) -> usize {
    // bits is the ilog2 0 based result, +8 accounts for the first byte boundary
    let sig_len = (bits + 8) >> 3;
    let is_multibyte_mask = ((sig_len > 1) as usize) | ((lsb > 0x7f) as usize);
    1 + sig_len as usize * is_multibyte_mask
}

/// Computes the length needed for a given payload length
#[inline]
pub const fn list_length(payload_len: usize) -> usize {
    if payload_len < 56 {
        // short prefix
        1 + payload_len
    } else {
        // encode payload_len as big endian without leading zeros
        let be_len = payload_len.ilog2() / 8 + 1;
        // prefix + payload_len encoding size + payload bytes
        1 + be_len as usize + payload_len
    }
}

/// Computes the length needed for a given byte-string and first byte
#[inline]
pub const fn bytes_length(bytes_len: usize, first_byte: u8) -> usize {
    if bytes_len == 1 && first_byte <= 0x7f {
        return 1;
    }

    if bytes_len < 56 {
        return 1 + bytes_len; // prefix (0x80 + len) + payload
    }

    // long (>=56 bytes)
    let be_len = bytes_len.ilog2() / 8 + 1;
    1 + be_len as usize + bytes_len // prefix + len(len) + payload
}

pub trait RLPEncode {
    fn encode(&self, buf: &mut Vec<u8>);

    fn length(&self) -> usize {
        // Without a polymorphic sink there is no way to count bytes other than
        // actually encoding them, so this allocates a throwaway buffer.
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }

    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl RLPEncode for bool {
    #[inline(always)]
    fn encode(&self, buf: &mut Vec<u8>) {
        if *self {
            buf.push(0x01);
        } else {
            buf.push(RLP_NULL);
        }
    }

    #[inline(always)]
    fn length(&self) -> usize {
        1
    }
}

// integer types impls

#[inline]
fn impl_encode<const N: usize>(value_be: [u8; N], buf: &mut Vec<u8>) {
    // count leading zeros
    let mut i = 0;
    while i < N && value_be[i] == 0 {
        i += 1;
    }

    // 0, also known as null or the empty string is 0x80
    if i == N {
        buf.push(RLP_NULL);
        return;
    }

    let first = value_be[i];

    // for a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding.
    if i == N - 1 && first <= 0x7f {
        buf.push(first);
        return;
    }

    // if a string is 0-55 bytes long, the RLP encoding consists of a
    // single byte with value RLP_NULL (0x80) plus the length of the string followed by the string.
    let len = N - i;
    buf.push(RLP_NULL + len as u8);
    buf.extend_from_slice(&value_be[i..]);
}

impl RLPEncode for u8 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        impl_encode(self.to_be_bytes(), buf);
    }

    #[inline]
    fn length(&self) -> usize {
        impl_length_integers(self.checked_ilog2().unwrap_or(0), *self)
    }
}

impl RLPEncode for u16 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        impl_encode(self.to_be_bytes(), buf);
    }
    #[inline]
    fn length(&self) -> usize {
        impl_length_integers(self.checked_ilog2().unwrap_or(0), (self & 0xff) as u8)
    }
}

impl RLPEncode for u32 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        impl_encode(self.to_be_bytes(), buf);
    }

    #[inline]
    fn length(&self) -> usize {
        impl_length_integers(self.checked_ilog2().unwrap_or(0), (self & 0xff) as u8)
    }
}

impl RLPEncode for u64 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        impl_encode(self.to_be_bytes(), buf);
    }

    #[inline]
    fn length(&self) -> usize {
        impl_length_integers(self.checked_ilog2().unwrap_or(0), (self & 0xff) as u8)
    }
}

impl RLPEncode for usize {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        impl_encode(self.to_be_bytes(), buf);
    }

    #[inline]
    fn length(&self) -> usize {
        impl_length_integers(self.checked_ilog2().unwrap_or(0), (self & 0xff) as u8)
    }
}

impl RLPEncode for u128 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        impl_encode(self.to_be_bytes(), buf);
    }

    #[inline]
    fn length(&self) -> usize {
        impl_length_integers(self.checked_ilog2().unwrap_or(0), (self & 0xff) as u8)
    }
}

impl RLPEncode for () {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(RLP_NULL);
    }
    #[inline]
    fn length(&self) -> usize {
        1
    }
}

impl RLPEncode for [u8] {
    #[inline(always)]
    fn encode(&self, buf: &mut Vec<u8>) {
        if self.len() == 1 && self[0] < RLP_NULL {
            buf.push(self[0]);
        } else {
            let len = self.len();
            if len < 56 {
                buf.push(RLP_NULL + len as u8);
            } else {
                let bytes = len.to_be_bytes();
                let start = bytes.iter().position(|&x| x != 0).unwrap();
                let len = bytes.len() - start;
                buf.push(0xb7 + len as u8);
                buf.extend_from_slice(&bytes[start..]);
            }
            buf.extend_from_slice(self);
        }
    }

    #[inline]
    fn length(&self) -> usize {
        if self.is_empty() {
            return 1;
        }
        bytes_length(self.len(), self[0])
    }
}

impl<const N: usize> RLPEncode for [u8; N] {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_ref().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        if N == 1 && self[0] <= 0x7f {
            return 1;
        }

        if N < 56 {
            return 1 + N;
        }

        // long case
        let be_len = if N == 0 {
            1
        } else {
            (N.ilog2() as usize / 8) + 1
        };

        1 + be_len + N
    }
}

impl RLPEncode for str {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for &str {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for String {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for U256 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        let leading_zeros_in_bytes: usize = (self.leading_zeros() / 8) as usize;
        let bytes = self.to_big_endian();
        bytes[leading_zeros_in_bytes..].encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        let ilog = self.bits().saturating_sub(1);
        impl_length_integers(ilog as u32, (self.low_u32() & 0xff) as u8)
    }
}

impl<T: RLPEncode> RLPEncode for Vec<T> {
    #[inline(always)]
    fn encode(&self, buf: &mut Vec<u8>) {
        if self.is_empty() {
            buf.push(0xc0);
        } else {
            // Write the payload first and fill the prefix in afterwards: the
            // `length()` pre-pass this replaces re-encoded every element.
            let start = buf.len();
            for item in self {
                item.encode(buf);
            }
            backpatch_list_prefix(buf, start);
        }
    }

    #[inline]
    fn length(&self) -> usize {
        if self.is_empty() {
            // 0xc0 (1 byte)
            return 1;
        }

        let mut payload_len = 0usize;
        for item in self {
            payload_len += item.length();
        }

        list_length(payload_len)
    }
}

/// Maximum size of a list prefix: the tag plus a `usize` payload length.
const MAX_LIST_PREFIX_LEN: usize = 1 + size_of::<usize>();

/// Builds the RLP list prefix for a payload of `payload_len` bytes.
///
/// Returned by value so that both writing a prefix ahead of a payload
/// ([`encode_list_prefix`]) and inserting one in front of a payload already written
/// ([`backpatch_list_prefix`]) share a single implementation.
#[inline]
fn list_prefix(payload_len: usize) -> ([u8; MAX_LIST_PREFIX_LEN], usize) {
    let mut prefix = [0u8; MAX_LIST_PREFIX_LEN];
    if payload_len < 56 {
        prefix[0] = 0xc0 + payload_len as u8;
        return (prefix, 1);
    }
    // `payload_len >= 56`, so `ilog2` is defined and there is at least one
    // significant byte.
    let be_len = payload_len.ilog2() as usize / 8 + 1;
    let be = payload_len.to_be_bytes();
    prefix[0] = 0xf7 + be_len as u8;
    prefix[1..1 + be_len].copy_from_slice(&be[be.len() - be_len..]);
    (prefix, 1 + be_len)
}

/// Appends the list prefix for a payload of `payload_len` bytes, which the
/// caller is about to write.
///
/// Use [`backpatch_list_prefix`] instead when the payload has already been
/// written and its length was not known up front.
#[inline]
pub fn encode_list_prefix(payload_len: usize, buf: &mut Vec<u8>) {
    let (prefix, prefix_len) = list_prefix(payload_len);
    buf.extend_from_slice(&prefix[..prefix_len]);
}

/// Inserts the list prefix for a payload occupying `buf[start..]`, shifting the
/// payload right to make room.
///
/// Lets a list be encoded in one pass: write the payload, then derive the
/// prefix from how much was written. `start` must be the buffer length recorded
/// before the payload was written.
///
/// # Panics
///
/// If `start > buf.len()`.
#[inline]
pub fn backpatch_list_prefix(buf: &mut Vec<u8>, start: usize) {
    let payload_len = buf.len() - start;
    let (prefix, prefix_len) = list_prefix(payload_len);
    buf.resize(buf.len() + prefix_len, 0);
    buf.copy_within(start..start + payload_len, start + prefix_len);
    buf[start..start + prefix_len].copy_from_slice(&prefix[..prefix_len]);
}

impl<S: RLPEncode, T: RLPEncode> RLPEncode for (S, T) {
    fn encode(&self, buf: &mut Vec<u8>) {
        super::structs::Encoder::new(buf)
            .encode_field(&self.0)
            .encode_field(&self.1)
            .finish();
    }

    #[inline]
    fn length(&self) -> usize {
        let payload_len = self.0.length() + self.1.length();
        list_length(payload_len)
    }
}

impl<S: RLPEncode, T: RLPEncode, U: RLPEncode> RLPEncode for (S, T, U) {
    fn encode(&self, buf: &mut Vec<u8>) {
        super::structs::Encoder::new(buf)
            .encode_field(&self.0)
            .encode_field(&self.1)
            .encode_field(&self.2)
            .finish();
    }

    #[inline]
    fn length(&self) -> usize {
        let payload_len = self.0.length() + self.1.length() + self.2.length();
        list_length(payload_len)
    }
}

impl<S: RLPEncode, T: RLPEncode, U: RLPEncode, V: RLPEncode> RLPEncode for (S, T, U, V) {
    fn encode(&self, buf: &mut Vec<u8>) {
        super::structs::Encoder::new(buf)
            .encode_field(&self.0)
            .encode_field(&self.1)
            .encode_field(&self.2)
            .encode_field(&self.3)
            .finish();
    }

    #[inline]
    fn length(&self) -> usize {
        let payload_len = self.0.length() + self.1.length() + self.2.length() + self.3.length();
        list_length(payload_len)
    }
}

impl<S: RLPEncode, T: RLPEncode, U: RLPEncode, V: RLPEncode, W: RLPEncode> RLPEncode
    for (S, T, U, V, W)
{
    fn encode(&self, buf: &mut Vec<u8>) {
        super::structs::Encoder::new(buf)
            .encode_field(&self.0)
            .encode_field(&self.1)
            .encode_field(&self.2)
            .encode_field(&self.3)
            .encode_field(&self.4)
            .finish();
    }

    #[inline]
    fn length(&self) -> usize {
        let payload_len =
            self.0.length() + self.1.length() + self.2.length() + self.3.length() + self.4.length();
        list_length(payload_len)
    }
}

impl RLPEncode for Ipv4Addr {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.octets().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(&self.octets())
    }
}

impl RLPEncode for Ipv6Addr {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.octets().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(&self.octets())
    }
}

impl RLPEncode for IpAddr {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            IpAddr::V4(ip) => ip.encode(buf),
            IpAddr::V6(ip) => ip.encode(buf),
        }
    }

    #[inline]
    fn length(&self) -> usize {
        match self {
            IpAddr::V4(ipv4_addr) => RLPEncode::length(&ipv4_addr.octets()),
            IpAddr::V6(ipv6_addr) => RLPEncode::length(&ipv6_addr.octets()),
        }
    }
}

impl RLPEncode for Bytes {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_ref().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        self.as_ref().length()
    }
}

// encoding for Ethereum types

impl RLPEncode for ethereum_types::H32 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::H64 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::H128 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::Address {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::H256 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::H264 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::H512 {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::Signature {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_bytes().encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(self.as_bytes())
    }
}

impl RLPEncode for ethereum_types::Bloom {
    #[inline]
    fn encode(&self, buf: &mut Vec<u8>) {
        self.0.encode(buf)
    }

    #[inline]
    fn length(&self) -> usize {
        RLPEncode::length(&self.0)
    }
}

pub trait PayloadRLPEncode {
    fn encode_payload(&self, buf: &mut Vec<u8>);
    fn encode_payload_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_payload(&mut buf);
        buf
    }
}
