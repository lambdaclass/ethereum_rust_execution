use super::{
    decode::{RLPDecode, decode_rlp_item, get_item_with_prefix},
    encode::{RLPEncode, backpatch_list_prefix},
    error::RLPDecodeError,
};
use alloc::format;
use alloc::vec::Vec;
use bytes::Bytes;

/// # Struct decoding helper
///
/// Used to decode a struct from RLP format.
/// The struct's fields must implement [`RLPDecode`].
/// The struct is expected as a list, with its values being the fields
/// in the order they are passed to [`Decoder::decode_field`].
///
/// # Examples
///
/// ```
/// # use ethrex_rlp::structs::Decoder;
/// # use ethrex_rlp::error::RLPDecodeError;
/// # use ethrex_rlp::decode::RLPDecode;
/// #[derive(Debug, PartialEq, Eq)]
/// struct Simple {
///     pub a: u8,
///     pub b: u16,
/// }
///
/// impl RLPDecode for Simple {
///     fn decode_unfinished(buf: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
///         let decoder = Decoder::new(&buf).unwrap();
///         // The fields are expected in the same order as given here
///         let (a, decoder) = decoder.decode_field("a").unwrap();
///         let (b, decoder) = decoder.decode_field("b").unwrap();
///         let rest = decoder.finish().unwrap();
///         Ok((Simple { a, b }, rest))
///     }
/// }
///
/// let bytes = [0xc2, 61, 75];
/// let decoded = Simple::decode(&bytes).unwrap();
///
/// assert_eq!(decoded, Simple { a: 61, b: 75 });
/// ```
#[derive(Debug)]
#[must_use = "`Decoder` must be consumed with `finish` to perform decoding checks"]
pub struct Decoder<'a> {
    payload: &'a [u8],
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, RLPDecodeError> {
        match decode_rlp_item(buf)? {
            (true, payload, remaining) => Ok(Self { payload, remaining }),
            (false, _, _) => Err(RLPDecodeError::UnexpectedString),
        }
    }

    pub fn decode_field<T: RLPDecode>(self, name: &str) -> Result<(T, Self), RLPDecodeError> {
        let (field, rest) = <T as RLPDecode>::decode_unfinished(self.payload)
            .map_err(|err| field_decode_error::<T>(name, err))?;
        let updated_self = Self {
            payload: rest,
            ..self
        };
        Ok((field, updated_self))
    }

    /// Returns the next field without decoding it, i.e. the payload bytes including its prefix.
    pub fn get_encoded_item(self) -> Result<(Vec<u8>, Self), RLPDecodeError> {
        self.get_encoded_item_ref()
            .map(|(field, updated_self)| (field.to_vec(), updated_self))
    }

    /// Returns the next field without decoding it, i.e. the payload bytes including its prefix.
    pub fn get_encoded_item_ref(self) -> Result<(&'a [u8], Self), RLPDecodeError> {
        get_item_with_prefix(self.payload).map(|(field, rest)| {
            let updated_self = Self {
                payload: rest,
                ..self
            };
            (field, updated_self)
        })
    }

    /// Returns Some(field) if there's some field to decode, otherwise returns None
    pub fn decode_optional_field<T: RLPDecode>(self) -> (Option<T>, Self) {
        match <T as RLPDecode>::decode_unfinished(self.payload) {
            Ok((field, rest)) => {
                let updated_self = Self {
                    payload: rest,
                    ..self
                };
                (Some(field), updated_self)
            }
            Err(_) => (None, self),
        }
    }

    /// Finishes encoding the struct and returns the remaining bytes after the item.
    /// If the item's payload is not empty, returns an error.
    pub const fn finish(self) -> Result<&'a [u8], RLPDecodeError> {
        if self.payload.is_empty() {
            Ok(self.remaining)
        } else {
            Err(RLPDecodeError::MalformedData)
        }
    }

    /// Returns true if the decoder has finished decoding the given input
    pub const fn is_done(&self) -> bool {
        self.payload.is_empty()
    }

    /// Same as [`finish`](Self::finish), but discards the item's remaining payload
    /// instead of failing.
    pub const fn finish_unchecked(self) -> &'a [u8] {
        self.remaining
    }

    pub const fn get_payload_len(&self) -> usize {
        self.payload.len()
    }
}

fn field_decode_error<T>(field_name: &str, err: RLPDecodeError) -> RLPDecodeError {
    let typ = core::any::type_name::<T>();
    let err_msg = format!("Error decoding field '{field_name}' of type {typ}: {err}");
    RLPDecodeError::Custom(err_msg)
}

/// # Struct encoding helper
///
/// Encodes a struct as an RLP list. The fields must implement [`RLPEncode`] and
/// are written in the order they are passed to [`Encoder::encode_field`].
///
/// ## How it writes
///
/// Fields go straight into the caller's buffer as they are encoded. The list
/// prefix cannot be written first because its size depends on the payload
/// length, which is only known once every field is in, so the encoder records
/// where the payload starts and inserts the prefix in front of it at the end.
/// Backpatching that way costs one memmove; measuring the payload up front
/// instead would mean encoding every field twice.
///
/// ## Finishing the list
///
/// The prefix is written when the encoder is dropped, so a list is always
/// terminated even on an early return. Prefer calling [`Encoder::finish`]
/// anyway: it fixes the point at which the list closes rather than leaving it
/// to wherever the value happens to die, which matters when several encoders
/// are nested and their order decides the byte layout.
///
/// Nesting needs no special handling. An inner encoder records a later start
/// and finishes first, so its prefix lands inside the outer payload. The buffer
/// stays mutably borrowed for as long as an encoder is alive, so the
/// half-written payload cannot be read in the meantime.
///
/// # Examples
///
/// ```
/// # use ethrex_rlp::structs::Encoder;
/// # use ethrex_rlp::encode::RLPEncode;
/// #[derive(Debug, PartialEq, Eq)]
/// struct Simple {
///     pub a: u8,
///     pub b: u16,
/// }
///
/// impl RLPEncode for Simple {
///     fn encode(&self, buf: &mut Vec<u8>) {
///         // The fields are encoded in the order given here
///         Encoder::new(buf)
///             .encode_field(&self.a)
///             .encode_field(&self.b)
///             .finish();
///     }
/// }
///
/// let mut buf = vec![];
/// Simple { a: 61, b: 75 }.encode(&mut buf);
///
/// // 0xc2 = list, 2 bytes of payload.
/// assert_eq!(&buf, &[0xc2, 61, 75]);
/// ```
///
/// Appending to a buffer that already holds bytes leaves them alone; only the
/// bytes this encoder wrote are wrapped:
///
/// ```
/// # use ethrex_rlp::structs::Encoder;
/// # use ethrex_rlp::encode::RLPEncode;
/// let mut buf = vec![0xff];
/// Encoder::new(&mut buf).encode_field(&61u8).finish();
///
/// assert_eq!(&buf, &[0xff, 0xc1, 61]);
/// ```
#[derive(Debug)]
#[must_use = "`Encoder` closes its list when dropped; call `finish` to close it explicitly"]
pub struct Encoder<'a> {
    buf: &'a mut Vec<u8>,
    /// Where this list's payload starts in `buf`; the prefix is inserted here
    /// when the list is closed.
    start: usize,
}

/// Closes the list, so an encoder that is dropped without an explicit
/// [`Encoder::finish`] still leaves well-formed RLP behind.
///
/// Fields are written straight into the output buffer, so without this a missed
/// `finish` would leave a payload with no prefix in front of it. Inside an outer
/// list that decodes cleanly but means something different, which is very hard
/// to trace back to its cause, so closing the list here rather than reporting
/// the mistake keeps a dropped encoder from corrupting the encoding at all.
impl Drop for Encoder<'_> {
    fn drop(&mut self) {
        backpatch_list_prefix(self.buf, self.start);
    }
}

impl<'a> Encoder<'a> {
    /// Starts a list that will be appended to `buf`.
    ///
    /// Records the buffer's current length as the start of the payload, so
    /// whatever `buf` already holds is left untouched and the prefix ends up in
    /// front of this list only.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        let start = buf.len();
        Self { buf, start }
    }

    /// Encodes `value` as the next field of the list.
    pub fn encode_field<T: RLPEncode>(self, value: &T) -> Self {
        <T as RLPEncode>::encode(value, self.buf);
        self
    }

    /// Encodes `value` as the next field if it is `Some`, and writes nothing at
    /// all if it is `None`.
    ///
    /// A `None` is omitted rather than encoded as empty, so the list simply
    /// comes out shorter. That is how optional *trailing* fields are
    /// represented (a `BlockHeader`'s `base_fee_per_gas` and the fork fields
    /// after it, say). Skipping a `None` in the middle of a list would shift
    /// every field after it into the wrong position, so this is only correct
    /// for a suffix of the fields.
    pub fn encode_optional_field<T: RLPEncode>(self, opt_value: &Option<T>) -> Self {
        if let Some(value) = opt_value {
            <T as RLPEncode>::encode(value, self.buf);
        }
        self
    }

    /// Encodes a list of `(key, value)` pairs whose values are already encoded,
    /// i.e. each value is a complete `RLP prefix || payload`.
    ///
    /// Keys are encoded as byte strings; values are copied in verbatim. This is
    /// for pair lists that arrive with their values pre-encoded, such as an
    /// ENR's key/value pairs.
    pub fn encode_key_value_list<T: RLPEncode>(self, list: &Vec<(Bytes, Bytes)>) -> Self {
        for (key, value) in list {
            <Bytes>::encode(key, self.buf);
            // value is already encoded
            self.buf.extend_from_slice(value);
        }
        self
    }

    /// Closes the list by inserting its prefix in front of the payload.
    ///
    /// This is the same work the [`Drop`] impl does; calling it decides *when*
    /// the list closes instead of leaving that to the end of the enclosing
    /// scope. Taking `self` also ends the borrow on the output buffer, so the
    /// finished bytes become readable again at this point.
    pub fn finish(self) {
        // Dropping `self` here runs the `Drop` impl, which writes the prefix.
    }

    /// Appends `value` to the payload exactly as given, without encoding it.
    ///
    /// The caller is asserting that `value` is already well-formed RLP; passing
    /// anything else produces a list that is malformed from this point on. Use
    /// [`Encoder::encode_field`] unless the bytes are known to be encoded
    /// already.
    pub fn encode_raw(self, value: &[u8]) -> Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Encodes `value` as the next field, as a single RLP byte string.
    ///
    /// [`Encoder::encode_field`] cannot express this: for a slice of bytes it
    /// would select the generic `Vec<T>`/slice impl and emit a *list* of
    /// one-byte items. This forces the `[u8]` byte-string impl instead.
    pub fn encode_bytes(self, value: &[u8]) -> Self {
        <[u8] as RLPEncode>::encode(value, self.buf);
        self
    }
}
