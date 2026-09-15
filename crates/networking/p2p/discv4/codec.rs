use crate::discv4::messages::{Message, Packet, PacketDecodeErr};

use bytes::BytesMut;
use secp256k1::SecretKey;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub struct Discv4Codec {
    signer: SecretKey,
}

impl Discv4Codec {
    pub fn new(signer: SecretKey) -> Self {
        Self { signer }
    }
}

impl Decoder for Discv4Codec {
    type Item = Packet;
    type Error = PacketDecodeErr;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !buf.is_empty() {
            Ok(Some(Packet::decode(&buf.split_to(buf.len()))?))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<Message> for Discv4Codec {
    type Error = PacketDecodeErr;

    fn encode(&mut self, message: Message, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // `encode_with_header` writes into a `Vec<u8>` now, so the framed
        // `BytesMut` sink needs an extra staging buffer + copy.
        let mut staging = Vec::new();
        message.encode_with_header(&mut staging, &self.signer);
        buf.extend_from_slice(&staging);
        Ok(())
    }
}
