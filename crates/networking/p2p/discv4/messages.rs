use crate::{
    types::{Endpoint, Node, NodeRecord},
    utils::{current_unix_time, node_id},
};
use ethrex_common::{H256, H512, H520, utils::keccak};
use ethrex_crypto::keccak::keccak_hash;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{self, Decoder, Encoder},
};
use secp256k1::{
    SecretKey,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use std::{convert::Into, io::ErrorKind};

#[derive(Debug, thiserror::Error)]
pub enum PacketDecodeErr {
    #[error("RLP decoding error")]
    RLPDecodeError(#[from] RLPDecodeError),
    #[error("Invalid packet size")]
    InvalidSize,
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Discv4 decoding error: {0}")]
    Discv4DecodingError(String),
    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),
}

impl From<PacketDecodeErr> for std::io::Error {
    fn from(error: PacketDecodeErr) -> Self {
        std::io::Error::new(ErrorKind::InvalidData, error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    hash: H256,
    signature: H520,
    message: Message,
    public_key: H512,
}

impl Packet {
    pub fn decode(encoded_packet: &[u8]) -> Result<Packet, PacketDecodeErr> {
        // the packet structure is
        // hash || signature || packet-type || packet-data
        let hash_len = 32;
        let signature_len = 65;
        let header_size = hash_len + signature_len; // 97

        if encoded_packet.len() < header_size + 1 {
            return Err(PacketDecodeErr::InvalidSize);
        };

        let hash = H256::from_slice(&encoded_packet[..hash_len]);
        let signature_bytes = &encoded_packet[hash_len..header_size];
        let packet_type = encoded_packet[header_size];
        let encoded_msg = &encoded_packet[header_size..];

        let header_hash = keccak(&encoded_packet[hash_len..]);

        if hash != header_hash {
            return Err(PacketDecodeErr::HashMismatch);
        }

        let digest: [u8; 32] = keccak_hash(encoded_msg);

        let rid = RecoveryId::try_from(Into::<i32>::into(signature_bytes[64]))
            .map_err(|_| PacketDecodeErr::InvalidSignature)?;

        let peer_pk = secp256k1::SECP256K1
            .recover_ecdsa(
                &secp256k1::Message::from_digest(digest),
                &RecoverableSignature::from_compact(&signature_bytes[0..64], rid)
                    .map_err(|_| PacketDecodeErr::InvalidSignature)?,
            )
            .map_err(|_| PacketDecodeErr::InvalidSignature)?;

        let encoded = peer_pk.serialize_uncompressed();

        let public_key = H512::from_slice(&encoded[1..]);
        let signature = H520::from_slice(signature_bytes);
        let message = Message::decode_with_type(packet_type, &encoded_msg[1..])
            .map_err(PacketDecodeErr::RLPDecodeError)?;

        Ok(Self {
            hash,
            signature,
            message,
            public_key,
        })
    }

    pub fn get_hash(&self) -> H256 {
        self.hash
    }

    pub fn get_message(&self) -> &Message {
        &self.message
    }

    #[allow(unused)]
    pub fn get_signature(&self) -> H520 {
        self.signature
    }

    pub fn get_public_key(&self) -> H512 {
        self.public_key
    }

    pub fn get_node_id(&self) -> H256 {
        node_id(&self.public_key)
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Message {
    Ping(PingMessage),
    Pong(PongMessage),
    FindNode(FindNodeMessage),
    Neighbors(NeighborsMessage),
    ENRRequest(ENRRequestMessage),
    ENRResponse(ENRResponseMessage),
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            Message::Ping(_) => "Ping",
            Message::Pong(_) => "Pong",
            Message::FindNode(_) => "FindNode",
            Message::Neighbors(_) => "Neighbors",
            Message::ENRRequest(_) => "ENRRequest",
            Message::ENRResponse(_) => "ENRResponse",
        };
        write!(f, "{variant}")
    }
}

impl Message {
    /// Returns a short, stable label suitable for use as a Prometheus metric label value.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Message::Ping(_) => "Ping",
            Message::Pong(_) => "Pong",
            Message::FindNode(_) => "FindNode",
            Message::Neighbors(_) => "Neighbors",
            Message::ENRRequest(_) => "ENRRequest",
            Message::ENRResponse(_) => "ENRResponse",
        }
    }

    pub fn encode_with_header(&self, buf: &mut Vec<u8>, node_signer: &SecretKey) {
        let signature_size = 65_usize;
        let mut data: Vec<u8> = Vec::with_capacity(signature_size.next_power_of_two());
        data.resize(signature_size, 0);

        self.encode_with_type(&mut data);

        let digest: [u8; 32] = keccak_hash(&data[signature_size..]);

        let (recovery_id, signature) = secp256k1::SECP256K1
            .sign_ecdsa_recoverable(&secp256k1::Message::from_digest(digest), node_signer)
            .serialize_compact();

        data[..signature_size - 1].copy_from_slice(&signature);
        data[signature_size - 1] = Into::<i32>::into(recovery_id) as u8;

        let hash = keccak_hash(&data[..]);
        buf.extend_from_slice(&hash);
        buf.extend_from_slice(&data[..]);
    }

    fn encode_with_type(&self, buf: &mut Vec<u8>) {
        buf.push(self.packet_type());
        match self {
            Message::Ping(msg) => msg.encode(buf),
            Message::Pong(msg) => msg.encode(buf),
            Message::FindNode(msg) => msg.encode(buf),
            Message::ENRRequest(msg) => msg.encode(buf),
            Message::ENRResponse(msg) => msg.encode(buf),
            Message::Neighbors(msg) => msg.encode(buf),
        }
    }

    pub fn decode_with_type(packet_type: u8, msg: &[u8]) -> Result<Message, RLPDecodeError> {
        // NOTE: extra elements inside the message should be ignored, along with extra data
        // after the message.
        match packet_type {
            0x01 => {
                let (ping, _rest) = PingMessage::decode_unfinished(msg)?;
                Ok(Message::Ping(ping))
            }
            0x02 => {
                let (pong, _rest) = PongMessage::decode_unfinished(msg)?;
                Ok(Message::Pong(pong))
            }
            0x03 => {
                let (find_node_msg, _rest) = FindNodeMessage::decode_unfinished(msg)?;
                Ok(Message::FindNode(find_node_msg))
            }
            0x04 => {
                let (neighbors_msg, _rest) = NeighborsMessage::decode_unfinished(msg)?;
                Ok(Message::Neighbors(neighbors_msg))
            }
            0x05 => {
                let (enr_request_msg, _rest) = ENRRequestMessage::decode_unfinished(msg)?;
                Ok(Message::ENRRequest(enr_request_msg))
            }
            0x06 => {
                let (enr_response_msg, _rest) = ENRResponseMessage::decode_unfinished(msg)?;
                Ok(Message::ENRResponse(enr_response_msg))
            }
            _ => Err(RLPDecodeError::MalformedData),
        }
    }

    fn packet_type(&self) -> u8 {
        match self {
            Message::Ping(_) => 0x01,
            Message::Pong(_) => 0x02,
            Message::FindNode(_) => 0x03,
            Message::Neighbors(_) => 0x04,
            Message::ENRRequest(_) => 0x05,
            Message::ENRResponse(_) => 0x06,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingMessage {
    /// The Ping message version. Should be set to 4, but mustn't be enforced.
    pub version: u8,
    /// The endpoint of the sender.
    pub from: Endpoint,
    /// The endpoint of the receiver.
    pub to: Endpoint,
    /// The expiration time of the message. If the message is older than this time,
    /// it shouldn't be responded to.
    pub expiration: u64,
    /// The ENR sequence number of the sender. This field is optional.
    pub enr_seq: Option<u64>,
}

impl PingMessage {
    pub fn new(from: Endpoint, to: Endpoint, expiration: u64) -> Self {
        Self {
            version: 4,
            from,
            to,
            expiration,
            enr_seq: None,
        }
    }

    // TODO: remove when used
    #[allow(unused)]
    pub fn with_enr_seq(self, enr_seq: u64) -> Self {
        Self {
            enr_seq: Some(enr_seq),
            ..self
        }
    }
}

impl RLPEncode for PingMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.version)
            .encode_field(&self.from)
            .encode_field(&self.to)
            .encode_field(&self.expiration)
            .encode_optional_field(&self.enr_seq)
            .finish();
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FindNodeMessage {
    /// The target is a 64-byte secp256k1 public key.
    pub target: H512,
    /// The expiration time of the message. If the message is older than this time,
    /// it shouldn't be responded to.
    pub expiration: u64,
}

impl FindNodeMessage {
    #[allow(unused)]
    pub fn new(target: H512, expiration: u64) -> Self {
        Self { target, expiration }
    }
}

impl RLPEncode for FindNodeMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.target)
            .encode_field(&self.expiration)
            .finish();
    }
}

impl RLPDecode for FindNodeMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (target, decoder) = decoder.decode_field("target")?;
        let (expiration, decoder) = decoder.decode_field("expiration")?;
        let remaining = decoder.finish_unchecked();
        let msg = FindNodeMessage { target, expiration };
        Ok((msg, remaining))
    }
}

#[derive(Debug, Clone)]
pub struct FindNodeRequest {
    /// the number of nodes sent
    /// we keep track of this number since we will accept neighbor messages until the max_per_bucket
    pub nodes_sent: u64,
    /// unix timestamp tracking when we have sent the request
    pub sent_at: u64,
    /// if present, server will send the nodes through this channel when receiving neighbors
    /// useful to wait for the response in lookups
    pub tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<Node>>>,
}

impl Default for FindNodeRequest {
    fn default() -> Self {
        Self {
            nodes_sent: 0,
            sent_at: current_unix_time(),
            tx: None,
        }
    }
}

impl FindNodeRequest {
    pub fn new_with_sender(sender: tokio::sync::mpsc::UnboundedSender<Vec<Node>>) -> Self {
        Self {
            tx: Some(sender),
            ..Self::default()
        }
    }
}

impl RLPDecode for PingMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (version, decoder): (u8, Decoder) = decoder.decode_field("version")?;
        let (from, decoder) = decoder.decode_field("from")?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (expiration, decoder) = decoder.decode_field("expiration")?;
        let (enr_seq, decoder) = decoder.decode_optional_field();

        let ping = PingMessage {
            version,
            from,
            to,
            expiration,
            enr_seq,
        };
        // NOTE: as per the spec, any additional elements should be ignored.
        let remaining = decoder.finish_unchecked();
        Ok((ping, remaining))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongMessage {
    /// The endpoint of the receiver.
    pub to: Endpoint,
    /// The hash of the corresponding ping packet.
    pub ping_hash: H256,
    /// The expiration time of the message. If the message is older than this time,
    /// it shouldn't be responded to.
    pub expiration: u64,
    /// The ENR sequence number of the sender. This field is optional.
    pub enr_seq: Option<u64>,
}

impl PongMessage {
    #[allow(unused)]
    pub fn new(to: Endpoint, ping_hash: H256, expiration: u64) -> Self {
        Self {
            to,
            ping_hash,
            expiration,
            enr_seq: None,
        }
    }

    pub fn with_enr_seq(self, enr_seq: u64) -> Self {
        Self {
            enr_seq: Some(enr_seq),
            ..self
        }
    }
}

impl RLPEncode for PongMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.to)
            .encode_field(&self.ping_hash)
            .encode_field(&self.expiration)
            .encode_optional_field(&self.enr_seq)
            .finish();
    }
}

impl RLPDecode for PongMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (to, decoder) = decoder.decode_field("to")?;
        let (ping_hash, decoder) = decoder.decode_field("ping_hash")?;
        let (expiration, decoder) = decoder.decode_field("expiration")?;
        let (enr_seq, decoder) = decoder.decode_optional_field();

        let pong = PongMessage {
            to,
            ping_hash,
            expiration,
            enr_seq,
        };
        // NOTE: as per the spec, any additional elements should be ignored.
        let remaining = decoder.finish_unchecked();
        Ok((pong, remaining))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborsMessage {
    // nodes is the list of neighbors
    pub nodes: Vec<Node>,
    pub expiration: u64,
}

impl NeighborsMessage {
    pub fn new(nodes: Vec<Node>, expiration: u64) -> Self {
        Self { nodes, expiration }
    }
}

impl RLPDecode for NeighborsMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (nodes, decoder) = decoder.decode_field("nodes")?;
        let (expiration, decoder) = decoder.decode_field("expiration")?;
        let remaining = decoder.finish_unchecked();

        let neighbors = NeighborsMessage::new(nodes, expiration);
        Ok((neighbors, remaining))
    }
}

impl RLPEncode for NeighborsMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.nodes)
            .encode_field(&self.expiration)
            .finish();
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ENRResponseMessage {
    pub request_hash: H256,
    pub node_record: NodeRecord,
}

impl ENRResponseMessage {
    pub fn new(request_hash: H256, node_record: NodeRecord) -> Self {
        Self {
            request_hash,
            node_record,
        }
    }
}

impl RLPDecode for ENRResponseMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (request_hash, decoder) = decoder.decode_field("request_hash")?;
        let (node_record, decoder) = decoder.decode_field("node_record")?;
        let remaining = decoder.finish_unchecked();
        let response = ENRResponseMessage {
            request_hash,
            node_record,
        };
        Ok((response, remaining))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ENRRequestMessage {
    pub expiration: u64,
}

impl ENRRequestMessage {
    pub fn new(expiration: u64) -> Self {
        Self { expiration }
    }
}

impl RLPDecode for ENRRequestMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (expiration, decoder) = decoder.decode_field("expiration")?;
        let remaining = decoder.finish_unchecked();
        let enr_request = ENRRequestMessage { expiration };
        Ok((enr_request, remaining))
    }
}

impl RLPEncode for ENRRequestMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.expiration)
            .finish();
    }
}

impl RLPEncode for ENRResponseMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.request_hash)
            .encode_field(&self.node_record)
            .finish();
    }
}
