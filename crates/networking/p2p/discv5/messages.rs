use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherError};
use aes_gcm::{Aes128Gcm, KeyInit, aead::AeadMutInPlace};
use bytes::Bytes;
use ethrex_common::H256;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use std::{array::TryFromSliceError, fmt::Display, net::SocketAddr};

use crate::types::NodeRecord;

type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

// Max and min packet sizes as defined in
// https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#udp-communication
// Used for package validation
const MIN_PACKET_SIZE: usize = 63;
const MAX_PACKET_SIZE: usize = 1280;
/// 32 src-id + 1 sig-size + 1 eph-key-size
const HANDSHAKE_AUTHDATA_HEAD: usize = 34;
// protocol data
const PROTOCOL_ID: &[u8] = b"discv5";
const PROTOCOL_VERSION: u16 = 0x0001;
// masking-iv size for a u128
const IV_MASKING_SIZE: usize = 16;
// static_header size is 23 bytes
const STATIC_HEADER_SIZE: usize = 23;
const STATIC_HEADER_END: usize = IV_MASKING_SIZE + STATIC_HEADER_SIZE;
// Number of distances to include in a FindNode message
pub const DISTANCES_PER_FIND_NODE_MSG: u8 = 3;

#[derive(Debug, thiserror::Error)]
pub enum PacketCodecError {
    #[error("RLP decoding error")]
    RLPDecodeError(#[from] RLPDecodeError),
    #[error("Packet header decoding error")]
    InvalidHeader,
    #[error("Message decoding error, message type: {0}")]
    InvalidMessage(u8),
    #[error("Invalid packet size")]
    InvalidSize,
    #[error("Session not established yet")]
    SessionNotEstablished,
    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),
    #[error("Stream Cipher Error: {0}")]
    CipherError(String),
    #[error("TryFromSliceError: {0}")]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Malformed Data")]
    MalformedData,
}

impl From<StreamCipherError> for PacketCodecError {
    fn from(error: StreamCipherError) -> Self {
        PacketCodecError::CipherError(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub masking_iv: [u8; IV_MASKING_SIZE],
    pub header: PacketHeader,
    pub encrypted_message: Vec<u8>,
}

impl Packet {
    pub fn decode(dest_id: &H256, encoded_packet: &[u8]) -> Result<Packet, PacketCodecError> {
        if encoded_packet.len() < MIN_PACKET_SIZE || encoded_packet.len() > MAX_PACKET_SIZE {
            return Err(PacketCodecError::InvalidSize);
        }

        // the packet structure is
        // masking-iv || masked-header || message
        // 16 bytes for an u128
        let masking_iv = &encoded_packet[..IV_MASKING_SIZE];

        let mut cipher = <Aes128Ctr64BE as KeyIvInit>::new(dest_id[..16].into(), masking_iv.into());

        let header = PacketHeader::decode(&mut cipher, encoded_packet)
            .map_err(|_e| PacketCodecError::InvalidHeader)?;
        let encrypted_message = encoded_packet[header.header_end_offset..].to_vec();
        Ok(Packet {
            masking_iv: masking_iv.try_into()?,
            header,
            encrypted_message,
        })
    }

    pub fn encode(&self, buf: &mut Vec<u8>, dest_id: &H256) -> Result<(), PacketCodecError> {
        let masking_iv = self.masking_iv;
        buf.extend_from_slice(&masking_iv);

        let mut cipher =
            <Aes128Ctr64BE as KeyIvInit>::new(dest_id[..16].into(), masking_iv[..].into());

        self.header.encode(buf, &mut cipher)?;
        buf.extend_from_slice(&self.encrypted_message);

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub static_header: [u8; STATIC_HEADER_SIZE],
    pub flag: u8,
    pub nonce: [u8; 12],
    pub authdata: Vec<u8>,
    /// Offset in the encoded packet where authdata ends, i.e where the header ends.
    pub header_end_offset: usize,
}

impl PacketHeader {
    fn decode<T: StreamCipher>(
        cipher: &mut T,
        encoded_packet: &[u8],
    ) -> Result<PacketHeader, PacketCodecError> {
        // static header
        let mut static_header: [u8; STATIC_HEADER_SIZE] =
            encoded_packet[IV_MASKING_SIZE..STATIC_HEADER_END].try_into()?;

        cipher.try_apply_keystream(&mut static_header)?;

        // static-header = protocol-id || version || flag || nonce || authdata-size
        //protocol check
        let protocol_id = &static_header[..6];
        let version = u16::from_be_bytes(static_header[6..8].try_into()?);
        if protocol_id != PROTOCOL_ID || version != PROTOCOL_VERSION {
            return Err(PacketCodecError::InvalidProtocol(
                match str::from_utf8(protocol_id) {
                    Ok(result) => format!("{} v{}", result, version),
                    Err(_) => format!("{:?} v{}", protocol_id, version),
                },
            ));
        }

        let flag = static_header[8];
        let nonce = static_header[9..21].try_into()?;
        let authdata_size = u16::from_be_bytes(static_header[21..23].try_into()?) as usize;
        let authdata_end = STATIC_HEADER_END + authdata_size;

        if encoded_packet.len() < authdata_end {
            return Err(PacketCodecError::InvalidSize);
        }

        let mut authdata = encoded_packet[STATIC_HEADER_END..authdata_end].to_vec();

        cipher.try_apply_keystream(&mut authdata)?;

        Ok(PacketHeader {
            static_header,
            flag,
            nonce,
            authdata,
            header_end_offset: authdata_end,
        })
    }

    fn encode<T: StreamCipher>(
        &self,
        buf: &mut Vec<u8>,
        cipher: &mut T,
    ) -> Result<(), PacketCodecError> {
        let mut static_header = Vec::new();
        static_header.extend_from_slice(PROTOCOL_ID);
        static_header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        static_header.push(self.flag);
        static_header.extend_from_slice(&self.nonce);
        static_header.extend_from_slice(&(self.authdata.len() as u16).to_be_bytes());
        cipher.try_apply_keystream(&mut static_header)?;
        buf.extend_from_slice(&static_header);

        let mut authdata = self.authdata.clone();
        cipher.try_apply_keystream(&mut authdata)?;
        buf.extend_from_slice(&authdata);

        Ok(())
    }
}

pub trait PacketTrait {
    const TYPE_FLAG: u8;
    fn encode_authdata(&self, buf: &mut Vec<u8>) -> Result<(), PacketCodecError>;
    fn get_encoded_message(&self) -> Vec<u8>;

    fn build_header(&self, nonce: &[u8; 12]) -> Result<PacketHeader, PacketCodecError> {
        let mut authdata = Vec::new();
        self.encode_authdata(&mut authdata)?;

        let authdata_size =
            u16::try_from(authdata.len()).map_err(|_| PacketCodecError::InvalidSize)?;

        let mut static_header: [u8; 23] = [0; 23];
        static_header[0..6].copy_from_slice(PROTOCOL_ID);
        static_header[6..8].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        static_header[8] = Self::TYPE_FLAG;
        static_header[9..21].copy_from_slice(nonce);
        static_header[21..].copy_from_slice(&authdata_size.to_be_bytes());
        let header_end_offset = 16 + authdata.len() + static_header.len();
        Ok(PacketHeader {
            static_header,
            flag: Self::TYPE_FLAG,
            nonce: *nonce,
            authdata,
            header_end_offset,
        })
    }

    /// Encodes the packet
    fn encode(
        &self,
        nonce: &[u8; 12],
        masking_iv: [u8; 16],
        encrypt_key: &[u8],
    ) -> Result<Packet, PacketCodecError> {
        if encrypt_key.len() < 16 {
            return Err(PacketCodecError::InvalidSize);
        }
        let header = self.build_header(nonce)?;

        let mut message = self.get_encoded_message();
        let mut message_ad = masking_iv.to_vec();
        message_ad.extend_from_slice(&header.static_header);
        message_ad.extend_from_slice(&header.authdata);

        let mut cipher = Aes128Gcm::new(encrypt_key[..16].into());
        cipher
            .encrypt_in_place(&header.nonce.into(), &message_ad, &mut message)
            .map_err(|e| PacketCodecError::CipherError(e.to_string()))?;

        Ok(Packet {
            masking_iv,
            header,
            encrypted_message: message,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordinary {
    pub src_id: H256,
    pub message: Message,
}

impl PacketTrait for Ordinary {
    const TYPE_FLAG: u8 = 0x00;

    fn encode_authdata(&self, buf: &mut Vec<u8>) -> Result<(), PacketCodecError> {
        buf.extend_from_slice(self.src_id.as_bytes());
        Ok(())
    }

    fn get_encoded_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        self.message.encode(&mut message);
        message
    }
}

impl Ordinary {
    /// Extracts the 32-byte source node id from an ordinary packet's authdata.
    ///
    /// The authdata length is peer-controlled, so this is length-checked: an ordinary packet
    /// carries exactly the 32-byte src-id as authdata, and anything else is rejected rather
    /// than panicking in `H256::from_slice`. Callers that need the src-id before decrypting
    /// (e.g. to look up the session key) must go through here, not `H256::from_slice` directly.
    pub fn src_id(packet: &Packet) -> Result<H256, PacketCodecError> {
        if packet.header.authdata.len() != 32 {
            return Err(PacketCodecError::InvalidSize);
        }
        Ok(H256::from_slice(&packet.header.authdata))
    }

    pub fn decode(packet: &Packet, decrypt_key: &[u8]) -> Result<Ordinary, PacketCodecError> {
        let src_id = Self::src_id(packet)?;

        let mut message = packet.encrypted_message.to_vec();
        decrypt_message(decrypt_key, packet, &mut message)?;

        let message = Message::decode(&message).map_err(|_e| {
            PacketCodecError::InvalidMessage(message.first().copied().unwrap_or(0))
        })?;
        Ok(Ordinary { src_id, message })
    }
}

/// Decrypts a message using AES-128-GCM.
/// The message is decrypted in place.
pub fn decrypt_message(
    key: &[u8],
    packet: &Packet,
    message: &mut Vec<u8>,
) -> Result<(), PacketCodecError> {
    if key.len() < 16 {
        return Err(PacketCodecError::InvalidSize);
    }

    // message-ad = masking-iv || static-header || authdata
    let mut message_ad = packet.masking_iv.to_vec();
    message_ad.extend_from_slice(&packet.header.static_header);
    message_ad.extend_from_slice(&packet.header.authdata);

    let mut cipher = Aes128Gcm::new(key[..16].into());
    cipher
        .decrypt_in_place(packet.header.nonce.as_slice().into(), &message_ad, message)
        .map_err(|e| PacketCodecError::CipherError(e.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoAreYou {
    pub id_nonce: u128,
    pub enr_seq: u64,
}

impl PacketTrait for WhoAreYou {
    const TYPE_FLAG: u8 = 0x01;

    fn encode_authdata(&self, buf: &mut Vec<u8>) -> Result<(), PacketCodecError> {
        buf.extend_from_slice(&self.id_nonce.to_be_bytes());
        buf.extend_from_slice(&self.enr_seq.to_be_bytes());
        Ok(())
    }

    fn get_encoded_message(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Encodes the WhoAreYou packet.
    /// No encryption needed, just an empty message
    fn encode(
        &self,
        nonce: &[u8; 12],
        masking_iv: [u8; 16],
        _encrypt_key: &[u8],
    ) -> Result<Packet, PacketCodecError> {
        Ok(Packet {
            masking_iv,
            header: self.build_header(nonce)?,
            encrypted_message: Vec::new(),
        })
    }
}

impl WhoAreYou {
    pub fn decode(packet: &Packet) -> Result<WhoAreYou, PacketCodecError> {
        // A peer controls the authdata length. WHOAREYOU authdata is exactly a 16-byte
        // id-nonce followed by an 8-byte enr-seq; reject anything else before slicing so a
        // short authdata can't panic on `authdata[..16]`.
        let authdata = &packet.header.authdata;
        if authdata.len() != 24 {
            return Err(PacketCodecError::InvalidSize);
        }
        let id_nonce = u128::from_be_bytes(authdata[..16].try_into()?);
        let enr_seq = u64::from_be_bytes(authdata[16..].try_into()?);

        Ok(WhoAreYou { id_nonce, enr_seq })
    }
}

/// Parsed handshake authdata, used for signature verification and session key derivation
/// before decrypting the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAuthdata {
    pub src_id: H256,
    pub id_signature: Vec<u8>,
    pub eph_pubkey: Vec<u8>,
    pub record: Option<NodeRecord>,
}

impl HandshakeAuthdata {
    /// Decodes the authdata from a handshake packet header.
    /// This can be called before decryption to extract the ephemeral public key
    /// needed for session key derivation.
    pub fn decode(authdata: &[u8]) -> Result<Self, PacketCodecError> {
        if authdata.len() < HANDSHAKE_AUTHDATA_HEAD {
            return Err(PacketCodecError::InvalidSize);
        }

        let src_id = H256::from_slice(&authdata[..32]);
        let sig_size = authdata[32] as usize;
        let eph_key_size = authdata[33] as usize;

        let authdata_head = HANDSHAKE_AUTHDATA_HEAD + sig_size + eph_key_size;
        if authdata.len() < authdata_head {
            return Err(PacketCodecError::InvalidSize);
        }

        let id_signature =
            authdata[HANDSHAKE_AUTHDATA_HEAD..HANDSHAKE_AUTHDATA_HEAD + sig_size].to_vec();

        let eph_key_start = HANDSHAKE_AUTHDATA_HEAD + sig_size;
        let eph_pubkey = authdata[eph_key_start..authdata_head].to_vec();

        let record = if authdata.len() > authdata_head {
            let record_bytes = &authdata[authdata_head..];
            if record_bytes.is_empty() {
                None
            } else {
                Some(NodeRecord::decode(record_bytes)?)
            }
        } else {
            None
        };

        Ok(HandshakeAuthdata {
            src_id,
            id_signature,
            eph_pubkey,
            record,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub src_id: H256,
    pub id_signature: Vec<u8>,
    pub eph_pubkey: Vec<u8>,
    /// The record field may be omitted if the enr-seq of WHOAREYOU is recent enough, i.e. when it matches the current sequence number of the sending node.
    /// If enr-seq is zero, the record must be sent.
    pub record: Option<NodeRecord>,
    pub message: Message,
}

impl PacketTrait for Handshake {
    const TYPE_FLAG: u8 = 0x02;

    fn encode_authdata(&self, buf: &mut Vec<u8>) -> Result<(), PacketCodecError> {
        let sig_size: u8 = self
            .id_signature
            .len()
            .try_into()
            .map_err(|_| PacketCodecError::InvalidSize)?;
        let eph_key_size: u8 = self
            .eph_pubkey
            .len()
            .try_into()
            .map_err(|_| PacketCodecError::InvalidSize)?;

        buf.extend_from_slice(self.src_id.as_bytes());
        buf.push(sig_size);
        buf.push(eph_key_size);
        buf.extend_from_slice(&self.id_signature);
        buf.extend_from_slice(&self.eph_pubkey);
        if let Some(record) = &self.record {
            record.encode(buf);
        }

        Ok(())
    }

    fn get_encoded_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        self.message.encode(&mut message);
        message
    }
}

impl Handshake {
    /// Decodes a handshake packet, including decrypting the message.
    pub fn decode(packet: &Packet, decrypt_key: &[u8]) -> Result<Handshake, PacketCodecError> {
        let authdata = HandshakeAuthdata::decode(&packet.header.authdata)?;

        let mut encrypted = packet.encrypted_message.to_vec();
        decrypt_message(decrypt_key, packet, &mut encrypted)?;
        let message = Message::decode(&encrypted)?;

        Ok(Handshake {
            src_id: authdata.src_id,
            id_signature: authdata.id_signature,
            eph_pubkey: authdata.eph_pubkey,
            record: authdata.record,
            message,
        })
    }

    /// Creates a Handshake from pre-parsed authdata and a decrypted message.
    /// Useful when authdata was already parsed for signature verification.
    pub fn from_authdata(authdata: HandshakeAuthdata, message: Message) -> Self {
        Handshake {
            src_id: authdata.src_id,
            id_signature: authdata.id_signature,
            eph_pubkey: authdata.eph_pubkey,
            record: authdata.record,
            message,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Message {
    Ping(PingMessage),
    Pong(PongMessage),
    FindNode(FindNodeMessage),
    Nodes(NodesMessage),
    TalkReq(TalkReqMessage),
    TalkRes(TalkResMessage),
    Ticket(TicketMessage),
    // TODO: add the other messages
}

impl Message {
    /// Returns a short, stable label suitable for use as a Prometheus metric label value.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Message::Ping(_) => "Ping",
            Message::Pong(_) => "Pong",
            Message::FindNode(_) => "FindNode",
            Message::Nodes(_) => "Nodes",
            Message::TalkReq(_) => "TalkReq",
            Message::TalkRes(_) => "TalkRes",
            Message::Ticket(_) => "Ticket",
        }
    }

    fn msg_type(&self) -> u8 {
        match self {
            Message::Ping(_) => 0x01,
            Message::Pong(_) => 0x02,
            Message::FindNode(_) => 0x03,
            Message::Nodes(_) => 0x04,
            Message::TalkReq(_) => 0x05,
            Message::TalkRes(_) => 0x06,
            Message::Ticket(_) => 0x08,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.msg_type());
        match self {
            Message::Ping(ping) => ping.encode(buf),
            Message::Pong(pong) => pong.encode(buf),
            Message::FindNode(find_node) => find_node.encode(buf),
            Message::Nodes(nodes) => nodes.encode(buf),
            Message::TalkReq(talk_req) => talk_req.encode(buf),
            Message::TalkRes(talk_res) => talk_res.encode(buf),
            Message::Ticket(ticket) => ticket.encode(buf),
        }
    }

    pub fn decode(message: &[u8]) -> Result<Message, RLPDecodeError> {
        let &message_type = message.first().ok_or(RLPDecodeError::InvalidLength)?;
        match message_type {
            0x01 => {
                let ping = PingMessage::decode(&message[1..])?;
                Ok(Message::Ping(ping))
            }
            0x02 => {
                let pong = PongMessage::decode(&message[1..])?;
                Ok(Message::Pong(pong))
            }
            0x03 => {
                let find_node_msg = FindNodeMessage::decode(&message[1..])?;
                Ok(Message::FindNode(find_node_msg))
            }
            0x04 => {
                let nodes_msg = NodesMessage::decode(&message[1..])?;
                Ok(Message::Nodes(nodes_msg))
            }
            0x05 => {
                let talk_req_msg = TalkReqMessage::decode(&message[1..])?;
                Ok(Message::TalkReq(talk_req_msg))
            }
            0x06 => {
                let enr_response_msg = TalkResMessage::decode(&message[1..])?;
                Ok(Message::TalkRes(enr_response_msg))
            }
            0x08 => {
                let ticket_msg = TicketMessage::decode(&message[1..])?;
                Ok(Message::Ticket(ticket_msg))
            }
            _ => Err(RLPDecodeError::MalformedData),
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Ping(_) => write!(f, "Ping"),
            Message::Pong(_) => write!(f, "Pong"),
            Message::FindNode(_) => write!(f, "FindNode"),
            Message::Nodes(_) => write!(f, "Nodes"),
            Message::TalkReq(_) => write!(f, "TalkReq"),
            Message::TalkRes(_) => write!(f, "TalkRes"),
            Message::Ticket(_) => write!(f, "Ticket"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingMessage {
    /// The request id of the sender.
    pub req_id: Bytes,
    /// The ENR sequence number of the sender.
    pub enr_seq: u64,
}

impl PingMessage {
    pub fn new(req_id: Bytes, enr_seq: u64) -> Self {
        Self { req_id, enr_seq }
    }
}

impl RLPEncode for PingMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&self.enr_seq)
            .finish();
    }
}

impl RLPDecode for PingMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (req_id, decoder) = decoder.decode_field("req_id")?;
        let (enr_seq, decoder) = decoder.decode_field("enr_seq")?;
        let ping = PingMessage { req_id, enr_seq };
        Ok((ping, decoder.finish()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongMessage {
    pub req_id: Bytes,
    pub enr_seq: u64,
    pub recipient_addr: SocketAddr,
}

impl RLPEncode for PongMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&self.enr_seq)
            .encode_field(&self.recipient_addr.ip())
            .encode_field(&self.recipient_addr.port())
            .finish();
    }
}

impl RLPDecode for PongMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        use std::net::IpAddr;
        let decoder = Decoder::new(rlp)?;
        let (req_id, decoder) = decoder.decode_field("req_id")?;
        let (enr_seq, decoder) = decoder.decode_field("enr_seq")?;
        let (recipient_ip, decoder): (IpAddr, _) = decoder.decode_field("recipient_ip")?;
        let (recipient_port, decoder): (u16, _) = decoder.decode_field("recipient_port")?;

        Ok((
            Self {
                req_id,
                enr_seq,
                recipient_addr: SocketAddr::new(recipient_ip, recipient_port),
            },
            decoder.finish()?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNodeMessage {
    pub req_id: Bytes,
    pub distances: Vec<u32>,
}

impl RLPEncode for FindNodeMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&self.distances)
            .finish();
    }
}

impl RLPDecode for FindNodeMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (req_id, decoder) = decoder.decode_field("req_id")?;
        let (distance, decoder) = decoder.decode_field("distance")?;

        Ok((
            Self {
                req_id,
                distances: distance,
            },
            decoder.finish()?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodesMessage {
    pub req_id: Bytes,
    pub total: u64,
    pub nodes: Vec<NodeRecord>,
}

impl RLPEncode for NodesMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&self.total)
            .encode_field(&self.nodes)
            .finish();
    }
}

impl RLPDecode for NodesMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (req_id, decoder) = decoder.decode_field("req_id")?;
        let (total, decoder) = decoder.decode_field("total")?;
        let (nodes, decoder) = decoder.decode_field("nodes")?;

        Ok((
            Self {
                req_id,
                total,
                nodes,
            },
            decoder.finish()?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TalkReqMessage {
    pub req_id: Bytes,
    pub protocol: Bytes,
    pub request: Bytes,
}

impl RLPEncode for TalkReqMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&self.protocol)
            .encode_field(&self.request)
            .finish();
    }
}

impl RLPDecode for TalkReqMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (req_id, decoder) = decoder.decode_field("req_id")?;
        let (protocol, decoder) = decoder.decode_field("protocol")?;
        let (request, decoder) = decoder.decode_field("request")?;

        Ok((
            Self {
                req_id,
                protocol,
                request,
            },
            decoder.finish()?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TalkResMessage {
    pub req_id: Bytes,
    pub response: Vec<u8>,
}

impl RLPEncode for TalkResMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&Bytes::copy_from_slice(&self.response))
            .finish();
    }
}

impl RLPDecode for TalkResMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let ((req_id, response), remaining) =
            <(Bytes, Bytes) as RLPDecode>::decode_unfinished(rlp)?;

        Ok((
            Self {
                req_id,
                response: response.to_vec(),
            },
            remaining,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketMessage {
    pub req_id: Bytes,
    pub ticket: Bytes,
    pub wait_time: u64,
}

impl RLPEncode for TicketMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.req_id)
            .encode_field(&self.ticket)
            .encode_field(&self.wait_time)
            .finish();
    }
}

impl RLPDecode for TicketMessage {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (req_id, decoder) = decoder.decode_field("req_id")?;
        let (ticket, decoder) = decoder.decode_field("ticket")?;
        let (wait_time, decoder) = decoder.decode_field("wait_time")?;

        Ok((
            Self {
                req_id,
                ticket,
                wait_time,
            },
            decoder.finish()?,
        ))
    }
}

#[cfg(test)]
mod authdata_tests {
    use super::*;

    fn packet_with_authdata(flag: u8, authdata: Vec<u8>) -> Packet {
        Packet {
            masking_iv: [0u8; IV_MASKING_SIZE],
            header: PacketHeader {
                static_header: [0u8; STATIC_HEADER_SIZE],
                flag,
                nonce: [0u8; 12],
                authdata,
                header_end_offset: 0,
            },
            encrypted_message: Vec::new(),
        }
    }

    /// A WHOAREYOU packet needs 24 authdata bytes (16-byte id-nonce + 8-byte enr-seq). A peer
    /// can forge a shorter one; decoding must return an error, not panic on `authdata[..16]`.
    #[test]
    fn who_are_you_decode_rejects_short_authdata() {
        let packet = packet_with_authdata(WhoAreYou::TYPE_FLAG, vec![0u8; 8]);
        assert!(
            matches!(
                WhoAreYou::decode(&packet),
                Err(PacketCodecError::InvalidSize)
            ),
            "short WHOAREYOU authdata must be rejected, not panic"
        );
    }

    /// The length check is exact (`!= 24`), so over-length authdata is rejected too — a peer
    /// can't smuggle trailing bytes past `authdata[16..]`.
    #[test]
    fn who_are_you_decode_rejects_over_length_authdata() {
        let packet = packet_with_authdata(WhoAreYou::TYPE_FLAG, vec![0u8; 32]);
        assert!(
            matches!(
                WhoAreYou::decode(&packet),
                Err(PacketCodecError::InvalidSize)
            ),
            "over-length WHOAREYOU authdata must be rejected"
        );
    }

    /// The ordinary-packet handler reads the 32-byte source id straight from `authdata` before
    /// the session lookup; a peer can send authdata of any length, so extracting the id must be
    /// length-checked rather than panicking in `H256::from_slice`.
    #[test]
    fn ordinary_src_id_rejects_short_authdata() {
        let packet = packet_with_authdata(Ordinary::TYPE_FLAG, vec![0u8; 8]);
        assert!(
            matches!(
                Ordinary::src_id(&packet),
                Err(PacketCodecError::InvalidSize)
            ),
            "short ordinary authdata must be rejected, not panic"
        );
    }

    /// A well-formed 32-byte ordinary authdata still yields the src id.
    #[test]
    fn ordinary_src_id_accepts_32_byte_authdata() {
        let packet = packet_with_authdata(Ordinary::TYPE_FLAG, vec![7u8; 32]);
        let src_id = Ordinary::src_id(&packet).expect("32-byte authdata must decode");
        assert_eq!(src_id, H256::from_slice(&[7u8; 32]));
    }
}
