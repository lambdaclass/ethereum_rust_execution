use super::{
    message::RLPxMessage,
    utils::{decompress_pubkey, snappy_compress},
};
use crate::rlpx::utils::{compress_pubkey, snappy_decompress};
use ethrex_common::H512;
use ethrex_rlp::structs::{Decoder, Encoder};
use ethrex_rlp::{
    decode::{RLPDecode, decode_rlp_item},
    encode::RLPEncode,
    error::{RLPDecodeError, RLPEncodeError},
};
use secp256k1::PublicKey;
use serde::Serialize;

pub const SUPPORTED_ETH_CAPABILITIES: [Capability; 5] = [
    Capability::eth(68),
    Capability::eth(69),
    Capability::eth(70),
    Capability::eth(71),
    Capability::eth(72),
];
pub const SUPPORTED_SNAP_CAPABILITIES: [Capability; 1] = [Capability::snap(1)];

/// The version of the base P2P protocol we support.
/// This is sent at the start of the Hello message instead of the capabilities list.
pub const SUPPORTED_P2P_CAPABILITY_VERSION: u8 = 5;

const CAPABILITY_NAME_MAX_LENGTH: usize = 8;

// Pads the input array to the right with zeros to ensure it is 8 bytes long.
// Panics if the input is longer than 8 bytes.
const fn pad_right<const N: usize>(input: &[u8; N]) -> [u8; 8] {
    assert!(
        N <= CAPABILITY_NAME_MAX_LENGTH,
        "Input array must be 8 bytes or less"
    );

    let mut padded = [0_u8; CAPABILITY_NAME_MAX_LENGTH];
    let mut i = 0;
    while i < input.len() {
        padded[i] = input[i];
        i += 1;
    }
    padded
}

#[derive(Debug, Clone, PartialEq)]
/// A capability is identified by a short ASCII name (max eight characters) and version number
pub struct Capability {
    protocol: [u8; CAPABILITY_NAME_MAX_LENGTH],
    pub version: u8,
}

impl Capability {
    pub const fn eth(version: u8) -> Self {
        Capability {
            protocol: pad_right(b"eth"),
            version,
        }
    }

    pub const fn snap(version: u8) -> Self {
        Capability {
            protocol: pad_right(b"snap"),
            version,
        }
    }

    pub const fn based(version: u8) -> Self {
        Capability {
            protocol: pad_right(b"based"),
            version,
        }
    }

    pub fn protocol(&self) -> &str {
        let len = self
            .protocol
            .iter()
            .position(|c| c == &b'\0')
            .unwrap_or(CAPABILITY_NAME_MAX_LENGTH);
        str::from_utf8(&self.protocol[..len]).expect("value parsed as utf8 in RLPDecode")
    }
}

impl RLPEncode for Capability {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.protocol())
            .encode_field(&self.version)
            .finish();
    }
}

impl RLPDecode for Capability {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let (protocol_name, rest) = String::decode_unfinished(&rlp[1..])?;
        if protocol_name.len() > CAPABILITY_NAME_MAX_LENGTH {
            return Err(RLPDecodeError::InvalidLength);
        }
        let (version, rest) = u8::decode_unfinished(rest)?;
        let mut protocol = [0; CAPABILITY_NAME_MAX_LENGTH];
        protocol[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
        Ok((Capability { protocol, version }, rest))
    }
}

impl Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}/{}", self.protocol(), self.version))
    }
}

#[derive(Debug, Clone)]
pub struct HelloMessage {
    pub capabilities: Vec<Capability>,
    pub node_id: PublicKey,
    pub client_id: String,
}

impl HelloMessage {
    pub fn new(capabilities: Vec<Capability>, node_id: PublicKey, client_id: String) -> Self {
        Self {
            capabilities,
            node_id,
            client_id,
        }
    }
}

impl RLPxMessage for HelloMessage {
    const CODE: u8 = 0x00;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        Encoder::new(buf)
            .encode_field(&SUPPORTED_P2P_CAPABILITY_VERSION) // protocolVersion
            .encode_field(&self.client_id) // clientId
            .encode_field(&self.capabilities) // capabilities
            .encode_field(&0u8) // listenPort (ignored)
            .encode_field(&decompress_pubkey(&self.node_id)) // nodeKey
            .finish();
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        // decode hello message: [protocolVersion: P, clientId: B, capabilities, listenPort: P, nodeId: B_64, ...]
        let decoder = Decoder::new(msg_data)?;
        let (protocol_version, decoder): (u64, _) = decoder.decode_field("protocolVersion")?;

        if protocol_version != SUPPORTED_P2P_CAPABILITY_VERSION as u64 {
            return Err(RLPDecodeError::IncompatibleProtocol(format!(
                "Received message is encoded in p2p version {} when negotiated p2p version was {} ",
                protocol_version, SUPPORTED_P2P_CAPABILITY_VERSION
            )));
        }

        let (client_id, decoder): (String, _) = decoder.decode_field("clientId")?;

        // [[cap1, capVersion1], [cap2, capVersion2], ...]
        let (capabilities, decoder): (Vec<Capability>, _) = decoder.decode_field("capabilities")?;

        // This field should be ignored
        let (_listen_port, decoder): (u16, _) = decoder.decode_field("listenPort")?;

        let (node_id, decoder): (H512, _) = decoder.decode_field("nodeId")?;

        // Implementations must ignore any additional list elements
        let _padding = decoder.finish_unchecked();

        Ok(Self::new(
            capabilities,
            compress_pubkey(node_id).ok_or(RLPDecodeError::MalformedData)?,
            client_id,
        ))
    }
}

// Create disconnectreason enum
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisconnectReason {
    DisconnectRequested = 0x00,
    NetworkError = 0x01,
    ProtocolError = 0x02,
    UselessPeer = 0x03,
    TooManyPeers = 0x04,
    AlreadyConnected = 0x05,
    IncompatibleVersion = 0x06,
    InvalidIdentity = 0x07,
    ClientQuitting = 0x08,
    UnexpectedIdentity = 0x09,
    SelfIdentity = 0x0a,
    PingTimeout = 0x0b,
    SubprotocolError = 0x10,
    InvalidReason = 0xff,
}

impl DisconnectReason {
    // Returns a vector of all DisconnectReason variants, we need to update this method when we add,
    // change or remove any DisconnectReason variants which are used in metrics.
    // A test ensures this method is up to date.
    pub fn all() -> Vec<DisconnectReason> {
        vec![
            DisconnectReason::DisconnectRequested,
            DisconnectReason::NetworkError,
            DisconnectReason::ProtocolError,
            DisconnectReason::UselessPeer,
            DisconnectReason::TooManyPeers,
            DisconnectReason::AlreadyConnected,
            DisconnectReason::IncompatibleVersion,
            DisconnectReason::InvalidIdentity,
            DisconnectReason::ClientQuitting,
            DisconnectReason::UnexpectedIdentity,
            DisconnectReason::SelfIdentity,
            DisconnectReason::PingTimeout,
            DisconnectReason::SubprotocolError,
            DisconnectReason::InvalidReason,
        ]
    }
}

// impl display for disconnectreason
impl std::fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisconnectReason::DisconnectRequested => write!(f, "Disconnect Requested"),
            DisconnectReason::NetworkError => write!(f, "TCP Subsystem Error"),
            DisconnectReason::ProtocolError => write!(f, "Breach of Protocol"),
            DisconnectReason::UselessPeer => write!(f, "Useless Peer"),
            DisconnectReason::TooManyPeers => write!(f, "Too Many Peers"),
            DisconnectReason::AlreadyConnected => write!(f, "Already Connected"),
            DisconnectReason::IncompatibleVersion => {
                write!(f, "Incompatible P2P Protocol Version")
            }
            DisconnectReason::InvalidIdentity => write!(f, "Null Node Identity Received"),
            DisconnectReason::ClientQuitting => write!(f, "Client Quitting"),
            DisconnectReason::UnexpectedIdentity => {
                write!(f, "Unexpected Identity in Handshake")
            }
            DisconnectReason::SelfIdentity => {
                write!(f, "Identity is the Same as This Node")
            }
            DisconnectReason::PingTimeout => write!(f, "Ping Timeout"),
            DisconnectReason::SubprotocolError => {
                write!(f, "Some Other Reason Specific to a Subprotocol")
            }
            DisconnectReason::InvalidReason => write!(f, "Invalid Disconnect Reason"),
        }
    }
}

impl From<u8> for DisconnectReason {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DisconnectReason::DisconnectRequested,
            0x01 => DisconnectReason::NetworkError,
            0x02 => DisconnectReason::ProtocolError,
            0x03 => DisconnectReason::UselessPeer,
            0x04 => DisconnectReason::TooManyPeers,
            0x05 => DisconnectReason::AlreadyConnected,
            0x06 => DisconnectReason::IncompatibleVersion,
            0x07 => DisconnectReason::InvalidIdentity,
            0x08 => DisconnectReason::ClientQuitting,
            0x09 => DisconnectReason::UnexpectedIdentity,
            0x0a => DisconnectReason::SelfIdentity,
            0x0b => DisconnectReason::PingTimeout,
            0x10 => DisconnectReason::SubprotocolError,
            _ => DisconnectReason::InvalidReason,
        }
    }
}

impl From<DisconnectReason> for u8 {
    fn from(val: DisconnectReason) -> Self {
        val as u8
    }
}
#[derive(Debug, Clone)]
pub struct DisconnectMessage {
    pub reason: Option<DisconnectReason>,
}

impl DisconnectMessage {
    pub fn new(reason: Option<DisconnectReason>) -> Self {
        Self { reason }
    }

    /// Returns the meaning of the disconnect reason's error code
    /// The meaning of each error code is defined by the spec: https://github.com/ethereum/devp2p/blob/master/rlpx.md#disconnect-0x01
    pub fn reason(&self) -> DisconnectReason {
        self.reason.unwrap_or(DisconnectReason::InvalidReason)
    }
}

impl RLPxMessage for DisconnectMessage {
    const CODE: u8 = 0x01;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        // Disconnect msg_data is reason or none
        match self.reason.map(Into::<u8>::into) {
            Some(value) => Encoder::new(&mut encoded_data)
                .encode_field(&value)
                .finish(),
            None => Vec::<u8>::new().encode(&mut encoded_data),
        }
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        // decode disconnect message: [reason (optional)]
        // The msg data may be compressed or not
        let msg_data = if let Ok(decompressed) = snappy_decompress(msg_data) {
            decompressed
        } else {
            msg_data.to_vec()
        };
        // It seems that disconnect reason can be encoded in different ways:
        let reason = match msg_data.len() {
            0 => None,
            // As a single u8
            1 => Some(msg_data[0]),
            // As an RLP encoded Vec<u8>
            _ => {
                let decoder = Decoder::new(&msg_data)?;
                let (reason, _): (Option<u8>, _) = decoder.decode_optional_field();
                reason
            }
        };

        Ok(Self::new(reason.map(|r| r.into())))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PingMessage {}

impl RLPxMessage for PingMessage {
    const CODE: u8 = 0x02;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        // Ping msg_data is only []
        Vec::<u8>::new().encode(&mut encoded_data);
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        // decode ping message: data is empty list [] or string but it is snappy compressed
        let decompressed_data = snappy_decompress(msg_data)?;
        let (_, payload, remaining) = decode_rlp_item(&decompressed_data)?;

        let empty: &[u8] = &[];
        assert_eq!(payload, empty, "Ping payload should be &[]");
        assert_eq!(remaining, empty, "Ping remaining should be &[]");
        Ok(Self {})
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PongMessage {}

impl RLPxMessage for PongMessage {
    const CODE: u8 = 0x03;
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), RLPEncodeError> {
        let mut encoded_data = vec![];
        // Pong msg_data is only []
        Vec::<u8>::new().encode(&mut encoded_data);
        let msg_data = snappy_compress(encoded_data)?;
        buf.extend_from_slice(&msg_data);
        Ok(())
    }

    fn decode(msg_data: &[u8]) -> Result<Self, RLPDecodeError> {
        // decode pong message: data is empty list [] or string but it is snappy compressed
        let decompressed_data = snappy_decompress(msg_data)?;
        let (_, payload, remaining) = decode_rlp_item(&decompressed_data)?;

        let empty: &[u8] = &[];
        assert_eq!(payload, empty, "Pong payload should be &[]");
        assert_eq!(remaining, empty, "Pong remaining should be &[]");
        Ok(Self {})
    }
}
