use super::{
    codec::RLPxCodec,
    server::{Initiator, Receiver},
};
#[cfg(feature = "l2")]
use crate::rlpx::l2::l2_connection::L2ConnState;
use crate::{
    rlpx::{
        connection::server::{ConnectionState, Established},
        error::PeerConnectionError,
        message::EthCapVersion,
        utils::{compress_pubkey, decompress_pubkey, ecdh_xchng, kdf, sha256, sha256_hmac},
    },
    types::Node,
};
use aes::cipher::{KeyIvInit, StreamCipher};
use ethrex_common::{H128, H256, H512, Signature};
use ethrex_crypto::keccak::keccak_hash;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use futures::{StreamExt, stream::SplitStream};
use rand::Rng;
use secp256k1::{
    PublicKey, SecretKey,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};
use tokio_util::codec::Framed;
use tracing::{debug, trace};

type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

// https://github.com/ethereum/go-ethereum/blob/master/p2p/peer.go#L44
pub const P2P_MAX_MESSAGE_SIZE: usize = 2048;

pub(crate) struct RemoteState {
    pub(crate) public_key: H512,
    pub(crate) nonce: H256,
    pub(crate) ephemeral_key: PublicKey,
    pub(crate) init_message: Vec<u8>,
}

pub(crate) struct LocalState {
    pub(crate) nonce: H256,
    pub(crate) ephemeral_key: SecretKey,
    pub(crate) init_message: Vec<u8>,
}

pub(crate) async fn perform(
    state: ConnectionState,
    eth_version: Arc<RwLock<EthCapVersion>>,
) -> Result<(Established, SplitStream<Framed<TcpStream, RLPxCodec>>), PeerConnectionError> {
    let (context, node, framed, is_inbound) = match state {
        ConnectionState::Initiator(Initiator { context, node }) => {
            let addr = SocketAddr::new(node.ip, node.tcp_port);
            let mut stream = match tcp_stream(addr).await {
                Ok(result) => result,
                Err(error) => {
                    // If we can't find a TCP connection it's an issue we should track in debug
                    debug!(peer=%node, %error, "Error creating tcp connection");
                    return Err(error)?;
                }
            };
            let local_state = send_auth(&context.signer, node.public_key, &mut stream).await?;
            let remote_state = receive_ack(&context.signer, node.public_key, &mut stream).await?;
            // Local node is initator
            // keccak256(nonce || initiator-nonce)
            let hashed_nonces: [u8; 32] =
                keccak_hash([remote_state.nonce.0, local_state.nonce.0].concat());
            let codec = RLPxCodec::new(&local_state, &remote_state, hashed_nonces, eth_version)?;
            trace!(peer=%node, "Completed handshake as initiator");
            (context, node, Framed::new(stream, codec), false)
        }
        ConnectionState::Receiver(Receiver {
            context,
            peer_addr,
            stream,
        }) => {
            let Some(mut stream) = Arc::into_inner(stream) else {
                return Err(PeerConnectionError::StateError(
                    "Cannot use the stream".to_string(),
                ));
            };
            let remote_state = receive_auth(&context.signer, &mut stream).await?;
            let local_state = send_ack(remote_state.public_key, &mut stream).await?;
            // Remote node is initiator
            // keccak256(nonce || initiator-nonce)
            let hashed_nonces: [u8; 32] =
                keccak_hash([local_state.nonce.0, remote_state.nonce.0].concat());
            let codec = RLPxCodec::new(&local_state, &remote_state, hashed_nonces, eth_version)?;
            let node = Node::new(
                peer_addr.ip(),
                peer_addr.port(),
                peer_addr.port(),
                remote_state.public_key,
            );
            trace!(peer=%node, "Completed handshake as receiver");
            (context, node, Framed::new(stream, codec), true)
        }
        ConnectionState::Established(_) => {
            return Err(PeerConnectionError::StateError(
                "Already established".to_string(),
            ));
        }
        // Shouldn't perform a Handshake on an already failed connection.
        // Put it here to complete the match arms
        ConnectionState::HandshakeFailed => {
            return Err(PeerConnectionError::StateError(
                "Handshake Failed".to_string(),
            ));
        }
    };
    let (sink, stream) = framed.split();
    // Move the socket sink into a dedicated writer task; the actor keeps only a bounded
    // sender, so it never blocks on a slow peer's network write (see `spawn_outbound_writer`).
    let (outbound_tx, outbound_writer_timed_out) =
        crate::rlpx::connection::server::spawn_outbound_writer(sink);
    Ok((
        Established {
            signer: context.signer,
            outbound_tx,
            outbound_writer_timed_out,
            node,
            is_inbound,
            storage: context.storage.clone(),
            blockchain: context.blockchain.clone(),
            capabilities: vec![],
            negotiated_eth_capability: None,
            negotiated_snap_capability: None,
            last_block_range_update_block: 0,
            requested_pooled_txs: HashMap::new(),
            requested_pooled_txs_72: HashMap::new(),
            pending_tx_requests: Vec::new(),
            pending_tx_requests_72: Vec::new(),
            pending_cell_requests: Vec::new(),
            requested_cells: HashMap::new(),
            last_custody_generation: 0,
            client_version: context.client_version.clone(),
            connection_broadcast_send: context.broadcast.clone(),
            peer_table: context.table.clone(),
            discovery: context.discovery.clone(),
            #[cfg(feature = "l2")]
            l2_state: context
                .based_context
                .map_or_else(|| L2ConnState::Unsupported, L2ConnState::Disconnected),
            tx_broadcaster: context.tx_broadcaster,
            current_requests: HashMap::new(),
            disconnect_reason: None,
            is_validated: false,
            registered: false,
            serve_request_window_start: std::time::Instant::now(),
            serve_requests_in_window: 0,
            txs_sent_to_peer: 0,
            received_txs_from_peer: false,
            missed_pongs: 0,
        },
        stream,
    ))
}

async fn tcp_stream(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?.connect(addr).await,
        SocketAddr::V6(_) => TcpSocket::new_v6()?.connect(addr).await,
    }
}

async fn send_auth<S: AsyncWrite + std::marker::Unpin>(
    signer: &SecretKey,
    remote_public_key: H512,
    mut stream: S,
) -> Result<LocalState, PeerConnectionError> {
    let peer_pk =
        compress_pubkey(remote_public_key).ok_or_else(|| PeerConnectionError::InvalidPeerId)?;

    let local_nonce = H256::random_using(&mut rand::thread_rng());
    let local_ephemeral_key = SecretKey::new(&mut rand::thread_rng());

    let msg = encode_auth_message(signer, local_nonce, &peer_pk, &local_ephemeral_key)?;
    stream.write_all(&msg).await?;

    Ok(LocalState {
        nonce: local_nonce,
        ephemeral_key: local_ephemeral_key,
        init_message: msg,
    })
}

async fn send_ack<S: AsyncWrite + std::marker::Unpin>(
    remote_public_key: H512,
    mut stream: S,
) -> Result<LocalState, PeerConnectionError> {
    let peer_pk =
        compress_pubkey(remote_public_key).ok_or_else(|| PeerConnectionError::InvalidPeerId)?;

    let local_nonce = H256::random_using(&mut rand::thread_rng());
    let local_ephemeral_key = SecretKey::new(&mut rand::thread_rng());

    let msg = encode_ack_message(&local_ephemeral_key, local_nonce, &peer_pk)?;
    stream.write_all(&msg).await?;

    Ok(LocalState {
        nonce: local_nonce,
        ephemeral_key: local_ephemeral_key,
        init_message: msg,
    })
}

async fn receive_auth<S: AsyncRead + std::marker::Unpin>(
    signer: &SecretKey,
    stream: S,
) -> Result<RemoteState, PeerConnectionError> {
    let msg_bytes = receive_handshake_msg(stream).await?;
    let size_data = &msg_bytes
        .get(..2)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;
    let msg = &msg_bytes
        .get(2..)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;
    let (auth, remote_ephemeral_key) = decode_auth_message(signer, msg, size_data)?;

    Ok(RemoteState {
        public_key: auth.public_key,
        nonce: auth.nonce,
        ephemeral_key: remote_ephemeral_key,
        init_message: msg_bytes,
    })
}

async fn receive_ack<S: AsyncRead + std::marker::Unpin>(
    signer: &SecretKey,
    remote_public_key: H512,
    stream: S,
) -> Result<RemoteState, PeerConnectionError> {
    let msg_bytes = receive_handshake_msg(stream).await?;
    let size_data = &msg_bytes
        .get(..2)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;
    let msg = &msg_bytes
        .get(2..)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;
    let ack = decode_ack_message(signer, msg, size_data)?;
    let remote_ephemeral_key = ack
        .get_ephemeral_pubkey()
        .ok_or_else(|| PeerConnectionError::NotFound("Remote ephemeral key".to_string()))?;

    Ok(RemoteState {
        public_key: remote_public_key,
        nonce: ack.nonce,
        ephemeral_key: remote_ephemeral_key,
        init_message: msg_bytes,
    })
}

async fn receive_handshake_msg<S: AsyncRead + std::marker::Unpin>(
    mut stream: S,
) -> Result<Vec<u8>, PeerConnectionError> {
    let mut buf = vec![0; 2];

    // Read the message's size
    stream.read_exact(&mut buf).await?;
    let ack_data = [buf[0], buf[1]];
    let msg_size = u16::from_be_bytes(ack_data) as usize;
    if msg_size > P2P_MAX_MESSAGE_SIZE {
        return Err(PeerConnectionError::InvalidMessageLength);
    }
    buf.resize(msg_size + 2, 0);

    // Read the rest of the message
    stream.read_exact(&mut buf[2..]).await?;
    Ok(buf)
}

/// Encodes an Auth message, to start a handshake.
fn encode_auth_message(
    static_key: &SecretKey,
    local_nonce: H256,
    remote_static_pubkey: &PublicKey,
    local_ephemeral_key: &SecretKey,
) -> Result<Vec<u8>, PeerConnectionError> {
    let public_key = decompress_pubkey(&static_key.public_key(secp256k1::SECP256K1));

    // Derive a shared secret from the static keys.
    let static_shared_secret = ecdh_xchng(static_key, remote_static_pubkey).map_err(|error| {
        PeerConnectionError::CryptographyError(format!(
            "Invalid generated static shared secret: {error}"
        ))
    })?;

    // Create the signature included in the message.
    let signature = sign_shared_secret(
        static_shared_secret.into(),
        local_nonce,
        local_ephemeral_key,
    )?;

    // Compose the auth message.
    let auth = AuthMessage::new(signature, public_key, local_nonce);

    // RLP-encode the message.
    let encoded_auth_msg = auth.encode_to_vec();

    encrypt_message(remote_static_pubkey, encoded_auth_msg)
}

/// Decodes an incomming Auth message, starting a handshake.
fn decode_auth_message(
    static_key: &SecretKey,
    msg: &[u8],
    auth_data: &[u8],
) -> Result<(AuthMessage, PublicKey), PeerConnectionError> {
    let payload = decrypt_message(static_key, msg, auth_data)?;

    // RLP-decode the message.
    let (auth, _padding) = AuthMessage::decode_unfinished(&payload)?;

    // Derive a shared secret from the static keys.
    let peer_pk =
        compress_pubkey(auth.public_key).ok_or_else(|| PeerConnectionError::InvalidPeerId)?;
    let static_shared_secret = ecdh_xchng(static_key, &peer_pk).map_err(|error| {
        PeerConnectionError::CryptographyError(format!(
            "Invalid generated static shared secret: {error}"
        ))
    })?;
    let remote_ephemeral_key =
        retrieve_remote_ephemeral_key(static_shared_secret.into(), auth.nonce, auth.signature)?;
    Ok((auth, remote_ephemeral_key))
}

/// Encodes an Ack message, to complete a handshake
fn encode_ack_message(
    local_ephemeral_key: &SecretKey,
    local_nonce: H256,
    remote_static_pubkey: &PublicKey,
) -> Result<Vec<u8>, PeerConnectionError> {
    // Compose the ack message.
    let ack_msg = AckMessage::new(
        decompress_pubkey(&local_ephemeral_key.public_key(secp256k1::SECP256K1)),
        local_nonce,
    );

    // RLP-encode the message.
    let encoded_ack_msg = ack_msg.encode_to_vec();

    encrypt_message(remote_static_pubkey, encoded_ack_msg)
}

/// Decodes an Ack message, completing a handshake.
pub fn decode_ack_message(
    static_key: &SecretKey,
    msg: &[u8],
    auth_data: &[u8],
) -> Result<AckMessage, PeerConnectionError> {
    let payload = decrypt_message(static_key, msg, auth_data)?;

    // RLP-decode the message.
    let (ack, _padding) = AckMessage::decode_unfinished(&payload)?;

    Ok(ack)
}

fn decrypt_message(
    static_key: &SecretKey,
    msg: &[u8],
    size_data: &[u8],
) -> Result<Vec<u8>, PeerConnectionError> {
    // Split the message into its components. General layout is:
    // public-key (65) || iv (16) || ciphertext || mac (32)
    let (pk, rest) = msg
        .split_at_checked(65)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;
    let (iv, rest) = rest
        .split_at_checked(16)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;
    let (c, d) = rest
        .split_at_checked(rest.len() - 32)
        .ok_or_else(|| PeerConnectionError::InvalidMessageLength)?;

    // Derive the message shared secret.
    let shared_secret = ecdh_xchng(static_key, &PublicKey::from_slice(pk)?).map_err(|error| {
        PeerConnectionError::CryptographyError(format!("Invalid generated shared secret: {error}"))
    })?;
    // Derive the AES and MAC keys from the message shared secret.
    let mut buf = [0; 32];
    kdf(&shared_secret, &mut buf).map_err(|error| {
        PeerConnectionError::CryptographyError(format!(
            "Couldn't get keys from shared secret: {error}"
        ))
    })?;
    let aes_key = &buf[..16];
    let mac_key = sha256(&buf[16..]);

    // Verify the MAC.
    let expected_d = sha256_hmac(&mac_key, &[iv, c], size_data)
        .map_err(|error| PeerConnectionError::CryptographyError(error.to_string()))?;
    if d != expected_d {
        return Err(PeerConnectionError::HandshakeError(String::from(
            "Invalid MAC",
        )));
    }

    // Decrypt the message with the AES key.
    let mut stream_cipher = Aes128Ctr64BE::new_from_slices(aes_key, iv)?;
    let mut decoded = c.to_vec();
    stream_cipher.try_apply_keystream(&mut decoded)?;
    Ok(decoded)
}

fn encrypt_message(
    remote_static_pubkey: &PublicKey,
    mut encoded_msg: Vec<u8>,
) -> Result<Vec<u8>, PeerConnectionError> {
    const SIGNATURE_SIZE: u16 = 65;
    const IV_SIZE: u16 = 16;
    const MAC_FOOTER_SIZE: u16 = 32;

    let mut rng = rand::thread_rng();

    // Pad with random amount of data. the amount needs to be at least 100 bytes to make
    // the message distinguishable from pre-EIP-8 handshakes.
    let padding_length = rng.gen_range(100..=300);
    encoded_msg.resize(encoded_msg.len() + padding_length, 0);

    // Precompute the size of the message. This is needed for computing the MAC.
    let ecies_overhead = SIGNATURE_SIZE + IV_SIZE + MAC_FOOTER_SIZE;
    let encoded_msg_len: u16 = encoded_msg
        .len()
        .try_into()
        .map_err(|_| PeerConnectionError::CryptographyError("Invalid message length".to_owned()))?;
    let auth_size = ecies_overhead + encoded_msg_len;
    let auth_size_bytes = auth_size.to_be_bytes();

    // Generate a keypair just for this message.
    let message_secret_key = SecretKey::new(&mut rng);

    // Derive a shared secret for this message.
    let message_secret =
        ecdh_xchng(&message_secret_key, remote_static_pubkey).map_err(|error| {
            PeerConnectionError::CryptographyError(format!(
                "Invalid generated message secret:  {error}"
            ))
        })?;

    // Derive the AES and MAC keys from the message secret.
    let mut secret_keys = [0; 32];
    kdf(&message_secret, &mut secret_keys)
        .map_err(|error| PeerConnectionError::CryptographyError(error.to_string()))?;
    let aes_key = &secret_keys[..16];
    let mac_key = sha256(&secret_keys[16..]);

    // Use the AES secret to encrypt the auth message.
    let iv = H128::random_using(&mut rng);
    let mut aes_cipher = Aes128Ctr64BE::new_from_slices(aes_key, &iv.0)?;
    aes_cipher.try_apply_keystream(&mut encoded_msg)?;
    let encrypted_auth_msg = encoded_msg;

    // Use the MAC secret to compute the MAC.
    let r_public_key = message_secret_key
        .public_key(secp256k1::SECP256K1)
        .serialize_uncompressed();
    let mac_footer = sha256_hmac(&mac_key, &[&iv.0, &encrypted_auth_msg], &auth_size_bytes)
        .map_err(|error| PeerConnectionError::CryptographyError(error.to_string()))?;

    // Return the message
    let mut final_msg = Vec::new();
    final_msg.extend_from_slice(&auth_size_bytes);
    final_msg.extend_from_slice(&r_public_key);
    final_msg.extend_from_slice(&iv.0);
    final_msg.extend_from_slice(&encrypted_auth_msg);
    final_msg.extend_from_slice(&mac_footer);
    Ok(final_msg)
}

fn retrieve_remote_ephemeral_key(
    shared_secret: H256,
    remote_nonce: H256,
    signature: Signature,
) -> Result<PublicKey, PeerConnectionError> {
    let signature_prehash = shared_secret ^ remote_nonce;
    let msg = secp256k1::Message::from_digest_slice(signature_prehash.as_bytes())?;
    let rid = RecoveryId::try_from(Into::<i32>::into(signature[64]))?;
    let sig = RecoverableSignature::from_compact(&signature[0..64], rid)?;
    Ok(secp256k1::SECP256K1.recover_ecdsa(&msg, &sig)?)
}

fn sign_shared_secret(
    shared_secret: H256,
    local_nonce: H256,
    local_ephemeral_key: &SecretKey,
) -> Result<Signature, PeerConnectionError> {
    let signature_prehash = shared_secret ^ local_nonce;
    let msg = secp256k1::Message::from_digest_slice(signature_prehash.as_bytes())?;
    let sig = secp256k1::SECP256K1.sign_ecdsa_recoverable(&msg, local_ephemeral_key);
    let (rid, signature) = sig.serialize_compact();
    let mut signature_bytes = [0; 65];
    signature_bytes[..64].copy_from_slice(&signature);
    signature_bytes[64] = Into::<i32>::into(rid)
        .try_into()
        .map_err(|_| PeerConnectionError::CryptographyError("Invalid recovery id".into()))?;
    Ok(signature_bytes.into())
}

#[derive(Debug)]
pub(crate) struct AuthMessage {
    /// The signature of the message.
    /// The signed data is `static-shared-secret ^ initiator-nonce`.
    pub signature: Signature,
    /// The uncompressed node public key of the initiator.
    pub public_key: H512,
    /// The nonce generated by the initiator.
    pub nonce: H256,
    /// The version of RLPx used by the sender.
    /// The current version is 5.
    pub version: u8,
}

impl AuthMessage {
    pub fn new(signature: Signature, public_key: H512, nonce: H256) -> Self {
        Self {
            signature,
            public_key,
            nonce,
            version: 5,
        }
    }
}

impl RLPEncode for AuthMessage {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.signature)
            .encode_field(&self.public_key)
            .encode_field(&self.nonce)
            .encode_field(&self.version)
            .finish()
    }
}

impl RLPDecode for AuthMessage {
    // NOTE: discards any extra data in the list after the known fields.
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (signature, decoder) = decoder.decode_field("signature")?;
        let (public_key, decoder) = decoder.decode_field("public_key")?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let (version, decoder) = decoder.decode_field("version")?;

        let rest = decoder.finish_unchecked();
        let this = Self {
            signature,
            public_key,
            nonce,
            version,
        };
        Ok((this, rest))
    }
}

#[derive(Debug, Clone)]
pub struct AckMessage {
    /// The recipient's ephemeral public key.
    pub ephemeral_pubkey: H512,
    /// The nonce generated by the recipient.
    pub nonce: H256,
    /// The version of RLPx used by the recipient.
    /// The current version is 5.
    pub version: u8,
}

impl AckMessage {
    pub fn new(ephemeral_pubkey: H512, nonce: H256) -> Self {
        Self {
            ephemeral_pubkey,
            nonce,
            version: 5,
        }
    }

    pub fn get_ephemeral_pubkey(&self) -> Option<PublicKey> {
        compress_pubkey(self.ephemeral_pubkey)
    }
}

impl RLPEncode for AckMessage {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.ephemeral_pubkey)
            .encode_field(&self.nonce)
            .encode_field(&self.version)
            .finish()
    }
}

impl RLPDecode for AckMessage {
    // NOTE: discards any extra data in the list after the known fields.
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (ephemeral_pubkey, decoder) = decoder.decode_field("ephemeral_pubkey")?;
        let (nonce, decoder) = decoder.decode_field("nonce")?;
        let (version, decoder) = decoder.decode_field("version")?;

        let rest = decoder.finish_unchecked();
        let this = Self {
            ephemeral_pubkey,
            nonce,
            version,
        };
        Ok((this, rest))
    }
}
