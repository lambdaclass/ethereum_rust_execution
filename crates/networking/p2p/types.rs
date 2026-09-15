use bytes::Bytes;
use ethrex_common::types::ForkId;
use ethrex_common::{H256, H264, H512};
use ethrex_crypto::keccak::keccak_hash;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{self, Decoder, Encoder},
};
use secp256k1::{PublicKey, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize, ser::Serializer};
use std::net::Ipv6Addr;
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, OnceLock, RwLock},
};
use thiserror::Error;

use crate::utils::node_id;

/// Holds the live, mutable copy of the local node identity.
///
/// Updated in-place whenever the IP predictor learns the public external IP
/// (via discv4/discv5 PONG voting). All reads must clone the needed values
/// out and drop the guard before any `.await`.
#[derive(Debug, Clone)]
pub struct LocalNode {
    pub node: Node,
    pub record: NodeRecord,
}

/// Shared, live local-node identity. Guards are `!Send`, so callers must
/// clone out values and drop the guard before crossing any `.await` point.
pub type SharedLocalNode = Arc<RwLock<LocalNode>>;

/// Holds the local node's network addressing configuration, separating the
/// socket bind address from the externally-announced address.
///
/// This is relevant for nodes running behind NAT: they bind to a private
/// address (e.g. `0.0.0.0`) but must announce their public IP to peers.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Address to bind UDP/TCP sockets to (e.g. `0.0.0.0` or `::`)
    pub bind_addr: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
}

impl NetworkConfig {
    /// Returns the socket address to bind the TCP listener to.
    pub fn bind_tcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_addr, self.tcp_port)
    }

    /// Returns the socket address to bind the UDP socket to.
    pub fn bind_udp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_addr, self.udp_port)
    }

    /// Builds a `NetworkConfig` where bind and external addresses are both
    /// taken from `node`. Useful when no NAT mapping is needed.
    pub fn from_node(node: &Node) -> Self {
        Self {
            bind_addr: node.ip,
            tcp_port: node.tcp_port,
            udp_port: node.udp_port,
        }
    }
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("RLP decode error: {0}")]
    RLPDecodeError(#[from] RLPDecodeError),
    #[error("Missing field: {0}")]
    MissingField(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
}

const MAX_NODE_RECORD_ENCODED_SIZE: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
}

impl RLPEncode for Endpoint {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.ip)
            .encode_field(&self.udp_port)
            .encode_field(&self.tcp_port)
            .finish();
    }
}

impl RLPDecode for Endpoint {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (ip, decoder) = decoder.decode_field("ip")?;
        let (udp_port, decoder) = decoder.decode_field("udp_port")?;
        let (tcp_port, decoder) = decoder.decode_field("tcp_port")?;
        let remaining = decoder.finish()?;
        let endpoint = Endpoint {
            ip,
            udp_port,
            tcp_port,
        };
        Ok((endpoint, remaining))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub ip: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub public_key: H512,
    pub version: Option<String>,
    node_id: OnceLock<H256>,
}

impl RLPDecode for Node {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (ip, decoder) = decoder.decode_field("ip")?;
        let (udp_port, decoder) = decoder.decode_field("upd_port")?;
        let (tcp_port, decoder) = decoder.decode_field("tcp_port")?;
        let (public_key, decoder) = decoder.decode_field("public_key")?;
        let remaining = decoder.finish_unchecked();

        let node = Node::new(ip, udp_port, tcp_port, public_key);
        Ok((node, remaining))
    }
}

impl<'de> serde::de::Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Node::from_str(&<String>::deserialize(deserializer)?)
            .map_err(|e| serde::de::Error::custom(format!("{}", e)))
    }
}

impl serde::Serialize for Node {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.enode_url())
    }
}

impl FromStr for Node {
    type Err = NodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if s.starts_with("enode://") => Self::from_enode_url(s),
            s if s.starts_with("enr:") => Self::from_enr_url(s),
            _ => Err(NodeError::InvalidFormat(
                "Invalid network address format".into(),
            )),
        }
    }
}

impl Node {
    pub fn new(ip: IpAddr, udp_port: u16, tcp_port: u16, public_key: H512) -> Self {
        Self {
            ip,
            udp_port,
            tcp_port,
            public_key,
            version: None,
            node_id: OnceLock::new(),
        }
    }

    pub fn client_name(&self) -> &str {
        self.version
            .as_deref()
            .and_then(|version| {
                let base = version
                    .split_once('/')
                    .map(|(name, _)| name.trim())
                    .unwrap_or_else(|| version.trim());
                if base.is_empty() { None } else { Some(base) }
            })
            .unwrap_or("unknown")
    }

    pub fn from_enode_url(enode: &str) -> Result<Self, NodeError> {
        let public_key = H512::from_str(&enode[8..136])
            .map_err(|_| NodeError::ParseError("Could not parse public_key".into()))?;

        let address_start = 137;
        let address_part = &enode[address_start..];

        // Remove `?discport=` if present
        let address_part = match address_part.find('?') {
            Some(pos) => &address_part[..pos],
            None => address_part,
        };

        let socket_address: SocketAddr = address_part
            .parse()
            .map_err(|_| NodeError::ParseError("Could not parse socket address".into()))?;
        let ip = socket_address.ip();
        let port = socket_address.port();

        let udp_port = match enode.find("?discport=") {
            Some(pos) => enode[pos + 10..]
                .parse()
                .map_err(|_| NodeError::ParseError("Could not parse discport".into()))?,
            None => port,
        };

        Ok(Self::new(ip, udp_port, port, public_key))
    }

    pub fn from_enr_url(enr: &str) -> Result<Self, NodeError> {
        let base64_decoded = ethrex_common::base64::decode(&enr.as_bytes()[4..]);
        let record = NodeRecord::decode(&base64_decoded).map_err(NodeError::from)?;
        Node::from_enr(&record)
    }

    pub fn from_enr(record: &NodeRecord) -> Result<Self, NodeError> {
        let pairs = record.pairs();
        let public_key = pairs.secp256k1.ok_or(NodeError::MissingField(
            "public key not found in record".into(),
        ))?;
        let verifying_key = PublicKey::from_slice(public_key.as_bytes()).map_err(|_| {
            NodeError::ParseError("public key could not be built from msg pub key bytes".into())
        })?;
        let encoded = verifying_key.serialize_uncompressed();
        let public_key = H512::from_slice(&encoded[1..]);

        let ip: IpAddr = match (pairs.ip, pairs.ip6) {
            (None, None) => {
                return Err(NodeError::MissingField(
                    "Ip not found in record, can't construct node".into(),
                ));
            }
            (None, Some(ipv6)) => IpAddr::from(ipv6),
            (Some(ipv4), None) => IpAddr::from(ipv4),
            (Some(ipv4), Some(_ipv6)) => IpAddr::from(ipv4),
        };

        // both udp and tcp can be defined in the pairs or only one
        // in the latter case, we have to default both ports to the one provided
        let udp_port = pairs
            .udp_port
            .or(pairs.tcp_port)
            .ok_or(NodeError::MissingField("No port found in record".into()))?;
        let tcp_port = pairs
            .tcp_port
            .or(pairs.udp_port)
            .ok_or(NodeError::MissingField("No port found in record".into()))?;

        Ok(Self::new(ip, udp_port, tcp_port, public_key))
    }

    pub fn enode_url(&self) -> String {
        let public_key = hex::encode(self.public_key);
        let node_ip = self.ip;
        let discovery_port = self.udp_port;
        let listener_port = self.tcp_port;
        if discovery_port != listener_port {
            format!("enode://{public_key}@{node_ip}:{listener_port}?discport={discovery_port}")
        } else {
            format!("enode://{public_key}@{node_ip}:{listener_port}")
        }
    }

    pub fn udp_addr(&self) -> SocketAddr {
        // Nodes that use ipv6 currently are only ipv4 masked addresses, so we can convert it to an ipv4 address.
        // If in the future we have real ipv6 nodes, we will need to handle them differently.
        SocketAddr::new(self.ip.to_canonical(), self.udp_port)
    }

    pub fn tcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.tcp_port)
    }

    pub fn node_id(&self) -> H256 {
        *self.node_id.get_or_init(|| node_id(&self.public_key))
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{0} #{1}({2}:{3})",
            self.client_name(),
            self.node_id(),
            self.ip,
            self.tcp_port
        ))
    }
}

/// Reference: [ENR records](https://github.com/ethereum/devp2p/blob/master/enr.md)
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct NodeRecordPairs {
    /// The ID of the identity scheme: https://github.com/ethereum/devp2p/blob/master/enr.md#v4-identity-scheme
    /// This is always "v4".
    pub id: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
    // the record structure reference says that tcp_port and udp_ports are big-endian integers
    // but they are actually encoded as 2 bytes, see geth for example: https://github.com/ethereum/go-ethereum/blob/f544fc3b4659aeca24a6de83f820dd61ea9b39db/p2p/enr/entries.go#L60-L78
    // I think the confusion comes from the fact that geth decodes the bytes and then builds an IPV4/6 big-integer structure.
    pub tcp_port: Option<u16>,
    pub udp_port: Option<u16>,
    pub secp256k1: Option<H264>,
    // https://github.com/ethereum/devp2p/blob/master/enr-entries/eth.md
    pub eth: Option<ForkId>,
    // Snap entry is being used by some tests such as `test_encode_enr_response`.
    pub snap: Option<Vec<u32>>,
    /// Entries outside the predefined dictionary, kept verbatim.
    ///
    /// Values are **already RLP-encoded**, and deliberately so. A record's
    /// signature covers its encoded bytes, so an entry only survives a
    /// decode/re-encode cycle if it comes back out exactly as it went in.
    /// Holding decoded payloads instead would mean committing to a shape: a
    /// value that is an RLP list rather than a byte string, which the dictionary
    /// has no room for and peers do emit, could not be represented at all, and a
    /// value that merely encodes unusually would be re-emitted canonically. In
    /// both cases the bytes we re-emit stop matching the bytes we verified.
    ///
    /// Keys here must be outside the dictionary. A dictionary key would be
    /// emitted twice by [`Self::encode_pairs`], once from its typed field and
    /// once from here, and EIP-778 requires keys to be unique. Such a record
    /// verifies locally, because both digests come from the same encoding, and
    /// is rejected by every remote. [`Self::set_extra`] and its siblings refuse
    /// those keys, and `encode_pairs` skips any that were written here directly,
    /// so no record ethrex signs can carry a duplicate.
    ///
    /// Prefer the setters over pushing tuples: hand-rolling the value encoding
    /// is easy to get wrong (see [`Self::set_extra`]). Pushing directly is for
    /// the values they cannot express, such as the RLP list EIP-7636 `client`
    /// carries, and then keeping the key unique is the caller's job.
    pub extra_fields: Vec<(Bytes, Bytes)>,
    // TODO implement ipv6 specific ports
}

impl NodeRecordPairs {
    pub fn try_from_raw_pairs(
        pairs: Vec<(Bytes, Bytes)>,
    ) -> Result<NodeRecordPairs, RLPDecodeError> {
        let mut decoded_pairs = NodeRecordPairs::default();
        for (key, value) in pairs {
            match key.as_ref() {
                b"id" => decoded_pairs.id = Some(String::decode(&value)?),
                b"ip" => decoded_pairs.ip = Some(Ipv4Addr::decode(&value)?),
                b"ip6" => decoded_pairs.ip6 = Some(Ipv6Addr::decode(&value)?),
                b"tcp" => decoded_pairs.tcp_port = Some(u16::decode(&value)?),
                b"udp" => decoded_pairs.udp_port = Some(u16::decode(&value)?),
                b"secp256k1" => decoded_pairs.secp256k1 = Some(H264(<[u8; 33]>::decode(&value)?)),
                b"snap" => decoded_pairs.snap = Some(Vec::<u32>::decode(&value)?),
                b"eth" => {
                    // https://github.com/ethereum/devp2p/blob/master/enr-entries/eth.md
                    // entry-value = [[ forkHash, forkNext ], ...]
                    let decoder = Decoder::new(&value)?;
                    // Here we decode fork-id = [ forkHash, forkNext ]
                    let (fork_id, decoder) = decoder.decode_field("forkId")?;

                    // As per the spec, we should ignore any additional list elements in entry-value
                    decoder.finish_unchecked();
                    decoded_pairs.eth = Some(fork_id);
                }
                // Any other key. Kept verbatim so an entry in a shape we did
                // not expect cannot fail the decode of the whole record.
                _ => {
                    decoded_pairs.extra_fields.push((key, value));
                }
            }
        }

        Ok(decoded_pairs)
    }

    /// Encodes to a list of (key, value) where keys are ascii bytes and values are rlp encoded bytes.
    pub fn encode_pairs(&self) -> Vec<(Bytes, Bytes)> {
        // The key/value pairs must be sorted by key and must be unique
        let mut pairs = vec![];
        if let Some(eth) = &self.eth {
            // Without the Vec wrapper, RLP encoding fork_id directly would produce:
            // [forkHash, forkNext]
            // But the spec requires nested lists:
            // [[forkHash, forkNext]]
            let eth = vec![eth.clone()];
            pairs.push(("eth".into(), eth.encode_to_vec().into()));
        }
        if let Some(id) = self.id.as_ref() {
            pairs.push(("id".into(), id.encode_to_vec().into()));
        }
        if let Some(ip) = self.ip {
            pairs.push(("ip".into(), ip.encode_to_vec().into()));
        }
        if let Some(ip6) = self.ip6 {
            pairs.push(("ip6".into(), ip6.encode_to_vec().into()));
        }
        if let Some(secp256k1) = self.secp256k1 {
            pairs.push(("secp256k1".into(), secp256k1.encode_to_vec().into()));
        }
        if let Some(snap) = self.snap.as_ref() {
            pairs.push(("snap".into(), snap.encode_to_vec().into()));
        }
        if let Some(tcp) = self.tcp_port {
            pairs.push(("tcp".into(), tcp.encode_to_vec().into()));
        }
        if let Some(udp) = self.udp_port {
            pairs.push(("udp".into(), udp.encode_to_vec().into()));
        }
        // Filter out any duplicate fields, keeping the first occurrence.
        let extra_fields = self
            .extra_fields
            .iter()
            .filter(|(key, _)| !Self::is_dictionary_key(key))
            .cloned();
        pairs.extend(extra_fields);
        // Sort pairs by key to ensure they are in the correct order for RLP encoding.
        pairs.sort_by(|(left_key, _), (right_key, _)| left_key.cmp(right_key));
        pairs
    }

    /// Whether `key` belongs to a typed field, and so may not be used for an
    /// extra entry.
    ///
    /// Exactly the keys [`Self::try_from_raw_pairs`] decodes into typed fields
    /// and [`Self::encode_pairs`] emits from them.
    pub fn is_dictionary_key(key: &[u8]) -> bool {
        matches!(
            key,
            b"id" | b"ip" | b"ip6" | b"tcp" | b"udp" | b"secp256k1" | b"snap" | b"eth"
        )
    }

    /// The RLP-decoded payload of an entry outside the predefined dictionary.
    ///
    /// Returns `None` when the key is absent *or* when its value is not an RLP
    /// byte string, so an entry whose shape we did not expect reads as missing
    /// rather than poisoning the record.
    pub fn extra(&self, key: &[u8]) -> Option<Bytes> {
        let (_, value) = self.extra_fields.iter().find(|(k, _)| k.as_ref() == key)?;
        Bytes::decode(value.as_ref()).ok()
    }

    /// An extra entry decoded as an integer, e.g. `quic`.
    ///
    /// `None` on an absent key or a value that is not a valid RLP integer,
    /// which includes the non-minimal encodings some clients emit.
    pub fn extra_int<T: RLPDecode>(&self, key: &[u8]) -> Option<T> {
        let (_, value) = self.extra_fields.iter().find(|(k, _)| k.as_ref() == key)?;
        T::decode(value.as_ref()).ok()
    }

    /// Advertise `payload` under `key`, replacing any existing entry. Returns
    /// whether it was stored, i.e. whether `key` is outside the dictionary.
    ///
    /// Encodes through [`Bytes`], whose `RLPEncode` delegates to `[u8]` and so
    /// emits a byte string. This is the step worth not hand-rolling: passing a
    /// bare `Vec<u8>` hits the blanket `Vec<T>` impl and emits a *list* of
    /// per-byte scalars, which is a well-formed ENR entry that no other client
    /// can read, and nothing local ever complains.
    pub fn set_extra(&mut self, key: &[u8], payload: impl Into<Bytes>) -> bool {
        let encoded = Bytes::from(payload.into().encode_to_vec());
        self.set_extra_encoded(key, encoded)
    }

    /// Advertise an integer under `key`, replacing any existing entry. Returns
    /// whether it was stored, i.e. whether `key` is outside the dictionary.
    ///
    /// Takes a `u64` rather than any [`RLPEncode`] so this cannot become the
    /// footgun [`Self::set_extra`] exists to close: a `Vec<u8>` passed to a
    /// generic bound would encode as an RLP list, under a method named for
    /// integers. Every ENR integer entry fits, being at most a uint64.
    pub fn set_extra_int(&mut self, key: &[u8], value: u64) -> bool {
        let encoded = Bytes::from(value.encode_to_vec());
        self.set_extra_encoded(key, encoded)
    }

    /// The write both setters end in, once the value is encoded: the dictionary
    /// guard and the replace-rather-than-append rule live here so neither can
    /// be reached without them.
    ///
    /// Replacing matters because EIP-778 requires keys to be unique, and
    /// appending a second entry for the same key yields a record that verifies
    /// locally (both digests come from the same encoding) yet is rejected by
    /// every remote, with no local symptom.
    ///
    /// Private: an already-encoded value is exactly the footgun the setters
    /// above exist to close, so the escape hatch is not offered. A value the
    /// typed setters cannot express, such as the RLP list EIP-7636 `client`
    /// carries, has to go onto [`Self::extra_fields`] directly; `encode_pairs`
    /// still refuses to emit a dictionary key from there.
    fn set_extra_encoded(&mut self, key: &[u8], encoded: Bytes) -> bool {
        if Self::is_dictionary_key(key) {
            return false;
        }
        self.extra_fields.retain(|(k, _)| k.as_ref() != key);
        self.extra_fields
            .push((Bytes::copy_from_slice(key), encoded));
        true
    }
}

pub const INITIAL_ENR_SEQ: u64 = 1;

/// Reference: [ENR records](https://github.com/ethereum/devp2p/blob/master/enr.md#record-structure)
#[derive(Debug, PartialEq, Clone, Eq, Default, Serialize, Deserialize)]
pub struct NodeRecord {
    pub signature: H512,
    pub seq: u64,
    /// The remainder of the record consists of key/value pairs represented as NodeRecordPairs
    pairs: NodeRecordPairs,
}

impl NodeRecord {
    pub fn new(signature: H512, seq: u64, pairs: NodeRecordPairs) -> Self {
        Self {
            signature,
            seq,
            pairs,
        }
    }

    pub fn enr_url(&self) -> Result<String, NodeError> {
        let rlp_encoded = self.encode_to_vec();
        let base64_encoded = ethrex_common::base64::encode(&rlp_encoded);
        let mut result: String = "enr:".into();
        let base64_encoded = String::from_utf8(base64_encoded)
            .map_err(|_| NodeError::ParseError("Could not base 64 encode enr record".into()))?;
        result.push_str(&base64_encoded);
        Ok(result)
    }

    pub fn from_node(node: &Node, seq: u64, signer: &SecretKey) -> Result<Self, NodeError> {
        let mut pairs = NodeRecordPairs {
            tcp_port: Some(node.tcp_port),
            udp_port: Some(node.udp_port),
            ..Default::default()
        };
        // Per EIP-778: a record without endpoint information is still valid.
        // When the IP is unspecified (not yet known), omit the ip/ip6 key entirely
        // rather than advertising 0.0.0.0, which peers would cache as unreachable.
        if !node.ip.is_unspecified() {
            match node.ip.to_canonical() {
                IpAddr::V4(ip) => pairs.ip = Some(ip),
                IpAddr::V6(ip) => pairs.ip6 = Some(ip),
            }
        }

        Self::from_pairs(seq, signer, pairs)
    }

    /// Builds a signed record from a fully specified entry set.
    ///
    /// `id` and `secp256k1` are always overwritten: both are fixed by the v4
    /// identity scheme and the signer, not chosen by the caller. Every other
    /// entry is taken verbatim, so a node with no TCP listener simply leaves
    /// `tcp_port` unset rather than encoding that intent as a port of 0.
    pub fn from_pairs(
        seq: u64,
        signer: &SecretKey,
        mut pairs: NodeRecordPairs,
    ) -> Result<Self, NodeError> {
        pairs.id = Some("v4".to_string());
        pairs.secp256k1 = Some(H264::from_slice(
            &PublicKey::from_secret_key(secp256k1::SECP256K1, signer).serialize(),
        ));

        let mut record = NodeRecord {
            seq,
            pairs,
            ..Default::default()
        };
        record.signature = record.sign_record(signer)?;

        Ok(record)
    }

    pub fn set_fork_id(&mut self, fork_id: ForkId, signer: &SecretKey) -> Result<(), NodeError> {
        self.edit(signer, |pairs| pairs.eth = Some(fork_id))
    }

    pub fn get_fork_id(&self) -> Option<&ForkId> {
        self.pairs.eth.as_ref()
    }

    /// The single path for changing a local record: apply `apply_edit` to the
    /// entry set, bump `seq` once, and re-sign.
    ///
    /// All or nothing. The edit lands on a copy that is committed only once the
    /// new signature is in hand, so a failure leaves the record exactly as it
    /// was instead of at a bumped `seq` its signature no longer covers. A
    /// half-updated record is worse than an unchanged one: it verifies nowhere,
    /// and the next edit bumps past the `seq` peers have already seen.
    ///
    /// Prefer this over rebuilding a record from a [`Node`]. A rebuild only
    /// carries the entries [`Self::from_node`] knows how to derive, so anything
    /// the caller added separately is silently lost, and stitching the lost
    /// entries back on afterwards bumps `seq` a second time.
    pub fn edit<F>(&mut self, signer: &SecretKey, apply_edit: F) -> Result<(), NodeError>
    where
        F: FnOnce(&mut NodeRecordPairs),
    {
        let mut edited = self.clone();
        apply_edit(&mut edited.pairs);
        edited.seq += 1;
        edited.signature = edited.sign_record(signer)?;

        *self = edited;
        Ok(())
    }

    pub fn sign_record(&self, signer: &SecretKey) -> Result<H512, NodeError> {
        let digest = &self.get_signature_digest();
        let msg = secp256k1::Message::from_digest_slice(digest)
            .map_err(|_| NodeError::SignatureError("Invalid message digest".into()))?;
        let (_recovery_id, signature_bytes) = secp256k1::SECP256K1
            .sign_ecdsa_recoverable(&msg, signer)
            .serialize_compact();

        Ok(H512::from_slice(&signature_bytes))
    }

    pub fn get_signature_digest(&self) -> [u8; 32] {
        let mut rlp = vec![];
        structs::Encoder::new(&mut rlp)
            .encode_field(&self.seq)
            .encode_key_value_list::<Bytes>(&self.pairs.encode_pairs())
            .finish();
        keccak_hash(&rlp)
    }

    /// Verifies the ENR signature using the embedded public key.
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify_signature(&self) -> bool {
        let pairs = self.pairs();
        let Some(pubkey_bytes) = pairs.secp256k1 else {
            return false;
        };

        let Ok(pubkey) = PublicKey::from_slice(pubkey_bytes.as_bytes()) else {
            return false;
        };

        let digest = self.get_signature_digest();
        let Ok(message) = secp256k1::Message::from_digest_slice(&digest) else {
            return false;
        };

        let Ok(signature) = Signature::from_compact(self.signature.as_bytes()) else {
            return false;
        };

        secp256k1::SECP256K1
            .verify_ecdsa(&message, &signature, &pubkey)
            .is_ok()
    }

    pub fn pairs(&self) -> &NodeRecordPairs {
        &self.pairs
    }
}

impl RLPDecode for NodeRecord {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        if decoder.get_payload_len() > MAX_NODE_RECORD_ENCODED_SIZE {
            return Err(RLPDecodeError::InvalidLength);
        }
        let (signature, decoder) = decoder.decode_field("signature")?;
        let (seq, decoder) = decoder.decode_field("seq")?;
        let (pairs, decoder) = decode_node_record_optional_fields(vec![], decoder)?;

        // all fields in pairs are optional except for id
        let id_pair = pairs.iter().find(|(k, _v)| k.eq("id".as_bytes()));
        if id_pair.is_some() {
            let pairs = NodeRecordPairs::try_from_raw_pairs(pairs)?;
            let node_record = NodeRecord {
                signature,
                seq,
                pairs,
            };
            let remaining = decoder.finish()?;
            Ok((node_record, remaining))
        } else {
            Err(RLPDecodeError::Custom(
                "Invalid node record, 'id' field missing".into(),
            ))
        }
    }
}

/// The NodeRecord optional fields are encoded as key/value pairs, according to the documentation
/// <https://github.com/ethereum/devp2p/blob/master/enr.md#record-structure>
/// This function returns a vector with (key, value) tuples. Both keys and values are stored as Bytes.
/// Each value is the actual RLP encoding of the field including its prefix so it can be decoded as T::decode(value)
fn decode_node_record_optional_fields(
    mut pairs: Vec<(Bytes, Bytes)>,
    decoder: Decoder,
) -> Result<(Vec<(Bytes, Bytes)>, Decoder), RLPDecodeError> {
    let (key, decoder): (Option<Bytes>, Decoder) = decoder.decode_optional_field();
    if let Some(k) = key {
        let (value, decoder): (Vec<u8>, Decoder) = decoder.get_encoded_item()?;
        pairs.push((k, Bytes::from(value)));
        decode_node_record_optional_fields(pairs, decoder)
    } else {
        Ok((pairs, decoder))
    }
}

impl RLPEncode for NodeRecord {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.signature)
            .encode_field(&self.seq)
            .encode_key_value_list::<Bytes>(&self.pairs.encode_pairs())
            .finish();
    }
}

impl RLPEncode for Node {
    fn encode(&self, buf: &mut Vec<u8>) {
        structs::Encoder::new(buf)
            .encode_field(&self.ip)
            .encode_field(&self.udp_port)
            .encode_field(&self.tcp_port)
            .encode_field(&self.public_key)
            .finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn test_signer() -> SecretKey {
        SecretKey::new(&mut rand::rngs::OsRng)
    }

    fn test_pubkey() -> H512 {
        let signer = test_signer();
        let pubkey = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &signer);
        let encoded = pubkey.serialize_uncompressed();
        H512::from_slice(&encoded[1..])
    }

    /// A NodeRecord built from a Node with an unspecified IP must omit the `ip` key entirely.
    /// Per EIP-778, this produces a valid endpoint-less ENR rather than advertising 0.0.0.0.
    #[test]
    fn node_record_from_unspecified_node_omits_ip_key() {
        let pubkey = test_pubkey();
        let node = Node::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 30303, 30303, pubkey);
        let signer = test_signer();
        let record = NodeRecord::from_node(&node, 1, &signer).unwrap();
        assert!(
            record.pairs().ip.is_none(),
            "ip key must be absent for unspecified address"
        );
        assert!(
            record.pairs().ip6.is_none(),
            "ip6 key must also be absent for unspecified address"
        );
        // The record must still have a valid signature (endpoint-less ENR is valid per EIP-778).
        assert!(
            record.verify_signature(),
            "endpoint-less ENR must have valid signature"
        );
    }

    /// A NodeRecord built from a Node with a public IP must include the `ip` key.
    #[test]
    fn node_record_from_public_node_includes_ip_key() {
        let pubkey = test_pubkey();
        let node = Node::new("1.2.3.4".parse().unwrap(), 30303, 30303, pubkey);
        let signer = test_signer();
        let record = NodeRecord::from_node(&node, 1, &signer).unwrap();
        assert!(
            record.pairs().ip.is_some(),
            "ip key must be present for a public address"
        );
        assert!(
            record.verify_signature(),
            "ENR with public IP must have valid signature"
        );
    }
}
