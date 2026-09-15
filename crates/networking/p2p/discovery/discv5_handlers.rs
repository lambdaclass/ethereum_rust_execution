use crate::{
    discovery::{
        ip_predictor::IpPredictor,
        lookup::{IterativeLookup, LOOKUP_ALPHA, LOOKUP_BUCKET_SIZE},
    },
    discv5::{
        messages::{
            DISTANCES_PER_FIND_NODE_MSG, FindNodeMessage, Handshake, HandshakeAuthdata, Message,
            NodesMessage, Ordinary, Packet, PacketTrait as _, PingMessage, PongMessage,
            TalkResMessage, WhoAreYou, decrypt_message,
        },
        server::{Discv5Message, SessionSource},
        session::{
            build_challenge_data, create_id_signature, derive_session_keys, verify_id_signature,
        },
    },
    metrics::METRICS,
    peer_table::{ContactValidation, DiscoveryProtocol, PeerTableServerProtocol as _},
    rlpx::utils::compress_pubkey,
    types::{Node, NodeRecord},
    utils::{distance, node_id},
};
use bytes::Bytes;
use ethrex_common::{H256, H512};
use rand::{Rng, rngs::OsRng};
use secp256k1::{PublicKey, SecretKey, ecdsa::Signature};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tracing::{debug, trace, warn};

use super::server::{DiscoveryServer, DiscoveryServerError};

/// Maximum number of ENRs per NODES message (limited by UDP packet size).
const MAX_ENRS_PER_MESSAGE: usize = 3;
/// Nodes not validated within this interval are candidates for revalidation.
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60); // 12 hours
/// Minimum interval between WHOAREYOU packets to the same IP address.
const WHOAREYOU_RATE_LIMIT: Duration = Duration::from_secs(1);
/// Maximum number of WHOAREYOU packets sent globally per second.
const GLOBAL_WHOAREYOU_RATE_LIMIT: u32 = 100;

impl DiscoveryServer {
    pub(crate) async fn discv5_handle_packet(
        &mut self,
        Discv5Message { packet, from }: Discv5Message,
    ) -> Result<(), DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            match packet.header.flag {
                0x01 => METRICS_P2P.inc_discv5_incoming("WhoAreYou"),
                0x02 => METRICS_P2P.inc_discv5_incoming("Handshake"),
                _ => {}
            }
        }
        match packet.header.flag {
            0x00 => self.discv5_handle_ordinary(packet, from).await,
            0x01 => self.discv5_handle_who_are_you(packet, from).await,
            0x02 => self.discv5_handle_handshake(packet, from).await,
            f => {
                tracing::trace!(protocol = "discv5", "Unexpected flag {f}");
                Err(crate::discv5::messages::PacketCodecError::MalformedData.into())
            }
        }
    }

    async fn discv5_handle_ordinary(
        &mut self,
        packet: Packet,
        addr: SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        // Length-checked: a peer can send an ordinary packet with authdata of any length, and
        // reading the src-id before the session lookup must not panic on a short/empty authdata
        // (an unauthenticated single-packet DoS of the discv5 actor).
        let src_id = Ordinary::src_id(&packet)?;

        let decrypt_key = self
            .peer_table
            .get_session_info(src_id)
            .await?
            .map(|s| s.inbound_key);

        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");

        let ordinary = match decrypt_key {
            Some(key) => match Ordinary::decode(&packet, &key) {
                Ok(ordinary) => {
                    if let Some(SessionSource { ip: session_ip, .. }) =
                        discv5.session_ips.get(&src_id)
                        && addr.ip() != *session_ip
                    {
                        trace!(
                            protocol = "discv5",
                            from = %src_id,
                            %addr,
                            expected_ip = %session_ip,
                            "IP mismatch for existing session, sending WhoAreYou"
                        );
                        discv5.whoareyou_rate_limit.pop(&(addr.ip(), src_id));
                        return self
                            .discv5_send_who_are_you(packet.header.nonce, src_id, addr)
                            .await;
                    }
                    ordinary
                }
                Err(_) => {
                    trace!(protocol = "discv5", from = %src_id, %addr, "Decryption failed, sending WhoAreYou");
                    return self
                        .discv5_send_who_are_you(packet.header.nonce, src_id, addr)
                        .await;
                }
            },
            None => {
                trace!(protocol = "discv5", from = %src_id, %addr, "No session, sending WhoAreYou");
                return self
                    .discv5_send_who_are_you(packet.header.nonce, src_id, addr)
                    .await;
            }
        };

        tracing::trace!(protocol = "discv5", received = %ordinary.message, from = %src_id, %addr);

        self.discv5_handle_message(ordinary, addr, None).await
    }

    async fn discv5_handle_who_are_you(
        &mut self,
        packet: Packet,
        addr: SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        let nonce = packet.header.nonce;
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        let Some((node, message, _)) = discv5.pending_by_nonce.remove(&nonce) else {
            tracing::trace!(
                protocol = "discv5",
                "Received unexpected WhoAreYou packet. Ignoring it"
            );
            return Ok(());
        };
        tracing::trace!(protocol = "discv5", received = "WhoAreYou", from = %node.node_id(), %addr);

        let challenge_data = build_challenge_data(
            &packet.masking_iv,
            &packet.header.static_header,
            &packet.header.authdata,
        );

        let ephemeral_key = SecretKey::new(&mut OsRng);
        let ephemeral_pubkey = ephemeral_key.public_key(secp256k1::SECP256K1).serialize();

        let Some(dest_pubkey) = compress_pubkey(node.public_key) else {
            return Err(DiscoveryServerError::CryptographyError(
                "Invalid public key".to_string(),
            ));
        };

        let session = derive_session_keys(
            &ephemeral_key,
            &dest_pubkey,
            &self.local_node.node_id(),
            &node.node_id(),
            &challenge_data,
            true,
        );

        let signature = create_id_signature(
            &self.signer,
            &challenge_data,
            &ephemeral_pubkey,
            &node.node_id(),
        );

        self.peer_table.set_session_info(node.node_id(), session)?;

        let whoareyou = WhoAreYou::decode(&packet)?;
        let record = (self.local_node_record.seq != whoareyou.enr_seq)
            .then(|| self.local_node_record.clone());
        self.discv5_send_handshake(message, signature, &ephemeral_pubkey, node, record)
            .await
    }

    async fn discv5_handle_handshake(
        &mut self,
        packet: Packet,
        addr: SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        let authdata = HandshakeAuthdata::decode(&packet.header.authdata)?;
        let src_id = authdata.src_id;

        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        let Some((challenge_data, _, _)) = discv5.pending_challenges.remove(&src_id) else {
            trace!(protocol = "discv5", from = %src_id, %addr, "Received unexpected Handshake packet");
            return Ok(());
        };

        let eph_pubkey = PublicKey::from_slice(&authdata.eph_pubkey).map_err(|_| {
            DiscoveryServerError::CryptographyError("Invalid ephemeral pubkey".into())
        })?;

        let src_pubkey = if let Some(contact) = self.peer_table.get_contact(src_id).await? {
            compress_pubkey(contact.node.public_key)
        } else if let Some(record) = &authdata.record {
            if !record.verify_signature() {
                trace!(from = %src_id, "Handshake ENR signature verification failed");
                return Ok(());
            }
            let pairs = record.pairs();
            let pubkey = pairs
                .secp256k1
                .and_then(|pk| PublicKey::from_slice(pk.as_bytes()).ok());

            if let Some(pk) = &pubkey {
                let uncompressed = pk.serialize_uncompressed();
                let derived_node_id = node_id(&H512::from_slice(&uncompressed[1..]));
                if derived_node_id != src_id {
                    trace!(from = %src_id, "Handshake ENR node_id mismatch");
                    return Ok(());
                }
            }

            pubkey
        } else {
            None
        };

        let Some(src_pubkey) = src_pubkey else {
            trace!(protocol = "discv5", from = %src_id, "Cannot verify handshake: unknown sender public key");
            return Ok(());
        };

        let signature = Signature::from_compact(&authdata.id_signature).map_err(|_| {
            DiscoveryServerError::CryptographyError("Invalid signature format".into())
        })?;

        if !verify_id_signature(
            &src_pubkey,
            &challenge_data,
            &authdata.eph_pubkey,
            &self.local_node.node_id(),
            &signature,
        ) {
            trace!(protocol = "discv5", from = %src_id, "Handshake signature verification failed");
            return Ok(());
        }

        if let Some(record) = &authdata.record {
            self.peer_table.new_contact_records(vec![record.clone()])?;
        }

        let session = derive_session_keys(
            &self.signer,
            &eph_pubkey,
            &src_id,
            &self.local_node.node_id(),
            &challenge_data,
            false,
        );

        self.peer_table.set_session_info(src_id, session.clone())?;
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        discv5.session_ips.insert(
            src_id,
            SessionSource {
                ip: addr.ip(),
                established_at: std::time::Instant::now(),
            },
        );

        let mut encrypted = packet.encrypted_message.clone();
        decrypt_message(&session.inbound_key, &packet, &mut encrypted)?;
        let message = Message::decode(&encrypted)?;
        trace!(protocol = "discv5", received = %message, from = %src_id, %addr, "Handshake completed");

        let ordinary = Ordinary { src_id, message };
        self.discv5_handle_message(ordinary, addr, Some(session.outbound_key))
            .await
    }

    pub(crate) async fn discv5_revalidate(&mut self) -> Result<(), DiscoveryServerError> {
        if let Some(contact) = self
            .peer_table
            .get_contact_to_revalidate(REVALIDATION_INTERVAL, DiscoveryProtocol::Discv5)
            .await?
            && let Err(e) = self.discv5_send_ping(&contact.node).await
        {
            trace!(protocol = "discv5", node = %contact.node.node_id(), err = ?e, "Failed to send revalidation PING");
        }
        Ok(())
    }

    pub(crate) async fn discv5_lookup(&mut self) -> Result<(), DiscoveryServerError> {
        if self.discv5.is_none() {
            return Ok(());
        }

        // Remove finished lookups
        self.discv5
            .as_mut()
            .expect("discv5 state must exist")
            .active_lookups
            .retain(|l| !l.is_finished());

        // If a lookup is already active, advance it instead of starting a new
        // one. Lookups are timer-driven: each tick sends the next alpha queries.
        // Responses feed results into the lookup but don't trigger new queries,
        // which naturally throttles traffic.
        if !self
            .discv5
            .as_ref()
            .expect("discv5 state must exist")
            .active_lookups
            .is_empty()
        {
            return self.advance_v5_lookup().await;
        }

        let mut rng = OsRng;
        let target_id: H256 = rng.r#gen();

        // Seed with closest known nodes from the connection pool
        let seed = self
            .peer_table
            .get_closest_from_pool(target_id, LOOKUP_BUCKET_SIZE)
            .await?;
        if seed.is_empty() {
            trace!(
                protocol = "discv5",
                "No seeds for lookup, connection pool empty"
            );
            return Ok(());
        }

        trace!(
            protocol = "discv5",
            seeds = seed.len(),
            "Starting new iterative lookup"
        );
        let lookup = IterativeLookup::new(target_id, seed);
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        discv5.active_lookups.push(lookup);

        // Fire the initial queries for the new lookup
        self.advance_v5_lookup().await
    }

    async fn advance_v5_lookup(&mut self) -> Result<(), DiscoveryServerError> {
        let discv5 = match &mut self.discv5 {
            Some(s) => s,
            None => return Ok(()),
        };

        if discv5.active_lookups.is_empty() {
            return Ok(());
        }

        // Collect queries from all active lookups
        let mut queries: Vec<(usize, H256, H256, Node)> = Vec::new();
        for (idx, lookup) in discv5.active_lookups.iter_mut().enumerate() {
            let target = lookup.target;
            for (node_id, node) in lookup.next_to_query(LOOKUP_ALPHA) {
                queries.push((idx, target, node_id, node));
            }
        }

        for (idx, target, node_id, node) in queries {
            let find_node_msg = self.discv5_build_find_node_for_target(target, &node);
            if let Err(e) = self.discv5_send_ordinary(find_node_msg, &node).await {
                debug!(protocol = "discv5", sending = "FindNode", addr = ?node.udp_addr(), err=?e, "Error sending message");
                self.peer_table.set_disposable(node_id)?;
                METRICS.record_new_discarded_node();
                if let Some(discv5) = &mut self.discv5
                    && let Some(lookup) = discv5.active_lookups.get_mut(idx)
                {
                    lookup.record_timeout();
                }
            }
        }
        Ok(())
    }

    fn discv5_build_find_node_for_target(&self, target: H256, node: &Node) -> Message {
        let center_distance = distance(&target, &node.node_id()) as u8;
        let mut distances = Vec::new();
        distances.push(center_distance as u32);
        for i in 0..DISTANCES_PER_FIND_NODE_MSG / 2 {
            if let Some(d) = center_distance.checked_add(i + 1) {
                distances.push(d as u32)
            }
            if let Some(d) = center_distance.checked_sub(i + 1) {
                distances.push(d as u32)
            }
        }
        Message::FindNode(FindNodeMessage {
            req_id: generate_req_id(),
            distances,
        })
    }

    async fn discv5_handle_ping(
        &mut self,
        ping_message: PingMessage,
        sender_id: H256,
        sender_addr: SocketAddr,
        outbound_key: Option<[u8; 16]>,
    ) -> Result<(), DiscoveryServerError> {
        trace!(protocol = "discv5", from = %sender_id, enr_seq = ping_message.enr_seq, "Received PING");

        let pong = Message::Pong(PongMessage {
            req_id: ping_message.req_id,
            enr_seq: self.local_node_record.seq,
            recipient_addr: sender_addr,
        });

        if outbound_key.is_none()
            && let Some(contact) = self.peer_table.get_contact(sender_id).await?
        {
            return self.discv5_send_ordinary(pong, &contact.node).await;
        }
        let key = self
            .discv5_resolve_outbound_key(&sender_id, outbound_key)
            .await?;
        self.discv5_send_ordinary_to(pong, &sender_id, sender_addr, &key)
            .await?;

        Ok(())
    }

    pub async fn discv5_handle_pong(
        &mut self,
        pong_message: PongMessage,
        sender_id: H256,
    ) -> Result<(), DiscoveryServerError> {
        self.peer_table
            .record_pong_received(sender_id, pong_message.req_id)?;

        if let Some(contact) = self.peer_table.get_contact(sender_id).await? {
            let cached_seq = contact.record.as_ref().map_or(0, |r| r.seq);
            if pong_message.enr_seq > cached_seq {
                trace!(
                    protocol = "discv5",
                    from = %sender_id,
                    cached_seq,
                    pong_seq = pong_message.enr_seq,
                    "ENR seq mismatch, requesting updated ENR (FINDNODE distance 0)"
                );
                let find_node = Message::FindNode(FindNodeMessage {
                    req_id: generate_req_id(),
                    distances: vec![0],
                });
                self.discv5_send_ordinary(find_node, &contact.node).await?;
            }
        }

        if let Some(ip) = self
            .ip_predictor
            .record_ip_vote(pong_message.recipient_addr.ip(), sender_id)
        {
            self.apply_predicted_ip(ip, "discv5");
        }

        Ok(())
    }

    async fn discv5_handle_find_node(
        &mut self,
        find_node_message: FindNodeMessage,
        sender_id: H256,
        sender_addr: SocketAddr,
        outbound_key: Option<[u8; 16]>,
    ) -> Result<(), DiscoveryServerError> {
        let send_to_contact = match self
            .peer_table
            .validate_contact(sender_id, sender_addr.ip())
            .await?
        {
            ContactValidation::Valid(contact) => Some(*contact),
            ContactValidation::UnknownContact => None,
            reason => {
                trace!(from = %sender_id, ?reason, "Rejected FINDNODE");
                return Ok(());
            }
        };

        let mut nodes = self
            .peer_table
            .get_nodes_at_distances(find_node_message.distances.clone())
            .await?;
        if find_node_message.distances.contains(&0) {
            nodes.push(self.local_node_record.clone());
        }

        let key = self
            .discv5_resolve_outbound_key(&sender_id, outbound_key)
            .await?;

        let chunks: Vec<_> = nodes.chunks(MAX_ENRS_PER_MESSAGE).collect();
        if chunks.is_empty() {
            let nodes_message = Message::Nodes(NodesMessage {
                req_id: find_node_message.req_id,
                total: 1,
                nodes: vec![],
            });
            if let Some(contact) = &send_to_contact {
                self.discv5_send_ordinary(nodes_message, &contact.node)
                    .await?;
            } else {
                self.discv5_send_ordinary_to(nodes_message, &sender_id, sender_addr, &key)
                    .await?;
            }
        } else {
            for chunk in &chunks {
                let nodes_message = Message::Nodes(NodesMessage {
                    req_id: find_node_message.req_id.clone(),
                    total: chunks.len() as u64,
                    nodes: chunk.to_vec(),
                });
                if let Some(contact) = &send_to_contact {
                    self.discv5_send_ordinary(nodes_message, &contact.node)
                        .await?;
                } else {
                    self.discv5_send_ordinary_to(nodes_message, &sender_id, sender_addr, &key)
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn discv5_handle_nodes_message(
        &mut self,
        nodes_message: NodesMessage,
        sender_id: H256,
    ) -> Result<(), DiscoveryServerError> {
        // Only accept a NODES that answers a FINDNODE we actually sent to this
        // peer. Without the check, any peer that has completed a handshake can
        // push ENRs of its choosing into our peer table with an unsolicited
        // NODES, and we then hand them back out in our own FINDNODE responses.
        let solicited = self.discv5.as_ref().is_some_and(|discv5| {
            discv5
                .pending_findnodes
                .contains_key(&(sender_id, nodes_message.req_id.clone()))
        });
        if !solicited {
            trace!(
                protocol = "discv5",
                from = %sender_id,
                "Dropping unsolicited NODES response"
            );
            return Ok(());
        }

        self.peer_table
            .new_contact_records(nodes_message.nodes.clone())?;

        // Feed results into ALL active lookups (but don't advance — the timer
        // drives lookup progress so that traffic stays controlled).
        if let Some(discv5) = &mut self.discv5 {
            let entries: Vec<(H256, Node)> = nodes_message
                .nodes
                .iter()
                .filter_map(|r| Node::from_enr(r).ok().map(|n| (n.node_id(), n)))
                .collect();
            for lookup in &mut discv5.active_lookups {
                lookup.feed_results(entries.clone());
            }
            if let Some(lookup) = discv5.active_lookups.first_mut() {
                lookup.record_response();
            }
        }

        Ok(())
    }

    async fn discv5_send_ping(&mut self, node: &Node) -> Result<(), DiscoveryServerError> {
        let req_id = generate_req_id();

        let ping = Message::Ping(PingMessage {
            req_id: req_id.clone(),
            enr_seq: self.local_node_record.seq,
        });

        self.discv5_send_ordinary(ping, node).await?;
        self.peer_table.record_ping_sent(node.node_id(), req_id)?;

        Ok(())
    }

    async fn discv5_send_ordinary(
        &mut self,
        message: Message,
        node: &Node,
    ) -> Result<(), DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv5_outgoing(message.metric_label());
        }
        let ordinary = Ordinary {
            src_id: self.local_node.node_id(),
            message: message.clone(),
        };
        let encrypt_key = match self.peer_table.get_session_info(node.node_id()).await? {
            Some(s) => s.outbound_key,
            None => {
                trace!(
                    protocol = "discv5",
                    node = %node.node_id(),
                    "No session found in send_ordinary, using zeroed key to trigger handshake"
                );
                [0; 16]
            }
        };

        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        // Remember the request id so the matching NODES response is accepted.
        // Done in every send path so none can issue a FINDNODE unregistered.
        if let Message::FindNode(find_node) = &message {
            discv5
                .pending_findnodes
                .insert((node.node_id(), find_node.req_id.clone()), Instant::now());
        }
        let mut rng = OsRng;
        let masking_iv: u128 = rng.r#gen();
        let nonce = discv5.next_nonce(&mut rng);

        let packet = ordinary.encode(&nonce, masking_iv.to_be_bytes(), &encrypt_key)?;

        self.discv5_send_packet(&packet, &node.node_id(), node.udp_addr())
            .await?;
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        discv5
            .pending_by_nonce
            .insert(nonce, (node.clone(), message, Instant::now()));
        Ok(())
    }

    async fn discv5_resolve_outbound_key(
        &self,
        node_id: &H256,
        key: Option<[u8; 16]>,
    ) -> Result<[u8; 16], DiscoveryServerError> {
        if let Some(key) = key {
            return Ok(key);
        }
        match self.peer_table.get_session_info(*node_id).await? {
            Some(s) => Ok(s.outbound_key),
            None => {
                trace!(
                    protocol = "discv5",
                    node = %node_id,
                    "No session found in resolve_outbound_key, using zeroed key"
                );
                Ok([0; 16])
            }
        }
    }

    async fn discv5_send_ordinary_to(
        &mut self,
        message: Message,
        dest_id: &H256,
        addr: SocketAddr,
        encrypt_key: &[u8; 16],
    ) -> Result<(), DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv5_outgoing(message.metric_label());
        }
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        // Remember the request id so the matching NODES response is accepted.
        // Done in every send path so none can issue a FINDNODE unregistered.
        if let Message::FindNode(find_node) = &message {
            discv5
                .pending_findnodes
                .insert((*dest_id, find_node.req_id.clone()), Instant::now());
        }
        let ordinary = Ordinary {
            src_id: self.local_node.node_id(),
            message,
        };

        let mut rng = OsRng;
        let masking_iv: u128 = rng.r#gen();
        let nonce = discv5.next_nonce(&mut rng);

        let packet = ordinary.encode(&nonce, masking_iv.to_be_bytes(), encrypt_key)?;

        self.discv5_send_packet(&packet, dest_id, addr).await?;
        Ok(())
    }

    async fn discv5_send_handshake(
        &mut self,
        message: Message,
        signature: Signature,
        eph_pubkey: &[u8],
        node: Node,
        record: Option<NodeRecord>,
    ) -> Result<(), DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv5_outgoing("Handshake");
        }
        let handshake = Handshake {
            src_id: self.local_node.node_id(),
            id_signature: signature.serialize_compact().to_vec(),
            eph_pubkey: eph_pubkey.to_vec(),
            record,
            message: message.clone(),
        };
        let encrypt_key = match self.peer_table.get_session_info(node.node_id()).await? {
            Some(s) => s.outbound_key,
            None => {
                trace!(
                    protocol = "discv5",
                    node = %node.node_id(),
                    "No session found in send_handshake, using zeroed key"
                );
                [0; 16]
            }
        };

        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        // Remember the request id so the matching NODES response is accepted.
        // Done in every send path so none can issue a FINDNODE unregistered.
        if let Message::FindNode(find_node) = &message {
            discv5
                .pending_findnodes
                .insert((node.node_id(), find_node.req_id.clone()), Instant::now());
        }
        let mut rng = OsRng;
        let masking_iv: u128 = rng.r#gen();
        let nonce = discv5.next_nonce(&mut rng);

        let packet = handshake.encode(&nonce, masking_iv.to_be_bytes(), &encrypt_key)?;

        self.discv5_send_packet(&packet, &node.node_id(), node.udp_addr())
            .await?;
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        discv5
            .pending_by_nonce
            .insert(nonce, (node, message, Instant::now()));
        Ok(())
    }

    pub async fn discv5_send_who_are_you(
        &mut self,
        nonce: [u8; 12],
        src_id: H256,
        addr: SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv5_outgoing("WhoAreYou");
        }
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");

        let rate_key = (addr.ip(), src_id);
        let now = Instant::now();

        // Global rate limit
        if now.duration_since(discv5.whoareyou_global_window_start) >= Duration::from_secs(1) {
            discv5.whoareyou_global_count = 0;
            discv5.whoareyou_global_window_start = now;
        }
        if discv5.whoareyou_global_count >= GLOBAL_WHOAREYOU_RATE_LIMIT {
            if discv5.whoareyou_global_count == GLOBAL_WHOAREYOU_RATE_LIMIT {
                discv5.whoareyou_global_count = GLOBAL_WHOAREYOU_RATE_LIMIT + 1;
                warn!(
                    protocol = "discv5",
                    "Global WHOAREYOU rate limit reached ({GLOBAL_WHOAREYOU_RATE_LIMIT}/s), \
                     dropping excess packets. This is normal during initial discovery or \
                     network churn; persistent occurrences may indicate a DoS attempt"
                );
            }
            return Ok(());
        }

        // Resend existing challenge if pending
        if let Some((_, _, raw_bytes)) = discv5.pending_challenges.get(&src_id) {
            trace!(
                protocol = "discv5",
                to = %src_id,
                %addr,
                "Resending existing WhoAreYou challenge"
            );
            self.udp_socket.send_to(raw_bytes, addr).await?;
            return Ok(());
        }

        // Per-(IP, node) rate limit
        if !IpPredictor::is_private_ip(addr.ip())
            && let Some(last_sent) = discv5.whoareyou_rate_limit.get(&rate_key)
            && now.duration_since(*last_sent) < WHOAREYOU_RATE_LIMIT
        {
            trace!(
                protocol = "discv5",
                to_ip = %addr.ip(),
                "Rate limiting WHOAREYOU packet (amplification attack prevention)"
            );
            return Ok(());
        }

        discv5.whoareyou_rate_limit.push(rate_key, now);
        discv5.whoareyou_global_count += 1;

        let mut rng = OsRng;

        let enr_seq = self
            .peer_table
            .get_contact(src_id)
            .await?
            .map_or(0, |c| c.record.as_ref().map_or(0, |r| r.seq));

        let who_are_you = WhoAreYou {
            id_nonce: rng.r#gen(),
            enr_seq,
        };

        let masking_iv: u128 = rng.r#gen();
        let packet = who_are_you.encode(&nonce, masking_iv.to_be_bytes(), &[0; 16])?;

        let mut raw_buf = Vec::new();
        packet.encode(&mut raw_buf, &src_id)?;
        let raw_bytes = raw_buf;

        let challenge_data = build_challenge_data(
            &masking_iv.to_be_bytes(),
            &packet.header.static_header,
            &packet.header.authdata,
        );
        let discv5 = self.discv5.as_mut().expect("discv5 state must exist");
        discv5
            .pending_challenges
            .insert(src_id, (challenge_data, Instant::now(), raw_bytes.clone()));

        self.udp_socket.send_to(&raw_bytes, addr).await?;
        trace!(protocol = "discv5", to = %src_id, %addr, flag = packet.header.flag, "Sent packet");

        Ok(())
    }

    async fn discv5_send_packet(
        &self,
        packet: &Packet,
        dest_id: &H256,
        addr: SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        let mut buf = Vec::new();
        packet.encode(&mut buf, dest_id)?;
        self.udp_socket.send_to(&buf, addr).await?;
        trace!(protocol = "discv5", to = %dest_id, %addr, flag = packet.header.flag, "Sent packet");
        Ok(())
    }

    async fn discv5_handle_message(
        &mut self,
        ordinary: Ordinary,
        sender_addr: SocketAddr,
        outbound_key: Option<[u8; 16]>,
    ) -> Result<(), DiscoveryServerError> {
        let sender_id = ordinary.src_id;
        if sender_id == self.local_node.node_id() {
            return Ok(());
        }
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv5_incoming(ordinary.message.metric_label());
        }
        match ordinary.message {
            Message::Ping(ping_message) => {
                if ping_message.req_id.len() > 8 {
                    trace!(protocol = "discv5", from = %sender_id, "Dropping PING with oversized req_id");
                    return Ok(());
                }
                self.discv5_handle_ping(ping_message, sender_id, sender_addr, outbound_key)
                    .await?
            }
            Message::Pong(pong_message) => {
                self.discv5_handle_pong(pong_message, sender_id).await?;
            }
            Message::FindNode(find_node_message) => {
                if find_node_message.req_id.len() > 8 {
                    trace!(protocol = "discv5", from = %sender_id, "Dropping FINDNODE with oversized req_id");
                    return Ok(());
                }
                self.discv5_handle_find_node(
                    find_node_message,
                    sender_id,
                    sender_addr,
                    outbound_key,
                )
                .await?;
            }
            Message::Nodes(nodes_message) => {
                self.discv5_handle_nodes_message(nodes_message, sender_id)
                    .await?;
            }
            Message::TalkReq(talk_req_message) => {
                if talk_req_message.req_id.len() > 8 {
                    trace!(protocol = "discv5", from = %sender_id, "Dropping TALKREQ with oversized req_id");
                    return Ok(());
                }
                let talk_res = Message::TalkRes(TalkResMessage {
                    req_id: talk_req_message.req_id,
                    response: vec![],
                });
                let key = self
                    .discv5_resolve_outbound_key(&sender_id, outbound_key)
                    .await?;
                self.discv5_send_ordinary_to(talk_res, &sender_id, sender_addr, &key)
                    .await?;
            }
            Message::TalkRes(_talk_res_message) => (),
            Message::Ticket(_ticket_message) => (),
        }
        Ok(())
    }
}

fn generate_req_id() -> Bytes {
    let mut rng = OsRng;
    Bytes::from(rng.r#gen::<u64>().to_be_bytes().to_vec())
}
