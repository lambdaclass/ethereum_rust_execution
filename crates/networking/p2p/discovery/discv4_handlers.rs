use crate::{
    discovery::contact_table::{Contact, ContactValidation, DiscoveryProtocol},
    discovery::lookup::{IterativeLookup, LOOKUP_ALPHA, LOOKUP_BUCKET_SIZE},
    discv4::{
        messages::{
            ENRRequestMessage, ENRResponseMessage, FindNodeMessage, Message, NeighborsMessage,
            PingMessage, PongMessage,
        },
        server::{Discv4Message, EXPIRATION_SECONDS},
    },
    metrics::METRICS,
    types::{Endpoint, Node},
    utils::{
        get_msg_expiration_from_seconds, is_msg_expired, node_id, public_key_from_signing_key,
    },
};
use bytes::{Bytes, BytesMut};
use ethrex_common::{H256, H512};
use rand::rngs::OsRng;
use secp256k1::SecretKey;
use std::time::Duration;
use tracing::{debug, trace};

use super::server::{DiscoveryServer, DiscoveryServerError};

/// Discv4 revalidation interval.
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60); // 12 hours

impl DiscoveryServer {
    pub(crate) async fn discv4_process_message(
        &mut self,
        Discv4Message {
            from,
            message,
            hash,
            sender_public_key,
        }: Discv4Message,
    ) -> Result<(), DiscoveryServerError> {
        // Ignore packets sent by ourselves
        if node_id(&sender_public_key) == self.local_node.node_id() {
            return Ok(());
        }
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv4_incoming(message.metric_label());
        }
        match message {
            Message::Ping(ping_message) => {
                trace!(protocol = "discv4", received = "Ping", msg = ?ping_message, from = %format!("{sender_public_key:#x}"));

                if is_msg_expired(ping_message.expiration) {
                    trace!(protocol = "discv4", "Ping expired, skipped");
                    return Ok(());
                }

                let node = Node::new(
                    from.ip().to_canonical(),
                    from.port(),
                    ping_message.from.tcp_port,
                    sender_public_key,
                );

                let _ = self.discv4_handle_ping(ping_message, hash, sender_public_key, node).await.inspect_err(|e| {
                    debug!(protocol = "discv4", sent = "Ping", to = %format!("{sender_public_key:#x}"), err = ?e, "Error handling message");
                });
            }
            Message::Pong(pong_message) => {
                trace!(protocol = "discv4", received = "Pong", msg = ?pong_message, from = %format!("{:#x}", sender_public_key));
                let node_id = node_id(&sender_public_key);
                self.discv4_handle_pong(pong_message, node_id).await?;
            }
            Message::FindNode(find_node_message) => {
                trace!(protocol = "discv4", received = "FindNode", msg = ?find_node_message, from = %format!("{:#x}", sender_public_key));

                if is_msg_expired(find_node_message.expiration) {
                    trace!(protocol = "discv4", "FindNode expired, skipped");
                    return Ok(());
                }

                self.discv4_handle_find_node(sender_public_key, find_node_message.target, from)
                    .await?;
            }
            Message::Neighbors(neighbors_message) => {
                trace!(protocol = "discv4", received = "Neighbors", msg = ?neighbors_message, from = %format!("{sender_public_key:#x}"));

                if is_msg_expired(neighbors_message.expiration) {
                    trace!(protocol = "discv4", "Neighbors expired, skipping");
                    return Ok(());
                }

                self.discv4_handle_neighbors(neighbors_message, sender_public_key)
                    .await?;
            }
            Message::ENRRequest(enrrequest_message) => {
                trace!(protocol = "discv4", received = "ENRRequest", msg = ?enrrequest_message, from = %format!("{sender_public_key:#x}"));

                if is_msg_expired(enrrequest_message.expiration) {
                    trace!(protocol = "discv4", "ENRRequest expired, skipping");
                    return Ok(());
                }

                self.discv4_handle_enr_request(sender_public_key, from, hash)
                    .await?;
            }
            Message::ENRResponse(enrresponse_message) => {
                trace!(protocol = "discv4", received = "ENRResponse", msg = ?enrresponse_message, from = %format!("{sender_public_key:#x}"));
                self.discv4_handle_enr_response(sender_public_key, from, enrresponse_message)
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn discv4_revalidate(&mut self) -> Result<(), DiscoveryServerError> {
        if let Some(contact) = self
            .contacts
            .contact_to_revalidate(REVALIDATION_INTERVAL, DiscoveryProtocol::Discv4)
        {
            let node = contact.node.clone();
            self.discv4_send_ping(&node).await?;
        }
        Ok(())
    }

    pub(crate) async fn discv4_lookup(&mut self) -> Result<(), DiscoveryServerError> {
        if self.discv4.is_none() {
            return Ok(());
        }

        // Remove finished lookups
        self.discv4
            .as_mut()
            .expect("discv4 state must exist")
            .active_lookups
            .retain(|(l, _)| !l.is_finished());

        // If a lookup is already active, advance it instead of starting a new
        // one. Lookups are timer-driven: each tick sends the next alpha queries.
        // Responses feed results into the lookup but don't trigger new queries,
        // which naturally throttles traffic.
        if !self
            .discv4
            .as_ref()
            .expect("discv4 state must exist")
            .active_lookups
            .is_empty()
        {
            return self.advance_v4_lookup().await;
        }

        // Generate random target
        let random_priv_key = SecretKey::new(&mut OsRng);
        let random_pub_key = public_key_from_signing_key(&random_priv_key);
        let target_id = node_id(&random_pub_key);

        // Seed with closest known nodes from the connection pool
        let seed = self
            .contacts
            .closest_from_pool(target_id, LOOKUP_BUCKET_SIZE);
        if seed.is_empty() {
            trace!(
                protocol = "discv4",
                "No seeds for lookup, connection pool empty"
            );
            return Ok(());
        }

        trace!(
            protocol = "discv4",
            seeds = seed.len(),
            "Starting new iterative lookup"
        );
        let lookup = IterativeLookup::new(target_id, seed);

        // Sign one FindNode message for this target
        let expiration = get_msg_expiration_from_seconds(EXPIRATION_SECONDS);
        let msg = Message::FindNode(FindNodeMessage::new(random_pub_key, expiration));
        let mut buf = BytesMut::new();
        msg.encode_with_header(&mut buf, &self.signer);

        let discv4 = self.discv4.as_mut().expect("discv4 state must exist");
        discv4.active_lookups.push((lookup, buf));

        // Fire the initial queries for the new lookup
        self.advance_v4_lookup().await
    }

    async fn advance_v4_lookup(&mut self) -> Result<(), DiscoveryServerError> {
        let discv4 = match &mut self.discv4 {
            Some(s) => s,
            None => return Ok(()),
        };

        if discv4.active_lookups.is_empty() {
            return Ok(());
        }

        // Collect queries from all active lookups
        let mut queries: Vec<(usize, H256, Node, BytesMut)> = Vec::new();
        for (idx, (lookup, message)) in discv4.active_lookups.iter_mut().enumerate() {
            for (node_id, node) in lookup.next_to_query(LOOKUP_ALPHA) {
                queries.push((idx, node_id, node, message.clone()));
            }
        }

        if !queries.is_empty() {
            trace!(
                protocol = "discv4",
                count = queries.len(),
                "Advancing lookups, querying nodes"
            );
        }

        for (idx, node_id, node, message) in queries {
            if let Err(e) = self.udp_socket.send_to(&message, &node.udp_addr()).await {
                debug!(protocol = "discv4", sending = "FindNode", addr = ?node.udp_addr(), err=?e, "Error sending message");
                self.contacts.set_disposable(&node_id);
                METRICS.record_new_discarded_node();
                if let Some(discv4) = &mut self.discv4
                    && let Some((lookup, _)) = discv4.active_lookups.get_mut(idx)
                {
                    lookup.record_timeout();
                }
            } else {
                #[cfg(feature = "metrics")]
                {
                    use ethrex_metrics::p2p::METRICS_P2P;
                    METRICS_P2P.inc_discv4_outgoing("FindNode");
                }
                self.discv4
                    .as_mut()
                    .expect("discv4 state must exist")
                    .pending_find_node
                    .insert(node_id, std::time::Instant::now());
            }
        }
        Ok(())
    }

    pub(crate) async fn discv4_enr_lookup(&mut self) -> Result<(), DiscoveryServerError> {
        if let Some(contact) = self.contacts.contact_for_enr_lookup() {
            let node = contact.node.clone();
            self.discv4_send_enr_request(&node).await?;
        }
        Ok(())
    }

    pub(crate) async fn discv4_send_ping(
        &mut self,
        node: &Node,
    ) -> Result<(), DiscoveryServerError> {
        let expiration: u64 = get_msg_expiration_from_seconds(EXPIRATION_SECONDS);
        let from = Endpoint {
            ip: self.local_node.ip,
            udp_port: self.local_node.udp_port,
            tcp_port: self.local_node.tcp_port,
        };
        let to = Endpoint {
            ip: node.ip,
            udp_port: node.udp_port,
            tcp_port: node.tcp_port,
        };
        let enr_seq = self.local_node_record.seq;
        let ping = Message::Ping(PingMessage::new(from, to, expiration).with_enr_seq(enr_seq));
        let ping_hash = self.discv4_send_else_dispose(ping, node).await?;
        trace!(protocol = "discv4", sent = "Ping", to = %format!("{:#x}", node.public_key));
        METRICS.record_ping_sent().await;
        let ping_id = Bytes::copy_from_slice(ping_hash.as_bytes());
        self.contacts.record_ping_sent(&node.node_id(), ping_id);
        Ok(())
    }

    async fn discv4_send_pong(
        &mut self,
        ping_hash: H256,
        node: &Node,
    ) -> Result<(), DiscoveryServerError> {
        let expiration: u64 = get_msg_expiration_from_seconds(EXPIRATION_SECONDS);
        let to = Endpoint {
            ip: node.ip,
            udp_port: node.udp_port,
            tcp_port: node.tcp_port,
        };
        let enr_seq = self.local_node_record.seq;
        let pong = Message::Pong(PongMessage::new(to, ping_hash, expiration).with_enr_seq(enr_seq));
        self.discv4_send(pong, node.udp_addr()).await?;
        trace!(protocol = "discv4", sent = "Pong", to = %format!("{:#x}", node.public_key));
        Ok(())
    }

    async fn discv4_send_neighbors(
        &mut self,
        neighbors: Vec<Node>,
        node: &Node,
    ) -> Result<(), DiscoveryServerError> {
        let expiration: u64 = get_msg_expiration_from_seconds(EXPIRATION_SECONDS);
        let msg = Message::Neighbors(NeighborsMessage::new(neighbors, expiration));
        self.discv4_send(msg, node.udp_addr()).await?;
        trace!(protocol = "discv4", sent = "Neighbors", to = %format!("{:#x}", node.public_key));
        Ok(())
    }

    async fn discv4_send_enr_request(&mut self, node: &Node) -> Result<(), DiscoveryServerError> {
        let expiration: u64 = get_msg_expiration_from_seconds(EXPIRATION_SECONDS);
        let enr_request = Message::ENRRequest(ENRRequestMessage { expiration });
        let enr_request_hash = self.discv4_send_else_dispose(enr_request, node).await?;
        self.contacts
            .record_enr_request_sent(node.node_id(), enr_request_hash);
        Ok(())
    }

    async fn discv4_send_enr_response(
        &mut self,
        request_hash: H256,
        from: std::net::SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        let node_record = &self.local_node_record;
        let msg = Message::ENRResponse(ENRResponseMessage::new(request_hash, node_record.clone()));
        self.discv4_send(msg, from).await?;
        Ok(())
    }

    async fn discv4_handle_ping(
        &mut self,
        ping_message: PingMessage,
        hash: H256,
        sender_public_key: H512,
        node: Node,
    ) -> Result<(), DiscoveryServerError> {
        self.discv4_send_pong(hash, &node).await?;

        if self
            .contacts
            .insert_if_new(node.clone(), DiscoveryProtocol::Discv4)
            .await
        {
            self.discv4_send_ping(&node).await?;
        } else {
            let node_id = node_id(&sender_public_key);
            let stored_enr_seq = self
                .contacts
                .get_contact(&node_id)
                .and_then(|c| c.record.as_ref())
                .map(|r| r.seq);

            let received_enr_seq = ping_message.enr_seq;

            if let (Some(received), Some(stored)) = (received_enr_seq, stored_enr_seq)
                && received > stored
            {
                self.discv4_send_enr_request(&node).await?;
            }
        }
        Ok(())
    }

    async fn discv4_handle_pong(
        &mut self,
        message: PongMessage,
        node_id: H256,
    ) -> Result<(), DiscoveryServerError> {
        // Everything needed from the contact is copied out before the mutable
        // borrows below: the table is plain state now, not an actor behind a
        // channel, so a live `&Contact` would pin it for the rest of the call.
        let Some((node, stored_enr_seq)) = self
            .contacts
            .get_contact(&node_id)
            .map(|c| (c.node.clone(), c.record.as_ref().map(|r| r.seq)))
        else {
            return Ok(());
        };

        let ping_id = Bytes::copy_from_slice(message.ping_hash.as_bytes());
        self.contacts.record_pong_received(&node_id, &ping_id);
        let received_enr_seq = message.enr_seq;
        if let (Some(received), Some(stored)) = (received_enr_seq, stored_enr_seq)
            && received > stored
        {
            self.discv4_send_enr_request(&node).await?;
        }

        trace!(protocol = "discv4", observed_ip = %message.to.ip, "Recorded discv4 PONG IP vote");
        if let Some(ip) = self.ip_predictor.record_ip_vote(message.to.ip, node_id) {
            self.apply_predicted_ip(ip, "discv4");
        }

        Ok(())
    }

    async fn discv4_handle_find_node(
        &mut self,
        sender_public_key: H512,
        target: H512,
        from: std::net::SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        let sender_id = node_id(&sender_public_key);
        if let Ok(contact) = self
            .discv4_validate_contact(sender_public_key, sender_id, from, "FindNode")
            .await
        {
            let target_id = node_id(&target);
            let neighbors = self.contacts.closest_nodes(target_id);

            for chunk in neighbors.chunks(8) {
                let _ = self
                    .discv4_send_neighbors(chunk.to_vec(), &contact.node)
                    .await;
            }
        }
        Ok(())
    }

    async fn discv4_handle_neighbors(
        &mut self,
        neighbors_message: NeighborsMessage,
        sender_public_key: H512,
    ) -> Result<(), DiscoveryServerError> {
        let sender_id = node_id(&sender_public_key);
        let expiration = Duration::from_secs(EXPIRATION_SECONDS);

        let discv4 = match &self.discv4 {
            Some(s) => s,
            None => return Ok(()),
        };

        match discv4.pending_find_node.get(&sender_id) {
            Some(sent_at) if sent_at.elapsed() < expiration => {}
            _ => {
                trace!(
                    protocol = "discv4",
                    from = %format!("{sender_public_key:#x}"),
                    "Dropping unsolicited Neighbors (no pending FindNode)"
                );
                return Ok(());
            }
        }

        let nodes = neighbors_message.nodes;
        self.contacts
            .new_contacts(nodes.clone(), DiscoveryProtocol::Discv4)
            .await;

        // Feed results into ALL active lookups (but don't advance — the timer
        // drives lookup progress so that traffic stays controlled).
        if let Some(discv4) = &mut self.discv4 {
            let entries: Vec<(H256, Node)> =
                nodes.iter().map(|n| (n.node_id(), n.clone())).collect();
            for (lookup, _) in &mut discv4.active_lookups {
                lookup.feed_results(entries.clone());
            }
            if let Some((lookup, _)) = discv4.active_lookups.first_mut() {
                lookup.record_response();
            }
        }

        Ok(())
    }

    async fn discv4_handle_enr_request(
        &mut self,
        sender_public_key: H512,
        from: std::net::SocketAddr,
        hash: H256,
    ) -> Result<(), DiscoveryServerError> {
        let node_id = node_id(&sender_public_key);

        if self
            .discv4_validate_contact(sender_public_key, node_id, from, "ENRRequest")
            .await
            .is_err()
        {
            return Ok(());
        }

        if self.discv4_send_enr_response(hash, from).await.is_err() {
            return Ok(());
        }

        self.contacts.mark_knows_us(&node_id);
        Ok(())
    }

    async fn discv4_handle_enr_response(
        &mut self,
        sender_public_key: H512,
        from: std::net::SocketAddr,
        enr_response_message: ENRResponseMessage,
    ) -> Result<(), DiscoveryServerError> {
        let node_id = node_id(&sender_public_key);

        if self
            .discv4_validate_enr_response(sender_public_key, node_id, from)
            .await
            .is_err()
        {
            return Ok(());
        }

        self.contacts.record_enr_response_received(
            node_id,
            enr_response_message.request_hash,
            enr_response_message.node_record.clone(),
        );

        Ok(())
    }

    async fn discv4_validate_contact(
        &mut self,
        sender_public_key: H512,
        node_id: H256,
        from: std::net::SocketAddr,
        message_type: &str,
    ) -> Result<Contact, DiscoveryServerError> {
        match self.contacts.validate_contact(node_id, from.ip()) {
            ContactValidation::UnknownContact => {
                debug!(protocol = "discv4", received = message_type, to = %format!("{sender_public_key:#x}"), "Unknown contact, skipping");
                Err(DiscoveryServerError::InvalidContact)
            }
            ContactValidation::InvalidContact => {
                debug!(protocol = "discv4", received = message_type, to = %format!("{sender_public_key:#x}"), "Contact not validated, skipping");
                Err(DiscoveryServerError::InvalidContact)
            }
            ContactValidation::IpMismatch => {
                debug!(protocol = "discv4", received = message_type, to = %format!("{sender_public_key:#x}"), "IP address mismatch, skipping");
                Err(DiscoveryServerError::InvalidContact)
            }
            ContactValidation::Valid(contact) => Ok(*contact),
        }
    }

    async fn discv4_validate_enr_response(
        &mut self,
        sender_public_key: H512,
        node_id: H256,
        from: std::net::SocketAddr,
    ) -> Result<(), DiscoveryServerError> {
        let contact = self
            .discv4_validate_contact(sender_public_key, node_id, from, "ENRResponse")
            .await?;
        if !contact.has_pending_enr_request() {
            debug!(protocol = "discv4", received = "ENRResponse", from = %format!("{sender_public_key:#x}"), "unsolicited message received, skipping");
            return Err(DiscoveryServerError::InvalidContact);
        }
        Ok(())
    }

    async fn discv4_send(
        &mut self,
        message: Message,
        addr: std::net::SocketAddr,
    ) -> Result<usize, DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv4_outgoing(message.metric_label());
        }
        let mut buf = BytesMut::new();
        message.encode_with_header(&mut buf, &self.signer);
        Ok(self.udp_socket.send_to(&buf, addr).await.inspect_err(
            |e| debug!(protocol = "discv4", sending = ?message, addr = ?addr, err=?e, "Error sending message"),
        )?)
    }

    async fn discv4_send_else_dispose(
        &mut self,
        message: Message,
        node: &Node,
    ) -> Result<H256, DiscoveryServerError> {
        #[cfg(feature = "metrics")]
        {
            use ethrex_metrics::p2p::METRICS_P2P;
            METRICS_P2P.inc_discv4_outgoing(message.metric_label());
        }
        let mut buf = BytesMut::new();
        message.encode_with_header(&mut buf, &self.signer);
        let message_hash: [u8; 32] = buf[..32]
            .try_into()
            .expect("first 32 bytes are the message hash");
        if let Err(e) = self.udp_socket.send_to(&buf, node.udp_addr()).await {
            debug!(protocol = "discv4", sending = ?message, addr = ?node.udp_addr(), to = ?node.node_id(), err=?e, "Error sending message");
            self.contacts.set_disposable(&node.node_id());
            METRICS.record_new_discarded_node();
            return Err(e.into());
        }
        Ok(H256::from(message_hash))
    }
}
