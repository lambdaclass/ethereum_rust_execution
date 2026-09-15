use bytes::Bytes;
use ethrex_common::H256;
use ethrex_p2p::discovery::DiscoveryServer;
use ethrex_p2p::discovery::{ContactTable, Session as ContactSession};
use ethrex_p2p::discv5::messages::PongMessage;
use ethrex_p2p::peer_filter::AcceptAllFilter;
use ethrex_p2p::types::{Node, NodeRecord};
use rand::{SeedableRng, rngs::StdRng};
use rustc_hash::FxHashSet;
use secp256k1::SecretKey;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::net::UdpSocket;

async fn test_server() -> DiscoveryServer {
    let local_node = Node::from_enode_url(
        "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    ).expect("Bad enode url");
    let signer = SecretKey::new(&mut rand::rngs::OsRng);
    let local_node_record = NodeRecord::from_node(&local_node, 1, &signer).unwrap();
    DiscoveryServer::new_for_discv5_test(
        local_node,
        local_node_record,
        signer,
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        Box::new(AcceptAllFilter),
    )
}

/// Helper to get a mutable reference to the discv5 state.
fn discv5(server: &mut DiscoveryServer) -> &mut ethrex_p2p::discv5::server::Discv5State {
    server.discv5.as_mut().expect("discv5 state must exist")
}

#[tokio::test]
async fn test_next_nonce_counter() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut server = test_server().await;

    let n1 = discv5(&mut server).next_nonce(&mut rng);
    let n2 = discv5(&mut server).next_nonce(&mut rng);

    assert_eq!(&n1[..4], &[0, 0, 0, 0]);
    assert_eq!(&n2[..4], &[0, 0, 0, 1]);
    assert_ne!(&n1[4..], &n2[4..]);
}

#[tokio::test]
async fn test_whoareyou_rate_limiting() {
    let mut server = test_server().await;

    let nonce = [0u8; 12];
    // Use a public IP so rate limiting is actually exercised (private IPs are exempt).
    let addr: SocketAddr = "8.8.8.8:30303".parse().unwrap();
    let src_id1 = H256::from_low_u64_be(1);
    let src_id2 = H256::from_low_u64_be(2);
    let src_id3 = H256::from_low_u64_be(3);

    assert!(discv5(&mut server).whoareyou_rate_limit.is_empty());

    let _ = server.discv5_send_who_are_you(nonce, src_id1, addr).await;

    // Rate limit is keyed by (IP, node_id)
    assert!(
        discv5(&mut server)
            .whoareyou_rate_limit
            .peek(&(addr.ip(), src_id1))
            .is_some()
    );
    assert!(
        discv5(&mut server)
            .pending_challenges
            .contains_key(&src_id1)
    );

    // Same IP but different node_id should NOT be rate limited
    let _ = server.discv5_send_who_are_you(nonce, src_id2, addr).await;

    assert!(
        discv5(&mut server)
            .pending_challenges
            .contains_key(&src_id2)
    );

    // Same node_id and same IP should be rate limited
    let _ = server.discv5_send_who_are_you(nonce, src_id1, addr).await;

    let addr2: SocketAddr = "8.8.4.4:30303".parse().unwrap();
    let _ = server.discv5_send_who_are_you(nonce, src_id3, addr2).await;

    assert!(
        discv5(&mut server)
            .pending_challenges
            .contains_key(&src_id3)
    );
    assert_eq!(discv5(&mut server).whoareyou_rate_limit.len(), 3);
}

#[tokio::test]
async fn test_global_whoareyou_rate_limiting() {
    let mut server = test_server().await;
    let nonce = [0u8; 12];

    discv5(&mut server).whoareyou_global_window_start = Instant::now();

    // Send 100 WHOAREYOU packets to different IPs (hits global limit)
    for i in 0..100u32 {
        let ip = format!("10.0.{}.{}", i / 256, i % 256);
        let addr: SocketAddr = format!("{ip}:30303").parse().unwrap();
        let src_id = H256::from_low_u64_be(i as u64 + 1);
        let _ = server.discv5_send_who_are_you(nonce, src_id, addr).await;
    }
    assert_eq!(discv5(&mut server).pending_challenges.len(), 100);

    // The 101st packet from a new IP should be dropped by the global limit
    let addr_over_limit: SocketAddr = "10.1.0.0:30303".parse().unwrap();
    let src_id_over = H256::from_low_u64_be(1000);
    let _ = server
        .discv5_send_who_are_you(nonce, src_id_over, addr_over_limit)
        .await;
    assert!(
        !discv5(&mut server)
            .pending_challenges
            .contains_key(&src_id_over)
    );
    assert_eq!(discv5(&mut server).pending_challenges.len(), 100);
}

#[tokio::test]
async fn test_whoareyou_rate_limit_lru_cache_works() {
    let mut server = test_server().await;
    let nonce = [0u8; 12];

    // Bypass the global rate limit so we can insert many entries
    discv5(&mut server).whoareyou_global_window_start =
        Instant::now() - std::time::Duration::from_secs(10);

    for i in 0..200u32 {
        discv5(&mut server).whoareyou_global_count = 0;
        let ip = format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256);
        let addr: SocketAddr = format!("{ip}:30303").parse().unwrap();
        let src_id = H256::from_low_u64_be(i as u64 + 1);
        let _ = server.discv5_send_who_are_you(nonce, src_id, addr).await;
    }

    assert_eq!(discv5(&mut server).whoareyou_rate_limit.len(), 200);
    assert!(discv5(&mut server).whoareyou_rate_limit.len() <= 10_000);
}

#[tokio::test]
async fn test_enr_update_request_on_pong() {
    let local_node = Node::from_enode_url(
        "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    ).expect("Bad enode url");
    let signer = SecretKey::new(&mut rand::rngs::OsRng);
    let local_node_record = NodeRecord::from_node(&local_node, 1, &signer).unwrap();

    let remote_signer = SecretKey::new(&mut rand::rngs::OsRng);
    let remote_node_template = Node::from_enode_url(
        "enode://a448f24c6d18e575453db127a3d8eeeea3e3426f0db43bd52067d85cc5a1e87ad09f44b2bbaa66bb3a8c47cff8082ca4cde4b03f5ba52c1e92b3d2b9125d6da5@127.0.0.1:30304",
    ).expect("Bad enode url");

    let remote_record = NodeRecord::from_node(&remote_node_template, 5, &remote_signer).unwrap();
    let remote_node = Node::from_enr(&remote_record).expect("Should create node from record");
    let remote_node_id = remote_node.node_id();

    let mut contacts = ContactTable::new(local_node.node_id(), 10, Box::new(AcceptAllFilter));
    contacts.new_contact_records(vec![remote_record]).await;
    contacts.set_session(
        remote_node_id,
        ContactSession {
            outbound_key: [0u8; 16],
            inbound_key: [0u8; 16],
        },
    );

    let mut server = DiscoveryServer::new_for_discv5_test(
        local_node,
        local_node_record,
        signer,
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        Box::new(AcceptAllFilter),
    );
    *server.contacts_mut() = contacts;

    let contact = server.contacts_mut().get_contact(&remote_node_id).cloned();
    assert!(
        contact.is_some(),
        "Contact should have been added to the contact table"
    );
    let contact = contact.unwrap();
    assert_eq!(
        contact.record.as_ref().map(|r| r.seq),
        Some(5),
        "Contact should have ENR with seq=5"
    );

    // Test 1: PONG with same enr_seq should NOT trigger FINDNODE
    let pong_same_seq = PongMessage {
        req_id: Bytes::from(vec![1, 2, 3]),
        enr_seq: 5,
        recipient_addr: "127.0.0.1:30303".parse().unwrap(),
    };
    let initial_pending_count = discv5(&mut server).pending_by_nonce.len();
    server
        .discv5_handle_pong(pong_same_seq, remote_node_id)
        .await
        .expect("handle_pong failed for matching enr_seq");
    assert_eq!(
        discv5(&mut server).pending_by_nonce.len(),
        initial_pending_count
    );

    // Test 2: PONG with higher enr_seq should trigger FINDNODE
    let pong_higher_seq = PongMessage {
        req_id: Bytes::from(vec![4, 5, 6]),
        enr_seq: 10,
        recipient_addr: "127.0.0.1:30303".parse().unwrap(),
    };
    server
        .discv5_handle_pong(pong_higher_seq, remote_node_id)
        .await
        .expect("handle_pong failed for higher enr_seq");
    assert_eq!(
        discv5(&mut server).pending_by_nonce.len(),
        initial_pending_count + 1
    );

    // Test 3: PONG with lower enr_seq should NOT trigger FINDNODE
    let pong_lower_seq = PongMessage {
        req_id: Bytes::from(vec![7, 8, 9]),
        enr_seq: 3,
        recipient_addr: "127.0.0.1:30303".parse().unwrap(),
    };
    server
        .discv5_handle_pong(pong_lower_seq, remote_node_id)
        .await
        .expect("handle_pong failed for lower enr_seq");
    assert_eq!(
        discv5(&mut server).pending_by_nonce.len(),
        initial_pending_count + 1
    );
}

#[tokio::test]
async fn test_ip_voting_updates_ip_on_threshold() {
    let mut server = test_server().await;
    let original_ip = server.local_node.ip;

    let new_ip: IpAddr = "203.0.113.50".parse().unwrap();
    let voter1 = H256::from_low_u64_be(1);
    let voter2 = H256::from_low_u64_be(2);
    let voter3 = H256::from_low_u64_be(3);

    assert_eq!(server.ip_predictor.record_ip_vote(new_ip, voter1), None);
    assert_eq!(server.local_node.ip, original_ip);

    assert_eq!(server.ip_predictor.record_ip_vote(new_ip, voter2), None);
    assert_eq!(server.local_node.ip, original_ip);

    // Vote 3 triggers round end and returns the winning IP
    let result = server.ip_predictor.record_ip_vote(new_ip, voter3);
    assert_eq!(result, Some(new_ip));
    assert!(server.ip_predictor.ip_votes.is_empty());

    // Applying the winner must update the local node IP (the point of the test).
    server.apply_predicted_ip(result.unwrap(), "test");
    assert_eq!(server.local_node.ip, new_ip);
    assert_ne!(server.local_node.ip, original_ip);
}

#[tokio::test]
async fn test_ip_voting_same_peer_votes_once() {
    let mut server = test_server().await;

    let new_ip: IpAddr = "203.0.113.50".parse().unwrap();
    let same_voter = H256::from_low_u64_be(1);

    server.ip_predictor.record_ip_vote(new_ip, same_voter);
    server.ip_predictor.record_ip_vote(new_ip, same_voter);
    server.ip_predictor.record_ip_vote(new_ip, same_voter);

    assert_eq!(
        server.ip_predictor.ip_votes.get(&new_ip).map(|v| v.len()),
        Some(1)
    );
}

#[tokio::test]
async fn test_ip_voting_no_update_if_same_ip() {
    let mut server = test_server().await;
    let original_ip = server.local_node.ip;

    let voter1 = H256::from_low_u64_be(1);
    let voter2 = H256::from_low_u64_be(2);
    let voter3 = H256::from_low_u64_be(3);

    server.ip_predictor.record_ip_vote(original_ip, voter1);
    server.ip_predictor.record_ip_vote(original_ip, voter2);
    server.ip_predictor.record_ip_vote(original_ip, voter3);

    assert_eq!(server.local_node.ip, original_ip);
    assert!(server.ip_predictor.ip_votes.is_empty());
    assert!(server.ip_predictor.first_ip_vote_round_completed);
}

#[tokio::test]
async fn test_handle_pong_same_ip_does_not_bump_enr_seq() {
    let mut server = test_server().await;
    let original_ip = server.local_node.ip;
    let original_seq = server.local_node_record.seq;

    let recipient_addr = SocketAddr::new(original_ip, 30303);
    let make_pong = || PongMessage {
        // No matching PING set up in peer_table; record_pong_received silently ignores it.
        req_id: Bytes::from_static(b""),
        enr_seq: 0,
        recipient_addr,
    };

    for i in 1..=3u64 {
        server
            .discv5_handle_pong(make_pong(), H256::from_low_u64_be(i))
            .await
            .unwrap();
    }

    // Round must have actually completed; otherwise the guard at discv5_handle_pong
    // is never evaluated and the assertions below would trivially pass.
    assert!(server.ip_predictor.first_ip_vote_round_completed);
    // Voting round reached threshold with the local IP as winner; the guard at
    // apply_predicted_ip must skip update_local_ip and leave the ENR sequence intact.
    assert_eq!(server.local_node.ip, original_ip);
    assert_eq!(server.local_node_record.seq, original_seq);
}

#[tokio::test]
async fn test_ip_voting_split_votes_no_update() {
    let mut server = test_server().await;
    let original_ip = server.local_node.ip;

    let ip1: IpAddr = "203.0.113.50".parse().unwrap();
    let ip2: IpAddr = "203.0.113.51".parse().unwrap();
    let voter1 = H256::from_low_u64_be(1);
    let voter2 = H256::from_low_u64_be(2);
    let voter3 = H256::from_low_u64_be(3);

    server.ip_predictor.record_ip_vote(ip1, voter1);
    assert_eq!(server.local_node.ip, original_ip);

    server.ip_predictor.record_ip_vote(ip2, voter2);
    assert_eq!(server.local_node.ip, original_ip);

    server.ip_predictor.record_ip_vote(ip1, voter3);
    assert_eq!(server.local_node.ip, original_ip);
    assert!(server.ip_predictor.ip_votes.is_empty());
    assert!(server.ip_predictor.first_ip_vote_round_completed);
}

#[tokio::test]
async fn test_ip_vote_cleanup() {
    let mut server = test_server().await;

    let ip: IpAddr = "203.0.113.50".parse().unwrap();
    let voter1 = H256::from_low_u64_be(1);

    let mut voters = FxHashSet::default();
    voters.insert(voter1);
    server.ip_predictor.ip_votes.insert(ip, voters);
    server.ip_predictor.ip_vote_period_start = Some(Instant::now());
    assert_eq!(server.ip_predictor.ip_votes.len(), 1);

    server.ip_predictor.check_timeout();
    assert_eq!(server.ip_predictor.ip_votes.len(), 1);

    assert!(!server.ip_predictor.first_ip_vote_round_completed);
}

#[tokio::test]
async fn test_ip_voting_ignores_unroutable_but_keeps_private() {
    let mut server = test_server().await;
    let voter1 = H256::from_low_u64_be(1);

    // Unroutable addresses can never be a valid externally-advertised endpoint
    // and must be dropped: loopback, link-local, unspecified (v4 and v6). Each
    // is ignored, so `ip_votes` stays empty (and no round ever starts).
    for unroutable in [
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "::",
    ] {
        let ip: IpAddr = unroutable.parse().unwrap();
        server.ip_predictor.record_ip_vote(ip, voter1);
        assert!(
            server.ip_predictor.ip_votes.is_empty(),
            "unroutable {unroutable} must not be recorded as a vote"
        );
    }

    // RFC1918 (IPv4 private) and IPv6 unique-local are *kept* as candidates: on
    // a flat private network they are the address peers actually reach us at (a
    // public IP still wins if one reaches quorum). Single votes stay below
    // IP_VOTE_THRESHOLD so the round doesn't finalize and clear the map.
    let private_v4: IpAddr = "192.168.1.100".parse().unwrap();
    server.ip_predictor.record_ip_vote(private_v4, voter1);
    assert_eq!(
        server
            .ip_predictor
            .ip_votes
            .get(&private_v4)
            .map(|v| v.len()),
        Some(1),
        "RFC1918 private IPv4 must remain a valid vote candidate"
    );

    let ula_v6: IpAddr = "fd12::1".parse().unwrap();
    server.ip_predictor.record_ip_vote(ula_v6, voter1);
    assert_eq!(
        server.ip_predictor.ip_votes.get(&ula_v6).map(|v| v.len()),
        Some(1),
        "IPv6 unique-local must remain a valid vote candidate"
    );
}
