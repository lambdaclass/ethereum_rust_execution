use crate::rlpx::utils::pubkey2id;
use aes::{
    cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher},
    Aes256Enc,
};
use bytes::Bytes;
use ethereum_rust_core::{
    rlp::{
        decode::RLPDecode,
        encode::RLPEncode,
        structs::{Decoder, Encoder},
    },
    H128, H256, H512,
};
use k256::PublicKey;
use sha3::{Digest, Keccak256};
use std::pin::pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SUPPORTED_CAPABILITIES: [(&str, u8); 1] = [("p2p", 5)];

pub(crate) type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

/// Fully working RLPx connection.
pub(crate) struct RLPxConnection {
    #[allow(unused)]
    state: RLPxState,
    // ...capabilities information
}

/// RLPx connection which is pending the receive of a Hello message.
pub(crate) struct RLPxConnectionPending {
    state: RLPxState,
}

impl RLPxConnectionPending {
    pub fn new(state: RLPxState) -> Self {
        Self { state }
    }

    pub async fn send_hello<S: AsyncWrite>(&mut self, node_pk: &PublicKey, stream: S) {
        let mut stream = pin!(stream);

        let egress_aes = &mut self.state.egress_aes;
        let egress_mac = &mut self.state.egress_mac;

        let mac_aes_cipher = Aes256Enc::new_from_slice(&self.state.mac_key.0).unwrap();

        // Generate Hello message
        // [protocolVersion: P, clientId: B, capabilities, listenPort: P, nodeKey: B_64, ...]
        let msg_id = 1_u8;
        let protocol_version = 5_u8;
        let client_id = "Ethereum(++)/1.0.0";
        let capabilities = SUPPORTED_CAPABILITIES.to_vec();
        let listen_port = 0_u8; // This one is ignored
        let node_id = pubkey2id(node_pk);
        let mut frame_data = vec![];
        msg_id.encode(&mut frame_data);
        Encoder::new(&mut frame_data)
            .encode_field(&protocol_version)
            .encode_field(&client_id)
            .encode_field(&capabilities)
            .encode_field(&listen_port)
            .encode_field(&node_id)
            .finish();

        // header = frame-size || header-data || header-padding
        let mut header = Vec::with_capacity(32);
        let frame_size = frame_data.len().to_be_bytes();
        header.extend_from_slice(&frame_size[5..8]);
        // header-data = [capability-id, context-id]  (both always zero)
        let header_data = (0_u8, 0_u8);
        header_data.encode(&mut header);

        header.resize(16, 0);
        egress_aes.apply_keystream(&mut header[..16]);

        let header_mac_seed = {
            let mac_digest: [u8; 16] = egress_mac.clone().finalize()[..16].try_into().unwrap();
            let mut seed = mac_digest.into();
            mac_aes_cipher.encrypt_block(&mut seed);
            H128(seed.into()) ^ H128(header[..16].try_into().unwrap())
        };
        egress_mac.update(header_mac_seed);
        let header_mac = egress_mac.clone().finalize();
        header.extend_from_slice(&header_mac[..16]);

        // Write header
        stream.write_all(&header).await.unwrap();

        // Pad to next multiple of 16
        frame_data.resize(frame_data.len().next_multiple_of(16), 0);
        egress_aes.apply_keystream(&mut frame_data);
        let frame_ciphertext = frame_data;

        // Send frame
        stream.write_all(&frame_ciphertext).await.unwrap();

        // Compute frame-mac
        egress_mac.update(&frame_ciphertext);

        // frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
        let frame_mac_seed = {
            let mac_digest: [u8; 16] = egress_mac.clone().finalize()[..16].try_into().unwrap();
            let mut seed = mac_digest.into();
            mac_aes_cipher.encrypt_block(&mut seed);
            (H128(seed.into()) ^ H128(mac_digest)).0
        };
        egress_mac.update(frame_mac_seed);
        let frame_mac = egress_mac.clone().finalize();

        // Send frame-mac
        stream.write_all(&frame_mac[..16]).await.unwrap();
    }

    pub async fn receive_hello<S: AsyncRead>(self, stream: S) -> RLPxConnection {
        let mut stream = pin!(stream);

        let Self { mut state } = self;

        let ingress_aes = &mut state.ingress_aes;
        let ingress_mac = &mut state.ingress_mac;

        let mac_aes_cipher = Aes256Enc::new_from_slice(&state.mac_key.0).unwrap();

        // Receive the hello message's frame header
        let mut frame_header = [0; 32];
        stream.read_exact(&mut frame_header).await.unwrap();
        // Both are padded to the block's size (16 bytes)
        let (header_ciphertext, header_mac) = frame_header.split_at_mut(16);

        // Validate MAC header
        // header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
        let header_mac_seed = {
            let mac_digest: [u8; 16] = ingress_mac.clone().finalize()[..16].try_into().unwrap();
            let mut seed = mac_digest.into();
            mac_aes_cipher.encrypt_block(&mut seed);
            (H128(seed.into()) ^ H128(header_ciphertext.try_into().unwrap())).0
        };

        // ingress-mac = keccak256.update(ingress-mac, header-mac-seed)
        ingress_mac.update(header_mac_seed);

        // header-mac = keccak256.digest(egress-mac)[:16]
        let expected_header_mac = H128(ingress_mac.clone().finalize()[..16].try_into().unwrap());

        assert_eq!(header_mac, expected_header_mac.0);

        let header_text = header_ciphertext;
        ingress_aes.apply_keystream(header_text);

        // header-data = [capability-id, context-id]
        // Both are unused, and always zero
        assert_eq!(&header_text[3..6], &(0_u8, 0_u8).encode_to_vec());

        let frame_size: usize =
            u32::from_be_bytes([0, header_text[0], header_text[1], header_text[2]])
                .try_into()
                .unwrap();
        // Receive the hello message
        let padded_size = frame_size.next_multiple_of(16);
        let mut frame_data = vec![0; padded_size + 16];
        stream.read_exact(&mut frame_data).await.unwrap();
        let (frame_ciphertext, frame_mac) = frame_data.split_at_mut(padded_size);

        // check MAC
        #[allow(clippy::needless_borrows_for_generic_args)]
        ingress_mac.update(&frame_ciphertext);
        let frame_mac_seed = {
            let mac_digest: [u8; 16] = ingress_mac.clone().finalize()[..16].try_into().unwrap();
            let mut seed = mac_digest.into();
            mac_aes_cipher.encrypt_block(&mut seed);
            (H128(seed.into()) ^ H128(mac_digest)).0
        };
        ingress_mac.update(frame_mac_seed);
        let expected_frame_mac: [u8; 16] = ingress_mac.clone().finalize()[..16].try_into().unwrap();

        assert_eq!(frame_mac, expected_frame_mac);

        // decrypt frame
        ingress_aes.apply_keystream(frame_ciphertext);

        let (frame_data, _padding) = frame_ciphertext.split_at(frame_size);

        let (msg_id, msg_data): (u8, _) = RLPDecode::decode_unfinished(frame_data).unwrap();

        // Hello has an ID of 0x00
        assert_eq!(msg_id, 0);

        // decode hello message: [protocolVersion: P, clientId: B, capabilities, listenPort: P, nodeId: B_64, ...]
        let decoder = Decoder::new(msg_data).unwrap();
        let (protocol_version, decoder): (u64, _) =
            decoder.decode_field("protocolVersion").unwrap();

        assert_eq!(protocol_version, 5, "only protocol version 5 is supported");

        let (_client_id, decoder): (String, _) = decoder.decode_field("clientId").unwrap();
        // TODO: store client id for debugging purposes

        // [[cap1, capVersion1], [cap2, capVersion2], ...]
        let (_capabilities, decoder): (Vec<(Bytes, u64)>, _) =
            decoder.decode_field("capabilities").unwrap();
        // TODO: derive shared capabilities for further communication

        // This field should be ignored
        let (_listen_port, decoder): (u16, _) = decoder.decode_field("listenPort").unwrap();

        let (_node_id, decoder): (H512, _) = decoder.decode_field("nodeId").unwrap();
        // TODO: check node id is the one we expect

        // Implementations must ignore any additional list elements
        let _padding = decoder.finish_unchecked();

        RLPxConnection { state }
    }
}

/// The current state of an RLPx connection
#[derive(Clone)]
pub(crate) struct RLPxState {
    // TODO: maybe discard aes_key, since we only need the cipher
    // TODO: maybe precompute some values that are used more than once
    #[allow(unused)]
    aes_key: H256,
    mac_key: H256,
    ingress_mac: Keccak256,
    egress_mac: Keccak256,
    ingress_aes: Aes256Ctr64BE,
    egress_aes: Aes256Ctr64BE,
}

impl RLPxState {
    pub fn new(
        aes_key: H256,
        mac_key: H256,
        local_nonce: H256,
        local_init_message: &[u8],
        remote_nonce: H256,
        remote_init_message: &[u8],
    ) -> Self {
        // egress-mac = keccak256.init((mac-secret ^ remote-nonce) || auth)
        let egress_mac = Keccak256::default()
            .chain_update(mac_key ^ remote_nonce)
            .chain_update(local_init_message);

        // ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
        let ingress_mac = Keccak256::default()
            .chain_update(mac_key ^ local_nonce)
            .chain_update(remote_init_message);

        let ingress_aes = <Aes256Ctr64BE as KeyIvInit>::new(&aes_key.0.into(), &[0; 16].into());
        let egress_aes = ingress_aes.clone();

        Self {
            aes_key,
            mac_key,
            ingress_mac,
            egress_mac,
            ingress_aes,
            egress_aes,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rlpx::handshake::RLPxLocalClient;
    use hex_literal::hex;
    use k256::SecretKey;

    #[test]
    fn test_ack_decoding() {
        // This is the Ack₂ message from EIP-8.
        let msg = hex!("01ea0451958701280a56482929d3b0757da8f7fbe5286784beead59d95089c217c9b917788989470b0e330cc6e4fb383c0340ed85fab836ec9fb8a49672712aeabbdfd1e837c1ff4cace34311cd7f4de05d59279e3524ab26ef753a0095637ac88f2b499b9914b5f64e143eae548a1066e14cd2f4bd7f814c4652f11b254f8a2d0191e2f5546fae6055694aed14d906df79ad3b407d94692694e259191cde171ad542fc588fa2b7333313d82a9f887332f1dfc36cea03f831cb9a23fea05b33deb999e85489e645f6aab1872475d488d7bd6c7c120caf28dbfc5d6833888155ed69d34dbdc39c1f299be1057810f34fbe754d021bfca14dc989753d61c413d261934e1a9c67ee060a25eefb54e81a4d14baff922180c395d3f998d70f46f6b58306f969627ae364497e73fc27f6d17ae45a413d322cb8814276be6ddd13b885b201b943213656cde498fa0e9ddc8e0b8f8a53824fbd82254f3e2c17e8eaea009c38b4aa0a3f306e8797db43c25d68e86f262e564086f59a2fc60511c42abfb3057c247a8a8fe4fb3ccbadde17514b7ac8000cdb6a912778426260c47f38919a91f25f4b5ffb455d6aaaf150f7e5529c100ce62d6d92826a71778d809bdf60232ae21ce8a437eca8223f45ac37f6487452ce626f549b3b5fdee26afd2072e4bc75833c2464c805246155289f4");

        let static_key = hex!("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee");
        let nonce = hex!("7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6");
        let ephemeral_key =
            hex!("869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d");

        let mut client =
            RLPxLocalClient::new(nonce.into(), SecretKey::from_slice(&ephemeral_key).unwrap());

        assert_eq!(&client.ephemeral_key.to_bytes()[..], &ephemeral_key[..]);
        assert_eq!(client.nonce.0, nonce);

        let auth_data = msg[..2].try_into().unwrap();

        client.auth_message = Some(vec![]);

        let conn = client.decode_ack_message(
            &SecretKey::from_slice(&static_key).unwrap(),
            &msg[2..],
            auth_data,
        );

        let state = conn.state;

        let expected_aes_secret =
            hex!("80e8632c05fed6fc2a13b0f8d31a3cf645366239170ea067065aba8e28bac487");
        let expected_mac_secret =
            hex!("2ea74ec5dae199227dff1af715362700e989d889d7a493cb0639691efb8e5f98");

        assert_eq!(state.aes_key.0, expected_aes_secret);
        assert_eq!(state.mac_key.0, expected_mac_secret);
    }
}
