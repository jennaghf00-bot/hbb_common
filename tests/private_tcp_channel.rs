use hbb_common::{
    private_tcp::{ClientHandshake, ServerHandshake, SessionCipher},
    protobuf::Message,
    rendezvous_proto::*,
    sodiumoxide::{self, crypto::sign},
    tcp::FramedStream,
    tokio,
};
use std::time::{Duration, Instant};

struct Fixture {
    client: ClientHandshake,
    device_key: sign::SecretKey,
    server_key: sign::SecretKey,
    server_public: sign::PublicKey,
}

fn fixture() -> Fixture {
    sodiumoxide::init().unwrap();
    let (device_public, device_key) = sign::gen_keypair();
    let (server_public, server_key) = sign::gen_keypair();
    Fixture {
        client: ClientHandshake::new("ZBX-TEST".into(), b"test-machine".to_vec(), &device_public)
            .unwrap(),
        device_key,
        server_key,
        server_public,
    }
}

fn ciphers() -> (SessionCipher, SessionCipher) {
    let f = fixture();
    let now = Instant::now();
    let pending = ServerHandshake::new(f.client.hello(), &f.server_key, now).unwrap();
    let (proof, client) = f
        .client
        .respond(pending.challenge(), &f.server_public, &f.device_key)
        .unwrap();
    (client, pending.finish(&proof, now).unwrap())
}

fn heartbeat() -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_register_peer(RegisterPeer {
        id: "ZBX-TEST".into(),
        ..Default::default()
    });
    message
}

#[test]
fn private_tcp_mutual_authentication_protects_both_directions() {
    let (mut client, mut server) = ciphers();
    let message = heartbeat();
    let outbound = client.seal(&message).unwrap();
    assert!(!outbound
        .ciphertext
        .windows(8)
        .any(|bytes| bytes == b"ZBX-TEST"));
    assert_eq!(server.open(&outbound).unwrap(), message);
    let inbound = server.seal(&message).unwrap();
    assert_ne!(outbound.ciphertext, inbound.ciphertext);
    assert_eq!(client.open(&inbound).unwrap(), message);
}

#[test]
fn private_tcp_rejects_wrong_pinned_server() {
    let f = fixture();
    let pending = ServerHandshake::new(f.client.hello(), &f.server_key, Instant::now()).unwrap();
    let (wrong, _) = sign::gen_keypair();
    assert!(f
        .client
        .respond(pending.challenge(), &wrong, &f.device_key)
        .is_err());
}

#[test]
fn private_tcp_device_key_must_match_the_hello_identity() {
    let f = fixture();
    let pending = ServerHandshake::new(f.client.hello(), &f.server_key, Instant::now()).unwrap();
    let (_, wrong) = sign::gen_keypair();
    assert!(f
        .client
        .respond(pending.challenge(), &f.server_public, &wrong)
        .is_err());
}

#[test]
fn private_tcp_server_signature_covers_every_challenge_field() {
    for field in ["nonce", "ephemeral", "signature", "version"] {
        let f = fixture();
        let pending =
            ServerHandshake::new(f.client.hello(), &f.server_key, Instant::now()).unwrap();
        let mut challenge = pending.challenge().clone();
        match field {
            "nonce" => challenge.nonce = vec![0; 32].into(),
            "ephemeral" => challenge.ephemeral_key = vec![1; 32].into(),
            "signature" => challenge.signature = vec![0; 64].into(),
            _ => challenge.version = 2,
        }
        assert!(
            f.client
                .respond(&challenge, &f.server_public, &f.device_key)
                .is_err(),
            "{}",
            field
        );
    }
}

#[test]
fn private_tcp_server_signature_binds_every_hello_field() {
    for field in ["id", "uuid", "pk", "ephemeral"] {
        let f = fixture();
        let mut hello = f.client.hello().clone();
        match field {
            "id" => hello.id = "ZBX-OTHER".into(),
            "uuid" => hello.uuid = b"other-machine".to_vec().into(),
            "pk" => hello.public_key = sign::gen_keypair().0.as_ref().to_vec().into(),
            _ => hello.ephemeral_key = vec![2; 32].into(),
        }
        let pending = ServerHandshake::new(&hello, &f.server_key, Instant::now()).unwrap();
        assert!(
            f.client
                .respond(pending.challenge(), &f.server_public, &f.device_key)
                .is_err(),
            "{}",
            field
        );
    }
}

#[test]
fn private_tcp_proof_cannot_be_replayed_on_another_connection() {
    let f = fixture();
    let now = Instant::now();
    let first = ServerHandshake::new(f.client.hello(), &f.server_key, now).unwrap();
    let second = ServerHandshake::new(f.client.hello(), &f.server_key, now).unwrap();
    assert_ne!(first.challenge().nonce, second.challenge().nonce);
    let (proof, _) = f
        .client
        .respond(first.challenge(), &f.server_public, &f.device_key)
        .unwrap();
    assert!(first.finish(&proof, now).is_ok());
    assert!(second.finish(&proof, now).is_err());
}

#[test]
fn private_tcp_rejects_forged_and_unsupported_proofs() {
    for version in [1, 2] {
        let f = fixture();
        let now = Instant::now();
        let pending = ServerHandshake::new(f.client.hello(), &f.server_key, now).unwrap();
        let proof = PrivateTcpProof {
            version,
            signature: vec![0; 64].into(),
            ..Default::default()
        };
        assert!(pending.finish(&proof, now).is_err());
    }
}

#[test]
fn private_tcp_proof_deadline_is_strict() {
    for elapsed in [Duration::from_millis(9999), Duration::from_secs(10)] {
        let f = fixture();
        let now = Instant::now();
        let pending = ServerHandshake::new(f.client.hello(), &f.server_key, now).unwrap();
        let (proof, _) = f
            .client
            .respond(pending.challenge(), &f.server_public, &f.device_key)
            .unwrap();
        assert_eq!(
            pending.finish(&proof, now + elapsed).is_ok(),
            elapsed < Duration::from_secs(10)
        );
    }
}

#[test]
fn private_tcp_rejects_malformed_or_unsupported_hello_before_signing() {
    let f = fixture();
    for field in ["id", "uuid", "pk", "ephemeral", "version"] {
        let mut hello = f.client.hello().clone();
        match field {
            "id" => hello.id = "bad\nID".into(),
            "uuid" => hello.uuid = Vec::new().into(),
            "pk" => hello.public_key = vec![0; 31].into(),
            "ephemeral" => hello.ephemeral_key = vec![0; 33].into(),
            _ => hello.version = 0,
        }
        assert!(
            ServerHandshake::new(&hello, &f.server_key, Instant::now()).is_err(),
            "{}",
            field
        );
    }
    for id in ["short".to_owned(), "x".repeat(65), "with space".to_owned()] {
        assert!(ClientHandshake::new(id, vec![1], &f.device_key.public_key()).is_err());
    }
    assert!(
        ClientHandshake::new("ZBX-TEST".into(), vec![1; 257], &f.device_key.public_key()).is_err()
    );
}

#[test]
fn private_tcp_rejects_low_order_exchange_keys() {
    let f = fixture();
    let mut hello = f.client.hello().clone();
    hello.ephemeral_key = vec![0; 32].into();
    let pending = ServerHandshake::new(&hello, &f.server_key, Instant::now());
    assert!(pending.is_err());
}

#[test]
fn private_tcp_cipher_rejects_replay_and_stays_failed() {
    let (mut client, mut server) = ciphers();
    let frame = client.seal(&heartbeat()).unwrap();
    server.open(&frame).unwrap();
    assert!(server.open(&frame).is_err());
    assert!(server.open(&client.seal(&heartbeat()).unwrap()).is_err());
    assert!(server.seal(&heartbeat()).is_err());
}

#[test]
fn private_tcp_cipher_rejects_reflection_and_cross_session_frames() {
    let (mut client, _) = ciphers();
    let frame = client.seal(&heartbeat()).unwrap();
    assert!(client.open(&frame).is_err());
    let (_, mut other_server) = ciphers();
    assert!(other_server.open(&frame).is_err());
}

#[test]
fn private_tcp_cipher_rejects_corruption_and_oversize() {
    let (mut client, mut server) = ciphers();
    let mut frame = client.seal(&heartbeat()).unwrap();
    let mut bytes = frame.ciphertext.to_vec();
    bytes[0] ^= 1;
    frame.ciphertext = bytes.into();
    assert!(server.open(&frame).is_err());
    let (mut client, mut server) = ciphers();
    let mut large = RendezvousMessage::new();
    large.set_request_relay(RequestRelay {
        token: "x".repeat(65536),
        ..Default::default()
    });
    assert!(client.seal(&large).is_err());
    let large = PrivateTcpFrame {
        ciphertext: vec![0; 65553].into(),
        ..Default::default()
    };
    assert!(server.open(&large).is_err());
}

#[test]
fn private_tcp_cipher_rejects_empty_messages_and_truncated_frames() {
    let (mut client, mut server) = ciphers();
    assert!(client.seal(&RendezvousMessage::new()).is_err());
    assert!(server.open(&PrivateTcpFrame::new()).is_err());
}

#[test]
fn private_tcp_wire_tags_are_private_and_round_trip() {
    let mut messages = vec![RendezvousMessage::new(); 4];
    messages[0].set_private_tcp_hello(PrivateTcpHello::new());
    messages[1].set_private_tcp_challenge(PrivateTcpChallenge::new());
    messages[2].set_private_tcp_proof(PrivateTcpProof::new());
    messages[3].set_private_tcp_frame(PrivateTcpFrame::new());
    for (message, tag) in messages.iter().zip([0xc2, 0xca, 0xd2, 0xda]) {
        let bytes = message.write_to_bytes().unwrap();
        assert_eq!(&bytes[..2], &[tag, 0x3e]);
        assert_eq!(
            RendezvousMessage::parse_from_bytes(&bytes).unwrap(),
            *message
        );
    }
}

async fn receive(stream: &mut FramedStream) -> RendezvousMessage {
    RendezvousMessage::parse_from_bytes(&stream.next_timeout(1000).await.unwrap().unwrap()).unwrap()
}

#[tokio::test]
async fn private_tcp_handshake_and_encrypted_messages_cross_real_tcp_socket() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let Fixture {
            client,
            device_key,
            server_key,
            server_public,
        } = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let local = tcp.local_addr().unwrap();
            let mut stream = FramedStream::from(tcp, local);
            stream.set_send_timeout(1000);
            let hello = receive(&mut stream).await.private_tcp_hello().clone();
            let pending = ServerHandshake::new(&hello, &server_key, Instant::now()).unwrap();
            let mut envelope = RendezvousMessage::new();
            envelope.set_private_tcp_challenge(pending.challenge().clone());
            stream.send(&envelope).await.unwrap();
            let proof = receive(&mut stream).await.private_tcp_proof().clone();
            let mut cipher = pending.finish(&proof, Instant::now()).unwrap();
            let incoming = receive(&mut stream).await;
            assert_eq!(
                cipher.open(incoming.private_tcp_frame()).unwrap(),
                heartbeat()
            );
            let mut ack = RendezvousMessage::new();
            ack.set_register_pk_response(RegisterPkResponse::new());
            envelope.set_private_tcp_frame(cipher.seal(&ack).unwrap());
            stream.send(&envelope).await.unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let local = tcp.local_addr().unwrap();
        let mut stream = FramedStream::from(tcp, local);
        stream.set_send_timeout(1000);
        let mut envelope = RendezvousMessage::new();
        envelope.set_private_tcp_hello(client.hello().clone());
        stream.send(&envelope).await.unwrap();
        let challenge = receive(&mut stream).await;
        let (proof, mut cipher) = client
            .respond(
                challenge.private_tcp_challenge(),
                &server_public,
                &device_key,
            )
            .unwrap();
        envelope.set_private_tcp_proof(proof);
        stream.send(&envelope).await.unwrap();
        envelope.set_private_tcp_frame(cipher.seal(&heartbeat()).unwrap());
        stream.send(&envelope).await.unwrap();
        let reply = receive(&mut stream).await;
        assert!(matches!(
            cipher.open(reply.private_tcp_frame()).unwrap().union,
            Some(rendezvous_message::Union::RegisterPkResponse(_))
        ));
        server.await.unwrap();
    })
    .await
    .unwrap();
}
