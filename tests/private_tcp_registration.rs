use hbb_common::{
    private_tcp::{register_client, ClientHandshake, ServerHandshake, MAX_PLAINTEXT},
    protobuf::Message,
    rendezvous_proto::*,
    sodiumoxide::{self, crypto::sign},
    tcp::FramedStream,
    tokio,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Success,
    Plaintext,
    OldServer,
    WrongPin,
    WrongMessage,
    WrongIdentity,
    StorageFailure,
    Oversize,
    ResetAfterProof,
}

async fn receive(stream: &mut FramedStream) -> Option<RendezvousMessage> {
    match stream.next_timeout(1000).await {
        Some(Ok(bytes)) => Some(RendezvousMessage::parse_from_bytes(&bytes).unwrap()),
        _ => None,
    }
}

async fn server(
    mode: Mode,
) -> (
    std::net::SocketAddr,
    sign::PublicKey,
    tokio::task::JoinHandle<()>,
) {
    sodiumoxide::init().unwrap();
    let (public, original) = sign::gen_keypair();
    let secret = if mode == Mode::WrongPin {
        sign::gen_keypair().1
    } else {
        original
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        if mode == Mode::ResetAfterProof {
            tcp.set_linger(Some(Duration::ZERO)).unwrap();
        }
        let local = tcp.local_addr().unwrap();
        let mut stream = FramedStream::from(tcp, local);
        stream.set_send_timeout(1000);
        let hello = receive(&mut stream).await.unwrap();
        if mode == Mode::OldServer {
            return;
        }
        let pending =
            ServerHandshake::new(hello.private_tcp_hello(), &secret, Instant::now()).unwrap();
        let mut message = RendezvousMessage::new();
        message.set_private_tcp_challenge(pending.challenge().clone());
        stream.send(&message).await.unwrap();
        let proof = match receive(&mut stream).await {
            Some(proof) => proof,
            None => return,
        };
        let mut cipher = pending
            .finish(proof.private_tcp_proof(), Instant::now())
            .unwrap();
        if mode == Mode::ResetAfterProof {
            return;
        }
        let result = match mode {
            Mode::WrongIdentity => register_pk_response::Result::UUID_MISMATCH,
            Mode::StorageFailure => register_pk_response::Result::SERVER_ERROR,
            _ => register_pk_response::Result::OK,
        };
        let mut ack = RendezvousMessage::new();
        ack.set_register_pk_response(RegisterPkResponse {
            result: result.into(),
            keep_alive: 10,
            ..Default::default()
        });
        if mode == Mode::WrongMessage {
            ack.set_register_peer_response(RegisterPeerResponse::new());
        }
        if mode == Mode::Plaintext {
            stream.send(&ack).await.unwrap();
            return;
        }
        if mode == Mode::Oversize {
            message.set_private_tcp_frame(PrivateTcpFrame {
                ciphertext: vec![0; MAX_PLAINTEXT + 256].into(),
                ..Default::default()
            });
            let _ = stream.send(&message).await;
            return;
        }
        message.set_private_tcp_frame(cipher.seal(&ack).unwrap());
        stream.send(&message).await.unwrap();
        if mode == Mode::Success {
            let frame = receive(&mut stream).await.unwrap();
            let heartbeat = cipher.open(frame.private_tcp_frame()).unwrap();
            assert_eq!(heartbeat.register_peer().id, "ZBX-TEST");
            ack.set_register_peer_response(RegisterPeerResponse::new());
            message.set_private_tcp_frame(cipher.seal(&ack).unwrap());
            stream.send(&message).await.unwrap();
        }
    });
    (addr, public, task)
}

async fn stream(addr: std::net::SocketAddr) -> FramedStream {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let local = tcp.local_addr().unwrap();
    FramedStream::from(tcp, local)
}

#[tokio::test]
async fn private_tcp_registration_requires_encrypted_ok_and_returns_live_channel() {
    let (addr, public, task) = server(Mode::Success).await;
    let (_, device) = sign::gen_keypair();
    let state =
        ClientHandshake::new("ZBX-TEST".into(), b"machine".to_vec(), &device.public_key()).unwrap();
    let mut stream = stream(addr).await;
    let (mut cipher, keep_alive) = register_client(&mut stream, state, &public, &device)
        .await
        .unwrap();
    assert!(keep_alive > Duration::ZERO && keep_alive <= Duration::from_secs(10));
    let mut message = RendezvousMessage::new();
    message.set_register_peer(RegisterPeer {
        id: "ZBX-TEST".into(),
        ..Default::default()
    });
    message.set_private_tcp_frame(cipher.seal(&message).unwrap());
    stream.send(&message).await.unwrap();
    let reply = receive(&mut stream).await.unwrap();
    assert!(matches!(
        cipher.open(reply.private_tcp_frame()).unwrap().union,
        Some(rendezvous_message::Union::RegisterPeerResponse(_))
    ));
    task.await.unwrap();
}

async fn rejected(mode: Mode, expected: &str) {
    let (addr, public, task) = server(mode).await;
    let (_, device) = sign::gen_keypair();
    let state =
        ClientHandshake::new("ZBX-TEST".into(), b"machine".to_vec(), &device.public_key()).unwrap();
    let mut stream = stream(addr).await;
    let result = register_client(&mut stream, state, &public, &device).await;
    assert_eq!(
        result.err().expect("must not register").to_string(),
        expected
    );
    drop(stream);
    task.await.unwrap();
}

#[tokio::test]
async fn private_tcp_registration_rejects_plaintext_success() {
    rejected(Mode::Plaintext, "private_tcp_unencrypted_message").await;
}

#[tokio::test]
async fn private_tcp_registration_reports_old_server_without_fallback() {
    rejected(Mode::OldServer, "server_tcp_unsupported").await;
}

#[tokio::test]
async fn private_tcp_registration_rejects_wrong_pin() {
    rejected(Mode::WrongPin, "private_tcp_server_identity_mismatch").await;
}

#[tokio::test]
async fn private_tcp_registration_rejects_other_encrypted_message() {
    rejected(Mode::WrongMessage, "private_tcp_unexpected_registration").await;
}

#[tokio::test]
async fn private_tcp_registration_never_accepts_identity_rejection() {
    rejected(Mode::WrongIdentity, "identity_mismatch").await;
}

#[tokio::test]
async fn private_tcp_registration_never_accepts_failed_persistence() {
    rejected(Mode::StorageFailure, "private_tcp_registration_failed").await;
}

#[tokio::test]
async fn private_tcp_registration_bounds_outer_frames_before_parsing() {
    rejected(Mode::Oversize, "private_tcp_invalid_frame").await;
}

#[tokio::test]
async fn private_tcp_reset_after_verified_challenge_cannot_downgrade_authentication() {
    rejected(Mode::ResetAfterProof, "private_tcp_registration_failed").await;
}
