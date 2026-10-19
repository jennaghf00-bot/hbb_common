use crate::{
    anyhow::{anyhow, ensure},
    protobuf::Message,
    rendezvous_proto::{
        PrivateTcpChallenge, PrivateTcpFrame, PrivateTcpHello, PrivateTcpProof, RendezvousMessage,
    },
    ResultType,
};
use sodiumoxide::{
    crypto::{kx, secretbox, sign},
    randombytes,
};
use std::time::{Duration, Instant};

pub const VERSION: u32 = 1;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_PLAINTEXT: usize = 64 * 1024;

// These objects own transient secrets; do not derive Debug or Serialize.
pub struct ClientHandshake {
    hello: PrivateTcpHello,
    ephemeral_secret: kx::SecretKey,
}

pub struct ServerHandshake {
    hello: PrivateTcpHello,
    challenge: PrivateTcpChallenge,
    server_public: sign::PublicKey,
    started: Instant,
    cipher: SessionCipher,
}

pub struct SessionCipher {
    receive_key: secretbox::Key,
    send_key: secretbox::Key,
    receive_sequence: u64,
    send_sequence: u64,
    failed: bool,
}

fn validate_hello(hello: &PrivateTcpHello) -> ResultType<()> {
    ensure!(hello.version == VERSION, "private_tcp_unsupported_version");
    ensure!(
        (6..=64).contains(&hello.id.len())
            && !hello
                .id
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control()),
        "private_tcp_invalid_identity"
    );
    ensure!(
        !hello.uuid.is_empty()
            && hello.uuid.len() <= 256
            && hello.public_key.len() == sign::PUBLICKEYBYTES
            && hello.ephemeral_key.len() == kx::PUBLICKEYBYTES,
        "private_tcp_invalid_hello"
    );
    Ok(())
}

fn validate_challenge(challenge: &PrivateTcpChallenge) -> ResultType<()> {
    ensure!(
        challenge.version == VERSION,
        "private_tcp_unsupported_version"
    );
    ensure!(
        challenge.nonce.len() == 32
            && challenge.ephemeral_key.len() == kx::PUBLICKEYBYTES
            && challenge.signature.len() == sign::SIGNATUREBYTES,
        "private_tcp_invalid_challenge"
    );
    Ok(())
}

fn transcript(
    domain: &[u8],
    hello: &PrivateTcpHello,
    challenge: &PrivateTcpChallenge,
    server_public: &sign::PublicKey,
) -> Vec<u8> {
    let mut bytes = b"RustDesk-Private-TCP-v1\0".to_vec();
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    // Length prefixes make variable ID/UUID fields unambiguous. Callers validate all sizes first.
    for field in [
        hello.id.as_bytes(),
        hello.uuid.as_ref(),
        hello.public_key.as_ref(),
        hello.ephemeral_key.as_ref(),
        server_public.as_ref(),
        challenge.nonce.as_ref(),
        challenge.ephemeral_key.as_ref(),
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

impl ClientHandshake {
    pub fn new(id: String, uuid: Vec<u8>, key: &sign::PublicKey) -> ResultType<Self> {
        sodiumoxide::init().map_err(|_| anyhow!("private_tcp_crypto_unavailable"))?;
        let mut hello = PrivateTcpHello {
            version: VERSION,
            id,
            uuid: uuid.into(),
            public_key: key.as_ref().to_vec().into(),
            ephemeral_key: vec![0; kx::PUBLICKEYBYTES].into(),
            ..Default::default()
        };
        validate_hello(&hello)?;
        let (public, ephemeral_secret) = kx::gen_keypair();
        hello.ephemeral_key = public.as_ref().to_vec().into();
        Ok(Self {
            hello,
            ephemeral_secret,
        })
    }

    pub fn hello(&self) -> &PrivateTcpHello {
        &self.hello
    }

    pub fn respond(
        self,
        challenge: &PrivateTcpChallenge,
        pinned_server: &sign::PublicKey,
        device_key: &sign::SecretKey,
    ) -> ResultType<(PrivateTcpProof, SessionCipher)> {
        validate_challenge(challenge)?;
        let signature = sign::Signature::from_bytes(&challenge.signature)
            .map_err(|_| anyhow!("private_tcp_invalid_challenge"))?;
        ensure!(
            sign::verify_detached(
                &signature,
                &transcript(b"server-challenge\0", &self.hello, challenge, pinned_server),
                pinned_server
            ),
            "private_tcp_server_identity_mismatch"
        );
        ensure!(
            device_key.public_key().as_ref() == self.hello.public_key.as_ref(),
            "private_tcp_device_proof_invalid"
        );
        let peer = kx::PublicKey::from_slice(&challenge.ephemeral_key)
            .ok_or_else(|| anyhow!("private_tcp_invalid_challenge"))?;
        let local = kx::PublicKey::from_slice(&self.hello.ephemeral_key)
            .ok_or_else(|| anyhow!("private_tcp_invalid_hello"))?;
        let (rx, tx) = kx::client_session_keys(&local, &self.ephemeral_secret, &peer)
            .map_err(|_| anyhow!("private_tcp_key_exchange_failed"))?;
        let proof = PrivateTcpProof {
            version: VERSION,
            signature: sign::sign_detached(
                &transcript(b"client-proof\0", &self.hello, challenge, pinned_server),
                device_key,
            )
            .as_ref()
            .to_vec()
            .into(),
            ..Default::default()
        };
        Ok((proof, SessionCipher::new(rx, tx)))
    }
}

impl ServerHandshake {
    pub fn new(
        hello: &PrivateTcpHello,
        server_key: &sign::SecretKey,
        now: Instant,
    ) -> ResultType<Self> {
        validate_hello(hello)?;
        sodiumoxide::init().map_err(|_| anyhow!("private_tcp_crypto_unavailable"))?;
        let peer = kx::PublicKey::from_slice(&hello.ephemeral_key)
            .ok_or_else(|| anyhow!("private_tcp_invalid_hello"))?;
        let (public, secret) = kx::gen_keypair();
        let (rx, tx) = kx::server_session_keys(&public, &secret, &peer)
            .map_err(|_| anyhow!("private_tcp_key_exchange_failed"))?;
        let server_public = server_key.public_key();
        let mut challenge = PrivateTcpChallenge {
            version: VERSION,
            nonce: randombytes::randombytes(32).into(),
            ephemeral_key: public.as_ref().to_vec().into(),
            ..Default::default()
        };
        challenge.signature = sign::sign_detached(
            &transcript(b"server-challenge\0", hello, &challenge, &server_public),
            server_key,
        )
        .as_ref()
        .to_vec()
        .into();
        Ok(Self {
            hello: hello.clone(),
            challenge,
            server_public,
            started: now,
            cipher: SessionCipher::new(rx, tx),
        })
    }

    pub fn challenge(&self) -> &PrivateTcpChallenge {
        &self.challenge
    }

    pub fn finish(self, proof: &PrivateTcpProof, now: Instant) -> ResultType<SessionCipher> {
        ensure!(
            now.checked_duration_since(self.started)
                .map(|age| age < HANDSHAKE_TIMEOUT)
                .unwrap_or(false),
            "private_tcp_handshake_expired"
        );
        ensure!(proof.version == VERSION, "private_tcp_unsupported_version");
        let signature = sign::Signature::from_bytes(&proof.signature)
            .map_err(|_| anyhow!("private_tcp_device_proof_invalid"))?;
        let public = sign::PublicKey::from_slice(&self.hello.public_key)
            .ok_or_else(|| anyhow!("private_tcp_invalid_hello"))?;
        ensure!(
            sign::verify_detached(
                &signature,
                &transcript(
                    b"client-proof\0",
                    &self.hello,
                    &self.challenge,
                    &self.server_public
                ),
                &public
            ),
            "private_tcp_device_proof_invalid"
        );
        Ok(self.cipher)
    }
}

fn nonce(sequence: u64) -> secretbox::Nonce {
    let mut bytes = [0; secretbox::NONCEBYTES];
    bytes[..8].copy_from_slice(&sequence.to_le_bytes());
    secretbox::Nonce(bytes)
}

impl SessionCipher {
    fn new(rx: kx::SessionKey, tx: kx::SessionKey) -> Self {
        Self {
            receive_key: secretbox::Key(rx.0),
            send_key: secretbox::Key(tx.0),
            receive_sequence: 0,
            send_sequence: 0,
            failed: false,
        }
    }

    pub fn seal(&mut self, message: &RendezvousMessage) -> ResultType<PrivateTcpFrame> {
        ensure!(!self.failed, "private_tcp_channel_failed");
        let result = self.seal_inner(message);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn seal_inner(&mut self, message: &RendezvousMessage) -> ResultType<PrivateTcpFrame> {
        ensure!(message.union.is_some(), "private_tcp_invalid_frame");
        ensure!(
            message.compute_size() <= MAX_PLAINTEXT as u64,
            "private_tcp_frame_too_large"
        );
        let sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("private_tcp_sequence_exhausted"))?;
        let bytes = message.write_to_bytes()?;
        let ciphertext = secretbox::seal(&bytes, &nonce(sequence), &self.send_key);
        self.send_sequence = sequence;
        Ok(PrivateTcpFrame {
            ciphertext: ciphertext.into(),
            ..Default::default()
        })
    }

    pub fn open(&mut self, frame: &PrivateTcpFrame) -> ResultType<RendezvousMessage> {
        ensure!(!self.failed, "private_tcp_channel_failed");
        let result = self.open_inner(frame);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn open_inner(&mut self, frame: &PrivateTcpFrame) -> ResultType<RendezvousMessage> {
        ensure!(
            frame.ciphertext.len() > secretbox::MACBYTES
                && frame.ciphertext.len() <= MAX_PLAINTEXT + secretbox::MACBYTES,
            "private_tcp_invalid_frame"
        );
        let sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("private_tcp_sequence_exhausted"))?;
        let plaintext = secretbox::open(&frame.ciphertext, &nonce(sequence), &self.receive_key)
            .map_err(|_| anyhow!("private_tcp_invalid_frame"))?;
        let message = RendezvousMessage::parse_from_bytes(&plaintext)
            .map_err(|_| anyhow!("private_tcp_invalid_frame"))?;
        ensure!(message.union.is_some(), "private_tcp_invalid_frame");
        self.receive_sequence = sequence;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous_proto::RegisterPeer;

    fn message() -> RendezvousMessage {
        let mut message = RendezvousMessage::new();
        message.set_register_peer(RegisterPeer {
            id: "ZBX-TEST".into(),
            ..Default::default()
        });
        message
    }

    #[test]
    fn private_tcp_send_sequence_exhaustion_fails_closed() {
        let mut cipher = SessionCipher::new(kx::SessionKey([1; 32]), kx::SessionKey([2; 32]));
        cipher.send_sequence = u64::MAX;
        assert_eq!(
            cipher.seal(&message()).err().unwrap().to_string(),
            "private_tcp_sequence_exhausted"
        );
        assert!(cipher.failed);
        assert_eq!(
            cipher.seal(&message()).err().unwrap().to_string(),
            "private_tcp_channel_failed"
        );
    }

    #[test]
    fn private_tcp_receive_sequence_exhaustion_fails_closed() {
        let mut cipher = SessionCipher::new(kx::SessionKey([1; 32]), kx::SessionKey([2; 32]));
        cipher.receive_sequence = u64::MAX;
        let frame = PrivateTcpFrame {
            ciphertext: vec![1; 32].into(),
            ..Default::default()
        };
        assert_eq!(
            cipher.open(&frame).err().unwrap().to_string(),
            "private_tcp_sequence_exhausted"
        );
        assert!(cipher.failed);
    }
}
