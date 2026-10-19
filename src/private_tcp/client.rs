use super::{ClientHandshake, SessionCipher, HANDSHAKE_TIMEOUT, MAX_PLAINTEXT};
use crate::{
    anyhow::{anyhow, bail, ensure},
    protobuf::Message,
    rendezvous_proto::*,
    sodiumoxide::crypto::sign,
    tcp::FramedStream,
    ResultType,
};
use std::{io::ErrorKind, time::Duration};

async fn receive(
    stream: &mut FramedStream,
    eof: &'static str,
    limit: usize,
) -> ResultType<RendezvousMessage> {
    let bytes = match stream.next().await {
        Some(Ok(bytes)) => bytes,
        Some(Err(error)) if error.kind() == ErrorKind::InvalidData => {
            bail!("private_tcp_invalid_frame")
        }
        Some(Err(_)) => bail!("private_tcp_connection_lost"),
        None => bail!(eof),
    };
    ensure!(bytes.len() <= limit, "private_tcp_invalid_frame");
    RendezvousMessage::parse_from_bytes(&bytes).map_err(|_| anyhow!("private_tcp_invalid_frame"))
}

pub async fn register_client(
    stream: &mut FramedStream,
    state: ClientHandshake,
    pinned_server: &sign::PublicKey,
    device_key: &sign::SecretKey,
) -> ResultType<(SessionCipher, Duration)> {
    ensure!(!stream.is_secured(), "private_tcp_transport_mismatch");
    stream
        .codec_mut()
        .set_max_packet_length(MAX_PLAINTEXT + 128);
    stream.set_send_timeout(3000);
    let mut authenticated_server = false;
    let exchange = async {
        let mut envelope = RendezvousMessage::new();
        envelope.set_private_tcp_hello(state.hello().clone());
        stream
            .send(&envelope)
            .await
            .map_err(|_| anyhow!("private_tcp_connection_lost"))?;
        let challenge = receive(stream, "server_tcp_unsupported", 4096).await?;
        let challenge = match challenge.union {
            Some(rendezvous_message::Union::PrivateTcpChallenge(challenge)) => challenge,
            _ => bail!("server_tcp_unsupported"),
        };
        let (proof, mut cipher) = state.respond(&challenge, pinned_server, device_key)?;
        authenticated_server = true;
        envelope.set_private_tcp_proof(proof);
        stream
            .send(&envelope)
            .await
            .map_err(|_| anyhow!("private_tcp_connection_lost"))?;
        let reply = receive(
            stream,
            "private_tcp_registration_failed",
            MAX_PLAINTEXT + 128,
        )
        .await?;
        let frame = match reply.union {
            Some(rendezvous_message::Union::PrivateTcpFrame(frame)) => frame,
            _ => bail!("private_tcp_unencrypted_message"),
        };
        let reply = cipher.open(&frame)?;
        let reply = match reply.union {
            Some(rendezvous_message::Union::RegisterPkResponse(reply)) => reply,
            _ => bail!("private_tcp_unexpected_registration"),
        };
        match reply.result.enum_value() {
            Ok(register_pk_response::Result::OK) => {}
            Ok(register_pk_response::Result::UUID_MISMATCH)
            | Ok(register_pk_response::Result::ID_EXISTS) => bail!("identity_mismatch"),
            Ok(register_pk_response::Result::NOT_SUPPORT) => bail!("server_tcp_unsupported"),
            Ok(register_pk_response::Result::INVALID_ID_FORMAT) => {
                bail!("private_tcp_invalid_identity")
            }
            _ => bail!("private_tcp_registration_failed"),
        }
        let seconds = if reply.keep_alive > 0 {
            reply.keep_alive.min(10)
        } else {
            10
        };
        Ok((cipher, Duration::from_secs(seconds as u64)))
    };
    match crate::timeout(HANDSHAKE_TIMEOUT.as_millis() as u64, exchange).await {
        Ok(Err(error))
            if authenticated_server && error.to_string() == "private_tcp_connection_lost" =>
        {
            Err(anyhow!("private_tcp_registration_failed"))
        }
        Ok(result) => result,
        Err(_) if authenticated_server => Err(anyhow!("private_tcp_registration_failed")),
        Err(_) => Err(anyhow!("private_tcp_handshake_timeout")),
    }
}
