use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, Context, anyhow};
use bytes::BytesMut;
use crate::messages::ack_message::AckMessage;
use crate::messages::auth_message::AuthMessage;
use crate::utils::encryption;
use crate::utils::key_gen::KeyGen;

pub async fn handshake(enode_url : &str,
                 initiator_secret_key: &secp256k1::SecretKey) -> Result<()>{
    let (remote_address, remote_public_key) = parse_enode_url(enode_url).
        with_context(|| format!("failed to parse url {enode_url}"))?;

    let log_prefix = pretty_enode(enode_url);

    let mut key_gen = KeyGen::new();
    let mut tcp_stream = TcpStream::connect(remote_address).await.
        context("failed to connect to remote node")?;
    println!("{log_prefix} Connected to {}", tcp_stream.peer_addr().unwrap());

    send_auth_message(&initiator_secret_key, &remote_public_key, &mut tcp_stream, &mut key_gen).await?;
    println!("{log_prefix} Sent Auth message");

    let _ack_message = receive_ack_message(&initiator_secret_key, &mut tcp_stream, &mut key_gen).await?;
    println!("{log_prefix} Received Ack message");

    Ok(())
}

fn parse_enode_url(enode_url: &str) -> Result<(&str, secp256k1::PublicKey)> {
    let enode_without_prefix = enode_url.strip_prefix("enode://").
        ok_or(anyhow!("failed strip prefix"))?;

    let mut enode_parts = enode_without_prefix.split('@');
    let remote_public_key_hex = enode_parts.next().ok_or(anyhow!("failed to split at @"))?;
    let remote_address = enode_parts.next().ok_or(anyhow!("failed to split at @"))?;

    if remote_address.is_empty() {
        return Err(anyhow!("enode url does not contain an address"))
    }

    let remote_public_key_bytes = hex::decode(remote_public_key_hex).
        context("failed to decode key hex")?;

    // Prepend the 0x04 byte to indicate uncompressed format
    let mut uncompressed_key_bytes = Vec::with_capacity(65);
    uncompressed_key_bytes.push(0x04);
    uncompressed_key_bytes.extend_from_slice(&remote_public_key_bytes);
    let remote_public_key = secp256k1::PublicKey::from_slice(uncompressed_key_bytes.as_slice()).
        context("could not create remote public key")?;

    Ok((remote_address, remote_public_key))
}

async fn send_auth_message(initiator_secret_key: &secp256k1::SecretKey,
                           remote_public_key: &secp256k1::PublicKey,
                           tcp_stream: &mut TcpStream,
                           mut key_gen: &mut KeyGen) -> Result<()> {
    let auth_message = AuthMessage::new(&mut key_gen,
                                        &initiator_secret_key,
                                        &remote_public_key).
        context("failed to create auth message")?;

    let encoded_message = auth_message.encode();
    let encrypted = encryption::encrypt_data(encoded_message, &remote_public_key, &mut key_gen).
        context("failed to encrypt auth message")?;

    let auth_size: u16 = encrypted.len() as u16;
    tcp_stream.write_all(&auth_size.to_be_bytes()).await?;
    tcp_stream.write_all(&encrypted).await?;
    Ok(())
}

async fn receive_ack_message(initiator_secret_key: &secp256k1::SecretKey,
                             tcp_stream: &mut TcpStream,
                             mut key_gen: &mut KeyGen) -> Result<AckMessage> {
    let mut ack_size_bytes = [0u8; 2];
    tcp_stream.read_exact(&mut ack_size_bytes).await.context("failed to read size of ack message")?;
    let ack_size = u16::from_be_bytes(ack_size_bytes);

    let mut encrypted_ack_bytes = BytesMut::with_capacity(ack_size as usize);
    encrypted_ack_bytes.resize(ack_size as usize, 0);
    tcp_stream.read_exact(&mut encrypted_ack_bytes).await.context("failed to read ack message")?;

    let ack_bytes = encryption::decrypt_data(encrypted_ack_bytes, &initiator_secret_key, &mut key_gen).
        context("failed to decrypt auth message")?;

    let ack_message = AckMessage::decode(&ack_bytes).context("failed to decode ack message")?;
    Ok(ack_message)
}

pub fn pretty_enode(enode_url: &str) -> String {
    let maybe_parts = enode_url.split_at_checked(14);
    maybe_parts.map(|(l, _r)| format!("[{l}]")).unwrap_or(String::from("[enode://INVALID]"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enode_url_without_scheme() {
        let result = parse_enode_url(
            "5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("prefix")));
    }

    #[test]
    fn parse_enode_url_with_wrong_scheme() {
        let result = parse_enode_url(
            "https://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("prefix")));
    }

    #[test]
    fn parse_enode_url_with_invalid_scheme_syntax() {
        let result = parse_enode_url(
            "enode//5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("prefix")));
    }

    #[test]
    fn parse_enode_url_with_short_node_id() {
        let result = parse_enode_url(
            "enode://a23c3079febc407d@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("public key")));
    }

    #[test]
    fn parse_enode_url_with_too_long_node_id() {
        let result = parse_enode_url(
            "enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407dbc407d@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("public key")));
    }

    #[test]
    fn parse_enode_url_with_empty_node_id() {
        let result = parse_enode_url(
            "enode://@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("public key")));
    }

    #[test]
    fn parse_enode_url_with_random_bytes_in_node_id() {
        let result = parse_enode_url(
            "enode://b2f1a64c4c7c1e4c1e5db8bdf54c0b1e283d032f4de2956d3d4f9a6c1b5b0dc8b2f1a64c4c7c1e4c1e5db8bdf54c0b1e283d032f4de2956d3d4f9a6c1b5b0dc8@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("public key")));
    }

    #[test]
    fn parse_enode_url_non_hex_chars_in_node_id() {
        let result = parse_enode_url(
            "enode://q6rt9b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303");
        assert!(result.is_err_and(|e| e.to_string().contains("hex")));
    }

    #[test]
    fn parse_enode_url_without_address() {
        let result = parse_enode_url(
            "enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@");
        assert!(result.is_err_and(|e| e.to_string().contains("address")));
    }

    #[test]
    fn parse_enode_url_without_at_character() {
        let result = parse_enode_url(
            "enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d127.0.0.1:4444");
        assert!(result.is_err_and(|e| e.to_string().contains("@")));
    }

    #[test]
    fn pretty_enode_valid_enode() {
        let result = pretty_enode(
            "enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d127.0.0.1:4444");
        assert_eq!(result, "[enode://5f379b]");
    }

    #[test]
    fn pretty_enode_too_short_enode() {
        let result = pretty_enode(
            "enode://5f");
        assert_eq!(result, "[enode://INVALID]");
    }
}
