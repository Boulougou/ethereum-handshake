use std::io::{Read, Write};
use std::net::TcpStream;
use anyhow::{Result, Context, anyhow};
use bytes::BytesMut;
use crate::messages::ack_message::AckMessage;
use crate::messages::auth_message::AuthMessage;
use crate::utils::encryption;
use crate::utils::key_gen::KeyGen;

pub fn handshake(enode_url : &str) -> Result<()>{
    let (remote_address, remote_public_key) = parse_enode_url(enode_url).
        with_context(|| format!("failed to parse url {enode_url}"))?;

    let mut tcp_stream = TcpStream::connect(remote_address).
        context("failed to connect to remote node")?;

    println!("Connected to {}!", tcp_stream.peer_addr().unwrap());

    let mut key_gen = KeyGen::new();
    let auth_message = AuthMessage::new(&mut key_gen, &remote_public_key).
        context("failed to create auth message")?;

    let encoded_message = auth_message.encode();
    let encrypted = encryption::encrypt_data(encoded_message, &remote_public_key, &mut key_gen).
        context("failed to encrypt auth message")?;

    let auth_size: u16 = encrypted.len() as u16;
    tcp_stream.write_all(&auth_size.to_be_bytes())?;
    tcp_stream.write_all(&encrypted)?;
    println!("Sent auth message of size {auth_size}");

    let mut ack_size_bytes = [0u8; 2];
    tcp_stream.read(&mut ack_size_bytes).context("failed to read size of ack message")?;
    let ack_size = u16::from_be_bytes(ack_size_bytes);

    let mut encrypted_ack_bytes = BytesMut::with_capacity(ack_size as usize);
    tcp_stream.read(&mut encrypted_ack_bytes).context("failed to read ack message")?;
    println!("Received of ack message of size {ack_size}");
    let ack_bytes = encryption::decrypt_data(encrypted_ack_bytes, &remote_public_key, &mut key_gen).
        context("failed to encrypt auth message")?;
    let _ack_message = AckMessage::decode(&ack_bytes);

    Ok(())
}

fn parse_enode_url(enode_url: &str) -> Result<(&str, secp256k1::PublicKey)> {
    let enode_without_prefix = enode_url.strip_prefix("enode://").
        ok_or(anyhow!("failed strip prefix"))?;

    let mut enode_parts = enode_without_prefix.split('@');
    let remote_public_key_hex = enode_parts.next().ok_or(anyhow!("failed to split at @"))?;
    let remote_address = enode_parts.next().ok_or(anyhow!("failed to split at @"))?;
    let remote_public_key_bytes = hex::decode(remote_public_key_hex).context("failed to decode key hex")?;

    // Prepend the 0x04 byte to indicate uncompressed format
    let mut uncompressed_key_bytes = Vec::with_capacity(65);
    uncompressed_key_bytes.push(0x04);
    uncompressed_key_bytes.extend_from_slice(&remote_public_key_bytes);
    let remote_public_key = secp256k1::PublicKey::from_slice(uncompressed_key_bytes.as_slice()).
        context("could not create remote public key")?;

    Ok((remote_address, remote_public_key))
}
