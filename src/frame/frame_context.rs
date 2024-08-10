use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, StreamCipher};
use anyhow::{anyhow, Context, Error, Result};
use bytes::{BufMut, Bytes, BytesMut};
use ctr::cipher::KeyIvInit;
use sha3;
use sha3::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auth::encryption::ecdh_x;
use crate::utils::*;

const UINT16_MAX : usize = 0xffffff;
const FRAME_HEADER_SIZE : usize = 32;

pub struct FrameContext {
    ingress_aes : ctr::Ctr64BE::<Aes256>,
    egress_aes : ctr::Ctr64BE::<Aes256>,
    ingress_mac : sha3::Keccak256,
    egress_mac : sha3::Keccak256,
    mac_secret: [u8; 32]
}

impl FrameContext {
    pub fn new(ephemeral_secret_key : &secp256k1::SecretKey,
               remote_ephemeral_public_key : &secp256k1::PublicKey,
               initiator_nonce: [u8; 32],
               remote_nonce: [u8; 32],
               auth_bytes: &Bytes,
               ack_bytes: &Bytes) -> Result<FrameContext> {
        let ephemeral_shared_secret =
            ecdh_x(remote_ephemeral_public_key, &ephemeral_secret_key);

        let h_nonce = Self::keccak256(&[&remote_nonce, &initiator_nonce]);
        let shared_secret = Self::keccak256(&[&ephemeral_shared_secret, &h_nonce]);
        let aes_secret = Self::keccak256(&[&ephemeral_shared_secret, &shared_secret]);
        let mac_secret = Self::keccak256(&[&ephemeral_shared_secret, &aes_secret]);

        let (ingress_aes, ingress_mac) =
            Self::initialize_ingress(initiator_nonce, ack_bytes, aes_secret, mac_secret);

        let (egress_aes, egress_mac) =
            Self::initialize_egress(remote_nonce, auth_bytes, aes_secret, mac_secret);

        Ok(FrameContext{
            ingress_aes,
            egress_aes,
            ingress_mac,
            egress_mac,
            mac_secret
        })
    }

    fn keccak256(slices: &[&[u8]]) -> [u8; 32] {
        let mut hasher = sha3::Keccak256::new();
        for slice in slices {
            hasher.update(slice);
        }
        let digest = hasher.finalize();
        to_array(&digest)
    }

    fn initialize_egress(remote_nonce: [u8; 32],
                         auth_bytes: &Bytes,
                         aes_secret: [u8; 32],
                         mac_secret: [u8; 32]) -> (ctr::Ctr64BE::<Aes256>, sha3::Keccak256) {
        let iv = [0u8; 16];
        let egress_aes = ctr::Ctr64BE::<Aes256>::new(
            &aes_secret.into(), iv.as_slice().into());

        let mut egress_mac = sha3::Keccak256::new();
        egress_mac.update(xor_slices(mac_secret, remote_nonce));
        egress_mac.update(auth_bytes);

        (egress_aes, egress_mac)
    }

    fn initialize_ingress(initiator_nonce: [u8; 32],
                          ack_bytes: &Bytes,
                          aes_secret: [u8; 32],
                          mac_secret: [u8; 32]) -> (ctr::Ctr64BE::<Aes256>, sha3::Keccak256) {
        let iv = [0u8; 16];
        let ingress_aes = ctr::Ctr64BE::<Aes256>::new(
            &aes_secret.into(), iv.as_slice().into());

        let mut ingress_mac = sha3::Keccak256::new();
        ingress_mac.update(xor_slices(mac_secret, initiator_nonce));
        ingress_mac.update(ack_bytes);

        (ingress_aes, ingress_mac)
    }

    pub async fn send_frame(&mut self, tcp_stream: &mut TcpStream, payload : Bytes) -> Result<()> {
        let payload_size = payload.len();
        if payload_size > UINT16_MAX {
            return Err(anyhow!("payload is too large"))
        }
        let payload_size = payload_size as u32;

        self.write_frame_header(tcp_stream, payload_size).await?;
        self.write_frame_body(tcp_stream, &payload, payload_size).await?;

        Ok(())
    }

    async fn write_frame_body(&mut self, tcp_stream: &mut TcpStream, payload: &Bytes, payload_size: u32) -> Result<(), Error> {
        let mut output = BytesMut::with_capacity(payload_size as usize);
        let len = if payload_size % 16 == 0 { payload_size } else { (payload_size / 16 + 1) * 16 };

        output.put_slice(&payload);
        output.resize(len as usize, 0u8);
        self.egress_aes.try_apply_keystream(&mut output).
            map_err(|e| anyhow!("failed to encrypt body {e}"))?;

        let tag = Self::update_mac_body(&mut self.egress_mac, self.mac_secret, &output)?;
        output.extend_from_slice(&tag);

        tcp_stream.write_all(&output).await.context("failed to write body")?;
        Ok(())
    }

    async fn write_frame_header(&mut self, tcp_stream: &mut TcpStream, payload_size: u32) -> Result<(), Error> {
        let payload_size_bytes = payload_size.to_be_bytes();
        let payload_size_bytes = &payload_size_bytes[1..];

        let mut header_bytes = BytesMut::with_capacity(16);
        header_bytes.put_slice(&payload_size_bytes);
        header_bytes.put_slice(&[0u8; 16 - 3]);
        self.egress_aes.try_apply_keystream(&mut header_bytes).
            map_err(|e| anyhow!("failed to encrypt header {e}"))?;

        let tag = Self::update_mac_header(&mut self.egress_mac, self.mac_secret, &header_bytes)?;

        let mut output = BytesMut::with_capacity(FRAME_HEADER_SIZE);
        output.put_slice(&header_bytes);
        output.put_slice(&tag);

        tcp_stream.write_all(&output).await.context("failed to write header")?;
        Ok(())
    }

    pub async fn receive_frame(&mut self, tcp_stream: &mut TcpStream) -> Result<Bytes> {
        // RECEIVE HEADER
        let body_size = self.read_frame_header(tcp_stream).await?;
        let body = self.read_frame_body(tcp_stream, body_size).await?;

        Ok(body)
    }

    async fn read_frame_header(&mut self, tcp_stream: &mut TcpStream) -> Result<u32> {
        let mut header_bytes = BytesMut::with_capacity(FRAME_HEADER_SIZE);
        header_bytes.resize(header_bytes.capacity(), 0);
        tcp_stream.read_exact(&mut header_bytes).await.context("failed to read frame header")?;

        let received_header_tag = header_bytes.split_off(16);
        let tag = Self::update_mac_header(&mut self.ingress_mac, self.mac_secret, &header_bytes)?;
        if tag.as_slice() != received_header_tag {
            return Err(anyhow!("Received header tag is invalid"));
        }

        self.ingress_aes.try_apply_keystream(&mut header_bytes).
            map_err(|e| anyhow!("failed to decrypt header {e}"))?;
        let body_size_bytes = [0, header_bytes[0], header_bytes[1], header_bytes[2]];
        let body_size = u32::from_be_bytes(body_size_bytes);
        Ok(body_size)
    }

    async fn read_frame_body(&mut self, tcp_stream: &mut TcpStream, body_size: u32) -> Result<Bytes, Error> {
        let padded_body_size = if body_size % 16 == 0 { body_size } else { (body_size / 16 + 1) * 16 };
        let mut body_bytes = BytesMut::with_capacity(16 + padded_body_size as usize);
        body_bytes.resize(body_bytes.capacity(), 0);

        tcp_stream.read_exact(&mut body_bytes).await.context("failed to read frame body")?;

        let received_body_tag = body_bytes.split_off(body_bytes.len() - 16);
        let tag = Self::update_mac_body(&mut self.ingress_mac, self.mac_secret, &body_bytes)?;
        if tag.as_slice() != received_body_tag {
            return Err(anyhow!("Received body tag is invalid"));
        }

        self.ingress_aes.try_apply_keystream(&mut body_bytes).
            map_err(|e| anyhow!("failed to decrypt body {e}"))?;
        body_bytes.truncate((body_size) as usize);

        Ok(body_bytes.freeze())
    }

    fn update_mac_header(mac: &mut sha3::Keccak256, mac_secret: [u8; 32],
                       header_bytes: &BytesMut) -> Result<[u8; 16]> {
        let tag = &mut mac.clone().finalize()[..16];
        let tag_length = tag.len();

        let aes = aes::Aes256Enc::new_from_slice(&mac_secret).
            context("failed initialize Aes256Enc")?;
        let tag = aes.encrypt_padded::<block_padding::NoPadding>(tag, tag_length).
            map_err(|e| anyhow!("failed to encrypt header tag {e}"))?;

        let tag = xor_slices::<16>(to_array(&tag), to_array(&header_bytes));
        mac.update(tag);

        let tag = &mac.clone().finalize()[..16];
        Ok(to_array(tag))
    }

    fn update_mac_body(mac: &mut sha3::Keccak256, mac_secret: [u8; 32],
                       body_bytes: &BytesMut) -> Result<[u8; 16]> {
        mac.update(&body_bytes);

        let tag = &mac.clone().finalize()[..16];
        let aes = aes::Aes256Enc::new_from_slice(&mac_secret).
            context("failed initialize Aes256Enc")?;
        let encrypted_tag = &mut mac.clone().finalize()[..16];
        let encrypted_tag_length = encrypted_tag.len();
        let encrypted_tag = aes.encrypt_padded::<block_padding::NoPadding>(encrypted_tag, encrypted_tag_length).
            map_err(|e| anyhow!("failed to encrypt header tag {e}"))?;

        let tag = xor_slices::<16>(to_array(&tag), to_array(&encrypted_tag));
        mac.update(tag);

        let tag = &mac.clone().finalize()[..16];
        Ok(to_array(tag))
    }
}
