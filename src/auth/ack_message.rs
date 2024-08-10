use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use rlp::Rlp;
use secp256k1::PublicKey;
use crate::utils::to_array;

#[derive(Debug)]
pub struct AckMessage {
    pub remote_ephemeral_public_key: secp256k1::PublicKey,
    pub remote_nonce: [u8; 32],
    pub _ack_vsn: u8,
}

impl AckMessage {
    pub fn decode(bytes: &Bytes) -> Result<AckMessage> {
        let rlp_msg = Rlp::new(&bytes);

        let public_key = Self::decode_public_key(&rlp_msg)?;
        let nonce = Self::decode_nonce(&rlp_msg)?;
        let version = Self::decode_version(rlp_msg)?;

        Ok(AckMessage {
            remote_ephemeral_public_key: public_key,
            remote_nonce: to_array(&nonce),
            _ack_vsn : version
        })
    }

    fn decode_version(rlp_msg: Rlp) -> Result<u8> {
        let version: u8 = rlp_msg.val_at(2).context("failed to parse ack version")?;
        Ok(version)
    }

    fn decode_nonce(rlp_msg: &Rlp) -> Result<Bytes> {
        let nonce: Bytes = rlp_msg.val_at(1)?;
        if nonce.len() != 32 {
            return Err(anyhow!("nonce should be 32 bytes long, instead it is {}", nonce.len()))
        }
        Ok(nonce)
    }

    fn decode_public_key(rlp_msg: &Rlp) -> Result<PublicKey> {
        let public_key_bytes: Bytes = rlp_msg.val_at(0)?;

        let mut uncompressed_key_bytes = Vec::with_capacity(65);
        uncompressed_key_bytes.push(0x04);
        uncompressed_key_bytes.extend_from_slice(&public_key_bytes);

        let public_key = secp256k1::PublicKey::from_slice(&uncompressed_key_bytes).
            context("failed to parse public key")?;

        Ok(public_key)
    }
}
