use anyhow::{Context, Result};
use bytes::BytesMut;
use rlp::RlpStream;
use secp256k1::{ecdh, ecdsa};

use crate::utils::key_gen::KeyGen;

#[derive(Debug)]
pub struct AuthMessage {
    sig: ecdsa::RecoverableSignature,
    initiator_public_key: secp256k1::PublicKey,
    initiator_nonce: [u8; 32],
    auth_vsn: u8,
    padding_size: u16
}

impl AuthMessage {
    pub fn new(key_gen: &mut KeyGen,
               initiator_secret_key: &secp256k1::SecretKey,
               remote_public_key: & secp256k1::PublicKey) -> Result<AuthMessage> {
        let initiator_public_key = key_gen.public_from_secret_key(&initiator_secret_key);
        let ephemeral_secret_key = key_gen.generate_secret_key();

        // Create nonce
        let mut initiator_nonce = [0u8; 32];
        key_gen.fill_random_bytes(&mut initiator_nonce).context("failed to initialize initiator_nonce")?;

        // Shared secret
        let shared_secret = ecdh::SharedSecret::new(&remote_public_key, &initiator_secret_key);

        // Sig
        let shared_secret_bytes = shared_secret.secret_bytes();
        let xor_to_sign : Vec<u8> = shared_secret_bytes.
            iter().
            enumerate().
            map(|(i, b)| b ^ initiator_nonce[i]).
            collect();
        let sig = key_gen.sign_data(xor_to_sign.as_slice(), &ephemeral_secret_key).
            context("failed to sign shared secret")?;

        let auth_message = AuthMessage {
            sig,
            initiator_public_key,
            initiator_nonce,
            auth_vsn: 4,
            padding_size: key_gen.generate_range(100, 300)
        };
        return Ok(auth_message)
    }

    pub fn encode(&self) -> BytesMut {
        let mut rlp_stream = RlpStream::new();

        rlp_stream.begin_list(4);
        self.encode_sig(&mut rlp_stream);
        self.encode_initiator_public_key(&mut rlp_stream);
        self.encode_initiator_nonce(&mut rlp_stream);
        self.encode_version(&mut rlp_stream);

        let mut rlp_auth_message = rlp_stream.out();

        self.add_padding(&mut rlp_auth_message);
        rlp_auth_message
    }

    fn encode_version(&self, rlp_stream: &mut RlpStream) {
        rlp_stream.append(&self.auth_vsn);
    }

    fn encode_initiator_nonce(&self, rlp_stream: &mut RlpStream) {
        rlp_stream.append(&self.initiator_nonce.as_slice());
    }

    fn encode_initiator_public_key(&self, rlp_stream: &mut RlpStream) {
        // We skip the first byte, it is a code that indicates the key is in uncompressed format,
        // but it is not needed
        rlp_stream.append(&self.initiator_public_key.serialize_uncompressed()[1..].to_vec());
    }

    fn encode_sig(&self, rlp_stream: &mut RlpStream) {
        let (recovery_id, sig) = self.sig.serialize_compact();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig);
        sig_bytes[64] = recovery_id.to_i32() as u8;
        rlp_stream.append(&sig_bytes.as_slice());
    }

    fn add_padding(&self, rlp_auth_message: &mut BytesMut) {
        rlp_auth_message.resize(rlp_auth_message.len() + self.padding_size as usize, 0);
    }
}
