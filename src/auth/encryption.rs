use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use ctr::Ctr64BE;
use hmac::{Hmac, Mac};
use secp256k1::ecdh;
use sha2::Digest;

use crate::utils::{KeyGen, to_array};

const IV_SIZE: usize = 16;
const MAC_SIZE: usize = 32;
const ECIES_OVERHEAD: usize = secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + IV_SIZE + MAC_SIZE;

pub fn encrypt_data(mut unencrypted : BytesMut, remote_public_key: &secp256k1::PublicKey,
                    key_gen : &mut KeyGen) -> Result<Bytes> {
    let (random_secret_key, random_public_key) = key_gen.generate_key_pair();

    let x = ecdh_x(remote_public_key, &random_secret_key);
    let mut key = [0u8; 32];
    kdf(&x, &[], &mut key).context("failed to calculate kdf")?;

    let enc_key = &key[..16];
    let mac_key = sha2::Sha256::digest(&key[16..32]);

    let mut iv = [0u8; IV_SIZE];
    key_gen.fill_random_bytes(&mut iv).context("failed to initialize IV")?;

    let mut encryptor = Ctr64BE::<Aes128>::new(enc_key.into(), &iv.into());
    // Encrypt in place to avoid copying the data
    let mut encrypted = &mut unencrypted;
    encryptor.try_apply_keystream(&mut encrypted).
        map_err(|e| anyhow!("failed to encrypt data {e}"))?;

    let total_size: u16 = u16::try_from(ECIES_OVERHEAD + encrypted.len()).
        with_context(|| format!("encrypted message is too large: {}", encrypted.len()))?;

    let tag = hmac_sha256(mac_key.as_slice(),
                          &[iv.as_slice(), &encrypted],
                          &total_size.to_be_bytes()).
        context("failed to calculate HMAC sha256")?;

    let mut output = BytesMut::with_capacity(total_size as usize);
    output.put_slice(&random_public_key.serialize_uncompressed());
    output.put_slice(&iv);
    output.put_slice(&encrypted);
    output.put_slice(&tag);
    return Ok(output.freeze())
}

pub fn decrypt_data(mut encrypted : BytesMut, local_secret_key : &secp256k1::SecretKey,
                    _key_gen : &mut KeyGen) -> Result<Bytes> {
    let total_size = encrypted.len();
    if total_size <= ECIES_OVERHEAD {
        return Err(anyhow!("encrypted data are too short {} <= {ECIES_OVERHEAD}", total_size))
    }
    let payload_size = total_size - ECIES_OVERHEAD;

    let total_size : u16 = total_size.try_into().
        with_context(|| format!("encrypted data are too long, {total_size} does not fit in u16"))?;

    let random_public_key_bytes = encrypted.split_to(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE);
    let iv_bytes = encrypted.split_to(IV_SIZE);
    let mut encrypted_payload = encrypted.split_to(payload_size);
    let tag_bytes = encrypted.split_to(MAC_SIZE);
    let iv = &iv_bytes[..];
    let tag = &tag_bytes[..];

    let random_public_key = secp256k1::PublicKey::from_slice(&random_public_key_bytes[..]).
        context("failed to parse public key")?;

    let x = ecdh_x(&random_public_key, &local_secret_key);
    let mut key = [0u8; 32];
    kdf(&x, &[], &mut key).context("failed to calculate kdf")?;

    let enc_key = &key[..16];
    let mac_key = sha2::Sha256::digest(&key[16..32]);

    let calculated_tag = hmac_sha256(mac_key.as_slice(),
                          &[iv, &encrypted_payload],
                          &total_size.to_be_bytes()).
        context("failed to calculate HMAC sha256")?;
    if calculated_tag != tag {
        return Err(anyhow!("tag mismatch"));
    }

    let mut decryptor = Ctr64BE::<Aes128>::new(enc_key.into(), iv.into());
    let decrypted = &mut encrypted_payload[..];
    decryptor.try_apply_keystream(decrypted).
        map_err(|e| anyhow!("failed to decrypt data {e}"))?;

    let mut output = BytesMut::with_capacity(decrypted.len());
    output.put_slice(&decrypted);
    Ok(output.freeze())
}

fn hmac_sha256(key: &[u8], input: &[&[u8]], auth_size: &[u8]) -> Result<[u8; MAC_SIZE]> {
    let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_size);
    let hash = hmac.finalize().into_bytes();

    Ok(to_array(&hash))
}

pub fn ecdh_x(public_key: &secp256k1::PublicKey, secret_key: &secp256k1::SecretKey) -> [u8; 32] {
    let slice = &ecdh::shared_secret_point(public_key, secret_key)[..32];

    to_array(slice)
}

fn kdf(secret: &[u8; 32], s1: &[u8], dest: &mut [u8]) -> Result<()> {
    concat_kdf::derive_key_into::<sha2::Sha256>(secret.as_slice(), s1, dest).
        map_err(|e| anyhow!("concat_kdf error {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_and_decrypt_data() {
        let mut key_gen = KeyGen::new();
        let (secret_key, public_key) = key_gen.generate_key_pair();

        let data = Bytes::copy_from_slice(&[3u8, 6, 34, 244, 0, 12, 43]);
        let encrypted_result = encrypt_data(
            BytesMut::from(data.clone()), &public_key, &mut key_gen);
        assert!(encrypted_result.is_ok(), "failed to encrypt data {:?}", encrypted_result.unwrap_err());

        let decrypted_result = decrypt_data(
            BytesMut::from(encrypted_result.unwrap()), &secret_key, &mut key_gen);
        assert!(decrypted_result.is_ok(), "failed to decrypt data {:?}", decrypted_result.unwrap_err());

        assert_eq!(decrypted_result.unwrap(), Bytes::copy_from_slice(&data))
    }
}
