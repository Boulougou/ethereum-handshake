use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use ctr::Ctr64BE;
use hmac::{Hmac, Mac};
use secp256k1::ecdh;
use sha2::Digest;

use crate::key_gen::KeyGen;

const ECIES_OVERHEAD: usize = secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 /* IV */ + 32 /* MAC */;

pub fn encrypt_data(mut unencrypted : BytesMut, public_key : &secp256k1::PublicKey,
                       key_gen : &mut KeyGen) -> Result<Bytes> {
    let (random_secret_key, random_public_key) = key_gen.generate_key_pair();

    let x = ecdh_x(public_key, &random_secret_key);
    let mut key = [0u8; 32];
    kdf(&x, &[], &mut key).context("failed to calculate kdf")?;

    let enc_key = &key[..16];
    let mac_key = sha2::Sha256::digest(&key[16..32]);

    let mut iv = [0u8; 16];
    key_gen.fill_random_bytes(&mut iv).context("failed to initialize IV")?;

    let mut encryptor = Ctr64BE::<Aes128>::new(enc_key.into(), &iv.into());
    // Encrypt in place to avoid copying the data
    let mut encrypted = &mut unencrypted;
    encryptor.apply_keystream(&mut encrypted);

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

fn hmac_sha256(key: &[u8], input: &[&[u8]], auth_size: &[u8]) -> Result<[u8; 32]> {
    let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_size);
    let hash = hmac.finalize().into_bytes();

    Ok(to_array32(&hash))
}

fn ecdh_x(public_key: &secp256k1::PublicKey, secret_key: &secp256k1::SecretKey) -> [u8; 32] {
    let slice = &ecdh::shared_secret_point(public_key, secret_key)[..32];

    to_array32(slice)
}

fn kdf(secret: &[u8; 32], s1: &[u8], dest: &mut [u8]) -> Result<()> {
    let result = concat_kdf::derive_key_into::<sha2::Sha256>(secret.as_slice(), s1, dest);
    // work around `concat_kdf::Error` not implementing `std::error::Error`
    match result {
        Err(e) => Err(anyhow!("concat_kdf error {e}")),
        Ok(v) => Ok(v)
    }
}

fn to_array32(slice: &[u8]) -> [u8; 32] {
    let mut array = [0u8; 32];
    slice.iter().enumerate().for_each(|(i, x)| array[i] = *x);
    array
}

