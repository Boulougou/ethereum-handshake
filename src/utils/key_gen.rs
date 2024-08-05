use secp256k1::{ecdsa, Secp256k1};
use secp256k1::rand::rngs::OsRng;
use anyhow::Result;
use secp256k1::rand::{Rng, RngCore};

pub struct KeyGen {
    context : Secp256k1<secp256k1::SignOnly>,
    rng : OsRng
}

impl KeyGen {
    pub fn new() -> KeyGen {
        let mut secp = Secp256k1::signing_only();
        let mut rng = OsRng;
        secp.randomize(&mut rng);

        return KeyGen {
            context : secp,
            rng
        }
    }

    pub fn generate_key_pair(&mut self) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        self.context.generate_keypair(&mut self.rng)
    }

    pub fn generate_secret_key(&mut self) -> secp256k1::SecretKey {
        secp256k1::SecretKey::new(&mut self.rng)
    }

    pub fn sign_data(&mut self, data : &[u8], key : &secp256k1::SecretKey) -> Result<ecdsa::RecoverableSignature> {
        let message = secp256k1::Message::from_digest_slice(data)?;
        Ok(self.context.sign_ecdsa_recoverable(&message, key))
    }

    pub fn fill_random_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        let void = self.rng.try_fill_bytes(dest)?;
        Ok(void)
    }

    pub fn generate_range(&mut self, min: u16, max: u16) -> u16 {
        self.rng.gen_range(min..max)
    }
}
