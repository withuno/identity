use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chacha20poly1305::aead;
use chacha20poly1305::aead::{Aead, NewAead, Payload};

pub use ed25519_dalek::PublicKey;
pub use ed25519_dalek::Signature;
pub use ed25519_dalek::Signer;
pub use ed25519_dalek::Verifier;
pub type PrivateKey = ed25519_dalek::SecretKey;
pub type KeyPair = ed25519_dalek::Keypair;

pub type SymmetricKey = chacha20poly1305::Key;
pub type Error = aead::Error;

pub const PRIVATE_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

use strum_macros::IntoStaticStr;

use rand::RngCore;

#[derive(IntoStaticStr)]
enum Usage {
    #[strum(to_string = "authentication vault")]
    Vault,
}

use rand;

/// Encrypt data using key and return an opaque blob. The nonce is the first 12
/// bytes of the blob.
pub fn encrypt(key: SymmetricKey, data: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let mut nonce = Nonce::default();
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    let ctx: &'static str = Usage::Vault.into();
    let payload = Payload {
        msg: data,
        aad: ctx.as_bytes(),
    };
    let ciphertext = cipher.encrypt(&nonce, payload)?;
    let blob = [&nonce.as_slice(), &ciphertext[..]].concat().to_vec();
    Ok(blob)
}

/// Decrypt data using key and return the original message. The nonce is the
/// first 12 bytes of data.
pub fn decrypt(key: SymmetricKey, data: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let nonce = Nonce::from_slice(&data[0..12]);
    let cipher = ChaCha20Poly1305::new(&key);
    let ctx: &'static str = Usage::Vault.into();
    let payload = Payload {
        msg: &data[nonce.len()..],
        aad: ctx.as_bytes(),
    };
    cipher.decrypt(&nonce, payload)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
