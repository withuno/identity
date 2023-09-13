//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use ed25519_dalek::Signature;
pub use ed25519_dalek::Signer;
pub use ed25519_dalek::Verifier;
pub type PublicKey = ed25519_dalek::VerifyingKey;
pub type PrivateKey = ed25519_dalek::SecretKey;
pub type KeyPair = ed25519_dalek::SigningKey;

pub type SymmetricKey = chacha20poly1305::Key;
pub type Error = aead::Error;

pub const PRIVATE_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const KEYPAIR_LENGTH: usize = ed25519_dalek::KEYPAIR_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

use chacha20poly1305::aead;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

#[cfg(not(test))]
use rand::RngCore;

#[cfg(not(test))]
use rand;

#[cfg(test)]
use test_rand as rand;

#[cfg(test)]
mod test_rand
{
    pub struct R {}
    impl R
    {
        pub fn fill_bytes(&mut self, dest: &mut [u8])
        {
            for i in dest.iter_mut() {
                *i = 0;
            }
        }
    }
    pub fn thread_rng() -> R { R {} }
}

/// Encrypt data using key and return an opaque blob. The nonce is the first 12
/// bytes of the blob.
pub fn encrypt(
    key: SymmetricKey,
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, aead::Error>
{
    let mut nonce = Nonce::default();
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    let payload = Payload { msg: data, aad: aad };
    let ciphertext = cipher.encrypt(&nonce, payload)?;
    let blob = [&nonce.as_slice(), &ciphertext[..]].concat().to_vec();

    Ok(blob)
}

/// Decrypt data using key and return the original message. The nonce is the
/// first 12 bytes of data.
pub fn decrypt(
    key: SymmetricKey,
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, aead::Error>
{
    let nonce = Nonce::from_slice(&data[0..12]);
    let cipher = ChaCha20Poly1305::new(&key);
    let payload = Payload { msg: &data[nonce.len()..], aad: aad };

    cipher.decrypt(&nonce, payload)
}

#[cfg(test)]
mod unit
{
    use super::*;

    #[test]
    fn aead_encrypt() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = b"dust has only just begun to form";
        let msg = b"spin me around again";
        let aad = b"hide and seek";
        let sym = SymmetricKey::from_slice(key);
        let actual = encrypt(*sym, msg, aad)?;
        let expected64 =
            "AAAAAAAAAAAAAAAASVL67erDFBxUzRM4trcn565Rqwq7SN7IXH+XfKDX3qMmVCJr";
        let expected = base64::decode(expected64)?;
        assert_eq!(expected, &*actual);

        Ok(())
    }

    #[test]
    fn aead_decrypt() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = b"dust has only just begun to form";
        let blob64 =
            "66e/2LzVClrO8V/EhfoDwHUt0J35UB53CvqNgXCysoHy5Sd4yvwe+OufBEsHaHSA";
        let blob = base64::decode(blob64)?;
        let aad = b"hide and seek";
        let sym = SymmetricKey::from_slice(key);
        let actual = decrypt(*sym, &blob, aad)?;
        let expected = b"spin me around again";
        assert_eq!(expected, &*actual);

        Ok(())
    }
}
