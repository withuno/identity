//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
pub use error::Error;

/// The uno identity is 32 bytes of entropy.
pub const ID_LENGTH: usize = 32;

/// And uno identity newtype.
#[derive(Debug, Copy, Clone)]
pub struct Id(pub [u8; ID_LENGTH]);

impl Id
{
    /// Generate a new uno ID.
    pub fn new() -> Self
    {
        let mut seed = [0u8; ID_LENGTH];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        Id(seed)
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MagicShare
{
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub schema_version: u64,
    pub encrypted_credential: String,
}

use std::convert::TryFrom;
use std::str;

/// A group share is the result of running split on an uno id.
/// You need a threshold number (currently 1) of reconstructed groups in order
/// to be able to reconstruct the original uno id.
pub use s39::GroupShare;
/// A share is the individual element in a group share. Shares in a group are
/// combined to reconstruct the group share. Then group shares are combined to
/// reconstruct the original ID.
pub use s39::Share;

/// Build an uno identity from a byte slice.
impl TryFrom<&[u8]> for Id
{
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error>
    {
        let array = <[u8; ID_LENGTH]>::try_from(bytes)?;
        Ok(Id(array))
    }
}

pub type KeyPair = djb::KeyPair;
pub type PublicKey = djb::PublicKey;
pub use djb::Signature;
pub use djb::Signer;
pub use djb::Verifier;

pub const SIGNATURE_LENGTH: usize = djb::SIGNATURE_LENGTH;

pub type SymmetricKey = djb::SymmetricKey;

use strum_macros::Display;
use strum_macros::EnumString;
use strum_macros::IntoStaticStr;

/// Keys are derived from Uno IDs depending on their usage. This corresponds
/// to the context passed to the key derivation function.
#[derive(IntoStaticStr)]
enum Usage
{
    #[strum(to_string = "uno seed identity signing keypair")]
    Signature,
    #[strum(to_string = "uno seed private symmetric encryption key")]
    Encryption,
}

/// Convert an uno Id into its public/private keypair representation.
impl From<Id> for KeyPair
{
    fn from(id: Id) -> Self { KeyPair::from(&id) }
}

/// Convert an uno ID into its symmetric encryption secret.
impl From<Id> for SymmetricKey
{
    fn from(id: Id) -> Self { SymmetricKey::from(&id) }
}

/// Convert an uno Id into its public/private keypair representation.
impl From<&Id> for KeyPair
{
    fn from(id: &Id) -> Self
    {
        let ctx: &'static str = Usage::Signature.into();
        let mut secret = [0u8; djb::PRIVATE_KEY_LENGTH];
        blake3::derive_key(ctx, &id.0, &mut secret);
        // This only panics if we use the wrong keys size, and we use the right
        // one so there's no point in propagating the error.
        let private = djb::PrivateKey::from_bytes(&secret).unwrap();
        let public: djb::PublicKey = (&private).into();
        KeyPair { secret: private, public: public }
    }
}

/// Convert an uno ID into its symmetric encryption secret.
impl From<&Id> for SymmetricKey
{
    fn from(id: &Id) -> Self
    {
        let ctx: &'static str = Usage::Encryption.into();
        let mut key = SymmetricKey::default();
        blake3::derive_key(ctx, &id.0, key.as_mut_slice());
        key
    }
}

/// Split an uno ID into shards using the SLIP-0039 shamir's protocol.
/// The scheme parameter is a list of tuples (t, n) like [(3, 5)] which means,
/// "one group of five with a share threshold of 3". The threshold is the
/// minimum number of shares needed to reconstitute the identity.
pub fn split(id: Id, scheme: &[(u8, u8)]) -> Result<Vec<GroupShare>, Error>
{
    let shares = s39::split(&id.0, scheme)?;
    Ok(shares)
}

/// Combine shards back into the original uno id.
pub fn combine(shares: &[Vec<String>]) -> Result<Id, Error>
{
    let bytes = s39::combine(shares)?;
    let id = Id::try_from(&bytes[..])?;
    Ok(id)
}

/// The Mu (μ) represents seed entropy for short-lived shamirs sessions. While
/// our Id seed is 32 bytes, the Mu is only 10 bytes. Ecoji encodes 80 bits as
/// 8 unicode emoji with no padding.
pub struct Mu(pub [u8; MU_LENGTH]);

pub const MU_LENGTH: usize = 10;

impl Mu
{
    /// Generate new uno Mu entropy.
    pub fn new() -> Self
    {
        let mut seed = [0u8; MU_LENGTH];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        Mu(seed)
    }
}

/// Convert an uno ID into its symmetric encryption secret.
impl From<Mu> for SymmetricKey
{
    fn from(mu: Mu) -> Self { SymmetricKey::from(&mu) }
}

impl TryFrom<&[u8]> for Mu
{
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error>
    {
        let array = <[u8; MU_LENGTH]>::try_from(bytes)?;
        Ok(Mu(array))
    }
}

/// Convert an uno Mu into its symmetric encryption secret.
impl From<&Mu> for SymmetricKey
{
    fn from(mu: &Mu) -> Self
    {
        let ctx = "uno recovery share secret";
        let mut key = SymmetricKey::default();
        blake3::derive_key(ctx, &mu.0, key.as_mut_slice());
        key
    }
}

/// A Session is "public" bits derived from Mu entropy for keying ephemeral
/// shamir's sessions on the server.
pub struct Session(pub [u8; 32]);

impl TryFrom<Mu> for Session
{
    type Error = Error;

    fn try_from(mu: Mu) -> Result<Self, Self::Error> { Session::try_from(&mu) }
}

impl TryFrom<&Mu> for Session
{
    type Error = Error;

    fn try_from(mu: &Mu) -> Result<Self, Self::Error>
    {
        let salt = b"uno shamir secret share session id";

        use argon2::{Algorithm, Argon2, Version};

        #[cfg(not(test))]
        // let ctx = Argon2::new(None, 512, 4096, 16, Version::V0x13)?;
        let ctx = Argon2::new(None, 16, 65536, 16, Version::V0x13)?;
        #[cfg(test)]
        let ctx = Argon2::new(None, 3, 4096, 1, Version::V0x13)?;

        let mut out = [0u8; 32];
        let _ = ctx.hash_password_into(
            Algorithm::Argon2d,
            &mu.0,
            salt,
            b"",
            &mut out,
        )?;

        Ok(Session(out))
    }
}

/// The additional data associated with an encrypt/decrypt (aead) operation.
#[derive(Copy, Clone, Debug, Display, EnumString)]
pub enum Binding<'a>
{
    /// Vault data
    #[strum(serialize = "vault")]
    Vault,
    /// Shamir's Scret Sharing Session split
    #[strum(serialize = "split")]
    Split,
    /// Shamir's Secret Sharing Session combine
    #[strum(serialize = "combine")]
    Combine,
    /// A 1 of 1 "split" for bootstrapping the web extension or another app
    #[strum(serialize = "transfer")]
    Transfer,
    /// A Magic Share payload
    #[strum(serialize = "share")]
    MagicShare,
    /// User-specified additional data
    #[strum(disabled)]
    Custom(&'a str),
    /// Empty additional data
    #[strum(serialize = "none")]
    None,
}

impl<'a> Binding<'a>
{
    pub fn context(self) -> &'a str
    {
        match self {
            Binding::Vault => "authentication vault",
            Binding::Split => "uno ssss split",
            Binding::Combine => "uno share combine",
            Binding::Transfer => "uno ssss transfer",
            Binding::MagicShare => "uno magic share",
            Binding::Custom(s) => s,
            Binding::None => "",
        }
    }
}

pub fn encrypt(
    usage: Binding,
    key: SymmetricKey,
    data: &[u8],
) -> Result<Vec<u8>, Error>
{
    let ctx = usage.context();
    Ok(djb::encrypt(key, data, ctx.as_bytes())?)
}

pub fn decrypt(
    usage: Binding,
    key: SymmetricKey,
    data: &[u8],
) -> Result<Vec<u8>, Error>
{
    let ctx = usage.context();
    Ok(djb::decrypt(key, data, ctx.as_bytes())?)
}

pub fn prove_blake3_work(nonce: &[u8], cost: u8) -> Option<u32>
{
    let maxn: u32 = u32::MAX - 1;
    let mut n: u32 = 0;
    while n < maxn {
        if verify_blake3_work(nonce, n, cost) {
            return Some(n);
        }

        n += 1;
    }

    None
}

pub fn verify_blake3_work(nonce: &[u8], proof: u32, cost: u8) -> bool
{
    let mut hash = blake3::Hasher::new();
    hash.update(&nonce);
    hash.update(&proof.to_le_bytes());

    let digest = hash.finalize().as_bytes().to_vec();
    if (digest[0] & cost) == 0 {
        return true;
    }

    false
}

#[cfg(test)]
mod unit
{
    use super::*;

    #[test]
    fn keypair_from_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let bytes64 = "JAqq6Fa/tHQD2LRtyn5B/RgX0FzKpjikcgDPi5Rgxbo";
        let bytes = base64::decode(bytes64)?;
        let id = Id::try_from(&*bytes)?;
        let actual = KeyPair::from(&id);
        let expected64 = "18ORHYIJBf48uXH9tj3uSx/0/hK1EtIxB6aY/\
                          fedPHYdQFZwBfUaRtU33C/w7eeqC0G+vHbLq/nmFFZay2/8Vg==";

        let expected = base64::decode(expected64)?;
        assert_eq!(expected, actual.to_bytes());

        Ok(())
    }

    #[test]
    fn encryption_from_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let bytes64 = "JAqq6Fa/tHQD2LRtyn5B/RgX0FzKpjikcgDPi5Rgxbo";
        let bytes = base64::decode(bytes64)?;
        let id = Id::try_from(&*bytes)?;
        let actual = SymmetricKey::from(&id);
        let expected64 = "DrEDTahFReS8G+dCGz5GjUnG+idrEWZbOXfsgo7ZGFc=";
        let expected = base64::decode(expected64)?;

        assert_eq!(expected, actual.as_slice());

        Ok(())
    }

    #[test]
    fn session_from_mu() -> Result<(), Box<dyn std::error::Error>>
    {
        let bytes64 = "zrzOvM68zrzOvA"; // "μμμμμ".as_bytes();
        let bytes = base64::decode(bytes64)?;
        let mu = Mu::try_from(&*bytes)?;
        let actual = Session::try_from(mu)?;
        // #[cfg(not(test))]
        // let expected64 = "/OyfB68hodit2UYqBp/9nMY1qukjNhEMH401e/r7D78";
        // #[cfg(test)]
        let expected64 = "rFM2e4J8LBPhFZ2AeyK70/wkfiomaiVh8+Ktya+XNdg";
        let expected = base64::decode(expected64)?;
        dbg!(base64::encode(&actual.0));
        assert_eq!(expected, actual.0);

        Ok(())
    }

    #[test]
    fn encryption_from_mu() -> Result<(), Box<dyn std::error::Error>>
    {
        let bytes64 = "zrzOvM68zrzOvA"; // "μμμμμ".as_bytes();
        let bytes = base64::decode(bytes64)?;
        let mu = Mu::try_from(&*bytes)?;
        let actual = SymmetricKey::from(&mu);
        let expected = vec![
            231, 65, 139, 157, 21, 173, 103, 71, 3, 93, 33, 90, 217, 249, 187,
            37, 4, 1, 111, 216, 84, 125, 27, 119, 71, 92, 3, 52, 10, 37, 70,
            116,
        ];
        assert_eq!(expected, actual.as_slice());

        Ok(())
    }

    #[test]
    fn blake3_proof()
    {
        let random_bytes = b"12345678901234567890123456789012";
        let cost = 255; // make it easy

        let proof = prove_blake3_work(random_bytes, cost);
        assert!(proof.is_some());

        assert!(verify_blake3_work(random_bytes, proof.unwrap(), cost));
        // some other proof will fail
        assert!(!verify_blake3_work(random_bytes, 0, cost));
    }
}
