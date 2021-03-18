//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// The uno identity is 32 bytes of entropy.
pub const ID_LENGTH: usize = 32;

mod error;
pub use error::Error;

/// And uno identity newtype.
#[derive(Debug)]
pub struct Id(pub [u8; ID_LENGTH]);

impl Id {
    /// Generate a new uno ID.
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        Id(seed)
    }
}

use std::str;
use std::convert::TryFrom;

/// A share is the result of running split on an uno id.
pub use adi::Share;

/// Build an uno identity from a byte slice.
impl TryFrom<&[u8]> for Id {
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array = <[u8; ID_LENGTH]>::try_from(bytes)?;
        Ok(Id(array))
    }
}

pub type Signing = djb::KeyPair;
pub type Verification = djb::PublicKey;
pub use djb::Signature;
pub use djb::Signer;
pub use djb::Verifier;

pub const SIGNATURE_LENGTH: usize = djb::SIGNATURE_LENGTH;

pub type Encryption = djb::SymmetricKey;

use strum_macros::IntoStaticStr;

/// Keys are derived from Uno IDs depending on their usage. This corresponds
/// to the context passed to the key derivation function.
#[derive(IntoStaticStr)]
pub enum Usage {
    #[strum(to_string = "uno seed identity keypair")]
    Signature,
    #[strum(to_string = "uno seed encryption secret")]
    Encryption,
}

/// Convert an uno Id into its public/private keypair representation.
impl From<Id> for Signing {
    fn from(id: Id) -> Self {
        Signing::from(&id)
    }
}

/// Convert an uno ID into its symmetric encryption secret.
impl From<Id> for Encryption {
    fn from(id: Id) -> Self {
        Encryption::from(&id)
    }
}

/// Convert an uno Id into its public/private keypair representation.
impl From<&Id> for Signing {
    fn from(id: &Id) -> Self {
        let ctx: &'static str = Usage::Signature.into();
        let mut secret = [0u8; djb::PRIVATE_KEY_LENGTH];
        blake3::derive_key(ctx, &id.0, &mut secret);
        // This only panics if we use the wrong keys size, and we use
        // the right one so there's no point in propagating the error.
        let private = djb::PrivateKey::from_bytes(&secret).unwrap();
        let public: djb::PublicKey = (&private).into();
        Signing {
                secret: private,
                public: public,
        }
    }
}

/// Convert an uno ID into its symmetric encryption secret.
impl From<&Id> for Encryption {
    fn from(id: &Id) -> Self {
        let ctx: &'static str = Usage::Encryption.into();
        let mut secret = Encryption::default();
        blake3::derive_key(ctx, &id.0, secret.as_mut_slice());
        secret
    }
}

/// Split an uno ID into shards using the SLIP-0039 shamir's protocol.
/// The scheme parameter is a list of tuples (t, n) like [(3, 5)] which means,
/// "one group of five with a share threshold of 3". The threshold is the
/// minimum number of shares needed to reconstitute the identity.
pub fn split(id: Id, scheme: &[(usize,usize)]) -> Result<Vec<Share>, Error> {
    let shares = adi::split(&id.0, scheme)?;
    Ok(shares)
}

/// Combine shards back into the original uno id.
pub fn combine(shares: &[Share]) -> Result<Id, Error> {
    let bytes = adi::combine(shares)?;
    let id = Id::try_from(&bytes[..])?;
    Ok(id)
}

pub use djb::decrypt;
pub use djb::encrypt;

use surf::Url;
use chrono::offset::Utc;

pub fn get_vault(host: String, id: Id) -> Result<String, Error>
{
    let key = Signing::from(&id);
    let sym = Encryption::from(&id);

    let timestamp = Utc::now().to_rfc3339();
    let signature = key.sign(timestamp.as_bytes());

    let url = url_from_key(&host, &key)?;
    let req = surf::get(url.as_str())
        .header("x-uno-timestamp", timestamp)
        .header("x-uno-signature", base64::encode(&signature.to_bytes()))
        .build();

    let blob = async_std::task::block_on(do_vault_http(req))?;
    let vault = decrypt(sym, &blob)?;
    Ok(String::from_utf8(vault)?)
}

pub fn put_vault(host: String, id: Id, data: &[u8]) -> Result<String, Error>
{
    let key = Signing::from(&id);
    let sym = Encryption::from(&id);

    let timestamp = Utc::now().to_rfc3339();
    let signature = key.sign(timestamp.as_bytes());

    let cyph = encrypt(sym, data)?;
    let csig = key.sign(&cyph).to_bytes();
    let body = [&csig[..], &*cyph].concat();

    let url = url_from_key(&host, &key)?;
    let req = surf::put(url.as_str())
        .header("x-uno-timestamp", timestamp)
        .header("x-uno-signature", base64::encode(&signature.to_bytes()))
        .body(body)
        .build();

    let blob = async_std::task::block_on(do_vault_http(req))?;
    let vault = decrypt(sym, &blob)?;
    Ok(String::from_utf8(vault)?)
}

fn url_from_key(endpoint: &str, key: &Signing) -> Result<surf::Url, Error>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("api/v1/vaults/")?;
    let cfg = base64::URL_SAFE_NO_PAD;
    let vid = base64::encode_config(key.public.as_bytes(), cfg);
    Ok(base.join(&vid)?)
}

async fn do_vault_http(req: surf::Request) -> Result<Vec<u8>, Error>
{
    let sclient = surf::client();
    let mut res = sclient.send(req).await?;
    let status = res.status();
    if status != 200 {
        return Err(Error::Uno(format!("server returned: {}", status)));
    }
    Ok(res.body_bytes().await?)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_id_gen() {

    }

    #[test]
    fn test_signature_into() {

    }

    #[test]
    fn test_encryption_into() {

    }
}
