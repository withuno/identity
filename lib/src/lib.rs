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
impl From<Id> for Encryption {
    fn from(id: Id) -> Self {
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
