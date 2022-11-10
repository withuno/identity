//
// Copyright (C) 2022 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use crate::store::Database;

use std::result;

use uno::{Mu, PublicKey, UnverifiedToken, VerifiedToken, VerifyMethod};

use chrono::{DateTime, Utc};
use serde_json::Error as SerdeError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyTokenError
{
    #[error("Serde error")]
    Serde
    {
        #[from]
        source: SerdeError,
    },
    #[error("Bad secret")]
    Secret,
    #[error("Expired")]
    Expired,
    #[error("Already verified")]
    Done,
    #[error("Not found")]
    NotFound,
    #[error("Unsupported schema version")]
    Schema,
    #[error("Unknown verify token error")]
    Unknown,
}

type Result<T> = result::Result<T, VerifyTokenError>;

pub async fn create(
    db: &impl Database,
    id: PublicKey,
    expires_at: DateTime<Utc>,
) -> Result<UnverifiedToken>
{
    let encoded_id = base64::encode(id);

    if let Ok(bytes) = db.get(&encoded_id).await {
        if serde_json::from_slice::<VerifiedToken>(&bytes).is_ok() {
            return Err(VerifyTokenError::Done);
        }

        match serde_json::from_slice::<UnverifiedToken>(&bytes) {
            Ok(_) => {},
            Err(e) => {
                return Err(VerifyTokenError::Serde { source: e });
            },
        };

        // otherwise overwrite the unverified token, which corresponds
        // to the case of "resend the confirmation email", etc.
    }

    let secret = Mu::new();
    let encoded_secret = base64::encode(secret.0);

    let t = UnverifiedToken {
        schema_version: 0,
        secret: encoded_secret,
        expires_at: expires_at,
    };

    let bytes = match serde_json::to_vec(&t) {
        Ok(b) => b,
        Err(e) => return Err(VerifyTokenError::Serde { source: e }),
    };

    match db.put(encoded_id, &bytes).await {
        Ok(_) => Ok(t),
        Err(_) => Err(VerifyTokenError::Unknown),
    }
}

pub async fn verify(
    db: &impl Database,
    id: PublicKey,
    secret: &str,
    method: VerifyMethod,
) -> Result<VerifiedToken>
{
    let encoded_id = base64::encode(id);

    if let Ok(bytes) = db.get(&encoded_id).await {
        if serde_json::from_slice::<VerifiedToken>(&bytes).is_ok() {
            return Err(VerifyTokenError::Done);
        }

        match serde_json::from_slice::<UnverifiedToken>(&bytes) {
            Ok(u) => match u.schema_version {
                0 => {
                    if Utc::now() > u.expires_at {
                        return Err(VerifyTokenError::Expired);
                    }

                    if u.secret != secret {
                        return Err(VerifyTokenError::Secret);
                    }

                    let v = VerifiedToken { schema_version: 0, method: method };

                    let bytes = match serde_json::to_vec(&v) {
                        Ok(b) => b,
                        Err(e) => {
                            return Err(VerifyTokenError::Serde { source: e });
                        },
                    };

                    return match db.put(encoded_id, &bytes).await {
                        Ok(_) => Ok(v),
                        Err(_) => Err(VerifyTokenError::Unknown),
                    };
                },
                _ => {
                    return Err(VerifyTokenError::Schema);
                },
            },
            Err(e) => {
                return Err(VerifyTokenError::Serde { source: e });
            },
        };
    }

    Err(VerifyTokenError::NotFound)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use chrono::Duration;
    use uno::{Id, KeyPair};


    #[cfg(not(feature = "s3"))]
    use crate::store::FileStore;

    #[cfg(not(feature = "s3"))]
    #[async_std::test]
    async fn test_token_roundtrip()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let id = Id::new();
        let keypair = KeyPair::from(id);

        let email = VerifyMethod::Email("user@uno.app".to_string());

        match verify(&db, keypair.public, "secret", email.clone()).await {
            Err(VerifyTokenError::NotFound) => {},
            _ => {
                assert!(false);
            },
        }

        let mut u = create(&db, keypair.public, Utc::now() - Duration::days(1))
            .await
            .unwrap();

        match verify(&db, keypair.public, &u.secret, email.clone()).await {
            Err(VerifyTokenError::Expired) => {},
            _ => {
                assert!(false);
            },
        }

        u = create(&db, keypair.public, Utc::now() + Duration::days(1))
            .await
            .unwrap();

        match verify(&db, keypair.public, "some other secret", email.clone())
            .await
        {
            Err(VerifyTokenError::Secret) => {},
            _ => {
                assert!(false);
            },
        }

        let v = verify(&db, keypair.public, &u.secret, email).await.unwrap();
        assert_eq!(v.method, VerifyMethod::Email("user@uno.app".to_string()));

        match create(&db, keypair.public, Utc::now() + Duration::days(1)).await
        {
            Err(VerifyTokenError::Done) => {},
            _ => {
                assert!(false);
            },
        }
    }
}
