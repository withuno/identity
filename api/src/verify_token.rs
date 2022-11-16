//
// Copyright (C) 2022 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use crate::store::Database;

use std::result;

use uno::{Mu, UnverifiedToken, VerifiedToken, VerifyMethod};

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

pub enum PossibleToken
{
    Verified,
    Unverified,
}

pub async fn get(db: &impl Database, id: &str) -> Result<PossibleToken>
{
    match db.get(&id).await {
        Ok(bytes) => {
            if serde_json::from_slice::<UnverifiedToken>(&bytes).is_ok() {
                return Ok(PossibleToken::Unverified);
            }

            match serde_json::from_slice::<VerifiedToken>(&bytes) {
                Ok(_) => Ok(PossibleToken::Verified),
                Err(e) => Err(VerifyTokenError::Serde { source: e }),
            }
        },
        Err(_) => Ok(PossibleToken::Unverified),
    }
}

pub async fn create(
    db: &impl Database,
    id: &str,
    analytics_id: String,
    method: VerifyMethod,
    expires_at: DateTime<Utc>,
) -> Result<UnverifiedToken>
{
    if let Ok(bytes) = db.get(&id).await {
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

    let t = UnverifiedToken::new(
        0,
        method,
        analytics_id,
        encoded_secret,
        expires_at,
    );

    let bytes = match serde_json::to_vec(&t) {
        Ok(b) => b,
        Err(e) => return Err(VerifyTokenError::Serde { source: e }),
    };

    match db.put(id, &bytes).await {
        Ok(_) => Ok(t),
        Err(_) => Err(VerifyTokenError::Unknown),
    }
}

pub async fn verify(
    db: &impl Database,
    id: &str,
    secret: &str,
) -> Result<VerifiedToken>
{
    if let Ok(bytes) = db.get(id).await {
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

                    let v = VerifiedToken::new(0, u.analytics_id, u.method);

                    let bytes = match serde_json::to_vec(&v) {
                        Ok(b) => b,
                        Err(e) => {
                            return Err(VerifyTokenError::Serde { source: e });
                        },
                    };

                    return match db.put(id, &bytes).await {
                        Ok(_) => Ok(v),
                        Err(_) => Err(VerifyTokenError::Unknown),
                    };
                },
                _ => {
                    return Err(VerifyTokenError::Schema);
                },
            },
            Err(e) => {
                println!("serde error {:?}", e);
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

    #[cfg(not(feature = "s3"))]
    use crate::store::FileStore;

    #[cfg(not(feature = "s3"))]
    #[async_std::test]
    async fn test_token_roundtrip()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let id = "some id";
        let encoded_id = base64::encode_config(id, base64::URL_SAFE_NO_PAD);

        let email = VerifyMethod::Email("user@example.com".to_string());

        match verify(&db, &encoded_id, "secret").await {
            Err(VerifyTokenError::NotFound) => {},
            _ => {
                assert!(false);
            },
        }

        let mut u = create(
            &db,
            &encoded_id,
            "analytics_id".to_string(),
            email.clone(),
            Utc::now() - Duration::days(1),
        )
        .await
        .unwrap();

        match verify(&db, &encoded_id, &u.secret).await {
            Err(VerifyTokenError::Expired) => {},
            _ => {
                assert!(false);
            },
        }

        u = create(
            &db,
            &encoded_id,
            "analytics_id".to_string(),
            email.clone(),
            Utc::now() + Duration::days(1),
        )
        .await
        .unwrap();

        match verify(&db, &encoded_id, "some other secret").await {
            Err(VerifyTokenError::Secret) => {},
            _ => {
                assert!(false);
            },
        }

        let v = verify(&db, &encoded_id, &u.secret).await.unwrap();
        assert_eq!(
            v.method,
            VerifyMethod::Email("user@example.com".to_string())
        );

        match create(
            &db,
            &encoded_id,
            "analytics_id".to_string(),
            email,
            Utc::now() + Duration::days(1),
        )
        .await
        {
            Err(VerifyTokenError::Done) => {},
            _ => {
                assert!(false);
            },
        }
    }
}
