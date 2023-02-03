//
// Copyright (C) 2022 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use crate::store::Database;

use std::result;

use uno::{Mu, UnverifiedToken, VerifiedToken};

use chrono::{DateTime, Utc};
use serde_json::Error as SerdeError;

use thiserror::Error;

use serde::{Deserialize, Serialize};

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
    let key = format!("entries/{}", id);

    match db.get(&key).await {
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

#[derive(Serialize, Deserialize, Debug)]
pub struct LookupItem
{
    pub id: String,
}

pub async fn get_by_email(
    db: &impl Database,
    email: &str,
    pubkey: Option<&str>,
) -> Result<bool>
{
    let key = format!("lookup/{}", email);

    if db.exists(&key).await.map_err(|_| VerifyTokenError::Unknown)? {
        if let Some(pk) = pubkey {
            let bytes =
                db.get(&key).await.map_err(|_| VerifyTokenError::Unknown)?;
            let item: LookupItem = serde_json::from_slice(&bytes)?;
            if pk != item.id {
                return Ok(false);
            }
        }
        Ok(true)
    } else {
        Ok(false)
    }
}


pub async fn create(
    db: &impl Database,
    id: &str,
    analytics_id: &str,
    email: &str,
    expires_at: DateTime<Utc>,
) -> Result<UnverifiedToken>
{
    let key = format!("pending/{}", id);

    let secret = Mu::new();
    let encoded_secret = base64::encode(secret.0);

    let token =
        UnverifiedToken::new(email, analytics_id, encoded_secret, expires_at);

    let bytes = serde_json::to_vec(&token)
        .map_err(|e| VerifyTokenError::Serde { source: e })?;

    let _ =
        db.put(&key, &bytes).await.map_err(|_| VerifyTokenError::Unknown)?;

    Ok(token)
}

pub async fn verify(
    db: &impl Database,
    id: &str,
    secret: &str,
) -> Result<VerifiedToken>
{
    let pending_key = format!("pending/{}", id);
    let entries_key = format!("entries/{}", id);

    // get pending entry
    // match secrets
    // delete old entry
    // commit new entry

    let pending_exists =
        db.exists(&pending_key).await.map_err(|_| VerifyTokenError::Unknown)?;
    if !pending_exists {
        return Err(VerifyTokenError::NotFound);
    }

    let pending_bytes =
        db.get(&pending_key).await.map_err(|_| VerifyTokenError::Unknown)?;

    let pending_token: UnverifiedToken =
        serde_json::from_slice(&pending_bytes)?;

    // check

    if Utc::now() > pending_token.expires_at {
        return Err(VerifyTokenError::Expired);
    }

    if secret != pending_token.secret {
        return Err(VerifyTokenError::Secret);
    }

    // request is allowed

    let lookup_key = format!("lookup/{}", pending_token.email);

    let old_exists =
        db.exists(&lookup_key).await.map_err(|_| VerifyTokenError::Unknown)?;
    if old_exists {
        let old_bytes =
            db.get(&lookup_key).await.map_err(|_| VerifyTokenError::Unknown)?;
        let old_item: LookupItem = serde_json::from_slice(&old_bytes)?;
        let old_entry_key = format!("entries/{}", old_item.id);
        db.del(&old_entry_key).await.map_err(|_| VerifyTokenError::Unknown)?;

        db.del(&lookup_key).await.map_err(|_| VerifyTokenError::Unknown)?;
    }

    let verified_token =
        VerifiedToken::new(pending_token.email, pending_token.analytics_id);

    let verified_token_bytes = serde_json::to_vec(&verified_token)?;

    let _ = db
        .put(&entries_key, &verified_token_bytes)
        .await
        .map_err(|_| VerifyTokenError::Unknown)?;

    let item = LookupItem { id: id.into() };
    let item_bytes = serde_json::to_vec(&item)?;

    let _ = db
        .put(&lookup_key, &item_bytes)
        .await
        .map_err(|_| VerifyTokenError::Unknown)?;

    return Ok(verified_token);
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

        let email = "user@example.com";

        let result = verify(&db, &encoded_id, "secret").await;

        assert_eq!(
            VerifyTokenError::NotFound.to_string(),
            result.err().unwrap().to_string()
        );

        let mut u = create(
            &db,
            &encoded_id,
            "analytics_id",
            email,
            Utc::now() - Duration::days(1),
        )
        .await
        .unwrap();

        let result = verify(&db, &encoded_id, &u.secret).await;

        assert_eq!(
            VerifyTokenError::Expired.to_string(),
            result.err().unwrap().to_string()
        );

        u = create(
            &db,
            &encoded_id,
            "analytics_id",
            email,
            Utc::now() + Duration::days(1),
        )
        .await
        .unwrap();

        let result = verify(&db, &encoded_id, "some other secret").await;

        assert_eq!(
            VerifyTokenError::Secret.to_string(),
            result.err().unwrap().to_string()
        );

        let result = verify(&db, &encoded_id, &u.secret).await.unwrap();
        assert_eq!(result.email, "user@example.com");
    }
}
