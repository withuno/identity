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
use serde_json::json;

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

#[derive(PartialEq, Debug)]
pub enum VerificationStatus
{
    Verified(String),
    Pending(String, PreviousStatus),
    Unverified,
}

#[derive(PartialEq, Debug)]
pub enum PreviousStatus
{
    Verified(String),
    Unverified,
}

pub async fn get(db: &impl Database, id: &str) -> Result<VerificationStatus>
{
    let pending_key = format!("pending/{}", id);
    let entries_key = format!("entries/{}", id);

    let pending_exists =
        db.exists(&pending_key).await.map_err(|_| VerifyTokenError::Unknown)?;

    let entry_exists =
        db.exists(&entries_key).await.map_err(|_| VerifyTokenError::Unknown)?;

    if pending_exists {
        // TODO: && not expired?

        let pending_bytes = db
            .get(&pending_key)
            .await
            .map_err(|_| VerifyTokenError::Unknown)?;
        let pending_entry: UnverifiedToken =
            serde_json::from_slice(&pending_bytes)?;

        if entry_exists {
            let entry_bytes = db
                .get(&entries_key)
                .await
                .map_err(|_| VerifyTokenError::Unknown)?;
            let verified_entry: VerifiedToken =
                serde_json::from_slice(&entry_bytes)?;

            return Ok(VerificationStatus::Pending(
                pending_entry.email,
                PreviousStatus::Verified(verified_entry.email),
            ));
        } else {
            return Ok(VerificationStatus::Pending(
                pending_entry.email,
                PreviousStatus::Unverified,
            ));
        }
    } else {
        if entry_exists {
            let entry_bytes = db
                .get(&entries_key)
                .await
                .map_err(|_| VerifyTokenError::Unknown)?;
            let verified_entry: VerifiedToken =
                serde_json::from_slice(&entry_bytes)?;

            return Ok(VerificationStatus::Verified(verified_entry.email));
        }
    }

    return Ok(VerificationStatus::Unverified);
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LookupItem
{
    pub id: String,
}

pub async fn get_by_email(
    db: &impl Database,
    email: &str,
    include_pending: Option<bool>,
) -> Result<bool>
{
    let key = format!("lookup/{}", email);

    if db.exists(&key).await.map_err(|_| VerifyTokenError::Unknown)? {
        Ok(true)
    } else {
        if let Some(true) = include_pending {
            let key = format!("pending/email-cache/{}", email);
            if db.exists(&key).await.map_err(|_| VerifyTokenError::Unknown)? {
                return Ok(true);
            }
        }
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

    let cache_key = format!("pending/email-cache/{}", email);
    let cbytes = serde_json::to_vec(&json!(true))
        .map_err(|e| VerifyTokenError::Serde { source: e })?;
    let _ = db
        .put(&cache_key, &cbytes)
        .await
        .map_err(|_| VerifyTokenError::Unknown)?;

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
    // delete pending entry
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

    let _ =
        db.del(&pending_key).await.map_err(|_| VerifyTokenError::Unknown)?;

    let pending_cache_key =
        format!("pending/email-cache/{}", pending_token.email);
    let _ = db
        .del(&pending_cache_key)
        .await
        .map_err(|_| VerifyTokenError::Unknown)?;

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
    async fn test_statuses()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let id = "some id";
        let encoded_id = base64::encode_config(id, base64::URL_SAFE_NO_PAD);

        // no token
        assert_eq!(
            get(&db, &encoded_id).await.unwrap(),
            VerificationStatus::Unverified
        );

        let token = create(
            &db,
            &encoded_id,
            "analytics_id",
            "email",
            Utc::now() + Duration::days(30),
        )
        .await
        .unwrap();

        // pending token, no previous
        assert_eq!(
            get(&db, &encoded_id).await.unwrap(),
            VerificationStatus::Pending(
                "email".to_string(),
                PreviousStatus::Unverified
            )
        );

        // verified token
        verify(&db, &encoded_id, &token.secret).await.unwrap();
        assert_eq!(
            get(&db, &encoded_id).await.unwrap(),
            VerificationStatus::Verified("email".to_string())
        );

        // re-verify, same email
        create(
            &db,
            &encoded_id,
            "analytics_id",
            "email",
            Utc::now() + Duration::days(30),
        )
        .await
        .unwrap();
        assert_eq!(
            get(&db, &encoded_id).await.unwrap(),
            VerificationStatus::Pending(
                "email".to_string(),
                PreviousStatus::Verified("email".to_string())
            )
        );

        // re-verify, different email
        create(
            &db,
            &encoded_id,
            "analytics_id",
            "email2",
            Utc::now() + Duration::days(30),
        )
        .await
        .unwrap();
        assert_eq!(
            get(&db, &encoded_id).await.unwrap(),
            VerificationStatus::Pending(
                "email2".to_string(),
                PreviousStatus::Verified("email".to_string())
            )
        );
    }

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
