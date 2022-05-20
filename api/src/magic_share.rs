//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use crate::store::Database;

use std::result;

use uno::MagicShare;

use chrono::{Duration, Utc};
use serde_json::{Error as SerdeError, Value};

use thiserror::Error;

const PREFIX_ONE_DAY: &'static str = "1d";
const PREFIX_ONE_WEEK: &'static str = "1w";
const PREFIX_ONE_MONTH: &'static str = "1m";

#[derive(Error, Debug)]
pub enum MagicShareError
{
    #[error("Serde error")]
    Serde
    {
        #[from]
        source: SerdeError,
    },
    #[error("Duplicate")]
    Duplicate,
    #[error("Expired")]
    Expired,
    #[error("Not found")]
    NotFound,
    #[error("Unsupported schema version")]
    Schema,
    #[error("Unknown magic share error")]
    Unknown,
}

type Result<T> = result::Result<T, MagicShareError>;

fn v0_from_json(json: &[u8]) -> Result<MagicShare>
{
    match serde_json::from_slice::<MagicShare>(json) {
        Ok(v) => Ok(v),
        Err(e) => Err(MagicShareError::Serde { source: e }),
    }
}

pub fn new_from_json(json: &[u8]) -> Result<MagicShare>
{
    let v: Value = match serde_json::from_slice(json) {
        Ok(s) => s,
        Err(e) => return Err(MagicShareError::Serde { source: e }),
    };

    if let Some(s) = v["schema_version"].as_u64() {
        match s {
            0 => return v0_from_json(json),
            _ => return Err(MagicShareError::Schema),
        };
    }

    //XXX: this could be a separate error?
    Err(MagicShareError::Schema)
}

pub async fn find_by_id(db: &impl Database, id: &str) -> Result<MagicShare>
{
    for x in &[PREFIX_ONE_DAY, PREFIX_ONE_WEEK, PREFIX_ONE_MONTH] {
        let key = format!("{}/{}", x, id);
        if let Ok(v) = get_share(db, &key).await {
            // XXX: handle the other error types here?
            return Ok(v);
        }
    }

    Err(MagicShareError::NotFound)
}

pub async fn get_share(db: &impl Database, location: &str)
-> Result<MagicShare>
{
    if let Ok(bytes) = db.get(location).await {
        match serde_json::from_slice::<MagicShare>(&bytes) {
            Ok(m) => {
                if Utc::now() > m.expires_at {
                    return Err(MagicShareError::Expired);
                }

                return Ok(m);
            },
            Err(e) => return Err(MagicShareError::Serde { source: e }),
        }
    }

    Err(MagicShareError::NotFound)
}

pub async fn store_share(
    db: &impl Database,
    share: &MagicShare,
) -> Result<String>
{
    if find_by_id(db, &share.id).await.is_ok() {
        return Err(MagicShareError::Duplicate);
    }

    let diff = share.expires_at - Utc::now();
    let expiration_prefix = if diff < Duration::days(1) {
        PREFIX_ONE_DAY
    } else if diff < Duration::days(7) {
        PREFIX_ONE_WEEK
    } else {
        PREFIX_ONE_MONTH
    };

    let key = format!("{}/{}", expiration_prefix, share.id);
    let bytes = match serde_json::to_vec(&share) {
        Ok(b) => b,
        Err(e) => return Err(MagicShareError::Serde { source: e }),
    };

    match db.put(&key, &bytes).await {
        Ok(_) => Ok(key.to_string()),
        Err(_) => Err(MagicShareError::Unknown),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_new_v0_from_json()
    {
        let bad_schema_version = "";
        assert!(new_from_json(bad_schema_version.as_bytes()).is_err());

        let unsupported_schema = "{\"schema_version\": 1000}";
        assert!(new_from_json(unsupported_schema.as_bytes()).is_err());

        let v = r#"
        {
            "schema_version": 0,
            "id": "1234",
            "expires_at": "2014-03-12T13:37:27+00:00",
            "encrypted_credential": "some encrypted thing"
        }"#;

        let m = new_from_json(v.as_bytes()).unwrap();

        assert_eq!(m.schema_version, 0);
        //XXX: assert dates somehow...
    }

    #[cfg(not(feature = "s3"))]
    use crate::store::FileStore;

    #[cfg(not(feature = "s3"))]
    #[async_std::test]
    async fn test_share_roundtrip()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let m1 = MagicShare {
            id: "1234".to_string(),
            expires_at: Utc::now() + Duration::days(30),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        let location = store_share(&db, &m1).await.unwrap();
        let r = get_share(&db, &location).await.unwrap();
        assert_eq!(m1.id, r.id);
    }

    #[cfg(not(feature = "s3"))]
    #[async_std::test]
    async fn test_find_by_id()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let m1 = MagicShare {
            id: "1234".to_string(),
            expires_at: Utc::now() + Duration::days(30),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        store_share(&db, &m1).await.unwrap();
        let r = find_by_id(&db, &m1.id).await.unwrap();
        assert_eq!(r.id, m1.id);

        // find only non-expired items
        let m2 = MagicShare {
            id: "5678".to_string(),
            expires_at: Utc::now() - Duration::days(30),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        store_share(&db, &m2).await.unwrap();
        let r2 = find_by_id(&db, &m2.id).await;
        assert!(r2.is_err());

        // if an expired item exists with the same id as a
        // non-expired item, return the non-expired one.
        let m3 = MagicShare {
            id: "5678".to_string(),
            expires_at: Utc::now() + Duration::days(30),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        store_share(&db, &m3).await.unwrap();
        let r3 = find_by_id(&db, &m3.id).await.unwrap();
        assert_eq!(r3.id, m3.id);
    }

    #[cfg(not(feature = "s3"))]
    #[async_std::test]
    async fn test_no_duplicate_shares()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let mut m1 = MagicShare {
            id: "1234".to_string(),
            expires_at: Utc::now() + Duration::days(30),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        assert!(store_share(&db, &m1).await.is_ok());
        assert!(store_share(&db, &m1).await.is_err());

        // different expiration class doesn't matter
        m1.expires_at = Utc::now() + Duration::hours(1);
        assert!(store_share(&db, &m1).await.is_err());

        // expired objects can be overwritten
        let mut m2 = MagicShare {
            id: "5678".to_string(),
            expires_at: Utc::now() - Duration::days(30),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };
        assert!(store_share(&db, &m2).await.is_ok());

        m2.expires_at = Utc::now() + Duration::days(30);
        assert!(store_share(&db, &m2).await.is_ok());
    }

    #[cfg(not(feature = "s3"))]
    #[async_std::test]
    async fn test_expiration_rounding()
    {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        //XXX: this would be more correct if we had a test utility to freeze
        // time at different intervals...
        let m1 = MagicShare {
            id: "1234".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        let mut location = store_share(&db, &m1).await.unwrap();
        assert_eq!(location, "1d/1234".to_string());

        let m2 = MagicShare {
            id: "1234a".to_string(),
            expires_at: Utc::now() + Duration::days(2),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        location = store_share(&db, &m2).await.unwrap();
        assert_eq!(location, "1w/1234a".to_string());

        let m3 = MagicShare {
            id: "1234b".to_string(),
            expires_at: Utc::now() + Duration::weeks(2),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        location = store_share(&db, &m3).await.unwrap();
        assert_eq!(location, "1m/1234b".to_string());

        let m4 = MagicShare {
            id: "1234c".to_string(),
            expires_at: Utc::now() + Duration::weeks(8),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        location = store_share(&db, &m4).await.unwrap();
        assert_eq!(location, "1m/1234c".to_string());
    }
}
