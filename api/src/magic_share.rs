pub use crate::store::Database;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use anyhow::{anyhow, Result};

const PREFIX_ONE_DAY: &'static str = "1d";
const PREFIX_ONE_WEEK: &'static str = "1w";
const PREFIX_ONE_MONTH: &'static str = "1m";

#[derive(Serialize, Deserialize)]
pub struct MagicShare {
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub schema_version: u64,
    pub encrypted_credential: String,
}

fn v0_from_json(json: &[u8]) -> Result<MagicShare> {
    let m: MagicShare = serde_json::from_slice(json)?;

    Ok(m)
}

pub fn new_from_json(json: &[u8]) -> Result<MagicShare> {
    let v: Value = serde_json::from_slice(json)?;

    match v["schema_version"].as_u64() {
        Some(s) => match s {
            0 => v0_from_json(json),
            _ => Err(anyhow!("Unsupported schema version")),
        },
        None => Err(anyhow!("Bad schema version")),
    }
}

pub async fn get_share(
    db: &impl Database,
    location: &str,
) -> Result<MagicShare> {
    let bytes = db.get(location).await?;

    let s: MagicShare = serde_json::from_slice(&bytes)?;
    if Utc::now() > s.expires_at {
        return Err(anyhow!("Expired"));
    }

    Ok(s)
}

pub async fn store_share(
    db: &impl Database,
    share: &MagicShare,
) -> Result<String> {
    let diff = share.expires_at - Utc::now();
    let expiration_prefix = if diff < Duration::days(1) {
       PREFIX_ONE_DAY 
    } else if diff < Duration::days(7) {
        PREFIX_ONE_WEEK
    } else {
        PREFIX_ONE_MONTH
    };

    let key = format!("{}/{}", expiration_prefix, share.id);
    let bytes = serde_json::to_vec(&share)?;

    match db.put(&key, &bytes).await {
        Ok(_) => Ok(key.to_string()),
        Err(e) => Err(anyhow!(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_v0_from_json() {
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
    async fn test_share_roundtrip() {
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
    async fn test_expiration_rounding() {
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
