pub use crate::store::Database;

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::Value;

use anyhow::{anyhow, Result};

#[derive(Deserialize)]
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

pub fn store_share(db: &impl Database, share: &MagicShare) -> Result<String> {
    return Ok("cool".to_string());
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
    async fn test_store() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = FileStore::new(dir.path(), "test", "v0").await.unwrap();

        let m1 = MagicShare {
            id: "1234".to_string(),
            expires_at: Utc::now(),
            schema_version: 0,
            encrypted_credential: "5678".to_string(),
        };

        let location = store_share(&db, &m1).unwrap();
        assert_eq!(location, "1d/1234".to_string());
    }
}
