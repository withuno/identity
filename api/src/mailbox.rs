//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use crate::store::Database;

use anyhow::anyhow;
use anyhow::Result;
use futures::stream;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mailbox {
    pub messages: Vec<MessageStored>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Payload {
    pub signature: String,
    #[serde(default)]
    pub share: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MessageToDelete {
    pub from: String,
    pub id: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct MessageRequest {
    pub action: String,
    pub uuid: String,
    pub data: Payload,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageStored {
    pub action: String,
    pub uuid: String,
    pub id: u64,
    pub from: String,
    pub data: Payload,
}

pub async fn delete_messages(
    store: &impl Database,
    owner: &str,
    messages: &Vec<MessageToDelete>,
) -> Result<usize> {
    let results = stream::iter(messages)
        .filter_map(|m| async move {
            let dest = format!("{}/{}/{}", owner, m.from, m.id);
            // only count deletes that are Ok
            store.del(&dest).await.ok()
        })
        .collect::<Vec<_>>().await;

    Ok(results.len())
}

pub async fn get_messages(
    store: &impl Database,
    owner: &str,
) -> Result<Mailbox> {
    // LOCK
    let m_ids = store.list(owner).await?;
    let messages = stream::iter(m_ids)
        .filter_map(|id| async move {
            store.get(&id).await
                .and_then(|m| serde_json::from_slice(&m)
                    .map_err(|e| anyhow!(e)))
                .ok() // convert to option
        })
        .collect::<Vec<_>>()
        .await;
    // UNLOCK

    Ok(Mailbox { messages })
}

pub async fn post_message(
    store: &impl Database,
    recipient: &str,
    sender: &str,
    message: &MessageRequest,
) -> Result<MessageStored> {
    let prefix = format!("{}/{}", recipient, sender);

    // LOCK
    let existing = store.list(&prefix).await?;
    let ids: Vec<u64> = existing
        .iter()
        .map(|m| {
            let id = m.split("/").last().unwrap();
            id.parse::<u64>().unwrap()
        })
        .collect();

    let next_id = match ids.iter().max() {
        Some(max) => max + 1,
        None => 1,
    };

    let dest = format!("{}/{}", prefix, next_id);

    let m = MessageStored {
        id: next_id,
        from: sender.to_string(),
        uuid: message.uuid.clone(),
        action: message.action.clone(),
        data: message.data.clone(),
    };

    let j = serde_json::to_vec(&m)?;

    store.put(&dest, &j).await?;

    let b2 = store.get(&dest).await?;
    let m2: MessageStored = serde_json::from_slice(&b2)?;
    // UNLOCK

    Ok(m2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "s3")]
    use crate::store::S3Store;

    #[cfg(feature = "s3")]
    async fn new_store() -> Result<S3Store> {
        use rand::distributions::Alphanumeric;
        use rand::Rng;

        fn tmpname(rand_len: usize) -> String {
            let mut buf = String::with_capacity(rand_len);

            // Push each character in one-by-one. Unfortunately, this is the
            // only safe(ish) simple way to do this without allocating a
            // temporary String/Vec.
            unsafe {
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(rand_len)
                    .for_each(|b| {
                        buf.push_str(std::str::from_utf8_unchecked(&[b as u8]))
                    })
            }
            buf.to_lowercase()
        }

        let store = S3Store::new(
            "http://localhost:9000",
            "minio",
            "minioadmin",
            "minioadmin",
            &tmpname(32),
            "v0",
        ).await?;

        let _ = store.create_bucket_if_not_exists().await?;

        Ok(store)
    }

    #[cfg(not(feature = "s3"))]
    use crate::store::FileStore;

    #[cfg(not(feature = "s3"))]
    async fn new_store() -> Result<FileStore> {
        let dir = tempfile::TempDir::new()?;

        Ok(FileStore::new(dir.path(), "test", "v0").await?)
    }

    #[async_std::test]
    async fn message_uuid() -> Result<()> {
        let store = new_store().await?;
        let owner1 = "owner1".to_string();
        let sender1 = "sender1".to_string();

        let any_message = MessageRequest {
            uuid: "1111-2222".to_string(),
            action: "packed".to_string(),
            data: Payload {
                signature: "signature".to_string(),
                share: "share".to_string(),
            },
        };

        let _ = post_message(&store, &owner1, &sender1, &any_message).await?;

        let g1 = get_messages(&store, &owner1).await?;
        assert_eq!(g1.messages[0].uuid, "1111-2222");

        Ok(())
    }

    #[async_std::test]
    async fn mailbox_messages() -> Result<()> {
        let store = new_store().await?;
        let owner1 = "owner1".to_string();
        let owner2 = "owner2".to_string();

        let sender1 = "sender1".to_string();
        let sender2 = "sender2".to_string();

        let any_message = MessageRequest {
            uuid: "11111".to_string(),
            action: "packed".to_string(),
            data: Payload {
                signature: "signature".to_string(),
                share: "share".to_string(),
            },
        };

        let r1 = post_message(&store, &owner1, &sender1, &any_message).await?;
        assert_eq!(r1.id, 1);
        assert_eq!(r1.from, sender1.clone());

        let r2 = post_message(&store, &owner1, &sender1, &any_message).await?;
        assert_eq!(r2.id, 2);
        assert_eq!(r2.from, sender1);

        let r3 = post_message(&store, &owner1, &sender2, &any_message).await?;
        assert_eq!(r3.id, 1);
        assert_eq!(r3.from, sender2);

        let r4 = post_message(&store, &owner2, &sender1, &any_message).await?;
        assert_eq!(r4.id, 1);
        assert_eq!(r4.from, sender1);

        let g1 = get_messages(&store, &owner1).await?;
        assert_eq!(g1.messages.len(), 3);

        let num_deleted = delete_messages(
            &store,
            &owner1,
            &vec![
                MessageToDelete {
                    from: sender1,
                    id: r2.id,
                },
                MessageToDelete {
                    from: sender2,
                    id: r3.id,
                },
            ],
        ).await?;

        assert_eq!(num_deleted, 2);

        let g2 = get_messages(&store, &owner1).await?;
        assert_eq!(g2.messages.len(), 1);
        assert_eq!(g2.messages[0].id, 1);
        assert_eq!(g2.messages[0].from, "sender1".to_string());

        Ok(())
    }

    #[test]
    fn ios_deserialize() -> Result<()> {
        let s1 = r#"{"data":{"share":"IKlx5OuP22Xux5JSOeekYH+zLmhiemgHF25QV4yxK/Cq8VlYZa41qWElDD+Ue9tdzdm23j78MpfCTlLCew==","signature":"UEq/S7j5cXAuEo7K5LVEiMGdWbLwqQxxQNKVlXtgLbB8ecY4+u3YF3S\/uMhohZx5pmKJ6qWZccoj7+9dAqA/CQ=="},"uuid":"not_from_ios","action":"share-update","from":"DkxRk21yuqwA2Uf1P7At08OD8434fwEnAc9-Ckmve20"}"#;
        let s2 = r#"{"data":{"signature":"UEq/S7j5cXAuEo7K5LVEiMGdWbLwqQxxQNKVlXtgLbB8ecY4+u3YF3S\/uMhohZx5pmKJ6qWZccoj7+9dAqA/CQ=="},"uuid":"not_from_ios","action":"share-update","from":"DkxRk21yuqwA2Uf1P7At08OD8434fwEnAc9-Ckmve20"}"#;

        // just check that we don't panic
        let _: MessageRequest = serde_json::from_slice(s1.as_bytes())?;
        let _: MessageRequest = serde_json::from_slice(s2.as_bytes())?;
        assert!(true);

        Ok(())
    }
}
