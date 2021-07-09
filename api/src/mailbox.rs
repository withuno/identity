pub use crate::store::Database;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mailbox {
    pub messages: Vec<MessageStored>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Payload {
    pub signature: String,
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
    pub data: Payload,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageStored {
    pub action: String,
    pub id: u64,
    pub from: String,
    pub data: Payload,
}

pub fn delete_messages(
    store: &impl Database,
    owner: &str,
    messages: &Vec<MessageToDelete>,
) -> Result<(), anyhow::Error> {
    let _results: Vec<anyhow::Result<()>> = messages
        .iter()
        .map(|m| {
            let dest = format!("{}/{}/{}", owner, m.from, m.id);

            async_std::task::block_on(store.del(&dest))
        })
        .collect();

    Ok(())
}

pub fn get_messages(
    store: &impl Database,
    owner: &str,
) -> Result<Mailbox, anyhow::Error> {
    // LOCK
    let m = async_std::task::block_on(store.list(owner))?;
    let messages: Vec<MessageStored> = m
        .iter()
        .filter_map(|m| {
            let msg = match async_std::task::block_on(store.get(m)) {
                Ok(v) => v,
                Err(_) => return None,
            };

            match serde_json::from_slice(&msg) {
                Ok(v) => v,
                Err(_) => return None,
            }
        })
        .collect();

    // UNLOCK

    Ok(Mailbox { messages })
}

pub fn post_message(
    store: &impl Database,
    recipient: &str,
    sender: &str,
    message: &MessageRequest,
) -> Result<MessageStored, anyhow::Error> {
    let prefix = format!("{}/{}/", recipient, sender);

    // LOCK
    let existing = async_std::task::block_on(store.list(&prefix))?;
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
        action: message.action.clone(),
        data: message.data.clone(),
    };

    let j = serde_json::to_vec(&m)?;

    async_std::task::block_on(store.put(&dest, &j))?;
    // UNLOCK

    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "s3store"))]
    use crate::store::FileStore;

    #[cfg(not(feature = "s3store"))]
    fn new_store() -> FileStore {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();

        FileStore::new(dir.path().as_os_str()).unwrap()
    }

    #[test]
    fn mailbox_messages() {
        let store = new_store();
        let owner1 = "owner1".to_string();
        let owner2 = "owner2".to_string();

        let sender1 = "sender1".to_string();
        let sender2 = "sender2".to_string();

        let any_message = MessageRequest {
            action: "packed".to_string(),
            data: Payload {
                signature: "signature".to_string(),
                share: "share".to_string(),
            },
        };

        let r1 =
            post_message(&store, &owner1, &sender1, &any_message).unwrap();
        assert_eq!(r1.id, 1);
        assert_eq!(r1.from, sender1.clone());

        let r2 =
            post_message(&store, &owner1, &sender1, &any_message).unwrap();
        assert_eq!(r2.id, 2);
        assert_eq!(r2.from, sender1);

        let r3 =
            post_message(&store, &owner1, &sender2, &any_message).unwrap();
        assert_eq!(r3.id, 1);
        assert_eq!(r3.from, sender2);

        let r4 =
            post_message(&store, &owner2, &sender1, &any_message).unwrap();
        assert_eq!(r4.id, 1);
        assert_eq!(r4.from, sender1);

        let g1 = get_messages(&store, &owner1).unwrap();
        assert_eq!(g1.messages.len(), 3);

        delete_messages(
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
        )
        .unwrap();

        let g2 = get_messages(&store, &owner1).unwrap();
        assert_eq!(g2.messages.len(), 1);
        assert_eq!(g2.messages[0].id, 1);
        assert_eq!(g2.messages[0].from, "sender1".to_string());
    }

    #[test]
    fn ios_deserialize() {
        let s = r#"{"data":{"share":"IKlx5OuP22Xux5JSOeekYH+zLmhiemgHF25QV4yxK/Cq8VlYZa41qWElDD+Ue9tdzdm23j78MpfCTlLCew==","signature":"UEq/S7j5cXAuEo7K5LVEiMGdWbLwqQxxQNKVlXtgLbB8ecY4+u3YF3S\/uMhohZx5pmKJ6qWZccoj7+9dAqA/CQ=="},"action":"share-update","from":"DkxRk21yuqwA2Uf1P7At08OD8434fwEnAc9-Ckmve20"}"#;

        // just check that we don't panic
        let _m: MessageRequest = serde_json::from_slice(s.as_bytes()).unwrap();
        assert!(true);
    }
}
