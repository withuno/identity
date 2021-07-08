pub use crate::store::Database;

use std::error::Error;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mailbox {
    pub messages: Vec<MessageStored>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Payload {
    pub signature: Vec<u8>,
    pub share: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct MessageRequest {
    pub action: String,
    pub message: Payload,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageStored {
    pub action: String,
    pub id: u64,
    pub from: String,
    pub message: Payload,
}

pub fn get_messages(
    store: &impl Database,
    owner: &str,
) -> Result<Mailbox, Box<dyn Error>> {
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
) -> Result<MessageStored, Box<dyn Error>> {
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
        message: message.message.clone(),
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
            message: Payload {
                signature: b"signature".to_vec(),
                share: b"share".to_vec(),
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
    }
}
