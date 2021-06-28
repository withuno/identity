use anyhow::Result;

use async_trait::async_trait;

use std::fmt::Debug;

pub mod s3;
pub use s3::S3Store;

//pub mod file;
//pub use file::FileStore;

#[async_trait]
pub trait Database: Send + Sync + Clone + Debug {
    async fn exists(&self, object: &str) -> Result<bool>;
    async fn get(&self, object: &str) -> Result<Vec<u8>>;
    async fn put(&self, object: &str, data: &[u8]) -> Result<()>;
    async fn del(&self, object: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}
