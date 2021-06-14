use anyhow::{anyhow, ensure, Result};

use async_trait::async_trait;

use std::fmt::Debug;
use std::time::Duration;

use rusty_s3::{Bucket, Credentials, S3Action};

use surf::http::Method;
use surf::{Request, Response, StatusCode};

pub mod s3;
use s3::ListBucketResult;

#[async_trait]
pub trait Database: Send + Sync + Clone + Debug {
    async fn exists(&self, object: &str) -> Result<bool>;
    async fn get(&self, object: &str) -> Result<Vec<u8>>;
    async fn put(&self, object: &str, data: &[u8]) -> Result<()>;
    async fn del(&self, object: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Store to S3 and also the file system
#[derive(Clone, Debug)]
pub struct S3Store {
    creds: Credentials,
    bucket: Bucket,
}

impl S3Store {
    pub async fn empty_bucket(&self) -> Result<()> {
        for l in self.list("").await?.iter() {
            self.del(l).await?;
        }

        Ok(())
    }

    pub async fn create_bucket_if_not_exists(&self) -> Result<()> {
        let action = self.bucket.create_bucket(&self.creds);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Put, action.sign(ttl)).build();
        let res = let_it_rip(bro).await?;
        let status = res.status();

        // bucket already exists
        if status == StatusCode::Conflict {
            return Ok(());
        }

        ensure!(status.is_success(), "s3 PUT unexpected result ({})", status);

        Ok(())
    }

    pub fn new(
        host: &str,
        region: &str,
        key_id: &str,
        secret: &str,
        name: &str,
    ) -> Result<S3Store> {
        let path_style = true;

        let bucket = Bucket::new(host.parse()?, path_style, name, region)
            .ok_or_else(|| anyhow!("invalid bucket scheme"))?;

        Ok(S3Store {
            creds: Credentials::new(key_id, secret),
            bucket: bucket,
        })
    }
}

#[async_trait]
impl Database for S3Store {
    async fn exists(&self, object: &str) -> Result<bool> {
        let action = self.bucket.get_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl)).build();
        let res = let_it_rip(bro).await?;
        match res.status() {
            http_types::StatusCode::Ok => Ok(true),
            http_types::StatusCode::NotFound => Ok(false),
            _ => anyhow::bail!("unexpected result from s3 api"),
        }
    }

    async fn get(&self, object: &str) -> Result<Vec<u8>> {
        let action = self.bucket.get_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl)).build();
        let mut res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(status.is_success(), "s3 GET unexpected result ({})", status);
        Ok(res.body_bytes().await.map_err(|e| anyhow!(e))?)
    }

    async fn put(&self, object: &str, content: &[u8]) -> Result<()> {
        let action = self.bucket.put_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Put, action.sign(ttl))
            .body(content)
            .build();
        let res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(status.is_success(), "s3 PUT unexpected result ({})", status);
        Ok(())
    }

    async fn del(&self, object: &str) -> Result<()> {
        let action = self.bucket.delete_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Delete, action.sign(ttl)).build();
        let res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(
            status.is_success(),
            "s3 DELETE unexpected result ({})",
            status
        );
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut action = self.bucket.list_objects_v2(Some(&self.creds));
        let query = action.query_mut();
        query.insert("prefix", prefix);

        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl)).build();
        let mut res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(status.is_success(), "s3 GET unexpected result ({})", status);

        let body = res.body_bytes().await;

        match body {
            Ok(b) => {
                let result = match ListBucketResult::from_xml(&b[..]) {
                    Ok(r) => r,
                    Err(error) => return Err(anyhow!(error)),
                };

                Ok(result.contents.into_iter().map(|c| c.key).collect())
            }
            Err(error) => Err(anyhow!(error)),
        }
    }
}

async fn let_it_rip(req: Request) -> Result<Response> {
    let client = surf::client();
    let res = client.send(req).await.map_err(|e| anyhow!(e))?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_store() {
        let f = match S3Store::new(
            "http://localhost:9000",
            "minio",
            "minioadmin",
            "minioadmin",
            "somebucket",
        ) {
            Ok(s) => s,
            Err(error) => panic!("{:?}", error),
        };

        {
            let fut = f.get("anyfile");
            let err = async_std::task::block_on(fut);
            assert!(err.is_err());
        }
        {
            let fut = f.put("anyfile", b"some content");
            let yes = async_std::task::block_on(fut);
            assert!(yes.is_ok());
        }
        {
            let fut = f.get("anyfile");
            let yes = async_std::task::block_on(fut);
            assert!(yes.is_ok());
        }
        {
            let fut = f.del("anyfile");
            let yes = async_std::task::block_on(fut);
            assert!(yes.is_ok());
        }
        {
            let fut = f.get("anyfile");
            let err = async_std::task::block_on(fut);
            assert!(err.is_err());
        }
        {
            let fut = f.put("some/sub/directory", b"subcontent");
            let result = async_std::task::block_on(fut);
            assert!(result.is_ok());

            let fut = f.get("some/sub/directory");
            let result = async_std::task::block_on(fut);
            assert!(result.is_ok());

            let fut = f.get("some/sub/missing");
            let err = async_std::task::block_on(fut);
            assert!(err.is_err());

            let fut = f.get("some/sub");
            let err = async_std::task::block_on(fut);
            assert!(err.is_err());
        }
        {
            let f1 = f.put("multi/key1/file1", b"AA");
            let f2 = f.put("multi/key1/file2", b"AA");
            let f3 = f.put("multi/key2/file1", b"BB");
            let f4 = f.put("multiother/file1", b"CC");
            // don't need to do any of this jazz.
            let r1 = async_std::task::block_on(f1);
            let r2 = async_std::task::block_on(f2);
            let r3 = async_std::task::block_on(f3);
            let r4 = async_std::task::block_on(f4);

            assert!(r1.is_ok());
            assert!(r2.is_ok());
            assert!(r3.is_ok());
            assert!(r4.is_ok());

            let fut = f.list("multi/");
            let result = async_std::task::block_on(fut);
            assert!(result.is_ok());

            assert_eq!(
                result.unwrap(),
                // does not need to be order dependent eventually
                vec!(
                    "multi/key1/file1",
                    "multi/key1/file2",
                    "multi/key2/file1",
                )
            );
        }
    }
}
