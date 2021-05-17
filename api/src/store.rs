//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Result;
use async_std::fs;
use async_std::path::Path;
use async_std::path::PathBuf;
use async_trait::async_trait;
use std::ffi::OsStr;

#[async_trait]
pub trait Database: Send + Sync {
    async fn exists(&self, object: &str) -> Result<bool>;
    async fn get(&self, object: &str) -> Result<Vec<u8>>;
    async fn put(&self, object: &str, data: &[u8]) -> Result<()>;
    async fn del(&self, object: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct FileStore
{
    dir: PathBuf,
}

impl FileStore
{
    pub fn new(root: &OsStr) -> Result<FileStore>
    {
        std::fs::create_dir_all(root)?;
        Ok(Self{ dir: PathBuf::from(root), })
    }
}

#[async_trait]
impl Database for FileStore
{
    async fn exists(&self, file: &str) -> Result<bool>
    {
        // todo: introspect the failure cause and be more specific
        Ok(self.get(file).await.is_ok())
    }

    async fn get(&self, file: &str) -> Result<Vec<u8>>
    {
        let path = self.dir.join(file);
        Ok(fs::read(path).await?)
    }

    async fn put(&self, file: &str, content: &[u8]) -> Result<()>
    {
        let path = self.dir.join(file);
        Ok(fs::write(path, content).await?)
    }

    async fn del(&self, file: &str) -> Result<()>
    {
        let path = self.dir.join(file);
        Ok(fs::remove_file(path).await?)
    }
}

use std::convert::TryFrom;

impl TryFrom<&Path> for FileStore
{
    type Error = anyhow::Error;

    fn try_from(p: &Path) -> Result<FileStore>
    {
        FileStore::new(p.as_os_str())
    }
}

impl TryFrom<&'static str> for FileStore
{
    type Error = anyhow::Error;

    fn try_from(path: &'static str) -> Result<FileStore>
    {
        FileStore::new(OsStr::new(path))
    }
}

/// Store to S3 and also the file system
#[cfg(feature = "s3")]
#[derive(Clone)]
pub struct S3Store {
    creds: Credentials,
    bucket: Bucket,
}

// All these cfg's are silly and can be cleaned up I'm sure.

#[cfg(feature = "s3")]
use anyhow::anyhow;

#[cfg(feature = "s3")]
use anyhow::Context;

#[cfg(feature = "s3")]
use std::time::Duration;

#[cfg(feature = "s3")]
use surf::http::Method;

#[cfg(feature = "s3")]
use rusty_s3::{Bucket, Credentials, S3Action};

#[cfg(feature = "s3")]
use surf::{Request, Response};

#[cfg(feature = "s3")]
impl S3Store
{
    #[cfg(feature = "s3")]
    pub fn new(prefix: &str) -> Result<S3Store>
    {
        let key_id = std::env::var("SPACES_ACCESS_KEY_ID")
            .context("Failed to lookup SPACES_ACCESS_KEY_ID")?;
        let secret = std::env::var("SPACES_SECRET_ACCESS_KEY")
            .context("Failed to lookup SPACES_SECRET_ACCESS_KEY")?;

        let host = "https://nyc3.digitaloceanspaces.com".parse()?;
        let region = "nyc3".into();
        let path_style = true;
        let name = String::from(prefix) + ".u1o.dev";

        Ok(S3Store{
            creds: Credentials::new(key_id, secret),
            bucket: Bucket::new(host, path_style, name, region)
                .ok_or_else(|| anyhow!("bucket creation failed"))?,
        })
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl Database for S3Store
{
    #[cfg(feature = "s3")]
    async fn exists(&self, object: &str) -> Result<bool>
    {
        let action = self.bucket.get_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl))
            .build();
        let res = let_it_rip(bro).await?;
        if let Status::Okay = res.status() {
            Ok(true) 
        } else {
            Ok(false)
        }
        // ^you can't assign the result of an if/let, right?
    }

    #[cfg(feature = "s3")]
    async fn get(&self, object: &str) -> Result<Vec<u8>>
    {
        let action = self.bucket.get_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl))
            .build();
        let mut res = let_it_rip(bro).await?;
        Ok(res.body_bytes().await.map_err(|e| anyhow!(e))?)
    }

    #[cfg(feature = "s3")]
    async fn put(&self, object: &str, content: &[u8]) -> Result<()>
    {
        let action = self.bucket.put_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Put, action.sign(ttl))
            .body(content)
            .build();
        let mut _res = let_it_rip(bro).await?;
        Ok(())
    }

    #[cfg(feature = "s3")]
    async fn del(&self, object: &str, content: &[u8]) -> Result<()>
    {
        let action = self.bucket.delete_object(Some(&self.creds), object);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Put, action.sign(ttl))
            .body(content)
            .build();
        let mut _res = let_it_rip(bro).await?;
        Ok(())
    }
}

#[cfg(feature = "s3")]
use anyhow::ensure;

#[cfg(feature = "s3")]
async fn let_it_rip(req: Request) -> Result<Response>
{
    let client = surf::client();
    let method = req.method();
    let res = client.send(req).await.map_err(|e| anyhow!(e))?;
    let status = res.status();
    ensure!(status == 200, "s3 {} unexpected result ({})", method, status);
    Ok(res)
}


#[cfg(test)]
mod tests
{
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn file_store()
    {
        let dir = TempDir::new().unwrap();
        let f = FileStore::new(dir.path().as_os_str()).unwrap();

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

        //XXX: assert error types here.
        // write to bad directory etc.

        dir.close().unwrap();
    }
}
