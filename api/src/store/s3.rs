use anyhow::{anyhow, ensure, Result};

use async_trait::async_trait;
use std::fmt;

use serde::Deserialize;
use serde_xml_rs::from_reader;

use rusty_s3::{Bucket, Credentials, S3Action};

use surf::http::Method;
use surf::{Request, Response, StatusCode};

use std::fmt::Debug;
use std::time::Duration;

use crate::store::Database;

use urlencoding::decode;

#[derive(Debug, Clone)]
pub struct DeserializationError;

#[derive(Debug, Clone)]
pub struct SerializationError;

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid data for deserialization")
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Contents {
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct ListBucketResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "KeyCount")]
    key_count: i32,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,

    #[serde(rename = "Contents", default)]
    pub contents: Vec<Contents>,
}

impl ListBucketResult {
    pub fn from_xml(
        xml: &[u8],
    ) -> Result<ListBucketResult, DeserializationError> {
        from_reader(xml).or(Err(DeserializationError))
    }
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

        let phost = host.parse()?;

        let bucket = Bucket::new(
            phost,
            path_style,
            name.to_string(),
            region.to_string(),
        )
        .ok_or_else(|| anyhow!("invalid bucket scheme"))?;

        Ok(S3Store {
            creds: Credentials::new(key_id.to_string(), secret.to_string()),
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

                Ok(result
                    .contents
                    .into_iter()
                    .filter_map(|c| {
                        //XXX: i don't know if this is the right place
                        // to URL decode...
                        decode(&c.key).ok()
                    })
                    .collect())
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
#[cfg(feature = "s3store")]
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

        async_std::task::block_on(f.create_bucket_if_not_exists()).unwrap();

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

    #[test]
    fn list_bucket_response() {
        let r = r#"
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>somebucket</Name><Prefix>multi</Prefix><KeyCount>4</KeyCount><MaxKeys>4500</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated><Contents><Key>multi/key1/file1</Key><LastModified>2021-06-24T14:14:00.068Z</LastModified><ETag>&#34;3b98e2dffc6cb06a89dcb0d5c60a0206&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multi/key1/file2</Key><LastModified>2021-06-24T14:14:00.074Z</LastModified><ETag>&#34;3b98e2dffc6cb06a89dcb0d5c60a0206&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multi/key2/file1</Key><LastModified>2021-06-24T14:14:00.080Z</LastModified><ETag>&#34;9d3d9048db16a7eee539e93e3618cbe7&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multiother/file1</Key><LastModified>2021-06-24T14:14:00.086Z</LastModified><ETag>&#34;aa53ca0b650dfd85c4f59fa156f7a2cc&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><EncodingType>url</EncodingType></ListBucketResult>
"#;

        let response = ListBucketResult::from_xml(r.as_bytes()).unwrap();

        assert_eq!(
            response,
            ListBucketResult {
                name: "somebucket".to_string(),
                prefix: "multi".to_string(),
                key_count: 4,
                is_truncated: false,
                contents: vec!(
                    Contents {
                        key: "multi/key1/file1".to_string()
                    },
                    Contents {
                        key: "multi/key1/file2".to_string()
                    },
                    Contents {
                        key: "multi/key2/file1".to_string()
                    },
                    Contents {
                        key: "multiother/file1".to_string()
                    }
                ),
            }
        );
    }
}
