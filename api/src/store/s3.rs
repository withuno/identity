//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::{anyhow, bail, ensure, Context, Result};

use async_std::path::Path;
use async_trait::async_trait;
use std::fmt;

use serde::Deserialize;
use serde_xml_rs::from_reader;

use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};

use surf::http::Method;
use surf::Url;
use surf::{Request, Response, StatusCode};

use std::fmt::Debug;
use std::time::Duration;

use crate::store::Database;

use urlencoding::decode;

#[derive(Debug, Clone)]
pub struct DeserializationError;

#[derive(Debug, Clone)]
pub struct SerializationError;

impl fmt::Display for DeserializationError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "invalid data for deserialization")
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Contents
{
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct ListBucketResult
{
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

impl ListBucketResult
{
    pub fn from_xml(
        xml: &[u8],
    ) -> Result<ListBucketResult, DeserializationError>
    {
        from_reader(xml).or(Err(DeserializationError))
    }
}

/// Store to S3 and also the file system
#[derive(Clone, Debug)]
pub struct S3Store
{
    creds: Credentials,
    bucket: Bucket,
    version: String,
}

impl S3Store
{
    pub async fn empty_bucket(&self) -> Result<()>
    {
        for l in self.list("").await?.iter() {
            self.del(l).await?;
        }

        Ok(())
    }

    // TODO: in prod all the buckets are already created because we need to
    //       turn object versioning on. can this be done here?
    pub async fn create_bucket_if_not_exists(&self) -> Result<()>
    {
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

    pub async fn new(
        host: &str,
        region: &str,
        key_id: &str,
        secret: &str,
        name: &str,
        version: &str,
    ) -> Result<S3Store>
    {
        let phost = host.parse()?;

        let bucket = Bucket::new(
            phost,
            UrlStyle::Path,
            name.to_string(),
            region.to_string(),
        )?;

        Ok(S3Store {
            creds: Credentials::new(key_id.to_string(), secret.to_string()),
            bucket: bucket,
            version: version.to_owned(),
        })
    }
}

fn full_obj_from_path<P, Q>(version: Q, object: P) -> Result<String>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let path = Path::new("/").join(version).join(object);

    // convert windows style paths to a universal `/` scheme
    let path_url =
        Url::from_file_path(path).map_err(|_| anyhow!("bad path for url"))?;

    // remove the leading "file:///"
    let fbase = Url::parse("file:///")?;

    match fbase.make_relative(&path_url) {
        Some(u) => Ok(u.as_str().to_owned()),
        None => bail!("invalid version or object name"),
    }
}

fn full_prefix_from_path<P, Q>(version: Q, prefix: P) -> Result<String>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    // Note to the future: be very *very* careful. In s3 a trailing `/` is
    // relevant but for paths it is not. Nor do we know if the incoming prefix
    // is a simple prefix or should be treated as a directory. We *could*
    // probably assume a dir for our use case and use Url::from_directory_path.
    let path = Path::new("/").join(version).join(prefix);
    let pstr = path.to_str().ok_or(anyhow!("prefix not valid utf-8"))?;

    // Url::make_relative unconditionally strips trailing `/`. So we must check
    // if the path ends with the path separator and add a `/` back at the end.
    let is_directory = pstr.ends_with(std::path::MAIN_SEPARATOR);

    let purl = match is_directory {
        true => Url::from_directory_path(path),
        false => Url::from_file_path(path),
    }
    .map_err(|_| anyhow!("cannot convert path to Url"))?;

    // remove the leading "file:///"
    let base = Url::parse("file:///")?;

    let url_style_prefix = base
        .make_relative(&purl)
        .context("cannot make prefix relative to the root")?;

    if is_directory {
        Ok(format!("{}/", url_style_prefix.as_str()))
    } else {
        Ok(url_style_prefix.as_str().to_owned())
    }
}

#[async_trait]
impl Database for S3Store
{
    async fn exists<P>(&self, object: P) -> Result<bool>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.exists_version(&self.version, object).await?)
    }

    async fn exists_version<P, Q>(&self, version: Q, object: P) -> Result<bool>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let vobject = full_obj_from_path(version, object)?;
        let action = self.bucket.get_object(Some(&self.creds), &vobject);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl)).build();
        let res = let_it_rip(bro).await?;
        match res.status() {
            http_types::StatusCode::Ok => Ok(true),
            http_types::StatusCode::NotFound => Ok(false),
            _ => anyhow::bail!("unexpected result from s3 api"),
        }
    }

    async fn get<P>(&self, object: P) -> Result<Vec<u8>>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.get_version(&self.version, object).await?)
    }

    async fn get_version<P, Q>(&self, version: Q, object: P) -> Result<Vec<u8>>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let vobject = full_obj_from_path(version, object)?;
        let action = self.bucket.get_object(Some(&self.creds), &vobject);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl)).build();

        let mut res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(status.is_success(), "s3 GET unexpected result ({})", status);
        Ok(res.body_bytes().await.map_err(|e| anyhow!(e))?)
    }

    async fn put<P>(&self, object: P, content: &[u8]) -> Result<()>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.put_version(&self.version, object, content).await?)
    }

    async fn put_version<P, Q>(
        &self,
        version: Q,
        object: P,
        content: &[u8],
    ) -> Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let vobject = full_obj_from_path(version, object)?;
        let action = self.bucket.put_object(Some(&self.creds), &vobject);
        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Put, action.sign(ttl))
            .body(content)
            .build();
        let res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(status.is_success(), "s3 PUT unexpected result ({})", status);
        Ok(())
    }

    async fn del<P>(&self, object: P) -> Result<()>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.del_version(&self.version, object).await?)
    }

    async fn del_version<P, Q>(&self, version: Q, object: P) -> Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let vobject = full_obj_from_path(version, object)?;
        let action = self.bucket.delete_object(Some(&self.creds), &vobject);
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

    async fn list<P>(&self, prefix: P) -> Result<Vec<String>>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.list_version(&self.version, prefix).await?)
    }

    async fn list_version<P, Q>(
        &self,
        version: Q,
        prefix: P,
    ) -> Result<Vec<String>>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let mut action = self.bucket.list_objects_v2(Some(&self.creds));
        let query = action.query_mut();
        let vprefix = full_prefix_from_path(version, prefix)?;
        query.insert("prefix", &vprefix);

        let ttl = Duration::from_secs(60 * 60);
        let bro = Request::builder(Method::Get, action.sign(ttl)).build();

        let mut res = let_it_rip(bro).await?;
        let status = res.status();
        ensure!(status.is_success(), "s3 GET unexpected result ({})", status);

        let body = res.body_bytes().await.map_err(|e| anyhow!(e))?;

        let result =
            ListBucketResult::from_xml(&body[..]).map_err(|e| anyhow!(e))?;

        let decoded = result
            .contents
            .iter()
            .filter_map(|c| decode(&c.key).ok())
            .collect::<Vec<String>>();

        let stripped = decoded
            .iter()
            .filter_map(|k| k.strip_prefix(&self.version))
            .filter_map(|k| k.strip_prefix("/"))
            .collect::<Vec<&str>>();

        Ok(stripped.into_iter().map(|s| s.to_owned()).collect())
    }
}

async fn let_it_rip(req: Request) -> Result<Response>
{
    let client = surf::client();
    let res = client.send(req).await.map_err(|e| anyhow!(e))?;
    Ok(res)
}

#[cfg(test)]
#[cfg(feature = "s3")]
mod tests
{
    use super::*;

    #[async_std::test]
    async fn s3_store() -> Result<()>
    {
        let s = S3Store::new(
            "http://localhost:9000",
            "minio",
            "minioadmin",
            "minioadmin",
            "somebucket",
            "v0",
        )
        .await?;

        let _ = s.create_bucket_if_not_exists().await?;

        let err = s.get("anyfile").await;
        assert!(err.is_err());

        let yes = s.put("anyfile", b"some content").await;
        assert!(yes.is_ok());

        let yes = s.get("anyfile").await;
        assert!(yes.is_ok());

        let yes = s.del("anyfile").await;
        assert!(yes.is_ok());

        let err = s.get("anyfile").await;
        assert!(err.is_err());

        let result = s.put("some/sub/directory", b"subcontent").await;
        assert!(result.is_ok());

        let result = s.get("some/sub/directory").await;
        assert!(result.is_ok());

        let err = s.get("some/sub/missing").await;
        assert!(err.is_err());

        let err = s.get("some/sub").await;
        assert!(err.is_err());

        let r1 = s.put("multi/key1/file1", b"AA").await;
        let r2 = s.put("multi/key1/file2", b"AA").await;
        let r3 = s.put("multi/key2/file1", b"BB").await;
        let r4 = s.put("multiother/file1", b"CC").await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());
        assert!(r4.is_ok());

        let result = s.list("multi/").await;
        assert!(result.is_ok());

        assert_eq!(
            result.unwrap(),
            // does not need to be order dependent eventually
            vec!("multi/key1/file1", "multi/key1/file2", "multi/key2/file1",)
        );

        Ok(())
    }

    #[test]
    fn list_bucket_response() -> Result<()>
    {
        let r = r#"
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>somebucket</Name><Prefix>multi</Prefix><KeyCount>4</KeyCount><MaxKeys>4500</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated><Contents><Key>multi/key1/file1</Key><LastModified>2021-06-24T14:14:00.068Z</LastModified><ETag>&#34;3b98e2dffc6cb06a89dcb0d5c60a0206&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multi/key1/file2</Key><LastModified>2021-06-24T14:14:00.074Z</LastModified><ETag>&#34;3b98e2dffc6cb06a89dcb0d5c60a0206&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multi/key2/file1</Key><LastModified>2021-06-24T14:14:00.080Z</LastModified><ETag>&#34;9d3d9048db16a7eee539e93e3618cbe7&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multiother/file1</Key><LastModified>2021-06-24T14:14:00.086Z</LastModified><ETag>&#34;aa53ca0b650dfd85c4f59fa156f7a2cc&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><EncodingType>url</EncodingType></ListBucketResult>
"#;

        let response =
            ListBucketResult::from_xml(r.as_bytes()).map_err(|e| anyhow!(e))?;

        assert_eq!(response, ListBucketResult {
            name: "somebucket".to_string(),
            prefix: "multi".to_string(),
            key_count: 4,
            is_truncated: false,
            contents: vec!(
                Contents { key: "multi/key1/file1".to_string() },
                Contents { key: "multi/key1/file2".to_string() },
                Contents { key: "multi/key2/file1".to_string() },
                Contents { key: "multiother/file1".to_string() }
            ),
        });

        Ok(())
    }
}
