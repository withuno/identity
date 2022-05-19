//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::bail;
use anyhow::Result;
use async_std::fs;
use async_std::path::Path;
use async_std::path::PathBuf;
use async_trait::async_trait;
use std::convert::AsRef;
use std::fmt::Debug;

use crate::store::Database;

#[derive(Clone, Debug)]
pub struct FileStore
{
    db: PathBuf,
    version: PathBuf,
}

impl FileStore
{
    pub async fn new<P, Q, R>(root: P, name: Q, version: R) -> Result<FileStore>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        R: AsRef<Path>,
    {
        let path = root.as_ref().join(&name).join(&version);

        async_std::fs::create_dir_all(&path).await?;

        Ok(Self {
            db: root.as_ref().join(name).to_owned(),
            version: version.as_ref().to_owned(),
        })
    }
}

#[async_trait]
impl Database for FileStore
{
    async fn exists<P>(&self, file: P) -> Result<bool>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.exists_version(&self.version, file).await?)
    }

    async fn exists_version<P, Q>(&self, version: Q, file: P) -> Result<bool>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        // todo: introspect the failure cause and be more specific
        Ok(self.get_version(version, file).await.is_ok())
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
        let root = self.db.join(version);
        let dir = root.join(prefix);
        use walkdir::WalkDir;
        Ok(WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                e.path()
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect())
    }

    async fn get<P>(&self, file: P) -> Result<Vec<u8>>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.get_version(&self.version, file).await?)
    }

    async fn get_version<P, Q>(&self, version: Q, file: P) -> Result<Vec<u8>>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let path = self.db.join(version).join(file);
        Ok(fs::read(path).await?)
    }

    async fn put<P>(&self, file: P, content: &[u8]) -> Result<()>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.put_version(&self.version, file, content).await?)
    }

    async fn put_version<P, Q>(
        &self,
        version: Q,
        file: P,
        content: &[u8],
    ) -> Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let path = self.db.join(version).join(file);
        match path.parent() {
            Some(p) => fs::create_dir_all(p).await?,
            None => (),
        }

        Ok(fs::write(path, content).await?)
    }

    async fn del<P>(&self, file: P) -> Result<()>
    where
        P: AsRef<Path> + Send,
    {
        Ok(self.del_version(&self.version, file).await?)
    }

    async fn del_version<P, Q>(&self, version: Q, file: P) -> Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send,
    {
        let path = self.db.join(version).join(file);
        use async_std::io::ErrorKind;
        match fs::remove_file(path).await {
            Ok(_) => return Ok(()),
            // Trying to delete a file that doesn't exist is okay.
            Err(e) => {
                if ErrorKind::NotFound == e.kind() {
                    Ok(())
                } else {
                    bail!(e)
                }
            },
        }
    }
}


#[cfg(test)]
#[cfg(not(feature = "s3"))]
mod tests
{
    use super::*;
    use tempfile::TempDir;

    #[async_std::test]
    async fn store() -> Result<()>
    {
        let dir = TempDir::new()?;
        let f = FileStore::new(dir.path(), "testdata", "v0").await?;

        let err = f.get("anyfile").await;
        assert!(err.is_err());

        let yes = f.put("anyfile", b"some content").await;
        assert!(yes.is_ok());

        let yes = f.get("anyfile").await;
        assert!(yes.is_ok());

        let yes = f.del("anyfile").await;
        assert!(yes.is_ok());

        let err = f.get("anyfile").await;
        assert!(err.is_err());

        let result = f.put("some/sub/directory", b"subcontent").await;
        assert!(result.is_ok());

        let result = f.get("some/sub/directory").await;
        assert!(result.is_ok());

        let err = f.get("some/sub/missing").await;
        assert!(err.is_err());

        let err = f.get("some/sub").await;
        assert!(err.is_err());

        let r1 = f.put("multi/key1/file1", b"AA").await;
        let r2 = f.put("multi/key1/file2", b"AA").await;
        let r3 = f.put("multi/key2/file1", b"BB").await;
        let r4 = f.put("multiother/file1", b"CC").await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());
        assert!(r4.is_ok());

        let result = f.list("multi/").await;
        assert!(result.is_ok());

        assert_eq!(
            result?.sort(),
            // does not need to be order dependent eventually
            vec!("multi/key2/file1", "multi/key1/file2", "multi/key1/file1",)
                .sort()
        );

        Ok(())
    }
}
