//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_std::fs;
use async_std::io::Error;
use async_std::path::Path;
use async_std::path::PathBuf;

#[derive(Clone)]
pub struct FileStore
{
    dir: PathBuf,
}

impl FileStore
{
    pub fn new(root: &str) -> FileStore
    {
        return Self { dir: PathBuf::from(root), };
    }

    pub async fn get(&self, vault: &str) -> Result<Vec<u8>, Error>
    {
        let path = self.dir.join(vault);
        fs::read(path).await
    }

    pub async fn put(&self, vault: &str, content: &[u8])
    -> Result<(), Error>
    {
        let path = self.dir.join(vault);
        fs::write(path, content).await
    }
}

impl From<&Path> for FileStore
{
    fn from(p: &Path) -> FileStore
    {
        FileStore {
           dir: p.to_path_buf(),
        }
    }
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

        let f = FileStore::from(dir.path());
        assert!(f.get("anyfile").is_err());

        assert!(f.put("anyfile", b"some content").is_ok());
        assert!(f.get("anyfile").is_ok());

        //XXX: assert error types here.
        // write to bad directory etc.

        dir.close().unwrap();
    }
}
