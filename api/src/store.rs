//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_std::fs;
use async_std::io::Error;
use async_std::path::Path;
use async_std::path::PathBuf;

use std::ffi::OsStr;

#[derive(Clone)]
pub struct FileStore
{
    dir: PathBuf,
}

impl FileStore
{
    pub fn new(root: &OsStr) -> FileStore
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

impl From<&'static str> for FileStore
{
    fn from(path: &'static str) -> FileStore
    {
        FileStore::new(OsStr::new(path))
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
        let f = FileStore::new(dir.path().as_os_str());

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

        //XXX: assert error types here.
        // write to bad directory etc.

        dir.close().unwrap();
    }
}
