use anyhow::Result;
use async_std::fs;
use async_std::path::Path;
use async_std::path::PathBuf;
use async_trait::async_trait;
use std::ffi::OsStr;
use std::fmt::Debug;

use std::convert::TryFrom;

use crate::store::Database;

#[derive(Clone, Debug)]
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(root: &OsStr) -> Result<FileStore> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            dir: PathBuf::from(root),
        })
    }
}

#[async_trait]
impl Database for FileStore {
    async fn exists(&self, file: &str) -> Result<bool> {
        // todo: introspect the failure cause and be more specific
        Ok(self.get(file).await.is_ok())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        use walkdir::WalkDir;
        Ok(WalkDir::new(self.dir.join(prefix))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                e.path()
                    .strip_prefix(&self.dir)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect())
    }

    async fn get(&self, file: &str) -> Result<Vec<u8>> {
        let path = self.dir.join(file);
        Ok(fs::read(path).await?)
    }

    async fn put(&self, file: &str, content: &[u8]) -> Result<()> {
        let path = self.dir.join(file);
        match path.parent() {
            Some(p) => fs::create_dir_all(p).await?,
            None => (),
        }

        Ok(fs::write(path, content).await?)
    }

    async fn del(&self, file: &str) -> Result<()> {
        let path = self.dir.join(file);
        Ok(fs::remove_file(path).await?)
    }
}

impl TryFrom<&Path> for FileStore {
    type Error = anyhow::Error;

    fn try_from(p: &Path) -> Result<FileStore> {
        FileStore::new(p.as_os_str())
    }
}

impl TryFrom<&'static str> for FileStore {
    type Error = anyhow::Error;

    fn try_from(path: &'static str) -> Result<FileStore> {
        FileStore::new(OsStr::new(path))
    }
}

#[cfg(test)]
#[cfg(not(feature = "s3store"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn store() {
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
                result.unwrap().sort(),
                // does not need to be order dependent eventually
                vec!(
                    "multi/key2/file1",
                    "multi/key1/file2",
                    "multi/key1/file1",
                ).sort()
            );
        }
    }
}
