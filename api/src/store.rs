//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fs;
use std::io::Error;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone)]
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(root: &str) -> FileStore {
        return Self { dir: PathBuf::from(root), };
    }

    pub fn get(&self, vault: &str) -> Result<String, Error> {
        let path = self.dir.join(vault);
        fs::read_to_string(path)
    }

    pub fn put(&self, vault: &str, content: &[u8]) -> Result<(), Error> {
        let path = self.dir.join(vault);
        fs::write(path, content)
    }
}

impl From<&Path> for FileStore {
    fn from(p: &Path) -> FileStore {
        FileStore {
           dir: p.to_path_buf(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn file_store() {
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
