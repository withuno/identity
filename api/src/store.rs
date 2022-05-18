//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Result;

use async_trait::async_trait;

use std::fmt::Debug;

pub mod s3;
pub use s3::S3Store;

pub mod file;
pub use file::FileStore;

use async_std::path::Path;

#[async_trait]
pub trait Database: Send + Sync + Clone + Debug
{
    // Standard Operations
    //
    // Use these for all standard logic.
    //
    async fn exists<P>(&self, object: P) -> Result<bool>
    where
        P: AsRef<Path> + Send;

    async fn get<P>(&self, object: P) -> Result<Vec<u8>>
    where
        P: AsRef<Path> + Send;

    async fn put<P>(&self, object: P, data: &[u8]) -> Result<()>
    where
        P: AsRef<Path> + Send;

    async fn del<P>(&self, object: P) -> Result<()>
    where
        P: AsRef<Path> + Send;

    async fn list<P>(&self, prefix: P) -> Result<Vec<String>>
    where
        P: AsRef<Path> + Send;

    // *Versioned* Operations
    //
    // The db is already versioned. The only time these are necessary is when
    // performing an on-demand migration of data between major api versions.
    //
    async fn exists_version<P, Q>(&self, version: Q, object: P) -> Result<bool>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;

    async fn get_version<P, Q>(
        &self,
        version: Q,
        object: P
    ) -> Result<Vec<u8>>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;

    async fn put_version<P, Q>(
        &self,
        version: Q,
        object: P,
        data: &[u8],
    ) -> Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;

    async fn del_version<P, Q>(&self, version: Q, object: P) -> Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;

    async fn list_version<P, Q>(
        &self,
        version: Q,
        prefix: P,
    ) -> Result<Vec<String>>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;
}
