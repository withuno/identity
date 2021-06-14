//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Context;

use api::{build_api, S3Store};

#[cfg(feature = "filestore")]
fn make_db(name: &'static str) -> anyhow::Result<FileStore> {
    use api::FileStore;
    use std::convert::TryFrom;
    FileStore::try_from(name)
}

#[cfg(not(feature = "filestore"))]
fn make_db(name: &str) -> anyhow::Result<S3Store> {
    let key_id = std::env::var("SPACES_ACCESS_KEY_ID")
        .context("Failed to lookup SPACES_ACCESS_KEY_ID")?;

    let secret = std::env::var("SPACES_SECRET_ACCESS_KEY")
        .context("Failed to lookup SPACES_SECRET_ACCESS_KEY")?;

    let host = std::env::var("SPACES_HOSTNAME")
        .context("Failed to lookup SPACES_HOSTNAME")?;

    let region = std::env::var("SPACES_REGION")
        .context("Failed to lookup SPACES_REGION")?;

    let name = String::from(name) + ".u1o.dev";

    S3Store::new(&host, &region, &key_id, &secret, &name)
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let tok = make_db("tokens")?;
    let vau = make_db("vaults")?;
    let srv = make_db("services")?;
    let ses = make_db("sessions")?;
    let mbx = make_db("mailboxes")?;

    let api = build_api(tok, vau, srv, ses, mbx)?;

    let mut srv = tide::new();
    srv.at("/v1").nest(api);

    tide::log::start();
    srv.listen("[::]:8080").await?;
    Ok(())
}
