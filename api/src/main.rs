//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//


use api::{build_api, build_api_v2};

#[cfg(not(feature = "s3"))]
use api::store::FileStore;
#[cfg(not(feature = "s3"))]
fn make_db(name: &'static str) -> anyhow::Result<FileStore> {
    use std::convert::TryFrom;
    FileStore::try_from(name)
}

#[cfg(feature = "s3")]
use api::store::S3Store;
#[cfg(feature = "s3")]
fn make_db(name: &str) -> anyhow::Result<S3Store> {
    use anyhow::Context;

    let key_id = std::env::var("SPACES_ACCESS_KEY_ID")
        .context("Failed to lookup SPACES_ACCESS_KEY_ID")?;

    let secret = std::env::var("SPACES_SECRET_ACCESS_KEY")
        .context("Failed to lookup SPACES_SECRET_ACCESS_KEY")?;

    let host = std::env::var("SPACES_HOSTNAME")
        .context("Failed to lookup SPACES_HOSTNAME")?;

    let region = std::env::var("SPACES_REGION")
        .context("Failed to lookup SPACES_REGION")?;

    let bucket = std::env::var("SPACES_BUCKET_PREFIX")
        .context("Failed to lookup SPACES_BUCKET_PREFIX")?;

    let name = String::from(name) + "." + &String::from(bucket);

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

    // TODO: version db
    let tok2 = make_db("tokens")?;
    let vau2 = make_db("vaults")?;
    let srv2 = make_db("services")?;
    let ses2 = make_db("sessions")?;
    let mbx2 = make_db("mailboxes")?;

    let api_v2 = build_api_v2(tok2, vau2, srv2, ses2, mbx2)?;

    let mut srv = tide::new();

    srv.at("/v1").nest(api);
    srv.at("/v2").nest(api_v2);

    tide::log::start();

    let port = std::env::var("PORT").unwrap_or("8080".to_string());
    srv.listen(format!("[::]:{}", port)).await?;
    Ok(())
}
