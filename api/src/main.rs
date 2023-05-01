//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Context;
use anyhow::Result;

#[cfg(not(feature = "s3"))]
use api::store::FileStore;
#[cfg(not(feature = "s3"))]
async fn make_db(name: &'static str, version: &str) -> Result<FileStore>
{
    // use the current directory
    // TODO: figure out a better dir like /var/db but one that doesn't require
    //       root
    FileStore::new("./throwaway_local_dbs", name, version).await
}

#[cfg(feature = "s3")]
use api::store::S3Store;
#[cfg(feature = "s3")]
async fn make_db(name: &str, version: &str) -> Result<S3Store>
{
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

    S3Store::new(&host, &region, &key_id, &secret, &name, version).await
}

#[async_std::main]
async fn main() -> Result<()>
{
    if cfg!(feature = "twilio") && cfg!(not(test)) {
        let twilio_endpoint = std::env::var("TWILIO_API_ENDPOINT")
            .context("Must specify TWILIO_API_ENDPOINT")?;
        let _account_sid = std::env::var("TWILIO_ACCOUNT_SID")
            .context("Must specify TWILIO_ACCOUNT_SID")?;
        let _service_sid = std::env::var("TWILIO_SERVICE_SID")
            .context("Must specify TWILIO_SERVICE_SID")?;
        let _auth_token = std::env::var("TWILIO_AUTH_TOKEN")
            .context("Must specify TWILIO_AUTH_TOKEN")?;

        let _ = surf::Url::parse(&twilio_endpoint)
            .context("twilio API endpoint must be a url")?;
    }

    if cfg!(feature = "openai") && cfg!(not(test)) {
        let _ = std::env::var("OPENAI_API_KEY")
            .context("Must specify OPENAI_API_KEY")?;
    }
    if cfg!(feature = "openai") && cfg!(not(test)) {
        let _: surf::Url = std::env::var("ASSISTANT_ENDPOINT")
            .context("Must specify ASSISTANT_ENDPOINT")?
            .parse()
            .context("ASSISTANT_ENDPOINT must be a valid URL")?;
    }

    if cfg!(feature = "brandfetch") && cfg!(not(test)) {
        let _ = std::env::var("BRANDFETCH_API_KEY")
            .context("Must specify BRANDFETCH_API_KEY")?;
    }

    let tok2 = make_db("tokens", "v2").await?;
    let vau2 = make_db("vaults", "v2").await?;
    let srv2 = make_db("services", "").await?; // not (yet) versioned
    let ses2 = make_db("sessions", "v2").await?;
    let mbx2 = make_db("mailboxes", "v2").await?;
    let shr2 = make_db("shares", "v2").await?;
    let vdb2 = make_db("verify", "v2").await?;
    let dir2 = make_db("directory", "v2").await?;
    let ast2 = make_db("assistant", "v2").await?; // db is empty right now
    let brn2 = make_db("brands", "v2").await?; // brand cache


    let api_v2 = api::build_routes(
        tok2, vau2, srv2, ses2, mbx2, shr2, vdb2, dir2, ast2, brn2,
    )?;

    let mut srv = tide::new();

    srv.at("/v2").nest(api_v2);

    tide::log::start();

    let port = std::env::var("PORT").unwrap_or("8080".to_string());
    srv.listen(format!("[::]:{}", port)).await?;
    Ok(())
}
