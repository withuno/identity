//
// Copyright (C) 2023 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use http_types::headers::HeaderValues;
use http_types::headers::ACCEPT;
use http_types::headers::AUTHORIZATION;
use http_types::headers::CACHE_CONTROL;
use http_types::headers::CONTENT_TYPE;
use http_types::headers::ETAG;
use http_types::headers::IF_NONE_MATCH;
use http_types::Status;
use http_types::StatusCode;
use tide::Response;
use tide::Result;

use crate::Database;

pub async fn get_info<T>(domain: &str, db: &T) -> Result<Response>
where
    T: Database,
{
    // check cache
    let cache_control = "private, immutable, max-age=604800, \
                         stale-while-revalidate=86400, stale-if-error=86400";
    // the brands cache db has a 30 day object expiration policy
    if db.exists(domain).await? {
        let data = db.get(domain).await?;
        let response = Response::builder(StatusCode::Ok)
            .header(CONTENT_TYPE, "application/json")
            .header(CACHE_CONTROL, cache_control)
            .body(data)
            .build();

        return Ok(response);
    }

    let mut bf = req_info_authed(domain).await?;
    let bf_bytes = bf.body_bytes().await?;

    let mut builder =
        Response::builder(bf.status()).header(CONTENT_TYPE, "application/json");

    // if successful, cache the brand data
    if let StatusCode::Ok = bf.status() {
        let _ = db.put(domain, &bf_bytes).await?;
        builder = builder.header(CACHE_CONTROL, cache_control);
    }

    builder = builder.body(bf_bytes);

    Ok(builder.build())
}

async fn req_info_authed(domain: &str) -> Result<surf::Response>
{
    let token = std::env::var("BRANDFETCH_API_KEY")
        .status(StatusCode::InternalServerError)?;

    let url = format!("https://api.brandfetch.io/v2/brands/{}", domain);
    let response = surf::get(url)
        .header(AUTHORIZATION, format!("Bearer: {}", token))
        .header(ACCEPT, "application/json")
        .await?;

    Ok(response)
}

pub async fn get_asset(
    filepath: &str,
    etag: Option<&HeaderValues>,
) -> Result<Response>
{
    let url = format!("https://asset.brandfetch.io/{}", filepath);
    let mut req = surf::get(url);
    if let Some(etag) = etag {
        req = req.header(IF_NONE_MATCH, etag);
    }
    let mut res = req.await?;
    let bytes = res.body_bytes().await?;

    let mut builder = Response::builder(res.status()).body(bytes);
    if let Some(v) = res.header(CONTENT_TYPE) {
        builder = builder.header(CONTENT_TYPE, v);
    }
    if let Some(v) = res.header(ETAG) {
        builder = builder.header(ETAG, v);
    }
    // if successful, tell the client to cache the brand data
    if let StatusCode::Ok = res.status() {
        // add cache-control
        let cache_control = "private, immutable, max-age=2678400, \
                             stale-while-revalidate=604800, \
                             stale-if-error=604800";
        builder = builder.header(CACHE_CONTROL, cache_control);
    }

    Ok(builder.build())
}
