//
// Copyright (C) 2023 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use http_types::Status;
use http_types::StatusCode;
use http_types::headers::ACCEPT;
use http_types::headers::AUTHORIZATION;
use http_types::headers::CACHE_CONTROL;
use http_types::headers::CONTENT_TYPE;
use tide::Response;
use tide::Result;

use crate::Database;

pub async fn get<T>(domain: &str, db: &T) -> Result<Response>
where
    T: Database,
{
    // check cache
    let cache_control = "private, immutable, max-age=604800, stale-while-revalidate=86400, stale-if-error=86400";
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

    let mut bf = fetch(domain).await?;
    let bf_bytes = bf.body_bytes().await?;

    // if successful, cache the brand data
    if let StatusCode::Ok = bf.status() {
        let _ = db.put(domain, &bf_bytes).await?;
    }

    let response = Response::builder(bf.status())
        .header(CONTENT_TYPE, "application/json")
        .body(bf_bytes)
        .build();

    Ok(response)
}

async fn fetch(domain: &str) -> Result<surf::Response>
{
    let token = std::env::var("BRANDFETCH_API_KEY")
        .status(StatusCode::InternalServerError)?;

    let url = format!("https://api.brandfetch.io/v2/brands/{}", domain);
    let response = surf::post(url)
        .header(AUTHORIZATION, format!("Bearer: {}", token))
        .header(ACCEPT, "application/json")
        .await?;

    Ok(response)
}
