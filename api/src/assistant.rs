//
// Copyright (C) 2023 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::Context;
use http_types::Status;
use http_types::StatusCode;
use serde::{Deserialize, Serialize};

use tide::Response;
use tide::Result;

// unused
#[derive(Serialize, Deserialize, Debug)]
pub struct AssistTopicLookup
{
    // enum one of: password-reset, enable-2fa
    pub topic: String,
    pub domain: String,
}

// unused
#[derive(Serialize, Deserialize, Debug)]
pub struct AssistTopicResponse
{
    /// List of steps the user should take
    pub steps: Vec<String>,
    /// URL linking the user to the first step
    pub action_url: String,
}

pub async fn passthrough(req_bytes: Vec<u8>) -> Result<Response>
{
    // use the serverless function
    let lambda = std::env::var("ASSISTANT_ENDPOINT")
        .status(StatusCode::InternalServerError)?;

    let mut surf_response = surf::get(lambda).body_bytes(req_bytes).await?;
    let tide_response = Response::builder(surf_response.status())
        .body(surf_response.body_bytes().await?)
        .build();

    Ok(tide_response)
}
