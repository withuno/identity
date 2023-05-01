//
// Copyright (C) 2023 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use http_types::Status;
use http_types::StatusCode;
use serde::{Deserialize, Serialize};

use strum_macros::AsRefStr;
use strum_macros::EnumString;

use tide::Response;
use tide::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct AssistTopicLookup
{
    // Topic enum one of: reset-password, enable-2fa
    pub topic: String,
    pub domain: String,
}

#[derive(Debug, PartialEq, AsRefStr, EnumString)]
pub enum Topic
{
    #[strum(serialize = "reset-password")]
    ResetPassword,
    #[strum(serialize = "enable-2fa")]
    Enable2FA,
}

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

    let mut surf_response = surf::post(lambda)
        .header("content-type", "application/json")
        .body_bytes(req_bytes)
        .await?;

    let tide_response = Response::builder(surf_response.status())
        .header("content-type", "application/json")
        .body(surf_response.body_bytes().await?)
        .build();

    Ok(tide_response)
}
