//
// Copyright (C) 2022 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use crate::store::Database;

use uno::VerifyToken;

pub async fn create(
    db: &impl Database,
    id: String,
) -> Result<VerifyToken>
{
}

pub async fn verify(
    db: &impl Database,
    id: String,
    secret: String,
) -> Result<VerifyToken>
{
}

#[cfg(test)]
mod tests
{
    use super::*;
}
