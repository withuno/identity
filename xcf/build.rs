//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::error::Error;
use std::result::Result;

//
// Generate the C FFI using the cbindgen crate.
//
fn main() -> Result<(), Box<dyn Error>>
{
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let res = cbindgen::generate(crate_dir)?;
    res.write_to_file("include/uno.h");
    Ok(())
}
