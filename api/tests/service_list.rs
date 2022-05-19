//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use serde_json::{Result, Value};
use std::fs;

#[test]
fn service_list_is_valid() {
    // try to deserialize the service list file and hope for the best!
    let contents = fs::read_to_string("tests/services.json").unwrap();

    let v: Result<Value> = serde_json::from_str(&contents);

    assert!(v.is_ok());
}
