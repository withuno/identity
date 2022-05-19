#[cfg(test)]
use serde_json::{Result, Value};
use std::fs;

#[test]
fn service_list_is_valid()
{
    // try to deserialize the service list file and hope for the best!
    let contents = fs::read_to_string("tests/services.json").unwrap();

    let v: Result<Value> = serde_json::from_str(&contents);

    assert!(v.is_ok());
}
