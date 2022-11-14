//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use wasm_bindgen_test::*;

use wsm::*;

#[wasm_bindgen_test]
fn test_decrypt_share()
{
    let session_seed = String::from("lxAi2uKDOqW7zg");

    let share = String::from(
        r"cGpbsstHz8Gm15DSBtAliDOQpCn0qCY0Ycw8R/2SwwdkxLdxEBpgIeSWOs64nAopMoP5vfElKz5xg3eF7GT30IvMt/zDwO3upEekvUYJLHEfpxYlGVskDBKhR5VPgxwIHKKAC9NhxWGjr4V/CynaWmxXnnmNzG0C8OYGw2zehyzM0P1yyTQFgw0NRcxwSs6r3wjCiiN++k8l5YEXodmt/r/vZpFUecHEFmZc8dv/t8rS+gDhIn7lA8x0SvIfRDTdscoKBI5O4bJVDMrAKGLJjRcHQhaxpFU6o4KqNX4Zh+15sEE3TtKQ4/CrzEZKkHwqkFHuO9GZlHYUO4asbjF8aF25onCNf8VO",
    );

    let expected_seed = base64::encode(vec![
        62, 81, 232, 140, 251, 15, 5, 31, 21, 119, 64, 228, 110, 63, 195, 174,
        244, 154, 5, 22, 230, 100, 168, 91, 92, 127, 43, 139, 42, 113, 74, 167,
    ]);

    assert_eq!(wasm_decrypt_share(share, session_seed).unwrap(), expected_seed);
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_vault()
{
    let seed = base64::encode(vec![
        185, 203, 86, 9, 47, 81, 143, 207, 19, 215, 220, 79, 129, 50, 252, 151,
        18, 101, 187, 123, 90, 83, 228, 37, 202, 54, 46, 236, 245, 152, 160,
        159,
    ]);
    let seed2 = seed.clone();

    let vault = String::from("hello, vault");
    let vault2 = vault.clone();

    let e = wasm_encrypt_vault(vault, seed).unwrap();
    let d = wasm_decrypt_vault(&e, seed2).unwrap();

    assert_eq!(vault2, *d);
}

#[wasm_bindgen_test]
fn test_auth_header()
{
    //m=65536,t=3,p=8
    assert_eq!(
        wasm_auth_header(
            String::from("1234"),
            String::from("GET"),
            String::from("/"),
            b"salt1234",
            b"",
            128,
            1,
            1
        )
        .unwrap(),
        "c2FsdDEyMzQ$epmTu7qNOCcaCJ5GMStEjN9Xfq0jGm1mbwDFu/E5K4Q"
    );
}

#[wasm_bindgen_test]
fn test_generate_session_id()
{
    let expected = "kgFbVxPUAoaXjGXnyXJUlaKejL8SKaxM_9X0RvBYb44";
    let msg = base64::encode("0123456789");

    let r = wasm_generate_session_id(msg);
    assert_eq!(r.unwrap(), expected)
}

#[wasm_bindgen_test]
fn test_sign_message()
{
    assert_eq!(
        wasm_sign_message(
            String::from("WdqX7a7/vRDzJUBdoTXituZ7S6GnhYH+i/hrw0puMV8="),
            String::from("0123456789")
        )
        .unwrap(),
        "KX0MAhQIxsKBpj4IvdvQpJdYkaU3gNXELdnPd9UWMaowCmjG2hcN60b5VLwO/\
         cGzzIVQqdzEJniufvAJL3/WCw==",
    );
}

#[wasm_bindgen_test]
fn test_get_public_key()
{
    assert_eq!(
        wasm_get_public_key(
            String::from("WdqX7a7/vRDzJUBdoTXituZ7S6GnhYH+i/hrw0puMV8="),
            true
        )
        .unwrap(),
        "hQuTnfStbKhU-i4ri9QnMQFrsbHHOm04kHm3fE190aY"
    );

    assert_eq!(
        wasm_get_public_key(
            String::from("WdqX7a7/vRDzJUBdoTXituZ7S6GnhYH+i/hrw0puMV8="),
            false
        )
        .unwrap(),
        "hQuTnfStbKhU+i4ri9QnMQFrsbHHOm04kHm3fE190aY="
    );
}

use uno::{Id, KeyPair, Mu};

#[wasm_bindgen_test]
fn test_verify_params_from_query()
{
    let id = Id::new();
    let keypair = KeyPair::from(id);

    let mu = Mu::new();

    let q = format!(
        "{}::{}",
        base64::encode(&mu.0),
        base64::encode_config(keypair.public, base64::URL_SAFE_NO_PAD)
    );

    let StringTuple(one, two) =
        wasm_verify_params_from_query(base64::encode(q)).unwrap();
    assert_eq!(one, base64::encode(&mu.0));
    assert_eq!(
        two,
        base64::encode_config(keypair.public, base64::URL_SAFE_NO_PAD)
    );
}
