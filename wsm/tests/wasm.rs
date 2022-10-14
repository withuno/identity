//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use wasm_bindgen_test::*;

use wsm::*;

#[test]
fn test_share_recover_seed()
{
    use rand::prelude::*;
    let mut rng = rand::thread_rng();

    let mut seed_to_share: [u8; 32] = [0; 32];

    for _ in 1..100 {
        rng.fill(&mut seed_to_share);

        let mu_seed: [u8; 10] = [0; 10];

        let share = share_seed(&seed_to_share, &mu_seed).unwrap();

        assert_eq!(decrypt_share(&share, &mu_seed).unwrap(), seed_to_share);
    }
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
