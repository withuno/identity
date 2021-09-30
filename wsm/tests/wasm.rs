use wasm_bindgen_test::*;

use wsm::*;

#[wasm_bindgen_test]
fn test_decrypt_share() {
    let session_seed = String::from("lxAi2uKDOqW7zg");

    let share = String::from(
        r"cGpbsstHz8Gm15DSBtAliDOQpCn0qCY0Ycw8R/2SwwdkxLdxEBpgIeSWOs64nAopMoP5vfElKz5xg3eF7GT30IvMt/zDwO3upEekvUYJLHEfpxYlGVskDBKhR5VPgxwIHKKAC9NhxWGjr4V/CynaWmxXnnmNzG0C8OYGw2zehyzM0P1yyTQFgw0NRcxwSs6r3wjCiiN++k8l5YEXodmt/r/vZpFUecHEFmZc8dv/t8rS+gDhIn7lA8x0SvIfRDTdscoKBI5O4bJVDMrAKGLJjRcHQhaxpFU6o4KqNX4Zh+15sEE3TtKQ4/CrzEZKkHwqkFHuO9GZlHYUO4asbjF8aF25onCNf8VO"
    );

    let expected_seed = base64::encode(vec![
        62, 81, 232, 140, 251, 15, 5, 31, 21, 119, 64, 228, 110, 63, 195, 174,
        244, 154, 5, 22, 230, 100, 168, 91, 92, 127, 43, 139, 42, 113, 74,
        167,
    ]);

    assert_eq!(
        wasm_decrypt_share(share, session_seed).unwrap(),
        expected_seed
    );
}

#[wasm_bindgen_test]
fn test_decrypt_vault() {
    let vault = base64::decode(String::from(
        r"Vz9uXUsamtXfyr89RQMqU19Oas99joJ6BBoRramvYXnPVuVZ5gPTMLFOy+qhAk7RH17AulM0TpP2bvGu40HiOLxYkqFMnHTW0+OsRZ63zhgiiFlYenyojvdjTNi2Noizd9CUZ78R7mGbeH7JAtmyh+tNspZVp3CzUEoc2O7FohsEkLwCFNKWY4dWZKoryb8mmddUZROQs3oehtOs+NVBasvRxHRKgW+J2Mp1CcXIn67J1MimFtwRcQ5Uv6oVKwWDoe3xt82gfF+4vPvQWXYxKU3naZzDVvVpD0o/YS5JotIbanpaYaBruhy2KZ7gZU2/x9T3+Np29BesgptSzNHRAsoW+8ThtGNTtxP86EOPKFOly6+idD01lbx02Pn1tcdO5GWfuNFs01My96pWzN3bxRKz5S/oXt8BDSBmgv6KW9W/eXi5ch00UvpNzkNftwOF7B4kv8TMCdLj7ERyfhyHh6qRj15gH16g6Z4OcLbuK0IaPjk0ebt0yCC3OCX5MdVIIOvPVnz5ESwAyeZ5gYP+BXdaz4wd2UWa9E1QF/C2Ieaw+2yHHILZeVIXAO3y4tMeHRAUrqJZakjJPG0wj3UYjKDER+tXAdeGPldxv4oE6BMTTOkGbR69RS8tuIoJJ+ft78AKWjedyHs4V6P+ttkBrosRAMdkVLy8n/Lyy728t+UoubKmSHzBxN0VTV89ngqEXRAbnFbtSwjcU49vqgISoYVY4gMCDZjygZoKF2Cwg2Deu1UvxD0/Oa4N/Hxr8MwyP/epniBeHz4rj2Hm2W9a",
    )).unwrap();

    let expected = String::from(
        r"eyJjb250YWN0cyI6W10sImlkQ2FyZFZhbHVlIjoiNSDil48gSCBhIOKXjyDil48gMSDil48g4pePIOKXjyDil48g4pePIOKXjyBjIOKXjyDil48g4pePIOKXjyDil48g4pePIG0g4pePIGQgTiDil48g4pePIOKXjyBrIOKXjyBOIGIg4pePIEwgcSDil48gVyBQIOKXjyDil48gTCBKIGUg4pePIOKXjyDil48g4pePIOKXjyDil48g4pePIOKXjyDil48g4pePIOKXjyBJIOKXjyDil48g4pePIOKXjyBkIHog4pePIOKXjyDil48gMCDil48g4pePIGwg4pePIOKXjyDil48g4pePIOKXjyA0IOKXjyBkIOKXjyDil48gNiDil48gbyDil48g4pePICsg4pePIOKXjyDil48g4pePIOKXjyDil48g4pePIDAg4pePIEEg4pePIGUg4pePIEQg4pePIOKXjyDil48g4pePIDQg4pePIHAgVCDil48g4pePIFwvIFUgTiDil48g4pePIOKXjyDil48g4pePIE8g4pePIOKXjyDil48gNSDil48g4pePIG4g4pePIOKXjyDil48gSiDil48g4pePIOKXjyBZID0iLCJ2YXVsdCI6W10sImNvbmZpZGFudHMiOltdLCJvbGRQYXNzd29yZHMiOltdLCJ1dWlkIjoiRURDMjMxQjMtOEE5QS00NzE2LUEyM0MtNTU1OUJBMTE1NjAzIn0=",
    );

    let seed = base64::encode(vec![
        185, 203, 86, 9, 47, 81, 143, 207, 19, 215, 220, 79, 129, 50, 252,
        151, 18, 101, 187, 123, 90, 83, 228, 37, 202, 54, 46, 236, 245, 152,
        160, 159,
    ]);

    assert_eq!(
        base64::encode(wasm_decrypt_vault(&vault, seed).unwrap()),
        expected
    );
}

#[wasm_bindgen_test]
fn test_auth_header() {
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
fn test_generate_session_id() {
    let expected = "kgFbVxPUAoaXjGXnyXJUlaKejL8SKaxM_9X0RvBYb44";
    let msg = base64::encode("0123456789");

    let r = wasm_generate_session_id(msg);
    assert_eq!(r.unwrap(), expected)
}

#[wasm_bindgen_test]
fn test_sign_message() {
    assert_eq!(
        wasm_sign_message(
            String::from("WdqX7a7/vRDzJUBdoTXituZ7S6GnhYH+i/hrw0puMV8="),
            String::from("0123456789")
        )
        .unwrap(),
        "KX0MAhQIxsKBpj4IvdvQpJdYkaU3gNXELdnPd9UWMaowCmjG2hcN60b5VLwO/cGzzIVQqdzEJniufvAJL3/WCw==",
    );
}

#[wasm_bindgen_test]
fn test_get_public_key() {
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
