//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::fmt::Debug;

use argon2::{Algorithm, Argon2, Params, Version};

use wasm_bindgen::prelude::*;

use uno::prove_blake3_work;
use uno::Signer;

#[derive(Debug)]
pub enum Error
{
    Fatal(String),
}

impl From<argon2::Error> for Error
{
    fn from(e: argon2::Error) -> Self { Error::Fatal(e.to_string()) }
}

impl From<base64::DecodeError> for Error
{
    fn from(e: base64::DecodeError) -> Self { Error::Fatal(e.to_string()) }
}

impl From<uno::Error> for Error
{
    fn from(e: uno::Error) -> Self { Error::Fatal(e.to_string()) }
}

fn argon_hash(
    t_cost: u32,
    m_cost: u32,
    p: u32,
    salt: &[u8],
    body: &[u8],
) -> Result<std::vec::Vec<u8>, Error>
{
    let params = Params::new(m_cost, t_cost, p, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2.hash_password_into(body, salt, &mut out)?;

    Ok(out.to_vec())
}

#[wasm_bindgen]
pub fn wasm_sign_message(seed: String, message: String) -> Option<String>
{
    let decoded_seed = match base64::decode(seed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let id = match uno::Id::try_from(&decoded_seed[..]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let keypair = match uno::KeyPair::try_from(id) {
        Ok(v) => v,
        Err(_) => return None,
    };

    Some(base64::encode(keypair.sign(message.as_bytes())))
}

#[wasm_bindgen]
pub fn wasm_auth_header(
    nonce: String,
    method: String,
    resource: String,
    salt: &[u8],
    body: &[u8],
    argon_m: u32,
    argon_t: u32,
    argon_p: u32,
) -> Option<String>
{
    let body_hash = blake3::hash(body);
    let body_enc =
        base64::encode_config(body_hash.as_bytes(), base64::STANDARD_NO_PAD);

    let string_to_argon =
        format!("{}:{}:{}:{}", nonce, method, resource, body_enc);

    match argon_hash(
        argon_t,
        argon_m,
        argon_p,
        salt,
        &string_to_argon.as_bytes(),
    ) {
        Ok(out) => {
            let hash = base64::encode_config(out, base64::STANDARD_NO_PAD);
            let salthash = base64::encode_config(salt, base64::STANDARD_NO_PAD);
            Some(format!("{}${}", salthash, hash))
        },
        Err(_) => None,
    }
}

#[wasm_bindgen]
pub fn wasm_async_auth_header(
    nonce: String,
    method: String,
    resource: String,
    cost: u8,
    body: &[u8],
) -> Option<String>
{
    let body_hash = blake3::hash(body);
    let body_enc =
        base64::encode_config(body_hash.as_bytes(), base64::STANDARD_NO_PAD);

    let challenge = format!("{}:{}:{}:{}", nonce, method, resource, body_enc);

    match prove_blake3_work(&challenge.as_bytes(), cost) {
        Some(n) => Some(format!(
            "blake3${}${}",
            n,
            nonce,
        )),
        None => None,
    }
}

#[wasm_bindgen]
pub fn wasm_decrypt_share(share: String, seed: String) -> Option<String>
{
    let decoded_share = match base64::decode(share) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let decoded_seed = match base64::decode(seed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let id = match uno::Mu::try_from(&decoded_seed[..]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let key = uno::SymmetricKey::from(&id);
    let ctx = uno::Binding::Combine;

    let decrypted_share = match uno::decrypt(ctx, key, &decoded_share) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let string_share = match String::from_utf8(decrypted_share) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let words: Vec<String> =
        string_share.split(' ').map(|s| s.to_owned()).collect();

    let shares = vec![words];
    match uno::combine(&shares) {
        Ok(v) => Some(base64::encode(v.0)),
        Err(_) => None,
    }
}

#[wasm_bindgen]
pub fn wasm_decrypt_magic_share(share: &[u8], seed: String) -> Option<String>
{
    let decoded_seed =
        match base64::decode_config(seed, base64::URL_SAFE_NO_PAD) {
            Ok(v) => v,
            Err(_) => return None,
        };


    let id = match uno::Id::try_from(&decoded_seed[..]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let key = uno::SymmetricKey::from(&id);
    let ctx = uno::Binding::MagicShare;

    let decrypted_share = match uno::decrypt(ctx, key, &share) {
        Ok(v) => v,
        Err(_) => return None,
    };

    match String::from_utf8(decrypted_share) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

#[wasm_bindgen]
pub fn wasm_encrypt_vault(vault: String, seed: String) -> Option<Box<[u8]>>
{
    let decoded_seed = match base64::decode(seed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let id = match uno::Id::try_from(&decoded_seed[..]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let key = uno::SymmetricKey::from(&id);
    let ctx = uno::Binding::Vault;

    match uno::encrypt(ctx, key, vault.as_bytes()) {
        Ok(v) => Some(v.into_boxed_slice()),
        Err(_) => return None,
    }
}

#[wasm_bindgen]
pub fn wasm_decrypt_vault(vault: &[u8], seed: String) -> Option<String>
{
    let decoded_seed = match base64::decode(seed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let id = match uno::Id::try_from(&decoded_seed[..]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let key = uno::SymmetricKey::from(&id);
    let ctx = uno::Binding::Vault;

    let decrypted_vault = match uno::decrypt(ctx, key, vault) {
        Ok(v) => v,
        Err(_) => return None,
    };

    match String::from_utf8(decrypted_vault) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

#[wasm_bindgen]
pub fn wasm_generate_session_id(seed: String) -> Option<String>
{
    // assert len(seed) == 32

    let decoded_seed = match base64::decode(seed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let salt = b"uno recovery session id";

    match argon_hash(32, 256, 2, salt, &decoded_seed) {
        Ok(v) => Some(base64::encode_config(v, base64::URL_SAFE_NO_PAD)),
        Err(_) => None,
    }
}

#[wasm_bindgen]
pub fn wasm_get_public_key_url_encoded(seed: String) -> Option<String>
{
    match base64::decode_config(seed, base64::URL_SAFE_NO_PAD) {
        Ok(v) => wasm_get_public_key(base64::encode(v), true),
        Err(_) => return None,
    }
}

#[wasm_bindgen]
pub fn wasm_get_public_key(seed: String, url_encode: bool) -> Option<String>
{
    let decoded_seed = match base64::decode(seed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let id = match uno::Id::try_from(&decoded_seed[..]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    match uno::KeyPair::try_from(id) {
        Ok(v) => {
            if url_encode {
                return Some(base64::encode_config(
                    v.public,
                    base64::URL_SAFE_NO_PAD,
                ));
            }

            Some(base64::encode(v.public))
        },
        Err(_) => None,
    }
}
