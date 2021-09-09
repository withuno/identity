//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

// The client library contains high-level helper routines used primarily by the
// cli.

use anyhow::Result;
use anyhow::{anyhow, bail,};

use rand::RngCore;

use surf::{Request, Client, Response,};
use surf::middleware::{Middleware, Next};
use surf::Url;

use uno::Binding;
use uno::Signer;

use std::convert::From;
use std::convert::TryFrom;

pub fn get_vault(host: String, id: uno::Id) -> Result<String>
{
    let key = uno::KeyPair::from(&id);
    let sym = uno::SymmetricKey::from(&id);

    let url = vault_url_from_key(&host, &key)?;
    let req = surf::get(url.as_str())
        .build();

    let blob = async_std::task::block_on(do_http_signed(req, &id))
        .map_err(|e| anyhow!("{}", e))?;

    let vault = uno::decrypt(Binding::Vault, sym, &blob)?;
    Ok(String::from_utf8(vault)?)
}

pub fn put_vault(host: String, id: uno::Id, data: &[u8]) -> Result<String>
{
    let key = uno::KeyPair::from(&id);
    let sym = uno::SymmetricKey::from(&id);

    let body = uno::encrypt(Binding::Vault, sym, data)?;

    let url = vault_url_from_key(&host, &key)?;
    let req = surf::put(url.as_str())
        .body(body)
        .build();

    let blob = async_std::task::block_on(do_http_signed(req, &id))
        .map_err(|e| anyhow!("{}", e))?;

    let vault = uno::decrypt(Binding::Vault, sym, &blob)?;
    Ok(String::from_utf8(vault)?)
}

fn vault_url_from_key(endpoint: &str, key: &uno::KeyPair) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v1/vaults/")?;
    let cfg = base64::URL_SAFE_NO_PAD;
    let vid = base64::encode_config(key.public.as_bytes(), cfg);
    Ok(base.join(&vid)?)
}

pub fn get_ssss(host: String, mu: uno::Mu) -> Result<String>
{
    let session = uno::Session::try_from(&mu)?;
    let sym = uno::SymmetricKey::from(&mu);
    let url = ssss_url_from_session(&host, &session)?;
    let req = surf::get(url.as_str())
        .build();

    let data = async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    let out = match infer_binding(&data)? {
        Inference::Exact(b) => decrypt_share(b, sym, &data),
        Inference::Unknown => {
            // The data represents a "complete" split or combine session. Try
            // both and see which one works.
            let mut
                r = decrypt_share(Binding::Split, sym, &data);
            if r.is_err() { // TODO if let Err(aead::Error) = r
                r = decrypt_share(Binding::Combine, sym, &data);
            }
            Ok(r?)
        },
    }?;

    Ok(String::from_utf8(out)?)
}

pub fn put_ssss(host: String, mu: uno::Mu, data: &[u8]) -> Result<String>
{
    let session = uno::Session::try_from(&mu)?;
    let sym = uno::SymmetricKey::from(&mu);
    let usage = match infer_binding(data)? {
        Inference::Exact(b) => b,
        Inference::Unknown => Binding::None,
    };
    let body = encrypt_share(usage, sym, data)?;
    let url = ssss_url_from_session(&host, &session)?;
    let req = surf::put(url.as_str())
        .body(body)
        .build();

    let blob = async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    let out = decrypt_share(usage, sym, &blob)?;
    Ok(String::from_utf8(out)?)
}

pub fn patch_ssss(host: String, mu: uno::Mu, data: &[u8]) -> Result<String>
{
    let session = uno::Session::try_from(&mu)?;
    let sym = uno::SymmetricKey::from(&mu);
    let usage = match infer_binding(data)? {
        Inference::Exact(b) => b,
        // While this can happen on PUT, it shouldn't on PATCH.
        Inference::Unknown => Binding::None,
    };
    let body = encrypt_share(usage, sym, data)?;
    let url = ssss_url_from_session(&host, &session)?;
    let req = surf::patch(url.as_str())
        .body(body)
        .build();

    let blob = async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    let out = decrypt_share(usage, sym, &blob)?;
    Ok(String::from_utf8(out)?)
}

const CONFIDANT: &str = "confidant";
const SHARE: &str = "share";
const USER: &str = "user";

#[derive(Debug)]
enum Inference<'a>
{
    Exact(Binding<'a>),
    Unknown,
}

use serde_json::Value;

// https://www.notion.so/withuno/Shamir-Secret-Sharing-Session-de9d541155764826b9c9519a486a36d1
fn infer_binding(data: &[u8]) -> Result<Inference>
{
    let json: Value = serde_json::from_slice(data)?;
    let map = match json {
        Value::Object(m) => m,
        _ => bail!("not a valid session"),
    };
    let has_share = map.contains_key(SHARE);
    let has_user = map.contains_key(USER);
    let has_confidant = map.contains_key(CONFIDANT);

    if !has_share && !has_user && !has_confidant {
        return Ok(Inference::Exact(Binding::Transfer));
    }
    if has_share && !has_user && !has_confidant {
        return Ok(Inference::Exact(Binding::Transfer));
    }
    if has_share && has_user && !has_confidant {
        return Ok(Inference::Exact(Binding::Split));
    }
    if !has_share && !has_user && has_confidant {
        return Ok(Inference::Exact(Binding::Split));
    }
    if !has_share && has_user && !has_confidant {
        return Ok(Inference::Exact(Binding::Combine));
    }
    if has_share && !has_user && has_confidant {
        return Ok(Inference::Exact(Binding::Combine));
    }
    // !has_share && has_user && has_confidant
    // ^ shouldn't happen in practice
    // has_share && has_user && has_confidant
    // A "complete" session. These get cleaned up quickly.
    Ok(Inference::Unknown)
}

fn encrypt_share(usage: Binding, key: uno::SymmetricKey, data: &[u8])
-> Result<Vec<u8>>
{
    let mut json: Value = serde_json::from_slice(&data)?;
    let obj = json.as_object_mut()
        .ok_or(anyhow!("data is not a valid json object"))?;

    if let Some(Value::String(s)) = obj.get(SHARE) {
        use base64::STANDARD_NO_PAD;
        let raw = base64::decode_config(&s, STANDARD_NO_PAD)?;
        let txt = uno::encrypt(usage, key, &*raw)?;
        let val = Value::String(base64::encode(&txt));
        let _ = obj.insert(SHARE.into(), val);
    }

    Ok(serde_json::to_vec(&obj)?)
}

fn decrypt_share(usage: Binding, key: uno::SymmetricKey, data: &[u8])
-> Result<Vec<u8>>
{
    let mut json: Value = serde_json::from_slice(data)?;
    let obj = json.as_object_mut()
        .ok_or(anyhow!("data is not a valid json object"))?;

    if let Some(Value::String(s)) = obj.get(SHARE) {
        let raw = base64::decode(&s)?;
        let txt = uno::decrypt(usage, key, &*raw)?;
        use base64::STANDARD_NO_PAD;
        let b64 = base64::encode_config(&txt, STANDARD_NO_PAD);
        let val = Value::String(b64);
        let _ = obj.insert(SHARE.into(), val);
    }

    Ok(serde_json::to_vec(&obj)?)
}

fn ssss_url_from_session(endpoint: &str, session: &uno::Session) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v1/ssss/")?;
    let cfg = base64::URL_SAFE_NO_PAD;
    let sid = base64::encode_config(session.0, cfg);

    Ok(base.join(&sid)?)
}

async fn do_http_simple(req: surf::Request) -> Result<Vec<u8>>
{
    let client = surf::client()
        .with(surf::middleware::Logger::new());

    let mut res = client.send(req).await
        .map_err(|e| anyhow!("{}", e))?;

    let status = res.status();
    if status != 200 {
        bail!("server returned: {}", status);
    }
    let body = res.body_bytes().await
        .map_err(|e| anyhow!("{}", e))?;

    Ok(body)
}

async fn do_http_signed(req: surf::Request, id: &uno::Id) -> Result<Vec<u8>>
{
    let client = surf::client()
        .with(AuthClient{ id: uno::Id(id.0) })
        .with(surf::middleware::Logger::new());

    let mut res = client.send(req).await
        .map_err(|e| anyhow!("{}", e))?;

    let status = res.status();

    if status != 200 {
        let msg = res.body_string().await
            .map_err(|e| anyhow!("{}", e))?;
        bail!("server returned: {}\n{}", status, msg);
    }
    let body = res.body_bytes().await
        .map_err(|e| anyhow!("{}", e))?;

    Ok(body)
}

struct AuthClient {
    id: uno::Id,
}

#[surf::utils::async_trait]
impl Middleware for AuthClient
{
    async fn handle(&self, mut req: Request, cli: Client, next: Next<'_>)
    -> surf::Result<Response>
    {
        let mut req_c = req.clone();
        // copy the request and body bytes in case we have to redo it
        let bytes = req.take_body().into_bytes().await?;
        req.set_body(&*bytes);
        // run the request
        let mut res = next.run(req, cli.clone()).await?;
        use http_types::StatusCode;
        if let StatusCode::Unauthorized = res.status() {
            req_c.set_body(&*bytes);
            // if there's no header, skip sign + retry
            if let Some(www_auth) = res.header("www-authenticate") {
                let hstr = www_auth.last().as_str();
                let _ = sign(&mut req_c, bytes, hstr, &self.id)?;
                res = next.run(req_c, cli).await?;
            }
        }
        Ok(res) 
    }
}

use uno::KeyPair;

/// Sign a request using the www-authenticate info specfied in the provided 
/// www-authenticate header. Consume body and attach it to the request (the
/// body is required independent because the request signature contains the
/// hash of the body bytes, so it is up to the caller how to manage the body
/// bytes memory).
fn sign(req: &mut Request, body: Vec<u8>, header: &str, id: &uno::Id) -> Result<()>
{
    let www_auth = parse_www_auth(header)?;
    let n64 = &www_auth.params["nonce"];
    let bhash = blake3::hash(&body);
    let bhashb = bhash.as_bytes();
    let bhash_enc = base64::encode_config(bhashb, base64::STANDARD_NO_PAD);
    req.set_body(body);
    let method = req.method();
    let path = req.url().path().split("/").last().unwrap();
    let challenge = format!("{}:{}:/{}:{}", n64, method, path, bhash_enc);
    // println!("sign challenge: {:?}", &challenge);

    let mut sbytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut sbytes);
    let s64 = base64::encode_config(sbytes, base64::STANDARD_NO_PAD);

    use argon2::{Argon2, PasswordHash, PasswordHasher};
    let alg = Argon2::default();
    let param_str = format!("{}${}", &www_auth.params["algorithm"], &s64);
    let hash = PasswordHash::new(&param_str)
        .map_err(|_| anyhow!("hash parse failed"))?;
    let params = argon2::Params::try_from(&hash)
        .map_err(|_| anyhow!("param parse failed"))?;
    let alg_id = hash.algorithm;
    let cbytes = &challenge.as_bytes();

    let salt = argon2::password_hash::Salt::new(&s64)
        .map_err(|_| anyhow!("bad salt"))?;
    let pow = alg.hash_password(cbytes, Some(alg_id), params, salt)
        .map_err(|_| anyhow!("hash generation failed"))?;
    let response = format!("{}${}", s64, pow.hash.unwrap());

    let kp: uno::KeyPair = KeyPair::from(id);
    let pub_bytes = kp.public.to_bytes();
    let pub64 = base64::encode_config(&pub_bytes, base64::STANDARD_NO_PAD);
    let sig = kp.sign(&response.as_bytes());
    let sig64 = base64::encode_config(sig, base64::STANDARD_NO_PAD);

    let i = format!("identity={}", pub64);
    let n = format!("nonce={}", n64);
    let r = format!("response={}", response);
    let s = format!("signature={}", sig64);
    let auth = format!("tuned-digest-signature {};{};{};{}", i, n, r, s);
    req.insert_header("authorization", auth);

    Ok(())
}

use std::collections::HashMap;

struct WwwAuthTemp
{
    params: HashMap<String, String>,
}

fn parse_www_auth(header: &str) -> anyhow::Result<WwwAuthTemp>
{
    let items = match header.strip_prefix("tuned-digest-signature") {
        Some(s) => s.trim().split(';'),
        None => {
            bail!("wrong auth type");
        },
    };

    let mut map = HashMap::new();
    for i in items {
        let kv: Vec<&str> = i.trim().splitn(2, "=").collect();
        map.insert(kv[0].into(), kv[1].into());
    }
    let keys = ["nonce", "algorithm", "actions",];
    if keys.iter().fold(true, |a, k| a && map.contains_key(&k.to_string())) {
        Ok(WwwAuthTemp{params: map,})
    } else {
        Err(anyhow!("invalid www-auth"))
    }
}


#[cfg(test)]
mod unit
{
    use super::*;

    use uno::{Id, Mu, KeyPair, Session,};

    #[test]
    fn get_vault()
    {
    }

    #[test]
    fn put_vault()
    {
    }

    #[test]
    fn get_ssss()
    {
    }

    #[test]
    fn put_ssss()
    {
    }

    #[test]
    fn patch_ssss()
    {
    }

    #[test]
    fn url_from_key() -> Result<()>
    {
        let bytes64 = "XkjZ1zMeJqsrSkhgq2QqJXtDDM9hlnrF5HRFbcMuUzo";
        let bytes = base64::decode(bytes64)?;
        let id = Id::try_from(&*bytes)?;
        let pair = KeyPair::from(&id);
        let endpoint = "https://example.com";
        let actual = vault_url_from_key(endpoint, &pair)?;
        let expected = "https://example.com/v1/vaults/BOfVSES5eXi3HbbB0GIcmK35V57JyngUeDrnK_LJn5k";
        assert_eq!(expected, actual.to_string());

        Ok(())
    }

    #[test]
    fn url_from_session() -> Result<()>
    {
        let bytes = b"0123456789";
        let mu = Mu(*bytes);
        let session = Session::try_from(mu)?;
        let endpoint = "https://example.com";
        let actual = ssss_url_from_session(endpoint, &session)?;
        let expected = "https://example.com/v1/ssss/DMq6OqXqkDQWBVXkOXAL39A1xy-KYoxl0_Q7VnyEpjw";
        dbg!(&actual);
        assert_eq!(expected, actual.to_string());

        Ok(())
    }
}
