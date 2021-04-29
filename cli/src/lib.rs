//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

// The client library contains high-level helper routines used primarily by the
// cli.

use anyhow::Result;
use anyhow::{anyhow, bail,};

use surf::Url;
use chrono::offset::Utc;

use uno::Binding;
use uno::Signer;

use std::convert::From;
use std::convert::TryFrom;

pub fn get_vault(host: String, id: uno::Id) -> Result<String>
{
    let key = uno::KeyPair::from(&id);
    let sym = uno::SymmetricKey::from(&id);

    let timestamp = Utc::now().to_rfc3339();
    let signature = key.sign(timestamp.as_bytes());

    let url = vault_url_from_key(&host, &key)?;
    let req = surf::get(url.as_str())
        .header("x-uno-timestamp", timestamp)
        .header("x-uno-signature", base64::encode(&signature.to_bytes()))
        .build();

    let blob = async_std::task::block_on(do_http(req))
        .map_err(|e| anyhow!("{}", e))?;

    let vault = uno::decrypt(Binding::Vault, sym, &blob)?;
    Ok(String::from_utf8(vault)?)
}

pub fn put_vault(host: String, id: uno::Id, data: &[u8]) -> Result<String>
{
    let key = uno::KeyPair::from(&id);
    let sym = uno::SymmetricKey::from(&id);

    let timestamp = Utc::now().to_rfc3339();
    let signature = key.sign(timestamp.as_bytes());

    let cyph = uno::encrypt(Binding::Vault, sym, data)?;
    let csig = key.sign(&cyph).to_bytes();
    let body = [&csig[..], &*cyph].concat();

    let url = vault_url_from_key(&host, &key)?;
    let req = surf::put(url.as_str())
        .header("x-uno-timestamp", timestamp)
        .header("x-uno-signature", base64::encode(&signature.to_bytes()))
        .body(body)
        .build();

    let blob = async_std::task::block_on(do_http(req))
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

    let data = async_std::task::block_on(do_http(req))
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

    let blob = async_std::task::block_on(do_http(req))
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

    let blob = async_std::task::block_on(do_http(req))
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
        let raw = base64::decode(&s)?;
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
        let val = Value::String(base64::encode(&txt));
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

async fn do_http(req: surf::Request) -> Result<Vec<u8>>
{
    let client = surf::client();

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
        let expected = "https://example.com/v1/vaults/jvB9pRmsHw-87BTEBB9CvbQI_ENDFiNM_PmcQGmaId8";
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
