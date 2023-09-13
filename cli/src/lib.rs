//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

// The client library contains high-level helper routines used primarily by the
// cli.

use anyhow::Context;
use anyhow::Result;
use anyhow::{anyhow, bail};

use api::DirectoryEntry;
use api::DirectoryEntryCreate;
use api::LookupQuery;
use api::LookupResult;
use chrono::{Duration, Utc};

use http_types::headers::HeaderValues;
use http_types::StatusCode;
use rand::RngCore;
use uno::KeyPair;

use surf::middleware::{Middleware, Next};
use surf::Url;
use surf::{Client, Request, Response};

use uno::Binding;
use uno::MagicShare;
use uno::PublicKey;
use uno::Signer;

use std::convert::From;
use std::convert::TryFrom;
use std::ffi::OsString;
use std::path::Path;

use serde::{Deserialize, Serialize};

use uuid::Uuid;

pub const API_HOST: &'static str = "https://api.uno.app";

#[derive(Serialize, Deserialize)]
pub struct Config
{
    pub uuid: Uuid,
    pub api_host: String,
    pub seed_file: OsString,
    pub vclock_file: OsString,
}

impl Default for Config
{
    fn default() -> Config
    {
        let home = dirs_next::home_dir().unwrap();
        let mut uno = home.clone();
        uno.push(".uno");

        let mut seed = uno.clone();
        seed.push("identity");
        let mut vclock = uno.clone();
        vclock.push("vclock");

        Config {
            uuid: Uuid::new_v4(),
            seed_file: seed.into_os_string(),
            vclock_file: vclock.into_os_string(),
            api_host: String::from(API_HOST),
        }
    }
}

pub fn load_config(path: &Path) -> Result<Config>
{
    let file = std::fs::File::open(path)
        .context("Error loading config. Please run `uno init` first.")?;
    let config: Config =
        ron::de::from_reader(file).context("Error parsing config.")?;

    Ok(config)
}

///
/// Generate a new config including new client UUID and vclock. If an existing
/// seed is found, it will be reused. Any existing vclock will be clobbered.
///
pub fn gen_config(path: &Path, api: String) -> Result<Config>
{
    let mut config = Config::default();

    config.api_host = api;

    // if the seed loads fine, we don't have to generate and write a new one
    match load_seed(&config) {
        Ok(_) => match load_config(path) {
            // If we are reusing the seed and there is a client UUID, reuse it
            // as well so we don't build up a bunch of stale ones in the user's
            // vclock.
            Ok(old) => config.uuid = old.uuid,
            Err(_) => {},
        },
        Err(_) => {
            gen_seed(&config)?;
        },
    };

    // clobber the vclock. we'll get a new one from the server when we need it
    gen_vclock(&config)?;

    // write the actual config
    use ron::ser::PrettyConfig;
    let data = ron::ser::to_string_pretty(&config, PrettyConfig::default())?;
    std::fs::write(path, data)?;

    Ok(load_config(path)?)
}

pub fn load_seed(config: &Config) -> Result<uno::Id>
{
    let path = std::path::Path::new(&config.seed_file);
    let bytes = std::fs::read(path).with_context(|| {
        let s = config.seed_file.to_string_lossy();
        format!("error reading seed_file: {}", s)
    })?;

    Ok(uno::Id::try_from(&bytes[..])?)
}

fn gen_seed(config: &Config) -> Result<uno::Id>
{
    let seed = uno::Id::new();
    let path = std::path::Path::new(&config.seed_file);

    // the private key should not be world readable
    const MODE: u32 = 0o600;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MODE)
        .open(path)?;

    use std::io::Write;
    file.write_all(&seed.0)?;

    Ok(load_seed(config)?)
}

use vclock::VClock;

fn gen_vclock(config: &Config) -> Result<()>
{
    let client = config.uuid.to_hyphenated().to_string();
    let vclock = VClock::new(client);

    Ok(write_vclock(config, vclock)?)
}

fn write_vclock(config: &Config, c: VClock<String>) -> Result<()>
{
    let data = ron::ser::to_string(&c)?;
    std::fs::write(&config.vclock_file, data)?;

    Ok(())
}

fn merge_and_save_vclock(
    config: &Config,
    theirs: VClock<String>,
) -> Result<VClock<String>>
{
    let ours = load_vclock(config)?;
    let new = ours.merge(&theirs);

    write_vclock(config, new)?;

    Ok(load_vclock(config)?)
}

pub fn load_vclock(config: &Config) -> Result<VClock<String>>
{
    let path = std::path::Path::new(&config.vclock_file);
    let bytes = std::fs::read(path).with_context(|| {
        let s = config.seed_file.to_string_lossy();
        format!("error reading seed_file: {}", s)
    })?;

    ron::de::from_bytes(&bytes).map_err(|e| anyhow!(e))
}

pub fn get_vault(cfg: &Config, host: &String, id: uno::Id) -> Result<String>
{
    let key = uno::KeyPair::from(&id);
    let sym = uno::SymmetricKey::from(&id);

    let url = vault_url_from_key(&host, &key)?;
    let req = surf::get(url.as_str()).build();

    let mut res = async_std::task::block_on(do_http_signed_vc(req, &id))
        .map_err(|e| anyhow!("{}", e))?;

    let vclock = match &res.header("vclock") {
        Some(s) => api::parse_vclock(s.last().as_str())?,
        None => bail!("missing vclock"),
    };

    let blob = async_std::task::block_on(res.body_bytes())
        .map_err(|e| anyhow!("{}", e))?;

    let vault = uno::decrypt(Binding::Vault, sym, &blob)?;

    merge_and_save_vclock(cfg, vclock)?;

    Ok(String::from_utf8(vault)?)
}

pub fn put_vault(
    cfg: &Config,
    host: &String,
    id: uno::Id,
    data: &[u8],
) -> Result<String>
{
    let key = uno::KeyPair::from(&id);
    let sym = uno::SymmetricKey::from(&id);

    let body = uno::encrypt(Binding::Vault, sym, data)?;

    let url = vault_url_from_key(&host, &key)?;

    // get the known vclock and increment this client's version
    let mut vclock = load_vclock(cfg)?;
    vclock.incr(cfg.uuid.to_hyphenated().to_string());
    let vclock_header = api::write_vclock(&vclock)?;

    let req = surf::put(url.as_str())
        .header("vclock", vclock_header)
        .body(body)
        .build();

    let mut res = async_std::task::block_on(do_http_signed_vc(req, &id))
        .map_err(|e| anyhow!("{}", e))?;

    if res.status() == surf::StatusCode::Conflict {
        let msg = "vault out-of-date! \nPull the latest vault using `get` and \
                   reapply any modifications on top of the fresh copy.";
        bail!(msg);
    }

    let blob = async_std::task::block_on(res.body_bytes())
        .map_err(|e| anyhow!("{}", e))?;

    let vault = uno::decrypt(Binding::Vault, sym, &blob)?;
    Ok(String::from_utf8(vault)?)
}

fn vault_url_from_key(endpoint: &str, key: &uno::KeyPair) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v2/vaults/")?;
    let cfg = base64::URL_SAFE_NO_PAD;
    let pk = pubkey_bytes_from_keypair(key);
    let vid = base64::encode_config(&pk, cfg);
    Ok(base.join(&vid)?)
}

pub fn pubkey_bytes_from_keypair(kp: &KeyPair) -> Vec<u8>
{
    let start = uno::PRIVATE_KEY_LENGTH;
    let end = uno::KEYPAIR_LENGTH;
    kp.to_keypair_bytes()[start..end].to_vec()
}

pub fn get_share(host: &str, seed: uno::Id) -> Result<String>
{
    let keypair = uno::KeyPair::from(&seed);
    let pk = PublicKey::from(&keypair);
    let url = share_url_from_public_key(&host, &pk)?;

    let req = surf::get(url.as_str()).build();
    let result = async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    let v: MagicShare = serde_json::from_slice(&result)?;
    let decoded_encrypted_credential = base64::decode(v.encrypted_credential)?;

    let decryption_key = uno::SymmetricKey::from(&seed);
    let decrypted = uno::decrypt(
        Binding::MagicShare,
        decryption_key,
        &decoded_encrypted_credential,
    )?;

    let s = String::from_utf8(decrypted)?;

    Ok(s)
}

pub fn post_share(
    host: &str,
    _id: uno::Id,
    expire_seconds: &str,
    data: &[u8],
) -> Result<String>
{
    let entropy = uno::Id::new();

    let encryption_key = uno::SymmetricKey::from(&entropy);
    let encrypted = uno::encrypt(Binding::MagicShare, encryption_key, data)?;

    let keypair = uno::KeyPair::from(&entropy);

    let expires_in = expire_seconds.parse::<i64>().unwrap();
    let expires_at = Utc::now() + Duration::seconds(expires_in);

    let pk_bytes = pubkey_bytes_from_keypair(&keypair);
    let envelope = MagicShare {
        id: base64::encode_config(pk_bytes, base64::URL_SAFE_NO_PAD),
        schema_version: 0,
        expires_at,
        encrypted_credential: base64::encode(encrypted),
    };

    let pk = PublicKey::from(&keypair);
    let url = share_url_from_public_key(&host, &pk)?;
    let json_envelope = serde_json::to_string(&envelope)?;

    let req = surf::post(url.as_str()).body(json_envelope).build();

    async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    Ok(format!(
        "share created at {} with entropy {}",
        url,
        base64::encode_config(entropy.0, base64::URL_SAFE_NO_PAD)
    ))
}

pub fn create_verify_token(
    host: &str,
    id: uno::Id,
    email: &str,
) -> Result<String>
{
    let keypair = uno::KeyPair::from(id);
    let pk = PublicKey::from(&keypair);
    let url = verify_token_url_from_public_key(host, &pk)?;

    #[derive(Serialize)]
    struct VerifyCreateBody
    {
        email: String,
    }

    let json =
        serde_json::to_string(&VerifyCreateBody { email: email.into() })?;

    let req = surf::post(url.as_str()).body(json).build();

    async_std::task::block_on(do_http_signed_asym(req, &id))
        .map_err(|e| anyhow!("{}", e))?;

    Ok(format!("verify token created at {} for email: {}", url, email))
}

pub fn confirm_verify_token(
    host: &str,
    id: uno::Id,
    secret: &str,
) -> Result<String>
{
    let keypair = uno::KeyPair::from(id);
    let pk = PublicKey::from(&keypair);
    let url = verify_token_url_from_public_key(host, &pk)?;

    #[derive(Serialize)]
    struct ConfirmVerifyBody
    {
        secret: String,
    }

    let json =
        serde_json::to_string(&ConfirmVerifyBody { secret: secret.into() })?;

    let req = surf::put(url.as_str()).body(json).build();

    async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    Ok(format!("verified token."))
}

pub fn get_ssss(host: &String, mu: uno::Mu) -> Result<String>
{
    let session = uno::Session::try_from(&mu)?;
    let sym = uno::SymmetricKey::from(&mu);
    let url = ssss_url_from_session(&host, &session)?;
    let req = surf::get(url.as_str()).build();

    let data = async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    let out = match infer_binding(&data)? {
        Inference::Exact(b) => decrypt_share(b, sym, &data),
        Inference::Unknown => {
            // The data represents a "complete" split or combine session. Try
            // both and see which one works.
            let mut r = decrypt_share(Binding::Split, sym, &data);
            if r.is_err() {
                // TODO if let Err(aead::Error) = r
                r = decrypt_share(Binding::Combine, sym, &data);
            }
            Ok(r?)
        },
    }?;

    Ok(String::from_utf8(out)?)
}

pub fn put_ssss(host: &String, mu: uno::Mu, data: &[u8]) -> Result<String>
{
    let session = uno::Session::try_from(&mu)?;
    let sym = uno::SymmetricKey::from(&mu);

    let usage = match infer_binding(data)? {
        Inference::Exact(b) => b,
        Inference::Unknown => Binding::None,
    };
    let body =
        encrypt_share(usage, sym, data).context("cannot encrypt share")?;
    let url = ssss_url_from_session(&host, &session)?;
    let req = surf::put(url.as_str()).body(body).build();

    let blob = async_std::task::block_on(do_http_simple(req))
        .map_err(|e| anyhow!("{}", e))?;

    let out = decrypt_share(usage, sym, &blob)?;
    Ok(String::from_utf8(out)?)
}

pub fn patch_ssss(host: &String, mu: uno::Mu, data: &[u8]) -> Result<String>
{
    let session = uno::Session::try_from(&mu)?;
    let sym = uno::SymmetricKey::from(&mu);

    let usage = match infer_binding(data)? {
        Inference::Exact(b) => b,
        // While this can happen on PUT, it shouldn't on PATCH.
        Inference::Unknown => Binding::None,
    };
    let body =
        encrypt_share(usage, sym, data).context("cannot encrypt share")?;
    let url = ssss_url_from_session(&host, &session)?;
    let req = surf::patch(url.as_str()).body(body).build();

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
    let json: Value = serde_json::from_slice(data).context("invalid json")?;
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

fn encrypt_share(
    usage: Binding,
    key: uno::SymmetricKey,
    data: &[u8],
) -> Result<Vec<u8>>
{
    let mut json: Value = serde_json::from_slice(&data)?;
    let obj = json
        .as_object_mut()
        .ok_or(anyhow!("data is not a valid json object"))?;

    if let Some(Value::String(s)) = obj.get(SHARE) {
        let raw = base64::decode(&s)
            .context("\"share\" field is not base64 encoded")?;
        let txt = uno::encrypt(usage, key, &*raw)?;
        let val = Value::String(base64::encode(&txt));
        let _ = obj.insert(SHARE.into(), val);
    }

    Ok(serde_json::to_vec(&obj)?)
}

fn decrypt_share(
    usage: Binding,
    key: uno::SymmetricKey,
    data: &[u8],
) -> Result<Vec<u8>>
{
    let mut json: Value = serde_json::from_slice(data)?;
    let obj = json
        .as_object_mut()
        .ok_or(anyhow!("data is not a valid json object"))?;

    if let Some(Value::String(s)) = obj.get(SHARE) {
        let raw = base64::decode(&s)?;
        let txt = uno::decrypt(usage, key, &*raw)?;
        let b64 = base64::encode(&txt);
        let val = Value::String(b64);
        let _ = obj.insert(SHARE.into(), val);
    }

    Ok(serde_json::to_vec(&obj)?)
}

fn ssss_url_from_session(endpoint: &str, session: &uno::Session)
-> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v2/ssss/")?;
    let cfg = base64::URL_SAFE_NO_PAD;
    let sid = base64::encode_config(session.0, cfg);

    Ok(base.join(&sid)?)
}

fn share_url_from_public_key(
    endpoint: &str,
    key: &uno::PublicKey,
) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v2/shares/")?;
    let sid = base64::encode_config(key, base64::URL_SAFE_NO_PAD);

    Ok(base.join(&sid)?)
}

fn verify_token_url_from_public_key(
    endpoint: &str,
    key: &uno::PublicKey,
) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v2/verify_tokens/")?;
    let sid = base64::encode_config(key, base64::URL_SAFE_NO_PAD);

    Ok(base.join(&sid)?)
}

pub fn lookup_cids(
    host: &str,
    id: &uno::Id,
    country: &str,
    phones: &[&str],
) -> Result<LookupResult>
{
    let url = directory_lookup_url(host)?;

    // TODO: take query as a parameter
    let query = LookupQuery {
        country: String::from(country),
        phone_numbers: phones.iter().map(|s| String::from(*s)).collect(),
    };

    let req = surf::get(url.as_str())
        .body_json(&query)
        .map_err(|e| anyhow!("{}", e))?
        .build();

    let mut res = async_std::task::block_on(do_http_signed_asym(req, id))
        .map_err(|e| anyhow!("{}", e))?;

    let status = res.status();
    if status != 200 {
        let body = async_std::task::block_on(res.body_string())
            .map_err(|e| anyhow!(e))?;

        bail!("unexpected status: {}\nbody: {}", status, body)
    }

    let bytes =
        async_std::task::block_on(res.body_bytes()).map_err(|e| anyhow!(e))?;

    let result: LookupResult = serde_json::from_slice(&bytes)?;

    Ok(result)
}

fn directory_lookup_url(endpoint: &str) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;

    Ok(host.join("v2/directory/lookup")?)
}


pub fn post_entry(
    host: &str,
    id: &uno::Id,
    entry: DirectoryEntryCreate,
    code: Option<&str>,
) -> Result<String>
{
    let url = directory_entries_url(host)?;

    let mut builder =
        surf::post(url.as_str()).body_json(&entry).map_err(|e| anyhow!(e))?;

    if let Some(code) = code {
        builder = builder.header("verification", code);
    }

    let req = builder.build();

    let mut res = async_std::task::block_on(do_http_signed_asym(req, id))
        .map_err(|e| anyhow!("{}", e))?;

    let status = res.status();

    if status == StatusCode::PaymentRequired {
        return Ok("Verification code required.\nCheck SMS and retry with \
                   --verification <code>"
            .into());
    }

    if status != StatusCode::Created {
        let body = async_std::task::block_on(res.body_string())
            .map_err(|e| anyhow!(e))?;

        bail!("unexpected status: {}\nbody: {}", status, body);
    }

    let location = res
        .header("location")
        .ok_or_else(|| anyhow!("missing location header"))?
        .last()
        .as_str();

    let output = format!("cid: {}", location);

    Ok(output)
}


fn directory_entries_url(endpoint: &str) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;

    Ok(host.join("v2/directory/entries")?)
}


pub fn get_entry(host: &str, id: &uno::Id, cid: &[u8])
-> Result<DirectoryEntry>
{
    let url = directory_entry_url_from_cid(host, cid)?;
    let req = surf::get(url.as_str()).build();
    let mut res = async_std::task::block_on(do_http_signed_asym(req, id))
        .map_err(|e| anyhow!(e))?;

    let status = res.status();
    if status != 200 {
        let body = async_std::task::block_on(res.body_string())
            .map_err(|e| anyhow!(e))?;

        bail!("unexpected status: {}\nbody: {}", status, body)
    }

    let bytes =
        async_std::task::block_on(res.body_bytes()).map_err(|e| anyhow!(e))?;

    let result: DirectoryEntry = serde_json::from_slice(&bytes)?;

    Ok(result)
}

fn directory_entry_url_from_cid(endpoint: &str, cid: &[u8]) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;
    let base = host.join("v2/directory/entries/")?;
    let cid = base64::encode_config(cid, base64::URL_SAFE_NO_PAD);

    Ok(base.join(&cid)?)
}

pub fn get_assistance(
    host: &str,
    id: &uno::Id,
    domain: &str,
    topic: api::assistant::Topic,
) -> Result<String>
{
    let url = assistant_topics_url(host)?;

    let form = api::assistant::AssistTopicLookup {
        topic: topic.as_ref().into(),
        domain: domain.into(),
    };
    let form_bytes = serde_json::to_vec(&form)?;
    let req = surf::post(url.as_str()).body_bytes(&form_bytes).build();

    let mut res = async_std::task::block_on(do_http_signed_asym(req, id))
        .map_err(|e| anyhow!("{}", e))?;

    if res.status() != StatusCode::Ok {
        let mut body = async_std::task::block_on(res.body_string())
            .map_err(|e| anyhow!(e))?;
        if body.len() == 0 {
            body = "(empty)".into();
        }
        bail!("unexpected status {}\nbody: {}", res.status(), body);
    }

    let body =
        async_std::task::block_on(res.body_string()).map_err(|e| anyhow!(e))?;
    let json: Value = serde_json::from_str(&body)?;
    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or(anyhow!("malformed response `{}`", json))?;
    let items: Value = serde_json::from_str(content)?;
    let action_url = items["action_url"]
        .as_str()
        .ok_or(anyhow!("malformed content `{}`", items))?;
    let steps = serde_json::to_string_pretty(&items["steps"])?;

    use ansi_term::Color::{Green, Yellow};
    let output = format!(
        "{}\n{} {}\n{} {}",
        Green.bold().paint("INSTRUCTIONS"),
        Yellow.bold().paint("Visit:"),
        action_url,
        Yellow.bold().paint("Then:"),
        steps
    );

    Ok(output)
}


fn assistant_topics_url(endpoint: &str) -> Result<Url>
{
    let host = Url::parse(&endpoint)?;

    Ok(host.join("v2/assist/topics")?)
}


async fn do_http_simple(req: surf::Request) -> Result<Vec<u8>>
{
    let client = surf::client().with(surf::middleware::Logger::new());

    let mut res = client.send(req).await.map_err(|e| anyhow!("{}", e))?;

    let status = res.status();
    if status != 200 && status != 201 {
        bail!("server returned: {}", status);
    }

    if status == 200 {
        Ok(res.body_bytes().await.map_err(|e| anyhow!("{}", e))?)
    } else {
        Ok(Vec::default())
    }
}

#[allow(dead_code)]
async fn do_http_signed(req: surf::Request, id: &uno::Id) -> Result<Vec<u8>>
{
    let client = surf::client()
        .with(AuthClient { id: uno::Id(id.0) })
        .with(surf::middleware::Logger::new());

    let mut res = client.send(req).await.map_err(|e| anyhow!("{}", e))?;

    let status = res.status();

    if status != 200 && status != 201 {
        let msg = res.body_string().await.map_err(|e| anyhow!("{}", e))?;
        bail!("server returned: {}\n{}", status, msg);
    }
    if status == 200 {
        Ok(res.body_bytes().await.map_err(|e| anyhow!("{}", e))?)
    } else {
        Ok(Vec::default())
    }
}

async fn do_http_signed_vc(req: surf::Request, id: &uno::Id)
-> Result<Response>
{
    let client = surf::client()
        .with(AuthClient { id: uno::Id(id.0) })
        .with(surf::middleware::Logger::new());

    let mut res = client.send(req).await.map_err(|e| anyhow!("{}", e))?;

    let status = res.status();

    if status != 200 && status != 409 {
        let msg = res.body_string().await.map_err(|e| anyhow!("{}", e))?;
        bail!("server returned: {}\n{}", status, msg);
    }

    Ok(res)
}

async fn do_http_signed_asym(
    req: surf::Request,
    id: &uno::Id,
) -> Result<Response>
{
    let client = surf::client()
        .with(AsymAuthClient { id: uno::Id(id.0) })
        .with(surf::middleware::Logger::new());

    Ok(client.send(req).await.map_err(|e| anyhow!(e))?)
}


struct AuthClient
{
    id: uno::Id,
}

#[surf::utils::async_trait]
impl Middleware for AuthClient
{
    async fn handle(
        &self,
        mut req: Request,
        cli: Client,
        next: Next<'_>,
    ) -> surf::Result<Response>
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
                let _ = sign(&mut req_c, bytes, &www_auth, &self.id)?;
                res = next.run(req_c, cli).await?;
            }
        }
        Ok(res)
    }
}

/// Sign a request using the www-authenticate info specfied in the provided
/// www-authenticate header. Consume body and attach it to the request (the
/// body is required independent because the request signature contains the
/// hash of the body bytes, so it is up to the caller how to manage the body
/// bytes memory).
fn sign(
    req: &mut Request,
    body: Vec<u8>,
    header: &HeaderValues,
    id: &uno::Id,
) -> Result<()>
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
    let pow = alg
        .hash_password(cbytes, Some(alg_id), params, salt)
        .map_err(|_| anyhow!("hash generation failed"))?;
    let response = format!("{}${}", s64, pow.hash.unwrap());

    let kp: uno::KeyPair = KeyPair::from(id);
    let pub_bytes = pubkey_bytes_from_keypair(&kp);
    let pub64 = base64::encode_config(&pub_bytes, base64::STANDARD_NO_PAD);
    let sig = kp.sign(&response.as_bytes());
    let sig64 = base64::encode_config(sig.to_bytes(), base64::STANDARD_NO_PAD);

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

fn parse_www_auth(headers: &HeaderValues) -> Result<WwwAuthTemp>
{
    let mut map = HashMap::new();

    // tuned-digest-signature nonce=E2nl6WRukjQrm9pYcJB/LVwqGEZRU4ik+TM1NgvDSjk;algorithm=$argon2d$v=19$m=65536,t=3,p=8;actions=read
    let sym_tuned_re = regex::Regex::new(
        r"tuned-digest-signature nonce=([A-Za-z0-9/+]+=*);algorithm=(\$argon2d\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+);actions=([a-z,]+)",
    )
    .unwrap();

    for header in headers.iter() {
        match sym_tuned_re.captures(header.as_str()) {
            Some(caps) => {
                map.insert(
                    "nonce".to_string(),
                    caps.get(1).unwrap().as_str().to_string(),
                );

                map.insert(
                    "algorithm".to_string(),
                    caps.get(2).unwrap().as_str().to_string(),
                );

                map.insert(
                    "actions".to_string(),
                    caps.get(3).unwrap().as_str().to_string(),
                );

                return Ok(WwwAuthTemp { params: map });
            },
            None => {},
        }
    }

    bail!("invalid www-auth");
}


struct AsymAuthClient
{
    id: uno::Id,
}

#[surf::utils::async_trait]
impl Middleware for AsymAuthClient
{
    async fn handle(
        &self,
        mut req: Request,
        cli: Client,
        next: Next<'_>,
    ) -> surf::Result<Response>
    {
        let mut req_c = req.clone();
        // copy the request and body bytes in case we have to redo it
        let bytes = req.take_body().into_bytes().await?;
        req.set_body(&*bytes);
        // run the request
        let mut res = next.run(req, cli.clone()).await?;
        if let http_types::StatusCode::Unauthorized = res.status() {
            req_c.set_body(&*bytes);
            // if there's no header, skip sign + retry
            if let Some(www_auth) = res.header("www-authenticate") {
                let _ = blake3_sign(&mut req_c, &www_auth, &self.id)?;
                res = next.run(req_c, cli).await?;
            }
        }
        Ok(res)
    }
}

fn blake3_sign(
    req: &mut Request,
    header: &HeaderValues,
    id: &uno::Id,
) -> Result<()>
{
    let www_auth = parse_asym_www_auth(header)?;

    let n64 = www_auth.params["nonce"].as_str();
    let challenge = body_challenge(req, n64)?;

    let alg = www_auth.params["algorithm"].as_str();
    let cost: u8 = alg
        .split("$")
        .last()
        .ok_or_else(|| anyhow!("missing cost"))?
        .parse()?;

    let n = uno::prove_blake3_work(&challenge.as_bytes(), cost).unwrap();
    let response = format!("blake3${}${}", n, n64);

    let kp: KeyPair = KeyPair::from(id);
    let pub_bytes = pubkey_bytes_from_keypair(&kp);
    let pub64 = base64::encode_config(&pub_bytes, base64::STANDARD_NO_PAD);
    let sig = kp.sign(&response.as_bytes());
    let sig64 = base64::encode_config(sig.to_bytes(), base64::STANDARD_NO_PAD);

    let i = format!("identity={}", pub64);
    let n = format!("nonce={}", n64);
    let r = format!("response={}", response);
    let s = format!("signature={}", sig64);
    let auth = format!("asym-tuned-digest-signature {};{};{};{}", i, n, r, s);

    req.insert_header("authorization", auth);

    Ok(())
}

fn parse_asym_www_auth(headers: &HeaderValues) -> Result<WwwAuthTemp>
{
    let mut map = HashMap::new();

    let asym_tuned_re = regex::Regex::new(
       r"asym-tuned-digest-signature nonce=([A-Za-z0-9/+]+=*);algorithm=(blake3\$[0-9]+);actions=([a-z,]+)",
    ).unwrap();

    for header in headers.iter() {
        match asym_tuned_re.captures(header.as_str()) {
            Some(caps) => {
                map.insert(
                    "nonce".to_string(),
                    caps.get(1).unwrap().as_str().to_string(),
                );

                map.insert(
                    "algorithm".to_string(),
                    caps.get(2).unwrap().as_str().to_string(),
                );

                map.insert(
                    "actions".to_string(),
                    caps.get(3).unwrap().as_str().to_string(),
                );

                return Ok(WwwAuthTemp { params: map });
            },
            None => {},
        }
    }

    bail!("invalid auth-info");
}

fn body_challenge(req: &mut Request, n64: &str) -> Result<String>
{
    let body = req.take_body();
    let bbytes: Vec<u8> = async_std::task::block_on(body.into_bytes())
        .map_err(|_| anyhow!("body bytes failed"))?;
    let bhash = blake3::hash(&bbytes);
    let bhashb = bhash.as_bytes();
    let bhash_enc = base64::encode_config(bhashb, base64::STANDARD_NO_PAD);
    req.set_body(surf::Body::from_bytes(bbytes));

    let method = req.method();

    let path = req
        .url()
        .path_segments()
        .ok_or_else(|| anyhow!("missing path"))?
        .skip(2)
        .collect::<Vec<_>>()
        .join("/");

    let challenge = format!("{}:{}:/{}:{}", n64, method, path, bhash_enc);

    return Ok(challenge);
}


#[cfg(test)]
mod unit
{
    use super::*;

    use uno::{Id, KeyPair, Mu, Session};

    #[test]
    fn get_vault() {}

    #[test]
    fn put_vault() {}

    #[test]
    fn get_ssss() {}

    #[test]
    fn put_ssss() {}

    #[test]
    fn patch_ssss() {}

    #[test]
    fn url_from_key() -> Result<()>
    {
        let bytes64 = "XkjZ1zMeJqsrSkhgq2QqJXtDDM9hlnrF5HRFbcMuUzo";
        let bytes = base64::decode(bytes64)?;
        let id = Id::try_from(&*bytes)?;
        let pair = KeyPair::from(&id);
        let endpoint = "https://example.com";
        let actual = vault_url_from_key(endpoint, &pair)?;
        let expected = "https://example.com/v2/vaults/BOfVSES5eXi3HbbB0GIcmK35V57JyngUeDrnK_LJn5k";
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
        let expected = "https://example.com/v2/ssss/DMq6OqXqkDQWBVXkOXAL39A1xy-KYoxl0_Q7VnyEpjw";
        dbg!(&actual);
        assert_eq!(expected, actual.to_string());

        Ok(())
    }
}
