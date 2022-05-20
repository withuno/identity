//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::error;
use std::fmt;
use std::fmt::{Debug, Display};

pub mod store;
pub use store::Database;

pub mod magic_share;
pub mod mailbox;

use anyhow::bail;

pub mod auth;
use auth::UserId;

use std::future::Future;
use std::pin::Pin;

use json_patch::merge;

use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::Value;

use http_types::Method;
use tide::{Body, Error, Next, Request, Response, Result, StatusCode};

/// Enforce a global size limit on the body of requests
pub fn body_size_limit<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let bytes = req.body_bytes().await?;
        const ONE_MB: usize = 1024 * 1024;
        if bytes.len() > ONE_MB {
            Err(bad_request("body size limit 1 MB exceeded"))
        } else {
            req.set_body(bytes);
            Ok(next.run(req).await)
        }
    })
}

/// Short circuit the middleware chain if the request is not authorized.
pub fn signed_pow_auth<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let resp = match auth::check(&mut req).await {
            Ok(()) => next.run(req).await,
            Err(reason) => reason,
        };

        Ok(resp)
    })
}

/// On the way out, attach auth_info to all responses.
pub fn add_auth_info<'a, T>(
    req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let tok = req.state().tok.clone();
        let out = next.run(req).await;
        let resp = auth::add_info(out, tok).await;
        Ok(resp)
    })
}

/// Request state is used in the auth layer so declare it here.
#[derive(Clone, Debug)]
pub struct State<T>
where
    T: Database,
{
    pub db: T,
    pub tok: T,
}

impl<T> State<T>
where
    T: Database,
{
    pub fn new(db: T, tok: T) -> Self { Self { db, tok } }
}

#[derive(PartialEq, Debug)]
pub enum ApiError
{
    DecodeError(base64::DecodeError),
    BadRequest(String),
    NotFound,
    Unauthorized,
}

impl From<base64::DecodeError> for ApiError
{
    fn from(e: base64::DecodeError) -> Self { ApiError::DecodeError(e) }
}

impl error::Error for ApiError
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)>
    {
        match *self {
            ApiError::DecodeError(ref s) => Some(s),
            ApiError::BadRequest(_) => None,
            ApiError::NotFound => None,
            ApiError::Unauthorized => None,
        }
    }
}

impl fmt::Display for ApiError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            ApiError::DecodeError(ref e) => write!(f, "decode error: {}", e),
            ApiError::BadRequest(ref msg) => write!(f, "bad request: {}", msg),
            ApiError::NotFound => write!(f, "api error: not found"),
            ApiError::Unauthorized => write!(f, "api error: unauthorized"),
        }
    }
}

pub fn pubkey_from_b64(id: &str) -> anyhow::Result<uno::PublicKey, ApiError>
{
    let v = base64::decode(id)?;
    let pk = uno::PublicKey::from_bytes(&v);
    if pk.is_err() {
        return Err(ApiError::BadRequest("pubkey wrong length".to_string()));
    }
    Ok(pk.unwrap())
}

pub fn pubkey_from_url_b64(id: &str)
-> anyhow::Result<uno::PublicKey, ApiError>
{
    let v = base64::decode_config(id, base64::URL_SAFE)?;
    let pk = uno::PublicKey::from_bytes(&v);
    if pk.is_err() {
        return Err(ApiError::BadRequest("pubkey wrong length".to_string()));
    }
    Ok(pk.unwrap())
}

pub fn signature_from_b64(
    bytes: &str,
) -> anyhow::Result<uno::Signature, ApiError>
{
    let decoded_sig = base64::decode(bytes)?;

    uno::Signature::from_bytes(&decoded_sig)
        .map_err(|_| ApiError::BadRequest("bad signature".to_string()))
}

async fn health(_req: Request<()>) -> Result<Response>
{
    Ok(Response::new(StatusCode::NoContent))
}

// Make sure the mailbox in the url matches the public key that generated the
// signature on the request. Requires MailboxId middleware. Returns status 403
// forbidden if there is a mismatch.
//
fn check_mailbox_ownership<'a, T>(
    req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        if req.method() != Method::Post {
            let id = req.ext::<MailboxId>().unwrap();
            let target = pubkey_from_url_b64(&id.0).map_err(bad_request)?;
            let user = req.ext::<UserId>().unwrap().0;
            if target != user {
                return Err(forbidden("pubkey mismatch"));
            }
        }

        Ok(next.run(req).await)
    })
}

async fn delete_messages<T>(mut req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let body = req.body_bytes().await?;
    let db = &req.state().db.clone();
    let id = &req.ext::<MailboxId>().unwrap().0;

    let m: Vec<mailbox::MessageToDelete> = match serde_json::from_slice(&body) {
        Ok(ms) => ms,
        Err(_) => return Ok(StatusCode::BadRequest.into()),
    };
    mailbox::delete_messages(db, id, &m).await?;

    Ok(Response::builder(StatusCode::NoContent).build())
}

async fn post_mailbox<T>(mut req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let body = req.body_bytes().await?;

    let db = &req.state().db.clone();
    let id = &req.ext::<MailboxId>().unwrap().0;
    let signer = &req.ext::<UserId>().unwrap().0;

    let signerb64 = base64::encode(signer);

    let m: mailbox::MessageRequest = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(_) => return Ok(StatusCode::BadRequest.into()),
    };
    let message = mailbox::post_message(db, id, &signerb64, &m).await?;

    let r = serde_json::to_string(&message)?;

    Ok(Response::builder(StatusCode::Created).body(r).build())
}

async fn fetch_mailbox<T>(req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let id = &req.ext::<MailboxId>().unwrap().0;

    let mailbox = mailbox::get_messages(db, id).await?;

    let j = serde_json::to_string(&mailbox)?;

    Ok(Response::builder(StatusCode::Ok)
        .header("content-type", "application/json")
        .body(j)
        .build())
}

async fn fetch_share<T>(req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let id = &req.ext::<ShareId>().unwrap().0;

    let share = match magic_share::find_by_id(db, &id).await {
        Ok(v) => v,
        Err(e) => {
            println!("{:?}", e);
            return Err(server_err("error"));
        },
    };

    let j = serde_json::to_string(&share)?;
    Ok(Response::builder(StatusCode::Ok)
        .header("content-type", "application/json")
        .body(j)
        .build())
}

async fn store_share<T>(mut req: Request<State<T>>) -> Result<StatusCode>
where
    T: Database + 'static,
{
    let body = &req.body_bytes().await.map_err(server_err)?;
    let db = &req.state().db;

    let m = magic_share::new_from_json(&body).map_err(magic_share_err)?;

    magic_share::store_share(db, &m).await?;

    Ok(StatusCode::Created)
}

// Make sure the vault in the url matches the public key that generated the
// signature on the request. Requires VaultId middleware. Returns status 403
// forbidden if there is a mismatch.
//
fn check_vault_ownership<'a, T>(
    req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let id = req.ext::<VaultId>().unwrap();
        let target = pubkey_from_url_b64(&id.0).map_err(bad_request)?;
        let user = req.ext::<UserId>().unwrap().0;
        if target != user {
            return Err(forbidden("pubkey mismatch"));
        }
        Ok(next.run(req).await)
    })
}

async fn option_vault<T>(_req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let response = Response::builder(StatusCode::Ok)
        .body("ok")
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Headers",
            "WWW-Authenticate, Authentication-Info",
        )
        .build();

    Ok(response)
}

use vclock::VClock;

///
/// We need to store both the vault data and the version (vclock). Wrap them
/// together into one document so we don't need transactions.
#[derive(Serialize, Deserialize)]
struct Vault
{
    data: Vec<u8>,
    vclock: VClock<String>,
}

async fn fetch_vault<T>(req: Request<State<T>>) -> Result<Response>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;

    let vault_bytes = match db.get(&id).await {
        Ok(vb) => vb,
        Err(_) => {
            // check the v1 location, if found migrate the vault, if not 404
            let vb_old = db.get_version("v1", id).await.map_err(not_found)?;
            let vault =
                Vault { data: vb_old, vclock: VClock::<String>::default() };
            let vb_new = serde_json::to_vec(&vault).map_err(server_err)?;
            db.put(&id, &vb_new).await.map_err(server_err)?;

            db.get(&id).await.map_err(not_found)?
        },
    };

    let vault =
        serde_json::from_slice::<Vault>(&vault_bytes).map_err(server_err)?;

    let resp = Response::builder(StatusCode::Ok)
        .header("vclock", write_vclock(&vault.vclock).map_err(server_err)?)
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Headers",
            "WWW-Authenticate, Authentication-Info",
        )
        .body(Body::from_bytes(vault.data))
        .build();

    Ok(resp)
}

async fn store_vault<T>(mut req: Request<State<T>>) -> Result<Response>
where
    T: Database + 'static,
{
    let body = &req.body_bytes().await.map_err(server_err)?;
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;

    // The client is required to provide a vclock that progresses time forward
    // in the vault's reference frame. This ensures each client sees a
    // consistent vault before issuing its own writes. This is not a security
    // measure, a malicious client could deliberately choose to do bad things
    // like send an empty vault way in the future. Rather, this is a strategy
    // that enables clients to cooperate to avoid thrashing on the state of the
    // vault and potentially dropping data as a result. It also allows clients
    // to confirm whether their writes happened successfully.

    // The `vclock` header is required, always. If this is the first put, then
    // the client should provide an initial clock with its own id and the
    // counter initialized to 0.
    let vclock_new_str = match &req.header("vclock") {
        Some(v) => v.last().as_str(),
        None => {
            let resp = Response::builder(StatusCode::BadRequest)
                .body("missing vclock")
                .build();
            return Ok(resp);
        },
    };

    let vclock_new = parse_vclock(vclock_new_str).map_err(bad_request)?;

    // Now read the vault. If it exists, parse the vclock. If not, use an empty
    // vclock.

    let mut v_sto = Vault {
        data: Vec::<u8>::default(),
        vclock: VClock::<String>::default(),
    };

    if db.exists(&id).await.map_err(server_err)? {
        v_sto = db
            .get(&id)
            .await
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.into()))
            .map_err(server_err)?;
    }
    let vclock_cur = v_sto.vclock;

    // If the vclock the client provides is not a child of the current vclock,
    // reject the request.
    use std::cmp::Ordering;
    if vclock_new.partial_cmp(&vclock_cur) != Some(Ordering::Greater) {
        let data = serde_json::to_string(&v_sto.data).map_err(server_err)?;
        let resp = Response::builder(StatusCode::Conflict)
            .header("vclock", write_vclock(&vclock_cur).map_err(server_err)?)
            .body(format!(
                r#"{{"error": "causality violation", "vault": {}}}"#,
                data
            ))
            .build();
        return Ok(resp);
    }

    let vault = Vault { data: body.to_vec(), vclock: vclock_new };
    let vault_bytes = serde_json::to_vec(&vault).map_err(server_err)?;

    db.put(&id, &vault_bytes).await.map_err(server_err)?;

    // Read our own write...
    let read_bytes = db.get(&id).await.map_err(not_found)?;
    let v_read =
        serde_json::from_slice::<Vault>(&read_bytes).map_err(server_err)?;

    let resp = Response::builder(StatusCode::Ok)
        .header("vclock", write_vclock(&v_read.vclock).map_err(server_err)?)
        .body(Body::from_bytes(v_read.data))
        .build();

    Ok(resp)
}

/// Parse a vclock header into a VClock. A vclock is a list of tuples,
/// (key,count), so a map. Our keys are client ids.
///
///   client-id1=count,client-id2=count,client-id3=count
pub fn parse_vclock(
    vc_str: &str,
) -> std::result::Result<VClock<String>, anyhow::Error>
{
    // TODO: write a serde_rfc8941 crate. For now, manually parse.
    //
    let items = vc_str.trim().split(",");
    use std::collections::HashMap;
    let mut map = HashMap::<String, u64>::new(); // TODO: faster hasher
    for i in items {
        let kv: Vec<&str> = i.trim().splitn(2, "=").collect();
        if kv.len() != 2 {
            bail!("malformed vclock header");
        }
        let count = kv[1].parse()?;
        map.insert(kv[0].into(), count);
    }

    Ok(VClock::from(map))
}

pub fn write_vclock<K>(
    vc: &VClock<K>,
) -> std::result::Result<String, anyhow::Error>
where
    K: std::cmp::Eq,
    K: std::hash::Hash,
    K: serde::Serialize,
    K: Into<String>,
{
    // TODO: write a serde_rfc8941 crate. For now, manually print.
    //
    let value = serde_json::to_value(&vc)?;
    let clock = match value.get("c") {
        Some(Value::Object(ref m)) => m,
        _ => bail!("bad vclock structure"),
    };

    let mut out = String::new();
    for key in clock.keys() {
        let count = &clock[key];
        out.push_str(&format!("{}={}", String::from(key), count));
        out.push(',');
    }
    // remove the trailing ','
    if out.len() > 0 {
        out.remove(out.len() - 1);
    }

    Ok(out)
}

#[derive(Debug, PartialEq, Deserialize)]
struct ServiceQuery
{
    branch: String,
}

async fn fetch_service_list<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let list = db.get("services.json").await.map_err(not_found)?;
    Ok(list.into())
}

async fn fetch_service<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let name = req.param("name").map_err(bad_request)?;
    let query: Result<ServiceQuery> = req.query();
    let prefix = match query {
        Ok(ref q) => &q.branch,
        Err(_) => "main",
    };
    let path = format!("{}/{}", prefix, name);
    let service = db.get(&path).await.map_err(not_found)?;
    Ok(service.into())
}

struct SessionId(String);

fn session_id<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let p = req.param("id").map_err(bad_request)?;
        let sid = SessionId(String::from(p));
        req.set_ext(sid);
        Ok(next.run(req).await)
    })
}

async fn ssss_get<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let session = db.get(sid).await.map_err(not_found)?;

    Ok(Body::from_bytes(session))
}

async fn ssss_put<T>(mut req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let body = req.body_bytes().await?;

    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;

    db.put(sid, &body).await.map_err(server_err)?;

    let session = db.get(sid).await.map_err(not_found)?;
    Ok(Body::from_bytes(session))
}

async fn ssss_patch<T>(mut req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let body = req.body_bytes().await?;

    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;

    let json = db.get(sid).await.map_err(not_found)?;
    let mut doc = serde_json::from_slice::<Value>(&json).map_err(server_err)?;

    let body_json =
        serde_json::from_slice::<Value>(&body).map_err(bad_request)?;

    merge(&mut doc, &body_json);

    let data = serde_json::to_vec(&doc).map_err(server_err)?;
    db.put(sid, &data).await.map_err(server_err)?;

    let session = db.get(sid).await.map_err(not_found)?;
    Ok(Body::from_bytes(session))
}

async fn ssss_delete<T>(req: Request<State<T>>) -> Result<StatusCode>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let _ = db.del(sid).await.map_err(server_err)?;

    Ok(StatusCode::NoContent)
}

fn magic_share_err(e: magic_share::MagicShareError) -> Error
{
    //XXX: if DEBUG
    println!("{:?}", e);

    match e {
        magic_share::MagicShareError::Serde { source: _ } => {
            Error::from_str(StatusCode::BadRequest, "bad request")
        },
        magic_share::MagicShareError::Duplicate => {
            Error::from_str(StatusCode::Conflict, "duplicate entry")
        },
        magic_share::MagicShareError::Expired => {
            Error::from_str(StatusCode::NotFound, "not found")
        },
        magic_share::MagicShareError::Schema => {
            Error::from_str(StatusCode::BadRequest, "bad request")
        },
        magic_share::MagicShareError::NotFound => {
            Error::from_str(StatusCode::NotFound, "not found")
        },
        _ => Error::from_str(
            StatusCode::InternalServerError,
            "internal server error",
        ),
    }
}

fn bad_request<M>(msg: M) -> Error
where
    M: Display + Debug + Send + Sync + 'static,
{
    Error::from_str(StatusCode::BadRequest, msg)
}

fn not_found<M>(msg: M) -> Error
where
    M: Display + Debug + Send + Sync + 'static,
{
    Error::from_str(StatusCode::NotFound, msg)
}

fn server_err<M>(msg: M) -> Error
where
    M: Display + Debug + Send + Sync + 'static,
{
    Error::from_str(StatusCode::InternalServerError, msg)
}

#[allow(dead_code)]
fn unauthorized<M>(msg: M) -> Error
where
    M: Display + Debug + Send + Sync + 'static,
{
    Error::from_str(StatusCode::Unauthorized, msg)
}

fn forbidden<M>(msg: M) -> Error
where
    M: Display + Debug + Send + Sync + 'static,
{
    Error::from_str(StatusCode::Forbidden, msg)
}

struct VaultId(String);
struct MailboxId(String);
struct ShareId(String);

// Extract the MailboxId from the url parameter for conveniennce.
//
fn ensure_mailbox_id<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let p = req.param("id").map_err(bad_request)?;
        let mid = MailboxId(String::from(p));
        req.set_ext(mid);

        Ok(next.run(req).await)
    })
}

// Extract the VaultId from the url parameter for convenience.
//
fn ensure_vault_id<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let p = req.param("id").map_err(bad_request)?;
        let vid = VaultId(String::from(p));
        req.set_ext(vid);
        Ok(next.run(req).await)
    })
}

// Extract the ShareId from the url parameter for convenience.
//
fn ensure_share_id<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let p = req.param("id").map_err(bad_request)?;
        let vid = ShareId(String::from(p));
        req.set_ext(vid);
        Ok(next.run(req).await)
    })
}

pub fn build_routes<T>(
    token_db: T,
    vault_db: T,
    service_db: T,
    session_db: T,
    mailbox_db: T,
    share_db: T,
) -> anyhow::Result<tide::Server<()>>
where
    T: Database + 'static,
{
    // XXX: this is used in the development environment and not anywhere else.
    use http_types::headers::HeaderValue;
    use tide::security::{CorsMiddleware, Origin};

    let cors = CorsMiddleware::new()
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);
    // XXX: end development environment.

    let mut api = tide::new();
    api.at("health").get(health);

    {
        let mut vaults =
            tide::with_state(State::new(vault_db, token_db.clone()));
        vaults
            .at(":id")
            .with(body_size_limit)
            .with(add_auth_info)
            .with(signed_pow_auth)
            .with(ensure_vault_id)
            .with(check_vault_ownership)
            .options(option_vault)
            .get(fetch_vault)
            .put(store_vault);
        api.at("vaults").nest(vaults);
    }

    {
        let mut services =
            tide::with_state(State::new(service_db.clone(), token_db.clone()));
        services
            .at(":name")
            .with(body_size_limit)
            .with(add_auth_info)
            .with(signed_pow_auth)
            .get(fetch_service);
        api.at("services").nest(services);
    }

    {
        let mut service_list =
            tide::with_state(State::new(service_db.clone(), token_db.clone()));

        // putting a '/' here does not work,
        // so this is kind of a hack because we'll only have one file for now.
        service_list
            .at("services.json")
            .with(body_size_limit)
            .with(add_auth_info)
            .with(signed_pow_auth)
            .get(fetch_service_list);

        api.at("service_list").nest(service_list);
    }

    {
        // Shamir's Secret Sharing Session
        let mut ssss =
            tide::with_state(State::new(session_db, token_db.clone()));
        ssss.at(":id")
            .with(body_size_limit)
            .with(session_id)
            .get(ssss_get)
            .put(ssss_put)
            .patch(ssss_patch)
            .delete(ssss_delete);
        api.at("ssss").nest(ssss);
    }

    {
        let mut mailboxes =
            tide::with_state(State::new(mailbox_db, token_db.clone()));
        mailboxes
            .at(":id")
            .with(body_size_limit)
            .with(add_auth_info)
            .with(signed_pow_auth)
            .with(ensure_mailbox_id)
            .with(check_mailbox_ownership)
            .get(fetch_mailbox)
            .post(post_mailbox)
            .delete(delete_messages);
        api.at("mailboxes").nest(mailboxes);
    }

    {
        let mut shares =
            tide::with_state(State::new(share_db.clone(), token_db.clone()));
        shares
            .at(":id")
            .with(cors)
            .with(ensure_share_id)
            .get(fetch_share)
            .post(store_share);
        api.at("shares").nest(shares);
    }

    Ok(api)
}
