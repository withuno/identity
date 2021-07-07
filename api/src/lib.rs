//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;
use std::error;
use std::fmt;
use std::fmt::{Debug, Display};

pub mod store;
pub use crate::store::Database;

pub mod auth;
use auth::{BodyBytes, UserId};

use std::future::Future;
use std::pin::Pin;

use json_patch::merge;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use http_types::Method;
use tide::{Body, Error, Next, Request, Response, Result, StatusCode};

/// Short circuit the middleware chain if the request is not authorized.
///
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
///
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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct MailboxMessage {
    pub id: u64,
    pub sender: String,
    pub message: Vec<u8>,
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
    pub fn new(db: T, tok: T) -> Self {
        Self { db, tok }
    }
}

#[derive(PartialEq, Debug)]
pub enum ApiError {
    DecodeError(base64::DecodeError),
    BadRequest(String),
    NotFound,
    Unauthorized,
}

impl From<base64::DecodeError> for ApiError {
    fn from(e: base64::DecodeError) -> Self {
        ApiError::DecodeError(e)
    }
}

impl error::Error for ApiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            ApiError::DecodeError(ref s) => Some(s),
            ApiError::BadRequest(_) => None,
            ApiError::NotFound => None,
            ApiError::Unauthorized => None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ApiError::DecodeError(ref e) => write!(f, "decode error: {}", e),
            ApiError::BadRequest(ref msg) => write!(f, "bad request: {}", msg),
            ApiError::NotFound => write!(f, "api error: not found"),
            ApiError::Unauthorized => write!(f, "api error: unauthorized"),
        }
    }
}

pub fn pubkey_from_b64(id: &str) -> anyhow::Result<uno::PublicKey, ApiError> {
    let v = base64::decode(id)?;
    let pk = uno::PublicKey::from_bytes(&v);
    if pk.is_err() {
        return Err(ApiError::BadRequest("pubkey wrong length".to_string()));
    }
    Ok(pk.unwrap())
}

pub fn pubkey_from_url_b64(
    id: &str,
) -> anyhow::Result<uno::PublicKey, ApiError> {
    let v = base64::decode_config(id, base64::URL_SAFE)?;
    let pk = uno::PublicKey::from_bytes(&v);
    if pk.is_err() {
        return Err(ApiError::BadRequest("pubkey wrong length".to_string()));
    }
    Ok(pk.unwrap())
}

pub fn signature_from_b64(
    bytes: &str,
) -> anyhow::Result<uno::Signature, ApiError> {
    let decoded_sig = base64::decode(bytes)?;
    let sig_array = decoded_sig.try_into();
    if sig_array.is_err() {
        return Err(ApiError::BadRequest(
            "signature wrong length".to_string(),
        ));
    }

    Ok(uno::Signature::new(sig_array.unwrap()))
}

async fn health(_req: Request<()>) -> Result<Response> {
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

async fn delete_message<T>(req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    Ok(Response::builder(204).build())
}

async fn post_mailbox<T>(mut req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let id = &req.ext::<MailboxId>().unwrap().0;
    let signer = &req.ext::<UserId>().unwrap().0;

    let signerb64 = base64::encode_config(signer, base64::URL_SAFE_NO_PAD);
    // Make sure you do not put a preceding slash here since it will
    // replace the tmp file in the filestore version.
    // https://doc.rust-lang.org/std/path/struct.PathBuf.html#method.push
    // (XXX: what does the trailing slash do if you put it here?)
    let prefix = format!("{}/{}", id, signerb64);

    let db = req.state().db.clone();
    let body = req.body_bytes().await?;

    // LOCK
    let existing = db.list(&prefix).await?;
    let ids: Vec<u64> = existing
        .iter()
        .map(|m| {
            let id = m.split("/").last().unwrap();
            id.parse::<u64>().unwrap()
        })
        .collect();

    let next_id = match ids.iter().max() {
        Some(max) => max + 1,
        None => 1,
    };

    let dest = format!("{}/{}", prefix, next_id);
    db.put(&dest, &body).await?;
    // UNLOCK

    let created = serde_json::to_string(&vec![MailboxMessage {
        id: next_id,
        sender: signerb64,
        message: body,
    }])?;

    Ok(Response::builder(201).body(created).build())
}

async fn fetch_mailbox<T>(req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let id = &req.ext::<MailboxId>().unwrap().0;

    let mailbox = db.list(id).await?;

    let messages: Vec<MailboxMessage> = mailbox
        .iter()
        .filter_map(|m| {
            let mut s: Vec<&str> = m.split("/").collect();

            let id = match s.pop() {
                Some(v) => v,
                None => return None,
            };

            let sender = match s.pop() {
                Some(v) => v,
                None => return None,
            };

            let int_id = match id.parse::<u64>() {
                Ok(v) => v,
                Err(_) => return None,
            };

            let msg = match async_std::task::block_on(db.get(m)) {
                Ok(v) => v,
                Err(_) => return None,
            };

            Some(MailboxMessage {
                id: int_id,
                sender: sender.to_string(),
                message: msg,
            })
        })
        .collect();

    let j = serde_json::to_string(&messages)?;

    Ok(Response::builder(200)
        .header("content-type", "application/json")
        .body(j)
        .build())
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
    let response = Response::builder(200)
        .body("ok")
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Headers",
            "WWW-Authenticate, Authentication-Info",
        )
        .build();

    Ok(response)
}

async fn fetch_vault<T>(req: Request<State<T>>) -> Result
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;

    let vault = db.get(id).await.map_err(not_found)?;

    let response = Response::builder(200)
        .body(Body::from_bytes(vault))
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Headers",
            "WWW-Authenticate, Authentication-Info",
        )
        .build();

    Ok(response)
}

async fn store_vault<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;
    let body = &req.ext::<BodyBytes>().unwrap().0;

    db.put(id, &body).await.map_err(server_err)?;
    let vault = db.get(id).await.map_err(not_found)?;

    Ok(Body::from_bytes(vault))
}

async fn fetch_service<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + 'static,
{
    let db = &req.state().db;
    let name = req.param("name").map_err(bad_request)?;
    let service = db.get(name).await.map_err(not_found)?;
    Ok(Body::from_bytes(service))
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
    let mut doc =
        serde_json::from_slice::<Value>(&json).map_err(server_err)?;

    let body_json =
        serde_json::from_slice::<Value>(&body).map_err(bad_request)?;

    merge(&mut doc, &body_json);

    let data = serde_json::to_vec(&doc).map_err(server_err)?;
    db.put(sid, &data).await.map_err(server_err)?;

    let session = db.get(sid).await.map_err(not_found)?;
    Ok(Body::from_bytes(session))
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

// Extract the VaultId from the url parameter for conveniennce.
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

pub fn build_api<T>(
    token_db: T,
    vault_db: T,
    service_db: T,
    session_db: T,
    mailbox_db: T,
) -> anyhow::Result<tide::Server<()>>
where
    T: Database + 'static,
{
    let mut api = tide::new();
    api.at("health").get(health);

    {
        let mut vaults =
            tide::with_state(State::new(vault_db, token_db.clone()));
        vaults
            .at(":id")
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
            tide::with_state(State::new(service_db, token_db.clone()));
        services
            .at(":name")
            .with(add_auth_info)
            .with(signed_pow_auth)
            .get(fetch_service);
        api.at("services").nest(services);
    }

    {
        // Shamir's Secret Sharing Session
        let mut ssss =
            tide::with_state(State::new(session_db, token_db.clone()));
        ssss.at(":id")
            .with(session_id)
            .get(ssss_get)
            .put(ssss_put)
            .patch(ssss_patch);
        api.at("ssss").nest(ssss);
    }

    {
        let mut mailboxes =
            tide::with_state(State::new(mailbox_db.clone(), token_db.clone()));
        mailboxes
            .at(":id")
            .with(add_auth_info)
            .with(signed_pow_auth)
            .with(ensure_mailbox_id)
            .with(check_mailbox_ownership)
            .get(fetch_mailbox)
            .post(post_mailbox)
            .nest({
                let mut messages = tide::with_state(State::new(
                    mailbox_db.clone(),
                    token_db.clone(),
                ));
                messages
                    .at("/:sender_id/:message_id")
                    .delete(delete_message);

                messages
            });
        api.at("mailboxes").nest(mailboxes);
    }

    Ok(api)
}
