//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::env;
use std::error;
use std::fmt;
use std::fmt::{Debug, Display};

pub mod store;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
pub use store::Database;

pub mod magic_share;
pub mod mailbox;

pub mod verify_token;

use anyhow::anyhow;
use anyhow::bail;

pub mod auth;
use auth::UserId;

use std::future::Future;
use std::pin::Pin;

use json_patch::merge;

use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::{json, Value};

use chrono::{Duration, Utc};

use http_types::Method;
use tide::{Body, Error, Next, Request, Response, Result, StatusCode};

use uno::PUBLIC_KEY_LENGTH;

mod twilio;

pub mod assistant;

mod brandfetch;

/// Enforce a global size limit on the body of requests
///
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

pub fn pubkey_from_bytes(
    vec: Vec<u8>,
) -> anyhow::Result<uno::PublicKey, ApiError>
{
    let pk_bytes = match vec[0..PUBLIC_KEY_LENGTH].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(ApiError::BadRequest(
                "pubkey wrong length".to_string(),
            ));
        },
    };
    let pk = match uno::PublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return Err(ApiError::BadRequest(
                "pubkey decompression".to_string(),
            ));
        },
    };

    Ok(pk)
}

pub fn pubkey_from_b64(id: &str) -> anyhow::Result<uno::PublicKey, ApiError>
{
    let v = base64::decode(id)?;

    Ok(pubkey_from_bytes(v)?)
}

pub fn pubkey_from_url_b64(id: &str)
-> anyhow::Result<uno::PublicKey, ApiError>
{
    let v = base64::decode_config(id, base64::URL_SAFE)?;

    Ok(pubkey_from_bytes(v)?)
}

pub fn signature_from_b64(
    bytes: &str,
) -> anyhow::Result<uno::Signature, ApiError>
{
    let decoded_sig = base64::decode(bytes)?;
    use uno::SIGNATURE_LENGTH;
    let sig_bytes = match decoded_sig[0..SIGNATURE_LENGTH].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(ApiError::BadRequest(
                "signature wrong length".to_string(),
            ));
        },
    };

    Ok(uno::Signature::from_bytes(&sig_bytes))
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
    T: Database,
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
    T: Database,
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
    T: Database,
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
    T: Database,
{
    let db = &req.state().db;
    let id = &req.ext::<ShareId>().unwrap().0;

    let share = match magic_share::find_by_id(db, &id).await {
        Ok(v) => v,
        Err(e) => {
            tide::log::info!("fetch_share/find_by_id {:?}", &e);
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
    T: Database,
{
    let body = &req.body_bytes().await.map_err(server_err)?;
    let db = &req.state().db;

    let m = magic_share::new_from_json(&body).map_err(|e| {
        tide::log::info!("store_share/new_from_json {:?}", &e);
        magic_share_err(e)
    })?;

    magic_share::store_share(db, &m).await?;

    Ok(StatusCode::Created)
}

async fn verify_verification_token<T>(
    mut req: Request<State<T>>,
) -> Result<StatusCode>
where
    T: Database,
{
    #[derive(Deserialize)]
    struct VerifyVerifyBody
    {
        secret: String,
    }

    let body: VerifyVerifyBody = req.body_json().await.map_err(bad_request)?;

    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;
    // NOTE: this ID is not bound to any signature on the request. The security
    // of this request depends on knowledge of the shared secret emailed to the
    // recipient. We may upgrade this in the future.
    //
    // If the user specifies some other vault/user ID in the URL path, then the
    // request will fail because no pending entry would be present, and if it
    // were, the secrets would have to match, which is statistically improbable.

    match verify_token::verify(db, id, &body.secret).await {
        Ok(_) => Ok(StatusCode::Ok),
        Err(verify_token::VerifyTokenError::Expired) => {
            Err(Error::from_str(StatusCode::Gone, "expired"))
        },
        Err(verify_token::VerifyTokenError::Secret) => {
            Err(Error::from_str(StatusCode::Forbidden, "forbidden"))
        },
        Err(verify_token::VerifyTokenError::NotFound) => {
            Err(Error::from_str(StatusCode::NotFound, "not found"))
        },
        Err(err) => {
            eprintln!("verify_verification_token: {}", err);
            Err(server_err("internal server error"))
        },
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetVerificationStatusResponse
{
    pub status: String,
    pub email: Option<String>,
    pub previous_status: Option<GetVerificationStatusPrevious>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetVerificationStatusPrevious
{
    pub status: String,
    pub email: Option<String>,
}

async fn get_verification_status<T>(req: Request<State<T>>) -> Result
where
    T: Database,
{
    let db = &req.state().db;

    let uid = &req.ext::<UserId>().unwrap().0;
    let user_b64url =
        base64::encode_config(uid.as_bytes(), base64::URL_SAFE_NO_PAD);

    let response = Response::builder(StatusCode::Ok)
        .header("content-type", "application/json");

    use verify_token::VerificationStatus;
    let body = match verify_token::get(db, &user_b64url).await {
        Ok(VerificationStatus::Verified(email)) => {
            GetVerificationStatusResponse {
                status: "verified".into(),
                email: Some(email),
                previous_status: None,
            }
        },
        Ok(VerificationStatus::Pending(email, previous)) => {
            let previous_status = match previous {
                PreviousStatus::Verified(previous_email) => {
                    GetVerificationStatusPrevious {
                        status: "verified".into(),
                        email: Some(previous_email),
                    }
                },
                PreviousStatus::Unverified => GetVerificationStatusPrevious {
                    status: "unverified".into(),
                    email: None,
                },
            };

            GetVerificationStatusResponse {
                status: "pending".into(),
                email: Some(email),
                previous_status: Some(previous_status),
            }
        },
        Ok(VerificationStatus::Unverified) => GetVerificationStatusResponse {
            status: "unverified".into(),
            email: None,
            previous_status: None,
        },
        Err(e) => return Err(server_err(e)),
    };

    let body_bytes = serde_json::to_vec(&body).map_err(server_err)?;

    Ok(response.body(body_bytes).build())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetVerificationByEmailForm
{
    pub email: String,
    pub include_pending: Option<bool>,
}

async fn get_verification_status_by_email<T>(
    mut req: Request<State<T>>,
) -> Result
where
    T: Database,
{
    let body_bytes = req.body_bytes().await.map_err(server_err)?;
    let form: GetVerificationByEmailForm =
        serde_json::from_slice(&body_bytes).map_err(bad_request)?;

    let db = &req.state().db;

    let response = Response::builder(StatusCode::Ok)
        .header("content-type", "application/json");

    let result =
        verify_token::get_by_email(db, &form.email, form.include_pending)
            .await
            .map_err(server_err)?;

    Ok(response.body(json!(result).to_string()).build())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyCreateForm
{
    pub analytics_id: String,
    pub email: String,
}

async fn create_verification_token<T>(
    mut req: Request<State<T>>,
) -> Result<StatusCode>
where
    T: Database,
{
    let body: VerifyCreateForm = req.body_json().await.map_err(bad_request)?;

    let db = &req.state().db;

    let uid = &req.ext::<UserId>().unwrap().0;
    let uid_b64url =
        base64::encode_config(uid.as_bytes(), base64::URL_SAFE_NO_PAD);

    let result = verify_token::create(
        db,
        &uid_b64url,
        &body.analytics_id,
        &body.email,
        Utc::now() + Duration::hours(48),
    )
    .await;

    let unverified = match result {
        Ok(v) => v,
        Err(verify_token::VerifyTokenError::Done) => {
            return Err(Error::from_str(StatusCode::Conflict, "done"));
        },
        Err(_e) => {
            return Err(server_err("internal server error"));
        },
    };

    let _ = possibly_email_link(&uid_b64url, unverified)
        .await
        .map_err(server_err)?;

    // don't care if this fails and shouldn't block hot path
    async_std::task::spawn(publish_new_user(
        body.email,
        req.header("User-Agent")
            .map(http_types::headers::HeaderValues::to_string),
    ));

    Ok(StatusCode::Created)
}

async fn publish_new_user(
    email: String,
    agent: Option<String>,
) -> anyhow::Result<()>
{
    let url: surf::Url =
        env::var("SIGNUP_PUBLISH_URL").map(|s| s.parse())??;

    use user_agent_parser::UserAgentParser;
    let ua_parser = match UserAgentParser::from_path("./res/regexes.yaml") {
        Ok(p) => p,
        Err(_) => UserAgentParser::from_path("/usr/local/lib/api/regexes.yaml")
            .map_err(|e| {
                tide::log::error!("ua_parser init");
                e
            })?,
    };

    let agent_str = &agent.as_deref().unwrap_or("unknown");
    let product = ua_parser.parse_product(agent_str);
    let os = ua_parser.parse_os(agent_str);
    let device = ua_parser.parse_device(agent_str);

    let class =
        if agent_str.contains("Mozilla") { "browser" } else { "native" };

    let message = indoc::formatdoc! {"
        **New User Signup**
        environment: `{}`
        email: `{}`
        device: `{} {}`
        platform: `{} ({}.{}.{}) [{}]`
        os: `{} ({}.{}.{})`
        ",
        env::var("PUBLIC_URL").as_deref().unwrap_or("local"),
        email,
        device.brand.as_deref().unwrap_or("unknown"),
        device.name.as_deref().unwrap_or("unknown"),
        product.name.as_deref().unwrap_or("unknown"),
        product.major.as_deref().unwrap_or("0"),
        product.minor.as_deref().unwrap_or("0"),
        product.patch.as_deref().unwrap_or("0"),
        class,
        os.name.as_deref().unwrap_or("unknown"),
        os.major.as_deref().unwrap_or("0"),
        os.minor.as_deref().unwrap_or("0"),
        os.patch.as_deref().unwrap_or("0"),
    };

    let _ = surf::post(url)
        .body_json(&json!({ "content": message }))
        .map_err(|e| anyhow!(e))?
        .await
        .map(|r| {
            if r.status() != StatusCode::NoContent {
                tide::log::warn!("Error posting new user to Discord");
            }
        });

    Ok(())
}


async fn possibly_email_link(
    user_id: &str,
    token: uno::UnverifiedToken,
) -> Result<StatusCode>
{
    if std::env::var("VERIFY_EMAIL_DOMAIN").is_err()
        || std::env::var("CUSTOMER_IO_API_KEY").is_err()
        || std::env::var("CUSTOMER_IO_API_ENDPOINT").is_err()
        || std::env::var("CUSTOMER_IO_MESSAGE_ID").is_err()
    {
        return Ok(StatusCode::Created);
    }

    let query = format!("{}::{}", token.secret, user_id);
    let encoded_query = base64::encode_config(query, base64::URL_SAFE_NO_PAD);

    let base_url = std::env::var("VERIFY_EMAIL_DOMAIN").map_err(server_err)?;
    let verify_link = format!("{}?s={}", base_url, encoded_query);

    let api_key = std::env::var("CUSTOMER_IO_API_KEY").map_err(server_err)?;
    let api_endpoint =
        std::env::var("CUSTOMER_IO_API_ENDPOINT").map_err(server_err)?;
    let message_id =
        std::env::var("CUSTOMER_IO_MESSAGE_ID").map_err(server_err)?;

    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct MessageData
    {
        emailConfirmationURL: String,
        customer_email: String,
    }

    #[derive(Serialize)]
    struct Identifiers
    {
        id: String,
    }

    #[derive(Serialize)]
    struct Body
    {
        to: String,
        transactional_message_id: String,
        message_data: MessageData,
        identifiers: Identifiers,
    }

    let body = Body {
        to: token.email.clone(),
        transactional_message_id: message_id,
        message_data: MessageData {
            emailConfirmationURL: verify_link,
            customer_email: token.email,
        },
        identifiers: Identifiers { id: token.analytics_id },
    };

    let req = reqwest::blocking::Client::new()
        .post(api_endpoint)
        .json(&body)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", api_key));

    req.send().map_err(|e| {
        println!("{:?}", e);
        server_err(e)
    })?;

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

async fn option_ok<T>(_req: Request<State<T>>) -> Result
where
    T: Database,
{
    Ok(Response::builder(StatusCode::Ok).build())
}

async fn option_vault<T>(_req: Request<State<T>>) -> Result
where
    T: Database,
{
    let response = Response::builder(StatusCode::Ok)
        .body("ok")
        .header("Access-Control-Allow-Origin", "localhost:*")
        .header(
            "Access-Control-Allow-Headers",
            "WWW-Authenticate, Authentication-Info, Content-Type",
        )
        .header("Access-Control-Allow-Methods", "PUT")
        .build();

    Ok(response)
}

use vclock::VClock;

use crate::verify_token::PreviousStatus;

///
/// We need to store both the vault data and the version (vclock). Wrap them
/// together into one document so we don't need transactions.
///
#[derive(Serialize, Deserialize)]
struct Vault
{
    data: Vec<u8>,
    vclock: VClock<String>,
}

async fn fetch_vault<T>(req: Request<State<T>>) -> Result<Response>
where
    T: Database,
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
            db.del_version("v1", id).await.map_err(server_err)?;

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
    T: Database,
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

    if vault.data.len() == 0 {
        let res = Response::builder(StatusCode::BadRequest)
            .body("you probably didn't mean to put an empty body")
            .build();
        return Ok(res);
    }

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
///
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

async fn delete_vault<T>(req: Request<State<T>>) -> Result<Response>
where
    T: Database,
{
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;

    db.del(&id).await.map_err(server_err)?;

    Ok(Response::new(StatusCode::NoContent))
}

#[derive(Debug, PartialEq, Deserialize)]
struct ServiceQuery
{
    branch: String,
}

async fn fetch_service_list<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database,
{
    let db = &req.state().db;
    let list = db.get("services.json").await.map_err(not_found)?;
    Ok(list.into())
}

async fn fetch_service<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database,
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
    T: Database,
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let session = db.get(sid).await.map_err(not_found)?;

    Ok(Body::from_bytes(session))
}

async fn ssss_put<T>(mut req: Request<State<T>>) -> Result<Body>
where
    T: Database,
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
    T: Database,
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
    T: Database,
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let _ = db.del(sid).await.map_err(server_err)?;

    Ok(StatusCode::NoContent)
}

fn magic_share_err(e: magic_share::MagicShareError) -> Error
{
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

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryEntryCreate
{
    pub phone: String,
    pub country: String,
    pub signing_key: String,
    pub encryption_key: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DirectoryEntry
{
    pub signing_key: String,
    pub encryption_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryEntryInternal
{
    pub entry: DirectoryEntry,
    pub phone: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PendingItem
{
    pub sid: String,
    pub user: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LookupItem
{
    pub cid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LookupQuery
{
    pub country: String,
    pub phone_numbers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LookupResult
{
    pub cids: Vec<LookupItemClientSuccess>,
    pub errors: Vec<LookupItemClientError>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LookupItemClientSuccess
{
    pub phone_number: String,
    pub cid: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LookupItemClientError
{
    pub phone_number: String,
    pub cause: String,
}

async fn post_directory_entry<T>(mut req: Request<State<T>>) -> Result<Response>
where
    T: Database,
{
    let entry_bytes = req.body_bytes().await.map_err(server_err)?;

    let db = &req.state().db;
    let uid = &req.ext::<UserId>().unwrap().0;
    let user_b64 = base64::encode(uid.as_bytes());

    let entry: DirectoryEntryCreate =
        serde_json::from_slice(&entry_bytes).map_err(bad_request)?;

    let validated_phone = validate_phone(&entry.phone, &entry.country).await?;
    let pending_key = format!("pending/{}", validated_phone);

    let start_verification = || {
        let phone = validated_phone.clone();
        let user_id = user_b64.clone();
        let p_key = pending_key.clone();

        async move {
            let session_id = match verify_phone_start(&phone.clone()).await {
                Ok(s) => s,
                Err(e) => {
                    let ise = StatusCode::InternalServerError;
                    return Ok(Response::builder(ise)
                        .body(format!("cause: {}", e))
                        .build());
                },
            };

            let pending_item = PendingItem { sid: session_id, user: user_id };
            let pending_item_bytes = serde_json::to_vec(&pending_item)?;
            db.put(p_key, &pending_item_bytes).await.map_err(server_err)?;

            // The payment required is a verification code.
            let response = Response::builder(StatusCode::PaymentRequired)
                .body(json!({"cause": "verification.needed"}))
                .build();

            Ok::<tide::Response, tide::Error>(response)
        }
    };

    let accept_entry = || {
        let phone = validated_phone.clone();
        let user_id = user_b64.clone();
        let p_key = pending_key.clone();

        async move {
            let cid = cid_from_phone(&phone);
            let lookup_key = format!("lookup/{}", phone);

            let lookup_exists =
                db.exists(&lookup_key).await.map_err(server_err)?;
            if lookup_exists {
                let old_bytes =
                    db.get(&lookup_key).await.map_err(server_err)?;
                let old_item: LookupItem =
                    serde_json::from_slice(&old_bytes).map_err(server_err)?;
                let old_key = format!("entries/{}", old_item.cid);
                db.del(&old_key).await.map_err(server_err)?;
                db.del(&lookup_key).await.map_err(server_err)?;
            }

            let lookup_item = LookupItem { cid: cid.clone() };
            let lookup_bytes =
                serde_json::to_vec(&lookup_item).map_err(server_err)?;

            db.put(&lookup_key, &lookup_bytes).await.map_err(server_err)?;

            let entry_key = format!("entries/{}", cid);
            let entry_value = DirectoryEntryInternal {
                phone,
                entry: DirectoryEntry {
                    signing_key: user_id,
                    encryption_key: entry.encryption_key,
                },
            };

            let entry_bytes =
                serde_json::to_vec(&entry_value).map_err(server_err)?;

            db.put(&entry_key, &entry_bytes).await.map_err(server_err)?;
            db.del(p_key).await.map_err(server_err)?;

            let response = Response::builder(StatusCode::Created)
                .header("location", cid)
                .build();

            Ok::<tide::Response, tide::Error>(response)
        }
    };

    if db.exists(&pending_key).await.map_err(server_err)? {
        //
        // If pending data exists, check if the session has been verified, and
        // if so, allow the entry to be posted.
        //
        let pending_bytes = db.get(&pending_key).await.map_err(server_err)?;
        let pending: PendingItem =
            serde_json::from_slice(&pending_bytes).map_err(server_err)?;

        if user_b64 != pending.user {
            // The user making the request is not the user who initiated the
            // previous one. Cancel the pending request and start a new one.
            return Ok(start_verification().await?);
        }
        //
        // else: The user making this request matches the user that initiated
        // the verification in the first place. Check if they provided a code
        // this time and verify the status of the code, allowing the POST to
        // proceed if the verification code provided by the client is correct.
        //

        // expose the internal error here for now (will be twilio error)
        let status = match verify_check_status(&pending.sid).await {
            Ok(s) => s,
            Err(e) => {
                return Ok(Response::builder(StatusCode::InternalServerError)
                    .body(format!("cause: {}", e))
                    .build());
            },
        };

        match status.as_str() {
            //
            // Seems unlikely this could happen before verifying the code, but
            // if it does we can accept the entry. Maybe the user is retrying
            // after a previous error.
            "approved" => return Ok(accept_entry().await?),
            //
            // Expected, move along.
            "pending" => {},
            //
            // If the verification session is canceled at this point then
            // we need to send a new code regardless of whether the user
            // provided a (now old) one or not.
            "canceled" => return Ok(start_verification().await?),
            //
            // Otherwise bail.
            _ => return Err(server_err("unknown status")),
        }

        // Now actually verify the code.
        // 1. Get the code from the header
        let code = match req.header("verification") {
            Some(values) => values.last().as_str(),
            None => {
                // If the client didn't provide a code, this would normally be
                // a BadRequest. But it is unlikely the client would behave
                // incorrectly here. Instead, simply restart the verification
                // session. This allows the client to request the code be
                // resent while the current pending session is still active.
                //
                // let response = Response::builder(StatusCode::BadRequest)
                //    .body(json!({"cause": "missing.verification"}))
                //    .build();
                //
                // TODO: perhaps "retry_verification" instead of start
                return Ok(start_verification().await?);
            },
        };
        // 2. Verify the code.
        let verify_result =
            verify_code_submit(&validated_phone, code, &pending.sid).await;

        // expose the internal error here for now (will be twilio error)
        let status = match verify_result {
            Ok(s) => s,
            Err(e) => {
                return Ok(Response::builder(StatusCode::InternalServerError)
                    .body(format!("cause: {}", e))
                    .build());
            },
        };

        match status.as_str() {
            //
            // 3. Accept the entry.
            "approved" => return Ok(accept_entry().await?),
            //
            // The provided code was likely not correct. Don't resend the code
            // automatically here. Just respond that payment is still required
            // so the client can try again by asking the user for the code.
            // If the client wants to indicate that the code should be re-sent
            // then it can elect to send a post without the code header.
            "pending" => {
                let response = Response::builder(StatusCode::PaymentRequired)
                    .body(json!({"cause": "verification.needed"}))
                    .build();

                return Ok(response);
            },
            //
            // We already checked for "canceled" above, but if the session
            // happened to expire or something while this flow is in flight
            // then we handle it here by restarting it.
            "canceled" => return Ok(start_verification().await?),
            //
            // Otherwise bail.
            _ => return Err(server_err("unknown status")),
        }
    } else {
        //
        // If there is no pending verification, create one.
        //
        return Ok(start_verification().await?);
    }
}

async fn validate_phone(phone: &str, country: &str) -> Result<String>
{
    let validated_phone = match cfg!(all(feature = "twilio", not(test))) {
        true => twilio::validate_phone(phone, country).await?,
        false => String::from(phone),
    };

    Ok(validated_phone)
}

async fn verify_phone_start(phone: &str) -> Result<String>
{
    let sid = match cfg!(feature = "twilio") && cfg!(not(test)) {
        true => twilio::verify_phone(phone).await?,
        false => String::from("verification-disabled"),
    };

    Ok(sid)
}

async fn verify_check_status(sid: &str) -> Result<String>
{
    let status = match cfg!(feature = "twilio") && cfg!(not(test)) {
        true => twilio::verify_check_status(sid).await?,
        false => String::from("pending"),
    };

    Ok(status)
}

async fn verify_code_submit(
    phone: &str,
    code: &str,
    sid: &str,
) -> Result<String>
{
    let use_twilio = cfg!(feature = "twilio") && cfg!(not(test));

    if let Ok(override_code) = env::var("VERIFICATION_CODE_OVERRIDE_SMS") {
        if code == override_code {
            if use_twilio {
                twilio::verify_status_update(sid, "approved").await?;
            }
            return Ok(String::from("approved"));
        }
    }
    let status = match use_twilio {
        true => twilio::verify_code_submit(phone, code).await?,
        false => String::from("approved"),
    };

    Ok(status)
}

// Generate a `cid` from a validated phone string.
fn cid_from_phone(phone: &str) -> String
{
    let hash = blake3::hash(phone.as_bytes());
    let bytes = hash.as_bytes();

    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

async fn get_directory_entry<T>(req: Request<State<T>>) -> Result<Response>
where
    T: Database,
{
    let db = &req.state().db;
    let cid = &req.ext::<ContactId>().unwrap().0;

    let entry_key = format!("entries/{}", cid);

    let bytes = db.get(entry_key).await.map_err(not_found)?;
    let data: DirectoryEntryInternal =
        serde_json::from_slice(&bytes).map_err(server_err)?;

    let response = Response::builder(StatusCode::Ok)
        .body(serde_json::to_vec(&data.entry).map_err(server_err)?)
        .build();

    Ok(response)
}

async fn directory_lookup<T>(mut req: Request<State<T>>) -> Result<Response>
where
    T: Database,
{
    let body_bytes = req.body_bytes().await.map_err(server_err)?;
    let query: LookupQuery =
        serde_json::from_slice(&body_bytes).map_err(bad_request)?;

    let db = &req.state().db;

    let validate = |phone: &str| {
        let p = String::from(phone);
        let c = query.country.clone();
        async move { (p.clone(), validate_phone(&p, &c).await) }
    };

    let validated_phone_numbers = query
        .phone_numbers
        .iter()
        .map(|s| s.as_ref())
        .map(validate)
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let lookup = |tuple: (String, String)| {
        let orig = tuple.0.clone();
        let validated = tuple.1.clone();
        async move { (orig, lookup_phone(db, &validated).await) }
    };

    let lookup_pairs = validated_phone_numbers
        .iter()
        .filter(|t| t.1.is_ok())
        .map(|t| (t.0.clone(), t.1.as_ref().ok().unwrap().clone()))
        .map(lookup)
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let results = lookup_pairs
        .iter()
        .filter(|t| t.1.is_ok())
        .map(|t| (t.0.clone(), t.1.as_ref().ok().unwrap()))
        .filter(|t| t.1.is_some())
        .map(|t| (t.0, t.1.as_ref().unwrap()))
        .collect::<Vec<_>>();

    let items = results
        .iter()
        .map(|t| LookupItemClientSuccess {
            phone_number: t.0.clone(),
            cid: t.1.cid.clone(),
        })
        .collect::<Vec<_>>();

    let body = LookupResult {
        cids: items,
        errors: Vec::new(), // don't report errors
    };

    let body_bytes = serde_json::to_vec(&body).map_err(server_err)?;

    let response = Response::builder(StatusCode::Ok).body(body_bytes).build();

    Ok(response)
}

async fn lookup_phone<T>(db: &T, phone: &str) -> Result<Option<LookupItem>>
where
    T: Database,
{
    let key = format!("lookup/{}", phone);
    if db.exists(key).await.map_err(server_err)? {
        Ok(Some(LookupItem { cid: cid_from_phone(phone) }))
    } else {
        Ok(None)
    }
}

async fn assist_topic<T>(mut req: Request<State<T>>) -> Result<Response>
where
    T: Database,
{
    let bytes = req.body_bytes().await.map_err(server_err)?;
    let one_kb = 1024;
    if bytes.len() > one_kb {
        return Ok(StatusCode::BadRequest.into());
    }
    let response = if cfg!(feature = "openai") && cfg!(not(test)) {
        assistant::passthrough(bytes).await?
    } else {
        Response::builder(StatusCode::Ok)
            .body(json!({"message": "assistant is not configured"}))
            .build()
    };
    Ok(response)
}

async fn brand_by_domain<T>(req: Request<State<T>>) -> Result<Response>
where
    T: Database,
{
    let domain = req.param("domain")?;
    let response = if cfg!(feature = "brandfetch") && cfg!(not(test)) {
        brandfetch::get_info(domain, &req.state().db).await?
    } else {
        Response::builder(StatusCode::Ok)
            .body(json!({"message": "brandfetch info is not configured"}))
            .build()
    };
    Ok(response)
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
struct ContactId(String);

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
        let sid = ShareId(String::from(p));
        req.set_ext(sid);
        Ok(next.run(req).await)
    })
}

// Extract the SigningId from the url parameter for conveniennce.
//
fn ensure_contact_id<'a, T>(
    mut req: Request<State<T>>,
    next: Next<'a, State<T>>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + 'static,
{
    Box::pin(async {
        let p = req.param("id").map_err(bad_request)?;
        let cid = ContactId(String::from(p));
        req.set_ext(cid);
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
    verify_db: T,
    directory_db: T,
    assist_db: T,
    brands_db: T,
) -> anyhow::Result<tide::Server<()>>
where
    T: Database + 'static,
{
    let mut api = tide::new();
    api.at("health").get(health);

    use http_types::headers::HeaderValue;
    use tide::security::{CorsMiddleware, Origin};

    let mut cors = CorsMiddleware::new();

    if std::env::var("DEV_CORS").is_ok() {
        cors = CorsMiddleware::new()
            .allow_methods(
                "GET, PUT, POST, OPTIONS".parse::<HeaderValue>().unwrap(),
            )
            .allow_origin(Origin::from("*"))
            .allow_credentials(false);
    }

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
            .put(store_vault)
            .delete(delete_vault);
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
        // Magic shares
        let mut shares =
            tide::with_state(State::new(share_db, token_db.clone()));
        shares
            .at(":id")
            .with(ensure_share_id)
            .get(fetch_share)
            .post(store_share);
        api.at("shares").nest(shares);
    }

    {
        // Legacy verification endpoint. Remove for API v3
        let mut verify_tokens_legacy =
            tide::with_state(State::new(verify_db.clone(), token_db.clone()));

        verify_tokens_legacy
            .at(":id")
            .with(ensure_vault_id)
            .with(signed_pow_auth)
            .with(add_auth_info)
            .with(cors.clone())
            .options(option_ok)
            .get(get_verification_status)
            .post(create_verification_token);
        verify_tokens_legacy
            .at(":id")
            .with(ensure_vault_id)
            .with(cors.clone())
            .options(option_ok)
            .put(verify_verification_token);

        api.at("verify_tokens").nest(verify_tokens_legacy);

        // Verification tokens
        let mut verify =
            tide::with_state(State::new(verify_db.clone(), token_db.clone()));

        verify // authed by knowledge of shared secret
            .at("entries/:id")
            .with(add_auth_info)
            .with(ensure_vault_id)
            .with(cors)
            .options(option_ok)
            .put(verify_verification_token);
        verify // signature auth, id in url is a convenience/formality
            .at("entries/:id")
            .with(signed_pow_auth)
            .with(add_auth_info)
            .with(ensure_vault_id)
            .with(check_vault_ownership)
            .get(get_verification_status);
        verify // signature auth
            .at("entries")
            .with(signed_pow_auth)
            .with(add_auth_info)
            .post(create_verification_token);
        verify
            .at("lookup")
            .get(get_verification_status_by_email)
            .post(get_verification_status_by_email);

        api.at("verify").nest(verify);
    }

    {
        let mut directory =
            tide::with_state(State::new(directory_db, token_db.clone()));
        directory
            .at("lookup")
            .with(signed_pow_auth)
            .with(add_auth_info)
            .get(directory_lookup)
            .post(directory_lookup); // some things don't like get w/ body
        directory
            .at("entries")
            .with(signed_pow_auth)
            .with(add_auth_info)
            // need to ensure that the pubkey on the request owns the cid in question
            .post(post_directory_entry);
        directory
            .at("entries/:id")
            .with(body_size_limit)
            .with(signed_pow_auth)
            .with(add_auth_info)
            .with(ensure_contact_id)
            // need to ensure that the pubkey on the request owns the cid in question
            .get(get_directory_entry);
        api.at("directory").nest(directory);
    }

    {
        let mut assist =
            tide::with_state(State::new(assist_db, token_db.clone()));
        assist
            .at("topics")
            .with(signed_pow_auth)
            .with(add_auth_info)
            .get(assist_topic)
            .post(assist_topic); // some things don't like get w/ body
        api.at("assist").nest(assist);
    }

    {
        let mut brands =
            tide::with_state(State::new(brands_db, token_db.clone()));
        brands.at(":domain").get(brand_by_domain);
        api.at("brands").nest(brands);
    }

    Ok(api)
}
