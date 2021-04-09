//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::path::Path;
use std::pin::Pin; 
use std::sync::Arc;

use api::{pubkey_from_id, signature_from_header};
use api::Database;

use json_patch::merge;
use serde_json::Value;

use tide::{Body, Error, Next, Request, Response, Result, StatusCode};
use uno::Verifier;

#[async_std::main]
async fn main() -> anyhow::Result<()>
{
    let mut api = tide::new();
    // TODO add proof of work to all api requests
    //  .with(proof_of_work_token);

    api
        .at("health")
        .get(health);

    {
    let db = make_db("vaults")?;
    let mut vaults = tide::with_state(State::new(db));
    vaults
        .at(":pub")
        .with(vault_id)
        .with(pubkey)
        .options(option_vault)
        .get(fetch_vault)
        .put(store_vault);
    api
        .at("vaults")
        .nest(vaults);
    }

    {
    let db = make_db("services")?;
    let mut services = tide::with_state(State::new(db));
    services
        .at(":name")
        .get(fetch_service);
    api
        .at("services")
        .nest(services);
    }

    {
    // Shamir's Secret Sharing Session
    let db = make_db("sessions")?;
    let mut ssss = tide::with_state(State::new(db));
    ssss
        .at(":sid")
        .with(session_id)
        .get(ssss_get)
        .put(ssss_put)
        .patch(ssss_patch);
    api
        .at("ssss")
        .nest(ssss);
    }

    let mut srv = tide::new();
    srv
        .at("/v1")
        .nest(api);

    tide::log::start();
    srv.listen("[::]:8080").await?;
    Ok(())
}

async fn health(_req: Request<()>) -> Result<Response>
{
    Ok(Response::new(StatusCode::NoContent))
}

#[derive(Clone)]
struct State<T>
where
    T: Database + Clone + Send + Sync
{
    db: Arc<T>,
}

impl<T> State<T>
where
    T: Database + Clone + Send + Sync
{
    fn new(db: T) -> Self
    {
        Self { db: Arc::new(db), }
    }
}

#[cfg(feature = "s3")]
use api::S3Store;

#[cfg(feature = "s3")]
fn make_db(name: &str) -> anyhow::Result<S3Store>
{
    S3Store::new(name)
}

#[cfg(not(feature = "s3"))]
use api::FileStore;

#[cfg(not(feature = "s3"))]
fn make_db(name: &'static str) -> anyhow::Result<FileStore>
{
    FileStore::try_from(name)
}

//fn db_for_name<T>(name: &'static str) -> Result<Box<T>>
//where
//    T: Database + Send + Sync
//{
//    Ok(Box::new(match cfg!(feature = "s3") {
//        #[cfg(feature = "s3")]
//        true => api::S3Store::new(name),
//        _ => api::FileStore::try_from(name),
//    }?))
//}

struct VaultId(String);

fn vault_id<'a, T>(mut req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
{
    Box::pin(async {
        let p = req.param("pub").map_err(bad_request)?;
        let vid = VaultId(String::from(p));
        req.set_ext(vid);
        Ok(next.run(req).await)
    })
}

fn pubkey<'a, T>(mut req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
{
    Box::pin(async {
        let id = req.ext::<VaultId>().unwrap();
        let pk = pubkey_from_id(&id.0).map_err(bad_request)?;
        req.set_ext(pk);
        Ok(next.run(req).await)
    })
}

async fn option_vault<T>(_req: Request<State<T>>) -> Result
where
    T: Database + Clone + Send + Sync + 'static
{
    let response = Response::builder(200)
        .body("ok")
        .header("Access-Control-Allow-Origin", "*")
        .build();

    return Ok(response);
}

async fn fetch_vault<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;
    let pk = req.ext::<uno::Verification>().unwrap();

    let signature = req.header("x-uno-signature")
        .ok_or_else(|| bad_request("missing signature"))?.as_str();
    let timestamp = req.header("x-uno-timestamp")
        .ok_or_else(|| bad_request("missing timestamp"))?.as_str();
    let rawsig = signature_from_header(&signature)
        .map_err(bad_request)?;
    pk.verify(timestamp.as_bytes(), &rawsig)
        .map_err(unauthorized)?;

    let vault = db.get(id).await.map_err(not_found)?;

    Ok(Body::from_bytes(vault))
}

async fn store_vault<T>(mut req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    // Read the body first because it's a mutating operation.
    let body = req.body_bytes().await.map_err(server_err)?;

    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;
    let pk = req.ext::<uno::Verification>().unwrap();

    if body.len() < 65 {
        return Err(bad_request("body too short"));
    }
    let (raw_sig, blob) = body.split_at(64);
    let arr_sig = <[u8; uno::SIGNATURE_LENGTH]>::try_from(raw_sig)
        .map_err(bad_request)?;
    let signature = uno::Signature::new(arr_sig);

    pk.verify(blob, &signature).map_err(unauthorized)?;
    db.put(id, blob).await.map_err(server_err)?;
    let vault = db.get(id).await.map_err(not_found)?;

    Ok(Body::from_bytes(vault))
}

async fn fetch_service<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    let db = &req.state().db;
    let name = req.param("name").map_err(bad_request)?;
    let service = db.get(name).await.map_err(not_found)?;
    Ok(Body::from_bytes(service))
}

struct SessionId(String);

fn session_id<'a, T>(mut req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
{
    Box::pin(async {
        let p = req.param("sid").map_err(bad_request)?;
        let sid = SessionId(String::from(p));
        req.set_ext(sid);
        Ok(next.run(req).await)
    })
}

async fn ssss_get<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let session = db.get(sid).await.map_err(not_found)?;
    Ok(Body::from_bytes(session))
}

async fn ssss_put<T>(mut req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    // Read the body first because it's a mutating operation.
    let body = req.body_bytes().await.map_err(server_err)?;

    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;

    db.put(sid, &body).await.map_err(server_err)?;

    let session = db.get(sid).await.map_err(not_found)?;
    Ok(Body::from_bytes(session))
}

async fn ssss_patch<T>(mut req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    // Read the body first because it's a mutating operation.
    let body = req.body_json::<Value>().await
        .map_err(bad_request)?;

    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("sessions").join(sid);

    let json = async_std::fs::read_to_string(&path).await
        .map_err(not_found)?;
    let mut doc = serde_json::from_str::<Value>(&json)
        .map_err(bad_request)?;

    merge(&mut doc, &body);

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

fn unauthorized<M>(msg: M) -> Error
    where
        M: Display + Debug + Send + Sync + 'static,
{
    Error::from_str(StatusCode::Unauthorized, msg)
}
