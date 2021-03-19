//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::path::Path;
use std::pin::Pin; 

use api::{pubkey_from_id, signature_from_header};
use api::FileStore;

use json_patch::merge;
use serde_json::Value;

use tide::{Body, Error, Next, Request, Response, Result, StatusCode};

use uno::Verifier;

#[async_std::main]
async fn main() -> Result<()>
{
    let vault = State{ fs: FileStore::from("api/example/vaults"), };
    let mut vaults = tide::with_state(vault);
    vaults
        .at(":pub")
        .with(vault_id)
        .with(pubkey)
        .get(fetch_vault)
        .put(store_vault);

    let mut services = tide::new();
    services
        .at(":name")
        .get(fetch_service);

    let mut sss = tide::new();
    sss
        .with(session_id);

    sss.at("split/:sid")
        .get(split_get)
        .put(split_put)
        .patch(split_patch);

    sss.at("combine/:sid")
        .get(combine_get)
        .put(combine_put)
        .patch(combine_patch);

    let mut api = tide::new();
    // TODO
    //  .with(proof_of_work_token);

    api
        .at("health")
        .get(health);

    api
        .at("vaults")
        .nest(vaults);

    api
        .at("services")
        .nest(services);

    api
        .at("sss")
        .nest(sss);

    let mut srv = tide::new();
    srv
        .at("/api/v1")
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
struct State {
    fs: FileStore,
}

struct VaultId(String);

fn vault_id<'a>(mut req: Request<State>, next: Next<'a, State>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
{
    Box::pin(async {
        let p = req.param("pub").map_err(bad_request)?;
        let vid = VaultId(String::from(p));
        req.set_ext(vid);
        Ok(next.run(req).await)
    })
}

fn pubkey<'a>(mut req: Request<State>, next: Next<'a, State>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
{
    Box::pin(async {
        let id = req.ext::<VaultId>().unwrap();
        let pk = pubkey_from_id(&id.0).map_err(bad_request)?;
        req.set_ext(pk);
        Ok(next.run(req).await)
    })
}

async fn fetch_vault<'a>(req: Request<State>) -> Result<Body>
{
    let fs = &req.state().fs;
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

    let vault = fs.get(id).await.map_err(not_found)?;

    Ok(Body::from_bytes(vault))
}

async fn store_vault(mut req: Request<State>) -> Result<Body>
{
    // Read the body first because it's a mutating operation. Why? I don't
    // know...
    let body = req.body_bytes().await.map_err(server_err)?;

    let fs = &req.state().fs;
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
    fs.put(id, blob).await.map_err(server_err)?;
    let vault = fs.get(id).await.map_err(server_err)?;

    Ok(Body::from_bytes(vault))
}

async fn fetch_service(req: Request<()>) -> Result<Body>
{
    let name = req.param("name").map_err(bad_request)?;
    let path = Path::new("api/example/services").join(name);

    Body::from_file(path).await.map_err(not_found)
}

struct SessionId(String);

fn session_id<'a>(mut req: Request<()>, next: Next<'a, ()>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
{
    Box::pin(async {
        let p = req.param("sid").map_err(bad_request)?;
        let sid = SessionId(String::from(p));
        req.set_ext(sid);
        Ok(next.run(req).await)
    })
}

async fn split_get(req: Request<()>) -> Result<Body>
{
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("api/example/sessions").join(sid);

    Body::from_file(path).await.map_err(not_found)
}

async fn split_put(mut req: Request<()>) -> Result<Body>
{
    let body = req.body_bytes().await.map_err(server_err)?;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("api/example/sessions").join(sid);

    async_std::fs::write(&path, body).await.map_err(server_err)?;

    Body::from_file(&path).await.map_err(not_found)
}

async fn split_patch(mut req: Request<()>) -> Result<Body>
{
    let body = req.body_json::<Value>().await
        .map_err(bad_request)?;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("api/example/sessions").join(sid);

    let json = async_std::fs::read_to_string(&path).await
        .map_err(not_found)?;
    let mut doc = serde_json::from_str::<Value>(&json)
        .map_err(bad_request)?;

    merge(&mut doc, &body);

    let data = serde_json::to_vec(&doc)
        .map_err(server_err)?;
    async_std::fs::write(&path, data).await
        .map_err(server_err)?;

    Body::from_file(&path).await.map_err(not_found)
}

async fn combine_get(req: Request<()>) -> Result<Body>
{
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("api/example/sessions").join(sid);

    Body::from_file(path).await.map_err(not_found)
}

async fn combine_put(mut req: Request<()>) -> Result<Body>
{
    let body = req.body_bytes().await.map_err(server_err)?;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("api/example/sessions").join(sid);

    async_std::fs::write(&path, body).await.map_err(server_err)?;

    Body::from_file(&path).await.map_err(not_found)
}

async fn combine_patch(mut req: Request<()>) -> Result<Body>
{
    let body = req.body_json::<Value>().await
        .map_err(bad_request)?;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let path = Path::new("api/example/sessions").join(sid);

    let json = async_std::fs::read_to_string(&path).await
        .map_err(not_found)?;
    let mut doc = serde_json::from_str::<Value>(&json)
        .map_err(bad_request)?;

    merge(&mut doc, &body);

    let data = serde_json::to_vec(&doc)
        .map_err(server_err)?;
    async_std::fs::write(&path, data).await
        .map_err(server_err)?;

    Body::from_file(&path).await.map_err(not_found)
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
