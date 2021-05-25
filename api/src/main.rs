//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin; 

use api::pubkey_from_url_b64;
use api::auth;
use api::auth::BodyBytes;
use api::auth::UserId;
use api::Database;
use api::State;

use json_patch::merge;
use serde_json::Value;

use tide::{Body, Error, Next, Request, Response, Result, StatusCode};


#[async_std::main]
async fn main() -> anyhow::Result<()>
{
    let api = build_api()?;

    let mut srv = tide::new();
    srv
        .at("/v1")
        .nest(api);

    tide::log::start();
    srv.listen("[::]:8080").await?;
    Ok(())
}

fn build_api() -> anyhow::Result<tide::Server<()>>
{
    let mut api = tide::new();
    api
        .at("health")
        .get(health);

    {
    let db = make_db("vaults")?;
    let tok = make_db("tokens")?;
    let mut vaults = tide::with_state(State::new(db, tok));
    vaults
        .at(":id")
        .with(add_auth_info)
        .with(signed_pow_auth)
        .with(ensure_vault_id)
        .with(check_ownership)
        .options(option_vault)
        .get(fetch_vault)
        .put(store_vault);
    api
        .at("vaults")
        .nest(vaults);
    }

    {
    let db = make_db("services")?;
    let tok = make_db("tokens")?;
    let mut services = tide::with_state(State::new(db, tok));
    services
        .at(":name")
        .with(add_auth_info)
        .with(signed_pow_auth)
        .get(fetch_service);
    api
        .at("services")
        .nest(services);
    }

    {
    // Shamir's Secret Sharing Session
    let db = make_db("sessions")?;
    let tok = make_db("tokens")?;
    let mut ssss = tide::with_state(State::new(db, tok));
    ssss
        .at(":id")
        .with(add_auth_info)
        .with(signed_pow_auth)
        .with(session_id)
        .get(ssss_get)
        .put(ssss_put)
        .patch(ssss_patch);
    api
        .at("ssss")
        .nest(ssss);
    }

    Ok(api)
}


async fn health(_req: Request<()>) -> Result<Response>
{
    Ok(Response::new(StatusCode::NoContent))
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
    use std::convert::TryFrom;
    FileStore::try_from(name)
}

/// Short circuit the middleware chain if the request is not authorized.
///
fn signed_pow_auth<'a, T>(mut req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
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
fn add_auth_info<'a, T>(req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
{
    Box::pin(async {
        let tok = req.state().tok.clone();
        let resp = auth::add_info(next.run(req).await, tok).await;
        Ok(resp)
    })
}

struct VaultId(String);

// Extract the VaultId from the url parameter for conveniennce.
//
fn ensure_vault_id<'a, T>(mut req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
{
    Box::pin(async {
        let p = req.param("id")
            .map_err(bad_request)?;
        let vid = VaultId(String::from(p));
        req.set_ext(vid);
        Ok(next.run(req).await)
    })
}

// Make sure the vault in the url matches the public key that generated the
// signature on the request. Requires VaultId middleware. Returns status 403
// forbidden if there is a mismatch.
//
fn check_ownership<'a, T>(req: Request<State<T>>, next: Next<'a, State<T>>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
where
    T: Database + Clone + Send + Sync + 'static
{
    Box::pin(async {
        let id = req.ext::<VaultId>().unwrap();
        let target = pubkey_from_url_b64(&id.0)
            .map_err(bad_request)?;
        let user = req.ext::<UserId>().unwrap().0;
        if target != user {
            return Err(forbidden("pubkey mismatch"));
        }
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
        .header("Access-Control-Allow-Headers", "uno-timestamp, uno-signature")
        .build();

    Ok(response)
}

async fn fetch_vault<T>(req: Request<State<T>>) -> Result
where
    T: Database + Clone + Send + Sync + 'static
{
    let db = &req.state().db;
    let id = &req.ext::<VaultId>().unwrap().0;

    let vault = db.get(id).await.map_err(not_found)?;

    let response = Response::builder(200)
        .body(Body::from_bytes(vault))
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Headers",
            "WWW-Authenticate, Authentication-Info")
        .build();

    Ok(response)
}

async fn store_vault<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
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
        let p = req.param("id").map_err(bad_request)?;
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

async fn ssss_put<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;
    let body = &req.ext::<BodyBytes>().unwrap().0;

    db.put(sid, &body).await.map_err(server_err)?;

    let session = db.get(sid).await.map_err(not_found)?;
    Ok(Body::from_bytes(session))
}

async fn ssss_patch<T>(req: Request<State<T>>) -> Result<Body>
where
    T: Database + Clone + Send + Sync + 'static
{
    let db = &req.state().db;
    let sid = &req.ext::<SessionId>().unwrap().0;

    let json = db.get(sid).await
        .map_err(not_found)?;
    let mut doc = serde_json::from_slice::<Value>(&json)
        .map_err(server_err)?;

    let bytes = &req.ext::<BodyBytes>().unwrap().0;
    let body = serde_json::from_slice::<Value>(&bytes)
        .map_err(bad_request)?;

    merge(&mut doc, &body);

    let data = serde_json::to_vec(&doc)
        .map_err(server_err)?;
    db.put(sid, &data).await
        .map_err(server_err)?;

    let session = db.get(sid).await
        .map_err(not_found)?;
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

#[cfg(test)]
mod unit
{
    use super::*;

    use surf::Request;

    use async_std::task;

    #[test]
    fn v1_health_get() -> Result<()>
    {
        let api = build_api()?;
        let req: Request = surf::get("http://example.com/health").into();
        let res: Response = task::block_on(api.respond(req))?;
        assert_eq!(StatusCode::NoContent, res.status());
        Ok(())
    }

    #[test]
    fn v1_vault_put()
    {
    }

    #[test]
    fn v1_vault_get()
    {
    }

    #[test]
    fn v1_service_get()
    {
    }

    #[test]
    fn v1_ssss_put()
    {
    }

    #[test]
    fn v1_ssss_get()
    {
    }

    #[test]
    fn v1_ssss_patch()
    {
    }
}
