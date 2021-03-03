//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin; 

use tide::{Error, Next, Request, Result, StatusCode};
use api::{pubkey_from_id, signature_from_header};
use api::FileStore;

use uno::Verifier;

#[async_std::main]
async fn main() -> Result<()>
{
    let fs = State{ fs: FileStore::new("vaults"), };

    let mut app = tide::with_state(fs);
    app
        .at("vaults/:pub")
        .with(vault_id)
        .with(pubkey)
        .get(fetch_vault)
        .put(store_vault);

    let mut srv = tide::new();
    srv
        .at("/api/v1")
        .nest(app);

    srv.listen("localhost:3000").await?;
    Ok(())
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
        match req.param("pub") {
            Ok(id) => {
                let vid = VaultId(String::from(id));
                req.set_ext(vid);
                Ok(next.run(req).await)
            },
            Err(e) => Err(Error::from_str(StatusCode::BadRequest, e)),
        }
    })
}

fn pubkey<'a>(mut req: Request<State>, next: Next<'a, State>)
-> Pin<Box<dyn Future<Output = Result> + Send + 'a>>
{
    Box::pin(async {
        let id = req.ext::<VaultId>().unwrap();
        match pubkey_from_id(&id.0) {
            Ok(pk) => {
                req.set_ext(pk);
                Ok(next.run(req).await)
            },
            Err(e) => Err(Error::from_str(StatusCode::BadRequest, e)),
        }
    })
}

async fn fetch_vault<'a>(req: Request<State>) -> Result<String>
{
    let fs = &req.state().fs;
    let id = &req.ext::<VaultId>().unwrap().0;
    let pk = req.ext::<uno::Verification>().unwrap();

    let signature = req.header("x-uno-signature").unwrap().as_str();
    let timestamp = req.header("x-uno-timestamp").unwrap().as_str();
    let rawsig = signature_from_header(&signature).unwrap();

    let authz = pk.verify(timestamp.as_bytes(), &rawsig);
    match authz {
        Ok(_) => match fs.get(id) {
            Ok(vault) => Ok(vault),
            Err(e) => Err(Error::from_str(StatusCode::InternalServerError, e)),
        }
        Err(e) => Err(Error::from_str(StatusCode::Unauthorized, e)),
    }
}

async fn store_vault(mut req: Request<State>) -> Result<String>
{
    // Read the body first because it's a mutating operation. Why? I don't
    // know...
    let body = req.body_bytes().await.unwrap();

    let fs = &req.state().fs;
    let id = &req.ext::<VaultId>().unwrap().0;
    let pk = req.ext::<uno::Verification>().unwrap();

    let raw_sig = &body[..64];
    let blob = &body[64..];
    let arr_sig = <[u8; uno::SIGNATURE_LENGTH]>::try_from(raw_sig).unwrap();
    let signature = uno::Signature::new(arr_sig);

    let authz = pk.verify(blob, &signature);
    match authz {
        Ok(_) => match fs.put(id, blob) {
            Ok(_) => Ok("ok".into()),
            Err(e) => Err(Error::from_str(StatusCode::InternalServerError, e)),
        }
        Err(e) => Err(Error::from_str(StatusCode::Unauthorized, e)),
    }
}
