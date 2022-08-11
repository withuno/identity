//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::State;

use std::result::Result;
use tide::{Request, Response, StatusCode};

use uno::verify_blake3_work;

/// Returns Ok(orig req) if further processing of the request is authorized. If
/// the request is not authorized an Err(res) is returned and the enclosed
/// Response should be relayed to the client.
///
pub async fn check<T>(req: &mut Request<State<T>>) -> Result<(), Response>
where
    T: Database + 'static,
{
    // If there is an Authorization header and it is valid for this request,
    // then let it through.
    //

    let reason = match req.header("Authorization") {
        None => "authorization required",
        Some(a) => {
            // Parse the header and retrieve the nonce token.
            let auth = parse_auth(a.last().as_str())?;
            let raw_nonce =
                base64::decode(&auth.params["nonce"]).map_err(|_| {
                    return Response::builder(StatusCode::BadRequest)
                        .body(r#"{"message": "invalid nonce encoding"}"#)
                        .build();
                })?;
            use base64::URL_SAFE_NO_PAD;
            let url_nonce = base64::encode_config(&raw_nonce, URL_SAFE_NO_PAD);
            let tok_req = req.state().tok.get(&url_nonce).await;

            req.set_ext(auth);
            match tok_req {
                Err(_) => "unknown nonce",
                Ok(data) => {
                    let token = parse_token(&data)?;
                    let result = verify_challenge(token, req).await?;

                    match result {
                        Err(message) => message,
                        Ok(()) => {
                            // Burn the nonce.
                            // If this fails, don't worry about it right now
                            // we probably want to log this type of failure in
                            // the future and make sure it's not happening much
                            let _ = req.state().tok.del(&url_nonce).await;
                            // allow the request
                            return Ok(());
                        },
                    }
                },
            }
        },
    };

    // Otherwise, the request is not authorized. Generate a token and add the
    // details to the WWW-Authenticate header on the 401 response.
    //
    Err(unauthorized(req, &reason).await)
}

// TODO: use this when parsing !!!
/// Clients are required to privide authorization in the form of a signed
/// response to a challenge. In the authorization form,
///
#[allow(dead_code)]
#[derive(Debug)]
struct Authorization
{
    /// base64 encoded public key of the person sending the request
    identity: String,
    /// base64 encoded challenge nonce bytes, issued by the server
    nonce: String,
    /// base64 encoded response (hash) of the requesest parameters and nonce
    response: String,
    /// base64 encoded signature over the response, verifiable by `identity`
    signature: String,
}

use std::collections::HashMap;

// Using this for now until we get back around to parsing the Authorization
// header into the above structure.
struct AuthTemp
{
    params: HashMap<String, String>,
}

/// Parse the Authorization header provided by the client in response to an
/// authentication challenge.
///
/// An Authorization header looks like:
/// ```text
///     Authorization: Tuned-Digest-Signature
///       identity="51cBN9gxEge6aTv4yvF0IgSsV6ETCa+puinqlpRj4pg";
///       nonce="ij4SWiKZAkdL0SftSavftcuKJJUX9ZOutn4zg56cPDo";
///       response="Zm9vZGJhYmU$/fwnKozofi8OfqZEt0+3z3n10GZG3pekDvE0WvW66NE";
///       signature="N+xFiSOAJWIx5JGwRrNvlWVXD+3vzv0NZASETEdfDm61nY...(64)"
/// ```
///
/// Note: the response contains both the salt and the hash separated by `$`.
///       The client provides their own salt (helps mitigate chosen plaintext
///       attacks).
///
fn parse_auth(header: &str) -> Result<AuthTemp, Response>
{
    let items = match header.strip_prefix("tuned-digest-signature") {
        Some(s) => s.trim().split(';'),
        None => match header.strip_prefix("asym-tuned-digest-signature") {
            Some(s) => s.trim().split(';'),
            None => {
                return Err(Response::builder(StatusCode::BadRequest)
                    .body(r#"{"message": "unrecognized auth scheme"}"#)
                    .build());
            },
        },
    };

    // The defualt hasher uses entropy to achieve collision resistance. We do
    // not need that. TODO: use a lighter weight hasher or verify that the seed
    // is global per process and not obtained new for every instance of a map.
    let mut map = HashMap::new();
    for i in items {
        let kv: Vec<&str> = i.trim().splitn(2, "=").collect();
        map.insert(kv[0].into(), kv[1].into());
    }

    // require the following keys to have been provided by the client:
    let keys = ["identity", "nonce", "response", "signature"];
    if keys.iter().fold(true, |a, k| a && map.contains_key(&k.to_string())) {
        Ok(AuthTemp { params: map })
    } else {
        let fs = keys.join(",");
        // todo: change "required" to "missing"
        let msg = format!("authorization header requires fields: {}", fs);
        let r = Response::builder(StatusCode::BadRequest)
            .body(format!(r#"{{"message": {}"}}"#, msg))
            .build();
        Err(r)
    }
}

use serde::{Deserialize, Serialize};

/// The goal here is to store any information we cannot allow a client to forge
/// alonside knowledge of the nonce (nonce is the filename). When verifying the
/// challenge, the *action* of the request is checked against the allow list
/// associated with the nonce. Together, the nonce data plus allow list and
/// argon2 tuning parameters forms the token.
///
#[derive(Serialize, Deserialize, Debug)]
pub struct Token
{
    /// A list of allowed actions for the associated argon2 tuning params.
    /// Available actions are:
    ///
    /// ```text
    ///     "create", "read", "update", "delete", and "debug", "proxy"
    /// ```
    ///
    /// The debug and proxy actions are not used because our api does not
    /// service the trace or connect http methods.
    ///
    pub allow: Vec<String>,

    /// The encoded form of the argon2 tuning parameters (the enture encoded
    /// hash of some data minus the actual hash).
    ///
    pub argon: String,

    /// Cost value for the client-based, blake3 proof of work.
    /// The higher the cost, the easier the proof is to solve.
    /// The cost value range is 0-255.
    pub blake3: u8,
}

const NO_CREATE: [&str; 5] = ["read", "update", "delete", "debug", "proxy"];
const CREATE: [&str; 1] = ["create"];

fn parse_token(data: &[u8]) -> Result<Token, Response>
{
    let json = std::str::from_utf8(data)
        .map_err(|_| Response::new(StatusCode::InternalServerError))?;
    let toky = serde_json::from_str::<Token>(json)
        .map_err(|_| Response::new(StatusCode::InternalServerError))?;

    Ok(toky)
}

use http_types::Method;

/// Compute the required token scope for the given request. If a request is
/// determied to be e.g. a "create" request, then the token associated with the
/// nonce must allow "create".
///
async fn get_req_scope<T>(
    req: &Request<State<T>>,
) -> Result<&'static str, StatusCode>
where
    T: Database + 'static,
{
    let scope = match req.method() {
        Method::Get | Method::Options => "read",
        Method::Patch => "update",
        Method::Delete => "delete",
        Method::Put | Method::Post => {
            let id = req.param("id").map_err(|_| StatusCode::BadRequest)?;
            let exists = match req.state().db.exists(&id).await {
                Ok(e) => e,
                Err(e) => {
                    println!("db error: {:?}", e);
                    return Err(StatusCode::InternalServerError);
                },
            };
            if exists { "update" } else { "create" }
        },
        Method::Trace => "debug",
        Method::Connect => "proxy",
        // http_types 2.11 added a bunch of new methods which we're probably
        // never going to support. Return 418 until we comb through the new
        // methods and map them to some sensible action.
        _ => return Err(StatusCode::ImATeapot),
    };
    Ok(scope)
}

/// Given an authorization header, verify:
///
///  1. The token's action is appropriate for the request at hand.
///  2. The client computed the correct response to the challenge.
///  3. The user attests posession of their uno key via signature.
///
/// The response is computed by arranging the relevant pieces of the request in
/// a canonical order. The format we use is the same as specified in rfc7616
/// but we omit fields we do not use rather than leaving them empty. For any
/// challenge, the response has the form:
///
/// ```text
///     b64(salt)$argon2(b64(nonce):req.method:req.path:b64(blake3(body_bytes)))
/// ```
///
/// If the response successfully completes the challenge, proceed to validating
/// the provided signature over the response using the client's public key.
///
/// Returns Ok(Ok(req)) on success or Ok(Err(msg)) if the verification fails.
/// Returns Err(Response) if there was an error while attempting to perform the
/// verification.
///
async fn verify_challenge<T>(
    token: Token,
    req: &mut Request<State<T>>,
) -> Result<Result<(), &'static str>, Response>
where
    T: Database + 'static,
{
    // 1.
    let scope = get_req_scope(req).await?;
    if !token.allow.contains(&scope.to_string()) {
        return Ok(Err("scope mismatch"));
    }

    // 2.
    let body = req
        .body_bytes()
        .await
        .map_err(|_| Response::new(StatusCode::InternalServerError))?;

    // rewind body so later middleware can use it
    req.set_body(body.clone());

    let auth = req.ext::<AuthTemp>().unwrap();
    let nonce = &auth.params["nonce"];
    let response = &auth.params["response"];

    if response.starts_with("blake3") {
        let split: Vec<&str> = response.split('$').collect();
        if split.len() != 3 || split[2] != nonce {
            let res: Response = Response::builder(StatusCode::BadRequest)
                .body(r#"{"message": "malformed response field"}"#)
                .into();
            return Err(res);
        }

        let cost = token.blake3;
        let proof: u32 = split[1].parse().map_err(|_| {
            return Response::builder(StatusCode::BadRequest)
                .body(r#"{"message": "proof must be an unsigned integer"}"#)
                .build();
        })?;

        let decoded_nonce =
            base64::decode_config(nonce, base64::STANDARD_NO_PAD).map_err(
                |_| {
                    return Response::builder(StatusCode::BadRequest)
                        .body(r#"{"message": "impossible"}"#)
                        .build();
                },
            )?;

        if !verify_blake3_work(&decoded_nonce, proof, cost) {
            return Ok(Err("challenge verification failed"));
        }
    } else {
        let method = req.method();
        let path = req.url().path();
        // TODO: figure out how to fix this ^
        // print!("req: {:?}\n", &req);
        // print!("host: {:?}\n", req.host());
        // print!("url: {}\n", req.url());
        // let foo = req.param("--tide-path-rest");
        // print!("tide-path: {:?}\n", foo);
        let bhash = blake3::hash(&body);
        let bhashb = bhash.as_bytes();
        let body_enc = base64::encode_config(bhashb, base64::STANDARD_NO_PAD);

        let challenge = format!("{}:{}:{}:{}", nonce, method, path, body_enc);
        // print!("challenge: {}\n", &challenge);

        // The response contains both the salt and the hash so just cat them.
        use argon2::{Argon2, PasswordHash, PasswordVerifier};
        let enc_hash = format!("{}${}", token.argon, response);
        // print!("enc_hash: {}\n", &enc_hash);

        let hash = PasswordHash::new(&enc_hash).map_err(|_| {
            Response::builder(StatusCode::BadRequest)
                .body(r#"{"message": "bad request check salt$hash format"}"#)
                .build()
        })?;
        let alg = Argon2::default();

        // This works too:
        // hash.verify_password(&[&alg], challenge.as_bytes())?;

        use password_hash::Error;
        match alg.verify_password(challenge.as_bytes(), &hash) {
            Err(Error::Password) => {
                return Ok(Err("challenge verification failed"));
            },
            Err(e) => {
                // todo: make sure all these errors are okay to expose and do
                // constitute an issue with the request as provided by the client.
                let res: Response = Response::builder(StatusCode::BadRequest)
                    .body(format!(r#"{{"message": "{}"}}"#, e))
                    .into();
                return Err(res);
            },
            Ok(()) => {}, // success
        };
    };

    // 3.
    let pub64 = &auth.params["identity"]; // todo: use the real type
    let pubkey = crate::pubkey_from_b64(&pub64).map_err(|_| {
        Response::builder(StatusCode::BadRequest)
            .body(r#"{"message": "invalid identity pubkey data"}"#)
            .build()
    })?;

    let sig64 = &auth.params["signature"]; // todo: use the real type
    let signature = crate::signature_from_b64(&sig64).map_err(|_| {
        Response::builder(StatusCode::BadRequest)
            .body(r#"{"message": "invalid response signature data"}"#)
            .build()
    })?;
    use uno::Verifier;
    if pubkey.verify(response.as_bytes(), &signature).is_err() {
        return Ok(Err("signature verification failed"));
    }

    // Add useful parameters to the request for fusture middlewares & handlers.
    req.set_ext(UserId(pubkey));

    Ok(Ok(()))
}

/// The public key that signed the request.
pub struct UserId(pub uno::PublicKey);

/// Create an unauthorized response including the appropriate WWW-Authenticate
/// header for the provided request.
///
async fn unauthorized<T>(req: &Request<State<T>>, reason: &str) -> Response
where
    T: Database + 'static,
{
    let action = match get_req_scope(req).await {
        Ok(a) => a,
        Err(s) => return Response::new(s),
    };
    let actions = vec![action.to_string()];
    let (auth, asym_auth) = match gen_nonce(actions, req.state().tok.clone())
        .await
    {
        Ok((nonce, token)) => {
            use base64::STANDARD_NO_PAD;
            let encoded_nonce = base64::encode_config(nonce, STANDARD_NO_PAD);

            let mut params = String::new();
            params.push_str("tuned-digest-signature");
            params.push(' ');
            params.push_str("nonce");
            params.push('=');
            params.push_str(&encoded_nonce);
            params.push(';');
            params.push_str("algorithm");
            params.push('=');
            params.push_str(&token.argon);
            params.push(';');
            params.push_str("actions");
            params.push('=');
            params.push_str(&token.allow.join(","));

            let mut aparams = String::new();
            aparams.push_str("asym-tuned-digest-signature");
            aparams.push(' ');
            aparams.push_str("nonce");
            aparams.push('=');
            aparams.push_str(&encoded_nonce);
            aparams.push(';');
            aparams.push_str("algorithm");
            aparams.push_str("=blake3$");
            aparams.push_str(&token.blake3.to_string());
            aparams.push(';');
            aparams.push_str("actions");
            aparams.push('=');
            aparams.push_str(&token.allow.join(","));

            (params, aparams)
        },
        Err(_) => return Response::new(StatusCode::InternalServerError),
    };

    let body = format!(r#"{{"reason":"{}","action":"{}"}}"#, reason, action);
    let mut response = Response::builder(StatusCode::Unauthorized)
        .body(format!("{}", body))
        .build();

    response.append_header("WWW-Authenticate", auth);
    response.append_header("WWW-Authenticate", asym_auth);

    response
}

/// Add the Authentication-Info header to all responses that don't otherwise
/// get a WWW-Authenticate header (non 401).
pub async fn add_info<T>(mut response: Response, token_db: T) -> Response
where
    T: Database + 'static,
{
    if let StatusCode::Unauthorized = response.status() {
        return response;
    }
    if let StatusCode::InternalServerError = response.status() {
        return response;
    }
    for actions in vec![CREATE.to_vec(), NO_CREATE.to_vec()].into_iter() {
        let astrs = actions.iter().map(|s| s.to_string()).collect();
        let (nonce, token) = match gen_nonce(astrs, token_db.clone()).await {
            Ok((n, t)) => (n, t),
            // This isn't the end of the world and shouldn't fail the request.
            // The client will just have to request a new nonce and then that
            // portion can fail more gracefully if e.g. the token db is down
            // and new tokens can't be saved.
            Err(_) => continue,
        };

        let mut info = String::new();
        info.push_str("nextnonce");
        info.push('=');
        info.push_str(&base64::encode_config(&nonce, base64::STANDARD_NO_PAD));
        info.push(';');
        info.push_str("argon");
        info.push('=');
        info.push_str(&token.argon);
        info.push(';');
        info.push_str("scopes");
        info.push('=');
        info.push_str(&actions.join(","));
        response.insert_header("authentication-info", info);

        let mut asym_info = String::new();
        asym_info.push_str("nextnonce");
        asym_info.push('=');
        asym_info
            .push_str(&base64::encode_config(&nonce, base64::STANDARD_NO_PAD));
        asym_info.push(';');
        asym_info.push_str("blake3");
        asym_info.push('=');
        asym_info.push_str(&token.blake3.to_string());
        asym_info.push(';');
        asym_info.push_str("scopes");
        asym_info.push('=');
        asym_info.push_str(&actions.join(","));
        response.append_header("authentication-info", asym_info);
    }

    return response;
}

// these two are NOPs right now
/// Add quotes around a string.
//fn quote(mut s: String) -> String
//{
//    s.push('"');
//    s.insert(0, '"');
//    return s;
//}

/// Remove quotes around a string
//fn unquote(mut s: String) -> Result<String, ()>
//{
//    if s.char_at(0) != '"' && s.char_at(s.len() - 1) != '"' {
//
//    }
//}

// This should ultimately be some table that gets dynamically updated.
const CREATE_PARAMS: &str = "$argon2d$v=19$m=262144,t=5,p=8";
const ACCESS_PARAMS: &str = "$argon2d$v=19$m=65536,t=3,p=8";

// The higher the cost, the easier the proof is to solve.
const BLAKE3_CREATE_COST: u8 = 255;
// access should be free since we already verify the requests identity.
const BLAKE3_ACCESS_COST: u8 = 255;

use crate::store::Database;

/// Generate a nonce, store the token in the database, and return a base64 url
/// safe encoded string representing the nonce bytes.
///
async fn gen_nonce<T>(
    actions: Vec<String>,
    token_db: T,
) -> anyhow::Result<([u8; 32], Token)>
where
    T: Database + 'static,
{
    use rand::RngCore;

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let id = base64::encode_config(nonce, base64::URL_SAFE_NO_PAD);
    let params = match actions.contains(&"create".to_string()) {
        true => CREATE_PARAMS,
        false => ACCESS_PARAMS,
    };

    let blake3_cost = match actions.contains(&"create".to_string()) {
        true => BLAKE3_CREATE_COST,
        false => BLAKE3_ACCESS_COST,
    };

    let token = Token {
        allow: actions,
        blake3: blake3_cost,
        argon: params.to_string(),
    };

    let data = serde_json::to_string(&token)?;
    let _ = token_db.put(&id, data.as_bytes()).await?;

    Ok((nonce, token))
}

//#[cfg(test)]
//mod tests
//{
//    use super::*;
//
//    //#[async_std::test]
//    //#[test]
//    //
//}
