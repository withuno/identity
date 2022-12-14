//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
mod requests
{
    use api::mailbox::{
        Mailbox, MessageRequest, MessageStored, MessageToDelete,
    };
    use api::{
        add_auth_info, build_routes, signed_pow_auth, LookupItemClientSuccess,
        LookupQuery, LookupResult,
    };

    use api::State;
    use tide::{Body, Response, StatusCode};

    use anyhow::anyhow;
    use anyhow::Context;
    use anyhow::Result;
    use async_std::task;

    use base64::STANDARD_NO_PAD;
    use base64::URL_SAFE_NO_PAD;

    use rand::RngCore;
    use serde_json::json;

    use std::collections::HashMap;
    use std::convert::From;
    use std::convert::TryFrom;

    use http_types::headers::HeaderValues;
    use surf::Request;
    use surf::Url;

    use uno::prove_blake3_work;
    use uno::Id;
    use uno::KeyPair;
    use uno::Mu;
    use uno::Session;
    use uno::Signer;
    use uno::ID_LENGTH;
    use uno::MU_LENGTH;

    use vclock::VClock;

    use api::Database;
    use api::DirectoryEntry;
    use api::DirectoryEntryInternal;
    use api::LookupItem;
    use api::PendingItem;

    const TUNE: &str = "$argon2d$v=19$m=4096,t=3,p=1";
    const SALT: &str = "cm9ja3NhbHQ";

    struct Dbs<T: Database>
    {
        tokens: T,
        vaults: T,
        services: T,
        sessions: T,
        mailboxes: T,
        objects: T,
        shares: T,
        verify: T,
        directory: T,
    }

    #[cfg(not(feature = "s3"))]
    pub use api::store::FileStore;

    #[cfg(not(feature = "s3"))]
    async fn setup_tmp_api() -> Result<(tide::Server<()>, Dbs<FileStore>)>
    {
        let dir = tempfile::TempDir::new()?;
        let dbs = Dbs {
            objects: FileStore::new(dir.path(), "objs", "v0").await?,
            tokens: FileStore::new(dir.path(), "toks", "v0").await?,
            vaults: FileStore::new(dir.path(), "vaults", "v0").await?,
            services: FileStore::new(dir.path(), "serv", "v0").await?,
            sessions: FileStore::new(dir.path(), "sess", "v0").await?,
            mailboxes: FileStore::new(dir.path(), "mbxs", "v0").await?,
            shares: FileStore::new(dir.path(), "shrs", "v0").await?,
            verify: FileStore::new(dir.path(), "vdb", "v0").await?,
            directory: FileStore::new(dir.path(), "directory", "v0").await?,
        };
        // we don't include objects db here because its only used in tests
        // todo: I don't understand this comment ^
        let api = build_routes(
            dbs.tokens.clone(),
            dbs.vaults.clone(),
            dbs.services.clone(),
            dbs.sessions.clone(),
            dbs.mailboxes.clone(),
            dbs.shares.clone(),
            dbs.verify.clone(),
            dbs.directory.clone(),
        )?;
        Ok((api, dbs))
    }

    #[cfg(feature = "s3")]
    pub use api::store::S3Store;

    #[cfg(feature = "s3")]
    async fn setup_dbs() -> Result<Dbs<S3Store>>
    {
        // modified from:
        // https://doc.servo.org/src/tempfile/util.rs.html#9
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        use std::str;

        fn tmpname(rand_len: usize) -> String
        {
            let mut buf = String::with_capacity(rand_len);

            // Push each character in one-by-one. Unfortunately, this is the
            // only safe(ish) simple way to do this without allocating a
            // temporary String/Vec.
            unsafe {
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(rand_len)
                    .for_each(|b| {
                        buf.push_str(str::from_utf8_unchecked(&[b as u8]))
                    })
            }
            buf.to_lowercase()
        }

        let dbs = Dbs {
            objects: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            tokens: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            vaults: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            services: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            sessions: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            mailboxes: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            shares: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
            directory: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
                "v0",
            )
            .await?,
        };

        dbs.objects.create_bucket_if_not_exists().await?;
        dbs.tokens.create_bucket_if_not_exists().await?;
        dbs.vaults.create_bucket_if_not_exists().await?;
        dbs.services.create_bucket_if_not_exists().await?;
        dbs.sessions.create_bucket_if_not_exists().await?;
        dbs.mailboxes.create_bucket_if_not_exists().await?;
        dbs.shares.create_bucket_if_not_exists().await?;
        dbs.directory.create_bucket_if_not_exists().await?;

        dbs.objects.empty_bucket().await?;
        dbs.tokens.empty_bucket().await?;
        dbs.vaults.empty_bucket().await?;
        dbs.services.empty_bucket().await?;
        dbs.sessions.empty_bucket().await?;
        dbs.mailboxes.empty_bucket().await?;
        dbs.shares.empty_bucket().await?;
        dbs.directory.empty_bucket().await?;

        Ok(dbs)
    }

    #[cfg(feature = "s3")]
    async fn setup_tmp_api() -> Result<(tide::Server<()>, Dbs<S3Store>)>
    {
        // we don't include objects db here because its only used in tests
        let dbs = setup_dbs().await?;
        let api = build_routes(
            dbs.tokens.clone(),
            dbs.vaults.clone(),
            dbs.services.clone(),
            dbs.sessions.clone(),
            dbs.mailboxes.clone(),
            dbs.shares.clone(),
            dbs.directory.clone(),
        )?;
        Ok((api, dbs))
    }

    fn body_challenge(req: &mut Request, n64: &str) -> Result<String>
    {
        let body = req.take_body();
        let bbytes: Vec<u8> = task::block_on(body.into_bytes())
            .map_err(|_| anyhow!("body bytes failed"))?;
        let bhash = blake3::hash(&bbytes);
        let bhashb = bhash.as_bytes();
        let bhash_enc = base64::encode_config(bhashb, base64::STANDARD_NO_PAD);
        req.set_body(Body::from_bytes(bbytes));
        let method = req.method();

        let mut split: Vec<&str> = req.url().path().split("/").collect();
        split.reverse();
        split.pop();
        split.pop();
        split.reverse();

        let path = split.join("/");
        let challenge = format!("{}:{}:/{}:{}", n64, method, path, bhash_enc);

        return Ok(challenge);
    }

    // Add the correct authorization header to the client-based proof of work.
    fn blake3_sign_req(
        req: &mut Request,
        n64: &str,
        cost: u8,
        id: &Id,
    ) -> Result<()>
    {
        let challenge = body_challenge(req, n64)?;

        let n = prove_blake3_work(&challenge.as_bytes(), cost).unwrap();
        let response = format!("blake3${}${}", n, n64);

        let kp: uno::KeyPair = KeyPair::from(id);
        let pub_bytes = kp.public.to_bytes();
        let pub64 = base64::encode_config(&pub_bytes, base64::STANDARD_NO_PAD);
        let sig = kp.sign(&response.as_bytes());
        let sig64 = base64::encode_config(sig, base64::STANDARD_NO_PAD);

        let i = format!("identity={}", pub64);
        let n = format!("nonce={}", n64);
        let r = format!("response={}", response);
        let s = format!("signature={}", sig64);
        let auth =
            format!("asym-tuned-digest-signature {};{};{};{}", i, n, r, s);

        req.insert_header("authorization", auth);

        Ok(())
    }

    // Sign next request using previous request test helper.
    // TODO: put this in a util somewhere in the lib crate...
    fn asym_sign_req_using_res_with_id(
        prev: &Response,
        next: &mut Request,
        id: &Id,
    ) -> Result<()>
    {
        let auth_info_str = prev
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;

        let auth_info = parse_asym_auth_info(auth_info_str)?;
        let nonce_b64 = &auth_info.params["nextnonce"];
        let cost = auth_info.params["blake3"].parse::<u8>()?;

        blake3_sign_req(next, &nonce_b64, cost, id)?;

        Ok(())
    }

    // Add the correct authorization header to the request
    fn sign_req(
        req: &mut Request,
        n64: &str,
        argon: &str,
        s64: &str,
        id: &Id,
    ) -> Result<()>
    {
        let challenge = body_challenge(req, n64)?;

        use argon2::{Argon2, PasswordHash, PasswordHasher};
        let alg = Argon2::default();
        let param_str = format!("{}${}", argon, &s64);
        let hash = PasswordHash::new(&param_str)
            .map_err(|_| anyhow!("hash parse failed"))?;
        let params = argon2::Params::try_from(&hash)
            .map_err(|_| anyhow!("param parse failed"))?;
        let alg_id = hash.algorithm;
        let cbytes = &challenge.as_bytes();
        let salt =
            password_hash::Salt::new(&s64).map_err(|_| anyhow!("bad salt"))?;
        let pow = alg
            .hash_password(cbytes, Some(alg_id), params, salt)
            .map_err(|_| anyhow!("hash generation failed"))?;
        let response = format!("{}${}", s64, pow.hash.unwrap());

        let kp: uno::KeyPair = KeyPair::from(id);
        let pub_bytes = kp.public.to_bytes();
        let pub64 = base64::encode_config(&pub_bytes, base64::STANDARD_NO_PAD);
        let sig = kp.sign(&response.as_bytes());
        let sig64 = base64::encode_config(sig, base64::STANDARD_NO_PAD);

        let i = format!("identity={}", pub64);
        let n = format!("nonce={}", n64);
        let r = format!("response={}", response);
        let s = format!("signature={}", sig64);
        let auth = format!("tuned-digest-signature {};{};{};{}", i, n, r, s);
        req.insert_header("authorization", auth);

        Ok(())
    }

    // Sign next request using previous request test helper.
    // TODO: put this in a util somewhere in the lib crate...
    fn sign_req_using_res_with_id(
        prev: &Response,
        next: &mut Request,
        id: &Id,
    ) -> Result<()>
    {
        let auth_info_str = prev
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;

        let auth_info = parse_auth_info(auth_info_str)?;
        let nonce_b64 = &auth_info.params["nextnonce"];
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let salt_b64 = base64::encode_config(&salt, STANDARD_NO_PAD);
        let hash_alg = &auth_info.params["argon"];

        sign_req(next, &nonce_b64, hash_alg, &salt_b64, id)?;

        Ok(())
    }

    struct AuthInfoTemp
    {
        params: HashMap<String, String>,
    }

    struct WwwAuthTemp
    {
        params: HashMap<String, String>,
    }

    fn parse_www_auth(headers: &HeaderValues) -> Result<WwwAuthTemp>
    {
        use regex::Regex;
        let mut map = HashMap::new();

        // tuned-digest-signature nonce=E2nl6WRukjQrm9pYcJB/LVwqGEZRU4ik+TM1NgvDSjk;algorithm=$argon2d$v=19$m=65536,t=3,p=8;actions=read
        let sym_tuned_re = Regex::new(
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

        return Err(anyhow!("invalid auth-info"));
    }

    fn parse_asym_www_auth(headers: &HeaderValues) -> Result<WwwAuthTemp>
    {
        use regex::Regex;
        let mut map = HashMap::new();

        let asym_tuned_re = Regex::new(
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

        return Err(anyhow!("invalid auth-info"));
    }

    fn parse_auth_info(headers: &HeaderValues) -> Result<AuthInfoTemp>
    {
        for header in headers.iter() {
            let items = header.as_str().trim().split(';');
            let mut map = HashMap::new();
            for i in items {
                let kv: Vec<&str> = i.trim().splitn(2, "=").collect();
                map.insert(kv[0].into(), kv[1].into());
            }
            let keys = ["nextnonce", "argon", "scopes"];
            if keys
                .iter()
                .fold(true, |a, k| a && map.contains_key(&k.to_string()))
            {
                return Ok(AuthInfoTemp { params: map });
            }
        }

        Err(anyhow!("invalid auth-info"))
    }

    fn parse_asym_auth_info(headers: &HeaderValues) -> Result<AuthInfoTemp>
    {
        for header in headers.iter() {
            let items = header.as_str().trim().split(';');
            let mut map = HashMap::new();
            for i in items {
                let kv: Vec<&str> = i.trim().splitn(2, "=").collect();
                map.insert(kv[0].into(), kv[1].into());
            }
            let keys = ["nextnonce", "blake3", "scopes"];
            if keys
                .iter()
                .fold(true, |a, k| a && map.contains_key(&k.to_string()))
            {
                return Ok(AuthInfoTemp { params: map });
            }
        }

        Err(anyhow!("invalid auth-info"))
    }

    async fn init_nonce(
        token_db: &impl Database,
        scopes: &[&'static str],
    ) -> Result<String>
    {
        let n64 = "U4L+xVHzX4qzBSDPv5NJMhB2HJuhkksmFqJe7geX+xA";
        let n = base64::decode_config(&n64, STANDARD_NO_PAD)?;
        let n64url = base64::encode_config(&n, URL_SAFE_NO_PAD);
        let token = json!({"argon":TUNE,"allow":scopes,"blake3":MIN_COST});
        let tstr = token.to_string();
        let tok_bytes = tstr.as_bytes();
        let _ = token_db.put(&n64url, tok_bytes).await?;
        Ok(n64.into())
    }

    #[async_std::test]
    async fn health_get() -> Result<()>
    {
        let (api, _) = setup_tmp_api().await?;

        let req: Request = surf::get("http://example.com/health").into();
        let res: Response =
            api.respond(req).await.map_err(|_| anyhow!("request failed"))?;
        assert_eq!(StatusCode::NoContent, res.status());
        Ok(())
    }

    #[async_std::test]
    async fn body_size_limit() -> Result<()>
    {
        let (_, dbs) = setup_tmp_api().await?;

        let state = State::new(dbs.objects.clone(), dbs.tokens.clone());
        let mut foo = tide::with_state(state);
        foo.at(":id")
            .with(api::body_size_limit)
            .put(|_| async { Ok(Response::new(StatusCode::NoContent)) });

        let mut api = tide::new();
        api.at("/foo").nest(foo);

        let url = Url::parse("http://example.com/foo/bar")?;

        // A body of size 1 MB should succeed
        const ONE_MB: usize = 1024 * 1024;

        let mut req0: Request = surf::put(url.to_string()).into();
        let bytes0 = vec![0xF0; ONE_MB];
        req0.set_body(bytes0);

        let res0: Response =
            api.respond(req0).await.map_err(|_| anyhow!("request0 failed"))?;

        assert_eq!(StatusCode::NoContent, res0.status());

        let mut req1: Request = surf::put(url.to_string()).into();
        let bytes1 = vec![0xF0; ONE_MB + 1];
        req1.set_body(bytes1);

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request1 failed"))?;

        assert_eq!(StatusCode::BadRequest, res1.status());

        Ok(())
    }

    #[async_std::test]
    async fn blake3_authentication() -> Result<()>
    {
        // test www-authenticate
        // test auth-info
        // test scopes
        // test nonce reuse

        let (_, dbs) = setup_tmp_api().await?;

        let state = State::new(dbs.objects.clone(), dbs.tokens.clone());
        let mut foo = tide::with_state(state);
        foo.at(":id")
            .with(add_auth_info)
            .with(signed_pow_auth)
            .get(|_| async { Ok(Response::new(StatusCode::NoContent)) })
            .put(|_| async { Ok(Response::new(StatusCode::NoContent)) });

        let mut api = tide::new();
        api.at("/foo").nest(foo);

        let url = Url::parse("http://example.com/foo/bar")?;

        // don't sign the initial request
        let req0: Request = surf::get(url.to_string()).into();
        let res0: Response =
            api.respond(req0).await.map_err(|_| anyhow!("request0 failed"))?;

        // process the www-authenticate header
        let www_auth_header0 = res0
            .header("www-authenticate")
            .ok_or(anyhow!("expected www-authenticate header"))?;
        let www_auth1 = parse_asym_www_auth(www_auth_header0)?;
        let n64_1 = &www_auth1.params["nonce"];

        // sign the request this time
        let id = Id([0u8; ID_LENGTH]);

        let mut req1: Request = surf::get(url.to_string()).into();
        let blake_parts: Vec<&str> =
            www_auth1.params["algorithm"].split("$").collect();

        assert_eq!(blake_parts[0], "blake3");
        let cost: u8 = blake_parts[1].parse().unwrap();

        blake3_sign_req(&mut req1, &n64_1, cost, &id)?;
        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request1 failed"))?;

        assert_eq!(StatusCode::NoContent, res1.status());

        // grab the nextnonce
        let aih1 = res1
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info2 = parse_asym_auth_info(aih1)?;
        let n64_2 = &auth_info2.params["nextnonce"];

        let mut req2: Request = surf::put(url.to_string()).body("baz").into();
        let cost2: u8 = auth_info2.params["blake3"].parse().unwrap();
        blake3_sign_req(&mut req2, &n64_2, cost2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Unauthorized, res2.status());

        let exp_body2 = r#"{"reason":"scope mismatch","action":"create"}"#;
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(exp_body2.as_bytes(), actual_body2);

        // now use the correct scoped token
        let www_auth_header2 = res2
            .header("www-authenticate")
            .ok_or(anyhow!("expected www-authenticate header"))?;
        let www_auth3 = parse_asym_www_auth(www_auth_header2)?;
        let n64_3 = &www_auth3.params["nonce"];

        let mut req3: Request = surf::put(url.to_string()).body("baz").into();
        let blake_parts3: Vec<&str> =
            www_auth3.params["algorithm"].split("$").collect();

        assert_eq!(blake_parts[0], "blake3");
        let cost: u8 = blake_parts3[1].parse().unwrap();

        blake3_sign_req(&mut req3, &n64_3, cost, &id)?;

        let res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("request3 failed"))?;

        assert_eq!(StatusCode::NoContent, res3.status());

        // try a create
        let aih3 = res3
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info4 = parse_asym_auth_info(aih3)?;
        // todo: turns out this happens to be the right scope. need to fix the
        // auth layer so that it adds multiple auth-info headers with different
        // scope options.
        let n64_4 = &auth_info4.params["nextnonce"];
        // todo: test for scope: create

        // add some data so it's an update instead of a create
        let _ = dbs.objects.put("bar", "data".as_bytes()).await?;

        let mut req4: Request = surf::put(url.to_string()).body("qux").into();
        let cost4: u8 = auth_info4.params["blake3"].parse().unwrap();
        blake3_sign_req(&mut req4, &n64_4, cost4, &id)?;

        let res4: Response =
            api.respond(req4).await.map_err(|_| anyhow!("request4 failed"))?;

        assert_eq!(StatusCode::NoContent, res4.status());

        let mut req5: Request = surf::put(url.to_string()).body("qux").into();

        blake3_sign_req(&mut req5, &n64_4, cost4, &id)?;

        let mut res5: Response =
            api.respond(req5).await.map_err(|_| anyhow!("request5 failed"))?;

        assert_eq!(StatusCode::Unauthorized, res5.status());

        let expected_body5 = r#"{"reason":"unknown nonce","action":"update"}"#;
        let actual_body5 = res5
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body5.as_bytes(), actual_body5);

        Ok(())
    }

    #[async_std::test]
    async fn authentication() -> Result<()>
    {
        // test www-authenticate
        // test auth-info
        // test scopes
        // test nonce reuse

        let (_, dbs) = setup_tmp_api().await?;

        let state = State::new(dbs.objects.clone(), dbs.tokens.clone());
        let mut foo = tide::with_state(state);
        foo.at(":id")
            .with(add_auth_info)
            .with(signed_pow_auth)
            .get(|_| async { Ok(Response::new(StatusCode::NoContent)) })
            .put(|_| async { Ok(Response::new(StatusCode::NoContent)) });

        let mut api = tide::new();
        api.at("/foo").nest(foo);

        let url = Url::parse("http://example.com/foo/bar")?;

        // don't sign the initial request
        let req0: Request = surf::get(url.to_string()).into();
        let res0: Response =
            api.respond(req0).await.map_err(|_| anyhow!("request0 failed"))?;

        // process the www-authenticate header
        let www_auth_header0 = res0
            .header("www-authenticate")
            .ok_or(anyhow!("expected www-authenticate header"))?;

        let www_auth1 = parse_www_auth(www_auth_header0)?;
        let n64_1 = &www_auth1.params["nonce"];

        // gen a salt
        let mut salt1 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt1);
        let salt64_1 = base64::encode_config(&salt1, STANDARD_NO_PAD);

        // sign the request this time
        let id = Id([0u8; ID_LENGTH]);

        let mut req1: Request = surf::get(url.to_string()).into();
        let alg1 = &www_auth1.params["algorithm"];
        sign_req(&mut req1, &n64_1, alg1, &salt64_1, &id)?;
        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request1 failed"))?;

        assert_eq!(StatusCode::NoContent, res1.status());

        // grab the nextnonce
        let aih1 = res1
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info2 = parse_auth_info(aih1)?;
        let n64_2 = &auth_info2.params["nextnonce"];

        // try to use the nextnonce to create a reasource, it should fail
        // recall, the db is empty
        let mut salt2 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt2);
        let salt64_2 = base64::encode_config(&salt2, STANDARD_NO_PAD);

        let mut req2: Request = surf::put(url.to_string()).body("baz").into();
        let alg2 = &auth_info2.params["argon"];
        sign_req(&mut req2, &n64_2, alg2, &salt64_2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Unauthorized, res2.status());

        let exp_body2 = r#"{"reason":"scope mismatch","action":"create"}"#;
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(exp_body2.as_bytes(), actual_body2);

        // now use the correct scoped token
        let www_auth_header2 = res2
            .header("www-authenticate")
            .ok_or(anyhow!("expected www-authenticate header"))?;
        let www_auth3 = parse_www_auth(www_auth_header2)?;
        let n64_3 = &www_auth3.params["nonce"];

        let mut salt3 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt3);
        let salt64_3 = base64::encode_config(&salt3, STANDARD_NO_PAD);

        let mut req3: Request = surf::put(url.to_string()).body("baz").into();

        let alg3 = &www_auth3.params["algorithm"];
        sign_req(&mut req3, &n64_3, alg3, &salt64_3, &id)?;

        let res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("request3 failed"))?;

        assert_eq!(StatusCode::NoContent, res3.status());

        // try a create
        let aih3 = res3
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info4 = parse_auth_info(aih3)?;
        // todo: turns out this happens to be the right scope. need to fix the
        // auth layer so that it adds multiple auth-info headers with different
        // scope options.
        let n64_4 = &auth_info4.params["nextnonce"];
        // todo: test for scope: create

        // add some data so it's an update instead of a create
        let _ = dbs.objects.put("bar", "data".as_bytes()).await?;

        let mut salt4 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt4);
        let salt64_4 = base64::encode_config(&salt4, STANDARD_NO_PAD);

        let mut req4: Request = surf::put(url.to_string()).body("qux").into();

        let alg4 = &auth_info4.params["argon"];
        sign_req(&mut req4, &n64_4, alg4, &salt64_4, &id)?;

        let res4: Response =
            api.respond(req4).await.map_err(|_| anyhow!("request4 failed"))?;

        assert_eq!(StatusCode::NoContent, res4.status());

        // test nonce reuse
        let mut salt5 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt5);
        let salt64_5 = base64::encode_config(&salt5, STANDARD_NO_PAD);

        let mut req5: Request = surf::put(url.to_string()).body("qux").into();

        sign_req(&mut req5, &n64_4, alg4, &salt64_5, &id)?;

        let mut res5: Response =
            api.respond(req5).await.map_err(|_| anyhow!("request5 failed"))?;

        assert_eq!(StatusCode::Unauthorized, res5.status());

        let expected_body5 = r#"{"reason":"unknown nonce","action":"update"}"#;
        let actual_body5 = res5
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body5.as_bytes(), actual_body5);

        Ok(())
    }

    #[async_std::test]
    async fn service_get() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let n64_1 = init_nonce(&dbs.tokens, &["read"]).await?;

        let resource = "http://example.com/services/foo.json";
        let url = Url::parse(resource)?;
        let mut req1: Request = surf::get(url.to_string()).into();

        let salt1 = SALT;
        sign_req(&mut req1, &n64_1, TUNE, salt1, &id)?;
        let mut req2 = req1.clone(); // for the next request

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        // expect a 404 since the file does not exist yet
        assert_eq!(StatusCode::NotFound, res1.status());

        // get the next nonce so we can redo the request
        let aih1 = res1
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info1 = parse_auth_info(aih1)?;
        let n64_2 = &auth_info1.params["nextnonce"];

        // add the file so the next request will succeed
        let tdata = r#"{"test": "data"}"#;
        let _ = dbs.services.put("main/foo.json", &tdata.as_bytes()).await?;

        // gen a new salt and redo the request
        let mut salt2 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt2);
        let salt64_2 = base64::encode_config(&salt2, STANDARD_NO_PAD);
        let alg2 = &auth_info1.params["argon"];
        sign_req(&mut req2, &n64_2, alg2, &salt64_2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"test": "data"}"#;
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        // test branch query param

        let resource3 = "http://example.com/services/bar.json?branch=pr-add";
        let url3 = Url::parse(resource3)?;
        let mut req3: Request = surf::get(url3.to_string()).into();

        let aih3 = res2
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info3 = parse_auth_info(aih3)?;
        let n64_3 = &auth_info3.params["nextnonce"];

        let mut salt3 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt3);
        let salt64_3 = base64::encode_config(&salt3, STANDARD_NO_PAD);
        let alg3 = &auth_info3.params["argon"];

        sign_req(&mut req3, &n64_3, alg3, &salt64_3, &id)?;

        // add the file pr-add/bar.json so the next request will succeed
        let tdata3 = r#"{"newservice": "bar"}"#;
        let _ = dbs.services.put("pr-add/bar.json", &tdata3.as_bytes()).await?;

        let mut res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("request3 failed"))?;

        assert_eq!(StatusCode::Ok, res3.status());
        let expected_body3 = r#"{"newservice": "bar"}"#;
        let actual_body3 = res3
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body3.as_bytes(), &actual_body3);

        Ok(())
    }

    #[async_std::test]
    async fn services_put() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let n64 = init_nonce(&dbs.tokens, &["create", "update"]).await?;

        let resource = "http://example.com/services/foo.json";
        let url = Url::parse(resource)?;
        let mut req: Request =
            surf::put(url.to_string()).body(json!({"dummy": "data"})).into();

        let id = Id([0u8; ID_LENGTH]);
        sign_req(&mut req, &n64, TUNE, SALT, &id)?;

        let res: Response =
            api.respond(req).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::MethodNotAllowed, res.status());

        Ok(())
    }

    #[async_std::test]
    async fn services_delete() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let n64 = init_nonce(&dbs.tokens, &["delete"]).await?;

        let resource = "http://example.com/services/foo.json";
        let url = Url::parse(resource)?;
        let mut req: Request = surf::delete(url.to_string()).into();

        let id = Id([0u8; ID_LENGTH]);
        sign_req(&mut req, &n64, TUNE, SALT, &id)?;
        let res: Response =
            api.respond(req).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::MethodNotAllowed, res.status());

        Ok(())
    }

    #[async_std::test]
    async fn ssss_get() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid)?;

        let req1: Request = surf::get(url.to_string()).into();
        let req2 = req1.clone(); // for the next request
        let fut1 = api.respond(req1);
        let res1: Response =
            task::block_on(fut1).map_err(|_| anyhow!("request failed"))?;

        // expect a 404 since the file does not exist yet
        assert_eq!(StatusCode::NotFound, res1.status());

        // add the file so the next request will succeed
        let tdata = r#"{"test":"data"}"#;
        let _ = dbs.sessions.put(&sid, &tdata.as_bytes()).await?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"test":"data"}"#;
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        Ok(())
    }

    #[async_std::test]
    async fn ssss_put() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid)?;

        let req1: Request =
            surf::put(url.to_string()).body(json!({"test":"data"})).into();

        let mut res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res1.status());
        let expected_body1 = r#"{"test":"data"}"#;
        let actual_body1 = res1
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body1.as_bytes(), actual_body1);

        let stored_data = dbs.sessions.get(&sid).await?;
        assert_eq!(expected_body1.as_bytes(), stored_data);

        Ok(())
    }

    #[async_std::test]
    async fn ssss_patch() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid)?;

        let req1: Request =
            surf::patch(url.to_string()).body(json!({"patch": "me in"})).into();

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::NotFound, res1.status());

        // add the file so the next request will succeed
        let tdata = r#"{"test":"session data"}"#;
        let _ = dbs.sessions.put(&sid, &tdata.as_bytes()).await?;

        let req2: Request =
            surf::patch(url.to_string()).body(json!({"patch": "me in"})).into();

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"patch":"me in","test":"session data"}"#;
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        Ok(())
    }

    #[async_std::test]
    async fn ssss_delete() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid)?;

        // add the file so the request will succeed
        let tdata = r#"{"test":"data"}"#;
        let _ = dbs.sessions.put(&sid, &tdata.as_bytes()).await?;

        let req1: Request = surf::delete(url.to_string()).into();
        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::NoContent, res1.status());

        let req2: Request = surf::delete(url.to_string()).into();
        let res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::NoContent, res2.status());

        let req3: Request = surf::get(url.to_string()).into();
        let res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("request3 failed"))?;

        assert_eq!(StatusCode::NotFound, res3.status());

        Ok(())
    }

    async fn mb_do_req(
        api: &tide::Server<()>,
        dbs: &Dbs<impl Database>,
        signed_by: &Id,
        mut req: Request,
    ) -> Result<Response>
    {
        let nonce =
            init_nonce(&dbs.tokens, &["read", "create", "delete"]).await?;
        sign_req(&mut req, &nonce, TUNE, SALT, &signed_by)?;

        let res = api.respond(req).await.map_err(|e| anyhow!(e))?;

        Ok(res)
    }

    #[async_std::test]
    async fn mailbox_auth() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let recipient_id = Id([0u8; ID_LENGTH]);
        let recipient_keypair = KeyPair::from(&recipient_id);
        let recipient_pk = recipient_keypair.public.as_bytes();

        let urlenc_rec_pk =
            base64::encode_config(recipient_pk, base64::URL_SAFE_NO_PAD);
        let url = format!("https://example.com/mailboxes/{}", urlenc_rec_pk);

        let sender_id = Id([1u8; ID_LENGTH]);

        // 1. get your own mailbox
        //
        let req1 = surf::get(&url).build();
        let res1 = mb_do_req(&api, &dbs, &recipient_id, req1).await?;
        assert_eq!(res1.status(), StatusCode::Ok);

        // 2. get someone else's mailbox
        //
        let req2 = surf::get(&url).build();
        let res2 = mb_do_req(&api, &dbs, &sender_id, req2).await?;
        assert_eq!(res2.status(), StatusCode::Forbidden);

        // 3. post to someone's mailbox
        //
        let body = MessageRequest {
            uuid: "1111".to_string(),
            action: "packed".to_string(),
            data: json!("message data is opaque"),
        };
        let req3 = surf::post(&url).body(serde_json::to_string(&body)?).build();
        let res3 = mb_do_req(&api, &dbs, &sender_id, req3).await?;
        assert_eq!(res3.status(), StatusCode::Created);

        // 4 delete someone else's message (even if you created it)
        //
        let req4 = surf::delete(&url).build();
        let res4 = mb_do_req(&api, &dbs, &sender_id, req4).await?;
        assert_eq!(res4.status(), StatusCode::Forbidden);

        Ok(())
    }

    #[async_std::test]
    async fn mailbox_actions() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let recipient_id = Id([0u8; ID_LENGTH]);
        let recipient_pk = KeyPair::from(&recipient_id).public;

        let sender_id = Id([2u8; ID_LENGTH]);
        let sender_pk = KeyPair::from(&sender_id).public;
        let sender_pk_b64 = base64::encode(sender_pk);

        let urlenc_rec_pk =
            base64::encode_config(recipient_pk, base64::URL_SAFE_NO_PAD);
        let url = format!("https://example.com/mailboxes/{}", urlenc_rec_pk);

        // 1. get empty mailbox
        //
        let req1 = surf::get(&url).build();
        let mut res1 = mb_do_req(&api, &dbs, &recipient_id, req1).await?;
        assert_eq!(res1.status(), StatusCode::Ok);
        let bytes1 =
            res1.take_body().into_bytes().await.map_err(|e| anyhow!(e))?;
        let body1: Mailbox = serde_json::from_slice(&bytes1)?;
        assert_eq!(body1, Mailbox { messages: vec!() });

        // 2. post a new message and check the stored message
        //
        let req_body2 = MessageRequest {
            uuid: "1111".to_string(),
            action: "packed".to_string(),
            data: json!({"info": "message data is opaque"}),
        };
        let req2 =
            surf::post(&url).body(serde_json::to_string(&req_body2)?).build();
        let mut res2 = mb_do_req(&api, &dbs, &sender_id, req2).await?;
        assert_eq!(res2.status(), StatusCode::Created);

        let expected2 = MessageStored {
            id: 1,
            uuid: "1111".to_string(),
            action: "packed".to_string(),
            from: sender_pk_b64.clone(),
            data: json!({"info": "message data is opaque"}),
        };
        let bytes2 =
            res2.take_body().into_bytes().await.map_err(|e| anyhow!(e))?;
        let body2: MessageStored = serde_json::from_slice(&bytes2)?;
        assert_eq!(body2, expected2);

        // 3. post message 2 and ensure the resulting id has been incremented
        //
        let req_body3 = MessageRequest {
            uuid: "2222".to_string(),
            action: "packed".to_string(),
            data: json!(42),
        };
        let req3 =
            surf::post(&url).body(serde_json::to_string(&req_body3)?).build();
        let mut res3 = mb_do_req(&api, &dbs, &sender_id, req3).await?;
        assert_eq!(res3.status(), StatusCode::Created);

        let expected = MessageStored {
            id: 2,
            uuid: "2222".to_string(),
            action: "packed".to_string(),
            from: sender_pk_b64.clone(),
            data: json!(42),
        };
        let bytes3 =
            res3.take_body().into_bytes().await.map_err(|e| anyhow!(e))?;
        let body3: MessageStored = serde_json::from_slice(&bytes3)?;
        assert_eq!(body3, expected);

        // 4. delete both messages
        //
        let body4 = vec![
            MessageToDelete { from: sender_pk_b64.clone(), id: 1 },
            MessageToDelete { from: sender_pk_b64.clone(), id: 2 },
        ];
        let req4 =
            surf::delete(&url).body(serde_json::to_string(&body4)?).build();

        let res4 = mb_do_req(&api, &dbs, &recipient_id, req4).await?;
        assert_eq!(res4.status(), StatusCode::NoContent);

        // 5. mailbox should once again be empty
        //
        let req5 = surf::get(&url).build();
        let mut res5 = mb_do_req(&api, &dbs, &recipient_id, req5).await?;
        assert_eq!(res5.status(), StatusCode::Ok);
        let bytes5 =
            res5.take_body().into_bytes().await.map_err(|e| anyhow!(e))?;
        let body5: Mailbox = serde_json::from_slice(&bytes5)?;
        assert_eq!(body5, Mailbox { messages: vec!() });

        Ok(())
    }

    #[async_std::test]
    async fn vault_get() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let nonce_b64 = init_nonce(&dbs.tokens, &["read"]).await?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let vid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("http://example.com/vaults/")?;
        let url = base.join(&vid)?;

        let mut req1: Request = surf::get(url.to_string()).into();
        sign_req(&mut req1, &nonce_b64, TUNE, SALT, &id)?;

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::NotFound, res1.status());

        // add data

        let tdata_json1 = json!({
            "data": b"vault data is opaque",
            "vclock": { "c": { "c1": 1, "c2": 3, "c3": 2 } }
        });
        let tdata_vec1 = serde_json::to_vec(&tdata_json1)?;
        let _ = dbs.vaults.put(&vid, &tdata_vec1).await?;

        let mut req2: Request = surf::get(url.to_string()).into();
        sign_req_using_res_with_id(&res1, &mut req2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());

        let vc_hdr_str = res2
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();
        let expected_vclock = "c1=1,c2=3,c3=2";
        assert_eq!(expected_vclock, vc_hdr_str);

        let expected_body = "vault data is opaque";
        let actual_body = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body.as_bytes(), actual_body);

        // use the wrong identity
        let bad_id_bytes = [0xFFu8; uno::ID_LENGTH];
        let bad_id = uno::Id(bad_id_bytes);

        let mut req3: Request = surf::get(url.to_string()).into();
        sign_req_using_res_with_id(&res2, &mut req3, &bad_id)?;

        let res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Forbidden, res3.status());

        // test migrate

        let tdata_bytes4 = b"vault data is migrating";
        let _ = dbs.vaults.put_version("v1", &vid, &*tdata_bytes4).await?;
        let _ = dbs.vaults.del(&vid).await?;

        let mut req4: Request = surf::get(url.to_string()).into();
        sign_req_using_res_with_id(&res3, &mut req4, &id)?;

        let mut res4: Response =
            api.respond(req4).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res4.status());

        let vc_hdr_str4 = res4
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();
        let expected_vclock4 = "";
        assert_eq!(expected_vclock4, vc_hdr_str4);

        let expected_body4 = "vault data is migrating";
        let actual_body4 = res4
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body4, String::from_utf8(actual_body4)?);

        Ok(())
    }

    #[async_std::test]
    async fn vault_put() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let nonce_b64 = init_nonce(&dbs.tokens, &["create", "update"]).await?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let vid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("http://example.com/vaults/")?;
        let url = base.join(&vid)?;
        let mut vc = VClock::new("c1");

        // don't attach the vclock, req1 should fail

        let mut req1: Request =
            surf::put(url.to_string()).body("vault data is opaque").into();
        sign_req(&mut req1, &nonce_b64, TUNE, SALT, &id)?;

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::BadRequest, res1.status());

        // add the vclock

        let mut req2: Request = surf::put(url.to_string())
            .header("vclock", api::write_vclock(&vc)?)
            .body("vault data is opaque")
            .into();

        let nonce2_b64 = init_nonce(&dbs.tokens, &["create", "update"]).await?;
        sign_req(&mut req2, &nonce2_b64, TUNE, SALT, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());

        let vc_hdr_str2 = res2
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();

        assert_eq!("c1=1", vc_hdr_str2);

        let expected_body2 = "vault data is opaque";
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body2.as_bytes(), actual_body2);

        // use the wrong identity

        let bad_id_bytes = [0xFFu8; uno::ID_LENGTH];
        let bad_id = uno::Id(bad_id_bytes);

        let mut req3: Request = surf::get(url.to_string()).into();
        sign_req_using_res_with_id(&res2, &mut req3, &bad_id)?;

        let res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Forbidden, res3.status());

        let mut req4: Request = surf::put(url.to_string())
            .header("vclock", api::write_vclock(&vc)?)
            .body("vault data is outdated")
            .into();
        sign_req_using_res_with_id(&res3, &mut req4, &id)?;

        let mut res4: Response =
            api.respond(req4).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Conflict, res4.status());

        let expected_body4 = format!(
            "{{\"error\": \"causality violation\", \"vault\": {}}}",
            serde_json::to_string(b"vault data is opaque")?
        );
        let actual_body4 = res4
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body4, String::from_utf8(actual_body4)?);

        // increment the clock

        vc.incr("c1");

        let mut req5: Request = surf::put(url.to_string())
            .header("vclock", api::write_vclock(&vc)?)
            .body("vault data is fresh")
            .into();
        sign_req_using_res_with_id(&res4, &mut req5, &id)?;

        let mut res5: Response =
            api.respond(req5).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res5.status());

        let vc_hdr_str5 = res5
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();

        assert_eq!("c1=2", vc_hdr_str5);

        let expected_body5 = "vault data is fresh";
        let actual_body5 = res5
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body5.as_bytes(), actual_body5);

        // simulate foreign write

        vc.incr("c1");

        let mut req6: Request = surf::put(url.to_string())
            .header("vclock", api::write_vclock(&vc)?)
            .body("vault data is incoming")
            .into();
        sign_req_using_res_with_id(&res5, &mut req6, &id)?;

        let tdata_json6 = json!({
            "data": b"vault data is foreign",
            "vclock": { "c": { "c1": 2, "c2": 1 } }
        });
        let tdata_vec6 = serde_json::to_vec(&tdata_json6)?;
        let _ = dbs.vaults.put(&vid, &tdata_vec6).await?;

        let res6: Response =
            api.respond(req6).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Conflict, res6.status());

        let vc_hdr_str6 = res6
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();
        assert_eq!("c1=2,c2=1", vc_hdr_str6);

        // correct the timeline

        vc.incr("c2"); // we've seen client 2's change

        let mut req7: Request = surf::put(url.to_string())
            .header("vclock", api::write_vclock(&vc)?)
            .body("vault data is merged")
            .into();
        sign_req_using_res_with_id(&res6, &mut req7, &id)?;

        let mut res7: Response =
            api.respond(req7).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res7.status());

        let vc_hdr_str7 = res7
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();

        assert_eq!("c1=3,c2=1", vc_hdr_str7);

        let expected_body7 = "vault data is merged";
        let actual_body7 = res7
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body7.as_bytes(), actual_body7);

        // malformed vclock

        let mut req8: Request = surf::put(url.to_string())
            .header("vclock", "c1=nope")
            .body("vault data is irrelevant")
            .into();
        sign_req_using_res_with_id(&res7, &mut req8, &id)?;

        let res8: Response =
            api.respond(req8).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::BadRequest, res8.status());

        let mut req9: Request = surf::put(url.to_string())
            .header("vclock", "not an rfc8941 map")
            .body("vault data is irrelevant")
            .into();
        sign_req_using_res_with_id(&res8, &mut req9, &id)?;

        let res9: Response =
            api.respond(req9).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::BadRequest, res9.status());

        Ok(())
    }

    // This tests that the server can read the data that the server wrote.
    // Technically tested during the put tests but not explicitly.
    #[async_std::test]
    async fn vault_roundtrip() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let nonce_b64 = init_nonce(&dbs.tokens, &["create", "update"]).await?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let vid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("http://example.com/vaults/")?;
        let url = base.join(&vid)?;
        let mut vc = VClock::new("cz");

        // we'll make it version 5
        vc.incr("cz");
        vc.incr("cz");
        vc.incr("cz");
        vc.incr("cz");

        // put data

        let mut req1: Request = surf::put(url.to_string())
            .header("vclock", api::write_vclock(&vc)?)
            .body("vault data is opaque")
            .into();
        sign_req(&mut req1, &nonce_b64, TUNE, SALT, &id)?;

        let mut res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res1.status());

        let vc_hdr_str = res1
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();
        let expected_vclock = "cz=5";
        assert_eq!(expected_vclock, vc_hdr_str);

        let expected_body1 = "vault data is opaque";
        let actual_body1 = res1
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body1, std::str::from_utf8(&actual_body1)?);

        let expected_data_json2 = json!({
            "data": b"vault data is opaque",
            "vclock": { "c": { "cz": 5 } }
        });
        let expected_data_str2 = serde_json::to_string(&expected_data_json2)?;

        let stored_data2 = dbs.vaults.get(&vid).await?;

        assert_eq!(expected_data_str2, String::from_utf8(stored_data2)?);

        // get data

        let mut req2: Request = surf::get(url.to_string()).into();
        sign_req_using_res_with_id(&res1, &mut req2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());

        let vc_hdr_str = res2
            .header("vclock")
            .ok_or(anyhow!("expected vclock"))?
            .last()
            .as_str();
        let expected_vclock = "cz=5";
        assert_eq!(expected_vclock, vc_hdr_str);

        let expected_body2 = "vault data is opaque";
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body2.as_bytes(), actual_body2);

        Ok(())
    }

    #[async_std::test]
    async fn share_roundtrip() -> Result<()>
    {
        let (api, _) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let sid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("https://example.com/shares/")?;
        let url = base.join(&sid)?;

        //XXX: won't work after the year 2120!
        let j = json!({"id": sid, "schema_version": 0, "expires_at": "2120-03-12T13:37:27+00:00", "encrypted_credential": "1234"});
        let post: Request = surf::post(url.to_string()).body(j).into();

        let res1: Response =
            api.respond(post).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Created, res1.status());

        let get: Request = surf::get(url.to_string()).into();
        let res2: Response =
            api.respond(get).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());

        Ok(())
    }

    #[async_std::test]
    async fn vault_delete() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let nonce_b64 = init_nonce(&dbs.tokens, &["delete"]).await?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let vid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("http://example.com/vaults/")?;
        let url = base.join(&vid)?;

        // put a vault to be deleted
        dbs.vaults.put(&vid, b"data").await?;
        assert_eq!(true, dbs.vaults.exists(&vid).await?);

        let mut req1: Request = surf::delete(url.to_string()).into();
        sign_req(&mut req1, &nonce_b64, TUNE, SALT, &id)?;

        let res1: Response = api
            .respond(req1)
            .await
            .map_err(|e| anyhow!(e))
            .context("req1 delete failed")?;

        assert_eq!(StatusCode::NoContent, res1.status());
        // make sure the data is gone
        assert_eq!(false, dbs.vaults.exists(&vid).await?);

        let mut req2: Request = surf::delete(url.to_string()).into();
        sign_req_using_res_with_id(&res1, &mut req2, &id)?;

        let res2: Response = api
            .respond(req2)
            .await
            .map_err(|e| anyhow!(e))
            .context("req2 delete failed")?;

        assert_eq!(StatusCode::NoContent, res2.status());

        Ok(())
    }

    #[async_std::test]
    async fn service_list_get() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let n64_1 = init_nonce(&dbs.tokens, &["read"]).await?;

        let resource = "http://example.com/service_list/services.json";
        let url = Url::parse(resource)?;
        let mut req1: Request = surf::get(url.to_string()).into();

        let salt1 = SALT;
        sign_req(&mut req1, &n64_1, TUNE, salt1, &id)?;
        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        // expect a 404 since the file does not exist yet
        assert_eq!(StatusCode::NotFound, res1.status());

        // add the file so the next request will succeed
        let tdata = r#"{"test": "data"}"#;
        let _ = dbs.services.put("services.json", &tdata.as_bytes()).await?;

        let mut req2: Request = surf::get(url.to_string()).into();
        sign_req_using_res_with_id(&res1, &mut req2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"test": "data"}"#;
        let actual_body2 = res2
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        Ok(())
    }

    const MIN_COST: u8 = 1;

    #[async_std::test]
    async fn directory_roundtrip() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let n64_1 = init_nonce(&dbs.tokens, &["read"]).await?;

        let resource = "http://example.com/directory/lookup";
        let url = Url::parse(resource)?;
        let mut req1: Request = surf::get(url.to_string()).into();

        //let mut req2 = req1.clone(); // for the next request

        blake3_sign_req(&mut req1, &n64_1, MIN_COST, &id)?;

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::BadRequest, res1.status());

        let phone = "15005550000";
        let cid = cid_from_phone(&phone);

        // TODO post entry and receive from lookup

        Ok(())
    }

    #[async_std::test]
    async fn directory_lookup_query() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let n64_1 = init_nonce(&dbs.tokens, &["read"]).await?;

        let resource = "http://example.com/directory/lookup";

        let numbers = vec![
            "15005550001",
            "5005550002",
            "+1 500 555 0003",
            "500.555.0004",
            "1 (500) 555-0005",
            "not a number",
            "15005559000", // not found
        ];

        let owned_numbers =
            numbers.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        let body1 = LookupQuery {
            country: "US".into(),
            phone_numbers: owned_numbers.clone(),
        };
        let body1_bytes = serde_json::to_vec(&body1)?;

        let mut req1: Request =
            surf::get(resource).body_bytes(body1_bytes).build();

        blake3_sign_req(&mut req1, &n64_1, MIN_COST, &id)?;

        let mut res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        // the db is empty. expect a 200 with empty cids and errors arrays

        assert_eq!(StatusCode::Ok, res1.status());

        let res1_body: LookupResult = res1
            .take_body()
            .into_json()
            .await
            .map_err(|_| anyhow!("deserialize body1"))?;

        let expected_body1 =
            LookupResult { cids: Vec::new(), errors: Vec::new() };

        assert_eq!(expected_body1, res1_body);

        // add a phone number to the lookup table

        let phone2 = "15005550001";
        let cid2 = cid_from_phone(&phone2);
        let item2 = LookupItem { cid: cid2.clone() };
        let item2_bytes = serde_json::to_vec(&item2)?;
        let key2 = format!("lookup/{}", phone2);
        dbs.directory.put(key2, &item2_bytes).await?;

        let mut req2 = surf::post(resource)
            .body_json(&json!({
                "country": "US".to_string(),
                "phone_numbers": owned_numbers.clone(),
            }))
            .map_err(|_| anyhow!("req2 body json"))?
            .build();

        asym_sign_req_using_res_with_id(&res1, &mut req2, &id)?;

        let mut res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("req2 error"))?;

        assert_eq!(StatusCode::Ok, res2.status());

        let res2_body: LookupResult = res2
            .take_body()
            .into_json()
            .await
            .map_err(|_| anyhow!("deserialize res2 body"))?;

        let expected_body2 = LookupResult {
            cids: vec![LookupItemClientSuccess {
                phone_number: String::from(phone2),
                cid: cid2.clone(),
            }],
            errors: Vec::new(),
        };

        assert_eq!(expected_body2, res2_body);

        // add a few more entries

        let phone3_1 = "15005550001";
        let cid3_1 = cid_from_phone(&phone3_1);
        let item3_1 = LookupItem { cid: cid3_1.clone() };
        let item3_1_bytes = serde_json::to_vec(&item3_1)?;
        let key3_1 = format!("lookup/{}", phone3_1);

        let phone3_2 = "5005550002";
        let cid3_2 = cid_from_phone(&phone3_2);
        let item3_2 = LookupItem { cid: cid3_2.clone() };
        let item3_2_bytes = serde_json::to_vec(&item3_2)?;
        let key3_2 = format!("lookup/{}", phone3_2);

        let phone3_3 = "+1 500 555 0003";
        let cid3_3 = cid_from_phone(&phone3_3);
        let item3_3 = LookupItem { cid: cid3_3.clone() };
        let item3_3_bytes = serde_json::to_vec(&item3_3)?;
        let key3_3 = format!("lookup/{}", phone3_3);

        dbs.directory.put(key3_1, &item3_1_bytes).await?;
        dbs.directory.put(key3_2, &item3_2_bytes).await?;
        dbs.directory.put(key3_3, &item3_3_bytes).await?;

        let mut req3 = surf::post(resource)
            .body_json(&json!({
                "country": "US".to_string(),
                "phone_numbers": owned_numbers.clone(),
            }))
            .map_err(|_| anyhow!("req3 body json"))?
            .build();

        asym_sign_req_using_res_with_id(&res2, &mut req3, &id)?;

        let mut res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("req3 error"))?;

        assert_eq!(StatusCode::Ok, res3.status());

        let res3_body: LookupResult = res3
            .take_body()
            .into_json()
            .await
            .map_err(|_| anyhow!("deserialize res3 body"))?;

        let phone3_1 = "15005550001";
        let result3_1 = LookupItemClientSuccess {
            phone_number: phone3_1.into(),
            cid: cid_from_phone(&phone3_1),
        };

        let phone3_2 = "5005550002";
        let result3_2 = LookupItemClientSuccess {
            phone_number: phone3_2.into(),
            cid: cid_from_phone(&phone3_2),
        };

        let phone3_3 = "+1 500 555 0003";
        let result3_3 = LookupItemClientSuccess {
            phone_number: phone3_3.into(),
            cid: cid_from_phone(&phone3_3),
        };

        let phone3_4 = "555.500.0004";
        let result3_4 = LookupItemClientSuccess {
            phone_number: phone3_4.into(),
            cid: cid_from_phone(&phone3_4),
        };

        let phone3_5 = "+1 (555) 500-0005";
        let result3_5 = LookupItemClientSuccess {
            phone_number: phone3_5.into(),
            cid: cid_from_phone(&phone3_5),
        };

        let phone3_6 = "not a number";
        let result3_6 = LookupItemClientSuccess {
            phone_number: phone3_6.into(),
            cid: cid_from_phone(&phone3_6),
        };

        let phone3_7 = "15005559000";
        let result3_7 = LookupItemClientSuccess {
            phone_number: phone3_7.into(),
            cid: cid_from_phone(&phone3_7),
        };

        assert_eq!(res3_body.cids.contains(&result3_1), true);
        assert_eq!(res3_body.cids.contains(&result3_2), true);
        assert_eq!(res3_body.cids.contains(&result3_3), true);
        assert_eq!(res3_body.cids.contains(&result3_4), false);
        assert_eq!(res3_body.cids.contains(&result3_5), false);
        assert_eq!(res3_body.cids.contains(&result3_6), false);
        assert_eq!(res3_body.cids.contains(&result3_7), false);
        assert_eq!(res3_body.errors.is_empty(), true);

        // TODO: are there edge cases?

        Ok(())
    }

    fn cid_from_phone(phone: &str) -> String
    {
        let hash = blake3::hash(phone.as_bytes());
        let bytes = hash.as_bytes();

        base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
    }

    #[async_std::test]
    async fn directory_entry_roundtrip() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let id_pub_b64 = id_to_b64(&id);

        let n64_1 = init_nonce(&dbs.tokens, &["update"]).await?;

        let resource = "http://example.com/directory/entries";

        let phone = "15005550000";
        let cid = cid_from_phone(&phone);

        let request_body = json!({
           "phone": phone,
           "country": "US",
           "signing_key": id_pub_b64,
           "encryption_key": "unimportant",
        });

        let mut req1: Request = surf::post(resource)
            .body_json(&request_body)
            .map_err(|_| anyhow!("serialize body"))?
            .build();

        blake3_sign_req(&mut req1, &n64_1, MIN_COST, &id)?;

        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::PaymentRequired, res1.status());

        // assert that a pending entry was created
        let pending_key = format!("pending/{}", &phone);
        let pending_entry = dbs
            .directory
            .get(pending_key)
            .await
            .context("get pending object")?;
        let pending_obj: PendingItem = serde_json::from_slice(&pending_entry)?;

        assert_eq!(id_pub_b64, pending_obj.user);
        assert_eq!("verification-disabled", pending_obj.sid);

        let mut req2: Request = surf::post(resource)
            .body_json(&request_body)
            .map_err(|_| anyhow!("serialize body2"))?
            .header("verification", "XXXXXX")
            .build();

        asym_sign_req_using_res_with_id(&res1, &mut req2, &id)?;

        let res2: Response =
            api.respond(req2).await.map_err(|_| anyhow!("request 2 failed"))?;

        assert_eq!(StatusCode::Created, res2.status());

        let location = res2
            .header("location")
            .ok_or(anyhow!("missing location header"))?
            .last()
            .as_str();

        assert_eq!(cid, location);

        // get the entry and check the data
        let created_resource = format!("{}/{}", resource, location);
        let mut req3 = surf::get(created_resource).build();

        asym_sign_req_using_res_with_id(&res2, &mut req3, &id)?;

        let mut res3: Response =
            api.respond(req3).await.map_err(|_| anyhow!("req 3 failed"))?;

        assert_eq!(StatusCode::Ok, res3.status());

        let actual_body = res3
            .take_body()
            .into_bytes()
            .await
            .map_err(|_| anyhow!("res3 body"))?;

        let actual_obj: DirectoryEntry = serde_json::from_slice(&actual_body)?;

        let expected_entry = DirectoryEntry {
            signing_key: id_pub_b64,
            encryption_key: "unimportant".into(),
        };

        assert_eq!(expected_entry, actual_obj);

        Ok(())
    }

    #[async_std::test]
    async fn directory_entry_post() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let n64_1 = init_nonce(&dbs.tokens, &["create", "read"]).await?;

        let phone = "15005550000";
        let cid = cid_from_phone(&phone);

        let resource = format!("http://example.com/directory/entries/{}", cid);

        let mut req1: Request = surf::get(&resource).build();
        blake3_sign_req(&mut req1, &n64_1, MIN_COST, &id)?;
        let res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::NotFound, res1.status());

        // TODO: test all edge cases

        Ok(())
    }

    #[async_std::test]
    async fn directory_entry_get() -> Result<()>
    {
        let (api, dbs) = setup_tmp_api().await?;

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let uid = id_to_b64url(&id);

        let n64_1 = init_nonce(&dbs.tokens, &["read"]).await?;

        let phone = "15005550000";
        let cid = cid_from_phone(&phone);

        let resource = format!("http://example.com/directory/entries/{}", cid);

        let expected =
            DirectoryEntry { signing_key: uid, encryption_key: "bar".into() };

        let expected_entry_string = serde_json::to_string(&expected)?;

        let internal =
            DirectoryEntryInternal { entry: expected, phone: phone.into() };

        let db_bytes = serde_json::to_vec(&internal)?;

        let entry_key = format!("entries/{}", cid);
        dbs.directory.put(entry_key, &db_bytes).await?;

        let mut req1: Request = surf::get(&resource).build();
        blake3_sign_req(&mut req1, &n64_1, MIN_COST, &id)?;
        let mut res1: Response =
            api.respond(req1).await.map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res1.status());

        let actual_entry_string =
            res1.take_body().into_string().await.map_err(|e| anyhow!(e))?;
        assert_eq!(expected_entry_string, actual_entry_string);

        Ok(())
    }

    fn id_to_b64url(id: &Id) -> String
    {
        let keypair = KeyPair::from(id);
        let pubkey = keypair.public.as_bytes();

        base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD)
    }

    fn id_to_b64(id: &Id) -> String
    {
        let keypair = KeyPair::from(id);
        let pubkey = keypair.public.as_bytes();

        base64::encode_config(&pubkey, base64::STANDARD)
    }

    #[allow(dead_code)]
    fn print_body(res: &mut Response) -> Result<()>
    {
        let body_bytes = task::block_on(res.take_body().into_bytes())
            .map_err(|_| anyhow!("error reading body"))?;
        println!("{:?}", String::from_utf8(body_bytes.clone()));
        res.set_body(body_bytes);
        Ok(())
    }
}
