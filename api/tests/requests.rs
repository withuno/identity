#[cfg(test)]
mod requests {
    use api::{add_auth_info, build_api, signed_pow_auth};
    use api::mailbox::{
        Mailbox, MessageRequest, MessageStored, MessageToDelete, Payload,
    };

    use api::State;
    use tide::{Body, Response, StatusCode};

    use anyhow::anyhow;
    use anyhow::bail;
    use async_std::task;

    use base64::STANDARD_NO_PAD;
    use base64::URL_SAFE_NO_PAD;

    use rand::RngCore;
    use serde_json::json;

    use std::collections::HashMap;
    use std::convert::From;
    use std::convert::TryFrom;

    use surf::Request;
    use surf::Url;

    use uno::Id;
    use uno::KeyPair;
    use uno::Mu;
    use uno::Session;
    use uno::Signer;
    use uno::ID_LENGTH;
    use uno::MU_LENGTH;

    use api::Database;

    const TUNE: &str = "$argon2d$v=19$m=4096,t=3,p=1";
    const SALT: &str = "cm9ja3NhbHQ";

    struct Dbs<T: Database> {
        tokens: T,
        vaults: T,
        services: T,
        sessions: T,
        mailboxes: T,
        objects: T,
    }

    #[cfg(not(feature = "s3"))]
    pub use api::store::FileStore;

    #[cfg(not(feature = "s3"))]
    fn setup_tmp_api() -> anyhow::Result<(tide::Server<()>, Dbs<FileStore>)> {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();

        let dbs = Dbs {
            objects: FileStore::new(dir.path().as_os_str()).unwrap(),
            tokens: FileStore::new(dir.path().as_os_str()).unwrap(),
            vaults: FileStore::new(dir.path().as_os_str()).unwrap(),
            services: FileStore::new(dir.path().as_os_str()).unwrap(),
            sessions: FileStore::new(dir.path().as_os_str()).unwrap(),
            mailboxes: FileStore::new(dir.path().as_os_str()).unwrap(),
        };

        // we don't include objects db here because its only used in tests
        let api = build_api(
            dbs.tokens.clone(),
            dbs.vaults.clone(),
            dbs.services.clone(),
            dbs.sessions.clone(),
            dbs.mailboxes.clone(),
        )?;
        Ok((api, dbs))
    }

    #[cfg(feature = "s3")]
    pub use api::store::S3Store;

    #[cfg(feature = "s3")]
    fn setup_tmp_api() -> anyhow::Result<(tide::Server<()>, Dbs<S3Store>)> {
        // modified from:
        // https://doc.servo.org/src/tempfile/util.rs.html#9
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        use std::str;

        fn tmpname(rand_len: usize) -> String {
            let mut buf = String::with_capacity(rand_len);

            // Push each character in one-by-one. Unfortunately, this is the only
            // safe(ish) simple way to do this without allocating a temporary
            // String/Vec.
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
            )?,
            tokens: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
            )?,
            vaults: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
            )?,
            services: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
            )?,
            sessions: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
            )?,
            mailboxes: S3Store::new(
                "http://localhost:9000",
                "minio",
                "minioadmin",
                "minioadmin",
                &tmpname(32),
            )?,
        };

        async_std::task::block_on(dbs.objects.create_bucket_if_not_exists())?;
        async_std::task::block_on(dbs.tokens.create_bucket_if_not_exists())?;
        async_std::task::block_on(dbs.vaults.create_bucket_if_not_exists())?;
        async_std::task::block_on(dbs.services.create_bucket_if_not_exists())?;
        async_std::task::block_on(dbs.sessions.create_bucket_if_not_exists())?;
        async_std::task::block_on(
            dbs.mailboxes.create_bucket_if_not_exists(),
        )?;

        async_std::task::block_on(dbs.objects.empty_bucket())?;
        async_std::task::block_on(dbs.tokens.empty_bucket())?;
        async_std::task::block_on(dbs.vaults.empty_bucket())?;
        async_std::task::block_on(dbs.services.empty_bucket())?;
        async_std::task::block_on(dbs.sessions.empty_bucket())?;
        async_std::task::block_on(dbs.mailboxes.empty_bucket())?;

        // we don't include objects db here because its only used in tests
        let api = build_api(
            dbs.tokens.clone(),
            dbs.vaults.clone(),
            dbs.services.clone(),
            dbs.sessions.clone(),
            dbs.mailboxes.clone(),
        )?;
        Ok((api, dbs))
    }

    // Add the correct authorization header to the request
    fn sign_req(
        req: &mut Request,
        n64: &str,
        argon: &str,
        s64: &str,
        id: &Id,
    ) -> anyhow::Result<()> {
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
        // println!("sign challenge: {:?}", &challenge);

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

    struct AuthInfoTemp {
        params: HashMap<String, String>,
    }

    struct WwwAuthTemp {
        params: HashMap<String, String>,
    }

    fn parse_www_auth(header: &str) -> anyhow::Result<WwwAuthTemp> {
        let items = match header.strip_prefix("tuned-digest-signature") {
            Some(s) => s.trim().split(';'),
            None => {
                bail!("wrong auth type");
            }
        };

        let mut map = HashMap::new();
        for i in items {
            let kv: Vec<&str> = i.trim().splitn(2, "=").collect();
            map.insert(kv[0].into(), kv[1].into());
        }
        let keys = ["nonce", "algorithm", "actions"];
        if keys
            .iter()
            .fold(true, |a, k| a && map.contains_key(&k.to_string()))
        {
            Ok(WwwAuthTemp { params: map })
        } else {
            Err(anyhow!("invalid www-auth"))
        }
    }

    fn parse_auth_info(header: &str) -> anyhow::Result<AuthInfoTemp> {
        let items = header.trim().split(';');
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
            Ok(AuthInfoTemp { params: map })
        } else {
            Err(anyhow!("invalid auth-info"))
        }
    }

    fn init_nonce(
        token_db: &impl Database,
        scopes: &[&'static str],
    ) -> anyhow::Result<String> {
        let n64 = "U4L+xVHzX4qzBSDPv5NJMhB2HJuhkksmFqJe7geX+xA";
        let n = base64::decode_config(&n64, STANDARD_NO_PAD)?;
        let n64url = base64::encode_config(&n, URL_SAFE_NO_PAD);
        let token = json!({"argon":TUNE,"allow":scopes});
        let tstr = token.to_string();
        let tok_bytes = tstr.as_bytes();
        let _ = task::block_on(token_db.put(&n64url, tok_bytes))?;
        Ok(n64.into())
    }

    #[test]
    fn v1_health_get() -> anyhow::Result<()> {
        let (api, _) = setup_tmp_api().unwrap();

        let req: Request = surf::get("http://example.com/health").into();
        let res: Response = task::block_on(api.respond(req))
            .map_err(|_| anyhow!("request failed"))?;
        assert_eq!(StatusCode::NoContent, res.status());
        Ok(())
    }

    #[test]
    fn v1_authentication() -> anyhow::Result<()> {
        // test www-authenticate
        // test auth-info
        // test scopes
        // test nonce reuse

        let (_, dbs) = setup_tmp_api().unwrap();

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
        let res0: Response = task::block_on(api.respond(req0))
            .map_err(|_| anyhow!("request0 failed"))?;

        // process the www-authenticate header
        let www_auth_header0 = res0
            .header("www-authenticate")
            .ok_or(anyhow!("expected www-authenticate header"))?;
        let www_auth1 = parse_www_auth(www_auth_header0.last().as_str())?;
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
        let res1: Response = task::block_on(api.respond(req1))
            .map_err(|_| anyhow!("request1 failed"))?;

        assert_eq!(StatusCode::NoContent, res1.status());

        // grab the nextnonce
        let aih1 = res1
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info2 = parse_auth_info(aih1.last().as_str())?;
        let n64_2 = &auth_info2.params["nextnonce"];

        // try to use the nextnonce to create a reasource, it should fail
        // recall, the db is empty
        let mut salt2 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt2);
        let salt64_2 = base64::encode_config(&salt2, STANDARD_NO_PAD);

        let mut req2: Request = surf::put(url.to_string()).body("baz").into();
        let alg2 = &auth_info2.params["argon"];
        sign_req(&mut req2, &n64_2, alg2, &salt64_2, &id)?;

        let mut res2: Response = task::block_on(api.respond(req2))
            .map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Unauthorized, res2.status());

        let exp_body2 = r#"{"reason":"scope mismatch","action":"create"}"#;
        let actual_body2 = task::block_on(res2.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(exp_body2.as_bytes(), actual_body2);

        // now use the correct scoped token
        let www_auth_header2 = res2
            .header("www-authenticate")
            .ok_or(anyhow!("expected www-authenticate header"))?;
        let www_auth3 = parse_www_auth(www_auth_header2.last().as_str())?;
        let n64_3 = &www_auth3.params["nonce"];

        let mut salt3 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt3);
        let salt64_3 = base64::encode_config(&salt3, STANDARD_NO_PAD);

        let mut req3: Request = surf::put(url.to_string()).body("baz").into();

        let alg3 = &www_auth3.params["algorithm"];
        sign_req(&mut req3, &n64_3, alg3, &salt64_3, &id)?;

        let fut3 = api.respond(req3);
        let res3: Response =
            task::block_on(fut3).map_err(|_| anyhow!("request3 failed"))?;

        assert_eq!(StatusCode::NoContent, res3.status());

        // try a create
        let aih3 = res3
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info4 = parse_auth_info(aih3.last().as_str())?;
        // todo: turns out this happens to be the right scope. need to fix the
        // auth layer so that it adds multiple auth-info headers with different
        // scope options.
        let n64_4 = &auth_info4.params["nextnonce"];
        // todo: test for scope: create

        // add some data so it's an update instead of a create
        let _ = task::block_on(dbs.objects.put("bar", "data".as_bytes()))?;

        let mut salt4 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt4);
        let salt64_4 = base64::encode_config(&salt4, STANDARD_NO_PAD);

        let mut req4: Request = surf::put(url.to_string()).body("qux").into();

        let alg4 = &auth_info4.params["argon"];
        sign_req(&mut req4, &n64_4, alg4, &salt64_4, &id)?;

        let fut4 = api.respond(req4);
        let res4: Response =
            task::block_on(fut4).map_err(|_| anyhow!("request4 failed"))?;

        assert_eq!(StatusCode::NoContent, res4.status());

        // test nonce reuse
        let mut salt5 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt5);
        let salt64_5 = base64::encode_config(&salt5, STANDARD_NO_PAD);

        let mut req5: Request = surf::put(url.to_string()).body("qux").into();

        sign_req(&mut req5, &n64_4, alg4, &salt64_5, &id)?;

        let fut5 = api.respond(req5);
        let mut res5: Response =
            task::block_on(fut5).map_err(|_| anyhow!("request5 failed"))?;

        assert_eq!(StatusCode::Unauthorized, res5.status());

        let expected_body5 = r#"{"reason":"unknown nonce","action":"update"}"#;
        let actual_body5 = task::block_on(res5.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body5.as_bytes(), actual_body5);

        Ok(())
    }

    #[test]
    fn v1_vault_get() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let n64_1 = init_nonce(&dbs.tokens, &["read"])?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let vid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("http://example.com/vaults/")?;
        let url = base.join(&vid).unwrap();

        let mut req1: Request = surf::get(url.to_string()).into();
        sign_req(&mut req1, &n64_1, TUNE, SALT, &id)?;
        let res1: Response = task::block_on(api.respond(req1))
            .map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::NotFound, res1.status());

        let aih1 = res1
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info1 = parse_auth_info(aih1.last().as_str())?;
        let n64_2 = &auth_info1.params["nextnonce"];

        let tdata = "vault data is opaque";
        let foof = dbs.vaults.put(&vid, &tdata.as_bytes());
        let _ = task::block_on(foof)?;

        let mut req2: Request = surf::get(url.to_string()).into();
        let mut salt2 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt2);
        let salt64_2 = base64::encode_config(&salt2, STANDARD_NO_PAD);
        let alg1 = &auth_info1.params["argon"];
        sign_req(&mut req2, &n64_2, alg1, &salt64_2, &id)?;

        let mut res2: Response = task::block_on(api.respond(req2))
            .map_err(|_| anyhow!("request failed"))?;

        let expected_body = "vault data is opaque";
        let actual_body = task::block_on(res2.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body.as_bytes(), actual_body);

        let aih2 = res2
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info2 = parse_auth_info(aih2.last().as_str())?;
        let n64_3 = &auth_info2.params["nextnonce"];

        // use the wrong identity
        let bad_id_bytes = [0xFFu8; uno::ID_LENGTH];
        let bad_id = uno::Id(bad_id_bytes);

        let mut req3: Request = surf::get(url.to_string()).into();
        let mut salt3 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt3);
        let salt64_3 = base64::encode_config(&salt3, STANDARD_NO_PAD);
        let alg3 = &auth_info2.params["argon"];
        sign_req(&mut req3, &n64_3, alg3, &salt64_3, &bad_id)?;

        let res3: Response = task::block_on(api.respond(req3))
            .map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Forbidden, res3.status());

        Ok(())
    }

    #[test]
    fn v1_vault_put() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let n64 = init_nonce(&dbs.tokens, &["create", "update"])?;

        let id = Id([0u8; ID_LENGTH]);
        let keypair = KeyPair::from(&id);
        let pubkey = keypair.public.as_bytes();
        let vid = base64::encode_config(&pubkey, base64::URL_SAFE_NO_PAD);
        let base = Url::parse("http://example.com/vaults/")?;
        let url = base.join(&vid).unwrap();

        let mut req: Request = surf::put(url.to_string())
            .body("vault data is opaque")
            .into();
        sign_req(&mut req, &n64, TUNE, SALT, &id)?;

        let mut res: Response = task::block_on(api.respond(req))
            .map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res.status());

        let expected_body = "vault data is opaque";
        let actual_body = task::block_on(res.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body.as_bytes(), actual_body);

        let stored_data = task::block_on(dbs.vaults.get(&vid))?;
        assert_eq!(expected_body.as_bytes(), stored_data);

        let aih = res
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info = parse_auth_info(aih.last().as_str())?;
        let n64_2 = &auth_info.params["nextnonce"];

        // use the wrong identity
        let bad_id_bytes = [0xFFu8; uno::ID_LENGTH];
        let bad_id = uno::Id(bad_id_bytes);

        let mut req2: Request = surf::get(url.to_string()).into();
        let mut salt2 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt2);
        let salt64_2 = base64::encode_config(&salt2, STANDARD_NO_PAD);
        let alg2 = &auth_info.params["argon"];
        sign_req(&mut req2, &n64_2, alg2, &salt64_2, &bad_id)?;

        let res2: Response = task::block_on(api.respond(req2))
            .map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Forbidden, res2.status());

        Ok(())
    }

    #[test]
    fn v1_service_get() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let id = Id([0u8; ID_LENGTH]); // use the zero id
        let n64_1 = init_nonce(&dbs.tokens, &["read"])?;

        let resource = "http://example.com/services/foo.json";
        let url = Url::parse(resource)?;
        let mut req1: Request = surf::get(url.to_string()).into();

        let salt1 = SALT;
        sign_req(&mut req1, &n64_1, TUNE, salt1, &id)?;
        let mut req2 = req1.clone(); // for the next request
        let fut1 = api.respond(req1);
        let res1: Response =
            task::block_on(fut1).map_err(|_| anyhow!("request failed"))?;

        // expect a 404 since the file does not exist yet
        assert_eq!(StatusCode::NotFound, res1.status());

        // get the next nonce so we can redo the request
        let aih1 = res1
            .header("authentication-info")
            .ok_or(anyhow!("expected auth-info"))?;
        let auth_info1 = parse_auth_info(aih1.last().as_str())?;
        let n64_2 = &auth_info1.params["nextnonce"];

        // add the file so the next request will succeed
        let tdata = r#"{"test": "data"}"#;
        let foof = dbs.services.put("foo.json", &tdata.as_bytes());
        let _ = task::block_on(foof)?;

        // gen a new salt and redo the request
        let mut salt2 = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt2);
        let salt64_2 = base64::encode_config(&salt2, STANDARD_NO_PAD);
        let alg2 = &auth_info1.params["argon"];
        sign_req(&mut req2, &n64_2, alg2, &salt64_2, &id)?;

        let fut2 = api.respond(req2);
        let mut res2: Response =
            task::block_on(fut2).map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"test": "data"}"#;
        let actual_body2 = task::block_on(res2.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        Ok(())
    }

    #[test]
    fn v1_services_put() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let n64 = init_nonce(&dbs.tokens, &["create", "update"])?;

        let resource = "http://example.com/services/foo.json";
        let url = Url::parse(resource)?;
        let mut req: Request = surf::put(url.to_string())
            .body(json!({"dummy": "data"}))
            .into();

        let id = Id([0u8; ID_LENGTH]);
        sign_req(&mut req, &n64, TUNE, SALT, &id)?;
        let fut = api.respond(req);
        let res: Response =
            task::block_on(fut).map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::MethodNotAllowed, res.status());
        Ok(())
    }

    #[test]
    fn v1_services_delete() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let n64 = init_nonce(&dbs.tokens, &["delete"])?;

        let resource = "http://example.com/services/foo.json";
        let url = Url::parse(resource)?;
        let mut req: Request = surf::delete(url.to_string()).into();

        let id = Id([0u8; ID_LENGTH]);
        sign_req(&mut req, &n64, TUNE, SALT, &id)?;
        let fut = api.respond(req);
        let res: Response =
            task::block_on(fut).map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::MethodNotAllowed, res.status());
        Ok(())
    }

    #[test]
    fn v1_ssss_get() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid).unwrap();

        let req1: Request = surf::get(url.to_string()).into();
        let req2 = req1.clone(); // for the next request
        let fut1 = api.respond(req1);
        let res1: Response =
            task::block_on(fut1).map_err(|_| anyhow!("request failed"))?;

        // expect a 404 since the file does not exist yet
        assert_eq!(StatusCode::NotFound, res1.status());

        // add the file so the next request will succeed
        let tdata = r#"{"test":"data"}"#;
        let foof = dbs.sessions.put(&sid, &tdata.as_bytes());
        let _ = task::block_on(foof)?;

        let fut2 = api.respond(req2);
        let mut res2: Response =
            task::block_on(fut2).map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"test":"data"}"#;
        let actual_body2 = task::block_on(res2.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        Ok(())
    }

    #[test]
    fn v1_ssss_put() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid).unwrap();

        let req1: Request = surf::put(url.to_string())
            .body(json!({"test":"data"}))
            .into();

        let fut1 = api.respond(req1);
        let mut res1: Response =
            task::block_on(fut1).map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::Ok, res1.status());
        let expected_body1 = r#"{"test":"data"}"#;
        let actual_body1 = task::block_on(res1.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(expected_body1.as_bytes(), actual_body1);

        let stored_data = task::block_on(dbs.sessions.get(&sid))?;
        assert_eq!(expected_body1.as_bytes(), stored_data);

        Ok(())
    }

    #[test]
    fn v1_ssss_patch() -> anyhow::Result<()> {
        let (api, dbs) = setup_tmp_api().unwrap();

        let mu = Mu([0u8; MU_LENGTH]);
        let session = Session::try_from(&mu)?;
        let cfg = base64::URL_SAFE_NO_PAD;
        let sid = base64::encode_config(session.0, cfg);
        let base = Url::parse("http://example.com/ssss/")?;
        let url = base.join(&sid).unwrap();

        let req1: Request = surf::patch(url.to_string())
            .body(json!({"patch": "me in"}))
            .into();

        let fut1 = api.respond(req1);
        let res1: Response =
            task::block_on(fut1).map_err(|_| anyhow!("request failed"))?;

        assert_eq!(StatusCode::NotFound, res1.status());

        // add the file so the next request will succeed
        let tdata = r#"{"test":"session data"}"#;
        let ses = dbs.sessions.put(&sid, &tdata.as_bytes());
        let _ = task::block_on(ses)?;

        let req2: Request = surf::patch(url.to_string())
            .body(json!({"patch": "me in"}))
            .into();

        let fut2 = api.respond(req2);
        let mut res2: Response =
            task::block_on(fut2).map_err(|_| anyhow!("request2 failed"))?;

        assert_eq!(StatusCode::Ok, res2.status());
        let expected_body2 = r#"{"patch":"me in","test":"session data"}"#;
        let actual_body2 = task::block_on(res2.take_body().into_bytes())
            .map_err(|_| anyhow!("body read failed"))?;
        assert_eq!(&expected_body2.as_bytes(), &actual_body2);

        Ok(())
    }

    #[test]
    fn v1_mailbox_auth() {
        let (api, dbs) = setup_tmp_api().unwrap();

        let recipient_id = Id([0u8; ID_LENGTH]);
        let recipient_keypair = KeyPair::from(&recipient_id);
        let recipient_pk = recipient_keypair.public.as_bytes();

        let sender_id = Id([1u8; ID_LENGTH]);

        let request = |signed_by: &Id, mut req: Request| -> Response {
            let nonce = init_nonce(&dbs.tokens, &["read", "create", "delete"])
                .unwrap();
            sign_req(&mut req, &nonce, TUNE, SALT, &signed_by).unwrap();

            task::block_on(api.respond(req)).unwrap()
        };

        {
            // get your own mailbox
            assert_eq!(
                request(
                    &recipient_id,
                    surf::get(format!(
                        "https://example.com/mailboxes/{}",
                        base64::encode_config(
                            recipient_pk,
                            base64::URL_SAFE_NO_PAD
                        )
                    ))
                    .build()
                )
                .status(),
                StatusCode::Ok
            );

            // get someone else's mailbox
            assert_eq!(
                request(
                    &sender_id,
                    surf::get(format!(
                        "https://example.com/mailboxes/{}",
                        base64::encode_config(
                            recipient_pk,
                            base64::URL_SAFE_NO_PAD
                        )
                    ))
                    .build()
                )
                .status(),
                StatusCode::Forbidden
            );

            // post to someone's mailbox
            assert_eq!(
                request(
                    &sender_id,
                    surf::post(format!(
                        "https://example.com/mailboxes/{}",
                        base64::encode_config(
                            recipient_pk,
                            base64::URL_SAFE_NO_PAD
                        )
                    ))
                    .body(
                        serde_json::to_string(&MessageRequest {
                            action: "packed".to_string(),
                            data: Payload {
                                signature: "signature".to_string(),
                                share: "share".to_string(),
                            },
                        })
                        .unwrap()
                    )
                    .build()
                )
                .status(),
                StatusCode::Created
            );

            // delete someone else's message
            // (even if you created it)
            assert_eq!(
                request(
                    &sender_id,
                    surf::delete(format!(
                        "https://example.com/mailboxes/{}",
                        base64::encode_config(
                            recipient_pk,
                            base64::URL_SAFE_NO_PAD
                        ),
                    ))
                    .build()
                )
                .status(),
                StatusCode::Forbidden
            );
        }
    }

    #[test]
    fn v1_mailbox_actions() {
        use serde_json::from_slice;

        let (api, dbs) = setup_tmp_api().unwrap();

        let recipient_id = Id([0u8; ID_LENGTH]);
        let recipient_pk = KeyPair::from(&recipient_id).public;

        //let recipient2_id = Id([1u8; ID_LENGTH]);
        //let recipient2_pk = KeyPair::from(&recipient2_id).public;

        let sender_id = Id([2u8; ID_LENGTH]);
        let sender_pk = KeyPair::from(&sender_id).public;

        //let sender2_id = Id([3u8; ID_LENGTH]);
        //let sender2_pk = KeyPair::from(&sender2_id).public;

        let request = |signed_by: &Id, mut req: Request| -> Mailbox {
            let nonce = init_nonce(&dbs.tokens, &["read", "create", "delete"])
                .unwrap();
            sign_req(&mut req, &nonce, TUNE, SALT, &signed_by).unwrap();

            let mut r: Response = task::block_on(api.respond(req)).unwrap();

            from_slice(&task::block_on(r.take_body().into_bytes()).unwrap())
                .unwrap()
        };

        let delete_request = |signed_by: &Id, mut req: Request| -> Response {
            let nonce = init_nonce(&dbs.tokens, &["read", "create", "delete"])
                .unwrap();
            sign_req(&mut req, &nonce, TUNE, SALT, &signed_by).unwrap();

            task::block_on(api.respond(req)).unwrap()
        };

        let post_request = |signed_by: &Id,
                            mut req: Request|
         -> MessageStored {
            let nonce = init_nonce(&dbs.tokens, &["read", "create", "delete"])
                .unwrap();
            sign_req(&mut req, &nonce, TUNE, SALT, &signed_by).unwrap();

            let mut r: Response = task::block_on(api.respond(req)).unwrap();

            from_slice(&task::block_on(r.take_body().into_bytes()).unwrap())
                .unwrap()
        };

        assert_eq!(
            request(
                &recipient_id,
                surf::get(format!(
                    "https://example.com/mailboxes/{}",
                    base64::encode_config(
                        recipient_pk,
                        base64::URL_SAFE_NO_PAD
                    )
                ))
                .build(),
            ),
            Mailbox { messages: vec!() }
        );

        assert_eq!(
            post_request(
                &sender_id,
                surf::post(format!(
                    "https://example.com/mailboxes/{}",
                    base64::encode_config(
                        recipient_pk,
                        base64::URL_SAFE_NO_PAD
                    )
                ))
                .body(
                    serde_json::to_string(&MessageRequest {
                        action: "packed".to_string(),
                        data: Payload {
                            signature: "signature".to_string(),
                            share: "share".to_string(),
                        },
                    })
                    .unwrap()
                )
                .build()
            ),
            MessageStored {
                id: 1,
                action: "packed".to_string(),
                from: base64::encode(
                    sender_pk
                ),
                data: Payload {
                    signature: "signature".to_string(),
                    share: "share".to_string(),
                },
            }
        );

        assert_eq!(
            post_request(
                &sender_id,
                surf::post(format!(
                    "https://example.com/mailboxes/{}",
                    base64::encode_config(
                        recipient_pk,
                        base64::URL_SAFE_NO_PAD
                    )
                ))
                .body(
                    serde_json::to_string(&MessageRequest {
                        action: "packed".to_string(),
                        data: Payload {
                            signature: "signature".to_string(),
                            share: "share".to_string(),
                        },
                    })
                    .unwrap()
                )
                .into()
            ),
            MessageStored {
                id: 2,
                action: "packed".to_string(),
                from: base64::encode(
                    sender_pk
                ),
                data: Payload {
                    signature: "signature".to_string(),
                    share: "share".to_string(),
                },
            }
        );

        assert_eq!(
            delete_request(
                &recipient_id,
                surf::delete(format!(
                    "https://example.com/mailboxes/{}",
                    base64::encode_config(
                        recipient_pk,
                        base64::URL_SAFE_NO_PAD
                    )
                ))
                .body(
                    serde_json::to_string(&vec!(
                        MessageToDelete {
                            from: base64::encode(
                                sender_pk
                            ),
                            id: 1
                        },
                        MessageToDelete {
                            from: base64::encode(
                                sender_pk
                            ),
                            id: 2
                        }
                    ))
                    .unwrap()
                )
                .build(),
            )
            .status(),
            StatusCode::NoContent
        );

        assert_eq!(
            request(
                &recipient_id,
                surf::get(format!(
                    "https://example.com/mailboxes/{}",
                    base64::encode_config(
                        recipient_pk,
                        base64::URL_SAFE_NO_PAD
                    )
                ))
                .build(),
            ),
            Mailbox { messages: vec!() }
        );
    }

    #[allow(dead_code)]
    fn print_body(res: &mut Response) -> anyhow::Result<()> {
        let body_bytes = task::block_on(res.take_body().into_bytes())
            .map_err(|_| anyhow!("error reading body"))?;
        println!("{:?}", String::from_utf8(body_bytes));
        Ok(())
    }
}
