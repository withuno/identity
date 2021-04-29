//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// The uno utility is a cli frontend to operations that can be performed with
/// an uno identity.

use clap::Clap;
use anyhow::{anyhow, bail, Context, Result};
use uno::Binding;

use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Clap)]
#[clap(version = "0.1", author = "David C. <david@withuno.com>")]
struct Opts {
   #[clap(subcommand)]
   subcmd: SubCommand, 
}

#[derive(Clap)]
enum SubCommand {
    Seed(Seed),
    Split(Split),
    Combine(Combine),
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    Sign(Sign),
    Verify(Verify),
    Pubkey(Pubkey),
    Vault(Vault),
    Mu(Mu),
    Session(Session),
    Ssss(Ssss),
}

/// Generate an uno identity.
#[derive(Clap)]
struct Seed;

fn do_seed(_: Seed) -> Result<String>
{
    let id = uno::Id::new();
    Ok(base64::encode(id.0))
}

/// Print the public key corresponding to the signing keypair.
#[derive(Clap)]
struct Pubkey
{
    /// identity seed
    #[clap(long)]
    seed: String,
}

fn do_pubkey(c: Pubkey) -> Result<String>
{
    let id = id_from_b64(c.seed)?;
    let key = uno::KeyPair::from(id);
    Ok(base64::encode(&key.public.as_bytes()))
}

/// Split an uno identity seed into a number of shares
#[derive(Clap)]
struct Split
{
    /// minimum shares needed to reconstitute the seed
    #[clap(long, value_name = "num", default_value = "2")]
    minimum: usize,
    /// total shares generated
    #[clap(long, value_name = "num", default_value = "3")]
    total: usize,
    // TODO support groups
    /// The identity to split
    seed: String,
}

fn do_split(c: Split) -> Result<String>
{
    let id = id_from_b64(c.seed)?;
    let shares = uno::split(id, &[(c.minimum,c.total)])
        .context("failed to split shares")?;

    let mut view = String::new();
    for share in shares {
        let enc = base64::encode(&share[..]);
        view.push('\n');
        view.push_str(&enc);
    }
    view.push('\n');

    Ok(view)
}

/// Combine shares of a split seed back into the whole identity seed.
#[derive(Clap)]
struct Combine
{
    /// shares
    #[clap(
        long,
        value_name = "b64",
        multiple = true,
        multiple_occurrences = true)]
    shares: Vec<String>,
}

fn do_combine(c: Combine) -> Result<String>
{
    let parsed = c.shares.iter()
        .map(base64::decode)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse share")?;

    let id = uno::combine(&parsed[..])
        .context("failed to combine shares")?;

    Ok(base64::encode(&id.0))
}

/// AEAD open The decrypt operation works with both 32 byte identity seeds and
/// the 8 byte Mu. The actual symmetric key is derived appropriate in each case.
#[derive(Clap)]
struct Decrypt
{
    /// Identity seed.
    #[clap(long, value_name = "b64", required_unless_present = "mu")]
    seed: Option<String>,
    /// 8 byte Mu seed.
    #[clap(long, value_name = "b64", conflicts_with = "seed")]
    mu: Option<String>,
    /// The message to decrypt, base64 encoded.
    ciphertext: String,
    /// Bind context in which the decrypted data should be used.
    /// Options: "vault", "split", "combine", "transfer"
    #[clap(long, value_name = "option")]
    bind: Option<String>,
    /// Custom additional data context. Cannot be specified when a --bind is
    /// also provided. Bindings are uno domain specific contexts for the aead.
    #[clap(long, value_name = "text", conflicts_with = "bind")]
    data: Option<String>,
}

fn do_decrypt(c: Decrypt) -> Result<String>
{
    let key: uno::SymmetricKey;
    if let Some(r) = c.seed {
        let id = id_from_b64(r)?;
        key = id.into();
    } else
    if let Some(r) = c.mu {
        let mu = mu_from_b64(r)?;
        key = mu.try_into()?;
    } else {
        bail!("--seed or --mu required");
    }

    let blob = base64::decode(c.ciphertext)
        .context("ciphertext must be base64 encoded")?;

    let mut ctx = Binding::None;
    if let Some(o) = c.bind {
        ctx = o.parse()?;
    }
    if let Some(o) = &c.data {
        ctx = Binding::Custom(o);
    }

    let data = uno::decrypt(ctx, key, &blob[..])
        .context("decryption failed")?;

    Ok(String::from_utf8(data)?)
}

/// AEAD seal. The encrypt operation works with both 32 byte identity seeds and
/// the 8 byte Mu. The actual symmetric key is derived appropriate in each case.
#[derive(Clap)]
struct Encrypt
{
    /// 32 byte identity seed.
    #[clap(long, value_name = "b64", required_unless_present = "mu")]
    seed: Option<String>,
    /// 8 byte Mu seed.
    #[clap(long, value_name = "b64", conflicts_with = "seed")]
    mu: Option<String>,
    /// The message to encrypt, base64 encoded.
    plaintext: String,
    /// Bind context in which the encrypted data should be used.
    /// Options: "vault", "split", "combine", "transfer"
    #[clap(long, value_name = "option")]
    bind: Option<String>,
    /// Custom additional data context. Cannot be specified when a --bind is
    /// also provided. Bindings are uno domain specific contexts for the aead.
    #[clap(long, value_name = "text", conflicts_with = "bind")]
    data: Option<String>,
}

fn do_encrypt(c: Encrypt) -> Result<String>
{
    let key: uno::SymmetricKey;
    if let Some(r) = c.seed {
        let id = id_from_b64(r)?;
        key = id.into();
    } else
    if let Some(r) = c.mu {
        let mu = mu_from_b64(r)?;
        key = mu.try_into()?;
    } else {
        bail!("--seed or --mu required");
    }

    let mut ctx = Binding::None;
    if let Some(o) = c.bind {
        ctx = o.parse()?;
    }
    if let Some(o) = &c.data {
        ctx = Binding::Custom(o);
    }

    let blob = uno::encrypt(ctx, key, &c.plaintext.as_bytes())
        .context("encryption failed")?;

    Ok(base64::encode(&blob[..]))
}

/// Sign a message using an Uno ID.
#[derive(Clap)]
struct Sign
{
    /// Identity seed to use.
    #[clap(long)]
    seed: String,
    /// Data to sign.
    message: String,
}

fn do_sign(c: Sign) -> Result<String>
{
    use uno::Signer;
    let id = id_from_b64(c.seed)?;
    let key = uno::KeyPair::from(id);
    let sig = key.sign(&c.message.as_bytes());
    Ok(base64::encode(&sig.to_bytes()))
}

/// Verify a signature on a message.
#[derive(Clap)]
struct Verify
{
    /// EdDSA public key.
    #[clap(long, value_name = "b64")]
    pubkey: String,
    /// The message to decrypt.
    message: String,
    /// Signature to verify.
    #[clap(long, value_name = "b64")]
    signature: String
}

fn do_verify(c: Verify) -> Result<String>
{
    use uno::Verifier;

    let raw = base64::decode(c.pubkey)
        .context("pubkey must be base64 encoded")?;
    let pubkey = uno::PublicKey::from_bytes(&raw[..])
        .context("invalid public key")?;
    let bytes = base64::decode(c.signature)
        .context("signature must be base64 encoded")?;
    let array = <[u8; uno::SIGNATURE_LENGTH]>::try_from(bytes)
        // Can't use .context here because the error is Vec<u8>. See:
        // https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2595
        .map_err(|_| anyhow!("signature must be exactly 64 bytes long"))?;

    let sig = uno::Signature::new(array);
    pubkey.verify(&c.message.as_bytes(), &sig)
        .context("signature failed to verify")?;

    Ok("success".into())
}

/// Operate on a vault.
#[derive(Clap)]
struct Vault
{
    /// HTTP method (GET or PUT). Download or Upload?
    #[clap(long, short = 'X', value_name = "method", default_value = "get")]
    method: String,
    /// Vault store endpoint.
    #[clap(long,
        value_name = "endpoint",
        default_value = "https://api.u1o.dev"
    )]
    url: String,
    /// Identity seed to use.
    #[clap(long)]
    seed: String,
    /// When uploading, the vault data json.
    data: Option<String>,
}

fn do_vault(c: Vault) -> Result<String>
{
    use http_types::Method;
    use std::str::FromStr;

    let id = id_from_b64(c.seed)?;
    let method = Method::from_str(&c.method)
        .map_err(http_types::Error::into_inner)?;

    match method {
        Method::Get => {
            let v = cli::get_vault(c.url, id)
                .context("cannot download vault")?;
            Ok(v)
        },
        Method::Put => {
            let data = c.data
                .context("data is required")?;
            let v = cli::put_vault(c.url, id, data.as_bytes())
                .context("cannot upload vault")?;
            Ok(v)
        },
        _ => Err(anyhow!("bad method")),
    }
}

/// Generate an uno shamir's secert sharing session entropy seed.
#[derive(Clap)]
struct Mu;

fn do_mu(_: Mu) -> Result<String>
{
    let id = uno::Mu::new();
    Ok(base64::encode(id.0))
}

/// Print the session id derived from Mu entropy.
#[derive(Clap)]
struct Session
{
    /// identity seed
    #[clap(long, value_name = "mu")]
    seed: String,
}

fn do_session(c: Session) -> Result<String>
{
    let mu = mu_from_b64(c.seed)?;
    let sid = uno::Session::try_from(mu)?;
    Ok(base64::encode_config(&sid.0, base64::URL_SAFE_NO_PAD))
}

/// Shamir's secret sharing session operations.
///
/// When operating on the session endpoint, data in the "share" field will be
/// encrypted prior to uploading and decrypted when downloading.
#[derive(Clap)]
struct Ssss
{
    /// HTTP method (GET or PUT or PATCH). Download or Upload/Update?
    #[clap(long, short = 'X', value_name = "method", default_value = "get")]
    method: String,
    /// Vault store endpoint.
    #[clap(long,
        value_name = "endpoint",
        default_value = "https://api.u1o.dev"
    )]
    url: String,
    /// 80 bit (10 byte) session entropy to use. Not the same as the identity
    /// seed entropy. You can generate entropy with `uno mu`.
    #[clap(long, value_name = "mu")]
    seed: String,
    /// When uploading, the session data json.
    data: Option<String>,
}

fn do_ssss(c: Ssss) -> Result<String>
{
    use http_types::Method;
    use std::str::FromStr;

    let mu = mu_from_b64(c.seed)?;
    let method = Method::from_str(&c.method)
        .map_err(http_types::Error::into_inner)?;

    match method {
        Method::Get => {
            let s = cli::get_ssss(c.url, mu)
                .context("cannot download session")?;
            Ok(s)
        },
        Method::Put => {
            let data = c.data
                .context("data is required")?;
            let s = cli::put_ssss(c.url, mu, data.as_bytes())
                .context("cannot upload session")?;
            Ok(s)
        },
        Method::Patch => {
            let data = c.data
                .context("data is required")?;
            let s = cli::patch_ssss(c.url, mu, data.as_bytes())
                .context("cannot upload session")?;
            Ok(s)
        }
        m => Err(anyhow!("method {} not supported for ssss", m)),
    }
}

fn main() -> Result<()>
{
    let out = match Opts::parse().subcmd {
        SubCommand::Seed(c) => do_seed(c),
        SubCommand::Pubkey(c) => do_pubkey(c),
        SubCommand::Split(c) => do_split(c),
        SubCommand::Combine(c) => do_combine(c),
        SubCommand::Decrypt(c) => do_decrypt(c),
        SubCommand::Encrypt(c) => do_encrypt(c),
        SubCommand::Sign(c) => do_sign(c),
        SubCommand::Verify(c) => do_verify(c),
        SubCommand::Vault(c) => do_vault(c),
        SubCommand::Mu(c) => do_mu(c),
        SubCommand::Session(c) => do_session(c),
        SubCommand::Ssss(c) => do_ssss(c),
    }?;

    println!("{}", out);

    Ok(())
}

fn id_from_b64(seed: String) -> Result<uno::Id> {
    let seed = base64::decode(seed)
        .context("seed must be base64 encoded")?;
    let array = <[u8; 32]>::try_from(seed)
        .map_err(|_| anyhow!("seed must be exactly 32 bytes long"))?;
    Ok(uno::Id(array))
}

fn mu_from_b64(seed: String) -> Result<uno::Mu> {
    let seed = base64::decode(seed)
        .context("seed must be base64 encoded")?;
    let array = <[u8; 10]>::try_from(seed)
        .map_err(|_| anyhow!("seed must be exactly 10 bytes long"))?;
    Ok(uno::Mu(array))
}
#[cfg(test)]
mod test
{
//    use super::*;

    #[test]
    fn test_id() {
        // use:
        // https://docs.rs/clap/3.0.0-beta.2/clap/struct.App.html#method.try_get_matches_from
    }
}
