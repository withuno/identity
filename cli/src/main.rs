//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// The uno utility is a cli frontend to operations that can be performed with
/// an uno identity.

use clap::{Args, Parser,};
use anyhow::{anyhow, bail, Context as AnyContext, Result,};
use uno::Binding;

use std::path::PathBuf;
use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Parser)]
#[clap(version = "0.1", author = "David C. <david@uno.app>")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
    #[clap(flatten)]
    ctx: Context,
}

#[derive(Args)]
struct Context {
    /// Specify an optional config path to use instead of the default.
    #[clap(long, parse(from_os_str), value_name = "PATH")]
    conf: Option<PathBuf>,
}

#[derive(Parser)]
enum SubCommand {
    Init(Init),
    Seed(Seed),
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    Sign(Sign),
    Verify(Verify),
    Pubkey(Pubkey),
    Vault(Vault),
    Mu(Mu),
    Session(Session),
    Ssss(Ssss),
    S39(S39Cmd),
}

/// Initialize Uno in your home environment. Data and config is stored under
/// `~/.uno`. . 
#[derive(Parser)]
struct Init;

fn do_init(ctx: Context, _: Init) -> Result<String>
{
    // Check for existing config. If it exists, bail.
    match load_conf(&ctx) {
        Ok(_) => bail!("uno already initialized"),
        _ => {},
    };

    let conf_file = config_path(&ctx)?;
    let uno_dir = match conf_file.parent() {
        Some(p) => p,
        None => bail!("file `{}` has no parent", conf_file.to_string_lossy()),
    };
    std::fs::create_dir_all(&uno_dir)?;
    cli::gen_config(&conf_file)?;

    Ok(format!("wrote: {}", conf_file.to_string_lossy()))
}

fn config_path(ctx: &Context) -> Result<std::path::PathBuf>
{
    Ok(match ctx.conf {
        Some(ref p) => p.to_path_buf(),
        None => {
            let mut home = dirs_next::home_dir()
                .ok_or(anyhow!("can't find home dir"))?;
            home.push(".uno");
            home.push("config");
            home
        },
    })
}

fn load_conf(ctx: &Context) -> Result<cli::Config>
{
    let conf_file = config_path(ctx)?;
    cli::load_config(&conf_file)
}

/// Generate an uno identity. An identity seed is 32 bytes of entropy.
/// The base64 encoding of the entropy is written to standard out. .
#[derive(Parser)]
struct Seed
{
    #[clap(long)]
    ephemeral: bool
}

fn do_seed(ctx: Context, s: Seed) -> Result<String>
{
    let id = match s.ephemeral {
        true => uno::Id::new(),
        false => cli::load_seed(&load_conf(&ctx)?)?,
    };

    Ok(base64::encode(id.0))
}

/// Print the public key corresponding to the signing keypair associated with
/// the configured identity seed. .
#[derive(Parser)]
struct Pubkey
{
    /// Override the configured identity seed
    #[clap(long, value_name = "b64")]
    seed: Option<String>,
}

fn do_pubkey(ctx: Context, c: Pubkey) -> Result<String>
{
    let id = match c.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&load_conf(&ctx)?)?,
    };
    let key = uno::KeyPair::from(id);

    Ok(base64::encode(&key.public.as_bytes()))
}

/// AEAD/Sealed-box open.
///
/// The decrypt operation works with both 32 byte identity seeds and the 8 byte
/// Mu. The actual symmetric key is derived appropriate in each case.
#[derive(Parser)]
struct Decrypt
{
    /// Identity seed.
    #[clap(long, value_name = "b64", conflicts_with = "mu")]
    seed: Option<String>,
    /// 8 byte Mu seed.
    #[clap(long, value_name = "b64", conflicts_with = "seed")]
    mu: Option<String>,
    /// Bind context in which the decrypted data should be used.
    /// Options: "vault", "split", "combine", "transfer"
    #[clap(long, value_name = "option")]
    bind: Option<String>,
    /// Custom additional data context. Cannot be specified when a --bind is
    /// also provided. Bindings are uno domain specific contexts for the aead.
    #[clap(long, value_name = "text", conflicts_with = "bind")]
    data: Option<String>,
}

fn do_decrypt(ctx: Context, c: Decrypt) -> Result<String>
{
    let key: uno::SymmetricKey = match (c.seed, c.mu) {
        (None, None) => cli::load_seed(&load_conf(&ctx)?)?.into(),
        (Some(s), _) => id_from_b64(s)?.into(),
        (None, Some(m)) => mu_from_b64(m)?.try_into()?,
        // (Some(_), Some(_)) handled by clap via `conflicts_with`
    };

    let mut ciphertext = String::new();
    use std::io::stdin;
    use std::io::Read;
    let _ = stdin().read_to_string(&mut ciphertext)?;

    let blob = base64::decode(ciphertext)
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

/// AEAD/Sealed-box seal.
///
/// The encrypt operation works with both 32 byte identity seeds and the 8 byte
/// Mu. The actual symmetric key is derived appropriate in each case.
#[derive(Parser)]
struct Encrypt
{
    /// 32 byte identity seed.
    #[clap(long, value_name = "b64", conflicts_with = "mu")]
    seed: Option<String>,
    /// 8 byte Mu seed.
    #[clap(long, value_name = "b64", conflicts_with = "seed")]
    mu: Option<String>,
    /// Bind context in which the encrypted data should be used.
    /// Options: "vault", "split", "combine", "transfer"
    #[clap(long, value_name = "option")]
    bind: Option<String>,
    /// Custom additional data context. Cannot be specified when a --bind is
    /// also provided. Bindings are uno domain specific contexts for the aead.
    #[clap(long, value_name = "text", conflicts_with = "bind")]
    data: Option<String>,
    #[clap(long)]
    raw: bool
}

fn do_encrypt(ctx: Context, c: Encrypt) -> Result<String>
{
    let key: uno::SymmetricKey = match (c.seed, c.mu) {
        (None, None) => cli::load_seed(&load_conf(&ctx)?)?.into(),
        (Some(s), _) => id_from_b64(s)?.into(),
        (None, Some(m)) => mu_from_b64(m)?.try_into()?,
        // (Some(_), Some(_)) handled by clap via `conflicts_with`
    };

    let mut ctx = Binding::None;
    if let Some(o) = c.bind {
        ctx = o.parse()?;
    }
    if let Some(o) = &c.data {
        ctx = Binding::Custom(o);
    }

    let mut plaintext = String::new();
    use std::io::stdin;
    use std::io::Read;
    let _ = stdin().read_to_string(&mut plaintext)?;

    let blob = uno::encrypt(ctx, key, &plaintext.as_bytes())
        .context("encryption failed")?;

    let out = match c.raw {
        true => "raw not supported".into(),
        false => base64::encode(&blob[..]),
    };

    Ok(out)
}

/// Sign a message using the configured Uno ID.
///
/// The message is read from stdin.
#[derive(Parser)]
struct Sign
{
    /// Override the configured identity
    #[clap(long, value_name = "b64")]
    seed: Option<String>,
}

fn do_sign(ctx: Context, c: Sign) -> Result<String>
{
    let id = match c.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&load_conf(&ctx)?)?,
    };
    let key = uno::KeyPair::from(id);

    let mut message = String::new();
    use std::io::stdin;
    use std::io::Read;
    let _ = stdin().read_to_string(&mut message)?;

    use uno::Signer;
    let sig = key.sign(&message.as_bytes());
    Ok(base64::encode(&sig.to_bytes()))
}

/// Verify a signature on a message.
///
/// The message is read from stdin.
#[derive(Parser)]
struct Verify
{
    /// EdDSA public key.
    #[clap(long, value_name = "b64")]
    pubkey: String,
    /// Signature to verify.
    #[clap(long, value_name = "b64")]
    signature: String
}

fn do_verify(_: Context, c: Verify) -> Result<String>
{
    use uno::Verifier;

    let raw = base64::decode(c.pubkey)
        .context("pubkey must be base64 encoded")?;
    let pubkey = uno::PublicKey::from_bytes(&raw[..])
        .context("invalid public key")?;
    let bytes = base64::decode(c.signature)
        .context("signature must be base64 encoded")?;

    let sig = uno::Signature::from_bytes(&bytes)?;

    let mut message = String::new();
    use std::io::stdin;
    use std::io::Read;
    let _ = stdin().read_to_string(&mut message)?;

    pubkey.verify(&message.as_bytes(), &sig)
        .context("signature failed to verify")?;

    Ok("The signature is valid.".into())
}

/// Operate on a vault.
#[derive(Parser)]
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

// TODO make subcommand on method/action
fn do_vault(ctx: Context, c: Vault) -> Result<String>
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
#[derive(Parser)]
struct Mu;

fn do_mu(_: Context, _: Mu) -> Result<String>
{
    let id = uno::Mu::new();
    Ok(base64::encode(id.0))
}

/// Print the session id derived from Mu entropy.
#[derive(Parser)]
struct Session
{
    /// identity seed
    #[clap(long, value_name = "mu")]
    seed: String,
}

fn do_session(_: Context, c: Session) -> Result<String>
{
    let mu = mu_from_b64(c.seed)?;
    let sid = uno::Session::try_from(mu)?;
    Ok(base64::encode_config(&sid.0, base64::URL_SAFE_NO_PAD))
}

/// Shamir's secret sharing session operations.
///
/// When operating on the session endpoint, data in the "share" field will be
/// encrypted prior to uploading and decrypted when downloading.
#[derive(Parser)]
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

// TODO make subcommand keyed on method
fn do_ssss(ctx: Context, c: Ssss) -> Result<String>
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
                .context("cannot update session")?;
            Ok(s)
        }
        m => Err(anyhow!("method {} not supported for ssss", m)),
    }
}

/// SLIP-0039 operations.
///
#[derive(Parser)]
enum S39
{
    Split(S39Split),
    Combine(S39Combine),
    View(S39View),
}

/// SLIP-0039 Options
#[derive(Parser)]
struct S39Cmd
{
    // TODO group threshold, group support, etc.
    #[clap(subcommand)]
    subcmd: S39,
}

/// Split the configured uno identity seed into a number of shares. .
#[derive(Parser)]
struct S39Split
{
    /// minimum shares needed to reconstitute the seed
    #[clap(long, value_name = "num", default_value = "2")]
    minimum: u8,
    /// total shares generated
    #[clap(long, value_name = "num", default_value = "3")]
    total: u8,
    // TODO support groups
    /// Override the configured identity.
    seed: Option<String>,
}

fn do_s39(ctx: Context, s: S39Cmd) -> Result<String>
{
    match s.subcmd {
        S39::Split(c)  => do_s39_split(ctx, c),
        S39::Combine(c) => do_s39_combine(c),
        S39::View(c) => do_s39_view(c),
    }
}

fn do_s39_split(ctx: Context, c: S39Split) -> Result<String>
{
    let id = match c.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&load_conf(&ctx)?)?,
    };

    let groups = uno::split(id, &[(c.minimum,c.total)])
        .context("failed to split shares")?;
    let group = &groups[0];

    let mut view = String::new();

    view.push_str(&format!("Group {}:\n", group.group_index));
    view.push_str(&format!("\tGroup ID: {}\n", group.group_id));
    view.push_str(&format!("\tTotal Groups: {}\n", group.group_count));
    view.push_str(&format!("\tRequired Groups: {}\n", group.group_threshold));
    view.push_str(&format!("\tTotal Shares: {}\n", c.total));
    view.push_str(&format!("\tRequired Shares: {}\n", c.minimum));
    view.push_str(&format!("\tShares List:\n"));
    view.push_str("\t[\n");

    for share in &group.member_shares {
        let mnemonic = share.to_mnemonic()
            .map_err(|e| anyhow!(e))?;
        view.push('\t');
        view.push('\t');
        view.push_str(&mnemonic.join(" "));
        view.push(',');
        view.push('\n');
    }
    view.push_str("\t]");

    Ok(view)
}

/// Combine shares of a split seed back into the whole identity seed.
#[derive(Parser)]
struct S39Combine
{
    /// mnemonic share obtained from a previous s39 split operation
    #[clap(
        long,
        value_name = "nmemonic",
        multiple_values = true,
        multiple_occurrences = true)]
    shares: Vec<String>,
}

fn do_s39_combine(c: S39Combine) -> Result<String>
{
    let parsed = c.shares.iter()
        .map(|s| s.split(" ").map(|us| us.to_owned()).collect())
        .collect::<Vec<Vec<String>>>();

    let id = uno::combine(&parsed[..])
        .context("failed to combine shares")?;

    Ok(base64::encode_config(&id.0, base64::STANDARD_NO_PAD))
}

/// View metadata about a mnemonic share.
#[derive(Parser)]
struct S39View
{
    /// mnemonic share obtained from a previous s39 split operation
    share: String,
}

fn do_s39_view(c: S39View) -> Result<String>
{
    let words: Vec<String> = c.share.split(' ')
        .map(|s| s.to_owned())
        .collect();
    let share = uno::Share::from_mnemonic(&words)
        .map_err(|e| anyhow!(e))?;

    let mut view = String::new();

    view.push_str(&format!("\tShare ID: {:x}\n", share.identifier));
    view.push_str(&format!("\tGroup Index: {}\n", share.group_index));
    view.push_str(&format!("\tGroup Count: {}\n", share.group_count));
    view.push_str(&format!("\tGroup Threshold: {}\n", share.group_threshold));
    view.push_str(&format!("\tShare Index: {}\n", share.member_index));
    view.push_str(&format!("\tShare Threshold: {}\n", share.member_threshold));
    view.push_str(&format!("\tShare Bytes: {:?}\n", share.share_value));
    view.push_str(&format!("\tShare Checksum: {:x}\n", share.checksum));

    Ok(view)
}

fn main() -> Result<()>
{
    let cli = Opts::parse();
    let ctx = cli.ctx;

    let out = match cli.subcmd {
        SubCommand::Init(cmd) => do_init(ctx, cmd),
        SubCommand::Seed(cmd) => do_seed(ctx, cmd),
        SubCommand::Pubkey(cmd) => do_pubkey(ctx, cmd),
        SubCommand::Decrypt(cmd) => do_decrypt(ctx, cmd),
        SubCommand::Encrypt(cmd) => do_encrypt(ctx, cmd),
        SubCommand::Sign(cmd) => do_sign(ctx, cmd),
        SubCommand::Verify(cmd) => do_verify(ctx, cmd),
        SubCommand::Vault(cmd) => do_vault(ctx, cmd),
        SubCommand::Mu(cmd) => do_mu(ctx, cmd),
        SubCommand::Session(cmd) => do_session(ctx, cmd),
        SubCommand::Ssss(cmd) => do_ssss(ctx, cmd),
        SubCommand::S39(cmd) => do_s39(ctx, cmd),
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
    }
}
