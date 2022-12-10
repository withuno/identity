//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use anyhow::{anyhow, bail, Context as AnyContext, Result};
use api::DirectoryEntryCreate;
/// The uno utility is a cli frontend to operations that can be performed with
/// an uno identity.
use clap::{Args, Parser};
use uno::encrypt;
use uno::Binding;

use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::stdin;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(version = "0.1", author = "David C. <david@uno.app>")]
struct Opts
{
    #[clap(subcommand)]
    subcmd: SubCommand,
    #[clap(flatten)]
    ctx: Context,
}

#[derive(Args)]
struct Context
{
    /// Specify an optional config path to use instead of the default.
    #[clap(long, parse(from_os_str), value_name = "PATH")]
    conf: Option<PathBuf>,
}

#[derive(Parser)]
enum SubCommand
{
    #[clap(display_order = 10)]
    Init(Init),

    #[clap(display_order = 70)]
    Seed(Seed),

    #[clap(display_order = 40)]
    Encrypt(Encrypt),

    #[clap(display_order = 41)]
    Decrypt(Decrypt),

    #[clap(display_order = 30)]
    Sign(Sign),

    #[clap(display_order = 30)]
    Verify(Verify),

    #[clap(display_order = 30)]
    Pubkey(Pubkey),

    #[clap(display_order = 20)]
    Vault(Vault),

    #[clap(display_order = 71)]
    Mu(Mu),

    #[clap(display_order = 80)]
    Share(Share),

    #[clap(display_order = 90)]
    VerifyToken(VerifyToken),

    #[clap(display_order = 80)]
    Session(Session),

    #[clap(display_order = 80)]
    Ssss(Ssss),

    #[clap(display_order = 50)]
    S39(S39Cmd),

    #[clap(display_order = 90)]
    Directory(DirectoryCmd),
}

///
/// Initialize Uno in your home environment.
///
/// Data and config is stored under `~/.uno`. .
///
#[derive(Parser)]
struct Init
{
    /// Override the default API service endpoint. This option is used for testing and development and should not be used normally.
    #[clap(
        long,
        default_value = cli::API_HOST,
        display_order = 1,
        value_name = "url",
    )]
    host: String,
}

fn do_init(ctx: Context, cmd: Init) -> Result<String>
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
    cli::gen_config(&conf_file, cmd.host)?;

    Ok(format!("wrote: {}", conf_file.to_string_lossy()))
}

fn config_path(ctx: &Context) -> Result<std::path::PathBuf>
{
    Ok(match ctx.conf {
        Some(ref p) => p.to_path_buf(),
        None => {
            let mut home =
                dirs_next::home_dir().ok_or(anyhow!("can't find home dir"))?;
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

///
/// Generate an uno identity.
///
/// An identity seed is 32 bytes of entropy. The base64 encoding of the entropy
/// is written to standard out. .
///
#[derive(Parser)]
struct Seed
{
    #[clap(long, display_order = 1)]
    ephemeral: bool,
}

fn do_seed(ctx: Context, s: Seed) -> Result<String>
{
    let id = match s.ephemeral {
        true => uno::Id::new(),
        false => cli::load_seed(&load_conf(&ctx)?)?,
    };

    Ok(base64::encode(id.0))
}

///
/// Show your public signing key.
///
/// Print the public key corresponding to the signing keypair associated with
/// the configured identity seed. .
#[derive(Parser)]
struct Pubkey
{
    /// Override the configured identity seed
    #[clap(long, value_name = "b64", display_order = 1)]
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

///
/// AEAD/Sealed-box open.
///
/// The decrypt operation works with both 32 byte identity seeds and the 8 byte
/// Mu. The actual symmetric key is derived appropriate in each case.
///
#[derive(Parser)]
struct Decrypt
{
    /// Identity seed.
    #[clap(long, value_name = "b64", conflicts_with = "mu", display_order = 1)]
    seed: Option<String>,

    /// 8 byte Mu seed.
    #[clap(
        long,
        value_name = "b64",
        conflicts_with = "seed",
        display_order = 1
    )]
    mu: Option<String>,

    /// Bind context in which the decrypted data should be used.
    /// Options: "vault", "split", "combine", "transfer"
    #[clap(long, value_name = "option", display_order = 1)]
    bind: Option<String>,

    /// Custom additional data context. Cannot be specified when a --bind is
    /// also provided. Bindings are uno domain specific contexts for the aead.
    #[clap(
        long,
        value_name = "text",
        conflicts_with = "bind",
        display_order = 1
    )]
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

    let data =
        uno::decrypt(ctx, key, &blob[..]).context("decryption failed")?;

    Ok(String::from_utf8(data)?)
}

///
/// AEAD/Sealed-box seal.
///
/// The encrypt operation works with both 32 byte identity seeds and the 8 byte
/// Mu. The actual symmetric key is derived appropriate in each case.
///
#[derive(Parser)]
struct Encrypt
{
    /// 32 byte identity seed.
    #[clap(long, value_name = "b64", conflicts_with = "mu", display_order = 1)]
    seed: Option<String>,

    /// 8 byte Mu seed.
    #[clap(
        long,
        value_name = "b64",
        conflicts_with = "seed",
        display_order = 1
    )]
    mu: Option<String>,

    /// Bind context in which the encrypted data should be used.
    /// Options: "vault", "split", "combine", "transfer"
    #[clap(long, value_name = "option", display_order = 1)]
    bind: Option<String>,

    /// Custom additional data context. Cannot be specified when a --bind is
    /// also provided. Bindings are uno domain specific contexts for the aead.
    #[clap(
        long,
        value_name = "text",
        conflicts_with = "bind",
        display_order = 1
    )]
    data: Option<String>,

    /// Output raw bytes instead of base64 encoded data.
    #[clap(long, display_order = 1)]
    raw: bool,
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
    let _ = stdin().read_to_string(&mut plaintext)?;

    let blob = uno::encrypt(ctx, key, &plaintext.as_bytes())
        .context("encryption failed")?;

    let out = match c.raw {
        true => "raw not supported".into(),
        false => base64::encode(&blob[..]),
    };

    Ok(out)
}

///
/// Sign a message using the configured Uno ID.
///
/// The message is read from stdin.
///
#[derive(Parser)]
struct Sign
{
    /// Override the configured identity
    #[clap(long, value_name = "b64", display_order = 1)]
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
    let _ = stdin().read_to_string(&mut message)?;

    use uno::Signer;
    let sig = key.sign(&message.as_bytes());
    Ok(base64::encode(&sig.to_bytes()))
}

///
/// Verify a signature on a message.
///
/// The message is read from stdin.
///
#[derive(Parser)]
struct Verify
{
    /// EdDSA public key.
    #[clap(long, value_name = "b64", display_order = 1)]
    pubkey: String,

    /// Signature to verify.
    #[clap(long, value_name = "b64", display_order = 1)]
    signature: String,
}

fn do_verify(_: Context, c: Verify) -> Result<String>
{
    use uno::Verifier;

    let raw =
        base64::decode(c.pubkey).context("pubkey must be base64 encoded")?;
    let pubkey =
        uno::PublicKey::from_bytes(&raw[..]).context("invalid public key")?;
    let bytes = base64::decode(c.signature)
        .context("signature must be base64 encoded")?;

    let sig = uno::Signature::from_bytes(&bytes)?;

    let mut message = String::new();
    let _ = stdin().read_to_string(&mut message)?;

    pubkey
        .verify(&message.as_bytes(), &sig)
        .context("signature failed to verify")?;

    Ok("The signature is valid.".into())
}

///
/// Operate on a vault.
///
#[derive(Parser)]
struct Vault
{
    #[clap(subcommand)]
    subcmd: VaultCmd,
    #[clap(flatten)]
    opts: VaultOpts,
}

#[derive(Parser)]
struct VaultOpts
{
    /// Vault service API endpoint. If specified, supersedes the configured the
    /// configured value.
    #[clap(long, value_name = "endpoint", display_order = 1)]
    url: Option<String>,

    /// Identity seed to use. If specified, supersedes the configured value.
    #[clap(long, value_name = "b64", display_order = 1)]
    seed: Option<String>,
}

#[derive(Parser)]
enum VaultCmd
{
    #[clap(display_order = 1)]
    Get(VaultGet),

    #[clap(display_order = 1)]
    Put(VaultPut),
}

///
/// Get the latest saved copy of a vault.
///
#[derive(Parser)]
struct VaultGet;

///
/// Update a vault.
///
#[derive(Parser)]
struct VaultPut;

fn do_vault(ctx: Context, v: Vault) -> Result<String>
{
    match v.subcmd {
        VaultCmd::Get(c) => do_vault_get(ctx, v.opts, c),
        VaultCmd::Put(c) => do_vault_put(ctx, v.opts, c),
    }
}

fn do_vault_get(ctx: Context, opt: VaultOpts, _: VaultGet) -> Result<String>
{
    let cfg = load_conf(&ctx)?;

    let id = match opt.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };

    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let v = cli::get_vault(&cfg, url, id).context("cannot download vault")?;

    Ok(v)
}

fn do_vault_put(ctx: Context, opt: VaultOpts, _: VaultPut) -> Result<String>
{
    let cfg = load_conf(&ctx)?;

    let id = match opt.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };

    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let mut data = String::new();
    let _ = stdin().read_to_string(&mut data)?;

    let v = cli::put_vault(&cfg, url, id, data.as_bytes())
        .context("cannot upload vault")?;

    Ok(v)
}

///
/// Generate an uno shamir's secert sharing session entropy seed.
///
#[derive(Parser)]
struct Mu;

fn do_mu(_: Context, _: Mu) -> Result<String>
{
    let id = uno::Mu::new();
    Ok(base64::encode(id.0))
}

///
/// Print the session id derived from Mu entropy.
///
#[derive(Parser)]
struct Session
{
    /// Identity seed
    #[clap(long, value_name = "b64", display_order = 1)]
    mu: String,
}

fn do_session(_: Context, c: Session) -> Result<String>
{
    let mu = mu_from_b64(c.mu)?;
    let sid = uno::Session::try_from(mu)?;
    Ok(base64::encode_config(&sid.0, base64::URL_SAFE_NO_PAD))
}

#[derive(Parser)]
struct VerifyToken
{
    #[clap(subcommand)]
    subcmd: VerifyTokenCmd,
    #[clap(flatten)]
    opts: VerifyTokenOpts,
}

#[derive(Parser)]
struct VerifyTokenOpts
{
    #[clap(long, value_name = "endpoint", display_order = 1)]
    url: Option<String>,
}

#[derive(Parser)]
enum VerifyTokenCmd
{
    #[clap(display_order = 1)]
    Create(VerifyTokenCreate),

    #[clap(display_order = 2)]
    Verify(VerifyTokenVerify),
}

fn do_verify_token(ctx: Context, h: VerifyToken) -> Result<String>
{
    match h.subcmd {
        VerifyTokenCmd::Create(t) => do_verify_token_create(ctx, h.opts, t),
        VerifyTokenCmd::Verify(t) => do_verify_token_verify(ctx, h.opts, t),
    }
}

#[derive(Parser)]
struct VerifyTokenCreate
{
    #[clap(long, value_name = "email", display_order = 1)]
    email: Option<String>,

    /// Identity seed to use. If specified, supersedes the configured value.
    #[clap(long, value_name = "b64", display_order = 1)]
    seed: Option<String>,
}

fn do_verify_token_create(
    ctx: Context,
    opt: VerifyTokenOpts,
    c: VerifyTokenCreate,
) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let id = match c.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };

    let v = cli::create_verify_token(url, id, c.email)
        .context("cannot create verify token")?;

    Ok(v)
}

#[derive(Parser)]
struct VerifyTokenVerify
{
    #[clap(long, value_name = "secret", display_order = 1)]
    secret: String,

    /// Identity seed to use. If specified, supersedes the configured value.
    #[clap(long, value_name = "b64", display_order = 2)]
    seed: Option<String>,
}

fn do_verify_token_verify(
    ctx: Context,
    opt: VerifyTokenOpts,
    v: VerifyTokenVerify,
) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let id = match v.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };

    let c = cli::verify_verify_token(url, id, v.secret)
        .context("cannot verify verify token")?;

    Ok(c)
}

#[derive(Parser)]
struct Share
{
    #[clap(subcommand)]
    subcmd: ShareCmd,
    #[clap(flatten)]
    opts: ShareOpts,
}

#[derive(Parser)]
struct ShareOpts
{
    #[clap(long, value_name = "endpoint", display_order = 1)]
    url: Option<String>,
}

#[derive(Parser)]
enum ShareCmd
{
    #[clap(display_order = 1)]
    Get(ShareGet),

    #[clap(display_order = 2)]
    Put(SharePut),
}

fn do_share(ctx: Context, h: Share) -> Result<String>
{
    match h.subcmd {
        ShareCmd::Get(s) => do_share_get(ctx, h.opts, s),
        ShareCmd::Put(s) => do_share_put(ctx, h.opts, s),
    }
}

#[derive(Parser)]
struct ShareGet
{
    #[clap(long, value_name = "b64", display_order = 1)]
    seed: String,
}

fn do_share_get(ctx: Context, opt: ShareOpts, g: ShareGet) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);
    let seed = id_from_url_b64(g.seed)?;

    let v = cli::get_share(url, seed)?;

    Ok(v)
}

#[derive(Parser)]
struct SharePut
{
    #[clap(
        long,
        value_name = "expire_seconds",
        display_order = 1,
        default_value = "86400"
    )]
    expire_seconds: String,

    /// Identity seed to use. If specified, supersedes the configured value.
    #[clap(long, value_name = "b64", display_order = 1)]
    seed: Option<String>,
}

fn do_share_put(ctx: Context, opt: ShareOpts, p: SharePut) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let id = match p.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };

    let mut data = String::new();
    let _ = stdin().read_to_string(&mut data)?;

    let v = cli::post_share(url, id, &p.expire_seconds, data.as_bytes())
        .context("cannot upload share")?;

    Ok(v)
}

///
/// Shamir's secret sharing session operations.
///
/// When operating on the session endpoint, data in the "share" field will be
/// encrypted prior to uploading and decrypted when downloading.
///
#[derive(Parser)]
struct Ssss
{
    #[clap(subcommand)]
    subcmd: SsssCmd,
    #[clap(flatten)]
    opts: SsssOpts,
}

#[derive(Parser)]
struct SsssOpts
{
    /// Ephemeral session API endpoint. If specified, supersedes the configured
    /// value.
    #[clap(long, value_name = "endpoint", display_order = 1)]
    url: Option<String>,

    /// 80 bit (10 byte) session entropy to use. Not the same as the identity
    /// seed entropy. You can generate entropy with `uno mu`.
    #[clap(long, value_name = "b64", display_order = 1)]
    mu: String,
}

#[derive(Parser)]
enum SsssCmd
{
    #[clap(display_order = 1)]
    Get(SsssGet),

    #[clap(display_order = 2)]
    Put(SsssPut),

    #[clap(display_order = 3)]
    Patch(SsssPatch),
}

fn do_ssss(ctx: Context, c: Ssss) -> Result<String>
{
    match c.subcmd {
        SsssCmd::Get(s) => do_ssss_get(ctx, c.opts, s),
        SsssCmd::Put(s) => do_ssss_put(ctx, c.opts, s),
        SsssCmd::Patch(s) => do_ssss_patch(ctx, c.opts, s),
    }
}

///
/// Get a session using the session-id derived from the provided `mu` entropy.
///
/// The data in the "share" field is decrypted for you during this operation.
///
#[derive(Parser)]
struct SsssGet;

fn do_ssss_get(ctx: Context, opt: SsssOpts, _: SsssGet) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let mu = mu_from_b64(opt.mu)?;

    let s = cli::get_ssss(url, mu).context("cannot download session")?;
    Ok(s)
}

///
/// Put a share and associated data at the session-id endpoint derived from the
/// provided `mu` entropy.
///
/// The data in the "share" field is encrypted for you during this operation.
/// This command expects the JSON data to be uploaded on STDIN.
///
#[derive(Parser)]
struct SsssPut;

fn do_ssss_put(ctx: Context, opt: SsssOpts, _: SsssPut) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let mu = mu_from_b64(opt.mu)?;

    let mut data = String::new();
    let _ = stdin().read_to_string(&mut data)?;

    let s = cli::put_ssss(url, mu, data.as_bytes())
        .context("cannot upload session")?;

    Ok(s)
}

///
/// Update individual fields in an existing share session.
///
/// This command expects the JSON data to be uploaded on STDIN.
///
#[derive(Parser)]
struct SsssPatch;

fn do_ssss_patch(ctx: Context, opt: SsssOpts, _: SsssPatch) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let url = opt.url.as_ref().unwrap_or(&cfg.api_host);

    let mu = mu_from_b64(opt.mu)?;

    let mut data = String::new();
    let _ = stdin().read_to_string(&mut data)?;

    let s = cli::patch_ssss(url, mu, data.as_bytes())
        .context("cannot update session")?;

    Ok(s)
}

///
/// SLIP-0039 recovery shares operations
///
#[derive(Parser)]
enum S39
{
    #[clap(display_order = 1)]
    Split(S39Split),

    #[clap(display_order = 2)]
    Combine(S39Combine),

    #[clap(display_order = 3)]
    View(S39View),
}

///
/// SLIP-0039 recovery shares options
///
#[derive(Parser)]
struct S39Cmd
{
    // TODO group threshold, group support, etc.
    #[clap(subcommand)]
    subcmd: S39,
}

///
/// Split the configured uno identity seed into a number of shares. .
///
#[derive(Parser)]
struct S39Split
{
    /// minimum shares needed to reconstitute the seed
    #[clap(long, value_name = "num", default_value = "2", display_order = 1)]
    minimum: u8,

    /// total shares generated
    #[clap(long, value_name = "num", default_value = "3", display_order = 1)]
    total: u8,

    // TODO support groups
    /// Override the configured identity.
    seed: Option<String>,
}

fn do_s39(ctx: Context, s: S39Cmd) -> Result<String>
{
    match s.subcmd {
        S39::Split(c) => do_s39_split(ctx, c),
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

    let groups = uno::split(id, &[(c.minimum, c.total)])
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
        let mnemonic = share.to_mnemonic().map_err(|e| anyhow!(e))?;
        view.push('\t');
        view.push('\t');
        view.push_str(&mnemonic.join(" "));
        view.push(',');
        view.push('\n');
    }
    view.push_str("\t]");

    Ok(view)
}

///
/// Combine shares of a split seed back into the whole identity seed.
///
#[derive(Parser)]
struct S39Combine
{
    /// mnemonic share obtained from a previous s39 split operation
    #[clap(
        long,
        value_name = "nmemonic",
        multiple_values = true,
        multiple_occurrences = true
    )]
    shares: Vec<String>,
}

fn do_s39_combine(c: S39Combine) -> Result<String>
{
    let parsed = c
        .shares
        .iter()
        .map(|s| s.split(" ").map(|us| us.to_owned()).collect())
        .collect::<Vec<Vec<String>>>();

    let id = uno::combine(&parsed[..]).context("failed to combine shares")?;

    Ok(base64::encode_config(&id.0, base64::STANDARD_NO_PAD))
}

///
/// View metadata about a mnemonic share.
///
#[derive(Parser)]
struct S39View
{
    /// mnemonic share obtained from a previous s39 split operation
    share: String,
}

fn do_s39_view(c: S39View) -> Result<String>
{
    let words: Vec<String> = c.share.split(' ').map(|s| s.to_owned()).collect();
    let share = uno::Share::from_mnemonic(&words).map_err(|e| anyhow!(e))?;

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


///
/// Directory options
///
#[derive(Parser)]
struct DirectoryCmd
{
    #[clap(subcommand)]
    subcmd: Directory,
    #[clap(flatten)]
    opts: DirectoryOpts,
}

#[derive(Parser)]
struct DirectoryOpts
{
    /// Vault service API endpoint. If specified, supersedes the configured the
    /// configured value.
    #[clap(long, value_name = "endpoint", display_order = 1)]
    url: Option<String>,

    /// Identity seed to use. If specified, supersedes the configured value.
    #[clap(long, value_name = "b64", display_order = 1)]
    seed: Option<String>,
}

fn do_directory(ctx: Context, s: DirectoryCmd) -> Result<String>
{
    match s.subcmd {
        Directory::Lookup(c) => do_directory_lookup(ctx, s.opts, c),
        Directory::Entry(c) => do_directory_entry(ctx, s.opts, c),
        Directory::Verify(c) => do_directory_verify(ctx, s.opts, c),
    }
}

///
/// Directory subcommands
///
#[derive(Parser)]
enum Directory
{
    #[clap(display_order = 1)]
    Lookup(DirectoryLookup),

    #[clap(display_order = 2)]
    Entry(DirectoryEntry),

    #[clap(display_order = 3)]
    Verify(DirectoryVerify),
}


///
/// Lookup directory entry cids by phone number.
///
#[derive(Parser)]
struct DirectoryLookup
{
    /// A default locale used to validate any phone numbers without a country
    /// code.
    #[clap(
        long,
        value_name = "ISO 3166",
        default_value = "US",
        display_order = 1
    )]
    country: String,

    /// A list of phone numbers to query.
    #[clap(long, value_name = "E.164", display_order = 1)]
    phones: Vec<String>,
}

fn do_directory_lookup(
    ctx: Context,
    opts: DirectoryOpts,
    c: DirectoryLookup,
) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let id = match opts.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };
    let url = opts.url.as_ref().unwrap_or(&cfg.api_host);

    let phones = c.phones.iter().map(|s| s.as_str()).collect::<Vec<_>>();

    let result = cli::lookup_cids(url, &id, &c.country, &phones)?;
    let output = serde_json::to_string_pretty(&result)?;

    Ok(output)
}

///
/// Get a directory entry by cid.
///
#[derive(Parser)]
struct DirectoryEntry
{
    /// The cid of the resource to get.
    #[clap(long, value_name = "b64", display_order = 1)]
    cid: String,
}


fn do_directory_entry(
    ctx: Context,
    opts: DirectoryOpts,
    c: DirectoryEntry,
) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let id = match opts.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };
    let url = opts.url.as_ref().unwrap_or(&cfg.api_host);

    let cid = base64::decode(c.cid)?;

    let result = cli::get_entry(url, &id, &cid)?;
    let output = serde_json::to_string_pretty(&result)?;

    Ok(output)
}

///
/// Verify a phone number, associating it with your Uno signing and encryption
/// keys.
///
/// This allows other people to find you on the Uno network to make
/// social backup and recovery easier.
///
#[derive(Parser)]
struct DirectoryVerify
{
    /// Country code to use if the provided phone does not have one.
    #[clap(
        long,
        value_name = "ISO 3166",
        default_value = "US",
        display_order = 1
    )]
    country: String,

    /// Phone number to verify.
    #[clap(long, value_name = "E.164", display_order = 1)]
    phone: String,

    /// Verification code in the event that one is required.
    #[clap(long, value_name = "code", display_order = 1)]
    verification: Option<String>,
}

fn do_directory_verify(
    ctx: Context,
    opts: DirectoryOpts,
    c: DirectoryVerify,
) -> Result<String>
{
    let cfg = load_conf(&ctx)?;
    let id = match opts.seed {
        Some(s) => id_from_b64(s)?,
        None => cli::load_seed(&cfg)?,
    };
    let url = opts.url.as_ref().unwrap_or(&cfg.api_host);

    let key = uno::KeyPair::from(id);

    let signing_key_b64 = base64::encode(key.public.as_bytes());
    let encryption_key_b64 = "TODO: XXX".into();
    // TODO: I don't think we have dh lib support yet.

    let model = DirectoryEntryCreate {
        country: c.country,
        phone: c.phone,
        signing_key: signing_key_b64,
        encryption_key: encryption_key_b64,
    };

    let code = c.verification.as_deref();
    let result = cli::post_entry(url, &id, model, code)?;
    let output = serde_json::to_string_pretty(&result)?;

    Ok(output)
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
        SubCommand::Share(cmd) => do_share(ctx, cmd),
        SubCommand::S39(cmd) => do_s39(ctx, cmd),
        SubCommand::VerifyToken(cmd) => do_verify_token(ctx, cmd),
        SubCommand::Directory(cmd) => do_directory(ctx, cmd),
    }?;

    println!("{}", out);

    Ok(())
}

fn id_from_url_b64(seed: String) -> Result<uno::Id>
{
    let seed = base64::decode_config(seed, base64::URL_SAFE_NO_PAD)
        .context("seed must be base64 url encoded")?;
    let array = <[u8; 32]>::try_from(seed)
        .map_err(|_| anyhow!("seed must be exactly 32 bytes long"))?;
    Ok(uno::Id(array))
}

fn id_from_b64(seed: String) -> Result<uno::Id>
{
    let seed = base64::decode(seed).context("seed must be base64 encoded")?;
    let array = <[u8; 32]>::try_from(seed)
        .map_err(|_| anyhow!("seed must be exactly 32 bytes long"))?;
    Ok(uno::Id(array))
}

fn mu_from_b64(seed: String) -> Result<uno::Mu>
{
    let seed = base64::decode(seed).context("seed must be base64 encoded")?;
    let array = <[u8; 10]>::try_from(seed)
        .map_err(|_| anyhow!("seed must be exactly 10 bytes long"))?;
    Ok(uno::Mu(array))
}

#[cfg(test)]
mod test
{
    //    use super::*;

    #[test]
    fn test_id() {}
}
