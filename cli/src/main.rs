//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// The uno utility is a cli frontend to operations that can be performed with an uno identity.

use clap::Clap;

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
}

/// Generate an uno identity.
#[derive(Clap)]
struct Seed;

/// Print the public key corresponding to the signing keypair.
#[derive(Clap)]
struct Pubkey {
    /// identity seed
    #[clap(long)]
    seed: String,
}

/// Split an uno identity seed into a number of shares..
#[derive(Clap)]
struct Split {
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

/// Combine shares of a split seed back into the whole identity seed.
#[derive(Clap)]
struct Combine {
    /// shares
    #[clap(
        long,
        value_name = "b64",
        multiple = true,
        multiple_occurrences = true)]
    shares: Vec<String>,
}

/// AEAD open
#[derive(Clap)]
struct Decrypt {
    /// Identity seed.
    #[clap(long, value_name = "b64")]
    seed: String,
    /// Nonce used during encryption.
    #[clap(long)]
    nonce: Option<String>,
    /// The message to decrypt, base64 encoded.
    ciphertext: String,
    /// Additional data
    #[clap(long, value_name = "b64")]
    data: Option<String>,
}

/// AEAD seal
#[derive(Clap)]
struct Encrypt {
    /// Identity seed.
    #[clap(long, value_name = "b64")]
    seed: String,
    /// The message to encrypt, base64 encoded.
    plaintext: String,
    /// Additional Data
    #[clap(long, value_name = "b64")]
    data: Option<String>,
}

/// Verify a signature on a message.
#[derive(Clap)]
struct Verify {
    /// EdDSA public key.
    #[clap(long, value_name = "b64")]
    pubkey: String,
    /// The message to decrypt.
    message: String,
    /// Signature to verify.
    #[clap(long, value_name = "b64")]
    signature: String
}

/// Sign a message using an Uno ID.
#[derive(Clap)]
struct Sign {
    /// Identity seed to use.
    #[clap(long)]
    seed: String,
    /// Data to sign.
    message: String,
}

/// Operate on a vault.
#[derive(Clap)]
struct Vault {
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

fn do_vault(c: Vault)
{
    use http_types::Method;
    use std::str::FromStr;

    let id = id_from_b64_seed(c.seed);
    let method = Method::from_str(&c.method)
        .expect("error: invalid method");

    match method {
        Method::Get => {
            let v = uno::get_vault(c.url, id)
                .expect("error downloading vault");
            println!("{}", v);
        },
        Method::Put => {
            let data = c.data.expect("data is required");
            let v = uno::put_vault(c.url, id, data.as_bytes())
                .expect("error uploading vault");
            println!("{}", v);
        },
        _ => panic!("error: bad method"),
    }
}

use std::convert::TryFrom;

fn main() {
    let opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Seed(_) => {
            let id = uno::Id::new();
            println!("{}", base64::encode(id.0));
        },

        SubCommand::Pubkey(c) => {
            let id = id_from_b64_seed(c.seed);
            let key = uno::Signing::from(id);
            println!("{}", base64::encode(&key.public.as_bytes()));
        },

        SubCommand::Decrypt(c) => {
            let id = id_from_b64_seed(c.seed);
            let key = uno::Encryption::from(id);
            let blob = base64::decode(c.ciphertext)
                .expect("error: ciphertext must be base64 encoded");
            let _ = c.data; // TODO add additional data support
            let _ = c.nonce; // TODO maybe add separate nonce support
                             //      right now nonce is part of ciphertext
            match uno::decrypt(key, &blob[..]) {
                Err(e) => {
                    panic!("error: decryption failed {}", e);
                },
                Ok(c) => {
                    println!("{}", std::str::from_utf8(&c).unwrap());
                },
            }
        },

        SubCommand::Encrypt(c) => {
            let id = id_from_b64_seed(c.seed);
            let key = uno::Encryption::from(id);
            let _ = c.data; // TODO add additional data support
            match uno::encrypt(key, &c.plaintext.as_bytes()) {
                Err(e) => {
                    panic!("error: encryption failed {}", e);
                },
                Ok(blob) => {
                    println!("{}", base64::encode(&blob[..]));
                },
            }
        },

        SubCommand::Split(c) => {
            let id = id_from_b64_seed(c.seed);
            let shares = uno::split(id, &[(c.minimum,c.total)])
                .expect("error: failed to split shares");
            println!("");
            for share in shares {
                let enc = base64::encode(&share[..]);
                println!("{}", enc);
                println!("");
            }
        },

        SubCommand::Combine(c) => {
            let parsed = c.shares.iter()
                .map(|s| base64::decode(s))
                .map(|r| r.expect("failed to parse share"))
                .collect::<Vec<_>>();
            let id = uno::combine(&parsed[..])
                .expect("error: failed to combine shares");
            println!("{}", base64::encode(&id.0));
        },

        SubCommand::Sign(c) => {
            use uno::Signer;
            let id = id_from_b64_seed(c.seed);
            let key = uno::Signing::from(id);
            let sig = key.sign(&c.message.as_bytes());
            println!("{}", base64::encode(&sig.to_bytes()));
        },

        SubCommand::Verify(c) => {
            use uno::Verifier;
            let raw = base64::decode(c.pubkey)
                .expect("error: pubkey must be base64 encoded");
            let pubkey = uno::Verification::from_bytes(&raw[..])
                .expect("error: invalid public key");
            let bytes = base64::decode(c.signature)
                .expect("error: signature must be base64 encoded");
            let array = <[u8; uno::SIGNATURE_LENGTH]>::try_from(bytes)
                .expect("error: seed must be 64 bytes long");
            let sig = uno::Signature::new(array);
            pubkey.verify(&c.message.as_bytes(), &sig)
                .expect("error: signature failed to verify");
            println!("{}", "success");
        },

        SubCommand::Vault(c) => do_vault(c),
    }
}

fn id_from_b64_seed(seed: String) -> uno::Id {
    let seed = base64::decode(seed)
        .expect("error: Seed must be base64 encoded");
    let array = <[u8; 32]>::try_from(seed)
        .expect("error: seed must be 32 bytes long");
    uno::Id(array)
}


#[cfg(test)]
mod test {
//    use super::*;

    #[test]
    fn test_id() {
        // use:
        // https://docs.rs/clap/3.0.0-beta.2/clap/struct.App.html#method.try_get_matches_from
    }
}
