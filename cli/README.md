uno cli
===

A command-line interface for working with uno data and services.

At a high level, the CLI allows you to generate entropy for an Uno ID and perform useful operations with it.
For example, you can use the CLI to sign and encrypt messages, split and recombine your ID, and post ephemeral sessions.
You can also add your info to the Uno directory, and verify an email.

The CLI stores working information like your ID and config options in the `~/.uno` directory.


# Overview

The `uno` CLI program supports performing basic crypto operations with an uno identity (such as deriving keys and performing key split and recombination logic) as well as interfacing with the API server. The CLI is not a fully functional Uno client at the moment. Consult the [issue tracker][issues] for details.

[issues]: https://github.com/withuno/identity/issues?q=is%3Aissue+is%3Aopen+label%3Acli-client

# Examples

The cli is pretty self-explanatory.
Run `uno [help]` (or use `cargo run` in this directory) to get going:

```
$ uno help
cli 0.1
David C. <david@uno.app>

USAGE:
    uno <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    decrypt    AEAD open The decrypt operation works with both 32 byte
                   identity seeds and the 8 byte Mu. The actual symmetric key is
                   derived appropriate in each case
    encrypt    AEAD seal. The encrypt operation works with both 32 byte
                   identity seeds and the 8 byte Mu. The actual symmetric key is
                   derived appropriate in each case
    help       Print this message or the help of the given subcommand(s)
    mu         Generate an uno shamir's secert sharing session entropy seed
    pubkey     Print the public key corresponding to the signing keypair
    s39        SLIP-0039 Options
    seed       Generate an uno identity
    session    Print the session id derived from Mu entropy
    sign       Sign a message using an Uno ID
    ssss       Shamir's secret sharing session operations
    vault      Operate on a vault
    verify     Verify a signature on a message
```

To dive in, add a subcommand:

```
$ uno help seed
uno-seed 
Generate an uno identity. An identity seed is 32 bytes of entropy. The base64
encoding of the entropy is written to standard out.

USAGE:
    uno seed

OPTIONS:
    -h, --help    Print help information
```

If the CLI does not provide enough information from there on out, please file an issue.

