uno cli
===

A command-line interface for working with uno data and services.

# Overview

The `uno` CLI program supports performing basic crypto operations with an uno identity (such as deriving keys and performing key split and recombination logic) as well as interfacing with the API server. The CLI is not a fully functional Uno client at the moment. Consult the [issue tracker][issues] for details.

[issues]: https://github.com/withuno/identity/issues?q=is%3Aissue+is%3Aopen+label%3Acli-client

# Examples

The cli is pretty self-explanatory. Just run with no arguments to get going:

```
$ uno help
cli 0.1
David C. <david@withuno.com>

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

To dive in, jsut add a subcommand:

```
$ uno help seed
uno-seed 
Generate an uno identity

USAGE:
    uno seed

OPTIONS:
    -h, --help    Print help information
```


