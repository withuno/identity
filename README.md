Uno Identity Manager
===

The Uno identity platform is a modern <strike>password</strike> identity manager.
We have full featured clients on [iOS/macOS][1] with an accompanying [browser extension][2] for Safari and the Chrome family of browsers.
This is our Rust reference implementation with a CLI and associated API server.
You can read more about our project and design on [our blog][3].

[1]:
[2]:
[3]:

Note: the CLI is not currently designed to be used as a fully functional Uno client in the way our mobile, desktop, and browser applications are.
If you're intersted in a full-featured open source rust CLI password manager like we are, please, help us build it out (:

# Overview

There are two binaries:

* [`uno`](cli) is the cli for interacting with libuno and with the API.
* [`api`](api) is the server used for storage, messaging, and ephemeral sessions.

Supporting crates include:

* [`adi`](adi) contains our reference implementation of [SSS][sss], guided by HashiCorp's [go implementation][hashi-sss].
* [`djb`](djb) contains Curve25519 crypto, both symmetric cand asymmetric (chacha20-poly1305 AEAD and ed25519 public key signing).
* [`ffi`](ffi) contains the C bindings for libuno.
* [`lib`](lib) is libuno, which incorporates `s39` and `djb` as well as providing types for creating and working with uno identities (32 bytes of entropy plus some kdf).
* [`s39`](s39) exposes  SLIP-39 functionality using Uno library types.
* [`wsm`](wsm) [wasm][wasm] [bindings][wbindgen] for libuno, used in our browser extensions.
* [`xcf`](xcf) packages the `ffi` as an XCFramework use with [UnoSwift][] in our iOS and macOS apps.

[sss]: https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing
[hashi-sss]: https://github.com/hashicorp/vault/tree/main/shamir
[unoswift]: http://github.com/withuno/unoswift
[wasm]: https://webassembly.org
[wbindgen]: https://rustwasm.github.io/docs/wasm-bindgen/

# Usage

Run the uno CLI like:
```
cargo run --bin uno
```

Or the API server:
```
cargo run --bin api
```

Test everything using:
```
cargo test
```

If you just want to run the tests in a single "package", use:
```
cargo test -p <pkg>
```

For example, `cargo test -p lib` or `cargo test -p uno`.

When possible it's nice to use the `--release` flag.
Argon2 runs noticably faster with optimizations.

# Style

Code should read like a book.
The singular style goal is to structure code such that it grows vertically instead of horizontally.
To that end, we have an arbitrary column limit of 80 chars.
If your lines are under the limit, you're probably doing it right.

The README is sentence lines.
Since we're writing prose that gets formatted by whatever is rendering it, we don't care about manually formatting the README.
It's easier to move sentences around when they're on individual lines, so that's what we do.


# Legal things

Inspired by Signal's README (but not copied verbatim because we are EAR99):

## Cryptography Notice

This distribution includes cryptographic software.
The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See <http://www.wassenaar.org/> for more information.

In it's current form, this software exists to help users practically and securely manage their account credentials and login information.
In the United States, under the Export Administration Regulations (“EAR”), encryption software limited to authentication applications is not controlled as an encryption item and can be classified under Export Commodity Control Number (ECCN): **EAR99**.
The usage of encryption in this software is limited to the support of its primary function: password management and authentication.
Thus, this software does not require specific U.S. government authorization to export in either object or source form.

## License

Copyright 2021 WithUno, Inc. 

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
