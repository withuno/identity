# identity
The Uno identity platform.

There are two binaries, `uno` and `api`.

* `uno` is the cli for interacting with libuno and with the api.
* `api` is the server hosting vault and shmirs split/combine endpoints.

Supporting crates include: `adi`, `djb`, and `lib`.

* `adi` contains our reference implementation of SSS, guided by HashiCorp's go implementation.
* `djb` contains Curve25519 crypto, both symmetric cand asymmetric (chacha20-poly1305 AEAD and ed25519 public key signing).
* `lib` is libuno, which incorporates `adi` and `djb` as well as providing types for creating and working with uno identities (32 bytes of entropy plus some kdf).

TODO: link the subdirs.

# Usage

Run the uno cli like:
```
cargo run --bin uno
```

Same goes for the server:
```
cargo run --bin api
```

You can test everything using:
```
cargo test
```

If you just want to run the tests in a single "package", use:
```
cargo test -p <pkg>
```

For example, `cargo test -p adi` or `cargo test -p uno`.


# Legal things

(shamlessly cribbed from Signal's README)

## Cryptography Notice

This distribution includes cryptographic software.
The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing
cryptographic functions with asymmetric algorithms.
The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.

## License

Copyright 2021 WithUno, Inc. 

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
