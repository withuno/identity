API
===

The uno API service.

Formerly `ror`, after Th[ror]: a dwarf with a big vault.

# Overview

This is Uno's local, development, and production API server.

First, let's get a few things out of the way:

* Yes we use an S3 like as our database.
* No we don't have microservices.
* If you think our Rust code is bad, it probably is. Please, tell us how to improve it; we won't be offended.

Finally, the point of sharing this is not so that users go run their own API server.
It is so that concerned users can audit, verify, and critique our implementation and help us improve it when sensible.
Of couse, you're welcome to run your own server, but (other than the CLI) our apps have no way to specify a custom API endpoint.
Supporting such use cases is not currently on our roadmap and, even if it was, we'd need a federated protocol so that independent nodes could route messages across an application layer "uno network".
We're not building a P2P network (at least we don't think we are, yet?).
The API server simply allows a given user's uno clients to store and synchronize encrypted vault data.

# Usage

From this directory, run the API server:
```
cargo +nightly run
```
```
tide::log Logger started
    level Info
tide::server Server listening on http://[::]:8080
```

Note, adding `--release` to turn on optimizations will speed things up significantly.
However, you'll trade the nice colored logs for production friendly structured JSON data instead.

By default, the server uses the filesystem as it's backing store.
Upon startup, the server will create some data directories for storing vautls, sessions, mailboxes, nonces, etc.
If you'd prefer, you can point the server at anything that speaks S3.

For example, you can run minio (a local S3) using Docker like so:

```
docker run --name minio --rm -p 9000:9000 -p 9001:9001 minio/minio server /tmp/data --console-address :9001
```

In order to point the API server at your local minio instance, build with the `s3` feature:

```
cargo +nightly run --features s3
```

You'll also need to tell the server where to find an s3 endpoint using:

```
SPACES_ACCESS_KEY_ID=minioadmin
SPACES_SECRET_ACCESS_KEY=minioadmin
SPACES_HOSTNAME=http://localhost:9000
SPACES_REGION=
SPACES_BUCKET_PREFIX=
```

For example, after starting the minio server, to run the tests using release optimizations against a real s3 impelmentation:

```
SPACES_ACCESS_KEY_ID=minioadmin SPACES_SECRET_ACCESS_KEY=minioadmin SPACES_HOSTNAME=http://localhost:9000 SPACES_REGION= SPACES_BUCKET_PREFIX= cargo +nightly test --release --features s3
```
