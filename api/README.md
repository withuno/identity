API
===

The uno API service.

Formerly `ror`, after Th[ror]: a dwarf with a big vault.

# Overview

This is Uno's local, development, and production API server.

The point of sharing this is not so that users go run their own API server.
It is so that concerned users can audit, verify, and critique our implementation and help us improve it when sensible.
Of couse, you're welcome to run your own server, but (other than the CLI) our apps have no way to specify a custom API endpoint.
Supporting such use cases is not currently on our roadmap and, even if it was, we'd need a federated protocol so that independent nodes could route messages across an application layer "uno network".
We're not building a P2P network (at least we don't think we are, yet?).
The API server simply allows a given user's uno clients to store and synchronize encrypted vault data as well as coordinate recovery share distribution.

# Usage

From this directory, run the API server:
```
cargo run
```
```
tide::log Logger started
    level Info
tide::server Server listening on http://[::]:8080
```

Note, adding `--release` to turn on optimizations will speed things up significantly.
However, you'll trade the nice colored logs for production friendly structured JSON data instead.

## Database

By default, the server uses the filesystem as its backing store.
Upon startup, the server will create some data directories for storing vautls, sessions, mailboxes, nonces, etc.
If you'd prefer, you can point the server at anything that speaks S3.

For example, you can run minio (a local S3) using Docker like so:

```
docker run --name minio --rm -p 9000:9000 -p 9001:9001 minio/minio server /tmp/data --console-address :9001
```

In order to point the API server at your local minio instance, build with the `s3` feature:

```
cargo run --features s3
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

## Directory

The API server keeps a directory of phone numbers to pubkeys so that users can find other users for sharing credentials or key shards.
The client typically uses the system address book to perform lookups.
To appear in the directory, a user must claim their phone number(s).
By default, the API server will allow any user to claim any phone number.
This method of operation is rather insecure, so the API server also supports using Twilio Verify as a verification backend.

To run with Twilio enabled, pass the `twilio` feature.
```
cargo run --features s3 twilio 
```

For the `twilio` feature to work, you'll need to pass valid Twilio Verify API service identifiers and credentials:
```
TWILIO_API_ENDPOINT=https://twilio.com/
TWILIO_SERVICE_SID=********************
TWILIO_ACCOUNT_SID=********************
TWILIO_AUTH_TOKEN=********************
VERIFICATION_CODE_OVERRIDE_SMS=42424242
```

The `VERIFICATION_CODE_OVERRIDE_SMS` allows a static code to be accepted for phone verifications.
This is useful when using the live Twilio API in day-to-day development and regression testing.
Don't do this in production.


## Email Verification

When registering an account, users a prompted to verify an email address.
We use email to index an account.
This helps users not end up with multiple different vaults.
Like with the directory, by default any user can claim any email.
For real use case, an email verification backend can be enabled.

To require real email verification checks, pass the `customerio` feature:
```
cargo run --features s3 twilio customerio
````

For email verification using `customerio` to work, you'll need to pass valid credentials and a message template ID:
```
CUSTOMER_IO_API_ENDPOINT=https://api.customer.io/v1/send/email
CUSTOMER_IO_API_KEY=********************
CUSTOMER_IO_MESSAGE_ID=4
VERIFY_EMAIL_DOMAIN=https://verify.u1o.dev
```

For email verification to work, you must be running a verify site at `VERIFY_EMAIL_DOMAIN`.
Instructions TBD.
