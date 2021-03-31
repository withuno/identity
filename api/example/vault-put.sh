#!/bin/sh

curl -XPUT "http://localhost:8080/v1/vaults/$(cat seed.pub)" \
    -H "x-uno-timestamp: $(cat timestamp)" \
    -H "x-uno-signature: $(cat timestamp-sig)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @vault-bin \
    --trace-ascii -

