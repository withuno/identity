#!/bin/sh

curl -XGET "http://localhost:8080/v1/vaults/$(cat seed.pub)" \
    -H "x-uno-timestamp: $(cat timestamp)" \
    -H "x-uno-signature: $(cat timestamp-sig)" \
    --trace-ascii -
