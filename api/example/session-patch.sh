#!/bin/sh

curl -XPATCH "http://localhost:3000/api/v1/sss/combine/$(cat session-id.b64)" \
    --data-binary @session-patch.json
