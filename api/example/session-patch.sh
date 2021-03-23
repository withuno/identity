#!/bin/sh

curl -XPATCH "http://localhost:8080/v1/ssss/$(cat session-id.b64)" \
    --data-binary @session-patch.json
