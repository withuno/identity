#!/bin/sh

curl -XPUT "http://localhost:8080/v1/ssss/$(cat session-id.b64)" \
    --data-binary @session-put.json
