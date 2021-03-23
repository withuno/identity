#!/bin/sh

curl -XGET "http://localhost:8080/v1/ssss/$(cat session-id.b64)"
