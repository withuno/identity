#!/bin/sh

curl -XGET "http://localhost:3000/api/v1/sss/combine/$(cat session-id.b64)"
