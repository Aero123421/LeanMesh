#!/bin/sh
# Illustrative commands only. Requires a future Host implementation and an explicit token.
set -eu
: "${LEANMESH_TOKEN:?Set a valid local API token; never commit it}"
curl --fail-with-body --unix-socket /run/leanmesh/api.sock \
  -H "Authorization: Bearer $LEANMESH_TOKEN" \
  http://localhost/v1/status
# For POST /v1/messages first open and retain a client_epoch, then use a stable
# Idempotency-Key. An HTTP202 is NOT APP_APPLIED.
