#!/usr/bin/env bash
# Build the actsnmp interop image (idempotent; uses the docker build cache).
#   interop/build.sh [extra docker build args, e.g. --no-cache --build-arg WITH_MIBS=0]
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

hash="$(src_hash)"
log "building $IMAGE (srchash $hash)"
docker build \
    --label "actsnmp.srchash=$hash" \
    -t "$IMAGE" \
    "$@" \
    "$INTEROP_DIR"
log "built $IMAGE"
