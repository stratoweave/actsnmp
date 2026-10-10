#!/usr/bin/env bash
# Build the MIB oracle image actsnmp-mibs:1 (idempotent; uses the docker build cache).
#   interop/mibs/build.sh [extra docker build args]
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

hash="$(cd "$MIBS_DIR/docker" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)"
log "building $MIBS_IMAGE (srchash $hash)"
locked docker build --label "actsnmp.mibs.srchash=$hash" -t "$MIBS_IMAGE" "$@" "$MIBS_DIR/docker"
log "built $MIBS_IMAGE"
