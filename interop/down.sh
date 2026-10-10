#!/usr/bin/env bash
# Stop and remove all interop lab containers (idempotent).  The image is kept.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for c in "${ALL_CONTAINERS[@]}"; do
    if docker container inspect "$c" >/dev/null 2>&1; then
        log "removing $c"
        docker rm -f "$c" >/dev/null
    fi
done
log "lab is down"
