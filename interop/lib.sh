# shellcheck shell=bash
# Common settings for the actsnmp interop lab scripts (sourced, not executed).

INTEROP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${ACTSNMP_INTEROP_IMAGE:-actsnmp-interop:1}"

C_SNMPD=actsnmp-snmpd
C_SNMPSIM=actsnmp-snmpsim
C_SNMPTRAPD=actsnmp-snmptrapd
C_TOOLS=actsnmp-tools
ALL_CONTAINERS=("$C_SNMPD" "$C_SNMPSIM" "$C_SNMPTRAPD" "$C_TOOLS")

SNMPD_PORT=16161
SNMPSIM_PORT=16162
ACTON_AGENT_PORT=16163
SNMPTRAPD_PORT=16164
ACTSNMP_TRAPD_PORT=16165   # actsnmp trapd, or the notifycheck.sh --selftest stand-in

log() { echo "[interop] $*" >&2; }
die() { echo "[interop] ERROR: $*" >&2; exit 1; }

# Hash over everything that goes into the image; stored as image label so that
# up.sh can detect a stale image and rebuild it.
src_hash() {
    (
        cd "$INTEROP_DIR"
        find Dockerfile requirements.txt config container dataset snmpsim/variation \
             tools pysnmp_client.py pysnmp_notify.py -type f ! -name '*.pyc' ! -path '*/__pycache__/*' \
             -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16
    )
}

image_hash() {
    docker image inspect -f '{{ index .Config.Labels "actsnmp.srchash" }}' "$IMAGE" 2>/dev/null || true
}

container_running() {
    [ "$(docker container inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" = "true" ]
}

container_image_id() {
    docker container inspect -f '{{.Image}}' "$1" 2>/dev/null || true
}

image_id() {
    docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true
}
