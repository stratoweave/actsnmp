#!/usr/bin/env bash
# Run the generic interop checks, with both net-snmp's tools and pysnmp, against
# any agent that serves the lab dataset, typically actsnmp agent:
#
#   interop/agentcheck.sh acton=127.0.0.1:16163
#   interop/agentcheck.sh --quick --users u_noauth,u_sha_aes acton=127.0.0.1:16163,udp6:[::1]:16163
#   interop/agentcheck.sh --skip v1,negative acton=127.0.0.1:16163
#
# The agent must serve dataset/actsnmp_dataset.py below 1.3.6.1.4.1.8072.9999.1
# (writable objects reset to their initial values), communities public/private
# and the lab SNMPv3 users (see README.md). Writes a Markdown report to stdout
# and exits 0 when all mandatory checks pass. Only the tools container is needed.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

args=()
agents=()
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) args+=(--quick) ;;
        --users|--skip) args+=("$1" "$2"); shift ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *=*) agents+=(--agent "$1") ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done
[ ${#agents[@]} -gt 0 ] || die "usage: $0 [--quick] [--users LIST] [--skip LIST] NAME=ADDR[,ADDR6] ..."

if [ "$(image_hash)" != "$(src_hash)" ]; then
    "$INTEROP_DIR/build.sh"
fi
exec docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp "$IMAGE" \
    python3 /opt/actsnmp/tools/selftest.py "${args[@]}" "${agents[@]}"
