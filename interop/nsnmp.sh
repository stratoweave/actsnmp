#!/usr/bin/env bash
# Run a net-snmp command line tool (or any command) from the interop image with
# host networking, e.g.
#   interop/nsnmp.sh snmpget -v2c -c public 127.0.0.1:16161 1.3.6.1.2.1.1.1.0
#   interop/nsnmp.sh snmpbulkwalk -v2c -c public -On 127.0.0.1:16163 1.3.6.1
# Uses "docker exec" into the running actsnmp-tools container (fast) and falls
# back to a throw-away "docker run --rm --network host" container.
# Set NSNMP_STDIN=1 to forward stdin.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -ge 1 ] || die "usage: $0 <command> [args...]"
iflag=()
[ "${NSNMP_STDIN:-0}" = "1" ] && iflag=(-i)
if container_running "$C_TOOLS"; then
    exec docker exec "${iflag[@]}" "$C_TOOLS" "$@"
fi
[ -n "$(image_id)" ] || "$INTEROP_DIR/build.sh" >&2
exec docker run --rm "${iflag[@]}" --network host "$IMAGE" "$@"
