#!/usr/bin/env bash
# Start the interop lab (idempotent).  Builds/rebuilds the image when it is
# missing or older than the sources, (re)creates containers whose image is
# outdated, and waits until every agent answers SNMP.
#
#   interop/up.sh                 # snmpd + snmpsim + snmptrapd + tools
#   interop/up.sh snmpd tools     # only some services
#
# Services (all --network host, loopback only):
#   snmpd      net-snmp agent        udp 127.0.0.1:16161, udp6 [::1]:16161, tcp 127.0.0.1:16161
#   snmpsim    snmpsim responder     udp 127.0.0.1:16162, udp6 [::1]:16162
#   snmptrapd  net-snmp trap rcvr    udp 127.0.0.1:16164, udp6 [::1]:16164
# (udp 127.0.0.1:16163 / 16165 are left free for actsnmp agent / actsnmp trapd)
#   tools      idle container used by nsnmp.sh / pysnmp.sh (docker exec)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

services=("$@")
[ ${#services[@]} -eq 0 ] && services=(snmpd snmpsim snmptrapd tools)

if [ "$(image_hash)" != "$(src_hash)" ]; then
    log "image $IMAGE missing or stale -> building"
    "$INTEROP_DIR/build.sh"
fi
img_id="$(image_id)"

start() {  # name, command...
    local name="$1"; shift
    if container_running "$name" && [ "$(container_image_id "$name")" = "$img_id" ]; then
        log "$name already running"
        return 0
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    log "starting $name"
    docker run -d --name "$name" --network host --init \
        --label actsnmp.interop=1 \
        -e SNMPSIM_LOG_LEVEL="${SNMPSIM_LOG_LEVEL:-error}" \
        "$IMAGE" "$@" >/dev/null
}

# the tools container is always needed for the readiness checks
want_tools=1
for s in "${services[@]}"; do
    case "$s" in
        snmpd)     start "$C_SNMPD" run-snmpd ;;
        snmpsim)   start "$C_SNMPSIM" run-snmpsim ;;
        snmptrapd) start "$C_SNMPTRAPD" run-snmptrapd ;;
        tools)     ;;
        *) die "unknown service '$s' (snmpd|snmpsim|snmptrapd|tools)" ;;
    esac
done
[ $want_tools -eq 1 ] && start "$C_TOOLS" sleep infinity

wait_snmp() {  # name port
    local name="$1" port="$2" i
    for i in $(seq 1 60); do
        if docker exec "$C_TOOLS" snmpget -v2c -c public -r0 -t1 "127.0.0.1:$port" \
                .1.3.6.1.4.1.8072.9999.1.1.1.0 >/dev/null 2>&1; then
            log "$name ready on udp/127.0.0.1:$port"
            return 0
        fi
        container_running "$name" || { docker logs --tail 50 "$name" >&2 || true; die "$name exited"; }
        sleep 0.5
    done
    docker logs --tail 50 "$name" >&2 || true
    die "$name did not answer on udp/$port within 30s"
}

wait_trapd() {
    local i
    for i in $(seq 1 60); do
        # grep reads the whole log: "grep -q" would exit at the first match and docker logs would
        # get SIGPIPE, which pipefail turns into a failure once the log is large
        if docker logs "$C_SNMPTRAPD" 2>&1 | grep "NET-SNMP version" >/dev/null; then
            log "$C_SNMPTRAPD ready on udp/127.0.0.1:$SNMPTRAPD_PORT"
            return 0
        fi
        container_running "$C_SNMPTRAPD" || { docker logs --tail 50 "$C_SNMPTRAPD" >&2 || true; die "$C_SNMPTRAPD exited"; }
        sleep 0.5
    done
    die "$C_SNMPTRAPD did not start within 30s"
}

for s in "${services[@]}"; do
    case "$s" in
        snmpd)     wait_snmp "$C_SNMPD" "$SNMPD_PORT" ;;
        snmpsim)   wait_snmp "$C_SNMPSIM" "$SNMPSIM_PORT" ;;
        snmptrapd) wait_trapd ;;
    esac
done
log "lab is up"
