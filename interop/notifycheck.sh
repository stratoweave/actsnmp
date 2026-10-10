#!/usr/bin/env bash
# Notification interop, receiving side: send a fixed matrix of traps and
# informs with both net-snmp (snmptrap/snmpinform) and pysnmp (pysnmp_notify.py)
# to a receiver, normally "actsnmp trapd --canon" on udp 127.0.0.1:16165, and
# compare what the receiver printed with the expected canonical blocks.
#
#   interop/notifycheck.sh [--receiver HOST:PORT] [--quick|--all-users] [--log FILE] [--wait SEC]
#                          [--senders netsnmp,pysnmp]
#   interop/notifycheck.sh --selftest [--quick|--all-users]
#                                                  # validate the sending side + the expected
#                                                  # file against net-snmp snmptrapd (stand-in
#                                                  # receiver on 16165 in the tools container)
#   interop/notifycheck.sh --no-send --log FILE    # only compare an existing receiver log
#
# Every run (re)writes the expected receiver output, in send order, to
#   interop/expected/notify/matrix.txt        full matrix (86 notifications)
#   interop/expected/notify/matrix-quick.txt  --quick subset (22 notifications)
#   interop/expected/notify/matrix-all.txt    --all-users: v3 for all 43 net-snmp users (198)
# (with --senders other than both, the expected subset goes to a temp file).
#
# --log FILE   the receiver's --canon output; after sending, waits (max --wait SEC,
#              default 10) until FILE holds as many NOTIFICATION blocks as expected,
#              then compares the NOTIFICATION..END blocks of FILE (other lines are
#              ignored) with the expected file: unified diff + PASS/FAIL.
# The receiver must accept community "public" and the users of config/users.tsv
# (v3 TRAPs from the sender engine IDs 0x8000000001020304 = net-snmp and
# 0x8000000001020305 = pysnmp, v3 INFORMs to its own engine ID), incl. the
# noAuthNoPriv user u_noauth.  Informs are sent with -r 0 -t 5 (no retransmission).
#
# Exit status 0 when every notification was sent / acknowledged and (with --log
# or --selftest) the receiver output equals the expected file.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

receiver="127.0.0.1:$ACTSNMP_TRAPD_PORT"
quick=()
logfile=""
selftest=0
send=1
wait_s=10
senders="netsnmp,pysnmp"
while [ $# -gt 0 ]; do
    case "$1" in
        --receiver) receiver="$2"; shift ;;
        --quick|--all-users) quick=("$1") ;;
        --log) logfile="$2"; shift ;;
        --wait) wait_s="$2"; shift ;;
        --senders) senders="$2"; shift ;;
        --selftest) selftest=1 ;;
        --no-send) send=0 ;;
        -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
        *) die "unknown argument $1 (see --help)" ;;
    esac
    shift
done
if [ $send -eq 0 ] && [ -z "$logfile" ]; then die "--no-send needs --log FILE"; fi

"$INTEROP_DIR/up.sh" tools
NC=("$INTEROP_DIR/nsnmp.sh" python3 /opt/actsnmp/tools/notifycheck.py)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# expected receiver output
mkdir -p "$INTEROP_DIR/expected/notify"
"${NC[@]}" --expected > "$tmp/matrix.txt"
"${NC[@]}" --expected --quick > "$tmp/matrix-quick.txt"
"${NC[@]}" --expected --all-users > "$tmp/matrix-all.txt"
cp "$tmp/matrix.txt" "$tmp/matrix-quick.txt" "$tmp/matrix-all.txt" "$INTEROP_DIR/expected/notify/"
suffix=""
case "${quick[0]:-}" in --quick) suffix=-quick ;; --all-users) suffix=-all ;; esac
if [ "$senders" = "netsnmp,pysnmp" ]; then
    expected="$INTEROP_DIR/expected/notify/matrix$suffix.txt"
else
    expected="$tmp/expected-$senders.txt"
    "${NC[@]}" --expected "${quick[@]}" --senders "$senders" > "$expected"
fi
nexp="$(grep -c '^NOTIFICATION ' "$expected" || true)"
log "expected receiver output: $expected ($nexp notifications)"

blocks() {  # only the NOTIFICATION ... END blocks of a receiver log
    awk '/^NOTIFICATION /{inb=1} inb{print} /^END$/{inb=0}' "$1"
}

compare() {  # name got-file
    if diff -u --label "$expected" --label "$1" "$expected" "$2" > "$tmp/diff"; then
        echo "$1 == $(basename "$expected") ($nexp notifications): PASS"
        return 0
    fi
    echo "$1 differs from $expected: **FAIL**"
    head -100 "$tmp/diff"
    return 1
}

rc=0
if [ $selftest -eq 1 ]; then
    log "selftest: net-snmp snmptrapd as stand-in receiver on $receiver (inside $C_TOOLS)"
    "${NC[@]}" --selftest "${quick[@]}" --receiver "$receiver" --senders "$senders" \
        > "$tmp/standin.txt" || rc=1
    compare "converted stand-in snmptrapd log" "$tmp/standin.txt" || rc=1
    exit $rc
fi

if [ $send -eq 1 ]; then
    log "sending to $receiver ($senders)"
    "${NC[@]}" --send "${quick[@]}" --receiver "$receiver" --senders "$senders" || rc=1
    [ $rc -eq 0 ] && echo "all $nexp notifications sent / acknowledged: PASS" \
        || echo "some notifications could not be sent / were not acknowledged: **FAIL**"
fi

if [ -n "$logfile" ]; then
    for _ in $(seq 1 $((wait_s * 4))); do
        [ -f "$logfile" ] && [ "$(blocks "$logfile" | grep -c '^NOTIFICATION ' || true)" -ge "$nexp" ] && break
        sleep 0.25
    done
    sleep 0.5   # late duplicates would show up now
    [ -f "$logfile" ] || die "receiver log $logfile does not exist"
    blocks "$logfile" > "$tmp/got.txt"
    compare "receiver log $logfile" "$tmp/got.txt" || rc=1
fi
exit $rc
