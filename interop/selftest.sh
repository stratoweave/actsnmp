#!/usr/bin/env bash
# Verify the interop lab end-to-end (see tools/selftest.py for the checks).
#
#   interop/selftest.sh            # full run (~2-3 min), report on stdout
#   interop/selftest.sh --quick    # skip slow GETNEXT walks / pysnmp v3 matrix
#   interop/selftest.sh --record   # also regenerate interop/expected/*
#
# Agents are (re)started fresh first, because the checks rely on the initial
# dataset values and on engineBoots starting at 1.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

quick=() ; rec=0
for a in "$@"; do
    case "$a" in
        --quick) quick=(--quick) ;;
        --record) rec=1 ;;
        *) die "unknown argument $a" ;;
    esac
done

"$INTEROP_DIR/down.sh"
"$INTEROP_DIR/up.sh"

extra=()
mount=()
if [ $rec -eq 1 ]; then
    # everything selftest.py records (expected/notify/matrix*.txt belong to notifycheck.sh)
    rm -rf "$INTEROP_DIR/expected/canon" "$INTEROP_DIR/expected/netsnmp" \
        "$INTEROP_DIR/expected/pathological-netsnmp.txt" "$INTEROP_DIR/expected/v3-matrix.md"
    mkdir -p "$INTEROP_DIR/expected"
    mount=(-v "$INTEROP_DIR/expected:/out")
    extra=(--record /out)
fi

rc=0
docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp \
    "${mount[@]}" "$IMAGE" \
    python3 /opt/actsnmp/tools/selftest.py "${quick[@]}" "${extra[@]}" || rc=$?

# notifications sent by selftest.py (fixed uptimes) must show up in the
# snmptrapd log exactly as expected/notify/selftest-snmptrapd.txt
sleep 1
traplog="$(docker logs "$C_SNMPTRAPD" 2>&1)"
canon="$(NSNMP_STDIN=1 "$INTEROP_DIR/nsnmp.sh" snmptrapd2canon <<<"$traplog")" || {
    echo "snmptrapd log conversion (tools/snmptrapd2canon.py): **FAIL**"; rc=1; }
if [ $rec -eq 1 ]; then
    mkdir -p "$INTEROP_DIR/expected/notify"
    printf '%s\n' "$canon" > "$INTEROP_DIR/expected/notify/selftest-snmptrapd.txt"
    grep -E "^TRAP" <<<"$traplog" | sed -E 's/\[127\.0\.0\.1\]:[0-9]+->/[127.0.0.1]:<port>->/' \
        > "$INTEROP_DIR/expected/snmptrapd-log.txt" || true
fi
nexp="$(grep -c '^NOTIFICATION ' "$INTEROP_DIR/expected/notify/selftest-snmptrapd.txt" || true)"
if diff -u "$INTEROP_DIR/expected/notify/selftest-snmptrapd.txt" <(printf '%s\n' "$canon"); then
    echo "snmptrapd received the $nexp selftest notifications (canonical log == expected/notify/selftest-snmptrapd.txt): PASS"
else
    echo "snmptrapd log (canonical) differs from expected/notify/selftest-snmptrapd.txt: **FAIL**"; rc=1
fi
exit $rc
