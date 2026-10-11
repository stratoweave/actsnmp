#!/usr/bin/env bash
# All interop checks of actsnmp in one run: build, start the lab, run every check, write a summary,
# stop the lab. Exit status 0 only when every mandatory check passed.
#
#   interop/run-interop.sh [--quick] [--phases LIST] [--keep-lab] [--no-lock] [--results DIR]
#
# Phases (each its own hold of the bench lock, each well under 15 minutes):
#   build     acton build src/actsnmp.act (copied to RESULTS/bin/actsnmp for the other phases),
#             interop/up.sh (rebuilds the image when the lab sources changed)
#   library   acton test --tag interop --module test_interop: the library against snmpd, snmpsim
#             and snmptrapd (~5 min)
#   cli       interop/clicheck.sh: the CLI side by side with net-snmp's tools (~3 min)
#   agent     interop/agentcheck.sh (full, all users, IPv4 and IPv6): net-snmp and pysnmp against
#             our agent (actsnmp agent on 127.0.0.1:16163 and [::1]:16163)
#   notify    interop/notifycheck.sh --all-users: net-snmp and pysnmp senders to our receiver
#             (actsnmp trapd --canon on 127.0.0.1:16165)
#   trapd     interop/trapdcheck.sh cli --all-users: our CLI as the sender, the lab's snmptrapd as
#             the receiver
# Default: all phases in this order. --phases takes a comma separated subset (build is needed once
# for a fresh binary; without it the existing out/bin/actsnmp is used).
#
#   --quick       smaller variants: clicheck --quick, agentcheck --quick, the full instead of the
#                 all-users notification matrices; the library tests are the same
#   --keep-lab    leave the lab running at the end (default: interop/down.sh)
#   --no-lock     do not take the bench lock (the caller holds it, or there is none)
#   --results DIR where the logs and the summary go (default: interop/results)
#
# The compiler is acton from PATH.
#
# Environment: INTEROP_LOCK (default ~/gcperf/lock100/bench.lock when it exists, else no lock),
# CLI_FLAGS (extra flags of the CLI build, e.g. --fast), PHASE_TIMEOUT (seconds per phase, 840).
#
# Output: RESULTS/LATEST.md (the summary: per phase PASS/FAIL, run time in the lock, lock wait and key
# numbers), RESULTS/<phase>.log (the whole output of each phase), the reports RESULTS/clicheck.md and
# RESULTS/agentcheck.md, and what our servers printed (agent4.err, agent6.err, receiver.out/.err).
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
REPO="$(cd "$INTEROP_DIR/.." && pwd)"

LOCK="${INTEROP_LOCK-}"
if [ -z "${INTEROP_LOCK+x}" ] && [ -e "$HOME/gcperf/lock100/bench.lock" ]; then
    LOCK="$HOME/gcperf/lock100/bench.lock"
fi
PHASE_TIMEOUT="${PHASE_TIMEOUT:-840}"
ALL_PHASES="build,library,cli,agent,notify,trapd"
phases="$ALL_PHASES"
quick=0
keep_lab=0
results="$INTEROP_DIR/results"
in_phase=""
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) quick=1 ;;
        --phases) phases="$2"; shift ;;
        --keep-lab) keep_lab=1 ;;
        --no-lock) LOCK="" ;;
        --results) results="$2"; shift ;;
        --in-phase) in_phase="$2"; shift ;;     # internal: run one phase (under the caller's lock)
        -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
        *) die "unknown argument $1 (see --help)" ;;
    esac
    shift
done
mkdir -p "$results/bin"
results="$(cd "$results" && pwd)"
SUMMARY="$results/LATEST.md"
CLI="$results/bin/actsnmp"
cd "$REPO"

declare -a ROWS=()
failed=0
started=$(date +%s)

locked() {  # CMD... under the bench lock (one hold), with the phase timeout
    if [ -n "$LOCK" ]; then
        flock -w 3600 "$LOCK" timeout -k 10 "$PHASE_TIMEOUT" "$@"
    else
        timeout -k 10 "$PHASE_TIMEOUT" "$@"
    fi
}

record() {  # phase status detail
    ROWS+=("| $1 | $2 | $3 |")
    [ "$2" = "PASS" ] || failed=1
    log "phase $1: $2 ($3)"
}

want() { [[ ",$phases," == *",$1,"* ]]; }

# The actsnmp servers (agent, trapd) run in the background; each phase waits for the readiness line
# ("serving" / "listening") and stops them at its end.
SERVER_PIDS=()
start_server() {  # ready-word stderr-file stdout-file CMD...
    local word="$1" err="$2" out="$3" i
    shift 3
    "$@" >"$out" 2>"$err" &
    SERVER_PIDS+=($!)
    for i in $(seq 1 150); do
        grep -q "$word" "$err" 2>/dev/null && return 0
        kill -0 "${SERVER_PIDS[-1]}" 2>/dev/null || break
        sleep 0.2
    done
    cat "$err" >&2
    return 1
}
stop_servers() {
    local p
    for p in "${SERVER_PIDS[@]}"; do
        kill "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
    done
    SERVER_PIDS=()
}
cleanup() {
    stop_servers
    if [ -z "$in_phase" ] && [ $keep_lab -eq 0 ]; then
        "$INTEROP_DIR/down.sh" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 143' TERM INT       # so that the EXIT trap stops our servers when a phase times out

# ---------------------------------------------------------------- phases ---

phase_build() {
    acton build src/actsnmp.act ${CLI_FLAGS:-} || return 1
    cp out/bin/actsnmp "$CLI.new" && mv "$CLI.new" "$CLI" || return 1
    "$INTEROP_DIR/up.sh"
}

phase_library() {
    acton test --tag interop --no-cache --min-iter 1 --max-iter 1 --max-time 120000 --jobs 1 \
        --module test_interop
}

phase_cli() {
    local q=()
    [ $quick -eq 1 ] && q=(--quick)
    "$INTEROP_DIR/clicheck.sh" --cli "$CLI" "${q[@]}" --report "$results/clicheck.md" >/dev/null
}

phase_agent() {
    local q=() rc=0
    [ $quick -eq 1 ] && q=(--quick)
    start_server serving "$results/agent4.err" /dev/null "$CLI" agent || return 1
    start_server serving "$results/agent6.err" /dev/null "$CLI" agent --bind ::1 || return 1
    "$INTEROP_DIR/agentcheck.sh" "${q[@]}" 'acton=127.0.0.1:16163,udp6:[::1]:16163' >"$results/agentcheck.md" \
        || rc=1
    stop_servers
    return $rc
}

phase_notify() {
    local m=(--all-users) rc=0
    [ $quick -eq 1 ] && m=()
    start_server listening "$results/receiver.err" "$results/receiver.out" "$CLI" trapd --canon || return 1
    "$INTEROP_DIR/notifycheck.sh" "${m[@]}" --log "$results/receiver.out" --wait 30 || rc=1
    stop_servers
    return $rc
}

phase_trapd() {
    local m=(--all-users)
    [ $quick -eq 1 ] && m=()
    "$INTEROP_DIR/trapdcheck.sh" cli "${m[@]}" "$CLI"
}

# The key numbers of a phase, from its log and reports
detail_build() { grep -q "lab is up" "$1" && echo "out/bin/actsnmp built and copied, lab up"; }
detail_library() {
    local ok bad
    ok=$(grep -cE "^ +[a-z0-9_]+: +OK " "$1")
    bad=$(grep -cE "^ +[a-z0-9_]+: +(FAIL|ERR)" "$1")
    echo "test_interop: $ok OK, $bad failed;" "$(grep -E "tests? (passed|failed)" "$1" | tail -1 | xargs)"
}
detail_cli() { tail -1 "$results/clicheck.md" 2>/dev/null; }
detail_agent() { grep -E "^[0-9]+ passed, " "$results/agentcheck.md" 2>/dev/null | tail -1; }
detail_notify() {
    echo "$(grep -E '^sent [0-9]+ notifications' "$1" | tail -1);" \
        "receiver output $(grep -E '^receiver log ' "$1" | sed 's/^receiver log [^ ]* //' | tail -1)"
}
detail_trapd() {
    echo "$(grep -c '^\[PASS\]' "$1") sent, $(grep -c '^\[FAIL\]' "$1") failed;" \
        "$(grep -E 'snmptrapd (received|log)' "$1" | tail -1)"
}

run_phase() {  # name: this script again with --in-phase NAME, in one hold of the lock
    local name="$1" logf="$results/$1.log" t0 rc detail q=()
    t0=$(date +%s)
    [ $quick -eq 1 ] && q=(--quick)
    log "phase $name (log: $logf)"
    rm -f "$results/$name.ran"
    locked "$0" --in-phase "$name" --results "$results" "${q[@]}" >"$logf" 2>&1
    rc=$?
    detail="$(detail_$name "$logf" 2>/dev/null | head -1)"
    [ $rc -eq 124 ] && detail="timed out after ${PHASE_TIMEOUT}s; $detail"
    # the run time inside the lock, and the time spent waiting for it
    local ran total
    total=$(( $(date +%s) - t0 ))
    ran=$(cat "$results/$name.ran" 2>/dev/null || echo "$total")
    rm -f "$results/$name.ran"
    if [ $rc -eq 0 ]; then
        record "$name" PASS "$ran s (lock wait $(( total - ran )) s); $detail"
    else
        record "$name" "**FAIL** (exit $rc)" "$ran s (lock wait $(( total - ran )) s); $detail; see $name.log"
    fi
}

if [ -n "$in_phase" ]; then
    t_in=$(date +%s)
    "phase_$in_phase"
    rc=$?
    echo $(( $(date +%s) - t_in )) >"$results/$in_phase.ran"
    exit $rc
fi
if ! want build; then
    [ -x out/bin/actsnmp ] || die "out/bin/actsnmp missing: run the build phase"
    cp out/bin/actsnmp "$CLI"
fi
for p in ${phases//,/ }; do
    case ",$ALL_PHASES," in *",$p,"*) ;; *) die "unknown phase $p ($ALL_PHASES)" ;; esac
done
for p in ${ALL_PHASES//,/ }; do
    want "$p" || continue
    run_phase "$p"
    if [ "$p" = build ] && [ $failed -ne 0 ]; then
        log "build failed: the other phases are skipped"
        break
    fi
done

{
    echo "# actsnmp interop run ($(date '+%Y-%m-%d %H:%M'), $(( $(date +%s) - started )) s)"
    echo
    echo "Phases: $phases$([ $quick -eq 1 ] && echo ' (--quick)'); CLI: \`$CLI\`;" \
        "image: $IMAGE ($(image_hash)); host: $(hostname)."
    echo
    echo "| phase | result | details |"
    echo "|---|---|---|"
    printf '%s\n' "${ROWS[@]}"
    echo
    if [ $failed -eq 0 ]; then
        echo "All mandatory checks passed."
    else
        echo "**Some mandatory checks failed**: see the phase logs next to this file."
    fi
    if [ -f "$results/clicheck.md" ] && want cli; then
        echo
        echo "## CLI vs net-snmp (clicheck)"
        echo
        sed -n '/^| section/,/^| \*\*total/p' "$results/clicheck.md"
    fi
} >"$SUMMARY"
log "summary: $SUMMARY"
cat "$SUMMARY"
exit $failed
