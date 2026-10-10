# shellcheck shell=bash
# Common settings for the MIB corpus + oracle lab (sourced, not executed).

MIBS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS_DIR="${MIBLAB_CORPUS:-$MIBS_DIR/corpus}"
CACHE_DIR="${MIBLAB_CACHE:-$MIBS_DIR/cache}"
MIBS_IMAGE="${MIBLAB_IMAGE:-actsnmp-mibs:1}"
# The interop lab image; source of the IETF/IANA MIB set (snmp-mibs-downloader).
INTEROP_IMAGE="${ACTSNMP_INTEROP_IMAGE:-actsnmp-interop:1}"

# CPU-heavy steps run under a shared lock so that they do not skew benchmark
# runs on a shared machine. Default: ~/gcperf/lock100/bench.lock if it exists.
# MIBLAB_LOCK=none disables locking; MIBLAB_LOCK=/path/file uses another lock.
MIBLAB_LOCK="${MIBLAB_LOCK:-$HOME/gcperf/lock100/bench.lock}"

log() { echo "[mibs] $*" >&2; }
die() { echo "[mibs] ERROR: $*" >&2; exit 1; }

# locked CMD...: run one CPU-heavy command while holding the lock (one hold
# per command; callers keep every hold well below 15 minutes).
locked() {
    if [ "$MIBLAB_LOCK" != "none" ] && [ -e "$MIBLAB_LOCK" ]; then
        flock -w 3600 "$MIBLAB_LOCK" "$@"
    else
        "$@"
    fi
}

# Refuse heavy work at night (22:00-07:00 local time) unless MIBLAB_NIGHT=1.
check_daytime() {
    local h
    h=$((10#$(date +%H)))
    if [ "${MIBLAB_NIGHT:-0}" != "1" ] && { [ "$h" -ge 22 ] || [ "$h" -lt 7 ]; }; then
        die "it is $(date +%H:%M): heavy runs are not allowed between 22:00 and 07:00 (MIBLAB_NIGHT=1 overrides)"
    fi
}
