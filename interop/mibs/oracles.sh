#!/usr/bin/env bash
# Run the MIB oracles over the de-duplicated corpus (corpus/flat), resumably,
# in chunks: each chunk is one docker run holding the bench lock for at most
# MIBLAB_BUDGET seconds of new work (+ one per-module timeout).
#
#   interop/mibs/oracles.sh [ORACLE...]       default: pysmi-relaxed pysmi-strict pysmi-dialect netsnmp smilint
#   interop/mibs/oracles.sh --clean ORACLE    forget the results of ORACLE (rm -rf cache/ORACLE)
#   interop/mibs/oracles.sh --whole           whole-corpus net-snmp dumps (snmptranslate -m ALL -Tz/-Tp)
#   interop/mibs/oracles.sh --incremental [ORACLE...]
#                                             after a re-index: only modules whose corpus/flat copy is new or
#                                             changed, plus their importers (oracles/incremental.py; old
#                                             results are kept in cache/_prev/ for report.py)
#
# All named oracles share one chunk (they run one after the other inside the
# same docker run / lock hold), so a hold is at most BUDGET + TIMEOUT seconds.
# Env: MIBLAB_JOBS (default 28), MIBLAB_BUDGET (default 690 s), MIBLAB_TIMEOUT
# (per module, default 150 s), MIBLAB_MODULES (comma list: only these),
# MIBLAB_MODULES_FILE (file under cache/ with one module per line: only these),
# MIBLAB_STAGE=1 (run on the staged index of index.py --no-swap: corpus/flat.new,
# split.new and index.new are mounted at /corpus/flat, split, index; publish
# them afterwards with swap.py).
# Results: cache/<ORACLE>/status/<MODULE>.json (+ json/ or out/); summarize
# with report.py.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

JOBS="${MIBLAB_JOBS:-28}"
BUDGET="${MIBLAB_BUDGET:-690}"
TIMEOUT="${MIBLAB_TIMEOUT:-150}"
ALL_ORACLES=(pysmi-relaxed pysmi-strict pysmi-dialect netsnmp smilint)

[ -d "$CORPUS_DIR/flat" ] || die "no corpus: run fetch.sh first"
docker image inspect "$MIBS_IMAGE" >/dev/null 2>&1 || "$MIBS_DIR/build.sh"
mkdir -p "$CACHE_DIR"

# corpus mounts: the published index, or (MIBLAB_STAGE=1) the staged one
if [ "${MIBLAB_STAGE:-0}" = 1 ]; then
    for d in flat split index; do
        [ -d "$CORPUS_DIR/$d.new" ] || die "MIBLAB_STAGE=1 but no staged corpus/$d.new (index.py --no-swap)"
    done
    CORPUS_MOUNTS=(-v "$CORPUS_DIR/src:/corpus/src:ro" -v "$CORPUS_DIR/flat.new:/corpus/flat:ro"
                   -v "$CORPUS_DIR/split.new:/corpus/split:ro" -v "$CORPUS_DIR/index.new:/corpus/index:ro")
    INDEX_NEW="$CORPUS_DIR/index.new"
    INDEX_OLD="$CORPUS_DIR/index"
else
    CORPUS_MOUNTS=(-v "$CORPUS_DIR:/corpus:ro")
    INDEX_NEW="$CORPUS_DIR/index"
    INDEX_OLD="$CORPUS_DIR/index.prev"
fi
modules_file=""
if [ -n "${MIBLAB_MODULES_FILE:-}" ]; then
    case "$(realpath "$MIBLAB_MODULES_FILE")" in
        "$(realpath "$CACHE_DIR")"/*) modules_file="/cache/${MIBLAB_MODULES_FILE#"$CACHE_DIR"/}" ;;
        *) die "MIBLAB_MODULES_FILE must be under $CACHE_DIR" ;;
    esac
fi


if [ "${1:-}" = "--clean" ]; then
    [ -n "${2:-}" ] || die "--clean needs an oracle name"
    rm -rf "${CACHE_DIR:?}/$2"
    log "removed cache/$2"
    exit 0
fi

if [ "${1:-}" = "--whole" ]; then
    check_daytime
    mkdir -p "$CACHE_DIR/netsnmp-all"
    log "snmptranslate -m ALL -Tz/-Tp over corpus/flat"
    locked docker run --rm --user "$(id -u):$(id -g)" -v "$MIBS_DIR:/lab:ro" "${CORPUS_MOUNTS[@]}" \
        -v "$CACHE_DIR:/cache" -e HOME=/tmp "$MIBS_IMAGE" bash -c '
            gcc -O2 -o /tmp/mibwalk /lab/docker/mibwalk.c $(net-snmp-config --libs)
            cd /cache/netsnmp-all
            timeout 270 snmptranslate -M /corpus/flat -m ALL -Tz > Tz.txt 2> Tz.err || echo "rc $?" >> Tz.err
            timeout 270 snmptranslate -M /corpus/flat -m ALL -Tp > Tp.txt 2> Tp.err || echo "rc $?" >> Tp.err
            timeout 270 /tmp/mibwalk -M /corpus/flat ALL > all.jsonl 2> all.err || echo "rc $?" >> all.err
            wc -l Tz.txt Tp.txt all.jsonl Tz.err'
    exit 0
fi

if [ "${1:-}" = "--incremental" ]; then
    shift
    if [ -f "$CACHE_DIR/_incremental.txt" ] && [ "$CACHE_DIR/_incremental.txt" -nt "$INDEX_NEW/modules.tsv" ]; then
        log "--incremental: resuming with cache/_incremental.txt ($(wc -l < "$CACHE_DIR/_incremental.txt") modules)"
    else
        [ -f "$INDEX_OLD/modules.tsv" ] || die "--incremental: no previous index $INDEX_OLD"
        python3 "$MIBS_DIR/oracles/incremental.py" "$INDEX_OLD/modules.tsv" "$INDEX_NEW/modules.tsv" "$CACHE_DIR"
    fi
    modules_file=/cache/_incremental.txt
fi

oracles=("$@")
[ ${#oracles[@]} -gt 0 ] || oracles=("${ALL_ORACLES[@]}")
chunk=0
while :; do
    check_daytime
    chunk=$((chunk + 1))
    log "${oracles[*]}: chunk $chunk (jobs $JOBS, budget $BUDGET s)"
    set +e
    locked docker run --rm --user "$(id -u):$(id -g)" \
        -v "$MIBS_DIR:/lab:ro" "${CORPUS_MOUNTS[@]}" -v "$CACHE_DIR:/cache" \
        -e HOME=/tmp -e SNMP_PERSISTENT_DIR=/tmp/snmp-persist \
        "$MIBS_IMAGE" python3 /lab/oracles/run.py "${oracles[@]}" --jobs "$JOBS" --budget "$BUDGET" \
        --timeout "$TIMEOUT" ${MIBLAB_MODULES:+--modules "$MIBLAB_MODULES"} \
        ${modules_file:+--modules-file "$modules_file"}
    rc=$?
    set -e
    [ $rc = 3 ] && continue
    [ $rc = 0 ] || die "run.py failed (rc $rc)"
    break
done
log "done: ${oracles[*]}"
