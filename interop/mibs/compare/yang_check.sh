#!/bin/sh
# Check the RFC 6643 YANG output of src/mib/yang.act.
#
#   yang_check.sh [OUTDIR]                          reference MIBs + golden set (the gate)
#   yang_check.sh golden-all [OUTDIR]               whole golden set incl. IEEE/vendor modules
#   yang_check.sh sample [OUTDIR] [PARTS]           >= 1000 corpus modules (report)
#   yang_check.sh corpus [OUTDIR] [CHUNKS] [PARTS]  the whole corpus (report)
#
# ACTYANG_DIR must point to an acton-yang checkout; Build.act of yangcheck/ is
# generated from Build.act.in with that path. ACTONYANG=0 skips the acton-yang
# step in the report modes and then needs no checkout.
#
# The gate (OUTDIR defaults to ${TMPDIR:-/tmp}/actsnmp-yang-check):
#   1. emit:   mib.test_yang yang_golden writes OUTDIR/ref/ (the 9 MIBs of
#              interop/mibs/yang-examples/mibs) and OUTDIR/golden/ (the 43 modules of
#              interop/mibs/golden/mibs), each as <MOD>.yang, .diags and .mibmeta.json;
#   2. libsmi: yang_vs_libsmi.py, OUTDIR/ref against yang-examples/yang-libsmi-0.5.0;
#              every difference must be a documented deviation;
#   3. pyang:  pyang --strict over each set (image actsnmp-pyang:1, built from
#              pyang.Dockerfile when missing); warnings are listed, errors fail.
#              "imported module ietf-yang-smiv2 not used" is expected (RFC 6643
#              section 3 always imports it);
#   4. acton-yang: yangcheck/ compiles each set as one closure with yang-ietf/ and
#              checks it against the mibmeta JSON (smiv2:oid against the NodeMeta
#              YANG paths, list keys against IndexPart.key);
#   5. conv:   yang_conv_check.py: every leaf's YANG type fits the value conversion
#              mibmeta gives its object.
# Exits 1 when a step fails. If OUTDIR/libsmi-golden exists (libsmi_golden.sh),
# the libsmi diff of the golden set is printed for information.
#
# The report modes need interop/mibs/corpus and write to interop/mibs/cache/yang/
# by default. They emit YANG plus mibmeta with a mibcorpus test of mib.test_yang,
# split the targets into PARTS closures (yang_closure.py), run pyang and
# acton-yang per part (each bounded to 14 minutes, several per bench-lock hold
# while the hold is younger than EMIT_BUDGET/PYANG_BUDGET/ACTONYANG_BUDGET
# seconds, default 420/480/300), and write OUTDIR/check/report.md with
# yang_report.py:
#   golden-all: the golden set plus the IEEE/vendor golden modules staged from the
#              corpus (meta_vs_oracles.py --stage-vendor), as one part;
#   sample:    the deterministic, vendor-stratified pick of yang_sample.py (PARTS 3);
#   corpus:    every module of corpus/flat in CHUNKS emit runs (default 8) and
#              PARTS check parts (default 16).
# PYANG=0, ACTONYANG=0 and CONV=0 skip a step, META=0 skips mibmeta in corpus
# mode, LIBSMI=1 adds a libsmi 0.5.0 comparison (information) in golden-all and
# sample mode. An existing OUTDIR is reused; old files are overwritten, not
# removed.
# Expected pyang errors: BAD_STATUS_REFERENCE where a current definition refers
# to a deprecated or obsolete key column, INDEX object or TC of its own module
# (the emitter keeps MIB statuses and warns with yang.status-reference).
#
# Heavy steps run under the bench lock (~/gcperf/lock100/bench.lock, if it
# exists); LOCK= disables it.
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"
if [ -z "${LOCK+x}" ]; then
    if [ -e "$HOME/gcperf/lock100/bench.lock" ]; then
        LOCK="flock -w 3600 $HOME/gcperf/lock100/bench.lock"
    else
        LOCK=""
    fi
fi
EXAMPLES="$ROOT/interop/mibs/yang-examples"
IETF="$EXAMPLES/yang-ietf"
CMP="$ROOT/interop/mibs/compare"
CACHE="$ROOT/interop/mibs/cache/yang"
PYANG_IMAGE=actsnmp-pyang:1
YC="$CMP/yangcheck/out/bin/yangcheck"

pyang_image() {
    docker image inspect "$PYANG_IMAGE" >/dev/null 2>&1 ||
        $LOCK docker build -q -t "$PYANG_IMAGE" -f "$CMP/pyang.Dockerfile" "$CMP" >/dev/null
}

# need_actyang [HINT]: exit unless ACTYANG_DIR names a directory
need_actyang() {
    if [ -z "${ACTYANG_DIR:-}" ] || [ ! -d "${ACTYANG_DIR:-}" ]; then
        echo "yang_check.sh: ACTYANG_DIR must point to an acton-yang checkout${1:+ ($1)}" >&2
        exit 2
    fi
}

# yangcheck_build LOGFILE: write yangcheck/Build.act for ACTYANG_DIR (only when it
# changed, so an up-to-date build is kept) and build yangcheck
yangcheck_build() {
    dir=$(cd "$ACTYANG_DIR" && pwd)
    sed "s|@ACTYANG_DIR@|$dir|" "$CMP/yangcheck/Build.act.in" >"$CMP/yangcheck/Build.act.tmp"
    if cmp -s "$CMP/yangcheck/Build.act.tmp" "$CMP/yangcheck/Build.act"; then
        rm -f "$CMP/yangcheck/Build.act.tmp"
    else
        mv "$CMP/yangcheck/Build.act.tmp" "$CMP/yangcheck/Build.act"
    fi
    (cd "$CMP/yangcheck" && $LOCK acton build --fast >"$1" 2>&1)
}

# run_pyang DIR OUTFILE: pyang --strict over DIR/*.yang; prints the error count
run_pyang() {
    $LOCK docker run --rm -v "$1":/y:ro -v "$IETF":/ietf:ro "$PYANG_IMAGE" \
        sh -c 'cd /y && pyang --strict --no-path-recurse -p /ietf -p /y *.yang' >"$2" 2>&1
    grep -c ': error:' "$2"
}

# batch DIR BUDGET FILE: run the commands of FILE (lines "<name> <command>") under the lock,
# several per hold: a command is only started while the hold is younger than BUDGET seconds
# (each command bounds itself), and DIR/<name>.done records that it ran. Holds are taken until
# every command has run, so a hold stays below about BUDGET plus one command.
batch() {
    while :; do
        left=0
        while read -r name cmd; do
            [ -e "$1/$name.done" ] || left=1
        done <"$3"
        [ "$left" -eq 0 ] && break
        $LOCK sh -c '
            start=$(date +%s)
            while read -r name cmd; do
                [ -e "$1/$name.done" ] && continue
                [ $(( $(date +%s) - start )) -ge "$2" ] && break
                sh -c "$cmd" </dev/null
                touch "$1/$name.done"
            done <"$3"' batch "$1" "$2" "$3"
    done
}

# check_parts OUT NAMES PARTS TITLE: split NAMES (the targets) into PARTS closures under
# OUT/check, run pyang and acton-yang (+ mibmeta) per part, write OUT/check/report.md
check_parts() {
    out=$1
    names=$2
    parts=$3
    title=$4
    chk="$out/check"
    mkdir -p "$chk"
    python3 "$CMP/yang_closure.py" --dir "$out" --names "$names" --parts "$parts" --weights --out-dir "$chk"
    # reset only the steps that run now (PYANG=0 or ACTONYANG=0 keeps that step's earlier
    # results for the report)
    for p in $(cat "$chk/parts.txt"); do
        if [ "${PYANG:-1}" = "1" ]; then
            printf '' >"$chk/$p.pyang.txt"
            [ -e "$chk/$p.pyang.done" ] && mv "$chk/$p.pyang.done" "$chk/$p.pyang.old"
        fi
        if [ "${ACTONYANG:-1}" = "1" ]; then
            printf '' >"$chk/$p.actonyang.txt"
            [ -e "$chk/$p.acton.done" ] && mv "$chk/$p.acton.done" "$chk/$p.acton.old"
        fi
    done
    if [ "${PYANG:-1}" = "1" ]; then
        pyang_image
        printf '' >"$chk/pyang.cmds"
        for p in $(cat "$chk/parts.txt"); do
            sed 's|.*/||' "$chk/$p.files" >"$chk/$p.names"
            echo "$p.pyang timeout 840 docker run --rm -v $out:/y:ro -v $IETF:/ietf:ro -v $chk:/c:ro $PYANG_IMAGE sh -c 'cd /y && pyang --strict --no-path-recurse -p /ietf -p /y \$(cat /c/$p.names)' >$chk/$p.pyang.txt 2>&1" >>"$chk/pyang.cmds"
        done
        batch "$chk" "${PYANG_BUDGET:-480}" "$chk/pyang.cmds"
        for p in $(cat "$chk/parts.txt"); do
            echo "$p pyang: $(grep -c ': error:' "$chk/$p.pyang.txt") errors, $(grep -c ': warning:' "$chk/$p.pyang.txt") warnings"
        done
    fi
    if [ "${ACTONYANG:-1}" = "1" ]; then
        if ! yangcheck_build "$chk/yangcheck-build.txt"; then
            echo "FAILED to build yangcheck, see $chk/yangcheck-build.txt"
            return 1
        fi
        printf '' >"$chk/acton.cmds"
        for p in $(cat "$chk/parts.txt"); do
            { ls "$IETF"/*.yang; cat "$chk/$p.files"; } >"$chk/$p.yclist"
            sed -n 's|\.yang$|.mibmeta.json|p' "$chk/$p.files" | while read -r j; do [ -e "$j" ] && echo "$j"; done >"$chk/$p.metalist"
            meta=""
            [ -s "$chk/$p.metalist" ] && meta="--meta @$chk/$p.metalist"
            echo "$p.acton timeout 840 $YC --keep-going @$chk/$p.yclist $meta >$chk/$p.actonyang.txt 2>&1; [ \$? -eq 124 ] && echo 'COMPILE ERROR: timeout after 840 s' >>$chk/$p.actonyang.txt" >>"$chk/acton.cmds"
        done
        batch "$chk" "${ACTONYANG_BUDGET:-300}" "$chk/acton.cmds"
        for p in $(cat "$chk/parts.txt"); do
            echo "$p acton-yang: $(head -1 "$chk/$p.actonyang.txt" | cut -c1-110); $(grep -c '^PROBLEM' "$chk/$p.actonyang.txt") mibmeta problems"
        done
    fi
    if [ "${CONV:-1}" = "1" ]; then
        $LOCK timeout 840 python3 "$CMP/yang_conv_check.py" "$out" --show 200 >"$chk/conv.txt" 2>&1
        echo "conv (mibmeta vs YANG type): $(head -1 "$chk/conv.txt") ($chk/conv.txt)"
    fi
    python3 "$CMP/yang_report.py" --out "$out" --check "$chk" --title "$title" --md "$chk/report.md" >/dev/null
    echo "report: $chk/report.md"
}

# libsmi_diff OUT NAMES SET: libsmi YANG of NAMES (resumable) and yang_vs_libsmi.py (information)
libsmi_diff() {
    out=$1
    names=$2
    set=$3
    lo="$out/check/libsmi"
    mkdir -p "$lo"
    sh "$CMP/libsmi_yang.sh" "$lo" "$names" "$set"
    mods=$(cut -f1 "$names" | grep -v '^#' | while read -r m; do [ -e "$out/$m.yang" ] && [ -s "$lo/$m.yang" ] && echo "$m"; done | paste -sd, -)
    python3 "$CMP/yang_vs_libsmi.py" --ours "$out" --libsmi "$lo" --modules "$mods" --out "$out/check/libsmi.md" >/dev/null
    echo "libsmi (information): $(tail -1 "$out/check/libsmi.md" 2>/dev/null) ($out/check/libsmi.md)"
}

case "${1:-}" in
golden-all | sample | corpus) [ "${ACTONYANG:-1}" = "1" ] && need_actyang "ACTONYANG=0 skips the acton-yang step" ;;
*) need_actyang ;;
esac

case "${1:-}" in
golden-all)
    OUT=$(mkdir -p "${2:-$CACHE/golden-all}" && cd "${2:-$CACHE/golden-all}" && pwd)
    [ -d "$ROOT/interop/mibs/cache/golden-vendor" ] ||
        python3 "$CMP/meta_vs_oracles.py" --stage-vendor "$ROOT/interop/mibs/cache/golden-vendor" --mibs-dir "$ROOT/interop/mibs"
    if ! MIBYANG_OUT="$OUT" $LOCK acton test --tag mibcorpus --no-cache --module mib.test_yang --name yang_golden_vendor >"$OUT/emit.txt" 2>&1; then
        echo "FAILED, see $OUT/emit.txt"
        exit 1
    fi
    ls "$OUT" | sed -n 's|\.yang$||p' >"$OUT/targets.txt"
    echo "emitted $(wc -l <"$OUT/targets.txt") modules -> $OUT"
    check_parts "$OUT" "$OUT/targets.txt" 1 "Golden set incl. IEEE/vendor modules"
    [ "${LIBSMI:-0}" = "1" ] && libsmi_diff "$OUT" "$OUT/targets.txt" golden-all
    cat "$OUT/check/report.md"
    exit 0
    ;;
sample)
    OUT=$(mkdir -p "${2:-$CACHE/sample}" && cd "${2:-$CACHE/sample}" && pwd)
    PARTS=${3:-3}
    python3 "$CMP/yang_sample.py" --out "$OUT/sample.txt"
    if ! MIBCORPUS_LIST="$OUT/sample.txt" MIBYANG_OUT="$OUT" MIBYANG_META=1 $LOCK acton test --fast --tag mibcorpus --no-cache \
            --module mib.test_yang --name yang_corpus >"$OUT/emit.txt" 2>&1; then
        echo "emitter test FAILED, see $OUT/emit.txt"
    fi
    echo "sample: $(wc -l <"$OUT/sample.txt") modules -> $OUT"
    check_parts "$OUT" "$OUT/sample.txt" "$PARTS" "Corpus sample (yang_sample.py)"
    [ "${LIBSMI:-0}" = "1" ] && libsmi_diff "$OUT" "$OUT/sample.txt" corpus
    cat "$OUT/check/report.md"
    exit 0
    ;;
corpus)
    OUT=$(mkdir -p "${2:-$CACHE/corpus}" && cd "${2:-$CACHE/corpus}" && pwd)
    N=${3:-8}
    PARTS=${4:-16}
    mkdir -p "$OUT/check"
    printf '' >"$OUT/check/emit.cmds"
    k=1
    while [ "$k" -le "$N" ]; do
        [ -e "$OUT/check/emit$k.done" ] && mv "$OUT/check/emit$k.done" "$OUT/check/emit$k.old"
        echo "emit$k MIBCORPUS_CHUNK=$k/$N MIBYANG_OUT=$OUT MIBYANG_META=${META:-1} acton test --fast --tag mibcorpus --no-cache --module mib.test_yang --name yang_corpus >$OUT/emit.$k.txt 2>&1" >>"$OUT/check/emit.cmds"
        k=$((k + 1))
    done
    batch "$OUT/check" "${EMIT_BUDGET:-420}" "$OUT/check/emit.cmds"
    k=1
    while [ "$k" -le "$N" ]; do
        grep -q "tests passed" "$OUT/emit.$k.txt" || echo "chunk $k: emitter test FAILED, see $OUT/emit.$k.txt"
        echo "chunk $k/$N: $(grep -c . "$OUT/yang-modules.${k}of$N.tsv") modules"
        k=$((k + 1))
    done
    cat "$OUT"/yang-modules.*of"$N".tsv >"$OUT/targets.tsv"
    check_parts "$OUT" "$OUT/targets.tsv" "$PARTS" "Whole corpus (interop/mibs/corpus/flat)"
    cat "$OUT/check/report.md"
    exit 0
    ;;
esac

DEF_OUT="${TMPDIR:-/tmp}/actsnmp-yang-check"
OUT=$(mkdir -p "${1:-$DEF_OUT}" && cd "${1:-$DEF_OUT}" && pwd)
mkdir -p "$OUT/ref" "$OUT/golden"
rc=0

echo "== 1. emit (mib.test_yang yang_golden) -> $OUT"
if ! MIBYANG_OUT="$OUT" $LOCK acton test --no-cache --module mib.test_yang --name yang_golden >"$OUT/emit.txt" 2>&1; then
    echo "FAILED, see $OUT/emit.txt"
    exit 1
fi

echo "== 2. libsmi 0.5.0 comparison (reference MIBs)"
if python3 "$CMP/yang_vs_libsmi.py" --ours "$OUT/ref" --libsmi "$EXAMPLES/yang-libsmi-0.5.0" \
        --out "$OUT/libsmi-ref.md" >/dev/null; then
    echo "ok: only documented deviations ($OUT/libsmi-ref.md)"
else
    echo "FAILED: unexplained differences, see $OUT/libsmi-ref.md"
    rc=1
fi
if [ -d "$OUT/libsmi-golden" ]; then
    python3 "$CMP/yang_vs_libsmi.py" --ours "$OUT/golden" --libsmi "$OUT/libsmi-golden" --out "$OUT/libsmi-golden.md" >/dev/null
    echo "golden set (information): $(tail -1 "$OUT/libsmi-golden.md")"
fi

echo "== 3. pyang --strict"
pyang_image
for set in ref golden; do
    e=$(run_pyang "$OUT/$set" "$OUT/pyang-$set.txt")
    w=$(grep -c ': warning:' "$OUT/pyang-$set.txt")
    echo "$set: $(ls "$OUT/$set" | grep -c '\.yang$') modules, $e errors, $w warnings"
    grep ': error:' "$OUT/pyang-$set.txt" | head -20
    [ "$e" -eq 0 ] || rc=1
done

echo "== 4. acton-yang compile + mibmeta consistency"
if ! yangcheck_build "$OUT/yangcheck-build.txt"; then
    echo "FAILED to build yangcheck, see $OUT/yangcheck-build.txt"
    exit 1
fi
for set in ref golden; do
    if $LOCK "$YC" "$IETF"/*.yang "$OUT/$set"/*.yang --meta "$OUT/$set"/*.mibmeta.json \
            >"$OUT/yangcheck-$set.txt" 2>&1; then
        echo "$set: $(head -2 "$OUT/yangcheck-$set.txt" | tr '\n' ' ')"
    else
        echo "$set: FAILED"
        head -40 "$OUT/yangcheck-$set.txt"
        rc=1
    fi
done
echo "== 5. mibmeta conversion vs YANG type"
for set in ref golden; do
    if python3 "$CMP/yang_conv_check.py" "$OUT/$set" >"$OUT/conv-$set.txt" 2>&1; then
        echo "$set: $(head -1 "$OUT/conv-$set.txt")"
    else
        echo "$set: FAILED"
        head -20 "$OUT/conv-$set.txt"
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "ALL OK" || echo "FAILURES"
exit $rc
