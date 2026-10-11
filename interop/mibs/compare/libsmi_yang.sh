#!/bin/sh
# libsmi 0.5.0 YANG (smidump -k -f yang) of a list of modules, for yang_vs_libsmi.py (information:
# libsmi is the reference implementation of RFC 6643, but it has its own deviations L1-L10).
#
#   interop/mibs/compare/libsmi_yang.sh OUTDIR LISTFILE corpus     modules of interop/mibs/corpus/flat
#   interop/mibs/compare/libsmi_yang.sh OUTDIR LISTFILE golden-all the golden set incl. the staged
#                                                                  vendor texts (cache/golden-vendor)
#
# LISTFILE: one module name per line (a .tsv is read by its first column). Writes
# OUTDIR/<MOD>.yang and OUTDIR/<MOD>.err; skips modules whose .yang exists already (resumable),
# stops starting new modules after LIBSMI_BUDGET seconds (default 780) so one bench-lock hold
# stays below 15 minutes, and bounds every module by 60 s. Needs the docker image
# actsnmp-libsmi-trunk:1 (libsmi 0.5.0 built from libsmi's git master). Runs under the bench
# lock (~/gcperf/lock100/bench.lock, if it exists) unless LOCK= is set.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=$(mkdir -p "${1:?OUTDIR}" && cd "$1" && pwd)
LIST=$(cd "$(dirname "${2:?LISTFILE}")" && pwd)/$(basename "$2")
SET=${3:-corpus}
if [ -z "${LOCK+x}" ]; then
    if [ -e "$HOME/gcperf/lock100/bench.lock" ]; then LOCK="flock -w 3600 $HOME/gcperf/lock100/bench.lock"; else LOCK=""; fi
fi
case "$SET" in
    corpus) MOUNTS="-v $ROOT/interop/mibs/corpus:/corpus:ro"; SP=/corpus/flat ;;
    golden-all) MOUNTS="-v $ROOT/interop/mibs/golden/mibs:/g:ro -v $ROOT/interop/mibs/cache/golden-vendor:/v:ro"; SP=/g:/v ;;
    *) echo "unknown set $SET" >&2; exit 2 ;;
esac
cut -f1 "$LIST" | grep -v '^#' | grep -v '^$' >"$OUT/.list"
$LOCK docker run --rm $MOUNTS -v "$OUT":/out -e SMIPATH="$SP" -e BUDGET="${LIBSMI_BUDGET:-780}" \
    actsnmp-libsmi-trunk:1 sh -c '
start=$(date +%s)
n=0
while read m; do
    [ -e "/out/$m.err" ] && continue
    if [ $(( $(date +%s) - start )) -gt "$BUDGET" ]; then echo "budget exhausted after $n modules"; break; fi
    timeout 60 smidump -k -f yang "$m" >"/out/$m.yang" 2>"/out/$m.err" || true
    n=$((n + 1))
done </out/.list
chmod a+rw /out/* 2>/dev/null || true
echo "libsmi: $n modules"'
