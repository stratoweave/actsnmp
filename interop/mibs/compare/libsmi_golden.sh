#!/bin/sh
# libsmi 0.5.0 YANG of every golden module, for yang_vs_libsmi.py (information only; the gate
# compares the 9 reference MIBs with interop/mibs/yang-examples/yang-libsmi-0.5.0).
#
#   interop/mibs/compare/libsmi_golden.sh OUTDIR    -> OUTDIR/<MOD>.yang and <MOD>.err
#
# Needs the docker image actsnmp-libsmi-trunk:1 (libsmi 0.5.0 built from libsmi's git master).
# Runs under the bench lock (~/gcperf/lock100/bench.lock, if it exists) unless LOCK= is set.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=$(mkdir -p "${1:?OUTDIR}" && cd "$1" && pwd)
if [ -z "${LOCK+x}" ]; then
    if [ -e "$HOME/gcperf/lock100/bench.lock" ]; then LOCK="flock -w 3600 $HOME/gcperf/lock100/bench.lock"; else LOCK=""; fi
fi
$LOCK docker run --rm -v "$ROOT/interop/mibs/golden/mibs":/mibs:ro -v "$OUT":/out actsnmp-libsmi-trunk:1 sh -c '
cd /mibs
for f in *; do
    SMIPATH=/mibs smidump -k -f yang -p "/mibs/$f" "$f" > "/out/$f.yang" 2> "/out/$f.err"
done
chmod a+rw /out/*'
