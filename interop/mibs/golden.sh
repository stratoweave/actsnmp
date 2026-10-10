#!/usr/bin/env bash
# Golden set: rebuild or check golden/ (see README.md).
#
#   interop/mibs/golden.sh            select (golden/select.tsv + import closure), stage, run all oracles on
#                                     the staged set, write golden/expected/ (committed tier) and
#                                     golden/expected-local/ (local tier: derived from IEEE/vendor texts, not
#                                     committed)
#   interop/mibs/golden.sh --local    regenerate golden/expected-local/ from the corpus (golden.tsv, golden/mibs
#                                     and golden/expected/ unchanged), e.g. after a fresh clone + fetch.sh
#   interop/mibs/golden.sh --check    stage from golden/golden.tsv, run the oracles, diff with golden/expected/
#                                     and (if it exists) golden/expected-local/
#
# The reference-only (IEEE/vendor) texts come from the corpus (fetch.sh). Without it, --check skips the
# local tier with a notice and checks the committed tier (golden/mibs + golden/expected) only.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

mode=build
case "${1:-}" in
    --check) mode=check ;;
    --local) mode=local ;;
    "") ;;
    *) die "unknown argument: $1 (--check, --local)" ;;
esac
check_daytime
docker image inspect "$MIBS_IMAGE" >/dev/null 2>&1 || "$MIBS_DIR/build.sh"

if [ $mode = build ]; then
    python3 "$MIBS_DIR/golden.py" select
fi
if [ $mode = local ]; then
    python3 "$MIBS_DIR/golden.py" stage --local
else
    python3 "$MIBS_DIR/golden.py" stage
fi
stage="$CACHE_DIR/golden"
rm -rf "$stage/cache"
mkdir -p "$stage/cache"
locked docker run --rm --user "$(id -u):$(id -g)" \
    -v "$MIBS_DIR:/lab:ro" -v "$stage/corpus:/corpus:ro" -v "$stage/cache:/cache" \
    -e HOME=/tmp -e SNMP_PERSISTENT_DIR=/tmp/snmp-persist \
    "$MIBS_IMAGE" python3 /lab/oracles/run.py pysmi-relaxed pysmi-strict pysmi-dialect netsnmp smilint \
    --jobs 16 --budget 600 --timeout 150
case $mode in
    check) python3 "$MIBS_DIR/golden.py" expected --check ;;
    local) python3 "$MIBS_DIR/golden.py" expected --local ;;
    build) python3 "$MIBS_DIR/golden.py" expected ;;
esac
