#!/usr/bin/env bash
# The actsnmp CLI side by side with net-snmp's command line tools: every case runs the same arguments
# with the lab image's net-snmp tool (docker exec actsnmp-tools snmpget ...) and with our CLI
# (out/bin/actsnmp get ...) against snmpd (16161), snmpsim (16162), a closed port (16169) and the lab's
# snmptrapd (16164), and compares stdout, stderr and the exit code byte for byte. Documented
# differences (the case says why) are reported as KNOWN, not as failures.
#
#   interop/clicheck.sh [--cli PATH] [--quick] [--filter REGEX] [--section LIST] [--report FILE] [-v]
#   interop/clicheck.sh --list
#
#   --cli PATH      the CLI to test (default: out/bin/actsnmp)
#   --quick         skip the slow whole-dataset GETNEXT walks
#   --filter REGEX  only the cases whose "section/name" matches
#   --section LIST  only these sections: dataset,output,walk-options,address,timeout,v3-errors,
#                   error-status,pathological,local-errors,set,mib
#   --report FILE   also write the markdown report to FILE
#   -v              show the diff of every known difference too
#
# Needs snmpd, snmpsim and the tools container (interop/up.sh); about 4 minutes. The "set" section
# changes the writable B.20 objects of both agents and restores their initial values. The "mib"
# section runs both tools with MIBs loaded: it copies the MIB directories into the
# tools container, snapshots snmpd's MIB and serves the snapshot with `actsnmp agent` on 16167 while
# it runs. The cases and the documented differences are in interop/clicheck.py; the report
# (markdown) goes to stdout, the per-case progress to stderr. Exit status 0 when no case FAILs.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

case "${1:-}" in
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
esac
for c in "$C_SNMPD" "$C_SNMPSIM" "$C_TOOLS"; do
    container_running "$c" || die "$c is not running (interop/up.sh)"
done
exec python3 "$INTEROP_DIR/clicheck.py" "$@"
