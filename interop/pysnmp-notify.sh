#!/usr/bin/env bash
# Run the pysnmp based notification sender (interop/pysnmp_notify.py) from the
# interop image with host networking.  Arguments like net-snmp snmptrap /
# snmpinform, with the mode first, e.g.
#   interop/pysnmp-notify.sh trap -v2c -c public 127.0.0.1:16165 12345 .1.3.6.1.4.1.8072.9999.3.0.1 \
#       .1.3.6.1.4.1.8072.9999.1.1.1.0 i 0
#   interop/pysnmp-notify.sh trap -v1 -c public 127.0.0.1:16165 .1.3.6.1.4.1.8072.9999 192.0.2.1 6 42 12345
#   interop/pysnmp-notify.sh inform -v3 -l authPriv -u u_sha_aes -a SHA -A authpass123 -x AES -X privpass123 \
#       127.0.0.1:16165 100 .1.3.6.1.4.1.8072.9999.3.0.2
#   interop/pysnmp-notify.sh trap -v3 -e 0x8000000001020305 -l authNoPriv -u u_md5 -a MD5 -A authpass123 \
#       127.0.0.1:16165 100 .1.3.6.1.4.1.8072.9999.3.0.3
# See "interop/pysnmp-notify.sh --help".
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/nsnmp.sh" pysnmp-notify "$@"
