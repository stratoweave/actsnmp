#!/usr/bin/env bash
# Run the pysnmp based reference client (interop/pysnmp_client.py) from the
# interop image with host networking.  Same options as net-snmp tools, e.g.
#   interop/pysnmp.sh get -v2c -c public 127.0.0.1:16163 1.3.6.1.2.1.1.1.0
#   interop/pysnmp.sh bulkwalk -v3 -l authPriv -u u_sha256_aes -a SHA-256 \
#       -A authpass123 -x AES -X privpass123 127.0.0.1:16163 1.3.6.1.4.1.8072.9999.1
# See "interop/pysnmp.sh --help".
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/nsnmp.sh" pysnmp-client "$@"
