# pyang 2.6.1, the validator for actsnmp's RFC 6643 YANG (src/mib/yang.act).
# Built by interop/mibs/compare/yang_check.sh as actsnmp-pyang:1.
FROM python:3.11-slim
RUN pip install --no-cache-dir --disable-pip-version-check pyang==2.6.1 && pyang --version
WORKDIR /work
