# actsnmp MIB oracle image: the three independent MIB compilers we use as
# differential-testing oracles for the actsnmp MIB compiler.
#   - pysmi 2.0.0 (lextudio; lark LALR parser) -> JSON  (oracles.sh pysmi-*)
#   - net-snmp 5.9.4 libnetsnmp MIB parser: snmptranslate + mibwalk (our JSONL dumper)
#   - libsmi 0.4.8 smilint (error classification) / smidump
# Build with interop/mibs/build.sh (tags actsnmp-mibs:1). The oracle scripts are
# bind-mounted at run time (/lab), so editing them needs no rebuild.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG NETSNMP_VERSION=5.9.4+dfsg-1.1ubuntu3.2
ARG LIBSMI_VERSION=0.4.8+dfsg2-16.1build1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        snmp=${NETSNMP_VERSION} \
        libsnmp-dev=${NETSNMP_VERSION} \
        smitools=${LIBSMI_VERSION} \
        gcc libc6-dev python3 python3-venv ca-certificates; \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/miblab/requirements.txt
RUN set -eux; \
    python3 -m venv /opt/venv; \
    /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check \
        -r /opt/miblab/requirements.txt; \
    /opt/venv/bin/pip check

COPY mibwalk.c /opt/miblab/mibwalk.c
RUN set -eux; \
    gcc -O2 -Wall -o /usr/local/bin/mibwalk /opt/miblab/mibwalk.c $(net-snmp-config --libs); \
    # no default MIBs from the system: oracles always pass -M/-m explicitly
    printf 'mibs :\n' > /etc/snmp/snmp.conf

ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /tmp
CMD ["bash"]
