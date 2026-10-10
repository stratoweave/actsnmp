# actsnmp interop lab image: net-snmp 5.9.4 (agent, trap receiver, CLI tools),
# snmpsim 1.2.2 + pysnmp 7.1.30, our deterministic dataset and helper scripts
# (pysnmp_client.py manager, pysnmp_notify.py notification sender).
# Build with interop/build.sh (tags actsnmp-interop:1).
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# Ubuntu 24.04 (noble-updates) net-snmp package version
ARG NETSNMP_VERSION=5.9.4+dfsg-1.1ubuntu3.2
# 1 = also install snmp-mibs-downloader (fetches IETF/IANA MIBs at build time,
#     only needed for symbolic names with "-m ALL"); 0 = skip
ARG WITH_MIBS=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        snmpd=${NETSNMP_VERSION} \
        snmp=${NETSNMP_VERSION} \
        snmptrapd=${NETSNMP_VERSION} \
        python3 python3-venv ca-certificates iproute2 procps tcpdump; \
    if [ "${WITH_MIBS}" = "1" ]; then \
        apt-get install -y --no-install-recommends snmp-mibs-downloader; \
    fi; \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/actsnmp/requirements.txt
RUN set -eux; \
    python3 -m venv /opt/venv; \
    /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check \
        -r /opt/actsnmp/requirements.txt; \
    /opt/venv/bin/pip check

COPY dataset/ /opt/actsnmp/dataset/
COPY config/ /opt/actsnmp/config/
COPY snmpsim/variation/ /opt/actsnmp/snmpsim/variation/
COPY tools/ /opt/actsnmp/tools/
COPY pysnmp_client.py pysnmp_notify.py /opt/actsnmp/
COPY container/ /opt/actsnmp/bin/

RUN set -eux; \
    chmod +x /opt/actsnmp/dataset/actsnmp_pass.py /opt/actsnmp/bin/*; \
    # snmpsim: only load the variation modules we use (avoids redis/sql noise)
    SITE=$(/opt/venv/bin/python3 -c 'import snmpsim, os; print(os.path.dirname(snmpsim.__file__))'); \
    for m in writecache error delay numeric; do \
        cp "$SITE/variation/$m.py" /opt/actsnmp/snmpsim/variation/; \
    done; \
    python3 /opt/actsnmp/dataset/gen_snmprec.py /opt/actsnmp/snmpsim/data; \
    python3 -m compileall -q /opt/actsnmp; \
    useradd --system --uid 16161 --user-group --create-home --home-dir /home/actsnmp actsnmp; \
    chown -R actsnmp:actsnmp /opt/actsnmp/snmpsim

ENV PATH=/opt/actsnmp/bin:/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER actsnmp
WORKDIR /home/actsnmp
CMD ["bash"]
