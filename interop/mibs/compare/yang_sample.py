#!/usr/bin/env python3
"""A deterministic, vendor-stratified sample of corpus modules for the YANG corpus checks.

    python3 interop/mibs/compare/yang_sample.py [--modules interop/mibs/modules.tsv]
        [--fraction 0.04] [--out FILE] [--big N] [--stats]

Reads ``modules.tsv`` (one row per ``corpus/flat`` module) and prints one module name per line:

- every module is put into a group: its ``vendor`` column, or for the mibs.pysnmp.com
  aggregator (vendor ``pysnmp``, no vendor directories) ``ent:<enterprise number>``, else
  ``arc:<registration arc>`` (``mib-2``, ``experimental``, ...);
- from each group ``ceil(fraction * size)`` modules are taken (at least one per group, so
  small vendors are represented), in the order of ``sha256(module name)``;
- the ``MUST`` list is always included: core IETF modules (IP-MIB, IF-MIB, ...) and the
  big official Cisco, Juniper, Nokia and Huawei modules the YANG consumers care about;
- with ``--big N`` the N largest modules (by file size) of each of the vendors Cisco, Juniper,
  Nokia, Huawei and HP are added as well.

The selection only depends on ``modules.tsv`` (module names and the vendor, enterprise, arc
and size columns), so it is stable until the corpus is re-indexed. Pure stdlib.
"""

import argparse
import hashlib
import math
import sys

# always in the sample (when the corpus has them)
MUST = [
    "IF-MIB", "IP-MIB", "IP-FORWARD-MIB", "TCP-MIB", "UDP-MIB", "ENTITY-MIB", "ENTITY-SENSOR-MIB",
    "BRIDGE-MIB", "Q-BRIDGE-MIB", "LLDP-MIB", "LLDP-V2-MIB", "HOST-RESOURCES-MIB", "BGP4-MIB",
    "OSPF-MIB", "MPLS-TE-STD-MIB", "DISMAN-EVENT-MIB", "SNMPv2-MIB", "IPV6-MIB",
    "CISCO-PROCESS-MIB", "CISCO-CDP-MIB", "CISCO-ENTITY-SENSOR-MIB", "CISCO-MEMORY-POOL-MIB",
    "CISCO-ENHANCED-MEMPOOL-MIB", "CISCO-IF-EXTENSION-MIB", "CISCO-BGP4-MIB", "CISCO-VTP-MIB",
    "CISCO-ENTITY-FRU-CONTROL-MIB", "CISCO-CLASS-BASED-QOS-MIB",
    "JUNIPER-MIB", "JUNIPER-IF-MIB", "JUNIPER-DOM-MIB", "JUNIPER-FIREWALL-MIB", "BGP4-V2-MIB-JUNIPER",
    "JUNIPER-VPN-MIB", "JUNIPER-COS-MIB",
    "TIMETRA-CHASSIS-MIB", "TIMETRA-PORT-MIB", "TIMETRA-SERV-MIB", "TIMETRA-VRTR-MIB",
    "TIMETRA-BGP-MIB", "TIMETRA-GLOBAL-MIB",
    "HUAWEI-ENTITY-EXTENT-MIB", "HUAWEI-IF-EXT-MIB",
]

BIG_VENDORS = ["cisco", "juniper", "nokia", "huawei", "hp"]


def read_modules(path):
    rows = []
    hdr = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            cols = line.rstrip("\n").split("\t")
            if hdr is None:
                hdr = cols
                continue
            rows.append(dict(zip(hdr, cols)))
    return rows


def group_of(r):
    v = r.get("vendor", "")
    if v and v != "pysnmp":
        return v
    e = r.get("enterprise", "")
    if e:
        return "ent:" + e
    return "arc:" + (r.get("arc", "") or "?")


def key(name):
    return hashlib.sha256(name.encode()).hexdigest()


def sample(rows, fraction, big):
    groups = {}
    for r in rows:
        groups.setdefault(group_of(r), []).append(r["module"])
    picked = set()
    for g, names in groups.items():
        n = max(1, math.ceil(fraction * len(names)))
        for nm in sorted(names, key=key)[:n]:
            picked.add(nm)
    have = {r["module"] for r in rows}
    for nm in MUST:
        if nm in have:
            picked.add(nm)
    if big > 0:
        for v in BIG_VENDORS:
            vr = [r for r in rows if r.get("vendor", "") in (v, v + "-sros")]
            vr.sort(key=lambda r: (-int(r.get("size", "0") or "0"), r["module"]))
            for r in vr[:big]:
                picked.add(r["module"])
    return sorted(picked), groups


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--modules", default="interop/mibs/modules.tsv")
    ap.add_argument("--fraction", type=float, default=0.04)
    ap.add_argument("--big", type=int, default=3)
    ap.add_argument("--out")
    ap.add_argument("--stats", action="store_true", help="print the group sizes to stderr")
    a = ap.parse_args()
    rows = read_modules(a.modules)
    names, groups = sample(rows, a.fraction, a.big)
    text = "".join(nm + "\n" for nm in names)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if a.stats:
        by = {}
        gof = {r["module"]: group_of(r) for r in rows}
        for nm in names:
            g = gof[nm]
            by[g] = by.get(g, 0) + 1
        vend = sorted(((c, g) for g, c in by.items() if not g.startswith(("ent:", "arc:"))), reverse=True)
        print("sample: %d modules from %d groups (%d corpus modules)" % (len(names), len(by), len(rows)), file=sys.stderr)
        print("vendor groups: " + ", ".join("%s %d" % (g, c) for c, g in vend), file=sys.stderr)
        print("pysnmp aggregator: %d modules in %d enterprise/arc groups" %
              (sum(c for g, c in by.items() if g.startswith(("ent:", "arc:"))),
               len([g for g in by if g.startswith(("ent:", "arc:"))])), file=sys.stderr)


if __name__ == "__main__":
    main()
