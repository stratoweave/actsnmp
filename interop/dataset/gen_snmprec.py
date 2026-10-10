#!/usr/bin/env python3
"""Generate the snmpsim data directory for the actsnmp interop lab.

  <out>/public.snmprec        shared dataset (identical to what snmpd serves
                              below 1.3.6.1.4.1.8072.9999.1) + snmpsim system group
  <out>/self.snmprec          copy of public.snmprec; snmpsim maps SNMPv3
                              requests with an EMPTY context name to "self"
  <out>/private.snmprec       copy of public.snmprec (community "private")
  <out>/pathological.snmprec  snmpsim-only weird/broken behaviour
                              (community "pathological" / v3 context "pathological")

usage: gen_snmprec.py <outdir>

With --actsnmp it instead writes the files for actsnmp agent (committed
in interop/dataset/, regenerate with interop/dataset/regen.sh):

  <out>/actsnmp.snmprec       plain snmprec (no variation modules): the shared
                              dataset below 1.3.6.1.4.1.8072.9999.1 (writable
                              objects with their initial values), the snmpsim
                              system group values and an snmpEngineID.0 sentinel
  <out>/write-rules.tsv       write rules of the B.20 objects as the lab agents
                              enforce them
  <out>/pathological.snmprec  the static part of the pathological dataset

usage: gen_snmprec.py --actsnmp <outdir> [--system-canon FILE]
  --system-canon FILE  take the system group values from this canonical file
                       (interop/expected/canon/snmpsim-system.txt) and check
                       that they equal SYSTEM below
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import actsnmp_dataset as ds  # noqa: E402

TAG = {
    "INTEGER": "2",
    "OCTETS": "4",
    "NULL": "5",
    "OID": "6",
    "IPADDR": "64",
    "COUNTER32": "65",
    "GAUGE32": "66",
    "TIMETICKS": "67",
    "OPAQUE": "68",
    "COUNTER64": "70",
    "NOSUCHOBJECT": "128",
    "NOSUCHINSTANCE": "129",
    "ENDOFMIBVIEW": "130",
}


def rec_line(oid, typ, val):
    o = ds.oidstr(oid)
    t = TAG[typ]
    if typ in ("OCTETS", "OPAQUE"):
        # always hex: snmprec lines are stripped, so leading/trailing blanks,
        # '|' and non-printables would otherwise be mangled
        return "%s|%sx|%s" % (o, t, val.hex())
    if typ == "IPADDR":
        return "%s|%sx|%s" % (o, t, val.hex())
    if typ == "OID":
        return "%s|%s|%s" % (o, t, ds.oidstr(val))
    if typ in ("NULL", "NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW"):
        return "%s|%s|" % (o, t)
    return "%s|%s|%d" % (o, t, val)


def writecache_line(oid, typ, val, extra=""):
    o = ds.oidstr(oid)
    t = TAG[typ]
    if typ in ("OCTETS", "OPAQUE", "IPADDR"):
        v = "hexvalue=%s" % val.hex()
    elif typ == "OID":
        v = "value=%s" % ds.oidstr(val)
    else:
        v = "value=%d" % val
    return "%s|%s:writecache|%s%s" % (o, t, v, extra)


SYSTEM = [
    # snmpsim "system" group so that sysDescr/sysObjectID GETs work there too
    ((1, 3, 6, 1, 2, 1, 1, 1, 0), "OCTETS", b"actsnmp interop lab snmpsim agent"),
    ((1, 3, 6, 1, 2, 1, 1, 2, 0), "OID", (1, 3, 6, 1, 4, 1, 20408)),
    ((1, 3, 6, 1, 2, 1, 1, 3, 0), "TIMETICKS", 4242),
    ((1, 3, 6, 1, 2, 1, 1, 4, 0), "OCTETS", b"actsnmp-contact"),
    ((1, 3, 6, 1, 2, 1, 1, 5, 0), "OCTETS", b"actsnmp-snmpsim"),
    ((1, 3, 6, 1, 2, 1, 1, 6, 0), "OCTETS", b"actsnmp-lab"),
    ((1, 3, 6, 1, 2, 1, 1, 7, 0), "INTEGER", 72),
    # snmpEngineID.0 - also acts as a sentinel after the 8072.9999 subtree so
    # that walks of the dataset end the same way as on snmpd (next OID outside
    # the subtree) instead of with endOfMibView
    ((1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0), "OCTETS",
     bytes.fromhex("80004fb805") + b"actsnmpsim"),
]


def public_lines():
    lines = []
    for oid, typ, val in SYSTEM:
        lines.append((oid, rec_line(oid, typ, val)))
    writable = {ds.BASE + (20, n, 0): (n, rw) for (n, _t, _v, rw) in ds.WRITABLE}
    for oid, typ, val in ds.records():
        if oid in writable:
            n, rw = writable[oid]
            if not rw:
                lines.append((oid, rec_line(oid, typ, val)))
            elif n in ds.WRITABLE_RANGE:
                lo, hi = ds.WRITABLE_RANGE[n]
                lines.append((oid, writecache_line(
                    oid, typ, val,
                    ",vlist=lt:%d:wrongvalue:gt:%d:wrongvalue" % (lo, hi))))
            else:
                lines.append((oid, writecache_line(oid, typ, val)))
        else:
            lines.append((oid, rec_line(oid, typ, val)))
    lines.sort(key=lambda x: x[0])
    return [line for _o, line in lines]


P = ds.PATH


def pathological_lines():
    L = []

    def add(sub, line_rest):
        L.append((P + sub, "%s|%s" % (ds.oidstr(P + sub), line_rest)))

    # P.1 unusual but legal values
    add((1, 1, 0), "2|1")
    add((1, 2, 0), "5|")                                     # NULL value
    add((1, 3, 0), "4x|" + ds._pattern(10000).hex())         # 10000 byte string
    add((1, 4, 0), "4x|" + ds._pattern(65535).hex())         # max SMI size, cannot fit in UDP
    add((1, 5, 0), "2|5")
    add((1, 6, 0), "4x|" + ds._pattern(60000).hex())         # fits in one UDP datagram
    # P.2 exception values returned as if they were data (illegal in GETNEXT
    # responses); P.2.3.0 endOfMibView makes walks stop early, P.2.4.0 is
    # only reachable by GET
    add((2, 1, 0), "128|")                                   # noSuchObject
    add((2, 2, 0), "129|")                                   # noSuchInstance
    add((2, 3, 0), "130|")                                   # endOfMibView
    add((2, 4, 0), "2|24")
    # P.3 error-status responses (error variation module, any operation)
    for i, st in enumerate(["generror", "toobig", "noaccess", "authorizationerror",
                            "resourceunavailable", "nosuchname"], start=1):
        add((3, i, 0), "2:error|op=any,status=%s,value=%d" % (st, i))
    # P.4 slow responses (delay variation module, which blocks all of snmpsim)
    add((4, 1, 0), "2:delay|wait=1000,value=41")             # 1 s
    add((4, 2, 0), "2:delay|wait=5000,value=42")             # 5 s
    # P.5 broken lexicographic ordering (actsnmp_badnext variation module)
    add((5, 1, 0), "2|51")
    add((5, 2, 0), "2:actsnmp_badnext|target=%s,value=52" % ds.oidstr(P + (5, 1, 0)))
    add((5, 3, 0), "2|53")
    add((5, 4, 0), "2:actsnmp_badnext|target=self,value=54")
    add((5, 5, 0), "2|55")
    L.sort(key=lambda x: x[0])
    return [line for _o, line in L]


# ------------------------------------------------ actsnmp test agent files ---

# The default engine ID of actsnmp agent: 0x80001f88 (enterprise 8072), format
# 0x80, "actsnmpa". Used as the value of the snmpEngineID.0 sentinel record in
# actsnmp.snmprec; an agent with another engine ID should serve its own value.
ACTSNMP_AGENT_ENGINE_ID = bytes.fromhex("80001f8880") + b"actsnmpa"

SNMP_ENGINE_ID_OID = (1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)

# system group objects that interop/expected/canon/snmpsim-system.txt records
# (sysUpTime.0 is deliberately absent: snmpd's is volatile, snmpsim's a
# constant 4242; the agent should provide its own)
SYSTEM_CANON_OIDS = [(1, 3, 6, 1, 2, 1, 1, n, 0) for n in (1, 2, 4, 5, 6, 7)]


def parse_canon_line(line):
    """Inverse of actsnmp_dataset.canon_line() for the types the system
    group uses (INTEGER, STRING, Hex-STRING, OID)."""
    oid_s, sep, val = line.rstrip("\n").partition(" = ")
    if not sep or not oid_s.startswith("."):
        raise ValueError("not a canonical line: %r" % line)
    oid = tuple(int(x) for x in oid_s[1:].split("."))
    if val.startswith("INTEGER: "):
        return oid, "INTEGER", int(val[9:])
    if val.startswith('STRING: "') and val.endswith('"'):
        s = val[9:-1]
        out = []
        i = 0
        while i < len(s):
            if s[i] == "\\" and i + 1 < len(s):
                i += 1
            out.append(s[i])
            i += 1
        return oid, "OCTETS", "".join(out).encode("ascii")
    if val.startswith("Hex-STRING: "):
        return oid, "OCTETS", bytes(int(x, 16) for x in val[12:].split())
    if val.startswith("OID: ."):
        return oid, "OID", tuple(int(x) for x in val[6:].split("."))
    raise ValueError("unsupported canonical value: %r" % line)


def system_records(canon_file=None):
    """System group of actsnmp.snmprec.  Taken from the canonical snmpsim GET
    output when given, and cross-checked against SYSTEM (what snmpsim serves)."""
    ref = {oid: (typ, val) for oid, typ, val in SYSTEM}
    if canon_file is None:
        return [(oid,) + ref[oid] for oid in SYSTEM_CANON_OIDS]
    recs = []
    with open(canon_file) as f:
        for line in f:
            if line.strip():
                recs.append(parse_canon_line(line))
    got = [r[0] for r in recs]
    if got != SYSTEM_CANON_OIDS:
        raise SystemExit("%s: unexpected OIDs %s" % (canon_file, got))
    for oid, typ, val in recs:
        if ref[oid] != (typ, val):
            raise SystemExit("%s: %s = %r differs from gen_snmprec.SYSTEM %r"
                             % (canon_file, ds.oidstr(oid), (typ, val), ref[oid]))
    return recs


def actsnmp_lines(canon_file=None):
    """actsnmp.snmprec: plain records only (tags 2 4x 6 64x 65 66 67 68x 70)."""
    recs = system_records(canon_file) + ds.records() + [
        (SNMP_ENGINE_ID_OID, "OCTETS", ACTSNMP_AGENT_ENGINE_ID)]
    recs.sort(key=lambda r: r[0])
    return [rec_line(oid, typ, val) for oid, typ, val in recs]


# SET error statuses of the lab agents (snmpd, verified by selftest.py):
#   no rule / writable=no   -> notWritable   (v1: noSuchName)
#   tag not in tags         -> wrongType     (v1: badValue)
#   value outside min..max  -> wrongValue    (v1: badValue)
def write_rules_lines():
    L = [
        "# GENERATED by interop/dataset/gen_snmprec.py --actsnmp (interop/dataset/regen.sh)",
        "# Write rules of the lab dataset as snmpd (pass_persist) and snmpsim (writecache) enforce them.",
        "# oid: exact object instance (also usable as a prefix; first match wins, no match = not writable)",
        "# tags: allowed snmprec tag(s) of the SET value, comma separated (2 INTEGER, 4 OCTET STRING,",
        "#   6 OID, 64 IpAddress, 65 Counter32, 66 Gauge32/Unsigned32, 67 TimeTicks, 68 Opaque, 70 Counter64)",
        "# min/max: inclusive range of the value ('-' = only the type's own range)",
        "# writable: yes / no.  Errors (snmpd): not writable -> notWritable (v1 noSuchName),",
        "#   wrong tag -> wrongType (v1 badValue), out of range -> wrongValue (v1 badValue).",
        "# Not atomic on the lab agents: earlier varbinds of a failing multi-varbind SET stay applied.",
        "# oid\ttags\tmin\tmax\twritable",
    ]
    for n, typ, _val, rw in ds.WRITABLE:
        lo, hi = ds.WRITABLE_RANGE.get(n, (None, None))
        L.append("\t".join([
            "." + ds.oidstr(ds.BASE + (20, n, 0)),
            TAG[typ],
            "-" if lo is None else str(lo),
            "-" if hi is None else str(hi),
            "yes" if rw else "no",
        ]))
    return L


def pathological_static_lines():
    """The pathological dataset without the records that need a snmpsim
    variation module (P.3 error, P.4 delay, P.5.2/P.5.4 actsnmp_badnext)."""
    return [line for line in pathological_lines() if ":" not in line.split("|")[1]]


def main_actsnmp(args):
    canon = None
    if "--system-canon" in args:
        i = args.index("--system-canon")
        canon = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write(__doc__)
        sys.exit(2)
    out = args[0]
    os.makedirs(out, exist_ok=True)
    for name, lines in (("actsnmp.snmprec", actsnmp_lines(canon)),
                        ("write-rules.tsv", write_rules_lines()),
                        ("pathological.snmprec", pathological_static_lines())):
        fn = os.path.join(out, name)
        with open(fn, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote %s (%d lines)" % (fn, len(lines)))


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--actsnmp":
        main_actsnmp(sys.argv[2:])
        return
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        sys.exit(2)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, lines in (("public", public_lines()),
                        ("pathological", pathological_lines())):
        fn = os.path.join(out, name + ".snmprec")
        with open(fn, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote %s (%d records)" % (fn, len(lines)))
    # snmpsim maps a data file named "self.snmprec" to the EMPTY context name
    # (and the empty community).  It must be a regular file: a symlink is
    # resolved to its target name and then ignored as a duplicate "public".
    # "private.snmprec" gives snmpsim a "private" community like snmpd has.
    # snmpsim has no access control, so public/private/self are all
    # read-write for the writecache objects; the writecache store is keyed by
    # OID only, so a SET through one community is visible through the others.
    lines = public_lines()
    for name in ("self", "private"):
        fn = os.path.join(out, name + ".snmprec")
        if os.path.lexists(fn):
            os.remove(fn)
        with open(fn, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote %s (%d records, copy of public)" % (fn, len(lines)))


if __name__ == "__main__":
    main()
