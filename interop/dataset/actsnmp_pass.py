#!/usr/bin/env python3
"""net-snmp pass_persist backend serving the actsnmp deterministic dataset.

snmpd.conf:  pass_persist .1.3.6.1.4.1.8072.9999.1 /opt/actsnmp/dataset/actsnmp_pass.py

Protocol (see snmpd.conf(5), "pass_persist"):
  PING                       -> PONG
  get\\n<oid>                 -> <oid>\\n<type>\\n<value>   or NONE
  getnext\\n<oid>             -> same for the next OID     or NONE
  set\\n<oid>\\n<type> <value> -> DONE | not-writable | wrong-type | wrong-value ...

Writable objects (BASE.20.n.0) live in memory only, so every snmpd restart
starts from the documented initial values.
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import actsnmp_dataset as ds  # noqa: E402

PASS_TYPE = {
    "INTEGER": "integer",
    "COUNTER32": "counter",
    "GAUGE32": "gauge",
    "TIMETICKS": "timeticks",
    "COUNTER64": "counter64",
    "OID": "objectid",
    "IPADDR": "ipaddress",
    "OPAQUE": "opaque",
}

# incoming "set" type words (from netsnmp_internal_pass_set_format)
SET_TYPE = {
    "integer": "INTEGER",
    "gauge": "GAUGE32",
    "counter": "COUNTER32",
    "timeticks": "TIMETICKS",
    "ipaddress": "IPADDR",
    "string": "OCTETS",
    "octet": "OCTETS",
    "objectid": "OID",
}


def hexbytes(b):
    return " ".join("%02x" % x for x in b)


def is_pass_string(b):
    # pass "string" values are read line-wise and the trailing \n / \r is zapped
    return all(0x20 <= x <= 0x7E for x in b)


def fmt(typ, val):
    if typ == "OCTETS":
        if is_pass_string(val):
            return "string", val.decode("ascii")
        return "octet", hexbytes(val)
    if typ == "OPAQUE":
        return "opaque", hexbytes(val)
    if typ == "OID":
        return "objectid", "." + ds.oidstr(val)
    if typ == "IPADDR":
        return "ipaddress", ".".join(str(x) for x in val)
    return PASS_TYPE[typ], str(val)


class Store:
    def __init__(self):
        recs = ds.records()
        self.oids = [r[0] for r in recs]
        self.vals = {r[0]: (r[1], r[2]) for r in recs}
        self.writable = {}
        for (n, typ, _val, rw) in ds.WRITABLE:
            self.writable[ds.BASE + (20, n, 0)] = (n, typ, rw)

    def get(self, oid):
        if oid in self.vals:
            return oid, self.vals[oid]
        return None

    def getnext(self, oid):
        i = bisect.bisect_right(self.oids, oid)
        if i < len(self.oids):
            o = self.oids[i]
            return o, self.vals[o]
        return None

    def set(self, oid, typeword, raw):
        if oid not in self.writable:
            return "not-writable"
        n, typ, rw = self.writable[oid]
        if not rw:
            return "not-writable"
        styp = SET_TYPE.get(typeword)
        if styp != typ:
            return "wrong-type"
        try:
            val = parse_set_value(typeword, raw)
        except ValueError:
            return "wrong-value"
        if typ in ("GAUGE32", "TIMETICKS", "COUNTER32"):
            # pass_set_format prints these with "%d" of an int -> wrap back
            val &= 0xFFFFFFFF
        if n in ds.WRITABLE_RANGE:
            lo, hi = ds.WRITABLE_RANGE[n]
            if not (lo <= val <= hi):
                return "wrong-value"
        self.vals[oid] = (typ, val)
        return "DONE"


def parse_oid(s):
    s = s.strip().strip('"').strip()
    if s.startswith("."):
        s = s[1:]
    if not s:
        return ()
    return tuple(int(x) for x in s.split("."))


def parse_set_value(typeword, raw):
    raw = raw.rstrip("\n")
    if typeword in ("integer", "gauge", "counter", "timeticks"):
        return int(raw.strip())
    if typeword == "ipaddress":
        parts = [int(x) for x in raw.strip().split(".")]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            raise ValueError(raw)
        return bytes(parts)
    if typeword == "objectid":
        return parse_oid(raw)
    if typeword == "string":
        # format: "string \"<text>\""; the text itself is not escaped
        if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
            raw = raw[1:-1]
        return raw.encode("latin-1")
    if typeword == "octet":
        if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
            raw = raw[1:-1]
        return bytes(int(x, 16) for x in raw.split())
    raise ValueError(typeword)


def main():
    store = Store()
    inp = sys.stdin
    out = sys.stdout

    def reply(*lines):
        out.write("".join(line + "\n" for line in lines))
        out.flush()

    while True:
        line = inp.readline()
        if not line:
            return
        cmd = line.strip()
        if cmd == "":
            # snmpd sends an empty line to make us exit (or just noise)
            continue
        if cmd == "PING":
            reply("PONG")
            continue
        if cmd in ("get", "getnext"):
            oidline = inp.readline()
            try:
                oid = parse_oid(oidline)
            except ValueError:
                reply("NONE")
                continue
            res = store.get(oid) if cmd == "get" else store.getnext(oid)
            if res is None:
                reply("NONE")
                continue
            o, (typ, val) = res
            t, v = fmt(typ, val)
            reply("." + ds.oidstr(o), t, v)
            continue
        if cmd == "set":
            oidline = inp.readline()
            valline = inp.readline()
            try:
                oid = parse_oid(oidline)
                typeword, _, raw = valline.rstrip("\n").partition(" ")
                reply(store.set(oid, typeword.strip().lower(), raw))
            except Exception:  # noqa: BLE001 - must never die
                reply("gen-error")
            continue
        # unknown command
        reply("NONE")


if __name__ == "__main__":
    main()
