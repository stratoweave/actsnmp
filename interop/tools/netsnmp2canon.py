#!/usr/bin/env python3
"""Convert net-snmp tool output to the actsnmp *canonical* varbind format.

Input must be produced with -On -Oe -Ox --hexOutputLength=0 (numeric OIDs,
numeric enums, every OCTET STRING as unwrapped hex). Do not add -Ot, which
drops the Timeticks type label. Example:

  snmpbulkwalk -v2c -c public -On -Oe -Ox --hexOutputLength=0 127.0.0.1:16161 \\
      .1.3.6.1.4.1.8072.9999.1 | netsnmp2canon.py

Canonical format (one varbind per line, also printed by pysnmp_client.py):

  <.numeric.oid> = INTEGER: <signed decimal>
                 = STRING: "<text>"          bytes all in 0x20..0x7E, '"' and
                                             '\\' backslash-escaped; also ""
                 = Hex-STRING: 00 0A FF       any other OCTET STRING (uppercase,
                                             single spaces, no trailing space)
                 = OID: .1.3.6.1
                 = IpAddress: 192.0.2.1
                 = Counter32: <n> | Gauge32: <n> | Timeticks: <n> | Counter64: <n>
                 = Opaque: DE AD BE EF        raw Opaque content as hex
                 = NULL | noSuchObject | noSuchInstance | endOfMibView

net-snmp decodes "special" Opaque values (Float/Double/Int64/UInt64 wrapped
in 0x9f 0x78..0x7b); they are re-encoded here to their raw bytes.  That is
exact for the lab dataset (Float 1.0, Int64 42) but net-snmp prints floats
with %f so arbitrary floats may not round-trip.

Lines that are not varbinds (errors, "End of MIB", ...) are passed through
prefixed with "# ".  Exit status 1 if any varbind line could not be parsed.
"""
import re
import struct
import sys

LINE = re.compile(r"^(\.?[0-9]+(?:\.[0-9]+)*) = (.*)$")


def fmt_hex(b):
    return " ".join("%02X" % x for x in b)


def fmt_octets(b):
    if all(0x20 <= x <= 0x7E for x in b):
        s = b.decode("ascii").replace("\\", "\\\\").replace('"', '\\"')
        return 'STRING: "%s"' % s
    return "Hex-STRING: " + fmt_hex(b)


def parse_hex(s):
    s = s.strip()
    return bytes(int(x, 16) for x in s.split()) if s else b""


def unescape_netsnmp_string(s):
    # net-snmp escapes only '"' and '\\' inside STRING: "..."
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "\"\\":
            out.append(s[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out).encode("latin-1")


def ber_int(n, unsigned=False):
    if n == 0:
        return b"\x00"
    if unsigned:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b
    length = (n + (n < 0)).bit_length() // 8 + 1
    return n.to_bytes(length, "big", signed=True)


def opaque_special(kind, val):
    if kind == "Float":
        body = struct.pack(">f", float(val))
        return bytes([0x9F, 0x78, len(body)]) + body
    if kind == "Double":
        body = struct.pack(">d", float(val))
        return bytes([0x9F, 0x79, len(body)]) + body
    if kind == "Int64":
        body = ber_int(int(val))
        return bytes([0x9F, 0x7A, len(body)]) + body
    if kind == "UInt64":
        body = ber_int(int(val), unsigned=True)
        return bytes([0x9F, 0x7B, len(body)]) + body
    raise ValueError(kind)


SIMPLE = re.compile(r"^(INTEGER|Counter32|Gauge32|Counter64|UInteger32): (-?[0-9]+)$")


def convert_value(v):
    v = v.rstrip("\n")
    m = SIMPLE.match(v)
    if m:
        return "%s: %s" % (m.group(1), m.group(2))
    if v.startswith("INTEGER: "):
        # enum label left in (no -Oe): "up(1)"
        m = re.match(r"^INTEGER: .*\((-?[0-9]+)\)$", v)
        if m:
            return "INTEGER: " + m.group(1)
    if v.startswith("Hex-STRING:"):
        return fmt_octets(parse_hex(v[len("Hex-STRING:"):]))
    if v == '""':
        return 'STRING: ""'
    if v.startswith('STRING: "') and v.endswith('"'):
        return fmt_octets(unescape_netsnmp_string(v[len('STRING: "'):-1]))
    if v.startswith("OID: "):
        o = v[5:].strip()
        return "OID: " + (o if o.startswith(".") else "." + o)
    if v.startswith("IpAddress: "):
        return "IpAddress: " + v[len("IpAddress: "):].strip()
    m = re.match(r"^Timeticks: \(([0-9]+)\)", v)
    if m:
        return "Timeticks: " + m.group(1)
    if v.startswith("OPAQUE:"):
        b = parse_hex(v[len("OPAQUE:"):])
        return "Opaque: " + (fmt_hex(b) if b else '""')
    m = re.match(r"^Opaque: (Float|Double|Int64|UInt64): (.*)$", v)
    if m:
        return "Opaque: " + fmt_hex(opaque_special(m.group(1), m.group(2).strip()))
    if v == "NULL":
        return "NULL"
    if v.startswith("No Such Object available"):
        return "noSuchObject"
    if v.startswith("No Such Instance currently exists"):
        return "noSuchInstance"
    if v.startswith("No more variables left in this MIB View"):
        return "endOfMibView"
    raise ValueError(v)


def convert_line(line):
    m = LINE.match(line.rstrip("\n"))
    if not m:
        return None
    oid = m.group(1)
    if not oid.startswith("."):
        oid = "." + oid
    val = convert_value(m.group(2))
    if val in ("NULL", "noSuchObject", "noSuchInstance", "endOfMibView"):
        return "%s = %s" % (oid, val)
    return "%s = %s" % (oid, val)


def main():
    rc = 0
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    for line in src:
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            out = convert_line(line)
        except ValueError:
            sys.stdout.write("UNPARSED: %s\n" % line)
            rc = 1
            continue
        if out is None:
            sys.stdout.write("# %s\n" % line)
        else:
            sys.stdout.write(out + "\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
