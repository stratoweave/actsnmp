#!/usr/bin/env python3
"""Independent SNMP manager for interop testing, based on pysnmp (lextudio, 7.x).

Command line deliberately mimics the net-snmp tools:

  pysnmp_client.py [options] get      AGENT OID...
  pysnmp_client.py [options] getnext  AGENT OID...
  pysnmp_client.py [options] getbulk  AGENT OID...          (-Cn N -Cr M)
  pysnmp_client.py [options] walk     AGENT [ROOT]          (GETNEXT based)
  pysnmp_client.py [options] bulkwalk AGENT [ROOT]          (GETBULK based, -Cr M)
  pysnmp_client.py [options] set      AGENT OID TYPE VALUE [OID TYPE VALUE ...]

AGENT:   [udp:|udp6:]HOST[:PORT]   e.g. 127.0.0.1:16161, [::1]:16161, udp6:[::1]:16162
options: -v 1|2c|3   -c COMMUNITY   -t TIMEOUT(s)   -r RETRIES
         -u USER -l noAuthNoPriv|authNoPriv|authPriv -a AUTH -A AUTHPASS
         -x PRIV -X PRIVPASS -n CONTEXT -E CONTEXTENGINEID(hex) -e SECENGINEID(hex)
         -Cn NONREPEATERS -Cr MAXREPETITIONS
AUTH:    MD5 | SHA | SHA-224 | SHA-256 | SHA-384 | SHA-512
PRIV:    net-snmp names: DES | AES | AES-192 | AES-256 | AES-192-C | AES-256-C
         plus 3DES (pysnmp only).  AES-192/AES-256 use the Blumenthal key
         extension (pysnmp "AES192BLMT"), the -C variants the Reeder/"Cisco"
         one (pysnmp "AES192").  pysnmp names AES192BLMT/AES256BLMT are accepted.
SET TYPE: i INTEGER, u|g Gauge32/Unsigned32, c Counter32, C Counter64, t TimeTicks,
          a IpAddress, o OID, s STRING, x hex STRING, d decimal STRING, n NULL,
          q Opaque (hex)

OUTPUT (stdout), one line per varbind, "canonical" format (see interop/README.md):
  .1.3.6.1.2.1.1.5.0 = STRING: "name"
Errors: an SNMP error-status prints
  ERROR: <errorStatusName>(<code>) index=<errorIndex> oid=<oid>
on stdout and exits 1.  Timeouts/transport problems print to stderr and exit 1.
Walk problems ("OID not increasing") print to stderr and exit 1.
Usage errors exit 2.
"""
import asyncio
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    next_cmd,
    set_cmd,
    usm3DESEDEPrivProtocol,
    usmAesBlumenthalCfb192Protocol,
    usmAesBlumenthalCfb256Protocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto import rfc1902
from pyasn1.type import univ

AUTH = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA1": usmHMACSHAAuthProtocol,
    "SHA-1": usmHMACSHAAuthProtocol,
    "SHA-224": usmHMAC128SHA224AuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA-256": usmHMAC192SHA256AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA-384": usmHMAC256SHA384AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA-512": usmHMAC384SHA512AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}

PRIV = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
    "AES-128": usmAesCfb128Protocol,
    # Blumenthal key extension (net-snmp "AES-192"/"AES-256")
    "AES-192": usmAesBlumenthalCfb192Protocol,
    "AES192": usmAesBlumenthalCfb192Protocol,
    "AES192BLMT": usmAesBlumenthalCfb192Protocol,
    "AES-256": usmAesBlumenthalCfb256Protocol,
    "AES256": usmAesBlumenthalCfb256Protocol,
    "AES256BLMT": usmAesBlumenthalCfb256Protocol,
    # Reeder ("Cisco") key extension (net-snmp "AES-192-C"/"AES-256-C")
    "AES-192-C": usmAesCfb192Protocol,
    "AES192C": usmAesCfb192Protocol,
    "AES-256-C": usmAesCfb256Protocol,
    "AES256C": usmAesCfb256Protocol,
}

ERROR_STATUS = {
    0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly",
    5: "genErr", 6: "noAccess", 7: "wrongType", 8: "wrongLength",
    9: "wrongEncoding", 10: "wrongValue", 11: "noCreation",
    12: "inconsistentValue", 13: "resourceUnavailable", 14: "commitFailed",
    15: "undoFailed", 16: "authorizationError", 17: "notWritable",
    18: "inconsistentName",
}


class UsageError(Exception):
    pass


# ------------------------------------------------------------ formatting ---

def fmt_oid(oid):
    return "." + ".".join(str(x) for x in oid)


def fmt_hex(b):
    return " ".join("%02X" % x for x in b)


def fmt_octets(b):
    if all(0x20 <= x <= 0x7E for x in b):
        s = b.decode("ascii").replace("\\", "\\\\").replace('"', '\\"')
        return 'STRING: "%s"' % s
    return "Hex-STRING: " + fmt_hex(b)


def tag_of(value):
    """(tagClass|tagFormat|tagId) first byte as int, e.g. 0x02, 0x41, 0x80"""
    t = value.tagSet[0]
    return t.tagClass | t.tagFormat | t.tagId


def fmt_value(value):
    tag = tag_of(value)
    if tag == 0x02:
        return "INTEGER: %d" % int(value)
    if tag == 0x04:
        return fmt_octets(bytes(value.asOctets()))
    if tag == 0x05:
        return "NULL"
    if tag == 0x06:
        return "OID: " + fmt_oid(tuple(value))
    if tag == 0x40:
        b = bytes(value.asOctets())
        if len(b) == 4:
            return "IpAddress: %d.%d.%d.%d" % tuple(b)
        return "IpAddress: Hex: " + fmt_hex(b)
    if tag == 0x41:
        return "Counter32: %d" % int(value)
    if tag == 0x42:
        return "Gauge32: %d" % int(value)
    if tag == 0x43:
        return "Timeticks: %d" % int(value)
    if tag == 0x44:
        b = bytes(value.asOctets())
        return "Opaque: " + (fmt_hex(b) if b else '""')
    if tag == 0x46:
        return "Counter64: %d" % int(value)
    if tag == 0x47:
        return "UInteger32: %d" % int(value)
    if tag == 0x80:
        return "noSuchObject"
    if tag == 0x81:
        return "noSuchInstance"
    if tag == 0x82:
        return "endOfMibView"
    return "UNKNOWN(tag 0x%02x): %r" % (tag, value)


def vb_oid(name):
    for attr in ("get_oid", "getOid"):
        if hasattr(name, attr):
            try:
                return tuple(getattr(name, attr)())
            except Exception:  # noqa: BLE001
                pass
    return tuple(name)


def print_vb(name, value):
    sys.stdout.write("%s = %s\n" % (fmt_oid(vb_oid(name)), fmt_value(value)))


# --------------------------------------------------------------- parsing ---

def parse_oid(s):
    s = s.strip()
    if s.startswith("."):
        s = s[1:]
    try:
        return tuple(int(x) for x in s.split("."))
    except ValueError:
        raise UsageError("bad OID %r (only numeric OIDs are supported)" % s)


def parse_agent(spec):
    v6 = False
    if spec.startswith("udp6:"):
        v6, spec = True, spec[5:]
    elif spec.startswith("udp:"):
        spec = spec[4:]
    port = 161
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        v6 = True
        if rest.startswith(":"):
            port = int(rest[1:])
    elif spec.count(":") == 1:
        host, p = spec.split(":")
        port = int(p)
    elif spec.count(":") > 1:
        host, v6 = spec, True
    else:
        host = spec
    return host, port, v6


def parse_set_value(t, v):
    if t == "i":
        return rfc1902.Integer32(int(v))
    if t in ("u", "g"):
        return rfc1902.Gauge32(int(v))
    if t == "c":
        return rfc1902.Counter32(int(v))
    if t == "C":
        return rfc1902.Counter64(int(v))
    if t == "t":
        return rfc1902.TimeTicks(int(v))
    if t == "a":
        return rfc1902.IpAddress(v)
    if t == "o":
        return rfc1902.ObjectIdentifier(parse_oid(v))
    if t == "s":
        return rfc1902.OctetString(v.encode("utf-8"))
    if t == "x":
        return rfc1902.OctetString(hexValue=v.replace(" ", "").replace(":", ""))
    if t == "d":
        return rfc1902.OctetString(bytes(int(x) for x in v.replace(".", " ").split()))
    if t == "n":
        return univ.Null("")
    if t == "q":
        return rfc1902.Opaque(hexValue=v.replace(" ", ""))
    raise UsageError("unknown SET type %r" % t)


def parse_args(argv):
    # split glued net-snmp style options: -Cr25 -> -Cr 25, -v2c -> -v 2c
    expanded = []
    for a in argv:
        if a.startswith("-C") and len(a) > 3 and a[2] in "nr":
            expanded += [a[:3], a[3:]]
        elif len(a) > 2 and a[0] == "-" and a[1] in "vcutlaAxXnEer" and a[1] != "-":
            expanded += [a[:2], a[2:]]
        else:
            expanded.append(a)
    o = {"version": "2c", "community": "public", "timeout": 2.0, "retries": 1,
         "user": None, "level": None, "auth": None, "authpass": None,
         "priv": None, "privpass": None, "context": "", "ctxengine": None,
         "secengine": None, "nonrep": 0, "maxrep": 10}
    flags = {"-v": "version", "-c": "community", "-t": "timeout", "-r": "retries",
             "-u": "user", "-l": "level", "-a": "auth", "-A": "authpass",
             "-x": "priv", "-X": "privpass", "-n": "context", "-E": "ctxengine",
             "-e": "secengine", "-Cn": "nonrep", "-Cr": "maxrep"}
    pos = []
    i = 0
    while i < len(expanded):
        a = expanded[i]
        if a in ("-h", "--help"):
            sys.stdout.write(__doc__)
            sys.exit(0)
        if a in flags:
            if i + 1 >= len(expanded):
                raise UsageError("option %s needs a value" % a)
            o[flags[a]] = expanded[i + 1]
            i += 2
            continue
        if a.startswith("-") and len(a) > 1 and not a[1].isdigit():
            raise UsageError("unknown option %s" % a)
        pos.append(a)
        i += 1
    o["timeout"] = float(o["timeout"])
    o["retries"] = int(o["retries"])
    o["nonrep"] = int(o["nonrep"])
    o["maxrep"] = int(o["maxrep"])
    if len(pos) < 2:
        raise UsageError("need OPERATION and AGENT")
    return o, pos[0], pos[1], pos[2:]


def auth_data(o):
    v = o["version"]
    if v == "1":
        return CommunityData(o["community"], mpModel=0)
    if v == "2c":
        return CommunityData(o["community"], mpModel=1)
    if v != "3":
        raise UsageError("bad version %r" % v)
    if not o["user"]:
        raise UsageError("-u USER required for -v 3")
    level = o["level"] or "noAuthNoPriv"
    kw = {}
    if o["secengine"]:
        kw["securityEngineId"] = univ.OctetString(hexValue=o["secengine"].replace("0x", ""))
    if level.lower() in ("authnopriv", "authpriv"):
        a = (o["auth"] or "MD5").upper()
        if a not in AUTH:
            raise UsageError("unknown auth protocol %r" % o["auth"])
        if not o["authpass"]:
            raise UsageError("-A AUTHPASS required")
        kw["authKey"] = o["authpass"]
        kw["authProtocol"] = AUTH[a]
    if level.lower() == "authpriv":
        p = (o["priv"] or "DES").upper()
        if p not in PRIV:
            raise UsageError("unknown priv protocol %r" % o["priv"])
        if not o["privpass"]:
            raise UsageError("-X PRIVPASS required")
        kw["privKey"] = o["privpass"]
        kw["privProtocol"] = PRIV[p]
    elif level.lower() not in ("noauthnopriv", "authnopriv"):
        raise UsageError("bad security level %r" % level)
    return UsmUserData(o["user"], **kw)


def context_data(o):
    kw = {"contextName": o["context"].encode()}
    if o["ctxengine"]:
        kw["contextEngineId"] = univ.OctetString(hexValue=o["ctxengine"].replace("0x", ""))
    return ContextData(**kw)


# ------------------------------------------------------------- operation ---

class SnmpFailure(Exception):
    pass


def check(res, agent):
    err_ind, err_stat, err_idx, vbs = res
    if err_ind:
        msg = str(err_ind)
        if "timeout" in msg.lower() or "no snmp response" in msg.lower():
            raise SnmpFailure("Timeout: No Response from %s." % agent)
        raise SnmpFailure("Error: %s" % msg)
    if int(err_stat):
        code = int(err_stat)
        idx = int(err_idx)
        oid = ""
        if 1 <= idx <= len(vbs):
            oid = fmt_oid(vb_oid(vbs[idx - 1][0]))
        sys.stdout.write("ERROR: %s(%d) index=%d oid=%s\n"
                         % (ERROR_STATUS.get(code, "unknown"), code, idx, oid))
        sys.stdout.flush()
        sys.exit(1)
    return vbs


def in_subtree(root, oid):
    return len(oid) > len(root) and oid[:len(root)] == root


async def run(o, op, agent, args):
    host, port, v6 = parse_agent(agent)
    tcls = Udp6TransportTarget if v6 else UdpTransportTarget
    target = await tcls.create((host, port), timeout=o["timeout"], retries=o["retries"])
    eng = SnmpEngine()
    auth = auth_data(o)
    ctx = context_data(o)
    agent_s = agent

    def obj(oid):
        return ObjectType(ObjectIdentity(univ.ObjectIdentifier(oid)))

    try:
        if op in ("get", "getnext", "getbulk"):
            if not args:
                raise UsageError("need at least one OID")
            objs = [obj(parse_oid(a)) for a in args]
            if op == "get":
                res = await get_cmd(eng, auth, target, ctx, *objs, lookupMib=False)
            elif op == "getnext":
                res = await next_cmd(eng, auth, target, ctx, *objs, lookupMib=False)
            else:
                res = await bulk_cmd(eng, auth, target, ctx, o["nonrep"], o["maxrep"],
                                     *objs, lookupMib=False)
            for name, val in check(res, agent_s):
                print_vb(name, val)
            return 0

        if op == "set":
            if not args or len(args) % 3:
                raise UsageError("set needs OID TYPE VALUE triples")
            objs = []
            for i in range(0, len(args), 3):
                objs.append(ObjectType(ObjectIdentity(univ.ObjectIdentifier(parse_oid(args[i]))),
                                       parse_set_value(args[i + 1], args[i + 2])))
            res = await set_cmd(eng, auth, target, ctx, *objs, lookupMib=False)
            for name, val in check(res, agent_s):
                print_vb(name, val)
            return 0

        if op in ("walk", "bulkwalk"):
            root = parse_oid(args[0]) if args else (1, 3, 6, 1, 2, 1)
            if op == "bulkwalk" and o["version"] == "1":
                raise UsageError("bulkwalk needs SNMPv2c or SNMPv3")
            cur = root
            count = 0
            while True:
                if op == "walk":
                    res = await next_cmd(eng, auth, target, ctx, obj(cur), lookupMib=False)
                    err_ind, err_stat, _err_idx, _vbs = res
                    if not err_ind and int(err_stat) == 2 and o["version"] == "1":
                        break  # noSuchName = end of MIB view in SNMPv1
                else:
                    res = await bulk_cmd(eng, auth, target, ctx, 0, o["maxrep"], obj(cur),
                                         lookupMib=False)
                vbs = check(res, agent_s)
                if not vbs:
                    break
                done = False
                for name, val in vbs:
                    oid = vb_oid(name)
                    if tag_of(val) == 0x82:  # endOfMibView
                        done = True
                        break
                    if not in_subtree(root, oid):
                        done = True
                        break
                    if oid <= cur:
                        sys.stdout.flush()
                        sys.stderr.write("Error: OID not increasing: %s >= %s\n"
                                         % (fmt_oid(cur), fmt_oid(oid)))
                        return 1
                    print_vb(name, val)
                    count += 1
                    cur = oid
                if done:
                    break
            return 0

        raise UsageError("unknown operation %r" % op)
    finally:
        try:
            eng.close_dispatcher()
        except Exception:  # noqa: BLE001
            pass


def main(argv):
    try:
        o, op, agent, args = parse_args(argv)
        rc = asyncio.run(run(o, op, agent, args))
    except UsageError as e:
        sys.stderr.write("usage error: %s\n(see --help)\n" % e)
        return 2
    except SnmpFailure as e:
        sys.stdout.flush()
        sys.stderr.write("%s\n" % e)
        return 1
    sys.stdout.flush()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
