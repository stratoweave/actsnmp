#!/usr/bin/env python3
"""Convert the log of the lab's snmptrapd instances to canonical NOTIFICATION
blocks (the format "actsnmp trapd --canon" prints):

  NOTIFICATION v1 TRAP community="public" enterprise=.1.3.6.1.4.1.8072.9999 agent=192.0.2.1 generic=6 specific=42 uptime=12345 trapoid=.1.3.6.1.4.1.8072.9999.0.42
  .1.3.6.1.4.1.8072.9999.1.1.1.0 = INTEGER: 0
  END
  NOTIFICATION v2c TRAP2 community="public" uptime=0 trapoid=.1.3.6.1.6.3.1.1.5.1
  END
  NOTIFICATION v3 INFORM user="u_sha_aes" level=authPriv context="" uptime=1 trapoid=...
  ...

Input: snmptrapd output produced with the format1/format2 lines of
config/snmptrapd.conf / config/snmptrapd-standin.conf (one tab separated line
per notification, -On -Oe -Ox, hexOutputLength 0), e.g.

  docker logs actsnmp-snmptrapd 2>&1 | snmptrapd2canon.py

* v1: trapoid is derived as in RFC 3584 section 3.1 (generic 0..5 ->
  1.3.6.1.6.3.1.1.5.<generic+1>, enterpriseSpecific -> <enterprise>.0.<specific>);
  the payload is the original v1 varbinds.
* v2c/v3: uptime and trapoid come from the first two varbinds (sysUpTime.0,
  snmpTrapOID.0), which are not repeated in the payload.
* v3: snmptrapd cannot log the security level, it is taken from users.tsv.
  The lab snmptrapd configs accept every user only at exactly its configured
  level (authUser minimum level), so this is exact.
* Varbinds use the canonical varbind format (tools/netsnmp2canon.py).

Other lines (startup messages, ...) are ignored.  Exit status 1 if a
notification line could not be converted completely (the block then
contains "UNPARSED: ..." lines).

usage: snmptrapd2canon.py [--users USERS.TSV] [LOGFILE]
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import netsnmp2canon as n2c  # noqa: E402

SYS_UPTIME = ".1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = ".1.3.6.1.6.3.1.1.4.1.0"
SEC = re.compile(r"^(\S+), SNMP (v1|v2c|v3), (?:community (.*)|user (.*), context (.*))$")


def default_users_file():
    for p in ("/opt/actsnmp/config/users.tsv", os.path.join(HERE, "..", "config", "users.tsv")):
        if os.path.exists(p):
            return p
    return None


def load_levels(path):
    levels = {}
    if path:
        with open(path) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                c = line.rstrip("\n").split("\t")
                levels[c[0]] = c[1]
    return levels


def quote(s):
    """canonical STRING quoting"""
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def v1_trapoid(enterprise, generic, specific):
    if 0 <= generic <= 5:
        return ".1.3.6.1.6.3.1.1.5.%d" % (generic + 1)
    return "%s.0.%d" % (enterprise, specific)


def convert_varbinds(fields):
    out, ok = [], True
    for vb in fields:
        if not vb.strip():
            continue
        try:
            c = n2c.convert_line(vb)
        except ValueError:
            c = None
        if c is None:
            out.append("UNPARSED: " + vb)
            ok = False
        else:
            out.append(c)
    return out, ok


def convert_line(line, levels):
    """one snmptrapd log line -> (block lines or None if not a notification, ok)"""
    f = line.rstrip("\n").split("\t")
    if f[0] not in ("TRAP1", "TRAP2") or len(f) < 3:
        return None, True
    m = SEC.match(f[2])
    if not m:
        return ["NOTIFICATION ?", "UNPARSED: " + line.rstrip("\n"), "END"], False
    pdu, ver, community, user, context = m.groups()
    if ver == "v3":
        sec = "user=%s level=%s context=%s" % (quote(user), levels.get(user, "unknown"),
                                               quote(context))
        ok = user in levels
    else:
        sec = "community=%s" % quote(community)
        ok = True
    if f[0] == "TRAP1":
        kv = {}
        for item in f[3:8]:
            k, _, v = item.partition("=")
            kv[k] = v
        try:
            ent = kv["enterprise"]
            if not ent.startswith("."):
                ent = "." + ent
            gen = int(kv["generic"])
            spec = int(kv["specific"].lstrip("."))
            upt = int(kv["uptime"])
        except (KeyError, ValueError):
            return ["NOTIFICATION ?", "UNPARSED: " + line.rstrip("\n"), "END"], False
        head = ("NOTIFICATION %s %s %s enterprise=%s agent=%s generic=%d specific=%d uptime=%d trapoid=%s"
                % (ver, pdu, sec, ent, kv.get("agent", "?"), gen, spec, upt,
                   v1_trapoid(ent, gen, spec)))
        vbs, ok2 = convert_varbinds(f[8:])
        return [head] + vbs + ["END"], ok and ok2
    vbs, ok2 = convert_varbinds(f[3:])
    upt, trapoid = "?", "?"
    if len(vbs) >= 2 and vbs[0].startswith(SYS_UPTIME + " = Timeticks: ") \
            and vbs[1].startswith(SNMP_TRAP_OID + " = OID: "):
        upt = vbs[0].split(": ", 1)[1]
        trapoid = vbs[1].split(": ", 1)[1]
        vbs = vbs[2:]
    else:
        ok2 = False
    head = "NOTIFICATION %s %s %s uptime=%s trapoid=%s" % (ver, pdu, sec, upt, trapoid)
    return [head] + vbs + ["END"], ok and ok2


def convert(lines, levels):
    """iterable of log lines -> (canonical lines, all_ok)"""
    out, all_ok = [], True
    for line in lines:
        block, ok = convert_line(line, levels)
        if block is not None:
            out += block
            all_ok = all_ok and ok
    return out, all_ok


def main(argv):
    users = default_users_file()
    args = list(argv)
    if "--users" in args:
        i = args.index("--users")
        users = args[i + 1]
        del args[i:i + 2]
    if args and args[0] in ("-h", "--help"):
        sys.stdout.write(__doc__)
        return 0
    src = open(args[0], errors="replace") if args else sys.stdin
    out, ok = convert(src, load_levels(users))
    sys.stdout.write("".join(line + "\n" for line in out))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
