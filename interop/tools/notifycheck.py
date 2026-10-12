#!/usr/bin/env python3
"""Notification interop matrix of the actsnmp lab (runs inside the interop
image, normally via interop/notifycheck.sh or interop/trapdcheck.sh).

A fixed, deterministic list of notifications, each sent by net-snmp
(snmptrap / snmpinform) and by pysnmp (pysnmp_notify.py), covering

  * SNMPv1 traps: every generic-trap 0..5 and enterpriseSpecific (incl. the
    canonical-format example with specific-trap 42, and 2147483647),
    agent-addr variations
  * SNMPv2c traps and informs (with and without payload)
  * SNMPv3 traps and informs: noAuthNoPriv, authNoPriv with every auth
    protocol, authPriv with every priv protocol (DES, AES, AES-192/256 with
    both key extensions, paired with short auth keys where they differ)
  * payload values of every type of the lab dataset (INTEGER extremes,
    empty/binary/UTF-8/printable OCTET STRING, OIDs incl. 128 sub-ids and
    max sub-id, IpAddress, Counter32, Gauge32, TimeTicks, Counter64 max,
    Opaque raw/Float/Int64)

with fixed explicit uptimes, so the receiver output is deterministic.

usage: notifycheck.py [--quick|--all-users] [--receiver ADDRESS] [--senders netsnmp,pysnmp] ACTION
  --quick       small subset (22 notifications instead of 86)
  --all-users   the full matrix, but the v3 traps/informs for every user of
                config/users.tsv that net-snmp supports (43; no 3DES) - 198 notifications
  --receiver    a net-snmp agent address (default 127.0.0.1:16165); over TCP
                (tcp:127.0.0.1:16165) only net-snmp sends (the lab's pysnmp tools speak UDP only)
ACTION:
  --expected   print the canonical blocks the receiver must print, in send order
  --send       send the matrix to the receiver; exit 1 if a send failed
               (trap: tool error; inform: not acknowledged)
  --commands   print the net-snmp-syntax argument line of every notification of the
               chosen senders, shell quoted: "trap|inform ARGS..." (for other CLIs)
  --selftest   start net-snmp snmptrapd as a stand-in receiver on the receiver port
               (config/snmptrapd-standin.conf), send the matrix, convert its log with
               snmptrapd2canon.py and compare with --expected
"""
import difflib
import os
import shlex
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, "/opt/actsnmp/dataset")
sys.path.insert(0, "/opt/actsnmp/tools")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "dataset"))
sys.path.insert(0, HERE)
import actsnmp_dataset as ds  # noqa: E402
import snmptrapd2canon as t2c  # noqa: E402

PYNOTIFY = ["/opt/venv/bin/python3", "/opt/actsnmp/pysnmp_notify.py"]
# the container's config, else the repo's interop/config (host-side --commands/--expected)
CONFIG = "/opt/actsnmp/config"
if not os.path.isdir(CONFIG):
    CONFIG = os.path.join(HERE, "..", "config")
AUTHPASS = "authpass123"
PRIVPASS = "privpass123"
# fixed authoritative engine IDs of the v3 TRAP senders (snmptrapd has users
# for both, see tools/gen_config.py); actsnmp uses the first one when it sends
# v3 traps to the lab snmptrapd.
TRAP_ENGINE = {"netsnmp": "0x8000000001020304", "pysnmp": "0x8000000001020305"}
# inform options: a generous timeout and no retries (a retransmission would
# show up as a duplicate notification at the receiver)
INFORM_OPTS = ["-r", "0", "-t", "5"]
SENDERS = ["netsnmp", "pysnmp"]
# net-snmp's transport prefixes of an agent address; pysnmp_notify.py sends over UDP only
DOMAINS = ("udp", "udp6", "udpv6", "udpipv6", "tcp", "tcp6", "tcpv6", "tcpipv6")

E = (1, 3, 6, 1, 4, 1, 8072, 9999)          # netSnmpPlaypen
N = E + (3,)                                # notification OIDs: N.0.<k>
B = ds.BASE
DATA = {oid: (typ, val) for oid, typ, val in ds.records()}


def b(*sub):
    return B + sub


# ---------------------------------------------------------------- payload ---

FULL = [b(1, 18, 0), b(1, 19, 0), b(1, 7, 0),                    # INTEGER max/min/-129
        b(2, 1, 0), b(2, 2, 0), b(2, 3, 0), b(2, 4, 0),           # STRING, empty, 00..FF, UTF-8
        b(2, 5, 0), b(2, 6, 0), b(2, 16, 0),                      # quote/backslash, tab/newline, spaces
        b(3, 1, 0), b(3, 3, 0), b(3, 4, 0), b(3, 7, 0),           # OID 0.0, max sub-id, 2.999.1, 128 sub-ids
        b(4, 1, 0), b(4, 4, 0),                                   # IpAddress 0.0.0.0 / 255.255.255.255
        b(5, 4, 0), b(5, 5, 0), b(6, 4, 0),                       # Counter32 2^31 / max, Gauge32 max
        b(7, 3, 0), b(7, 4, 0),                                   # TimeTicks 8640000 / max
        b(8, 1, 0), b(8, 7, 0),                                   # Counter64 0 / max
        b(9, 1, 0), b(9, 2, 0), b(9, 3, 0)]                       # Opaque raw / Float 1.0 / Int64 42
V1FULL = [o for o in FULL if DATA[o][0] != "COUNTER64"]          # SNMPv1 has no Counter64


def float_opaque(val):
    """(letter, text) when val is a net-snmp special Opaque we can express as
    snmptrap F/I arguments, else None"""
    if len(val) == 7 and val[:3] == b"\x9f\x78\x04":
        f = struct.unpack(">f", val[3:])[0]
        if struct.pack(">f", float(repr(f))) == val[3:]:
            return "F", repr(f)
    if len(val) >= 4 and val[:2] == b"\x9f\x7a" and val[2] == len(val) - 3:
        n = int.from_bytes(val[3:], "big", signed=True)
        if n.to_bytes((n + (n < 0)).bit_length() // 8 + 1, "big", signed=True) == val[3:]:
            return "I", str(n)
    return None


def type_arg(typ, val, sender):
    """dataset value -> (net-snmp type letter, value text), None if the sender
    cannot send it"""
    if typ == "INTEGER":
        return "i", str(val)
    if typ == "OCTETS":
        if all(0x20 <= x <= 0x7E for x in val):
            return "s", val.decode("ascii")
        return "x", val.hex()
    if typ == "OID":
        return "o", "." + ds.oidstr(val)
    if typ == "IPADDR":
        return "a", "%d.%d.%d.%d" % tuple(val)
    if typ == "COUNTER32":
        return "c", str(val)
    if typ == "GAUGE32":
        return "u", str(val)
    if typ == "TIMETICKS":
        return "t", str(val)
    if typ == "COUNTER64":
        return "C", str(val)
    if typ == "OPAQUE":
        sp = float_opaque(val)
        if sp:
            return sp
        if sender == "pysnmp":
            return "q", val.hex()
        return None  # net-snmp tools cannot send a raw Opaque
    raise ValueError(typ)


# ------------------------------------------------------------------ users ---

def load_users():
    users = {}
    with open(os.path.join(CONFIG, "users.tsv")) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            c = line.rstrip("\n").split("\t")
            users[c[0]] = dict(name=c[0], level=c[1], auth=c[2], priv=c[3])
    return users


def v3_args(u):
    a = ["-v3", "-l", u["level"], "-u", u["name"]]
    if u["level"] in ("authNoPriv", "authPriv"):
        a += ["-a", u["auth"], "-A", AUTHPASS]
    if u["level"] == "authPriv":
        a += ["-x", u["priv"], "-X", PRIVPASS]
    return a


# --------------------------------------------------------------- the matrix ---

def quote(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


class Note:
    def __init__(self, sender, version, mode, uptime, payload, community="public", user=None,
                 enterprise=None, agent=None, generic=None, specific=None, trapoid=None):
        self.sender, self.version, self.mode = sender, version, mode
        self.uptime, self.community, self.user = uptime, community, user
        self.enterprise, self.agent, self.generic, self.specific = enterprise, agent, generic, specific
        self.trapoid = trapoid
        # drop what this sender cannot send (raw Opaque with net-snmp)
        self.payload = [o for o in payload if type_arg(*DATA[o], sender) is not None]

    def args(self, receiver):
        """argument list in snmptrap/snmpinform syntax (without the tool name)"""
        if self.version == "3":
            a = v3_args(self.user)
            if self.mode == "trap":
                a += ["-e", TRAP_ENGINE[self.sender]]
        else:
            a = ["-v" + self.version, "-c", self.community]
        if self.mode == "inform":
            a += INFORM_OPTS
        a.append(receiver)
        if self.version == "1":
            a += ["." + ds.oidstr(self.enterprise), self.agent, str(self.generic),
                  str(self.specific), str(self.uptime)]
        else:
            a += [str(self.uptime), "." + ds.oidstr(self.trapoid)]
        for oid in self.payload:
            t, v = type_arg(*DATA[oid], self.sender)
            a += ["." + ds.oidstr(oid), t, v]
        return a

    def argv(self, receiver):
        if self.sender == "netsnmp":
            return [{"trap": "snmptrap", "inform": "snmpinform"}[self.mode]] + self.args(receiver)
        return PYNOTIFY + [self.mode] + self.args(receiver)

    def v1_trapoid(self):
        if self.generic < 6:
            return (1, 3, 6, 1, 6, 3, 1, 1, 5, self.generic + 1)
        return self.enterprise + (0, self.specific)

    def expected(self):
        if self.version == "1":
            head = ("NOTIFICATION v1 TRAP community=%s enterprise=.%s agent=%s generic=%d "
                    "specific=%d uptime=%d trapoid=.%s"
                    % (quote(self.community), ds.oidstr(self.enterprise), self.agent, self.generic,
                       self.specific, self.uptime, ds.oidstr(self.v1_trapoid())))
        else:
            pdu = "TRAP2" if self.mode == "trap" else "INFORM"
            if self.version == "3":
                sec = "user=%s level=%s context=%s" % (quote(self.user["name"]), self.user["level"],
                                                       quote(""))
            else:
                sec = "community=%s" % quote(self.community)
            head = "NOTIFICATION v%s %s %s uptime=%d trapoid=.%s" % (
                self.version, pdu, sec, self.uptime, ds.oidstr(self.trapoid))
        return [head] + [ds.canon_line(o, *DATA[o]) for o in self.payload] + ["END"]

    def label(self):
        who = self.user["name"] if self.user else "community %s" % self.community
        return "%-7s v%-2s %-6s %s" % (self.sender, self.version, self.mode, who)


# v3 users of the matrix: noAuthNoPriv, one per auth protocol, one per priv
# protocol (AES-192/256 in both key extension variants, each with an auth key
# shorter than the priv key so the extension algorithm matters; plus one with
# a long auth key)
V3_FULL = ["u_noauth",
           "u_md5", "u_sha", "u_sha224", "u_sha256", "u_sha384", "u_sha512",
           "u_md5_des", "u_sha_aes", "u_md5_aes192", "u_sha_aes192c", "u_sha_aes256",
           "u_md5_aes256c", "u_sha224_aes256", "u_sha512_aes256c"]
V3_TRAP_QUICK = ["u_noauth", "u_sha_aes", "u_md5_aes256c"]
V3_INFORM_QUICK = ["u_md5", "u_sha256_aes", "u_sha_aes192"]

GENERIC_V1 = [  # generic, agent-addr, uptime, payload
    (0, "192.0.2.1", 0, []),
    (1, "127.0.0.1", 1, [b(1, 2, 0)]),
    (2, "10.0.0.1", 100, [b(10, 1, 1, 7), b(10, 1, 2, 7)]),
    (3, "255.255.255.255", 8640000, [b(10, 1, 1, 7), b(10, 1, 2, 7), b(10, 1, 5, 7)]),
    (4, "0.0.0.0", 2147483648, [b(4, 3, 0)]),
    (5, "192.0.2.254", 4294967295, [b(4, 2, 0), b(5, 1, 0)]),
]


def all_v3_users(users):
    """every user net-snmp (and so the snmptrapd stand-in) supports"""
    return [n for n, u in users.items() if u["priv"] != "-" or u["level"] != "authPriv"
            if not n.startswith("u_ro_")]


def build_matrix(quick=False, senders=SENDERS, all_users=False):
    users = load_users()
    v3_full = all_v3_users(users) if all_users else V3_FULL
    M = []
    # 1. SNMPv1 traps
    for s in senders:
        # the v1 example of the canonical NOTIFICATION format (see snmptrapd2canon.py), verbatim
        M.append(Note(s, "1", "trap", 12345, [b(1, 1, 0)], enterprise=E, agent="192.0.2.1",
                      generic=6, specific=42))
        gens = GENERIC_V1 if not quick else [GENERIC_V1[3]]
        for g, agent, upt, payload in gens:
            M.append(Note(s, "1", "trap", upt, payload, enterprise=N, agent=agent,
                          generic=g, specific=0))
        if not quick:
            M.append(Note(s, "1", "trap", 4294967295, [b(2, 1, 0)], enterprise=N,
                          agent="198.51.100.7", generic=6, specific=2147483647))
        M.append(Note(s, "1", "trap", 123456789, V1FULL, enterprise=N, agent="203.0.113.9",
                      generic=6, specific=None))           # specific = k, set below
    # 2. SNMPv2c traps
    for s in senders:
        if not quick:
            M.append(Note(s, "2c", "trap", 0, [], trapoid=(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)))
        M.append(Note(s, "2c", "trap", 4294967295, FULL))
    # 3. SNMPv2c informs
    for s in senders:
        M.append(Note(s, "2c", "inform", 123, FULL))
        if not quick:
            M.append(Note(s, "2c", "inform", 1, []))
    # 4. SNMPv3 traps, 5. SNMPv3 informs
    for mode, qlist in (("trap", V3_TRAP_QUICK), ("inform", V3_INFORM_QUICK)):
        for s in senders:
            for i, name in enumerate(qlist if quick else v3_full):
                M.append(Note(s, "3", mode, 3000000 + 1000 * (mode == "inform") + i, FULL,
                              user=users[name]))
    # unique notification numbers: trapoid N.0.k / v1 specific k (k = position)
    for k, n in enumerate(M, start=1):
        if n.version == "1":
            if n.specific is None:
                n.specific = k
        elif n.trapoid is None:
            n.trapoid = N + (0, k)
    return M


# ----------------------------------------------------------------- actions ---

def expected_lines(M):
    out = []
    for n in M:
        out += n.expected()
    return out


def send_all(M, receiver):
    failed = 0
    t0 = time.time()
    for k, n in enumerate(M, start=1):
        argv = n.argv(receiver)
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=60, errors="replace")
            rc, msg = p.returncode, (p.stdout + p.stderr).strip()
        except subprocess.TimeoutExpired:
            rc, msg = 124, "TIMEOUT"
        ok = rc == 0
        failed += not ok
        what = "acknowledged" if n.mode == "inform" else "sent"
        sys.stderr.write("[%s] %3d %s %s%s\n" % ("PASS" if ok else "FAIL", k, n.label(),
                                                 what if ok else "rc=%d" % rc,
                                                 "" if not msg else ": " + msg.replace("\n", " | ")[:200]))
    sys.stderr.write("sent %d notifications in %.1fs, %d failed\n" % (len(M), time.time() - t0, failed))
    return failed == 0


def blocks(lines):
    """canonical lines -> one tuple of lines per NOTIFICATION ... END block"""
    out, cur = [], []
    for line in lines:
        cur.append(line)
        if line == "END":
            out.append(tuple(cur))
            cur = []
    return out


def transport_domain(receiver):
    """the transport prefix of a net-snmp agent address (udp, tcp6, ...), "" for none"""
    prefix = receiver.split(":", 1)[0].lower()
    return prefix if prefix in DOMAINS else ""


def selftest(M, receiver):
    """net-snmp snmptrapd as a stand-in for our receiver"""
    work = tempfile.mkdtemp(prefix="notifycheck-standin-")
    log = os.path.join(work, "snmptrapd.log")
    conf = os.path.join(CONFIG, "snmptrapd-standin.conf")
    listen = receiver if transport_domain(receiver) else "udp:" + receiver
    if listen != "udp:127.0.0.1:16165":
        # same configuration on another address or transport
        text = open(conf).read().replace("snmpTrapdAddr udp:127.0.0.1:16165",
                                         "snmpTrapdAddr %s" % listen)
        conf = os.path.join(work, "snmptrapd.conf")
        with open(conf, "w") as f:
            f.write(text)
    env = dict(os.environ, SNMP_PERSISTENT_DIR=os.path.join(work, "persist"))
    proc = subprocess.Popen(["snmptrapd", "-f", "-Lf", log, "-On", "-C", "-c", conf],
                            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    try:
        for _ in range(120):
            if os.path.exists(log) and "NET-SNMP version" in open(log, errors="replace").read():
                break
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        if proc.poll() is not None or not os.path.exists(log):
            sys.stderr.write("stand-in snmptrapd did not start:\n%s\n"
                             % (open(log).read() if os.path.exists(log) else ""))
            return False
        sys.stderr.write("stand-in snmptrapd (net-snmp) listening on %s\n" % listen)
        sent_ok = send_all(M, receiver)
        want = len(M)
        for _ in range(40):  # traps are asynchronous: wait until all arrived (max 10 s)
            n = sum(1 for line in open(log, errors="replace") if line.startswith(("TRAP1\t", "TRAP2\t")))
            if n >= want:
                break
            time.sleep(0.25)
        time.sleep(0.5)  # anything unexpected (duplicates) would show up now
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    with open(log, errors="replace") as f:
        raw = f.read().splitlines()
    got, conv_ok = t2c.convert(raw, t2c.load_levels(os.path.join(CONFIG, "users.tsv")))
    exp = expected_lines(M)
    if transport_domain(receiver).startswith("tcp"):
        # one connection per notification: the receiver may take them in any order
        same = sorted(blocks(got)) == sorted(blocks(exp))
    else:
        same = got == exp
    sys.stdout.write("".join(line + "\n" for line in got))
    sys.stderr.write("stand-in snmptrapd log: %d lines, %d notifications\n"
                     % (len(raw), sum(1 for line in got if line.startswith("NOTIFICATION "))))
    if not same:
        sys.stderr.write("".join(difflib.unified_diff([x + "\n" for x in exp], [x + "\n" for x in got],
                                                      "expected", "snmptrapd (converted)")))
    sys.stderr.write("stand-in check: sends %s, log conversion %s, converted log == expected: %s\n"
                     % ("ok" if sent_ok else "FAILED", "ok" if conv_ok else "FAILED",
                        "PASS" if same else "**FAIL**"))
    return sent_ok and conv_ok and same


def main(argv):
    quick = "--quick" in argv
    all_users = "--all-users" in argv
    if quick and all_users:
        sys.stderr.write("--quick and --all-users exclude each other\n")
        return 2
    receiver = "127.0.0.1:16165"
    senders = SENDERS
    action = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--receiver":
            receiver = argv[i + 1]
            i += 1
        elif a == "--senders":
            senders = [s for s in argv[i + 1].split(",") if s]
            if not senders or set(senders) - set(SENDERS):
                sys.stderr.write("--senders: netsnmp and/or pysnmp\n")
                return 2
            i += 1
        elif a in ("--expected", "--send", "--commands", "--selftest"):
            action = a
        elif a in ("--quick", "--all-users"):
            pass
        elif a in ("-h", "--help"):
            sys.stdout.write(__doc__)
            return 0
        else:
            sys.stderr.write("unknown argument %s\n" % a)
            return 2
        i += 1
    if transport_domain(receiver).startswith("tcp") and "pysnmp" in senders and action != "--expected":
        sys.stderr.write("pysnmp_notify.py sends over UDP only: use --senders netsnmp with a tcp: receiver\n")
        return 2
    M = build_matrix(quick, senders, all_users)
    if action == "--expected":
        sys.stdout.write("".join(line + "\n" for line in expected_lines(M)))
        return 0
    if action == "--commands":
        for n in M:
            sys.stdout.write(shlex.join([n.mode] + n.args(receiver)) + "\n")
        return 0
    if action == "--send":
        return 0 if send_all(M, receiver) else 1
    if action == "--selftest":
        return 0 if selftest(M, receiver) else 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
