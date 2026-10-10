#!/usr/bin/env python3
"""Verification of the actsnmp interop lab, and conformance check of any other
agent that serves the lab dataset, such as actsnmp agent.

Runs INSIDE the interop image (normally via interop/selftest.sh or
interop/agentcheck.sh) with host networking.

Lab mode (default) - agents snmpd (127.0.0.1:16161) and snmpsim (127.0.0.1:16162):
  * every SNMPv1/v2c community and every SNMPv3 user, with both independent
    clients (net-snmp tools and pysnmp_client.py)
  * negative USM cases (wrong key extension, wrong password, unknown user,
    insufficient security level)
  * full walks of the shared dataset (GETNEXT and GETBULK, v1/v2c/v3,
    IPv4/IPv6) from both clients against both agents, compared with the
    ground truth computed from dataset/actsnmp_dataset.py
  * GET/GETBULK details, SET (success + error cases; values restored)
  * snmpsim pathological dataset, notifications to snmptrapd

Agent mode - only the generic checks against the given agent(s):
  selftest.py --agent acton=127.0.0.1:16163[,udp6:[::1]:16163] \\
              [--users u_noauth,u_sha_aes,...] [--skip v1,set,negative,...]
  The agent must serve the shared dataset below 1.3.6.1.4.1.8072.9999.1 with
  communities public (ro) / private (rw on .20) and the lab's v3 users.

usage: selftest.py [--quick] [--record OUTDIR] [--agent NAME=ADDR[,ADDR6]]...
                   [--users LIST] [--skip LIST]
  --record OUTDIR  (lab mode) also write reference outputs to OUTDIR
  --quick          skip the slow GETNEXT walks and the pysnmp v3 matrix
  --skip LIST      comma separated: community,v3,negative,get,walk,set,v1
Exit status 0 if every mandatory check passed.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, "/opt/actsnmp/dataset")
sys.path.insert(0, "/opt/actsnmp/tools")
import actsnmp_dataset as ds  # noqa: E402
import netsnmp2canon as n2c  # noqa: E402

SNMPTRAPD = "127.0.0.1:16164"
NS_CANON = ["-On", "-Oe", "-Ox", "--hexOutputLength=0"]
B = ds.oidstr(ds.BASE)
P = ds.oidstr(ds.PATH)
PYCLIENT = ["/opt/venv/bin/python3", "/opt/actsnmp/pysnmp_client.py"]
PYNOTIFY = ["/opt/venv/bin/python3", "/opt/actsnmp/pysnmp_notify.py"]
AUTHPASS = "authpass123"
PRIVPASS = "privpass123"
ENGINE_IDS = {"snmpd": "80001f8880" + b"actsnmpd".hex(),
              "snmpsim": "80004fb805" + b"actsnmpsim".hex()}

RESULTS = []      # (section, name, ok(bool|None), detail)
FAILED = []
SKIP = set()


class Agent:
    def __init__(self, name, addr, addr6=None, kind="custom"):
        self.name, self.addr, self.addr6, self.kind = name, addr, addr6, kind


LAB_AGENTS = [Agent("snmpd", "127.0.0.1:16161", "udp6:[::1]:16161", "snmpd"),
              Agent("snmpsim", "127.0.0.1:16162", "udp6:[::1]:16162", "snmpsim")]


def run(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT(%ss) %s" % (timeout, " ".join(cmd))


def record(section, name, ok, detail=""):
    RESULTS.append((section, name, ok, detail))
    if ok is False:
        FAILED.append((section, name, detail))
    tag = {True: "PASS", False: "FAIL", None: "INFO"}[ok]
    sys.stderr.write("[%s] %s: %s %s\n" % (tag, section, name, detail[:200]))


def strict(agent):
    """error-case expectations are mandatory for snmpd, informational otherwise"""
    return agent.kind == "snmpd"


def to_canon(text):
    lines = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            c = n2c.convert_line(line)
        except ValueError:
            c = "UNPARSED: " + line
        lines.append(c if c is not None else "# " + line)
    return lines


def ns(tool, args, timeout=180):
    """run a net-snmp tool with canonical output options -> (rc, lines, stderr)"""
    rc, out, err = run([tool] + NS_CANON + args, timeout)
    return rc, to_canon(out), err


def py(args, timeout=300):
    rc, out, err = run(PYCLIENT + args, timeout)
    return rc, [line for line in out.splitlines() if line.strip()], err


def first_line(lines, err, rc):
    if lines:
        return lines[0]
    if err.strip():
        return err.strip().splitlines()[0]
    return "rc=%d" % rc


# ------------------------------------------------------------------ users ---

def load_users():
    users = []
    with open("/opt/actsnmp/config/users.tsv") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            c = line.rstrip("\n").split("\t")
            users.append(dict(name=c[0], level=c[1], auth=c[2], priv=c[3], privpy=c[5],
                              in_snmpd=c[8].startswith("yes"), in_snmpsim=c[9] == "yes"))
    return users


USERS = {u["name"]: u for u in load_users()}


def v3args(u, level=None, auth=None, priv=None, authpass=AUTHPASS, privpass=PRIVPASS):
    """net-snmp style v3 options (also understood by pysnmp_client.py)"""
    level = level or u["level"]
    a = ["-v3", "-l", level, "-u", u["name"]]
    if level in ("authNoPriv", "authPriv"):
        a += ["-a", auth or u["auth"], "-A", authpass]
    if level == "authPriv":
        p = priv or (u["priv"] if u["priv"] != "-" else u.get("privpy", "-"))
        a += ["-x", p, "-X", privpass]
    return a


PROBE_OID = B + ".1.18.0"
PROBE_EXPECT = "." + PROBE_OID + " = INTEGER: 2147483647"


def probe_ns(addr, args):
    rc, lines, err = ns("snmpget", ["-r0", "-t3"] + args + [addr, PROBE_OID])
    return rc == 0 and lines == [PROBE_EXPECT], first_line(lines, err, rc)


def probe_py(addr, args):
    rc, lines, err = py(["-r", "0", "-t", "3"] + args + ["get", addr, PROBE_OID])
    return rc == 0 and lines == [PROBE_EXPECT], first_line(lines, err, rc)


# ------------------------------------------------------------ communities ---

def test_engine_ids(agents):
    sec = "engine"
    u = USERS["u_sha_aes"]
    for ag in agents:
        if ag.kind not in ENGINE_IDS:
            continue
        eid = ENGINE_IDS[ag.kind]
        rc, got, err = ns("snmpget", v3args(u) + [ag.addr, "1.3.6.1.6.3.10.2.1.1.0"])
        exp = ".1.3.6.1.6.3.10.2.1.1.0 = Hex-STRING: " + " ".join(
            "%02X" % b for b in bytes.fromhex(eid))
        record(sec, "%s snmpEngineID = 0x%s" % (ag.name, eid), got == [exp],
               " | ".join(got) or err[:100])
        ok, d = probe_ns(ag.addr, ["-e", "0x" + eid] + v3args(u))
        record(sec, "%s explicit -e 0x%s" % (ag.name, eid), ok, d)


def test_communities(agents):
    sec = "community"
    for ag in agents:
        cases = [("1", "public", True), ("2c", "public", True), ("1", "private", True),
                 ("2c", "private", True), ("2c", "wrongcommunity", False)]
        if "v1" in SKIP:
            cases = [c for c in cases if c[0] != "1"]
        for ver, comm, expect in cases:
            ok1, d1 = probe_ns(ag.addr, ["-v" + ver, "-c", comm])
            record(sec, "%s v%s %s net-snmp" % (ag.name, ver, comm), ok1 == expect, d1)
            ok2, d2 = probe_py(ag.addr, ["-v", ver, "-c", comm])
            record(sec, "%s v%s %s pysnmp" % (ag.name, ver, comm), ok2 == expect, d2)
        if ag.addr6:
            ok1, d1 = probe_ns(ag.addr6, ["-v2c", "-c", "public"])
            record(sec, "%s ipv6 v2c public net-snmp" % ag.name, ok1, d1)
            ok2, d2 = probe_py(ag.addr6, ["-v", "2c", "-c", "public"])
            record(sec, "%s ipv6 v2c public pysnmp" % ag.name, ok2, d2)
        if ag.kind == "snmpd":
            ok1, d1 = probe_ns("tcp:" + ag.addr, ["-v2c", "-c", "public"])
            record(sec, "snmpd tcp v2c public net-snmp", ok1, d1)
            rc, lines, _ = ns("snmpget", ["-v2c", "-c", "sysonly", ag.addr,
                                          "1.3.6.1.2.1.1.5.0", PROBE_OID])
            record(sec, "snmpd v2c sysonly view", rc == 0 and len(lines) == 2
                   and lines[0].startswith(".1.3.6.1.2.1.1.5.0 = STRING:")
                   and lines[1] == "." + PROBE_OID + " = noSuchObject", " | ".join(lines))
        if ag.kind == "snmpsim":
            rc, lines, _ = ns("snmpget", ["-v2c", "-c", "pathological", ag.addr, P + ".1.1.0"])
            record(sec, "snmpsim v2c pathological", lines == ["." + P + ".1.1.0 = INTEGER: 1"],
                   " | ".join(lines))


# --------------------------------------------------------------------- v3 ---

def user_on(u, ag, only_users):
    if ag.kind == "snmpd":
        return u["in_snmpd"]
    if ag.kind == "snmpsim":
        return u["in_snmpsim"] and u["name"] != "u_ro_sha_aes"
    if only_users:
        return u["name"] in only_users
    return u["in_snmpd"] and u["name"] != "u_ro_sha_aes"


def test_v3_matrix(agents, quick, only_users):
    sec = "v3"
    rows = []
    for u in load_users():
        row = {"user": u["name"], "level": u["level"], "auth": u["auth"],
               "priv": u["priv"] if u["priv"] != "-" or u["privpy"] == "-"
               else u["privpy"] + " (pysnmp only)"}
        for ag in agents:
            for client in ("net-snmp", "pysnmp"):
                key = "%s/%s" % (ag.name, client)
                if not user_on(u, ag, only_users):
                    row[key] = "-"
                    continue
                if client == "net-snmp" and u["level"] == "authPriv" and u["priv"] == "-":
                    row[key] = "n/a"   # 3DES: not supported by net-snmp
                    continue
                if client == "pysnmp" and quick:
                    row[key] = "skip"
                    continue
                ok, d = (probe_ns if client == "net-snmp" else probe_py)(ag.addr, v3args(u))
                row[key] = "OK" if ok else "FAIL"
                record(sec, "%s %s %s" % (u["name"], ag.name, client), ok, d)
        rows.append(row)
    return rows


def test_v3_negative(agents):
    sec = "v3-negative"
    U = USERS
    for ag in agents:
        a = ag.addr
        # wrong key extension algorithm must fail where an extension is needed
        for user, wrongpriv in (("u_md5_aes192", "AES-192-C"), ("u_md5_aes192c", "AES-192"),
                                ("u_sha_aes256", "AES-256-C"), ("u_sha_aes256c", "AES-256"),
                                ("u_sha224_aes256", "AES-256-C")):
            ok, d = probe_ns(a, v3args(U[user], priv=wrongpriv))
            record(sec, "%s %s with %s must fail" % (ag.name, user, wrongpriv), not ok, d)
        ok, d = probe_ns(a, v3args(U["u_sha"], authpass="wrongpass123"))
        record(sec, "%s wrong auth password must fail" % ag.name, not ok, d)
        ok, d = probe_ns(a, v3args(U["u_sha_aes"], privpass="wrongpass123"))
        record(sec, "%s wrong priv password must fail" % ag.name, not ok, d)
        ok, d = probe_ns(a, v3args(U["u_sha"], auth="MD5"))
        record(sec, "%s wrong auth protocol must fail" % ag.name, not ok, d)
        ok, d = probe_ns(a, ["-v3", "-l", "noAuthNoPriv", "-u", "u_nosuchuser"])
        record(sec, "%s unknown user must fail" % ag.name, not ok, d)
        # lower security level than configured: snmpd VACM rejects
        ok, d = probe_ns(a, v3args(U["u_sha_aes"], level="authNoPriv"))
        record(sec, "%s authPriv user at authNoPriv" % ag.name,
               (not ok) if strict(ag) else None, d)
        ok, d = probe_ns(a, v3args(U["u_sha"], level="noAuthNoPriv"))
        record(sec, "%s authNoPriv user at noAuthNoPriv" % ag.name,
               (not ok) if strict(ag) else None, d)
        if ag.kind == "snmpd":
            # informational: Blumenthal and Reeder key extension are identical
            # when no extension is needed (hash length >= key length)
            for au in ("md5", "sha", "sha224", "sha256", "sha384", "sha512"):
                for k, wrong in (("aes192", "AES-192-C"), ("aes256", "AES-256-C")):
                    u = U["u_%s_%s" % (au, k)]
                    ok, d = probe_ns(a, v3args(u, priv=wrong))
                    record("keyext-info", "snmpd %s accepts %s: %s" % (u["name"], wrong, ok),
                           None, d)


# ------------------------------------------------------------ get / walk ---

def expected_lines(recs, v1=False):
    return [ds.canon_line(o, t, v) for (o, t, v) in recs if not (v1 and t == "COUNTER64")]


def subtree(recs, prefix):
    n = len(prefix)
    return [r for r in recs if r[0][:n] == prefix]


def compare(sec, name, got, exp, mandatory=True):
    status = False if mandatory else None
    if got == exp:
        record(sec, name, True, "%d varbinds" % len(got))
        return True
    for i, (g, e) in enumerate(zip(got, exp)):
        if g != e:
            record(sec, name, status, "#%d got %r expected %r" % (i, g[:120], e[:120]))
            return False
    record(sec, name, status, "length %d expected %d (last got %r)"
           % (len(got), len(exp), got[-1][:120] if got else None))
    return False


def test_gets(agents):
    sec = "get"
    recs = ds.records()
    scal = [r for r in recs if r[0][len(ds.BASE)] < 10]
    oids = [ds.oidstr(r[0]) for r in scal]
    exp = expected_lines(scal)
    for ag in agents:
        a = ag.addr
        rc, got, _ = ns("snmpget", ["-v2c", "-c", "public", a] + oids)
        compare(sec, "%s net-snmp GET %d scalars in one PDU" % (ag.name, len(oids)), got, exp)
        rc, got, _ = py(["get", a] + oids)
        compare(sec, "%s pysnmp GET %d scalars in one PDU" % (ag.name, len(oids)), got, exp)
        rc, got, _ = ns("snmpgetnext", ["-v2c", "-c", "public", a, B, B + ".1.19.0",
                                        B + ".10.1.1"])
        e = [ds.canon_line(*recs[0]), ds.canon_line(*subtree(recs, ds.BASE + (2,))[0]),
             ds.canon_line(*subtree(recs, ds.BASE + (10, 1, 1))[0])]
        compare(sec, "%s net-snmp GETNEXT 3 varbinds" % ag.name, got, e)
        rc, got, _ = py(["getnext", a, B, B + ".1.19.0", B + ".10.1.1"])
        compare(sec, "%s pysnmp GETNEXT 3 varbinds" % ag.name, got, e)
        rc, got, _ = ns("snmpbulkget", ["-v2c", "-c", "public", "-Cn1", "-Cr3", a,
                                        B + ".1", B + ".10.1.2"])
        e = [ds.canon_line(*recs[0])] + expected_lines(subtree(recs, ds.BASE + (10, 1, 2))[:3])
        compare(sec, "%s net-snmp GETBULK N=1 R=3" % ag.name, got, e)
        rc, got, _ = py(["-Cn", "1", "-Cr", "3", "getbulk", a, B + ".1", B + ".10.1.2"])
        compare(sec, "%s pysnmp GETBULK N=1 R=3" % ag.name, got, e)
        rc, got, _ = ns("snmpget", ["-v2c", "-c", "public", a, B + ".99.0", B + ".1.1.0"])
        record(sec, "%s GET missing -> noSuch*" % ag.name,
               len(got) == 2 and got[0].split(" = ")[1] in ("noSuchObject", "noSuchInstance")
               and got[1] == ds.canon_line(*recs[0]), " | ".join(got))
        if "v1" not in SKIP:
            rc, out, err = run(["snmpget", "-On", "-v1", "-c", "public", a, B + ".8.7.0"])
            record(sec, "%s v1 GET Counter64 -> noSuchName" % ag.name,
                   rc != 0 and "noSuchName" in out + err, (out + err).strip()[:100])
            rc, out, err = run(["snmpget", "-On", "-v1", "-c", "public", a, B + ".99.0"])
            record(sec, "%s v1 GET missing -> noSuchName" % ag.name,
                   rc != 0 and "noSuchName" in out + err, (out + err).strip()[:100])


WPREFIX = "." + B + ".20."


def norm_writable(lines):
    """values below the writable subtree .20 depend on earlier SETs: compare
    OID and type only (test_initial_writable checks the values)"""
    out = []
    for line in lines:
        if line.startswith(WPREFIX):
            oid, _, val = line.partition(" = ")
            line = "%s = %s: <writable>" % (oid, val.split(":")[0])
        out.append(line)
    return out


def test_initial_writable(agents, lab):
    for ag in agents:
        rc, got, _ = ns("snmpbulkwalk", ["-v2c", "-c", "public", ag.addr, B + ".20"])
        compare("walk", "%s writable subtree .20 has initial values" % ag.name, got,
                expected_lines(subtree(ds.records(), ds.BASE + (20,))), mandatory=lab)


def test_walks(agents, quick):
    sec = "walk"
    recs = ds.records()
    exp = expected_lines(recs)
    exp_v1 = expected_lines(recs, v1=True)
    exp_tbl = expected_lines(subtree(recs, ds.BASE + (10,)))
    u1 = USERS["u_sha256_aes"]
    u2 = USERS["u_sha512_aes256c"]
    for ag in agents:
        a = ag.addr
        v3a = v3args(u1)
        v3b = v3args(u2)
        v3n = ["-v3", "-l", "noAuthNoPriv", "-u", "u_noauth"]
        cases = [
            ("net-snmp bulkwalk v2c", lambda: ns("snmpbulkwalk", ["-v2c", "-c", "public", a, B]), exp),
            ("net-snmp bulkwalk v2c -Cr50", lambda: ns("snmpbulkwalk", ["-v2c", "-c", "public", "-Cr50", a, B]), exp),
            ("net-snmp bulkwalk v2c -Cr1 table", lambda: ns("snmpbulkwalk", ["-v2c", "-c", "public", "-Cr1", a, B + ".10"]), exp_tbl),
            ("net-snmp bulkwalk v3 SHA-256/AES", lambda: ns("snmpbulkwalk", v3a + [a, B]), exp),
            ("net-snmp bulkwalk v3 SHA-512/AES-256-C", lambda: ns("snmpbulkwalk", v3b + [a, B]), exp),
            ("net-snmp bulkwalk v3 noAuthNoPriv", lambda: ns("snmpbulkwalk", v3n + [a, B]), exp),
            ("pysnmp bulkwalk v2c", lambda: py(["-v", "2c", "bulkwalk", a, B]), exp),
            ("pysnmp bulkwalk v2c -Cr50", lambda: py(["-v", "2c", "-Cr", "50", "bulkwalk", a, B]), exp),
            ("pysnmp bulkwalk v3 SHA-256/AES", lambda: py(v3a + ["bulkwalk", a, B]), exp),
        ]
        if ag.addr6:
            cases += [
                ("net-snmp bulkwalk v2c ipv6", lambda: ns("snmpbulkwalk", ["-v2c", "-c", "public", ag.addr6, B]), exp),
                ("pysnmp bulkwalk v2c ipv6", lambda: py(["-v", "2c", "bulkwalk", ag.addr6, B]), exp),
            ]
        if not quick:
            cases += [
                ("net-snmp walk v2c", lambda: ns("snmpwalk", ["-v2c", "-c", "public", a, B]), exp),
                ("pysnmp walk v2c", lambda: py(["-v", "2c", "walk", a, B]), exp),
            ]
            if "v1" not in SKIP:
                cases += [
                    ("net-snmp walk v1", lambda: ns("snmpwalk", ["-v1", "-c", "public", a, B]), exp_v1),
                    ("pysnmp walk v1", lambda: py(["-v", "1", "walk", a, B]), exp_v1),
                ]
        for name, fn, e in cases:
            t0 = time.time()
            rc, got, err = fn()
            ok = compare(sec, "%s %s" % (ag.name, name), norm_writable(got), norm_writable(e))
            if rc != 0 and ok:
                record(sec, "%s %s exit status" % (ag.name, name), False, "rc=%d %s" % (rc, err[:200]))
            sys.stderr.write("      (%.1fs)\n" % (time.time() - t0))


# -------------------------------------------------------------------- set ---

def test_sets(agents):
    sec = "set"
    U = USERS
    W = B + ".20"
    for ag in agents:
        a = ag.addr

        def nsset(args, auth=("-v2c", "-c", "private")):
            return ns("snmpset", list(auth) + [a] + args)

        def get1(oid):
            rc, got, _ = ns("snmpget", ["-v2c", "-c", "public", a, oid])
            return got[0] if got else ""

        cases = [
            ([W + ".1.0", "i", "99"], "." + W + ".1.0 = INTEGER: 99"),
            ([W + ".1.0", "i", "-2147483648"], "." + W + ".1.0 = INTEGER: -2147483648"),
            ([W + ".2.0", "s", "new value"], "." + W + '.2.0 = STRING: "new value"'),
            ([W + ".2.0", "x", "00 01 0A FF"], "." + W + ".2.0 = Hex-STRING: 00 01 0A FF"),
            ([W + ".2.0", "s", ""], "." + W + '.2.0 = STRING: ""'),
            ([W + ".3.0", "o", ".1.3.6.1.2"], "." + W + ".3.0 = OID: .1.3.6.1.2"),
            ([W + ".4.0", "a", "10.1.2.3"], "." + W + ".4.0 = IpAddress: 10.1.2.3"),
            ([W + ".5.0", "u", "4294967295"], "." + W + ".5.0 = Gauge32: 4294967295"),
            ([W + ".6.0", "t", "4294967295"], "." + W + ".6.0 = Timeticks: 4294967295"),
            ([W + ".8.0", "i", "100"], "." + W + ".8.0 = INTEGER: 100"),
        ]
        for args, e in cases:
            rc, got, err = nsset(args)
            ok = rc == 0 and got == [e] and get1(args[0]) == e
            record(sec, "%s net-snmp v2c set %s %s" % (ag.name, args[1], args[2] or '""'), ok,
                   " | ".join(got) or err.strip()[:150])
        rc, got, err = py(v3args(U["u_sha_aes"]) + ["set", a, W + ".1.0", "i", "1234",
                                                   W + ".2.0", "s", "py\"set"])
        e = ["." + W + ".1.0 = INTEGER: 1234", "." + W + '.2.0 = STRING: "py\\"set"']
        record(sec, "%s pysnmp v3 set 2 varbinds" % ag.name, rc == 0 and got == e
               and get1(W + ".1.0") == e[0], " | ".join(got) or err[:150])
        if "v1" not in SKIP:
            rc, got, err = py(["-v", "1", "-c", "private", "set", a, W + ".5.0", "g", "7"])
            e = ["." + W + ".5.0 = Gauge32: 7"]
            record(sec, "%s pysnmp v1 set" % ag.name, rc == 0 and got == e and get1(W + ".5.0") == e[0],
                   " | ".join(got) or err[:150])
        if ag.kind == "snmpd":
            # The system group implements RESERVE/ACTION/UNDO, so a SET with
            # another failing varbind leaves sysContact unchanged. The .20
            # objects (pass_persist, snmpsim writecache) are not atomic.
            before = get1("1.3.6.1.2.1.1.4.0")
            rc, got, err = nsset(["1.3.6.1.2.1.1.4.0", "s", "CHANGED", W + ".7.0", "i", "1"])
            record(sec, "snmpd atomic SET: failing 2nd varbind rolls back sysContact",
                   rc != 0 and get1("1.3.6.1.2.1.1.4.0") == before, before)
            for o, v in (("1.3.6.1.2.1.1.4.0", "new-contact"), ("1.3.6.1.2.1.1.5.0", "new-name"),
                         ("1.3.6.1.2.1.1.6.0", "new-location")):
                rc, got, err = nsset([o, "s", v])
                record(sec, "snmpd set %s" % o, rc == 0 and get1(o) == '.%s = STRING: "%s"' % (o, v),
                       " | ".join(got))
        errs = [
            ("read-only object", [W + ".7.0", "i", "1"], ("-v2c", "-c", "private"), "notWritable"),
            ("wrong type", [W + ".1.0", "s", "foo"], ("-v2c", "-c", "private"), "wrongType"),
            ("out of range", [W + ".8.0", "i", "101"], ("-v2c", "-c", "private"), "wrongValue"),
            ("non-existing object", [W + ".99.0", "i", "1"], ("-v2c", "-c", "private"), "notWritable"),
            ("read-only community", [W + ".1.0", "i", "1"], ("-v2c", "-c", "public"), "noAccess"),
            ("read-only dataset object", [B + ".1.1.0", "i", "1"], ("-v2c", "-c", "private"), "noAccess"),
            ("v1 read-only object", [W + ".7.0", "i", "1"], ("-v1", "-c", "private"), "noSuchName"),
            ("v1 wrong type", [W + ".1.0", "s", "foo"], ("-v1", "-c", "private"), "badValue"),
            ("v3 read-only user", [W + ".1.0", "i", "1"], tuple(v3args(U["u_ro_sha_aes"])), "noAccess"),
        ]
        for name, args, auth, expect in errs:
            if "read-only user" in name and ag.kind != "snmpd":
                continue
            if name.startswith("v1") and "v1" in SKIP:
                continue
            rc, out, err = run(["snmpset", "-On", "-r1", "-t2"] + list(auth) + [a] + args)
            text = (out + err).replace("\n", " ")
            ok = rc != 0 and expect in text
            record(sec, "%s %s -> %s" % (ag.name, name, expect),
                   ok if strict(ag) else None, text.strip()[:150])
        # restore the initial values
        restore = []
        for (n, typ, val, rw) in ds.WRITABLE:
            if not rw:
                continue
            o = W + ".%d.0" % n
            if typ == "INTEGER":
                restore += [o, "i", str(val)]
            elif typ == "OCTETS":
                restore += [o, "x", val.hex()]
            elif typ == "OID":
                restore += [o, "o", ds.oidstr(val)]
            elif typ == "IPADDR":
                restore += [o, "a", "%d.%d.%d.%d" % tuple(val)]
            elif typ == "GAUGE32":
                restore += [o, "u", str(val)]
            elif typ == "TIMETICKS":
                restore += [o, "t", str(val)]
        if ag.kind == "snmpd":
            restore += ["1.3.6.1.2.1.1.4.0", "s", "actsnmp-contact", "1.3.6.1.2.1.1.5.0", "s",
                        "actsnmp-snmpd", "1.3.6.1.2.1.1.6.0", "s", "actsnmp-lab"]
        rc, got, err = nsset(restore)
        rc2, got2, _ = ns("snmpbulkwalk", ["-v2c", "-c", "public", a, W])
        record(sec, "%s restore initial values" % ag.name,
               rc == 0 and got2 == expected_lines(subtree(ds.records(), ds.BASE + (20,))),
               err[:150])


# ---------------------------------------------------------- lab specials ---

def test_pathological(ag):
    sec = "pathological"
    A = ag.addr
    c = ["-v2c", "-c", "pathological"]
    infos = [
        ("GET NULL value", ["snmpget"] + c + [A, P + ".1.2.0"]),
        ("GET 10000 byte string", ["snmpget"] + c + [A, P + ".1.3.0"]),
        ("GET 60000 byte string", ["snmpget", "-r0", "-t3"] + c + [A, P + ".1.6.0"]),
        ("GET 65535 byte string (cannot fit in UDP)", ["snmpget", "-r0", "-t3"] + c + [A, P + ".1.4.0"]),
        ("GETBULK P.1 R=10 (response would exceed UDP)",
         ["snmpbulkget", "-r0", "-t3", "-Cr10"] + c + [A, P + ".1"]),
        ("GET noSuchObject value", ["snmpget"] + c + [A, P + ".2.1.0"]),
        ("GET noSuchInstance value", ["snmpget"] + c + [A, P + ".2.2.0"]),
        ("GET endOfMibView value", ["snmpget"] + c + [A, P + ".2.3.0"]),
        ("walk P.2 (exceptions inside a walk)", ["snmpwalk"] + c + [A, P + ".2"]),
        ("GET P.2.4.0 (after endOfMibView)", ["snmpget"] + c + [A, P + ".2.4.0"]),
        ("walk P.1", ["snmpwalk", "-r0", "-t3"] + c + [A, P + ".1"]),
    ]
    for i, st in enumerate(["genErr", "tooBig", "noAccess", "authorizationError",
                            "resourceUnavailable", "noSuchName"], start=1):
        infos.append(("GET error %s" % st, ["snmpget"] + c + [A, P + ".3.%d.0" % i]))
    infos += [
        ("GET 1s delay (timeout 3s)", ["snmpget", "-r0", "-t3"] + c + [A, P + ".4.1.0"]),
        ("GET 5s delay (timeout 2s, 0 retries)", ["snmpget", "-r0", "-t2"] + c + [A, P + ".4.2.0"]),
        ("walk P.5 (decreasing OID)", ["snmpwalk", "-r0", "-t3"] + c + [A, P + ".5"]),
        ("walk P.5.3 (repeated OID)", ["snmpwalk", "-r0", "-t3"] + c + [A, P + ".5.3"]),
        ("bulkwalk P.5 (decreasing OID)", ["snmpbulkwalk", "-r0", "-t3"] + c + [A, P + ".5"]),
    ]
    out = {}
    for name, cmd in infos:
        t0 = time.time()
        rc, o, e = run(cmd[:1] + NS_CANON + cmd[1:], timeout=30)
        dt = time.time() - t0
        lines = []
        for line in (o + e).splitlines():
            if not line.strip():
                continue
            try:
                cv = n2c.convert_line(line)
            except ValueError:
                cv = None
            if cv and len(cv) > 140:
                cv = cv[:140] + "...(%d chars)" % len(cv)
            lines.append(cv if cv else line)
        out[name] = (rc, lines, dt)
        record(sec, name, None, "rc=%d %.1fs: %s" % (rc, dt, " | ".join(lines)[:300]))
    rc, lines, err = py(["-c", "pathological", "walk", A, P + ".5"])
    record(sec, "pysnmp walk P.5 detects non-increasing OID", rc == 1 and "not increasing" in err,
           " | ".join(lines) + " || " + err.strip())
    rc, lines, err = py(["-c", "pathological", "bulkwalk", A, P + ".5"])
    record(sec, "pysnmp bulkwalk P.5 detects non-increasing OID", rc == 1 and "not increasing" in err,
           " | ".join(lines) + " || " + err.strip())
    rc_, o_, e_ = run(["snmpwalk", "-On", "-v2c", "-c", "pathological", A, P + ".5"])
    record(sec, "net-snmp walk P.5 detects non-increasing OID",
           "OID not increasing" in (o_ + e_), (o_ + e_).replace("\n", " | ")[:200])
    return out


def test_informs():
    """Fixed explicit uptimes: selftest.sh compares the converted snmptrapd log
    with expected/notify/selftest-snmptrapd.txt"""
    sec = "snmptrapd"
    U = USERS
    rc, o, e = run(["snmpinform", "-v2c", "-c", "public", "-r0", "-t3", SNMPTRAPD, "101",
                    "1.3.6.1.4.1.8072.9999.3.1", B + ".1.1.0", "i", "1"])
    record(sec, "v2c inform acknowledged", rc == 0, (o + e).strip()[:150])
    rc, o, e = run(["snmpinform"] + v3args(U["u_sha256_aes"]) + ["-r0", "-t3", SNMPTRAPD, "102",
                   "1.3.6.1.4.1.8072.9999.3.2", B + ".1.1.0", "i", "2"])
    record(sec, "v3 inform (u_sha256_aes) acknowledged", rc == 0, (o + e).strip()[:150])
    rc, o, e = run(["snmptrap", "-v2c", "-c", "public", SNMPTRAPD, "103",
                    "1.3.6.1.4.1.8072.9999.3.3", B + ".1.1.0", "i", "3"])
    record(sec, "v2c trap sent", rc == 0, (o + e).strip()[:150])
    rc, o, e = run(["snmptrap", "-e", "0x8000000001020304"] + v3args(U["u_sha_aes"]) +
                   [SNMPTRAPD, "104", "1.3.6.1.4.1.8072.9999.3.4", B + ".1.1.0", "i", "4"])
    record(sec, "v3 trap (u_sha_aes, engine 0x8000000001020304) sent", rc == 0, (o + e).strip()[:150])
    rc, o, e = run(["snmptrap", "-v1", "-c", "public", SNMPTRAPD, "1.3.6.1.4.1.8072.9999.3",
                    "127.0.0.1", "6", "5", "105", B + ".1.1.0", "i", "5"])
    record(sec, "v1 trap sent", rc == 0, (o + e).strip()[:150])
    rc, o, e = run(PYNOTIFY + ["inform", "-v2c", "-c", "public", "-r", "0", "-t", "3", SNMPTRAPD,
                               "106", "1.3.6.1.4.1.8072.9999.3.6", B + ".1.1.0", "i", "6"])
    record(sec, "pysnmp_notify v2c inform acknowledged", rc == 0, (o + e).strip()[:150])
    rc, o, e = run(PYNOTIFY + ["trap", "-e", "0x8000000001020305"] + v3args(U["u_sha512_aes256c"]) +
                   [SNMPTRAPD, "107", "1.3.6.1.4.1.8072.9999.3.7", B + ".1.1.0", "i", "7"])
    record(sec, "pysnmp_notify v3 trap (u_sha512_aes256c, engine 0x8000000001020305) sent", rc == 0,
           (o + e).strip()[:150])
    rc, o, e = run(PYNOTIFY + ["trap", "-v1", "-c", "public", SNMPTRAPD, "1.3.6.1.4.1.8072.9999.3",
                               "192.0.2.1", "3", "0", "108", B + ".9.1.0", "q", "deadbeef"])
    record(sec, "pysnmp_notify v1 trap sent", rc == 0, (o + e).strip()[:150])


# --------------------------------------------------------------- record ---

def write(outdir, name, lines):
    path = os.path.join(outdir, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    sys.stderr.write("wrote %s (%d lines)\n" % (path, len(lines)))


def record_expected(outdir, agents, patho):
    recs = ds.records()
    groups = [
        ("dataset.txt", ds.BASE, False),
        ("dataset-v1.txt", ds.BASE, True),
        ("scalars.txt", None, False),
        ("table.txt", ds.BASE + (10,), False),
        ("strtable.txt", ds.BASE + (11,), False),
        ("bigtable.txt", ds.BASE + (12,), False),
        ("writable-initial.txt", ds.BASE + (20,), False),
    ]
    for name, pfx, v1 in groups:
        sel = [r for r in recs if r[0][len(ds.BASE)] < 10] if pfx is None else subtree(recs, pfx)
        write(outdir, "canon/" + name, expected_lines(sel, v1=v1))
    sysoids = ["1.3.6.1.2.1.1.%d.0" % i for i in (1, 2, 4, 5, 6, 7)]
    for ag in agents:
        rc, got, _ = ns("snmpget", ["-v2c", "-c", "public", ag.addr] + sysoids)
        write(outdir, "canon/%s-system.txt" % ag.name, got)
    for ag in agents:
        for tool, args, fn in (
                ("snmpbulkwalk", ["-v2c", "-c", "public", "-On", ag.addr, B], "dataset.On.txt"),
                ("snmpwalk", ["-v1", "-c", "public", "-On", ag.addr, B], "dataset-v1.On.txt"),
                ("snmpbulkwalk", ["-v2c", "-c", "public", "-On", "-Ox", "--hexOutputLength=0",
                                  ag.addr, B], "dataset.On-Ox.txt"),
        ):
            rc, out, err = run([tool] + args)
            write(outdir, "netsnmp/%s-%s" % (ag.name, fn), out.rstrip("\n").split("\n"))
    lines = []
    for name, (rc, ls, dt) in patho.items():
        lines.append("## %s  (exit %d)" % (name, rc))
        lines += ls
    write(outdir, "pathological-netsnmp.txt", lines)


# ----------------------------------------------------------------- main ---

def matrix_md(rows, agents):
    cols = ["%s/%s" % (ag.name, c) for ag in agents for c in ("net-snmp", "pysnmp")]
    out = ["| user | level | auth | priv | " + " | ".join(cols) + " |",
           "|---|---|---|---|" + "---|" * len(cols)]
    for r in rows:
        out.append("| %s | %s | %s | %s | %s |" % (r["user"], r["level"], r["auth"], r["priv"],
                                                   " | ".join(r.get(c, "") for c in cols)))
    return "\n".join(out)


def main():
    args = sys.argv[1:]
    quick = "--quick" in args
    outdir = None
    custom = []
    only_users = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--record":
            outdir = args[i + 1]
            i += 1
        elif a == "--agent":
            name, _, addrs = args[i + 1].partition("=")
            a4, _, a6 = addrs.partition(",")
            custom.append(Agent(name, a4, a6 or None, "custom"))
            i += 1
        elif a == "--users":
            only_users = set(args[i + 1].split(","))
            i += 1
        elif a == "--skip":
            SKIP.update(args[i + 1].split(","))
            i += 1
        elif a in ("--quick",):
            pass
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            sys.stderr.write("unknown argument %s\n" % a)
            return 2
        i += 1
    agents = custom or LAB_AGENTS
    lab = not custom
    t0 = time.time()
    rows = []
    if lab:
        test_engine_ids(agents)
    if "community" not in SKIP:
        test_communities(agents)
    if "v3" not in SKIP:
        rows = test_v3_matrix(agents, quick, only_users)
    if "negative" not in SKIP:
        test_v3_negative(agents)
    if "get" not in SKIP:
        test_gets(agents)
    if "walk" not in SKIP:
        test_initial_writable(agents, lab)
        test_walks(agents, quick)
    if "set" not in SKIP:
        test_sets(agents)
    patho = {}
    if lab:
        patho = test_pathological(agents[1])
        test_informs()
        if outdir:
            record_expected(outdir, agents, patho)
            write(outdir, "v3-matrix.md", matrix_md(rows, agents).split("\n"))
    print("# actsnmp interop %s (%.0fs)\n" % ("selftest" if lab else "agent check",
                                             time.time() - t0))
    print("Agents: " + ", ".join("%s=%s%s" % (a.name, a.addr, (" " + a.addr6) if a.addr6 else "")
                                 for a in agents) + "\n")
    if rows:
        print("## SNMPv3 user matrix\n")
        print(matrix_md(rows, agents))
    print("\n## Checks\n")
    print("| section | check | result | detail |")
    print("|---|---|---|---|")
    for sec, name, ok, det in RESULTS:
        if sec == "v3":
            continue
        res = {True: "PASS", False: "**FAIL**", None: "info"}[ok]
        print("| %s | %s | %s | %s |" % (sec, name, res, det.replace("|", "/")[:160]))
    npass = sum(1 for r in RESULTS if r[2] is True)
    print("\n%d passed, %d failed, %d informational" % (
        npass, len(FAILED), sum(1 for r in RESULTS if r[2] is None)))
    if FAILED:
        print("\nFAILED:")
        for f in FAILED:
            print("  - %s / %s: %s" % f)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
