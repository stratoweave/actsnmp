#!/usr/bin/env python3
"""Side-by-side check of the actsnmp CLI against net-snmp's command line tools.

Runs on the HOST (python3 >= 3.8, stdlib only), normally via
interop/clicheck.sh. Every case runs the same argument list twice:

  * net-snmp:  docker exec actsnmp-tools snmp<TOOL> ARGS...   (the lab image's net-snmp 5.9.4)
  * actsnmp:   out/bin/actsnmp <TOOL> ARGS...                   (on the host)

against the lab agents (snmpd 127.0.0.1:16161, snmpsim 127.0.0.1:16162, both
with host networking), a closed port (127.0.0.1:16169) or the lab snmptrapd,
and compares stdout, stderr and the exit code byte for byte. The "tcp" section
runs the same kind of cases with tcp: and tcp6: addresses (RFC 3430) against
snmpd and snmptrapd, which listen on TCP too (snmpsim does not).

A case marked "known" is a documented difference (its reason is printed): it
is reported as KNOWN when the outputs differ, and as FIXED? when they no
longer do. Every other difference is a FAIL. Cases marked "first-line" compare
only the first stderr line (the usage text that follows a usage error is
actsnmp's own); "sorted" cases compare the sorted lines of stdout (actsnmp
table, row by row, against a net-snmp walk of the same columns, column by
column).

The SET cases change the writable B.20 objects of both agents and restore their
initial values at the end of the "set" section.

usage: clicheck.py [--cli PATH] [--quick] [--filter REGEX] [--section LIST] [--list]
                   [--report FILE] [--jobs N] [-v]
  --cli PATH      the CLI to test (default: out/bin/actsnmp of this repository)
  --quick         skip the slow whole-dataset GETNEXT walks
  --filter REGEX  only cases whose "section/name" matches
  --section LIST  only these sections (comma separated): dataset, output, walk-options, address, timeout,
                  v3-errors, error-status, pathological, local-errors, set, tcp, mib
  --list          print the cases and exit
  --report FILE   also write the markdown report to FILE
  --jobs N        cases of read-only sections run N at a time (default 4)
  -v              print every case's diff, also of known differences
Exit status 0 when no case FAILs (KNOWN differences are allowed), 1 otherwise,
2 for usage errors.
"""
import concurrent.futures
import difflib
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
TOOLS_CONTAINER = os.environ.get("ACTSNMP_TOOLS_CONTAINER", "actsnmp-tools")

B = ".1.3.6.1.4.1.8072.9999.1"           # the shared dataset
P = ".1.3.6.1.4.1.8072.9999.2"           # snmpsim's pathological dataset
D = "127.0.0.1:16161"                    # snmpd
S = "127.0.0.1:16162"                    # snmpsim
D6 = "udp6:[::1]:16161"
S6 = "udp6:[::1]:16162"
X = "127.0.0.1:16169"                    # nothing listens here
TRAPD = "127.0.0.1:16164"                # the lab's snmptrapd
DT = "tcp:" + D                          # snmpd and snmptrapd over TCP, a closed TCP port
DT6 = "tcp6:[::1]:16161"
XT = "tcp:" + X
XT6 = "tcp6:[::1]:16169"
TRAPDT = "tcp:" + TRAPD
TRAPDT6 = "tcp6:[::1]:16164"
SNMPD_ENGINE = "0x80001f8880616374736e6d7064"
SNMPSIM_ENGINE = "0x80004fb805616374736e6d7073696d"
AUTH = "authpass123"
PRIV = "privpass123"

V2 = ["-v2c", "-c", "public"]
V2W = ["-v2c", "-c", "private"]
V1 = ["-v1", "-c", "public"]
V1W = ["-v1", "-c", "private"]
PATH2 = ["-v2c", "-c", "pathological"]
PATH1 = ["-v1", "-c", "pathological"]
QUICK_FAIL = ["-t", "0.3", "-r", "1"]     # 2 attempts of 0.3 s against a silent target
SIM_FAIL = ["-t", "1", "-r", "1"]         # snmpsim (pysnmp) can take more than 0.3 s for a first v3 answer


def v3(user, level, auth=None, priv=None, authpass=AUTH, privpass=PRIV):
    a = ["-v3", "-u", user, "-l", level]
    if auth:
        a += ["-a", auth, "-A", authpass]
    if priv:
        a += ["-x", priv, "-X", privpass]
    return a


U_NOAUTH = v3("u_noauth", "noAuthNoPriv")
U_SHA = v3("u_sha", "authNoPriv", "SHA")
U_SHA_AES = v3("u_sha_aes", "authPriv", "SHA", "AES")
U_SHA256_AES = v3("u_sha256_aes", "authPriv", "SHA-256", "AES")
U_SHA512_AES256C = v3("u_sha512_aes256c", "authPriv", "SHA-512", "AES-256-C")
U_MD5_DES = v3("u_md5_des", "authPriv", "MD5", "DES")
U_MD5_AES192 = v3("u_md5_aes192", "authPriv", "MD5", "AES-192")
U_RO = v3("u_ro_sha_aes", "authPriv", "SHA", "AES")

# Reasons of the documented differences (Case.known)
K_NAMES = ("net-snmp without -On prints OID names from its MIB tree (no MIBs: iso.3.6...); actsnmp without "
           "-m/-M/MIBS/MIBDIRS loads no MIBs and prints numeric OIDs")
K_LOOP = "net-snmp loops forever on this agent behaviour; actsnmp ends the walk with exit 1"
K_STRICT = ("net-snmp sends a value outside the type's range as typed (INTEGER above Integer32 as a 5-octet "
            "INTEGER, wrapping unsigned values); actsnmp's encoders are strict and refuse it")
K_MANGLED_OID = ("net-snmp sends a mangled OID (one arc as .0.N, an arc above 4294967295 modulo 2^32, a second "
                 "arc >= 40 folded into the first); actsnmp refuses it")
K_EXTENSION = "actsnmp set accepts the type letters c, C and q, which snmpset rejects (an extension)"
K_QOPAQUE = "actsnmp trap accepts q (raw Opaque), which snmptrap does not know (an extension)"
K_DEFAULT_VERSION = ("the default SNMP version is a build option of net-snmp (Ubuntu: 3); actsnmp's default "
                     "is 2c")
K_OP = "-Op PRECISION (printf format of Opaque floats) is not implemented"
K_ENGINE_HINT = ("with -e, net-snmp keeps the given engine ID and times out when the agent reports "
                 "unknownEngineIDs (snmpd) or unknownUserNames from its own engine (snmpsim); actsnmp's "
                 "Client takes -e as a hint and rediscovers")
K_VERSION = "-V prints actsnmp's own version"
K_TRAP_UPTIME = ("snmptrap ignores a v2c UPTIME it cannot read (the trap goes out without sysUpTime.0); "
                 "actsnmp refuses it")
K_NO_DNS = "actsnmp resolves no host names in values (a v1 AGENT-ADDR must be an IPv4 address)"
K_ERRNO = "net-snmp appends a stale errno text (No such file or directory) to this error"
K_CE_LAST = "-CE as the last argument crashes snmpwalk (SIGSEGV); actsnmp reports the missing end OID"
K_TCP_REFUSED = ("snmptrap and snmpinform print an empty error (\"snmptrap: \") when the TCP connection is refused; "
                 "actsnmp prints the reason as snmpget does (\"snmptrap: Unknown host (tcp:HOST:PORT) (Connection "
                 "refused)\")")


class Case:
    def __init__(self, section, name, tool, args, known=None, cmp="exact", serial=False,
                 net_tool=None, net_args=None, normalize=(), timeout=120, quick=True, env=None):
        self.section = section
        self.name = name
        self.tool = tool
        self.args = args
        self.known = known
        self.cmp = cmp
        self.serial = serial
        self.net_tool = net_tool or ("snmp" + tool)
        self.net_args = net_args if net_args is not None else args
        self.normalize = normalize
        self.timeout = timeout
        self.quick = quick
        self.env = env or {}

    def key(self):
        return "%s/%s" % (self.section, self.name)


CASES = []
# the scalars B.1 .. B.9 of the dataset
SCALARS = ["%s.%d.%d.0" % (B, g, n) for g, cnt in ((1, 19), (2, 16), (3, 8), (4, 4), (5, 5), (6, 4), (7, 4), (8, 7),
                                                  (9, 3)) for n in range(1, cnt + 1)]


def case(section, name, tool, args, **kw):
    CASES.append(Case(section, name, tool, args, **kw))


# ---------------------------------------------------------------- cases ---

def dataset_cases():
    sec = "dataset"
    for ag, a, a6 in (("snmpd", D, D6), ("snmpsim", S, S6)):
        case(sec, "%s bulkwalk v2c B" % ag, "bulkwalk", ["-On"] + V2 + [a, B])
        case(sec, "%s bulkwalk v2c -Cr50 B" % ag, "bulkwalk", ["-On", "-Cr50"] + V2 + [a, B])
        case(sec, "%s walk v2c B" % ag, "walk", ["-On"] + V2 + [a, B], quick=False)
        case(sec, "%s walk v1 B" % ag, "walk", ["-On"] + V1 + [a, B], quick=False)
        case(sec, "%s bulkwalk v3 SHA-256/AES B" % ag, "bulkwalk", ["-On"] + U_SHA256_AES + [a, B])
        case(sec, "%s bulkwalk v3 noAuthNoPriv B.10" % ag, "bulkwalk", ["-On"] + U_NOAUTH + [a, B + ".10"])
        case(sec, "%s walk v3 MD5/DES B.11" % ag, "walk", ["-On"] + U_MD5_DES + [a, B + ".11"])
        case(sec, "%s bulkwalk v2c IPv6 B.12" % ag, "bulkwalk", ["-On"] + V2 + [a6, B + ".12"])
        case(sec, "%s bulkwalk v3 SHA-512/AES-256-C IPv6 B.1" % ag, "bulkwalk",
             ["-On"] + U_SHA512_AES256C + [a6, B + ".1"])
        case(sec, "%s get 70 scalars v2c" % ag, "get", ["-On"] + V2 + [a] + SCALARS)
        case(sec, "%s get 70 scalars v3 MD5/AES-192" % ag, "get", ["-On"] + U_MD5_AES192 + [a] + SCALARS)
        case(sec, "%s get 70 scalars v1 (Counter64: noSuchName, fixed and resent)" % ag, "get",
             ["-On"] + V1 + [a] + SCALARS)
        case(sec, "%s getnext 3 varbinds" % ag, "getnext", ["-On"] + V2 + [a, B, B + ".1.19.0", B + ".10.1.1"])
        case(sec, "%s getnext 3 varbinds v1" % ag, "getnext", ["-On"] + V1 + [a, B + ".7.4.0", B + ".1.19.0",
                                                                             B + ".10.1.1"])
        case(sec, "%s bulkget N=1 R=3" % ag, "bulkget", ["-On", "-Cn1", "-Cr3"] + V2 + [a, B + ".1", B + ".10.1.2"])
        case(sec, "%s bulkget N=2 R=2, 3 OIDs" % ag, "bulkget",
             ["-On", "-Cn2", "-Cr2"] + V2 + [a, B + ".1", B + ".2.1.0", B + ".10.1.2"])
        case(sec, "%s bulkget R=200 (agent cap)" % ag, "bulkget", ["-On", "-Cr200"] + V2 + [a, B + ".12"])
        case(sec, "%s bulkget R=0" % ag, "bulkget", ["-On", "-Cr0", "-Cn1"] + V2 + QUICK_FAIL + [a, B, B + ".1"])
        case(sec, "%s get missing objects v2c" % ag, "get", ["-On"] + V2 + [a, B + ".1.1.1", B + ".99.0",
                                                                           B + ".1.1.0"])
        case(sec, "%s get missing objects v1 (two noSuchName rounds)" % ag, "get",
             ["-On"] + V1 + [a, B + ".99.0", B + ".1.1.0", B + ".98.0", B + ".1.2.0"])
        case(sec, "%s get -Cf v1 missing object" % ag, "get", ["-On", "-Cf"] + V1 + [a, B + ".99.0", B + ".1.1.0"])
        # snmptable needs MIBs ("Was that a table?"): actsnmp table is compared, line by line in sorted order,
        # with a net-snmp walk of the same columns
        case(sec, "%s table B.10 v2c (sorted, vs snmpbulkwalk)" % ag, "table",
             ["-On"] + V2 + [a] + ["%s.10.1.%d" % (B, c) for c in range(1, 8)],
             cmp="sorted", net_tool="snmpbulkwalk", net_args=["-On"] + V2 + [a, B + ".10.1"])
        case(sec, "%s table B.11 v1 (sorted, vs snmpwalk)" % ag, "table",
             ["-On"] + V1 + [a] + ["%s.11.1.%d" % (B, c) for c in range(1, 4)],
             cmp="sorted", net_tool="snmpwalk", net_args=["-On"] + V1 + [a, B + ".11.1"])
        case(sec, "%s table B.12 v3 (sorted, vs snmpbulkwalk)" % ag, "table",
             ["-On", "-Cr40"] + U_SHA_AES + [a, B + ".12.1.1", B + ".12.1.2"],
             cmp="sorted", net_tool="snmpbulkwalk", net_args=["-On", "-Cr40"] + U_SHA_AES + [a, B + ".12.1"])
    # snmpd's own MIB (static parts) and snmpsim's system group
    case(sec, "snmpd usmUserTable", "bulkwalk", ["-On"] + V2 + [D, ".1.3.6.1.6.3.15"])
    case(sec, "snmpd VACM to the end of the MIB", "bulkwalk", ["-On"] + V2 + [D, ".1.3.6.1.6.3.16"])
    case(sec, "snmpd VACM to the end of the MIB, walk", "walk", ["-On"] + V2 + [D, ".1.3.6.1.6.3.16"])
    case(sec, "snmpd VACM v1 to the end of the MIB", "walk", ["-On"] + V1 + [D, ".1.3.6.1.6.3.16.1.5"])
    case(sec, "snmpsim default root (mib-2)", "walk", ["-On"] + V2 + [S])
    case(sec, "snmpsim default root bulkwalk", "bulkwalk", ["-On"] + V2 + [S])
    case(sec, "snmpd sysonly view get", "get", ["-On", "-v2c", "-c", "sysonly", D, "1.3.6.1.2.1.1.5.0", B + ".1.1.0"])
    case(sec, "snmpd sysonly view getnext past the view", "getnext",
         ["-On", "-v2c", "-c", "sysonly", D, "1.3.6.1.2.1.1.9.1.4.9"])


def output_cases():
    sec = "output"
    flagsets = ["", "-Oq", "-OQ", "-Ov", "-Ot", "-OT", "-Oa", "-Ox", "-Oqv", "-Oqt", "-OvT", "-OQx", "-OxT", "-Oqq",
                "-OtQ", "-Oe", "-On", "-OU", "-Ob", "-OE", "-OX", "-O0", "-Oxq", "-Oaq", "-OaT", "-OTq", "-OQv",
                "-Oq -Oq", "-Ox -Oa", "-Ox --hexOutputLength=0", "--hexOutputLength=8", "--hexOutputLength=1",
                "-OT --hexOutputLength=4", "-Oq --hexOutputLength=0", "--hexOutputLength=0", "-OQ -OT", "-OQQq"]
    for f in flagsets:
        fl = f.split() if f else []
        case(sec, "walk B.1-B.9 %s" % (f or "(default)"), "walk", ["-On"] + fl + V2 + ["-CE", B + ".10", S, B])
        case(sec, "get B.2 strings %s" % (f or "(default)"), "get", ["-On"] + fl + V2 + [S] +
             ["%s.2.%d.0" % (B, n) for n in range(1, 17)])
    case(sec, "no -On", "get", V2 + [S, B + ".1.1.0", B + ".3.2.0"], known=K_NAMES)
    for f in ("-Of", "-Os", "-OS", "-Ou"):
        case(sec, "OID style %s" % f, "get", ["-On", f] + V2 + [S, B + ".1.1.0"], known=K_NAMES)
    case(sec, "-Op precision", "get", ["-On", "-Op", "%.2f"] + V2 + [S, B + ".9.2.0"], known=K_OP)


def walk_option_cases():
    sec = "walk-options"
    for t in ("walk", "bulkwalk"):
        case(sec, "%s -Ci" % t, t, ["-On", "-Ci"] + V2 + [S, B + ".4"])
        case(sec, "%s -Ci scalar instance" % t, t, ["-On", "-Ci"] + V2 + [S, B + ".4.1.0"])
        case(sec, "%s -Cp" % t, t, ["-On", "-Cp"] + V2 + [S, B + ".5"])
        case(sec, "%s -Cp empty subtree" % t, t, ["-On", "-Cp"] + V2 + [S, B + ".15"])
        case(sec, "%s -Ct" % t, t, ["-On", "-Ct"] + V2 + [S, B + ".6"],
             normalize=[(r"Total traversal time = [0-9.]+ seconds", "Total traversal time = T seconds")])
        case(sec, "%s -Cc" % t, t, ["-On", "-Cc"] + V2 + [S, B + ".7"])
        case(sec, "%s empty subtree (GET of the root)" % t, t, ["-On"] + V2 + [S, B + ".15"])
        case(sec, "%s empty subtree -CI" % t, t, ["-On", "-CI"] + V2 + [S, B + ".15"])
        case(sec, "%s scalar instance" % t, t, ["-On"] + V2 + [S, B + ".1.1.0"])
        case(sec, "%s end of the MIB (snmpsim sentinel)" % t, t, ["-On"] + V2 + [S, ".1.3.6.1.6.3.10"])
        case(sec, "%s past the end of the MIB" % t, t, ["-On"] + V2 + [S, ".1.3.6.1.6.3.11"])
        case(sec, "%s -Cp -Ci combined" % t, t, ["-On", "-Cpi"] + V2 + [S, B + ".4"])
        case(sec, "%s -C p -C i separate" % t, t, ["-On", "-C", "p", "-C", "i"] + V2 + [S, B + ".4"])
    case(sec, "walk -CE", "walk", ["-On", "-CE", B + ".10.1.1.5"] + V2 + [S, B + ".10"])
    case(sec, "walk -CE glued", "walk", ["-On", "-CE" + B + ".2.3.0"] + V2 + [S, B + ".2"])
    case(sec, "walk -CE before the root", "walk", ["-On", "-CE", B + ".1"] + V2 + [S, B + ".2"])
    case(sec, "walk -CE outside the subtree", "walk", ["-On", "-CE", B + ".5"] + V2 + [S, B + ".4"])
    case(sec, "walk v1 end of the MIB", "walk", ["-On"] + V1 + [S, ".1.3.6.1.6.3.10"])
    case(sec, "walk v1 empty subtree", "walk", ["-On"] + V1 + [S, B + ".15"])
    case(sec, "walk v1 Counter64 subtree", "walk", ["-On"] + V1 + [S, B + ".8"])
    case(sec, "bulkwalk -Cn1", "bulkwalk", ["-On", "-Cn1"] + V2 + [S, B + ".2"])
    case(sec, "bulkwalk -Cr1", "bulkwalk", ["-On", "-Cr1"] + V2 + [S, B + ".11"])
    case(sec, "bulkwalk -Cr 3 separate", "bulkwalk", ["-On", "-C", "r3"] + V2 + [D, B + ".11"])
    case(sec, "bulkwalk -Cr0 (snmpsim does not answer)", "bulkwalk", ["-On", "-Cr0", "-t", "0.5", "-r", "0"] + V2
         + [S, B + ".2"])
    case(sec, "bulkwalk -Cr0 snmpd (no progress)", "bulkwalk", ["-On", "-Cr0"] + V2 + [D, B + ".2"], known=K_LOOP,
         timeout=8)
    case(sec, "bulkwalk -CE (snmpwalk only)", "bulkwalk", ["-On", "-CE", B + ".3"] + V2 + [S, B + ".2"])
    case(sec, "getnext end of the MIB", "getnext", ["-On"] + V2 + [S, ".1.3.6.1.6.3.10.2.1.1.0"])
    case(sec, "getnext end of the MIB v1", "getnext", ["-On"] + V1 + [S, ".1.3.6.1.6.3.10.2.1.1.0"])
    case(sec, "bulkget end of the MIB", "bulkget", ["-On", "-Cr3"] + V2 + [S, ".1.3.6.1.6.3.10.2.1.1"])
    case(sec, "set -Cq", "set", ["-On", "-Cq"] + V2W + [D, B + ".20.1.0", "i", "42"], serial=True)


def address_cases():
    sec = "address"
    case(sec, "udp: prefix", "get", ["-On"] + V2 + ["udp:" + D, B + ".1.2.0"])
    case(sec, "udp6: bracketed", "get", ["-On"] + V2 + [D6, B + ".1.2.0"])
    case(sec, "bracketed IPv6 without udp6:", "get", ["-On"] + V2 + ["[::1]:16162", B + ".1.2.0"])
    case(sec, "udp6: IPv6 without port (161: timeout)", "get", ["-On"] + V2 + QUICK_FAIL + ["udp6:::1", B + ".1.2.0"])
    case(sec, "localhost", "get", ["-On"] + V2 + ["localhost:16161", B + ".1.2.0"])
    case(sec, "default port 161 (timeout)", "get", ["-On"] + V2 + QUICK_FAIL + ["127.0.0.1", B + ".1.2.0"])
    case(sec, "udp6: timeout text", "walk", ["-On"] + V2 + QUICK_FAIL + ["udp6:[::1]:16169", B])
    case(sec, "tcp: prefix", "get", ["-On"] + V2 + [DT, B + ".1.2.0"])


def timeout_cases():
    sec = "timeout"
    for t, extra in (("get", [B + ".1.1.0"]), ("getnext", [B + ".1.1.0"]), ("bulkget", [B + ".1"]),
                     ("walk", [B + ".1"]), ("bulkwalk", [B + ".1"]), ("set", [B + ".20.1.0", "i", "1"])):
        case(sec, "%s v2c closed port" % t, t, ["-On"] + V2 + QUICK_FAIL + [X] + extra)
        case(sec, "%s v3 closed port (discovery)" % t, t, ["-On"] + U_SHA + QUICK_FAIL + [X] + extra)
        case(sec, "%s v3 -e closed port (no discovery)" % t, t,
             ["-On", "-e", SNMPD_ENGINE] + U_SHA + QUICK_FAIL + [X] + extra)
    case(sec, "get v1 closed port", "get", ["-On"] + V1 + QUICK_FAIL + [X, B + ".1.1.0"])
    case(sec, "table v2c closed port", "table", ["-On"] + V2 + QUICK_FAIL + [X, B + ".10.1.1"],
         net_tool="snmpbulkwalk", net_args=["-On"] + V2 + QUICK_FAIL + [X, B + ".10.1.1"])
    for ag, a in (("snmpd", D), ("snmpsim", S)):
        case(sec, "%s unknown community v2c" % ag, "get", ["-On", "-v2c", "-c", "nosuch"] + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s unknown community v1 walk" % ag, "walk", ["-On", "-v1", "-c", "nosuch"] + QUICK_FAIL + [a, B])
        case(sec, "%s unknown context" % ag, "get", ["-On", "-n", "nosuchctx"] + U_SHA + QUICK_FAIL + [a, B + ".1.1.0"])
    case(sec, "snmpsim 5 s delay, -t 2 -r 0", "get", ["-On", "-t", "2", "-r", "0"] + PATH2 + [S, P + ".4.2.0"],
         serial=True)


def v3_error_cases():
    sec = "v3-errors"
    for ag, a in (("snmpd", D), ("snmpsim", S)):
        QUICK_FAIL = ["-t", "0.3", "-r", "1"] if ag == "snmpd" else SIM_FAIL
        for t, extra in (("get", [B + ".1.1.0"]), ("getnext", [B + ".1.1.0"]), ("bulkget", [B + ".1"]),
                         ("walk", [B + ".1"]), ("bulkwalk", [B + ".1"]), ("set", [B + ".20.1.0", "i", "42"])):
            case(sec, "%s %s unknown user" % (ag, t), t, ["-On"] + v3("u_nosuch", "noAuthNoPriv") + QUICK_FAIL + [a] + extra,
                 serial=(t == "set"))
        case(sec, "%s wrong auth password" % ag, "get", ["-On"] + v3("u_sha", "authNoPriv", "SHA", authpass="wrongpass1")
             + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s wrong auth password walk" % ag, "walk",
             ["-On"] + v3("u_sha", "authNoPriv", "SHA", authpass="wrongpass1") + QUICK_FAIL + [a, B + ".1"])
        case(sec, "%s wrong auth protocol" % ag, "get", ["-On"] + v3("u_sha", "authNoPriv", "MD5") + QUICK_FAIL
             + [a, B + ".1.1.0"])
        case(sec, "%s wrong priv password" % ag, "get",
             ["-On"] + v3("u_sha_aes", "authPriv", "SHA", "AES", privpass="wrongpass1") + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s wrong priv password bulkwalk" % ag, "bulkwalk",
             ["-On"] + v3("u_sha_aes", "authPriv", "SHA", "AES", privpass="wrongpass1") + QUICK_FAIL + [a, B + ".1"])
        case(sec, "%s wrong priv protocol" % ag, "get", ["-On"] + v3("u_sha_aes", "authPriv", "SHA", "DES")
             + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s wrong AES key extension" % ag, "get",
             ["-On"] + v3("u_md5_aes192", "authPriv", "MD5", "AES-192-C") + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s level below the user's" % ag, "get", ["-On"] + v3("u_sha_aes", "authNoPriv", "SHA")
             + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s level below the user's, noAuthNoPriv" % ag, "get", ["-On"] + v3("u_sha", "noAuthNoPriv")
             + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s level above the user's" % ag, "get", ["-On"] + v3("u_sha", "authPriv", "SHA", "AES")
             + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s wrong -e engine ID" % ag, "get", ["-On", "-e", "0x8000000001020399"] + U_SHA + QUICK_FAIL
             + [a, B + ".1.1.0"], known=K_ENGINE_HINT)
        case(sec, "%s no user" % ag, "get", ["-On", "-v3", "-l", "authNoPriv", "-A", AUTH] + QUICK_FAIL
             + [a, B + ".1.1.0"])
        case(sec, "%s no auth pass phrase" % ag, "get", ["-On", "-v3", "-u", "u_sha", "-l", "authNoPriv"] + QUICK_FAIL
             + [a, B + ".1.1.0"])
        case(sec, "%s no priv pass phrase" % ag, "walk", ["-On", "-v3", "-u", "u_sha_aes", "-l", "authPriv", "-A", AUTH]
             + QUICK_FAIL + [a, B + ".1"])
        case(sec, "%s no user, -e" % ag, "get", ["-On", "-v3", "-e", SNMPD_ENGINE] + QUICK_FAIL + [a, B + ".1.1.0"])
        case(sec, "%s right -e engine ID" % ag, "get",
             ["-On", "-e", SNMPD_ENGINE if ag == "snmpd" else SNMPSIM_ENGINE] + U_SHA + [a, B + ".1.1.0"])
        case(sec, "%s -E context engine ID" % ag, "get",
             ["-On", "-E", SNMPD_ENGINE if ag == "snmpd" else SNMPSIM_ENGINE] + U_SHA + [a, B + ".1.1.0"])
    case(sec, "snmpd read-only user SET", "set", ["-On"] + U_RO + [D, B + ".20.1.0", "i", "1"], serial=True)
    case(sec, "snmpd trap -Ci no user (snmpinform's name)", "trap", ["-v3", "-l", "authNoPriv", "-A", AUTH, "-Ci"]
         + QUICK_FAIL + [D, "", B + ".1.1.0"])
    case(sec, "snmpsim context pathological", "get", ["-On", "-n", "pathological"] + U_SHA + [S, P + ".1.1.0"])
    case(sec, "snmpsim context pathological genErr", "get", ["-On", "-n", "pathological"] + U_SHA + [S, P + ".3.1.0"])


def error_status_cases():
    sec = "error-status"
    for ver, auth in (("v2c", PATH2), ("v1", PATH1)):
        for i, st in enumerate(["genErr", "tooBig", "noAccess", "authorizationError", "resourceUnavailable",
                                "noSuchName"], start=1):
            o = "%s.3.%d.0" % (P, i)
            case(sec, "get %s %s" % (ver, st), "get", ["-On"] + auth + [S, o])
            case(sec, "getnext %s %s" % (ver, st), "getnext", ["-On"] + auth + [S, "%s.3.%d" % (P, i)])
            if ver == "v2c":
                case(sec, "bulkget %s %s" % (ver, st), "bulkget", ["-On", "-Cr1"] + auth + [S, "%s.3.%d" % (P, i)])
                case(sec, "bulkwalk %s %s" % (ver, st), "bulkwalk", ["-On", "-Cr1"] + auth + [S, "%s.3.%d" % (P, i)])
            case(sec, "walk %s %s" % (ver, st), "walk", ["-On"] + auth + [S, "%s.3.%d" % (P, i)])
            case(sec, "set %s %s" % (ver, st), "set", ["-On"] + auth + [S, o, "i", "1"], serial=True)
        case(sec, "get %s 3 varbinds, error at 2 (fixed and resent)" % ver, "get",
             ["-On"] + auth + [S, P + ".1.1.0", P + ".3.1.0", P + ".1.5.0"])
        case(sec, "get %s 3 varbinds, error at 1 -Cf" % ver, "get",
             ["-On", "-Cf"] + auth + [S, P + ".3.3.0", P + ".1.1.0", P + ".1.5.0"])
        case(sec, "getnext %s 3 varbinds, error at 2" % ver, "getnext",
             ["-On"] + auth + [S, P + ".1.1.0", P + ".3.0", P + ".1.4.0"])
        case(sec, "get %s tooBig with 2 varbinds" % ver, "get", ["-On"] + auth + [S, P + ".1.1.0", P + ".3.2.0"])
        case(sec, "getnext %s tooBig with 2 varbinds" % ver, "getnext", ["-On"] + auth + [S, P + ".1.1.0", P + ".3.1.0"])
    case(sec, "walk v2c error variation P.3", "walk", ["-On"] + PATH2 + [S, P + ".3"])
    case(sec, "bulkwalk v2c error variation P.3", "bulkwalk", ["-On"] + PATH2 + [S, P + ".3"])
    case(sec, "get v2c snmpd tooBig (v3, 20 x 4000 octets)", "get",
         ["-On"] + U_SHA_AES + [D] + [B + ".2.13.0"] * 20)
    case(sec, "get v2c 20 x 4000 octets (dropped: timeout)", "get",
         ["-On"] + V2 + QUICK_FAIL + [D] + [B + ".2.13.0"] * 20)


def set_cases():
    sec = "set"
    W = B + ".20"
    for ag, a in (("snmpd", D), ("snmpsim", S)):
        ok = [
            ("INTEGER", [W + ".1.0", "i", "99"]),
            ("INTEGER min", [W + ".1.0", "i", "-2147483648"]),
            ("STRING", [W + ".2.0", "s", "new value"]),
            ("hex STRING", [W + ".2.0", "x", "00 01 0A FF"]),
            ("empty STRING", [W + ".2.0", "s", ""]),
            ("decimal STRING", [W + ".2.0", "d", "1.2.250"]),
            ("BITS", [W + ".2.0", "b", "0 9 15"]),
            ("OID", [W + ".3.0", "o", ".1.3.6.1.2"]),
            ("IpAddress", [W + ".4.0", "a", "10.1.2.3"]),
            ("Gauge32", [W + ".5.0", "u", "4294967295"]),
            ("TimeTicks", [W + ".6.0", "t", "4294967295"]),
            ("range max", [W + ".8.0", "i", "100"]),
            ("two varbinds", [W + ".1.0", "i", "7", W + ".2.0", "s", "two"]),
        ]
        for name, args in ok:
            case(sec, "%s %s" % (ag, name), "set", ["-On"] + V2W + [a] + args, serial=True)
        case(sec, "%s v1 Gauge32" % ag, "set", ["-On"] + V1W + [a, W + ".5.0", "u", "7"], serial=True)
        case(sec, "%s v3 two varbinds" % ag, "set", ["-On"] + U_SHA_AES + [a, W + ".1.0", "i", "1234", W + ".2.0", "s",
                                                                          "py\"set"], serial=True)
        errs = [
            ("read-only object", V2W, [W + ".7.0", "i", "1"]),
            ("wrong type", V2W, [W + ".1.0", "s", "foo"]),
            ("out of range", V2W, [W + ".8.0", "i", "101"]),
            ("non-existing object", V2W, [W + ".99.0", "i", "1"]),
            ("read-only community", V2, [W + ".1.0", "i", "1"]),
            ("read-only dataset object", V2W, [B + ".1.1.0", "i", "1"]),
            ("v1 read-only object", V1W, [W + ".7.0", "i", "1"]),
            ("v1 wrong type", V1W, [W + ".1.0", "s", "foo"]),
            ("v1 out of range", V1W, [W + ".8.0", "i", "101"]),
            ("second varbind fails", V2W, [W + ".1.0", "i", "43", W + ".7.0", "i", "1"]),
            ("v3 wrong type", U_SHA_AES, [W + ".1.0", "s", "foo"]),
        ]
        for name, auth, args in errs:
            case(sec, "%s %s" % (ag, name), "set", ["-On"] + auth + [a] + args, serial=True)
        case(sec, "%s INTEGER above Integer32" % ag, "set", ["-On"] + V2W + QUICK_FAIL + [a, W + ".1.0", "i",
                                                                                       "2147483648"],
             serial=True, known=K_STRICT)
    case(sec, "snmpd sysContact atomic rollback", "set",
         ["-On"] + V2W + [D, "1.3.6.1.2.1.1.4.0", "s", "CHANGED", W + ".7.0", "i", "1"], serial=True)
    case(sec, "snmpd sysContact", "set", ["-On"] + V2W + [D, "1.3.6.1.2.1.1.4.0", "s", "actsnmp-contact"], serial=True)
    restore = [W + ".1.0", "i", "42", W + ".2.0", "s", "initial", W + ".3.0", "o", ".1.3.6.1", W + ".4.0", "a",
               "192.0.2.1", W + ".5.0", "u", "0", W + ".6.0", "t", "0", W + ".8.0", "i", "50"]
    for ag, a in (("snmpd", D), ("snmpsim", S)):
        case(sec, "%s restore the initial values" % ag, "set", ["-On"] + V2W + [a] + restore, serial=True)
        case(sec, "%s initial values" % ag, "bulkwalk", ["-On"] + V2 + [a, W], serial=True)


def tcp_cases():
    # SNMP over TCP (RFC 3430): snmpd and snmptrapd on tcp:127.0.0.1 and tcp6:[::1], nothing on port 16169. net-snmp's
    # tools use one connection per command; so does actsnmp, unless a request goes 2 x -t without an answer.
    sec = "tcp"
    W = B + ".20"
    case(sec, "get 70 scalars v2c", "get", ["-On"] + V2 + [DT] + SCALARS)
    case(sec, "get 70 scalars v3 SHA-256/AES (discovery)", "get", ["-On"] + U_SHA256_AES + [DT] + SCALARS)
    case(sec, "get 70 scalars v1 (Counter64: noSuchName, fixed and resent)", "get", ["-On"] + V1 + [DT] + SCALARS)
    case(sec, "get missing objects v2c", "get", ["-On"] + V2 + [DT, B + ".1.1.1", B + ".99.0", B + ".1.1.0"])
    case(sec, "getnext 3 varbinds", "getnext", ["-On"] + V2 + [DT, B, B + ".1.19.0", B + ".10.1.1"])
    case(sec, "bulkget N=1 R=3", "bulkget", ["-On", "-Cn1", "-Cr3"] + V2 + [DT, B + ".1", B + ".10.1.2"])
    case(sec, "bulkget R=200 (agent cap)", "bulkget", ["-On", "-Cr200"] + V2 + [DT, B + ".12"])
    case(sec, "bulkwalk v2c B", "bulkwalk", ["-On"] + V2 + [DT, B])
    case(sec, "bulkwalk v3 SHA-256/AES B", "bulkwalk", ["-On"] + U_SHA256_AES + [DT, B])
    case(sec, "bulkwalk v3 noAuthNoPriv B.10", "bulkwalk", ["-On"] + U_NOAUTH + [DT, B + ".10"])
    case(sec, "walk v2c B.10", "walk", ["-On"] + V2 + [DT, B + ".10"])
    case(sec, "walk v1 B.11", "walk", ["-On"] + V1 + [DT, B + ".11"])
    case(sec, "walk v3 MD5/DES B.11", "walk", ["-On"] + U_MD5_DES + [DT, B + ".11"])
    case(sec, "table B.10 v2c (sorted, vs snmpbulkwalk)", "table",
         ["-On"] + V2 + [DT] + ["%s.10.1.%d" % (B, c) for c in range(1, 8)],
         cmp="sorted", net_tool="snmpbulkwalk", net_args=["-On"] + V2 + [DT, B + ".10.1"])
    case(sec, "tcp6: bulkwalk v2c B.12", "bulkwalk", ["-On"] + V2 + [DT6, B + ".12"])
    case(sec, "tcp6: get v3 SHA-512/AES-256-C", "get", ["-On"] + U_SHA512_AES256C + [DT6] + SCALARS[:5])
    case(sec, "tcp: localhost", "get", ["-On"] + V2 + ["tcp:localhost:16161", B + ".1.2.0"])
    case(sec, "tcp6: localhost", "get", ["-On"] + V2 + ["tcp6:localhost:16161", B + ".1.2.0"])
    case(sec, "tcp: unknown host", "get", ["-On"] + V2 + ["tcp:nosuchhost.invalid:161", B + ".1.1.0"])
    # the agent does not answer: timeouts on a live connection
    case(sec, "unknown community", "get", ["-On", "-v2c", "-c", "nosuch"] + QUICK_FAIL + [DT, B + ".1.1.0"])
    case(sec, "unknown community v1 walk", "walk", ["-On", "-v1", "-c", "nosuch"] + QUICK_FAIL + [DT, B])
    case(sec, "v3 wrong priv password", "get",
         ["-On"] + v3("u_sha_aes", "authPriv", "SHA", "AES", privpass="wrongpass1") + QUICK_FAIL + [DT, B + ".1.1.0"])
    # Reports
    case(sec, "v3 unknown user", "get", ["-On"] + v3("u_nosuch", "noAuthNoPriv") + QUICK_FAIL + [DT, B + ".1.1.0"])
    case(sec, "v3 wrong auth password", "get", ["-On"] + v3("u_sha", "authNoPriv", "SHA", authpass="wrongpass1")
         + QUICK_FAIL + [DT, B + ".1.1.0"])
    case(sec, "v3 level above the user's", "get", ["-On"] + v3("u_sha", "authPriv", "SHA", "AES") + QUICK_FAIL
         + [DT, B + ".1.1.0"])
    # a refused connection ends the command at once (-t 5: a timeout would take 30 s)
    for t, extra in (("get", [B + ".1.1.0"]), ("getnext", [B + ".1.1.0"]), ("bulkget", [B + ".1"]),
                     ("walk", [B + ".1"]), ("bulkwalk", [B + ".1"]), ("set", [W + ".1.0", "i", "1"])):
        case(sec, "%s refused" % t, t, ["-On", "-t", "5"] + V2 + [XT] + extra, timeout=10)
    case(sec, "get v3 refused (discovery)", "get", ["-On", "-t", "5"] + U_SHA + [XT, B + ".1.1.0"], timeout=10)
    case(sec, "walk tcp6: refused", "walk", ["-On", "-t", "5"] + V2 + [XT6, B + ".1"], timeout=10)
    # (each tool names itself in the error)
    case(sec, "table refused", "table", ["-On", "-t", "5"] + V2 + [XT, B + ".10.1.1"], timeout=10,
         net_tool="snmpbulkwalk", net_args=["-On", "-t", "5"] + V2 + [XT, B + ".10.1.1"],
         normalize=[(r"(?m)^snmp(?:bulkwalk|table): ", "snmp<TOOL>: ")])
    case(sec, "trap refused", "trap", ["-On", "-t", "5"] + V2 + [XT, "1", ".1.3.6.1.6.3.1.1.5.1"], timeout=10,
         known=K_TCP_REFUSED)
    case(sec, "trap v1 refused", "trap", ["-On", "-t", "5"] + V1 + [XT, ".1.3.6.1.4.1.8072", "192.0.2.1", "6", "1",
                                                                   "1"], timeout=10, known=K_TCP_REFUSED)
    case(sec, "inform refused", "inform", ["-On", "-t", "5"] + V2 + [XT, "1", ".1.3.6.1.6.3.1.1.5.1"], timeout=10,
         known=K_TCP_REFUSED)
    # notifications to snmptrapd: both tools print nothing (trapdcheck.sh checks what snmptrapd receives)
    case(sec, "trap v2c to snmptrapd", "trap", ["-On"] + V2 + [TRAPDT, "1", ".1.3.6.1.4.1.8072.9999.3.0.98",
                                                              B + ".1.1.0", "i", "1"])
    case(sec, "trap v1 to snmptrapd", "trap", ["-On"] + V1 + [TRAPDT, ".1.3.6.1.4.1.8072.9999", "192.0.2.1", "6",
                                                             "98", "1"])
    case(sec, "trap tcp6: to snmptrapd", "trap", ["-On"] + V2 + [TRAPDT6, "1", ".1.3.6.1.4.1.8072.9999.3.0.98"])
    case(sec, "inform to snmptrapd", "inform", ["-On"] + V2 + [TRAPDT, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    case(sec, "inform tcp6: to snmptrapd", "inform", ["-On"] + V2 + [TRAPDT6, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    case(sec, "inform v3 to snmptrapd (discovery)", "inform", ["-On"] + U_SHA_AES
         + [TRAPDT, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    case(sec, "inform v3 wrong password to snmptrapd", "inform",
         ["-On"] + v3("u_sha", "authNoPriv", "SHA", authpass="wrongpass1") + QUICK_FAIL
         + [TRAPDT, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    # SET, then the initial values again
    case(sec, "set INTEGER", "set", ["-On"] + V2W + [DT, W + ".1.0", "i", "99"], serial=True)
    case(sec, "set v3 two varbinds", "set", ["-On"] + U_SHA_AES + [DT, W + ".1.0", "i", "1234", W + ".2.0", "s",
                                                                    "tcp"], serial=True)
    case(sec, "set read-only object", "set", ["-On"] + V2W + [DT, W + ".7.0", "i", "1"], serial=True)
    case(sec, "set v1 wrong type", "set", ["-On"] + V1W + [DT, W + ".1.0", "s", "foo"], serial=True)
    case(sec, "restore the initial values", "set", ["-On"] + V2W + [DT, W + ".1.0", "i", "42", W + ".2.0", "s",
                                                                    "initial"], serial=True)
    case(sec, "initial values", "bulkwalk", ["-On"] + V2 + [DT, W], serial=True)


def pathological_cases():
    sec = "pathological"
    T3 = ["-t", "3", "-r", "0"]
    case(sec, "GET NULL value", "get", ["-On"] + PATH2 + [S, P + ".1.2.0"])
    case(sec, "GET 10000 byte string", "get", ["-On"] + PATH2 + [S, P + ".1.3.0"])
    case(sec, "GET 60000 byte string", "get", ["-On"] + PATH2 + T3 + [S, P + ".1.6.0"])
    case(sec, "GET 65535 byte string (timeout)", "get", ["-On"] + PATH2 + ["-t", "1", "-r", "0"] + [S, P + ".1.4.0"])
    case(sec, "GETBULK P.1 R=10 (timeout)", "bulkget", ["-On", "-Cr10"] + PATH2 + ["-t", "1", "-r", "0"] + [S, P + ".1"],
         known=None)
    for i, n in ((1, "noSuchObject"), (2, "noSuchInstance"), (3, "endOfMibView")):
        case(sec, "GET %s value" % n, "get", ["-On"] + PATH2 + [S, "%s.2.%d.0" % (P, i)])
        case(sec, "GETNEXT to %s value" % n, "getnext", ["-On"] + PATH2 + [S, "%s.2.%d" % (P, i)])
    case(sec, "GET exception values v1", "get", ["-On"] + PATH1 + [S, P + ".2.1.0", P + ".1.1.0"])
    case(sec, "GET P.2.4.0", "get", ["-On"] + PATH2 + [S, P + ".2.4.0"])
    case(sec, "walk P.2", "walk", ["-On"] + PATH2 + [S, P + ".2"])
    case(sec, "walk P.2 v1", "walk", ["-On"] + PATH1 + [S, P + ".2"])
    case(sec, "bulkwalk P.2", "bulkwalk", ["-On"] + PATH2 + [S, P + ".2"])
    case(sec, "bulkwalk P.2 -Cr4", "bulkwalk", ["-On", "-Cr4"] + PATH2 + [S, P + ".2"])
    case(sec, "walk P.1 (timeout midway)", "walk", ["-On"] + PATH2 + ["-t", "1", "-r", "0"] + [S, P + ".1"])
    case(sec, "walk P.5 (decreasing OID)", "walk", ["-On"] + PATH2 + T3 + [S, P + ".5"])
    case(sec, "walk P.5.3 (repeated OID)", "walk", ["-On"] + PATH2 + T3 + [S, P + ".5.3"])
    case(sec, "walk P.5 v1", "walk", ["-On"] + PATH1 + T3 + [S, P + ".5"])
    case(sec, "bulkwalk P.5", "bulkwalk", ["-On"] + PATH2 + T3 + [S, P + ".5"])
    case(sec, "bulkwalk P.5 -Cr1", "bulkwalk", ["-On", "-Cr1"] + PATH2 + T3 + [S, P + ".5"])
    case(sec, "bulkwalk P.5.3 -Cr2", "bulkwalk", ["-On", "-Cr2"] + PATH2 + T3 + [S, P + ".5.3"])
    case(sec, "walk P.5 -Cc", "walk", ["-On", "-Cc"] + PATH2 + T3 + [S, P + ".5"], known=K_LOOP, timeout=8)
    case(sec, "getnext P.5.2.0 (decreasing)", "getnext", ["-On"] + PATH2 + [S, P + ".5.1.0"])
    case(sec, "GET 1 s delay", "get", ["-On"] + PATH2 + T3 + [S, P + ".4.1.0"], serial=True)
    case(sec, "v3 context: walk P.5", "walk", ["-On", "-n", "pathological"] + U_SHA + T3 + [S, P + ".5"])


def local_error_cases():
    sec = "local-errors"
    oids = ["foo", "1.3.foo", "foo.1", ".1.3.x", "1..3", "", "1.3.-1", "x.y", "1x", "1.3.1x", "0x1.3", "1.3.foo.bar",
            "1.3.", "..1", "1.3.6 ", B + ".1.010.0", B + ".1.0x10.0", "1.3.+1", "1.3.0x", "1.3.08",
            "3.1", "5.1"]
    for o in oids:
        case(sec, "OID [%s]" % o, "get", ["-On"] + V2 + [D, o])
    case(sec, "OID [.]", "get", ["-On"] + V2 + [D, "."], known=K_MANGLED_OID)
    case(sec, "OIDs: every bad one (snmpget)", "get", ["-On"] + V2 + [D, "foo", B + ".1.1.0", "1.x"])
    case(sec, "OIDs: every bad one (snmpgetnext)", "getnext", ["-On"] + V2 + [D, "foo", B + ".1.1.0", "1.x"])
    case(sec, "OIDs: the first bad one (snmpbulkget)", "bulkget", ["-On"] + V2 + [D, "foo", B + ".1.1.0", "1.x"])
    case(sec, "walk root [3.1]", "walk", ["-On"] + V2 + QUICK_FAIL + [X, "3.1"])
    case(sec, "bulkwalk root [3.1]", "bulkwalk", ["-On"] + V2 + QUICK_FAIL + [X, "3.1"])
    case(sec, "walk root [foo]", "walk", ["-On"] + V2 + [D, "foo"])
    case(sec, "set name [3.1]", "set", ["-On"] + V2W + QUICK_FAIL + [X, "3.1", "i", "1"])
    case(sec, "trap OID [3.1]", "trap", ["-On"] + V2 + [X, "1", "3.1"])
    case(sec, "trap v1 enterprise [3.1]", "trap", ["-On"] + V1 + [X, "3.1", "", "6", "1", "1"])
    case(sec, "trap value o [3.1]", "trap", ["-On"] + V2 + [X, "1", "1.3", B + ".1.1.0", "o", "3.1"])
    for o in ("1", ".1", "1.40", "0.40", B + ".1.1.4294967296", B + ".1.1.99999999999999999999"):
        case(sec, "OID [%s]" % o, "get", ["-On"] + V2 + [D, o], known=K_MANGLED_OID)
    case(sec, "OID with 129 arcs", "get", ["-On"] + V2 + QUICK_FAIL + [X, ".1.3" + ".1" * 127])
    case(sec, "OID with 128 arcs", "get", ["-On"] + V2 + QUICK_FAIL + [X, ".1.3" + ".1" * 126])
    # value parsing: snmpset against the closed port (a parsed value times out, a bad one is an error)
    values = [("i", ""), ("i", " 5"), ("i", "5 "), ("i", "+5"), ("i", "-5"), ("i", "0x10"), ("i", "010"), ("i", "abc"),
              ("i", "5abc"), ("i", "2147483647"), ("i", "-2147483648"),
              ("u", ""), ("u", "abc"), ("u", "4294967295"), ("u", "0x10"), ("u", " 7"), ("u", "+7"), ("u", "5x"),
              ("t", "abc"), ("t", "5x"), ("t", "100"), ("3", "5"),
              ("a", ""), ("a", "1.2.3"), ("a", "1.2"), ("a", "1"), ("a", "0x7f.1"), ("a", "256.1.1.1"),
              ("a", "localhost"), ("a", "1.2.3.4.5"), ("a", " 1.2.3.4"), ("a", "1.2.3.256"), ("a", "1.2.65536"),
              ("a", "0x01020304"), ("a", "1.2.3.4 "), ("a", "01.02.03.010"), ("a", "1.2.3.4 x"), ("a", "1.2.3.08"),
              ("a", "4294967295"), ("a", "255.255.255.255"), ("a", "0xffffffff"),
              ("o", ""), ("o", ".1.3"), ("o", "1.3.x"), ("o", "foo"), ("o", "1.3.0x10"), ("o", "3.1"),
              ("s", ""), ("s", "text"),
              ("x", ""), ("x", "0x"), ("x", "abc"), ("x", "0g"), ("x", "DE AD"), ("x", "DEADBEE"), ("x", "0xDEAD"),
              ("x", "de:ad"), ("x", " DEAD"), ("x", "DE  AD"), ("x", "D E A D"), ("x", "0XDEAD"), ("x", "DE\tAD"),
              ("x", "DEAD "),
              ("d", ""), ("d", "1.2.3"), ("d", "1 2 3"), ("d", "256"), ("d", "1.a"), ("d", "-1"), ("d", "1..2"),
              ("d", "1,2"), ("d", "0x10"), ("d", "010"),
              ("b", ""), ("b", "0 9"), ("b", "1,2"), ("b", "x"), ("b", "1 x"), ("b", "65536"),
              ("n", ""), ("n", "foo"),
              ("F", "1.5"), ("F", "abc"), ("F", ""), ("F", " 1.5"), ("F", "inf"), ("F", "1e400"),
              ("D", "1.5"), ("D", "1e400"), ("I", "-5"), ("I", "abc"), ("I", " 5"), ("U", "5"),
              ("e", "5"), ("S", "5"), ("Z", "5"), ("ii", "5"), ("integer", "5"), ("=", "5"), ("=", ""), ("", "5"),
              ("U", "-1"), ("I", "5x"), ("F", "1.5x"), ("F", "0x1p3"), ("b", "0x10"), ("b", "010")]
    for letter, value in values:
        case(sec, "set value %s [%s]" % (letter, value), "set",
             ["-On"] + V2W + ["-t", "0.2", "-r", "0", X, B + ".20.1.0", letter, value])
    known_values = [("i", "2147483648", K_STRICT), ("i", "-2147483649", K_STRICT),
                    ("i", "9223372036854775808", K_STRICT), ("u", "-1", K_STRICT), ("u", "4294967296", K_STRICT),
                    ("t", "-1", K_STRICT), ("t", "4294967296", K_STRICT), ("3", "-1", K_STRICT),
                    ("o", "1", K_MANGLED_OID), ("o", ".", K_MANGLED_OID), ("o", "1.40", K_MANGLED_OID),
                    ("c", "5", K_EXTENSION), ("C", "5", K_EXTENSION), ("q", "DEAD", K_EXTENSION),
                    ("b", "-1", "net-snmp accepts a negative bit number (undefined behaviour; -9 crashes it); "
                                "actsnmp refuses it")]
    for letter, value, why in known_values:
        case(sec, "set value %s [%s]" % (letter, value), "set",
             ["-On"] + V2W + ["-t", "0.2", "-r", "0", X, B + ".20.1.0", letter, value], known=why)
    case(sec, "set two bad values (both reported)", "set",
         ["-On"] + V2W + ["-t", "0.2", "-r", "0", X, B + ".20.1.0", "i", "abc", B + ".20.2.0", "x", "0g"])
    case(sec, "set bad OID and bad value", "set",
         ["-On"] + V2W + ["-t", "0.2", "-r", "0", X, "1.3.foo", "i", "1", B + ".20.2.0", "x", "0g"])
    case(sec, "set bad type after bad value", "set",
         ["-On"] + V2W + ["-t", "0.2", "-r", "0", X, B + ".20.1.0", "i", "abc", B + ".20.2.0", "z", "1"])
    case(sec, "set missing value", "set", ["-On"] + V2W + [X, B + ".20.1.0", "i"])
    case(sec, "set missing type and value", "set", ["-On"] + V2W + [X, B + ".20.1.0"])
    case(sec, "set missing value of the second varbind", "set", ["-On"] + V2W + [X, B + ".20.1.0", "i", "1",
                                                                             B + ".20.2.0", "s"])
    # trap value parsing (snmp_add_var without snmpset's type check)
    trap_values = [("c", "5"), ("C", "5"), ("C", "abc"), ("C", "-1"), ("C", "5x"), ("C", "18446744073709551615"),
                   ("C", "18446744073709551616"), ("3", "5"), ("i", "abc"), ("e", "5"), ("=", "5"), ("n", "x"),
                   ("U", "-1"), ("U", "5x"), ("U", "0x10"), ("I", "5x"), ("F", "1.5x"), ("F", "0x10"),
                   ("D", "0x1p3"), ("x", "D E"), ("a", "1.2.3")]
    for letter, value in trap_values:
        case(sec, "trap value %s [%s]" % (letter, value), "trap",
             ["-On"] + V2 + [X, "1", ".1.3.6.1.6.3.1.1.5.1", B + ".20.1.0", letter, value])
    case(sec, "trap value b [-1]", "trap", ["-On"] + V2 + [X, "1", ".1.3.6.1.6.3.1.1.5.1", B + ".20.1.0", "b", "-1"],
         known="net-snmp accepts a negative bit number (undefined behaviour; -9 crashes it); actsnmp refuses it")
    case(sec, "trap value q [DEAD]", "trap", ["-On"] + V2 + [X, "1", ".1.3.6.1.6.3.1.1.5.1", B + ".20.1.0", "q", "DEAD"],
         known=K_QOPAQUE)
    case(sec, "trap missing type/value", "trap", ["-On"] + V2 + [X, "1", ".1.3.6.1.6.3.1.1.5.1", B + ".20.1.0", "i"])
    case(sec, "trap missing type and value", "trap", ["-On"] + V2 + [X, "1", ".1.3.6.1.6.3.1.1.5.1", B + ".20.1.0"])
    case(sec, "trap missing trap OID", "trap", ["-On"] + V2 + [X, "1"])
    case(sec, "trap bad trap OID", "trap", ["-On"] + V2 + [X, "1", "foo"])
    case(sec, "trap bad uptime", "trap", ["-On"] + V2 + [X, "abc", ".1.3.6.1.6.3.1.1.5.1"], known=K_TRAP_UPTIME)
    case(sec, "trap uptime with blanks", "trap", ["-On"] + V2 + [X, " 5", ".1.3.6.1.6.3.1.1.5.1"])
    case(sec, "trap v1 generic [x] (atoi: 0)", "trap", ["-On"] + V1 + [X, ".1.3.6.1.4.1.8072", "192.0.2.1", "x", "0",
                                                                       "1"])
    case(sec, "trap v1 specific and uptime [5x]", "trap", ["-On"] + V1 + [X, ".1.3.6.1.4.1.8072", "192.0.2.1", "6",
                                                                          "5x", "5x"])
    case(sec, "trap v1 generic 7", "trap", ["-On"] + V1 + [X, ".1.3.6.1.4.1.8072", "192.0.2.1", "7", "0", "1"],
         known=K_STRICT)
    case(sec, "trap v1 bad agent address", "trap", ["-On"] + V1 + [X, ".1.3.6.1.4.1.8072", "nosuchhost.invalid", "6",
                                                                  "1", "1"])
    case(sec, "trap v1 agent address 1.2.3", "trap", ["-On"] + V1 + [X, ".1.3.6.1.4.1.8072", "1.2.3", "6", "1", "1"])
    case(sec, "trap v1 agent address localhost", "trap", ["-On"] + V1 + [X, ".1.3.6.1.4.1.8072", "localhost", "6",
                                                                        "1", "1"], known=K_NO_DNS)
    for n, extra in ((0, []), (1, [".1.3.6.1.4.1.8072"]), (2, [".1.3.6.1.4.1.8072", ""]),
                     (3, [".1.3.6.1.4.1.8072", "", "6"]), (4, [".1.3.6.1.4.1.8072", "", "6", "1"])):
        case(sec, "trap v1 with %d of 5 parameters" % n, "trap", ["-On"] + V1 + [X] + extra)
    case(sec, "trap v2c without parameters", "trap", ["-On"] + V2 + [X])
    case(sec, "trap -Ci (inform) timeout", "trap", ["-On", "-Ci"] + V2 + QUICK_FAIL + [X, "1", "1.3"])
    case(sec, "inform -Ci", "inform", ["-On", "-Ci"] + V2 + QUICK_FAIL + [X, "1", "1.3"])
    case(sec, "inform -Cx", "inform", ["-On", "-Cx"] + V2 + [X, "1", "1.3"])
    case(sec, "trap v3 -Z 5,0", "trap", ["-On", "-Z", "5,0", "-e", "0x8000000001020304"] + U_SHA + [X, "1", "1.3"])
    for z in ("abc", "5", "5,x", ",5"):
        case(sec, "trap v3 -Z [%s]" % z, "trap", ["-On", "-Z", z, "-e", "0x8000000001020304"] + U_SHA + [X, "1", "1.3"])
    case(sec, "inform v1", "inform", ["-On"] + V1 + [X, "1", ".1.3.6.1.6.3.1.1.5.1"])
    case(sec, "inform timeout", "inform", ["-On"] + V2 + QUICK_FAIL + [X, "1", ".1.3.6.1.6.3.1.1.5.1"])
    case(sec, "inform v3 timeout (discovery)", "inform", ["-On"] + U_SHA + QUICK_FAIL + [X, "1", ".1.3.6.1.6.3.1.1.5.1"])
    case(sec, "inform to snmptrapd", "inform", ["-On"] + V2 + [TRAPD, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    case(sec, "inform v3 to snmptrapd", "inform", ["-On"] + U_SHA_AES + [TRAPD, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    case(sec, "inform v3 wrong password to snmptrapd", "inform",
         ["-On"] + v3("u_sha", "authNoPriv", "SHA", authpass="wrongpass1") + QUICK_FAIL
         + [TRAPD, "1", ".1.3.6.1.4.1.8072.9999.3.0.99"])
    case(sec, "trap v2c", "trap", ["-On"] + V2 + [X, "1", ".1.3.6.1.6.3.1.1.5.1", B + ".1.1.0", "i", "1"])
    case(sec, "trap v3 without -e", "trap", ["-On"] + U_SHA + [X, "1", ".1.3.6.1.6.3.1.1.5.1"])
    # option errors
    opts = [
        ("missing OID", ["get"] + V2 + [D]),
        ("no agent", ["get"] + V2),
        ("no community", ["get", "-v2c", D, B + ".1.1.0"]),
        ("invalid version", ["get", "-v9", "-c", "public", D, B + ".1.1.0"]),
        ("unknown option", ["get", "-k"] + V2 + [D, B + ".1.1.0"]),
        ("unknown long option", ["get", "--nosuch"] + V2 + [D, B + ".1.1.0"]),
        ("-r without value", ["get"] + V2 + [D, B + ".1.1.0", "-r"]),
        ("-O unknown letter", ["get", "-OZ"] + V2 + [D, B + ".1.1.0"]),
        ("-C unknown letter get", ["get", "-Cx"] + V2 + [D, B + ".1.1.0"]),
        ("-C unknown letter walk", ["walk", "-Cx"] + V2 + [D, B]),
        ("-C unknown letter bulkwalk", ["bulkwalk", "-Cx"] + V2 + [D, B]),
        ("-C unknown letter bulkget", ["bulkget", "-Cx"] + V2 + [D, B]),
        ("-C unknown letter set", ["set", "-Cx"] + V2W + [D, B + ".20.1.0", "i", "42"]),
        ("-Cr without number", ["bulkget", "-Cr"] + V2 + [D, B]),
        ("-Cn without number bulkwalk", ["bulkwalk", "-Cn"] + V2 + [D, B]),
        ("-CE without OID", ["walk", "-CE"] + V2 + [D, B]),
        ("-CE bad OID", ["walk", "-CE", "foo"] + V2 + [D, B]),
        ("v3 without -u", ["get", "-v3", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("bad -l", ["get", "-v3", "-u", "u_sha", "-l", "nosuch", D, B + ".1.1.0"]),
        ("bad -a", ["get", "-v3", "-u", "u_sha", "-l", "authNoPriv", "-a", "SHA-999", "-A", AUTH, D, B + ".1.1.0"]),
        ("bad -x", ["get", "-v3", "-u", "u_sha_aes", "-l", "authPriv", "-a", "SHA", "-A", AUTH, "-x", "AES-999", "-X",
                    PRIV, D, B + ".1.1.0"]),
        ("short auth pass", ["get", "-v3", "-u", "u_sha", "-l", "authNoPriv", "-a", "SHA", "-A", "short", D,
                             B + ".1.1.0"]),
        ("authNoPriv without -A", ["get", "-v3", "-u", "u_sha", "-l", "authNoPriv", "-a", "SHA", D, B + ".1.1.0"]),
        ("authPriv without -X", ["get", "-v3", "-u", "u_sha_aes", "-l", "authPriv", "-a", "SHA", "-A", AUTH, "-x",
                                 "AES", D, B + ".1.1.0"]),
        ("bad -e", ["get", "-v3", "-e", "xyz", "-u", "u_sha", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("bad -t", ["get", "-t", "abc"] + V2 + [D, B + ".1.1.0"]),
        ("bad -r", ["get", "-r", "abc"] + V2 + [D, B + ".1.1.0"]),
        ("bad port", ["get"] + V2 + ["127.0.0.1:99999", B + ".1.1.0"]),
        ("unknown host", ["get"] + V2 + ["nosuchhost.invalid", B + ".1.1.0"]),
        ("bulkget v1", ["bulkget"] + V1 + [D, B + ".1"]),
        ("bulkwalk v1", ["bulkwalk"] + V1 + [D, B + ".1"]),
        ("walk two OIDs", ["walk"] + V2 + [D, B + ".1", B + ".2"]),
        ("-Cn negative", ["bulkget", "-Cn-1", "-Cr2"] + V2 + [D, B + ".1"]),
        ("-Cr negative bulkwalk", ["bulkwalk", "-Cr-1"] + V2 + [D, B + ".1"]),
        ("-Cr hex", ["bulkget", "-Cr0x3"] + V2 + [D, B + ".1"]),
        ("-Cr then letters", ["bulkwalk", "-Cr5p"] + V2 + [D, B + ".1"]),
        ("-Cr then a bad letter", ["bulkget", "-Cr5x"] + V2 + [D, B + ".1"]),
        ("-Cr not a number", ["bulkget", "-Crx"] + V2 + [D, B + ".1"]),
        ("-Cr separate number", ["bulkget", "-Cr", "5"] + V2 + [D, B + ".1"]),
        ("-Cr huge", ["bulkget", "-Cr99999999999"] + V2 + [D, B + ".1"]),
        ("-CE glued", ["walk", "-CE.1.3"] + V2 + [D, B]),
        ("-CEp OID", ["walk", "-CEp", B + ".1.3.0"] + V2 + [D, B + ".1"]),
        ("bulkwalk -CI", ["bulkwalk", "-CI"] + V2 + [D, B + ".15"]),
        ("bulkwalk -Ct", ["bulkwalk", "-Ct"] + V2 + [D, B + ".6"]),
        ("-e too short", ["get", "-v3", "-e", "0x0102", "-u", "u_sha", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("-e odd", ["get", "-v3", "-e", "0x01020", "-u", "u_sha", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("-e 33 octets", ["get", "-v3", "-e", "0x" + "01" * 33, "-u", "u_sha", "-l", "noAuthNoPriv", D,
                          B + ".1.1.0"]),
        ("-e without 0x", ["get", "-v3", "-e", SNMPD_ENGINE[2:], "-u", "u_sha", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("-e with blanks", ["get", "-v3", "-e", "80 00 1f 88 80 61 63 74 73 6e 6d 70 64", "-u", "u_sha", "-l",
                            "noAuthNoPriv", D, B + ".1.1.0"]),
        ("-E too short", ["get", "-v3", "-E", "0x0102", "-u", "u_sha", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("-E bad hex", ["get", "-v3", "-E", "xyz", "-u", "u_sha", "-l", "noAuthNoPriv", D, B + ".1.1.0"]),
        ("-t 1x", ["get", "-t", "1x", "-r", "0"] + V2 + [D, B + ".1.1.0"]),
        ("-t 0x1", ["get", "-t", "0x1", "-r", "0"] + V2 + [D, B + ".1.1.0"]),
        ("-t inf", ["get", "-t", "inf"] + V2 + [D, B + ".1.1.0"]),
        ("-t 0", ["get", "-t", "0"] + V2 + [D, B + ".1.1.0"]),
        ("-t -1", ["get", "-t", "-1"] + V2 + [D, B + ".1.1.0"]),
        ("-r 1x", ["get", "-r", "1x"] + V2 + [D, B + ".1.1.0"]),
        ("-r blank 1", ["get", "-r", " 1"] + V2 + [D, B + ".1.1.0"]),
        ("-r -1", ["get", "-r", "-1"] + V2 + [D, B + ".1.1.0"]),
        ("-r 2147483648", ["get", "-r", "2147483648"] + V2 + [D, B + ".1.1.0"]),
        ("short auth pass, noAuthNoPriv", ["get", "-v3", "-u", "u_sha", "-l", "noAuthNoPriv", "-A", "short", D,
                                           B + ".1.1.0"]),
        ("short priv pass", ["get", "-v3", "-u", "u_sha_aes", "-l", "authPriv", "-a", "SHA", "-A", AUTH, "-x", "AES",
                             "-X", "short", D, B + ".1.1.0"]),
        ("short auth and priv pass", ["get", "-v3", "-u", "u_sha_aes", "-l", "authPriv", "-A", "short", "-X", "short",
                                      D, B + ".1.1.0"]),
        ("unknown host with udp:", ["get"] + V2 + ["udp:nosuchhost.invalid:161", B + ".1.1.0"]),
        ("help", ["get", "-h"]),
        ("unknown command letter -k", ["get", "-k"] + V2 + [D, B + ".1.1.0"]),
        ("set empty type", ["set"] + V2W + [X, B + ".20.1.0", "", "5"]),
    ]
    for name, argv in opts:
        case(sec, name, argv[0], ["-On"] + argv[1:], known=K_ERRNO if name == "bad port" else None)
    case(sec, "default version", "get", ["-On", "-c", "public", D, B + ".1.1.0"], known=K_DEFAULT_VERSION)
    case(sec, "version", "get", ["-V"], known=K_VERSION)
    case(sec, "-CE as the last argument", "walk", ["-On"] + V2 + [D, B, "-CE"], known=K_CE_LAST, timeout=10)


def build_cases():
    dataset_cases()
    output_cases()
    walk_option_cases()
    address_cases()
    timeout_cases()
    v3_error_cases()
    error_status_cases()
    pathological_cases()
    local_error_cases()
    set_cases()
    tcp_cases()
    mib_cases()


# ------------------------------------------------------------------ MIBs ---
#
# The "mib" section runs both tools with MIBs loaded: the same -M directories (copied into the tools container at
# the same absolute paths, so file names in messages agree) and the same -m lists:
#
#   GOLDEN   interop/mibs/golden/mibs (the committed IETF/IANA/net-snmp golden modules)
#   LABMIBS  interop/mibs/lab (ACTSNMP-LAB-MIB: types, hints, enumerations, BITS and indexes for the lab dataset B)
#   NSMIBS   interop/results/mibs-netsnmp/{mibs,iana,ietf}: the MIB directories of the lab image's net-snmp
#            (net-snmp's own modules and snmp-mibs-downloader's IETF/IANA set), copied out of the container
#
# snmpd serves volatile data (interfaces, ip, host resources, counters): the section takes a snapshot of its whole
# MIB (snmpbulkwalk -On -Oe -Ox, converted to snmprec) and serves it with `actsnmp agent` on SNAP (16167), so both
# tools walk identical values; only sysUpTime.0 (the agent's own) changes, its lines are dropped (UPTIME_LINES).
# The lab dataset B is static in snmpd and snmpsim and is walked there with ACTSNMP-LAB-MIB.

GOLDEN = os.path.join(REPO, "interop", "mibs", "golden", "mibs")
LABMIBS = os.path.join(REPO, "interop", "mibs", "lab")
NSMIBS = os.path.join(REPO, "interop", "results", "mibs-netsnmp")
NSPATH = ":".join(os.path.join(NSMIBS, d) for d in ("mibs", "mibs/iana", "mibs/ietf"))
LABPATH = GOLDEN + ":" + LABMIBS
SNAP_FILE = os.path.join(REPO, "interop", "results", "mib-snapshot.snmprec")
SNAP_PORT = 16167
SNAP = "127.0.0.1:%d" % SNAP_PORT
GOLDEN_MODS = ("SNMPv2-MIB:IF-MIB:IP-MIB:HOST-RESOURCES-MIB:UCD-SNMP-MIB:NET-SNMP-MIB:TCP-MIB:UDP-MIB:"
               "SNMP-FRAMEWORK-MIB:SNMP-VIEW-BASED-ACM-MIB:SNMP-USER-BASED-SM-MIB:SNMP-TARGET-MIB:IP-FORWARD-MIB")
LAB_MODS = "ACTSNMP-LAB-MIB:SNMPv2-MIB:NET-SNMP-MIB:IF-MIB"
MG = ["-M", GOLDEN, "-m", GOLDEN_MODS]
ML = ["-M", LABPATH, "-m", LAB_MODS]
MN = ["-M", NSPATH, "-m", "ALL"]

# sysUpTime.0 of the snapshot agent (any OID style) is the only value that changes between the two runs
UPTIME_LINES = [(r"(?m)^.*(?:sysUpTime|\.1\.3\.6\.1\.2\.1\.1\.3\.0|iso\.3\.6\.1\.2\.1\.1\.3\.0|system\.3\.0).*\n", "")]
# net-snmp's MIB parser reports syntax it does not like (actsnmp's compiler accepts it, `actsnmp miblint` lists
# its own diagnostics): these lines are dropped from both outputs
NS_PARSER = [(r"(?m)^(?:Bad operator|Bad month in timestamp|Expected |Warning: |Unlinked OID|Undefined identifier"
              r"|Cannot adopt OID|Bad parse of|Unknown token|.* \(is a reserved word\)).*: At line \d+ in .*\n", "")]

K_NS_PARSER = ("net-snmp's MIB parser differs: it links no object of DPI20-MIB (no message), gives the children "
               "of ISDN-MIB's isdnMibTrapPrefix (registered at the same OID as isdnMibConformance) to "
               "isdnMibConformance, and numbers its anonymous nodes (anonymous#N, shown by -Tp and -Td) in an order "
               "actsnmp does not reproduce")
K_NS_CRASH = ("snmptranslate crashes (SIGSEGV) on -IS or -Is followed by a separate argument (snmp_in_options reads "
              "a NULL argv); actsnmp takes the argument as the prefix or suffix, which translate then ignores as "
              "snmptranslate ignores -ISPREFIX")
K_INDEX_WRAP = ("with -Ir net-snmp takes an index sub-identifier above 4294967295 and sends it modulo 2^32; "
                "actsnmp refuses it (its encoders are strict)")

# OIDs whose -Td or -OS output differs for the reasons of K_NS_PARSER (net-snmp's MIB directories, -m ALL)
NS_KNOWN_OIDS = [".1.3.6.1.2.1.10.94.1.2.1.0", ".1.3.6.1.2.1.10.94.1.2.2.0", ".1.3.6.1.2.1.22.0",
                 ".1.3.6.1.2.1.10.20.2.0", ".1.3.6.1.2.1.10.20.2.0.1", ".1.3.6.1.4.1.2"]

MIB_LISTS = {}


def _docker(*args, check=True):
    return subprocess.run(["docker"] + list(args), capture_output=True, check=check)


def _copy_into_container(path):
    # the host directory at the same absolute path in the tools container (readable by its user)
    _docker("exec", "-u", "root", TOOLS_CONTAINER, "rm", "-rf", path)
    _docker("exec", "-u", "root", TOOLS_CONTAINER, "mkdir", "-p", os.path.dirname(path))
    _docker("cp", path, "%s:%s" % (TOOLS_CONTAINER, path))
    _docker("exec", "-u", "root", TOOLS_CONTAINER, "chmod", "-R", "a+rX", path)


def _canon_to_snmprec(lines):
    # interop canonical lines (tools/netsnmp2canon.py) to snmprec records, sorted by OID
    recs = []
    for line in lines:
        m = re.match(r"^\.([0-9.]+) = (.*)$", line)
        if not m:
            continue
        oid, v = m.group(1), m.group(2)

        def hx(t):
            return "".join(t.split()).lower()
        if v.startswith("INTEGER: "):
            recs.append("%s|2|%s" % (oid, v[9:]))
        elif v == 'STRING: ""':
            recs.append("%s|4x|" % oid)
        elif v.startswith('STRING: "'):
            body = v[9:-1].replace('\\"', '"').replace("\\\\", "\\")
            recs.append("%s|4x|%s" % (oid, body.encode("latin-1").hex()))
        elif v.startswith("Hex-STRING: "):
            recs.append("%s|4x|%s" % (oid, hx(v[12:])))
        elif v.startswith("OID: "):
            recs.append("%s|6|%s" % (oid, v[5:].lstrip(".")))
        elif v.startswith("IpAddress: "):
            recs.append("%s|64x|%s" % (oid, bytes(int(x) for x in v[11:].split(".")).hex()))
        elif v.startswith("Opaque: "):
            recs.append("%s|68x|%s" % (oid, "" if v[8:] == '""' else hx(v[8:])))
        elif v == "NULL":
            recs.append("%s|5|" % oid)
        else:
            for t, tag in (("Counter32", 65), ("Gauge32", 66), ("Timeticks", 67), ("Counter64", 70)):
                if v.startswith(t + ": "):
                    recs.append("%s|%d|%s" % (oid, tag, v[len(t) + 2:]))
    recs.sort(key=lambda r: [int(x) for x in r.split("|")[0].split(".")])
    return recs


def mib_setup(cli):
    """Prepare the "mib" section: MIB directories in the tools container, the OID lists for translate, the
    snapshot of snmpd and `actsnmp agent` serving it (returned, the caller stops it)"""
    os.makedirs(NSMIBS, exist_ok=True)
    if not os.path.isdir(os.path.join(NSMIBS, "mibs", "ietf")):
        tmp = os.path.join(NSMIBS, "mibs")
        if os.path.exists(tmp):
            subprocess.run(["rm", "-rf", tmp], check=True)
        _docker("cp", "%s:/usr/share/snmp/mibs" % TOOLS_CONTAINER, tmp)
        for d in ("iana", "ietf"):
            link = os.path.join(tmp, d)
            if os.path.islink(link):
                os.unlink(link)
            _docker("cp", "%s:/var/lib/mibs/%s" % (TOOLS_CONTAINER, d), link)
    for d in (GOLDEN, LABMIBS, NSMIBS):
        _copy_into_container(d)

    def oids(path, report):
        p = _docker("exec", TOOLS_CONTAINER, "snmptranslate", "-M", path, "-m", "ALL", report, check=False)
        return [x for x in p.stdout.decode("utf-8", "replace").split("\n") if x.startswith(".")]
    MIB_LISTS["golden"] = oids(GOLDEN, "-To")
    MIB_LISTS["golden-sym"] = oids(GOLDEN, "-Ts")
    MIB_LISTS["netsnmp"] = [o for o in oids(NSPATH, "-To") if o not in NS_KNOWN_OIDS]
    # the snapshot of snmpd: net-snmp's own walk, canonical, as snmprec
    sys.path.insert(0, os.path.join(HERE, "tools"))
    import netsnmp2canon
    p = _docker("exec", TOOLS_CONTAINER, "snmpbulkwalk", "-On", "-Oe", "-Ox", "--hexOutputLength=0", "-Cr50",
                "-v2c", "-c", "public", D, ".1.3")
    canon = []
    for line in p.stdout.decode("latin-1").split("\n"):
        if line.strip():
            try:
                c = netsnmp2canon.convert_line(line)
            except ValueError:
                c = None
            if c:
                canon.append(c)
    with open(SNAP_FILE, "w") as f:
        f.write("\n".join(_canon_to_snmprec(canon)) + "\n")
    agent = subprocess.Popen([cli, "agent", "--snmprec", SNAP_FILE, "--port", str(SNAP_PORT)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    t0 = time.time()
    while time.time() - t0 < 30:
        r = run(["docker", "exec", TOOLS_CONTAINER, "snmpget", "-v2c", "-c", "public", "-r0", "-t1", SNAP,
                 ".1.3.6.1.2.1.1.1.0"], 5)
        if r.rc == 0:
            break
        time.sleep(0.5)
    MIB_LISTS["walk-names"] = []
    return agent


def _chunks(lst, n):
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def mib_cases():
    sec = "mib"
    W = B + ".20"
    tr = "translate"
    nt = "snmptranslate"
    # translate (snmptranslate) over every OID net-snmp knows with the golden modules
    gold = MIB_LISTS.get("golden", [])
    if gold:
        for o in ("-On", "-OS", "-Of", "-Os", "-Ou", "-Td"):
            case(sec, "translate golden ALL, %d OIDs %s" % (len(gold), o), tr, ["-M", GOLDEN, "-m", "ALL", o] + gold,
                 net_tool=nt, normalize=NS_PARSER)
        case(sec, "translate golden ALL, %d names -On" % len(MIB_LISTS["golden-sym"]), tr,
             ["-M", GOLDEN, "-m", "ALL", "-On"] + MIB_LISTS["golden-sym"], net_tool=nt, normalize=NS_PARSER)
    case(sec, "translate golden ALL -Tp", tr, ["-M", GOLDEN, "-m", "ALL", "-Tp"], net_tool=nt, normalize=NS_PARSER)
    # ... and with the MIB directories of net-snmp itself (about 370 modules)
    ns = MIB_LISTS.get("netsnmp", [])
    for k, ch in enumerate(_chunks(ns, 3000)):
        for o in ("-OS", "-Td"):
            case(sec, "translate net-snmp ALL, OIDs %d-%d %s" % (k * 3000 + 1, k * 3000 + len(ch), o), tr,
                 MN + [o] + ch, net_tool=nt, normalize=NS_PARSER, quick=False)
    case(sec, "translate net-snmp ALL, the OIDs it treats differently -Td", tr, MN + ["-Td"] + NS_KNOWN_OIDS,
         net_tool=nt, normalize=NS_PARSER, known=K_NS_PARSER)
    case(sec, "translate net-snmp ALL -Tp", tr, MN + ["-Tp"], net_tool=nt, normalize=NS_PARSER, known=K_NS_PARSER,
         quick=False)
    # translate options and errors
    T = [
        ("labels -IR", ["-IR", "-On", "sysDescr", "ifInOctets", "labIfMtu", "labStrFlags", "hrStorageDescr"]),
        ("-Td -w 40", ["-Td", "-w", "40", "labIfEntry", ".1.3.6.1.4.1.8072.9999.1.0.1", "IF-MIB::ifEntry",
                       "IF-MIB::ifOperStatus", "IF-MIB::ifType"]),
        ("-Td of the lab MIB's objects", ["-Td", "ACTSNMP-LAB-MIB::labStrFlags", "ACTSNMP-LAB-MIB::labIntKeywords",
                                          "ACTSNMP-LAB-MIB::labBigEntry", "ACTSNMP-LAB-MIB::labIfXEntry",
                                          "ACTSNMP-LAB-MIB::labStrAlias", "ACTSNMP-LAB-MIB::labOpaqueFloat"]),
        ("-Tp -w 30", ["-Tp", "-w", "30", "IF-MIB::ifTable"]),
        ("-Tp lab MIB", ["-Tp", ".1.3.6.1.4.1.8072.9999.1"]),
        ("unknown name", ["nosuch"]),
        ("unknown name -IR", ["-IR", "nosuch"]),
        ("names, instances, indexes -On", ["-On", "sysDescr.0", "IF-MIB::ifDescr.1", ".iso.org.dod",
                                           'labIfMtu."eth0"', 'ACTSNMP-LAB-MIB::labIfMtu."eth0"', "labBigName.65"]),
        ("-Tp unknown name", ["-Tp", "nosuch"]),
        ("-Tp of a leaf", ["-Tp", ".1.3.6.1.2.1.1.1"]),
        ("-Ou input", ["-Ou", "-On", "interfaces.ifTable"]),
        ("-Iu input", ["-Iu", "-On", "interfaces.ifTable"]),
        ("-Ib regular expression", ["-Ib", "-On", "if.*Descr"]),
        ("-Ib no match", ["-Ib", "nomatchzzz"]),
        ("-Ib several names (reported nodes)", ["-Ib", "-On", "ifdescr", "IFDESCR", "sys", "if.*Speed", "sys"]),
        ("-IR index range and C numbers", ["-IR", "-On", "ifDescr.0x10", "ifDescr.077", "ifDescr.2147483647",
                                            "ifDescr.0"]),
        ("-TB", ["-TB", "if.*Descr", "sysDescr"]),
        ("-TB -Td", ["-TB", "-Td", "lab.*Mtu"]),
        ("-TB -OS", ["-TB", "-OS", "ifIn"]),
        ("-TB no match", ["-TB", "zzzz"]),
        ("-O unknown letter", ["-OZ", "sysDescr.0"]),
        ("-T unknown letter", ["-Tx", "sysDescr.0"]),
        ("no OID", []),
    ]
    for name, args in T:
        case(sec, "translate " + name, tr, ML + args, net_tool=nt)
    # labels that several modules define (NET-SNMP-TC and UCD-SNMP-MIB: linux, unknown, ...): get_wild_node gives the
    # newest node of the label it matched (get_node of the label), -TB prints that node for every match
    for args in (["-On", "-Ib", "linux"], ["-On", "-Ib", "unknown"], ["-On", "-Ib", "hpux10"], ["-On", "-Ib", "^lin"],
                 ["-TB", "linux"], ["-TB", "-OS", "^(linux|win32)$"], ["-TB", "-Td", "^solaris$"]):
        case(sec, "translate golden ALL " + " ".join(args), tr, ["-M", GOLDEN, "-m", "ALL"] + args, net_tool=nt,
             normalize=NS_PARSER)
    # quoted index strings with a DISPLAY-HINT (MacAddress 1x:, SIZE 6): net-snmp's lenient parse_octet_hint, the
    # characters where it fails; each error ends snmptranslate, so one case per error
    FDB = "BRIDGE-MIB::dot1dTpFdbPort."
    MB = ["-M", GOLDEN, "-m", "BRIDGE-MIB", "-On"]
    case(sec, "translate hinted index forms", tr, MB + [FDB + "'0:1a:2b:3c:4d:5e'", FDB + "'00:1A:2B:3C:4D:5E'",
                                                       FDB + "'0x0:0x1a: 2b:+3c:4d:5e'", FDB + "'1a::2b'", FDB + "'ffff:1:2:3:4:5'"],
         net_tool=nt)
    case(sec, "translate hinted index -Ir", tr, MB + ["-Ir", FDB + "'abcdef'", FDB + "'abc'", FDB + "'zz'", FDB + "'-1:2'",
                                                       FDB + "'1a2b:3c'", FDB + "'1:2:'", FDB + "''"], net_tool=nt)
    case(sec, "translate hinted index -Ih", tr, MB + ["-Ih", FDB + "'abcdef'"], net_tool=nt)
    for v in ("'abcdef'", "'zz'", "'1:2:3'"):
        case(sec, "translate hinted index error %s" % v, tr, MB + [FDB + v], net_tool=nt)
    case(sec, "translate -IS prefix", tr, ML + ["-IS", "IF-MIB::", "-On", "ifDescr.1"], net_tool=nt, known=K_NS_CRASH)
    case(sec, "translate a module not found", tr, ["-M", GOLDEN, "-m", "NOPE-MIB:IF-MIB", "-On", "ifDescr.1"],
         net_tool=nt)
    case(sec, "translate no MIB directory (line 0)", tr, ["-M", "/nonexistent-mib-dir", "-m", "IF-MIB", "-On",
                                                          "ifDescr", "IF-MIB::ifDescr", "NOPE-MIB::x"], net_tool=nt)
    case(sec, "translate modules named only by the OIDs", tr, ["-M", GOLDEN, "-On", "IF-MIB::ifDescr", "sysDescr.0",
                                                                "SNMPv2-MIB::sysDescr.0", "NOPE-MIB::x"], net_tool=nt)
    case(sec, "translate MIBDIRS and MIBS", tr, ["-On", "ifDescr.1", "labIfMtu"], net_tool=nt,
         env={"MIBDIRS": LABPATH, "MIBS": "IF-MIB:ACTSNMP-LAB-MIB"})
    # (the default directories differ between the image and the host: every case sets the directories)
    case(sec, "translate -M twice (the last one counts)", tr, ["-M", "/nonexistent", "-M", GOLDEN, "-m", "IF-MIB",
                                                               "-On", "IF-MIB::ifDescr.1"], net_tool=nt)

    # walks of the snmpd snapshot with the golden modules, every -O style
    flagsets = ["", "-Of", "-Ou", "-On", "-Os", "-OS", "-Oe", "-Ob", "-OX", "-OE", "-Oq", "-OQ", "-Ot", "-OU", "-Ox",
                "-Oa", "-OT", "-O0", "-OXs", "-OXb", "-OEs", "-Oqs", "-OQs", "-Ofn", "-OfX", "-OuX", "-Oxa",
                "-OQq", "-OQQ"]
    for f in flagsets:
        case(sec, "snapshot bulkwalk golden %s" % (f or "(default)"), "bulkwalk",
             MG + ([f] if f else []) + V2 + ["-Cr50", SNAP, ".1.3"], normalize=UPTIME_LINES)
    case(sec, "snapshot bulkwalk golden -Ov (from interfaces)", "bulkwalk",
         MG + ["-Ov"] + V2 + ["-Cr50", SNAP, ".1.3.6.1.2.1.2"])
    case(sec, "snapshot walk golden ifTable", "walk", MG + V2 + [SNAP, "IF-MIB::ifTable"])
    case(sec, "snapshot bulkwalk golden ALL", "bulkwalk", ["-M", GOLDEN, "-m", "ALL"] + V2 + ["-Cr50", SNAP, ".1.3"],
         normalize=UPTIME_LINES + NS_PARSER)
    case(sec, "snapshot bulkwalk net-snmp ALL", "bulkwalk", MN + V2 + ["-Cr50", SNAP, ".1.3"],
         normalize=UPTIME_LINES + NS_PARSER, quick=False)
    case(sec, "snapshot getnext and bulkget names", "getnext", MG + V2 + [SNAP, "sysDescr", "ifTable", "ifDescr.999",
                                                                         "hrStorageDescr"])
    case(sec, "snapshot bulkget -Cn1 -Cr3", "bulkget", MG + ["-Cn1", "-Cr3"] + V2 + [SNAP, "sysDescr", "ifDescr"])
    G = [
        ("names and instances", ["sysDescr.0", "SNMPv2-MIB::sysName.0", "ifDescr.1", "IF-MIB::ifOperStatus.2",
                                 ".1.3.6.1.2.1.1.5.0", "iso.3.6.1.2.1.1.6.0"]),
        ("string and enum indexes", ['SNMP-VIEW-BASED-ACM-MIB::vacmAccessReadViewName."grp_public"."".0.noAuthNoPriv',
                                     'vacmAccessReadViewName."grp_public"."".0.1',
                                     'IP-MIB::ipAddressPrefixOrigin.1.ipv4."127.0.0.0".8',
                                     'ipAddressPrefixOrigin[1][ipv4]["127.0.0.0"][8]']),
        ("-IR", ["-IR", "sysDescr.0", "ifInOctets.1", "hrStorageDescr.1"]),
        ("bad names (stale detail)", ["nosuchname.0", "sysDescr.0", "IF-MIB::nosuch.1", "NOPE-MIB::x",
                                      "ifDescr.notanumber", 'ifDescr."x"', "NOPE-MIB::y", "NOPE2-MIB::z",
                                      "NOPE-MIB::w"]),
        ("regular expression last resort", ["ifD", "sysUp", "if.*Descr"]),
        ("-Ib", ["-Ib", "ifDescr", "if.*Speed"]),
        ("C numbers in instances", ["ifDescr.0x3", "ifDescr.010", "ifDescr.1.2"]),
    ]
    for name, args in G:
        opts = [a for a in args if a.startswith("-I")]
        oids_ = [a for a in args if not a.startswith("-I")]
        case(sec, "snapshot get " + name, "get", MG + opts + V2 + [SNAP] + oids_)
    case(sec, "snapshot get -Is and -IS with separate arguments", "get",
         MG + ["-Is", ".0"] + V2 + [SNAP, "sysDescr", "sysName", "-IRS", "SNMPv2-MIB::"])
    case(sec, "snapshot getnext -Is with a separate argument", "getnext", MG + V2 + ["-Is", "1", SNAP, "ifDescr"])
    case(sec, "snapshot get, modules named only by the OIDs", "get",
         ["-M", GOLDEN] + V2 + [SNAP, "sysDescr.0", "SNMPv2-MIB::sysDescr.0", "IF-MIB::ifDescr.1", "NOPE-MIB::x",
                                "ifDescr.2", "RMON2-MIB::probeDateTime.0"])
    case(sec, "snapshot get, no MIB directory (line 0)", "get", ["-M", "/nonexistent-mib-dir"] + V2
         + [SNAP, "IF-MIB::ifDescr.1", "NOPE-MIB::x", ".1.3.6.1.2.1.1.1.0"])
    case(sec, "snapshot walk of a module not found", "walk", ["-M", GOLDEN, "-m", "NOPE:IF-MIB"] + V2
         + [SNAP, "NOPE-MIB::x"])
    case(sec, "snapshot getnext, modules named only by the OIDs", "getnext",
         ["-M", GOLDEN] + V2 + [SNAP, "IF-MIB::ifDescr", "RMON-MIB::etherStatsTable"])
    case(sec, "snapshot get MIBS and MIBDIRS", "get", V2 + [SNAP, "sysDescr.0", "ifDescr.1"],
         env={"MIBDIRS": GOLDEN, "MIBS": "SNMPv2-MIB:IF-MIB"})
    case(sec, "snapshot get MIBS=+IF-MIB (net-snmp's default list)", "get", V2 + [SNAP, "ifDescr.1"],
         env={"MIBDIRS": GOLDEN, "MIBS": "+IF-MIB"})
    case(sec, "snapshot get MIBDIRS and -M +DIR", "get", ["-M", "+" + LABMIBS, "-m", "IF-MIB:ACTSNMP-LAB-MIB"] + V2
         + [SNAP, "ifDescr.1", "labIfMtu"], env={"MIBDIRS": GOLDEN})
    case(sec, "snapshot get MIBDIRS=+DIR and -M -DIR", "get", ["-M", "-" + LABMIBS, "-m", "IF-MIB:ACTSNMP-LAB-MIB"]
         + V2 + [SNAP, "ifDescr.1"], env={"MIBDIRS": GOLDEN})
    case(sec, "snapshot table ifDescr (sorted, vs snmpbulkwalk)", "table", MG + V2 + [SNAP, "IF-MIB::ifDescr"],
         cmp="sorted", net_tool="snmpbulkwalk", net_args=MG + V2 + [SNAP, "IF-MIB::ifDescr"])
    case(sec, "lab table labIfMtu (sorted, vs snmpbulkwalk)", "table", ML + ["-OX"] + V2 + [D, "labIfMtu"],
         cmp="sorted", net_tool="snmpbulkwalk", net_args=ML + ["-OX"] + V2 + [D, "labIfMtu"])

    # the lab dataset with ACTSNMP-LAB-MIB on snmpd and snmpsim
    for ag, a in (("snmpd", D), ("snmpsim", S)):
        for f in ("", "-Of", "-On", "-Oe", "-Ob", "-OX", "-OE", "-Oq", "-OQ", "-Ov", "-Ot", "-OU", "-Ox", "-Oa",
                  "-OT", "-O0", "-Os", "-OXs", "-OqX", "-Ox0", "-OxT", "-OeU", "-Ih", "-Ih -OX"):
            case(sec, "%s lab dataset %s" % (ag, f or "(default)"), "bulkwalk", ML + f.split() + V2 + ["-Cr50", a, B])
        case(sec, "%s lab dataset walk v1" % ag, "walk", ML + V1 + [a, B + ".2"])
        case(sec, "%s lab get indexes" % ag, "get", ML + V2 + [a] + [
            'labIfMtu."eth0"', "labIfMtu.4.101.116.104.49", 'ACTSNMP-LAB-MIB::labIfAdmin."ge-0/0/3"',
            'labIfMtu."nosuch"', "labName.7", "labName.0", "labBigName.65", "labIntEnum.0", "labStrFlags.0",
            "labNotifications", "labStateChange"])
        case(sec, "%s lab get index errors" % ag, "get", ML + V2 + [a] + [
            "labIfMtu.eth0", "labIfMtu.'eth0'", "labBigName.'A'", 'labBigName."A"', 'labIfMtu."ab"x',
            'labIfMtu."a\\"b"', 'labIfMtu."unterminated', 'labIfMtu.""', 'labName."x"', "labIfMtu.3.97.98",
            "labIfMtu.3.97.98.300", "labName.-1", "labIntEnum.0.1", 'labIfXAlias."eth0"', "labIfAdmin.up",
            'labIfMtu."nosuchname-that-is-much-longer-than-sixty-four-characters-in-total-xxxxxxxxx"'])
        case(sec, "%s lab get -Ir" % ag, "get", ML + ["-Ir"] + V2 + [a] + [
            'labIfMtu."nosuchname-that-is-much-longer-than-sixty-four-characters-in-total-xxxxxxxxx"',
            "labIfMtu.3.97.98.300", 'labName."x"'])
        case(sec, "%s lab get -Ir index above 2^32-1" % ag, "get", ML + ["-Ir"] + V2 + [a, "labName.4294967296"],
             known=K_INDEX_WRAP)
        case(sec, "%s lab get -OX form input (refused)" % ag, "get", ML + ["-OX"] + V2 + [a, 'labIfMtu["eth0"]', "labName[7]"])
        sets = [
            ("typed", [W + ".1.0", "i", "43", "labWString.0", "s", "hello", "labWOid.0", "o", "sysDescr.0",
                       "labWAddr.0", "a", "10.0.0.1", "labWGauge.0", "u", "5", "labWTicks.0", "t", "100"]),
            ("=", ["labWInt.0", "=", "44", "labWString.0", "=", "hi", "labWOid.0", "=", "labWInt", "labWAddr.0", "=",
                   "10.0.0.2", "labWGauge.0", "=", "6", "labWTicks.0", "=", "200"]),
            ("out of range", ["labWRange.0", "=", "101"]),
            ("enumeration labels", ["labWRange.0", "i", "50", "labWReadOnly.0", "=", "eight"]),
            ("enumeration label read-only", ["labWReadOnly.0", "=", "seven"]),
            ("string too long", ["labWString.0", "=", "y" * 40]),
            ("wrong types", ["labWString.0", "x", "41 42", "labWInt.0", "s", "bad", "labWAddr.0", "i", "5"]),
            ("restore", [W + ".1.0", "i", "42", "labWString.0", "s", "initial", "labWOid.0", "o", ".1.3.6.1",
                         "labWAddr.0", "a", "192.0.2.1", "labWGauge.0", "u", "0", "labWTicks.0", "t", "0",
                         "labWRange.0", "i", "50"]),
        ]
        for name, args in sets:
            case(sec, "%s lab set %s" % (ag, name), "set", ML + V2W + [a] + args, serial=True)
        case(sec, "%s lab set -Ir wrong type" % ag, "set", ML + ["-Ir"] + V2W + [a, "labWString.0", "i", "5"],
             serial=True)
        case(sec, "%s lab initial values" % ag, "bulkwalk", ML + V2 + [a, W], serial=True)
    # SNMPv3 session errors after a label lookup: net-snmp's snmp_sess_perror appends the detail read_objid left
    for t, extra in (("get", ["sysDescr.0", "IF-MIB::ifDescr.1"]), ("walk", ["sysORDescr"]),
                     ("bulkget", ["sysDescr", "ifDescr"]), ("set", ["sysContact.0", "s", "x"])):
        case(sec, "snmpd v3 unknown user, %s by name" % t, t, MG + v3("u_nosuch", "noAuthNoPriv") + QUICK_FAIL + [D]
             + extra, serial=(t == "set"))
        case(sec, "snmpd v3 wrong auth password, %s by name" % t, t, MG + v3("u_sha", "authNoPriv", "SHA",
                                                                               authpass="wrongpass1") + QUICK_FAIL
             + [D] + extra, serial=(t == "set"))
    case(sec, "snmpd v3 no user, getnext by name", "getnext", MG + ["-v3", "-l", "authNoPriv", "-A", AUTH]
         + QUICK_FAIL + [D, "sysDescr"])
    case(sec, "snmpd v3 no auth pass phrase, bulkwalk by name", "bulkwalk", MG + ["-v3", "-u", "u_sha", "-l",
                                                                                  "authNoPriv"] + QUICK_FAIL + [D, "system"])
    case(sec, "v3 discovery timeout, get by name", "get", MG + U_SHA + QUICK_FAIL + [X, "sysDescr.0"])
    case(sec, "v3 discovery timeout, MOD::name only", "walk", MG + U_SHA + QUICK_FAIL + [X, "SNMPv2-MIB::system"])
    case(sec, "v2c timeout by name", "get", MG + V2 + QUICK_FAIL + [X, "sysDescr.0"])
    case(sec, "snmpd v3 trap -Ci no auth pass phrase by name", "trap", MG + ["-v3", "-u", "u_sha", "-l", "authNoPriv",
                                                                             "-Ci"] + QUICK_FAIL
         + [D, "", "coldStart", "sysContact.0", "s", "x"])
    # snmpd's own writable objects by name (restored)
    case(sec, "snmpd set sysContact by name", "set", MG + V2W + [D, "SNMPv2-MIB::sysContact.0", "=", "mib contact"],
         serial=True)
    case(sec, "snmpd set errors by name", "set", MG + V2W + [D, "sysContact.0", "i", "5", "sysServices.0", "i", "999"],
         serial=True)
    case(sec, "snmpd set noAccess by name", "set", MG + V2W + [D, "ifAdminStatus.1", "i", "up"], serial=True)
    case(sec, "snmpd set sysContact restore", "set", MG + V2W + [D, "sysContact.0", "s", "actsnmp-contact"],
         serial=True)
    # trap and inform arguments by name (to the lab snmptrapd)
    TR = [
        ("v2c names and = values", ["''", "labStateChange", 'labIfAdmin."eth0"', "=", "up", 'labIfMtu."eth0"', "i",
                                    "1500"]),
        ("bad enumeration label", ["''", "ACTSNMP-LAB-MIB::labStateChange", 'labIfAdmin."eth0"', "=", "bogus"]),
        ("unknown trap OID", ["''", "nosuchtrap"]),
        ("bad index", ["''", "labStateChange", "labIfAdmin.nosuch", "i", "1"]),
        ("BITS by name", ["''", "labStateChange", "labStrFlags.0", "=", "b0 b31"]),
        ("unknown bit name", ["''", "labStateChange", "labStrFlags.0", "b", "b0 nosuchbit"]),
        ("DISPLAY-HINT value", ["''", "labStateChange", "labStrNul.0", "=", "0a"]),
    ]
    for name, args in TR:
        args = ["" if x == "''" else x for x in args]
        case(sec, "trap " + name, "trap", ML + V2 + [TRAPD] + args, serial=True)
    case(sec, "trap v1 by name", "trap", ML + V1 + [TRAPD, "actsnmpLabMIB", "127.0.0.1", "6", "1", "", "sysDescr.0",
                                                    "s", "hi"], serial=True)
    case(sec, "inform by name", "inform", ML + V2 + [TRAPD, "", "labStateChange", 'labIfAdmin."eth0"', "=", "up"],
         serial=True)


# ---------------------------------------------------------------- running ---

class Run:
    def __init__(self, rc, out, err, secs):
        self.rc, self.out, self.err, self.secs = rc, out, err, secs


def run(cmd, timeout, env=None):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                           env=dict(os.environ, **env) if env else None)
        return Run(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"),
                   time.time() - t0)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace")
        err = (e.stderr or b"").decode("utf-8", "replace")
        return Run(124, out, err + "[killed after %ss]\n" % timeout, time.time() - t0)


def normalize(text, rules):
    for pat, rep in rules:
        text = re.sub(pat, rep, text)
    return text


USAGE_RE = re.compile(r"(?ms)^USAGE: .*\Z")


def compare(c, net, ours):
    """-> list of difference descriptions (empty: equal)

    The usage text that follows a usage error is replaced by "<usage text>" on both sides: actsnmp's is its own.
    """
    diffs = []
    if net.rc != ours.rc:
        diffs.append("exit code: net-snmp %d, actsnmp %d" % (net.rc, ours.rc))
    no, ao = normalize(net.out, c.normalize), normalize(ours.out, c.normalize)
    ne, ae = normalize(net.err, c.normalize), normalize(ours.err, c.normalize)
    ne = USAGE_RE.sub("<usage text>\n", ne)
    ae = USAGE_RE.sub("<usage text>\n", ae)
    if c.cmp == "sorted":
        no = "".join(sorted(no.splitlines(True)))
        ao = "".join(sorted(ao.splitlines(True)))
    if c.cmp == "first-line":
        ne = ne.split("\n")[0]
        ae = ae.split("\n")[0]
    for what, a, b in (("stdout", no, ao), ("stderr", ne, ae)):
        if a != b:
            d = list(difflib.unified_diff(a.splitlines(True), b.splitlines(True), "net-snmp " + what,
                                          "actsnmp " + what, n=1))
            text = "".join(d[:40])
            if len(d) > 40:
                text += "... (%d more diff lines)\n" % (len(d) - 40)
            if not text.endswith("\n"):
                text += "\n"
            diffs.append(text)
    return diffs


def run_case(c, cli):
    envargs = []
    for k, v in sorted(c.env.items()):
        envargs += ["-e", "%s=%s" % (k, v)]
    net_cmd = ["docker", "exec"] + envargs + [TOOLS_CONTAINER, c.net_tool] + c.net_args
    our_cmd = [cli, c.tool] + c.args
    if c.serial:
        net = run(net_cmd, c.timeout)
        ours = run(our_cmd, c.timeout, c.env)
    else:
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            fn = ex.submit(run, net_cmd, c.timeout)
            fo = ex.submit(run, our_cmd, c.timeout, c.env)
            net, ours = fn.result(), fo.result()
    diffs = compare(c, net, ours)
    if not diffs:
        status = "PASS" if not c.known else "FIXED?"
    else:
        status = "KNOWN" if c.known else "FAIL"
    return status, diffs, net, ours


def shell_line(argv):
    import shlex
    return " ".join(shlex.quote(a) for a in argv)


def main(argv):
    cli = os.path.join(REPO, "out", "bin", "actsnmp")
    quick = False
    filt = None
    sections = None
    listing = False
    report = None
    jobs = 4
    verbose = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--cli":
            cli = argv[i + 1]
            i += 1
        elif a == "--quick":
            quick = True
        elif a == "--filter":
            filt = re.compile(argv[i + 1])
            i += 1
        elif a == "--section":
            sections = set(argv[i + 1].split(","))
            i += 1
        elif a == "--list":
            listing = True
        elif a == "--report":
            report = argv[i + 1]
            i += 1
        elif a == "--jobs":
            jobs = int(argv[i + 1])
            i += 1
        elif a == "-v":
            verbose = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            sys.stderr.write("unknown argument %s\n" % a)
            return 2
        i += 1
    want_mib = sections is None or "mib" in sections
    agent = None
    if want_mib and not listing:
        agent = mib_setup(cli)
    try:
        return run_all(cli, quick, filt, sections, listing, report, jobs, verbose)
    finally:
        if agent is not None:
            agent.terminate()
            try:
                agent.wait(5)
            except subprocess.TimeoutExpired:
                agent.kill()


SECTIONS = ("dataset", "output", "walk-options", "address", "timeout", "v3-errors", "error-status", "pathological",
            "local-errors", "set", "tcp", "mib")


def run_all(cli, quick, filt, sections, listing, report, jobs, verbose):
    build_cases()
    cases = [c for c in CASES if (not quick or c.quick) and (sections is None or c.section in sections)
             and (filt is None or filt.search(c.key()))]
    if listing:
        for c in cases:
            print("%-70s actsnmp %s %s" % (c.key(), c.tool, shell_line(c.args)))
        return 0
    t0 = time.time()
    results = {}

    def one(c):
        r = run_case(c, cli)
        tag = r[0]
        sys.stderr.write("[%s] %s (%.1fs/%.1fs)\n" % (tag, c.key(), r[2].secs, r[3].secs))
        return r

    # read-only cases of a section run in parallel; serial cases (SET, snmpsim delays) one at a time, in order
    order = []
    for c in cases:
        if not order or order[-1][0] != c.section:
            order.append((c.section, []))
        order[-1][1].append(c)
    for sec, cs in order:
        batch = []
        for c in cs + [None]:
            if c is not None and not c.serial:
                batch.append(c)
                continue
            if batch:
                with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
                    for cc, r in zip(batch, ex.map(one, batch)):
                        results[cc.key()] = r
                batch = []
            if c is not None:
                results[c.key()] = one(c)
    counts = {"PASS": 0, "FAIL": 0, "KNOWN": 0, "FIXED?": 0}
    lines = ["# actsnmp CLI vs net-snmp (%s, %.0f s)" % (time.strftime("%Y-%m-%d %H:%M"), time.time() - t0), ""]
    lines.append("CLI: `%s`; net-snmp: `docker exec %s snmp<TOOL>` (5.9.4); %d cases%s." %
                 (cli, TOOLS_CONTAINER, len(cases), " (--quick)" if quick else ""))
    lines.append("")
    lines.append("| section | cases | pass | fail | known | fixed? |")
    lines.append("|---|---|---|---|---|---|")
    for sec, cs in order:
        st = [results[c.key()][0] for c in cs]
        lines.append("| %s | %d | %d | %d | %d | %d |" % (sec, len(cs), st.count("PASS"), st.count("FAIL"),
                                                       st.count("KNOWN"), st.count("FIXED?")))
        for s in st:
            counts[s] += 1
    lines.append("| **total** | %d | %d | %d | %d | %d |" % (len(cases), counts["PASS"], counts["FAIL"],
                                                             counts["KNOWN"], counts["FIXED?"]))
    fails = [c for c in cases if results[c.key()][0] == "FAIL"]
    if fails:
        lines += ["", "## Failures", ""]
        for c in fails:
            st, diffs, net, ours = results[c.key()]
            lines.append("### %s" % c.key())
            lines.append("")
            lines.append("    actsnmp %s %s" % (c.tool, shell_line(c.args)))
            lines.append("")
            lines.append("```")
            lines.append("".join(d if d.endswith("\n") else d + "\n" for d in diffs).rstrip("\n"))
            lines.append("```")
            lines.append("")
    known = [c for c in cases if results[c.key()][0] in ("KNOWN", "FIXED?")]
    if known:
        lines += ["", "## Documented differences", ""]
        reasons = {}
        for c in known:
            reasons.setdefault(c.known, []).append(c)
        for why, cs in reasons.items():
            lines.append("- %s:" % why)
            for c in cs:
                st = results[c.key()][0]
                lines.append("  - %s%s" % (c.key(), " (**no longer differs**)" if st == "FIXED?" else ""))
                if verbose and st == "KNOWN":
                    for d in results[c.key()][1]:
                        lines.append("    " + d.rstrip("\n").replace("\n", "\n    "))
    lines.append("")
    lines.append("%d passed, %d failed, %d known differences, %d known but equal" %
                 (counts["PASS"], counts["FAIL"], counts["KNOWN"], counts["FIXED?"]))
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if report:
        with open(report, "w") as f:
            f.write(text)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
