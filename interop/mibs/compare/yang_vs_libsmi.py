#!/usr/bin/env python3
"""Compare actsnmp's RFC 6643 YANG (mib.yang) with libsmi 0.5.0 ``smidump -f yang``.

    python3 interop/mibs/compare/yang_vs_libsmi.py --ours DIR --libsmi DIR
        [--modules A,B,...] [--out FILE.md] [--show N] [--strict]

``--ours``: ``<MOD>.yang`` written by ``MIBYANG_OUT=<dir> acton test --module mib.test_yang
--name yang_golden`` (``<dir>/ref`` for the 9 reference MIBs). ``--libsmi``: the libsmi
output, ``interop/mibs/yang-examples/yang-libsmi-0.5.0`` for the reference MIBs.

Both sides are parsed into statement trees (comments dropped, strings unquoted by the RFC 6020
section 6.1.3 rules), then normalised:

- prefixes are replaced by module names (``if-mib:ifIndex`` -> ``IF-MIB:ifIndex``), in
  arguments of ``type``, ``base``, ``path`` and ``augment``;
- text arguments (``description``, ``reference``, ``contact``, ``organization``) are compared
  without trailing white space per line and without trailing empty lines; a remaining
  difference in leading white space only is L9;
- the substatements of a statement are compared as sets: data definitions, typedefs,
  identities, aliases, enums, bits, imports and revisions by (keyword, argument), properties
  (type, status, description, smiv2:oid, ...) by keyword. Order is not compared.

Every remaining difference must be explained by a documented deviation, else it is reported
as UNEXPLAINED (exit status 1). The deviations are libsmi's L1-L10 and our own decisions
(D1-D25):

- L1  ``smiv2:max-access "read-write"`` where the MIB says read-create;
- L2  octet ``length`` on hinted strings (omitted unless ``Na``/``Nt``; lower bound ceil(lo/4));
- L3  OBJECT-IDENTITY also as ``smiv2:alias``;
- L4  imports of RFC1155-SMI, RFC-1212, RFC-1215 and unused modules;
- L5  not-accessible scalars and non-index columns (we emit them);
- L6  SMIv1 informal DisplayString/PhysAddress as binary (we: string with the hint);
- L7  duplicate leaf names in notification containers (we: ``_n``);
- L8  scalar INDEX objects without a key leaf (we: a leafref);
- L9  white space in texts: trailing white space and trailing empty lines are normalised
      away; texts that still differ only in leading white space count as L9 (libsmi cuts every
      continuation line at the indent of the first one, we remove the common indent);
- L10 ambiguous scalar parents (libsmi only reports them);
- D1  a ``revision`` for LAST-UPDATED when no REVISION has its date (RFC 6643 section 4.1);
- D2  the ``_n`` copy of an own index column carries no ``smiv2:oid`` (one OID per data node);
- D3  ranges sorted and merged, and ranges on Counter32/Counter64/TimeTicks dropped;
- D4  identifiers YANG cannot express rewritten, and synthetic SMIv1 index leafs (``INDEX { INTEGER }``);
- D5  the language modules SNMPv2-SMI and RFC1155-SMI: their base-type typedefs map to the
      YANG base types (libsmi: restricted uint32/binary typedefs, an undeclared inet prefix);
- D6  SMIv1 ``STATUS deprecated`` stays deprecated (libsmi makes it obsolete);
- D7  DisplayString/PhysAddress imported from RFC1213-MIB resolve to SNMPv2-TC
      (libsmi refers to RFC1213-MIB's informal types); other RFC1213-MIB
      symbols (``ifIndex``) stay in RFC1213-MIB, libsmi redirects them to IF-MIB;
- D8  libsmi reported severe errors for the module (``<MOD>.err``: "contains errors") and lost
      or misread definitions: everything only in ours, libsmi's misread revisions, and values
      libsmi could not resolve (``<unknown>`` access, OID ``0``);
- D9  a leafref leaf copies the status of its target only when the target is in the same
      module (libsmi always copies it, which makes a current list refer to a "deprecated" key
      leaf when another module's INDEX object is deprecated);
- D10 enumerations YANG cannot express: a label repeating a value is left out; a value
      outside int32 makes the type int64 with the labels in the description;
- D11 a scalar whose parent OID has no descriptor is a leaf of the module container (libsmi
      emits a container without a name).

- D12 an empty DESCRIPTION/REFERENCE gives no statement (libsmi emits ``description ""``);
- D13 a 2-digit LAST-UPDATED/REVISION year that would be before 1988 means 20YY (libsmi
      reads 19YY);
- D14 prefixes are unique across the translated set (``Options.set_prefixes``), so a
      module's own or import prefix can differ from libsmi's per-module allocation;
- D15 named numbers on a non-INTEGER base (SMIv1 ``Gauge { no(0) }``) keep the base type, the
      labels go into the description (libsmi emits an enumeration);

- D16 SMIv1 TRAP-TYPEs with ``ENTERPRISE snmp`` get ``snmpTraps.(n+1)`` (RFC 3584 section 3.1;
      libsmi gives ``snmp.0.n``);
- D17 a refinement wider than its type's constraint is intersected with it
      (``resolve.range-widened``): our range/length lies within libsmi's;
- D18 a vendor or language module's type that redefines a base type name (``Counter32 ::=
      Counter``, RFC1065-SMI's types) resolves to the base type (libsmi refers to the
      redefinition);
- D19 module aliases (a built-in alias table): ``SNMPv2-TC-v1`` is ``SNMPv2-TC``, ``SNMPv2-SMI-v1`` is
      ``SNMPv2-SMI``;
- D20 a notification object that is not a column or scalar gives an empty ``object-<k>``
      container (libsmi emits a leaf for it);
- D21 the resolver drops what does not fit the syntax: a DEFVAL that does not match
      (``resolve.defval-invalid``), an invalid DISPLAY-HINT (``resolve.hint-invalid``), and IMPLIED
      on a fixed-size or integer index item (``resolve.index-implied-fixed``);
- D22 a notification object without a data leaf in its own module is a typed copy: a column of
      another module's row without AUGMENTS (``yang.column-orphan``; libsmi: a leafref to a path
      that does not exist) or an object whose type does not resolve (no data leaf);
- D23 a well-known type used without IMPORTS (``DisplayString``) resolves to its home module
      (``resolve.not-imported``; libsmi: binary);
- D24 a local definition shadows an imported symbol of the same name
      (``resolve.import-shadowed``; libsmi uses the import);
- D25 a hex DEFVAL stays ``'..'H`` where libsmi prints the octets as text;

and libsmi defects the corpus comparison found (the libsmi output is wrong; information only):

- LX1 libsmi refers to a prefix it does not import (``yang:counter32`` without importing
      ietf-yang-types, ``snmpv2-tc:DisplayString``);
- LX2 libsmi translates the first module of a file that holds several, whatever module was
      asked for (the module name differs);
- LX3 libsmi emits an enumeration label or bit name twice (``resolve.enum-duplicate-label``: we
      keep the first);
- LX4 libsmi invents OIDs below ``0`` for a module whose root import does not resolve (we leave
      the module's nodes unlinked, with the resolver's errors), so everything else differs too;
      also libsmi's ``<unknown>`` access and OID ``0`` for objects it could not resolve;
- LX5 libsmi's leafref path into another module's table omits the table container;
- LX6 libsmi emits empty or incomplete statements: a module container without children (we
      leave it out), an ``augment`` without a target (with the aliases of its table and row) where
      the AUGMENTS base row does not resolve (we: a keyless list, ``resolve.augments-not-row``);
- LX7 libsmi prints garbage DEFVALs (pointer values, ``(null)``);
- LX8 libsmi drops one trailing character of a text for every backslash it escapes;
- LX9 libsmi puts scalars of other modules registered below the same node into a module's
      scalar group container (NETBOTZ-MIB's objects in NETBOTZ-DEVICE-MIB). The cross-check:
      mibmeta shows no own scalar or column with a resolved type lacking a data node.

L1-L10 and D1-D4, D9-D11 are the deviations the reference set can show; D5-D8 and D12-D15
only occur in the wider golden set and the corpus (SMIv1, vendor and broken modules), where the
libsmi output is informative, not a gate.

Pure stdlib.
"""

import argparse
import os
import re
import sys

TEXT_KW = {"description", "reference", "contact", "organization"}
# substatements matched by (keyword, argument); everything else by keyword
KEYED_KW = {"leaf", "leaf-list", "list", "container", "notification", "augment", "typedef", "identity",
            "smiv2:alias", "enum", "bit", "import", "revision", "uses", "grouping", "choice", "case"}
PREFIXED_ARG_KW = {"type", "base", "path", "augment"}


# --- parsing ---------------------------------------------------------------------------------

class Stmt:
    __slots__ = ("kw", "arg", "subs", "line", "parent", "undeclared", "lx4")

    def __init__(self, kw, arg, line):
        self.kw = kw
        self.arg = arg
        self.subs = []
        self.line = line
        self.parent = None

    def find(self, kw):
        for s in self.subs:
            if s.kw == kw:
                return s
        return None

    def findall(self, kw):
        return [s for s in self.subs if s.kw == kw]

    def path(self):
        out = []
        s = self
        while s is not None and s.kw != "module":
            out.append(s.kw + (" " + s.arg if s.arg is not None and s.kw in KEYED_KW else ""))
            s = s.parent
        return " / ".join(reversed(out))


def _unquote_double(body, col):
    """RFC 6020 section 6.1.3: strip trailing white space before line breaks and the indentation up to
    and including the quote column on continuation lines; process escapes (an unknown escape is
    kept literally, as libsmi writes unescaped backslashes in some texts)."""
    lines = body.split("\n")
    out = []
    for i, ln in enumerate(lines):
        if i < len(lines) - 1:
            ln = ln.rstrip(" \t")
        if i > 0:
            k = 0
            w = 0
            while k < len(ln) and ln[k] in " \t" and w <= col:
                w = (w // 8 + 1) * 8 if ln[k] == "\t" else w + 1
                k += 1
            ln = ln[k:]
        out.append(ln)
    s = "\n".join(out)
    res = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "n":
                res.append("\n")
            elif n == "t":
                res.append("\t")
            elif n == "\"":
                res.append("\"")
            elif n == "\\":
                res.append("\\")
            else:
                res.append("\\" + n)
            i += 2
            continue
        res.append(c)
        i += 1
    return "".join(res)


def tokenize(text):
    toks = []  # (kind, value, line)
    i = 0
    n = len(text)
    line = 1
    col0 = 0  # offset of the current line start
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            col0 = i
            continue
        if c in " \t\r":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            k = text.rfind("\n", i, j)
            if k >= 0:
                col0 = k + 1
            i = j
            continue
        if c in "{};":
            toks.append((c, c, line))
            i += 1
            continue
        if c == "\"":
            col = i - col0
            j = i + 1
            while j < n and text[j] != "\"":
                if text[j] == "\\":
                    j += 1
                j += 1
            body = text[i + 1:j]
            line_start = line
            line += body.count("\n")
            k = body.rfind("\n")
            if k >= 0:
                col0 = i + 1 + k + 1
            toks.append(("str", _unquote_double(body, col), line_start))
            i = j + 1
            continue
        if c == "'":
            j = text.find("'", i + 1)
            body = text[i + 1:j]
            line += body.count("\n")
            toks.append(("str", body, line))
            i = j + 1
            continue
        if c == "+":
            toks.append(("+", "+", line))
            i += 1
            continue
        j = i
        while j < n and text[j] not in " \t\r\n{};\"'":
            j += 1
        toks.append(("word", text[i:j], line))
        i = j
    return toks


def parse(text):
    toks = tokenize(text)
    pos = 0

    def stmt(parent):
        nonlocal pos
        kind, kw, line = toks[pos]
        pos += 1
        arg = None
        if toks[pos][0] in ("word", "str"):
            arg = toks[pos][1]
            pos += 1
            while toks[pos][0] == "+":
                arg += toks[pos + 1][1]
                pos += 2
        s = Stmt(kw, arg, line)
        s.parent = parent
        if toks[pos][0] == ";":
            pos += 1
        elif toks[pos][0] == "{":
            pos += 1
            while toks[pos][0] != "}":
                s.subs.append(stmt(s))
            pos += 1
        else:
            raise ValueError("line %d: unexpected %r" % (toks[pos][2], toks[pos][1]))
        return s

    return stmt(None)


# --- normalisation ---------------------------------------------------------------------------

def norm_text(s):
    """Trailing white space per line and trailing empty lines removed (both sides do this or
    YANG does it on unquoting; libsmi keeps a trailing space-only line)."""
    lines = [ln.rstrip() for ln in s.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def loose_text(s):
    """Also without leading white space per line: what remains when the two indent rules differ."""
    lines = [ln.strip() for ln in s.split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    return "\n".join(lines)


def prefix_map(mod):
    pm = {}
    p = mod.find("prefix")
    if p is not None:
        pm[p.arg] = mod.arg
    for im in mod.findall("import"):
        ip = im.find("prefix")
        if ip is not None:
            pm[ip.arg] = im.arg
    return pm


_PFX = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*):")


def norm_args(s, pm):
    if s.arg is not None:
        if s.kw in TEXT_KW:
            s.arg = norm_text(s.arg)
        elif s.kw in PREFIXED_ARG_KW:
            s.arg = _PFX.sub(lambda m: pm.get(m.group(1), m.group(1)) + ":", s.arg)
        elif s.kw == "key":
            s.arg = " ".join(s.arg.split())
    for c in s.subs:
        norm_args(c, pm)


def load(path):
    with open(path, encoding="utf-8") as f:
        mod = parse(f.read())
    pm = prefix_map(mod)
    norm_args(mod, pm)
    return mod


# --- comparison ------------------------------------------------------------------------------

class Diff:
    __slots__ = ("kind", "path", "ours", "lib", "why")

    def __init__(self, kind, path, ours, lib):
        self.kind = kind      # "only-ours", "only-libsmi", "value"
        self.path = path
        self.ours = ours      # Stmt or None
        self.lib = lib        # Stmt or None
        self.why = ""

    def show(self):
        if self.kind == "value":
            return "%s: ours %r, libsmi %r" % (self.path, self.ours.arg, self.lib.arg)
        s = self.ours if self.ours is not None else self.lib
        side = "only in ours" if self.kind == "only-ours" else "only in libsmi"
        return "%s: %s (%s %r)" % (s.path(), side, s.kw, s.arg)


def keyed(subs):
    out = {}
    order = []
    for s in subs:
        if s.kw in KEYED_KW:
            k = (s.kw, s.arg)
        else:
            k = (s.kw, None)
        i = 0
        while (k, i) in out:
            i += 1
        out[(k, i)] = s
        order.append((k, i))
    return out, order


def compare(a, b, diffs):
    """a: ours, b: libsmi."""
    ka, oa = keyed(a.subs)
    kb, ob = keyed(b.subs)
    for k in oa:
        if k not in kb:
            diffs.append(Diff("only-ours", a.path(), ka[k], None))
    for k in ob:
        if k not in ka:
            diffs.append(Diff("only-libsmi", b.path(), None, kb[k]))
    for k in oa:
        if k in kb:
            x, y = ka[k], kb[k]
            if x.arg != y.arg:
                diffs.append(Diff("value", x.path(), x, y))
            compare(x, y, diffs)


# --- deviation rules -------------------------------------------------------------------------

HINTED_TYPES = {"string", "ietf-yang-types:phys-address", "ietf-yang-types:mac-address"}


def ceil4(lo):
    return (lo + 3) // 4 if lo > 0 else 0


def t13_length(lib_len):
    """Our length for libsmi's octet length on an Na/Nt string (lower bounds ceil(lo/4))."""
    out = []
    for part in lib_len.split("|"):
        if ".." in part:
            lo, hi = part.split("..")
            out.append((ceil4(int(lo)), int(hi)))
        else:
            v = int(part)
            out.append((ceil4(v), v))
    out.sort()
    merged = []
    for lo, hi in out:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return "|".join(str(lo) if lo == hi else "%d..%d" % (lo, hi) for lo, hi in merged)


def range_set(arg):
    """A range argument as a sorted list of merged (lo, hi) pairs."""
    out = []
    for part in arg.split("|"):
        part = part.strip()
        if ".." in part:
            lo, hi = part.split("..")
            out.append((int(lo), int(hi)))
        else:
            out.append((int(part), int(part)))
    out.sort()
    merged = []
    for lo, hi in out:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def leaf_is_key(leaf):
    lst = leaf.parent
    if lst is None or lst.kw != "list":
        return False
    k = lst.find("key")
    return k is not None and leaf.arg in k.arg.split()


def uses_prefix(mod, module):
    """Whether any argument (outside the import statements) refers to `module`."""
    def walk(s):
        if s.kw == "import":
            return False
        if s.arg is not None and s.kw in PREFIXED_ARG_KW and re.search(r"(^|[^A-Za-z0-9_.-])" + re.escape(module) + ":", s.arg):
            return True
        return any(walk(c) for c in s.subs)
    return any(walk(c) for c in mod.subs)


BASE_NAMES = {"Counter", "Counter32", "Counter64", "Gauge", "Gauge32", "TimeTicks", "IpAddress", "NetworkAddress",
              "Opaque", "Unsigned32", "Integer32", "UInteger32", "INTEGER", "OCTET STRING", "DisplayString", "PhysAddress"}
BASE_YANG = {"ietf-yang-types:counter32", "ietf-yang-types:counter64", "ietf-yang-types:gauge32", "ietf-yang-types:timeticks",
             "ietf-inet-types:ipv4-address", "ietf-yang-smiv2:opaque", "uint32", "int32", "binary", "string",
             "SNMPv2-TC:DisplayString", "ietf-yang-types:phys-address"}
MODULE_ALIASES = {"SNMPv2-TC-v1": "SNMPv2-TC", "SNMPv2-SMI-v1": "SNMPv2-SMI", "RFC1213-MIB": "SNMPv2-TC"}
GARBAGE_DEFVAL = re.compile(r"^(\(null\)|\d{12,})$")


def explain(d, ours, lib):
    """The deviation id that explains a difference, or ""."""
    s = d.ours if d.ours is not None else d.lib
    kw = s.kw
    par = s.parent
    if d.kind == "only-libsmi" and kw in ("smiv2:max-access", "smiv2:oid") and s.arg in ("<unknown>", "0"):
        return "LX4"
    if d.kind == "value" and kw in TEXT_KW and "\\" in d.ours.arg and \
            d.lib.arg == d.ours.arg[:len(d.ours.arg) - d.ours.arg.count("\\")]:
        return "LX8"
    if d.kind == "value" and kw in TEXT_KW and "\\" in d.ours.arg:
        lo = loose_text(d.ours.arg)
        if loose_text(lo[:len(lo) - d.ours.arg.count("\\")]) == loose_text(d.lib.arg):
            return "LX8"
    if d.kind == "value" and kw == "path" and any(p in d.lib.arg for p in [x + ":" for x in getattr(lib, "undeclared", set())]):
        return "LX1"
    if d.kind == "only-libsmi" and kw == "path" and par is not None:
        ol = find_same(ours, par.parent) if par.parent is not None else None
        if ol is not None:
            ot = ol.find("type")
            if ot is not None and ot.arg != "leafref":
                return "D22"
    if d.kind == "only-libsmi" and kw == "leaf" and par is not None and par.kw == "container" and \
            not (par.arg or "").startswith("object-") and par is not lib:
        oc = find_same(ours, par)
        if oc is not None and oc.find("smiv2:oid") is not None:
            return "LX9"
    if d.kind == "only-libsmi" and (kw == "augment" and s.arg is None):
        return "LX6"
    if d.kind == "only-libsmi" and kw == "smiv2:alias" and par is lib and any(x.kw == "augment" and x.arg is None for x in lib.subs):
        if any(x.kw == "list" and x.arg == s.arg or x.kw == "container" and x.arg == s.arg for x in iter_stmts(ours)):
            return "LX6"
    if kw in KEYED_KW and d.kind == "only-libsmi" and par is not None and \
            len([x for x in par.subs if x.kw == kw and x.arg == s.arg]) > 1 and \
            any(x.kw == kw and x.arg == s.arg + "_2" for x in (find_same(ours, par) or ours).subs):
        return "D4"
    if kw == "revision" and d.kind == "only-libsmi" and s.arg and s.arg[:4].isdigit() and int(s.arg[:4]) < 1900:
        return "D13"
    if getattr(lib, "lx4", False) and (d.kind == "only-libsmi" or kw in ("smiv2:oid", "import", "type", "path") or
                                        (d.kind == "value" and d.lib.arg and d.lib.arg.startswith("0."))):
        return "LX4"
    if ours.arg in ("SNMPv2-SMI", "RFC1155-SMI") and (kw in ("import", "typedef") or s.path().startswith("typedef ")):
        return "D5"
    if ours.arg != lib.arg:
        return "LX2"
    if kw in TEXT_KW and d.kind == "only-libsmi" and (s.arg or "").strip() == "":
        return "D12"
    if kw == "revision" and d.kind != "value" and s.arg and len(s.arg) == 10:
        other = lib if d.kind == "only-ours" else ours
        want = ("19" if d.kind == "only-ours" else "20") + s.arg[2:]
        if s.arg[:2] in ("19", "20") and int(s.arg[2:4]) < 88 and any(x.kw == "revision" and x.arg == want for x in other.subs):
            return "D13"
    if kw == "description" and par is not None and par.kw == "revision" and par.arg and int(par.arg[2:4]) < 88:
        alt = ("19" if par.arg.startswith("20") else "20") + par.arg[2:]
        if any(x.kw == "revision" and x.arg == alt for x in (lib.subs if d.kind == "only-ours" else ours.subs)):
            return "D13"
    if kw == "prefix" and d.kind == "value":
        return "D14"
    if kw in ("units",) and d.kind == "only-libsmi" and (s.arg or "").strip() == "":
        return "D12"
    if kw in ("enum", "bit") and d.kind == "only-libsmi" and par is not None and \
            len([x for x in par.subs if x.kw == kw and x.arg == s.arg]) > 1:
        return "LX3"
    if d.kind == "value" and kw == "smiv2:oid" and par is not None and par.kw == "notification" and \
            d.lib.arg.startswith("1.3.6.1.2.1.11.0.") and d.ours.arg.startswith("1.3.6.1.6.3.1.1.5."):
        if int(d.ours.arg.rsplit(".", 1)[1]) == int(d.lib.arg.rsplit(".", 1)[1]) + 1:
            return "D16"
    if d.kind == "value" and kw in ("range", "length") and par is not None and par.kw == "type":
        try:
            lr, orr = range_set(d.lib.arg), range_set(d.ours.arg)
            if all(any(a <= lo and hi <= b for a, b in lr) for lo, hi in orr):
                return "D17"
        except ValueError:
            pass
    if d.kind == "value" and kw == "type" and d.lib.arg and ":" in d.lib.arg:
        lm, ln = d.lib.arg.split(":", 1)
        if ln in BASE_NAMES and d.ours.arg in BASE_YANG:
            return "D18"
        if d.ours.arg == ours.arg + ":" + ln and lm != ours.arg:
            return "D24"
        if MODULE_ALIASES.get(lm) and d.ours.arg == MODULE_ALIASES[lm] + ":" + ln:
            return "D19"
        if lm == "RFC1213-MIB" and ln == "PhysAddress" and d.ours.arg == "ietf-yang-types:phys-address":
            return "D7"
    if d.kind == "value" and kw == "path" and d.ours.arg.replace("RFC1213-MIB", "IF-MIB") == d.lib.arg.replace("RFC1213-MIB", "IF-MIB"):
        return "D7"
    if d.kind == "value" and kw == "smiv2:defval" and re.match(r"^'([0-9a-fA-F]{2})+'H$", d.ours.arg or ""):
        try:
            if bytes.fromhex(d.ours.arg[1:-2]).decode("latin-1") == d.lib.arg:
                return "D25"
        except ValueError:
            pass
    if d.kind == "value" and kw == "type" and d.lib.arg == "binary" and d.ours.arg in ("SNMPv2-TC:DisplayString", "ietf-yang-types:phys-address",
                                                                             "SNMPv2-TC:DateAndTime", "ietf-yang-types:mac-address"):
        return "D23"
    if kw in ("type", "description", "smiv2:max-access", "smiv2:oid", "status", "units", "reference", "smiv2:defval") and \
            par is not None and par.kw == "leaf" and par.parent is not None and (par.parent.arg or "").startswith("object-"):
        ol = find_same(ours, par) if d.ours is None else par
        ll = find_same(lib, par) if d.lib is None else (d.lib.parent if d.kind == "value" else par)
        if ol is not None and ll is not None:
            ot, lt = ol.find("type"), ll.find("type")
            if ot is not None and lt is not None and ot.arg != "leafref" and lt.arg == "leafref":
                return "D22"
    if kw == "import" and d.kind == "only-libsmi" and s.arg in MODULE_ALIASES and \
            any(x.kw == "import" and x.arg == MODULE_ALIASES[s.arg] for x in ours.subs):
        return "D19"
    if kw == "import" and d.kind == "only-ours" and any(x.kw == "import" and MODULE_ALIASES.get(x.arg) == s.arg for x in lib.subs):
        return "D19"
    if d.kind == "only-libsmi" and par is not None and par.kw == "container" and (par.arg or "").startswith("object-"):
        oc = find_same(ours, par)
        if oc is not None and not oc.subs:
            return "D20"
    if d.kind == "only-libsmi" and kw in ("smiv2:defval", "smiv2:display-hint", "smiv2:implied"):
        if kw == "smiv2:defval" and GARBAGE_DEFVAL.match(s.arg or ""):
            return "LX7"
        return "D21"
    if d.kind == "value" and kw == "smiv2:defval" and GARBAGE_DEFVAL.match(d.lib.arg or ""):
        return "LX7"
    if d.kind == "value" and kw == "path":
        segs_o = d.ours.arg.split("/")
        segs_l = d.lib.arg.split("/")
        if len(segs_o) == len(segs_l) + 1 and any(segs_o[:i] + segs_o[i + 1:] == segs_l for i in range(len(segs_o))):
            return "LX5"
    if kw == "container" and d.kind == "only-libsmi" and par is lib and not any(x.kw in ("container", "list", "leaf") for x in s.subs):
        return "LX6"
    if d.kind == "value" and kw == "key" and all(re.search(r"Index\d+$", k) for k, l in zip(d.ours.arg.split(), d.lib.arg.split()) if k != l):
        return "D4"
    if d.kind == "value" and kw in PREFIXED_ARG_KW and d.lib.arg and ":" in d.lib.arg:
        lp = d.lib.arg.split(":", 1)[0]
        if lp not in prefix_map(lib) and lp not in MODULE_NAMES(ours, lib) and ":" in d.ours.arg and \
                d.ours.arg.split(":", 1)[1] == d.lib.arg.split(":", 1)[1]:
            return "LX1"
    if kw == "import" and d.kind == "only-ours":
        ip = d.ours.find("prefix")
        if ip is not None and ip.arg in getattr(lib, "undeclared", set()):
            return "LX1"
    if kw == "revision" and d.kind == "only-libsmi" and any(x.kw == "revision" and x.arg == s.arg for x in lib.subs if x is not s):
        return "D1"
    if kw == "description" and par is not None and par.kw == "revision" and d.kind != "only-ours":
        dups = [x for x in lib.subs if x.kw == "revision" and x.arg == par.arg]
        if s.arg == "[Revision added by libsmi due to a LAST-UPDATED clause.]" or len(dups) > 1:
            return "D1"
    if kw == "status" and d.kind == "value" and d.ours.arg == "deprecated" and d.lib.arg == "obsolete":
        return "D6"
    if kw == "type" and d.kind == "value" and d.lib.arg.startswith("RFC1213-MIB:") and \
            d.ours.arg == "SNMPv2-TC:" + d.lib.arg.split(":", 1)[1]:
        return "D7"
    if kw == "import" and d.lib is not None and d.lib.arg == "RFC1213-MIB" and \
            any(x.kw == "import" and x.arg == "SNMPv2-TC" for x in ours.subs):
        return "L4"
    if kw == "import" and d.kind == "only-ours" and d.ours.arg == "SNMPv2-TC" and \
            any(x.kw == "import" and x.arg == "RFC1213-MIB" for x in lib.subs):
        return "D7"
    if kw == "prefix" and par is ours and d.kind == "value":
        # the libsmi prefix was taken by an import we leave out (L4)
        for im in lib.findall("import"):
            ip = im.find("prefix")
            if ip is not None and ip.arg == d.ours.arg and not any(x.kw == "import" and x.arg == im.arg for x in ours.subs):
                return "L4"
    if kw == "status" and d.kind == "only-libsmi" and par is not None and par.kw == "leaf":
        t = par.find("type")
        p = t.find("path") if t is not None and t.arg == "leafref" else None
        if p is not None and not p.arg.startswith("/" + ours.arg + ":"):
            return "D9"
    if kw == "enum" and d.kind == "only-libsmi" and par is not None:
        # a label repeating an earlier value (D10)
        v = s.find("value")
        earlier = par.subs[:par.subs.index(s)]
        if v is not None and any(x.kw == "enum" and x.find("value") is not None and x.find("value").arg == v.arg
                                 for x in earlier):
            return "D10"
    # the int64 fallback of an enumeration with values outside int32 (D10)
    if d.kind == "value" and kw in ("type", "description"):
        o_owner, l_owner = par, find_same(lib, par) if par is not None else None
    elif d.kind == "only-libsmi" and kw == "enum" and par is not None:
        l_owner = par.parent
        o_owner = find_same(ours, l_owner) if l_owner is not None else None
    else:
        o_owner, l_owner = None, None
    if o_owner is not None and l_owner is not None:
        ot, lt = o_owner.find("type"), l_owner.find("type")
        if ot is not None and lt is not None and ot.arg == "int64" and lt.arg == "enumeration":
            return "D10"
        if ot is not None and lt is not None and ot.arg not in ("int32", "int64", "enumeration") and lt.arg == "enumeration":
            return "D15"
    if kw == "description" and d.ours is not None and "Named numbers (not expressible in YANG" in (d.ours.arg or ""):
        return "D15"
    if kw == "container" and d.kind == "only-libsmi" and s.arg is None:
        return "D11"
    if d.kind == "value":
        if kw in TEXT_KW and loose_text(d.ours.arg) == loose_text(d.lib.arg):
            return "L9"
        if kw == "smiv2:max-access" and d.lib.arg == "read-write" and d.ours.arg == "read-create":
            return "L1"
        if kw == "length" and par is not None and par.kw == "type":
            if t13_length(d.lib.arg) == d.ours.arg:
                return "L2"
        if kw == "type" and par is not None and par.kw == "typedef" and par.arg in ("DisplayString", "PhysAddress") \
                and d.lib.arg == "binary" and d.ours.arg == "string":
            return "L6"
        if kw == "range" and par is not None and par.kw == "type":
            lr = range_set(d.lib.arg)
            if lr == range_set(d.ours.arg):
                return "D3"
            # clamped to the YANG type: every range of ours lies within libsmi's
            if all(any(a <= lo and hi <= b for a, b in lr) for lo, hi in range_set(d.ours.arg)):
                return "D3"
        if kw == "type" and d.lib.arg == "int32" and d.ours.arg == "int64":
            r = d.ours.find("range")
            if r is not None and any(lo < -2147483648 or hi > 2147483647 for lo, hi in range_set(r.arg)):
                return "D3"
        return ""
    if d.kind == "only-libsmi":
        if kw == "length" and par is not None and par.kw == "type" and \
                (par.arg in HINTED_TYPES or (":" in par.arg and not par.arg.startswith("ietf-"))):
            return "L2"
        if kw == "smiv2:alias" and par is lib and any(x.kw == "identity" and x.arg == s.arg for x in ours.subs):
            return "L3"
        if kw == "import" and (s.arg is None or s.arg in ("RFC1155-SMI", "RFC-1212", "RFC-1215") or not uses_prefix(lib, s.arg)):
            return "L4"
        if kw == "leaf" and par is not None and par.kw == "container" and par.arg.startswith("object-"):
            dup = [x for x in par.subs if x.kw == "leaf" and x.arg == s.arg]
            if len(dup) > 1:
                return "L7"
        if kw == "smiv2:oid" and par is not None and par.kw == "leaf" and re.search(r"_\d+$", par.arg):
            return "D2"
        if kw in KEYED_KW and kw not in ("enum", "import", "revision", "augment") and s.arg is not None and \
                not re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*$", s.arg):
            return "D4"
        if kw == "range" and par is not None and par.kw == "type" and par.arg in (
                "ietf-yang-types:counter32", "ietf-yang-types:counter64", "ietf-yang-types:timeticks",
                "ietf-yang-types:zero-based-counter32", "ietf-yang-types:zero-based-counter64",
                "ietf-yang-types:timestamp", "ietf-yang-types:gauge64"):
            return "D3"
        return ""
    # only in ours
    if kw == "leaf":
        ma = s.find("smiv2:max-access")
        if ma is not None and ma.arg == "not-accessible" and not leaf_is_key(s):
            return "L5"
        if par is not None and par.kw == "container" and par.arg.startswith("object-") and re.search(r"_\d+$", s.arg):
            return "L7"
        t = s.find("type")
        if t is not None and t.arg == "leafref" and leaf_is_key(s):
            p = t.find("path")
            if p is not None and p.arg.count("/") == 3:
                return "L8"
        if leaf_is_key(s) and re.search(r"Index\d+$", s.arg):
            return "D4"
    if kw == "container" and par is not None and par.kw == "container":
        leaves = [x for x in s.subs if x.kw == "leaf"]
        if leaves and all((x.find("smiv2:max-access") is not None and x.find("smiv2:max-access").arg == "not-accessible") for x in leaves):
            return "L5"
    if kw == "smiv2:display-hint" and par is not None and par.kw == "typedef" and par.arg in ("DisplayString", "PhysAddress"):
        return "L6"
    if kw == "revision" and s.find("description") is None:
        return "D1"
    if kw in KEYED_KW and s.arg is not None and s.arg.startswith("_") and par is not None and \
            not re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*$", s.arg[1:]):
        return "D4"
    return ""


def MODULE_NAMES(ours, lib):
    """Module names both trees refer to (normalised prefixes are module names)."""
    out = {ours.arg, lib.arg}
    for t in (ours, lib):
        for im in t.findall("import"):
            out.add(im.arg)
    return out


def undeclared_prefixes(lib):
    """Prefixes libsmi uses in arguments but never declares (normalisation left them as is)."""
    names = MODULE_NAMES(lib, lib)
    out = set()

    def walk(s):
        if s.arg is not None and s.kw in PREFIXED_ARG_KW and s.kw != "import":
            for m in _PFX.finditer(s.arg):
                if m.group(1) not in names:
                    out.add(m.group(1))
        for c in s.subs:
            walk(c)
    walk(lib)
    return out


def find_same(root, stmt):
    """The statement of `root`'s tree at the same keyed path as `stmt` (of the other tree)."""
    chain = []
    s = stmt
    while s is not None and s.parent is not None:
        chain.append((s.kw, s.arg if s.kw in KEYED_KW else None))
        s = s.parent
    cur = root
    for kw, arg in reversed(chain):
        nxt = None
        for c in cur.subs:
            if c.kw == kw and (arg is None or c.arg == arg):
                nxt = c
                break
        if nxt is None:
            return None
        cur = nxt
    return cur


def iter_stmts(s):
    yield s
    for c in s.subs:
        yield from iter_stmts(c)


def libsmi_broken(lib_path):
    ep = lib_path[:-5] + ".err"
    if os.path.exists(ep):
        with open(ep, encoding="utf-8", errors="replace") as f:
            return "contains errors" in f.read()
    return False


def compare_module(ours_path, lib_path):
    ours = load(ours_path)
    lib = load(lib_path)
    lib.undeclared = undeclared_prefixes(lib)
    lib.lx4 = any(x.kw == "smiv2:oid" and (x.arg or "").startswith("0.") for x in iter_stmts(lib)) and \
        not any(x.kw == "smiv2:oid" and (x.arg or "").startswith("0.") for x in iter_stmts(ours))
    diffs = []
    if ours.arg != lib.arg:
        diffs.append(Diff("value", "module", ours, lib))
    compare(ours, lib, diffs)
    broken = libsmi_broken(lib_path)
    for d in diffs:
        d.why = explain(d, ours, lib)
        if not d.why and broken and (d.kind == "only-ours" or (d.lib is not None and d.lib.kw in ("revision", "leaf", "list", "container")) or
                                     (d.kind == "value" and d.lib.arg in ("<unknown>", "0"))):
            d.why = "D8"
    return diffs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ours", required=True)
    ap.add_argument("--libsmi", required=True)
    ap.add_argument("--modules", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--show", type=int, default=50, help="unexplained differences to list per module")
    ap.add_argument("--explained", action="store_true", help="also list the explained differences")
    a = ap.parse_args()
    if a.modules:
        mods = [m.strip() for m in a.modules.split(",") if m.strip()]
    else:
        mods = sorted(f[:-5] for f in os.listdir(a.libsmi) if f.endswith(".yang"))
    report = ["# actsnmp mib.yang vs libsmi 0.5.0", ""]
    report.append("| module | differences | explained | unexplained | by deviation |")
    report.append("|---|---|---|---|---|")
    detail = []
    total_bad = 0
    for m in mods:
        op = os.path.join(a.ours, m + ".yang")
        lp = os.path.join(a.libsmi, m + ".yang")
        if not os.path.exists(op) or not os.path.exists(lp) or os.path.getsize(lp) == 0:
            report.append("| %s | missing input | | | |" % m)
            continue
        try:
            diffs = compare_module(op, lp)
        except (ValueError, IndexError) as e:
            report.append("| %s | parse error: %s | | | |" % (m, e))
            total_bad += 1
            continue
        bad = [d for d in diffs if not d.why]
        by = {}
        for d in diffs:
            if d.why:
                by[d.why] = by.get(d.why, 0) + 1
        total_bad += len(bad)
        report.append("| %s | %d | %d | %d | %s |" % (m, len(diffs), len(diffs) - len(bad), len(bad),
                                                      ", ".join("%s %d" % (k, by[k]) for k in sorted(by))))
        if bad or a.explained:
            detail.append("")
            detail.append("## " + m)
            detail.append("")
            for d in bad[:a.show]:
                detail.append("- UNEXPLAINED " + d.show())
            if a.explained:
                for d in diffs:
                    if d.why:
                        detail.append("- %s %s" % (d.why, d.show()))
    report.append("")
    report.append("Unexplained differences: %d" % total_bad)
    text = "\n".join(report + detail) + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(text)
    sys.stdout.write(text)
    return 1 if total_bad else 0


if __name__ == "__main__":
    sys.exit(main())
