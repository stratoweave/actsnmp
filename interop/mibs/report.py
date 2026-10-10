#!/usr/bin/env python3
"""Summarize corpus index + oracle results.

    python3 report.py [--mibs-dir interop/mibs] [--stage]

Reads   corpus/index/{modules.tsv,instances.tsv,files.tsv,stats.json}, corpus/sources.tsv,
        duplicates.tsv, vendors.tsv, cache/<oracle>/status/*.json, cache/pysmi-relaxed/json/*.json,
        cache/netsnmp/out/*.jsonl, cache/_prev/ + cache/_incremental.json (oracles.sh --incremental)
Writes  modules.tsv  (committed) one row per unique module: oracle verdicts + error classes
        cache/report/REPORT.md  statistics, quirk catalogue, top error classes with examples
        cache/report/*.tsv      full per-class module lists
With --stage it reads the staged index of index.py --no-swap (corpus/index.new,
duplicates.tsv.new, vendors.tsv.new) and writes modules.tsv.new and
cache/report/REPORT.md.new for swap.py; otherwise both outputs are replaced
atomically.

Pure stdlib. The error classification lives here rather than in the oracle
runs, so it can be refined without re-running the oracles.
"""

import argparse
import collections
import glob
import json
import os
import re
import sys

ORACLES = ["pysmi-relaxed", "pysmi-strict", "pysmi-dialect", "netsnmp", "smilint"]
TOP = 25


# input/output paths (main() sets them; --stage switches to the staged *.new versions)
P = {}


def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def read_tsv(path):
    with open(path) as f:
        lines = [l for l in f if not l.startswith("#")]
    hdr = lines[0].rstrip("\n").split("\t")
    return [dict(zip(hdr, l.rstrip("\n").split("\t"))) for l in lines[1:]]


def load_status(cache, oracle):
    res = {}
    for p in glob.glob(os.path.join(cache, oracle, "status", "*.json")):
        with open(p) as f:
            r = json.load(f)
        res[r["module"]] = r
    return res


# --------------------------------------------------------------------------
# pysmi classification
# --------------------------------------------------------------------------

KEYWORDS = {"MAX-ACCESS", "ACCESS", "STATUS", "SYNTAX", "DESCRIPTION", "REFERENCE", "INDEX", "DEFVAL",
            "UNITS", "DISPLAY-HINT", "OBJECTS", "NOTIFICATIONS", "MODULE", "MANDATORY-GROUPS", "GROUP",
            "OBJECT", "WRITE-SYNTAX", "MIN-ACCESS", "LAST-UPDATED", "ORGANIZATION", "CONTACT-INFO",
            "REVISION", "AUGMENTS", "IMPORTS", "FROM", "END", "BEGIN", "SEQUENCE", "OF", "INTEGER",
            "OCTET", "STRING", "OBJECT-TYPE", "MODULE-IDENTITY", "TEXTUAL-CONVENTION", "ENTERPRISE",
            "VARIABLES", "TRAP-TYPE", "NOTIFICATION-TYPE", "OBJECT-GROUP", "NOTIFICATION-GROUP",
            "MODULE-COMPLIANCE", "AGENT-CAPABILITIES", "OBJECT-IDENTITY", "IDENTIFIER", "BITS", "SIZE",
            "IMPLIED", "PRODUCT-RELEASE", "SUPPORTS", "INCLUDES", "VARIATION", "CREATION-REQUIRES",
            "EXPORTS", "MACRO", "CHOICE", "TRUE", "FALSE", "MIN", "MAX", "NULL"}


RFC_ARTEFACT_RE = re.compile(
    r"\[Page \d+\]|\bPage \d+\b|Expires|Internet[- ]Draft|draft-[a-z]|RFC \d+\s+.*\s(19|20)\d\d\s*$|"
    r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(19|20)\d\d\s*$")


def lark_class(d):
    """Grammar error -> quirk class, from the lark token detail (token, expected set, source line)."""
    if not d:
        return "parse: grammar error"
    line = d.get("source_line", "") or ""
    tok = d.get("token", "") or ""
    tt = d.get("token_type", "") or ""
    exp = d.get("expected", []) or []
    kind = d.get("lark")
    if RFC_ARTEFACT_RE.search(line) or re.match(r"^\s*\[(\d+|RFC\d+)\]", line):
        return "parse: RFC/draft page header or footer left in the module"
    if kind == "UnexpectedCharacters":
        c = d.get("char", "")
        if c == "_":
            if "DEFINITIONS" in line:
                return "lex: underscore in module name"
            return "lex: underscore in identifier"
        if c == "\x1a":
            return "lex: DOS EOF marker (^Z) at end of file"
        if c == "/" and ("/*" in line or "//" in line):
            return "lex: C/C++ style comment"
        if c == "-" and re.match(r"^\s*[A-Z][-\w]*\s+(OBJECT-TYPE|OBJECT-IDENTITY|NOTIFICATION-TYPE|OBJECT-GROUP|"
                                 r"MODULE-COMPLIANCE|TRAP-TYPE|NOTIFICATION-GROUP|MODULE-IDENTITY)", line):
            return "parse: value name (descriptor) starts with an uppercase letter"
        if c == "." and re.search(r"\d+\.\d+\.\d+\.\d+", line):
            return "lex: dotted IP address literal (e.g. DEFVAL { 0.0.0.0 })"
        if c in "'\"":
            return "lex: bad quoted/hex/bin literal"
        if c and ord(c) > 127:
            return "lex: non-ASCII character outside strings"
        if c in "/&*#@!?:%+=<>|$\\[]^`~":
            return f"lex: illegal character {c!r} in identifier/clause"
        return f"lex: unexpected character {c!r}"
    if kind == "UnexpectedEOF":
        return "parse: unexpected end of file (truncated module / missing END)"
    if tok == "IMPLICIT" or (tt == "NUMBER" and "APPLICATION" in exp):
        return "parse: non-SMI ASN.1 module (IMPLICIT TAGS, tagged PDU types)"
    if tok == "" and line.strip() == "END":
        return "parse: empty module body"
    if tok in ("..", "...") or line.strip().startswith(".."):
        return "parse: placeholder text ('...') in an example module"
    if tok == "{" and "BIT STRING" in line:
        return "parse: ASN.1 BIT STRING type"
    if tok == "{" and "LPAR" in exp:
        return "parse: named numbers on Integer32/Unsigned32/Gauge32 (not INTEGER)"
    if tok == "(" and line.strip().startswith("}"):
        return "parse: range constraint after an enumeration list"
    if tok == "REVISION" and exp == ["DESCRIPTION"]:
        return "parse: REVISION/clause order wrong or DESCRIPTION missing"
    if tok == "::=":
        return "parse: malformed assignment (missing/invalid name or type before ::=)"
    if tok == "MODULE-IDENTITY" and any(e in exp for e in ("SEMICOLON", "FROM", "COMMA")):
        return "parse: IMPORTS not terminated by ';'"
    if tok == "MODULE-IDENTITY":
        return "parse: value name (descriptor) starts with an uppercase letter"
    if tt in ("HEX_STRING", "BIN_STRING") and "NUMBER" in exp:
        return "parse: hex/binary string where a number is expected"
    if tok in ("TRUE", "FALSE"):
        return "parse: TRUE/FALSE value (e.g. DEFVAL { FALSE })"
    if tt == "LOWERCASE_IDENTIFIER" and "SEQUENCE OF" in line:
        return "parse: SEQUENCE OF <lowercase entry name>"
    if tt == "LOWERCASE_IDENTIFIER" and exp == ["BIN_STRING", "HEX_STRING", "NUMBER"]:
        return "parse: symbolic name in a range/size constraint"
    if tt == "LBRACE" and re.search(r"(Integer32|Unsigned32|Gauge32|Counter32|Counter64|TimeTicks)\s*\{", line):
        return "parse: named numbers on Integer32/Unsigned32/Gauge32 (not INTEGER)"
    if tt == "STRING" and "BIT STRING" in line:
        return "parse: ASN.1 BIT STRING type"
    if tok == "SIZE" and re.search(r"INTEGER|Integer32", line):
        return "parse: SIZE constraint on an integer type"
    if tt == "NUMBER" and "SIZE" in exp:
        return "parse: OCTET STRING (n..m) without SIZE"
    if tt == "QUOTED_STRING" and re.search(r'"[^"]*"\s*\(\s*-?\d+\s*\)', line):
        return "parse: quoted string as enumeration label"
    if tt == "QUOTED_STRING" and "INDEX" in line:
        return "parse: quoted INDEX element"
    if tt == "NUMBER" and re.match(r"^\s*\d+\s*\(", line):
        return "parse: enumeration label starts with a digit"
    if tok == "}" and re.search(r"\{\s*\}", line):
        return "parse: empty list { } (e.g. OBJECTS { })"
    if tok == "}" or (tok == "," and ("RBRACE" in exp or "RPAR" in exp)):
        return "parse: trailing comma / empty list element"
    if tok == ",":
        return "parse: unexpected comma"
    if tok == ";":
        return "parse: stray ';' (e.g. after IMPORTS list / SMIv1 EXPORTS)"
    if tt == "LOWERCASE_IDENTIFIER" and any(e in exp for e in ("COMMA", "RBRACE")):
        return "parse: missing comma between list items"
    if tt == "QUOTED_STRING" and any(e in exp for e in ("DESCRIPTION", "ORGANIZATION")):
        return "parse: REVISION/clause order wrong or DESCRIPTION missing"
    if tt == "QUOTED_STRING":
        return "parse: unexpected quoted string (unbalanced quotes?)"
    if tt in ("UPPERCASE_IDENTIFIER", "LOWERCASE_IDENTIFIER") and re.search(r"[a-z]\s+[a-z]+\s+[a-z]", line) \
            and not re.search(r"::=|OBJECT|SYNTAX|INDEX", line):
        return "parse: unquoted free text (comment/description without quotes or --)"
    if tt == "UPPERCASE_IDENTIFIER" and "LOWERCASE_IDENTIFIER" in exp and "RBRACE" in exp:
        return "parse: uppercase identifier in a list (e.g. SEQUENCE item / enum label)"
    if tt == "UPPERCASE_IDENTIFIER" and ("FROM" in exp or "COMMA" in exp):
        return "parse: IMPORTS list malformed (missing FROM / module name)"
    if tok in KEYWORDS:
        if tok == "END":
            return "parse: unexpected END (truncated module or clause)"
        if tok in ("MAX-ACCESS", "ACCESS"):
            return "parse: ACCESS vs MAX-ACCESS mismatch / misplaced access clause"
        if tok in ("UNITS", "REFERENCE", "DESCRIPTION", "STATUS", "SYNTAX", "INDEX", "DEFVAL", "AUGMENTS",
                   "DISPLAY-HINT"):
            return f"parse: misplaced or duplicated {tok} clause"
        return f"parse: unexpected keyword {tok}"
    if tt == "NUMBER":
        return "parse: unexpected number"
    if tt in ("UPPERCASE_IDENTIFIER", "LOWERCASE_IDENTIFIER"):
        return "parse: unexpected identifier"
    if tt:
        return f"parse: unexpected token {tok!r}"
    return "parse: grammar error"


PYSMI_RULES = [
    (r"^Identifier should not end with '-'", "lex: identifier ends with '-'"),
    (r"is forbidden", "lex: ASN.1 reserved word used as identifier"),
    (r"^Number \S+ is too big", "lex: number too big"),
    (r"Unknown parents? (symbol|for symbols)", "sem: OID parent not defined (undefined/unimported symbol)"),
    (r"^Duplicate symbol found", "sem: duplicate symbol definition"),
    (r'^no module "[^"]*" in symbolTable', "dep: imported module failed/missing"),
    (r"^no symbol \S+ in module", "sem: imported symbol not defined in that module"),
    (r"MIB source \S+ not found", "missing: module not found"),
    (r"too large|older than needed", "file too large (> 10 MB pysmi reader limit)"),
    (r"requires? \w+ option", "parse: needs a pysmi relaxation option"),
    (r"^Bad grammar", None),  # -> lark_class
    (r"[Ii]nvalid (timestamp|date)|LAST-UPDATED|REVISION", "sem: bad LAST-UPDATED/REVISION timestamp"),
    (r"Duplicate module identity", "sem: more than one MODULE-IDENTITY"),
    (r"[Bb]it|[Hh]ex|[Bb]inary", "lex: bad hex/binary string (strict)"),
    (r"[Ff]ailed to resolve|[Uu]nknown (type|symbol)", "sem: unknown type/symbol"),
]


def pysmi_class(r, own_name):
    """-> (verdict, class). verdict: ok | ok-depfail | fail | depfail | missing | timeout | crash"""
    st = r.get("status")
    deps = r.get("deps") or {}
    if st in ("compiled", "untouched"):
        return ("ok-depfail" if deps else "ok"), ""
    if st == "missing":
        return "missing", "missing: module not found"
    if st in ("timeout", "crash"):
        e = r.get("error") or {}
        return st, f"{st}: {e.get('type', '')}".strip()
    e = r.get("error") or {}
    msg = e.get("msg", "")
    if st == "unprocessed":
        return "depfail", "dep: import closure failed"
    m = re.match(r'^no module "([^"]*)" in symbolTable', msg)
    if m:
        dep = deps.get(m.group(1), {})
        if dep.get("status") == "missing":
            return "depfail", "dep: imported module missing"
        return "depfail", "dep: imported module failed"
    for rx, cls in PYSMI_RULES:
        if re.search(rx, msg):
            if cls is None:
                cls = lark_class(r.get("detail"))
            if cls.startswith("dep:"):
                return "depfail", cls
            return "fail", cls
    m = re.sub(r" at MIB \S+", "", msg)
    m = re.sub(r"\b[A-Za-z][-\w]*[0-9_A-Z][-\w]*\b", "X", m)
    return "fail", "other: " + m[:60]


def dialect_class(r):
    st = r.get("status")
    if st != "ok":
        if st == "grammar-error":
            return "grammar-error"
        return st or "?"
    if r.get("relaxations"):
        return "relaxed:" + "+".join(r["relaxations"])
    return r.get("dialect", "?")


# --------------------------------------------------------------------------
# net-snmp classification
# --------------------------------------------------------------------------

NETSNMP_RULES = [
    (r"^Cannot find module \(([^)]*)\)", "missing import module"),
    (r"^Did not find '([^']*)' in module ([^ ]+)", "imported symbol not found in module"),
    (r"^Unlinked OID in ([^:]+):", "unlinked OID (parent undefined)"),
    (r"^Undefined identifier: ", "undefined identifier"),
    (r"^Cannot adopt OID in ([^:]+):", "cannot adopt OID (orphan)"),
    (r"^(Object|Group) not found in module|^Undefined (OBJECT|OBJECT-GROUP|NOTIFICATION)",
     "compliance/group/capabilities refers to an undefined object"),
    (r"^(Module not found|Unknown module)", "compliance/capabilities refers to an unknown module"),
    (r"[Tt]imestamp", "bad LAST-UPDATED/REVISION timestamp"),
    (r"is a reserved word\)", "token where a descriptor is expected (reserved word)"),
    (r"pretty silly", "warning: odd descriptor (e.g. capitalised)"),
    (r"^Textual convention doesn't map", "TC with unknown base type"),
    (r"^Attempt to define a root oid", "redefines a root OID"),
    (r"^STATUS should be", "invalid STATUS value"),
    (r"^Bad parse of ([A-Z-]+)", "bad parse of macro"),
    (r"^Expected ", "syntax: expected token"),
    (r"^Bad operator", "syntax: bad operator"),
    (r"^Too long OID", "OID too long"),
    (r"^Warning:", "warning"),
    (r"^Unexpected ", "syntax: unexpected token"),
    (r"^Bad ", "syntax: bad clause"),
    (r"^Unknown ", "unknown"),
    (r"^Should be ", "syntax: should be"),
    (r"^Missing ", "syntax: missing"),
    (r"^Unterminated|^Unexpected EOF|end of file", "syntax: EOF/unterminated"),
    (r"^Too many", "limits: too many"),
    (r"^Cannot open", "file: cannot open"),
    (r"^Error", "error"),
]


def netsnmp_line_class(line):
    for rx, cls in NETSNMP_RULES:
        if re.search(rx, line):
            return cls
    return "other: " + re.sub(r"\(.*", "", line)[:40]


def netsnmp_own(line, mod):
    f = "/corpus/flat/" + mod
    if f + ")" in line or f + "\n" in line or line.endswith(f) or (f + " ") in line or (f + ":") in line:
        return True
    if re.search(r"(in|of) module %s\b" % re.escape(mod), line) and not line.startswith("Did not find"):
        return True
    if re.search(r"^(Unlinked OID|Cannot adopt OID) in %s:" % re.escape(mod), line):
        return True
    if line.startswith("Did not find") and line.rstrip().endswith("(" + f + ")"):
        return True
    return False


def netsnmp_verdict(r, mod):
    if r.get("status") == "timeout":
        return "timeout", [], []
    lines = [l for l in r.get("stderr", []) if l.strip() and not l.startswith(("...", "MIB search path"))]
    own = [l for l in lines if netsnmp_own(l, mod)]
    other = [l for l in lines if l not in own]
    if not r.get("loaded"):
        v = "fail"
    elif own:
        v = "errors"
    else:
        v = "ok"
    return v, own, other


# --------------------------------------------------------------------------
# smilint
# --------------------------------------------------------------------------

SMILINT_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+): \[(?P<sev>\d)\] \{(?P<name>[^}]+)\} (?P<msg>.*)$")


SMILINT_MSG = {}


def smilint_parse(r, mod):
    sev = collections.Counter()
    names = collections.Counter()
    for l in r.get("lines", []):
        m = SMILINT_RE.match(l)
        if not m:
            continue
        if os.path.basename(m.group("file")) != mod:
            continue
        key = (int(m.group("sev")), m.group("name"))
        if "counts" not in r:
            sev[key[0]] += 1
            names[key] += 1
        if key not in SMILINT_MSG:
            SMILINT_MSG[key] = re.sub(r"`[^']*'", "`X'", m.group("msg"))[:90]
    for k, n in (r.get("counts") or {}).items():
        f, s, name = k.split("|")
        if f == mod:
            sev[int(s)] += n
            names[(int(s), name)] += n
    return sev, names


# --------------------------------------------------------------------------
# pysmi JSON vs net-snmp OIDs
# --------------------------------------------------------------------------

ARCS = [("1.3.6.1.2.1.10.", "mib-2/transmission"), ("1.3.6.1.2.1.", "mib-2"), ("1.3.6.1.6.3.", "snmpModules"),
        ("1.3.6.1.3.", "experimental"), ("1.3.6.1.4.1.", "enterprises"), ("1.0.8802.", "ieee8802"),
        ("1.3.111.", "ieee"), ("1.3.6.1.1.", "directory")]


def module_arc(cache, mod):
    """-> (arc, enterprise number or '') from the nodes net-snmp attributes to the module."""
    nj = os.path.join(cache, "netsnmp", "out", mod + ".jsonl")
    if not os.path.exists(nj):
        return "", ""
    c = collections.Counter()
    ent = collections.Counter()
    with open(nj) as f:
        for l in f:
            o = json.loads(l)
            oid = o.get("oid")
            if not oid or o.get("module") != mod:
                continue
            for pfx, name in ARCS:
                if (oid + ".").startswith(pfx):
                    c[name] += 1
                    if name == "enterprises":
                        ent[oid.split(".")[6] if len(oid.split(".")) > 6 else ""] += 1
                    break
            else:
                c["other"] += 1
    if not c:
        return "", ""
    arc = c.most_common(1)[0][0]
    return arc, (ent.most_common(1)[0][0] if arc == "enterprises" and ent else "")


def enterprise_names(cache):
    """enterprise number -> label, from the node 1.3.6.1.4.1.N in any net-snmp dump."""
    names = collections.defaultdict(collections.Counter)
    for p in glob.glob(os.path.join(cache, "netsnmp", "out", "*.jsonl")):
        with open(p) as f:
            for l in f:
                if '"oid":"1.3.6.1.4.1.' not in l:
                    continue
                o = json.loads(l)
                parts = o["oid"].split(".")
                if len(parts) == 7:
                    names[parts[6]][o["name"]] += 1
    return {k: v.most_common(1)[0][0] for k, v in names.items()}


def oid_compare(cache, mod):
    pj = os.path.join(cache, "pysmi-relaxed", "json", mod + ".json")
    nj = os.path.join(cache, "netsnmp", "out", mod + ".jsonl")
    if not (os.path.exists(pj) and os.path.exists(nj)):
        return None
    with open(pj) as f:
        doc = json.load(f)
    p = {}
    for k, v in doc.items():
        if isinstance(v, dict) and "oid" in v and v.get("class") not in ("textualconvention",):
            p[v.get("name", k)] = v["oid"]
    n = {}
    with open(nj) as f:
        for l in f:
            o = json.loads(l)
            if "oid" in o and o.get("module") == mod:
                n[o["name"]] = o["oid"]
    agree = sum(1 for k in p if k in n and n[k] == p[k])
    differ = sorted(k for k in p if k in n and n[k] != p[k])
    return {"pysmi": len(p), "netsnmp": len(n), "agree": agree, "differ": differ,
            "only_pysmi": sorted(set(p) - set(n)), "only_netsnmp": sorted(set(n) - set(p)),
            "pairs": [(k, p[k], n[k]) for k in differ[:3]]}


# --------------------------------------------------------------------------
# Unified quirk catalogue: evidence from all oracles + the lexical index
# --------------------------------------------------------------------------

# (key, title, smilint error names, pysmi class regex, net-snmp class regex,
#  pysmi dialect options, index quirks/flags, implication for our compiler)
QUIRKS = [
    ("imports", "Unresolvable imports: module missing, misspelled/aliased module name, symbol not defined there",
     {"module-not-found", "import-failed"}, r"^(missing|dep: imported module missing|sem: imported symbol)",
     r"missing import|imported symbol not found|unknown module", set(), {"missing-import"},
     "resolver: ordered search paths, alias table (RFC-1213 -> RFC1213-MIB, RFC1212 -> RFC-1212, ...), "
     "continue with a partial symbol table and report"),
    ("oid-parent", "OID parent not defined (typo, not imported, defined in a missing module)",
     {"object-identifier-unknown", "parent-node"}, r"OID parent not defined",
     r"unlinked OID|undefined identifier|cannot adopt", set(), set(),
     "keep the node with a symbolic, unresolved parent; never abort the module"),
    ("not-imported", "Macros, base types or TCs used without IMPORTS",
     {"macro-not-imported", "basetype-not-imported"}, r"^$", r"^$", set(), set(),
     "implicitly know SNMPv2-SMI/-TC/-CONF and RFC1155/1212/1215 names; warn"),
    ("identifier-chars", "Underscores, trailing hyphens, illegal characters in identifiers (incl. module names)",
     {"underscore-in-identifier", "hyphen-end"}, r"underscore|ends with '-'|illegal character",
     r"^$", set(), {"underscore-id"},
     "lexer: accept [A-Za-z][-_A-Za-z0-9]* (and trailing '-') with a warning"),
    ("identifier-case", "Initial letter case wrong (uppercase descriptors, lowercase type names, uppercase enum labels)",
     {"bad-identifier-case"}, r"uppercase|SEQUENCE OF <lowercase", r"odd descriptor", {"uppercaseIdentifier",
                                                                                     "lowcaseIdentifier"}, set(),
     "parser: do not use the initial case to tell type references from values"),
    ("hyphen-label", "Hyphens in enumeration/BITS labels and object names (SMIv1 legal, SMIv2 not)",
     {"hyphen-in-label", "hyphen-in-object"}, r"^$", r"^$", set(), set(),
     "accept; YANG enum names may contain '-' anyway"),
    ("smi-mix", "SMIv1 and SMIv2 constructs mixed (ACCESS in SMIv2, mandatory/current mixed, no MODULE-IDENTITY)",
     {"access-in-smiv2", "maxaccess-in-smiv1", "status-invalid-smiv1", "status-invalid-smiv2",
      "access-invalid-smiv1", "access-invalid-smiv2", "module-identity-missing", "module-identity-multiple",
      "access-write-only-smiv1", "access-write-only-smiv2"}, r"ACCESS vs MAX-ACCESS", r"invalid STATUS",
     {"supportSmiV1Keywords"},
     set(), "one grammar for SMIv1+SMIv2 clauses; decide the dialect per module from what is used, normalise to SMIv2"),
    ("redefinition", "Duplicate definitions (same descriptor, OID, enum label/number twice)",
     {"identifier-redefined", "object-identifier-redefined", "oid-registered", "enum-name-redefinition",
      "enum-number-redefinition", "bits-name-redefinition", "bits-number-redefinition", "duplicate-type-name"},
     r"duplicate symbol", r"^$", set(), set(),
     "symbol table: first (or last) definition wins, report the other"),
    ("punctuation", "Trailing or missing commas, stray ';', empty lists, unterminated IMPORTS",
     set(), r"comma|stray ';'|empty list|IMPORTS not terminated|IMPORTS list", r"^$",
     {"commaAtTheEndOfImport", "commaAtTheEndOfSequence", "mixOfCommasAndSpaces"}, {"import-trailing-comma"},
     "parser: tolerate trailing/missing commas in IMPORTS, SEQUENCE, enum and OBJECTS lists"),
    ("defval", "Invalid DEFVALs (wrong type, TRUE/FALSE, dotted IP literals, unknown enum label)",
     {"defval-syntax", "defval-range", "defval-enum", "defval-basetype"}, r"TRUE/FALSE|IP address literal",
     r"^$", set(), set(), "keep DEFVAL as raw tokens; convert lazily, drop with a warning when invalid"),
    ("enums", "Enumeration oddities: zero/negative values, labels starting with a digit or quoted, named numbers "
              "on Integer32/Unsigned32, BIT STRING, hex values",
     {"enum-zero", "enum-illegal", "enum-name-not-defined", "subtype-enumeration-illegal", "bits-number-negative",
      "bits-number-too-large", "subtype-bits-illegal"},
     r"named numbers|enumeration label|BIT STRING|hex/binary string", r"^$",
     {"uppercaseIdentifier"}, set(), "accept named numbers on any integer type; keep the value list as data"),
    ("ranges", "Illegal ranges/sizes (SIZE on integers, ranges without SIZE, symbolic bounds, out of range numbers)",
     {"range-illegal", "size-illegal", "subtype-illegal", "range-overlap", "range-bounds", "range-exchanged",
      "number-range", "out-of-range-signed", "out-of-range-unsigned", "out-of-range-integer32",
      "out-of-range-signed64", "out-of-range-unsigned64", "counter-range-illegal", "number-leading-zero"},
     r"SIZE constraint|without SIZE|range constraint|symbolic name in a range|number too big", r"^$", set(), set(),
     "constraints are only metadata: parse leniently, validate separately"),
    ("unknown-type", "Unknown types (typos, types from missing modules, ASN.1 types)",
     {"type-unknown", "basetype-unknown", "type-or-class-unknown"}, r"unknown type", r"TC with unknown base type",
     set(), set(),
     "fall back to the base type when known, else opaque/binary"),
    ("table", "Table/row structure errors (SEQUENCE vs columns mismatch, wrong parents, AUGMENTS without row)",
     {"sequence-type-mismatch", "sequence-no-column", "sequence-missing-column", "not-a-column", "parent-table",
      "parent-row", "parent-scalar", "table-type", "row-node-subidentifier-one", "augment-no-row",
      "index-and-augments", "augment-nested", "access-row-illegal", "access-table-illegal"}, r"^$", r"^$", set(),
     set(), "derive table structure from OID nesting + INDEX/AUGMENTS, use SEQUENCE only as a hint"),
    ("index", "INDEX elements: no SIZE (variable-length encoding), illegal base types, accessible index columns",
     {"index-element-no-size", "index-element-no-range", "index-illegal-basetype", "index-element-accessible",
      "index-exceeds-too-large", "index-element-enum-negative", "index-element-range-negative"},
     r"quoted INDEX", r"^$", {"supportIndex"}, set(),
     "index encoding spec from the resolved type (fixed vs variable size, IMPLIED)"),
    ("dates", "LAST-UPDATED/REVISION problems (missing, order, 2-digit years, bad format)",
     {"revision-missing", "revision-after-update", "revision-not-descending", "date-in-past", "date-year-2digits",
      "date-character", "date-day", "date-hour", "date-month", "date-value", "date-year", "date-minutes",
      "date-length"}, r"timestamp|REVISION/clause order", r"timestamp", set(), set(),
     "store dates as strings; the YANG revision needs a best-effort parse"),
    ("strings", "Non-ASCII/illegal characters in strings, unbalanced quotes",
     {"char-illegal-string"}, r"unbalanced quotes|bad quoted|non-ASCII", r"^$", set(), {"non-utf8", "no-end"},
     "lexer works on bytes; decode strings as UTF-8 with Latin-1 fallback"),
    ("not-smi", "Text that is not SMI: RFC page headers/footers, C comments, ^Z, unquoted free text, placeholders, "
                "non-SMI ASN.1",
     {"lexical", "keyword-illegal", "choice-not-allowed", "macro-not-allowed", "export-not-allowed",
      "tagged-type-not-allowed"},
     r"RFC/draft page|C/C\+\+ style|DOS EOF|unquoted free text|placeholder|non-SMI ASN.1|empty module body",
     r"^$", set(), {"leading-text", "trailing-text", "ctrl"},
     "skip MACRO/CHOICE/EXPORTS in base modules; recover at the next top-level assignment; strip RFC artefacts"),
    ("syntax-other", "Other syntax errors (clause order, misplaced/duplicated clauses, unexpected tokens)",
     {"internal-other"}, r"^parse: (misplaced|unexpected|malformed|missing comma|REVISION)",
     r"syntax|bad parse|reserved word", set(), set(),
     "error recovery per macro invocation, so one bad definition does not lose the module"),
    ("file-layout", "File layout: several modules per file, file name != module name, same module twice in one file, "
                    "empty bodies",
     set(), r"^$", r"^$", set(), {"multi-module", "empty-body", "name-mismatch"},
     "index files by the module names they contain, not by file name"),
]


LAYER = {"identifier-chars": "lexer", "strings": "lexer", "not-smi": "lexer",
         "punctuation": "parser", "identifier-case": "parser", "enums": "parser", "ranges": "parser",
         "defval": "parser", "syntax-other": "parser", "smi-mix": "parser", "file-layout": "parser",
         "imports": "resolver", "oid-parent": "resolver", "not-imported": "resolver", "redefinition": "resolver",
         "unknown-type": "resolver",
         "index": "lint", "dates": "lint", "hyphen-label": "lint", "table": "lint"}
LAYER_ORDER = {"lexer": 0, "parser": 1, "resolver": 2, "lint": 3}


def quirk_hits(rows, st, index_rows):
    """-> {quirk key: {module: set(evidence)}}"""
    by_mod_index = {r["module"]: r for r in index_rows}
    hits = {q[0]: collections.defaultdict(set) for q in QUIRKS}
    for row in rows:
        m = row["module"]
        names = set()
        r = st["smilint"].get(m)
        if r:
            _, nm = smilint_parse(r, m)
            names = {n for (_, n) in nm}
        pclass = row.get("pysmi_relaxed_class", "") + "|" + row.get("pysmi_strict_class", "")
        nclass = row.get("netsnmp_class", "")
        d = st["pysmi-dialect"].get(m) or {}
        dopts = set(d.get("options") or [])
        dclass = lark_class(d.get("detail")) if d.get("status") == "grammar-error" else ""
        ir = by_mod_index.get(m, {})
        iflags = set(filter(None, (ir.get("quirks", "") + "," + ir.get("flags", "")).split(",")))
        if ir.get("missing_imports"):
            iflags.add("missing-import")
        if ir.get("path") and os.path.basename(ir["path"]).split(".")[0] != m:
            iflags.add("name-mismatch")
        for key, _, sn, prx, nrx, dop, ifl, _ in QUIRKS:
            ev = hits[key][m]
            if names & sn:
                ev.add("smilint")
            if prx != "^$" and (re.search(prx, row.get("pysmi_relaxed_class", "")) or
                                re.search(prx, row.get("pysmi_strict_class", "")) or (dclass and re.search(prx, dclass))):
                ev.add("pysmi")
            if dopts & dop:
                ev.add("pysmi-dialect")
            if nrx != "^$" and re.search(nrx, nclass):
                ev.add("netsnmp")
            if iflags & ifl:
                ev.add("index")
            if not ev:
                del hits[key][m]
    return hits


def pct(a, b):
    return f"{100.0 * a / b:.1f}%" if b else "-"


def md_table(hdr, rows):
    out = ["| " + " | ".join(hdr) + " |", "|" + "|".join("---" for _ in hdr) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(x).replace("|", "\\|") for x in r) + " |")
    return "\n".join(out)


def examples(mods, n=4):
    mods = sorted(mods)
    s = ", ".join(f"`{m}`" for m in mods[:n])
    return s + (" ..." if len(mods) > n else "")


# --------------------------------------------------------------------------
# Official vendor sources vs aggregator copies (section 5)
# --------------------------------------------------------------------------

FAMILY_TITLE = {"juniper": "Juniper", "nokia": "Nokia", "cisco": "Cisco", "net-snmp": "net-snmp"}
# vendor namespaces for "vendor modules not in the official bundle" (Nokia: ALCATEL-IND1-* etc. are
# Alcatel-Lucent Enterprise OmniSwitch MIBs, enterprise 6486, not SR OS: excluded)
FAMILY_NS = {"juniper": (("JUNIPER-", "JNX-"), ()), "nokia": (("TIMETRA-", "ALU-", "NOKIA-"), ()),
             "cisco": (("CISCO-",), ())}


def diff_kind(a, b):
    if a["sha"] == b["sha"]:
        return "same"
    if a["nhash"] == b["nhash"]:
        return "ws"
    if a["shash"] == b["shash"]:
        return "text"
    return "syntax"


def rev_kind(agg, off):
    la, lo = agg["last_updated"], off["last_updated"]
    if not la or not lo:
        return "undated"
    return "older" if la < lo else ("newer" if la > lo else "same")


def verdict_triplet(name, pr, ns, sl):
    p = pysmi_class(pr, name)[0] if pr else "-"
    n = netsnmp_verdict(ns, name)[0] if ns else "-"
    if sl:
        sev, _ = smilint_parse(sl, name)
        e = sev.get(1, 0) + sev.get(2, 0)
    else:
        e = None
    return p, n, e


def official_section(stats, rows, st, cache):
    """-> (lines, summary bullets) for REPORT.md section 5."""
    out = []
    w = out.append
    summ = []
    srcs = stats.get("sources", {})
    vendors = stats.get("vendors", {})
    insts = read_tsv(os.path.join(P["index"], "instances.tsv"))
    rowmap = {r["module"]: r for r in rows}
    flat_off = {k for k, v in srcs.items() if v["type"] == "official-vendor" and v["role"] == "flat"}
    by_name = collections.defaultdict(list)
    for i in insts:
        by_name[i["module"]].append(i)
    winner = {i["module"]: i for i in insts if i["winner"] == "1"}
    # the official copy of each owned module (what rule 1 prefers; the flat copy unless rule 1b or an
    # override chose another one): first flat official source in source order (Junos OS before Evolved)
    official = {}

    def off_key(i):  # rule 1 among the flat official copies: newest LAST-UPDATED, source order, depth, path
        return (-int(i["last_updated"] or 0), srcs[i["source"]].get("order", 0), i["path"].count("/"), i["path"])
    for i in insts:
        if i["owned"] == "1" and i["source"] in flat_off:
            cur = official.get(i["module"])
            if cur is None or off_key(i) < off_key(cur):
                official[i["module"]] = i

    w("## 5. Official vendor sources vs aggregator copies\n")
    w("Precedence (index.py, README.md section 1): (O) an explicit **override** (`index.py: OVERRIDES`, module -> "
      "source + path, with the reason) wins outright; (0) history releases never win, empty bodies lose; "
      "(1) an **official-vendor** source wins the modules its vendor **owns** (name prefixes and root modules of "
      "the vendor, plus bundle modules that import from them; not module names that the IETF/IANA sources also "
      "have, so bundled copies of standard MIBs never override the standards copies), newest release first, "
      "(1b) **unless** a non-history copy of another source (aggregator, other) has a LAST-UPDATED strictly newer "
      "than every official copy: then the newest such copy wins (*newer-aggregator*; ties, undated and implausible "
      "dates keep the official copy); (2) then the source rank (IETF/IANA standards and net-snmp, cisco-v2, "
      "LibreNMS, the vendor bundles' other modules, IANA, pysnmp, cisco-v1; newest revision for IANA-maintained "
      "modules); (3) newest LAST-UPDATED, shallower path, path. `duplicates.tsv` and `modules.tsv` record why each "
      "winner won (`reason`).\n")
    reasons = collections.Counter(wi.get("reason", "") for wi in winner.values())
    rsrc = collections.defaultdict(collections.Counter)
    for wi in winner.values():
        rsrc[wi.get("reason", "")][wi["source"]] += 1
    rdesc = {"override": "explicit override (`index.py: OVERRIDES`)",
             "official": "official copy of a module its vendor owns (rule 1)",
             "newer-aggregator": "non-official copy with a strictly newer LAST-UPDATED than every official copy "
                                 "(rule 1b)",
             "standards": "IETF/IANA copy by source rank / LAST-UPDATED (rules 2-5)",
             "rank": "any other source by source rank / LAST-UPDATED / path (rules 2-5)"}
    w("Why each `corpus/flat` winner won:\n")
    w(md_table(["reason", "meaning", "modules", "winner sources"],
               [[f"`{k}`", rdesc.get(k, ""), reasons[k], ", ".join(f"{s} {c}" for s, c in rsrc[k].most_common(6))]
                for k in ("override", "official", "newer-aggregator", "standards", "rank") if reasons[k]]))
    w("")
    frows = []
    for fam, v in vendors.items():
        own = set(v.get("owned", []))
        offs = sorted(k for k in flat_off if srcs[k].get("family") == fam)
        if not offs:
            continue
        own_flat = {n for n in own if any(i["source"] in offs and i["owned"] == "1" for i in by_name[n])}
        won = sum(1 for n in own_flat if winner.get(n, {}).get("source") in offs)
        newer = sum(1 for n in own_flat if winner.get(n, {}).get("reason") == "newer-aggregator")
        over = sum(1 for n in own_flat if winner.get(n, {}).get("reason") == "override")
        with_agg = sum(1 for n in own_flat if any(srcs[i["source"]]["type"] == "aggregator" for i in by_name[n]))
        frows.append([FAMILY_TITLE.get(fam, fam), ", ".join(offs), ", ".join(str(e) for e in v["enterprises"]),
                      ", ".join(v["prefixes"] + tuple(v.get("suffixes", ())) if isinstance(v["prefixes"], tuple)
                                else list(v["prefixes"]) + list(v.get("suffixes", []))),
                      len(own_flat), won, newer, over, with_agg])
    w(md_table(["vendor", "official source(s) in flat", "enterprises", "owned name patterns (+ importers)",
                "owned modules", "won by the official copy", "won by a newer aggregator copy", "override",
                "of which also in LibreNMS/pysnmp"], frows))
    w("")

    # --- overrides and newer-aggregator winners
    ovs = stats.get("overrides", [])
    if ovs:
        w("### Overrides (`index.py: OVERRIDES`)\n")
        w(md_table(["module", "chosen copy", "status", "official copy (kept in the index)", "reason"],
                   [[f"`{o['module']}`", f"{o['source']}:{o['path']}", o["status"],
                     ", ".join(sorted(f"{i['source']}:{i['path']}" for i in by_name.get(o["module"], [])
                                      if i["owned"] == "1" and i["source"] in flat_off)) or "-",
                     o["reason"]] for o in ovs]))
        w("")
    nag = stats.get("newer_aggregator", [])
    w("### Newer aggregator copies that beat the official copy (rule 1b)\n")
    if nag:
        w("A LibreNMS / mibs.pysnmp.com copy wins when its LAST-UPDATED is strictly newer than that of every "
          "official copy (history releases included). This **mixes releases**: the newer copy may import symbols "
          "that the official (older) copies of its imports do not define yet, or vice versa (see the verdict "
          "changes below).\n")
        nrows = []
        for x in nag:
            n = x["module"]
            r = rowmap.get(n, {})
            off = [i for i in by_name.get(n, []) if i["owned"] == "1" and i["source"] == x["official_source"]]
            wi = winner.get(n)
            dk = diff_kind(wi, off[0]) if wi and off else "?"
            nrows.append([f"`{n}`", f"{x['source']}:{x['path']}", x["last_updated"],
                          f"{x['official_source']}:{x['official_path']}", x["official_last_updated"], dk,
                          r.get("pysmi_relaxed", "-"), r.get("netsnmp", "-"), r.get("error_class", "")])
        w(md_table(["module", "winner", "LAST-UPDATED", "official copy", "newest official LAST-UPDATED (all releases)",
                    "diff vs official", "pysmi relaxed", "net-snmp", "error class"], nrows))
        w("")
    else:
        w("(none)\n")

    # --- aggregator copies vs the official copy
    w("### How the aggregator copies differ from the official ones\n")
    w("Every LibreNMS / mibs.pysnmp.com copy of a module owned by an official source, compared with the "
      "official copy (the one rule 1 prefers, whether or not it is the `corpus/flat` copy): identical; "
      "comments/whitespace only; only inside strings (DESCRIPTION etc.); or a syntax difference, split by the "
      "copy's LAST-UPDATED relative to the official one (older revision, same LAST-UPDATED = an unversioned edit, "
      "newer revision; as stored in the index, two-digit years read as 19YY). The newer revisions are the "
      "candidates of rule 1b.\n")
    cats = ["same", "ws", "text", "older", "same-rev", "newer", "undated"]
    ex = collections.defaultdict(list)
    trows = []
    agg_srcs = sorted(k for k, v in srcs.items() if v["type"] == "aggregator")
    totals = collections.Counter()
    for fam in ("juniper", "nokia", "cisco"):
        offs = {k for k in flat_off if srcs[k].get("family") == fam}
        if not offs:
            continue
        for agg in agg_srcs:
            c = collections.Counter()
            names = set()
            for n, lst in by_name.items():
                wi = official.get(n)
                if not wi or wi["source"] not in offs:
                    continue
                for i in lst:
                    if i["source"] != agg:
                        continue
                    k = diff_kind(i, wi)
                    if k == "syntax":
                        k = {"older": "older", "newer": "newer", "same": "same-rev", "undated": "undated"}[rev_kind(i, wi)]
                    c[k] += 1
                    names.add(n)
                    ex[(fam, agg, k)].append(f"`{n}` ({i['last_updated'] or '-'} vs {wi['last_updated'] or '-'})"
                                             if k in ("older", "newer", "same-rev") else f"`{n}`")
            if not names:
                continue
            totals[(fam, "copies")] += sum(c.values())
            for k in cats:
                totals[(fam, k)] += c[k]
            trows.append([FAMILY_TITLE[fam], agg, len(names), sum(c.values())] + [c[k] for k in cats])
    w(md_table(["vendor", "aggregator", "modules", "copies", "identical", "comments/ws only", "strings only",
                "syntax: older revision", "syntax: same LAST-UPDATED", "syntax: newer revision",
                "syntax: undated"], trows))
    w("")
    labels = {"ws": "comments/whitespace only", "text": "strings only", "older": "older revision",
              "same-rev": "same LAST-UPDATED, syntax differs", "newer": "NEWER revision than the official copy",
              "undated": "no LAST-UPDATED"}
    w("Examples (LAST-UPDATED of the aggregator copy vs the official copy):\n")
    for (fam, agg, k), lst in sorted(ex.items()):
        if k == "same":
            continue
        w(f"- {FAMILY_TITLE[fam]}, {agg}, {labels[k]} ({len(lst)}): " + ", ".join(sorted(lst)[:5]) +
          (" ..." if len(lst) > 5 else ""))
    w("")
    for fam in ("juniper", "nokia", "cisco"):
        if totals[(fam, "copies")]:
            diff = totals[(fam, "copies")] - totals[(fam, "same")]
            summ.append((fam, totals[(fam, "copies")], diff, totals[(fam, "newer")], totals[(fam, "older")]))

    # --- winner changes and oracle verdicts (oracles.sh --incremental)
    incp = os.path.join(cache, "_incremental.json")
    if os.path.exists(incp):
        with open(incp) as f:
            inc = json.load(f)
        imports = {m["module"]: [x for x in m["imports"].split(",") if x]
                   for m in read_tsv(os.path.join(P["index"], "modules.tsv"))}
        w("### What the last re-index changed in `corpus/flat`\n")
        w("From the last re-index (`cache/_incremental.json`, oracles.sh --incremental): modules whose flat copy "
          "changed (text differs from the previous winner), new modules, modules that now link to another file "
          "with identical text, and the importers (transitive) whose oracle results were recomputed. "
          "`new winner` / `reason` describe the copy chosen now.\n")
        crow = collections.Counter()
        for n, (src, path, _) in inc.get("changed_from", {}).items():
            crow[(winner.get(n, {}).get("source", "?"), winner.get(n, {}).get("reason", "?"), "from " + src)] += 1
        for n in inc.get("added", []):
            crow[(winner.get(n, {}).get("source", "?"), winner.get(n, {}).get("reason", "?"), "new")] += 1
        for n in inc.get("moved_same_text", []):
            crow[(winner.get(n, {}).get("source", "?"), winner.get(n, {}).get("reason", "?"),
                  "identical text, other file")] += 1
        for n in inc.get("removed", []):
            crow[("-", "-", "removed")] += 1
        w(md_table(["new winner", "reason", "change", "modules"], [[a, b, c, d] for (a, b, c), d in sorted(crow.items())]))
        w("")
        ch = inc.get("changed_from", {})
        if 0 < len(ch) <= 40:
            w("Changed flat copies: " + ", ".join(
                f"`{n}` ({o[0]} -> {winner.get(n, {}).get('source', '?')}, {winner.get(n, {}).get('reason', '?')})"
                for n, o in sorted(ch.items())) + f"; {len(inc.get('cascade', []))} importers re-run with them.\n")
        prev = {o: load_status(os.path.join(cache, "_prev"), o) for o in ("pysmi-relaxed", "netsnmp", "smilint")}
        seeds = set(ch) | set(inc.get("added", []))

        def via(n):
            """the changed/new modules in n's import closure (n itself included)"""
            seen, todo = set(), [n]
            while todo:
                m = todo.pop()
                if m in seen:
                    continue
                seen.add(m)
                todo.extend(imports.get(m, []))
            return sorted(seen & seeds)

        vrows = []
        regress = []
        fixed = collections.Counter()
        degraded = collections.Counter()
        for group, names in (("changed copy", sorted(ch)), ("importers (cascade)", inc.get("cascade", []))):
            c = collections.Counter()
            for n in names:
                if n not in rowmap:
                    continue
                old = verdict_triplet(n, prev["pysmi-relaxed"].get(n), prev["netsnmp"].get(n), prev["smilint"].get(n))
                new = verdict_triplet(n, st["pysmi-relaxed"].get(n), st["netsnmp"].get(n), st["smilint"].get(n))
                okp = lambda v: v in ("ok", "ok-depfail")
                if old[0] == "ok" and new[0] == "ok-depfail":
                    c["pysmi depfail now"] += 1
                    degraded[",".join(via(n))] += 1
                if okp(old[0]) != okp(new[0]):
                    c["pysmi " + ("fixed" if okp(new[0]) else "broken")] += 1
                    if okp(new[0]):
                        fixed[("pysmi", ",".join(via(n)))] += 1
                    else:
                        r = st["pysmi-relaxed"].get(n) or {}
                        why = pysmi_class(r, n)[1]
                        bad = [d for d, dv in (r.get("deps") or {}).items() if dv.get("status") in ("failed", "missing")]
                        if bad:
                            why += " (" + ", ".join(sorted(bad)[:3]) + ")"
                        regress.append((n, "pysmi", old[0], new[0], why, via(n)))
                if (old[1] == "ok") != (new[1] == "ok"):
                    c["net-snmp " + ("fixed" if new[1] == "ok" else "broken")] += 1
                    if new[1] == "ok":
                        fixed[("net-snmp", ",".join(via(n)))] += 1
                    else:
                        own = netsnmp_verdict(st["netsnmp"].get(n) or {}, n)[1]
                        why = re.sub(r"\s*\(/corpus/flat/[^)]*\)", "", own[0])[:110] if own else "not loaded"
                        regress.append((n, "net-snmp", old[1], new[1], why, via(n)))
                if old[2] is not None and new[2] is not None:
                    c["smilint sev1-2 old"] += old[2]
                    c["smilint sev1-2 new"] += new[2]
                    if (old[2] == 0) != (new[2] == 0):
                        c["smilint " + ("clean now" if new[2] == 0 else "errors now")] += 1
                c["n"] += 1
            vrows.append([group, c["n"], c["pysmi fixed"], c["pysmi broken"], c["pysmi depfail now"],
                          c["net-snmp fixed"], c["net-snmp broken"],
                          f"{c['smilint sev1-2 old']} -> {c['smilint sev1-2 new']}",
                          c["smilint clean now"], c["smilint errors now"]])
        w("Oracle verdicts before (previous flat copy, `cache/_prev/`) and after (new flat copy) for the modules "
          "re-run (pysmi `ok -> ok-depfail`: the module still compiles, but a module in its import closure now "
          "fails):\n")
        w(md_table(["modules", "n", "pysmi relaxed: fail -> ok", "ok -> fail", "ok -> ok-depfail",
                    "net-snmp: errors -> ok", "ok -> errors", "smilint sev 1-2 messages",
                    "smilint: now without sev 1-2", "now with sev 1-2"], vrows))
        w("")
        P["reindex_degraded"] = degraded
        if degraded:
            w("pysmi `ok -> ok-depfail`, by the changed module(s) in the import closure: " + "; ".join(
                f"{c} via {v or '-'}" for v, c in sorted(degraded.items(), key=lambda x: -x[1])[:10]) + ".\n")
        if fixed:
            w("Verdicts that improved, by the changed module(s) in the import closure: " + "; ".join(
                f"{o} {c} via {v or '-'}" for (o, v), c in sorted(fixed.items(), key=lambda x: -x[1])[:10]) + ".\n")
        P["reindex_regress"] = regress
        P["reindex_fixed"] = fixed
        if regress:
            w(f"Verdicts that got worse ({len(regress)}; *via* = the changed flat copies in the module's import "
              "closure, i.e. the likely cause):\n")
            w(md_table(["module", "oracle", "before", "after", "why (after)", "via"],
                       [[f"`{n}`", o, a_, b_, y.replace("|", "\\|"), ", ".join(f"`{x}`" for x in v) or "-"]
                        for n, o, a_, b_, y, v in sorted(regress)[:60]]))
            if len(regress) > 60:
                w(f"... and {len(regress) - 60} more")
            w("")

    # --- vendor modules not covered by the official bundles
    w("### Vendor modules that only the aggregators have\n")
    w("Modules in the vendor's namespace that the official bundle does not contain (removed or renamed in "
      "newer releases, other product lines, or newer than the local bundle) keep their aggregator copy:\n")
    nrows = []
    for fam, (pfx, _) in FAMILY_NS.items():
        offs = {k for k in flat_off if srcs[k].get("family") == fam}
        if not offs:
            continue
        c = collections.Counter()
        exs = collections.defaultdict(list)
        for n, wi in winner.items():
            if n.startswith(pfx) and wi["source"] not in offs and n not in official:
                c[wi["source"]] += 1
                exs[wi["source"]].append(n)
        if c:
            nrows.append([FAMILY_TITLE[fam], " ".join(p + "*" for p in pfx), sum(c.values()),
                          ", ".join(f"{k} {v}" for k, v in c.most_common()),
                          examples([x for v in exs.values() for x in v], 4)])
    w(md_table(["vendor", "names", "modules", "won by", "examples"], nrows))
    w("")

    # --- release history (history sources)
    hist = [k for k, v in srcs.items() if v.get("family") and v["type"] == "official-vendor"
            and (v["role"] == "history" or any(x["role"] == "history" and x.get("family") == v.get("family")
                                               for x in srcs.values()))]
    fams = sorted({srcs[k]["family"] for k in hist})
    for fam in fams:
        rels = sorted((k for k in hist if srcs[k]["family"] == fam),
                      key=lambda k: tuple(int(x) for x in re.findall(r"\d+", srcs[k]["release"])))
        w(f"### {FAMILY_TITLE.get(fam, fam)} releases (history sources)\n")
        w(f"The newest local release is the flat source; older ones are indexed as history sources "
          f"(`duplicates.tsv` lists every copy). Change per release (modules):\n")
        hrows = []
        prevm = None
        mods_by_rel = {}
        for k in rels:
            m = {i["module"]: i for i in insts if i["source"] == k}
            mods_by_rel[k] = m
            if prevm is None:
                hrows.append([k, srcs[k]["release"], srcs[k]["role"], len(m), "", "", "", "", ""])
            else:
                common = set(m) & set(prevm)
                kinds = collections.Counter(diff_kind(m[n], prevm[n]) for n in common)
                hrows.append([k, srcs[k]["release"], srcs[k]["role"], len(m), len(set(m) - set(prevm)),
                              len(set(prevm) - set(m)), kinds["same"], kinds["ws"] + kinds["text"], kinds["syntax"]])
            prevm = m
        w(md_table(["source", "release", "role", "modules", "added", "removed", "unchanged",
                    "comments/strings only", "syntax changed"], hrows))
        w("")
        # which official release do the aggregator copies match?
        sha_rel = collections.defaultdict(set)
        for k, m in mods_by_rel.items():
            for n, i in m.items():
                sha_rel[(n, i["sha"])].add(srcs[k]["release"])
        newest_rel = srcs[rels[-1]]["release"]
        mrows = []
        for agg in agg_srcs:
            c = collections.Counter()
            for n in set().union(*[set(m) for m in mods_by_rel.values()]):
                for i in by_name[n]:
                    if i["source"] != agg:
                        continue
                    r_ = sha_rel.get((n, i["sha"]))
                    c[" / ".join(sorted(r_, key=lambda x: tuple(int(y) for y in re.findall(r"\d+", x))))
                      if r_ else "no local release"] += 1
            if c:
                mrows.append([agg, sum(c.values()), ", ".join(f"{k} {v}" for k, v in c.most_common(6))])
        w(f"Aggregator copies of these module names, by the local release with byte-identical text "
          f"(\"no local release\": a different text, e.g. a release newer than {newest_rel} or an edited copy):\n")
        w(md_table(["aggregator", "copies", "identical to release"], mrows))
        w("")
    return out, summ


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mibs-dir", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--stage", action="store_true",
                    help="read the staged index (index.py --no-swap), write modules.tsv.new + cache/report/REPORT.md.new")
    a = ap.parse_args()
    md = a.mibs_dir
    corpus = os.path.join(md, "corpus")
    cache = os.path.join(md, "cache")
    sfx = ".new" if a.stage else ""
    P.update(index=os.path.join(corpus, "index" + sfx), dups=os.path.join(md, "duplicates.tsv" + sfx),
             vendors=os.path.join(md, "vendors.tsv" + sfx), modules_out=os.path.join(md, "modules.tsv" + sfx),
             report_out=os.path.join(cache, "report", "REPORT.md" + sfx), cache=cache)
    for k in ("index", "dups", "vendors"):
        if not os.path.exists(P[k]):
            sys.exit(f"report.py: {P[k]} missing" + (" (index.py --no-swap first)" if a.stage else ""))
    mods = read_tsv(os.path.join(P["index"], "modules.tsv"))
    with open(os.path.join(P["index"], "stats.json")) as f:
        stats = json.load(f)
    sources = read_tsv(os.path.join(corpus, "sources.tsv"))
    st = {o: load_status(cache, o) for o in ORACLES}
    os.makedirs(os.path.join(cache, "report"), exist_ok=True)

    rows = []
    cls_mods = {o: collections.defaultdict(list) for o in ["pysmi-relaxed", "pysmi-strict", "netsnmp"]}
    netsnmp_lines = collections.defaultdict(list)
    smilint_names = collections.defaultdict(set)
    smilint_counts = collections.Counter()
    dialects = collections.defaultdict(list)
    relax_opts = collections.defaultdict(list)
    oidcmp = {}
    verdicts = {}
    for m in mods:
        name = m["module"]
        row = {k: m[k] for k in ("module", "source", "vendor", "path", "size", "smi", "last_updated",
                                 "copies", "distinct")}
        row["source_type"] = m.get("source_type", "")
        row["official"] = m.get("owned", "")
        row["reason"] = m.get("reason", "")
        row["sha256"] = m["sha256"][:16]
        v = {}
        for o in ("pysmi-strict", "pysmi-relaxed"):
            r = st[o].get(name)
            if r is None:
                v[o], c = "-", ""
            else:
                v[o], c = pysmi_class(r, name)
                if c:
                    cls_mods[o][c].append(name)
            row[o.replace("-", "_")] = v[o]
            row[o.replace("-", "_") + "_class"] = c
        r = st["pysmi-dialect"].get(name)
        row["pysmi_dialect"] = dialect_class(r) if r else "-"
        if r:
            dialects[row["pysmi_dialect"].split(":")[0]].append(name)
            for opt in r.get("relaxations", []) or []:
                relax_opts[opt].append(name)
        r = st["netsnmp"].get(name)
        if r is None:
            row["netsnmp"], row["netsnmp_nodes"], row["netsnmp_class"] = "-", "", ""
        else:
            nv, own, other = netsnmp_verdict(r, name)
            row["netsnmp"] = nv
            row["netsnmp_nodes"] = str(r.get("nodes", ""))
            ocls = []
            for l in own:
                c = netsnmp_line_class(l)
                if c not in ocls:
                    ocls.append(c)
                netsnmp_lines[c].append((name, l))
            if not r.get("loaded"):
                ocls.insert(0, "module not loaded")
            row["netsnmp_class"] = ",".join(ocls[:3])
            for c in ocls:
                cls_mods["netsnmp"][c].append(name)
            v["netsnmp"] = nv
        r = st["smilint"].get(name)
        if r is None:
            row["smilint"], row["smilint_top"] = "-", ""
        else:
            sev, names = smilint_parse(r, name)
            row["smilint"] = "/".join(str(sev.get(i, 0)) for i in range(1, 7))
            if r.get("status") in ("crash", "timeout"):
                row["smilint"] = r["status"]
                names[(0, "smilint-" + r["status"])] += 1
            top = [n for (s, n), _ in sorted(names.items(), key=lambda x: (x[0][0], -x[1])) if s <= 2][:3]
            row["smilint_top"] = ",".join(top)
            for (s, n), c in names.items():
                smilint_names[(s, n)].add(name)
                smilint_counts[(s, n)] += c
            v["smilint"] = "sev1" if sev.get(1) else ("sev2" if sev.get(2) else "ok")
        # primary error class
        ec = ""
        for o in ("pysmi-relaxed", "pysmi-strict"):
            if row[o.replace("-", "_")] in ("fail", "depfail", "missing", "timeout", "crash"):
                ec = ("" if o == "pysmi-relaxed" else "strict-only ") + row[o.replace("-", "_") + "_class"]
                break
        if not ec and row.get("netsnmp") in ("fail", "errors"):
            ec = "netsnmp: " + row["netsnmp_class"].split(",")[0]
        if not ec and row.get("smilint_top"):
            ec = "smilint: " + row["smilint_top"].split(",")[0]
        row["error_class"] = ec
        row["arc"], row["enterprise"] = module_arc(cache, name)
        oc = oid_compare(cache, name)
        if oc is not None:
            oidcmp[name] = oc
            row["oid_agree"] = f"{oc['agree']}/{oc['pysmi']}/{oc['netsnmp']}"
        else:
            row["oid_agree"] = ""
        verdicts[name] = v
        rows.append(row)

    cols = ["module", "source", "vendor", "path", "size", "sha256", "smi", "last_updated", "copies", "distinct",
            "pysmi_strict", "pysmi_relaxed", "pysmi_dialect", "netsnmp", "netsnmp_nodes", "smilint",
            "error_class", "pysmi_relaxed_class", "netsnmp_class", "smilint_top", "oid_agree", "arc", "enterprise",
            "source_type", "official", "reason"]
    write_atomic(P["modules_out"],
                 "# One row per unique module name (the corpus/flat winner); see README.md for the columns.\n" +
                 "\t".join(cols) + "\n" +
                 "".join("\t".join(str(r.get(c, "")) for c in cols) + "\n" for r in rows))

    # full class lists (not committed)
    for o, d in cls_mods.items():
        with open(os.path.join(cache, "report", o + "-classes.tsv"), "w") as f:
            for c, ms in sorted(d.items(), key=lambda x: -len(x[1])):
                f.write(f"{c}\t{len(ms)}\t{','.join(sorted(ms))}\n")
    with open(os.path.join(cache, "report", "netsnmp-lines.tsv"), "w") as f:
        for c, ls in sorted(netsnmp_lines.items(), key=lambda x: -len(x[1])):
            for mname, l in ls:
                f.write(f"{c}\t{mname}\t{l}\n")

    write_report(md, mods, stats, sources, rows, st, cls_mods, smilint_names, smilint_counts, dialects,
                 relax_opts, oidcmp)


def write_report(md, mods, stats, sources, rows, st, cls_mods, smilint_names, smilint_counts, dialects,
                 relax_opts, oidcmp):
    N = len(rows)
    out = []
    w = out.append
    # cascading failures: which failed imports take the most dependents with them
    rowmap = {r["module"]: r for r in rows}
    cas = collections.defaultdict(list)
    for r in rows:
        if r["pysmi_relaxed"] != "depfail":
            continue
        rr = st["pysmi-relaxed"].get(r["module"]) or {}
        for d, dv in (rr.get("deps") or {}).items():
            if dv.get("status") in ("failed", "missing"):
                cas[d].append(r["module"])
    culprits = []
    for d, ms in sorted(cas.items(), key=lambda x: -len(x[1])):
        own = rowmap.get(d, {}).get("pysmi_relaxed_class", "") or ("missing" if d not in rowmap else "")
        culprits.append((d, len(ms), (own, ms)))
    w("# MIB corpus and oracle report\n")
    w("Generated by `report.py` from the corpus index and the oracle results "
      "(see README.md for how to reproduce). All counts are per **unique module name** "
      "(the de-duplicated set in `corpus/flat`) unless stated otherwise.\n")

    # --- corpus
    w("## 1. Corpus\n")
    srows = []
    ps = stats["per_source"]
    srcmap = {s["source"]: s for s in sources}
    def src_of(label):
        return {"ietf": "ietf-iana", "iana": "ietf-iana", "cisco-v2": "cisco", "cisco-v1": "cisco"}.get(label, label)
    def origin(url):
        url = url.replace("https://", "")
        if url.startswith("apps.juniper.net/mib-explorer/downloadArchive"):
            return "apps.juniper.net/mib-explorer (" + url.split("filename=")[-1] + ")"
        return url
    for label, d in ps.items():
        s = srcmap.get(src_of(label), {})
        srows.append([label, d.get("type", ""), d.get("role", "flat"), origin(s.get("url", "")), s.get("ref", ""),
                      s.get("commit", "")[:12], d["files"], d["mib_files"], d["instances"], d.get("owned", 0),
                      d["winners"], f"{d['bytes'] / 1e6:.1f}"])
    srows.append(["**total** (flat sources)", "", "", "", "", "", stats["files"], stats["mib_files"],
                  stats["instances"], "", stats["unique_modules"], f"{stats['bytes'] / 1e6:.1f}"])
    w(md_table(["source", "type", "role", "origin", "ref", "commit", "files", "MIB files", "module instances",
                "official (owned)", "unique winners", "MB"], srows))
    w("")
    w("*type*: official-vendor = the vendor's own distribution (authoritative for the modules it owns, "
      "*official (owned)* instances), standards = IETF/IANA, aggregator = collections of copies, other = derived "
      "(cisco-v1: SMIv1 conversions). *role* history = older vendor releases: indexed (instances, "
      "`duplicates.tsv`, section 5) but never chosen for `corpus/flat`; the totals and all statistics below "
      "cover the flat sources only. Winner rule: README.md section 1 / section 5 below.\n")
    w(f"- **{stats['unique_modules']} unique module names** from {stats['instances']} module instances "
      f"in {stats['mib_files']} MIB files ({stats['files'] - stats['mib_files']} other files: "
      "READMEs, scripts, archives).")
    w(f"- **{stats['dup_names']} module names occur more than once**; {stats['dup_names_conflicting']} of them "
      f"with differing text, {stats['dup_names_syntax_conflict']} differing outside comments/strings "
      "(real content differences, mostly other revisions). `duplicates.tsv` lists every copy.")
    hist_srcs = {k for k, v in stats.get("sources", {}).items() if v.get("role") == "history"}
    dup_all = read_tsv(P["dups"])
    # corpus statistics: flat sources only (history sources are covered in section 5)
    dup = [d for d in dup_all if d["source"] not in hist_srcs]
    ncopies = collections.Counter(d["module"] for d in dup)
    dup = [d for d in dup if ncopies[d["module"]] > 1]
    for d in dup:
        d["copies"] = str(ncopies[d["module"]])
    dc = collections.Counter(d["diff"] for d in dup if d["winner"] == "0")
    w(f"- Non-winning copies vs. the winner: {dc.get('same', 0)} identical, {dc.get('ws', 0)} differ only in "
      f"comments/whitespace, {dc.get('text', 0)} only inside strings, {dc.get('syntax', 0)} in the syntax.")
    multi = collections.Counter()
    for d in dup:
        multi[d["module"]] = int(d["copies"])
    w("- Most copied module names: " + ", ".join(f"`{k}` ({v})" for k, v in multi.most_common(12)) + ".")
    # within-vendor conflicts (same name, two different texts in one source) matter for the resolver
    by_name = collections.defaultdict(list)
    for d in dup:
        by_name[d["module"]].append(d)
    cross_vendor = sum(1 for k, v in by_name.items()
                       if len({x["source"] + "/" + x["vendor"] for x in v if x["diff"] == "syntax"}) >= 1
                       and len({x["vendor"] for x in v}) > 1)
    w(f"- {cross_vendor} duplicated names have copies in more than one vendor directory or source "
      "with a syntax-level difference: a global module-name namespace is not enough; the resolver needs "
      "ordered search paths (per device/vendor) and must report which file won.")
    same_lu = 0
    for k, v in by_name.items():
        w0 = [x for x in v if x["winner"] == "1"]
        if not w0 or not w0[0]["last_updated"]:
            continue
        if any(x["diff"] == "syntax" and x["last_updated"] == w0[0]["last_updated"] for x in v):
            same_lu += 1
    w(f"- {same_lu} module names have a copy that differs from the winner in the syntax but carries the "
      "*same* LAST-UPDATED: LAST-UPDATED/REVISION is not a reliable version key; the resolver should identify "
      "a module version by content hash.")
    smi = stats["smi"]
    w(f"- SMI version (lexical heuristic): SMIv2 {smi.get('v2', 0)}, SMIv1 {smi.get('v1', 0)}, "
      f"SPPI/PIB {smi.get('pib', 0)}, undetermined {smi.get('?', 0)}.")
    ff = stats["file_flags"]
    w("- Lexical properties of the MIB files: see the table below "
      "(crlf = CRLF line ends, non-utf8 = bytes > 0x7f that are not UTF-8 (Latin-1/CP1252), "
      "tab, formfeed, ctrl = other control characters, multi-module = several modules in one file, "
      "inline-comment-end = a `--` comment closed by a second `--` and followed by text "
      "(ASN.1 ends the comment there, most tools do not), leading/trailing-text = text outside the module, "
      "utf8 = valid UTF-8 with non-ASCII bytes, bom = UTF-8 byte order mark, cr = old Mac line ends).")
    files = [f for f in read_tsv(os.path.join(P["index"], "files.tsv")) if f["modules"] and f["source"] not in hist_srcs]
    winners = {(r["source"], r["path"]) for r in mods}
    flag_ex = collections.defaultdict(list)
    flag_n = collections.Counter()
    flag_w = collections.Counter()
    for f in files:
        for fl in filter(None, f["flags"].split(",")):
            flag_n[fl] += 1
            if (f["source"], f["path"]) in winners:
                flag_w[fl] += 1
                flag_ex[fl].append(f["source"] + ":" + f["path"])
    w("")
    w(md_table(["lexical flag (MIB files)", "files", "of which winners", "examples"],
               [[k, v, flag_w[k], ", ".join(f"`{x}`" for x in flag_ex[k][:3])]
                for k, v in sorted(flag_n.items(), key=lambda x: -x[1])]))
    w("")
    mq = stats["module_quirks"]
    w("- Module-level lexical quirks (winners): " + ", ".join(f"{k} {v}" for k, v in mq.items()) + ".")
    mi = stats["missing_imports"]
    w(f"- Imports of modules that exist nowhere in the corpus: {len(mi)} names, e.g. " +
      ", ".join(f"`{k}` ({v})" for k, v in mi[:12]) +
      ". Typos/aliases of real modules (`RFC-1213` for `RFC1213-MIB`, `RFC1212` for `RFC-1212`) are common: "
      "the resolver needs an alias table.")
    w("")
    ent_names = enterprise_names(os.path.join(md, "cache"))
    arcs = collections.Counter(r["arc"] or "(no nodes)" for r in rows)
    w("Where the modules live in the OID tree (majority arc of the nodes net-snmp attributes to each module): " +
      ", ".join(f"{k} {v}" for k, v in arcs.most_common()) + ".\n")
    ents = collections.defaultdict(list)
    for r in rows:
        if r["enterprise"]:
            ents[r["enterprise"]].append(r)
    w(f"{len(ents)} distinct enterprises (1.3.6.1.4.1.N). Largest, by modules (a vendor breakdown independent of "
      "the source directory layout):\n")
    erows = []
    for e, rs in sorted(ents.items(), key=lambda x: -len(x[1]))[:30]:
        n = len(rs)
        p = sum(1 for r in rs if r["pysmi_relaxed"] in ("ok", "ok-depfail"))
        ns = sum(1 for r in rs if r["netsnmp"] == "ok")
        srcs = collections.Counter(r["source"] for r in rs)
        erows.append([e, ent_names.get(e, ""), n, ", ".join(f"{k} {v}" for k, v in srcs.most_common()),
                      pct(p, n), pct(ns, n)])
    w(md_table(["enterprise", "name", "modules", "sources", "pysmi ok", "net-snmp ok"], erows))
    w("")
    vend = read_tsv(P["vendors"])
    vrows = sorted(vend, key=lambda x: -int(x["winners"]))[:30]
    w("Largest vendor groups (by unique modules won; full list in `vendors.tsv`):\n")
    w(md_table(["source", "vendor", "files", "modules", "winners", "MB"],
               [[v["source"], v["vendor"], v["files"], v["modules"], v["winners"],
                 f"{int(v['bytes']) / 1e6:.1f}"] for v in vrows]))
    w("")

    # --- oracle summary
    w("## 2. Oracle verdicts\n")
    w("Oracles: **pysmi 2.0.0** (`mibdump --destination-format json`, relaxed = default, strict = `--strict`; "
      "plus a parse-only *dialect* probe), **net-snmp 5.9.4** (libnetsnmp MIB parser via `mibwalk`, "
      "the same parser as `snmptranslate`), **libsmi 0.4.8** (`smilint -l 9`). "
      "Each module is compiled on its own with its imports resolved from `corpus/flat`.\n")
    vc = {}
    for o, key in (("pysmi-relaxed", "pysmi_relaxed"), ("pysmi-strict", "pysmi_strict"), ("netsnmp", "netsnmp")):
        vc[o] = collections.Counter(r[key] for r in rows)
    srows = []
    for o in ("pysmi-relaxed", "pysmi-strict"):
        c = vc[o]
        okn = c["ok"] + c["ok-depfail"]
        srows.append([o, len(st[o]), f"{okn} ({pct(okn, N)})", c["ok-depfail"], c["fail"], c["depfail"],
                      c["missing"], c["timeout"] + c["crash"]])
    w(md_table(["oracle", "ran", "ok (compiled)", "of which some import failed", "fail (own error)",
                "fail (import failed)", "missing", "timeout/crash"], srows))
    w("")
    w("pysmi strict caveat: `mibdump --strict` rejects the SMI base modules themselves (SNMPv2-SMI: "
      "\"Duplicate symbol found: Integer32\", SNMPv2-TC and RFC1213-MIB: \"DisplayString\"), so on a source "
      "corpus every module importing them fails; in normal use pysmi hides this by borrowing precompiled base "
      "modules from mibs.pysnmp.com. Our strict run therefore processes pysmi's base modules "
      "(`JsonCodeGen.baseMibs`) non-strictly and everything else strictly.\n")
    c = vc["netsnmp"]
    w(f"- **net-snmp**: {c['ok']} ok ({pct(c['ok'], N)}), {c['errors']} loaded with errors attributed to the "
      f"module itself, {c['fail']} not loaded, {c['timeout']} timeouts. net-snmp is very lenient: it "
      "skips what it cannot parse and still links the rest, often silently.")
    sl = collections.Counter()
    for r in rows:
        s = r["smilint"]
        if "/" not in s:
            sl[s] += 1
            continue
        a = [int(x) for x in s.split("/")]
        sl["sev1" if a[0] else ("sev2" if a[1] else ("sev3" if a[2] else ("warn" if a[3] + a[4] else "clean")))] += 1
    w(f"- **smilint** (highest severity per module): severe (1: syntax error, module not found) {sl['sev1']}, "
      f"error (2) {sl['sev2']}, minor error (3) {sl['sev3']}, only warnings (4-5) {sl['warn']}, "
      f"clean or notices only {sl['clean']}; smilint crashed (segfault/abort) on {sl['crash']} and timed out "
      f"on {sl['timeout']}.")
    dd = {k: len(v) for k, v in dialects.items()}
    w(f"- **pysmi dialect probe** (module text alone, no imports): " + ", ".join(
        f"{k} {v}" for k, v in sorted(dd.items(), key=lambda x: -x[1])) +
      " (smiv2 = parses with pysmi's SMIv2 option set {}, smiv1 = needs only the SMIv1 options, "
      "relaxed = needs one of the relaxation options, grammar-error = the lark grammar rejects it whatever "
      "the options, ast-error = rejected while building the AST).")
    w("")
    # per source
    w("Per source (pysmi relaxed ok / net-snmp ok / smilint without severity 1-2):\n")
    ps_rows = []
    by_src = collections.defaultdict(list)
    for r in rows:
        by_src[r["source"]].append(r)
    for s, rs in sorted(by_src.items(), key=lambda x: -len(x[1])):
        n = len(rs)
        p = sum(1 for r in rs if r["pysmi_relaxed"] in ("ok", "ok-depfail"))
        ns = sum(1 for r in rs if r["netsnmp"] == "ok")
        sm = sum(1 for r in rs if "/" in r["smilint"] and r["smilint"].split("/")[0] == "0"
                 and r["smilint"].split("/")[1] == "0")
        ps_rows.append([s, n, pct(p, n), pct(ns, n), pct(sm, n)])
    w(md_table(["source", "modules", "pysmi relaxed ok", "net-snmp ok", "smilint no sev 1-2"], ps_rows))
    w("")
    # agreement
    w("Agreement between pysmi (relaxed) and net-snmp:\n")
    ag = collections.Counter()
    for r in rows:
        if r["pysmi_relaxed"] == "-" or r["netsnmp"] == "-":
            continue
        p = r["pysmi_relaxed"] in ("ok", "ok-depfail")
        n = r["netsnmp"] == "ok"
        ag[(p, n)] += 1
    w(md_table(["", "net-snmp ok", "net-snmp errors/fail"],
               [["pysmi ok", ag[(True, True)], ag[(True, False)]],
                ["pysmi fail", ag[(False, True)], ag[(False, False)]]]))
    w("")
    tot_p = tot_a = 0
    mods_d = []
    if oidcmp:
        tot_p = sum(o["pysmi"] for o in oidcmp.values())
        tot_a = sum(o["agree"] for o in oidcmp.values())
        tot_d = sum(len(o["differ"]) for o in oidcmp.values())
        tot_op = sum(len(o["only_pysmi"]) for o in oidcmp.values())
        tot_on = sum(len(o["only_netsnmp"]) for o in oidcmp.values())
        mods_d = [m for m, o in oidcmp.items() if o["differ"]]
        w(f"OID cross-check on {len(oidcmp)} modules that pysmi (relaxed) compiled and for which net-snmp produced a node dump "
          "(including modules that net-snmp loaded with errors): "
          f"{tot_a} of {tot_p} pysmi OID assignments ({pct(tot_a, tot_p)}) have the same name->OID in net-snmp; "
          f"{tot_d} names map to different OIDs (in {len(mods_d)} modules, e.g. {examples(mods_d)}); "
          f"{tot_op} names only in pysmi, {tot_on} only in net-snmp (net-snmp drops what it cannot link, "
          "pysmi has no entries for some macro kinds). Disagreements are where an oracle is wrong: check "
          "both before trusting either.\n")

    # --- whole-corpus net-snmp load
    allj = os.path.join(md, "cache", "netsnmp-all", "all.jsonl")
    if os.path.exists(allj):
        names_by_oid = collections.defaultdict(set)
        oids_by_name = collections.defaultdict(set)
        multi_mod = 0
        nodes = 0
        with open(allj) as f:
            for l in f:
                o = json.loads(l)
                if "oid" not in o:
                    continue
                nodes += 1
                names_by_oid[o["oid"]].add(o["name"])
                oids_by_name[o["name"]].add(o["oid"])
                if len(o.get("modules", [])) > 1:
                    multi_mod += 1
        errf = os.path.join(md, "cache", "netsnmp-all", "all.err")
        nerr = sum(1 for _ in open(errf, errors="replace")) if os.path.exists(errf) else 0
        tzf = os.path.join(md, "cache", "netsnmp-all", "Tz.txt")
        ntz = sum(1 for _ in open(tzf, errors="replace")) if os.path.exists(tzf) else 0
        oid_multi = [k for k, v in names_by_oid.items() if len(v) > 1]
        name_multi = [k for k, v in oids_by_name.items() if len(v) > 1]
        w("### Whole corpus in one namespace (net-snmp `-m ALL`)\n")
        w(f"Loading all {N} modules into one net-snmp tree (`oracles.sh --whole`: `snmptranslate -m ALL -Tz` "
          f"= {ntz} lines, `mibwalk ALL`) gives {nodes} nodes; {multi_mod} nodes are defined by more than one "
          f"module, {len(oid_multi)} OIDs carry more than one name, and {len(name_multi)} names are used for "
          f"more than one OID (e.g. " + ", ".join(f"`{k}`" for k in sorted(name_multi, key=lambda k: -len(oids_by_name[k]))[:6]) +
          f"); {nerr} parse messages. A global name->OID map is ambiguous: symbolic names must be qualified "
          "by module (`IF-MIB::ifIndex`).\n")

    # --- known oracle defects
    w("### Known oracle defects (do not copy them into expected data)\n")
    big_subid = [m for m, o in oidcmp.items() if any(
        any(int(x) >= 2 ** 31 for x in po.split(".")) for _, po, _ in o["pairs"])]
    sl_crash = [r["module"] for r in rows if r["smilint"] in ("crash", "timeout")]
    py_crash = [r["module"] for r in rows if r["pysmi_relaxed"] in ("crash", "timeout")]
    py_big = [r["module"] for r in rows if r["pysmi_relaxed_class"].startswith("file too large")]
    us_mod = [r["module"] for r in rows if "_" in r["module"]]
    us_ns = [m for m in us_mod if next((r for r in rows if r["module"] == m), {}).get("netsnmp") == "fail"]
    w(f"- net-snmp's MIB parser sign-extends OID sub-identifiers >= 2^31 (3922453424 becomes "
      f"18446744073337037744): found by the OID cross-check in {examples(big_subid)}. pysmi is right there.")
    w(f"- net-snmp (without `-Pu`) and libsmi cannot even locate modules whose *name* contains `_`: "
      f"{len(us_ns)} of {len(us_mod)} such modules are not loaded by net-snmp (e.g. {examples(us_ns, 3)}).")
    w(f"- smilint crashes (segfault/abort) or hangs on {len(sl_crash)} modules ({examples(sl_crash, 4)}); "
      f"pysmi crashes or times out (150 s) on {len(py_crash)} ({examples(py_crash, 4)}).")
    w(f"- pysmi refuses files larger than 10 MB ({examples(py_big)}).")
    w("- pysmi strict mode rejects its own base modules (see above).\n")

    # --- quirk catalogue
    w("## 3. Quirk classes ranked (all oracles + lexical index)\n")
    w("Each quirk class unifies evidence from smilint error names, pysmi failure classes, the pysmi dialect probe, "
      "net-snmp messages and the lexical index (definitions in `report.py: QUIRKS`). *modules* counts distinct "
      "modules with evidence from any source; the per-oracle columns show who sees it. Ranked by modules.\n")
    index_rows = read_tsv(os.path.join(P["index"], "modules.tsv"))
    hits = quirk_hits(rows, st, index_rows)
    quirk_break = {}
    failing = {r["module"] for r in rows if r["pysmi_relaxed"] in ("fail", "depfail")
               or r["netsnmp"] in ("fail", "errors")}
    qrows = []
    for key, title, _, _, _, _, _, impl in sorted(QUIRKS, key=lambda q: (LAYER_ORDER[LAYER[q[0]]],
                                                                         -len(hits[q[0]]))):
        h = hits[key]
        cnt = collections.Counter(e for ev in h.values() for e in ev)
        breaks = sum(1 for m, ev in h.items() if m in failing and ev & {"pysmi", "netsnmp"})
        quirk_break[key] = breaks
        qrows.append([LAYER[key], f"**{key}**: {title}", len(h), pct(len(h), N), breaks, cnt["smilint"],
                      cnt["pysmi"] + cnt["pysmi-dialect"], cnt["netsnmp"], cnt["index"], examples(list(h), 3), impl])
    w(md_table(["layer", "quirk", "modules", "% of corpus", "breaks pysmi/net-snmp", "smilint", "pysmi", "net-snmp",
                "index", "examples", "implication for our compiler"], qrows))
    w("")
    w("*layer*: where our compiler has to deal with it (lint = no effect on parsing/resolution, only on "
      "validation and the generated metadata). *breaks pysmi/net-snmp*: modules where this quirk is among "
      "the reasons pysmi (relaxed) fails or net-snmp reports errors for the module. The pysmi column includes "
      "modules that only need one of pysmi's relaxation options (dialect probe), which pysmi accepts by default.")
    w("")
    with open(os.path.join(md, "cache", "report", "quirks.tsv"), "w") as f:
        for key, h in hits.items():
            for m, ev in sorted(h.items()):
                f.write(f"{key}\t{m}\t{','.join(sorted(ev))}\n")

    # --- error classes
    w("## 4. Error classes per oracle\n")
    for o in ("pysmi-relaxed", "pysmi-strict"):
        d = cls_mods[o]
        if o == "pysmi-strict":
            # only report the classes that are strict-specific
            relaxed_fail = {r["module"] for r in rows if r["pysmi_relaxed"] not in ("ok", "ok-depfail")}
            d = {c: [m for m in ms if m not in relaxed_fail] for c, ms in d.items()}
            d = {c: ms for c, ms in d.items() if ms}
            w(f"### pysmi strict: additional failures (relaxed ok, strict fails)\n")
        else:
            w(f"### pysmi relaxed (mibdump default): failure classes\n")
        trs = [[c, len(ms), examples(ms)] for c, ms in sorted(d.items(), key=lambda x: -len(x[1]))[:TOP]]
        w(md_table(["class", "modules", "examples"], trs) if trs else "(none)")
        w("")
    w("### pysmi: cascading failures - the broken imports that fail the most dependents\n")
    w(md_table(["broken module", "dependents failing in pysmi (relaxed)", "its own error class", "examples"],
               [[f"`{c}`", n, cls, examples(ex, 3)] for c, n, (cls, ex) in
                [(c, n, x) for c, n, x in culprits[:20]]]))
    w("")
    w("### net-snmp: messages attributed to the module itself\n")
    d = cls_mods["netsnmp"]
    trs = [[c, len(ms), examples(ms)] for c, ms in sorted(d.items(), key=lambda x: -len(x[1]))[:TOP]]
    w(md_table(["class", "modules", "examples"], trs) if trs else "(none)")
    w("")
    w("### smilint: most frequent error names (severity <= 3), by modules affected\n")
    trs = [[s, n, SMILINT_MSG.get((s, n), ""), len(ms), smilint_counts[(s, n)], examples(ms, 3)]
           for (s, n), ms in sorted(smilint_names.items(), key=lambda x: -len(x[1])) if s <= 3][:40]
    w(md_table(["sev", "error", "message", "modules", "occurrences", "examples"], trs))
    w("")
    w("### smilint: most frequent warnings (severity 4-6)\n")
    trs = [[s, n, SMILINT_MSG.get((s, n), ""), len(ms), smilint_counts[(s, n)], examples(ms, 3)]
           for (s, n), ms in sorted(smilint_names.items(), key=lambda x: -len(x[1])) if s >= 4][:20]
    w(md_table(["sev", "warning", "message", "modules", "occurrences", "examples"], trs))
    w("")
    w("### pysmi grammar relaxation options needed (dialect probe)\n")
    trs = [[k, len(v), examples(v)] for k, v in sorted(relax_opts.items(), key=lambda x: -len(x[1]))]
    w(md_table(["option", "modules", "examples"], trs) if trs else "(none)")
    w("")
    # --- official vendor sources (section 5)
    off_lines, off_summ = official_section(stats, rows, st, P["cache"])
    out.extend(off_lines)
    w("## Notes\n")
    w("- The Juniper and Nokia MIB texts are not redistributable: only their pins (`pins/juniper.tsv`, "
      "`pins/nokia.tsv`), hashes and these statistics are committed; the golden set references them by "
      "path + sha256, and its expected oracle outputs for vendor/IEEE modules are generated locally "
      "(`golden/expected-local/`, not committed).")
    w("- Re-index history (2026-10-10): (1) official precedence for Juniper/Nokia: 102 flat copies changed "
      "(+44 new modules, 131 identical texts now official), 160 importers re-run; the official `JUNIPER-SMI` "
      "(TEXTUAL-CONVENTION/Opaque used without IMPORTS) failed pysmi and took 151 Juniper modules with it "
      "(`cache/_prev.round1-official/`). (2) The override list (`JUNIPER-SMI` from LibreNMS) and the "
      "newer-aggregator rule (rule 1b): section 5 above.")
    w("- Mixing releases: with rule 1b a newer LibreNMS/pysnmp copy of one module sits next to older official "
      "copies of the modules it imports (LibreNMS's `TIMETRA-SAP-MIB`, LAST-UPDATED 2025, imports TCs that the "
      "19.7.R1 `TIMETRA-TC-MIB` does not define yet), and an override can drop symbols the official copy defines "
      "(LibreNMS's `JUNIPER-SMI` lacks `jnxSoftGreMibRoot`): every such import mismatch is listed under "
      "\"Verdicts that got worse\" in section 5.")
    w("")
    # --- summary (inserted after the title)
    sm = []
    a = sm.append
    a("## Summary\n")
    okr = sum(1 for r in rows if r["pysmi_relaxed"] in ("ok", "ok-depfail"))
    oks = sum(1 for r in rows if r["pysmi_strict"] in ("ok", "ok-depfail"))
    okn = sum(1 for r in rows if r["netsnmp"] == "ok")
    oksl = sum(1 for r in rows if "/" in r["smilint"] and r["smilint"].split("/")[0] == "0"
               and r["smilint"].split("/")[1] == "0")
    all_ok = sum(1 for r in rows if r["pysmi_relaxed"] == "ok" and r["pysmi_strict"] == "ok" and r["netsnmp"] == "ok"
                 and "/" in r["smilint"] and r["smilint"].split("/")[0] == "0")
    nflat = sum(1 for v in stats["per_source"].values() if v.get("role", "flat") == "flat")
    nhist = sum(1 for v in stats["per_source"].values() if v.get("role") == "history")
    a(f"- Corpus: {stats['files']} files ({stats['bytes'] / 1e6:.0f} MB) from {nflat} pinned source labels "
      f"(+{nhist} history releases) -> "
      f"**{N} unique modules**; {stats['dup_names']} names occur more than once, {stats['dup_names_syntax_conflict']} "
      "of them with real content differences.")
    a(f"- pysmi compiles **{pct(okr, N)}** (relaxed, the mibdump default) / {pct(oks, N)} (strict); net-snmp loads "
      f"**{pct(okn, N)}** without a message about the module itself; smilint reports no severity 1-2 problem for "
      f"only **{pct(oksl, N)}**. {pct(all_ok, N)} pass pysmi (relaxed and strict), net-snmp and smilint severity 1 "
      "together. Valid SMI is the exception in vendor MIBs; a useful compiler must be lenient and report "
      "instead of rejecting.")
    a(f"- Failures cascade: {sum(1 for r in rows if r['pysmi_relaxed'] == 'depfail')} modules fail in pysmi only "
      f"because an imported module failed; the top {len(culprits[:10])} broken modules account for "
      f"{sum(n for _, n, _ in culprits[:10])} of those (section 4). Graceful degradation (partial symbol tables) "
      "matters as much as accepting quirks.")
    by_break = sorted(((k, v) for k, v in quirk_break.items()), key=lambda x: -x[1])[:6]
    a("- Quirks that actually break the existing compilers most often (modules): " +
      ", ".join(f"{k} {v}" for k, v in by_break) + " (section 3).")
    lexparse = sorted(((k, len(hits[k])) for k in hits if LAYER[k] in ("lexer", "parser")), key=lambda x: -x[1])
    a("- Lexer/parser quirks by modules affected: " + ", ".join(f"{k} {v}" for k, v in lexparse) + ".")
    incp = os.path.join(P["cache"], "_incremental.json")
    if os.path.exists(incp):
        with open(incp) as f:
            inc = json.load(f)
        reg = P.get("reindex_regress") or []
        fx = P.get("reindex_fixed") or {}
        rs = stats.get("reasons", {})
        a(f"- Last re-index (precedence: override list + newer-aggregator rule): {len(inc['changed'])} flat copies "
          f"replaced by a different text ({rs.get('override', 0)} override, {rs.get('newer-aggregator', 0)} "
          f"newer aggregator copies), {len(inc['added'])} new modules; oracles re-run on {len(inc['rerun'])} "
          f"modules incl. importers: {sum(c for (o, _), c in fx.items() if o == 'pysmi')} pysmi verdicts fixed "
          "(" + ", ".join(sorted({v for (_, v), _ in fx.items() if v})) + "); worse: "
          f"{sum(1 for r in reg if r[1] == 'pysmi')} pysmi and {sum(1 for r in reg if r[1] == 'net-snmp')} "
          f"net-snmp verdicts in {len({r[0] for r in reg})} modules" +
          (f", {sum(P['reindex_degraded'].values())} importers now compile with a failed import"
           if P.get("reindex_degraded") else "") +
          " (import mismatches: mixed releases, override; listed in section 5).")
    if off_summ:
        a("- Official vendor sources take precedence for the modules their vendor owns: " + "; ".join(
            f"{FAMILY_TITLE[f]}: {d} of {c} LibreNMS/pysnmp copies differ from the official text "
            f"({nw} carry a newer, {od} an older LAST-UPDATED)" for f, c, d, nw, od in off_summ) + " (section 5).")
    if oidcmp:
        a(f"- Where pysmi compiles a module and net-snmp dumps it (possibly with errors) they agree on {pct(tot_a, tot_p)} of the name->OID "
          f"assignments; {len(mods_d)} modules have conflicting OIDs between the two oracles.")
    a("")
    out[2:2] = sm

    write_atomic(P["report_out"], "\n".join(out) + "\n")
    print(f"wrote modules.tsv ({len(rows)} rows) and {os.path.relpath(P['report_out'], md)}", file=sys.stderr)


if __name__ == "__main__":
    main()
