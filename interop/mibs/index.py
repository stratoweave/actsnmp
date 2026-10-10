#!/usr/bin/env python3
"""Index the fetched MIB corpus and build the de-duplicated flat directory.

    python3 index.py --corpus interop/mibs/corpus --out interop/mibs [--no-swap]

Reads   corpus/src/<source dir>/...  (fetch.sh; see SOURCES and discover_sources)
Writes  (staged next to the published versions, then swapped in atomically by
        swap.py unless --no-swap)
        corpus/index/files.tsv      every file: source, path, size, sha256, lexical flags, modules
        corpus/index/instances.tsv  every module instance (a file may hold several modules)
        corpus/index/modules.tsv    one row per module name: the chosen instance ("winner")
        corpus/index/stats.json     counts, source types/roles/releases, official ownership (report.py)
        corpus/flat/<MODULE>        winner of each module name: relative symlink to the source
                                    file, or (multi-module files) the extracted module text
                                    under corpus/split/
        OUT/duplicates.tsv          (committed) all instances of module names seen more than once
        OUT/vendors.tsv             (committed) per source/vendor counts and sizes

Pure stdlib; parallel over files (multiprocessing). Module detection is a
lexical scan (comments and strings masked), not a parse: a module starts at
"<Name> DEFINITIONS ::= BEGIN" (also PIB-DEFINITIONS, "... TAGS ::="), and
ends at the last END before the next module header.

Winner (corpus/flat copy) of a module name, first rule that decides:
  O. an explicit OVERRIDES entry (module -> source + path, with the reason);
  0. instances of history sources (older vendor releases) never win; an
     instance with an empty body loses against any non-empty one;
  1. an official-vendor source that OWNS the module (VENDORS: name prefixes
     and root modules of the vendor, plus the modules of the vendor bundle
     that import from those, except module names that the standards sources
     (IETF/IANA) also have; compute_ownership): newest release first;
     1b. unless a non-history copy from another source (aggregator, other)
     carries a LAST-UPDATED strictly newer than the newest official copy
     (plausible dates only, date_key): then the newest such copy wins
     ("newer-aggregator"); ties and undated copies keep the official copy;
  2. source rank (SOURCE_RANK: IETF/IANA standards and net-snmp first, then
     cisco-v2, LibreNMS, the vendor bundles' other modules, IANA, pysnmp,
     cisco-v1); for IANA-maintained modules all sources but cisco-v1 rank
     equal and the newest LAST-UPDATED wins (the pinned IANA set is from
     2016; on a tie the older sources keep precedence over the vendor
     bundles);
  3. newest LAST-UPDATED; 4. shallower path; 5. path name.
Every winner records why it won (modules.tsv / instances.tsv / duplicates.tsv
column `reason`): override | official (rule 1) | newer-aggregator (rule 1b) |
standards (rules 2-5, IETF/IANA source) | rank (rules 2-5, any other source).
"""

import argparse
import collections
import datetime
import hashlib
import json
import multiprocessing
import os
import re
import sys

# Sources with a fixed location: label, directory under corpus/src, type, vendor family.
# type: official-vendor (the vendor's own distribution; official for the modules
# it owns, see VENDORS) | standards (IETF/IANA) | aggregator (collections of
# copies) | other. The Juniper and Nokia bundles are discovered by
# discover_sources() (one source per release directory).
STATIC_SOURCES = [
    ("netsnmp", "netsnmp/mibs", "official-vendor", "net-snmp"),
    ("ietf", "ietf-iana/ietf", "standards", None),
    ("iana", "ietf-iana/iana", "standards", None),
    ("librenms", "librenms/mibs", "aggregator", None),
    ("cisco-v2", "cisco/v2", "official-vendor", "cisco"),
    ("cisco-v1", "cisco/v1", "other", None),  # SMIv1 conversions of cisco/v2: never official
    ("pysnmp", "pysnmp/asn1", "aggregator", None),
]

# Official vendor families: what each vendor's own distribution is authoritative
# for. A module of an official-vendor source is OWNED by the vendor when its
# name matches `prefixes`/`suffixes` or is one of `roots`, or it imports from
# such a module and no standards source (IETF/IANA) has a module of that name
# (vendors bundle copies of IETF modules, sometimes under the vendor's
# experimental arc: those never override the standards copies); see
# compute_ownership. The prefixes are derived from the bundles.
VENDORS = {
    "cisco": {"enterprises": [9], "prefixes": ("CISCO-",), "suffixes": (), "roots": ("CISCO-SMI",)},
    "juniper": {"enterprises": [2636], "prefixes": ("JUNIPER-", "JNX-"), "suffixes": ("-JUNIPER",),
                "roots": ("JUNIPER-SMI",)},
    "nokia": {"enterprises": [6527], "prefixes": ("TIMETRA-", "ALCATEL-", "ALU-", "NOKIA-"), "suffixes": (),
              "roots": ("TIMETRA-GLOBAL-MIB",)},
    "net-snmp": {"enterprises": [8072, 2021], "prefixes": ("NET-SNMP-", "UCD-"), "suffixes": (),
                 "roots": ("NET-SNMP-MIB", "UCD-SNMP-MIB")},
}

# Rule 2 (modules not owned by an official source): lower rank wins.
SOURCE_RANK = {"ietf": 0, "netsnmp": 1, "cisco-v2": 2, "librenms": 3, "juniper": 4, "juniper-evo": 4,
               "nokia": 4, "iana": 5, "pysnmp": 6, "cisco-v1": 7}
NEW_VENDOR_SOURCES = {"juniper", "juniper-evo", "nokia"}

# Explicit winner overrides, decided case by case. Each
# row: module name, source label, path under that source's root (as in
# instances.tsv), reason. An override beats every other rule; the other copies
# stay indexed (instances.tsv, duplicates.tsv). If the named instance is not in
# the corpus (source not fetched, path moved by a new pin) the override is
# reported and the normal rules apply.
OVERRIDES = [
    # module         source      path                    reason
    ("JUNIPER-SMI", "librenms", "juniper/JUNIPER-SMI",
     "the official Junos 26.2R1.7 JUNIPER-SMI uses TEXTUAL-CONVENTION and Opaque without importing them, so "
     "pysmi rejects it and every Juniper module importing it; LibreNMS's copy of the same revision "
     "(LAST-UPDATED 201912180000) adds the two IMPORTS (but lacks jnxSoftGreMibRoot = jnxMibs 92, which "
     "only JUNIPER-SOFT-GRE-MIB uses)."),
]
OVERRIDE_BY_NAME = {m: {"source": s, "path": p, "reason": r} for m, s, p, r in OVERRIDES}

# Rule 1b compares LAST-UPDATED values that are plausible dates only (date_key).
FIRST_PLAUSIBLE_YEAR = 1988  # SMIv1 (RFC 1065, 1988): no MIB module is older


class Source:
    def __init__(self, label, sub, type_, family=None, role="flat", release="", origin=""):
        self.label, self.sub, self.type, self.family = label, sub, type_, family
        self.role, self.release, self.origin = role, release, origin
        self.release_key = release_key(release)
        self.order = 0

    def as_dict(self):
        return {"dir": self.sub, "type": self.type, "family": self.family, "role": self.role,
                "release": self.release, "order": self.order}


def release_key(rel):
    return tuple(int(x) for x in re.findall(r"\d+", rel))


def discover_sources(corpus):
    """Static sources + one source per release directory of the vendor bundles:
    corpus/src/juniper-official/<release>[-EVO]/ (fetch.sh: pins/juniper.tsv) and
    corpus/src/nokia-sros/<release>/ (fetch.sh: pins/nokia.tsv, optional local
    source). The newest release of each line is the flat source ("juniper",
    "juniper-evo", "nokia"); older ones are history sources ("<label>-<release>"):
    indexed, never chosen for corpus/flat."""
    srcs = [Source(*x) for x in STATIC_SOURCES]
    src = os.path.join(corpus, "src")

    def releases(base):
        d = os.path.join(src, base)
        if not os.path.isdir(d):
            return []
        return [x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x)) and not x.endswith(".tmp")]

    jun = releases("juniper-official")
    for label, rels, family in (("juniper", [r for r in jun if not r.endswith("-EVO")], "juniper"),
                                ("juniper-evo", [r for r in jun if r.endswith("-EVO")], "juniper"),
                                ("nokia", releases("nokia-sros"), "nokia")):
        base = "nokia-sros" if label == "nokia" else "juniper-official"
        for i, rel in enumerate(sorted(rels, key=release_key, reverse=True)):
            srcs.append(Source(label if i == 0 else f"{label}-{rel}", f"{base}/{rel}", "official-vendor", family,
                               "flat" if i == 0 else "history", rel))
    for i, s in enumerate(srcs):
        s.order = i
    return srcs


SRC = {}  # label -> Source (set in main)

TOKEN_RE = re.compile(r'"[^"]*"|--[^\n\r]*|"')
HEADER_RE = re.compile(
    r"(?<![-\w])([A-Za-z][-\w]*)\s*(?:\{[^}]*\}\s*)?((?:PIB-)?DEFINITIONS)\s*"
    r"(?:(?:IMPLICIT|EXPLICIT|AUTOMATIC)\s+TAGS\s*)?::=\s*BEGIN(?![-\w])"
)
END_RE = re.compile(r"(?<![-\w])END(?![-\w])")
IMPORTS_RE = re.compile(r"(?<![-\w])IMPORTS(?![-\w])(.*?);", re.S)
FROM_RE = re.compile(r"(?<![-\w])FROM\s+([A-Za-z][-\w]*)")
LAST_UPDATED_RE = re.compile(r'(?<![-\w])LAST-UPDATED\s*"([^"]*)"')
MODULE_IDENTITY_RE = re.compile(r"(?<![-\w])[a-zA-Z][-\w]*\s+MODULE-IDENTITY(?![-\w])")
TRAP_TYPE_RE = re.compile(r"(?<![-\w])[a-zA-Z][-\w]*\s+TRAP-TYPE(?![-\w])")
OBJECT_TYPE_RE = re.compile(r"(?<![-\w])[a-zA-Z][-\w]*\s+OBJECT-TYPE(?![-\w])")
UNDERSCORE_ID_RE = re.compile(r"(?<![-\w])[A-Za-z][-\w]*_[-\w]*")
WS_RE = re.compile(r"\s+")
SMIV1_MODULES = {"RFC1155-SMI", "RFC-1212", "RFC-1215", "RFC1065-SMI", "RFC1213-MIB"}


def mask(text):
    """Return (no_comments, no_comments_no_strings): same length as text.

    Comments run from "--" to end of line (the common practical rule; see
    count_inline_comment_end for the ASN.1 "-- ... --" rule). String bodies
    are blanked in the second result (quotes kept, newlines kept)."""
    nc = []
    ns = []
    pos = 0
    for m in TOKEN_RE.finditer(text):
        s, e = m.span()
        if s > pos:
            chunk = text[pos:s]
            nc.append(chunk)
            ns.append(chunk)
        tok = m.group(0)
        if tok.startswith("--"):
            blank = " " * len(tok)
            nc.append(blank)
            ns.append(blank)
        elif tok == '"':  # unterminated string: rest of file
            rest = text[s:]
            nc.append(rest)
            ns.append('"' + re.sub(r"[^\r\n]", " ", rest[1:]))
            pos = len(text)
            break
        else:
            nc.append(tok)
            ns.append('"' + re.sub(r"[^\r\n]", " ", tok[1:-1]) + '"')
        pos = e
    if pos < len(text):
        chunk = text[pos:]
        nc.append(chunk)
        ns.append(chunk)
    return "".join(nc), "".join(ns)


def count_inline_comment_end(text):
    """Lines where a '--' comment is closed by a second '--' and followed by
    more text: ASN.1 (X.208) says the comment ends there, most MIB tools
    (and the 'to end of line' rule) disagree."""
    n = 0
    in_str = False
    for line in text.splitlines():
        if in_str:
            if line.count('"') % 2 == 1:
                in_str = False
            continue
        i = 0
        L = len(line)
        while i < L:
            c = line[i]
            if c == '"':
                j = line.find('"', i + 1)
                if j < 0:
                    in_str = True
                    break
                i = j + 1
                continue
            if c == "-" and line.startswith("--", i):
                rest = line[i + 2:]
                k = rest.find("--")
                if k >= 0:
                    after = rest[k + 2:].strip().strip("-").strip()
                    if after:
                        n += 1
                break
            i += 1
    return n


def norm_last_updated(v):
    v = v.strip()
    m = re.match(r"^(\d{10}|\d{12})[Zz]?$", v)
    if not m:
        return ""
    d = m.group(1)
    if len(d) == 10:
        d = "19" + d
    return d


def date_key(lu, this_year=datetime.date.today().year):
    """LAST-UPDATED as an int YYYYMMDDHHMM for rule 1b, or None when it is missing
    or implausible.

    Two-digit years are 19YY (RFC 2578). A year outside FIRST_PLAUSIBLE_YEAR up
    to this year, or an invalid month, day or time, counts as undated, so such a
    copy never beats an official one and an official one with such a value is
    never beaten (pysnmp's CISCO-DSL-PROVISION-MIB has year 9906)."""
    if not lu:
        return None
    y, mo, d, h, mi = int(lu[:4]), int(lu[4:6]), int(lu[6:8]), int(lu[8:10]), int(lu[10:12])
    if not (FIRST_PLAUSIBLE_YEAR <= y <= this_year and 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60):
        return None
    return int(lu)


def analyse_file(args):
    source, root, rel = args
    path = os.path.join(root, rel)
    with open(path, "rb") as f:
        data = f.read()
    rec = {
        "source": source,
        "path": rel,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    flags = []
    if data.startswith(b"\xef\xbb\xbf"):
        flags.append("bom")
    if b"\r\n" in data:
        flags.append("crlf")
    elif b"\r" in data:
        flags.append("cr")
    if any(b > 127 for b in data):
        try:
            data.decode("utf-8")
            flags.append("utf8")
        except UnicodeDecodeError:
            flags.append("non-utf8")
    if re.search(rb"[\x00-\x08\x0b\x0e-\x1f\x7f]", data):
        flags.append("ctrl")
    if b"\x0c" in data:
        flags.append("formfeed")
    if b"\t" in data:
        flags.append("tab")
    if data[:2] == b"\x1f\x8b" or data[:4] == b"PK\x03\x04":
        flags.append("binary")
    text = data.decode("latin-1")
    nc, ns = mask(text)
    headers = list(HEADER_RE.finditer(ns))
    mods = []
    for i, h in enumerate(headers):
        start = h.start()
        # line start of the header (keeps the module text self-contained)
        ls = ns.rfind("\n", 0, start) + 1
        if ns[ls:start].strip() == "":
            start = ls
        nxt = headers[i + 1].start() if i + 1 < len(headers) else len(ns)
        if i + 1 < len(headers):
            nl = ns.rfind("\n", 0, nxt) + 1
            if ns[nl:nxt].strip() == "":
                nxt = nl
        ends = [m for m in END_RE.finditer(ns, h.end(), nxt)]
        end = ends[-1].end() if ends else nxt
        span_ns = ns[h.end():end]
        span_nc = nc[h.end():end]
        imp = IMPORTS_RE.search(span_ns)
        imports = []
        if imp:
            imports = sorted(set(FROM_RE.findall(imp.group(1))))
        lu = LAST_UPDATED_RE.search(span_nc)
        last_updated = norm_last_updated(lu.group(1)) if lu else ""
        if MODULE_IDENTITY_RE.search(span_ns):
            smi = "v2"
        elif TRAP_TYPE_RE.search(span_ns) or (set(imports) & SMIV1_MODULES):
            smi = "v1"
        elif any(x.startswith("SNMPv2-") for x in imports):
            smi = "v2"
        else:
            smi = "?"
        if h.group(2) == "PIB-DEFINITIONS":
            smi = "pib"
        mtext = text[start if i else 0:end if i + 1 < len(headers) else len(text)]
        q = []
        if not ends:
            q.append("no-end")
        body = ns[h.end():ends[-1].start()] if ends else span_ns
        if not body.strip():
            q.append("empty-body")
        if UNDERSCORE_ID_RE.search(span_ns):
            q.append("underscore-id")
        if imp and re.search(r",\s*(FROM|$)", imp.group(1)):
            q.append("import-trailing-comma")
        norm = WS_RE.sub(" ", nc[h.start():end]).strip()
        struct = WS_RE.sub(" ", ns[h.start():end]).strip()
        mods.append({
            "module": h.group(1),
            "start": start if i else 0,
            "end": end if i + 1 < len(headers) else len(text),
            "imports": imports,
            "last_updated": last_updated,
            "smi": smi,
            "n_objects": len(OBJECT_TYPE_RE.findall(span_ns)),
            "sha": hashlib.sha256(mtext.encode("latin-1")).hexdigest(),
            "nhash": hashlib.sha256(norm.encode("latin-1")).hexdigest(),
            "shash": hashlib.sha256(struct.encode("latin-1")).hexdigest(),
            "quirks": q,
        })
    if headers:
        lead = ns[: headers[0].start()].strip()
        if lead:
            flags.append("leading-text")
        last_end = mods[-1]["end"]
        ends = list(END_RE.finditer(ns, headers[-1].end()))
        if ends and ns[ends[-1].end():].strip():
            flags.append("trailing-text")
        if len(headers) > 1:
            flags.append("multi-module")
        n_ice = count_inline_comment_end(text)
        if n_ice:
            flags.append("inline-comment-end")
    rec["flags"] = flags
    rec["modules"] = mods
    return rec


def list_files(corpus):
    jobs = []
    for so in SRC.values():
        root = os.path.join(corpus, "src", so.sub)
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            dns[:] = sorted(d for d in dns if d != ".git")
            for fn in sorted(fns):
                # net-snmp's mibs/ also holds Makefiles, scripts and rfcmibs.diff
                # (a patch full of MIB text): only its *.txt files are MIBs
                if so.label == "netsnmp" and not fn.endswith(".txt"):
                    continue
                rel = os.path.relpath(os.path.join(dp, fn), root)
                jobs.append((so.label, root, rel))
    return jobs


def vendor_of(source, rel):
    if source == "librenms":
        parts = rel.split("/")
        return parts[0] if len(parts) > 1 else "_std"
    if source.startswith("cisco"):
        return "cisco"
    if source == "netsnmp":
        return "net-snmp"
    if source.startswith("juniper-evo"):
        return "juniper-evo"
    if source.startswith("juniper"):
        return "juniper-std" if rel.startswith("StandardMibs/") else "juniper"
    if source.startswith("nokia"):
        return "nokia-sros"
    return source


def vendor_name_match(name, spec):
    return name in spec["roots"] or name.startswith(spec["prefixes"]) or (
        spec["suffixes"] and name.endswith(spec["suffixes"]))


def compute_ownership(instances):
    """Set inst["owned"] (an official-vendor copy of a module its vendor owns) and
    return {family: set of owned module names}.

    An instance of an official-vendor source is owned when its module name is in
    the vendor's namespace (VENDORS: prefixes, suffixes, roots), or when it
    imports directly from a module of that namespace (i.e. it hangs below the
    vendor's subtree: Juniper's MPLS-MIB, VPLS-*-DRAFT-01-MIB, ...) and no
    standards source (IETF/IANA) has a module of that name. A name the vendor
    also ships without such imports (Cisco's pre-standard IEEE8021-CFM-MIB next
    to the IEEE one) is contested and not owned."""
    standards = {i["module"] for i in instances if SRC[i["source"]].type == "standards"}
    owned = {}
    for i in instances:
        i["owned"] = False
    for fam, spec in VENDORS.items():
        insts = [i for i in instances if SRC[i["source"]].family == fam and SRC[i["source"]].type == "official-vendor"]
        by_name = collections.defaultdict(list)
        for i in insts:
            by_name[i["module"]].append(i)
            if vendor_name_match(i["module"], spec):
                i["owned"] = True
            elif i["module"] not in standards and any(vendor_name_match(x, spec) for x in i["imports"]):
                i["owned"] = True
        for n, lst in by_name.items():
            if not vendor_name_match(n, spec) and not all(i["owned"] for i in lst):
                for i in lst:
                    i["owned"] = False
        owned[fam] = {i["module"] for i in insts if i["owned"]}
    return owned


def winner_key(inst):
    """Sort key: the first instance of a name wins (unless it is a history instance)."""
    so = SRC[inst["source"]]
    lu = int(inst["last_updated"] or "0")
    head = (so.role == "history", "empty-body" in inst["quirks"])
    depth = inst["path"].count("/")
    if inst["owned"] or so.role == "history":
        # official copy of a vendor-owned module: newest release first
        return head + (0, tuple(-x for x in so.release_key), -lu, so.order, depth, inst["path"])
    rank = SOURCE_RANK[so.label]
    tie = 0
    if inst["module"].upper().startswith("IANA") and so.label != "cisco-v1":
        rank, tie = 0, int(so.label in NEW_VENDOR_SOURCES)
    return head + (1, rank, -lu, tie, depth, inst["path"])


def order_instances(name, insts, override_status=None):
    """Sort the instances of one module name, winner first, and return why the
    first one wins: override | official | newer-aggregator | standards | rank
    (module docstring), or "" when no instance may win (history sources only).

    winner_key orders by rules 0-5; on top of that an OVERRIDES entry wins
    outright, and an official copy (rule 1) gives way to a non-history copy of
    another source whose LAST-UPDATED (date_key) is strictly newer than that of
    every official copy, history releases included (rule 1b; the newest such
    copy, on a tie the one first in rule-2 order). override_status (dict)
    receives "applied" or why an override did not apply."""
    insts.sort(key=winner_key)
    if SRC[insts[0]["source"]].role == "history":
        return ""

    def promote(inst):
        insts.remove(inst)
        insts.insert(0, inst)

    ov = OVERRIDE_BY_NAME.get(name)
    if ov:
        hit = [i for i in insts if i["source"] == ov["source"] and i["path"] == ov["path"]
               and SRC[i["source"]].role != "history"]
        if override_status is not None:
            override_status[name] = "applied" if hit else "instance not in the corpus: normal rules apply"
        if hit:
            promote(hit[0])
            return "override"
    w = insts[0]
    if w["owned"]:
        official = [d for d in (date_key(i["last_updated"]) for i in insts if i["owned"]) if d is not None]
        if official:
            newest = max(official)
            newer = [i for i in insts if not i["owned"] and SRC[i["source"]].role != "history"
                     and "empty-body" not in i["quirks"] and (date_key(i["last_updated"]) or 0) > newest]
            if newer:
                promote(max(newer, key=lambda i: (date_key(i["last_updated"]), -insts.index(i))))
                return "newer-aggregator"
        return "official"
    return "standards" if SRC[w["source"]].type == "standards" else "rank"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=min(16, os.cpu_count() or 1))
    ap.add_argument("--no-swap", action="store_true",
                    help="leave the result staged (*.new) for a later swap.py (e.g. after oracle runs)")
    a = ap.parse_args()
    corpus = os.path.abspath(a.corpus)
    out = os.path.abspath(a.out)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import swap as swapmod
    swapmod.clean_prev(out, stale_new=True, corpus=corpus)
    for so in discover_sources(corpus):
        SRC[so.label] = so
    jobs = list_files(corpus)
    with multiprocessing.Pool(a.jobs) as pool:
        files = pool.map(analyse_file, jobs, chunksize=16)

    # everything is written to staging paths (<name>.new) and swapped in at the end
    idx = os.path.join(corpus, "index.new")
    os.makedirs(idx)

    # all instances
    instances = []
    for f in files:
        f["vendor"] = vendor_of(f["source"], f["path"])
        for m in f["modules"]:
            inst = dict(m)
            inst.update(source=f["source"], path=f["path"], vendor=f["vendor"],
                        file_sha256=f["sha256"], file_size=f["size"],
                        n_in_file=len(f["modules"]), file_flags=f["flags"])
            instances.append(inst)
    owned = compute_ownership(instances)
    by_name = collections.defaultdict(list)
    for inst in instances:
        by_name[inst["module"]].append(inst)
    override_status = {}
    for name, insts in by_name.items():
        reason = order_instances(name, insts, override_status)
        for i, inst in enumerate(insts):
            inst["winner"] = i == 0 and SRC[inst["source"]].role != "history"
            inst["reason"] = reason if inst["winner"] else ""
    for name in OVERRIDE_BY_NAME:
        if name not in by_name:
            override_status[name] = "module not in the corpus"
    for name, s in sorted(override_status.items()):
        if s != "applied":
            print(f"index.py: NOTICE override {name}: {s}", file=sys.stderr)
    # module names that only occur in history sources have no winner (not in corpus/flat)
    winners = {n: v[0] for n, v in by_name.items() if v[0]["winner"]}

    with open(os.path.join(idx, "files.tsv"), "w") as o:
        o.write("source\tvendor\tpath\tsize\tsha256\tflags\tmodules\n")
        for f in files:
            o.write("\t".join([f["source"], f["vendor"], f["path"], str(f["size"]), f["sha256"],
                               ",".join(f["flags"]), ",".join(m["module"] for m in f["modules"])]) + "\n")

    for inst in instances:
        inst["source_type"] = SRC[inst["source"]].type
    cols = ["module", "source", "vendor", "path", "start", "end", "file_size", "file_sha256", "sha",
            "nhash", "shash", "last_updated", "smi", "n_objects", "n_in_file", "winner", "imports",
            "quirks", "file_flags", "source_type", "owned", "reason"]

    def fmt(v):
        if isinstance(v, list):
            return ",".join(v)
        if isinstance(v, bool):
            return "1" if v else "0"
        return str(v)

    with open(os.path.join(idx, "instances.tsv"), "w") as o:
        o.write("\t".join(cols) + "\n")
        for inst in instances:
            o.write("\t".join(fmt(inst[c]) for c in cols) + "\n")

    # flat dir: winners. Links are relative (../src/..., ../split/<M>) so they are
    # valid once flat.new and split.new have been renamed to flat and split.
    flat = os.path.join(corpus, "flat.new")
    split = os.path.join(corpus, "split.new")
    for d in (flat, split):
        os.makedirs(d)
    all_names = set(winners)
    mcols = ["module", "source", "vendor", "path", "size", "sha256", "smi", "last_updated", "n_objects",
             "copies", "distinct", "imports", "missing_imports", "quirks", "flags", "source_type", "owned",
             "reason"]
    missing_counter = collections.Counter()
    with open(os.path.join(idx, "modules.tsv"), "w") as o:
        o.write("\t".join(mcols) + "\n")
        for name in sorted(winners):
            insts = by_name[name]
            w = winners[name]
            srcpath = os.path.join(corpus, "src", SRC[w["source"]].sub, w["path"])
            if w["n_in_file"] == 1:
                os.symlink(os.path.relpath(srcpath, os.path.join(corpus, "flat")), os.path.join(flat, name))
                size, sha = w["file_size"], w["file_sha256"]
            else:
                with open(srcpath, "rb") as f:
                    data = f.read()[w["start"]:w["end"]]
                with open(os.path.join(split, name), "wb") as f:
                    f.write(data)
                os.symlink(os.path.join("..", "split", name), os.path.join(flat, name))
                size, sha = len(data), hashlib.sha256(data).hexdigest()
            missing = [x for x in w["imports"] if x not in all_names]
            missing_counter.update(missing)
            flat_insts = [i for i in insts if SRC[i["source"]].role != "history"]
            row = dict(w, size=size, sha256=sha, copies=len(flat_insts),
                       distinct=len({i["sha"] for i in flat_insts}), missing_imports=missing,
                       flags=w["file_flags"])
            o.write("\t".join(fmt(row[c]) for c in mcols) + "\n")

    def diff_kind(inst, ref):
        if inst["sha"] == ref["sha"]:
            return "same"
        if inst["nhash"] == ref["nhash"]:
            return "ws"
        if inst["shash"] == ref["shash"]:
            return "text"
        return "syntax"

    # committed: duplicates.tsv (incl. history sources)
    with open(os.path.join(out, "duplicates.tsv.new"), "w") as o:
        o.write("# All instances of module names found more than once in the corpus (see README.md).\n"
                "# diff: vs the winner: same = identical text, ws = differs only in comments/whitespace,\n"
                "#       text = differs only inside strings (DESCRIPTION etc.), syntax = differs outside strings.\n"
                "# Names that only occur in history sources (older vendor releases) have no winner: diff is\n"
                "# relative to the newest release. type = source type; official = 1: the copy of the vendor's\n"
                "# official distribution of a module it owns (index.py: VENDORS).\n"
                "# reason (winner row only): why it won: override (index.py: OVERRIDES), official (official copy\n"
                "# of a vendor-owned module), newer-aggregator (a non-official copy with a strictly newer\n"
                "# LAST-UPDATED than every official copy), standards / rank (source rank, LAST-UPDATED, path).\n")
        o.write("module\tcopies\tdistinct\twinner\tdiff\tsource\tvendor\tpath\tsize\tsha256\tlast_updated"
                "\ttype\tofficial\treason\n")
        for name in sorted(by_name):
            insts = by_name[name]
            if len(insts) < 2:
                continue
            ref = insts[0]
            nd = len({i["sha"] for i in insts})
            for inst in insts:
                o.write("\t".join([name, str(len(insts)), str(nd), "1" if inst["winner"] else "0",
                                   diff_kind(inst, ref), inst["source"], inst["vendor"], inst["path"],
                                   str(inst["end"] - inst["start"]), inst["sha"][:16], inst["last_updated"],
                                   inst["source_type"], "1" if inst["owned"] else "0", inst["reason"]]) + "\n")

    # committed: vendors.tsv
    vs = collections.OrderedDict()
    for f in files:
        k = (f["source"], f["vendor"])
        v = vs.setdefault(k, collections.Counter())
        v["files"] += 1
        v["bytes"] += f["size"]
        if f["modules"]:
            v["mib_files"] += 1
            v["modules"] += len(f["modules"])
            for m in f["modules"]:
                w = winners.get(m["module"])
                if w is not None and w["path"] == f["path"] and w["source"] == f["source"] and \
                        w["start"] == m["start"]:
                    v["winners"] += 1
    with open(os.path.join(out, "vendors.tsv.new"), "w") as o:
        o.write("# Corpus breakdown per source and vendor directory (librenms: mibs/<vendor>/, _std = mibs/ top level;\n"
                "# juniper: JuniperMibs/ = juniper, StandardMibs/ = juniper-std).\n"
                "# files: all files, mib_files: files with >= 1 module header, modules: module instances,\n"
                "# winners: instances chosen for corpus/flat (the de-duplicated set the oracles run on),\n"
                "# type: source type (official-vendor, standards, aggregator, other), role: flat or history\n"
                "# (older vendor releases: indexed, never chosen).\n")
        o.write("source\tvendor\tfiles\tmib_files\tmodules\twinners\tbytes\ttype\trole\n")
        for (s, v), c in sorted(vs.items()):
            o.write(f"{s}\t{v}\t{c['files']}\t{c['mib_files']}\t{c['modules']}\t{c['winners']}\t{c['bytes']}"
                    f"\t{SRC[s].type}\t{SRC[s].role}\n")

    # stats.json for report.py
    flat_files = [f for f in files if SRC[f["source"]].role != "history"]
    flat_insts = [i for i in instances if SRC[i["source"]].role != "history"]
    flat_names = collections.defaultdict(list)
    for i in flat_insts:
        flat_names[i["module"]].append(i)
    st = {
        "files": len(flat_files),
        "bytes": sum(f["size"] for f in flat_files),
        "mib_files": sum(1 for f in flat_files if f["modules"]),
        "non_mib_files": [f["source"] + ":" + f["path"] for f in flat_files if not f["modules"]],
        "instances": len(flat_insts),
        "unique_modules": len(winners),
        "dup_names": sum(1 for v in flat_names.values() if len(v) > 1),
        "dup_names_conflicting": sum(1 for v in flat_names.values() if len({i["sha"] for i in v}) > 1),
        "dup_names_syntax_conflict": sum(1 for v in flat_names.values() if len({i["shash"] for i in v}) > 1),
        "file_flags": collections.Counter(fl for f in flat_files for fl in f["flags"]),
        "module_quirks": collections.Counter(q for i in instances if i["winner"] for q in i["quirks"]),
        "smi": collections.Counter(i["smi"] for i in instances if i["winner"]),
        "missing_imports": missing_counter.most_common(),
        "history": {"files": len(files) - len(flat_files), "instances": len(instances) - len(flat_insts),
                    "names_only_in_history": sorted(n for n in by_name if n not in winners)},
        "sources": {so.label: so.as_dict() for so in SRC.values()},
        "vendors": {fam: dict(VENDORS[fam], owned=sorted(owned[fam])) for fam in VENDORS},
        "reasons": collections.Counter(w["reason"] for w in winners.values()),
        "overrides": [{"module": m, "source": s, "path": p, "reason": r, "status": override_status.get(m, "")}
                      for m, s, p, r in OVERRIDES],
        "newer_aggregator": [],
        "per_source": {},
    }
    for name, w in sorted(winners.items()):
        if w["reason"] != "newer-aggregator":
            continue
        off = [i for i in by_name[name] if i["owned"] and SRC[i["source"]].role != "history"] or \
            [i for i in by_name[name] if i["owned"]]
        st["newer_aggregator"].append({
            "module": name, "source": w["source"], "path": w["path"], "last_updated": w["last_updated"],
            "official_source": off[0]["source"], "official_path": off[0]["path"],
            "official_last_updated": max((i["last_updated"] for i in by_name[name] if i["owned"]),
                                         key=lambda x: date_key(x) or 0)})
    for so in SRC.values():
        s = so.label
        fs = [f for f in files if f["source"] == s]
        if not fs and so.label not in dict((x[0], 1) for x in STATIC_SOURCES):
            continue
        st["per_source"][s] = {
            "files": len(fs), "bytes": sum(f["size"] for f in fs),
            "mib_files": sum(1 for f in fs if f["modules"]),
            "instances": sum(len(f["modules"]) for f in fs),
            "winners": sum(1 for i in instances if i["source"] == s and i["winner"]),
            "owned": sum(1 for i in instances if i["source"] == s and i["owned"]),
            "type": so.type, "role": so.role, "release": so.release,
        }
    with open(os.path.join(idx, "stats.json"), "w") as o:
        json.dump(st, o, indent=1, sort_keys=True)
    print(f"files {st['files']} ({st['bytes'] / 1e6:.0f} MB), MIB files {st['mib_files']}, "
          f"module instances {st['instances']}, unique module names {st['unique_modules']}, "
          f"names with copies {st['dup_names']} (differing {st['dup_names_conflicting']}); "
          f"history sources: {st['history']['files']} files, {st['history']['instances']} instances; "
          "owned by official sources: " + ", ".join(f"{k} {len(v)}" for k, v in owned.items()) +
          "; winners by reason: " + ", ".join(f"{k} {v}" for k, v in st["reasons"].most_common()),
          file=sys.stderr)
    if a.no_swap:
        print("staged: corpus/{flat,split,index}.new, duplicates.tsv.new, vendors.tsv.new (swap.py publishes them)",
              file=sys.stderr)
    else:
        swapmod.swap(out, corpus=corpus)


if __name__ == "__main__":
    main()
