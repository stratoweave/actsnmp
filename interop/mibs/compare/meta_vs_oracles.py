#!/usr/bin/env python3
"""Compare actsnmp mibmeta JSON with the pysmi JSON and net-snmp JSONL oracle outputs.

    python3 interop/mibs/compare/meta_vs_oracles.py --ours DIR
        [--expected interop/mibs/golden/expected] [--expected-extra DIR ...]
        [--modules A,B,...] [--out FILE.md] [--show N] [--list FILE.tsv]
    python3 interop/mibs/compare/meta_vs_oracles.py --stage-vendor DIR [--mibs-dir interop/mibs]

Typical golden run (IETF tier, then the vendor tier from the local corpus):

    MIBMETA_OUT=/tmp/mm acton test --module mib.test_golden --name golden_resolve
    python3 interop/mibs/compare/meta_vs_oracles.py --ours /tmp/mm
    python3 interop/mibs/compare/meta_vs_oracles.py --stage-vendor interop/mibs/cache/golden-vendor
    MIBMETA_OUT=/tmp/mv acton test --tag mibcorpus --module mib.test_golden --name golden_vendor
    python3 interop/mibs/compare/meta_vs_oracles.py --ours /tmp/mv \
        --expected interop/mibs/golden/expected-local --expected-extra interop/mibs/golden/expected

Inputs:

- ``--ours DIR``: ``<MOD>.mibmeta.json`` files (format ``actsnmp-mibmeta/1``), written by
  ``MIBMETA_OUT=DIR acton test --module mib.test_golden`` (golden set) or any other
  producer of ``mib.meta.to_json``.
- ``--expected DIR`` (repeatable through ``--expected-extra``): oracle outputs laid out as
  ``pysmi/<MOD>.json`` and ``netsnmp/<MOD>.jsonl`` (``interop/mibs/golden/expected`` and
  ``.../expected-local`` for the vendor golden modules).

For every module that has our JSON and at least one oracle output, every node (and TC)
the oracle knows is matched by name and compared field by field:

pysmi: ``oid``, ``kind`` (class/nodetype), ``access`` (maxaccess), ``status``, ``base``
(the syntax resolved to its SMI base type through pysmi's own TC definitions), ``tc``
(the named type), ``ranges``, ``sizes``, ``enums``, ``bits`` (the object's own
constraints, else the TC chain's), ``index`` (indices objects), ``implied``, ``augments``,
``units``; for TCs ``tc.base``, ``tc.status``, ``tc.hint`` (displayhint), ``tc.ranges``,
``tc.sizes``, ``tc.enums``.

net-snmp: ``oid``, ``type`` (kind: the leaf's base type or the macro), ``tc``, ``access``,
``status``, ``hint``, ``ranges`` (net-snmp merges ranges and sizes), ``enums`` (also BITS),
``index`` (indexes), ``augments``, ``units``.

Normalisation before comparing (the RFC 3584 mapping we apply on purpose): SMIv1 status
mandatory/optional -> current, write-only -> read-write, Integer32 -> INTEGER, Counter ->
Counter32, Gauge -> Gauge32, NetworkAddress -> IpAddress, Bits -> BITS. Our ``hint`` of an
object whose type chain reaches an SMIv1 informal ``DisplayString``/``PhysAddress`` type
assignment (not SNMPv2-TC's) is the SNMPv2-TC hint the YANG emitter gives it; it is compared
as "" with net-snmp, which has no hint there.

Output: a Markdown report with the agreement rate per oracle and field, missing names
(oracle knows the name, we do not) and with ``--show N`` the first N disagreements per
field. ``--list`` writes every disagreement as TSV. Pure stdlib.
"""

import argparse
import collections
import glob
import json
import os
import sys

BASES = {
    "INTEGER": "INTEGER", "Integer32": "INTEGER", "Unsigned32": "Unsigned32", "Gauge32": "Gauge32",
    "Gauge": "Gauge32", "Counter32": "Counter32", "Counter": "Counter32", "Counter64": "Counter64",
    "TimeTicks": "TimeTicks", "IpAddress": "IpAddress", "NetworkAddress": "IpAddress", "Opaque": "Opaque",
    "OCTET STRING": "OCTET STRING", "OBJECT IDENTIFIER": "OBJECT IDENTIFIER", "Bits": "BITS", "BITS": "BITS",
    "ObjectName": "OBJECT IDENTIFIER", "NotificationName": "OBJECT IDENTIFIER",
}

PYSMI_CLASS = {
    "moduleidentity": "module-identity", "notificationtype": "notification", "objectgroup": "object-group",
    "notificationgroup": "notification-group", "modulecompliance": "compliance",
    "agentcapabilities": "capabilities",
}

NETSNMP_MACRO = {
    "OBJECT-IDENTITY": ("object-identity",), "OBJECT-GROUP": ("object-group",),
    "MODULE-COMPLIANCE": ("compliance",), "MODULE-IDENTITY": ("module-identity",),
    "NOTIFICATION-TYPE": ("notification",), "NOTIFICATION-GROUP": ("notification-group",),
    "AGENT-CAPABILITIES": ("capabilities",), "TRAPTYPE": ("notification",),
    "other": ("node", "table", "row", "object-identity", "module-identity", "notification"),
}


def norm_status(s):
    if s in ("mandatory", "optional"):
        return "current"
    return s


def norm_access(a):
    if a == "write-only":
        return "read-write"
    return a


def local(q):
    """`MOD::name` -> name."""
    return q.split("::")[-1] if q else q


class Stats:
    def __init__(self):
        self.cmp = collections.Counter()
        self.ok = collections.Counter()
        self.bad = collections.defaultdict(list)
        self.missing = collections.defaultdict(list)
        self.modules = collections.Counter()

    def check(self, oracle, field, mod, name, theirs, ours):
        key = (oracle, field)
        self.cmp[key] += 1
        if theirs == ours:
            self.ok[key] += 1
        else:
            self.bad[key].append((mod, name, theirs, ours))


def load_ours(d, mods):
    out = {}
    for p in sorted(glob.glob(os.path.join(d, "*.mibmeta.json"))):
        with open(p, encoding="utf-8") as f:
            m = json.load(f)
        if mods and m["module"] not in mods:
            continue
        out[m["module"]] = m
    return out


class PysmiTypes:
    """pysmi's TC and type definitions per module, looked up the way pysmi resolves a
    syntax: the module itself, then the module it imports the name from, then any module."""

    def __init__(self, dirs, flat_dirs=()):
        self.by_mod = {}
        self.imports = {}
        self.any = {}
        paths = []
        for d in dirs:
            paths.extend(sorted(glob.glob(os.path.join(d, "pysmi", "*.json"))))
        for d in flat_dirs:
            paths.extend(sorted(glob.glob(os.path.join(d, "*.json"))))
        if True:
            for p in paths:
                try:
                    with open(p, encoding="utf-8") as f:
                        doc = json.load(f)
                except (OSError, ValueError):
                    continue
                mod = os.path.basename(p)[:-5]
                if mod in self.by_mod:
                    continue
                tbl = {}
                for v in doc.values():
                    if isinstance(v, dict) and v.get("class") in ("textualconvention", "type") and "name" in v:
                        tbl[v["name"]] = v
                        self.any.setdefault(v["name"], (mod, v))
                self.by_mod[mod] = tbl
                imp = {}
                for m2, syms in (doc.get("imports") or {}).items():
                    if isinstance(syms, list):
                        for x in syms:
                            imp.setdefault(x, m2)
                self.imports[mod] = imp

    def find(self, mod, name):
        t = self.by_mod.get(mod, {}).get(name)
        if t is not None:
            return mod, t
        m2 = self.imports.get(mod, {}).get(name)
        if m2 is not None and name in self.by_mod.get(m2, {}):
            return m2, self.by_mod[m2][name]
        return self.any.get(name, (None, None))


def pysmi_syntax_chain(syn, tcs, mod):
    """[syntax dicts] from the object's syntax through the TC chain (base last)."""
    out = [syn]
    seen = set()
    cur = syn
    while True:
        t = cur.get("type")
        if t in BASES or t is None or (mod, t) in seen:
            break
        seen.add((mod, t))
        mod2, tc = tcs.find(mod, t)
        if tc is None:
            break
        nxt = tc.get("type")
        if not isinstance(nxt, dict):
            break
        out.append(nxt)
        cur = nxt
        mod = mod2
    return out


def pysmi_base(chain):
    t = chain[-1].get("type")
    return BASES.get(t, t)


def first_constraint(chain, kind):
    for s in chain:
        c = (s.get("constraints") or {}).get(kind)
        if c:
            return c
    return None


def ranges_of(c):
    if c is None:
        return []
    return [[r.get("min"), r.get("max")] for r in c]


def enums_pysmi(chain):
    for s in chain:
        e = (s.get("constraints") or {}).get("enumeration")
        if e:
            return sorted([[k, v] for k, v in e.items()], key=lambda x: (x[1], x[0]))
    return []


def bits_pysmi(chain):
    for s in chain:
        b = s.get("bits")
        if b:
            return sorted([[k, v] for k, v in b.items()], key=lambda x: (x[1], x[0]))
    return []


def sorted_named(xs):
    return sorted([[a, b] for a, b in xs], key=lambda x: (x[1], x[0]))


def compare_pysmi(st, mod, ours, doc, tcs):
    nodes = {}
    for n in ours["nodes"]:
        nodes.setdefault(n["name"], n)
    oids = all_oids(ours)
    types = {t["name"]: t for t in ours["types"]}
    for k, v in doc.items():
        if not isinstance(v, dict) or "name" not in v:
            continue
        cls = v.get("class")
        name = v["name"]
        if cls == "textualconvention":
            t = types.get(name)
            if t is None:
                st.missing["pysmi"].append((mod, name, "tc"))
                continue
            sx = t.get("syntax") or {}
            chain = pysmi_syntax_chain(v.get("type") or {}, tcs, mod)
            st.check("pysmi", "tc.base", mod, name, pysmi_base(chain), sx.get("wire"))
            st.check("pysmi", "tc.status", mod, name, norm_status(v.get("status")), t.get("status"))
            if "displayhint" in v:
                # ours is the effective hint (inherited through the chain); pysmi has the TC's own
                st.check("pysmi", "tc.hint", mod, name, v["displayhint"], sx.get("hint", ""))
            st.check("pysmi", "tc.ranges", mod, name, ranges_of(first_constraint(chain, "range")), sx.get("ranges", []))
            st.check("pysmi", "tc.sizes", mod, name, ranges_of(first_constraint(chain, "size")), sx.get("sizes", []))
            st.check("pysmi", "tc.enums", mod, name, enums_pysmi(chain), sorted_named(sx.get("enums", [])))
            continue
        if "oid" not in v:
            continue
        n = nodes.get(name)
        if n is None:
            st.missing["pysmi"].append((mod, name, v["oid"]))
            continue
        check_oid(st, "pysmi", mod, name, v["oid"], n, oids)
        if cls == "objecttype":
            kind = v.get("nodetype")
        elif cls == "objectidentity":
            kind = "object-identity" if n["kind"] == "object-identity" else "node"
        else:
            kind = PYSMI_CLASS.get(cls, cls)
        st.check("pysmi", "kind", mod, name, kind, n["kind"])
        if "status" in v:
            st.check("pysmi", "status", mod, name, norm_status(v["status"]), n.get("status"))
        if "maxaccess" in v:
            st.check("pysmi", "access", mod, name, norm_access(v["maxaccess"]), n.get("access", ""))
        if "units" in v:
            st.check("pysmi", "units", mod, name, v["units"], n.get("units", ""))
        syn = v.get("syntax")
        if syn and v.get("nodetype") in ("scalar", "column"):
            sx = n.get("syntax") or {}
            chain = pysmi_syntax_chain(syn, tcs, mod)
            st.check("pysmi", "base", mod, name, pysmi_base(chain), sx.get("wire"))
            t = syn.get("type")
            st.check("pysmi", "tc", mod, name, "" if t in BASES else t, local(sx.get("tc", "")))
            st.check("pysmi", "ranges", mod, name, ranges_of(first_constraint(chain, "range")), sx.get("ranges", []))
            st.check("pysmi", "sizes", mod, name, ranges_of(first_constraint(chain, "size")), sx.get("sizes", []))
            if pysmi_base(chain) == "BITS":
                st.check("pysmi", "bits", mod, name, bits_pysmi(chain), sorted_named(sx.get("bits", [])))
            else:
                st.check("pysmi", "enums", mod, name, enums_pysmi(chain), sorted_named(sx.get("enums", [])))
        if v.get("nodetype") == "row":
            if "augmention" in v:
                st.check("pysmi", "augments", mod, name, v["augmention"].get("object"), local(n.get("augments", "")))
            elif "indices" in v:
                ix = [i.get("object") for i in v["indices"]]
                if any(x.startswith("pysmiFakeCol") for x in ix):
                    continue
                ours_ix = [local(p["object"]) for p in n.get("index", [])]
                st.check("pysmi", "index", mod, name, ix, ours_ix)
                imp = bool(v["indices"] and v["indices"][-1].get("implied"))
                st.check("pysmi", "implied", mod, name, imp, n.get("implied", False))


def all_oids(ours):
    """name -> every OID we give it (a name defined twice keeps both nodes, the second only in
    the OID tree: the oracles list both)."""
    out = collections.defaultdict(set)
    for n in ours["nodes"]:
        out[n["name"]].add(n["oid"])
    return out


def check_oid(st, oracle, mod, name, theirs, n, oids):
    st.check(oracle, "oid", mod, name, theirs, theirs if theirs in oids.get(name, ()) else n["oid"])


# "MOD::name" -> our TypeMeta, over all loaded modules (for t9_hint)
ALL_TYPES = {}
T9_HINTS = {"DisplayString": "255a", "PhysAddress": "1x:"}


def t9_hint(sx):
    """The SNMPv2-TC hint our syntax carries because its chain reaches an SMIv1 informal
    DisplayString or PhysAddress, or ""."""
    q = sx.get("tc", "")
    for _ in range(16):
        if not q:
            return ""
        mod, _, name = q.partition("::")
        t = ALL_TYPES.get(q)
        if t is None:
            return ""
        if name in T9_HINTS and mod != "SNMPv2-TC" and (t.get("syntax") or {}).get("wire") == "OCTET STRING":
            return T9_HINTS[name]
        q = t.get("parent", "")
    return ""


def compare_netsnmp(st, mod, ours, lines):
    nodes = {}
    for n in ours["nodes"]:
        nodes.setdefault(n["name"], n)
    oids = all_oids(ours)
    for d in lines:
        if d.get("module") != mod or "name" not in d:
            continue
        name = d["name"]
        n = nodes.get(name)
        if n is None:
            st.missing["netsnmp"].append((mod, name, d.get("oid")))
            continue
        check_oid(st, "netsnmp", mod, name, d["oid"], n, oids)
        kind = d.get("kind")
        sx = n.get("syntax")
        if kind in NETSNMP_MACRO:
            st.check("netsnmp", "type", mod, name, True, n["kind"] in NETSNMP_MACRO[kind])
        else:
            st.check("netsnmp", "type", mod, name, BASES.get(kind, kind), (sx or {}).get("wire"))
        if "access" in d:
            st.check("netsnmp", "access", mod, name, norm_access(d["access"]), n.get("access", ""))
        if "status" in d:
            st.check("netsnmp", "status", mod, name, norm_status(d["status"]), n.get("status"))
        if "units" in d:
            st.check("netsnmp", "units", mod, name, d["units"], n.get("units", ""))
        if sx is not None:
            st.check("netsnmp", "tc", mod, name, d.get("tc", ""), local(sx.get("tc", "")))
            h = sx.get("hint", "")
            if d.get("hint", "") == "" and h != "" and h == t9_hint(sx):
                h = ""
            st.check("netsnmp", "hint", mod, name, d.get("hint", ""), h)
            ours_r = sx.get("ranges") or sx.get("sizes") or []
            st.check("netsnmp", "ranges", mod, name, d.get("ranges", []), ours_r)
            ours_e = sx.get("enums") or sx.get("bits") or []
            st.check("netsnmp", "enums", mod, name, sorted([[b, a] for a, b in d.get("enums", [])], key=lambda x: (x[1], x[0])),
                     sorted_named(ours_e))
        if "augments" in d:
            st.check("netsnmp", "augments", mod, name, d["augments"], local(n.get("augments", "")))
        elif "indexes" in d:
            ix = [x[0] for x in d["indexes"]]
            ours_ix = [local(p["object"]) or p["key"] for p in n.get("index", [])]
            st.check("netsnmp", "index", mod, name, ix, ours_ix)


def stage_vendor(mibs, dest):
    """Copy the texts of the IEEE/vendor golden modules (golden.tsv tiers other than ietf and
    netsnmp, their text lives in corpus/src) into `dest`, one file per module name, for the
    tagged Acton test `mib.test_golden.golden_vendor`."""
    with open(os.path.join(mibs, "corpus", "index", "stats.json"), encoding="utf-8") as f:
        sources = json.load(f)["sources"]
    os.makedirs(dest, exist_ok=True)
    n = 0
    with open(os.path.join(mibs, "golden", "golden.tsv"), encoding="utf-8") as f:
        rows = [l.rstrip("\n").split("\t") for l in f if not l.startswith("#") and l.strip()]
    hdr = rows[0]
    for r in rows[1:]:
        d = dict(zip(hdr, r))
        if d.get("tier") in ("ietf", "netsnmp"):
            continue
        src = sources.get(d["source"], {}).get("dir")
        if src is None:
            print("unknown source", d["source"], "for", d["module"], file=sys.stderr)
            continue
        path = os.path.join(mibs, "corpus", "src", src, d["path"])
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            print("cannot read", path, e, file=sys.stderr)
            continue
        with open(os.path.join(dest, d["module"]), "wb") as f:
            f.write(data)
        n += 1
    print("staged %d vendor golden modules in %s" % (n, dest))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stage-vendor", metavar="DIR", help="copy the vendor golden texts to DIR and exit")
    ap.add_argument("--mibs-dir", default="interop/mibs")
    ap.add_argument("--ours")
    ap.add_argument("--expected", default="interop/mibs/golden/expected")
    ap.add_argument("--expected-extra", action="append", default=[])
    ap.add_argument("--pysmi-dir", help="flat directory of pysmi <MOD>.json (e.g. cache/pysmi-relaxed/json)")
    ap.add_argument("--netsnmp-dir", help="flat directory of net-snmp <MOD>.jsonl (e.g. cache/netsnmp/out)")
    ap.add_argument("--modules", default="")
    ap.add_argument("--out")
    ap.add_argument("--show", type=int, default=5)
    ap.add_argument("--list")
    a = ap.parse_args()
    if a.stage_vendor:
        stage_vendor(a.mibs_dir, a.stage_vendor)
        return
    if not a.ours:
        ap.error("--ours is required")
    mods = set(x for x in a.modules.split(",") if x)
    ours = load_ours(a.ours, mods)
    for mod, m in ours.items():
        for t in m.get("types", []):
            ALL_TYPES[mod + "::" + t["name"]] = t
    dirs = [a.expected] + a.expected_extra
    tcs = PysmiTypes(dirs, [a.pysmi_dir] if a.pysmi_dir else [])
    st = Stats()
    compared_mods = []
    for mod, m in sorted(ours.items()):
        seen = False
        cands = [(os.path.join(d, "pysmi", mod + ".json"), os.path.join(d, "netsnmp", mod + ".jsonl")) for d in dirs]
        if a.pysmi_dir or a.netsnmp_dir:
            cands.append((os.path.join(a.pysmi_dir or "/nonexistent", mod + ".json"),
                          os.path.join(a.netsnmp_dir or "/nonexistent", mod + ".jsonl")))
        for pj, nj in cands:
            if os.path.exists(pj) and not st.modules[("pysmi", mod)]:
                with open(pj, encoding="utf-8") as f:
                    compare_pysmi(st, mod, m, json.load(f), tcs)
                st.modules[("pysmi", mod)] = 1
                seen = True
            if os.path.exists(nj) and not st.modules[("netsnmp", mod)]:
                with open(nj, encoding="utf-8") as f:
                    lines = [json.loads(l) for l in f if l.strip()]
                compare_netsnmp(st, mod, m, lines)
                st.modules[("netsnmp", mod)] = 1
                seen = True
        if seen:
            compared_mods.append(mod)
    out = []
    out.append("# actsnmp mibmeta vs oracles\n")
    out.append("Modules with our JSON: %d; compared with an oracle: %d (pysmi %d, net-snmp %d).\n" % (
        len(ours), len(compared_mods), sum(1 for k in st.modules if k[0] == "pysmi"),
        sum(1 for k in st.modules if k[0] == "netsnmp")))
    out.append("| oracle | field | compared | agree | rate |")
    out.append("|---|---|---|---|---|")
    tot_c = collections.Counter()
    tot_o = collections.Counter()
    for key in sorted(st.cmp):
        c = st.cmp[key]
        o = st.ok[key]
        tot_c[key[0]] += c
        tot_o[key[0]] += o
        out.append("| %s | %s | %d | %d | %.2f%% |" % (key[0], key[1], c, o, 100.0 * o / c if c else 100.0))
    for orc in sorted(tot_c):
        out.append("| %s | **all** | %d | %d | %.2f%% |" % (orc, tot_c[orc], tot_o[orc], 100.0 * tot_o[orc] / tot_c[orc]))
    out.append("")
    for orc in sorted(st.missing):
        ms = st.missing[orc]
        out.append("Names %s knows and we do not: %d" % (orc, len(ms)))
        for x in ms[: a.show]:
            out.append("- %s::%s %s" % x)
        out.append("")
    if a.show:
        for key in sorted(st.bad):
            bs = st.bad[key]
            out.append("## %s %s: %d disagreements\n" % (key[0], key[1], len(bs)))
            for mod, name, theirs, ours_v in bs[: a.show]:
                out.append("- %s::%s oracle=%s ours=%s" % (mod, name, json.dumps(theirs), json.dumps(ours_v)))
            out.append("")
    text = "\n".join(out) + "\n"
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if a.list:
        with open(a.list, "w", encoding="utf-8") as f:
            f.write("oracle\tfield\tmodule\tname\toracle_value\tours\n")
            for key in sorted(st.bad):
                for mod, name, theirs, ours_v in st.bad[key]:
                    f.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (key[0], key[1], mod, name, json.dumps(theirs), json.dumps(ours_v)))


if __name__ == "__main__":
    main()
