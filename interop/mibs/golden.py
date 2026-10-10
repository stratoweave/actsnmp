#!/usr/bin/env python3
"""Golden set helper (driven by golden.sh).

    golden.py select    golden/select.tsv + corpus -> golden/golden.tsv, golden/mibs/
    golden.py stage [--local]
                        golden/golden.tsv (+ golden/mibs, corpus for reference-only
                        modules, verified by sha256) -> cache/golden/corpus/{flat,index}
    golden.py expected [--check] [--local]
                        cache/golden/cache/<oracle>/ -> golden/expected/ + golden/expected-local/
                        (or diff with them); --local: only the local tier

Licence tiers: `ietf` (IETF/IANA modules: RFC code components) and
`netsnmp` (net-snmp's own MIBs, BSD) are committed under golden/mibs/;
`ieee` and `vendor` modules are referenced by corpus path + sha256 only.

Expected outputs come in two tiers (golden.tsv column `expected`):
  committed  golden/expected/        modules of a redistributable tier whose import
                                     closure is redistributable too (committed)
  local      golden/expected-local/  everything derived from IEEE/vendor texts
                                     (.gitignore'd; regenerated from the corpus by
                                     golden.sh / golden.sh --local; pysmi JSON
                                     without the free texts)
Without the corpus (or with a source of the local tier not fetched, e.g. the
optional Nokia bundles) `stage` skips the whole local tier with a notice and
`expected --check` checks the committed tier only.
"""

import collections
import difflib
import hashlib
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden")
CORPUS = os.path.join(HERE, "corpus")
STAGE = os.path.join(HERE, "cache", "golden")
SKIPPED = os.path.join(STAGE, "skipped.txt")  # written by stage: local-tier modules not staged
REDISTRIBUTABLE = {"ietf", "netsnmp"}
# expected-output tiers -> directory under golden/ (golden/expected-local/ is in .gitignore)
EXPECTED_DIRS = {"committed": "expected", "local": "expected-local"}
sys.path.insert(0, HERE)
from index import VENDORS  # noqa: E402  (vendor namespaces: never redistributable)
IETF_BY_NAME = {"RFC-1212", "RFC-1215", "RFC1155-SMI", "RFC1065-SMI", "RFC1158-MIB", "RFC1213-MIB"}
TEXT_KEYS = {"description", "reference", "organization", "contactinfo"}


def read_tsv(path):
    with open(path) as f:
        lines = [l for l in f if not l.startswith("#") and l.strip()]
    hdr = lines[0].rstrip("\n").split("\t")
    return [dict(zip(hdr, l.rstrip("\n").split("\t"))) for l in lines[1:]]


def foreign_copyright(text):
    """True if the text carries a copyright notice of anyone but the Internet Society / IETF Trust, e.g.
    a vendor's header on its copy of a standard module (LibreNMS's bintec/RFC1158-MIB: "(C)opyright
    2004-2014 bintec elmeg GmbH"): such a copy is not an RFC code component and is never committed."""
    notices = re.findall(r"^.*(?:\(C\)\s*opyright|Copyright\s*(?:\(C\)|\xa9|\d{4})).*$", text, re.I | re.M)
    return any(not re.search(r"Internet Society|IETF Trust", l, re.I) for l in notices)


def tier_of(row, text):
    name, src = row["module"], row["source"]
    if src in ("ietf", "iana") or ((name in IETF_BY_NAME or name.startswith("IANA") or re.match(r"RFC-?\d+", name))
                                   and not foreign_copyright(text)):
        return "ietf"
    if src == "netsnmp" and re.match(r"(NET-SNMP-|UCD-|LM-SENSORS-MIB)", name):
        return "netsnmp"
    if row.get("owned") == "1" or src.startswith(("juniper", "nokia")):
        return "vendor"  # official vendor copy (Juniper/Nokia bundles: never committed)
    if any(fam != "net-snmp" and (name in v["roots"] or name.startswith(v["prefixes"]) or
                                  (v["suffixes"] and name.endswith(v["suffixes"])))
           for fam, v in VENDORS.items()):
        return "vendor"  # a vendor's module, whichever copy won (e.g. LibreNMS's JUNIPER-SMI: override)
    if re.search(r"Internet Society|IETF Trust", text) and not re.search(r"Copyright.*(cisco|Juniper|IEEE)",
                                                                        text, re.I):
        return "ietf"
    if name.startswith(("IEEE", "LLDP")) or re.search(r"Copyright \(C\) IEEE", text):
        return "ieee"
    return "vendor"


def cmd_select():
    sel = read_tsv(os.path.join(GOLDEN, "select.tsv"))
    mods = {r["module"]: r for r in read_tsv(os.path.join(CORPUS, "index", "modules.tsv"))}
    want = collections.OrderedDict()
    missing = []
    for r in sel:
        if r["module"] not in mods:
            missing.append(r["module"])
            continue
        want[r["module"]] = (r["role"], r["why"])
    # import closure
    queue = list(want)
    while queue:
        m = queue.pop(0)
        for imp in filter(None, mods[m]["imports"].split(",")):
            if imp in mods and imp not in want:
                want[imp] = ("dep", "imported by " + m)
                queue.append(imp)
    if missing:
        print("not in corpus: " + ", ".join(missing), file=sys.stderr)
    mdir = os.path.join(GOLDEN, "mibs")
    if os.path.isdir(mdir):
        shutil.rmtree(mdir)
    os.makedirs(mdir)
    rows = []
    for m, (role, why) in want.items():
        r = mods[m]
        with open(os.path.join(CORPUS, "flat", m), "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        assert sha == r["sha256"], m
        tier = tier_of(r, data.decode("latin-1"))
        if tier in REDISTRIBUTABLE:
            with open(os.path.join(mdir, m), "wb") as f:
                f.write(data)
        rows.append([m, role, tier, r["source"], r["path"], sha, why])
    # expected-output tier: committed only if the module and its whole import closure are redistributable
    tiers = {x[0]: x[2] for x in rows}
    for x in rows:
        seen, todo = set(), [x[0]]
        while todo:
            n = todo.pop()
            if n in seen or n not in tiers:
                continue
            seen.add(n)
            todo.extend(i for i in mods[n]["imports"].split(",") if i)
        x.insert(6, "committed" if all(tiers[n] in REDISTRIBUTABLE for n in seen) else "local")
    order = {"core": 0, "sample": 1, "quirk": 2, "dep": 3}
    rows.sort(key=lambda x: (order.get(x[1], 9), x[0]))
    with open(os.path.join(GOLDEN, "golden.tsv"), "w") as f:
        f.write("# Golden set: curated modules (golden/select.tsv) + their import closure (role dep).\n"
                "# tier ietf/netsnmp: text committed in golden/mibs/; ieee/vendor: reference only, the text is\n"
                "# corpus/src/<source dir>/<path> (fetch.sh; source dirs: corpus/index/stats.json \"sources\",\n"
                "# e.g. juniper = juniper-official/<release>, nokia = nokia-sros/<release> (pins/*.tsv)),\n"
                "# verified by sha256 (of the module text).\n"
                "# expected: committed = expected oracle outputs in golden/expected/ (committed: the module and\n"
                "# its import closure are ietf/netsnmp tier); local = golden/expected-local/ (not committed,\n"
                "# derived from IEEE/vendor texts; golden.sh regenerates it from the corpus).\n")
        f.write("module\trole\ttier\tsource\tpath\tsha256\texpected\twhy\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    c = collections.Counter((r[1], r[2]) for r in rows)
    e = collections.Counter(r[6] for r in rows)
    print(f"golden: {len(rows)} modules: " + ", ".join(f"{k[0]}/{k[1]} {v}" for k, v in sorted(c.items())) +
          "; expected outputs: " + ", ".join(f"{k} {v}" for k, v in sorted(e.items())), file=sys.stderr)


def corpus_sources():
    """Source labels of the indexed corpus (None without a corpus)."""
    p = os.path.join(CORPUS, "index", "stats.json")
    if not os.path.isdir(os.path.join(CORPUS, "flat")) or not os.path.exists(p):
        return None
    with open(p) as f:
        return set(json.load(f).get("sources", {}))


def cmd_stage(local_only=False):
    """Stage the golden modules for an oracle run. The committed tier always comes from golden/mibs/;
    the reference-only texts come from the corpus. If the corpus (or one of the sources the local tier
    needs) is absent, the whole local tier is skipped with a notice (SKIPPED lists it for `expected`)."""
    rows = read_tsv(os.path.join(GOLDEN, "golden.tsv"))
    flat = os.path.join(STAGE, "corpus", "flat")
    idx = os.path.join(STAGE, "corpus", "index")
    for d in (flat, idx):
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d)
    srcs = corpus_sources()
    bad, skip, data_of = [], [], {}
    for r in rows:
        m = r["module"]
        p = os.path.join(GOLDEN, "mibs", m)
        if not os.path.exists(p):
            if srcs is None:
                skip.append(f"{m}: no corpus (fetch.sh)")
                continue
            if r["source"] not in srcs:
                skip.append(f"{m}: source {r['source']} not in the corpus (optional source not fetched?)")
                continue
            p = os.path.join(CORPUS, "flat", m)
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            (bad if p.startswith(GOLDEN) else skip).append(f"{m}: {p} not found")
            continue
        if hashlib.sha256(data).hexdigest() != r["sha256"]:
            bad.append(f"{m}: sha256 mismatch for {p} (corpus re-indexed? re-run golden.sh to reselect)")
            continue
        data_of[m] = data
    if bad:
        print("\n".join(bad), file=sys.stderr)
        sys.exit(1)
    local = [r["module"] for r in rows if r.get("expected", "local") == "local"]
    if skip:
        if local_only:
            print("\n".join(skip), file=sys.stderr)
            sys.exit("golden: the local tier needs the corpus (fetch.sh)")
        print(f"golden: NOTICE: skipping the local tier ({len(local)} modules with expected outputs in "
              f"golden/expected-local/, derived from IEEE/vendor texts): " + "; ".join(skip[:3]) +
              (f"; ... ({len(skip)} texts unavailable)" if len(skip) > 3 else ""), file=sys.stderr)
        keep = [r for r in rows if r.get("expected") == "committed"]
    else:
        keep = rows
    os.makedirs(STAGE, exist_ok=True)
    with open(SKIPPED, "w") as f:
        f.write("".join(m + "\n" for m in (local if skip else [])))
    with open(os.path.join(idx, "modules.tsv"), "w") as o:
        o.write("module\tsize\n")
        for r in keep:
            m = r["module"]
            with open(os.path.join(flat, m), "wb") as f:
                f.write(data_of[m])
            o.write(f"{m}\t{len(data_of[m])}\n")
    print(f"staged {len(keep)} modules in {flat}", file=sys.stderr)


def strip_texts(o):
    if isinstance(o, dict):
        return {k: strip_texts(v) for k, v in o.items() if k not in TEXT_KEYS}
    if isinstance(o, list):
        return [strip_texts(x) for x in o]
    return o


def expected_files():
    """-> {tier: {relative path: text}} generated from the staged oracle run (tiers: EXPECTED_DIRS)."""
    rows = read_tsv(os.path.join(GOLDEN, "golden.tsv"))
    cache = os.path.join(STAGE, "cache")
    hdr = ("module\tpysmi_relaxed\tpysmi_strict\tpysmi_dialect\tnetsnmp_loaded\tnetsnmp_nodes\t"
           "netsnmp_messages\tsmilint_by_severity")
    out = {t: {} for t in EXPECTED_DIRS}
    status = {t: [hdr] for t in EXPECTED_DIRS}
    skipped = set()
    if os.path.exists(SKIPPED):
        with open(SKIPPED) as f:
            skipped = {l.strip() for l in f if l.strip()}

    def st(oracle, m):
        p = os.path.join(cache, oracle, "status", m + ".json")
        if not os.path.exists(p):
            return {}
        with open(p) as f:
            return json.load(f)

    for r in rows:
        m, tier = r["module"], r["tier"]
        t = r.get("expected", "local")
        if m in skipped:
            continue
        o = out[t]
        pj = os.path.join(cache, "pysmi-relaxed", "json", m + ".json")
        if os.path.exists(pj):
            with open(pj) as f:
                doc = json.load(f)
            if tier not in REDISTRIBUTABLE:
                doc = strip_texts(doc)
            o[f"pysmi/{m}.json"] = json.dumps(doc, indent=1, sort_keys=True) + "\n"
        nj = os.path.join(cache, "netsnmp", "out", m + ".jsonl")
        if os.path.exists(nj):
            with open(nj) as f:
                o[f"netsnmp/{m}.jsonl"] = f.read()
        s = st("smilint", m)
        lines = [l.replace("/corpus/flat/", "") for l in s.get("lines", [])]
        o[f"smilint/{m}.txt"] = "".join(l + "\n" for l in lines)
        pr, ps, pd, ns = st("pysmi-relaxed", m), st("pysmi-strict", m), st("pysmi-dialect", m), st("netsnmp", m)
        sev = collections.Counter()
        for l in lines:
            mm = re.match(r"^([^:]+):\d+: \[(\d)\]", l)
            if mm and mm.group(1) == m:
                sev[mm.group(2)] += 1
        dial = pd.get("dialect", pd.get("status", "-"))
        if pd.get("relaxations"):
            dial += ":" + "+".join(pd["relaxations"])
        status[t].append("\t".join([m, pr.get("status", "-"), ps.get("status", "-"), dial,
                                    str(ns.get("loaded", "-")).lower(), str(ns.get("nodes", "-")),
                                    str(len(ns.get("stderr", []))),
                                    "/".join(str(sev.get(str(i), 0)) for i in range(1, 7))]))
    for t in EXPECTED_DIRS:
        out[t]["status.tsv"] = "\n".join(status[t]) + "\n"
    return out, bool(skipped)


def cmd_expected(check, local_only=False):
    tiers, skipped = expected_files()
    names = ["local"] if local_only else list(EXPECTED_DIRS)
    if skipped:
        names = [t for t in names if t != "local"]
        print("golden: NOTICE: local tier skipped (no corpus): golden/expected-local/ " +
              ("not checked" if check else "left unchanged"), file=sys.stderr)
    if check:
        bad = total = 0
        for t in names:
            edir = os.path.join(GOLDEN, EXPECTED_DIRS[t])
            files = tiers[t]
            if not os.path.isdir(edir):
                print(f"golden: NOTICE: {t} tier: golden/{EXPECTED_DIRS[t]}/ does not exist (not generated yet: "
                      "golden.sh --local); not checked", file=sys.stderr)
                continue
            have = set()
            for root, _, fns in os.walk(edir):
                for fn in fns:
                    have.add(os.path.relpath(os.path.join(root, fn), edir))
            for rel in sorted(set(files) | have):
                p = os.path.join(edir, rel)
                old = open(p).read() if os.path.exists(p) else None
                new = files.get(rel)
                if old != new:
                    bad += 1
                    lab = f"{EXPECTED_DIRS[t]}/{rel}"
                    if old is None or new is None:
                        print(f"{lab}: {'missing in golden/' + EXPECTED_DIRS[t] if old is None else 'not produced any more'}")
                    else:
                        sys.stdout.writelines(list(difflib.unified_diff(
                            old.splitlines(True), new.splitlines(True), lab, "actual/" + rel))[:40])
            total += len(files)
            print(f"golden check: {t} tier (golden/{EXPECTED_DIRS[t]}/): {len(files)} files", file=sys.stderr)
        print(f"golden check: {total} files, {bad} differ", file=sys.stderr)
        sys.exit(1 if bad else 0)
    for t in names:
        edir = os.path.join(GOLDEN, EXPECTED_DIRS[t])
        if os.path.isdir(edir):
            shutil.rmtree(edir)
        for rel, text in tiers[t].items():
            p = os.path.join(edir, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        print(f"wrote {len(tiers[t])} files to {edir} ({t} tier)", file=sys.stderr)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "select":
        cmd_select()
    elif cmd == "stage":
        cmd_stage("--local" in sys.argv)
    elif cmd == "expected":
        cmd_expected("--check" in sys.argv, "--local" in sys.argv)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
