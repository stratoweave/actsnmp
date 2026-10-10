#!/usr/bin/env python3
"""Compare the actsnmp front-end corpus sweep with the oracle verdicts.

    python3 interop/mibs/compare/parse_vs_oracles.py [--mibs-dir interop/mibs]
        [--ours cache/actsnmp-parse.tsv] [--out FILE.md] [--list FILE.tsv] [--show N]

Inputs (relative to --mibs-dir):

- ``cache/actsnmp-parse.tsv``: one row per corpus file, written by the tagged Acton test
  ``mib.test_corpus.corpus_parse`` (columns: module, modules, bytes, ms, max_level, defs,
  codes, errors). When it is missing, ``cache/actsnmp-parse.part*of*.tsv`` are merged.
- ``modules.tsv``: oracle verdicts per module (see README.md).
- ``cache/pysmi-dialect/status/M.json``: the pysmi parse-only probe (lark grammar plus AST
  build of M's own text, no imports), with the lark error detail.
- ``cache/smilint/status/M.json``: smilint messages, to count smilint's *syntax* errors
  (severity 1 ``internal-other``, ``lexical``, ``keyword-illegal*``), which unlike
  ``modules.tsv``'s severity-1 count exclude unresolved imports and OIDs.

"Parses fine" per oracle:

- pysmi: the dialect probe is ``smiv2``, ``smiv1`` or ``relaxed`` (``grammar-error`` and
  ``ast-error`` are parse failures). This is a parse-only verdict, comparable to ours.
- net-snmp: ``netsnmp`` is ``ok`` (loaded, no message attributed to the module). net-snmp
  always resolves imports, so ``errors``/``fail`` can also come from other modules.
- smilint: no severity-1 syntax message (see above) in the module.

We "fail" a module when the sweep reports a level-0 or level-1 diagnostic in its file.

Output: a Markdown report (stdout, or --out) with the rates, the four discrepancy sets
(we fail / an oracle parses; an oracle fails / we parse), our level-1 modules grouped by
the first error, and with --show N the first N level-1 errors of each module together with
the offending source line. --list writes the per-module comparison as TSV.
Pure stdlib.
"""

import argparse
import collections
import glob
import json
import os
import re
import sys

PYSMI_OK = ("smiv2", "smiv1", "relaxed")
SMILINT_SYNTAX = ("internal-other", "lexical", "keyword-illegal", "keyword-illegal-in-mib")


def read_tsv(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l for l in f if not l.startswith("#")]
    hdr = lines[0].rstrip("\n").split("\t")
    return [dict(zip(hdr, l.rstrip("\n").split("\t"))) for l in lines[1:] if l.strip()]


def load_ours(mibs, path):
    if path is None:
        path = os.path.join(mibs, "cache", "actsnmp-parse.tsv")
    paths = [path]
    if not os.path.exists(path):
        paths = sorted(glob.glob(os.path.join(mibs, "cache", "actsnmp-parse.part*of*.tsv")))
        if not paths:
            sys.exit("no sweep output: run mib.test_corpus.corpus_parse first (" + path + ")")
    rows = {}
    for p in paths:
        for r in read_tsv(p):
            rows[r["module"]] = r
    return rows


def load_json_dir(mibs, oracle):
    res = {}
    for p in glob.glob(os.path.join(mibs, "cache", oracle, "status", "*.json")):
        try:
            with open(p) as f:
                r = json.load(f)
        except (OSError, ValueError):
            continue
        res[r.get("module", os.path.basename(p)[:-5])] = r
    return res


SMILINT_RE = re.compile(r":(\d+): \[(\d)\] \{([^}]*)\}")


def smilint_syntax_errors(st):
    """Number of severity-1 syntax-type smilint messages located in the module itself."""
    n = 0
    for line in (st or {}).get("lines", []):
        m = SMILINT_RE.search(line)
        if m and m.group(2) == "1" and m.group(3) in SMILINT_SYNTAX:
            n += 1
    return n


def ours_fails(r):
    ml = r.get("max_level", "-")
    return ml in ("0", "1")


def first_error_class(r):
    """Our first level-0/1 error, normalised: code plus message with quoted text elided."""
    e = r.get("errors", "").split(" | ")[0]
    parts = e.split(" ", 2)
    if len(parts) < 3:
        return e
    code, msg = parts[1], parts[2]
    msg = re.sub(r"'[^']*'", "'_'", msg)
    msg = re.sub(r"\b\d+\b", "N", msg)
    return code + ": " + msg


def source_line(mibs, module, line):
    p = os.path.join(mibs, "corpus", "flat", module)
    try:
        with open(p, "rb") as f:
            data = f.read()
    except OSError:
        return ""
    lines = re.split(rb"\r\n|\r|\n", data)
    if 1 <= line <= len(lines):
        return lines[line - 1].decode("latin-1").strip()[:160]
    return ""


def pysmi_detail(st):
    if not st:
        return ""
    d = st.get("detail") or {}
    if d:
        return "line %s: %s %s" % (d.get("line"), d.get("lark", ""), (d.get("source_line") or "").strip()[:100])
    e = st.get("error") or {}
    if e:
        return "line %s: %s" % (e.get("lineno"), str(e.get("msg", ""))[:100])
    return ""


def pct(n, d):
    return "%.2f%%" % (100.0 * n / d) if d else "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mibs-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    ap.add_argument("--ours", default=None, help="sweep TSV (default cache/actsnmp-parse.tsv)")
    ap.add_argument("--out", default=None, help="write the Markdown report here instead of stdout")
    ap.add_argument("--list", default=None, help="write the per-module comparison TSV here")
    ap.add_argument("--show", type=int, default=0, help="show up to N level-1 errors with source lines per module")
    a = ap.parse_args()
    mibs = os.path.abspath(a.mibs_dir)

    ours = load_ours(mibs, a.ours)
    mods = {r["module"]: r for r in read_tsv(os.path.join(mibs, "modules.tsv"))}
    dialect = load_json_dir(mibs, "pysmi-dialect")
    smilint = load_json_dir(mibs, "smilint")

    names = sorted(set(ours) & set(mods))
    only_ours = sorted(set(ours) - set(mods))
    only_oracles = sorted(set(mods) - set(ours))

    rows = []
    for n in names:
        o, m = ours[n], mods[n]
        pys = m.get("pysmi_dialect", "")
        pys_ok = pys.split(":")[0] in PYSMI_OK
        ns = m.get("netsnmp", "")
        sl = smilint_syntax_errors(smilint.get(n))
        rows.append({
            "module": n,
            "ours_fail": ours_fails(o),
            "ours_max": o.get("max_level", "-"),
            "ours_errors": o.get("errors", ""),
            "ours_class": first_error_class(o) if ours_fails(o) else "",
            "pysmi": pys,
            "pysmi_ok": pys_ok,
            "pysmi_class": m.get("pysmi_relaxed_class", ""),
            "pysmi_detail": pysmi_detail(dialect.get(n)),
            "netsnmp": ns,
            "netsnmp_class": m.get("netsnmp_class", ""),
            "smilint_syntax": sl,
            "bytes": int(o.get("bytes", "0") or 0),
            "ms": float(o.get("ms", "0") or 0),
        })

    total = len(rows)
    n_ours = sum(1 for r in rows if r["ours_fail"])
    n_pys = sum(1 for r in rows if not r["pysmi_ok"])
    n_ns_fail = sum(1 for r in rows if r["netsnmp"] == "fail")
    n_ns_notok = sum(1 for r in rows if r["netsnmp"] != "ok")
    n_sl = sum(1 for r in rows if r["smilint_syntax"] > 0)
    a_set = [r for r in rows if r["ours_fail"] and r["pysmi_ok"]]
    b_set = [r for r in rows if r["ours_fail"] and r["netsnmp"] == "ok"]
    c_set = [r for r in rows if not r["ours_fail"] and not r["pysmi_ok"]]
    d_set = [r for r in rows if not r["ours_fail"] and r["netsnmp"] == "fail"]
    e_set = [r for r in rows if r["ours_fail"] and not r["pysmi_ok"] and r["netsnmp"] != "ok"]

    out = []
    w = out.append
    w("# actsnmp front end vs. oracles (parse level)")
    w("")
    w("Modules compared: %d (sweep rows not in modules.tsv: %d; modules.tsv rows not swept: %d)."
      % (total, len(only_ours), len(only_oracles)))
    tb = sum(r["bytes"] for r in rows)
    tms = sum(r["ms"] for r in rows)
    if tms > 0:
        w("Sweep: %.1f MB in %.1f s lex+parse (%.1f MB/s)." % (tb / 1e6, tms / 1e3, tb / 1e6 / (tms / 1e3)))
    w("")
    w("| verdict | modules | rate |")
    w("|---|---|---|")
    w("| actsnmp: level 0-1 diagnostic | %d | %s |" % (n_ours, pct(n_ours, total)))
    w("| pysmi parse-only probe: grammar-error/ast-error | %d | %s |" % (n_pys, pct(n_pys, total)))
    w("| net-snmp: not loaded (`fail`) | %d | %s |" % (n_ns_fail, pct(n_ns_fail, total)))
    w("| net-snmp: not `ok` (`errors` or `fail`, imports included) | %d | %s |" % (n_ns_notok, pct(n_ns_notok, total)))
    w("| smilint: severity-1 syntax message | %d | %s |" % (n_sl, pct(n_sl, total)))
    w("")
    w("| discrepancy set | modules |")
    w("|---|---|")
    w("| A: we report level 1, pysmi parses | %d |" % len(a_set))
    w("| B: we report level 1, net-snmp `ok` | %d |" % len(b_set))
    w("| C: pysmi grammar/AST error, we have no level 1 | %d |" % len(c_set))
    w("| D: net-snmp `fail`, we have no level 1 | %d |" % len(d_set))
    w("| E: we report level 1, pysmi fails and net-snmp is not `ok` | %d |" % len(e_set))
    w("")

    def table(title, rs, show):
        w("## " + title + " (%d)" % len(rs))
        w("")
        if not rs:
            w("(none)")
            w("")
            return
        w("| module | ours | pysmi | net-snmp | smilint syntax |")
        w("|---|---|---|---|---|")
        for r in rs:
            w("| %s | %s | %s %s | %s %s | %d |" % (
                r["module"], (r["ours_errors"] or "-").replace("|", "/")[:160],
                r["pysmi"], r["pysmi_detail"].replace("|", "/")[:120],
                r["netsnmp"], r["netsnmp_class"].replace("|", "/")[:60], r["smilint_syntax"]))
        w("")
        if show:
            for r in rs:
                errs = [e for e in r["ours_errors"].split(" | ") if e][:show]
                for e in errs:
                    m = re.match(r"(\d+):(\d+) ", e)
                    if m:
                        w("    %s:%s  %s" % (r["module"], m.group(1), source_line(mibs, r["module"], int(m.group(1)))))
            w("")

    table("A: we report level 1, pysmi parses", a_set, a.show)
    table("B: we report level 1, net-snmp ok", [r for r in b_set if r not in a_set], a.show)
    table("E: we report level 1, both oracles fail too", [r for r in e_set if r not in a_set and r not in b_set], a.show)

    w("## Our level-1 modules by first error (%d)" % n_ours)
    w("")
    groups = collections.Counter(r["ours_class"] for r in rows if r["ours_fail"])
    w("| first error | modules | examples |")
    w("|---|---|---|")
    for cls, cnt in groups.most_common():
        ex = [r["module"] for r in rows if r["ours_fail"] and r["ours_class"] == cls][:4]
        w("| %s | %d | %s |" % (cls.replace("|", "/")[:140], cnt, ", ".join(ex)))
    w("")

    w("## C: pysmi grammar/AST error, we have no level 1, by pysmi class (%d)" % len(c_set))
    w("")
    cg = collections.Counter(r["pysmi_class"] or "(unclassified)" for r in c_set)
    w("| pysmi class | modules | examples |")
    w("|---|---|---|")
    for cls, cnt in cg.most_common():
        ex = [r["module"] for r in c_set if (r["pysmi_class"] or "(unclassified)") == cls][:4]
        w("| %s | %d | %s |" % (cls.replace("|", "/"), cnt, ", ".join(ex)))
    w("")
    w("## D: net-snmp fail, we have no level 1, by net-snmp class (%d)" % len(d_set))
    w("")
    dg = collections.Counter(r["netsnmp_class"] or "(unclassified)" for r in d_set)
    w("| net-snmp class | modules | examples |")
    w("|---|---|---|")
    for cls, cnt in dg.most_common():
        ex = [r["module"] for r in d_set if (r["netsnmp_class"] or "(unclassified)") == cls][:4]
        w("| %s | %d | %s |" % (cls.replace("|", "/"), cnt, ", ".join(ex)))
    w("")

    text = "\n".join(out) + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if a.list:
        cols = ["module", "ours_max", "ours_fail", "pysmi", "pysmi_ok", "netsnmp", "smilint_syntax",
                "ours_class", "ours_errors", "pysmi_class", "pysmi_detail", "netsnmp_class"]
        with open(a.list, "w") as f:
            f.write("\t".join(cols) + "\n")
            for r in rows:
                f.write("\t".join(str(r[c]).replace("\t", " ") for c in cols) + "\n")


if __name__ == "__main__":
    main()
