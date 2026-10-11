#!/usr/bin/env python3
"""Summarise a YANG check run (yang_check.sh golden-all|sample|corpus): pass rates per validator.

    python3 interop/mibs/compare/yang_report.py --out DIR [--check DIR] [--title T] [--md FILE]
        [--examples N]

Inputs (as yang_check.sh lays them out):

- ``--out DIR``: the emitted YANG (``<MOD>.yang``), the emitter's per-slice results
  ``yang-modules*.tsv`` (``<MOD>\\tok|failed|not-loaded``) and diagnostics ``yang-diags*.txt``
  (or per-module ``<MOD>.diags`` for the golden sets);
- ``--check DIR`` (default ``DIR/check``): per part ``p<i>.targets`` (target modules),
  ``p<i>.files`` (their closure), ``p<i>.pyang.txt`` (``pyang --strict`` output) and
  ``p<i>.actonyang.txt`` (``yangcheck --keep-going ... --meta ...`` output).

Pass rates are per module: the emitter (translation ``ok``), pyang (no error in the module's
file; warnings listed separately), acton-yang (the module compiled within its part's closure,
not ``FAILED``/``BLOCKED``) and the mibmeta consistency check (no ``PROBLEM``
about the module's paths). Each is given for the target modules and for every module checked
(targets plus the closure modules they import). pyang messages are grouped by class (quoted
names replaced by ``X``) with the modules they occur in. Pure stdlib.
"""

import argparse
import glob
import os
import re
import sys

PYANG_RE = re.compile(r"^([^:]+?)\.yang:(\d+)(?:\s*\(at [^)]*\))?: (error|warning): (.*)$")


def norm(msg):
    return re.sub(r'"[^"]*"', '"X"', msg).strip()


def read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [l.rstrip("\n") for l in f]
    except OSError:
        return []


def pct(a, b):
    return "%.2f%%" % (100.0 * a / b) if b else "n/a"


class Run:
    def __init__(self, out, check):
        self.out = out
        self.check = check
        self.emit = {}          # module -> ok|failed|not-loaded
        self.diag_codes = {}    # code -> count
        self.diag_mods = {}     # code -> set(modules)
        self.parts = []         # (name, targets, files)
        self.pyang = {}         # (module, line, sev, msg) set per part
        self.acton = {}         # part -> dict
        self.load()

    def load(self):
        for p in sorted(glob.glob(os.path.join(self.out, "yang-modules*.tsv"))):
            for l in read_lines(p):
                c = l.split("\t")
                if len(c) >= 2:
                    self.emit[c[0]] = c[1]
        diag_files = sorted(glob.glob(os.path.join(self.out, "yang-diags*.txt")))
        if not diag_files:
            diag_files = sorted(glob.glob(os.path.join(self.out, "*.diags")))
            if not self.emit:
                for f in diag_files:
                    m = os.path.basename(f)[:-6]
                    self.emit[m] = "ok"
                    for l in read_lines(f):
                        if "[1] {yang." in l:
                            self.emit[m] = "failed"
        for f in diag_files:
            for l in read_lines(f):
                mm = re.search(r"\[(\d)\] \{([^}]+)\}", l)
                if not mm:
                    continue
                code = "[%s] %s" % (mm.group(1), mm.group(2))
                self.diag_codes[code] = self.diag_codes.get(code, 0) + 1
                mod = os.path.basename(l.split(":")[0])
                self.diag_mods.setdefault(code, set()).add(mod)
        pnames = [l.strip() for l in read_lines(os.path.join(self.check, "parts.txt")) if l.strip()]
        if not pnames:
            pnames = sorted((os.path.basename(t)[:-8] for t in glob.glob(os.path.join(self.check, "p*.targets"))),
                            key=lambda p: int(re.sub(r"\D", "", p) or 0))
        for name in pnames:
            targets = [l.strip() for l in read_lines(os.path.join(self.check, name + ".targets")) if l.strip()]
            files = [os.path.basename(l.strip())[:-5] for l in read_lines(os.path.join(self.check, name + ".files")) if l.strip()]
            self.parts.append((name, targets, files))
            for l in read_lines(os.path.join(self.check, name + ".pyang.txt")):
                m = PYANG_RE.match(l)
                if m:
                    self.pyang[(os.path.basename(m.group(1)), int(m.group(2)), m.group(3), m.group(4))] = True
            a = {"ran": False, "compiled": "", "failed": {}, "blocked": {}, "problems": [], "meta": "", "error": ""}
            for l in read_lines(os.path.join(self.check, name + ".actonyang.txt")):
                a["ran"] = True
                if l.startswith("compiled "):
                    a["compiled"] = l
                elif l.startswith("FAILED "):
                    mod, _, msg = l[7:].partition(": ")
                    a["failed"][mod] = msg
                elif l.startswith("BLOCKED "):
                    mod, _, msg = l[8:].partition(": ")
                    a["blocked"][mod] = msg
                elif l.startswith("mibmeta: "):
                    a["meta"] = l
                elif l.startswith("PROBLEM "):
                    a["problems"].append(l[8:])
                elif l.startswith("COMPILE ERROR"):
                    a["error"] = l
            self.acton[name] = a

    def report(self, title, examples):
        out = []
        w = out.append
        w("## " + title)
        w("")
        targets = sorted({m for _, t, _ in self.parts for m in t}) or sorted(self.emit)
        checked = sorted({m for _, _, f in self.parts for m in f})
        # emitter
        st = {}
        for m in targets:
            s = self.emit.get(m, "?")
            st[s] = st.get(s, 0) + 1
        tgt_emit = [m for m in self.emit if self.emit[m] != "not-loaded"]
        w("| validator | target modules passing | all modules checked passing |")
        w("|---|---|---|")
        ok_t = sum(1 for m in tgt_emit if self.emit[m] == "ok")
        w("| emitter (translation ok, RFC 6643 §7.1 T16 failures counted as failing) | %d / %d (%s) | |" % (ok_t, len(tgt_emit), pct(ok_t, len(tgt_emit))))
        perr = {}
        pwarn = {}
        for (mod, line, sev, msg) in self.pyang:
            (perr if sev == "error" else pwarn).setdefault(mod, []).append((line, msg))
        if self.pyang or any(os.path.exists(os.path.join(self.check, p + ".pyang.txt")) for p, _, _ in self.parts):
            tp = [m for m in targets if m in checked]
            ok_t = sum(1 for m in tp if m not in perr)
            ok_a = sum(1 for m in checked if m not in perr)
            w("| pyang 2.6.1 --strict (no error) | %d / %d (%s) | %d / %d (%s) |" % (ok_t, len(tp), pct(ok_t, len(tp)), ok_a, len(checked), pct(ok_a, len(checked))))
            ok_t = sum(1 for m in tp if m not in perr and m not in pwarn)
            ok_a = sum(1 for m in checked if m not in perr and m not in pwarn)
            w("| pyang 2.6.1 --strict (no error, no warning) | %d / %d (%s) | %d / %d (%s) |" % (ok_t, len(tp), pct(ok_t, len(tp)), ok_a, len(checked), pct(ok_a, len(checked))))
        ran = [p for p, _, _ in self.parts if self.acton.get(p, {}).get("ran")]
        if ran:
            bad = set()
            unknown = set()
            for p, t, f in self.parts:
                a = self.acton.get(p, {})
                if not a.get("ran"):
                    continue
                bad |= set(a["failed"]) | set(a["blocked"])
                if a["error"]:
                    unknown |= set(f)
            tp = [m for p, t, f in self.parts if p in ran for m in t]
            ap = sorted({m for p, t, f in self.parts if p in ran for m in f})
            ok_t = sum(1 for m in tp if m not in bad and m not in unknown)
            ok_a = sum(1 for m in ap if m not in bad and m not in unknown)
            w("| acton-yang compile (closure per part) | %d / %d (%s) | %d / %d (%s) |" % (ok_t, len(tp), pct(ok_t, len(tp)), ok_a, len(ap), pct(ok_a, len(ap))))
            pm = set()
            for p in ran:
                for pr in self.acton[p]["problems"]:
                    for seg in re.findall(r"/([A-Za-z0-9_.-]+):", pr)[:1]:
                        pm.add(seg)
            nprob = sum(len(self.acton[p]["problems"]) for p in ran)
            w("| mibmeta vs acton-yang schema | %d problems | %s |" % (nprob, ", ".join(self.acton[p]["meta"] for p in ran if self.acton[p]["meta"])[:300] or "not run"))
        w("")
        if st:
            w("Emitter status of the targets: " + ", ".join("%s %d" % (k, v) for k, v in sorted(st.items())) + ".")
            failed = sorted(m for m in tgt_emit if self.emit[m] == "failed")
            if failed:
                w("Translation failures: " + ", ".join(failed) + ".")
            w("")
        if ran:
            w("acton-yang parts:")
            w("")
            for p, t, f in self.parts:
                a = self.acton.get(p, {})
                if not a.get("ran"):
                    continue
                w("- %s: %d targets, closure %d: %s%s%s" % (p, len(t), len(f), a["compiled"] or a["error"],
                                                          "; FAILED " + ", ".join(sorted(a["failed"])) if a["failed"] else "",
                                                          "; BLOCKED %d" % len(a["blocked"]) if a["blocked"] else ""))
                for m, msg in sorted(a["failed"].items()):
                    w("  - FAILED %s: %s" % (m, msg[:300]))
            w("")
        for sev, d in (("error", perr), ("warning", pwarn)):
            cls = {}
            for mod, items in d.items():
                for line, msg in items:
                    cls.setdefault(norm(msg), []).append((mod, line))
            if not cls:
                continue
            w("pyang %ss by class (messages / modules):" % sev)
            w("")
            for c, items in sorted(cls.items(), key=lambda kv: -len(kv[1])):
                mods = sorted({m for m, _ in items})
                ex = ", ".join("%s:%d" % (m, l) for m, l in sorted(items)[:examples])
                w("- %d / %d: `%s` (e.g. %s)" % (len(items), len(mods), c, ex))
            w("")
        cov = self.coverage(targets)
        if cov:
            w("Data node coverage of the targets (mibmeta nodes that have no YANG data node):")
            w("")
            for k, (n, missing, ex) in sorted(cov.items()):
                w("- %s: %d of %d without a data node%s" % (k, missing, n, (" (e.g. " + ", ".join(ex) + ")") if ex else ""))
            w("")
        probs = [pr for p in ran for pr in self.acton[p]["problems"]]
        if probs:
            cls = {}
            for pr in probs:
                cls.setdefault(re.sub(r"/[^ ]+", "PATH", re.sub(r"\(smiv2:oid [^)]*\)", "(OID)", pr)), []).append(pr)
            w("mibmeta problems by class:")
            w("")
            for c, items in sorted(cls.items(), key=lambda kv: -len(kv[1])):
                w("- %d: `%s` (e.g. %s)" % (len(items), c, "; ".join(items[:examples])[:500]))
            w("")
        if self.diag_codes:
            w("Emitter diagnostics (code: count / modules):")
            w("")
            for c, n in sorted(self.diag_codes.items(), key=lambda kv: (-kv[1], kv[0])):
                w("- %s: %d / %d" % (c, n, len(self.diag_mods.get(c, ()))))
            w("")
        return "\n".join(out) + "\n"


def _coverage(self, targets, examples=3):
    """Per class: (objects, objects without a YANG data node, examples). Objects: scalars and
    columns except accessible-for-notify ones (split by resolved/unresolved syntax), rows and
    tables (split by augmenting or not), notifications."""
    import json
    out = {}
    for m in targets:
        p = os.path.join(self.out, m + ".mibmeta.json")
        if not os.path.exists(p):
            continue
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        rows = {}
        for n in d.get("nodes", []):
            if n.get("kind") == "row":
                rows.setdefault(n.get("oid", "").rsplit(".", 1)[0], []).append(n)
        for n in d.get("nodes", []):
            k = n.get("kind")
            if k in ("scalar", "column"):
                if n.get("access") == "accessible-for-notify":
                    continue
                cls = k + (" (resolved syntax)" if "syntax" in n else " (unresolved syntax)")
            elif k == "row":
                cls = "row" + (" (augmenting: none expected)" if n.get("augments") else "")
            elif k == "table":
                rs = rows.get(n.get("oid", ""), [])
                if rs and all(r.get("augments") for r in rs):
                    cls = "table (of augmenting rows: none expected)"
                elif not rs:
                    cls = "table (without a row)"
                else:
                    cls = "table"
            elif k == "notification":
                cls = "notification"
            else:
                continue
            e = out.setdefault(cls, [0, 0, []])
            e[0] += 1
            if not n.get("yang"):
                e[1] += 1
                if len(e[2]) < examples:
                    e[2].append(m + "::" + n.get("name", "?"))
    return {k: tuple(v) for k, v in out.items()}


Run.coverage = _coverage


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--check")
    ap.add_argument("--title", default="YANG check")
    ap.add_argument("--md")
    ap.add_argument("--examples", type=int, default=3)
    a = ap.parse_args()
    r = Run(a.out, a.check or os.path.join(a.out, "check"))
    text = r.report(a.title, a.examples)
    if a.md:
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
