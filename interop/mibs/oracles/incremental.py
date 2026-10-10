#!/usr/bin/env python3
"""Select the modules whose oracle results are stale after a re-index, and stash
their old results (host side, driven by oracles.sh --incremental).

    incremental.py OLD_MODULES_TSV NEW_MODULES_TSV CACHE_DIR [--dry-run]

Stale = the chosen corpus/flat copy is new or its text changed (sha256 of the
module text in corpus/index*/modules.tsv), plus every module that imports one
of those, transitively (the oracles resolve imports, so an importer's verdict
can change with its imports). Same text from another source/path is not stale.
Names that disappeared from the corpus are listed too (their results are
stashed so report.py does not count them).

For every stale module the existing results in CACHE_DIR/<oracle>/ (status/,
json/, out/) are moved to CACHE_DIR/_prev/<oracle>/ (report.py compares old
and new verdicts there), so a resumable oracles.sh run redoes exactly these.
Writes CACHE_DIR/_incremental.txt (the module list, one per line, for
run.py --modules-file) and CACHE_DIR/_incremental.json (the classification).
"""

import collections
import json
import os
import shutil
import sys

ORACLES = ["pysmi-relaxed", "pysmi-strict", "pysmi-dialect", "netsnmp", "smilint"]
SUBDIRS = {"status": ".json", "json": ".json", "out": ".jsonl"}


def read_modules(path):
    with open(path) as f:
        lines = [l.rstrip("\n").split("\t") for l in f if not l.startswith("#")]
    hdr = lines[0]
    return {r[0]: dict(zip(hdr, r)) for r in lines[1:]}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    old, new = read_modules(args[0]), read_modules(args[1])
    cache = args[2]
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(n for n in set(old) & set(new) if old[n]["sha256"] != new[n]["sha256"])
    moved = sorted(n for n in set(old) & set(new) if old[n]["sha256"] == new[n]["sha256"]
                   and (old[n]["source"], old[n]["path"]) != (new[n]["source"], new[n]["path"]))
    importers = collections.defaultdict(set)
    for table in (old, new):
        for n, r in table.items():
            for i in filter(None, r["imports"].split(",")):
                importers[i].add(n)
    seed = set(added) | set(changed) | set(removed)
    stale = set(seed)
    queue = list(seed)
    while queue:
        m = queue.pop()
        for imp in importers.get(m, ()):
            if imp not in stale:
                stale.add(imp)
                queue.append(imp)
    cascade = sorted(stale - seed)
    todo = sorted(n for n in stale if n in new)
    info = {"added": added, "changed": changed, "removed": removed, "moved_same_text": moved,
            "cascade": cascade, "rerun": todo,
            "changed_from": {n: [old[n]["source"], old[n]["path"], old[n]["sha256"][:16]] for n in changed}}
    print(f"incremental: {len(added)} new, {len(changed)} changed, {len(removed)} removed, "
          f"{len(moved)} same text from another source (no rerun), {len(cascade)} importers -> "
          f"{len(todo)} modules to re-run", file=sys.stderr)
    if dry:
        return
    moved_files = 0
    for o in ORACLES:
        for sub, ext in SUBDIRS.items():
            src = os.path.join(cache, o, sub)
            if not os.path.isdir(src):
                continue
            dst = os.path.join(cache, "_prev", o, sub)
            for n in stale:
                p = os.path.join(src, n + ext)
                if os.path.exists(p):
                    os.makedirs(dst, exist_ok=True)
                    shutil.move(p, os.path.join(dst, n + ext))
                    moved_files += 1
    with open(os.path.join(cache, "_incremental.txt"), "w") as f:
        f.write("".join(n + "\n" for n in todo))
    with open(os.path.join(cache, "_incremental.json"), "w") as f:
        json.dump(info, f, indent=1)
    print(f"incremental: stashed {moved_files} old result files in {os.path.join(cache, '_prev')}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
