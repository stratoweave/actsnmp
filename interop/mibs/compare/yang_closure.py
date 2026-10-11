#!/usr/bin/env python3
"""Split a list of emitted YANG modules into parts and list each part's import closure.

    python3 interop/mibs/compare/yang_closure.py --dir DIR --names FILE --parts K --out-dir D

``DIR`` holds ``<MOD>.yang`` files written by ``mib.test_yang`` (``yang_corpus`` or
``yang_golden_vendor``); ``--names`` lists the target modules (one per line; a ``.tsv`` is read
by its first column, as ``yang-modules*.tsv``). The targets that have a ``.yang`` file are
split into ``K`` parts (contiguous slices of the sorted names, so a vendor's modules mostly
stay together), and for part ``i`` (1-based) the script writes

- ``D/p<i>.targets``: the part's target module names;
- ``D/p<i>.files``: the ``.yang`` paths of the targets and of every module they import,
  transitively (``import X {`` statements; the IETF modules ``ietf-*`` are left out, the
  checkers take them from ``interop/mibs/yang-examples/yang-ietf``).

``D/parts.txt`` lists the part names of this run (``p1`` ...). The parts are the units for pyang (``--strict`` over ``p<i>.files``) and for acton-yang
(``yangcheck`` compiles one part as one closure, under the 15-minute lock hold). With
``--weights`` the parts are balanced by the total size of their closure files instead of the
number of targets. Pure stdlib.
"""

import argparse
import os
import re

IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z0-9_.-]+)\s*\{", re.M)


def read_names(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line.split("\t")[0])
    return out


class Repo:
    def __init__(self, d):
        self.d = d
        self.imports = {}

    def path(self, m):
        return os.path.join(self.d, m + ".yang")

    def has(self, m):
        return os.path.exists(self.path(m))

    def imps(self, m):
        if m not in self.imports:
            try:
                with open(self.path(m), encoding="utf-8", errors="replace") as f:
                    head = f.read(200000)
                # imports come before the first data definition; the header is small
                self.imports[m] = [x for x in IMPORT_RE.findall(head) if not x.startswith("ietf-")]
            except OSError:
                self.imports[m] = []
        return self.imports[m]

    def closure(self, targets):
        seen = set()
        todo = list(targets)
        while todo:
            m = todo.pop()
            if m in seen or not self.has(m):
                continue
            seen.add(m)
            todo.extend(self.imps(m))
        return sorted(seen)


def split(names, k, weight=None):
    if k <= 1 or not names:
        return [names]
    if weight is None:
        n = len(names)
        return [names[i * n // k:(i + 1) * n // k] for i in range(k)]
    total = sum(weight(m) for m in names)
    parts, cur, acc = [], [], 0
    for m in names:
        cur.append(m)
        acc += weight(m)
        if acc >= total * (len(parts) + 1) / k and len(parts) < k - 1:
            parts.append(cur)
            cur = []
    parts.append(cur)
    return parts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", required=True)
    ap.add_argument("--names", required=True)
    ap.add_argument("--parts", type=int, default=1)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--weights", action="store_true", help="balance parts by YANG file size")
    a = ap.parse_args()
    repo = Repo(a.dir)
    names = sorted({m for m in read_names(a.names) if repo.has(m)})
    w = (lambda m: os.path.getsize(repo.path(m))) if a.weights else None
    os.makedirs(a.out_dir, exist_ok=True)
    parts = split(names, a.parts, w)
    with open(os.path.join(a.out_dir, "parts.txt"), "w", encoding="utf-8") as f:
        f.write("".join("p%d\n" % i for i in range(1, len(parts) + 1)))
    for i, part in enumerate(parts, 1):
        clo = repo.closure(part)
        with open(os.path.join(a.out_dir, "p%d.targets" % i), "w", encoding="utf-8") as f:
            f.write("".join(m + "\n" for m in part))
        with open(os.path.join(a.out_dir, "p%d.files" % i), "w", encoding="utf-8") as f:
            f.write("".join(repo.path(m) + "\n" for m in clo))
        size = sum(os.path.getsize(repo.path(m)) for m in clo)
        print("part %d: %d targets, closure %d modules, %.1f MB" % (i, len(part), len(clo), size / 1e6))


if __name__ == "__main__":
    main()
