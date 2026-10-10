#!/usr/bin/env python3
"""Publish a staged corpus index atomically.

    python3 swap.py [--mibs-dir DIR] [--keep-prev]

index.py builds the new de-duplicated corpus next to the published one
(corpus/flat.new, corpus/split.new, corpus/index.new, duplicates.tsv.new,
vendors.tsv.new) and report.py --stage writes modules.tsv.new and
cache/report/REPORT.md.new. This script moves every staged item into place
with renameat2(RENAME_EXCHANGE), which is atomic per path: a reader sees
either the old or the new directory, never a half-built one. The previous
versions are kept as <name>.prev until the next index.py run. The swap time
is appended to corpus/swap.log.

The links in corpus/flat.new point to ../src/... and ../split/<M>, so they
only resolve once split.new has become split. To run the oracles on a staged
corpus, use oracles.sh with MIBLAB_STAGE=1, which mounts the staged
directories at the published paths.
"""

import argparse
import ctypes
import datetime
import os
import shutil
import sys

AT_FDCWD = -100
RENAME_EXCHANGE = 2
_libc = ctypes.CDLL(None, use_errno=True)


def exchange(a, b):
    """Atomically exchange two existing paths (Linux >= 3.15, glibc >= 2.28)."""
    if _libc.renameat2(AT_FDCWD, os.fsencode(a), AT_FDCWD, os.fsencode(b), RENAME_EXCHANGE) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), f"renameat2({a}, {b}, RENAME_EXCHANGE)")


def items(mibs_dir, corpus=None):
    corpus = corpus or os.environ.get("MIBLAB_CORPUS") or os.path.join(mibs_dir, "corpus")
    dirs = [os.path.join(corpus, d) for d in ("flat", "split", "index")]
    files = [os.path.join(mibs_dir, f) for f in ("duplicates.tsv", "vendors.tsv", "modules.tsv")]
    files.append(os.path.join(mibs_dir, "cache", "report", "REPORT.md"))
    return corpus, dirs, files


def remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.unlink(path)


def clean_prev(mibs_dir, stale_new=False, corpus=None):
    """Remove *.prev (and, with stale_new, leftover *.new) of all swappable items."""
    _, dirs, files = items(mibs_dir, corpus)
    for p in dirs + files:
        remove(p + ".prev")
        if stale_new:
            remove(p + ".new")


def swap(mibs_dir, keep_prev=True, corpus=None):
    corpus, dirs, files = items(mibs_dir, corpus)
    staged = [p for p in dirs + files if os.path.lexists(p + ".new")]
    if not staged:
        print("swap: nothing staged", file=sys.stderr)
        return None
    if os.path.lexists(os.path.join(corpus, "flat.new")) != os.path.lexists(os.path.join(corpus, "split.new")):
        sys.exit("swap: flat.new and split.new must be staged together")
    for p in staged:
        remove(p + ".prev")
    t0 = datetime.datetime.now().astimezone()
    done = []
    for p in staged:  # the swap itself: renames only
        if os.path.lexists(p):
            exchange(p + ".new", p)
            os.rename(p + ".new", p + ".prev")
        else:
            os.rename(p + ".new", p)
        done.append(p)
    t1 = datetime.datetime.now().astimezone()
    if not keep_prev:
        for p in staged:
            remove(p + ".prev")
    rel = [os.path.relpath(p, mibs_dir) for p in done]
    line = (f"{t0.isoformat(timespec='milliseconds')}\tswapped in {(t1 - t0).total_seconds() * 1000:.1f} ms\t"
            + " ".join(rel))
    with open(os.path.join(corpus, "swap.log"), "a") as f:
        f.write(line + "\n")
    print("swap: " + line, file=sys.stderr)
    return t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mibs-dir", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--corpus", default=None, help="default: $MIBLAB_CORPUS or MIBS_DIR/corpus")
    ap.add_argument("--no-prev", action="store_true", help="delete the previous versions after the swap")
    a = ap.parse_args()
    swap(os.path.abspath(a.mibs_dir), keep_prev=not a.no_prev, corpus=a.corpus and os.path.abspath(a.corpus))


if __name__ == "__main__":
    main()
