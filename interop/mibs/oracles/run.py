#!/usr/bin/env python3
"""Run one oracle over the de-duplicated corpus (inside actsnmp-mibs:1).

    run.py ORACLE... [--jobs N] [--budget SEC] [--timeout SEC] [--modules M,M,...]
           [--modules-file FILE] [--redo]

ORACLE: pysmi-relaxed | pysmi-strict | pysmi-dialect | netsnmp | smilint
(several: run one after the other, sharing the budget)

Mounts (see oracles.sh): /lab = interop/mibs (ro), /corpus = corpus (ro),
/cache = cache (rw). Module list: /corpus/index/modules.tsv (largest first).

Resumable: a module is done when /cache/ORACLE/status/<M>.json exists.
Stops submitting new modules after --budget seconds (in-flight ones finish,
each bounded by --timeout), so one invocation fits in one bench-lock hold.
Exit status: 0 = all modules done, 3 = budget exhausted, modules remain.

Outputs per module:
  pysmi-*:  status/<M>.json  {"module","status","error","deps","detail",...}
            json/<M>.json    the pysmi JSON document (relaxed/strict)
  netsnmp:  status/<M>.json  {"module","loaded","nodes","stderr":[...]}
            out/<M>.jsonl    mibwalk output (nodes defined by M)
  smilint:  status/<M>.json  {"module","rc","lines":[...]}
"""

import argparse
import json
import os
import queue
import re
import resource
import select
import subprocess
import sys
import threading
import time

FLAT = "/corpus/flat"
CACHE = "/cache"
LAB = "/lab"
MEM_LIMIT = 6 << 30
SMILINT_RE = re.compile(r"^([^:]+):\d+: \[(\d)\] \{([^}]+)\} ")


def limit_mem():
    resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, MEM_LIMIT))


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


class PysmiChild:
    """A persistent pysmi_worker.py process; restarted after a timeout/crash."""

    def __init__(self, mode, outdir, logf):
        self.mode, self.outdir, self.logf = mode, outdir, logf
        self.p = None

    def start(self):
        self.p = subprocess.Popen(
            [sys.executable, os.path.join(LAB, "oracles", "pysmi_worker.py"), self.mode, FLAT, self.outdir],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.logf, preexec_fn=limit_mem)
        self.buf = b""

    def kill(self):
        if self.p:
            self.p.kill()
            self.p.wait()
            self.p = None

    def run(self, module, timeout):
        if self.p is None:
            self.start()
        try:
            self.p.stdin.write((module + "\n").encode())
            self.p.stdin.flush()
        except BrokenPipeError:
            self.kill()
            return {"status": "crash", "error": {"type": "BrokenPipe", "msg": "worker died"}}
        deadline = time.monotonic() + timeout
        fd = self.p.stdout.fileno()
        while b"\n" not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0:
                self.kill()
                return {"status": "timeout", "error": {"type": "Timeout", "msg": f"> {timeout} s"}}
            r, _, _ = select.select([fd], [], [], left)
            if r:
                chunk = os.read(fd, 65536)
                if not chunk:
                    rc = self.p.wait()
                    self.p = None
                    return {"status": "crash", "error": {"type": "WorkerExit", "msg": f"exit status {rc}"}}
                self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)


MIBWALK = "/tmp/mibwalk"


def build_mibwalk():
    """Compile the bind-mounted mibwalk.c (so changes need no image rebuild)."""
    cflags = subprocess.run(["net-snmp-config", "--libs"], stdout=subprocess.PIPE, text=True).stdout.split()
    subprocess.run(["gcc", "-O2", "-Wall", "-o", MIBWALK, os.path.join(LAB, "docker", "mibwalk.c")] + cflags,
                   check=True)


def run_netsnmp(module, timeout, outdir):
    out = os.path.join(outdir, "out", module + ".jsonl")
    try:
        with open(out + ".tmp", "wb") as fo:
            p = subprocess.run([MIBWALK, "-M", FLAT, module], stdout=fo, stderr=subprocess.PIPE,
                               timeout=timeout, preexec_fn=limit_mem)
        err = p.stderr.decode("latin-1").splitlines()
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    loaded = None
    nodes = 0
    with open(out + ".tmp", "rb") as f:
        lines = f.read().splitlines()
    if lines and lines[-1].startswith(b'{"_loaded"'):
        loaded = json.loads(lines[-1])["_loaded"].get(module)
        nodes = len(lines) - 1
    os.replace(out + ".tmp", out)
    if len(err) > 400:
        err = err[:400] + [f"... {len(err) - 400} more lines"]
    return {"status": "ok" if rc == 0 else f"rc{rc}", "loaded": loaded, "nodes": nodes, "stderr": err}


def run_smilint(module, timeout, outdir):
    env = dict(os.environ, SMIPATH=FLAT)
    try:
        p = subprocess.run(["smilint", "-c", "/dev/null", "-l", "9", "-s", "-m", module],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                           env=env, preexec_fn=limit_mem)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    lines = p.stdout.decode("latin-1").splitlines()
    # complete per-file counts (the raw lines are capped)
    counts = {}
    for l in lines:
        m = SMILINT_RE.match(l)
        if m:
            k = f"{os.path.basename(m.group(1))}|{m.group(2)}|{m.group(3)}"
            counts[k] = counts.get(k, 0) + 1
    if len(lines) > 2000:
        lines = lines[:2000] + [f"... {len(lines) - 2000} more lines"]
    return {"status": "ok" if p.returncode >= 0 else "crash", "rc": p.returncode, "lines": lines,
            "counts": counts}


def run_oracle(oracle, a, t0, sizes):
    outdir = os.path.join(CACHE, oracle)
    sdir = os.path.join(outdir, "status")
    os.makedirs(sdir, exist_ok=True)
    os.makedirs(os.path.join(outdir, "out"), exist_ok=True)
    if a.modules:
        mods = [m for m in a.modules.split(",") if m]
    elif a.modules_file:
        with open(a.modules_file) as f:
            mods = sorted({l.strip() for l in f if l.strip() and l.strip() in sizes}, key=lambda m: (-sizes[m], m))
    else:
        mods = sorted(sizes, key=lambda m: (-sizes[m], m))
    todo = [m for m in mods if a.redo or not os.path.exists(os.path.join(sdir, m + ".json"))]
    print(f"[{oracle}] {len(mods)} modules, {len(todo)} to do, jobs {a.jobs}, "
          f"{a.budget - (time.monotonic() - t0):.0f} s of budget left", file=sys.stderr, flush=True)
    if not todo:
        return 0
    if oracle == "netsnmp":
        build_mibwalk()
    q = queue.Queue()
    for m in todo:
        q.put(m)
    t1 = time.monotonic()
    done = [0]
    lock = threading.Lock()
    logf = open(os.path.join(outdir, "worker.log"), "ab")

    def worker():
        child = PysmiChild(oracle.split("-", 1)[1], outdir, logf) if oracle.startswith("pysmi") else None
        try:
            while time.monotonic() - t0 < a.budget:
                try:
                    m = q.get_nowait()
                except queue.Empty:
                    break
                ts = time.monotonic()
                if child:
                    res = child.run(m, a.timeout)
                elif oracle == "netsnmp":
                    res = run_netsnmp(m, a.timeout, outdir)
                else:
                    res = run_smilint(m, a.timeout, outdir)
                res["module"] = m
                res.setdefault("elapsed", round(time.monotonic() - ts, 3))
                write_json(os.path.join(sdir, m + ".json"), res)
                with lock:
                    done[0] += 1
                    if done[0] % 500 == 0:
                        print(f"[{oracle}] {done[0]}/{len(todo)} in {time.monotonic() - t1:.0f} s",
                              file=sys.stderr, flush=True)
        finally:
            if child:
                child.kill()

    threads = [threading.Thread(target=worker) for _ in range(a.jobs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    left = q.qsize()
    print(f"[{oracle}] did {done[0]} in {time.monotonic() - t1:.0f} s, {left} left", file=sys.stderr, flush=True)
    return left


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("oracles", nargs="+",
                    choices=["pysmi-relaxed", "pysmi-strict", "pysmi-dialect", "netsnmp", "smilint"])
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) * 3 // 4))
    ap.add_argument("--budget", type=float, default=600)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--modules", default="")
    ap.add_argument("--modules-file", default="", help="file with one module name per line (only these)")
    ap.add_argument("--redo", action="store_true", help="ignore existing status files")
    a = ap.parse_args()
    sizes = {}
    with open("/corpus/index/modules.tsv") as f:
        hdr = f.readline().rstrip("\n").split("\t")
        for line in f:
            r = dict(zip(hdr, line.rstrip("\n").split("\t")))
            sizes[r["module"]] = int(r["size"])
    t0 = time.monotonic()
    left = 0
    for o in a.oracles:
        if time.monotonic() - t0 >= a.budget:
            left += 1
            continue
        left += run_oracle(o, a, t0, sizes)
    return 3 if left else 0


if __name__ == "__main__":
    sys.exit(main())
