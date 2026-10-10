#!/usr/bin/env python3
"""Persistent pysmi worker (runs inside actsnmp-mibs:1, driven by run.py).

    pysmi_worker.py MODE FLATDIR OUTDIR

Reads one module name per line on stdin, writes one JSON result line per
module on stdout. MODE:

  relaxed  = `mibdump --destination-format json --generate-mib-texts M`
             (SmiV1CompatParser = smi_v1_relaxed grammar options, config.STRICT_MODE off)
  strict   = the same with `mibdump --strict` (config.STRICT_MODE on), except
             that the SMI base modules are processed non-strictly (they fail
             pysmi's own strict checks; see compile_one)
  dialect  = parse-only probe of the module's own text (no imports): which
             pysmi grammar options does it need? pysmi's lark grammar is the
             same for all options; the options are checked while building
             the AST, so the tree is parsed once and transformed with
             growing option sets, starting from the SMIv2 set {}.

relaxed/strict compile with noDeps (imports are parsed for their symbols but
only M itself is generated), ignoreErrors (M is generated even if some module
in its import closure failed; "deps" lists those), no borrowers, no stubs
(so SNMPv2-SMI, RFC1213-MIB, ... are generated too), sources = FLATDIR only.
The generated JSON goes to OUTDIR/json/M.json with the volatile meta.comments
(timestamp, host, user, python version) removed.
"""

import collections
import copy
import hashlib
import json
import os
import sys
import time
import traceback

from pysmi import config, error
from pysmi.codegen.jsondoc import JsonCodeGen
from pysmi.compiler import MibCompiler
from pysmi.parser import lark_parser
from pysmi.parser.dialect import smi_v1_relaxed
from pysmi.parser.smi import parserFactory
from pysmi.reader.localfile import FileReader
from pysmi.writer.callback import CallbackWriter

try:
    from lark.exceptions import UnexpectedCharacters, UnexpectedEOF, UnexpectedInput, UnexpectedToken, VisitError
except ImportError:  # pragma: no cover
    UnexpectedInput = Exception

MODE, FLAT, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
config.STRICT_MODE = MODE == "strict"
PARSER = parserFactory(**smi_v1_relaxed)()  # what mibdump uses in both modes

# pysmi re-parses every imported module for every compile; memoize the parse
# (keyed by the text, deep-copied out so a mutating code generator cannot leak
# state between modules). MIBLAB_PARSE_CACHE=0 disables it.
_PARSE_CACHE = collections.OrderedDict()
_parse_uncached = PARSER.parse


def _parse_cached(data, **kwargs):
    key = hashlib.sha1(data.encode("utf-8", "surrogatepass")).digest()
    hit = _PARSE_CACHE.get(key)
    if hit is None:
        hit = _parse_uncached(data, **kwargs)
        _PARSE_CACHE[key] = hit
        if len(_PARSE_CACHE) > 400:
            _PARSE_CACHE.popitem(last=False)
    else:
        _PARSE_CACHE.move_to_end(key)
    return copy.deepcopy(hit)


if os.environ.get("MIBLAB_PARSE_CACHE", "1") != "0":
    PARSER.parse = _parse_cached

BASE_MIBS = set(JsonCodeGen.baseMibs)  # RFC1155-SMI, RFC-1212, SNMPv2-SMI, SNMPv2-TC, ...

OPTIONS = ["supportSmiV1Keywords", "supportIndex", "commaAtTheEndOfImport", "commaAtTheEndOfSequence",
           "mixOfCommasAndSpaces", "uppercaseIdentifier", "lowcaseIdentifier",
           "curlyBracesAroundEnterpriseInTrap", "noCells"]


def read_text(name):
    with open(os.path.join(FLAT, name), "rb") as f:
        return f.read().decode("utf-8", "ignore")  # as pysmi's FileReader does


def lark_detail(text):
    """Re-run the lark parse to get token-level detail for a grammar error."""
    data = lark_parser._normalize_legacy_lexer_skips(text)
    try:
        PARSER.parser.parse(data)
    except UnexpectedInput as exc:
        d = {"lark": type(exc).__name__, "line": getattr(exc, "line", None),
             "column": getattr(exc, "column", None)}
        if isinstance(exc, UnexpectedToken):
            d["token_type"] = exc.token.type
            d["token"] = str(exc.token)[:80]
            d["expected"] = sorted(exc.expected)[:12]
        elif isinstance(exc, UnexpectedCharacters):
            d["char"] = exc.char
            d["expected"] = sorted(getattr(exc, "allowed", None) or [])[:12]
        elif isinstance(exc, UnexpectedEOF):
            d["expected"] = sorted(exc.expected)[:12]
        ln = d.get("line")
        if isinstance(ln, int) and ln > 0:
            lines = data.split("\n")
            if ln <= len(lines):
                d["source_line"] = lines[ln - 1].strip()[:200]
        return d
    except Exception as exc:  # parse ok: error came from the transformer
        return {"lark": "ok", "note": f"{type(exc).__name__}: {str(exc)[:200]}"}
    return {"lark": "ok"}


def err_dict(exc):
    if exc is None:
        return None
    d = {"type": type(exc).__name__, "msg": str(getattr(exc, "msg", exc))[:500]}
    ln = getattr(exc, "lineno", None)
    if ln not in (None, "?"):
        d["lineno"] = ln
    return d


def compile_one(name):
    out = {}

    def cb(mibname, data, ctx):
        out[mibname] = data

    comp = MibCompiler(PARSER, JsonCodeGen(), CallbackWriter(cb))
    # recursive=False: FLAT has no subdirectories; the default re-lists the
    # 14k-entry directory for every lookup
    comp.add_sources(FileReader(FLAT, recursive=False))
    if MODE == "strict":
        # The SMI base modules themselves fail pysmi's strict checks (e.g.
        # "Duplicate symbol found: Integer32 at MIB SNMPv2-SMI"), which would
        # fail every module importing them; mibdump hides this by borrowing
        # precompiled base modules from mibs.pysnmp.com. Process the base
        # modules non-strictly, everything else strictly.
        for attr in ("_symbolgen", "_codegen"):
            gen = getattr(comp, attr)

            def wrapped(mibTree, *args, _orig=gen.gen_code, **kwargs):
                config.STRICT_MODE = mibTree[0] not in BASE_MIBS
                try:
                    return _orig(mibTree, *args, **kwargs)
                finally:
                    config.STRICT_MODE = True

            gen.gen_code = wrapped
    # ignoreErrors: still emit M when some module in its import closure failed
    # (without it pysmi reports M "unprocessed" even if M never uses that
    # module's symbols; if M does need them, M itself fails).
    processed = comp.compile(name, noDeps=True, rebuild=True, genTexts=True, ignoreErrors=True)
    st = processed.get(name)
    res = {"status": str(st) if st is not None else "absent"}
    if st is not None and getattr(st, "error", None) is not None:
        res["error"] = err_dict(st.error)
    deps = {}
    for k, v in processed.items():
        if k == name:
            continue
        if str(v) in ("failed", "missing", "unprocessed"):
            deps[k] = {"status": str(v)}
            if getattr(v, "error", None) is not None:
                deps[k]["error"] = err_dict(v.error)
    if deps:
        res["deps"] = deps
    res["n_deps"] = len(processed) - 1
    if res["status"] == "failed" and isinstance(st.error, error.PySmiLexerError) \
            and "Bad grammar" in res["error"]["msg"] and f"at MIB {name}" in res["error"]["msg"]:
        try:
            res["detail"] = lark_detail(read_text(name))
        except Exception as exc:
            res["detail"] = {"lark": "error", "note": str(exc)[:200]}
    if name in out:
        doc = json.loads(out[name])
        meta = doc.get("meta")
        if isinstance(meta, dict):
            meta.pop("comments", None)
        res["n_symbols"] = sum(1 for k in doc if k not in ("meta", "imports"))
        os.makedirs(os.path.join(OUT, "json"), exist_ok=True)
        tmp = os.path.join(OUT, "json", name + ".json.tmp")
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        os.replace(tmp, os.path.join(OUT, "json", name + ".json"))
    return res


def dialect_one(name):
    text = read_text(name)
    data = lark_parser._normalize_legacy_lexer_skips(text)
    try:
        tree = PARSER.parser.parse(data)
    except UnexpectedInput:
        return {"status": "grammar-error", "detail": lark_detail(text)}
    opts = set()
    tried = []
    while True:
        tr = lark_parser._BootstrapAstBuilder({o: True for o in opts})
        try:
            tr.transform(tree)
            break
        except VisitError as exc:
            e = exc.orig_exc
        except error.PySmiError as exc:
            e = exc
        msg = str(getattr(e, "msg", e))
        need = [o for o in OPTIONS if f"require {o} option" in msg or f"requires {o} option" in msg]
        if not need or need[0] in opts or len(tried) > 12:
            return {"status": "ast-error", "options": sorted(opts), "error": err_dict(e)}
        tried.append(need[0])
        opts.add(need[0])
    v1 = {"supportSmiV1Keywords", "supportIndex"}
    relax = sorted(opts - v1)
    if relax:
        dialect = "relaxed"
    elif opts:
        dialect = "smiv1"
    else:
        dialect = "smiv2"
    return {"status": "ok", "dialect": dialect, "options": sorted(opts), "relaxations": relax}


def main():
    fn = dialect_one if MODE == "dialect" else compile_one
    for line in sys.stdin:
        name = line.strip()
        if not name:
            continue
        t0 = time.monotonic()
        try:
            res = fn(name)
        except MemoryError:
            res = {"status": "crash", "error": {"type": "MemoryError", "msg": ""}}
        except RecursionError:
            res = {"status": "crash", "error": {"type": "RecursionError", "msg": ""}}
        except Exception as exc:
            res = {"status": "crash", "error": {"type": type(exc).__name__, "msg": str(exc)[:500],
                                                "trace": traceback.format_exc()[-1500:]}}
        res["module"] = name
        res["elapsed"] = round(time.monotonic() - t0, 3)
        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
