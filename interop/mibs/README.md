# MIB corpus and oracles

Differential testing for the actsnmp MIB compiler. This directory holds:

* a pinned, reproducible corpus of about 20,000 real-world MIB files from
  net-snmp, the IETF/IANA set, LibreNMS, mibs.pysnmp.com and the official
  Cisco, Juniper and Nokia distributions, de-duplicated by module name;
* three independent oracles run over every module: pysmi 2.0.0, net-snmp
  5.9.4's MIB parser and libsmi 0.4.8 `smilint`;
* committed summaries of the results (`modules.tsv`, `duplicates.tsv`,
  `vendors.tsv`);
* a golden set (`golden/`) of 96 modules with their expected oracle outputs,
  small enough for unit tests;
* a script in `compare/` that checks the compiler's parse results against
  the oracles.

None of this is a dependency of the library. The corpus (`corpus/`, about
1.4 GB) and the oracle outputs (`cache/`, 2 to 3 GB) are not committed.

## Running it

```
interop/mibs/fetch.sh            # fetch and verify the corpus, then index it
interop/mibs/build.sh            # build the oracle image actsnmp-mibs:1
interop/mibs/oracles.sh          # run all oracles over corpus/flat (resumable)
python3 interop/mibs/report.py   # write modules.tsv and cache/report/REPORT.md
interop/mibs/golden.sh --check   # re-run the oracles on golden/ and diff
```

A full run from scratch takes about 20 minutes with 28 jobs. After a
re-index, `oracles.sh --incremental` only runs new or changed modules and
their importers. `oracles.sh --whole` adds net-snmp's view of the whole corpus
loaded at once (`snmptranslate -m ALL`).

To update a corpus that others are reading without exposing a half-built
state, stage everything and publish it in one step:

```
interop/mibs/fetch.sh --no-swap                      # writes corpus/{flat,split,index}.new, *.tsv.new
MIBLAB_STAGE=1 interop/mibs/oracles.sh --incremental
python3 interop/mibs/report.py --stage
python3 interop/mibs/swap.py                         # atomic exchange; old versions kept as *.prev
```

Every CPU-heavy step runs under the shared bench lock (`lib.sh: locked`).
The oracle runner works in chunks of one `docker run` per lock hold, so a
hold stays under 15 minutes, and results are written per module.
`oracles.sh` and `golden.sh` refuse to run between 22:00 and 07:00.

| Variable | Default | Meaning |
|---|---|---|
| `MIBLAB_LOCK` | `~/gcperf/lock100/bench.lock` | lock file; `none` disables locking |
| `MIBLAB_JOBS` | 28 | parallel oracle workers |
| `MIBLAB_BUDGET` | 690 | seconds of new work per lock hold |
| `MIBLAB_TIMEOUT` | 150 | seconds per module and oracle |
| `MIBLAB_NIGHT` | 0 | 1 allows runs at night |
| `MIBLAB_NOKIA_DIR` | `~/para/resources` | directory with the Nokia SR OS archives of `pins/nokia.tsv` |

## Corpus

| Source | Type | Pin |
|---|---|---|
| `netsnmp` | official for `NET-SNMP-*`, `UCD-*` | git tag v5.9.4 |
| `ietf`, `iana` | standards | sha256 manifest `pins/ietf-iana.sha256` (Ubuntu `snmp-mibs-downloader` in the interop image) |
| `librenms` | aggregator | git tag 26.9.1 |
| `cisco-v2`, `cisco-v1` | official for `CISCO-*` (v2 only) | git commit of cisco/cisco-mibs |
| `pysnmp` | aggregator | git commit of lextudio/mibs.pysnmp.com |
| `juniper`, `juniper-evo` | official for `JUNIPER-*`, `JNX-*` | download URL and sha256 in `pins/juniper.tsv` |
| `nokia` | official for `TIMETRA-*`, `ALCATEL-*`, `ALU-*`, `NOKIA-*` | local archives, sha256 in `pins/nokia.tsv`; optional |

The Nokia bundles are only available from Nokia's support portal. Archives
missing from `MIBLAB_NOKIA_DIR` are skipped, and without them the corpus has
no Nokia source. Older Nokia releases are indexed as history sources but
never chosen. Juniper and Nokia MIB texts must never be committed; only pins,
hashes and statistics are.

`index.py` finds modules lexically (a file may hold several), records hashes,
imports, `LAST-UPDATED` and lexical quirks, and links one winner per module
name as `corpus/flat/<NAME>`. The oracles only see `corpus/flat`. The winner
is chosen in this order:

1. an entry of the override list (`index.py: OVERRIDES`);
2. the official vendor copy of a module the vendor owns, unless a copy from
   another source has a strictly newer valid `LAST-UPDATED`. A vendor owns
   the modules in its namespace, and copies of standard modules that import
   from its namespace when no IETF/IANA module of that name exists;
3. the source rank: ietf, netsnmp, cisco-v2, librenms, the vendor bundles,
   iana, pysnmp, cisco-v1 (all `IANA*` copies rank equal, newest wins);
4. the newest `LAST-UPDATED`, the shallower path, the path name.

History sources and copies with an empty body never win. Each winner records
the rule that chose it (`reason` in `modules.tsv` and `duplicates.tsv`).
Mixing releases this way can produce import mismatches, which show up in the
oracle results.

## Oracles

The image `actsnmp-mibs:1` (`docker/Dockerfile`) has net-snmp, libsmi, pysmi
and `mibwalk` (`docker/mibwalk.c`). The oracle scripts are bind-mounted, so
editing them needs no rebuild. Each module is compiled on its own with its
imports resolved from `corpus/flat` only.

| Oracle | What runs | Output in `cache/<oracle>/` |
|---|---|---|
| `pysmi-relaxed` | pysmi like `mibdump --destination-format json` with every relaxation | `status/M.json`, `json/M.json` |
| `pysmi-strict` | the same in strict mode | same |
| `pysmi-dialect` | parse of M alone, adding relaxations only as errors require | `status/M.json` |
| `netsnmp` | `mibwalk`: net-snmp's `read_module(M)`, then every node M defines as JSON lines | `status/M.json`, `out/M.jsonl` |
| `smilint` | `smilint -l 9 -s -m M` | `status/M.json` |

In strict mode pysmi's own base modules are compiled non-strictly, since its
strict checks reject them and would fail every importer.

`report.py` classifies the results and writes `modules.tsv` (one row per
module: winner, oracle verdicts, error classes, OID agreement between pysmi
and net-snmp) and `cache/report/REPORT.md` (statistics, a ranked quirk
catalogue, top error classes with examples, vendor copy comparison). The
classification rules live in `report.py`, so they can be refined without
re-running the oracles. `duplicates.tsv` lists every instance of a module
name seen more than once and how it differs from the winner; `vendors.tsv`
counts files and winners per source.

## Golden set

`golden/select.tsv` lists the curated modules (SMI core, standard and vendor
samples, and real-world modules with known quirks). `golden.sh` adds their
import closure, runs every oracle on the set and writes `golden/golden.tsv`
and the expected outputs.

Module texts and expected outputs are split by licence:

* IETF/IANA modules and net-snmp's own MIBs are committed: texts in
  `golden/mibs/`, expected outputs in `golden/expected/`.
* IEEE and vendor modules are referenced by corpus path and sha256 only.
  Their expected outputs go to `golden/expected-local/` (ignored), which
  `golden.sh --local` regenerates from the corpus.

`golden.sh --check` re-runs the oracles and diffs both tiers; without the
corpus it checks the committed tier only. If a reference-only text no longer
matches its sha256 after a re-index, re-run `golden.sh`.

To add a module, add a row to `golden/select.tsv`, run `golden.sh`, and
review the new expected files. Make sure that only redistributable texts end
up in `golden/mibs/`.

## Comparison scripts (`compare/`)

| Script | What it checks |
|---|---|
| `parse_vs_oracles.py` | the compiler's parse status per module against pysmi, smilint and net-snmp |

It writes a Markdown report with `--out FILE`; put it under `cache/`.
