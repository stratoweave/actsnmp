#!/usr/bin/env python3
"""Check that mibmeta's value conversion agrees with the YANG type of each data and notification
leaf: the SNMP adapter converts a varbind by `syntax.conv`, and acton-yang
validates the result against the leaf's YANG type, so the two must name the same value space.

    python3 interop/mibs/compare/yang_conv_check.py DIR [--ietf DIR] [--show N]

DIR holds `<MOD>.yang` and `<MOD>.mibmeta.json` (``MIBYANG_META=1`` runs of mib.test_yang's
yang_corpus, or yang_golden output). Every leaf with ``smiv2:oid`` (data nodes and notification
leafs) is matched to its mibmeta node by module and OID; its type is followed through typedefs
(also of ietf-yang-types, ietf-inet-types and ietf-yang-smiv2 in ``--ietf``) to the built-in
type, and the conversion must fit:

    truthvalue -> boolean          enum -> enumeration       bits -> bits
    int, int-hint -> int32/int64 (int also an unsigned type: Dscp, IPv6FlowLabel, §7.4)
    uint -> uint8..uint64          ipv4 -> inet:ipv4-address
    oid -> yang:object-identifier-128                        opaque -> smiv2:opaque
    phys-address -> yang:phys-address   mac-address -> yang:mac-address
    string-hint -> string (other than the named string types above)
    binary -> binary (not smiv2:opaque)

Prints the mismatches (exit status 1 when there are any).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yang_vs_libsmi as yl  # noqa: E402

IETF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../yang-examples/yang-ietf")

BUILTIN = {"binary", "bits", "boolean", "decimal64", "empty", "enumeration", "identityref",
           "instance-identifier", "int8", "int16", "int32", "int64", "leafref", "string",
           "uint8", "uint16", "uint32", "uint64", "union"}

NAMED = {"ietf-inet-types:ipv4-address": "ipv4", "ietf-yang-types:object-identifier-128": "oid",
         "ietf-yang-smiv2:opaque": "opaque", "ietf-yang-types:phys-address": "phys-address",
         "ietf-yang-types:mac-address": "mac-address"}


def load_dir(d, out):
    for f in sorted(os.listdir(d)):
        if f.endswith(".yang"):
            try:
                m = yl.load(os.path.join(d, f))
            except Exception as e:  # noqa: BLE001
                print("PARSE %s: %s" % (f, e))
                continue
            name = m.arg.split("@")[0]
            out[name] = m


def typedefs(mods):
    td = {}
    for name, m in mods.items():
        for t in m.findall("typedef"):
            td[name + ":" + t.arg] = t
    return td


def chain(mod, tstmt, td):
    """(built-in type, list of named types) of a `type` statement in module `mod`."""
    names = []
    cur_mod = mod
    t = tstmt
    for _ in range(64):
        a = t.arg
        if ":" not in a and a in BUILTIN:
            return a, names
        q = a if ":" in a else cur_mod + ":" + a
        names.append(q)
        d = td.get(q)
        if d is None:
            return "?" + q, names
        cur_mod = q.split(":")[0]
        t = d.find("type")
        if t is None:
            return "?", names
    return "?loop", names


def fits(conv, builtin, names):
    named = [NAMED[n] for n in names if n in NAMED]
    if conv == "truthvalue":
        return builtin == "boolean"
    if conv == "enum":
        return builtin == "enumeration"
    if conv == "bits":
        return builtin == "bits"
    if conv == "int":
        return builtin in ("int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64")
    if conv == "int-hint":
        return builtin in ("int32", "int64")
    if conv == "uint":
        return builtin in ("uint8", "uint16", "uint32", "uint64")
    if conv in ("ipv4", "oid", "opaque", "phys-address", "mac-address"):
        return conv in named
    if conv == "string-hint":
        return builtin == "string" and len(named) == 0
    if conv == "binary":
        return builtin == "binary" and "opaque" not in named
    return False


def leafs(s, acc):
    for c in s.subs:
        if c.kw == "leaf":
            o = c.find("smiv2:oid")
            t = c.find("type")
            if o is not None and t is not None:
                acc.append((c, t, o.arg))
        else:
            leafs(c, acc)


def main():
    args = sys.argv[1:]
    show = 40
    ietf = IETF
    d = None
    i = 0
    while i < len(args):
        if args[i] == "--show":
            show = int(args[i + 1])
            i += 2
        elif args[i] == "--ietf":
            ietf = args[i + 1]
            i += 2
        else:
            d = args[i]
            i += 1
    if d is None:
        print(__doc__)
        return 2
    mods = {}
    load_dir(ietf, mods)
    load_dir(d, mods)
    td = typedefs(mods)
    bad = []
    n = 0
    conv = {}  # (module, oid) -> [(name, conv or None, yang path)]
    for name in sorted(mods):
        jp = os.path.join(d, name + ".mibmeta.json")
        if not os.path.exists(jp):
            continue
        with open(jp, encoding="utf-8") as f:
            mm = json.load(f)
        for nd in mm.get("nodes", []):
            sx = nd.get("syntax")
            cv = sx.get("conv", "") if sx is not None and nd.get("kind") in ("scalar", "column") else None
            conv.setdefault((name, nd["oid"]), []).append((nd["name"], cv, nd.get("yang", "")))
    for name in sorted(mods):
        if not os.path.exists(os.path.join(d, name + ".mibmeta.json")):
            continue
        imports = [im.arg for im in mods[name].findall("import")]
        acc = []
        leafs(mods[name], acc)
        for leaf, t, oid in acc:
            # the module's own node at the OID, else (a notification leaf of an imported object)
            # an imported module's; a MIB may register two objects at one OID: match the name
            cs = conv.get((name, oid))
            if cs is None:
                cs = []
                for im in imports:
                    cs.extend(conv.get((im, oid), []))
            same = [x for x in cs if x[0] == leaf.arg or x[2].endswith(":" + leaf.arg)]
            if len(same) == 0:
                same = cs
            if len(same) == 0 or same[0][1] is None:
                continue  # no mibmeta syntax (an unresolved type: a placeholder string leaf)
            c = same[0]
            n += 1
            b, names = chain(name, t, td)
            if not fits(c[1], b, names):
                bad.append("%s %s (%s): conv %s, YANG %s via %s" % (name, c[0], oid, c[1], b, " ".join(names) or "-"))
    print("leafs checked %d, mismatches %d" % (n, len(bad)))
    for x in bad[:show]:
        print("MISMATCH " + x)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
