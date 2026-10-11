# actsnmp

actsnmp is an SNMP implementation for [Acton](https://www.acton-lang.org),
written in Acton. The Acton package name is `snmp`.

## Features

- **Protocol:** SNMPv1, SNMPv2c and SNMPv3 with the User-based Security
  Model.
  - Authentication: HMAC-MD5, HMAC-SHA-1 and HMAC-SHA-224/256/384/512.
  - Privacy: DES, 3DES, AES-128 and AES-192/256. AES-192/256 comes in both
    key-extension variants, net-snmp's `AES-192`/`AES-256` and the
    "Cisco" `AES-192-C`/`AES-256-C`.
  - The cryptographic primitives come from the mbedtls that ships with the
    Acton toolchain.
- **Client (manager):**
  - get, getnext, getbulk and set;
  - walks using GETNEXT or GETBULK, streaming walks, and tables;
  - sending traps and informs;
  - per-request timeouts and retries, SNMPv3 engine discovery, IPv4 and
    IPv6.
- **Notification receiver:** SNMPv1/v2c traps, SNMPv2c informs, and SNMPv3
  traps and informs.
- **Agent:** a small command responder that serves values from an
  snmpsim-style `.snmprec` file. It is useful for tests.
- **Command-line tool:** `actsnmp` takes net-snmp-style options and prints
  net-snmp-style output.
- **MIB compiler:** parses SMIv1/SMIv2 MIB modules, resolves them, and
  emits JSON metadata with OIDs, types, enumerations, display hints and
  table index encodings.

## Building

```bash
acton build
```

This builds the library and the command-line tool, `out/bin/actsnmp`.

```bash
acton test
```

`acton test` runs the unit, actor and loopback tests.

## Using the library

Add actsnmp as a dependency in your project's `Build.act`:

```python
dependencies = {
    "snmp": (path="../actsnmp")
}
```

All operations are asynchronous. Results arrive through a callback, which
is called exactly once per request.

### Walk a subtree (SNMPv2c)

```python
import net
import snmp.client
import snmp.errors
import snmp.fmt
import snmp.oid
import snmp.security
import snmp.values

actor main(env):
    cap = net.UDPConnectCap(net.UDPCap(net.NetCap(env.cap)))
    c = snmp.client.Client(cap, "192.0.2.1", snmp.security.Community("public"), None)

    def walked(cl: snmp.client.Client, vbs: list[snmp.values.VarBind], err: ?snmp.errors.SnmpError):
        for vb in vbs:
            print(snmp.fmt.netsnmp_varbind(vb))
        if err is not None:
            print("error:", err.error_message)
        cl.close()
        env.exit(0 if err is None else 1)

    c.walk(walked, snmp.oid.Oid.parse("1.3.6.1.2.1.1"))
```

### SNMPv3

For SNMPv3, pass USM credentials instead of a community:

```python
    sec = snmp.security.Usm.from_passwords("admin", snmp.usm.AUTH_SHA256, "authpass123",
                                           snmp.usm.PRIV_AES128, "privpass123")
    c = snmp.client.Client(cap, "192.0.2.1", sec, None)
```

The client discovers the agent's engine ID and time on first use. The
security protocols are the `snmp.usm.AUTH_*` and `snmp.usm.PRIV_*`
constants.

Turning a password into a key costs a megabyte of hashing, so create one
`Usm` per set of credentials and share it between clients.
`Usm.with_context()` returns the same credentials for another context, and
`Options(context_name=...)` sets the context of a single request.

### Errors

A failed request passes an `snmp.errors.SnmpError` to the callback. Its
`transient` attribute is true when the same request may succeed if it is
tried again later on the same client, for example after a timeout.

### Many devices

Each client has its own UDP socket, so a process that polls many devices
needs one file descriptor per device. Raise the process's limit on open
files for large fleets.

## Command-line tool

`actsnmp` accepts net-snmp's options, for example `-v`, `-c`, `-u`, `-l`,
`-a`, `-A`, `-x`, `-X`, `-t`, `-r`, `-O...` and `-C...`. `actsnmp COMMAND -h`
lists the options of a command.

```bash
out/bin/actsnmp get -v2c -c public 192.0.2.1 1.3.6.1.2.1.1.1.0
```

```bash
out/bin/actsnmp bulkwalk -v3 -u admin -l authPriv -a SHA-256 -A authpass123 -x AES -X privpass123 192.0.2.1 1.3.6.1.2.1.2
```

```bash
out/bin/actsnmp set -v2c -c private 192.0.2.1 1.3.6.1.2.1.1.6.0 s "server room"
```

```bash
out/bin/actsnmp trap -v2c -c public 192.0.2.10 '' 1.3.6.1.6.3.1.1.5.4 1.3.6.1.2.1.2.2.1.1.2 i 2
```

```bash
out/bin/actsnmp trapd --port 1162
```

```bash
out/bin/actsnmp agent --snmprec data.snmprec --port 1161
```

The commands are `get`, `getnext`, `bulkget`, `walk`, `bulkwalk`, `set`,
`table`, `trap`, `inform`, `trapd` and `agent`.

## Interoperability testing

`interop/` holds a Docker-based lab with net-snmp and snmpsim/pysnmp
agents, managers and trap receivers. It serves a shared deterministic
dataset and has SNMPv3 users for every supported protocol combination.

```bash
interop/run-interop.sh
```

`interop/run-interop.sh` builds the lab, runs the library and the command-line
tool against the reference implementations in both directions, compares
output with net-snmp's, and writes a summary to
`interop/results/LATEST.md`.

Each check can also be run on its own while the lab is up (`interop/up.sh`
starts it, `interop/down.sh` stops it):

- `src/test_interop.act`, the tests tagged `interop`, runs the library
  against snmpd, snmpsim and snmptrapd;
- `interop/clicheck.sh` runs `actsnmp` and net-snmp's tools side by side
  and compares their output;
- `interop/agentcheck.sh` runs net-snmp's and pysnmp's managers against
  `actsnmp agent`;
- `interop/notifycheck.sh` sends traps and informs from net-snmp and pysnmp
  to `actsnmp trapd`;
- `interop/trapdcheck.sh` checks what net-snmp's snmptrapd received from
  actsnmp as the sender.

See `interop/README.md` for ports, users and options.

`interop/mibs/` holds a MIB corpus and oracle setup for testing the MIB
compiler against pysmi, net-snmp and libsmi; see `interop/mibs/README.md`.
