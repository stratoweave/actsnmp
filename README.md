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
- **Dispatcher:** many clients share one UDP socket, for polling large
  numbers of devices without one socket per device.
- **Notification receiver:** SNMPv1/v2c traps, SNMPv2c informs, and SNMPv3
  traps and informs.
- **Agent:** a small command responder that serves values from an
  snmpsim-style `.snmprec` file. It is useful for tests.
- **Command-line tool:** `actsnmp` takes net-snmp-style options and prints
  net-snmp-style output.
- **MIB compiler:** parses SMIv1/SMIv2 MIB modules, resolves them, and
  emits YANG modules following RFC 6643. It also emits JSON metadata with
  OIDs, types, enumerations, display hints and table index encodings.
  DISPLAY-HINT rendering and table index decoding are available at
  runtime.

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

### Get with SNMPv3

```python
import net
import snmp.client
import snmp.errors
import snmp.fmt
import snmp.oid
import snmp.security
import snmp.usm

actor main(env):
    cap = net.UDPConnectCap(net.UDPCap(net.NetCap(env.cap)))
    sec = snmp.security.Usm.from_passwords("admin", snmp.usm.AUTH_SHA256, "authpass123",
                                           snmp.usm.PRIV_AES128, "privpass123")
    c = snmp.client.Client(cap, "192.0.2.1", sec, None)

    def got(cl: snmp.client.Client, resp: ?snmp.client.Response, err: ?snmp.errors.SnmpError):
        if err is not None:
            print("error:", err.error_message)
        elif resp is not None:
            for vb in resp.varbinds:
                print(snmp.fmt.netsnmp_varbind(vb))
        cl.close()
        env.exit(0 if err is None else 1)

    c.get(got, [snmp.oid.Oid.parse("1.3.6.1.2.1.1.1.0"), snmp.oid.Oid.parse("1.3.6.1.2.1.1.5.0")])
```

The client discovers the agent's engine ID and time on first use. The
security protocols are the `snmp.usm.AUTH_*` and `snmp.usm.PRIV_*`
constants.

### Fetch a table

`get_table` walks the given columns together and groups the values into
rows by index. `row.cells` holds one value per requested column, or `None`
where the row has no value.

```python
    columns = [snmp.oid.Oid.parse("1.3.6.1.2.1.2.2.1.2"),    # ifDescr
               snmp.oid.Oid.parse("1.3.6.1.2.1.2.2.1.8")]    # ifOperStatus

    def got_table(cl: snmp.client.Client, t: ?snmp.client.Table, err: ?snmp.errors.SnmpError):
        if t is not None:
            for row in t.rows:
                print(".".join([str(a) for a in row.index]),
                      [snmp.fmt.netsnmp_value(v) if v is not None else "-" for v in row.cells])

    c.get_table(got_table, columns)
```

### Receive traps and informs

```python
import net
import snmp.fmt
import snmp.notify
import snmp.receiver
import snmp.transport

actor main(env):
    cap = net.UDPListenCap(net.UDPCap(net.NetCap(env.cap)))
    # Accepted communities, SNMPv3 users, SNMPv3 trap engine IDs (empty: any),
    # our engine ID (for SNMPv3 informs) and engine boots
    config = snmp.receiver.ReceiverConfig(["public"], [], [], bytes.from_hex("80001f8880616374736e6d7072"), 1)
    var receiver: ?snmp.receiver.NotificationReceiver = None

    def received(r: snmp.receiver.NotificationReceiver, n: snmp.notify.Notification):
        print("trap", n.trap_oid.dotted(), "from", n.source_address)
        for vb in n.payload():
            print("  " + snmp.fmt.netsnmp_varbind(vb))

    def listening(t: snmp.transport.ServerTransport, err: ?str):
        if err is not None:
            print("listen failed:", err)
            env.exit(1)
        else:
            receiver = snmp.receiver.NotificationReceiver(t, config, received, None)

    snmp.transport.udp_server_transport(cap, "0.0.0.0", 162, listening)
```

SNMPv1 traps are converted to the SNMPv2 form (RFC 3584), and informs are
acknowledged.

### Many devices on one socket

A `Dispatcher` gives each client a transport on a single shared UDP
socket:

```python
    cap = net.UDPListenCap(net.UDPCap(net.NetCap(env.cap)))

    def listening(d: snmp.dispatcher.Dispatcher, err: ?str):
        if err is None:
            for address in ["192.0.2.1", "192.0.2.2", "2001:db8::1"]:
                c = snmp.client.Client(None, address, sec, None, transport=d.attach(address, 161))
                ...

    snmp.dispatcher.udp_dispatcher(cap, "::", 0, listening)
```

Addresses given to `attach` must be IP literals.

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
`interop/results/LATEST.md`. See `interop/README.md` for details.

`interop/mibs/` holds a MIB corpus and oracle setup for testing the MIB
compiler against pysmi, net-snmp and libsmi; see `interop/mibs/README.md`.
