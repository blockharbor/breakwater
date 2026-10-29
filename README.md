# Breakwater

Breakwater runs security audits against automotive CAN and network interfaces
and discovers targets on CAN buses and IP networks, through a single command-line tool,
`bw_cli`.

- 22 built-in audits: UDS (security access, memory read/write, upload/download,
  IO and communication control), CCP and XCP (upload, download, program), CAN
  bus DoS recovery, and network checks (TLS versions and ciphers, mTLS with a
  self-signed certificate, SSH password login, telnet anonymous login).
- Discovery of UDS servers (sessions, services, DIDs) and XCP slaves over
  SocketCAN, including CAN FD, and of IP hosts and their open TCP ports on
  Ethernet and Wi-Fi, without root.
- Audit metadata as text, Markdown or JSON.

Documentation: https://docs.blockharbor.io

## Safety

Several audits are intrusive. `can_dos` floods the bus, and the `*_program`,
`*_download` and `*_write_*` audits write to ECU memory or flash. Only run
Breakwater against equipment you own or are authorised to test, on a bench
rather than a vehicle in use.

## Install

Breakwater needs Linux (SocketCAN) and Python 3.9 or newer.

From a checkout:

```bash
pip install -r requirements.txt
./bw_cli.py ls
```

As a Debian/Ubuntu package (Debian bookworm and trixie, Ubuntu noble), built
with `make package` (needs [fpm](https://fpm.readthedocs.io/)):

```bash
sudo apt install ./build/dist/deb/breakwater-cli_<version>_all.deb
```

The `breakwater-cli` package pulls python-can, pyroute2, pyserial, paramiko and requests from
the distribution. can-isotp is not packaged by any distribution, so the UDS
audits and discovery get it through pip (`--install-deps`, see below).

## Command line

```bash
bw_cli ls                                    # list audits
bw_cli info uds_security_access              # one audit's description and parameters
bw_cli info --json                           # every audit, machine-readable
bw_cli info --markdown > audits.md           # every audit as a docs page
bw_cli interfaces                            # host interfaces as JSON
bw_cli discover -p iface=can0                # UDS and XCP targets on can0
bw_cli discover -p iface=can0 -p min_did=0x0000 -p max_did=0x00FF   # read DIDs 0x0000-0x00FF instead
bw_cli discover -p iface=can0 -p protocol=xcp # XCP only (protocol=uds: UDS only)
bw_cli discover -p iface=eth0 -p protocol=ip  # hosts on eth0 (ARP sweep, IPv6 ping) and their open TCP ports
bw_cli discover -p iface=can0,eth0             # every scan that fits each interface
bw_cli run uds_security_access -p iface=can0 -p req_arb=0x7e0 -p resp_arb=0x7e8
bw_cli run telnet_check -p target_host=10.1.0.1 --json
```

From a checkout, use `./bw_cli.py` in place of `bw_cli`.

`run` prints a readable report on stdout. With `--json` it prints
`{"status": "PASSED" | "FAILED" | "NO_RESULT", "result": {...}, "report": [...]}`
instead: the audit's raw result and the same report as data. Log messages go to
stderr, so stdout holds only the report or the JSON. By default only warnings and errors are logged; `-v` adds progress and the
final verdict, `-vv` adds debug output such as the parameters and each request.
Parameters you don't set take the defaults shown by `bw_cli info`.

`discover` prints one JSON object. `_metadata` holds the layout version
(`format`), the Breakwater `version`, `started` and `finished` times (UTC), the
`params` in effect and the number of failed scans (`errors`). `interfaces` maps
each scanned interface to its description, as `bw_cli interfaces` gives it, and
its `scans` (`uds`, `xcp`, `ip`). Each scan has a `duration` in seconds and
either its `targets` or an `error`; a failed scan does not stop the others.

Every audit and `discover` name the interface `iface`. The older name `device`
is accepted as well; setting both is an error.

| Exit code | Meaning |
|-----------|---------|
| 0 | passed, or the command succeeded |
| 1 | failed: the target is vulnerable |
| 2 | no result: the target was unreachable or a parameter was bad |
| 64 | usage error |
| 69 | missing dependencies |
| 74 | `discover`: at least one scan failed |

### Audit dependencies

Each audit lists the Python packages it needs. If one is missing, `run` stops
with exit code 69 and says which. Add `--install-deps` to install it into
Breakwater's own directory, `~/.local/share/breakwater/lib/python3.X` (set
`BW_HOME` to move it). Breakwater never installs into the Python environment
it runs from. `bw_cli deps` shows the directory and what each audit needs;
`bw_cli deps --clean` deletes it.

### Custom audits

`--audit-path` loads audits from a `.py` file, or from every `.py` file in a
directory (not recursive; names starting with `_` or `.` are skipped). It works
with every command and can be repeated:

```bash
bw_cli --audit-path ./my_audits ls
bw_cli run my_audit --audit-path ./my_audits/my_audit.py -p iface=can0
```

A custom audit is written like the built-in ones in `audits/`: it imports
`framework` and registers itself with `@register_audit("name")`.

- A file that fails to import is skipped with a warning; the others still load.
- An audit name that is already loaded, built-in or custom, is a usage error
  (exit code 64), so a custom audit cannot replace a built-in one.

`bw_cli info --json` reports every audit's `source` (the file it was loaded
from) and the `sha256` of that file, so a run can be traced to the exact code.

## Tests

```bash
python3 -m tests
```

The tests simulate targets. The CAN tests need a `vcan0` interface
(`sudo ip link add dev vcan0 type vcan && sudo ip link set vcan0 up`), and
`observed_tls_version` needs packet capture rights (root or `CAP_NET_RAW`).

## License

GPL-2.0-only. See [LICENSE](LICENSE).
Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC.
