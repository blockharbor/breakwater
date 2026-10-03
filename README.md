# Breakwater

Breakwater runs security audits against automotive CAN and network interfaces
and discovers targets on CAN buses, through a single command-line tool,
`bw_cli`.

- 22 built-in audits: UDS (security access, memory read/write, upload/download,
  IO and communication control), CCP and XCP (upload, download, program), CAN
  bus DoS recovery, and network checks (TLS versions and ciphers, mTLS with a
  self-signed certificate, SSH password login, telnet anonymous login).
- Discovery of UDS servers (sessions, services, DIDs) and XCP slaves over
  SocketCAN, including CAN FD.
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
sudo apt install ./build/dist/deb/breakwater_<version>_all.deb
```

The `.deb` pulls python-can, pyroute2, pyserial, paramiko and requests from
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
bw_cli run uds_security_access -p device=can0 -p req_arb=0x7e0 -p resp_arb=0x7e8
bw_cli run telnet_check -p target_host=10.1.0.1 --report
```

From a checkout, use `./bw_cli.py` in place of `bw_cli`.

`run` prints the audit's raw result as JSON on stdout (or the formatted report
with `--report`); progress goes to stderr. Parameters you don't set take the
defaults shown by `bw_cli info`.

| Exit code | Meaning |
|-----------|---------|
| 0 | passed, or the command succeeded |
| 1 | failed: the target is vulnerable |
| 2 | no result: the target was unreachable or a parameter was bad |
| 64 | usage error |
| 69 | missing dependencies |

### Audit dependencies

Each audit lists the Python packages it needs. If one is missing, `run` stops
with exit code 69 and says which. Add `--install-deps` to install it into
Breakwater's own directory, `~/.local/share/breakwater/lib/python3.X` (set
`BW_HOME` to move it). Breakwater never installs into the Python environment
it runs from. `bw_cli deps` shows the directory and what each audit needs;
`bw_cli deps --clean` deletes it.

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
