# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# End-to-end tests of `bw_cli discover`: each one puts a known target on an
# interface, runs the CLI and checks its JSON.

import os
import sys
import json
import subprocess

from tests.base import *

BW_CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bw_cli.py')

def discover(*params, wrap=(), timeout=600):
    """Run `bw_cli discover` and return its exit code and parsed JSON."""
    args = [sys.executable, BW_CLI, 'discover'] + [a for p in params for a in ('-p', p)]
    r = subprocess.run(list(wrap) + args, capture_output=True, text=True, timeout=timeout)
    try:
        out = json.loads(r.stdout)
    except ValueError:
        raise AssertionError(f'no JSON from bw_cli (exit {r.returncode}): {r.stdout}{r.stderr}')
    return r.returncode, out

def scan_of(out, iface, scan):
    assert out['_metadata']['errors'] == 0, out
    return out['interfaces'][iface]['scans'][scan]

# --- ip ---------------------------------------------------------------------

PEER_MAC = '02:00:00:00:77:02'
PEER_IPV4 = '192.168.77.2'
PEER_IPV6 = 'fe80::ff:fe00:7702'      # link-local derived from PEER_MAC
GONE_IPV4 = '192.168.77.3'            # in the neighbour cache, but no host behind it

# Builds a private network without root: a user, network and mount namespace
# (with its own /sys, so get_interfaces sees bw0 and not the host's
# interfaces), a veth pair, and a peer namespace that holds the far end and
# listens on TCP 8080. Then runs the command given as arguments.
NETNS_SETUP = f'''
set -e
mount -t sysfs sysfs /sys
sysctl -qw net.ipv6.conf.default.accept_dad=0
ip link set lo up
unshare -n "$PY" -c 'import socket, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", 8080))
s.listen()
time.sleep(600)' >/dev/null 2>&1 &
PEER=$!
trap 'kill $PEER' EXIT
# Wait until the peer process has its own network namespace
while [ "$(readlink /proc/$PEER/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do :; done
ip link add bw0 type veth peer name bwpeer address {PEER_MAC}
ip link set bwpeer netns $PEER
nsenter -t $PEER -n sh -c 'sysctl -qw net.ipv6.conf.bwpeer.accept_dad=0
  ip link set lo up; ip addr add {PEER_IPV4}/24 dev bwpeer; ip link set bwpeer up'
ip addr add 192.168.77.1/24 dev bw0
ip link set bw0 up
ip neigh add {GONE_IPV4} lladdr 02:00:00:00:77:03 dev bw0 nud stale
"$@"
'''

def discover_ip():
    wrap = ['env', f'PY={sys.executable}', 'unshare', '-Urnm', 'sh', '-c', NETNS_SETUP, 'netns']
    code, out = discover('iface=bw0', 'protocol=ip', wrap=wrap)
    assert code == os.EX_OK, (code, out)
    assert out['_metadata']['params']['protocol'] == 'ip', out['_metadata']
    targets = scan_of(out, 'bw0', 'ip')['targets']
    # Exactly the peer, over IPv4 and IPv6: not our own addresses, and not the
    # stale cache entry for a host that is gone.
    assert targets == [
        {'address': PEER_IPV4, 'mac': PEER_MAC, 'ports': [8080]},
        {'address': PEER_IPV6, 'mac': PEER_MAC, 'ports': [8080]},
    ], targets
bw_tc_func('discover.ip', discover_ip)

def discover_ip_down():
    wrap = ['unshare', '-Urnm', 'sh', '-c',
            'mount -t sysfs sysfs /sys; ip link add bw0 type veth peer name bwpeer; "$@"', 'netns']
    code, out = discover('iface=bw0', 'protocol=ip', wrap=wrap)
    assert code == os.EX_IOERR, (code, out)
    assert out['_metadata']['errors'] == 1, out['_metadata']
    assert out['interfaces']['bw0']['scans']['ip']['error'] == 'bw0 is DOWN', out['interfaces']
bw_tc_func('discover.ip_down', discover_ip_down)

# --- uds and xcp on vcan0 -----------------------------------------------------

CanParams = {
    'iface': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'False'
}

VIN = b'WBA00000000000001'

def with_sim(sim, func):
    sim.start()
    try:
        func()
    finally:
        sim.stop()

def discover_uds():
    # Sessions 1 and 3, services 0x10, 0x22 and 0x3E, and the VIN in 0xF190.
    # Everything else is serviceNotSupported, which the scan tells apart from
    # a supported service that rejects the bare request.
    sim = bw_tc_sim_iso14229('uds_ecu', CanParams, [
        [bytes([0x10, 0x01]), bytes([0x50, 0x01, 0x00, 0x32, 0x01, 0xF4])],
        [bytes([0x10, 0x03]), bytes([0x50, 0x03, 0x00, 0x32, 0x01, 0xF4])],
        [bytes([0x10]), lambda msg, sim: bytes([0x7F, 0x10, 0x12 if len(msg) > 1 else 0x13])],
        [bytes([0x22, 0xF1, 0x90]), bytes([0x62, 0xF1, 0x90]) + VIN],
        [bytes([0x22]), bytes([0x7F, 0x22, 0x31])],
        [bytes([0x3E, 0x00]), bytes([0x7E, 0x00])],
        [bytes([0x3E]), bytes([0x7F, 0x3E, 0x13])],
        [b'', lambda msg, sim: bytes([0x7F, msg[0], 0x11])],
    ], error_unknown=False)

    def check():
        code, out = discover('iface=vcan0', 'protocol=uds', 'min_did=0xF190', 'max_did=0xF191')
        assert code == os.EX_OK, (code, out)
        targets = scan_of(out, 'vcan0', 'uds')['targets']
        assert len(targets) == 1, targets
        t = targets[0]
        assert t['address'] == {'server_id': 0x7E0, 'client_id': 0x7E8}, t['address']
        assert t['fd'] is False, t
        sessions = {s['id']: s for s in t['sessions']}
        assert set(sessions) == {1, 3}, sessions.keys()
        for s in sessions.values():
            assert [x['sid'] for x in s['services']] == [0x10, 0x22, 0x3E], s['services']
            assert [d['id'] for d in s['dids']] == [0xF190], s['dids']
            assert VIN.decode() in s['dids'][0]['decodedValues'], s['dids']
    with_sim(sim, check)
bw_tc_func('discover.uds', discover_uds)

def discover_xcp():
    # CONNECT and GET_STATUS answer positively, every other command is unknown.
    sim = bw_tc_sim_can('xcp_slave', CanParams, [
        [bytes([0xFF]), bytes([0xFF, 0x15, 0x80, 0x08, 0x08, 0x00, 0x01, 0x01])],
        [bytes([0xFD]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00])],
    ], default_response=bytes([0xFE, 0x20]))

    def check():
        code, out = discover('iface=vcan0', 'protocol=xcp')
        assert code == os.EX_OK, (code, out)
        targets = scan_of(out, 'vcan0', 'xcp')['targets']
        assert len(targets) == 1, targets
        t = targets[0]
        assert t['address'] == {'request_id': 0x7E0, 'response_id': 0x7E8}, t['address']
        assert t['fd'] is False, t
        connect = t['connect']
        assert connect['resource'] == {'cal_pag': True, 'daq': True, 'stim': False, 'pgm': True}, connect
        assert connect['max_cto'] == 8 and connect['max_dto'] == 8, connect
        supported = [c['name'] for c in t['commands'] if c['supported']]
        assert supported == ['GET_STATUS'], supported
    with_sim(sim, check)
bw_tc_func('discover.xcp', discover_xcp)
