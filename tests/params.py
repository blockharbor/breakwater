# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# The interface parameter: audits declare `iface`, callers may pass the older
# name `device` instead.

import os
import sys
import subprocess

from tests.base import *

BW_CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bw_cli.py')

@register_audit('example_param_iface')
class example_param_iface(AuditRunner):
    parameters = [Parameter('iface', 'Interface', 'default0', 'The interface')]
    friendly_name = 'example_param_iface'

    def run_audit(self):
        return {'iface': self.params['iface'], 'pass_rules': {'vulnerable': False}}

    def format_results(self, results):
        return [{'title': 'example_param_iface', 'segments': []}]

def iface_of(params):
    result = run_audit('example_param_iface', params)
    assert result.status == Status.PASSED, result.raw
    return result.raw['iface']

def interface_names():
    assert iface_of({'iface': 'can1'}) == 'can1'
    assert iface_of({'device': 'can1'}) == 'can1'
    assert iface_of({}) == 'default0'
bw_tc_func('params.interface_names', interface_names)

def interface_both():
    result = run_audit('example_param_iface', {'iface': 'can1', 'device': 'can1'})
    assert result.status == Status.NO_RESULT, result.status
    assert 'not both' in result.raw['error'], result.raw
    r = subprocess.run([sys.executable, BW_CLI, 'discover', '-p', 'iface=can1', '-p', 'device=can1'],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == os.EX_USAGE, r.returncode
    assert 'not both' in r.stderr, r.stderr
bw_tc_func('params.interface_both', interface_both)

def discover_bad_protocol():
    r = subprocess.run([sys.executable, BW_CLI, 'discover', '-p', 'iface=vcan0', '-p', 'protocol=eth'],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == os.EX_USAGE, r.returncode
    assert 'not uds, xcp or ip' in r.stderr, r.stderr
bw_tc_func('params.discover_bad_protocol', discover_bad_protocol)

# discover never picks interfaces itself: none set, an unknown one or a scan that
# does not fit the interface type is a usage error, before any scan starts
def discover_bad_ifaces():
    for params, expect in (([], 'set the interfaces'),
                           (['-p', 'iface=vcan0,nosuch0'], 'nosuch0 not found'),
                           (['-p', 'iface=vcan0', '-p', 'protocol=ip'], 'no ip scan on vcan0')):
        r = subprocess.run([sys.executable, BW_CLI, 'discover', *params],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == os.EX_USAGE, (params, r.returncode)
        assert expect in r.stderr, (params, r.stderr)
bw_tc_func('params.discover_bad_ifaces', discover_bad_ifaces)

# A built-in CAN audit declares iface; the old name still reaches the bus. With
# the alias ignored, the audit would open its default can0 and report no result.
device_params = {'device': 'vcan0', 'req_arb': '0x7e0', 'resp_arb': '0x7e8', 'session': '1',
                 'min_seed_len': '4', 'seeds_requested': '4', 'is_fd': 'False',
                 'extended_id': 'False'}
bw_tc('uds_security_access', bw_res.FAILED, device_params,
    bw_tc_sim_iso14229('device_alias', device_params, [
        [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
        [b'\x27\x01', b'\x67\x01\x11\x22\x33\x44'],
        [b'\x27', b'\x7f\x27\x12'],
    ])
)
