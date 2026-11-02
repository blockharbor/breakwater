# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# Reading a CAN interface's settings from IFLA_LINKINFO, as pyroute2 hands it
# over: decoded from 0.7.10 on, a hex string before that, when they are read
# from iproute2 instead.

import json
import subprocess

from tests.base import *
import discover.hardware as hardware
from discover.hardware import can_settings

def info_data(*attrs):
    return {'attrs': [('IFLA_INFO_KIND', 'can'), ('IFLA_INFO_DATA', {'attrs': list(attrs)})]}

def can_settings_decoded():
    got = can_settings('can0', info_data(
        ('IFLA_CAN_BITTIMING', {'bitrate': 500000, 'sample_point': 875}),
        ('IFLA_CAN_DATA_BITTIMING', {'bitrate': 2000000, 'sample_point': 750}),
        ('IFLA_CAN_CLOCK', 40000000),
        ('IFLA_CAN_CTRLMODE', {'loopback': 'off', 'listenonly': 'off', 'fd': 'on'}),
        ('IFLA_CAN_CTRLMODE_EXT', {'attrs': [('IFLA_CAN_CTRLMODE_SUPPORTED', {'loopback': 'yes', 'listenonly': 'yes', 'fd': 'yes'})]}),
    ))
    want = {'bitrate': 500000, 'sample_point': 875, 'fd_bitrate': 2000000, 'fd_sample_point': 750,
            'clock_freq': 40000000, 'loopback': False, 'listenonly': False, 'fd': True,
            'loopback_supported': True, 'listenonly_supported': True, 'fd_supported': True}
    assert got == want, got
bw_tc_func('hardware.can_settings_decoded', can_settings_decoded)

# `ip -details -json link show dev can0` on a Raspberry Pi with a gs_usb CAN FD
# adapter, Debian trixie (pyroute2 0.7.7), interface down
IP_GS_USB = json.dumps([{"ifindex": 8, "ifname": "can0", "flags": ["NOARP", "ECHO"], "mtu": 16, "operstate": "DOWN",
    "txqlen": 10, "link_type": "can", "linkinfo": {"info_kind": "can", "info_data": {
        "ctrlmode_supported": ["LOOPBACK", "LISTEN-ONLY", "ONE-SHOT", "FD", "CC-LEN8-DLC"], "state": "STOPPED",
        "berr_counter": {"tx": 0, "rx": 0}, "restart_ms": 0,
        "bittiming": {"bitrate": 500000, "sample_point": "0.875", "tq": 16, "prop_seg": 52, "phase_seg1": 52,
                      "phase_seg2": 15, "sjw": 7, "brp": 1},
        "bittiming_const": {"name": "gs_usb", "tseg1": {"min": 1, "max": 256}, "tseg2": {"min": 1, "max": 128},
                            "sjw": {"min": 1, "max": 128}, "brp": {"min": 1, "max": 512}, "brp_inc": 1},
        "data_bittiming_const": {"name": "gs_usb", "tseg1": {"min": 1, "max": 32}, "tseg2": {"min": 1, "max": 16},
                                 "sjw": {"min": 1, "max": 16}, "brp": {"min": 1, "max": 32}, "brp_inc": 1},
        "clock": 60000000}}}])

GS_USB = {
    'bitrate': 500000, 'sample_point': 875, 'clock_freq': 60000000,
    'bittiming_const': {'tseg1_min': 1, 'tseg1_max': 256, 'tseg2_min': 1, 'tseg2_max': 128,
                        'sjw_max': 128, 'brp_min': 1, 'brp_max': 512, 'brp_inc': 1},
    'fd_bittiming_const': {'tseg1_min': 1, 'tseg1_max': 32, 'tseg2_min': 1, 'tseg2_max': 16,
                           'sjw_max': 16, 'brp_min': 1, 'brp_max': 32, 'brp_inc': 1},
    'loopback': False, 'listenonly': False, 'fd': False,
    'loopback_supported': True, 'listenonly_supported': True, 'fd_supported': True,
}

def fake_ip(stdout=IP_GS_USB, fail=False):
    """Stands in for subprocess.run in discover.hardware, recording the command"""
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        if fail:
            raise FileNotFoundError(2, 'No such file or directory', 'ip')
        return subprocess.CompletedProcess(cmd, 0, stdout, '')
    return run, calls

def with_run(run, func):
    saved = hardware.subprocess.run
    hardware.subprocess.run = run
    try:
        return func()
    finally:
        hardware.subprocess.run = saved

def can_settings_from_ip():
    assert hardware.can_settings_from_ip(json.loads(IP_GS_USB)[0]['linkinfo']['info_data']) == GS_USB
    # Modes that are on, and the CAN FD data phase once configured
    info = {'ctrlmode': ['LOOPBACK', 'FD'], 'data_bittiming': {'bitrate': 2000000, 'sample_point': '0.750'}}
    got = hardware.can_settings_from_ip(info)
    assert got == {'fd_bitrate': 2000000, 'fd_sample_point': 750, 'loopback': True, 'listenonly': False, 'fd': True}, got
bw_tc_func('hardware.can_settings_from_ip', can_settings_from_ip)

def can_settings_undecoded():
    # pyroute2 before 0.7.10 has no CAN plugin, so IFLA_INFO_DATA stays raw:
    # the settings come from iproute2 instead
    linkinfo = {'attrs': [('IFLA_INFO_KIND', 'can'), ('IFLA_INFO_DATA', '0c:00:0e:00:40:78:7d:01')]}
    run, calls = fake_ip()
    got = with_run(run, lambda: can_settings('can0', linkinfo))
    assert got == GS_USB, got
    assert calls == [['ip', '-details', '-json', 'link', 'show', 'dev', 'can0']], calls
    # iproute2 missing too: listed without the settings
    run, _ = fake_ip(fail=True)
    assert with_run(run, lambda: can_settings('can0', linkinfo)) == {}
    run, _ = fake_ip(stdout='not json')
    assert with_run(run, lambda: can_settings('can0', linkinfo)) == {}
    # Nested attributes pyroute2 could not decode are skipped, without iproute2
    run, calls = fake_ip()
    got = with_run(run, lambda: can_settings('can0', info_data(('IFLA_CAN_CTRLMODE_EXT', '08:00:01:00'), ('IFLA_CAN_CTRLMODE', '00:00'))))
    assert got == {} and calls == [], (got, calls)
bw_tc_func('hardware.can_settings_undecoded', can_settings_undecoded)
