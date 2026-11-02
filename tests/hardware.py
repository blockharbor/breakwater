# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# Reading a CAN interface's settings from IFLA_LINKINFO, as pyroute2 hands it
# over: decoded from 0.7.10 on, a hex string before that.

from tests.base import *
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

def can_settings_undecoded():
    # pyroute2 before 0.7.10, a CAN controller that is down: no CAN plugin, so
    # IFLA_INFO_DATA stays raw
    linkinfo = {'attrs': [('IFLA_INFO_KIND', 'can'), ('IFLA_INFO_DATA', '0c:00:0e:00:40:78:7d:01')]}
    assert can_settings('can0', linkinfo) == {}
    # and nested attributes it could not decode either
    got = can_settings('can0', info_data(('IFLA_CAN_CTRLMODE_EXT', '08:00:01:00'), ('IFLA_CAN_CTRLMODE', '00:00')))
    assert got == {}, got
bw_tc_func('hardware.can_settings_undecoded', can_settings_undecoded)
