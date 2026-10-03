# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import *
from utils.udsutil import *

audit_params = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'session': '1',
    'scan_interval': '0x1000',   
    'min_did': '0xF000',  
    'max_did': '0xFFFF',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}
audit_params_fd = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'session': '1',
    'scan_interval': '0x1000',   
    'min_did': '0xF000',  
    'max_did': '0xFFFF',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [ audit_params, audit_params_fd ]:
    bw_tc('uds_write_by_id', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    bw_tc('uds_write_by_id', bw_res.PASSED, params, 
        bw_tc_sim_iso14229(f'safe_write_did', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [
                bytes([0x2E]),
                bytes([0x7f, 0x2E, 0x33])
            ],
        ])
    )

    bw_tc(
        'uds_write_by_id',
        bw_res.FAILED,
        params, 
        bw_tc_sim_iso14229(
            'unsafe_write_did',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [ b'\x2e', b'\x6e' ],
            ]
        )
    )
