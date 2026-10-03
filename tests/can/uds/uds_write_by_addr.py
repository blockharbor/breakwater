# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import *
from utils.udsutil import *

audit_params = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'session': '3', 
    'scan_interval': '0x100000000',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}
audit_params_fd = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'session': '3', 
    'scan_interval': '0x100000000',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [ audit_params, audit_params_fd ]:
    bw_tc('uds_write_by_addr', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    WriteByAddress_SID = 0x3D
    NegativeResponse_SID = 0x7F
    NRCsecurityAccessDenied = 0x33


    bw_tc(
        
        'uds_write_by_addr',
        bw_res.PASSED,
        params,
        bw_tc_sim_iso14229(
            'protected_write',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [
                    bytes([WriteByAddress_SID]),
                    bytes([
                        NegativeResponse_SID,  
                        WriteByAddress_SID, 
                        NRCsecurityAccessDenied
                    ])
                ]
            ]
        )
    )

    bw_tc(
        'uds_write_by_addr',
        bw_res.FAILED,
        params, 
        bw_tc_sim_iso14229(
            'unprotected_write',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [
                    bytes([WriteByAddress_SID]), 
                    bytes([0x7D])     # positive WriteMemoryByAddress response
                ]
            ]
        )
    )
