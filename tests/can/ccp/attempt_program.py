# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import * 
from utils.ccputil import * 

CCP_SET_MTA_PROGRAM = bytes([0x02, 0x01, 0x40])
CCP_PROGRAM_03 = bytes([0x03, 0x02, 0x04])
CCP_PROGRAM_23 = bytes([0x23, 0x02, 0x04])

AuditParams = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'False'
}
AuditParams_fd = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'True',
}

for params in [ AuditParams, AuditParams_fd ]:
    bw_tc('ccp_program', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    bw_tc(
        'ccp_program',
        bw_res.PASSED,
        params,
        bw_tc_sim_can('secure_ccp_program', params, [
                [b'\x01\x01', b'\xFF\x01\x00'],
                [CCP_SET_MTA_PROGRAM, bytes([0xFE, 0x02, 0x33])],
                [CCP_SET_MTA_PROGRAM, bytes([0xFE, 0x02, 0x33])],
            ]
        ) 
    )

    bw_tc(
        'ccp_program',
        bw_res.FAILED,
        params,
        bw_tc_sim_can('vulnerable_ccp_program', params, [
                [CCP_SET_MTA_PROGRAM, bytes([0xFF, 0x02, 0x00])],
                [CCP_PROGRAM_03, bytes([0xFF, 0x03, 0x00])],
                [CCP_SET_MTA_PROGRAM, bytes([0xFF, 0x02, 0x00])],
                [CCP_PROGRAM_23, bytes([0xFF, 0x03, 0x00])],
            ]
        ) 
    )