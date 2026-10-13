# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import * 
from utils.xcputil import * 

XCP_PROGRAM_CLEAR = bytes([0xD2])
XCP_SET_MTA = bytes([0xF6, 0, 0, 0])
XCP_PROGRAM = bytes([0xD0, 0x01, 0x00])

AuditParams = {
    'iface': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'False'
}
AuditParams_fd = {
    'iface': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'True'
}

for params in [ AuditParams, AuditParams_fd ]:
    bw_tc('xcp_program', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    bw_tc(
        'xcp_program',
        bw_res.PASSED,
        params,
        bw_tc_sim_can('secure_xcp_program', params, [
                [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],  # CONNECT -> Success
                [XCP_PROGRAM_CLEAR, bytes([0xFE, 0x26])],  ### PAGE_NOT_VALID
                [XCP_SET_MTA, bytes([0xFE, 0x22])],        ### OUT_OF_RANGE
                [XCP_PROGRAM, bytes([0xFE, 0x26])],        ### PAGE_NOT_VALID
            ]
        ) 
    )

    bw_tc(
        'xcp_program',
        bw_res.FAILED,
        params,
        bw_tc_sim_can('vulnerable_xcp_program', params, [
                [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],  # CONNECT -> Success
                [XCP_PROGRAM_CLEAR, bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
                [XCP_SET_MTA, bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
                [XCP_PROGRAM, bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
            ]
        ) 
    )