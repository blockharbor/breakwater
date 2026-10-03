# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import * 
from utils.xcputil import * 

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
    'is_fd': 'True'
}

for params in [ AuditParams, AuditParams_fd ]:
    bw_tc('xcp_upload', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    sim_xcp_secure = bw_tc_sim_can('xcp_deny_upload', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        [bytes([0xF4]), bytes([0xFE, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
    ])  

    sim_xcp_vulnerable = bw_tc_sim_can('xcp_allow_upload', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        [bytes([0xF5]), bytes([0xFF, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00])],
        [bytes([0xF4]), bytes([0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00])],
    ])

    bw_tc('xcp_upload', bw_res.PASSED, params, sim_xcp_secure)
    bw_tc('xcp_upload', bw_res.FAILED, params, sim_xcp_vulnerable)
