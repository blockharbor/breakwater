# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import * 
from utils.ccputil import * 

#### Messages 
SET_MTA_MSG = bytes([0x02, 0x01, 0x40])
UPLOAD_MSG = bytes([0x04, 0x02, 0x04])
SHORT_UP_MSG = bytes([0x0F, 0x01, 0x40, 0x00, 0x00, 0x00]) 


AuditParams = {
    'iface': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'False',
}
AuditParams_fd = {
    'iface': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'is_fd': 'True',
}

for params in [ AuditParams, AuditParams_fd ]:
    bw_tc('ccp_upload', bw_res.NORESULT, params, bw_tc_base_sim('passive'))
    
    bw_tc(
        'ccp_upload', bw_res.PASSED, params,
        bw_tc_sim_can('secured_server', params, [
            [b'\x01\x01', b'\xFF\x01\x00'],
            [SET_MTA_MSG, bytes([0xFE, 0x2, 0x33])], 
            [UPLOAD_MSG, bytes([0xFE, 0x04, 0x33])],
            [SHORT_UP_MSG, bytes([0xFE, 0x01, 0x33])],
        ])
    )

    bw_tc(
        'ccp_upload', bw_res.PASSED, params,
        bw_tc_sim_can('partially_secured_mem', params, [
            [SET_MTA_MSG, bytes([0xFF, 0x2, 0x00])], ### SET MTA (OK)
            [UPLOAD_MSG, bytes([0xFE, 0x04, 0x33])],### 0x33=CCP ACCESS_DENIED
            [SHORT_UP_MSG, bytes([0xFE, 0x01, 0x33])], ### 0x33=CCP ACCESS_DENIED
        ])
    )

    bw_tc(
        'ccp_upload', bw_res.FAILED, params,
        bw_tc_sim_can('vulnerable_server', params, [
            [SET_MTA_MSG, bytes([0xFF, 0x2, 0x00])], 
            [UPLOAD_MSG, bytes([0xFF, 0x04, 0x00])],
            [SHORT_UP_MSG, bytes([0xFF, 0x01, 0x00])],
        ])
    )

    # SHORT_UP works without CONNECT, and CONNECT gets no answer. The read that
    # got through must still be reported.
    bw_tc(
        'ccp_upload', bw_res.FAILED, params,
        bw_tc_sim_can('short_upload_no_connect', params, [
            [SET_MTA_MSG, bytes([0xFF, 0x2, 0x33])],
            [SHORT_UP_MSG, bytes([0xFF, 0x01, 0x00])],
        ])
    )
