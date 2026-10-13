# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import * 
from utils.xcputil import * 

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
    bw_tc('xcp_download', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    xcp_download_access_denied = bw_tc_sim_can('xcp_download_access_denied', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        [bytes([0xF0]), bytes([0xFE, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
    ])  

    xcp_download_access_granted = bw_tc_sim_can('xcp_download_access_granted', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        [bytes([0xF0]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
    ])

    bw_tc('xcp_download', bw_res.PASSED, params, xcp_download_access_denied)
    bw_tc('xcp_download', bw_res.FAILED, params, xcp_download_access_granted)

    # Positive responses are the bare PID, without padding.
    xcp_download_unpadded = bw_tc_sim_can('xcp_download_unpadded_responses', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF])],
        [bytes([0xF0]), bytes([0xFF])],
    ])
    bw_tc('xcp_download', bw_res.FAILED, params, xcp_download_unpadded)
