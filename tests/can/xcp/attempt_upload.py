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

    # CONNECT is rejected, so nothing else is tested, even though SHORT_UPLOAD
    # would have answered.
    sim_xcp_reject_connect = bw_tc_sim_can('xcp_reject_connect', params, [
        [bytes([0xFF]), bytes([0xFE, 0x21])],
        [bytes([0xF6]), b''],
        [bytes([0xF4]), bytes([0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00])],
    ])
    bw_tc('xcp_upload', bw_res.NORESULT, params, sim_xcp_reject_connect)

    # UPLOAD is only accepted as a full 8 byte frame padded with 0xAA.
    def upload_needs_fill(data, sim):
        if bytes(data) == bytes([0xF5, 0x01] + [0xAA] * 6):
            return bytes([0xFF, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00])
        return bytes([0xFE, 0x21])

    sim_xcp_fill = bw_tc_sim_can('xcp_upload_needs_fill', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        [bytes([0xF5]), upload_needs_fill],
        [bytes([0xF4]), bytes([0xFE, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
    ])
    bw_tc('xcp_upload', bw_res.PASSED, params, sim_xcp_fill)
    bw_tc('xcp_upload', bw_res.FAILED, {**params, 'frame_len': '8', 'frame_fill': '0xAA'}, sim_xcp_fill)

    # Positive responses are the bare PID, without padding.
    sim_xcp_unpadded = bw_tc_sim_can('xcp_upload_unpadded_responses', params, [
        [bytes([0xFF]), bytes([0xFF, 0x10, 0x08, 0x20, 0x04, 0x00, 0x08, 0x00])],
        [bytes([0xF6]), bytes([0xFF])],
        [bytes([0xF5]), bytes([0xFF, 0x12])],
        [bytes([0xF4]), bytes([0xFE, 0x29])],
    ])
    bw_tc('xcp_upload', bw_res.FAILED, params, sim_xcp_unpadded)
