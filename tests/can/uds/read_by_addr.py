# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os

from tests.base import *

from utils.udsutil import *

rm_params1 = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'scan_interval': '0x1000000',
    'session': '3',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}
rm_params1_fd = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'scan_interval': '0x1000000',
    'session': '3',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [ rm_params1, rm_params1_fd ]:
    bw_tc('uds_read_by_addr', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    # all memory formats
    for a in range(1, 5): # address fmt
        for s in range(1, 5): # size fmt
            bw_tc('uds_read_by_addr', bw_res.FAILED, params, 
                bw_tc_sim_iso14229(f'readable_at_0x0_fmt_{(s<<4)|a:02x}', params, [
                    [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                    # memory read works at address zero
                    [bytes([0x23, (s<<4)|a] + [0] * a), lambda cue, sim: bytes([0x63] + [0x77] * int.from_bytes(cue[2+a:6+a], 'big'))],
                    # memory read out of range in correct alfid
                    [bytes([0x23, (s<<4)|a]), b'\x7f\x23\x31'],
                    # memory read conditions not correct
                    [b'\x23', b'\x7f\x23\x22'],
                ])
            )

    bw_tc('uds_read_by_addr', bw_res.FAILED, params, 
        bw_tc_sim_iso14229('read_restricted_by_addr', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [
                # service memory request
                bytes([0x23]), lambda cue, sim: 
                    # return memory if address in proper range
                    bytes([0x63] + [0x77] * int.from_bytes(cue[6:10], 'big'))
                        if (a >= 0xa0000000 and (a+s) < 0xa0800000) else
                    # return out of range
                    bytes([ 0x7f, 0x23, 0x31 ])
            ]
        ])
    )

    for nrc in NRC_NAMES.keys():
        if nrc == 0x31:
            continue
        bw_tc('uds_read_by_addr', bw_res.PASSED, params, 
            bw_tc_sim_iso14229(NRC_NAMES[nrc], params, [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [b'\x23', bytes([0x7f, 0x23, nrc])],
            ])
        )


