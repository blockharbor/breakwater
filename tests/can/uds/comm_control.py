# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os

from tests.base import *
from utils.udsutil import *

cc_params1 = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'session': '1',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}
cc_params1_fd = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'session': '1',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [ cc_params1, cc_params1_fd ]:
    bw_tc('uds_comm_control', bw_res.NORESULT, params, bw_tc_base_sim('no_response'))

    bw_tc('uds_comm_control', bw_res.FAILED, params, 
        bw_tc_sim_iso14229(f'allow_comm_control', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [bytes([0x28]), lambda cue, sim: bytes([0x68, cue[1], cue[2]])],
        ])
    )

    bw_tc('uds_comm_control', bw_res.PASSED, params, 
        bw_tc_sim_iso14229(f'allow_comm_control_enable_only', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [bytes([0x28, 0x00, 0x01]), bytes([0x68, 0x00, 0x01])],
            [bytes([0x28]), bytes([0x7f, 0x28, 0x33])],
        ])
    )
