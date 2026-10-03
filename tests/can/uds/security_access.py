# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os

from tests.base import *

from utils.udsutil import *

sa_params1 = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'min_seed_len': '4',
    'seeds_requested': '10',
    'session': '3',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}
sa_params1_fd = {
    'device': 'vcan0',
    'extended_id': 'False',
    'req_arb': '0x7e0',
    'resp_arb': '0x7e8',
    'min_seed_len': '4',
    'seeds_requested': '10',
    'session': '3',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [ sa_params1, sa_params1_fd ]:
    bw_tc('uds_security_access', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    for access_level in range(1, 0x80, 0x20):
        bw_tc('uds_security_access', bw_res.PASSED, params, 
            bw_tc_sim_iso14229(f'{access_level:02x}_random_seeds', params, [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [bytes([0x27, access_level]), lambda cue, sim: bytes([0x67, access_level]) + os.urandom(8)],
            ])
        )
        bw_tc('uds_security_access', bw_res.FAILED, params, 
            bw_tc_sim_iso14229(f'{access_level:02x}_duplicate_seeds', params, [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [bytes([0x27, access_level]), bytes([0x67, access_level]) + os.urandom(8)],
                [b'\x27', b'\x7f\x27\x80'],
            ])
        )

    bw_tc('uds_security_access', bw_res.NORESULT, params, bw_tc_base_sim('no_response'))

    bw_tc('uds_security_access', bw_res.FAILED, params, 
        bw_tc_sim_iso14229(f'seed_too_small', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [bytes([0x27, 0x01]), bytes([0x67, 0x01]) + os.urandom(2)],
            [b'\x27', b'\x7f\x27\x80'],
        ])
    )

    # find seed behind session request
    def enter_session(cue, sim):
        sim.queue(b'\x27\x01', b'\x67\x01\xaa\xbb')
        return bytes([0x50, 0x03])
    bw_tc('uds_security_access', bw_res.FAILED, params, 
        bw_tc_sim_iso14229('behind_session', params, [
            [b'\x27\x01', bytes([0x7f, 0x27, 0x7e])],
            [b'\x10\x03', enter_session],
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
        ])
    )


