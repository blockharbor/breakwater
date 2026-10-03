# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import *
from utils.udsutil import *

audit_params = {
    'device': 'vcan0',         
    'extended_id': 'False',      
    'req_arb': '0x7e0',          
    'resp_arb': '0x7e8',        
    'session': '1',      
    'min_did': '0xF000',
    'max_did': '0xF010',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}   
audit_params_fd = {
    'device': 'vcan0',         
    'extended_id': 'False',      
    'req_arb': '0x7e0',          
    'resp_arb': '0x7e8',        
    'session': '1',      
    'min_did': '0xF000',
    'max_did': '0xF010',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
} 

for params in [ audit_params, audit_params_fd ]:
    bw_tc('uds_io_control', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    T1 = bytes( 
            [
                0x2F,
                0xF0,
                0x01,
                0x01 
            ]
        ), 

    bw_tc(
        'uds_io_control', bw_res.PASSED, params, 
            bw_tc_sim_iso14229('secured_io_control', params, [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [
                    T1, 
                    bytes([0x7F, 0x2F, 0x33])
                ],
            ]
        )
    )

    bw_tc(
        'uds_io_control', bw_res.PASSED, params, 
        bw_tc_sim_iso14229('unsecured_io_control', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [
                T1,
                bytes([0x7F, 0x2F, 0x22])
            ]
        ]) 
    )

    bw_tc(
        'uds_io_control', bw_res.FAILED, params, 
        bw_tc_sim_iso14229('unsecured_io_control', params, [
            [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
            [
                T1, 
                bytes([0x6F, 0xF0, 0x01])
            ],
        ])
    )
