# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

### PASS CONDITION - Service 'DynamicallyDefineDataIdentifier' (0x2C) response NRC securityAccessDenied upon baseline request to define a data identifier 
from tests.base import *
from utils.udsutil import *

audit_params = {
    'device': 'vcan0',         
    'extended_id': 'False',       
    'req_arb': '0x7e0',           
    'resp_arb': '0x7e8',        
    'session': '1',            
    'did': '0xF001',            
    'address': '0x12',         
    'size': '0x14',
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
    'did': '0xF001',            
    'address': '0x12',         
    'size': '0x14',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [ audit_params, audit_params_fd ]:
    bw_tc('uds_read_memory_by_did', bw_res.NORESULT, params, bw_tc_base_sim('passive'))


    T1 = bytes([
        0x2C,               # DynamicallyDefineDataIdentifier SID
        0x02,               # SubFunction - defineByMemoryAddress
        0xF0, 0x01,         # dynamicallyDefinedDataIdentifier (0xF001)
        0x11,               # addressAndLengthFormatIdentifier (1 byte address, 1 byte size)
    ])


    ###### TEST #1 - PASS if service 0x7F responds with NRC securityAccessDenied (0x33)
    bw_tc(
        'uds_read_memory_by_did', 
        bw_res.PASSED,
        params,
        bw_tc_sim_iso14229(
            'read_hardcoded_address',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [T1, bytes([0x7F, 0x2C, 0x33])],
            ]
        )
    )

    bw_tc(
        'uds_read_memory_by_did', 
        bw_res.PASSED,
        params,
        bw_tc_sim_iso14229(
            'allow_define',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                # allow define
                [b'\x2C\x02\xF0\x01\x42', b'\x6C\x02\xF0\x01'],
                # do not allow read
                [b'\x22\xF0\x01', b'\x7F\x22\x33']
            ]
        )
    )

    bw_tc(
        'uds_read_memory_by_did', 
        bw_res.FAILED,
        params,
        bw_tc_sim_iso14229(
            'allow_define_and_read',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                # allow define
                [b'\x2C\x02\xF0\x01\x42', b'\x6C\x02\xF0\x01'],
                # allow read
                [b'\x22\xF0\x01', b'\x62FLAG']
            ]
        )
    )

    # A 4 byte address does not fit the narrow formats, those are skipped
    # instead of crashing and the 4 byte formats still get tested
    wide_params = {**params, 'address': '0x12345678'}
    bw_tc(
        'uds_read_memory_by_did',
        bw_res.FAILED,
        wide_params,
        bw_tc_sim_iso14229(
            'allow_define_and_read_wide_address',
            wide_params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                # allow define with a 4 byte address and 1 byte size
                [b'\x2C\x02\xF0\x01\x14\x12\x34\x56\x78', b'\x6C\x02\xF0\x01'],
                [b'\x2C', b'\x7F\x2C\x31'],
                # allow read
                [b'\x22\xF0\x01', b'\x62FLAG']
            ]
        )
    )

    # An address wider than any format is an error, not a crash
    bw_tc(
        'uds_read_memory_by_did',
        bw_res.NORESULT,
        {**params, 'address': '0x123456789A'},
        bw_tc_sim_iso14229(
            'address_too_wide',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [b'\x2C', b'\x7F\x2C\x31'],
            ]
        )
    )
