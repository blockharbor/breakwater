# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from tests.base import *
from utils.udsutil import *

audit_params = {
    'device': 'vcan0',         
    'extended_id': 'False',       
    'req_arb': '0x7e0',        
    'resp_arb': '0x7e8',        
    'session': '3',         
    'scan_interval': '0x1000000',
    'is_fd': 'False',
    'frame_len': '0',
    'frame_fill': '0x00',
}
audit_params_fd = {
    'device': 'vcan0',         
    'extended_id': 'False',       
    'req_arb': '0x7e0',        
    'resp_arb': '0x7e8',        
    'session': '3',         
    'scan_interval': '0x1000000',
    'is_fd': 'True',
    'frame_len': '0',
    'frame_fill': '0x00',
}

for params in [audit_params, audit_params_fd]:
    bw_tc('uds_request_download', bw_res.NORESULT, params, bw_tc_base_sim('passive'))

    RequestDownload_SID = 0x34                  
    NegativeRespons_SID = 0x7F
    RequestDownload_DataFormatID = 0x00 
    NRCsecurityAccessDenied = 0x33 

    bw_tc('uds_request_download', bw_res.PASSED, params,
        bw_tc_sim_iso14229(
            'protected_download', 
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [
                    bytes([
                        RequestDownload_SID, 
                        RequestDownload_DataFormatID, 
                        0x11,  ### ALFID 
                        0x00,  ### Memory Address 
                        0x04,  ### Memory Size
                    ]),
                    bytes([
                        NegativeRespons_SID, 
                        RequestDownload_SID, 
                        NRCsecurityAccessDenied, 
                    ])
                ]
            ]
        )
    )

    bw_tc('uds_request_download', bw_res.FAILED, params, 
        bw_tc_sim_iso14229(
            'unprotected_download',
            params,
            [
                [b'\x10', lambda cue, sim: bytes([0x50, cue[1]])],
                [
                    bytes([
                        RequestDownload_SID, 
                        RequestDownload_DataFormatID, 
                        0x11,  ### ALFID 
                        0x00,  ### Memory Address 
                        0x04,  ### Memory Size
                    ]),
                    bytes([
                        0x74,
                        0x11     # positive RequestDownload response; the audit checks the SID
                    ])
                ]
            ]
        )
    )


