# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os

from tests.base import *

params1 = {
    'iface': 'lo',
    'target_host': '127.0.0.1',
    'target_port': '18443',
    
    'temp_ip': '',
    'temp_mask': '',
}

bw_tc('supported_tls_versions', bw_res.NORESULT, params1, bw_tc_base_sim('no_response'))
bw_tc('supported_tls_versions', bw_res.PASSED, params1, bw_tc_sim_tls('new_tls_versions', params1, [1.2,1.3], None))
# Not run: current OpenSSL builds refuse TLS 1.0 and 1.1, so the sim cannot offer them.
#bw_tc('supported_tls_versions', bw_res.FAILED, params1, bw_tc_sim_tls('all_versions', params1, [1,1.1,1.2,1.3], 'ALL:@SECLEVEL=0'))
