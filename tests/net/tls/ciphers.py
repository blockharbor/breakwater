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

bw_tc('supported_tls_ciphers', bw_res.NORESULT, params1, bw_tc_base_sim('no_response'))
bw_tc('supported_tls_ciphers', bw_res.FAILED, params1, bw_tc_sim_tls('all_ciphers', params1, [1,1.1,1.2,1.3], None))
_strong_ciphers = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-CBC-SHA256:ECDHE-ECDSA-AES256-CBC-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-CBC-SHA256:ECDHE-RSA-AES256-CBC-SHA384:ECDHE-RSA-AES128-CBC-SHA256:ECDHE-RSA-AES256-CBC-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-CBC-SHA:DHE-RSA-AES256-CBC-SHA:DHE-RSA-AES128-CBC-SHA256:DHE-RSA-AES256-CBC-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305'
bw_tc('supported_tls_ciphers', bw_res.PASSED, params1, bw_tc_sim_tls('strong_ciphers', params1, [1,1.1,1.2,1.3], _strong_ciphers))
