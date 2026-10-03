# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os

from tests.base import *

params1 = {
    'iface': 'lo',
    'uri': 'https://127.0.0.1:8443',

    'temp_ip': '',
    'temp_mask': '',
}

bw_tc('mtls_self_signed', bw_res.PASSED, params1, bw_tc_base_sim('passive'))
