# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os

from tests.base import *

params1 = {
    'iface': 'lo',
    'target_host': '127.0.0.1'
}

bw_tc('observed_tls_version', bw_res.PASSED, params1, bw_tc_base_sim('passive'))
