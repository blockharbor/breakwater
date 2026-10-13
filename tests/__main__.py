# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# The goal of this file is to run all unit tests and display their results.
# the vast majority of the logic lives in tests/base.py

import sys
from tests.base import *

import tests.can
import tests.net
import tests.audit_path
import tests.params

failures = []
for tc in bw_tc.all_test_cases:
    result = tc.exec()
    print('\033[92m[PASS]\033[0m' if result else '\033[91m[FAIL]\033[0m', '\033[96m', tc, '\033[0m')
    if not result:
        tc.report('-v' in sys.argv)
        failures.append(tc)
    elif '-v' in sys.argv:
        tc.report(True)

print('=== TEST RESULTS ===')
n_total = len(bw_tc.all_test_cases)
n_failed = len(failures)
n_passed = n_total - n_failed

print(f'TESTS EXECUTED: {n_total}')
print(f'TESTS PASSED: {n_passed}')
print(f'TESTS FAILED: {n_failed}')
if n_total:
    print(f'PASS RATE: {n_passed/n_total*100.0:.2f}%')

if n_failed:
    print(f'=== FAILURES ===')
    for tc in failures:
        print('\t', tc)

sys.exit(1 if n_failed else 0)

