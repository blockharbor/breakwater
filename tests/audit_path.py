# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# Custom audits loaded with --audit-path: loading, rejection, and what
# `bw_cli info --json` reports about where an audit came from.

import os
import sys
import json
import atexit
import shutil
import hashlib
import tempfile
import subprocess

from tests.base import *

BW_CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bw_cli.py')

def audit_source(name, extra=''):
    return f'''from framework import *

@register_audit("{name}")
class {name}(AuditRunner):
    parameters = [Parameter("flag", "Flag", "0", "1 makes the audit fail")]
    friendly_name = "{name}"
    description = "Fails when flag is 1"
    fail_condition = "flag is 1"
{extra}
    def run_audit(self):
        return {{"pass_rules": {{"vulnerable": self.params["flag"] == "1"}}}}

    def format_results(self, results):
        return [{{"title": "{name}", "segments": []}}]
'''

def make_dir(files):
    d = tempfile.mkdtemp(prefix='bw_audit_path_')
    atexit.register(shutil.rmtree, d, ignore_errors=True)
    for name, code in files.items():
        with open(os.path.join(d, name), 'w') as f:
            f.write(code)
    return d

def sha256_of(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def expect_load_error(path, text):
    try:
        load_audit_path(path)
    except AuditLoadError as e:
        assert text in str(e), f'unexpected error: {e}'
        return
    raise AssertionError(f'{path} loaded without an error')

def bw_cli(*args):
    return subprocess.run([sys.executable, BW_CLI, *args], capture_output=True, text=True, timeout=60)


# A custom audit runs through the same path as the built-in ones
custom_dir = make_dir({'example_custom_flag.py': audit_source('example_custom_flag')})
load_audit_path(custom_dir)
bw_tc('example_custom_flag', bw_res.PASSED, {'flag': '0'}, bw_tc_base_sim('custom_audit'))
bw_tc('example_custom_flag', bw_res.FAILED, {'flag': '1'}, bw_tc_base_sim('custom_audit'))


def describe_custom():
    path = os.path.join(custom_dir, 'example_custom_flag.py')
    d = describe_audit('example_custom_flag')
    assert d['source'] == path, d['source']
    assert d['sha256'] == sha256_of(path), d['sha256']
    assert d['fileName'] == 'example_custom_flag.py', d['fileName']
    assert d['isCustom'] is True
bw_tc_func('audit_path.describe_custom', describe_custom)

def describe_builtin():
    d = describe_audit('uds_security_access')
    assert d['source'].endswith(os.path.join('audits', 'can', 'uds_security_access.py')), d['source']
    assert d['sha256'] == sha256_of(d['source']), d['sha256']
    assert d['isCustom'] is False
bw_tc_func('audit_path.describe_builtin', describe_builtin)

def single_file():
    d = make_dir({'example_custom_single.py': audit_source('example_custom_single'),
                  'example_custom_other.py': audit_source('example_custom_other')})
    load_audit_path(os.path.join(d, 'example_custom_single.py'))
    assert 'example_custom_single' in list_audits()
    assert 'example_custom_other' not in list_audits()
bw_tc_func('audit_path.single_file', single_file)

def skips_private_files():
    d = make_dir({'_helper.py': audit_source('example_custom_private'),
                  'example_custom_public.py': audit_source('example_custom_public')})
    load_audit_path(d)
    assert 'example_custom_public' in list_audits()
    assert 'example_custom_private' not in list_audits()
bw_tc_func('audit_path.skips_private_files', skips_private_files)

def broken_file_skipped():
    # The broken file registers an audit before it fails; that is rolled back
    broken = 'from framework import *\n' + audit_source('example_custom_half') + '\nraise RuntimeError("broken")\n'
    d = make_dir({'a_broken.py': broken, 'b_good.py': audit_source('example_custom_good')})
    load_audit_path(d)
    assert 'example_custom_good' in list_audits()
    assert 'example_custom_half' not in list_audits()
bw_tc_func('audit_path.broken_file_skipped', broken_file_skipped)

def builtin_clash_rejected():
    builtin = list_audits()['uds_security_access']
    d = make_dir({'clash.py': audit_source('uds_security_access')})
    expect_load_error(d, 'already loaded')
    assert list_audits()['uds_security_access'] is builtin
bw_tc_func('audit_path.builtin_clash_rejected', builtin_clash_rejected)

def custom_clash_rejected():
    d1 = make_dir({'one.py': audit_source('example_custom_twice')})
    d2 = make_dir({'two.py': audit_source('example_custom_twice')})
    load_audit_path(d1)
    expect_load_error(d2, 'already loaded')
    assert describe_audit('example_custom_twice')['source'] == os.path.join(d1, 'one.py')
bw_tc_func('audit_path.custom_clash_rejected', custom_clash_rejected)

def bad_paths_rejected():
    expect_load_error(os.path.join(custom_dir, 'missing.py'), 'does not exist')
    d = make_dir({'notes.txt': 'not an audit'})
    expect_load_error(os.path.join(d, 'notes.txt'), 'not a .py file')
bw_tc_func('audit_path.bad_paths_rejected', bad_paths_rejected)

def cli_info_and_run():
    path = os.path.join(custom_dir, 'example_custom_flag.py')
    # --audit-path is accepted before and after the command
    for args in (['--audit-path', custom_dir, 'info', 'example_custom_flag', '--json'],
                 ['info', 'example_custom_flag', '--json', '--audit-path', path]):
        r = bw_cli(*args)
        assert r.returncode == 0, r.stderr
        d = json.loads(r.stdout)
        assert d['source'] == path and d['sha256'] == sha256_of(path), d
    r = bw_cli('--audit-path', custom_dir, 'run', 'example_custom_flag', '-p', 'flag=1', '--json')
    assert r.returncode == 1, r.stderr
    assert json.loads(r.stdout)['pass_rules']['vulnerable'] is True
    r = bw_cli('run', 'example_custom_flag')
    assert r.returncode == os.EX_USAGE, r.stderr
bw_tc_func('audit_path.cli_info_and_run', cli_info_and_run)

def cli_load_error():
    r = bw_cli('--audit-path', make_dir({'clash.py': audit_source('uds_security_access')}), 'ls')
    assert r.returncode == os.EX_USAGE, r.returncode
    assert 'already loaded' in r.stderr, r.stderr
bw_tc_func('audit_path.cli_load_error', cli_load_error)
