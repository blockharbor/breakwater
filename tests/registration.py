# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# Checks that every built-in audit registers, and that registering imports none
# of the audits' dependencies. bw_cli imports all of audits/ to list them, before
# --install-deps can install anything, so a single audit that imports a
# dependency at module level stops `ls`, `info` and every `run` on a machine
# that lacks it. Dependencies are imported inside run_audit instead.
#
# Run from the top of a checkout: python3 -m tests.registration
# It needs nothing from requirements.txt, and gives the same answer whether or
# not those packages are installed.

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def audit_files():
    """{name: path} for every audits/<interface>/<name>.py."""
    files = {}
    audits_dir = os.path.join(ROOT, 'audits')
    for iface in sorted(os.listdir(audits_dir)):
        iface_dir = os.path.join(audits_dir, iface)
        if not os.path.isdir(iface_dir) or iface.startswith(('_', '.')):
            continue
        for f in sorted(os.listdir(iface_dir)):
            if f.endswith('.py') and not f.startswith(('_', '.')):
                files[f[:-3]] = os.path.join('audits', iface, f)
    return files

def requirement_names():
    """Distribution names in requirements.txt."""
    names = []
    with open(os.path.join(ROOT, 'requirements.txt')) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if line:
                names.append(re.split(r'[<>=!~\[;\s]', line)[0])
    return names

def main():
    before = set(sys.modules)
    sys.path.insert(0, ROOT)
    import framework

    try:
        audits = framework.list_audits()
    except Exception as e:
        print(f'FAIL: importing audits/ raised {type(e).__name__}: {e}')
        print('An audit imports something at module level that is not installed here. '
              'Import dependencies inside run_audit, not at the top of the file.')
        return 1

    failures = []

    # One audit per file, registered under the file's name and imported by
    # its package's __init__.py.
    files = audit_files()
    for name in sorted(files.keys() - audits.keys()):
        failures.append(f'{files[name]} registers no audit named {name}: '
                        f'is it imported in its package\'s __init__.py, under that name?')
    for name in sorted(audits.keys() - files.keys()):
        failures.append(f'audit {name} has no file of the same name under audits/')

    # Registering must not have imported a dependency, even one that happens to
    # be installed here: on a machine without it, the import fails instead.
    deps = {}
    for dep in requirement_names():
        deps.setdefault(framework._import_name(dep), set()).add('requirements.txt')
    for name, cls in audits.items():
        for dep in cls.dependencies:
            deps.setdefault(framework._import_name(dep), set()).add(name)
    for module in sorted(deps):
        if module in sys.modules and module not in before:
            failures.append(f'registering the audits imported {module} (a dependency of '
                            f'{", ".join(sorted(deps[module]))}): import it inside run_audit')

    # Every audit describes itself, as `bw_cli info --json` needs.
    for name in sorted(audits):
        try:
            framework.describe_audit(name)
        except Exception as e:
            failures.append(f'describe_audit({name}) raised {type(e).__name__}: {e}')

    for failure in failures:
        print('FAIL:', failure)
    print(f'{len(audits)} audits registered, {len(failures)} problem(s)')
    return 1 if failures else 0

if __name__ == '__main__':
    sys.exit(main())
