#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC
"""bw_cli: run Breakwater audits and discovery from the command line."""

import os
import sys
import json
import time
import shutil
import argparse

from framework import (DEP_MODULES, Logger, Status, describe_audit, dependency_dir, enable_dependency_dir,
                       get_version, list_audits, missing_dependencies, run_audit)

DOCS_URL = 'https://docs.blockharbor.io'

EPILOG = """examples:
  bw_cli ls
  bw_cli info uds_security_access
  bw_cli info --json
  bw_cli run uds_security_access -p device=can0 -p req_arb=0x7e0 -p resp_arb=0x7e8
  bw_cli run telnet_check -p target_host=10.1.0.1 --report
  bw_cli discover -p iface=can0
  bw_cli deps

exit codes:
  0  passed / ok           1  failed (target vulnerable)    2  no result
  64 usage (bad args)      69 missing dependencies
"""

class UsageError(Exception):
    pass

class cli_logger(Logger):
    def log(self, log_level, msg):
        print(f'{time.time():.4f}: {log_level} [{self.name}]: {msg}', file=sys.stderr, flush=True)

def _style(text, code, stream=sys.stdout):
    return f'\033[{code}m{text}\033[0m' if stream.isatty() else text

def _banner(n_audits):
    try:
        devices = ', '.join(sorted(os.listdir('/sys/class/net/')))
    except OSError:
        devices = 'unknown'
    print(f"\033[31m\033[1m  ╭──────╮  \033[0m\033[1m Breakwater {get_version()}\033[0m", file=sys.stderr)
    print(f"\033[31m\033[1m  │      │  \033[0m\033[0m Devices: {devices}\033[0m", file=sys.stderr)
    print(f"\033[31m\033[1m  │    ⬤ │  \033[0m\033[0m Loaded {n_audits} Audits\033[0m", file=sys.stderr)
    print(f"\033[31m\033[1m  ╰──────╯  \033[0m", file=sys.stderr)
    print('', file=sys.stderr)

def _unavailable(what, e):
    dist = {module: dist for dist, module in DEP_MODULES.items()}.get(e.name, e.name)
    print(f'bw_cli: {what} is unavailable: {e}', file=sys.stderr)
    if e.name:
        print(f'bw_cli: install it with: {sys.executable} -m pip install --target {dependency_dir()} {dist}', file=sys.stderr)
    return os.EX_UNAVAILABLE

def _params(groups):
    params = {}
    for group in groups or []:
        for kv in group:
            key, sep, value = kv.partition('=')
            if not sep or not key:
                raise UsageError(f'parameter "{kv}" is not in key=value format')
            params[key] = value
    return params

def _audit_name(args, audits):
    name = args.audit or args.audit_opt
    if not name:
        raise UsageError('specify an audit to run, e.g. `bw_cli run uds_security_access`')
    if name not in audits:
        raise UsageError(f'audit {name} not found, see `bw_cli ls`')
    return name

def _example(d):
    return f"bw_cli run {d['name']} " + ' '.join(f"-p {k}={v}" for k, v in d['defaultParameters'].items())

def _info_text(d):
    lines = [
        f"{_style(d['friendlyName'], '1')} ({d['name']})  {d['auditId']}",
        f"  {d['description']}",
        f"  Fail condition: {d['failCondition']}",
        f"  Interfaces: {', '.join(d['relevantInterfaces']) or '-'}",
        f"  Protocols: {', '.join(d['relevantProtocols']) or '-'}",
        f"  Mitigations: {', '.join(d['relevantMitigations']) or '-'}",
        f"  Dependencies: {', '.join(d['dependencies']) or 'none'}",
        f"  Estimated time: {d['estimatedTime']} min",
        "  Parameters:",
    ]
    for name, p in d['parameters'].items():
        lines.append(f"    {name.ljust(16)} {p['friendly_name']} (default {p['default_value']!r}): {p['description']}")
    lines.append(f"  Example: {_example(d)}")
    return '\n'.join(lines)

def _info_markdown(d):
    lines = [
        f"## {d['friendlyName']}", "",
        d['description'], "",
        f"**Fail Condition**: {d['failCondition']}", "",
        "### Parameters", "",
        "| Name | Default Value | Description |",
        "| - | -- | ------ |",
    ]
    for p in d['parameters'].values():
        lines.append(f"| {p['friendly_name']} | {p['default_value']} | {p['description']} |")
    lines += ["", "### Outcomes"]
    for outcome, v in d['testOutcomes'].items():
        lines += ["", f"**{outcome}**: {v['description']}", "", "Recommendations:"]
        lines += [f"- {r}" for r in v['recommendations']]
        lines.append("")
    lines += ["### Example Usage", "", "```bash", _example(d), "```", ""]
    return '\n'.join(lines)

def _cmd_ls(args):
    print(f'Documentation available at: {DOCS_URL}')
    for name, audit in list_audits().items():
        interfaces = ', '.join(audit.relevant_interfaces)
        print(f"{_style(audit.friendly_name, '1')} ({name}) [{interfaces}]")
    return os.EX_OK

def _cmd_info(args):
    audits = list_audits()
    if args.audit and args.audit not in audits:
        raise UsageError(f'audit {args.audit} not found, see `bw_cli ls`')
    described = [describe_audit(name) for name in ([args.audit] if args.audit else audits)]
    if args.json:
        print(json.dumps(described[0] if args.audit else described, indent=4))
    elif args.markdown:
        print('\n'.join(_info_markdown(d) for d in described))
    else:
        print('\n\n'.join(_info_text(d) for d in described))
    return os.EX_OK

def _cmd_run(args):
    name = _audit_name(args, list_audits())
    params = _params(args.parameter)
    logger = cli_logger(name)
    result = run_audit(name, params, logger, install_deps=args.install_deps)

    if result.raw.get('missing_dependencies'):
        logger.error(f"Missing dependencies: {', '.join(result.raw['missing_dependencies'])}. "
                     f"Install them with `bw_cli run {name} --install-deps`.")
        return os.EX_UNAVAILABLE

    if args.report:
        for section in result.report:
            print(_style(section['title'], '1'))
            for segment in section['segments']:
                print(segment)
    else:
        print(json.dumps(result.raw, indent=4))

    colour = {Status.PASSED: '32', Status.FAILED: '31', Status.NO_RESULT: '33'}[result.status]
    print(_style(result.status.name.replace('_', ' '), '1;' + colour, sys.stderr), file=sys.stderr)
    return int(result.status)

def _cmd_discover(args):
    iface = _params(args.parameter).get('iface')
    try:
        from discover.can import discover_can
        from discover.xcp import discover_xcp
    except ImportError as e:
        return _unavailable('discovery', e)
    log = cli_logger('discover.' + (iface if iface else 'all'))
    res = discover_can(iface, log) + discover_xcp(iface, log)
    print(json.dumps(res, indent=4))
    return os.EX_OK

def _cmd_interfaces(args):
    try:
        from discover.hardware import get_interfaces
    except ImportError as e:
        return _unavailable('interface listing', e)
    print(json.dumps(get_interfaces(), indent=4))
    return os.EX_OK

def _cmd_deps(args):
    path = dependency_dir()
    if args.clean:
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f'Removed {path}')
        else:
            print(f'Nothing to remove, {path} does not exist')
        return os.EX_OK
    print(f"Dependency directory: {path}{'' if os.path.isdir(path) else ' (not created yet)'}")
    for name, audit in list_audits().items():
        if not audit.dependencies:
            continue
        missing = missing_dependencies(audit.dependencies)
        state = _style(f"missing {', '.join(missing)}", '33') if missing else _style('ok', '32')
        print(f"  {name.ljust(24)} {', '.join(audit.dependencies).ljust(28)} {state}")
    return os.EX_OK

def _add_param_arg(p):
    p.add_argument('-p', '--parameter', action='append', nargs='+', metavar='KEY=VALUE',
                   help='set a parameter, e.g. -p device=can0 (repeatable)')

def _build_parser():
    parser = argparse.ArgumentParser(
        prog='bw_cli', description='Security audits and target discovery for automotive CAN and network interfaces.',
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-V', '--version', action='version', version=f'Breakwater {get_version()}')
    sub = parser.add_subparsers(dest='command', metavar='command')

    p = sub.add_parser('ls', help='list audits')
    p.set_defaults(func=_cmd_ls)

    p = sub.add_parser('info', help='show audit metadata')
    p.add_argument('audit', nargs='?', help='one audit (default: all)')
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument('--markdown', action='store_true', help='print a Markdown docs page')
    fmt.add_argument('--json', action='store_true', help='print machine-readable JSON')
    p.set_defaults(func=_cmd_info)

    p = sub.add_parser('run', help='run one audit')
    p.add_argument('audit', nargs='?', help='audit to run')
    p.add_argument('-a', '--audit', dest='audit_opt', help=argparse.SUPPRESS)
    _add_param_arg(p)
    p.add_argument('--install-deps', action='store_true',
                   help="install missing audit dependencies into Breakwater's own directory (see `bw_cli deps`)")
    p.add_argument('--report', action='store_true', help='print the formatted report instead of the raw JSON result')
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser('discover', help='discover CAN (UDS) and XCP targets, -p iface=NAME limits it to one interface')
    _add_param_arg(p)
    p.set_defaults(func=_cmd_discover)

    p = sub.add_parser('interfaces', help='list the host interfaces as JSON')
    p.set_defaults(func=_cmd_interfaces)

    p = sub.add_parser('deps', help="show or delete Breakwater's own dependency directory")
    p.add_argument('--clean', action='store_true', help='delete the directory')
    p.set_defaults(func=_cmd_deps)

    return parser

def main(argv=None):
    enable_dependency_dir()
    _banner(len(list_audits()))     # before parsing, so --help and usage errors show it too

    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, 'command', None):
        parser.print_help()
        return os.EX_OK

    try:
        return args.func(args)
    except UsageError as e:
        print(f'bw_cli: {e}', file=sys.stderr)
        return os.EX_USAGE

if __name__ == '__main__':
    sys.exit(main())
