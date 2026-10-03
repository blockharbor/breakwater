# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from abc import abstractmethod
from enum import IntEnum
from typing import Any, NamedTuple

import os
import re
import sys
import json
import logging
import importlib
import importlib.util
import traceback
import subprocess

class Logger:
    """The logger audits write to. The default forwards to the stdlib logger
    `name`; override log() to send messages somewhere else."""
    LEVELS = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARN': logging.WARNING, 'ERROR': logging.ERROR}

    def __init__(self, name='breakwater'):
        self.name = name

    def log(self, log_level, msg):
        logging.getLogger(self.name).log(self.LEVELS.get(log_level, logging.INFO), msg)

    def info(self, *args):
        self.log('INFO', ' '.join(map(str, args)))

    def debug(self, *args):
        self.log('DEBUG', ' '.join(map(str, args)))

    def warn(self, *args):
        self.log('WARN', ' '.join(map(str, args)))

    def error(self, *args):
        self.log('ERROR', ' '.join(map(str, args)))

class Report:
    @staticmethod
    def create_text_segment(text):
        return text

    @staticmethod
    def create_heading_segment(text):
        return text

    @staticmethod
    def create_list_segment(lst):
        return "".join([f"\t- {e}\n" for e in lst])

audits = dict()

def register_audit(name):
    def inner(cls):
        audits[name] = cls
        return cls
    return inner

_builtin_loaded = False

def _load_builtin():
    global _builtin_loaded
    if not _builtin_loaded:
        importlib.import_module('audits')
        _builtin_loaded = True

def list_audits():
    """All registered audits as {name: AuditRunner subclass}, built-ins included."""
    _load_builtin()
    return dict(audits)

def get_audit(name):
    _load_builtin()
    if name not in audits:
        raise KeyError(f'unknown audit: {name}')
    return audits[name]

class Parameter:
    name = ""
    value = None
    friendly_name = ""
    default_value = None
    description = ""
    required = True

    def __init__(
        self, name, friendly_name, default_value, description="", required=True
    ):
        self.name = name
        self.value = default_value
        self.friendly_name = friendly_name
        self.default_value = default_value
        self.description = description
        self.required = required

    @staticmethod
    def number(str_value):
        return int(str_value, 0)

    @staticmethod
    def boolean(str_value):
        return str_value in ['True', 'true', '1']

# Distribution name -> import name, for the dependencies where the two differ.
DEP_MODULES = {
    'python-can': 'can',
    'python_can': 'can',
    'can-isotp': 'isotp',
    'ipy': 'IPy',
    'pyserial': 'serial',
}

def _import_name(dep):
    dist = re.split(r'[<>=!~\[;\s]', dep)[0]
    return DEP_MODULES.get(dist.lower(), dist.replace('-', '_'))

def _is_available(module):
    if module in sys.modules:
        return True
    try:
        if importlib.util.find_spec(module) is not None:
            return True
    except Exception:
        pass
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False

def missing_dependencies(deps):
    return [dep for dep in deps if not _is_available(_import_name(dep))]

def dependency_dir():
    """Where `--install-deps` puts audit dependencies: one directory per Python
    version, since compiled packages only work with the interpreter they were
    built for. BW_HOME overrides the base directory."""
    home = os.environ.get('BW_HOME') or os.path.join(os.path.expanduser('~'), '.local', 'share', 'breakwater')
    return os.path.join(home, 'lib', f'python{sys.version_info.major}.{sys.version_info.minor}')

def enable_dependency_dir():
    """Appends dependency_dir() to sys.path. Appended rather than prepended, so a
    package installed in the environment itself wins over the copy in there."""
    path = dependency_dir()
    if path not in sys.path:
        sys.path.append(path)
    importlib.invalidate_caches()

def pip_install(deps, log):
    """Installs missing dependencies into dependency_dir(), never into the
    environment Breakwater runs from."""
    deps = missing_dependencies(deps)
    if len(deps) == 0:
        return True

    if not _is_available('pip'):
        log.error(f'Dependencies {deps} are missing and pip is not available to install them.')
        return False

    target = dependency_dir()
    try:
        log.warn(f'Attempting to install {deps} into {target}')
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--target", target] + deps)
        enable_dependency_dir()
        log.info(f'Successfully installed {deps}')
        return True
    except Exception as e:
        log.error(f'Failed to install dependencies: {e}')

    return False

class AuditRunner:
    severity_list = ["n/a", "information", "low", "medium", "high", "critical"]
    log = Logger()
    params = {}
    parameters = []
    dependencies = []
    relevant_protocols = []
    relevant_interfaces = []
    relevant_mitigations = []
    bw_audit_id = "N/A"

    def __init__(self, params: dict, logger=None):
        self.params = params
        if logger != None:
            self.log = logger

    def install_dependencies(self) -> bool:
        return pip_install(self.dependencies, self.log)

    @abstractmethod
    def run_audit(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def format_results(self, results):
        return results

class Status(IntEnum):
    PASSED = 0
    FAILED = 1
    NO_RESULT = 2

class AuditResult(NamedTuple):
    """Unpacks like the (code, raw, formatted) tuple run_audit used to return."""
    status: Status
    raw: dict
    report: list

def get_version():
    try:
        from _version import VERSION    # written by `make package`
    except ImportError:                 # running from a checkout
        VERSION = 'develop'
    return VERSION

def _number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

def describe_audit(name):
    """The audit's metadata as a JSON-safe dict with camelCase keys
    (friendlyName, failCondition, ...)."""
    audit = get_audit(name)
    return {
        'name': name,
        'friendlyName': audit.friendly_name,
        'fileName': audit.__module__.rsplit('.', 1)[-1] + '.py',
        'description': audit.description,
        'failCondition': audit.fail_condition,
        'relevantMitigations': list(audit.relevant_mitigations),
        'parameters': {
            p.name: {
                'friendly_name': p.friendly_name,
                'default_value': p.default_value,
                'description': p.description,
                'required': p.required,
            } for p in audit.parameters
        },
        'defaultParameters': {p.name: p.default_value for p in audit.parameters},
        'auditId': audit.bw_audit_id,
        'estimatedTime': _number(getattr(audit, 'estimated_time_in_minutes', None)),
        'isCustom': not audit.__module__.startswith('audits.'),
        'interface': audit.relevant_interfaces[0] if audit.relevant_interfaces else None,
        'relevantInterfaces': list(audit.relevant_interfaces),
        'relevantProtocols': list(audit.relevant_protocols),
        'dependencies': list(audit.dependencies),
        'testOutcomes': getattr(audit, 'test_outcomes', {}),
    }

def _error_report(title, segments):
    return [{'title': title, 'segments': segments}]

def run_audit(audit_name, params=None, log=None, install_deps=False):
    """Runs one audit and returns an AuditResult. Missing parameters take their
    defaults. Missing dependencies are installed only when install_deps is set;
    otherwise the result is NO_RESULT and raw['missing_dependencies'] lists them."""
    audit = get_audit(audit_name)
    log = log if log is not None else Logger(f'bw.{audit_name}')
    params = dict(params or {})
    log.warn(f"Running audit {audit.friendly_name}...")
    for p in audit.parameters:
        if p.name not in params.keys():
            params[p.name] = p.default_value
        log.debug(f"\t{p.name.ljust(16)} : {params[p.name]}")

    instance = audit(params, log)

    missing = missing_dependencies(audit.dependencies)
    if missing and not (install_deps and instance.install_dependencies()):
        missing = missing_dependencies(audit.dependencies)
        log.error(f'Missing dependencies {", ".join(missing)}, test run aborted.')
        return AuditResult(Status.NO_RESULT, {'error': f'missing dependencies: {", ".join(missing)}', 'missing_dependencies': missing}, _error_report(
            'Missing Dependencies',
            [
                Report.create_text_segment(
                    f'{audit.friendly_name} did not run because required dependencies are not available.'
                ),
                Report.create_heading_segment('Missing'),
                Report.create_list_segment(missing),
            ],
        ))

    try:
        results = instance.run_audit()
        formatted_results = instance.format_results(results)
    except Exception as e:
        tb = traceback.format_exc()
        log.error('Error during test execution')
        log.error(str(e))
        log.error(tb)
        return AuditResult(Status.NO_RESULT, {'error': f'{type(e).__name__}: {e}', 'traceback': tb}, _error_report(
            'Test Execution Exception',
            [
                Report.create_text_segment(
                    f'{audit.friendly_name} raised an exception and did not complete.'
                ),
                Report.create_heading_segment('Exception'),
                Report.create_text_segment(f'{type(e).__name__}: {e}'),
                Report.create_heading_segment('Parameters'),
                Report.create_list_segment([f'{k} = {v}' for k, v in params.items()]),
                Report.create_heading_segment('Traceback'),
                Report.create_text_segment(tb),
            ],
        ))
    status = Status.NO_RESULT
    if "pass_rules" in results:
        status = Status.FAILED if results["pass_rules"]["vulnerable"] else Status.PASSED
    log.warn(f'{audit.friendly_name} {status.name.replace("_", " ")}')
    return AuditResult(status, results, formatted_results)
