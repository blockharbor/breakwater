# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os
import time
import can
import socket
import threading

from framework import *
list_audits()                   # registers the built-in audits into `audits`

from utils.udsutil import *

import ssl
import http.server

class bw_res:
    PASSED = 0,
    FAILED = 1,
    NORESULT = 2,

    def string(res):
        return 'pass' if res == bw_res.PASSED else 'fail' if res == bw_res.FAILED else 'no_result'

class bw_tc_logger:
    def __init__(self, sim):
        self.sim = sim

    def log(self, log_level, msg):
        self.sim.log.append([time.time(), f'[{log_level}] {msg}'])

    def info(self, *args):
        self.log('INFO', ' '.join(str(arg) for arg in args))

    def debug(self, *args):
        pass    # debug messages are left out of the sim log

    def warn(self, *args):
        self.log('WARN', ' '.join(str(arg) for arg in args))

    def error(self, *args):
        self.log('ERROR', ' '.join(str(arg) for arg in args))

class bw_tc:
    all_test_cases = []
    STATUS = {Status.PASSED: bw_res.PASSED, Status.FAILED: bw_res.FAILED, Status.NO_RESULT: bw_res.NORESULT}

    def __init__(self, audit_name, expected, params, sim):
        self.audit_name = audit_name
        self.audit = audits[audit_name]
        self.expected_result = expected
        self.params = params
        self.sim = sim
        self.logger = bw_tc_logger(self.sim)
        self.tc_duration = 0
        self.result = None
        self.actual = None
        self.error = None

        bw_tc.all_test_cases.append(self)

    def __repr__(self):
        exp_str = 'pass' if self.expected_result == bw_res.PASSED else 'fail' if self.expected_result == bw_res.FAILED else 'no_result'
        return f'{self.audit_name}.{self.sim.name}.{exp_str}'.ljust(80) + f'{len(self.sim.log)} msgs'.rjust(12) + f'{(self.tc_duration//60):02.0f}:{self.tc_duration%60:05.2f}'.rjust(10)

    def exec(self):
        """Runs the audit through framework.run_audit, the same path bw_cli takes, so
        format_results always runs too. An exception anywhere (sim, audit, report)
        fails the case instead of stopping the whole run, and the sim is always stopped."""
        import traceback
        started = False
        try:
            self.sim.start()
            started = True
            start_time = time.time()
            self.result = run_audit(self.audit_name, self.params, self.logger)
            self.tc_duration = time.time() - start_time
            if 'traceback' in self.result.raw:
                self.error = f'audit raised {self.result.raw["error"]}\n{self.result.raw["traceback"]}'
            elif self.result.raw.get('missing_dependencies'):
                self.error = f'missing dependencies: {", ".join(self.result.raw["missing_dependencies"])}'
            self.actual = bw_tc.STATUS[self.result.status]
        except Exception:
            self.error = traceback.format_exc()
        finally:
            if started:
                try:
                    self.sim.stop()
                except Exception:
                    self.error = self.error or traceback.format_exc()

        return self.error is None and self.actual == self.expected_result

    def report(self, show_log=False):
        for entry in self.sim.log if show_log else []:
            print('\t', f'[{entry[0]:.2f}] {entry[1]}')
        if self.error:
            print('[error]', self.error)
        actual = bw_res.string(self.actual) if self.actual is not None else 'none'
        print(f'[result] expected {bw_res.string(self.expected_result)} actual {actual}')
        if self.result:
            print('[raw]', self.result.raw)
            for fmt in self.result.report:
                print('#', fmt['title'])
                for seg in fmt['segments']:
                    print('\t', seg)


class bw_tc_base_sim:
    def __init__(self, name):
        self.name = name
        self.simulating = False
        # list of [time, string] describing the actions that were simulated
        self.log = []

    def __repr__(self):
        return self.name

    def simulate(self):
        while self.simulating:
            time.sleep(1)
        # can do anything here to simulate DUT (keep state, etc)
        # supplies start, stop, log and name to the test case
        # but you can even overwrite start/stop and popen some other process/sim

    def start(self):
        if not self.simulating:
            self.simulating = True
            self.sim_thread = threading.Thread(target=self.simulate)
            self.sim_thread.start()

    def stop(self, timeout=None):
        self.simulating = False
        self.sim_thread.join(timeout=timeout)

class bw_tc_sim_can(bw_tc_base_sim):
    def __init__(self, name, params, actions, default_response = bytes([ 0xfe, 0, 0x80 ])):
        super().__init__(name)

        self.params = params
        self.req_arb = Parameter.number(self.params['req_arb'])
        self.resp_arb = Parameter.number(self.params['resp_arb'])
        self.is_fd = Parameter.boolean(self.params['is_fd'])
        self.is_extended_id = Parameter.boolean(self.params['extended_id'])

        self.default_response = default_response
        self.cues = {}
        for action in actions:
            self.cues[action[0]] = action[1]

    def start(self):
        self.bus = can.Bus(self.params['device'], interface='socketcan', fd=self.is_fd)
        super().start()

    def stop(self):
        super().stop()
        self.bus.shutdown()

    def queue(self, cue, action):
        self.cues[cue] = action

    def simulate(self):
        while self.simulating:
            msg = self.bus.recv(timeout=0.1)
            if not msg or len(msg) < 1:
                continue
            if msg.arbitration_id != self.req_arb:
                continue
            response = self.default_response
            for cue in self.cues.keys():
                if msg.data.startswith(cue):
                    action = self.cues[cue]
                    response = action(msg.data, self) if callable(action) else action
                    break
            if response:
                self.bus.send(can.Message(arbitration_id=self.resp_arb, data=response, is_extended_id=self.is_extended_id, is_fd=self.is_fd))
                self.log.append([time.time(), f'{msg.data.hex()} -> {response.hex()}'])

class bw_tc_sim_iso14229(bw_tc_base_sim):
    def __init__(self, name, params, actions, error_unknown = True):
        super().__init__(name)

        self.params = params
        self.req_arb = Parameter.number(self.params['req_arb'])
        self.resp_arb = Parameter.number(self.params['resp_arb'])
        self.is_fd = Parameter.boolean(self.params['is_fd'])
        self.is_extended_id = Parameter.boolean(self.params['extended_id'])

        self.error_unknown = error_unknown
        self.cues = {}
        for action in actions:
            self.cues[action[0]] = action[1]

    def start(self):
        self.bus = can.Bus(self.params['device'], interface='socketcan', fd=self.is_fd)
        self.tp = mk_isotp(self.bus, [self.resp_arb, self.req_arb], extended_id=self.is_extended_id, is_fd=self.is_fd)
        super().start()

    def stop(self):
        super().stop()
        self.bus.shutdown()

    def queue(self, cue, action):
        self.cues[cue] = action

    def simulate(self):
        while self.simulating:
            msg = self.tp.recv()
            if not msg or len(msg) < 1:
                continue
            response = bytes([ 0x7f, msg[0], 0x80 ]) if self.error_unknown else None
            for cue in self.cues.keys():
                if msg.startswith(cue):
                    action = self.cues[cue]
                    response = action(msg, self) if callable(action) else action
                    break
            if response:
                self.tp.send(response)
                self.log.append([time.time(), f'{msg.hex()} -> {response.hex()}'])

_test_cert = None

def test_cert():
    """A throwaway self-signed CN=localhost certificate for the TLS sims, made
    once per run so no private key has to live in the repo."""
    global _test_cert
    if _test_cert is None:
        import tempfile, subprocess
        d = tempfile.mkdtemp(prefix='bw-tests-')
        crt, key = os.path.join(d, 'server.crt'), os.path.join(d, 'server.key')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', key, '-out', crt],
                       check=True, capture_output=True)
        _test_cert = (crt, key)
    return _test_cert

class bw_tc_sim_tls(bw_tc_base_sim):
    def __init__(self, name, params, versions, ciphers):
        super().__init__(name)

        self.params = params
        self.target_port = Parameter.number(params['target_port'])

        self.versions = versions
        self.ciphers = ciphers

    def start(self):
        server_address = (self.params["target_host"], self.target_port)
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(server_address)
        self.socket.listen(5)
        self.socket.settimeout(0.2)
        
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        if 1 not in self.versions:
            self.context.options |= ssl.OP_NO_TLSv1
        if 1.1 not in self.versions:
            self.context.options |= ssl.OP_NO_TLSv1_1
        if 1.2 not in self.versions:
            self.context.options |= ssl.OP_NO_TLSv1_2
        if 1.3 not in self.versions:
            self.context.options |= ssl.OP_NO_TLSv1_3

        if self.ciphers:
            self.context.set_ciphers(self.ciphers)
        certfile, keyfile = test_cert()
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        super().start()

    def stop(self):
        super().stop(1.0)
        self.socket.close()

    def simulate(self):
        while self.simulating:
            try:
                newsocket, fromaddr = self.socket.accept()
            except TimeoutError:
                continue

            try:
                connstream = self.context.wrap_socket(newsocket, server_side=True)
                cipher = connstream.cipher()
                self.log.append([time.time(), f'{fromaddr[0]}:{fromaddr[1]} {cipher[0]} {cipher[1]} {cipher[2]}'])
            except Exception as e:
                newsocket.close()
                continue

            try:
                connstream.send(b'hello from breakwater')
            finally:
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()

