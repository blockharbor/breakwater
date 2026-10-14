# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *
from utils.netutil import temporary_static_ip, tcp_reachable
@register_audit("telnet_check")
class telnet_check(AuditRunner):
    parameters = [
        Parameter("iface", "Network Interface", "eth0", "The network interface on which to interact"),
        Parameter("target_host", "Target IP", "10.1.0.1", "The IP to use when attempting to connect to"),
        Parameter("target_port", "Telnet Port", "23", "The port number to attempt to connect to telnet on"),
        Parameter("temp_ip", "Temporary IP", "", "A temporary IP address to set on the network interface, which will be reset after the test completes"),
        Parameter("temp_mask", "Temporary Subnet Mask", "255.255.255.0", "A temporary subnet mask to set on the network interface, which will be reset after the test completes"),
    ]
    dependencies = []
    friendly_name = "Telnet Check"
    description = "Attempts to log in to a telnet server at the specified IP and port with anonymous and guest credentials."
    fail_condition = "If any of the credentials gives shell access, the test will be marked failed."
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["Automotive Ethernet", "WiFi", "Cellular"]
    bw_audit_id = "TS_NET_0014"
    estimated_time_in_minutes = "1"
    test_outcomes = {
        "SUCCESS": {
            "description": "The specified Telnet server rejected the anonymous and guest logins.",
            "recommendations": [
                "Ensure the credentials are secure and ideally unique per device."
            ]
        },
        "NO_RESPONSE": {
            "description": "The test failed to communicate with the specified `target_host`",
            "recommendations": [
                "Check test parameters, physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "The specified Telnet server allows login with anonymous or guest credentials.",
            "recommendations": [
                "Review the offending Telnet server and modify that server's configuration."
            ]
        }
    }

    # Telnet commands and the options the server is allowed to enable (RFC 854/857/858)
    IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
    ECHO, SGA = 1, 3

    LOGIN_PROMPT = r'(login|username|user name)\s*:\s*\Z'
    PASSWORD_PROMPT = r'password\s*:\s*\Z'
    LOGIN_FAILURE = r'login incorrect|authentication fail|access denied|incorrect password'
    SHELL_PROMPT = r'[$#>]\s*\Z'

    @staticmethod
    def _validate_port(port: int) -> bool:
        return 1 <= port <= 65535

    def _negotiate(self, conn, data):
        """Strips telnet commands from received data, answering each option once:
        the server may echo and suppress go-ahead, everything else is refused.
        Returns the plain text and any incomplete command left at the end."""
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] != self.IAC:
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= len(data):
                break
            cmd = data[i + 1]
            if cmd == self.IAC:
                out.append(self.IAC)
                i += 2
            elif cmd in (self.DO, self.DONT, self.WILL, self.WONT):
                if i + 2 >= len(data):
                    break
                opt = data[i + 2]
                if (cmd, opt) not in self.answered:
                    self.answered.add((cmd, opt))
                    if cmd == self.DO:
                        conn.sendall(bytes([self.IAC, self.WONT, opt]))
                    elif cmd == self.WILL:
                        conn.sendall(bytes([self.IAC, self.DO if opt in (self.ECHO, self.SGA) else self.DONT, opt]))
                i += 3
            elif cmd == self.SB:
                end = data.find(bytes([self.IAC, self.SE]), i + 2)
                if end < 0:
                    break
                i = end + 2
            else:
                i += 2
        return out.decode('latin-1'), data[i:]

    def _read_until(self, conn, patterns, timeout=10):
        """Reads until one of the regex patterns matches the text received so far.
        Returns the index of the matching pattern, or None on timeout or close."""
        import re
        import time
        import socket

        deadline = time.time() + timeout
        while True:
            for idx, pattern in enumerate(patterns):
                if re.search(pattern, self.response, re.IGNORECASE):
                    return idx
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            conn.settimeout(remaining)
            try:
                data = conn.recv(4096)
            except socket.timeout:
                return None
            if not data:
                return None
            text, self.pending = self._negotiate(conn, self.pending + data)
            self.response += text

    def _send(self, conn, line):
        self.response = ''
        conn.sendall(line.encode('latin-1') + b'\r\n')

    def _try_login(self, target, port, user, password):
        """Logs in with the given credentials and runs `id`. Returns the line
        containing the uid if a shell was reached, None otherwise."""
        import socket

        self.answered = set()
        self.pending = b''
        self.response = ''
        conn = socket.create_connection((target, port), timeout=10)
        try:
            prompt = self._read_until(conn, [self.LOGIN_PROMPT, self.PASSWORD_PROMPT, self.SHELL_PROMPT])
            if prompt == 0:
                self._send(conn, user)
                prompt = self._read_until(conn, [self.PASSWORD_PROMPT, self.LOGIN_FAILURE, self.SHELL_PROMPT])
                if prompt == 1:
                    return None
                prompt = 1 if prompt == 0 else None
            if prompt == 1:
                self._send(conn, password)
                if self._read_until(conn, [self.LOGIN_FAILURE, self.LOGIN_PROMPT, self.SHELL_PROMPT]) in (0, 1):
                    return None
            self._send(conn, 'id')
            if self._read_until(conn, [r'uid=', self.LOGIN_FAILURE, self.LOGIN_PROMPT]) != 0:
                return None
            self._read_until(conn, [r'uid=.*\n'], timeout=1)
            return next((l.strip() for l in self.response.splitlines() if 'uid=' in l), None)
        finally:
            conn.close()

    def run_audit(self):
        target = self.params["target_host"]
        port = Parameter.number(self.params["target_port"])

        segments = []
        severity = "n/a"
        title = "Telnet Check Complete"

        self.temp_ip = temporary_static_ip(
            self.params["iface"],
            self.params["temp_ip"],
            self.params["temp_mask"],
            self.log,
        )

        if not self._validate_port(port):
            segments.append(
                Report.create_text_segment(
                    f"Invalid port:{port}, Please make sure the format is correct"
                )
            )
            return {"title": title, "segments": segments}

        if not tcp_reachable(target, port):
            segments.append(Report.create_text_segment(f"Could not reach the target server at {target}:{port}"))
            return {"title": title, "segments": segments}

        vulnerable = False
        acc_list = [('anonymous', ''), ('guest', 'guest')]
        for user, password in acc_list:
            creds = f'"{user}:{password}"'
            try:
                self.log.debug(f'Trying credentials {creds}')
                resp = self._try_login(target, port, user, password)
                if resp:
                    vulnerable = True
                    self.log.info(f'Logged in as', resp)
                    self.log.info(f"Telnet on {target}:{port} provides shell access, test FAILED")
                    segments.append(Report.create_text_segment(f'Credentials {creds} accepted and provide shell access on {target}:{port}!'))
                else:
                    self.log.debug(f"Credentials {creds} rejected or no shell access on {target}:{port}.")
            except Exception as e:
                segments.append(Report.create_text_segment(f"Failed to connect to telnet on {target}:{port}, test not run."))
                return {
                    "title": title,
                    "segments": segments,
                }

        return {
            "title": title,
            "segments": segments,
            "pass_rules": {"vulnerable": vulnerable},
        }

    def format_results(self, results):
        return [{"title": results["title"], "segments": results["segments"]}]
