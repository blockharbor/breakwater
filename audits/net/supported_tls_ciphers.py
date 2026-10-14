# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *
from utils.netutil import temporary_static_ip

@register_audit("supported_tls_ciphers")
class supported_tls_ciphers(AuditRunner):
    parameters = [
        Parameter("iface", "Network Interface", "eth0", "The network interface on which to interact"),
        Parameter("target_host", "Target IP", "10.1.0.1", "The IP to use when attempting to connect to"),
        Parameter("target_port", "Target Port", "443", "The port to connect to"),
        Parameter("temp_ip", "Temporary IP", "", "A temporary IP address to set on the network interface, which will be reset after the test completes"),
        Parameter("temp_mask", "Temporary Subnet Mask", "255.255.255.0", "A temporary subnet mask to set on the network interface, which will be reset after the test completes"),
    ]
    friendly_name = "Supported TLS Cipher Scan"
    description = "Iterates through all known TLS ciphers and attempts a connection to the web server with each. Accepted ciphers are reported."
    fail_condition = "if a weak cipher is accepted the test will be marked as failed."
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["Automotive Ethernet", "WiFi", "Cellular"]
    bw_audit_id = "TS_NET_0007"
    estimated_time_in_minutes = "3"
    test_outcomes = {
        "SUCCESS": {
            "description": "The specified TLS server negotiates strong ciphers.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The test failed to communicate with the specified `target_host`",
            "recommendations": [
                "Check test parameters, physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "The specified TLS server allows negotiating weak ciphers.",
            "recommendations": [
                "Review the destination of the offending TLS connection and modify that server's configuration."
            ]
        }
    }

    versions = ["-tls1_2", "-tls1_3"]
    version_names = ["TLSv1.2", "TLSv1.3"]
    allowed_ciphers = [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-CBC-SHA256",
        "ECDHE-ECDSA-AES256-CBC-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-CBC-SHA256",
        "ECDHE-RSA-AES256-CBC-SHA384",
        "ECDHE-RSA-AES128-CBC-SHA256",
        "ECDHE-RSA-AES256-CBC-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-CBC-SHA",
        "DHE-RSA-AES256-CBC-SHA",
        "DHE-RSA-AES128-CBC-SHA256",
        "DHE-RSA-AES256-CBC-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ]

    @staticmethod
    def _validate_ipv4(ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return False
        return True

    @staticmethod
    def _validate_ipv6(ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.IPv6Address(ip)
        except ipaddress.AddressValueError:
            return False
        return True

    @staticmethod
    def _validate_port(port: int) -> bool:
        return 1 <= port <= 65535

    def target_alive(self, address: str, port: int) -> bool:
        import socket
        # Create a TCP socket
        timeout = 5  # timeout in seconds
        s = socket.socket(
            socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM
        )
        s.settimeout(timeout)

        try:
            s.connect((address, port))
            return True
        except socket.error as error:
            return False
        finally:
            s.close()

    def run_audit(self):
        import os
        import socket
        import subprocess
        iface = self.params["iface"]
        ip = self.params["target_host"]
        port = Parameter.number(self.params["target_port"])

        title = "Supported TLS Cipher Scan Complete"
        segments = [Report.create_heading_segment("Allowed Cipher Suites:")]

        if not self._validate_ipv4(ip) and not self._validate_ipv6(ip):
            segments.append(
                Report.create_text_segment(
                    f"Invalid target IP:{ip}, Please make sure the format is correct"
                )
            )
            return {"title": title, "segments": segments}

        if not self._validate_port(port):
            segments.append(
                Report.create_text_segment(
                    f"Invalid port:{port}, Please make sure the format is correct"
                )
            )
            return {"title": title, "segments": segments}

        target = f"{ip}:{port}"

        self.temp_ip = temporary_static_ip(
            self.params["iface"],
            self.params["temp_ip"],
            self.params["temp_mask"],
            self.log,
        )

        if not self.target_alive(ip, port):
            segments.append(Report.create_text_segment("Could not connect to the target server!"))
            return {
                "iface": iface,
                "target": target,
                "title": title,
                "segments": segments,
            }

        vulnerable = False
        ciphers_accepted = []
        ciphers_rejected = []
        cipher_lines = subprocess.check_output(["openssl", "ciphers", "-v"]).decode('utf-8').split('\n')

        for cipher_line in cipher_lines:
            cipher_s = cipher_line.split()
            if len(cipher_s) < 4:
                continue
            cipher = cipher_s[0]
            cipher_v = cipher_s[1]
            if cipher_v not in self.version_names:
                continue
            tls_v = self.versions[self.version_names.index(cipher_v)]
            self.log.debug(f'Attempting connection with {cipher_v} {cipher}')
            output = subprocess.run(
                ["openssl", "s_client", "-cipher", cipher+':@SECLEVEL=0', "-connect", target, tls_v],
                capture_output=True,
            )
            cond1 = f'Cipher is {cipher}'.encode() in output.stdout
            cond2 = b'unable to verify the first certificate verify return' in output.stderr
            if cond1 or cond2:
                self.log.info(f'Successfully connected with {cipher_v} {cipher}')
                ciphers_accepted.append(cipher)
                if cipher in self.allowed_ciphers:
                    segments.append(Report.create_text_segment(f'Accepted: {cipher}'))
                else:
                    vulnerable = True
                    segments.append(Report.create_text_segment(f'Accepted: {cipher} (WEAK)'))
            elif b'no cipher match' in output.stderr or b'error' in output.stdout:
                ciphers_rejected.append(cipher)
            else:
                self.log.debug(f'Got an unexpected reply with {cipher_v} {cipher}')
                pass


        self.log.debug(f'Discovered {len(ciphers_accepted)} accepted ciphers')
        if len(ciphers_accepted) == 0:
            segments.append(Report.create_text_segment("Unable to establish a successful TLS connection to the target server!"))
            return {
                "iface": iface,
                "target": target,
                "title": title,
                "segments": segments,
            }

        return {
            "iface": iface,
            "target": target,
            "title": title,
            "segments": segments,
            "pass_rules": {"vulnerable": vulnerable},
        }

    def format_results(self, results):
        return [{"title": results["title"], "segments": results["segments"]}]
