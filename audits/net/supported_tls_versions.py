# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *
from utils.netutil import temporary_static_ip

versions = ["-tls1", "-tls1_1", "-tls1_2", "-tls1_3"]
version_names = ["TLS v1.0", "TLS v1.1", "TLS v1.2", "TLS v1.3"]
versions_severity = ["low", "low", False, False]


@register_audit("supported_tls_versions")
class supported_tls_versions(AuditRunner):
    parameters = [
        Parameter("iface", "Network Interface", "eth0", "The network interface on which to interact"),
        Parameter("target_host", "Target IP/hostname", "10.1.0.1", "The IP or hostname to use when attempting to connect to"),
        Parameter("target_port", "Port", "443", "The port to connect to"),
        Parameter("temp_ip", "Temporary IP", "", "A temporary IP address to set on the network interface, which will be reset after the test completes"),
        Parameter("temp_mask", "Temporary Subnet Mask", "255.255.255.0", "A temporary subnet mask to set on the network interface, which will be reset after the test completes"),
    ]
    friendly_name = "Supported TLS Version Scan"
    description = "Attempts a connection to the target host with each version of TLS."
    fail_condition = (
        "If TLS 1.0 or 1.1 connects successfully the test will be marked as failed."
    )
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["Automotive Ethernet", "WiFi", "Cellular"]
    bw_audit_id = "TS_NET_0008"
    estimated_time_in_minutes = "1"
    test_outcomes = {
        "SUCCESS": {
            "description": "The specified TLS server negotiates strong versions.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The test failed to communicate with the specified `target_host`",
            "recommendations": [
                "Check test parameters, physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "The specified TLS server allows negotiating weak versions.",
            "recommendations": [
                "Review the destination of the offending TLS connection and modify that server's configuration."
            ]
        }
    }

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

    def run_audit(self):
        import subprocess
        import socket

        iface = self.params["iface"]
        target_host = self.params["target_host"]
        port = Parameter.number(self.params["target_port"])

        self.temp_ip = temporary_static_ip(
            self.params["iface"],
            self.params["temp_ip"],
            self.params["temp_mask"],
            self.log,
        )

        title = "Supported TLS Version Scan Complete"
        segments = [Report.create_heading_segment("Allowed TLS Versions:")]
        severity = "n/a"

        if target_host == "":
            segments.append(
                Report.create_text_segment(
                    f"Please provide a valid target IP or hostname"
                )
            )
            return {"title": title, "segments": segments}

        if not self._validate_ipv4(target_host) and not self._validate_ipv6(target_host):
            try:
                socket.gethostbyname(target_host)
            except socket.error:
                segments.append(
                    Report.create_text_segment(
                        f"Invalid hostname or IP address: {target_host}"
                    )
                )
                return {"title": title, "segments": segments}

        if not self._validate_port(port):
            segments.append(
                Report.create_text_segment(
                    f"Invalid port: {port}, Please make sure the format is correct"
                )
            )
            return {"title": title, "segments": segments}

        target = f"{target_host}:{port}"
        supported_versions = []

        for i in range(len(versions)):
            version = versions[i]
            self.log.debug(f'Attempting connection with {version_names[i]}')
            output = subprocess.run(
                ["openssl", "s_client", "-connect", target, version],
                capture_output=True,
            )
            if b"Connection timed out" in output.stdout:
                segments.append(Report.create_text_segment("Timed out trying to connect to target host"))
                return {
                    "iface": iface,
                    "target": target,
                    "title": title,
                    "segments": segments,
                }
            elif b"Cipher is (NONE)" in output.stdout:
                self.log.debug(version_names[i] + " not allowed")
                for line in output.stdout.decode('utf-8').split('\n'):
                    self.log.debug(line)
            elif b"CONNECTED" in output.stdout:
                supported_versions.append(i)
                self.log.warn(version_names[i] + " allowed")
                for line in output.stdout.decode('utf-8').split('\n'):
                    self.log.debug(line)
                segments.append(Report.create_text_segment(version_names[i] + 'accepted'))
                if versions_severity[i]:
                    severity = versions_severity[i]
                    segments.append(
                        Report.create_text_segment(
                            f"This version is considered insecure and has lead to a test failure."
                        )
                    )

        if len(supported_versions) < 1:
            segments.append(Report.create_text_segment("Unable to establish a TLS connection with the target"))
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
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

    def format_results(self, results):
        return [{"title": results["title"], "segments": results["segments"]}]
