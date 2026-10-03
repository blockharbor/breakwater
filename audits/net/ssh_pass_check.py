# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *
from utils.netutil import temporary_static_ip


@register_audit("ssh_pass_check")
class ssh_pass_check(AuditRunner):
    parameters = [
        Parameter("iface", "Network Interface", "eth0", "The network interface on which to interact with the DNS Server"),
        Parameter("target_host", "Target IP", "10.1.0.1", "The IP to use when attempting to connect"),
        Parameter("target_port", "Target Port", "8000", "The port to use when attempting to connect"),
        Parameter("temp_ip", "Temporary IP", "", "A temporary IP address to set on the network interface, which will be reset after the test completes"),
        Parameter("temp_mask", "Temporary Subnet Mask", "255.255.255.0", "A temporary subnet mask to set on the network interface, which will be reset after the test completes"),
    ]
    dependencies = ['paramiko']
    friendly_name = "SSH Password Authentication Check"
    description = "Checks if an SSH server supports password authentication by attempting to connect to it."
    fail_condition = "If the SSH Server does support password authentication, this test will be marked as failed."
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["Automotive Ethernet", "WiFi", "Cellular"]
    bw_audit_id = "TS_NET_0011"
    estimated_time_in_minutes = "1"
    test_outcomes = {
        "SUCCESS": {
            "description": "The specified SSH server rejected password login.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The test failed to communicate with the specified `target_host`",
            "recommendations": [
                "Check test parameters, physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "The specified SSH server allows password login.",
            "recommendations": [
                "Review the offending SSH server and modify that server's configuration."
            ]
        }
    }

    def run_audit(self):
        import paramiko
        from paramiko.ssh_exception import BadAuthenticationType, AuthenticationException
        import time

        target = self.params["target_host"]
        ssh_port = Parameter.number(self.params["target_port"])

        self.temp_ip = temporary_static_ip(
            self.params["iface"],
            self.params["temp_ip"],
            self.params["temp_mask"],
            self.log,
        )

        title = "SSH Password Authentication Test Complete"
        segments = []
        severity = "n/a"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target, port=ssh_port, username="user", password="password"
            )
            severity = "high"
        except BadAuthenticationType:
            pass
        except AuthenticationException:
            severity = "medium"

        except OSError as e:
            if e.errno == 22:
                segments.append(
                    Report.create_text_segment(
                        f"Invalid {target}:{ssh_port} argument error occurred"
                    )
                )
            else:
                segments.append(
                    Report.create_text_segment(
                        f"OS Error occurred: {e}"
                    )
                )
            return {"title": title, "segments": segments}
        except Exception as e:
            segments.append(
                Report.create_text_segment(
                    f"Exception encountered while connecting to SSH: {e}"
                )
            )

        output = (
            "not available. Test passed"
            if severity == "n/a"
            else "available. Test failed"
        )
        segments.append(
            Report.create_text_segment(f"SSH Password Authentication {output}")
        )

        return {
            "title": title,
            "segments": segments,
            "pass_rules": {"vulnerable": (severity != "n/a"),},
        }

    def format_results(self, results):
        return [{"title": results["title"], "segments": results["segments"]}]
