# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *


@register_audit("xcp_program")
class xcp_program(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
    ]
    dependencies = ['python-can']
    friendly_name = "XCP Program"
    description = (
        "Attempts to write memory using the XCP service Program (0xD0) service."
    )
    fail_condition = (
        "If the XCP Server responds success this test will be marked as failed."
    )
    relevant_mitigations = ["M7", "M23"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["XCP"]
    bw_audit_id = "TS_CAN_0015"
    estimated_time_in_minutes = "5"
    test_outcomes = {
        "SUCCESS": {
            "description": "XCP programming operations were properly secured and authentication was required, preventing unauthorized code modification.",
            "recommendations": [
                "Continue monitoring XCP programming service security controls.",
                "Verify code signing and authentication mechanisms.",
                "Document security posture for compliance purposes."
            ]
        },
        "NO_RESPONSE": {
            "description": "The device did not respond to basic queries from the test.",
            "recommendations": [
                "Check physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "XCP programming service allowed code modification without proper authentication, indicating a critical security vulnerability.",
            "recommendations": [
                "Immediately implement authentication for XCP programming operations.",
                "Restrict XCP programming service in production environments.",
                "Implement code signing and integrity verification.",
                "Audit programmed memory for unauthorized modifications."
            ]
        }
    }

    def xcp_exchange(self, can_data):
        import can
        import time
        msg = can.Message(
            arbitration_id=self.req_arb,
            data=can_data,
            is_extended_id=self.extended_id,
            is_fd=self.is_fd,
        )
        self.bus.send(msg)
        end_time = time.time() + 0.1
        while time.time() < end_time:
            resp = self.bus.recv(0.1)
            if resp is None or len(resp.data) < 2 or resp.arbitration_id != self.resp_arb:
                continue
            if resp.data[0] != 0xFF and resp.data[0] != 0xFE:
                continue
            if len(resp.data) == 3 and resp.data[2] == 0x30:
                continue
            return resp.data
        return None

    def try_program(self):
        self.xcp_exchange([0xD2])
        for x in range(0, 256, 1):
            for y in range(0, 256, 1):
                # Big endian SET_MTA
                set_mta_resp = self.xcp_exchange([0xF6, 0, 0, 0, x, y, 0, 0])
                if not set_mta_resp:
                    return False
                if set_mta_resp[0] != 0xFF:
                    continue

                program_resp = self.xcp_exchange([0xD0, 0x01, 0x00])
                if not program_resp:
                    return False
                if program_resp[0] == 0xFF:
                    return True
                if program_resp[0] == 0xFE and program_resp[1] != 0x22:
                    return False

                program_resp = self.xcp_exchange([0xD0, 0x01, 0x00, 0, 0, 0, 0, 0])
                if not program_resp:
                    return False
                if program_resp[0] == 0xFF:
                    return True
                if program_resp[0] == 0xFE and program_resp[1] != 0x22:
                    return False

                # Little endian SET_MTA
                set_mta_resp = self.xcp_exchange([0xF6, 0, 0, 0, 0, 0, y, x])
                if not set_mta_resp:
                    return False
                if set_mta_resp[0] != 0xFF:
                    continue

                program_resp = self.xcp_exchange([0xD0, 0x01, 0x00])
                if not program_resp:
                    return False
                if program_resp[0] == 0xFF:
                    return True
                if program_resp[0] == 0xFE and program_resp[1] != 0x22:
                    return False

                program_resp = self.xcp_exchange([0xD0, 0x01, 0x00, 0, 0, 0, 0, 0])
                if not program_resp:
                    return False
                if program_resp[0] == 0xFF:
                    return True
                if program_resp[0] == 0xFE and program_resp[1] != 0x22:
                    return False
        return False

    def try_connect(self):
        for connect_mode in range(256):
            resp = self.xcp_exchange([0xFF, connect_mode])
            if resp and resp[0] == 0xFF:
                return True
            if not resp:
                break

            resp = self.xcp_exchange([0xFF, connect_mode, 0, 0, 0, 0, 0, 0])
            if resp and resp[0] == 0xFF:
                return True
            if not resp:
                break
        return False

    def run_audit(self):
        import can

        device = self.params["device"]
        self.extended_id = Parameter.boolean(self.params['extended_id'])
        self.is_fd = Parameter.boolean(self.params['is_fd'])
        self.req_arb = Parameter.number(self.params["req_arb"])
        self.resp_arb = Parameter.number(self.params["resp_arb"])

        segments = []
        severity = "n/a"

        self.bus = can.Bus(device, interface="socketcan", fd=self.is_fd)
        prog_res = self.try_program()
        self.log.debug("initial prog_res:", prog_res)

        if not prog_res:
            self.log.debug("attempting xcp connection")
            if self.try_connect():
                self.log.debug("successfully connected to XCP server")
                prog_res = self.try_program()
                self.log.debug("connected program:", hex(prog_res))
            else:
                self.bus.shutdown()
                segments.append(Report.create_text_segment("Failed to connect to the XCP server."))
                return {"segments": segments}

        if prog_res:
            severity = "high"
            segments.append(
                Report.create_text_segment(
                    "XCP Program (service 0xF0) can write memory"
                )
            )

        self.bus.shutdown()
        return {"segments": segments, "pass_rules": {"vulnerable": (severity != "n/a")}}

    def format_results(self, results):
        title = "XCP Program Scan Complete"
        if not results["segments"] or len(results["segments"]) == 0:
            title = "No XCP Program Found"
            results["segments"].append(Report.create_text_segment("Test Passed"))
        else:
            results["segments"].append(Report.create_text_segment("Test Failed"))
        return [{"title": title, "segments": results["segments"]}]
