# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *


@register_audit("xcp_upload")
class xcp_upload(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
    ]
    dependencies = ['python-can']
    friendly_name = "XCP Upload"
    description = "Tests if it is posible to read memory with XCP Upload with STD commands 0xF5 (UPLOAD) and 0xF4 (SHORT_UPLOAD) on a common range of memory addresses."
    fail_condition = "If the XCP server responds success to either request this test will be marked as failed."
    relevant_mitigations = ["M8", "M23"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["XCP"]
    bw_audit_id = "TS_CAN_0013"
    estimated_time_in_minutes = "5"
    test_outcomes = {
        "SUCCESS": {
            "description": "XCP upload operations required proper authentication and were secured against unauthorized access.",
            "recommendations": [
                "Continue monitoring XCP upload service security controls.",
                "Verify authentication mechanisms remain robust.",
                "Document security controls for compliance purposes."
            ]
        },
        "NO_RESPONSE": {
            "description": "The device did not respond to basic queries from the test.",
            "recommendations": [
                "Check physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "XCP upload service allowed memory reading without proper authentication, indicating a security vulnerability.",
            "recommendations": [
                "Implement proper authentication for XCP upload operations.",
                "Restrict XCP upload service availability in production.",
                "Review memory access controls and data protection mechanisms.",
                "Audit accessible memory regions for sensitive data exposure."
            ]
        }
    }

    def xcp_exchange(self, can_data):
        import can
        import time
        if len(can_data) < self.frame_len:
            can_data = list(can_data) + [self.frame_fill] * (self.frame_len - len(can_data))
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
            if resp is None or len(resp.data) < 1 or resp.arbitration_id != self.resp_arb:
                continue
            if resp.data[0] != 0xFF and resp.data[0] != 0xFE:
                continue
            # A positive response can be the bare PID (e.g. DISCONNECT or
            # SET_MTA without padding), an error always carries its code.
            if resp.data[0] == 0xFE and len(resp.data) < 2:
                continue
            if len(resp.data) == 3 and resp.data[2] == 0x30:
                continue
            return resp.data
        return None

    def try_upload(self):
        for x in range(0, 256, 1):
            for y in range(0, 256, 1):
                # Big endian SET_MTA
                set_mta_resp = self.xcp_exchange([0xF6, 0, 0, 0, x, y, 0, 0])
                if not set_mta_resp:
                    return False
                if set_mta_resp[0] != 0xFF:
                    continue

                upload_resp = self.xcp_exchange([0xF5, 0x01])
                if not upload_resp:
                    return False
                if upload_resp[0] == 0xFF:
                    return True
                if upload_resp[0] == 0xFE and upload_resp[1] != 0x22:
                    return False

                # Little endian SET_MTA
                set_mta_resp = self.xcp_exchange([0xF6, 0, 0, 0, 0, 0, y, x])
                if not set_mta_resp:
                    return False
                if set_mta_resp[0] != 0xFF:
                    continue

                upload_resp = self.xcp_exchange([0xF5, 0x01])
                if not upload_resp:
                    return False
                if upload_resp[0] == 0xFF:
                    return True
                if upload_resp[0] == 0xFE and upload_resp[1] != 0x22:
                    return False
        return False

    def try_short_upload(self):
        for x in range(0, 256, 1):
            for y in range(0, 256, 1):
                # Big endian SHORT_UPLOAD
                upload_resp = self.xcp_exchange([0xF4, 0x01, 0, 0, x, y, 0, 0])
                if not upload_resp:
                    return False
                if upload_resp[0] == 0xFF:
                    return True
                if upload_resp[0] == 0xFE and upload_resp[1] != 0x22:
                    break

                # Little endian SHORT_UPLOAD
                upload_resp = self.xcp_exchange([0xF4, 0x01, 0, 0, 0, 0, y, x])
                if not upload_resp:
                    return False
                if upload_resp[0] == 0xFF:
                    return True
                if upload_resp[0] == 0xFE and upload_resp[1] != 0x22:
                    break
        return False

    def try_connect(self):
        for connect_mode in range(256):
            resp = self.xcp_exchange([0xFF, connect_mode])
            if resp and resp[0] == 0xFF:
                return True

            resp = self.xcp_exchange([0xFF, connect_mode, 0, 0, 0, 0, 0, 0])
            if resp and resp[0] == 0xFF:
                return True
        return False

    def run_audit(self):
        import can

        device = self.params["device"]
        self.extended_id = Parameter.boolean(self.params['extended_id'])
        self.is_fd = Parameter.boolean(self.params['is_fd'])
        # A static frame length pads every frame out to that length with the
        # fill byte, instead of letting the DLC follow the real payload size.
        self.frame_len = Parameter.number(self.params["frame_len"])
        self.frame_fill = Parameter.number(self.params["frame_fill"])
        if self.frame_len > 8 and not self.is_fd:
            return {"segments": [Report.create_text_segment("Static frame lengths above 8 bytes require CAN FD!")]}
        self.req_arb = Parameter.number(self.params["req_arb"])
        self.resp_arb = Parameter.number(self.params["resp_arb"])

        segments = []
        severity = "n/a"

        self.bus = can.Bus(device, interface="socketcan", fd=self.is_fd)
        # Connect before testing, a correct XCP server ignores every other
        # command until it has seen CONNECT.
        self.log.debug("attempting xcp connection")
        if not self.try_connect():
            self.bus.shutdown()
            segments.append(Report.create_text_segment("Failed to connect to the XCP server."))
            return {"segments": segments}
        self.log.debug("successfully connected to XCP server")

        up_res = self.try_upload()
        self.log.debug("up_res:", up_res)
        short_up_res = self.try_short_upload()
        self.log.debug("short_up_res:", short_up_res)

        if up_res:
            severity = "medium"
            segments.append(
                Report.create_text_segment(
                    "XCP UPLOAD (service 0xF5) can read memory"
                )
            )

        if short_up_res:
            severity = "medium"
            segments.append(
                Report.create_text_segment(
                    "XCP UPLOAD (service 0xF4) can read memory"
                )
            )

        self.bus.shutdown()
        return {"segments": segments, "pass_rules": {"vulnerable": (severity != "n/a")}}

    def format_results(self, results):
        title = "XCP Upload Scan Complete"
        if not results["segments"] or len(results["segments"]) == 0:
            title = "No XCP Upload Found"
            results["segments"].append(Report.create_text_segment("Test Passed"))
        else:
            results["segments"].append(Report.create_text_segment("Test Failed"))
        return [{"title": title, "segments": results["segments"]}]
