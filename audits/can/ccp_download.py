# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *


@register_audit("ccp_download")
class ccp_download(AuditRunner):
    parameters = [
        Parameter("iface", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
    ]
    dependencies = ['python-can']
    friendly_name = "CCP Download"
    description = "Attempts to use the CCP download service to write device memory."
    fail_condition = "If the CCP Server responds with an out of range response or with memory contents this test will be failed. If the server replies with out of range, the severity will be low, otherwise if memory is written, the severity will be high."
    relevant_mitigations = ["M7", "M23"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["CCP"]
    bw_audit_id = "TS_CAN_0011"
    estimated_time_in_minutes = "5"
    test_outcomes = {
        "SUCCESS": {
            "description": "CCP download operations were properly secured and authentication was required, preventing unauthorized memory access.",
            "recommendations": [
                "Continue monitoring CCP service availability and access controls.",
                "Verify authentication mechanisms are properly implemented.",
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
            "description": "CCP download service allowed memory extraction without proper authentication, indicating a security vulnerability.",
            "recommendations": [
                "Implement proper authentication for CCP download operations.",
                "Restrict CCP service availability in production environments.",
                "Review memory access controls and segmentation.",
                "Audit downloaded memory contents for sensitive data exposure."
            ]
        }
    }

    def ccp_exchange(self, can_data, timeout=0.2):
        import can
        import time
        if len(can_data) < self.frame_len:
            can_data = list(can_data) + [self.frame_fill] * (self.frame_len - len(can_data))
        msg = can.Message(
            arbitration_id=self.req_arb,
            data=can_data,
            is_extended_id=self.extended_id,
            is_fd=self.is_fd
        )
        self.bus.send(msg)
        end_time = time.time() + timeout
        while time.time() < end_time:
            resp = self.bus.recv(timeout)
            if resp is None or len(resp.data) < 1 or resp.arbitration_id != self.resp_arb:
                continue
            if resp.data[0] != 0xFF:
                continue
            return resp.data
        return None

    def try_download(self, sid, seq=1):
        set_mta_resp = self.ccp_exchange([0x02, seq, 0x40, 0x00, 0x00, 0x00])
        if not set_mta_resp or set_mta_resp[2] == 0x33:
            return 0x33
        if set_mta_resp and len(set_mta_resp) == 3 and set_mta_resp[2] == 0:
            download_resp = self.ccp_exchange([sid, seq + 1, 0x04])
            if download_resp and len(download_resp) > 2:
                if download_resp[2] == 0:
                    return 0
                if download_resp[2] == 0x33:
                    return 0x33
                if download_resp[2] == 0x32:
                    return 0x32
                if download_resp[2] == 0x35:
                    return 0x35
        return 0x30

    def try_connect(self):
        for i in range(0, 65535):
            resp = self.ccp_exchange([0x01, 0x01, (i >> 8) & 0xFF, i & 0xFF])
            if i == 0 and not resp:
                return 0x30
            if resp and len(resp) == 3:
                if resp[2] == 0x32:
                    continue
                if resp[2] == 0:
                    return 0
                if resp[2] == 0x36:
                    return 0x36
        return 0x30

    def run_audit(self):
        import can

        device = self.params["iface"]
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

        up03 = self.try_download(0x03)
        self.log.debug("initial download03:", hex(up03))
        up23 = self.try_download(0x23)
        self.log.debug("initial download23:", hex(up23))

        if up03 == 0x33 or up23 == 0x33:
            self.log.debug("attempting CCP connection")
            connect_res = self.try_connect()
            if connect_res == 0:
                self.log.debug("successfully connected to CCP server")
                if up03 == 0x33:
                    up03 = self.try_download(0x03)
                    self.log.debug("connected download03:", hex(up03))
                if up23 == 0x33:
                    up23 = self.try_download(0x23)
                    self.log.debug("connected download23:", hex(up23))
            elif connect_res == 0x30:
                self.bus.shutdown()
                segments.append(Report.create_text_segment("Failed to connect to the CCP server."))
                return {"segments": segments}

        if up03 == 0:
            severity = "high"
            segments.append(
                Report.create_text_segment(
                    "CCP DOWNLOAD (service 0x03) can write memory"
                )
            )
        elif up03 == 0x32:
            if severity == "n/a":
                severity = "low"
            segments.append(
                Report.create_text_segment(
                    "CCP DOWNLOAD (service 0x03) seems to be able to write memory (got out of range)"
                )
            )

        if up23 == 0:
            severity = "high"
            segments.append(
                Report.create_text_segment(
                    "CCP DOWNLOAD (service 0x23) can write memory"
                )
            )
        elif up23 == 0x32:
            if severity == "n/a":
                severity = "low"
            segments.append(
                Report.create_text_segment(
                    "CCP DOWNLOAD (service 0x23) seems to be able to write memory (got out of range)"
                )
            )

        self.bus.shutdown()
        return {"segments": segments, "pass_rules": {"vulnerable": (severity != "n/a")}}

    def format_results(self, results):
        title = "CCP Download Scan Complete"
        if not results["segments"] or len(results["segments"]) == 0:
            title = "No CCP Download Found"
            results["segments"].append(Report.create_text_segment("Test Passed"))
        else:
            results["segments"].append(Report.create_text_segment("Test Failed"))
        return [{"title": title, "segments": results["segments"]}]
