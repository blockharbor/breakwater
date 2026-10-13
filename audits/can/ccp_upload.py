# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *


@register_audit("ccp_upload")
class ccp_upload(AuditRunner):
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
    friendly_name = "CCP Upload"
    description = "Attempts to use the CCP upload service to read device memory."
    fail_condition = "If the server responds with success the test will be marked as failed with severity medium. If the server responds with an 'out of range' error code, the test will be marked as failed with severity low."
    relevant_mitigations = ["M8", "M23"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["CCP"]
    bw_audit_id = "TS_CAN_0010"
    estimated_time_in_minutes = "5"
    test_outcomes = {
        "SUCCESS": {
            "description": "CCP upload operations required proper authentication and were secured against unauthorized access.",
            "recommendations": [
                "Continue monitoring CCP upload service security controls.",
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
            "description": "CCP upload service allowed data transmission without proper authentication, indicating a security vulnerability.",
            "recommendations": [
                "Implement proper authentication for CCP upload operations.",
                "Restrict CCP upload service availability in production.",
                "Review data validation and integrity controls.",
                "Audit uploaded data for potential security implications."
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

    def try_upload_04(self, seq=1):
        set_mta_resp = self.ccp_exchange([0x02, seq, 0x40, 0x00, 0x00, 0x00])
        if not set_mta_resp or set_mta_resp[2] == 0x33:
            return 0x33
        if set_mta_resp and len(set_mta_resp) == 3 and set_mta_resp[2] == 0:
            upload_resp = self.ccp_exchange([0x04, seq + 1, 0x04])
            if upload_resp and len(upload_resp) > 2:
                if upload_resp[2] == 0:
                    return 0
                if upload_resp[2] == 0x33:
                    return 0x33
                if upload_resp[2] == 0x32:
                    return 0x32
                if upload_resp[2] == 0x35:
                    return 0x35
        return 0x30

    def try_upload_0f(self, seq=1):
        short_up_resp = self.ccp_exchange([0x0F, seq, 0x40, 0x00, 0x00, 0x00])
        if short_up_resp and len(short_up_resp) > 2:
            if short_up_resp[2] == 0x32:
                return 0x32
            if short_up_resp[2] == 0:
                return 0
            if short_up_resp[2] == 0x33:
                return 0x33
            if short_up_resp[2] == 0x35:
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

        up04 = self.try_upload_04()
        self.log.debug("initial upload04:", hex(up04))
        up0f = self.try_upload_0f()
        self.log.debug("initial upload0f:", hex(up0f))

        if up04 == 0x33 or up0f == 0x33:
            self.log.debug("attempting CCP connection")
            connect_res = self.try_connect()
            if connect_res == 0:
                self.log.debug("successfully connected to CCP server")
                if up04 == 0x33:
                    up04 = self.try_upload_04()
                    self.log.debug("connected upload04:", hex(up04))
                if up0f == 0x33:
                    up0f = self.try_upload_0f()
                    self.log.debug("connected upload0f:", hex(up0f))
            elif connect_res == 0x30 and up04 != 0 and up0f != 0:
                # A read that already worked without connecting is a finding on
                # its own, so only give up when neither method got through.
                self.bus.shutdown()
                segments.append(Report.create_text_segment("Failed to connect to the CCP server."))
                return {"segments": segments}

        if up04 == 0:
            severity = "medium"
            segments.append(
                Report.create_text_segment(
                    "CCP UPLOAD (service 0x04) can read memory"
                )
            )
        elif up04 == 0x32:
            if severity == "n/a":
                severity = "low"
            segments.append(
                Report.create_text_segment(
                    "CCP UPLOAD (service 0x04) seems to be able to read memory (got out of range)"
                )
            )

        if up0f == 0:
            severity = "medium"
            segments.append(
                Report.create_text_segment(
                    "CCP UPLOAD (service 0x0f) can read memory"
                )
            )
        elif up0f == 0x32:
            if severity == "n/a":
                severity = "low"
            segments.append(
                Report.create_text_segment(
                    "CCP UPLOAD (service 0x0f) seems to be able to read memory (got out of range)"
                )
            )

        self.bus.shutdown()
        return {"segments": segments, "pass_rules": {"vulnerable": (severity != "n/a")}}

    def format_results(self, results):
        title = "CCP Upload Scan Complete"
        if not results["segments"] or len(results["segments"]) == 0:
            title = "No CCP Upload Found"
            results["segments"].append(Report.create_text_segment("Test Passed"))
        else:
            results["segments"].append(Report.create_text_segment("Test Failed"))
        return [{"title": title, "segments": results["segments"]}]
