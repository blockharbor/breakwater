# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *


@register_audit("uds_comm_control")
class uds_comm_control(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
        Parameter("session", "Diagnostic session", "1", "The diagnostic session (or pair) to enter for this test"),
    ]
    dependencies = ['python-can', 'can-isotp']
    friendly_name = "UDS Communication Control"
    description = "Attempts to toggle the communication state of a module via UDS. Disabling communication of a module can cause serious issues and should not be allowed without authentication."
    fail_condition = "If the UDS Server responds with success to the Communication Control request, the test will be marked as failed."
    relevant_mitigations = ["M15", "M10", "M22"]
    relevant_interfaces = ["CAN"]
    bw_audit_id = "TS_CAN_0007"
    estimated_time_in_minutes = "1"
    test_outcomes = {
        "SUCCESS": {
            "description": "Communication control functions were not available to the test script.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The device did not respond to basic queries from the test.",
            "recommendations": [
                "Check physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "Communication control service allowed disabling of normal communication without proper authentication, indicating a security vulnerability.",
            "recommendations": [
                "Implement proper authentication for communication control operations.",
                "Restrict communication control service in production environments.",
                "Review impact of communication disruption on system safety.",
                "Implement additional safeguards against communication denial of service."
            ]
        }
    }

    def send(self, msg_data, timeout=0.5):
        import time
        self.tp.send(bytearray(msg_data))
        end_time = time.time() + timeout
        while time.time() < end_time:
            self.tp.process()
            resp = self.tp.recv()
            if resp is not None:
                return bytearray(resp)
            time.sleep(0.001)
        return None

    def run_audit(self):
        import can
        import isotp
        import time
        import ast

        device = self.params["device"]
        eid = Parameter.boolean(self.params['extended_id'])
        is_fd = Parameter.boolean(self.params['is_fd'])

        # A static frame length pads every frame out to that length with the
        # fill byte, instead of letting the DLC follow the real payload size.
        frame_len = Parameter.number(self.params["frame_len"])
        frame_fill = Parameter.number(self.params["frame_fill"])
        if frame_len > 8 and not is_fd:
            return {"params": self.params, "error": "Static frame lengths above 8 bytes require CAN FD!"}
        isotp_params = {}
        if frame_len:
            isotp_params = {"tx_padding": frame_fill, "tx_data_min_length": frame_len}
            if frame_len > 8:
                isotp_params.update({"tx_data_length": frame_len, "can_fd": True})
        arb_req = self.params["req_arb"]
        arb_resp = self.params["resp_arb"]
        sessions_raw = self.params["session"].strip()
        session = [int(s.strip(), 0) for s in sessions_raw.split(",")] if "," in sessions_raw else [int(sessions_raw, 0)]

        severity = "n/a"

        addr_mode = isotp.AddressingMode.Normal_29bits if eid else isotp.AddressingMode.Normal_11bits
        addr = isotp.Address(addr_mode, txid=int(arb_req, 16), rxid=int(arb_resp, 16))
        bus = can.Bus(interface="socketcan", channel=device, fd=is_fd)
        try:
            self.tp = isotp.CanStack(bus, address=addr, params=isotp_params)
        except ValueError as e:
            bus.shutdown()
            return {"params": self.params, "error": f"Bad frame parameters: {e}"}

        for step in [1] + session:
            resp = self.send([0x10, step])
            if not resp or resp[0] != 0x50:
                bus.shutdown()
                return {"params": self.params, "error": "Failed to enter session!"}

        resp = self.send([0x28, 0x01, 0x01])
        if resp and resp[0] == 0x68:
            severity = "medium"
            # if successful, enable normal communication again for future tests
            self.send([0x28, 0x00, 0x01])

        bus.shutdown()
        return {
            "params": self.params,
            "severity": severity,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

    def format_results(self, results):
        if "error" in results:
            return [{"title": results["error"], "segments": [
                Report.create_text_segment("This test encountered an error and did not run."),
                Report.create_text_segment("Please check the communication interface logs for more information.")
            ]}]


        title = "Communication Control Test Complete"
        segments = []
        if not results["pass_rules"]["vulnerable"]:
            segments.append(
                Report.create_text_segment(
                    f"Could not disable normal communication of target. Test passed"
                )
            )
        else:
            segments.append(
                Report.create_text_segment(
                    f'Test failed. Normal communication could be disabled on server {results["params"]["req_arb"]}'
                )
            )

        return [{"title": title, "segments": segments}]
