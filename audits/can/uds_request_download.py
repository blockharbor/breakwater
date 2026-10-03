# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *

@register_audit("uds_request_download")
class uds_request_download(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
        Parameter("scan_interval", "Address Scan Interval", "0x100000", "The address interval that this test scans with, the lower the number the more granular the scan (which can find small memory regions), but takes more time."),
        Parameter("session", "Diagnostic session", "1", "The diagnostic session (or pair) to enter for this test"),
    ]
    dependencies = ['python-can', 'can-isotp']
    friendly_name = "UDS Request Download"
    description = "Iterates through download formats and requests to download files to an ECU. Request Download can modify the firmware and behavior of a device, it should not be allowed without access control."
    fail_condition = (
        "If the UDS Server responds with success, this test will be marked as failed."
    )
    relevant_mitigations = ["M7", "M22"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["UDS"]
    bw_audit_id = "TS_CAN_0005"
    estimated_time_in_minutes = "5"
    test_outcomes = {
        "SUCCESS": {
            "description": "Download requests were properly rejected and authentication was required, preventing unauthorized firmware/data downloads.",
            "recommendations": [
                "Continue monitoring download service security controls.",
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
            "description": "Download requests were accepted without proper authentication, allowing unauthorized firmware/data modification.",
            "recommendations": [
                "Implement proper authentication for download operations.",
                "Restrict download service availability in production.",
                "Implement code signing and integrity verification.",
                "Review firmware update security mechanisms."
            ]
        }
    }

    def _send(self, data, timeout=0.5):
        import time
        self.tp.send(bytearray(data))
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
        scan_interval = self.params["scan_interval"]
        sessions_raw = self.params["session"].strip()
        sessions = [int(s.strip(), 0) for s in sessions_raw.split(",")] if "," in sessions_raw else [int(sessions_raw, 0)]

        severity = "n/a"
        downloads = []
        test_results = {
            "params": self.params,
            "severity": severity,
            "downloads": downloads,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

        bus = can.Bus(interface="socketcan", channel=device, fd=is_fd)
        addr = isotp.Address(
            isotp.AddressingMode.Normal_29bits if eid else isotp.AddressingMode.Normal_11bits,
            txid=int(arb_req, 16),
            rxid=int(arb_resp, 16),
        )
        try:
            self.tp = isotp.CanStack(bus, address=addr, params=isotp_params)
        except ValueError as e:
            bus.shutdown()
            return {"params": self.params, "error": f"Bad frame parameters: {e}"}

        for session in [1] + sessions:
            resp = self._send([0x10, session])
            if not resp or resp[0] != 0x50:
                bus.shutdown()
                return {"params": self.params, "error": "Failed to enter session!"}

        if not self._send([0x34, 0x00, 0x11, 0x0, 0x0]):
            bus.shutdown()
            return {"params": self.params, "error": "Service not supported!"}

        for upload_fmt in [
            0x11,0x12,0x13,0x14,
            0x21,0x22,0x23,0x24,
            0x31,0x32,0x33,0x34,
            0x41,0x42,0x43,0x44,
        ]:
            for address in range(
                0, 2 ** (8 * (upload_fmt & 0xF)), int(scan_interval, 16)
            ):
                req = [0x34, 0x00, upload_fmt]
                req = req + list(address.to_bytes(upload_fmt & 0xF, "big"))
                req = req + list((4).to_bytes((upload_fmt >> 4) & 0xF, "big"))
                resp = self._send(req)

                if not resp or (resp[0] == 0x7F and resp[2] in [0x11, 0x7F]):
                    break

                elif resp[0] == 0x74:
                    severity = "high"
                    downloads.append([upload_fmt, address])
                    break

                elif resp[0] == 0x7F and resp[1] == 0x34:

                    if resp[2] == 0x31:
                        if severity == "n/a":
                            severity = "medium"
                        continue

                    elif resp[2] == 0x22:
                        if severity == "n/a":
                            severity = "medium"
                        continue
                    elif resp[2] == 0x33:
                        continue
                    elif resp[2] == 0x13:
                        continue

        bus.shutdown()
        test_results["downloads"] = downloads
        test_results["severity"] = severity
        test_results["pass_rules"]["vulnerable"] = severity != "n/a"
        return test_results

    def format_results(self, results):
        if "error" in results:
            return [{"title": results["error"], "segments": [
                Report.create_text_segment("This test encountered an error and did not run."),
                Report.create_text_segment("Please check the communication interface logs for more information.")
            ]}]


        title = "Request Download Test Complete"
        segments = []
        if not results["pass_rules"]["vulnerable"]:
            segments.append(
                Report.create_text_segment(
                    f"Module did not accept any request download requests. Test passed"
                )
            )
        elif len(results["downloads"]) == 0:
            segments.append(
                Report.create_text_segment(
                    f"Module returned NRC which gave indication that download is possible. Further testing recommended."
                )
            )
            segments.append(
                Report.create_text_segment(
                    f"If NRC $31 is returned, possible try smaller scan_interval parameter to find the writable memory region."
                )
            )
        else:
            for download in results["downloads"]:
                segments.append(
                    Report.create_text_segment(
                        f"Download request accepted with request format {hex(download[0])} at address {hex(download[1])}"
                    )
                )

        return [{"title": title, "segments": segments}]

