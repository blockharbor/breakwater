# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *

@register_audit("uds_write_by_id")
class uds_write_by_id(AuditRunner):
    parameters = [
        Parameter("iface", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
        Parameter("min_did", "Minimum DID", "0xF000", "Start of Data ID range to test against"),
        Parameter("max_did", "Maximum DID", "0xFFFF", "End of Data ID range to test against"),
        Parameter("session", "Diagnostic session", "1", "The diagnostic session (or pair) to enter for this test"),
    ]
    dependencies = ['python-can', 'can-isotp']
    friendly_name = "UDS Write Data by Identifier"
    description = "Will iterate through given DID range attempting to write module memory. Memory should not be writable in any session without security unlock."
    fail_condition = "If the UDS Server responds with write successful, this test will be marked as failed."
    relevant_mitigations = ["M7", "M22"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["UDS"]
    bw_audit_id = "TS_CAN_0006"
    estimated_time_in_minutes = "10"
    test_outcomes = {
        "SUCCESS": {
            "description": "No data writes were successful through DID-based services without proper authentication, indicating secure data protection.",
            "recommendations": [
                "Continue monitoring DID write access controls.",
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
            "description": "Data was successfully written through UDS WriteDataByIdentifier service without authentication, indicating insufficient access controls.",
            "recommendations": [
                "Implement proper authentication for DID write operations.",
                "Review and restrict writable DID ranges in production.",
                "Consider data validation and integrity controls.",
                "Audit all writable DIDs for potential security impact."
            ]
        }
    }

    def _recv(self, timeout=0.5):
        import time
        end_time = time.time() + timeout
        while time.time() < end_time:
            self.isotp.process()
            resp = self.isotp.recv()
            if resp is not None:
                return resp
            time.sleep(0.001)
        return None

    @staticmethod
    def _proc_did_resp(resp, sid):
        if not resp:
            return {"isSupported": False, "nrc": 0}
        if resp[0] == sid + 0x40:
            return {"isSupported": True, "nrc": 0}
        if resp[0] == 0x7F and resp[1] == sid and resp[2] not in [0x13, 0x31, 0x33, 0x34]:
            return {"isSupported": True, "nrc": resp[2]}
        return {"isSupported": False, "nrc": 0}

    def run_audit(self):
        import can
        import isotp

        device = self.params["iface"]
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
        arb_req = int(self.params["req_arb"], 16)
        arb_resp = int(self.params["resp_arb"], 16)
        min_did = int(self.params["min_did"], 16)
        max_did = int(self.params["max_did"], 16)
        sessions_raw = self.params["session"].strip()
        sessions = [int(s.strip(), 0) for s in sessions_raw.split(",")] if "," in sessions_raw else [int(sessions_raw, 0)]
        hitlist = []
        severity = "n/a"

        bus = can.Bus(interface="socketcan", channel=device, fd=is_fd)
        test_results = {"params": self.params}

        addr_mode = isotp.AddressingMode.Normal_29bits if eid else isotp.AddressingMode.Normal_11bits
        addr = isotp.Address(addr_mode, txid=arb_req, rxid=arb_resp)
        try:
            self.isotp = isotp.CanStack(bus, address=addr, params=isotp_params)
        except ValueError as e:
            bus.shutdown()
            return {"params": self.params, "error": f"Bad frame parameters: {e}"}

        for session in [1] + sessions:
            self.isotp.send([0x10, session])
            resp = self._recv()
            if not resp or resp[0] != 0x50:
                bus.shutdown()
                return {"params": self.params, "error": "Failed to enter session!"}

        self.isotp.send([0x2E, 0x01, 0x00, 0xFF])
        if not self._recv():
            bus.shutdown()
            return {"params": self.params, "error": "Service not supported!"}

        did_table = []
        for id in range(min_did, max_did + 1):
            self.isotp.send([0x22, (id >> 8) & 0xFF, id & 0xFF])
            resp = self._recv()
            if resp is None:
                continue
            read = self._proc_did_resp(resp, 0x22)
            data_value = list(resp[3:]) if read["isSupported"] and read["nrc"] == 0 else []

            msg = [0x2E, (id >> 8) & 0xFF, id & 0xFF] + (data_value or [0xFF])
            self.isotp.send(msg)
            resp = self._recv()
            write = self._proc_did_resp(resp, 0x2E)
            if write["isSupported"]:
                did_table.append({"id": id, "write": write})

        bus.shutdown()

        for did in did_table:
            nrc = did["write"]["nrc"]
            if nrc == 0:
                hitlist.append(did)
                severity = "high"
            elif nrc == 0x22:
                hitlist.append(did)
                if severity == "n/a":
                    severity = "medium"

        test_results["dids"] = hitlist
        test_results["severity"] = severity
        test_results["pass_rules"] = {"vulnerable": (severity != "n/a")}
        return test_results

    def format_results(self, results):
        if "error" in results:
            return [{"title": results["error"], "segments": [
                Report.create_text_segment("This test encountered an error and did not run."),
                Report.create_text_segment("Please check the communication interface logs for more information.")
            ]}]

        title = "UDS - Write Data by ID Test Complete"
        segments = []
        if not results["pass_rules"]["vulnerable"]:
            segments.append(
                Report.create_text_segment(
                    f'Could not write data by ID on server {results["params"]["req_arb"]}. Test passed'
                )
            )
        else:
            for did in results["dids"]:
                segments.append(
                    Report.create_text_segment(
                        f'Write Data by ID: {did["id"]:#0{6}x} was possible'
                        + (
                            f'with NRC {did["write"]["nrc"]:#0{4}x}'
                            if did["write"]["nrc"] != 0
                            else ""
                        )
                    )
                )

            segments.append(
                Report.create_text_segment(
                    f'Test failed. Write Data by ID was successful without authentication on server {results["params"]["req_arb"]}'
                )
            )

        return [{"title": title, "segments": segments}]
