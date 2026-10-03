# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *

# If InputOutputControlByIdentifier (0x2F, ISO 14229-1) is available in the
# selected session, tries to take control of the module's inputs and outputs
# through it.
@register_audit("uds_io_control")
class uds_io_control(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
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
    friendly_name = "UDS IO Control"
    description = "Attempts to control the IO state of a module via UDS. Controlling the IO can cause the vehicle to act in unexpected ways and should not be allowed without authentication."
    fail_condition = "If the UDS Server replies success to the IO Control request, this test will be marked as failed."
    relevant_mitigations = ["M15", "M10", "M22"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["UDS"]
    bw_audit_id = "TS_CAN_0008"
    estimated_time_in_minutes = "10"
    test_outcomes = {
        "SUCCESS": {
            "description": "IO control functions were not accessible to the test script.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The device did not respond to basic queries from the test.",
            "recommendations": [
                "Check physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "IO control was successful without authentication, allowing unauthorized manipulation of system inputs and outputs.",
            "recommendations": [
                "Implement proper authentication for IO control operations.",
                "Restrict IO control service availability in production.",
                "Review safety implications of unauthorized IO manipulation.",
                "Implement additional safeguards for critical IO functions."
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

    def _proc_did_resp(self, resp, sid):
        supported = False
        nrc = 0
        if resp:
            if resp[0] == sid + 0x40:
                supported = True
            elif resp[0] == 0x7F and resp[1] == sid:
                if resp[2] not in [0x13, 0x31, 0x33, 0x34]:
                    nrc = resp[2]
                    supported = True
        return {"isSupported": supported, "nrc": nrc}

    def run_audit(self):
        import can
        import isotp
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
        min_did = self.params["min_did"]
        max_did = self.params["max_did"]
        sessions_raw = self.params["session"].strip()
        sessions = [int(s.strip(), 0) for s in sessions_raw.split(",")] if "," in sessions_raw else [int(sessions_raw, 0)]

        severity = "n/a"

        did_table = []
        hitlist = []
        test_results = {
            "params": self.params,
            "severity": severity,
            "dids": hitlist,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

        addr_mode = isotp.AddressingMode.Normal_29bits if eid else isotp.AddressingMode.Normal_11bits
        addr = isotp.Address(addr_mode, txid=int(arb_req, 16), rxid=int(arb_resp, 16))
        bus = can.Bus(interface="socketcan", channel=device, fd=is_fd)
        try:
            self.tp = isotp.CanStack(bus, address=addr, params=isotp_params)
        except ValueError as e:
            bus.shutdown()
            return {"params": self.params, "error": f"Bad frame parameters: {e}"}

        for step in [1] + sessions:
            resp = self.send([0x10, step])
            if not resp or resp[0] != 0x50:
                bus.shutdown()
                return {"params": self.params, "error": "Failed to enter session!"}

        if not self.send([0x2F, 0x0, 0x0, 0x0]):
            bus.shutdown()
            return {"params": self.params, "error": "Service not supported!"}

        for id in range(int(min_did, 16), int(max_did, 16) + 1):
            data_value = []
            controls = []
            save_did = False

            resp = self.send([0x22, (id >> 8) & 0xFF, id & 0xFF])
            if resp is None:
                continue
            read = self._proc_did_resp(resp, 0x22)
            if read["isSupported"] and read["nrc"] == 0:
                data_value = resp[3:len(resp)]

            for state in range(1, 3):
                msg = [0x2F, (id >> 8) & 0xFF, id & 0xFF, state]
                controls.append(self._proc_did_resp(self.send(msg), 0x2F))

            if data_value:
                msg = [0x2F, (id >> 8) & 0xFF, id & 0xFF, 0x03]
                msg.extend(data_value)
                controls.append(self._proc_did_resp(self.send(msg), 0x2F))

            for control in controls:
                if control["isSupported"]:
                    save_did = True
                    if control["nrc"] == 0:
                        self.send([0x2F, (id >> 8) & 0xFF, id & 0xFF, 0x00])
                        break

            if save_did:
                did_table.append({"id": id, "controls": controls})

        for did in did_table:
            IocParam = 0
            for control in did["controls"]:
                IocParam = IocParam + 1
                if control["isSupported"] == True:
                    nrc = control["nrc"]
                    if nrc == 0:
                        hitlist.append(
                            {
                                "id": did["id"],
                                "IocParam": IocParam,
                                "nrc": control["nrc"],
                            }
                        )
                        severity = "high"
                        test_results["pass_rules"]["vulnerable"] = True
                    elif nrc == 0x22:
                        hitlist.append(
                            {
                                "id": did["id"],
                                "IocParam": IocParam,
                                "nrc": control["nrc"],
                            }
                        )
                        if severity == "n/a":
                            severity = "medium"

        bus.shutdown()
        test_results["dids"] = hitlist
        test_results["severity"] = severity
        return test_results

    def format_results(self, results):
        if "error" in results:
            return [{"title": results["error"], "segments": [
                Report.create_text_segment("This test encountered an error and did not run."),
                Report.create_text_segment("Please check the communication interface logs for more information.")
            ]}]


        title = "UDS - IO Control by ID Test Complete"
        segments = []
        if not results["pass_rules"]["vulnerable"]:
            segments.append(
                Report.create_text_segment(
                    f'Could not control IO on server {results["params"]["req_arb"]}. Test passed'
                )
            )
        else:
            for did in results["dids"]:
                if did["nrc"] == 0:
                    segments.append(
                        Report.create_text_segment(
                            f'IO Control by ID: {did["id"]:#0{6}x} and IoCotrolParam {did["IocParam"]:#0{4}x} was possible no NRCs!'
                        )
                    )
                else:
                    segments.append(
                        Report.create_text_segment(
                            f'IO Control by ID: {did["id"]:#0{6}x} and IoCotrolParam {did["IocParam"]:#0{4}x} was possible with NRC {did["nrc"]:#0{4}x}'
                        )
                    )

            segments.append(
                Report.create_text_segment(
                    f'Test failed. IO Control by ID was successful without authentication on server {results}'
                )
            )

        return [{"title": title, "segments": segments}]
