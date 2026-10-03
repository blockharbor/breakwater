# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC
from framework import *

@register_audit("uds_read_memory_by_did")
class uds_read_memory_by_did(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
        Parameter("did", "Attempted DID to define", "0xF000", "The actual did to attempt to be defined as memory"),
        Parameter("address", "Attempted address to read", "0x0", "The actual address to attempt to read from"),
        Parameter("size", "Attempted size to read", "0x10", "The actual size to attempt to read from"),
        Parameter("session", "Diagnostic session", "1", "The diagnostic session (or pair) to enter for this test"),
    ]
    dependencies = ['python-can', 'can-isotp']
    friendly_name = "UDS Read Memory by Did"
    description = (
        "Attempts to dynamically define a did as a memory regoin, and read memory"
    )
    fail_condition = "Able to read memory"
    relevant_mitigations = [""]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["UDS"]
    bw_audit_id = "CUST_CAN_0001"
    estimated_time_in_minutes = "1"
    test_outcomes = {
        "SUCCESS": {
            "description": "Dynamic DID definition and memory reading was properly restricted, preventing unauthorized memory access.",
            "recommendations": [
                "Continue monitoring DID definition service security controls.",
                "Verify proper authentication requirements for memory-mapped DIDs.",
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
            "description": "Successfully defined a DID as a memory region and read memory contents, indicating insufficient access controls.",
            "recommendations": [
                "Implement proper authentication for DID definition services.",
                "Restrict dynamic DID creation in production environments.",
                "Review memory access controls and segmentation.",
                "Audit accessible memory regions for sensitive data exposure."
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
                return resp
            time.sleep(0.001)
        return None

    def run_audit(self):
        import can
        import isotp

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
        did = Parameter.number(self.params["did"])
        addr = Parameter.number(self.params["address"])
        size = Parameter.number(self.params["size"])
        sessions_raw = self.params["session"].strip()
        session = [int(s.strip(), 0) for s in sessions_raw.split(",")] if "," in sessions_raw else [int(sessions_raw, 0)]
        severity = "n/a"
        memory_contents = {}

        addr_mode = isotp.AddressingMode.Normal_29bits if eid else isotp.AddressingMode.Normal_11bits
        tp_addr = isotp.Address(addr_mode, txid=int(arb_req, 16), rxid=int(arb_resp, 16))
        bus = can.Bus(interface="socketcan", channel=device, fd=is_fd)
        try:
            self.tp = isotp.CanStack(bus, address=tp_addr, params=isotp_params)
        except ValueError as e:
            bus.shutdown()
            return {"params": self.params, "error": f"Bad frame parameters: {e}"}

        for step in [1] + session:
            resp = self.send([0x10, step])
            if not resp or resp[0] != 0x50:
                bus.shutdown()
                return {"params": self.params, "error": "Failed to enter session!"}

        if not self.send([0x2C, 0x1]):
            bus.shutdown()
            return {"params": self.params, "error": "Service not supported!"}

        for format_byte in [
            0x11, 0x12, 0x13, 0x14,
            0x21, 0x22, 0x23, 0x24,
            0x31, 0x32, 0x33, 0x34,
            0x41, 0x42, 0x43, 0x44]:

            addr_size = format_byte & 0xF
            size_size = (format_byte >> 4) & 0xF

            resp = self.send(
                [0x2C, 0x02]
                + list(did.to_bytes(2, "big"))
                + [format_byte]
                + list(addr.to_bytes(addr_size, "big"))
                + list(size.to_bytes(size_size, "big")),
            )

            if not resp:
                print("[-] no response from UDS server")
                continue
            if resp[0] == 0x6C:
                read_resp = self.send([0x22] + list(did.to_bytes(2, "big")))
                if read_resp and read_resp[0] == 0x62:
                    severity = "med"
                    memory_contents[format_byte] = read_resp[1:]
                    self.log.debug(f"[!] Format {format_byte:x} read '{read_resp[1:]}' ({read_resp[1:].hex()})")
                else:
                    memory_contents[format_byte] = 0
                    self.log.debug(f"[!] Format {format_byte:x} defined but not read")
            elif resp[0] == 0x7F and resp[1] == 0x2C:
                if resp[2] == 0x31:
                    continue
                elif resp[2] == 0x33:
                    continue
                elif resp[2] == 0x13:
                    continue

        bus.shutdown()
        return {
            "params": self.params,
            "severity": severity,
            "pass_rules": {"vulnerable": (severity != "n/a")},
            "memory_contents": memory_contents
        }


    def format_results(self, results):
        if "error" in results:
            return [{"title": results["error"], "segments": [
                Report.create_text_segment("This test encountered an error and did not run."),
                Report.create_text_segment("Please check the communication interface logs for more information.")
            ]}]


        title = "UDS Read Memory By Did"
        segments = []

        for k, v in results["memory_contents"].items():
            if v == 0:
                segments.append(Report.create_text_segment(f'Format {k:x} allowed definition but not reading'))
            else:
                segments.append(Report.create_text_segment(f'Format {k:x} read "{v}" ({v.hex()})'))

        if not results["pass_rules"]["vulnerable"]:
            segments.append(
                Report.create_text_segment(
                    f"Could not read any target memory. Test passed."
                )
            )

        return [{"title": title, "segments": segments}]

