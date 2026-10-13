# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *

@register_audit("uds_security_access")
class uds_security_access(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("extended_id", "Extended ID", "False", "Whether or not to use 29 bit arbitration IDs"),
        Parameter("is_fd", "Flexible Data Rate", "False", "Whether or not to use CAN FD frames for this test"),
        Parameter("frame_len", "Static Frame Length", "0", "Pad every CAN frame out to this fixed length, 0 leaves each frame at its natural length. Lengths above 8 (12, 16, 20, 24, 32, 48, 64) require CAN FD"),
        Parameter("frame_fill", "Frame Fill Byte", "0x00", "The byte used to pad frames up to the static frame length"),
        Parameter("req_arb", "Request Arbitration ID", "0x7e0", "The arbitration ID to send requests to"),
        Parameter("resp_arb", "Response Arbitration ID", "0x7e8", "The arbitration ID where replies will be sent"),
        Parameter("min_seed_len", "Expected Minimum Seed Length", "8", "The minimum number of bytes the seed shall be to pass this test"),
        Parameter("seeds_requested", "Number of Seeds Requested", "5", "Number of seeds requested when checking for duplicates"),
        Parameter("session", "Diagnostic session", "1", "The diagnostic session (or pair) to enter for this test"),
        Parameter("uds_reset_after", "ECU Reset After Seeds", "0", "Send an ECU reset (0x11 0x01) after every this many seeds and re-enter the session, 0 disables it. A seed generator that restarts from a fixed state repeats its seeds after each reset"),
    ]
    dependencies = ['python-can', 'can-isotp']
    friendly_name = "UDS Security Access"
    description = "Validates security access seed strength. The test requests seeds for every access level and validates that Service 27 always returns a unique seed of sufficient length."
    fail_condition = "If duplicate seeds are obtained, or a seed of insufficient length is seen for any access level, this test will be marked as failed."
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["CAN"]
    relevant_protocols = ["UDS"]
    bw_audit_id = "TS_CAN_0016"
    estimated_time_in_minutes = "5"
    test_outcomes = {
        "SUCCESS": {
            "description": "Security Access service returned unique seeds of sufficient length for every access level.",
            "recommendations": [
                "Continue monitoring seed strength and uniqueness.",
                "Verify timeout mechanisms remain effective against brute force attacks.",
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
            "description": "Security Access returned seeds that are too short or repeated, making brute force attacks feasible.",
            "recommendations": [
                "Increase minimum seed length to at least 64 bits.",
                "Implement cryptographically secure random number generation.",
                "Review seed generation algorithms for predictability.",
                "Fix seed generation to ensure uniqueness.",
                "Review seed storage and caching mechanisms.",
                "Consider implementing additional authentication factors."
            ]
        }
    }

    def _uds_session_enter(self, sessions):
        import time
        for session in [1] + sessions:
            self.stack.send(bytearray([0x10, session]))
            end_time = time.time() + 0.5
            resp = None
            while time.time() < end_time:
                self.stack.process()
                resp = self.stack.recv()
                if resp is not None:
                    break
                time.sleep(0.001)
            if not resp or resp[0] != 0x50:
                return False
        return True

    def _uds_reset(self, sessions, timeout=5):
        """Hard resets the ECU and re-enters the sessions once it answers again."""
        import time
        self.stack.send(bytearray([0x11, 0x01]))
        end_time = time.time() + 1
        while time.time() < end_time:
            self.stack.process()
            resp = self.stack.recv()
            if resp is not None and resp[0] in [0x51, 0x7f]:
                break
            time.sleep(0.001)
        # The ECU may take a while to come back after the reset
        end_time = time.time() + timeout
        while time.time() < end_time:
            if self._uds_session_enter(sessions):
                return True
            time.sleep(0.1)
        return False

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
        min_seed_len = Parameter.number(self.params["min_seed_len"])
        seeds_requested = Parameter.number(self.params["seeds_requested"])
        reset_after = Parameter.number(self.params["uds_reset_after"])
        seed_count = 0
        sessions_raw = self.params["session"].strip()
        sessions = [int(s.strip(), 0) for s in sessions_raw.split(",")] if "," in sessions_raw else [int(sessions_raw, 0)]
        severity = "n/a"
        seeds = []
        seed_length = min_seed_len

        bus = can.Bus(interface="socketcan", channel=device, fd=is_fd)

        addr = isotp.Address(
            isotp.AddressingMode.Normal_29bits if eid else isotp.AddressingMode.Normal_11bits,
            txid=int(arb_req, 16),
            rxid=int(arb_resp, 16),
        )
        try:
            self.stack = isotp.CanStack(bus, address=addr, params=isotp_params)
        except ValueError as e:
            bus.shutdown()
            return {"params": self.params, "error": f"Bad frame parameters: {e}"}

        if not self._uds_session_enter(sessions):
            bus.shutdown()
            return {"params": self.params, "error": "Failed to enter session!"}

        session_seeds = {}
        for access_level in range(1, 0x80, 2):
            session_seeds[access_level] = []

            while len(session_seeds[access_level]) < seeds_requested:
                self.stack.send(bytearray([0x27, access_level]))
                end_time = time.time() + 0.5
                seed_resp = None
                while time.time() < end_time:
                    self.stack.process()
                    seed_resp = self.stack.recv()
                    if seed_resp is not None:
                        break
                    time.sleep(0.001)

                if not seed_resp:
                    break

                if seed_resp[0] == 0x67:
                    session_seeds[access_level].append(seed_resp[2:].hex())
                    seed_count += 1
                    if reset_after and seed_count % reset_after == 0:
                        self.log.debug(f'resetting the ECU after {seed_count} seeds')
                        if not self._uds_reset(sessions):
                            bus.shutdown()
                            return {"params": self.params, "error": "Failed to re-enter session after ECU reset!"}
                    continue

                if seed_resp[0] != 0x7f:
                    self.log.debug('nonsense reply received:', seed_resp.hex())
                    continue

                if seed_resp[2] in [ 0x36, 0x37 ]:
                    self.log.debug(f'Waiting a bit before requesting more seeds...')
                    time.sleep(5)
                    continue

                self.log.debug(f'unexpected NRC requesting seeds with access level {access_level}: 0x{seed_resp[2]:02x}')
                break

            if len(session_seeds[access_level]) == 0:
                del session_seeds[access_level]

        bus.shutdown()

        test_results = {
            "params": self.params,
            "severity": severity,
            "seeds": session_seeds,
            'min_seed_len': min_seed_len,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

        all_seeds = [seed for seeds in session_seeds.values() for seed in seeds]
        if len(all_seeds) > 0:
            # Seeds are kept as hex, two characters per byte
            if min(len(seed) // 2 for seed in all_seeds) < min_seed_len:
                test_results['fail_cond'] = 'seed_too_small'
                test_results['pass_rules']['vulnerable'] = True

            if len(set(all_seeds)) < len(all_seeds):
                test_results['fail_cond'] = 'duplicate_seeds'
                test_results['pass_rules']['vulnerable'] = True

        return test_results

    def format_results(self, results):
        if "error" in results:
            return [{"title": results["error"], "segments": [
                Report.create_text_segment("This test encountered an error and did not run."),
                Report.create_text_segment("Please check the communication interface logs for more information.")
            ]}]


        title = "Security Access Test Complete"

        segments = []

        if 'fail_cond' in results:
            if results['fail_cond'] == 'seed_too_small':
                title = "Security Access Insufficient Seed Length"
                segments.append(
                    Report.create_text_segment(
                        f'Request Seed returned a seed of insufficient security strength at {results["min_seed_len"]} bytes. Test failed.'
                    )
                )
            elif results['fail_cond'] == 'duplicate_seeds':
                title = "Security Access Duplicate Seeds"
                segments.append(
                    Report.create_text_segment(
                        f"Repeated seed values found. Test failed."
                    )
                )
        else:
            segments.append(
                Report.create_text_segment(
                    f"Security Access seed strength evaluation completed. Test passed"
                )
            )

        return [{"title": title, "segments": segments}]
