# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import can
import time

CCP_SERVICE_NAMES = {
    0x01: "CONNECT",
    0x02: "SET_MTA",
    0x03: "DOWNLOAD",
    0x04: "UPLOAD",
    0x05: "TEST",
    0x06: "START_STOP",
    0x07: "DISCONNECT",
    0x08: "START_STOP_ALL",
    0x09: "GET_ACTIVE_CAL_PAGE",
    0x0C: "SET_S_STATUS",
    0x0D: "GET_S_STATUS",
    0x0E: "BUILD_CHECKSUM",
    0x0F: "SHORT_UP",
    0x10: "CLEAR_MEMORY",
    0x11: "SELECT_CAL_PAGE",
    0x12: "GET_SEED",
    0x13: "UNLOCK",
    0x14: "GET_DAQ_SIZE",
    0x15: "SET_DAQ_PTR",
    0x16: "WRITE_DAQ",
    0x17: "EXCHANGE_ID",
    0x18: "PROGRAM",
    0x1B: "GET_XCP_VERSION",
    0x20: "DIAG_SERVICE",
    0x21: "ACTION_SERVICE",
    0x22: "PROGRAM_6",
    0x23: "DOWNLOAD_6",
}

CCP_NRCs = {
    0x00: "ACKNOWLEDGE",
    0x01: "DAQ Processor Overload",
    0x10: "Command Processor Busy",
    0x11: "DAQ Processor Busy",
    0x12: "Internal Timeout",
    0x18: "Key Request",
    0x19: "Session Status Request",
    0x20: "Cold Start Request",
    0x21: "Cal data init request",
    0x22: "DAQ list init request",
    0x23: "Code Update Request",
    0x30: "Unknown Command",
    0x31: "Command Syntax Error",
    0x32: "Param out of range",
    0x33: "Access Denied",
    0x34: "Overload",
    0x35: "Access locked",
    0x36: "Resource not available",
}


class ccp:
    def __init__(self, bus, req_arb, resp_arb, extended_id=False, is_fd=False):
        self.bus = bus
        self.req_arb = req_arb
        self.resp_arb = resp_arb
        self.extended_arb = extended_id
        self.is_fd = is_fd

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def send(self, data):
        msg = can.Message(
            arbitration_id=self.req_arb, data=data, is_extended_id=self.extended_arb, is_fd=self.is_fd
        )
        self.bus.send(msg)

    def recv(self, timeout=1.0):
        end_time = time.time() + timeout
        while time.time() < end_time:
            msg = self.bus.recv(timeout)
            if msg is None or len(msg.data) < 1 or msg.arbitration_id != self.resp_arb:
                continue
            if msg.data[0] != 0xFF:
                continue
            return msg.data


def mk_ccp(bus, server, extended_id=None, is_fd=False):
    if extended_id == None:
        extended_id = server[0] > 0x7FF
    x = ccp(bus, server[0], server[1], extended_id, is_fd)
    return x
