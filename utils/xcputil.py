# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import can
import time

XCP_ERROR_CODES = {
    0x00: "SYNCH",
    0x10: "BUSY",
    0x11: "DAQ_ACTIVE",
    0x12: "PGM_ACTIVE",
    0x20: "CMD_UNKNOWN",
    0x21: "INVALID_SYNTAX",
    0x22: "OUT_OF_RANGE",
    0x23: "WRITE_PROTECTED",
    0x24: "ACCESS_DENIED",
    0x25: "ACCESS_LOCKED",
    0x26: "PAGE_NOT_VALID",
    0x27: "MODE_NOT_VALID",
    0x28: "SEGMENT_NOT_VALID",
    0x29: "SEQUENCE_ERROR",
    0x2A: "INVALID_DAQ_CONFIG",
    0x30: "MEMORY_OVERFLOW",
    0x31: "GENERIC_ERROR",
    0x32: "INTERNAL_APP_VERIFY_ERROR",
}

XCP_SERVICES = {
    0xFF: "CONNECT",
    0xFE: "DISCONNECT",
    0xFD: "GET_STATUS",
    0xFC: "SYNCH",
    0xFB: "GET_COMM_MODE_INFO",
    0xFA: "GET_ID",
    0xF9: "SET_REQUEST",
    0xF8: "GET_SEED",
    0xF7: "UNLOCK",
    0xF6: "SET_MTA",
    0xF5: "UPLOAD",
    0xF4: "SHORT_UPLOAD",
    0xF3: "BUILD_CHECKSUM",
    0xF2: "TRANSPORT_LAYER_CMD",
    0xF1: "USER_CMD",
    0xF0: "DOWNLOAD",
    0xEF: "DOWNLOAD_NEXT",
    0xEE: "DOWNLOAD_MAX",
    0xED: "SHORT_DOWNLOAD",
    0xEC: "MODIFY_BITS",
    0xEB: "SET_CAL_PAGE",
    0xEA: "GET_CAL_PAGE",
    0xE9: "GET_PAG_PROCESSOR_INFO",
    0xE8: "GET_SEGMENT_INFO",
    0xE7: "GET_PAGE_INFO",
    0xE6: "SET_SEGMENT_MODE",
    0xE5: "GET_SEGMENT_MODE",
    0xE4: "COPY_CAL_PAGE",
    0xE3: "CLEAR_DAQ_LIST",
    0xE2: "SET_DAQ_PTR",
    0xE1: "WRITE_DAQ",
    0xE0: "SET_DAQ_LIST_MODE",
    0xDF: "GET_DAQ_LIST_MODE",
    0xDE: "START_STOP_DAQ_LIST",
    0xDD: "START_STOP_SYNCH",
    0xDC: "GET_DAQ_CLOCK",
    0xDB: "READ_DAQ",
    0xDA: "GET_DAQ_PROCESSOR_INFO",
    0xD9: "GET_DAQ_RESOLUTION_INFO",
    0xD8: "GET_DAQ_LIST_INFO",
    0xD7: "GET_DAQ_EVENT_INFO",
    0xD6: "FREE_DAQ",
    0xD5: "ALLOC_DAQ",
    0xD4: "ALLOC_ODT",
    0xD3: "ALLOC_ODT_ENTRY",
    0xD2: "PROGRAM_START",
    0xD1: "PROGRAM_CLEAR",
    0xD0: "PROGRAM",
    0xCF: "PROGRAM_RESET",
    0xCE: "GET_PGM_PROCESSOR_INFO",
    0xCD: "GET_SECTOR_INFO",
    0xCC: "PROGRAM_PREPARE",
    0xCB: "PROGRAM_FORMAT",
    0xCA: "PROGRAM_NEXT",
    0xC9: "PROGRAM_MAX",
    0xC8: "PROGRAM_VERIFY",
}


class xcp:
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
            if msg is None or len(msg.data) < 2 or msg.arbitration_id != self.resp_arb:
                continue
            if msg.data[0] != 0xFF and msg.data[0] != 0xFE:
                continue
            if len(msg.data) == 3 and msg.data[2] == 0x30:
                continue  # CCP response
            return msg.data


def mk_xcp(bus, server, extended_id=None, is_fd=False):
    if extended_id == None:
        extended_id = server[0] > 0x7FF
    return xcp(bus, server[0], server[1], extended_id, is_fd)
