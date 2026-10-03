# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os
import can
import sys
import time
import threading

NRC_NAMES = {
    0x00: "POSITIVE_RESPONSE",
    0x10: "GENERAL_REJECT",
    0x11: "SERVICE_NOT_SUPPORTED",
    0x12: "SUB_FUNCTION_NOT_SUPPORTED",
    0x13: "INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT",
    0x14: "RESPONSE_TOO_LONG",
    0x21: "BUSY_REPEAT_REQUEST",
    0x22: "CONDITIONS_NOT_CORRECT",
    0x24: "REQUEST_SEQUENCE_ERROR",
    0x25: "NO_RESPONSE_FROM_SUBNET_COMPONENT",
    0x26: "FAILURE_PREVENTS_EXECUTION_OF_REQUESTED_ACTION",
    0x31: "REQUEST_OUT_OF_RANGE",
    0x33: "SECURITY_ACCESS_DENIED",
    0x34: "AUTHENTICATION_REQUIRED",
    0x35: "INVALID_KEY",
    0x36: "EXCEEDED_NUMBER_OF_ATTEMPTS",
    0x37: "REQUIRED_TIME_DELAY_NOT_EXPIRED",
    0x70: "UPLOAD_DOWNLOAD_NOT_ACCEPTED",
    0x71: "TRANSFER_DATA_SUSPENDED",
    0x72: "GENERAL_PROGRAMMING_FAILURE",
    0x73: "WRONG_BLOCK_SEQUENCE_COUNTER",
    0x78: "REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING",
    0x7E: "SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION",
    0x7F: "SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION",
    0x81: "RPM_TOO_HIGH",
    0x82: "RPM_TOO_LOW",
    0x83: "ENGINE_IS_RUNNING",
    0x84: "ENGINE_IS_NOT_RUNNING",
    0x85: "ENGINE_RUN_TIME_TOO_LOW",
    0x86: "TEMPERATURE_TOO_HIGH",
    0x87: "TEMPERATURE_TOO_LOW",
    0x88: "VEHICLE_SPEED_TOO_HIGH",
    0x89: "VEHICLE_SPEED_TOO_LOW",
    0x8A: "THROTTLE_PEDAL_TOO_HIGH",
    0x8B: "THROTTLE_PEDAL_TOO_LOW",
    0x8C: "TRANSMISSION_RANGE_NOT_IN_NEUTRAL",
    0x8D: "TRANSMISSION_RANGE_NOT_IN_GEAR",
    0x8F: "BRAKE_SWITCHES_NOT_CLOSED",
    0x90: "SHIFT_LEVER_NOT_IN_PARK",
    0x91: "TORQUE_CONVERTER_CLUTCH_LOCKED",
    0x92: "VOLTAGE_TOO_HIGH",
    0x93: "VOLTAGE_TOO_LOW",
}

SERVICE_NAMES = {
    0x10: "DIAGNOSTIC_SESSION_CONTROL",
    0x11: "ECU_RESET",
    0x14: "CLEAR_DIAGNOSTIC_INFORMATION",
    0x19: "READ_DTC_INFORMATION",
    0x22: "READ_DATA_BY_IDENTIFIER",
    0x23: "READ_MEMORY_BY_ADDRESS",
    0x24: "READ_SCALING_DATA_BY_IDENTIFIER",
    0x27: "SECURITY_ACCESS",
    0x28: "COMMUNICATION_CONTROL",
    0x29: "AUTHENTICATION",
    0x2A: "READ_DATA_BY_PERIODIC_IDENTIFIER",
    0x2C: "DYNAMICALLY_DEFINE_DATA_IDENTIFIER",
    0x2E: "WRITE_DATA_BY_IDENTIFIER",
    0x2F: "INPUT_OUTPUT_CONTROL_BY_IDENTIFIER",
    0x31: "ROUTINE_CONTROL",
    0x34: "REQUEST_DOWNLOAD",
    0x35: "REQUEST_UPLOAD",
    0x36: "TRANSFER_DATA",
    0x37: "REQUEST_TRANSFER_EXIT",
    0x38: "REQUEST_FILE_TRANSFER",
    0x3D: "WRITE_MEMORY_BY_ADDRESS",
    0x3E: "TESTER_PRESENT",
    0x83: "ACCESS_TIMING_PARAMETER",
    0x84: "SECURED_DATA_TRANSMISSION",
    0x85: "CONTROL_DTC_SETTING",
    0x86: "RESPONSE_ON_EVENT",
    0x87: "LINK_CONTROL",
}

SESSION_NAMES = {
    0x01: "defaultSession",
    0x02: "ProgrammingSession",
    0x03: "extendedDiagnosticSession",
    0x04: "safetySystemDiagnosticSession",
}
for i in range(0x40, 0x60):
    SESSION_NAMES[i] = "vehicleManufacturerSpecific"
for i in range(0x60, 0x7F):
    SESSION_NAMES[i] = "systemSupplierSpecific"

DID_META = {
    0xF180: {
        "name": "BootSoftwareIdentificationDataIdentifier",
        "mnemonic": "BSIDID",
        "description": "This value shall be used to reference the vehicle manufacturer specific ECU boot software identification record. The first data byte of the record data shall be the numberOfModules that are reported. Following the numberOfModules the boot software identification(s) are reported. The format of the boot software identification structure shall be ECU specific and defined by the vehicle manufacturer.",
    },
    0xF181: {
        "name": "applicationSoftwareIdentificationDataIdentifier",
        "mnemonic": "ASIDID",
        "description": "This value shall be used to reference the vehicle manufacturer specific ECU application software number(s). The first data byte of the record data shall be the numberOfModules that are reported. Following the numberOfModules the application software identification(s) are reported. The format of the application software identification structure shall be ECU specific and defined by the vehicle manufacturer.",
    },
    0xF182: {
        "name": "applicationDataIdentificationDataIdentifier",
        "mnemonic": "ADIDID",
        "description": "This value shall be used to reference the vehicle manufacturer specific ECU application data identification record. The first data byte of the record data shall be the numberOfModules that are reported. Following the numberOfModules the application data identification(s) are reported. The format of the application data identification structure shall be ECU specific and defined by the vehicle manufacturer.",
    },
    0xF183: {
        "name": "bootSoftwareFingerprintDataIdentifier",
        "mnemonic": "BSFPDID",
        "description": "This value shall be used to reference the vehicle manufacturer specific ECU boot software fingerprint identification record. Record data content and format shall be ECU specific and defined by the vehicle manufacturer.",
    },
    0xF184: {
        "name": "applicationSoftwareFingerprintDataIdentifier",
        "mnemonic": "ASFPDID",
        "description": "This value shall be used to reference the vehicle manufacturer specific ECU application software fingerprint identification record. Record data content and format shall be ECU specific and defined by the vehicle manufacturer.",
    },
    0xF185: {
        "name": "applicationDataFingerprintDataIdentifier",
        "mnemonic": "ADFPDID",
        "description": "This value shall be used to reference the vehicle manufacturer specific ECU application data fingerprint identification record. Record data content and format shall be ECU specific and defined by the vehicle manufacturer.",
    },
    0xF186: {
        "name": "ActiveDiagnosticSessionDataIdentifier",
        "mnemonic": "ADSDID",
        "description": "This value shall be used to report the active diagnostic session in the server. The values are defined by the diagnosticSessionTypeSubFunction parameter in the DiagnosticSessionControl service.",
    },
    0xF187: {
        "name": "vehicleManufacturerSparePartNumberDataIdentifier",
        "mnemonic": "VMSPNDID",
        "description": "This value shall be used to reference the vehicle manufacturer spare part number. Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF188: {
        "name": "vehicleManufacturerECUSoftwareNumberDataIdentifier",
        "mnemonic": "VMECUSNDID",
        "description": "This value shall be used to reference the vehicle manufacturer ECU (server) software number. Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF189: {
        "name": "vehicleManufacturerECUSoftwareVersionNumberDataIdentifier",
        "mnemonic": "VMECUSVNDID",
        "description": "This value shall be used to reference the vehicle manufacturer ECU (server) software version number. Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF18A: {
        "name": "systemSupplierIdentifierDataIdentifier",
        "mnemonic": "SSIDDID",
        "description": "This value shall be used to reference the system supplier name and address information. Record data content and format shall be server specific and defined by the system supplier.",
    },
    0xF18B: {
        "name": "ECUManufacturingDateDataIdentifier",
        "mnemonic": "ECUMDDID",
        "description": "This value shall be used to reference the ECU (server) manufacturing date. Record data content and format shall be unsigned numeric, ASCII or BCD, and shall be ordered as Year, Month, Day.",
    },
    0xF18C: {
        "name": "ECUSerialNumberDataIdentifier",
        "mnemonic": "ECUSNDID",
        "description": "This value shall be used to reference the ECU (server) serial number. Record data content and format shall be server specific.",
    },
    0xF18D: {
        "name": "supportedFunctionalUnitsDataIdentifier",
        "mnemonic": "SFUDID",
        "description": "This value shall be used to request the functional units implemented in a server.",
    },
    0xF18E: {
        "name": "VehicleManufacturerKitAssemblyPartNumberDataIdentifier",
        "mnemonic": "VMKAPNDID",
        "description": "This value shall be used to reference the vehicle manufacturer order number for a kit (assembled parts bought as a whole for production e.g. cockpit), when the spare part number designates only the server (e.g. for aftersales). The record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF18F: {
        "name": "RegulationXSoftwareIdentificationNumbers",
        "mnemonic": "RXSWIN",
        "description": "This value shall be used to report Regulation-related Software Identification Numbers.",
    },
    0xF190: {
        "name": "VINDataIdentifier",
        "mnemonic": "VINDID",
        "description": "This value shall be used to reference the VIN number. Record data content and format shall be specified by the vehicle manufacturer.",
    },
    0xF191: {
        "name": "vehicleManufacturerECUHardwareNumberDataIdentifier",
        "mnemonic": "VMECUHNDID",
        "description": "This value shall be used by reading services to reference the vehicle manufacturer specific ECU (server) hardware number. Record data content and format shall be server specific and defined by vehicle manufacturer.",
    },
    0xF192: {
        "name": "systemSupplierECUHardwareNumberDataIdentifier",
        "mnemonic": "SSECUHWNDID",
        "description": "This value shall be used to reference the system supplier specific ECU (server) hardware number. Record data content and format shall be server specific and defined by the system supplier.",
    },
    0xF193: {
        "name": "systemSupplierECUHardwareVersionNumberDataIdentifier",
        "mnemonic": "SSECUHWVNDID",
        "description": "This value shall be used to reference the system supplier specific ECU (server) hardware version number. Record data content and format shall be server specific and defined by the system supplier.",
    },
    0xF194: {
        "name": "systemSupplierECUSoftwareNumberDataIdentifier",
        "mnemonic": "SSECUSWNDID",
        "description": "This value shall be used to reference the system supplier specific ECU (server) software number. Record data content and format shall be server specific and defined by the system supplier.",
    },
    0xF195: {
        "name": "systemSupplierECUSoftwareVersionNumberDataIdentifier",
        "mnemonic": "SSECUSWVNDID",
        "description": "This value shall be used to reference the system supplier specific ECU (server) software version number. Record data content and format shall be server specific and defined by the system supplier.",
    },
    0xF196: {
        "name": "exhaustRegulationOrTypeApprovalNumberDataIdentifier",
        "mnemonic": "EROTANDID",
        "description": "This value shall be used to reference the exhaust regulation or type approval number (valid for those systems which require type approval). Record data content and format shall be server specific and defined by the vehicle manufacturer. Refer to the relevant legislation for any applicable requirements.",
    },
    0xF197: {
        "name": "systemNameOrEngineTypeDataIdentifier",
        "mnemonic": "SNOETDID",
        "description": "This value shall be used to reference the system name or engine type. Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF198: {
        "name": "repairShopCodeOrTesterSerialNumberDataIdentifier",
        "mnemonic": "RSCOTSNDID",
        "description": "This value shall be used to reference the repair shop code or tester (client) serial number (e.g. to indicate the most recent service client used reprogram server memory). Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF199: {
        "name": "programmingDateDataIdentifier",
        "mnemonic": "PDDID",
        "description": "This value shall be used to reference the date when the server was last programmed. Record data content and format shall be unsigned numeric, ASCII or BCD, and shall be ordered as Year, Month, Day.",
    },
    0xF19A: {
        "name": "calibrationRepairShopCodeOrCalibrationEquipmentSerialNumberDataIdentifier",
        "mnemonic": "CRSCOCESNDID",
        "description": "This value shall be used to reference the repair shop code or client serial number (e.g. to indicate the most recent service used by the client to re-calibrate the server). Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF19B: {
        "name": "calibrationDateDataIdentifier",
        "mnemonic": "CDDID",
        "description": "This value shall be used to reference the date when the server was last calibrated. Record data content and format shall be unsigned numeric, ASCII or BCD, and shall be ordered as Year, Month, Day.",
    },
    0xF19C: {
        "name": "calibrationEquipmentSoftwareNumberDataIdentifier",
        "mnemonic": "CESWNDID",
        "description": "This value shall be used to reference software version within the client used to calibrate the server. Record data content and format shall be server specific and defined by the vehicle manufacturer.",
    },
    0xF19D: {
        "name": "ECUInstallationDateDataIdentifier",
        "mnemonic": "EIDDID",
        "description": "This value shall be used to reference the date when the ECU (server) was installed in the vehicle. Record data content and format shall be either unsigned numeric, ASCII or BCD, and shall be ordered as Year, Month, Day.",
    },
    0xF19E: {
        "name": "ODXFileDataIdentifier",
        "mnemonic": "ODXFDID",
        "description": "This value shall be used to reference the ODX (Open Diagnostic Data Exchange) file of the server to be used to interpret and scale the server data.",
    },
    0xF19F: {
        "name": "EntityDataIdentifier",
        "mnemonic": "EDID",
        "description": "This value shall be used to reference the entity data identifier for a secured data transmission.",
    },
    0xFA10: {
        "name": "NumberOfEDRDevices",
        "mnemonic": "NOEDRD",
        "description": "This value shall be used to report the number of EDR devices capable of reporting EDR data.",
    },
    0xFA11: {
        "name": "EDRIdentification",
        "mnemonic": "EDRI",
        "description": "This value shall be used to report EDR identification data.",
    },
    0xFA12: {
        "name": "EDRDeviceAddressInformation",
        "mnemonic": "EDRDAI",
        "description": "This value shall be used to report EDR device adress information according to the format defined in ISO 26021-2 for dataIdentifier 0xFA02.",
    },
    0xFF00: {
        "name": "UDSVersionDataIdentifier",
        "mnemonic": "UDSVDID",
        "description": "This value shall be used to reference the UDS version implemented in the server. See Table C.11 for the scaling of this DID.",
    },
    0xFF01: {
        "name": "FDSupportDataIdentifier",
        "mnemonic": "RESRVDCPADLC",
        "description": "This value shall be used to identify whether the vehicle's ECUs (servers) connected to the diagnostic link connector support CAN Classical or CAN FD or both.",
    },
}

def bytes2hex(byte_array):
    return "".join(f"{b:02x}" for b in byte_array)


class isotp:
    def __init__(self, bus, req_arb, resp_arb, logger, extended_id=False, is_fd=False):
        self.bus = bus
        self.req_arb = req_arb
        self.resp_arb = resp_arb
        self.extended_arb = extended_id
        self.is_fd = is_fd
        self.log = logger

        self.state = []  # seq, data len, data
        self.flow_control = can.Message(
            arbitration_id=req_arb,
            data=[0x30, 0, 0, 0, 0, 0, 0, 0],
            is_extended_id=self.extended_arb,
            is_fd=is_fd,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @staticmethod
    def _send(bus, req_arb, resp_arb, msg, timeout=0.5, extended_arb=False, is_fd=False):
        data_len = len(msg)
        data = []
        data.extend(msg)
        maxdlc = 64 if is_fd else 8

        if data_len < 8:
            data.insert(0, len(data))
            while len(data) < 8:
                data.append(0)
            msg = can.Message(
                arbitration_id=req_arb, data=data, is_extended_id=extended_arb, is_fd=is_fd
            )
            bus.send(msg)
        elif is_fd and data_len < 63:
            data.insert(0, 0)
            data.insert(1, data_len)
            while len(data) < 64:
                data.append(0)
            msg = can.Message(
                arbitration_id=req_arb, data=data, is_extended_id=extended_arb, is_fd=is_fd
            )
            bus.send(msg)
        elif data_len < 4096:
            msg = can.Message(
                arbitration_id=req_arb,
                data=[0x10 | ((data_len >> 8) & 0xF), data_len & 0xFF] + data[:(maxdlc-2)],
                is_extended_id=extended_arb,
                is_fd=is_fd,
            )
            bus.send(msg)

            end_time = time.time() + timeout
            while True:  # wait for flow control message
                msg = bus.recv(timeout)
                # we only break out on continue frames, flow control is more complex
                if msg and msg.arbitration_id == resp_arb and msg.data[0] == 0x30:
                    break
                if time.time() > end_time:
                    return

            seq = 0
            data_idx = (maxdlc-2)
            while data_idx < data_len:
                seq = (seq + 1) & 0xF
                msg_data = [0x20 | seq] + data[data_idx : data_idx + (maxdlc-1)]
                while len(msg_data) < maxdlc:
                    msg_data.append(0)
                msg = can.Message(
                    arbitration_id=req_arb, data=msg_data, is_extended_id=extended_arb, is_fd=is_fd,
                )

                data_idx += (maxdlc-1)
                bus.send(msg)
        elif is_fd and data_len < 0x100000000:
            msg = can.Message(
                arbitration_id=req_arb,
                data=b'\x10\x00' + data_len.to_bytes(4, 'big') + bytes(data[:(maxdlc-6)]),
                is_extended_id=extended_arb,
                is_fd=is_fd,
            )
            bus.send(msg)

            end_time = time.time() + timeout
            while True:  # wait for flow control message
                msg = bus.recv(timeout)
                # we only break out on continue frames, flow control is more complex
                if msg and msg.arbitration_id == resp_arb and msg.data[0] == 0x30:
                    break
                if time.time() > end_time:
                    return

            seq = 0
            data_idx = (maxdlc-6)
            while data_idx < data_len:
                seq = (seq + 1) & 0xF
                msg_data = [0x20 | seq] + data[data_idx : data_idx + (maxdlc-1)]
                while len(msg_data) < maxdlc:
                    msg_data.append(0)
                msg = can.Message(
                    arbitration_id=req_arb, data=msg_data, is_extended_id=extended_arb, is_fd=is_fd,
                )

                data_idx += (maxdlc-1)
                bus.send(msg)
        else:
            print("message too long for isotp frame")

    def send(self, data, timeout=0.5):
        isotp._send(self.bus, self.req_arb, self.resp_arb, data, timeout, self.extended_arb, self.is_fd)

    def recv(self, timeout=0.5):
        end_time = time.time() + timeout
        while time.time() < end_time:
            msg = self.bus.recv(timeout)
            if msg is None or len(msg.data) < 1 or msg.arbitration_id != self.resp_arb:
                continue

            frame_type = (msg.data[0] >> 4) & 0xF
            if frame_type == 0:  # single frame
                offset = 1
                data_len = msg.data[0] & 0xF
                if data_len == 0:
                    offset = 2
                    data_len = msg.data[1]
                return msg.data[offset : data_len + offset]
            elif frame_type == 1:  # first frame
                self.bus.send(self.flow_control)
                offset = 2
                data_len = ((msg.data[0] & 0xF) << 8) | msg.data[1]
                if data_len == 0:
                    offset = 6
                    data_len = (((((msg.data[2] << 8) | msg.data[3]) << 8) | msg.data[4]) << 8) | msg.data[5]
                self.state = [0, data_len, msg.data[offset:]]
            elif frame_type == 2:  # continuous frame
                seq = msg.data[0] & 0xF
                data = msg.data[1:]
                if seq == (self.state[0] + 1) % 16:
                    self.state[0] = seq
                    self.state[2] += data
                    if len(self.state[2]) >= self.state[1]:
                        msg = self.state[2][: self.state[1]]
                        self.state = []
                        return msg


def mk_isotp(bus, server, extended_id=None, is_fd=False, max_dlc=8, log=print):
    if extended_id == None:
        extended_id = server[0] > 0x7FF
    tp = isotp(bus, server[0], server[1], log, extended_id, is_fd)
    return tp

def send(tp, msg_data, timeout=0.5, capture_response=True):
    tp.send(msg_data)
    return tp.recv(timeout) if capture_response else None

def uds_session_enter(tp, requested):
    for session in [ 1 ] + requested:
        resp = send(tp, [0x10, session])
        if not resp or resp[0] != 0x50:
            return False

    return True


def uds_session_scan(tp):
    # Discover available sessions
    supported_sessions = []
    secured_sessions = []

    # skip session 1: default session (which is always supported)
    for session in range(2, 0x7F):
        session_resp = send(tp, [0x10, session])

        # successful transition
        if session_resp and (session_resp[0] == 0x50):
            supported_sessions.append([0x01, session])
            time.sleep(0.1)  # delay to let target finish switching

            # check for secondary transitions
            for level2 in range(2, 0x7F):
                if (level2 > 4 and level2 <= 0x3F) or (level2 == session):
                    continue  # iso sae reserved

                session_resp = send(tp, [0x10, level2])

                # successful transition
                if session_resp and (session_resp[0] == 0x50):
                    supported_sessions.append([session, level2])
                    time.sleep(0.1)  # delay to let target finish switching

                    # switch back to previous session
                    send(tp, [0x10, session])
                    time.sleep(0.1)  # delay to let target finish switching

                elif (
                    session_resp
                    and (session_resp[0] == 0x7F)
                    and (session_resp[1] == 0x10)
                    and (
                        session_resp[2] == 0x22
                        or session_resp[2] == 0x33
                        or session_resp[2] == 0x34
                    )
                ):
                    # the session exists but is protected (NRC 0x22, 0x33 or 0x34)
                    secured_sessions.append([session, level2, session_resp[2]])

            # reset session back to default
            send(tp, [0x10, 0x01])
            time.sleep(0.2)  # delay to let target switch sessions

        elif (
            session_resp
            and (session_resp[0] == 0x7F)
            and (session_resp[1] == 0x10)
            and (
                session_resp[2] == 0x22
                or session_resp[2] == 0x33
                or session_resp[2] == 0x34
            )
        ):
            # the session exists but is protected (NRC 0x22, 0x33 or 0x34)
            secured_sessions.append([0x01, session, session_resp[2]])

    return {"sessions": supported_sessions, "secured": secured_sessions}


def check_service_support_in_session(tp, req_msg):

    sid = req_msg[0]
    resp = send(tp, req_msg)
    # Any response, positive or negative, counts as the service being present.
    if resp:
        return True
    return False


def proc_did_resp(resp, sid):
    supported = False
    nrc = 0

    # any response?
    if resp:
        # positive response
        if resp[0] == sid + 0x40:
            supported = True
        # negative response
        elif resp[0] == 0x7F and resp[1] == sid:
            if resp[2] not in [0x13, 0x31, 0x33, 0x34]:  # DID is supported
                nrc = resp[2]
                supported = True

    return {"isSupported": supported, "nrc": nrc}


def check_did_read_support(tp, supported_sessions, min_did=0x0000, max_did=0xFFFF):

    did_table = []

    for session in supported_sessions:
        session_resp = send(tp, [0x10, session])
        time.sleep(0.3)  # delay to let target switch sessions

        if session_resp and (session_resp[0] == 0x50):
            for id in range(min_did, max_did + 1):
                # check read
                resp = send(tp, [0x22, (id >> 8) & 0xFF, id & 0xFF])
                read = proc_did_resp(resp, 0x22)

                # append DID support information into table
                if read["isSupported"]:
                    did_table.append({"session": session, "id": id, "read": read})

    # reset session to default
    send(tp, [0x10, 0x01])
    time.sleep(0.3)  # delay to let target switch sessions

    return did_table


def check_did_write_support(tp, did_table, min_did=0x0000, max_did=0xFFFF):
    # scan through range of dids
    for id in range(min_did, max_did + 1):
        data_value = []

        # check read
        resp = send(tp, [0x22, (id >> 8) & 0xFF, id & 0xFF])
        if resp == None:
            continue
        read = proc_did_resp(resp, 0x22)
        if read["isSupported"] == True and read["nrc"] == 0:
            # save data for later use
            data_value = resp[3 : len(resp)]

        # check write
        msg = [0x2E, (id >> 8) & 0xFF, id & 0xFF]
        if data_value != []:
            # write back what we read to minimize potential damage
            msg.extend(data_value)
        else:
            # nothing was read, so write a single 0xFF byte
            msg.append(0xFF)

        resp = send(tp, msg)
        write = proc_did_resp(resp, 0x2E)

        # append DID support information into table
        if write["isSupported"]:
            did_table.append({"id": id, "write": write})


def check_did_control_support(tp, did_table, min_did=0x0000, max_did=0xFFFF):
    # scan through range of dids
    for id in range(min_did, max_did + 1):
        data_value = []
        controls = []
        save_did = False

        # check read
        resp = send(tp, [0x22, (id >> 8) & 0xFF, id & 0xFF])
        if resp == None:
            continue
        read = proc_did_resp(resp, 0x22)
        if read["isSupported"] == True and read["nrc"] == 0:
            # save data for later use
            data_value = resp[3 : len(resp)]

        # check IO control
        # check inputOutputControlParameter 1 and 2
        for state in range(1, 3):
            msg = [0x2F, (id >> 8) & 0xFF, id & 0xFF, state]
            resp = send(tp, msg)
            controls.append(proc_did_resp(resp, 0x2F))

        # Check inputOutputControlParameter 3 using what we read out
        if data_value != []:
            msg = [0x2F, (id >> 8) & 0xFF, id & 0xFF, 0x03]
            msg.extend(data_value)
            resp = send(tp, msg)
            controls.append(proc_did_resp(resp, 0x2F))

        # Return control to ECU if any modification was successful and append DID support information into table
        for control in controls:
            if control["isSupported"] == True:
                save_did = True
                if control["nrc"] == 0:
                    msg = [0x2F, (id >> 8) & 0xFF, id & 0xFF, 0x00]
                    resp = send(tp, msg)
                    break

        # append DID support information into table
        if save_did == True:
            did_table.append({"id": id, "controls": controls})


def Parameter_uds_session(session_param: str):
    sessions_raw = session_param.strip()
    if "," in sessions_raw:
        return [int(s.strip(), 0) for s in sessions_raw.split(",")]
    else:
        return [int(sessions_raw, 0)]