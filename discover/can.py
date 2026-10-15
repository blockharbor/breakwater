# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# Discovery on CAN buses: UDS servers and XCP slaves.

import can
import sys
import json
import time
import isotp
import threading

from utils.udsutil import uds_session_enter, mk_isotp, SERVICE_NAMES, DID_META, SESSION_NAMES
from utils.xcputil import XCP_SERVICES, XCP_ERROR_CODES, mk_xcp
from discover.hardware import *


# --- UDS ---------------------------------------------------------------------

def discover_uds_servers(bus, is_fd, min_arb, max_arb, config, ignoring_time=5, arb_step=1):
    def is_valid_uds(msg):
        return (
            len(msg.data) > 2
            and msg.data[0] >> 4 == 0
            and (msg.data[1] == 0x50 or (msg.data[1] == 0x7F and msg.data[2] == 0x10))
        )

    tester_present = can.Message(
        arbitration_id=0x7DF, data=[2, 0x3E, 0, 0, 0, 0, 0, 0], is_extended_id=False, is_fd=is_fd
    )

    ignored = []
    ignoring_end = time.time() + ignoring_time
    while time.time() < ignoring_end:
        msg = bus.recv(0.1)
        if msg and is_valid_uds(msg) and msg.arbitration_id not in ignored:
            ignored.append(msg.arbitration_id)

    arb_id = min_arb
    servers = []
    listening = True
    found_prompt = "?"

    def listen_for_servers():
        while listening:
            msg = bus.recv(0.1)
            if msg and msg.arbitration_id not in ignored and is_valid_uds(msg):
                srvr = [arb_id, msg.arbitration_id]
                if srvr not in servers:
                    servers.append(srvr)

    listener = threading.Thread(target=listen_for_servers)
    listener.start()

    bus.send(tester_present)
    send_errors = 0
    msg = can.Message(data=[2, 0x10, 1, 0, 0, 0, 0, 0], is_extended_id=arb_id > 0x7FF, is_fd=is_fd)
    while arb_id < max_arb:
        if arb_id == 0x800:
            msg.is_extended_id = True
        msg.arbitration_id = arb_id
        try:
            if arb_id != 0x7DF and arb_id != 0x18DB33F1:
                bus.send(msg, timeout=0.1)
            arb_id = arb_id + arb_step
            time.sleep(config["discover_speed"])
        except:
            send_errors = send_errors + 1
            if send_errors > (max_arb - min_arb):
                listening = False
                listener.join()
                raise DiscoveryError(
                    "failed sending on this network: no node acknowledged the frames (check the bitrate, wiring and termination)"
                )
        if arb_id & 0x3F == 0:
            time.sleep(config["discover_speed"])

    time.sleep(2)
    potential_servers = servers
    servers = []
    found_prompt = "!"
    bus.send(tester_present)

    for server in potential_servers:
        found_len = len(servers)
        for arb_id in range(server[0], server[0] - (16 * arb_step), -arb_step):
            msg.arbitration_id = arb_id
            bus.send(msg)
            time.sleep(0.1)
            if len(servers) > found_len:
                break

    listening = False
    listener.join()

    return servers


def discover_uds_services(bus, is_fd, server, config):
    supported = []
    unsupported = []
    listening = True

    def listen_for_services():
        while listening:
            msg = bus.recv(0.1)
            if msg and msg.arbitration_id == server[1]:
                if msg.data[0] == 0x03 and msg.data[1] == 0x7F:
                    if msg.data[3] == 0x11:
                        unsupported.append(msg.data[2])
                    else:
                        supported.append(msg.data[2])
                else:
                    msg_type = (msg.data[0] & 0xF0) >> 4
                    if msg_type == 0:
                        supported.append(msg.data[1] ^ 0x40)
                    elif msg_type == 1:
                        supported.append(msg.data[2] ^ 0x40)

    listener = threading.Thread(target=listen_for_services)
    listener.start()

    service_id = 0
    msg = can.Message(
        arbitration_id=server[0],
        data=[1, 0, 0, 0, 0, 0, 0, 0],
        is_extended_id=server[0] > 0x7FF,
        is_fd=is_fd
    )
    while service_id < 0x100:
        msg.data[1] = service_id
        bus.send(msg)
        service_id = service_id + 1
        time.sleep(config["discover_speed"])

    time.sleep(1)
    listening = False
    listener.join()

    return sorted(list(set(supported)))


def discover_uds_dids(tp, config, min_did=0xF180, max_did=0xF1A0):
    dids = []
    listening = True

    def listen_for_dids():
        while listening:
            try:
                msg = tp.recv()
                if not msg or msg[0] != 0x62:
                    continue
                did = int.from_bytes(msg[1:3], "big")
                decoded = []
                for chunk in msg[3:].strip(b'\x00').split(b'\x00'):
                    try:
                        dchunk = chunk.decode("utf-8", errors="strict")
                        decoded.append(dchunk)
                    except UnicodeDecodeError:
                        pass
                dido = {
                    "id": did,
                    "raw": msg[3:].hex(),
                    "decodedValues": decoded
                }
                if did in DID_META.keys():
                    dido["name"] = DID_META[did]["name"]
                    dido["description"] = DID_META[did]["description"]
                dids.append(dido)
            except TimeoutError:
                continue

    listener = threading.Thread(target=listen_for_dids)
    listener.start()

    did_id = min_did
    while did_id <= max_did:
        tp.send(bytearray([0x22, (did_id >> 8) & 0xFF, did_id & 0xFF]))
        did_id = did_id + 1
        time.sleep(config["discover_speed"])

    time.sleep(3)
    listening = False
    listener.join()

    return dids


def discover_uds_sessions(bus, is_fd, server, config):
    sessions = []
    listening = True

    def listen_for_sessions():
        while listening:
            msg = bus.recv(0.1)
            if msg and msg.arbitration_id == server[1]:
                if msg.data[0] == 0x03:
                    if msg.data[1] == 0x50:
                        sessions.append(msg.data[2])
                else:
                    msg_type = (msg.data[0] & 0xF0) >> 4
                    if msg_type == 0:
                        if msg.data[1] == 0x50:
                            sessions.append(msg.data[2])
                    elif msg_type == 1:
                        if msg.data[2] == 0x50:
                            sessions.append(msg.data[3])

    listener = threading.Thread(target=listen_for_sessions)
    listener.start()

    for session in range(2, 0x7F):
        msg = can.Message(
            arbitration_id=server[0],
            data=[0x02, 0x10, session, 0, 0, 0, 0, 0],
            is_extended_id=server[0] > 0x7FF,
            is_fd=is_fd
        )
        bus.send(msg)
        time.sleep(config["discover_speed"])

    time.sleep(1)
    listening = False
    listener.join()

    # Dedupe
    return list(set(sessions))


def discover_uds_targets(
    can_interface, is_fd, logger, detailed=True, config={"discover_speed": 0.05},
    min_did=0xF180, max_did=0xF1A0
):

    rcon = dict()
    bus = can.Bus(interface="socketcan", channel=can_interface, fd=is_fd)

    normal_min = 0x400
    normal_max = 0x800
    extended_min = 0x18DA00F1
    extended_max = 0x18DA0100
    extended_step = 0x1

    # TODO add option to do intensive scan / control the arbitration ID range

    logger.info(f"discovering between {hex(normal_min)}-{hex(normal_max)}")
    servers = discover_uds_servers(bus, is_fd, normal_min, normal_max, config)
    logger.info(
        f"discovering between {hex(extended_min)}-{hex(extended_max)} with {hex(extended_step)} step"
    )
    servers += discover_uds_servers(
        bus, is_fd, extended_min, extended_max, config, arb_step=extended_step
    )
    logger.info(f"found {len(servers)} servers")
    logger.debug(f"servers: {servers}")
    for server in servers:
        logger.info(f"discovering sessions on {server}")
        sessions = discover_uds_sessions(bus, is_fd, server, config)
        logger.info(f"found {len(sessions)} sessions on {server}")
        logger.debug(f"sessions: {sessions}")

        if len(sessions) == 0:
            sessions.append(1)

        if 1 not in sessions:
            sessions = [1] + sessions

        rcon[hex(server[1])] = {}
        rcon[hex(server[1])]["sessions"] = []
        rcon[hex(server[1])]["address"] = {
            "server_id": server[0],
            "client_id": server[1]
        }
        rcon[hex(server[1])]["arb_target"] = server[0]
        rcon[hex(server[1])]["arb_listen"] = server[1]

        for session in sessions:
            logger.debug(f"entering {session}")
            tp = mk_isotp(bus, [server[0], server[1]], server[1] > 0x800, is_fd=is_fd, log=logger.info)
            uds_session_enter(tp, [session])

            logger.info(f"discovering services on {server} @ session {session}")
            services = discover_uds_services(bus, is_fd, server, config)
            logger.debug(f"found {len(services)} on {services}")

            details = {}

            if detailed:
                if 0x22 in services:
                    logger.info(f"discovering DIDs on {server} @ session {session}")
                    details[0x22] = discover_uds_dids(
                        tp, config, min_did=min_did, max_did=max_did
                    )

            services_full = [{ "sid": s, "name": SERVICE_NAMES[s] if s in SERVICE_NAMES.keys() else '' } for s in services ]
            session_obj = {"id": session, "services": services_full, "dids": details[0x22] if 0x22 in details.keys() else None }
            if session in SESSION_NAMES.keys():
                session_obj["name"] = SESSION_NAMES[session]
            else:
                session_obj["name"] = "UNKNOWN"
            rcon[hex(server[1])]["sessions"].append(session_obj)

    bus.shutdown()

    return rcon

def discover_uds(iface, logger, min_did=0xF180, max_did=0xF1A0):
    """UDS servers on one CAN interface, over CAN FD as well when it supports it."""
    targets = []
    for fd in (False, True) if iface['mtu'] == 72 else (False,):
        found = discover_uds_targets(iface['name'], fd, logger, min_did=min_did, max_did=max_did)
        targets += [{"address": t["address"], "fd": fd, "sessions": t["sessions"]} for t in found.values()]
    return targets


# --- XCP ---------------------------------------------------------------------

def _is_valid_xcp(msg):
    # A positive response is PID 0xFF followed by at least one non-zero byte
    # (this filters out CCP frames and empty padding); an error response is
    # PID 0xFE.
    data = msg.data
    return (len(data) > 1 and data[0] == 0xFF and any(data[1:])) or \
           (len(data) > 0 and data[0] == 0xFE)


def _decode_connect_response(data):
    # Decode an XCP CONNECT positive response (8 bytes) into a dict of the
    # slave's advertised capabilities.
    if data is None or len(data) < 8 or data[0] != 0xFF:
        return None
    resource = data[1]
    comm_mode_basic = data[2]
    return {
        "resource": {
            "cal_pag": bool(resource & 0x01),
            "daq": bool(resource & 0x04),
            "stim": bool(resource & 0x08),
            "pgm": bool(resource & 0x10),
        },
        "comm_mode_basic": {
            "byte_order": "motorola" if comm_mode_basic & 0x01 else "intel",
            "address_granularity": 1 << ((comm_mode_basic >> 1) & 0x03),
            "slave_block_mode": bool(comm_mode_basic & 0x40),
            "optional": bool(comm_mode_basic & 0x80),
        },
        "max_cto": data[3],
        "max_dto": (data[5] << 8) | data[4],
        "protocol_layer_version": data[6],
        "transport_layer_version": data[7],
    }


def discover_xcp_servers(bus, is_fd, min_arb, max_arb, config, ignoring_time=5, arb_step=1):
    # Learn the arbitration IDs that already emit XCP-looking frames before we
    # send anything, so periodic slave traffic (e.g. a running DAQ) does not
    # register as a discovery hit.
    ignored = []
    ignoring_end = time.time() + ignoring_time
    while time.time() < ignoring_end:
        msg = bus.recv(0.1)
        if msg and _is_valid_xcp(msg) and msg.arbitration_id not in ignored:
            ignored.append(msg.arbitration_id)

    arb_id = min_arb
    servers = []
    listening = True

    def listen_for_servers():
        while listening:
            msg = bus.recv(0.1)
            if msg and msg.arbitration_id not in ignored and _is_valid_xcp(msg):
                srvr = [arb_id, msg.arbitration_id]
                if srvr not in servers:
                    servers.append(srvr)

    listener = threading.Thread(target=listen_for_servers)
    listener.start()

    connect = can.Message(
        data=[0xFF, 0, 0, 0, 0, 0, 0, 0], is_extended_id=arb_id > 0x7FF, is_fd=is_fd
    )
    send_errors = 0
    while arb_id < max_arb:
        if arb_id == 0x800:
            connect.is_extended_id = True
        connect.arbitration_id = arb_id
        try:
            bus.send(connect, timeout=0.1)
            arb_id = arb_id + arb_step
            time.sleep(config["discover_speed"])
        except:
            send_errors = send_errors + 1
            if send_errors > (max_arb - min_arb):
                listening = False
                listener.join()
                raise DiscoveryError(
                    "failed sending on this network: no node acknowledged the frames (check the bitrate, wiring and termination)"
                )

    time.sleep(2)
    # Narrow down the exact request id for each candidate. The threaded sweep
    # only records the id that happened to be in flight when the reply arrived,
    # which can be slightly off, so re-probe the neighbourhood one id at a time.
    potential_servers = servers
    servers = []
    for server in potential_servers:
        found_len = len(servers)
        for arb_id in range(server[0], server[0] - (16 * arb_step), -arb_step):
            connect.arbitration_id = arb_id
            connect.is_extended_id = arb_id > 0x7FF
            bus.send(connect)
            time.sleep(0.1)
            if len(servers) > found_len:
                break

    listening = False
    listener.join()

    return servers


def discover_xcp_commands(bus, is_fd, server, config):
    # Probe every XCP command with an empty (no-parameter) request. A slave
    # that implements a command answers with a positive response (PID 0xFF) or
    # a parameter error (PID 0xFE, e.g. OUT_OF_RANGE); one that does not answers
    # with ERR_CMD_UNKNOWN. "Supported" means any reply other than
    # ERR_CMD_UNKNOWN, since a rejected empty request still shows the command
    # exists. Error codes are recorded so the report can tell "recognised but
    # rejected" from "accepted".
    supported = []
    errors = {}
    xc = mk_xcp(bus, server, is_fd=is_fd)

    for cmd in XCP_SERVICES:
        if cmd == 0xFF:  # CONNECT is used below to (re)establish the session
            continue
        # Re-connect before every probe: some commands change or drop the
        # session state, so a fresh CONNECT keeps the slave responsive.
        xc.send([0xFF, 0, 0, 0, 0, 0, 0, 0])
        if xc.recv(timeout=0.5) is None:
            continue
        xc.send([cmd, 0, 0, 0, 0, 0, 0, 0])
        reply = xc.recv(timeout=0.5)
        if reply is None:
            continue
        if reply[0] != 0xFE:
            supported.append(cmd)
        elif len(reply) > 1:
            errors[cmd] = reply[1]
            if reply[1] != 0x20:  # ERR_CMD_UNKNOWN
                supported.append(cmd)

    # Leave the slave in a clean state.
    xc.send([0xFE, 0, 0, 0, 0, 0, 0, 0])

    return supported, errors


def discover_xcp_targets(
    can_interface, is_fd, logger, detailed=True, config={"discover_speed": 0.05}
):

    rcon = dict()
    bus = can.Bus(interface="socketcan", channel=can_interface, fd=is_fd)

    normal_min = 0x000
    normal_max = 0x800

    logger.info(f"discovering XCP between {hex(normal_min)}-{hex(normal_max)}")
    servers = discover_xcp_servers(bus, is_fd, normal_min, normal_max, config)
    logger.info(f"found {len(servers)} XCP servers")
    logger.debug(f"servers: {servers}")

    for server in servers:
        logger.info(f"connecting to {server}")
        xc = mk_xcp(bus, server, is_fd=is_fd)
        xc.send([0xFF, 0, 0, 0, 0, 0, 0, 0])
        connect_info = _decode_connect_response(xc.recv(timeout=0.5))

        entry = {
            "address": {"request_id": server[0], "response_id": server[1]},
            "connect": connect_info,
            "commands": None,
        }

        if detailed:
            logger.info(f"discovering XCP commands on {server}")
            supported, errors = discover_xcp_commands(bus, is_fd, server, config)
            logger.debug(f"found {len(supported)} supported commands: {supported}")
            entry["commands"] = [
                {
                    "code": cmd,
                    "name": XCP_SERVICES[cmd],
                    "supported": cmd in supported,
                    "error": XCP_ERROR_CODES.get(errors[cmd]) if cmd in errors else None,
                }
                for cmd in XCP_SERVICES if cmd != 0xFF
            ]

        rcon[hex(server[1])] = entry

    bus.shutdown()

    return rcon


def discover_xcp(iface, logger):
    """XCP slaves on one CAN interface, over CAN FD as well when it supports it."""
    targets = []
    for fd in (False, True) if iface['mtu'] == 72 else (False,):
        found = discover_xcp_targets(iface['name'], fd, logger)
        targets += [{"address": t["address"], "fd": fd, "connect": t["connect"], "commands": t["commands"]}
                    for t in found.values()]
    return targets
