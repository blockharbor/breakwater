# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import can
import sys
import json
import time
import isotp
import threading

from utils.udsutil import uds_session_enter, mk_isotp, SERVICE_NAMES, DID_META, SESSION_NAMES
from discover.hardware import *

def discover_can_servers(bus, is_fd, min_arb, max_arb, config, ignoring_time=5, arb_step=1):
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


def discover_can_services(bus, is_fd, server, config):
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


def discover_can_dids(tp, config, min_did=0xF180, max_did=0xF1A0):
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


def discover_can_sessions(bus, is_fd, server, config):
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


def discover_can_targets(
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
    servers = discover_can_servers(bus, is_fd, normal_min, normal_max, config)
    logger.info(
        f"discovering between {hex(extended_min)}-{hex(extended_max)} with {hex(extended_step)} step"
    )
    servers += discover_can_servers(
        bus, is_fd, extended_min, extended_max, config, arb_step=extended_step
    )
    logger.info(f"found {len(servers)} servers")
    logger.debug(f"servers: {servers}")
    for server in servers:
        logger.info(f"discovering sessions on {server}")
        sessions = discover_can_sessions(bus, is_fd, server, config)
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
            services = discover_can_services(bus, is_fd, server, config)
            logger.debug(f"found {len(services)} on {services}")

            details = {}

            if detailed:
                if 0x22 in services:
                    logger.info(f"discovering dids on {server} @ session {session}")
                    details[0x22] = discover_can_dids(
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

def discover_can(target_iface, logger, min_did=0xF180, max_did=0xF1A0):
    res = []
    errors = []
    interfaces = get_interfaces()
    for iface in interfaces['can']:
        if target_iface and iface['name'] != target_iface:
            continue
        logger.info(f"Discovering on {iface['name']}")
        source = {
            "interface": {
                "type": "can",
                "name": iface['name'],
                "mtu": iface['mtu'],
            },
            "discovery": "uds-scan v0.1"
        }
        fd_capable = iface['mtu'] == 72
        if 'bitrate' in iface.keys():
            source['interface']['bitrate'] = iface['bitrate']
        if 'fd_supported' in iface.keys():
            source['interface']['fd_supported'] = iface['fd_supported']
        try:
            targets = discover_can_targets(iface['name'], False, logger, min_did=min_did, max_did=max_did)
            for t_id in targets:
                target = targets[t_id]
                res.append({
                    "source": source,
                    "discovery": {
                        "protocol": "uds",
                        "address": target["address"],
                        "sessions": target["sessions"],
                    }
                })
            if fd_capable:
                targets = discover_can_targets(iface['name'], True, logger, min_did=min_did, max_did=max_did)
                for t_id in targets:
                    target = targets[t_id]
                    res.append({
                        "source": source,
                        "discovery": {
                            "protocol": "uds-fd",
                            "address": target["address"],
                            "sessions": target["sessions"],
                        }
                    })
        except Exception as e:
            logger.error(f"Encountered error {e} discovering {iface['name']}")
            errors.append(f"{iface['name']}: {e}")

    # An empty scan is a valid result; only an error means the scan failed.
    if errors:
        raise DiscoveryError("; ".join(errors))

    return res
