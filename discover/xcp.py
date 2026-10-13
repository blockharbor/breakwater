# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import can
import time
import threading

from utils.xcputil import XCP_SERVICES, XCP_ERROR_CODES, mk_xcp
from discover.hardware import *


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


def discover_xcp(target_iface, logger):
    res = []
    errors = []
    interfaces = get_interfaces()
    for iface in interfaces['can']:
        if target_iface and iface['name'] != target_iface:
            continue
        logger.info(f"Discovering XCP on {iface['name']}")
        source = {
            "interface": {
                "type": "can",
                "name": iface['name'],
                "mtu": iface['mtu'],
            },
            "discovery": "xcp-scan v0.1"
        }
        fd_capable = iface['mtu'] == 72
        if 'bitrate' in iface.keys():
            source['interface']['bitrate'] = iface['bitrate']
        if 'fd_supported' in iface.keys():
            source['interface']['fd_supported'] = iface['fd_supported']
        try:
            targets = discover_xcp_targets(iface['name'], False, logger)
            for t_id in targets:
                target = targets[t_id]
                res.append({
                    "source": source,
                    "discovery": {
                        "protocol": "xcp",
                        "address": target["address"],
                        "connect": target["connect"],
                        "commands": target["commands"],
                    }
                })
            if fd_capable:
                targets = discover_xcp_targets(iface['name'], True, logger)
                for t_id in targets:
                    target = targets[t_id]
                    res.append({
                        "source": source,
                        "discovery": {
                            "protocol": "xcp-fd",
                            "address": target["address"],
                            "connect": target["connect"],
                            "commands": target["commands"],
                        }
                    })
        except Exception as e:
            logger.error(f"Encountered error {e} discovering XCP on {iface['name']}")
            errors.append(f"{iface['name']}: {e}")

    # An empty scan is a valid result; only an error means the scan failed.
    if errors:
        raise DiscoveryError("; ".join(errors))

    return res
