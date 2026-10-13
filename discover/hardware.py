# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os
import socket
from pyroute2 import IPRoute
from utils.netutil import temporary_static_ip
from serial.tools.list_ports import comports

ARPHRD_ETHER = 1
ARPHRD_CAN = 280


class DiscoveryError(Exception):
    """Discovery could not be carried out on an interface.

    Raised instead of exiting so the caller can report the job as failed rather
    than as a successful scan that happened to find nothing.
    """


def bittiming_const(nla):
    """The controller's timing limits, keeping only the fields the driver sets."""
    return {
        field: nla[field]
        for field in (
            "tseg1_min",
            "tseg1_max",
            "tseg2_min",
            "tseg2_max",
            "sjw_max",
            "brp_min",
            "brp_max",
            "brp_inc",
        )
        if field in nla
    }


def get_interfaces():
    interfaces = {"can": [], "eth": [], "wifi": [], "bt": [], "usb": []}

    ip_route = IPRoute()

    for f in os.listdir("/sys/class/net"):
        if os.path.isdir("/sys/class/net/" + f):
            with open("/sys/class/net/" + f + "/type", "r") as typ_f:
                typ = int(typ_f.read().strip())
            if typ == ARPHRD_CAN:
                can_obj = {}
                can_obj["name"] = f
                idx = ip_route.link_lookup(ifname=f)
                if idx == None:
                    continue
                
                assert(len(idx) == 1)
                idx = idx[0]

                link = ip_route.link("get", index=idx)

                # pyroute2 up to 0.8 returns a tuple, 0.9 and later a list
                assert(len(link) == 1)

                with open("/sys/class/net/" + f + "/mtu", "r") as mtu_f:
                    can_obj["mtu"] = int(mtu_f.read().strip())

                for attr in link[0]["attrs"]:
                    if attr[0] == "IFLA_TXQLEN":
                        can_obj["txqueuelen"] = attr[1]
                    elif attr[0] == "IFLA_OPERSTATE":
                        can_obj["state"] = attr[1]
                    elif attr[0] == "IFLA_STATS":
                        can_obj["stats"] = attr[1]
                    elif attr[0] == "IFLA_LINKINFO":
                        for attr2 in attr[1]["attrs"]:
                            if attr2[0] == "IFLA_INFO_DATA":
                                for attr3 in attr2[1]["attrs"]:
                                    if attr3[0] == "IFLA_CAN_BITTIMING":
                                        can_obj["bitrate"] = attr3[1]["bitrate"]
                                        can_obj["sample_point"] = attr3[1][
                                            "sample_point"
                                        ]
                                    # The CAN FD data phase timing, reported
                                    # alongside the nominal bitrate.
                                    elif attr3[0] == "IFLA_CAN_DATA_BITTIMING":
                                        can_obj["fd_bitrate"] = attr3[1]["bitrate"]
                                        can_obj["fd_sample_point"] = attr3[1][
                                            "sample_point"
                                        ]
                                    # The clock and the timing constants decide
                                    # which bitrates and sample points the
                                    # controller can reach.
                                    elif attr3[0] == "IFLA_CAN_CLOCK":
                                        can_obj["clock_freq"] = attr3[1]
                                    elif attr3[0] == "IFLA_CAN_BITTIMING_CONST":
                                        can_obj["bittiming_const"] = bittiming_const(
                                            attr3[1]
                                        )
                                    elif attr3[0] == "IFLA_CAN_DATA_BITTIMING_CONST":
                                        can_obj["fd_bittiming_const"] = bittiming_const(
                                            attr3[1]
                                        )
                                    elif attr3[0] == "IFLA_CAN_CTRLMODE":
                                        can_obj["loopback"] = (
                                            attr3[1]["loopback"] == "on"
                                        )
                                        can_obj["listenonly"] = (
                                            attr3[1]["listenonly"] == "on"
                                        )
                                        can_obj["fd"] = attr3[1]["fd"] == "on"
                                    elif attr3[0] == "IFLA_CAN_CTRLMODE_EXT":
                                        for attr4 in attr3[1]["attrs"]:
                                            if (
                                                attr4[0]
                                                == "IFLA_CAN_CTRLMODE_SUPPORTED"
                                            ):
                                                can_obj["loopback_supported"] = (
                                                    attr4[1]["loopback"] == "yes"
                                                )
                                                can_obj["listenonly_supported"] = (
                                                    attr4[1]["listenonly"] == "yes"
                                                )
                                                can_obj["fd_supported"] = (
                                                    attr4[1]["fd"] == "yes"
                                                )

                interfaces["can"].append(can_obj)
            elif typ == ARPHRD_ETHER:
                if os.path.exists("/sys/class/net/" + f + "/wireless"):
                    wifi_obj = {}
                    wifi_obj["name"] = f
                    with open(f"/sys/class/net/{f}/address", "r") as mac_f:
                        wifi_obj["mac"] = mac_f.read().strip()
                    temp_ip = temporary_static_ip(f)
                    ip = temp_ip.get_ip()
                    if ip:
                        wifi_obj["ip"] = socket.inet_ntoa(ip)
                        mask = temp_ip.get_mask()
                        if mask:
                            wifi_obj["subnetmask"] = socket.inet_ntoa(mask)
                        wifi_obj["gateway"] = temp_ip.get_gateway()
                    idx = ip_route.link_lookup(ifname=f)
                    if idx == None:
                        continue
                    
                    assert(len(idx) == 1)
                    idx = idx[0]

                    link = ip_route.link("get", index=idx)

                    assert(len(link) == 1)
                    for attr in link[0]["attrs"]:
                        if attr[0] == "IFLA_STATS":
                            wifi_obj["stats"] = attr[1]
                        elif attr[0] == "IFLA_OPERSTATE":
                            wifi_obj["state"] = attr[1]
                        elif attr[0] == "IFLA_PROMISCUITY":
                            wifi_obj["promiscuity"] = attr[1]
                    interfaces["wifi"].append(wifi_obj)
                else:
                    eth_obj = {}
                    eth_obj["name"] = f
                    with open(f"/sys/class/net/{f}/address", "r") as mac_f:
                        eth_obj["mac"] = mac_f.read().strip()
                    temp_ip = temporary_static_ip(f)
                    ip = temp_ip.get_ip()
                    if ip:
                        eth_obj["ip"] = socket.inet_ntoa(ip)
                        mask = temp_ip.get_mask()
                        if mask:
                            temp_mask = temp_ip.get_mask()
                            assert(type(temp_mask) == bytes)
                            eth_obj["subnetmask"] = socket.inet_ntoa(temp_mask)
                        eth_obj["gateway"] = temp_ip.get_gateway()
                    idx = ip_route.link_lookup(ifname=f)
                    if idx == None:
                        continue
                    
                    assert(len(idx) == 1)
                    idx = idx[0]

                    link = ip_route.link("get", index=idx)

                    assert(len(link) == 1)
                    for attr in link[0]["attrs"]:
                        if attr[0] == "IFLA_STATS":
                            eth_obj["stats"] = attr[1]
                        elif attr[0] == "IFLA_OPERSTATE":
                            eth_obj["state"] = attr[1]
                        elif attr[0] == "IFLA_PROMISCUITY":
                            eth_obj["promiscuity"] = attr[1]
                    interfaces["eth"].append(eth_obj)

    # Bluetooth and USB devices are not enumerated yet; those lists stay empty.

    ip_route.close()
    return interfaces
