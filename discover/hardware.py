# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import os
import sys
import json
import subprocess
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


def ip_addresses(ip_route, idx):
    """The interface's IPv4 and IPv6 addresses in CIDR notation."""
    return [f"{a.get_attr('IFA_ADDRESS')}/{a['prefixlen']}" for a in ip_route.get_addr(index=idx)]


def _attrs(nla):
    """The attributes inside a nested netlink attribute, or [] when pyroute2
    left it undecoded, as a hex string."""
    attrs = nla.get("attrs") if isinstance(nla, dict) else None
    return attrs if isinstance(attrs, list) else []


def _flag(nla, name, on):
    """One mode of a CAN ctrlmode attribute, or None if it is not there"""
    return nla[name] == on if isinstance(nla, dict) and name in nla else None


def can_settings(name, linkinfo):
    """Bitrates, clock, timing limits and modes of a CAN interface from its
    IFLA_LINKINFO. pyroute2 decodes them from 0.7.10 on; an older one, such
    as Debian trixie's 0.7.7, returns them as a hex string, and they are read
    from iproute2 instead."""
    out = {}
    data = [a[1] for a in _attrs(linkinfo) if a[0] == "IFLA_INFO_DATA"]
    if data and not _attrs(data[0]):
        return ip_can_settings(name)
    for key, value in (a for d in data for a in _attrs(d)):
        if key == "IFLA_CAN_BITTIMING" and isinstance(value, dict):
            out["bitrate"] = value.get("bitrate")
            out["sample_point"] = value.get("sample_point")
        # The CAN FD data phase timing, reported alongside the nominal bitrate
        elif key == "IFLA_CAN_DATA_BITTIMING" and isinstance(value, dict):
            out["fd_bitrate"] = value.get("bitrate")
            out["fd_sample_point"] = value.get("sample_point")
        # The clock and the timing constants decide which bitrates and
        # sample points the controller can reach
        elif key == "IFLA_CAN_CLOCK":
            out["clock_freq"] = value
        elif key == "IFLA_CAN_BITTIMING_CONST" and isinstance(value, dict):
            out["bittiming_const"] = bittiming_const(value)
        elif key == "IFLA_CAN_DATA_BITTIMING_CONST" and isinstance(value, dict):
            out["fd_bittiming_const"] = bittiming_const(value)
        elif key == "IFLA_CAN_CTRLMODE":
            for mode in ("loopback", "listenonly", "fd"):
                if (on := _flag(value, mode, "on")) is not None:
                    out[mode] = on
        elif key == "IFLA_CAN_CTRLMODE_EXT":
            for supported in (v for k, v in _attrs(value) if k == "IFLA_CAN_CTRLMODE_SUPPORTED"):
                for mode in ("loopback", "listenonly", "fd"):
                    if (yes := _flag(supported, mode, "yes")) is not None:
                        out[mode + "_supported"] = yes
    return out


def ip_can_settings(name):
    """can_settings() from `ip -details -json link show`, for a pyroute2 that
    cannot decode them. Listed without them if that fails too."""
    try:
        out = subprocess.run(["ip", "-details", "-json", "link", "show", "dev", name],
                             capture_output=True, text=True, timeout=10, check=True).stdout
        info = json.loads(out)[0]["linkinfo"]["info_data"]
    except (OSError, subprocess.SubprocessError, ValueError, LookupError, TypeError) as e:
        print(f"bw_cli: {name}: pyroute2 {_pyroute2_version()} cannot read CAN settings and "
              f"ip failed too ({e}), listing it without bitrate and modes", file=sys.stderr)
        return {}
    return can_settings_from_ip(info)


# iproute2's names for the modes bw_cli reports
IP_CTRLMODES = {"loopback": "LOOPBACK", "listenonly": "LISTEN-ONLY", "fd": "FD"}


def _ip_timing_const(c):
    """iproute2's {"tseg1": {"min": 1, "max": 256}, ...} as bittiming_const() keys"""
    flat = {}
    for field in ("tseg1", "tseg2", "sjw", "brp"):
        for bound in ("min", "max"):
            if isinstance(c.get(field), dict) and bound in c[field]:
                flat[f"{field}_{bound}"] = c[field][bound]
    if "brp_inc" in c:
        flat["brp_inc"] = c["brp_inc"]
    return bittiming_const(flat)


def _ip_sample_point(v):
    """iproute2 prints "0.875"; pyroute2 and the kernel use tenths of a percent"""
    try:
        return round(float(v) * 1000)
    except (TypeError, ValueError):
        return None


def can_settings_from_ip(info):
    """can_settings() keys from the info_data of `ip -details -json link show`"""
    out = {}
    for prefix, key in (("", "bittiming"), ("fd_", "data_bittiming")):
        t = info.get(key)
        if isinstance(t, dict):
            if "bitrate" in t:
                out[prefix + "bitrate"] = t["bitrate"]
            if "sample_point" in t:
                out[prefix + "sample_point"] = _ip_sample_point(t["sample_point"])
    if "clock" in info:
        out["clock_freq"] = info["clock"]
    for prefix, key in (("", "bittiming_const"), ("fd_", "data_bittiming_const")):
        if isinstance(info.get(key), dict):
            out[prefix + "bittiming_const"] = _ip_timing_const(info[key])
    # iproute2 leaves ctrlmode out when no mode is on
    modes = info.get("ctrlmode") or []
    for mode, ip_name in IP_CTRLMODES.items():
        out[mode] = ip_name in modes
    if isinstance(info.get("ctrlmode_supported"), list):
        for mode, ip_name in IP_CTRLMODES.items():
            out[mode + "_supported"] = ip_name in info["ctrlmode_supported"]
    return out


def _pyroute2_version():
    try:
        from pyroute2 import __version__
        return __version__
    except ImportError:
        return "(unknown version)"


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
                        can_obj.update(can_settings(f, attr[1]))

                interfaces["can"].append(can_obj)
            elif typ == ARPHRD_ETHER:
                if os.path.exists("/sys/class/net/" + f + "/wireless"):
                    wifi_obj = {}
                    wifi_obj["name"] = f
                    with open(f"/sys/class/net/{f}/address", "r") as mac_f:
                        wifi_obj["mac"] = mac_f.read().strip()
                    idx = ip_route.link_lookup(ifname=f)
                    if idx == None:
                        continue
                    
                    assert(len(idx) == 1)
                    idx = idx[0]

                    wifi_obj["addresses"] = ip_addresses(ip_route, idx)
                    gateway = temporary_static_ip(f).get_gateway()
                    if gateway:
                        wifi_obj["gateway"] = gateway

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
                    idx = ip_route.link_lookup(ifname=f)
                    if idx == None:
                        continue
                    
                    assert(len(idx) == 1)
                    idx = idx[0]

                    eth_obj["addresses"] = ip_addresses(ip_route, idx)
                    gateway = temporary_static_ip(f).get_gateway()
                    if gateway:
                        eth_obj["gateway"] = gateway

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
