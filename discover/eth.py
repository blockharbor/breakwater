# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

# Ethernet discovery without crafting packets: the kernel does the ARP and
# neighbour discovery, pyroute2 reads the results back from the neighbour
# table, and the port scan is a plain TCP connect scan. None of it needs root
# on a current kernel, unlike the old scapy version.

import time
import select
import socket
import asyncio
import ipaddress
from pyroute2 import IPRoute
from pyroute2.netlink.rtnl import RTMGRP_NEIGH

from discover.hardware import *

DISCOVER_PORTS = [21, 22, 23, 80, 102, 135, 443, 445, 502, 1883, 2222, 2022, 3000, 3306, 3389, 4840, 5000,
                  5060, 5683, 5684, 5900, 8000, 8080, 8443, 8883, 9000, 9001, 13100, 13400, 30490]

# Larger subnets would overflow the neighbour table (gc_thresh3 defaults to
# 1024 entries) and take long to sweep, so they are not swept.
MAX_SWEEP_HOSTS = 1024

# Neighbour states (see NUD_* in linux/neighbour.h). CONFIRMED means the host
# answered recently, VALID only that the kernel holds a MAC for it.
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
NUD_FAILED = 0x20
NUD_PERMANENT = 0x80
NUD_CONFIRMED = NUD_REACHABLE | NUD_PERMANENT
NUD_VALID = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT

ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129

# How long to collect echo replies to the IPv6 ping, and how many to send.
PING6_WAIT = 3.5
PING6_COUNT = 3

# Upper bound for the kernel to settle the poked neighbours. With the default
# timers an unknown address fails after three probes a second apart, and a
# stale entry is first probed after 5s (delay_first_probe_time), then answers
# or fails within 3s more.
RESOLVE_TIMEOUT = 10


def _neighbours(ipr, ifindex, family, states):
    """Neighbours on the interface in one of the states, as {address: mac}."""
    found = {}
    for n in ipr.get_neighbours(ifindex=ifindex, family=family):
        addr = n.get_attr('NDA_DST')
        mac = n.get_attr('NDA_LLADDR')
        if addr and mac and n['state'] & states:
            found[addr] = mac
    return found


def _addresses(ipr, ifindex, family):
    return [(a.get_attr('IFA_ADDRESS'), a['prefixlen']) for a in ipr.get_addr(index=ifindex, family=family)]


def _poke(name, family, addresses):
    """Send one UDP datagram to each address so the kernel resolves its MAC.

    Each datagram gets its own socket: a datagram waiting for resolution counts
    against its socket's send buffer, so a single socket blocks after a few
    hundred addresses until the kernel gives up on the first ones.
    """
    ifindex = socket.if_nametoindex(name)
    for addr in addresses:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, name.encode())
            except OSError:
                pass  # older kernels need CAP_NET_RAW; the subnet route picks the interface anyway
            try:
                # Port 9 is discard; the payload never matters, only the resolution.
                s.sendto(b'\x00', (addr, 9, 0, ifindex) if family == socket.AF_INET6 else (addr, 9))
            except OSError:
                pass


def _settle(ev, ifindex, family, pending, states):
    """Read neighbour events until every pending address is in one of the states."""
    deadline = time.monotonic() + RESOLVE_TIMEOUT
    while pending and select.select([ev], [], [], max(0, deadline - time.monotonic()))[0]:
        for m in ev.get():
            if (m.get('event') == 'RTM_NEWNEIGH' and m['ifindex'] == ifindex and m['family'] == family
                    and m['state'] & states):
                pending.discard(m.get_attr('NDA_DST'))


def _resolve(ipr, name, ifindex, family, addresses, wanted, logger):
    """Have the kernel resolve the addresses and return those that end up in
    one of the wanted states, as {address: mac}.

    Neighbour events only tell when every address has settled (reached a
    wanted state or failed); the table read afterwards gives the result, so
    a lost event costs time, not a target.
    """
    ev = IPRoute()
    ev.bind(groups=RTMGRP_NEIGH)  # before poking, so no event is missed
    try:
        pending = set(addresses) - set(_neighbours(ipr, ifindex, family, wanted))
        if pending:
            _poke(name, family, pending)
            _settle(ev, ifindex, family, pending, wanted | NUD_FAILED)
            if pending:
                logger.debug(f'{name}: {len(pending)} addresses still unsettled after {RESOLVE_TIMEOUT}s')
    finally:
        ev.close()
    found = _neighbours(ipr, ifindex, family, wanted)
    return {a: found[a] for a in addresses if a in found}


def discover_ip_targets_arp(ipr, iface, ifindex, logger):
    addresses = _addresses(ipr, ifindex, socket.AF_INET)
    if not addresses:
        logger.warning(f'{iface["name"]} has no IPv4 address, skipping the ARP sweep')
        return []
    candidates = set()
    for addr, prefixlen in addresses:
        net = ipaddress.ip_network(f'{addr}/{prefixlen}', strict=False)
        if net.num_addresses > MAX_SWEEP_HOSTS:
            logger.warning(f'{iface["name"]}: {net} is too large to sweep, checking only already known neighbours')
            known = _neighbours(ipr, ifindex, socket.AF_INET, NUD_VALID)
            candidates |= {a for a in known if ipaddress.ip_address(a) in net}
        else:
            logger.info(f'{iface["name"]}: sweeping {net}')
            candidates |= {str(h) for h in net.hosts()}
    candidates -= {addr for addr, _ in addresses}
    # Only hosts that answer now count: an entry left over from earlier is
    # probed again and reported only if the host confirms it.
    found = _resolve(ipr, iface['name'], ifindex, socket.AF_INET, candidates, NUD_CONFIRMED, logger)
    return [{"address": a, "mac": found[a]} for a in sorted(found, key=ipaddress.ip_address)]


def _icmpv6_socket():
    # An unprivileged ping socket works when net.ipv4.ping_group_range covers
    # our group (systemd sets it to everyone); otherwise fall back to raw.
    try:
        return socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
    except OSError:
        return socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)


def _ping6_all_nodes(s, ifindex, own):
    """Ping ff02::1 and collect the replies as they arrive.

    Replies come within a fraction of a second, but some hosts skip the odd
    multicast echo, so the pings go out a second apart within the window.
    """
    responders = set()
    start = time.monotonic()
    end = start + PING6_WAIT
    pings = [start + i for i in range(PING6_COUNT)]
    seq = 0
    while (now := time.monotonic()) < end:
        if pings and now >= pings[0]:
            pings.pop(0)
            seq += 1
            s.sendto(bytes([ICMPV6_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, seq]), ('ff02::1', 0, 0, ifindex))
        # Wake on the next reply, or when the next ping or the end is due.
        wake = pings[0] if pings else end
        if select.select([s], [], [], max(0, wake - time.monotonic()))[0]:
            data, src = s.recvfrom(1500)
            addr = src[0].split('%')[0]
            if data and data[0] == ICMPV6_ECHO_REPLY and addr not in own:
                responders.add(addr)
    return responders


def discover_ip_targets_ping6(ipr, iface, ifindex, logger):
    try:
        s = _icmpv6_socket()
    except OSError as e:
        logger.warning(f'{iface["name"]}: cannot open an ICMPv6 socket ({e}), skipping the IPv6 ping')
        return []
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    # Every interface of this host, not only the scanned one: another of our
    # interfaces on the same link answers the ping too.
    own = {a.get_attr('IFA_ADDRESS') for a in ipr.get_addr(family=socket.AF_INET6)}
    responders = set()
    try:
        responders = _ping6_all_nodes(s, ifindex, own)
    except OSError as e:
        logger.warning(f'{iface["name"]}: IPv6 ping failed ({e})')
    finally:
        s.close()

    # The echo reply already shows the host is there; only its MAC is missing
    # when the reply left no entry in our neighbour table.
    found = _resolve(ipr, iface['name'], ifindex, socket.AF_INET6, responders, NUD_VALID, logger)
    return [{"address": a, "mac": found.get(a)} for a in sorted(responders, key=ipaddress.ip_address)]


async def _open_ports(host, ports, timeout, limit):
    async def probe(port):
        async with limit:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            except (OSError, asyncio.TimeoutError):
                return None
            writer.close()
            return port

    return [p for p in await asyncio.gather(*(probe(p) for p in ports)) if p is not None]


def _scoped(addr, name):
    """Link-local addresses only mean something together with the interface."""
    ip = ipaddress.ip_address(addr)
    return f'{addr}%{name}' if ip.version == 6 and ip.is_link_local else addr


def scan_ports(targets, name, ports=DISCOVER_PORTS, timeout=1.5, concurrency=256):
    """TCP connect scan of every target, returning the open ports per target."""
    async def scan():
        limit = asyncio.Semaphore(concurrency)
        hosts = [_scoped(t['address'], name) for t in targets]
        return await asyncio.gather(*(_open_ports(h, ports, timeout, limit) for h in hosts))

    return asyncio.run(scan())


def discover_ip(iface, logger, ports=DISCOVER_PORTS):
    """IP hosts on one Ethernet or Wi-Fi interface and their open TCP ports."""
    name = iface['name']
    if iface.get('state') != 'UP':
        raise DiscoveryError(f'{name} is {iface.get("state", "down")}')
    ifindex = socket.if_nametoindex(name)
    with IPRoute() as ipr:
        targets = (discover_ip_targets_arp(ipr, iface, ifindex, logger)
                   + discover_ip_targets_ping6(ipr, iface, ifindex, logger))
    logger.info(f'found {len(targets)} hosts on {name}, scanning {len(ports)} ports each')
    for target, open_ports in zip(targets, scan_ports(targets, name, ports)):
        logger.debug(f'{target["address"]}: open ports {open_ports}')
        target["ports"] = open_ports
    return targets
