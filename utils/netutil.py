# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

import socket
import fcntl
import struct
import traceback

class temporary_static_ip:
    original_ip = None
    desired_ip = None

    original_mask = None
    desired_mask = None

    def __init__(self, iface, ip_str="", mask_str="", logger=None):
        self.log = logger
        self.iface = iface

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if len(ip_str) == 0 or len(mask_str) == 0:
            return

        try:
            self.desired_ip = socket.inet_aton(ip_str)
        except:
            pass

        try:
            self.desired_mask = socket.inet_aton(mask_str)
        except:
            pass

        self.original_mask = self.get_mask()
        if self.desired_ip:
            self.original_ip = self.get_ip()
            self.change_ip(self.desired_ip)

        if self.desired_mask:
            self.change_mask(self.desired_mask)
        elif self.desired_ip and self.original_mask:
            self.change_mask(self.original_mask)

    def __del__(self):
        if self.original_ip:
            self.change_ip(self.original_ip)

        if self.original_mask:
            self.change_mask(self.original_mask)

        self.s.close()

    def get_ip(self):
        try:
            return fcntl.ioctl(
                self.s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", bytes(self.iface, "utf-8")),
            )[20:24]
        except Exception as e:
            return None

    def change_ip(self, ip):
        # self.log.debug('STATICIP SIOCSIFADDR ' + ' '.join([ hex(a) for a in ip ]))
        fcntl.ioctl(
            self.s,
            0x8916,  # SIOCSIFADDR
            struct.pack(
                "16sH2s4s8s",
                bytes(self.iface, "utf-8"),
                socket.AF_INET,
                b"\x00\x00",
                ip,
                b"\x00" * 8,
            ),
        )

    def get_mask(self):
        try:
            return fcntl.ioctl(
                self.s.fileno(),
                0x891B,  # SIOCGIFNETMASK
                struct.pack("256s", bytes(self.iface, "utf-8")),
            )[20:24]
        except:
            return None

    def change_mask(self, mask):
        # self.log.debug('STATICIP SIOCSIFNETMASK ' + ' '.join([ hex(a) for a in mask ]))
        fcntl.ioctl(
            self.s,
            0x891C,  # SIOCSIFNETMASK
            struct.pack(
                "16sH2s4s8s",
                bytes(self.iface, "utf-8"),
                socket.AF_INET,
                b"\x00\x00",
                mask,
                b"\x00" * 8,
            ),
        )

    def get_gateway(self):
        with open("/proc/net/route", "r") as route_f:
            for line in route_f:
                if line.startswith(self.iface):
                    fields = line.strip().split()
                    if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                        # If not default route or not RTF_GATEWAY, skip it
                        continue

                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        return None


def tcp_reachable(address: str, port: int, timeout: int = 5) -> bool:
    s = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((address, port))
        return True
    except socket.error as error:
        return False
    finally:
        s.close()

