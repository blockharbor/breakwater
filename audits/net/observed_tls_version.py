# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *

@register_audit("observed_tls_version")
class observed_tls_version(AuditRunner):
    parameters = [
        Parameter("iface", "Network Interface", "eth0", "The network interface on which to interact with the DNS Server"),
        Parameter("target_host", "Target Host", "10.1.0.1", "The IP who's packets to inspect"),
    ]
    dependencies = []
    friendly_name = "Observed TLS Version"
    description = "Observes traffic outgoing from a specific IP and checks that its TLS version is at least 1.2."
    fail_condition = "If any TLS traffic is sent by the host that is using a version less than TLS 1.2 this test will be marked as failed"
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["Automotive Ethernet", "WiFi", "Cellular"]
    bw_audit_id = "TS_NET_0006"
    estimated_time_in_minutes = "3"
    test_outcomes = {
        "SUCCESS": {
            "description": "No traffic was observed originating from the specified `target_host` using an insecure TLS version",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "No traffic was observed originating from the specified `target_host`",
            "recommendations": [
                "Check physical connections and device power.",
                "Ensure you are in a network position where target's traffic will be seen by test"
            ]
        },
        "FAILURE": {
            "description": "Communication was observed originating from the `target_host` using an insecure TLS version.",
            "recommendations": [
                "Review the destination of the offending TLS connection and determine if this insecure protocol version can be replaced."
            ]
        }
    }

    # TLS wire version -> name. TLS 1.2 (0x0303) is the minimum acceptable.
    TLS_VERSIONS = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }
    MIN_ACCEPTABLE = 0x0303

    @staticmethod
    def _validate_ipv4(ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return False
        return True

    @staticmethod
    def _validate_ipv6(ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.IPv6Address(ip)
        except ipaddress.AddressValueError:
            return False
        return True

    @staticmethod
    def _parse_ip(frame):
        """Return (src, dst, l4_protocol, l4_payload) or None if not IPv4/IPv6/TCP."""
        import socket as s
        import struct
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        # Step over a VLAN tag if present.
        if ethertype == 0x8100:
            if len(frame) < 18:
                return None
            ethertype = struct.unpack("!H", frame[16:18])[0]
            offset = 18

        if ethertype == 0x0800:
            if len(frame) < offset + 20:
                return None
            ihl = (frame[offset] & 0x0F) * 4
            if ihl < 20 or len(frame) < offset + ihl:
                return None
            proto = frame[offset + 9]
            src = s.inet_ntop(s.AF_INET, frame[offset + 12:offset + 16])
            dst = s.inet_ntop(s.AF_INET, frame[offset + 16:offset + 20])
            return src, dst, proto, frame[offset + ihl:]

        if ethertype == 0x86DD:
            if len(frame) < offset + 40:
                return None
            proto = frame[offset + 6]
            src = s.inet_ntop(s.AF_INET6, frame[offset + 8:offset + 24])
            dst = s.inet_ntop(s.AF_INET6, frame[offset + 24:offset + 40])
            return src, dst, proto, frame[offset + 40:]

        return None

    @staticmethod
    def _tcp_payload(segment):
        if len(segment) < 20:
            return None
        data_offset = (segment[12] >> 4) * 4
        if data_offset < 20 or len(segment) < data_offset:
            return None
        return segment[data_offset:]

    @classmethod
    def _server_hello_version(cls, payload):
        """Return the version a server negotiated, or None if this is not a ServerHello.

        Only the ServerHello is inspected. The record-layer version is not a
        reliable signal: a ClientHello routinely carries 0x0301 for backward
        compatibility even from a modern client, so checking every record
        produces false positives.
        """
        import struct
        # TLS record: type(1) version(2) length(2)
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        record = payload[5:5 + struct.unpack("!H", payload[3:5])[0]]
        # Handshake message: msg_type(1) length(3)
        if len(record) < 4 or record[0] != 0x02:
            return None
        body = record[4:]
        # ServerHello: legacy_version(2) random(32) session_id_len(1) ...
        if len(body) < 35:
            return None
        version = struct.unpack("!H", body[0:2])[0]

        # TLS 1.3 pins legacy_version to 0x0303 and states the real version in
        # the supported_versions extension, so that takes precedence.
        pos = 34 + 1 + body[34]
        if len(body) < pos + 2 + 1 + 2:
            return version
        pos += 2 + 1  # cipher_suite, compression_method
        ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            if ext_type == 0x002B and ext_len == 2 and pos + 2 <= len(body):
                return struct.unpack("!H", body[pos:pos + 2])[0]
            pos += ext_len
        return version

    def run_audit(self):
        import socket
        import time
        iface = self.params["iface"]
        target = self.params["target_host"]

        if not self._validate_ipv4(target) and not self._validate_ipv6(target):
            segments = [
                Report.create_text_segment(
                    f"Invalid IP: {target}, Please make sure the format is correct"
                )
            ]
            return {"title": "Invalid parameters", "segments": segments}

        _tls_seen = dict()

        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            sock.bind((iface, 0))
        except Exception as e:
            segments = [
                Report.create_text_segment(
                    f"Could not capture on {iface}: {e}"
                )
            ]
            return {"title": "Capture failed", "segments": segments}

        try:
            sock.settimeout(1)
            deadline = time.time() + 15
            while time.time() < deadline:
                try:
                    frame = sock.recv(65535)
                except socket.timeout:
                    continue

                parsed = self._parse_ip(frame)
                if parsed is None:
                    continue
                src, dst, proto, segment = parsed
                if src != target or proto != 6:
                    continue

                payload = self._tcp_payload(segment)
                if not payload:
                    continue
                version = self._server_hello_version(payload)
                if version is None or version >= self.MIN_ACCEPTABLE:
                    continue

                name = self.TLS_VERSIONS.get(version, f"unknown (0x{version:04x})")
                _tls_seen.setdefault(dst, set()).add(name)
        finally:
            sock.close()

        title = "TLS Traffic Observation Complete"
        severity = "n/a"
        segments = []

        for k in _tls_seen.keys():
            for v in _tls_seen[k]:
                severity = "medium"
                segments.append(
                    Report.create_text_segment(f"{v} communication seen with {k}")
                )

        output = (
            "Test failed"
            if severity != "n/a"
            else "NO TLS < 1.2 communication seen. Test passed"
        )
        segments.append(Report.create_text_segment(output))

        return {
            "title": title,
            "segments": segments,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

    def format_results(self, results):
        return [{"title": results["title"], "segments": results["segments"]}]
