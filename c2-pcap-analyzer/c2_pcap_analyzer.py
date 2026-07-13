#!/usr/bin/env python3
"""
C2/PCAP Analysis Helper
=======================

Purpose
-------
Perform read-only, defensive triage of PCAP and common PCAPNG captures for SOC
analysis. The tool summarizes hosts, protocols, ports, DNS, and clear-text HTTP
metadata, then identifies candidates for scanning, beaconing, and large flows.

Safety guarantees
-----------------
* Never executes, imports, opens, or launches captured payloads.
* Never connects to observed IP addresses, domains, or URLs.
* Never extracts files or writes packet payloads to disk.
* Uses only Python's standard library at runtime.
* Writes only an optional JSON report chosen by the analyst.
* Treats detections as investigation leads, not final verdicts.

Examples
--------
    python c2_pcap_analyzer.py analyze suspicious.pcap
    python c2_pcap_analyzer.py analyze suspicious.pcap --json-out report.json
    python c2_pcap_analyzer.py decode --encoding base64 --value SGVsbG8=

Handle malicious captures in an isolated analysis environment and follow your
organization's evidence-handling rules.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import socket
import statistics
import struct
import sys
import urllib.parse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator


TOOL_NAME = "c2-pcap-analyzer"
TOOL_VERSION = "1.0.0"
MAX_PACKET_BYTES = 16 * 1024 * 1024
MAX_DECODE_INPUT = 1_048_576
HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
)


class CaptureFormatError(ValueError):
    """Raised when a capture is unsupported, malformed, or truncated."""


@dataclass(frozen=True)
class AnalysisConfig:
    max_packets: int = 250_000
    max_file_mb: int = 2_048
    scan_window_seconds: float = 60.0
    scan_port_threshold: int = 20
    scan_host_threshold: int = 20
    beacon_min_events: int = 6
    beacon_min_interval: float = 2.0
    beacon_max_interval: float = 3_600.0
    beacon_max_cv: float = 0.20
    large_transfer_mb: float = 5.0
    http_record_limit: int = 200

    def validate(self) -> None:
        values = {
            "max_packets": self.max_packets,
            "max_file_mb": self.max_file_mb,
            "scan_window_seconds": self.scan_window_seconds,
            "scan_port_threshold": self.scan_port_threshold,
            "scan_host_threshold": self.scan_host_threshold,
            "beacon_min_events": self.beacon_min_events,
            "beacon_min_interval": self.beacon_min_interval,
            "beacon_max_interval": self.beacon_max_interval,
            "large_transfer_mb": self.large_transfer_mb,
            "http_record_limit": self.http_record_limit,
        }
        for name, value in values.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if not 0 <= self.beacon_max_cv <= 1:
            raise ValueError("beacon_max_cv must be between 0 and 1")
        if self.beacon_max_interval < self.beacon_min_interval:
            raise ValueError("beacon_max_interval must be >= beacon_min_interval")


@dataclass(frozen=True)
class CapturedPacket:
    timestamp: float
    data: bytes
    linktype: int


@dataclass(frozen=True)
class ParsedPacket:
    source: str
    destination: str
    protocol: str
    source_port: int
    destination_port: int
    tcp_flags: int
    payload: bytes
    captured_length: int
    fragmented: bool = False


def read_exact(handle: BinaryIO, size: int, context: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise CaptureFormatError(f"Truncated {context}")
    return data


def sha256_file(path: Path, chunk_size: int = 1_048_576) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def ip_scope(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    if address.is_global:
        return "global"
    return "special"


def counter_rows(counter: Counter[Any], limit: int = 20, key_name: str = "value") -> list[dict[str, Any]]:
    return [{key_name: str(key), "count": count} for key, count in counter.most_common(limit)]


def iter_classic_pcap(handle: BinaryIO, magic: bytes) -> Iterator[CapturedPacket]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    endian, resolution = formats[magic]
    remainder = read_exact(handle, 20, "PCAP global header")
    _, _, _, _, _, linktype = struct.unpack(endian + "HHIIII", remainder)

    while True:
        header = handle.read(16)
        if not header:
            return
        if len(header) != 16:
            raise CaptureFormatError("Truncated PCAP packet header")
        seconds, fraction, captured_length, _ = struct.unpack(endian + "IIII", header)
        if captured_length > MAX_PACKET_BYTES:
            raise CaptureFormatError(
                f"Packet length {captured_length} exceeds safety limit {MAX_PACKET_BYTES}"
            )
        data = read_exact(handle, captured_length, "PCAP packet data")
        yield CapturedPacket(seconds + (fraction / resolution), data, linktype)


def parse_pcapng_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = defaultdict(list)
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        if offset + length > len(data):
            break
        options[code].append(data[offset : offset + length])
        offset += (length + 3) & ~3
    return options


def iter_pcapng(handle: BinaryIO, first_magic: bytes) -> Iterator[CapturedPacket]:
    interfaces: list[tuple[int, float]] = []
    pending_type = first_magic
    endian: str | None = None

    while pending_type:
        raw_length = read_exact(handle, 4, "PCAPNG block length")
        if pending_type == b"\x0a\x0d\x0d\x0a":
            byte_order = read_exact(handle, 4, "PCAPNG byte-order magic")
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("Invalid PCAPNG byte-order magic")
            block_length = struct.unpack(endian + "I", raw_length)[0]
            if block_length < 28 or block_length % 4:
                raise CaptureFormatError("Invalid PCAPNG section header length")
            remainder = read_exact(handle, block_length - 12, "PCAPNG section header")
            if struct.unpack_from(endian + "I", remainder, len(remainder) - 4)[0] != block_length:
                raise CaptureFormatError("PCAPNG section length mismatch")
            interfaces = []
        else:
            if endian is None:
                raise CaptureFormatError("PCAPNG data appeared before a section header")
            block_type = struct.unpack(endian + "I", pending_type)[0]
            block_length = struct.unpack(endian + "I", raw_length)[0]
            if block_length < 12 or block_length % 4 or block_length > MAX_PACKET_BYTES + 1_048_576:
                raise CaptureFormatError(f"Invalid PCAPNG block length: {block_length}")
            block = read_exact(handle, block_length - 8, "PCAPNG block")
            if struct.unpack_from(endian + "I", block, len(block) - 4)[0] != block_length:
                raise CaptureFormatError("PCAPNG block length mismatch")
            body = block[:-4]

            if block_type == 1 and len(body) >= 8:  # Interface Description Block
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
                resolution = 1e-6
                options = parse_pcapng_options(body[8:], endian)
                if 9 in options and options[9] and options[9][0]:
                    value = options[9][0][0]
                    resolution = 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
                interfaces.append((linktype, resolution))
            elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
                interface_id, timestamp_high, timestamp_low, captured_length, _ = struct.unpack_from(
                    endian + "IIIII", body, 0
                )
                if interface_id >= len(interfaces):
                    raise CaptureFormatError("PCAPNG packet references an unknown interface")
                if captured_length > MAX_PACKET_BYTES or 20 + captured_length > len(body):
                    raise CaptureFormatError("Invalid PCAPNG captured packet length")
                linktype, resolution = interfaces[interface_id]
                raw_timestamp = (timestamp_high << 32) | timestamp_low
                yield CapturedPacket(
                    raw_timestamp * resolution,
                    body[20 : 20 + captured_length],
                    linktype,
                )

        pending_type = handle.read(4)
        if pending_type and len(pending_type) != 4:
            raise CaptureFormatError("Truncated PCAPNG block type")


def iter_capture_packets(path: Path) -> Iterator[CapturedPacket]:
    with path.open("rb") as handle:
        magic = read_exact(handle, 4, "capture header")
        if magic in {
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        }:
            yield from iter_classic_pcap(handle, magic)
        elif magic == b"\x0a\x0d\x0d\x0a":
            yield from iter_pcapng(handle, magic)
        else:
            raise CaptureFormatError("Unsupported capture format: expected PCAP or PCAPNG")


def network_payload(data: bytes, linktype: int) -> tuple[int, bytes] | None:
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        offset = 14
        ethertype = struct.unpack_from("!H", data, 12)[0]
        for _ in range(2):
            if ethertype not in (0x8100, 0x88A8):
                break
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        return ethertype, data[offset:]
    if linktype == 101:  # Raw IPv4/IPv6
        if not data:
            return None
        version = data[0] >> 4
        return (0x0800 if version == 4 else 0x86DD if version == 6 else 0), data
    if linktype == 113:  # Linux cooked capture v1
        if len(data) < 16:
            return None
        return struct.unpack_from("!H", data, 14)[0], data[16:]
    if linktype == 276:  # Linux cooked capture v2
        if len(data) < 20:
            return None
        return struct.unpack_from("!H", data, 0)[0], data[20:]
    return None


def parse_transport(
    source: str,
    destination: str,
    protocol_number: int,
    payload: bytes,
    captured_length: int,
    fragmented: bool,
) -> ParsedPacket:
    if fragmented:
        return ParsedPacket(source, destination, "fragment", 0, 0, 0, b"", captured_length, True)
    if protocol_number == 6 and len(payload) >= 20:
        source_port, destination_port = struct.unpack_from("!HH", payload, 0)
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or data_offset > len(payload):
            data_offset = len(payload)
        return ParsedPacket(
            source,
            destination,
            "tcp",
            source_port,
            destination_port,
            payload[13],
            payload[data_offset:],
            captured_length,
        )
    if protocol_number == 17 and len(payload) >= 8:
        source_port, destination_port = struct.unpack_from("!HH", payload, 0)
        return ParsedPacket(
            source,
            destination,
            "udp",
            source_port,
            destination_port,
            0,
            payload[8:],
            captured_length,
        )
    return ParsedPacket(
        source,
        destination,
        f"ip-{protocol_number}",
        0,
        0,
        0,
        b"",
        captured_length,
    )


def parse_ip_packet(data: bytes, linktype: int) -> ParsedPacket | None:
    network = network_payload(data, linktype)
    if network is None:
        return None
    ethertype, payload = network
    if ethertype == 0x0800 and len(payload) >= 20:
        version = payload[0] >> 4
        header_length = (payload[0] & 0x0F) * 4
        if version != 4 or header_length < 20 or header_length > len(payload):
            return None
        total_length = struct.unpack_from("!H", payload, 2)[0]
        packet_end = min(len(payload), total_length if total_length >= header_length else len(payload))
        fragment_field = struct.unpack_from("!H", payload, 6)[0]
        fragment_offset = fragment_field & 0x1FFF
        source = socket.inet_ntop(socket.AF_INET, payload[12:16])
        destination = socket.inet_ntop(socket.AF_INET, payload[16:20])
        return parse_transport(
            source,
            destination,
            payload[9],
            payload[header_length:packet_end],
            len(data),
            fragment_offset != 0,
        )
    if ethertype == 0x86DD and len(payload) >= 40:
        if payload[0] >> 4 != 6:
            return None
        source = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        destination = socket.inet_ntop(socket.AF_INET6, payload[24:40])
        next_header = payload[6]
        offset = 40
        fragmented = False
        for _ in range(8):
            if next_header in (0, 43, 60):
                if offset + 2 > len(payload):
                    return None
                current = next_header
                next_header = payload[offset]
                length = (payload[offset + 1] + 1) * 8
                if length < 8 or offset + length > len(payload):
                    return None
                offset += length
                if current == 0:
                    continue
            elif next_header == 44:
                if offset + 8 > len(payload):
                    return None
                next_header = payload[offset]
                fragment_field = struct.unpack_from("!H", payload, offset + 2)[0]
                fragmented = ((fragment_field >> 3) & 0x1FFF) != 0
                offset += 8
            elif next_header == 51:
                if offset + 2 > len(payload):
                    return None
                next_header = payload[offset]
                length = (payload[offset + 1] + 2) * 4
                if offset + length > len(payload):
                    return None
                offset += length
            else:
                break
        return parse_transport(
            source, destination, next_header, payload[offset:], len(data), fragmented
        )
    return None


def dns_name(data: bytes, offset: int, seen: set[int] | None = None) -> tuple[str, int]:
    labels: list[str] = []
    original_offset = offset
    jumped = False
    seen = set() if seen is None else seen
    while offset < len(data):
        if offset in seen:
            raise ValueError("DNS compression loop")
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), (original_offset + 2 if jumped else offset)
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("Truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            pointed, _ = dns_name(data, pointer, seen)
            labels.append(pointed)
            if not jumped:
                original_offset = offset
            jumped = True
            return ".".join(filter(None, labels)), original_offset + 2
        if length > 63 or offset + 1 + length > len(data):
            raise ValueError("Invalid DNS label")
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    raise ValueError("Truncated DNS name")


def parse_dns(data: bytes) -> tuple[list[str], list[str]]:
    if len(data) < 12:
        return [], []
    _, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", data, 0)
    offset = 12
    queries: list[str] = []
    responses: list[str] = []
    try:
        for _ in range(min(questions, 100)):
            name, offset = dns_name(data, offset)
            if offset + 4 > len(data):
                return queries, responses
            offset += 4
            if name:
                queries.append(name[:1024])
        if not (flags & 0x8000):
            return queries, responses
        for _ in range(min(answers, 100)):
            _, offset = dns_name(data, offset)
            if offset + 10 > len(data):
                break
            record_type, _, _, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if offset + length > len(data):
                break
            rdata_offset = offset
            rdata = data[offset : offset + length]
            offset += length
            if record_type == 1 and length == 4:
                responses.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif record_type == 28 and length == 16:
                responses.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif record_type in (2, 5, 12):
                name, _ = dns_name(data, rdata_offset)
                if name:
                    responses.append(name[:1024])
    except (ValueError, OSError, struct.error):
        pass
    return queries, responses


def parse_http_request(payload: bytes) -> tuple[str, str, str | None] | None:
    sample = payload[:4096]
    if not sample.startswith(HTTP_METHODS):
        return None
    lines = sample.split(b"\r\n")
    request_parts = lines[0].decode("latin-1", errors="replace").split(" ", 2)
    if len(request_parts) < 2:
        return None
    host = None
    for line in lines[1:100]:
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")[:512]
            break
    return request_parts[0][:16], request_parts[1][:2048], host


def sliding_unique_max(events: Iterable[tuple[float, Any]], window_seconds: float) -> dict[str, Any]:
    ordered = sorted(events, key=lambda item: item[0])
    window: deque[tuple[float, Any]] = deque()
    counts: Counter[Any] = Counter()
    best: dict[str, Any] = {"unique_count": 0, "start": None, "end": None, "values": []}
    for timestamp, value in ordered:
        window.append((timestamp, value))
        counts[value] += 1
        while window and timestamp - window[0][0] > window_seconds:
            _, expired = window.popleft()
            counts[expired] -= 1
            if counts[expired] <= 0:
                del counts[expired]
        if len(counts) > best["unique_count"]:
            best = {
                "unique_count": len(counts),
                "start": window[0][0],
                "end": timestamp,
                "values": sorted(counts, key=str)[:50],
            }
    return best


def detect_scans(
    vertical: dict[tuple[str, str, str], list[tuple[float, int]]],
    horizontal: dict[tuple[str, int, str], list[tuple[float, str]]],
    config: AnalysisConfig,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for (source, destination, protocol), events in vertical.items():
        best = sliding_unique_max(events, config.scan_window_seconds)
        if best["unique_count"] >= config.scan_port_threshold:
            findings.append(
                {
                    "type": "vertical_port_scan_candidate",
                    "source": source,
                    "source_scope": ip_scope(source),
                    "destination": destination,
                    "destination_scope": ip_scope(destination),
                    "protocol": protocol,
                    "unique_ports": best["unique_count"],
                    "window_seconds": round(best["end"] - best["start"], 3),
                    "first_seen": iso_timestamp(best["start"]),
                    "last_seen": iso_timestamp(best["end"]),
                    "port_sample": best["values"],
                    "assessment": "Suspicious pattern; validate against authorized scanning and asset roles.",
                }
            )
    for (source, port, protocol), events in horizontal.items():
        best = sliding_unique_max(events, config.scan_window_seconds)
        if best["unique_count"] >= config.scan_host_threshold:
            findings.append(
                {
                    "type": "horizontal_scan_candidate",
                    "source": source,
                    "source_scope": ip_scope(source),
                    "destination_port": port,
                    "protocol": protocol,
                    "unique_destinations": best["unique_count"],
                    "window_seconds": round(best["end"] - best["start"], 3),
                    "first_seen": iso_timestamp(best["start"]),
                    "last_seen": iso_timestamp(best["end"]),
                    "destination_sample": best["values"],
                    "assessment": "Suspicious pattern; validate against scanners and administration activity.",
                }
            )
    return sorted(
        findings,
        key=lambda item: item.get("unique_ports", item.get("unique_destinations", 0)),
        reverse=True,
    )


def detect_beacons(
    events_by_flow: dict[tuple[str, str, int, str], list[float]], config: AnalysisConfig
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for (source, destination, port, protocol), values in events_by_flow.items():
        timestamps = sorted(set(values))
        if len(timestamps) < config.beacon_min_events:
            continue
        intervals = [right - left for left, right in zip(timestamps, timestamps[1:]) if right > left]
        if len(intervals) < config.beacon_min_events - 1:
            continue
        mean_interval = statistics.fmean(intervals)
        if not config.beacon_min_interval <= mean_interval <= config.beacon_max_interval:
            continue
        standard_deviation = statistics.pstdev(intervals)
        coefficient_variation = standard_deviation / mean_interval if mean_interval else math.inf
        if coefficient_variation > config.beacon_max_cv:
            continue
        findings.append(
            {
                "type": "periodic_communication_candidate",
                "source": source,
                "source_scope": ip_scope(source),
                "destination": destination,
                "destination_scope": ip_scope(destination),
                "destination_port": port,
                "protocol": protocol,
                "events": len(timestamps),
                "mean_interval_seconds": round(mean_interval, 3),
                "minimum_interval_seconds": round(min(intervals), 3),
                "maximum_interval_seconds": round(max(intervals), 3),
                "coefficient_of_variation": round(coefficient_variation, 4),
                "first_seen": iso_timestamp(timestamps[0]),
                "last_seen": iso_timestamp(timestamps[-1]),
                "assessment": "Regular timing is a lead, not proof of C2; correlate process, DNS, TLS, and threat intelligence.",
            }
        )
    return sorted(findings, key=lambda item: (item["coefficient_of_variation"], -item["events"]))


def analyze_pcap(path: Path, config: AnalysisConfig) -> dict[str, Any]:
    config.validate()
    input_path = path.expanduser().resolve(strict=True)
    if not input_path.is_file():
        raise ValueError(f"Input is not a file: {input_path}")
    file_size = input_path.stat().st_size
    if file_size > config.max_file_mb * 1024 * 1024:
        raise ValueError(
            f"Capture is {file_size / (1024 * 1024):.1f} MiB; limit is {config.max_file_mb} MiB"
        )

    protocols: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    addresses: set[str] = set()
    dns_queries: Counter[str] = Counter()
    dns_answers: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()
    http_requests: list[dict[str, Any]] = []
    flow_stats: dict[tuple[str, str, int, str], dict[str, Any]] = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "first": None, "last": None}
    )
    vertical: dict[tuple[str, str, str], list[tuple[float, int]]] = defaultdict(list)
    horizontal: dict[tuple[str, int, str], list[tuple[float, str]]] = defaultdict(list)
    beacon_events: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)

    packet_count = 0
    parse_errors = 0
    unsupported_link_packets = 0
    truncated = False
    first_seen: float | None = None
    last_seen: float | None = None

    try:
        for captured in iter_capture_packets(input_path):
            if packet_count >= config.max_packets:
                truncated = True
                break
            packet_count += 1
            first_seen = captured.timestamp if first_seen is None else min(first_seen, captured.timestamp)
            last_seen = captured.timestamp if last_seen is None else max(last_seen, captured.timestamp)
            try:
                packet = parse_ip_packet(captured.data, captured.linktype)
                if packet is None:
                    unsupported_link_packets += 1
                    protocols["non-ip-or-unsupported"] += 1
                    continue
                addresses.update((packet.source, packet.destination))
                sources[packet.source] += 1
                destinations[packet.destination] += 1
                protocols[packet.protocol] += 1

                if packet.destination_port:
                    ports[f"{packet.protocol}/{packet.destination_port}"] += 1
                    key = (
                        packet.source,
                        packet.destination,
                        packet.destination_port,
                        packet.protocol,
                    )
                    flow = flow_stats[key]
                    flow["packets"] += 1
                    flow["bytes"] += packet.captured_length
                    flow["first"] = (
                        captured.timestamp if flow["first"] is None else min(flow["first"], captured.timestamp)
                    )
                    flow["last"] = (
                        captured.timestamp if flow["last"] is None else max(flow["last"], captured.timestamp)
                    )

                    scan_relevant = packet.protocol == "udp" or (
                        packet.protocol == "tcp"
                        and bool(packet.tcp_flags & 0x02)
                        and not bool(packet.tcp_flags & 0x10)
                    )
                    if scan_relevant:
                        vertical[(packet.source, packet.destination, packet.protocol)].append(
                            (captured.timestamp, packet.destination_port)
                        )
                        horizontal[(packet.source, packet.destination_port, packet.protocol)].append(
                            (captured.timestamp, packet.destination)
                        )
                        beacon_events[key].append(captured.timestamp)

                if packet.protocol == "udp" and (
                    packet.source_port == 53 or packet.destination_port == 53
                ):
                    queries, answers = parse_dns(packet.payload)
                    dns_queries.update(queries)
                    dns_answers.update(answers)

                if packet.protocol == "tcp" and packet.payload:
                    request = parse_http_request(packet.payload)
                    if request is not None:
                        method, target, host = request
                        if host:
                            http_hosts[host] += 1
                        if len(http_requests) < config.http_record_limit:
                            http_requests.append(
                                {
                                    "time": iso_timestamp(captured.timestamp),
                                    "source": packet.source,
                                    "destination": packet.destination,
                                    "destination_port": packet.destination_port,
                                    "method": method,
                                    "host": host,
                                    "target": target,
                                }
                            )
            except (IndexError, OSError, struct.error, ValueError):
                parse_errors += 1
    except (OSError, EOFError, CaptureFormatError, struct.error) as exc:
        raise ValueError(f"Unable to parse capture: {exc}") from exc

    large_threshold = int(config.large_transfer_mb * 1024 * 1024)
    large_transfers: list[dict[str, Any]] = []
    for (source, destination, port, protocol), flow in flow_stats.items():
        if flow["bytes"] >= large_threshold:
            large_transfers.append(
                {
                    "type": "large_transfer_candidate",
                    "source": source,
                    "destination": destination,
                    "destination_port": port,
                    "protocol": protocol,
                    "packets": flow["packets"],
                    "bytes": flow["bytes"],
                    "megabytes": round(flow["bytes"] / (1024 * 1024), 3),
                    "first_seen": iso_timestamp(flow["first"]),
                    "last_seen": iso_timestamp(flow["last"]),
                    "assessment": "Review direction, application behavior, transferred objects, and user impact.",
                }
            )
    large_transfers.sort(key=lambda item: item["bytes"], reverse=True)

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else 0.0
    return {
        "metadata": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "input_file": input_path.name,
            "input_sha256": sha256_file(input_path),
            "input_size_bytes": file_size,
            "packets_processed": packet_count,
            "packet_limit": config.max_packets,
            "truncated_at_packet_limit": truncated,
            "parse_errors": parse_errors,
            "unsupported_link_or_non_ip_packets": unsupported_link_packets,
            "first_seen": iso_timestamp(first_seen),
            "last_seen": iso_timestamp(last_seen),
            "duration_seconds": round(duration, 3),
        },
        "safety": {
            "payload_execution": False,
            "payload_extraction": False,
            "network_connections": False,
            "packet_payloads_written": False,
            "runtime_dependencies": "Python standard library only",
        },
        "summary": {
            "unique_ip_count": len(addresses),
            "ip_addresses": [
                {"ip": address, "scope": ip_scope(address)}
                for address in sorted(addresses, key=lambda item: (ip_scope(item), item))
            ],
            "protocols": counter_rows(protocols, key_name="protocol"),
            "top_sources": counter_rows(sources, key_name="source"),
            "top_destinations": counter_rows(destinations, key_name="destination"),
            "top_destination_ports": counter_rows(ports, key_name="port"),
            "dns_query_count": sum(dns_queries.values()),
            "cleartext_http_request_count": len(http_requests),
        },
        "dns": {
            "top_queries": counter_rows(dns_queries, limit=100, key_name="query"),
            "top_answers": counter_rows(dns_answers, limit=100, key_name="answer"),
        },
        "http": {
            "top_hosts": counter_rows(http_hosts, limit=100, key_name="host"),
            "requests": http_requests,
            "note": "Only request lines and Host headers are retained; bodies are never stored.",
        },
        "detections": {
            "port_scan_candidates": detect_scans(vertical, horizontal, config),
            "beacon_candidates": detect_beacons(beacon_events, config),
            "large_transfer_candidates": large_transfers,
        },
        "judgement_rule": (
            "A match is not proof of malicious activity, and no match does not prove safety. "
            "Combine timing, endpoint, DNS, process, identity, threat intelligence, and business context."
        ),
    }


def decode_value(value: str, encoding: str) -> bytes:
    if len(value.encode("utf-8")) > MAX_DECODE_INPUT:
        raise ValueError(f"Encoded input exceeds {MAX_DECODE_INPUT} bytes")
    compact = "".join(value.split())
    selected = encoding.lower()
    if selected == "url":
        return urllib.parse.unquote_to_bytes(value)
    if selected == "hex":
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError("Invalid hexadecimal input") from exc
    if selected in {"base64", "base64url"}:
        padding = "=" * (-len(compact) % 4)
        try:
            if selected == "base64url":
                return base64.urlsafe_b64decode(compact + padding)
            return base64.b64decode(compact + padding, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid {selected} input") from exc
    if selected == "auto":
        if "%" in value:
            return decode_value(value, "url")
        if re.fullmatch(r"[0-9a-fA-F]+", compact or "x") and len(compact) % 2 == 0:
            return decode_value(compact, "hex")
        for candidate in ("base64", "base64url"):
            try:
                return decode_value(compact, candidate)
            except ValueError:
                continue
        raise ValueError("Unable to identify encoding; specify --encoding")
    raise ValueError(f"Unsupported encoding: {encoding}")


def printable_preview(data: bytes, limit: int) -> str:
    return "".join(
        chr(byte) if 32 <= byte <= 126 or byte in (9, 10, 13) else "." for byte in data[:limit]
    )


def write_json_report(report: dict[str, Any], output: Path, input_path: Path) -> Path:
    resolved_output = output.expanduser().resolve()
    if resolved_output == input_path.expanduser().resolve():
        raise ValueError("JSON output path must not overwrite the input capture")
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    resolved_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return resolved_output


def print_human_summary(report: dict[str, Any]) -> None:
    metadata = report["metadata"]
    summary = report["summary"]
    detections = report["detections"]
    print(f"{TOOL_NAME} {metadata['version']}")
    print(f"Input: {metadata['input_file']}")
    print(f"SHA256: {metadata['input_sha256']}")
    print(
        f"Packets: {metadata['packets_processed']} | Duration: {metadata['duration_seconds']}s | "
        f"Unique IPs: {summary['unique_ip_count']}"
    )
    print(
        "Candidates: "
        f"scans={len(detections['port_scan_candidates'])}, "
        f"beacons={len(detections['beacon_candidates'])}, "
        f"large_transfers={len(detections['large_transfer_candidates'])}"
    )
    if metadata["truncated_at_packet_limit"]:
        print("Warning: packet limit reached; results cover only part of the capture.")
    print("Judgement: detections are investigation leads, not proof of malicious activity.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only defensive PCAP/C2 triage. Never executes or extracts payloads."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="Analyze a PCAP/PCAPNG file read-only")
    analyze.add_argument("pcap", type=Path)
    analyze.add_argument("--json-out", type=Path)
    analyze.add_argument("--max-packets", type=int, default=AnalysisConfig.max_packets)
    analyze.add_argument("--max-file-mb", type=int, default=AnalysisConfig.max_file_mb)
    analyze.add_argument("--scan-window", type=float, default=AnalysisConfig.scan_window_seconds)
    analyze.add_argument("--scan-port-threshold", type=int, default=AnalysisConfig.scan_port_threshold)
    analyze.add_argument("--scan-host-threshold", type=int, default=AnalysisConfig.scan_host_threshold)
    analyze.add_argument("--beacon-min-events", type=int, default=AnalysisConfig.beacon_min_events)
    analyze.add_argument("--beacon-min-interval", type=float, default=AnalysisConfig.beacon_min_interval)
    analyze.add_argument("--beacon-max-interval", type=float, default=AnalysisConfig.beacon_max_interval)
    analyze.add_argument("--beacon-max-cv", type=float, default=AnalysisConfig.beacon_max_cv)
    analyze.add_argument("--large-transfer-mb", type=float, default=AnalysisConfig.large_transfer_mb)
    analyze.add_argument("--http-limit", type=int, default=AnalysisConfig.http_record_limit)

    decode = subparsers.add_parser(
        "decode", help="Decode one selected value; never execute or write decoded bytes"
    )
    decode.add_argument("--value", required=True)
    decode.add_argument(
        "--encoding",
        choices=("auto", "base64", "base64url", "hex", "url"),
        default="auto",
    )
    decode.add_argument("--preview-bytes", type=int, default=256)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "decode":
            if not 1 <= args.preview_bytes <= 4096:
                raise ValueError("--preview-bytes must be between 1 and 4096")
            decoded = decode_value(args.value, args.encoding)
            preview = decoded[: args.preview_bytes]
            print(f"Decoded length: {len(decoded)} bytes")
            print(f"Hex preview: {preview.hex()}")
            print("Printable preview:")
            print(printable_preview(decoded, args.preview_bytes))
            if len(decoded) > args.preview_bytes:
                print(f"Preview truncated at {args.preview_bytes} bytes.")
            return 0

        config = AnalysisConfig(
            max_packets=args.max_packets,
            max_file_mb=args.max_file_mb,
            scan_window_seconds=args.scan_window,
            scan_port_threshold=args.scan_port_threshold,
            scan_host_threshold=args.scan_host_threshold,
            beacon_min_events=args.beacon_min_events,
            beacon_min_interval=args.beacon_min_interval,
            beacon_max_interval=args.beacon_max_interval,
            beacon_max_cv=args.beacon_max_cv,
            large_transfer_mb=args.large_transfer_mb,
            http_record_limit=args.http_limit,
        )
        report = analyze_pcap(args.pcap, config)
        print_human_summary(report)
        if args.json_out:
            output = write_json_report(report, args.json_out, args.pcap)
            print(f"JSON report: {output}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
