"""Minimal network protocol parsing for defensive metadata analysis."""

from __future__ import annotations

import socket
import struct

from .models import HTTP_METHODS, ParsedPacket


def network_payload(data: bytes, linktype: int) -> tuple[int, bytes] | None:
    if linktype == 1:
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
    if linktype == 101:
        if not data:
            return None
        version = data[0] >> 4
        return (0x0800 if version == 4 else 0x86DD if version == 6 else 0), data
    if linktype == 113:
        if len(data) < 16:
            return None
        return struct.unpack_from("!H", data, 14)[0], data[16:]
    if linktype == 276:
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
