"""Read classic PCAP and common PCAPNG captures without extracting payloads."""

from __future__ import annotations

import struct
from collections import defaultdict
from pathlib import Path
from typing import BinaryIO, Iterator

from .models import CaptureFormatError, CapturedPacket, MAX_PACKET_BYTES


MAX_PCAPNG_BLOCK_BYTES = MAX_PACKET_BYTES + 1_048_576


def read_exact(handle: BinaryIO, size: int, context: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise CaptureFormatError(f"Truncated {context}")
    return data


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
            if (
                block_length < 28
                or block_length % 4
                or block_length > MAX_PCAPNG_BLOCK_BYTES
            ):
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
            if block_length < 12 or block_length % 4 or block_length > MAX_PCAPNG_BLOCK_BYTES:
                raise CaptureFormatError(f"Invalid PCAPNG block length: {block_length}")
            block = read_exact(handle, block_length - 8, "PCAPNG block")
            if struct.unpack_from(endian + "I", block, len(block) - 4)[0] != block_length:
                raise CaptureFormatError("PCAPNG block length mismatch")
            body = block[:-4]

            if block_type == 1 and len(body) >= 8:
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
                resolution = 1e-6
                options = parse_pcapng_options(body[8:], endian)
                if 9 in options and options[9] and options[9][0]:
                    value = options[9][0][0]
                    resolution = 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
                interfaces.append((linktype, resolution))
            elif block_type == 6 and len(body) >= 20:
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
