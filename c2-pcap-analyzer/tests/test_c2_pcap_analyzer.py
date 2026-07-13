from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from soc_c2 import AnalysisConfig, analyze_pcap, decode_value, write_json_report
from soc_c2.protocols import dns_name


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack(
        "!H", ethertype
    ) + payload


def ipv4(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return header + payload


def tcp(source_port: int, destination_port: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack(
        "!HHIIBBHHH", source_port, destination_port, 0, 0, 0x50, flags, 8192, 0, 0
    ) + payload


def udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in packets:
            seconds = int(timestamp)
            microseconds = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
            handle.write(packet)


def test_decode_supported_encodings() -> None:
    assert decode_value("SGVsbG8=", "base64") == b"Hello"
    assert decode_value("SGVsbG8", "base64url") == b"Hello"
    assert decode_value("48656c6c6f", "hex") == b"Hello"
    assert decode_value("%48%65%6c%6c%6f", "url") == b"Hello"


def test_decode_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        decode_value("not!base64", "base64")


def test_detects_scan_beacon_dns_and_http_without_extracting(tmp_path: Path) -> None:
    packets: list[tuple[float, bytes]] = []
    for index, port in enumerate(range(20, 45)):
        packets.append(
            (
                1_700_000_000.0 + index,
                ethernet(
                    ipv4(
                        "10.0.0.10",
                        "10.0.0.20",
                        6,
                        tcp(40_000 + index, port, 0x02),
                    )
                ),
            )
        )
    for index in range(8):
        packets.append(
            (
                1_700_001_000.0 + index * 30,
                ethernet(
                    ipv4(
                        "10.0.0.30",
                        "203.0.113.50",
                        6,
                        tcp(50_000 + index, 443, 0x02),
                    )
                ),
            )
        )
    packets.append(
        (
            1_700_002_000.0,
            ethernet(ipv4("10.0.0.30", "8.8.8.8", 17, udp(53_000, 53, dns_query("example.test")))),
        )
    )
    http = b"GET /status HTTP/1.1\r\nHost: test.invalid\r\n\r\n"
    packets.append(
        (
            1_700_002_010.0,
            ethernet(ipv4("10.0.0.30", "203.0.113.60", 6, tcp(51_000, 80, 0x18, http))),
        )
    )

    pcap = tmp_path / "synthetic.pcap"
    write_pcap(pcap, packets)
    before = {item.name for item in tmp_path.iterdir()}
    report = analyze_pcap(
        pcap,
        AnalysisConfig(
            max_packets=10_000,
            scan_port_threshold=20,
            beacon_min_events=6,
            beacon_max_cv=0.10,
            large_transfer_mb=100,
        ),
    )
    after = {item.name for item in tmp_path.iterdir()}

    assert before == after == {"synthetic.pcap"}
    assert report["metadata"]["packets_processed"] == len(packets)
    assert report["metadata"]["input_sha256"]
    assert report["safety"]["payload_execution"] is False
    assert report["safety"]["payload_extraction"] is False
    assert report["detections"]["port_scan_candidates"]
    assert any(
        item["destination"] == "203.0.113.50"
        for item in report["detections"]["beacon_candidates"]
    )
    assert report["dns"]["top_queries"][0]["query"] == "example.test"
    assert report["http"]["requests"][0]["host"] == "test.invalid"
    assert "body" not in report["http"]["requests"][0]


def test_packet_limit_marks_report_truncated(tmp_path: Path) -> None:
    packets = [
        (
            float(index),
            ethernet(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1000 + index, 80, 0x10))),
        )
        for index in range(5)
    ]
    pcap = tmp_path / "limit.pcap"
    write_pcap(pcap, packets)
    report = analyze_pcap(pcap, AnalysisConfig(max_packets=2))
    assert report["metadata"]["packets_processed"] == 2
    assert report["metadata"]["truncated_at_packet_limit"] is True


def test_json_report_cannot_overwrite_capture(tmp_path: Path) -> None:
    pcap = tmp_path / "evidence.pcap"
    pcap.write_bytes(b"not-a-real-pcap")
    with pytest.raises(ValueError):
        write_json_report({"ok": True}, pcap, pcap)


def test_rejects_unknown_capture_format(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture")
    with pytest.raises(ValueError, match="Unable to parse capture"):
        analyze_pcap(bad, AnalysisConfig())


def test_rejects_oversized_pcapng_section_before_reading_body(tmp_path: Path) -> None:
    capture = tmp_path / "oversized-section.pcapng"
    capture.write_bytes(
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 0x7FFFFFFC)
        + b"\x4d\x3c\x2b\x1a"
    )

    with pytest.raises(ValueError, match="Invalid PCAPNG section header length"):
        analyze_pcap(capture, AnalysisConfig())


def test_dns_compression_pointer_depth_is_bounded() -> None:
    data = bytearray((130 * 2) + 1)
    for offset in range(0, 130 * 2, 2):
        pointer = offset + 2
        data[offset] = 0xC0 | ((pointer >> 8) & 0x3F)
        data[offset + 1] = pointer & 0xFF
    data[-1] = 0

    with pytest.raises(ValueError, match="pointer depth exceeded"):
        dns_name(bytes(data), 0)
