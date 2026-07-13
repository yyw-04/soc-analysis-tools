"""Shared data models and safety limits."""

from __future__ import annotations

from dataclasses import dataclass


TOOL_NAME = "c2-pcap-analyzer"
TOOL_VERSION = "2.1.0"
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
