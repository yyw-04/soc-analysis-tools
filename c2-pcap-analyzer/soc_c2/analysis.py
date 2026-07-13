"""SOC-focused heuristics and report construction."""

from __future__ import annotations

import math
import statistics
import struct
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .capture import iter_capture_packets
from .models import AnalysisConfig, CaptureFormatError, TOOL_NAME, TOOL_VERSION
from .protocols import parse_dns, parse_http_request, parse_ip_packet
from .utils import counter_rows, ip_scope, iso_timestamp, sha256_file


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
                "assessment": (
                    "Regular timing is a lead, not proof of C2; correlate process, DNS, "
                    "TLS, and threat intelligence."
                ),
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
                        captured.timestamp
                        if flow["first"] is None
                        else min(flow["first"], captured.timestamp)
                    )
                    flow["last"] = (
                        captured.timestamp
                        if flow["last"] is None
                        else max(flow["last"], captured.timestamp)
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
                    "assessment": (
                        "Review direction, application behavior, transferred objects, and user impact."
                    ),
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
