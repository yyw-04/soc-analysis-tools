"""Command-line interface for passive PCAP analysis and decoding."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analysis import analyze_pcap
from .transforms import decode_value
from .models import AnalysisConfig, TOOL_VERSION
from .reporting import print_human_summary, write_json_report
from .utils import printable_preview


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
