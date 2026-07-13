"""Human and JSON reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import TOOL_NAME


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
