"""Automatic passive analysis, encoding discovery, and triage orchestration."""

from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any

from .analysis import analyze_pcap
from .models import AnalysisConfig
from .transforms import decode_detected_layers
from .utils import printable_preview


MAX_AUTOMATIC_CANDIDATES = 100
def discover_encoded_http_values(
    report: dict[str, Any], preview_bytes: int = 128
) -> list[dict[str, Any]]:
    """Decode bounded query values already present in retained HTTP metadata.

    Path segments are intentionally excluded because ordinary slugs and asset
    names create too many Base64URL false positives.
    """

    if not 1 <= preview_bytes <= 4096:
        raise ValueError("Automatic decode preview must be between 1 and 4096 bytes")
    findings: list[dict[str, Any]] = []
    requests = report.get("http", {}).get("requests", [])
    for request_index, request in enumerate(requests, 1):
        target = str(request.get("target", ""))
        parsed = urllib.parse.urlsplit(target)
        raw_values: list[tuple[str, str]] = []
        for pair in parsed.query.split("&") if parsed.query else []:
            name, separator, value = pair.partition("=")
            if separator and value:
                raw_values.append((urllib.parse.unquote_plus(name), value))

        for value_index, (name, value) in enumerate(raw_values, 1):
            if len(findings) >= MAX_AUTOMATIC_CANDIDATES:
                return findings
            try:
                decoded, encoding_chain = decode_detected_layers(value)
            except ValueError:
                continue
            if not decoded or not encoding_chain:
                continue
            encoding = encoding_chain[-1]
            identifier = f"http-{request_index:04d}-{value_index:02d}"
            preview = decoded[:preview_bytes]
            findings.append(
                {
                    "candidate_id": identifier,
                    "time": request.get("time"),
                    "source": request.get("source"),
                    "destination": request.get("destination"),
                    "location": "http.request.uri.query",
                    "field_name": name,
                    "encoding": encoding,
                    "encoding_chain": encoding_chain,
                    "encoding_confidence": (
                        "high"
                        if encoding in {"hex", "url"} or any(char in value for char in "=+/_-")
                        else "medium"
                    ),
                    "encoded_length": len(value),
                    "decoded_length": len(decoded),
                    "decoded_hex_preview": preview.hex(),
                    "decoded_text_preview": printable_preview(preview, preview_bytes),
                    "preview_truncated": len(decoded) > preview_bytes,
                    "assessment": (
                        "Decoded automatically as an investigation lead. Encoding alone is not malicious."
                    ),
                }
            )
    return findings


def _triage(report: dict[str, Any], encoded_count: int) -> dict[str, Any]:
    detections = report["detections"]
    evidence: list[str] = []
    score = 0
    if detections["beacon_candidates"]:
        score += 4
        evidence.append("periodic communication candidates")
    if detections["port_scan_candidates"]:
        score += 2
        evidence.append("scan candidates")
    if detections["large_transfer_candidates"]:
        score += 2
        evidence.append("large transfer candidates")
    if encoded_count:
        score += 1
        evidence.append("encoded HTTP field candidates")
    if score >= 6:
        assessment = "suspicious"
    elif score >= 2:
        assessment = "investigate"
    else:
        assessment = "lower suspicion"
    return {
        "assessment": assessment,
        "score": score,
        "evidence": evidence,
        "rule": (
            "This score prioritizes review; it is not a malicious verdict. Correlate endpoint, "
            "identity, DNS, TLS, threat intelligence, and business context."
        ),
    }


def run_automatic_analysis(
    path: Path,
    config: AnalysisConfig,
    *,
    decode_preview_bytes: int = 128,
) -> dict[str, Any]:
    """Run every safe passive stage without executing or extracting payloads."""

    report = analyze_pcap(path, config)
    decoded = discover_encoded_http_values(report, decode_preview_bytes)
    report["automation"] = {
        "mode": "automatic",
        "stages": {
            "capture_analysis": "completed",
            "encoded_field_discovery": "completed",
        },
        "encoded_candidates": decoded,
        "triage": _triage(report, len(decoded)),
    }
    report["safety"]["automatic_payload_execution"] = False
    report["safety"]["automatic_payload_extraction"] = False
    return report
