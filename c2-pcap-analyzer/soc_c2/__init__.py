"""Defensive C2 and PCAP analysis helpers."""

from .analysis import analyze_pcap
from .automation import run_automatic_analysis
from .transforms import decode_value
from .models import AnalysisConfig, CaptureFormatError
from .reporting import write_json_report

__all__ = [
    "AnalysisConfig",
    "CaptureFormatError",
    "analyze_pcap",
    "run_automatic_analysis",
    "decode_value",
    "write_json_report",
]

__version__ = "2.1.0"
