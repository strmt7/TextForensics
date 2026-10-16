"""TextForensics: detector reliability and AI-text forensics."""

from .casefile import seal_case_file, verify_case_file
from .compare import compare_texts
from .engine import analyze_text
from .report import build_forensic_bundle
from .version import get_version

__all__ = [
    "analyze_text",
    "build_forensic_bundle",
    "compare_texts",
    "get_version",
    "seal_case_file",
    "verify_case_file",
]

__version__ = get_version()
