"""TextForensics: detector reliability and AI-text forensics."""

from .benchmark_fingerprint import (
    DatasetFingerprint,
    check_disjointness,
    fingerprint_dataset,
    load_fingerprint,
    save_fingerprint,
    validate_disjointness,
    verify_fingerprint,
)
from .casefile import seal_case_file, verify_case_file
from .compare import compare_texts
from .drift import DriftObservatory
from .engine import analyze_text
from .report import build_forensic_bundle
from .threshold_selection import (
    evaluate_threshold,
    select_threshold,
)
from .version import get_version

__all__ = [
    "analyze_text",
    "build_forensic_bundle",
    "check_disjointness",
    "compare_texts",
    "DatasetFingerprint",
    "DriftObservatory",
    "evaluate_threshold",
    "fingerprint_dataset",
    "get_version",
    "load_fingerprint",
    "save_fingerprint",
    "select_threshold",
    "seal_case_file",
    "verify_fingerprint",
    "verify_case_file",
    "validate_disjointness",
]

__version__ = get_version()
