"""TextForensics: evidence-first AI-text forensics."""

from .engine import analyze_text
from .compare import compare_texts
from .report import build_forensic_bundle

__all__ = ["analyze_text", "compare_texts", "build_forensic_bundle"]
__version__ = "0.1.0"
