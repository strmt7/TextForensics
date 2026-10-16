"""TextForensics: evidence-first AI-text forensics."""

from .engine import analyze_text
from .compare import compare_texts

__all__ = ["analyze_text", "compare_texts"]
__version__ = "0.1.0"
