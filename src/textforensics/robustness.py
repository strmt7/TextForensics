from __future__ import annotations

import re


def benign_variants(text: str) -> dict[str, str]:
    """Create meaning-preserving formatting variants for verdict stability checks."""
    whitespace = re.sub(r"[ \t]+", " ", text)
    whitespace = re.sub(r"\n{3,}", "\n\n", whitespace)
    ascii_punct = (
        text.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
        .replace("—", "-").replace("–", "-")
    )
    no_markdown = re.sub(r"(?m)^\s*[-*+]\s+", "", text)
    return {
        "original": text,
        "normalized_whitespace": whitespace,
        "normalized_punctuation": ascii_punct,
        "plain_list_formatting": no_markdown,
    }
