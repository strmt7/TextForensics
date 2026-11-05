"""Deterministic input-condition extraction for evidence-conditioned auditing.

The purpose of this module is *not* to classify authorship. It extracts the
conditions that determine whether a detector's validation evidence applies to
an input: language, script, length, domain/genre, editing regime, generator,
and human population.

Rules:

* Language, domain, and script are inferred conservatively from transparent
  cues. Low-confidence inferences are surfaced as low confidence and are
  treated as ``unknown`` by the Trust Map.
* Editing regime, generator, and human population are **never** inferred from
  text. They are ``unknown`` unless the caller declares them.
* Every field is deterministic for the same input and extraction version.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

CONDITIONS_SCHEMA = "textforensics.input-conditions/v1"
EXTRACTION_VERSION = "1"

LENGTH_BANDS: tuple[tuple[str, int, int | None], ...] = (
    ("very_short", 0, 49),
    ("short", 50, 149),
    ("medium", 150, 499),
    ("long", 500, 999),
    ("very_long", 1000, None),
)

DOMAINS = frozenset(
    {
        "academic",
        "business",
        "email",
        "fiction",
        "general",
        "legal",
        "news",
        "social_media",
        "student_essay",
        "technical",
        "unknown",
    }
)

EDITING_REGIMES = frozenset(
    {
        "human_only",
        "machine_only",
        "machine_then_human_edited",
        "machine_then_machine_paraphrased",
        "mixed",
        "unknown",
    }
)

LANGUAGE_CONFIDENCE = frozenset({"high", "medium", "low", "declared", "unknown"})
DOMAIN_CONFIDENCE = frozenset({"high", "medium", "low", "declared", "unknown"})

_WORD_RE = re.compile(r"\b[\w]+(?:['’][\w]+)?\b", re.UNICODE)
_LETTER_RE = re.compile(r"[^\W\d_]", re.UNICODE)

# A compact, auditable stopword profile. It is deliberately small: the goal is
# a conservative language hint, not a language identification system.
_STOPWORDS: dict[str, frozenset[str]] = {
    "en": frozenset(
        ["the", "of", "and", "to", "in", "is", "that", "for", "it", "as", "was", "with", "be", "by", "on", "not", "he", "i", "this", "are", "or", "his", "from", "at", "which", "but", "have", "an", "they", "you", "were", "her", "she", "there", "one", "all", "we", "can", "has", "been", "would", "their", "will", "more", "when", "who", "if", "no", "do", "what", "about"]
    ),
    "es": frozenset(
        ["el", "la", "de", "que", "y", "en", "los", "se", "del", "las", "un", "por", "con", "no", "una", "su", "para", "es", "al", "lo", "como", "más", "pero", "sus", "le", "ya", "o", "este", "sí", "porque", "esta", "entre", "cuando", "muy", "sin", "sobre", "también", "me", "hasta", "hay", "donde", "quien", "desde", "todo", "nos", "durante", "todos", "uno", "les", "ni", "contra"]
    ),
    "fr": frozenset(
        ["le", "la", "les", "de", "des", "du", "un", "une", "et", "en", "est", "que", "qui", "dans", "pour", "pas", "sur", "au", "avec", "ce", "il", "elle", "nous", "vous", "ils", "elles", "se", "son", "sa", "ses", "mais", "ou", "par", "plus", "ne", "comme", "je", "tu", "mon", "ma", "mes", "ton", "ta", "tes", "notre", "votre", "leur"]
    ),
    "de": frozenset(
        ["der", "die", "das", "und", "in", "den", "von", "zu", "mit", "sich", "des", "auf", "für", "ist", "im", "dem", "nicht", "ein", "eine", "als", "auch", "es", "an", "werden", "aus", "er", "hat", "dass", "sie", "nach", "wird", "bei", "einer", "um", "am", "sind", "noch", "wie", "einem", "über", "einen", "so", "zum", "war", "haben", "nur", "oder", "aber"]
    ),
    "it": frozenset(
        ["il", "la", "di", "che", "e", "per", "un", "in", "una", "è", "non", "con", "si", "da", "al", "le", "dei", "del", "delle", "come", "ma", "anche", "più", "questo", "questa", "sono", "gli", "lo", "alla", "nel", "nella", "su", "tra", "io", "tu", "lui", "lei", "noi", "voi", "loro"]
    ),
    "pt": frozenset(
        ["o", "a", "de", "que", "e", "do", "da", "em", "um", "para", "é", "com", "não", "uma", "os", "no", "se", "na", "por", "mais", "as", "dos", "como", "mas", "foi", "ao", "ele", "das", "tem", "à", "seu", "sua", "ou", "ser", "quando", "muito", "há", "nos", "já", "está", "eu", "também"]
    ),
    "nl": frozenset(
        ["de", "het", "een", "en", "van", "in", "is", "dat", "op", "te", "zijn", "met", "voor", "niet", "aan", "er", "om", "ook", "als", "dan", "maar", "bij", "of", "uit", "nog", "naar", "door", "over", "deze", "dit", "hij", "zij", "wij", "jullie", "ze", "kan", "werd", "worden"]
    ),
}

_DOMAIN_CUES: dict[str, tuple[str, ...]] = {
    "academic": (
        "abstract",
        "et al",
        "doi",
        "hypothesis",
        "literature review",
        "methodology",
        "peer review",
        "results",
        "statistical significance",
        "this paper",
        "we propose",
        "dataset",
        "empirical",
        "citation",
    ),
    "business": (
        "revenue",
        "stakeholder",
        "quarterly",
        "strategy",
        "customer",
        "market share",
        "roadmap",
        "kpi",
        "roi",
        "business plan",
        "shareholder",
        "profit",
    ),
    "email": (
        "subject:",
        "dear ",
        "best regards",
        "kind regards",
        "sincerely",
        "hi ",
        "hello ",
        "thank you",
        "please find",
        "attached",
        "meeting",
    ),
    "fiction": (
        "once upon",
        "chapter",
        "prologue",
        "epilogue",
        "she said",
        "he said",
        "novel",
        "character",
        "story",
        "whispered",
        "smiled",
    ),
    "legal": (
        "whereas",
        "hereby",
        "jurisdiction",
        "liability",
        "statute",
        "contract",
        "agreement",
        "party",
        "plaintiff",
        "defendant",
        "compliance",
        "regulation",
    ),
    "news": (
        "according to",
        "reported",
        "officials",
        "spokesperson",
        "breaking",
        "associated press",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "statement",
        "press conference",
    ),
    "social_media": (
        "http://",
        "https://",
        "www.",
        "lol",
        "omg",
        "imo",
        "imho",
        "dm ",
        "rt ",
        "#",
        "@",
    ),
    "student_essay": (
        "essay",
        "assignment",
        "introduction",
        "in conclusion",
        "this paper will",
        "i believe",
        "my argument",
        "the purpose of this",
        "furthermore",
        "in summary",
    ),
    "technical": (
        "algorithm",
        "api",
        "configuration",
        "deployment",
        "function",
        "implementation",
        "parameter",
        "runtime",
        "server",
        "source code",
        "system",
        "database",
    ),
}

_SCRIPT_RANGES: tuple[tuple[str, int, int], ...] = (
    ("latin", 0x0041, 0x024F),
    ("greek", 0x0370, 0x03FF),
    ("cyrillic", 0x0400, 0x04FF),
    ("hebrew", 0x0590, 0x05FF),
    ("arabic", 0x0600, 0x06FF),
    ("devanagari", 0x0900, 0x097F),
    ("thai", 0x0E00, 0x0E7F),
    ("hangul", 0xAC00, 0xD7AF),
    ("kana", 0x3040, 0x30FF),
    ("han", 0x3400, 0x9FFF),
)

_SCRIPT_LANGUAGE_HINTS: dict[str, tuple[str, str]] = {
    "greek": ("el", "high"),
    "hebrew": ("he", "high"),
    "hangul": ("ko", "high"),
    "thai": ("th", "high"),
    "kana": ("ja", "medium"),
    "han": ("zh", "low"),
    "arabic": ("ar", "medium"),
    "devanagari": ("hi", "medium"),
    "cyrillic": ("ru", "low"),
}


def _word_count(text: str) -> int:
    return len(_WORD_RE.findall(text))


def length_band(word_count: int) -> str:
    """Return the declared length band for a word count."""
    if isinstance(word_count, bool) or not isinstance(word_count, int):
        raise TypeError("word_count must be an integer.")
    if word_count < 0:
        raise ValueError("word_count must be non-negative.")
    for name, minimum, maximum in LENGTH_BANDS:
        if word_count >= minimum and (maximum is None or word_count <= maximum):
            return name
    return "very_long"


def detect_script(text: str) -> str:
    """Return the dominant script, or ``unknown`` when no letters are present."""
    counts: dict[str, int] = {}
    for character in text:
        if not _LETTER_RE.match(character):
            continue
        codepoint = ord(character)
        name = unicodedata.name(character, "")
        if "CJK UNIFIED IDEOGRAPH" in name or "CJK COMPATIBILITY IDEOGRAPH" in name:
            counts["han"] = counts.get("han", 0) + 1
            continue
        if "HIRAGANA" in name or "KATAKANA" in name:
            counts["kana"] = counts.get("kana", 0) + 1
            continue
        for script, start, end in _SCRIPT_RANGES:
            if start <= codepoint <= end:
                counts[script] = counts.get(script, 0) + 1
                break
    if not counts:
        return "unknown"
    return max(counts.items(), key=lambda item: (item[1], item[0]))[0]


def _language_scores(text: str) -> dict[str, int]:
    words = [item.lower() for item in _WORD_RE.findall(text)]
    if not words:
        return {}
    scores: dict[str, int] = {}
    for language, stopwords in _STOPWORDS.items():
        hits = sum(1 for word in words if word in stopwords)
        if hits:
            scores[language] = hits
    return scores


def detect_language(text: str, script: str) -> tuple[str, str, dict[str, Any]]:
    """Return ``(language, confidence, cues)``.

    The function is intentionally conservative. Short texts and ambiguous
    stopword profiles return ``und`` rather than a guess.
    """
    word_count = _word_count(text)
    if word_count < 8:
        return "und", "low", {"reason": "too_short", "word_count": word_count}

    if script != "latin":
        hint = _SCRIPT_LANGUAGE_HINTS.get(script)
        if hint is None:
            return "und", "low", {"script": script, "reason": "no_script_hint"}
        language, confidence = hint
        return language, confidence, {"script": script, "reason": "script_hint"}

    scores = _language_scores(text)
    if not scores:
        return "und", "low", {"stopword_hits": {}, "reason": "no_stopword_hits"}

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    best_language, best_hits = ranked[0]
    second_hits = ranked[1][1] if len(ranked) > 1 else 0
    cues = {
        "stopword_hits": dict(ranked),
        "best_language": best_language,
        "best_hits": best_hits,
        "second_hits": second_hits,
    }

    if best_hits >= 4 and (second_hits == 0 or best_hits >= 1.5 * second_hits):
        return best_language, "high", cues
    if best_hits >= 2 and best_hits >= 1.25 * second_hits:
        return best_language, "medium", cues
    return "und", "low", cues


def _domain_scores(text: str) -> dict[str, int]:
    lower = f" {text.lower()} "
    scores: dict[str, int] = {}
    for domain, cues in _DOMAIN_CUES.items():
        hits = 0
        for cue in cues:
            if cue in lower:
                hits += 2 if " " in cue else 1
        if hits:
            scores[domain] = hits
    return scores


def detect_domain(text: str) -> tuple[str, str, dict[str, Any]]:
    """Return ``(domain, confidence, cues)`` using transparent lexical cues."""
    scores = _domain_scores(text)
    if not scores:
        return "general", "low", {"domain_hits": {}, "reason": "no_domain_cues"}

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    best_domain, best_hits = ranked[0]
    second_hits = ranked[1][1] if len(ranked) > 1 else 0
    cues = {
        "domain_hits": dict(ranked),
        "best_domain": best_domain,
        "best_hits": best_hits,
        "second_hits": second_hits,
    }
    if best_hits >= 4 and (second_hits == 0 or best_hits >= 1.5 * second_hits):
        return best_domain, "high", cues
    if best_hits >= 2 and best_hits > second_hits:
        return best_domain, "medium", cues
    return best_domain, "low", cues


def _validate_declared(declared: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "language",
        "domain_genre",
        "editing_regime",
        "generator",
        "human_population",
    }
    unknown = sorted(set(declared) - allowed)
    if unknown:
        raise ValueError(f"Unknown declared condition field(s): {', '.join(unknown)}")

    normalized: dict[str, Any] = {}
    for key, value in declared.items():
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Declared {key} must be a non-empty string or null.")
        value = value.strip()
        if key == "language":
            if not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", value):
                raise ValueError("Declared language must be a BCP-47-like tag.")
            normalized[key] = value.lower()
        elif key == "domain_genre":
            if value not in DOMAINS - {"unknown"}:
                raise ValueError(
                    f"Declared domain_genre must be one of: "
                    f"{', '.join(sorted(DOMAINS - {'unknown'}))}."
                )
            normalized[key] = value
        elif key == "editing_regime":
            if value not in EDITING_REGIMES - {"unknown"}:
                raise ValueError(
                    f"Declared editing_regime must be one of: "
                    f"{', '.join(sorted(EDITING_REGIMES - {'unknown'}))}."
                )
            normalized[key] = value
        else:
            normalized[key] = value
    return normalized


@dataclass(frozen=True, slots=True)
class InputConditions:
    """Observed and declared conditions for an audit input."""

    schema: str
    language: str
    language_confidence: str
    script: str
    word_count: int
    char_count: int
    length_band: str
    domain_genre: str
    domain_confidence: str
    editing_regime: str
    generator: str | None
    human_population: str
    declared: dict[str, Any] = field(default_factory=dict)
    cues: dict[str, Any] = field(default_factory=dict)
    extraction_version: str = EXTRACTION_VERSION

    @property
    def effective_language(self) -> str:
        """Language suitable for coverage matching; ``und`` when uncertain."""
        if self.language_confidence in {"high", "medium", "declared"}:
            return self.language
        return "und"

    @property
    def effective_domain(self) -> str:
        """Domain suitable for coverage matching; ``unknown`` when uncertain."""
        if self.domain_confidence in {"high", "medium", "declared"}:
            return self.domain_genre
        return "unknown"

    @property
    def effective_editing_regime(self) -> str:
        return self.editing_regime if self.editing_regime in EDITING_REGIMES else "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_conditions(
    text: str,
    *,
    declared: Mapping[str, Any] | None = None,
) -> InputConditions:
    """Extract conditions from text, applying explicit caller declarations.

    Declared values always win over inferred values. The ``declared`` block
    records which fields were supplied so downstream consumers can audit the
    provenance of a condition.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must be a non-empty string.")
    if declared is not None and not isinstance(declared, Mapping):
        raise TypeError("declared must be a mapping or None.")

    normalized_declared = _validate_declared(declared or {})
    words = _word_count(text)
    script = detect_script(text)
    language, language_confidence, language_cues = detect_language(text, script)
    domain, domain_confidence, domain_cues = detect_domain(text)

    if "language" in normalized_declared:
        language = normalized_declared["language"]
        language_confidence = "declared"
    if "domain_genre" in normalized_declared:
        domain = normalized_declared["domain_genre"]
        domain_confidence = "declared"

    editing_regime = normalized_declared.get("editing_regime", "unknown")
    generator = normalized_declared.get("generator")
    human_population = normalized_declared.get("human_population", "unknown")

    cues: dict[str, Any] = {
        "language": language_cues,
        "domain": domain_cues,
    }
    if declared:
        cues["declared_fields"] = sorted(normalized_declared)
        if (
            "language" in normalized_declared
            and language_cues.get("best_language") not in (None, normalized_declared["language"])
        ):
            cues["declared_language_conflict"] = language_cues.get("best_language")
        if (
            "domain_genre" in normalized_declared
            and domain_cues.get("best_domain") not in (None, normalized_declared["domain_genre"])
        ):
            cues["declared_domain_conflict"] = domain_cues.get("best_domain")

    return InputConditions(
        schema=CONDITIONS_SCHEMA,
        language=language,
        language_confidence=language_confidence,
        script=script,
        word_count=words,
        char_count=len(text),
        length_band=length_band(words),
        domain_genre=domain,
        domain_confidence=domain_confidence,
        editing_regime=editing_regime,
        generator=generator,
        human_population=human_population,
        declared={
            "source": "caller" if normalized_declared else "none",
            "fields": sorted(normalized_declared),
            "values": normalized_declared,
        },
        cues=cues,
        extraction_version=EXTRACTION_VERSION,
    )


def conditions_from_dict(payload: Mapping[str, Any]) -> InputConditions:
    """Deserialize and validate an ``InputConditions`` payload."""
    if payload.get("schema") != CONDITIONS_SCHEMA:
        raise ValueError("Unsupported input-conditions schema.")
    language = str(payload["language"])
    language_confidence = str(payload["language_confidence"])
    domain = str(payload["domain_genre"])
    domain_confidence = str(payload["domain_confidence"])
    editing = str(payload.get("editing_regime", "unknown"))
    if language_confidence not in LANGUAGE_CONFIDENCE:
        raise ValueError("Invalid language_confidence.")
    if domain_confidence not in DOMAIN_CONFIDENCE:
        raise ValueError("Invalid domain_confidence.")
    if domain not in DOMAINS:
        raise ValueError("Invalid domain_genre.")
    if editing not in EDITING_REGIMES:
        raise ValueError("Invalid editing_regime.")
    word_count = payload["word_count"]
    if isinstance(word_count, bool) or not isinstance(word_count, int) or word_count < 0:
        raise ValueError("word_count must be a non-negative integer.")
    char_count = payload["char_count"]
    if isinstance(char_count, bool) or not isinstance(char_count, int) or char_count < 0:
        raise ValueError("char_count must be a non-negative integer.")
    return InputConditions(
        schema=CONDITIONS_SCHEMA,
        language=language,
        language_confidence=language_confidence,
        script=str(payload.get("script", "unknown")),
        word_count=word_count,
        char_count=char_count,
        length_band=str(payload.get("length_band", length_band(word_count))),
        domain_genre=domain,
        domain_confidence=domain_confidence,
        editing_regime=editing,
        generator=payload.get("generator"),
        human_population=str(payload.get("human_population", "unknown")),
        declared=dict(payload.get("declared", {})),
        cues=dict(payload.get("cues", {})),
        extraction_version=str(payload.get("extraction_version", EXTRACTION_VERSION)),
    )
