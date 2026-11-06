"""Bright-line test: adversarial.py is detection-only, forever.

This module detects text that has been processed by AI humanizers. It must
never emit rewrite suggestions, "humanization" advice, paraphrases, or any
text intended to evade detection (AGENTS.md rule 23: editing assistance must
not promise "undetectability" or optimize solely for detector evasion).

The line this test draws, in four independent checks:

1. No public entry point returns text. Every entry point returns a report,
   a summary dict, or a list of findings — never a ``str`` that could be
   pasted back as a replacement for the input.
2. No rewrite/evasion vocabulary appears anywhere in the outputs — neither
   in dict keys nor in string values.
3. No output string is a rewritten copy of the input. Every long string in
   the output is either a verbatim quote of the input (the ``segment``
   field, truncated with an ellipsis) or module-fixed wording / hashes that
   look nothing like the input.
4. The public API has no evasion-named function. Adding one (``suggest_*``,
   ``rewrite_*``, ``humanize_*``, ...) fails this test on purpose: such a
   feature needs an explicit decision, not a quiet addition.

"humanization" is deliberately NOT a forbidden word: it is the module's
subject matter (detection *of* humanization) and appears in fixed
limitation strings. The forbidden words are the *action* words — rewrite,
paraphrase, evade, bypass, suggest, recommend — which only a feature that
tells the user how to change their text would emit.
"""

from __future__ import annotations

import inspect
import unittest
from difflib import SequenceMatcher
from typing import Any

import textforensics.adversarial as adversarial
from textforensics.adversarial import (
    AdversarialDetector,
    HumanizationPatternLibrary,
    detect_deliberate_typos,
    detect_discourse_overload,
    detect_forced_contractions,
    detect_hedge_overload,
    detect_humanization,
    detect_humanization_simple,
    detect_mechanical_transitions,
    detect_mechanical_variation,
    detect_perplexity_anomalies,
    detect_regex_artifacts,
)

HUMAN_CLEAN = (
    "I ran the experiment twice this morning. The first result looked odd, "
    "so I checked the cables, repeated the measurement, and wrote down the "
    "second result. The numbers agreed within the expected range, and I "
    "noted the remaining uncertainty in the lab book for next week."
)

HUMANIZED_HEAVY = (
    "Furthermore, this is teh most robust solution. And it is gonna change "
    "everything, frankly. It is sort of amazing, kinda sorta. Additionally, "
    "moreover, therefore the results are definately recieveing attention. "
    "But the system is quite literally the best, honestly, basically "
    "essentially. Thier approach occured to me yesterday, and I gotta say "
    "it was a real eye-opener, wanna see it again."
)

AI_FORMAL = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential of an ever-evolving landscape. "
    "Moreover, the framework additionally provides a comprehensive "
    "methodology. Consequently, stakeholders can leverage these insights "
    "to drive transformative outcomes across diverse domains."
)

LONG_TEXT = (
    "The committee met on Tuesday to review the proposal. The first speaker "
    "outlined the budget, the second described the timeline, and the third "
    "summarized the risks. After a long discussion about staffing and "
    "equipment, the members agreed to proceed in stages, with a review after "
    "each stage. The minutes record the decision and the dissenting view "
    "that the schedule was optimistic. A follow-up meeting was set for the "
    "following month to check progress against the agreed milestones."
)

SHORT_TEXT = "hi there"

INPUTS = [HUMAN_CLEAN, HUMANIZED_HEAVY, AI_FORMAL, LONG_TEXT, SHORT_TEXT]

_DETECTORS = (
    detect_regex_artifacts,
    detect_mechanical_variation,
    detect_mechanical_transitions,
    detect_deliberate_typos,
    detect_forced_contractions,
    detect_discourse_overload,
    detect_hedge_overload,
    detect_perplexity_anomalies,
)

# Words that only a rewrite/evasion feature would emit (checked against
# both dict keys and string values, case-insensitively).
_FORBIDDEN_KEY_TOKENS = (
    "rewrite",
    "rewritten",
    "suggest",
    "paraphras",
    "evad",
    "bypass",
    "undetectab",
    "recommend",
    "advice",
    "revised",
    "edited_text",
    "alternative_text",
    "replacement",
)

_FORBIDDEN_VALUE_PHRASES = (
    "rewrite",
    "rewritten",
    "rephrase",
    "paraphrase",
    "evade",
    "evasion",
    "bypass",
    "undetectable",
    "undetectability",
    "suggestion",
    "suggested",
    "recommend",
    "advice",
    "try writing",
    "consider changing",
    "make it sound",
    "to avoid detection",
    "sound more human",
)

# Forbidden tokens in public function/class names.
_FORBIDDEN_NAME_TOKENS = (
    "rewrite",
    "paraphras",
    "evad",
    "bypass",
    "undetectab",
    "suggest",
    "recommend",
    "rephras",
)

# Only strings at least this long can be a rewritten passage; shorter
# strings are labels, severities, hashes, or ids.
_MIN_REWRITE_LENGTH = 40

# A rewritten passage is near-identical to the input without being a
# verbatim quote of it. Fixed wording and hashes score far below this.
_NEAR_COPY_RATIO = 0.9


def _all_outputs(text: str) -> list[Any]:
    """Collect every output the module produces for one input."""
    detector = AdversarialDetector()
    library = HumanizationPatternLibrary()
    outputs: list[Any] = [
        detect_humanization(text).to_dict(),
        detect_humanization_simple(text),
        detector.analyze(text).to_dict(),
        [finding.to_dict() for finding in library.run_all(text)],
    ]
    for detect in _DETECTORS:
        outputs.append([finding.to_dict() for finding in detect(text)])
    return outputs


def _string_leaves(value: Any) -> list[str]:
    """Every string leaf in a nested output structure (keys and values)."""
    leaves: list[str] = []
    if isinstance(value, str):
        leaves.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            leaves.append(str(key))
            leaves.extend(_string_leaves(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            leaves.extend(_string_leaves(item))
    return leaves


def _findings_for(text: str) -> list[Any]:
    """All finding objects (not dicts) the module produces for one input."""
    findings: list[Any] = []
    findings.extend(detect_humanization(text).findings)
    findings.extend(AdversarialDetector().analyze(text).findings)
    findings.extend(HumanizationPatternLibrary().run_all(text))
    for detect in _DETECTORS:
        findings.extend(detect(text))
    return findings


class AdversarialBrightLineTests(unittest.TestCase):
    """Tests proving adversarial.py never emits rewrite suggestions."""

    def test_no_entry_point_returns_text(self):
        """Test that no public entry point returns a str."""
        for text in INPUTS:
            self.assertNotIsInstance(detect_humanization(text), str)
            self.assertIsInstance(detect_humanization_simple(text), dict)
            self.assertNotIsInstance(AdversarialDetector().analyze(text), str)
            self.assertIsInstance(HumanizationPatternLibrary().run_all(text), list)
            for detect in _DETECTORS:
                result = detect(text)
                self.assertIsInstance(result, list, detect.__name__)
                self.assertNotIsInstance(result, str, detect.__name__)

    def test_no_rewrite_vocabulary_anywhere(self):
        """Test that outputs contain no rewrite/evasion words at all."""
        for text in INPUTS:
            for output in _all_outputs(text):
                for leaf in _string_leaves(output):
                    lowered = leaf.lower()
                    for token in _FORBIDDEN_VALUE_PHRASES:
                        self.assertNotIn(
                            token,
                            lowered,
                            f"output contains evasion phrase {token!r}: {leaf!r}",
                        )
                if isinstance(output, dict):
                    for key in output:
                        for token in _FORBIDDEN_KEY_TOKENS:
                            self.assertNotIn(
                                token,
                                str(key).lower(),
                                f"output key contains evasion token {token!r}: {key!r}",
                            )

    def test_no_output_string_is_rewritten_input(self):
        """Test that no long output string is a rewritten copy of the input.

        A verbatim quote (the ``segment`` field, truncated with "...") is
        allowed; module-fixed wording and hashes are nothing like the input.
        A rewritten passage would be near-identical to the input without
        being a verbatim quote of it — exactly what this rejects.
        """
        for text in INPUTS:
            if len(text) < _MIN_REWRITE_LENGTH:
                continue
            for output in _all_outputs(text):
                for leaf in _string_leaves(output):
                    if len(leaf) < _MIN_REWRITE_LENGTH:
                        continue
                    # A trailing ellipsis marks truncation of a verbatim quote.
                    core = leaf[:-3] if leaf.endswith("...") else leaf
                    if core in text:
                        continue
                    ratio = SequenceMatcher(None, core, text).ratio()
                    self.assertLess(
                        ratio,
                        _NEAR_COPY_RATIO,
                        f"output string looks like a rewritten copy of the input "
                        f"(ratio {ratio:.2f}): {leaf!r}",
                    )

    def test_findings_quote_only_verbatim_evidence(self):
        """Test that findings quote the input verbatim and carry no text.

        ``segment`` is either the literal "full_text" or a verbatim prefix
        of the input; ``evidence`` is a number (a count or a statistic),
        never replacement text.
        """
        for text in INPUTS:
            for finding in _findings_for(text):
                self.assertIsInstance(finding.evidence, (int, float))
                segment = finding.segment
                if segment == "full_text":
                    continue
                core = segment[:-3] if segment.endswith("...") else segment
                self.assertTrue(
                    text.startswith(core) or core in text,
                    f"finding segment is not a verbatim quote: {segment!r}",
                )

    def test_public_api_has_no_evasion_verbs(self):
        """Test that no public name in the module suggests rewriting.

        Adding a ``suggest_*`` / ``rewrite_*`` / ``humanize_*`` function
        fails this test on purpose: evasion output needs an explicit
        decision, not a quiet addition.
        """
        names = set(adversarial.__all__)
        names.update(
            name
            for name, obj in vars(adversarial).items()
            if not name.startswith("_") and (inspect.isfunction(obj) or inspect.isclass(obj))
        )
        for name in sorted(names):
            for token in _FORBIDDEN_NAME_TOKENS:
                self.assertNotIn(
                    token,
                    name.lower(),
                    f"public API name {name!r} contains evasion token {token!r}",
                )


if __name__ == "__main__":
    unittest.main()
