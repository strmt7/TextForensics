from __future__ import annotations

import pytest

# Test that rich_output can be imported and functions gracefully when Rich is not installed


def test_rich_output_import() -> None:
    """Test that rich_output module can be imported."""
    from textforensics import rich_output

    assert hasattr(rich_output, "HAS_RICH")
    assert hasattr(rich_output, "print_scan_results")
    assert hasattr(rich_output, "print_report_summary")
    assert hasattr(rich_output, "print_case_summary")
    assert hasattr(rich_output, "print_trust_map")
    assert hasattr(rich_output, "print_detector_health")
    assert hasattr(rich_output, "print_diff")
    assert hasattr(rich_output, "create_progress_bar")


def test_rich_output_functions_when_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that functions don't crash when Rich is not installed."""
    import textforensics.rich_output as ro

    # Force HAS_RICH to False
    monkeypatch.setattr(ro, "HAS_RICH", False)

    # These should all return None gracefully
    assert ro.print_scan_results({}) is None
    assert ro.print_report_summary({}) is None
    assert ro.print_case_summary({}) is None
    assert ro.print_trust_map({}) is None
    assert ro.print_detector_health([]) is None
    assert ro.print_diff("a", "b") is None
    assert ro.create_progress_bar() is None


def test_rich_output_scan_results_with_analysis_result() -> None:
    """Test print_scan_results with an AnalysisResult-like object."""
    from textforensics.rich_output import print_scan_results

    # Mock an AnalysisResult-like object with to_dict method
    class MockResult:
        def to_dict(self):
            return {
                "verdict": "human_like_patterns",
                "score": 0.3,
                "diagnostic_reliability": 0.85,
                "disagreement": 0.1,
                "robustness_stability": 0.95,
                "word_count": 150,
                "analyzers": [
                    {
                        "name": "analyzer1",
                        "score": 0.2,
                        "reliability": 0.9,
                        "verdict": "human_like",
                    },
                    {
                        "name": "analyzer2",
                        "score": 0.4,
                        "reliability": 0.8,
                        "verdict": "human_like",
                    },
                ],
                "warnings": ["Short text may reduce reliability"],
            }

    # This should not raise (or return None if Rich not available)
    result = print_scan_results(MockResult())
    assert result is None  # Returns None (or nothing useful without Rich)


def test_rich_output_scan_results_with_dict() -> None:
    """Test print_scan_results with a plain dict."""
    from textforensics.rich_output import print_scan_results

    data = {
        "verdict": "ai_like",
        "score": 0.7,
        "diagnostic_reliability": 0.6,
        "disagreement": 0.2,
        "robustness_stability": 0.8,
        "word_count": 300,
        "analyzers": [
            {"name": "detector1", "score": 0.8, "reliability": 0.7, "verdict": "ai_like"},
            {"name": "detector2", "score": 0.6, "reliability": 0.5, "verdict": "human_like"},
        ],
        "warnings": [],
    }

    result = print_scan_results(data)
    assert result is None


def test_rich_output_report_summary() -> None:
    """Test print_report_summary with a ForensicBundle-like dict."""
    from textforensics.rich_output import print_report_summary

    data = {
        "content_sha256": "abc123def456",
        "input": {"word_count": 250},
        "trust_map": {
            "overall": "mixed",
            "dimensions": [
                {
                    "dimension": "text_length",
                    "state": "supported",
                    "reason": "Text meets minimum length",
                },
                {
                    "dimension": "detector_diversity",
                    "state": "partial",
                    "reason": "Only one detector family",
                },
            ],
        },
        "verdict_integrity": {
            "grade": "B",
            "score": 0.75,
        },
        "consensus": {
            "family_agreement": 0.8,
            "family_count": 2,
        },
        "provenance": {"valid": True},
        "limitations": ["Text-only detection cannot prove authorship"],
    }

    result = print_report_summary(data)
    assert result is None


def test_rich_output_case_summary() -> None:
    """Test print_case_summary with a case file dict."""
    from textforensics.rich_output import print_case_summary

    case = {
        "schema": "textforensics.case-file/v1",
        "tool": {"name": "TextForensics", "version": "0.2.0"},
        "forensic_bundle": {
            "content_sha256": "abc123",
            "detector_results": [
                {"detector_id": "detector1", "verdict": "ai_like"},
                {"detector_id": "detector2", "verdict": "human_like"},
            ],
            "detector_failures": [],
            "trust_map": {"overall": "strong"},
            "provenance": {"valid": True},
            "limitations": ["Test limitation"],
        },
        "raw_text_included": False,
        "case_sha256": "casehash123",
    }

    result = print_case_summary(case)
    assert result is None


def test_rich_output_trust_map() -> None:
    """Test print_trust_map with a TrustMap-like dict."""
    from textforensics.rich_output import print_trust_map

    trust_map = {
        "overall": "mixed",
        "dimensions": [
            {"dimension": "language", "state": "unknown", "reason": "No language detection"},
            {"dimension": "text_length", "state": "supported", "reason": "Meets min words"},
            {"dimension": "detector_diversity", "state": "partial", "reason": "One family"},
            {"dimension": "benign_stability", "state": "unknown", "reason": "No robustness data"},
            {
                "dimension": "temporal_version_stability",
                "state": "unknown",
                "reason": "No drift data",
            },
        ],
    }

    result = print_trust_map(trust_map)
    assert result is None


def test_rich_output_detector_health() -> None:
    """Test print_detector_health with health list."""
    from textforensics.rich_output import print_detector_health

    health = [
        {
            "entry_point": "builtin",
            "status": "ok",
            "detector_id": "textforensics/builtin-heuristic",
            "error_type": None,
            "message": None,
        },
        {
            "entry_point": "plugin",
            "status": "error",
            "detector_id": "plugin1",
            "error_type": "ImportError",
            "message": "Failed to load",
        },
    ]

    result = print_detector_health(health)
    assert result is None


def test_rich_output_diff() -> None:
    """Test print_diff with two texts."""
    from textforensics.rich_output import print_diff

    text1 = "Hello world\nThis is a test"
    text2 = "Hello world\nThis is a changed test"

    result = print_diff(text1, text2, style="side_by_side")
    assert result is None

    result = print_diff(text1, text2, style="unified")
    assert result is None


def test_rich_output_create_progress_bar() -> None:
    """Test create_progress_bar returns a Progress object when Rich is available."""
    from textforensics.rich_output import HAS_RICH, create_progress_bar

    # Should return a Progress object when Rich is installed
    result = create_progress_bar()
    if HAS_RICH:
        assert result is not None
        from rich.progress import Progress

        assert isinstance(result, Progress)
    else:
        assert result is None


def test_cli_help_includes_rich_flag() -> None:
    """Test that CLI help includes --rich flags for relevant commands."""
    from textforensics.cli import build_parser

    parser = build_parser()

    # Find the subparsers action (it's the one with choices dict containing commands)
    subparsers_action = None
    for action in parser._subparsers._actions:
        if hasattr(action, "choices") and action.choices is not None and "scan" in action.choices:
            subparsers_action = action
            break

    assert subparsers_action is not None

    # Verify rich flag is added to scan
    scan_choices = subparsers_action.choices["scan"]
    rich_args = [a for a in scan_choices._actions if a.dest == "rich"]
    assert len(rich_args) == 1

    # Check report command
    report_choices = subparsers_action.choices["report"]
    rich_args = [a for a in report_choices._actions if a.dest == "rich"]
    assert len(rich_args) == 1

    # Check case export
    case_choices = subparsers_action.choices["case"]
    case_subparsers = None
    for action in case_choices._subparsers._actions:
        if hasattr(action, "choices") and action.choices is not None and "export" in action.choices:
            case_subparsers = action
            break
    assert case_subparsers is not None
    export_choices = case_subparsers.choices["export"]
    rich_args = [a for a in export_choices._actions if a.dest == "rich"]
    assert len(rich_args) == 1

    # Check drift report
    drift_choices = subparsers_action.choices["drift"]
    drift_subparsers = None
    for action in drift_choices._subparsers._actions:
        if hasattr(action, "choices") and action.choices is not None and "report" in action.choices:
            drift_subparsers = action
            break
    assert drift_subparsers is not None
    drift_report_choices = drift_subparsers.choices["report"]
    rich_args = [a for a in drift_report_choices._actions if a.dest == "rich"]
    assert len(rich_args) == 1

    # Check localize
    localize_choices = subparsers_action.choices["localize"]
    rich_args = [a for a in localize_choices._actions if a.dest == "rich"]
    assert len(rich_args) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
