"""W5 Worker F kill tests for observatory (audit-w5-f).

Kill evidence for the seven runtime survivors in textforensics.observatory:

* ``DriftObservatory.save_snapshots`` (line 1181):
  ``json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)``.
  Byte-exact assertions kill indent 2->3 / 2->1 and ensure_ascii
  False->True (a non-ASCII snapshot value must stay raw UTF-8); a NaN
  payload must raise ValueError, killing allow_nan False->True.
* ``DetectorHealthReport.save`` (line 1968):
  ``json.dumps(self.to_dict(), indent=2, ensure_ascii=False)``.
  Byte-exact assertions kill indent 2->3 / 2->1 and ensure_ascii
  False->True (non-ASCII metadata must stay raw UTF-8).
"""

import json
from pathlib import Path

import pytest

from textforensics.observatory import (
    DetectorHealthReport,
    DriftObservatory,
    HealthState,
)


def test_save_snapshots_is_byte_exact_utf8(tmp_path: Path):
    """save_snapshots writes 2-space indented raw-UTF-8 JSON + newline."""
    obs = DriftObservatory()
    obs.snapshots = [{"sample_id": "s1", "note": "caf\xe9", "score": 0.5}]
    path = tmp_path / "snapshots.json"
    obs.save_snapshots(path)
    payload = {"schema": "textforensics.drift-snapshot-store/v1", "snapshots": obs.snapshots}
    expected = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    raw = path.read_bytes()
    assert raw == expected.encode("utf-8")
    assert "caf\xe9".encode() in raw
    assert b"\\u00e9" not in raw
    assert b'\n  "schema"' in raw


def test_save_snapshots_rejects_nan_payload(tmp_path: Path):
    """save_snapshots raises on a NaN value instead of writing 'NaN'."""
    obs = DriftObservatory()
    obs.snapshots = [{"sample_id": "s1", "score": float("nan")}]
    with pytest.raises(ValueError):
        obs.save_snapshots(tmp_path / "snapshots.json")


def test_health_report_save_is_byte_exact_utf8(tmp_path: Path):
    """DetectorHealthReport.save writes 2-space indented raw-UTF-8 JSON."""
    report = DetectorHealthReport(
        detector_id="det",
        overall_state=HealthState.HEALTHY,
        health_score=0.9,
        last_updated="2026-11-15T00:00:00Z",
        metadata={"note": "caf\xe9"},
    )
    path = tmp_path / "health.json"
    assert report.save(path) is True
    expected = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    raw = path.read_bytes()
    assert raw == expected.encode("utf-8")
    assert "caf\xe9".encode() in raw
    assert b"\\u00e9" not in raw
    assert b'\n  "detector_id"' in raw
