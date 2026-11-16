"""W7 Worker D regression tests: CodeQL py/tarslip (alerts #295-#299).

Every tar extraction site in the repo must pass ``filter="data"``
(PEP 706): ``scripts/check_reproducibility.py`` (own ``git archive``
output), ``scripts/verify_release.py`` (pre-existing precedent) and
``tests/test_audit_w6_b_build_identity.py`` (built sdist). The AST
guard pins the call sites; the containment test proves what the filter
guarantees for a hostile member (a ``../`` escape is refused, a normal
member still extracts). The containment test exercises the stdlib
filter itself — the guard is what ties it to our code.
"""

from __future__ import annotations

import ast
import io
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

EXTRACTION_SITES = (
    REPO_ROOT / "scripts" / "check_reproducibility.py",
    REPO_ROOT / "scripts" / "verify_release.py",
    REPO_ROOT / "tests" / "test_audit_w6_b_build_identity.py",
)


def _extractall_calls(path: Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "extractall"
        ):
            calls.append(node)
    return calls


def test_every_extractall_passes_filter_data():
    for site in EXTRACTION_SITES:
        calls = _extractall_calls(site)
        assert calls, f"no extractall call found in {site} (guard is stale)"
        for call in calls:
            filters = [kw for kw in call.keywords if kw.arg == "filter"]
            assert len(filters) == 1, f"{site}:{call.lineno}: extractall must pass filter="
            value = filters[0].value
            assert isinstance(value, ast.Constant) and value.value == "data", (
                f'{site}:{call.lineno}: filter must be the literal "data"'
            )


def _make_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def test_data_filter_refuses_parent_escape(tmp_path: Path):
    tar_path = tmp_path / "hostile.tar"
    # Benign member first: the hostile member aborts the extraction, so
    # the benign one must precede it for the "still extracts" assertion.
    _make_tar(tar_path, {"ok.txt": b"ok", "../escape.txt": b"escape"})
    dest = tmp_path / "dest"
    dest.mkdir()
    with tarfile.open(tar_path) as archive:
        try:
            archive.extractall(dest, filter="data")
        except (tarfile.OutsideDestinationError, tarfile.TarError):
            pass
    assert not (tmp_path / "escape.txt").exists()
    assert not (dest.parent / "escape.txt").exists()
    assert (dest / "ok.txt").read_bytes() == b"ok"
