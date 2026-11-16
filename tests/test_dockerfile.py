"""W7 Worker D regression tests: Dockerfile pip pinning (Scorecard #294).

Scorecard Pinned-Dependencies flags any ``pip install`` of a named
package with only a version pin ("pipCommand not pinned by hash"):
the runtime stage used to install ``textforensics[api]==0.2.0`` from
the locally built wheels, which has no remote hash to pin. The fix
installs the locally built wheels by file glob with ``--no-deps``
(the builder stage already produced every dependency wheel in
``/wheels``), which Scorecard treats as pinned (verified locally:
Pinned-Dependencies 9 -> 10, 71/71 pipCommand pinned).

These tests pin the Dockerfile's install shape so the finding cannot
 silently come back: every ``pip install`` line must be either
hash-verified (``--require-hashes``) or a local-wheel install
(``--no-deps`` with a ``.whl`` path/glob), and both base images must
stay digest-pinned.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"

_SHA256 = re.compile(r"@sha256:[0-9a-f]{64}\b")


def _run_lines() -> list[str]:
    lines = []
    for raw in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        lines.append(line)
    return lines


def test_base_images_digest_pinned():
    from_lines = [ln for ln in _run_lines() if ln.startswith("FROM ")]
    assert len(from_lines) == 2, f"expected 2 FROM lines, got {from_lines}"
    for line in from_lines:
        assert _SHA256.search(line), f"base image not digest-pinned: {line}"


def test_runtime_install_is_local_wheels_no_deps():
    # Non-comment lines only: the comment above the RUN legitimately
    # names the old specifier it documents replacing.
    run_text = " ".join(_run_lines())
    assert "textforensics[api]==" not in run_text, (
        "named textforensics[api]== specifier is back (Scorecard #294)"
    )
    assert "--no-index --no-deps /wheels/*.whl" in run_text, (
        "runtime stage must install the locally built wheels by file glob"
    )


def test_every_pip_install_is_hash_verified_or_local_wheel():
    joined = " ".join(_run_lines())
    for match in re.finditer(r"pip install ([^&|;]+)", joined):
        cmd = match.group(1)
        hash_verified = "--require-hashes" in cmd
        local_wheel = "--no-deps" in cmd and ".whl" in cmd
        assert hash_verified or local_wheel, (
            f"pip install is neither hash-verified nor a local wheel: {cmd!r}"
        )


# ── W10 Worker D: builder-stage dependency lockfile (Scorecard #294) ──
# The builder stage used to resolve the `textforensics[api]` closure from
# PyPI with only the pyproject version ranges, so a rebuild could silently
# pick up newer dependency releases. It now builds the dependency wheels
# from `requirements-container-hashed.txt` with `--require-hashes`, and
# builds the local package wheel separately with `--no-deps` (no index
# access for dependencies). These tests pin that shape and the lockfile's
# drift guard: every container pin must exist in `requirements-pinned.txt`
# at the same version (the tested closure), so a pinned bump without a
# container-lockfile regeneration fails loudly here instead of shipping a
# stale image.

_CONTAINER_LOCKFILE = REPO_ROOT / "requirements-container-hashed.txt"
_PINNED = REPO_ROOT / "requirements-pinned.txt"

_PIN_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;\\#]+)")
_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")


def _lockfile_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in _CONTAINER_LOCKFILE.read_text(encoding="utf-8").splitlines():
        match = _PIN_RE.match(line.strip())
        if match:
            pins[match.group(1).lower().replace("-", "_")] = match.group(2)
    return pins


def _pinned_versions() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in _PINNED.read_text(encoding="utf-8").splitlines():
        match = _PIN_RE.match(line.strip())
        if match:
            pins[match.group(1).lower().replace("-", "_")] = match.group(2)
    return pins


def test_builder_deps_use_hash_pinned_lockfile():
    joined = " ".join(_run_lines())
    assert "--require-hashes -r requirements-container-hashed.txt" in joined, (
        "builder stage must build dependency wheels from the hash-pinned "
        "container lockfile (Scorecard #294)"
    )
    assert _CONTAINER_LOCKFILE.is_file(), "container lockfile is missing"
    # The local package wheel is built separately with --no-deps so the
    # `.[api]` build performs no index dependency resolution.
    assert '--wheel-dir /wheels --no-deps ".[api]"' in joined, (
        "local package wheel must be built with --no-deps, separately from "
        "the hash-pinned dependency build"
    )


def _logical_lines() -> list[str]:
    """Dockerfile lines with backslash continuations joined, comments dropped."""
    logical: list[str] = []
    current = ""
    for raw in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
        else:
            current += line
            logical.append(current)
            current = ""
    if current:
        logical.append(current)
    return logical


def test_every_pip_wheel_is_hash_verified_or_local_only():
    for line in _logical_lines():
        if "pip wheel" not in line:
            continue
        cmd = line.split("pip wheel", 1)[1]
        hash_verified = "--require-hashes" in cmd
        local_only = "--no-deps" in cmd and '".[api]"' in cmd
        assert hash_verified or local_only, (
            f"pip wheel is neither hash-verified nor a local-only build: {cmd!r}"
        )


def test_container_lockfile_every_entry_hash_pinned():
    text = _CONTAINER_LOCKFILE.read_text(encoding="utf-8")
    assert "NO HASHES" not in text, "container lockfile has a package without hashes"
    pins = _lockfile_pins()
    assert len(pins) == 17, f"expected the 17-package api closure, got {len(pins)}"
    # Every entry block (pin line + its continuation lines) must carry at
    # least one sha256 hash — a bare `name==version` line would install
    # unverified under --require-hashes and fail the build loudly, but
    # the test pins the invariant so the failure is caught here, not in CI.
    lines = text.splitlines()
    entry_starts = [i for i, ln in enumerate(lines) if _PIN_RE.match(ln.strip())]
    assert len(entry_starts) == 17
    for idx, start in enumerate(entry_starts):
        end = entry_starts[idx + 1] if idx + 1 < len(entry_starts) else len(lines)
        block = "\n".join(lines[start:end])
        assert _HASH_RE.search(block), (
            f"container lockfile entry has no sha256 hash: {lines[start].strip()}"
        )


def test_container_lockfile_matches_pinned_closure():
    pins = _lockfile_pins()
    pinned = _pinned_versions()
    # The four direct api dependencies (pyproject [project.optional-dependencies] api).
    for direct in ("fastapi", "jinja2", "uvicorn", "websockets"):
        assert direct in pins, f"direct api dep {direct} missing from container lockfile"
    for name, version in sorted(pins.items()):
        assert name in pinned, (
            f"container lockfile pins {name}=={version} which is not in "
            "requirements-pinned.txt — regenerate the lockfile from the pinned file"
        )
        assert pinned[name] == version, (
            f"container lockfile pins {name}=={version} but "
            f"requirements-pinned.txt has {name}=={pinned[name]} — "
            "regenerate the container lockfile in the same commit"
        )
