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
