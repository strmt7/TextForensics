"""Setup script for TextForensics with build-time identity embedding.

This script extends the setuptools build process to embed build identity
information (source commit, dependency hashes, contract info) into the
installed package at build time, following the rejection-rejector pattern.

The build-time embedding ensures that installed packages carry their own
provenance without requiring git access at runtime.

ENG-02 (W6): provenance is captured immutably at sdist time and
preserved in wheels derived from the sdist, so a wheel built outside
any Git worktree still carries the source commit and contract digests
of the tree it came from. Git queries are bound to the actual source
root (never the caller's cwd), and a build with no verifiable
provenance records ``source_commit: "unknown"`` and fails closed at
verify time instead of claiming validity.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

# Fields every provenance record must carry. Records missing any of
# these are treated as absent (fail closed downstream).
PROVENANCE_FIELDS = (
    "source_commit",
    "source_commit_verified",
    "dependencies_sha256",
    "contract_info",
    "api_spec_sha256",
    "detector_adapter_api_sha256",
    "provenance_status",
)


def _source_root() -> Path:
    """The source tree this setup.py belongs to."""
    return Path(__file__).resolve().parent


def _git_toplevel(source_root: Path) -> Path | None:
    """The top level of the git checkout containing source_root, or None.

    Returns None when source_root is not inside a git checkout at all.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None
    return Path(result.stdout.strip())


def _get_source_commit(source_root: Path) -> tuple[str, bool]:
    """Get the current git commit hash and verification status.

    Git queries are bound to the source root: the checkout's top level
    must BE the source root, so a source tree copied inside an unrelated
    repository never inherits that repository's HEAD. A source root
    that is not itself a checkout top level yields "unknown".

    Returns:
        Tuple of (commit_hash, verified) where verified indicates
        whether the working directory is clean.
    """
    toplevel = _git_toplevel(source_root)
    if toplevel is None:
        return "unknown", False
    try:
        if toplevel.resolve() != source_root.resolve():
            return "unknown", False
    except OSError:
        return "unknown", False
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        commit = result.stdout.strip()

        result_status = subprocess.run(
            ["git", "-C", str(source_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        verified = result_status.stdout.strip() == ""

        return commit, verified
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return "unknown", False


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _compute_dependencies_hash(source_root: Path) -> str:
    """Compute SHA-256 hash of dependencies from pyproject.toml."""
    pyproject = source_root / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    return "unavailable"


def _compute_contract_info(source_root: Path) -> dict[str, str]:
    """Compute hashes of contract/documentation files."""
    contract_info: dict[str, str] = {}

    # Hash all schema files
    schemas_dir = source_root / "src" / "textforensics" / "schemas"
    if not schemas_dir.exists():
        schemas_dir = source_root / "schemas"

    if schemas_dir.exists():
        schema_hashes = {}
        for schema_file in sorted(schemas_dir.glob("*.json")):
            schema_hashes[schema_file.name] = _sha256_file(schema_file)

        aggregate = hashlib.sha256()
        for name in sorted(schema_hashes.keys()):
            aggregate.update(name.encode("utf-8"))
            aggregate.update(schema_hashes[name].encode("utf-8"))
        contract_info["schemas_sha256"] = aggregate.hexdigest()
        contract_info["schema_files"] = json.dumps(schema_hashes, sort_keys=True)

    for filename, key in (
        ("engineering.toml", "engineering_toml_sha256"),
        ("AGENTS.md", "agents_md_sha256"),
        ("SPEC.md", "spec_md_sha256"),
        ("ARCHITECTURE.md", "architecture_md_sha256"),
    ):
        path = source_root / filename
        if path.exists():
            contract_info[key] = _sha256_file(path)

    return contract_info


def _sdist_provenance_path(source_root: Path) -> Path:
    """Where the sdist provenance record lives in the source tree.

    The file is written by the sdist command, shipped inside the sdist
    (see MANIFEST.in), and gitignored — it is a build artifact, not a
    source file. Wheels built from the sdist read it back.
    """
    return source_root / "src" / "textforensics" / "_sdist_provenance.json"


def _load_sdist_provenance(source_root: Path) -> dict | None:
    """Load the sdist provenance record, if present and well-formed.

    Returns None for a missing, unreadable, or malformed record — the
    caller falls through to an "unknown" provenance, which fails closed
    at verify time.
    """
    path = _sdist_provenance_path(source_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if any(field not in data for field in PROVENANCE_FIELDS):
        return None
    if not isinstance(data["source_commit"], str):
        return None
    if not isinstance(data["contract_info"], dict):
        return None
    return data


def _capture_provenance(source_root: Path) -> dict:
    """Capture the immutable provenance record for this source tree.

    Preference order:
    1. Git, when the source root IS a checkout top level — the live
       commit, its clean-tree flag, and freshly computed digests.
    2. The sdist provenance record, when the tree was unpacked from an
       sdist (no .git) — the record captured at sdist time, unchanged.
    3. "unknown": no verifiable provenance. The record still carries
       whatever digests can be computed from the files present, but
       ``source_commit`` is "unknown" and ``source_commit_verified``
       is False, so verification fails closed.
    """
    source_commit, source_commit_verified = _get_source_commit(source_root)
    if source_commit != "unknown":
        contract_info = _compute_contract_info(source_root)
        return {
            "source_commit": source_commit,
            "source_commit_verified": source_commit_verified,
            "dependencies_sha256": _compute_dependencies_hash(source_root),
            "contract_info": contract_info,
            "api_spec_sha256": contract_info.get("spec_md_sha256", "unavailable"),
            "detector_adapter_api_sha256": contract_info.get(
                "engineering_toml_sha256", "unavailable"
            ),
            "provenance_status": "git",
            "embedded_at": "build_time",
        }

    inherited = _load_sdist_provenance(source_root)
    if inherited is not None:
        return dict(inherited)

    contract_info = _compute_contract_info(source_root)
    return {
        "source_commit": "unknown",
        "source_commit_verified": False,
        "dependencies_sha256": _compute_dependencies_hash(source_root),
        "contract_info": contract_info,
        "api_spec_sha256": contract_info.get("spec_md_sha256", "unavailable"),
        "detector_adapter_api_sha256": contract_info.get(
            "engineering_toml_sha256", "unavailable"
        ),
        "provenance_status": "unknown",
        "embedded_at": "build_time",
    }


def _write_sdist_provenance(source_root: Path, provenance: dict) -> Path:
    """Write the provenance record into the source tree for the sdist."""
    output_path = _sdist_provenance_path(source_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


class SdistWithProvenance(sdist):
    """Custom sdist command that captures provenance into the sdist.

    The provenance record is written into the source tree before the
    sdist file list is computed, so MANIFEST.in picks it up and the
    tarball carries it. Wheels built from the sdist inherit it via
    ``_capture_provenance`` in the build_py step.
    """

    def run(self) -> None:
        """Run the sdist build, capturing provenance first."""
        source_root = _source_root()
        provenance = _capture_provenance(source_root)
        output_path = _write_sdist_provenance(source_root, provenance)
        print(f"Captured sdist provenance: {output_path} "
              f"(status={provenance['provenance_status']}, "
              f"commit={provenance['source_commit']})")
        super().run()

    def make_release_tree(self, base_dir, files) -> None:
        """Build the release tree with deterministic mtimes.

        setuptools does not honor SOURCE_DATE_EPOCH for sdist tar
        entries: files generated during the build carry "now" mtimes,
        so two builds seconds apart produce different sdists even
        though every member's content is identical. Two such files —
        PKG-INFO and setup.cfg — are written INTO the release tree by
        setuptools itself (not part of the file list), and the tree's
        directories also carry "now" mtimes, so normalizing the file
        list alone is not enough. When SOURCE_DATE_EPOCH is set, pin
        every entry under the release tree (files and directories) to
        it before the tree is tarred. This normalizes the build's
        inputs (the standard reproducible-build practice); it does
        not doctor the artifact afterwards, and it touches only the
        release-tree copies, never the source tree.
        """
        super().make_release_tree(base_dir, files)
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if not epoch:
            return
        try:
            epoch_int = int(epoch)
        except ValueError:
            return
        if epoch_int <= 0:
            return
        for dirpath, dirnames, filenames in os.walk(base_dir):
            for name in filenames:
                try:
                    os.utime(os.path.join(dirpath, name), (epoch_int, epoch_int))
                except OSError:
                    pass
            for name in dirnames:
                try:
                    os.utime(os.path.join(dirpath, name), (epoch_int, epoch_int))
                except OSError:
                    pass
        try:
            os.utime(base_dir, (epoch_int, epoch_int))
        except OSError:
            pass


class BuildPyWithBuildInfo(build_py):
    """Custom build_py command that embeds build identity information.

    This command runs before the standard build_py to generate a
    _build_info.json file containing the source commit, dependency hash,
    and contract info. The _build_info.py module reads this file at
    runtime to provide build identity without requiring git access.
    """

    def run(self) -> None:
        """Run the build, embedding build identity first."""
        self._embed_build_info()
        super().run()

    def _embed_build_info(self) -> None:
        """Write build identity information to a JSON file."""
        source_root = _source_root()
        provenance = _capture_provenance(source_root)

        # Write to the package directory
        package_dir = Path(self.build_lib) / "textforensics" if self.build_lib else None
        if package_dir is None:
            # Fallback: write to source directory
            package_dir = source_root / "src" / "textforensics"

        package_dir.mkdir(parents=True, exist_ok=True)
        output_path = package_dir / "_build_info.json"
        output_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Embedded build info: {output_path}")


setup(
    cmdclass={"build_py": BuildPyWithBuildInfo, "sdist": SdistWithProvenance},
)
