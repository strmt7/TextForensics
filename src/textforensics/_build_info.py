"""Build identity information for TextForensics.

This module embeds build-time identity information following the rejection-rejector pattern:
- Source commit hash (verified via git)
- Dependencies hash (from requirements.lock or pyproject.toml)
- Contract info hashes (from docs/ and src/textforensics/schemas/)
- Python version
- API and schema version identifiers

The build info is embedded at build time and can be displayed via the CLI.

ENG-02 (W6): provenance precedence is (1) the embedded
_build_info.json written by setup.py at build time, (2) the sdist
provenance record captured at sdist time (for wheels built from an
sdist outside any Git worktree), (3) runtime computation bound to the
actual source root. Git queries are bound to the source root, never
the caller's cwd, and ``verify_build_identity`` fails closed: any
failed required identity check returns invalid, never valid.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

# These fields are populated at build time by the build system.
# During development, they fall back to computed/derived values.
BUILD_INFO: dict[str, Any] = {
    "source_commit": "",
    "source_commit_verified": False,
    "python_version": "",
    "dependencies_sha256": "",
    "api_version": "",
    "api_spec_sha256": "",
    "detector_adapter_api_sha256": "",
    "calibration_format_version": "",
    "benchmark_format_version": "",
    "contract_info": {},
    "provenance_status": "",
}

# Fields an embedded or sdist provenance record must carry to be trusted.
PROVENANCE_FIELDS = (
    "source_commit",
    "source_commit_verified",
    "dependencies_sha256",
    "contract_info",
)


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def _source_root(candidate: Path | None = None) -> Path | None:
    """The TextForensics source root for this module, or None.

    The source root is the directory containing both ``pyproject.toml``
    and ``src/textforensics/__init__.py``. For an editable/dev install
    that is the checkout root (derived from this file's location). For
    an installed wheel there is no source root — the package lives in
    site-packages, which must never be mistaken for a source tree, and
    Git must never be queried from there.
    """
    if candidate is None:
        candidate = Path(__file__).resolve().parent.parent.parent
    if (candidate / "pyproject.toml").is_file() and (
        candidate / "src" / "textforensics" / "__init__.py"
    ).is_file():
        return candidate
    return None


def _git_toplevel(source_root: Path) -> Path | None:
    """The top level of the git checkout containing source_root, or None."""
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


def _get_source_commit(source_root: Path | None = None) -> tuple[str, bool]:
    """Get the current git commit hash and verification status.

    Git queries are bound to the actual source root (never the caller's
    cwd): the checkout's top level must BE the source root, so a source
    tree copied inside an unrelated repository never inherits that
    repository's HEAD. A source root that is not itself a checkout top
    level yields "unknown".

    Returns:
        Tuple of (commit_hash, verified) where verified indicates
        whether the working directory is clean.
    """
    root = _source_root(source_root) if source_root is not None else _source_root()
    if root is None:
        return "unknown", False
    toplevel = _git_toplevel(root)
    if toplevel is None:
        return "unknown", False
    try:
        if toplevel.resolve() != root.resolve():
            return "unknown", False
    except OSError:
        return "unknown", False
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        commit = result.stdout.strip()

        # Check if working directory is clean
        result_status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        verified = result_status.stdout.strip() == ""

        return commit, verified
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return "unknown", False


def _compute_dependencies_hash(source_root: Path | None = None) -> str:
    """Compute SHA-256 hash of dependencies.

    Tries in order:
    1. requirements.lock (pinned dependencies)
    2. pyproject.toml [project] dependencies + [project.optional-dependencies]
    3. Falls back to "unavailable" if neither exists (including when
       there is no source root, e.g. an installed wheel).
    """
    root = _source_root(source_root) if source_root is not None else _source_root()
    if root is None:
        return "unavailable"

    # Try requirements.lock first
    lock_file = root / "requirements.lock"
    if lock_file.exists():
        return _sha256_file(lock_file)

    # Try pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        # Hash the entire pyproject.toml for simplicity
        # This includes dependencies and all other config
        return _sha256_bytes(content.encode("utf-8"))

    return "unavailable"


def _compute_contract_info(source_root: Path | None = None) -> dict[str, str]:
    """Compute hashes of contract/documentation files.

    Returns a dict with hashes of:
    - API spec (if exists)
    - Detector adapter API doc (if exists)
    - All schemas in src/textforensics/schemas/ (the single source)
    - engineering.toml (if exists)
    - AGENTS.md (development contract)

    Returns {} when there is no source root (e.g. an installed wheel):
    contract files are not shipped outside the schemas directory, so
    nothing verifiable can be computed at runtime.
    """
    root = _source_root(source_root) if source_root is not None else _source_root()
    if root is None:
        return {}
    contract_info: dict[str, str] = {}

    # Hash all schema files (packaged schemas are the single source)
    schemas_dir = root / "src" / "textforensics" / "schemas"

    if schemas_dir.exists():
        schema_hashes = {}
        for schema_file in sorted(schemas_dir.glob("*.json")):
            schema_hashes[schema_file.name] = _sha256_file(schema_file)
        # Compute aggregate hash of all schemas
        aggregate = hashlib.sha256()
        for name in sorted(schema_hashes.keys()):
            aggregate.update(name.encode("utf-8"))
            aggregate.update(schema_hashes[name].encode("utf-8"))
        contract_info["schemas_sha256"] = aggregate.hexdigest()
        contract_info["schema_files"] = json.dumps(schema_hashes, sort_keys=True)

    # Hash engineering.toml if exists
    engineering_toml = root / "engineering.toml"
    if engineering_toml.exists():
        contract_info["engineering_toml_sha256"] = _sha256_file(engineering_toml)

    # Hash AGENTS.md if exists
    agents_md = root / "AGENTS.md"
    if agents_md.exists():
        contract_info["agents_md_sha256"] = _sha256_file(agents_md)

    # Hash SPEC.md if exists (API spec)
    spec_md = root / "SPEC.md"
    if spec_md.exists():
        contract_info["spec_md_sha256"] = _sha256_file(spec_md)

    # Hash ARCHITECTURE.md if exists
    architecture_md = root / "ARCHITECTURE.md"
    if architecture_md.exists():
        contract_info["architecture_md_sha256"] = _sha256_file(architecture_md)

    return contract_info


def _get_api_version(source_root: Path | None = None) -> str:
    """Get the API version from the package."""
    try:
        from importlib.metadata import version

        return version("textforensics")
    except Exception:
        pass

    # Fallback: try to read from pyproject.toml
    root = _source_root(source_root) if source_root is not None else _source_root()
    if root is None:
        return "unknown"
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.startswith("version = "):
                return line.split("=", 1)[1].strip().strip("\"'")

    return "unknown"


def _get_format_versions(source_root: Path | None = None) -> tuple[str, str]:
    """Get calibration and benchmark format versions.

    These are derived from the schema versions.
    """
    # Default versions based on current schema design
    calibration_version = "1.0.0"
    benchmark_version = "1.0.0"

    # Try to read from engineering.toml if it specifies different versions
    root = _source_root(source_root) if source_root is not None else _source_root()
    if root is None:
        return calibration_version, benchmark_version
    engineering_toml = root / "engineering.toml"
    if engineering_toml.exists():
        content = engineering_toml.read_text(encoding="utf-8")
        # Look for schema version references
        for line in content.splitlines():
            if "calibration" in line.lower() and "schema" in line.lower():
                # Extract version if present
                pass
            if "benchmark" in line.lower() and "schema" in line.lower():
                # Extract version if present
                pass

    return calibration_version, benchmark_version


def _load_embedded_build_info() -> dict[str, Any] | None:
    """Load build info from embedded _build_info.json if present.

    This file is written by setup.py during the build process.
    Returns None if the file does not exist, is not valid JSON, or
    lacks the required provenance fields (a partial record is not
    trusted — the caller falls through to the next provenance source,
    which fails closed when nothing verifiable remains).
    """
    data: dict[str, Any] | None = None
    try:
        # Try to load from the package directory
        from importlib.resources import files

        resource = files("textforensics").joinpath("_build_info.json")
        if resource.is_file():
            data = json.loads(resource.read_text(encoding="utf-8"))
    except (ImportError, FileNotFoundError, OSError, json.JSONDecodeError):
        pass

    if data is None:
        # Fallback: try relative path
        base = Path(__file__).resolve().parent
        embedded_path = base / "_build_info.json"
        if embedded_path.exists():
            try:
                data = json.loads(embedded_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    if data is None or not isinstance(data, dict):
        return None
    if any(field not in data for field in PROVENANCE_FIELDS):
        return None
    return data


def _load_sdist_provenance(source_root: Path | None = None) -> dict[str, Any] | None:
    """Load the sdist provenance record, if present and well-formed.

    The record is written by the custom sdist command in setup.py and
    shipped inside the sdist, so a wheel built from the sdist outside
    any Git worktree can still prove which source tree it came from.
    Returns None for a missing, unreadable, or malformed record.
    """
    root = _source_root(source_root) if source_root is not None else _source_root()
    if root is None:
        return None
    path = root / "src" / "textforensics" / "_sdist_provenance.json"
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


def _apply_provenance(provenance: dict[str, Any], status: str) -> None:
    """Fill BUILD_INFO from a provenance record (embedded or sdist)."""
    global BUILD_INFO
    BUILD_INFO["source_commit"] = provenance.get("source_commit", "unknown")
    BUILD_INFO["source_commit_verified"] = provenance.get(
        "source_commit_verified", False
    )
    BUILD_INFO["dependencies_sha256"] = provenance.get(
        "dependencies_sha256", "unavailable"
    )
    contract_info = provenance.get("contract_info", {})
    BUILD_INFO["contract_info"] = contract_info
    BUILD_INFO["api_spec_sha256"] = provenance.get(
        "api_spec_sha256", contract_info.get("spec_md_sha256", "unavailable")
    )
    BUILD_INFO["detector_adapter_api_sha256"] = provenance.get(
        "detector_adapter_api_sha256",
        contract_info.get("engineering_toml_sha256", "unavailable"),
    )
    BUILD_INFO["provenance_status"] = provenance.get(
        "provenance_status", status
    )


def initialize_build_info() -> None:
    """Initialize the BUILD_INFO dict with current values.

    Provenance precedence (ENG-02):
    1. The embedded _build_info.json written by setup.py at build time.
    2. The sdist provenance record (wheels built from an sdist).
    3. Runtime computation bound to the actual source root.
    """
    global BUILD_INFO

    # Try to load embedded build info first
    embedded = _load_embedded_build_info()

    if embedded is not None:
        _apply_provenance(embedded, "embedded")
    else:
        sdist_provenance = _load_sdist_provenance()
        if sdist_provenance is not None:
            _apply_provenance(sdist_provenance, "sdist")
        else:
            # Runtime computation fallback
            commit, verified = _get_source_commit()
            BUILD_INFO["source_commit"] = commit
            BUILD_INFO["source_commit_verified"] = verified
            BUILD_INFO["dependencies_sha256"] = _compute_dependencies_hash()
            contract_info = _compute_contract_info()
            BUILD_INFO["contract_info"] = contract_info
            BUILD_INFO["api_spec_sha256"] = contract_info.get(
                "spec_md_sha256", "unavailable"
            )
            BUILD_INFO["detector_adapter_api_sha256"] = contract_info.get(
                "engineering_toml_sha256", "unavailable"
            )
            BUILD_INFO["provenance_status"] = "runtime"

    # Python version (always computed at runtime)
    BUILD_INFO["python_version"] = sys.version.split()[0]

    # API version
    BUILD_INFO["api_version"] = _get_api_version()

    # Format versions
    cal_version, bench_version = _get_format_versions()
    BUILD_INFO["calibration_format_version"] = cal_version
    BUILD_INFO["benchmark_format_version"] = bench_version


def get_build_info() -> dict[str, Any]:
    """Get the current build info.

    Returns:
        The BUILD_INFO dict with all build identity fields.
    """
    return BUILD_INFO.copy()


def get_build_info_json(indent: int = 2) -> str:
    """Get the build info as a JSON string.

    Args:
        indent: Number of spaces for JSON indentation.

    Returns:
        JSON string representation of BUILD_INFO.
    """
    return json.dumps(BUILD_INFO, indent=indent, sort_keys=True)


def verify_build_identity(expected_commit: str | None = None) -> dict[str, Any]:
    """Verify build identity against expected values.

    FAIL CLOSED (ENG-02): any failed required check sets valid=False.
    A build whose provenance is unknown, unverified, or missing its
    dependency/contract digests is invalid, never valid.

    Args:
        expected_commit: Optional expected source commit hash.

    Returns:
        Dict with verification results:
        - valid: bool indicating overall validity
        - checks: list of individual check results
        - errors: list of error messages if any
    """
    result: dict[str, Any] = {
        "valid": True,
        "checks": [],
        "errors": [],
    }

    def _fail(name: str, expected: Any, actual: Any, error: str) -> None:
        result["valid"] = False
        result["checks"].append(
            {
                "name": name,
                "expected": expected,
                "actual": actual,
                "passed": False,
            }
        )
        result["errors"].append(error)

    def _pass(name: str, expected: Any, actual: Any) -> None:
        result["checks"].append(
            {
                "name": name,
                "expected": expected,
                "actual": actual,
                "passed": True,
            }
        )

    # Check source commit is known (not "unknown" / empty)
    commit = BUILD_INFO["source_commit"]
    if not commit or commit == "unknown":
        _fail(
            "source_commit_known",
            "a known commit hash",
            commit,
            "Source commit is unknown: no verifiable provenance",
        )
    else:
        _pass("source_commit_known", "a known commit hash", commit)

    # Check source commit
    if expected_commit is not None:
        if commit != expected_commit:
            _fail(
                "source_commit",
                expected_commit,
                commit,
                f"Source commit mismatch: expected {expected_commit}, "
                f"got {commit}",
            )
        else:
            _pass("source_commit", expected_commit, commit)

    # Check commit verification
    if not BUILD_INFO["source_commit_verified"]:
        _fail(
            "source_commit_verified",
            True,
            BUILD_INFO["source_commit_verified"],
            "Working directory was not clean at build time",
        )
    else:
        _pass(
            "source_commit_verified",
            True,
            BUILD_INFO["source_commit_verified"],
        )

    # Check dependencies hash is available
    if BUILD_INFO["dependencies_sha256"] == "unavailable":
        _fail(
            "dependencies_sha256",
            "available",
            "unavailable",
            "Dependencies hash unavailable",
        )
    else:
        _pass(
            "dependencies_sha256",
            "available",
            BUILD_INFO["dependencies_sha256"][:16] + "...",
        )

    # Check contract info is present (provenance without contract
    # digests cannot prove which contracts the build embodies)
    if not BUILD_INFO["contract_info"]:
        _fail(
            "contract_info",
            "present",
            "empty",
            "Contract info unavailable: no contract digests recorded",
        )
    else:
        _pass("contract_info", "present", "present")

    return result


def get_version() -> str:
    """Return the installed package version without duplicating it in source code.

    Single source of version truth for the package (merged from
    version.py, Phase 2 wave e). Distinct from _get_api_version()
    above: no pyproject.toml fallback, and "0+unknown" (not "unknown")
    when the package metadata is missing.
    """
    try:
        return version("textforensics")
    except PackageNotFoundError:
        return "0+unknown"


# Initialize build info at module load time
initialize_build_info()


if __name__ == "__main__":
    # When run directly, print the build info
    print(get_build_info_json())
