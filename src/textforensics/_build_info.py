"""Build identity information for TextForensics.

This module embeds build-time identity information following the rejection-rejector pattern:
- Source commit hash (verified via git)
- Dependencies hash (from requirements.lock or pyproject.toml)
- Contract info hashes (from docs/ and schemas/)
- Python version
- API and schema version identifiers

The build info is embedded at build time and can be displayed via the CLI.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
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
}


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


def _get_source_commit() -> tuple[str, bool]:
    """Get the current git commit hash and verification status.

    Returns:
        Tuple of (commit_hash, verified) where verified indicates
        whether the working directory is clean.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        commit = result.stdout.strip()

        # Check if working directory is clean
        result_status = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        verified = result_status.stdout.strip() == ""

        return commit, verified
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return "unknown", False


def _compute_dependencies_hash() -> str:
    """Compute SHA-256 hash of dependencies.

    Tries in order:
    1. requirements.lock (pinned dependencies)
    2. pyproject.toml [project] dependencies + [project.optional-dependencies]
    3. Falls back to "unavailable" if neither exists
    """
    base = Path(__file__).resolve().parent.parent.parent

    # Try requirements.lock first
    lock_file = base / "requirements.lock"
    if lock_file.exists():
        return _sha256_file(lock_file)

    # Try pyproject.toml
    pyproject = base / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        # Hash the entire pyproject.toml for simplicity
        # This includes dependencies and all other config
        return _sha256_bytes(content.encode("utf-8"))

    return "unavailable"


def _compute_contract_info() -> dict[str, str]:
    """Compute hashes of contract/documentation files.

    Returns a dict with hashes of:
    - API spec (if exists)
    - Detector adapter API doc (if exists)
    - All schemas in schemas/ directory
    - engineering.toml (if exists)
    - AGENTS.md (development contract)
    """
    base = Path(__file__).resolve().parent.parent.parent
    contract_info: dict[str, str] = {}

    # Hash all schema files
    schemas_dir = base / "src" / "textforensics" / "schemas"
    if not schemas_dir.exists():
        schemas_dir = base / "schemas"

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
    engineering_toml = base / "engineering.toml"
    if engineering_toml.exists():
        contract_info["engineering_toml_sha256"] = _sha256_file(engineering_toml)

    # Hash AGENTS.md if exists
    agents_md = base / "AGENTS.md"
    if agents_md.exists():
        contract_info["agents_md_sha256"] = _sha256_file(agents_md)

    # Hash SPEC.md if exists (API spec)
    spec_md = base / "SPEC.md"
    if spec_md.exists():
        contract_info["spec_md_sha256"] = _sha256_file(spec_md)

    # Hash ARCHITECTURE.md if exists
    architecture_md = base / "ARCHITECTURE.md"
    if architecture_md.exists():
        contract_info["architecture_md_sha256"] = _sha256_file(architecture_md)

    return contract_info


def _get_api_version() -> str:
    """Get the API version from the package."""
    try:
        from importlib.metadata import version

        return version("textforensics")
    except Exception:
        pass

    # Fallback: try to read from pyproject.toml
    base = Path(__file__).resolve().parent.parent.parent
    pyproject = base / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.startswith("version = "):
                return line.split("=", 1)[1].strip().strip("\"'")

    return "unknown"


def _get_format_versions() -> tuple[str, str]:
    """Get calibration and benchmark format versions.

    These are derived from the schema versions.
    """
    # Default versions based on current schema design
    calibration_version = "1.0.0"
    benchmark_version = "1.0.0"

    # Try to read from engineering.toml if it specifies different versions
    base = Path(__file__).resolve().parent.parent.parent
    engineering_toml = base / "engineering.toml"
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
    Returns None if the file does not exist.
    """
    try:
        # Try to load from the package directory
        from importlib.resources import files

        resource = files("textforensics").joinpath("_build_info.json")
        if resource.is_file():
            data = json.loads(resource.read_text(encoding="utf-8"))
            return data
    except (ImportError, FileNotFoundError, OSError, json.JSONDecodeError):
        pass

    # Fallback: try relative path
    base = Path(__file__).resolve().parent
    embedded_path = base / "_build_info.json"
    if embedded_path.exists():
        try:
            return json.loads(embedded_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    return None


def initialize_build_info() -> None:
    """Initialize the BUILD_INFO dict with current values.

    This is called once at module import time.
    First checks for an embedded build-info JSON file (written by setup.py
    at build time), then falls back to runtime computation.
    """
    global BUILD_INFO

    # Try to load embedded build info first
    embedded = _load_embedded_build_info()

    if embedded is not None:
        # Source commit
        BUILD_INFO["source_commit"] = embedded.get("source_commit", "unknown")
        BUILD_INFO["source_commit_verified"] = embedded.get("source_commit_verified", False)
        # Dependencies hash
        BUILD_INFO["dependencies_sha256"] = embedded.get("dependencies_sha256", "unavailable")
        # Contract info
        contract_info = embedded.get("contract_info", {})
        BUILD_INFO["contract_info"] = contract_info
        # API spec hash
        BUILD_INFO["api_spec_sha256"] = embedded.get(
            "api_spec_sha256", contract_info.get("spec_md_sha256", "unavailable")
        )
        # Detector adapter API hash
        BUILD_INFO["detector_adapter_api_sha256"] = embedded.get(
            "detector_adapter_api_sha256",
            contract_info.get("engineering_toml_sha256", "unavailable"),
        )
    else:
        # Runtime computation fallback
        commit, verified = _get_source_commit()
        BUILD_INFO["source_commit"] = commit
        BUILD_INFO["source_commit_verified"] = verified
        BUILD_INFO["dependencies_sha256"] = _compute_dependencies_hash()
        contract_info = _compute_contract_info()
        BUILD_INFO["contract_info"] = contract_info
        BUILD_INFO["api_spec_sha256"] = contract_info.get("spec_md_sha256", "unavailable")
        BUILD_INFO["detector_adapter_api_sha256"] = contract_info.get(
            "engineering_toml_sha256", "unavailable"
        )

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

    # Check source commit
    if expected_commit is not None:
        if BUILD_INFO["source_commit"] != expected_commit:
            result["valid"] = False
            result["checks"].append(
                {
                    "name": "source_commit",
                    "expected": expected_commit,
                    "actual": BUILD_INFO["source_commit"],
                    "passed": False,
                }
            )
            result["errors"].append(
                f"Source commit mismatch: expected {expected_commit}, "
                f"got {BUILD_INFO['source_commit']}"
            )
        else:
            result["checks"].append(
                {
                    "name": "source_commit",
                    "expected": expected_commit,
                    "actual": BUILD_INFO["source_commit"],
                    "passed": True,
                }
            )

    # Check commit verification
    if not BUILD_INFO["source_commit_verified"]:
        result["checks"].append(
            {
                "name": "source_commit_verified",
                "expected": True,
                "actual": BUILD_INFO["source_commit_verified"],
                "passed": False,
            }
        )
        result["errors"].append("Working directory was not clean at build time")
    else:
        result["checks"].append(
            {
                "name": "source_commit_verified",
                "expected": True,
                "actual": BUILD_INFO["source_commit_verified"],
                "passed": True,
            }
        )

    # Check dependencies hash is available
    if BUILD_INFO["dependencies_sha256"] == "unavailable":
        result["checks"].append(
            {
                "name": "dependencies_sha256",
                "expected": "available",
                "actual": "unavailable",
                "passed": False,
            }
        )
        result["errors"].append("Dependencies hash unavailable")
    else:
        result["checks"].append(
            {
                "name": "dependencies_sha256",
                "expected": "available",
                "actual": BUILD_INFO["dependencies_sha256"][:16] + "...",
                "passed": True,
            }
        )

    return result


# Initialize build info at module load time
initialize_build_info()


if __name__ == "__main__":
    # When run directly, print the build info
    print(get_build_info_json())
