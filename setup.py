"""Setup script for TextForensics with build-time identity embedding.

This script extends the setuptools build process to embed build identity
information (source commit, dependency hashes, contract info) into the
installed package at build time, following the rejection-rejector pattern.

The build-time embedding ensures that installed packages carry their own
provenance without requiring git access at runtime.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


def _get_source_commit() -> tuple[str, bool]:
    """Get the current git commit hash and verification status."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        commit = result.stdout.strip()

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
    """Compute SHA-256 hash of dependencies from pyproject.toml."""
    base = Path(__file__).resolve().parent
    pyproject = base / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    return "unavailable"


def _compute_contract_info() -> dict[str, str]:
    """Compute hashes of contract/documentation files."""
    base = Path(__file__).resolve().parent
    contract_info: dict[str, str] = {}

    # Hash all schema files
    schemas_dir = base / "src" / "textforensics" / "schemas"
    if not schemas_dir.exists():
        schemas_dir = base / "schemas"

    if schemas_dir.exists():
        schema_hashes = {}
        for schema_file in sorted(schemas_dir.glob("*.json")):
            hasher = hashlib.sha256()
            with schema_file.open("rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            schema_hashes[schema_file.name] = hasher.hexdigest()

        aggregate = hashlib.sha256()
        for name in sorted(schema_hashes.keys()):
            aggregate.update(name.encode("utf-8"))
            aggregate.update(schema_hashes[name].encode("utf-8"))
        contract_info["schemas_sha256"] = aggregate.hexdigest()
        contract_info["schema_files"] = json.dumps(schema_hashes, sort_keys=True)

    # Hash engineering.toml
    engineering_toml = base / "engineering.toml"
    if engineering_toml.exists():
        hasher = hashlib.sha256()
        with engineering_toml.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        contract_info["engineering_toml_sha256"] = hasher.hexdigest()

    # Hash AGENTS.md
    agents_md = base / "AGENTS.md"
    if agents_md.exists():
        hasher = hashlib.sha256()
        with agents_md.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        contract_info["agents_md_sha256"] = hasher.hexdigest()

    # Hash SPEC.md
    spec_md = base / "SPEC.md"
    if spec_md.exists():
        hasher = hashlib.sha256()
        with spec_md.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        contract_info["spec_md_sha256"] = hasher.hexdigest()

    # Hash ARCHITECTURE.md
    architecture_md = base / "ARCHITECTURE.md"
    if architecture_md.exists():
        hasher = hashlib.sha256()
        with architecture_md.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        contract_info["architecture_md_sha256"] = hasher.hexdigest()

    return contract_info


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
        source_commit, source_commit_verified = _get_source_commit()
        dependencies_sha256 = _compute_dependencies_hash()
        contract_info = _compute_contract_info()

        build_info = {
            "source_commit": source_commit,
            "source_commit_verified": source_commit_verified,
            "dependencies_sha256": dependencies_sha256,
            "contract_info": contract_info,
            "api_spec_sha256": contract_info.get("spec_md_sha256", "unavailable"),
            "detector_adapter_api_sha256": contract_info.get(
                "engineering_toml_sha256", "unavailable"
            ),
            "embedded_at": "build_time",
        }

        # Write to the package directory
        package_dir = Path(self.build_lib) / "textforensics" if self.build_lib else None
        if package_dir is None:
            # Fallback: write to source directory
            package_dir = Path(__file__).resolve().parent / "src" / "textforensics"

        package_dir.mkdir(parents=True, exist_ok=True)
        output_path = package_dir / "_build_info.json"
        output_path.write_text(
            json.dumps(build_info, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Embedded build info: {output_path}")


setup(
    cmdclass={"build_py": BuildPyWithBuildInfo},
)
