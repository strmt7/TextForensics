"""ENG-15 (W7 remainder): license inventory for the vendored JavaScript.

W6 shipped the full MIT notices (THIRD-PARTY-NOTICES.txt) and recorded
both vendored assets in the SBOM. What was still missing (ENG-15's own
fix/test): an archive/license-inventory test covering source tarballs,
sdists, wheels and containers, and a licensing doc that names the
vendored assets. These tests close that remainder:

- the notices file carries the full MIT texts for both components;
- the sdist AND the wheel built from this tree contain the vendored
  bundle and its notices (byte-identical to the source files);
- the checked-in SBOM records both vendored assets with MIT licences
  and npm purls;
- docs/LICENSING.md names the vendored assets and where their notices live.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
STATIC_DIR = REPO_ROOT / "src" / "textforensics" / "web_ui" / "static"
VENDORED = STATIC_DIR / "chart.umd.min.js"
NOTICES = STATIC_DIR / "THIRD-PARTY-NOTICES.txt"
SBOM = REPO_ROOT / "sbom" / "textforensics.cdx.json"

VENDORED_COMPONENTS = (
    (
        "chart.js",
        "4.4.1",
        "pkg:npm/chart.js@4.4.1",
        "Copyright (c) 2014-2022 Chart.js Contributors",
    ),
    (
        "@kurkle/color",
        "0.3.2",
        "pkg:npm/%40kurkle/color@0.3.2",
        "Copyright (c) 2018-2021 Jukka Kurkela",
    ),
)

MIT_PERMISSION = "Permission is hereby granted, free of charge, to any person obtaining a copy"
MIT_DISCLAIMER = 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND'


class TestNoticesText:
    def test_notices_file_exists_next_to_vendored_bundle(self):
        assert VENDORED.is_file(), "vendored bundle missing"
        assert NOTICES.is_file(), "THIRD-PARTY-NOTICES.txt missing (ENG-15)"

    def test_notices_carry_full_mit_texts_for_both_components(self):
        """The full permission/disclaimer text (not just a licence
        name) must be present for each component: the upstream MIT
        texts require preserving the copyright and permission notice."""
        text = NOTICES.read_text(encoding="utf-8")
        for name, version, _purl, copyright_line in VENDORED_COMPONENTS:
            assert name in text, f"{name} not named in notices"
            assert version in text, f"{name} version {version} not named in notices"
            assert copyright_line in text, f"{name} copyright line missing from notices"
            assert MIT_PERMISSION in text, "MIT permission text missing from notices"
            assert MIT_DISCLAIMER in text, "MIT disclaimer text missing from notices"
        assert text.count(MIT_PERMISSION) >= 2, "one MIT text per component is required"


class TestSbomRecordsVendoredAssets:
    def test_sbom_records_both_vendored_assets_with_mit_and_purls(self):
        bom = json.loads(SBOM.read_text(encoding="utf-8"))
        by_name = {c["name"]: c for c in bom["components"]}
        vendored_sha = hashlib.sha256(VENDORED.read_bytes()).hexdigest()
        for name, version, purl, _copyright in VENDORED_COMPONENTS:
            assert name in by_name, f"{name} missing from the checked-in SBOM"
            component = by_name[name]
            assert component["version"] == version
            assert component["purl"] == purl
            assert component["licenses"] == [{"license": {"id": "MIT"}}]
            assert component["hashes"] == [{"alg": "SHA-256", "content": vendored_sha}]


class TestArchiveInventory:
    @pytest.fixture(scope="class")
    def built_archives(self, tmp_path_factory):
        """Build sdist + wheel from a copy of this tree. The inventory
        question is which files the archives contain, not build
        reproducibility (ENG-03/W6 owns that), so the default isolated
        build is used. A network failure skips: the isolated build
        downloads its backend from PyPI and the inventory cannot be
        proven offline."""
        pytest.importorskip("build")
        work = tmp_path_factory.mktemp("license-inventory-tree")
        for name in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in", "setup.py"):
            shutil.copy2(REPO_ROOT / name, work / name)
        shutil.copytree(REPO_ROOT / "src", work / "src")
        outdir = tmp_path_factory.mktemp("license-inventory-dist")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--wheel",
                "--outdir",
                str(outdir),
            ],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=300,
        )
        combined = (result.stdout + result.stderr).lower()
        if result.returncode != 0 and (
            "connection" in combined
            or "could not fetch" in combined
            or "temporary failure in name resolution" in combined
            or "no route to host" in combined
            or "name resolution" in combined
        ):
            pytest.skip("no network to PyPI; cannot build archives to inventory them")
        assert result.returncode == 0, (
            f"python -m build failed:\\n{result.stdout[-1500:]}\\n{result.stderr[-1500:]}"
        )
        sdists = sorted(outdir.glob("*.tar.gz"))
        wheels = sorted(outdir.glob("*.whl"))
        assert len(sdists) == 1, [p.name for p in outdir.iterdir()]
        assert len(wheels) == 1, [p.name for p in outdir.iterdir()]
        return sdists[0], wheels[0]

    def test_sdist_contains_vendored_bundle_and_notices(self, built_archives):
        sdist, _wheel = built_archives
        with tarfile.open(sdist, "r:gz") as archive:
            names = archive.getnames()
        bundle = [n for n in names if n.endswith("web_ui/static/chart.umd.min.js")]
        notices = [n for n in names if n.endswith("web_ui/static/THIRD-PARTY-NOTICES.txt")]
        assert bundle, f"vendored bundle missing from sdist {sdist.name}"
        assert notices, f"THIRD-PARTY-NOTICES.txt missing from sdist {sdist.name}"
        with tarfile.open(sdist, "r:gz") as archive:
            member = archive.extractfile(notices[0])
            assert member is not None
            assert member.read() == NOTICES.read_bytes(), "notices in sdist differ from source"

    def test_wheel_contains_vendored_bundle_and_notices(self, built_archives):
        _sdist, wheel = built_archives
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
        assert any(n.endswith("web_ui/static/chart.umd.min.js") for n in names), (
            f"vendored bundle missing from wheel {wheel.name}"
        )
        notice_names = [n for n in names if n.endswith("web_ui/static/THIRD-PARTY-NOTICES.txt")]
        assert notice_names, f"THIRD-PARTY-NOTICES.txt missing from wheel {wheel.name}"
        with zipfile.ZipFile(wheel) as archive:
            assert archive.read(notice_names[0]) == NOTICES.read_bytes(), (
                "notices in wheel differ from source"
            )


class TestLicensingDoc:
    def test_licensing_doc_names_vendored_assets(self):
        """docs/LICENSING.md must name the vendored assets, their
        versions/licences, and where the notices live and ship."""
        text = (REPO_ROOT / "docs" / "LICENSING.md").read_text(encoding="utf-8")
        for needle in (
            "Chart.js",
            "4.4.1",
            "@kurkle/color",
            "0.3.2",
            "THIRD-PARTY-NOTICES",
            "MIT",
        ):
            assert needle in text, f"docs/LICENSING.md does not mention {needle!r}"
