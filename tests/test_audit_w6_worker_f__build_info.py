"""Worker F (W6) — kill tests for the _build_info.py phase-1 survivors.

Fixtures: throwaway git repositories (clean / dirty / empty / corrupt
index) and throwaway source roots, so every branch is exercised on
inputs the test itself controls — never on the ambient worktree state.

- test_source_root_requires_both_markers kills ReplaceAndWithOr
  occ 0 ([83, 48]): a directory with pyproject.toml but no
  src/textforensics/__init__.py is not a source root.
- test_git_toplevel_none_outside_repo kills ReplaceTrueWithFalse
  occ 2 ([97, 18], ``check=True`` -> False): a failing rev-parse
  must yield None, not Path(".").
- test_git_toplevel_missing_git_returns_none /
  test_git_toplevel_os_error_returns_none kill ExceptionReplacer
  occ 1 ([100, 40], FileNotFoundError) / occ 2 ([100, 59], OSError).
- test_source_commit_clean_repo_is_verified /
  test_source_commit_dirty_repo_is_unverified kill the Eq_* occ 0
  mutants at [147, 48] (NotEq, Lt, Gt, GtE) and ReplaceTrueWithFalse
  occ 7 ([143, 17], ``text=True`` -> False on the status run).
- test_source_commit_subdir_root_is_unknown kills
  ReplaceComparisonOperator_NotEq_Gt occ 0 / NotEq_Is occ 0
  ([125, 30]) and ReplaceFalseWithTrue occ 3 ([126, 30]).
- test_source_commit_no_git_repo_is_unknown kills
  ReplaceFalseWithTrue occ 2 ([123, 26]).
- test_source_commit_empty_repo_is_unknown kills
  ReplaceTrueWithFalse occ 5 ([134, 18], ``check=True`` -> False on
  rev-parse HEAD) and ReplaceFalseWithTrue occ 5 ([151, 26]).
- test_source_commit_corrupt_index_is_unknown kills
  ReplaceTrueWithFalse occ 8 ([144, 18], ``check=True`` -> False on
  the status run): a corrupt .git/index makes status fail.
- test_api_version_falls_back_to_pyproject kills Div_* occ 13
  ([253, 21], 11 mutants: ``root / "pyproject.toml"`` -> any other
  operator raises TypeError), Is_IsNot occ 5 ([251, 12]), AddNot
  occ 19 ([254, 7]) / occ 20 ([257, 15]), ExceptionReplacer occ 7
  ([246, 11], ``except Exception``), NumberReplacer occ 9
  ([258, 39], maxsplit 1 -> 0, IndexError), occ 10 ([258, 42],
  [1] -> [2], IndexError), occ 11 ([258, 42], [1] -> [0], returns
  the key "version"), and ZeroIterationForLoop occ 3 ([256, 20]).
  The importlib.metadata lookup is patched to fail so the fallback
  runs. test_api_version_uses_explicit_root additionally kills
  IsNot_Is occ 3 ([250, 52]) and AddNot occ 17 ([250, 40]).
- test_dependencies_hash_in_repo kills Is_IsNot occ 3 ([164, 12])
  and AddNot occ 7 ([164, 7]) / occ 9 ([174, 7]);
  test_dependencies_hash_uses_explicit_root kills IsNot_Is occ 1
  ([163, 52]) and AddNot occ 6 ([163, 40]).
- test_contract_info_in_repo kills Is_IsNot occ 4 ([198, 12]),
  AddNot occ 11 ([198, 7]) / occ 13 ([205, 7]) / occ 14 ([219, 7])
  / occ 15 ([224, 7]) / occ 16 ([229, 7]) / occ 17 ([234, 7]) and
  ZeroIterationForLoop occ 1 ([207, 27]) / occ 2 ([211, 20]);
  test_contract_info_uses_explicit_root kills IsNot_Is occ 2
  ([197, 52]) and AddNot occ 10 ([197, 40]).
- test_embedded_resource_is_preferred kills Delete_Not occ 0
  ([319, 23]), AddNot occ 29 ([319, 7]) / occ 30 ([321, 7]),
  Is_IsNot occ 8 ([319, 12]), AddNot occ 26 ([306, 11],
  ``resource.is_file()``) and the [311, 12] Is_IsNot occ 7 /
  [311, 7] AddNot occ 27 pair (the fallback must NOT run when the
  resource already loaded: the relative-path file carries DIFFERENT
  content, so the mutants return the wrong record).
- test_embedded_fallback_reads_relative_path kills AddNot occ 28
  ([315, 11], ``embedded_path.exists()``): with the resource load
  failing, the relative-path file is the only source.
- test_embedded_list_record_is_refused kills ReplaceOrWithAnd
  occ 0 ([319, 20]): a JSON list naming the provenance fields must
  still be refused (the mutant proceeds past the type check).
- test_sdist_provenance_loads / _uses_explicit_root kill Is_IsNot
  occ 9 ([335, 12]), IsNot_Is occ 5 ([334, 52]), AddNot occ 31
  ([334, 40]) / occ 32 ([335, 7]) / occ 34 ([342, 7]) / occ 35
  ([344, 7]) / occ 36 ([346, 7]) / occ 37 ([348, 7]) and
  Delete_Not occ 1 ([342, 7]) / occ 2 ([346, 7]) / occ 3 ([348, 7]).
- test_apply_provenance_missing_verified_defaults_false kills
  ReplaceFalseWithTrue occ 6 ([357, 84]).
- test_initialize_sets_python_version kills NumberReplacer occ 12
  / occ 13 ([405, 55], ``sys.version.split()[0]`` -> [1] / [-1]).
- test_verify_* kill the verify_build_identity survivors:
  Eq_GtE occ 1 ([483, 28]), NotEq_Lt occ 1 / NotEq_IsNot occ 1
  ([495, 18]), ReplaceTrueWithFalse occ 12 ([477, 26], _pass
  ``passed``), occ 13 ([509, 12], _fail ``expected``), occ 14
  ([516, 12], _pass ``expected``), NumberReplacer occ 16 / occ 17
  ([532, 47], ``[:16]`` -> [:17] / [:15]).

NOTE: 23 _build_info survivors are NOT killable and are classified
equivalent in audit-w6-f-equiv-reasons-_build_info.json: the five
Eq/NotEq variants whose comparisons coincide on the reachable domain
([147, 48] LtE; [521, 41] GtE; [125, 30] Lt), the seven
_get_format_versions mutants (the function returns ("1.0.0","1.0.0")
on every path — its engineering.toml loop bodies are ``pass``), the
sort_keys no-op ([215, 76]), the unreachable OSError handler
([127, 11] / [128, 26] — resolve() of a path that passed
_source_root cannot raise OSError), the two ``and``-in-``pass``-body
mutants ([281, 45] / [284, 43]), the six timeout NumberReplacers
(10 -> 11 / 9), the maxsplit 1 -> 2 mutant ([258, 39] occ 8), and
the zero-iteration loop over the ``pass`` bodies ([280, 20] occ 4).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from textforensics import _build_info as bi


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


def _make_source_root(base: Path, version: str = "0.2.0") -> Path:
    base.mkdir(parents=True, exist_ok=True)
    (base / "pyproject.toml").write_text(
        f'[project]\nname = "textforensics"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (base / "src" / "textforensics").mkdir(parents=True, exist_ok=True)
    (base / "src" / "textforensics" / "__init__.py").write_text("", encoding="utf-8")
    return base


def _make_repo(base: Path) -> tuple[Path, str]:
    _git("init", "-q", "-b", "main", cwd=base)
    _make_source_root(base)
    (base / "f.txt").write_text("hello\n", encoding="utf-8")
    _git("add", "-A", cwd=base)
    _git("commit", "-qm", "init", cwd=base)
    commit = _git("rev-parse", "HEAD", cwd=base).stdout.strip()
    return base, commit


def _check(result: dict, name: str) -> dict:
    for entry in result["checks"]:
        if entry["name"] == name:
            return entry
    raise AssertionError(f"no check named {name!r} in {result['checks']!r}")


class _BuildInfoState:
    """Save/restore the BUILD_INFO global around a mutation."""

    def __init__(self, test: unittest.TestCase):
        self.test = test
        self.saved: dict = {}

    def __enter__(self):
        self.saved = dict(bi.BUILD_INFO)
        return self

    def __exit__(self, *exc):
        bi.BUILD_INFO.clear()
        bi.BUILD_INFO.update(self.saved)
        return False


class TestBuildInfoW6Killers(unittest.TestCase):
    # -- _source_root / _git_toplevel -----------------------------------

    def test_source_root_requires_both_markers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            self.assertIsNone(bi._source_root(root))

    def test_git_toplevel_none_outside_repo(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(bi._git_toplevel(Path(td)))

    def test_git_toplevel_missing_git_returns_none(self):
        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.object(bi.subprocess, "run", side_effect=FileNotFoundError(2, "git")),
        ):
            self.assertIsNone(bi._git_toplevel(Path(td)))

    def test_git_toplevel_os_error_returns_none(self):
        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.object(bi.subprocess, "run", side_effect=OSError("cannot spawn git")),
        ):
            self.assertIsNone(bi._git_toplevel(Path(td)))

    # -- _get_source_commit ----------------------------------------------

    def test_source_commit_clean_repo_is_verified(self):
        with tempfile.TemporaryDirectory() as td:
            root, commit = _make_repo(Path(td))
            got_commit, verified = bi._get_source_commit(root)
            self.assertEqual(got_commit, commit)
            self.assertTrue(verified)

    def test_source_commit_dirty_repo_is_unverified(self):
        with tempfile.TemporaryDirectory() as td:
            root, commit = _make_repo(Path(td))
            (root / "untracked.txt").write_text("x\n", encoding="utf-8")
            got_commit, verified = bi._get_source_commit(root)
            self.assertEqual(got_commit, commit)
            self.assertFalse(verified)

    def test_source_commit_subdir_root_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root, _commit = _make_repo(Path(td))
            sub = root / "sub"
            _make_source_root(sub)
            self.assertEqual(bi._get_source_commit(sub), ("unknown", False))

    def test_source_commit_no_git_repo_is_unknown(self):
        # ReplaceFalseWithTrue occ 2 ([123, 26]): a valid source root
        # that is not inside any git checkout must yield
        # ("unknown", False) — the toplevel-is-None return.
        with tempfile.TemporaryDirectory() as td:
            root = _make_source_root(Path(td))
            self.assertEqual(bi._get_source_commit(root), ("unknown", False))

    def test_source_commit_empty_repo_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _git("init", "-q", "-b", "main", cwd=root)
            _make_source_root(root)
            self.assertEqual(bi._get_source_commit(root), ("unknown", False))

    def test_source_commit_corrupt_index_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root, commit = _make_repo(Path(td))
            (root / ".git" / "index").write_bytes(b"garbage-not-an-index")
            self.assertEqual(bi._get_source_commit(root), ("unknown", False))

    def test_source_commit_missing_git_returns_unknown(self):
        # ExceptionReplacer occ 5/6 ([150, 40]/[150, 59]): the rev-parse
        # run raising FileNotFoundError / OSError must fail closed.
        with tempfile.TemporaryDirectory() as td:
            root, _commit = _make_repo(Path(td))

            def fake_run(argv, **kwargs):
                if argv[-1] == "--show-toplevel":
                    return subprocess.CompletedProcess(argv, 0, stdout=str(root) + "\n", stderr="")
                raise FileNotFoundError(2, "git")

            with mock.patch.object(bi.subprocess, "run", side_effect=fake_run):
                self.assertEqual(bi._get_source_commit(root), ("unknown", False))

            def fake_run_os(argv, **kwargs):
                if argv[-1] == "--show-toplevel":
                    return subprocess.CompletedProcess(argv, 0, stdout=str(root) + "\n", stderr="")
                raise OSError("cannot spawn git")

            with mock.patch.object(bi.subprocess, "run", side_effect=fake_run_os):
                self.assertEqual(bi._get_source_commit(root), ("unknown", False))

    # -- _get_api_version -------------------------------------------------

    def _fail_metadata_version(self):
        from importlib.metadata import PackageNotFoundError

        return mock.patch(
            "importlib.metadata.version",
            side_effect=PackageNotFoundError("textforensics"),
        )

    def test_api_version_falls_back_to_pyproject(self):
        with self._fail_metadata_version():
            version = bi._get_api_version()
        pyproject = Path(bi.__file__).resolve().parent.parent.parent / "pyproject.toml"
        expected = next(
            line.split("=", 1)[1].strip().strip("\"'")
            for line in pyproject.read_text(encoding="utf-8").splitlines()
            if line.startswith("version = ")
        )
        self.assertEqual(version, expected)
        self.assertNotEqual(version, "unknown")

    def test_api_version_uses_explicit_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_source_root(Path(td), version="9.9.9")
            with self._fail_metadata_version():
                self.assertEqual(bi._get_api_version(root), "9.9.9")

    # -- _compute_dependencies_hash / _compute_contract_info --------------

    def test_dependencies_hash_in_repo(self):
        digest = bi._compute_dependencies_hash()
        self.assertNotEqual(digest, "unavailable")
        self.assertEqual(len(digest), 64)

    def test_dependencies_hash_uses_explicit_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_source_root(Path(td))
            lock = root / "requirements.lock"
            lock.write_bytes(b"pinned==1.0\n")
            expected = hashlib.sha256(b"pinned==1.0\n").hexdigest()
            self.assertEqual(bi._compute_dependencies_hash(root), expected)

    def test_contract_info_in_repo(self):
        info = bi._compute_contract_info()
        for key in (
            "schemas_sha256",
            "schema_files",
            "engineering_toml_sha256",
            "agents_md_sha256",
            "spec_md_sha256",
            "architecture_md_sha256",
        ):
            self.assertIn(key, info)
        self.assertNotEqual(info["schemas_sha256"], hashlib.sha256(b"").hexdigest())
        schemas = json.loads(info["schema_files"])
        self.assertTrue(schemas)
        self.assertIn("case-file.schema.json", schemas)

    def test_contract_info_uses_explicit_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_source_root(Path(td))
            schemas_dir = root / "src" / "textforensics" / "schemas"
            schemas_dir.mkdir(parents=True)
            (schemas_dir / "only.json").write_text('{"a": 1}', encoding="utf-8")
            info = bi._compute_contract_info(root)
            self.assertIn("schemas_sha256", info)
            self.assertEqual(
                json.loads(info["schema_files"]),
                {"only.json": hashlib.sha256(b'{"a": 1}').hexdigest()},
            )

    # -- _load_embedded_build_info ----------------------------------------

    def _provenance_record(self, **overrides) -> dict:
        record = {
            "source_commit": "a" * 40,
            "source_commit_verified": True,
            "dependencies_sha256": "b" * 64,
            "contract_info": {"schemas_sha256": "c" * 64},
        }
        record.update(overrides)
        return record

    def _fake_resource(self, payload: object):
        """A stub for ``importlib.resources.files(...)``: its joinpath
        returns the resource stub carrying the payload."""

        class _Resource:
            def is_file(self) -> bool:
                return True

            def read_text(self, encoding: str = "utf-8") -> str:
                return json.dumps(payload)

        class _Package:
            def joinpath(self, _name: str) -> _Resource:
                return _Resource()

        return _Package()

    def _relative_embedded_path(self) -> Path:
        return Path(bi.__file__).resolve().parent / "_build_info.json"

    def test_embedded_resource_is_preferred(self):
        record_a = self._provenance_record()
        record_b = self._provenance_record(source_commit="d" * 40)
        target = self._relative_embedded_path()
        target.write_text(json.dumps(record_b), encoding="utf-8")
        try:
            with mock.patch(
                "importlib.resources.files",
                return_value=self._fake_resource(record_a),
            ):
                loaded = bi._load_embedded_build_info()
            self.assertEqual(loaded, record_a)
        finally:
            target.unlink(missing_ok=True)

    def test_embedded_fallback_reads_relative_path(self):
        record_b = self._provenance_record()
        target = self._relative_embedded_path()
        target.write_text(json.dumps(record_b), encoding="utf-8")
        try:
            with mock.patch("importlib.resources.files", side_effect=ImportError("no resources")):
                loaded = bi._load_embedded_build_info()
            self.assertEqual(loaded, record_b)
        finally:
            target.unlink(missing_ok=True)

    def test_embedded_list_record_is_refused(self):
        payload = [
            "source_commit",
            "source_commit_verified",
            "dependencies_sha256",
            "contract_info",
        ]
        with mock.patch(
            "importlib.resources.files",
            return_value=self._fake_resource(payload),
        ):
            self.assertIsNone(bi._load_embedded_build_info())

    def test_embedded_import_error_returns_none(self):
        # ExceptionReplacer occ 8 ([308, 12], ImportError).
        with mock.patch("importlib.resources.files", side_effect=ImportError("no resources")):
            self.assertIsNone(bi._load_embedded_build_info())

    def test_embedded_missing_file_returns_none(self):
        # ExceptionReplacer occ 9 ([308, 25], FileNotFoundError) and
        # occ 10 ([308, 44], OSError): a resource whose read fails.
        class _FailingResource:
            def is_file(self) -> bool:
                return True

            def read_text(self, encoding: str = "utf-8") -> str:
                raise FileNotFoundError(2, "gone")

        class _FailingPackage:
            def __init__(self, resource):
                self._resource = resource

            def joinpath(self, _name: str):
                return self._resource

        with mock.patch(
            "importlib.resources.files",
            return_value=_FailingPackage(_FailingResource()),
        ):
            self.assertIsNone(bi._load_embedded_build_info())

        class _FailingResourceOs:
            def is_file(self) -> bool:
                return True

            def read_text(self, encoding: str = "utf-8") -> str:
                raise OSError("cannot read")

        with mock.patch(
            "importlib.resources.files",
            return_value=_FailingPackage(_FailingResourceOs()),
        ):
            self.assertIsNone(bi._load_embedded_build_info())

    # -- _load_sdist_provenance / _apply_provenance ------------------------

    def test_sdist_provenance_loads(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_source_root(Path(td))
            record = self._provenance_record()
            path = root / "src" / "textforensics" / "_sdist_provenance.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            self.assertEqual(bi._load_sdist_provenance(root), record)

    def test_apply_provenance_missing_verified_defaults_false(self):
        with _BuildInfoState(self):
            bi._apply_provenance({}, "test")
            self.assertFalse(bi.BUILD_INFO["source_commit_verified"])
            self.assertEqual(bi.BUILD_INFO["source_commit"], "unknown")

    # -- initialize_build_info --------------------------------------------

    def test_initialize_sets_python_version(self):
        with _BuildInfoState(self):
            bi.initialize_build_info()
            self.assertEqual(bi.BUILD_INFO["python_version"], sys.version.split()[0])

    # -- verify_build_identity ----------------------------------------------

    def _valid_build_info(self, **overrides) -> dict:
        info = {
            "source_commit": "5" * 40,
            "source_commit_verified": True,
            "dependencies_sha256": "a" * 64,
            "contract_info": {"schemas_sha256": "b" * 64},
        }
        info.update(overrides)
        return info

    def test_verify_known_commit_passes(self):
        with _BuildInfoState(self):
            bi.BUILD_INFO.update(self._valid_build_info())
            result = bi.verify_build_identity()
            self.assertTrue(_check(result, "source_commit_known")["passed"])
            self.assertEqual(_check(result, "source_commit_known")["actual"], "5" * 40)

    def test_verify_high_commit_passes_known_check(self):
        # Eq_GtE occ 1 ([483, 28]): "zzzz" >= "unknown" but != "unknown".
        with _BuildInfoState(self):
            bi.BUILD_INFO.update(self._valid_build_info(source_commit="zzzz"))
            result = bi.verify_build_identity()
            self.assertTrue(_check(result, "source_commit_known")["passed"])

    def test_verify_mismatched_commit_fails(self):
        # NotEq_Lt occ 1 ([495, 18]): "" < commit, but "" != commit.
        with _BuildInfoState(self):
            bi.BUILD_INFO.update(self._valid_build_info())
            result = bi.verify_build_identity(expected_commit="")
            self.assertFalse(_check(result, "source_commit")["passed"])

    def test_verify_matching_commit_by_value_passes(self):
        # NotEq_IsNot occ 1 ([495, 18]): an equal-valued but distinct
        # string object must still match. NOTE: f"{s}", "%s" % s and
        # "".join([s]) all return s ITSELF in CPython (verified
        # 2026-11-16) — only a real re-encode (or a multi-part join)
        # allocates a distinct equal object.
        with _BuildInfoState(self):
            bi.BUILD_INFO.update(self._valid_build_info())
            result = bi.verify_build_identity(
                expected_commit=bi.BUILD_INFO["source_commit"].encode().decode()
            )
            self.assertTrue(_check(result, "source_commit")["passed"])

    def test_verify_expected_flag_true_on_fail(self):
        # ReplaceTrueWithFalse occ 13 ([509, 12]).
        with _BuildInfoState(self):
            bi.BUILD_INFO.update(self._valid_build_info(source_commit_verified=False))
            result = bi.verify_build_identity()
            self.assertFalse(result["valid"])
            self.assertTrue(_check(result, "source_commit_verified")["expected"])

    def test_verify_expected_flag_true_on_pass(self):
        # ReplaceTrueWithFalse occ 14 ([516, 12]).
        with _BuildInfoState(self):
            bi.BUILD_INFO.update(self._valid_build_info())
            result = bi.verify_build_identity()
            self.assertTrue(result["valid"])
            self.assertTrue(_check(result, "source_commit_verified")["expected"])

    def test_verify_dependencies_hash_prefix(self):
        # NumberReplacer occ 16/17 ([532, 47]).
        with _BuildInfoState(self):
            digest = "f" * 64
            bi.BUILD_INFO.update(self._valid_build_info(dependencies_sha256=digest))
            result = bi.verify_build_identity()
            self.assertEqual(
                _check(result, "dependencies_sha256")["actual"],
                digest[:16] + "...",
            )


if __name__ == "__main__":
    unittest.main()
