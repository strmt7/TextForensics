# Quality gates

TextForensics can be misread as an authorship authority, so its quality gates are intentionally strict.

## Concepts and claims
1. Never relabel a detector score as probability without calibration evidence.
2. "Confidence" must state what it describes and how it was derived.
3. Text-only output states that it is not proof of authorship.
4. Unsupported regimes are visible.
5. Abstention remains abstention.
6. Public performance claims have reproducible run artifacts.
7. Do not make absolute human/AI certainty claims.
8. Maintain differentiation beyond multi-detector aggregation.

## Detector adapters
9. Stable unique detector ID.
10. Detector/model/checkpoint version recorded.
11. Detector family declared.
12. Native score direction and semantics documented.
13. Supported languages documented.
14. Minimum/recommended text length documented.
15. Known domain limitations documented.
16. Local/remote execution explicit.
17. Network use opt-in.
18. License/model terms documented.
19. Timeout/error paths return structured failure or abstention.
20. Outputs validate against protocol schema.
21. Calibrated probability requires a calibration reference.
22. Broken optional plugins cannot crash the forensic core.

## Benchmarks
23. Dataset license/provenance known.
24. Dataset/revision fingerprint recorded.
25. Calibration and final evaluation disjoint.
26. Derivatives/near-duplicates do not cross partitions.
27. AUROC and AUPRC reported where applicable.
28. Human FPR reported at declared thresholds.
29. TPR reported at the same thresholds.
30. Probability outputs receive calibration metrics.
31. Release claims include uncertainty estimates.
32. Relevant domain/language/length/editing slices reported.
33. Missing/error/abstained samples counted.
34. Hardware/runtime/software versions recorded.
35. External paper results are never presented as TextForensics results.

## Trust Map
36. Every dimension has a rule or evidence reference.
37. Missing evidence becomes `unknown`.
38. Known unsupported input becomes `out_of_scope`.
39. Overall coverage cannot ignore a material unsupported dimension.
40. Trust Map state is not an authorship probability.
41. Temporal stability requires multiple probe samples/timestamps.

## Ensemble
42. Detector-family correlation is considered.
43. Detector-local calibration is not reused as ensemble calibration.
44. Exact ensemble membership is versioned.
45. Missing-detector behavior is specified.
46. Ensemble calibration uses separate data.
47. Ensemble performance is tested held out.
48. Ablations show marginal value.
49. Unvalidated detectors cannot silently influence a calibrated top-level probability.

## Stability and drift
50. Benign transformations preserve meaning/content sufficiently for the test.
51. Score stability and verdict stability are distinct.
52. Drift is never inferred from one document.
53. Drift reports use stable probe IDs/hashes.
54. Probe-set changes create a new version.
55. Provider/model/version metadata is preserved where exposed.

## Provenance and case files
56. Raw text is absent from portable case files by default.
57. Input hash is included.
58. Detector/calibration/version provenance is included.
59. Case-file canonicalization/hash behavior is tested.
60. Local hash ledgers are called tamper-evident, not trusted timestamps.
61. External signatures/timestamps are described according to their real trust model.
62. Process provenance is not silently mixed numerically into detector scores.

## Privacy and security
63. Core sends no text over the network.
64. Remote adapters require explicit enablement.
65. Secrets never enter reports.
66. Provider errors are sanitized if they may echo input.
67. Logs exclude raw user text by default.
68. Imported paths/metadata are sanitized.
69. Model/data downloads are transparent.
70. Dependency additions are justified.

## Engineering
71. Supported Python versions pass CI.
72. Tests cover changed score/report semantics.
73. Schema changes receive version/migration notes.
74. CLI JSON remains parseable.
75. Python API, CLI and MCP share one core implementation.
76. Heavy optional dependencies do not become mandatory core imports.
77. Contract violations fail clearly.
78. Documentation links remain valid.
79. Example outputs come from code or are clearly labeled illustrative.
80. Clean-checkout smoke paths are documented.

## Release
81. Clean checkout installs.
82. Tests pass.
83. End-to-end CLI smoke test passes.
84. Benchmark smoke fixture runs.
85. Published benchmark artifacts match the release commit.
86. README limitations match actual behavior.
87. SECURITY/responsible-use guidance is current.
88. Reproducibility-critical versions are pinned.
89. Changelog documents score/schema semantic changes.
90. Reproduction instructions work outside the original development path.

## Dependency audit
91. pip-audit runs as a failing gate: any finding not matched by a
    per-finding entry in `pip-audit-baseline.toml` fails CI
    (`scripts/check_pip_audit.py`, exit 2).
92. Baseline entries are per finding (package, vulnerability id,
    affected version) with a reason and a review date; no blanket
    ignores, no `--ignore` flags, no severity downgrades.
93. A baseline entry past its review date fails the gate (exit 1)
    while the finding is still present; an entry whose finding is
    fixed is reported as dormant and removed by a human, never left
    to rot silently.

91. The checked-in SBOM is regenerated and diffed in CI; a stale SBOM fails the gate.

## Software Bill of Materials (SBOM)

TextForensics has four SBOMs. They are not four copies of the same data:
they differ in scope, format, home and retention, and only one of them is
checked in and staleness-checked.

| SBOM | Generator | Scope | Format | Home | Retention / trigger |
|---|---|---|---|---|---|
| Checked-in SBOM (this section) | `scripts/generate_sbom.py` (stdlib only; see below) | Resolved dependency closure of `requirements-pinned.txt` as installed (123 components at introduction) | CycloneDX 1.6 JSON | `sbom/textforensics.cdx.json` (in the repo; out of the import path and out of the wheel/sdist — verified by inspecting a built wheel and sdist, which contain no `sbom/` entry) | Committed; regenerated + diffed on every push by the `sbom` job in `ci.yml` |
| Release SBOM | `anchore/sbom-action@v0` (syft) in `release.yml` | Built artifacts in `./dist` (wheel, sdist, source tarball) | CycloneDX JSON + SPDX JSON | Release artifacts, cosign-signed (`dist/textforensics-sbom.cdx.json`, `dist/textforensics-sbom.spdx.json`) | Attached to the GitHub Release; manual `workflow_dispatch` only (requires typing `RELEASE`) |
| Supply-chain SBOM | `anchore/sbom-action@v0` (syft) in `supply-chain.yml` (`sbom` job) | Project directory (`.`) | syft JSON (not CycloneDX/SPDX) | CI artifact `textforensics-sbom-<sha>` | 30 days; every push to `main` + weekly Monday 04:23 UTC |
| Container SBOM | `anchore/sbom-action@v0` (syft) in `container.yml` | Project directory (`.`) at image build | CycloneDX JSON | CI artifact `textforensics-sbom-<version>-<sha>` | Default artifact retention; only on container-path changes (`Dockerfile`, `pyproject.toml`, `src/**`, …), weekly Sunday 03:00 UTC, or manual dispatch. Verified live 2026-11-08: run 42431729810 on main (head `a384ec1`) succeeded and its `textforensics-sbom-0.2.0-a384ec1…` artifact (5,100 bytes) was present and unexpired. |

Why a checked-in SBOM exists at all, given the three CI ones: the
container SBOM only exists after a container build (not on every push —
a change to `requirements-pinned.txt` alone does not even trigger
`container.yml`), the supply-chain SBOM is syft JSON rather than an
interchange format, and all three are expiring workflow artifacts that
cannot be reviewed in a diff and are never compared against anything.
The checked-in SBOM makes dependency changes reviewable in the diff and
lets the gate fail on every push when the declared dependencies and the
recorded SBOM disagree.

Generation (one canonical path for the checked-in SBOM):

    python -m pip install -r requirements-pinned.txt
    python scripts/generate_sbom.py [--check]

The generator is stdlib-only (no new dependency). It reads the extras
from the `-e .[...]` line of `requirements-pinned.txt` plus every package
named directly in that file, resolves exact versions from the installed
environment (the file is an exact-pin lockfile, so a fresh install is
deterministic; a live install is still required because exact versions
are read from the installed environment — the canonical install is the
command above), walks the transitive `Requires-Dist` closure, and emits
CycloneDX 1.6 JSON. `cyclonedx-python-lib` (already in the dev/audit
environment) is not a generation input: its CLI embeds wall-clock
timestamps and it resolves from the file rather than from the installed
environment. It is used only as an independent cross-check in
`tests/test_generate_sbom.py` (`Bom.from_json(...).validate()`).

Reproducibility guarantee: same inputs produce byte-identical output.
Components and `dependsOn` lists are sorted by PEP 503 normalized name;
`metadata.timestamp` is omitted (CycloneDX leaves it optional — a
wall-clock value would change the output on every run); no source-commit
field is embedded (it would make every commit stale by construction —
provenance is the git history of the SBOM file itself); and
`serialNumber` is a deterministic UUIDv5 of the SHA-256 of the canonical
BOM content, so it changes exactly when the content changes. The inputs
are pinned in `metadata.properties` as `requirementsPinnedSha256` and
`pyprojectSha256`. Proven by running the generator twice from the same
install and diffing the outputs (identical), and by the test suite.

What "stale" means, per SBOM:

* Checked-in SBOM: `python scripts/generate_sbom.py --check` (the `sbom`
  CI job) exits 1 and prints a unified diff when regeneration from a
  fresh `requirements-pinned.txt` install differs. Regenerate and commit
  the result. Since 2026-11-10 the file is an exact-pin lockfile (see the
  lockfile decision in SECURITY.md), so a fresh install cannot resolve to
  a newer release on its own: staleness now means a deliberate change (a
  pin bump, a pyproject/extras change, or a generator change). Before the
  lockfile, ranges could resolve to a newer upstream release with no repo
  change; that was a real staleness event, not CI flakiness.
  Regenerating in a partial environment (e.g. only `.[dev]` installed)
  lists the missing declared packages in `metadata.properties` as
  `unresolvedDependencies` instead of silently omitting them; that output
  will not match the committed file, by design. Regenerating also changes
  the two SHA-256 property values in the SBOM, which `detect-secrets`
  flags as Hex High Entropy Strings: the two hashes are recorded as
  audited false positives in `.secrets.baseline`, so a regeneration
  commit must update those two baseline entries in the same commit or
  pre-commit fails. Do NOT run a blanket `detect-secrets scan --baseline`
  for this — it rewrites the whole baseline (observed: +91/−226 lines,
  pruning unrelated entries and adding test-file entries the hook
  deliberately excludes); add only the two SBOM entries.
* Release / supply-chain / container SBOMs: "stale" has no check — they
  are generated fresh at the moment they run and are never compared.
  Their freshness is bounded by their triggers and retention in the table
  above, which is why the release gate relies on the checked-in SBOM.

Known flags (not fixed here — other owners):

* `anchore/sbom-action@v0` is an UNPINNED major tag in `release.yml`,
  `supply-chain.yml` and `container.yml`. Action-pinning decisions belong
  to the cosign worker; this wave does not change any `uses:` ref.
