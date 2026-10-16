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
