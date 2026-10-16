# AGENTS.md — TextForensics development contract

This file is the durable handoff contract for human and AI contributors. Read it before changing architecture, detector semantics, benchmarking, reports, MCP tools, or user-facing claims.

## North star

**TextForensics is an independent audit layer for AI-text detection.**

The project should answer not only:

> Does this text trigger machine-generation signals?

but, more importantly:

> How trustworthy is that conclusion for this exact text regime, detector version, and evidence set?

The differentiator is **forensic reliability engineering**: detector evidence + validation coverage + stability/drift + provenance + reproducible case files.

TextForensics must not regress into:
- a wrapper around one classifier,
- a generic "jury of detectors",
- an MCP wrapper whose novelty is only MCP,
- a detector-bypass loop,
- or a product that presents an arbitrary score as certainty.

## Hard rules

1. **Never invent benchmark results.** README numbers must trace to a committed/reproducible run artifact.
2. **A score is not a probability.** Populate or display an AI-authorship probability only when a documented calibration artifact supports that exact output semantics.
3. **Detector-local calibration is not ensemble calibration.** Averaging calibrated detector probabilities does not make the average calibrated. A top-level probability requires separate validation/calibration for the exact ensemble definition.
4. **Preserve abstention.** Unsupported language, insufficient length, out-of-domain inputs, missing calibration, severe detector disagreement, or instability are reasons to abstain or downgrade coverage.
5. **Do not hide disagreement.** Heterogeneous detector outputs remain inspectable.
6. **Provenance is first-class.** Record detector ID/version, checkpoint or provider version when available, calibration ID, configuration, runtime mode, and benchmark/run provenance.
7. **Core is local-first.** No text leaves the machine unless the user explicitly selects an opt-in remote adapter.
8. **No silent telemetry.**
9. **Remote provider results are observations, not ground truth.** Use official/authorized APIs only; never scrape or reverse-engineer a provider to evade its controls.
10. **Human false positives are a release gate.** Accuracy alone is insufficient.
11. **Every serious claim must be sliced.** At minimum consider generator, domain/genre, language, length, editing/paraphrase regime, and human population/style where ethically appropriate.
12. **Prevent benchmark contamination.** Training, threshold selection, calibration, and final evaluation must be disjoint. Track dataset fingerprints and model provenance.
13. **Prefer methodological diversity over detector count.** Three correlated classifiers are not three independent evidence families.
14. **Heavy dependencies are optional extras.** Keep the forensic core importable without GPU stacks.
15. **Schemas are public contracts.** Version them deliberately; do not silently change field meaning.
16. **Tests accompany behavior changes.**
17. **Never lower thresholds, delete warnings, or relabel metrics to make a demo look better.**
18. **Sentence/chunk scores are not sentence-level authorship probabilities unless specifically validated as such.**
19. **Short-text limitations must be visible in the output.**
20. **Unsupported language/domain coverage must be explicit, not inferred from a confident-looking number.**
21. **Revalidate calibrations after detector/model/provider changes.**
22. **Raw text is excluded from portable case files by default.** Store hashes and derived evidence unless the user explicitly opts in.
23. **Editing assistance is separate from inference.** It may improve clarity, voice, specificity, or investigate false-positive triggers, but must not promise "undetectability" or optimize solely for detector evasion.
24. **Text-only detection cannot prove authorship.** Keep this limitation visible in CLI/API/MCP/UI outputs.
25. **Cryptographic provenance/watermarks are a distinct evidence class.** Do not blend them into stylometric scores.

## Required architecture separation

Keep these concepts separate in code and schemas:

### A. Detector observation
What an instrument returned:
- raw/native score,
- native score semantics and direction,
- detector verdict/abstention,
- detector/model/provider version,
- runtime and configuration,
- local/remote execution,
- optional calibrated probability plus calibration ID.

### B. Validation evidence
What is known about the detector:
- benchmark dataset and fingerprint,
- held-out split,
- domain/language/length/editing slice,
- AUROC/AUPRC,
- human false-positive rate at declared operating points,
- calibration error/Brier where probabilities are emitted,
- confidence intervals,
- evaluation date/version.

### C. Trust Map
Whether the current input is inside validated operating conditions. Initial dimensions:
- language coverage,
- text-length coverage,
- domain/genre coverage,
- editing/paraphrase robustness,
- nearest-slice human FPR evidence,
- detector-family diversity/disagreement,
- benign-transformation stability,
- temporal/provider-version stability.

Use qualitative states initially: **supported / partial / unknown / out_of_scope**. Do not invent a numeric "trust percentage" until one is empirically validated.

### D. Ensemble inference
Optional. If implemented, it must have:
- a fixed detector set/family definition,
- an explicit missing-detector policy,
- a separately fitted ensemble calibration artifact,
- independent held-out validation,
- an abstention policy,
- versioned provenance.

### E. Process provenance
Draft hashes/history, Git history, document revision evidence, trusted timestamps/signatures where available. This supports process evidence; it is not a text detector.

### F. Case file
Portable, reproducible audit artifact containing hashes, observations, versions, Trust Map, benchmark references, stability/drift evidence, provenance evidence and limitations. Raw input text is omitted by default.

## Detector adapter checklist

A detector PR is not ensemble-eligible merely because it runs.

Before eligibility:
1. Identify detector family and explain its independent value.
2. Record immutable model/checkpoint/provider identifiers where possible.
3. Document license, hardware, dependencies, network behavior, supported languages, minimum/recommended length and known limitations.
4. Implement protocol/schema validation.
5. Add deterministic unit tests and failure/timeout tests.
6. Benchmark on at least one in-domain and one out-of-domain slice.
7. Separate threshold-selection/calibration data from final test data.
8. Report AUROC, AUPRC and operating-point FPR/TPR.
9. If emitting probabilities, report Brier score and calibration error/reliability curves.
10. Test short text, edited/paraphrased text and benign formatting perturbations.
11. Add a versioned benchmark manifest.
12. Only then mark the adapter eligible for calibrated fusion.

## Benchmark discipline

Primary benchmark targets should include:
- RAID for broad model/domain/decoding/attack coverage,
- DetectRL for prompts, human revisions, errors, attacks and realistic scenarios,
- M4 for multilingual/multi-domain/multi-generator generalization.

Do not copy leaderboard numbers into the README as if they describe TextForensics. Run the exact committed version and archive the run manifest.

Every benchmark run should eventually capture:
- TextForensics git SHA,
- detector/model versions,
- dependency/environment lock,
- dataset name/version/fingerprint,
- split and filters,
- thresholds/calibration IDs,
- random seeds,
- hardware,
- runtime,
- per-slice metrics and confidence intervals.

## Drift observatory

A distinctive project capability is longitudinal detector reliability.

Maintain a stable, license-compatible probe corpus with immutable sample IDs/hashes. For versioned local detectors and authorized remote providers, record snapshots over time and report:
- score distribution shift,
- verdict/threshold flips,
- calibration drift,
- human-slice FPR changes,
- missing/changed provider version metadata,
- changed supported input regimes.

Never claim provider drift solely from one sample.

## Editing / "humanization"

The project may expose a writing-review layer, but the objective must be quality and false-positive diagnostics, not concealment. Suitable objectives include:
- clarity,
- specificity,
- removal of formulaic phrasing,
- preservation of author voice,
- semantic fidelity,
- identifying features correlated with false positives.

Never market "100% human", "undetectable", or guaranteed bypass.

## Security and privacy

Treat submitted text as sensitive:
- local by default,
- no raw text in logs,
- no raw text in case files unless opted in,
- redact provider errors that echo text,
- constrain remote requests and timeouts,
- make network use visible,
- pin/check model artifacts where practical,
- sanitize filenames and imported metadata.

## Pull-request self-review

Before a PR is ready, ask:
- Did I change score semantics?
- Did I accidentally call an uncalibrated score a probability?
- Could this increase false positives?
- Is the input regime supported?
- Are calibration/test sets disjoint?
- Did I add/update tests?
- Is network behavior explicit?
- Are model/data licenses compatible?
- Could the report be misread as proof of authorship?
- Did I preserve abstention and warnings?
- Does this duplicate an existing project rather than advance TextForensics' reliability-audit identity?

If any answer is unclear, stop and document it before merging.
