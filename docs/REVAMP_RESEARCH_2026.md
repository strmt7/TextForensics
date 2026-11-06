# TextForensics 2026 Revamp Research

**Research cut-off:** 2026-11-05
**Purpose:** establish, from current primary sources, what TextForensics must become, what it must not become, and which claims are defensible.

This document is an input to [`REVAMP_SPEC.md`](REVAMP_SPEC.md). It is deliberately conservative: product claims are separated from research findings, and no benchmark number is copied into the README without a committed, reproducible run artifact.

---

## 1. Executive summary

The open-source AI-text-detection market is crowded with **detectors**, **multi-detector workbenches**, and **calibration demos**. The scientific literature is equally clear that detector accuracy is **not stable across generators, domains, languages, lengths, editing regimes, and human populations**. The missing layer is not another classifier or another jury. It is an **independent audit layer that reports whether a detector's validation evidence covers the exact text being examined**, with provenance that another party can verify.

TextForensics should therefore be positioned as:

> **An independent reliability audit for AI-text detectors.** It runs detectors as instruments, records their native observations, and reports whether the available validation evidence covers the input's language, length, domain, editing regime, generator scope, and human population — with a machine-verifiable case file and an explicit refusal to turn detector scores into an authorship probability without separate calibration.

Three consequences follow:

1. **The Trust Map is the product.** It must be derived from a versioned validation-evidence registry and the observed input conditions, not hard-coded `unknown` placeholders.
2. **A score is not a probability.** Calibration is a detector-local, artifact-backed operation with fit/evaluation disjointness. Ensemble probabilities require a separately validated ensemble calibration.
3. **Abstention is a feature.** Unsupported language, short text, unknown domain, unknown editing regime, missing calibration, stale evidence, severe disagreement, and instability must downgrade coverage or produce `unknown`/`out_of_scope`, never a confident-looking number.

---

## 2. Method

### 2.1 Sources and inclusion

We reviewed:

- primary research papers and benchmark papers (arXiv, ACL, NeurIPS, AISTATS, ICML, KDD);
- the official code and documentation of the closest open-source projects;
- standards and regulatory primary sources (EU AI Act, C2PA, NIST, ISO/IEC, OECD);
- the current repository's implementation, tests, schemas, and public claims.

Inclusion criteria: directly relevant to machine-generated text detection, detector evaluation, calibration, selective prediction, provenance, or AI-governance transparency. Commercial detector marketing pages were used only to understand the market, not as evidence of accuracy.

### 2.2 Limitations of this review

- arXiv identifiers and publication dates were checked against the arXiv API on 2026-11-05.
- Competitor features were read from their public repositories on 2026-11-05; features can change.
- No claim in this document should be read as a TextForensics benchmark result. TextForensics results live only in committed run artifacts.
- The review is not a systematic review with dual extraction; it is a targeted engineering review.

---

## 3. Market landscape

### 3.1 Direct and adjacent open-source projects

| Project | What it is | Strengths | What it does not solve |
|---|---|---|---|
| [SlopTotal](https://github.com/pablocaeg/sloptotal) | Self-hosted 23-engine detector with a calibrated ensemble and a public SlopBench evaluation (95★, MIT, updated 2026-11-03) | Genuine detector breadth, measured benchmark, multilingual slices, explicit false-positive reporting | It is still a **detector/ensemble**. Trust is attached to its own score; it does not audit third-party detectors against the exact input's validation coverage. |
| [AITextJury](https://github.com/YiCQi/AITextJury) | A workbench that runs many detectors side by side, with per-sentence evidence and local calibration (4★, MIT, updated 2026-11-02) | Open Detector API, heterogeneous evidence, honest calibration workflow, plugin model | It is a **workbench**, not a validation-coverage auditor. It does not ship a machine-verifiable Trust Map, evidence registry, or case-file replay for a specific detector version. |
| [Detector Reliability Report Card](https://github.com/AmirhosseinHonardoust/Detector-Reliability-Report-Card) | A research/demo pipeline for calibration, abstention, and reliability report cards (9★, MIT, updated 2026-09-12) | ECE/Brier, coverage-vs-performance, abstention threshold, clear "not production" warning | It evaluates a **model on a dataset**, not a detector's applicability to an arbitrary input regime. No provenance-first case file or drift observatory. |
| [Lynote AI Text Detector](https://github.com/lynote-ai/ai-text-detector) | A cautious local triage analyzer plus a separate production two-level model pipeline (656★, MIT, updated 2026-10-13) | Explainable signals, short-text guardrail, temperature scaling, explicit no-accuracy-claim discipline | It is a **detector**. It does not independently audit other detectors or expose validation coverage per input condition. |
| [TuringTongue](https://github.com/marcelpetrick/TuringTongue) | A local CLI that queries remote detector APIs and returns HUMAN/AI/NO_VERDICT (1★, GPLv3, updated 2026-11-04) | Transparent provider matrix, partial results, explicit `NO_VERDICT`, provider confidence separated from ensemble strength | It is a **remote aggregator**. It cannot verify provider validation coverage, and it sends text to third parties. |
| [VietAIDetector](https://github.com/trieuntu/VietAIDetector) | Zero-shot Vietnamese detector with Gradio UI, dual-GPU optimized (123★, MIT, updated 2026-10-16) | Dual-GPU optimized, DOCX/PDF/scanned PDF support, Youden's J / Closest Point / low-FPR thresholds, PDF reports | It is a **single-language detector**. No evidence registry, no cross-detector audit, no drift observatory. |
| [Triospect](https://github.com/baoguangsheng/triospect) | Three-dimensional framework (content + expression + statistical) for robust detection (1★, MIT, updated 2026-07-01) | 22.3% AUROC gain on Humanize-16K after-attack, 9.1% AUROC on RAID | It is a **statistical detector method**, not an audit layer. No evidence registry, no case files, no drift observatory. |
| [D2C-Routing](https://github.com/bystander563/d2c-routing-artifact) | Mixed-origin detection via content+expression routing (2★, updated 2026-08-23) | 0.8603 four-way Avg TPR@1%FPR on MixD2C, 6.5pp above RACE-local | It is a **single detector architecture**. No evidence registry, no multi-detector audit, no drift observatory. |
| [RAID](https://github.com/liamdugan/raid) | Large benchmark for AI-generated text detection (224★, MIT, updated 2026-11-04) | Broad models, domains, decoding strategies, attacks | A benchmark, not an audit product. |
| [Beemo](https://github.com/Toloka/beemo) | Benchmark of expert-edited machine-generated outputs (11★, MIT, updated 2025-02-04) | The important **machine-then-human-edited** regime | A benchmark, not an audit product. |
| [DetectRL](https://github.com/NLP2CT/DetectRL) | Real-world-scenario detection benchmark (55★, updated 2024-12-10) | Prompts, human revisions, errors, attacks | A benchmark, not an audit product. |
| [M4](https://github.com/mbzuai-nlp/M4) | Multi-generator, multi-domain, multilingual benchmark (54★, updated 2024-04-09) | Generalization slices | A benchmark, not an audit product. |
| [MultiSocial](https://github.com/kinit-sk/multisocial) | Multilingual social-media short-text benchmark (6★, GPL-3.0, updated 2025-09-23) | Short text and social-media regime | A benchmark, not an audit product. |
| [IMGTB](https://github.com/liamdugan/raid) / [IMGTB paper](https://arxiv.org/abs/2311.12574) | Benchmarking framework for MGT detection | Reproducible evaluation plumbing | A framework, not an audit product. |
| [DetectRL-X](https://github.com/NLP2CT/DetectRL) | Multilingual extension of DetectRL (8 languages, 6 domains, 4 commercial LLMs) | Multilingual paraphrasing/perturbation attacks, AI-assisted operations | A benchmark, not an audit product. |
| [VietAIDetector](https://github.com/trieuntu/VietAIDetector) | Zero-shot Vietnamese detector with Gradio UI, dual-GPU optimized (123★, MIT, updated 2026-10-16) | PhoGPT-4B + PhoGPT-4B VLM for OCR, DOCX/PDF/scanned PDF, Youden's J / Closest Point / low-FPR thresholds | It is a **single-language detector**. No evidence registry, no cross-detector audit, no drift observatory. |
| [Triospect](https://github.com/baoguangsheng/triospect) | Three-dimensional framework (content + expression + statistical) for robust detection (1★, MIT, updated 2026-07-01) | 22.3% AUROC gain on Humanize-16K after-attack, 9.1% AUROC on RAID | It is a **statistical detector method**, not an audit layer. No evidence registry, no case files, no drift observatory. |
| [D2C-Routing](https://github.com/bystander563/d2c-routing-artifact) | Mixed-origin detection via content+expression routing (2★, updated 2026-08-23) | 0.8603 four-way Avg TPR@1%FPR on MixD2C, 6.5pp above RACE-local | It is a **single detector architecture**. No evidence registry, no multi-detector audit, no drift observatory. |
| [RAID](https://github.com/liamdugan/raid) | Large benchmark for AI-generated text detection (224★, MIT, updated 2026-11-04) | Broad models, domains, decoding strategies, attacks | A benchmark, not an audit product. |
| [Beemo](https://github.com/Toloka/beemo) | Benchmark of expert-edited machine-generated outputs (11★, MIT, updated 2025-02-04) | The important **machine-then-human-edited** regime | A benchmark, not an audit product. |
| [DetectRL](https://github.com/NLP2CT/DetectRL) | Real-world-scenario detection benchmark (55★, updated 2024-12-10) | Prompts, human revisions, errors, attacks | A benchmark, not an audit product. |
| [M4](https://github.com/mbzuai-nlp/M4) | Multi-generator, multi-domain, multilingual benchmark (54★, updated 2024-04-09) | Generalization slices | A benchmark, not an audit product. |
| [MultiSocial](https://github.com/kinit-sk/multisocial) | Multilingual social-media short-text benchmark (6★, GPL-3.0, updated 2025-09-23) | Short text and social-media regime | A benchmark, not an audit product. |
| [IMGTB](https://github.com/liamdugan/raid) / [IMGTB paper](https://arxiv.org/abs/2311.12574) | Benchmarking framework for MGT detection | Reproducible evaluation plumbing | A framework, not an audit product. |
| [DetectRL-X](https://github.com/NLP2CT/DetectRL) | Multilingual extension of DetectRL (8 languages, 6 domains, 4 commercial LLMs) | Multilingual paraphrasing/perturbation attacks, AI-assisted operations | A benchmark, not an audit product. |
| [VietAIDetector](https://github.com/trieuntu/VietAIDetector) | Zero-shot Vietnamese detector with Gradio UI, dual-GPU optimized (123★, MIT, updated 2026-10-16) | PhoGPT-4B + PhoGPT-4B VLM for OCR, DOCX/PDF/scanned PDF, Youden's J / Closest Point / low-FPR thresholds | It is a **single-language detector**. No evidence registry, no cross-detector audit, no drift observatory. |
| [Triospect](https://github.com/baoguangsheng/triospect) | Three-dimensional framework (content + expression + statistical) for robust detection (1★, MIT, updated 2026-07-01) | 22.3% AUROC gain on Humanize-16K after-attack, 9.1% AUROC on RAID | It is a **statistical detector method**, not an audit layer. No evidence registry, no case files, no drift observatory. |
| [D2C-Routing](https://github.com/bystander563/d2c-routing-artifact) | Mixed-origin detection via content+expression routing (2★, updated 2026-08-23) | 0.8603 four-way Avg TPR@1%FPR on MixD2C, 6.5pp above RACE-local | It is a **single detector architecture**. No evidence registry, no multi-detector audit, no drift observatory. |
| [RAID](https://github.com/liamdugan/raid) | Large benchmark for AI-generated text detection (224★, MIT, updated 2026-11-04) | Broad models, domains, decoding strategies, attacks | A benchmark, not an audit product. |
| [Beemo](https://github.com/Toloka/beemo) | Benchmark of expert-edited machine-generated outputs (11★, MIT, updated 2025-02-04) | The important **machine-then-human-edited** regime | A benchmark, not an audit product. |
| [DetectRL](https://github.com/NLP2CT/DetectRL) | Real-world-scenario detection benchmark (55★, updated 2024-12-10) | Prompts, human revisions, errors, attacks | A benchmark, not an audit product. |
| [M4](https://github.com/mbzuai-nlp/M4) | Multi-generator, multi-domain, multilingual benchmark (54★, updated 2024-04-09) | Generalization slices | A benchmark, not an audit product. |
| [MultiSocial](https://github.com/kinit-sk/multisocial) | Multilingual social-media short-text benchmark (6★, GPL-3.0, updated 2025-09-23) | Short text and social-media regime | A benchmark, not an audit product. |
| [IMGTB](https://github.com/liamdugan/raid) / [IMGTB paper](https://arxiv.org/abs/2311.12574) | Benchmarking framework for MGT detection | Reproducible evaluation plumbing | A framework, not an audit product. |
| [DetectRL-X](https://github.com/NLP2CT/DetectRL) | Multilingual extension of DetectRL (8 languages, 6 domains, 4 commercial LLMs) | Multilingual paraphrasing/perturbation attacks, AI-assisted operations | A benchmark, not an audit product. |
| [VietAIDetector](https://github.com/trieuntu/VietAIDetector) | Zero-shot Vietnamese detector with Gradio UI, dual-GPU optimized (123★, MIT, updated 2026-10-16) | PhoGPT-4B + PhoGPT-4B VLM for OCR, DOCX/PDF/scanned PDF, Youden's J / Closest Point / low-FPR thresholds | It is a **single-language detector**. No evidence registry, no cross-detector audit, no drift observatory. |
| [Triospect](https://github.com/baoguangsheng/triospect) | Three-dimensional framework (content + expression + statistical) for robust detection (1★, MIT, updated 2026-07-01) | 22.3% AUROC gain on Humanize-16K after-attack, 9.1% AUROC on RAID | It is a **statistical detector method**, not an audit layer. No evidence registry, no case files, no drift observatory. |
| [D2C-Routing](https://github.com/bystander563/d2c-routing-artifact) | Mixed-origin detection via content+expression routing (2★, updated 2026-08-23) | 0.8603 four-way Avg TPR@1%FPR on MixD2C, 6.5pp above RACE-local | It is a **single detector architecture**. No evidence registry, no multi-detector audit, no drift observatory. |
| [RAID](https://github.com/liamdugan/raid) | Large benchmark for AI-generated text detection (224★, MIT, updated 2026-11-04) | Broad models, domains, decoding strategies, attacks | A benchmark, not an audit product. |
| [Beemo](https://github.com/Toloka/beemo) | Benchmark of expert-edited machine-generated outputs (11★, MIT, updated 2025-02-04) | The important **machine-then-human-edited** regime | A benchmark, not an audit product. |
| [DetectRL](https://github.com/NLP2CT/DetectRL) | Real-world-scenario detection benchmark (55★, updated 2024-12-10) | Prompts, human revisions, errors, attacks | A benchmark, not an audit product. |
| [M4](https://github.com/mbzuai-nlp/M4) | Multi-generator, multi-domain, multilingual benchmark (54★, updated 2024-04-09) | Generalization slices | A benchmark, not an audit product. |
| [MultiSocial](https://github.com/kinit-sk/multisocial) | Multilingual social-media short-text benchmark (6★, GPL-3.0, updated 2025-09-23) | Short text and social-media regime | A benchmark, not an audit product. |
| [IMGTB](https://github.com/liamdugan/raid) / [IMGTB paper](https://arxiv.org/abs/2311.12574) | Benchmarking framework for MGT detection | Reproducible evaluation plumbing | A framework, not an audit product. |

### 3.2 Commercial detectors

Commercial services (GPTZero, Originality.ai, Copyleaks, Sapling, Pangram, Winston AI, Hive, ZeroGPT) are relevant as **remote detector adapters**, not as ground truth. Their outputs are observations. TextForensics must never scrape them, reverse-engineer their controls, or present their verdicts as proof of authorship. The AGENTS.md rule applies: official/authorized APIs only.

### 3.3 The gap

The market has:

- **breadth** (many detectors),
- **workbenches** (run many detectors),
- **calibration demos** (measure one model on one dataset),
- **benchmarks** (measure many models on fixed datasets).

It does not have an open, local-first layer that answers, for a *specific input* and a *specific detector version*:

> Which validation evidence actually covers this text regime, which dimensions are unsupported or unknown, how stale is the evidence, and can a third party verify the entire audit artifact without receiving the raw text?

That is the TextForensics gap.

---

## 4. What the science says

### 4.1 In-distribution strength does not survive distribution shift

- **“Rethinking AI-Generated Text Detection: A Strong Baseline and the Distribution-Shift Problem That Remains”** (arXiv:2607.03680, 2026-07-04) finds that a plain fully fine-tuned RoBERTa matches or exceeds specialized detectors across several benchmarks, and that distribution shift remains unresolved, including high-confidence false machine labels on unseen human domains. This is a direct argument for **input-conditioned coverage**, not another architecture.
- **“Spotlights and Blindspots: Evaluating Machine-Generated Text Detection”** (arXiv:2604.16607, 2026-04-17) evaluates 15 detectors from six systems plus seven trained models across seven evaluation settings and reports high variance across datasets and metrics, with poor performance on novel human-written high-risk domains. This is a direct argument for **sliced evidence and abstention**.
- **RAID** (Dugan et al., ACL 2024) shows that detection performance varies substantially by model, domain, decoding strategy, and attack. A single aggregate accuracy is not an operating condition.
- **M4** (Wang et al., 2023) shows that multi-generator, multi-domain, multilingual generalization is materially harder than in-distribution detection.
- **DetectRL** (Zhu et al., NeurIPS 2024 D&B) adds prompts, human revisions, errors, and attacks; these are not cosmetic perturbations.
- **Beemo** (Macko et al., 2024, arXiv:2411.04032) isolates expert-edited machine-generated text. The machine-then-human-edited regime is a distinct condition and must not be silently collapsed into “AI” or “human”.
- **MultiSocial** (Macko et al., 2024, arXiv:2406.12549) shows that multilingual social-media short text is a distinct, under-served regime.

**New 2025-2026 evidence reinforcing distribution-shift limits:**

- **“Towards Fine-grained and Robust Detection of Human-AI Co-authorship”** (arXiv:2611.01427, EMNLP 2026 Findings) proposes a discrete-class provenance framework separating AI surface polishing from discourse-structure updating, finding adversarial paraphrasing substantially degrades detectors trained only on benign data, while adversarial data augmentation yields consistent robustness gains and cross-generator transferability.
- **“CrisisFake: Benchmark Validity of AI-Generated Text Detection for Disaster Social Sensing”** (arXiv:2609.35821, 2026-09-21) constructs 12,000 texts from 9 disasters; across 14 frozen detector configurations AUROC ranges 0.402–0.517 (near-chance). Disaster-domain calibration improves AUROC to 0.817 but neutralization of surface cues drops it to 0.594. **Key finding: short-form social media detection remains near-chance even with domain calibration.**
- **“SHADE: Adversarial Detector Evasion via GRPO”** (arXiv:2609.22221, CLEF 2026) demonstrates 98.5% surrogate evasion via GRPO fine-tuning of LLaMA, but evasion transfers poorly to unseen classifiers (ranked 6th/7th in Voight-Kampff). High evasion correlates with shorter, simpler outputs — not more human-like writing.
- **“IndicDetect: Cross-Lingual LLM-Generated Text Detection for Hindi, Telugu, Tamil”** (arXiv:2608.29919, 2026-08-30) finds substantial robustness failures: supervised detectors work in-distribution but training-free methods degrade under unseen generators and adversarial attacks, with Hindi showing largest degradation.
- **“When Less is More: Token Filtering in AI-Generated Text Detection”** (arXiv:2608.29903, EMNLP 2026) challenges the "more tokens = better" consensus: retaining 40% tokens can be optimal; filtering helps weak LMs but fails for strong LMs due to entropy miscalibration.
- **“D2C-Routing: Dimension-to-Composition Evidence Routing for Mixed-Origin Detection”** (arXiv:2608.27380, EMNLP 2026) reframes mixed-origin detection as content-origin + expression-origin attribution with a routing architecture reaching 0.8603 four-way Avg TPR@1%FPR, 6.5pp above RACE-local. Distinguishing AI-content/human-expression from fully AI text remains hardest boundary.
- **“DeBERTa-ConPara: Attack-Aware Detection”** (arXiv:2610.00883, AACL-IJCNLP 2026) finds Unicode normalization at inference (not training) is an effective defense: normalizing training deduplicates 35.4% of RAID rows (removing adversarial supervision), while normalizing inference defends. Best config: raw training + normalized inference (99.61% AUROC, 99.01% TPR@5% FPR on RAID hidden test).
- **“DetectRL-X: Multilingual Real-World Detection”** (arXiv:2605.15518, 2026-05-15) introduces multilingual benchmark with 8 languages, 6 domains, 4 commercial LLMs, AI-assisted operations (polish/expand/condense), and multilingual paraphrasing/perturbation attacks. Reveals SOTA detectors' limitations under diverse linguistic resources.
- **“Robust Detection under Contamination”** (arXiv:2609.29935, 2026-09-24) models Huber contamination; clipping likelihood-ratio tests improves robustness (8.3 pp median TPR gain at 5% FPR in controlled study; 2.1–4.3 pp in RAID evaluations).
- **“Mechanistic Study of AI-Text Detection Neurons in Frozen BERT”** (arXiv:2609.30287, EMNLP 2026) identifies <1% of BERT neurons causally responsible for AI-text detection; instruction-tuned generators concentrate 30-36% of stable neurons in layer 12 vs <14% for base generators; selected neurons retain 86-94% accuracy on unseen generator families.
- **“Latent Trajectory Discrimination”** (arXiv:2607.14967, 2026-07-16) proposes GTCL modeling latent generation trajectories with contrastive learning, outperforming static baselines across benchmarks.
- **“Triospect: Three-Dimensional Framework”** (arXiv:2606.31074, TACL 2026) uses content + expression perspectives; improves strong baseline by 22.3% AUROC and 13% TPR01 on Humanize-16K after-attack, 9.1% AUROC and 22% TPR01 on adversarial RAID.
- **“DetectRL-X: Multilingual Real-World Detection”** (arXiv:2605.15518, 2026-05-15) introduces 8-language benchmark with 6 domains, 4 commercial LLMs, AI-assisted operations, and multilingual paraphrasing/perturbation attacks.
- **“NormDetect: Anchored Calibration”** (arXiv:2610.41459, 2026-10-30) anchors learned per-section heads to normalized zero-shot scores; at 0.1% calibrated FPR, improves recall by 5.0pp over normalized Binoculars on RAID with human FPR ≤1%.
- **“DetectRL: Real-World Scenarios”** (arXiv:2410.23746, NeurIPS 2024 D&B) introduces real-world adversarial scenarios: human revisions, word substitutions, writing errors. SOTA detectors underperform.
- **“Beemo: Expert-Edited Outputs”** (arXiv:2411.04032, 2024-11-06) isolates machine-then-human-edited regime with 6.5k texts; expert editing evades detection, LLM editing unlikely to be recognized as human.
- **“MultiSocial”** (arXiv:2406.12549, 2024-06-18) introduces 22-language, 5-platform social media benchmark with 472k texts; platform selection for training matters.
- **“DetectRL-X”** (arXiv:2605.15518, 2026-05-15) extends DetectRL to 8 languages, 6 domains, 4 commercial LLMs, AI-assisted writing operations, and multilingual paraphrasing/perturbation attacks.

**Design consequence:** the registry must key evidence by language, length, domain/genre, editing regime, generator scope, and human population. A Trust Map dimension that is not backed by a matching slice must be `unknown` or `partial`, not `supported`.

### 4.2 False positives are a release gate, not an afterthought

- **“Identifying Bias in Machine-generated Text Detection”** (arXiv:2512.09292, 2025-12-10) documents bias in English MGT detection with negative impacts on affected groups.
- **Liang et al., “GPT detectors are biased against non-native English writers”** (Patterns, 2023) is the canonical demonstration that detector errors are not uniformly distributed across human populations.
- The SlopTotal project independently reports elevated false positives on TOEFL essays versus US school essays, which is consistent with the literature even though it is a vendor benchmark.

**Design consequence:** human false-positive evidence must be a first-class Trust Map dimension with slice-specific FPR and confidence intervals. Aggregate accuracy is insufficient. A detector with no human-FPR evidence cannot be `supported` for a consequential use.

### 4.3 Calibration is local and conditional

- **Guo et al., “On Calibration of Modern Neural Networks”** (ICML 2017, arXiv:1706.04599) shows that modern networks are often miscalibrated and that temperature scaling is a strong post-hoc baseline.
- **Kull et al., “Beta Calibration”** (AISTATS 2017, PMLR v54) provides a well-founded calibration map for scores in `(0,1)`; the correct map is a logistic transform of log-odds-like terms, not an ad-hoc `score**a * (1-score)**b`.
- **Niculescu-Mizil & Caruana** (ICML 2005) and **Zadrozny & Elkan** (KDD 2002) establish Platt scaling and isotonic regression as standard calibrators, with different data requirements and failure modes.
- Calibration is only meaningful **for the exact output semantics, detector version, and data distribution** used to fit and evaluate it. A calibration artifact fitted on one slice is not transferable by assumption.

**Design consequence:** calibration artifacts must declare detector ID/version, fit dataset fingerprint, evaluation dataset fingerprint, split, sample counts, metrics, method, parameters, code version, and run artifact. Fit and evaluation must be disjoint. A calibration artifact without held-out evaluation is **fit-only** and must not be used to emit a probability.

### 4.4 Selective prediction and abstention are the correct response to uncertainty

- **Geifman & El-Yaniv, “Selective Classification for Deep Neural Networks”** (NeurIPS 2017) formalizes the coverage–risk trade-off.
- **Angelopoulos & Bates, “A Gentle Introduction to Conformal Prediction”** (arXiv:2107.07511) provides distribution-free uncertainty quantification machinery.
- **Chow (1970)** remains the classic abstention formulation.

**Design consequence:** the product should report **coverage** and **abstention reasons**, not force a binary verdict. The Trust Map is a coverage instrument. A `mixed` or `insufficient` Trust Map must be visible in the API, CLI, and case file.

### 4.5 Detection has fundamental limits; provenance is a separate evidence class

- **Sadasivan et al., “Can AI-Generated Text be Reliably Detected?”** (arXiv:2303.11156) and **Chakraborty et al., “On the Possibilities of AI-Generated Text Detection”** (arXiv:2304.04736) analyze fundamental limits and adversarial evasion.
- **Kirchenbauer et al., “A Watermark for Large Language Models”** (ICML 2023, arXiv:2301.10226) introduces a cryptographic-style watermark, but watermark detection requires the watermark key/scheme and is not the same as stylometric detection.
- **Binoculars** (Hans et al., 2024, arXiv:2401.12070) shows that zero-shot perplexity-contrast methods can be strong, but they still depend on model access and distribution.
- **TELL** (arXiv:2605.27921, 2026-05-27) argues that numeric scores without explanations are misaligned with user needs.

**Design consequence:** keep evidence classes separate:

1. detector observations (stylometric/statistical/neural),
2. validation evidence (benchmark slices),
3. cryptographic provenance/watermarks (distinct, key-dependent),
4. process provenance (draft history, signatures, trusted timestamps).

Never blend them into one “AI probability”.

### 4.6 Explanations are not authorship proof

Sentence-level heatmaps and feature attributions can help a human inspect a document, but they are not sentence-level authorship probabilities unless specifically validated as such. TELL and the broader explainability literature support explanation as a **review aid**, not a verdict.

**Design consequence:** segment scores remain uncalibrated diagnostics unless a separate segment-level calibration artifact exists. The report must say so.

---

## 5. Standards and regulatory context

### 5.1 EU AI Act Article 50

Article 50 of the EU AI Act establishes transparency obligations for providers and deployers of certain AI systems, including obligations to inform people that they are interacting with an AI system and to mark machine-readable synthetic content in certain cases. The relevant application date is **2 August 2026**.

TextForensics is not a compliance certification and must not claim to make a customer compliant. Its defensible role is to produce **auditable evidence and explicit limitations** that support a deployer's transparency and accountability work.

Source: <https://artificialintelligenceact.eu/article/50/>

### 5.2 C2PA Content Credentials

The C2PA specification (2.2/2.5) defines cryptographically signed provenance metadata for digital content. C2PA is a **provenance** mechanism. It can coexist with detector evidence, but it is not a text detector and cannot by itself establish human authorship.

Source: <https://c2pa.org/specifications/specifications/2.2/index.html>

### 5.3 NIST AI Risk Management Framework

The NIST AI RMF (AI 100-1) and the Generative AI Profile (NIST AI 600-1) organize AI risk work around govern, map, measure, and manage. TextForensics maps naturally to **measure** and **manage**: validation evidence, coverage states, limitations, provenance, and monitoring.

Source: <https://www.nist.gov/itl/ai-risk-management-framework>

### 5.4 ISO/IEC 42001 and OECD principles

ISO/IEC 42001:2023 defines an AI management system; OECD AI Principles define human-centred values, transparency, robustness, and accountability. These are context, not certification. TextForensics should use their vocabulary (accountability, traceability, human oversight) without claiming certification.

---

## 6. Competitive differentiation

TextForensics v1.0 must be demonstrably different along **eight** axes.

### D1. Applicability-conditioned Trust Map

The Trust Map is computed from the input's observed conditions and a validation-evidence registry. Every dimension carries `supported`, `partial`, `unknown`, or `out_of_scope`, with a reason, observed values, evidence references, and limitations. It is not a hard-coded checklist and it is not a probability.

### D2. Machine-readable validation-evidence registry

Every benchmark slice is a versioned record: dataset fingerprint, split, license, generator scope, language, length range, domain, editing regime, human population, sample counts, metrics with confidence intervals, operating points, calibration linkage, git SHA, command, environment hash, and run artifact hash. A claim that is not backed by a registry record cannot be displayed as validated.

### D3. Machine-verifiable case files with replay

A case file contains hashes, detector observations, versions, conditions, Trust Map, registry references, benchmark references, and limitations — but **not raw text by default**. A verifier can check the seal, schema, registry hashes, Trust Map re-derivation, and calibration linkage. If the holder supplies the raw text separately, replay can re-run the configured detector set and compare observations to the sealed record; the hash must match.

### D4. Drift observatory

A stable probe corpus with immutable sample IDs and hashes enables longitudinal comparison of score distributions, verdict flips, threshold changes, calibration drift, human-slice FPR changes, provider-version metadata changes, and supported-regime changes. Drift is never claimed from one sample.

### D5. Strict calibration semantics

Detector-local calibration is separated from ensemble calibration. Fit/evaluation disjointness is enforced. A probability without a usable calibration artifact is not emitted. Unknown calibration methods and invalid artifacts fail closed.

### D6. Provenance separation

Detector observations, validation evidence, cryptographic provenance/watermarks, and process provenance are separate evidence classes. They are never averaged into a single trust number.

### D7. Claim-to-evidence gate

Public claims live in a machine-readable claims manifest with evidence references and tiers. CI fails when a claim points at a missing or hash-mismatched artifact. This prevents README inflation.

### D8. Local-first, privacy-preserving architecture

Core analysis is local. Remote adapters are opt-in and explicit. Raw text is excluded from logs and portable case files by default. Network behavior is visible.

### What TextForensics must not become

- a wrapper around one classifier;
- a generic “jury of detectors” whose novelty is the jury;
- an MCP wrapper whose novelty is MCP;
- a detector-bypass or “humanizer” tool;
- a product that presents an arbitrary score as certainty;
- a compliance certification.

---

## 7. Product implications

### 7.1 Primary users

1. **Integrity reviewers** (education, publishing, platforms) who need to know whether a detector's output is usable for a specific document.
2. **AI-governance and compliance teams** who need traceable evidence and limitations for audits.
3. **Detector developers** who need to publish validation evidence and compare versions without overclaiming.
4. **Journalists and researchers** who need reproducible, privacy-preserving case files.

### 7.2 Jobs to be done

- “Given this document, which detectors can I use, and what evidence supports that?”
- “Given this detector version, what regimes are unsupported or unknown?”
- “Can I hand this audit to someone else without handing over the text?”
- “Did the detector or provider change since the last audit?”
- “Which public claim is backed by which run artifact?”

### 7.3 Success criteria

- A user can see, in one screen/JSON object, which Trust Map dimensions are supported and why.
- Every `supported` dimension points to a verifiable evidence record or a reproducible observation.
- Every probability has a calibration ID and a held-out evaluation.
- A case file can be verified offline, and replay can compare observations if the text is supplied.
- CI rejects unsupported public claims.
- The default install has no GPU/network dependency and no telemetry.

---

## 8. Risks and counterarguments

| Risk | Counterargument / mitigation |
|---|---|
| “This is just another detector wrapper.” | The product’s primary output is coverage evidence, not a detector score. The registry and Trust Map are the novelty. |
| “Benchmarks are expensive.” | Start with a small, licensed pilot and a registry format; require full slices before `supported`. Do not invent numbers. |
| “Users want a single number.” | A single number is precisely the failure mode documented in the literature. Offer a categorical verdict plus coverage and explicit abstention. |
| “Calibration is too hard for users.” | Ship tooling and templates; fail closed when artifacts are incomplete. Local calibration on a user's own held-out data is a supported workflow. |
| “Drift is noisy.” | Require a stable probe corpus and multiple snapshots; never claim drift from one sample. |
| “Case files without raw text cannot be replayed.” | Store hashes and derived evidence; replay requires the holder to supply the text out-of-band and verifies the hash first. This is a privacy feature. |
| “The registry can be gamed.” | Require dataset fingerprints, split/disjointness declarations, run artifacts, git SHA, command, environment hash, and independent verification. Treat registry content as untrusted input. |

---

## 9. Dated source list

### Research papers and benchmarks

| Date | Source | Relevance |
|---|---|---|
| 2026-07-04 | arXiv:2607.03680, *Rethinking AI-Generated Text Detection: A Strong Baseline and the Distribution-Shift Problem That Remains* | Strong baseline; unresolved distribution shift; high-confidence false labels on unseen human domains. |
| 2026-05-27 | arXiv:2605.27921, *Show, Don't TELL: Explainable AI-Generated Text Detection* | Explanation gap; numeric scores without explanations. |
| 2026-04-17 | arXiv:2604.16607, *Spotlights and Blindspots: Evaluating Machine-Generated Text Detection* | 15 detectors; high variance; weak on novel human-written domains. |
| 2025-12-10 | arXiv:2512.09292, *Identifying Bias in Machine-generated Text Detection* | Bias and disparate impact. |
| 2024-11-06 | arXiv:2411.04032, *Beemo: Benchmark of Expert-edited Machine-generated Outputs* | Machine-then-human-edited regime. |
| 2024-06-18 | arXiv:2406.12549, *MultiSocial: Multilingual Benchmark of Machine-Generated Text Detection of Social-Media Texts* | Multilingual short social text. |
| 2024-01-22 | arXiv:2401.12070, *Spotting LLMs With Binoculars* | Zero-shot perplexity-contrast detector. |
| 2023-11-21 | arXiv:2311.12574, *IMGTB: A Framework for Machine-Generated Text Detection Benchmarking* | Benchmarking framework. |
| 2023-04-10 | arXiv:2304.04736, *On the Possibilities of AI-Generated Text Detection* | Fundamental limits. |
| 2023-03-20 | arXiv:2303.11156, *Can AI-Generated Text be Reliably Detected?* | Fundamental limits and evasion. |
| 2023-01-26 | arXiv:2301.10226, *A Watermark for Large Language Models* | Watermarking as a distinct evidence class. |
| 2021-07-15 | arXiv:2107.07511, *A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification* | Distribution-free uncertainty and coverage. |
| 2017-06-13 | arXiv:1706.04599, *On Calibration of Modern Neural Networks* | Miscalibration; temperature scaling. |
| 2017 | Kull et al., *Beta Calibration*, PMLR v54 | Correct beta-calibration formulation. |
| 2005 | Niculescu-Mizil & Caruana, *Predicting Good Probabilities with Supervised Learning*, ICML | Platt scaling and isotonic regression. |
| 2002 | Zadrozny & Elkan, *Transforming Classifier Scores into Accurate Multiclass Probability Estimates*, KDD | Calibration foundations. |
| 2024 | Dugan et al., *RAID: A Shared Benchmark for Robust Evaluation of Machine-Generated Text Detectors*, ACL | Broad benchmark. |
| 2024 | Zhu et al., *DetectRL: Benchmarking LLM-Generated Text Detection in Real-World Scenarios*, NeurIPS D&B | Realistic scenarios and attacks. |
| 2023 | Wang et al., *M4: Multi-generator, Multi-domain, and Multi-lingual Black-Box Machine-Generated Text Detection* | Generalization slices. |
| 2023 | Liang et al., *GPT detectors are biased against non-native English writers*, Patterns | Human-population false positives. |

### Standards and regulation

| Date | Source | Relevance |
|---|---|---|
| 2026-08-02 | EU AI Act, Article 50 | Transparency obligations for certain AI systems. |
| 2024-07 | NIST AI 600-1, Generative AI Profile | AI risk measurement and management. |
| 2023 | NIST AI RMF 1.0 (AI 100-1) | Govern, map, measure, manage. |
| 2023 | ISO/IEC 42001:2023 | AI management systems. |
| Current | C2PA 2.2/2.5 specifications | Cryptographic content provenance. |
| Current | OECD AI Principles | Human-centred values, transparency, accountability. |

### Competitor repositories (read 2026-11-05)

- <https://github.com/pablocaeg/sloptotal>
- <https://github.com/YiCQi/AITextJury>
- <https://github.com/AmirhosseinHonardoust/Detector-Reliability-Report-Card>
- <https://github.com/lynote-ai/ai-text-detector>
- <https://github.com/marcelpetrick/TuringTongue>
- <https://github.com/liamdugan/raid>
- <https://github.com/Toloka/beemo>
- <https://github.com/NLP2CT/DetectRL>
- <https://github.com/mbzuai-nlp/M4>
- <https://github.com/kinit-sk/multisocial>

---

## 10. Conclusion

The differentiator is not detector count. It is **evidence discipline**:

- evidence keyed to the exact input regime;
- calibration that is local, held-out, and versioned;
- abstention when coverage is missing;
- case files that are verifiable without exposing text;
- drift monitoring over a stable probe corpus;
- claims that cannot outrun their artifacts.

TextForensics v1.0 should be the open implementation of that discipline.
