# Benchmarking and calibration standard

Performance claims are part of the scientific surface of TextForensics. Treat them like code.

## Benchmark families

Use multiple public benchmarks because no single dataset represents deployment:

- **RAID** — broad generator, domain, decoding and robustness coverage: https://github.com/liamdugan/raid
- **DetectRL** — realistic prompts, human revision, writing errors and varying lengths: https://github.com/NLP2CT/DetectRL
- **M4** — multi-generator, multi-domain and multilingual generalization: https://github.com/mbzuai-nlp/M4

Additional datasets require clear license, provenance and evaluation purpose.

## Split discipline

Never use the final evaluation split for model training, detector selection, threshold selection, calibration, ensemble weighting or prompt tuning.

Keep conceptually separate:
1. development/training;
2. threshold-selection data where needed;
3. calibration data;
4. final held-out evaluation.

Derivatives of the same source document must stay in the same partition. Record deterministic split rules and prevent source/near-duplicate leakage.

## Dataset fingerprints

Every serious run should record:
- dataset name and source,
- version/revision and retrieval date,
- license,
- file checksums,
- filters,
- sample counts,
- split method,
- split fingerprints.

Do not silently mutate a benchmark under the same name.

## Required metrics

### Discrimination
- AUROC
- AUPRC

### Declared operating points
- TP / FP / TN / FN
- precision
- recall / TPR
- specificity
- human false-positive rate
- false-negative rate

Prefer explicit low-FPR operating points. Aggregate accuracy alone is not sufficient.

### Probability calibration
Only for outputs explicitly defined as probabilities:
- Brier score
- expected calibration error or clearly documented equivalent
- reliability-diagram/bin data

### Abstention
- coverage
- selective accuracy/risk
- FPR/TPR on covered samples
- abstention reasons by slice

### Efficiency
- latency/throughput
- peak memory when practical
- CPU/GPU/runtime environment

## Confidence intervals

Release-quality claims need uncertainty estimates, preferably paired bootstrap or another justified method. Preserve paired structure when comparing detectors on the same samples.

## Mandatory slices

Where metadata exists, report by:
- generator/model family
- domain/genre
- language
- word/token length
- decoding regime
- editing/revision regime
- relevant human writing cohort/style when ethical and supported

Never infer sensitive demographic attributes from text merely to create slices.

## Human false-positive audit

For each proposed operating point:
1. identify the human evaluation population;
2. report sample count/provenance;
3. report FPR with uncertainty;
4. inspect highest-scoring false positives;
5. check clustering by domain/language/length/style;
6. record failure categories without publishing private text.

Do not hide an uncomfortable slice by excluding it.

## Detector comparison

- preserve native scores;
- never compare score magnitudes as if they share semantics;
- compare metrics on the same samples where possible;
- use paired analysis;
- count errors, unavailable results and abstentions;
- state the supported operating regime.

## Ensemble evaluation

Evaluate:
1. each component;
2. a simple baseline;
3. the proposed fusion method;
4. ablations removing each detector family.

Also measure error correlation, prediction correlation, marginal value, missing-adapter behavior and final ensemble calibration.

Averaging detector probabilities is a baseline, not proof of calibrated fusion.

## Robustness

Maintain two categories.

**Benign stability:** meaning-preserving representation changes such as whitespace, Unicode punctuation, line wrapping and markup/list normalization.

**Real-world revision robustness:** benchmark-provided or clearly specified human revision, paraphrase, noise, mixed-origin text and translation where appropriately labeled.

A large shift under benign changes is evidence of instrumental fragility.

## Run manifests

Every serious run should produce a machine-readable manifest with:
- TextForensics git SHA;
- dataset/split fingerprint;
- detector/model/config versions;
- calibration ID;
- threshold policy;
- random seeds;
- environment/hardware;
- timestamps;
- metrics artifact references.

## Calibration artifacts

A calibration artifact identifies:
- score semantics;
- detector/version/config;
- calibration method;
- calibration dataset fingerprint/slice;
- sample counts;
- output semantics;
- metrics before/after calibration;
- creation git SHA/date;
- validity limitations.

A detector or provider version change invalidates the assumption that an older calibration still applies until tested.

## README publication rule

Do not publish accuracy/superiority/state-of-the-art or low-FPR claims unless the exact result is reproducible from a committed run manifest and the evaluation conditions sit next to the claim.
