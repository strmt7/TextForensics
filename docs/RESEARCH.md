# Research map

This file records the initial external research anchors for the project. It is not a claim that TextForensics reproduces their published results.

## Benchmarks

### RAID
https://github.com/liamdugan/raid

Large benchmark spanning many generators, domains, decoding settings and robustness transformations. Use it as one major stress-test family, not the only evaluation source.

### DetectRL
https://github.com/NLP2CT/DetectRL

Designed around realistic conditions such as prompt variation, human revision, writing errors, varying length and robustness scenarios.

### M4
https://github.com/mbzuai-nlp/M4

Multi-generator, multi-domain and multilingual benchmark. Its published work emphasizes difficulty generalizing to unseen domains and generators.

## Detector-method references

Potential families to study/integrate only after license/implementation review:
- Binoculars: https://arxiv.org/abs/2401.12070
- Fast-DetectGPT: https://arxiv.org/abs/2310.05130
- DetectGPT: https://arxiv.org/abs/2301.11305
- RADAR: https://github.com/IBM/RADAR

Do not assume a paper's headline result transfers to a new model family, domain or modern generator.

## Fairness / false-positive references

A prominent 2023 study reported substantial false-positive concerns for non-native English writing in several public detectors:
https://arxiv.org/abs/2304.02819

Later research has also shown that carefully constructed detectors can behave differently in controlled domains, reinforcing the need for domain- and population-specific evidence rather than universal claims.

## Product-landscape anchor

AITextJury already demonstrates that a local multi-detector workbench with stylometry, likelihood methods, classifiers, calibration and plugins exists:
https://github.com/YiCQi/AITextJury

Therefore TextForensics' defensible identity should remain **detector reliability auditing, applicability, drift, reproducible case files and provenance**, not "we run many detectors".

## Research questions

1. Which detector families provide genuinely independent error information?
2. How quickly does performance degrade outside validated language/domain/length regimes?
3. What minimum text length is defensible per detector family?
4. Can a qualitative Trust Map predict elevated false-positive risk better than a generic confidence indicator?
5. Which benign formatting changes reveal instrumental instability?
6. How often do detector/provider outputs drift on a stable probe corpus?
7. Can calibrated fusion improve TPR at very low human FPR without hiding unsupported regimes?
8. How should mixed human/machine or heavily revised text be represented without forcing a false binary ground truth?
9. How should detector disagreement be communicated so users do not interpret consensus as proof?
10. Which process-provenance evidence meaningfully complements text-only signals?

## Evidence policy

When adding research:
- link the primary paper/repository,
- record publication/version date,
- distinguish published results from TextForensics results,
- document licensing before importing data/code,
- prefer reproducible primary sources over marketing comparisons.
