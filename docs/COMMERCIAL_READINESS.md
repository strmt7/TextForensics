# Commercial readiness

This document states what is and is not ready for a commercial distribution.

## Two different readiness questions

TextForensics has two layers that must not be conflated:

### 1. Platform/runtime readiness
Can the software be packaged, installed, operated, upgraded, tested, and integrated reliably?

### 2. Scientific detector readiness
Can TextForensics substantiate claims such as "matches or exceeds leading commercial AI-text detectors" across intended languages/domains/generators at an acceptable human false-positive rate?

The enterprise-hardening work targets **platform/runtime readiness**. Scientific detector readiness requires the remaining benchmark and detector-family roadmap.

## Platform/runtime release gate

A release candidate is operationally acceptable only when all of the following are green:

- Python 3.11, 3.12, 3.13, 3.14, 3.15 CI;
- Linux, macOS, Windows installation/CLI smoke tests;
- source/editable installation;
- wheel build and clean wheel install;
- optional API import/tests;
- optional MCP import/server construction;
- OCI image build/start/health check;
- non-root OCI runtime assertion;
- schema packaging validation;
- detector contract tests;
- calibration-leakage guards;
- provenance tamper tests;
- case-file integrity tests;
- CodeQL on the PR/main branch;
- dependency review on the PR;
- no unreviewed critical/high dependency vulnerability accepted silently.

## Current platform capabilities

- dependency-free Python core;
- CLI;
- local browser UI;
- optional ASGI/FastAPI API;
- optional MCP server;
- stable detector-plugin contract validation;
- plugin-health reporting;
- strict raw-score vs calibrated-probability semantics;
- qualitative Trust Map;
- sealed raw-text-free case files;
- provenance ledger with tamper verification;
- calibration/evaluation dataset separation guard;
- cross-platform package tests;
- non-root OCI image;
- Docker/Podman/Compose-compatible deployment;
- health/readiness endpoints;
- environment-based configuration;
- safe loopback binding by default;
- no application telemetry.

## Scientific-release blockers

The following remain required before advertising detector accuracy or parity with commercial systems:

1. **implemented, validation pending:** pinned Desklib supervised-transformer adapter with real-weight integration smoke tests;
2. **implemented, validation pending:** independent Qwen Raw Alignment Imprint likelihood-family adapter, which abstains categorically until calibrated;
3. reproducible RAID, DetectRL, and M4 benchmark adapters/runs for the exact pinned detector versions;
4. held-out threshold/calibration/evaluation separation;
5. confidence intervals and human false-positive operating points;
6. language/domain/length/revision slices;
7. versioned calibration registry;
8. empirical detector-family correlation/ablation analysis;
9. benchmark-backed Trust Map applicability evidence;
10. longitudinal detector/provider drift evidence where provider adapters are used.

Until the benchmark/calibration gates are satisfied, the built-in detector remains a transparent development baseline and the two model-backed adapters remain **experimental detector instruments**, not a commercial detection-performance claim.

## Commercial claims that are currently acceptable

Examples:
- "local-first AI-text detector reliability framework";
- "extensible detector interoperability and forensic reporting";
- "cross-platform Python package with CLI/API/MCP/OCI deployment";
- "raw-text-free sealed case artifacts by default";
- "explicit calibration, abstention, and evidence-coverage semantics".

## Claims that are not yet acceptable

Do not claim:
- "best AI detector";
- "state of the art";
- "more accurate than GPTZero/Turnitin/Pangram/etc.";
- a universal accuracy percentage;
- guaranteed identification of AI authorship;
- guaranteed humanization/bypass;
- production-ready calibrated authorship probability.

Those require evidence that does not yet exist in this repository.


## Licensing gate

The repository is currently AGPL-3.0-or-later. Commercial use is possible, but distribution/hosted-use obligations and third-party/model licenses must be reviewed before a commercial offering.

See [Licensing and commercial distribution](LICENSING.md).
