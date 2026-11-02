# Operations Guide — TextForensics

> Living document. Last major update: 2026-11-02.
> See [AGENTS.md](../AGENTS.md) for the non-negotiable development contract.

---

## 1. Monitoring

### 1.1 Detector Health

**What to monitor:**
- All detectors load without errors
- Plugin health status for each registered detector
- Execution time trends (baseline for alerting)

**How to check:**
```bash
# List all detectors and their health
textforensics detectors --health

# Programmatic
from textforensics import list_detector_health
for status in list_detector_health():
    print(f"{status['entry_point']}: {status['status']} ({status.get('detector_id', '?')})")
```

**Alerting thresholds:**
- **Critical**: Any built-in detector fails to load
- **Warning**: Plugin detector fails to load (non-blocking; the core continues)
- **Info**: New plugin available via entry point

### 1.2 Calibration Drift

**What to monitor:**
- Calibration artifact validity dates
- Score distribution shifts across drift snapshots
- Human false-positive rate trends
- Verdict flip rates between snapshots

**How to check:**
```bash
# Compare two drift snapshots
textforensics drift compare --baseline baseline.json --current current.json

# Programmatic
from textforensics import DriftObservatory

obs = DriftObservatory(corpus_path="data/probe_corpus.json")
obs.load_snapshots("artifacts/drift/snapshots.json")
report = obs.compare_snapshots(obs.snapshots[-2], obs.snapshots[-1])

# Check for drift
if report["overall"]["status"] == "drift_detected":
    print(f"DRIFT: {report['overall']['detectors_with_drift']} detector(s) drifted")
```

**Alerting thresholds:**
- **Critical**: Human FPR increased by ≥ 5 percentage points
- **Critical**: Behavioral drift detected with claim_allowed=True
- **Warning**: Score distribution shift above threshold
- **Warning**: Calibration artifact changed without version explanation
- **Warning**: Provider version metadata missing or changed

### 1.3 Benchmark Status

**What to monitor:**
- Benchmark evaluation results vs. quality gates
- Dataset fingerprint stability (no silent contamination)
- Calibration-evaluation disjointness

**How to check:**
```bash
# Run benchmark evaluation
textforensics benchmark run --dataset data/raid_en.jsonl

# Verify dataset fingerprint
textforensics benchmark fingerprint --verify --file data/raid_en.jsonl

# Programmatic
from textforensics import verify_benchmark, verify_calibration

report = verify_benchmark("artifacts/benchmark/raid_en_evaluation.json")
if not report["valid"]:
    print(f"BENCHMARK FAILURE: {report['errors']}")
```

**Alerting thresholds:**
- **Critical**: Contamination detected between calibration and evaluation sets
- **Critical**: Benchmark metrics fall below quality gate thresholds
- **Warning**: Dataset fingerprint mismatch (data was modified)

### 1.4 Health Check Endpoints

For server deployments:

| Endpoint | Purpose | What it checks |
|---|---|---|
| `GET /healthz` | Liveness | Process is responding |
| `GET /readyz` | Readiness | Application initialization is complete |

These endpoints **do not** analyze text or exercise remote detectors.

---

## 2. Backup

TextForensics is stateless for analysis. No database is required. Backup user-chosen artifact locations:

### 2.1 Critical Artifacts

| Artifact | Location | Backup Frequency | Retention |
|---|---|---|---|
| Calibration artifacts | `artifacts/calibration/` | Every change | Keep all versions |
| Benchmark results | `artifacts/benchmark/` | Every run | Keep all versions |
| Drift snapshots | `artifacts/drift/` | Every snapshot | Keep all versions |
| Capability ledger | Configured path | Every change | Keep current + previous |
| Provenance ledgers | User-specified | Continuous | Keep all versions |
| Case files | User-specified | On creation | Per organizational policy |

### 2.2 Backup Strategy

**Files to preserve:**
```
artifacts/
├── calibration/
│   ├── en_builtin_heuristic_v0_1_0.json       # Threshold artifacts
│   └── en_builtin_heuristic_v0_2_0.json       # New version replaces, old stays
├── benchmark/
│   ├── raid_en_calibration.jsonl               # Calibration data
│   ├── raid_en_evaluation.jsonl               # Evaluation data
│   ├── raid_en_fingerprint.json               # Dataset fingerprints
│   └── raid_en_evaluation_result.json         # Evaluation results
├── drift/
│   ├── probe_corpus.json                       # Immutable probe corpus
│   ├── snapshots.json                          # Snapshot store
│   └── reports/                                # Comparison reports
└── case-files/
    └── case_*.json                              # Sealed case files
```

**Integrity:**
- Calibration artifacts contain `calibration_record_hash` for self-verification
- Case files contain `case_sha256` for integrity verification
- Dataset fingerprints hash sample-level content
- Provenance ledgers use chained hashes

**Verify backup integrity:**
```bash
# Verify a case file
python -c "
from textforensics import verify_case_file_path
result = verify_case_file_path('artifacts/case-files/case_20261102.json')
print('Valid:', result['valid'], 'Errors:', result['errors'])
"

# Verify calibration artifact hash
python -c "
from textforensics import load_threshold_artifact
artifact = load_threshold_artifact('artifacts/calibration/en_builtin_v0_1_0.json')
print('Dataset hash:', artifact['calibration_dataset_hash'])
print('Record hash:', artifact['calibration_record_hash'])
"
```

---

## 3. Recovery

### 3.1 Restore from Backup

**Calibration artifacts:**
```bash
# Restore calibration artifact from backup
cp backup/artifacts/calibration/en_builtin_heuristic_v0_1_0.json \
   artifacts/calibration/

# Verify the restored artifact
python -c "
from textforensics import load_threshold_artifact
artifact = load_threshold_artifact('artifacts/calibration/en_builtin_heuristic_v0_1_0.json')
print('Threshold:', artifact['threshold'])
print('FPR:', artifact['observed_false_positive_rate'])
"
```

**Provenance ledger:**
```bash
# Verify ledger chain integrity after restore
python -c "
from textforensics import verify_ledger
result = verify_ledger('data/provenance/ledger.jsonl')
print('Valid:', result['valid'], 'Records:', result['records'])
if result['errors']:
    for err in result['errors']:
        print(f'  Error: {err}')
"
```

**Drift snapshots:**
```bash
# Restore and verify drift snapshots
python -c "
from textforensics import DriftObservatory

obs = DriftObservatory(corpus_path='data/probe_corpus.json')
obs.load_snapshots('artifacts/drift/snapshots.json')
print(f'Loaded {len(obs.snapshots)} snapshots')
print(f'Corpus hash: {obs.corpus_sha256}')
"
```

### 3.2 Calibration Replay

When calibration artifacts are lost, replay the calibration pipeline:

```python
from textforensics import run_calibration_evaluation

# Replay with committed data
result = run_calibration_evaluation(
    calibration_path="data/calibration/en.jsonl",
    evaluation_path="data/evaluation/en.jsonl",
    target_fpr=0.01,
)

# Verify results match expected values
cal = result["calibration_result"]
eval_ = result["evaluation_result"]

assert abs(cal["threshold"] - EXPECTED_THRESHOLD) < 0.001
assert eval_["contamination_detected"] is False
```

### 3.3 Audit Anchor Recovery

When a case file's provenance chain is broken:
1. Locate the last valid ledger entry before the break
2. Create a new ledger starting from that point
3. Re-snapshotted any files affected by the break
4. Document the recovery in the case file limitations

---

## 4. Incident Response

### 4.1 Detector Failure

**Symptoms:**
- `DetectorFailure` in forensic bundle `detector_failures` list
- Plugin health status shows `error`
- Consensus degrades due to missing family

**Response:**
1. Check detector health: `textforensics detectors --health`
2. Review failure details — note that raw exception text is stripped
3. If built-in detector fails: **immediate investigation required**
4. If plugin detector fails: note in bundle limitations; continue with remaining detectors
5. File bug report with detector ID, version, and family

**Prevention:**
- Pin detector dependency versions
- Monitor for upstream provider changes
- Keep drift snapshots for version comparison

### 4.2 Calibration Drift

**Symptoms:**
- Drift report shows `calibration_drift` with `significant: true`
- Human FPR increased between snapshots
- Score distribution shifted above threshold

**Response:**
1. Identify which detector(s) drifted:
   ```python
   report = obs.compare_snapshots(baseline, current)
   for detector in report["detectors"]:
       if detector["drift_detected"]:
           print(f"{detector['detector_id']}: {detector['findings']}")
   ```
2. Determine trigger:
   - Detector version change? → Revalidate calibration
   - Provider version change? → Check for upstream model update
   - No version change? → Investigate data distribution change
3. Revalidate calibration:
   ```python
   from textforensics import run_calibration_evaluation

   result = run_calibration_evaluation(cal_path, eval_path, target_fpr=0.01)
   ```
4. If calibration revalidation passes: update artifact, archive old
5. If calibration revalidation fails: **stop using this detector** until root cause is found
6. Update capability ledger with new evidence

### 4.3 Benchmark Failure

**Symptoms:**
- Benchmark metrics below quality gate thresholds
- Contamination detected between calibration and evaluation sets
- Dataset fingerprint mismatch

**Response:**
1. **Do not publish or use results from a contaminated benchmark**
2. Identify the contamination source:
   ```python
   from textforensics import validate_no_contamination

   report = validate_no_contamination(cal_path, eval_path)
   if report["contamination_detected"]:
       print(f"Shared samples: {report['shared_samples']}")
       print(f"Shared hashes: {report['shared_hashes'][:5]}")
   ```
3. Recreate disjoint datasets from authoritative source
4. Re-run calibration and evaluation with fresh data
5. Update dataset fingerprints
6. Investigate how contamination occurred

### 4.4 Case File Integrity Violation

**Symptoms:**
- `verify_case_file` returns `valid: false`
- `case_hash_mismatch` error
- `raw_text_policy_violation` error

**Response:**
1. **Do not distribute compromised case files**
2. If hash mismatch: case file was modified after sealing; re-create from source forensic bundle
3. If raw text violation: raw text was inadvertently included; re-create with `raw_text_included=false`
4. If schema mismatch: case file was created by incompatible version; re-create with current version
5. Document the violation in incident log

---

## 5. Escalation Guidelines

### 5.1 Severity Levels

| Severity | Criteria | Response Time |
|---|---|---|
| **P0: Critical** | Built-in detector not loading; contamination detected; human FPR spike >5% | Immediate |
| **P1: High** | Plugin detector failure affecting consensus; calibration drift detected; benchmark below gates | Within 4 hours |
| **P2: Medium** | Single plugin failure (non-blocking); drift warning without claim; FPR increase <5% | Within 24 hours |
| **P3: Low** | Documentation inconsistency; non-functional test failure; cosmetic issue | Next sprint |

### 5.2 Escalation Path

```
P0: Alert maintainers immediately
     ├── If calibration contamination: halt all production use of affected detector
     ├── If built-in detector failure: fall back to raw feature analysis with clear warnings
     └── If human FPR spike: disable affected detector until revalidated

P1: Create issue with reproduction steps
     ├── Investigate root cause within 4 hours
     ├── Update Trust Map to reflect reduced confidence
     └── If no fix within 24 hours, escalate to P0

P2: Create issue with standard triage
     ├── Assess impact on current analysis output
     ├── Add appropriate warnings to affected bundles
     └── Schedule fix in next release cycle

P3: Add to backlog
     └── No user impact; fix in regular development cadence
```

### 5.3 Emergency Stop

TextForensics has an emergency stop mechanism (`emergency_stop.py`). When activated:
- All analysis calls return immediately with an error
- No text is processed
- The stop must be cleared before analysis resumes

**When to use:**
- Active contamination of calibration data
- Known unsafe detector behavior detected
- Regulatory requirement to halt analysis

**How to clear:**
```python
from textforensics.emergency_stop import clear_emergency_stop

clear_emergency_stop()
```

---

## 6. Deployment Model

TextForensics is **stateless** for analysis calls. No database, message broker, or shared state is required.

### 6.1 Scaling

- **Horizontal**: Standard process/container replicas behind a load balancer
- **GPU**: Isolate GPU-backed detector adapters; limit concurrency to accelerator memory
- **Concurrency**: Do not share mutable detector objects across threads unless thread-safety is documented

### 6.2 Network Safety

- Default: binds to `127.0.0.1` (loopback)
- Remote: requires `--allow-remote` flag or `TEXTFORENSICS_ALLOW_REMOTE=1`
- No telemetry
- No raw text in access logs (access logs disabled by default)
- Input size limit: 2,000,000 UTF-8 bytes (configurable via `TEXTFORENSICS_MAX_INPUT_BYTES`)

### 6.3 Filesystem

- Container supports read-only root filesystem
- Writable paths only needed for: provenance ledgers, calibration artifacts, case files, drift snapshots
- API-only deployments need no persistent application data directory

### 6.4 Upgrade Policy

Before upgrading:
1. Read `CHANGELOG.md` for breaking changes
2. Check schema version changes
3. Rebuild/reinstall the package
4. Run `textforensics --version`
5. Check `/healthz`
6. **Revalidate calibration when detector/model/provider versions changed**
