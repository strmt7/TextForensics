# Rejection Rejector Enterprise Patterns for TextForensics

**Research Date:** 2026-11-02
**Source Repository:** strmt7/rejection-rejector (main branch, 1,155+ commits)
**Repository Type:** Local-first Rust application with enterprise-grade CI/CD, security, and testing patterns

---

## Executive Summary

The `strmt7/rejection-rejector` repository demonstrates an exceptionally mature engineering discipline for a solo-maintainer project. Its patterns for **supply-chain security**, **evidence-based releases**, **mutation testing**, **fuzzing**, **enterprise policy enforcement**, and **deterministic reproducibility** represent state-of-the-art practices that would significantly elevate TextForensics' reliability, auditability, and enterprise readiness.

Key differentiators:
- **Per-commit evidence preservation** (workflows never cancel mid-run on main)
- **Fail-closed release gates** with bounded waiting for deep-quality evidence
- **Cryptographic binding** of binaries to source commits, dependencies, and contracts
- **Independent authentication** of enterprise policies (SHA-256 pinning + Ed25519 signatures)
- **Comprehensive testing pyramid** (unit → integration → mutation → fuzz → recovery drills)

---

## 1. CI/CD Workflows (Enterprise Patterns)

### 1.1 Per-Commit Evidence Preservation

**Pattern Name:** Independent Run Identity Per Commit (S04/RR-06)

**Why Valuable for TextForensics:**
TextForensics produces forensic evidence that must be tied to exact source commits. Allowing newer pushes to cancel older runs would destroy the audit trail needed for reproducibility claims.

**Implementation:**
```yaml
concurrency:
  # Push/schedule/dispatch runs group by SHA; PR runs group by ref
  group: rust-ci-${{ github.event_name == 'pull_request' && github.ref || github.sha }}
  # Main-only development uses each commit as an auditable evidence point
  cancel-in-progress: false
```

**Key Insight:** Differentiate between PR workflows (where cancellation is acceptable) and main-branch workflows (where every commit is release evidence).

### 1.2 Stable Aggregate Verify Job

**Pattern Name:** Aggregate Result Job (S04/D5)

**Why Valuable:** Ensures a single check status that downstream tools can rely on, even when individual jobs have complex dependencies.

**Implementation:**
```yaml
verify:
  name: All required checks
  if: always()  # Runs even on failure/cancellation/skip
  needs: [test]
  runs-on: ubuntu-latest
  steps:
    - name: Require every required job green
      env:
        TEST_RESULT: ${{ needs.test.result }}
      run: |
        if [ "${TEST_RESULT:-missing}" != "success" ]; then
          echo "required job did not succeed: ${TEST_RESULT:-missing}" >&2
          exit 1
        fi
```

**TextForensics Application:** Create a `verify` job that aggregates detector validation, benchmark results, and calibration evidence checks.

### 1.3 Evidence-Age Gating

**Pattern Name:** Bounded Evidence Freshness

**Why Valuable:** Prevents stale test results from being used as release evidence.

**Implementation (from `scripts/release_guard.py`):**
```python
MAX_EVIDENCE_AGE = timedelta(days=8)
MAX_CLOCK_SKEW = timedelta(minutes=5)


def _validate_run_outcome(run, workflow, commit, now):
    age = now - parse_time(run.get("updated_at"))
    if age < -MAX_CLOCK_SKEW or age > MAX_EVIDENCE_AGE:
        raise GateError(f"{workflow}: evidence timestamp is stale or in the future")
```

**TextForensics Application:** Benchmark results older than 7 days should not qualify a release claiming accuracy metrics.

### 1.4 Workflow Inventory

| Workflow | Purpose | Frequency | TextForensics Adaptation |
|----------|---------|-----------|-------------------------|
| `ci.yml` | Core CI (fmt, test, clippy) | Push/PR | Detector tests, API contract checks |
| `supply-chain.yml` | SBOM, advisories, secrets | Push + Weekly | Dependency audit for detector libs |
| `mutation.yml` | Mutation testing | Push (diff-based) + Weekly | Test quality for scoring logic |
| `fuzz.yml` | LibFuzzer regression | Push + Weekly | Fuzz input parsers, score boundaries |
| `coverage.yml` | Coverage evidence | Push + Weekly | Ensure detector adapters tested |
| `codeql.yml` | Security analysis | Push + Weekly | Find security issues in API layer |
| `reproducibility.yml` | Byte-for-byte rebuild | Weekly | Verify deterministic builds |
| `release.yml` | Attested packaging | Manual | Signed releases with provenance |
| `enterprise-deep-verification.yml` | Deep verification | Weekly | Recovery drills, nextest, docs |
| `repository-integrity.yml` | Source integrity | Push/PR | Ensure no hidden modifications |
| `semver.yml` | API compatibility | Push | Check public API breaks |
| `scorecard.yml` | Security posture | Push + Weekly | OpenSSF score tracking |
| `workflow-lint.yml` | Workflow validation | Push + Weekly | Ensure workflow correctness |

---

## 2. Security Practices (Supply Chain, SBOM, Provenance)

### 2.1 Pinned Toolchain with Checksum Verification

**Pattern Name:** Checksum-Pinned Tool Installation

**Why Valuable:** Prevents supply-chain attacks through compromised tool binaries.

**Implementation:**
```yaml
- name: Install pinned cargo-mutants
  uses: taiki-e/install-action@86f7a0ffb25f40114606501a311ebcfaf882ea32 # v2.88.0
  with:
    tool: cargo-mutants@27.1.0
    checksum: true  # Verifies against known-good checksums
    fallback: none  # Fails closed if checksum unavailable
```

**TextForensics Application:** Pin all Python tools (pytest, coverage, mypy) with hashes in `requirements-dev.txt` and use checksum-verified installs.

### 2.2 CycloneDX SBOM Generation

**Pattern Name:** Per-Commit SBOM Attestation

**Why Valuable:** Provides complete dependency inventory for security audits and vulnerability response.

**Implementation:**
```yaml
- name: Generate CycloneDX 1.5 SBOM
  run: |
    cargo cyclonedx --format json --spec-version 1.5 --all-features --target all \
      --override-filename rejection-rejector.cdx
    sha256sum artifacts/rejection-rejector.cdx.json > artifacts/rejection-rejector.cdx.sha256
```

**TextForensics Application:** Generate SBOM for Python dependencies, detector libraries, and any native extensions.

### 2.3 Binary Audit Before Release

**Pattern Name:** Independent Binary Auditing

**Why Valuable:** Verifies that compiled binaries don't introduce vulnerabilities not present in source.

**Implementation (from `scripts/release_guard.py`):**
```python
def audit_binaries(paths: list[Path], output: Path):
    for path in paths:
        result = subprocess.run(
            ["cargo", "audit", "bin", str(path)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        (output / f"{path.stem}-binary-audit.txt").write_text(result.stdout + result.stderr)
        if result.returncode != 0:
            raise GateError(f"Binary audit failed: {path.name}")
```

**TextForensics Application:** Audit Python wheels or compiled extensions before release.

### 2.4 Full-History Secret Scanning

**Pattern Name:** Complete History Secret Scan

**Why Valuable:** Detects secrets that may have been committed historically even if removed.

**Implementation:**
```yaml
- name: Checkout complete repository history
  uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0  # Full history
- name: Gitleaks
  uses: gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e # v3.0.0
```

### 2.5 Dependency Policy Enforcement

**Pattern Name:** Multi-Tool Dependency Policy (deny.toml)

**Why Valuable:** Enforces license compatibility, source restrictions, and advisory handling.

**Implementation (deny.toml):**
```toml
[advisories]
version = 2
yanked = "deny"
# No suppressions by standing policy

[licenses]
version = 2
allow = [
  "MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0",
  # Explicitly reviewed exceptions
]

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = [
  "https://github.com/rust-lang/crates.io-index",
  "sparse+https://index.crates.io/",
]
```

**TextForensics Application:** Create equivalent policy for PyPI packages, restricting to known registries and requiring license review.

---

## 3. Testing Patterns (Mutation Testing, Fuzzing, Property-Based)

### 3.1 Diff-Based Mutation Testing

**Pattern Name:** Incremental Mutation Testing

**Why Valuable:** Tests only changed code on push, full suite weekly—balances speed with thoroughness.

**Implementation:**
```yaml
- name: Mutate only the Rust lines the push changed
  run: |
    git diff "$since"...HEAD -- '*.rs' > artifacts/mutation.diff
    if [ ! -s artifacts/mutation.diff ]; then
      echo "No Rust lines changed; nothing to mutate."
      exit 0
    fi
    cargo mutants \
      --all-features \
      --timeout-multiplier 2 \
      --minimum-test-timeout 15 \
      --jobs 4 \
      --in-diff artifacts/mutation.diff
```

**Exit Code Semantics:**
- `0`: All mutants caught
- `2`: Surviving mutants (release blocker)
- `3`: Budget exceeded (inconclusive)
- `1,4,5,6,70`: Infrastructure failure

**TextForensics Application:** Use `cosmic-ray` or `mutmut` for Python mutation testing on scoring logic and detector adapters.

### 3.2 Safety-Critical Deep Mutation Pass

**Pattern Name:** Targeted Deep Mutation

**Why Valuable:** Weekly exhaustive testing of safety-critical modules.

**Implementation:**
```yaml
- name: Run deep mutation suite
  run: |
    scope_args=()
    if [ "${SCOPE_INPUT:-safety-critical}" = "safety-critical" ]; then
      scope_args+=(
        --file src/store.rs        # State machine
        --file src/vault.rs        # Cryptography
        --file src/emergency.rs    # Emergency stop
        --file src/decision.rs     # Deterministic gates
        --file src/audit_anchor.rs # Rollback detection
        --file src/policy.rs       # Enterprise policy
        --file src/recovery.rs     # Backup/restore
      )
    fi
    cargo mutants --all-features --timeout-multiplier 3 "${scope_args[@]}"
```

**TextForensics Application:** Target mutation testing at:
- `textforensics/scoring.py` (score computation)
- `textforensics/calibration.py` (probability calibration)
- `textforensics/trust_map.py` (coverage determination)
- `textforensics/ensemble.py` (detector fusion)

### 3.3 Bounded LibFuzzer Regression

**Pattern Name:** Time-Bounded Fuzzing

**Why Valuable:** Finds edge cases in parsers and boundary conditions.

**Implementation:**
```yaml
- name: Fuzz mailbox and quote boundaries
  run: |
    cargo +nightly fuzz run mail_boundaries --fuzz-dir fuzz \
      -- -max_total_time=90 -max_len=65536 -timeout=10 -rss_limit_mb=2048
```

**Fuzz Targets (from `fuzz/fuzz_targets/`):**

```rust
// fuzz_targets/mail_boundaries.rs
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = mail::mailbox(&text);
    let _ = mail::valid_message_id(&text);
    let _ = mail::current_text(&text);

    // Verify bounded text extraction
    let budget = u16::from_le_bytes([data[0], data[1]]) as usize;
    let (bounded, complete) = mail::bounded_text(&text, budget);
    assert!(bounded.len() <= text.len());
    if complete {
        assert_eq!(bounded.len(), text.len());
    } else {
        assert!(bounded.len() <= budget);
    }
});
```

**TextForensics Application:** Create fuzz targets for:
- Text input parsing (UTF-8 boundaries, null bytes, control characters)
- Score boundary conditions (NaN, infinity, out-of-range)
- JSON/YAML configuration parsing
- Benchmark dataset loading

### 3.4 Property-Based Testing Integration

**Pattern Name:** Deterministic Randomized Invariants

**Why Valuable:** Reproducible failures with extensive state-space coverage.

**Implementation (from `tests/state_invariants.rs`):**
```rust
const SEED: u64 = 0x5252_454A_4543_544F;  // Fixed seed for reproducibility

#[test]
fn enterprise_policy_is_monotone_and_idempotent_across_generated_settings() {
    let mut rng = StdRng::seed_from_u64(SEED);

    for case in 0..10_000u32 {
        // Generate random settings
        let mut settings = Settings {
            sending_enabled: rng.random_bool(0.5),
            daily_send_limit: rng.random_range(1..=100),
            // ...
        };

        // Generate random policy
        let policy = EnterprisePolicy {
            force_human_review: rng.random_bool(0.25),
            prohibit_sending: rng.random_bool(0.25),
            // ...
        };

        // Verify invariants
        let first_changed = policy.enforce(&mut settings, true)?;
        let second_changed = policy.enforce(&mut settings, true)?;

        assert_eq!(settings, once, "policy is not idempotent");
        assert!(!second_changed, "second enforcement reported drift");
    }
}
```

**TextForensics Application:** Use Hypothesis for property-based testing:
```python
from hypothesis import given, strategies as st


@given(
    scores=st.lists(st.floats(min_value=0, max_value=1)),
    weights=st.lists(st.floats(min_value=0, max_value=1)),
)
def test_ensemble_calibration_is_stable(scores, weights):
    # Test invariants
    pass
```

### 3.5 Recovery Drill Testing

**Pattern Name:** Production Path Recovery Verification

**Why Valuable:** Ensures backup/restore actually works, not just theoretically.

**Implementation:**
```yaml
- name: Synthetic encrypted recovery drill
  run: |
    workspace="$RUNNER_TEMP/rr-enterprise-deep-workspace"
    backup="$RUNNER_TEMP/rr-enterprise-deep-backup"

    # Create fresh workspace
    cargo run --bin rr -- --data-dir "$workspace" status

    # Create backup
    cargo run --bin rr -- --data-dir "$workspace" backup --out "$backup"

    # Verify backup
    cargo run --bin rr -- --data-dir "$workspace" verify-backup "$backup"

    # Drill restore (isolated temp workspace)
    cargo run --bin rr -- --data-dir "$workspace" recovery-drill "$backup"

    # Verify drill succeeded
    python3 - <<'PY'
    import json
    drill = json.loads(Path("artifacts/recovery-drill.json").read_text())
    assert drill["isolated_restore_succeeded"] is True
    assert drill["restored_schema_version"] >= 1
    PY
```

**TextForensics Application:** Test backup/restore of:
- Calibration artifacts
- Benchmark results
- Trust map configurations
- Detector metadata

---

## 4. Documentation Patterns

### 4.1 Architecture Decision Records

**Pattern Name:** Living Architecture Documentation

**Why Valuable:** Explains not just what the system does, but why it's structured that way.

**Key Documents:**
- `docs/ARCHITECTURE.md` - Component map, state machine, trust boundaries
- `docs/THREAT_MODEL.md` - Security objectives, trust boundaries, mitigations
- `docs/ENTERPRISE_POLICY.md` - Policy schema, deployment workflow
- `docs/OPERATIONS.md` - Runbook, incident response, monitoring
- `AGENTS.md` - Development contract for human/AI contributors

**Structure Example (from THREAT_MODEL.md):**
```markdown
## Trust Boundaries

### TB1 — Untrusted incoming email → parser/policy/model

Recruiters, ATS systems and attackers can control email subject/body/headers.
Email is **data, never instructions**.

**Security consequence:** Prompt injection inside an email cannot directly call
Gmail send, alter settings or grant Automatic eligibility.
```

**TextForensics Application:** Create equivalent documents:
- `docs/ARCHITECTURE.md` - Detector adapter architecture, ensemble design
- `docs/TRUST_MODEL.md` - When to trust detector outputs, abstention criteria
- `docs/CALIBRATION.md` - Calibration methodology, validation splits
- `docs/BENCHMARK_DISCIPLINE.md` - How to run benchmarks without contamination

### 4.2 Machine-Readable Engineering Policy

**Pattern Name:** Engineering Policy as Code (engineering.toml)

**Why Valuable:** Makes engineering standards explicit, verifiable, and enforceable.

**Implementation:**
```toml
schema_version = "1.0"
repo = "strmt7/rejection-rejector"
audit_baseline_sha = "589b89fceac51effa6922e210d4ee8a4033c9a32"

[[commands]]
id = "test-fast"
command = "cargo test --locked --lib --no-default-features"
environment = "rust-windows-msvc"
reason = "Deterministic core library tests"

[[test_families]]
id = "rust-core-tests"
command_id = "test-fast"
minimum_executed = 100
required_test_ids = [
  "new_database_creates_schema_and_vault_marker_together",
  "audit_chain_detects_ciphertext_tampering",
]

[[standards]]
id = "S06"
applicable = true
reason = "Locked Cargo builds, pinned toolchain, SHA-pinned tool installs"
command_ids = ["audit", "audit-policy", "verify"]
```

**TextForensics Application:** Create `engineering.toml` defining:
- Required test coverage thresholds
- Benchmark validation requirements
- Calibration data handling rules
- Release evidence requirements

### 4.3 Inline Documentation Contracts

**Pattern Name:** Input/Output Documentation for Functions

**Why Valuable:** Makes function contracts explicit for reviewers and maintainers.

**Implementation:**
```rust
/// Evaluate the complete configured local pipeline on synthetic recruiting mail.
///
/// Inputs: `settings` — settings describing the configured pipeline (delivery
/// is disarmed during evaluation). Output: `Result<serde_json::Value>` — the
/// evaluation report over the synthetic fixture corpus.
///
/// This is deliberately application-specific. False rejection replies are weighted
/// more heavily than missed rejections because an unattended reply to an interview,
/// offer, quoted history, or adversarial message is the costliest model error here.
fn evaluate(settings: &Settings) -> Result<serde_json::Value> {
```

---

## 5. CLI Design Patterns

### 5.1 Machine-Readable Output Contract

**Pattern Name:** JSON Output for All Status Commands

**Why Valuable:** Enables fleet tooling and automation without screen scraping.

**Implementation:**
```rust
#[test]
fn readiness_and_status_commands_emit_machine_readable_reports() {
    let status = json_stdout(&rr_in(&dir, &["status"]));
    assert_eq!(status.get("demo"), Some(&serde_json::json!(false)));
    assert!(status.get("mode").is_some() && status.get("counts").is_some());

    let doctor = json_stdout(&rr_in(&dir, &["doctor"]));
    assert!(doctor.get("configuration_readiness").is_some());
    assert!(doctor.get("database").is_some());
    assert!(doctor.get("local_ai").is_some());
}
```

**TextForensics Application:** Ensure all CLI commands output JSON:
```python
# textforensics/cli.py
@click.command()
@click.option("--format", type=click.Choice(["json", "text"]), default="json")
def status(format):
    result = get_status()
    if format == "json":
        click.echo(json.dumps(result, indent=2))
```

### 5.2 Readiness Levels with Strict Gating

**Pattern Name:** Tiered Readiness Verification

**Why Valuable:** Different deployment stages require different readiness levels.

**Implementation:**
```bash
.\rr.exe doctor --require workspace      # Basic workspace integrity
.\rr.exe doctor --require mailbox        # + Gmail connected
.\rr.exe doctor --require analysis       # + Model qualified
.\rr.exe doctor --require automatic      # + All gates for unattended send
```

**Exit Code Semantics:**
- `0`: Requested level satisfied
- `1`: Level not satisfied (with specific error message)

**TextForensics Application:**
```bash
textforensics doctor --require basic      # Installation OK
textforensics doctor --require detectors  # + Detectors loaded
textforensics doctor --require calibrated # + Calibration artifacts valid
textforensics doctor --require production # + All benchmarks passing
```

### 5.3 Explicit Acknowledgement for Destructive Operations

**Pattern Name:** Literal Acknowledgement Tokens

**Why Valuable:** Prevents accidental destructive operations through muscle memory.

**Implementation:**
```rust
// Restore refuses anything but the literal acknowledgement
let refused = rr_in(&dir, &[
    "restore-backup", backup_path,
    "--confirm", "yes",  // Wrong token
]);
assert!(!refused.status.success());
assert!(stderr.contains("Restore requires --confirm RESTORE"));

// Correct acknowledgement succeeds
let restored = rr_in(&dir, &[
    "restore-backup", backup_path,
    "--confirm", "RESTORE",  // Exact token required
]);
```

**TextForensics Application:**
```bash
# Require explicit acknowledgement for dangerous operations
textforensics reset-calibration --confirm RESET_CALIBRATION
textforensics delete-benchmarks --confirm DELETE_BENCHMARKS
textforensics purge-cache --confirm PURGE_CACHE
```

### 5.4 Privacy-Safe Diagnostics

**Pattern Name:** Redacted Diagnostic Output

**Why Valuable:** Enables support without exposing sensitive data.

**Implementation:**
```rust
/// Runtime journal records cannot contain:
/// - Mailbox bodies/subjects/addresses
/// - OAuth/API secrets
/// - Signature, candidate facts
/// - Arbitrary exception strings
```

**TextForensics Application:**
```python
def generate_diagnostics():
    return {
        "version": __version__,
        "detectors_loaded": list_detectors(),
        "calibration_status": get_calibration_meta(),  # No raw scores
        "benchmark_results": get_benchmark_summary(),  # Aggregates only
        # Never include: raw text, individual scores, PII
    }
```

---

## 6. Release Workflow Patterns

### 6.1 Manual Release with Explicit Confirmation

**Pattern Name:** Attested Manual Release

**Why Valuable:** Prevents accidental releases while maintaining full automation of the release process.

**Implementation:**
```yaml
on:
  workflow_dispatch:
    inputs:
      confirmation:
        description: Type PACKAGE to build an attested Windows package
        required: true
        type: string
      signing:
        description: Signing mode
        required: true
        type: choice
        options: [unsigned, azure-artifact-signing]

jobs:
  package:
    if: inputs.confirmation == 'PACKAGE'  # Explicit gate
```

### 6.2 Source-Bound Automated Release Evidence

**Pattern Name:** Release Evidence Gate

**Why Valuable:** Ensures releases only happen when all quality gates pass.

**Implementation (from `scripts/release_guard.py`):**
```python
EXACT = {
    "ci.yml": "Rust CI",
    "semver.yml": "Rust public API compatibility",
    "supply-chain.yml": "Supply-chain security",
    "codeql.yml": "CodeQL Rust security",
}
DEEP = {
    "fuzz.yml": "Rust fuzzing",
    "coverage.yml": "Rust coverage",
    "mutation.yml": "Mutation testing",
    "reproducibility.yml": "Windows reproducibility",
}


def collect_evidence(repository, commit, now):
    """Collect green evidence for every required workflow."""
    evidence = []
    for workflow in {**EXACT, **DEEP}:
        run = latest_run(repository, workflow, commit)
        validate_run(run, workflow, repository, commit, now)
        evidence.append(
            {
                "workflow": workflow,
                "run_id": run["id"],
                "commit": run["head_sha"],
                "conclusion": "success",
            }
        )
    return {"automated_evidence": evidence}
```

**TextForensics Application:**
```python
REQUIRED_EVIDENCE = {
    "ci.yml": "Core CI",
    "test-detectors.yml": "Detector tests",
    "benchmark.yml": "Benchmark validation",
    "calibration.yml": "Calibration verification",
    "supply-chain.yml": "Dependency audit",
    "mutation.yml": "Mutation testing",
}
```

### 6.3 Embedded Build Identity

**Pattern Name:** Self-Describing Binaries

**Why Valuable:** Binaries carry their own provenance, enabling verification without external metadata.

**Implementation:**
```rust
// Embedded in binary at build time
{
    "source_commit": "abc123...",
    "source_commit_verified": true,
    "rustc_version": "rustc 1.99.1",
    "target": "x86_64-pc-windows-msvc",
    "profile": "release",
    "cargo_lock_sha256": "def456...",
    "identity_sha256": "computed_from_above_fields"
}
```

**Verification:**
```powershell
.\rr.exe build-info | ConvertFrom-Json
# Verify source_commit matches expected release commit
# Verify cargo_lock_sha256 matches packaged Cargo.lock
```

**TextForensics Application:**
```python
# textforensics/_build_info.py
BUILD_INFO = {
    "source_commit": os.environ.get("GITHUB_SHA", "unknown"),
    "source_commit_verified": True,
    "python_version": sys.version,
    "dependencies_sha256": hash_file("requirements.lock"),
}


@click.command()
def build_info():
    """Print embedded build identity."""
    click.echo(json.dumps(BUILD_INFO, indent=2))
```

### 6.4 Contract Info Embedding

**Pattern Name:** Embedded Compatibility Contract

**Why Valuable:** Enables deployment tooling to verify API/schema compatibility before integration.

**Implementation:**
```json
{
    "api_contract_sha256": "<hash of openapi-v1.json>",
    "enterprise_policy_schema_sha256": "<hash of policy schema>",
    "settings_format_version": 1,
    "database_schema_version": 1,
    "evaluation_suite_sha256": "<hash of test fixtures>"
}
```

**TextForensics Application:**
```python
CONTRACT_INFO = {
    "api_version": "1.0.0",
    "api_spec_sha256": hash_file("docs/api-spec.yaml"),
    "detector_adapter_api_sha256": hash_file("docs/detector-adapter-api.md"),
    "calibration_format_version": 1,
    "benchmark_format_version": 1,
}
```

### 6.5 SLSA Provenance Attestation

**Pattern Name:** GitHub Artifact Attestation

**Why Valuable:** Cryptographically proves build origin and workflow.

**Implementation:**
```yaml
- name: Attest build provenance
  uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
  with:
    subject-path: ${{ steps.package.outputs.package_path }}

- name: Attest package SBOM
  uses: actions/attest@...
  with:
    subject-path: ${{ steps.package.outputs.package_path }}
    sbom-path: artifacts/rejection-rejector.cdx.json
```

**Verification:**
```bash
gh attestation verify package.zip \
  --repo strmt7/rejection-rejector \
  --signer-workflow strmt7/rejection-rejector/.github/workflows/release.yml \
  --source-ref refs/heads/main \
  --source-digest <commit-sha> \
  --deny-self-hosted-runners
```

### 6.6 Package Verification Without Extraction

**Pattern Name:** Read-Only Package Verification

**Why Valuable:** Verifies package integrity without executing or extracting untrusted code.

**Implementation (from `scripts/verify_package.py`):**
```python
def verify(path: Path, commit: str, signing: str) -> dict:
    """Verify package bytes, checksums and metadata without extracting."""

    # 1. Verify archive hash
    archive_hash = sha256_file(path)
    require(archive_hash == expected_sha256, "ZIP checksum mismatch")

    # 2. Preflight ZIP directory (bound allocation)
    preflight_directory(handle, size)

    # 3. Validate every entry name (Windows-safe, no traversal)
    files = inventory(archive)
    require(files.keys() >= REQUIRED, "Required files missing")

    # 4. Verify checksum manifest covers exact file set
    manifest = checksum_manifest(read_member(archive, "SHA256SUMS.txt"))
    require(manifest.keys() == files.keys() - {"SHA256SUMS.txt"})

    # 5. Verify each file against manifest
    for name, entry in files.items():
        digest = sha256_stream(archive.open(entry))
        require(digest == manifest[name], f"Checksum mismatch: {name}")

    # 6. Cross-check metadata (build-info, contract-info, signing, evidence)
    metadata_check(data, manifest, commit, signing)

    return {"schema_version": 1, "files_verified": len(manifest)}
```

**TextForensics Application:** Create equivalent verification for Python wheels or source distributions.

---

## 7. Unique Innovations

### 7.1 Emergency Stop Sentinel

**Pattern Name:** Out-of-Band Emergency Stop

**Why Valuable:** Provides immediate containment independent of application state.

**Implementation:**
```python
# Checked at dispatch entry AND again before network request
EMERGENCY_STOP_FILE = os.environ.get("RR_EMERGENCY_STOP_FILE")


def check_emergency_stop():
    if not EMERGENCY_STOP_FILE:
        return False  # Not configured

    path = Path(EMERGENCY_STOP_FILE)
    if not path.is_absolute():
        return True  # Malformed config fails closed

    if path.is_file():
        return True  # Sentinel present - STOP

    return False  # No sentinel - proceed


# Usage in dispatch path
if check_emergency_stop():
    release_reservation()
    raise EmergencyStopError("Out-of-band stop sentinel active")
```

**TextForensics Application:**
```bash
# Configure emergency stop
export TEXTFORENSICS_EMERGENCY_STOP=/etc/textforensics/STOP

# Blocks all detector API calls when file exists
touch /etc/textforensics/STOP

# Remove to resume
rm /etc/textforensics/STOP
```

### 7.2 Revision Floor for Enterprise Policy

**Pattern Name:** Encrypted Revision Floor

**Why Valuable:** Prevents rollback attacks on enterprise policy.

**Implementation:**
```rust
struct PolicyRevisionFloor {
    highest_revision: u64,
    highest_digest: String,  // SHA-256 of policy bytes
}

fn observe(&mut self, loaded: &LoadedPolicy) -> Result<bool> {
    let revision = loaded.policy.revision.ok_or("v1 policy")?;

    // Reject rollback
    if revision < self.highest_revision {
        return Err("Policy rollback detected");
    }

    // Reject same-revision drift
    if revision == self.highest_revision && loaded.digest != self.highest_digest {
        return Err("Same-revision content drift");
    }

    // Advance floor
    if revision > self.highest_revision {
        self.highest_revision = revision;
        self.highest_digest = loaded.digest.clone();
        return Ok(true);  // Floor advanced
    }

    Ok(false)  // No change
}
```

**TextForensics Application:**
```python
class PolicyRevisionFloor:
    def __init__(self):
        self.state = load_encrypted_state()

    def observe(self, policy: EnterprisePolicy):
        if policy.revision < self.state["revision"]:
            raise PolicyRollbackError("Revision rollback detected")

        if policy.revision == self.state["revision"] and policy.digest != self.state["digest"]:
            raise PolicyDriftError("Same-revision drift")

        if policy.revision > self.state["revision"]:
            self.state = {"revision": policy.revision, "digest": policy.digest}
            save_encrypted_state(self.state)
```

### 7.3 Deterministic Send Gate

**Pattern Name:** Multi-Factor Send Authorization

**Why Valuable:** Model output alone never authorizes external writes.

**Implementation:**
```rust
// Automatic mode requires ALL of:
// 1. Deterministic rejection phrase in current message
let has_rejection_phrase = clear_rejection_language(&subject, &current_text);

// 2. No language conflict
let no_conflict = !auto_language_conflict(&subject, &current_text);

// 3. Model classification matches
let model_says_rejection = analysis.verdict.category == Category::Rejection;

// 4. Verification passed
let verification_passed = analysis.verification.passed();

// 5. Draft is safe
let draft_safe = !automatic_draft_conflict(&draft_body, &signature);

// 6. Recipient burst ceiling not exceeded
let under_ceiling = check_recipient_ceiling(&recipient, HOURS_24, MAX=2);

// ALL must pass for unattended send
if has_rejection_phrase && no_conflict && model_says_rejection
    && verification_passed && draft_safe && under_ceiling {
    authorize_send()
} else {
    hold_for_human_review()
}
```

**TextForensics Application:**
```python
def authorize_inference(text: str, context: InferenceContext) -> Authorization:
    """Multi-factor authorization for detector inference."""

    # 1. Text meets minimum length
    if len(text) < MIN_LENGTH:
        return Authorization.ABSTAIN_INSUFFICIENT_LENGTH

    # 2. Language supported
    if not is_supported_language(text):
        return Authorization.ABSTAIN_UNSUPPORTED_LANGUAGE

    # 3. Within calibrated domain
    if not in_calibrated_domain(text):
        return Authorization.ABSTAIN_OUT_OF_DOMAIN

    # 4. Trust map coverage adequate
    trust = trust_map.evaluate(text)
    if trust.status == TrustStatus.OUT_OF_SCOPE:
        return Authorization.ABSTAIN_OUT_OF_SCOPE

    # All checks pass
    return Authorization.AUTHORIZED
```

### 7.4 Audit Anchor for Rollback Detection

**Pattern Name:** External Audit Anchor

**Why Valuable:** Detects whole-database rollback attacks.

**Implementation:**
```rust
// Export audit anchor (external to workspace)
{
    "schema_version": 1,
    "database_sha256": "...",
    "audit_chain_head": "...",  // Hash of latest audit event
    "exported_at": "2026-11-02T..."
}

// Later verification
fn verify_audit_anchor(anchor: &AuditAnchor) -> Result {
    let current_head = db.get_audit_chain_head();

    if current_head == anchor.audit_chain_head {
        return Ok("No changes since anchor")
    }

    // Verify current chain extends anchor
    if db.audit_chain_contains(anchor.audit_chain_head) {
        return Ok("Audit chain valid")
    }

    Err("Audit chain broken - possible rollback")
}
```

**TextForensics Application:**
```python
def export_audit_anchor():
    """Export audit point for rollback detection."""
    return {
        "calibration_artifacts_sha256": hash_dir("calibrations/"),
        "benchmark_results_sha256": hash_dir("benchmarks/"),
        "detector_versions": get_detector_versions(),
        "exported_at": datetime.utcnow().isoformat(),
    }


def verify_audit_anchor(anchor):
    """Verify no rollback occurred."""
    current_hash = hash_dir("calibrations/")
    if current_hash != anchor["calibration_artifacts_sha256"]:
        # Check if current state extends anchor
        if not calibration_chain_contains(anchor):
            raise RollbackError("Calibration artifacts rolled back")
```

### 7.5 Shadow Automatic Mode

**Pattern Name:** Read-Only Simulation

**Why Valuable:** Tests automatic mode eligibility without risk.

**Implementation:**
```bash
# Simulate automatic mode without enabling it
.\rr.exe shadow-automatic --out automatic-shadow.json

# Output includes:
{
    "would_be_eligible": false,
    "blocking_reasons": [
        "MODEL_NOT_QUALIFIED",
        "RECIPIENT_CEILING_REACHED",
        "ENTERPRISE_POLICY_FORCE_HUMAN_REVIEW"
    ],
    "backlog_items": 15,
    "daily_capacity_remaining": 8
}
```

**TextForensics Application:**
```bash
textforensics shadow-production --out shadow-report.json

# Reports:
{
    "production_ready": false,
    "blocking_detectors": ["detector_x: calibration expired"],
    "trust_map_gaps": ["language: ar", "domain: medical"],
    "benchmark_status": {"raid": "passing", "m4": "outdated"}
}
```

---

## 8. Implementation Roadmap for TextForensics

### Phase 1: Foundation (Weeks 1-2)

1. **Create engineering.toml**
   - Define required commands (test, lint, benchmark, calibrate)
   - Specify test families and minimum coverage
   - Document standards (S01-S15 equivalent)

2. **Set up CI workflow structure**
   - Per-commit evidence preservation
   - Aggregate verify job
   - Evidence-age gating

3. **Implement supply-chain security**
   - Pin all dependencies with hashes
   - Generate CycloneDX SBOM
   - Set up dependency policy (licenses, sources)

### Phase 2: Testing Infrastructure (Weeks 3-4)

1. **Mutation testing setup**
   - Install cosmic-ray or mutmut
   - Create diff-based mutation workflow
   - Define safety-critical modules for deep passes

2. **Fuzzing infrastructure**
   - Create fuzz targets for input parsers
   - Set up bounded fuzzing workflow
   - Integrate with CI

3. **Property-based testing**
   - Add Hypothesis for invariant testing
   - Define invariants for scoring, calibration, ensemble

### Phase 3: Release Infrastructure (Weeks 5-6)

1. **Build identity embedding**
   - Create _build_info.py module
   - Embed source commit, dependency hashes
   - Add `textforensics build-info` command

2. **Contract info embedding**
   - Hash API specs, schemas, fixtures
   - Add `textforensics contract-info` command
   - Enable deployment drift detection

3. **Package verification**
   - Create verify_package.py
   - Implement read-only verification
   - Add checksum manifests

### Phase 4: Enterprise Features (Weeks 7-8)

1. **Enterprise policy framework**
   - Define policy schema (JSON Schema)
   - Implement policy enforcement
   - Add revision floor mechanism

2. **Emergency stop sentinel**
   - Implement environment variable configuration
   - Add checks at API boundaries
   - Document in operations runbook

3. **Audit anchor system**
   - Create export/verify commands
   - Document rollback detection
   - Integrate with backup/restore

### Phase 5: Documentation (Weeks 9-10)

1. **Architecture documentation**
   - ARCHITECTURE.md (component map, data flow)
   - TRUST_MODEL.md (trust boundaries, abstention criteria)
   - CALIBRATION.md (methodology, validation)

2. **Operations runbook**
   - OPERATIONS.md (monitoring, backup, recovery)
   - Incident response procedures
   - Escalation guidelines

3. **Development contract**
   - AGENTS.md (North star, hard rules)
   - CONTRIBUTING.md (review checklist)
   - TESTING.md (evidence rules)

---

## 9. Key Takeaways

### What Makes This Repository Exceptional

1. **Honesty about limitations:** Every claim is qualified, every metric has context, every boundary is explicit.

2. **Evidence over assertion:** Nothing is claimed without verifiable evidence (commits, hashes, attestations).

3. **Fail-closed by default:** When in doubt, refuse. When uncertain, hold for human review.

4. **Cryptographic binding:** Everything ties back to source commits through hashes.

5. **Independent verification:** Multiple tools cross-check the same properties (cargo-audit + cargo-deny, SHA-256 + Ed25519).

6. **Reproducibility as a feature:** Byte-for-byte reproducible builds, deterministic test seeds, bounded randomness.

7. **Documentation as contract:** Docs aren't just explanations—they're specifications with machine-readable components.

### Patterns Most Applicable to TextForensics

| Priority | Pattern | Effort | Impact |
|----------|---------|--------|--------|
| **P0** | Per-commit evidence preservation | Low | High |
| **P0** | Engineering policy as code | Medium | High |
| **P0** | Embedded build/contract identity | Low | High |
| **P1** | Mutation testing for scoring logic | Medium | High |
| **P1** | Release evidence gating | Medium | High |
| **P1** | Machine-readable CLI output | Low | Medium |
| **P2** | Fuzzing for input parsers | Medium | Medium |
| **P2** | Enterprise policy framework | High | Medium |
| **P2** | Audit anchor system | Medium | Medium |
| **P3** | Emergency stop sentinel | Low | Low |
| **P3** | SLSA attestation | Medium | Low |

---

## Appendix A: Workflow File Templates

### A.1 Core CI Template

```yaml
name: TextForensics CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: textforensics-ci-${{ github.event_name == 'pull_request' && github.ref || github.sha }}
  cancel-in-progress: false  # Preserve per-commit evidence

jobs:
  test:
    name: Verify (${{ matrix.os }})
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          pip install --require-hashes -r requirements.txt
          pip install --require-hashes -r requirements-dev.txt

      - name: Run detector tests
        run: pytest tests/detectors/ -v

      - name: Run calibration tests
        run: pytest tests/calibration/ -v

      - name: Run benchmark validation
        run: pytest tests/benchmarks/ -v

      - name: Verify source unchanged
        run: git diff --exit-code HEAD

  verify:
    name: All required checks
    if: always()
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - name: Require every required job green
        env:
          TEST_RESULT: ${{ needs.test.result }}
        run: |
          if [ "${TEST_RESULT:-missing}" != "success" ]; then
            echo "required job did not succeed" >&2
            exit 1
          fi
```

### A.2 Supply Chain Template

```yaml
name: Supply-chain security
on:
  push:
    branches: [main]
  schedule:
    - cron: "23 4 * * 1"  # Weekly

permissions:
  contents: read

jobs:
  advisories:
    name: Dependency advisories
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5

      - name: Install pip-audit
        run: pip install pip-audit

      - name: Run pip-audit
        run: pip-audit --require-hashes -r requirements.txt

      - name: Run safety check
        run: safety check --full-report

  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5

      - name: Install cyclonedx-bom
        run: pip install cyclonedx-bom

      - name: Generate SBOM
        run: |
          cyclonedx-py requirements -i requirements.txt -o sbom.cdx.json
          sha256sum sbom.cdx.json > sbom.cdx.sha256

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: sbom.*
```

---

## Appendix B: Script Templates

### B.1 Release Evidence Collector

```python
#!/usr/bin/env python3
"""Collect release evidence from GitHub Actions workflows."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import urlopen, Request

MAX_EVIDENCE_AGE = timedelta(days=7)

REQUIRED_WORKFLOWS = {
    "ci.yml": "Core CI",
    "test-detectors.yml": "Detector tests",
    "benchmark.yml": "Benchmark validation",
    "calibration.yml": "Calibration verification",
    "supply-chain.yml": "Supply-chain security",
}


def get_workflow_run(repo: str, workflow: str, commit: str) -> dict:
    """Get latest workflow run for commit."""
    url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs"
    url += f"?head_sha={commit}&per_page=1"

    req = Request(url, headers={"Accept": "application/vnd.github+json"})
    with urlopen(req) as resp:
        data = json.loads(resp.read())

    if not data["workflow_runs"]:
        raise ValueError(f"No runs found for {workflow}")

    return data["workflow_runs"][0]


def validate_run(run: dict, workflow: str, commit: str) -> None:
    """Validate workflow run meets evidence requirements."""
    if run["head_sha"] != commit:
        raise ValueError(f"{workflow}: wrong commit")

    if run["status"] != "completed":
        raise ValueError(f"{workflow}: not completed")

    if run["conclusion"] != "success":
        raise ValueError(f"{workflow}: not successful")

    updated = datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
    age = datetime.now(timezone.utc) - updated
    if age > MAX_EVIDENCE_AGE:
        raise ValueError(f"{workflow}: evidence too old ({age})")


def collect_evidence(repo: str, commit: str) -> dict:
    """Collect all required evidence."""
    evidence = []

    for workflow, name in REQUIRED_WORKFLOWS.items():
        run = get_workflow_run(repo, workflow, commit)
        validate_run(run, workflow, commit)

        evidence.append(
            {
                "workflow": workflow,
                "name": name,
                "run_id": run["id"],
                "commit": run["head_sha"],
                "updated_at": run["updated_at"],
                "conclusion": "success",
            }
        )

    return {
        "schema_version": 1,
        "repository": repo,
        "source_commit": commit,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "automated_evidence": evidence,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: collect_evidence.py <repo> <commit>")
        sys.exit(1)

    repo, commit = sys.argv[1], sys.argv[2]
    evidence = collect_evidence(repo, commit)

    output = Path("release-evidence.json")
    output.write_text(json.dumps(evidence, indent=2))
    print(f"Evidence collected: {output}")
```

---

**Document Version:** 1.0
**Last Updated:** 2026-11-02
**Maintainer:** Research subagent for TextForensics project
