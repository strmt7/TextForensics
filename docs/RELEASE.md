# Release checklist

Use this checklist for every tagged release.

## Version and compatibility
- [ ] Version follows the project's pre-1.0 semantic-versioning policy.
- [ ] `CHANGELOG.md` describes user-visible changes.
- [ ] Supported Python versions match CI and metadata.
- [ ] Public JSON/schema changes are versioned or backwards compatible.
- [ ] Detector/calibration semantic changes are explicitly documented.

## Quality
- [ ] Full unit/integration test suite passes.
- [ ] Linux/macOS/Windows smoke matrix passes.
- [ ] Wheel builds and installs in a clean environment.
- [ ] Optional API suite passes.
- [ ] Optional MCP construction/integration suite passes.
- [ ] OCI image builds, starts, passes health check, and runs non-root.
- [ ] `pip check` passes.
- [ ] Ruff critical checks pass.

## Security / supply chain
- [ ] CodeQL is green.
- [ ] Dependency review is green for release PR.
- [ ] Scheduled/manual dependency audit has no unaccepted high/critical finding.
- [ ] Release artifacts are checksummed.
- [ ] No credentials, private corpora, or raw user documents are included.
- [ ] New network behavior is documented and opt-in where required.

## Scientific claims
- [ ] No benchmark number was copied from external work and presented as TextForensics performance.
- [ ] Any performance claim points to a reproducible run artifact.
- [ ] Threshold/calibration data are separate from final evaluation data.
- [ ] Human false-positive rate is visible at the claimed operating point.
- [ ] Relevant domain/language/length/revision limitations are adjacent to the claim.
- [ ] Any top-level probability has an explicit calibration artifact for the exact detector/ensemble version.

## Packaging
- [ ] `python -m build` succeeds.
- [ ] `twine check dist/*` succeeds.
- [ ] wheel contains packaged schemas.
- [ ] OCI image uses the intended application version.
- [ ] installation guide commands match the tagged version.

## Documentation
- [ ] README reflects actual behavior.
- [ ] SECURITY policy is current.
- [ ] SUPPORT policy is current.
- [ ] operations/install docs are current.
- [ ] migration notes exist for breaking changes.

## Post-tag
- [ ] Verify released artifact checksum.
- [ ] Install from the published distribution in a clean environment.
- [ ] Run `textforensics --version`.
- [ ] Run one CLI report/case round trip.
- [ ] Start the published OCI image and check `/healthz`.
