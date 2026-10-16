## What changed?

<!-- Briefly describe the change and why it belongs in TextForensics. -->

## Evidence / validation

<!-- Tests, benchmark run IDs, screenshots, or reproduction commands. -->

## Semantics checklist

- [ ] I did not relabel an uncalibrated score as a probability.
- [ ] If detector/calibration semantics changed, I documented the exact meaning and version.
- [ ] Abstention and unsupported-input behavior remain visible.
- [ ] I considered human false-positive impact.
- [ ] Benchmark/calibration data are separate from final evaluation data where applicable.
- [ ] I documented network behavior for any remote capability.
- [ ] Raw user text is not newly persisted/logged by default.
- [ ] Tests cover the changed behavior.
- [ ] Documentation/schema changes are included when public contracts changed.
- [ ] Public performance claims, if any, point to reproducible run artifacts.

## Detector/plugin additions

If this adds a detector, include:
- detector family and independent value,
- model/checkpoint/provider version,
- license,
- language/length/domain constraints,
- local/remote execution,
- benchmark/calibration status.

See [AGENTS.md](../AGENTS.md) and [docs/QUALITY_GATES.md](../docs/QUALITY_GATES.md).
