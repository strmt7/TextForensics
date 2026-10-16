# External provider adapters

External detector providers can be useful evidence sources, but they are changing black-box instruments.

## Rules

1. Use official or otherwise authorized APIs/integrations only.
2. Never scrape a provider or circumvent access controls.
3. Require explicit user opt-in before sending document text.
4. Credentials are user supplied and never written into case files.
5. Expose cost/rate/timeout controls.
6. Preserve the provider's native score/verdict semantics.
7. Record provider/product/model/version metadata when exposed.
8. Record observation timestamp.
9. Treat provider output as an observation, not ground truth.
10. Revalidate assumptions when provider behavior/version changes.

## Adapter result metadata

Where available, capture:
- provider,
- product,
- model/version,
- API version,
- detector score/verdict,
- native score semantics,
- minimum text length,
- supported language/format,
- request timestamp,
- response/request identifiers that are safe to store,
- latency,
- documented limitations.

## Drift

A provider adapter should integrate with the observatory.

Use a stable probe corpus and multiple observations before reporting drift. Useful comparisons include:
- paired score change,
- verdict flips,
- human-control false-positive changes,
- provider/model version changes,
- changes in unsupported inputs.

If provider version metadata is unavailable, make that uncertainty visible.

## Data handling

Remote adapters must:
- make the network boundary visible in UI/CLI/MCP,
- sanitize errors that may echo source text,
- avoid persistent raw-text logs,
- allow the user to disable all remote adapters,
- document provider retention/privacy implications when known.

