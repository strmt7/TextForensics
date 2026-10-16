# Support policy

TextForensics is an open-source project under active development.

## Community support

For reproducible bugs, installation problems, and feature requests, use GitHub Issues and the provided issue templates.

Before opening an issue:
1. check existing issues;
2. record `textforensics --version`;
3. identify installation mode and operating system;
4. remove private source text and credentials from logs/reproductions;
5. include the smallest synthetic example that reproduces the behavior.

## Security reports

Do **not** use normal issues for security vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## Detector-result disputes

A detector outcome is not a conventional software bug merely because it disagrees with a human expectation. For detector-quality reports, include:
- detector ID/version;
- language/domain/approximate length;
- whether text was revised, translated, or mixed-origin;
- a privacy-safe reproduction if possible;
- benchmark or false-positive evidence if available.

Never upload confidential material just to demonstrate a detector disagreement.

## Compatibility

The project targets Python 3.10–3.13 and validates the core on Linux, macOS, and Windows in CI. OCI deployment is validated on Linux.

Optional detector plugins may have narrower hardware/platform requirements; those requirements belong to the plugin.

## Service levels

The public repository does not provide a contractual SLA, response-time guarantee, availability commitment, or commercial support entitlement.

Any commercial SLA/support arrangement would require a separate explicit agreement.
