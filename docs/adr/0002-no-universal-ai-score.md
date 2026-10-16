# ADR 0002 — No universal AI score

**Status:** accepted

## Decision

TextForensics does not define one universal "AI percentage" from arbitrary detector scores.

## Why

Different detectors expose incompatible score semantics and operating ranges. Even individually calibrated probabilities do not imply that an arithmetic ensemble is calibrated.

## Consequences

- preserve detector-native observations;
- calibrated probability is optional and provenance-linked;
- aggregate diagnostic/consensus values are labeled according to what they actually mean;
- top-level probability requires a separately calibrated, versioned ensemble.
