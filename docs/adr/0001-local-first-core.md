# ADR 0001 — Local-first core

**Status:** accepted

## Decision

The TextForensics core performs analysis without sending document text over the network. Remote detector/provider adapters are optional and explicitly enabled.

## Why

Documents may contain private academic, professional, legal or unpublished material. Local-first behavior also improves reproducibility and makes the network trust boundary obvious.

## Consequences

- heavy local detector dependencies stay optional;
- remote adapters disclose data flow;
- tests must not require remote services for core behavior;
- UI/MCP/API should identify when a requested operation crosses the network boundary.
