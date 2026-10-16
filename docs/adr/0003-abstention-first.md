# ADR 0003 — Abstention first

**Status:** accepted

## Decision

Unsupported or weak-evidence cases may return an explicit abstention/insufficient-evidence state.

## Why

Forcing every input into human-like or AI-like hides model limitations and increases the risk of false accusations.

## Consequences

- adapters may abstain by capability rules;
- Trust Map can downgrade/withhold an overall conclusion;
- APIs and MCP preserve abstention as a first-class state;
- product UX treats insufficient evidence as a valid result.
