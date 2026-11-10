# Supported profiles

W0 record of what this repository **currently** supports, derived from
`pyproject.toml`, `.github/workflows/*.yml`, `docs/INSTALLATION.md`,
`SECURITY.md`, `Dockerfile` and `compose.yaml` at head `3ff3650`.
Nothing here is aspirational: where the evidence contradicts a claimed
profile, the limitation is recorded as a limitation. Any narrowing of
advertised Windows/macOS support beyond what the evidence already
states is an **open owner decision** (see the end of this document);
W0 does not decide it.

## Interpreters

| Item | Value | Source |
| --- | --- | --- |
| `requires-python` | `>=3.11` | `pyproject.toml` |
| Classifiers | 3.11, 3.12, 3.13, 3.14, 3.15 | `pyproject.toml` |
| CI core matrix | 3.11, 3.12, 3.13, 3.14, 3.15 (Ubuntu) | `ci.yml` job `core` |
| Claims / pinned / SBOM / package jobs | 3.12 only | `ci.yml` |
| OS smoke matrix | 3.11, 3.15 | `ci.yml` job `os-smoke` |
| API / MCP surface jobs | 3.11, 3.15 | `ci.yml` jobs `api`, `mcp` |
| Deep-verification matrix | 3.11–3.15 | `enterprise-deep-verification.yml` |
| Fuzz matrix | 3.11, 3.12, 3.13 | `fuzz.yml` |
| Mutation | 3.11 | `mutation.yml` |
| Canonical lock resolution | Python 3.12 | `requirements-pinned.txt` header; `SECURITY.md` |

## Operating systems

| OS | Claimed | Actually exercised | Source |
| --- | --- | --- | --- |
| Linux (Ubuntu) | Yes | Full core suite, claims, SBOM, packaging, deep verification | `ci.yml`, `enterprise-deep-verification.yml` |
| Windows 10+ | Yes, in installation docs | Two shallow CLI operations only (`--version`, one `scan --json` piped through a JSON parse) | `ci.yml` job `os-smoke`; `docs/INSTALLATION.md` |
| macOS | Yes, in installation docs | Two shallow CLI operations only (same as Windows) | `ci.yml` job `os-smoke`; `docs/INSTALLATION.md` |

**Limitation (evidence-contradicted, do not claim otherwise):** the
real Windows extras suite is **red** at the audit baseline — 3,961
passed, 21 failed, 4 errors, 1 skipped, 1,985 subtests passed in
198.64 s, exit 1 (audit `evidence.json` `/full_suite`, Windows,
Python 3.12.10, extras constrained to applicable pinned versions,
Linux-only atheris absent). Cross-platform "green" in CI therefore
does **not** substantiate the breadth of advertised Windows/macOS
functionality (audit ENG-09). Full pytest/coverage, evidence/claims/
SBOM, sealing, dataset-fixture handling and installed-distribution
web tests run nowhere in the Windows/macOS CI lanes.

**Limitation:** no repository `.gitattributes` protects hash-covered
bytes, so an ordinary Windows checkout with `core.autocrlf=true`
converts tracked JSON/text to CRLF and the claims gate returns 0/33
with 34 registry hash failures (audit ENG-08). An ordinary
supported-platform checkout currently cannot verify the repository's
own evidence on Windows.

## Extras (install profiles)

From `pyproject.toml` `[project.optional-dependencies]`:

| Extra | Contents | Notes |
| --- | --- | --- |
| (core, no extra) | No mandatory third-party runtime dependencies | The forensic core is importable without GPU stacks |
| `api` | fastapi, jinja2, uvicorn, websockets | Serves `textforensics serve` and `textforensics-web` |
| `mcp` | mcp | Serves `textforensics-mcp` |
| `all` | api + mcp | |
| `cli-rich` | rich | `--rich` terminal output |
| `enterprise` | cryptography | Sealing/policy features; used by the OS-smoke install |
| `diagnostics` | psutil | Diagnostics |
| `fuzzing` | atheris | **Linux-only** (manylinux wheels); see limitation below |
| `ollama` | aiohttp | Ollama/local-LLM adapter (`src/textforensics/ollama.py`) |
| `dev` | build, coverage, jsonschema, pre-commit, pytest + plugins, ruff, twine, hypothesis, cosmic-ray, httpx, psutil, cryptography, aiohttp | Core CI venv is `.[dev]` |
| `security` | bandit, pip-audit | Security gates |

**Limitation:** the canonical `requirements-pinned.txt` install fails
on Windows because atheris 3.1.0 ships manylinux-only wheels
(audit ENG-09). The lock is Python 3.12 / Ubuntu-specific by design
(`SECURITY.md`: "installed only on 3.12/ubuntu (the `pinned`, `sbom`,
and `pip-audit-gate` jobs); if a job ever installs it on another
Python or OS, the lock must be re-resolved per environment first").
It carries versions, not hashes, and has no environment markers. It
is **not** a portable installer, and no per-environment locks exist
yet (W6).

**Limitation:** the installed web console cannot start from a normal
wheel install (audit ENG-01): package data includes only
`schemas/*.json` and `_build_info.json` (`pyproject.toml`), while
`textforensics-web` requires `web_ui/static` and templates. Both
downloaded exact-SHA CI wheels contain only
`textforensics/web_ui/main.py` under that package. `create_web_app()`
raises `RuntimeError` for the absent static directory when installed
outside the checkout. The wheel gate does not exercise the installed
web application.

## Deployment profiles

| Profile | How it runs | Bind | Notes |
| --- | --- | --- | --- |
| Local CLI | `textforensics …` | n/a (no socket) | Core is local-first; no text leaves the machine unless an opt-in remote adapter is selected |
| API server | `textforensics serve` / `textforensics-api` | `127.0.0.1:8765` by default | `serve_api()` refuses a non-loopback bind unless `--allow-remote` / `TEXTFORENSICS_ALLOW_REMOTE=1` |
| Web UI (FastAPI) | `textforensics web` / `textforensics web-fastapi` / `textforensics-web` | `127.0.0.1:8765` by default | Same bind guard; `web` additionally opens a browser unless `--no-browser` |
| MCP server | `textforensics-mcp` | stdio (no socket) | MCP transport is the client's stdio channel, not a network listener |
| Container | `Dockerfile` (`python:3.12-slim`, multi-arch linux/amd64 + linux/arm64) | Loopback publishing in the hardened `compose.yaml` example (read-only rootfs, dropped capabilities, `no-new-privileges`, tmpfs `/tmp`) | See deployment policy |

Full bind/authentication rules are in
`docs/verification/deployment-policy.md`.

## What is NOT supported (explicit)

- **Remote tenancy / multi-user hosted service.** The current alpha
  explicitly excludes remote tenancy (interfaces audit). There is no
  authentication, no per-user isolation, and no tenant model anywhere
  in the shipped surfaces. See the deployment-policy doc.
- **Windows/macOS full-workflow qualification.** Not supported by
  evidence at the audit baseline (see the limitations above); W9 must
  qualify it before it can be claimed.
- **Portable canonical-lock install.** The exact-pin lock is
  Python 3.12 / Ubuntu only.
- **Atheris fuzzing on Windows/macOS.** Linux-only.
- **Qualified timestamps.** Only a qualified timestamp from a QTSP
  carries an eIDAS presumption; qualified timestamps are out of scope
  for v1.0 (`SECURITY.md`). Free public TSA tokens are honestly
  labelled "RFC 3161 timestamp (non-qualified)".

## Open owner decisions

1. **Narrowing advertised Windows/macOS support.** The evidence
   already states the limitations above; deciding whether to narrow
   the advertised support (rather than qualify it in W9) is an owner
   decision. W0 records the gap and does not narrow anything.
2. **Per-environment locks.** Whether to produce tested
   environment-specific locks (W6) and which profiles they cover.
3. **Signing/TSA trust identity, public-snapshot/container policy,
   branch-protection governance, final release authorization.**
   Flagged in every W0 doc; none is decided here.
