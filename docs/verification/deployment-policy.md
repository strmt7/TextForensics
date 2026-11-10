# Deployment policy

Explicit deployment policy at head `3ff3650`, stated from source
(`src/textforensics/config.py`, `src/textforensics/api.py`,
`src/textforensics/web_ui/main.py`, `src/textforensics/cli.py`,
`Dockerfile`, `compose.yaml`). This policy describes what the code
currently enforces; it does not invent an authentication deployment
that does not exist.

## 1. Local-only by default

TextForensics is local-first. By default nothing listens on a
non-loopback interface and no text leaves the machine:

- `Settings` defaults (`config.py:75-79`): host `127.0.0.1`, port
  `8765`, `max_input_bytes` 2,000,000, `allow_remote` False.
- `serve_api()` (`api.py:187-191`), `serve_web()`
  (`web_ui/main.py:743-765`) and the CLI `serve` / `web` /
  `web-fastapi` commands all call `ensure_bind_allowed(host,
  allow_remote=…)` **before** starting the server
  (`config.py:66-73`).
- The MCP server uses stdio transport; it opens no network listener.

## 2. Loopback-only vs remotely accessible

| Surface | Default bind | Non-loopback bind | What gates it |
| --- | --- | --- | --- |
| API server (`textforensics serve`, `textforensics-api`) | `127.0.0.1:8765` | Refused unless `--allow-remote` or `TEXTFORENSICS_ALLOW_REMOTE=1` | `ensure_bind_allowed` in `serve_api()` before `uvicorn.run` |
| Web UI (`textforensics web`, `textforensics web-fastapi`, `textforensics-web`) | `127.0.0.1:8765` | Refused unless `--allow-remote` or `TEXTFORENSICS_ALLOW_REMOTE=1` | `ensure_bind_allowed` in the CLI dispatch (before the web-UI import, so the refusal surfaces first in a core-only install) and in `serve_web()` |
| MCP server (`textforensics-mcp`) | stdio, no socket | n/a — no listener exists | n/a |
| CLI (all analysis commands) | n/a — no socket | n/a | n/a |
| Container (`Dockerfile`, `compose.yaml`) | Loopback publishing in the hardened `compose.yaml` example | Only if the operator publishes a non-loopback port | Operator's compose/run invocation; the image itself does not enforce a bind |

`ensure_bind_allowed` (`config.py:66-73`) refuses any host that is
not loopback (`127.0.0.0/8`, `::1`, `localhost`, `ip6-localhost`)
and not an unspecified address, unless `allow_remote` is true. The
refusal message tells the operator to pass `--allow-remote` or set
`TEXTFORENSICS_ALLOW_REMOTE=1`.

**Important scope note:** `--allow-remote` / `TEXTFORENSICS_ALLOW_REMOTE`
is a *bind* opt-in: it permits the server to listen on a
non-loopback interface. It is **not** authentication, not
authorization, and not per-request remote-adapter consent:

- The HTTP surfaces have no authentication of any kind: no token,
  no password, no TLS configuration, no per-user session credential
  for mutating operations. Anyone who can reach a remotely-bound
  server can submit text, read history, clear history, join sessions
  and share analyses.
- The WebSocket endpoint has no Host/Origin check beyond the
  same-origin Content-Security-Policy (`connect-src 'self'`), which
  constrains the shipped page, not a raw WebSocket client.
- `--allow-remote` also doubles as the remote-*detector* opt-in on
  the drift path (`drift snapshot` / `drift run`), which is a
  separate meaning of "remote" from the bind. The two meanings share
  one flag; W1 must separate them (execution policy vs bind policy).

## 3. Remote tenancy is explicitly excluded

The current alpha **explicitly excludes remote tenancy** (interfaces
audit). There is no multi-user hosted service, no tenant isolation,
no per-user data separation, and no account system in the shipped
surfaces:

- The web UI's "sessions" are in-memory collaboration rooms keyed
  by a client-supplied or server-generated session id, held in a
  process-local ring buffer (max 100 entries by default). They are
  not authenticated, not persisted, and not isolated per user.
- Analysis history is a process-local, unauthenticated ring buffer.
- Case files, ledgers and policy state are local files with
  filesystem permissions as their only protection.

**Consequence:** a remotely-bound server is a single-tenant,
unauthenticated service for whoever can reach it. Remote access is
supported only in the narrow sense that the bind guard can be
overridden with an explicit flag; it is **not** a supported
multi-user deployment. Do not present `--allow-remote` as making the
service safe to expose.

## 4. Container deployment

- Image: `Dockerfile`, `python:3.12-slim`, multi-arch
  linux/amd64 + linux/arm64, published to GHCR by
  `.github/workflows/container.yml` on qualifying main pushes.
- The hardened `compose.yaml` example uses loopback publishing, a
  read-only root filesystem, dropped Linux capabilities,
  `no-new-privileges`, and tmpfs for `/tmp`.
- **Limitation (audit ENG-14):** container publication bypasses
  release acceptance — a qualifying main push builds and immediately
  pushes `latest`, version and short-SHA tags with no dependency on
  the test/claims/security/package/reproducibility jobs and no
  post-build running-image acceptance step. The container is
  therefore not a governed release artifact at the audit baseline,
  and the image SBOM scans the source tree (`path: .`), not the
  built image digest.
- In-container HEALTHCHECK behaviour is unverified (live-host
  verification, 2026-11-08); `docker run` itself is blocked on the
  build VM by a host/cell restriction, not a repo defect.

## 5. What is NOT supported

- No authenticated remote deployment (no authn/authz, no TLS
  configuration, no tenant model). Any deployment that exposes the
  API or web UI beyond loopback is the operator's explicit,
  unauthenticated choice, not a supported multi-user service.
- No remote tenancy, no hosted service, no per-user isolation.
- No public snapshot policy: whether automated main snapshots are
  intentionally public is unstated (ENG-14) — see open decisions.
- No signing/TSA trust identity for release material yet (W10).

## 6. Open owner decisions

1. **Public-snapshot/container policy** — state clearly whether
   automated main snapshots are intentionally public; do not call
   them governed releases without the W0/W7/W10 controls.
2. **Signing/TSA trust identity and credential policy** — external
   signing identity, TSA trust policy, and who holds the keys.
3. **Branch-protection governance** — repository governance changes.
4. **History-rewrite privacy cleanup** — owner-authorized only; see
   `docs/audits/2026-11-10/privacy-disposition-w0.md`.
5. **Final release authorization** — owner only.
6. **Which remote providers/adapters are eligible for opt-in at
   all** — no remote provider is endorsed here; eligibility is a
   W1/W2 decision, not a W0 one.
7. **Whether the stop should cover MCP ledger/drift writes and the
   `/api/export` and `/api/compare` handlers** (per-handler asserts
   vs middleware-only gating) — see the operation inventory §8.
