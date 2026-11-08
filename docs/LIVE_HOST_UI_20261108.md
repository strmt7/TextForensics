# Live-host verification — web UI (2026-11-08)

Worker 3 of the live-host verification wave. Branch `fix/live-host-ui`,
base `884f590`. Scope: web UI live check + `docs/INSTALLATION.md`
accuracy for the server/container commands. No code, tests, CI, or
claims changes.

## What the code says

- `textforensics serve` runs the ASGI **API only**
  (`src/textforensics/api.py`): routes `/healthz`, `/readyz`,
  `/version`, `/v1/*`. It has **no** `/` route and mounts no static
  files or templates.
- The browser UI is a separate command: `textforensics web` (also
  `textforensics web-fastapi`, or the `textforensics-web` console
  script). It serves `src/textforensics/web_ui/main.py`
  (`create_web_app`): `GET /` and `GET /index.html` (Jinja2
  `index.html`), `/static/*` (vendored `style.css`, `app.js`,
  `chart.umd.min.js`), `/healthz`, `/readyz`, `/version`,
  `/v1/detectors`, `/api/*`, and `ws:///ws/analyze`. The UI and the
  API are **not** served by the same process; `web` is its own
  process that happens to include `/api/*` endpoints.
- The container image runs the API only: `Dockerfile` ends with
  `ENTRYPOINT ["textforensics"]`, `CMD ["serve"]`.

## Live check — bare server (this VM)

Invocation (documented `web` command; `--no-browser` avoids opening a
browser on a headless host; port 8766 because a sibling worker owns
8765):

```bash
PYTHONPATH=<worktree>/src <main-clone>/.venv/bin/textforensics web \
  --host 127.0.0.1 --port 8766 --no-browser
```

Server started cleanly, loopback only
(`Uvicorn running on http://127.0.0.1:8766`).

| Request | Status | Content-Type | Size |
|---|---|---|---|
| `GET /` | 200 | text/html; charset=utf-8 | 11036 B |
| `GET /index.html` | 200 | text/html; charset=utf-8 | 11036 B |
| `GET /static/style.css` | 200 | text/css; charset=utf-8 | 20880 B |
| `GET /static/app.js` | 200 | text/javascript; charset=utf-8 | 34935 B |
| `GET /static/chart.umd.min.js` | 200 | text/javascript; charset=utf-8 | 205399 B |
| `GET /healthz` | 200 | application/json | 15 B |
| `GET /readyz` | 200 | application/json | 18 B |
| `GET /version` | 200 | application/json | 42 B (`{"name":"TextForensics","version":"0.2.0"}`) |
| `GET /v1/detectors` | 200 | application/json | 273 B |
| `GET /nonexistent-ui-route` | 404 | application/json | 22 B (`{"detail":"Not Found"}`) |
| `GET /static/nope.css` | 404 | application/json | 22 B (`{"detail":"Not Found"}`) |
| `POST /api/analyze` (short human sentence) | 200 | application/json | 9611 B (`success: true`, verdict `abstain`) |

- `/` is real TextForensics UI HTML: `<title>TextForensics - AI
  Text Detection Dashboard</title>`, references only the three local
  static assets above. No third-party URLs in `index.html` or
  `app.js` (local-first holds).
- Every asset the index references was fetched and returned 200.
- Nonexistent routes return a clean JSON 404, no traceback.
- Security headers present on responses (CSP `default-src 'self'`,
  `Permissions-Policy`, `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store`, `X-TextForensics-Version: 0.2.0`).
- Server log: **0 tracebacks, 0 errors** across all requests
  (including the 404s and the analyze POST).
- Minor observation, not a defect: `HEAD /` returns 405 (FastAPI
  registers GET only). Not documented anywhere, not fixed.

## Docs audit — `docs/INSTALLATION.md`

| Documented command | Verdict | Evidence / correction |
|---|---|---|
| `python -m pip install ".[api]"` then `textforensics serve` | Works as written (API) | `serve` starts; `/healthz` 200. But it serves **no UI** — see correction below. |
| `textforensics serve --host 127.0.0.1` (bare server) | Works as written (API) | Verified live on port 18765: `/healthz` 200, `/version` 200, `/` **404** (API has no root route). |
| `textforensics serve --host 0.0.0.0 --allow-remote` | Works as written (guard path) | Without `--allow-remote`, `0.0.0.0` is refused with exit 3 for both `serve` and `web`. The `--allow-remote` form itself was not executed (would bind a network-visible interface on this VM); the guard behaviour on both sides of it is verified. |
| `docker build -t textforensics:local .` / `docker run --rm -p 127.0.0.1:8765:8765 textforensics:local` | **Not verifiable here yet** | `docker: command not found` on this VM at check time (2026-11-08 ~09:32 CET); a sibling worker is installing Docker in parallel. |
| `podman build …` / `podman run …` | **Not verifiable here yet** | `podman: command not found` on this VM. |
| `docker compose up --build` | **Not verifiable here yet** | No Docker/Compose on this VM. `compose.yaml` itself was read: loopback publish `127.0.0.1:${TEXTFORENSICS_HOST_PORT:-8765}:8765`, read-only fs, `TEXTFORENSICS_HOST=0.0.0.0` inside the container, image `textforensics:local`. |

No documented command was proven wrong. Two gaps were corrected in
`docs/INSTALLATION.md` (this branch):

1. **The UI had no run command in the doc at all.** `INSTALLATION.md`
   documented only `serve`, so a reader following it to run the
   browser UI gets a 404 at `/`. Added a "Browser UI (bare server /
   VM)" section documenting `textforensics web --host 127.0.0.1`
   (default `127.0.0.1:8765`, `--no-browser`, same remote-bind
   guard) and stating `serve` is API-only.
2. **Docker section did not say what the image serves.** Added that
   the image runs `textforensics serve` (API only) and the browser UI
   is not available from the container (`GET /` → 404).

## Still unverified (pending)

- **Container re-check (step 4 of the brief):** no Docker image was
  reported by the sibling worker before this report, and Docker is
  not installed on this VM, so the UI check against
  `textforensics:local` on `127.0.0.1:8765` could not run. Expected
  outcome when it does run, from the code + the live `serve` probe:
  `/healthz` 200, `/` **404** — the image's `CMD ["serve"]` serves
  the API only, so a UI check against the container as documented
  will fail at the index page. If the release intends the container
  to serve the UI, the image CMD (not the docs) needs to change; that
  decision is outside this worker's scope.
- `podman` commands: untested (no Podman on this VM).
- `textforensics serve --host 0.0.0.0 --allow-remote` executed form:
  not run (network-visible bind); only the refusal side is verified.

## Verification on this branch

- `pre-commit run --all-files`: 13/13 hooks passed, exit 0; the run
  modified no files (`git status` shows only the two intended
  files).
- Claims gate: 33 passed, 0 failed (`scripts/check_claims.py`,
  exit 0).
- Schemas: 12/12 OK (`scripts/validate_schemas.py`, exit 0).
- Full test suite: **not yet fully green at report time — see
  below.** This is a docs-only branch (2 `.md` files, no code), so
  no test outcome can be caused by the change; the incompleteness
  is runtime, not a failure:
  - Main full run (`python -m pytest tests/ -q`, started 09:47
    CET, log `/tmp/lh-ui-suite.log`, PID 13392): reached 68% with
    **0 failures**, then entered `tests/test_mutation.py`, which is
    still running at report time (37/44 test functions, 0 failures
    so far). The slowness is pre-existing and environmental:
    `parse_results` re-validates all 787 baseline entries
    (~0.37 s each, ~5 min per call at full CPU; measured directly),
    several mutation tests call it, and sibling workers' cosmic-ray
    sessions kept VM load at 5–13 on 4 CPUs, giving this run
    ~10–30% CPU share.
  - Separate run of the 39 test files alphabetically after
    `test_mutation.py` (log `/tmp/lh-ui-suite-rest.log`):
    **852 passed, 36 subtests passed, 0 failed** in 8:12.
  - Net: every test file except `tests/test_mutation.py` is proven
    green on this branch; `test_mutation.py` is in progress with 0
    failures. The main full run was left running for the parent to
    confirm (PID 13392, `/tmp/lh-ui-suite.log`).
