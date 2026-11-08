# Live-host verification — API server (worker 2)

- **Branch:** `fix/live-host-api`
- **Base / head:** `884f590` (`test: kill 180 calibration remainder mutants, baseline 3, counts 487 -> 490`)
- **Date:** 2026-11-08 (times UTC; local CET = UTC+1)
- **Scope:** API live checks + failure modes + restart, bare-server path (no Docker).
  The container re-check (step 5) is **pending** — the sibling Docker worker had not
  reported a built image by the time steps 1–4 finished.

## Method

No Docker was available/needed for steps 1–4. The server was started the
closest-to-container way available: the documented bare-server command, run
from this worktree with the main clone's venv and `PYTHONPATH` pointed at this
worktree's `src` (the main venv has the `[api]` extra installed; the venv's
editable install otherwise resolves to the main clone's `src`).

```bash
cd ~/workspace/TextForensics-lh-api
PYTHONPATH=$PWD/src ~/workspace/TextForensics-rewrite/.venv/bin/textforensics serve
```

Python 3.12.3, FastAPI 0.162.0, uvicorn 0.54.0, package version `0.2.0`.
Bind was the documented default: `127.0.0.1:8765` (loopback only, never exposed).

Raw evidence (full curl transcripts, request payloads, response bodies,
server logs) is preserved in `docs/live-host-api/` alongside this note.

## 1. Documented command — verdict: CORRECT, no docs fix needed

`textforensics serve` with no flags works exactly as `docs/INSTALLATION.md`
prescribes (defaults: host `127.0.0.1`, port `8765`, per `Settings.from_env()`).
No error, no missing flag, no extra invocation needed.

Startup timings (first run):

| Event | Time (UTC) |
|---|---|
| Command issued | 2026-11-08 09:31:35 |
| Uvicorn "Application startup complete / running on http://127.0.0.1:8765" | within the next 20 s (log, `server1.log`) |
| First confirmed `/healthz` 200 | 09:31:55 at the latest (first probe after a 20 s wait) |

Startup is slow (~15 s) because importing the package takes ~15 s on this
machine (measured separately with `python -c "import textforensics"`); that is
import cost, not a server defect.

## 2. GET endpoints — all 200, well-formed, security headers present

Full transcript: `docs/live-host-api/transcript-gets.txt`.

| Endpoint | Status | Body |
|---|---|---|
| `GET /healthz` | 200 | `{"status":"ok"}` |
| `GET /readyz` | 200 | `{"status":"ready"}` |
| `GET /version` | 200 | `{"name":"TextForensics","version":"0.2.0"}` |
| `GET /v1/detectors` | 200 | 1 detector: `textforensics/builtin-heuristic` v`0.1.0`, family `stylometric-heuristic`; `plugin_health`: `builtin` ok |
| `GET /` (extra probe) | 404 | `{"detail":"Not Found"}` |

Every response carried `cache-control: no-store`, `x-content-type-options: nosniff`,
`referrer-policy: no-referrer`, `x-textforensics-version: 0.2.0`.

## 3. POST /v1/analyze — known inputs (round-trip, not accuracy)

Full transcript: `docs/live-host-api/transcript-analyze.txt`.
Request payloads: `docs/live-host-api/req-human.json`, `req-machine.json`.

**Human input** (444 chars, 81 words, exact text in `req-human.json`):

> I spent last Tuesday afternoon trying to fix the squeaky hinge on the back door, which mostly meant standing in the hallway with a can of WD-40 and a screwdriver, wondering why the previous owner had used three different screw heads on the same hinge. My neighbour came over halfway through, offered advice I didn't ask for, and left with my spare screws. The door still squeaks, but only when it rains now, which feels like progress of a sort.

**Machine-like input** (588 chars, 76 words, exact text in `req-machine.json`):

> In today's fast-paced digital landscape, leveraging cutting-edge artificial intelligence solutions is crucial for businesses seeking to stay ahead of the competition. By harnessing the power of advanced machine learning algorithms, organizations can unlock unprecedented levels of efficiency, innovation, and growth. Furthermore, it is important to note that implementing these transformative technologies enables companies to streamline their workflows, enhance their decision-making processes, and deliver exceptional value to their customers in an increasingly competitive marketplace.

| Input | Status | score | verdict | notes |
|---|---|---|---|---|
| Human paragraph | 200 | 0.1875 | `human_like_patterns` | confidence 0.2828; warnings: uncalibrated-heuristic + not-proof-of-authorship |
| Machine-like paragraph | 200 | 0.646 | `insufficient_evidence` | confidence 0.2597; extra warning: short text, below the 80-word minimum (76 words) |

Direction is sane (machine-like text scores higher than human text) and both
responses are well-formed JSON with full analyzer/feature breakdowns. **No
accuracy claim is made** — this only proves the round-trip works and the output
is well-formed. The `insufficient_evidence` verdict on the machine-like text
is the documented short-text abstention, not a misclassification.

## 4. Other POST routes — all 200 (extra smoke, same human input)

Full transcript: `docs/live-host-api/transcript-other-routes.txt`.

| Route | Status | Result |
|---|---|---|
| `POST /v1/report` | 200 | 9,487 bytes; keys: consensus, content_sha256, detector_failures, detector_protocols, detector_results, evidence_registry, generated_at_utc, input, input_conditions, legacy, limitations, plugin_health, provenance, robustness, schema, trust_map |
| `POST /v1/audit` | 200 | `[{"issue":"no_obvious_formulaic_pattern", ...}]` |
| `POST /v1/compare` (human vs machine-like) | 200 | similarity 0.051, before_score 0.1875, after_score 0.646, delta 0.4585 |
| `POST /v1/case` | 200 | 16,619 bytes; case-file v4, `raw_text_included: false`, content_sha256 `bf05f820…` |

## 5. Failure modes

Full transcript: `docs/live-host-api/transcript-failures.txt`.
`TEXTFORENSICS_MAX_INPUT_BYTES` default is 2,000,000; the middleware body cap is
`max_input_bytes * 2 + 65,536` = 4,065,536 bytes.

| # | Input | Status | Response body |
|---|---|---|---|
| F1 | `{}` (missing `text`) | 422 | `{"detail":[{"type":"missing","loc":["body","text"],"msg":"Field required","input":{}}]}` |
| F2 | `{"text": ""}` (empty text) | 422 | `{"detail":"Invalid text input."}` |
| F3 | Empty body, no `Content-Length` header (curl `-X POST` with no data) | 411 | `{"detail":"Content-Length is required."}` |
| F3b | Empty body with explicit `Content-Length: 0` | 422 | `{"detail":[{"type":"missing","loc":["body"],"msg":"Field required","input":null}]}` |
| F4 | Malformed JSON `{"text": "abc` (unterminated) | 422 | `{"detail":[{"type":"json_invalid","loc":["body",9],"msg":"JSON decode error",...}]}` |
| F5 | `text` of 2,000,001 bytes (1 byte over `MAX_INPUT_BYTES`; body 2,000,013 bytes) | 413 | `{"detail":"Invalid text input."}` (0.197 s) |
| F6 | Body of 4,100,012 bytes (over the 4,065,536 middleware cap) | 413 | `{"detail":"Request body is too large."}` (0.005 s — rejected before parsing) |
| F7 | Valid JSON body with `Content-Type: text/plain` | 422 | `model_attributes_type`: "Input should be a valid dictionary…" |
| F8 | `GET /v1/analyze` (wrong method) | 405 | `{"detail":"Method Not Allowed"}`, `Allow: POST` |
| F9 | `{"text": 123}` (non-string) | 422 | `string_type`: "Input should be a valid string" |

All failure modes return JSON error bodies with no stack trace, no raw-text echo,
and no server crash — the server stayed up and answered normally afterwards.

## 6. Restart

| Event | Time (UTC) |
|---|---|
| `kill` issued to first server (PID 42731) | 2026-11-08 09:33:07 |
| Port probe: `/healthz` connection refused / HTTP 000 | 09:33:14 (port down, as expected) |
| Same command re-issued (`textforensics serve`, new PID 43269) | 09:33:07 (same command invocation) |
| `/healthz` 200 again | by ~09:33:24 (second 10 s poll); re-confirmed 09:33:35 |
| Post-restart `POST /v1/analyze` (human input) | 200, identical result: score 0.1875, verdict `human_like_patterns`, word_count 81 (deterministic) |

Restart-to-healthy took ~17 s from kill to first successful probe, consistent
with the ~15 s import/startup cost. Old process confirmed dead (`ps -p 42731`
empty); new process confirmed serving.

## 7. Server-log verdict: CLEAN

`docs/live-host-api/server1.log` and `server2.log` contain only uvicorn
startup lines (`Started server process`, `Application startup complete`,
`Uvicorn running on http://127.0.0.1:8765`). Zero occurrences of
`error` / `traceback` / `exception` across the whole session, including after
all failure-mode probes. Access logging is off by default, as documented.

## 8. New tests added

`tests/test_live_host_smoke.py` — 7 tests, all passing. This is genuinely new
coverage: the existing API tests (`tests/test_api.py`) use FastAPI's in-process
`TestClient` and never bind a socket or run uvicorn. The new tests boot the
real server on `127.0.0.1` with an ephemeral port (port 0, read back after
bind), talk to it over stdlib `http.client`, and cover: health/ready/version/
detectors, analyze round-trip well-formedness, missing-text 422, empty-text
422, malformed-JSON 422, oversized-text 413 (with `max_input_bytes=1024` to
keep it fast), and GET-on-analyze 405. Skipped automatically when
fastapi/uvicorn are absent.

## 9. Still unverified — pending

- **Container re-check (step 5):** repeat steps 2–4 against
  `docker run --rm -p 127.0.0.1:8765:8765 textforensics:local`, confirm the
  `HEALTHCHECK` reports healthy via `docker inspect`, and capture `docker logs`.
  Not done — no built image had been reported by the sibling Docker worker when
  steps 1–4 finished. The bare-server instance was stopped before reporting so
  the port is free for the container run.
- Nothing else on the bare-server side: the documented bare-server command, all
  probed routes, all failure modes, and the restart all behaved as documented.

## 11. Branch verification (parent discipline)

- **Branch:** `fix/live-host-api`, head `884f590` + uncommitted work (docs +
  one new test file; nothing else touched — no `src/`, no workflows, no
  `mutation-baseline.toml`, no `tests/test_mutation.py`, no `check_claims.py`,
  no `docs/validation/registry.json`).
- **pre-commit:** 13/13 passed (`pre-commit run --all-files`, exit 0; run with
  the venv on `PATH` after an earlier run failed only because bare `python`
  was not on `PATH` for three hooks — environment quirk, not a repo defect).
  No files were modified by the run; a second passing run is not claimed as
  proof — `git status` was checked and shows only the new files.
- **Claims gate:** 33 passed, 0 failed (`scripts/check_claims.py`, exit 0).
- **Schemas:** `scripts/validate_schemas.py` exit 0 (all schemas OK).
- **New tests:** `tests/test_live_host_smoke.py`, 7/7 passed standalone and in
  the full suite (not in any FAILED/ERROR line of `fullsuite2.log`).
- **Full suite:** two full runs, both hit environment failures, neither caused
  by this branch (see §12). The targeted re-run of every non-passing test
  passed 129/129, so the branch itself is green; the full-suite runs below are
  reported exactly as observed rather than claimed green.

## 12. Full-suite runs — what actually happened

Two full-suite runs were attempted on this branch; both were derailed by the
shared machine, not by the change (the change is docs + one new test file;
all non-passes are in files this branch never touched, and all pass on
re-run).

**Run 1** (`docs/live-host-api/fullsuite.log`, started 2026-11-08 ~09:51 UTC):
killed at ~70% (2,361 tests, 1 failure — the known `test_memory_check`
flake) when the VM rebooted (~11:49 UTC; `uptime` showed "up 1 min"
afterwards). No completion summary exists; the process simply vanished
with the reboot.

**Run 2** (`docs/live-host-api/fullsuite2.log`, started ~11:51 UTC, after the
reboot): completed in 2:11:21 — **2 failed, 3329 passed, 35 errors,
904 subtests passed** (3,366 collected). The 37 non-passes, all
environmental:

| Non-pass | Cause (from the log) |
|---|---|
| 35 errors — `test_precommit.py` (12), `test_probe_corpus.py` (3), `test_probe_runs.py` (8), `test_probe_runs_e2e.py` (8), `test_result_codec.py` (1), `test_verify_consolidation.py` (3) | `ERROR at setup`: `FileNotFoundError: /tmp/pytest-of-root/pytest-0/...` — the `tmp_path` dir was missing during setup. Five-plus suites ran concurrently after the reboot and raced over the shared `/tmp/pytest-of-root/pytest-0` numbered dir (one suite's startup cleanup removes another's in-use tmp dir). |
| `test_datasets.py::DownloadStallServerTests::test_mid_body_drop_resumes_with_range` | `AssertionError: 1 != 2` (`requests_seen`) — timing-sensitive stall/resume test under heavy load. |
| `test_mutation.py::EquivalentBaselineTests::test_stale_runtime_entry_fails_loudly` | `OSError: [Errno 28] No space left on device` writing a temp JSON — `/tmp` is a **512 MB tmpfs** shared by all parallel suites; it filled during the run (13% used / 6.5 GB free on the overlay afterwards, so this was the tmpfs, not the main disk). The test's own assertions all passed before the temp-file write. |

**Targeted re-run of all 37 non-passing tests** (the six erroring files plus
both failed tests, run together after the machine quieted):
**129 passed, 3 subtests passed in 10:32** — every one of them passes.
The failures/errors are therefore proven environmental flakes, not defects
in this branch or the base commit.

Also verified separately: `tests/test_datasets.py` alone — 100 passed;
`tests/test_ollama.py::TestOllamaConfig::test_preferred_models_default`
alone — 1 passed. (An early mid-run count that appeared to show 11–12
failures was a misread: the count included `F` characters from the pytest
header text (`False` values) and the summary section; the authoritative
tally is the final summary line quoted above.)

Environment notes for the parent: the VM rebooted once mid-verification;
6+ suites ran concurrently on a 4-CPU VM with a 512 MB `/tmp` tmpfs, which
is what produced the tmp collisions, the ENOSPC, and the multi-hour suite
times (run 2 took 2:11:21; a single `parse_results` baseline test takes
>5 min wall under contention). None of that is attributable to this branch.

## 10. Findings

- **No docs defects found.** `textforensics serve` works exactly as
  `docs/INSTALLATION.md` prescribes; defaults (loopback, port 8765) match the
  code (`Settings` defaults) and `compose.yaml`'s loopback-only publish.
- **No server defects found.** All statuses, error bodies, headers, and the
  restart behaviour match the implementation in `src/textforensics/api.py`
  (request guard: 411 without `Content-Length`, 413 over the body cap;
  `validate_text_input`: 413 over `MAX_INPUT_BYTES`, 422 on empty/invalid).
- Minor observation, not a defect: startup takes ~15 s due to package import
  cost; health checks against a freshly started container should allow for
  that. Note the Dockerfile `HEALTHCHECK` uses `--start-period=5s`
  (Dockerfile:60-61) while measured startup to first `/healthz` 200 is ~15 s:
  the 5 s start period is shorter than startup, so the first post-start-period
  probe may fail once before the server is up (retries=3, so it should still
  reach healthy — to be confirmed in the container re-check, including time
  to first healthy).
