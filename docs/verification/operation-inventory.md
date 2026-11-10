# Operation inventory

Exact operation inventory at head `3ff3650`, enumerated read-only from
source. Method: CLI commands and options were taken from
`src/textforensics/cli.py` (`build_parser`, argparse) and confirmed by
running `textforensics <command> --help` against this tree; HTTP routes
from `src/textforensics/api.py` and `src/textforensics/web_ui/main.py`
(route decorators); MCP tools from `src/textforensics/mcp_server.py`
(`@mcp.tool()` registrations) cross-checked against
`src/textforensics/mcp_tools.py` (implemented helpers); UI actions from
`src/textforensics/web_ui/static/app.js` (event listeners and `fetch` /
`WebSocket` calls). No operation is invented. Anything whose behaviour
could not be established from source is marked **UNVERIFIED** with the
exact file/line — never guessed.

## How to read the tables

- **Remote dispatch**: whether the operation can send submitted text
  to a remote detector adapter. The mechanism is in §6: only
  `build_forensic_bundle` (`report.py`) and `run_all_detectors`
  (`detectors.py`) execute *discovered* entry-point detectors, and
  neither applies an `allow_remote` filter (audit IF-01). Everything
  on the `analyze_text` path (`engine.py`, builtin analyzers only) is
  local-only. The drift observatory is the one path with an explicit
  `allow_remote` opt-in (default off).
- **Emergency-stop gated**: whether an active emergency stop blocks
  the operation. Sources: CLI dispatch gate (`cli.py:1555`,
  all commands except `emergency`); API/web HTTP middleware returning
  503 (`api.py:73-84`, `web_ui/main.py:314-335`); per-handler
  `assert_not_stopped()` calls; `engine.analyze_text`
  (`engine.py:52-58`). The WebSocket handler has no stop check
  (audit IF-03).

## 1. CLI — `textforensics` (`src/textforensics/cli.py`, 2,533 lines)

Top-level flags: `--version`. Input text is taken from `--file`,
`--text`, or stdin as noted per command; `validate_text_input`
enforces `max_input_bytes` (default 2,000,000). **All CLI commands
except `emergency` are emergency-stop gated at dispatch**
(`cli.py:1555`); the table therefore lists the stop column as "Yes"
for every CLI row except the `emergency` family, and notes the
exception once here instead of repeating it.

| Operation | Inputs | Remote dispatch | Notes |
| --- | --- | --- | --- |
| `scan` | `--file/-f`, `--text/-t`, `--json`, `--rich`, `--deterministic` | No — `analyze_text`, builtin analyzers only (`cli.py:1564`) | Local alpha pattern baseline |
| `mixed-origin` | `--file/-f`, `--text/-t`, `--json`, `--out/-o`, `--language`, `--domain`, `--registry`, `--segment-slice`, `--no-adversarial` | No — `analyze_text` + registry files (`cli.py:1335`) | U4 mixed-origin / co-authorship report |
| `audit` | `--file/-f`, `--text/-t`, `--json`, `--base-dir`, `--chain` | No — `audit_naturalness` (`cli.py:1592`) | Naturalness audit, no subcommand |
| `audit export` | `anchor_arg` (output path) | No — writes an audit anchor file, no text analysis (`cli.py:2192-2217`) | Optional `anchor_command` positional; handled manually |
| `audit verify` | `anchor_arg` (anchor file path) | No — verifies an anchor file (`cli.py:2219+`) | Optional `anchor_command` positional |
| `localize` | `--file/-f`, `--sentences` (default 4), `--style {side_by_side,unified,inline}`, `--output/-o`, `--threshold` (default 2.0), `--rich` | No — `localize_text` (`cli.py:1653`) | Segment scoring / diff; not sentence-level authorship |
| `compare` | `before`, `after` (positional), `--json` | No — `compare_texts` (`cli.py:1663`) | Before/after text comparison |
| `snapshot` | `file` (positional), `--ledger` (default `.textforensics-ledger.jsonl`) | No — ledger append | Tamper-evident draft snapshot |
| `verify-ledger` | `ledger` (positional, optional) | No — ledger verification | Hash-chain verification |
| `calibrate` | `dataset` (positional), `--target-fpr` (default 0.01), `--output/-o` | No — fits a threshold artifact on calibration JSONL | Calibration-only data |
| `benchmark` | `dataset` (positional), `--threshold` \| `--calibration`, `--allow-same-dataset` | No — evaluates the built-in baseline on labeled JSONL | `--allow-same-dataset` is diagnostic only |
| `fingerprint` | `dataset` (positional), `--name` (required), `--version` (default 1.0.0), `--split` (default test), `--output/-o`, `--strict` / `--no-strict` | No — dataset fingerprint for contamination tracking | |
| `check` | `calibration`, `evaluation` (positional), `--output/-o` | No — contamination check between two datasets | |
| `select-threshold` | `dataset` (positional), `--target-fpr` (default 0.01), `--detector-id`, `--detector-version`, `--output/-o` | No — threshold selection on calibration JSONL | |
| `detectors` | `--health`, `--rich` | No — lists installed adapters / plugin health only | No text is submitted |
| `schema validate` | `file` (positional), `--type {forensic-bundle,detector-result,case-file,trust-map,enterprise-policy}` | No — local schema validation | |
| `schema list` | — | No | Lists available schemas |
| `schema show` | `name` (positional) | No | Shows one schema definition |
| `report` | `--file/-f`, `--text/-t`, `--ledger`, `--output/-o`, `--deterministic`, `--fixed-timestamp`, `--rich` | **YES** — `build_forensic_bundle` runs all discovered detectors with no `allow_remote` filter (`cli.py:1796`; `report.py:329-342`) | IF-01 applies |
| `case export` | `--file/-f`, `--text/-t`, `--ledger`, `--output/-o` (required), `--deterministic`, `--fixed-timestamp`, `--determinism <detector_id>:<value>` (repeatable), `--rich`, `--seal`, `--signing-key`, `--timestamp-url` | **YES** — `build_forensic_bundle` (`cli.py:1831`) | Sealed case file; raw text excluded by default |
| `case verify` | `case_file` (positional), `--expect-digest`, `--text/-t`, `--text-file`, `--public-key`, `--timestamp-token` | No — replay passes no detectors (`replay_case_file_path(path, text=…)`; `casefile.py:2054-2057`: "no detector re-execution was attempted" when no detectors are supplied) | Exit codes 0/1/2 per the MPL contract |
| `case keygen` | `--output/-o` (required), `--identity` (default: current username), `--role` (default: sealer), `--public-out` | No — generates an Ed25519 sealing key, mode 0600, refuses to overwrite | |
| `bundle pack` | `case_file`, `output` (positional) | No — archive packing (.tar.gz / .zip) | |
| `bundle verify` | `bundle` (positional), `--expect-digest` | No — bundle integrity verification | |
| `bundle list` | `bundle` (positional) | No — lists bundle contents | |
| `bundle check` | `bundle` (positional), `--json/-j` | No — internal-consistency check of a bundle / case file | |
| `verify` | `case_file` (positional, optional), `--calibration`, `--benchmark`, `--all` | No — re-derives Trust Map / calibration / benchmark metrics from supplied artifact files; `verify.py` contains no detector execution | N-version integrity replay |
| `web` | `--host`, `--port`, `--no-browser`, `--allow-remote` | n/a — serves the Web UI surface (§3); served operations dispatch per §3 | Bind guard runs before the web-UI import (`cli.py:1891-1900`) |
| `web-fastapi` | `--host`, `--port`, `--allow-remote`, `--access-log` | n/a — serves the Web UI surface (§3) | Same bind guard |
| `serve` | `--host`, `--port`, `--allow-remote`, `--access-log` | n/a — serves the API surface (§2) | Same bind guard; API-only, no UI |
| `drift snapshot` | `--corpus`, `--label`, `--allow-remote`, `--output/-o`, `--snapshot-id` | **Gated** — `take_snapshot(allow_remote=…)` skips remote detectors unless `--allow-remote` is given (`observatory.py:973-981`); default off | |
| `drift compare` | `baseline`, `current` (positional), `--corpus`, `--output/-o` | No — compares two snapshot files | |
| `drift report` | `baseline`, `current` (positional), `--corpus`, `--output/-o`, `--rich` | No — generates a drift report from two snapshot files | |
| `drift run` | `--manifest`, `--texts`, `--holdback` (all required), `--scope {full,monthly-attacked,monthly-current-generator,event-driven}`, `--detector-id`, `--detector-version`, `--runs-dir`, `--registry`, `--output`, `--allow-remote`, `--dry-run`, `--fail-on-tier1` | **Gated** — probe-run scoring passes `--allow-remote` through; default off | U3 probe run over the frozen probe corpus |
| `drift status` | `--detector-id` (required), `--detector-version`, `--runs-dir`, `--registry` | No — reads run history | |
| `capability list` | `--detector`, `--ledger` | No — ledger read | |
| `capability check` | `detector`, `capability` (positional), `--ledger` | No — ledger read | |
| `capability export` | `--output/-o`, `--ledger` | No — ledger export as JSON | |
| `capability register` | `detector`, `capability`, `{validated,tool_backed,readable}`, `artifact` (positional), `--ledger`, `--label {reported,calculated,proposed,executed}`, `--detail`, `--valid-until` | No — ledger write | |
| `capability policy` | `detector` (positional), `--ledger`, `--policy/-p {production,report,calibration,minimum}`, `--json/-j` | No — policy evaluation over ledger | |
| `build-info` | `--verify`, `--expected-commit` | No — displays/verifies embedded build identity | |
| `policy load` | `file` (positional), `--state-path`, `--key-path`, `--no-advance` | No — loads/validates an enterprise policy file | |
| `policy check` | `file` (positional, optional), `--state-path`, `--key-path` | No — checks current policy against the revision floor | |
| `policy advance` | `file` (positional), `--state-path`, `--key-path` | No — advances the revision floor | |
| `policy export` | `--state-path`, `--key-path`, `--policy-file` | No — exports current policy state | |
| `emergency status` | `--path` (sentinel override, default `$TEXTFORENSICS_EMERGENCY_STOP`) | No — reads sentinel state | **Not stop-gated** (must stay usable while the stop is active) |
| `emergency activate` | `--path` | No — creates the sentinel file | **Not stop-gated** |
| `emergency deactivate` | `--path` | No — removes the sentinel file | **Not stop-gated** |

Notes:

- There is no `typer_cli.py` in this tree; the CLI is argparse
  (`cli.py:442-1180`). The "typer" dependency was removed in the
  SBOM-pinning wave and no `import typer` exists anywhere.
- Entry points (`pyproject.toml`): `textforensics`,
  `textforensics-api`, `textforensics-mcp`, `textforensics-web`
  (all four map to the modules inventoried here).
- The `textforensics.detectors` entry-point group is empty in
  `pyproject.toml`; the only detector shipped in-tree is the builtin
  heuristic (`textforensics/builtin-heuristic`,
  `detectors.py:482-483`). Remote dispatch therefore requires a
  third-party plugin installed into that entry-point group — but once
  one is installed, the paths marked YES above execute it with no
  per-request opt-in (IF-01). That is the finding, not a claim that a
  remote adapter ships with the package.

## 2. HTTP API surface — `textforensics.api` (`src/textforensics/api.py`, 210 lines)

Entry point `textforensics serve` / `textforensics-api`. Requires the
`[api]` extra; `create_app()` raises an install hint without it.
`Settings` defaults: host `127.0.0.1`, port `8765`,
`max_input_bytes` 2,000,000, `allow_remote` False (`config.py:75-79`).
The HTTP middleware gates **every** HTTP request on the emergency
stop (503 while active) and enforces `Content-Length` presence and a
body cap of `max_input_bytes * 2 + 65,536` on POST/PUT/PATCH
(`api.py:73-125`).

| Operation | Inputs | Remote dispatch | Stop gated |
| --- | --- | --- | --- |
| `GET /healthz` | — | No | Yes (middleware; returns 503 while stopped) |
| `GET /readyz` | — | No | Yes (middleware) |
| `GET /version` | — | No | Yes (middleware) |
| `GET /v1/detectors` | — | No — lists detector metadata + plugin health | Yes (middleware) |
| `POST /v1/analyze` | `{text}` | No — `analyze_text`, builtin analyzers only | Yes (middleware + `assert_not_stopped`) |
| `POST /v1/report` | `{text}` | **YES** — `build_forensic_bundle`, all discovered detectors, no opt-in | Yes (middleware + `assert_not_stopped`) |
| `POST /v1/case` | `{text}` | **YES** — `build_forensic_bundle` + `seal_case_file` | Yes (middleware + `assert_not_stopped`) |
| `POST /v1/audit` | `{text}` | No — `audit_naturalness` | Yes (middleware + `assert_not_stopped`) |
| `POST /v1/compare` | `{before, after}` | No — `compare_texts` | Yes (middleware + `assert_not_stopped`) |

## 3. Web UI surface — `textforensics.web_ui.main` (`src/textforensics/web_ui/main.py`, 1,016 lines)

Entry points `textforensics web` / `textforensics web-fastapi` /
`textforensics-web`. Requires the `[api]` extra. Same `Settings`
defaults as §2. The HTTP middleware gates **every** HTTP request on
the emergency stop (503 while active) with the same body rules as §2
(`main.py:314-367`). Static files are mounted at `/static`
(`main.py:204-205`); templates at `templates/` (`main.py:208-209`).
Security headers include `Content-Security-Policy: default-src 'self';
… connect-src 'self'` and `frame-ancestors 'none'`
(`main.py:292-313`).

| Operation | Inputs | Remote dispatch | Stop gated |
| --- | --- | --- | --- |
| `GET /`, `GET /index.html` | — | No — serves the HTML template | Yes (middleware) |
| `GET /healthz`, `GET /readyz` | — | No | Yes (middleware) |
| `GET /version` | — | No | Yes (middleware) |
| `GET /v1/detectors` | — | No — lists detector metadata + plugin health | Yes (middleware) |
| `POST /api/session` | — | No — creates a collaboration session id | Yes (middleware) |
| `GET /api/session/{session_id}` | path `session_id` | No — session info | Yes (middleware) |
| `GET /api/session/{session_id}/users` | path `session_id` | No — lists session users | Yes (middleware) |
| `DELETE /api/session` | — | No — cleans up empty/expired sessions | Yes (middleware) |
| `POST /api/analyze` | `{text}` | **YES** — `build_forensic_bundle`, all discovered detectors, no opt-in; result stored in the server-side history ring buffer | Yes (middleware + `assert_not_stopped`, `main.py:434`) |
| `POST /api/report` | `{text}` (raw JSON) | **YES** — `build_forensic_bundle`; result is **not** stored in history (compatibility alias for the former stdlib UI) | Yes (middleware + `assert_not_stopped`, `main.py:457`) |
| `POST /api/export` | `{data, format}` where `format ∈ {json, csv, html}` | No — formats caller-supplied data only, no analysis | Yes (middleware; **no** per-handler stop check — the middleware is the only gate) |
| `POST /api/compare` | `{a, b}` (two analysis results) | No — `_build_comparison` over supplied data, no analysis | Yes (middleware; **no** per-handler stop check) |
| `GET /api/history` | `limit`, `offset`, `verdict`, `family`, `min_score`, `max_score` | No — metadata-only history query (paginated, ring buffer, default max 100 entries via `TEXTFORENSICS_HISTORY_MAX`) | Yes (middleware; **no** per-handler stop check) |
| `DELETE /api/history` | — | No — clears the history buffer | Yes (middleware; **no** per-handler stop check) |
| `GET /api/history/{analysis_id}` | path `analysis_id` | No — returns one stored analysis result | Yes (middleware; **no** per-handler stop check) |
| `WS /ws/analyze` | frames: `join_session`, `leave_session`, `analysis_shared`, `analyze` (`{text}`) | **YES** — `analyze` runs `run_all_detectors` (all discovered detectors, no opt-in) then `build_forensic_bundle`; `analysis_shared` stores caller-supplied data and broadcasts it to session peers | **NO** — the handler never checks the emergency stop and HTTP middleware does not apply to WebSocket (audit IF-03). `join_session` / `leave_session` / `analysis_shared` also run while stopped. |

## 4. MCP surface — `textforensics.mcp_server` (`src/textforensics/mcp_server.py`, 165 lines)

Entry point `textforensics-mcp`. Requires the `[mcp]` extra; stdio
transport (no network listener). Tool wrappers validate text with
`validate_text_input` (`max_input_bytes`) and serialize with
`json.dumps(…, allow_nan=False)`.

### 4.1 Registered tools (16)

| Operation | Inputs | Remote dispatch | Stop gated |
| --- | --- | --- | --- |
| `analyze_ai_text` | `text` | No — `analyze_text`, builtin analyzers only | Yes (`assert_not_stopped`) |
| `build_forensic_report` | `text` | **YES** — `build_forensic_bundle`, all discovered detectors, no opt-in | Yes (`assert_not_stopped`) |
| `build_case_file` | `text` | **YES** — `build_forensic_bundle` + `seal_case_file` | Yes (`assert_not_stopped`) |
| `detector_health` | — | No — lists detector metadata + plugin health | **No, by design** (comment in source: "Read-only introspection: not gated by emergency stop") |
| `localize_text_patterns` | `text`, `sentences_per_segment` (default 4) | No — `localize_text` | Yes (`assert_not_stopped`) |
| `compare_text_versions` | `before`, `after` | No — `compare_texts` | Yes (`assert_not_stopped`) |
| `audit_writing_naturalness` | `text` | No — `audit_naturalness` | Yes (`assert_not_stopped`) |
| `capability_register` | `params` (JSON string) | No — `mcp_tools.capability_register`, ledger write | **No** — no stop check in the wrapper; the operation takes no text and executes no detectors |
| `capability_check` | `params` (JSON string) | No — ledger read | **No** — same as above |
| `capability_list` | `params` (JSON string) | No — ledger read | **No** — same as above |
| `verify_case_file` | `params` (JSON string) | No — `mcp_tools.verify_case_file` runs `verify_case_file_combined` over the supplied case-file object; no text input, no detector execution | **No** — no stop check in the wrapper |
| `drift_snapshot` | `params` (JSON string) | No — `mcp_tools.drift_snapshot` builds a snapshot from caller-supplied corpus + observations; executes no detectors | **No** — no stop check in the wrapper |
| `drift_compare` | `params` (JSON string) | No — snapshot-file comparison | **No** — same as above |
| `drift_report` | `params` (JSON string) | No — report from two snapshots | **No** — same as above |
| `fingerprint_dataset` | `params` (JSON string) | No — dataset fingerprint | **No** — same as above |
| `check_contamination` | `params` (JSON string) | No — contamination check | **No** — same as above |

### 4.2 Implemented but NOT registered (audit IF-16 — recorded, not fixed)

`src/textforensics/mcp_tools.py` (648 lines) implements three helpers
that have no `@mcp.tool()` registration in `mcp_server.py`, so no MCP
client can discover or call them. This matches the audit evidence
(`/interfaces_extra/unregistered_mcp_implementations`):

| Helper | Location | What it does |
| --- | --- | --- |
| `result_encode` | `mcp_tools.py:465` | Encodes a detector result |
| `result_decode` | `mcp_tools.py:509` | Decodes a detector result |
| `capability_policy_evaluate` | `mcp_tools.py:562` | Evaluates capability-ledger policies for a detector |

Fixing the registration gap belongs to W5; W0 records the fact.

## 5. UI actions — `src/textforensics/web_ui/static/app.js` (984 lines)

Actions the shipped page performs. The page talks only to the same
origin (`connect-src 'self'`).

| UI action | Trigger | Server operation | Notes |
| --- | --- | --- | --- |
| Analyze (streaming) | Analyze button, stream toggle on | `WS /ws/analyze` (`analyze` frame) | Streams per-detector results, then the final bundle; result stored server-side and broadcast to session peers |
| Analyze (REST) | Analyze button, stream toggle off | `POST /api/analyze` | Full bundle in one response |
| Load version | Page load | `GET /version` | Display only |
| Clear | Clear button | — (local only) | Clears the text input and results panel |
| Word / character count | Text input event | — (local only) | Live counts, no server call |
| Export JSON / CSV / HTML | Export buttons | **None — client-side only** | `exportAnalysis(format)` builds a `Blob` of `JSON.stringify({data, format})` and downloads it with the requested extension. It never calls `POST /api/export`, and the downloaded content is always JSON regardless of the requested format (audit IF-14). |
| Compare | Compare button | **None — client-side only** | `toggleCompareMode` renders a comparison from the current analysis and a history item selected by `prompt()`; it never calls `POST /api/compare` |
| Load history | Load-history button | `GET /api/history?…` | Paginated history list |
| Load history item | History item click | `GET /api/history/{historyId}` | Single stored analysis |
| Join / leave session, share analysis | WebSocket messages | `WS /ws/analyze` (`join_session`, `leave_session`, `analysis_shared` frames) | Collaboration lifecycle; no stop gate (§3) |
| Close WebSocket | `beforeunload` | — (local only) | Closes the socket on page unload |

Server routes the shipped UI **never** calls (surface-parity note
for W5, not a W0 fix): `POST /api/report`, `POST /api/export`,
`POST /api/compare`, `POST /api/session`,
`GET /api/session/{session_id}`,
`GET /api/session/{session_id}/users`, `DELETE /api/session`,
`DELETE /api/history`.

## 6. Remote-dispatch mechanism (shared)

- Detectors are discovered by `discover_detector_registry()`
  (`detectors.py:570-616`): the builtin heuristic plus every
  installed `textforensics.detectors` entry-point plugin. A plugin
  declares `runtime.mode` / `prediction.execution` of `local` or
  `remote` (`detectors.py:356-357, 391-392`); an Ollama-backed
  detector mixin exists (`ollama.py:618`) and Ollama URLs are
  loopback-restricted unless explicitly opted in (`ollama.py:88-100`).
- `build_forensic_bundle` (`report.py:329-342`) and
  `run_all_detectors` (`detectors.py:669-700`) execute **every**
  discovered detector with no `allow_remote` filter and no
  per-request opt-in. Any operation marked YES above therefore sends
  submitted text to a remote adapter the moment one is installed
  (audit IF-01). The only in-tree detector is the local builtin
  heuristic, so no remote call happens in a default install — the
  risk is the absence of the gate, not a shipped remote adapter.
- The drift observatory is the exception: `take_snapshot`
  (`observatory.py:935-981`) skips detectors for which
  `_is_remote_detector` is true unless `allow_remote=True`
  (CLI `--allow-remote`, default off).
- `engine.analyze_text` never touches the detector registry: it runs
  `run_builtin_analyzers` on local features only (`engine.py:30-41`).

## 7. Emergency-stop mechanism (shared)

- The sentinel is a file whose path defaults to
  `$TEXTFORENSICS_EMERGENCY_STOP` (`emergency_stop.py`). `check_emergency_stop()`
  / `assert_not_stopped()` read it; `textforensics emergency
  activate|deactivate|status` manages it.
- CLI: dispatch gate in `_run` (`cli.py:1555-1562`) blocks every
  command except `emergency` while the stop is active; analysis
  entry points additionally assert (`engine.py:52-58`).
- API + web HTTP: middleware returns 503 for every request while
  the stop is active (`api.py:73-84`, `web_ui/main.py:314-335`).
  Text endpoints additionally assert per-handler.
- WebSocket: **not gated** (IF-03). MCP text tools: gated, except
  `detector_health` (read-only introspection, deliberately ungated)
  and the non-text ledger/drift/fingerprint tools, which carry no
  stop check (they execute no detectors and take no text).
- Observatory execution between detector calls does not re-check the
  stop (audit S08) — recorded here; the fix belongs to W1/W4.

## 8. UNVERIFIED items

None remain in this inventory: every operation above was traced to
its dispatch function and its remote/stop behaviour from source. Two
judgement calls are recorded explicitly rather than hidden:

1. MCP non-text tools (`capability_*`, `verify_case_file`,
   `drift_*`, `fingerprint_dataset`, `check_contamination`) carry no
   stop check. That is a fact of the source, not a verdict that they
   *should* be gated — whether the stop should cover state-changing
   ledger/drift writes is a W1 policy decision, flagged here as an
   open question, not decided.
2. `POST /api/export` and `POST /api/compare` have no per-handler
   stop check; they are gated only by the HTTP middleware. If the
   middleware is ever bypassed or removed, they would run while
   stopped. Whether to add per-handler asserts is a W1 decision.
