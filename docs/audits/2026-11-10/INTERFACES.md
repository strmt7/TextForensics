# Interfaces and integrations audit

## Scope, snapshot, and evidence limits

- Audited immutable snapshot `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` . Audit
  and plan only; no implementation or repository writes.
- Reviewed all 21 owned source/assets: the 16 named top-level Python modules,
  `web_ui/main.py` , `web_ui/static/app.js` , `web_ui/static/style.css` ,
  `web_ui/static/chart.umd.min.js` , and `web_ui/templates/index.html` .
- First-party Python, JavaScript, HTML, and CSS received full source review. The
  minified vendored Chart.js asset received a complete-byte sink/URL scan and
  JavaScript syntax check, not a claim of exhaustive third-party
  semantic/security review. No network primitives or dynamic-code evaluation
  were found by that scan; see `interfaces-vendor-review.json` for exact search
  terms and counts.
- Matching-test review: **29 files, 621 test functions identified, 505
  test-function bodies reviewed**. Nineteen files were reviewed in full; the
  remainder were parsed in full and reviewed by risk-focused function slices.
  Three additional fuzz targets were read in full but not executed.
  `inventory.json` records every path, line range, reviewed function name,
  source hash, and totals. These are source-review counts, not line/branch
  coverage percentages.
- Executed **333 targeted tests in 15 files: 333 passed, zero
  failed/errors/skipped**. Exact selection and JUnit evidence are in
  `interfaces-targeted-tests-summary.json` , `interfaces-targeted-tests.xml` ,
  and `interfaces-targeted-tests.txt` .
- All probes used the provisioned Python 3.12 interpreter, disposable state,
  small inputs, and bounded loopback HTTP fakes. The JavaScript harness used
  Node and a minimal DOM/canvas recorder, not a browser. No headed/headless
  browser, GPU/model workload, external provider, real account/key, full test
  suite, or build ran in this audit. Parent owns full-suite/build evidence.
  Atheris was unavailable on this Windows environment, so no Atheris execution
  is claimed.
- Findings below are reproducible at this snapshot. Severity is contextual to
  the documented local-first alpha, not an assertion of supported remote
  multi-tenant deployment. Installed plugins are trusted Python code; no finding
  assumes the current alpha promises a sandbox.

## Reproducing interface findings

`evidence.json` preserves Python, extra-boundary and Node observations under
`interfaces` , `interfaces_extra` and `interfaces_js` . Use the actual
application factories and JavaScript against server-produced bundles, disposable
ASGI state, and small protocol-faithful loopback fakes. Reproduction setup and
expected behavior appear in each finding. The audit scripts, generated sample
text and raw logs are not shipped.

## Findings index

- **IF-01**
  Severity: High
  Outcome: Report surfaces invoke discovered remote adapters without per-request
  opt-in

- **IF-02**
  Severity: High
  Outcome: Ollama loopback-only policy is bypassed by an HTTP redirect carrying
  the prompt

- **IF-03**
  Severity: High
  Outcome: WebSocket analysis bypasses emergency stop

- **IF-04**
  Severity: High
  Outcome: UI invents 85%, 15%, and 50% AI probabilities when none exist

- **IF-05**
  Severity: Medium
  Outcome: Untrusted-origin WebSockets accept forged, oversized history; history
  HTML is unescaped

- **IF-06**
  Severity: Medium
  Outcome: Shipped UI cannot consume its own actual analysis bundle

- **IF-07**
  Severity: Medium
  Outcome: HTTP/provider errors disclose submitted text and exception contents

- **IF-08**
  Severity: Medium
  Outcome: Adapter scanner executes imports and labels
  uninspectable/network-capable source verified local

- **IF-09**
  Severity: Medium
  Outcome: Ollama response-size protection checks only after buffering the full
  response

- **IF-10**
  Severity: Medium
  Outcome: Collaboration disconnect/leave does not release users or connections

- **IF-11**
  Severity: Medium
  Outcome: Saved explanation reports contain original sentences without raw-text
  opt-in

- **IF-12**
  Severity: Medium
  Outcome: Unsupported one-word inputs receive maximal confidence rather than
  abstention

- **IF-13**
  Severity: Medium
  Outcome: Ollama embeddings use the wrong wire endpoint and omit explicit
  `truncate=False`

- **IF-14**
  Severity: Medium
  Outcome: UI CSV/HTML export downloads JSON under the requested extension

- **IF-15**
  Severity: Medium
  Outcome: Ollama streaming fails on a fresh client and uses a separate,
  inconsistent request path

- **IF-16**
  Severity: Medium
  Outcome: Three implemented MCP helpers are absent from the actual tool
  registry

- **IF-17**
  Severity: Medium
  Outcome: Diagnostics publish placeholder health and ignore declared
  configuration

- **IF-18**
  Severity: Low
  Outcome: Literal Rich markup in user text crashes diff output

- **IF-19**
  Severity: Low
  Outcome: Explanation report overstates successfully scored segments

## IF-01 — Discovered remote adapters run without request opt-in

**Locations:** `src/textforensics/api.py:31-32,150-159` ;
`src/textforensics/mcp_server.py:49-60` ;
`src/textforensics/web_ui/main.py:431-443,684-704` ;
`src/textforensics/cli.py:1795-1800,1831-1836` . Supporting dispatch is in
`src/textforensics/report.py` and `src/textforensics/detectors.py` (coordinate
the core auditor's remediation).

**Expected vs observed:** AGENTS.md:34 requires explicit selection of an opt-in
remote adapter. A normal `POST /v1/report` contains only `text` , yet an
installed/discovered adapter advertising `execution="remote"` receives the
input. Probe `api_remote_without_opt_in` returns status 200, **four adapter
calls**, and a remote detector observation. The recording adapter performs no
network I/O; this demonstrates dispatch/consent failure, not an actual external
transmission. The other listed interfaces call the same unrestricted bundle
builder and expose no corresponding adapter-selection/consent parameter.

**Impact / preconditions:** A remote-capable plugin is installed. Merely running
a normal report/case operation can pass sensitive text to it, including
robustness variants, without selection in that operation. Installing trusted
code is not equivalent to selecting remote use for every document.

**Fix plan:** Centralize execution policy in the report/registry boundary:
default to local-only, require explicit remote detector IDs and consent,
propagate the same policy through CLI/API/MCP/UI, and record the selected policy
in provenance. Do not confuse inbound `allow_remote` binding permission with
outbound adapter consent.

**Regression acceptance:** With a discovered recording remote plugin, default
report/case requests on all surfaces make zero remote calls. An explicit
allowed-ID request invokes only that plugin; missing/unknown consent is
rejected. Benign-variant evaluation cannot widen the authorized detector set.

## IF-02 — Redirect escapes Ollama's loopback-only boundary

**Locations:** `src/textforensics/ollama.py:87-104,436-441,551-554,585-589` .

**Expected vs observed:** `allow_remote_host=False` rejects non-loopback initial
URLs. The actual aiohttp request uses automatic redirects without revalidating
the destination. Probe `ollama_redirect` starts from `127.0.0.1` , receives a
307 to `receiver.example` , and the receiver records the original
`SENSITIVE-DISPOSABLE-PROMPT` while `allow_remote_host` remains false. The
example hostname is deliberately resolved to a second loopback fake, so no real
egress occurs.

**Impact / preconditions:** The configured local endpoint, proxy, or an endpoint
impersonating it emits a redirect. A POST-preserving redirect can forward
private prompts outside the host allow policy. This is a proven request-policy
bypass; it is not a claim that an honest default Ollama installation normally
redirects.

**Fix plan:** Disable redirects by default for inference/model operations, or
implement a small bounded redirect loop validating every destination against the
same policy before any request body is forwarded. Apply it to streaming as well
as ordinary requests. Redact URLs and response bodies in public errors.

**Regression acceptance:** Test 301/302/303/307/308, same-host and cross-host
chains, redirect loops, relative locations, and streaming. Disallowed receivers
must receive zero bytes/requests. Explicitly opted-in destinations remain
bounded and auditable.

## IF-03 — Emergency stop does not protect WebSocket analysis

**Locations:** `src/textforensics/web_ui/main.py:314-325,574-587,661-704` ;
compare `src/textforensics/api.py:73-82,150-153` and
`src/textforensics/mcp_server.py:49-53` .

**Expected vs observed:** With the disposable stop sentinel present, HTTP
`/healthz` returns 503. The same application's `/ws/analyze` accepts and
completes a new analysis, sending `started` , `detector_result` , and `complete`
. Probe `stopped_websocket` records **five calls** to the recording remote
adapter. The HTTP-only middleware is never the WebSocket gate; the WebSocket
handler has no equivalent stop check before acceptance or detector dispatch.

**Impact / preconditions:** A web server is running and stop is activated. An
automation/client channel can continue executing detector work and passing text
to plugins despite the stated stop condition. Core baseline failure/abstention
does not protect plugin dispatch.

**Fix plan:** Share stop/policy validation across HTTP, WebSocket, CLI, and MCP
dispatch. Check at WebSocket handshake, each new analysis/share operation, and
meaningful execution boundaries. Define in-flight cancellation behavior
explicitly; merely cancelling an asyncio Future does not terminate a detector
already running in an executor thread.

**Regression acceptance:** Activate stop before connecting and after connecting
but before sending `analyze` ; both must refuse work with zero detector calls.
Toggle stop between bounded detector steps and verify no subsequent plugin step
starts. Assert history/share mutations are also refused while stopped.

## IF-04 — UI fabricates authorship probabilities

**Locations:**
`src/textforensics/web_ui/static/app.js:263-266,312-322,364-372,389-405` ;
`AGENTS.md:29-31,90` .

**Expected vs observed:** A missing calibrated ensemble probability must remain
missing/abstained. The gauge substitutes 85 for `ai_like` , 15 for `human_like`
, and 50 for every other verdict, then draws `%` and **AI Probability**. The
family chart also substitutes 50 for missing calibration. The real bundle
exposes `consensus.calibrated_ai_probability` ; the UI looks for
`consensus.ai_probability` instead. Node probe `gauge_ai_like` ,
`gauge_human_like` , and `gauge_abstain` records the exact substituted
datasets/text with no probability supplied.

**Impact / preconditions:** Any ordinary uncalibrated report; the baseline
report in the fixture abstains. A polished output communicates invented
quantitative certainty and reverses the project's core score/probability and
abstention rules. This is not a disputed statistical interpretation: the
percentages are literal constants.

**Fix plan:** Consume the canonical consensus schema, require the
ensemble-calibration provenance needed for that field, and show
unavailable/abstained rather than a numerical fallback. Render raw native scores
only with native semantics/direction and units. Missing family calibration is
N/A, not 50%.

**Regression acceptance:** Feed uncalibrated `ai_like` , `human_like` ,
`abstain` , failed, and missing-family cases through the actual UI code. None
may display a numerical authorship probability. A valid canonical calibrated
field displays its exact value and calibration identity. Add a guard forbidding
unsupported probability fallbacks.

## IF-05 — WebSocket trust boundary permits forged history and HTML injection

**Locations:** `src/textforensics/web_ui/main.py:574-587,643-656` (acceptance
and unvalidated sharing); `src/textforensics/web_ui/static/app.js:940-955`
(history sink). API host acceptance is also observable at
`src/textforensics/api.py:46-51,73-124` .

**Expected vs observed:** An unrelated browser origin must not be able to drive
a sensitive local service; shared results need a schema, bounded size, and
provenance. Probe `cross_origin_websocket` supplies
`Origin: https://attacker.example` and receives a complete analysis without
credentials. With a known disposable collaboration ID,
`websocket_forged_history` submits a caller-created verdict containing
`<strong id="injected">FORGED</strong>` plus 65,536 padding bytes while
`max_input_bytes=1024` . The exact data is read back from server history. Node
probe `unescaped_history` confirms this verdict is inserted verbatim into
`innerHTML` by the shipped history renderer. `api_untrusted_host` also returns
200 for an unrelated Host value.

**Impact / preconditions:** Local web service running; untrusted-origin analysis
requires no room ID, while forged sharing requires a known/obtainable room ID.
This demonstrates unauthorized work, report/history forgery, a bypass of the
configured input-size boundary for sharing, and stored HTML injection.
**Arbitrary script execution is not claimed:** current `script-src 'self'`
restricts inline script/event handlers, and no browser exploit was run. No
remote multi-tenant security claim is assumed.

**Fix plan:** Validate configured Host and exact Origin at the boundary; bind
state-changing operations to an unpredictable same-origin token or authenticated
session as deployment requires. Reject oversized frames before JSON parsing,
validate message/bundle schemas and verdict enums, and share server-side
analysis IDs instead of trusting arbitrary result objects. Escape text/attribute
output even after validation. Apply separate byte/count quotas to retained
history.

**Regression acceptance:** Rejected origins cannot start analyses or mutate
history. An authenticated/same-origin valid flow still works. Reject
oversized/shared malformed bundles before retention. Read back a synthetic
markup verdict and assert it is rejected or rendered as inert text. Tests must
explicitly account for CSP rather than assert unproven script execution.

## IF-06 — Shipped UI and server schemas/DOM are incompatible

**Locations:**
`src/textforensics/web_ui/static/app.js:42,149-151,223-225,229-245,390-392,578-599`
; `src/textforensics/web_ui/templates/index.html` (no `warningsList` element).

**Expected vs observed:** An actual server bundle must pass through streaming
and complete-result handlers without exception, with limitations visible. The
fixture comes from the real WebSocket endpoint. `complete_analysis_real_bundle`
throws `TypeError: Cannot read properties of undefined (reading 'replace')` :
family votes use `family` , but the chart expects `detector_family` .
Independently, `streaming_first_detector` throws
`ReferenceError: updateDetectorChart is not defined` ; `warnings_real_bundle`
throws because `warningsList` is null. The code also constructs `ws://` even
under an HTTPS page; the Node harness records `ws://audit.localhost/ws/analyze`
for `window.location.protocol='https:'` .

**Impact / preconditions:** Normal UI analysis; no malicious input required.
Results/warnings/history are interrupted. HTTPS deployment additionally selects
an insecure WebSocket URL. The current Python UI tests test routes/assets and
source text, not execution of the actual frontend against a real bundle.

**Fix plan:** Use a single versioned bundle contract for all consumers, correct
the streaming function wiring and template IDs, and choose `wss:` under HTTPS.
Test the actual JS with server-produced fixtures; do not add fake schema aliases
solely to satisfy old tests. Avoid invoking a second detector run to build a
result already streamed (`main.py:686-703`); one operation should own
observations and final bundle.

**Regression acceptance:** Execute a real baseline bundle through complete and
streaming paths and assert no JS errors, visible abstention/limitations, correct
family labels, and populated raw data/history. Check every declared DOM ID
resolves. Exercise HTTP/HTTPS URL construction and exactly-once base-observation
reuse.

## IF-07 — Error paths echo sensitive material

**Locations:** `src/textforensics/api.py:31-36,46-51` (default
request-validation handler); `src/textforensics/web_ui/main.py:431-443,724-727`
; `src/textforensics/ollama.py:443-448` .

**Expected vs observed:** Sensitive text/provider exceptions must be redacted,
and rejected requests must retain appropriate status codes.
`api_validation_echo` sends a list containing `SENSITIVE-PROBE-INPUT` where a
string is expected and receives that input in a 422 body. `web_error_echo`
injects an exception marker through the actual endpoint and gets the marker
verbatim in a status-200 error response. `web_invalid_input` exceeds the
configured text cap and receives HTTP 200 with error `413: Invalid text input.`
rather than 413. A real loopback provider fake echoes a prompt on a 400;
`ollama_error_echo` confirms the marker appears in `OllamaError` .

**Impact / preconditions:** Malformed sensitive submissions or a provider/plugin
exception containing text. This is exposure to response collectors/logging
layers and misleading transport status, not evidence of one remote tenant
reading another tenant's text. Raw exception propagation can additionally
disclose internal paths/details.

**Fix plan:** Register redacting request-validation/exception handlers shared by
both HTTP applications, preserve `HTTPException` status/structured codes, and
return stable public errors without rejected `input` or raw provider bodies.
Keep private diagnostics text-free and correlate with a request ID. Apply the
same rule to WebSocket errors and CLI/MCP provider failures.

**Regression acceptance:** Unique text markers in malformed values, plugin
exceptions, provider error JSON, and nested validation failures never appear in
public error responses/logs. Oversize text is 413, invalid type is 422,
unexpected error is 500 (or a documented non-200 error contract), with no
traceback/path disclosure.

## IF-08 — Scanner executes plugins and overclaims local verification

**Locations:**
`src/textforensics/adapter_scanner.py:225-245,486-511,527-530,546-556` .

**Expected vs observed:** A source scanner must not execute the code it is
inspecting; inability to inspect is not proof of no network.
`scanner_import_before_scan` supplies a disposable entry point whose module
import writes a marker; the marker is written before the scanner reports the
file-write finding. `scanner_syntax_error` reports critical DYN-999 but
`local_only_verified=true` . `scanner_submodule_network` scans
`import httpx._client as h` and `h.Client().post(...)` , returns no findings,
and sets `local_only_verified=true` . Network code is scanned as text only,
never executed.

**Impact / preconditions:** An operator scans an installed plugin/source.
Import-time code executes as a side effect of the purported inspection, and a
boolean verification result can mislead local-first admission/provenance.
Trusted-plugin status means this is **not** an assertion of sandbox escape; it
is a failure of scan-before-execute and the verification claim.

**Fix plan:** Resolve distribution source paths without importing the
entry-point module, report unavailable/native/dynamic/transitive code as
unknown, fail closed on parse errors, normalize import roots and resolve
aliases. Keep heuristic findings distinct from execution-policy enforcement.
Never claim a regex/AST absence check proves whole-package network isolation.

**Regression acceptance:** Scan an import-side-effect fixture and assert no
marker exists. Syntax errors and unresolved source cannot return verified local.
Pin dotted imports/aliases, dynamic imports, delegated helpers, and native
dependencies as detected or explicitly unknown. Existing security findings
remain visible; do not suppress them to regain green.

## IF-09 — Response byte cap is enforced after complete buffering

**Locations:** `src/textforensics/ollama.py:443-455` .

**Expected vs observed:** Stop reading as soon as the configured response budget
is exceeded. A delayed chunked loopback fake sends 65,536 bytes with
`max_response_bytes=1024` . Probe `ollama_response_cap` records
`body_completed_before_error=true` : the client reads all bytes and only then
raises. Error responses call `.text()` without even the later size check.

**Impact / preconditions:** A faulty, compromised, or oversized local/opted-in
endpoint. The advertised byte cap does not bound peak input memory for
non-streaming successes and error bodies. No large allocation or
denial-of-service run was needed to establish the ordering defect.

**Fix plan:** Read incrementally under a cumulative byte cap, include
decompressed bytes in the budget, cancel/close the response immediately on
overflow, and separately cap/redact error bodies. Use the same reader for all
ordinary/streaming operations and deterministic response cleanup.

**Regression acceptance:** A paced chunked fake must observe the connection
close before completing an over-budget body, for both 2xx and 4xx responses,
compressed and uncompressed. Under-budget valid JSON still parses. Assert
response/session closure and a bounded retained buffer, not only that an
exception eventually occurs.

## IF-10 — Session bookkeeping retains disconnected users/connections

**Locations:**
`src/textforensics/web_ui/main.py:102-118,143-155,606-607,624-627,728-730` .

**Expected vs observed:** `join_user` maps WebSocket key to session ID, but the
handler overwrites that value with `id(websocket)` . `leave_user` then cannot
find the session. The explicit leave path also pops the mapping before calling
`leave_user` . Probe `session_after_disconnect` observes `user_count=1` ,
`cleanup_removed=0` , and `still_present=true` after the client disconnects.
Cleanup only removes sessions with no users, so it cannot repair these entries.

**Impact / preconditions:** Any normal collaboration join/disconnect. Ghost
participants and closed socket references persist and can exhaust
per-session/per-server capacity; reconnects are not equivalent to one live user.
Sharing uses the same corrupted map and loses intended room routing.

**Fix plan:** Preserve one typed `ws_key -> session_id` mapping, have
`leave_user` exclusively own removal, avoid redundant direct private-map edits,
and expire idle sessions by a real last-activity policy. Keep the manager
application-scoped where app isolation is expected.

**Regression acceptance:** Join/leave, normal disconnect, abnormal disconnect,
duplicate join, and reconnect each release the exact user/socket references.
Last-user departure removes the session; cleanup reclaims stale entries.
Multi-client broadcasts reach live users exactly once and never closed
connections. Use a bounded reconnect test rather than a memory stress test.

## IF-11 — Explanation export retains source sentences by default

**Locations:**
`src/textforensics/explain.py:45,64-73,94-105,120-125,255-264,353-357` .

**Expected vs observed:** Portable evidence should omit sensitive original text
unless explicitly requested (AGENTS.md:49,174-178). `saved_explanation_text`
explains two disposable marker sentences, calls the public save function without
a raw-text option, and finds both original sentences in the JSON.
`segment_attribution` plus top-driving lists repeat them; `summary()` also
exposes text snippets. The implementation's assertion that this is safe because
it is the user's own input is not a privacy control.

**Impact / preconditions:** The user saves/forwards an explanation report or
logs a compact summary. A report expected to be derived evidence carries the
source document. This is not a claim that the explainer itself performs network
I/O.

**Fix plan:** Separate in-memory reviewer text from portable serialization.
Default to offsets/indices/hashes; add an explicit, conspicuous
`include_raw_text` choice through CLI/API/MCP consumers and record it in
metadata. Redact both attribution arrays and summary/top lists consistently.
Specify an intentional opt-in for saving sensitive reviewer text.

**Regression acceptance:** Marker strings are absent from default
save/summary/portable forms but attribution indices/hashes remain useful.
Explicit opt-in preserves exact Unicode text and round-trips. Top lists cannot
accidentally bypass the default redaction.

## IF-12 — Heuristic reports express certainty on unsupported tiny samples

**Locations:** `src/textforensics/adversarial.py:18-25,639-693,700-723` ;
`src/textforensics/semantic.py:480-499,506-509,545-573` .

**Expected vs observed:** Insufficient text must abstain/downgrade, and numeric
confidence must not masquerade as calibration (AGENTS.md:31,46-47).
`unsupported_confidence` observes
`AdversarialDetector().analyze('ordinary') -> risk none, confidence 1.0` ;
one-word `teh` produces medium risk/confidence 0.7 with two triggered patterns.
`analyze_semantic_consistency('ordinary')` has one segment yet returns score 0.0
(documented as human-like), risk none, confidence 1.0. These values are
constants derived from finding counts/severity, not a calibration artifact.
Generic short-text limitations are present but do not prevent maximal
quantitative confidence; adversarial module prose explicitly calls it calibrated
confidence.

**Impact / preconditions:** A short/unsupported input, including non-native
writing/ordinary spelling mistakes. Reviewers receive false reassurance or
overconfident humanization suspicion. This is a demonstrated
semantics/abstention failure, not a claim about empirical error rates that were
not measured.

**Fix plan:** Make support/minimum-sample checks part of report state. Return
unknown/abstain and null undefined aggregates on insufficient data; expose
observed pattern counts/severities separately from empirically calibrated
confidence. Remove the unsupported calibration claim at source and add explicit
failed-pattern coverage instead of silently treating pattern exceptions as no
finding.

**Regression acceptance:** Empty, one-word, one/two-segment,
unsupported-language, and failed-pattern inputs cannot report fully confident
clean/no-risk authorship-related conclusions. A clean result means no observed
patterns under stated coverage, not probability 1 of absence. Numeric
calibration, if later offered, requires versioned held-out evidence.

## IF-13 — Embeddings request does not match Ollama's endpoint contract

**Locations:** `src/textforensics/ollama.py:340-356,359-375,596-600` .

**Expected vs observed:** The implemented request (`input`, batch support,
`truncate` ) and response (`embeddings`) are the `/api/embed` contract, but the
client POSTs them to legacy `/api/embeddings` , whose request uses `prompt` .
`ollama_embeddings_wire` observes `/api/embeddings` with
`{"model":"audit-model","input":["one","two"]}` and a deliberate
protocol-faithful 400. The caller supplied `truncate=False` ; the flag is
omitted because serialization only emits truthy values, allowing the service
default to contradict intent. Reference checked during audit:
<https://docs.ollama.com/api/embed>.

**Impact / preconditions:** Calling public embeddings with a real
Ollama-compatible endpoint. Requests fail or return the wrong shape; explicit
refusal to truncate is silently lost.

**Fix plan:** Target `/api/embed` with explicit boolean serialization, or
implement a separately named legacy adapter with the appropriate
request/response mapping. Avoid accepting successful empty default responses as
valid vectors; validate count, dimensions, and finite values.

**Regression acceptance:** A loopback wire fake asserts exact route/body for
scalar and batch input, especially `truncate=False` , and returns matching
non-empty vectors. Pin wrong-shape/empty response refusal and timeout behavior.
No real model is necessary.

## IF-14 — CSV/HTML export writes a JSON wrapper

**Locations:** `src/textforensics/web_ui/static/app.js:735-754` ; compare actual
server export routes at `src/textforensics/web_ui/main.py:481-524` .

**Expected vs observed:** Selecting CSV or HTML must yield that format.
`export_csv` and `export_html` record `application/json` Blobs beginning with
`{` , containing wrapper keys `data` and `format` , while naming files `.csv`
and `.html` . Even JSON output is the export request wrapper, not the server's
report response. The frontend never calls the implemented export endpoint.

**Impact / preconditions:** Exporting any available current result. Files fail
downstream parsers or silently lose report portability; backend route tests
remain green because they do not exercise the download wiring.

**Fix plan:** Route all formats through the canonical export implementation (or
a shared tested serializer), honor response content type/filename, and preserve
the report schema rather than the request envelope. Do not fix only the
extension.

**Regression acceptance:** Execute each actual export action, parse
JSON/CSV/HTML independently, assert MIME/extension/content agreement, preserve
abstention/limitations/provenance, and compare the content against the API
export for the same real bundle. Include unsafe metadata escaping/formula-safe
CSV handling in the serializer contract.

## IF-15 — Streaming skips normal session and request setup

**Locations:** `src/textforensics/ollama.py:244-255,397-413,529-560,562-594` .

**Expected vs observed:** The public client should initialize/manage its
transport consistently. `ollama_stream_without_context` constructs a fresh
client, obtains `await client.generate(request, stream=True)` , then iterates
once and gets `AttributeError: 'NoneType' object has no attribute 'post'` .
Ordinary methods call `_request` , which ensures a session, but streaming calls
`_session.post` directly. Additionally, the method's `stream=True` argument is
not copied into the `GenerationRequest` body, whose default remains
`stream:false` . The separate streaming path also lacks `_request` status/error
classification and redirect controls.

**Impact / preconditions:** Fresh public client used without `async with` , or a
caller selects method-level streaming on a default request. Streaming fails or
its wire mode contradicts the requested behavior. No real provider/model was
invoked by the failing probe.

**Fix plan:** Use one request lifecycle for streaming and ordinary responses,
explicitly reconcile the stream argument with the wire body, ensure sessions
before iteration, validate HTTP status before parsing, and close/release
responses on completion/cancellation. Apply IF-02/07/09 protections here too.

**Regression acceptance:** Public fresh-client and context-manager
generation/chat streaming both work with a loopback NDJSON fake and
`stream:true` on the wire. Pin 4xx/5xx, timeout, partial/malformed lines,
response cap, consumer cancellation, and cleanup. Count fake
connections/closures; do not simply mock `_session` into existence.

## IF-16 — Implemented MCP tools are not registered

**Locations:** `src/textforensics/mcp_tools.py:465,509,562` ;
`src/textforensics/mcp_server.py:43-157` .

**Expected vs observed:** Tested MCP helper implementations must be reachable
from the actual server if they are part of its tool surface. The real
`_server().list_tools()` returns 16 tools, but not `result_encode` ,
`result_decode` , or `capability_policy_evaluate` ;
`unregistered_mcp_implementations` records all three. Their helper tests
exercise direct Python calls and therefore do not prove MCP availability.

**Impact / preconditions:** An MCP client attempts these implemented
codec/policy operations. Discovery/call routing cannot reach them; direct helper
green is an inaccurate integration signal. Broader API/CLI/UI parity remains a
separate contract decision, not evidence that every Python helper necessarily
belongs on every surface.

**Fix plan:** Define a deliberate public operation inventory, register supported
helpers through the same validated/policy-gated command channel, and update tool
schemas/descriptions and tests together. If intentionally private, remove the
MCP-facing promise/naming and document that decision rather than silently
shipping unreachable functionality.

**Regression acceptance:** Assert exact intended tool names and schemas from the
real server, invoke the newly public operations through MCP dispatch, and
compare structured results/error codes with CLI/API equivalents. Do not settle
for testing helper functions alone.

## IF-17 — Diagnostics report placeholders rather than checked facts

**Locations:** `src/textforensics/diagnostics.py:190-228,239-281,375-395` .

**Expected vs observed:** Readiness must describe configured dependencies;
optional checks must preserve their declared criticality; version/metrics must
obey supplied configuration. `diagnostics_default_claims` observes default
database/storage checks returning `Database connected` and `Storage writable`
from constant-true lambdas, without validating either resource. With only an
optional failed check registered, `diagnostics_contract` returns `critical` ,
because `critical=False` is discarded. Supplying application version
`audit-version` serializes `0.1.0` . The same probe shows a labeled metric
emitted as `# TYPE test_metric{...} gauge` with a literal newline inside a
label, not valid Prometheus exposition.

**Impact / preconditions:** Relying on these public diagnostics classes for
operator health/readiness/export. Systems can be declared healthy without a
check, optional faults can cause inappropriate critical status, and
version/metrics evidence is unreliable. HTTP `/readyz` also returns a constant,
but no stronger claim of complete subsystem readiness is imputed to that shallow
endpoint.

**Fix plan:** Replace default positive placeholders with real injected bounded
checks or explicit not-configured/unknown state. Retain criticality in
registered check records. Use build-info/provided service/version values. Use a
conforming Prometheus exporter or implement proper metric-family declarations
and label escaping at source.

**Regression acceptance:** A deliberately unavailable dependency must not
produce a connected/writable claim. Optional failure degrades while critical
failure is critical. Custom version/service round-trip unchanged. Parse metrics
with a real exposition parser using quotes, backslashes, newlines, and multiple
label sets. No silent omission or scanner suppression.

## IF-18 — Rich diff parses original text as markup

**Location:** `src/textforensics/rich_output.py:465-492` .

**Expected vs observed:** Arbitrary source text must be displayed literally.
`rich_diff_markup` invokes `print_diff('literal [/]', 'changed', console=...)`
with an in-memory Console and receives
`MarkupError: closing tag '[/]' ... has nothing to close` . The strings are
interpolated into Rich markup without escaping.

**Impact / preconditions:** A local reviewer compares text containing Rich-like
syntax, including ordinary code/documentation. Output aborts or styling is
injected; no terminal command execution is claimed.

**Fix plan:** Build Rich `Text` /styled spans from literal user data or escape
it before adding trusted markup. Apply the same discipline to all report fields,
not only this one example.

**Regression acceptance:** Bare `[/]` , nested brackets, Rich color/link tags,
Unicode, and long lines render literally without exceptions, while trusted diff
styling remains correct. Capture plain output and assert original content is
preserved.

## IF-19 — Explanation scored count includes abstained perturbations

**Location:** `src/textforensics/explain.py:234-245,273-281` .

**Expected vs observed:** Successfully scored attribution count must exclude
unavailable/abstained scores, or be named attempted count.
`explanation_scored_count` uses a score function that returns 0.4 for the full
two-sentence document but `None` for both removals. The report returns
`n_scored=2` with zero attributions; the counter is assigned segment count
before iteration.

**Impact / preconditions:** A detector abstains on shortened counterfactuals, a
normal outcome around minimum-length boundaries. Reviewers overestimate
explanation coverage and absence of attributed contribution.

**Fix plan:** Track attempted, scored, abstained, and failed perturbations
separately; increment successful count only after a valid score. State
partial/absent explanation coverage in limitations/summary and preserve
unknowns.

**Regression acceptance:** All-success, partial-abstention, all-abstention,
exception, and singleton cases report exact counts and reasons. Progress totals
may count attempts but must not be serialized as completed successful
attribution count.

## Surface parity and trust matrix

- **Baseline analysis**
  CLI / Python: Present
  HTTP API: `/v1/analyze`
  MCP: `analyze_ai_text`
  UI / WebSocket: Bundled analysis, frontend broken (IF-06)

- **Full report / case**
  CLI / Python: Present
  HTTP API: `/v1/report` , `/v1/case`
  MCP: `build_forensic_report` , `build_case_file`
  UI / WebSocket: `/api/analyze` and streaming full bundle

- **Outbound adapter consent**
  CLI / Python: No per-report selector in audited wrappers
  HTTP API: No parameter
  MCP: No parameter
  UI / WebSocket: No parameter (IF-01)

- **Emergency-stop entry gate**
  CLI / Python: Present on main command path
  HTTP API: HTTP middleware + analysis calls
  MCP: Analysis/report/case gated; read-only introspection deliberately ungated
  UI / WebSocket: HTTP gate, WebSocket bypass (IF-03)

- **Text size/type**
  CLI / Python: CLI/core validators
  HTTP API: `TextRequest` + byte checks
  MCP: Text wrapper validation
  UI / WebSocket: Analyze validates; share bypass (IF-05)

- **Exports**
  CLI / Python: JSON/case paths
  HTTP API: Case JSON; web app has JSON/CSV/HTML route
  MCP: Case/verification tools
  UI / WebSocket: Download wiring wrong (IF-14)

- **Codec / policy helper tools**
  CLI / Python: Python implementations and CLI features
  HTTP API: Not the same inventory
  MCP: Three unregistered helpers (IF-16)
  UI / WebSocket: No equivalent controls surfaced

- **Collaboration/history**
  CLI / Python: No corresponding CLI command in audited parser
  HTTP API: Web app routes only, unauthenticated local alpha
  MCP: None
  UI / WebSocket: Corrupt lifecycle and untrusted sharing (IF-05/10)

The two HTTP apps are materially different contracts (`/v1/*` versus `/api/*` )
with different error/status behavior. Future parity work should route actions
through one command/policy channel, define authentication according to supported
deployment scope, and pin an explicit operation inventory/OpenAPI/MCP schema. Do
not add unauthenticated sensitive actions just to increase parity counts. The
current alpha explicitly excludes remote tenancy; missing enterprise
authentication alone is not reported as a new vulnerability.

## Verified controls and bounded non-findings

- Remote bind has explicit guards in audited entry points; Ollama initial URL
  validation refuses unopted non-loopback hosts. IF-02 is about subsequent
  redirects, not absence of that initial guard.
- HTTP text/body limits, no-store/nosniff/referrer headers, and the UI CSP
  exist. TestClient probe `static_traversal` returns 404 for
  `/static/%2e%2e/main.py` ; `template_session_escaped=true` for a script-shaped
  session query. These narrow checks are not a claim that every possible
  traversal/XSS route was exhausted.
- Most detector/trust/warning text renderers use escaping/textContent; the
  history verdict sink in IF-05 is the concrete exception tested. Current CSP
  materially limits the HTML injection finding.
- `compliance.py` , `corpus_analyzer.py` , `localize.py` , and public
  `__init__.py` were read, with matching tests included in the manifest. No
  additional independently verified issue is asserted here merely because these
  modules expose heuristics, filesystem access, or local analysis. MCP stdio's
  caller-selected local paths are not classified as an HTTP traversal
  vulnerability.
- Ollama ordinary requests have configured total/connect/read timeouts and a
  finite retry loop. No hung provider/model or large-resource stress test was
  run. WebSocket work lacks a shared per-operation cancellation contract;
  IF-03/06/15 acceptance tests specify the concrete integration work rather than
  claiming an unmeasured hang.
- Additional positive/error tests returned green, but frontend tests largely
  check route/asset presence, not JS execution. Fuzz files also contain broad
  exception swallowing around assertions and reimplemented endpoint logic
  (`tests/fuzz/fuzz_web_ui.py:42-46,65-70,119-124` are examples). They are not
  evidence that the real API/JS integration rejects the probes above. No fuzz
  coverage claim is made.

## Cross-auditor lead, not an independent interface-only conclusion

`mcp_tools.capability_check` accepts a claim with `tier=validated` , no
evidence, and `valid_until=2000-01-01` as `is_validated=true`
(`mcp_expired_claim`). The core `CapabilityLedger.enforce` returns the same
validated tier (`cli_equivalent_expired_claim`), so this is **not** a CLI/MCP
discrepancy. The policy owner should adjudicate expiry/evidence semantics at the
shared source and propagate the result to wrappers; do not patch only the MCP
boolean.

## Remediation sequence and release acceptance

1. **Contain text egress and execution:** IF-01/02/03; share one policy and stop
   gate across all surfaces. Add bounded protocol/dispatch probes as regression
   tests before modifying source.
2. **Restore scientific truth and privacy:** IF-04/07/11/12/19. Preserve nulls,
   abstention, native semantics, and raw-text exclusion; never replace them with
   decorative certainty.
3. **Repair local web trust/lifecycle:** IF-05/06/10/14. Add same-origin/token
   policy, canonical messages, bounded retention, typed session bookkeeping, and
   actual frontend execution tests against server outputs.
4. **Repair adapter/tool contracts:** IF-08/09/13/15/16; side-effect-free
   scanning, streaming byte limits, exact Ollama wire contract, and actual MCP
   registry/dispatch tests.
5. **Repair operator evidence/presentation:** IF-17/18. Replace positive
   placeholders with measured facts and literal-safe output.

Each wave must fix source, not suppress static analysis, relax tests, or delete
inconvenient warnings. Parent should run the complete
lint/type/security/build/full-suite lanes after implementation, followed by
installed-package smoke checks outside the checkout. This audit's 333-test green
is deliberately a limited baseline, not release readiness.
