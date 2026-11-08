# Live-TSA interop — status and re-attempt procedure

Status: **NOT achieved. Still blocked from this VM (2026-11-08).**
No live round-trip is claimed anywhere in the repo. The claims gate
stays 33/33 and `qualified` stays `"unknown"` offline.

The client code path itself is verified: `tests/test_timestamp_mock_tsa.py`
exercises `request_timestamp` end-to-end against a local mock TSA
(stdlib `http.server` on loopback) that returns a real CMS token built
with the production DER encoder, and the client verifies the mock's
token through `verify_timestamp_token` exactly as it would a live
one. What is missing is only a live round-trip against a real TSA.

## What was tried from this VM

All probes used short timeouts (10 s per attempt, max 2 attempts per
endpoint) and were wrapped in a hard outer timeout, so no probe could
hang the run. Production timeouts were never edited to make a probe
pass: `request_timestamp` accepts a `timeout` parameter and was called
with `timeout=10.0`.

### 2026-11-08 re-attempt (this wave)

Run at 2026-11-08 00:11–00:22 UTC from this VM, worktree at `3e53278`.

| # | Attempt | Result |
| --- | --- | --- |
| C1 | GET `https://freetsa.org/` (urllib, 10 s) | **200 in 1.08 s**, 200 bytes read |
| C2 | GET `https://timestamp.digicert.com/` (urllib, 10 s) | **Timeout after 10.12 s** (`TimeoutError: The read operation timed out`) — the DigiCert homepage itself did not answer within 10 s this time |
| 1 | POST `https://freetsa.org/tsr` via `request_timestamp(timeout=10.0)` | **Timeout after 10.51 s** (`TimeoutError: The read operation timed out`) |
| 1 | POST `https://timestamp.digicert.com` via `request_timestamp(timeout=10.0)` | **Timeout after 10.30 s** (`TimeoutError: The read operation timed out`) |
| 2 | POST `https://freetsa.org/tsr`, raw urllib, real 62-byte `TimeStampReq` built by `build_timestamp_request` (nonce 424242) | **Timeout after 10.35 s** (`TimeoutError: The read operation timed out`) |
| 2 | POST `https://timestamp.digicert.com`, raw urllib, same 62-byte request | **Timeout after 10.27 s** (`TimeoutError: The read operation timed out`) |
| X | POST `https://freetsa.org/tsr` via curl, `--max-time 10`, empty body | **HTTP 000, 10.002 s, 0 bytes, exit 28** (timeout) |
| X | GET `https://freetsa.org/` via curl, `--max-time 10` | **302 in 0.63 s** |

### 2026-11-07 (U2, for comparison)

`request_timestamp` against both endpoints hung via urllib (30 s
each); curl POST to freetsa `/tsr` hung (HTTP 000, 30 s and 60 s
attempts) while the freetsa homepage GET returned 302 in 0.6 s.
Same pattern as the 2026-11-08 re-attempt.

### Where it hangs

Every POST failure is a **read timeout after the request was sent**:
urllib raises `TimeoutError` from `response.read`, not a DNS,
connect, or TLS error (those would surface as `URLError`) and not an
HTTP error (no `HTTPError`, no status code). The request reaches the
server/proxy and no response bytes ever come back. The freetsa
homepage GET works from the same VM in ~1 s, so sandbox egress
reaches the host — only the `/tsr` POST path hangs. The DigiCert
homepage GET did not answer within 10 s on 2026-11-08, so for
DigiCert even the control was inconclusive this time; the POST
result (read timeout, twice, via two transports) is the same.

Nothing in the client was changed to work around this: no timeout
was raised, no retry loop was added, no fallback TSA was invented.
The block is in the sandbox egress path, not in `timestamp.py`
(the mock-TSA tests prove the client round-trips correctly).

## Procedure: re-attempt from an unrestricted host

Run this on a host with unrestricted egress (not this VM). It needs
only the repo checkout and a Python 3.11+ venv; no account, no key,
no registration. Use the production default timeout (30 s) — the
10 s timeouts above were a sandbox-probe constraint only.

### 1. Check out the repo and prepare the environment

```sh
git clone https://github.com/strmt7/TextForensics.git
cd TextForensics
python3 -m venv .venv
.venv/bin/pip install -e .  # or: PYTHONPATH=$PWD/src .venv/bin/python ...
```

### 2. Run one live round-trip per endpoint

Save this as `tsa_roundtrip.py` (or paste it after `python3 -`):

```python
import hashlib
import sys

sys.path.insert(0, "src")
from textforensics.timestamp import request_timestamp

digest = hashlib.sha256(b"tsa-interop-check").digest()
for url in ("https://freetsa.org/tsr", "https://timestamp.digicert.com"):
    print(f"== {url} ==", flush=True)
    try:
        report = request_timestamp(digest, url)  # default timeout=30.0
    except Exception as exc:  # noqa: BLE001 - manual probe, print and continue
        print(f"FAILED {type(exc).__name__}: {exc}", flush=True)
        continue
    print(f"OK valid={report['valid']}", flush=True)
    print(f"  gen_time={report['gen_time']} gen_time_utc={report['gen_time_utc']}", flush=True)
    print(f"  policy={report['policy']} serial={report['serial_number']}", flush=True)
    print(f"  nonce={report['nonce']} signature_algorithm={report['signature_algorithm']}", flush=True)
    print(f"  signer_cert_fingerprint={report['signer_cert_fingerprint']}", flush=True)
    print(f"  certificate_count={report['certificate_count']}", flush=True)
    print(f"  qualified={report['qualified']} label={report['qualification_label']}", flush=True)
    print(f"  token_bytes={len(report['token_der'])}", flush=True)
    with open(f"token-{url.split('/')[2]}.der", "wb") as fh:
        fh.write(report["token_der"])
    print(f"  token saved to token-{url.split('/')[2]}.der", flush=True)
```

Run it with a hard outer timeout so a hang cannot stall the session:

```sh
timeout 120 python3 tsa_roundtrip.py
```

### 3. What counts as success

**Both** of these, for at least one endpoint:

1. The script prints `OK valid=True` with a `gen_time`, a policy OID,
   a serial number, and a signer-certificate fingerprint.
2. The saved `token-*.der` file re-verifies offline: run
   `verify_timestamp_token` on it against the same digest
   (`hashlib.sha256(b"tsa-interop-check").digest()`) and confirm
   `valid` is `True` with no errors.

`qualified` will still read `"unknown"` — that is expected and
honest: qualification needs an EU Trusted List snapshot, which no
offline check provides. A live round-trip changes the interop
status, not the qualification claim; no qualified TSA is claimed
for v1.0.

### 4. What counts as failure

- `TimeoutError` / `URLError` / `TSA HTTP error` / `TSA did not
  grant the token` printed by the script, or the outer `timeout 120`
  killing the run: the endpoint is unreachable from that host too.
  Record the exact error, the elapsed time, and whether the
  homepage GET works from the same host
  (`curl -s -o /dev/null -w '%{http_code} %{time_total}s\n'
  --max-time 10 https://freetsa.org/`), then stop — do not keep
  retrying, and do not raise the timeout or add retries to the
  production client to make it pass.
- `OK` printed but `valid=False`, or the saved token failing
  offline re-verification: the TSA answered but the token does not
  verify. Save the token and the full error list; that is a client
  or TSA defect to investigate, not an interop success.

### 5. Recording a success (do this, do not hand-edit evidence)

If step 3 succeeds, keep the printed output and the `token-*.der`
file, and record the round-trip as a run artifact through
`scripts/seed_evidence.py` (never hand-edit
`docs/evidence/registry.json` or any artifact). The claim update is
a separate step after the artifact exists: interop becomes
"achieved against <endpoint> on <date>", with the endpoint, latency,
genTime, policy, serial, and certificate fingerprint cited from the
artifact. Until then, no live round-trip is claimed.
