# Live-TSA interop — status and re-attempt procedure

Status: **ACHIEVED against `https://freetsa.org/tsr` on 2026-11-10
(09:13 UTC).** A live round-trip through `request_timestamp` returned
`valid=True` (genTime `20261110091331Z`, policy `1.2.3.4.1`, serial
`166098057`, signer fingerprint
`32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc`,
2 certificates, ECDSA-SHA512, token 4627 B, 0.80 s). The token bytes
are preserved as a run artifact outside the repo (see the 2026-11-10
addendum below); `qualified` stays `"unknown"` offline, honestly
labelled. The claims gate stays 33/33.

The client code path is verified against a live token **since the
2026-11-10 fix below** — not before. The earlier sentence that stood
here ("The client code path itself is verified") was false: the mock
suite was self-consistent with two wrong production constants (the
id-signedData OID and the P-384 curve table), so it verified only
tokens built to the wrong shape and had never confronted the client
with a real token. What is true now: the mock suite pins the true
id-signedData OID as a hardcoded literal and a P-384/ECDSA-SHA512
token, and `request_timestamp` against freeTSA returns `valid=True`
(see the addendum). Sectigo and ai.moda also answer POSTs now, but
their tokens do not verify through this client (see addendum) — they
are separate, out-of-scope findings, not interop success.

This wave (2026-11-10) also closed two mock-proof gaps in the client:
`request_timestamp` now wraps a transport timeout into
`TimestampError("TSA timed out: …")` instead of letting a raw
`TimeoutError` escape (its docstring always promised `TimestampError`
on any transport failure), pinned by a new slow-mock test; and a new
unit test pins verification of multi-certificate chain tokens, the
shape every live TSA returns. No timeout value, retry, or verification
was weakened — the live symptom is unchanged, only its exception type
is now the documented one.

## What was tried from this VM

The 2026-11-08 probes used short timeouts (10 s per attempt, max 2
attempts per endpoint) and were wrapped in a hard outer timeout, so no
probe could hang the run. Production timeouts were never edited to make
a probe pass: `request_timestamp` accepts a `timeout` parameter and was
called with `timeout=10.0` then; the 2026-11-10 wave used the timeout
ladder 10 s / 30 s / 60 s described below.

### 2026-11-10 re-attempt (this wave)

Run at 2026-11-10 ~08:06–08:14 UTC from this VM, worktree at `8c8a1cf`,
branch `fix/live-tsa-reprobe`. Worker A widened the probe to
**10 endpoints** (freetsa, DigiCert, Sectigo, GlobalSign R45, Certum,
ssl.com, Entrust, Apple, Actalis, ai.moda), each with a control GET
(10 s) + raw urllib POST of the real 62-byte `TimeStampReq` (10 s) +
POST via the repo client `request_timestamp` (30 s, the production
default) + raw urllib POST (60 s); pinned nonce 424242, digest
`sha256(b"tsa-interop-check")`. Traffic bound respected: 10 control
GETs + 30 POSTs total (exactly 3 POSTs per endpoint). Every attempt was
wrapped in the script's own timeout plus a hard outer `timeout 900`.
**Result: 0 of 10 endpoints returned a token. No live round-trip is
claimed.**

| Endpoint | GET control (10 s) | POST 10 s (raw) | POST 30 s (`request_timestamp`) | POST 60 s (raw) | Verdict |
| --- | --- | --- | --- | --- | --- |
| `https://freetsa.org/tsr` | `GET https://freetsa.org/` → HTTP 200 in 2.25 s (curl: 302 in 0.63–0.76 s) | Read timeout, 10.22 s | Read timeout, 30.77 s | Read timeout, 60.16 s | **BLOCKED** — homepage GET works, every POST hangs on read |
| `https://timestamp.digicert.com` | `GET https://timestamp.digicert.com/` → read timeout, 10.82 s (curl: HTTP 000, 10.00 s) | Read timeout, 10.17 s | Read timeout, 30.43 s | Read timeout, 60.28 s | **BLOCKED** — even the homepage GET hangs; POSTs hang at all timeouts |
| `https://timestamp.sectigo.com` | `GET https://timestamp.sectigo.com/` → HTTP 403 Forbidden in 2.17 s | Read timeout, 10.20 s | Read timeout, 30.75 s | Read timeout, 60.25 s | **BLOCKED** — host answers GET (403) yet every POST hangs on read |
| `https://timestamp.globalsign.com/tsa/r45standard` | `GET https://timestamp.globalsign.com/` → read timeout, 11.01 s | Read timeout, 10.18 s | Read timeout, 30.73 s | Read timeout, 60.16 s | **BLOCKED** — GET and POSTs all hang |
| `https://time.certum.pl` | `GET https://time.certum.pl/` → read timeout, 10.26 s (curl: HTTP 000, 10.00 s) | Read timeout, 10.17 s | Read timeout, 30.71 s | Read timeout, 60.27 s | **BLOCKED** — GET and POSTs all hang |
| `https://ts.ssl.com` | `GET https://ts.ssl.com/` → `RemoteDisconnected` (remote end closed connection without response), 0.90 s | Read timeout, 10.14 s | Read timeout, 30.55 s | Read timeout, 60.29 s | **BLOCKED** — GET is closed immediately, POSTs hang on read |
| `https://timestamp.entrust.net/TSS/RFC3161sha2TS` | `GET https://timestamp.entrust.net/` → `RemoteDisconnected`, 1.70 s | Read timeout, 10.18 s | Read timeout, 30.50 s | Read timeout, 60.20 s | **BLOCKED** — GET is closed immediately, POSTs hang on read |
| `https://timestamp.apple.com/ts01` | `GET https://timestamp.apple.com/` → `URLError: <urlopen error _ssl.c:983: The handshake operation timed out>`, 10.12 s | `URLError` TLS handshake timed out, 10.09 s | Read timeout, **40.48 s** (see note) | Read timeout, **70.30 s** (see note) | **BLOCKED** — handshake only completes with longer timeouts, then the read hangs like all others |
| `https://timestamp.actalis.it` | `GET https://timestamp.actalis.it/` → read timeout, 10.21 s | Read timeout, 10.20 s | Read timeout, 30.39 s | Read timeout, 60.30 s | **BLOCKED** — GET and POSTs all hang |
| `https://rfc3161.ai.moda` | `GET https://rfc3161.ai.moda/` → HTTP 200 in 0.90 s | Read timeout, 10.23 s | Read timeout, 30.37 s | Read timeout, 60.31 s | **BLOCKED** — homepage GET works, every POST hangs on read |

Apple note: the 30 s client POST elapsed 40.48 s and the 60 s raw POST
elapsed 70.30 s — about 10 s over the nominal timeout in both cases.
The 10 s attempts fail in the TLS handshake (`_ssl.c:983: The handshake
operation timed out`), so the extra ~10 s is the connect/handshake phase
completing before the read timer expires; once the handshake completes,
the POST hangs on read exactly like every other endpoint. This is an
observation about the timeout accounting, not a partial success: zero
bytes came back.

"Read timeout" = `TimeoutError: The read operation timed out` — the
request was sent and no response bytes ever came back (same failure
class as 2026-11-07 and 2026-11-08). From this wave on, the repo client
wraps that into `TimestampError("TSA timed out: …")`; the underlying
failure is unchanged.

Microsoft ACS (`http://timestamp.acs.microsoft.com`) was NOT POSTed: it
is http-only and the repo client refuses non-loopback http by policy.
As a control, `curl` GET returned HTTP 200 in 0.65 s via the proxy —
general http egress works; the TSA POST path does not.

Endpoint sources (2024–2026): the nine canonical endpoints are from
the dev.to check of 2026-10-16, which verified all nine answer real RFC
3161 requests from an unrestricted host
(`dev.to/lizhuojunx86/i-checked-nine-free-rfc-3161-endpoints-against-the-eu-trusted-list-none-is-qualified-five-of-the-djc`);
the GlobalSign R45 URL / hierarchy change (2025-12-10, old URLs redirect
from 2026-03-04) is from TBS-Certificates
(`www.tbs-certificates.co.uk/FAQ/en/serveur-horodatage-globalsign-2025.html`);
ai.moda is from the maintained free-TSA list
(`gist.github.com/Manouchehri/fd754e402d98430243455713efada710`). No other
free/public TSA was found in 2024–2026 sources beyond these ten (plus
http-only ACS and the long-dead StartSSL/VeriSign/Starfield endpoints,
which were not probed).

Egress findings (this wave — the new evidence):

| Check | Result |
| --- | --- |
| Egress proxy | `hatch-egress-proxy:3128`, auth required (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` set; credentials never logged). TLS-terminating with an injected CA bundle (`SSL_CERT_FILE` / `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` = `/run/hatch/egress-tls/ca-bundle.pem`) |
| Direct egress (no proxy) | **Blocked**: `curl --noproxy '*'` to `https://freetsa.org/` connects to the cell gateway `198.19.0.1:443`, which answers plain HTTP → TLS fails with `wrong version number` (curl exit 35, 0.20 s); `openssl s_client` fails identically for freetsa and DigiCert. Direct internet access does not exist from this VM; the proxy is the only path out |
| DNS | Virtualised by the egress layer: `/etc/resolv.conf` points at the cell gateway (`198.19.0.1`, `fd8b:4f84:7d32:99::1`); all ten TSA hosts resolve to sequential synthetic addresses `198.18.208.179`–`.188` (198.18/15 benchmarking range), one per host in probe order. Names resolve; the proxy knows the hosts |
| IPv4 vs IPv6 | No difference: `curl --ipv4` and `--ipv6` GETs of `https://freetsa.org/` both return 302 in 0.66–0.76 s through the proxy |
| Controls that work through the same proxy | `https://example.com/` → 200 in 0.78 s; `http://timestamp.acs.microsoft.com` → 200 in 0.65 s; `https://freetsa.org/` → 302/200 in ~0.7–2.3 s; `https://rfc3161.ai.moda/` → 200 in 0.90 s; `https://timestamp.sectigo.com/` → 403 in 2.17 s |
| Controls that hang or close | DigiCert, GlobalSign, Certum, Actalis homepage GETs: read timeouts at 10 s. SSL.com and Entrust homepage GETs: closed immediately (`RemoteDisconnected`, 0.90 s / 1.70 s) |

Net position: the pattern from 2026-11-07/08 continues, now on 10
endpoints instead of 2. **The discriminating factor is the POST to a
TSA path, not the host or HTTPS in general**: freetsa and ai.moda
homepages answer promptly, yet their `/tsr` POSTs hang at 10/30/60 s;
Sectigo answers a root GET with a fast 403 yet its POST hangs; SSL.com
and Entrust close a root GET immediately yet their POSTs hang rather
than being closed. The uniform outcome — request sent, zero response
bytes, read timeout at every timeout level — is consistent with the
egress proxy (or something behind it) silently dropping / never
answering RFC 3161 POSTs (`Content-Type: application/timestamp-query`),
while ordinary GETs are passed through per-host. Raising the timeout
from 10 s to 30 s to 60 s changed nothing, so this is not a latency
problem. No allowlist documentation for the proxy is visible from
inside the VM, and no proxy error/status is ever returned for the
POSTs — they simply hang.

### 2026-11-10 addendum — freeTSA answers; two client defects found and fixed; live round-trip achieved

**Worker C re-probe, 08:47–08:54 UTC (same morning, same 62-byte
request, pinned nonce 424242).** FreeTSA answered **8/8 raw RFC 3161
POSTs** (HTTP 200, 4635–4637 B, `Content-Type:
application/timestamp-reply`), including 4 parallel POSTs — so
concurrency does not explain Worker A's hangs, and the request shape
was identical. One body was captured (4635 B, sha256
`d14424ca3bfb2cf9a9b83dda16b6fa0abb83ed0020003b043729f49c2a761624`):
a genuine token (status 0, policy `1.2.3.4.1`, serial `166090741`,
genTime `20261110085020Z`, nonce `424242`, ECDSA-SHA512, 2-cert chain).
The repo client **rejected** it — twice, on two pre-existing defects
the mock suite could not see. DigiCert and Certum stayed blocked in
C's run, with a different failure signature than A's (fast
`RemoteDisconnected` on the client leg at ~10.7 s instead of 30 s
read timeouts).

**Defect 1 — wrong OID.** `OID_SIGNED_DATA` was
`1.2.840.113549.1.9.16.1.2` (id-ct-authData) instead of
`1.2.840.113549.1.7.2` (id-signedData, RFC 3161 §2.4.2 / RFC 5652
§5), in both `src/textforensics/timestamp.py` and
`src/textforensics/_standalone_verify.py`. Every conforming token
was rejected at parse time. `OID_DATA` (`1.2.840.113549.1.9.7.1`,
also wrong — id-data is `1.2.840.113549.1.7.1`) was unused
anywhere and was removed. All other OID constants in both files
were audited against RFC 5652/3161 and verified correct (id-ct-TSTInfo,
id-messageDigest, id-signingTime, SHA-1/256/384/512, rsaEncryption,
sha*WithRSAEncryption, id-ecPublicKey, ecdsa-with-SHA256/384/512,
prime256v1, secp384r1; the RSA DigestInfo prefixes were decoded and
checked to embed the right hash OIDs).

**Defect 2 — wrong P-384 constants.** The `_EC_CURVES["P-384"]`
table in both files had `gy` 64 hex chars (not the true value) and
`n` 104 hex chars (8 extra leading `F`s; `n > p`, impossible for a
curve order). The repo generator was not on the curve and `n*G` was
not infinity, so every P-384 verification failed — including
freeTSA's, whose signature `cryptography` verifies independently.
Both values are now the OpenSSL/FIPS secp384r1 values (`n` =
`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973`,
`gy` =
`3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F`),
verified numerically in both files: G on-curve and `n*G` infinity
for P-256 and P-384. Both defects entered in commit `8eb4163`
(standalone copy in `58f7978`).

**Why the suite could not see either defect.** Both token-fixture
builders imported the OID constant from production code, so mock
tokens carried the wrong OID and passed; and no test exercised P-384
at all. The fix adds regression tests that cannot pass with the old
values (proven by a before/after run in `/tmp`: HEAD code + new tests
→ 4 failed; OID-only fix → 1 passed, P-384 test still fails with
`signature_verification_failed`; fixed code → 4 passed): a token
whose ContentInfo contentType is the hardcoded literal
`1.2.840.113549.1.7.2` must verify; a P-384/ECDSA-SHA512 token
(SECP384R1 fixture) must verify end-to-end; and the `_EC_CURVES`
generators must be on-curve with correct order for P-256 and P-384
in both files' tables (the standalone table is a separate literal,
not shared). The captured 08:50 freeTSA token now verifies
`valid=True` offline with the fixed code.

**A-vs-C discrepancy: stated as observed, mechanism unproven.** A
got read timeouts on all 10 endpoints 08:06–08:14 UTC; C got
freeTSA answering 8/8 at 08:47–08:54 UTC. Concurrency and request
shape are ruled out; whether the egress proxy changed rules between
the runs or A hit a transient proxy state cannot be determined from
inside the VM. No mechanism is claimed. The DigiCert/Certum
failure-signature change points the same way — the egress path is
time-varying, not a fixed block.

**Worker D live re-proof and 10-endpoint re-probe, 09:13–09:15 UTC.**
Control GET (10 s) + raw POST (10 s) for all 10 endpoints; client
POST (30 s) for any that answered the raw POST. Max 2 POSTs per
endpoint in this run (plus one capture POST each for Sectigo and
ai.moda, within the 3-per-endpoint bound).

| Endpoint | GET control (10 s) | Raw POST (10 s) | Client POST (30 s) |
| --- | --- | --- | --- |
| `https://freetsa.org/tsr` | HTTP 200 in 0.88 s | HTTP 200, 4637 B in 0.25 s | **`valid=True` in 0.80 s** — genTime `20261110091331Z`, policy `1.2.3.4.1`, serial `166098057`, nonce `424242`, signer fingerprint `32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc`, ECDSA-SHA512, 2 certs, `qualified=unknown`, token 4627 B, sha256 `82459ffc8b940e5612760cbbf21799efb4e43d6c01bffdf46328091109334991`. Saved token re-verifies offline `valid=True`. |
| `https://timestamp.digicert.com` | Read timeout, 10.01 s | Read timeout, 10.01 s | Not attempted |
| `https://timestamp.sectigo.com` | HTTP 403 in 1.16 s | HTTP 200, 6628 B in 0.44 s | **Answers, token rejected:** `TimestampError: TSA token failed verification: unsupported_signature_algorithm:1.2.840.113549.1.1.1 with key 1.2.840.113549.1.1.1` in 0.77 s. Saved response re-parses (repo parser + `openssl asn1parse`) to a genuine token: status 0, policy `1.3.6.1.4.1.6449.2.1.1`, serial `1205580823972057359519299208553396177349491881297`, genTime `20261110091549Z`, nonce `424242`, 3 certs, digest sha384, signature algorithm `rsaEncryption` — Sectigo signs with the bare rsaEncryption OID, which this client does not accept. A separate client limitation, **not** fixed in this wave; no workaround applied. |
| `https://timestamp.globalsign.com/tsa/r45standard` | Read timeout, 10.06 s | Read timeout, 10.01 s | Not attempted |
| `https://time.certum.pl` | Read timeout, 10.01 s | Read timeout, 10.06 s | Not attempted |
| `https://ts.ssl.com` | `URLError: CERTIFICATE_VERIFY_FAILED: Hostname mismatch, certificate is not valid for 'ts.ssl.com'` in 0.53 s | Same hostname-mismatch error in 0.39 s | Not attempted |
| `https://timestamp.entrust.net/TSS/RFC3161sha2TS` | `URLError: CERTIFICATE_VERIFY_FAILED: Hostname mismatch` in 0.48 s | Same hostname-mismatch error in 0.30 s | Not attempted |
| `https://timestamp.apple.com/ts01` | TLS handshake timed out, 10.11 s | TLS handshake timed out, 10.19 s | Not attempted |
| `https://timestamp.actalis.it` | Read timeout, 10.02 s | Read timeout, 10.01 s | Not attempted |
| `https://rfc3161.ai.moda` | `RemoteDisconnected` in 0.66 s | HTTP 200, 6000 B in 0.42 s | **Answers, body unparseable:** `TimestampError: DER length exceeds input.` in 0.78 s. A re-fetch for capture failed mid-body (`IncompleteRead: 2646 bytes read, 3354 more expected`), so the response bytes were not preserved; whether the 6000 B body is itself malformed or truncated in transit is unproven from this run. |

So 3 of 10 endpoints answer POSTs now (freeTSA, Sectigo, ai.moda)
where 0 of 10 did at 08:06–08:14 UTC; only freeTSA's token verifies
through this client. The ssl.com/Entrust hostname-mismatch failures
are a new failure signature vs. Worker A (`RemoteDisconnected`) —
recorded as observed, mechanism unclaimed. The egress path keeps
changing between runs; no fixed block is claimed for any endpoint.

**Evidence.** The verified round-trip could **not** be recorded
through `scripts/seed_evidence.py`: the script has no TSA/interop
measurement — its fixed set is only `suite, ruff, bandit, pip-audit,
schemas, determinism, doc-license, doc-ci-matrix, doc-repro,
code-audit` (`--only tsa` → `Unknown measurement: tsa`, exit 2).
The token and the full verification report are preserved outside the
repo instead (see the verification report in the goal's hidden
files); no evidence file was hand-edited. Seeding a live round-trip
needs a TSA measurement added to that script — a coordinator
decision, not a workaround.

**Note on the standalone verifier.** Its OID and P-384 table are
fixed as above, and its curve table is pinned by the same unit test.
But `_verify_timestamp_token` still requires a sha256 imprint, so a
P-384 token (SHA-384/SHA-512 digest) cannot reach its ECDSA path
today. Pre-existing limitation, flagged here, not changed in this
wave.

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
(From the 2026-11-10 wave on, the client wraps the read timeout into
`TimestampError("TSA timed out: …")`; the underlying failure is
unchanged.)

Nothing in the client was changed to work around this: no timeout
was raised, no retry loop was added, no fallback TSA was invented.
The block is in the sandbox egress path, not in `timestamp.py`
(the mock-TSA tests prove the client round-trips correctly).

## Procedure: re-attempt from an unrestricted host

This procedure is now the **fallback**, not the only path: since
2026-11-10 this VM reaches freeTSA (see the addendum above), but
other endpoints still hang or answer with tokens this client rejects,
so an unrestricted host remains the way to probe the rest. Run this
on a host with unrestricted egress (not this VM). It needs
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
# All ten endpoints probed from the VM on 2026-11-10; the dev.to check
# of 2026-10-16 verified the first nine answer real RFC 3161 requests
# from an unrestricted host. Try freetsa and DigiCert first.
for url in (
    "https://freetsa.org/tsr",
    "https://timestamp.digicert.com",
    "https://timestamp.sectigo.com",
    "https://timestamp.globalsign.com/tsa/r45standard",
    "https://time.certum.pl",
    "https://ts.ssl.com",
    "https://timestamp.entrust.net/TSS/RFC3161sha2TS",
    "https://timestamp.apple.com/ts01",
    "https://timestamp.actalis.it",
    "https://rfc3161.ai.moda",
):
    print(f"== {url} ==", flush=True)
    try:
        report = request_timestamp(digest, url)  # default timeout=30.0
    except Exception as exc:  # noqa: BLE001 - manual probe, print and continue
        print(f"FAILED {type(exc).__name__}: {exc}", flush=True)
        continue
    print(f"OK valid={report['valid']}", flush=True)
    print(f"  gen_time={report['gen_time']} gen_time_utc={report['gen_time_utc']}", flush=True)
    print(f"  policy={report['policy']} serial={report['serial_number']}", flush=True)
    print(
        f"  nonce={report['nonce']} signature_algorithm={report['signature_algorithm']}", flush=True
    )
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

- `TimestampError` (including `TSA timed out`) / `URLError` / `TSA HTTP error` /
  `TSA did not grant the token` printed by the script, or the outer
  `timeout 120` killing the run: the endpoint is unreachable from that
  host too. Record the exact error, the elapsed time, and whether the
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
