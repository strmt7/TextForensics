"""Benchmark dataset loaders — Phase 3, datasets wave 1 + wave 2.

Loaders for the five wave-1 evaluation datasets (RAID, MAGE, Beemo, MixSet,
OpAI-Bench), the wave-2 GhostWriter loader, and the wave-2 DetectRL-X
loader, all fetched from Hugging Face through the public
datasets-server HTTP API — except DetectRL-X, whose viewer/default
load is broken (``DatasetGenerationCastError`` on heterogeneous
columns), so it is fetched as one whole file from the HF resolve URL
and streamed from the local cache instead.

Design rules
------------
* Standard library only. The forensic core has zero third-party
  dependencies (AGENTS.md rule 14); the loaders use ``urllib`` against
  ``https://datasets-server.huggingface.co`` and never require the
  ``datasets`` package. Full-corpus parquet evaluation is future work
  (U1/U3) and would use ``datasets`` as an optional extra then.
* No network at import time. Every fetch goes through
  :class:`DatasetsServerClient`, which is constructed explicitly.
* Licence gate (hard rule). A dataset may not be fetched — not even one
  row — until its licence is resolved and recorded in its
  :class:`DatasetSpec` with ``licence_status == "verified"``. The gate is
  enforced in code (:func:`require_licence`), not by convention.
* TextForensics label convention. Normalised rows use ``label == 1`` for
  machine-generated / machine-involved text and ``label == 0`` for human
  text, matching PAN subtask 1. Datasets whose native polarity differs
  (MAGE: 0 = machine, 1 = human) are flipped by their mapper, and the
  flip is documented on the mapper, not hidden.
* No raw text leaves the cache. Loaders write normalised rows as JSONL to
  a local cache directory (XDG cache by default, see
  :func:`default_cache_dir`); run artifacts record hashes and counts,
  never raw text. Dataset text is never committed to the repo.
* Determinism. Samples are the first *n* rows by server row index
  (paginated, 100 rows per request), or — where a split is ordered by
  testbed/label, so first-*n* would be one-sided — *n* evenly spaced
  rows across the split (:func:`fetch_strided_sample`); no randomness,
  no wall-clock in output. A cache manifest records source URL, fetch
  date, row count and file SHA-256 so a sample can be re-verified later.
* Disjointness. Cache files are JSONL with ``text``/``label`` fields, the
  exact format :func:`textforensics.benchmark.fingerprint_dataset` and
  :func:`textforensics.benchmark.check_disjointness` consume, so split
  disjointness is checked with the existing fail-closed machinery.
* Large files. :func:`download_large_file` is the shared resumable
  downloader for whole-file fetches (a ~1 GB DetectRL-X file):
  HTTP Range resume, retries with jittered capped back-off,
  ``.part`` + atomic rename so a partial file is never mistaken for a
  valid one, SHA-256 verification against a manifest hash, split
  connect vs stall timeouts, and a curl subprocess fallback for
  stalls urllib cannot ride out (curl is a recommended system tool,
  not a Python dependency; core stays stdlib-only).
* Whole-file datasets. DetectRL-X is served as one JSON array per
  file (~879 MB for the general file); loading it whole would need
  several GB of RAM, so :func:`iter_detectrl_x_rows` decodes one
  object at a time with ``json.JSONDecoder.raw_decode`` over a small
  rolling buffer, and :func:`sample_detectrl_x_rows` counts rows per
  split and collects strided samples in a single streaming pass.

Wave-1 scope only, plus GhostWriter and DetectRL-X in wave 2, and
the licence-blocked DetectRL, M4 and M4GT-Bench loaders (MixSet precedent: spec + a
mapper that refuses until the licence resolves and a live row has
been inspected — no live rows, no artifacts, no records). RealDet /
CrisisFake have no verified route (no loader), PAN 2025 is wave 2
(gated on TIRA registration), MultiSocial was dropped by Greg's decision.
"""

from __future__ import annotations

import ast
import hashlib
import http.client
import json
import logging
import os
import random
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATASETS_SERVER_BASE = "https://datasets-server.huggingface.co"
ROWS_PER_REQUEST = 100
DEFAULT_TIMEOUT_S = 30
DEFAULT_RETRIES = 3

logger = logging.getLogger(__name__)

# curl fallback caps (see _download_with_curl): connect budget, total
# wall-clock budget, and the stall detector (abort only if throughput
# collapses below this floor for this long, instead of a fixed read
# timeout — the property that lets curl ride out the stalls that
# abort urllib attempts).
_CURL_CONNECT_TIMEOUT_S = 30
_CURL_MAX_TIME_S = 3600
_CURL_SPEED_LIMIT_BPS = 1024
_CURL_SPEED_TIME_S = 120
_CURL_RETRIES = 3
_CURL_RETRY_DELAY_S = 5

# Plain http is only ever allowed to loopback (local fixtures); see
# _require_https_or_loopback_http.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _require_https_or_loopback_http(url: str) -> None:
    """Refuse any URL that is not https (or http on loopback).

    The scheme policy shared by every network call in this module —
    the urllib path of :func:`download_large_file`, the curl fallback
    (see :func:`_curl_proto_args`, which used to enforce it alone)
    and :class:`DatasetsServerClient`. Plain http off-loopback would
    send the request (and, for the downloader, the dataset bytes) in
    the clear where it can be observed or altered, and ``urllib``
    would also honour non-http schemes such as ``file://``. https
    everywhere; plain http only for loopback fixtures (the local
    stall servers in the tests). Raises :class:`DownloadError` with
    the same wording the curl fallback already used, so the two
    transports cannot drift apart again.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (parsed.hostname or "").lower() in _LOOPBACK_HOSTS:
        return
    raise DownloadError(
        f"refuses non-https URL (loopback http only): {parsed.scheme}://{parsed.hostname or '?'}"
    )


class _NoDowngradeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler that refuses any redirect the scheme policy refuses.

    ``urllib`` follows redirects silently, so an https URL could
    redirect to http and the bytes would travel in the clear — bounded
    only by the SHA-256/size verification afterwards (curl's fallback
    already pins ``--proto-redir =https``; the urllib path had no
    equivalent). Two checks run on every hop, so the two transports
    cannot drift apart again:

    1. the target must pass :func:`_require_https_or_loopback_http`,
       the same rule the original URL already passed (so a redirect
       to ``file://`` or to http off-loopback is refused); and
    2. a hop from https to http is refused even when the target is
       loopback — a downgrade is a downgrade, and curl's
       ``--proto-redir =https`` refuses it too. Only an origin that
       was itself http on loopback may stay on http loopback.
    The refusal raises :class:`DownloadError` before any request to
    the target is made (``http_error_302`` resolves a relative
    ``Location`` against the request URL first, so the target seen
    here is always absolute). The hop-by-hop comparison uses the
    request being redirected, so a chained https→https→http redirect
    is refused at the downgrading hop.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https_or_loopback_http(newurl)
        target = urllib.parse.urlparse(newurl)
        if urllib.parse.urlparse(req.full_url).scheme == "https" and target.scheme == "http":
            raise DownloadError(
                f"refuses https-to-http redirect downgrade: http://{target.hostname or '?'}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _guarded_urlopen(request: urllib.request.Request, *, timeout: float) -> Any:
    """``urllib.request.urlopen`` through an opener carrying the redirect guard.

    Same call shape as ``urlopen`` (request + timeout) so the
    downloader and the datasets-server client keep one transport
    seam. The opener is the default one ``build_opener`` assembles
    (proxy support included) with the default redirect handler
    replaced by :class:`_NoDowngradeRedirectHandler` — ``build_opener``
    drops the default handler when a subclass instance is passed.
    """
    return urllib.request.build_opener(_NoDowngradeRedirectHandler()).open(request, timeout=timeout)


# TextForensics label convention: 1 = machine-generated / machine-involved,
# 0 = human. Mirrors PAN subtask 1 (class 1 = machine, 0 = human).
LABEL_MACHINE = 1
LABEL_HUMAN = 0

# Editing regimes, using the U1 vocabulary (research §2.2).
REGIME_RAW = "raw"
REGIME_PARAPHRASED = "paraphrased"
REGIME_HUMAN_EDITED = "human-edited"
REGIME_LLM_EDITED = "llm-edited"
REGIME_MIXED_ORIGIN = "mixed-origin"

LICENCE_VERIFIED = "verified"
LICENCE_UNRESOLVED = "unresolved"

# DetectRL-X whole-file fetch (wave 2, worker B). Verified 2026-11-07
# from the HF tree API: Binary/binary_general_open.json is 878,631,989
# bytes; the LFS oid is its SHA-256. The HF viewer / default load is
# broken (DatasetGenerationCastError: perturbation files add a
# `perturbation_info` column), so this file is the only route for the
# preliminary slice. README "Open vs. Heldout" table: 124,800 rows per
# file (76,800 train + 48,000 test); the headline 3,456,000 counts
# overlapping categories and is NEVER a downloadable row count.
DETECTRL_X_URL = (
    "https://huggingface.co/datasets/WUJUNCHAO/DetectRL-X/resolve/main/"
    "Binary/binary_general_open.json"
)
DETECTRL_X_FILE = "Binary/binary_general_open.json"
DETECTRL_X_SHA256 = (
    "815be1667a5e7404d9e513ab339c214c713bd7ac4eb46f375fa0a26bf2dfc15f"  # pragma: allowlist secret
)
# ^ Public content hash of a public dataset file (the HF LFS oid, served
# by the HF tree API) — a file-integrity check value, not a credential.
DETECTRL_X_BYTES = 878_631_989
DETECTRL_X_TRAIN_ROWS = 76_800
DETECTRL_X_TEST_ROWS = 48_000
DETECTRL_X_LANGS = (
    "arabic",
    "chinese",
    "english",
    "french",
    "german",
    "portuguese",
    "russian",
    "spanish",
)
DETECTRL_X_MODELS = ("deepseek-v3", "gemini-2.5-flash", "gpt-4o", "qwen-max")
DETECTRL_X_DOMAINS = ("Academic", "News", "Novel", "Wiki", "SEO", "Webtext")


class DatasetError(Exception):
    """Base error for dataset loader failures."""


class DatasetLicenceError(DatasetError):
    """Raised when a fetch is attempted before licence resolution."""


class DatasetFetchError(DatasetError):
    """Raised when the datasets-server API cannot serve a request."""


class DownloadError(DatasetError):
    """Raised when a large-file download cannot be completed/verified."""


DOWNLOAD_CHUNK_SIZE = 1 << 20  # 1 MiB per read while streaming


def _is_retryable_download_error(exc: Exception) -> bool:
    """True for transient download failures; 4xx HTTP errors are not retried."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return isinstance(
        exc,
        (
            urllib.error.URLError,
            TimeoutError,
            http.client.HTTPException,
            ConnectionError,
        ),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(DOWNLOAD_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _log_host(url: str) -> str:
    """Host part of ``url`` for log lines (never the full URL)."""
    return urllib.parse.urlparse(url).hostname or "?"


def _response_content_length(response: Any) -> int | None:
    """Declared Content-Length of ``response``, or None if absent/unparseable.

    Only a plain int/str header is trusted: mocked responses return
    MagicMocks for unconfigured attributes, and those must never be
    mistaken for a declared length.
    """
    raw = response.getheader("Content-Length")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw.strip())
        except ValueError:
            return None
    return None


def _backoff_delay(attempt: int, base: float = 2.0, cap: float = 60.0) -> float:
    """Full-jitter back-off before download attempt ``attempt`` (0-based).

    Uniform in ``[0, min(cap, base * 2**attempt)]``: retries spread
    over minutes instead of re-hitting the same stalled window seconds
    apart (the shipped ``2**attempt`` discipline totalled 31 s for
    six attempts), and concurrent clients do not synchronise their
    retries. The ``time.sleep`` call site stays patchable in tests.
    """
    return random.uniform(0, min(cap, base * 2**attempt))


class _SplitTimeoutHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose socket timeout switches after connect().

    The connection is created with the connect budget (``timeout``);
    once connect() returns — TCP + proxy CONNECT done — the socket
    timeout becomes the stall budget, which then bounds TTFB and every
    body read. Verified against a local delayed-headers server
    (2026-11-07): a 2 s header delay trips a 0.5 s stall budget in
    ~0.53 s and succeeds with a 5 s budget.
    """

    def __init__(self, *args: Any, stall_timeout_s: float | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._stall_timeout_s = stall_timeout_s

    def connect(self) -> None:
        super().connect()
        if self._stall_timeout_s is not None and self.sock is not None:
            self.sock.settimeout(self._stall_timeout_s)


class _SplitTimeoutHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection with the same connect/stall split (see above).

    connect() does TCP + TLS here, so the stall budget is set on the
    wrapped socket after the handshake, and bounds TTFB and reads.
    """

    def __init__(self, *args: Any, stall_timeout_s: float | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._stall_timeout_s = stall_timeout_s

    def connect(self) -> None:
        super().connect()
        if self._stall_timeout_s is not None and self.sock is not None:
            self.sock.settimeout(self._stall_timeout_s)


class _SplitTimeoutHTTPHandler(urllib.request.HTTPHandler):
    """HTTPHandler opening connections with a split connect/stall timeout."""

    def __init__(self, stall_timeout_s: float) -> None:
        super().__init__()
        self._stall_timeout_s = stall_timeout_s

    def http_open(self, req: urllib.request.Request):
        return self.do_open(_SplitTimeoutHTTPConnection, req, stall_timeout_s=self._stall_timeout_s)


class _SplitTimeoutHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler opening connections with a split connect/stall timeout."""

    def __init__(self, stall_timeout_s: float) -> None:
        super().__init__()
        self._stall_timeout_s = stall_timeout_s

    def https_open(self, req: urllib.request.Request):
        return self.do_open(
            _SplitTimeoutHTTPSConnection, req, stall_timeout_s=self._stall_timeout_s
        )


def _split_timeout_opener(stall_timeout_s: float) -> urllib.request.OpenerDirector:
    """Opener whose HTTP/HTTPS handlers enforce a split connect/stall timeout.

    ``build_opener`` keeps its default ProxyHandler (egress proxies
    still work) and drops only the default HTTP/HTTPS handlers, which
    these subclasses replace; each redirect hop re-enters the handler,
    so every hop gets the same split. The ``timeout=`` passed to
    ``opener.open`` is the connect budget; the stall budget travels
    inside the handler. The redirect guard
    (:class:`_NoDowngradeRedirectHandler`) rides along, so a redirect
    on this path can no more downgrade https to http than on the
    plain path.
    """
    return urllib.request.build_opener(
        _SplitTimeoutHTTPHandler(stall_timeout_s),
        _SplitTimeoutHTTPSHandler(stall_timeout_s),
        _NoDowngradeRedirectHandler(),
    )


def _curl_proto_args(url: str) -> tuple[str, str]:
    """``--proto`` / ``--proto-redir`` values for ``url``.

    https everywhere; plain http only for loopback (local fixtures).
    Any other http URL is refused: a redirect downgrade to http (or
    file) would be an SSRF / file-exfiltration shape, and the only
    production caller passes a constant https URL. The refusal itself
    lives in :func:`_require_https_or_loopback_http`, which the
    urllib path calls too, so both transports enforce one policy.
    """
    _require_https_or_loopback_http(url)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return "=https", "=https"
    return "=http", "=http"


def _download_with_curl(url: str, part: Path, *, limit_bytes: int | None = None) -> None:
    """Fetch ``url`` into ``part`` with curl (fallback / forced path).

    argv list via :func:`subprocess.run` (``shell=False``), with a
    ``--`` separator before the URL so a hostile URL cannot be parsed
    as flags. Flags: ``--fail`` (HTTP errors fail instead of writing
    an error page to ``.part``), ``--location`` with
    ``--proto =https --proto-redir =https`` (no downgrade), a 30 s
    connect timeout, a 3600 s total budget, and the stall detector
    ``--speed-limit 1024 --speed-time 120`` (abort only if throughput
    collapses, instead of a fixed read timeout). ``--retry 3
    --retry-delay 5`` retries transient failures.

    ``--retry-all-errors`` is deliberately NOT passed: verified
    2026-11-07 against a local server (curl 8.5.0) that it retries
    404s (3 requests for one 404, vs 1 without it), which would
    defeat the fail-fast 4xx discipline. A server that ignores Range
    on a resume makes curl exit 33; the ``.part`` is then deleted and
    the fetch restarts from byte 0 (also verified locally). Any other
    non-zero exit raises :class:`DownloadError` with the exit code
    only — curl's stderr can echo the URL, so it is never logged or
    included in the error. The caller still runs the size/SHA-256
    verification + atomic rename afterwards; the transport is never
    trusted.

    With ``limit_bytes`` the fetch is a prefix probe: ``--range`` asks
    for the first N bytes and ``--max-filesize`` is the fail-safe if
    the server ignores Range and answers 200 with the whole file
    (curl then exits 63 instead of downloading it all).
    """
    curl = shutil.which("curl")
    if curl is None:
        raise DownloadError(
            "curl fallback unavailable: no curl binary on PATH; the urllib download already failed"
        )
    proto, proto_redir = _curl_proto_args(url)

    def _argv(*, resume: bool) -> list[str]:
        argv = [
            curl,
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            proto,
            "--proto-redir",
            proto_redir,
            "--connect-timeout",
            str(_CURL_CONNECT_TIMEOUT_S),
            "--max-time",
            str(_CURL_MAX_TIME_S),
            "--speed-limit",
            str(_CURL_SPEED_LIMIT_BPS),
            "--speed-time",
            str(_CURL_SPEED_TIME_S),
            "--retry",
            str(_CURL_RETRIES),
            "--retry-delay",
            str(_CURL_RETRY_DELAY_S),
        ]
        if limit_bytes is not None:
            argv += ["--range", f"0-{limit_bytes - 1}", "--max-filesize", str(limit_bytes)]
        elif resume:
            argv += ["--continue-at", "-"]
        argv += ["-o", str(part), "--", url]
        return argv

    logger.debug("curl download: host=%s resume=%s", _log_host(url), limit_bytes is None)
    result = subprocess.run(_argv(resume=True), shell=False, capture_output=True, text=True)
    if result.returncode == 33 and limit_bytes is None:
        # Server ignored Range on a resume: restart from byte 0.
        logger.debug("curl exit 33 (server ignored Range); restarting from byte 0")
        part.unlink(missing_ok=True)
        result = subprocess.run(_argv(resume=False), shell=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise DownloadError(f"curl download failed with exit code {result.returncode}")


def download_large_file(
    url: str,
    dest: str | Path,
    *,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
    chunk_size: int = DOWNLOAD_CHUNK_SIZE,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    retries: int = DEFAULT_RETRIES,
    user_agent: str = "TextForensics/0.2.0 (research evaluation)",
    stall_timeout_s: float | None = None,
    connect_timeout_s: float = 30,
    use_curl_fallback: bool = True,
    force_curl: bool = False,
    limit_bytes: int | None = None,
) -> Path:
    """Download ``url`` to ``dest`` with resume, retries and verification.

    ``url`` must be https, or http on loopback (local fixtures):
    anything else raises :class:`DownloadError` before any network
    use — the urllib path enforces the same scheme policy the curl
    fallback already enforced (see
    :func:`_require_https_or_loopback_http`).

    Standard library only, plus an opportunistic curl subprocess
    fallback (curl is a recommended system tool, not a dependency).
    The download streams to ``dest`` + ``".part"`` and is renamed into
    place with :func:`os.replace` only after the transfer completes
    and verifies — a partial or corrupt file is never left at
    ``dest``. A pre-existing ``.part`` file is resumed with an HTTP
    ``Range`` request when the server honours it (HTTP 206); if the
    server ignores the range (HTTP 200) the partial file is discarded
    and the download restarts from byte 0. A body shorter than the
    declared ``Content-Length`` is treated as a truncated transfer
    and retried (a clean mid-body close otherwise reads as a
    successful short download). Transient failures
    (``RemoteDisconnected`` / ``HTTPException`` / ``ConnectionError``
    / ``URLError`` / timeouts, and 5xx HTTP errors) are retried with
    jittered capped back-off (see :func:`_backoff_delay`); 4xx errors
    fail immediately. ``expected_sha256`` (and ``expected_bytes`` when
    known) are checked before the rename; a mismatch raises
    :class:`DownloadError` and leaves only the ``.part`` file behind.
    A destination that already exists and verifies against the
    expected hash/size is returned without re-downloading.

    Timeouts are split: ``connect_timeout_s`` bounds TCP connect, TLS
    handshake and proxy CONNECT, while ``stall_timeout_s`` bounds
    time-to-first-byte and every body read (``None`` falls back to
    ``timeout_s``). The split is implemented with a custom urllib
    handler (see :func:`_split_timeout_opener`); when the two budgets
    are equal the plain ``urlopen`` path is used instead, which is
    the same semantics with no extra machinery. Per-attempt phase
    timing (TTFB, bytes written, slowest chunk read) is logged at
    debug level; argv and curl stderr are never logged.

    When urllib exhausts its retries and ``use_curl_fallback`` is
    set, the download is retried once via :func:`_download_with_curl`
    (curl has no read timeout, only a throughput-floor stall
    detector, so it rides out the stalls that abort urllib attempts;
    it is also the existence proof for the 2026-11-07 DetectRL-X
    incident). If curl is absent the error names curl and chains the
    urllib error as context. ``force_curl`` skips urllib entirely
    (for the probe job); the size/SHA-256 verification + atomic
    rename still gate the rename on every path.

    ``limit_bytes`` fetches only the first N bytes (``Range:
    bytes=0-(N-1)``, reads capped so a Range-ignoring server cannot
    stream the whole file) and skips the full-file size/SHA-256
    checks — a prefix probe, not a verified download. Callers must
    only pass allowlisted dataset URLs.
    """
    _require_https_or_loopback_http(url)
    stall = timeout_s if stall_timeout_s is None else stall_timeout_s
    dest = Path(dest)
    part = dest.with_name(dest.name + ".part")
    if limit_bytes is not None:
        # A prefix probe is always a fresh fetch: a stale destination
        # or .part must not short-circuit it, and a resumed Range
        # would overshoot the prefix.
        dest.unlink(missing_ok=True)
        part.unlink(missing_ok=True)
    elif dest.exists():
        if expected_sha256 is not None and _sha256_file(dest) == expected_sha256:
            return dest
        if (
            expected_sha256 is None
            and expected_bytes is not None
            and dest.stat().st_size == expected_bytes
        ):
            return dest
        if expected_sha256 is None and expected_bytes is None:
            return dest
        dest.unlink()

    dest.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    if force_curl:
        _download_with_curl(url, part, limit_bytes=limit_bytes)
    else:
        for attempt in range(retries + 1):
            resume_from = part.stat().st_size if part.exists() else 0
            headers = {"User-Agent": user_agent}
            if limit_bytes is not None:
                headers["Range"] = f"bytes=0-{limit_bytes - 1}"
            elif resume_from:
                headers["Range"] = f"bytes={resume_from}-"
            request = urllib.request.Request(url, headers=headers)
            attempt_started = time.monotonic()
            ttfb_s: float | None = None
            bytes_written = 0
            slowest_read_s = 0.0
            try:
                if stall == connect_timeout_s:
                    # B310 reviewed: url scheme validated at the top of
                    # download_large_file by _require_https_or_loopback_http
                    # (https, or http on loopback only); redirects go
                    # through _guarded_urlopen, which refuses any hop the
                    # scheme policy refuses (no https→http downgrade).
                    response_cm = _guarded_urlopen(request, timeout=stall)
                else:
                    opener = _split_timeout_opener(stall)
                    response_cm = opener.open(request, timeout=connect_timeout_s)
                with response_cm as response:
                    ttfb_s = time.monotonic() - attempt_started
                    status = getattr(response, "status", 200)
                    if status == 416:
                        # Range not satisfiable: the part already holds the
                        # whole file; fall through to verification below.
                        break
                    if resume_from and status != 206:
                        # Server ignored the Range header; restart cleanly.
                        part.unlink(missing_ok=True)
                        resume_from = 0
                    mode = "ab" if resume_from else "wb"
                    remaining = limit_bytes if limit_bytes is not None else None
                    with part.open(mode) as handle:
                        while True:
                            if remaining is not None and remaining <= 0:
                                break
                            read_started = time.monotonic()
                            chunk = response.read(
                                chunk_size if remaining is None else min(chunk_size, remaining)
                            )
                            slowest_read_s = max(slowest_read_s, time.monotonic() - read_started)
                            if not chunk:
                                break
                            handle.write(chunk)
                            bytes_written += len(chunk)
                            if remaining is not None:
                                remaining -= len(chunk)
                    if limit_bytes is None:
                        # A clean mid-body close is silent truncation:
                        # read() returns b"" instead of raising, so a
                        # short body would otherwise be renamed as
                        # complete. Compare against the declared length
                        # (206: the remaining bytes) and retry on a
                        # mismatch — the next attempt resumes from the
                        # bytes already written.
                        declared = _response_content_length(response)
                        if declared is not None and bytes_written != declared:
                            raise http.client.IncompleteRead(b"", declared)
                logger.debug(
                    "download attempt %d/%d: host=%s status=%s ttfb=%.2fs "
                    "bytes=%d slowest_read=%.2fs",
                    attempt + 1,
                    retries + 1,
                    _log_host(url),
                    status,
                    ttfb_s if ttfb_s is not None else float("nan"),
                    bytes_written,
                    slowest_read_s,
                )
                break
            except Exception as exc:  # noqa: BLE001 — retryability decides
                logger.debug(
                    "download attempt %d/%d failed: host=%s ttfb=%.2fs bytes=%d error=%s",
                    attempt + 1,
                    retries + 1,
                    _log_host(url),
                    ttfb_s if ttfb_s is not None else float("nan"),
                    bytes_written,
                    type(exc).__name__,
                )
                if not _is_retryable_download_error(exc):
                    raise DownloadError(f"GET {url} failed (not retryable): {exc}") from exc
                last_error = exc
                if attempt < retries:
                    time.sleep(_backoff_delay(attempt))
        else:
            # urllib exhausted every attempt: one curl fallback, then
            # the error stands (with the urllib error as context).
            if not use_curl_fallback:
                raise DownloadError(
                    f"GET {url} failed after {retries + 1} attempts: {last_error}"
                ) from last_error
            try:
                _download_with_curl(url, part, limit_bytes=limit_bytes)
            except DownloadError as exc:
                raise exc from last_error
    if not part.exists():
        raise DownloadError(f"GET {url}: server reported the range complete but no data arrived")

    if limit_bytes is None:
        if expected_bytes is not None and part.stat().st_size != expected_bytes:
            raise DownloadError(
                f"GET {url}: downloaded {part.stat().st_size} bytes, "
                f"expected {expected_bytes}; leaving {part} for inspection"
            )
        if expected_sha256 is not None:
            actual = _sha256_file(part)
            if actual != expected_sha256:
                raise DownloadError(
                    f"GET {url}: SHA-256 mismatch (got {actual}, "
                    f"expected {expected_sha256}); leaving {part} for inspection"
                )
    else:
        logger.debug(
            "prefix fetch: host=%s bytes=%d (limit %d, no full-file checks)",
            _log_host(url),
            part.stat().st_size,
            limit_bytes,
        )
    os.replace(part, dest)
    logger.info("downloaded host=%s bytes=%d -> %s", _log_host(url), dest.stat().st_size, dest)
    return dest


@dataclass(frozen=True)
class DatasetSpec:
    """Static, citable facts about one benchmark dataset.

    The licence fields are the pre-download gate: ``licence_status`` must
    be ``"verified"`` (with ``licence`` naming the exact licence string
    as stated by the source) before any row may be fetched.
    """

    key: str
    name: str
    hf_id: str
    paper: str
    source_url: str
    licence: str | None
    licence_note: str
    licence_status: str
    configs: tuple[str, ...]
    splits: tuple[tuple[str, str], ...]  # (config, split) pairs
    notes: str
    citation: str
    # Per-domain licences, for datasets with no single licence
    # (GhostWriter). When present, the mapper refuses any row whose
    # domain has no recorded licence (fail closed); datasets without
    # per-domain licences leave this as None.
    domain_licences: dict[str, str] | None = None


@dataclass(frozen=True)
class NormalizedRow:
    """One evaluation row in TextForensics convention.

    ``label`` is 1 for machine-generated / machine-involved text, 0 for
    human text, and None where the origin is ambiguous (mixed-origin rows
    carry their regime and coverage in ``meta`` instead of a clean label).
    ``text`` is the raw text as served; it lives only in the local cache,
    never in a run artifact.
    """

    text: str
    label: int | None
    dataset: str
    config: str
    split: str
    source_id: str
    regime: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_jsonl(self) -> dict[str, Any]:
        """Serialise for the JSONL cache (benchmark-fingerprint format)."""
        return {
            "text": self.text,
            "label": self.label,
            "dataset": self.dataset,
            "config": self.config,
            "split": self.split,
            "source_id": self.source_id,
            "regime": self.regime,
            "meta": self.meta,
        }


SPECS: dict[str, DatasetSpec] = {
    "detectrl_x": DatasetSpec(
        key="detectrl_x",
        name="DetectRL-X",
        hf_id="WUJUNCHAO/DetectRL-X",
        paper="Wu et al., ACL 2026, arXiv:2605.15518",
        source_url="https://huggingface.co/datasets/WUJUNCHAO/DetectRL-X",
        licence="Three-way conflict — GitHub README: Apache License 2.0 "
        "with use strictly restricted to non-commercial academic research "
        "purposes; Hugging Face card/API: MIT; ACL 2026 paper: use strictly "
        "restricted to noncommercial academic research purposes. The "
        "strictest reading (non-commercial academic research only) governs.",
        licence_note="Three-way licence conflict, all verified live "
        "2026-11-07. (1) GitHub README §License (ATH-MaaS/Marco-LLM, "
        "formerly AIDC-AI/Marco-LLM): 'licensed under the Apache License "
        "2.0. Usage is strictly restricted to non-commercial academic "
        "research purposes.' (README badge also says Apache 2.0; repo "
        "record license:null, no LICENSE file.) (2) HF card + HF API "
        "record: MIT (license:mit tag; record last modified 2026-07-27). "
        "(3) ACL 2026 paper, Ethical Considerations: use 'strictly "
        "restricted to noncommercial academic research purposes.' "
        "Reasoning (Beemo precedent — MIT + a CC-BY-NC-4.0 carve-out was "
        "verified with the carve-out recorded and honoured): the strictest "
        "reading (NC academic research only) is satisfiable, and under ALL "
        "THREE readings TextForensics' intended use — non-commercial "
        "academic research evaluation, local cache only, no redistribution, "
        "no commercial use — is permitted. The conflict blocks commercial "
        "use and redistribution, neither of which we do. Record all three "
        "strings verbatim; the NC-academic-only restriction governs. No "
        "redistribution of raw text, ever.",
        licence_status=LICENCE_VERIFIED,
        configs=("binary",),
        splits=(("binary", "train"), ("binary", "test")),
        notes="Multilingual raw slice (8 languages, 6 domains, 4 commercial "
        "LLMs). Scope for this wave: ONE Binary file only, "
        "Binary/binary_general_open.json (878,631,989 bytes, SHA-256 "
        "815be1667a5e7404d9e513ab339c214c713bd7ac4eb46f375fa0a26bf2dfc15f, "
        "verified from the HF tree API 2026-11-07); the README states the "
        "train split is identical across all strategy files, so the "
        "general file is the representative preliminary slice. Downloading "
        "all 16 Binary files (~14.67 GB) for a preliminary slice is not "
        "proportionate. Ternary files are out of scope for the measurement "
        "(the mapper supports llm_refined_text if present). HF viewer / "
        "default load is BROKEN (DatasetGenerationCastError: perturbation "
        "files add a perturbation_info column; datasets-server /size "
        "confirms num_rows 0) — load per-file only, never the dataset "
        "default. README table: 124,800 rows per file (76,800 train + "
        "48,000 test), 2:1 train-test split, 192 (language x model x "
        "domain) cells; the headline 3,456,000 counts overlapping "
        "categories. No numeric label field — the label is which text "
        "field the row comes from. No row id field — source_id is file + "
        "row index. The general file has no perturbation_info column; "
        "perturbation files carry it (list of structs) — the loader "
        "tolerates heterogeneous columns across files and never assumes a "
        "single schema. Authors' metrics (F1B/F1F) are context only, never "
        "ours.",
        citation="Wu et al., DetectRL-X, ACL 2026, arXiv:2605.15518.",
    ),
    "ghostwriter": DatasetSpec(
        key="ghostwriter",
        name="GhostWriter",
        hf_id="TheItCrOw/GhostWriter",
        paper="Schaaf, Bönisch & Mehler, LREC 2026",
        source_url="https://huggingface.co/datasets/TheItCrOw/GhostWriter",
        licence="Per-domain licences (no single dataset licence): "
        "cnn_news Apache-2.0; arxiv_papers arXiv.org non-exclusive "
        "licence to distribute; blog_authorship_corpus CC0 / free for "
        "non-commercial research; bundestag DL-DE-BY-2.0; "
        "house_of_commons Open Parliament Licence; euro_court_cases "
        "CC-BY-NC-SA 4.0; student_essays CC-BY-NC-SA 4.0; gutenberg CC0",
        licence_note="Per-domain licence table verified 2026-11-07 from "
        "the live HF dataset card (lines 340-468): cnn_news Apache-2.0; "
        "arxiv_papers arXiv.org non-exclusive licence to distribute; "
        "blog_authorship_corpus CC0 / free for non-commercial research; "
        "bundestag DL-DE-BY-2.0; house_of_commons Open Parliament "
        "Licence; euro_court_cases CC-BY-NC-SA 4.0; student_essays "
        "CC-BY-NC-SA 4.0; gutenberg CC0. There is no `license:` tag in "
        "the HF API record — the card text is the only licence source. "
        "Restrictions that govern TextForensics use: euro_court_cases "
        "and student_essays are CC-BY-NC-SA 4.0 (non-commercial, "
        "share-alike) and blog_authorship_corpus is free for "
        "non-commercial research only. Use is non-commercial research "
        "evaluation, local cache only, no redistribution, no commercial "
        "use. The card says 'seven domains' in one place, but the "
        "licence table and the viewer show 8 — trust 8.",
        licence_status=LICENCE_VERIFIED,
        configs=("default",),
        splits=(
            ("default", "train"),
            ("default", "validation"),
            ("default", "test"),
        ),
        notes="Mixed-origin slice (label 2 = fusion). 474,904 rows "
        "verified from datasets-server /size 2026-11-07 (train 332,224 "
        "/ test 95,132 / validation 47,548; single config `default`, "
        "9 columns, partial:false). `date` formats are inconsistent "
        "across rows (e.g. `2025`, `-`, `01,July,2004`, "
        "`2022-09-23T00:00:00`, `2007-2015`) — never parse as a date; "
        "the mapper keeps the raw string. `source` mixes UUIDs, Kaggle "
        "URLs and API URLs; `chunk` rows carry a `__[start:end]` suffix "
        "on the source id. `lang` has 3 values (en-EN, de-DE + one "
        "unidentified) — do not assume the third.",
        citation="Schaaf, Bönisch & Mehler, GhostWriter, LREC 2026.",
        domain_licences={
            "cnn_news": "Apache-2.0",
            "arxiv_papers": "arXiv.org non-exclusive licence to distribute",
            "blog_authorship_corpus": "CC0 / free for non-commercial research",
            "bundestag": "DL-DE-BY-2.0",
            "house_of_commons": "Open Parliament Licence",
            "euro_court_cases": "CC-BY-NC-SA 4.0",
            "student_essays": "CC-BY-NC-SA 4.0",
            "gutenberg": "CC0",
        },
    ),
    "raid": DatasetSpec(
        key="raid",
        name="RAID",
        hf_id="liamdugan/raid",
        paper="Dugan et al., ACL 2024, arXiv:2405.07940",
        source_url="https://huggingface.co/datasets/liamdugan/raid",
        licence="MIT",
        licence_note="Verified 2026-11-06 from the HF API record "
        "(license:mit), GitHub repo metadata (MIT) and the LICENSE file "
        "(Copyright (c) 2024- Liam Dugan). Caveat: the MIT text covers "
        "the distribution; the underlying human source texts (arXiv, NYT, "
        "Reddit, IMDb, Wikipedia, books, code, Czech/German news) carry "
        "their own upstream licences, which RAID does not address. "
        "Retain the copyright notice in copies. HF parquet conversion "
        "is partial (endpoint reports partial=true; viewer exposes the "
        "first 5 GB) — row counts are the loaded counts, not estimates.",
        licence_status=LICENCE_VERIFIED,
        configs=("raid", "raid_test"),
        splits=(("raid", "train"), ("raid", "extra"), ("raid_test", "test")),
        notes="Legacy-generator robustness slice (2022-23 generators). "
        "Test split is unlabelled in the CSV distribution; do NOT train "
        "on test. RAID-trained detectors evaluated on RAID test are "
        "in-distribution by construction — never present as OOD.",
        citation="Dugan et al., RAID: A Shared Benchmark for Robust "
        "Evaluation of Machine-Generated Text Detectors, ACL 2024.",
    ),
    "mage": DatasetSpec(
        key="mage",
        name="MAGE",
        hf_id="yaful/MAGE",
        paper="Li et al., arXiv:2305.13242",
        source_url="https://huggingface.co/datasets/yaful/MAGE",
        licence="Apache-2.0 (LICENSE file, repo metadata, HF tag); README "
        "badge asserts CC BY 4.0 — record both, attribute the authors",
        licence_note="Verified 2026-11-06: LICENSE file, GitHub metadata "
        "and HF API tag all say Apache-2.0, but the README licence badge "
        "reads CC BY 4.0. Both readings are permissive (no NC/ND/"
        "research-only restriction), so local evaluation is permitted "
        "under either; attribute the MAGE authors in any case. Upstream "
        "caveat as with RAID: human texts come from 10 source datasets "
        "whose own licences are not stated.",
        licence_status=LICENCE_VERIFIED,
        configs=("default",),
        splits=(
            ("default", "train"),
            ("default", "validation"),
            ("default", "test"),
        ),
        notes="Multi-generator OOD + paraphrase split. Native label "
        "polarity is INVERTED vs the TextForensics convention (0 = "
        "machine, 1 = human); the mapper flips it. Report per-testbed, "
        "never one pooled accuracy.",
        citation="Li et al., MAGE: Machine-generated Text Detection in the Wild, arXiv:2305.13242.",
    ),
    "beemo": DatasetSpec(
        key="beemo",
        name="Beemo",
        hf_id="toloka/beemo",
        paper="Artemova et al., arXiv:2411.04032, NAACL 2025",
        source_url="https://huggingface.co/datasets/toloka/beemo",
        licence="MIT (card) with field-level carve-outs: prompts + "
        "human_output from No Robots are CC-BY-NC-4.0; model_output and "
        "LLM-edited versions follow the underlying LLM licences",
        licence_note="Do NOT cite 'MIT' alone — the CC-BY-NC-4.0 carve-out "
        "on the human half is non-commercial and governs TextForensics "
        "use of human_output. Verified from the HF card (lines 522, "
        "672-680) in the Phase 3 research, 2026-11-06.",
        licence_status=LICENCE_VERIFIED,
        configs=("default",),
        splits=(("default", "train"),),
        notes="Expert-edited regime (the hard slice). One row holds "
        "several texts (human_output, model_output, human_edits, "
        "llama-3.1-70b_edits P1-P3, gpt-4o_edits P1-P3); the mapper emits "
        "one normalised row per text. 2,187 rows on HF, ~19.6k text "
        "variants in total. No train/test split — single benchmark set. "
        "Evaluate expert-edited vs LLM-edited separately; do not pool.",
        citation="Artemova et al., Beemo: Benchmark for Expert-Edited "
        "Machine-Generated Text, NAACL 2025.",
    ),
    "mixset": DatasetSpec(
        key="mixset",
        name="MixSet",
        hf_id="ONE-Lab/MixSet",
        paper="Zhang et al., NAACL 2024 Findings, arXiv:2401.05952",
        source_url="https://huggingface.co/datasets/ONE-Lab/MixSet",
        licence=None,
        licence_note="NO LICENCE FOUND anywhere checked 2026-11-06 (HF "
        "card: empty yaml metadata, no licence field; GitHub repo: no "
        "licence field, no LICENSE file; READMEs: no statement; paper is "
        "CC BY 4.0 on arXiv — that covers the paper, NOT the dataset). "
        "The authors invite evaluation use, but that is not a licence. "
        "DO NOT FETCH until clarified: contact the authors for a licence "
        "statement, or proceed only on an explicit 'evaluation use only, "
        "no redistribution, no derived artefacts' decision. The loader "
        "is code-complete and tested with mocks; live rows and run "
        "artifacts are deferred.",
        licence_status=LICENCE_UNRESOLVED,
        configs=("default",),
        splits=(("default", "train"), ("default", "test")),
        notes="Mixed-origin spine for U4 (later). AI-revised human text "
        "+ human-revised machine text; 5 operations (polish token / "
        "sentence, rewrite, adapt, humanize). Report by operation / "
        "category, never one pooled accuracy.",
        citation="Zhang et al., MixSet: A Large-Scale Dataset for "
        "Detecting Mixed Human and AI-Generated Text, NAACL 2024.",
    ),
    "opai_bench": DatasetSpec(
        key="opai_bench",
        name="OpAI-Bench",
        hf_id="OpAI-Bench1/OpAI-Bench",
        paper="Bsharat et al., arXiv:2606.06481",
        source_url="https://huggingface.co/datasets/OpAI-Bench1/OpAI-Bench",
        licence="Apache-2.0",
        licence_note="Verified 2026-11-06; the known conflict is resolved "
        "in favour of Apache-2.0: HF card 'Licensing and Reuse' section "
        "quotes Apache-2.0, HF tag is apache-2.0, README badge is "
        "Apache-2.0, and the LICENSE file is an abbreviated Apache-2.0 "
        "(37 lines — hence GitHub's 'Other (NOASSERTION)' detection "
        "artefact, which is not a competing licence). The LICENSE file "
        "closes with 'Copyright 2026 Anonymous' (anonymisation "
        "placeholder). Card notes the text is not redacted (may contain "
        "public names, emails, URLs) and the intended use is research / "
        "evaluation of AI-text detection.",
        licence_status=LICENCE_VERIFIED,
        configs=("default", "ablations"),
        splits=(
            ("default", "train"),
            ("default", "dev"),
            ("default", "test"),
            ("ablations", "train"),
            ("ablations", "dev"),
            ("ablations", "test"),
        ),
        notes="Progressive-edit spine for U4 (later). 9 versions v0-v8 "
        "per document, cumulative editing, AI sentence coverage "
        "0/15/25/40/50/60/75/90/100%. Non-monotonic detection: "
        "intermediate mixed versions (esp. v4, 50% + compression) are "
        "harder than either pure endpoint. Evaluate per-version / per-op, "
        "never only endpoints. Qwen3-8B is the held-out generator.",
        citation="Bsharat et al., OpAI-Bench: A Benchmark for Detecting "
        "Progressively AI-Edited Text, arXiv:2606.06481.",
    ),
    "detectrl": DatasetSpec(
        key="detectrl",
        name="DetectRL",
        hf_id="NLP2CT/DetectRL",
        paper="Wu et al., NeurIPS 2024 D&B, arXiv:2410.23746 v3",
        source_url="https://github.com/NLP2CT/DetectRL",
        licence=None,
        licence_note="NO LICENCE FOUND anywhere checked 2026-11-07. "
        'GitHub API record for NLP2CT/DetectRL: "license":null; the '
        'parent fork junchaoIU/DetectRL is also "license":null. No '
        "LICENSE file (404) and no licence statement in the README. "
        "The FAU Erlangen reprocessed version "
        "(github.com/philipp-ding/"
        "Contamination-in-Generated-Text-Detection-Benchmarks, "
        'cleaned_DetectRL_files/) is ALSO "license":null with no '
        "LICENSE file — the same gate applies to it. No Hugging Face "
        "dataset exists for DetectRL. DO NOT FETCH until unblocked: "
        "what would unblock it is a dataset licence statement from "
        "the authors. The loader is code-complete and tested with "
        "mocks; live rows and run artifacts are deferred.",
        licence_status=LICENCE_UNRESOLVED,
        configs=(),
        splits=(),
        notes="Licence-blocked (MixSet precedent). Verified route, for "
        "the record — DO NOT clone for data: `git clone "
        "https://github.com/NLP2CT/DetectRL.git` (271,708 KB). Human "
        "data in Benchmark/Original_Dataset/ (4 x 2,800 JSONs: arxiv, "
        "writing_prompt, xsum, yelp_review; 11,200 human texts). "
        "Generated data in Benchmark/Benchmark_Data/ (11 subdirs: "
        "Direct_Prompt, Multi_Domain, Multi_LLM, Paraphrase_Attacks "
        "(+_Human), Perturbation_Attacks (+_Human), Prompt_Attacks, "
        "Data_Mixing (+_Human), Varying_Length). Task splits in "
        "Benchmark/Tasks/ (Task1-4; Task1 == Task2 content) — loader "
        "splits are NOT mapped until a live row is inspected, so "
        "configs/splits are empty here. Paper count 235,200 (100,800 "
        "human + 134,400 LLM-generated) is a PAPER figure only; "
        "in-repo file row counts NOT verified. Labels are implicit in "
        "file/directory (task x domain x LLM x attack); field names "
        "inside the benchmark JSONs NOT verified. Traps: "
        "load_dataset.sh only runs the four get_*_data.py samplers "
        "against LOCAL *_all.json files not in the repo — it downloads "
        "nothing; data_generation.sh regenerates via paid LLM APIs "
        "(cannot re-run without keys); benchmark_construction.sh does "
        "NOT exist at the repo root (the README is stale) — the "
        "construction script is Data_Generation/benchmark "
        "construction.py (space in the filename). FAU Erlangen "
        "reprocessing found simple patterns in 98.5% of Claude-LLM "
        "data (e.g. 'Sure! Here is the academic article abstract:', "
        "refusals) — detectors trained on the original learn "
        "shortcuts; do not use it as a clean training set without the "
        "cleansing, and record the shortcut warning in any future "
        "record's limits. No Hugging Face dataset exists, so hf_id "
        "holds the GitHub repo slug — never pass it to the "
        "datasets-server client. Generators: GPT-3.5-turbo, "
        "PaLM-2-bison, Claude-instant, Llama-2-70b. Attacks: prompt, "
        "paraphrase, perturbation, data-mixing.",
        citation="Wu et al., DetectRL, NeurIPS 2024 D&B, arXiv:2410.23746.",
    ),
    "m4": DatasetSpec(
        key="m4",
        name="M4",
        hf_id="mbzuai-nlp/M4",
        paper="Wang et al., arXiv:2305.14902, EACL 2024 Best Resource Paper",
        source_url="https://github.com/mbzuai-nlp/M4",
        licence=None,
        licence_note="NO SINGLE DATASET LICENCE exists anywhere checked "
        "2026-11-07. GitHub API record for mbzuai-nlp/M4: "
        '"license":null; no LICENSE file; no licence statement in the '
        "README. Per-source licences exist in paper Table 1 (arXiv "
        "HTML 2305.14902, verified): Wikipedia CC BY-SA-3.0; Reddit "
        "ELI5 'Huggingface' (not a licence); WikiHow CC-BY-NC-SA; "
        "PeerRead Apache; arXiv abstract CC0; Arabic-Wikipedia CC "
        "BY-SA-3.0; True & Fake News MIT; Baike/Web QA MIT; "
        "id_newspapers_2018 CC BY-NC-SA-4.0; RuATD Apache 2.0; "
        "Urdu-news CC BY 4.0. Two sources are NC (WikiHow, "
        "id_newspapers_2018). Per-source licences do not add up to a "
        "dataset licence — the gate stays closed. DO NOT FETCH until "
        "unblocked: what would unblock it is a dataset licence "
        "statement from the authors. The loader is code-complete and "
        "tested with mocks; live rows and run artifacts are deferred.",
        licence_status=LICENCE_UNRESOLVED,
        configs=(),
        splits=(),
        notes="Licence-blocked (MixSet precedent). Verified route, for "
        "the record — DO NOT clone for data: `git clone "
        "https://github.com/mbzuai-nlp/M4.git`; `data/` holds 38 "
        "`.jsonl` files + README.md (1,005,995,293 B total, ~1.006 "
        "GB). Naming `<DOMAIN>_<MODEL>.jsonl` (e.g. "
        "`arxiv_chatGPT.jsonl`; `russian_chatGPT.jsonl` 74,318,020 B "
        "largest). NO `*_human.jsonl` files exist despite "
        "`data/README.md` documenting that naming scheme — human text "
        "is embedded per-row. Counts — CONTRADICTION, stated not "
        "resolved, quote none as the size: paper Table 1 total "
        "147,895 (35,798 human + 112,097 machine); secondary figures "
        "122K and 245K BOTH contradict the paper's own table. "
        "Per-file row counts NOT verified. The paper lists 14,344 "
        "GPT-4 generations but NO `*gpt4*` file exists in `data/`; "
        "`flant5` only for arXiv/Reddit, `llama` only for PeerRead. "
        "Loader facts (from `data/README.md`, verified): JSONL fields "
        "`prompt, human_text, machine_text, model, source, "
        "source_ID`; each row is a (human, machine) pair — the label "
        "is implicit, no numeric label column. No train/test split "
        "defined — loader splits are NOT mapped until a live row is "
        "inspected, so configs/splits are empty here. Authors' "
        "metrics are accuracy/precision/recall/F1. Known limitation "
        "for any future fetcher: the shared urllib downloader "
        "(`download_large_file`) could not sustain an ~879 MB "
        "DetectRL-X download (timed out after 6 attempts, never past "
        "headers) while curl fetched the full file in ~5 min with the "
        "SHA-256 verified; fixed 2026-11-07 — `download_large_file` "
        "now has split connect/stall timeouts, jittered back-off and "
        "a curl subprocess fallback, so a future ~1.006 GB M4 fetch "
        "uses the fixed downloader; fetchers are still deferred "
        "pending licence resolution. No Hugging Face "
        "dataset exists, so hf_id holds the GitHub repo slug — never "
        "pass it to the datasets-server client. Domains: Wikipedia, "
        "WikiHow, Reddit ELI5, arXiv, PeerRead, Chinese Baike/Web QA, "
        "Russian RuATD, Arabic Wikipedia, Urdu/Indonesian/Bulgarian "
        "news; 7 languages (AR, BG, ZH, EN, ID, RU, UR). Generators: "
        "davinci-003, ChatGPT, GPT-4, Cohere, Dolly-v2, BLOOMz 176B.",
        citation="Wang et al., M4, arXiv:2305.14902.",
    ),
    "m4gt_bench": DatasetSpec(
        key="m4gt_bench",
        name="M4GT-Bench",
        hf_id="mbzuai-nlp/M4GT-Bench",
        paper="Wang et al., arXiv:2402.11175 v2",
        source_url="https://github.com/mbzuai-nlp/M4GT-Bench",
        licence=None,
        licence_note="NO SINGLE DATASET LICENCE exists anywhere checked "
        "2026-11-07. GitHub API record for mbzuai-nlp/M4GT-Bench: "
        '"license":null; no LICENSE file; no licence statement in the '
        "README. Per-source licences exist in paper Table 2 (arXiv "
        "HTML 2402.11175v2, verified): Arabic-Wikipedia CC BY-SA-3.0; "
        "True & Fake News (Bulgarian) MIT; Baike/Web QA (Chinese) "
        "MIT; id_newspapers_2018 CC BY-NC-SA-4.0; RuATD Apache 2.0; "
        "Urdu-news CC BY 4.0; News (Arabic) Apache 2.0; CHANGE-it "
        "News (Italian) CC BY-NC-SA 4.0; News (German) CC BY-NC-SA-"
        "4.0; Wikipedia (German) CC BY-SA-3.0. Three sources are NC "
        "(id_newspapers_2018, CHANGE-it News, News (German)). "
        "Per-source licences do not add up to a dataset licence — the "
        "gate stays closed. DO NOT FETCH until unblocked: what would "
        "unblock it is a dataset licence statement from the authors. "
        "The loader is code-complete and tested with mocks; live rows "
        "and run artifacts are deferred.",
        licence_status=LICENCE_UNRESOLVED,
        configs=(),
        splits=(),
        notes="Licence-blocked (MixSet precedent). Verified route, for "
        "the record — DO NOT download: Google Drive folder "
        "https://drive.google.com/drive/folders/"
        "1xC-n5hHiXmaCLmA0q3p8Cbyd7Dk0dpDE?usp=sharing (verbatim from "
        "the README, public link): SubtaskA_multilingual.jsonl 693.4 "
        "MB; SubtaskA.jsonl 480.5 MB; SubtaskB.jsonl 332.3 MB; "
        "subtaskC_test.jsonl 73.8 MB; subtaskC_train_dev.jsonl 138.4 "
        "MB (approx. 1.72 GB total). Drive offers no row counts — "
        "Drive row counts NOT verifiable without downloading. Counts "
        "are SCOPE-QUALIFIED figures from the paper's own tables, "
        "quote only with scope: Task 1 English 138,465 (65,177 human "
        "+ 73,288 machine); + multilingual 65,100 + GPT-4 14,344 = "
        "217,909 (approx. 217k); Task 3 adds 31,893; all-in with "
        "OUTFOX approx. 281k. Tasks: (1) binary mono/multilingual "
        "detection; (2) multi-way generator identification; (3) mixed "
        "human-machine change-point detection (human share 0-50% of "
        "words) — the U4 spine. Authors' metrics: Tasks 1/2 "
        "F1/precision/recall per generator + F1-macro and accuracy; "
        "Task 3 MAE on the boundary index. Report per-task, never "
        "pooled. Field names inside the JSONL files NOT verified — no "
        "live row has been inspected. Loader splits are NOT mapped "
        "until a live row is inspected, so configs/splits are empty "
        "here. Known limitation for any future fetcher: the shared "
        "urllib downloader (`download_large_file`, the candidate for "
        "a future Drive fetch) could not sustain an ~879 MB "
        "DetectRL-X download (timed out after 6 attempts, never past "
        "headers) while curl fetched the full file in ~5 min with the "
        "SHA-256 verified; fixed 2026-11-07 — `download_large_file` "
        "now has split connect/stall timeouts, jittered back-off and "
        "a curl subprocess fallback, so a future ~1.72 GB Drive fetch "
        "uses the fixed downloader; fetchers are still deferred "
        "pending licence resolution. No Hugging Face "
        "dataset exists, so hf_id holds the GitHub repo slug — never "
        "pass it to the datasets-server client. Scope: 9 languages, 6 "
        "domains, 9 generators (incl. GPT-4, LLaMA-2).",
        citation="Wang et al., M4GT-Bench, arXiv:2402.11175.",
    ),
}


def get_spec(key: str) -> DatasetSpec:
    """Return the spec for a dataset key, or raise KeyError."""
    return SPECS[key]


def require_licence(spec: DatasetSpec) -> None:
    """Enforce the pre-download licence gate.

    Raises:
        DatasetLicenceError: If the dataset's licence is unresolved.
    """
    if spec.licence_status != LICENCE_VERIFIED or not spec.licence:
        raise DatasetLicenceError(
            f"Licence for {spec.name} ({spec.hf_id}) is unresolved: "
            f"{spec.licence_note} Resolve it and record it in the spec "
            "before any download."
        )


def default_cache_dir() -> Path:
    """Local cache directory for downloaded dataset samples.

    XDG cache by default; override with TEXTFORENSICS_DATASETS_DIR.
    The cache lives outside the repo so dataset text is never committed.
    """
    override = os.environ.get("TEXTFORENSICS_DATASETS_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "textforensics" / "datasets"


def cache_path(key: str, config: str, split: str, *, cache_dir: Path | None = None) -> Path:
    """JSONL cache file for one fetched sample."""
    root = cache_dir or default_cache_dir()
    return root / key / config / f"{split}.jsonl"


def manifest_path(key: str, config: str, split: str, *, cache_dir: Path | None = None) -> Path:
    """Manifest file next to a cache file (source, date, counts, hash)."""
    return cache_path(key, config, split, cache_dir=cache_dir).with_suffix(".manifest.json")


class DatasetsServerClient:
    """Minimal client for the Hugging Face datasets-server API.

    Uses only the standard library. The API serves parquet-converted
    datasets: ``/splits`` and ``/size`` for metadata, ``/rows`` for
    paginated row fetches (at most 100 rows per request). No state is
    kept between calls, so the client is safe to construct per use.
    ``base_url`` must be https (http on loopback only, for local
    fixtures); anything else raises at construction — the same scheme
    policy the downloader enforces (see
    :func:`_require_https_or_loopback_http`).
    """

    def __init__(
        self,
        base_url: str = DATASETS_SERVER_BASE,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        retries: int = DEFAULT_RETRIES,
        user_agent: str = "TextForensics/0.2.0 (research evaluation)",
    ) -> None:
        _require_https_or_loopback_http(base_url)
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.retries = retries
        self.user_agent = user_agent

    def _get_json(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                # B310 reviewed: base_url validated in __init__ by
                # _require_https_or_loopback_http (https, or http on
                # loopback only); path is a fixed literal, params urlencoded.
                # Redirects go through _guarded_urlopen (no downgrade).
                with _guarded_urlopen(request, timeout=self.timeout_s) as response:
                    return json.loads(response.read().decode("utf-8"))
            except (
                urllib.error.URLError,
                TimeoutError,
                http.client.HTTPException,
                ConnectionError,
                json.JSONDecodeError,
            ) as exc:
                # RemoteDisconnected / BadStatusLine escape urlopen raw
                # (they are NOT wrapped in URLError); without catching
                # them a single transient proxy reset kills a 600-row
                # strided fetch. Retried with back-off like the rest.
                last_error = exc
                if attempt < self.retries:
                    time.sleep(2**attempt)
        raise DatasetFetchError(f"GET {url} failed after {self.retries + 1} attempts: {last_error}")

    def splits(self, hf_id: str) -> list[dict[str, Any]]:
        """Return the (config, split) pairs the server knows for a dataset."""
        payload = self._get_json("/splits", {"dataset": hf_id})
        return list(payload.get("splits", []))

    def size(self, hf_id: str) -> dict[str, Any]:
        """Return the server's row/byte counts for a dataset."""
        payload = self._get_json("/size", {"dataset": hf_id})
        return dict(payload.get("size", {}))

    def rows(
        self,
        hf_id: str,
        config: str,
        split: str,
        *,
        offset: int = 0,
        length: int = ROWS_PER_REQUEST,
    ) -> list[dict[str, Any]]:
        """Fetch one page of rows (at most 100) for a config/split."""
        if length > ROWS_PER_REQUEST:
            raise ValueError(f"datasets-server serves at most {ROWS_PER_REQUEST} rows per request")
        payload = self._get_json(
            "/rows",
            {
                "dataset": hf_id,
                "config": config,
                "split": split,
                "offset": str(offset),
                "length": str(length),
            },
        )
        return [row["row"] for row in payload.get("rows", [])]


def fetch_sample(
    spec: DatasetSpec,
    config: str,
    split: str,
    n: int,
    *,
    client: DatasetsServerClient | None = None,
    cache_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Fetch the first ``n`` raw rows of a config/split, paginated.

    Enforces the licence gate. Rows are returned in server row-index
    order (deterministic); no randomness is involved. Raises
    :class:`DatasetFetchError` if the server returns fewer rows than
    requested without explanation (a short page is treated as an error,
    never silently padded).
    """
    require_licence(spec)
    if n <= 0:
        raise ValueError("n must be positive")
    client = client or DatasetsServerClient()
    rows: list[dict[str, Any]] = []
    offset = 0
    while len(rows) < n:
        before = len(rows)
        page = client.rows(
            spec.hf_id, config, split, offset=offset, length=min(ROWS_PER_REQUEST, n - len(rows))
        )
        if not page:
            raise DatasetFetchError(
                f"{spec.hf_id} {config}/{split}: server returned {len(rows)} rows, "
                f"fewer than the requested {n}"
            )
        rows.extend(page)
        offset += len(page)
        if len(rows) == before:
            # A page that adds no rows would loop forever; refuse instead.
            raise DatasetFetchError(
                f"{spec.hf_id} {config}/{split}: server page at offset "
                f"{offset - len(page)} added no rows"
            )
    return rows[:n]


def sample_offsets(total: int, n: int) -> list[int]:
    """Evenly spaced row offsets covering ``0 .. total - 1``.

    Deterministic (no randomness): offset ``i`` is ``i * total // n``.
    Used when a split is ordered by testbed or label, so first-*n*
    sampling would return one side only (MAGE train is blocked by
    ``src``; see the MAGE mapper). ``n`` must not exceed ``total``.
    """
    if total <= 0:
        raise ValueError("total must be positive")
    if n <= 0:
        raise ValueError("n must be positive")
    if n > total:
        raise ValueError(f"n ({n}) exceeds split size ({total})")
    return [i * total // n for i in range(n)]


def fetch_strided_sample(
    spec: DatasetSpec,
    config: str,
    split: str,
    n: int,
    total: int,
    *,
    client: DatasetsServerClient | None = None,
) -> list[dict[str, Any]]:
    """Fetch ``n`` rows evenly spaced across a config/split.

    Same licence gate and determinism guarantees as
    :func:`fetch_sample`; each offset is one ``/rows`` request of
    length 1, so this costs ``n`` requests. This is the sampling
    method for every wave-1 measurement: all five splits are ordered
    by testbed/model (RAID first-200 rows are all human), so first-*n*
    sampling would return one side only.
    """
    require_licence(spec)
    client = client or DatasetsServerClient()
    rows: list[dict[str, Any]] = []
    for offset in sample_offsets(total, n):
        page = client.rows(spec.hf_id, config, split, offset=offset, length=1)
        if not page:
            raise DatasetFetchError(
                f"{spec.hf_id} {config}/{split}: server returned no row at offset {offset}"
            )
        rows.extend(page)
    return rows


def _require_text(row: dict[str, Any], field: str, key: str) -> str:
    text = row.get(field)
    if not isinstance(text, str) or not text.strip():
        raise DatasetFetchError(f"{key}: row has no usable text in field {field!r}")
    return text


def _meta(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {f: row[f] for f in fields if row.get(f) is not None}


def _map_raid(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """RAID: ``generation`` is the text; ``model == 'human'`` marks humans.

    Verified live 2026-11-06: train rows carry 11 columns; the
    ``raid_test`` config carries only ``id`` + ``generation`` and is
    unlabelled, so those rows normalise with ``label=None``.
    """
    text = _require_text(row, "generation", "raid")
    model = row.get("model")
    if model is None:
        label: int | None = None
    elif not isinstance(model, str):
        raise DatasetFetchError(f"raid: unexpected model value {model!r}")
    else:
        label = 0 if model == "human" else 1
    return [
        NormalizedRow(
            text=text,
            label=label,
            dataset="raid",
            config=config,
            split=split,
            source_id=str(row.get("id", "")),
            regime="raid",
            meta=_meta(
                row,
                (
                    "domain",
                    "model",
                    "attack",
                    "decoding",
                    "repetition_penalty",
                    "source_id",
                    "adv_source_id",
                ),
            ),
        )
    ]


def _map_mage(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """MAGE: native polarity is INVERTED (0 = machine, 1 = human).

    The flip is verified from the data itself (2026-11-06): every
    probed row with ``src`` ending ``_human`` has label 1, every row
    with ``_machine_`` in ``src`` has label 0. The mapper cross-checks
    the two signals on every row and refuses on a mismatch — a silent
    polarity error would invert every downstream metric. MAGE has no
    row id, so ``source_id`` is the first 16 hex of the text SHA-256.
    """
    text = _require_text(row, "text", "mage")
    native = row.get("label")
    if native not in (0, 1):
        raise DatasetFetchError(f"mage: unexpected native label {native!r}")
    src = row.get("src")
    if not isinstance(src, str):
        raise DatasetFetchError(f"mage: row has no src field: {sorted(row)}")
    if src.endswith("_human") and native != 1:
        raise DatasetFetchError(f"mage: src {src!r} is human but native label is {native}")
    if "_machine_" in src and native != 0:
        raise DatasetFetchError(f"mage: src {src!r} is machine but native label is {native}")
    return [
        NormalizedRow(
            text=text,
            label=1 - int(native),
            dataset="mage",
            config=config,
            split=split,
            source_id=f"mage:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}",
            regime="mage",
            meta={"src": src, "native_label": int(native)},
        )
    ]


def _parse_beemo_edits(value: Any, field: str) -> list[dict[str, str]]:
    """Beemo edit columns arrive as a string holding a Python literal.

    The datasets-server stringifies the sequence-of-struct column, so
    ``llama-3.1-70b_edits`` is ``"[{'P1': '...'}, {'P2': '...'},
    {'P3': '...'}]"`` — single quotes, so ``json.loads`` fails and
    :func:`ast.literal_eval` is the safe parser. Anything else is a
    schema change and fails closed.
    """
    if not isinstance(value, str):
        raise DatasetFetchError(f"beemo: {field} is {type(value).__name__}, expected str")
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, SyntaxError) as exc:
        raise DatasetFetchError(f"beemo: {field} did not parse as a Python literal") from exc
    if not isinstance(parsed, list) or not parsed:
        raise DatasetFetchError(
            f"beemo: {field} parsed to {type(parsed).__name__}, expected non-empty list"
        )
    edits: list[dict[str, str]] = []
    for item in parsed:
        if not isinstance(item, dict) or not item:
            raise DatasetFetchError(f"beemo: {field} contains a non-dict item: {item!r:.80}")
        for level, text in item.items():
            if not isinstance(level, str) or not isinstance(text, str) or not text.strip():
                raise DatasetFetchError(f"beemo: {field} has an unusable {level!r} edit")
            edits.append({level: text})
    return edits


def _map_beemo(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """Beemo: one dataset row expands to ~10 normalised rows.

    ``human_output`` (label 0) and ``model_output`` (label 1) are the
    plain slice; ``human_edits`` is an expert human rewrite of the
    human text (label 0 — still human-authored); each P1/P2/P3 edit by
    Llama-3.1-70B and GPT-4o is a machine-edited text (label 1). The
    ``kind`` in ``meta`` (and in ``source_id``) keeps the slices
    separable — measurements must report per-kind, never one pooled
    number, or the hard edited slice disappears into the average.
    """
    base_id = row.get("id")
    if base_id is None:
        raise DatasetFetchError("beemo: row has no id")
    category = row.get("category")
    prompt_id = row.get("prompt_id")
    model = row.get("model")
    out: list[NormalizedRow] = []

    def _row(text: str, label: int, kind: str, **extra: Any) -> NormalizedRow:
        meta: dict[str, Any] = {"kind": kind}
        if category is not None:
            meta["category"] = category
        if prompt_id is not None:
            meta["prompt_id"] = prompt_id
        if model is not None:
            meta["generator"] = model
        meta.update(extra)
        return NormalizedRow(
            text=text,
            label=label,
            dataset="beemo",
            config=config,
            split=split,
            source_id=f"beemo-{base_id}:{kind}",
            regime="beemo",
            meta=meta,
        )

    out.append(_row(_require_text(row, "human_output", "beemo"), 0, "human"))
    out.append(_row(_require_text(row, "model_output", "beemo"), 1, "model_output"))
    human_edits = row.get("human_edits")
    if isinstance(human_edits, str) and human_edits.strip():
        out.append(_row(human_edits, 0, "human_edits"))
    for column, editor in (
        ("llama-3.1-70b_edits", "llama-3.1-70b"),
        ("gpt-4o_edits", "gpt-4o"),
    ):
        for item in _parse_beemo_edits(row.get(column), column):
            for level, text in item.items():
                out.append(_row(text, 1, f"{editor}_{level}", editor=editor, prompt_level=level))
    return out


def _parse_json_list_field(row: dict[str, Any], field: str, dataset: str) -> list[Any]:
    """Parse a datasets-server list column (JSON string or plain list).

    The datasets-server serialises list columns as JSON-encoded
    strings; a caller may also pass an already-decoded list (tests,
    cached rows). Anything else — missing, a scalar, malformed JSON,
    a JSON non-list — is a malformed row and fails closed.
    """
    value = row.get(field)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DatasetFetchError(f"{dataset}: field {field!r} is not valid JSON: {exc}") from exc
    elif isinstance(value, list):
        parsed = value
    else:
        raise DatasetFetchError(f"{dataset}: field {field!r} missing or not a list: {value!r}")
    if not isinstance(parsed, list):
        raise DatasetFetchError(f"{dataset}: field {field!r} is not a list: {parsed!r}")
    return parsed


def _map_opai_bench(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """OpAI-Bench: binary label only at the ends of the edit ladder.

    ``v0`` rows have ``ai_sentence_ratio == 0.0`` (pure human, label 0);
    a row with ratio 1.0 would be fully machine (label 1). Partial
    rows (0 < ratio < 1) get ``label=None`` — assigning a binary label
    to a mixed-origin document would be a lie, and these rows are the
    U4 spine, reported by ratio, not pooled. ``id`` is the document
    title, not an identifier; ``record_id`` is the per-version key.

    Segment-level ground truth (U4) is preserved in ``meta``:
    ``sentences`` (list of str), ``sentence_labels`` (list of 0/1,
    same length), ``ai_spans_char`` (list of [start, end] char offsets
    into the text). Verified live 2026-11-07 on 30 rows across v0–v8
    and on the full 500-row strided sample: the fields are
    JSON-encoded strings on the server, labels are 0/1 with
    ``len(labels) == len(sentences)``, and spans lie inside the text.
    Every one of those invariants is checked here and a violation
    fails closed. The ``default`` config is the verified schema, so
    it requires the fields; the ``ablations`` config is unverified
    for them, so it preserves them when present and never assumes
    them.

    Deliberately NOT checked: ``mean(sentence_labels)`` against
    ``ai_sentence_ratio``. That cross-check was in the first version
    of this mapper and the full 500-row sample falsified it as a
    dataset invariant: 6/500 rows disagree (max |diff| 0.032, all
    intermediate versions, no v0/v8 endpoint row affected) because
    the ratio and the labels were computed on slightly different
    sentence segmentations (e.g. ratio 12/20 vs labels 12/19). The
    labels are the segment ground truth and the ratio is the
    document-level summary; each is used for its own purpose, and
    the segment run measures and reports the agreement instead of
    asserting it.
    """
    text = _require_text(row, "text", "opai_bench")
    ratio = row.get("ai_sentence_ratio")
    if not isinstance(ratio, (int, float)) or isinstance(ratio, bool):
        raise DatasetFetchError(f"opai_bench: bad ai_sentence_ratio {ratio!r}")
    ratio = float(ratio)
    if ratio == 0.0:
        label: int | None = 0
    elif ratio == 1.0:
        label = 1
    elif 0.0 < ratio < 1.0:
        label = None
    else:
        raise DatasetFetchError(f"opai_bench: ai_sentence_ratio out of range: {ratio}")
    meta = _meta(
        row,
        (
            "version",
            "version_index",
            "edit_operation",
            "generator",
            "domain",
            "document_hash_id",
            "ai_sentence_ratio",
            "ai_token_ratio",
            "ai_char_ratio",
            "boundary_pattern",
            "subset",
            "ablation_type",
        ),
    )
    segment_fields = ("sentences", "sentence_labels", "ai_spans_char")
    if config == "default":
        sentences = _parse_json_list_field(row, "sentences", "opai_bench")
        labels = _parse_json_list_field(row, "sentence_labels", "opai_bench")
        spans = _parse_json_list_field(row, "ai_spans_char", "opai_bench")
        if not sentences or not all(isinstance(s, str) for s in sentences):
            raise DatasetFetchError("opai_bench: sentences must be a non-empty list of str")
        if len(labels) != len(sentences) or any(
            isinstance(x, bool) or x not in (0, 1) for x in labels
        ):
            raise DatasetFetchError(
                "opai_bench: sentence_labels must be 0/1 with len == len(sentences)"
            )
        if any(
            not (
                isinstance(p, list)
                and len(p) == 2
                and all(isinstance(v, int) and not isinstance(v, bool) for v in p)
                and 0 <= p[0] <= p[1] <= len(text)
            )
            for p in spans
        ):
            raise DatasetFetchError(
                "opai_bench: ai_spans_char must be [start, end] pairs inside the text"
            )
        meta["sentences"] = sentences
        meta["sentence_labels"] = labels
        meta["ai_spans_char"] = spans
    else:
        for field in segment_fields:
            if row.get(field) is not None:
                meta[field] = _parse_json_list_field(row, field, "opai_bench")
    return [
        NormalizedRow(
            text=text,
            label=label,
            dataset="opai_bench",
            config=config,
            split=split,
            source_id=str(row.get("record_id", "")),
            regime="opai_bench",
            meta=meta,
        )
    ]


def _map_ghostwriter(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """GhostWriter: per-domain licences, ternary label, fusion is mixed-origin.

    Verified from the viewer 2026-11-07: ``label`` 0 = human, 1 = ai,
    2 = fusion. Fusion rows get ``label=None`` — a binary label on a
    mixed-origin document would be a lie (same rule as the OpAI-Bench
    partials); they take regime ``mixed-origin`` and are the U4 spine.
    Human and ai rows are regime ``raw``. The mapper refuses any row
    whose ``domain`` has no recorded licence in the spec (fail closed)
    and any unexpected label value. ``date`` is kept as the raw string
    — formats are inconsistent across rows and must never be parsed.
    ``source_id`` is the row ``id`` (UUID string).
    """
    text = _require_text(row, "text", "ghostwriter")
    domain = row.get("domain")
    licences = SPECS["ghostwriter"].domain_licences or {}
    if not isinstance(domain, str) or domain not in licences:
        raise DatasetFetchError(
            f"ghostwriter: domain {domain!r} has no recorded licence — refusing to map"
        )
    label = row.get("label")
    if isinstance(label, bool) or label not in (0, 1, 2):
        raise DatasetFetchError(f"ghostwriter: unexpected label {label!r}")
    row_id = row.get("id")
    if not isinstance(row_id, str) or not row_id.strip():
        raise DatasetFetchError("ghostwriter: row has no id")
    if label == 2:
        mapped_label: int | None = None
        regime = REGIME_MIXED_ORIGIN
    else:
        mapped_label = int(label)
        regime = REGIME_RAW
    return [
        NormalizedRow(
            text=text,
            label=mapped_label,
            dataset="ghostwriter",
            config=config,
            split=split,
            source_id=row_id,
            regime=regime,
            meta=_meta(row, ("domain", "lang", "agent", "type", "date", "source")),
        )
    ]


def _map_detectrl_x(
    row: dict[str, Any],
    config: str,
    split: str,
    *,
    row_index: int | None = None,
    file: str = DETECTRL_X_FILE,
) -> list[NormalizedRow]:
    """DetectRL-X: one normalised row per text field; no numeric label.

    Verified from the downloaded general file 2026-11-07: rows carry
    exactly ``human_written_text``, ``llm_generated_text``, ``lang``,
    ``model``, ``split``, ``domain`` — no id field, no
    ``perturbation_info`` column in this file. ``human_written_text``
    -> label 0, ``llm_generated_text`` -> label 1 (Binary file); a
    present ``llm_refined_text`` (Ternary files) -> label None, regime
    ``mixed-origin`` — human+LLM refined text never takes a binary
    label. Both Binary rows are regime ``raw``. ``source_id`` is file
    + row index, because no id field exists; the caller must supply
    ``row_index`` — a missing index fails closed rather than inventing
    an id. The row's own ``split`` field is cross-checked against the
    split being mapped. Unknown lang/model/domain values, missing text
    fields, or a row with neither text field all fail closed.
    """
    if row_index is None:
        raise DatasetFetchError("detectrl_x: row_index is required — the file has no id field")
    lang = row.get("lang")
    if lang not in DETECTRL_X_LANGS:
        raise DatasetFetchError(f"detectrl_x: unexpected lang {lang!r}")
    model = row.get("model")
    if model not in DETECTRL_X_MODELS:
        raise DatasetFetchError(f"detectrl_x: unexpected model {model!r}")
    domain = row.get("domain")
    if domain not in DETECTRL_X_DOMAINS:
        raise DatasetFetchError(f"detectrl_x: unexpected domain {domain!r}")
    row_split = row.get("split")
    if row_split != split:
        raise DatasetFetchError(f"detectrl_x: row split {row_split!r} != mapped split {split!r}")
    human_text = _require_text(row, "human_written_text", "detectrl_x")
    llm_text = _require_text(row, "llm_generated_text", "detectrl_x")
    meta: dict[str, Any] = {
        "lang": lang,
        "model": model,
        "split": split,
        "domain": domain,
        "file": file,
    }
    out = [
        NormalizedRow(
            text=human_text,
            label=0,
            dataset="detectrl_x",
            config=config,
            split=split,
            source_id=f"detectrl-x:{file}:{row_index}:human",
            regime=REGIME_RAW,
            meta=dict(meta),
        ),
        NormalizedRow(
            text=llm_text,
            label=1,
            dataset="detectrl_x",
            config=config,
            split=split,
            source_id=f"detectrl-x:{file}:{row_index}:llm",
            regime=REGIME_RAW,
            meta=dict(meta),
        ),
    ]
    if "llm_refined_text" in row:
        refined_text = _require_text(row, "llm_refined_text", "detectrl_x")
        out.append(
            NormalizedRow(
                text=refined_text,
                label=None,
                dataset="detectrl_x",
                config=config,
                split=split,
                source_id=f"detectrl-x:{file}:{row_index}:refined",
                regime=REGIME_MIXED_ORIGIN,
                meta=dict(meta),
            )
        )
    return out


def _map_detectrl(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """DetectRL: refused until the licence resolves and a live row is inspected.

    The licence is unresolved (see the spec's ``licence_note``), so no
    live row has ever been inspected; the field names inside the
    benchmark JSONs are UNVERIFIED and the labels are implicit in
    file/directory (task x domain x LLM x attack), so the mapper fails
    closed instead of guessing a schema. Revisit only after the
    licence is clarified AND a live row has been read. No fetcher is
    written in this task — the verified route is a git clone (see the
    spec notes); a future fetcher must clone NLP2CT/DetectRL and map
    the Benchmark/Original_Dataset + Benchmark/Benchmark_Data trees.
    """
    raise DatasetFetchError(
        "detectrl: licence unresolved AND no live row inspected "
        "(field names inside the benchmark JSONs unverified); "
        "refusing to map"
    )


def _map_m4(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """M4: refused until the licence resolves and a live row is inspected.

    The licence is unresolved (see the spec's ``licence_note``), so no
    live row has ever been inspected. The row schema IS documented
    (``data/README.md``: JSONL fields ``prompt, human_text,
    machine_text, model, source, source_ID``; each row is a (human,
    machine) pair with the label implicit and no numeric label
    column), but the mapper still fails closed: the schema has never
    been confirmed against a live row, and mapping a pair-per-row file
    without one would be guessing at the pairing. Revisit only after
    the licence is clarified AND a live row has been read. No fetcher
    is written in this task — the verified route is a git clone (see
    the spec notes); a future fetcher must clone mbzuai-nlp/M4 and
    map the 38 ``data/*.jsonl`` files; a future fetcher uses
    `download_large_file`, whose split timeouts and curl fallback
    were fixed 2026-11-07 (see the spec notes).
    """
    raise DatasetFetchError(
        "m4: licence unresolved AND no live row inspected "
        "(documented schema unconfirmed against data); refusing to map"
    )


def _map_m4gt_bench(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """M4GT-Bench: refused until the licence resolves and a live row is inspected.

    The licence is unresolved (see the spec's ``licence_note``), so no
    live row has ever been inspected; the field names inside the Drive
    JSONL files are UNVERIFIED and the three tasks (binary detection,
    multi-way generator identification, mixed human-machine
    change-point detection) each need their own mapping, so the mapper
    fails closed instead of guessing a schema. Revisit only after the
    licence is clarified AND a live row has been read. No fetcher is
    written in this task — the verified route is the public Google
    Drive folder (see the spec notes); a future fetcher must download
    the five Subtask files from Drive; a future fetcher uses
    `download_large_file`, whose split timeouts and curl fallback
    were fixed 2026-11-07 (see the spec notes).
    """
    raise DatasetFetchError(
        "m4gt_bench: licence unresolved AND no live row inspected "
        "(field names inside the Drive JSONL files unverified); "
        "refusing to map"
    )


def _map_mixset(row: dict[str, Any], config: str, split: str) -> list[NormalizedRow]:
    """MixSet: refused until the label polarity is verified from data.

    The loader is code-complete but the licence is unresolved (see
    ``phase3-datasets-licences.md``), so no live row has ever been
    inspected; the ``binary`` field's polarity is unverified and the
    mapper fails closed instead of guessing. Revisit only after the
    licence is clarified AND a live row has been read.
    """
    raise DatasetFetchError(
        "mixset: label polarity unverified — no live row inspected "
        "(licence unresolved); refusing to map"
    )


_MAPPERS: dict[str, Any] = {
    "raid": _map_raid,
    "mage": _map_mage,
    "beemo": _map_beemo,
    "mixset": _map_mixset,
    "opai_bench": _map_opai_bench,
    "ghostwriter": _map_ghostwriter,
    "detectrl_x": _map_detectrl_x,
    "detectrl": _map_detectrl,
    "m4": _map_m4,
    "m4gt_bench": _map_m4gt_bench,
}


def map_row(
    key: str,
    row: dict[str, Any],
    config: str,
    split: str,
    *,
    row_index: int | None = None,
) -> list[NormalizedRow]:
    """Normalise one raw server row to TextForensics rows.

    Returns a list because one Beemo record expands to ~10 rows and one
    DetectRL-X row expands to 2 (3 for Ternary). The licence gate is
    enforced here too: mapping is part of fetching, so an unresolved
    licence refuses before any row is normalised. ``row_index`` is the
    row's index in its source file; only DetectRL-X needs it (the file
    has no id field), and its mapper fails closed without it.
    """
    spec = get_spec(key)
    require_licence(spec)
    if key == "detectrl_x":
        return _map_detectrl_x(row, config, split, row_index=row_index)
    return _MAPPERS[key](row, config, split)


def write_sample_cache(
    spec: DatasetSpec,
    config: str,
    split: str,
    normalized: list[NormalizedRow],
    *,
    cache_dir: Path | None = None,
    fetched_from: str | None = None,
    filename: str | None = None,
) -> tuple[Path, Path]:
    """Write normalised rows as JSONL cache + manifest, return both paths.

    The manifest records the source, the fetch date, the row count and
    the SHA-256 of the cache file, so a cached sample can be re-verified
    without re-downloading.

    ``filename`` overrides the cache file name (plain file name only,
    e.g. ``"train-segments.jsonl"``) — used when a second sample of
    the same config/split must coexist with the first, as the U4
    segment cache does next to the U1 document cache. The manifest
    takes the matching ``.manifest.json`` name. Default preserves the
    ``<split>.jsonl`` layout.
    """
    from datetime import date

    path = cache_path(spec.key, config, split, cache_dir=cache_dir)
    if filename is not None:
        if not filename or filename != Path(filename).name:
            raise ValueError(f"filename must be a plain file name, got {filename!r}")
        path = path.with_name(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row.to_jsonl(), ensure_ascii=False, sort_keys=True) for row in normalized]
    content = "\n".join(lines) + ("\n" if lines else "")
    path.write_text(content, encoding="utf-8")
    file_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    manifest = {
        "dataset": spec.key,
        "hf_id": spec.hf_id,
        "config": config,
        "split": split,
        "licence": spec.licence,
        "fetched_from": fetched_from or DATASETS_SERVER_BASE,
        "fetch_date": date.today().isoformat(),
        "rows": len(normalized),
        "file": path.name,
        "file_sha256": file_sha256,
    }
    manifest_file = (
        path.with_suffix(".manifest.json")
        if filename is not None
        else manifest_path(spec.key, config, split, cache_dir=cache_dir)
    )
    manifest_file.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path, manifest_file


def read_sample_cache(
    spec: DatasetSpec,
    config: str,
    split: str,
    *,
    cache_dir: Path | None = None,
    filename: str | None = None,
) -> list[NormalizedRow]:
    """Read normalised rows back from a JSONL cache file.

    ``filename`` is the ``write_sample_cache`` override: the plain
    file name of a coexisting second sample of the same config/split
    (e.g. ``"train-segments.jsonl"``).
    """
    path = cache_path(spec.key, config, split, cache_dir=cache_dir)
    if filename is not None:
        if not filename or filename != Path(filename).name:
            raise ValueError(f"filename must be a plain file name, got {filename!r}")
        path = path.with_name(filename)
    if not path.exists():
        raise FileNotFoundError(f"No cached sample for {spec.key} {config}/{split}: {path}")
    rows: list[NormalizedRow] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        rows.append(
            NormalizedRow(
                text=data["text"],
                label=data["label"],
                dataset=data["dataset"],
                config=data["config"],
                split=data["split"],
                source_id=data["source_id"],
                regime=data["regime"],
                meta=data.get("meta", {}),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# DetectRL-X whole-file fetch (wave 2, worker B)
# ---------------------------------------------------------------------------


def detectrl_x_raw_path(*, cache_dir: Path | None = None) -> Path:
    """Local path of the downloaded DetectRL-X general file (cache, never the repo)."""
    root = cache_dir or default_cache_dir()
    return root / "detectrl_x" / DETECTRL_X_FILE


def download_detectrl_x(*, cache_dir: Path | None = None) -> Path:
    """Download the DetectRL-X general file via the shared resumable downloader.

    The HF resolve URL + expected SHA-256/size come from the HF tree
    API (2026-11-07); a destination that already exists and verifies
    is returned without re-downloading. Stall budget and retries are
    raised above the defaults (300 s, 8 retries) with a curl fallback:
    the 2026-11-07 incident — six attempts stalling in the header
    phase — falsified the earlier diagnosis that the transfer "stalls
    under the 30 s default", because those attempts ran with a 120 s
    timeout, so the stall exceeded 120 s per attempt. The fix is a
    long stall budget plus curl, which has no read timeout and waits
    stalls out — not a larger single timeout alone.
    """
    return download_large_file(
        DETECTRL_X_URL,
        detectrl_x_raw_path(cache_dir=cache_dir),
        expected_sha256=DETECTRL_X_SHA256,
        expected_bytes=DETECTRL_X_BYTES,
        stall_timeout_s=300,
        retries=8,
    )


def verify_detectrl_x_file(path: str | Path) -> Path:
    """Fail closed unless ``path`` is the expected DetectRL-X file.

    Size and SHA-256 are checked against the HF tree API values before
    any row is read, so a truncated or substituted download is refused
    instead of sampled.
    """
    path = Path(path)
    if not path.exists():
        raise DatasetFetchError(f"detectrl_x: raw file missing: {path}")
    size = path.stat().st_size
    if size != DETECTRL_X_BYTES:
        raise DatasetFetchError(
            f"detectrl_x: raw file is {size} bytes, expected {DETECTRL_X_BYTES}"
        )
    actual = _sha256_file(path)
    if actual != DETECTRL_X_SHA256:
        raise DatasetFetchError(
            f"detectrl_x: raw file SHA-256 mismatch (got {actual}, expected {DETECTRL_X_SHA256})"
        )
    return path


def iter_detectrl_x_rows(path: str | Path, *, max_object_bytes: int = 16 * 1024 * 1024):
    """Yield ``(row_index, row_dict)`` from a DetectRL-X JSON-array file, streaming.

    The general file is ~879 MB; loading it whole would need several
    GB of RAM, so objects are decoded one at a time with
    ``json.JSONDecoder.raw_decode`` over a 1 MiB rolling buffer. The
    file must be a JSON array of objects (verified on arrival
    2026-11-07: the file starts ``[{``); anything else — JSONL, a
    bare object, truncated input — raises :class:`DatasetFetchError`
    instead of being guessed at.

    Grammar (W1: CORE-09) — strict, state-machine enforced:

    * ``[`` then zero or more objects separated by exactly one comma
      each; no leading, repeated or trailing comma; no missing comma
      between elements; exactly one top-level array.
    * After the closing ``]`` only whitespace may follow: EOF is
      required, and any trailing data is rejected.
    * Each object is capped by ``max_object_bytes`` (default 16 MiB):
      a single object that cannot be decoded within that budget is
      rejected instead of growing the buffer without bound, and the
      rolling buffer never holds more than one partial object plus
      one read chunk.  Streaming is preserved: rows are yielded as
      they decode; the file is never read into memory whole.
    * Malformed Unicode (invalid UTF-8 bytes, truncated sequences)
      and pathological nesting depth are rejected as
      :class:`DatasetFetchError`, never as a bare codec or recursion
      exception escaping the parser.
    """
    decoder = json.JSONDecoder()
    path = Path(path)
    buf = ""
    eof = False
    chunk_size = 1 << 20
    with path.open("r", encoding="utf-8") as handle:

        def _fill() -> bool:
            nonlocal buf, eof
            if eof:
                return False
            try:
                chunk = handle.read(chunk_size)
            except UnicodeDecodeError as exc:
                raise DatasetFetchError("detectrl_x: file is not valid UTF-8") from exc
            if not chunk:
                eof = True
                return False
            buf += chunk
            if len(buf) > max_object_bytes + chunk_size:
                raise DatasetFetchError(
                    f"detectrl_x: single object exceeds the {max_object_bytes}-byte object budget"
                )
            return True

        def _skip_ws() -> None:
            """Drop leading whitespace, filling until non-ws or EOF."""
            nonlocal buf
            while True:
                stripped = buf.lstrip(" \t\r\n")
                if stripped:
                    buf = stripped
                    return
                buf = ""
                if not _fill():
                    return

        def _peek() -> str:
            """First non-whitespace character, or "" at EOF."""
            _skip_ws()
            return buf[:1]

        def _require_eof_after_close() -> None:
            """After ']', only whitespace may follow, then EOF."""
            while True:
                _skip_ws()
                if not buf:
                    if eof:
                        return
                    _fill()
                    continue
                raise DatasetFetchError("detectrl_x: trailing data after the closing JSON array")

        first = _peek()
        if first != "[":
            raise DatasetFetchError(
                "detectrl_x: expected a JSON array file (first non-whitespace "
                f"character is {first!r}, not '[')"
            )
        buf = buf[1:]
        index = 0
        expect_element = True  # after '[' or ','; False after an object
        while True:
            char = _peek()
            if eof and not buf:
                raise DatasetFetchError(
                    "detectrl_x: file ended before the JSON array closed (truncated?)"
                )
            if char == "]":
                if index > 0:
                    # Reached only after a comma: a trailing comma.
                    raise DatasetFetchError("detectrl_x: trailing comma in JSON array")
                buf = buf[1:]
                _require_eof_after_close()
                return
            if char == ",":
                raise DatasetFetchError("detectrl_x: unexpected comma in JSON array")
            if not expect_element:
                raise DatasetFetchError(
                    f"detectrl_x: expected ',' or ']' after row {index - 1}, "
                    f"found {char!r} (missing comma?)"
                )
            if char != "{":
                raise DatasetFetchError(
                    f"detectrl_x: row {index} is not a JSON object (found {char!r})"
                )
            try:
                obj, end = decoder.raw_decode(buf)
            except json.JSONDecodeError:
                if eof:
                    raise DatasetFetchError(
                        f"detectrl_x: row {index} is not parseable JSON"
                    ) from None
                _fill()
                continue
            except RecursionError as exc:
                raise DatasetFetchError(
                    f"detectrl_x: row {index} exceeds the nesting-depth budget"
                ) from exc
            if end > max_object_bytes:
                raise DatasetFetchError(
                    f"detectrl_x: row {index} exceeds the {max_object_bytes}-byte object budget"
                )
            if not isinstance(obj, dict):
                raise DatasetFetchError(
                    f"detectrl_x: row {index} is {type(obj).__name__}, expected object"
                )
            yield index, obj
            index += 1
            buf = buf[end:]
            expect_element = False
            # After an object, the separator must be ',' or ']'.
            char = _peek()
            if eof and not buf:
                raise DatasetFetchError(
                    "detectrl_x: file ended before the JSON array closed (truncated?)"
                )
            if char == ",":
                buf = buf[1:]
                expect_element = True
            elif char == "]":
                buf = buf[1:]
                _require_eof_after_close()
                return
            else:
                raise DatasetFetchError(
                    f"detectrl_x: expected ',' or ']' after row {index - 1}, "
                    f"found {char!r} (missing comma?)"
                )


def sample_detectrl_x_rows(
    path: str | Path,
    train_offsets: list[int],
    test_offsets: list[int],
) -> tuple[list[tuple[int, dict[str, Any]]], list[tuple[int, dict[str, Any]]], dict[str, int]]:
    """One streaming pass: count rows per split, collect strided samples.

    ``train_offsets`` / ``test_offsets`` are per-split row indices
    (from :func:`sample_offsets` over the plan totals). Returns
    ``(train_rows, test_rows, counts)`` where each row is an
    ``(index, row_dict)`` pair and ``counts`` is
    ``{"train": n, "test": n, "total": n}``. A row whose ``split`` is
    neither ``train`` nor ``test`` fails closed, and a short sample
    (fewer collected rows than requested offsets) is a hard error —
    the caller refuses on a count mismatch with the plan instead of
    sampling a stale denominator.
    """
    train_want = set(train_offsets)
    test_want = set(test_offsets)
    train_rows: list[tuple[int, dict[str, Any]]] = []
    test_rows: list[tuple[int, dict[str, Any]]] = []
    counts = {"train": 0, "test": 0, "total": 0}
    for index, row in iter_detectrl_x_rows(path):
        split = row.get("split")
        if split not in ("train", "test"):
            raise DatasetFetchError(f"detectrl_x: row {index} has unexpected split {split!r}")
        per_split_index = counts[split]
        counts[split] += 1
        counts["total"] += 1
        if split == "train" and per_split_index in train_want:
            train_rows.append((index, row))
        elif split == "test" and per_split_index in test_want:
            test_rows.append((index, row))
    if len(train_rows) != len(train_offsets) or len(test_rows) != len(test_offsets):
        raise DatasetFetchError(
            "detectrl_x: short sample — collected "
            f"{len(train_rows)}/{len(train_offsets)} train and "
            f"{len(test_rows)}/{len(test_offsets)} test rows; "
            "the file is shorter than the plan totals"
        )
    return train_rows, test_rows, counts
