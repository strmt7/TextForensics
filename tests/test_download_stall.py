"""Local stall-server fixture tests for ``download_large_file``.

No egress: a threaded :class:`http.server.ThreadingHTTPServer` running
in the test process serves a small Range-capable file with scripted
faults, so the failure modes behind the ~879 MB DetectRL-X incident
are deterministic instead of weather-dependent:

* response headers delayed past the stall timeout (the attempt is
  retried, then succeeds);
* body trickled a few bytes at a time (slow-but-steady must not trip
  the stall timeout);
* connection closed mid-body (Range resume completes the file);
* server ignores ``Range`` (curl ``--continue-at -`` exit 33 restarts
  from byte 0; loopback HTTP carve-out).

The mid-body close is a clean FIN: ``http.client`` on its own would
return ``b""`` as if the body were complete, but the loader compares
the bytes written against the declared ``Content-Length`` and turns
the short body into a retryable ``IncompleteRead``, so the retry
resumes via Range. (An abort/RST would raise on the next read
instead; the FIN shape is used here because it is the silent one.)

The downloader under test lives in ``textforensics.datasets``; this
module only drives it over loopback HTTP. No dataset text is involved:
the payload is a synthetic byte pattern.
"""

from __future__ import annotations

import http.server
import re
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

from textforensics.datasets import download_large_file

PAYLOAD_SIZE = 65_536
PAYLOAD = bytes(i % 251 for i in range(PAYLOAD_SIZE))
DROP_AFTER = 32_768
TRICKLE_PAYLOAD_SIZE = 4_096
TRICKLE_CHUNK = 128
TRICKLE_SLEEP_S = 0.1
HEADER_DELAY_S = 3.0
STALL_TIMEOUT_S = 1.0

_RANGE_RE = re.compile(r"bytes=(\d+)-")


class _FaultServer(http.server.ThreadingHTTPServer):
    """Threading HTTP server carrying the scripted-fault configuration."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, mode, payload=PAYLOAD):
        super().__init__(address, handler)
        self.mode = mode
        self.payload = payload
        # One dict per request, in receipt order:
        # {"range": str | None, "user_agent": str, "status": int | None}.
        self.request_log: list[dict] = []
        self.log_lock = threading.Lock()
        self.header_delay_s = HEADER_DELAY_S
        self.trickle_chunk = TRICKLE_CHUNK
        self.trickle_sleep_s = TRICKLE_SLEEP_S
        self.drop_after = DROP_AFTER

    def handle_error(self, request, client_address):
        # A faulted client (curl aborting a connection, the stalled
        # attempt going away) is an expected event for this fixture,
        # not a server failure worth a traceback in the test log.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class _FaultHandler(http.server.BaseHTTPRequestHandler):
    """Serve the payload, honouring Range except in ``ignore-range`` mode."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 — silence stderr noise
        pass

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler naming
        server = self.server
        range_header = self.headers.get("Range")
        user_agent = self.headers.get("User-Agent", "")
        with server.log_lock:
            request_no = len(server.request_log)
            server.request_log.append(
                {"range": range_header, "user_agent": user_agent, "status": None}
            )
        try:
            self._serve(request_no, range_header)
        except (BrokenPipeError, ConnectionResetError):
            # The client timed out or went away mid-fault; the fault
            # already happened, so there is nothing to report.
            pass

    def _serve(self, request_no, range_header):
        server = self.server
        payload = server.payload
        mode = server.mode
        if mode == "delay-headers-once" and request_no == 0:
            time.sleep(server.header_delay_s)
        start = 0
        status = 200
        if mode != "ignore-range" and range_header:
            match = _RANGE_RE.match(range_header)
            if match:
                start = int(match.group(1))
                status = 206
        if mode == "drop-once" and request_no == 0 and start == 0:
            # Declare the full length, send only the first part, then
            # close the connection mid-body. The loader's declared
            # Content-Length check turns the short body into a
            # retryable IncompleteRead (see the module docstring).
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            self._record_status(request_no, 200)
            self.wfile.write(payload[: server.drop_after])
            self.wfile.flush()
            self.close_connection = True
            return
        body = payload[start:]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{len(payload) - 1}/{len(payload)}")
        self.end_headers()
        self._record_status(request_no, status)
        if mode == "trickle":
            for offset in range(0, len(body), server.trickle_chunk):
                self.wfile.write(body[offset : offset + server.trickle_chunk])
                self.wfile.flush()
                time.sleep(server.trickle_sleep_s)
        else:
            self.wfile.write(body)
            self.wfile.flush()

    def _record_status(self, request_no, status):
        with self.server.log_lock:
            self.server.request_log[request_no]["status"] = status


@pytest.fixture()
def make_server(monkeypatch):
    """Factory returning ``(base_url, server)`` for a given fault mode.

    Loopback is forced past any egress proxy in the environment so the
    tests never leave the machine.
    """
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    servers: list[_FaultServer] = []

    def _make(mode, payload=PAYLOAD):
        server = _FaultServer(("127.0.0.1", 0), _FaultHandler, mode=mode, payload=payload)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        host, port = server.server_address
        return f"http://{host}:{port}/file.bin", server

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


def _part_path(dest: Path) -> Path:
    return dest.with_name(dest.name + ".part")


def test_plain_download_over_local_server(tmp_path, make_server):
    """Sanity: the fixture itself serves a plain download correctly."""
    url, server = make_server("normal")
    dest = tmp_path / "file.bin"
    assert download_large_file(url, dest, stall_timeout_s=STALL_TIMEOUT_S, retries=1) == dest
    assert dest.read_bytes() == PAYLOAD
    assert not _part_path(dest).exists()
    assert len(server.request_log) == 1


def test_header_stall_is_retried_then_succeeds(tmp_path, make_server):
    """Headers delayed past the stall timeout: attempt fails, retry succeeds.

    The server stalls only the first request's headers for longer than
    ``stall_timeout_s``; the retry must then complete the download.
    Exactly two requests proves the stall fired (one request would mean
    the timeout never engaged) and the retry succeeded.
    """
    url, server = make_server("delay-headers-once")
    dest = tmp_path / "file.bin"
    result = download_large_file(url, dest, stall_timeout_s=STALL_TIMEOUT_S, retries=2)
    assert result == dest
    assert dest.read_bytes() == PAYLOAD
    assert not _part_path(dest).exists()
    assert len(server.request_log) == 2


def test_slow_trickle_does_not_trip_stall_timeout(tmp_path, make_server):
    """Slow-but-steady body must not trip the stall timeout.

    The server sends 128 bytes every 0.1 s (about 3 s for the 4 KiB
    payload) while the stall budget is 1 s: every individual read
    completes well inside the budget, so the download must finish on
    its first attempt with no retry.
    """
    payload = bytes(i % 251 for i in range(TRICKLE_PAYLOAD_SIZE))
    url, server = make_server("trickle", payload=payload)
    dest = tmp_path / "file.bin"
    result = download_large_file(url, dest, stall_timeout_s=STALL_TIMEOUT_S, retries=2)
    assert result == dest
    assert dest.read_bytes() == payload
    assert not _part_path(dest).exists()
    assert len(server.request_log) == 1


def test_dropped_connection_resumes_with_range(tmp_path, make_server):
    """Connection closed mid-body: the retry resumes via Range.

    The server sends the first 32 KiB of the 64 KiB payload, then
    closes the connection. A small ``chunk_size`` makes the partial
    data land in the ``.part`` file before the failure, so the retry
    must resume at exactly byte 32768 with a 206 response.
    """
    url, server = make_server("drop-once")
    dest = tmp_path / "file.bin"
    result = download_large_file(
        url, dest, stall_timeout_s=STALL_TIMEOUT_S, retries=2, chunk_size=4096
    )
    assert result == dest
    assert dest.read_bytes() == PAYLOAD
    assert not _part_path(dest).exists()
    assert len(server.request_log) == 2
    assert server.request_log[0]["range"] is None
    assert server.request_log[1]["range"] == f"bytes={DROP_AFTER}-"
    assert server.request_log[1]["status"] == 206


def test_server_ignoring_range_restarts_from_zero_via_curl(tmp_path, make_server):
    """Server ignores Range: forced curl restarts from byte 0 (exit 33 path).

    A ``.part`` file holding the first half is pre-seeded, so curl's
    ``--continue-at -`` sends ``Range``; the server answers 200 with
    the full body, which curl reports as exit 33. The downloader must
    delete the stale ``.part`` and restart from byte 0, completing the
    file. The curl ``User-Agent`` on the ranged request proves the
    forced-curl path actually ran.
    """
    if shutil.which("curl") is None:
        pytest.skip("curl is not installed; the curl fallback cannot be exercised")
    url, server = make_server("ignore-range")
    dest = tmp_path / "file.bin"
    part = _part_path(dest)
    part.write_bytes(PAYLOAD[:DROP_AFTER])
    result = download_large_file(url, dest, force_curl=True, stall_timeout_s=30.0, retries=1)
    assert result == dest
    assert dest.read_bytes() == PAYLOAD
    assert not part.exists()
    curl_requests = [
        entry for entry in server.request_log if entry["user_agent"].startswith("curl/")
    ]
    assert curl_requests, "expected the forced-curl path to issue the requests"
    assert curl_requests[0]["range"] == f"bytes={DROP_AFTER}-"
    assert len(server.request_log) >= 2
    assert server.request_log[-1]["range"] is None
