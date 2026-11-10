"""W1 Worker B — IF-02 / IF-09 / IF-07 (Ollama transport) regression tests.

Loopback wire fakes only (real ``aiohttp.web`` servers on 127.0.0.1 /
127.0.0.2); no real model, no real provider, no external network.
Reserved example domains (``receiver.example``) and disposable markers
only — no real user text, accounts or keys.

Reproduction notes (audit baseline 5ea804c, evidence ``interfaces``):
- IF-02 ``ollama_redirect``: a 307 from 127.0.0.1 to ``receiver.example``
  forwarded SENSITIVE-DISPOSABLE-PROMPT while ``allow_remote_host`` was
  false, because aiohttp followed redirects without revalidating.
- IF-09 ``ollama_response_cap``: a 65,536-byte chunked response with
  ``max_response_bytes=1024`` was fully read before the cap raised
  (``body_completed_before_error=true``); error bodies called ``.text()``
  without even the later size check.
- IF-07 ``ollama_error_echo``: a provider error body echoing the prompt
  appeared verbatim in ``OllamaError``.

IF-13 (embeddings endpoint) and IF-15 (streaming session/setup) are
W5-owned and are NOT fixed here; tests below deliberately do not assert
the IF-15 wire ``stream:true`` flag.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import socket

import pytest
from aiohttp import web

from textforensics.execution_policy import diagnostic_record, public_error_body
from textforensics.ollama import (
    GenerationRequest,
    OllamaClient,
    OllamaConfig,
    OllamaError,
    OllamaModelNotFoundError,
    _iter_capped_lines,
    _read_capped,
)

PROMPT = "SENSITIVE-DISPOSABLE-PROMPT"
ERROR_MARKER = "W1B-ERROR-ECHO-MARKER-7F3A"
OVER_BUDGET_TOTAL = 65_536
CAP = 1024


async def _wait_for_server_observation(state: dict, *, timeout: float = 2.0) -> None:
    """Poll until the paced fake observes the early close (or times out).

    The client closes as soon as the cap trips, but the fake only learns
    of it on its next paced write (~50 ms later); asserting immediately
    would race the server's next write.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if state.get("disconnected") or state.get("completed"):
            return
        await asyncio.sleep(0.02)


# ---------------------------------------------------------------------------
# Loopback wire-fake helpers
# ---------------------------------------------------------------------------


async def _start(app: web.Application, host: str = "127.0.0.1") -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://{host}:{port}"


def _recording_app(record: list, state: dict) -> web.Application:
    """An endpoint that records every request (method/path/body bytes)."""

    async def handler(request: web.Request) -> web.Response:
        body = await request.read()
        record.append(
            {"method": request.method, "path": request.path, "body": body, "host": request.host}
        )
        state["hits"] = state.get("hits", 0) + 1
        return web.json_response({"model": "audit-model", "response": "ok", "done": True})

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


def _redirect_app(target_url: str, status: int) -> web.Application:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=status, headers={"Location": target_url})

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


async def _paced_stream(
    request: web.Request,
    *,
    state: dict,
    total: int = OVER_BUDGET_TOTAL,
    chunk: int = 4096,
    delay: float = 0.05,
    status: int = 200,
    payload: bytes | None = None,
    content_type: str = "application/json",
    extra_headers: dict | None = None,
) -> web.StreamResponse:
    """Write ``total`` bytes in paced chunks; record early-close evidence."""
    resp = web.StreamResponse(status=status)
    resp.content_type = content_type
    for key, value in (extra_headers or {}).items():
        resp.headers[key] = value
    await resp.prepare(request)
    sent = 0
    try:
        while sent < total:
            await asyncio.sleep(delay)
            size = min(chunk, total - sent)
            data = payload if payload is not None else b"x" * size
            if payload is not None:
                data = payload[sent : sent + size]
            await resp.write(data)
            sent += len(data)
            state["bytes_sent"] = sent
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        state["disconnected"] = True
        return resp
    except Exception:  # pragma: no cover - transport teardown varies
        state["disconnected"] = True
        return resp
    state["completed"] = True
    return resp


# ---------------------------------------------------------------------------
# IF-02 — redirect escapes the loopback-only boundary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestIF02Redirects:
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_redirect_to_receiver_example_refused_zero_requests(self, status):
        """Audit vector: 307 from 127.0.0.1 to receiver.example must not forward."""
        record: list = []
        state: dict = {}
        receiver = _recording_app(record, state)
        recv_runner, recv_url = await _start(receiver)
        recv_port = recv_url.rsplit(":", 1)[1]
        target = f"http://receiver.example:{recv_port}/collect"
        origin_runner, origin_url = await _start(_redirect_app(target, status))
        client = OllamaClient(
            OllamaConfig(base_url=origin_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert record == [], "disallowed receiver must receive zero requests"
            assert state.get("hits", 0) == 0
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_redirect_same_host_refused_by_default(self, status):
        """Default policy disables redirects even to another loopback host."""
        record: list = []
        state: dict = {}
        recv_runner, recv_url = await _start(_recording_app(record, state))
        origin_runner, origin_url = await _start(_redirect_app(f"{recv_url}/collect", status))
        client = OllamaClient(
            OllamaConfig(base_url=origin_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert record == []
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_redirect_cross_loopback_host_refused_by_default(self, status):
        record: list = []
        state: dict = {}
        recv_runner, recv_url = await _start(_recording_app(record, state), host="127.0.0.2")
        origin_runner, origin_url = await _start(_redirect_app(f"{recv_url}/collect", status))
        client = OllamaClient(
            OllamaConfig(base_url=origin_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert record == []
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()

    async def test_relative_location_refused_by_default(self):
        record: list = []
        app = web.Application()

        async def redirect_handler(request: web.Request) -> web.Response:
            return web.Response(status=307, headers={"Location": "/collect"})

        async def collect_handler(request: web.Request) -> web.Response:
            body = await request.read()
            record.append({"method": request.method, "path": request.path, "body": body})
            return web.json_response({"model": "audit-model", "response": "ok", "done": True})

        app.router.add_post("/api/generate", redirect_handler)
        app.router.add_route("*", "/collect", collect_handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert record == []
        finally:
            await client.close()
            await runner.cleanup()

    async def test_redirect_loop_refused_by_default(self):
        state: dict = {}
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            state["hits"] = state.get("hits", 0) + 1
            return web.Response(status=307, headers={"Location": "/api/generate"})

        app.router.add_post("/api/generate", handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            # Default policy refuses the first redirect: exactly one request.
            assert state["hits"] == 1
        finally:
            await client.close()
            await runner.cleanup()

    async def test_redirect_chain_refused_by_default(self):
        """A -> B -> C: no hop beyond the origin may receive the prompt."""
        record_c: list = []
        state_c: dict = {}
        runner_c, url_c = await _start(_recording_app(record_c, state_c))
        runner_b, url_b = await _start(_redirect_app(f"{url_c}/collect", 307))
        runner_a, url_a = await _start(_redirect_app(f"{url_b}/collect", 307))
        client = OllamaClient(OllamaConfig(base_url=url_a, max_response_bytes=CAP, max_retries=0))
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert record_c == []
        finally:
            await client.close()
            await runner_a.cleanup()
            await runner_b.cleanup()
            await runner_c.cleanup()

    async def test_streaming_redirect_refused_zero_requests(self):
        """IF-02 applies to streaming as well as ordinary requests."""
        record: list = []
        state: dict = {}
        recv_runner, recv_url = await _start(_recording_app(record, state))
        origin_runner, origin_url = await _start(_redirect_app(f"{recv_url}/collect", 307))
        client = OllamaClient(
            OllamaConfig(base_url=origin_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            stream = await client.generate(
                GenerationRequest(model="audit-model", prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError, match="redirect"):
                async for _ in stream:
                    pass
            assert record == []
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()

    async def test_opted_in_same_host_chain_is_bounded_and_auditable(self):
        """allow_redirects=True: a short same-host chain succeeds, chain recorded."""
        record: list = []
        state: dict = {}
        runner_c, url_c = await _start(_recording_app(record, state))
        runner_b, url_b = await _start(_redirect_app(f"{url_c}/collect", 307))
        runner_a, url_a = await _start(_redirect_app(f"{url_b}/collect", 307))
        client = OllamaClient(
            OllamaConfig(
                base_url=url_a,
                max_response_bytes=CAP,
                max_retries=0,
                allow_redirects=True,
                max_redirects=5,
            )
        )
        try:
            response = await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert response.response == "ok"
            assert len(record) == 1
            assert record[0]["body"] != b""  # prompt forwarded only to allowed hop
            assert PROMPT.encode() in record[0]["body"]
            chain = client.last_redirect_chain
            assert len(chain) == 2
            assert all(status == 307 for status, _host in chain)
        finally:
            await client.close()
            await runner_a.cleanup()
            await runner_b.cleanup()
            await runner_c.cleanup()

    async def test_opted_in_redirect_loop_is_bounded(self):
        state: dict = {}
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            state["hits"] = state.get("hits", 0) + 1
            return web.Response(status=307, headers={"Location": "/api/generate"})

        app.router.add_post("/api/generate", handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(
                base_url=base_url,
                max_response_bytes=CAP,
                max_retries=0,
                allow_redirects=True,
                max_redirects=3,
            )
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            # 1 original + at most max_redirects followed hops.
            assert state["hits"] <= 4
        finally:
            await client.close()
            await runner.cleanup()

    async def test_opted_in_cross_host_still_needs_remote_opt_in(self):
        """allow_redirects does not widen the host policy: 127.0.0.2 is loopback,
        but receiver.example is not — it stays refused without allow_remote_host."""
        record: list = []
        state: dict = {}
        recv_runner, recv_url = await _start(_recording_app(record, state))
        recv_port = recv_url.rsplit(":", 1)[1]
        target = f"http://receiver.example:{recv_port}/collect"
        origin_runner, origin_url = await _start(_redirect_app(target, 307))
        client = OllamaClient(
            OllamaConfig(
                base_url=origin_url,
                max_response_bytes=CAP,
                max_retries=0,
                allow_redirects=True,
            )
        )
        try:
            with pytest.raises(OllamaError, match="redirect"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert record == []
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()

    async def test_opted_in_receiver_example_reachable_when_both_opt_ins_set(self, monkeypatch):
        """Both opt-ins set: the audit's receiver is reachable, bounded, audited.

        ``receiver.example`` is resolved to loopback for this test only, via
        a patched ``socket.getaddrinfo`` (restored by monkeypatch). This
        proves the default refusal above is the host policy, not DNS.
        """
        record: list = []
        state: dict = {}
        recv_runner, recv_url = await _start(_recording_app(record, state))
        recv_port = recv_url.rsplit(":", 1)[1]
        target = f"http://receiver.example:{recv_port}/collect"
        origin_runner, origin_url = await _start(_redirect_app(target, 307))

        real_getaddrinfo = socket.getaddrinfo

        def _patched_getaddrinfo(host, port, *args, **kwargs):
            if host == "receiver.example":
                return real_getaddrinfo("127.0.0.1", port, *args, **kwargs)
            return real_getaddrinfo(host, port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", _patched_getaddrinfo)
        client = OllamaClient(
            OllamaConfig(
                base_url=origin_url,
                max_response_bytes=CAP,
                max_retries=0,
                allow_redirects=True,
                allow_remote_host=True,
                max_redirects=5,
            )
        )
        try:
            response = await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert response.response == "ok"
            assert len(record) == 1
            assert PROMPT.encode() in record[0]["body"]
            assert client.last_redirect_chain == ((307, "receiver.example"),)
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()

    async def test_redirect_refusal_redacts_url(self):
        record: list = []
        state: dict = {}
        recv_runner, recv_url = await _start(_recording_app(record, state))
        origin_runner, origin_url = await _start(
            _redirect_app(f"{recv_url}/collect?secret=disposable", 307)
        )
        client = OllamaClient(
            OllamaConfig(base_url=origin_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert "secret=disposable" not in str(excinfo.value)
            assert PROMPT not in str(excinfo.value)
        finally:
            await client.close()
            await origin_runner.cleanup()
            await recv_runner.cleanup()


# ---------------------------------------------------------------------------
# IF-09 — response byte cap enforced after complete buffering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestIF09ResponseCap:
    async def _paced_app(self, state: dict, **kwargs) -> web.Application:
        app = web.Application()

        async def handler(request: web.Request) -> web.StreamResponse:
            return await _paced_stream(request, state=state, **kwargs)

        app.router.add_route("*", "/{tail:.*}", handler)
        return app

    async def test_over_budget_2xx_closes_before_completion(self):
        """Audit vector: 65,536 bytes with cap 1024 must close early."""
        state: dict = {}
        app = await self._paced_app(state)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="exceeds"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            await _wait_for_server_observation(state)
            assert state.get("completed", False) is False
            assert state.get("bytes_sent", OVER_BUDGET_TOTAL) < OVER_BUDGET_TOTAL
            assert state.get("disconnected", False) is True
        finally:
            await client.close()
            await runner.cleanup()

    async def test_over_budget_4xx_error_body_closes_before_completion(self):
        """Error bodies are capped separately and closed early too."""
        state: dict = {}
        payload = (ERROR_MARKER + ": " + PROMPT + " ").encode() * 1024
        payload = payload[:OVER_BUDGET_TOTAL]
        app = await self._paced_app(
            state, status=400, payload=payload, content_type="application/json"
        )
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert ERROR_MARKER not in str(excinfo.value)
            assert PROMPT not in str(excinfo.value)
            await _wait_for_server_observation(state)
            assert state.get("completed", False) is False
            assert state.get("bytes_sent", OVER_BUDGET_TOTAL) < OVER_BUDGET_TOTAL
        finally:
            await client.close()
            await runner.cleanup()

    async def test_over_budget_compressed_2xx_counts_decompressed_bytes(self):
        """Decompressed bytes count toward the cap, not compressed bytes."""
        state: dict = {}
        raw = b"y" * OVER_BUDGET_TOTAL
        compressed = gzip.compress(raw)
        app = web.Application()

        async def handler(request: web.Request) -> web.StreamResponse:
            return await _paced_stream(
                request,
                state=state,
                total=len(compressed),
                chunk=64,
                delay=0.02,
                payload=compressed,
                extra_headers={"Content-Encoding": "gzip"},
            )

        app.router.add_route("*", "/{tail:.*}", handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="exceeds"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            # The compressed body is tiny (~100 bytes); only a decompressed
            # budget can trip the cap before the body completes.
            await _wait_for_server_observation(state)
            assert state.get("completed", False) is False
        finally:
            await client.close()
            await runner.cleanup()

    async def test_over_budget_compressed_4xx_counts_decompressed_bytes(self):
        state: dict = {}
        raw = (ERROR_MARKER + " ").encode() * 4096
        compressed = gzip.compress(raw)
        app = web.Application()

        async def handler(request: web.Request) -> web.StreamResponse:
            return await _paced_stream(
                request,
                state=state,
                status=400,
                total=len(compressed),
                chunk=64,
                delay=0.02,
                payload=compressed,
                extra_headers={"Content-Encoding": "gzip"},
            )

        app.router.add_route("*", "/{tail:.*}", handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert ERROR_MARKER not in str(excinfo.value)
            await _wait_for_server_observation(state)
            assert state.get("completed", False) is False
        finally:
            await client.close()
            await runner.cleanup()

    async def test_under_budget_valid_json_still_parses(self):
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            return web.json_response(
                {
                    "models": [
                        {
                            "name": "audit-model",
                            "model": "audit-model",
                            "size": 1,
                            "digest": "d",
                            "modified_at": "2026-01-01T00:00:00Z",
                        }
                    ]
                }
            )

        app.router.add_get("/api/tags", handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            models = await client.list_models()
            assert [m.name for m in models] == ["audit-model"]
        finally:
            await client.close()
            await runner.cleanup()

    async def test_session_survives_overflow_and_next_request_succeeds(self):
        """Overflow closes the response, not the session."""
        state: dict = {}
        app = web.Application()

        async def paced(request: web.Request) -> web.StreamResponse:
            return await _paced_stream(request, state=state)

        async def small(request: web.Request) -> web.Response:
            return web.json_response({"model": "audit-model", "response": "ok", "done": True})

        async def health(request: web.Request) -> web.Response:
            return web.Response(status=200, text="ok")

        app.router.add_post("/api/generate", paced)
        app.router.add_get("/api/tags", small)
        app.router.add_get("/", health)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError, match="exceeds"):
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert client._session is not None and not client._session.closed
            assert await client.check_health() is True
        finally:
            await client.close()
            await runner.cleanup()

    async def test_streaming_over_budget_closes_before_completion(self):
        """Streaming uses the same capped reader and closes early."""
        state: dict = {}
        lines = [
            json.dumps({"model": "audit-model", "response": "x" * 512, "done": False}).encode()
            + b"\n"
            for _ in range(8)
        ]
        payload = b"".join(lines)
        app = web.Application()

        async def handler(request: web.Request) -> web.StreamResponse:
            return await _paced_stream(
                request,
                state=state,
                total=len(payload),
                chunk=256,
                delay=0.02,
                payload=payload,
            )

        app.router.add_post("/api/generate", handler)
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=CAP, max_retries=0)
        )
        try:
            stream = await client.generate(
                GenerationRequest(model="audit-model", prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError, match="exceeds"):
                async for _ in stream:
                    pass
            await _wait_for_server_observation(state)
            assert state.get("completed", False) is False
            assert state.get("bytes_sent", len(payload)) < len(payload)
        finally:
            await client.close()
            await runner.cleanup()

    async def test_read_capped_closes_response_on_overflow_and_retains_bounded_buffer(self):
        """Unit pin: the shared reader closes the response on overflow and
        never retains more than the cap plus one chunk."""

        class FakeContent:
            def __init__(self, chunks):
                self._chunks = iter(chunks)

            async def iter_chunked(self, size):
                for chunk in self._chunks:
                    yield chunk

        class FakeResponse:
            def __init__(self):
                self.content = FakeContent([b"a" * 600, b"b" * 600, b"c" * 600])
                self.closed = False

            def close(self):
                self.closed = True

        response = FakeResponse()
        with pytest.raises(OllamaError, match="exceeds"):
            await _read_capped(response, max_bytes=1024)
        assert response.closed is True

    async def test_iter_capped_lines_closes_response_on_overflow(self):
        class FakeResponse:
            def __init__(self):
                self.content = self._gen()
                self.closed = False

            async def _gen(self):
                yield b"a" * 600
                yield b"b" * 600

            def close(self):
                self.closed = True

        response = FakeResponse()
        with pytest.raises(OllamaError, match="exceeds"):
            [line async for line in _iter_capped_lines(response, max_bytes=1024)]
        assert response.closed is True


# ---------------------------------------------------------------------------
# IF-07 — Ollama error path (shared redaction contract wiring)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestIF07OllamaErrorPath:
    async def _error_app(self, status: int, body: dict) -> web.Application:
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            return web.json_response(body, status=status)

        app.router.add_route("*", "/{tail:.*}", handler)
        return app

    async def test_provider_error_body_never_echoed(self):
        """Audit vector ollama_error_echo: marker must not appear in OllamaError."""
        app = await self._error_app(400, {"error": f"bad prompt: {PROMPT} {ERROR_MARKER}"})
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=10_000, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            message = str(excinfo.value)
            assert PROMPT not in message
            assert ERROR_MARKER not in message
            assert excinfo.value.request_id  # correlated, opaque
            assert excinfo.value.status_code == 400
            public = public_error_body(
                excinfo.value.status_code,
                request_id=excinfo.value.request_id,
            )
            assert PROMPT not in json.dumps(public)
            assert ERROR_MARKER not in json.dumps(public)
            assert public["request_id"] == excinfo.value.request_id
            diag = diagnostic_record(excinfo.value, request_id=excinfo.value.request_id)
            assert diag == {
                "request_id": excinfo.value.request_id,
                "error_type": "OllamaError",
            }
        finally:
            await client.close()
            await runner.cleanup()

    async def test_model_not_found_is_generic(self):
        app = await self._error_app(404, {"error": f"model not found for prompt {PROMPT}"})
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=10_000, max_retries=0)
        )
        try:
            with pytest.raises(OllamaModelNotFoundError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert PROMPT not in str(excinfo.value)
            assert excinfo.value.status_code == 404
        finally:
            await client.close()
            await runner.cleanup()

    async def test_server_error_is_generic_and_correlated(self):
        app = await self._error_app(500, {"error": f"internal failure on {PROMPT}"})
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=10_000, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            assert PROMPT not in str(excinfo.value)
            assert excinfo.value.status_code == 500
            assert excinfo.value.request_id
        finally:
            await client.close()
            await runner.cleanup()

    async def test_error_path_does_not_echo_base_url(self):
        app = await self._error_app(400, {"error": "bad request"})
        runner, base_url = await _start(app)
        client = OllamaClient(
            OllamaConfig(base_url=base_url, max_response_bytes=10_000, max_retries=0)
        )
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.generate(GenerationRequest(model="audit-model", prompt=PROMPT))
            # Public errors redact URLs: no host/port from the endpoint.
            assert "127.0.0.1" not in str(excinfo.value)
        finally:
            await client.close()
            await runner.cleanup()


# ---------------------------------------------------------------------------
# Config surface for the new transport policy
# ---------------------------------------------------------------------------


class TestOllamaTransportConfig:
    def test_redirects_disabled_by_default(self):
        config = OllamaConfig()
        assert config.allow_redirects is False
        assert config.max_redirects == 5

    def test_error_body_cap_defaults_to_bounded_value(self):
        config = OllamaConfig()
        assert 0 < config.max_error_body_bytes <= config.max_response_bytes

    def test_invalid_redirect_budget_rejected(self):
        with pytest.raises(ValueError):
            OllamaConfig(max_redirects=-1)
        with pytest.raises(ValueError):
            OllamaConfig(max_error_body_bytes=0)
