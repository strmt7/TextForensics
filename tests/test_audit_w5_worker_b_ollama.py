"""W5 Worker B — IF-13 (embeddings endpoint) and IF-15 (streaming setup).

Loopback wire fakes only (real ``aiohttp.web`` servers on 127.0.0.1);
no real model, no real provider, no external network. Disposable
markers only — no real user text, accounts or keys.

Reproduction notes (audit baseline 5ea804c, evidence ``interfaces``):
- IF-13 ``ollama_embeddings_wire``: the client POSTs the ``/api/embed``
  request shape (``input``, batch support, ``truncate``) to legacy
  ``/api/embeddings``, whose request uses ``prompt``; the fake answers
  with a protocol-faithful 400. ``truncate=False`` is dropped by
  truthy-only serialization, letting the service default contradict it.
- IF-15 ``ollama_stream_without_context``: a fresh client
  (no ``async with``) gets
  ``AttributeError: 'NoneType' object has no attribute 'post'`` on the
  first streamed item, and the ``stream=True`` argument never reaches
  the wire body (default stays ``stream:false``).
"""

from __future__ import annotations

import asyncio
import json

import pytest
from aiohttp import web

from textforensics.ollama import (
    EmbeddingRequest,
    GenerationRequest,
    OllamaClient,
    OllamaConfig,
    OllamaError,
    OllamaModelNotFoundError,
    OllamaTimeoutError,
)

MODEL = "audit-model"
PROMPT = "SENSITIVE-DISPOSABLE-PROMPT"
MALFORMED_MARKER = "W5B-MALFORMED-MARKER-9C41"
VEC_A = [0.1, 0.2, 0.3]
VEC_B = [0.4, 0.5, 0.6]


async def _start(app: web.Application, host: str = "127.0.0.1") -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://{host}:{port}"


def _client(base_url: str, **kwargs) -> OllamaClient:
    config = OllamaConfig(base_url=base_url, max_retries=0, **kwargs)
    return OllamaClient(config)


async def _wait_for_server_observation(state: dict, *, timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if state.get("disconnected") or state.get("completed"):
            return
        await asyncio.sleep(0.02)


# ---------------------------------------------------------------------------
# IF-13 — embeddings endpoint contract
# ---------------------------------------------------------------------------


def _embed_app(record: list, *, responder) -> web.Application:
    """``/api/embed`` via ``responder``; legacy ``/api/embeddings`` 400s."""

    async def embed_handler(request: web.Request) -> web.Response:
        body = await request.json()
        record.append({"path": request.path, "body": body})
        payload, status = responder(body)
        return web.json_response(payload, status=status)

    async def legacy_handler(request: web.Request) -> web.Response:
        body = await request.json()
        record.append({"path": request.path, "body": body})
        # Protocol-faithful legacy refusal: /api/embeddings takes `prompt`.
        return web.json_response(
            {"error": "unknown field 'input': /api/embeddings expects 'prompt'"},
            status=400,
        )

    app = web.Application()
    app.router.add_post("/api/embed", embed_handler)
    app.router.add_post("/api/embeddings", legacy_handler)
    return app


def _vectors_for(body: dict) -> list:
    """One vector per input; scalar input yields exactly one vector."""
    inputs = body.get("input")
    count = len(inputs) if isinstance(inputs, list) else 1
    vectors = [list(VEC_A), list(VEC_B), [0.7, 0.8, 0.9], [1.0, 1.1, 1.2]]
    return vectors[:count]


@pytest.mark.asyncio
class TestIF13EmbeddingsEndpoint:
    async def test_scalar_input_posts_to_api_embed_with_truncate_false(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": _vectors_for(body)}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            response = await client.embeddings(
                EmbeddingRequest(model=MODEL, input="one", truncate=False)
            )
            assert response.embeddings == [VEC_A]
            assert len(record) == 1
            assert record[0]["path"] == "/api/embed"
            body = record[0]["body"]
            assert body["model"] == MODEL
            assert body["input"] == "one"
            # Explicit boolean serialization: False must appear on the wire.
            assert "truncate" in body
            assert body["truncate"] is False
        finally:
            await client.close()
            await runner.cleanup()

    async def test_batch_input_posts_to_api_embed_with_truncate_false(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": _vectors_for(body)}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            response = await client.embeddings(
                EmbeddingRequest(model=MODEL, input=["one", "two"], truncate=False)
            )
            assert response.embeddings == [VEC_A, VEC_B]
            assert len(record) == 1
            assert record[0]["path"] == "/api/embed"
            body = record[0]["body"]
            assert body["input"] == ["one", "two"]
            assert body["truncate"] is False
        finally:
            await client.close()
            await runner.cleanup()

    async def test_truncate_true_is_also_explicit_on_the_wire(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": _vectors_for(body)}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            await client.embeddings(EmbeddingRequest(model=MODEL, input="one", truncate=True))
            assert record[0]["body"]["truncate"] is True
        finally:
            await client.close()
            await runner.cleanup()

    async def test_empty_embeddings_refused(self):
        record: list = []
        app = _embed_app(record, responder=lambda body: ({"model": MODEL, "embeddings": []}, 200))
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input="one"))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_missing_embeddings_key_refused(self):
        record: list = []
        app = _embed_app(record, responder=lambda body: ({"model": MODEL}, 200))
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input="one"))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_wrong_vector_count_refused(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": [VEC_A]}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input=["one", "two"]))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_ragged_dimensions_refused(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": [VEC_A, [0.4, 0.5]]}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input=["one", "two"]))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_empty_vector_refused(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": [[]]}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input="one"))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_nonfinite_vector_refused(self):
        record: list = []
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            body = await request.json()
            record.append({"path": request.path, "body": body})
            # Raw NaN literal: Python's json accepts it, so the client
            # must check finiteness itself instead of trusting the parse.
            return web.Response(
                text='{"model": "audit-model", "embeddings": [[0.1, NaN, 0.3]]}',
                content_type="application/json",
            )

        app.router.add_post("/api/embed", handler)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input="one"))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_wrong_shape_refused(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"model": MODEL, "embeddings": "not-a-list"}, 200),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError, match="embedding"):
                await client.embeddings(EmbeddingRequest(model=MODEL, input="one"))
        finally:
            await client.close()
            await runner.cleanup()

    async def test_provider_400_is_redacted(self):
        record: list = []
        app = _embed_app(
            record,
            responder=lambda body: ({"error": f"bad input: {PROMPT}"}, 400),
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            with pytest.raises(OllamaError) as excinfo:
                await client.embeddings(EmbeddingRequest(model=MODEL, input=PROMPT))
            assert PROMPT not in str(excinfo.value)
            assert excinfo.value.status_code == 400
        finally:
            await client.close()
            await runner.cleanup()

    async def test_embeddings_timeout(self):
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            await asyncio.sleep(1.0)
            return web.json_response({"model": MODEL, "embeddings": [VEC_A]})

        app.router.add_post("/api/embed", handler)
        runner, base_url = await _start(app)
        client = _client(base_url, timeout_seconds=0.2)
        try:
            with pytest.raises(OllamaTimeoutError):
                await client.embeddings(EmbeddingRequest(model=MODEL, input="one"))
        finally:
            await client.close()
            await runner.cleanup()

    @pytest.mark.asyncio
    async def test_empty_input_list_rejected_client_side(self):
        client = OllamaClient(OllamaConfig(max_retries=0))
        try:
            with pytest.raises(ValueError, match="empty"):
                # No server involved: the call must fail before any request.
                await client.embeddings(EmbeddingRequest(model=MODEL, input=[]))
        finally:
            await client.close()


class TestIF13EmbeddingRequestSerialization:
    def test_truncate_false_is_serialized(self):
        data = EmbeddingRequest(model=MODEL, input="one", truncate=False).to_dict()
        assert data["truncate"] is False

    def test_truncate_true_is_serialized(self):
        data = EmbeddingRequest(model=MODEL, input="one", truncate=True).to_dict()
        assert data["truncate"] is True

    def test_batch_input_serialized(self):
        data = EmbeddingRequest(model=MODEL, input=["one", "two"], truncate=False).to_dict()
        assert data["input"] == ["one", "two"]
        assert data["truncate"] is False


# ---------------------------------------------------------------------------
# IF-15 — streaming uses the shared request lifecycle
# ---------------------------------------------------------------------------


def _ndjson_app(
    record: list,
    state: dict,
    *,
    lines: list[bytes],
    status: int = 200,
    delay_before: float = 0.0,
    delay_between: float = 0.0,
    error_body: dict | None = None,
) -> web.Application:
    """NDJSON fake for /api/generate and /api/chat; counts connections."""

    async def handler(request: web.Request) -> web.StreamResponse:
        body = await request.read()
        record.append({"method": request.method, "path": request.path, "body": body})
        state["connections"] = state.get("connections", 0) + 1
        if error_body is not None:
            return web.json_response(error_body, status=status)
        resp = web.StreamResponse(status=status)
        resp.content_type = "application/x-ndjson"
        await resp.prepare(request)
        try:
            if delay_before:
                await asyncio.sleep(delay_before)
            for line in lines:
                await resp.write(line + b"\n")
                if delay_between:
                    await asyncio.sleep(delay_between)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            state["disconnected"] = True
            return resp
        except Exception:  # pragma: no cover - transport teardown varies
            state["disconnected"] = True
            return resp
        state["completed"] = True
        return resp

    app = web.Application()
    app.router.add_post("/api/generate", handler)
    app.router.add_post("/api/chat", handler)
    return app


def _gen_lines(*texts: str, done: bool = True) -> list[bytes]:
    lines = []
    for i, text in enumerate(texts):
        last = done and i == len(texts) - 1
        lines.append(
            json.dumps(
                {
                    "model": MODEL,
                    "created_at": "2026-01-01T00:00:00Z",
                    "response": text,
                    "done": last,
                }
            ).encode()
        )
    return lines


def _chat_lines(*texts: str) -> list[bytes]:
    lines = []
    for i, text in enumerate(texts):
        last = i == len(texts) - 1
        lines.append(
            json.dumps(
                {
                    "model": MODEL,
                    "created_at": "2026-01-01T00:00:00Z",
                    "message": {"role": "assistant", "content": text},
                    "done": last,
                }
            ).encode()
        )
    return lines


@pytest.mark.asyncio
class TestIF15StreamingLifecycle:
    async def test_generate_stream_fresh_client_stream_true_on_wire(self):
        """Audit vector: fresh client, no `async with`, stream=True."""
        record: list = []
        state: dict = {}
        lines = _gen_lines("Hello ", "world", done=True)
        # A blank keep-alive line between chunks must be skipped, not parsed.
        lines = [lines[0], b"", lines[1]]
        app = _ndjson_app(record, state, lines=lines)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            assert client._session is None
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            # Session is ensured before iteration begins.
            assert client._session is not None
            assert not client._session.closed
            responses = [item async for item in stream]
            assert [r.response for r in responses] == ["Hello ", "world"]
            assert responses[-1].done is True
            assert len(record) == 1
            body = json.loads(record[0]["body"])
            assert body["stream"] is True
            assert body["prompt"] == PROMPT
            assert state["connections"] == 1
            assert state.get("completed") is True
        finally:
            await client.close()
            await runner.cleanup()

    async def test_generate_stream_request_flag_does_not_override_method_flag(self):
        """Wire `stream` always follows the method argument, not the request."""
        record: list = []
        state: dict = {}
        app = _ndjson_app(record, state, lines=_gen_lines("ok"))
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT, stream=True), stream=True
            )
            assert [r.response async for r in stream] == ["ok"]
            assert json.loads(record[0]["body"])["stream"] is True
        finally:
            await client.close()
            await runner.cleanup()

    async def test_generate_nonstream_request_flag_reconciled_to_false(self):
        """A request built with stream=True but called without streaming
        must not ask the server to stream: the single-JSON parse would
        otherwise fail on NDJSON."""
        record: list = []
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            body = await request.read()
            record.append({"path": request.path, "body": body})
            return web.json_response(
                {
                    "model": MODEL,
                    "created_at": "2026-01-01T00:00:00Z",
                    "response": "ok",
                    "done": True,
                }
            )

        app.router.add_post("/api/generate", handler)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            response = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT, stream=True)
            )
            assert response.response == "ok"
            assert json.loads(record[0]["body"])["stream"] is False
        finally:
            await client.close()
            await runner.cleanup()

    async def test_chat_stream_fresh_client(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(record, state, lines=_chat_lines("Hi", " there"))
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.chat(MODEL, [{"role": "user", "content": PROMPT}], stream=True)
            assert client._session is not None
            chunks = [item async for item in stream]
            assert [c["message"]["content"] for c in chunks] == ["Hi", " there"]
            assert chunks[-1]["done"] is True
            body = json.loads(record[0]["body"])
            assert body["stream"] is True
            assert state["connections"] == 1
        finally:
            await client.close()
            await runner.cleanup()

    async def test_generate_stream_inside_context_manager(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(record, state, lines=_gen_lines("ctx"))
        runner, base_url = await _start(app)
        try:
            async with _client(base_url) as client:
                stream = await client.generate(
                    GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
                )
                assert [r.response async for r in stream] == ["ctx"]
                assert json.loads(record[0]["body"])["stream"] is True
        finally:
            await runner.cleanup()

    async def test_chat_stream_inside_context_manager(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(record, state, lines=_chat_lines("ctx"))
        runner, base_url = await _start(app)
        try:
            async with _client(base_url) as client:
                stream = await client.chat(
                    MODEL, [{"role": "user", "content": PROMPT}], stream=True
                )
                assert [c["message"]["content"] async for c in stream] == ["ctx"]
                assert json.loads(record[0]["body"])["stream"] is True
        finally:
            await runner.cleanup()

    async def test_stream_4xx_is_classified_and_redacted(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(
            record,
            state,
            lines=[],
            status=404,
            error_body={"error": f"model not found for prompt {PROMPT}"},
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaModelNotFoundError) as excinfo:
                async for _ in stream:
                    pass
            assert PROMPT not in str(excinfo.value)
            assert excinfo.value.status_code == 404
            assert state["connections"] == 1
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_5xx_is_classified_and_redacted(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(
            record,
            state,
            lines=[],
            status=500,
            error_body={"error": f"internal failure on {PROMPT}"},
        )
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError) as excinfo:
                async for _ in stream:
                    pass
            assert PROMPT not in str(excinfo.value)
            assert excinfo.value.status_code == 500
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_malformed_line_is_redacted_error(self):
        record: list = []
        state: dict = {}
        lines = [
            _gen_lines("first")[0],
            b'{"response": "' + MALFORMED_MARKER.encode() + b'", "done": false',
            _gen_lines("third")[0],
        ]
        app = _ndjson_app(record, state, lines=lines)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError) as excinfo:
                async for _ in stream:
                    pass
            assert MALFORMED_MARKER not in str(excinfo.value)
            assert PROMPT not in str(excinfo.value)
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_trailing_partial_line_is_error(self):
        record: list = []
        state: dict = {}
        lines = [_gen_lines("first")[0], b'{"model": "audit-model", "response": "par']
        app = _ndjson_app(record, state, lines=lines)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError):
                async for _ in stream:
                    pass
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_non_object_line_is_error(self):
        record: list = []
        state: dict = {}
        lines = [b'["not", "an", "object"]']
        app = _ndjson_app(record, state, lines=lines)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError):
                async for _ in stream:
                    pass
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_timeout_before_first_line(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(record, state, lines=_gen_lines("late"), delay_before=1.0)
        runner, base_url = await _start(app)
        client = _client(base_url, timeout_seconds=0.2)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaTimeoutError):
                async for _ in stream:
                    pass
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_midstream_stall_times_out(self):
        record: list = []
        state: dict = {}
        app = _ndjson_app(record, state, lines=_gen_lines("first", "second"), delay_between=1.0)
        runner, base_url = await _start(app)
        client = _client(base_url, timeout_seconds=0.2)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            seen = []
            with pytest.raises(OllamaTimeoutError):
                async for item in stream:
                    seen.append(item.response)
            assert seen == ["first"]
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_response_cap_enforced(self):
        record: list = []
        state: dict = {}
        lines = [
            json.dumps({"model": MODEL, "response": "x" * 512, "done": False}).encode() + b"\n"
            for _ in range(8)
        ]
        payload_lines = [line.rstrip(b"\n") for line in lines]
        app = _ndjson_app(record, state, lines=payload_lines)
        runner, base_url = await _start(app)
        client = _client(base_url, max_response_bytes=1024)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError, match="exceeds"):
                async for _ in stream:
                    pass
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_consumer_cancellation_closes_response(self):
        """Consumer reads one chunk then abandons the stream: the fake
        must observe the close (paced sender, never completes) and the
        client session must stay usable afterwards."""
        record: list = []
        state: dict = {}
        lines = _gen_lines(*[f"chunk-{i}" for i in range(20)], done=False)
        app = _ndjson_app(record, state, lines=lines, delay_between=0.05)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            first = None
            async for item in stream:
                first = item.response
                break
            assert first == "chunk-0"
            await stream.aclose()
            await _wait_for_server_observation(state)
            assert state.get("completed", False) is False
            assert state.get("disconnected", False) is True
            assert client._session is not None and not client._session.closed
        finally:
            await client.close()
            await runner.cleanup()

    async def test_stream_redirect_refused(self):
        """Streaming inherits the shared redirect policy (IF-02)."""
        record: list = []
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            return web.Response(status=307, headers={"Location": "/api/generate"})

        app.router.add_post("/api/generate", handler)
        runner, base_url = await _start(app)
        client = _client(base_url)
        try:
            stream = await client.generate(
                GenerationRequest(model=MODEL, prompt=PROMPT), stream=True
            )
            with pytest.raises(OllamaError, match="redirect"):
                async for _ in stream:
                    pass
            assert record == []
        finally:
            await client.close()
            await runner.cleanup()
