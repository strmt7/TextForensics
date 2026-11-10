"""Ollama / Local LLM Integration for TextForensics.

Provides integration with Ollama and compatible local LLM servers for
enhanced AI-text detection capabilities. Supports both direct detection
and detector calibration assistance using local LLMs.

Features:
- Async HTTP client for Ollama API
- Model management (list, pull, show, delete)
- Streaming and non-streaming generation
- Structured output parsing for detector outputs
- Automatic model selection based on capabilities
- Fallback handling for unavailable models
- Request/response logging for audit trail
- Connection pooling and retry logic

Design principles:
- Local-first: No external dependencies beyond local Ollama server
- Graceful degradation: Graceful fallback when Ollama unavailable
- Audit-friendly: All requests/responses can be logged
- Configurable: Timeouts, retries, model preferences
- Extensible: Plugin architecture for custom parsers
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from .execution_policy import diagnostic_record, new_request_id, public_error_body

logger = logging.getLogger(__name__)

# Redirect statuses that carry a Location (RFC 9110 §15.4). 307/308 preserve
# the method and body; 301/302/303 may convert POST to GET.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Separate, smaller cap for provider error bodies (IF-09): error bodies are
# drained under this budget and then discarded, never echoed.
_DEFAULT_ERROR_BODY_BYTES = 4096

__all__ = [
    "OllamaConfig",
    "OllamaModel",
    "OllamaClient",
    "OllamaError",
    "ModelCapabilities",
    "GenerationRequest",
    "GenerationResponse",
    "EmbeddingRequest",
    "EmbeddingResponse",
    "OllamaDetectorMixin",
]


class OllamaError(Exception):
    """Base exception for Ollama-related errors.

    Provider errors never echo prompt/response text or provider bodies:
    the message is a stable generic string plus an opaque ``request_id``
    for correlation with the text-free private diagnostic record (see
    :func:`textforensics.execution_policy.diagnostic_record`). ``status_code``
    is the provider HTTP status when one was received, else ``None``.
    """

    request_id: str | None = None
    status_code: int | None = None


class OllamaConnectionError(OllamaError):
    """Raised when connection to Ollama server fails."""

    pass


class OllamaModelNotFoundError(OllamaError):
    """Raised when requested model is not available."""

    pass


class OllamaTimeoutError(OllamaError):
    """Raised when request times out."""

    pass


def _is_loopback_host(host: str) -> bool:
    """True for loopback hosts only (localhost, 127/8, ::1)."""
    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_base_url(base_url: str, *, allow_remote_host: bool) -> None:
    """Reject non-loopback Ollama endpoints unless explicitly opted in.

    An Ollama URL is an SSRF vector: every request POSTs submitted text
    to it. The default therefore allows only loopback hosts; a remote
    host (including a LAN/Docker service name) requires
    ``allow_remote_host=True`` — an explicit, auditable opt-in.
    """
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Ollama base_url must use http(s): {base_url!r}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"Ollama base_url has no host: {base_url!r}")
    if not allow_remote_host and not _is_loopback_host(host):
        raise ValueError(
            "Refusing non-loopback Ollama base_url without explicit opt-in. "
            f"Got {base_url!r}; pass allow_remote_host=True to use a remote host."
        )


def _close_response(response: Any) -> None:
    """Best-effort synchronous close of a response (no-op for fakes)."""
    close = getattr(response, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):  # close is idempotent
            close()


async def _consume_capped(response: Any, *, max_bytes: int) -> bytes | None:
    """Read a response incrementally under a cumulative byte cap.

    Counts decompressed bytes (``aiohttp`` yields decompressed chunks from
    ``response.content``), so a gzip body is budgeted on its real size.
    Returns the full body when it fits, else closes the response
    immediately and returns ``None`` — the caller must not retain more
    than the cap plus one chunk. Sets ``response._body`` on success so
    later ``response.json()`` / ``response.text()`` calls reuse the
    already-read bytes instead of re-reading an exhausted stream.
    """
    content = getattr(response, "content", None)
    iter_chunked = getattr(content, "iter_chunked", None)
    if iter_chunked is None:  # pragma: no cover - non-aiohttp fakes only
        body = await response.read()
        if len(body) > max_bytes:
            _close_response(response)
            return None
        return body
    buf = bytearray()
    async for chunk in iter_chunked(8192):
        if not chunk:
            continue
        buf += chunk
        if len(buf) > max_bytes:
            _close_response(response)
            return None
    body = bytes(buf)
    with contextlib.suppress(Exception):  # pragma: no cover - defensive
        response._body = body
    return body


async def _read_capped(response: Any, *, max_bytes: int) -> bytes:
    """Read a whole response under a cumulative byte cap, or raise.

    The shared reader for all ordinary (non-streaming) operations: on
    overflow the response is closed immediately — before the sender has
    finished — and the retained buffer is bounded to the cap plus one
    chunk. The raised error carries no body text.
    """
    body = await _consume_capped(response, max_bytes=max_bytes)
    if body is None:
        raise OllamaError(f"Ollama response exceeds {max_bytes} bytes")
    return body


async def _iter_capped_lines(
    response: aiohttp.ClientResponse, *, max_bytes: int
) -> AsyncIterator[bytes]:
    """Yield streamed response lines, enforcing a total size cap.

    The shared reader for all streaming operations: the same cumulative
    byte cap as :func:`_read_capped`, counting decompressed bytes. On
    overflow — or when the consumer stops early — the response is closed
    deterministically in the ``finally`` block, so a paced sender
    observes the close before completing an over-budget body.
    """
    total = 0
    try:
        async for line in response.content:
            total += len(line)
            if total > max_bytes:
                raise OllamaError(f"Ollama response exceeds {max_bytes} bytes")
            yield line
    finally:
        _close_response(response)


def _validate_redirect_destination(url: str, *, allow_remote_host: bool) -> None:
    """Reject a redirect destination that violates the host policy.

    Every hop is validated against the same policy as the initial URL
    (loopback-only unless ``allow_remote_host`` was explicitly opted
    in) *before* any request body is forwarded to it. The raised error
    never contains the destination URL.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not host:
        raise OllamaError("Ollama redirect refused: destination is not a valid http(s) URL.")
    if not allow_remote_host and not _is_loopback_host(host):
        logger.debug("Redirect destination refused for host: %s", host)
        raise OllamaError(
            "Ollama redirect refused: destination is not permitted by the Ollama host policy."
        )


def _redirect_refused(request_id: str, *, reason: str) -> OllamaError:
    """Build the (URL-free, body-free) error for a refused redirect."""
    exc = OllamaError(f"Ollama redirect refused: {reason} (request_id={request_id})")
    exc.request_id = request_id
    return exc


def _raise_provider_error(status: int, *, request_id: str) -> None:
    """Raise the redacted provider error for an HTTP error status.

    Uses the shared redaction contract
    (:func:`textforensics.execution_policy.public_error_body`): the
    message is a stable generic string plus the opaque request ID. The
    provider error body is never included — it may echo the submitted
    prompt. The private diagnostic record is text-free (error type +
    request ID only) and is logged, not returned.
    """
    body = public_error_body(status, request_id=request_id)
    message = f"{body['detail']} (request_id={request_id})"
    exc: OllamaError = OllamaModelNotFoundError(message) if status == 404 else OllamaError(message)
    exc.request_id = request_id
    exc.status_code = status
    logger.debug("Ollama provider error: %s", diagnostic_record(exc, request_id=request_id))
    raise exc


@dataclass(frozen=True, slots=True)
class OllamaConfig:
    """Configuration for Ollama client."""

    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 300.0  # 5 minutes for generation
    connect_timeout: float = 10.0
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    verify_ssl: bool = True
    default_model: str | None = None
    allow_remote_host: bool = False
    max_response_bytes: int = 10_000_000  # 10 MB cap on any single response
    max_error_body_bytes: int = _DEFAULT_ERROR_BODY_BYTES
    # Redirects are disabled by default (IF-02): a redirecting endpoint
    # could otherwise forward the submitted prompt to a host the
    # loopback-only policy never approved. Opt in with
    # ``allow_redirects=True``; every hop is then validated against the
    # same host policy before any body is forwarded, and the chain is
    # bounded by ``max_redirects`` and recorded on the client.
    allow_redirects: bool = False
    max_redirects: int = 5
    preferred_models: list[str] = field(
        default_factory=lambda: [
            "llama3.1:8b",
            "llama3.1:70b",
            "mistral:7b",
            "mixtral:8x7b",
            "phi3:14b",
            "qwen2.5:7b",
            "gemma2:9b",
        ]
    )

    def __post_init__(self) -> None:
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if self.max_error_body_bytes <= 0:
            raise ValueError("max_error_body_bytes must be positive")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be zero or positive")
        _validate_base_url(self.base_url, allow_remote_host=self.allow_remote_host)
        if not self.base_url.endswith("/"):
            object.__setattr__(self, "base_url", self.base_url + "/")


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    """Capabilities of an Ollama model."""

    name: str
    size_bytes: int
    digest: str
    family: str
    parameter_size: str
    quantization_level: str
    context_window: int = 4096
    supports_chat: bool = True
    supports_completion: bool = True
    supports_embeddings: bool = False
    supports_tools: bool = False
    modality: str = "text"  # "text", "vision", "multimodal"


@dataclass(frozen=True, slots=True)
class OllamaModel:
    """Information about an available Ollama model."""

    name: str
    model: str  # Full model identifier (e.g., "llama3.1:8b")
    size: int
    digest: str
    modified_at: str
    details: dict[str, Any] | None = None

    @property
    def capabilities(self) -> ModelCapabilities | None:
        """Extract capabilities from model details or infer from model name."""
        # Extract family and parameter size from details if available
        family = ""
        param_size = ""
        quant_level = ""
        if self.details:
            family = self.details.get("family", "")
            param_size = self.details.get("parameter_size", "")
            quant_level = self.details.get("quantization_level", "")

        # Determine capabilities from model name/family
        supports_embeddings = "embed" in self.model.lower() or "nomic" in self.model.lower()
        supports_tools = any(x in self.model.lower() for x in ["tool", "function", "instruct"])

        return ModelCapabilities(
            name=self.name,
            size_bytes=self.size,
            digest=self.digest,
            family=family,
            parameter_size=param_size,
            quantization_level=quant_level,
            supports_embeddings=supports_embeddings,
            supports_tools=supports_tools,
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "name": self.name,
            "model": self.model,
            "size": self.size,
            "digest": self.digest,
            "modified_at": self.modified_at,
        }
        if self.details:
            result["details"] = self.details
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OllamaModel:
        return cls(
            name=data.get("name", ""),
            model=data.get("model", ""),
            size=data.get("size", 0),
            digest=data.get("digest", ""),
            modified_at=data.get("modified_at", ""),
            details=data.get("details"),
        )


@dataclass(frozen=True, slots=True)
class GenerationRequest:
    """Request for text generation."""

    model: str
    prompt: str
    system: str | None = None
    template: str | None = None
    context: list[int] | None = None
    options: dict[str, Any] | None = None
    stream: bool = False
    raw: bool = False
    keep_alive: str | None = None
    format: str | None = None  # "json", "yaml", etc.
    think: bool = False
    temperature: float | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "model": self.model,
            "prompt": self.prompt,
            "stream": self.stream,
        }
        if self.system is not None:
            data["system"] = self.system
        if self.template is not None:
            data["template"] = self.template
        if self.context is not None:
            data["context"] = self.context
        if self.options is not None:
            data["options"] = self.options
        if self.raw:
            data["raw"] = True
        if self.keep_alive is not None:
            data["keep_alive"] = self.keep_alive
        if self.format is not None:
            data["format"] = self.format
        if self.think:
            data["think"] = True
        if self.temperature is not None:
            if "options" not in data:
                data["options"] = {}
            data["options"]["temperature"] = self.temperature
        return data


@dataclass(frozen=True, slots=True)
class GenerationResponse:
    """Response from text generation."""

    model: str
    created_at: str
    response: str
    done: bool
    context: list[int] | None = None
    total_duration: int | None = None  # nanoseconds
    load_duration: int | None = None
    prompt_eval_count: int | None = None
    prompt_eval_duration: int | None = None
    eval_count: int | None = None
    eval_duration: int | None = None
    done_reason: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GenerationResponse:
        return cls(
            model=data.get("model", ""),
            created_at=data.get("created_at", ""),
            response=data.get("response", ""),
            done=data.get("done", False),
            context=data.get("context"),
            total_duration=data.get("total_duration"),
            load_duration=data.get("load_duration"),
            prompt_eval_count=data.get("prompt_eval_count"),
            prompt_eval_duration=data.get("prompt_eval_duration"),
            eval_count=data.get("eval_count"),
            eval_duration=data.get("eval_duration"),
            done_reason=data.get("done_reason"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "created_at": self.created_at,
            "response": self.response,
            "done": self.done,
            "context": self.context,
            "total_duration": self.total_duration,
            "load_duration": self.load_duration,
            "prompt_eval_count": self.prompt_eval_count,
            "prompt_eval_duration": self.prompt_eval_duration,
            "eval_count": self.eval_count,
            "eval_duration": self.eval_duration,
            "done_reason": self.done_reason,
        }

    @property
    def tokens_per_second(self) -> float | None:
        """Calculate tokens per second if eval data available."""
        if self.eval_count and self.eval_duration and self.eval_duration > 0:
            return (self.eval_count / self.eval_duration) * 1_000_000_000
        return None


@dataclass(frozen=True, slots=True)
class EmbeddingRequest:
    """Request for text embeddings."""

    model: str
    input: str | list[str]
    truncate: bool = True
    options: dict[str, Any] | None = None
    keep_alive: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {"model": self.model, "input": self.input}
        if self.truncate:
            data["truncate"] = True
        if self.options:
            data["options"] = self.options
        if self.keep_alive:
            data["keep_alive"] = self.keep_alive
        return data


@dataclass(frozen=True, slots=True)
class EmbeddingResponse:
    """Response containing embeddings."""

    model: str
    embeddings: list[list[float]]
    total_duration: int | None = None
    load_duration: int | None = None
    prompt_eval_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmbeddingResponse:
        return cls(
            model=data.get("model", ""),
            embeddings=data.get("embeddings", []),
            total_duration=data.get("total_duration"),
            load_duration=data.get("load_duration"),
            prompt_eval_count=data.get("prompt_eval_count"),
        )


class OllamaClient:
    """Async client for Ollama API with connection pooling and retry logic."""

    def __init__(self, config: OllamaConfig | None = None):
        self.config = config or OllamaConfig()
        self._session: aiohttp.ClientSession | None = None
        self._model_cache: dict[str, OllamaModel] = {}
        self._cache_timestamp: float = 0
        self._cache_ttl = 300  # 5 minutes
        # Redirect hops followed by the most recent request, as
        # (status, destination host) pairs — bounded, auditable, and
        # free of URLs, query strings and request bodies.
        self._last_redirect_chain: tuple[tuple[int, str], ...] = ()

    @property
    def last_redirect_chain(self) -> tuple[tuple[int, str], ...]:
        """Redirect hops followed by the most recent request.

        Each entry is ``(status, destination host)``. Empty when the
        last request followed no redirect (the default: redirects are
        refused, not followed).
        """
        return self._last_redirect_chain

    async def __aenter__(self) -> OllamaClient:
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        """Ensure aiohttp session exists."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.config.timeout_seconds,
                connect=self.config.connect_timeout,
            )
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                ssl=self.config.verify_ssl,
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": "TextForensics-Ollama/1.0"},
            )

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        json_data: dict | None = None,
        stream: bool = False,
    ) -> aiohttp.ClientResponse:
        """Make an HTTP request with retry logic.

        Retries cover transient transport failures only
        (``TimeoutError`` / ``aiohttp.ClientError``). Redirect refusals,
        response-cap overflows and provider errors raise immediately and
        are never retried: retrying a refused redirect or an over-budget
        body would re-send the prompt or re-read the body.
        """
        await self._ensure_session()

        url = f"{self.config.base_url}{endpoint}"
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            try:
                return await self._request_once(method, url, json_data, stream=stream)
            except TimeoutError:
                last_exception = OllamaTimeoutError(
                    f"Request timed out after {self.config.timeout_seconds}s"
                )
            except aiohttp.ClientError as e:
                last_exception = OllamaConnectionError(f"Connection error: {e}")

            if attempt < self.config.max_retries:
                delay = self.config.retry_delay * (self.config.retry_backoff**attempt)
                await asyncio.sleep(delay)

        raise last_exception or OllamaError("Max retries exceeded")

    async def _request_once(
        self,
        method: str,
        url: str,
        json_data: dict | None,
        *,
        stream: bool,
    ) -> aiohttp.ClientResponse:
        """One request attempt: bounded redirect loop, then capped read.

        Redirects are handled manually (``allow_redirects=False`` on the
        wire) so every destination is validated against the host policy
        before any request body is forwarded (IF-02). Error bodies are
        drained under a separate smaller cap and discarded, never echoed
        (IF-07). Non-streaming bodies are read incrementally under the
        response cap (IF-09); streaming responses are returned unread
        for the shared capped line reader.
        """
        request_id = new_request_id()
        current_method, current_json, current_url = method, json_data, url
        chain: list[tuple[int, str]] = []
        for hop in range(self.config.max_redirects + 1):
            response = await self._session.request(  # type: ignore[union-attr]
                current_method,
                current_url,
                json=current_json,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
            status = int(getattr(response, "status", 200))
            headers = getattr(response, "headers", None)
            location = headers.get("Location") if headers is not None else None
            if status in _REDIRECT_STATUSES and location:
                _close_response(response)
                if not self.config.allow_redirects:
                    self._last_redirect_chain = tuple(chain)
                    raise _redirect_refused(request_id, reason="redirects are disabled")
                destination = urljoin(current_url, location)
                _validate_redirect_destination(
                    destination, allow_remote_host=self.config.allow_remote_host
                )
                if hop >= self.config.max_redirects:
                    self._last_redirect_chain = tuple(chain)
                    raise _redirect_refused(
                        request_id,
                        reason=f"redirect limit of {self.config.max_redirects} exceeded",
                    )
                dest_host = urlparse(destination).hostname or ""
                chain.append((status, dest_host))
                logger.debug(
                    "Ollama redirect hop: %s -> host %s (request_id=%s)",
                    status,
                    dest_host,
                    request_id,
                )
                if status == 303 or (status in (301, 302) and current_method == "POST"):
                    # 303 always, and 301/302 for POST, convert to GET
                    # and drop the body: the prompt must not be
                    # re-sent as a GET body to the new destination.
                    current_method, current_json = "GET", None
                current_url = destination
                continue
            break
        self._last_redirect_chain = tuple(chain)

        if status >= 400:
            error_cap = min(self.config.max_error_body_bytes, self.config.max_response_bytes)
            await _consume_capped(response, max_bytes=error_cap)
            _close_response(response)
            _raise_provider_error(status, request_id=request_id)

        if not stream:
            await _read_capped(response, max_bytes=self.config.max_response_bytes)

        return response

    async def list_models(self, force_refresh: bool = False) -> list[OllamaModel]:
        """List available models."""
        now = time.time()
        if (
            not force_refresh
            and self._model_cache
            and (now - self._cache_timestamp) < self._cache_ttl
        ):
            return list(self._model_cache.values())

        response = await self._request("GET", "api/tags")
        data = await response.json()

        models = []
        for model_data in data.get("models", []):
            model = OllamaModel.from_dict(model_data)
            self._model_cache[model.name] = model
            models.append(model)

        self._cache_timestamp = time.time()
        return models

    async def get_model(self, name: str) -> OllamaModel | None:
        """Get a specific model by name."""
        models = await self.list_models()
        for model in models:
            if model.name == name or model.model == name:
                return model
        return None

    async def pull_model(self, name: str, stream: bool = True) -> AsyncIterator[dict]:
        """Pull a model from Ollama registry."""
        response = await self._request("POST", "api/pull", {"name": name, "stream": stream})

        if stream:
            async for line in _iter_capped_lines(
                response, max_bytes=self.config.max_response_bytes
            ):
                if line:
                    yield json.loads(line)
        else:
            data = await response.json()
            yield data

    async def delete_model(self, name: str) -> bool:
        """Delete a model."""
        response = await self._request("DELETE", "api/delete", {"name": name})
        await response.json()
        if name in self._model_cache:
            del self._model_cache[name]
        return True

    async def show_model_info(self, name: str) -> dict[str, Any]:
        """Get detailed model information."""
        response = await self._request("POST", "api/show", {"name": name})
        return await response.json()

    async def generate(
        self,
        request: GenerationRequest,
        *,
        stream: bool = False,
    ) -> GenerationResponse | AsyncIterator[GenerationResponse]:
        """Generate text using the model."""
        data = request.to_dict()

        if stream:
            return self._generate_stream(request.model, data)
        else:
            response = await self._request("POST", "api/generate", data)
            data = await response.json()
            return GenerationResponse.from_dict(data)

    async def _generate_stream(
        self,
        model: str,
        data: dict,
    ) -> AsyncIterator[GenerationResponse]:
        """Stream generation response.

        Routed through :meth:`_request` (``stream=True``) so streaming
        gets the same redirect validation, error classification and
        capped reader as ordinary requests (IF-02/IF-09); the response
        is closed deterministically when iteration ends, errors, or is
        abandoned. NOTE (W5 / IF-15): the ``stream`` argument of
        :meth:`generate` is deliberately NOT reconciled with the wire
        body here — that reconciliation, and the fresh-client
        session-setup contract, belong to W5.
        """
        response = await self._request("POST", "api/generate", data, stream=True)
        try:
            async for line in _iter_capped_lines(
                response, max_bytes=self.config.max_response_bytes
            ):
                if line:
                    data = json.loads(line)
                    yield GenerationResponse.from_dict(data)
        finally:
            _close_response(response)

    async def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        stream: bool = False,
        options: dict | None = None,
    ) -> dict | AsyncIterator[dict]:
        """Chat completion (for models that support chat)."""
        data = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        if options:
            data["options"] = options

        if stream:
            return self._chat_stream(model, data)
        else:
            response = await self._request("POST", "api/chat", data)
            return await response.json()

    async def _chat_stream(self, model: str, data: dict) -> AsyncIterator[dict]:
        """Stream chat responses through the shared request lifecycle.

        Same redirect / error / capped-reader protections as
        :meth:`_generate_stream` (IF-02/IF-09); response closed
        deterministically on end, error, or abandonment. The IF-15
        stream-flag reconciliation is W5-owned (see
        :meth:`_generate_stream`).
        """
        response = await self._request("POST", "api/chat", data, stream=True)
        try:
            async for line in _iter_capped_lines(
                response, max_bytes=self.config.max_response_bytes
            ):
                if line:
                    yield json.loads(line)
        finally:
            _close_response(response)

    async def embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embeddings for input text."""
        data = request.to_dict()
        response = await self._request("POST", "api/embeddings", request.to_dict())
        data = await response.json()
        return EmbeddingResponse.from_dict(data)

    async def check_health(self) -> bool:
        """Check if Ollama server is reachable."""
        try:
            response = await self._request("GET", "")
            return response.status == 200
        except Exception:
            return False

    async def get_version(self) -> str:
        """Get Ollama server version."""
        response = await self._request("GET", "api/version")
        data = await response.json()
        return data.get("version", "unknown")


class OllamaDetectorMixin:
    """Mixin to add Ollama-based detection capabilities to detectors.

    This mixin provides a standard interface for detectors that want to
    optionally use Ollama for enhanced detection.
    """

    # An Ollama-backed detector samples from the model, so repeated
    # runs on the same text may return different scores: it is declared
    # non-deterministic at seal time, and a replay mismatch for it is
    # reported as ``not_reproducible`` rather than a failure.
    deterministic = False
    determinism_reason = (
        "Ollama sampling is non-deterministic: repeated runs on the same "
        "text may return different scores."
    )

    def __init__(self, *args, ollama_config: OllamaConfig | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ollama_config = ollama_config or OllamaConfig()
        self._ollama_client: OllamaClient | None = None

    @property
    def ollama_client(self) -> OllamaClient:
        """Lazy initialization of Ollama client."""
        if self._ollama_client is None:
            self._ollama_client = OllamaClient(self._ollama_config)
        return self._ollama_client

    async def close(self) -> None:
        """Close Ollama client."""
        if self._ollama_client:
            await self._ollama_client.close()

    async def enhance_with_llm(
        self,
        text: str,
        *,
        model: str | None = None,
        prompt_template: str | None = None,
        system_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Enhance detection with LLM reasoning.

        Args:
            text: Text to analyze
            model: Ollama model to use (uses default if not specified)
            prompt_template: Custom prompt template
            system_prompt: System prompt for the LLM

        Returns:
            Dictionary with LLM analysis results
        """
        model = model or self._ollama_config.default_model

        if not model:
            models = await self.ollama_client.list_models()
            if models:
                model = models[0].name
            else:
                raise OllamaError("No models available")

        # Default prompt template for AI detection
        default_prompt = """Analyze the following text and determine if it was likely written by an AI or a human.
Consider:
- Vocabulary diversity and repetition patterns
- Sentence structure variety
- Logical coherence and flow
- Presence of typical AI markers (excessive hedging, perfect grammar, lack of idiosyncrasies)
- Stylistic consistency vs. natural variation

Text: {text}

Respond in JSON format:
{{
  "verdict": "ai" | "human" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "explanation",
  "indicators": ["indicator1", "indicator2"]
}}"""

        prompt = prompt_template or default_prompt
        prompt = prompt.format(text=text)

        system = (
            system_prompt
            or "You are an expert forensic linguist specializing in AI-generated text detection."
        )

        request = GenerationRequest(
            model=model,
            prompt=prompt,
            system=system,
            format="json",
            options={"temperature": 0.1, "top_p": 0.9},
        )

        response = await self.ollama_client.generate(request)
        try:
            return json.loads(response.response)
        except json.JSONDecodeError:
            return {
                "verdict": "uncertain",
                "confidence": 0.0,
                "reasoning": "Failed to parse LLM response",
                "indicators": ["parse_error"],
            }
