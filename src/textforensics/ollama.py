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
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import aiohttp

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
    """Base exception for Ollama-related errors."""

    pass


class OllamaConnectionError(OllamaError):
    """Raised when connection to Ollama server fails."""

    pass


class OllamaModelNotFoundError(OllamaError):
    """Raised when requested model is not available."""

    pass


class OllamaTimeoutError(OllamaError):
    """Raised when request times out."""

    pass


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
        """Make HTTP request with retry logic."""
        await self._ensure_session()

        url = f"{self.config.base_url}{endpoint}"
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            try:
                response = await self._session.request(
                    method,
                    url,
                    json=json_data,
                    headers={"Content-Type": "application/json"},
                )

                status = int(getattr(response, "status", 200))
                if status >= 400:
                    error_text = await response.text()
                    if status == 404:
                        raise OllamaModelNotFoundError(f"Model not found: {error_text}")
                    raise OllamaError(f"HTTP {status}: {error_text}")

                return response

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
            async for line in response.content:
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
        """Stream generation response."""
        async with self._session.post(
            f"{self.config.base_url}api/generate",
            json=data,
        ) as response:
            async for line in response.content:
                if line:
                    data = json.loads(line)
                    yield GenerationResponse.from_dict(data)

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
        async with self._session.post(
            f"{self.config.base_url}api/chat",
            json=data,
        ) as response:
            async for line in response.content:
                if line:
                    yield json.loads(line)

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
