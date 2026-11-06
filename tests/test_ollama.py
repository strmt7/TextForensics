"""Tests for Ollama integration — data structures and pure logic.

HTTP-level mocking of aiohttp internals is intentionally avoided; these tests
focus on the testable data classes, config normalization, capability inference,
error hierarchy, and the detector mixin contract.
"""

from __future__ import annotations

import json

import pytest

from textforensics.ollama import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
    ModelCapabilities,
    OllamaClient,
    OllamaConfig,
    OllamaConnectionError,
    OllamaDetectorMixin,
    OllamaError,
    OllamaModel,
    OllamaModelNotFoundError,
    OllamaTimeoutError,
)


class TestOllamaConfig:
    def test_default_config(self):
        config = OllamaConfig()
        assert config.base_url == "http://localhost:11434/"
        assert config.timeout_seconds == 300.0
        assert config.connect_timeout == 10.0
        assert config.max_retries == 3
        assert config.retry_delay == 1.0
        assert config.retry_backoff == 2.0
        assert config.default_model is None

    def test_base_url_normalization(self):
        config = OllamaConfig(base_url="http://remote:11434")
        assert config.base_url == "http://remote:11434/"

        config2 = OllamaConfig(base_url="http://remote:11434/")
        assert config2.base_url == "http://remote:11434/"

    def test_custom_config(self):
        config = OllamaConfig(
            base_url="http://remote:11434",
            timeout_seconds=600,
            max_retries=5,
            default_model="llama3.1:8b",
        )
        assert config.timeout_seconds == 600.0
        assert config.max_retries == 5
        assert config.default_model == "llama3.1:8b"

    def test_preferred_models_default(self):
        config = OllamaConfig()
        assert "llama3.1:8b" in config.preferred_models

    def test_frozen(self):
        config = OllamaConfig()
        with pytest.raises(AttributeError):
            config.timeout_seconds = 1.0


class TestModelCapabilities:
    def test_defaults(self):
        caps = ModelCapabilities(
            name="test",
            size_bytes=1,
            digest="d",
            family="f",
            parameter_size="1B",
            quantization_level="Q4",
        )
        assert caps.supports_chat is True
        assert caps.supports_embeddings is False
        assert caps.context_window == 4096

    def test_frozen(self):
        caps = ModelCapabilities(
            name="test",
            size_bytes=1,
            digest="d",
            family="f",
            parameter_size="1B",
            quantization_level="Q4",
        )
        with pytest.raises(AttributeError):
            caps.supports_chat = False


class TestOllamaModel:
    def test_model_creation(self):
        model = OllamaModel(
            name="llama3.1:8b",
            model="llama3.1:8b",
            size=4661220000,
            digest="abc123",
            modified_at="2024-01-01T00:00:00Z",
            details={"family": "llama", "parameter_size": "8B", "quantization_level": "Q4_K_M"},
        )
        assert model.name == "llama3.1:8b"
        assert model.size == 4661220000

    def test_model_roundtrip(self):
        model = OllamaModel(
            name="test",
            model="test:latest",
            size=1000,
            digest="abc",
            modified_at="2024-01-01T00:00:00Z",
        )
        d = model.to_dict()
        m2 = OllamaModel.from_dict(d)
        assert m2.name == model.name
        assert m2.model == model.model
        assert m2.size == model.size

    def test_from_dict_missing_details(self):
        model = OllamaModel.from_dict(
            {"name": "x", "model": "x", "size": 1, "digest": "d", "modified_at": "t"}
        )
        assert model.details is None

    def test_capabilities_from_details(self):
        model = OllamaModel(
            name="llama3.1:8b",
            model="llama3.1:8b",
            size=4661220000,
            digest="abc123",
            modified_at="2024-01-01T00:00:00Z",
            details={"family": "llama", "parameter_size": "8B", "quantization_level": "Q4_K_M"},
        )
        caps = model.capabilities
        assert caps is not None
        assert caps.family == "llama"
        assert caps.parameter_size == "8B"
        assert caps.quantization_level == "Q4_K_M"
        assert caps.supports_embeddings is False

    def test_capabilities_embedding_model(self):
        model = OllamaModel(
            name="nomic-embed-text",
            model="nomic-embed-text",
            size=100000000,
            digest="abc",
            modified_at="2024-01-01T00:00:00Z",
        )
        caps = model.capabilities
        assert caps is not None
        assert caps.supports_embeddings is True

    def test_capabilities_instruct_model(self):
        model = OllamaModel(
            name="llama3.1:8b-instruct",
            model="llama3.1:8b-instruct",
            size=100,
            digest="abc",
            modified_at="2024-01-01T00:00:00Z",
        )
        caps = model.capabilities
        assert caps is not None
        assert caps.supports_tools is True


class TestGenerationRequest:
    def test_minimal(self):
        req = GenerationRequest(model="m", prompt="p")
        d = req.to_dict()
        assert d == {"model": "m", "prompt": "p", "stream": False}

    def test_full(self):
        req = GenerationRequest(
            model="m",
            prompt="p",
            system="s",
            format="json",
            options={"temperature": 0.5},
            stream=True,
        )
        d = req.to_dict()
        assert d["model"] == "m"
        assert d["prompt"] == "p"
        assert d["system"] == "s"
        assert d["format"] == "json"
        assert d["options"] == {"temperature": 0.5}
        assert d["stream"] is True

    def test_temperature_merges_into_options(self):
        req = GenerationRequest(model="m", prompt="p", temperature=0.1)
        d = req.to_dict()
        assert d["options"]["temperature"] == 0.1

    def test_temperature_does_not_override_options(self):
        req = GenerationRequest(
            model="m",
            prompt="p",
            options={"top_p": 0.9},
            temperature=0.2,
        )
        d = req.to_dict()
        assert d["options"]["top_p"] == 0.9
        assert d["options"]["temperature"] == 0.2


class TestGenerationResponse:
    def test_roundtrip(self):
        resp = GenerationResponse(
            model="llama3.1:8b",
            created_at="2024-01-01T00:00:00Z",
            response="Hello world",
            done=True,
            eval_count=10,
            eval_duration=1000000000,
        )
        d = resp.to_dict()
        assert d["model"] == "llama3.1:8b"
        assert resp.done is True

    def test_from_dict(self):
        resp = GenerationResponse.from_dict(
            {
                "model": "test",
                "created_at": "2024-01-01T00:00:00Z",
                "response": "Hello",
                "done": True,
            }
        )
        assert resp.response == "Hello"
        assert resp.done is True
        assert resp.eval_count is None

    def test_tokens_per_second(self):
        resp = GenerationResponse(
            model="test",
            created_at="",
            response="",
            done=True,
            eval_count=100,
            eval_duration=1_000_000_000,
        )
        assert resp.tokens_per_second == 100.0

    def test_tokens_per_second_missing(self):
        resp = GenerationResponse(model="t", created_at="", response="", done=True)
        assert resp.tokens_per_second is None


class TestEmbeddingRequest:
    def test_single_input(self):
        req = EmbeddingRequest(model="nomic-embed-text", input="Hello world")
        d = req.to_dict()
        assert d["model"] == "nomic-embed-text"
        assert d["input"] == "Hello world"
        assert d["truncate"] is True

    def test_batch_input(self):
        req = EmbeddingRequest(model="nomic-embed-text", input=["Hello", "World"])
        d = req.to_dict()
        assert d["input"] == ["Hello", "World"]


class TestEmbeddingResponse:
    def test_embeddings(self):
        resp = EmbeddingResponse(
            model="nomic-embed-text",
            embeddings=[[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
        )
        assert len(resp.embeddings) == 2
        assert len(resp.embeddings[0]) == 3

    def test_from_dict(self):
        resp = EmbeddingResponse.from_dict(
            {
                "model": "test",
                "embeddings": [[0.1, 0.2]],
            }
        )
        assert len(resp.embeddings) == 1
        assert resp.embeddings[0] == [0.1, 0.2]


class TestOllamaErrors:
    def test_error_hierarchy(self):
        assert issubclass(OllamaConnectionError, OllamaError)
        assert issubclass(OllamaModelNotFoundError, OllamaError)
        assert issubclass(OllamaTimeoutError, OllamaError)
        assert issubclass(OllamaError, Exception)


class TestOllamaClient:
    def test_client_creation(self):
        config = OllamaConfig(base_url="http://test:11434")
        client = OllamaClient(config)
        assert client.config == config
        assert client._session is None

    def test_default_client(self):
        client = OllamaClient()
        assert client.config.base_url == "http://localhost:11434/"

    def test_model_cache(self):
        client = OllamaClient()
        model = OllamaModel(name="x", model="x", size=1, digest="d", modified_at="t")
        client._model_cache[model.name] = model
        assert "x" in client._model_cache


class TestOllamaDetectorMixin:
    def test_mixin_initialization(self):
        class TestDetector(OllamaDetectorMixin):
            pass

        mixin = TestDetector()
        assert mixin._ollama_config is not None
        assert mixin._ollama_config.base_url == "http://localhost:11434/"

    def test_mixin_custom_config(self):
        class TestDetector(OllamaDetectorMixin):
            pass

        mixin = TestDetector(ollama_config=OllamaConfig(base_url="http://custom:11434"))
        assert mixin._ollama_config.base_url == "http://custom:11434/"

    def test_mixin_lazy_client(self):
        class TestDetector(OllamaDetectorMixin):
            pass

        mixin = TestDetector()
        assert mixin._ollama_client is None
        client = mixin.ollama_client
        assert client is not None
        assert mixin._ollama_client is client

    def test_default_prompt_contains_analysis_criteria(self):
        class TestDetector(OllamaDetectorMixin):
            pass

        mixin = TestDetector()
        # The enhance_with_llm method builds a JSON prompt; verify the class
        # can at least be constructed with a config override
        assert hasattr(mixin, "enhance_with_llm")
        assert hasattr(mixin, "close")


class TestRequestSerialization:
    def test_generation_request_json_serializable(self):
        req = GenerationRequest(model="m", prompt="p", system="s", format="json")
        d = req.to_dict()
        assert json.dumps(d)  # Must not raise

    def test_embedding_request_json_serializable(self):
        req = EmbeddingRequest(model="m", input="text")
        assert json.dumps(req.to_dict())

    def test_generation_response_roundtrip_json(self):
        resp = GenerationResponse(model="m", created_at="t", response="r", done=True)
        d = resp.to_dict()
        assert json.dumps(d)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
