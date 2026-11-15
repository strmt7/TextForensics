"""W5 Worker F kill tests for ollama (audit-w5-f).

Kill evidence for the 14 runtime survivors in textforensics.ollama:

* ``*`` -> ``/`` (Mul_Div) on the keyword-only markers of
  ``_iter_stream_json`` (line 209), ``_validate_embeddings_response``
  (line 559), ``OllamaClient.generate`` (line 824) and
  ``OllamaClient.chat`` (line 877): the mutant makes the PRECEDING
  parameters positional-only, so the kill is passing them by keyword
  (``response=``, ``data=``, ``request=``, ``model=``/``messages=``),
  which the mutant rejects with TypeError at call time.
* ``EmbeddingRequest.to_dict`` AddNot on ``if self.options`` / ``if
  self.keep_alive`` (lines ~529/531): set values must be serialised.
* ``OllamaClient.chat`` ReplaceFalseWithTrue on the ``stream`` default
  (line 877): the default call must send ``"stream": False``.
* ``_validate_embeddings_response`` boolean/count/dimension checks:
  OrWithAnd on the no-embeddings guard (line 570), NotEq_IsNot /
  NotEq_Lt on the count check (line 572), NotEq_IsNot / NotEq_Lt on
  the dimension check (line 584), OrWithAnd on the per-value numeric
  check (line 588). The ``is not`` mutants are killed with 300-element
  inputs: CPython caches only -5..256, so ``len(...) is not 300`` is
  True even when the counts are equal.
"""

import pytest

from textforensics.ollama import (
    EmbeddingRequest,
    GenerationRequest,
    OllamaClient,
    OllamaError,
    _iter_stream_json,
    _validate_embeddings_response,
)


@pytest.mark.asyncio
async def test_iter_stream_json_max_bytes_is_keyword_only():
    """_iter_stream_json accepts max_bytes as a keyword argument.

    The ``*`` -> ``/`` mutant makes the PRECEDING parameter
    positional-only (``response, /, max_bytes``), so max_bytes stays
    callable by keyword -- the kill is passing ``response`` by keyword,
    which the mutant rejects.
    """
    gen = _iter_stream_json(response=object(), max_bytes=1024)
    await gen.aclose()


def test_validate_embeddings_response_expected_count_is_keyword_only():
    """_validate_embeddings_response accepts expected_count as a keyword.

    Same ``*`` -> ``/`` shape: the kill is passing ``data`` by keyword.
    """
    assert _validate_embeddings_response(data={"embeddings": [[1.0]]}, expected_count=1) == [[1.0]]


def test_generate_stream_is_keyword_only():
    """OllamaClient.generate accepts stream as a keyword argument."""
    client = OllamaClient()
    coro = client.generate(request=GenerationRequest(model="m", prompt="p"), stream=False)
    coro.close()


def test_chat_stream_is_keyword_only():
    """OllamaClient.chat accepts stream as a keyword argument."""
    client = OllamaClient()
    coro = client.chat(model="m", messages=[], stream=False)
    coro.close()


def test_embedding_request_to_dict_includes_set_options_and_keep_alive():
    """to_dict serialises options and keep_alive when they are set."""
    req = EmbeddingRequest(model="m", input="x", options={"temperature": 0.5}, keep_alive="5m")
    data = req.to_dict()
    assert data["options"] == {"temperature": 0.5}
    assert data["keep_alive"] == "5m"


def test_embedding_request_to_dict_omits_unset_options_and_keep_alive():
    """to_dict omits options and keep_alive when they are not set."""
    data = EmbeddingRequest(model="m", input="x").to_dict()
    assert "options" not in data
    assert "keep_alive" not in data


@pytest.mark.asyncio
async def test_chat_default_stream_is_false(monkeypatch):
    """chat() without stream sends stream=False to the API."""
    captured = {}

    class _FakeResponse:
        async def json(self):
            return {"ok": True}

    async def _fake_request(self, method, path, payload, **kwargs):
        captured.update(payload)
        return _FakeResponse()

    monkeypatch.setattr(OllamaClient, "_request", _fake_request)
    client = OllamaClient()
    assert await client.chat("m", [{"role": "user", "content": "hi"}]) == {"ok": True}
    assert captured["stream"] is False
    assert "options" not in captured


def test_validate_rejects_non_list_embeddings_with_no_embeddings_message():
    """A truthy non-list 'embeddings' reports 'no embeddings returned'."""
    with pytest.raises(OllamaError, match="no embeddings returned"):
        _validate_embeddings_response({"embeddings": "not-a-list"}, expected_count=1)


def test_validate_accepts_300_embeddings_for_expected_count_300():
    """300 embeddings satisfy expected_count=300 (kills 'is not')."""
    vectors = [[float(i)] for i in range(300)]
    assert _validate_embeddings_response({"embeddings": vectors}, expected_count=300) == [
        [float(i)] for i in range(300)
    ]


def test_validate_rejects_more_embeddings_than_expected():
    """More embeddings than expected raises (kills '<' on the count check)."""
    with pytest.raises(OllamaError, match="expected 1 embedding"):
        _validate_embeddings_response({"embeddings": [[1.0], [2.0]]}, expected_count=1)


def test_validate_accepts_two_300_dim_vectors():
    """Two 300-dim vectors are not ragged (kills 'is not' on dimensions)."""
    vectors = [[1.0] * 300, [2.0] * 300]
    assert _validate_embeddings_response({"embeddings": vectors}, expected_count=2) == vectors


def test_validate_rejects_longer_second_vector_as_ragged():
    """A longer second vector is ragged (kills '<' on the dimension check)."""
    with pytest.raises(OllamaError, match="ragged"):
        _validate_embeddings_response(
            {"embeddings": [[1.0, 2.0], [1.0, 2.0, 3.0]]}, expected_count=2
        )


def test_validate_rejects_bool_vector_value():
    """A bool vector value is non-numeric (kills 'and' on the value check)."""
    with pytest.raises(OllamaError, match="non-numeric"):
        _validate_embeddings_response({"embeddings": [[True]]}, expected_count=1)
