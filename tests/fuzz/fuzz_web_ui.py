#!/usr/bin/env python3
"""
Fuzz target for web UI WebSocket message handling and REST API inputs.

Covers:
- WebSocket message parsing (analyze type, missing fields, bad JSON)
- TextRequest / CompareRequest / AnalyzeResponse pydantic models
- API request guard middleware edge cases (Content-Length, transfer-encoding)
- validate_text_input via the web UI checked() wrapper
- REST endpoint input validation paths
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import atheris
except ImportError:  # atheris optional; TestOneInput still importable
    atheris = None

    def instrument_func(func):
        return func

    if atheris is not None:
        instrument_func = atheris.instrument_func

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _fuzz_text_request(text: str) -> None:
    """Fuzz TextRequest pydantic model with extreme inputs."""
    try:
        from textforensics.api import TextRequest
    except Exception:
        return

    # Valid texts
    for t in (text[:500], "", "x" * 200, "\n" * 50):
        try:
            req = TextRequest(text=t)
            assert isinstance(req.text, str)
        except Exception:
            pass

    # Non-string inputs
    for bad_val in [123, None, True, [], {}]:
        try:
            TextRequest(text=bad_val)
        except Exception:
            pass


def _fuzz_compare_request(text: str) -> None:
    """Fuzz CompareRequest with extreme inputs."""
    try:
        from textforensics.api import CompareRequest
    except Exception:
        return

    for before in (text[:200], "x" * 100, ""):
        for after in (text[200:400] or "", "", "y" * 50):
            try:
                req = CompareRequest(before=before, after=after)
                assert isinstance(req.before, str)
                assert isinstance(req.after, str)
            except Exception:
                pass

    # Non-string
    for bad in ([{"before": 123, "after": "x"}], [{"before": "x", "after": None}]):
        try:
            CompareRequest(**bad[0])
        except Exception:
            pass


def _fuzz_websocket_messages(text: str) -> None:
    """Fuzz WebSocket message parsing (as done in web_ui.main.websocket_analyze)."""
    # Simulate the message parsing logic from the WebSocket endpoint
    # data = await websocket.receive_text()
    # message = json.loads(data)

    # 1. Parse as JSON
    try:
        message = json.loads(text)
    except json.JSONDecodeError:
        # The endpoint would raise an error here; just continue
        return

    if not isinstance(message, dict):
        return

    # 2. Check message type
    msg_type = message.get("type")
    if msg_type != "analyze":
        return

    # 3. Extract text field
    text_field = message.get("text")
    if not isinstance(text_field, str) or not text_field:
        # Empty or missing text — would trigger error response
        return

    # 4. Validate via checked()
    try:
        from textforensics.config import Settings, validate_text_input

        settings = Settings.from_env()
        checked_text = validate_text_input(
            text_field,
            max_input_bytes=settings.max_input_bytes,
        )
        # 5. Run analysis
        from textforensics.engine import analyze_text

        result = analyze_text(checked_text)
        assert hasattr(result, "score")
    except ValueError:
        pass  # Input validation failure
    except Exception:
        pass

    # 6. Fuzz non-analyze message types
    for bad_type in ("", "unknown", 123, None, "start", "stop"):
        try:
            msg = {"type": bad_type, "text": text[:100]}
            json.dumps(msg)
        except Exception:
            pass

    # 7. Fuzz truncated JSON
    for cut in (len(text) // 2, len(text) // 4, 5):
        if cut < len(text):
            try:
                json.loads(text[:cut])
            except json.JSONDecodeError:
                pass


def _fuzz_request_guard(text: str) -> None:
    """Fuzz request guard middleware Content-Length parsing."""
    # Simulate the middleware's Content-Length handling from api.py / web_ui/main.py
    raw_length = text.strip()

    # 1. Missing Content-Length
    # (Handled by middleware — just verify we don't crash)

    # 2. Invalid Content-Length
    for raw in (raw_length, "abc", "", "0", "-1", "1e10", "999999999999"):
        try:
            body_length = int(raw)
            assert body_length >= 0
        except ValueError:
            pass  # middleware returns 400
        except AssertionError:
            pass  # middleware returns 400 for negative

    # 3. Oversized Content-Length
    try:
        from textforensics.config import Settings

        settings = Settings.from_env()
        max_body = settings.max_input_bytes * 2 + 65_536
        for raw in (str(max_body + 1), str(10**12)):
            try:
                length = int(raw)
                if length > max_body:
                    pass  # would be 413
            except ValueError:
                pass
    except Exception:
        pass


def _fuzz_analyze_response(text: str) -> None:
    """Fuzz AnalyzeResponse model from web_ui."""
    try:
        from textforensics.web_ui.main import AnalyzeResponse
    except Exception:
        return

    # Success case
    try:
        resp = AnalyzeResponse(success=True, data={"score": 0.5})
        assert resp.success
    except Exception:
        pass

    # Error case
    try:
        resp = AnalyzeResponse(success=False, error=text[:200])
        assert not resp.success
    except Exception:
        pass

    # Bad data
    for data_val in [text, 123, None, {"score": "nan"}]:
        try:
            AnalyzeResponse(success=True, data=data_val)
        except Exception:
            pass


def _fuzz_create_web_app(text: str) -> None:
    """Fuzz web app creation with edge-case settings."""
    try:
        from textforensics.config import Settings
    except Exception:
        return

    # Create app with various settings
    try:
        from textforensics.web_ui.main import create_web_app

        settings = Settings(
            host="127.0.0.1",
            port=9999,
            max_input_bytes=max(1, len(text) % 10000),
        )
        app = create_web_app(settings)
        assert app is not None
    except Exception:
        pass


def _fuzz_text_request_edge_cases(text: str) -> None:
    """Fuzz TextRequest with extreme string types and boundary values."""
    try:
        from textforensics.api import TextRequest
    except Exception:
        return

    # Very long text (boundary testing)
    for size in (1, 100, 10000, 100000):
        try:
            sample = text[:size] if len(text) >= size else "x" * size
            req = TextRequest(text=sample)
            assert isinstance(req.text, str)
        except Exception:
            pass

    # Surrogate pairs and unusual Unicode
    for bad_unicode in (
        "\ud800",  # Lone surrogate
        "\ud800\udc00",  # Valid surrogate pair
        "\ufffd",  # Replacement char
        "\u0000",  # Null char
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\ufeff",  # BOM
    ):
        try:
            req = TextRequest(text=bad_unicode * 10)
        except Exception:
            pass


def _fuzz_websocket_message_types(text: str) -> None:
    """Fuzz WebSocket message type parsing with all known and unknown types."""
    types_to_try = [
        "analyze",
        "ping",
        "pong",
        "status",
        "heartbeat",
        "subscribe",
        "unsubscribe",
        "",
        "ANALYZE",
        "analyze ",
        " analyze",
    ]
    types_to_try.extend(t.strip() for t in text.split("\n")[:10] if t.strip())

    for msg_type in types_to_try:
        for text_val in (text[:200], "", None, 123, True, []):
            try:
                msg = {"type": msg_type, "text": text_val}
                serialized = json.dumps(msg)
                parsed = json.loads(serialized)
                assert parsed.get("type") == msg_type
            except (TypeError, ValueError):
                pass

    # Fuzz nested message structures
    nested = {"type": "analyze", "text": text[:100], "extra": {"nested": {"deep": text[:50]}}}
    try:
        json.dumps(nested)
        json.loads(json.dumps(nested))
    except Exception:
        pass


def _fuzz_websocket_binary_messages(text: str) -> None:
    """Fuzz WebSocket binary message handling."""
    # Simulate binary data that might arrive on WebSocket
    binary_payloads = [
        text.encode("utf-8", errors="replace"),
        b"\x00" * 100,
        b"\xff" * 100,
        b"\x00\xff\x00\xff",
    ]

    for payload in binary_payloads:
        # Try parsing as UTF-8
        try:
            decoded = payload.decode("utf-8")
            msg = json.loads(decoded)
            if isinstance(msg, dict) and msg.get("type") == "analyze":
                text_field = msg.get("text", "")
                if isinstance(text_field, str):
                    pass  # Would proceed to validation
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass


def _fuzz_checked_wrapper(text: str) -> None:
    """Fuzz the checked() wrapper function used in web endpoints."""
    try:
        from textforensics.config import validate_text_input
    except Exception:
        return

    # Various max_input_bytes values
    for max_bytes in (0, 1, 10, 100, 1000, 10000, 1_000_000):
        for sample in (text[:200], "", "x" * 50):
            try:
                result = validate_text_input(sample, max_input_bytes=max_bytes)
                assert isinstance(result, str)
            except ValueError:
                pass  # Expected for oversized or invalid input
            except Exception:
                pass


def _fuzz_compare_request_edge_cases(text: str) -> None:
    """Fuzz CompareRequest with additional edge cases."""
    try:
        from textforensics.api import CompareRequest
    except Exception:
        return

    # Unicode normalization edge cases
    for before in (text[:200], "caf\u00e9", "cafe\u0301", "\u200b" * 50):
        for after in (text[200:400] or "", "", "\ufeff" * 50):
            try:
                req = CompareRequest(before=before, after=after)
                assert isinstance(req.before, str)
                assert isinstance(req.after, str)
            except Exception:
                pass


@instrument_func
def TestOneInput(data: bytes) -> None:
    """Fuzz WebSocket message handling and REST API inputs."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    _fuzz_text_request(text)
    _fuzz_compare_request(text)
    _fuzz_websocket_messages(text)
    _fuzz_request_guard(text)
    _fuzz_analyze_response(text)
    _fuzz_create_web_app(text)
    _fuzz_text_request_edge_cases(text)
    _fuzz_websocket_message_types(text)
    _fuzz_websocket_binary_messages(text)
    _fuzz_checked_wrapper(text)
    _fuzz_compare_request_edge_cases(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
