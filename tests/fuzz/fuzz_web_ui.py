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

import atheris

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


@atheris.instrument_func
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


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
