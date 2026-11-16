"""W9 refresh kill tests for the new live mutants in the A-fix code.

The A-fix added new code to ``textforensics.web_ui.main`` (the
None-sentinel import guard, ``_require_web()``, the ``serve_web()``
host/port defaults). The live mutants in that added code are killed
here or by the existing A-fix / D tests; this file covers the ones no
existing test observes:

- the ``serve_web()`` ``str | None`` / ``int | None`` annotations: the
  rendered signature pins the declared parameter types, so any change
  to the annotation text fails here (the rendering reads the
  annotation strings as written; it does not resolve them);
- ``_require_web()`` with only one of FastAPI / BaseModel missing: the
  guard must raise unless BOTH names are present, so a mutant that
  lets a half-present extra through fails here.
"""

import pytest


def test_serve_web_signature_pins_optional_host_port():
    """serve_web keeps its A-fix signature: host/port are optional.

    The A-fix made host/port default to the environment (``str | None``
    / ``int | None`` = None). Pinning the full rendered signature
    observes the declared parameter types, so any change to the
    annotation text fails here.
    """
    import inspect

    from textforensics.web_ui.main import serve_web

    assert str(inspect.signature(serve_web)) == (
        "(host: 'str | None' = None, port: 'int | None' = None, *, "
        "allow_remote: 'bool' = False, access_log: 'bool' = True, "
        "log_level: 'str' = 'info', max_input_bytes: 'int | None' = None, "
        "open_browser: 'bool' = False) -> 'None'"
    )


def test_require_web_raises_when_only_fastapi_missing(monkeypatch):
    """create_web_app refuses when only FastAPI is missing.

    The guard must raise unless BOTH names are present: a mutant that
    checks only one operand, or that requires both to be missing,
    would let a half-present extra through and fail here.
    """
    import textforensics.web_ui.main as web_main

    monkeypatch.setattr(web_main, "FastAPI", None)
    with pytest.raises(RuntimeError, match="Install web UI support"):
        web_main.create_web_app()


def test_require_web_raises_when_only_basemodel_missing(monkeypatch):
    """create_web_app refuses when only BaseModel is missing.

    Mirror of the FastAPI-only case: the guard must raise unless BOTH
    names are present.
    """
    import textforensics.web_ui.main as web_main

    monkeypatch.setattr(web_main, "BaseModel", None)
    with pytest.raises(RuntimeError, match="Install web UI support"):
        web_main.create_web_app()
