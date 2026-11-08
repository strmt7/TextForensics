# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

# Build-time trust knob for TLS-intercepting egress proxies (empty by
# default: pip verifies TLS normally). Behind such a proxy, pass e.g.
#   --build-arg PIP_TRUSTED_HOST=pypi.org,files.pythonhosted.org
# so pip accepts the proxy's re-signed certificate for PyPI hosts.
ARG PIP_TRUSTED_HOST

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120

WORKDIR /build

# Install build dependencies first for better layer caching
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Build wheels for the package and its API extras
# (PIP_TRUSTED_HOST is expanded by the Dockerfile parser from the ARG above;
# the sed turns a comma list into --trusted-host flags. pip's build-isolation
# subprocess does not honour PIP_TRUSTED_HOST from the environment, so the
# flags must be on the command line. Empty by default: no flags, TLS verified.)
RUN python -m pip wheel \
    $(echo "$PIP_TRUSTED_HOST" | sed -e '/^$/d' -e 's/,/ --trusted-host /g' -e 's/^/--trusted-host /') \
    --wheel-dir /wheels ".[api]"

# ── Runtime stage ────────────────────────────────────────────────────────────

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/strmt7/TextForensics" \
      org.opencontainers.image.title="TextForensics" \
      org.opencontainers.image.description="Local-first AI-text detector reliability auditing, provenance, CLI, API and MCP." \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TEXTFORENSICS_HOST=0.0.0.0 \
    TEXTFORENSICS_PORT=8765 \
    TEXTFORENSICS_ALLOW_REMOTE=1 \
    TEXTFORENSICS_ACCESS_LOG=0 \
    HOME=/tmp

# NOTE on the bind above: 0.0.0.0 + ALLOW_REMOTE=1 is the
# container-internal bind only. Docker port publishing forwards to the
# container's own IP, so a loopback bind inside the container would
# make the documented `docker run -p 127.0.0.1:8765:8765` command
# refuse connections. Remote exposure is controlled on the HOST side:
# always publish loopback-only (127.0.0.1:8765:8765, as in compose.yaml
# and docs/INSTALLATION.md) and never `-p 8765:8765`. The API has no
# authentication and must never be published on a network interface.

# Install runtime deps from pre-built wheels
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels "textforensics[api]" \
    && rm -rf /wheels /tmp/pip*

WORKDIR /app

# Non-root user for container hardening
RUN groupadd -r textforensics && useradd -r -g textforensics -d /app -s /sbin/nologin textforensics

USER textforensics:textforensics

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('TEXTFORENSICS_PORT','8765')+'/healthz',timeout=2).read()" || exit 1

ENTRYPOINT ["textforensics"]
CMD ["serve"]
