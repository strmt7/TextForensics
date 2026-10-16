# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder
ARG TEXTFORENSICS_EXTRAS=api
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels ".[${TEXTFORENSICS_EXTRAS}]"

FROM python:3.12-slim AS runtime
ARG TEXTFORENSICS_EXTRAS=api
LABEL org.opencontainers.image.source="https://github.com/strmt7/TextForensics" \
      org.opencontainers.image.title="TextForensics" \
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

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels "textforensics[${TEXTFORENSICS_EXTRAS}]" \
    && rm -rf /wheels

WORKDIR /app
USER 65532:65532
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('TEXTFORENSICS_PORT','8765')+'/healthz',timeout=2).read()" || exit 1

ENTRYPOINT ["textforensics"]
CMD ["serve"]
