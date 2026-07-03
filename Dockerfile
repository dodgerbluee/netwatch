# syntax=docker/dockerfile:1.7

# ----- builder -----------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build deps for any wheels that need compiling (cffi etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip build \
    && pip wheel --wheel-dir /wheels .

# ----- runtime -----------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    NETWATCH_DATA_DIR=/data

RUN mkdir -p /data /app

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels netwatch \
    && rm -rf /wheels

EXPOSE 8099

# Healthcheck hits the readiness endpoint that doesn't require UniFi/MQTT
# to be reachable, so the container is "healthy" once the HTTP server is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=3).status == 200 else 1)"

ENTRYPOINT ["netwatch"]

# OCI labels (filled in by CI via --label or via .github/workflows/release.yaml)
LABEL org.opencontainers.image.title="netwatch" \
      org.opencontainers.image.description="WiFi device watcher for UniFi + Home Assistant" \
      org.opencontainers.image.source="https://github.com/dodgerbluee/netwatch"
