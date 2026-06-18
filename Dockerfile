# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git \
    && rm -rf /var/lib/apt/lists/*

COPY setup.py .
COPY auditlens/ auditlens/
COPY README.md* ./

# Install the package with all optional features including dashboard
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[all]" gunicorn

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Create non-root user
RUN groupadd -r auditlens && useradd -r -g auditlens -m auditlens

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app/auditlens /app/auditlens

# Directory for scan target (mounted as volume) and SQLite persistence
RUN mkdir -p /data/scan /data/db \
    && chown -R auditlens:auditlens /data /app

# Copy gunicorn entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER auditlens

# SQLite will live in /data/db (mount a persistent volume here in Azure)
ENV AUDITLENS_DB=/data/db/history.db
# Scan path inside the container (mount your project at /data/scan)
ENV SCAN_PATH=/data/scan
# Auth credentials (override in Azure App Service environment variables)
ENV AUDITLENS_USER=admin
ENV AUDITLENS_PASSWORD=changeme
# Gunicorn workers
ENV WEB_CONCURRENCY=2

EXPOSE 8080

ENTRYPOINT ["docker-entrypoint.sh"]
