# Recon Operator — multi-tool recon control plane
# Base image pinned by digest for reproducible builds (refresh periodically).
FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_HOST=0.0.0.0 \
    RESULTS_DIR=/app/encrypted_results \
    SCAN_LOG_PATH=/app/logs/scan_log.txt

RUN apt-get update \
    && apt-get install --no-install-recommends -y nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 app

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install -r requirements.txt

COPY --chown=app:app . .
RUN mkdir -p encrypted_results logs data \
    && chown -R app:app encrypted_results logs data

USER app
EXPOSE 5000
VOLUME ["/app/encrypted_results", "/app/logs", "/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/live', timeout=3)"]

STOPSIGNAL SIGTERM
CMD ["python", "autonmap.py"]
