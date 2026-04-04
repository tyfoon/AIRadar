# ──────────────────────────────────────────────────────────────
# AI-Radar — Production container image
# Runs the FastAPI backend (Uvicorn) + Zeek log tailer
# ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

# System dependencies for mac-vendor-lookup & arp resolution
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        net-tools \
        iproute2 \
        curl \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py ./
COPY static/ ./static/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

# Environment defaults (can be overridden in docker-compose / .env)
ENV AIRADAR_DB_PATH="/app/data/airadar.db"
ENV ZEEK_LOG_DIR="/app/logs"
ENV ADGUARD_URL="http://localhost:80"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Health check — ensures both FastAPI and zeek_tailer are alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Entrypoint manages both zeek_tailer and uvicorn with proper signal handling
CMD ["./entrypoint.sh"]
