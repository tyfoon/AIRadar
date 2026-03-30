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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py ./
COPY static/ ./static/

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

# Environment defaults (can be overridden in docker-compose)
ENV AIRADAR_DB_PATH="/app/data/airadar.db"
ENV ZEEK_LOG_DIR="/app/logs"
ENV ADGUARD_URL="http://localhost:3000"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Start Uvicorn — zeek_tailer runs as a background asyncio task
# Use a shell entrypoint so we can start both processes
CMD ["sh", "-c", "python zeek_tailer.py --zeek-log-dir ${ZEEK_LOG_DIR} & uvicorn api:app --host 0.0.0.0 --port 8000"]
