#!/bin/sh
# ──────────────────────────────────────────────────────────────
# AI-Radar — Container Entrypoint
# Starts zeek_tailer in background, uvicorn in foreground.
# If either process dies, the container exits (triggering restart).
# ──────────────────────────────────────────────────────────────
set -e

echo "╔══════════════════════════════════════════╗"
echo "║        AI-Radar Container Starting       ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  DB Path:     ${AIRADAR_DB_PATH}"
echo "  Zeek Logs:   ${ZEEK_LOG_DIR}"
echo "  AdGuard:     ${ADGUARD_URL}"
echo ""

# Start zeek_tailer in background — monitor its PID
python zeek_tailer.py --zeek-log-dir "${ZEEK_LOG_DIR}" &
TAILER_PID=$!
echo "[entrypoint] zeek_tailer started (PID ${TAILER_PID})"

# Trap signals to clean up both processes
cleanup() {
    echo "[entrypoint] Shutting down..."
    kill ${TAILER_PID} 2>/dev/null || true
    wait ${TAILER_PID} 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

# Start uvicorn in foreground
uvicorn api:app --host 0.0.0.0 --port 8000 &
UVICORN_PID=$!
echo "[entrypoint] uvicorn started (PID ${UVICORN_PID})"

# Monitor both processes — exit if either dies
while true; do
    if ! kill -0 ${TAILER_PID} 2>/dev/null; then
        echo "[entrypoint] ERROR: zeek_tailer died! Restarting container..."
        kill ${UVICORN_PID} 2>/dev/null || true
        exit 1
    fi
    if ! kill -0 ${UVICORN_PID} 2>/dev/null; then
        echo "[entrypoint] ERROR: uvicorn died! Restarting container..."
        kill ${TAILER_PID} 2>/dev/null || true
        exit 1
    fi
    sleep 5
done
