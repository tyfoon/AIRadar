#!/usr/bin/env bash
# fix_zeek_mount.sh — Repair Zeek logs mount after broken symlink
# Usage: sudo ./fix_zeek_mount.sh
set -e

echo "=== Fixing Zeek logs mount ==="

echo "[1/5] Stopping containers (release mount)..."
cd "$(dirname "$0")"
docker compose down

echo "[2/5] Removing broken current/ directory..."
rm -rf /opt/zeek/logs/current

echo "[3/5] Creating fresh current/ directory..."
mkdir -p /opt/zeek/logs/current
chown root:zeek /opt/zeek/logs/current
chmod 2775 /opt/zeek/logs/current

echo "[4/5] Deploying Zeek..."
/opt/zeek/bin/zeekctl deploy 2>&1 | grep -v "Warning:" || true
sleep 3

# Verify Zeek is writing logs
LOG_COUNT=$(ls /opt/zeek/logs/current/ 2>/dev/null | wc -l)
if [ "$LOG_COUNT" -gt 0 ]; then
    echo "     Zeek writing logs: $LOG_COUNT files in current/"
else
    echo "     WARNING: No logs in current/ yet — check zeekctl status"
fi

echo "[5/5] Starting containers..."
docker compose up -d

echo ""
echo "=== Done. Check: ==="
echo "  sudo /opt/zeek/bin/zeekctl status"
echo "  sudo docker exec airadar-app ls /app/logs/"
