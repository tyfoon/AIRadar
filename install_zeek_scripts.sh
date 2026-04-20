#!/bin/bash
# Install AIradar custom Zeek scripts and reload Zeek.
# Run with: sudo bash install_zeek_scripts.sh

set -e

ZEEK_SITE="/opt/zeek/share/zeek/site"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)/zeek-scripts"

echo "[*] Installing long-connections Zeek script..."
cp -r "$SCRIPT_DIR/long-connections" "$ZEEK_SITE/"

# Add @load directive if not already present
if ! grep -q "long-connections" "$ZEEK_SITE/local.zeek"; then
    echo "" >> "$ZEEK_SITE/local.zeek"
    echo "# AIradar: long-lived connection monitoring (Firewalla-inspired)" >> "$ZEEK_SITE/local.zeek"
    echo "@load long-connections" >> "$ZEEK_SITE/local.zeek"
    echo "[*] Added @load long-connections to local.zeek"
else
    echo "[*] long-connections already in local.zeek, skipping"
fi

echo "[*] Restarting Zeek..."
/opt/zeek/bin/zeekctl deploy

echo "[*] Done. conn_long.log will appear in /opt/zeek/spool/zeek/ after 2 minutes."
