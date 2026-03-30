#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# AI-Radar — N95 Mini-PC Host Setup Script
# Run once on a fresh Ubuntu Server before starting Docker.
#
# Usage:
#   chmod +x setup_n95.sh
#   sudo ./setup_n95.sh
# ──────────────────────────────────────────────────────────────
set -e

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║           🛡️  AI-Radar Host Setup  🛡️            ║${NC}"
    echo -e "${CYAN}${BOLD}║       N95 Mini-PC · Layer 2 Bridge Appliance     ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() { echo -e "\n${GREEN}${BOLD}[$1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"; }
info() { echo -e "    ${CYAN}ℹ${NC}  $1"; }
warn() { echo -e "    ${YELLOW}⚠${NC}  $1"; }
ok()   { echo -e "    ${GREEN}✓${NC}  $1"; }

TOTAL_STEPS=6

banner

# ── Check root ───────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run this script as root (sudo ./setup_n95.sh)${NC}"
    exit 1
fi

# ── Step 1: System update ────────────────────────────────────
step 1 "Updating system packages"
apt update -qq
apt upgrade -y -qq
ok "System packages updated"

# ── Step 2: Install Docker (if not present) ──────────────────
step 2 "Installing Docker Engine"
if command -v docker &> /dev/null; then
    ok "Docker already installed ($(docker --version | awk '{print $3}'))"
else
    apt install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt update -qq
    apt install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    ok "Docker installed and started"
fi

# ── Step 3: Install Zeek ─────────────────────────────────────
step 3 "Installing Zeek network monitor"
if command -v zeek &> /dev/null; then
    ok "Zeek already installed ($(zeek --version 2>/dev/null | head -1))"
else
    # Zeek official repository
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_$(lsb_release -rs)/ /" | \
        tee /etc/apt/sources.list.d/zeek.list > /dev/null
    curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_$(lsb_release -rs)/Release.key" | \
        gpg --dearmor -o /etc/apt/keyrings/zeek.gpg
    apt update -qq
    apt install -y -qq zeek
    ok "Zeek installed"
fi

# Ensure Zeek log directory exists
mkdir -p /opt/zeek/logs
ok "Zeek log directory ready (/opt/zeek/logs)"

# ── Step 4: Configure bridge interface reminder ──────────────
step 4 "Network bridge configuration"
warn "Please ensure Zeek is configured to listen on the bridge interface."
info "Edit ${BOLD}/etc/zeek/node.cfg${NC} and set:"
echo ""
echo -e "    ${YELLOW}[zeek]"
echo -e "    type=standalone"
echo -e "    host=localhost"
echo -e "    interface=br0${NC}"
echo ""
info "Then deploy with: ${BOLD}zeekctl deploy${NC}"

# ── Step 5: Prepare AI-Radar directory structure ─────────────
step 5 "Preparing AI-Radar directory structure"

AIRADAR_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$AIRADAR_DIR/data"
mkdir -p "$AIRADAR_DIR/adguard/conf"
mkdir -p "$AIRADAR_DIR/adguard/work"
mkdir -p "$AIRADAR_DIR/crowdsec/conf"
mkdir -p "$AIRADAR_DIR/crowdsec/data"

# Create .env from example if it doesn't exist
if [ ! -f "$AIRADAR_DIR/.env" ]; then
    cp "$AIRADAR_DIR/.env.example" "$AIRADAR_DIR/.env"
    ok "Created .env from .env.example"
    warn "Edit ${BOLD}$AIRADAR_DIR/.env${NC} before starting the stack."
else
    ok ".env already exists"
fi

ok "Directory structure ready"

# ── Step 6: CrowdSec API key instructions ────────────────────
step 6 "CrowdSec bouncer API key"
echo ""
info "After starting the stack with ${BOLD}docker compose up -d${NC}, generate"
info "a CrowdSec API key for the AI-Radar dashboard:"
echo ""
echo -e "    ${BOLD}${CYAN}sudo docker exec crowdsec cscli bouncers add airadar_dashboard${NC}"
echo ""
info "Copy the generated key into your ${BOLD}.env${NC} file:"
echo ""
echo -e "    ${YELLOW}CROWDSEC_API_KEY=<paste_key_here>${NC}"
echo ""
info "Then restart the app container to pick up the key:"
echo ""
echo -e "    ${BOLD}${CYAN}docker compose restart airadar-app${NC}"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║            ✅ Host setup complete!                ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "  1. Configure Zeek bridge interface (see step 4)"
echo -e "  2. Edit ${BOLD}.env${NC} with your settings"
echo -e "  3. Run: ${CYAN}${BOLD}docker compose up -d --build${NC}"
echo -e "  4. Generate CrowdSec API key (see step 6)"
echo -e "  5. Open ${CYAN}http://<bridge-ip>:8000${NC} in your browser"
echo ""
