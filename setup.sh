#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# AI-Radar — Host Setup Script
# Supports both single-NIC and dual-NIC (bridge) deployments.
#
# Usage:
#   chmod +x setup.sh
#   sudo ./setup.sh
# ──────────────────────────────────────────────────────────────
set -e

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║           🛡️  AI-Radar Host Setup  🛡️            ║${NC}"
    echo -e "${CYAN}${BOLD}║       Network Monitor · DNS Filter · IPS         ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() { echo -e "\n${GREEN}${BOLD}[$1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"; }
info() { echo -e "    ${CYAN}ℹ${NC}  $1"; }
warn() { echo -e "    ${YELLOW}⚠${NC}  $1"; }
ok()   { echo -e "    ${GREEN}✓${NC}  $1"; }
err()  { echo -e "    ${RED}✗${NC}  $1"; }

AIRADAR_DIR="$(cd "$(dirname "$0")" && pwd)"
TOTAL_STEPS=9

banner

# ── Check root ───────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run this script as root (sudo ./setup.sh)${NC}"
    exit 1
fi

# ── Load .env if it exists ───────────────────────────────────
if [ -f "$AIRADAR_DIR/.env" ]; then
    set -a
    source "$AIRADAR_DIR/.env"
    set +a
    ok "Loaded .env configuration"
else
    warn "No .env file found — will create from template"
fi

# ── Step 1: System update ────────────────────────────────────
step 1 "Updating system packages"
apt update -qq
apt upgrade -y -qq
ok "System packages updated"

# ── Step 2: Install Docker ───────────────────────────────────
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
if command -v zeek &> /dev/null || [ -f /opt/zeek/bin/zeek ]; then
    ok "Zeek already installed"
else
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_$(lsb_release -rs)/ /" | \
        tee /etc/apt/sources.list.d/zeek.list > /dev/null
    curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_$(lsb_release -rs)/Release.key" | \
        gpg --dearmor -o /etc/apt/keyrings/zeek.gpg
    apt update -qq
    apt install -y -qq zeek
    echo 'export PATH=/opt/zeek/bin:$PATH' >> /etc/profile.d/zeek.sh
    ok "Zeek installed"
fi

mkdir -p /opt/zeek/logs
ok "Zeek log directory ready (/opt/zeek/logs)"

# ── Step 4: Detect network mode ─────────────────────────────
step 4 "Configuring network"

# List available physical interfaces
info "Available network interfaces:"
AVAILABLE_IFACES=()
while IFS= read -r line; do
    iface=$(echo "$line" | awk '{print $1}')
    AVAILABLE_IFACES+=("$iface")
    echo -e "      ${line}"
done < <(ip -br link show | grep -v "lo\|docker\|veth\|br-\|virbr")

# Determine mode: bridge (2+ NICs) or single (1 NIC)
IFACE_LIST="${BRIDGE_INTERFACES:-}"
NUM_ETHS=$(ip -br link show | grep -cE "^(eth|enp|eno)" || true)

if [ -n "$IFACE_LIST" ]; then
    IFACE_1=$(echo "$IFACE_LIST" | awk '{print $1}')
    IFACE_2=$(echo "$IFACE_LIST" | awk '{print $2}')
fi

BRIDGE_IP_ADDR="${BRIDGE_IP:-192.168.1.2/24}"
BRIDGE_GW="${BRIDGE_GATEWAY:-192.168.1.1}"
UPSTREAM="${UPSTREAM_DNS:-1.1.1.1}"

DEPLOY_MODE="single"

if [ -n "$IFACE_2" ] && ip link show "$IFACE_1" &>/dev/null && ip link show "$IFACE_2" &>/dev/null; then
    DEPLOY_MODE="bridge"
elif [ "$NUM_ETHS" -ge 2 ] && [ -z "$IFACE_LIST" ]; then
    # Auto-detect two ethernet interfaces
    IFACE_1=$(ip -br link show | grep -E "^(eth|enp|eno)" | awk 'NR==1{print $1}')
    IFACE_2=$(ip -br link show | grep -E "^(eth|enp|eno)" | awk 'NR==2{print $1}')
    info "Detected two NICs: $IFACE_1 + $IFACE_2"
    echo ""
    read -p "    Use bridge mode with these interfaces? (Y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        DEPLOY_MODE="bridge"
    fi
fi

# If single NIC, auto-detect the primary interface
if [ "$DEPLOY_MODE" = "single" ] && [ -z "$IFACE_1" ]; then
    IFACE_1=$(ip route show default | awk '{print $5; exit}')
    if [ -z "$IFACE_1" ]; then
        IFACE_1=$(ip -br link show | grep -E "^(eth|enp|eno)" | awk 'NR==1{print $1}')
    fi
fi

ZEEK_IFACE="$IFACE_1"

if [ "$DEPLOY_MODE" = "bridge" ]; then
    info "Mode: ${BOLD}Bridge${NC} ($IFACE_1 + $IFACE_2 → br0)"
    ZEEK_IFACE="br0"

    NETPLAN_FILE="/etc/netplan/01-airadar-bridge.yaml"
    sed -e "s|{{IFACE_1}}|${IFACE_1}|g" \
        -e "s|{{IFACE_2}}|${IFACE_2}|g" \
        -e "s|{{BRIDGE_IP}}|${BRIDGE_IP_ADDR}|g" \
        -e "s|{{BRIDGE_GATEWAY}}|${BRIDGE_GW}|g" \
        -e "s|{{UPSTREAM_DNS}}|${UPSTREAM}|g" \
        "$AIRADAR_DIR/network/netplan-bridge.yaml.template" > "$NETPLAN_FILE"

    chmod 600 "$NETPLAN_FILE"
    ok "Netplan bridge config written to $NETPLAN_FILE"
    info "Bridge: ${IFACE_1} + ${IFACE_2} → br0 (${BRIDGE_IP_ADDR})"
else
    info "Mode: ${BOLD}Single NIC${NC} ($IFACE_1 — promiscuous mode)"

    NETPLAN_FILE="/etc/netplan/01-airadar.yaml"
    sed -e "s|{{IFACE_1}}|${IFACE_1}|g" \
        -e "s|{{BRIDGE_IP}}|${BRIDGE_IP_ADDR}|g" \
        -e "s|{{BRIDGE_GATEWAY}}|${BRIDGE_GW}|g" \
        -e "s|{{UPSTREAM_DNS}}|${UPSTREAM}|g" \
        "$AIRADAR_DIR/network/netplan-single.yaml.template" > "$NETPLAN_FILE"

    chmod 600 "$NETPLAN_FILE"
    ok "Netplan single-NIC config written to $NETPLAN_FILE"
    info "Interface: ${IFACE_1} (${BRIDGE_IP_ADDR})"
fi

echo ""
warn "Network will be reconfigured. Make sure you have console access!"
echo ""
read -p "    Apply netplan now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    netplan apply
    ok "Netplan applied"
else
    info "Skipped. Apply manually with: ${BOLD}sudo netplan apply${NC}"
fi

# ── Step 5: Configure Zeek ──────────────────────────────────
step 5 "Configuring Zeek for ${ZEEK_IFACE}"

ZEEK_CFG=""
for path in /opt/zeek/etc/node.cfg /etc/zeek/node.cfg /usr/local/zeek/etc/node.cfg; do
    if [ -d "$(dirname "$path")" ]; then
        ZEEK_CFG="$path"
        break
    fi
done

if [ -n "$ZEEK_CFG" ]; then
    # Write Zeek node config with detected interface
    cat > "$ZEEK_CFG" <<EOF
[zeek]
type=standalone
host=localhost
interface=${ZEEK_IFACE}
EOF
    ok "Zeek configured to listen on ${ZEEK_IFACE} ($ZEEK_CFG)"
else
    warn "Could not find Zeek config directory"
    info "Manually set interface=${ZEEK_IFACE} in your Zeek node.cfg"
fi

# Install Zeek systemd service for auto-start
cp "$AIRADAR_DIR/network/zeek-autostart.service" /etc/systemd/system/zeek-airadar.service
systemctl daemon-reload
systemctl enable zeek-airadar.service
ok "Zeek auto-start service installed (zeek-airadar.service)"

if command -v zeekctl &>/dev/null || [ -f /opt/zeek/bin/zeekctl ]; then
    ZEEKCTL=$(command -v zeekctl 2>/dev/null || echo /opt/zeek/bin/zeekctl)
    $ZEEKCTL install 2>/dev/null || true
    ok "Zeek configuration installed"
    info "Start with: ${BOLD}sudo zeekctl deploy${NC}"
else
    warn "zeekctl not found — install Zeek first, then run: zeekctl deploy"
fi

# ── Step 6: Transparent DNS redirect ─────────────────────────
step 6 "Installing transparent DNS redirect"

if [ "$DEPLOY_MODE" = "bridge" ]; then
    # Install iptables if not present
    if ! command -v iptables &>/dev/null; then
        apt install -y -qq iptables
    fi

    # Deploy systemd service for persistent iptables rules
    cp "$AIRADAR_DIR/network/airadar-dns-redirect.service" /etc/systemd/system/airadar-dns-redirect.service
    systemctl daemon-reload
    systemctl enable airadar-dns-redirect.service
    ok "DNS redirect service installed"
    info "All DNS traffic through the bridge is automatically redirected to AdGuard"
    info "No DNS/DHCP changes needed on your router or client devices!"
else
    warn "Single-NIC mode: transparent DNS redirect not available"
    info "Clients need to point their DNS to ${BRIDGE_IP_ADDR%/*}"
fi

# ── Step 7: Prepare directory structure ──────────────────────
step 7 "Preparing AI-Radar directory structure"

mkdir -p "$AIRADAR_DIR/data"
mkdir -p "$AIRADAR_DIR/adguard/conf"
mkdir -p "$AIRADAR_DIR/adguard/work"
mkdir -p "$AIRADAR_DIR/crowdsec/conf"
mkdir -p "$AIRADAR_DIR/crowdsec/data"

if [ ! -f "$AIRADAR_DIR/.env" ]; then
    cp "$AIRADAR_DIR/.env.example" "$AIRADAR_DIR/.env"
    ok "Created .env from .env.example"
    warn "Edit ${BOLD}$AIRADAR_DIR/.env${NC} with your settings before starting!"
else
    ok ".env already exists"
fi

# Update .env with detected interface if not already set
if [ -z "$BRIDGE_INTERFACES" ]; then
    if [ "$DEPLOY_MODE" = "bridge" ]; then
        echo "BRIDGE_INTERFACES=${IFACE_1} ${IFACE_2}" >> "$AIRADAR_DIR/.env"
    else
        echo "BRIDGE_INTERFACES=${IFACE_1}" >> "$AIRADAR_DIR/.env"
    fi
    ok "Wrote interface config to .env"
fi

ok "Directory structure ready"

# ── Step 7: SQLite backup cron ───────────────────────────────
step 7 "Setting up automated database backup"

BACKUP_DIR="$AIRADAR_DIR/backups"
mkdir -p "$BACKUP_DIR"

CRON_LINE="0 3 * * * sqlite3 $AIRADAR_DIR/data/airadar.db \".backup $BACKUP_DIR/airadar-\$(date +\\%Y\\%m\\%d).db\" && find $BACKUP_DIR -name 'airadar-*.db' -mtime +7 -delete"

(crontab -l 2>/dev/null | grep -v "airadar.*backup"; echo "$CRON_LINE") | crontab -
ok "Daily backup at 03:00 → $BACKUP_DIR (7-day retention)"

# ── Step 8: Post-setup instructions ──────────────────────────
step 8 "Final steps"

MGMT_IP="${BRIDGE_IP_ADDR%/*}"

echo ""
info "After starting the stack with ${BOLD}docker compose up -d --build${NC}:"
echo ""
echo -e "    ${BOLD}${CYAN}1.${NC} Complete the AdGuard Home setup wizard:"
echo -e "       ${BOLD}http://${MGMT_IP}:3000${NC}"
echo -e "       Set your admin credentials, then update ${BOLD}.env${NC}:"
echo -e "       ${YELLOW}ADGUARD_USER=your_email${NC}"
echo -e "       ${YELLOW}ADGUARD_PASS=your_password${NC}"
echo ""
echo -e "    ${BOLD}${CYAN}2.${NC} Generate CrowdSec API key:"
echo -e "       ${BOLD}sudo docker exec crowdsec cscli bouncers add airadar_dashboard${NC}"
echo -e "       Copy the key into ${BOLD}.env${NC}:"
echo -e "       ${YELLOW}CROWDSEC_API_KEY=<paste_key_here>${NC}"
echo ""
echo -e "    ${BOLD}${CYAN}3.${NC} Restart to pick up all config:"
echo -e "       ${BOLD}docker compose restart airadar-app${NC}"
echo ""
echo -e "    ${BOLD}${CYAN}4.${NC} Set client devices' DNS to: ${BOLD}${MGMT_IP}${NC}"
echo -e "       (or configure your DHCP server to push this DNS)"

if [ "$DEPLOY_MODE" = "single" ]; then
    echo ""
    echo -e "    ${BOLD}${CYAN}5.${NC} ${YELLOW}Single-NIC note:${NC} Zeek captures via promiscuous mode."
    echo -e "       For best coverage, enable ${BOLD}port mirroring${NC} on your switch"
    echo -e "       to mirror all traffic to the ${IFACE_1} port."
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║            ✅ Host setup complete!                ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Deploy mode:${NC} ${DEPLOY_MODE^^} (${ZEEK_IFACE})"
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "  1. Review ${BOLD}.env${NC} settings"
echo -e "  2. Deploy Zeek: ${CYAN}${BOLD}sudo zeekctl deploy${NC}"
echo -e "  3. Start stack: ${CYAN}${BOLD}docker compose up -d --build${NC}"
echo -e "  4. Open dashboard: ${CYAN}http://${MGMT_IP}:8000${NC}"
echo ""
