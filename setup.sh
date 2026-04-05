#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# AI-Radar — Host Setup Script
# Supports both single-NIC and dual-NIC (bridge) deployments.
#
# Usage:
#   chmod +x setup.sh
#   sudo ./setup.sh
# ──────────────────────────────────────────────────────────────
# Don't exit on error — handle failures per step
set +e

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

# Ensure Zeek is always in PATH for this script
export PATH=/opt/zeek/bin:$PATH

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
# Prevent interactive prompts during apt installs (e.g. postfix)
export DEBIAN_FRONTEND=noninteractive
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
    UBUNTU_VER=$(lsb_release -rs)
    ZEEK_INSTALLED=false

    # Method 1: Try official Zeek OBS repository (signed)
    info "Trying Zeek OBS repository..."
    ZEEK_REPO="http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VER}"
    if curl -fsSL "${ZEEK_REPO}/Release.key" 2>/dev/null | gpg --dearmor -o /etc/apt/keyrings/zeek.gpg 2>/dev/null; then
        echo "deb [signed-by=/etc/apt/keyrings/zeek.gpg] ${ZEEK_REPO}/ /" | \
            tee /etc/apt/sources.list.d/zeek.list > /dev/null
        apt update -qq 2>/dev/null
        if apt install -y -qq zeek 2>/dev/null; then
            ZEEK_INSTALLED=true
        fi
    fi

    # Method 2: Try trusted repo (skip GPG) — for repos with key issues
    if [ "$ZEEK_INSTALLED" = false ]; then
        warn "Signed repo failed, trying trusted repo..."
        echo "deb [trusted=yes] ${ZEEK_REPO}/ /" | \
            tee /etc/apt/sources.list.d/zeek.list > /dev/null
        apt update -qq 2>/dev/null
        if apt install -y -qq zeek 2>/dev/null; then
            ZEEK_INSTALLED=true
        fi
    fi

    # Method 3: Try Zeek binary package directly
    if [ "$ZEEK_INSTALLED" = false ]; then
        warn "Repo install failed, trying direct .deb download..."
        ZEEK_DEB_URL="https://download.zeek.org/binary-packages/xUbuntu_${UBUNTU_VER}/amd64/"
        ZEEK_DEB=$(curl -fsSL "$ZEEK_DEB_URL" 2>/dev/null | grep -oP 'zeek_[0-9][^"]*_amd64\.deb' | sort -V | tail -1)
        if [ -n "$ZEEK_DEB" ]; then
            curl -fsSL "${ZEEK_DEB_URL}${ZEEK_DEB}" -o /tmp/zeek.deb
            dpkg -i /tmp/zeek.deb || apt install -f -y
            ZEEK_INSTALLED=true
            rm -f /tmp/zeek.deb
        fi
    fi

    # Method 4: Snap fallback
    if [ "$ZEEK_INSTALLED" = false ]; then
        warn "Direct download failed, trying snap..."
        snap install zeek --classic 2>/dev/null && ZEEK_INSTALLED=true
    fi

    if [ "$ZEEK_INSTALLED" = true ]; then
        echo 'export PATH=/opt/zeek/bin:$PATH' >> /etc/profile.d/zeek.sh
        export PATH=/opt/zeek/bin:$PATH
        ok "Zeek installed"
    else
        err "Could not install Zeek automatically"
        info "Install manually: https://docs.zeek.org/en/current/install.html"
        info "Then re-run this script."
    fi
fi

# Ensure Zeek directories exist
mkdir -p /opt/zeek/logs
mkdir -p /opt/zeek/spool/zeek
ok "Zeek directories ready"

# Fix Zeek log symlink: Docker cannot mount symlinks as volumes.
# Replace the 'current' symlink with a bind mount of the actual spool dir.
if [ -L /opt/zeek/logs/current ]; then
    rm /opt/zeek/logs/current
    info "Removed symlink /opt/zeek/logs/current"
fi
if [ ! -d /opt/zeek/logs/current ]; then
    mkdir -p /opt/zeek/logs/current
fi
# Create a persistent bind mount (spool dir → logs/current)
if ! mountpoint -q /opt/zeek/logs/current; then
    mount --bind /opt/zeek/spool/zeek /opt/zeek/logs/current
    ok "Bind-mounted Zeek spool → /opt/zeek/logs/current"
fi
# Make the bind mount persistent across reboots
if ! grep -q "zeek/spool/zeek" /etc/fstab 2>/dev/null; then
    echo "/opt/zeek/spool/zeek /opt/zeek/logs/current none bind 0 0" >> /etc/fstab
    ok "Added Zeek log bind mount to /etc/fstab (persistent)"
fi

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

BRIDGE_IP_ADDR="${BRIDGE_IP:-192.168.1.7/24}"
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

# Enable MAC logging in Zeek
ZEEK_LOCAL=""
for path in /opt/zeek/share/zeek/site/local.zeek /etc/zeek/site/local.zeek /usr/local/zeek/share/zeek/site/local.zeek; do
    if [ -f "$path" ]; then
        ZEEK_LOCAL="$path"
        break
    fi
done

if [ -n "$ZEEK_LOCAL" ]; then
    if ! grep -q "mac-logging" "$ZEEK_LOCAL" 2>/dev/null; then
        echo "@load policy/protocols/conn/mac-logging" >> "$ZEEK_LOCAL"
        ok "Zeek MAC logging enabled (orig_l2_addr in conn.log)"
    else
        ok "Zeek MAC logging already enabled"
    fi
else
    warn "Could not find Zeek local.zeek — manually add: @load policy/protocols/conn/mac-logging"
fi

# Install Zeek plugins: JA4 (DHCP fingerprinting) + mDNS (device names)
ZKG=$(command -v zkg 2>/dev/null || echo /opt/zeek/bin/zkg)
if [ -x "$ZKG" ] || command -v zkg &>/dev/null; then
    $ZKG autoconfig 2>/dev/null || true

    if $ZKG install zeek/foxio/ja4 --force --skiptests 2>/dev/null; then
        ok "JA4 plugin installed (DHCP fingerprinting)"
    else
        warn "JA4 plugin installation failed — ja4d.log will not be available"
    fi

    if $ZKG install zeek/fdekeers/mdns --force --skiptests 2>/dev/null; then
        ok "mDNS plugin installed (device name discovery)"
    else
        warn "mDNS plugin installation failed — mdns.log will not be available"
    fi

    if [ -n "$ZEEK_LOCAL" ]; then
        if ! grep -q "@load ja4" "$ZEEK_LOCAL" 2>/dev/null; then
            echo "@load ja4" >> "$ZEEK_LOCAL"
            ok "JA4 loaded in local.zeek"
        fi
        if ! grep -q "@load mdns" "$ZEEK_LOCAL" 2>/dev/null; then
            echo "@load mdns" >> "$ZEEK_LOCAL"
            ok "mDNS loaded in local.zeek"
        fi
    fi
else
    warn "zkg not found — install zeek-zkg to enable JA4D and mDNS plugins"
fi

# Install Zeek systemd service for auto-start
cp "$AIRADAR_DIR/network/zeek-autostart.service" /etc/systemd/system/zeek-airadar.service
systemctl daemon-reload
systemctl enable zeek-airadar.service
ok "Zeek auto-start service installed (zeek-airadar.service)"

# Install and deploy Zeek
ZEEKCTL=$(command -v zeekctl 2>/dev/null || echo /opt/zeek/bin/zeekctl)
if [ -x "$ZEEKCTL" ]; then
    $ZEEKCTL install 2>/dev/null || true
    $ZEEKCTL deploy 2>/dev/null || true
    ok "Zeek installed and deployed"
    $ZEEKCTL status
else
    warn "zeekctl not found — install Zeek first, then run: /opt/zeek/bin/zeekctl deploy"
fi

# ── Step 6: Transparent DNS redirect ─────────────────────────
step 6 "Installing transparent DNS redirect"

if [ "$DEPLOY_MODE" = "bridge" ]; then
    if ! command -v iptables &>/dev/null; then
        apt install -y -qq iptables
    fi

    # Deploy systemd service for persistent iptables rules
    cp "$AIRADAR_DIR/network/airadar-dns-redirect.service" /etc/systemd/system/airadar-dns-redirect.service
    systemctl daemon-reload
    systemctl enable --now airadar-dns-redirect.service
    ok "DNS redirect service installed and started"
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

# ── GeoIP country database for Geo Traffic dashboard ────────
GEO_DB_PATH="$AIRADAR_DIR/data/GeoLite2-Country.mmdb"
GEO_DB_URL="https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country-mmdb/dbip-country.mmdb"
if [ ! -f "$GEO_DB_PATH" ]; then
    info "Downloading DB-IP Country database (~8 MB)..."
    if curl -sSL --max-time 120 -o "$GEO_DB_PATH" "$GEO_DB_URL"; then
        ok "GeoIP country database installed at $GEO_DB_PATH"
    else
        rm -f "$GEO_DB_PATH"
        warn "GeoIP database download failed — Geo Traffic dashboard will be empty"
    fi
else
    ok "GeoIP database already present at $GEO_DB_PATH"
fi

# ── Step 8: SQLite backup cron ───────────────────────────────
step 8 "Setting up automated database backup"

BACKUP_DIR="$AIRADAR_DIR/backups"
mkdir -p "$BACKUP_DIR"

CRON_LINE="0 3 * * * sqlite3 $AIRADAR_DIR/data/airadar.db \".backup $BACKUP_DIR/airadar-\$(date +\\%Y\\%m\\%d).db\" && find $BACKUP_DIR -name 'airadar-*.db' -mtime +7 -delete"

(crontab -l 2>/dev/null | grep -v "airadar.*backup"; echo "$CRON_LINE") | crontab -
ok "Daily backup at 03:00 → $BACKUP_DIR (7-day retention)"

# ── Step 9: Start the stack ──────────────────────────────────
step 9 "Starting AI-Radar stack"

cd "$AIRADAR_DIR"
docker compose up -d --build

if [ $? -eq 0 ]; then
    ok "All containers started"
else
    err "Docker compose failed — check logs with: docker compose logs"
fi

MGMT_IP="${BRIDGE_IP_ADDR%/*}"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║            ✅ Host setup complete!                ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Deploy mode:${NC} ${DEPLOY_MODE^^} (${ZEEK_IFACE})"
echo -e "  ${BOLD}Management IP:${NC} ${MGMT_IP}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "  1. Open AdGuard setup wizard: ${CYAN}${BOLD}http://${MGMT_IP}:3000${NC}"
echo -e "     Create an admin account, then put the credentials in ${BOLD}.env${NC}:"
echo -e "     ${YELLOW}ADGUARD_USER=your_email${NC}"
echo -e "     ${YELLOW}ADGUARD_PASS=your_password${NC}"
echo ""
echo -e "  2. Generate CrowdSec API key:"
echo -e "     ${CYAN}${BOLD}sudo docker exec crowdsec cscli bouncers add airadar_dashboard${NC}"
echo -e "     Put the key in ${BOLD}.env${NC}:"
echo -e "     ${YELLOW}CROWDSEC_API_KEY=<paste_key_here>${NC}"
echo ""
echo -e "  3. Restart to pick up config:"
echo -e "     ${CYAN}${BOLD}cd $AIRADAR_DIR && docker compose restart${NC}"
echo ""
echo -e "  4. Open dashboard: ${CYAN}${BOLD}http://${MGMT_IP}:8000${NC}"

if [ "$DEPLOY_MODE" = "bridge" ]; then
    echo ""
    echo -e "  ${GREEN}${BOLD}Zero-touch DNS:${NC} All DNS queries are transparently redirected"
    echo -e "  to AdGuard. No changes needed on your router or devices!"
else
    echo ""
    echo -e "  5. Set client devices' DNS to: ${BOLD}${MGMT_IP}${NC}"
    echo ""
    echo -e "  ${YELLOW}Single-NIC note:${NC} For best coverage, enable port mirroring"
    echo -e "  on your switch to mirror all traffic to ${IFACE_1}."
fi
echo ""
