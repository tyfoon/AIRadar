<p align="center">
  <img src="https://img.shields.io/badge/AI--Radar-v1.0.0-indigo?style=for-the-badge" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Zeek-Network%20Monitor-orange?style=for-the-badge" alt="Zeek" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge" alt="License" />
</p>

# AI-Radar

**Enterprise-grade network intelligence appliance for monitoring, analyzing, and controlling AI service usage, cloud storage transfers, and privacy threats across your entire network.**

AI-Radar is designed to run as a transparent Layer 2 bridge on a dedicated mini-PC (Intel N95 or similar), providing complete visibility into how AI tools, cloud services, and tracking networks are being used — without requiring any software installation on client devices.

---

## Why AI-Radar?

Organizations face a new challenge: **Shadow AI**. Employees adopt AI tools like ChatGPT, Gemini, and Claude faster than IT can track. Sensitive data gets uploaded to third-party AI providers. VPN tunnels bypass corporate policies. Traditional firewalls see none of this.

AI-Radar solves this by combining **deep packet inspection** (Zeek), **DNS-level blocking** (AdGuard Home), and **intrusion prevention** (CrowdSec) into a single, elegant dashboard.

### What Makes It Different From a Firewall?

| Capability | Traditional Firewall | AdGuard Home | AI-Radar |
|---|:---:|:---:|:---:|
| Block domains | ✅ | ✅ | ✅ |
| See _which device_ uses _which AI service_ | ❌ | ❌ | ✅ |
| Detect data uploads to AI providers | ❌ | ❌ | ✅ |
| AI adoption metrics (% of workforce) | ❌ | ❌ | ✅ |
| VPN evasion detection | ❌ | ❌ | ✅ |
| Per-device, per-service analytics | ❌ | ❌ | ✅ |
| Time-based blocking (block for 2 hours) | ❌ | ❌ | ✅ |

---

## Features

### AI Service Monitoring
- **Real-time detection** of 20+ AI services: ChatGPT, Gemini, Claude, Copilot, Perplexity, Mistral, HuggingFace, DeepSeek, and more
- **Upload detection** — alerts when devices send large amounts of data to AI providers (potential data leakage)
- **SNI-based identification** via TLS handshake inspection — works even with encrypted traffic
- **Context-aware Google disambiguation** — correctly distinguishes Gemini (AI) from Google Drive (cloud) traffic using the same `googleapis.com` domains

### AI Adoption Intelligence
- **Adoption rate** — percentage of network devices actively using AI tools
- **Queries per device per day** — understand usage intensity
- **Power user identification** — devices with >50 AI queries/day
- **Service popularity breakdown** — which AI tools are most used
- **Per-device adoption bars** — visual breakdown per device

### Cloud Storage Monitoring
- Track transfers to **Google Drive, Dropbox, OneDrive, iCloud, Box, MEGA, WeTransfer**, and more
- **Volumetric upload detection** with intelligent debouncing (clusters parallel TCP streams into single events)
- Upload threshold alerting (configurable, default 100 KB)

### Privacy & Tracker Detection
- **Zeek-based tracker identification** — detects Google Analytics, Facebook Pixel, Hotjar, Datadog, Sentry, Mixpanel, Criteo, and 15+ tracking services via TLS SNI inspection
- **AdGuard Home integration** — real-time DNS blocking statistics, top blocked domains, block rate percentage
- **Filterable views** — filter by tracker, device, and time period

### VPN & Evasion Detection (3-Layer System)
1. **Port-based detection** — OpenVPN (UDP/1194), WireGuard (UDP/51820), IPsec (UDP/500, 4500), PPTP, L2TP
2. **DPD (Dynamic Protocol Detection)** — Zeek identifies VPN/Tor protocols _regardless of port_, catching tunnels hidden on port 443
3. **Heuristic detection** — flags devices sending disproportionate encrypted traffic to a single unknown destination (catches NordVPN, ExpressVPN, etc.)
4. **DNS/SNI detection** — identifies connections to known VPN provider domains (NordVPN, ExpressVPN, Surfshark, ProtonVPN, Mullvad, and 10+ others)

### Device Intelligence
- **Passive device recognition via DHCP** — extracts hostname, MAC, and IP from DHCP leases without any client-side software
- **MAC vendor lookup** (OUI database) — identifies device manufacturers (Apple, Ubiquiti, Espressif, Hikvision, etc.)
- **Device type detection** — pattern matching on hostname/vendor to classify devices (💻 MacBook, 📡 Router, 📱 iPhone, 📹 IP Camera, 🔌 IoT Device, etc.)
- **IPv6 privacy address merging** — correctly groups multiple IPv6 privacy extension addresses to a single physical device via /64 prefix matching
- **Category-grouped device matrix** — collapsible columns grouped by AI/Cloud/Privacy with heat-map cells and click-to-drill-down event detail

### Rules & Access Control
- **Per-service blocking** with toggle switches — block any AI, cloud, or tracking service with one click
- **Time-based blocking** — block services for 1h, 4h, 8h, 24h, or set a custom end time
- **Global category filters** — Parental Controls, Social Media, Gaming (via AdGuard blocked services API)
- **Automatic expiry** — timed blocks automatically lift when the duration expires

### Active Protect (IPS)
- **CrowdSec integration** — community-driven intrusion prevention system
- Parses Zeek logs for threat intelligence
- Displays blocked threat count, engine status, and threat intelligence sources

### Infrastructure
- **Docker Compose deployment** — single `docker compose up -d` to launch the entire stack
- **Host networking** (`network_mode: host`) — preserves real client IPs on the bridge
- **Persistent storage** — SQLite database survives container restarts via volume mount
- **Environment-based configuration** — `.env` file for all deployment variables
- **One-command host setup** — `setup_n95.sh` installs Docker, Zeek, and prepares the appliance

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Network Traffic                       │
│              (all devices on the LAN)                    │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │   Zeek (DPI)   │  ← Deep Packet Inspection on bridge interface
              │   en0 / br0    │  ← Promiscuous mode — sees ALL traffic
              └──┬─────┬───┬──┘
                 │     │   │
          ssl.log  conn.log  dhcp.log
                 │     │   │
                 ▼     ▼   ▼
         ┌──────────────────────┐
         │   zeek_tailer.py     │  ← Async Python log tailer
         │  ┌────────────────┐  │
         │  │ SNI matching   │  │  ← AI/Cloud/Tracker domain detection
         │  │ VPN detection  │  │  ← Port + DPD + Heuristic + DNS layers
         │  │ Upload detect  │  │  ← Volumetric analysis with debouncing
         │  │ DHCP enrichment│  │  ← Passive device fingerprinting
         │  └────────────────┘  │
         └──────────┬───────────┘
                    │ HTTP POST
                    ▼
         ┌──────────────────────┐
         │   FastAPI Backend    │  ← api.py (REST API + static file serving)
         │  ┌────────────────┐  │
         │  │ SQLite (ORM)   │  │  ← Device registry, events, block rules
         │  │ AdGuard client │  │  ← DNS blocking via AdGuard Home API
         │  │ CrowdSec client│  │  ← IPS status via CrowdSec LAPI
         │  └────────────────┘  │
         └──────────┬───────────┘
                    │ JSON API
                    ▼
         ┌──────────────────────┐
         │   Frontend (SPA)     │  ← index.html + app.js (Tailwind + Chart.js)
         │  ┌────────────────┐  │
         │  │ Dashboard      │  │  ← Overview with live stats
         │  │ AI Radar       │  │  ← AI service monitoring + Adoption tab
         │  │ Cloud Storage  │  │  ← Cloud transfer tracking
         │  │ Privacy        │  │  ← Tracker + VPN evasion alerts
         │  │ Devices        │  │  ← Device matrix with drill-down
         │  │ Active Protect │  │  ← CrowdSec IPS insights
         │  │ Rules          │  │  ← Per-service blocking controls
         │  │ Settings       │  │  ← Config + About & Legal
         │  └────────────────┘  │
         └──────────────────────┘
```

---

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **Backend** | FastAPI + Uvicorn | REST API, static file serving |
| **Database** | SQLAlchemy + SQLite | Device registry, events, block rules |
| **Packet Inspection** | Zeek Network Monitor | Deep packet inspection, protocol analysis |
| **DNS Blocking** | AdGuard Home | DNS-level service blocking |
| **IPS** | CrowdSec | Community-driven intrusion prevention |
| **Frontend** | Vanilla JS + Tailwind CSS | Single-page application, dark mode UI |
| **Charts** | Chart.js + Apache ECharts | Doughnut, bar, timeline, Sankey diagrams |
| **Device Fingerprinting** | mac-vendor-lookup + DHCP | OUI database + passive DHCP hostname extraction |
| **Containerization** | Docker + Docker Compose | Production deployment |
| **Async HTTP** | httpx | Non-blocking API calls (CrowdSec, AdGuard) |

---

## Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/yourusername/AIRadar.git
cd AIRadar

# Install Python dependencies
pip install -r requirements.txt

# Start the FastAPI backend
uvicorn api:app --host 0.0.0.0 --port 8000 --reload

# In a separate terminal, start Zeek (requires sudo for packet capture)
cd AIRadar
sudo zeek -i en0 -C LogAscii::use_json=F

# In a third terminal, start the log tailer
python3 zeek_tailer.py --zeek-log-dir .

# Open the dashboard
open http://localhost:8000
```

---

## Production Deployment (N95 Mini-PC)

AI-Radar is designed to run on a headless Intel N95 mini-PC configured as a transparent Layer 2 network bridge. All traffic passes through the bridge, giving Zeek complete visibility.

### Prerequisites
- Ubuntu Server 22.04+ on the N95 mini-PC
- Two Ethernet ports (for bridge mode) or one + WiFi
- Docker and Docker Compose

### Setup

```bash
# 1. Clone to the appliance
git clone https://github.com/yourusername/AIRadar.git /opt/airadar
cd /opt/airadar

# 2. Run the automated host setup script
sudo ./setup_n95.sh

# 3. Configure environment variables
nano .env

# 4. Configure Zeek to listen on the bridge interface
sudo nano /etc/zeek/node.cfg
# Set: interface=br0

# 5. Deploy Zeek and start the stack
sudo zeekctl deploy
docker compose up -d --build

# 6. Generate CrowdSec API key
sudo docker exec crowdsec cscli bouncers add airadar_dashboard
# Paste the key into .env, then:
docker compose restart airadar-app

# 7. Access the dashboard
# Open http://<bridge-ip>:8000 in your browser
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Default | Description |
|---|---|---|
| `AIRADAR_DB_PATH` | `./data/airadar.db` | SQLite database path |
| `ZEEK_LOG_DIR` | `/opt/zeek/logs` | Host path to Zeek log directory |
| `ADGUARD_URL` | `http://localhost:80` | AdGuard Home API endpoint |
| `CROWDSEC_URL` | `http://localhost:8080` | CrowdSec LAPI endpoint |
| `CROWDSEC_API_KEY` | (required) | Generated via `cscli bouncers add` |

---

## Project Structure

```
AIRadar/
├── api.py                 # FastAPI backend — REST API + routing
├── database.py            # SQLAlchemy models (Device, DeviceIP, DetectionEvent, BlockRule)
├── schemas.py             # Pydantic request/response schemas
├── adguard_client.py      # Async AdGuard Home API client
├── zeek_tailer.py         # Async Zeek log tailer (ssl.log, conn.log, dhcp.log)
├── sensor.py              # Legacy scapy-based sensor (deprecated)
├── static/
│   ├── index.html         # SPA frontend — all pages in one HTML file
│   └── app.js             # Frontend logic — routing, charts, filters, device matrix
├── Dockerfile             # Python 3.11-slim container image
├── docker-compose.yml     # Production stack (AI-Radar + AdGuard + CrowdSec)
├── setup_n95.sh           # One-time host setup script for the N95 appliance
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template
└── .gitignore             # Git ignore rules
```

---

## Monitored Services

### AI Services (20+)
Google Gemini, OpenAI/ChatGPT, Anthropic Claude, Microsoft Copilot, Perplexity, HuggingFace, Mistral, DeepSeek, and more.

### Cloud Storage
Google Drive, Dropbox, OneDrive, iCloud, Box, MEGA, WeTransfer, SendGB, Smash.

### Tracking & Analytics
Google Ads, Google Analytics, Facebook/Meta Pixel, Apple Ads, Microsoft Ads, Hotjar, Datadog, Sentry, New Relic, Mixpanel, Segment, Amplitude, FullStory, AdNexus, Criteo, ScoreCard Research.

### VPN Providers
NordVPN, ExpressVPN, Surfshark, ProtonVPN, Private Internet Access, CyberGhost, Mullvad, IPVanish, TunnelBear, Windscribe, Cloudflare WARP.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/ingest` | Ingest a detection event from the Zeek tailer |
| `GET` | `/api/events` | Query events with filters (category, service, source_ip, start) |
| `GET` | `/api/events/export` | Export filtered events as CSV |
| `GET` | `/api/timeline` | Aggregated event timeline (minute/hour/day buckets) |
| `GET` | `/api/summary` | Dashboard summary statistics |
| `GET` | `/api/devices` | List all discovered devices with IPs and vendor info |
| `POST` | `/api/devices` | Register or update a device |
| `GET` | `/api/privacy/stats` | Combined AdGuard + Zeek tracker + VPN alert statistics |
| `POST` | `/api/rules/block` | Block a service (with optional duration) |
| `POST` | `/api/rules/unblock` | Unblock a service |
| `GET` | `/api/rules/status` | Current block rules and global filter status |
| `POST` | `/api/rules/global-filter` | Toggle global filters (parental, social, gaming) |
| `GET` | `/api/ips/status` | CrowdSec IPS status and threat count |
| `POST` | `/api/ips/toggle` | Enable/disable IPS |

---

## Design Philosophy

- **Zero client-side software** — everything is detected passively via network traffic analysis
- **Privacy-first** — AI-Radar inspects metadata (TLS SNI, DNS queries, connection sizes) — never the actual content of encrypted traffic
- **Appliance-grade reliability** — designed to run 24/7 on dedicated hardware with `unless-stopped` restart policies
- **Premium dark mode UI** — UniFi-inspired deep dark theme (#0B0C10) with smooth transitions and hover effects
- **Modular detection** — new services can be added by simply extending the `DOMAIN_MAP` dictionary

---

## Screenshots

The dashboard features a premium dark-mode interface inspired by Ubiquiti's UniFi design language, with real-time statistics, interactive charts, per-device breakdowns, and one-click service blocking.

---

## License

AI-Radar is proprietary software. See the About & Legal section in the Settings page for full attribution of open-source dependencies (FastAPI, Zeek, CrowdSec, AdGuard Home, Chart.js, Apache ECharts).

---

<p align="center">
  Built with ❤️ for network security professionals and business owners who need visibility into AI adoption.
</p>
