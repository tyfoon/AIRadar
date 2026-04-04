# AI-Radar — Claude Code Instructions

## Project
AI-Radar is a network monitoring dashboard that detects AI service usage, cloud traffic, and tracking on a home/SMB network. It runs on a mini-PC (Firebat AM02L) as a transparent L2 bridge.

## Stack
- **Backend**: Python FastAPI + SQLite (api.py)
- **Frontend**: Vanilla JS SPA (static/index.html, static/app.js, static/style.css)
- **Network monitor**: Zeek (runs on host, logs in /opt/zeek/logs/current)
- **DNS filtering**: AdGuard Home (Docker container)
- **IPS**: CrowdSec (Docker container)
- **Deployment**: Docker Compose with host networking

## Key files
- `api.py` — FastAPI backend, device registration, health check, all API endpoints
- `zeek_tailer.py` — Tails Zeek logs, detects AI services, registers devices
- `sensor.py` — Legacy sensor (mostly replaced by zeek_tailer)
- `database.py` — SQLAlchemy models (Device, DeviceIP, DetectionEvent, BlockRule)
- `adguard_client.py` — AdGuard Home API client
- `static/app.js` — Frontend SPA logic
- `static/index.html` — Dashboard HTML
- `static/i18n.js` — Translations (EN/NL)
- `setup.sh` — Deployment script for fresh Ubuntu installs
- `docker-compose.yml` — Production Docker stack
- `.env` — Local config (not in git)

## Git workflow
- After making code changes, always **commit and push** to keep GitHub in sync.
- Commit messages: concise, English, describe the "why".
- Remote: `origin` → `https://github.com/goswijnthijssen/AIRadar.git`

## Deployment
- Production runs on this machine (AM02L mini-PC, Ubuntu 24.04)
- After code changes: `sudo docker compose up -d --build` to rebuild and restart
- Zeek runs on the host: `sudo /opt/zeek/bin/zeekctl deploy`
- Config in `.env` (not committed to git)

## Network
- Bridge interface: br0 (eno1 + enp2s0)
- Bridge IP: 192.168.1.7
- Transparent DNS redirect via iptables (airadar-dns-redirect.service)
- All DNS on the bridge is intercepted and sent to AdGuard
