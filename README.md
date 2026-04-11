<p align="center">
  <img src="https://img.shields.io/badge/AI--Radar-v2.0.0-indigo?style=for-the-badge" alt="Version" />
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
| Block domains | Yes | Yes | Yes |
| See _which device_ uses _which AI service_ | No | No | Yes |
| Detect data uploads to AI providers | No | No | Yes |
| AI adoption metrics (% of workforce) | No | No | Yes |
| VPN evasion detection | No | No | Yes |
| Beacon / C2 detection | No | No | Yes |
| IoT lateral movement alerts | No | No | Yes |
| Per-device, per-service analytics | No | No | Yes |
| Time-based blocking (block for 2 hours) | No | No | Yes |

---

## Features

### Unified Alert System

AI-Radar v2.0 introduces a unified alert card system that provides consistent, actionable threat notifications across every page. Twelve distinct alert types cover the full spectrum of network threats, each rendered with type-specific detail lines, severity badges, and device context.

#### Alert Types

| # | Type | Description |
|---|---|---|
| 1 | **beaconing_threat** | Malware C2 beacon detection using RITA-style multi-dimensional scoring (Bowley skewness, MADM, connection density). Displays source-to-destination IP, country flag with ASN, SNI hostname, connection count, byte totals, severity label (Critical / High / Moderate), and a "new dest" badge when the destination has not been seen before. |
| 2 | **vpn_tunnel** | VPN tunnel detection for NordVPN, ExpressVPN, ProtonVPN, and other commercial providers via SNI pattern matching, ASN lookup, and connection heuristics. |
| 3 | **stealth_vpn_tunnel** | Stealth tunneling protocol detection (AYIYA, Teredo, GRE) identified through Zeek Dynamic Protocol Detection. |
| 4 | **upload** | Data upload alerts to AI and cloud services when transfer volume exceeds the configured threshold, shown with a HIGH severity badge. |
| 5 | **service_access** | Service access notifications with MED severity badge for routine AI/cloud/tracker connections. |
| 6 | **new_device** | New device appearance on the network. Enrichment is delayed five minutes to allow p0f, DHCP, and mDNS data to arrive. IPv6 privacy extension addresses are filtered out to avoid duplicate alerts. |
| 7 | **iot_lateral_movement** | IoT device connecting to other LAN hosts on suspicious ports. HTTP/443 connections are only flagged when Zeek reports an established state (S1/SF) to suppress false positives from UPnP and HEOS discovery. |
| 8 | **iot_suspicious_port** | IoT device connecting to external hosts on ports associated with SSH, Telnet, or IRC. |
| 9 | **iot_new_country** | IoT device communicating with a country it has never contacted before. |
| 10 | **iot_volume_spike** | Traffic volume spike with separate upload/download breakdown and destination identification. |
| 11 | **inbound_threat** | Inbound attacks with CrowdSec integration, including connection outcome badges (blocked / connected / rejected) derived from Zeek conn_state. |
| 12 | **inbound_port_scan** | Port scanning detection from external sources. |

#### Alert Card Features

- **Device type icons** with online/offline status indicator
- **Shortened ASN names** that strip corporate suffixes (Inc, Ltd, GmbH, etc.)
- **Expandable action panel** — Snooze (1h / 4h / 8h / custom datetime picker), Permanent ignore, or Set rule (navigates to the Rules page)
- **Dismiss vs Delete** — Dismiss means "I have seen it" (card grays out but remains on detail pages). Delete is permanent removal, available only on detail pages.
- **Shared rendering** across Summary, Privacy, IoT, and IPS pages via a single `_renderAlertCard()` builder function

---

### Smart Beacon Detection

AI-Radar includes a custom beacon analysis engine inspired by the RITA project. It scores periodic outbound connections across multiple statistical dimensions to surface potential command-and-control channels.

**Destination novelty detection** ensures only genuinely new destinations trigger alerts. A two-tier check compares the exact IP (destinations seen for more than seven days are treated as known baseline) and the ASN organization (catches CDN and cloud providers that rotate IPs). Known destinations have their score reduced by 70%, dropping them below the alert threshold, while new destinations with an unrecognized ASN receive a 20% score boost.

When a beacon alert is dismissed, the current score is stored as a baseline. The alert re-surfaces only if the score rises more than ten points above that baseline, preventing repeated notifications for stable traffic patterns.

---

### Lateral Movement Network Graph

The IoT page features an interactive force-directed network graph built with vis.js. It visualizes internal device-to-device connections that triggered lateral movement alerts.

- Device nodes display type-specific icons (Phosphor icon set) with green (online) or gray (offline) coloring
- Red edges show the suspicious port (SSH/22, HTTP/80, etc.) and the number of observed connections
- A time range selector (1h / 4h / 24h / 48h / 7d) controls the window of displayed activity
- The graph auto-hides when no lateral movements are detected in the selected range
- HTTP/443 lateral movement is only flagged on established connections (Zeek states S1/SF) to avoid false positives from UPnP and HEOS discovery traffic

---

### Connection Outcome Tracking

Every inbound attack now carries a connection outcome derived from Zeek's `conn_state` field:

| Badge | Conn State | Meaning |
|---|---|---|
| **connected** (red, pulsing) | SF | Full connection established — attacker completed handshake and exchanged data |
| **connected** (orange) | S1 | Connection initiated and acknowledged, but no clean teardown observed |
| **blocked** (green) | S0, REJ | SYN sent but no reply, or connection actively rejected |
| **rejected** (gray) | Other | Probe or incomplete attempt |

Escalation logic applies at the group level: if any single connection within an alert group reached an established state, the entire group inherits the most severe outcome badge.

---

### Upload / Download Split

The GeoConversation tracking layer now records `orig_bytes` (upload) and `resp_bytes` (download) separately for every connection. Volume spike alerts display the breakdown as directional indicators (e.g., upload 1.1 MB / download 4.3 MB), making it straightforward to distinguish firmware updates (predominantly download) from potential data exfiltration (predominantly upload).

---

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

### VPN & Evasion Detection (4-Layer System)
1. **Port-based detection** — OpenVPN (UDP/1194), WireGuard (UDP/51820), IPsec (UDP/500, 4500), PPTP, L2TP
2. **DPD (Dynamic Protocol Detection)** — Zeek identifies VPN/Tor protocols _regardless of port_, catching tunnels hidden on port 443
3. **Heuristic detection** — flags devices sending disproportionate encrypted traffic to a single unknown destination (catches NordVPN, ExpressVPN, etc.)
4. **DNS/SNI detection** — identifies connections to known VPN provider domains (NordVPN, ExpressVPN, Surfshark, ProtonVPN, Mullvad, and 10+ others)

### Device Intelligence
- **Passive device recognition via DHCP** — extracts hostname, MAC, and IP from DHCP leases without any client-side software
- **Passive OS fingerprinting via p0f** — identifies operating systems from TCP/IP stack characteristics
- **MAC vendor lookup** (OUI database) — identifies device manufacturers (Apple, Ubiquiti, Espressif, Hikvision, etc.)
- **Device type detection** — pattern matching on hostname/vendor to classify devices (MacBook, Router, iPhone, IP Camera, IoT Device, etc.)
- **IPv6 privacy address merging** — correctly groups multiple IPv6 privacy extension addresses to a single physical device via /64 prefix matching
- **Category-grouped device matrix** — collapsible columns grouped by AI/Cloud/Privacy with heat-map cells and click-to-drill-down event detail

### Rules & Access Control
- **Per-service blocking** with toggle switches — block any AI, cloud, or tracking service with one click
- **Time-based blocking** — block services for 1h, 4h, 8h, 24h, or set a custom end time
- **Global category filters** — Parental Controls, Social Media, Gaming (via AdGuard blocked services API)
- **Automatic expiry** — timed blocks automatically lift when the duration expires

### Active Protect (IPS)
- **CrowdSec integration** — community-driven intrusion prevention system
- Inbound attacks displayed as unified alert cards with connection outcome badges (blocked / connected / rejected)
- CrowdSec reason display with fallback labels ("blocklist match" / "probe / scan")
- Severity filter works directly on the card feed
- Permanent deletion of individual attack records via dedicated API endpoint

### Infrastructure
- **Docker Compose deployment** — single `docker compose up -d` to launch the entire stack
- **Host networking** (`network_mode: host`) — preserves real client IPs on the bridge
- **Persistent storage** — SQLite database survives container restarts via volume mount
- **Environment-based configuration** — `.env` file for all deployment variables
- **One-command host setup** — `setup_n95.sh` installs Docker, Zeek, and prepares the appliance

---

## Service Labeling Pipeline

Identifying _which service_ a flow belongs to is the single hardest problem in network visibility on a modern home network. Direct SNI inspection works beautifully for classic TLS 1.2 / 1.3 handshakes, but it only covers about 30% of real-world traffic once you account for QUIC (HTTP/3), Encrypted ClientHello (ECH), 0-RTT session resumption, and long-lived persistent connections that never re-handshake.

AI-Radar solves this with a **multi-source labeling pipeline** organized as four cooperating layers, resolved by a central `labeler.py` module that enforces a deterministic trust hierarchy. Every label carries provenance (`labeler=...`, `confidence=...`, `rationale=...`) so the UI can always answer "why is this flow marked as YouTube?".

### Quality principles

Quality of information is the top priority of the pipeline — a wrong label is strictly worse than a missing one, because wrong labels poison sessionization, the AI recap, the alert engine, and the operator's mental model.

- **Every label has a herkomst and a confidence.** Events sourced from the AdGuard seed at confidence 0.85 are clearly distinguishable from manual-seed matches at 1.00, and every event records its labeler in `label_attributions` so conflicts can be audited months later.
- **Conflicts are resolved explicitly.** When two labelers propose different services for the same flow, the tier-gated trust hierarchy picks a winner and flags the loser in the audit trail. Nothing is silently overwritten.
- **Multi-source corroboration boosts confidence.** When two labelers agree on the same service within a score window, the winner's confidence is bumped up as a reward for independent corroboration.
- **Observability is first-class.** A dedicated `/api/labeler/stats` endpoint reports coverage per labeler in real time, so the operator can measure how much traffic each layer catches and where the gaps are.
- **Fail-closed.** If the pipeline is uncertain (effective score below `CONFIDENCE_FLOOR = 0.60`), the flow stays unlabeled rather than being assigned a shaky label. Sessionization, the AI recap, and alerts skip these flows entirely; they remain visible in raw-event views for manual review.
- **Per-client scoping.** Multi-tenant CDN IPs (Apple's 17.x edge ranges, Cloudflare, Fastly, Akamai) are labeled per `(client_mac, server_ip)` tuple rather than globally, so one device's observation never pollutes another device's flows.

### The four layers

#### Layer 1 — Direct on-wire SNI (`tail_ssl_log`, `tail_quic_log`)

Classic TLS 1.2/1.3 ClientHellos carry the SNI in plaintext. QUIC Initial packets expose the same `server_name` field until ECH is negotiated. Both logs (`ssl.log` and `quic.log`) are tailed continuously and matched against the curated domain map via `match_domain()`. Direct SNI matches produce `sni_hello` events (labeler `sni_direct`, effective_score 0.95) and direct QUIC matches produce `quic_hello` events (labeler `quic_sni_direct`, effective_score 0.90). This layer catches everything visible at the packet level and is the ground truth for all downstream layers.

#### Layer 2 — DNS correlation (`dns_cache.py`, `tail_dns_log`)

For flows whose ClientHello is missing — typically QUIC 0-RTT resumption or ECH-encrypted handshakes — Layer 2 recovers the service identity from the most recent DNS resolution the same client did. Zeek's `dns.log` is tailed into a per-client LRU cache keyed on `(client_mac, server_ip)`. When `tail_conn_log` sees an unlabeled flow, it asks the cache what hostname the client resolved to that destination IP; if the hostname matches a known service, a `dns_correlated` event fires (labeler `dns_correlation`, effective_score 0.75). The cache enforces several correctness invariants:

- **CNAME-aware parsing** — every IP in a Zeek answer chain maps to the ORIGINAL query, never to intermediate CNAMEs. A response like `youtube.com → youtube-ui.l.google.com → 142.250.180.110` correctly records the IP under `youtube.com`, not under the CNAME.
- **Per-client scoping** — cache entries are keyed on `(client_mac, server_ip)`, so device A resolving `discord.com → 162.159.x.x` and device B resolving `twitch.tv → 162.159.x.x` do not corrupt each other's labels on shared Cloudflare infrastructure.
- **OrderedDict LRU + wire-TTL expiry** — capped at 50,000 entries with O(1) eviction, honoring each DNS response's wire TTL with a sane floor and ceiling.
- **Durable persistence + warm-up** — observations are batched into a `dns_observations` table every 30 seconds, and the cache is re-primed from that table on startup so the ~5 minute cold window after a container rebuild collapses to roughly zero.

#### Layer 3 — Per-client volumetric attribution (`_known_ips`, `tail_conn_log`)

Once Layer 1 or Layer 2 has identified a service for a specific `(client_mac, destination_ip)` pair, Layer 3 propagates that label to the volumetric path: every subsequent flow in `conn.log` from the same client to the same destination accumulates bytes under the same service. This is what makes the byte-per-service charts accurate for streaming sessions that open a few connections at the start and hold them open for 25+ minutes.

The cache is scoped per `(client_mac, server_ip)` — **never** globally by IP. Apple's edge IPs (`17.253.63.x`, `17.248.236.x`, etc.) serve many unrelated services (iCloud, Photos, Mail, Apple TV, App Store, Push, Apple Music), so a global cache would cause device A's `tv.apple.com` handshake to mis-attribute device B's iCloud Photos sync as Apple TV. Per-client scoping closes that leak. When a flow arrives from a device whose MAC is not yet known (brand-new device, pre-DHCP), the write is deliberately skipped — no entry is better than an unscoped entry that re-introduces the bug.

#### Layer 4 — Session reconstruction (activity sessionizer)

Daily usage timelines need per-service active-time estimates, but Layer 1–3 events are sparse by design: SNI dedup limits each `(service, source_ip)` to one event per 30 minutes to avoid flooding. A 25-minute YouTube view might produce only 1–2 handshake events — not enough for the noise-filter threshold the session detector applies.

Layer 4 fixes this by UNIONing the `detection_events` stream with the much denser `geo_conversations` byte-counter table. Every `geo_conversations` row (one per `(mac, service, dest_ip)`) contributes two virtual events at `first_seen` and `last_seen`, clamped to the day window. A Hay Day session touching 6 Supercell IPs thus produces ~12 virtual events over the correct 17-minute timespan, and the session detector correctly renders it as a single Gaming session even though only 2 handshakes made it into `detection_events`.

### The trust hierarchy (`labeler.py`)

Every labeler submits a `LabelProposal(labeler, service, category, confidence, rationale)` to `labeler.resolve()`, which picks a winner and persists the full proposal list as `label_attributions` rows for auditability.

```
SOURCE_WEIGHTS (higher = more trusted)
  manual_seed         1.00   ← operator wrote it down
  curated_v2fly       0.95   ← community-maintained list
  sni_direct          0.95   ← TCP TLS ClientHello, on-wire
  quic_sni_direct     0.90   ← QUIC Initial, on-wire
  adguard_services    0.85   ← AdGuard's official service map
  ja4_community_db    0.80   ← (planned) FoxIO JA4 matches
  dns_correlation     0.75   ← per-client DNS cache match
  llm_inference       0.70   ← (planned) LLM classifier
  ip_asn_heuristic    0.50   ← ASN org-name fuzzy match
```

`effective_score = source_weight × confidence`. Resolution rules:

1. **Tier gate.** Proposals are split into deterministic (`sni_direct`, `quic_sni_direct`, `adguard_services`, `ja4_community_db`, `dns_correlation`, and curated seeds) and probabilistic (`llm_inference`, `ip_asn_heuristic`) tiers. If any deterministic proposal exists, only those can win — a probabilistic source cannot outrank an on-wire observation regardless of its self-reported confidence.
2. **Score-based pick within the winning tier.** Highest `effective_score` wins.
3. **Agreement boost.** When the runner-up agrees on the same service within `AGREEMENT_WINDOW = 0.05`, the winner's confidence is multiplied by `AGREEMENT_BOOST = 1.10` (capped at 1.00) and flagged as `boosted=true`.
4. **Dispute flag.** When the runner-up _disagrees_ with the winner within the same window, the decision is still recorded but marked `is_disputed=true` so the UI can show a warning badge.
5. **Confidence floor.** Winners with effective_score below `CONFIDENCE_FLOOR = 0.60` are marked `is_low_confidence=true`, which excludes them from primary labeling but keeps them in the audit trail.

### Per-labeler rollback flags

Each labeler layer can be toggled independently via environment variables, so an operator can isolate a new labeler in production without a code revert:

| Env var | Default | Effect when `false` |
|---|---|---|
| `LABELER_DNS_SNOOPING` | `true` | Disables `tail_dns_log`, `flush_dns_observations`, and the cache warm-up on startup |
| `LABELER_QUIC_TAILER` | `true` | Disables `tail_quic_log` — QUIC flows fall back through Layer 2/3 |
| _(planned)_ `LABELER_JA4_MATCH` | `true` | Will disable the JA4 community DB lookup once Day 3 ships |
| _(planned)_ `LABELER_LLM_CLASSIFIER` | `true` | Will disable the LLM classifier once Day 4 ships |

### Diagnostic tooling

A family of standalone Bash scripts ship in the repository root for live labeling diagnostics. Each calls into the in-container SQLite database through `docker compose exec` so no host-side Python or database client is required.

| Script | Args | Purpose |
|---|---|---|
| `check_dns_correlation.sh` | none | Post-rebuild smoke test. Container health, tailer banners, detection_events per type, dns_observations persistence, warm-up evidence, quic_hello sample. Run after every labeler deploy. |
| `check_device_activity.sh` | `<ip-or-mac>` | Diagnoses empty Daily usage for a device. Walks the sessionizer data path and reports the count at every filter step (raw → candidates → surviving). Pinpoints whether the problem is categories, thresholds, or missing events. |
| `list_apple_devices.sh` | none | Lists every Apple-vendor or iPad/iPhone/Mac-named device sorted by recent activity. Use when "I played X on the iPad" turns up empty — there may be more than one iPad on the network. |
| `check_hayday.sh` | `<ip>` | Mobile-game specific seed and label audit. Confirms detection_events categories for a device, top unlabeled destinations, and whether `hay`/`supercell`/`clash` exists anywhere in `known_domains` or `detection_events`. |
| `check_hayday_real_traffic.sh` | `<ip>` | Deeper dive around the labeling layer. Lists `geo_conversations` rows 21–50 (beyond the top 20), PTR/ASN matching on Supercell infrastructure, top unlabeled destinations by bytes, mobile-game-ad event timestamps, and temporal correlation of services ±5 min around ad events. |
| `check_laptop_appletv.sh` | `<ip> <utc-ts>` | Per-client-scoping verification. Separates legitimate direct-match events from stale-label inheritance, with section A/B/C verdicts. Use after any `_known_ips` change. |
| `check_laptop_appletv_dns.sh` | `<ip>` | Follow-up that finds which specific DNS queries from the device match an `apple_tv` seed entry. Use when the above verdict is ambiguous. |
| `check_appletv_seed.sh` | none | Audits all `apple_tv` seed entries, flags suspiciously broad ones, simulates `match_domain()` on key iCloud hostnames, and runs the LIVE `match_domain()` from `zeek_tailer` against the most representative samples. |
| `find_appletv_trigger.sh` | `<ip>` | Runs `match_domain()` on every distinct DNS query a device made in the last 12 hours and classifies each as `apple_tv` / other / unlabeled. Uses source_ip for context-aware refinement. |
| `inspect_appletv_event.sh` | `<ip>` | Joins `detection_events` with `label_attributions` so the exact rationale string ("DNS resolved hostname → resp_ip via MAC-suffix") is visible for every apple_tv event. This is the definitive answer to "why did this flow get this label?". |

### Where this is headed

The four layers above deliver approximately 80% coverage of real-world home traffic as of this writing. Remaining work on the roadmap:

- **JA4 community database matching** — adds a deterministic TLS fingerprint lookup against FoxIO's public JA4 database. Catches long-lived QUIC streams whose DNS lookup has expired from the cache, 0-RTT resumed connections, and apps with unique TLS stacks.
- **LLM classifier (PydanticAI + Haiku 4.5)** — classifies the long tail of unknown SNIs and JA4 hashes via typed LLM output, persists ≥0.70 confidence results back into `known_domains` with `source=llm` for subsequent rounds. Strict privacy filter drops `.local`, `.lan`, `.arpa`, raw IPs, and RFC1918 hostnames before any LLM call. Budgeted at $0.50 / day.
- **Coverage dashboard widget** — surfaces `/api/labeler/stats` in the UI with a per-labeler breakdown, attribution-on-hover info icons next to service names, and a disputed-label warning badge for rows where the audit trail has competing proposals.

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
          ssl.log  conn.log  dhcp.log  weird.log  dpd.log
                 │     │   │     │        │
                 ▼     ▼   ▼     ▼        ▼
         ┌──────────────────────────────────────┐
         │          zeek_tailer.py               │  ← Async Python log tailer
         │  ┌────────────────────────────────┐   │
         │  │ SNI matching                   │   │  ← AI/Cloud/Tracker domain detection
         │  │ VPN detection (4-layer)        │   │  ← Port + DPD + Heuristic + DNS
         │  │ Upload / download tracking     │   │  ← Volumetric analysis with debouncing
         │  │ DHCP enrichment                │   │  ← Passive device fingerprinting
         │  │ Lateral movement detection     │   │  ← IoT device-to-device monitoring
         │  │ GeoConversation tracking       │   │  ← Country + ASN + byte split
         │  └────────────────────────────────┘   │
         └──────────────┬───────────────────────-┘
                        │
         ┌──────────────┼───────────────────────┐
         │              │                        │
         ▼              ▼                        ▼
  ┌──────────────┐ ┌────────────────┐  ┌────────────────────┐
  │ beacon_      │ │ p0f_tailer.py  │  │ network_scanner.py │
  │ analyzer.py  │ │                │  │                    │
  │ RITA-style   │ │ Passive OS     │  │ nmap + nbtscan     │
  │ C2 scoring   │ │ fingerprinting │  │ active discovery   │
  └──────┬───────┘ └───────┬────────┘  └─────────┬──────────┘
         │                 │                      │
         └─────────┬───────┘──────────────────────┘
                   │ HTTP POST
                   ▼
         ┌──────────────────────┐
         │   FastAPI Backend    │  ← api.py (REST API + static file serving)
         │  ┌────────────────┐  │
         │  │ SQLite (ORM)   │  │  ← Device registry, events, block rules
         │  │ AdGuard client │  │  ← DNS blocking via AdGuard Home API
         │  │ CrowdSec client│  │  ← IPS status via CrowdSec LAPI
         │  │ Alert engine   │  │  ← Unified alert feed with 12 alert types
         │  │ Gemini summary │  │  ← AI-generated plain-language alert summary
         │  └────────────────┘  │
         └──────────┬───────────┘
                    │ JSON API
                    ▼
         ┌──────────────────────┐
         │   Frontend (SPA)     │  ← index.html + app.js (Tailwind + Chart.js)
         │  ┌────────────────┐  │
         │  │ Dashboard      │  │  ← Overview with unified alert cards
         │  │ AI Radar       │  │  ← AI service monitoring + Adoption tab
         │  │ Cloud Storage  │  │  ← Cloud transfer tracking
         │  │ Privacy        │  │  ← Tracker + VPN evasion + beacon alerts
         │  │ IoT Monitor    │  │  ← Lateral movement graph + IoT alerts
         │  │ Devices        │  │  ← Device matrix with drill-down
         │  │ Active Protect │  │  ← CrowdSec IPS + inbound attack cards
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
| **Network Graph** | vis.js Network | Force-directed lateral movement visualization |
| **Icons** | Phosphor Icons | Consistent icon set across all pages |
| **Flags** | flag-icons CSS | Country flag rendering in alert cards |
| **Device Fingerprinting** | mac-vendor-lookup + DHCP | OUI database + passive DHCP hostname extraction |
| **OS Fingerprinting** | p0f | Passive TCP/IP stack fingerprinting |
| **Beacon Analysis** | Custom RITA-style engine | Multi-dimensional C2 beacon scoring |
| **Internationalization** | Custom i18n module | English and Dutch language support |
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
├── api.py                      # FastAPI backend — REST API, unified alert engine,
│                                 /api/labeler/stats, activity sessionizer SQL
├── database.py                 # SQLAlchemy models — Device, DeviceIP, DetectionEvent,
│                                 DnsObservation, LabelAttribution, JA4Signature,
│                                 UnknownObservation, GeoConversation, BlockRule
├── schemas.py                  # Pydantic schemas, incl. LabelAttributionCreate
├── labeler.py                  # Trust hierarchy + resolve() + tier gate
│                                 (SOURCE_WEIGHTS, DETERMINISTIC_LABELERS,
│                                 persist_attributions)
├── dns_cache.py                # Thread-safe LRU+TTL DNS→IP correlation cache with
│                                 CNAME-aware parsing and per-client scoping
├── adguard_client.py           # Async AdGuard Home API client
├── seed_adguard_services.py    # One-off script that seeds known_domains from
│                                 AdGuard's services.json (source=adguard, conf=0.85)
├── zeek_tailer.py              # Async Zeek log tailer —
│                                 tail_ssl_log   (Layer 1: TCP TLS SNI)
│                                 tail_quic_log  (Layer 1: QUIC Initial SNI)
│                                 tail_dns_log   (Layer 2: DNS cache population)
│                                 tail_conn_log  (Layer 3: per-client volumetric
│                                                 attribution + dns_correlated fallback)
│                                 plus dhcp, ja4d, mdns, DPD, p0f, network scanner
├── beacon_analyzer.py          # RITA-style beacon scoring engine
├── p0f_tailer.py               # Passive OS fingerprinting via p0f log tailing
├── service_updater.py          # Third-party domain list updater
├── network_scanner.py          # Active network scanner (nmap + nbtscan)
├── sensor.py                   # Legacy scapy-based sensor (deprecated)
├── tests/
│   ├── test_dns_cache.py       # 68 stdlib-only assertions for dns_cache invariants
│   │                            (LRU eviction, TTL expiry, CNAME parsing,
│   │                            per-client isolation, replacement counter)
│   └── test_labeler.py         # 46 assertions for labeler.resolve() — tier gate,
│                                 agreement boost, dispute flag, confidence clamp
├── static/
│   ├── index.html              # SPA frontend — all pages in one HTML file
│   ├── app.js                  # Frontend logic — routing, charts, alert cards,
│   │                            _eventDescription, Daily usage renderer
│   ├── style.css               # Custom styles and alert card CSS
│   └── i18n.js                 # Internationalization (English + Dutch) — incl.
│                                 ev.quicConnection / ev.dnsCorrelated keys
├── check_dns_correlation.sh    # Labeler smoke test (Day 0–2 coverage)
├── check_device_activity.sh    # Daily usage sessionizer diagnostic per device
├── list_apple_devices.sh       # Multi-iPad / multi-Mac discovery helper
├── check_hayday.sh             # Mobile-game seed + label audit
├── check_hayday_real_traffic.sh# Deeper mobile-game traffic analysis via geo_conv
├── check_laptop_appletv.sh     # Per-client scoping verification (Day 2.4)
├── check_laptop_appletv_dns.sh # DNS-query to apple_tv seed match trace
├── check_appletv_seed.sh       # Seed audit + live match_domain() calls
├── find_appletv_trigger.sh     # Per-query match_domain classification over 12h
├── inspect_appletv_event.sh    # detection_events + label_attributions rationale
│                                 inspector (the script that cracks "why this label?")
├── Dockerfile                  # Python 3.11-slim container image
├── docker-compose.yml          # Production stack (AI-Radar + AdGuard + CrowdSec)
├── setup_n95.sh                # One-time host setup script for the N95 appliance
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
└── .gitignore                  # Git ignore rules
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
| `POST` | `/api/ingest` | Ingest a detection event from the Zeek tailer. Accepts an optional `attribution` payload (labeler, confidence, rationale) which is persisted to `label_attributions` as the winning proposal for the event. |
| `GET` | `/api/labeler/stats` | Real-time service-labeling coverage per labeler. Reports how many flows were labeled by `sni_direct`, `quic_sni_direct`, `dns_correlation`, `adguard_services`, etc. so the operator can see where coverage is improving or regressing. |
| `GET` | `/api/events` | Query events with filters (category, service, source_ip, start). The `include_heartbeats` flag (default `true`) controls whether zero-byte `sni_hello`, `quic_hello`, and `dns_correlated` events are suppressed to avoid background-handshake noise. |
| `GET` | `/api/events/export` | Export filtered events as CSV |
| `GET` | `/api/timeline` | Aggregated event timeline (minute/hour/day buckets) |
| `GET` | `/api/summary` | Dashboard summary statistics |
| `GET` | `/api/alerts/active` | Unified alert feed with type-specific enrichment for all 12 alert types |
| `GET` | `/api/alerts/ai-summary` | Gemini-generated plain-language alert summary |
| `GET` | `/api/devices` | List all discovered devices with IPs and vendor info |
| `POST` | `/api/devices` | Register or update a device |
| `GET` | `/api/network/graph` | Lateral movement network graph data (nodes + edges) |
| `GET` | `/api/privacy/stats` | Combined AdGuard + Zeek tracker + VPN alert statistics |
| `POST` | `/api/rules/block` | Block a service (with optional duration) |
| `POST` | `/api/rules/unblock` | Unblock a service |
| `GET` | `/api/rules/status` | Current block rules and global filter status |
| `POST` | `/api/rules/global-filter` | Toggle global filters (parental, social, gaming) |
| `POST` | `/api/exceptions` | Create alert exception (dismiss / snooze / permanent whitelist) |
| `GET` | `/api/ips/status` | CrowdSec IPS status and threat count |
| `POST` | `/api/ips/toggle` | Enable/disable IPS |
| `DELETE` | `/api/vpn-alert` | Permanently delete VPN detection events |
| `DELETE` | `/api/inbound-attack` | Permanently delete inbound attack records |

---

## Design Philosophy

- **Zero client-side software** — everything is detected passively via network traffic analysis
- **Privacy-first** — AI-Radar inspects metadata (TLS SNI, DNS queries, connection sizes) — never the actual content of encrypted traffic
- **Appliance-grade reliability** — designed to run 24/7 on dedicated hardware with `unless-stopped` restart policies
- **Premium dark mode UI** — UniFi-inspired deep dark theme (#0B0C10) with smooth transitions and hover effects
- **Modular detection** — new services can be added by simply extending the `DOMAIN_MAP` dictionary
- **Unified alerting** — every threat type renders through the same card system with consistent actions (snooze, dismiss, ignore, set rule)
- **Smart baselines** — beacon and volume alerts adapt to your network over time, reducing false positives without manual tuning

---

## Screenshots

The dashboard features a premium dark-mode interface inspired by Ubiquiti's UniFi design language, with real-time statistics, interactive charts, per-device breakdowns, lateral movement graphs, and unified alert cards with one-click actions.

---

## License

AI-Radar is proprietary software. See the About & Legal section in the Settings page for full attribution of open-source dependencies (FastAPI, Zeek, CrowdSec, AdGuard Home, Chart.js, Apache ECharts, vis.js, Phosphor Icons, flag-icons).

---

<p align="center">
  Built with care for network security professionals and business owners who need visibility into AI adoption.
</p>
