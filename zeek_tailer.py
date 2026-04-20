"""
AI-Radar — Zeek Log Tailer.
Replaces the old scapy-based sensor.py.  Asynchronously tails Zeek's
ssl.log and conn.log files, matches domains against known AI & Cloud
services, and forwards detection events to the FastAPI backend.

Usage:
    python3 zeek_tailer.py [--zeek-log-dir /path/to/zeek/logs]
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

# Local modules — keep imports near the top so dependency cycles surface fast.
from dns_cache import (
    GLOBAL_CACHE as _DNS_CACHE,
    parse_zeek_answers,
    DEFAULT_MIN_TTL_SECONDS,
)
from labeler import LabelProposal, SOURCE_WEIGHTS

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("AIRADAR_API_URL", "http://localhost:8000/api/ingest")
DEVICE_API_URL = os.environ.get("AIRADAR_DEVICE_API_URL", "http://localhost:8000/api/devices")
GEO_API_URL = os.environ.get("AIRADAR_GEO_API_URL", "http://localhost:8000/api/geo/ingest")
GEO_CONV_API_URL = os.environ.get(
    "AIRADAR_GEO_CONV_API_URL",
    "http://localhost:8000/api/geo/conversations/ingest",
)
LAN_CONV_API_URL = os.environ.get(
    "AIRADAR_LAN_CONV_API_URL",
    "http://localhost:8000/api/lan/conversations/ingest",
)
GEO_META_API_URL = os.environ.get(
    "AIRADAR_GEO_META_API_URL",
    "http://localhost:8000/api/geo/metadata/ingest",
)
INBOUND_API_URL = os.environ.get(
    "AIRADAR_INBOUND_API_URL",
    "http://localhost:8000/api/inbound/ingest",
)
SENSOR_ID = socket.gethostname()

# Volumetric upload threshold (bytes)
UPLOAD_THRESHOLD_BYTES = 100_000  # 100 KB

# ---------------------------------------------------------------------------
# VPN detection — known VPN/tunnel ports
# ---------------------------------------------------------------------------
VPN_PORTS: dict[tuple[str, int], str] = {
    # (protocol, port) → VPN type label
    ("udp", 1194):  "OpenVPN",
    ("tcp", 1194):  "OpenVPN",
    ("udp", 51820): "WireGuard",
    ("udp", 500):   "IPsec/IKEv2",
    ("udp", 4500):  "IPsec NAT-T",
    ("tcp", 443):   None,          # Skip — too common (HTTPS); ASN match covers commercial VPNs
    ("udp", 443):   None,          # Skip — UDP/443 is normal QUIC/HTTP3 traffic; rely on DPD + ASN
    ("tcp", 1723):  "PPTP",
    ("udp", 1701):  "L2TP",
    ("tcp", 22):    None,          # SSH — skip, too common
}

# Only flag a port-match VPN if bytes exceed this threshold — filters
# out iOS carrier IKE/IPsec keep-alives which send 50-80 KB one-off
# handshakes to the carrier. Real IPsec tunnels rapidly cross 500 KB.
VPN_BYTE_THRESHOLD = 500_000  # 500 KB

# ---------------------------------------------------------------------------
# Infrastructure protocol detection — well-known low-level services
# ---------------------------------------------------------------------------
# These (proto, port) pairs identify harmless background protocols that an
# IoT device or OS produces automatically.  When matched, the flow is
# labelled with the given (service, category) instead of "unknown", so the
# dashboard shows them as identified traffic.
INFRA_PORTS: dict[tuple[str, int], tuple[str, str]] = {
    ("udp", 123):  ("ntp", "infrastructure"),
    ("udp", 5353): ("mdns", "infrastructure"),
    ("udp", 1900): ("ssdp", "infrastructure"),
}

# Dedup VPN events per (src_ip, dest_port) — avoid flooding dashboard
VPN_DEDUP_SECONDS = 300  # 5-minute window
_vpn_last_seen: dict[tuple[str, int], float] = {}  # (src_ip, resp_port) → ts


# ---------------------------------------------------------------------------
# VPN provider ASN detection — the primary detection method
# ---------------------------------------------------------------------------
# Every major consumer VPN service rents IP space from a small number of
# Autonomous Systems. Matching resp_ip → ASN → provider is deterministic
# (no DPI, no byte-threshold heuristics) and catches commercial VPN apps
# that hop ports and evade DPD. Self-hosted VPNs on standard ports are
# still caught by VPN_PORTS; obfuscated protocols by Zeek's DPD.
#
# Sources (manually curated, April 2026):
#   - https://github.com/brianhama/bad-asn-list
#   - https://github.com/NullifiedCode/ASN-Lists
#   - https://ipapi.is/vpn-exit-nodes.html
#   - WHOIS lookups for each provider's published ranges
#
# Each key is the AS number, each value is the provider label used in
# ai_service (stored as "vpn_<label>"). Update this table when a provider
# migrates or you see false negatives in production.
VPN_PROVIDER_ASNS: dict[int, str] = {
    # M247 — hosts NordVPN, Surfshark, ProtonVPN, CyberGhost, many others.
    # Heavily VPN-dominated; home users rarely have legitimate traffic here.
    9009:   "m247",
    # NOTE: Datacamp/CDN77 (AS60068) intentionally removed. It hosts
    # some NordVPN/ExpressVPN exits but is primarily a legitimate CDN
    # used by thousands of apps. On a home network it produced false
    # positives on normal CDN fetches (186 KB iPhone request flagged
    # as VPN). Real VPN usage through Datacamp exits is still caught
    # via DPD protocol signatures and VPN_PORTS.
    # Mullvad VPN AB — confirmed own ASN.
    16247:  "mullvad",
    # ExpressVPN International Limited.
    133199: "expressvpn",
    # IP Volume inc — ProtonVPN, Surfshark partial.
    202425: "ipvolume",
    # HVC-AS — IPVanish, StrongVPN.
    29802:  "ipvanish",
    # Trabia Network — ExpressVPN pool.
    43350:  "trabia",
    # Quadranet Enterprises — Private Internet Access (PIA).
    8100:   "quadranet",
    # Netprotect / PIA / IPVanish (London Trust Media).
    133695: "pia",
    # CDN Pro Limited — various VPN resellers.
    212238: "cdnpro",
    # Global Layer B.V. — Mullvad partial, multiple niche VPNs.
    49453:  "globallayer",
    # 31173 Services AB — Mullvad partial.
    39351:  "31173",
    # Datapacket.com — ExpressVPN, NordVPN partial.
    44087:  "datapacket",
    # Tefincom S.A. — NordVPN's legacy holding ASN.
    136787: "nordvpn",
    # FlokiNET ehf — many niche / privacy VPNs.
    200651: "flokinet",
}

# Minimum bytes to flag an ASN-matched VPN connection. Much lower than
# the old heuristic because ASN match is deterministic — we just need
# to filter single-packet probes.
VPN_ASN_BYTE_THRESHOLD = 100_000  # 100 KB
VPN_ASN_DEDUP_SECONDS = 300
_vpn_asn_seen: dict[tuple[str, int], float] = {}  # (src_ip, asn) → ts
_vpn_sni_dedup: dict[tuple[str, str], float] = {}  # (src_ip, service) → ts


def _vpn_provider_for_ip(ip: str) -> tuple[int, str] | None:
    """Return (asn, provider_label) if the IP belongs to a known VPN
    provider's ASN, otherwise None. Uses the existing ASN MMDB reader
    loaded for the Geo Traffic drilldown.
    """
    if not ip or not _asn_reader:
        return None
    asn_num, _org = _resolve_asn(ip)
    if asn_num is None:
        return None
    label = VPN_PROVIDER_ASNS.get(asn_num)
    if label:
        return asn_num, label
    return None

# ---------------------------------------------------------------------------
# IoT anomaly detection — lateral movement + suspicious ports
# ---------------------------------------------------------------------------
# These run in the conn.log hot path and fire detection_events
# with category='security' for IoT devices behaving abnormally.

# Device types that count as "IoT" for anomaly monitoring. Matches
# the same classification _detectDeviceType uses in app.js.
_IOT_DEVICE_TYPES = frozenset({
    "air quality monitor", "robot vacuum", "smart dryer", "smart washer",
    "smart dishwasher", "smart airco", "somfy blinds", "slide curtains",
    "energy monitor", "p1 energy meter", "water meter", "smart home",
    "home assistant", "wled led", "awtrix pixel clock", "sonoff nspanel",
    "smart alarm clock", "health monitor", "presence sensor", "camera hub",
    "zigbee coordinator", "iot device", "thermostat", "smart lighting",
    "google home", "google home mini", "nest doorbell", "nest protect",
    "nest hub", "nest cam", "nest", "speaker", "sonos speaker",
    "homepod", "ip camera", "doorbell", "router", "hue sync box",
    "harmony hub", "denon av receiver", "av receiver", "e-reader",
    "chromecast", "apple tv", "tv/media", "lg smart tv",
})

# Ports that indicate lateral scan / exploitation when an IoT device
# connects to another LAN host on them.
_LATERAL_MOVEMENT_PORTS = frozenset({22, 23, 80, 443, 445, 3389, 8080, 8443})
# HTTP(S) ports: only flag as lateral movement when connection was
# actually established (S1/SF). Unestablished probes on these ports
# are typically harmless discovery (mDNS, SSDP, HEOS, UPnP).
_LATERAL_ESTABLISHED_ONLY_PORTS = frozenset({80, 443, 8080, 8443})

# Ports an IoT device should never talk to externally — these are
# strong indicators of compromise (botnet C2, spam relay, etc.)
_IOT_SUSPICIOUS_OUTBOUND_PORTS = frozenset({
    22,    # SSH — IoT shouldn't initiate SSH
    23,    # Telnet — classic Mirai
    25,    # SMTP — spam relay
    6667,  # IRC — botnet C2
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6668, 6669,  # IRC range
})

IOT_ALERT_DEDUP_SECONDS = 300
_iot_alert_last: dict[tuple, float] = {}

# --- Inbound threat detection ---
# Whitelist of (dest_ip, port) tuples that are expected to receive
# external traffic (e.g. reverse proxy).  Loaded from INBOUND_WHITELIST
# env var: "192.168.1.38:80,192.168.1.38:443"
_INBOUND_WHITELIST: set[tuple[str, int]] = set()
_inbound_whitelist_raw = os.environ.get("INBOUND_WHITELIST", "")
for _entry in _inbound_whitelist_raw.split(","):
    _entry = _entry.strip()
    if ":" in _entry:
        _ip, _port = _entry.rsplit(":", 1)
        try:
            _INBOUND_WHITELIST.add((_ip.strip(), int(_port.strip())))
        except ValueError:
            pass

# Ports that are always suspicious when open to the internet
_INBOUND_DANGEROUS_PORTS = frozenset({
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP alt
    8443,  # HTTPS alt
    27017, # MongoDB
})

INBOUND_THREAT_DEDUP_SECONDS = 300
_inbound_threat_last: dict[tuple, float] = {}

# Web probe (80/443 S0) hit counter: only alert when an IP exceeds
# this threshold to avoid flooding Summary with one-off scanners.
INBOUND_WEB_PROBE_ALERT_THRESHOLD = 10  # hits before alerting
_inbound_web_probe_hits: dict[tuple, int] = {}  # (src_ip, resp_ip, port) → hit count

# Port scan detection: track unique ports per (src_ip, dest_ip) in a
# sliding window.  If an external IP hits >= PORTSCAN_THRESHOLD distinct
# ports on the same internal host within PORTSCAN_WINDOW_SECONDS, fire.
PORTSCAN_THRESHOLD = int(os.environ.get("PORTSCAN_THRESHOLD", "5"))
PORTSCAN_WINDOW_SECONDS = int(os.environ.get("PORTSCAN_WINDOW", "60"))
PORTSCAN_DEDUP_SECONDS = 600
_portscan_tracker: dict[tuple[str, str], list[tuple[float, int]]] = {}
_portscan_last_alert: dict[tuple[str, str], float] = {}


def _is_iot_device(mac: str | None) -> str | None:
    """Return the device type string if the MAC is an IoT device, else None.

    Uses the cached _device_meta dict (refreshed every 60s from the API).
    Classification mirrors _detectDeviceType in app.js: checks hostname,
    vendor, display_name, device_class against known IoT patterns.
    """
    if not mac:
        return None
    meta = _device_meta.get(mac)
    if not meta:
        return None

    # Build a haystack from the device metadata — same fields as app.js
    haystack = " ".join(filter(None, [
        meta.get("hostname"),
        meta.get("vendor"),
        meta.get("display_name") if hasattr(meta, "get") else None,
    ])).lower()

    # Quick vendor checks
    vendor = (meta.get("vendor") or "").lower()
    if any(v in vendor for v in (
        "espressif", "hikvision", "sonos", "nest", "signify",
        "philips lighting", "lumi", "withings", "xiaomi", "myenergi",
        "resideo", "honeywell", "texas instruments", "shanghai high",
    )):
        return vendor

    # Hostname pattern checks — check the haystack against known IoT keywords
    for iot_type in _IOT_DEVICE_TYPES:
        # Simple substring check (good enough for a hot-path filter)
        keywords = iot_type.split()
        if all(kw in haystack for kw in keywords):
            return iot_type

    # DHCP vendor class check
    dvc = (meta.get("dhcp_vendor_class") or "").lower()
    if dvc.startswith("udhcp"):  # BusyBox embedded Linux
        return "embedded_iot"

    # device_class from p0f
    dc = (meta.get("device_class") or "").lower()
    if dc == "iot":
        return "iot"

    return None


# ---------------------------------------------------------------------------
# Domain → service mapping (AI + Cloud)
# ---------------------------------------------------------------------------

DOMAIN_MAP: dict[str, tuple[str, str]] = {
    # --- AI services (category="ai") ---
    # Google Gemini — browser sessions use many backend domains
    "gemini.google.com":                                 ("google_gemini", "ai"),
    "gemini.google":                                     ("google_gemini", "ai"),
    "generativelanguage.googleapis.com":                 ("google_gemini", "ai"),
    "aistudio.google.com":                               ("google_gemini", "ai"),
    "ai.google.dev":                                     ("google_gemini", "ai"),
    "bard.google.com":                                   ("google_gemini", "ai"),
    "makersuite.google.com":                             ("google_gemini", "ai"),
    "deepmind.google":                                   ("google_gemini", "ai"),
    "deepmind.com":                                      ("google_gemini", "ai"),
    "notebooklm.google.com":                             ("google_gemini", "ai"),
    "notebooklm.google":                                 ("google_gemini", "ai"),
    "labs.google.com":                                   ("google_gemini", "ai"),
    # Gemini backend API domains (Chrome browser sessions)
    "geller-pa.googleapis.com":                          ("google_gemini", "ai"),
    "proactivebackend-pa.googleapis.com":                ("google_gemini", "ai"),
    "robinfrontend-pa.googleapis.com":                   ("google_gemini", "ai"),
    "aisandbox-pa.googleapis.com":                       ("google_gemini", "ai"),
    "notebooklm-pa.googleapis.com":                      ("google_gemini", "ai"),
    "cloudcode-pa.googleapis.com":                       ("google_gemini", "ai"),
    "alkalimakersuite-pa.clients6.google.com":           ("google_gemini", "ai"),
    "alkalicore-pa.clients6.google.com":                 ("google_gemini", "ai"),
    "webchannel-alkalimakersuite-pa.clients6.google.com":("google_gemini", "ai"),
    # OpenAI / ChatGPT
    "openai.com":                        ("openai", "ai"),
    "chatgpt.com":                       ("openai", "ai"),
    "oaiusercontent.com":                ("openai", "ai"),
    # Anthropic / Claude
    "claude.ai":                         ("anthropic_claude", "ai"),
    "anthropic.com":                     ("anthropic_claude", "ai"),
    # Microsoft Copilot
    "copilot.microsoft.com":             ("microsoft_copilot", "ai"),
    "sydney.bing.com":                   ("microsoft_copilot", "ai"),
    # Microsoft Teams
    "teams.microsoft.com":               ("microsoft_teams", "communication"),
    "teams.cloud.microsoft":             ("microsoft_teams", "communication"),
    "teams.live.com":                    ("microsoft_teams", "communication"),
    "trouter.teams.microsoft.com":       ("microsoft_teams", "communication"),
    "lync.com":                          ("microsoft_teams", "communication"),
    "skype.com":                         ("microsoft_teams", "communication"),
    "skypeassets.com":                   ("microsoft_teams", "communication"),
    # Microsoft Outlook / Exchange
    "outlook.office.com":                ("outlook", "communication"),
    "outlook.office365.com":             ("outlook", "communication"),
    "outlook.live.com":                  ("outlook", "communication"),
    "outlook.cloud.microsoft":           ("outlook", "communication"),
    # Microsoft SharePoint / OneDrive
    "sharepoint.com":                    ("sharepoint", "cloud"),
    "onedrive.com":                      ("onedrive", "cloud"),
    "onedrive.live.com":                 ("onedrive", "cloud"),
    # Perplexity
    "perplexity.ai":                     ("perplexity", "ai"),
    # Hugging Face
    "huggingface.co":                    ("huggingface", "ai"),
    # Mistral
    "mistral.ai":                        ("mistral", "ai"),

    # --- Cloud storage / transfer (category="cloud") ---
    "github.com":                        ("github", "cloud"),
    "githubusercontent.com":             ("github", "cloud"),
    "github.io":                         ("github", "cloud"),
    "dropbox.com":                       ("dropbox", "cloud"),
    "wetransfer.com":                    ("wetransfer", "cloud"),
    "drive.google.com":                  ("google_drive", "cloud"),
    "docs.google.com":                   ("google_drive", "cloud"),
    "drive.usercontent.google.com":      ("google_drive", "cloud"),
    # NOTE: storage.googleapis.com is intentionally NOT in the static map.
    # It's the generic Google Cloud Storage backend used by Drive AND
    # Google Home / Nest device sync AND thousands of 3rd-party apps on
    # GCP. It's resolved context-aware via _AMBIGUOUS_SNI_RESOLVERS below,
    # based on the source device kind (browser_host → google_drive,
    # iot_google → google_device_sync, else → google_generic_cdn).
    "onedrive.live.com":                 ("onedrive", "cloud"),
    "storage.live.com":                  ("onedrive", "cloud"),
    "1drv.ms":                           ("onedrive", "cloud"),
    "icloud.com":                        ("icloud", "cloud"),
    "apple-dns.net":                     ("icloud", "cloud"),
    "apple-dns.com":                     ("icloud", "cloud"),
    # --- Apple infrastructure (not Apple TV) ---
    "mzstatic.com":                      ("app_store", "cloud"),
    "apps.apple.com":                    ("app_store", "cloud"),
    "itunes.apple.com":                  ("app_store", "cloud"),
    "bag.itunes.apple.com":              ("app_store", "cloud"),
    "itunes-apple.com.akadns.net":       ("app_store", "cloud"),
    "swdist.apple.com":                  ("app_store", "cloud"),
    "swdownload.apple.com":              ("app_store", "cloud"),
    "music.apple.com":                   ("apple_music", "streaming"),
    "aod.itunes.apple.com":              ("apple_music", "streaming"),
    "smoot.apple.com":                   ("siri", "cloud"),
    "ls.apple.com":                      ("apple", "cloud"),
    "aaplimg.com":                       ("apple", "cloud"),
    "apple.com.akadns.net":              ("apple", "cloud"),
    "cdn-apple.com":                     ("apple", "cloud"),
    "gdmf.apple.com":                    ("apple", "cloud"),
    "push.apple.com":                    ("apple", "cloud"),
    "push-apple.com.akadns.net":         ("apple", "cloud"),
    "courier-push-apple.com.akadns.net": ("apple", "cloud"),
    "apple-cloudkit.com":                ("icloud", "cloud"),
    "apple.com":                         ("apple", "cloud"),
    "box.com":                           ("box", "cloud"),
    "mega.nz":                           ("mega", "cloud"),
    "sendgb.com":                        ("sendgb", "cloud"),
    "smash.gg":                          ("smash", "cloud"),

    # --- VPN services (category="tracking") ---
    # NordVPN
    "nordvpn.com":                       ("vpn_nordvpn", "tracking"),
    "nordvpn.net":                       ("vpn_nordvpn", "tracking"),
    "nord-apps.com":                     ("vpn_nordvpn", "tracking"),
    "nordcdn.com":                       ("vpn_nordvpn", "tracking"),
    # ExpressVPN
    "expressvpn.com":                    ("vpn_expressvpn", "tracking"),
    "expressapisv2.net":                 ("vpn_expressvpn", "tracking"),
    # Surfshark
    "surfshark.com":                     ("vpn_surfshark", "tracking"),
    # ProtonVPN
    "protonvpn.com":                     ("vpn_protonvpn", "tracking"),
    "protonvpn.ch":                      ("vpn_protonvpn", "tracking"),
    "proton.me":                         ("vpn_protonvpn", "tracking"),
    # Private Internet Access
    "privateinternetaccess.com":         ("vpn_pia", "tracking"),
    # CyberGhost
    "cyberghostvpn.com":                 ("vpn_cyberghost", "tracking"),
    # Mullvad
    "mullvad.net":                       ("vpn_mullvad", "tracking"),
    # IPVanish
    "ipvanish.com":                      ("vpn_ipvanish", "tracking"),
    # TunnelBear
    "tunnelbear.com":                    ("vpn_tunnelbear", "tracking"),
    # Windscribe
    "windscribe.com":                    ("vpn_windscribe", "tracking"),
    # Generic
    "warp.cloudflareaccess.org":         ("vpn_cloudflare_warp", "tracking"),

    # --- Tracking / Ads (category="tracking") ---
    # Google Ads & Analytics
    "doubleclick.net":                   ("google_ads", "tracking"),
    "googlesyndication.com":             ("google_ads", "tracking"),
    "googleadservices.com":              ("google_ads", "tracking"),
    "adservice.google.com":              ("google_ads", "tracking"),
    "google-analytics.com":              ("google_analytics", "tracking"),
    "googletagmanager.com":              ("google_analytics", "tracking"),
    # Facebook / Meta tracking
    "connect.facebook.net":              ("meta_tracking", "tracking"),
    "pixel.facebook.com":                ("meta_tracking", "tracking"),
    # Apple Ads
    "iadsdk.apple.com":                  ("apple_ads", "tracking"),
    # Microsoft Ads
    "adsdk.microsoft.com":               ("microsoft_ads", "tracking"),
    # Third-party analytics & tracking
    "hotjar.com":                        ("hotjar", "tracking"),
    "datadoghq.com":                     ("datadog", "tracking"),
    "sentry.io":                         ("sentry", "tracking"),
    "newrelic.com":                       ("newrelic", "tracking"),
    "mixpanel.com":                      ("mixpanel", "tracking"),
    "segment.io":                        ("segment", "tracking"),
    "segment.com":                       ("segment", "tracking"),
    "amplitude.com":                     ("amplitude", "tracking"),
    "fullstory.com":                     ("fullstory", "tracking"),
    "adnexus.net":                       ("adnexus", "tracking"),
    "criteo.com":                        ("criteo", "tracking"),
    "scorecardresearch.com":             ("scorecardresearch", "tracking"),
    # Google Chrome telemetry
    "antigravity-unleash.goog":          ("google_telemetry", "tracking"),

    # --- Social media (category="social") ---
    "facebook.com":                      ("facebook", "social"),
    "fbcdn.net":                         ("facebook", "social"),
    "instagram.com":                     ("instagram", "social"),
    "cdninstagram.com":                  ("instagram", "social"),
    "tiktok.com":                        ("tiktok", "social"),
    "tiktokcdn.com":                     ("tiktok", "social"),
    "musical.ly":                        ("tiktok", "social"),
    "snapchat.com":                      ("snapchat", "social"),
    "sc-cdn.net":                        ("snapchat", "social"),
    "twitter.com":                       ("twitter", "social"),
    "x.com":                             ("twitter", "social"),
    "twimg.com":                         ("twitter", "social"),
    "pinterest.com":                     ("pinterest", "social"),
    "pinimg.com":                        ("pinterest", "social"),
    "linkedin.com":                      ("linkedin", "social"),
    "reddit.com":                        ("reddit", "social"),
    "redditmedia.com":                   ("reddit", "social"),
    "redditstatic.com":                  ("reddit", "social"),
    "tumblr.com":                        ("tumblr", "social"),
    "whatsapp.com":                      ("whatsapp", "social"),
    "whatsapp.net":                      ("whatsapp", "social"),
    "signal.org":                        ("signal", "social"),

    # --- Gaming (category="gaming") ---
    "steampowered.com":                  ("steam", "gaming"),
    "steamcommunity.com":                ("steam", "gaming"),
    "steamstatic.com":                   ("steam", "gaming"),
    "valvesoftware.com":                 ("steam", "gaming"),
    "epicgames.com":                     ("epic_games", "gaming"),
    "unrealengine.com":                  ("epic_games", "gaming"),
    "fortnite.com":                      ("epic_games", "gaming"),
    "roblox.com":                        ("roblox", "gaming"),
    "rbxcdn.com":                        ("roblox", "gaming"),
    "ea.com":                            ("ea_games", "gaming"),
    "origin.com":                        ("ea_games", "gaming"),
    "xboxlive.com":                      ("xbox_live", "gaming"),
    "xbox.com":                          ("xbox_live", "gaming"),
    "playstation.com":                   ("playstation", "gaming"),
    "playstation.net":                   ("playstation", "gaming"),
    "nintendo.com":                      ("nintendo", "gaming"),
    "nintendo.net":                      ("nintendo", "gaming"),
    "twitch.tv":                         ("twitch", "gaming"),
    "twitchcdn.net":                     ("twitch", "gaming"),
    "discord.com":                       ("discord", "gaming"),
    "discordapp.com":                    ("discord", "gaming"),
    "discord.gg":                        ("discord", "gaming"),
    "supercell.com":                     ("supercell", "gaming"),
    "supercell.net":                     ("supercell", "gaming"),
    "hayday.com":                        ("supercell", "gaming"),
    "haydaygame.com":                    ("supercell", "gaming"),
    "clashofclans.com":                  ("supercell", "gaming"),
    "clashroyale.com":                   ("supercell", "gaming"),
    "brawlstars.com":                    ("supercell", "gaming"),
    "boombeach.com":                     ("supercell", "gaming"),

    # --- Streaming (category="streaming") ---
    "netflix.com":                       ("netflix", "streaming"),
    "nflxvideo.net":                     ("netflix", "streaming"),
    "nflximg.net":                       ("netflix", "streaming"),
    "nflxso.net":                        ("netflix", "streaming"),
    "youtube.com":                       ("youtube", "streaming"),
    "googlevideo.com":                   ("youtube", "streaming"),
    "ytimg.com":                         ("youtube", "streaming"),
    "youtu.be":                          ("youtube", "streaming"),
    "spotify.com":                       ("spotify", "streaming"),
    "spotifycdn.com":                    ("spotify", "streaming"),
    "scdn.co":                           ("spotify", "streaming"),
    "disneyplus.com":                    ("disney_plus", "streaming"),
    "disney-plus.net":                   ("disney_plus", "streaming"),
    "dssott.com":                        ("disney_plus", "streaming"),
    "hbomax.com":                        ("hbo_max", "streaming"),
    "max.com":                           ("hbo_max", "streaming"),
    "primevideo.com":                    ("prime_video", "streaming"),
    "aiv-cdn.net":                       ("prime_video", "streaming"),
    "aiv-delivery.net":                  ("prime_video", "streaming"),
    "pv-cdn.net":                        ("prime_video", "streaming"),
    "amazonvideo.com":                   ("prime_video", "streaming"),
    "tv.apple.com":                      ("apple_tv", "streaming"),
    "videoland.com":                     ("videoland", "streaming"),
    "npo.nl":                            ("npo_start", "streaming"),
    "npostart.nl":                       ("npo_start", "streaming"),

    # --- Adult (category="adult") ---
    "pornhub.com":                       ("pornhub", "adult"),
    "phncdn.com":                        ("pornhub", "adult"),
    "xvideos.com":                       ("xvideos", "adult"),
    "xvideos-cdn.com":                   ("xvideos", "adult"),
    "xhamster.com":                      ("xhamster", "adult"),
    "youporn.com":                       ("youporn", "adult"),
    "redtube.com":                       ("redtube", "adult"),
    "onlyfans.com":                      ("onlyfans", "adult"),
    "chaturbate.com":                    ("chaturbate", "adult"),
    "stripchat.com":                     ("stripchat", "adult"),
    "brazzers.com":                      ("brazzers", "adult"),

    # --- Shopping (category="shopping") ---
    "amazon.com":                        ("amazon", "shopping"),
    "amazon.nl":                         ("amazon", "shopping"),
    "amazon.de":                         ("amazon", "shopping"),
    "media-amazon.com":                  ("amazon", "shopping"),
    "ssl-images-amazon.com":             ("amazon", "shopping"),
    "bol.com":                           ("bol", "shopping"),
    "coolblue.nl":                       ("coolblue", "shopping"),
    "mediamarkt.nl":                     ("mediamarkt", "shopping"),
    "zalando.nl":                        ("zalando", "shopping"),
    "zalando.com":                       ("zalando", "shopping"),
    "shein.com":                         ("shein", "shopping"),
    "temu.com":                          ("temu", "shopping"),
    "aliexpress.com":                    ("aliexpress", "shopping"),
    "marktplaats.nl":                    ("marktplaats", "shopping"),
    "vinted.nl":                         ("vinted", "shopping"),
    "vinted.com":                        ("vinted", "shopping"),
    "ikea.com":                          ("ikea", "shopping"),
    "ebay.com":                          ("ebay", "shopping"),
    "ebay.nl":                           ("ebay", "shopping"),
    "etsy.com":                          ("etsy", "shopping"),

    # --- News (category="news") ---
    "nos.nl":                            ("nos", "news"),
    "nu.nl":                             ("nu_nl", "news"),
    "telegraaf.nl":                      ("telegraaf", "news"),
    "ad.nl":                             ("ad_nl", "news"),
    "nrc.nl":                            ("nrc", "news"),
    "volkskrant.nl":                     ("volkskrant", "news"),
    "bbc.com":                           ("bbc", "news"),
    "bbc.co.uk":                         ("bbc", "news"),
    "nytimes.com":                       ("nytimes", "news"),
    "nyt.com":                           ("nytimes", "news"),
    "reuters.com":                       ("reuters", "news"),
    "theguardian.com":                   ("guardian", "news"),

    # --- Dating (category="dating") ---
    "tinder.com":                        ("tinder", "dating"),
    "gotinder.com":                      ("tinder", "dating"),
    "bumble.com":                        ("bumble", "dating"),
    "hinge.co":                          ("hinge", "dating"),
    "grindr.com":                        ("grindr", "dating"),
    "lexa.nl":                           ("lexa", "dating"),
    "parship.nl":                        ("parship", "dating"),
    "happn.com":                         ("happn", "dating"),
    "okcupid.com":                       ("okcupid", "dating"),
}


# ---------------------------------------------------------------------------
# Context-aware Google service tracker
# ---------------------------------------------------------------------------
# Ambiguous googleapis.com domains (www, content) are used by BOTH Gemini and
# Drive.  We resolve the ambiguity by tracking which Google "context" an IP
# was recently associated with (e.g. gemini.google.com → ai, drive.google.com
# → cloud).  When we see www.googleapis.com from the same IP, we use the most
# recent context to classify it.

# Maps device key → (service, category, timestamp)
# Uses MAC address when available (via _ip_to_mac), falls back to source_ip.
# MAC-based keying is critical because IPv6 privacy extensions rotate the
# source IP, so context set via one IP would not match a later request
# from the same device using a different IPv6 address.
_google_context: dict[str, tuple[str, str, float]] = {}
GOOGLE_CONTEXT_TTL = 3600  # 1 hour — Gemini sessions last longer than 5 min

# Domains that set Google context (but are NOT ambiguous themselves)
_GOOGLE_CONTEXT_SETTERS = {
    "gemini.google.com":                                 ("google_gemini", "ai"),
    "gemini.google":                                     ("google_gemini", "ai"),
    "generativelanguage.googleapis.com":                 ("google_gemini", "ai"),
    "aistudio.google.com":                               ("google_gemini", "ai"),
    "geller-pa.googleapis.com":                          ("google_gemini", "ai"),
    "proactivebackend-pa.googleapis.com":                ("google_gemini", "ai"),
    "robinfrontend-pa.googleapis.com":                   ("google_gemini", "ai"),
    "alkalicore-pa.clients6.google.com":                 ("google_gemini", "ai"),
    "alkalimakersuite-pa.clients6.google.com":           ("google_gemini", "ai"),
    "drive.google.com":                                  ("google_drive", "cloud"),
    "docs.google.com":                                   ("google_drive", "cloud"),
}

# Ambiguous Google domains — classified based on recent context
_GOOGLE_AMBIGUOUS = {
    "www.googleapis.com",
    "content.googleapis.com",
    "content-autofill.googleapis.com",
}


# ---------------------------------------------------------------------------
# Dynamic domain lookup — three-layer merge
# ---------------------------------------------------------------------------
# Layer 1: _dynamic_domain_map (from KnownDomain DB table — seeded from
#          former DOMAIN_MAP, enriched nightly by v2fly). Highest priority.
# Layer 2: third-party data (AdGuard + DuckDuckGo, refreshed every 12h).
# Layer 3: DOMAIN_MAP (static fallback until DB is populated — typically
#          only for the first few seconds of the very first boot).
# The merged result is _effective_domain_map, used by match_domain().

_dynamic_domain_map: dict[str, tuple[str, str]] = {}
_effective_domain_map: dict[str, tuple[str, str]] = dict(DOMAIN_MAP)


def _rebuild_lookup(third_party: dict[str, tuple[str, str]] | None = None) -> None:
    """Merge the three domain layers into one lookup dict.

    Called whenever _dynamic_domain_map or the third-party cache changes.
    Priority: dynamic (KnownDomain) > curated fallback (DOMAIN_MAP) >
    third-party (AdGuard/DDG). Keeps the hot path's lookup dict effectively
    immutable during scans.
    """
    global _effective_domain_map
    merged = dict(third_party) if third_party else {}
    merged.update(DOMAIN_MAP)           # static fallback wins over third-party
    merged.update(_dynamic_domain_map)  # KnownDomain wins over everything
    _effective_domain_map = merged


DOMAIN_CACHE_SYNC_INTERVAL = 300  # refresh from DB every 5 minutes

async def cleanup_memory_caches() -> None:
    """Background task: evict stale entries from in-memory dedup dicts.

    Without this, keys seen only once (e.g. a one-off VPN probe IP or
    a transient Google context) stay in memory forever. Runs every 5
    minutes and removes entries older than their respective TTLs.
    """
    while True:
        await asyncio.sleep(300)
        now = time.time()
        evicted = 0

        # _vpn_last_seen: (src_ip, resp_port) → ts, TTL = VPN_DEDUP_SECONDS (300)
        for k in list(_vpn_last_seen):
            if now - _vpn_last_seen[k] > VPN_DEDUP_SECONDS * 2:
                del _vpn_last_seen[k]; evicted += 1

        # _vpn_asn_seen: (src_ip, asn) → ts, TTL = VPN_ASN_DEDUP_SECONDS (300)
        for k in list(_vpn_asn_seen):
            if now - _vpn_asn_seen[k] > VPN_ASN_DEDUP_SECONDS * 2:
                del _vpn_asn_seen[k]; evicted += 1

        # _dpd_last_seen: (src_ip, proto) → ts, TTL = DPD_DEDUP_SECONDS (300)
        for k in list(_dpd_last_seen):
            if now - _dpd_last_seen[k] > DPD_DEDUP_SECONDS * 2:
                del _dpd_last_seen[k]; evicted += 1

        # _iot_alert_last: (type, src, dst/port) → ts, TTL = IOT_ALERT_DEDUP_SECONDS (300)
        for k in list(_iot_alert_last):
            if now - _iot_alert_last[k] > IOT_ALERT_DEDUP_SECONDS * 2:
                del _iot_alert_last[k]; evicted += 1

        # _google_context: src_ip → (svc, cat, ts), TTL = GOOGLE_CONTEXT_TTL (300)
        for k in list(_google_context):
            _, _, ts = _google_context[k]
            if now - ts > GOOGLE_CONTEXT_TTL * 2:
                del _google_context[k]; evicted += 1

        # _known_ips: (mac, ip) → (svc, cat, ts), TTL = IP_TTL_SECONDS
        # Per-client scoping (Day 2.4) — key is a tuple, value shape
        # is unchanged, so iteration + unpacking still work as-is.
        for k in list(_known_ips):
            _, _, ts = _known_ips[k]
            if now - ts > IP_TTL_SECONDS * 2:
                del _known_ips[k]; evicted += 1

        # _sni_last_seen: (svc, src_ip) → ts, TTL = SNI_DEDUP_SECONDS
        for k in list(_sni_last_seen):
            if now - _sni_last_seen[k] > SNI_DEDUP_SECONDS * 2:
                del _sni_last_seen[k]; evicted += 1

        # _device_cache: ip → ts, TTL = DEVICE_CACHE_TTL
        for k in list(_device_cache):
            if now - _device_cache[k] > DEVICE_CACHE_TTL * 2:
                del _device_cache[k]; evicted += 1

        # _ja4_sent: (ip, ja4, ja4s, sni) → ts, TTL = JA4_TTL_SECONDS
        for k in list(_ja4_sent):
            if now - _ja4_sent[k] > JA4_TTL_SECONDS * 2:
                del _ja4_sent[k]; evicted += 1

        if evicted > 0:
            print(f"[cache-gc] Evicted {evicted} stale entries from memory caches")


async def sync_domain_cache(client=None) -> None:
    """Background task: populate _dynamic_domain_map from KnownDomain
    every 5 minutes. This is how the zeek_tailer picks up domains
    added/updated by the service_updater without a restart.
    """
    global _dynamic_domain_map
    from database import SessionLocal as _SL, KnownDomain as _KD
    while True:
        try:
            db = _SL()
            rows = db.query(_KD.domain, _KD.service_name, _KD.category).all()
            db.close()
            new_map = {r.domain: (r.service_name, r.category) for r in rows}
            if new_map != _dynamic_domain_map:
                _dynamic_domain_map = new_map
                _rebuild_lookup()  # merge with whatever third-party is cached
                print(f"[domain-cache] Synced {len(new_map)} domains from KnownDomain")
        except Exception as exc:
            print(f"[domain-cache] Sync failed: {exc}")
        await asyncio.sleep(DOMAIN_CACHE_SYNC_INTERVAL)


# ---------------------------------------------------------------------------
# PTR / ASN category fallback
# ---------------------------------------------------------------------------
# When DNS correlation fails, use ip_metadata (PTR + ASN) to assign a
# category. We do NOT invent fake service names — the service stays
# "unknown" but the category is set so the dashboard can group traffic.
# Some PTR patterns are specific enough to assign a real service.

# ASN → category mapping. Only ASNs where the category is unambiguous.
_ASN_CATEGORY: dict[int, str] = {
    2906:  "streaming",    # Netflix
    40027: "streaming",    # Netflix Streaming Services
    13414: "streaming",    # Twitter/X video CDN
    32934: "social",       # Facebook/Meta
    63293: "social",       # Facebook/WhatsApp
    714:   "cloud",        # Apple
    15169: "cloud",        # Google
    8075:  "cloud",        # Microsoft
    19679: "cloud",        # Dropbox
    14618: "cloud",        # Amazon (too broad for streaming)
    16509: "cloud",        # Amazon AWS
    13335: "infrastructure",  # Cloudflare (DNS/CDN infra)
    20940: "cloud",        # Akamai
    54113: "cloud",        # Fastly
    63949: "cloud",        # Akamai Technologies
}

# PTR pattern → (service, category). Checked via substring match.
# Only patterns specific enough to identify the actual service.
_PTR_SERVICE_PATTERNS: list[tuple[str, str, str]] = [
    ("nflxvideo.net",    "netflix",       "streaming"),
    ("nflxso.net",       "netflix",       "streaming"),
    ("googlevideo.com",  "youtube",       "streaming"),
    ("fbcdn.net",        "facebook",      "social"),
    ("whatsapp",         "whatsapp",      "social"),
    ("instagram",        "instagram",     "social"),
    ("spotify",          "spotify",       "streaming"),
    ("steamcontent.com", "steam",         "gaming"),
    ("twitch.tv",        "twitch",        "gaming"),
    (".github.com",      "github",        "cloud"),
    (".github.io",       "github",        "cloud"),
    ("aiv-cdn.net",      "prime_video",   "streaming"),
    ("aiv-delivery.net", "prime_video",   "streaming"),
    ("pv-cdn.net",       "prime_video",   "streaming"),
    (".cloudfront.net",  "amazon_cdn",    "cloud"),
    (".aaplimg.com",     "apple",         "cloud"),
]

# In-memory ip_metadata cache: ip → (ptr, asn, asn_org)
# Synced from DB periodically alongside the domain cache.
_ip_meta_cache: dict[str, tuple[str | None, int | None, str | None]] = {}
IP_META_SYNC_INTERVAL = 300  # same cadence as domain cache


async def sync_ip_meta_cache() -> None:
    """Background task: populate _ip_meta_cache from ip_metadata table."""
    global _ip_meta_cache
    from database import SessionLocal as _SL
    while True:
        try:
            db = _SL()
            from sqlalchemy import text as _text
            rows = db.execute(_text(
                "SELECT ip, ptr, asn, asn_org FROM ip_metadata "
                "WHERE asn IS NOT NULL OR ptr IS NOT NULL"
            )).fetchall()
            db.close()
            new = {r[0]: (r[1], r[2], r[3]) for r in rows}
            if len(new) != len(_ip_meta_cache):
                print(f"[ip-meta-cache] Synced {len(new)} entries from ip_metadata")
            _ip_meta_cache = new
        except Exception as exc:
            print(f"[ip-meta-cache] Sync failed: {exc}")
        await asyncio.sleep(IP_META_SYNC_INTERVAL)


def _label_via_ptr_asn(resp_ip: str) -> tuple[str, str] | None:
    """Try to assign (service, category) from PTR/ASN metadata.

    Returns (service, category) or None.  Service may be "unknown" if
    only the category can be determined (ASN-only match).
    """
    meta = _ip_meta_cache.get(resp_ip)
    if not meta:
        return None
    ptr, asn, asn_org = meta

    # PTR patterns first — more specific than ASN
    if ptr:
        ptr_lower = ptr.lower()
        for pattern, service, category in _PTR_SERVICE_PATTERNS:
            if pattern in ptr_lower:
                return service, category

    # ASN category fallback — category only, service stays "unknown"
    if asn and asn in _ASN_CATEGORY:
        return "unknown", _ASN_CATEGORY[asn]

    return None


# ---------------------------------------------------------------------------
# M365 IP-prefix matching
# ---------------------------------------------------------------------------
# IP-prefix list from Microsoft 365 endpoint API. Populated by
# _refresh_third_party_sources() and used as a labeling fallback
# between DNS correlation and PTR/ASN.

import ipaddress as _ipaddress

_m365_ip_prefixes: list[tuple[_ipaddress.IPv4Network | _ipaddress.IPv6Network, str, str]] = []


def _label_via_ip_prefix(resp_ip: str) -> tuple[str, str] | None:
    """Match an IP against M365 IP-prefix ranges.

    Returns (service, category) or None. Unlike PTR/ASN fallback,
    this always returns a specific service name (e.g. microsoft_teams).
    """
    if not _m365_ip_prefixes:
        return None
    try:
        addr = _ipaddress.ip_address(resp_ip)
    except ValueError:
        return None
    for net, service, category in _m365_ip_prefixes:
        if addr in net:
            return service, category
    return None


# ---------------------------------------------------------------------------
# JA4 community DB — in-memory lookup map
# ---------------------------------------------------------------------------
# Keyed on ja4 fingerprint hash → (application, category, confidence).
# Synced from ja4_signatures table every 5 minutes (same cadence as domains).
_ja4_lookup: dict[str, tuple[str, str | None, float]] = {}

JA4_SYNC_INTERVAL = 300  # seconds — match domain cache cadence


async def sync_ja4_cache() -> None:
    """Background task: populate _ja4_lookup from ja4_signatures."""
    global _ja4_lookup
    from database import SessionLocal as _SL, JA4Signature as _JS
    while True:
        try:
            db = _SL()
            rows = db.query(_JS.ja4, _JS.application, _JS.category, _JS.confidence).all()
            db.close()
            new_map = {r.ja4: (r.application, r.category, r.confidence) for r in rows}
            if len(new_map) != len(_ja4_lookup):
                _ja4_lookup = new_map
                print(f"[ja4-cache] Synced {len(new_map)} fingerprints from ja4_signatures")
            else:
                _ja4_lookup = new_map
        except Exception as exc:
            print(f"[ja4-cache] Sync failed: {exc}")
        await asyncio.sleep(JA4_SYNC_INTERVAL)


def match_ja4(ja4_hash: str) -> tuple[str, str | None, float, str] | None:
    """Look up a JA4 hash in the community DB cache.

    Returns (application, category, confidence, rationale) on hit, None on miss.
    """
    hit = _ja4_lookup.get(ja4_hash)
    if not hit:
        return None
    app, cat, conf = hit
    rationale = f"JA4 community DB: {ja4_hash[:20]}… → {app}"
    return app, cat, conf, rationale


def match_domain(
    hostname: str, source_ip: str | None = None
) -> tuple[str, str, str] | None:
    """Match a hostname against the effective domain map.

    Lookup strategy:
      1. Apply Google ambiguous-domain resolver (context-aware).
      2. Exact match on the full hostname — O(1) dict lookup.
      3. Walk the parent domains (foo.bar.example.com → bar.example.com
         → example.com → com) checking each in the dict. This turns
         a previously O(n) scan over ~5000 entries into O(log n) on
         the hostname length (typically 2-4 checks).

    Returns (service_name, category, matched_domain) or None.
    """
    hostname = hostname.rstrip(".").lower()
    if not hostname:
        return None

    # 1) Update Google context if this is a context-setting domain
    #    Key by MAC (via _ip_to_mac) so context survives IPv6 rotation.
    if source_ip:
        ctx_key = _ip_to_mac.get(source_ip, source_ip)
        for ctx_domain, (ctx_svc, ctx_cat) in _GOOGLE_CONTEXT_SETTERS.items():
            if hostname == ctx_domain or hostname.endswith("." + ctx_domain):
                _google_context[ctx_key] = (ctx_svc, ctx_cat, time.time())
                break

    # 2) Handle ambiguous Google domains using context
    for amb_domain in _GOOGLE_AMBIGUOUS:
        if hostname == amb_domain or hostname.endswith("." + amb_domain):
            ctx_key = _ip_to_mac.get(source_ip, source_ip) if source_ip else None
            if ctx_key and ctx_key in _google_context:
                svc, cat, ts = _google_context[ctx_key]
                if (time.time() - ts) < GOOGLE_CONTEXT_TTL:
                    return svc, cat, hostname
            # No context → classify based on domain specifics
            # content-autofill and fonts are clearly not AI
            if hostname in ("content-autofill.googleapis.com", "fonts.googleapis.com"):
                return "google", "tracking", hostname
            # www.googleapis.com is the main Google API gateway — most
            # commonly used by Gemini browser sessions when no context
            # setter was seen yet. Default to Gemini.
            if hostname == "www.googleapis.com":
                return "google_gemini", "ai", hostname
            return "google_drive", "cloud", hostname

    # 3) Fast lookup via the merged map. Exact match first, then walk
    #    parent domains by chopping off the leftmost label each time.
    lookup = _effective_domain_map
    hit = lookup.get(hostname)
    if hit:
        return hit[0], hit[1], hostname
    parts = hostname.split(".")
    for i in range(1, len(parts)):
        candidate = ".".join(parts[i:])
        hit = lookup.get(candidate)
        if hit:
            return hit[0], hit[1], candidate
    return None


async def _refresh_third_party_sources() -> None:
    """Background task: refresh the third-party lookup table.

    Runs once at startup (using the disk cache if fresh, otherwise
    fetching live) and then every 12 hours. The load_third_party_map
    function handles its own caching and fallback logic.
    """
    global _m365_ip_prefixes
    from third_party_sources import load_third_party_map
    while True:
        try:
            tp, ip_prefixes = await load_third_party_map()
            if tp:
                _rebuild_lookup(tp)
                print(
                    f"[third-party] Effective domain map rebuilt: "
                    f"{len(_effective_domain_map)} entries "
                    f"({len(_dynamic_domain_map)} KnownDomain + "
                    f"{len(DOMAIN_MAP)} static fallback + "
                    f"{len(tp)} third-party)"
                )
            if ip_prefixes:
                _m365_ip_prefixes = ip_prefixes
                print(
                    f"[third-party] M365 IP-prefix table loaded: "
                    f"{len(ip_prefixes)} prefixes"
                )
        except Exception as exc:
            print(f"[third-party] Refresh failed: {exc}")
        # Wait 12 hours before the next refresh (cache itself has 7-day TTL)
        await asyncio.sleep(12 * 3600)


# ---------------------------------------------------------------------------
# Phase 2: Context-aware service classification
# ---------------------------------------------------------------------------
# Some SNIs are shared across wildly different services. storage.googleapis.com
# is the canonical example — used by Google Drive, Google Home/Nest device
# sync, Google Photos, Spotify metadata (runs on GCP), and countless 3rd-party
# apps that host assets on GCS. Classifying it uniformly as "google_drive"
# produced misleading alerts like "Google Nest uploading to Drive" when the
# device was actually just syncing its state.
#
# The approach:
#   1. Periodically mirror device metadata (vendor, device_class,
#      dhcp_vendor_class, os_name) from the API into a local cache.
#   2. For each SNI match, derive a coarse "device_kind" from the metadata.
#   3. If the SNI is in _AMBIGUOUS_SNI_RESOLVERS, let the resolver function
#      pick a refined (service_name, category) based on the device_kind.
#
# This keeps the resolver fast (no DB I/O in the hot path), extensible
# (just add new entries to the dict), and graceful (devices without
# metadata fall back to the generic label).

# mac_address → {vendor, device_class, dhcp_vendor_class, os_name}
_device_meta: dict[str, dict] = {}
_device_meta_refreshed_at: float = 0.0
DEVICE_META_TTL = 60  # refresh from API every 60 seconds
API_DEVICES_URL = os.environ.get(
    "AIRADAR_DEVICES_LIST_URL",
    "http://localhost:8000/api/devices",
)


async def _refresh_device_meta(client: "httpx.AsyncClient") -> None:
    """Background task: pull device metadata from the API every minute.

    Stored in a local dict so the hot ssl.log path can classify each
    connection without an HTTP round-trip.
    """
    global _device_meta, _device_meta_refreshed_at
    while True:
        try:
            resp = await client.get(API_DEVICES_URL, timeout=5)
            if resp.status_code == 200:
                new: dict[str, dict] = {}
                for d in resp.json():
                    mac = d.get("mac_address")
                    if not mac:
                        continue
                    new[mac] = {
                        "vendor": d.get("vendor"),
                        "device_class": d.get("device_class"),
                        "dhcp_vendor_class": d.get("dhcp_vendor_class"),
                        "os_name": d.get("os_name"),
                        "hostname": d.get("hostname"),
                    }
                _device_meta = new
                _device_meta_refreshed_at = time.time()
        except Exception as exc:
            # Silent retry — API may be briefly unavailable during restart
            pass
        await asyncio.sleep(DEVICE_META_TTL)


def _classify_device_kind(meta: dict | None) -> str:
    """Infer a coarse device kind from stored metadata.

    Returns one of: browser_host, mobile_ios, mobile_android, iot_google,
    iot_amazon, iot_generic, network_gear, embedded, unknown.
    Priority order: DHCP vendor_class_id (strongest) > p0f OS > MAC vendor.
    """
    if not meta:
        return "unknown"

    vci = (meta.get("dhcp_vendor_class") or "").lower()
    vendor = (meta.get("vendor") or "").lower()
    dc = (meta.get("device_class") or "").lower()
    os_name = (meta.get("os_name") or "").lower()

    # 1. DHCP vendor_class_id — strongest signal
    if vci.startswith("android-dhcp"):
        return "mobile_android"
    if vci.startswith("msft") or "microsoft" in vci:
        return "browser_host"    # Windows desktop/laptop
    if vci.startswith("dhcpcd"):
        return "browser_host"    # Linux
    if vci == "ubnt":
        return "network_gear"
    if "udhcp" in vci:
        return "embedded"        # BusyBox DHCP client = embedded Linux

    # 2. p0f OS fingerprint
    if "macos" in os_name or "mac os" in os_name:
        return "browser_host"
    if "windows" in os_name:
        return "browser_host"
    if os_name == "ios":
        return "mobile_ios"
    if "linux" in os_name and dc not in ("iot",):
        return "browser_host"

    # 3. Vendor + device_class heuristics
    if dc == "phone":
        if "apple" in vendor:
            return "mobile_ios"
        return "mobile_android"
    if dc in ("laptop", "computer"):
        if "apple" in vendor:
            return "browser_host"
        return "browser_host"
    if dc == "iot":
        if "google" in vendor or "nest" in vendor:
            return "iot_google"
        if "amazon" in vendor:
            return "iot_amazon"
        return "iot_generic"

    # 4. Fallback: use vendor alone
    if "google" in vendor and "nest" in vendor:
        return "iot_google"
    if "amazon" in vendor:
        return "iot_amazon"

    return "unknown"


# Ambiguous-SNI resolvers. Each takes a device_kind and returns a
# (service_name, category) tuple. The dict key is matched both as an
# exact hostname and as a parent domain (endswith "." + key).
def _resolve_storage_googleapis(kind: str) -> tuple[str, str]:
    """storage.googleapis.com is shared across many GCP-hosted services.

    - browser_host → likely Drive or a webapp using GCS as a CDN
    - iot_google   → Nest/Chromecast device sync (NOT a file upload)
    - mobile_*     → ambiguous (could be any Google app), use generic label
    - else         → generic GCS backend
    """
    if kind == "browser_host":
        return ("google_drive", "cloud")
    if kind == "iot_google":
        return ("google_device_sync", "cloud")
    if kind in ("mobile_android", "mobile_ios"):
        # Android/iOS apps use GCS for all sorts of things — don't claim Drive
        return ("google_generic_cdn", "cloud")
    return ("google_generic_cdn", "cloud")


_AMBIGUOUS_SNI_RESOLVERS: dict[str, callable] = {
    "storage.googleapis.com": _resolve_storage_googleapis,
}


def _refine_classification(
    sni: str,
    base_service: str,
    base_category: str,
    device_kind: str,
) -> tuple[str, str]:
    """If sni is in the ambiguous list, re-resolve based on device_kind.

    Falls back to the base classification for unknown SNIs, so this can
    be called unconditionally without changing existing behaviour.
    """
    if not sni:
        return base_service, base_category
    host = sni.lower().rstrip(".")
    for amb_sni, resolver in _AMBIGUOUS_SNI_RESOLVERS.items():
        if host == amb_sni or host.endswith("." + amb_sni):
            return resolver(device_kind)
    return base_service, base_category


# ---------------------------------------------------------------------------
# Device fingerprinting
# ---------------------------------------------------------------------------

_device_cache: dict[str, float] = {}  # ip -> last_registered_at
DEVICE_CACHE_TTL = 300  # 5 minutes

# IP → MAC cache — populated from conn.log's orig_l2_addr field.
# Used by ssl.log (which has no MAC) to link events to the correct device.
_ip_to_mac: dict[str, str] = {}  # ip → normalized MAC


# ---------------------------------------------------------------------------
# Hostname sanitization — reject junk values that mDNS/DHCP tailers sometimes
# pick up (service UUIDs, reverse-DNS PTRs, placeholder strings).
# ---------------------------------------------------------------------------
_JUNK_HOSTNAME_LITERALS = {
    "", "(empty)", "(null)", "null", "none", "unknown",
    "localhost", "localhost.localdomain",
    "espressif", "esp32", "esp8266", "esp-device",
}
# UUID v4: 8-4-4-4-12
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# 16+ char pure hex (Spotify Connect IDs, Lumi hex device names)
_HEX_ID_RE = re.compile(r"^[0-9a-f]{16,}$")


def _is_junk_hostname(name) -> bool:
    """Return True if a hostname string is meaningless noise we shouldn't store.

    Catches: empty/placeholder strings, UUIDs, long hex IDs (Spotify/Lumi),
    reverse-DNS PTR records (*.in-addr.arpa / *.ip6.arpa), and known
    default/factory names like 'espressif'.
    """
    if name is None:
        return True
    if not isinstance(name, str):
        return True
    s = name.strip().lower()
    if s in _JUNK_HOSTNAME_LITERALS:
        return True
    if s.endswith(".in-addr.arpa") or s.endswith(".ip6.arpa"):
        return True
    if _UUID_RE.match(s):
        return True
    if _HEX_ID_RE.match(s):
        return True
    return False


def _normalize_mac(mac: str) -> str:
    """Normalize MAC: lowercase, zero-padded octets, colon-separated.
    e.g. 'A2:C0:6D:40:7:F7' → 'a2:c0:6d:40:07:f7'
    """
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return ":".join(format(int(p, 16), "02x") for p in parts)
    except (ValueError, AttributeError):
        return mac.lower()


async def _resolve_mac(ip: str) -> str | None:
    """Resolve an IP address to a MAC via ARP (IPv4) or NDP (IPv6).

    Uses async subprocess so the event loop isn't blocked during
    network spikes when many IPs need resolution simultaneously.
    """
    if ":" in ip:
        return await _resolve_mac_ipv6(ip)
    try:
        proc = await asyncio.create_subprocess_exec(
            "arp", "-n", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
        for line in stdout.decode(errors="replace").splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "at" and i + 1 < len(parts):
                    mac = parts[i + 1]
                    if ":" in mac and mac != "(incomplete)":
                        return _normalize_mac(mac)
                if p == "ether" and i + 1 < len(parts):
                    return _normalize_mac(parts[i + 1])
    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        pass
    return None


# Cache NDP table to avoid running ndp -a for every single IPv6 address
_ndp_cache: dict[str, str] = {}   # normalized IPv6 → MAC
_ndp_cache_ts: float = 0.0
_NDP_CACHE_TTL = 60  # refresh every 60s


async def _refresh_ndp_cache() -> None:
    """Parse the full NDP neighbor table into a lookup dict.

    Uses async subprocess to avoid blocking the event loop.
    """
    global _ndp_cache, _ndp_cache_ts
    now = time.time()
    if now - _ndp_cache_ts < _NDP_CACHE_TTL:
        return
    _ndp_cache_ts = now
    new_cache: dict[str, str] = {}

    async def _run(cmd):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            return stdout.decode(errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return ""

    # macOS: ndp -a
    output = await _run(["ndp", "-a"])
    if output:
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and ":" in parts[1] and parts[1] != "(incomplete)":
                host = parts[0]
                mac = _normalize_mac(parts[1])
                ip_part = host.split(".")[0]
                candidate = ip_part.replace("-", ":")
                try:
                    import ipaddress
                    addr = ipaddress.ip_address(candidate)
                    new_cache[str(addr)] = mac
                except ValueError:
                    pass
    else:
        # Linux fallback: ip -6 neigh
        output = await _run(["ip", "-6", "neigh"])
        for line in output.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    ip6 = parts[0]
                    mac = _normalize_mac(parts[idx + 1])
                    try:
                        import ipaddress
                        addr = ipaddress.ip_address(ip6)
                        new_cache[str(addr)] = mac
                    except ValueError:
                        pass
    _ndp_cache = new_cache


def _eui64_to_mac(ipv6_str: str) -> str | None:
    """Extract MAC address from an EUI-64 encoded IPv6 address (link-local or global).

    EUI-64 embeds the MAC with ff:fe in the middle and flips bit 6 of byte 0.
    e.g. fe80::fa4d:fcff:feda:7058 → f8:4d:fc:da:70:58
    """
    try:
        import ipaddress
        addr = ipaddress.ip_address(ipv6_str)
        if addr.version != 6:
            return None
        iid = int(addr) & 0xFFFFFFFFFFFFFFFF
        eui = iid.to_bytes(8, "big")
        # Verify ff:fe sentinel in bytes 3-4
        if eui[3] != 0xFF or eui[4] != 0xFE:
            return None
        mac_bytes = bytearray(6)
        mac_bytes[0] = eui[0] ^ 0x02  # flip universal/local bit
        mac_bytes[1] = eui[1]
        mac_bytes[2] = eui[2]
        mac_bytes[3] = eui[5]
        mac_bytes[4] = eui[6]
        mac_bytes[5] = eui[7]
        return _normalize_mac(":".join(f"{b:02x}" for b in mac_bytes))
    except (ValueError, IndexError):
        return None


async def _resolve_mac_ipv6(ip: str) -> str | None:
    """Resolve an IPv6 address to MAC via the NDP neighbor cache,
    falling back to EUI-64 extraction for link-local addresses."""
    await _refresh_ndp_cache()
    try:
        import ipaddress
        normalized = str(ipaddress.ip_address(ip))
        mac = _ndp_cache.get(normalized)
        if mac:
            return mac
        # Fallback: extract MAC from EUI-64 encoded addresses
        return _eui64_to_mac(normalized)
    except ValueError:
        return _ndp_cache.get(ip)


def _detect_local_v6_prefixes() -> list[ipaddress.IPv6Network]:
    """Auto-detect global IPv6 /64 prefixes assigned to local interfaces.

    This runs once at startup (not in the hot path), so synchronous
    subprocess is acceptable here.
    """
    prefixes: list[ipaddress.IPv6Network] = []
    try:
        result = subprocess.run(
            ["ip", "-6", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6 "):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        net = ipaddress.ip_network(parts[1], strict=False)
                        # Ensure /64 prefix
                        net64 = ipaddress.ip_network(f"{net.network_address}/64", strict=False)
                        if net64 not in prefixes:
                            prefixes.append(net64)
                    except ValueError:
                        pass
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    # Also allow manual override via env var
    env_prefix = os.environ.get("LOCAL_IPV6_PREFIX", "")
    if env_prefix:
        try:
            net = ipaddress.ip_network(env_prefix, strict=False)
            prefixes.append(net)
        except ValueError:
            pass
    if prefixes:
        print(f"[*] Local IPv6 prefixes: {prefixes}")
    return prefixes

_local_v6_prefixes: list[ipaddress.IPv6Network] = _detect_local_v6_prefixes()


def _detect_local_v4_subnets() -> list[ipaddress.IPv4Network]:
    """Auto-detect IPv4 subnets directly attached to this host.

    Used by the lateral-movement detector to distinguish true in-VLAN
    lateral movement from cross-VLAN routed traffic (which went through
    a gateway and is therefore not a compromise indicator).

    Resolution order:
      1. LOCAL_V4_SUBNETS env var (comma-separated CIDRs) — explicit override
      2. `ip -4 -o addr` on the host network namespace — auto-detect
    """
    subnets: list[ipaddress.IPv4Network] = []

    env_subnets = os.environ.get("LOCAL_V4_SUBNETS", "").strip()
    if env_subnets:
        for part in env_subnets.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                net = ipaddress.ip_network(part, strict=False)
                if isinstance(net, ipaddress.IPv4Network) and net not in subnets:
                    subnets.append(net)
            except ValueError:
                print(f"[!] LOCAL_V4_SUBNETS: invalid CIDR {part!r}, ignoring")
        if subnets:
            print(f"[*] Local IPv4 subnets (env): {[str(s) for s in subnets]}")
            return subnets

    # Interfaces that look local but aren't real LAN segments — Docker
    # bridges, virtual ethernet pairs, tailscale/wireguard tunnels, etc.
    # We filter by interface name prefix; this is cheap and independent
    # of the exact CIDR the user might have configured for Docker.
    _SKIP_IFACE_PREFIXES = (
        "docker", "br-",   # Docker default bridge + user-defined bridges
        "veth",            # container veth pairs
        "cni", "flannel",  # Kubernetes
        "tailscale", "wg", # VPN tunnels
        "zt",              # ZeroTier
        "virbr",           # libvirt
        "tun", "tap",      # generic tunnels
    )

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            # Format: "N: iface    inet 192.168.1.7/24 brd ... scope global iface"
            parts = line.split()
            if len(parts) < 4:
                continue
            # parts[0] = "N:", parts[1] = iface name
            iface = parts[1]
            if any(iface.startswith(p) for p in _SKIP_IFACE_PREFIXES):
                continue
            try:
                idx = parts.index("inet")
            except ValueError:
                continue
            if idx + 1 >= len(parts):
                continue
            cidr = parts[idx + 1]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            if net.is_loopback or net.is_link_local:
                continue
            # Only keep private ranges — public addresses on an interface
            # would indicate a routed public prefix, not a LAN segment.
            if not net.is_private:
                continue
            if net not in subnets:
                subnets.append(net)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        print(f"[!] Failed to auto-detect IPv4 subnets: {exc}")

    if subnets:
        print(f"[*] Local IPv4 subnets (auto): {[str(s) for s in subnets]}")
    else:
        print(
            "[!] No local IPv4 subnets detected — lateral-movement detector "
            "will fall back to 'same /24' heuristic"
        )
    return subnets


_local_v4_subnets: list[ipaddress.IPv4Network] = _detect_local_v4_subnets()


def _is_local_ip(ip: str) -> bool:
    """Check if an IP address is a local/private network address.

    For IPv6, global addresses on the home network (e.g. 2a02:a447:...)
    are NOT in RFC1918 private ranges but ARE local devices.
    Auto-detects the local IPv6 prefix from interface addresses.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_link_local:
            return True
        # Match global IPv6 against local interface prefixes
        if addr.version == 6 and _local_v6_prefixes:
            for prefix in _local_v6_prefixes:
                if addr in prefix:
                    return True
        return False
    except ValueError:
        return False


def _is_multicast_or_broadcast(ip: str) -> bool:
    """True for multicast, broadcast, or all-zero IPs.

    Used by the LAN-conversation accumulator to skip one-to-many chatter
    (mDNS 224.0.0.251, SSDP 239.255.255.250, IPv6 multicast ff02::/16,
    IPv4 broadcast 255.255.255.255). Recording those would explode row
    counts while adding little diagnostic value — they aren't per-peer
    conversations in the sense a user thinks about.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or addr.is_unspecified:
            return True
        if addr.version == 4 and ip == "255.255.255.255":
            return True
        return False
    except ValueError:
        return False


def _same_lan_segment(ip1: str, ip2: str) -> bool:
    """Return True iff ip1 and ip2 are in the same L2 broadcast domain.

    Used to suppress lateral-movement false positives on cross-VLAN
    traffic: if two RFC1918 IPs live in different subnets, the traffic
    between them necessarily traversed a router/firewall and is not
    true lateral movement.

    Rules:
      - Different IP versions → False
      - IPv6: same /64 prefix
      - IPv4: both IPs must fall inside the same detected local subnet.
        If no subnets were detected (headless container without host
        ip access) we fall back to 'same /24' to preserve the legacy
        behaviour on simple flat LANs.
    """
    try:
        a1 = ipaddress.ip_address(ip1)
        a2 = ipaddress.ip_address(ip2)
    except ValueError:
        return False

    if a1.version != a2.version:
        return False

    if a1.version == 6:
        try:
            n1 = ipaddress.ip_network(f"{ip1}/64", strict=False)
            n2 = ipaddress.ip_network(f"{ip2}/64", strict=False)
            return n1.network_address == n2.network_address
        except ValueError:
            return False

    # IPv4
    if _local_v4_subnets:
        for net in _local_v4_subnets:
            if a1 in net and a2 in net:
                return True
        return False

    # Fallback for environments where auto-detect failed
    try:
        n1 = ipaddress.ip_network(f"{ip1}/24", strict=False)
        n2 = ipaddress.ip_network(f"{ip2}/24", strict=False)
        return n1.network_address == n2.network_address
    except ValueError:
        return False


# Dedup cache for TLS fingerprint observations:
# (ip, ja4, ja4s, sni) → timestamp. A device can produce many unique
# (ja4, ja4s, sni) tuples (different apps, different backends) so we
# key on the full tuple — each unique tuple is reported once per TTL.
_ja4_sent: dict[tuple[str, str | None, str | None, str | None], float] = {}
JA4_TTL_SECONDS = 3600  # 1 hour — plenty to survive log rotation

# Separate dedup cache for DHCP vendor_class_id so we don't re-send
# the same fingerprint for the same MAC on every DHCP request.
_dhcp_fp_sent: dict[str, float] = {}
DHCP_FP_TTL_SECONDS = 86400  # 1 day — DHCP fingerprints rarely change


async def register_device(
    client: httpx.AsyncClient,
    ip: str,
    mac: str | None = None,
    ja4: str | None = None,
    ja4s: str | None = None,
    sni: str | None = None,
    dhcp_vendor_class: str | None = None,
    dhcp_fingerprint: str | None = None,
) -> None:
    """Register/update a device on the API (non-blocking).

    Only registers devices with local/private IP addresses — public IPs
    (AI service servers, CDNs, etc.) are NOT devices on our network.

    If *mac* is provided (e.g. from Zeek's orig_l2_addr), it is used
    directly — no ARP lookup needed.

    If *ja4* is provided (JA4 TLS fingerprint from ssl.log), it is sent
    once per (ip, ja4) pair within JA4_TTL_SECONDS. This is independent
    of the general device cache so new JA4s can be reported even when
    the device was already registered recently.
    """
    if not _is_local_ip(ip):
        return

    now = time.time()

    # TLS tuple dedup: skip the call if we've already reported this exact
    # (ip, ja4, ja4s, sni) combination recently AND the general device
    # cache is still warm. This allows frequently-recurring tuples
    # (e.g. "device X talks to storage.googleapis.com") to be reported
    # once per JA4_TTL window instead of on every connection.
    has_tls = bool(ja4 or ja4s or sni)
    if has_tls:
        tls_key = (ip, ja4, ja4s, sni)
        last_tls = _ja4_sent.get(tls_key, 0)
        if now - last_tls < JA4_TTL_SECONDS:
            last_dev = _device_cache.get(ip, 0)
            if now - last_dev < DEVICE_CACHE_TTL:
                return
            # Fall through for keep-alive — but drop the TLS fields
            # so we don't re-record the same tuple counter.
            ja4 = ja4s = sni = None
            has_tls = False
        else:
            _ja4_sent[tls_key] = now

    if not has_tls and not dhcp_vendor_class and not dhcp_fingerprint:
        # No enrichment payload → only send occasional keep-alive
        last = _device_cache.get(ip, 0)
        if now - last < DEVICE_CACHE_TTL:
            return

    _device_cache[ip] = now

    # No reverse DNS — hostnames come exclusively from DHCP and mDNS tailers.
    # Prefer Zeek-provided MAC > conn.log cache > ARP lookup
    if not mac:
        mac = _ip_to_mac.get(ip)  # conn.log cache
    if not mac:
        mac = await _resolve_mac(ip)    # ARP/NDP fallback (async)
    if mac:
        mac = _normalize_mac(mac)
    payload: dict = {"ip": ip}
    if mac:
        payload["mac_address"] = mac
    if ja4:
        payload["ja4"] = ja4
    if ja4s:
        payload["ja4s"] = ja4s
    if sni:
        payload["sni"] = sni
    if dhcp_vendor_class:
        payload["dhcp_vendor_class"] = dhcp_vendor_class
    if dhcp_fingerprint:
        payload["dhcp_fingerprint"] = dhcp_fingerprint
    try:
        await client.post(DEVICE_API_URL, json=payload, timeout=5)
        name = mac or ip
        tags = []
        if ja4:
            tags.append(f"ja4={ja4[:12]}")
        if ja4s:
            tags.append(f"ja4s={ja4s[:12]}")
        if sni:
            tags.append(f"sni={sni}")
        if dhcp_vendor_class:
            tags.append(f"vci={dhcp_vendor_class[:20]}")
        tag_str = f" [{', '.join(tags)}]" if tags else ""
        print(f"[*] Device registered: {ip} -> {name}{tag_str}")
    except httpx.HTTPError:
        pass


# ---------------------------------------------------------------------------
# Known AI IP tracking (for volumetric upload detection via conn.log)
# ---------------------------------------------------------------------------

# Maps destination IP → (service, category, timestamp) — learned from ssl.log SNI
# IPs expire after IP_TTL_SECONDS to prevent false positives from shared IP ranges
# (e.g. Google reuses the same IPs for Gemini, Drive, Gmail, Chrome sync, etc.)
IP_TTL_SECONDS = 600  # 10 minutes — after this, the IP→service mapping is stale

# Per-client scoped label cache (Day 2.4). Key is (client_mac, resp_ip);
# value is (service, category, learned_at_ts). Scoping is the same
# pattern dns_cache.DnsCache uses for DNS correlation: each device's
# flows only inherit labels learned from THAT device's own on-wire
# handshakes. Without this, Apple's edge IPs (and any other multi-
# tenant CDN) get globally tagged with whichever service happened to
# fire first — e.g. iPad A's TLS hello to tv.apple.com on 17.253.63.x
# would cause the laptop's unrelated iCloud Photos sync to the same
# 17.253.63.x to be labelled as "apple_tv" by the conn.log volumetric
# path. Scoping the cache per-client closes that cross-client leak.
#
# Writers MUST skip the write when the client MAC is not yet known
# (e.g. a brand-new device before DHCP/ARP populates _ip_to_mac). No
# entry is better than an unscoped entry that re-introduces the bug;
# the flow will naturally fall through to the per-client DNS
# correlation pad on the next read.
_known_ips: dict[tuple[str, str], tuple[str, str, float]] = {}
#                ^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^
#                (client_mac,       (service, category, ts)

# Day 3: JA4 community DB match — set in main(), checked in ssl.log handler
_ja4_match_enabled: bool = True
#                 resp_ip)

# Tracks cumulative outbound bytes per service
_outbound_bytes: dict[str, int] = {}
_outbound_src: dict[str, str] = {}

# ---------------------------------------------------------------------------
# SNI deduplication — suppress heartbeat / keep-alive TLS handshakes
# ---------------------------------------------------------------------------
# ssl.log doesn't carry byte counts, so we can't tell a real query from a
# keep-alive by size alone.  Instead we deduplicate: for each (service, src_ip)
# pair we only emit one sni_hello event per window.  Actual data transfer is
# still captured separately via conn.log → volumetric_upload events.
#
# Heartbeats from mobile apps (iCloud push, Snapchat presence, etc) fire every
# 5-10 min per device. With a 2-minute window every single ping still made it
# through, producing ~70 noise events per device per 12h. A 30-minute window
# caps it at ~2 events/hour which is plenty to show "service is active" while
# dropping 10-15x of the noise.
SNI_DEDUP_SECONDS = 1800  # 30 minutes per (service, device)
_sni_last_seen: dict[tuple[str, str], float] = {}  # (service, src_ip) → timestamp

# ---------------------------------------------------------------------------
# Upload debounce / clustering
# ---------------------------------------------------------------------------
# When multiple connections to the same service fire within a short window
# (e.g. Google Drive uses 5-10 parallel TCP streams for one file upload),
# we cluster them into a single "volumetric_upload" event instead of flooding
# the dashboard with duplicates.

UPLOAD_DEBOUNCE_SECONDS = 30  # Cluster window

# Per-service tracking: service_name → {first_seen, last_seen, total_bytes, src_ip, category}
_upload_buckets: dict[str, dict] = {}
_debounce_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Event sender
# ---------------------------------------------------------------------------

async def send_event(
    client: httpx.AsyncClient,
    detection_type: str,
    ai_service: str,
    source_ip: str,
    bytes_transferred: int,
    category: str = "ai",
    possible_upload: bool = False,
    attribution: dict | None = None,
) -> None:
    """POST a detection event to the API.

    The optional `attribution` payload is used by labeler-aware paths
    (DNS correlation, JA4 matching, LLM classification, ...) to record
    WHY this event got the service it got. The /api/ingest endpoint
    persists it as a LabelAttribution row for the audit trail. Legacy
    paths that match SNI directly against the service map omit it and
    are bucketed under 'sni_direct_legacy' in /api/labeler/stats.
    """
    event = {
        "sensor_id": SENSOR_ID,
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "detection_type": detection_type,
        "ai_service": ai_service,
        "source_ip": source_ip,
        "bytes_transferred": bytes_transferred,
        "category": category,
        "possible_upload": possible_upload,
    }
    if attribution is not None:
        event["attribution"] = attribution
    try:
        resp = await client.post(API_URL, json=event, timeout=5)
        resp.raise_for_status()
        tag = " [UPLOAD]" if possible_upload else ""
        labeler_tag = f" via {attribution['labeler']}" if attribution else ""
        print(
            f"[+] Event: {ai_service.upper()} ({category}) "
            f"{detection_type} from {source_ip}{tag}{labeler_tag}"
        )
    except httpx.HTTPError as exc:
        print(f"[!] Failed to send event: {exc}")


async def record_upload(
    service: str, category: str, src_ip: str, orig_bytes: int
) -> None:
    """Accumulate an upload hit into a debounce bucket.

    Instead of firing immediately, we collect all upload traffic for the same
    service within UPLOAD_DEBOUNCE_SECONDS into one bucket.  The background
    flusher (flush_upload_buckets) sends the aggregated event once the window
    closes.
    """
    async with _debounce_lock:
        now = time.time()
        if service in _upload_buckets:
            bucket = _upload_buckets[service]
            bucket["total_bytes"] += orig_bytes
            bucket["last_seen"] = now
            bucket["src_ip"] = src_ip  # keep latest
        else:
            _upload_buckets[service] = {
                "first_seen": now,
                "last_seen": now,
                "total_bytes": orig_bytes,
                "src_ip": src_ip,
                "category": category,
            }


async def flush_upload_buckets(client: httpx.AsyncClient) -> None:
    """Background task: every 5s, flush buckets whose window has closed.

    A bucket is flushed when (now - last_seen) > UPLOAD_DEBOUNCE_SECONDS,
    meaning no new traffic arrived for that service within the window.
    """
    while True:
        await asyncio.sleep(5)
        now = time.time()
        to_flush: list[tuple[str, dict]] = []

        async with _debounce_lock:
            expired = [
                svc for svc, b in _upload_buckets.items()
                if (now - b["last_seen"]) > UPLOAD_DEBOUNCE_SECONDS
            ]
            for svc in expired:
                to_flush.append((svc, _upload_buckets.pop(svc)))

        for svc, bucket in to_flush:
            await send_event(
                client,
                detection_type="volumetric_upload",
                ai_service=svc,
                source_ip=bucket["src_ip"],
                bytes_transferred=bucket["total_bytes"],
                category=bucket["category"],
                possible_upload=True,
            )
            total_kb = bucket["total_bytes"] / 1024
            print(
                f"    └─ Clustered upload: {total_kb:,.0f} KB total "
                f"(window: {bucket['last_seen'] - bucket['first_seen']:.1f}s)"
            )


# ---------------------------------------------------------------------------
# Zeek log parser helpers
# ---------------------------------------------------------------------------

def parse_zeek_line(line: str) -> dict[str, str] | None:
    """Parse a tab-separated Zeek log line into a dict using the header.

    Returns None for comment lines or empty lines.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    return line


def parse_zeek_header(lines: list[str]) -> list[str] | None:
    """Extract field names from Zeek log header (#fields line)."""
    for line in lines:
        if line.startswith("#fields"):
            return line.strip().split("\t")[1:]  # skip "#fields"
    return None


# ---------------------------------------------------------------------------
# ssl.log tailer — detects AI/Cloud SNI connections
# ---------------------------------------------------------------------------

async def tail_ssl_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Continuously tail Zeek's ssl.log for new TLS connections.

    When a new line appears, extract the SNI (server_name field), check
    it against our domain map, and if it matches, send a detection event.
    """
    print(f"[*] Tailing ssl.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(2)
            continue

        with open(log_path, "r") as f:
            # Read header to find field indices
            header_lines: list[str] = []
            for line in f:
                if line.startswith("#"):
                    header_lines.append(line)
                else:
                    break
            fields = parse_zeek_header(header_lines) or []

            # Seek to end for tailing
            f.seek(0, 2)

            _line_count = 0
            while True:
                line = f.readline()
                if not line:
                    # Check if file was rotated
                    try:
                        if f.tell() > os.path.getsize(log_path):
                            break  # file rotated, re-open
                    except OSError:
                        break
                    await asyncio.sleep(0.5)
                    continue

                line = line.strip()
                if line.startswith("#") or not line:
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    continue

                if not fields:
                    continue

                parts = line.split("\t")
                if len(parts) != len(fields):
                    continue

                _line_count += 1
                if _line_count % 1000 == 0:
                    await asyncio.sleep(0)

                try:
                    record = dict(zip(fields, parts))
                except Exception as _parse_exc:
                    print(f"[ssl.log] Malformed line skipped: {_parse_exc}")
                    continue

                # Extract SNI and source IP
                sni = record.get("server_name", "-")
                if sni == "-" or not sni:
                    continue

                src_ip = record.get("id.orig_h", "unknown")

                # ── JA4 + JA4S fingerprint extraction (BEFORE domain match) ──
                # Every TLS handshake carries a JA4 (client fingerprint) and
                # sometimes a JA4S (server fingerprint). We record tuples of
                # (client, server, SNI) per device so we can later do
                # context-aware classification — e.g. distinguish a Google
                # Nest talking to storage.googleapis.com from a browser.
                #
                # Zeek writes "-" for missing fields AND "(empty)" for fields
                # that were present but contained an empty value. Both mean
                # "no data" and must be normalised to None so we don't store
                # "(empty)" as a literal string and split one logical tuple
                # into two rows.
                def _clean(val):
                    if not val or val == "-" or val == "(empty)":
                        return None
                    return val
                ja4 = _clean(record.get("ja4"))
                ja4s = _clean(record.get("ja4s"))

                # Pass source_ip so ambiguous Google domains can be resolved
                match = match_domain(sni, source_ip=src_ip)

                # Always report (ja4, ja4s) even if the SNI isn't in our
                # domain map — the naming fallback uses just the JA4 label.
                # When we DO have a match, include the SNI in the tuple so
                # the backend can store it in tls_fingerprints for later
                # context-aware classification.
                if ja4 and _is_local_ip(src_ip):
                    cached_mac = _ip_to_mac.get(src_ip)
                    tuple_sni = sni if match else None
                    asyncio.create_task(register_device(
                        client, src_ip, cached_mac,
                        ja4=ja4, ja4s=ja4s, sni=tuple_sni,
                    ))

                if not match:
                    # --- Day 3: JA4 community DB fallback ---
                    # When SNI doesn't match our domain map, try identifying
                    # the TLS client via its JA4 fingerprint. Only fires for
                    # non-generic fingerprints (generic browsers are dampened
                    # to low confidence by ja4_db_sync and won't pass the
                    # confidence floor in labeler.resolve()).
                    if ja4 and _ja4_match_enabled:
                        ja4_hit = match_ja4(ja4)
                        if ja4_hit:
                            j_app, j_cat, j_conf, j_rationale = ja4_hit
                            # Skip generic browser matches entirely — they
                            # don't tell us which service, only the client.
                            if j_conf <= 0.50:
                                continue
                            proposal = LabelProposal(
                                labeler="ja4_community_db",
                                service=j_app.lower().replace(" ", "_"),
                                category=j_cat or "cloud",
                                confidence=j_conf,
                                rationale=j_rationale,
                            )
                            if proposal.effective_score >= 0.60:
                                await send_event(
                                    client,
                                    detection_type="sni_hello",
                                    ai_service=proposal.service,
                                    source_ip=src_ip,
                                    bytes_transferred=0,
                                    category=proposal.category,
                                    attribution={
                                        "labeler": "ja4_community_db",
                                        "confidence": proposal.effective_score,
                                        "rationale": j_rationale,
                                        "proposed_service": proposal.service,
                                        "proposed_category": proposal.category,
                                    },
                                )
                    continue

                service, category, _domain = match

                # --- Phase 2: context-aware refinement ---
                # For ambiguous SNIs (storage.googleapis.com, etc) we pick
                # a more specific service label based on the source device
                # kind. Lookup uses cached metadata — no DB/API call here.
                cached_mac_for_kind = _ip_to_mac.get(src_ip)
                device_kind = "unknown"
                if cached_mac_for_kind:
                    device_kind = _classify_device_kind(
                        _device_meta.get(cached_mac_for_kind)
                    )
                service, category = _refine_classification(
                    sni, service, category, device_kind
                )

                resp_ip = record.get("id.resp_h", "")

                # Learn this destination IP for conn.log correlation (with
                # TTL). Day 2.4 per-client scoping: the label is stored
                # under (this client's MAC, resp_ip) so it only applies
                # to THIS device's future flows. If we don't know the
                # client's MAC yet (brand-new device pre-DHCP), skip the
                # write entirely — no entry is better than a globally-
                # scoped one that re-introduces the multi-tenant CDN bug.
                _ssl_client_mac = _ip_to_mac.get(src_ip)
                if _ssl_client_mac and resp_ip and resp_ip != "-":
                    _known_ips[(_ssl_client_mac, resp_ip)] = (
                        service, category, time.time()
                    )

                # The JA4 call above already registered the device for us;
                # no separate plain register_device call needed.

                # --- SNI deduplication ---
                # Suppress repeated TLS handshakes (heartbeats / keep-alives)
                # for the same (service, device) within the dedup window.
                # The first hit is always recorded; subsequent ones within
                # SNI_DEDUP_SECONDS are silently dropped.  Real data transfer
                # still shows up via conn.log → volumetric_upload events.
                now = time.time()
                dedup_key = (service, src_ip)
                last = _sni_last_seen.get(dedup_key, 0)
                if (now - last) < SNI_DEDUP_SECONDS:
                    continue  # duplicate — skip
                _sni_last_seen[dedup_key] = now

                # Parse bytes for the event (ssl.log rarely has this)
                orig_bytes = 0
                try:
                    ob = record.get("orig_bytes", "0")
                    if ob and ob != "-":
                        orig_bytes = int(ob)
                except ValueError:
                    pass

                # If this is a VPN service, also fire a vpn_tunnel alert
                # so it shows in the summary dashboard. SNI-based VPN
                # detection (e.g. nordvpn.com domain match) is reliable
                # but the old code only generated sni_hello events which
                # the alert system ignores. Dedup: 1 alert per 5 min.
                if service.startswith("vpn_"):
                    _vpn_sni_key = (src_ip, service)
                    _vpn_sni_now = time.time()
                    _vpn_sni_last = _vpn_sni_dedup.get(_vpn_sni_key, 0)
                    if (_vpn_sni_now - _vpn_sni_last) >= 300:
                        _vpn_sni_dedup[_vpn_sni_key] = _vpn_sni_now
                        await send_event(
                            client,
                            detection_type="vpn_tunnel",
                            ai_service=service,
                            source_ip=src_ip,
                            bytes_transferred=orig_bytes,
                            category="security",
                        )

                await send_event(
                    client,
                    detection_type="sni_hello",
                    ai_service=service,
                    source_ip=src_ip,
                    bytes_transferred=orig_bytes,
                    category=category,
                )


# ---------------------------------------------------------------------------
# Day 2 — QUIC SNI tailer
# ---------------------------------------------------------------------------
# Zeek's quic.log records the unencrypted Initial-packet SNI for every QUIC
# (HTTP/3) connection on the bridge. ECH adoption is still nascent, so the
# server_name field is populated for ~50-70% of QUIC handshakes today —
# YouTube, Spotify, WhatsApp, mobile apps. Without this tailer those
# flows show up as anonymous UDP/443 in conn.log and have to fall through
# to the dns_correlation pad (Day 1) — which works, but loses the bytes
# attribution and the per-flow precision that direct on-wire SNI gives us.
#
# This tailer is a near-clone of tail_ssl_log: same field shape (server_name
# is the SNI), same _known_ips population, same dedup window. Three things
# are different:
#
#   1. detection_type = "quic_hello" so /api/labeler/stats can split QUIC
#      from TCP TLS in coverage reports.
#
#   2. The send_event call carries an attribution payload from the start —
#      labeler="quic_sni_direct", confidence=1.0 → effective 0.90 (vs
#      sni_direct's 0.95). The slightly-lower weight reflects that QUIC
#      Initial packets allow a bit more parser ambiguity than TCP TLS
#      ClientHello, but it still sits firmly above adguard_services and
#      every probabilistic source.
#
#   3. No JA4 / JA4S extraction. JA4 for QUIC is JA4Q which is structurally
#      different and lives in tls_fingerprints already from the existing
#      ja4d pipeline. Day 3 (JA4 community DB matching) will close that
#      loop separately.
#
# bytes_transferred is set to 0 here — quic.log has no orig_bytes / resp_bytes
# fields, so byte attribution comes from the existing volumetric path in
# tail_conn_log via _known_ips, exactly like the SNI hello path does.

async def tail_quic_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Continuously tail Zeek's quic.log for QUIC connections with a
    visible (un-ECH'd) server_name in their Initial packet.

    Same dedup, same _known_ips contract, same VPN handling as ssl.log;
    different detection_type and labeler so the audit trail can tell
    them apart.
    """
    print(f"[*] Tailing quic.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            # Zeek may not have the QUIC analyzer enabled yet (older
            # builds, or @load policy/protocols/quic missing from
            # local.zeek). The tailer is harmless when the file is
            # missing — we just keep checking. The setup.sh notes
            # this requirement for fresh installs.
            await asyncio.sleep(5)
            continue

        try:
            with open(log_path, "r") as f:
                header_lines: list[str] = []
                for line in f:
                    if line.startswith("#"):
                        header_lines.append(line)
                    else:
                        break
                fields = parse_zeek_header(header_lines) or []
                f.seek(0, 2)

                _line_count = 0
                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break  # rotated, re-open
                        except OSError:
                            break
                        await asyncio.sleep(0.5)
                        continue

                    line = line.strip()
                    if line.startswith("#") or not line:
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        continue

                    if not fields:
                        continue

                    parts = line.split("\t")
                    if len(parts) != len(fields):
                        continue

                    _line_count += 1
                    if _line_count % 1000 == 0:
                        await asyncio.sleep(0)

                    try:
                        record = dict(zip(fields, parts))
                    except Exception as _parse_exc:
                        print(f"[quic.log] Malformed line skipped: {_parse_exc}")
                        continue

                    # Most QUIC handshakes start with an Initial packet
                    # that has no server_name yet, then the analyzer
                    # updates the same row when the second Initial
                    # arrives. We only act when server_name is present;
                    # the half-row (no SNI) is irrelevant for labelling.
                    sni = record.get("server_name", "-")
                    if not sni or sni == "-" or sni == "(empty)":
                        continue

                    src_ip = record.get("id.orig_h", "unknown")
                    resp_ip = record.get("id.resp_h", "")

                    # Domain match — same path as ssl.log so a domain
                    # in known_domains gets the same service identity
                    # whether it arrived via TCP TLS or QUIC.
                    match = match_domain(sni, source_ip=src_ip)
                    if not match:
                        continue
                    service, category, _domain = match

                    # Phase-2 context-aware refinement: ambiguous SNIs
                    # (storage.googleapis.com and friends) get a more
                    # specific label based on the source device kind.
                    cached_mac_for_kind = _ip_to_mac.get(src_ip)
                    device_kind = "unknown"
                    if cached_mac_for_kind:
                        device_kind = _classify_device_kind(
                            _device_meta.get(cached_mac_for_kind)
                        )
                    service, category = _refine_classification(
                        sni, service, category, device_kind
                    )

                    # Promote into _known_ips so subsequent volumetric
                    # flows in conn.log to this destination get the
                    # same attribution. TTL is bumped on every hit
                    # because we just observed fresh activity.
                    # Day 2.4 per-client scoping: key is (mac, ip), so
                    # a QUIC hello from THIS device only influences
                    # THIS device's future conn.log attribution. The
                    # MAC comes from `cached_mac_for_kind` which the
                    # phase-2 refinement above already looked up — no
                    # extra lookup needed. Skip the write if we don't
                    # yet know the client's MAC.
                    if cached_mac_for_kind and resp_ip and resp_ip != "-":
                        _known_ips[(cached_mac_for_kind, resp_ip)] = (
                            service, category, time.time()
                        )

                    # Dedup against the SHARED _sni_last_seen dict, not
                    # a separate quic dict. Rationale: from the
                    # operator's perspective, "youtube on iPad-A" is
                    # one logical event regardless of whether it
                    # arrived via TCP TLS or QUIC. Whichever tailer
                    # sees it first reports it; the other respects
                    # the dedup window and stays silent. The downside
                    # is that the QUIC tailer's hit count looks
                    # smaller in /api/labeler/stats than reality
                    # (Day 6 can break this out into "seen vs
                    # deduped" if it matters).
                    now = time.time()
                    dedup_key = (service, src_ip)
                    last = _sni_last_seen.get(dedup_key, 0)
                    if (now - last) < SNI_DEDUP_SECONDS:
                        continue
                    _sni_last_seen[dedup_key] = now

                    # Build the attribution payload. Effective score
                    # is computed by labeler.LabelProposal so a future
                    # change to SOURCE_WEIGHTS or DETERMINISTIC_LABELERS
                    # propagates here without a code change.
                    quic_version = record.get("version", "?")
                    proposal = LabelProposal(
                        labeler="quic_sni_direct",
                        service=service,
                        category=category,
                        confidence=1.0,
                        rationale=(
                            f"QUIC Initial server_name={sni} "
                            f"(version={quic_version})"
                        ),
                    )

                    # VPN-tunnel side event: same handling as the SSL
                    # path so the alert dashboard sees vpn_ services
                    # arriving via QUIC too (NordVPN's QUIC mode and
                    # any other vpn over h3).
                    if service.startswith("vpn_"):
                        _vpn_key = (src_ip, service)
                        _vpn_now = time.time()
                        _vpn_last = _vpn_sni_dedup.get(_vpn_key, 0)
                        if (_vpn_now - _vpn_last) >= 300:
                            _vpn_sni_dedup[_vpn_key] = _vpn_now
                            await send_event(
                                client,
                                detection_type="vpn_tunnel",
                                ai_service=service,
                                source_ip=src_ip,
                                bytes_transferred=0,
                                category="security",
                                attribution={
                                    "labeler": proposal.labeler,
                                    "confidence": proposal.effective_score,
                                    "rationale": proposal.rationale,
                                    "proposed_service": service,
                                    "proposed_category": "security",
                                    "is_low_confidence": False,
                                    "is_disputed": False,
                                },
                            )

                    await send_event(
                        client,
                        detection_type="quic_hello",
                        ai_service=service,
                        source_ip=src_ip,
                        bytes_transferred=0,  # quic.log has no byte counts;
                                              # tail_conn_log accumulates
                                              # via _known_ips
                        category=category,
                        attribution={
                            "labeler": proposal.labeler,
                            "confidence": proposal.effective_score,
                            "rationale": proposal.rationale,
                            "proposed_service": service,
                            "proposed_category": category,
                            "is_low_confidence": False,
                            "is_disputed": False,
                        },
                    )
        except (OSError, IOError) as exc:
            print(f"[!] quic.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# GeoIP country lookups + traffic accumulation
# ---------------------------------------------------------------------------
# Resolves public IPs to country codes via a local MMDB (DB-IP Country Lite,
# MaxMind-format compatible). The conn.log tailer accumulates byte totals per
# (country_code, direction) into an in-memory buffer, and a background task
# flushes this buffer to the geo_traffic table every 15 seconds so the UI
# gets near-real-time updates without one DB write per packet.

GEO_DB_CANDIDATES = [
    os.environ.get("GEOIP_DB_PATH", ""),
    "/app/data/GeoLite2-Country.mmdb",
    str(Path(__file__).parent / "data" / "GeoLite2-Country.mmdb"),
]
_geo_reader = None
# Use the low-level maxminddb reader directly instead of geoip2.database.Reader
# because geoip2's high-level methods (.country(), .city(), etc.) validate the
# database type string in the MMDB metadata — e.g. they require
# "GeoLite2-Country". DB-IP's free country MMDB has a different type string
# ("DBIP-Country-Lite"), so geoip2 rejects it even though the schema is
# compatible. maxminddb.open_database() works on ANY MMDB file.
try:
    import maxminddb  # type: ignore
    for _p in GEO_DB_CANDIDATES:
        if _p and os.path.exists(_p):
            try:
                _geo_reader = maxminddb.open_database(_p)
                print(f"[geo] GeoIP country DB loaded from {_p} (type: {_geo_reader.metadata().database_type})")
                break
            except Exception as _exc:
                print(f"[geo] Failed to open {_p}: {_exc}")
    if not _geo_reader:
        print("[geo] No GeoIP database found — Geo Traffic dashboard will be empty")
except ImportError:
    print("[geo] maxminddb library not installed — Geo Traffic dashboard disabled")


_geo_lookup_errors = 0

# ---------------------------------------------------------------------------
# ASN lookup (separate MMDB from the country DB)
# ---------------------------------------------------------------------------
ASN_DB_CANDIDATES = [
    os.environ.get("ASN_DB_PATH", ""),
    "/app/data/GeoLite2-ASN.mmdb",
    "/app/data/dbip-asn.mmdb",
    str(Path(__file__).parent / "data" / "GeoLite2-ASN.mmdb"),
    str(Path(__file__).parent / "data" / "dbip-asn.mmdb"),
]
ASN_DB_DOWNLOAD_URL = os.environ.get(
    "ASN_DB_DOWNLOAD_URL",
    "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn-mmdb/dbip-asn.mmdb",
)
# Where to write the DB if we auto-download — prefer the shared data
# volume so the file persists across container restarts.
ASN_DB_DOWNLOAD_DEST = Path(
    os.environ.get("ASN_DB_DOWNLOAD_DEST", "/app/data/dbip-asn.mmdb")
)
_asn_reader = None


def _open_asn_reader() -> None:
    """Look for an ASN MMDB in the candidate paths and open the first
    one we find. Kept as a function so it can be called again after a
    runtime download."""
    global _asn_reader
    try:
        import maxminddb  # type: ignore  # harmless reimport
    except ImportError:
        return
    for _p in ASN_DB_CANDIDATES:
        if _p and os.path.exists(_p):
            try:
                _asn_reader = maxminddb.open_database(_p)
                print(f"[asn] ASN DB loaded from {_p} (type: {_asn_reader.metadata().database_type})")
                return
            except Exception as _exc:
                print(f"[asn] Failed to open {_p}: {_exc}")


async def ensure_asn_db(client) -> None:
    """Download the ASN MMDB at startup if none is present.

    Lets the feature work without requiring the user to re-run setup.sh
    — the tailer pulls the file into the shared data volume on first
    boot, then uses it for all subsequent enrichment. Safe to call
    repeatedly; noop if a reader is already loaded.
    """
    global _asn_reader
    if _asn_reader:
        return
    try:
        ASN_DB_DOWNLOAD_DEST.parent.mkdir(parents=True, exist_ok=True)
        print(f"[asn] Downloading ASN MMDB → {ASN_DB_DOWNLOAD_DEST}")
        async with client.stream("GET", ASN_DB_DOWNLOAD_URL, timeout=120) as resp:
            resp.raise_for_status()
            with open(ASN_DB_DOWNLOAD_DEST, "wb") as f:
                async for chunk in resp.aiter_bytes():
                    f.write(chunk)
        print(f"[asn] Downloaded ASN MMDB ({ASN_DB_DOWNLOAD_DEST.stat().st_size / 1024 / 1024:.1f} MB)")
        _open_asn_reader()
    except Exception as exc:
        print(f"[asn] Download failed: {exc} — enrichment will use PTR only")


# Initial attempt at startup (covers the case where setup.sh already
# placed the file). The runtime download below handles fresh installs.
_open_asn_reader()
if not _asn_reader:
    print("[asn] No ASN database found yet — will auto-download on tailer startup")


def _resolve_asn(ip: str) -> tuple[int | None, str | None]:
    """Return (asn_number, asn_org) for an IP or (None, None)."""
    if not _asn_reader or not ip:
        return None, None
    try:
        result = _asn_reader.get(ip)
        if not result or not isinstance(result, dict):
            return None, None
        # MaxMind GeoLite2-ASN schema:
        asn_num = result.get("autonomous_system_number")
        asn_org = result.get("autonomous_system_organization")
        if asn_num or asn_org:
            return (int(asn_num) if asn_num else None, asn_org)
        # DB-IP ASN-Lite alternative schema:
        if "asn" in result:
            try:
                return int(result["asn"]), result.get("as_name") or result.get("organization")
            except (TypeError, ValueError):
                pass
        return None, None
    except Exception:
        return None, None


# IATA airport code → ISO-3166-1 alpha-2. Used to override the MMDB
# country result for anycast networks (Google 1e100.net, CloudFront)
# whose IPs the free DB-IP MMDB tends to misattribute — e.g. Google
# Frankfurt edges (74.125.163.x with `fra24s19-in-fN.1e100.net` PTR)
# get tagged as RU. The PTR contains the real PoP location, so we
# parse the leading airport code and trust that over the MMDB row.
_AIRPORT_TO_CC: dict[str, str] = {
    # Europe
    "fra": "DE", "muc": "DE", "ber": "DE", "ham": "DE", "dus": "DE", "txl": "DE",
    "ams": "NL", "lhr": "GB", "lcy": "GB", "lgw": "GB", "man": "GB", "edi": "GB",
    "cdg": "FR", "par": "FR", "ory": "FR", "mrs": "FR", "lyn": "FR",
    "mad": "ES", "bcn": "ES", "vlc": "ES",
    "mil": "IT", "mxp": "IT", "lin": "IT", "fco": "IT", "rom": "IT",
    "waw": "PL", "vie": "AT", "zrh": "CH", "gva": "CH", "bru": "BE",
    "cph": "DK", "arn": "SE", "sto": "SE", "hel": "FI", "osl": "NO",
    "dub": "IE", "lis": "PT", "ath": "GR", "buh": "RO", "prg": "CZ",
    "bud": "HU", "sof": "BG", "kbp": "UA",
    # North America
    "iad": "US", "dca": "US", "bwi": "US", "jfk": "US", "lga": "US", "ewr": "US",
    "bos": "US", "phl": "US", "atl": "US", "mia": "US", "mco": "US", "tpa": "US",
    "ord": "US", "mdw": "US", "dfw": "US", "iah": "US", "den": "US", "phx": "US",
    "lax": "US", "sfo": "US", "sjc": "US", "sea": "US", "pdx": "US", "slc": "US",
    "msp": "US", "stl": "US", "clt": "US", "rdu": "US", "las": "US",
    "yyz": "CA", "yul": "CA", "yvr": "CA", "yyc": "CA",
    "mex": "MX", "mty": "MX", "qro": "MX",
    # APAC
    "nrt": "JP", "hnd": "JP", "kix": "JP", "itm": "JP",
    "icn": "KR", "gmp": "KR",
    "hkg": "HK", "tpe": "TW", "sin": "SG",
    "syd": "AU", "mel": "AU", "bne": "AU", "per": "AU", "akl": "NZ",
    "bom": "IN", "del": "IN", "maa": "IN", "blr": "IN", "hyd": "IN",
    "bkk": "TH", "kul": "MY", "cgk": "ID", "mnl": "PH",
    # Middle East / Africa
    "dxb": "AE", "auh": "AE", "doh": "QA", "ruh": "SA", "jed": "SA",
    "tlv": "IL", "ist": "TR", "saw": "TR",
    "cai": "EG", "jnb": "ZA", "cpt": "ZA", "lag": "NG", "los": "NG",
    # South America
    "gru": "BR", "gig": "BR", "bsb": "BR", "cnf": "BR",
    "scl": "CL", "eze": "AR", "lim": "PE", "bog": "CO", "ccs": "VE",
}

# Compiled once. Matches PTRs that start with a 3-letter airport code
# followed by a digit (Google 1e100.net format) or a dash (CloudFront).
import re as _re
_AIRPORT_PTR_RE = _re.compile(r"(?:^|\.)([a-z]{3})\d")


def _country_from_ptr(ptr: str | None, asn_org: str | None = None) -> str | None:
    """Best-effort country code from a reverse-DNS hostname.

    Targets the cases where the free DB-IP MMDB consistently lies:
      - Google 1e100.net edges (e.g. ``fra24s19-in-f7.1e100.net`` → DE)
      - CloudFront edges (e.g. ``server-1-2-3-4.fra50.r.cloudfront.net`` → DE)
    Returns None for everything else, so the caller falls back to the
    MMDB result.
    """
    if not ptr:
        return None
    p = ptr.lower().rstrip(".")
    # Restrict the override to PTRs we know follow the airport-prefix
    # convention. Anything else stays MMDB-driven.
    if not (p.endswith(".1e100.net") or ".cloudfront.net" in p):
        return None
    # 1e100.net format: leading label like ``fra24s19-in-f7``.
    head = p.split(".", 1)[0]
    m = _AIRPORT_PTR_RE.match(head)
    if not m:
        # CloudFront has the airport code in the SECOND label
        # (server-x-x-x-x.fra50.r.cloudfront.net).
        labels = p.split(".")
        for lbl in labels[1:3]:
            m = _AIRPORT_PTR_RE.match(lbl)
            if m:
                break
    if not m:
        return None
    code = m.group(1)
    return _AIRPORT_TO_CC.get(code)


# Per-IP country overrides resolved from PTR. Populated by the enrich
# loop (which has the PTR) and consulted by _resolve_country (which
# only sees the IP) so future conn.log buckets land in the right
# country immediately, even before they get re-enriched.
_ip_country_override: dict[str, str] = {}


def _resolve_country(ip: str) -> str | None:
    """Return ISO-3166-1 alpha-2 country code for a public IP, or None.

    Handles multiple MMDB schemas:
      - MaxMind GeoLite2:  {"country": {"iso_code": "US"}, ...}
      - DB-IP Country:     {"country": {"iso_code": "US"}, ...}  (same)
      - iptoasn-country:   {"country_code": "US"}

    PTR-based overrides (populated by ``enrich_ip_metadata_loop``)
    take precedence over the MMDB row, so once we've seen the
    reverse-DNS for a Google/CloudFront IP we trust the airport code
    over DB-IP's frequently-wrong country guess.
    """
    global _geo_lookup_errors
    if not ip or ip == "-":
        return None
    override = _ip_country_override.get(ip)
    if override:
        return override
    if not _geo_reader:
        return None
    try:
        result = _geo_reader.get(ip)
        if not result or not isinstance(result, dict):
            return None
        # GeoLite2 / DB-IP schema
        country = result.get("country")
        if isinstance(country, dict):
            iso = country.get("iso_code") or country.get("iso_code_3166_1_alpha_2")
            if iso:
                return str(iso).upper()[:2]
        # Alternative flat schema
        if "country_code" in result:
            return str(result["country_code"]).upper()[:2]
        return None
    except Exception as exc:
        _geo_lookup_errors += 1
        if _geo_lookup_errors <= 3:
            print(f"[geo] lookup error for {ip}: {exc}")
        return None


# Per-(country_code, direction) byte/hit accumulator. Flushed to SQL every
# GEO_FLUSH_INTERVAL seconds by flush_geo_buckets.
_geo_buckets: dict[tuple[str, str], dict] = {}
_geo_lock = asyncio.Lock()
GEO_FLUSH_INTERVAL = 15  # seconds

# High-resolution conversations buffer — keyed on the full 5-tuple so we
# can later tell "which device used which service to talk to which IP in
# which country". Same flush cadence as the rollup buffer.
# Key: (country_code, direction, mac_or_none, ai_service, resp_ip)
_geo_conv_buckets: dict[tuple[str, str, str | None, str, str], dict] = {}

# LAN-to-LAN buffer — for flows where BOTH endpoints are local. Fills the
# blind spot the geo pipeline leaves (geo needs a country tag, LAN has
# none). Same flush cadence as geo.
# Key: (src_mac, peer_ip, port, proto)
_lan_conv_buckets: dict[tuple[str, str, int, str], dict] = {}

# IPs awaiting PTR/ASN enrichment. Populated by the ingest endpoint's
# response and drained by enrich_ip_metadata_loop.
_ip_enrich_queue: set[str] = set()
_ip_enrich_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Inbound attack tracking — Firewalla-style "all inbound connections" +
# CrowdSec severity upgrade for known-bad IPs.
# ---------------------------------------------------------------------------
# Key: (source_ip, target_ip, target_port)
_inbound_buckets: dict[tuple[str, str, int], dict] = {}
INBOUND_FLUSH_INTERVAL = 15  # same cadence as geo flush

# CrowdSec blocklist cache — refreshed periodically from LAPI
_crowdsec_blocked_ips: set[str] = set()
_crowdsec_ip_reasons: dict[str, str] = {}  # ip -> scenario
CROWDSEC_CACHE_REFRESH = 120  # seconds


async def _record_geo_traffic(country_code: str, direction: str, total_bytes: int) -> None:
    """Add a connection's bytes to the in-memory buffer."""
    if not country_code:
        return
    key = (country_code, direction)
    async with _geo_lock:
        bucket = _geo_buckets.get(key)
        if bucket:
            bucket["bytes"] += total_bytes
            bucket["hits"] += 1
        else:
            _geo_buckets[key] = {"bytes": total_bytes, "hits": 1}


async def _record_geo_conversation(
    country_code: str,
    direction: str,
    mac: str | None,
    service: str,
    resp_ip: str,
    total_bytes: int,
    ob: int = 0,
    rb: int = 0,
) -> None:
    """Record one conversation row keyed on (cc, dir, mac, svc, resp_ip)."""
    if not country_code or not resp_ip:
        return
    key = (country_code, direction, mac, service or "unknown", resp_ip)
    async with _geo_lock:
        bucket = _geo_conv_buckets.get(key)
        if bucket:
            bucket["bytes"] += total_bytes
            bucket["ob"] += ob
            bucket["rb"] += rb
            bucket["hits"] += 1
        else:
            _geo_conv_buckets[key] = {"bytes": total_bytes, "ob": ob, "rb": rb, "hits": 1}


async def _record_lan_conversation(
    src_mac: str,
    peer_ip: str,
    peer_mac: str | None,
    port: int,
    proto: str,
    total_bytes: int,
    ob: int = 0,
    rb: int = 0,
) -> None:
    """Record one LAN-to-LAN flow keyed on (src_mac, peer_ip, port, proto).

    Both src and peer are local. Without this the conn.log record is
    dropped by the geo pipeline (no country tag). IoT fleet cards then
    show 0B for devices whose PRIMARY activity is LAN (cameras → NVRs,
    smart hubs → home assistant, printers → clients, ...).
    """
    if not src_mac or not peer_ip:
        return
    key = (src_mac, peer_ip, port, proto or "tcp")
    async with _geo_lock:
        bucket = _lan_conv_buckets.get(key)
        if bucket:
            bucket["bytes"] += total_bytes
            bucket["ob"] += ob
            bucket["rb"] += rb
            bucket["hits"] += 1
            if peer_mac and not bucket.get("peer_mac"):
                bucket["peer_mac"] = peer_mac
        else:
            _lan_conv_buckets[key] = {
                "bytes": total_bytes, "ob": ob, "rb": rb, "hits": 1,
                "peer_mac": peer_mac,
            }


# Ranked priority for Zeek conn_state. Higher rank = more informative about
# whether the connection actually carried data. We use this to decide which
# state to display when aggregating multiple flows under the same
# (src, dst, port) tuple, so a later RSTO session that transferred real
# bytes overrides an earlier S0 probe that saw nothing.
CONN_STATE_RANK = {
    "":       0,
    "S0":     1,   # SYN, no reply
    "REJ":    2,   # responder rejected
    "RSTOS0": 3,   # orig SYN+RST, no reply
    "OTH":    3,   # mid-stream capture
    "SH":     3,   # orig SYN+FIN, no reply
    "SHR":    3,   # resp SYN-ACK+FIN, no orig ack
    "RSTR":   4,   # established, responder reset
    "RSTRH":  4,   # resp SYN-ACK+RST
    "RSTO":   5,   # established, originator reset — real data likely
    "S2":     6,   # established, orig FIN only
    "S3":     6,   # established, resp FIN only
    "S1":     7,   # established, no FIN seen yet
    "SF":     8,   # established + normal close
}


def _conn_state_rank(cs: str) -> int:
    return CONN_STATE_RANK.get(cs or "", 0)


async def _record_inbound_attack(
    src_ip: str, target_ip: str, target_port: int,
    target_mac: str | None, total_bytes: int, proto: str = "tcp",
    conn_state: str = "",
) -> None:
    """Buffer an inbound connection attempt for periodic flush."""
    key = (src_ip, target_ip, target_port)
    is_threat = src_ip in _crowdsec_blocked_ips
    async with _geo_lock:
        bucket = _inbound_buckets.get(key)
        if bucket:
            bucket["bytes"] += total_bytes
            bucket["hits"] += 1
            if is_threat and bucket["severity"] != "threat":
                bucket["severity"] = "threat"
                bucket["crowdsec_reason"] = _crowdsec_ip_reasons.get(src_ip)
            # Keep the most informative conn_state we've seen so far, so a
            # row's label matches the flow that actually carried the bytes.
            if _conn_state_rank(conn_state) > _conn_state_rank(bucket.get("conn_state", "")):
                bucket["conn_state"] = conn_state
        else:
            cc = _resolve_country(src_ip)
            asn_num, asn_org = _resolve_asn(src_ip)
            _inbound_buckets[key] = {
                "bytes": total_bytes,
                "hits": 1,
                "severity": "threat" if is_threat else "blocked",
                "crowdsec_reason": _crowdsec_ip_reasons.get(src_ip) if is_threat else None,
                "conn_state": conn_state,
                "target_mac": target_mac,
                "proto": proto,
                "country_code": cc,
                "asn": asn_num,
                "asn_org": asn_org,
            }


async def _refresh_crowdsec_cache(client: httpx.AsyncClient) -> None:
    """Background task: pull CrowdSec decisions into a fast lookup set."""
    crowdsec_url = os.environ.get("CROWDSEC_URL", "http://localhost:8080")
    api_key = os.environ.get("CROWDSEC_API_KEY", "")
    if not api_key:
        print("[crowdsec-cache] No CROWDSEC_API_KEY — skipping cache")
        return
    while True:
        try:
            r = await client.get(
                f"{crowdsec_url}/v1/decisions",
                headers={"X-Api-Key": api_key},
                timeout=10,
            )
            if r.status_code == 200:
                decisions = r.json() or []
                new_ips = set()
                new_reasons = {}
                for d in decisions:
                    ip = d.get("value", "")
                    if ip:
                        new_ips.add(ip)
                        new_reasons[ip] = d.get("scenario", "")
                _crowdsec_blocked_ips.clear()
                _crowdsec_blocked_ips.update(new_ips)
                _crowdsec_ip_reasons.clear()
                _crowdsec_ip_reasons.update(new_reasons)
                if new_ips:
                    print(f"[crowdsec-cache] Refreshed: {len(new_ips)} blocked IPs")
        except Exception as exc:
            print(f"[crowdsec-cache] Refresh failed: {exc}")
        await asyncio.sleep(CROWDSEC_CACHE_REFRESH)


async def flush_geo_buckets(client: httpx.AsyncClient) -> None:
    """Background task: flush both geo buffers to the API periodically."""
    while True:
        await asyncio.sleep(GEO_FLUSH_INTERVAL)
        async with _geo_lock:
            snapshot = [
                {"country_code": cc, "direction": d, "bytes": v["bytes"], "hits": v["hits"]}
                for (cc, d), v in _geo_buckets.items()
            ] if _geo_buckets else []
            conv_snapshot = [
                {
                    "country_code": cc,
                    "direction": d,
                    "mac_address": mac,
                    "ai_service": svc,
                    "resp_ip": ip,
                    "bytes": v["bytes"],
                    "orig_bytes": v.get("ob", 0),
                    "resp_bytes": v.get("rb", 0),
                    "hits": v["hits"],
                }
                for (cc, d, mac, svc, ip), v in _geo_conv_buckets.items()
            ] if _geo_conv_buckets else []
            lan_snapshot = [
                {
                    "mac_address": src_mac,
                    "peer_ip": peer_ip,
                    "peer_mac": v.get("peer_mac"),
                    "port": port,
                    "proto": proto,
                    "bytes": v["bytes"],
                    "orig_bytes": v.get("ob", 0),
                    "resp_bytes": v.get("rb", 0),
                    "hits": v["hits"],
                }
                for (src_mac, peer_ip, port, proto), v in _lan_conv_buckets.items()
            ] if _lan_conv_buckets else []
            if snapshot:
                _geo_buckets.clear()
            if conv_snapshot:
                _geo_conv_buckets.clear()
            if lan_snapshot:
                _lan_conv_buckets.clear()

        if snapshot:
            try:
                await client.post(
                    GEO_API_URL,
                    json={"updates": snapshot},
                    timeout=10,
                )
            except httpx.HTTPError as exc:
                print(f"[geo] Flush failed ({len(snapshot)} updates): {exc}")

        if conv_snapshot:
            try:
                r = await client.post(
                    GEO_CONV_API_URL,
                    json={"updates": conv_snapshot},
                    timeout=10,
                )
                # The backend tells us which IPs it has never seen before
                # so we can queue them for ASN/PTR enrichment.
                try:
                    data = r.json()
                    to_enrich = data.get("enrich") or []
                    if to_enrich:
                        async with _ip_enrich_lock:
                            _ip_enrich_queue.update(to_enrich)
                except Exception:
                    pass
            except httpx.HTTPError as exc:
                print(f"[geo-conv] Flush failed ({len(conv_snapshot)} updates): {exc}")

        if lan_snapshot:
            try:
                await client.post(
                    LAN_CONV_API_URL,
                    json={"updates": lan_snapshot},
                    timeout=10,
                )
            except httpx.HTTPError as exc:
                print(f"[lan-conv] Flush failed ({len(lan_snapshot)} updates): {exc}")

        # --- Inbound attack buffer flush ---
        async with _geo_lock:
            inbound_snapshot = [
                {
                    "source_ip": src,
                    "target_ip": tgt,
                    "target_port": port,
                    "target_mac": v["target_mac"],
                    "protocol": v["proto"],
                    "severity": v["severity"],
                    "conn_state": v.get("conn_state", ""),
                    "crowdsec_reason": v["crowdsec_reason"],
                    "country_code": v["country_code"],
                    "asn": v["asn"],
                    "asn_org": v["asn_org"],
                    "bytes": v["bytes"],
                    "hits": v["hits"],
                }
                for (src, tgt, port), v in _inbound_buckets.items()
            ] if _inbound_buckets else []
            if inbound_snapshot:
                _inbound_buckets.clear()

        if inbound_snapshot:
            try:
                await client.post(
                    INBOUND_API_URL,
                    json={"updates": inbound_snapshot},
                    timeout=10,
                )
            except httpx.HTTPError as exc:
                print(f"[inbound] Flush failed ({len(inbound_snapshot)} updates): {exc}")


# ---------------------------------------------------------------------------
# IP enrichment loop — resolve PTR + ASN for new remote IPs
# ---------------------------------------------------------------------------
IP_ENRICH_INTERVAL = 20      # seconds between enrichment batches
IP_ENRICH_BATCH = 20         # max IPs resolved per batch
IP_ENRICH_PTR_TIMEOUT = 1.5  # per-IP reverse-DNS timeout

def _reverse_dns_blocking(ip: str) -> str | None:
    """Synchronous reverse DNS lookup with a short timeout.

    Runs in a thread pool via asyncio.to_thread so the event loop is
    never blocked. Returns None on any failure (NXDOMAIN, timeout,
    private IP, etc.) — enrichment is best-effort.
    """
    import socket as _socket
    _socket.setdefaulttimeout(IP_ENRICH_PTR_TIMEOUT)
    try:
        host, _, _ = _socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
    finally:
        _socket.setdefaulttimeout(None)


GEO_MISSING_ASN_URL = os.environ.get(
    "AIRADAR_GEO_MISSING_ASN_URL",
    "http://localhost:8000/api/geo/metadata/missing_asn",
)


async def backfill_missing_asn(client: httpx.AsyncClient) -> None:
    """Run-once startup task: re-enrich existing ip_metadata rows that
    have a NULL asn. These are rows created before the ASN MMDB was
    downloaded — PTR lookups succeeded but ASN resolution returned
    None because the reader didn't exist yet. Now that we have the
    MMDB, sweep through and fill in the gaps.

    Flow:
      1. Give the tailer a moment to finish its own startup
      2. Fetch list of IPs missing ASN from the API
      3. Resolve each locally with _asn_reader
      4. POST the results in chunks back to the existing metadata ingest
    """
    await asyncio.sleep(30)  # let the API warm up
    if not _asn_reader:
        return

    try:
        r = await client.get(GEO_MISSING_ASN_URL, params={"limit": 5000}, timeout=30)
        if r.status_code != 200:
            print(f"[asn-backfill] Skip (HTTP {r.status_code})")
            return
        ips = r.json().get("ips", [])
    except Exception as exc:
        print(f"[asn-backfill] Fetch failed: {exc}")
        return

    if not ips:
        return

    print(f"[asn-backfill] {len(ips)} IP(s) with missing ASN — resolving locally")
    CHUNK = 200
    updated = 0
    for i in range(0, len(ips), CHUNK):
        chunk = ips[i:i + CHUNK]
        entries = []
        for ip in chunk:
            asn_num, asn_org = _resolve_asn(ip)
            if asn_num is None and not asn_org:
                continue
            entries.append({
                "ip": ip,
                "asn": asn_num,
                "asn_org": asn_org,
            })
        if not entries:
            continue
        try:
            await client.post(
                GEO_META_API_URL,
                json={"entries": entries},
                timeout=15,
            )
            updated += len(entries)
        except Exception as exc:
            print(f"[asn-backfill] POST chunk failed: {exc}")

    print(f"[asn-backfill] Completed: {updated} rows updated")


async def enrich_ip_metadata_loop(client: httpx.AsyncClient) -> None:
    """Background task: drain _ip_enrich_queue, resolve PTR + ASN + country,
    and push the results to /api/geo/metadata/ingest in small batches.

    Runs forever at IP_ENRICH_INTERVAL cadence. IPs that come back with
    nothing useful are still recorded (with NULL asn/ptr) so we don't
    retry them every cycle — the ingest endpoint stamps updated_at
    regardless.
    """
    while True:
        await asyncio.sleep(IP_ENRICH_INTERVAL)
        async with _ip_enrich_lock:
            if not _ip_enrich_queue:
                continue
            batch = []
            for _ in range(min(IP_ENRICH_BATCH, len(_ip_enrich_queue))):
                batch.append(_ip_enrich_queue.pop())

        if not batch:
            continue

        entries = []
        for ip in batch:
            # ASN + country from MMDB (fast, offline)
            asn_num, asn_org = _resolve_asn(ip)
            cc = _resolve_country(ip)
            # PTR via blocking call in a thread so the loop stays responsive
            try:
                ptr = await asyncio.to_thread(_reverse_dns_blocking, ip)
            except Exception:
                ptr = None
            # If the PTR contains a known airport-code hint, trust it
            # over the MMDB result. This catches Google/CloudFront
            # anycast prefixes that DB-IP misattributes (e.g. Frankfurt
            # 1e100.net edges showing up as RU). Also seed the in-memory
            # override map so future conn.log buckets for this IP land
            # in the right country immediately.
            ptr_cc = _country_from_ptr(ptr, asn_org)
            if ptr_cc and ptr_cc != cc:
                _ip_country_override[ip] = ptr_cc
                cc = ptr_cc
            entries.append({
                "ip": ip,
                "ptr": ptr,
                "asn": asn_num,
                "asn_org": asn_org,
                "country_code": cc,
            })

        try:
            await client.post(
                GEO_META_API_URL,
                json={"entries": entries},
                timeout=10,
            )
        except httpx.HTTPError as exc:
            print(f"[ip-meta] ingest failed ({len(entries)} entries): {exc}")


# ---------------------------------------------------------------------------
# conn.log tailer — detects volumetric uploads to known AI/Cloud IPs
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# conn.log correlation delay — Firewalla-inspired
# ---------------------------------------------------------------------------
# Firewalla delays conn.log processing by 2 seconds to allow DNS, SSL, and
# HTTP log processors to populate IP→domain caches first. Without this,
# connections established right after a DNS lookup may miss the correlation.
CONN_DELAY_SECONDS = 2.0


async def tail_conn_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Continuously tail Zeek's conn.log for completed connections.

    When a connection to a known AI/Cloud IP has large outbound bytes
    (orig_bytes > threshold), fire a volumetric_upload event.

    Records are buffered for CONN_DELAY_SECONDS before processing to
    allow DNS/SSL/HTTP tailers to populate the IP→domain cache first
    (Firewalla BroDetect pattern).
    """
    # Wait for DNS/SSL/HTTP tailers to start and populate initial caches.
    # Firewalla does this by delaying conn.log processing by 2 seconds.
    await asyncio.sleep(CONN_DELAY_SECONDS)

    print(f"[*] Tailing conn.log: {log_path} (started after {CONN_DELAY_SECONDS}s correlation delay)")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(2)
            continue

        with open(log_path, "r") as f:
            header_lines: list[str] = []
            for line in f:
                if line.startswith("#"):
                    header_lines.append(line)
                else:
                    break
            fields = parse_zeek_header(header_lines) or []

            f.seek(0, 2)

            _line_count = 0
            while True:
                line = f.readline()
                if not line:
                    try:
                        if f.tell() > os.path.getsize(log_path):
                            break
                    except OSError:
                        break
                    await asyncio.sleep(0.5)
                    continue

                line = line.strip()
                if line.startswith("#") or not line:
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    continue

                if not fields:
                    continue

                parts = line.split("\t")
                if len(parts) != len(fields):
                    continue

                _line_count += 1
                if _line_count % 1000 == 0:
                    await asyncio.sleep(0)

                try:
                    record = dict(zip(fields, parts))
                except Exception as _parse_exc:
                    print(f"[conn.log] Malformed line skipped: {_parse_exc}")
                    continue

                src_ip = record.get("id.orig_h", "unknown")
                resp_ip = record.get("id.resp_h", "")
                # MAC address from Zeek conn.log (requires @load policy/protocols/conn/mac-logging)
                # Populate IP→MAC cache IMMEDIATELY — other tailers (ssl, http, mdns)
                # need this without delay.
                src_mac = record.get("orig_l2_addr")
                if src_mac and src_mac == "-":
                    src_mac = None
                if src_mac and _is_local_ip(src_ip):
                    _ip_to_mac[src_ip] = _normalize_mac(src_mac)
                proto = record.get("proto", "").lower()
                l2_mac = record.get("orig_l2_addr")
                if l2_mac and l2_mac == "-":
                    l2_mac = None
                if l2_mac and _is_local_ip(src_ip):
                    _ip_to_mac[src_ip] = _normalize_mac(l2_mac)
                resp_port_str = record.get("id.resp_p", "0")
                try:
                    resp_port = int(resp_port_str) if resp_port_str != "-" else 0
                except ValueError:
                    resp_port = 0

                # Parse byte counters early (used by geo, inbound, upload)
                try:
                    _ob = record.get("orig_bytes", "0")
                    orig_bytes = int(_ob) if _ob and _ob != "-" else 0
                except ValueError:
                    orig_bytes = 0
                try:
                    _rb = record.get("resp_bytes", "0")
                    resp_bytes = int(_rb) if _rb and _rb != "-" else 0
                except ValueError:
                    resp_bytes = 0

                # --- Geo traffic accumulation ---
                # For every connection where one side is local and the
                # other is public, resolve the public IP to a country and
                # add the total bytes to the in-memory buffer. The buffer
                # is flushed to the DB by flush_geo_buckets() every 15s.
                if _geo_reader and resp_ip and resp_ip != "-":
                    src_local = _is_local_ip(src_ip)
                    dst_local = _is_local_ip(resp_ip)
                    direction = None
                    public_ip = None
                    if src_local and not dst_local:
                        direction = "outbound"
                        public_ip = resp_ip
                    elif dst_local and not src_local:
                        direction = "inbound"
                        public_ip = src_ip
                    if direction and public_ip:
                        try:
                            _ob = record.get("orig_bytes", "0")
                            _rb = record.get("resp_bytes", "0")
                            _ob = int(_ob) if _ob and _ob != "-" else 0
                            _rb = int(_rb) if _rb and _rb != "-" else 0
                        except ValueError:
                            _ob = _rb = 0
                        total = _ob + _rb
                        if total > 0:
                            cc = _resolve_country(public_ip)
                            if cc:
                                asyncio.create_task(
                                    _record_geo_traffic(cc, direction, total)
                                )
                                # Parallel high-res bucket: attribute bytes
                                # to a specific (device, service, remote IP)
                                # so the UI can drill into "who is talking
                                # to UA and why". Service resolves via the
                                # existing _known_ips cache; unknown IPs
                                # fall into the 'unknown' bucket.
                                #
                                # Resolve the LOCAL device's MAC. For outbound
                                # flows the local side is src_ip; for inbound
                                # it's resp_ip. Two bugs were fixed here:
                                #   1) Outbound: used to only use this record's
                                #      orig_l2_addr. When Zeek missed the L2
                                #      frame (mid-stream capture, some IPv6
                                #      paths, long-lived sessions that predate
                                #      Zeek's restart) the row was written with
                                #      mac_address=NULL and the fleet card
                                #      filter GeoConversation.mac == device.mac
                                #      dropped it — user saw "0B / 0 dst" for
                                #      demonstrably active IoT devices.
                                #   2) Inbound: used the same orig_l2_addr,
                                #      but for inbound flows that is the
                                #      UPSTREAM router's MAC, not the local
                                #      device's. Attributed inbound bytes to
                                #      the wrong device (or NULL).
                                # Fallback to _ip_to_mac cache — populated
                                # earlier by this tailer, the SSL/QUIC
                                # sibling tailers, and ARP/NDP where available.
                                if direction == "outbound":
                                    local_ip = src_ip
                                    conv_mac = (
                                        _normalize_mac(l2_mac) if l2_mac
                                        else _ip_to_mac.get(local_ip)
                                    )
                                else:  # inbound
                                    conv_mac = _ip_to_mac.get(resp_ip)
                                conv_svc = "unknown"
                                conv_cat = None

                                # --- Infrastructure protocol short-circuit ---
                                # NTP, mDNS, SSDP etc. are identifiable by
                                # port alone.  Label them immediately so they
                                # don't pollute the "unknown" bucket and skip
                                # the expensive DNS/nDPI/PTR fallback chain.
                                infra = INFRA_PORTS.get((proto, resp_port))
                                if infra:
                                    conv_svc, conv_cat = infra

                                # Day 2.4 per-client scoping: only accept
                                # a label from (this device, this public
                                # IP). If conv_mac is unknown, the label
                                # stays "unknown" rather than inheriting
                                # whatever service some OTHER device
                                # happened to tag this IP with.
                                if conv_svc == "unknown" and conv_mac:
                                    svc_info = _known_ips.get((conv_mac, public_ip))
                                    if svc_info:
                                        conv_svc = svc_info[0] or "unknown"

                                # --- Coverage fix: DNS correlation fallback ---
                                # When _known_ips has no label (no SNI/QUIC
                                # was seen for this flow), try the DNS cache.
                                # This is the same lookup that fires in the
                                # volumetric-upload path, but applied BEFORE
                                # geo_conversation recording so the row gets
                                # a service label instead of "unknown".
                                if conv_svc == "unknown" and conv_mac:
                                    dns_label = _label_flow_via_dns(
                                        src_ip, public_ip,
                                    )
                                    if dns_label:
                                        conv_svc = dns_label[0]
                                        conv_cat = dns_label[1]
                                        _known_ips[(conv_mac, public_ip)] = (
                                            dns_label[0], dns_label[1], time.time()
                                        )

                                # --- M365 IP-prefix fallback ---
                                # Teams media relays (52.112.0.0/14) have
                                # no SNI and no DNS — match by IP prefix.
                                if conv_svc == "unknown" and conv_mac:
                                    pfx_label = _label_via_ip_prefix(public_ip)
                                    if pfx_label:
                                        conv_svc = pfx_label[0]
                                        conv_cat = pfx_label[1]
                                        _known_ips[(conv_mac, public_ip)] = (
                                            pfx_label[0], pfx_label[1], time.time()
                                        )

                                # --- nDPI DPI fallback ---
                                # nDPI identifies apps in encrypted traffic
                                # via packet pattern analysis. Promote the
                                # resolved label into _known_ips so the next
                                # flow on the same (mac, public_ip) skips the
                                # whole fallback cascade — matches how the
                                # DNS and IP-prefix fallbacks above cache.
                                if conv_svc == "unknown":
                                    try:
                                        from ndpi_tailer import label_via_ndpi
                                        ndpi_label = label_via_ndpi(public_ip)
                                        if ndpi_label:
                                            conv_svc, conv_cat = ndpi_label
                                            if conv_mac:
                                                _known_ips[(conv_mac, public_ip)] = (
                                                    conv_svc, conv_cat, time.time()
                                                )
                                    except ImportError:
                                        pass

                                # --- PTR/ASN category fallback ---
                                # Last resort: if DNS correlation also failed,
                                # check ip_metadata for PTR patterns (e.g.
                                # nflxvideo.net → netflix) or ASN category
                                # (e.g. AS2906 → streaming). Service may
                                # stay "unknown" but the category is assigned.
                                #
                                # Only promote to _known_ips when a real
                                # service was resolved (PTR pattern match).
                                # ASN-only matches return service="unknown",
                                # and caching those would block later
                                # enrichment from ever upgrading the label
                                # when a better signal (SNI, DNS, nDPI)
                                # arrives on a subsequent flow.
                                if conv_svc == "unknown":
                                    ptr_asn = _label_via_ptr_asn(public_ip)
                                    if ptr_asn:
                                        ptr_svc, ptr_cat = ptr_asn
                                        if ptr_svc != "unknown":
                                            conv_svc = ptr_svc
                                            if conv_mac:
                                                _known_ips[(conv_mac, public_ip)] = (
                                                    ptr_svc, ptr_cat, time.time()
                                                )
                                        conv_cat = ptr_cat

                                asyncio.create_task(
                                    _record_geo_conversation(
                                        cc, direction, conv_mac, conv_svc, public_ip, total,
                                        ob=_ob, rb=_rb,
                                    )
                                )

                    # --- LAN-to-LAN conversation accumulation ---
                    # Complements the geo branch above: when BOTH ends are
                    # local, the geo pipeline skips the flow (no country
                    # tag). Without this, IoT devices whose primary activity
                    # is intra-LAN (cameras → NVRs, hubs → HomeAssistant,
                    # printers → clients) show 0B on the fleet card even
                    # when they're actively streaming 24/7.
                    elif src_local and dst_local and src_ip != resp_ip:
                        # Skip multicast/broadcast destinations — those are
                        # one-to-many chatter (mDNS, SSDP, UPnP discovery)
                        # and fan out to massive row counts with limited
                        # diagnostic value. Unicast peers are what users
                        # actually care about.
                        if not _is_multicast_or_broadcast(resp_ip):
                            src_lan_mac = (
                                _normalize_mac(l2_mac) if l2_mac
                                else _ip_to_mac.get(src_ip)
                            )
                            if src_lan_mac:
                                try:
                                    _ob = record.get("orig_bytes", "0")
                                    _rb = record.get("resp_bytes", "0")
                                    _ob = int(_ob) if _ob and _ob != "-" else 0
                                    _rb = int(_rb) if _rb and _rb != "-" else 0
                                except ValueError:
                                    _ob = _rb = 0
                                lan_total = _ob + _rb
                                # Drop empty probes (SYN+RST, failed UDP
                                # send, rejected connections) — these
                                # explode row count without telling us
                                # about real device activity.
                                if lan_total > 0:
                                    peer_lan_mac = _ip_to_mac.get(resp_ip)
                                    asyncio.create_task(
                                        _record_lan_conversation(
                                            src_lan_mac, resp_ip, peer_lan_mac,
                                            resp_port, proto,
                                            lan_total, ob=_ob, rb=_rb,
                                        )
                                    )

                # --- VPN / tunnel detection ---
                vpn_key = (proto, resp_port)
                vpn_type = VPN_PORTS.get(vpn_key)
                if vpn_type and _is_local_ip(src_ip):
                    # Check total bytes (orig + resp)
                    try:
                        ob = record.get("orig_bytes", "0")
                        vpn_orig = int(ob) if ob and ob != "-" else 0
                    except ValueError:
                        vpn_orig = 0
                    try:
                        rb = record.get("resp_bytes", "0")
                        vpn_resp = int(rb) if rb and rb != "-" else 0
                    except ValueError:
                        vpn_resp = 0
                    vpn_total = vpn_orig + vpn_resp

                    if vpn_total >= VPN_BYTE_THRESHOLD:
                        # Dedup: only one VPN event per (src_ip, port) per window
                        now = time.time()
                        dedup_k = (src_ip, resp_port)
                        last_vpn = _vpn_last_seen.get(dedup_k, 0)
                        if (now - last_vpn) >= VPN_DEDUP_SECONDS:
                            _vpn_last_seen[dedup_k] = now
                            asyncio.create_task(register_device(client, src_ip, l2_mac))
                            await send_event(
                                client,
                                detection_type="vpn_tunnel",
                                ai_service="vpn_active",
                                source_ip=src_ip,
                                bytes_transferred=vpn_total,
                                category="tracking",
                            )
                            print(
                                f"    └─ VPN detected: {vpn_type} "
                                f"({proto.upper()}/{resp_port}) "
                                f"from {src_ip} — {vpn_total/1024:,.0f} KB"
                            )

                # --- DPD-based stealth VPN/Tor detection ---
                # Zeek's Dynamic Protocol Detection identifies protocols
                # regardless of port.  This catches VPNs on port 443, etc.
                service_field = record.get("service", "-")
                if service_field and service_field != "-" and _is_local_ip(src_ip):
                    # service can be comma-separated (e.g. "quic,ssl,ayiya")
                    detected_svcs = [s.strip().lower() for s in service_field.split(",")]
                    for dpd_proto in detected_svcs:
                        evasion_svc = DPD_EVASION_PROTOCOLS.get(dpd_proto)
                        if not evasion_svc:
                            continue
                        # DTLS is used by many legitimate Apple services
                        # (iCloud Private Relay, FaceTime, AirDrop, APNs).
                        # Only flag DTLS when the destination is a known
                        # VPN provider ASN to avoid false positives.
                        if dpd_proto == "dtls":
                            if not resp_ip or not _vpn_provider_for_ip(resp_ip):
                                continue
                        # Dedup per (src_ip, protocol)
                        now_dpd = time.time()
                        dpd_key = (src_ip, dpd_proto)
                        dpd_last = _dpd_last_seen.get(dpd_key, 0)
                        if (now_dpd - dpd_last) < DPD_DEDUP_SECONDS:
                            continue
                        _dpd_last_seen[dpd_key] = now_dpd

                        # Calculate bytes
                        try:
                            dpd_ob = record.get("orig_bytes", "0")
                            dpd_orig = int(dpd_ob) if dpd_ob and dpd_ob != "-" else 0
                        except ValueError:
                            dpd_orig = 0
                        try:
                            dpd_rb = record.get("resp_bytes", "0")
                            dpd_resp = int(dpd_rb) if dpd_rb and dpd_rb != "-" else 0
                        except ValueError:
                            dpd_resp = 0
                        dpd_total = dpd_orig + dpd_resp

                        asyncio.create_task(register_device(client, src_ip, l2_mac))
                        await send_event(
                            client,
                            detection_type="stealth_vpn_tunnel",
                            ai_service=f"{evasion_svc}:{resp_ip}",
                            source_ip=src_ip,
                            bytes_transferred=dpd_total,
                            category="tracking",
                        )
                        print(
                            f"    └─ DPD stealth detection: {dpd_proto.upper()} "
                            f"on port {resp_port} ({proto.upper()}) "
                            f"from {src_ip} — {dpd_total/1024:,.0f} KB"
                        )

                # --- IoT anomaly detection ---
                # Lateral movement: IoT device talking to another LAN host
                # on scan-typical ports = possible compromise.
                # Suspicious outbound: IoT device talking to external host
                # on SSH/Telnet/IRC/SMTP = botnet indicator.
                if l2_mac and _is_local_ip(src_ip):
                    iot_type = _is_iot_device(_normalize_mac(l2_mac))
                    if iot_type:
                        now_iot = time.time()
                        # Lateral movement check
                        # For HTTP(S) ports: only alert on established connections
                        # to avoid false positives from IoT discovery (HEOS, UPnP, etc.)
                        _lat_established_ok = (
                            resp_port not in _LATERAL_ESTABLISHED_ONLY_PORTS
                            or conn_state in ("S1", "SF")
                        )
                        # VLAN-aware: only alert if src and dst are in the
                        # SAME subnet (same L2 broadcast domain). Cross-VLAN
                        # traffic goes through a router, so it's not true
                        # lateral movement and shouldn't trigger the alert.
                        if (
                            resp_ip and _is_local_ip(resp_ip)
                            and _same_lan_segment(src_ip, resp_ip)
                            and resp_port in _LATERAL_MOVEMENT_PORTS
                            and src_ip != resp_ip
                            and _lat_established_ok
                        ):
                            dk = ("lateral", src_ip, resp_ip, resp_port)
                            if (now_iot - _iot_alert_last.get(dk, 0)) >= IOT_ALERT_DEDUP_SECONDS:
                                _iot_alert_last[dk] = now_iot
                                asyncio.create_task(register_device(client, src_ip, l2_mac))
                                await send_event(
                                    client,
                                    detection_type="iot_lateral_movement",
                                    ai_service=f"lateral_{resp_port}_{resp_ip}",
                                    source_ip=src_ip,
                                    bytes_transferred=0,
                                    category="security",
                                )
                                print(
                                    f"    └─ IoT LATERAL MOVEMENT: {iot_type} ({src_ip}) "
                                    f"→ {resp_ip}:{resp_port}"
                                )
                        # Suspicious outbound port check
                        if (
                            resp_ip and not _is_local_ip(resp_ip)
                            and resp_port in _IOT_SUSPICIOUS_OUTBOUND_PORTS
                        ):
                            dk = ("susport", src_ip, resp_port)
                            if (now_iot - _iot_alert_last.get(dk, 0)) >= IOT_ALERT_DEDUP_SECONDS:
                                _iot_alert_last[dk] = now_iot
                                asyncio.create_task(register_device(client, src_ip, l2_mac))
                                await send_event(
                                    client,
                                    detection_type="iot_suspicious_port",
                                    ai_service=f"port_{resp_port}",
                                    source_ip=src_ip,
                                    bytes_transferred=0,
                                    category="security",
                                )
                                print(
                                    f"    └─ IoT SUSPICIOUS PORT: {iot_type} ({src_ip}) "
                                    f"→ external:{resp_port}"
                                )

                # --- Inbound threat detection ---
                # External IP initiating a connection to an internal device.
                conn_state = record.get("conn_state", "")
                if (
                    resp_ip
                    and not _is_local_ip(src_ip)
                    and _is_local_ip(resp_ip)
                    and proto == "tcp"
                ):
                    # Track inbound connection attempts for the attack dashboard.
                    # Filter logic:
                    # - High ports (>=1024): always skip (ephemeral callbacks)
                    # - Port 80/443 with S1/SF: skip (legit web visitors)
                    # - Port 80/443 with S0/REJ: KEEP (probe/scan on web port)
                    # - Low ports (<1024, not 80/443): always keep
                    is_probe = conn_state in ("S0", "REJ", "RSTO", "RSTR", "S2", "S3", "OTH", "ShR")
                    is_established = conn_state in ("S1", "SF")
                    if resp_port >= 1024:
                        pass  # skip: ephemeral callback
                    elif resp_port in (80, 443) and is_established:
                        pass  # skip: successful connection to open web service
                    elif is_probe or (resp_port < 1024 and not resp_port in (80, 443)):
                        target_mac = _ip_to_mac.get(resp_ip)
                        await _record_inbound_attack(
                            src_ip, resp_ip, resp_port, target_mac,
                            orig_bytes + resp_bytes, proto, conn_state,
                        )

                    now_ib = time.time()

                    # --- Port scan detection ---
                    # Track distinct ports per (src, dest) in a sliding window.
                    ps_key = (src_ip, resp_ip)
                    ps_entries = _portscan_tracker.get(ps_key)
                    if ps_entries is None:
                        ps_entries = []
                        _portscan_tracker[ps_key] = ps_entries
                    ps_entries.append((now_ib, resp_port))
                    # Prune old entries outside the window
                    cutoff_ps = now_ib - PORTSCAN_WINDOW_SECONDS
                    _portscan_tracker[ps_key] = [
                        (t, p) for t, p in ps_entries if t >= cutoff_ps
                    ]
                    distinct_ports = {p for _, p in _portscan_tracker[ps_key]}
                    if (
                        len(distinct_ports) >= PORTSCAN_THRESHOLD
                        and (now_ib - _portscan_last_alert.get(ps_key, 0)) >= PORTSCAN_DEDUP_SECONDS
                    ):
                        _portscan_last_alert[ps_key] = now_ib
                        port_list = ",".join(str(p) for p in sorted(distinct_ports)[:10])
                        await send_event(
                            client,
                            detection_type="inbound_port_scan",
                            ai_service=f"portscan_{resp_ip}",
                            source_ip=src_ip,
                            bytes_transferred=0,
                            category="security",
                        )
                        print(
                            f"    └─ INBOUND PORT SCAN: {src_ip} → {resp_ip} "
                            f"({len(distinct_ports)} ports: {port_list})"
                        )

                    # --- Suspicious inbound port ---
                    # Alert on: dangerous ports always, other low ports
                    # except 80/443 established (legit visitors). For 80/443
                    # with S0/REJ (blocked probes/DDoS), only alert after
                    # INBOUND_WEB_PROBE_ALERT_THRESHOLD hits per IP to avoid
                    # flooding Summary with one-off scanners.
                    if (resp_ip, resp_port) not in _INBOUND_WHITELIST and resp_port < 1024:
                        is_dangerous = resp_port in _INBOUND_DANGEROUS_PORTS
                        is_web_probe = resp_port in (80, 443) and is_probe
                        should_alert = False
                        if is_dangerous or (resp_port not in (80, 443)):
                            should_alert = True
                        elif is_web_probe:
                            # Count hits per (src, target, port) — only alert
                            # when threshold reached (filters one-off scanners)
                            wpk = (src_ip, resp_ip, resp_port)
                            _inbound_web_probe_hits[wpk] = _inbound_web_probe_hits.get(wpk, 0) + 1
                            if _inbound_web_probe_hits[wpk] >= INBOUND_WEB_PROBE_ALERT_THRESHOLD:
                                should_alert = True
                        if should_alert:
                            dk = ("inbound", src_ip, resp_ip, resp_port)
                            if (now_ib - _inbound_threat_last.get(dk, 0)) >= INBOUND_THREAT_DEDUP_SECONDS:
                                _inbound_threat_last[dk] = now_ib
                                sev = "CRITICAL" if is_dangerous else "WARNING"
                                await send_event(
                                    client,
                                    detection_type="inbound_threat",
                                    ai_service=f"inbound_{resp_port}",
                                    source_ip=src_ip,
                                    bytes_transferred=orig_bytes + resp_bytes,
                                    category="security",
                                )
                                print(
                                    f"    └─ INBOUND {sev}: {src_ip} → {resp_ip}:{resp_port}"
                                )

                # --- Day 2.4 per-client cache key ---
                # Build the scoped lookup key once, reuse everywhere
                # below so the stale-eviction, presence check, primary
                # read, and dns_correlated writes all hit the same
                # (client_mac, resp_ip) tuple. When we don't know the
                # source MAC for this flow the key is None, and every
                # subsequent check treats the destination as unlabelled
                # — forcing a fall-through to the per-client DNS
                # correlation pad, which is also client-scoped.
                _src_mac_norm = _normalize_mac(l2_mac) if l2_mac else None
                _kip_key: tuple[str, str] | None = (
                    (_src_mac_norm, resp_ip) if _src_mac_norm and resp_ip else None
                )

                # --- Evict stale IP mappings before further checks ---
                if _kip_key is not None and _kip_key in _known_ips:
                    _, _, _learned = _known_ips[_kip_key]
                    if (time.time() - _learned) > IP_TTL_SECONDS:
                        del _known_ips[_kip_key]

                # --- ASN-based VPN detection ---
                # The old "large flow to unknown IP = VPN" heuristic fired
                # on every Netflix stream, Steam download, iCloud backup,
                # and TV box. Replaced with deterministic ASN matching:
                # if resp_ip belongs to a known consumer-VPN provider's
                # ASN, flag it. Self-hosted VPNs on standard ports are
                # still caught by VPN_PORTS; obfuscated protocols by DPD.
                if (
                    _is_local_ip(src_ip)
                    and resp_ip
                    and not _is_local_ip(resp_ip)
                ):
                    vpn_asn_hit = _vpn_provider_for_ip(resp_ip)
                    if vpn_asn_hit:
                        asn_num, provider_label = vpn_asn_hit
                        try:
                            a_ob = record.get("orig_bytes", "0")
                            a_orig = int(a_ob) if a_ob and a_ob != "-" else 0
                        except ValueError:
                            a_orig = 0
                        try:
                            a_rb = record.get("resp_bytes", "0")
                            a_resp = int(a_rb) if a_rb and a_rb != "-" else 0
                        except ValueError:
                            a_resp = 0
                        a_total = a_orig + a_resp

                        if a_total >= VPN_ASN_BYTE_THRESHOLD:
                            now = time.time()
                            asn_key = (src_ip, asn_num)
                            last = _vpn_asn_seen.get(asn_key, 0)
                            if (now - last) >= VPN_ASN_DEDUP_SECONDS:
                                _vpn_asn_seen[asn_key] = now
                                asyncio.create_task(register_device(client, src_ip, l2_mac))
                                await send_event(
                                    client,
                                    detection_type="vpn_tunnel",
                                    ai_service=f"vpn_{provider_label}:{resp_ip}",
                                    source_ip=src_ip,
                                    bytes_transferred=a_total,
                                    category="tracking",
                                )
                                print(
                                    f"    └─ VPN provider ASN match: AS{asn_num} "
                                    f"({provider_label}) from {src_ip} to {resp_ip} "
                                    f"— {a_total/1024:,.0f} KB"
                                )

                # Check if destination IP is a known AI/Cloud service
                # (stale mappings were already evicted above). Day 2.4
                # per-client scoping: we look up (this device, resp_ip)
                # — a label tagged by a different device does NOT
                # bleed over.
                if _kip_key is None or _kip_key not in _known_ips:
                    # ── DNS correlation fallback ──
                    # The flow has no SNI hello attached (typical for
                    # QUIC, ECH, or 0-RTT resumption). Last chance: ask
                    # the DNS-IP cache whether this client recently
                    # resolved a hostname to this destination.
                    #
                    # The lookup is scoped per (client_mac, resp_ip)
                    # so CDN multi-tenancy can't cross-pollute labels.
                    # Per-flow lookup, no shared state — see the design
                    # notes in dns_cache.py and _label_flow_via_dns().
                    dns_label = _label_flow_via_dns(src_ip, resp_ip)
                    if dns_label is None:
                        # ── M365 IP-prefix fallback ──
                        # Teams media relays etc. have no SNI and no DNS.
                        # Populate _known_ips so volumetric path picks it up.
                        _pfx = _label_via_ip_prefix(resp_ip)
                        if _pfx is None:
                            continue
                        _pfx_mac = _ip_to_mac.get(src_ip)
                        if _pfx_mac:
                            _known_ips[(_pfx_mac, resp_ip)] = (
                                _pfx[0], _pfx[1], time.time()
                            )
                            _kip_key = (_pfx_mac, resp_ip)
                        if _kip_key is None or _kip_key not in _known_ips:
                            continue
                        # _known_ips populated — skip DNS event, jump to
                        # the volumetric upload check at line ~3693.
                    else:
                        dns_service, dns_category, dns_hostname, dns_score, dns_rationale = dns_label

                        # The DNS correlation pad already verified it knows
                        # this client's MAC (otherwise dns_label would be
                        # None). Re-resolve here to get the SAME MAC that
                        # dns_cache uses, so the _known_ips write lands on
                        # the right scoped key. We prefer _ip_to_mac over
                        # l2_mac because the dns_cache lookup above used
                        # _ip_to_mac and we want consistency.
                        _dns_client_mac = _ip_to_mac.get(src_ip)

                        # Per-(service, src_ip) dedup using the same window
                        # as direct SNI hellos. The first hit fires; the
                        # rest within SNI_DEDUP_SECONDS are silently
                        # absorbed. This prevents one streaming session
                        # from generating thousands of duplicate events.
                        _dns_dedup_now = time.time()
                        _dns_dedup_key = (dns_service, src_ip)
                        _dns_dedup_last = _sni_last_seen.get(_dns_dedup_key, 0)
                        if (_dns_dedup_now - _dns_dedup_last) < SNI_DEDUP_SECONDS:
                            # Refresh TTL on the existing per-client entry
                            # so the volumetric path can still attribute
                            # upload bytes to this service for this device.
                            if _dns_client_mac:
                                _known_ips[(_dns_client_mac, resp_ip)] = (
                                    dns_service, dns_category, time.time()
                                )
                            continue
                        _sni_last_seen[_dns_dedup_key] = _dns_dedup_now

                        # Promote the DNS-correlated label into _known_ips
                        # scoped per (this client, resp_ip). The dns_cache
                        # itself is already per-client, so this write just
                        # propagates that scoping to the volumetric pad.
                        if _dns_client_mac:
                            _known_ips[(_dns_client_mac, resp_ip)] = (
                                dns_service, dns_category, time.time()
                            )
                            # Update the scoped key so the fall-through
                            # read at the bottom of this block hits the
                            # entry we just wrote.
                            _kip_key = (_dns_client_mac, resp_ip)

                        try:
                            flow_orig = int(record.get("orig_bytes", "0") or 0)
                        except ValueError:
                            flow_orig = 0
                        try:
                            flow_resp = int(record.get("resp_bytes", "0") or 0)
                        except ValueError:
                            flow_resp = 0

                        await send_event(
                            client,
                            detection_type="dns_correlated",
                            ai_service=dns_service,
                            source_ip=src_ip,
                            bytes_transferred=flow_orig + flow_resp,
                            category=dns_category,
                            attribution={
                                "labeler": "dns_correlation",
                                "confidence": dns_score,
                                "rationale": dns_rationale,
                                "proposed_service": dns_service,
                                "proposed_category": dns_category,
                                "is_low_confidence": False,
                                "is_disputed": False,
                            },
                        )
                        # Fall through to the volumetric upload path below —
                        # the (service, category) we just learned will be
                        # used by the existing record_upload accumulator.
                        # If _dns_client_mac was None we never wrote to
                        # _known_ips, so _kip_key still points nowhere and
                        # the read below would KeyError — guard against it.
                        if _kip_key is None or _kip_key not in _known_ips:
                            continue

                service, category, _ts = _known_ips[_kip_key]

                # Check outbound bytes
                try:
                    ob = record.get("orig_bytes", "0")
                    orig_bytes = int(ob) if ob and ob != "-" else 0
                except ValueError:
                    orig_bytes = 0

                if orig_bytes < UPLOAD_THRESHOLD_BYTES:
                    continue

                # Don't fire immediately — accumulate into a debounce
                # bucket so parallel connections are clustered into one event
                await record_upload(service, category, src_ip, orig_bytes)


# ---------------------------------------------------------------------------
# Stealth VPN / Tor detection via Zeek DPD (Dynamic Protocol Detection)
# ---------------------------------------------------------------------------
# Zeek's DPD engine populates the `service` column in conn.log regardless of
# port.  This catches VPNs running on port 443 or any other non-standard port.

DPD_EVASION_PROTOCOLS: dict[str, str] = {
    "openvpn":    "vpn_openvpn",
    "wireguard":  "vpn_wireguard",
    "tor":        "tor_active",
    "socks":      "vpn_socks_proxy",
    "dtls":       "vpn_dtls_tunnel",    # DTLS can indicate VPN (e.g. AnyConnect) — ASN-gated below
    # NOTE: ayiya + teredo intentionally removed. Both are IPv6-over-IPv4
    # tunnel protocols from the 2000s. SixXS (the main AYIYA provider)
    # shut down in 2017 and Microsoft Teredo has been deprecated for
    # years. In 2026 Zeek's DPD signatures for these protocols fire
    # almost exclusively on modern QUIC / obfuscated-UDP traffic from
    # iOS and other mobile devices — 100% false-positive rate in
    # practice. If you actually need to detect them, reintroduce with
    # an IP-based allowlist rather than DPD alone.
}

DPD_DEDUP_SECONDS = 300  # 5-minute window per (src_ip, protocol)
_dpd_last_seen: dict[tuple[str, str], float] = {}


# ---------------------------------------------------------------------------
# dhcp.log tailer — passive device recognition
# ---------------------------------------------------------------------------

DHCP_DEDUP_SECONDS = 600  # Only update device once per 10 min per MAC

_dhcp_last_seen: dict[str, float] = {}  # mac → last_registered_ts


async def tail_dhcp_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Continuously tail Zeek's dhcp.log for DHCP leases.

    Extracts MAC, IP, hostname, and FQDN from DHCP requests/acks and
    registers (or updates) the device via the API.  This provides far
    richer device names than reverse-DNS or MAC-vendor lookups alone.
    """
    print(f"[*] Tailing dhcp.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(5)
            continue

        try:
            with open(log_path, "r") as f:
                # Read header
                header_lines: list[str] = []
                for line in f:
                    if line.startswith("#"):
                        header_lines.append(line)
                    else:
                        break
                fields = parse_zeek_header(header_lines) or []

                # Seek to end for tailing
                f.seek(0, 2)

                _line_count = 0
                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break  # file rotated
                        except OSError:
                            break
                        await asyncio.sleep(1)
                        continue

                    line = line.strip()
                    if line.startswith("#") or not line:
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        continue

                    if not fields:
                        continue

                    parts = line.split("\t")
                    if len(parts) != len(fields):
                        continue

                    _line_count += 1
                    if _line_count % 1000 == 0:
                        await asyncio.sleep(0)

                    try:
                        record = dict(zip(fields, parts))
                    except Exception as _parse_exc:
                        print(f"[dhcp.log] Malformed line skipped: {_parse_exc}")
                        continue

                    mac_raw = record.get("mac", "-")
                    if not mac_raw or mac_raw == "-":
                        continue
                    mac = _normalize_mac(mac_raw)

                    # Determine IP: prefer assigned_addr, fall back to
                    # requested_addr, then client_addr
                    ip = None
                    for ip_field in ("assigned_addr", "requested_addr", "client_addr"):
                        val = record.get(ip_field, "-")
                        if val and val != "-" and val != "0.0.0.0":
                            ip = val
                            break

                    if not ip:
                        continue

                    # Dedup: don't spam API for the same MAC
                    now = time.time()
                    last = _dhcp_last_seen.get(mac, 0)
                    if (now - last) < DHCP_DEDUP_SECONDS:
                        continue
                    _dhcp_last_seen[mac] = now

                    # Build device payload with DHCP-enriched data
                    hostname = None
                    for name_field in ("host_name", "client_fqdn"):
                        val = record.get(name_field, "-")
                        if val and val != "-":
                            hostname = val
                            break

                    payload: dict = {"ip": ip, "mac_address": mac}
                    if hostname and not _is_junk_hostname(hostname):
                        payload["hostname"] = hostname
                    else:
                        hostname = None

                    try:
                        await client.post(DEVICE_API_URL, json=payload, timeout=5)
                        label = hostname or mac
                        print(f"[DHCP] Device: {label} → {ip} (MAC: {mac})")
                    except httpx.HTTPError as exc:
                        print(f"[!] DHCP device registration failed: {exc}")

        except (OSError, IOError) as exc:
            print(f"[!] dhcp.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# JA4D DHCP fingerprinting — enrich devices from ja4d.log
# ---------------------------------------------------------------------------

JA4D_DEDUP_SECONDS = 600  # 10 min per MAC
_ja4d_last_seen: dict[str, float] = {}


async def tail_ja4d_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Tail Zeek's ja4d.log for DHCP fingerprints (JA4 plugin).

    ja4d.log fields include client_mac, hostname, vendor_class_id, ja4d.
    Uses these to enrich device records with better hostnames.
    """
    print(f"[*] Tailing ja4d.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(5)
            continue

        try:
            with open(log_path, "r") as f:
                header_lines: list[str] = []
                for line in f:
                    if line.startswith("#"):
                        header_lines.append(line)
                    else:
                        break
                fields = parse_zeek_header(header_lines) or []
                f.seek(0, 2)

                _line_count = 0
                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break
                        except OSError:
                            break
                        await asyncio.sleep(1)
                        continue

                    line = line.strip()
                    if line.startswith("#") or not line:
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        continue

                    if not fields:
                        continue

                    parts = line.split("\t")
                    if len(parts) != len(fields):
                        continue

                    _line_count += 1
                    if _line_count % 1000 == 0:
                        await asyncio.sleep(0)

                    try:
                        record = dict(zip(fields, parts))
                    except Exception as _parse_exc:
                        print(f"[ja4d.log] Malformed line skipped: {_parse_exc}")
                        continue

                    mac_raw = record.get("client_mac", "-")
                    if not mac_raw or mac_raw == "-":
                        continue
                    mac = _normalize_mac(mac_raw)

                    now = time.time()
                    last = _ja4d_last_seen.get(mac, 0)
                    if (now - last) < JA4D_DEDUP_SECONDS:
                        continue
                    _ja4d_last_seen[mac] = now

                    # Zeek writes "-" for missing and "(empty)" for present-
                    # but-blank. Normalise both to None.
                    def _clean_zeek(val):
                        if not val or val == "-" or val == "(empty)":
                            return None
                        return val

                    hostname = _clean_zeek(record.get("hostname"))

                    # vendor_class_id is extremely valuable for device type
                    # identification — e.g. "MSFT 5.0", "android-dhcp-14",
                    # "dhcpcd-10.0.0", "LG_webOS", "Google Nest". More
                    # reliable than OUI for distinguishing Google device
                    # types (Nest vs Chromecast vs Pixel).
                    vendor_class = _clean_zeek(
                        record.get("vendor_class_id") or record.get("vendor_class")
                    )

                    ja4d_hash = _clean_zeek(record.get("ja4d"))

                    assigned_ip = record.get("assigned_addr") or record.get("requested_ip")
                    if assigned_ip and assigned_ip == "-":
                        assigned_ip = None

                    # Fall back to IP→MAC reverse lookup
                    ip = assigned_ip
                    if not ip:
                        for cached_ip, cached_mac in _ip_to_mac.items():
                            if cached_mac == mac:
                                ip = cached_ip
                                break

                    if not ip:
                        continue

                    payload: dict = {"ip": ip, "mac_address": mac}
                    if hostname and not _is_junk_hostname(hostname):
                        payload["hostname"] = hostname
                    else:
                        hostname = None
                    if vendor_class:
                        payload["dhcp_vendor_class"] = vendor_class
                    if ja4d_hash:
                        payload["dhcp_fingerprint"] = ja4d_hash

                    try:
                        await client.post(DEVICE_API_URL, json=payload, timeout=5)
                        label = hostname or mac
                        vci_tag = f", VCI={vendor_class[:30]}" if vendor_class else ""
                        print(f"[JA4D] Device: {label} → {ip} (MAC: {mac}, JA4D: {ja4d_hash or '?'}{vci_tag})")
                    except httpx.HTTPError as exc:
                        print(f"[!] JA4D device registration failed: {exc}")

        except (OSError, IOError) as exc:
            print(f"[!] ja4d.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# mDNS device name discovery — tail mdns.log for .local announcements
# ---------------------------------------------------------------------------

MDNS_DEDUP_SECONDS = 600  # 10 min per (ip, name)
_mdns_last_seen: dict[str, float] = {}

# ---------------------------------------------------------------------------
# mDNS service type → device_class mapping (Firewalla-inspired)
# ---------------------------------------------------------------------------
# mDNS service types reveal what a device IS. When Zeek captures a query
# like "_airplay._tcp.local", the originator is an AirPlay-capable device.
# We map known service types to device classes.
MDNS_SERVICE_TYPE_MAP: dict[str, str] = {
    # Apple ecosystem
    "_airplay._tcp":         "media_player",   # AirPlay (Apple TV, HomePod, smart TVs)
    "_raop._tcp":            "media_player",   # Remote Audio Output (AirPlay audio)
    "_hap._tcp":             "smart_home",     # HomeKit Accessory Protocol
    "_homekit._tcp":         "smart_home",     # HomeKit
    "_companion-link._tcp":  "phone",          # Apple Continuity (iPhone/iPad)
    "_apple-mobdev2._tcp":   "phone",          # Apple mobile device sync
    "_touch-able._tcp":      "phone",          # iPhone/iPad remote
    "_rdlink._tcp":          "laptop",         # Apple Remote Desktop
    "_sleep-proxy._udp":     "network",        # Apple sleep proxy (router/AP)

    # Printing
    "_ipp._tcp":             "printer",        # Internet Printing Protocol
    "_ipps._tcp":            "printer",        # IPP over TLS
    "_printer._tcp":         "printer",        # LPR printer
    "_pdl-datastream._tcp":  "printer",        # Raw printing (port 9100)
    "_scanner._tcp":         "printer",        # Network scanner

    # Google/Chromecast
    "_googlecast._tcp":      "media_player",   # Chromecast / Google TV
    "_googlerpc._tcp":       "speaker",        # Google Home RPC
    "_googlezone._tcp":      "speaker",        # Google Home multi-room

    # Media / A/V
    "_spotify-connect._tcp": "media_player",   # Spotify Connect
    "_sonos._tcp":           "speaker",        # Sonos
    "_daap._tcp":            "media_player",   # iTunes/DAAP music sharing
    "_dpap._tcp":            "media_player",   # iPhoto sharing

    # Smart home
    "_hue._tcp":             "smart_lighting", # Philips Hue
    "_ozw._tcp":             "smart_home_hub", # OpenZWave
    "_mqtt._tcp":            "smart_home_hub", # MQTT broker
    "_coap._udp":            "iot",            # CoAP (IoT protocol)

    # Network infrastructure
    "_smb._tcp":             "nas",            # SMB/CIFS file sharing
    "_afpovertcp._tcp":      "nas",            # AFP file sharing (Apple)
    "_nfs._tcp":             "nas",            # NFS file sharing
    "_ssh._tcp":             "server",         # SSH server
    "_http._tcp":            None,             # Too generic — skip
    "_https._tcp":           None,             # Too generic — skip
}

def _mdns_service_to_class(name: str) -> str | None:
    """Extract device_class from an mDNS service type string.

    Input examples:
        "_airplay._tcp.local"
        "Chromecast-abc123._googlecast._tcp.local"
        "_hap._tcp"
    """
    name_lower = name.lower().rstrip(".")
    if name_lower.endswith(".local"):
        name_lower = name_lower[:-6]

    # Try matching the full service type first, then look for known patterns
    for svc_type, device_class in MDNS_SERVICE_TYPE_MAP.items():
        if svc_type in name_lower:
            return device_class
    return None


async def tail_mdns_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Tail Zeek's mdns.log for mDNS name announcements.

    Devices (Apple, Chromecast, printers, IoT) broadcast their .local
    hostnames via mDNS (port 5353).  We extract these and link them to
    devices via the IP→MAC cache from conn.log.
    """
    print(f"[*] Tailing mdns.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(5)
            continue

        try:
            with open(log_path, "r") as f:
                header_lines: list[str] = []
                for line in f:
                    if line.startswith("#"):
                        header_lines.append(line)
                    else:
                        break
                fields = parse_zeek_header(header_lines) or []
                f.seek(0, 2)

                _line_count = 0
                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break
                        except OSError:
                            break
                        await asyncio.sleep(1)
                        continue

                    line = line.strip()
                    if line.startswith("#") or not line:
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        continue

                    if not fields:
                        continue

                    parts = line.split("\t")
                    if len(parts) != len(fields):
                        continue

                    _line_count += 1
                    if _line_count % 1000 == 0:
                        await asyncio.sleep(0)

                    try:
                        record = dict(zip(fields, parts))
                    except Exception as _parse_exc:
                        print(f"[mdns.log] Malformed line skipped: {_parse_exc}")
                        continue

                    src_ip = record.get("id.orig_h", "-")
                    if src_ip == "-" or not _is_local_ip(src_ip):
                        continue

                    # Extract hostname from mDNS — try common field names
                    mdns_name = None
                    for field in ("query", "qname", "name", "answers"):
                        val = record.get(field, "-")
                        if val and val != "-":
                            mdns_name = val
                            break

                    if not mdns_name:
                        continue

                    # Clean up: strip trailing dots and ".local" suffix
                    hostname = mdns_name.rstrip(".")
                    if hostname.lower().endswith(".local"):
                        hostname = hostname[:-6]

                    # Service type detection — extract device_class from
                    # mDNS service types like "_airplay._tcp" before
                    # potentially skipping the entry as a "non-hostname".
                    mdns_device_class = None
                    if "._" in hostname or hostname.startswith("_"):
                        mdns_device_class = _mdns_service_to_class(hostname)
                        # Extract instance name from service records
                        # e.g. "Living Room._airplay._tcp" → "Living Room"
                        if "._" in hostname:
                            instance_name = hostname.split("._")[0]
                            if instance_name and not instance_name.startswith("_"):
                                hostname = instance_name
                            else:
                                hostname = None
                        else:
                            hostname = None

                    # Skip too-short or numeric-only names
                    if hostname and len(hostname) < 2:
                        hostname = None

                    # Skip junk hostnames (UUIDs, hex IDs, reverse-DNS PTRs)
                    if hostname and _is_junk_hostname(hostname):
                        hostname = None

                    # Need at least a hostname or a device_class to be useful
                    if not hostname and not mdns_device_class:
                        continue

                    # Dedup
                    now = time.time()
                    dedup_key = f"{src_ip}:{hostname or ''}:{mdns_device_class or ''}"
                    last = _mdns_last_seen.get(dedup_key, 0)
                    if (now - last) < MDNS_DEDUP_SECONDS:
                        continue
                    _mdns_last_seen[dedup_key] = now

                    # Look up MAC from conn.log cache
                    mac = _ip_to_mac.get(src_ip)

                    payload: dict = {"ip": src_ip}
                    if hostname:
                        payload["hostname"] = hostname
                    if mac:
                        payload["mac_address"] = mac

                    try:
                        await client.post(DEVICE_API_URL, json=payload, timeout=5)
                        # Also update device_class if we identified a service type
                        if mdns_device_class and mac:
                            fp_payload = {
                                "ip": src_ip,
                                "device_class": mdns_device_class,
                            }
                            fp_url = DEVICE_API_URL.replace("/devices", "/devices/fingerprint")
                            await client.post(fp_url, json=fp_payload, timeout=5)
                        label = f"{hostname or '?'} ({mdns_device_class})" if mdns_device_class else hostname
                        print(f"[mDNS] Device: {label} → {src_ip} (MAC: {mac or 'unknown'})")
                    except httpx.HTTPError as exc:
                        print(f"[!] mDNS device registration failed: {exc}")

        except (OSError, IOError) as exc:
            print(f"[!] mdns.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# HTTP User-Agent fingerprinting — tail http.log (Firewalla-inspired)
# ---------------------------------------------------------------------------
# Parse User-Agent strings from Zeek http.log to identify device type,
# brand, model, and OS. Uses the device_detector library. Results are
# sent to the API which stores them in the Device table.
#
# Firewalla insight: if a single MAC shows 3+ different device types in
# its UA history, it's likely a router (proxying traffic from many devices).

UA_FINGERPRINT_API_URL = os.environ.get(
    "AIRADAR_UA_FP_API_URL",
    "http://localhost:8000/api/devices/ua-fingerprint",
)
UA_DEDUP_SECONDS = 3600  # 1 hour per (mac, ua_hash)
_ua_last_seen: dict[str, float] = {}

# Lazy-loaded device detector (import is slow, ~200ms)
_ua_detector = None

def _get_ua_detector():
    global _ua_detector
    if _ua_detector is None:
        try:
            from device_detector import DeviceDetector
            _ua_detector = DeviceDetector
            print("[ua-fp] device_detector library loaded")
        except ImportError:
            print("[ua-fp] device_detector not installed — UA fingerprinting disabled")
            _ua_detector = False  # sentinel: tried and failed
    return _ua_detector if _ua_detector is not False else None


async def tail_http_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Tail Zeek's http.log for User-Agent device fingerprinting."""
    print(f"[*] Tailing http.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(5)
            continue

        try:
            with open(log_path, "r") as f:
                header_lines: list[str] = []
                for line in f:
                    if line.startswith("#"):
                        header_lines.append(line)
                    else:
                        break
                fields = parse_zeek_header(header_lines) or []
                f.seek(0, 2)

                _line_count = 0
                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break
                        except OSError:
                            break
                        await asyncio.sleep(1)
                        continue

                    line = line.strip()
                    if line.startswith("#") or not line:
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        continue

                    if not fields:
                        continue

                    parts = line.split("\t")
                    if len(parts) != len(fields):
                        continue

                    _line_count += 1
                    if _line_count % 1000 == 0:
                        await asyncio.sleep(0)

                    try:
                        record = dict(zip(fields, parts))
                    except Exception:
                        continue

                    ua = record.get("user_agent", "-")
                    if ua in ("-", "(empty)", "") or not ua:
                        continue

                    src_ip = record.get("id.orig_h", "-")
                    if src_ip == "-" or not _is_local_ip(src_ip):
                        continue

                    # Get MAC for this IP
                    mac = _ip_to_mac.get(src_ip)
                    if not mac:
                        continue

                    # Dedup: only process each (mac, ua) pair once per hour
                    ua_hash = f"{mac}:{hash(ua) & 0xFFFFFFFF}"
                    now = time.time()
                    last = _ua_last_seen.get(ua_hash, 0)
                    if (now - last) < UA_DEDUP_SECONDS:
                        continue
                    _ua_last_seen[ua_hash] = now

                    # Parse User-Agent
                    detector_cls = _get_ua_detector()
                    if not detector_cls:
                        continue

                    try:
                        det = detector_cls(ua).parse()
                        device_type = det.device_type() or None
                        brand = det.device_brand() or None
                        model = det.device_model() or None
                        os_name = None
                        os_info = det.os_name()
                        if os_info:
                            os_name = os_info

                        # Normalize phone types (Firewalla pattern)
                        if device_type and device_type.lower() in (
                            "smartphone", "feature phone", "phablet"
                        ):
                            device_type = "phone"

                        if not any([device_type, brand, model, os_name]):
                            continue

                        payload = {
                            "ip": src_ip,
                            "mac_address": mac,
                            "device_type": device_type,
                            "brand": brand,
                            "model": model,
                            "os_name": os_name,
                        }
                        await client.post(UA_FINGERPRINT_API_URL, json=payload, timeout=5)
                        print(f"[ua-fp] {mac}: {device_type or '?'} {brand or ''} {model or ''} ({os_name or '?'})")
                    except Exception as exc:
                        print(f"[ua-fp] Parse error for UA '{ua[:60]}…': {exc}")

        except (OSError, IOError) as exc:
            print(f"[!] http.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# DNS-IP correlation — tail dns.log to populate the labeler fallback cache
# ---------------------------------------------------------------------------
# This is the heart of the Day-1 coverage uplift. Zeek's dns.log records
# every DNS A/AAAA response on the bridge in plaintext. By recording the
# (client_mac, resolved_ip) → query mapping into dns_cache.GLOBAL_CACHE,
# we give every other labeler in the pipeline a way to recover the
# hostname for an encrypted flow that has no visible SNI (QUIC, ECH).
#
# The cache itself lives in the dns_cache module — pure stdlib, fully
# tested in isolation. This function is just the Zeek-format adapter.

async def tail_dns_log(log_path: Path) -> None:
    """Tail Zeek's dns.log and feed every successful A/AAAA response
    into the global DNS correlation cache.

    Filters: NOERROR responses, A or AAAA qtype, query and answers
    fields populated, originating client is on the local network and
    we know its MAC. Anything else is dropped — better to miss a
    record than to poison the cache with garbage.

    The CNAME-correctness rule (every IP in the chain maps to the
    ORIGINAL query, never to an intermediate CNAME) is enforced inside
    dns_cache.parse_zeek_answers() and verified by tests/test_dns_cache.py.
    """
    print(f"[*] Tailing dns.log: {log_path}")
    fields: list[str] = []

    while True:
        if not log_path.exists():
            await asyncio.sleep(5)
            continue

        try:
            with open(log_path, "r") as f:
                header_lines: list[str] = []
                for line in f:
                    if line.startswith("#"):
                        header_lines.append(line)
                    else:
                        break
                fields = parse_zeek_header(header_lines) or []
                f.seek(0, 2)

                _line_count = 0
                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break  # rotated
                        except OSError:
                            break
                        await asyncio.sleep(0.5)
                        continue

                    line = line.strip()
                    if line.startswith("#") or not line:
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        continue

                    if not fields:
                        continue

                    parts = line.split("\t")
                    if len(parts) != len(fields):
                        continue

                    _line_count += 1
                    if _line_count % 1000 == 0:
                        await asyncio.sleep(0)

                    try:
                        record = dict(zip(fields, parts))
                    except Exception as _parse_exc:
                        print(f"[dns.log] Malformed line skipped: {_parse_exc}")
                        continue

                    # Only successful resolutions. NXDOMAIN, REFUSED,
                    # SERVFAIL, etc. add no signal.
                    if record.get("rcode_name", "-") != "NOERROR":
                        continue

                    # Only IP-resolving queries. MX, TXT, SRV etc. give
                    # us hostnames-pointing-to-hostnames which is not
                    # what we want for IP correlation.
                    qtype = record.get("qtype_name", "-")
                    if qtype not in ("A", "AAAA"):
                        continue

                    query = record.get("query", "-")
                    if not query or query == "-":
                        continue

                    answers = record.get("answers", "-")
                    if not answers or answers == "-":
                        continue

                    # The client that asked the question is the orig_h
                    # of the DNS query. It must be local — we don't
                    # care about anyone else's lookups.
                    client_ip = record.get("id.orig_h", "-")
                    if client_ip == "-" or not _is_local_ip(client_ip):
                        continue

                    client_mac = _ip_to_mac.get(client_ip)
                    if not client_mac:
                        # No MAC means we can't scope per-client, which
                        # would re-introduce the CDN multi-tenancy bug
                        # the cache is designed to prevent. Drop.
                        continue

                    ttls = record.get("TTLs")

                    # Parse the answers field ourselves (instead of using
                    # _DNS_CACHE.ingest_zeek_response) so we have access to
                    # each individual (ip, query, ttl) triple. We need
                    # them per-IP both to feed the in-memory cache AND
                    # to queue durable observations into the persist
                    # buffer for the dns_observations table.
                    triples = parse_zeek_answers(
                        query=query,
                        answers_field=answers,
                        ttls_field=ttls,
                        default_ttl=DEFAULT_MIN_TTL_SECONDS,
                    )
                    if not triples:
                        continue

                    obs_now = datetime.now(timezone.utc).replace(tzinfo=None)
                    answer_ips_json = json.dumps([t[0] for t in triples])

                    for ip, q, ttl in triples:
                        _DNS_CACHE.put(client_mac, ip, q, ttl)
                        # Queue for durable persistence. Drained by
                        # flush_dns_observations() every 30s. Buffer is
                        # capped via DNS_PERSIST_BATCH_MAX in the
                        # flusher; if pressure builds we drop the
                        # oldest rather than the newest.
                        if len(_dns_persist_buffer) < DNS_PERSIST_BATCH_MAX * 4:
                            _dns_persist_buffer.append({
                                "client_mac": client_mac,
                                "server_ip": ip,
                                "query": q,
                                "answer_ips": answer_ips_json,
                                "ttl": ttl,
                                "observed_at": obs_now,
                            })

                    # Telemetry: only print on novel queries to avoid
                    # log spam from chatty resolvers.
                    if _DNS_CACHE.stats()["puts"] % 500 == 0:
                        s = _DNS_CACHE.stats()
                        print(
                            f"[dns] cache: {s['size']} entries, "
                            f"hit_rate {s['hit_rate']*100:.1f}%, "
                            f"replacements {s['replacements']}, "
                            f"persist_buf {len(_dns_persist_buffer)}"
                        )
        except (OSError, IOError) as exc:
            print(f"[!] dns.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# DNS correlation labeler — fallback for flows with no visible SNI
# ---------------------------------------------------------------------------
# Hookpoint helper used by tail_conn_log when a flow's destination IP is
# not in the SNI-populated _known_ips cache. We try the DNS cache: maybe
# this client recently resolved a hostname to this IP, and that hostname
# matches a known service. If so, we have a label.
#
# The lookup is per-flow (not cached at the IP level) because per-IP
# caching across clients is exactly the CDN multi-tenancy bug we're
# trying to avoid. dns_cache.get() is O(1) and lock-protected, so this
# is fine to call on every conn.log line.

def _label_flow_via_dns(
    src_ip: str, resp_ip: str
) -> tuple[str, str, str, float, str] | None:
    """Try to label a flow via the DNS-IP correlation cache.

    Returns (service, category, hostname, effective_score, rationale)
    on hit, or None when:
      - we don't know the source MAC (can't scope the lookup)
      - the cache has no entry for (mac, resp_ip)
      - the cached hostname doesn't match anything in known_domains

    The effective_score is computed via labeler.LabelProposal so it
    respects the SOURCE_WEIGHTS hierarchy. Falls below CONFIDENCE_FLOOR
    only when the labeler weight changes — for dns_correlation at 0.75
    weight × 1.0 nominal confidence we sit at 0.75, comfortably above.
    """
    client_mac = _ip_to_mac.get(src_ip)
    if not client_mac:
        return None
    hostname = _DNS_CACHE.get(client_mac, resp_ip)
    if not hostname:
        return None
    match = match_domain(hostname, source_ip=src_ip)
    if not match:
        return None
    service, category, matched_domain = match
    proposal = LabelProposal(
        labeler="dns_correlation",
        service=service,
        category=category,
        confidence=1.0,  # the DNS lookup itself is deterministic; the
                         # uncertainty is captured by the source weight
        rationale=f"DNS resolved {hostname} → {resp_ip} via {client_mac[-8:]}",
    )
    return service, category, hostname, proposal.effective_score, proposal.rationale


# ---------------------------------------------------------------------------
# DNS observation persistence — durable backing store for the in-memory cache
# ---------------------------------------------------------------------------
# The in-memory DnsCache is fast but volatile: every container rebuild
# wipes it, leaving a ~5 minute window where dns_correlation labels
# nothing because the cache hasn't refilled. We close that gap by
# (1) writing every cache insert to the dns_observations table in
# small batches, and (2) reading the most recent rows back into the
# cache on startup as a warm-up.
#
# The buffer is only ever touched by coroutines on the same event
# loop (tail_dns_log appends, flush_dns_observations drains). Neither
# operation yields between read and clear, so a lock is not required —
# coroutines don't preempt each other in CPython asyncio. If a future
# change adds an `await` between the snapshot and clear in the flush
# loop, revisit this assumption.

_dns_persist_buffer: list[dict] = []

# Tunables. Conservative defaults: a quiet home network produces a few
# hundred DNS lookups per minute, so a 30 s flush at batch-size 100
# means at most ~1 batch per flush, and the buffer never grows beyond
# the size of two intervals' worth of traffic.
DNS_PERSIST_FLUSH_INTERVAL = 30.0   # seconds between batched DB writes
DNS_PERSIST_BATCH_MAX = 500          # safety cap so a thundering herd
                                     # doesn't OOM us during a DNS storm
DNS_WARMUP_MAX_AGE_HOURS = 6         # how far back warm-up reaches
DNS_WARMUP_ROW_LIMIT = 20_000        # cap on rows pulled at startup;
                                     # 20k * ~150B ≈ 3 MB, fast even
                                     # on the mini-PC's spinning disk


async def flush_dns_observations() -> None:
    """Background task: drain _dns_persist_buffer to the dns_observations table.

    Writes are batched on a fixed interval to keep the SQLite write
    rate low and predictable. A failed batch is logged but the buffer
    is still cleared — we'd rather drop a few audit rows than let the
    buffer grow without bound while the DB is down.
    """
    # Lazy import — keeps zeek_tailer importable even if database.py is
    # mid-migration on a fresh install (the table is created by Day 0).
    from database import SessionLocal as _SL, DnsObservation as _DO

    print("[*] DNS observation persister: enabled (batched flush every "
          f"{int(DNS_PERSIST_FLUSH_INTERVAL)}s)")

    while True:
        await asyncio.sleep(DNS_PERSIST_FLUSH_INTERVAL)

        # Snapshot + clear in one synchronous step. No await between
        # these two lines → no other coroutine can sneak an append in
        # and lose it.
        if not _dns_persist_buffer:
            continue
        batch = _dns_persist_buffer[:DNS_PERSIST_BATCH_MAX]
        del _dns_persist_buffer[:len(batch)]

        try:
            db = _SL()
            try:
                for obs in batch:
                    db.add(_DO(
                        client_mac=obs["client_mac"],
                        server_ip=obs["server_ip"],
                        query=obs["query"],
                        answer_ips=obs.get("answer_ips"),
                        ttl=obs.get("ttl"),
                        observed_at=obs["observed_at"],
                        source_log="zeek_dns",
                    ))
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            # We deliberately don't re-queue failed rows: a persistent
            # DB error would balloon the buffer indefinitely. The next
            # interval will pick up fresh observations and the gap
            # shows up in the audit trail as a small hole.
            print(f"[dns-persist] flush of {len(batch)} rows failed: {exc}")


async def warmup_dns_cache_from_db() -> int:
    """One-shot at startup: prime _DNS_CACHE from recent dns_observations.

    Skips rows whose wire TTL has already expired (we don't want to
    poison the cache with mappings the original DNS resolver itself
    would no longer trust). Returns the number of cache entries
    restored, for the startup banner.

    This is what closes the cold-start gap. Without it, every
    `docker compose up -d --build` produces a ~5 minute window where
    dns_correlation labels nothing because the in-memory cache is
    empty. With it, the cache is warm before tail_dns_log even reads
    its first new line.
    """
    from database import SessionLocal as _SL, DnsObservation as _DO

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=DNS_WARMUP_MAX_AGE_HOURS)
    restored = 0
    skipped_expired = 0

    try:
        db = _SL()
        try:
            rows = (
                db.query(_DO)
                .filter(_DO.observed_at > cutoff)
                .order_by(_DO.observed_at.asc())  # oldest first → newest
                                                  # observation wins on
                                                  # any (mac, ip) collision
                .limit(DNS_WARMUP_ROW_LIMIT)
                .all()
            )
        finally:
            db.close()

        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        for r in rows:
            obs_at = r.observed_at
            if obs_at is None:
                continue
            if obs_at.tzinfo is None:
                obs_at = obs_at.replace(tzinfo=timezone.utc)

            obs_age = (now_dt - obs_at).total_seconds()
            wire_ttl = r.ttl or DEFAULT_MIN_TTL_SECONDS
            remaining = wire_ttl - obs_age
            if remaining <= 0:
                skipped_expired += 1
                continue

            _DNS_CACHE.put(
                client_mac=r.client_mac,
                server_ip=r.server_ip,
                hostname=r.query,
                raw_ttl=int(remaining),
            )
            restored += 1
    except Exception as exc:
        print(f"[dns-warmup] failed: {exc}")
        return 0

    if skipped_expired:
        print(f"[dns-warmup] skipped {skipped_expired} rows past their wire TTL")
    return restored


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

async def main(zeek_log_dir: str) -> None:
    log_dir = Path(zeek_log_dir)
    ssl_log = log_dir / "ssl.log"
    conn_log = log_dir / "conn.log"
    dhcp_log = log_dir / "dhcp.log"
    ja4d_log = log_dir / "ja4d.log"
    mdns_log = log_dir / "mdns.log"
    dns_log = log_dir / "dns.log"
    quic_log = log_dir / "quic.log"
    http_log = log_dir / "http.log"

    # Per-labeler rollback flags. Each labeler can be turned off via
    # an env var so we can isolate it in production without a code
    # revert. Default true — rollback is opt-in. The plan calls for
    # one such flag per stage; Day 1 added DNS snooping, Day 2 adds
    # the QUIC tailer.
    global _ja4_match_enabled

    dns_snooping_enabled = os.environ.get(
        "LABELER_DNS_SNOOPING", "true"
    ).strip().lower() in ("true", "1", "yes", "on")
    quic_tailer_enabled = os.environ.get(
        "LABELER_QUIC_TAILER", "true"
    ).strip().lower() in ("true", "1", "yes", "on")
    _ja4_match_enabled = os.environ.get(
        "LABELER_JA4_MATCH", "true"
    ).strip().lower() in ("true", "1", "yes", "on")

    print(f"[*] AI-Radar Zeek Tailer starting on host '{SENSOR_ID}'")
    print(f"[*] Reporting to API at {API_URL}")
    print(f"[*] Monitoring {len(DOMAIN_MAP)} domains (AI + Cloud)")
    print(f"[*] Upload threshold: {UPLOAD_THRESHOLD_BYTES:,} bytes")
    print(f"[*] Upload debounce window: {UPLOAD_DEBOUNCE_SECONDS}s")
    print(f"[*] DHCP passive device recognition: enabled")
    print(f"[*] JA4D DHCP fingerprinting: enabled (tailing ja4d.log)")
    print(f"[*] mDNS device name + service type discovery: enabled (tailing mdns.log)")
    print(f"[*] HTTP User-Agent fingerprinting: enabled (tailing http.log)")
    if dns_snooping_enabled:
        print(f"[*] DNS-IP correlation labeler: enabled (tailing dns.log)")
    else:
        print(f"[*] DNS-IP correlation labeler: DISABLED via LABELER_DNS_SNOOPING")
    if quic_tailer_enabled:
        print(f"[*] QUIC SNI labeler: enabled (tailing quic.log)")
    else:
        print(f"[*] QUIC SNI labeler: DISABLED via LABELER_QUIC_TAILER")
    if _ja4_match_enabled:
        print(f"[*] JA4 community DB labeler: enabled (weekly sync from FoxIO)")
    else:
        print(f"[*] JA4 community DB labeler: DISABLED via LABELER_JA4_MATCH")
    print(f"[*] DPD stealth VPN/Tor detection: enabled ({len(DPD_EVASION_PROTOCOLS)} protocols)")
    print(f"[*] Zeek log directory: {log_dir}")

    # p0f passive OS fingerprinting — tail existing p0f log file
    p0f_task = None
    try:
        from p0f_tailer import tail_p0f_standalone, P0F_LOG_FILE
        p0f_log = Path(P0F_LOG_FILE)
        p0f_task = tail_p0f_standalone(p0f_log)
        print(f"[*] p0f passive OS fingerprinting: enabled (tailing {p0f_log})")
    except ImportError:
        print(f"[*] p0f passive OS fingerprinting: disabled (p0f_tailer not found)")
    except Exception as exc:
        print(f"[*] p0f passive OS fingerprinting: disabled ({exc})")

    # nDPI deep packet inspection — tail ndpiReader output
    ndpi_task = None
    try:
        from ndpi_tailer import tail_ndpi_output, NDPI_OUTPUT_FILE
        ndpi_path = Path(NDPI_OUTPUT_FILE)
        ndpi_task = tail_ndpi_output(ndpi_path)
        print(f"[*] nDPI deep packet inspection: enabled (tailing {ndpi_path})")
    except ImportError:
        print(f"[*] nDPI deep packet inspection: disabled (ndpi_tailer not found)")
    except Exception as exc:
        print(f"[*] nDPI deep packet inspection: disabled ({exc})")

    print()

    # Network scanner — periodic nmap + nbtscan for hostname discovery
    scanner_task = None
    try:
        from network_scanner import run_network_scanner
        scanner_task = run_network_scanner()
        print(f"[*] Network scanner: enabled (nmap + nbtscan)")
    except ImportError:
        print(f"[*] Network scanner: disabled (network_scanner not found)")
    except Exception as exc:
        print(f"[*] Network scanner: disabled ({exc})")

    client = httpx.AsyncClient()

    # Auto-download the ASN MMDB if it's missing. This is the only
    # reliable way to ensure enrichment works on a fresh install where
    # setup.sh was skipped — without it every Top-remote-IP entry
    # shows "enriching…" forever.
    await ensure_asn_db(client)

    # DNS cache warm-up: pull recent dns_observations rows back into
    # the in-memory cache BEFORE any conn.log line gets the chance to
    # ask for a label. This collapses the cold-start gap (~5 minutes
    # of zero correlation coverage after every rebuild) to roughly
    # zero. Skipped when DNS snooping is disabled — no point warming
    # a cache nobody will read.
    if dns_snooping_enabled:
        warmed = await warmup_dns_cache_from_db()
        print(f"[*] DNS cache warm-up: {warmed} entries restored from DnsObservation")

    # JA4 community DB sync — issue #6 fix: persist last_sync_at in the
    # ja4_signatures.updated_at column. On startup, check if a sync is
    # needed (>7 days since last import) and run it before tailing starts.
    if _ja4_match_enabled:
        try:
            from ja4_db_sync import sync_ja4_db, needs_sync
            from database import SessionLocal as _JA4SL
            _ja4_db = _JA4SL()
            if needs_sync(_ja4_db):
                print("[ja4-sync] JA4 community DB is stale or empty — syncing from FoxIO…")
                synced = await sync_ja4_db(_ja4_db)
                print(f"[ja4-sync] Imported {synced} fingerprints")
            else:
                print("[ja4-sync] JA4 community DB is fresh — skipping sync")
            _ja4_db.close()
        except Exception as exc:
            print(f"[ja4-sync] Startup sync failed (will retry in 7d): {exc}")

    tasks = [
        tail_ssl_log(ssl_log, client),
        tail_conn_log(conn_log, client),
        tail_dhcp_log(dhcp_log, client),
        tail_ja4d_log(ja4d_log, client),
        tail_mdns_log(mdns_log, client),
        tail_http_log(http_log, client),
        flush_upload_buckets(client),  # background flusher
        flush_geo_buckets(client),     # geo traffic buffer → DB every 15s
        enrich_ip_metadata_loop(client), # PTR + ASN lookups for new remote IPs
        sync_domain_cache(),           # refresh dynamic domain map from KnownDomain every 5min
        cleanup_memory_caches(),       # evict stale entries from in-memory dedup dicts
        backfill_missing_asn(client),  # one-shot retry for pre-MMDB rows
        _refresh_device_meta(client),  # pull device metadata for Phase 2
        _refresh_third_party_sources(),# AdGuard + DDG lookup refresh
        _refresh_crowdsec_cache(client), # CrowdSec IP blocklist → fast local set
    ]
    if dns_snooping_enabled:
        tasks.append(tail_dns_log(dns_log))
        tasks.append(flush_dns_observations())
    if quic_tailer_enabled:
        tasks.append(tail_quic_log(quic_log, client))
    if _ja4_match_enabled:
        tasks.append(sync_ja4_cache())
    tasks.append(sync_ip_meta_cache())  # PTR/ASN fallback cache
    if p0f_task is not None:
        tasks.append(p0f_task)
    if scanner_task is not None:
        tasks.append(scanner_task)
    if ndpi_task is not None:
        tasks.append(ndpi_task)

    try:
        await asyncio.gather(*tasks)
    finally:
        await client.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Radar Zeek Log Tailer")
    parser.add_argument(
        "--zeek-log-dir",
        default="/opt/homebrew/var/log/zeek/current",
        help="Path to Zeek's current log directory",
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(args.zeek_log_dir))
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
