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
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

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
GEO_META_API_URL = os.environ.get(
    "AIRADAR_GEO_META_API_URL",
    "http://localhost:8000/api/geo/metadata/ingest",
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
    # Datacamp Limited / CDN77 — NordVPN, ExpressVPN exit pools.
    60068:  "datacamp",
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
    # Google Gemini
    "gemini.google.com":                 ("google_gemini", "ai"),
    "generativelanguage.googleapis.com": ("google_gemini", "ai"),
    "aistudio.google.com":               ("google_gemini", "ai"),
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
    # Perplexity
    "perplexity.ai":                     ("perplexity", "ai"),
    # Hugging Face
    "huggingface.co":                    ("huggingface", "ai"),
    # Mistral
    "mistral.ai":                        ("mistral", "ai"),

    # --- Cloud storage / transfer (category="cloud") ---
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
    "amazonvideo.com":                   ("prime_video", "streaming"),
    "tv.apple.com":                      ("apple_tv", "streaming"),
}


# ---------------------------------------------------------------------------
# Context-aware Google service tracker
# ---------------------------------------------------------------------------
# Ambiguous googleapis.com domains (www, content) are used by BOTH Gemini and
# Drive.  We resolve the ambiguity by tracking which Google "context" an IP
# was recently associated with (e.g. gemini.google.com → ai, drive.google.com
# → cloud).  When we see www.googleapis.com from the same IP, we use the most
# recent context to classify it.

# Maps source_ip → (service, category, timestamp)
_google_context: dict[str, tuple[str, str, float]] = {}
GOOGLE_CONTEXT_TTL = 300  # 5 minutes

# Domains that set Google context (but are NOT ambiguous themselves)
_GOOGLE_CONTEXT_SETTERS = {
    "gemini.google.com":                 ("google_gemini", "ai"),
    "generativelanguage.googleapis.com": ("google_gemini", "ai"),
    "aistudio.google.com":               ("google_gemini", "ai"),
    "drive.google.com":                  ("google_drive", "cloud"),
    "docs.google.com":                   ("google_drive", "cloud"),
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

        # _known_ips: ip → (svc, cat, ts), TTL = IP_TTL_SECONDS
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
    if source_ip:
        for ctx_domain, (ctx_svc, ctx_cat) in _GOOGLE_CONTEXT_SETTERS.items():
            if hostname == ctx_domain or hostname.endswith("." + ctx_domain):
                _google_context[source_ip] = (ctx_svc, ctx_cat, time.time())
                break

    # 2) Handle ambiguous Google domains using context
    for amb_domain in _GOOGLE_AMBIGUOUS:
        if hostname == amb_domain or hostname.endswith("." + amb_domain):
            if source_ip and source_ip in _google_context:
                svc, cat, ts = _google_context[source_ip]
                if (time.time() - ts) < GOOGLE_CONTEXT_TTL:
                    return svc, cat, hostname
            # No context → default to google_drive / cloud
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
    from third_party_sources import load_third_party_map
    while True:
        try:
            tp = await load_third_party_map()
            if tp:
                _rebuild_lookup(tp)
                print(
                    f"[third-party] Effective domain map rebuilt: "
                    f"{len(_effective_domain_map)} entries "
                    f"({len(_dynamic_domain_map)} KnownDomain + "
                    f"{len(DOMAIN_MAP)} static fallback + "
                    f"{len(tp)} third-party)"
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
    """Normalize MAC: lowercase, strip leading zeros per octet.
    e.g. 'A2:C0:6D:40:07:F7' → 'a2:c0:6d:40:7:f7'
    """
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return ":".join(format(int(p, 16), "x") for p in parts)
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
_known_ips: dict[str, tuple[str, str, float]] = {}  # ip → (service, category, time.time())

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
) -> None:
    """POST a detection event to the API."""
    event = {
        "sensor_id": SENSOR_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_type": detection_type,
        "ai_service": ai_service,
        "source_ip": source_ip,
        "bytes_transferred": bytes_transferred,
        "category": category,
        "possible_upload": possible_upload,
    }
    try:
        resp = await client.post(API_URL, json=event, timeout=5)
        resp.raise_for_status()
        tag = " [UPLOAD]" if possible_upload else ""
        print(
            f"[+] Event: {ai_service.upper()} ({category}) "
            f"{detection_type} from {source_ip}{tag}"
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

                record = dict(zip(fields, parts))

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

                # Learn this destination IP for conn.log correlation (with TTL)
                if resp_ip and resp_ip != "-":
                    _known_ips[resp_ip] = (service, category, time.time())

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

                await send_event(
                    client,
                    detection_type="sni_hello",
                    ai_service=service,
                    source_ip=src_ip,
                    bytes_transferred=orig_bytes,
                    category=category,
                )


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


def _resolve_country(ip: str) -> str | None:
    """Return ISO-3166-1 alpha-2 country code for a public IP, or None.

    Handles multiple MMDB schemas:
      - MaxMind GeoLite2:  {"country": {"iso_code": "US"}, ...}
      - DB-IP Country:     {"country": {"iso_code": "US"}, ...}  (same)
      - iptoasn-country:   {"country_code": "US"}
    """
    global _geo_lookup_errors
    if not _geo_reader or not ip or ip == "-":
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

# IPs awaiting PTR/ASN enrichment. Populated by the ingest endpoint's
# response and drained by enrich_ip_metadata_loop.
_ip_enrich_queue: set[str] = set()
_ip_enrich_lock = asyncio.Lock()


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
) -> None:
    """Record one conversation row keyed on (cc, dir, mac, svc, resp_ip)."""
    if not country_code or not resp_ip:
        return
    key = (country_code, direction, mac, service or "unknown", resp_ip)
    async with _geo_lock:
        bucket = _geo_conv_buckets.get(key)
        if bucket:
            bucket["bytes"] += total_bytes
            bucket["hits"] += 1
        else:
            _geo_conv_buckets[key] = {"bytes": total_bytes, "hits": 1}


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
                    "hits": v["hits"],
                }
                for (cc, d, mac, svc, ip), v in _geo_conv_buckets.items()
            ] if _geo_conv_buckets else []
            if snapshot:
                _geo_buckets.clear()
            if conv_snapshot:
                _geo_conv_buckets.clear()

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

async def tail_conn_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Continuously tail Zeek's conn.log for completed connections.

    When a connection to a known AI/Cloud IP has large outbound bytes
    (orig_bytes > threshold), fire a volumetric_upload event.
    """
    print(f"[*] Tailing conn.log: {log_path}")
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

                record = dict(zip(fields, parts))

                src_ip = record.get("id.orig_h", "unknown")
                resp_ip = record.get("id.resp_h", "")
                # MAC address from Zeek conn.log (requires @load policy/protocols/conn/mac-logging)
                src_mac = record.get("orig_l2_addr")
                if src_mac and src_mac == "-":
                    src_mac = None
                if src_mac and _is_local_ip(src_ip):
                    _ip_to_mac[src_ip] = _normalize_mac(src_mac)
                proto = record.get("proto", "").lower()
                # Zeek MAC logging: use orig_l2_addr if available
                l2_mac = record.get("orig_l2_addr")
                if l2_mac and l2_mac == "-":
                    l2_mac = None
                # Populate IP→MAC cache for use by ssl.log and mDNS tailers
                if l2_mac and _is_local_ip(src_ip):
                    _ip_to_mac[src_ip] = _normalize_mac(l2_mac)
                resp_port_str = record.get("id.resp_p", "0")
                try:
                    resp_port = int(resp_port_str) if resp_port_str != "-" else 0
                except ValueError:
                    resp_port = 0

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
                                conv_mac = _normalize_mac(l2_mac) if l2_mac else None
                                conv_svc = "unknown"
                                svc_info = _known_ips.get(public_ip)
                                if svc_info:
                                    conv_svc = svc_info[0] or "unknown"
                                asyncio.create_task(
                                    _record_geo_conversation(
                                        cc, direction, conv_mac, conv_svc, public_ip, total,
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
                            ai_service=evasion_svc,
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
                        if (
                            resp_ip and _is_local_ip(resp_ip)
                            and resp_port in _LATERAL_MOVEMENT_PORTS
                            and src_ip != resp_ip
                        ):
                            dk = ("lateral", src_ip, resp_ip, resp_port)
                            if (now_iot - _iot_alert_last.get(dk, 0)) >= IOT_ALERT_DEDUP_SECONDS:
                                _iot_alert_last[dk] = now_iot
                                asyncio.create_task(register_device(client, src_ip, l2_mac))
                                await send_event(
                                    client,
                                    detection_type="iot_lateral_movement",
                                    ai_service=f"lateral_{resp_port}",
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

                # --- Evict stale IP mappings before further checks ---
                if resp_ip in _known_ips:
                    _, _, _learned = _known_ips[resp_ip]
                    if (time.time() - _learned) > IP_TTL_SECONDS:
                        del _known_ips[resp_ip]

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
                                    ai_service=f"vpn_{provider_label}",
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
                # (stale mappings were already evicted above)
                if resp_ip not in _known_ips:
                    continue

                service, category, _ts = _known_ips[resp_ip]

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
    "dtls":       "vpn_dtls_tunnel",    # DTLS can indicate VPN (e.g. AnyConnect)
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

                    record = dict(zip(fields, parts))

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

                    record = dict(zip(fields, parts))

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

                    record = dict(zip(fields, parts))

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

                    # Skip service discovery queries (_tcp, _udp, _services)
                    if hostname.startswith("_") or "._" in hostname:
                        continue

                    # Skip too-short or numeric-only names
                    if len(hostname) < 2:
                        continue

                    # Skip junk hostnames (UUIDs, hex IDs, reverse-DNS PTRs)
                    if _is_junk_hostname(hostname):
                        continue

                    # Dedup
                    now = time.time()
                    dedup_key = f"{src_ip}:{hostname}"
                    last = _mdns_last_seen.get(dedup_key, 0)
                    if (now - last) < MDNS_DEDUP_SECONDS:
                        continue
                    _mdns_last_seen[dedup_key] = now

                    # Look up MAC from conn.log cache
                    mac = _ip_to_mac.get(src_ip)

                    payload: dict = {"ip": src_ip, "hostname": hostname}
                    if mac:
                        payload["mac_address"] = mac

                    try:
                        await client.post(DEVICE_API_URL, json=payload, timeout=5)
                        print(f"[mDNS] Device: {hostname} → {src_ip} (MAC: {mac or 'unknown'})")
                    except httpx.HTTPError as exc:
                        print(f"[!] mDNS device registration failed: {exc}")

        except (OSError, IOError) as exc:
            print(f"[!] mdns.log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


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

    print(f"[*] AI-Radar Zeek Tailer starting on host '{SENSOR_ID}'")
    print(f"[*] Reporting to API at {API_URL}")
    print(f"[*] Monitoring {len(DOMAIN_MAP)} domains (AI + Cloud)")
    print(f"[*] Upload threshold: {UPLOAD_THRESHOLD_BYTES:,} bytes")
    print(f"[*] Upload debounce window: {UPLOAD_DEBOUNCE_SECONDS}s")
    print(f"[*] DHCP passive device recognition: enabled")
    print(f"[*] JA4D DHCP fingerprinting: enabled (tailing ja4d.log)")
    print(f"[*] mDNS device name discovery: enabled (tailing mdns.log)")
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

    tasks = [
        tail_ssl_log(ssl_log, client),
        tail_conn_log(conn_log, client),
        tail_dhcp_log(dhcp_log, client),
        tail_ja4d_log(ja4d_log, client),
        tail_mdns_log(mdns_log, client),
        flush_upload_buckets(client),  # background flusher
        flush_geo_buckets(client),     # geo traffic buffer → DB every 15s
        enrich_ip_metadata_loop(client), # PTR + ASN lookups for new remote IPs
        sync_domain_cache(),           # refresh dynamic domain map from KnownDomain every 5min
        cleanup_memory_caches(),       # evict stale entries from in-memory dedup dicts
        backfill_missing_asn(client),  # one-shot retry for pre-MMDB rows
        _refresh_device_meta(client),  # pull device metadata for Phase 2
        _refresh_third_party_sources(),# AdGuard + DDG lookup refresh
    ]
    if p0f_task is not None:
        tasks.append(p0f_task)
    if scanner_task is not None:
        tasks.append(scanner_task)

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
