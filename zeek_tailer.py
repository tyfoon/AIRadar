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
import os
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
    ("tcp", 443):   None,          # Skip — too common (HTTPS); only flagged via heuristic below
    ("udp", 443):   None,          # Skip — UDP/443 is normal QUIC/HTTP3 traffic; rely on DPD instead
    ("tcp", 1723):  "PPTP",
    ("udp", 1701):  "L2TP",
    ("tcp", 22):    None,           # SSH — skip, too common
}

# Only flag VPN if bytes exceed this threshold (filters handshakes / probes)
VPN_BYTE_THRESHOLD = 50_000  # 50 KB

# Dedup VPN events per (src_ip, dest_port) — avoid flooding dashboard
VPN_DEDUP_SECONDS = 300  # 5-minute window
_vpn_last_seen: dict[tuple[str, int], float] = {}  # (src_ip, resp_port) → ts

# ---------------------------------------------------------------------------
# Heuristic VPN detection — single-destination high-volume encrypted flows
# ---------------------------------------------------------------------------
# On a network bridge, a VPN client appears as a device sending huge amounts
# of encrypted UDP (WireGuard/NordLynx) or TCP traffic to a single external IP,
# often on port 443 to look like normal HTTPS.  We detect this by tracking
# per-(src_ip, dest_ip) byte accumulation.  If a single destination receives
# a disproportionate share of a device's traffic AND the traffic is not a
# known service (not in _known_ips), flag it as a potential VPN tunnel.

HEURISTIC_VPN_BYTE_THRESHOLD = 20_000_000  # 20 MB in one conn.log entry (was 5 MB — too aggressive)
HEURISTIC_VPN_DEDUP_SECONDS = 600  # 10 min window
_heuristic_vpn_seen: dict[tuple[str, str], float] = {}  # (src_ip, dest_ip) → ts

# Zeek DPD service labels that indicate normal (non-VPN) traffic.
# If conn.log's `service` field contains any of these, do NOT flag as heuristic VPN.
HEURISTIC_VPN_SAFE_SERVICES = frozenset({
    "ssl", "http", "dns", "quic", "ntp", "dhcp", "krb", "dce_rpc",
    "smb", "smtp", "imap", "pop3", "ftp", "ssh", "rdp", "mysql",
    "ntlm", "gssapi", "ldap", "snmp", "sip", "stun", "mqtt",
})

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
    "storage.googleapis.com":            ("google_drive", "cloud"),
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


def match_domain(
    hostname: str, source_ip: str | None = None
) -> tuple[str, str, str] | None:
    """Match a hostname against the domain map.

    Returns (service_name, category, matched_domain) or None.
    Supports exact match and subdomain matching (e.g. foo.dropbox.com).

    For ambiguous Google domains (www.googleapis.com), uses source_ip context
    to determine whether traffic is Gemini (ai) or Drive (cloud).
    """
    hostname = hostname.rstrip(".").lower()

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

    # 3) Normal domain map lookup
    for domain, (service, category) in DOMAIN_MAP.items():
        if hostname == domain or hostname.endswith("." + domain):
            return service, category, domain
    return None


# ---------------------------------------------------------------------------
# Device fingerprinting
# ---------------------------------------------------------------------------

_device_cache: dict[str, float] = {}  # ip -> last_registered_at
DEVICE_CACHE_TTL = 300  # 5 minutes


def _resolve_hostname(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _normalize_mac(mac: str) -> str:
    """Normalize MAC: lowercase, strip leading zeros per octet.
    e.g. 'A2:C0:6D:40:07:F7' → 'a2:c0:6d:40:7:f7'
    """
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return ":".join(format(int(p, 16), "x") for p in parts)
    except (ValueError, AttributeError):
        return mac.lower()


def _resolve_mac(ip: str) -> str | None:
    """Resolve an IP address to a MAC via ARP (IPv4) or NDP (IPv6)."""
    # --- IPv6: use ndp -a (macOS) or ip neigh (Linux) ---
    if ":" in ip:
        return _resolve_mac_ipv6(ip)
    # --- IPv4: use arp ---
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True, text=True, timeout=3,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "at" and i + 1 < len(parts):
                    mac = parts[i + 1]
                    if ":" in mac and mac != "(incomplete)":
                        return _normalize_mac(mac)
                if p == "ether" and i + 1 < len(parts):
                    return _normalize_mac(parts[i + 1])
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# Cache NDP table to avoid running ndp -a for every single IPv6 address
_ndp_cache: dict[str, str] = {}   # normalized IPv6 → MAC
_ndp_cache_ts: float = 0.0
_NDP_CACHE_TTL = 60  # refresh every 60s


def _refresh_ndp_cache() -> None:
    """Parse the full NDP neighbor table into a lookup dict."""
    global _ndp_cache, _ndp_cache_ts
    now = time.time()
    if now - _ndp_cache_ts < _NDP_CACHE_TTL:
        return
    _ndp_cache_ts = now
    new_cache: dict[str, str] = {}
    try:
        # macOS: ndp -a
        result = subprocess.run(
            ["ndp", "-a"], capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            # Format: "2a02-a447-...-8cfc.host.net a2:c0:6d:40:7:f7 en0 permanent R"
            parts = line.split()
            if len(parts) >= 2 and ":" in parts[1] and parts[1] != "(incomplete)":
                # The hostname field encodes the IPv6 as dashes — resolve via column 0
                # But we need the actual IPv6. Try parsing it from the hostname.
                host = parts[0]
                mac = _normalize_mac(parts[1])
                # Convert dashed hostname back to IPv6
                # "2a02-a447-d50b-0-e15b-602c-c763-8cfc.fixed6.kpn.net"
                #  → "2a02:a447:d50b:0:e15b:602c:c763:8cfc"
                ip_part = host.split(".")[0]  # strip domain
                candidate = ip_part.replace("-", ":")
                try:
                    import ipaddress
                    addr = ipaddress.ip_address(candidate)
                    new_cache[str(addr)] = mac
                except ValueError:
                    pass
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Linux fallback: ip -6 neigh
        try:
            result = subprocess.run(
                ["ip", "-6", "neigh"], capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                # Format: "2a02:a447:... dev eth0 lladdr a2:c0:6d:40:07:f7 REACHABLE"
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
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
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


def _resolve_mac_ipv6(ip: str) -> str | None:
    """Resolve an IPv6 address to MAC via the NDP neighbor cache,
    falling back to EUI-64 extraction for link-local addresses."""
    _refresh_ndp_cache()
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


def _is_local_ip(ip: str) -> bool:
    """Check if an IP address is a local/private network address."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        # Private ranges: 10.x, 172.16-31.x, 192.168.x, fc00::/7, fe80::/10
        return addr.is_private or addr.is_link_local
    except ValueError:
        return False


async def register_device(client: httpx.AsyncClient, ip: str) -> None:
    """Register/update a device on the API (non-blocking).

    Only registers devices with local/private IP addresses — public IPs
    (AI service servers, CDNs, etc.) are NOT devices on our network.
    """
    if not _is_local_ip(ip):
        return

    now = time.time()
    last = _device_cache.get(ip, 0)
    if now - last < DEVICE_CACHE_TTL:
        return
    _device_cache[ip] = now

    hostname = _resolve_hostname(ip)
    mac = _resolve_mac(ip)
    payload: dict = {"ip": ip}
    if hostname:
        payload["hostname"] = hostname
    if mac:
        payload["mac_address"] = mac
    try:
        await client.post(DEVICE_API_URL, json=payload, timeout=5)
        name = hostname or mac or ip
        print(f"[*] Device registered: {ip} -> {name}")
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
SNI_DEDUP_SECONDS = 120  # 2-minute window per (service, device)
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

                # Pass source_ip so ambiguous Google domains can be resolved
                match = match_domain(sni, source_ip=src_ip)
                if not match:
                    continue

                service, category, _domain = match
                resp_ip = record.get("id.resp_h", "")

                # Learn this destination IP for conn.log correlation (with TTL)
                if resp_ip and resp_ip != "-":
                    _known_ips[resp_ip] = (service, category, time.time())

                # Register the device if it's a local source
                asyncio.create_task(register_device(client, src_ip))

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
                proto = record.get("proto", "").lower()
                resp_port_str = record.get("id.resp_p", "0")
                try:
                    resp_port = int(resp_port_str) if resp_port_str != "-" else 0
                except ValueError:
                    resp_port = 0

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
                            asyncio.create_task(register_device(client, src_ip))
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

                        asyncio.create_task(register_device(client, src_ip))
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

                # --- Evict stale IP mappings before further checks ---
                if resp_ip in _known_ips:
                    _, _, _learned = _known_ips[resp_ip]
                    if (time.time() - _learned) > IP_TTL_SECONDS:
                        del _known_ips[resp_ip]

                # --- Heuristic VPN detection ---
                # Large single-connection to an unknown external IP (not a known
                # AI/Cloud service) hints at an encrypted tunnel.
                # Skip if Zeek's DPD already identified a known safe protocol.
                h_services = {s.strip().lower() for s in service_field.split(",")} if service_field and service_field != "-" else set()
                h_has_safe_svc = bool(h_services & HEURISTIC_VPN_SAFE_SERVICES)
                if (
                    _is_local_ip(src_ip)
                    and resp_ip
                    and resp_ip not in _known_ips
                    and not _is_local_ip(resp_ip)
                    and not h_has_safe_svc  # DPD says it's a known protocol → not a VPN
                ):
                    try:
                        h_ob = record.get("orig_bytes", "0")
                        h_orig = int(h_ob) if h_ob and h_ob != "-" else 0
                    except ValueError:
                        h_orig = 0
                    try:
                        h_rb = record.get("resp_bytes", "0")
                        h_resp = int(h_rb) if h_rb and h_rb != "-" else 0
                    except ValueError:
                        h_resp = 0
                    h_total = h_orig + h_resp

                    if h_total >= HEURISTIC_VPN_BYTE_THRESHOLD:
                        now = time.time()
                        h_key = (src_ip, resp_ip)
                        h_last = _heuristic_vpn_seen.get(h_key, 0)
                        if (now - h_last) >= HEURISTIC_VPN_DEDUP_SECONDS:
                            _heuristic_vpn_seen[h_key] = now
                            asyncio.create_task(register_device(client, src_ip))
                            await send_event(
                                client,
                                detection_type="vpn_tunnel",
                                ai_service="vpn_active",
                                source_ip=src_ip,
                                bytes_transferred=h_total,
                                category="tracking",
                            )
                            print(
                                f"    └─ Heuristic VPN: large encrypted flow "
                                f"to {resp_ip}:{resp_port} ({proto.upper()}) "
                                f"from {src_ip} — {h_total/1024/1024:,.1f} MB"
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
    "ayiya":      "vpn_ayiya_tunnel",   # IPv6-in-IPv4 tunnel
    "teredo":     "vpn_teredo_tunnel",  # IPv6-in-IPv4 tunnel
    "dtls":       "vpn_dtls_tunnel",    # DTLS can indicate VPN (e.g. AnyConnect)
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
                    if hostname:
                        payload["hostname"] = hostname

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
# Entrypoint
# ---------------------------------------------------------------------------

async def main(zeek_log_dir: str) -> None:
    log_dir = Path(zeek_log_dir)
    ssl_log = log_dir / "ssl.log"
    conn_log = log_dir / "conn.log"
    dhcp_log = log_dir / "dhcp.log"

    print(f"[*] AI-Radar Zeek Tailer starting on host '{SENSOR_ID}'")
    print(f"[*] Reporting to API at {API_URL}")
    print(f"[*] Monitoring {len(DOMAIN_MAP)} domains (AI + Cloud)")
    print(f"[*] Upload threshold: {UPLOAD_THRESHOLD_BYTES:,} bytes")
    print(f"[*] Upload debounce window: {UPLOAD_DEBOUNCE_SECONDS}s")
    print(f"[*] DHCP passive device recognition: enabled")
    print(f"[*] DPD stealth VPN/Tor detection: enabled ({len(DPD_EVASION_PROTOCOLS)} protocols)")
    print(f"[*] Zeek log directory: {log_dir}")

    # p0f passive OS fingerprinting — tail existing p0f log file
    p0f_task = None
    try:
        from p0f_tailer import tail_p0f_standalone, P0F_LOG_FILE
        p0f_log = Path(P0F_LOG_FILE)
        p0f_task = tail_p0f_standalone(p0f_log)
        print(f"[*] p0f passive OS fingerprinting: enabled (tailing {p0f_log})")
        print(f"[*]   Start p0f separately: sudo p0f -i en0 -f /opt/homebrew/etc/p0f/p0f.fp -o {p0f_log} -p")
    except ImportError:
        print(f"[*] p0f passive OS fingerprinting: disabled (p0f_tailer not found)")
    except Exception as exc:
        print(f"[*] p0f passive OS fingerprinting: disabled ({exc})")

    print()

    tasks = [
        tail_ssl_log(ssl_log, client := httpx.AsyncClient()),
        tail_conn_log(conn_log, client),
        tail_dhcp_log(dhcp_log, client),
        flush_upload_buckets(client),  # background flusher
    ]
    if p0f_task is not None:
        tasks.append(p0f_task)

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
