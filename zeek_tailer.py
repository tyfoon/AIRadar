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

API_URL = "http://localhost:8000/api/ingest"
DEVICE_API_URL = "http://localhost:8000/api/devices"
SENSOR_ID = socket.gethostname()

# Volumetric upload threshold (bytes)
UPLOAD_THRESHOLD_BYTES = 100_000  # 100 KB

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


def _resolve_mac(ip: str) -> str | None:
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
                        return mac.lower()
                if p == "ether" and i + 1 < len(parts):
                    return parts[i + 1].lower()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


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

# Maps destination IP → (service, category) — learned from ssl.log SNI
_known_ips: dict[str, tuple[str, str]] = {}

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

                # Learn this destination IP for conn.log correlation
                if resp_ip and resp_ip != "-":
                    _known_ips[resp_ip] = (service, category)

                # Register the device if it's a local source
                asyncio.create_task(register_device(client, src_ip))

                # Parse bytes for the event
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

                # Check if destination IP is a known AI/Cloud service
                resp_ip = record.get("id.resp_h", "")
                if resp_ip not in _known_ips:
                    continue

                service, category = _known_ips[resp_ip]
                src_ip = record.get("id.orig_h", "unknown")

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
# Entrypoint
# ---------------------------------------------------------------------------

async def main(zeek_log_dir: str) -> None:
    log_dir = Path(zeek_log_dir)
    ssl_log = log_dir / "ssl.log"
    conn_log = log_dir / "conn.log"

    print(f"[*] AI-Radar Zeek Tailer starting on host '{SENSOR_ID}'")
    print(f"[*] Reporting to API at {API_URL}")
    print(f"[*] Monitoring {len(DOMAIN_MAP)} domains (AI + Cloud)")
    print(f"[*] Upload threshold: {UPLOAD_THRESHOLD_BYTES:,} bytes")
    print(f"[*] Upload debounce window: {UPLOAD_DEBOUNCE_SECONDS}s")
    print(f"[*] Zeek log directory: {log_dir}")
    print()

    async with httpx.AsyncClient() as client:
        await asyncio.gather(
            tail_ssl_log(ssl_log, client),
            tail_conn_log(conn_log, client),
            flush_upload_buckets(client),  # background flusher
        )


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
