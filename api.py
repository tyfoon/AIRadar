"""
AI-Radar — FastAPI server.
Exposes endpoints for ingesting and querying detection events (AI + Cloud),
managing discovered devices, analytics, and AdGuard Home privacy stats.
"""

import asyncio
import csv
import io
import json
import os
import re
import socket
import time


# ---------------------------------------------------------------------------
# IPv6-safe socket resolver
# ---------------------------------------------------------------------------
# The container uses host networking on a LAN that has global IPv6 but no
# working upstream IPv6 route to the broader internet. Python's default
# getaddrinfo() returns AAAA records first for dual-stack hosts like
# generativelanguage.googleapis.com, and httpx / httpcore / google-genai
# then try to connect() over IPv6 — which silently hangs until the kernel
# TCP timeout fires (~2 minutes). urllib in the stdlib handles this
# slightly differently and still works, but all httpx-based clients
# inherit the bug.
#
# Fix: monkey-patch getaddrinfo to strip IPv6 results, so every outbound
# socket.connect() goes directly to the IPv4 A record. This affects ALL
# httpx / aiohttp / requests / google-genai traffic in-process, but the
# tradeoff is worth it — the app only talks to external APIs (Gemini,
# AdGuard, itself) over IPv4 anyway, and IPv6 was causing 120-second
# hangs on Gemini calls.
_ORIG_GETADDRINFO = socket.getaddrinfo


def _ipv4_only_getaddrinfo(host, *args, **kwargs):
    results = _ORIG_GETADDRINFO(host, *args, **kwargs)
    filtered = [r for r in results if r[0] == socket.AF_INET]
    return filtered or results  # fallback to IPv6 if no IPv4 exists


if os.environ.get("AIRADAR_DISABLE_IPV6_FALLBACK") != "1":
    socket.getaddrinfo = _ipv4_only_getaddrinfo
    print("[net] IPv4-only getaddrinfo patch active (outbound httpx/SDK calls forced to IPv4)")

# Auto-load .env so credentials work regardless of how the server is started.
# First try python-dotenv; if not installed, fall back to a simple manual parser.
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
try:
    from dotenv import load_dotenv
    load_dotenv(_env_path)
except ImportError:
    # python-dotenv not available (e.g. system Python 3.9) — parse .env manually
    if os.path.isfile(_env_path):
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _key, _, _val = _line.partition("=")
                _key = _key.strip()
                _val = _val.strip().strip('"').strip("'")
                if _key and _key not in os.environ:  # don't overwrite explicit env
                    os.environ[_key] = _val
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Integer, func, text
from sqlalchemy.orm import Session

from adguard_client import AdGuardClient
from beacon_analyzer import run_beacon_analysis
from database import (
    AlertException,
    BlockRule,
    DetectionEvent,
    Device,
    DeviceBaseline,
    DeviceGroup,
    DeviceGroupMember,
    DeviceIP,
    GeoTraffic,
    GeoConversation,
    IpMetadata,
    InboundAttack,
    KnownDomain,
    NetworkPerformance,
    NotificationConfig,
    ServicePolicy,
    SessionLocal,
    TlsFingerprint,
    init_db,
)

# MAC Vendor lookup — sync dict-based OUI lookup (avoids async issues with MacLookup)
_oui_db: dict[str, str] = {}
try:
    from mac_vendor_lookup import BaseMacLookup
    _vendor_file = BaseMacLookup().find_vendors_list()
    if _vendor_file:
        with open(_vendor_file) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and ":" in _line:
                    _prefix, _vendor = _line.split(":", 1)
                    _oui_db[_prefix.strip().upper()] = _vendor.strip()
        print(f"[vendor] Loaded {len(_oui_db):,} OUI entries")
except Exception as exc:
    print(f"[vendor] Could not load OUI database: {exc}")


# ── Hostname → vendor mapping ──────────────────────────────────────────────
# Loaded from a JSON file so users can extend it without touching code.
# Falls back to a built-in default if the file doesn't exist yet.
_HOSTNAME_VENDORS_FILE = os.path.join(os.path.dirname(__file__), "data", "hostname_vendors.json")

_HOSTNAME_VENDORS_DEFAULT: list[dict] = [
    {"keywords": ["macbook", "imac", "iphone", "ipad", "apple", "airpods"], "vendor": "Apple Inc."},
    {"keywords": ["ubiquiti", "unifi"], "vendor": "Ubiquiti Inc"},
    {"keywords": ["samsung", "galaxy"], "vendor": "Samsung Electronics"},
    {"keywords": ["ds-2cd", "hikvision"], "vendor": "Hikvision"},
    {"keywords": ["android", "pixel"], "vendor": "Google Inc."},
    {"keywords": ["kobo"], "vendor": "Kobo Inc."},
    {"keywords": ["smartgateway", "watermeter"], "vendor": "Smart Gateways B.V."},
    {"keywords": ["sonos"], "vendor": "Sonos Inc."},
    {"keywords": ["philips", "hue"], "vendor": "Signify (Philips)"},
    {"keywords": ["ring", "doorbell"], "vendor": "Ring LLC"},
    {"keywords": ["nest"], "vendor": "Google Nest"},
    {"keywords": ["tplink", "tp-link", "tapo", "kasa"], "vendor": "TP-Link"},
    {"keywords": ["synology", "diskstation"], "vendor": "Synology Inc."},
    {"keywords": ["qnap"], "vendor": "QNAP Systems"},
    {"keywords": ["roku"], "vendor": "Roku Inc."},
    {"keywords": ["chromecast"], "vendor": "Google Inc."},
    {"keywords": ["xbox"], "vendor": "Microsoft"},
    {"keywords": ["playstation", "ps5", "ps4"], "vendor": "Sony Interactive"},
    {"keywords": ["nintendo", "switch"], "vendor": "Nintendo"},
    {"keywords": ["ecobee", "tado"], "vendor": "Smart Thermostat"},
    {"keywords": ["roomba", "irobot"], "vendor": "iRobot"},
    {"keywords": ["dyson"], "vendor": "Dyson"},
    {"keywords": ["tesla", "teslafi"], "vendor": "Tesla Inc."},
    {"keywords": ["brother", "hl-", "mfc-", "dcp-"], "vendor": "Brother Industries"},
    {"keywords": ["hp-", "hpprinter", "envy", "officejet", "laserjet"], "vendor": "HP Inc."},
    {"keywords": ["canon", "pixma"], "vendor": "Canon Inc."},
    {"keywords": ["epson"], "vendor": "Seiko Epson"},
    {"keywords": ["daikin"], "vendor": "Daikin"},
    {"keywords": ["shelly"], "vendor": "Shelly (Allterco)"},
    {"keywords": ["tuya", "smartlife"], "vendor": "Tuya Inc."},
    {"keywords": ["ikea", "tradfri", "dirigera"], "vendor": "IKEA"},
    {"keywords": ["fritz", "fritzbox"], "vendor": "AVM GmbH (Fritz!)"},
    {"keywords": ["netgear", "orbi"], "vendor": "Netgear"},
    {"keywords": ["asus", "rt-ax", "rt-ac"], "vendor": "ASUSTeK"},
    {"keywords": ["linksys", "velop"], "vendor": "Linksys (Belkin)"},
]

def _load_hostname_vendors() -> list[dict]:
    """Load hostname→vendor mappings from JSON file, or create it from defaults."""
    try:
        if os.path.exists(_HOSTNAME_VENDORS_FILE):
            with open(_HOSTNAME_VENDORS_FILE) as f:
                data = json.load(f)
                if isinstance(data, list) and data:
                    return data
    except Exception:
        pass
    # Write default file so user can edit it
    try:
        os.makedirs(os.path.dirname(_HOSTNAME_VENDORS_FILE), exist_ok=True)
        with open(_HOSTNAME_VENDORS_FILE, "w") as f:
            json.dump(_HOSTNAME_VENDORS_DEFAULT, f, indent=2)
        print(f"[vendor] Created editable hostname map: {_HOSTNAME_VENDORS_FILE}")
    except Exception:
        pass
    return _HOSTNAME_VENDORS_DEFAULT

_hostname_vendors: list[dict] = _load_hostname_vendors()


# ---------------------------------------------------------------------------
# Hostname sanitization — reject junk values from mDNS/DHCP tailers.
# Must match the helper in zeek_tailer.py so both ends agree on what's junk.
# ---------------------------------------------------------------------------
_JUNK_HOSTNAME_LITERALS = {
    "", "(empty)", "(null)", "null", "none", "unknown",
    "localhost", "localhost.localdomain",
    "espressif", "esp32", "esp8266", "esp-device",
}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX_ID_RE = re.compile(r"^[0-9a-f]{16,}$")


# ---------------------------------------------------------------------------
# JA4 TLS fingerprint → friendly label resolver
# ---------------------------------------------------------------------------
# JA4 format: <proto><tls_ver><sni><alpn><ciphers><ext>_<cipher_hash>_<ext_hash>
# The first "a-part" before the first underscore is the most stable part
# and encodes the TLS client profile. We match on either the full hash
# (exact) or the a-part prefix (family match).
#
# Seed list hand-curated from public Wireshark/foxio samples. Users can
# extend via the /api/ja4-labels endpoint (TODO) or the JSON file.
_JA4_EXACT_LABELS: dict[str, str] = {
    # Chrome desktop (recent versions)
    "t13d1516h2_8daaf6152771_02713d6af862": "Chrome",
    "t13d1517h2_8daaf6152771_b0da82dd1658": "Chrome",
    # Firefox
    "t13d1715h2_5b57614c22b0_3d5424432f57": "Firefox",
    "t13d1715h1_5b57614c22b0_93c746dc12af": "Firefox",
    # Safari macOS / iOS
    "t13d2014h2_a09f3c656075_14788d8d241b": "Safari (Apple)",
    # cURL
    "t13d3112h2_e8f1e7e78f70_1f3f5c5c2e8e": "curl",
    # Go HTTP client
    "t13d1715h1_9313f49636e6_db1a0dc7fd7c": "Go http client",
    # Python requests / urllib3
    "t13d591100_ba7ebdd8f9d7_6aee39d76e4b": "Python requests",
}

# Match on the "a-part" prefix (everything before first `_`). This catches
# the whole family of a TLS client even when the cipher order drifts.
_JA4_PREFIX_LABELS: list[tuple[str, str]] = [
    # Apple: t13d2014h2 = TLS 1.3, SNI, h2 ALPN, 20 ciphers, 14 extensions
    ("t13d2014h2", "Apple device (Safari/iOS)"),
    ("t13d1517h2", "Apple app / Chrome-based"),
    # Chrome family (Chromium, Edge, Brave, modern Electron apps)
    ("t13d1516h2", "Chromium-based browser"),
    ("t13d1517h1", "Chromium-based app (HTTP/1.1)"),
    # Firefox family
    ("t13d1715h2", "Firefox"),
    # Apple Lockdown / MDM agents / System daemons
    ("t13d1313h2", "Apple system daemon"),
    ("t13d1512h2", "Apple Mail / Messages"),
    # Go libraries (many IoT devices, Docker, Kubernetes, Grafana Agent)
    ("t13d1715h1", "Go HTTP client"),
    # Python
    ("t13d591100",  "Python requests/urllib3"),
    ("t13d301000",  "Python httpx/aiohttp"),
    # Java
    ("t13d311100",  "Java HttpsURLConnection"),
    # Node.js
    ("t13d1411h2",  "Node.js TLS client"),
    # Minimal embedded TLS stacks (ESP32, Arduino, IoT firmware)
    ("t13d060200",  "Embedded TLS (ESP/Arduino)"),
    ("t13d070300",  "Embedded TLS (mbedTLS/IoT)"),
    ("t13d080500",  "Embedded TLS (IoT firmware)"),
    # TLS 1.2 legacy clients (older smart TVs, consoles, printers)
    ("t12d310600",  "Legacy TLS 1.2 client"),
    ("t12d311000",  "Legacy TLS 1.2 (smart TV/console)"),
    # QUIC (HTTP/3)
    ("q13d1516h3",  "Chromium-based (HTTP/3)"),
    ("q13d2014h3",  "Apple device (HTTP/3)"),
]


def _resolve_ja4_label(ja4: Optional[str]) -> Optional[str]:
    """Resolve a JA4 TLS fingerprint to a human label.

    Priority: exact hash match > a-part prefix match. Returns None when
    the fingerprint is unknown — callers should fall back to vendor/MAC.
    """
    if not ja4 or not isinstance(ja4, str):
        return None
    ja4 = ja4.strip()
    if not ja4:
        return None
    # Exact full-hash match (most precise)
    if ja4 in _JA4_EXACT_LABELS:
        return _JA4_EXACT_LABELS[ja4]
    # Prefix match on the a-part (before first underscore)
    a_part = ja4.split("_", 1)[0]
    for prefix, label in _JA4_PREFIX_LABELS:
        if a_part == prefix:
            return label
    return None


def _is_junk_hostname(name) -> bool:
    """True if a hostname is meaningless (UUID, hex ID, reverse-DNS, placeholder)."""
    if name is None or not isinstance(name, str):
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


def _resolve_vendor(mac: Optional[str] = None, hostname: Optional[str] = None) -> Optional[str]:
    """Look up the hardware vendor from a MAC address and/or hostname.

    Priority: hostname keyword match > OUI database.
    Hostname is more specific (e.g. "MACBOOK" → Apple) and catches cases
    where the OUI prefix has been reassigned or is shared across vendors.
    """
    # Layer 1: hostname keyword matching (user-editable JSON, most specific)
    if hostname:
        hn = hostname.lower()
        for entry in _hostname_vendors:
            if any(kw in hn for kw in entry.get("keywords", [])):
                return entry["vendor"]
    # Layer 2: OUI database (39k+ manufacturers by MAC prefix)
    if mac and _oui_db and not mac.startswith("unknown_"):
        try:
            # Re-pad each octet to 2 hex digits before concatenating,
            # because _normalize_mac strips leading zeros (e.g. "2:a:6d" → "020A6D")
            parts = mac.upper().replace("-", ":").replace(".", ":").split(":")
            clean = "".join(p.zfill(2) for p in parts)
            vendor = _oui_db.get(clean[:6])
            if vendor:
                return vendor
        except Exception:
            pass
    return None


from schemas import (
    ActiveAlert,
    AlertExceptionCreate,
    AlertExceptionRead,
    BlockRuleCreate,
    BlockRuleRead,
    BlockRuleUnblock,
    DeviceRead,
    DeviceRegister,
    DeviceUpdate,
    EventCreate,
    EventRead,
    GlobalFilterToggle,
    PrivacyStats,
    ServicePolicyCreate,
    ServicePolicyRead,
    TimelineBucket,
)

STATIC_DIR = Path(__file__).parent / "static"

# AdGuard Home client (configure port as needed)
adguard = AdGuardClient(base_url=os.environ.get("ADGUARD_URL", "http://127.0.0.1:3001"))

# ---------------------------------------------------------------------------
# Data retention settings
# ---------------------------------------------------------------------------
RETENTION_DAYS = 7          # Keep events for 7 days
MAX_EVENTS = 50_000         # Hard cap on total events
CLEANUP_INTERVAL = 3600     # Run cleanup every hour (seconds)
DB_PATH = Path(__file__).parent / "airadar.db"
MAX_DB_SIZE_MB = 500        # Warn/compact if DB exceeds this


async def _periodic_cleanup():
    """Background task: prune old events and compact the database."""
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL)
        try:
            db = SessionLocal()

            # 1) Delete events older than RETENTION_DAYS
            cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
            old = db.query(DetectionEvent).filter(
                DetectionEvent.timestamp < cutoff
            ).delete(synchronize_session=False)

            # 2) If still over MAX_EVENTS, delete oldest
            total = db.query(func.count(DetectionEvent.id)).scalar() or 0
            overflow = 0
            if total > MAX_EVENTS:
                overflow_ids = (
                    db.query(DetectionEvent.id)
                    .order_by(DetectionEvent.timestamp.asc())
                    .limit(total - MAX_EVENTS)
                    .all()
                )
                ids = [r[0] for r in overflow_ids]
                if ids:
                    db.query(DetectionEvent).filter(
                        DetectionEvent.id.in_(ids)
                    ).delete(synchronize_session=False)
                    overflow = len(ids)

            # 3) Prune old performance snapshots (keep 7 days)
            perf_cutoff = datetime.utcnow() - timedelta(days=7)
            old_perf = db.query(NetworkPerformance).filter(
                NetworkPerformance.timestamp < perf_cutoff
            ).delete(synchronize_session=False)

            # 4) Prune old geo_conversations (keep 30 days)
            geo_cutoff = datetime.utcnow() - timedelta(days=30)
            old_geo = db.query(GeoConversation).filter(
                GeoConversation.last_seen < geo_cutoff
            ).delete(synchronize_session=False)

            # 5) Prune stale ip_metadata (not updated in 30 days)
            ip_cutoff = datetime.utcnow() - timedelta(days=30)
            old_ip = db.query(IpMetadata).filter(
                IpMetadata.updated_at < ip_cutoff
            ).delete(synchronize_session=False)

            # 6) Prune old tls_fingerprints (not seen in 30 days)
            tls_cutoff = datetime.utcnow() - timedelta(days=30)
            old_tls = db.query(TlsFingerprint).filter(
                TlsFingerprint.last_seen < tls_cutoff
            ).delete(synchronize_session=False)

            # 7) Remove expired alert_exceptions
            old_alerts = db.query(AlertException).filter(
                AlertException.expires_at.isnot(None),
                AlertException.expires_at < datetime.utcnow(),
            ).delete(synchronize_session=False)

            # 8) Prune old inbound_attacks (keep 7 days)
            inbound_cutoff = datetime.utcnow() - timedelta(days=7)
            old_inbound = db.query(InboundAttack).filter(
                InboundAttack.last_seen < inbound_cutoff
            ).delete(synchronize_session=False)

            db.commit()

            remaining = db.query(func.count(DetectionEvent.id)).scalar() or 0
            db.close()

            pruned_extras = old_perf + old_geo + old_ip + old_tls + old_alerts + old_inbound
            if pruned_extras > 0:
                print(
                    f"[cleanup] Pruned: {old_perf} perf, {old_geo} geo_conv, "
                    f"{old_ip} ip_meta, {old_tls} tls_fp, {old_alerts} expired alerts"
                )

            # 8) VACUUM to reclaim disk space (runs outside SQLAlchemy session)
            if old > 0 or overflow > 0 or pruned_extras > 0:
                from sqlalchemy import create_engine, text
                engine = create_engine(f"sqlite:///{DB_PATH}")
                with engine.connect() as conn:
                    conn.execute(text("VACUUM"))
                engine.dispose()

            # 9) Log cleanup results
            db_size_mb = DB_PATH.stat().st_size / (1024 * 1024) if DB_PATH.exists() else 0
            if old > 0 or overflow > 0:
                print(
                    f"[cleanup] Removed {old} old + {overflow} overflow events. "
                    f"Remaining: {remaining}. DB size: {db_size_mb:.1f} MB"
                )

        except Exception as exc:
            print(f"[cleanup] Error: {exc}")


RULE_EXPIRY_INTERVAL = 60  # Check expired rules every 60 seconds
BEACON_SCAN_INTERVAL = 3600  # Run beaconing detection hourly after the first pass
BEACON_WARMUP_SECONDS = 90    # Delay before the first scan so Zeek has data
BEACON_DEDUP_HOURS = 24       # Don't re-alert the same src→dst pair within 24h

# Live status of the beacon scanner, surfaced by /api/privacy/stats so
# the frontend can show "Last scanned HH:MM · N threats" instead of a
# mystery empty panel.
_beacon_status: dict = {
    "running": False,
    "last_scan_at": None,     # ISO timestamp of the last completed scan
    "last_findings": 0,        # number of beacon patterns found in the last scan
    "last_new_alerts": 0,      # new rows written to detection_events
    "scans_completed": 0,
    "last_error": None,
}


async def _periodic_beacon_scan():
    """Background task: scan Zeek conn.log for malware C2 beacons.

    Runs once ~90s after container startup (giving Zeek time to produce
    conn.log data), then every hour thereafter. Findings are stored as
    DetectionEvent rows with detection_type='beaconing_threat' and
    category='security'. Dedup logic skips any (src, dst) pair that
    already has a beacon alert in the last 24 hours, so we don't spam
    the alerts list when a C2 keeps running for days.

    Status is tracked in _beacon_status so the frontend can show the
    user that the scanner is alive and when it last ran — critical on
    a clean home network where the correct result is "0 threats" but
    a blank panel otherwise looks like a broken feature.
    """
    # Warmup: let Zeek's conn.log accumulate some data before the first
    # scan. Without this, a rebuild-and-immediately-check workflow sees
    # an empty conn.log and thinks the feature is broken.
    await asyncio.sleep(BEACON_WARMUP_SECONDS)

    while True:
        _beacon_status["running"] = True
        try:
            findings = await run_beacon_analysis()
            new_count = 0
            if findings:
                db = SessionLocal()
                try:
                    cutoff = datetime.utcnow() - timedelta(hours=BEACON_DEDUP_HOURS)
                    for f in findings:
                        already = (
                            db.query(DetectionEvent.id)
                            .filter(
                                DetectionEvent.detection_type == "beaconing_threat",
                                DetectionEvent.source_ip == f["src"],
                                DetectionEvent.ai_service == f["dst"],
                                DetectionEvent.timestamp >= cutoff,
                            )
                            .first()
                        )
                        if already:
                            continue

                        event = DetectionEvent(
                            sensor_id="airadar",
                            timestamp=datetime.utcnow(),
                            detection_type="beaconing_threat",
                            ai_service=f["dst"],        # destination IP lives here
                            source_ip=f["src"],
                            category="security",
                            bytes_transferred=0,
                            possible_upload=False,
                        )
                        db.add(event)
                        new_count += 1
                        print(
                            f"[beacon] 🚨 THREAT: {f['src']} → {f['dst']}:{f['port']}/{f['proto']} "
                            f"every {f['mean_interval_s']}s (±{f['stddev_s']}s, n={f['connection_count']})"
                        )
                    if new_count:
                        db.commit()
                        print(f"[beacon] {new_count} new beacon alert(s) recorded")
                    else:
                        print(f"[beacon] Scan complete — {len(findings)} pattern(s) found, all already alerted")
                finally:
                    db.close()
            else:
                print("[beacon] Scan complete — no beaconing patterns detected")

            _beacon_status["last_scan_at"] = datetime.utcnow().isoformat()
            _beacon_status["last_findings"] = len(findings)
            _beacon_status["last_new_alerts"] = new_count
            _beacon_status["scans_completed"] += 1
            _beacon_status["last_error"] = None
        except Exception as exc:
            _beacon_status["last_error"] = f"{type(exc).__name__}: {exc}"
            print(f"[beacon] Scan error: {exc}")
        finally:
            _beacon_status["running"] = False

        await asyncio.sleep(BEACON_SCAN_INTERVAL)


async def _expire_block_rules():
    """Background task: unblock services whose temporary rules have expired."""
    while True:
        await asyncio.sleep(RULE_EXPIRY_INTERVAL)
        try:
            db = SessionLocal()
            now = datetime.utcnow()

            # Find active rules that have expired
            expired = (
                db.query(BlockRule)
                .filter(
                    BlockRule.is_active == True,
                    BlockRule.expires_at != None,
                    BlockRule.expires_at <= now,
                )
                .all()
            )

            for rule in expired:
                # Unblock in AdGuard
                ok = await adguard.unblock_domain(rule.domain)
                rule.is_active = False
                status = "ok" if ok else "AdGuard error"
                print(
                    f"[rules] Expired: {rule.service_name} ({rule.domain}) "
                    f"— unblocked ({status})"
                )

            if expired:
                db.commit()

            db.close()
        except Exception as exc:
            print(f"[rules] Expiry check error: {exc}")


POLICY_EXPIRY_INTERVAL = 60  # Check every 60 seconds


async def _expire_service_policies():
    """Background task: delete expired ServicePolicy rows and unblock
    any AdGuard domains they were blocking.

    When a time-limited policy expires, the system reverts to default
    behavior (no policy = allow for standard traffic, alert for AI).
    """
    while True:
        await asyncio.sleep(POLICY_EXPIRY_INTERVAL)
        try:
            db = SessionLocal()
            now = datetime.utcnow()
            expired = (
                db.query(ServicePolicy)
                .filter(
                    ServicePolicy.expires_at != None,   # noqa: E711
                    ServicePolicy.expires_at <= now,
                )
                .all()
            )
            for policy in expired:
                # If the expired policy was blocking, lift the block in AdGuard
                if (
                    policy.action == "block"
                    and policy.scope == "global"
                    and policy.service_name
                ):
                    info = SERVICE_DOMAINS.get(policy.service_name)
                    if info:
                        for domain in info.get("domains", []):
                            try:
                                await adguard.unblock_domain(domain)
                            except Exception as exc:
                                print(f"[policy-expiry] AdGuard unblock {domain}: {exc}")
                print(
                    f"[policy-expiry] Expired: {policy.service_name or policy.category} "
                    f"({policy.action}) for {'device ' + policy.mac_address if policy.mac_address else 'global'}"
                )
                db.delete(policy)
            if expired:
                db.commit()
                print(f"[policy-expiry] Cleaned up {len(expired)} expired policies")
            db.close()
        except Exception as exc:
            print(f"[policy-expiry] Error: {exc}")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
def _backfill_vendors():
    """One-time vendor backfill for devices that are missing vendor info."""
    db = SessionLocal()
    try:
        devices = db.query(Device).filter(
            (Device.vendor == None) | (Device.vendor == "")  # noqa: E711
        ).all()
        updated = 0
        for dev in devices:
            vendor = _resolve_vendor(dev.mac_address, dev.hostname)
            if vendor:
                dev.vendor = vendor
                updated += 1
        if updated:
            db.commit()
            print(f"[backfill] Resolved vendor for {updated}/{len(devices)} devices")
        else:
            print(f"[backfill] No vendor updates needed ({len(devices)} devices checked)")
    except Exception as exc:
        print(f"[backfill] Error: {exc}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
def _cleanup_junk_hostnames():
    """One-shot sweep on startup: null out junk hostnames and hostname
    collisions left by the earlier too-aggressive mDNS overwrite logic.

    1. Any hostname matching a junk pattern (UUID, hex ID, *.arpa, etc.)
       is nulled.
    2. When the same hostname is attached to multiple MACs and the MAC
       suffix of one of them matches the hostname suffix (e.g. MAC
       24:6f:28:49:63:f0 → hostname "slide-246f284963f0"), keep that
       match and null the others — they got polluted via a stale
       ip→mac lookup.

    display_name is never touched.
    """
    db = SessionLocal()
    try:
        cleared = 0
        # Step 1: junk hostnames
        for dev in db.query(Device).filter(Device.hostname.isnot(None)).all():
            if _is_junk_hostname(dev.hostname):
                print(f"[cleanup] Nulling junk hostname '{dev.hostname}' on {dev.mac_address}")
                dev.hostname = None
                cleared += 1

        # Step 2: hostname collisions (same hostname on multiple MACs).
        # Keep the device whose MAC suffix appears in the hostname, or
        # the first-seen one if no MAC matches.
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for dev in db.query(Device).filter(Device.hostname.isnot(None)).all():
            groups[dev.hostname.lower()].append(dev)
        for hostname, devs in groups.items():
            if len(devs) < 2:
                continue
            # Find the device whose MAC (without colons) appears in the hostname
            host_nocolon = hostname.replace("-", "").replace("_", "").replace(":", "")
            best = None
            for dev in devs:
                mac_flat = dev.mac_address.replace(":", "").lower()
                if mac_flat and mac_flat in host_nocolon:
                    best = dev
                    break
            # If no MAC match, keep the earliest first_seen
            if best is None:
                best = min(devs, key=lambda d: d.first_seen or datetime.max)
            for dev in devs:
                if dev.mac_address != best.mac_address:
                    print(f"[cleanup] Hostname collision: nulling '{dev.hostname}' on {dev.mac_address} (kept on {best.mac_address})")
                    dev.hostname = None
                    cleared += 1

        if cleared:
            db.commit()
            print(f"[cleanup] Cleared {cleared} hostname entries")
    except Exception as exc:
        print(f"[cleanup] Junk hostname sweep failed: {exc}")
    finally:
        db.close()


def _cleanup_empty_sentinel_strings():
    """One-shot sweep: replace Zeek '(empty)' sentinel strings with NULL.

    Early Phase 1 data collection stored Zeek's literal '(empty)' string
    when a field was present-but-blank. Normalise to NULL so that tuple
    dedup works properly (otherwise the same logical (ja4, ja4s, sni)
    gets split into two rows).
    """
    db = SessionLocal()
    try:
        from sqlalchemy import update, or_
        fixed = 0

        # tls_fingerprints table
        for col in ("ja4", "ja4s", "sni"):
            stmt = text(
                f"UPDATE tls_fingerprints SET {col} = NULL "
                f"WHERE {col} IN ('(empty)', '-', '')"
            )
            result = db.execute(stmt)
            fixed += result.rowcount

        # devices table
        for col in ("dhcp_vendor_class", "dhcp_fingerprint", "ja4_fingerprint"):
            stmt = text(
                f"UPDATE devices SET {col} = NULL "
                f"WHERE {col} IN ('(empty)', '-', '')"
            )
            result = db.execute(stmt)
            fixed += result.rowcount

        if fixed:
            db.commit()
            print(f"[cleanup] Normalised {fixed} Zeek '(empty)' sentinel string(s) to NULL")

        # Also collapse duplicate tls_fingerprints rows that differ only in
        # NULL vs '(empty)'. After the UPDATE above we may now have two rows
        # with the exact same (mac, ja4, ja4s, sni) — merge their hit_counts.
        dupes = db.execute(text("""
            SELECT mac_address, ja4, ja4s, sni, MIN(id), SUM(hit_count), MIN(first_seen), MAX(last_seen), COUNT(*)
            FROM tls_fingerprints
            GROUP BY mac_address, ja4, ja4s, sni
            HAVING COUNT(*) > 1
        """)).fetchall()
        for row in dupes:
            mac, ja4, ja4s, sni, keep_id, total_hits, first_seen, last_seen, _n = row
            # Update the kept row with merged counts
            db.execute(text("""
                UPDATE tls_fingerprints
                SET hit_count = :hits, first_seen = :fs, last_seen = :ls
                WHERE id = :id
            """), {"hits": total_hits, "fs": first_seen, "ls": last_seen, "id": keep_id})
            # Delete the others
            db.execute(text("""
                DELETE FROM tls_fingerprints
                WHERE mac_address = :mac
                  AND (ja4 IS :ja4 OR ja4 = :ja4)
                  AND (ja4s IS :ja4s OR ja4s = :ja4s)
                  AND (sni IS :sni OR sni = :sni)
                  AND id != :id
            """), {"mac": mac, "ja4": ja4, "ja4s": ja4s, "sni": sni, "id": keep_id})
        if dupes:
            db.commit()
            print(f"[cleanup] Merged {len(dupes)} duplicate TLS fingerprint tuple(s)")
    except Exception as exc:
        print(f"[cleanup] Empty-string sweep failed: {exc}")
    finally:
        db.close()


def _normalize_mac_addresses():
    """One-shot startup sweep: re-pad any MAC addresses that were stored
    without leading zeros (e.g. 'a2:c0:6d:40:7:f7' → 'a2:c0:6d:40:07:f7').

    Handles three cases:
    1. Simple rename: old non-padded MAC → new padded MAC (no conflict).
    2. Merge: both old and new MAC exist as separate devices — merge them,
       keeping the richer record (hostname, vendor, earliest first_seen).
    3. Destination column in alert_exceptions also stores MACs for
       new_device alerts.
    """
    db = SessionLocal()
    try:
        # Disable FK checks for SQLite so we can freely update PKs
        db.execute(text("PRAGMA foreign_keys = OFF"))

        # Tables with unique constraints involving mac_address — must
        # delete old rows to avoid IntegrityError during merge/rename.
        delete_tables = ["device_baselines", "tls_fingerprints",
                         "geo_conversations", "device_group_members",
                         "service_policies"]
        # device_ips handled specially (drop conflicting IPs, move rest)

        # Find all MACs in devices table that need fixing
        all_devices = db.execute(text(
            "SELECT mac_address, hostname, vendor, display_name, "
            "       first_seen, last_seen FROM devices"
        )).fetchall()

        # Group by normalized MAC to detect duplicates AND renames
        from collections import defaultdict
        groups = defaultdict(list)
        for row in all_devices:
            mac = row[0]
            if not mac or mac.startswith("unknown_"):
                continue
            norm = _normalize_mac(mac)
            groups[norm].append(row)

        fixed = 0
        merged = 0

        def _move_mac_refs(old_mac, new_mac):
            """Move or clean up all references from old_mac to new_mac."""
            for tbl in delete_tables:
                db.execute(text(
                    f"DELETE FROM {tbl} WHERE mac_address = :old"
                ), {"old": old_mac})
            # device_ips: drop conflicting, move rest
            db.execute(text(
                "DELETE FROM device_ips WHERE mac_address = :old "
                "AND ip IN (SELECT ip FROM device_ips WHERE mac_address = :new)"
            ), {"old": old_mac, "new": new_mac})
            db.execute(text(
                "UPDATE device_ips SET mac_address = :new WHERE mac_address = :old"
            ), {"old": old_mac, "new": new_mac})
            # alert_exceptions
            db.execute(text(
                "UPDATE alert_exceptions SET mac_address = :new "
                "WHERE mac_address = :old"
            ), {"old": old_mac, "new": new_mac})
            db.execute(text(
                "UPDATE alert_exceptions SET destination = :new "
                "WHERE destination = :old"
            ), {"old": old_mac, "new": new_mac})

        for norm_mac, entries in groups.items():
            if len(entries) == 1 and entries[0][0] == norm_mac:
                continue  # Already correct, nothing to do

            # Pick the richest record as keeper (prefer hostname, then vendor,
            # then display_name). Among equals, prefer the oldest first_seen.
            entries.sort(key=lambda e: (
                e[1] is not None,   # has hostname
                e[3] is not None,   # has display_name
                e[2] is not None,   # has vendor
            ), reverse=True)

            keeper_mac = entries[0][0]
            earliest_first = min(e[4] for e in entries)
            latest_last = max(e[5] for e in entries if e[5])

            # Move all references from non-keeper MACs to keeper
            for entry in entries[1:]:
                old_mac = entry[0]
                _move_mac_refs(old_mac, keeper_mac)
                db.execute(text(
                    "DELETE FROM devices WHERE mac_address = :old"
                ), {"old": old_mac})
                merged += 1

            # Rename keeper to normalized MAC if needed
            if keeper_mac != norm_mac:
                _move_mac_refs(keeper_mac, norm_mac)
                db.execute(text(
                    "UPDATE devices SET mac_address = :new, "
                    "       first_seen = :fs, last_seen = :ls "
                    "WHERE mac_address = :old"
                ), {"new": norm_mac, "old": keeper_mac,
                    "fs": earliest_first, "ls": latest_last})
            else:
                # Just restore the earliest timestamps from merged records
                db.execute(text(
                    "UPDATE devices SET first_seen = :fs, last_seen = :ls "
                    "WHERE mac_address = :mac"
                ), {"mac": norm_mac, "fs": earliest_first, "ls": latest_last})

            fixed += 1

        # Also fix the 'destination' column in alert_exceptions where it
        # stores a MAC address (new_device alerts use MAC as destination)
        ae_rows = db.execute(text(
            "SELECT id, destination FROM alert_exceptions "
            "WHERE destination IS NOT NULL AND destination LIKE '%:%'"
        )).fetchall()
        ae_fixed = 0
        for row_id, dest in ae_rows:
            norm_dest = _normalize_mac(dest)
            if norm_dest != dest:
                db.execute(text(
                    "UPDATE alert_exceptions SET destination = :new WHERE id = :id"
                ), {"new": norm_dest, "id": row_id})
                ae_fixed += 1

        if fixed or ae_fixed:
            db.commit()
            parts = []
            if fixed:
                parts.append(f"normalized {fixed} MAC group(s)")
            if merged:
                parts.append(f"merged {merged} duplicate(s)")
            if ae_fixed:
                parts.append(f"fixed {ae_fixed} alert exception destination(s)")
            print(f"[cleanup] {', '.join(parts)}")

        db.execute(text("PRAGMA foreign_keys = ON"))
    except Exception as exc:
        print(f"[cleanup] MAC normalization sweep failed: {exc}")
        db.rollback()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Network performance collector — stores a snapshot every 60s
# ---------------------------------------------------------------------------
PERF_COLLECT_INTERVAL = 60  # seconds

async def _collect_network_performance():
    """Background task: measure DNS, ping, interface stats, system load."""
    import subprocess, psutil

    await asyncio.sleep(10)  # Let other services start first
    print("[perf] Network performance collector running every 60s")

    while True:
        try:
            row = {}

            # --- DNS latency: resolve google.com via system DNS (AdGuard) ---
            try:
                t0 = time.monotonic()
                await asyncio.to_thread(socket.getaddrinfo, "google.com", 80,
                                        socket.AF_INET, socket.SOCK_STREAM)
                row["dns_latency_ms"] = round((time.monotonic() - t0) * 1000)
            except Exception:
                row["dns_latency_ms"] = None

            # --- Ping gateway + internet ---
            async def _ping(host):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ping", "-c", "3", "-W", "2", host,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                    text_out = stdout.decode(errors="replace")
                    # Parse avg from "rtt min/avg/max/mdev = 0.5/1.2/2.0/0.3 ms"
                    m = re.search(r"rtt [^=]+=\s*[\d.]+/([\d.]+)/", text_out)
                    avg_ms = round(float(m.group(1))) if m else None
                    # Parse packet loss "3 packets transmitted, 3 received, 0% packet loss"
                    lm = re.search(r"(\d+)% packet loss", text_out)
                    loss = int(lm.group(1)) if lm else None
                    return avg_ms, loss
                except Exception:
                    return None, None

            # Detect default gateway
            gw_ip = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "route", "show", "default",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                out, _ = await proc.communicate()
                gw_match = re.search(r"default via ([\d.]+)", out.decode(errors="replace"))
                if gw_match:
                    gw_ip = gw_match.group(1)
            except Exception:
                pass

            gw_ms, gw_loss = (None, None)
            inet_ms, inet_loss = (None, None)
            if gw_ip:
                gw_ms, gw_loss = await _ping(gw_ip)
            inet_ms, inet_loss = await _ping("8.8.8.8")

            row["ping_gateway_ms"] = gw_ms
            row["ping_internet_ms"] = inet_ms
            row["packet_loss_pct"] = inet_loss if inet_loss is not None else gw_loss

            # --- Bridge interface stats from /proc/net/dev ---
            try:
                iface_stats = await asyncio.to_thread(psutil.net_io_counters, pernic=True)
                br = iface_stats.get("br0")
                if br:
                    row["br_rx_bytes"] = br.bytes_recv
                    row["br_tx_bytes"] = br.bytes_sent
                    row["br_rx_packets"] = br.packets_recv
                    row["br_tx_packets"] = br.packets_sent
                    row["br_rx_errors"] = br.errin
                    row["br_tx_errors"] = br.errout
                    row["br_rx_drops"] = br.dropin
                    row["br_tx_drops"] = br.dropout
            except Exception:
                pass

            # --- System load ---
            try:
                row["cpu_percent"] = round(psutil.cpu_percent(interval=0))
                row["memory_percent"] = round(psutil.virtual_memory().percent)
                load1, load5, load15 = psutil.getloadavg()
                row["load_avg_1"] = round(load1 * 100)
                row["load_avg_5"] = round(load5 * 100)
                row["load_avg_15"] = round(load15 * 100)
            except Exception:
                pass

            # --- Store in DB ---
            db = SessionLocal()
            try:
                db.add(NetworkPerformance(**row))
                db.commit()
            finally:
                db.close()

        except Exception as exc:
            print(f"[perf] Collection error: {exc}")

        await asyncio.sleep(PERF_COLLECT_INTERVAL)


async def lifespan(app: FastAPI):
    init_db()
    _backfill_vendors()
    _cleanup_junk_hostnames()
    _cleanup_empty_sentinel_strings()
    _normalize_mac_addresses()
    # One-shot: clear false-positive inbound attacks (established connections
    # to open web ports recorded before the conn_state filter was added).
    _db = SessionLocal()
    try:
        cleared = _db.query(InboundAttack).filter(
            InboundAttack.target_port >= 1024,
        ).delete(synchronize_session=False)
        # Also remove false-positive inbound_threat detection events on high ports
        cleared2 = _db.query(DetectionEvent).filter(
            DetectionEvent.detection_type == "inbound_threat",
            DetectionEvent.ai_service.like("inbound_%"),
        ).all()
        high_port_ids = []
        for e in cleared2:
            try:
                port = int(e.ai_service.replace("inbound_", ""))
                if port >= 1024:
                    high_port_ids.append(e.id)
            except ValueError:
                pass
        if high_port_ids:
            _db.query(DetectionEvent).filter(
                DetectionEvent.id.in_(high_port_ids)
            ).delete(synchronize_session=False)
            cleared += len(high_port_ids)
        if cleared:
            _db.commit()
            print(f"[cleanup] Cleared {cleared} false-positive inbound entries")
    except Exception:
        pass
    finally:
        _db.close()
    # Start background tasks
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    expiry_task = asyncio.create_task(_expire_block_rules())
    policy_expiry_task = asyncio.create_task(_expire_service_policies())
    baseline_task = asyncio.create_task(_compute_device_baselines())
    volume_spike_task = asyncio.create_task(_check_volume_spikes())
    notifier_task = asyncio.create_task(_push_notifier_task())
    watchdog_task = asyncio.create_task(_adguard_watchdog())
    beacon_task = asyncio.create_task(_periodic_beacon_scan())
    # Dynamic domain list updater — seeds from former DOMAIN_MAP on first
    # boot, then fetches v2fly community domain lists every 24h.
    from service_updater import periodic_update_domains
    domain_updater_task = asyncio.create_task(periodic_update_domains())
    perf_task = asyncio.create_task(_collect_network_performance())
    print(
        f"[cleanup] Auto-cleanup enabled: retain {RETENTION_DAYS} days, "
        f"max {MAX_EVENTS:,} events, check every {CLEANUP_INTERVAL}s"
    )
    print(f"[rules] Block rule expiry checker running every {RULE_EXPIRY_INTERVAL}s")
    print(f"[watchdog] AdGuard auto-failsafe active (check every 30s, trigger after 3 failures)")
    print(f"[beacon] Malware C2 beacon detector running every {BEACON_SCAN_INTERVAL}s")
    print(f"[service-updater] Domain list updater running (immediate + every 24h)")
    # Restore IPS (CrowdSec) toggle state — defaults to ON on first run
    # so the network is protected from the start without manual action.
    ips_pref = _read_ips_pref()
    crowdsec.enabled = bool(ips_pref.get("enabled", True))
    ips_tag = "user preference" if ips_pref.get("user_set") else "first-run default"
    print(f"[ips] Active Protect set to {'ON' if crowdsec.enabled else 'OFF'} ({ips_tag})")

    # Restore killswitch state from last run — overrides IPS if active
    ks = _read_killswitch_state()
    if ks.get("active"):
        print(f"[killswitch] ⚠️  Killswitch was active before restart — still active")
        crowdsec.enabled = False

    # Restore AdGuard DNS filtering preference (defaults to OFF on first run).
    # When ON, set_protection() automatically disables all subscription
    # filter lists so only our explicit custom rules take effect.
    async def _restore_adguard_pref():
        try:
            pref = _read_adguard_protection_pref()
            desired = bool(pref.get("enabled", False))
            await adguard.set_protection(desired)
            tag = "user preference" if pref.get("user_set") else "first-run default"
            print(f"[adguard] DNS filtering set to {'ON' if desired else 'OFF'} ({tag})")
        except Exception as exc:
            print(f"[adguard] Could not apply DNS filtering preference: {exc}")
    asyncio.create_task(_restore_adguard_pref())

    yield
    cleanup_task.cancel()
    expiry_task.cancel()
    watchdog_task.cancel()
    beacon_task.cancel()
    perf_task.cancel()


app = FastAPI(title="AI-Radar", version="0.3.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/sw.js")
def service_worker():
    return FileResponse(STATIC_DIR / "sw.js", media_type="application/javascript")


# ---------------------------------------------------------------------------
# DB session dependency
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# POST /api/ingest — store a new detection event
# ---------------------------------------------------------------------------
@app.post("/api/ingest", response_model=EventRead, status_code=201)
def ingest_event(event: EventCreate, db: Session = Depends(get_db)):
    db_event = DetectionEvent(**event.model_dump())
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


# ---------------------------------------------------------------------------
# GET /api/events — return events with optional filters
# ---------------------------------------------------------------------------
def _apply_heartbeat_filter(q, include_heartbeats: bool):
    """Filter out zero-byte SNI heartbeats unless explicitly included.

    A "heartbeat" is a TLS handshake to a known service (sni_hello) that
    carries no byte count and is not flagged as an upload. They represent
    "service is configured and reachable" (e.g. iPhone checking iCloud push
    every 5-10 min) — useful for service adoption but noise in event tables.
    """
    if include_heartbeats:
        return q
    from sqlalchemy import or_
    return q.filter(
        or_(
            DetectionEvent.detection_type != "sni_hello",
            DetectionEvent.bytes_transferred > 0,
            DetectionEvent.possible_upload == True,  # noqa: E712
        )
    )


# Categories explicitly surfaced as their own columns/sections in the UI.
# Anything else (gaming, social, streaming, shopping, gambling, tracking-
# subcategories, "other") is bucketed into the "Other" column via the
# special category=other query value.
_PRIMARY_CATEGORIES = ("ai", "cloud", "tracking")


@app.get("/api/events", response_model=list[EventRead])
def list_events(
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    category: Optional[str] = Query(
        None,
        description="Filter by category: ai, cloud, tracking, or 'other' "
                    "(= everything except ai/cloud/tracking)",
    ),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    include_heartbeats: bool = Query(
        True,
        description="Include zero-byte sni_hello heartbeats (keep-alives / push-notification pings)",
    ),
    db: Session = Depends(get_db),
):
    q = db.query(DetectionEvent)
    if service:
        q = q.filter(DetectionEvent.ai_service == service)
    if source_ip:
        ips = [s.strip() for s in source_ip.split(',') if s.strip()]
        q = q.filter(DetectionEvent.source_ip.in_(ips)) if len(ips) > 1 else q.filter(DetectionEvent.source_ip == ips[0])
    if category:
        if category == "other":
            q = q.filter(~DetectionEvent.category.in_(_PRIMARY_CATEGORIES))
        else:
            q = q.filter(DetectionEvent.category == category)
    if start:
        q = q.filter(DetectionEvent.timestamp >= start)
    if end:
        q = q.filter(DetectionEvent.timestamp <= end)
    q = _apply_heartbeat_filter(q, include_heartbeats)
    return q.order_by(DetectionEvent.timestamp.desc()).offset(offset).limit(limit).all()


# ---------------------------------------------------------------------------
# GET /api/events/export — CSV download
# ---------------------------------------------------------------------------
@app.get("/api/events/export")
def export_events(
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(DetectionEvent)
    if service:
        q = q.filter(DetectionEvent.ai_service == service)
    if source_ip:
        ips = [s.strip() for s in source_ip.split(',') if s.strip()]
        q = q.filter(DetectionEvent.source_ip.in_(ips)) if len(ips) > 1 else q.filter(DetectionEvent.source_ip == ips[0])
    if category:
        if category == "other":
            q = q.filter(~DetectionEvent.category.in_(_PRIMARY_CATEGORIES))
        else:
            q = q.filter(DetectionEvent.category == category)
    if start:
        q = q.filter(DetectionEvent.timestamp >= start)
    if end:
        q = q.filter(DetectionEvent.timestamp <= end)

    rows = q.order_by(DetectionEvent.timestamp.desc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "timestamp", "sensor_id", "ai_service", "category",
        "detection_type", "source_ip", "bytes_transferred", "possible_upload",
    ])
    for r in rows:
        writer.writerow([
            r.id, r.timestamp.isoformat(), r.sensor_id, r.ai_service, r.category,
            r.detection_type, r.source_ip, r.bytes_transferred, r.possible_upload,
        ])
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=airadar_events.csv"},
    )


# ---------------------------------------------------------------------------
# GET /api/timeline — bucketed event counts for charts
# ---------------------------------------------------------------------------
@app.get("/api/timeline", response_model=list[TimelineBucket])
def timeline(
    bucket_size: str = Query("hour", pattern="^(minute|hour|day)$"),
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    fmt_map = {
        "minute": "%Y-%m-%dT%H:%M:00",
        "hour":   "%Y-%m-%dT%H:00:00",
        "day":    "%Y-%m-%dT00:00:00",
    }
    fmt = fmt_map[bucket_size]
    bucket_col = func.strftime(fmt, DetectionEvent.timestamp).label("bucket")

    q = db.query(
        bucket_col,
        DetectionEvent.ai_service,
        func.count().label("count"),
        func.sum(func.cast(DetectionEvent.possible_upload, Integer)).label("uploads"),
    )
    if service:
        q = q.filter(DetectionEvent.ai_service == service)
    if source_ip:
        ips = [s.strip() for s in source_ip.split(',') if s.strip()]
        q = q.filter(DetectionEvent.source_ip.in_(ips)) if len(ips) > 1 else q.filter(DetectionEvent.source_ip == ips[0])
    if category:
        if category == "other":
            q = q.filter(~DetectionEvent.category.in_(_PRIMARY_CATEGORIES))
        else:
            q = q.filter(DetectionEvent.category == category)
    if start:
        q = q.filter(DetectionEvent.timestamp >= start)
    if end:
        q = q.filter(DetectionEvent.timestamp <= end)

    rows = q.group_by(bucket_col, DetectionEvent.ai_service).order_by(bucket_col).all()

    buckets: OrderedDict[str, dict] = OrderedDict()
    for r in rows:
        if r.bucket not in buckets:
            buckets[r.bucket] = {"services": {}, "uploads": 0}
        buckets[r.bucket]["services"][r.ai_service] = r.count
        buckets[r.bucket]["uploads"] += r.uploads or 0

    return [
        TimelineBucket(bucket=b, services=data["services"], uploads=data["uploads"])
        for b, data in buckets.items()
    ]


# ---------------------------------------------------------------------------
# Device endpoints
# ---------------------------------------------------------------------------

@app.get("/api/devices", response_model=list[DeviceRead])
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    # Hydrate each device with the derived ja4_label (computed on the fly
    # from the stored ja4_fingerprint so the curated label list can evolve
    # without needing a data migration).
    result = []
    for d in devices:
        dr = DeviceRead.model_validate(d)
        dr.ja4_label = _resolve_ja4_label(d.ja4_fingerprint)
        result.append(dr)
    return result


# ---------------------------------------------------------------------------
# GET /api/devices/{mac}/report — AI-powered device activity recap (Gemini)
# ---------------------------------------------------------------------------
@app.get("/api/devices/{mac_address}/report")
async def device_ai_report(
    mac_address: str,
    force: bool = Query(False, description="Regenerate the report even if a cached one exists"),
    lang: str = Query("nl", description="Report language: 'nl' or 'en'"),
    db: Session = Depends(get_db),
):
    """Return the AI recap for a device.

    By default returns the previously-cached report if one exists.
    Pass ?force=true to regenerate (overwrites the cached copy).
    The cached report is persisted on the Device row, so it survives
    across container restarts and the user sees it immediately next
    time they open the drawer.
    """
    # 1. Find device + associated IPs
    device = db.query(Device).filter(Device.mac_address == mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Apparaat niet gevonden.")

    # Detect the language of the cached report from its section headers.
    # The Dutch prompt emits "## Samenvatting", the English prompt
    # emits "## Summary". If the caller's requested language doesn't
    # match the cache, fall through and regenerate so a locale switch
    # in the UI immediately yields a report in the new language.
    cached_lang = None
    if device.ai_report_md:
        if "## Summary" in device.ai_report_md:
            cached_lang = "en"
        elif "## Samenvatting" in device.ai_report_md:
            cached_lang = "nl"
    requested_lang = (lang or "nl").lower()
    if requested_lang not in ("nl", "en"):
        requested_lang = "nl"
    lang_mismatch = cached_lang is not None and cached_lang != requested_lang

    # If we have a cached report in the right language and the caller
    # didn't ask for a refresh, return it — no Gemini call, instant.
    if device.ai_report_md and not force and not lang_mismatch:
        return {
            "device": device.display_name or device.hostname or device.mac_address,
            "mac": device.mac_address,
            "report": device.ai_report_md,
            "tokens": {
                "total_tokens": device.ai_report_tokens or 0,
                # Per-bucket tokens aren't stored — UI only needs total
                # for the footer pricing calc, and total × blended rate
                # is close enough.
                "prompt_tokens": 0,
                "response_tokens": device.ai_report_tokens or 0,
                "thinking_tokens": 0,
            },
            "model": device.ai_report_model or "gemini-2.5-flash-lite",
            "cached": True,
            "generated_at": device.ai_report_at.isoformat() if device.ai_report_at else None,
        }

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        raise HTTPException(
            status_code=400,
            detail="GEMINI_API_KEY is niet geconfigureerd. "
                   "Voeg je API-sleutel toe aan .env (krijg er een op https://aistudio.google.com/app/apikey).",
        )

    device_ips = [dip.ip for dip in device.ips]
    if not device_ips:
        raise HTTPException(status_code=404, detail="Geen IP-adressen gekoppeld aan dit apparaat.")

    device_label = device.display_name or device.hostname or device_ips[0]

    # 2. Fetch detection events (last 24h)
    cutoff = datetime.utcnow() - timedelta(hours=24)
    all_events = (
        db.query(DetectionEvent)
        .filter(
            DetectionEvent.source_ip.in_(device_ips),
            DetectionEvent.timestamp >= cutoff,
        )
        .order_by(DetectionEvent.timestamp.asc())
        .all()
    )

    # Aggregate every service over the full 24-hour window. We don't
    # want to throw away sni_hello heartbeats here — for streaming and
    # gaming apps, ssl.log doesn't report bytes so heartbeats are the
    # ONLY usage signal we have (Spotify/Discord/Ubisoft Connect all
    # show 0-byte sni_hello events when actively used, because the
    # real traffic goes over UDP or is downstream).
    #
    # Classification rule (by hit count, not bytes):
    #   count >= 3  → ACTIVE usage         (heavy in-session use)
    #   count == 2  → LIGHT activity       (brief touch / keep-alive)
    #   count == 1  → BACKGROUND only      (one-off ping)
    # On top of that, any volumetric_upload event upgrades the service
    # to ACTIVE regardless of hit count.
    anomaly_types = {"vpn_tunnel", "stealth_vpn_tunnel", "beaconing_threat"}
    svc_totals: dict[str, dict] = {}
    for e in all_events:
        svc = e.ai_service
        if svc not in svc_totals:
            svc_totals[svc] = {
                "count": 0,
                "bytes": 0,
                "uploads": 0,
                "category": e.category,
                "first": e.timestamp,
                "last": e.timestamp,
                "has_anomaly": False,
            }
        t = svc_totals[svc]
        t["count"] += 1
        t["bytes"] += e.bytes_transferred or 0
        if e.possible_upload:
            t["uploads"] += 1
        if e.detection_type in anomaly_types:
            t["has_anomaly"] = True
        if e.timestamp > t["last"]:
            t["last"] = e.timestamp
        if e.timestamp < t["first"]:
            t["first"] = e.timestamp

    # Classify each service into ACTIVE / LIGHT / BACKGROUND buckets
    active_svcs: list = []
    light_svcs: list = []
    background_svcs: list = []
    for svc, t in svc_totals.items():
        is_active = (t["count"] >= 3 or t["uploads"] > 0 or t["bytes"] > 1024*1024)
        if is_active:
            active_svcs.append((svc, t))
        elif t["count"] == 2:
            light_svcs.append((svc, t))
        else:
            background_svcs.append((svc, t))
    active_svcs.sort(key=lambda x: -x[1]["count"])
    light_svcs.sort(key=lambda x: -x[1]["count"])
    background_svcs.sort(key=lambda x: x[0])

    # --- Hourly distribution across the 24h window ---
    # Gives Gemini the "shape of the day" so it can lead the summary
    # with the dominant activity period instead of just describing
    # "what's happening right now".
    hourly: dict[int, dict] = {}
    for e in all_events:
        hr = e.timestamp.strftime("%Y-%m-%d %H:00 UTC")
        if hr not in hourly:
            hourly[hr] = {"events": 0, "bytes": 0, "services": set()}
        hourly[hr]["events"] += 1
        hourly[hr]["bytes"] += e.bytes_transferred or 0
        hourly[hr]["services"].add(e.ai_service)
    hourly_rows = sorted(hourly.items())  # chronological

    # Prompt budget: hard caps so the LLM prompt stays under Gemini's
    # context window even for extremely active devices.
    MAX_SERVICES_IN_PROMPT = 15
    MAX_LIGHT_SERVICES = 12
    MAX_BACKGROUND_SERVICES = 25
    MAX_UPLOAD_EVENTS = 20
    MAX_DNS_DOMAINS = 20
    MAX_PROMPT_CHARS = 20000

    # Build event summary for the "actively used" bucket
    events = all_events  # used later for upload timeline
    event_summary_lines = []
    for svc, t in active_svcs[:MAX_SERVICES_IN_PROMPT]:
        kb = t["bytes"] / 1024
        line = f"- {svc} ({t['category']}): {t['count']} hits"
        if t["bytes"] > 0:
            line += f", {kb:,.0f} KB"
        if t["uploads"] > 0:
            line += f", {t['uploads']} uploads"
        line += f" | actief {t['first'].strftime('%H:%M')}–{t['last'].strftime('%H:%M')} UTC"
        event_summary_lines.append(line)
    if len(active_svcs) > MAX_SERVICES_IN_PROMPT:
        event_summary_lines.append(f"- ... +{len(active_svcs) - MAX_SERVICES_IN_PROMPT} more actively-used services")

    light_lines = [
        f"- {svc}: {t['count']} hits | {t['first'].strftime('%H:%M')}–{t['last'].strftime('%H:%M')} UTC"
        for svc, t in light_svcs[:MAX_LIGHT_SERVICES]
    ]
    background_lines = [
        f"- {svc}: {t['count']} ping"
        for svc, t in background_svcs[:MAX_BACKGROUND_SERVICES]
    ]

    # Activity level — computed from ACTIVE bucket size + total bytes
    total_bytes = sum(t["bytes"] for _, t in active_svcs)
    total_uploads_meaningful = sum(1 for e in all_events if e.possible_upload)
    active_svc_count = len(active_svcs)

    if active_svc_count == 0 and total_uploads_meaningful == 0:
        activity_level = "IDLE — only background heartbeats, no sustained service usage"
    elif active_svc_count <= 2 and total_bytes < 5 * 1024 * 1024:
        activity_level = "LIGHT — brief touches, probably background sync or short checks"
    elif active_svc_count <= 5:
        activity_level = "MODERATE — several services in sustained use over the window"
    else:
        activity_level = "ACTIVE — heavy usage across many services, clear user session"

    # Upload timeline — cap to most recent N, sort by timestamp desc
    upload_events = [
        e for e in events
        if e.possible_upload and e.bytes_transferred and e.bytes_transferred > 0
    ]
    upload_events.sort(key=lambda e: e.timestamp, reverse=True)
    total_uploads = len(upload_events)
    upload_timeline = []
    for e in upload_events[:MAX_UPLOAD_EVENTS]:
        kb = e.bytes_transferred / 1024
        upload_timeline.append(
            f"- {e.timestamp.strftime('%H:%M')} UTC: {e.ai_service} upload ({kb:,.0f} KB)"
        )
    if total_uploads > MAX_UPLOAD_EVENTS:
        upload_timeline.append(f"- ... +{total_uploads - MAX_UPLOAD_EVENTS} oudere uploads (niet getoond)")

    # 3. Fetch DNS queries from AdGuard (capped)
    dns_domains = await adguard.get_recent_dns_queries(device_ips, hours=24)
    dns_lines = []
    for domain, count in list(dns_domains.items())[:MAX_DNS_DOMAINS]:
        dns_lines.append(f"- {domain}: {count}x")

    # 4. Build the data block for the LLM
    # Include device type signals (OS, device class, DHCP fingerprint,
    # JA4 label) so Gemini can open its report with a concrete
    # "This is a Windows gaming PC / iPad / IoT speaker" classification
    # instead of a vague "this device does traffic".
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ja4_label_resolved = _resolve_ja4_label(device.ja4_fingerprint)

    # Language selection — 'en' falls back to NL for anything other than
    # explicit 'en'. All user-facing labels in both the data block and
    # the system prompt are branched on this flag.
    lang = (lang or "nl").lower()
    if lang not in ("nl", "en"):
        lang = "nl"
    is_en = lang == "en"

    L = {
        "name":        "Name"            if is_en else "Naam",
        "mac":         "MAC",
        "vendor":      "OUI Vendor",
        "unknown":     "Unknown"         if is_en else "Onbekend",
        "os":          "OS (p0f)",
        "dclass":      "Device class (p0f)",
        "dhcp":        "DHCP vendor class",
        "ja4":         "JA4 TLS stack",
        "dist":        "Network distance",
        "hops":        "hops",
        "ips":         "IP addresses"    if is_en else "IP-adressen",
        "more":        "more"            if is_en else "meer",
        "generated":   "Report generated"if is_en else "Rapport gegenereerd",
    }

    device_lines = [
        f"{L['name']}: {device_label}",
        f"{L['mac']}: {mac_address}",
        f"{L['vendor']}: {device.vendor or L['unknown']}",
    ]
    if device.os_full or device.os_name:
        os_str = device.os_full or device.os_name
        if device.os_version and device.os_version not in os_str:
            os_str = f"{os_str} {device.os_version}"
        device_lines.append(f"{L['os']}: {os_str}")
    if device.device_class:
        device_lines.append(f"{L['dclass']}: {device.device_class}")
    if device.dhcp_vendor_class:
        device_lines.append(f"{L['dhcp']}: {device.dhcp_vendor_class}")
    if ja4_label_resolved:
        device_lines.append(f"{L['ja4']}: {ja4_label_resolved}")
    if device.network_distance is not None:
        device_lines.append(f"{L['dist']}: {device.network_distance} {L['hops']}")
    device_lines.append(
        f"{L['ips']}: {', '.join(device_ips[:5])}"
        f"{' (+' + str(len(device_ips) - 5) + ' ' + L['more'] + ')' if len(device_ips) > 5 else ''}"
    )
    device_lines.append(f"{L['generated']}: {now_str}")

    # Hourly activity lines — one line per hour with events, KB, and
    # the top-3 services so Gemini can see which hours dominated the
    # 24h window and lead the summary with that period.
    hourly_lines = []
    for hr, info in hourly_rows:
        top3 = sorted(info["services"])[:3]
        extra = len(info["services"]) - 3
        svc_str = ", ".join(top3)
        if extra > 0:
            svc_str += f" (+{extra})"
        kb = info["bytes"] / 1024
        hourly_lines.append(
            f"- {hr}: {info['events']} events, {kb:,.0f} KB | {svc_str}"
        )

    # ---- Section labels (NL / EN) ----
    if is_en:
        hdr_device     = "=== DEVICE INFO ==="
        hdr_activity   = "=== ACTIVITY LEVEL ==="
        lbl_total_ev   = "Total events in 24h window"
        lbl_total_by   = "Total outbound bytes"
        lbl_total_up   = "Total uploads"
        hdr_hourly     = "=== HOURLY ACTIVITY (24h window, UTC) ==="
        hdr_hourly_hint= (
            "This shows the shape of the day. Lead your summary with the "
            "hours where most activity happened — do NOT focus only on the "
            "most recent hour."
        )
        hourly_empty   = "- No activity recorded"
        hdr_active     = f"=== ACTIVELY USED SERVICES (>=3 hits, top {MAX_SERVICES_IN_PROMPT}) ==="
        hdr_active_hint= (
            "These services were used repeatedly during the window. Treat "
            "them as the dominant user activity. Bytes are often 0 for "
            "streaming/gaming apps because real traffic runs over QUIC/UDP — "
            "hit count is the reliable usage signal, not bytes."
        )
        active_empty   = "- No services with sustained usage"
        hdr_light      = f"=== LIGHTLY TOUCHED (2 hits, top {MAX_LIGHT_SERVICES}) ==="
        hdr_light_hint = (
            "Brief interactions — mention only as 'briefly checked' or "
            "'short touch', never as 'used' or 'streamed'."
        )
        light_empty    = "- (none)"
        hdr_bg         = f"=== BACKGROUND ONLY (1 ping, top {MAX_BACKGROUND_SERVICES}) ==="
        hdr_bg_hint    = (
            "One-off keep-alive pings. These apps are installed / reachable "
            "but NOT actively used. Only describe them as 'running in "
            "background', never as 'used', 'streamed', 'watched', 'chatted'."
        )
        bg_empty       = "- (none)"
        hdr_uploads    = f"=== UPLOAD TIMELINE (most recent {MAX_UPLOAD_EVENTS}) ==="
        upload_empty   = "- No uploads detected"
        hdr_dns        = f"=== DNS QUERIES (top {MAX_DNS_DOMAINS} domains, last 24h) ==="
        dns_empty      = "- No DNS data available (AdGuard querylog empty or unreachable)"
    else:
        hdr_device     = "=== APPARAAT INFO ==="
        hdr_activity   = "=== ACTIVITEITSNIVEAU ==="
        lbl_total_ev   = "Totaal events in 24u-venster"
        lbl_total_by   = "Totale uitgaande bytes"
        lbl_total_up   = "Totale uploads"
        hdr_hourly     = "=== UURLIJKSE ACTIVITEIT (24u-venster, UTC) ==="
        hdr_hourly_hint= (
            "Dit laat de vorm van de dag zien. Leid je samenvatting in met "
            "de uren waar de meeste activiteit zat — focus NIET alleen op "
            "het laatste uur."
        )
        hourly_empty   = "- Geen activiteit geregistreerd"
        hdr_active     = f"=== ACTIEF GEBRUIKTE SERVICES (>=3 hits, top {MAX_SERVICES_IN_PROMPT}) ==="
        hdr_active_hint= (
            "Deze services zijn herhaaldelijk aangeraakt tijdens het venster. "
            "Behandel ze als het zwaartepunt van het gebruik. Bytes zijn vaak "
            "0 voor streaming/gaming apps omdat het echte verkeer via "
            "QUIC/UDP loopt — hit count is het betrouwbare signaal, niet "
            "bytes."
        )
        active_empty   = "- Geen services met duurzaam gebruik"
        hdr_light      = f"=== LICHT AANGERAAKT (2 hits, top {MAX_LIGHT_SERVICES}) ==="
        hdr_light_hint = (
            "Korte interacties — alleen benoemen als 'kort gecheckt' of "
            "'even aangeraakt', nooit als 'gebruikt' of 'gestreamd'."
        )
        light_empty    = "- (geen)"
        hdr_bg         = f"=== ALLEEN ACHTERGROND (1 ping, top {MAX_BACKGROUND_SERVICES}) ==="
        hdr_bg_hint    = (
            "Eenmalige keep-alive pings. Deze apps zijn geïnstalleerd / "
            "bereikbaar maar NIET actief gebruikt. Beschrijf ze alleen als "
            "'draait op achtergrond', nooit als 'gebruikt', 'gestreamd', "
            "'bekeken' of 'gechat'."
        )
        bg_empty       = "- (geen)"
        hdr_uploads    = f"=== UPLOAD TIJDLIJN (recentste {MAX_UPLOAD_EVENTS}) ==="
        upload_empty   = "- Geen uploads gedetecteerd"
        hdr_dns        = f"=== DNS VERZOEKEN (top {MAX_DNS_DOMAINS} domeinen, afgelopen 24u) ==="
        dns_empty      = "- Geen DNS-data beschikbaar (AdGuard querylog leeg of niet bereikbaar)"

    data_block = f"""{hdr_device}
{chr(10).join(device_lines)}

{hdr_activity}
{activity_level}
{lbl_total_ev}: {len(all_events)}
{lbl_total_by}: {total_bytes:,}
{lbl_total_up}: {total_uploads_meaningful}

{hdr_hourly}
{hdr_hourly_hint}
{chr(10).join(hourly_lines) if hourly_lines else hourly_empty}

{hdr_active}
{hdr_active_hint}
{chr(10).join(event_summary_lines) if event_summary_lines else active_empty}

{hdr_light}
{hdr_light_hint}
{chr(10).join(light_lines) if light_lines else light_empty}

{hdr_bg}
{hdr_bg_hint}
{chr(10).join(background_lines) if background_lines else bg_empty}

{hdr_uploads}
{chr(10).join(upload_timeline) if upload_timeline else upload_empty}

{hdr_dns}
{chr(10).join(dns_lines) if dns_lines else dns_empty}
"""

    # Hard safety net: if the prompt is still huge, trim the middle.
    # Gemini 2.5 Flash has a large context window but extremely long
    # inputs cause cost spikes and 400-level errors on edge cases.
    if len(data_block) > MAX_PROMPT_CHARS:
        head = data_block[: MAX_PROMPT_CHARS // 2]
        tail = data_block[-MAX_PROMPT_CHARS // 2 :]
        data_block = head + "\n\n[... data truncated for prompt budget ...]\n\n" + tail
        print(f"[gemini] Prompt truncated to {MAX_PROMPT_CHARS} chars for {mac_address}")

    # 5. Call Gemini
    # The prompt enforces a fixed structure:
    #   1. Plain-language "TL;DR" paragraph (2-3 sentences max) that
    #      reads like a human describing the device: what it is,
    #      which apps/services it's running, anything that stands out.
    #      This is the most valuable part — the user wants to scan it
    #      in 5 seconds and know what's going on.
    #   2. Chronological day breakdown (morning / afternoon / evening).
    #   3. "Opvallende observaties" — 3 specific bullets.
    if is_en:
        system_prompt = (
            "You are a network analyst explaining to a non-technical end "
            "user (household or small-business owner) what a specific "
            "device on their network has been doing. Write in English, "
            "in markdown.\n\n"

            "CRITICAL — COVER BOTH THE DAY SHAPE AND THE CURRENT STATE:\n"
            "Use the HOURLY ACTIVITY section to find the dominant activity "
            "period(s) in the 24h window. Your summary should describe "
            "what happened over the day AND what is happening RIGHT NOW. "
            "Look at the MOST RECENT hour(s) in the hourly data: if there "
            "are gaming/streaming/communication services active, the device "
            "is NOT idle — say so clearly (e.g. 'is currently in an active "
            "gaming session'). Only say 'idle' or 'quiet' if the most "
            "recent hour(s) truly have zero or near-zero events.\n\n"

            "BYTES ARE UNRELIABLE FOR STREAMING/GAMING:\n"
            "Spotify, Discord, Roblox, Ubisoft Connect, Steam downloads, "
            "Twitch, etc. often show 0 bytes in TLS logs because the real "
            "traffic runs over QUIC/UDP. Trust HIT COUNT as the primary "
            "usage signal: a service with 30 hits across 4 hours is "
            "actively used even if bytes are near zero.\n\n"

            "THREE SERVICE BUCKETS — USE DIFFERENT VERBS FOR EACH:\n"
            "  - ACTIVELY USED SERVICES (>=3 hits): use verbs like "
            "'played', 'streamed', 'watched', 'chatted', 'used'.\n"
            "  - LIGHTLY TOUCHED (2 hits): use 'briefly checked', "
            "'short touch' — never 'used' or 'streamed'.\n"
            "  - BACKGROUND ONLY (1 ping): say 'installed', 'running in "
            "background', 'reachable'. NEVER say 'used', 'watched', "
            "'streamed', 'chatted' for these.\n"
            "Wrong example: 'The user listened to Spotify' — when "
            "Spotify was background-only.\n"
            "Correct: 'Spotify is installed and reachable but shows no "
            "active playback signature.'\n\n"

            "SECURITY & PRIVACY — ALWAYS FLAG THESE:\n"
            "  - Any service starting with 'vpn_' (e.g. vpn_nordvpn, "
            "vpn_mullvad) is a VPN connection — ALWAYS mention this "
            "prominently. VPN usage is privacy-relevant.\n"
            "  - If many ad-tracking services appear (adform, openx, "
            "index_exchange, rtb_house, ogury, vidazoo, etc.), flag "
            "this as 'significant ad-tracker presence' — it may "
            "indicate adware or ad-heavy browsing.\n"
            "  - Unexpected services for the device type (e.g. baidu "
            "on a Dutch PC, or AI services on a child's device) "
            "should be called out specifically.\n"
            "  - AI service usage (openai, google_gemini, copilot, "
            "anthropic, etc.) should always be mentioned.\n\n"

            "REQUIRED STRUCTURE — stick to it exactly:\n\n"
            "## Summary\n"
            "3 to 4 sentences in plain language, in this order:\n"
            "  1. What the device is (e.g. 'a Windows gaming PC', 'an "
            "iPhone', 'a Google Nest speaker'). Use OS, device class, "
            "vendor and JA4 TLS stack from DEVICE INFO. Be concrete — "
            "not 'this device' but 'this Windows laptop'.\n"
            "  2. The 24h DOMINANT activity: what was the main thing "
            "that happened over the day as a whole. Lead with this.\n"
            "  3. The current state in the last few hours: 'right now "
            "it's idle', 'still actively gaming', 'winding down', etc.\n"
            "  4. Only mention background-sync uploads as 'automatic "
            "sync / telemetry', never as user action.\n\n"
            "## Timeline\n"
            "Short chronological breakdown using the HOURLY ACTIVITY "
            "data. Point out the busy windows by hour range (e.g. "
            "'17:00–21:00 UTC: heavy gaming on Roblox + Discord voice'). "
            "If the level is IDLE, say explicitly that there was no user "
            "session. Max one paragraph.\n\n"
            "## Notable observations\n"
            "Exactly 3 bullets with specific noteworthy findings. Each "
            "bullet starts with a short bold header. Prioritize: VPN "
            "usage, AI usage, unusual services, ad-tracker density, "
            "large uploads — over generic observations.\n"
        )
    else:
        system_prompt = (
            "Je bent een netwerk-analist die een eindgebruiker (niet-"
            "technisch, huishouden of kleine ondernemer) uitlegt wat een "
            "specifiek apparaat op z'n netwerk heeft gedaan. Schrijf in "
            "het Nederlands, in markdown.\n\n"

            "KRITIEK — BESCHRIJF ZOWEL DE DAG ALS DE HUIDIGE STAAT:\n"
            "Gebruik de UURLIJKSE ACTIVITEIT sectie om de dominante "
            "periode(s) in het 24u-venster te vinden. Je samenvatting "
            "moet beschrijven wat er over de dag is gedaan EN wat er NU "
            "gebeurt. Kijk naar de MEEST RECENTE uren in de data: als "
            "daar gaming/streaming/communicatie services actief zijn, is "
            "het apparaat NIET idle — zeg dat duidelijk (bv. 'is nu in "
            "een actieve gaming-sessie'). Zeg alleen 'idle' of 'rustig' "
            "als de meest recente uren echt nul of bijna nul events "
            "hebben.\n\n"

            "BYTES ZIJN ONBETROUWBAAR VOOR STREAMING/GAMING:\n"
            "Spotify, Discord, Roblox, Ubisoft Connect, Steam downloads, "
            "Twitch, etc. tonen vaak 0 bytes in TLS logs omdat het echte "
            "verkeer via QUIC/UDP loopt. Vertrouw op HIT COUNT als "
            "primair signaal: een service met 30 hits verspreid over 4 "
            "uur wordt actief gebruikt, ook als bytes bijna nul zijn.\n\n"

            "DRIE SERVICE-BAKKEN — GEBRUIK ANDERE WERKWOORDEN PER BAK:\n"
            "  - ACTIEF GEBRUIKTE SERVICES (>=3 hits): werkwoorden als "
            "'gespeeld', 'gestreamd', 'gekeken', 'gechat', 'gebruikt'.\n"
            "  - LICHT AANGERAAKT (2 hits): 'kort gecheckt', 'even "
            "aangeraakt' — nooit 'gebruikt' of 'gestreamd'.\n"
            "  - ALLEEN ACHTERGROND (1 ping): 'geïnstalleerd', 'draait "
            "op achtergrond', 'bereikbaar'. NOOIT 'gebruikt', 'bekeken', "
            "'gestreamd' of 'gechat' voor deze services.\n"
            "Foutief: 'De gebruiker luisterde naar Spotify' — terwijl "
            "Spotify alleen in background stond.\n"
            "Goed: 'Spotify is geïnstalleerd en bereikbaar, maar er is "
            "geen actieve afspeelsignatuur te zien.'\n\n"

            "BEVEILIGING & PRIVACY — BENOEM DEZE ALTIJD:\n"
            "  - Elke service die begint met 'vpn_' (bv. vpn_nordvpn, "
            "vpn_mullvad) is een VPN-verbinding — benoem dit ALTIJD "
            "prominent. VPN-gebruik is privacy-relevant.\n"
            "  - Als er veel ad-tracking services verschijnen (adform, "
            "openx, index_exchange, rtb_house, ogury, vidazoo, etc.), "
            "meld dit als 'opvallend veel ad-trackers' — kan duiden "
            "op adware of ad-intensief browsen.\n"
            "  - Onverwachte services voor het type apparaat (bv. baidu "
            "op een Nederlandse PC, of AI-services op een kinder-"
            "apparaat) moeten specifiek benoemd worden.\n"
            "  - AI-gebruik (openai, google_gemini, copilot, anthropic, "
            "etc.) moet altijd vermeld worden.\n\n"

            "VERPLICHTE STRUCTUUR — houd je hier strikt aan:\n\n"
            "## Samenvatting\n"
            "3 tot 4 zinnen in gewone taal, in deze volgorde:\n"
            "  1. Wat voor apparaat dit is (bv. 'een Windows gaming-PC', "
            "'een iPhone', 'een Google Nest speaker'). Gebruik de OS, "
            "device class, vendor en JA4 TLS stack uit APPARAAT INFO. "
            "Wees concreet — niet 'dit apparaat' maar 'deze Windows "
            "laptop'.\n"
            "  2. Het 24u-HOOFDGEBRUIK: waar ging de dag in hoofdlijnen "
            "over. Begin hier mee.\n"
            "  3. De huidige staat in de laatste paar uur: 'nu idle', "
            "'nog steeds aan het gamen', 'aan het afbouwen', etc.\n"
            "  4. Alleen ACHTERGROND-sync uploads vermelden als "
            "'automatische sync / telemetrie', nooit als "
            "gebruikersactie.\n\n"
            "## Dagverloop\n"
            "Korte chronologische samenvatting op basis van de UURLIJKSE "
            "ACTIVITEIT. Benoem de drukke vensters per uurrange (bv. "
            "'17:00–21:00 UTC: zware gaming-sessie op Roblox + Discord "
            "voice'). Als het niveau IDLE is, zeg dan expliciet dat er "
            "geen gebruikersessie heeft plaatsgevonden. Max een "
            "alinea.\n\n"
            "## Opvallende observaties\n"
            "Exact 3 bullets met specifieke dingen die de moeite waard "
            "zijn om te weten. Elke bullet begint met een korte kop in "
            "vet. Prioriteer: VPN-gebruik, AI-gebruik, onverwachte "
            "services, ad-tracker concentratie, grote uploads — boven "
            "generieke observaties.\n"
        )

    prompt_chars = len(system_prompt) + len(data_block)
    print(f"[gemini] Device report prompt for {mac_address}: {prompt_chars} chars, "
          f"{len(events)} events, {total_uploads} uploads")

    # Model choice — see https://ai.google.dev/gemini-api/docs/deprecations
    # gemini-2.5-flash-lite: GA, no thinking mode, shutdown July 22 2026.
    # Why not the others:
    #   - gemini-2.0-flash        → blocked for new API keys already,
    #                                 200s hangs instead of 404
    #   - gemini-2.5-flash        → thinking mode adds 30-120s latency
    #   - gemini-flash-latest     → alias currently points at 2.5-flash
    #                                 (thinking enabled)
    #   - gemini-3-flash-preview  → preview, unstable API
    # When 2.5-flash-lite is shut down, migrate to gemini-3.1-flash-lite
    # (currently preview, should be GA before July 2026).
    # Override via GEMINI_MODEL env var in .env.
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")
    gemini_timeout = int(os.environ.get("GEMINI_TIMEOUT_S", "90"))

    try:
        from google import genai
        import time as _time

        client = genai.Client(api_key=gemini_key)
        _t0 = _time.time()
        print(f"[gemini] Calling {gemini_model} for {mac_address} "
              f"(prompt {prompt_chars} chars, timeout {gemini_timeout}s)...")

        # Run the blocking Gemini SDK call in a thread pool so it doesn't
        # freeze the asyncio event loop (which would block all other
        # requests including healthchecks and crash the container).
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model=gemini_model,
                contents=f"{system_prompt}\n\n{data_block}",
            ),
            timeout=gemini_timeout,
        )
        elapsed = _time.time() - _t0
        report_md = response.text

        # Extract token usage for cost transparency
        usage = response.usage_metadata
        token_info = {
            "prompt_tokens": getattr(usage, "prompt_token_count", 0),
            "response_tokens": getattr(usage, "candidates_token_count", 0),
            "thinking_tokens": getattr(usage, "thoughts_token_count", 0),
            "total_tokens": getattr(usage, "total_token_count", 0),
        }
        print(f"[gemini] Report for {mac_address} done in {elapsed:.1f}s: {token_info}")
    except asyncio.TimeoutError:
        print(f"[gemini] Device report timed out after {gemini_timeout}s for {mac_address}")
        raise HTTPException(
            status_code=504,
            detail=f"Gemini timed out na {gemini_timeout} seconden (model: {gemini_model}). "
                   f"Probeer het later opnieuw.",
        )
    except Exception as exc:
        # Surface the actual error type + message so the user can see
        # whether it's a key issue, rate limit, safety filter, context
        # window exceeded, etc. — instead of a generic 502.
        err_type = type(exc).__name__
        err_msg = str(exc) or repr(exc)
        print(f"[gemini] Device report failed for {mac_address}: {err_type}: {err_msg}")
        # Shorten overly long error strings (Gemini errors can contain
        # the entire input back in the message)
        if len(err_msg) > 500:
            err_msg = err_msg[:500] + "..."
        raise HTTPException(
            status_code=502,
            detail=f"Gemini-fout ({err_type}): {err_msg}",
        )

    # Persist the freshly-generated report on the Device row so future
    # reads hit the cache instead of Gemini.
    device.ai_report_md = report_md
    device.ai_report_at = datetime.utcnow()
    device.ai_report_model = gemini_model
    device.ai_report_tokens = token_info.get("total_tokens", 0)
    db.commit()

    return {
        "device": device_label,
        "mac": mac_address,
        "report": report_md,
        "tokens": token_info,
        "model": gemini_model,
        "cached": False,
        "generated_at": device.ai_report_at.isoformat(),
    }


def _normalize_mac(mac: str) -> str:
    """Normalize MAC: lowercase, zero-padded octets, colon-separated.
    e.g. 'A2:C0:6D:40:7:F7' → 'a2:c0:6d:40:07:f7'
    """
    if not mac:
        return mac
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return ":".join(format(int(p, 16), "02x") for p in parts)
    except (ValueError, AttributeError):
        return mac.lower()


@app.post("/api/devices", response_model=DeviceRead, status_code=201)
def register_device(payload: DeviceRegister, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    mac = _normalize_mac(payload.mac_address)

    # Sanitize incoming hostname — drop junk so it never lands in the DB
    if payload.hostname and _is_junk_hostname(payload.hostname):
        payload.hostname = None

    # Normalise Zeek's "(empty)" sentinels to None so we don't store
    # literal placeholder strings as values.
    for field in ("ja4", "ja4s", "sni", "dhcp_vendor_class", "dhcp_fingerprint"):
        val = getattr(payload, field, None)
        if val in ("(empty)", "-", ""):
            setattr(payload, field, None)

    if not mac:
        # No MAC provided — check if this IP already belongs to a device
        existing_ip = db.query(DeviceIP).filter(DeviceIP.ip == payload.ip).first()
        if existing_ip:
            mac = existing_ip.mac_address
        else:
            # Completely new IP without a MAC — create placeholder
            mac = f"unknown_{payload.ip.replace('.', '_').replace(':', '_')}"

    # Hostname uniqueness check. MUST run AFTER mac is resolved (above),
    # otherwise mDNS calls that arrive with just ip+hostname silently
    # bypass it. The mDNS tailer is vulnerable to a race condition where
    # one device's mDNS record ("slide-<mac>") gets attributed to a
    # different MAC via a stale IP→MAC cache, usually because Google
    # Cast devices forward each other's mDNS announcements over their
    # mesh.
    #
    # Rules (evaluated in order):
    #   1. The incoming MAC is the rightful owner (its flat form appears
    #      in the hostname) — always accept, even if another device
    #      currently has the hostname. In that case, steal it from the
    #      squatter and null out the squatter's hostname.
    #   2. Another device already has this hostname — refuse the
    #      assignment, log and drop to None.
    #   3. No collision — accept.
    if payload.hostname and mac and not mac.startswith("unknown_"):
        mac_flat = mac.replace(":", "").lower()
        host_flat = payload.hostname.replace("-", "").replace("_", "").replace(".", "").lower()
        self_match = bool(mac_flat) and mac_flat in host_flat

        if self_match:
            # This MAC is the rightful owner of the hostname. If any
            # other device currently has it, reclaim it for the real owner.
            squatters = (
                db.query(Device)
                .filter(
                    Device.hostname == payload.hostname,
                    Device.mac_address != mac,
                )
                .all()
            )
            for sq in squatters:
                print(
                    f"[hostname-collision] Reclaiming '{payload.hostname}' "
                    f"from {sq.mac_address} for rightful owner {mac}"
                )
                sq.hostname = None
        else:
            # Not the rightful owner — refuse if anyone else has it
            collision = (
                db.query(Device)
                .filter(
                    Device.hostname == payload.hostname,
                    Device.mac_address != mac,
                )
                .first()
            )
            if collision:
                owner_flat = collision.mac_address.replace(":", "").lower()
                owner_matches = bool(owner_flat) and owner_flat in host_flat
                reason = (
                    f"rightful owner {collision.mac_address} (mac suffix match)"
                    if owner_matches
                    else f"already claimed by {collision.mac_address}"
                )
                print(
                    f"[hostname-collision] Refusing '{payload.hostname}' for {mac} — {reason}"
                )
                payload.hostname = None

    # ── Upgrade placeholder to real MAC ──────────────────────────────
    # When a request for a specific IP now includes a real MAC, migrate
    # the placeholder device's IPs to the real MAC device and delete it.
    if not mac.startswith("unknown_"):
        placeholder_key = f"unknown_{payload.ip.replace('.', '_').replace(':', '_')}"
        placeholder_dev = db.query(Device).filter(Device.mac_address == placeholder_key).first()
        if placeholder_dev:
            db.query(DeviceIP).filter(DeviceIP.mac_address == placeholder_key).update(
                {DeviceIP.mac_address: mac}, synchronize_session="fetch"
            )
            db.delete(placeholder_dev)
            db.flush()

    # Upsert Device by MAC address
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if device:
        # Stronger-wins hostname logic:
        # - fill if currently empty
        # - overwrite if the stored one is junk and the new one is clean
        # - NEVER silently overwrite one clean hostname with another. That
        #   used to happen when mDNS cache had a stale ip→mac mapping and a
        #   "slide-xxx" hostname from one device ended up on a completely
        #   different MAC. If both are clean but differ, keep the existing
        #   one — it was set first and is probably correct.
        if payload.hostname:
            if not device.hostname:
                device.hostname = payload.hostname
            elif _is_junk_hostname(device.hostname) and not _is_junk_hostname(payload.hostname):
                device.hostname = payload.hostname
        # Re-resolve vendor — hostname match may be more accurate than stale OUI
        new_vendor = _resolve_vendor(mac, payload.hostname) or _resolve_vendor(payload.mac_address, payload.hostname)
        if new_vendor and new_vendor != device.vendor:
            device.vendor = new_vendor
        # Update JA4 fingerprint if the sensor provided one
        if payload.ja4:
            device.ja4_fingerprint = payload.ja4
            device.ja4_last_seen = now
        # DHCP vendor class ID from ja4d.log — high-confidence device type
        if payload.dhcp_vendor_class:
            device.dhcp_vendor_class = payload.dhcp_vendor_class
        if payload.dhcp_fingerprint:
            device.dhcp_fingerprint = payload.dhcp_fingerprint
        device.last_seen = now
    else:
        vendor = _resolve_vendor(mac, payload.hostname) or _resolve_vendor(payload.mac_address, payload.hostname)
        device = Device(
            mac_address=mac,
            hostname=payload.hostname,
            vendor=vendor,
            ja4_fingerprint=payload.ja4,
            ja4_last_seen=now if payload.ja4 else None,
            dhcp_vendor_class=payload.dhcp_vendor_class,
            dhcp_fingerprint=payload.dhcp_fingerprint,
            first_seen=now,
            last_seen=now,
        )
        db.add(device)

    # Upsert DeviceIP — never steal an IP from a real MAC to a placeholder
    dev_ip = db.query(DeviceIP).filter(DeviceIP.ip == payload.ip).first()
    if dev_ip:
        # Only reassign if new MAC is real, or existing is also placeholder
        if not mac.startswith("unknown_") or dev_ip.mac_address.startswith("unknown_"):
            dev_ip.mac_address = mac
        dev_ip.last_seen = now
    else:
        dev_ip = DeviceIP(
            ip=payload.ip,
            mac_address=mac,
            first_seen=now,
            last_seen=now,
        )
        db.add(dev_ip)

    # ── TLS fingerprint tuple recording ─────────────────────────────
    # When the sensor reports (ja4, ja4s, sni), upsert a row in
    # tls_fingerprints keyed on (mac, ja4, ja4s, sni). Hit count grows,
    # last_seen updates. This builds the dataset for later context-aware
    # service classification (Phase 2).
    if payload.ja4 or payload.ja4s or payload.sni:
        tls_row = (
            db.query(TlsFingerprint)
            .filter(
                TlsFingerprint.mac_address == mac,
                TlsFingerprint.ja4 == payload.ja4,
                TlsFingerprint.ja4s == payload.ja4s,
                TlsFingerprint.sni == payload.sni,
            )
            .first()
        )
        if tls_row:
            tls_row.hit_count += 1
            tls_row.last_seen = now
        else:
            db.add(TlsFingerprint(
                mac_address=mac,
                ja4=payload.ja4,
                ja4s=payload.ja4s,
                sni=payload.sni,
                first_seen=now,
                last_seen=now,
                hit_count=1,
            ))

    db.commit()
    db.refresh(device)
    return device


@app.get("/api/debug/tls-fingerprints")
def debug_tls_fingerprints(
    mac: Optional[str] = None,
    sni: Optional[str] = None,
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    """Inspect the (mac, ja4, ja4s, sni) tuples observed so far.

    Used to verify that Phase 1 data collection is working and to
    explore which tuples exist before we wire up Phase 2 classification.
    """
    q = db.query(TlsFingerprint)
    if mac:
        q = q.filter(TlsFingerprint.mac_address == mac)
    if sni:
        q = q.filter(TlsFingerprint.sni == sni)
    rows = q.order_by(TlsFingerprint.hit_count.desc()).limit(limit).all()

    # Enrich with device info so the dataset is readable in the browser
    result = []
    for r in rows:
        dev = db.query(Device).filter(Device.mac_address == r.mac_address).first()
        result.append({
            "mac_address": r.mac_address,
            "hostname": dev.hostname if dev else None,
            "display_name": dev.display_name if dev else None,
            "vendor": dev.vendor if dev else None,
            "device_class": dev.device_class if dev else None,
            "dhcp_vendor_class": dev.dhcp_vendor_class if dev else None,
            "ja4": r.ja4,
            "ja4s": r.ja4s,
            "sni": r.sni,
            "hit_count": r.hit_count,
            "first_seen": str(r.first_seen),
            "last_seen": str(r.last_seen),
        })
    return {
        "total_rows": len(result),
        "tuples": result,
    }


@app.post("/api/devices/fingerprint")
def update_device_fingerprint(payload: dict, db: Session = Depends(get_db)):
    """Update a device's OS fingerprint from p0f data.

    Expects: {ip, os_name, os_version, os_full, device_class, network_distance}
    Looks up the device by IP → DeviceIP → Device.
    """
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip' field")

    # Find device owning this IP
    dev_ip = db.query(DeviceIP).filter(DeviceIP.ip == ip).first()
    if not dev_ip:
        raise HTTPException(status_code=404, detail=f"No device found for IP {ip}")

    device = db.query(Device).filter(Device.mac_address == dev_ip.mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device record missing for MAC {dev_ip.mac_address}")

    # Update fingerprint fields
    if payload.get("os_name"):
        device.os_name = payload["os_name"]
    if payload.get("os_version"):
        device.os_version = payload["os_version"]
    if payload.get("os_full"):
        device.os_full = payload["os_full"]
    if payload.get("device_class") and payload["device_class"] != "unknown":
        device.device_class = payload["device_class"]
    if payload.get("network_distance") is not None:
        device.network_distance = payload["network_distance"]
    device.p0f_last_seen = datetime.utcnow()

    db.commit()
    db.refresh(device)
    return {"status": "ok", "mac": device.mac_address, "os": device.os_full}


@app.put("/api/devices/{mac_address:path}", response_model=DeviceRead)
def rename_device(mac_address: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.mac_address == mac_address).first()
    if not device:
        # Fallback: try to find by IP (for backwards compat with old frontend)
        dev_ip = db.query(DeviceIP).filter(DeviceIP.ip == mac_address).first()
        if dev_ip:
            device = db.query(Device).filter(Device.mac_address == dev_ip.mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.display_name = payload.display_name
    db.commit()
    db.refresh(device)
    return device


# ---------------------------------------------------------------------------
# GET/PUT /api/hostname-vendors — user-editable hostname → vendor mapping
# ---------------------------------------------------------------------------
@app.get("/api/hostname-vendors")
def get_hostname_vendors():
    """Return the current hostname→vendor mapping list."""
    return _hostname_vendors


@app.put("/api/hostname-vendors")
def update_hostname_vendors(entries: list[dict]):
    """Replace the hostname→vendor mapping. Persists to disk.

    Body: [{"keywords": ["kobo"], "vendor": "Kobo Inc."}, ...]
    """
    global _hostname_vendors
    # Validate
    for entry in entries:
        if "keywords" not in entry or "vendor" not in entry:
            raise HTTPException(400, "Each entry needs 'keywords' (list) and 'vendor' (str)")
        if not isinstance(entry["keywords"], list):
            raise HTTPException(400, "'keywords' must be a list of strings")
    # Save
    try:
        os.makedirs(os.path.dirname(_HOSTNAME_VENDORS_FILE), exist_ok=True)
        with open(_HOSTNAME_VENDORS_FILE, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception as exc:
        raise HTTPException(500, f"Could not save: {exc}")
    _hostname_vendors = entries
    return {"status": "ok", "count": len(entries)}


# ---------------------------------------------------------------------------
# Geo Traffic — aggregated country-level inbound/outbound bytes
# ---------------------------------------------------------------------------
@app.post("/api/geo/ingest")
def geo_ingest(payload: dict, db: Session = Depends(get_db)):
    """Batch ingest endpoint for the Zeek tailer's geo buffer.

    Body: {"updates": [{"country_code": "NL", "direction": "outbound",
                        "bytes": 12345, "hits": 3}, ...]}
    """
    updates = payload.get("updates") or []
    if not isinstance(updates, list):
        raise HTTPException(status_code=400, detail="updates must be a list")
    now = datetime.utcnow()
    for u in updates:
        cc = (u.get("country_code") or "").upper()[:2]
        direction = u.get("direction") or ""
        if direction not in ("outbound", "inbound") or not cc:
            continue
        byts = int(u.get("bytes") or 0)
        hits = int(u.get("hits") or 0)
        if byts <= 0 and hits <= 0:
            continue
        row = (
            db.query(GeoTraffic)
            .filter(
                GeoTraffic.country_code == cc,
                GeoTraffic.direction == direction,
            )
            .first()
        )
        if row:
            row.bytes_transferred += byts
            row.hits += hits
            row.last_seen = now
        else:
            db.add(GeoTraffic(
                country_code=cc,
                direction=direction,
                bytes_transferred=byts,
                hits=hits,
                last_seen=now,
            ))
    db.commit()
    return {"status": "ok", "accepted": len(updates)}


_IOT_COUNTRY_DEDUP_SECONDS = 3600
_iot_country_alert_last: dict[tuple, float] = {}


@app.post("/api/geo/conversations/ingest")
def ingest_geo_conversations(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
):
    """Tailer ingests buffered geo conversations (one row per
    country/direction/mac/service/resp_ip tuple accumulated in the
    15s window).

    Body:
      {"updates": [
          {"country_code": "US", "direction": "outbound",
           "mac_address": "aa:bb:...", "ai_service": "spotify",
           "resp_ip": "35.186.x.x", "bytes": 12345, "hits": 3},
          ...
      ]}
    """
    updates = payload.get("updates") or []
    if not isinstance(updates, list):
        raise HTTPException(status_code=400, detail="updates must be a list")
    now = datetime.utcnow()
    now_ts = time.time()
    unseen_ips: set[str] = set()
    accepted = 0

    # Pre-load baselines + IoT classification for new-country alerting
    import json as _json
    _baselines = {b.mac_address: b for b in db.query(DeviceBaseline).all()}
    _all_devices = {d.mac_address: d for d in db.query(Device).all()}
    _mac_to_ip = {}
    for dip in db.query(DeviceIP).all():
        _mac_to_ip.setdefault(dip.mac_address, dip.ip)

    for u in updates:
        cc = (u.get("country_code") or "").upper()[:2]
        direction = u.get("direction") or ""
        resp_ip = u.get("resp_ip") or ""
        if direction not in ("outbound", "inbound") or not cc or not resp_ip:
            continue
        mac = u.get("mac_address") or None
        svc = u.get("ai_service") or "unknown"
        byts = int(u.get("bytes") or 0)
        hits = int(u.get("hits") or 0)
        if byts <= 0 and hits <= 0:
            continue
        row = (
            db.query(GeoConversation)
            .filter(
                GeoConversation.country_code == cc,
                GeoConversation.direction == direction,
                GeoConversation.mac_address == mac,
                GeoConversation.ai_service == svc,
                GeoConversation.resp_ip == resp_ip,
            )
            .first()
        )
        if row:
            row.bytes_transferred += byts
            row.hits += hits
            row.last_seen = now
        else:
            db.add(GeoConversation(
                country_code=cc,
                direction=direction,
                mac_address=mac,
                ai_service=svc,
                resp_ip=resp_ip,
                bytes_transferred=byts,
                hits=hits,
                first_seen=now,
                last_seen=now,
            ))
            unseen_ips.add(resp_ip)
        accepted += 1

        # --- IoT new-country alert ---
        # If this is an IoT device talking to a country not in its baseline,
        # create a DetectionEvent.
        if mac and cc and direction == "outbound":
            dev = _all_devices.get(mac)
            if dev and _is_iot_backend(dev):
                bl = _baselines.get(mac)
                if bl and bl.known_countries:
                    try:
                        known = _json.loads(bl.known_countries)
                    except (ValueError, TypeError):
                        known = []
                    if cc not in known:
                        dk = (mac, cc)
                        if (now_ts - _iot_country_alert_last.get(dk, 0)) >= _IOT_COUNTRY_DEDUP_SECONDS:
                            _iot_country_alert_last[dk] = now_ts
                            src_ip = _mac_to_ip.get(mac, mac)
                            db.add(DetectionEvent(
                                sensor_id="airadar",
                                timestamp=now,
                                detection_type="iot_new_country",
                                ai_service=f"country_{cc}",
                                source_ip=src_ip,
                                bytes_transferred=byts,
                                category="security",
                            ))
    db.commit()

    # Return the set of resp_ips that don't yet have metadata so the
    # tailer can enrich them next cycle. Fetch in one IN query to
    # avoid per-ip roundtrips.
    to_enrich: list[str] = []
    if unseen_ips:
        have = {
            r[0]
            for r in db.query(IpMetadata.ip)
            .filter(IpMetadata.ip.in_(list(unseen_ips)))
            .all()
        }
        to_enrich = [ip for ip in unseen_ips if ip not in have]

    return {"status": "ok", "accepted": accepted, "enrich": to_enrich}


@app.get("/api/geo/metadata/missing_asn")
def list_missing_asn(
    limit: int = Query(5000, ge=1, le=20000),
    db: Session = Depends(get_db),
):
    """Return IPs in ip_metadata that don't have an ASN resolved yet.

    Used by the tailer's backfill_missing_asn startup task to catch up
    after a first-boot where the ASN MMDB was downloaded mid-run.
    """
    rows = (
        db.query(IpMetadata.ip)
        .filter(IpMetadata.asn.is_(None))
        .limit(limit)
        .all()
    )
    return {"ips": [r[0] for r in rows]}


@app.post("/api/geo/metadata/ingest")
def ingest_ip_metadata(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
):
    """Tailer pushes resolved PTR/ASN data for a batch of IPs.

    Body: {"entries": [{"ip": "...", "ptr": "...", "asn": 15169,
                        "asn_org": "Google LLC", "country_code": "US"}, ...]}
    """
    entries = payload.get("entries") or []
    if not isinstance(entries, list):
        raise HTTPException(status_code=400, detail="entries must be a list")
    now = datetime.utcnow()
    for e in entries:
        ip = e.get("ip") or ""
        if not ip:
            continue
        row = db.query(IpMetadata).filter(IpMetadata.ip == ip).first()
        if row:
            row.ptr = e.get("ptr") or row.ptr
            row.asn = e.get("asn") if e.get("asn") is not None else row.asn
            row.asn_org = e.get("asn_org") or row.asn_org
            row.country_code = e.get("country_code") or row.country_code
            row.updated_at = now
        else:
            db.add(IpMetadata(
                ip=ip,
                ptr=e.get("ptr"),
                asn=e.get("asn"),
                asn_org=e.get("asn_org"),
                country_code=e.get("country_code"),
                updated_at=now,
            ))
    db.commit()
    return {"status": "ok", "accepted": len(entries)}


@app.get("/api/analytics/geo")
def get_geo_traffic(
    direction: str = Query("outbound", description="outbound or inbound"),
    service: Optional[str] = Query(None, description="Filter to a single ai_service"),
    source_ip: Optional[str] = Query(None, description="Filter to a single device IP"),
    start: Optional[datetime] = Query(None, description="Only include conversations active since this ISO timestamp"),
    db: Session = Depends(get_db),
):
    """Return per-country bandwidth totals for the dashboard map.

    Without filters the heavy-lifting uses the pre-aggregated GeoTraffic
    rollup. As soon as any filter is supplied we switch to the
    high-resolution GeoConversation table so we can apply device /
    service / period constraints; that costs a bit more per request
    but only fires when the user actually filters.

    The top-3 devices-per-country list and the opposite-direction byte
    total (used for in/out ratio shading) are computed from
    GeoConversation in both code paths so they respect the filters.
    """
    if direction not in ("outbound", "inbound"):
        raise HTTPException(status_code=400, detail="direction must be outbound or inbound")
    other = "inbound" if direction == "outbound" else "outbound"

    # Resolve source_ip to the owning MAC (if any) so device filter
    # matches both IPv4 and IPv6 traffic from the same device.
    filter_mac = None
    if source_ip:
        dip = db.query(DeviceIP).filter(DeviceIP.ip == source_ip).first()
        if dip:
            filter_mac = dip.mac_address

    filters_active = bool(service or source_ip or start)

    def _apply_conv_filters(q, direction_val):
        q = q.filter(GeoConversation.direction == direction_val)
        if service:
            q = q.filter(GeoConversation.ai_service == service)
        if filter_mac:
            q = q.filter(GeoConversation.mac_address == filter_mac)
        if start:
            q = q.filter(GeoConversation.last_seen >= start)
        return q

    if filters_active:
        # Compute country totals from GeoConversation so filters apply.
        agg_rows = (
            _apply_conv_filters(
                db.query(
                    GeoConversation.country_code,
                    func.coalesce(func.sum(GeoConversation.bytes_transferred), 0).label("bytes"),
                    func.coalesce(func.sum(GeoConversation.hits), 0).label("hits"),
                    func.max(GeoConversation.last_seen).label("last_seen"),
                ),
                direction,
            )
            .group_by(GeoConversation.country_code)
            .order_by(func.sum(GeoConversation.bytes_transferred).desc())
            .all()
        )
        rows = agg_rows  # list of Row objects; accessed as r.country_code etc.
    else:
        rows = (
            db.query(GeoTraffic)
            .filter(GeoTraffic.direction == direction)
            .order_by(GeoTraffic.bytes_transferred.desc())
            .all()
        )

    # Pull the opposite direction in one query so we can compute the
    # in/out ratio without an extra round-trip per row.
    if filters_active:
        opp_rows = (
            _apply_conv_filters(
                db.query(
                    GeoConversation.country_code,
                    func.coalesce(func.sum(GeoConversation.bytes_transferred), 0).label("bytes"),
                ),
                other,
            )
            .group_by(GeoConversation.country_code)
            .all()
        )
        opp_map = {r.country_code: int(r.bytes or 0) for r in opp_rows}
    else:
        opp_map = {
            r.country_code: r.bytes_transferred
            for r in db.query(GeoTraffic).filter(GeoTraffic.direction == other).all()
        }

    # Top-3 devices per country (in the requested direction) from the
    # high-resolution conversations table, respecting the same filters.
    conv_rows = (
        _apply_conv_filters(
            db.query(
                GeoConversation.country_code,
                GeoConversation.mac_address,
                func.sum(GeoConversation.bytes_transferred).label("bytes"),
            ),
            direction,
        )
        .group_by(GeoConversation.country_code, GeoConversation.mac_address)
        .all()
    )
    # Resolve MAC → display name once
    devs = {d.mac_address: d for d in db.query(Device).all()}
    top_by_cc: dict[str, list[dict]] = {}
    for cc, mac, byts in conv_rows:
        if not mac:
            continue
        top_by_cc.setdefault(cc, []).append({
            "mac": mac,
            "name": (devs.get(mac).display_name or devs.get(mac).hostname or mac) if mac in devs else mac,
            "bytes": int(byts or 0),
        })
    for cc in top_by_cc:
        top_by_cc[cc].sort(key=lambda x: -x["bytes"])
        top_by_cc[cc] = top_by_cc[cc][:3]

    # Normalise the two row shapes (GeoTraffic model row vs aggregated
    # conversations Row) into the same country dict.
    countries_out = []
    for r in rows:
        if filters_active:
            # Aggregated row from GeoConversation query: r.bytes, r.hits
            country_code = r.country_code
            byts = int(r.bytes or 0)
            hits = int(r.hits or 0)
            last_seen = str(r.last_seen) if r.last_seen else ""
        else:
            # GeoTraffic model row
            country_code = r.country_code
            byts = r.bytes_transferred
            hits = r.hits
            last_seen = str(r.last_seen)
        countries_out.append({
            "country_code": country_code,
            "bytes": byts,
            "hits": hits,
            "last_seen": last_seen,
            "opposite_bytes": int(opp_map.get(country_code, 0)),
            "top_devices": top_by_cc.get(country_code, []),
        })

    return {
        "direction": direction,
        "countries": countries_out,
    }


@app.get("/api/analytics/geo/country/{country_code}")
def get_country_detail(
    country_code: str,
    direction: str = Query("outbound", description="outbound or inbound"),
    db: Session = Depends(get_db),
):
    """Drilldown for one country: top devices, top services, top remote
    IPs (with cached ASN / PTR), and an hourly timeline.
    """
    cc = (country_code or "").upper()[:2]
    if not cc:
        raise HTTPException(status_code=400, detail="country_code required")
    if direction not in ("outbound", "inbound"):
        raise HTTPException(status_code=400, detail="direction must be outbound or inbound")

    base = db.query(GeoConversation).filter(
        GeoConversation.country_code == cc,
        GeoConversation.direction == direction,
    )

    # Totals
    total_bytes = db.query(
        func.coalesce(func.sum(GeoConversation.bytes_transferred), 0)
    ).filter(
        GeoConversation.country_code == cc,
        GeoConversation.direction == direction,
    ).scalar() or 0
    total_hits = db.query(
        func.coalesce(func.sum(GeoConversation.hits), 0)
    ).filter(
        GeoConversation.country_code == cc,
        GeoConversation.direction == direction,
    ).scalar() or 0

    # Top devices
    dev_rows = (
        db.query(
            GeoConversation.mac_address,
            func.sum(GeoConversation.bytes_transferred).label("bytes"),
            func.sum(GeoConversation.hits).label("hits"),
            func.max(GeoConversation.last_seen).label("last_seen"),
        )
        .filter(
            GeoConversation.country_code == cc,
            GeoConversation.direction == direction,
        )
        .group_by(GeoConversation.mac_address)
        .order_by(func.sum(GeoConversation.bytes_transferred).desc())
        .limit(15)
        .all()
    )
    devs = {d.mac_address: d for d in db.query(Device).all()}
    top_devices = []
    for mac, byts, hits, lseen in dev_rows:
        d = devs.get(mac) if mac else None
        top_devices.append({
            "mac": mac,
            "name": (d.display_name or d.hostname or mac) if d else (mac or "unknown"),
            "vendor": d.vendor if d else None,
            "bytes": int(byts or 0),
            "hits": int(hits or 0),
            "last_seen": str(lseen) if lseen else None,
        })

    # Top services
    svc_rows = (
        db.query(
            GeoConversation.ai_service,
            func.sum(GeoConversation.bytes_transferred).label("bytes"),
            func.sum(GeoConversation.hits).label("hits"),
        )
        .filter(
            GeoConversation.country_code == cc,
            GeoConversation.direction == direction,
        )
        .group_by(GeoConversation.ai_service)
        .order_by(func.sum(GeoConversation.bytes_transferred).desc())
        .limit(15)
        .all()
    )
    top_services = [
        {"service": s, "bytes": int(b or 0), "hits": int(h or 0)}
        for s, b, h in svc_rows
    ]

    # Top IPs with ASN/PTR join
    ip_rows = (
        db.query(
            GeoConversation.resp_ip,
            func.sum(GeoConversation.bytes_transferred).label("bytes"),
            func.sum(GeoConversation.hits).label("hits"),
            func.max(GeoConversation.last_seen).label("last_seen"),
        )
        .filter(
            GeoConversation.country_code == cc,
            GeoConversation.direction == direction,
        )
        .group_by(GeoConversation.resp_ip)
        .order_by(func.sum(GeoConversation.bytes_transferred).desc())
        .limit(20)
        .all()
    )
    ip_list = [ip for ip, *_ in ip_rows]
    meta_map = {
        m.ip: m
        for m in db.query(IpMetadata).filter(IpMetadata.ip.in_(ip_list)).all()
    } if ip_list else {}
    top_ips = []
    for ip, byts, hits, lseen in ip_rows:
        m = meta_map.get(ip)
        top_ips.append({
            "ip": ip,
            "bytes": int(byts or 0),
            "hits": int(hits or 0),
            "last_seen": str(lseen) if lseen else None,
            # 'enriched' tells the UI whether the metadata lookup has
            # already completed (possibly with NULL results) vs still
            # pending. Without this, the frontend can't distinguish
            # 'enriching…' from 'resolved but no rDNS/ASN available'.
            "enriched": m is not None,
            "ptr": m.ptr if m else None,
            "asn": m.asn if m else None,
            "asn_org": m.asn_org if m else None,
        })

    return {
        "country_code": cc,
        "direction": direction,
        "total_bytes": int(total_bytes),
        "total_hits": int(total_hits),
        "top_devices": top_devices,
        "top_services": top_services,
        "top_ips": top_ips,
    }


# ---------------------------------------------------------------------------
# Policy Engine — ServicePolicy CRUD + AlertException CRUD + /api/alerts/active
# ---------------------------------------------------------------------------
#
# Architecture:
#
#   ServicePolicy governs STANDARD traffic (ai, cloud, gaming, social,
#   streaming, tracking). For each detection event we resolve a policy
#   action in this priority order (most specific wins):
#
#       1. device + service_name match
#       2. device + category match
#       3. global + service_name match
#       4. global + category match
#
#   The resolved action is one of {"allow", "alert", "block"}. For now,
#   both "alert" and "block" cause the event to surface as an ActiveAlert
#   (so the user sees attempted access even after blocking is active).
#
#   AlertException governs ANOMALY traffic (vpn_tunnel, stealth_vpn_tunnel,
#   beaconing_threat). Anomalies are always alerted unless a matching
#   exception snoozes or whitelists them.
#
#   Default behaviour when no policy exists:
#     - Standard traffic → "allow"  (no alert)
#     - possible_upload==True → "alert"  (exfiltration risk)
#     - Anomalies → always alert (exception required to silence)
# ---------------------------------------------------------------------------

# Detection types that are treated as anomalies (policy-bypass, exception-only)
_ANOMALY_DETECTION_TYPES = {
    "vpn_tunnel",
    "stealth_vpn_tunnel",
    "beaconing_threat",
    "iot_lateral_movement",
    "iot_suspicious_port",
    "iot_new_country",
    "iot_volume_spike",
    "inbound_threat",
    "inbound_port_scan",
}


@app.get("/api/policies", response_model=list[ServicePolicyRead])
def list_policies(
    scope: Optional[str] = Query(None, description="filter by scope: global|group|device"),
    mac_address: Optional[str] = Query(None),
    group_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(ServicePolicy)
    if scope:
        q = q.filter(ServicePolicy.scope == scope)
    if mac_address:
        q = q.filter(ServicePolicy.mac_address == mac_address)
    if group_id:
        q = q.filter(ServicePolicy.group_id == group_id)
    return q.order_by(
        ServicePolicy.scope.desc(),
        ServicePolicy.updated_at.desc(),
    ).all()


async def _sync_policy_to_adguard(policy: ServicePolicy) -> None:
    """Keep AdGuard's blocklist in sync with a ServicePolicy.

    Only GLOBAL policies that target a specific service_name can translate
    to DNS-level blocking (AdGuard has no per-device DNS rules and no
    concept of "a whole category"). For those:
      - action=="block"            → ensure protection is ON + block all domains
      - action in ("allow","alert") → unblock all domains
    For device-scoped or category-only policies, AdGuard is not touched —
    those are handled at the alert/visibility layer only.

    When the first block action is applied, we automatically enable
    AdGuard protection (with all subscription lists disabled — so only
    our explicit custom rules take effect). This way the user never
    has to manually toggle DNS filtering ON.
    """
    if policy.scope != "global":
        return
    if not policy.service_name:
        return
    info = SERVICE_DOMAINS.get(policy.service_name)
    if not info:
        # Unknown service — can't figure out its domains
        return
    domains = info.get("domains") or []
    if not domains:
        return

    if policy.action == "block":
        # Ensure protection is ON (with subscription lists disabled)
        # so our custom block rules actually take effect. This is a
        # no-op if protection is already enabled.
        if not await adguard.is_protection_enabled():
            await adguard.set_protection(True)
            _write_adguard_protection_pref(True)
            print("[policy] AdGuard protection auto-enabled for block rule")
        for domain in domains:
            try:
                await adguard.block_domain(domain)
            except Exception as exc:
                print(f"[policy] AdGuard block_domain({domain}) failed: {exc}")
    else:
        # allow or alert → ensure the domain is NOT blocked in AdGuard
        for domain in domains:
            try:
                await adguard.unblock_domain(domain)
            except Exception as exc:
                print(f"[policy] AdGuard unblock_domain({domain}) failed: {exc}")


@app.post("/api/policies", response_model=ServicePolicyRead, status_code=201)
async def upsert_policy(payload: ServicePolicyCreate, db: Session = Depends(get_db)):
    """Create or update a service policy.

    A policy is uniquely identified by (scope, mac_address, service_name,
    category). If an existing row matches, it is updated in place instead
    of duplicating — this keeps the UI idempotent ("turn on alert for
    Roblox on Jantje's iPad" can be clicked multiple times safely).

    When a global per-service policy changes action, the AdGuard blocklist
    is synced automatically so the ServicePolicy table is the single
    source of truth for both dashboard alerts AND real DNS blocking.
    """
    if payload.scope not in ("global", "group", "device"):
        raise HTTPException(status_code=400, detail="scope must be 'global', 'group', or 'device'")
    if payload.scope == "device" and not payload.mac_address:
        raise HTTPException(status_code=400, detail="mac_address is required when scope='device'")
    if payload.scope == "group" and not payload.group_id:
        raise HTTPException(status_code=400, detail="group_id is required when scope='group'")
    if payload.scope == "global" and (payload.mac_address or payload.group_id):
        raise HTTPException(status_code=400, detail="mac_address and group_id must be null when scope='global'")
    if payload.action not in ("allow", "alert", "block"):
        raise HTTPException(status_code=400, detail="action must be 'allow', 'alert' or 'block'")
    if not payload.service_name and not payload.category:
        raise HTTPException(status_code=400, detail="either service_name or category must be set")

    existing = (
        db.query(ServicePolicy)
        .filter(
            ServicePolicy.scope == payload.scope,
            ServicePolicy.mac_address == payload.mac_address,
            ServicePolicy.group_id == payload.group_id,
            ServicePolicy.service_name == payload.service_name,
            ServicePolicy.category == payload.category,
        )
        .first()
    )
    now = datetime.utcnow()
    if existing:
        existing.action = payload.action
        existing.expires_at = payload.expires_at
        existing.updated_at = now
        db.commit()
        db.refresh(existing)
        await _sync_policy_to_adguard(existing)
        return existing

    policy = ServicePolicy(
        scope=payload.scope,
        mac_address=payload.mac_address,
        group_id=payload.group_id,
        service_name=payload.service_name,
        category=payload.category,
        action=payload.action,
        expires_at=payload.expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    await _sync_policy_to_adguard(policy)
    return policy


@app.delete("/api/policies/{policy_id}", status_code=204)
async def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    policy = db.query(ServicePolicy).filter(ServicePolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    # If we were actively blocking this service in AdGuard, unblock it
    # before removing the policy row so the system returns to default.
    was_blocking = (
        policy.scope == "global"
        and policy.action == "block"
        and policy.service_name
    )
    db.delete(policy)
    db.commit()
    if was_blocking:
        info = SERVICE_DOMAINS.get(policy.service_name)
        if info:
            for domain in info.get("domains", []):
                try:
                    await adguard.unblock_domain(domain)
                except Exception as exc:
                    print(f"[policy] AdGuard unblock_domain({domain}) on delete failed: {exc}")
    return None


@app.get("/api/exceptions", response_model=list[AlertExceptionRead])
def list_exceptions(
    mac_address: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    include_expired: bool = Query(False),
    db: Session = Depends(get_db),
):
    q = db.query(AlertException)
    if mac_address:
        q = q.filter(AlertException.mac_address == mac_address)
    if alert_type:
        q = q.filter(AlertException.alert_type == alert_type)
    if not include_expired:
        now = datetime.utcnow()
        q = q.filter(
            (AlertException.expires_at.is_(None)) | (AlertException.expires_at > now)
        )
    return q.order_by(AlertException.created_at.desc()).all()


@app.post("/api/exceptions", response_model=AlertExceptionRead, status_code=201)
def create_exception(payload: AlertExceptionCreate, db: Session = Depends(get_db)):
    if not payload.mac_address or not payload.alert_type:
        raise HTTPException(status_code=400, detail="mac_address and alert_type are required")
    exc = AlertException(
        mac_address=payload.mac_address,
        alert_type=payload.alert_type,
        destination=payload.destination,
        expires_at=payload.expires_at,
        created_at=datetime.utcnow(),
    )
    db.add(exc)
    db.commit()
    db.refresh(exc)
    return exc


@app.delete("/api/exceptions/{exception_id}", status_code=204)
def delete_exception(exception_id: int, db: Session = Depends(get_db)):
    exc = db.query(AlertException).filter(AlertException.id == exception_id).first()
    if not exc:
        raise HTTPException(status_code=404, detail="Exception not found")
    db.delete(exc)
    db.commit()
    return None


# ---------------------------------------------------------------------------
# Policy resolver + exception matcher (used by /api/alerts/active)
# ---------------------------------------------------------------------------

def _resolve_policy_action(
    policies: list,
    mac: Optional[str],
    service_name: Optional[str],
    category: Optional[str],
    device_group_ids: Optional[list] = None,
) -> Optional[str]:
    """Return the resolved action string ("allow"/"alert"/"block") or None.

    Priority order (most specific first):
      1. device + service_name
      2. device + category
      3. child-group + service_name  (most restrictive if multiple groups)
      4. child-group + category
      5. parent-group + service_name
      6. parent-group + category
      7. global + service_name
      8. global + category

    When a device belongs to multiple groups at the same nesting level,
    the most restrictive action wins (block > alert > allow).

    Policies with an expires_at in the past are treated as non-existent.
    """
    now = datetime.utcnow()
    _action_rank = {"block": 3, "alert": 2, "allow": 1}

    def _first(pred):
        for p in policies:
            if p.expires_at and p.expires_at <= now:
                continue
            if pred(p):
                return p.action
        return None

    def _most_restrictive(pred):
        """Among all matching policies, return the most restrictive action."""
        best = None
        for p in policies:
            if p.expires_at and p.expires_at <= now:
                continue
            if pred(p):
                if best is None or _action_rank.get(p.action, 0) > _action_rank.get(best, 0):
                    best = p.action
        return best

    # 1. device + service_name
    if mac and service_name:
        hit = _first(lambda p: p.scope == "device"
                     and p.mac_address == mac
                     and p.service_name == service_name)
        if hit:
            return hit
    # 2. device + category
    if mac and category:
        hit = _first(lambda p: p.scope == "device"
                     and p.mac_address == mac
                     and p.category == category
                     and not p.service_name)
        if hit:
            return hit

    # 3-6. Group policies (child-groups first, then parent-groups)
    # device_group_ids is pre-fetched: [(group_id, parent_id), ...]
    if device_group_ids:
        child_ids = [gid for gid, pid in device_group_ids if pid is not None]
        parent_ids = [gid for gid, pid in device_group_ids if pid is None]

        # 3. child-group + service_name (most restrictive wins)
        if child_ids and service_name:
            hit = _most_restrictive(lambda p: p.scope == "group"
                                    and p.group_id in child_ids
                                    and p.service_name == service_name)
            if hit:
                return hit
        # 4. child-group + category
        if child_ids and category:
            hit = _most_restrictive(lambda p: p.scope == "group"
                                    and p.group_id in child_ids
                                    and p.category == category
                                    and not p.service_name)
            if hit:
                return hit
        # 5. parent-group + service_name
        if parent_ids and service_name:
            hit = _most_restrictive(lambda p: p.scope == "group"
                                    and p.group_id in parent_ids
                                    and p.service_name == service_name)
            if hit:
                return hit
        # 6. parent-group + category
        if parent_ids and category:
            hit = _most_restrictive(lambda p: p.scope == "group"
                                    and p.group_id in parent_ids
                                    and p.category == category
                                    and not p.service_name)
            if hit:
                return hit

    # 7. global + service_name
    if service_name:
        hit = _first(lambda p: p.scope == "global"
                     and not p.mac_address
                     and p.service_name == service_name)
        if hit:
            return hit
    # 8. global + category
    if category:
        hit = _first(lambda p: p.scope == "global"
                     and not p.mac_address
                     and p.category == category
                     and not p.service_name)
        if hit:
            return hit
    return None


def _is_exception_active(
    exceptions: list,
    mac: Optional[str],
    alert_type: str,
    destination: Optional[str],
    now: datetime,
) -> bool:
    """True if a non-expired AlertException matches this alert."""
    for exc in exceptions:
        if exc.mac_address != mac:
            continue
        if exc.alert_type != alert_type:
            continue
        # destination match: NULL in exception = wildcard
        if exc.destination and exc.destination != destination:
            continue
        if exc.expires_at is not None and exc.expires_at <= now:
            continue
        return True
    return False


def _expired_exception_cutoff(
    expired_exceptions: list,
    mac: Optional[str],
    alert_type: str,
    destination: Optional[str],
) -> Optional[datetime]:
    """Return the latest expires_at from matching expired exceptions.

    Events that occurred before this cutoff were already "handled"
    (snoozed or dismissed) and should not reappear after the exception
    expires.  Returns None if no matching expired exception exists.
    """
    latest = None
    for exc in expired_exceptions:
        if exc.mac_address != mac:
            continue
        if exc.alert_type != alert_type:
            continue
        if exc.destination and exc.destination != destination:
            continue
        if latest is None or exc.expires_at > latest:
            latest = exc.expires_at
    return latest


# ---------------------------------------------------------------------------
# GET /api/alerts/active — the unified alert feed
# ---------------------------------------------------------------------------

@app.get("/api/alerts/active")
def get_active_alerts(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Return the currently-active alerts after policy + exception resolution.

    Steps:
      1. Load recent events (last N hours).
      2. Pre-fetch all policies and active exceptions so we don't hit
         the DB per event.
      3. For each event, classify as anomaly vs standard traffic.
         - Anomaly: alert unless a matching exception exists.
         - Standard: consult ServicePolicy, alert if action is "alert"
           or "block". Default is "allow" except for possible_upload
           which defaults to "alert".
      4. Group the resulting alerts by (mac_address, alert_type,
         service_or_dest) so repeated hits collapse into one row.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    now = datetime.utcnow()

    # Eager-load policies + exceptions + group memberships once
    policies = db.query(ServicePolicy).all()
    all_memberships = db.query(DeviceGroupMember).all()
    group_parent_map = {
        g.id: g.parent_id
        for g in db.query(DeviceGroup).all()
    }
    # Active exceptions suppress alerts entirely while active.
    exceptions = db.query(AlertException).filter(
        (AlertException.expires_at.is_(None)) | (AlertException.expires_at > now)
    ).all()

    # Expired exceptions (within the query window) prevent old events from
    # reappearing after a snooze/dismiss expires.  Only events that occurred
    # AFTER the exception expired will surface as new alerts.
    expired_exceptions = db.query(AlertException).filter(
        AlertException.expires_at.isnot(None),
        AlertException.expires_at <= now,
        AlertException.expires_at >= cutoff,
    ).all()

    # Build IP → (mac, device) lookup map
    dev_ip_rows = db.query(DeviceIP).all()
    ip_to_mac: dict[str, str] = {d.ip: d.mac_address for d in dev_ip_rows}
    device_by_mac: dict[str, Device] = {
        d.mac_address: d for d in db.query(Device).all()
    }

    events = (
        db.query(DetectionEvent)
        .filter(DetectionEvent.timestamp >= cutoff)
        .order_by(DetectionEvent.timestamp.asc())
        .all()
    )

    # Aggregate by (mac, alert_type, service_or_dest)
    groups: dict[tuple, dict] = {}

    for e in events:
        mac = ip_to_mac.get(e.source_ip)

        # ---------- Anomaly path ----------
        if e.detection_type in _ANOMALY_DETECTION_TYPES:
            alert_type = e.detection_type
            destination = e.ai_service  # VPN service name or beacon dst IP
            if _is_exception_active(exceptions, mac, alert_type, destination, now):
                continue
            # Skip events that occurred before an expired exception —
            # they were already handled (snoozed/dismissed) and should
            # not reappear after the exception expires.
            exp_cutoff = _expired_exception_cutoff(
                expired_exceptions, mac, alert_type, destination
            )
            if exp_cutoff and e.timestamp <= exp_cutoff:
                continue
            reason = "anomaly"
        else:
            # ---------- Standard-service path ----------
            # Look up the device's group memberships for group-level policy resolution
            _dev_groups = None
            if mac:
                _memberships = [m for m in all_memberships if m.mac_address == mac]
                if _memberships:
                    _dev_groups = [
                        (m.group_id, group_parent_map.get(m.group_id))
                        for m in _memberships
                    ]
            action = _resolve_policy_action(
                policies, mac, e.ai_service, e.category, _dev_groups
            )
            if action is None:
                # No explicit policy → default allow. The old logic
                # alerted on every upload from services without a policy,
                # flooding the inbox with normal Google Drive / Snapchat /
                # YouTube activity. Now: no policy = allowed, including
                # uploads. Only services with an explicit "alert" or
                # "block" policy generate alerts. The user controls what
                # they want to monitor via the Rules page.
                continue
            else:
                if action == "allow":
                    continue
                reason = f"policy_{action}"

            alert_type = "upload" if e.possible_upload else "service_access"
            destination = e.ai_service

            # Check AlertExceptions for standard-service alerts too —
            # without this, the "Clear all alerts" snooze has no effect
            # on upload / service_access alerts because only the anomaly
            # path was checking exceptions.
            if _is_exception_active(exceptions, mac, alert_type, destination, now):
                continue
            # Skip events handled by expired exceptions
            exp_cutoff = _expired_exception_cutoff(
                expired_exceptions, mac, alert_type, destination
            )
            if exp_cutoff and e.timestamp <= exp_cutoff:
                continue

        key = (mac or e.source_ip, alert_type, destination)
        g = groups.get(key)
        if g is None:
            dev = device_by_mac.get(mac) if mac else None
            groups[key] = {
                "alert_id": f"{key[0]}|{alert_type}|{destination}",
                "mac_address": mac or e.source_ip,
                "hostname": dev.hostname if dev else None,
                "display_name": dev.display_name if dev else None,
                "vendor": dev.vendor if dev else None,
                "alert_type": alert_type,
                "service_or_dest": destination,
                "category": e.category,
                "first_seen": e.timestamp,
                "timestamp": e.timestamp,
                "hits": 0,
                "total_bytes": 0,
                "details": {
                    "reason": reason,
                    "detection_type": e.detection_type,
                },
            }
            g = groups[key]
        g["hits"] += 1
        g["total_bytes"] += e.bytes_transferred or 0
        if e.timestamp > g["timestamp"]:
            g["timestamp"] = e.timestamp
        if e.timestamp < g["first_seen"]:
            g["first_seen"] = e.timestamp

    # --- New device alerts ---
    # Devices whose first_seen is within the alert window are surfaced
    # as "new_device" alerts. This is purely informational — the user
    # sees a new device appeared and can assign it to a group / set rules.
    new_device_alerts = []
    new_devices = (
        db.query(Device)
        .filter(Device.first_seen >= cutoff)
        .order_by(Device.first_seen.desc())
        .all()
    )
    for d in new_devices:
        # Skip if snoozed via AlertException
        if _is_exception_active(exceptions, d.mac_address, "new_device", d.mac_address, now):
            continue
        # Skip devices that were already dismissed — their first_seen
        # predates the expired exception, so they shouldn't reappear.
        exp_cutoff = _expired_exception_cutoff(
            expired_exceptions, d.mac_address, "new_device", d.mac_address
        )
        if exp_cutoff and d.first_seen <= exp_cutoff:
            continue
        device_ips = [dip.ip for dip in d.ips][:3] if d.ips else []
        # Build a short human-readable summary of what we know about this device
        info_parts = []
        if d.vendor:
            info_parts.append(d.vendor)
        if d.os_full or d.os_name:
            info_parts.append(d.os_full or d.os_name)
        if device_ips:
            info_parts.append(", ".join(device_ips))
        new_device_alerts.append({
            "alert_id": f"{d.mac_address}|new_device|{d.mac_address}",
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "display_name": d.display_name,
            "vendor": d.vendor,
            "alert_type": "new_device",
            "service_or_dest": None,
            "category": None,
            "first_seen": d.first_seen,
            "timestamp": d.first_seen,
            "hits": 1,
            "total_bytes": 0,
            "details": {
                "reason": "new_device",
                "detection_type": "new_device",
                "ips": device_ips,
                "info_summary": " · ".join(info_parts) if info_parts else None,
            },
        })

    all_alerts = list(groups.values()) + new_device_alerts

    # Sort: anomalies first, new devices next, then by last_seen desc
    def _priority(item):
        a = item["alert_type"]
        if a in _ANOMALY_DETECTION_TYPES:
            rank = 0
        elif a == "new_device":
            rank = 1
        elif a == "upload":
            rank = 2
        else:
            rank = 3
        return (rank, -item["timestamp"].timestamp())

    result = sorted(all_alerts, key=_priority)
    return {
        "count": len(result),
        "window_hours": hours,
        "alerts": result,
    }


# ---------------------------------------------------------------------------
# GET /api/alerts/ai-summary — Gemini-generated plain-language summary
# ---------------------------------------------------------------------------
@app.get("/api/alerts/ai-summary")
async def alerts_ai_summary(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Return a short, non-technical Dutch summary of active alerts.

    Calls the same resolver as /api/alerts/active, then asks Gemini to
    turn the structured list into 3 sentences the homeowner can act on.
    """
    # Reuse the resolver so the summary is always in sync with what the
    # user sees in the inbox.
    active = get_active_alerts(hours=hours, db=db)
    alerts = active["alerts"]

    if not alerts:
        return {
            "summary": "Alles rustig op je netwerk. Er zijn op dit moment geen meldingen die actie vereisen.",
            "alert_count": 0,
            "model": None,
            "tokens": None,
        }

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        # Graceful fallback: return a deterministic one-liner so the UI
        # still has something to show even without an API key.
        return {
            "summary": f"Er zijn {len(alerts)} actieve meldingen die om aandacht vragen. "
                       f"Configureer GEMINI_API_KEY in .env om een uitgebreide samenvatting te krijgen.",
            "alert_count": len(alerts),
            "model": None,
            "tokens": None,
        }

    # Build a compact text block for the LLM
    lines = []
    for a in alerts[:20]:  # cap at 20 to keep prompt small
        device_name = a.get("display_name") or a.get("hostname") or a.get("mac_address")
        svc = a.get("service_or_dest")
        atype = a.get("alert_type")
        hits = a.get("hits", 0)
        last_seen = a.get("timestamp")
        if hasattr(last_seen, "strftime"):
            last_seen = last_seen.strftime("%Y-%m-%d %H:%M")
        lines.append(f"- {device_name} | {atype} → {svc} | {hits} hits | laatst {last_seen}")
    alert_block = "\n".join(lines)

    system_prompt = (
        "Je bent een netwerkbeveiligingsassistent voor een kleine ondernemer of gezin. "
        "Vat de volgende actieve netwerkmeldingen samen in MAXIMAAL 3 eenvoudige, "
        "niet-technische Nederlandse zinnen. Leg uit welke apparaten aandacht nodig "
        "hebben en waarom. Gebruik geen jargon. Als er geen meldingen zijn, zeg je dat "
        "alles in orde is. Geef GEEN opsomming — alleen lopende zinnen. Begin met het "
        "belangrijkste."
    )

    # gemini-2.5-flash-lite: non-thinking, always fast. See device report
    # endpoint for the rationale. Override via GEMINI_MODEL env var.
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")

    try:
        from google import genai
        import time as _time
        client = genai.Client(api_key=gemini_key)
        _t0 = _time.time()
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model=gemini_model,
                contents=f"{system_prompt}\n\n=== ACTIEVE MELDINGEN ({len(alerts)} totaal) ===\n{alert_block}",
            ),
            timeout=45,
        )
        elapsed = _time.time() - _t0
        summary = (response.text or "").strip()
        usage = getattr(response, "usage_metadata", None)
        tokens = None
        if usage:
            tokens = {
                "prompt": getattr(usage, "prompt_token_count", 0),
                "response": getattr(usage, "candidates_token_count", 0),
                "total": getattr(usage, "total_token_count", 0),
            }
        print(f"[ai-summary] {gemini_model} returned in {elapsed:.1f}s, {tokens}")
    except Exception as exc:
        print(f"[ai-summary] Gemini call failed: {type(exc).__name__}: {exc}")
        summary = (
            f"Er zijn {len(alerts)} actieve meldingen in je netwerk. "
            f"Controleer het Actie Inbox-overzicht voor details."
        )
        tokens = None

    return {
        "summary": summary,
        "alert_count": len(alerts),
        "model": gemini_model,
        "tokens": tokens,
    }


# ---------------------------------------------------------------------------
# GET /api/analytics/category-tree — hierarchical view of non-AI traffic
# ---------------------------------------------------------------------------
EXCLUDED_CATEGORIES = {"ai", "cloud", "tracking"}

@app.get("/api/analytics/category-tree")
def category_tree(
    service: Optional[str] = Query(None, description="Filter to a single ai_service"),
    source_ip: Optional[str] = Query(None, description="Filter to a single device IP"),
    start: Optional[datetime] = Query(None, description="Only include events after this ISO timestamp"),
    db: Session = Depends(get_db),
):
    # Resolve source_ip → all IPs owned by the same device, so filtering
    # by the IPv4 address also catches the device's IPv6 counterpart.
    source_ips = None
    if source_ip:
        dip = db.query(DeviceIP).filter(DeviceIP.ip == source_ip).first()
        if dip:
            source_ips = [
                d.ip for d in
                db.query(DeviceIP).filter(DeviceIP.mac_address == dip.mac_address).all()
            ]
        else:
            source_ips = [source_ip]

    q = (
        db.query(
            DetectionEvent.category,
            DetectionEvent.ai_service,
            DetectionEvent.source_ip,
            func.sum(DetectionEvent.bytes_transferred).label("bytes"),
            func.count().label("hits"),
        )
        .filter(~DetectionEvent.category.in_(EXCLUDED_CATEGORIES))
    )
    if service:
        q = q.filter(DetectionEvent.ai_service == service)
    if source_ips:
        q = q.filter(DetectionEvent.source_ip.in_(source_ips))
    if start:
        q = q.filter(DetectionEvent.timestamp >= start)
    rows = (
        q.group_by(DetectionEvent.category, DetectionEvent.ai_service, DetectionEvent.source_ip)
         .all()
    )

    # Resolve every source_ip to its owning MAC so dual-stack devices
    # (IPv4 + IPv6 on the same physical phone/laptop) aggregate into a
    # single device row per service instead of appearing twice. IPs
    # without a registered device fall back to their raw IP as a key.
    ip_to_mac: dict[str, str] = {
        d.ip: d.mac_address for d in db.query(DeviceIP).all()
    }
    # A representative IP per MAC — used for the device row's "ip" field
    # so the frontend can still resolve a display name via ipName[ip].
    mac_to_representative_ip: dict[str, str] = {}
    for ip, mac in ip_to_mac.items():
        # Prefer IPv4 (no colons) as the representative — cleaner display.
        if mac not in mac_to_representative_ip or ":" in mac_to_representative_ip[mac]:
            mac_to_representative_ip[mac] = ip

    # Build nested dict: category → service → {device_key: aggregated}
    tree: dict = {}
    for cat, svc, ip, byt, hits in rows:
        if cat not in tree:
            tree[cat] = {"category": cat, "total_bytes": 0, "services": {}}
        tree[cat]["total_bytes"] += byt or 0
        svcs = tree[cat]["services"]
        if svc not in svcs:
            svcs[svc] = {"service_name": svc, "total_bytes": 0, "devices": {}}
        svcs[svc]["total_bytes"] += byt or 0

        # Device key: MAC if known, otherwise raw IP. This collapses
        # IPv4 + IPv6 + any other aliases into a single entry.
        mac = ip_to_mac.get(ip)
        dev_key = mac or ip
        display_ip = mac_to_representative_ip.get(mac, ip) if mac else ip

        dev_map = svcs[svc]["devices"]
        if dev_key not in dev_map:
            dev_map[dev_key] = {"ip": display_ip, "bytes": 0, "hits": 0}
        dev_map[dev_key]["bytes"] += byt or 0
        dev_map[dev_key]["hits"] += hits

    # Flatten services dict to list, sort by bytes desc
    result = []
    for cat_data in sorted(tree.values(), key=lambda c: -c["total_bytes"]):
        services_list = sorted(
            cat_data["services"].values(), key=lambda s: -s["total_bytes"]
        )
        for svc in services_list:
            svc["devices"] = sorted(svc["devices"].values(), key=lambda d: -d["bytes"])
        cat_data["services"] = services_list
        result.append(cat_data)
    return result


# ---------------------------------------------------------------------------
# GET /api/privacy/stats — AdGuard Home + Zeek tracking statistics
# ---------------------------------------------------------------------------
@app.get("/api/privacy/stats")
async def privacy_stats(
    db: Session = Depends(get_db),
    service: Optional[str] = None,
    source_ip: Optional[str] = None,
    start: Optional[str] = None,
):
    """Fetch combined privacy stats: AdGuard blocking + Zeek tracker detection.

    Returns a safe fallback if AdGuard is not running yet.
    Supports optional filters: service, source_ip, start (ISO timestamp).
    """
    # Build base filter for tracker queries
    tracker_filter = [DetectionEvent.category == "tracking"]
    if service:
        tracker_filter.append(DetectionEvent.ai_service == service)
    if source_ip:
        tracker_filter.append(DetectionEvent.source_ip == source_ip)
    if start:
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            tracker_filter.append(DetectionEvent.timestamp >= start_dt)
        except (ValueError, TypeError):
            pass

    # 1) AdGuard stats
    try:
        adguard_stats = await adguard.get_stats()
    except Exception:
        adguard_stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "block_percentage": 0.0,
            "top_blocked": [],
            "status": "unavailable",
        }

    # 2) Zeek-detected trackers from our database (category="tracking")
    from sqlalchemy import func

    # Total tracking events
    tracking_total = (
        db.query(func.count(DetectionEvent.id))
        .filter(*tracker_filter)
        .scalar() or 0
    )

    # Top trackers (grouped by ai_service, sorted by count)
    top_trackers_raw = (
        db.query(
            DetectionEvent.ai_service,
            func.count(DetectionEvent.id).label("hits"),
        )
        .filter(*tracker_filter)
        .group_by(DetectionEvent.ai_service)
        .order_by(func.count(DetectionEvent.id).desc())
        .limit(10)
        .all()
    )
    top_trackers = [
        {"service": row[0], "hits": row[1]} for row in top_trackers_raw
    ]

    # Recent tracking events (last 50)
    recent_tracking = (
        db.query(DetectionEvent)
        .filter(*tracker_filter)
        .order_by(DetectionEvent.timestamp.desc())
        .limit(50)
        .all()
    )
    recent_list = [
        {
            "timestamp": str(e.timestamp),
            "service": e.ai_service,
            "source_ip": e.source_ip,
            "detection_type": e.detection_type,
        }
        for e in recent_tracking
    ]

    # 3) VPN / tunnel alerts — only real tunnel detections.
    #    The old query also OR'd ai_service LIKE 'vpn_%', which made a
    #    browser visit to nordvpn.com or an ad impression from a VPN
    #    affiliate fire a "VPN active" alert with 0 bytes transferred.
    #    Those SNI events still exist as normal events in the privacy
    #    section (category=tracking) — they just don't show up as
    #    active-VPN alerts anymore.
    #
    #    A VPN alert now requires one of:
    #      - detection_type = vpn_tunnel          (port-match or ASN-match)
    #      - detection_type = stealth_vpn_tunnel  (DPD protocol signature)
    #      - ai_service LIKE 'tor_%'              (Tor DPD signature)
    #    The last event must be within 15 minutes, so a device that
    #    stopped its VPN an hour ago doesn't keep flashing red.
    from sqlalchemy import case, Integer
    vpn_active_cutoff = datetime.utcnow() - timedelta(minutes=15)
    stealth_flag = func.sum(
        case((DetectionEvent.detection_type == "stealth_vpn_tunnel", 1), else_=0)
    ).label("stealth_hits")
    regular_flag = func.sum(
        case((DetectionEvent.detection_type != "stealth_vpn_tunnel", 1), else_=0)
    ).label("regular_hits")
    vpn_rows = (
        db.query(
            DetectionEvent.source_ip,
            func.max(DetectionEvent.timestamp).label("last_seen"),
            func.sum(DetectionEvent.bytes_transferred).label("total_bytes"),
            func.count(DetectionEvent.id).label("hits"),
            func.max(DetectionEvent.ai_service).label("vpn_service"),
            stealth_flag,
            regular_flag,
        )
        .filter(
            (DetectionEvent.detection_type == "vpn_tunnel")
            | (DetectionEvent.detection_type == "stealth_vpn_tunnel")
            | (DetectionEvent.ai_service.like("tor_%"))
        )
        .group_by(DetectionEvent.source_ip)
        .having(func.max(DetectionEvent.timestamp) >= vpn_active_cutoff)
        .order_by(func.max(DetectionEvent.timestamp).desc())
        .limit(20)
        .all()
    )

    # Enrich with device info (hostname / MAC)
    vpn_alerts = []
    for row in vpn_rows:
        # Try to find a device for this IP
        device_ip = (
            db.query(DeviceIP).filter(DeviceIP.ip == row.source_ip).first()
        )
        device_info = {}
        if device_ip and device_ip.device:
            dev = device_ip.device
            device_info = {
                "hostname": dev.hostname,
                "mac_address": dev.mac_address,
                "display_name": dev.display_name,
                "vendor": dev.vendor,
            }
        vpn_alerts.append({
            "source_ip": row.source_ip,
            "last_seen": str(row.last_seen),
            "total_bytes": int(row.total_bytes or 0),
            "hits": row.hits,
            "vpn_service": row.vpn_service,
            "stealth_hits": int(row.stealth_hits or 0),
            "regular_hits": int(row.regular_hits or 0),
            "is_stealth": int(row.stealth_hits or 0) > 0,
            **device_info,
        })

    # 4) Security stats: beaconing_threat + any future security-category events
    sec_cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    sec_cutoff_7d = datetime.utcnow() - timedelta(days=7)
    sec_filter = (
        (DetectionEvent.detection_type == "beaconing_threat")
        | (DetectionEvent.category == "security")
    )
    total_24h = (
        db.query(func.count(DetectionEvent.id))
        .filter(sec_filter, DetectionEvent.timestamp >= sec_cutoff_24h)
        .scalar() or 0
    )
    total_7d = (
        db.query(func.count(DetectionEvent.id))
        .filter(sec_filter, DetectionEvent.timestamp >= sec_cutoff_7d)
        .scalar() or 0
    )
    # Daily buckets for a 7-day sparkline (oldest → newest)
    sparkline = [0] * 7
    start_of_today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    daily_rows = (
        db.query(
            func.strftime("%Y-%m-%d", DetectionEvent.timestamp).label("day"),
            func.count(DetectionEvent.id).label("cnt"),
        )
        .filter(sec_filter, DetectionEvent.timestamp >= sec_cutoff_7d)
        .group_by("day")
        .all()
    )
    day_counts = {r.day: r.cnt for r in daily_rows}
    for i in range(7):
        day = (start_of_today - timedelta(days=6 - i)).strftime("%Y-%m-%d")
        sparkline[i] = day_counts.get(day, 0)
    security_stats = {
        "total_24h": total_24h,
        "total_7d": total_7d,
        "sparkline_7d": sparkline,
    }

    # 5) Beaconing / C2 threat alerts (last 24h, one row per src→dst pair)
    beacon_cutoff = datetime.utcnow() - timedelta(hours=24)
    beacon_rows = (
        db.query(
            DetectionEvent.source_ip,
            DetectionEvent.ai_service,        # destination IP
            func.max(DetectionEvent.timestamp).label("last_seen"),
            func.count(DetectionEvent.id).label("hits"),
        )
        .filter(
            DetectionEvent.detection_type == "beaconing_threat",
            DetectionEvent.timestamp >= beacon_cutoff,
        )
        .group_by(DetectionEvent.source_ip, DetectionEvent.ai_service)
        .order_by(func.max(DetectionEvent.timestamp).desc())
        .limit(20)
        .all()
    )
    beacon_alerts = []
    for row in beacon_rows:
        device_ip = db.query(DeviceIP).filter(DeviceIP.ip == row.source_ip).first()
        device_info = {}
        if device_ip and device_ip.device:
            dev = device_ip.device
            device_info = {
                "hostname": dev.hostname,
                "mac_address": dev.mac_address,
                "display_name": dev.display_name,
                "vendor": dev.vendor,
            }
        # Enrich destination IP with ASN, country, PTR
        dest_meta = db.query(IpMetadata).filter(IpMetadata.ip == row.ai_service).first()
        dest_info = {}
        if dest_meta:
            dest_info = {
                "dest_asn_org": dest_meta.asn_org,
                "dest_country": dest_meta.country_code,
                "dest_ptr": dest_meta.ptr,
            }
        # Find SNI domain from TLS fingerprints for this device+dest
        dest_sni = None
        if device_info.get("mac_address"):
            # Look for any TLS fingerprint where the SNI resolves to this IP
            # by checking geo_conversations for a service name
            geo_row = db.query(GeoConversation).filter(
                GeoConversation.resp_ip == row.ai_service,
                GeoConversation.mac_address == device_info["mac_address"],
            ).order_by(GeoConversation.hits.desc()).first()
            if geo_row and geo_row.ai_service and geo_row.ai_service != "unknown":
                dest_sni = geo_row.ai_service
        # Also check geo for bytes/hits context
        geo_ctx = db.query(GeoConversation).filter(
            GeoConversation.resp_ip == row.ai_service,
        ).order_by(GeoConversation.hits.desc()).first()
        geo_info = {}
        if geo_ctx:
            geo_info = {
                "total_bytes": geo_ctx.bytes_transferred,
                "total_hits": geo_ctx.hits,
            }
        beacon_alerts.append({
            "source_ip": row.source_ip,
            "dest_ip": row.ai_service,
            "dest_sni": dest_sni,
            "last_seen": str(row.last_seen),
            "hits": row.hits,
            **device_info,
            **dest_info,
            **geo_info,
        })

    return {
        # AdGuard section
        "adguard": adguard_stats,
        # Zeek tracker section
        "trackers": {
            "total_detected": tracking_total,
            "top_trackers": top_trackers,
            "recent": recent_list,
        },
        # VPN / evasion alerts
        "vpn_alerts": vpn_alerts,
        # Malware C2 beaconing alerts
        "beaconing_alerts": beacon_alerts,
        # Live scanner status — lets the UI show "last scanned HH:MM"
        # instead of a blank panel on networks with zero beacons.
        "beaconing_status": dict(_beacon_status),
        # Security stats (beaconing + future security categories)
        "security": security_stats,
    }


# ---------------------------------------------------------------------------
# Global Filters — Parental Control & Service Blocking via AdGuard
# ---------------------------------------------------------------------------

# AdGuard built-in service identifiers for social media / gaming
SOCIAL_MEDIA_SERVICES = [
    "facebook", "instagram", "tiktok", "twitter", "snapchat",
    "pinterest", "linkedin", "reddit", "tumblr",
]
GAMING_SERVICES = [
    "steam", "epic_games", "roblox", "twitch", "discord",
    "origin", "nintendo", "playstation", "xbox_live",
]


@app.post("/api/filters/parental")
async def toggle_parental(payload: GlobalFilterToggle):
    """Enable or disable AdGuard Parental Control (NSFW / gambling / safe-search)."""
    ok = await adguard.set_parental_control(payload.enabled)
    if not ok:
        raise HTTPException(status_code=502, detail="AdGuard Home is not reachable")
    state = "enabled" if payload.enabled else "disabled"
    print(f"[filters] Parental control {state}")
    return {"parental_enabled": payload.enabled}


@app.post("/api/filters/social")
async def toggle_social_media(payload: GlobalFilterToggle):
    """Block or unblock social media services via AdGuard blocked_services."""
    current = await adguard.get_blocked_services()
    if payload.enabled:
        # ADD social services to the list (keep gaming etc.)
        merged = list(set(current + SOCIAL_MEDIA_SERVICES))
    else:
        # REMOVE social services from the list
        merged = [s for s in current if s not in SOCIAL_MEDIA_SERVICES]
    ok = await adguard.set_blocked_services(merged)
    if not ok:
        raise HTTPException(status_code=502, detail="AdGuard Home is not reachable")
    state = "blocked" if payload.enabled else "unblocked"
    print(f"[filters] Social media {state} ({len(SOCIAL_MEDIA_SERVICES)} services)")
    return {"social_media_blocked": payload.enabled, "services": merged}


@app.post("/api/filters/gaming")
async def toggle_gaming(payload: GlobalFilterToggle):
    """Block or unblock gaming services via AdGuard blocked_services."""
    current = await adguard.get_blocked_services()
    if payload.enabled:
        merged = list(set(current + GAMING_SERVICES))
    else:
        merged = [s for s in current if s not in GAMING_SERVICES]
    ok = await adguard.set_blocked_services(merged)
    if not ok:
        raise HTTPException(status_code=502, detail="AdGuard Home is not reachable")
    state = "blocked" if payload.enabled else "unblocked"
    print(f"[filters] Gaming {state} ({len(GAMING_SERVICES)} services)")
    return {"gaming_blocked": payload.enabled, "services": merged}


@app.get("/api/filters/status")
async def get_filter_status():
    """Return current state of all global filters."""
    parental = await adguard.get_parental_status()
    blocked_services = await adguard.get_blocked_services()

    social_active = all(s in blocked_services for s in SOCIAL_MEDIA_SERVICES)
    gaming_active = all(s in blocked_services for s in GAMING_SERVICES)

    return {
        "parental_enabled": parental,
        "social_media_blocked": social_active,
        "gaming_blocked": gaming_active,
        "blocked_services": blocked_services,
    }


# ---------------------------------------------------------------------------
# Active Protect — CrowdSec IPS Integration
# ---------------------------------------------------------------------------

class CrowdSecClient:
    """Client for CrowdSec Local API (LAPI).

    Connects to http://localhost:8080 to fetch alerts and decisions.
    """

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self._api_key = os.getenv("CROWDSEC_API_KEY", "")
        self._enabled = False

    def _headers(self) -> dict:
        return {"X-Api-Key": self._api_key}

    async def is_running(self) -> bool:
        """Check if CrowdSec LAPI is reachable."""
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                r = await client.get(f"{self.base_url}/health")
                return r.status_code == 200
        except Exception:
            return False

    async def get_decisions(self) -> list[dict]:
        """Get active decisions (bans/captchas) with full details."""
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(
                    f"{self.base_url}/v1/decisions",
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    return r.json() or []
        except Exception:
            pass
        return []

    async def get_decisions_count(self) -> int:
        """Get the number of active ban decisions (blocked IPs)."""
        return len(await self.get_decisions())

    async def get_alerts(self, limit: int = 50) -> list[dict]:
        """Fetch recent alerts from CrowdSec LAPI.

        Note: bouncer API keys only have access to /v1/decisions, not /v1/alerts.
        If a machine/watcher login is configured via CROWDSEC_MACHINE_ID and
        CROWDSEC_MACHINE_PASSWORD, those are used for alert access.
        """
        machine_id = os.getenv("CROWDSEC_MACHINE_ID", "")
        machine_pw = os.getenv("CROWDSEC_MACHINE_PASSWORD", "")
        if not machine_id:
            return []

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                # Authenticate with machine credentials
                login = await client.post(
                    f"{self.base_url}/v1/watchers/login",
                    json={"machine_id": machine_id, "password": machine_pw},
                )
                if login.status_code != 200:
                    return []
                token = login.json().get("token", "")

                r = await client.get(
                    f"{self.base_url}/v1/alerts",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": limit},
                )
                if r.status_code == 200:
                    return r.json() or []
        except Exception:
            pass
        return []

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value


crowdsec = CrowdSecClient(base_url=os.environ.get("CROWDSEC_URL", "http://localhost:8080"))


@app.get("/api/ips/status")
async def get_ips_status():
    """Return Active Protect (IPS) status with alerts and decisions."""
    running = await crowdsec.is_running()
    if not running:
        return {
            "enabled": crowdsec.enabled,
            "crowdsec_running": False,
            "active_threats_blocked": 0,
            "alerts": [],
            "decisions": [],
        }

    alerts_raw = await crowdsec.get_alerts(limit=50)
    decisions_raw = await crowdsec.get_decisions()

    # Normalize alerts and filter out CAPI community-blocklist entries.
    # CrowdSec's /v1/alerts returns BOTH locally-triggered scenarios
    # AND the periodic import from the community threat-intel feed. The
    # latter are not attacks on this network — they're preventive bans
    # pushed by CAPI every 2 hours. They belong in the Blocklist tab
    # (via get_decisions with origin=CAPI), not in the Attacks tab.
    alerts = []
    for a in alerts_raw:
        source = a.get("source", {})
        scenario = a.get("scenario", "unknown") or ""
        # Skip anything sourced from CAPI or matching the community
        # blocklist scenario name used by CrowdSec hub collections.
        origin_fields = (
            (a.get("decisions") or [{}])[0].get("origin", "")
            if a.get("decisions") else ""
        )
        if (
            origin_fields == "CAPI"
            or "community_blocklist" in scenario
            or "lists:" in scenario  # CAPI list imports carry a `lists:<name>` scenario
        ):
            continue
        alerts.append({
            "id": a.get("id"),
            "created_at": a.get("created_at", ""),
            "scenario": scenario,
            "message": a.get("message", ""),
            "ip": source.get("ip", source.get("value", "?")),
            "country": source.get("cn", ""),
            "as_name": source.get("as_name", ""),
            "events_count": a.get("events_count", 0),
            "scope": source.get("scope", ""),
        })

    # Split decisions into local (detected on our network) vs CAPI (community blocklist)
    local_decisions = []
    blocklist = []
    for d in decisions_raw:
        entry = {
            "id": d.get("id"),
            "created_at": d.get("created_at", ""),
            "ip": d.get("value", "?"),
            "reason": d.get("scenario", "manual"),
            "origin": d.get("origin", ""),
            "type": d.get("type", "ban"),
            "duration": d.get("duration", ""),
        }
        if d.get("origin") == "CAPI":
            blocklist.append(entry)
        else:
            local_decisions.append(entry)

    # --- Inbound attack stats from Zeek conn.log ---
    db = SessionLocal()
    try:
        cutoff_24h = datetime.utcnow() - timedelta(hours=24)
        from sqlalchemy import func as sa_func
        total_blocked_24h = db.query(
            sa_func.coalesce(sa_func.sum(InboundAttack.hit_count), 0)
        ).filter(InboundAttack.last_seen >= cutoff_24h).scalar()
        threats_24h = db.query(
            sa_func.coalesce(sa_func.sum(InboundAttack.hit_count), 0)
        ).filter(
            InboundAttack.last_seen >= cutoff_24h,
            InboundAttack.severity == "threat",
        ).scalar()
        unique_attackers_24h = db.query(
            sa_func.count(sa_func.distinct(InboundAttack.source_ip))
        ).filter(InboundAttack.last_seen >= cutoff_24h).scalar()

        recent_attacks = (
            db.query(InboundAttack)
            .filter(InboundAttack.last_seen >= cutoff_24h)
            .order_by(InboundAttack.last_seen.desc())
            .limit(100)
            .all()
        )
        # Resolve target MAC → device name for display
        target_macs = {a.target_mac for a in recent_attacks if a.target_mac}
        mac_to_name = {}
        if target_macs:
            devs = db.query(Device).filter(Device.mac_address.in_(target_macs)).all()
            for d in devs:
                mac_to_name[d.mac_address] = d.display_name or d.hostname or d.vendor

        inbound_list = [
            {
                "source_ip": a.source_ip,
                "target_ip": a.target_ip,
                "target_name": mac_to_name.get(a.target_mac),
                "target_port": a.target_port,
                "severity": a.severity,
                "crowdsec_reason": a.crowdsec_reason,
                "country_code": a.country_code,
                "asn": a.asn,
                "asn_org": a.asn_org,
                "hit_count": a.hit_count,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in recent_attacks
        ]
    finally:
        db.close()

    return {
        "enabled": crowdsec.enabled,
        "crowdsec_running": running,
        "local_alerts_count": len(alerts) + len(local_decisions) + (threats_24h or 0),
        "blocklist_count": len(blocklist),
        "inbound_attacks_24h": total_blocked_24h or 0,
        "inbound_threats_24h": threats_24h or 0,
        "inbound_unique_ips_24h": unique_attackers_24h or 0,
        "alerts": alerts,
        "local_decisions": local_decisions,
        "inbound_attacks": inbound_list,
        "blocklist": blocklist[:100],  # Limit blocklist to 100 for UI performance
    }


_IPS_PREF_FILE = os.path.join(os.path.dirname(__file__), "data", "ips_enabled.json")


def _read_ips_pref() -> dict:
    """Read persisted user preference for IPS (CrowdSec) toggle."""
    try:
        if os.path.exists(_IPS_PREF_FILE):
            with open(_IPS_PREF_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    # First-run default: IPS ON (CrowdSec should protect from the start)
    return {"enabled": True, "user_set": False}


def _write_ips_pref(enabled: bool):
    """Persist the user's IPS toggle state so it survives restarts."""
    try:
        os.makedirs(os.path.dirname(_IPS_PREF_FILE), exist_ok=True)
        with open(_IPS_PREF_FILE, "w") as f:
            json.dump({"enabled": bool(enabled), "user_set": True}, f, indent=2)
    except Exception as exc:
        print(f"[ips] Failed to write IPS preference: {exc}")


@app.post("/api/ips/toggle")
async def toggle_ips(payload: GlobalFilterToggle):
    """Enable or disable Active Protect (IPS)."""
    crowdsec.enabled = payload.enabled
    _write_ips_pref(payload.enabled)
    state = "enabled" if payload.enabled else "disabled"
    print(f"[ips] Active Protect {state}")
    return {"enabled": crowdsec.enabled}


# ---------------------------------------------------------------------------
# Admin: one-click stale-data cleanup
# ---------------------------------------------------------------------------
# The periodic cleanup handles age-based retention (7 days / 50k events),
# but doesn't purge specific stale categories that need a clean-slate
# reset. Triggered manually from Settings. Removes:
#   - ALL vpn_tunnel events (both old heuristic rows and any old
#     ASN/port-match rows — gives the new detection pipeline a fresh
#     start without stale noise in the Privacy / IPS views)
#   - ALL stealth_vpn_tunnel events (AYIYA/Teredo/other DPD rows)
#   - All sni_hello events whose ai_service starts with 'vpn_'
#     (NordVPN/ExpressVPN domain touches from the old alert query)
#   - Orphaned tls_fingerprints pointing to non-existent devices
# Then runs VACUUM to reclaim disk space. Service policies, block
# rules, and device metadata are untouched — only noisy event rows.
@app.post("/api/admin/fix-macs")
def admin_fix_macs():
    """On-demand trigger for MAC address normalization + dedup migration."""
    _normalize_mac_addresses()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Inbound attack ingest — aggregated by (source_ip, target_ip, target_port)
# ---------------------------------------------------------------------------

@app.post("/api/inbound/ingest")
def ingest_inbound_attacks(payload: dict, db: Session = Depends(get_db)):
    """Upsert inbound connection attempts from the Zeek tailer buffer."""
    updates = payload.get("updates") or []
    now = datetime.utcnow()
    for u in updates:
        src = u.get("source_ip")
        tgt = u.get("target_ip")
        port = u.get("target_port")
        if not src or not tgt or port is None:
            continue
        row = db.query(InboundAttack).filter(
            InboundAttack.source_ip == src,
            InboundAttack.target_ip == tgt,
            InboundAttack.target_port == port,
        ).first()
        if row:
            row.hit_count += u.get("hits", 1)
            row.bytes_transferred += u.get("bytes", 0)
            row.last_seen = now
            if u.get("severity") == "threat" and row.severity != "threat":
                row.severity = "threat"
                row.crowdsec_reason = u.get("crowdsec_reason")
        else:
            db.add(InboundAttack(
                source_ip=src,
                target_ip=tgt,
                target_port=port,
                target_mac=u.get("target_mac"),
                protocol=u.get("protocol", "tcp"),
                severity=u.get("severity", "blocked"),
                crowdsec_reason=u.get("crowdsec_reason"),
                country_code=u.get("country_code"),
                asn=u.get("asn"),
                asn_org=u.get("asn_org"),
                hit_count=u.get("hits", 1),
                bytes_transferred=u.get("bytes", 0),
                first_seen=now,
                last_seen=now,
            ))
    db.commit()
    return {"accepted": len(updates)}


@app.post("/api/admin/cleanup")
def admin_cleanup(db: Session = Depends(get_db)):
    from database import engine as _db_engine  # local to avoid circular-ish feel

    counts: dict[str, int] = {}

    # 1) All VPN tunnel events — wipe the Privacy → VPN section clean.
    #    New detections will repopulate via the ASN-match pipeline.
    counts["vpn_tunnel_events"] = db.query(DetectionEvent).filter(
        DetectionEvent.detection_type == "vpn_tunnel"
    ).delete(synchronize_session=False)

    # 2) All stealth VPN tunnels (AYIYA/Teredo/etc. — dead DPD paths).
    counts["stealth_vpn_events"] = db.query(DetectionEvent).filter(
        DetectionEvent.detection_type == "stealth_vpn_tunnel"
    ).delete(synchronize_session=False)

    # 3) SNI heartbeats where the service was tagged as vpn_* — leftover
    #    NordVPN/ExpressVPN domain touches from the old alert path.
    counts["vpn_sni_events"] = db.query(DetectionEvent).filter(
        DetectionEvent.detection_type == "sni_hello",
        DetectionEvent.ai_service.like("vpn_%"),
    ).delete(synchronize_session=False)

    # 4) Orphaned tls_fingerprints pointing to devices that no longer exist.
    counts["orphaned_tls_fingerprints"] = db.execute(
        text(
            "DELETE FROM tls_fingerprints WHERE mac_address NOT IN "
            "(SELECT mac_address FROM devices)"
        )
    ).rowcount or 0

    db.commit()

    # 4) VACUUM via a fresh connection (SQLite rejects VACUUM inside a tx).
    #    Use the shared engine so we hit the exact same DB file SQLAlchemy
    #    reads/writes — the old api.DB_PATH constant is out of date.
    try:
        with _db_engine.connect() as conn:
            conn.execute(text("VACUUM"))
        vacuum_ok = True
    except Exception as exc:
        print(f"[admin-cleanup] VACUUM failed: {exc}")
        vacuum_ok = False

    total = sum(counts.values())
    print(
        f"[admin-cleanup] Purged {total} rows "
        f"({counts['vpn_tunnel_events']} vpn_tunnel, "
        f"{counts['stealth_vpn_events']} stealth_vpn_tunnel, "
        f"{counts['vpn_sni_events']} vpn SNI, "
        f"{counts['orphaned_tls_fingerprints']} orphan TLS fingerprints)"
    )

    return {
        "status": "ok",
        "total_removed": total,
        "removed": counts,
        "vacuum": vacuum_ok,
    }


# ---------------------------------------------------------------------------
# Block Rule Engine
# ---------------------------------------------------------------------------

# Known services with all their domains (for multi-domain blocking)
SERVICE_DOMAINS: dict[str, dict] = {
    # AI
    "openai":           {"domains": ["openai.com", "chatgpt.com", "oaiusercontent.com"], "category": "ai"},
    "anthropic_claude": {"domains": ["claude.ai", "anthropic.com"], "category": "ai"},
    "google_gemini":    {"domains": ["gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com"], "category": "ai"},
    "microsoft_copilot":{"domains": ["copilot.microsoft.com", "sydney.bing.com"], "category": "ai"},
    "perplexity":       {"domains": ["perplexity.ai"], "category": "ai"},
    "huggingface":      {"domains": ["huggingface.co"], "category": "ai"},
    "mistral":          {"domains": ["mistral.ai"], "category": "ai"},
    # Cloud
    "dropbox":          {"domains": ["dropbox.com"], "category": "cloud"},
    "wetransfer":       {"domains": ["wetransfer.com"], "category": "cloud"},
    "google_drive":     {"domains": ["drive.google.com", "docs.google.com"], "category": "cloud"},
    "google_device_sync":  {"domains": [], "category": "cloud"},
    "google_generic_cdn":  {"domains": [], "category": "cloud"},
    "onedrive":         {"domains": ["onedrive.live.com", "storage.live.com"], "category": "cloud"},
    "icloud":           {"domains": ["icloud.com"], "category": "cloud"},
    "box":              {"domains": ["box.com"], "category": "cloud"},
    "mega":             {"domains": ["mega.nz"], "category": "cloud"},
    # Social
    "facebook":         {"domains": ["facebook.com", "fbcdn.net"], "category": "social"},
    "instagram":        {"domains": ["instagram.com", "cdninstagram.com"], "category": "social"},
    "tiktok":           {"domains": ["tiktok.com", "tiktokcdn.com", "musical.ly"], "category": "social"},
    "snapchat":         {"domains": ["snapchat.com", "sc-cdn.net"], "category": "social"},
    "twitter":          {"domains": ["twitter.com", "x.com", "twimg.com"], "category": "social"},
    "pinterest":        {"domains": ["pinterest.com", "pinimg.com"], "category": "social"},
    "linkedin":         {"domains": ["linkedin.com"], "category": "social"},
    "reddit":           {"domains": ["reddit.com", "redditmedia.com", "redditstatic.com"], "category": "social"},
    "whatsapp":         {"domains": ["whatsapp.com", "whatsapp.net"], "category": "social"},
    # Gaming
    "steam":            {"domains": ["steampowered.com", "steamcommunity.com", "steamstatic.com"], "category": "gaming"},
    "epic_games":       {"domains": ["epicgames.com", "unrealengine.com", "fortnite.com"], "category": "gaming"},
    "roblox":           {"domains": ["roblox.com", "rbxcdn.com"], "category": "gaming"},
    "ea_games":         {"domains": ["ea.com", "origin.com"], "category": "gaming"},
    "xbox_live":        {"domains": ["xboxlive.com", "xbox.com"], "category": "gaming"},
    "playstation":      {"domains": ["playstation.com", "playstation.net"], "category": "gaming"},
    "nintendo":         {"domains": ["nintendo.com", "nintendo.net"], "category": "gaming"},
    "discord":          {"domains": ["discord.com", "discordapp.com", "discord.gg"], "category": "gaming"},
    "twitch":           {"domains": ["twitch.tv", "twitchcdn.net"], "category": "gaming"},
    "supercell":        {"domains": ["supercell.com", "supercell.net", "hayday.com", "clashofclans.com", "brawlstars.com", "clashroyale.com"], "category": "gaming"},
    # Streaming
    "netflix":          {"domains": ["netflix.com", "nflxvideo.net", "nflximg.net"], "category": "streaming"},
    "youtube":          {"domains": ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be"], "category": "streaming"},
    "spotify":          {"domains": ["spotify.com", "spotifycdn.com", "scdn.co"], "category": "streaming"},
    "disney_plus":      {"domains": ["disneyplus.com", "disney-plus.net", "dssott.com"], "category": "streaming"},
    "hbo_max":          {"domains": ["hbomax.com", "max.com"], "category": "streaming"},
    "prime_video":      {"domains": ["primevideo.com", "aiv-cdn.net", "amazonvideo.com"], "category": "streaming"},
    "apple_tv":         {"domains": ["tv.apple.com"], "category": "streaming"},
}


@app.get("/api/rules", response_model=list[BlockRuleRead])
def get_rules(db: Session = Depends(get_db)):
    """Return all block rules (active and expired)."""
    return (
        db.query(BlockRule)
        .order_by(BlockRule.created_at.desc())
        .all()
    )


@app.post("/api/rules/block", response_model=list[BlockRuleRead], status_code=201)
async def block_service(payload: BlockRuleCreate, db: Session = Depends(get_db)):
    """Block a service by adding rules to AdGuard Home.

    If the service has multiple domains, ALL are blocked. Optionally
    set duration_minutes for a temporary block.
    """
    svc = payload.service_name.lower()
    info = SERVICE_DOMAINS.get(svc)
    domains = info["domains"] if info else [payload.domain]
    category = info["category"] if info else payload.category

    # Calculate expiry
    expires = None
    if payload.duration_minutes and payload.duration_minutes > 0:
        expires = datetime.utcnow() + timedelta(minutes=payload.duration_minutes)

    created = []
    for domain in domains:
        # Check if already actively blocked
        existing = (
            db.query(BlockRule)
            .filter(
                BlockRule.domain == domain,
                BlockRule.is_active == True,
            )
            .first()
        )
        if existing:
            # Update expiry if changed
            existing.expires_at = expires
            db.commit()
            db.refresh(existing)
            created.append(existing)
            continue

        # Block in AdGuard
        ok = await adguard.block_domain(domain)
        if not ok:
            print(f"[rules] Warning: AdGuard block failed for {domain}")

        rule = BlockRule(
            service_name=svc,
            domain=domain,
            category=category,
            is_active=True,
            expires_at=expires,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        created.append(rule)

    label = f"for {payload.duration_minutes}m" if payload.duration_minutes else "permanently"
    print(f"[rules] Blocked {svc} ({len(domains)} domains) {label}")
    return created


@app.post("/api/rules/unblock")
async def unblock_service(payload: BlockRuleUnblock, db: Session = Depends(get_db)):
    """Unblock a service by removing rules from AdGuard Home."""
    svc = payload.service_name.lower()
    info = SERVICE_DOMAINS.get(svc)
    domains = info["domains"] if info else [payload.domain]

    unblocked = 0
    for domain in domains:
        # Unblock in AdGuard
        await adguard.unblock_domain(domain)

        # Deactivate all active rules for this domain
        active = (
            db.query(BlockRule)
            .filter(
                BlockRule.domain == domain,
                BlockRule.is_active == True,
            )
            .all()
        )
        for rule in active:
            rule.is_active = False
            unblocked += 1

    db.commit()
    print(f"[rules] Unblocked {svc} ({unblocked} rules deactivated)")
    return {"service": svc, "unblocked": unblocked}


@app.get("/api/rules/services")
def get_known_services(db: Session = Depends(get_db)):
    """Return all known services with their current block status.

    Each service includes a 'seen' flag indicating whether it has been
    detected in actual network traffic, plus a hit_count and last_seen
    timestamp.  Services that have never been seen are labeled as
    'preventive' in the UI.
    """
    # Get active block rules
    active_rules = (
        db.query(BlockRule)
        .filter(BlockRule.is_active == True)
        .all()
    )
    blocked_map: dict[str, dict] = {}
    for rule in active_rules:
        if rule.service_name not in blocked_map:
            blocked_map[rule.service_name] = {
                "expires_at": str(rule.expires_at) if rule.expires_at else None,
                "is_permanent": rule.expires_at is None,
            }

    # Query actual traffic per service — all categories that are in
    # SERVICE_DOMAINS so gaming/social/streaming show "seen" correctly.
    svc_categories = list({info["category"] for info in SERVICE_DOMAINS.values() if info["category"]})
    seen_raw = (
        db.query(
            DetectionEvent.ai_service,
            func.count(DetectionEvent.id).label("hits"),
            func.max(DetectionEvent.timestamp).label("last_seen"),
        )
        .filter(DetectionEvent.category.in_(svc_categories))
        .group_by(DetectionEvent.ai_service)
        .all()
    )
    seen_map: dict[str, dict] = {}
    for row in seen_raw:
        seen_map[row[0]] = {
            "hit_count": row[1],
            "last_seen": str(row[2]) if row[2] else None,
        }

    services = []
    for svc, info in SERVICE_DOMAINS.items():
        block_info = blocked_map.get(svc)
        traffic = seen_map.get(svc)
        services.append({
            "service_name": svc,
            "category": info["category"],
            "domains": info["domains"],
            "is_blocked": svc in blocked_map,
            "is_permanent": block_info["is_permanent"] if block_info else False,
            "expires_at": block_info["expires_at"] if block_info else None,
            "seen": traffic is not None,
            "hit_count": traffic["hit_count"] if traffic else 0,
            "last_seen": traffic["last_seen"] if traffic else None,
        })

    # Sort: seen services first, then preventive
    services.sort(key=lambda s: (not s["seen"], s["service_name"]))
    return services


# ---------------------------------------------------------------------------
# ADGUARD DNS FILTERING TOGGLE — user-controllable, defaults to OFF
# ---------------------------------------------------------------------------
# State file remembers the user's last choice across restarts.
# On first boot (no file), filtering is disabled by default.
_ADGUARD_PROTECTION_FILE = os.path.join(os.path.dirname(__file__), "data", "adguard_protection.json")


def _read_adguard_protection_pref() -> dict:
    """Read persisted user preference for AdGuard DNS filtering."""
    try:
        if os.path.exists(_ADGUARD_PROTECTION_FILE):
            with open(_ADGUARD_PROTECTION_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    # First-run default: filtering OFF
    return {"enabled": False, "user_set": False}


def _write_adguard_protection_pref(enabled: bool):
    """Persist the user's AdGuard filtering preference."""
    try:
        os.makedirs(os.path.dirname(_ADGUARD_PROTECTION_FILE), exist_ok=True)
        with open(_ADGUARD_PROTECTION_FILE, "w") as f:
            json.dump({"enabled": bool(enabled), "user_set": True}, f, indent=2)
    except Exception as exc:
        print(f"[adguard] Failed to write protection preference: {exc}")


@app.get("/api/adguard/protection")
async def get_adguard_protection():
    """Return whether AdGuard DNS filtering is currently enabled."""
    try:
        enabled = await adguard.is_protection_enabled()
    except Exception as exc:
        return {"enabled": False, "error": str(exc)}
    return {"enabled": bool(enabled)}


@app.post("/api/adguard/protection")
async def set_adguard_protection(payload: dict):
    """Enable or disable AdGuard DNS filtering.

    Body: {"enabled": true/false}
    """
    enabled = bool(payload.get("enabled", False))
    ok = await adguard.set_protection(enabled)
    if ok:
        _write_adguard_protection_pref(enabled)
        print(f"[adguard] DNS filtering {'enabled' if enabled else 'disabled'} by user")
    return {"enabled": enabled, "success": ok}


# ---------------------------------------------------------------------------
# KILLSWITCH — Emergency bypass for all protection systems
# ---------------------------------------------------------------------------
# State file persists across restarts so killswitch survives a reboot
_KILLSWITCH_FILE = os.path.join(os.path.dirname(__file__), "data", "killswitch.json")


def _read_killswitch_state() -> dict:
    """Read killswitch state from disk."""
    try:
        if os.path.exists(_KILLSWITCH_FILE):
            with open(_KILLSWITCH_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"active": False, "activated_at": None, "activated_by": "system"}


def _write_killswitch_state(state: dict):
    """Persist killswitch state to disk."""
    try:
        os.makedirs(os.path.dirname(_KILLSWITCH_FILE), exist_ok=True)
        with open(_KILLSWITCH_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as exc:
        print(f"[killswitch] Failed to write state: {exc}")


@app.get("/api/killswitch")
async def get_killswitch():
    """Return current killswitch status."""
    state = _read_killswitch_state()
    # Also check live AdGuard protection status
    adguard_protection = await adguard.is_protection_enabled()
    return {
        **state,
        "adguard_protection": adguard_protection,
    }


@app.post("/api/killswitch")
async def toggle_killswitch(payload: dict):
    """Activate or deactivate the killswitch.

    Body: {"active": true/false}

    When ACTIVATED (active=true):
      1. AdGuard protection → disabled (DNS keeps forwarding, no filtering)
      2. All AI-Radar block rules → suspended
      3. IPS (CrowdSec) → disabled
      4. New detections still logged but no blocking actions taken

    When DEACTIVATED (active=false):
      1. AdGuard protection → re-enabled
      2. Block rules → re-activated
      3. IPS → re-enabled
    """
    active = payload.get("active", False)
    now = datetime.utcnow().isoformat()
    results = {"actions": []}

    if active:
        # ── ACTIVATE KILLSWITCH ──
        # 1. Disable AdGuard DNS protection (keeps DNS forwarding alive!)
        adguard_ok = await adguard.set_protection(False)
        results["actions"].append({
            "service": "AdGuard Home",
            "action": "protection_disabled",
            "success": adguard_ok,
            "detail": "DNS forwarding active, filtering off" if adguard_ok else "Failed — may need manual intervention",
        })

        # 2. Disable IPS
        crowdsec.enabled = False
        results["actions"].append({
            "service": "CrowdSec IPS",
            "action": "disabled",
            "success": True,
            "detail": "Intrusion prevention paused",
        })

        # 3. Suspend all active block rules
        db = SessionLocal()
        try:
            active_rules = db.query(BlockRule).filter(BlockRule.is_active == True).all()  # noqa: E712
            suspended_count = 0
            for rule in active_rules:
                try:
                    await adguard.unblock_domain(rule.domain)
                    suspended_count += 1
                except Exception:
                    pass
            results["actions"].append({
                "service": "Block Rules",
                "action": "suspended",
                "success": True,
                "detail": f"{suspended_count} rules suspended in AdGuard (DB rules preserved)",
            })
        finally:
            db.close()

        state = {"active": True, "activated_at": now, "activated_by": "user"}
        print(f"[KILLSWITCH] ⚠️  ACTIVATED — all protection disabled")

    else:
        # ── DEACTIVATE KILLSWITCH ──
        # 1. Re-enable AdGuard DNS protection
        adguard_ok = await adguard.set_protection(True)
        results["actions"].append({
            "service": "AdGuard Home",
            "action": "protection_enabled",
            "success": adguard_ok,
            "detail": "DNS filtering re-enabled" if adguard_ok else "Failed — re-enable manually in AdGuard UI",
        })

        # 2. Re-enable IPS
        crowdsec.enabled = True
        results["actions"].append({
            "service": "CrowdSec IPS",
            "action": "enabled",
            "success": True,
            "detail": "Intrusion prevention active",
        })

        # 3. Re-apply active block rules
        db = SessionLocal()
        try:
            active_rules = db.query(BlockRule).filter(BlockRule.is_active == True).all()  # noqa: E712
            restored_count = 0
            for rule in active_rules:
                try:
                    await adguard.block_domain(rule.domain)
                    restored_count += 1
                except Exception:
                    pass
            results["actions"].append({
                "service": "Block Rules",
                "action": "restored",
                "success": True,
                "detail": f"{restored_count} rules re-applied to AdGuard",
            })
        finally:
            db.close()

        state = {"active": False, "activated_at": None, "activated_by": "system"}
        print(f"[KILLSWITCH] ✅ DEACTIVATED — all protection re-enabled")

    _write_killswitch_state(state)
    return {"killswitch": state, **results}


# ── Auto-failsafe: monitor AdGuard and activate killswitch if it crashes ──
async def _adguard_watchdog():
    """Background task that monitors AdGuard availability.

    If AdGuard is unreachable for 3 consecutive checks (90s), it
    automatically activates the killswitch to prevent DNS blackhole.
    When AdGuard recovers, it notifies but does NOT auto-deactivate
    (that requires explicit user action for safety).
    """
    fail_count = 0
    max_failures = 3
    auto_activated = False

    while True:
        await asyncio.sleep(30)
        try:
            status = await adguard.get_status()
            is_running = status.get("running", False)

            if is_running:
                if fail_count > 0:
                    print(f"[watchdog] AdGuard recovered (was failing for {fail_count} checks)")
                fail_count = 0
                if auto_activated:
                    print(f"[watchdog] ℹ️  AdGuard is back — killswitch still active, deactivate manually when ready")
            else:
                fail_count += 1
                print(f"[watchdog] ⚠️  AdGuard unreachable ({fail_count}/{max_failures})")

                if fail_count >= max_failures and not auto_activated:
                    # Emergency: activate killswitch
                    state = {
                        "active": True,
                        "activated_at": datetime.utcnow().isoformat(),
                        "activated_by": "auto_failsafe",
                    }
                    _write_killswitch_state(state)
                    auto_activated = True
                    crowdsec.enabled = False
                    print(f"[watchdog] 🚨 AUTO-FAILSAFE: Killswitch activated — AdGuard down for {max_failures} checks")

        except Exception as exc:
            fail_count += 1
            print(f"[watchdog] Error checking AdGuard: {exc}")


# GET /api/system/performance — CPU/memory per container + host totals
# ---------------------------------------------------------------------------
def _docker_get(path: str):
    """Issue a GET request to the Docker daemon via its Unix socket."""
    import httpx
    transport = httpx.HTTPTransport(uds="/var/run/docker.sock")
    with httpx.Client(transport=transport, timeout=5.0) as client:
        resp = client.get(f"http://localhost{path}")
        resp.raise_for_status()
        return resp.json()


def _calc_container_cpu(stats: dict) -> float:
    """Convert Docker container stats JSON into a CPU percentage."""
    try:
        cpu = stats["cpu_stats"]
        pre = stats["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        online = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or [1])
        if sys_delta > 0 and cpu_delta > 0:
            return round((cpu_delta / sys_delta) * online * 100.0, 1)
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    return 0.0


# ---------------------------------------------------------------------------
# Notification Settings — Home Assistant integration
# ---------------------------------------------------------------------------

def _mask_token(token: str | None) -> str | None:
    if not token or len(token) < 8:
        return token
    return token[:4] + "••••••••" + token[-4:]


def _get_or_create_notification_config(db) -> NotificationConfig:
    config = db.query(NotificationConfig).first()
    if not config:
        config = NotificationConfig(
            provider="homeassistant",
            is_enabled=False,
            enabled_categories="security,new_device",
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


@app.get("/api/settings/notifications")
def get_notification_settings(db: Session = Depends(get_db)):
    config = _get_or_create_notification_config(db)
    return {
        "id": config.id,
        "provider": config.provider,
        "url": config.url,
        "token_masked": _mask_token(config.token),
        "notify_service": config.notify_service,
        "enabled_categories": config.enabled_categories,
        "is_enabled": config.is_enabled,
    }


@app.post("/api/settings/notifications")
def update_notification_settings(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
):
    config = _get_or_create_notification_config(db)
    if "url" in payload:
        config.url = (payload["url"] or "").strip().rstrip("/")
    if "token" in payload and payload["token"]:
        # Only update token if a new one is provided (not the masked version)
        token = payload["token"].strip()
        if "••••" not in token:
            config.token = token
    if "notify_service" in payload:
        config.notify_service = (payload["notify_service"] or "").strip()
    if "enabled_categories" in payload:
        config.enabled_categories = payload["enabled_categories"]
    if "is_enabled" in payload:
        config.is_enabled = bool(payload["is_enabled"])
    db.commit()
    return {"status": "ok", "is_enabled": config.is_enabled}


@app.post("/api/settings/notifications/test")
async def test_notification(db: Session = Depends(get_db)):
    """Send a test notification to Home Assistant."""
    config = _get_or_create_notification_config(db)
    if not config.url or not config.token:
        raise HTTPException(status_code=400, detail="URL and token must be configured first")

    # Use the configured notify service, or fall back to the generic notify.notify
    svc = config.notify_service or "notify"
    service_path = f"notify/{svc}" if svc != "notify" else "notify/notify"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{config.url}/api/services/{service_path}",
                headers={
                    "Authorization": f"Bearer {config.token}",
                    "Content-Type": "application/json",
                },
                json={
                    "message": "AI-Radar test notification — connection successful!",
                    "title": "AI-Radar",
                },
            )
            if resp.status_code in (200, 201):
                return {"status": "ok", "message": f"Test sent via {service_path}"}
            else:
                return {"status": "error", "message": f"HA returned HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as exc:
        return {"status": "error", "message": f"Connection failed: {exc}"}


# Background task: push alerts to Home Assistant
async def _push_notifier_task():
    """Background task: check for new alerts every 60s and push to Home Assistant.

    Uses a DB-persisted watermark (last_notified_at) so that container
    restarts don't re-send notifications for previously seen alerts.
    """
    await asyncio.sleep(30)  # warm-up
    while True:
        await asyncio.sleep(60)
        try:
            db = SessionLocal()
            config = db.query(NotificationConfig).first()
            if not config or not config.is_enabled or not config.url or not config.token:
                db.close()
                continue

            enabled_cats = set((config.enabled_categories or "").split(","))
            enabled_cats.discard("")

            # Use the DB watermark — only process events/devices newer
            # than the last successful notification cycle.  On first
            # run (watermark is NULL) start from now to avoid flooding.
            watermark = config.last_notified_at or datetime.utcnow()
            if config.last_notified_at is None:
                # First run after migration: set watermark to now so we
                # don't retroactively notify for old events.
                config.last_notified_at = datetime.utcnow()
                db.commit()
                db.close()
                continue

            events = (
                db.query(DetectionEvent)
                .filter(DetectionEvent.timestamp > watermark)
                .all()
            )

            new_devices = (
                db.query(Device)
                .filter(Device.first_seen > watermark)
                .all()
            )

            notifications = []

            # Anomaly events
            _notify_anomaly_types = _ANOMALY_DETECTION_TYPES
            for e in events:
                if e.detection_type not in _notify_anomaly_types:
                    continue
                cat = "security" if e.detection_type in _notify_anomaly_types else e.category
                if cat not in enabled_cats:
                    continue
                notifications.append({
                    "title": f"AI-Radar: {e.detection_type.replace('_', ' ').title()}",
                    "message": f"{e.source_ip} → {e.ai_service} ({e.detection_type})",
                })

            # New device notifications
            if "new_device" in enabled_cats:
                for d in new_devices:
                    name = d.display_name or d.hostname or d.mac_address
                    notifications.append({
                        "title": "AI-Radar: New Device",
                        "message": f"{name} ({d.vendor or 'unknown vendor'}) joined the network",
                    })

            # Send notifications
            if notifications:
                svc = config.notify_service or "notify"
                svc_path = f"notify/{svc}" if svc != "notify" else "notify/notify"
                async with httpx.AsyncClient(timeout=10) as client:
                    for n in notifications[:5]:  # cap at 5 per cycle
                        try:
                            await client.post(
                                f"{config.url}/api/services/{svc_path}",
                                headers={
                                    "Authorization": f"Bearer {config.token}",
                                    "Content-Type": "application/json",
                                },
                                json=n,
                            )
                        except Exception as exc:
                            print(f"[notify] HA push failed: {exc}")
                            break
                print(f"[notify] Sent {len(notifications)} notification(s) to Home Assistant")

            # Advance watermark to now — persisted in DB, survives restarts
            config.last_notified_at = datetime.utcnow()
            db.commit()
            db.close()

        except Exception as exc:
            print(f"[notify] Error: {exc}")


@app.get("/api/system/data-sources")
def get_data_sources(db: Session = Depends(get_db)):
    """Return info about all data sources / mapping lists the system uses,
    their purpose, entry count, and when they were last refreshed.
    """
    from pathlib import Path as _P
    import json as _json

    sources = []

    # 1. KnownDomain table (v2fly + seed)
    kd_total = db.query(func.count(KnownDomain.id)).scalar() or 0
    kd_seed = db.query(func.count(KnownDomain.id)).filter(KnownDomain.source == "seed").scalar() or 0
    kd_v2fly = db.query(func.count(KnownDomain.id)).filter(KnownDomain.source == "v2fly").scalar() or 0
    kd_last = db.query(func.max(KnownDomain.updated_at)).scalar()
    sources.append({
        "name": "KnownDomain (service mapping)",
        "description": "Domain → service classification. Seeded from curated list, enriched nightly from v2fly/domain-list-community.",
        "entries": kd_total,
        "detail": f"{kd_seed} seed + {kd_v2fly} v2fly",
        "last_updated": str(kd_last) if kd_last else None,
        "source": "github.com/v2fly/domain-list-community",
    })

    # 2. Third-party services cache (AdGuard + DuckDuckGo)
    tp_file = _P(os.environ.get("AIRADAR_DATA_DIR", "/app/data")) / "third_party_services.json"
    tp = {}  # safe default
    tp_fetched = None
    if tp_file.exists():
        try:
            with open(tp_file) as f:
                tp = _json.load(f) or {}
            tp_fetched = tp.get("fetched_at")
        except Exception:
            pass
    adguard_entries = tp.get("adguard_services", {})
    ddg_entries = tp.get("ddg_trackers", {})
    tp_time = None
    if tp_fetched:
        try:
            tp_time = str(datetime.utcfromtimestamp(float(tp_fetched)))
        except (TypeError, ValueError, OSError):
            pass
    sources.append({
        "name": "AdGuard HostlistsRegistry",
        "description": "Community-maintained service → domain mappings for gaming, streaming, social, shopping, gambling services.",
        "entries": len(adguard_entries),
        "last_updated": tp_time,
        "source": "github.com/AdguardTeam/HostlistsRegistry",
    })
    sources.append({
        "name": "DuckDuckGo Tracker Radar",
        "description": "Tracker domain → company ownership mapping (~3000 trackers with owner grouping).",
        "entries": len(ddg_entries),
        "last_updated": tp_time,
        "source": "staticcdn.duckduckgo.com",
    })

    # 3. GeoIP Country MMDB
    def _file_mtime(path):
        try:
            return str(datetime.utcfromtimestamp(path.stat().st_mtime)) if path.exists() else None
        except Exception:
            return None

    data_dir = _P(os.environ.get("AIRADAR_DATA_DIR", "/app/data"))
    geo_file = data_dir / "GeoLite2-Country.mmdb"
    sources.append({
        "name": "GeoIP Country Database",
        "description": "IP → country mapping for the Geo Traffic dashboard (DB-IP / MaxMind format).",
        "entries": "~200 countries",
        "last_updated": _file_mtime(geo_file),
        "source": "github.com/sapics/ip-location-db",
    })

    # 4. ASN MMDB
    asn_file = data_dir / "dbip-asn.mmdb"
    sources.append({
        "name": "ASN Database",
        "description": "IP → Autonomous System (ASN + organization) for Geo drilldown and VPN provider detection.",
        "entries": "~70k ASNs",
        "last_updated": _file_mtime(asn_file),
        "source": "github.com/sapics/ip-location-db",
    })

    # 5. IP Metadata cache
    meta_total = db.query(func.count(IpMetadata.ip)).scalar() or 0
    meta_with_asn = db.query(func.count(IpMetadata.ip)).filter(IpMetadata.asn.isnot(None)).scalar() or 0
    meta_with_ptr = db.query(func.count(IpMetadata.ip)).filter(IpMetadata.ptr.isnot(None)).scalar() or 0
    meta_last = db.query(func.max(IpMetadata.updated_at)).scalar()
    sources.append({
        "name": "IP Metadata Cache",
        "description": "Reverse DNS (PTR) + ASN lookup cache for remote IPs seen in Geo conversations.",
        "entries": meta_total,
        "detail": f"{meta_with_asn} with ASN, {meta_with_ptr} with PTR",
        "last_updated": str(meta_last) if meta_last else None,
        "source": "Runtime enrichment (DNS + MMDB)",
    })

    # 6. VPN Provider ASNs (inline in zeek_tailer)
    sources.append({
        "name": "VPN Provider ASN List",
        "description": "ASN numbers of commercial VPN providers (NordVPN, ExpressVPN, Mullvad, etc.) for tunnel detection.",
        "entries": "~15 ASNs",
        "last_updated": None,
        "source": "Curated (github.com/brianhama/bad-asn-list)",
    })

    return {"sources": sources}


# ---------------------------------------------------------------------------
# "Ask anything" — natural language network queries via Gemini
# ---------------------------------------------------------------------------
_ask_rate_limit: dict[str, list] = {}  # IP → list of timestamps
ASK_RATE_LIMIT_PER_HOUR = 10


@app.post("/api/ask")
async def ask_network(payload: dict = Body(...), db: Session = Depends(get_db)):
    """Answer a natural-language question about the network using Gemini.

    Builds a context block from recent network data, sends it to Gemini
    with a strict system prompt that limits answers to network topics only.
    Rate-limited to 10 questions per hour.
    """
    question = (payload.get("question") or "").strip()
    if len(question) < 5:
        raise HTTPException(status_code=400, detail="Question too short")

    # Rate limiting (simple in-memory, keyed by constant since single-user)
    now = datetime.utcnow()
    timestamps = _ask_rate_limit.setdefault("global", [])
    cutoff = now - timedelta(hours=1)
    timestamps[:] = [t for t in timestamps if t > cutoff]
    if len(timestamps) >= ASK_RATE_LIMIT_PER_HOUR:
        raise HTTPException(status_code=429, detail="Rate limit: max 10 questions per hour")
    timestamps.append(now)

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        raise HTTPException(status_code=400, detail="GEMINI_API_KEY not configured")

    # Build context block from recent network data
    hours_back = 4
    ctx_cutoff = now - timedelta(hours=hours_back)

    # Recent events grouped by device + service
    events = (
        db.query(
            DetectionEvent.source_ip,
            DetectionEvent.ai_service,
            DetectionEvent.category,
            func.count().label("hits"),
            func.sum(DetectionEvent.bytes_transferred).label("bytes"),
            func.max(DetectionEvent.timestamp).label("last_seen"),
        )
        .filter(DetectionEvent.timestamp >= ctx_cutoff)
        .group_by(DetectionEvent.source_ip, DetectionEvent.ai_service)
        .order_by(func.count().desc())
        .limit(50)
        .all()
    )

    # Device lookup
    ip_to_mac = {d.ip: d.mac_address for d in db.query(DeviceIP).all()}
    devices = {d.mac_address: d for d in db.query(Device).all()}

    def dev_name(ip):
        mac = ip_to_mac.get(ip)
        if mac and mac in devices:
            d = devices[mac]
            return d.display_name or d.hostname or mac
        return ip

    event_lines = []
    for e in events:
        name = dev_name(e.source_ip)
        b = int(e.bytes or 0)
        event_lines.append(
            f"- {name} → {e.ai_service} ({e.category}): "
            f"{e.hits} hits, {b:,} bytes, last {e.last_seen}"
        )

    # Active policies
    policies = db.query(ServicePolicy).filter(ServicePolicy.action != "allow").all()
    policy_lines = [
        f"- {p.service_name or p.category}: {p.action} "
        f"({'global' if p.scope == 'global' else 'device ' + (p.mac_address or '')})"
        for p in policies[:20]
    ]

    # Device list
    device_lines = []
    for d in sorted(devices.values(), key=lambda x: x.last_seen or datetime.min, reverse=True)[:30]:
        ips = [dip.ip for dip in d.ips][:2] if d.ips else []
        device_lines.append(
            f"- {d.display_name or d.hostname or d.mac_address} "
            f"(vendor={d.vendor or '?'}, mac={d.mac_address}, ips={','.join(ips)})"
        )

    # Groups
    groups = db.query(DeviceGroup).all()
    group_lines = [f"- {g.name} (id={g.id})" for g in groups]

    context = f"""=== NETWORK DATA (last {hours_back}h) ===
Timestamp: {now.strftime('%Y-%m-%d %H:%M UTC')}

=== RECENT ACTIVITY (top 50 device→service pairs) ===
{chr(10).join(event_lines) if event_lines else '- No recent activity'}

=== ACTIVE POLICIES (alert/block only) ===
{chr(10).join(policy_lines) if policy_lines else '- No active alert/block policies'}

=== DEVICES ({len(devices)} total, top 30 by last_seen) ===
{chr(10).join(device_lines)}

=== GROUPS ===
{chr(10).join(group_lines) if group_lines else '- No groups'}
"""

    lang = payload.get("lang", "en")
    if lang == "nl":
        system_prompt = (
            "Je bent een netwerk-analist voor AI-Radar. Je beantwoordt "
            "vragen over dit specifieke thuisnetwerk: welke apparaten er "
            "zijn, welke apps en services ze gebruiken, hoeveel data ze "
            "verbruiken, welke regels er actief zijn, en beveiligingszaken.\n\n"
            "BELANGRIJK: vragen over specifieke apps (TikTok, Netflix, "
            "Hay Day, YouTube, etc.), apparaat-typen (iPhone, iPad, "
            "MacBook, Sonos, Nest, etc.), of gedrag op het netwerk ZIJN "
            "netwerkgerelateerde vragen — beantwoord ze op basis van de "
            "meegeleverde data.\n\n"
            "WEIGER ALLEEN vragen die NIETS met het netwerk te maken "
            "hebben (bv. weer, recepten, huiswerk, filosofie). Antwoord "
            "dan: 'Ik kan alleen vragen beantwoorden over je netwerk.'\n\n"
            "Antwoord beknopt in het Nederlands, in markdown."
        )
    else:
        system_prompt = (
            "You are a network analyst for AI-Radar. You answer questions "
            "about this specific home network: which devices are on it, "
            "which apps and services they use, how much data they consume, "
            "which rules are active, and security matters.\n\n"
            "IMPORTANT: questions about specific apps (TikTok, Netflix, "
            "Hay Day, YouTube, etc.), device types (iPhone, iPad, MacBook, "
            "Sonos, Nest, etc.), or behavior on the network ARE network "
            "questions — answer them based on the provided data.\n\n"
            "ONLY REFUSE questions that have NOTHING to do with the "
            "network (e.g. weather, recipes, homework, philosophy). "
            "Respond: 'I can only answer questions about your network.'\n\n"
            "Answer concisely in English, in markdown."
        )

    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")
    try:
        from google import genai
        import time as _time

        client = genai.Client(api_key=gemini_key)
        _t0 = _time.time()
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model=gemini_model,
                contents=f"{system_prompt}\n\n{context}\n\nVRAAG: {question}",
            ),
            timeout=30,
        )
        elapsed = _time.time() - _t0
        answer = response.text
        usage = response.usage_metadata
        tokens = {
            "prompt_tokens": getattr(usage, "prompt_token_count", 0),
            "response_tokens": getattr(usage, "candidates_token_count", 0),
            "total_tokens": getattr(usage, "total_token_count", 0),
        }
        return {
            "answer": answer,
            "model": gemini_model,
            "tokens": tokens,
            "elapsed_s": round(elapsed, 1),
        }
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Gemini timeout (30s)")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Gemini error: {exc}")


# ---------------------------------------------------------------------------
# Device Groups — CRUD + membership + auto-match
# ---------------------------------------------------------------------------

@app.get("/api/groups")
def list_groups(db: Session = Depends(get_db)):
    """Return all device groups with member counts."""
    groups = db.query(DeviceGroup).order_by(DeviceGroup.name).all()
    result = []
    for g in groups:
        member_count = db.query(DeviceGroupMember).filter(
            DeviceGroupMember.group_id == g.id
        ).count()
        result.append({
            "id": g.id,
            "name": g.name,
            "parent_id": g.parent_id,
            "icon": g.icon or "users-three",
            "color": g.color or "blue",
            "auto_match_rules": g.auto_match_rules,
            "member_count": member_count,
            "created_at": str(g.created_at),
        })
    return {"groups": result}


@app.post("/api/groups", status_code=201)
def create_group(payload: dict = Body(...), db: Session = Depends(get_db)):
    """Create a new device group."""
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    existing = db.query(DeviceGroup).filter(DeviceGroup.name == name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Group name already exists")
    group = DeviceGroup(
        name=name,
        parent_id=payload.get("parent_id"),
        icon=payload.get("icon", "users-three"),
        color=payload.get("color", "blue"),
        auto_match_rules=payload.get("auto_match_rules"),
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return {"id": group.id, "name": group.name}


@app.put("/api/groups/{group_id}")
def update_group(group_id: int, payload: dict = Body(...), db: Session = Depends(get_db)):
    """Update a group's name, icon, color, parent, or auto-match rules."""
    group = db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if "name" in payload:
        group.name = payload["name"]
    if "parent_id" in payload:
        group.parent_id = payload["parent_id"]
    if "icon" in payload:
        group.icon = payload["icon"]
    if "color" in payload:
        group.color = payload["color"]
    if "auto_match_rules" in payload:
        group.auto_match_rules = payload["auto_match_rules"]
    db.commit()
    return {"status": "ok"}


@app.delete("/api/groups/{group_id}", status_code=204)
def delete_group(group_id: int, db: Session = Depends(get_db)):
    """Delete a group and all its memberships + policies."""
    group = db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    # Remove memberships
    db.query(DeviceGroupMember).filter(DeviceGroupMember.group_id == group_id).delete()
    # Remove group-scoped policies
    db.query(ServicePolicy).filter(
        ServicePolicy.scope == "group",
        ServicePolicy.group_id == group_id,
    ).delete()
    # Re-parent children to this group's parent (flatten)
    db.query(DeviceGroup).filter(DeviceGroup.parent_id == group_id).update(
        {DeviceGroup.parent_id: group.parent_id}, synchronize_session="fetch"
    )
    db.delete(group)
    db.commit()
    return None


@app.get("/api/groups/{group_id}/members")
def list_group_members(group_id: int, db: Session = Depends(get_db)):
    """Return all devices in a group."""
    members = (
        db.query(DeviceGroupMember)
        .filter(DeviceGroupMember.group_id == group_id)
        .all()
    )
    devs = {d.mac_address: d for d in db.query(Device).all()}
    return {
        "members": [
            {
                "mac_address": m.mac_address,
                "source": m.source,
                "hostname": devs[m.mac_address].hostname if m.mac_address in devs else None,
                "display_name": devs[m.mac_address].display_name if m.mac_address in devs else None,
                "vendor": devs[m.mac_address].vendor if m.mac_address in devs else None,
            }
            for m in members
        ]
    }


@app.post("/api/groups/{group_id}/members", status_code=201)
def add_group_member(group_id: int, payload: dict = Body(...), db: Session = Depends(get_db)):
    """Add a device to a group."""
    mac = payload.get("mac_address")
    if not mac:
        raise HTTPException(status_code=400, detail="mac_address required")
    existing = db.query(DeviceGroupMember).filter(
        DeviceGroupMember.group_id == group_id,
        DeviceGroupMember.mac_address == mac,
    ).first()
    if existing:
        return {"status": "already_member"}
    db.add(DeviceGroupMember(
        group_id=group_id,
        mac_address=mac,
        source=payload.get("source", "manual"),
    ))
    db.commit()
    return {"status": "added"}


@app.delete("/api/groups/{group_id}/members/{mac_address}", status_code=204)
def remove_group_member(group_id: int, mac_address: str, db: Session = Depends(get_db)):
    """Remove a device from a group."""
    db.query(DeviceGroupMember).filter(
        DeviceGroupMember.group_id == group_id,
        DeviceGroupMember.mac_address == mac_address,
    ).delete()
    db.commit()
    return None


@app.get("/api/devices/{mac_address}/groups")
def device_groups(mac_address: str, db: Session = Depends(get_db)):
    """Return all groups a device belongs to."""
    memberships = db.query(DeviceGroupMember).filter(
        DeviceGroupMember.mac_address == mac_address
    ).all()
    groups = {g.id: g for g in db.query(DeviceGroup).all()}
    return {
        "groups": [
            {
                "id": m.group_id,
                "name": groups[m.group_id].name if m.group_id in groups else "?",
                "source": m.source,
            }
            for m in memberships
            if m.group_id in groups
        ]
    }


# ---------------------------------------------------------------------------
# IoT Fleet + Anomaly + Device Profile endpoints
# ---------------------------------------------------------------------------

# Device types considered "IoT" — mirrors _IOT_DEVICE_TYPES in zeek_tailer.py
# plus the _detectDeviceType patterns in app.js. Keep in sync.
_IOT_TYPE_KEYWORDS = {
    "air quality", "vacuum", "dryer", "washer", "dishwasher", "airco",
    "blinds", "curtains", "energy", "meter", "smart home", "home assistant",
    "wled", "awtrix", "nspanel", "alarm clock", "health monitor",
    "presence sensor", "camera hub", "zigbee", "iot", "thermostat",
    "smart lighting", "google home", "nest", "speaker", "sonos",
    "homepod", "ip camera", "doorbell", "hue sync", "harmony",
    "denon", "av receiver", "chromecast", "apple tv", "tv/media",
    "lg smart tv", "e-reader",
}


def _classify_device_type_backend(device: Device) -> str:
    """Return the device type string, mirroring app.js _detectDeviceType.

    Uses hostname, vendor, display_name, device_class, dhcp_vendor_class.
    """
    haystack = " ".join(filter(None, [
        device.hostname, device.vendor, device.display_name
    ])).lower()

    # Check against IoT keywords
    for kw in _IOT_TYPE_KEYWORDS:
        if kw in haystack:
            return kw

    # Vendor-based
    v = (device.vendor or "").lower()
    for iot_vendor in ("espressif", "hikvision", "sonos", "nest", "signify",
                       "philips lighting", "lumi", "withings", "xiaomi",
                       "myenergi", "resideo", "honeywell", "texas instruments"):
        if iot_vendor in v:
            return iot_vendor

    # DHCP vendor class
    dvc = (device.dhcp_vendor_class or "").lower()
    if dvc.startswith("udhcp"):
        return "embedded_iot"

    dc = (device.device_class or "").lower()
    if dc == "iot":
        return "iot"

    return ""


def _is_iot_backend(device: Device) -> bool:
    return bool(_classify_device_type_backend(device))


@app.get("/api/devices/{mac_address}/connections")
def device_connections(
    mac_address: str,
    db: Session = Depends(get_db),
):
    """Return all network connections (from geo_conversations) for a device.

    This fills the gap where detection_events (SNI-based) shows zero
    rows but the device has hundreds of IP-level connections visible
    in conn.log via geo_conversations. Shows destination IP, country,
    ASN/PTR, bytes, hits, direction.
    """
    rows = (
        db.query(GeoConversation)
        .filter(GeoConversation.mac_address == mac_address)
        .order_by(GeoConversation.bytes_transferred.desc())
        .limit(100)
        .all()
    )

    # Enrich with ip_metadata
    resp_ips = [r.resp_ip for r in rows]
    meta_map = {
        m.ip: m for m in
        db.query(IpMetadata).filter(IpMetadata.ip.in_(resp_ips)).all()
    } if resp_ips else {}

    return {
        "mac_address": mac_address,
        "connections": [
            {
                "resp_ip": r.resp_ip,
                "country_code": r.country_code,
                "direction": r.direction,
                "service": r.ai_service,
                "bytes": r.bytes_transferred,
                "hits": r.hits,
                "first_seen": str(r.first_seen) if r.first_seen else None,
                "last_seen": str(r.last_seen) if r.last_seen else None,
                "ptr": meta_map[r.resp_ip].ptr if r.resp_ip in meta_map else None,
                "asn": meta_map[r.resp_ip].asn if r.resp_ip in meta_map else None,
                "asn_org": meta_map[r.resp_ip].asn_org if r.resp_ip in meta_map else None,
            }
            for r in rows
        ],
    }


@app.get("/api/iot/fleet")
def iot_fleet(db: Session = Depends(get_db)):
    """Return all IoT devices with traffic stats and health scores."""
    devices = db.query(Device).all()
    iot_devices = [d for d in devices if _is_iot_backend(d)]

    # Traffic stats from geo_conversations (last 24h approximation)
    cutoff = datetime.utcnow() - timedelta(hours=24)
    conv_stats = {}
    for row in (
        db.query(
            GeoConversation.mac_address,
            func.sum(GeoConversation.bytes_transferred).label("bytes"),
            func.sum(GeoConversation.hits).label("hits"),
            func.count(func.distinct(GeoConversation.resp_ip)).label("destinations"),
        )
        .filter(GeoConversation.last_seen >= cutoff)
        .group_by(GeoConversation.mac_address)
        .all()
    ):
        conv_stats[row.mac_address] = {
            "bytes_24h": int(row.bytes or 0),
            "hits_24h": int(row.hits or 0),
            "destinations": int(row.destinations or 0),
        }

    # Baselines
    baselines = {b.mac_address: b for b in db.query(DeviceBaseline).all()}

    # Recent anomalies (last 24h), filtered by AlertExceptions so
    # whitelisted anomalies don't make a device show red on the IoT page.
    now = datetime.utcnow()
    exceptions = db.query(AlertException).filter(
        (AlertException.expires_at.is_(None)) | (AlertException.expires_at > now)
    ).all()
    ip_to_mac = {d.ip: d.mac_address for d in db.query(DeviceIP).all()}

    anomaly_types = ("iot_lateral_movement", "iot_suspicious_port", "iot_new_country", "iot_volume_spike")
    anomaly_counts = {}
    for row in (
        db.query(
            DetectionEvent.source_ip,
            DetectionEvent.detection_type,
            DetectionEvent.ai_service,
            func.count().label("cnt"),
        )
        .filter(
            DetectionEvent.detection_type.in_(anomaly_types),
            DetectionEvent.timestamp >= cutoff,
        )
        .group_by(DetectionEvent.source_ip, DetectionEvent.detection_type, DetectionEvent.ai_service)
        .all()
    ):
        mac = ip_to_mac.get(row.source_ip)
        if _is_exception_active(exceptions, mac, row.detection_type, row.ai_service, now):
            continue
        anomaly_counts[row.source_ip] = anomaly_counts.get(row.source_ip, 0) + row.cnt

    result = []
    total_bytes = 0
    anomaly_device_count = 0
    for d in iot_devices:
        stats = conv_stats.get(d.mac_address, {})
        baseline = baselines.get(d.mac_address)
        device_ips = [dip.ip for dip in d.ips] if d.ips else []

        # Health score: green/orange/red
        anomalies = sum(anomaly_counts.get(ip, 0) for ip in device_ips)
        health = "green"
        if anomalies > 0:
            health = "red"
            anomaly_device_count += 1
        elif baseline and stats.get("bytes_24h", 0) > 0:
            avg_24h = baseline.avg_bytes_hour * 24
            stddev_24h = (baseline.stddev_bytes or 0) * 24
            if stddev_24h > 0 and stats["bytes_24h"] > avg_24h + 3 * stddev_24h:
                health = "orange"
            elif avg_24h > 0 and stddev_24h == 0 and stats["bytes_24h"] > avg_24h * 3:
                # Fallback for devices without stddev data yet
                health = "orange"

        bytes_24h = stats.get("bytes_24h", 0)
        total_bytes += bytes_24h

        result.append({
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "display_name": d.display_name,
            "vendor": d.vendor,
            "device_type": _classify_device_type_backend(d),
            "health": health,
            "bytes_24h": bytes_24h,
            "hits_24h": stats.get("hits_24h", 0),
            "destinations": stats.get("destinations", 0),
            "anomalies": anomalies,
            "last_seen": str(d.last_seen) if d.last_seen else None,
            "ips": device_ips[:3],
        })

    result.sort(key=lambda x: -x["bytes_24h"])

    return {
        "total_devices": len(result),
        "total_bytes_24h": total_bytes,
        "anomaly_devices": anomaly_device_count,
        "top_talker": result[0]["display_name"] or result[0]["hostname"] or result[0]["mac_address"] if result else None,
        "devices": result,
    }


@app.get("/api/iot/anomalies")
def iot_anomalies(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Return IoT-specific security anomalies, respecting AlertExceptions.

    Anomalies that the user has whitelisted or snoozed via the Summary
    inbox are filtered out here too, keeping both views in sync.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    now = datetime.utcnow()
    anomaly_types = ("iot_lateral_movement", "iot_suspicious_port", "iot_new_country", "iot_volume_spike")

    # Pre-fetch active exceptions (same pattern as /api/alerts/active)
    exceptions = db.query(AlertException).filter(
        (AlertException.expires_at.is_(None)) | (AlertException.expires_at > now)
    ).all()
    ip_to_mac = {d.ip: d.mac_address for d in db.query(DeviceIP).all()}

    rows = (
        db.query(
            DetectionEvent.source_ip,
            DetectionEvent.detection_type,
            DetectionEvent.ai_service,
            func.count().label("hits"),
            func.max(DetectionEvent.timestamp).label("last_seen"),
        )
        .filter(
            DetectionEvent.detection_type.in_(anomaly_types),
            DetectionEvent.timestamp >= cutoff,
        )
        .group_by(DetectionEvent.source_ip, DetectionEvent.detection_type, DetectionEvent.ai_service)
        .order_by(func.max(DetectionEvent.timestamp).desc())
        .limit(50)
        .all()
    )

    # Filter out whitelisted/snoozed anomalies
    filtered_rows = []
    for r in rows:
        mac = ip_to_mac.get(r.source_ip)
        if _is_exception_active(exceptions, mac, r.detection_type, r.ai_service, now):
            continue
        filtered_rows.append(r)
    rows = filtered_rows

    ip_to_device = {}
    for dip in db.query(DeviceIP).all():
        dev = db.query(Device).filter(Device.mac_address == dip.mac_address).first()
        if dev:
            ip_to_device[dip.ip] = {
                "mac": dev.mac_address,
                "hostname": dev.hostname,
                "display_name": dev.display_name,
                "vendor": dev.vendor,
            }

    return {
        "anomalies": [
            {
                "source_ip": r.source_ip,
                "detection_type": r.detection_type,
                "detail": r.ai_service,
                "hits": r.hits,
                "last_seen": str(r.last_seen),
                **(ip_to_device.get(r.source_ip, {})),
            }
            for r in rows
        ]
    }


@app.get("/api/iot/device/{mac_address}")
def iot_device_profile(mac_address: str, db: Session = Depends(get_db)):
    """Return detailed IoT profile for a specific device."""
    device = db.query(Device).filter(Device.mac_address == mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device_ips = [dip.ip for dip in device.ips] if device.ips else []

    # Top destinations from geo_conversations
    top_dests = (
        db.query(
            GeoConversation.resp_ip,
            GeoConversation.country_code,
            func.sum(GeoConversation.bytes_transferred).label("bytes"),
            func.sum(GeoConversation.hits).label("hits"),
        )
        .filter(GeoConversation.mac_address == mac_address)
        .group_by(GeoConversation.resp_ip, GeoConversation.country_code)
        .order_by(func.sum(GeoConversation.bytes_transferred).desc())
        .limit(10)
        .all()
    )

    # Enrich with ASN/PTR
    dest_ips = [r.resp_ip for r in top_dests]
    meta_map = {
        m.ip: m for m in
        db.query(IpMetadata).filter(IpMetadata.ip.in_(dest_ips)).all()
    } if dest_ips else {}

    destinations = []
    for r in top_dests:
        m = meta_map.get(r.resp_ip)
        destinations.append({
            "ip": r.resp_ip,
            "country": r.country_code,
            "bytes": int(r.bytes or 0),
            "hits": int(r.hits or 0),
            "ptr": m.ptr if m else None,
            "asn": m.asn if m else None,
            "asn_org": m.asn_org if m else None,
        })

    # TLS fingerprints
    tls_fps = (
        db.query(TlsFingerprint)
        .filter(TlsFingerprint.mac_address == mac_address)
        .order_by(TlsFingerprint.hit_count.desc())
        .limit(5)
        .all()
    )

    # Baseline
    baseline = db.query(DeviceBaseline).filter(
        DeviceBaseline.mac_address == mac_address
    ).first()

    # Traffic stats
    total_bytes = db.query(
        func.coalesce(func.sum(GeoConversation.bytes_transferred), 0)
    ).filter(GeoConversation.mac_address == mac_address).scalar() or 0
    total_hits = db.query(
        func.coalesce(func.sum(GeoConversation.hits), 0)
    ).filter(GeoConversation.mac_address == mac_address).scalar() or 0

    # First/last activity
    first_conv = db.query(func.min(GeoConversation.first_seen)).filter(
        GeoConversation.mac_address == mac_address
    ).scalar()
    last_conv = db.query(func.max(GeoConversation.last_seen)).filter(
        GeoConversation.mac_address == mac_address
    ).scalar()

    hours_active = 0
    if first_conv and last_conv:
        hours_active = max(1, (last_conv - first_conv).total_seconds() / 3600)

    return {
        "mac_address": mac_address,
        "hostname": device.hostname,
        "display_name": device.display_name,
        "vendor": device.vendor,
        "device_type": _classify_device_type_backend(device),
        "total_bytes": int(total_bytes),
        "total_hits": int(total_hits),
        "avg_bytes_hour": int(total_bytes / hours_active) if hours_active > 0 else 0,
        "contact_frequency": f"every {max(1, int(hours_active * 60 / max(1, total_hits)))} min",
        "destinations": destinations,
        "tls_fingerprints": [
            {"ja4": t.ja4, "sni": t.sni, "hits": t.hit_count}
            for t in tls_fps
        ],
        "baseline": {
            "avg_bytes_hour": baseline.avg_bytes_hour,
            "avg_connections_hour": baseline.avg_connections_hour,
            "avg_unique_destinations": baseline.avg_unique_destinations,
            "stddev_bytes": baseline.stddev_bytes or 0,
            "stddev_connections": baseline.stddev_connections or 0,
            "known_countries": baseline.known_countries,
            "computed_at": str(baseline.computed_at),
        } if baseline else None,
    }


# Baseline computation — runs daily
BASELINE_INTERVAL = 86400  # 24 hours


async def _compute_device_baselines():
    """Nightly task: compute rolling 7-day traffic baselines per device.

    Calculates avg + stddev per hour from daily aggregates so that
    volume-spike detection can use statistical thresholds (avg + 3σ)
    instead of a crude 3× multiplier.
    """
    await asyncio.sleep(120)  # let other tasks warm up first
    while True:
        try:
            import json as _json
            import statistics as _stats

            db = SessionLocal()
            cutoff = datetime.utcnow() - timedelta(days=7)
            macs = [r[0] for r in db.query(GeoConversation.mac_address).distinct().all() if r[0]]

            updated = 0
            for mac in macs:
                convs = (
                    db.query(
                        func.sum(GeoConversation.bytes_transferred).label("bytes"),
                        func.sum(GeoConversation.hits).label("hits"),
                        func.count(func.distinct(GeoConversation.resp_ip)).label("dests"),
                    )
                    .filter(
                        GeoConversation.mac_address == mac,
                        GeoConversation.last_seen >= cutoff,
                    )
                    .first()
                )
                if not convs or not convs.hits:
                    continue

                total_bytes = int(convs.bytes or 0)
                total_hits = int(convs.hits or 0)
                total_dests = int(convs.dests or 0)
                hours = 7 * 24  # 7-day window

                # Per-day aggregates for stddev calculation
                daily_rows = (
                    db.query(
                        func.date(GeoConversation.last_seen).label("day"),
                        func.sum(GeoConversation.bytes_transferred).label("bytes"),
                        func.sum(GeoConversation.hits).label("hits"),
                    )
                    .filter(
                        GeoConversation.mac_address == mac,
                        GeoConversation.last_seen >= cutoff,
                    )
                    .group_by(func.date(GeoConversation.last_seen))
                    .all()
                )
                daily_bytes_per_hour = [int(r.bytes or 0) / 24 for r in daily_rows]
                daily_hits_per_hour = [int(r.hits or 0) / 24 for r in daily_rows]

                stddev_bytes = 0
                stddev_connections = 0
                if len(daily_bytes_per_hour) >= 2:
                    stddev_bytes = int(_stats.stdev(daily_bytes_per_hour))
                    stddev_connections = int(_stats.stdev(daily_hits_per_hour))

                # Known countries
                countries = [
                    r[0] for r in
                    db.query(GeoConversation.country_code).filter(
                        GeoConversation.mac_address == mac,
                    ).distinct().all()
                    if r[0]
                ]

                existing = db.query(DeviceBaseline).filter(
                    DeviceBaseline.mac_address == mac
                ).first()
                if existing:
                    existing.avg_bytes_hour = total_bytes // hours
                    existing.avg_connections_hour = total_hits // hours
                    existing.avg_unique_destinations = total_dests
                    existing.stddev_bytes = stddev_bytes
                    existing.stddev_connections = stddev_connections
                    existing.known_countries = _json.dumps(countries)
                    existing.computed_at = datetime.utcnow()
                else:
                    db.add(DeviceBaseline(
                        mac_address=mac,
                        avg_bytes_hour=total_bytes // hours,
                        avg_connections_hour=total_hits // hours,
                        avg_unique_destinations=total_dests,
                        stddev_bytes=stddev_bytes,
                        stddev_connections=stddev_connections,
                        known_countries=_json.dumps(countries),
                        computed_at=datetime.utcnow(),
                    ))
                updated += 1

            db.commit()
            db.close()
            if updated:
                print(f"[baseline] Updated baselines for {updated} devices")
        except Exception as exc:
            print(f"[baseline] Error: {exc}")
        await asyncio.sleep(BASELINE_INTERVAL)


# Volume spike checker — runs every 15 minutes
VOLUME_SPIKE_CHECK_INTERVAL = 900
VOLUME_SPIKE_DEDUP_SECONDS = 3600
_volume_spike_last: dict[str, float] = {}


async def _check_volume_spikes():
    """Periodic task: compare IoT device traffic against baseline.

    For each IoT device with a computed baseline (stddev > 0), check
    if the last hour's traffic exceeds avg + 3σ.  If so, create a
    DetectionEvent with detection_type='iot_volume_spike'.
    """
    await asyncio.sleep(300)  # let baselines compute first

    # Seed dedup dict from DB so restarts don't re-alert existing spikes
    try:
        _db = SessionLocal()
        _cutoff = datetime.utcnow() - timedelta(seconds=VOLUME_SPIKE_DEDUP_SECONDS)
        ip_to_mac = {dip.ip: dip.mac_address for dip in _db.query(DeviceIP).all()}
        for evt in _db.query(DetectionEvent).filter(
            DetectionEvent.detection_type == "iot_volume_spike",
            DetectionEvent.timestamp >= _cutoff,
        ).all():
            mac = ip_to_mac.get(evt.source_ip)
            if mac:
                _volume_spike_last[mac] = evt.timestamp.timestamp()
        _db.close()
    except Exception:
        pass

    while True:
        try:
            import json as _json
            db = SessionLocal()
            now = datetime.utcnow()
            now_ts = time.time()
            hour_ago = now - timedelta(hours=1)

            # Only consider baselines with valid stddev AND enough history.
            # A device needs at least 3 days of data for a reliable baseline;
            # alerting on 1-2 days of data produces too many false positives.
            min_baseline_age = now - timedelta(days=3)
            baselines = db.query(DeviceBaseline).filter(
                DeviceBaseline.stddev_bytes > 0
            ).all()

            all_devices = {d.mac_address: d for d in db.query(Device).all()}
            mac_to_ip = {}
            for dip in db.query(DeviceIP).all():
                mac_to_ip.setdefault(dip.mac_address, dip.ip)

            checked = 0
            alerted = 0
            for bl in baselines:
                dev = all_devices.get(bl.mac_address)
                if not dev or not _is_iot_backend(dev):
                    continue

                # Skip devices without enough baseline history
                if dev.first_seen and dev.first_seen > min_baseline_age:
                    continue

                # Sum traffic for this device in the last hour
                hour_bytes = db.query(
                    func.coalesce(func.sum(GeoConversation.bytes_transferred), 0)
                ).filter(
                    GeoConversation.mac_address == bl.mac_address,
                    GeoConversation.last_seen >= hour_ago,
                ).scalar() or 0

                checked += 1
                threshold = bl.avg_bytes_hour + 3 * bl.stddev_bytes
                # Minimum threshold of 100 KB/h to avoid noise from
                # devices with very low baselines (e.g. 50 bytes/h)
                threshold = max(threshold, 100_000)
                if hour_bytes <= threshold:
                    continue

                # Dedup
                if (now_ts - _volume_spike_last.get(bl.mac_address, 0)) < VOLUME_SPIKE_DEDUP_SECONDS:
                    continue
                _volume_spike_last[bl.mac_address] = now_ts

                src_ip = mac_to_ip.get(bl.mac_address, bl.mac_address)
                dev_name = dev.display_name or dev.hostname or bl.mac_address
                # Find top destination in the spike window for context
                top_dest = db.query(
                    GeoConversation.ai_service,
                ).filter(
                    GeoConversation.mac_address == bl.mac_address,
                    GeoConversation.last_seen >= hour_ago,
                ).order_by(
                    GeoConversation.bytes_transferred.desc()
                ).first()
                top_svc = top_dest.ai_service if top_dest else "unknown"

                def _fmt_bytes_short(b):
                    if b >= 1_000_000:
                        return f"{b/1_000_000:.1f} MB"
                    return f"{b/1024:.0f} KB"

                spike_label = (
                    f"{_fmt_bytes_short(hour_bytes)}/h "
                    f"(baseline {_fmt_bytes_short(bl.avg_bytes_hour)}/h) "
                    f"→ {top_svc}"
                )

                db.add(DetectionEvent(
                    sensor_id="airadar",
                    timestamp=now,
                    detection_type="iot_volume_spike",
                    ai_service=spike_label,
                    source_ip=src_ip,
                    bytes_transferred=int(hour_bytes),
                    category="security",
                ))
                alerted += 1
                print(
                    f"[volume-spike] {dev_name} ({bl.mac_address}): "
                    f"{hour_bytes/1024:.0f} KB/h vs baseline "
                    f"{bl.avg_bytes_hour/1024:.0f} ± {bl.stddev_bytes/1024:.0f} KB/h"
                )

            if alerted:
                db.commit()
            db.close()
            if checked:
                print(f"[volume-spike] Checked {checked} IoT devices, {alerted} alerts")
        except Exception as exc:
            print(f"[volume-spike] Error: {exc}")
        await asyncio.sleep(VOLUME_SPIKE_CHECK_INTERVAL)


@app.get("/api/system/performance")
async def system_performance():
    """Return overall host stats + per-container resource usage."""
    import psutil

    # --- Host overall stats (via psutil, reads host /proc under host networking) ---
    def _collect_host():
        cpu_percent = psutil.cpu_percent(interval=0.5)
        vm = psutil.virtual_memory()
        # Use /app/data (bind-mounted from the host) so we see the real host
        # disk, not the container's overlay filesystem. Fall back to "/" when
        # running outside a container.
        disk_path = "/app/data" if os.path.exists("/app/data") else "/"
        disk = psutil.disk_usage(disk_path)
        try:
            load1, load5, load15 = psutil.getloadavg()
        except (AttributeError, OSError):
            load1 = load5 = load15 = 0.0
        return {
            "cpu_percent": round(cpu_percent, 1),
            "cpu_count": psutil.cpu_count(logical=True) or 1,
            "memory": {
                "used": vm.used,
                "total": vm.total,
                "percent": round(vm.percent, 1),
            },
            "disk": {
                "used": disk.used,
                "total": disk.total,
                "percent": round(disk.percent, 1),
            },
            "load_avg": [round(load1, 2), round(load5, 2), round(load15, 2)],
        }

    host = await asyncio.to_thread(_collect_host)

    # --- Per-container stats via Docker socket ---
    containers: list[dict] = []
    try:
        container_list = await asyncio.to_thread(_docker_get, "/containers/json")
        # Fetch stats for each container in parallel threads
        async def _one(c):
            cid = c["Id"]
            name = (c.get("Names") or ["?"])[0].lstrip("/")
            try:
                stats = await asyncio.to_thread(
                    _docker_get, f"/containers/{cid}/stats?stream=false"
                )
                cpu_pct = _calc_container_cpu(stats)
                mem = stats.get("memory_stats", {}) or {}
                mem_usage = mem.get("usage", 0) or 0
                mem_cache = (mem.get("stats") or {}).get("cache", 0) or 0
                mem_used = max(0, mem_usage - mem_cache)
                mem_limit = mem.get("limit", 0) or 0
                mem_pct = round((mem_used / mem_limit) * 100, 1) if mem_limit else 0.0
                return {
                    "name": name,
                    "state": c.get("State", "unknown"),
                    "status": c.get("Status", ""),
                    "cpu_percent": cpu_pct,
                    "memory_used": mem_used,
                    "memory_limit": mem_limit,
                    "memory_percent": mem_pct,
                }
            except Exception as exc:
                return {
                    "name": name,
                    "state": c.get("State", "unknown"),
                    "status": c.get("Status", ""),
                    "cpu_percent": 0.0,
                    "memory_used": 0,
                    "memory_limit": 0,
                    "memory_percent": 0.0,
                    "error": str(exc),
                }

        containers = await asyncio.gather(*(_one(c) for c in container_list))
        containers.sort(key=lambda x: -x["memory_used"])
    except Exception as exc:
        # Docker socket unavailable — return host stats only with an explanation
        return {
            "host": host,
            "containers": [],
            "docker_error": f"Docker socket not accessible: {exc}",
        }

    return {"host": host, "containers": containers}


# GET /api/network/performance/history — historical performance time series
# ---------------------------------------------------------------------------
@app.get("/api/network/performance/history")
def network_performance_history(
    hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Return time-series performance data for the last N hours."""
    from datetime import timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.query(NetworkPerformance)
        .filter(NetworkPerformance.timestamp >= cutoff)
        .order_by(NetworkPerformance.timestamp.asc())
        .all()
    )

    # Compute deltas for cumulative interface counters
    result = []
    prev = None
    for r in rows:
        entry = {
            "ts": r.timestamp.isoformat() + "Z" if r.timestamp else None,
            "dns_ms": r.dns_latency_ms,
            "ping_gw_ms": r.ping_gateway_ms,
            "ping_inet_ms": r.ping_internet_ms,
            "loss_pct": r.packet_loss_pct,
            "cpu_pct": r.cpu_percent,
            "mem_pct": r.memory_percent,
            "load1": round(r.load_avg_1 / 100, 2) if r.load_avg_1 is not None else None,
            "load5": round(r.load_avg_5 / 100, 2) if r.load_avg_5 is not None else None,
            "load15": round(r.load_avg_15 / 100, 2) if r.load_avg_15 is not None else None,
            # Interface throughput (bytes/sec between samples)
            "br_rx_bps": None,
            "br_tx_bps": None,
            # Error/drop rates (per interval)
            "br_rx_errors": None,
            "br_tx_errors": None,
            "br_rx_drops": None,
            "br_tx_drops": None,
        }
        if prev and r.br_rx_bytes is not None and prev.br_rx_bytes is not None:
            dt = max((r.timestamp - prev.timestamp).total_seconds(), 1)
            rx_delta = r.br_rx_bytes - prev.br_rx_bytes
            tx_delta = r.br_tx_bytes - prev.br_tx_bytes
            # Handle counter wrap (reboot)
            if rx_delta >= 0 and tx_delta >= 0:
                entry["br_rx_bps"] = round(rx_delta / dt)
                entry["br_tx_bps"] = round(tx_delta / dt)
            if r.br_rx_errors is not None and prev.br_rx_errors is not None:
                err_rx = r.br_rx_errors - prev.br_rx_errors
                err_tx = r.br_tx_errors - prev.br_tx_errors
                drp_rx = r.br_rx_drops - prev.br_rx_drops
                drp_tx = r.br_tx_drops - prev.br_tx_drops
                if err_rx >= 0:
                    entry["br_rx_errors"] = err_rx
                    entry["br_tx_errors"] = err_tx
                    entry["br_rx_drops"] = drp_rx
                    entry["br_tx_drops"] = drp_tx
        prev = r
        result.append(entry)

    return {"hours": hours, "count": len(result), "data": result}


# GET /api/health — system health check for all services
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)):
    """Check the status of all AI-Radar components."""
    import time as _time
    import subprocess
    results = []

    # 1) FastAPI itself — if we get here, it's running
    results.append({
        "service": "FastAPI Backend",
        "icon": "🖥️",
        "status": "ok",
        "response_ms": 0,
        "details": "Serving on port 8000",
    })

    # 2) SQLite Database
    t0 = _time.monotonic()
    try:
        from sqlalchemy import func
        count = db.query(func.count(DetectionEvent.id)).scalar() or 0
        ms = round((_time.monotonic() - t0) * 1000, 1)
        results.append({
            "service": "SQLite Database",
            "icon": "🗄️",
            "status": "ok",
            "response_ms": ms,
            "details": f"{count:,} events stored",
        })
    except Exception as exc:
        ms = round((_time.monotonic() - t0) * 1000, 1)
        results.append({
            "service": "SQLite Database",
            "icon": "🗄️",
            "status": "error",
            "response_ms": ms,
            "details": str(exc),
        })

    # 3) Zeek process — check via log freshness (Zeek runs on host, not in container)
    t0 = _time.monotonic()
    try:
        import os as _os
        from pathlib import Path as _Path
        zeek_log = _Path(_os.environ.get("ZEEK_LOG_DIR", "/app/logs")) / "conn.log"
        ms = round((_time.monotonic() - t0) * 1000, 1)
        if zeek_log.exists():
            age_s = _time.time() - _os.path.getmtime(zeek_log)
            if age_s < 60:
                results.append({
                    "service": "Zeek (Packet Capture)",
                    "icon": "📡",
                    "status": "ok",
                    "response_ms": ms,
                    "details": f"Active — conn.log updated {age_s:.0f}s ago",
                })
            else:
                results.append({
                    "service": "Zeek (Packet Capture)",
                    "icon": "📡",
                    "status": "warning",
                    "response_ms": ms,
                    "details": f"Stale — conn.log last updated {age_s:.0f}s ago",
                })
        else:
            results.append({
                "service": "Zeek (Packet Capture)",
                "icon": "📡",
                "status": "error",
                "response_ms": ms,
                "details": "conn.log not found — is Zeek running?",
            })
    except Exception as exc:
        results.append({
            "service": "Zeek (Packet Capture)",
            "icon": "📡",
            "status": "error",
            "response_ms": 0,
            "details": str(exc),
        })

    # 4) Zeek Tailer process
    t0 = _time.monotonic()
    try:
        proc = subprocess.run(
            ["pgrep", "-f", "zeek_tailer"],
            capture_output=True, timeout=5,
        )
        ms = round((_time.monotonic() - t0) * 1000, 1)
        if proc.returncode == 0:
            pids = proc.stdout.decode().strip().split('\n')
            # Check freshness — was there an event in the last 60s?
            from datetime import datetime, timedelta
            cutoff = datetime.utcnow() - timedelta(seconds=60)
            recent = db.query(DetectionEvent).filter(
                DetectionEvent.timestamp > cutoff
            ).count()
            fresh = f", {recent} events in last 60s" if recent else ", no recent events"
            results.append({
                "service": "Zeek Tailer",
                "icon": "🔄",
                "status": "ok",
                "response_ms": ms,
                "details": f"Running (PID {pids[0]}){fresh}",
            })
        else:
            results.append({
                "service": "Zeek Tailer",
                "icon": "🔄",
                "status": "error",
                "response_ms": ms,
                "details": "Process not found — run: python3 zeek_tailer.py --zeek-log-dir .",
            })
    except Exception as exc:
        results.append({
            "service": "Zeek Tailer",
            "icon": "🔄",
            "status": "error",
            "response_ms": 0,
            "details": str(exc),
        })

    # 5) p0f Passive OS Fingerprinting
    t0 = _time.monotonic()
    try:
        proc = subprocess.run(
            ["pgrep", "-f", "p0f.*-i"],
            capture_output=True, timeout=5,
        )
        ms = round((_time.monotonic() - t0) * 1000, 1)
        if proc.returncode == 0:
            pids = proc.stdout.decode().strip().split('\n')
            # Check log freshness
            p0f_log = _Path("/app/data/p0f.log")
            if p0f_log.exists():
                age_s = _time.time() - _os.path.getmtime(p0f_log)
                size_kb = _os.path.getsize(p0f_log) / 1024
                # Count devices with OS fingerprints
                fp_count = db.query(Device).filter(Device.os_name != None).count()  # noqa: E711
                detail = f"Running (PID {pids[0]}), log {size_kb:,.0f} KB, {fp_count} devices fingerprinted"
                results.append({
                    "service": "p0f (OS Fingerprinting)",
                    "icon": "🔍",
                    "status": "ok",
                    "response_ms": ms,
                    "details": detail,
                })
            else:
                results.append({
                    "service": "p0f (OS Fingerprinting)",
                    "icon": "🔍",
                    "status": "warning",
                    "response_ms": ms,
                    "details": f"Process running (PID {pids[0]}) but no log file yet",
                })
        else:
            results.append({
                "service": "p0f (OS Fingerprinting)",
                "icon": "🔍",
                "status": "error",
                "response_ms": ms,
                "details": "Process not found — p0f not running",
            })
    except Exception as exc:
        results.append({
            "service": "p0f (OS Fingerprinting)",
            "icon": "🔍",
            "status": "error",
            "response_ms": 0,
            "details": str(exc),
        })

    # 6) AdGuard Home
    t0 = _time.monotonic()
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{adguard.base_url}/control/status",
                auth=adguard.auth,
                timeout=5,
            )
            ms = round((_time.monotonic() - t0) * 1000, 1)
            if resp.status_code == 200:
                data = resp.json()
                protection = "protection ON" if data.get("protection_enabled") else "protection OFF"
                results.append({
                    "service": "AdGuard Home",
                    "icon": "🛡️",
                    "status": "ok",
                    "response_ms": ms,
                    "details": f"Running on {adguard.base_url}, {protection}",
                })
            else:
                results.append({
                    "service": "AdGuard Home",
                    "icon": "🛡️",
                    "status": "warning",
                    "response_ms": ms,
                    "details": f"HTTP {resp.status_code} — may need authentication",
                })
    except Exception as exc:
        ms = round((_time.monotonic() - t0) * 1000, 1)
        results.append({
            "service": "AdGuard Home",
            "icon": "🛡️",
            "status": "error",
            "response_ms": ms,
            "details": f"Not reachable: {exc}",
        })

    # 7) CrowdSec IPS
    t0 = _time.monotonic()
    try:
        cs_running = await crowdsec.is_running()
        ms = round((_time.monotonic() - t0) * 1000, 1)
        if cs_running:
            decisions = await crowdsec.get_decisions_count()
            results.append({
                "service": "CrowdSec (IPS)",
                "icon": "🚨",
                "status": "ok",
                "response_ms": ms,
                "details": f"LAPI online, {decisions} active decision{'s' if decisions != 1 else ''}",
            })
        else:
            results.append({
                "service": "CrowdSec (IPS)",
                "icon": "🚨",
                "status": "error",
                "response_ms": ms,
                "details": "LAPI not reachable at " + crowdsec.base_url,
            })
    except Exception as exc:
        ms = round((_time.monotonic() - t0) * 1000, 1)
        results.append({
            "service": "CrowdSec (IPS)",
            "icon": "🚨",
            "status": "error",
            "response_ms": ms,
            "details": str(exc),
        })

    # 8) Zeek log freshness
    import os
    from pathlib import Path
    log_dir = Path(os.environ.get("ZEEK_LOG_DIR", "/app/logs"))
    for logname in ["ssl.log", "conn.log"]:
        logpath = log_dir / logname
        t0 = _time.monotonic()
        if logpath.exists():
            age_s = _time.time() - os.path.getmtime(logpath)
            ms = round((_time.monotonic() - t0) * 1000, 1)
            size_kb = os.path.getsize(logpath) / 1024
            if age_s < 30:
                status = "ok"
                detail = f"Last modified {age_s:.0f}s ago, {size_kb:,.0f} KB"
            else:
                status = "warning"
                detail = f"Stale — last modified {age_s:.0f}s ago"
            results.append({
                "service": f"Zeek {logname}",
                "icon": "📄",
                "status": status,
                "response_ms": ms,
                "details": detail,
            })
        else:
            results.append({
                "service": f"Zeek {logname}",
                "icon": "📄",
                "status": "error",
                "response_ms": 0,
                "details": "File not found",
            })

    # 9) Database size & retention info
    db_size_mb = DB_PATH.stat().st_size / (1024*1024) if DB_PATH.exists() else 0
    event_count = db.query(func.count(DetectionEvent.id)).scalar() or 0
    db_status = "ok" if db_size_mb < MAX_DB_SIZE_MB else "warning"
    results.append({
        "service": "Data Retention",
        "icon": "🧹",
        "status": db_status,
        "response_ms": 0,
        "details": (
            f"DB: {db_size_mb:.1f} MB, {event_count:,} events. "
            f"Policy: keep {RETENTION_DAYS} days, max {MAX_EVENTS:,} events. "
            f"Cleanup runs every {CLEANUP_INTERVAL//60} min."
        ),
    })

    ok = sum(1 for r in results if r["status"] == "ok")
    total = len(results)
    return {
        "summary": {"ok": ok, "total": total, "all_ok": ok == total},
        "services": results,
    }


# ---------------------------------------------------------------------------
# Service restart endpoints
# ---------------------------------------------------------------------------
@app.post("/api/services/zeek/restart")
async def restart_zeek():
    """Kill and restart Zeek packet capture on en0."""
    import subprocess, time as _t

    # Kill existing Zeek processes
    subprocess.run(["sudo", "pkill", "-9", "-f", "zeek.*-i"], capture_output=True, timeout=5)
    _t.sleep(1)

    # Determine log directory (same dir as the running app)
    log_dir = str(Path(".").resolve())

    # Restart Zeek
    proc = subprocess.Popen(
        ["sudo", "zeek", "-i", "en0", "-C", "LogAscii::use_json=F"],
        cwd=log_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _t.sleep(2)

    # Verify it started
    check = subprocess.run(["pgrep", "-f", "zeek.*-i"], capture_output=True, timeout=5)
    if check.returncode == 0:
        pid = check.stdout.decode().strip().split('\n')[0]
        return {"status": "ok", "message": f"Zeek restarted (PID {pid})"}
    return {"status": "error", "message": "Zeek failed to start — check sudo permissions"}


@app.post("/api/services/tailer/restart")
async def restart_tailer():
    """Kill and restart the zeek_tailer.py process."""
    import subprocess, time as _t

    # Kill existing tailer
    subprocess.run(["pkill", "-9", "-f", "zeek_tailer"], capture_output=True, timeout=5)
    _t.sleep(1)

    # Restart tailer
    log_dir = str(Path(".").resolve())
    proc = subprocess.Popen(
        ["python3", "zeek_tailer.py", "--zeek-log-dir", "."],
        cwd=log_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _t.sleep(2)

    # Verify
    check = subprocess.run(["pgrep", "-f", "zeek_tailer"], capture_output=True, timeout=5)
    if check.returncode == 0:
        pid = check.stdout.decode().strip().split('\n')[0]
        return {"status": "ok", "message": f"Zeek Tailer restarted (PID {pid})"}
    return {"status": "error", "message": "Tailer failed to start"}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import subprocess
    import uvicorn

    subprocess.run(
        "lsof -ti:8000 | xargs kill 2>/dev/null",
        shell=True, capture_output=True,
    )
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
