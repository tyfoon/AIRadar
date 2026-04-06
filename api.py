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
    DeviceIP,
    GeoTraffic,
    GeoConversation,
    IpMetadata,
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

            db.commit()

            remaining = db.query(func.count(DetectionEvent.id)).scalar() or 0
            db.close()

            # 3) VACUUM to reclaim disk space (runs outside SQLAlchemy session)
            if old > 0 or overflow > 0:
                from sqlalchemy import create_engine, text
                engine = create_engine(f"sqlite:///{DB_PATH}")
                with engine.connect() as conn:
                    conn.execute(text("VACUUM"))
                engine.dispose()

            # 4) Log cleanup results
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


async def lifespan(app: FastAPI):
    init_db()
    _backfill_vendors()
    _cleanup_junk_hostnames()
    _cleanup_empty_sentinel_strings()
    # Start background tasks
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    expiry_task = asyncio.create_task(_expire_block_rules())
    policy_expiry_task = asyncio.create_task(_expire_service_policies())
    watchdog_task = asyncio.create_task(_adguard_watchdog())
    beacon_task = asyncio.create_task(_periodic_beacon_scan())
    # Dynamic domain list updater — seeds from former DOMAIN_MAP on first
    # boot, then fetches v2fly community domain lists every 24h.
    from service_updater import periodic_update_domains
    domain_updater_task = asyncio.create_task(periodic_update_domains())
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


app = FastAPI(title="AI-Radar", version="0.3.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


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

            "CRITICAL — LEAD WITH THE 24H SHAPE, NOT THE LAST HOUR:\n"
            "Use the HOURLY ACTIVITY section to find the dominant activity "
            "period(s) in the 24h window. Your summary MUST start with "
            "what happened in bulk over the day (e.g. 'spent most of the "
            "afternoon and evening gaming'). Only AFTER that should you "
            "mention the current state in the last few hours. Never let "
            "the latest hour crowd out the day's main activity.\n\n"

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
            "bullet starts with a short bold header.\n"
        )
    else:
        system_prompt = (
            "Je bent een netwerk-analist die een eindgebruiker (niet-"
            "technisch, huishouden of kleine ondernemer) uitlegt wat een "
            "specifiek apparaat op z'n netwerk heeft gedaan. Schrijf in "
            "het Nederlands, in markdown.\n\n"

            "KRITIEK — LEID IN MET DE 24U-VORM, NIET HET LAATSTE UUR:\n"
            "Gebruik de UURLIJKSE ACTIVITEIT sectie om de dominante "
            "periode(s) in het 24u-venster te vinden. Je samenvatting "
            "MOET beginnen met wat er in hoofdlijnen over de dag is "
            "gedaan (bv. 'heeft de hele middag en avond gegamed'). Pas "
            "DAARNA noem je wat er nu in de laatste paar uur gebeurt. "
            "Laat het laatste uur nooit het hoofdgebruik van de dag "
            "verdringen.\n\n"

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
            "vet.\n"
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
    """Normalize MAC to consistent lowercase format without leading zeros.
    e.g. 'A2:C0:6D:40:07:F7' → 'a2:c0:6d:40:7:f7'
    """
    if not mac:
        return mac
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return ":".join(format(int(p, 16), "x") for p in parts)
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
    unseen_ips: set[str] = set()
    accepted = 0
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
}


@app.get("/api/policies", response_model=list[ServicePolicyRead])
def list_policies(
    scope: Optional[str] = Query(None, description="filter by scope: global|device"),
    mac_address: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(ServicePolicy)
    if scope:
        q = q.filter(ServicePolicy.scope == scope)
    if mac_address:
        q = q.filter(ServicePolicy.mac_address == mac_address)
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
    if payload.scope not in ("global", "device"):
        raise HTTPException(status_code=400, detail="scope must be 'global' or 'device'")
    if payload.scope == "device" and not payload.mac_address:
        raise HTTPException(status_code=400, detail="mac_address is required when scope='device'")
    if payload.scope == "global" and payload.mac_address:
        raise HTTPException(status_code=400, detail="mac_address must be null when scope='global'")
    if payload.action not in ("allow", "alert", "block"):
        raise HTTPException(status_code=400, detail="action must be 'allow', 'alert' or 'block'")
    if not payload.service_name and not payload.category:
        raise HTTPException(status_code=400, detail="either service_name or category must be set")

    existing = (
        db.query(ServicePolicy)
        .filter(
            ServicePolicy.scope == payload.scope,
            ServicePolicy.mac_address == payload.mac_address,
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
) -> Optional[str]:
    """Return the resolved action string ("allow"/"alert"/"block") or None.

    Walks the policy list in priority order (most specific first).
    Accepts a pre-fetched list so we don't hit the DB per event.
    Policies with an expires_at in the past are treated as non-existent
    (the expiry background task will garbage-collect them shortly).
    """
    now = datetime.utcnow()
    def _first(pred):
        for p in policies:
            # Skip expired policies — they're dead but not yet GC'd.
            if p.expires_at and p.expires_at <= now:
                continue
            if pred(p):
                return p.action
        return None

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
    # 3. global + service_name
    if service_name:
        hit = _first(lambda p: p.scope == "global"
                     and not p.mac_address
                     and p.service_name == service_name)
        if hit:
            return hit
    # 4. global + category
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

    # Eager-load policies + exceptions once
    policies = db.query(ServicePolicy).all()
    exceptions = db.query(AlertException).filter(
        (AlertException.expires_at.is_(None)) | (AlertException.expires_at > now)
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
            reason = "anomaly"
        else:
            # ---------- Standard-service path ----------
            action = _resolve_policy_action(
                policies, mac, e.ai_service, e.category
            )
            if action is None:
                # No explicit policy — default rules:
                #   - possible_upload → alert (exfiltration risk)
                #   - everything else → allow (no alert)
                if e.possible_upload:
                    action = "alert"
                    reason = "default_upload"
                else:
                    continue  # allowed, don't surface
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

    # Sort: anomalies first, then by last_seen desc
    def _priority(item):
        a = item["alert_type"]
        anomaly_rank = 0 if a in _ANOMALY_DETECTION_TYPES else (1 if a == "upload" else 2)
        return (anomaly_rank, -item["timestamp"].timestamp())

    result = sorted(groups.values(), key=_priority)
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
        beacon_alerts.append({
            "source_ip": row.source_ip,
            "dest_ip": row.ai_service,
            "last_seen": str(row.last_seen),
            "hits": row.hits,
            **device_info,
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

    return {
        "enabled": crowdsec.enabled,
        "crowdsec_running": running,
        "local_alerts_count": len(alerts) + len(local_decisions),
        "blocklist_count": len(blocklist),
        "alerts": alerts,
        "local_decisions": local_decisions,
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
    tp_entries = 0
    tp_fetched = None
    if tp_file.exists():
        try:
            with open(tp_file) as f:
                tp = _json.load(f)
            tp_fetched = tp.get("fetched_at")
            tp_entries = len(tp.get("adguard_services", {})) + len(tp.get("ddg_trackers", {}))
        except Exception:
            pass
    sources.append({
        "name": "AdGuard HostlistsRegistry",
        "description": "Community-maintained service → domain mappings for gaming, streaming, social, shopping, gambling services.",
        "entries": len((tp.get("adguard_services", {}) if tp_file.exists() else {})),
        "last_updated": str(datetime.utcfromtimestamp(tp_fetched)) if tp_fetched else None,
        "source": "github.com/AdguardTeam/HostlistsRegistry",
    })
    sources.append({
        "name": "DuckDuckGo Tracker Radar",
        "description": "Tracker domain → company ownership mapping (~3000 trackers with owner grouping).",
        "entries": len((tp.get("ddg_trackers", {}) if tp_file.exists() else {})),
        "last_updated": str(datetime.utcfromtimestamp(tp_fetched)) if tp_fetched else None,
        "source": "staticcdn.duckduckgo.com",
    })

    # 3. GeoIP Country MMDB
    geo_file = _P(os.environ.get("AIRADAR_DATA_DIR", "/app/data")) / "GeoLite2-Country.mmdb"
    sources.append({
        "name": "GeoIP Country Database",
        "description": "IP → country mapping for the Geo Traffic dashboard (DB-IP / MaxMind format).",
        "entries": "~200 countries",
        "last_updated": str(datetime.utcfromtimestamp(geo_file.stat().st_mtime)) if geo_file.exists() else None,
        "source": "github.com/sapics/ip-location-db",
    })

    # 4. ASN MMDB
    asn_file = _P(os.environ.get("AIRADAR_DATA_DIR", "/app/data")) / "dbip-asn.mmdb"
    sources.append({
        "name": "ASN Database",
        "description": "IP → Autonomous System (ASN + organization) for Geo drilldown and VPN provider detection.",
        "entries": "~70k ASNs",
        "last_updated": str(datetime.utcfromtimestamp(asn_file.stat().st_mtime)) if asn_file.exists() else None,
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
