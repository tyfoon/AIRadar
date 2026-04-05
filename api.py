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
from fastapi import Depends, FastAPI, HTTPException, Query
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
BEACON_SCAN_INTERVAL = 3600  # Run beaconing detection hourly
BEACON_DEDUP_HOURS = 24      # Don't re-alert the same src→dst pair within 24h


async def _periodic_beacon_scan():
    """Background task: scan Zeek conn.log for malware C2 beacons.

    Runs once an hour. Findings are stored as DetectionEvent rows with
    detection_type='beaconing_threat' and category='security'. Dedup
    logic skips any (src, dst) pair that already has a beacon alert in
    the last 24 hours, so we don't spam the alerts list when a C2 keeps
    running for days.
    """
    while True:
        await asyncio.sleep(BEACON_SCAN_INTERVAL)
        try:
            findings = await run_beacon_analysis()
            if not findings:
                continue

            db = SessionLocal()
            try:
                cutoff = datetime.utcnow() - timedelta(hours=BEACON_DEDUP_HOURS)
                new_count = 0
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
        except Exception as exc:
            print(f"[beacon] Scan error: {exc}")


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
    watchdog_task = asyncio.create_task(_adguard_watchdog())
    beacon_task = asyncio.create_task(_periodic_beacon_scan())
    print(
        f"[cleanup] Auto-cleanup enabled: retain {RETENTION_DAYS} days, "
        f"max {MAX_EVENTS:,} events, check every {CLEANUP_INTERVAL}s"
    )
    print(f"[rules] Block rule expiry checker running every {RULE_EXPIRY_INTERVAL}s")
    print(f"[watchdog] AdGuard auto-failsafe active (check every 30s, trigger after 3 failures)")
    print(f"[beacon] Malware C2 beacon detector running every {BEACON_SCAN_INTERVAL}s")
    # Restore killswitch state from last run
    ks = _read_killswitch_state()
    if ks.get("active"):
        print(f"[killswitch] ⚠️  Killswitch was active before restart — still active")
        crowdsec.enabled = False

    # Restore AdGuard DNS filtering preference (defaults to OFF on first run)
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


@app.get("/api/events", response_model=list[EventRead])
def list_events(
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    category: Optional[str] = Query(None, description="Filter by category: ai or cloud"),
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
async def device_ai_report(mac_address: str, db: Session = Depends(get_db)):
    """Generate a human-readable AI recap of a device's last 24h activity."""

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        raise HTTPException(
            status_code=400,
            detail="GEMINI_API_KEY is niet geconfigureerd. "
                   "Voeg je API-sleutel toe aan .env (krijg er een op https://aistudio.google.com/app/apikey).",
        )

    # 1. Find device + associated IPs
    device = db.query(Device).filter(Device.mac_address == mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Apparaat niet gevonden.")

    device_ips = [dip.ip for dip in device.ips]
    if not device_ips:
        raise HTTPException(status_code=404, detail="Geen IP-adressen gekoppeld aan dit apparaat.")

    device_label = device.display_name or device.hostname or device_ips[0]

    # 2. Fetch detection events (last 24h)
    cutoff = datetime.utcnow() - timedelta(hours=24)
    events = (
        db.query(DetectionEvent)
        .filter(
            DetectionEvent.source_ip.in_(device_ips),
            DetectionEvent.timestamp >= cutoff,
        )
        .order_by(DetectionEvent.timestamp.asc())
        .all()
    )

    # Prompt budget: hard caps so the LLM prompt stays under Gemini's
    # context window even for extremely active devices. Before these
    # limits, an iPhone with hundreds of iCloud sync events could
    # produce a 50k-character prompt that crashed the call.
    MAX_SERVICES_IN_PROMPT = 15        # top 15 services by bytes
    MAX_UPLOAD_EVENTS = 20             # most recent 20 uploads only
    MAX_DNS_DOMAINS = 20               # top 20 requested domains
    MAX_PROMPT_CHARS = 18000           # safety net on total prompt size

    # Summarize events by service + type
    svc_totals: dict[str, dict] = {}
    for e in events:
        svc = e.ai_service
        if svc not in svc_totals:
            svc_totals[svc] = {"count": 0, "bytes": 0, "uploads": 0, "category": e.category, "first": e.timestamp, "last": e.timestamp}
        svc_totals[svc]["count"] += 1
        svc_totals[svc]["bytes"] += e.bytes_transferred or 0
        if e.possible_upload:
            svc_totals[svc]["uploads"] += 1
        svc_totals[svc]["last"] = e.timestamp

    sorted_svcs = sorted(svc_totals.items(), key=lambda x: -x[1]["bytes"])
    event_summary_lines = []
    for svc, t in sorted_svcs[:MAX_SERVICES_IN_PROMPT]:
        kb = t["bytes"] / 1024
        line = f"- {svc} ({t['category']}): {t['count']} events, {kb:,.0f} KB totaal"
        if t["uploads"] > 0:
            line += f", {t['uploads']} uploads"
        line += f" | actief {t['first'].strftime('%H:%M')}–{t['last'].strftime('%H:%M')} UTC"
        event_summary_lines.append(line)
    extra_svcs = len(sorted_svcs) - MAX_SERVICES_IN_PROMPT
    if extra_svcs > 0:
        event_summary_lines.append(f"- ... +{extra_svcs} andere services (niet getoond)")

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

    device_lines = [
        f"Naam: {device_label}",
        f"MAC: {mac_address}",
        f"OUI Vendor: {device.vendor or 'Onbekend'}",
    ]
    if device.os_full or device.os_name:
        os_str = device.os_full or device.os_name
        if device.os_version and device.os_version not in os_str:
            os_str = f"{os_str} {device.os_version}"
        device_lines.append(f"OS (p0f): {os_str}")
    if device.device_class:
        device_lines.append(f"Device class (p0f): {device.device_class}")
    if device.dhcp_vendor_class:
        device_lines.append(f"DHCP vendor class: {device.dhcp_vendor_class}")
    if ja4_label_resolved:
        device_lines.append(f"JA4 TLS stack: {ja4_label_resolved}")
    if device.network_distance is not None:
        device_lines.append(f"Network distance: {device.network_distance} hops")
    device_lines.append(
        f"IP-adressen: {', '.join(device_ips[:5])}"
        f"{' (+' + str(len(device_ips) - 5) + ' meer)' if len(device_ips) > 5 else ''}"
    )
    device_lines.append(f"Rapport gegenereerd: {now_str}")

    data_block = f"""=== APPARAAT INFO ===
{chr(10).join(device_lines)}

=== AI/CLOUD ACTIVITEIT (afgelopen 24u) ===
Totaal events: {len(events)}
Totaal uploads: {sum(1 for e in events if e.possible_upload)}

Per service (top {MAX_SERVICES_IN_PROMPT} op bytes):
{chr(10).join(event_summary_lines) if event_summary_lines else '- Geen activiteit gedetecteerd'}

Upload tijdlijn (recentste {MAX_UPLOAD_EVENTS}):
{chr(10).join(upload_timeline) if upload_timeline else '- Geen uploads gedetecteerd'}

=== DNS VERZOEKEN (top {MAX_DNS_DOMAINS} domeinen, afgelopen 24u) ===
{chr(10).join(dns_lines) if dns_lines else '- Geen DNS-data beschikbaar (AdGuard querylog leeg of niet bereikbaar)'}
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
    system_prompt = (
        "Je bent een netwerk-analist die een eindgebruiker (niet-technisch, "
        "huishouden of kleine ondernemer) uitlegt wat een specifiek apparaat "
        "op z'n netwerk heeft gedaan. Schrijf in het Nederlands, in markdown.\n\n"
        "VERPLICHTE STRUCTUUR — houd je hier strikt aan:\n\n"
        "## Samenvatting\n"
        "2 tot 3 zinnen in gewone taal die meteen duidelijk maken:\n"
        "  - Wat voor apparaat dit is (bv. 'een Windows gaming-PC', 'een "
        "iPhone', 'een Google Nest speaker', 'een Philips Hue hub'). Gebruik "
        "de OS, device class, vendor en JA4 TLS stack signals uit APPARAAT "
        "INFO om dit te bepalen. Wees concreet — niet 'dit apparaat' maar "
        "'deze Windows laptop'.\n"
        "  - Welke apps of diensten er ACTIEF gebruikt worden (top 2-3, "
        "zoals 'Ubisoft Connect en Epic Games launcher staan open', "
        "'Spotify streamt muziek', 'Discord voor voice chat'). Vertaal "
        "technische service-namen naar wat een mens herkent.\n"
        "  - Eventuele opvallende patronen (bv. 'NordVPN is geïnstalleerd "
        "maar niet actief', 'er is geen upload-activiteit', 'het apparaat "
        "staat onder een VPN-tunnel', 'veel Windows telemetrie').\n"
        "Schrijf deze samenvatting alsof je het tegen een collega in 10 "
        "seconden vertelt. Geen jargon tenzij echt nodig.\n\n"
        "## Dagverloop\n"
        "Korte chronologische samenvatting van ochtend / middag / avond: "
        "wanneer was het apparaat actief, wanneer stil, welke diensten "
        "domineerden in welk dagdeel. Blijf kort, max een alinea.\n\n"
        "## Opvallende observaties\n"
        "Exact 3 bullets met specifieke dingen die de moeite waard zijn "
        "om te weten (uploads, onverwachte bestemmingen, veranderingen in "
        "gebruik, privacy-gevoelige diensten). Elke bullet begint met een "
        "korte kop in vet.\n"
    )

    prompt_chars = len(system_prompt) + len(data_block)
    print(f"[gemini] Device report prompt for {mac_address}: {prompt_chars} chars, "
          f"{len(events)} events, {total_uploads} uploads")

    # Use gemini-flash-lite-latest because gemini-2.5-flash has "thinking mode"
    # enabled by default which adds 30-60+ seconds of chain-of-thought
    # before responding. For pure summarisation we don't need reasoning
    # and 2.0-flash is always fast (5-10s) and same quality for this
    # use case. Override with env var if you want to experiment.
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
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

    return {
        "device": device_label,
        "mac": mac_address,
        "report": report_md,
        "tokens": token_info,
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


@app.get("/api/analytics/geo")
def get_geo_traffic(
    direction: str = Query("outbound", description="outbound or inbound"),
    db: Session = Depends(get_db),
):
    """Return per-country bandwidth totals for the dashboard map.

    Sorted by bytes_transferred descending so the heaviest-traffic
    countries appear first in the table and drive the color gradient.
    """
    if direction not in ("outbound", "inbound"):
        raise HTTPException(status_code=400, detail="direction must be outbound or inbound")
    rows = (
        db.query(GeoTraffic)
        .filter(GeoTraffic.direction == direction)
        .order_by(GeoTraffic.bytes_transferred.desc())
        .all()
    )
    return {
        "direction": direction,
        "countries": [
            {
                "country_code": r.country_code,
                "bytes": r.bytes_transferred,
                "hits": r.hits,
                "last_seen": str(r.last_seen),
            }
            for r in rows
        ],
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
      - action=="block"            → block all domains in SERVICE_DOMAINS[svc]
      - action in ("allow","alert") → unblock all domains
    For device-scoped or category-only policies, AdGuard is not touched —
    those are handled at the alert/visibility layer only.
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
    """
    def _first(pred):
        for p in policies:
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

    # gemini-flash-lite-latest: non-thinking, always fast. See device report
    # endpoint for the rationale. Override via GEMINI_MODEL env var.
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")

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
def category_tree(db: Session = Depends(get_db)):
    rows = (
        db.query(
            DetectionEvent.category,
            DetectionEvent.ai_service,
            DetectionEvent.source_ip,
            func.sum(DetectionEvent.bytes_transferred).label("bytes"),
            func.count().label("hits"),
        )
        .filter(~DetectionEvent.category.in_(EXCLUDED_CATEGORIES))
        .group_by(DetectionEvent.category, DetectionEvent.ai_service, DetectionEvent.source_ip)
        .all()
    )

    # Build nested dict: category → service → [devices]
    tree: dict = {}
    for cat, svc, ip, byt, hits in rows:
        if cat not in tree:
            tree[cat] = {"category": cat, "total_bytes": 0, "services": {}}
        tree[cat]["total_bytes"] += byt or 0
        svcs = tree[cat]["services"]
        if svc not in svcs:
            svcs[svc] = {"service_name": svc, "total_bytes": 0, "devices": []}
        svcs[svc]["total_bytes"] += byt or 0
        svcs[svc]["devices"].append({"ip": ip, "bytes": byt or 0, "hits": hits})

    # Flatten services dict to list, sort by bytes desc
    result = []
    for cat_data in sorted(tree.values(), key=lambda c: -c["total_bytes"]):
        cat_data["services"] = sorted(
            cat_data["services"].values(), key=lambda s: -s["total_bytes"]
        )
        for svc in cat_data["services"]:
            svc["devices"].sort(key=lambda d: -d["bytes"])
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

    # 3) VPN / tunnel alerts (vpn_tunnel events + vpn_* service SNI events)
    #    Only show alerts where the most recent event is within 15 minutes.
    #    Stealth tunnels (IPv6-over-IPv4 like AYIYA/Teredo, DPD-detected)
    #    are counted separately so the UI can distinguish them from
    #    commercial VPN clients.
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
            | (DetectionEvent.ai_service.like("vpn_%"))
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

    # Normalize alerts for the UI
    alerts = []
    for a in alerts_raw:
        source = a.get("source", {})
        alerts.append({
            "id": a.get("id"),
            "created_at": a.get("created_at", ""),
            "scenario": a.get("scenario", "unknown"),
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


@app.post("/api/ips/toggle")
async def toggle_ips(payload: GlobalFilterToggle):
    """Enable or disable Active Protect (IPS)."""
    crowdsec.enabled = payload.enabled
    state = "enabled" if payload.enabled else "disabled"
    print(f"[ips] Active Protect {state}")
    return {"enabled": crowdsec.enabled}


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
    # Phase 2 context-aware labels — same domain, different meaning per
    # device kind. We don't expose them as blockable in the Rules page
    # (can't block storage.googleapis.com without breaking Drive), so
    # they're informational/alert-only. Empty domain list keeps the
    # Rules UI from trying to call AdGuard.
    "google_device_sync":  {"domains": [], "category": "cloud"},
    "google_generic_cdn":  {"domains": [], "category": "cloud"},
    "onedrive":         {"domains": ["onedrive.live.com", "storage.live.com"], "category": "cloud"},
    "icloud":           {"domains": ["icloud.com"], "category": "cloud"},
    "box":              {"domains": ["box.com"], "category": "cloud"},
    "mega":             {"domains": ["mega.nz"], "category": "cloud"},
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

    # Query actual traffic per service (ai + cloud only, not tracking)
    seen_raw = (
        db.query(
            DetectionEvent.ai_service,
            func.count(DetectionEvent.id).label("hits"),
            func.max(DetectionEvent.timestamp).label("last_seen"),
        )
        .filter(DetectionEvent.category.in_(["ai", "cloud"]))
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
