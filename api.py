"""
AI-Radar — FastAPI server.
Exposes endpoints for ingesting and querying detection events (AI + Cloud),
managing discovered devices, analytics, and AdGuard Home privacy stats.
"""

import asyncio
import csv
import io
import os
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Integer, func
from sqlalchemy.orm import Session

from adguard_client import AdGuardClient
from database import BlockRule, DetectionEvent, Device, DeviceIP, SessionLocal, init_db

# MAC Vendor lookup
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    _mac_lookup.update_vendors()  # download OUI database on startup
except Exception:
    _mac_lookup = None


def _resolve_vendor(mac: Optional[str] = None, hostname: Optional[str] = None) -> Optional[str]:
    """Look up the hardware vendor from a MAC address, with hostname fallback."""
    if mac and _mac_lookup:
        try:
            return _mac_lookup.lookup(mac)
        except Exception:
            pass
    # Fallback: infer vendor from hostname patterns (e.g. Apple LAA MACs)
    if hostname:
        hn = hostname.lower()
        if any(k in hn for k in ("macbook", "imac", "iphone", "ipad", "apple", "airpods")):
            return "Apple Inc."
        if any(k in hn for k in ("ubiquiti", "unifi")):
            return "Ubiquiti Inc"
        if any(k in hn for k in ("samsung",)):
            return "Samsung Electronics"
        if any(k in hn for k in ("ds-2cd", "hikvision")):
            return "Hikvision"
        if any(k in hn for k in ("android", "pixel")):
            return "Google Inc."
    return None


def _ipv6_network64(addr: str):
    """Return the /64 network of an IPv6 address, or None."""
    try:
        import ipaddress
        ip = ipaddress.ip_address(addr)
        if ip.version != 6:
            return None
        return ipaddress.ip_network(f"{addr}/64", strict=False)
    except Exception:
        return None


def _same_ipv6_subnet(ip1: str, ip2: str) -> bool:
    """Check if two IPv6 addresses share the same /64 prefix."""
    n1 = _ipv6_network64(ip1)
    n2 = _ipv6_network64(ip2)
    if n1 and n2:
        return n1 == n2
    return False
from schemas import (
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
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Start background tasks
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    expiry_task = asyncio.create_task(_expire_block_rules())
    print(
        f"[cleanup] Auto-cleanup enabled: retain {RETENTION_DAYS} days, "
        f"max {MAX_EVENTS:,} events, check every {CLEANUP_INTERVAL}s"
    )
    print(f"[rules] Block rule expiry checker running every {RULE_EXPIRY_INTERVAL}s")
    yield
    cleanup_task.cancel()
    expiry_task.cancel()


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
@app.get("/api/events", response_model=list[EventRead])
def list_events(
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    category: Optional[str] = Query(None, description="Filter by category: ai or cloud"),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
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
    return db.query(Device).order_by(Device.last_seen.desc()).all()


@app.post("/api/devices", response_model=DeviceRead, status_code=201)
def register_device(payload: DeviceRegister, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    mac = payload.mac_address

    if not mac:
        # No MAC provided — try to find the device that already owns this IP
        existing_ip = db.query(DeviceIP).filter(DeviceIP.ip == payload.ip).first()
        if existing_ip and not existing_ip.mac_address.startswith("unknown_"):
            mac = existing_ip.mac_address
        elif existing_ip and existing_ip.mac_address.startswith("unknown_"):
            # Placeholder MAC — try to upgrade to a real device via /64 match
            if ":" in payload.ip:
                all_dev_ips = db.query(DeviceIP).all()
                for dip in all_dev_ips:
                    if not dip.mac_address.startswith("unknown_") and _same_ipv6_subnet(payload.ip, dip.ip):
                        mac = dip.mac_address
                        # Migrate the IP to the real device
                        existing_ip.mac_address = mac
                        break
            if not mac:
                mac = existing_ip.mac_address
        else:
            # Brand new IP — try multiple strategies to find the owning device
            # 1) Hostname match
            if payload.hostname:
                host_match = db.query(Device).filter(
                    Device.hostname == payload.hostname,
                    ~Device.mac_address.startswith("unknown_"),
                ).first()
                if host_match:
                    mac = host_match.mac_address
            # 2) IPv6 /64 prefix match — same subnet = same device
            if not mac and ":" in payload.ip:
                all_dev_ips = db.query(DeviceIP).all()
                # Prefer real-MAC devices first, then placeholders
                for prefer_real in [True, False]:
                    for dip in all_dev_ips:
                        if prefer_real and dip.mac_address.startswith("unknown_"):
                            continue
                        if _same_ipv6_subnet(payload.ip, dip.ip):
                            mac = dip.mac_address
                            break
                    if mac:
                        break
            if not mac:
                mac = f"unknown_{payload.ip.replace('.', '_').replace(':', '_')}"

    # Upsert Device by MAC address
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if device:
        if payload.hostname:
            device.hostname = payload.hostname
        # Resolve vendor if not already set
        if not device.vendor:
            device.vendor = _resolve_vendor(payload.mac_address, payload.hostname) or _resolve_vendor(mac, payload.hostname)
        device.last_seen = now
    else:
        vendor = _resolve_vendor(payload.mac_address, payload.hostname) or _resolve_vendor(mac, payload.hostname)
        device = Device(
            mac_address=mac,
            hostname=payload.hostname,
            vendor=vendor,
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

    db.commit()
    db.refresh(device)
    return device


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
    #    Only show alerts where the most recent event is within 15 minutes
    vpn_active_cutoff = datetime.utcnow() - timedelta(minutes=15)
    vpn_rows = (
        db.query(
            DetectionEvent.source_ip,
            func.max(DetectionEvent.timestamp).label("last_seen"),
            func.sum(DetectionEvent.bytes_transferred).label("total_bytes"),
            func.count(DetectionEvent.id).label("hits"),
            func.max(DetectionEvent.ai_service).label("vpn_service"),
        )
        .filter(
            (DetectionEvent.detection_type == "vpn_tunnel")
            | (DetectionEvent.ai_service.like("vpn_%"))
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
    """Stub client for CrowdSec Local API (LAPI).
    Will eventually connect to http://localhost:8080 to manage
    the firewall bouncer and fetch threat intelligence decisions.
    """

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self._enabled = False   # in-memory state until CrowdSec is deployed

    async def is_running(self) -> bool:
        """Check if CrowdSec LAPI is reachable."""
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                r = await client.get(f"{self.base_url}/health")
                return r.status_code == 200
        except Exception:
            return False

    async def get_decisions_count(self) -> int:
        """Get the number of active ban decisions (blocked IPs)."""
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(
                    f"{self.base_url}/v1/decisions",
                    headers={"X-Api-Key": os.getenv("CROWDSEC_API_KEY", "")},
                )
                if r.status_code == 200:
                    return len(r.json() or [])
        except Exception:
            pass
        return 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value


crowdsec = CrowdSecClient(base_url=os.environ.get("CROWDSEC_URL", "http://localhost:8080"))


@app.get("/api/ips/status")
async def get_ips_status():
    """Return Active Protect (IPS) status."""
    running = await crowdsec.is_running()
    blocked = await crowdsec.get_decisions_count() if running else 0
    return {
        "enabled": crowdsec.enabled,
        "crowdsec_running": running,
        "active_threats_blocked": blocked,
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

    # 3) Zeek process
    t0 = _time.monotonic()
    try:
        proc = subprocess.run(
            ["pgrep", "-f", "zeek.*-i"],
            capture_output=True, timeout=5,
        )
        ms = round((_time.monotonic() - t0) * 1000, 1)
        if proc.returncode == 0:
            pids = proc.stdout.decode().strip().split('\n')
            results.append({
                "service": "Zeek (Packet Capture)",
                "icon": "📡",
                "status": "ok",
                "response_ms": ms,
                "details": f"Running (PID {pids[0]})",
            })
        else:
            results.append({
                "service": "Zeek (Packet Capture)",
                "icon": "📡",
                "status": "error",
                "response_ms": ms,
                "details": "Process not found — run: sudo zeek -i en0 -C",
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

    # 5) AdGuard Home
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

    # 6) Zeek log freshness
    import os
    from pathlib import Path
    log_dir = Path(".")
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

    # 7) Database size & retention info
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
