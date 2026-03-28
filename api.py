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

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Integer, func
from sqlalchemy.orm import Session

from adguard_client import AdGuardClient
from database import BlockRule, DetectionEvent, Device, SessionLocal, init_db
from schemas import (
    BlockRuleCreate,
    BlockRuleRead,
    BlockRuleUnblock,
    DeviceRead,
    DeviceRegister,
    DeviceUpdate,
    EventCreate,
    EventRead,
    PrivacyStats,
    TimelineBucket,
)

STATIC_DIR = Path(__file__).parent / "static"

# AdGuard Home client (configure port as needed)
adguard = AdGuardClient(base_url="http://127.0.0.1:80")

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
        q = q.filter(DetectionEvent.source_ip == source_ip)
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
        q = q.filter(DetectionEvent.source_ip == source_ip)
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
        q = q.filter(DetectionEvent.source_ip == source_ip)
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
    device = db.query(Device).filter(Device.ip == payload.ip).first()
    if device:
        if payload.hostname:
            device.hostname = payload.hostname
        if payload.mac_address:
            device.mac_address = payload.mac_address
        device.last_seen = now
    else:
        device = Device(
            ip=payload.ip,
            hostname=payload.hostname,
            mac_address=payload.mac_address,
            first_seen=now,
            last_seen=now,
        )
        db.add(device)
    db.commit()
    db.refresh(device)
    return device


@app.put("/api/devices/{ip}", response_model=DeviceRead)
def rename_device(ip: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.ip == ip).first()
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
async def privacy_stats(db: Session = Depends(get_db)):
    """Fetch combined privacy stats: AdGuard blocking + Zeek tracker detection.

    Returns a safe fallback if AdGuard is not running yet.
    """
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
        .filter(DetectionEvent.category == "tracking")
        .scalar() or 0
    )

    # Top trackers (grouped by ai_service, sorted by count)
    top_trackers_raw = (
        db.query(
            DetectionEvent.ai_service,
            func.count(DetectionEvent.id).label("hits"),
        )
        .filter(DetectionEvent.category == "tracking")
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
        .filter(DetectionEvent.category == "tracking")
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

    return {
        # AdGuard section
        "adguard": adguard_stats,
        # Zeek tracker section
        "trackers": {
            "total_detected": tracking_total,
            "top_trackers": top_trackers,
            "recent": recent_list,
        },
    }


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
