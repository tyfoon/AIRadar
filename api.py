"""
AI-Radar — FastAPI server.
Exposes endpoints for ingesting and querying AI-traffic detection events,
managing discovered devices, and providing analytics/export data.
"""

import csv
import io
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Integer, func
from sqlalchemy.orm import Session

from database import AIEvent, Device, SessionLocal, init_db
from schemas import (
    AIEventCreate,
    AIEventRead,
    DeviceRead,
    DeviceRegister,
    DeviceUpdate,
    TimelineBucket,
)

STATIC_DIR = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Lifespan: ensure the database tables exist on startup
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI-Radar", version="0.2.0", lifespan=lifespan)

# Serve static assets (CSS, JS, images if added later)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Dashboard: serve index.html at the root
# ---------------------------------------------------------------------------
@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


# ---------------------------------------------------------------------------
# Dependency: yield a DB session per request
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# POST /api/ingest — store a new AI-traffic event
# ---------------------------------------------------------------------------
@app.post("/api/ingest", response_model=AIEventRead, status_code=201)
def ingest_event(event: AIEventCreate, db: Session = Depends(get_db)):
    db_event = AIEvent(**event.model_dump())
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


# ---------------------------------------------------------------------------
# GET /api/events — return events with optional filters
# ---------------------------------------------------------------------------
@app.get("/api/events", response_model=list[AIEventRead])
def list_events(
    service: Optional[str] = Query(None, description="Filter by ai_service"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    start: Optional[datetime] = Query(None, description="Events after this time (ISO)"),
    end: Optional[datetime] = Query(None, description="Events before this time (ISO)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(AIEvent)

    if service:
        q = q.filter(AIEvent.ai_service == service)
    if source_ip:
        q = q.filter(AIEvent.source_ip == source_ip)
    if start:
        q = q.filter(AIEvent.timestamp >= start)
    if end:
        q = q.filter(AIEvent.timestamp <= end)

    return q.order_by(AIEvent.timestamp.desc()).offset(offset).limit(limit).all()


# ---------------------------------------------------------------------------
# GET /api/events/export — CSV download of filtered events
# ---------------------------------------------------------------------------
@app.get("/api/events/export")
def export_events(
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(AIEvent)
    if service:
        q = q.filter(AIEvent.ai_service == service)
    if source_ip:
        q = q.filter(AIEvent.source_ip == source_ip)
    if start:
        q = q.filter(AIEvent.timestamp >= start)
    if end:
        q = q.filter(AIEvent.timestamp <= end)

    rows = q.order_by(AIEvent.timestamp.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "timestamp", "sensor_id", "ai_service",
        "detection_type", "source_ip", "bytes_transferred", "possible_upload",
    ])
    for r in rows:
        writer.writerow([
            r.id, r.timestamp.isoformat(), r.sensor_id, r.ai_service,
            r.detection_type, r.source_ip, r.bytes_transferred, r.possible_upload,
        ])

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=airadar_events.csv"},
    )


# ---------------------------------------------------------------------------
# GET /api/timeline — time-bucketed event counts for the timeline chart
#   Returns per-service counts and upload counts per bucket so the frontend
#   can render stacked bars (by service) with red upload markers.
# ---------------------------------------------------------------------------
@app.get("/api/timeline", response_model=list[TimelineBucket])
def timeline(
    bucket_size: str = Query("hour", regex="^(minute|hour|day)$"),
    service: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
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

    bucket_col = func.strftime(fmt, AIEvent.timestamp).label("bucket")

    # Query: group by bucket + service, also count uploads
    q = db.query(
        bucket_col,
        AIEvent.ai_service,
        func.count().label("count"),
        func.sum(func.cast(AIEvent.possible_upload, Integer)).label("uploads"),
    )

    if service:
        q = q.filter(AIEvent.ai_service == service)
    if source_ip:
        q = q.filter(AIEvent.source_ip == source_ip)
    if start:
        q = q.filter(AIEvent.timestamp >= start)
    if end:
        q = q.filter(AIEvent.timestamp <= end)

    rows = q.group_by(bucket_col, AIEvent.ai_service).order_by(bucket_col).all()

    # Aggregate rows into per-bucket objects
    from collections import OrderedDict
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
    """Return all known devices, ordered by last seen."""
    return db.query(Device).order_by(Device.last_seen.desc()).all()


@app.post("/api/devices", response_model=DeviceRead, status_code=201)
def register_device(payload: DeviceRegister, db: Session = Depends(get_db)):
    """Upsert a device record (called by the sensor on discovery)."""
    now = datetime.utcnow()
    device = db.query(Device).filter(Device.ip == payload.ip).first()

    if device:
        # Update existing — keep user-set display_name, update hostname/mac
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
    """Let the user set a friendly display name for a device."""
    device = db.query(Device).filter(Device.ip == ip).first()
    if not device:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Device not found")

    device.display_name = payload.display_name
    db.commit()
    db.refresh(device)
    return device


# ---------------------------------------------------------------------------
# Entrypoint for `python api.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import subprocess
    import uvicorn

    # Kill any leftover process on port 8000 before starting
    subprocess.run(
        "lsof -ti:8000 | xargs kill 2>/dev/null",
        shell=True, capture_output=True,
    )

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
