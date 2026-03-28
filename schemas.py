"""
AI-Radar — Pydantic schemas for request / response validation.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# AI Event schemas
# ---------------------------------------------------------------------------

class AIEventCreate(BaseModel):
    """Payload accepted by POST /api/ingest."""

    sensor_id: str
    timestamp: datetime
    detection_type: str
    ai_service: str
    source_ip: str
    bytes_transferred: int
    possible_upload: bool = False


class AIEventRead(AIEventCreate):
    """Response model returned by GET /api/events (includes the DB id)."""

    id: int

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Device schemas
# ---------------------------------------------------------------------------

class DeviceRead(BaseModel):
    """Device record returned by GET /api/devices."""

    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    display_name: Optional[str] = None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class DeviceRegister(BaseModel):
    """Payload sent by the sensor when it discovers a new device."""

    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None


class DeviceUpdate(BaseModel):
    """Payload for renaming a device from the dashboard."""

    display_name: str


# ---------------------------------------------------------------------------
# Timeline / analytics schemas
# ---------------------------------------------------------------------------

class TimelineBucket(BaseModel):
    """One time bucket for the timeline chart.

    Contains per-service event counts and the number of upload events,
    so the frontend can render stacked bars and upload markers.
    """

    bucket: str                        # ISO timestamp (e.g. "2026-03-27T18:00:00")
    services: dict[str, int]           # { "openai": 12, "anthropic_claude": 5, ... }
    uploads: int = 0                   # count of possible_upload events in this bucket
