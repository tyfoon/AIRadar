"""
AI-Radar — Pydantic schemas for request / response validation.
Supports both AI and Cloud detection categories.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Detection Event schemas
# ---------------------------------------------------------------------------

class EventCreate(BaseModel):
    """Payload accepted by POST /api/ingest."""

    sensor_id: str
    timestamp: datetime
    detection_type: str
    ai_service: str
    source_ip: str
    bytes_transferred: int
    possible_upload: bool = False
    category: str = "ai"  # "ai", "cloud", or "tracking"


class EventRead(EventCreate):
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
    """One time bucket for the timeline chart."""

    bucket: str
    services: dict[str, int]
    uploads: int = 0


# ---------------------------------------------------------------------------
# Privacy / AdGuard schemas
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Block Rule schemas
# ---------------------------------------------------------------------------

class BlockRuleCreate(BaseModel):
    """Payload for POST /api/rules/block."""

    service_name: str         # e.g. "openai"
    domain: str               # e.g. "openai.com"
    category: str = "ai"      # "ai" or "cloud"
    duration_minutes: Optional[int] = None  # None = permanent


class BlockRuleRead(BaseModel):
    """Response model for block rules."""

    id: int
    service_name: str
    domain: str
    category: str
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class BlockRuleUnblock(BaseModel):
    """Payload for POST /api/rules/unblock."""

    service_name: str
    domain: str


class GlobalFilterToggle(BaseModel):
    """Payload for POST /api/filters/parental and /api/filters/services."""

    enabled: bool


class GlobalFilterStatus(BaseModel):
    """Status of all global filters."""

    parental_enabled: bool = False
    social_media_blocked: list[str] = []
    gaming_blocked: list[str] = []


class PrivacyStats(BaseModel):
    """Summary of AdGuard Home blocking statistics."""

    total_queries: int = 0
    blocked_queries: int = 0
    block_percentage: float = 0.0
    top_blocked: list[dict] = []  # [{"domain": "...", "count": N}, ...]
    status: str = "ok"  # "ok" or "unavailable"
