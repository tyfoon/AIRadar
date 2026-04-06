"""
AI-Radar — Pydantic schemas for request / response validation.
Supports both AI and Cloud detection categories.
"""

from datetime import datetime
from typing import List, Optional

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

class DeviceIPRead(BaseModel):
    """An IP address associated with a device."""

    ip: str
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class DeviceRead(BaseModel):
    """Device record returned by GET /api/devices."""

    mac_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    display_name: Optional[str] = None
    os_name: Optional[str] = None          # e.g. "macOS", "Windows", "Linux"
    os_version: Optional[str] = None       # e.g. "14.x", "11"
    os_full: Optional[str] = None          # Full p0f label
    device_class: Optional[str] = None     # e.g. "laptop", "phone", "iot"
    network_distance: Optional[int] = None # Hops
    ja4_fingerprint: Optional[str] = None  # Most recent JA4 TLS hash
    ja4_label: Optional[str] = None        # Friendly name resolved from ja4
    dhcp_vendor_class: Optional[str] = None  # e.g. "MSFT 5.0", "android-dhcp-14"
    dhcp_fingerprint: Optional[str] = None   # JA4D DHCP hash
    first_seen: datetime
    last_seen: datetime
    ips: List[DeviceIPRead] = []

    model_config = {"from_attributes": True}


class DeviceRegister(BaseModel):
    """Payload sent by the sensor when it discovers a new device."""

    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    ja4: Optional[str] = None              # JA4 TLS fingerprint from ssl.log
    ja4s: Optional[str] = None             # JA4S TLS server fingerprint
    sni: Optional[str] = None              # Server Name Indication (matched)
    dhcp_vendor_class: Optional[str] = None  # DHCP vendor_class_id from ja4d.log
    dhcp_fingerprint: Optional[str] = None   # JA4D hash from ja4d.log


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


# ---------------------------------------------------------------------------
# Policy Engine — ServicePolicy + AlertException
# ---------------------------------------------------------------------------

class ServicePolicyCreate(BaseModel):
    """Payload for POST /api/policies."""

    scope: str = "global"              # "global" or "device"
    mac_address: Optional[str] = None  # required when scope == "device"
    service_name: Optional[str] = None
    category: Optional[str] = None
    action: str = "alert"              # "allow" | "alert" | "block"
    expires_at: Optional[datetime] = None  # NULL = permanent


class ServicePolicyRead(BaseModel):
    """Policy record returned by GET /api/policies."""

    id: int
    scope: str
    mac_address: Optional[str] = None
    service_name: Optional[str] = None
    category: Optional[str] = None
    action: str
    expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertExceptionCreate(BaseModel):
    """Payload for POST /api/exceptions."""

    mac_address: str
    alert_type: str
    destination: Optional[str] = None
    expires_at: Optional[datetime] = None   # None = permanent whitelist


class AlertExceptionRead(BaseModel):
    """Exception record returned by GET /api/exceptions."""

    id: int
    mac_address: str
    alert_type: str
    destination: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ActiveAlert(BaseModel):
    """Single row returned by GET /api/alerts/active.

    Represents one (mac_address, alert_type, service_or_dest) group
    after the policy + exception resolver has run. Multiple raw events
    in the same group are collapsed into one row with aggregated hits.
    """

    alert_id: str                       # stable synthetic id for the group
    mac_address: str
    hostname: Optional[str] = None
    display_name: Optional[str] = None
    vendor: Optional[str] = None
    alert_type: str                     # e.g. "beaconing_threat", "vpn_tunnel", "upload", "service_access"
    service_or_dest: str                # service_name or destination IP
    category: Optional[str] = None
    timestamp: datetime                 # last_seen
    first_seen: datetime
    hits: int
    total_bytes: int = 0
    details: dict = {}                  # free-form: policy_action, reason, etc.
