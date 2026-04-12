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

class LabelAttributionCreate(BaseModel):
    """Optional payload attached to an EventCreate when the labeler has
    something to say about WHY this event got the service it got.

    Sent by paths that route through labeler.resolve() — e.g. DNS-correlation
    fallback in the SSL/conn pipeline. The legacy direct-SNI path leaves
    this empty and is bucketed under 'sni_direct_legacy' in stats.

    The api.py /api/ingest handler writes a row into label_attributions
    when this is present, including the full proposals list so the audit
    trail captures losing labelers as well as the winner.
    """

    labeler: str                        # "dns_correlation" | "quic_sni_direct" | ...
    confidence: float                    # effective_score from labeler.resolve()
    rationale: Optional[str] = None
    proposed_service: str
    proposed_category: str
    is_low_confidence: bool = False
    is_disputed: bool = False


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
    # Optional: which labeler produced this label and at what confidence.
    # Legacy paths (direct SNI match against the service map) omit this
    # and get bucketed under 'sni_direct_legacy' by /api/labeler/stats.
    attribution: Optional[LabelAttributionCreate] = None


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


class FilterScheduleUpdate(BaseModel):
    """Payload for PUT /api/filters/schedules/{filter_key}.

    When mode="always" the time/day fields are ignored — the filter is
    simply held on as long as `enabled=True`. When mode="custom" the filter
    is on when the current clock matches `days` × [start_time, end_time].
    `enabled=False` deactivates the schedule entirely.
    """

    enabled: bool
    mode: str = "custom"            # "always" | "custom"
    days: list[str] = []            # e.g. ["mon","tue","wed","thu","fri"]
    start_time: str = "00:00"       # "HH:MM"
    end_time: str = "00:00"         # "HH:MM"
    timezone: str = "Europe/Amsterdam"


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

    scope: str = "global"              # "global", "group", or "device"
    mac_address: Optional[str] = None  # required when scope == "device"
    group_id: Optional[int] = None     # required when scope == "group"
    service_name: Optional[str] = None
    category: Optional[str] = None
    action: str = "alert"              # "allow" | "alert" | "block"
    expires_at: Optional[datetime] = None  # NULL = permanent


class ServicePolicyRead(BaseModel):
    """Policy record returned by GET /api/policies."""

    id: int
    scope: str
    mac_address: Optional[str] = None
    group_id: Optional[int] = None
    service_name: Optional[str] = None
    category: Optional[str] = None
    action: str
    expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class NotificationConfigRead(BaseModel):
    id: int
    provider: str
    url: Optional[str] = None
    token_masked: Optional[str] = None  # partially masked
    enabled_categories: Optional[str] = None
    is_enabled: bool

    model_config = {"from_attributes": True}


class NotificationConfigUpdate(BaseModel):
    url: Optional[str] = None
    token: Optional[str] = None
    enabled_categories: Optional[str] = None
    is_enabled: bool = True


class AlertExceptionCreate(BaseModel):
    """Payload for POST /api/exceptions."""

    mac_address: str
    alert_type: str
    destination: Optional[str] = None
    expires_at: Optional[datetime] = None   # None = permanent whitelist
    dismissed_score: Optional[float] = None  # beacon score at dismiss time


class AlertExceptionRead(BaseModel):
    """Exception record returned by GET /api/exceptions."""

    id: int
    mac_address: str
    alert_type: str
    destination: Optional[str] = None
    expires_at: Optional[datetime] = None
    dismissed_score: Optional[float] = None
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
