"""
AI-Radar — Database layer.
Initializes a local SQLite database and defines the DetectionEvent, Device,
DeviceIP, and BlockRule tables.
Supports both AI-service and Cloud-storage detection categories.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
    LargeBinary, String, UniqueConstraint, create_engine, event, inspect, text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

import os

_db_path = os.environ.get("AIRADAR_DB_PATH", "./data/airadar.db")
os.makedirs(os.path.dirname(_db_path) or ".", exist_ok=True)
DATABASE_URL = f"sqlite:///{_db_path}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


# Enable WAL (Write-Ahead Logging) to prevent "database is locked"
# errors from concurrent writes by FastAPI (web requests) and
# zeek_tailer (background ingest). WAL allows readers and writers
# to operate simultaneously. PRAGMA synchronous=NORMAL gives a good
# balance between durability and write performance.
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


class Base(DeclarativeBase):
    pass


class DetectionEvent(Base):
    """Stores a single traffic detection event (AI or Cloud)."""

    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, index=True)
    sensor_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    detection_type = Column(String, nullable=False)   # e.g. "sni_hello", "dns_query", "volumetric_upload"
    ai_service = Column(String, nullable=False)        # e.g. "openai", "dropbox"
    source_ip = Column(String, nullable=False)
    bytes_transferred = Column(Integer, nullable=False, default=0)
    possible_upload = Column(Boolean, nullable=False, default=False)
    category = Column(String, nullable=False, default="ai")  # "ai" or "cloud"


class Device(Base):
    """A physical device identified by MAC address."""

    __tablename__ = "devices"

    mac_address = Column(String, primary_key=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)          # MAC vendor (e.g. "Apple", "Samsung")
    display_name = Column(String, nullable=True)
    os_name = Column(String, nullable=True)         # e.g. "macOS", "Windows", "Linux"
    os_version = Column(String, nullable=True)      # e.g. "14.x", "11", "6.x"
    os_full = Column(String, nullable=True)         # Full p0f label, e.g. "Mac OS X 10.x"
    device_class = Column(String, nullable=True)    # e.g. "laptop", "phone", "iot", "server"
    network_distance = Column(Integer, nullable=True)  # Hops away from sensor
    p0f_last_seen = Column(DateTime, nullable=True) # Last p0f fingerprint update
    ja4_fingerprint = Column(String, nullable=True) # Most recent JA4 TLS hash observed
    ja4_last_seen = Column(DateTime, nullable=True) # Last time a JA4 was recorded
    dhcp_vendor_class = Column(String, nullable=True)   # DHCP vendor_class_id (e.g. "MSFT 5.0", "android-dhcp-14")
    dhcp_fingerprint = Column(String, nullable=True)    # JA4D hash from ja4d.log
    ai_report_md = Column(String, nullable=True)        # Latest LLM-generated report (markdown)
    ai_report_at = Column(DateTime, nullable=True)      # When the report was generated
    ai_report_model = Column(String, nullable=True)     # Which model produced it (gemini-2.5-flash-lite, claude-haiku-4-5, ...)
    ai_report_tokens = Column(Integer, nullable=True)   # Total tokens used (for cost display)
    ai_report_flags = Column(String, nullable=True)     # JSON: extracted RecapFlags (vpn_detected, ai_usage_present, ...)
    # User-Agent fingerprinting (from http.log, Firewalla-inspired)
    ua_device_type = Column(String, nullable=True)     # e.g. "phone", "tablet", "desktop", "tv", "router"
    ua_brand = Column(String, nullable=True)            # e.g. "Apple", "Samsung", "Google"
    ua_model = Column(String, nullable=True)            # e.g. "iPhone", "Pixel 8", "Galaxy S24"
    ua_os = Column(String, nullable=True)               # e.g. "iOS", "Android", "Windows"
    ua_last_seen = Column(DateTime, nullable=True)      # Last UA fingerprint update
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    ips = relationship("DeviceIP", back_populates="device",
                       order_by="DeviceIP.last_seen.desc()")


class DeviceIP(Base):
    """Maps an IP address to a Device (many IPs per device)."""

    __tablename__ = "device_ips"

    ip = Column(String, primary_key=True)
    mac_address = Column(String, ForeignKey("devices.mac_address"), nullable=False, index=True)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    device = relationship("Device", back_populates="ips")


class TlsFingerprint(Base):
    """Observed (JA4 client, JA4S server, SNI) tuples per device.

    Phase 1 of context-aware service classification. Each row is a unique
    combination of client TLS fingerprint, server TLS fingerprint, and
    server name. The hit_count tracks how often the tuple was seen so we
    can later derive which tuples are "typical" for a device type (e.g. a
    Google Nest speaker has a specific (ja4, ja4s) combination for
    storage.googleapis.com that is distinct from a browser pulling Drive).
    """

    __tablename__ = "tls_fingerprints"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, ForeignKey("devices.mac_address"),
                         nullable=False, index=True)
    ja4 = Column(String, nullable=True, index=True)
    ja4s = Column(String, nullable=True)
    sni = Column(String, nullable=True, index=True)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    hit_count = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("mac_address", "ja4", "ja4s", "sni",
                         name="uq_tls_fingerprint_tuple"),
    )


class ServicePolicy(Base):
    """User-defined policy rules for services and categories.

    Supports two scopes:
      - "global": applies to every device on the network
      - "device": applies only to a specific MAC address

    A policy targets either a specific service (service_name) or an
    entire category (category). Policies are consulted by the alert
    engine to decide whether an event should be allowed, surfaced as
    an alert, or (in future) actively blocked.

    Resolution order (most specific wins):
      1. device + service_name
      2. device + category
      3. global + service_name
      4. global + category
    """

    __tablename__ = "service_policies"

    id = Column(Integer, primary_key=True, index=True)
    scope = Column(String, nullable=False, default="global", index=True)  # "global" | "group" | "device"
    mac_address = Column(String, nullable=True, index=True)
    group_id = Column(Integer, nullable=True, index=True)  # FK to device_groups.id
    service_name = Column(String, nullable=True, index=True)  # e.g. "openai", "roblox"
    category = Column(String, nullable=True, index=True)      # e.g. "ai", "gaming"
    action = Column(String, nullable=False, default="alert")  # "allow" | "alert" | "block"
    expires_at = Column(DateTime, nullable=True)               # NULL = permanent
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        UniqueConstraint(
            "scope", "mac_address", "service_name", "category",
            name="uq_policy_scope_mac_svc_cat",
        ),
    )


class AlertException(Base):
    """Snooze / whitelist rules for anomaly alerts.

    When an alert would normally be raised (e.g. beaconing_threat, VPN
    tunnel), the alert engine first checks for a matching AlertException.
    If one exists and has not yet expired, the alert is suppressed.

    Match rule: (mac_address, alert_type) must match. If destination is
    set on the exception, it must also match the event's destination;
    if destination is NULL, the exception covers all destinations for
    that (mac, alert_type) pair.

    expires_at == NULL  →  permanent whitelist
    expires_at > now    →  temporary snooze
    expires_at <= now   →  expired, ignored
    """

    __tablename__ = "alert_exceptions"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, nullable=False, index=True)
    alert_type = Column(String, nullable=False, index=True)  # e.g. "beaconing_threat", "vpn_tunnel"
    destination = Column(String, nullable=True)              # e.g. specific IP, country, service
    expires_at = Column(DateTime, nullable=True)             # NULL = permanent
    dismissed_score = Column(Float, nullable=True)           # beacon score at time of dismiss (re-alert if score rises >10)
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class GeoTraffic(Base):
    """Aggregated bandwidth per country + direction.

    Populated by the Zeek conn.log tailer via an in-memory buffer that
    flushes every ~15 seconds. One row per (country_code, direction)
    pair — bytes_transferred and hits accumulate over time.
    """

    __tablename__ = "geo_traffic"

    id = Column(Integer, primary_key=True, index=True)
    country_code = Column(String, nullable=False, index=True)   # e.g. "US", "NL"
    direction = Column(String, nullable=False, index=True)      # "inbound" | "outbound"
    bytes_transferred = Column(Integer, nullable=False, default=0)
    hits = Column(Integer, nullable=False, default=0)
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        UniqueConstraint("country_code", "direction", name="uq_geo_traffic_cc_dir"),
    )


class GeoConversation(Base):
    """High-resolution geo traffic: per (country, direction, device, service, remote IP).

    GeoTraffic answers "how much data goes to country X"; GeoConversation
    answers "WHICH device, using WHICH service, talking to WHICH IP in
    country X". The conn.log tailer buffers into both tables in parallel
    and they flush together every ~15 seconds.

    Rows are upserted on the full 5-tuple so repeated conversations
    accumulate bytes/hits rather than producing new rows. mac_address
    may be NULL for IPs the tailer couldn't resolve back to a known
    device (rare — usually IPs seen before devices register).
    """

    __tablename__ = "geo_conversations"

    id = Column(Integer, primary_key=True, index=True)
    country_code = Column(String, nullable=False, index=True)
    direction = Column(String, nullable=False, index=True)      # "inbound" | "outbound"
    mac_address = Column(String, nullable=True, index=True)
    ai_service = Column(String, nullable=False, default="unknown", index=True)
    resp_ip = Column(String, nullable=False, index=True)        # the remote public IP
    bytes_transferred = Column(Integer, nullable=False, default=0)
    orig_bytes = Column(Integer, nullable=False, default=0)  # device → remote (upload)
    resp_bytes = Column(Integer, nullable=False, default=0)  # remote → device (download)
    hits = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        UniqueConstraint(
            "country_code", "direction", "mac_address", "ai_service", "resp_ip",
            name="uq_geo_conv_full",
        ),
    )


class LanConversation(Base):
    """LAN-to-LAN traffic: per (src device, peer IP, port, proto).

    Parallel to GeoConversation but for flows where BOTH ends are local
    (e.g. Hikvision camera → NVR, smart hub → HomeAssistant, printer →
    client). The geo pipeline skips these because it has no country to
    tag them with — historically this traffic was entirely invisible to
    the IoT fleet card even though it's often the PRIMARY activity of
    a device (cameras stream to local NVRs all day).

    Recorded from the same conn.log tail path as GeoConversation, but
    in its own accumulator. Aggregated per 5-tuple (mac, peer_ip, port,
    proto) so the chatty IoT long-lived UDP heartbeats don't explode
    row count — repeated flows upsert on the same row.

    Queries for a specific device should match on either end:
      WHERE mac_address = X OR peer_mac = X
    because conn.log records one row per flow keyed on the originator;
    the peer's fleet card needs to find its own traffic via peer_mac.
    """

    __tablename__ = "lan_conversations"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, nullable=False, index=True)  # originator (local)
    peer_ip = Column(String, nullable=False, index=True)      # other local IP
    peer_mac = Column(String, nullable=True, index=True)      # may be null if unresolved
    port = Column(Integer, nullable=False)                    # responder port
    proto = Column(String, nullable=False)                    # "tcp" | "udp" | "icmp"
    bytes_transferred = Column(Integer, nullable=False, default=0)
    orig_bytes = Column(Integer, nullable=False, default=0)   # originator → peer
    resp_bytes = Column(Integer, nullable=False, default=0)   # peer → originator
    hits = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False, index=True,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        UniqueConstraint(
            "mac_address", "peer_ip", "port", "proto",
            name="uq_lan_conv_flow",
        ),
    )


class IpMetadata(Base):
    """Reverse-DNS and ASN cache for remote IPs seen in geo conversations.

    Populated by a background enrichment task in the tailer that picks
    unseen resp_ip values from geo_conversations, resolves PTR + ASN
    from a local MMDB (and/or async DNS), and stores the result here so
    subsequent renders can show 'AS15169 Google LLC · static.l.google.com'
    next to the raw IP.

    A row with updated_at set but asn NULL means lookup was attempted
    and failed (private IP, no rDNS, no MMDB match) — used to avoid
    repeatedly retrying dead IPs.
    """

    __tablename__ = "ip_metadata"

    ip = Column(String, primary_key=True)
    ptr = Column(String, nullable=True)                # reverse-DNS hostname
    asn = Column(Integer, nullable=True)               # numeric AS (e.g. 15169)
    asn_org = Column(String, nullable=True)            # org / netname (e.g. "Google LLC")
    country_code = Column(String, nullable=True)       # mirror of geo lookup for convenience
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class ReputationCache(Base):
    """Cached IP/domain reputation results from external threat intel APIs.

    Layer 1 (proactive, free, no key): URLhaus + ThreatFox (abuse.ch)
    Layer 2 (on-demand, API keys): AbuseIPDB + VirusTotal

    Clean results have status='clean'. Only malware/C2 hits show badges
    in the UI. Rows are refreshed after 7 days (Layer 1) or on demand.
    """

    __tablename__ = "reputation_cache"

    ip_or_domain = Column(String, primary_key=True)

    # Layer 1: URLhaus (malware distribution)
    urlhaus_status = Column(String, nullable=True)       # "clean" | "malware"
    urlhaus_threat = Column(String, nullable=True)       # malware family
    urlhaus_tags = Column(String, nullable=True)         # JSON array of tags
    urlhaus_url_count = Column(Integer, nullable=True)   # number of malware URLs
    urlhaus_checked_at = Column(DateTime, nullable=True)

    # Layer 1: ThreatFox (C2 / IOC database)
    threatfox_status = Column(String, nullable=True)     # "clean" | "c2"
    threatfox_malware = Column(String, nullable=True)    # malware family
    threatfox_confidence = Column(Integer, nullable=True) # 0-100
    threatfox_checked_at = Column(DateTime, nullable=True)

    # Layer 2: AbuseIPDB (on-demand)
    abuseipdb_score = Column(Integer, nullable=True)     # 0-100 abuse confidence
    abuseipdb_reports = Column(Integer, nullable=True)   # total reports
    abuseipdb_checked_at = Column(DateTime, nullable=True)

    # Layer 2: VirusTotal (on-demand)
    vt_malicious = Column(Integer, nullable=True)        # vendors flagging malicious
    vt_total = Column(Integer, nullable=True)            # total vendors
    vt_checked_at = Column(DateTime, nullable=True)


class DeviceGroup(Base):
    """A named group of devices for policy management.

    Groups can be nested one level deep (parent_id). A device can belong
    to multiple groups. Policies set on a group apply to all member
    devices, with priority: device > child-group > parent-group > global.

    auto_match_rules is a JSON array of match criteria. Rules are OR'd
    together — any rule matching adds the device to the group:
      [
        {"field": "vendor", "op": "contains_any", "value": ["hikvision", "dahua"]},
        {"field": "classified_type", "op": "equals_any", "value": ["ip camera"]}
      ]
    Evaluated periodically + on device register/update. Members added
    this way get DeviceGroupMember.source='auto' and can be excluded
    per-device via source='exclude'.

    origin + modified_at distinguish suggested groups (seeded by
    AI-Radar) from user-created ones, for a subtle UI indicator.
    Functionally all groups are the same: any can have policies, rules,
    members. ``origin='suggested'`` + ``modified_at IS NULL`` = pristine
    suggestion ✨. ``origin='suggested'`` + ``modified_at IS NOT NULL``
    = customized suggestion 🛠️. ``origin='user'`` = user-created (no
    badge).
    """

    __tablename__ = "device_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    parent_id = Column(Integer, nullable=True, index=True)  # FK to self for nesting
    icon = Column(String, nullable=True, default="users-three")  # Phosphor icon name
    color = Column(String, nullable=True, default="blue")
    auto_match_rules = Column(String, nullable=True)  # JSON array
    origin = Column(String, nullable=False, default="user")  # "suggested" | "user"
    modified_at = Column(DateTime, nullable=True)  # set on any user edit to a suggested group
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class DeviceGroupMember(Base):
    """Maps a device to a group."""

    __tablename__ = "device_group_members"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, nullable=False, index=True)
    mac_address = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, default="manual")  # "manual" or "auto"
    added_at = Column(DateTime, nullable=False,
                      default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        UniqueConstraint("group_id", "mac_address", name="uq_group_member"),
    )


class NotificationConfig(Base):
    """Notification integration configuration (currently Home Assistant only).

    Stores connection details and which alert categories should trigger
    push notifications. The token is stored in plaintext in SQLite
    (acceptable for a local-only appliance — the DB file is already
    root-owned on the host filesystem).
    """

    __tablename__ = "notification_config"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, nullable=False, default="homeassistant")
    url = Column(String, nullable=True)          # e.g. http://homeassistant.local:8123
    token = Column(String, nullable=True)        # Long-Lived Access Token
    notify_service = Column(String, nullable=True)  # e.g. "mobile_app_iphone_van_goswijn"
    enabled_categories = Column(String, nullable=True)  # comma-separated: "security,ai,gaming"
    is_enabled = Column(Boolean, nullable=False, default=True)
    last_notified_at = Column(DateTime, nullable=True)   # DB-persisted dedup watermark


class DeviceBaseline(Base):
    """Rolling 7-day traffic baseline per device for IoT anomaly detection.

    Computed nightly by a background task. The IoT page compares live
    traffic against these baselines to flag volume spikes, fan-out
    spikes, and new country/ASN appearances.

    Two parallel detection paths are stored here:

      1. Legacy 3σ thresholds (avg_*, stddev_*) — kept as a fallback for
         devices that don't yet have enough history to train a multivariate
         detector.
      2. PyOD ECOD detector (model_blob) — multivariate, parameter-free,
         non-Gaussian. Trained on the device's hourly feature vectors and
         used as the primary signal once at least FEATURE_MIN_HOURS of
         history exist.
    """

    __tablename__ = "device_baselines"

    mac_address = Column(String, primary_key=True)
    avg_bytes_hour = Column(Integer, nullable=False, default=0)
    avg_connections_hour = Column(Integer, nullable=False, default=0)
    avg_unique_destinations = Column(Integer, nullable=False, default=0)
    stddev_bytes = Column(Integer, nullable=False, default=0)
    stddev_connections = Column(Integer, nullable=False, default=0)
    known_asns = Column(String, nullable=True)        # JSON array of ASN numbers
    known_countries = Column(String, nullable=True)    # JSON array of country codes
    computed_at = Column(DateTime, nullable=False,
                         default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # --- Multivariate PyOD detector (ECOD) ---
    # Pickled (joblib) detector instance, or NULL if not yet trained.
    model_blob = Column(LargeBinary, nullable=True)
    # Detector class name, e.g. "ECOD". Used so we can swap algorithms
    # later (IForest, HBOS, ...) without breaking the loader.
    model_kind = Column(String, nullable=True)
    # Feature schema version — bump in api.py when the feature vector
    # changes so old models get retrained instead of mis-scored.
    feature_version = Column(Integer, nullable=True)
    # Number of training samples used to fit the detector.
    model_samples = Column(Integer, nullable=True)
    # Score of the 99th percentile of the training distribution.
    # Live hours scoring above this are flagged as anomalies. Storing
    # the threshold per-device gives us calibrated alerting instead of
    # the global contamination=0.1 default.
    score_p99 = Column(Float, nullable=True)
    model_trained_at = Column(DateTime, nullable=True)
    # --- Per-hour-of-day baseline (JSON, 24 entries) ---
    # Each entry: {"avg": bytes, "std": bytes} keyed by hour "0"–"23".
    # Used by the 3σ fallback to compare against the expected traffic for
    # this specific hour of the day, not a flat 24h average.
    hourly_profile = Column(String, nullable=True)


class DeviceTrafficHourly(Base):
    """Hourly traffic snapshots per device for historical graphs.

    Populated by a background task that runs every hour, aggregating
    GeoConversation data into per-device hourly buckets. Retained for
    30 days (cleaned up by _periodic_cleanup).
    """

    __tablename__ = "device_traffic_hourly"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, nullable=False, index=True)
    hour = Column(DateTime, nullable=False, index=True)  # truncated to hour
    bytes_out = Column(Integer, nullable=False, default=0)    # orig_bytes (TX/upload)
    bytes_in = Column(Integer, nullable=False, default=0)     # resp_bytes (RX/download)
    connections = Column(Integer, nullable=False, default=0)
    unique_destinations = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("mac_address", "hour", name="uq_device_traffic_hour"),
    )


class ScreenTime(Base):
    """Per-device, per-app/category usage time tracking (Firewalla-inspired).

    Tracks how long each device actively communicates with each service or
    category per day. A "session" is a window of continuous activity — if no
    new flow for a service is seen within SESSION_GAP_SECONDS, the session ends.

    This is the foundation for the Family Plan "screen time" feature.
    """

    __tablename__ = "screen_time"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, nullable=False, index=True)
    date = Column(String, nullable=False, index=True)  # "2026-04-20" (local date)
    service = Column(String, nullable=False, index=True)  # e.g. "youtube", "netflix", "unknown"
    category = Column(String, nullable=False, index=True)  # e.g. "streaming", "social", "gaming"
    seconds = Column(Integer, nullable=False, default=0)  # Total active seconds
    sessions = Column(Integer, nullable=False, default=0)  # Number of distinct sessions
    bytes_total = Column(Integer, nullable=False, default=0)  # Total bytes (for context)
    last_activity = Column(DateTime, nullable=True)  # Last flow timestamp (for session tracking)

    __table_args__ = (
        UniqueConstraint("mac_address", "date", "service", "category",
                         name="uq_screen_time_device_date_svc"),
    )


class KnownDomain(Base):
    """Dynamic domain → service mapping, populated by the service updater.

    Replaces the old hardcoded DOMAIN_MAP in zeek_tailer.py. Entries
    are seeded from the former curated list on first boot and then
    enriched nightly by community sources (v2fly domain-list-community,
    and in the future others). AdGuard + DuckDuckGo third-party data
    merges separately via third_party_sources.py — KnownDomain is the
    "curated" layer that wins on conflict.
    """

    __tablename__ = "known_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, unique=True, index=True)
    service_name = Column(String, nullable=False, index=True)
    category = Column(String, nullable=False, index=True)
    # Where this entry came from. Each source has a baseline trust level
    # in labeler.SOURCE_WEIGHTS — manual_seed and curated_v2fly are the
    # most trusted (deterministic), llm is the lowest (probabilistic).
    source = Column(String, nullable=False, default="seed")
    # Per-row confidence in [0,1]. Multiplied by source weight to get the
    # effective score in conflict resolution. Seeds default to 1.0,
    # v2fly to 0.95, AdGuard to 0.85, LLM gets the model's self-rated
    # confidence (typically 0.6-0.95).
    confidence = Column(Float, nullable=False, default=1.0)
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


# ---------------------------------------------------------------------------
# Labeler infrastructure (stap 1-4 van het coverage-uitbreidingsplan)
# ---------------------------------------------------------------------------
# Four tables that together form the audit-trail and learning surface for
# the multi-source service-identification pipeline. See labeler.py for
# the priority/conflict-resolution logic that operates over these.


class DnsObservation(Base):
    """Persisted snapshot of DNS resolutions seen on the wire.

    Populated by the dns.log tailer (and as a fallback by AdGuard's
    /control/querylog API). The live DNS-correlation lookup uses an
    in-memory cache for sub-millisecond latency; this table is the
    durable backing store for backfill, debugging, and the periodic
    "what hostname did this client resolve to this IP" historical
    queries.

    The composite index on (client_mac, server_ip, observed_at) is the
    hot path: "give me the most recent lookup for this (client, ip)
    pair within the last N minutes".
    """

    __tablename__ = "dns_observations"

    id = Column(Integer, primary_key=True, index=True)
    client_mac = Column(String, ForeignKey("devices.mac_address"),
                        nullable=False, index=True)
    server_ip = Column(String, nullable=False, index=True)
    query = Column(String, nullable=False)              # the resolved hostname
    answer_ips = Column(String)                          # JSON list of all returned IPs
    ttl = Column(Integer)                                # for cache invalidation
    observed_at = Column(DateTime, nullable=False, index=True,
                         default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    source_log = Column(String, nullable=False, default="zeek_dns")
    # source_log: "zeek_dns" | "adguard_querylog"

    __table_args__ = (
        Index("ix_dns_obs_lookup", "client_mac", "server_ip", "observed_at"),
    )


class LabelAttribution(Base):
    """One row per labeler proposal for a detection_event.

    A single detection_event may have multiple attributions if more than
    one labeler proposed a service for the same flow. This is the audit
    trail: months later we can ask "why did this flow get labeled as
    youtube" and see exactly which labeler said so, with what
    confidence and what reasoning.

    The winning attribution (highest effective_score) is what gets
    written into detection_events.ai_service. Losing attributions are
    still kept here for diagnostic purposes.
    """

    __tablename__ = "label_attributions"

    id = Column(Integer, primary_key=True, index=True)
    detection_event_id = Column(Integer,
                                ForeignKey("detection_events.id"),
                                nullable=False, index=True)
    labeler = Column(String, nullable=False, index=True)
    # labeler: "sni_direct" | "quic_sni_direct" | "dns_correlation" |
    #          "ja4_community_db" | "llm_inference" | "adguard_services" | ...
    proposed_service = Column(String, nullable=False)
    proposed_category = Column(String, nullable=False)
    effective_score = Column(Float, nullable=False)
    rationale = Column(String)
    is_winner = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class JA4Signature(Base):
    """Community-maintained JA4 fingerprint → application mapping.

    Populated by ja4_db_sync.py (stap 3) which weekly pulls FoxIO's
    public JA4 database. JA4 is a TLS client fingerprint that uniquely
    identifies the TLS library + version + cipher preferences of the
    client — letting us identify "which app made this connection" even
    when the SNI is hidden by ECH or QUIC encryption.

    Generic library fingerprints (Cronet, OkHttp, plain Chrome) get
    confidence-dampened in labeler.py because they don't tell us the
    specific app — only that it's "an Android HTTPS client".
    """

    __tablename__ = "ja4_signatures"

    ja4 = Column(String, primary_key=True)
    application = Column(String, nullable=False)   # "Hay Day", "YouTube", "Chrome"
    library = Column(String)                        # "Cronet/116", "Unity TLS"
    category = Column(String)                       # gaming/streaming/social/...
    confidence = Column(Float, nullable=False, default=0.8)
    source = Column(String, nullable=False, default="foxio")
    # source: "foxio" | "manual" | "observed" (self-learned from co-occurrence with SNI)
    notes = Column(String)
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class UnknownObservation(Base):
    """Staging table for things we couldn't label yet.

    Populated whenever stap 1-3 (sni_direct / dns_correlation / quic /
    ja4) fail to identify a flow. The LLM classifier (stap 4) drains
    this table in batches, runs PydanticAI to assign service+category,
    and writes the result back to known_domains. Items below the LLM
    confidence floor are kept here with classified_at set so we don't
    re-classify them.

    Sample MACs and destinations are kept (capped at 5 each via JSON)
    so the LLM has minimal context for the classification call without
    blowing up the prompt size.
    """

    __tablename__ = "unknown_observations"

    id = Column(Integer, primary_key=True, index=True)
    kind = Column(String, nullable=False)        # "sni" | "domain" | "ja4"
    value = Column(String, nullable=False, index=True)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    hit_count = Column(Integer, nullable=False, default=1)
    sample_macs = Column(String)                  # JSON: up to 5 example MACs
    sample_destinations = Column(String)          # JSON: up to 5 example IPs/ASNs
    classified_at = Column(DateTime)              # set when LLM has processed it
    classification_result = Column(String)        # JSON of LLM output (kept even if rejected)

    __table_args__ = (
        UniqueConstraint("kind", "value", name="uq_unknown_obs_kind_value"),
    )


class NetworkPerformance(Base):
    """Periodic network + system performance snapshots for troubleshooting.

    Collected every 60 seconds by a background task. Stores DNS latency,
    ping latency, packet loss, bridge interface counters, and system load
    so users can review historical performance instead of guessing.
    """

    __tablename__ = "network_performance"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # DNS resolution latency (ms) — time to resolve a test domain via AdGuard
    dns_latency_ms = Column(Integer, nullable=True)

    # Ping latency to default gateway (ms)
    ping_gateway_ms = Column(Integer, nullable=True)
    # Ping latency to internet (8.8.8.8) (ms)
    ping_internet_ms = Column(Integer, nullable=True)
    # Packet loss percentage (0-100) from ping test
    packet_loss_pct = Column(Integer, nullable=True)

    # Bridge interface counters (cumulative from /proc/net/dev)
    br_rx_bytes = Column(Integer, nullable=True)
    br_tx_bytes = Column(Integer, nullable=True)
    br_rx_packets = Column(Integer, nullable=True)
    br_tx_packets = Column(Integer, nullable=True)
    br_rx_errors = Column(Integer, nullable=True)
    br_tx_errors = Column(Integer, nullable=True)
    br_rx_drops = Column(Integer, nullable=True)
    br_tx_drops = Column(Integer, nullable=True)

    # System load
    cpu_percent = Column(Integer, nullable=True)
    memory_percent = Column(Integer, nullable=True)
    load_avg_1 = Column(Integer, nullable=True)   # x100 for precision without float
    load_avg_5 = Column(Integer, nullable=True)
    load_avg_15 = Column(Integer, nullable=True)


class InboundAttack(Base):
    """Aggregated inbound connection attempts from external IPs.

    One row per (source_ip, target_ip, target_port) tuple. Accumulates
    hit_count over time. severity is "blocked" (any inbound) or "threat"
    (source IP found in CrowdSec blocklist).
    """

    __tablename__ = "inbound_attacks"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, nullable=False, index=True)
    target_ip = Column(String, nullable=False, index=True)
    target_mac = Column(String, nullable=True, index=True)
    target_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False, default="tcp")
    severity = Column(String, nullable=False, default="blocked")  # "blocked" | "threat"
    conn_state = Column(String, nullable=True)  # Zeek conn_state: S0, REJ, S1, SF, etc.
    crowdsec_reason = Column(String, nullable=True)
    country_code = Column(String, nullable=True)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String, nullable=True)
    hit_count = Column(Integer, nullable=False, default=1)
    bytes_transferred = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        UniqueConstraint("source_ip", "target_ip", "target_port",
                         name="uq_inbound_attack_tuple"),
    )


class GeoBlockRule(Base):
    """Country-level traffic blocking via ipset + iptables on the bridge.

    Each row represents one blocked country. The direction field controls
    whether inbound, outbound, or both directions are blocked. The
    startup sync task in api.py re-applies all enabled rules on boot so
    blocking survives container restarts.
    """

    __tablename__ = "geo_block_rules"

    id = Column(Integer, primary_key=True, index=True)
    country_code = Column(String, nullable=False, unique=True)
    direction = Column(String, nullable=False, default="both")  # "inbound"|"outbound"|"both"
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class BlockRule(Base):
    """Stores active and expired block rules for AI/Cloud services."""

    __tablename__ = "block_rules"

    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String, nullable=False, index=True)   # e.g. "dropbox", "openai"
    domain = Column(String, nullable=False)                      # e.g. "dropbox.com"
    category = Column(String, nullable=False, default="ai")      # "ai" or "cloud"
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    expires_at = Column(DateTime, nullable=True)                 # NULL = permanent


class FilterSchedule(Base):
    """Server-side schedules for the three AdGuard high-level filters.

    One row per filter_key ("parental" | "social" | "gaming"). The background
    enforcer loop in api.py periodically compares the current clock against
    each row and toggles the matching AdGuard filter if needed.

    mode="always"  → filter is permanently ON (ignores days/times)
    mode="custom"  → filter is ON when now() falls inside the selected
                     weekdays AND between start_time and end_time

    days is a CSV of lowercase weekday names: "mon,tue,wed,thu,fri".
    Times are "HH:MM" 24h strings (local time in the configured timezone).
    """

    __tablename__ = "filter_schedules"

    filter_key = Column(String, primary_key=True)  # "parental"|"social"|"gaming"
    enabled = Column(Boolean, nullable=False, default=False)
    mode = Column(String, nullable=False, default="custom")  # "always"|"custom"
    days = Column(String, nullable=False, default="")  # CSV of weekday names
    start_time = Column(String, nullable=False, default="00:00")  # "HH:MM"
    end_time = Column(String, nullable=False, default="00:00")    # "HH:MM"
    timezone = Column(String, nullable=False, default="Europe/Amsterdam")
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


def init_db() -> None:
    """Create all tables if they don't exist yet, and migrate schema.

    Handles migration from the old IP-keyed devices table to the new
    MAC-keyed devices + device_ips tables.
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    # --- Migration: old ai_events → detection_events ---
    if "ai_events" in existing_tables and "detection_events" not in existing_tables:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE ai_events RENAME TO detection_events"))
            conn.execute(text(
                "ALTER TABLE detection_events ADD COLUMN category TEXT NOT NULL DEFAULT 'ai'"
            ))

    # --- Migration: old IP-keyed devices → MAC-keyed devices + device_ips ---
    _needs_device_migration = False
    if "devices" in existing_tables:
        dev_cols = [c["name"] for c in inspector.get_columns("devices")]
        # Old schema has 'ip' as a column; new schema does not
        if "ip" in dev_cols:
            _needs_device_migration = True

    if _needs_device_migration:
        with engine.begin() as conn:
            # 1. Read all old device rows
            rows = conn.execute(text(
                "SELECT ip, hostname, mac_address, vendor, display_name, first_seen, last_seen FROM devices"
            )).fetchall()

            # 2. Drop old table
            conn.execute(text("DROP TABLE devices"))

            # 3. Create new tables via SQLAlchemy metadata
            Device.__table__.create(bind=conn)
            DeviceIP.__table__.create(bind=conn)

            # 4. Migrate data: group by mac_address
            mac_groups = {}
            for row in rows:
                ip, hostname, mac, vendor, dname, fseen, lseen = row
                # Generate a placeholder MAC for devices without one
                if not mac:
                    mac = f"unknown_{ip.replace('.', '_').replace(':', '_')}"
                if mac not in mac_groups:
                    mac_groups[mac] = {
                        "hostname": hostname,
                        "vendor": vendor,
                        "display_name": dname,
                        "first_seen": fseen,
                        "last_seen": lseen,
                        "ips": [],
                    }
                else:
                    # Merge: keep earliest first_seen, latest last_seen
                    grp = mac_groups[mac]
                    if fseen and (not grp["first_seen"] or fseen < grp["first_seen"]):
                        grp["first_seen"] = fseen
                    if lseen and (not grp["last_seen"] or lseen > grp["last_seen"]):
                        grp["last_seen"] = lseen
                    if hostname and not grp["hostname"]:
                        grp["hostname"] = hostname
                    if dname and not grp["display_name"]:
                        grp["display_name"] = dname
                mac_groups[mac]["ips"].append({
                    "ip": ip,
                    "first_seen": fseen,
                    "last_seen": lseen,
                })

            # 5. Insert migrated data
            for mac, data in mac_groups.items():
                conn.execute(text(
                    "INSERT INTO devices (mac_address, hostname, vendor, display_name, first_seen, last_seen) "
                    "VALUES (:mac, :hostname, :vendor, :dname, :fseen, :lseen)"
                ), {
                    "mac": mac,
                    "hostname": data["hostname"],
                    "vendor": data["vendor"],
                    "dname": data["display_name"],
                    "fseen": data["first_seen"],
                    "lseen": data["last_seen"],
                })
                for ip_rec in data["ips"]:
                    conn.execute(text(
                        "INSERT INTO device_ips (ip, mac_address, first_seen, last_seen) "
                        "VALUES (:ip, :mac, :fseen, :lseen)"
                    ), {
                        "ip": ip_rec["ip"],
                        "mac": mac,
                        "fseen": ip_rec["first_seen"],
                        "lseen": ip_rec["last_seen"],
                    })

    # Create any remaining tables that don't exist yet
    Base.metadata.create_all(bind=engine)

    # --- Ensure devices p0f columns exist ---
    inspector = inspect(engine)
    if "devices" in inspector.get_table_names():
        dev_cols = [c["name"] for c in inspector.get_columns("devices")]
        p0f_columns = {
            "os_name": "TEXT",
            "os_version": "TEXT",
            "os_full": "TEXT",
            "device_class": "TEXT",
            "network_distance": "INTEGER",
            "p0f_last_seen": "DATETIME",
            "ja4_fingerprint": "TEXT",
            "ja4_last_seen": "DATETIME",
            "dhcp_vendor_class": "TEXT",
            "dhcp_fingerprint": "TEXT",
            "ai_report_md": "TEXT",
            "ai_report_at": "DATETIME",
            "ai_report_model": "TEXT",
            "ai_report_tokens": "INTEGER",
            "ai_report_flags": "TEXT",
            "ua_device_type": "TEXT",
            "ua_brand": "TEXT",
            "ua_model": "TEXT",
            "ua_os": "TEXT",
            "ua_last_seen": "DATETIME",
        }
        for col_name, col_type in p0f_columns.items():
            if col_name not in dev_cols:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}"))

    # --- Ensure notification_config columns exist ---
    inspector = inspect(engine)
    if "notification_config" in inspector.get_table_names():
        nc_cols = [c["name"] for c in inspector.get_columns("notification_config")]
        if "notify_service" not in nc_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE notification_config ADD COLUMN notify_service TEXT"
                ))
        if "last_notified_at" not in nc_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE notification_config ADD COLUMN last_notified_at DATETIME"
                ))

    # --- Ensure service_policies columns exist ---
    inspector = inspect(engine)
    if "service_policies" in inspector.get_table_names():
        sp_cols = [c["name"] for c in inspector.get_columns("service_policies")]
        if "group_id" not in sp_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE service_policies ADD COLUMN group_id INTEGER"
                ))

    # --- Ensure service_policies.expires_at column exists ---
    inspector = inspect(engine)
    if "service_policies" in inspector.get_table_names():
        sp_cols = [c["name"] for c in inspector.get_columns("service_policies")]
        if "expires_at" not in sp_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE service_policies ADD COLUMN expires_at DATETIME"
                ))

    # --- Ensure device_groups.origin + modified_at columns exist ---
    # Added for the "unified groups" feature: distinguishes AI-Radar
    # seeded suggestions ("suggested") from user-created groups ("user"),
    # with a subtle "modified" state once a suggestion is edited.
    inspector = inspect(engine)
    if "device_groups" in inspector.get_table_names():
        dg_cols = [c["name"] for c in inspector.get_columns("device_groups")]
        if "origin" not in dg_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE device_groups ADD COLUMN origin TEXT NOT NULL DEFAULT 'user'"
                ))
        if "modified_at" not in dg_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE device_groups ADD COLUMN modified_at DATETIME"
                ))

    # --- Ensure detection_events columns exist ---
    inspector = inspect(engine)
    if "detection_events" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("detection_events")]
        if "possible_upload" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE detection_events ADD COLUMN possible_upload BOOLEAN NOT NULL DEFAULT 0"
                ))
        if "category" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE detection_events ADD COLUMN category TEXT NOT NULL DEFAULT 'ai'"
                ))

    # --- InboundAttack: add conn_state column (Zeek connection outcome) ---
    if "inbound_attacks" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("inbound_attacks")]
        if "conn_state" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE inbound_attacks ADD COLUMN conn_state TEXT"
                ))

    # --- KnownDomain: add confidence column (labeler trust hierarchy) ---
    # Existing rows are seeds or v2fly entries — they keep their full
    # weight via the source field, so we backfill confidence=1.0 for them
    # and let new sources (adguard / llm) write lower values explicitly.
    inspector = inspect(engine)
    if "known_domains" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("known_domains")]
        if "confidence" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE known_domains ADD COLUMN confidence REAL NOT NULL DEFAULT 1.0"
                ))

    # --- AlertException: add dismissed_score column (beacon score at dismiss time) ---
    if "alert_exceptions" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("alert_exceptions")]
        if "dismissed_score" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE alert_exceptions ADD COLUMN dismissed_score REAL"
                ))

    # --- DeviceBaseline: add PyOD detector columns ---
    if "device_baselines" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("device_baselines")]
        baseline_extras = {
            "model_blob": "BLOB",
            "model_kind": "TEXT",
            "feature_version": "INTEGER",
            "model_samples": "INTEGER",
            "score_p99": "REAL",
            "model_trained_at": "DATETIME",
            "hourly_profile": "TEXT",
        }
        for col_name, col_type in baseline_extras.items():
            if col_name not in columns:
                with engine.begin() as conn:
                    conn.execute(text(
                        f"ALTER TABLE device_baselines ADD COLUMN {col_name} {col_type}"
                    ))

    # --- GeoConversation: add orig_bytes + resp_bytes columns ---
    if "geo_conversations" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("geo_conversations")]
        if "orig_bytes" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE geo_conversations ADD COLUMN orig_bytes INTEGER NOT NULL DEFAULT 0"
                ))
                conn.execute(text(
                    "ALTER TABLE geo_conversations ADD COLUMN resp_bytes INTEGER NOT NULL DEFAULT 0"
                ))

    # --- One-time migration: rename google_api → google_gemini ---
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE detection_events SET ai_service = 'google_gemini' "
            "WHERE ai_service = 'google_api'"
        ))

    # --- Day 2.5: purge mislabeled apple_tv data ---
    # The v2fly "apple" domain list (900+ brand-protection domains) was
    # wrongly mapped to apple_tv.  Remove those seed entries and clean up
    # the downstream tables so the dashboard no longer shows NTP, MDM,
    # App Store, etc. as "Apple TV".  Idempotent.
    with engine.begin() as conn:
        conn.execute(text(
            "DELETE FROM known_domains "
            "WHERE service_name = 'apple_tv' AND source = 'v2fly'"
        ))
        conn.execute(text(
            "DELETE FROM geo_conversations WHERE ai_service = 'apple_tv'"
        ))
        conn.execute(text(
            "DELETE FROM detection_events WHERE ai_service = 'apple_tv'"
        ))
        conn.execute(text(
            "DELETE FROM label_attributions "
            "WHERE proposed_service = 'apple_tv'"
        ))

    # --- Backfill: push Device.first_seen back to the oldest DeviceIP
    # first_seen, so placeholder→real MAC upgrades (and other late MAC
    # bindings) don't keep firing spurious "new device" alerts for IPs
    # that were already known. Idempotent — only affects rows where a
    # DeviceIP has an older first_seen than the device itself.
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE devices SET first_seen = ("
            "  SELECT MIN(device_ips.first_seen) FROM device_ips "
            "  WHERE device_ips.mac_address = devices.mac_address"
            ") "
            "WHERE EXISTS ("
            "  SELECT 1 FROM device_ips "
            "  WHERE device_ips.mac_address = devices.mac_address "
            "    AND device_ips.first_seen < devices.first_seen"
            ")"
        ))

    # --- Performance indexes for large tables ---
    # These CREATE INDEX IF NOT EXISTS are idempotent and safe to run on every boot.
    with engine.begin() as conn:
        # geo_conversations: speed up GROUP BY country queries and retention cleanup
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_geo_conv_last_seen "
            "ON geo_conversations (last_seen)"
        ))
        # ip_metadata: speed up NULL-asn enrichment scan
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_ip_metadata_asn "
            "ON ip_metadata (asn)"
        ))
        # alert_exceptions: speed up active-exception lookups and expired cleanup
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alert_exc_expires "
            "ON alert_exceptions (expires_at)"
        ))
        # tls_fingerprints: speed up retention cleanup
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_tls_fp_last_seen "
            "ON tls_fingerprints (last_seen)"
        ))
        # detection_events: speed up the `WHERE timestamp >= cutoff` window
        # used by /api/alerts/active and friends. Without this the Summary
        # page did a full table scan on every load, which became the main
        # cause of "Summary loads slower over time".
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_detection_events_timestamp "
            "ON detection_events (timestamp)"
        ))
        # inbound_attacks: enrichment lookup in /api/alerts/active filters
        # on last_seen >= cutoff. With ~thousands of rows this is still
        # cheap, but the index keeps it O(log N) as the table grows.
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_inbound_attacks_last_seen "
            "ON inbound_attacks (last_seen)"
        ))
