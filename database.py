"""
AI-Radar — Database layer.
Initializes a local SQLite database and defines the DetectionEvent, Device,
DeviceIP, and BlockRule tables.
Supports both AI-service and Cloud-storage detection categories.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String,
    UniqueConstraint, create_engine, inspect, text,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

import os

_db_path = os.environ.get("AIRADAR_DB_PATH", "./data/airadar.db")
os.makedirs(os.path.dirname(_db_path) or ".", exist_ok=True)
DATABASE_URL = f"sqlite:///{_db_path}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class DetectionEvent(Base):
    """Stores a single traffic detection event (AI or Cloud)."""

    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, index=True)
    sensor_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
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
    ai_report_md = Column(String, nullable=True)        # Latest Gemini-generated report (markdown)
    ai_report_at = Column(DateTime, nullable=True)      # When the report was generated
    ai_report_model = Column(String, nullable=True)     # Which Gemini model produced it
    ai_report_tokens = Column(Integer, nullable=True)   # Total tokens used (for cost display)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc))

    ips = relationship("DeviceIP", back_populates="device",
                       order_by="DeviceIP.last_seen.desc()")


class DeviceIP(Base):
    """Maps an IP address to a Device (many IPs per device)."""

    __tablename__ = "device_ips"

    ip = Column(String, primary_key=True)
    mac_address = Column(String, ForeignKey("devices.mac_address"), nullable=False, index=True)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc))

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
                        default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc))
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
    scope = Column(String, nullable=False, default="global", index=True)  # "global" | "device"
    mac_address = Column(String, nullable=True, index=True)
    service_name = Column(String, nullable=True, index=True)  # e.g. "openai", "roblox"
    category = Column(String, nullable=True, index=True)      # e.g. "ai", "gaming"
    action = Column(String, nullable=False, default="alert")  # "allow" | "alert" | "block"
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

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
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))


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
                       default=lambda: datetime.now(timezone.utc))

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
    hits = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint(
            "country_code", "direction", "mac_address", "ai_service", "resp_ip",
            name="uq_geo_conv_full",
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
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


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
    source = Column(String, nullable=False, default="seed")  # "seed", "v2fly", "manual"
    updated_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


class BlockRule(Base):
    """Stores active and expired block rules for AI/Cloud services."""

    __tablename__ = "block_rules"

    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String, nullable=False, index=True)   # e.g. "dropbox", "openai"
    domain = Column(String, nullable=False)                      # e.g. "dropbox.com"
    category = Column(String, nullable=False, default="ai")      # "ai" or "cloud"
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)                 # NULL = permanent


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
        }
        for col_name, col_type in p0f_columns.items():
            if col_name not in dev_cols:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}"))

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
