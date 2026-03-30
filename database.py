"""
AI-Radar — Database layer.
Initializes a local SQLite database and defines the DetectionEvent, Device,
DeviceIP, and BlockRule tables.
Supports both AI-service and Cloud-storage detection categories.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String,
    create_engine, inspect, text,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

DATABASE_URL = "sqlite:///./airadar.db"

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

    # --- Merge placeholder devices into real-MAC devices ---
    inspector = inspect(engine)
    if "devices" in inspector.get_table_names() and "device_ips" in inspector.get_table_names():
        with engine.begin() as conn:
            placeholders = conn.execute(text(
                "SELECT d.mac_address, d.hostname FROM devices d "
                "WHERE d.mac_address LIKE 'unknown_%'"
            )).fetchall()

            for ph_mac, ph_host in placeholders:
                target_mac = None

                # Strategy 1: hostname match
                if ph_host:
                    real = conn.execute(text(
                        "SELECT mac_address FROM devices "
                        "WHERE hostname = :host AND mac_address NOT LIKE 'unknown_%' LIMIT 1"
                    ), {"host": ph_host}).fetchone()
                    if real:
                        target_mac = real[0]

                # Strategy 2: IPv6 /64 prefix match
                if not target_mac:
                    import ipaddress
                    ph_ips = conn.execute(text(
                        "SELECT ip FROM device_ips WHERE mac_address = :mac"
                    ), {"mac": ph_mac}).fetchall()
                    for (ph_ip,) in ph_ips:
                        if ":" not in ph_ip:
                            continue
                        try:
                            ph_net = ipaddress.ip_network(f"{ph_ip}/64", strict=False)
                        except Exception:
                            continue
                        # Find any real-MAC device with an IP in the same /64
                        real_ips = conn.execute(text(
                            "SELECT di.ip, di.mac_address FROM device_ips di "
                            "JOIN devices d ON d.mac_address = di.mac_address "
                            "WHERE d.mac_address NOT LIKE 'unknown_%'"
                        )).fetchall()
                        for (r_ip, r_mac) in real_ips:
                            if ":" not in r_ip:
                                continue
                            try:
                                r_net = ipaddress.ip_network(f"{r_ip}/64", strict=False)
                                if r_net == ph_net:
                                    target_mac = r_mac
                                    break
                            except Exception:
                                continue
                        if target_mac:
                            break

                if not target_mac:
                    continue

                # Move IPs and delete placeholder
                conn.execute(text(
                    "UPDATE device_ips SET mac_address = :real WHERE mac_address = :ph"
                ), {"real": target_mac, "ph": ph_mac})
                conn.execute(text(
                    "DELETE FROM devices WHERE mac_address = :mac"
                ), {"mac": ph_mac})

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
