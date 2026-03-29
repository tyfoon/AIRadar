"""
AI-Radar — Database layer.
Initializes a local SQLite database and defines the DetectionEvent and Device
tables.  Supports both AI-service and Cloud-storage detection categories.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

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
    """Caches resolved device information (reverse DNS, ARP/MAC)."""

    __tablename__ = "devices"

    ip = Column(String, primary_key=True)
    hostname = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    vendor = Column(String, nullable=True)          # MAC vendor (e.g. "Apple", "Samsung")
    display_name = Column(String, nullable=True)
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc))


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

    Handles migration from the old 'ai_events' table to 'detection_events'.
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    # Migrate: rename old ai_events table to detection_events and add category
    if "ai_events" in existing_tables and "detection_events" not in existing_tables:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE ai_events RENAME TO detection_events"))
            # Add category column to the renamed table
            conn.execute(text(
                "ALTER TABLE detection_events ADD COLUMN category TEXT NOT NULL DEFAULT 'ai'"
            ))

    # Create any missing tables (detection_events, devices)
    Base.metadata.create_all(bind=engine)

    # If detection_events already existed, ensure it has the category column
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

    # Ensure devices table has vendor column
    if "devices" in inspector.get_table_names():
        dev_cols = [c["name"] for c in inspector.get_columns("devices")]
        if "vendor" not in dev_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE devices ADD COLUMN vendor TEXT"
                ))
