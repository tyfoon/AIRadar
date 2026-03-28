"""
AI-Radar — Database layer.
Initializes a local SQLite database and defines the AI_Event and Device tables.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./airadar.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class AIEvent(Base):
    """Stores a single AI-traffic detection event reported by a sensor."""

    __tablename__ = "ai_events"

    id = Column(Integer, primary_key=True, index=True)
    sensor_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    detection_type = Column(String, nullable=False)  # e.g. "dns_query", "sni_hello"
    ai_service = Column(String, nullable=False)       # e.g. "openai", "anthropic"
    source_ip = Column(String, nullable=False)
    bytes_transferred = Column(Integer, nullable=False, default=0)
    possible_upload = Column(Boolean, nullable=False, default=False)


class Device(Base):
    """Caches resolved device information (reverse DNS, ARP/MAC).

    Keyed by IP address — the sensor populates this table as it discovers
    new source IPs on the network.  The dashboard uses it to show friendly
    device names instead of raw IP addresses.
    """

    __tablename__ = "devices"

    ip = Column(String, primary_key=True)               # e.g. "192.168.1.42"
    hostname = Column(String, nullable=True)             # reverse DNS result
    mac_address = Column(String, nullable=True)          # from ARP table
    display_name = Column(String, nullable=True)         # user-editable alias
    first_seen = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, nullable=False,
                       default=lambda: datetime.now(timezone.utc))


def init_db() -> None:
    """Create all tables if they don't exist yet, and migrate schema."""
    Base.metadata.create_all(bind=engine)

    # Add possible_upload column to existing databases that lack it
    inspector = inspect(engine)
    columns = [c["name"] for c in inspector.get_columns("ai_events")]
    if "possible_upload" not in columns:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE ai_events ADD COLUMN possible_upload BOOLEAN NOT NULL DEFAULT 0"
            ))
