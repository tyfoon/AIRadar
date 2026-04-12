"""
ja4_db_sync.py — Sync FoxIO JA4+ community database into ja4_signatures.

Fetches the full database from https://ja4db.com/api/read/, filters to
entries with a ja4_fingerprint, and upserts into the ja4_signatures table.

Generic browser/library fingerprints (Chrome, Firefox, Safari, Chromium,
OkHttp, Cronet) are imported with dampened confidence (0.40) because they
identify the TLS client, not the service. App-specific fingerprints
(Anydesk, SoftEther VPN, etc.) get full confidence (0.80).

The sync is designed to be called:
  - On startup (if last sync was >7 days ago)
  - Periodically (every 7 days via asyncio background task)

Issue #6 fix: last_sync_at is persisted in SQLite (killswitch.json was
considered but a DB column is more robust). We read it on startup and
skip the sync if fresh enough.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

JA4DB_API_URL = "https://ja4db.com/api/read/"
SYNC_INTERVAL_DAYS = 7

# Generic TLS libraries/browsers — fingerprints for these don't identify
# a specific service, only the client stack. Confidence is dampened.
_GENERIC_PREFIXES = (
    "Chrome", "Chromium", "Firefox", "Safari", "Edge", "Opera",
    "Samsung Internet", "Brave", "Vivaldi", "UC Browser", "Yandex",
    "OkHttp", "Cronet", "boringssl", "OpenSSL", "GnuTLS", "NSS",
    "WinHTTP", "Java", "Go-http-client", "Python", "curl",
)

GENERIC_CONFIDENCE = 0.40   # dampened for generic browser/library
SPECIFIC_CONFIDENCE = 0.80  # full confidence for app-specific match


def _is_generic(application: str | None, library: str | None) -> bool:
    """Check if a JA4 entry is a generic browser/library fingerprint."""
    for prefix in _GENERIC_PREFIXES:
        if application and application.startswith(prefix):
            return True
        if library and library.startswith(prefix):
            return True
    return False


def _map_category(application: str | None) -> str | None:
    """Rough category mapping for known JA4 applications."""
    if not application:
        return None
    app_lower = application.lower()
    if any(k in app_lower for k in ("cobalt strike", "sliver", "icedid", "metasploit")):
        return "security"
    if any(k in app_lower for k in ("vpn", "softether", "wireguard")):
        return "tracking"  # VPN category
    if "anydesk" in app_lower or "teamviewer" in app_lower:
        return "cloud"
    if "ngrok" in app_lower:
        return "cloud"
    return None


async def sync_ja4_db(db_session) -> int:
    """Fetch FoxIO JA4 DB and upsert into ja4_signatures.

    Returns the number of rows upserted.
    """
    from database import JA4Signature

    log.info("[ja4_sync] Fetching FoxIO JA4+ database from %s", JA4DB_API_URL)
    async with httpx.AsyncClient() as client:
        resp = await client.get(JA4DB_API_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()

    log.info("[ja4_sync] Received %d records, filtering to ja4_fingerprint entries", len(data))

    count = 0
    for entry in data:
        ja4 = entry.get("ja4_fingerprint")
        if not ja4:
            continue

        application = entry.get("application")
        library = entry.get("library")

        # We need at least an application or library name to be useful
        if not application and not library:
            continue

        generic = _is_generic(application, library)
        confidence = GENERIC_CONFIDENCE if generic else SPECIFIC_CONFIDENCE
        category = _map_category(application)

        # Display name: prefer application, fall back to library
        display_name = application or library or "unknown"

        existing = db_session.query(JA4Signature).filter(
            JA4Signature.ja4 == ja4
        ).first()

        if existing:
            # Only update if source is "foxio" (don't overwrite manual entries)
            if existing.source == "foxio":
                existing.application = display_name
                existing.library = library
                existing.category = category
                existing.confidence = confidence
                existing.notes = entry.get("notes")
                existing.updated_at = datetime.now(timezone.utc)
        else:
            db_session.add(JA4Signature(
                ja4=ja4,
                application=display_name,
                library=library,
                category=category,
                confidence=confidence,
                source="foxio",
                notes=entry.get("notes"),
            ))
        count += 1

    db_session.commit()
    log.info("[ja4_sync] Upserted %d ja4_signatures rows", count)
    return count


def needs_sync(db_session) -> bool:
    """Check if the JA4 DB needs a sync (last sync >7 days ago or never)."""
    from database import JA4Signature
    from sqlalchemy import func

    latest = db_session.query(func.max(JA4Signature.updated_at)).scalar()
    if latest is None:
        return True
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - latest
    return age > timedelta(days=SYNC_INTERVAL_DAYS)
