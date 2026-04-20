"""Seed extra domain categories into the KnownDomain table.

Run manually or called from api.py startup:
    python3 seed_domain_categories.py

Reads domain_categories_extra.json and upserts into known_domains.
Existing entries with source='seed' or source='v2fly' are NOT overwritten.
"""
import json
from pathlib import Path
from datetime import datetime, timezone

def seed_extra_categories(db_session, force=False):
    """Seed domain_categories_extra.json into KnownDomain table.

    Returns the number of new domains added.
    """
    from database import KnownDomain

    json_path = Path(__file__).parent / "domain_categories_extra.json"
    if not json_path.exists():
        print("[seed-categories] domain_categories_extra.json not found, skipping")
        return 0

    data = json.loads(json_path.read_text())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    added = 0

    for category, services in data.items():
        if category.startswith("_"):
            continue
        for service_name, domains in services.items():
            for domain in domains:
                domain = domain.lower().strip()
                if not domain:
                    continue

                # Check if already exists
                existing = db_session.query(KnownDomain).filter(
                    KnownDomain.domain == domain
                ).first()

                if existing:
                    if force:
                        existing.category = category
                        existing.service_name = service_name
                        existing.source = "extra_categories"
                        existing.updated_at = now
                        added += 1
                    continue

                entry = KnownDomain(
                    domain=domain,
                    service_name=service_name,
                    category=category,
                    source="extra_categories",
                    confidence=0.90,
                    updated_at=now,
                )
                db_session.add(entry)
                added += 1

    db_session.commit()
    return added


if __name__ == "__main__":
    from database import SessionLocal
    db = SessionLocal()
    try:
        count = seed_extra_categories(db)
        print(f"[seed-categories] Added {count} new domain→category mappings")
    finally:
        db.close()
