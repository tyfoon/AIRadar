"""
seed_adguard_services.py — one-shot import of AdGuard's service catalog.

AdGuard Home maintains a curated list of ~100 popular online services
(Facebook, YouTube, Discord, Supercell, etc.) with the domains each
service uses. This is exactly the kind of high-quality, community-
maintained data we'd otherwise have to curate ourselves.

What this script does:
  1. Try to fetch the catalog from the local AdGuard Home instance via
     /control/blocked_services/all (no auth required if running from
     trusted hosts; falls through silently otherwise).
  2. Fall back to the GitHub raw URL of the same JSON file maintained
     by the AdGuard team — this is the source of truth they ship with
     each AdGuard Home release.
  3. Parse the AdBlock-format rules ("||facebook.com^") into clean
     domains, dropping anything we can't normalize confidently.
  4. Map each AdGuard service id to one of our internal categories
     (social / streaming / gaming / shopping / ai / other) using a
     curated lookup table — and a name-keyword fallback for newer
     services we haven't classified yet.
  5. Bulk upsert into known_domains with source='adguard' and
     confidence=0.85 — high enough to beat heuristic labelers but
     below the manually curated seed/v2fly tiers.

Idempotent: re-running this script updates existing rows in place
(latest service name + category) and only adds new domains. It does
not delete domains that have disappeared from AdGuard's catalog — we
intentionally keep historical labels so an upstream removal doesn't
silently break our coverage.

Run manually:
    python seed_adguard_services.py

Or via the API admin endpoint we'll wire up later:
    POST /api/admin/seed-adguard
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from typing import Iterable, Optional

import httpx

# Make sibling modules importable when running directly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import KnownDomain, SessionLocal, init_db


# ---------------------------------------------------------------------------
# Sources (in order of preference)
# ---------------------------------------------------------------------------

# Local AdGuard Home — same instance our adguard_client.py talks to.
# Default port matches docker-compose.yml; ADGUARD_URL env var can override.
LOCAL_ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://localhost:3000")
LOCAL_ADGUARD_PATH = "/control/blocked_services/all"

# Authoritative GitHub source. This is the same JSON file shipped with
# every AdGuard Home release. Maintained by the AdGuard team in their
# HostlistsRegistry repo.
GITHUB_FALLBACK = (
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/"
    "assets/services.json"
)

# Confidence we assign to AdGuard-sourced entries. Sits below our
# manually curated seeds (1.0) and v2fly community lists (0.95) but
# comfortably above probabilistic labelers (LLM at 0.70). See
# labeler.SOURCE_WEIGHTS for the full hierarchy.
ADGUARD_CONFIDENCE = 0.85
ADGUARD_SOURCE_TAG = "adguard"


# ---------------------------------------------------------------------------
# AdGuard service id → our category mapping
# ---------------------------------------------------------------------------
# AdGuard's catalog uses descriptive ids like "facebook", "youtube",
# "supercell". We map them to AI-Radar's category set:
#   social / streaming / gaming / shopping / ai / news / cloud / other
#
# This list is a snapshot of what AdGuard ships as of the writing of
# this script (early 2026). New services they add later will fall
# through to the keyword-based fallback in derive_category().
ADGUARD_CATEGORY_MAP: dict[str, str] = {
    # Social / messaging
    "facebook": "social", "facebook_messenger": "social",
    "instagram": "social", "twitter": "social", "x": "social",
    "tiktok": "social", "snapchat": "social", "linkedin": "social",
    "pinterest": "social", "reddit": "social", "discord": "social",
    "tumblr": "social", "vk": "social", "ok_ru": "social",
    "weibo": "social", "wechat": "social", "qq": "social",
    "telegram": "social", "whatsapp": "social", "signal": "social",
    "mastodon": "social", "threads": "social", "bluesky": "social",
    "viber": "social", "line": "social", "kik": "social",
    "skype": "social",
    # Streaming (video + music)
    "youtube": "streaming", "netflix": "streaming", "spotify": "streaming",
    "twitch": "streaming", "hulu": "streaming", "disneyplus": "streaming",
    "disney_plus": "streaming", "primevideo": "streaming",
    "amazon_video": "streaming", "amazonprime": "streaming",
    "hbo_max": "streaming", "hbomax": "streaming", "max": "streaming",
    "appletv": "streaming", "apple_tv": "streaming",
    "soundcloud": "streaming", "deezer": "streaming", "tidal": "streaming",
    "vimeo": "streaming", "dailymotion": "streaming", "rumble": "streaming",
    "crunchyroll": "streaming", "funimation": "streaming",
    "iqiyi": "streaming", "bilibili": "streaming", "youku": "streaming",
    "9gag": "streaming", "tubitv": "streaming",
    "plex": "streaming", "vudu": "streaming", "peacock": "streaming",
    # Gaming
    "steam": "gaming", "epic_games": "gaming", "epicgames": "gaming",
    "battle_net": "gaming", "battlenet": "gaming",
    "origin": "gaming", "ea": "gaming", "ea_games": "gaming",
    "xbox_live": "gaming", "xboxlive": "gaming", "xbox": "gaming",
    "playstation": "gaming", "playstation_network": "gaming", "psn": "gaming",
    "nintendo": "gaming", "ubisoft": "gaming", "rockstar_games": "gaming",
    "rockstargames": "gaming", "riot_games": "gaming", "riotgames": "gaming",
    "supercell": "gaming", "minecraft": "gaming", "roblox": "gaming",
    "twitch_tv": "gaming", "discord_inc": "gaming",
    "wargaming": "gaming",
    # Shopping
    "amazon": "shopping", "ebay": "shopping", "aliexpress": "shopping",
    "etsy": "shopping", "wish": "shopping", "shein": "shopping",
    "temu": "shopping", "alibaba": "shopping", "walmart": "shopping",
    "target": "shopping", "bestbuy": "shopping", "ikea": "shopping",
    # AI
    "openai": "ai", "chatgpt": "ai", "anthropic": "ai", "claude": "ai",
    "google_gemini": "ai", "gemini": "ai", "perplexity": "ai",
    "huggingface": "ai", "mistral": "ai",
    # Cloud / productivity (we deliberately keep these in their own bucket)
    "dropbox": "cloud", "google_drive": "cloud", "googledrive": "cloud",
    "onedrive": "cloud", "icloud": "cloud", "box": "cloud",
    "github": "cloud", "gitlab": "cloud", "bitbucket": "cloud",
    "notion": "cloud",
    # News
    "cnn": "news", "bbc": "news", "nyt": "news", "fox_news": "news",
    "guardian": "news",
}


def derive_category(service_id: str, name: Optional[str]) -> str:
    """Map an AdGuard service id (with optional friendly name) to our category set.

    Falls through to a name-keyword heuristic for services not in the
    explicit map, then defaults to 'other'. We bias towards 'other'
    rather than guessing wrong because a wrong category corrupts the
    Activity tab and AI recap downstream.
    """
    if service_id in ADGUARD_CATEGORY_MAP:
        return ADGUARD_CATEGORY_MAP[service_id]

    haystack = " ".join(filter(None, [service_id, (name or "")])).lower()

    # Order matters: more specific keywords first.
    if any(k in haystack for k in (
        "messenger", "chat ", "social", "dating", "forum"
    )):
        return "social"
    if any(k in haystack for k in (
        "video", "music", "stream", "tv", "podcast", "radio", "anime"
    )):
        return "streaming"
    if any(k in haystack for k in ("game", "gaming", "esports", "play")):
        return "gaming"
    if any(k in haystack for k in ("shop", "store", "market", "deal", "buy")):
        return "shopping"
    if any(k in haystack for k in ("news", "press", "journal", "media")):
        return "news"
    if any(k in haystack for k in ("cloud", "drive", "backup", "sync", "git", "code")):
        return "cloud"
    if any(k in haystack for k in ("ai", "llm", "gpt", "model")):
        return "ai"

    return "other"


# ---------------------------------------------------------------------------
# AdBlock rule parsing
# ---------------------------------------------------------------------------

# Anchored AdBlock domain rule: ||domain.tld^ (optionally with port suffix).
# We deliberately ONLY accept this exact form. Anything more complex
# (regex, $-modifiers, paths) is dropped — those rules don't translate
# cleanly to "this hostname == this service" labels.
_RULE_DOMAIN_RE = re.compile(r"^\|\|([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})\^?$")


def extract_domains(rules: Iterable[str]) -> set[str]:
    """Pull clean lowercase domains out of AdBlock-format rules.

    Rejects anything we cannot confidently normalize: rules with paths,
    rules with $modifiers, regex rules, wildcards in the host portion,
    rules without the leading || anchor, etc. The goal is precision —
    we'd rather skip an ambiguous rule than misclassify it.
    """
    out: set[str] = set()
    for raw in rules:
        if not raw or not isinstance(raw, str):
            continue
        rule = raw.strip()
        # Strip $-modifiers like "||example.com^$third-party"
        if "$" in rule:
            rule = rule.split("$", 1)[0]
        m = _RULE_DOMAIN_RE.match(rule)
        if not m:
            continue
        domain = m.group(1).lower()
        # Sanity bounds
        if len(domain) < 4 or len(domain) > 253:
            continue
        out.add(domain)
    return out


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

async def _try_local_adguard() -> Optional[dict]:
    """Try the local AdGuard Home API. Returns parsed JSON or None on failure."""
    url = LOCAL_ADGUARD_URL.rstrip("/") + LOCAL_ADGUARD_PATH
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                print(f"[adguard-seed] local AdGuard returned HTTP {resp.status_code}")
                return None
            return resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        print(f"[adguard-seed] local AdGuard unreachable: {exc}")
        return None


async def _try_github_fallback() -> Optional[dict]:
    """Fetch the canonical services.json from AdGuard's HostlistsRegistry."""
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(GITHUB_FALLBACK)
            if resp.status_code != 200:
                print(f"[adguard-seed] GitHub fallback HTTP {resp.status_code}")
                return None
            return resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        print(f"[adguard-seed] GitHub fallback failed: {exc}")
        return None


async def fetch_catalog() -> Optional[list[dict]]:
    """Try local AdGuard first, then GitHub. Return the list of service entries.

    Both endpoints return the same shape:
        {"blocked_services": [{"id": ..., "name": ..., "rules": [...]}, ...]}
    Some older AdGuard versions return just a bare list — we handle both.
    """
    payload = await _try_local_adguard()
    if payload is None:
        print("[adguard-seed] falling back to GitHub raw URL...")
        payload = await _try_github_fallback()
    if payload is None:
        return None

    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("blocked_services") or payload.get("services") or []
    return None


# ---------------------------------------------------------------------------
# Bulk upsert into known_domains
# ---------------------------------------------------------------------------

def upsert_domains(catalog: list[dict]) -> dict:
    """Upsert each (domain, service, category) triple into known_domains.

    Quality rules:
      - We never lower an existing row's confidence. If a manual seed at
        confidence 1.0 already covers a domain that AdGuard also lists,
        we leave the seed alone — manual is gold.
      - We never overwrite a row whose source has a higher trust tier
        in labeler.SOURCE_WEIGHTS. So adguard cannot replace seed/v2fly
        entries even if AdGuard's version is newer.
      - For our own (adguard-sourced) rows, re-running this script
        updates the service name + category if upstream has changed and
        bumps updated_at. Idempotent.

    Returns a stats dict for the caller to log.
    """
    from labeler import SOURCE_WEIGHTS

    db = SessionLocal()
    stats = {
        "services_seen": 0,
        "domains_seen": 0,
        "rows_inserted": 0,
        "rows_updated": 0,
        "rows_skipped_higher_trust": 0,
        "rows_skipped_no_change": 0,
    }

    try:
        # Build the full target set first so we can do bulk lookups
        # instead of one query per domain. AdGuard's catalog occasionally
        # lists the same domain under multiple services (e.g. primevideo.tv
        # appears under both "amazon_video" and "amazon_streaming") — we
        # dedupe to "first service wins" so the import is deterministic
        # and never tries to insert a domain twice in one batch.
        targets_by_domain: dict[str, tuple[str, str]] = {}  # domain → (service, category)
        for svc in catalog:
            if not isinstance(svc, dict):
                continue
            sid = (svc.get("id") or "").strip().lower()
            if not sid:
                continue
            stats["services_seen"] += 1
            sname = svc.get("name") or sid
            category = derive_category(sid, sname)
            domains = extract_domains(svc.get("rules") or [])
            stats["domains_seen"] += len(domains)
            for d in domains:
                # We use the AdGuard service id as the canonical service
                # name. Lowercase snake_case keeps it consistent with our
                # existing seed convention. First-wins on duplicates.
                if d not in targets_by_domain:
                    targets_by_domain[d] = (sid, category)

        if not targets_by_domain:
            return stats

        targets = [(d, s, c) for d, (s, c) in targets_by_domain.items()]

        # Bulk fetch existing rows for the domains we want to upsert.
        domain_set = set(targets_by_domain.keys())
        existing = {
            r.domain: r for r in
            db.query(KnownDomain).filter(KnownDomain.domain.in_(domain_set)).all()
        }

        adguard_weight = SOURCE_WEIGHTS.get("adguard_services", 0.85)

        for domain, service, category in targets:
            row = existing.get(domain)
            if row is None:
                db.add(KnownDomain(
                    domain=domain,
                    service_name=service,
                    category=category,
                    source=ADGUARD_SOURCE_TAG,
                    confidence=ADGUARD_CONFIDENCE,
                ))
                stats["rows_inserted"] += 1
                continue

            # Trust hierarchy: never overwrite something more trusted.
            existing_weight = SOURCE_WEIGHTS.get(
                _source_to_weight_key(row.source),
                0.5,
            )
            if existing_weight > adguard_weight:
                stats["rows_skipped_higher_trust"] += 1
                continue

            # It's our own (or a lower-tier) row — refresh it if anything changed.
            changed = False
            if row.service_name != service:
                row.service_name = service
                changed = True
            if row.category != category:
                row.category = category
                changed = True
            if row.source != ADGUARD_SOURCE_TAG:
                row.source = ADGUARD_SOURCE_TAG
                changed = True
            if (row.confidence or 0) < ADGUARD_CONFIDENCE:
                row.confidence = ADGUARD_CONFIDENCE
                changed = True

            if changed:
                stats["rows_updated"] += 1
            else:
                stats["rows_skipped_no_change"] += 1

        db.commit()
    finally:
        db.close()

    return stats


def _source_to_weight_key(source: Optional[str]) -> str:
    """Map a known_domains.source value to its labeler.SOURCE_WEIGHTS key.

    The labeler hierarchy uses descriptive labeler-name keys
    ('manual_seed', 'curated_v2fly', etc.) but the database stores
    shorter source tags ('seed', 'v2fly', 'adguard'). This bridges them.
    """
    if not source:
        return "manual_seed"  # be charitable to nulls
    return {
        "seed": "manual_seed",
        "manual": "manual_seed",
        "v2fly": "curated_v2fly",
        "adguard": "adguard_services",
        "llm": "llm_inference",
    }.get(source, "manual_seed")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def main() -> int:
    print("[adguard-seed] starting AdGuard service catalog import")
    print(f"[adguard-seed] target DB: {os.environ.get('AIRADAR_DB_PATH', './data/airadar.db')}")

    # Make sure the schema is up to date (idempotent).
    init_db()

    catalog = await fetch_catalog()
    if not catalog:
        print("[adguard-seed] FAILED to fetch catalog from any source")
        return 1

    print(f"[adguard-seed] fetched {len(catalog)} services from upstream")

    stats = upsert_domains(catalog)
    print()
    print("[adguard-seed] import complete")
    for k, v in stats.items():
        print(f"  {k:<30} {v}")
    print()
    print(f"[adguard-seed] {stats['rows_inserted']} new domains added, "
          f"{stats['rows_updated']} updated, "
          f"{stats['rows_skipped_higher_trust']} preserved (higher trust)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
