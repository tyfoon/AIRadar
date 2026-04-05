"""
Third-party service & tracker data sources.

Loads two community-maintained datasets and merges them into a lookup
map that the Zeek tailer uses on top of its hand-curated DOMAIN_MAP:

    1. AdGuard HostlistsRegistry (services.json)
       ~130 services with groups (streaming, social_network, gaming,
       messenger, shopping, ai, gambling, hosting, ...). Covers services
       our hand-curated list misses — full Roblox / Netflix / TikTok
       domain sets, Epic Games, PlayStation, Xbox Live, Disney+, HBO
       Max, Prime Video, etc.

    2. DuckDuckGo Tracker Dataset (android-tds.json)
       ~3000 tracker domains with owner grouping and categories.
       Replaces our ~30 hand-curated tracker entries with 100x broader
       coverage plus owner labels (doubleclick.net → "Google LLC").

The merged result is a dict:
    { domain: (service_name, category) }

Our hand-curated DOMAIN_MAP in zeek_tailer.py is always overlaid on
top — curated entries win on conflict. The third-party data only
fills in gaps.

On-disk cache: data/third_party_services.json, refreshed weekly.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import httpx  # only for type hints — avoid hard import at module load


# ---------------------------------------------------------------------------
# Data source URLs
# ---------------------------------------------------------------------------

ADGUARD_SERVICES_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/"
    "main/assets/services.json"
)
DDG_TDS_URL = (
    "https://staticcdn.duckduckgo.com/trackerblocking/v5/current/"
    "android-tds.json"
)

# Category name normalisation. AdGuard uses snake_case group names;
# we map them to the lowercase category tags our backend already uses.
_ADGUARD_GROUP_MAP: dict[str, str] = {
    "streaming":      "streaming",
    "social_network": "social",
    "gaming":         "gaming",
    "messenger":      "social",
    "shopping":       "shopping",
    "ai":             "ai",
    "gambling":       "gambling",
    "hosting":        "cloud",
    "privacy":        "tracking",
    "dating":         "social",
    "software":       "cloud",
    "cdn":            "cloud",
}

# DDG uses PascalCase category names. Everything the TDS calls a tracker
# goes into our single "tracking" bucket — the upstream categories
# (Advertising, Analytics, Session Replay, ...) are kept as a detail
# field so the UI can drill down if needed, but the primary category
# is always "tracking".


# ---------------------------------------------------------------------------
# Adblock rule → domain parser
# ---------------------------------------------------------------------------

# Domains that Phase 2 context-aware resolvers handle specially. These
# must be excluded from the third-party map so DDG/AdGuard don't
# reintroduce them under a different label (e.g. DDG labelling
# storage.googleapis.com as "google_ads" tracking, bypassing the
# browser-vs-Nest disambiguation).
_RESOLVER_OWNED_DOMAINS: set[str] = {
    "storage.googleapis.com",
    # Future additions: *.amazonaws.com domains used by Alexa, etc.
}

# Accepts entries like "||example.com^" or "||sub.example.com^|$third-party".
# We strip the leading "||", the trailing anchors, and any options.
_ADBLOCK_RULE = re.compile(r"^\|\|([a-z0-9.\-_]+)\^?(?:\$.*)?$", re.IGNORECASE)


def _parse_adblock_rule(rule: str) -> Optional[str]:
    """Extract a plain domain from an AdGuard/adblock filter rule."""
    if not rule or not isinstance(rule, str):
        return None
    rule = rule.strip().lower()
    m = _ADBLOCK_RULE.match(rule)
    if not m:
        return None
    domain = m.group(1).strip(".")
    if not domain or "." not in domain:
        return None
    return domain


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

async def fetch_adguard_services(client) -> dict[str, tuple[str, str]]:
    """Download AdGuard HostlistsRegistry services.json and flatten to
    a {domain: (service_id, category)} dict."""
    result: dict[str, tuple[str, str]] = {}
    try:
        resp = await client.get(ADGUARD_SERVICES_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[third-party] AdGuard services fetch failed: {exc}")
        return result

    for svc in data.get("blocked_services", []):
        svc_id = svc.get("id")
        group = svc.get("group") or "unknown"
        if not svc_id:
            continue
        category = _ADGUARD_GROUP_MAP.get(group, "other")
        for rule in svc.get("rules", []):
            domain = _parse_adblock_rule(rule)
            if not domain or domain in _RESOLVER_OWNED_DOMAINS:
                continue
            # First rule wins (avoid overwriting a service's own
            # primary domain with a secondary one).
            result.setdefault(domain, (svc_id, category))
    return result


def _slugify_owner(name: str) -> str:
    """Turn a DDG owner displayName into a clean service_id slug.

    "Google Ads (Google)"  → "google_ads"
    "Google LLC"           → "google"
    "Meta Platforms, Inc." → "meta_platforms"
    "Microsoft Corporation"→ "microsoft"
    """
    if not name:
        return "unknown"
    s = name.strip()
    # Strip trailing parenthetical (often a parent-company tag that
    # just duplicates information, e.g. "Google Ads (Google)")
    s = re.sub(r"\s*\([^)]*\)\s*$", "", s)
    # Strip common corporate suffixes
    s = re.sub(
        r",?\s+(llc|inc|inc\.|corporation|corp|corp\.|ltd|limited|co|co\.|llp|gmbh|ag|bv|b\.v\.?|plc|sa|s\.a\.?|oy|ab)\s*$",
        "",
        s,
        flags=re.IGNORECASE,
    )
    # Slugify remaining: lowercase, non-alphanumerics → _
    slug = re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
    return slug or "unknown"


async def fetch_tracker_radar(client) -> dict[str, tuple[str, str]]:
    """Download DuckDuckGo TDS and flatten to {domain: (service_id, category)}.

    The service_id is the owner's displayName slugified (e.g. "Google LLC"
    → "google"), so multiple tracker domains from the same company
    aggregate under one name (doubleclick.net + google-analytics.com +
    googletagmanager.com all become "google").
    """
    result: dict[str, tuple[str, str]] = {}
    try:
        resp = await client.get(DDG_TDS_URL, timeout=45)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[third-party] DuckDuckGo TDS fetch failed: {exc}")
        return result

    trackers = data.get("trackers") or {}
    for domain, info in trackers.items():
        if not domain:
            continue
        dom = domain.lower()
        if dom in _RESOLVER_OWNED_DOMAINS:
            continue
        owner = (info or {}).get("owner") or {}
        display = owner.get("displayName") or owner.get("name") or ""
        svc_id = _slugify_owner(display) or "unknown_tracker"
        result[dom] = (svc_id, "tracking")
    return result


# ---------------------------------------------------------------------------
# Caching + merging
# ---------------------------------------------------------------------------

CACHE_TTL_SECONDS = 7 * 24 * 3600  # weekly refresh


def _cache_path() -> Path:
    base = Path(os.environ.get("AIRADAR_DATA_DIR", "/app/data"))
    return base / "third_party_services.json"


def _load_cache() -> Optional[dict]:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        age = time.time() - float(data.get("fetched_at", 0))
        if age > CACHE_TTL_SECONDS:
            return None
        return data
    except Exception as exc:
        print(f"[third-party] Cache read failed: {exc}")
        return None


def _save_cache(adguard: dict, ddg: dict) -> None:
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": time.time(),
        "adguard_services": {d: list(v) for d, v in adguard.items()},
        "ddg_trackers":     {d: list(v) for d, v in ddg.items()},
    }
    try:
        with open(path, "w") as f:
            json.dump(payload, f)
    except Exception as exc:
        print(f"[third-party] Cache write failed: {exc}")


def _cache_to_maps(cache: dict) -> tuple[dict, dict]:
    adguard = {d: tuple(v) for d, v in cache.get("adguard_services", {}).items()}
    ddg = {d: tuple(v) for d, v in cache.get("ddg_trackers", {}).items()}
    return adguard, ddg


async def load_third_party_map(force_refresh: bool = False) -> dict[str, tuple[str, str]]:
    """Return a combined {domain: (service_id, category)} map from all
    third-party sources. Uses on-disk cache if fresh.

    On first boot (or after the 7-day TTL expires) both sources are
    fetched in parallel. If a fetch fails the function falls back to
    any stale cache that's still on disk so the tailer never crashes
    on transient network errors.
    """
    if not force_refresh:
        cache = _load_cache()
        if cache:
            adguard, ddg = _cache_to_maps(cache)
            return {**ddg, **adguard}  # AdGuard wins over DDG for overlaps

    import httpx  # lazy import — only needed when fetching live
    async with httpx.AsyncClient() as client:
        adguard = await fetch_adguard_services(client)
        ddg = await fetch_tracker_radar(client)

    if adguard or ddg:
        _save_cache(adguard, ddg)
        print(
            f"[third-party] Loaded {len(adguard)} AdGuard service domains + "
            f"{len(ddg)} DuckDuckGo tracker domains"
        )
    else:
        # Both failed — try the stale cache as a last resort
        stale_path = _cache_path()
        if stale_path.exists():
            try:
                with open(stale_path) as f:
                    stale = json.load(f)
                adguard, ddg = _cache_to_maps(stale)
                print("[third-party] Using stale cache (both fetches failed)")
            except Exception:
                pass

    return {**ddg, **adguard}


def merge_with_curated(
    curated: dict[str, tuple[str, str]],
    third_party: dict[str, tuple[str, str]],
) -> dict[str, tuple[str, str]]:
    """Merge third-party entries into the curated map.

    Curated entries always win on conflict — the third-party data only
    fills in gaps. Returns a new dict; the inputs are not mutated.
    """
    merged = dict(third_party)
    merged.update(curated)  # curated values overwrite
    return merged
