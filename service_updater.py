"""
AI-Radar — Dynamic domain list updater.

Replaces the old hardcoded DOMAIN_MAP with a database-backed system.
On first boot, seeds KnownDomain from the former curated list. Then
enriches it nightly from community sources (v2fly domain-list-community).

The zeek_tailer reads KnownDomain every 5 minutes via sync_domain_cache()
so new domains are picked up without a restart.

Architecture:
  Layer 1: KnownDomain table (this file) — "curated" layer, wins over
           third-party data on conflict.
  Layer 2: AdGuard + DuckDuckGo (third_party_sources.py) — fills gaps,
           never overwrites Layer 1.
  Merge:   _effective_domain_map in zeek_tailer.py = Layer 2 + Layer 1.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional

from database import KnownDomain, SessionLocal

# ---------------------------------------------------------------------------
# Seed data — the former hardcoded DOMAIN_MAP from zeek_tailer.py.
# Written into KnownDomain on first boot (source="seed") so the system
# works immediately before any community fetch completes.
# ---------------------------------------------------------------------------
_SEED_DOMAINS: dict[str, tuple[str, str]] = {
    # --- AI services ---
    "gemini.google.com":                 ("google_gemini", "ai"),
    "generativelanguage.googleapis.com": ("google_gemini", "ai"),
    "aistudio.google.com":               ("google_gemini", "ai"),
    "openai.com":                        ("openai", "ai"),
    "chatgpt.com":                       ("openai", "ai"),
    "oaiusercontent.com":                ("openai", "ai"),
    "claude.ai":                         ("anthropic_claude", "ai"),
    "anthropic.com":                     ("anthropic_claude", "ai"),
    "copilot.microsoft.com":             ("microsoft_copilot", "ai"),
    "sydney.bing.com":                   ("microsoft_copilot", "ai"),
    "perplexity.ai":                     ("perplexity", "ai"),
    "huggingface.co":                    ("huggingface", "ai"),
    "mistral.ai":                        ("mistral", "ai"),
    # --- Cloud storage ---
    "dropbox.com":                       ("dropbox", "cloud"),
    "wetransfer.com":                    ("wetransfer", "cloud"),
    "drive.google.com":                  ("google_drive", "cloud"),
    "docs.google.com":                   ("google_drive", "cloud"),
    "drive.usercontent.google.com":      ("google_drive", "cloud"),
    "onedrive.live.com":                 ("onedrive", "cloud"),
    "storage.live.com":                  ("onedrive", "cloud"),
    "1drv.ms":                           ("onedrive", "cloud"),
    "icloud.com":                        ("icloud", "cloud"),
    "box.com":                           ("box", "cloud"),
    "mega.nz":                           ("mega", "cloud"),
    "sendgb.com":                        ("sendgb", "cloud"),
    "smash.gg":                          ("smash", "cloud"),
    # --- VPN services ---
    "nordvpn.com":                       ("vpn_nordvpn", "tracking"),
    "nordvpn.net":                       ("vpn_nordvpn", "tracking"),
    "nord-apps.com":                     ("vpn_nordvpn", "tracking"),
    "nordcdn.com":                       ("vpn_nordvpn", "tracking"),
    "expressvpn.com":                    ("vpn_expressvpn", "tracking"),
    "expressapisv2.net":                 ("vpn_expressvpn", "tracking"),
    "surfshark.com":                     ("vpn_surfshark", "tracking"),
    "protonvpn.com":                     ("vpn_protonvpn", "tracking"),
    "protonvpn.ch":                      ("vpn_protonvpn", "tracking"),
    "proton.me":                         ("vpn_protonvpn", "tracking"),
    "privateinternetaccess.com":         ("vpn_pia", "tracking"),
    "cyberghostvpn.com":                 ("vpn_cyberghost", "tracking"),
    "mullvad.net":                       ("vpn_mullvad", "tracking"),
    "ipvanish.com":                      ("vpn_ipvanish", "tracking"),
    "tunnelbear.com":                    ("vpn_tunnelbear", "tracking"),
    "windscribe.com":                    ("vpn_windscribe", "tracking"),
    "warp.cloudflareaccess.org":         ("vpn_cloudflare_warp", "tracking"),
    # --- Tracking / Ads ---
    "doubleclick.net":                   ("google_ads", "tracking"),
    "googlesyndication.com":             ("google_ads", "tracking"),
    "googleadservices.com":              ("google_ads", "tracking"),
    "adservice.google.com":              ("google_ads", "tracking"),
    "google-analytics.com":              ("google_analytics", "tracking"),
    "googletagmanager.com":              ("google_analytics", "tracking"),
    "connect.facebook.net":              ("meta_tracking", "tracking"),
    "pixel.facebook.com":                ("meta_tracking", "tracking"),
    "iadsdk.apple.com":                  ("apple_ads", "tracking"),
    "adsdk.microsoft.com":               ("microsoft_ads", "tracking"),
    "hotjar.com":                        ("hotjar", "tracking"),
    "datadoghq.com":                     ("datadog", "tracking"),
    "sentry.io":                         ("sentry", "tracking"),
    "newrelic.com":                      ("newrelic", "tracking"),
    "mixpanel.com":                      ("mixpanel", "tracking"),
    "segment.io":                        ("segment", "tracking"),
    "segment.com":                       ("segment", "tracking"),
    "amplitude.com":                     ("amplitude", "tracking"),
    "fullstory.com":                     ("fullstory", "tracking"),
    "adnexus.net":                       ("adnexus", "tracking"),
    "criteo.com":                        ("criteo", "tracking"),
    "scorecardresearch.com":             ("scorecardresearch", "tracking"),
    "antigravity-unleash.goog":          ("google_telemetry", "tracking"),
    # --- Social media ---
    "facebook.com":                      ("facebook", "social"),
    "fbcdn.net":                         ("facebook", "social"),
    "instagram.com":                     ("instagram", "social"),
    "cdninstagram.com":                  ("instagram", "social"),
    "tiktok.com":                        ("tiktok", "social"),
    "tiktokcdn.com":                     ("tiktok", "social"),
    "musical.ly":                        ("tiktok", "social"),
    "snapchat.com":                      ("snapchat", "social"),
    "sc-cdn.net":                        ("snapchat", "social"),
    "twitter.com":                       ("twitter", "social"),
    "x.com":                             ("twitter", "social"),
    "twimg.com":                         ("twitter", "social"),
    "pinterest.com":                     ("pinterest", "social"),
    "pinimg.com":                        ("pinterest", "social"),
    "linkedin.com":                      ("linkedin", "social"),
    "reddit.com":                        ("reddit", "social"),
    "redditmedia.com":                   ("reddit", "social"),
    "redditstatic.com":                  ("reddit", "social"),
    "tumblr.com":                        ("tumblr", "social"),
    "whatsapp.com":                      ("whatsapp", "social"),
    "whatsapp.net":                      ("whatsapp", "social"),
    "signal.org":                        ("signal", "social"),
    # --- Gaming ---
    "steampowered.com":                  ("steam", "gaming"),
    "steamcommunity.com":                ("steam", "gaming"),
    "steamstatic.com":                   ("steam", "gaming"),
    "valvesoftware.com":                 ("steam", "gaming"),
    "epicgames.com":                     ("epic_games", "gaming"),
    "unrealengine.com":                  ("epic_games", "gaming"),
    "fortnite.com":                      ("epic_games", "gaming"),
    "roblox.com":                        ("roblox", "gaming"),
    "rbxcdn.com":                        ("roblox", "gaming"),
    "ea.com":                            ("ea_games", "gaming"),
    "origin.com":                        ("ea_games", "gaming"),
    "xboxlive.com":                      ("xbox_live", "gaming"),
    "xbox.com":                          ("xbox_live", "gaming"),
    "playstation.com":                   ("playstation", "gaming"),
    "playstation.net":                   ("playstation", "gaming"),
    "nintendo.com":                      ("nintendo", "gaming"),
    "nintendo.net":                      ("nintendo", "gaming"),
    "twitch.tv":                         ("twitch", "gaming"),
    "twitchcdn.net":                     ("twitch", "gaming"),
    "discord.com":                       ("discord", "gaming"),
    "discordapp.com":                    ("discord", "gaming"),
    "discord.gg":                        ("discord", "gaming"),
    "supercell.com":                     ("supercell", "gaming"),
    "supercell.net":                     ("supercell", "gaming"),
    "hayday.com":                        ("supercell", "gaming"),
    "haydaygame.com":                    ("supercell", "gaming"),
    "clashofclans.com":                  ("supercell", "gaming"),
    "clashroyale.com":                   ("supercell", "gaming"),
    "brawlstars.com":                    ("supercell", "gaming"),
    "boombeach.com":                     ("supercell", "gaming"),
    # --- Streaming ---
    "netflix.com":                       ("netflix", "streaming"),
    "nflxvideo.net":                     ("netflix", "streaming"),
    "nflximg.net":                       ("netflix", "streaming"),
    "nflxso.net":                        ("netflix", "streaming"),
    "youtube.com":                       ("youtube", "streaming"),
    "googlevideo.com":                   ("youtube", "streaming"),
    "ytimg.com":                         ("youtube", "streaming"),
    "youtu.be":                          ("youtube", "streaming"),
    "spotify.com":                       ("spotify", "streaming"),
    "spotifycdn.com":                    ("spotify", "streaming"),
    "scdn.co":                           ("spotify", "streaming"),
    "disneyplus.com":                    ("disney_plus", "streaming"),
    "disney-plus.net":                   ("disney_plus", "streaming"),
    "dssott.com":                        ("disney_plus", "streaming"),
    "hbomax.com":                        ("hbo_max", "streaming"),
    "max.com":                           ("hbo_max", "streaming"),
    "primevideo.com":                    ("prime_video", "streaming"),
    "aiv-cdn.net":                       ("prime_video", "streaming"),
    "amazonvideo.com":                   ("prime_video", "streaming"),
    "tv.apple.com":                      ("apple_tv", "streaming"),
}


# ---------------------------------------------------------------------------
# v2fly domain-list-community sources
# ---------------------------------------------------------------------------
# Each entry: (category, service_name) → raw GitHub URL.
# v2fly files contain one domain per line with optional prefixes
# (full:, domain:, regexp:, include:) and attributes (@cn, @ads).
# We extract plain domains and full: domains, skip regexp/include.
#
# Only services that ARE in the v2fly repo are listed here. Services
# NOT covered by v2fly (Steam, Roblox, EA, Netflix, etc.) are already
# seeded from _SEED_DOMAINS and supplemented by AdGuard HostlistsRegistry.

V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

V2FLY_SOURCES: dict[tuple[str, str], str] = {
    ("ai", "anthropic_claude"):   V2FLY_BASE + "anthropic",
    ("ai", "openai"):             V2FLY_BASE + "openai",
    ("social", "tiktok"):         V2FLY_BASE + "tiktok",
    ("social", "facebook"):       V2FLY_BASE + "facebook",
    ("social", "instagram"):      V2FLY_BASE + "instagram",
    ("social", "twitter"):        V2FLY_BASE + "twitter",
    ("social", "linkedin"):       V2FLY_BASE + "linkedin",
    ("social", "pinterest"):      V2FLY_BASE + "pinterest",
    ("social", "reddit"):         V2FLY_BASE + "reddit",
    ("social", "snapchat"):       V2FLY_BASE + "snapchat",
    ("social", "whatsapp"):       V2FLY_BASE + "whatsapp",
    ("social", "signal"):         V2FLY_BASE + "signal",
    ("social", "telegram"):       V2FLY_BASE + "telegram",
    ("gaming", "discord"):        V2FLY_BASE + "discord",
    ("gaming", "epicgames"):      V2FLY_BASE + "epicgames",
    ("gaming", "steam"):          V2FLY_BASE + "steampowered",
    ("streaming", "netflix"):     V2FLY_BASE + "netflix",
    ("streaming", "spotify"):     V2FLY_BASE + "spotify",
    ("streaming", "youtube"):     V2FLY_BASE + "youtube",
    ("streaming", "disney_plus"): V2FLY_BASE + "disney",
    ("streaming", "prime_video"): V2FLY_BASE + "amazonvideo",
    # NOTE: v2fly "apple" list deliberately NOT mapped here — it contains
    # 900+ brand-protection domains (NTP, MDM, CDN, typosquats, country
    # sites …) that are NOT Apple TV content.  Mapping them all to
    # apple_tv caused massive mislabeling.  Apple TV is covered by the
    # static DOMAIN_MAP entry for tv.apple.com; iCloud has its own v2fly
    # list below.  See Day 2.5 commit for details.
    ("cloud", "dropbox"):         V2FLY_BASE + "dropbox",
    ("cloud", "onedrive"):        V2FLY_BASE + "onedrive",
    ("cloud", "icloud"):          V2FLY_BASE + "icloud",
    ("tracking", "google_ads"):   V2FLY_BASE + "googleads",
}

# Domains that Phase 2 context-aware resolvers own. Never import
# these from v2fly — they'd bypass the device-kind disambiguation.
_RESOLVER_OWNED_DOMAINS: set[str] = {
    "storage.googleapis.com",
}

# ---------------------------------------------------------------------------
# v2fly parser
# ---------------------------------------------------------------------------

_V2FLY_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


def parse_v2fly_file(text: str) -> list[str]:
    """Extract plain domains from a v2fly-format file.

    Handles:
      example.com          → included
      full:exact.domain    → included (strip prefix)
      domain:example.com   → included (strip prefix)
      regexp:...           → skipped (we can't use regex in our O(1) map)
      include:other        → skipped (we don't resolve cross-references)
      # comment            → skipped
      @attr suffix         → stripped

    Returns a deduplicated list of lowercase domain strings.
    """
    domains: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline attributes: "example.com @cn @ads" → "example.com"
        parts = line.split()
        token = parts[0].lower()
        # Handle prefixes
        if token.startswith("regexp:"):
            continue
        if token.startswith("include:"):
            continue
        for prefix in ("full:", "domain:"):
            if token.startswith(prefix):
                token = token[len(prefix):]
                break
        token = token.strip(".")
        if not token or "." not in token:
            continue
        if not _V2FLY_DOMAIN_RE.match(token):
            continue
        if token in _RESOLVER_OWNED_DOMAINS:
            continue
        domains.append(token)
    return list(dict.fromkeys(domains))  # deduplicate preserving order


# ---------------------------------------------------------------------------
# Main updater
# ---------------------------------------------------------------------------

def _seed_domains() -> None:
    """Write _SEED_DOMAINS into KnownDomain if the table is empty.

    Runs once on first boot. After that, v2fly enrichment and manual
    edits keep the table alive; the seed is not re-applied so user
    deletions are respected.
    """
    db = SessionLocal()
    try:
        if db.query(KnownDomain).first() is not None:
            return  # already seeded
        now = datetime.now(timezone.utc)
        for domain, (svc, cat) in _SEED_DOMAINS.items():
            db.add(KnownDomain(
                domain=domain,
                service_name=svc,
                category=cat,
                source="seed",
                updated_at=now,
            ))
        db.commit()
        print(f"[service-updater] Seeded {len(_SEED_DOMAINS)} domains from former DOMAIN_MAP")
    except Exception as exc:
        db.rollback()
        print(f"[service-updater] Seed failed: {exc}")
    finally:
        db.close()


async def update_domains() -> None:
    """Fetch v2fly domain lists and upsert into KnownDomain.

    - Seed data is written once on first boot (source="seed").
    - v2fly data is upserted with source="v2fly"; existing seed rows
      for the same domain are NOT overwritten so curated entries win.
    - New domains from v2fly that don't exist yet are inserted.
    """
    _seed_domains()

    import httpx  # lazy — only needed for the actual fetch

    total_new = 0
    total_updated = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for (category, service_name), url in V2FLY_SOURCES.items():
            try:
                resp = await client.get(url)
                if resp.status_code == 404:
                    # v2fly doesn't have this service — fine, seed covers it
                    continue
                resp.raise_for_status()
                domains = parse_v2fly_file(resp.text)
            except Exception as exc:
                print(f"[service-updater] {service_name}: fetch failed ({exc})")
                continue

            if not domains:
                continue

            db = SessionLocal()
            try:
                for domain in domains:
                    existing = db.query(KnownDomain).filter(
                        KnownDomain.domain == domain
                    ).first()
                    if existing:
                        # Only update if we (v2fly) originally wrote this row.
                        # Seed and manual rows are left alone so curated data wins.
                        if existing.source == "v2fly":
                            existing.service_name = service_name
                            existing.category = category
                            existing.updated_at = datetime.now(timezone.utc)
                            total_updated += 1
                    else:
                        db.add(KnownDomain(
                            domain=domain,
                            service_name=service_name,
                            category=category,
                            source="v2fly",
                            updated_at=datetime.now(timezone.utc),
                        ))
                        total_new += 1
                db.commit()
            except Exception as exc:
                db.rollback()
                print(f"[service-updater] {service_name}: DB error ({exc})")
            finally:
                db.close()

    print(
        f"[service-updater] v2fly sync complete: "
        f"{total_new} new + {total_updated} updated domains "
        f"from {len(V2FLY_SOURCES)} sources"
    )


async def periodic_update_domains() -> None:
    """Background task: run update_domains() immediately then every 24h."""
    while True:
        try:
            await update_domains()
        except Exception as exc:
            print(f"[service-updater] Error: {exc}")
        await asyncio.sleep(86400)


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from database import init_db
    init_db()
    asyncio.run(update_domains())
