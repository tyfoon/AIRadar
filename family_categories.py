"""
AI-Radar — Family categories helper.

Single source of truth for which DOMAIN_MAP / SERVICE_DOMAINS categories
belong to the Family page. AI + cloud + tracking each have their own
dedicated page and are excluded here.

This module intentionally holds no data of its own — it only wraps the
categories already declared in api.SERVICE_DOMAINS / zeek_tailer.DOMAIN_MAP
so backend and frontend agree on what "family" means.
"""

from __future__ import annotations

# Ordered list — this is also the display order on the Family page
# (Overview cards + Categories sidebar). Putting adult last is deliberate:
# it keeps the family-friendly picture at the top and the "sensitive"
# bucket at the bottom where it draws less eye weight by default.
FAMILY_CATEGORIES: list[str] = [
    "social",
    "gaming",
    "streaming",
    "shopping",
    "news",
    "dating",
    "adult",
]

# Metadata used by both the API (for fallback labels/colours) and the UI.
# Icons are Phosphor duotone names so the frontend can swap them into
# <i class="ph-duotone ph-{icon}"> without any extra mapping.
FAMILY_CATEGORY_META: dict[str, dict[str, str]] = {
    "social":    {"icon": "chat-circle-text", "color": "pink",    "label_en": "Social",    "label_nl": "Sociaal"},
    "gaming":    {"icon": "game-controller",  "color": "indigo",  "label_en": "Games",     "label_nl": "Games"},
    "streaming": {"icon": "play-circle",      "color": "purple",  "label_en": "Streaming", "label_nl": "Streaming"},
    "shopping":  {"icon": "shopping-bag",     "color": "amber",   "label_en": "Shopping",  "label_nl": "Winkelen"},
    "news":      {"icon": "newspaper",        "color": "sky",     "label_en": "News",      "label_nl": "Nieuws"},
    "dating":    {"icon": "heart",            "color": "rose",    "label_en": "Dating",    "label_nl": "Dating"},
    "adult":     {"icon": "warning-circle",   "color": "red",     "label_en": "Adult",     "label_nl": "Volwassen"},
}


def is_family_category(cat: str | None) -> bool:
    """True iff the given category belongs on the Family page."""
    return cat in FAMILY_CATEGORIES


def family_categories_for_display() -> list[dict]:
    """Return the category list in display order, with metadata folded in.

    Shape (one entry per category):
        {"key": "social", "icon": "chat-circle-text", "color": "pink",
         "label_en": "Social", "label_nl": "Sociaal"}
    """
    out: list[dict] = []
    for key in FAMILY_CATEGORIES:
        meta = FAMILY_CATEGORY_META.get(key, {})
        out.append({"key": key, **meta})
    return out
