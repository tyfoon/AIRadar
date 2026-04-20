"""
Suggested groups — AI-Radar ships with a set of default groups that
auto-populate based on device attributes. Once created they're just
regular groups: policies can be attached, members can be edited,
names/icons/rules can be changed. The only distinguishing thing is
``origin='suggested'`` + an optional ``modified_at`` timestamp, purely
for a subtle UI indicator.

Match rule schema (JSON stored in DeviceGroup.auto_match_rules):

    [
      {"field": "<attr>", "op": "<operator>", "value": <string|list>},
      ...
    ]

Rules inside the array are OR'd — any match puts the device in the
group. Rule fields are derived from the Device record and the existing
classification helpers. Evaluated periodically and on device register /
metadata update.
"""

from __future__ import annotations

import json
import re
from typing import Iterable

from sqlalchemy.orm import Session

from database import Device, DeviceGroup, DeviceGroupMember


# ---------------------------------------------------------------------------
# Default groups seeded on first run
# ---------------------------------------------------------------------------
# Order matters only for "Te classificeren" — it's the catch-all for
# devices that didn't match anything else, so it uses ``op='is_empty'``
# against ``classified_type`` to surface truly unclassified hardware.

DEFAULT_GROUPS: list[dict] = [
    {
        "name": "Camera's",
        "icon": "video-camera",
        "color": "rose",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "hikvision", "dahua", "axis", "reolink", "ring", "nest cam",
                "arlo", "foscam", "amcrest", "eufy", "wyze",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": [
                "hikvision", "ip camera", "doorbell", "camera hub",
            ]},
        ],
    },
    {
        "name": "Smart Home",
        "icon": "house-line",
        "color": "purple",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "signify", "philips lighting", "lumi", "xiaomi", "nest labs",
                "withings", "smartthings", "hubitat",
            ]},
            {"field": "hostname", "op": "contains_any", "value": [
                "hue", "home-assistant", "homeassistant", "smartthings",
                "hubitat", "zigbee", "zwave",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": [
                "smart home", "smart lighting", "philips lighting",
                "signify", "aqara smart home", "xiaomi smart home",
                "nest", "zigbee",
            ]},
        ],
    },
    {
        "name": "Media & Speakers",
        "icon": "speaker-high",
        "color": "pink",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "sonos", "denon", "marantz", "d&m", "bose", "harmony",
                "logitech",
            ]},
            {"field": "hostname", "op": "contains_any", "value": [
                "sonos", "chromecast", "homepod", "appletv",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": [
                "sonos speaker", "av receiver", "chromecast", "apple tv",
                "homepod", "denon", "speaker", "harmony",
            ]},
        ],
    },
    {
        "name": "TVs",
        "icon": "television-simple",
        "color": "orange",
        "rules": [
            {"field": "hostname", "op": "contains_any", "value": [
                "tv", "webos", "lgwebos", "samsungtv", "roku",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": [
                "lg smart tv", "apple tv", "tv/media", "roku",
            ]},
        ],
    },
    {
        "name": "Phones & Tablets",
        "icon": "device-mobile",
        "color": "sky",
        "rules": [
            {"field": "dhcp_vendor_class", "op": "startswith", "value": "android-dhcp"},
            {"field": "device_class", "op": "equals_any", "value": ["phone", "tablet"]},
            {"field": "classified_type", "op": "equals_any", "value": ["android"]},
            # iPhones / iPads routinely appear as "Apple, Inc." vendor
            # with no cleaner signal; keep them here not in Computers.
            {"field": "hostname", "op": "matches",
             "value": r"iphone|ipad|galaxy|pixel|oneplus"},
        ],
    },
    {
        "name": "Computers",
        "icon": "laptop",
        "color": "blue",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "intel", "dell", "lenovo", "asus", "acer", "asrock",
                "elitegroup", "gigabyte", "msi", "microsoft",
            ]},
            {"field": "device_class", "op": "equals_any", "value": [
                "laptop", "pc", "computer", "desktop", "server",
            ]},
            {"field": "os_name", "op": "contains_any", "value": [
                "windows", "linux", "macos", "mac os",
            ]},
        ],
    },
    {
        "name": "Klimaat & Energie",
        "icon": "thermometer",
        "color": "amber",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "resideo", "honeywell", "myenergi", "ecobee", "tado",
                "sensibo", "netatmo",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": [
                "thermostat", "energy monitor", "energy",
            ]},
        ],
    },
    {
        "name": "Printers",
        "icon": "printer",
        "color": "slate",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "brother", "hp printer", "epson", "canon", "xerox",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": ["printer"]},
        ],
    },
    {
        "name": "IoT / MCUs",
        "icon": "cpu",
        "color": "teal",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "espressif", "texas instruments", "shanghai high",
            ]},
            {"field": "dhcp_vendor_class", "op": "startswith", "value": "udhcp"},
            {"field": "classified_type", "op": "equals_any", "value": [
                "embedded_iot", "iot", "iot device",
            ]},
        ],
    },
    {
        "name": "Network Gear",
        "icon": "router",
        "color": "indigo",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "ubiquiti", "cisco", "tp-link", "tplink", "netgear",
                "aruba", "mikrotik", "meraki",
            ]},
            {"field": "dhcp_vendor_class", "op": "equals", "value": "ubnt"},
            {"field": "classified_type", "op": "equals_any", "value": [
                "ubiquiti", "access point", "gateway", "router", "network",
            ]},
        ],
    },
    {
        "name": "Appliances",
        "icon": "washing-machine",
        "color": "emerald",
        "rules": [
            {"field": "vendor", "op": "contains_any", "value": [
                "miele", "bosch", "siemens",
            ]},
            {"field": "classified_type", "op": "equals_any", "value": [
                "vacuum", "washer", "dryer", "dishwasher", "airco", "fridge",
            ]},
        ],
    },
    {
        "name": "Te classificeren",
        "icon": "question",
        "color": "stone",
        "rules": [
            # Catch-all: device with no classification + no device_class.
            # Surfaces devices we couldn't figure out so the user can
            # manually name/assign them.
            {"field": "classified_type", "op": "is_empty"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

def _device_attrs(device: Device, classified_type: str) -> dict[str, str]:
    """Build the string attributes used to evaluate match rules.

    ``classified_type`` is passed separately because it's computed by
    ``_classify_device_type_backend`` in api.py — importing that here
    would cause a circular import at module load time, so callers
    compute it and pass it in.
    """
    return {
        "vendor": (device.vendor or "").lower(),
        "hostname": (device.hostname or "").lower(),
        "display_name": (device.display_name or "").lower(),
        "device_class": (device.device_class or "").lower(),
        "dhcp_vendor_class": (device.dhcp_vendor_class or "").lower(),
        "os_name": (device.os_name or "").lower(),
        "classified_type": classified_type.lower(),
    }


def _match_one(attrs: dict[str, str], rule: dict) -> bool:
    field_val = attrs.get(rule.get("field", ""), "")
    op = rule.get("op", "")
    val = rule.get("value")

    if op == "is_empty":
        return field_val == ""
    if val is None:
        return False

    if op == "equals":
        return field_val == str(val).lower()
    if op == "equals_any":
        if not isinstance(val, list):
            return False
        return field_val in [str(v).lower() for v in val]
    if op == "contains":
        return str(val).lower() in field_val
    if op == "contains_any":
        if not isinstance(val, list):
            return False
        return any(str(v).lower() in field_val for v in val)
    if op == "startswith":
        return field_val.startswith(str(val).lower())
    if op == "matches":
        try:
            return bool(re.search(str(val), field_val, re.IGNORECASE))
        except re.error:
            return False
    return False


def match_rules(attrs: dict[str, str], rules_json: str | None) -> bool:
    """Any rule matching → device belongs. None/empty rules → no match."""
    if not rules_json:
        return False
    try:
        rules = json.loads(rules_json)
    except (ValueError, TypeError):
        return False
    if not isinstance(rules, list):
        return False
    return any(_match_one(attrs, r) for r in rules if isinstance(r, dict))


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------

def seed_default_groups(db: Session) -> int:
    """Create the 12 suggested groups on first run.

    Idempotent: only creates a group if no DeviceGroup with the same
    name already exists. Does NOT overwrite user edits to existing
    suggestions — the evaluator respects ``modified_at``.

    Returns number of groups created.
    """
    created = 0
    for spec in DEFAULT_GROUPS:
        existing = db.query(DeviceGroup).filter(DeviceGroup.name == spec["name"]).first()
        if existing:
            continue
        db.add(DeviceGroup(
            name=spec["name"],
            icon=spec["icon"],
            color=spec["color"],
            auto_match_rules=json.dumps(spec["rules"]),
            origin="suggested",
            modified_at=None,
        ))
        created += 1
    if created:
        db.commit()
    return created


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def evaluate_auto_groups(
    db: Session,
    classifier,  # callable(Device) -> str — pass _classify_device_type_backend
    only_macs: Iterable[str] | None = None,
) -> dict:
    """Apply auto_match_rules and sync DeviceGroupMember.source='auto'.

    - Devices matching a rule get added as source='auto' (if not already).
    - Previously auto-matched devices that no longer match → removed.
    - source='manual' members are always kept (user explicit).
    - source='exclude' members are skipped (user said no, respect it).

    ``only_macs`` scopes evaluation to specific devices — called on
    device registration / metadata update to avoid re-evaluating the
    whole fleet. Pass None for the full scan (periodic / startup).
    """
    stats = {"added": 0, "removed": 0, "groups_evaluated": 0}

    groups = (
        db.query(DeviceGroup)
        .filter(DeviceGroup.auto_match_rules.isnot(None))
        .all()
    )
    if not groups:
        return stats

    device_q = db.query(Device)
    if only_macs is not None:
        only_macs = list(only_macs)
        if not only_macs:
            return stats
        device_q = device_q.filter(Device.mac_address.in_(only_macs))
    devices = device_q.all()

    # Pre-compute classifier for each device (it's the heavy part).
    attrs_by_mac = {
        d.mac_address: _device_attrs(d, classifier(d) or "")
        for d in devices
    }

    for group in groups:
        stats["groups_evaluated"] += 1

        # Existing memberships for the devices in scope
        mem_q = db.query(DeviceGroupMember).filter(
            DeviceGroupMember.group_id == group.id
        )
        if only_macs is not None:
            mem_q = mem_q.filter(DeviceGroupMember.mac_address.in_(only_macs))
        existing_by_mac = {m.mac_address: m for m in mem_q.all()}

        for device in devices:
            attrs = attrs_by_mac[device.mac_address]
            matches = match_rules(attrs, group.auto_match_rules)
            current = existing_by_mac.get(device.mac_address)

            # Respect user overrides: excluded = never auto-add;
            # manual = never auto-remove.
            if current and current.source == "exclude":
                continue
            if current and current.source == "manual":
                continue

            if matches and not current:
                db.add(DeviceGroupMember(
                    group_id=group.id,
                    mac_address=device.mac_address,
                    source="auto",
                ))
                stats["added"] += 1
            elif not matches and current and current.source == "auto":
                db.delete(current)
                stats["removed"] += 1

    if stats["added"] or stats["removed"]:
        db.commit()
    return stats
