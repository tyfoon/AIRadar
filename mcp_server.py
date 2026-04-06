"""
AI-Radar — MCP Server
Exposes network alerts and policy management to local LLMs
(e.g. Claude Desktop) via the Model Context Protocol.

Run:  python mcp_server.py
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

from database import (
    SessionLocal,
    AlertException,
    DetectionEvent,
    DeviceGroupMember,
    DeviceGroup,
    DeviceIP,
    Device,
    ServicePolicy,
)

mcp = FastMCP("AI-Radar")

# Same set used by the main API
_ANOMALY_DETECTION_TYPES = {
    "vpn_tunnel",
    "stealth_vpn_tunnel",
    "beaconing_threat",
    "iot_lateral_movement",
    "iot_suspicious_port",
}


def _is_exception_active(
    exceptions: list,
    mac: Optional[str],
    alert_type: str,
    destination: Optional[str],
    now: datetime,
) -> bool:
    """True if a non-expired AlertException matches this alert."""
    for exc in exceptions:
        if exc.mac_address != mac:
            continue
        if exc.alert_type != alert_type:
            continue
        if exc.destination and exc.destination != destination:
            continue
        if exc.expires_at is not None and exc.expires_at <= now:
            continue
        return True
    return False


def _resolve_policy_action(
    policies: list,
    mac: Optional[str],
    service_name: Optional[str],
    category: Optional[str],
    device_group_ids: Optional[list] = None,
) -> Optional[str]:
    """Return the resolved action ("allow"/"alert"/"block") or None.

    Priority: device > child-group > parent-group > global.
    Within a level: service_name > category.
    Multiple groups at the same level: most restrictive wins.
    """
    now = datetime.utcnow()
    _action_rank = {"block": 3, "alert": 2, "allow": 1}

    def _first(pred):
        for p in policies:
            if p.expires_at and p.expires_at <= now:
                continue
            if pred(p):
                return p.action
        return None

    def _most_restrictive(pred):
        best = None
        for p in policies:
            if p.expires_at and p.expires_at <= now:
                continue
            if pred(p):
                if best is None or _action_rank.get(p.action, 0) > _action_rank.get(best, 0):
                    best = p.action
        return best

    # 1-2: device + service / category
    if mac:
        r = _first(lambda p: p.scope == "device" and p.mac_address == mac and p.service_name == service_name and service_name)
        if r:
            return r
        r = _first(lambda p: p.scope == "device" and p.mac_address == mac and p.category == category and category and not p.service_name)
        if r:
            return r

    # 3-6: group policies
    if device_group_ids:
        child_ids = [gid for gid, _ in device_group_ids]
        parent_ids = [pid for _, pid in device_group_ids if pid]

        for ids in (child_ids, parent_ids):
            if not ids:
                continue
            r = _most_restrictive(lambda p, _ids=ids: p.scope == "group" and p.group_id in _ids and p.service_name == service_name and service_name)
            if r:
                return r
            r = _most_restrictive(lambda p, _ids=ids: p.scope == "group" and p.group_id in _ids and p.category == category and category and not p.service_name)
            if r:
                return r

    # 7-8: global
    r = _first(lambda p: p.scope == "global" and p.service_name == service_name and service_name and not p.mac_address)
    if r:
        return r
    r = _first(lambda p: p.scope == "global" and p.category == category and category and not p.service_name and not p.mac_address)
    if r:
        return r

    return None


# ── Tool 1: get_network_status ──────────────────────────────────


@mcp.tool()
def get_network_status() -> str:
    """Haalt een samenvatting op van alle actieve, onbehandelde netwerkwaarschuwingen
    (alerts) van de afgelopen 24 uur. Gebruik dit om te zien welke apparaten
    verdacht verkeer genereren, geblokkeerde diensten gebruiken, of anomalieen
    vertonen (VPN tunnels, beaconing, port scans)."""
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=24)

        policies = db.query(ServicePolicy).all()
        all_memberships = db.query(DeviceGroupMember).all()
        group_parent_map = {g.id: g.parent_id for g in db.query(DeviceGroup).all()}
        exceptions = db.query(AlertException).filter(
            (AlertException.expires_at.is_(None)) | (AlertException.expires_at > now)
        ).all()

        dev_ip_rows = db.query(DeviceIP).all()
        ip_to_mac = {d.ip: d.mac_address for d in dev_ip_rows}
        device_by_mac = {d.mac_address: d for d in db.query(Device).all()}

        events = (
            db.query(DetectionEvent)
            .filter(DetectionEvent.timestamp >= cutoff)
            .order_by(DetectionEvent.timestamp.asc())
            .all()
        )

        # Aggregate alerts (same logic as /api/alerts/active)
        groups: dict[tuple, dict] = {}

        for e in events:
            mac = ip_to_mac.get(e.source_ip)

            if e.detection_type in _ANOMALY_DETECTION_TYPES:
                alert_type = e.detection_type
                destination = e.ai_service
                if _is_exception_active(exceptions, mac, alert_type, destination, now):
                    continue
                reason = "anomaly"
            else:
                _dev_groups = None
                if mac:
                    _memberships = [m for m in all_memberships if m.mac_address == mac]
                    if _memberships:
                        _dev_groups = [
                            (m.group_id, group_parent_map.get(m.group_id))
                            for m in _memberships
                        ]
                action = _resolve_policy_action(
                    policies, mac, e.ai_service, e.category, _dev_groups
                )
                if action is None or action == "allow":
                    continue
                reason = f"policy_{action}"

                alert_type = "upload" if e.possible_upload else "service_access"
                destination = e.ai_service

                if _is_exception_active(exceptions, mac, alert_type, destination, now):
                    continue

            key = (mac or e.source_ip, alert_type, destination)
            g = groups.get(key)
            if g is None:
                dev = device_by_mac.get(mac) if mac else None
                groups[key] = {
                    "device": dev.display_name or dev.hostname or mac if dev else (mac or e.source_ip),
                    "mac": mac or e.source_ip,
                    "alert_type": alert_type,
                    "service": destination,
                    "reason": reason,
                    "hits": 0,
                    "total_bytes": 0,
                    "latest": e.timestamp,
                }
                g = groups[key]
            g["hits"] += 1
            g["total_bytes"] += e.bytes_transferred or 0
            if e.timestamp > g["latest"]:
                g["latest"] = e.timestamp

        if not groups:
            return "Geen actieve waarschuwingen in de afgelopen 24 uur."

        lines = [f"Actieve waarschuwingen (afgelopen 24 uur): {len(groups)}\n"]
        for g in sorted(groups.values(), key=lambda x: x["latest"], reverse=True):
            bytes_kb = g["total_bytes"] / 1024
            lines.append(
                f"- [{g['alert_type']}] {g['device']} ({g['mac']}) → {g['service']} "
                f"| {g['hits']}x | {bytes_kb:.0f} KB | reden: {g['reason']} "
                f"| laatst: {g['latest'].strftime('%H:%M')}"
            )
        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 2: block_service ───────────────────────────────────────


@mcp.tool()
def block_service(mac_address: str, service_name: str, duration_hours: int = None) -> str:
    """Blokkeert een specifieke dienst (zoals 'roblox', 'openai', 'tiktok') voor
    een specifiek apparaat (MAC-adres). Optioneel tijdelijk voor een opgegeven
    aantal uren. Zonder duration_hours is de blokkade permanent."""
    db = SessionLocal()
    try:
        expires_at = None
        if duration_hours:
            expires_at = datetime.utcnow() + timedelta(hours=duration_hours)

        policy = (
            db.query(ServicePolicy)
            .filter_by(scope="device", mac_address=mac_address, service_name=service_name, category=None)
            .first()
        )
        if policy:
            policy.action = "block"
            policy.expires_at = expires_at
            policy.updated_at = datetime.utcnow()
        else:
            policy = ServicePolicy(
                scope="device",
                mac_address=mac_address,
                service_name=service_name,
                action="block",
                expires_at=expires_at,
            )
            db.add(policy)
        db.commit()

        duration_str = f" voor {duration_hours} uur" if duration_hours else " (permanent)"
        return f"Dienst '{service_name}' geblokkeerd voor apparaat {mac_address}{duration_str}."
    finally:
        db.close()


# ── Tool 3: allow_service ───────────────────────────────────────


@mcp.tool()
def allow_service(mac_address: str, service_name: str) -> str:
    """Staat een dienst expliciet toe voor een apparaat (MAC-adres), waardoor
    waarschuwingen voor deze dienst op dit apparaat stoppen."""
    db = SessionLocal()
    try:
        policy = (
            db.query(ServicePolicy)
            .filter_by(scope="device", mac_address=mac_address, service_name=service_name, category=None)
            .first()
        )
        if policy:
            policy.action = "allow"
            policy.expires_at = None
            policy.updated_at = datetime.utcnow()
        else:
            policy = ServicePolicy(
                scope="device",
                mac_address=mac_address,
                service_name=service_name,
                action="allow",
            )
            db.add(policy)
        db.commit()

        return f"Dienst '{service_name}' is nu toegestaan voor apparaat {mac_address}."
    finally:
        db.close()


# ── Tool 4: snooze_anomaly ──────────────────────────────────────


@mcp.tool()
def snooze_anomaly(mac_address: str, alert_type: str, duration_hours: int) -> str:
    """Negeert (snooze) een specifiek type netwerkanomalie voor een apparaat
    gedurende een opgegeven aantal uren. Voorbeelden van alert_type:
    'vpn_tunnel', 'stealth_vpn_tunnel', 'beaconing_threat',
    'iot_lateral_movement', 'iot_suspicious_port', 'service_access', 'upload',
    'new_device'."""
    db = SessionLocal()
    try:
        expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
        exception = AlertException(
            mac_address=mac_address,
            alert_type=alert_type,
            expires_at=expires_at,
        )
        db.add(exception)
        db.commit()

        return (
            f"Anomalie '{alert_type}' voor apparaat {mac_address} wordt "
            f"genegeerd voor {duration_hours} uur (tot {expires_at.strftime('%Y-%m-%d %H:%M')} UTC)."
        )
    finally:
        db.close()


if __name__ == "__main__":
    mcp.run()
