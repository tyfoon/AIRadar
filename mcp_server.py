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
    DeviceBaseline,
    DeviceGroupMember,
    DeviceGroup,
    DeviceIP,
    Device,
    FilterSchedule,
    GeoConversation,
    InboundAttack,
    IpMetadata,
    NetworkPerformance,
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
    "iot_new_country",
    "iot_volume_spike",
    "inbound_threat",
    "inbound_port_scan",
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
    now = datetime.now(timezone.utc).replace(tzinfo=None)
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
        now = datetime.now(timezone.utc).replace(tzinfo=None)
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
            expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=duration_hours)

        policy = (
            db.query(ServicePolicy)
            .filter_by(scope="device", mac_address=mac_address, service_name=service_name, category=None)
            .first()
        )
        if policy:
            policy.action = "block"
            policy.expires_at = expires_at
            policy.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
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
            policy.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
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
        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=duration_hours)
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


# ── Tool 5: search_network_activity ────────────────────────────


@mcp.tool()
def search_network_activity(
    search: str = "",
    hours: int = 24,
    limit: int = 50,
) -> str:
    """Doorzoekt alle recente netwerkactiviteit (niet alleen alerts).
    Gebruik dit om te kijken welke diensten, apps of websites worden
    gebruikt op het netwerk en door wie.

    Voorbeelden:
    - search="hayday" of search="supercell" → kijken of Hay Day gespeeld wordt
    - search="openai" → wie gebruikt OpenAI
    - search="roblox" → wie speelt Roblox
    - search="" (leeg) → alle recente activiteit

    Retourneert per dienst: wie (apparaat), wanneer, hoeveel data."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
        dev_ip_rows = db.query(DeviceIP).all()
        ip_to_mac = {d.ip: d.mac_address for d in dev_ip_rows}
        device_by_mac = {d.mac_address: d for d in db.query(Device).all()}

        q = (
            db.query(DetectionEvent)
            .filter(DetectionEvent.timestamp >= cutoff)
        )
        if search:
            pattern = f"%{search.lower()}%"
            q = q.filter(
                DetectionEvent.ai_service.ilike(pattern)
                | DetectionEvent.detection_type.ilike(pattern)
                | DetectionEvent.category.ilike(pattern)
            )
        events = q.order_by(DetectionEvent.timestamp.desc()).limit(limit).all()

        if not events:
            if search:
                return (
                    f"Geen activiteit gevonden voor '{search}' in de afgelopen "
                    f"{hours} uur. De dienst is niet gedetecteerd op het netwerk."
                )
            return f"Geen netwerkactiviteit gevonden in de afgelopen {hours} uur."

        # Group by (device, service)
        groups: dict[tuple, dict] = {}
        for e in events:
            mac = ip_to_mac.get(e.source_ip)
            dev = device_by_mac.get(mac) if mac else None
            dev_name = (
                (dev.display_name or dev.hostname or mac)
                if dev else e.source_ip
            )
            key = (dev_name, e.ai_service)
            g = groups.get(key)
            if g is None:
                groups[key] = {
                    "device": dev_name,
                    "service": e.ai_service,
                    "category": e.category,
                    "hits": 0,
                    "total_bytes": 0,
                    "first": e.timestamp,
                    "last": e.timestamp,
                }
                g = groups[key]
            g["hits"] += 1
            g["total_bytes"] += e.bytes_transferred or 0
            if e.timestamp < g["first"]:
                g["first"] = e.timestamp
            if e.timestamp > g["last"]:
                g["last"] = e.timestamp

        lines = [f"Netwerkactiviteit (afgelopen {hours} uur)"
                 + (f", zoekterm: '{search}'" if search else "")
                 + f": {len(groups)} resultaten\n"]
        for g in sorted(groups.values(), key=lambda x: x["last"], reverse=True):
            kb = g["total_bytes"] / 1024
            lines.append(
                f"- {g['device']} → {g['service']} ({g['category']}) "
                f"| {g['hits']}x | {kb:.0f} KB "
                f"| {g['first'].strftime('%H:%M')}–{g['last'].strftime('%H:%M')}"
            )
        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 6: list_devices ──────────────────────────────────────


@mcp.tool()
def list_devices() -> str:
    """Geeft een overzicht van alle bekende apparaten op het netwerk,
    inclusief naam, MAC-adres, IP-adres(sen), fabrikant en wanneer
    ze het laatst gezien zijn. Gebruik dit om te achterhalen welke
    apparaten er zijn en hoe ze heten."""
    db = SessionLocal()
    try:
        devices = db.query(Device).order_by(Device.last_seen.desc()).all()
        ip_rows = db.query(DeviceIP).all()
        mac_to_ips: dict[str, list[str]] = {}
        for row in ip_rows:
            mac_to_ips.setdefault(row.mac_address, []).append(row.ip)

        if not devices:
            return "Geen apparaten gevonden."

        lines = [f"Bekende apparaten op het netwerk: {len(devices)}\n"]
        for d in devices:
            name = d.display_name or d.hostname or "onbekend"
            ips = ", ".join(mac_to_ips.get(d.mac_address, []))
            last = d.last_seen.strftime("%Y-%m-%d %H:%M") if d.last_seen else "?"
            vendor = d.vendor or "?"
            lines.append(
                f"- {name} | MAC: {d.mac_address} | IP: {ips} "
                f"| Fabrikant: {vendor} | Laatst gezien: {last}"
            )
        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 7: get_device_screen_time ────────────────────────────


@mcp.tool()
def get_device_screen_time(mac_address: str, hours: int = 24) -> str:
    """Shows how long a device has been actively using apps, grouped by
    category (gaming, social, streaming, ai). Answers questions like
    "How long did this device play Roblox?" or "How much Netflix today?"

    Returns a timeline of sessions with service name, duration, and bytes."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = now - timedelta(hours=hours)

        dev = db.query(Device).filter(Device.mac_address == mac_address).first()
        dev_name = (dev.display_name or dev.hostname or mac_address) if dev else mac_address

        # Get IPs for this device
        ips = [r.ip for r in db.query(DeviceIP.ip).filter(DeviceIP.mac_address == mac_address).all()]
        if not ips:
            return f"Device {mac_address} not found."

        # Activity categories
        activity_cats = ("social", "streaming", "gaming", "ai", "shopping", "news")

        # Get detection events
        from sqlalchemy import or_
        events = (
            db.query(DetectionEvent)
            .filter(
                DetectionEvent.source_ip.in_(ips),
                DetectionEvent.timestamp >= cutoff,
                DetectionEvent.category.in_(activity_cats),
            )
            .order_by(DetectionEvent.timestamp.asc())
            .all()
        )

        # Also get geo_conversations for richer data
        geo = (
            db.query(GeoConversation)
            .filter(
                GeoConversation.mac_address == mac_address,
                GeoConversation.last_seen >= cutoff,
                GeoConversation.ai_service.isnot(None),
                GeoConversation.ai_service != "unknown",
                GeoConversation.ai_service != "",
            )
            .all()
        )

        # Build per-service summary
        svc_stats: dict[str, dict] = {}
        for e in events:
            s = svc_stats.setdefault(e.ai_service, {
                "service": e.ai_service, "category": e.category,
                "hits": 0, "bytes": 0, "first": e.timestamp, "last": e.timestamp,
            })
            s["hits"] += 1
            s["bytes"] += e.bytes_transferred or 0
            if e.timestamp < s["first"]:
                s["first"] = e.timestamp
            if e.timestamp > s["last"]:
                s["last"] = e.timestamp

        # Add geo_conversation bytes (often much larger than event bytes)
        for g in geo:
            s = svc_stats.setdefault(g.ai_service, {
                "service": g.ai_service, "category": "unknown",
                "hits": 0, "bytes": 0, "first": g.first_seen, "last": g.last_seen,
            })
            s["bytes"] += g.bytes_transferred or 0
            s["hits"] += g.hits or 0

        if not svc_stats:
            return f"No app activity for {dev_name} in the last {hours} hours."

        # Group by category
        by_cat: dict[str, list] = {}
        for s in sorted(svc_stats.values(), key=lambda x: x["bytes"], reverse=True):
            by_cat.setdefault(s["category"], []).append(s)

        lines = [f"Screen time for {dev_name} (last {hours}h):\n"]
        grand_bytes = sum(s["bytes"] for s in svc_stats.values())
        lines.append(f"Total data: {grand_bytes / 1048576:.1f} MB\n")

        for cat in ("streaming", "gaming", "social", "ai", "shopping", "news"):
            svcs = by_cat.get(cat, [])
            if not svcs:
                continue
            cat_bytes = sum(s["bytes"] for s in svcs)
            lines.append(f"**{cat.upper()}** ({cat_bytes / 1048576:.1f} MB)")
            for s in svcs:
                duration = (s["last"] - s["first"]).total_seconds()
                dur_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m" if duration >= 3600 else f"{int(duration // 60)}m"
                mb = s["bytes"] / 1048576
                lines.append(f"  - {s['service']}: {dur_str} active, {mb:.1f} MB, {s['hits']} events")
            lines.append("")

        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 8: get_geo_traffic ──────────────────────────────────


@mcp.tool()
def get_geo_traffic(mac_address: str = None, hours: int = 24) -> str:
    """Shows which countries and external networks (ASNs) a device or the
    entire network is communicating with. Answers questions like "Is any
    device talking to China?" or "Where does most traffic go?"

    If mac_address is provided, filters for that specific device."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)

        q = db.query(GeoConversation).filter(GeoConversation.last_seen >= cutoff)
        if mac_address:
            q = q.filter(GeoConversation.mac_address == mac_address)

        convs = q.all()
        if not convs:
            target = f"device {mac_address}" if mac_address else "the network"
            return f"No geo traffic data for {target} in the last {hours} hours."

        # Aggregate by country
        by_country: dict[str, dict] = {}
        for c in convs:
            cc = c.country_code or "??"
            s = by_country.setdefault(cc, {"bytes": 0, "hits": 0, "devices": set()})
            s["bytes"] += c.bytes_transferred or 0
            s["hits"] += c.hits or 0
            if c.mac_address:
                s["devices"].add(c.mac_address)

        # Aggregate by ASN (via ip_metadata)
        resp_ips = list({c.resp_ip for c in convs if c.resp_ip})
        ip_meta = {}
        if resp_ips:
            for m in db.query(IpMetadata).filter(IpMetadata.ip.in_(resp_ips)).all():
                ip_meta[m.ip] = m

        by_asn: dict[str, dict] = {}
        for c in convs:
            meta = ip_meta.get(c.resp_ip)
            asn_label = f"AS{meta.asn} {meta.asn_org}" if meta and meta.asn else "Unknown ASN"
            s = by_asn.setdefault(asn_label, {"bytes": 0, "hits": 0})
            s["bytes"] += c.bytes_transferred or 0
            s["hits"] += c.hits or 0

        # Device name for header
        target = "Network-wide"
        if mac_address:
            dev = db.query(Device).filter(Device.mac_address == mac_address).first()
            target = (dev.display_name or dev.hostname or mac_address) if dev else mac_address

        lines = [f"Geo traffic for {target} (last {hours}h):\n"]

        lines.append("**Top countries:**")
        for cc, s in sorted(by_country.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]:
            mb = s["bytes"] / 1048576
            lines.append(f"  - {cc}: {mb:.1f} MB, {s['hits']} connections, {len(s['devices'])} devices")

        lines.append("\n**Top ASNs:**")
        for asn, s in sorted(by_asn.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]:
            mb = s["bytes"] / 1048576
            lines.append(f"  - {asn}: {mb:.1f} MB, {s['hits']} connections")

        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 9: get_global_filter_status ─────────────────────────


@mcp.tool()
def get_global_filter_status() -> str:
    """Shows the current state of all network-wide content filters and
    service policies. Answers questions like "Is the parental filter on?"
    or "Which services are blocked globally?"."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Filter schedules
        schedules = db.query(FilterSchedule).all()

        # Global policies
        policies = (
            db.query(ServicePolicy)
            .filter(ServicePolicy.scope == "global")
            .all()
        )

        lines = ["**Network Filter Status**\n"]

        # Schedules
        if schedules:
            lines.append("**Filter Schedules:**")
            for s in schedules:
                status = "ENABLED" if s.enabled else "disabled"
                if s.mode == "always":
                    mode_str = "always on"
                else:
                    days = s.days or "none"
                    mode_str = f"{s.start_time}–{s.end_time} on {days}"
                lines.append(f"  - {s.filter_key}: {status} ({mode_str})")
        else:
            lines.append("No filter schedules configured.")

        lines.append("")

        # Policies
        active_policies = [p for p in policies if not p.expires_at or p.expires_at > now]
        if active_policies:
            blocked = [p for p in active_policies if p.action == "block"]
            alerted = [p for p in active_policies if p.action == "alert"]
            allowed = [p for p in active_policies if p.action == "allow"]

            if blocked:
                lines.append(f"**Blocked services ({len(blocked)}):**")
                for p in blocked:
                    target = p.service_name or f"category:{p.category}"
                    exp = f" (until {p.expires_at.strftime('%Y-%m-%d %H:%M')})" if p.expires_at else " (permanent)"
                    lines.append(f"  - {target}{exp}")

            if alerted:
                lines.append(f"\n**Alert-only services ({len(alerted)}):**")
                for p in alerted:
                    target = p.service_name or f"category:{p.category}"
                    lines.append(f"  - {target}")

            if allowed:
                lines.append(f"\n**Explicitly allowed ({len(allowed)}):**")
                for p in allowed:
                    target = p.service_name or f"category:{p.category}"
                    lines.append(f"  - {target}")
        else:
            lines.append("No active global policies.")

        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 10: get_network_performance ─────────────────────────


@mcp.tool()
def get_network_performance(hours: int = 4) -> str:
    """Shows recent network performance metrics: latency, packet loss,
    bandwidth, and system load. Answers questions like "Is the internet
    slow?" or "Is the AIradar box overloaded?"."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)

        rows = (
            db.query(NetworkPerformance)
            .filter(NetworkPerformance.timestamp >= cutoff)
            .order_by(NetworkPerformance.timestamp.desc())
            .limit(50)
            .all()
        )

        if not rows:
            return f"No network performance data in the last {hours} hours."

        latest = rows[0]
        lines = [f"**Network Performance** (last {hours}h, {len(rows)} samples)\n"]

        # Latest metrics
        lines.append("**Current (most recent sample):**")
        if latest.ping_internet_ms is not None:
            lines.append(f"  - Internet ping: {latest.ping_internet_ms:.0f} ms")
        if latest.ping_gateway_ms is not None:
            lines.append(f"  - Gateway ping: {latest.ping_gateway_ms:.0f} ms")
        if latest.dns_latency_ms is not None:
            lines.append(f"  - DNS latency: {latest.dns_latency_ms:.0f} ms")
        if latest.packet_loss_pct is not None:
            lines.append(f"  - Packet loss: {latest.packet_loss_pct:.1f}%")
        if latest.cpu_percent is not None:
            lines.append(f"  - CPU: {latest.cpu_percent:.0f}%")
        if latest.memory_percent is not None:
            lines.append(f"  - Memory: {latest.memory_percent:.0f}%")
        if latest.load_avg_1 is not None:
            lines.append(f"  - Load: {latest.load_avg_1:.2f} / {latest.load_avg_5:.2f} / {latest.load_avg_15:.2f}")

        # Averages
        pings = [r.ping_internet_ms for r in rows if r.ping_internet_ms is not None]
        losses = [r.packet_loss_pct for r in rows if r.packet_loss_pct is not None]
        cpus = [r.cpu_percent for r in rows if r.cpu_percent is not None]

        if pings:
            lines.append(f"\n**Averages ({len(rows)} samples):**")
            lines.append(f"  - Avg internet ping: {sum(pings)/len(pings):.0f} ms (min {min(pings):.0f}, max {max(pings):.0f})")
        if losses:
            lines.append(f"  - Avg packet loss: {sum(losses)/len(losses):.2f}%")
        if cpus:
            lines.append(f"  - Avg CPU: {sum(cpus)/len(cpus):.0f}%")

        # Warnings
        warnings = []
        if pings and max(pings) > 100:
            warnings.append(f"High latency detected: {max(pings):.0f} ms peak")
        if losses and max(losses) > 1.0:
            warnings.append(f"Packet loss detected: {max(losses):.1f}% peak")
        if cpus and max(cpus) > 90:
            warnings.append(f"High CPU usage: {max(cpus):.0f}% peak")

        if warnings:
            lines.append("\n**⚠️ Warnings:**")
            for w in warnings:
                lines.append(f"  - {w}")

        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 11: get_iot_health ──────────────────────────────────


@mcp.tool()
def get_iot_health() -> str:
    """Shows the health status of IoT/smart home devices compared to their
    learned baselines. Answers questions like "Are my smart devices behaving
    normally?" or "Which IoT device is acting weird?"."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff_24h = now - timedelta(hours=24)

        baselines = db.query(DeviceBaseline).all()
        device_by_mac = {d.mac_address: d for d in db.query(Device).all()}

        if not baselines:
            return "No IoT baselines computed yet. Devices need 7+ days of data."

        # Get recent anomaly alerts
        anomaly_types = ("iot_volume_spike", "iot_new_country", "iot_lateral_movement", "iot_suspicious_port")
        ip_rows = db.query(DeviceIP).all()
        mac_to_ips = {}
        for r in ip_rows:
            mac_to_ips.setdefault(r.mac_address, []).append(r.ip)

        all_anomaly_ips = []
        for b in baselines:
            all_anomaly_ips.extend(mac_to_ips.get(b.mac_address, []))

        anomalies = []
        if all_anomaly_ips:
            anomalies = (
                db.query(DetectionEvent)
                .filter(
                    DetectionEvent.source_ip.in_(all_anomaly_ips),
                    DetectionEvent.detection_type.in_(anomaly_types),
                    DetectionEvent.timestamp >= cutoff_24h,
                )
                .all()
            )

        # Map anomalies to MACs
        ip_to_mac = {ip: mac for mac, ips in mac_to_ips.items() for ip in ips}
        anomalies_by_mac: dict[str, list] = {}
        for a in anomalies:
            mac = ip_to_mac.get(a.source_ip)
            if mac:
                anomalies_by_mac.setdefault(mac, []).append(a)

        lines = [f"**IoT Health Report** ({len(baselines)} devices with baselines)\n"]

        # Devices with anomalies
        problem_devices = []
        healthy_devices = []
        for b in baselines:
            dev = device_by_mac.get(b.mac_address)
            name = (dev.display_name or dev.hostname or b.mac_address) if dev else b.mac_address
            device_anomalies = anomalies_by_mac.get(b.mac_address, [])

            if device_anomalies:
                problem_devices.append((name, b, device_anomalies))
            else:
                healthy_devices.append((name, b))

        if problem_devices:
            lines.append(f"**⚠️ Devices with anomalies ({len(problem_devices)}):**")
            for name, b, anoms in problem_devices:
                lines.append(f"  - **{name}** (baseline: {b.avg_bytes_hour / 1024:.0f} KB/h)")
                for a in anoms[:3]:
                    lines.append(f"    - {a.detection_type}: {a.ai_service} ({a.bytes_transferred / 1024:.0f} KB) at {a.timestamp.strftime('%H:%M')}")
            lines.append("")

        lines.append(f"**✅ Healthy devices ({len(healthy_devices)}):**")
        for name, b in healthy_devices[:15]:
            countries = b.known_countries or "[]"
            lines.append(f"  - {name}: {b.avg_bytes_hour / 1024:.0f} KB/h baseline, countries: {countries}")

        return "\n".join(lines)
    finally:
        db.close()


# ── Tool 12: get_inbound_threats ─────────────────────────────


@mcp.tool()
def get_inbound_threats(hours: int = 24) -> str:
    """Shows inbound attacks and port scans detected by CrowdSec and the
    IPS. Answers questions like "Is someone trying to hack my network?"
    or "Which ports are being scanned?"."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)

        attacks = (
            db.query(InboundAttack)
            .filter(InboundAttack.last_seen >= cutoff)
            .order_by(InboundAttack.hit_count.desc())
            .limit(50)
            .all()
        )

        if not attacks:
            return f"No inbound threats detected in the last {hours} hours. Network perimeter is clean."

        total_hits = sum(a.hit_count or 0 for a in attacks)
        unique_ips = len({a.source_ip for a in attacks})
        unique_ports = len({a.target_port for a in attacks if a.target_port})

        lines = [
            f"**Inbound Threats** (last {hours}h)\n",
            f"Total: {total_hits} blocked attempts from {unique_ips} unique IPs targeting {unique_ports} ports\n",
        ]

        # Group by severity
        by_severity: dict[str, list] = {}
        for a in attacks:
            by_severity.setdefault(a.severity or "unknown", []).append(a)

        for sev in ("threat", "aggressive", "scan", "unknown"):
            group = by_severity.get(sev, [])
            if not group:
                continue
            lines.append(f"**{sev.upper()} ({len(group)} sources):**")
            for a in group[:10]:
                country = f" ({a.country_code})" if a.country_code else ""
                asn = f" [{a.asn_org}]" if a.asn_org else ""
                reason = f" — {a.crowdsec_reason}" if a.crowdsec_reason else ""
                lines.append(
                    f"  - {a.source_ip}{country}{asn}: "
                    f"port {a.target_port}/{a.protocol or '?'}, "
                    f"{a.hit_count}x{reason}"
                )
            lines.append("")

        return "\n".join(lines)
    finally:
        db.close()


if __name__ == "__main__":
    mcp.run()
