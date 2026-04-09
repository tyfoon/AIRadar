"""
AI-Radar — IP/Domain Reputation Client.

Layer 1 (proactive, free):  URLhaus + ThreatFox (abuse.ch)
Layer 2 (on-demand, keys):  AbuseIPDB + VirusTotal

All methods are async and return plain dicts suitable for
merging into a ReputationCache row.
"""

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone

import httpx

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_checkable(target: str) -> bool:
    """Return True if target is a public IP or a domain (not private/local)."""
    try:
        addr = ipaddress.ip_address(target)
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast
        )
    except ValueError:
        # Not a valid IP → treat as domain
        return bool(target and "." in target)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Layer 1: abuse.ch (free, no key, no rate limit)
# ---------------------------------------------------------------------------

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

_TIMEOUT = 10  # seconds per request


async def check_urlhaus(host: str) -> dict:
    """Check a host (IP or domain) against URLhaus malware URL database.

    Returns dict with urlhaus_status, urlhaus_threat, urlhaus_tags,
    urlhaus_url_count, urlhaus_checked_at.
    """
    now = _now()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(URLHAUS_API, data={"host": host})
            resp.raise_for_status()
            data = resp.json()

        status = data.get("query_status", "")
        if status == "no_results":
            return {
                "urlhaus_status": "clean",
                "urlhaus_threat": None,
                "urlhaus_tags": None,
                "urlhaus_url_count": 0,
                "urlhaus_checked_at": now,
            }

        # Host found — extract malware info
        urls = data.get("urls", [])
        threats = set()
        tags = set()
        for u in urls:
            t = u.get("threat")
            if t:
                threats.add(t)
            for tag in (u.get("tags") or []):
                if tag:
                    tags.add(tag)

        return {
            "urlhaus_status": "malware",
            "urlhaus_threat": ", ".join(sorted(threats)) or None,
            "urlhaus_tags": json.dumps(sorted(tags)) if tags else None,
            "urlhaus_url_count": len(urls),
            "urlhaus_checked_at": now,
        }
    except Exception as exc:
        print(f"[reputation] URLhaus error for {host}: {exc}")
        return {"urlhaus_checked_at": now}


async def check_threatfox(host: str) -> dict:
    """Check a host against ThreatFox IOC database (C2 servers, etc).

    Returns dict with threatfox_status, threatfox_malware,
    threatfox_confidence, threatfox_checked_at.
    """
    now = _now()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                THREATFOX_API,
                json={"query": "search_ioc", "search_term": host},
            )
            resp.raise_for_status()
            data = resp.json()

        status = data.get("query_status", "")
        if status == "no_result" or not data.get("data"):
            return {
                "threatfox_status": "clean",
                "threatfox_malware": None,
                "threatfox_confidence": None,
                "threatfox_checked_at": now,
            }

        # IOC found — extract info from first (most relevant) result
        iocs = data["data"]
        first = iocs[0] if iocs else {}
        malware = first.get("malware_printable") or first.get("malware")
        confidence = first.get("confidence_level")

        return {
            "threatfox_status": "c2",
            "threatfox_malware": malware,
            "threatfox_confidence": confidence,
            "threatfox_checked_at": now,
        }
    except Exception as exc:
        print(f"[reputation] ThreatFox error for {host}: {exc}")
        return {"threatfox_checked_at": now}


async def check_proactive(host: str) -> dict:
    """Run both Layer 1 checks in parallel. Returns merged dict."""
    import asyncio
    results = await asyncio.gather(
        check_urlhaus(host),
        check_threatfox(host),
        return_exceptions=True,
    )
    merged = {}
    for r in results:
        if isinstance(r, dict):
            merged.update(r)
    return merged


# ---------------------------------------------------------------------------
# Layer 2: AbuseIPDB + VirusTotal (on-demand, requires API keys)
# ---------------------------------------------------------------------------

# Simple in-memory rate limiting
_rate_limits: dict[str, dict] = {
    "abuseipdb": {"count": 0, "day": None, "max": 950},   # leave buffer
    "virustotal": {"count": 0, "day": None, "max": 480,
                   "minute_calls": [], "max_per_min": 4},
}


def _check_rate_limit(service: str) -> bool:
    """Return True if we're within rate limits for the service."""
    rl = _rate_limits.get(service)
    if not rl:
        return True
    today = datetime.now(timezone.utc).date()
    if rl["day"] != today:
        rl["day"] = today
        rl["count"] = 0
    if rl["count"] >= rl["max"]:
        return False
    # Per-minute limit for VT
    if "minute_calls" in rl:
        now = time.time()
        rl["minute_calls"] = [t for t in rl["minute_calls"] if now - t < 60]
        if len(rl["minute_calls"]) >= rl.get("max_per_min", 999):
            return False
    return True


def _record_call(service: str):
    rl = _rate_limits.get(service)
    if rl:
        rl["count"] += 1
        if "minute_calls" in rl:
            rl["minute_calls"].append(time.time())


def get_rate_limit_status() -> dict:
    """Return current rate limit usage for the frontend."""
    result = {}
    for svc, rl in _rate_limits.items():
        today = datetime.now(timezone.utc).date()
        count = rl["count"] if rl["day"] == today else 0
        result[svc] = {"used": count, "max": rl["max"]}
    return result


async def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Check an IP against AbuseIPDB. Returns abuse confidence score."""
    now = _now()
    if not _check_rate_limit("abuseipdb"):
        return {"_error": "AbuseIPDB daily limit reached"}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

        _record_call("abuseipdb")
        return {
            "abuseipdb_score": data.get("abuseConfidenceScore", 0),
            "abuseipdb_reports": data.get("totalReports", 0),
            "abuseipdb_checked_at": now,
        }
    except Exception as exc:
        print(f"[reputation] AbuseIPDB error for {ip}: {exc}")
        return {"_error": f"AbuseIPDB: {exc}"}


async def check_virustotal(target: str, api_key: str) -> dict:
    """Check an IP or domain against VirusTotal (70+ vendor verdicts)."""
    now = _now()
    if not _check_rate_limit("virustotal"):
        return {"_error": "VirusTotal rate limit reached"}

    # Determine if target is IP or domain
    try:
        ipaddress.ip_address(target)
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    except ValueError:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                endpoint,
                headers={"x-apikey": api_key},
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})

        _record_call("virustotal")
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        return {
            "vt_malicious": malicious,
            "vt_total": total,
            "vt_checked_at": now,
        }
    except Exception as exc:
        print(f"[reputation] VirusTotal error for {target}: {exc}")
        return {"_error": f"VirusTotal: {exc}"}


async def check_ondemand(
    target: str,
    abuseipdb_key: str | None = None,
    virustotal_key: str | None = None,
) -> dict:
    """Run Layer 2 checks (whichever keys are available) in parallel."""
    import asyncio
    tasks = []

    # Always run Layer 1 as well (refresh)
    tasks.append(check_proactive(target))

    # AbuseIPDB — IP only
    if abuseipdb_key:
        try:
            ipaddress.ip_address(target)
            tasks.append(check_abuseipdb(target, abuseipdb_key))
        except ValueError:
            pass  # domain — AbuseIPDB only does IPs

    # VirusTotal — IP or domain
    if virustotal_key:
        tasks.append(check_virustotal(target, virustotal_key))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    merged = {}
    errors = []
    for r in results:
        if isinstance(r, dict):
            err = r.pop("_error", None)
            if err:
                errors.append(err)
            merged.update(r)
    if errors:
        merged["_errors"] = errors
    return merged
