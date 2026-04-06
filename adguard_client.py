"""
AI-Radar — AdGuard Home API Client.
Fetches blocking statistics from a local AdGuard Home instance.
"""

from __future__ import annotations

import os

import httpx


class AdGuardClient:
    """Async client for the AdGuard Home REST API."""

    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ):
        self.base_url = (base_url or os.environ.get("ADGUARD_URL", "http://127.0.0.1:80")).rstrip("/")
        _user = username or os.environ.get("ADGUARD_USER", "")
        _pass = password or os.environ.get("ADGUARD_PASS", "")
        self.auth = (_user, _pass) if _user else None

    async def get_stats(self) -> dict:
        """Fetch aggregated statistics from AdGuard Home.

        Returns a dict with:
          - total_queries: int
          - blocked_queries: int
          - block_percentage: float
          - top_blocked: list[{"domain": str, "count": int}]
          - status: "ok" | "unavailable"
        """
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.base_url}/control/stats",
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                data = resp.json()

            total = data.get("num_dns_queries", 0)
            blocked = data.get("num_blocked_filtering", 0)
            pct = (blocked / total * 100) if total > 0 else 0.0

            # top_blocked_domains is a list of {"name": ..., "count": ...}
            top_raw = data.get("top_blocked_domains", [])
            top_blocked = []
            for entry in top_raw[:10]:
                if isinstance(entry, dict):
                    for domain, count in entry.items():
                        top_blocked.append({"domain": domain, "count": count})

            return {
                "total_queries": total,
                "blocked_queries": blocked,
                "block_percentage": round(pct, 1),
                "top_blocked": top_blocked[:10],
                "status": "ok",
            }
        except (httpx.HTTPError, Exception) as exc:
            return {
                "total_queries": 0,
                "blocked_queries": 0,
                "block_percentage": 0.0,
                "top_blocked": [],
                "status": f"unavailable: {exc}",
            }

    async def _get_user_rules(self) -> list[str]:
        """Fetch current user filtering rules from AdGuard."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.base_url}/control/filtering/status",
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                data = resp.json()
                rules = data.get("user_rules") or []
                return [r for r in rules if r.strip()]
        except (httpx.HTTPError, Exception):
            return []

    async def _set_user_rules(self, rules: list[str]) -> bool:
        """Write the full set of user filtering rules to AdGuard."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/control/filtering/set_rules",
                    json={"rules": rules},
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                return True
        except (httpx.HTTPError, Exception) as exc:
            print(f"[adguard] Failed to set rules: {exc}")
            return False

    async def block_domain(self, domain: str) -> bool:
        """Add a block rule for a domain (||domain^).

        Returns True if the rule was added successfully.
        """
        rule = f"||{domain}^"
        rules = await self._get_user_rules()
        if rule in rules:
            return True  # Already blocked
        rules.append(rule)
        return await self._set_user_rules(rules)

    async def unblock_domain(self, domain: str) -> bool:
        """Remove the block rule for a domain.

        Returns True if the rule was removed successfully.
        """
        rule = f"||{domain}^"
        rules = await self._get_user_rules()
        if rule not in rules:
            return True  # Already unblocked
        rules = [r for r in rules if r != rule]
        return await self._set_user_rules(rules)

    async def get_blocked_domains(self) -> list[str]:
        """Return list of currently blocked domains from user rules."""
        rules = await self._get_user_rules()
        blocked = []
        for r in rules:
            if r.startswith("||") and r.endswith("^"):
                blocked.append(r[2:-1])
        return blocked

    async def set_parental_control(self, enabled: bool) -> bool:
        """Enable or disable AdGuard Parental Control (NSFW / gambling / safe-search)."""
        action = "enable" if enabled else "disable"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/control/parental/{action}",
                    content="sensitivity=TEEN",
                    headers={"Content-Type": "text/plain"},
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                return True
        except (httpx.HTTPError, Exception) as exc:
            print(f"[adguard] Failed to {action} parental control: {exc}")
            return False

    async def get_parental_status(self) -> bool:
        """Return True if parental control is currently enabled."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.base_url}/control/parental/status",
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("enabled", False)
        except (httpx.HTTPError, Exception):
            return False

    async def set_blocked_services(self, services: list[str]) -> bool:
        """Push the full list of blocked services to AdGuard Home.

        The AdGuard endpoint replaces the entire list each time, so pass
        ALL services that should be blocked (e.g. ["tiktok", "facebook"]).
        Pass an empty list to unblock all.
        """
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/control/blocked_services/set",
                    json={"ids": services, "schedule": {"time_zone": "Local"}},
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                return True
        except (httpx.HTTPError, Exception) as exc:
            print(f"[adguard] Failed to set blocked services: {exc}")
            return False

    async def get_blocked_services(self) -> list[str]:
        """Return the list of currently blocked services in AdGuard."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.base_url}/control/blocked_services/list",
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                data = resp.json()
                # AdGuard may return {"ids": [...]} or just [...]
                if isinstance(data, list):
                    return data
                return data.get("ids", [])
        except (httpx.HTTPError, Exception):
            return []

    # Background noise domains to exclude from AI reports
    _NOISE_DOMAINS = {
        "time.apple.com", "time.google.com", "time.windows.com",
        "ntp.ubuntu.com", "pool.ntp.org",
        "captive.apple.com", "connectivitycheck.gstatic.com",
        "detectportal.firefox.com", "nmcheck.gnome.org",
        "msftconnecttest.com", "www.msftconnecttest.com",
        "dns.msftncsi.com", "ipv4only.arpa",
        "ocsp.apple.com", "ocsp2.apple.com", "ocsp.digicert.com",
        "crl.apple.com", "crl3.digicert.com", "crl4.digicert.com",
        "gateway.icloud.com", "gsa.apple.com",
        "xp.apple.com", "identity.apple.com",
        "localhost", "local", "broadcasthost",
    }

    async def get_recent_dns_queries(
        self, ips: list[str], hours: int = 24
    ) -> dict[str, int]:
        """Fetch aggregated DNS query counts for specific client IPs.

        Returns a dict of {domain: hit_count} for the top 50 domains,
        filtered to remove background noise (NTP, captive portal, OCSP, etc.).
        """
        try:
            async with httpx.AsyncClient() as client:
                # AdGuard querylog API — fetch recent entries
                # The API paginates; we request a large limit to cover 24h
                resp = await client.get(
                    f"{self.base_url}/control/querylog",
                    params={"limit": 5000, "offset": 0},
                    auth=self.auth,
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json()

            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            ip_set = set(ips)
            domain_counts: dict[str, int] = {}

            entries = data.get("data", data.get("oldest", []))
            if isinstance(data, dict) and "data" in data:
                entries = data["data"]
            elif isinstance(data, list):
                entries = data

            for entry in entries:
                # Filter by client IP
                client_ip = entry.get("client", "")
                if client_ip not in ip_set:
                    continue

                # Filter by time
                ts_str = entry.get("time", "")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass

                # Extract queried domain
                question = entry.get("question", {})
                domain = question.get("name", "").rstrip(".")
                if not domain:
                    continue

                # Skip noise
                if domain in self._NOISE_DOMAINS:
                    continue
                # Skip subdomains of noise
                if any(domain.endswith(f".{nd}") for nd in self._NOISE_DOMAINS):
                    continue

                domain_counts[domain] = domain_counts.get(domain, 0) + 1

            # Return top 50 by hit count
            sorted_domains = sorted(domain_counts.items(), key=lambda x: -x[1])
            return dict(sorted_domains[:50])

        except (httpx.HTTPError, Exception) as exc:
            print(f"[adguard] Failed to fetch query log: {exc}")
            return {}

    async def get_status(self) -> dict:
        """Check if AdGuard Home is running and protection is enabled."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.base_url}/control/status",
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                return resp.json()
        except (httpx.HTTPError, Exception):
            return {"running": False}

    async def set_protection(self, enabled: bool) -> bool:
        """Enable or disable AdGuard DNS protection globally.

        When enabled, we also disable all subscription filter lists so
        only AI-Radar's explicit custom rules (||domain^) take effect.
        This prevents AdGuard's built-in ad/tracker lists from blocking
        things the user didn't ask to block.

        When disabled, AdGuard still runs as a DNS forwarder but stops
        filtering/blocking — all DNS queries pass through untouched.
        This is the key mechanism behind the killswitch: internet keeps
        working, just without filtering.
        """
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/control/dns_config",
                    json={"protection_enabled": enabled},
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                # When turning ON protection, disable all subscription
                # filter lists so only our custom user rules are active.
                if enabled:
                    await self._disable_all_filter_lists()
                return True
        except (httpx.HTTPError, Exception) as exc:
            print(f"[adguard] Failed to {'enable' if enabled else 'disable'} protection: {exc}")
            return False

    async def _disable_all_filter_lists(self) -> None:
        """Disable every subscription-based filter list in AdGuard.

        AdGuard ships with built-in lists (AdGuard Base, AdGuard Mobile
        Ads, etc.) that block thousands of ad/tracker domains. When
        AI-Radar enables protection, we only want OUR explicit custom
        rules to apply — the user controls blocking per service via the
        Rules page, not via bulk ad-blocking lists.

        This function fetches the current filter list config and sets
        every list's `enabled` flag to false. Custom user rules (the
        ones we add via block_domain/unblock_domain) are unaffected —
        they live in a separate section that AdGuard always evaluates
        regardless of filter list state.
        """
        try:
            async with httpx.AsyncClient() as client:
                # Get current filtering status
                resp = await client.get(
                    f"{self.base_url}/control/filtering/status",
                    auth=self.auth,
                    timeout=5,
                )
                resp.raise_for_status()
                data = resp.json()

                filters = data.get("filters") or []
                whitelist = data.get("whitelist_filters") or []
                changed = 0

                for f in filters:
                    if f.get("enabled"):
                        await client.post(
                            f"{self.base_url}/control/filtering/set_url",
                            json={
                                "url": f["url"],
                                "data": {
                                    "name": f.get("name", ""),
                                    "url": f["url"],
                                    "enabled": False,
                                },
                            },
                            auth=self.auth,
                            timeout=5,
                        )
                        changed += 1

                if changed:
                    print(f"[adguard] Disabled {changed} subscription filter list(s) — only custom rules active")
        except Exception as exc:
            print(f"[adguard] Failed to disable filter lists: {exc}")

    async def is_protection_enabled(self) -> bool:
        """Return True if DNS protection (filtering) is currently active."""
        status = await self.get_status()
        return status.get("protection_enabled", True)
