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
