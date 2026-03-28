"""
AI-Radar — AdGuard Home API Client.
Fetches blocking statistics from a local AdGuard Home instance.
"""

from __future__ import annotations

import httpx


class AdGuardClient:
    """Async client for the AdGuard Home REST API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:80",
        username: str = "goswijn@goswijn.com",
        password: str = "3xvBqkA5vYKUW7z",
    ):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password) if username else None

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
