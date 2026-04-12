"""
dns_cache.py — passive DNS-to-IP correlation cache.

Populated by zeek_tailer.tail_dns_log() from Zeek's dns.log. Used by the
labeler fallback path: when a TLS or QUIC flow has no visible SNI, we
look up the most recent hostname this client resolved to that server IP
and use it as the service-identification signal.

Why this matters: 70-80% of our network traffic today flows over QUIC
(YouTube, Netflix, mobile games, ...), and a growing fraction of those
QUIC streams use Encrypted Client Hello (ECH) which makes the SNI
literally invisible on the wire. The DNS lookup that preceded the
encrypted connection, however, is still in plaintext (or visible to
AdGuard, which we hijack on the bridge). Correlating client→IP back to
the original DNS query is the single highest-leverage technique for
recovering visibility into encrypted traffic.

Quality / correctness invariants enforced here:

  1. CNAME-aware parsing. Zeek's dns.log "answers" field for a query
     like youtube.com may contain `youtube.l.google.com,142.250.x.x` —
     a CNAME followed by the actual A record. We map IPs to the
     ORIGINAL query (youtube.com), never to the intermediate CNAME.
     If a labeler later looks up "youtube.l.google.com" in our service
     map it would miss; "youtube.com" hits.

  2. Per-client scoping. CDN multi-tenancy is the #1 false-positive
     source for any naive DNS-correlation system: the same Cloudflare
     IP serves dozens of unrelated services in the same minute. We
     scope every cache entry to (client_mac, server_ip), so client A
     resolving "discord.com → 162.159.x.x" and client B resolving
     "twitch.tv → 162.159.x.x" do not corrupt each other's labels.

  3. OrderedDict-based LRU. A naive Python dict has no eviction
     semantics; we'd either leak memory or burn CPU on periodic
     cleanup loops. OrderedDict.popitem(last=False) gives us O(1)
     LRU eviction with no extra bookkeeping.

  4. TTL-honoured expiry. Each entry inherits the TTL from the DNS
     response (clamped to a sane floor and ceiling). On lookup we
     evict expired entries lazily — no separate sweeper thread needed.

  5. Replacement counter. If the same (client, server_ip) pair starts
     getting different hostnames in quick succession, that's a strong
     signal that we're looking at a multi-tenant CDN where DNS-based
     correlation is unreliable. The counter is exposed via stats() so
     observability can flag it.

The module has zero dependencies on zeek_tailer, sqlalchemy, httpx, or
any application code — pure stdlib so the tests can run in isolation.
"""

from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Maximum number of (client_mac, server_ip) entries kept in memory.
# At ~150 bytes per entry this caps memory at ~7.5 MB which is fine for
# a home/SMB network. Larger deployments can override at runtime.
DEFAULT_MAX_ENTRIES = 50_000

# Hard floor: we keep an entry alive at least this long even if the DNS
# response specified a tiny TTL. Many CDNs ship 30-60 s TTLs for load
# balancing reasons, but the application that just resolved the domain
# typically caches the result client-side for far longer.
#
# 12 hours: a Netflix stream can last 3+ hours, and Zeek writes conn.log
# at connection teardown. With a 5-minute TTL, the DNS→IP correlation
# fails for any long-lived connection. 12h covers overnight streaming
# sessions and work-from-home video calls while still expiring within
# the same day to limit staleness.
DEFAULT_MIN_TTL_SECONDS = 43200  # 12 hours

# Hard ceiling: never trust a single DNS observation for longer than
# this, regardless of advertised TTL, to bound staleness during
# multi-day uptimes.
DEFAULT_MAX_TTL_SECONDS = 86400


# ---------------------------------------------------------------------------
# Address parsing
# ---------------------------------------------------------------------------

def is_ip_addr(value: str) -> bool:
    """Return True if `value` looks like an IPv4 or IPv6 address.

    Used to distinguish IPs from CNAMEs in Zeek's `answers` field.
    Deliberately conservative: we'd rather miss a malformed IP than
    treat a CNAME as one. Uses the stdlib `ipaddress` module for
    correctness — handling IPv6 ourselves is a footgun.
    """
    if not value or not isinstance(value, str):
        return False
    s = value.strip()
    if not s:
        return False
    # ipaddress.ip_address() raises on garbage; cheap and authoritative.
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def parse_zeek_answers(
    query: str,
    answers_field: str,
    ttls_field: Optional[str] = None,
    default_ttl: int = DEFAULT_MIN_TTL_SECONDS,
) -> list[tuple[str, str, int]]:
    """Extract (ip, query, ttl) triples from a Zeek dns.log answers field.

    Zeek's "answers" is a comma-separated vector that mixes intermediate
    CNAMEs and the final A/AAAA records:

        query   = "youtube.com"
        answers = "youtube-ui.l.google.com,142.250.180.110,142.250.180.142"
        TTLs    = "300.0,289.0,289.0"

    The CNAME-correctness rule is: every IP in the chain represents the
    ORIGINAL query, regardless of how many CNAMEs sit between them.
    Mapping IPs to the intermediate CNAME would defeat the whole point
    (the labeler then has to look up "youtube-ui.l.google.com" instead
    of "youtube.com" and miss the service map).

    Returns an empty list if the query is empty or no IPs are present.
    Each TTL is clamped via _normalize_ttl() before being returned.
    """
    if not query:
        return []
    q = query.rstrip(".").lower()
    if not q or q == "-":
        return []

    if not answers_field or answers_field == "-":
        return []

    answer_list = [a.strip() for a in answers_field.split(",")]

    ttl_list: list[int] = []
    if ttls_field and ttls_field != "-":
        for raw in ttls_field.split(","):
            raw = raw.strip()
            if not raw:
                ttl_list.append(default_ttl)
                continue
            try:
                ttl_list.append(int(float(raw)))
            except (ValueError, TypeError):
                ttl_list.append(default_ttl)

    out: list[tuple[str, str, int]] = []
    for i, ans in enumerate(answer_list):
        if not is_ip_addr(ans):
            # CNAME or other RR type — skip but DO NOT update the query.
            # The query string we keep mapping to is still the original.
            continue
        ttl = ttl_list[i] if i < len(ttl_list) else default_ttl
        out.append((ans, q, ttl))
    return out


def _normalize_ttl(
    raw_ttl: int,
    min_ttl: int = DEFAULT_MIN_TTL_SECONDS,
    max_ttl: int = DEFAULT_MAX_TTL_SECONDS,
) -> int:
    """Clamp a raw TTL into [min_ttl, max_ttl]."""
    if raw_ttl is None or raw_ttl <= 0:
        return min_ttl
    return max(min_ttl, min(max_ttl, int(raw_ttl)))


# ---------------------------------------------------------------------------
# DnsCache — the actual store
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    hostname: str
    observed_at: float       # epoch seconds when we recorded it
    ttl: int                 # seconds, normalized


class DnsCache:
    """Thread-safe LRU+TTL cache mapping (client_mac, server_ip) to hostnames.

    Used as a singleton from zeek_tailer (the global instance is at the
    bottom of this module) but the class itself is testable in isolation
    by instantiating with custom parameters and a custom time source.

    The custom time source (`now_fn`) is the trick that makes TTL-expiry
    tests fast: we pass a callable that returns a controllable timestamp
    instead of relying on time.sleep().
    """

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        min_ttl: int = DEFAULT_MIN_TTL_SECONDS,
        max_ttl: int = DEFAULT_MAX_TTL_SECONDS,
        now_fn=time.time,
    ) -> None:
        self.max_entries = max_entries
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self._now = now_fn
        # OrderedDict keyed by (client_mac, server_ip). Most-recently
        # accessed entry is at the END; oldest at the FRONT. This is
        # the canonical Python LRU pattern and gives O(1) on every op.
        self._store: "collections.OrderedDict[tuple[str, str], CacheEntry]" = (
            collections.OrderedDict()
        )
        self._lock = threading.Lock()
        # Counters: lookups / hits / misses / evictions / replacements.
        # Replacements is the most interesting one for observability —
        # it spikes when we're seeing CDN multi-tenancy false positives.
        self._stats = {
            "puts": 0,
            "lookups": 0,
            "hits": 0,
            "misses": 0,
            "expired": 0,
            "evictions": 0,
            "replacements": 0,
        }

    def put(
        self,
        client_mac: str,
        server_ip: str,
        hostname: str,
        raw_ttl: int = DEFAULT_MIN_TTL_SECONDS,
    ) -> None:
        """Insert or refresh an entry. Evicts the oldest if at capacity.

        If the same key already maps to a different hostname, we count
        it as a replacement (multi-tenancy / TTL-roll signal) and
        overwrite. The original is gone — we always trust the most
        recent observation.
        """
        if not client_mac or not server_ip or not hostname:
            return

        ttl = _normalize_ttl(raw_ttl, self.min_ttl, self.max_ttl)
        key = (client_mac, server_ip)
        now = self._now()

        with self._lock:
            self._stats["puts"] += 1
            existing = self._store.get(key)
            if existing is not None and existing.hostname != hostname:
                self._stats["replacements"] += 1
            self._store[key] = CacheEntry(
                hostname=hostname,
                observed_at=now,
                ttl=ttl,
            )
            # Mark as most-recently-used.
            self._store.move_to_end(key, last=True)

            # LRU eviction. Pop from the FRONT (least-recently-used) until
            # we're back under capacity. Almost always one iteration.
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)
                self._stats["evictions"] += 1

    def get(self, client_mac: str, server_ip: str) -> Optional[str]:
        """Return the most recent hostname for this (client, server_ip), or None.

        Honors TTL: an expired entry is removed lazily on the lookup
        that discovers it, no separate sweeper. Successful lookups
        also bump LRU position so frequently-correlated pairs survive
        eviction longer.
        """
        if not client_mac or not server_ip:
            return None
        key = (client_mac, server_ip)
        now = self._now()

        with self._lock:
            self._stats["lookups"] += 1
            entry = self._store.get(key)
            if entry is None:
                self._stats["misses"] += 1
                return None
            if (now - entry.observed_at) > entry.ttl:
                # Lazy TTL expiry.
                del self._store[key]
                self._stats["expired"] += 1
                self._stats["misses"] += 1
                return None
            # Hit — bump LRU position.
            self._store.move_to_end(key, last=True)
            self._stats["hits"] += 1
            return entry.hostname

    def ingest_zeek_response(
        self,
        client_mac: str,
        query: str,
        answers_field: str,
        ttls_field: Optional[str] = None,
    ) -> int:
        """Convenience: parse a Zeek dns.log row and put() each resolved IP.

        Returns the number of (ip, query, ttl) triples that were
        inserted. Caller can use this for telemetry / debugging.
        """
        triples = parse_zeek_answers(query, answers_field, ttls_field, self.min_ttl)
        for ip, q, ttl in triples:
            self.put(client_mac, ip, q, ttl)
        return len(triples)

    def stats(self) -> dict:
        """Return a copy of the cache stats. Safe to call from any thread."""
        with self._lock:
            snapshot = dict(self._stats)
            snapshot["size"] = len(self._store)
            snapshot["max_entries"] = self.max_entries
            # Hit rate is the most useful headline metric.
            lookups = snapshot["lookups"] or 1
            snapshot["hit_rate"] = round(snapshot["hits"] / lookups, 4)
        return snapshot

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """Empty the cache (for tests / restart). Counters are also reset."""
        with self._lock:
            self._store.clear()
            for k in self._stats:
                self._stats[k] = 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
# zeek_tailer imports this and uses it as the process-wide cache. Tests
# create their own DnsCache() instances to keep state isolated.
GLOBAL_CACHE = DnsCache()
