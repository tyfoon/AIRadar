"""
test_dns_cache.py — self-running assertions for the DNS correlation cache.

No pytest dependency. Run with:
    python tests/test_dns_cache.py

Covers the invariants the rest of the labeler pipeline relies on:

  - IP detection helper handles IPv4 and IPv6, rejects junk
  - Zeek answers parsing maps IPs to the ORIGINAL query, never to
    intermediate CNAMEs (the most important correctness rule)
  - Per-client scoping prevents CDN multi-tenancy false positives
  - LRU eviction kicks in at capacity (no memory leak)
  - TTL expiry happens lazily on lookup (no sweeper thread needed)
  - Replacement counter increments when the same key gets a new
    hostname — observability signal for noisy CDN IPs
  - Stats hit-rate calculation is correct
  - clear() resets both store and counters
"""

import os
import sys
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dns_cache import (  # noqa: E402
    DnsCache,
    is_ip_addr,
    parse_zeek_answers,
    DEFAULT_MIN_TTL_SECONDS,
)


_failures: list[tuple[str, str]] = []
_passed = 0


def check(name: str, condition: bool, message: str = "") -> None:
    global _passed
    if condition:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failures.append((name, message))
        print(f"  FAIL {name}: {message}")


def run(test_func) -> None:
    print(f"\n{test_func.__name__}")
    try:
        test_func()
    except Exception as exc:
        _failures.append((test_func.__name__, f"raised {type(exc).__name__}: {exc}"))
        traceback.print_exc()


# ---------------------------------------------------------------------------
# is_ip_addr
# ---------------------------------------------------------------------------

def test_is_ip_addr_ipv4_basic():
    check("v4.simple", is_ip_addr("142.250.180.110"))
    check("v4.zero", is_ip_addr("0.0.0.0"))
    check("v4.broadcast", is_ip_addr("255.255.255.255"))
    check("v4.loopback", is_ip_addr("127.0.0.1"))


def test_is_ip_addr_ipv6_basic():
    check("v6.full", is_ip_addr("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
    check("v6.compressed", is_ip_addr("2001:db8::1"))
    check("v6.loopback", is_ip_addr("::1"))
    check("v6.linklocal", is_ip_addr("fe80::1"))


def test_is_ip_addr_rejects_garbage():
    check("reject.cname", not is_ip_addr("youtube.l.google.com"))
    check("reject.empty", not is_ip_addr(""))
    check("reject.dash", not is_ip_addr("-"))
    check("reject.partial", not is_ip_addr("142.250.180"))
    check("reject.over_255", not is_ip_addr("256.250.180.110"))
    check("reject.text", not is_ip_addr("not.an.ip.really"))
    check("reject.none", not is_ip_addr(None))


# ---------------------------------------------------------------------------
# parse_zeek_answers — the CNAME-correctness rules
# ---------------------------------------------------------------------------

def test_parse_zeek_answers_simple_a_record():
    """Single A record, no CNAME — trivial case."""
    triples = parse_zeek_answers(
        query="example.com",
        answers_field="93.184.216.34",
        ttls_field="3600",
    )
    check("simple_a.count", len(triples) == 1)
    ip, q, ttl = triples[0]
    check("simple_a.ip", ip == "93.184.216.34")
    check("simple_a.query_preserved", q == "example.com")
    check("simple_a.ttl", ttl == 3600)


def test_parse_zeek_answers_cname_chain_maps_to_original_query():
    """The critical correctness test: CNAMEs in the chain do NOT
    become the mapped hostname. All resolved IPs must come back
    pointing to the ORIGINAL query.
    """
    triples = parse_zeek_answers(
        query="youtube.com",
        answers_field="youtube-ui.l.google.com,142.250.180.110,142.250.180.142",
        ttls_field="300,289,289",
    )
    # 1 CNAME + 2 IPs = 2 IP triples (CNAME is skipped, not mapped)
    check("cname_chain.count_skips_cname", len(triples) == 2)
    # Both IPs map to "youtube.com", NEVER to "youtube-ui.l.google.com"
    queries = {t[1] for t in triples}
    check("cname_chain.all_map_to_original",
          queries == {"youtube.com"},
          f"got hostnames {queries}")
    ips = {t[0] for t in triples}
    check("cname_chain.both_ips_present",
          ips == {"142.250.180.110", "142.250.180.142"})


def test_parse_zeek_answers_multi_cname_still_maps_to_query():
    """A longer CNAME chain (CDN aliasing) is still all → original query."""
    triples = parse_zeek_answers(
        query="www.netflix.com",
        answers_field=(
            "www.geo.netflix.com,www.eu-west-1.prodaa.netflix.com,"
            "ipv4-c001-ams001-ix.1.oca.nflxvideo.net,52.85.132.21"
        ),
        ttls_field="60,60,60,60",
    )
    check("multi_cname.one_ip_extracted", len(triples) == 1)
    ip, q, _ = triples[0]
    check("multi_cname.ip", ip == "52.85.132.21")
    check("multi_cname.query_is_original", q == "www.netflix.com")


def test_parse_zeek_answers_handles_ipv6_in_chain():
    triples = parse_zeek_answers(
        query="cloudflare.com",
        answers_field="2606:4700::6810:84e5,104.16.132.229",
        ttls_field="300,300",
    )
    check("ipv6.count", len(triples) == 2)
    check("ipv6.has_v6", any(t[0] == "2606:4700::6810:84e5" for t in triples))
    check("ipv6.has_v4", any(t[0] == "104.16.132.229" for t in triples))
    check("ipv6.both_query_correct", all(t[1] == "cloudflare.com" for t in triples))


def test_parse_zeek_answers_empty_inputs():
    check("empty.no_query", parse_zeek_answers("", "1.2.3.4", "300") == [])
    check("empty.no_answers", parse_zeek_answers("a.com", "", "300") == [])
    check("empty.dash_answers", parse_zeek_answers("a.com", "-", "300") == [])


def test_parse_zeek_answers_query_lowercased_and_dot_stripped():
    triples = parse_zeek_answers(
        query="WWW.EXAMPLE.COM.",
        answers_field="1.2.3.4",
        ttls_field="60",
    )
    check("normalize.lowercase", triples[0][1] == "www.example.com")


def test_parse_zeek_answers_missing_ttls_uses_default():
    """Some Zeek versions ship dns.log without TTLs in some rows."""
    triples = parse_zeek_answers(
        query="a.com",
        answers_field="1.2.3.4",
        ttls_field=None,
        default_ttl=600,
    )
    check("missing_ttls.uses_default", triples[0][2] == 600)


# ---------------------------------------------------------------------------
# DnsCache — put, get, LRU, TTL
# ---------------------------------------------------------------------------

def test_cache_put_and_get_basic():
    cache = DnsCache()
    cache.put("aa:bb:cc:11:22:33", "1.2.3.4", "youtube.com", raw_ttl=3600)
    got = cache.get("aa:bb:cc:11:22:33", "1.2.3.4")
    check("basic.hit", got == "youtube.com")
    check("basic.size", len(cache) == 1)


def test_cache_get_miss_returns_none():
    cache = DnsCache()
    cache.put("aa:bb:cc:11:22:33", "1.2.3.4", "youtube.com")
    check("miss.different_ip", cache.get("aa:bb:cc:11:22:33", "5.6.7.8") is None)
    check("miss.different_mac", cache.get("ff:ff:ff:ff:ff:ff", "1.2.3.4") is None)
    check("miss.empty_args", cache.get("", "") is None)


def test_cache_per_client_scoping_prevents_cdn_false_positives():
    """The big one: two clients hitting the same Cloudflare IP for
    different services must NOT see each other's hostnames.
    """
    cache = DnsCache()
    cache.put("client:A", "162.159.1.1", "discord.com")
    cache.put("client:B", "162.159.1.1", "twitch.tv")
    check("scope.client_A_isolated",
          cache.get("client:A", "162.159.1.1") == "discord.com")
    check("scope.client_B_isolated",
          cache.get("client:B", "162.159.1.1") == "twitch.tv")


def test_cache_lru_eviction_at_capacity():
    """Capacity = 3, insert 5 entries, the 2 oldest must be gone."""
    cache = DnsCache(max_entries=3)
    cache.put("c", "1.1.1.1", "a.com")
    cache.put("c", "2.2.2.2", "b.com")
    cache.put("c", "3.3.3.3", "c.com")
    cache.put("c", "4.4.4.4", "d.com")
    cache.put("c", "5.5.5.5", "e.com")
    check("lru.size_capped_at_3", len(cache) == 3)
    check("lru.oldest_evicted", cache.get("c", "1.1.1.1") is None)
    check("lru.second_oldest_evicted", cache.get("c", "2.2.2.2") is None)
    check("lru.newest_three_present",
          cache.get("c", "3.3.3.3") == "c.com"
          and cache.get("c", "4.4.4.4") == "d.com"
          and cache.get("c", "5.5.5.5") == "e.com")
    stats = cache.stats()
    check("lru.eviction_counter", stats["evictions"] == 2)


def test_cache_lru_get_refreshes_position():
    """get() must bump the LRU position so a recently-accessed entry
    survives the next eviction round."""
    cache = DnsCache(max_entries=3)
    cache.put("c", "1.1.1.1", "a.com")
    cache.put("c", "2.2.2.2", "b.com")
    cache.put("c", "3.3.3.3", "c.com")
    # Touch the oldest to move it to the most-recent position
    cache.get("c", "1.1.1.1")
    # Now insert a new one — the LRU should evict 2.2.2.2, NOT 1.1.1.1
    cache.put("c", "4.4.4.4", "d.com")
    check("lru_refresh.oldest_kept_alive_by_get",
          cache.get("c", "1.1.1.1") == "a.com")
    check("lru_refresh.middle_evicted",
          cache.get("c", "2.2.2.2") is None)


def test_cache_ttl_expiry_lazy():
    """TTL expiry happens on the lookup that discovers the stale entry,
    not via a sweeper. Use a controllable clock so the test is fast."""
    fake_now = [1000.0]
    cache = DnsCache(min_ttl=60, max_ttl=600, now_fn=lambda: fake_now[0])
    cache.put("c", "1.1.1.1", "youtube.com", raw_ttl=120)
    # 60 seconds later → still alive
    fake_now[0] = 1060.0
    check("ttl.alive_at_60s", cache.get("c", "1.1.1.1") == "youtube.com")
    # 200 seconds after put → expired (TTL was 120, clamped to >= min)
    fake_now[0] = 1200.0
    check("ttl.expired_at_200s", cache.get("c", "1.1.1.1") is None)
    stats = cache.stats()
    check("ttl.expired_counter", stats["expired"] == 1)


def test_cache_ttl_clamped_to_min():
    """A 5 s wire TTL is unhelpful — we clamp to MIN_TTL."""
    fake_now = [1000.0]
    cache = DnsCache(min_ttl=300, max_ttl=86400, now_fn=lambda: fake_now[0])
    cache.put("c", "1.1.1.1", "a.com", raw_ttl=5)
    # 100 s later — still alive because we clamped the wire TTL up to 300
    fake_now[0] = 1100.0
    check("ttl_clamp.min_floor_applied", cache.get("c", "1.1.1.1") == "a.com")


def test_cache_ttl_clamped_to_max():
    """A 1-day wire TTL doesn't extend our retention beyond max."""
    fake_now = [1000.0]
    cache = DnsCache(min_ttl=60, max_ttl=600, now_fn=lambda: fake_now[0])
    cache.put("c", "1.1.1.1", "a.com", raw_ttl=99999)
    # 700 s later → expired despite the wild raw TTL
    fake_now[0] = 1700.0
    check("ttl_clamp.max_ceiling_applied", cache.get("c", "1.1.1.1") is None)


def test_cache_replacement_counter_increments_on_conflict():
    """Same key, different hostname → counts as a replacement."""
    cache = DnsCache()
    cache.put("c", "1.1.1.1", "discord.com")
    cache.put("c", "1.1.1.1", "twitch.tv")  # different hostname for same key
    cache.put("c", "1.1.1.1", "twitch.tv")  # same — should NOT count
    stats = cache.stats()
    check("replace.count_is_one", stats["replacements"] == 1)
    check("replace.most_recent_wins", cache.get("c", "1.1.1.1") == "twitch.tv")


def test_cache_stats_hit_rate():
    cache = DnsCache()
    cache.put("c", "1.1.1.1", "a.com")
    cache.get("c", "1.1.1.1")  # hit
    cache.get("c", "1.1.1.1")  # hit
    cache.get("c", "9.9.9.9")  # miss
    stats = cache.stats()
    check("stats.lookups", stats["lookups"] == 3)
    check("stats.hits", stats["hits"] == 2)
    check("stats.misses", stats["misses"] == 1)
    check("stats.hit_rate", stats["hit_rate"] == round(2/3, 4))


def test_cache_clear_resets_everything():
    cache = DnsCache()
    cache.put("c", "1.1.1.1", "a.com")
    cache.get("c", "1.1.1.1")
    cache.clear()
    check("clear.empty", len(cache) == 0)
    stats = cache.stats()
    check("clear.lookups_zeroed", stats["lookups"] == 0)
    check("clear.puts_zeroed", stats["puts"] == 0)


# ---------------------------------------------------------------------------
# ingest_zeek_response convenience method
# ---------------------------------------------------------------------------

def test_cache_ingest_zeek_response_end_to_end():
    """The convenience wrapper that the tailer actually calls."""
    cache = DnsCache()
    n = cache.ingest_zeek_response(
        client_mac="aa:bb:cc:11:22:33",
        query="youtube.com",
        answers_field="youtube-ui.l.google.com,142.250.180.110,142.250.180.142",
        ttls_field="300,289,289",
    )
    check("ingest.returned_count", n == 2)
    check("ingest.first_ip_mapped",
          cache.get("aa:bb:cc:11:22:33", "142.250.180.110") == "youtube.com")
    check("ingest.second_ip_mapped",
          cache.get("aa:bb:cc:11:22:33", "142.250.180.142") == "youtube.com")
    # Critical: NO entry should exist for the CNAME
    check("ingest.no_cname_mapped",
          cache.get("aa:bb:cc:11:22:33", "youtube-ui.l.google.com") is None)


def test_cache_ingest_skips_garbage_query():
    cache = DnsCache()
    n = cache.ingest_zeek_response("c", "-", "1.1.1.1", "60")
    check("garbage.dash_query_skipped", n == 0)
    n = cache.ingest_zeek_response("c", "", "1.1.1.1", "60")
    check("garbage.empty_query_skipped", n == 0)


# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_is_ip_addr_ipv4_basic,
        test_is_ip_addr_ipv6_basic,
        test_is_ip_addr_rejects_garbage,
        test_parse_zeek_answers_simple_a_record,
        test_parse_zeek_answers_cname_chain_maps_to_original_query,
        test_parse_zeek_answers_multi_cname_still_maps_to_query,
        test_parse_zeek_answers_handles_ipv6_in_chain,
        test_parse_zeek_answers_empty_inputs,
        test_parse_zeek_answers_query_lowercased_and_dot_stripped,
        test_parse_zeek_answers_missing_ttls_uses_default,
        test_cache_put_and_get_basic,
        test_cache_get_miss_returns_none,
        test_cache_per_client_scoping_prevents_cdn_false_positives,
        test_cache_lru_eviction_at_capacity,
        test_cache_lru_get_refreshes_position,
        test_cache_ttl_expiry_lazy,
        test_cache_ttl_clamped_to_min,
        test_cache_ttl_clamped_to_max,
        test_cache_replacement_counter_increments_on_conflict,
        test_cache_stats_hit_rate,
        test_cache_clear_resets_everything,
        test_cache_ingest_zeek_response_end_to_end,
        test_cache_ingest_skips_garbage_query,
    ]

    for t in tests:
        run(t)

    print()
    print("=" * 60)
    print(f"  {_passed} checks passed, {len(_failures)} failed")
    print("=" * 60)

    if _failures:
        print()
        for name, msg in _failures:
            print(f"  FAIL: {name} — {msg}")
        sys.exit(1)
    sys.exit(0)
