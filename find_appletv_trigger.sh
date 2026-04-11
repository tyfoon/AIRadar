#!/usr/bin/env bash
#
# find_appletv_trigger.sh
#
# Finds the exact DNS query (or queries) from a given device that
# match_domain() classifies as 'apple_tv'. This is the precise
# reproduction of what the dns_correlated path does: take the
# hostname from dns_observations, call match_domain(), see what
# service it returns. If we find one, we know the hostname and can
# trace back to which macOS process asked for it.
#
# Usage:  sudo ./find_appletv_trigger.sh 192.168.1.251

set -u

if [ $# -lt 1 ]; then
    echo "usage: $0 <ip>"
    exit 2
fi

CONTAINER="airadar-app"
DB="/app/data/airadar.db"
IP="$1"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" "$IP" <<'PY'
import sqlite3, sys

db_path, ip = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

# Resolve IP → MAC
c.execute("""
    SELECT di.mac_address, d.display_name
    FROM device_ips di
    LEFT JOIN devices d ON d.mac_address = di.mac_address
    WHERE di.ip = ?
    ORDER BY di.last_seen DESC
    LIMIT 1
""", (ip,))
row = c.fetchone()
if not row:
    print(f"!! no device for {ip}")
    sys.exit(1)
mac = row["mac_address"]
name = row["display_name"] or mac
print(f"Device: {name}  ({mac})")
print()

# Get DISTINCT queries this laptop has made in the last 12 hours. We
# dedupe because chatty resolvers like macOS ask the same thing
# hundreds of times. 12h is wide enough to catch long-TTL entries
# that are still alive in the in-memory DNS cache but were originally
# resolved hours ago.
c.execute("""
    SELECT query, MAX(observed_at) AS last_ts, COUNT(*) AS n
    FROM dns_observations
    WHERE client_mac = ?
      AND observed_at > datetime('now','-12 hours')
    GROUP BY query
    ORDER BY last_ts DESC
""", (mac,))
queries = c.fetchall()
print(f"Total distinct DNS queries from this device in last 12h: {len(queries)}")
print()

# Now import the REAL match_domain and run every query through it.
# This tells us exactly what the dns_correlated pipeline would label
# each query as, without any simulation fudge.
try:
    sys.path.insert(0, "/app")
    from zeek_tailer import match_domain  # type: ignore
except Exception as exc:
    print(f"!! cannot import match_domain: {exc}")
    sys.exit(1)

# Test each query via match_domain() TWICE: once without source_ip
# (baseline) and once WITH source_ip (the way the real tailer calls
# it from _label_flow_via_dns). Context-aware refinement in
# _refine_classification can transform a generic label into a more
# specific one based on device kind, and we want to catch any case
# where it turns something into apple_tv.
apple_tv_hits = []
other_labeled_hits = {}
unlabeled_count = 0

for r in queries:
    q = r["query"]
    # Try with source_ip first (matches tailer behavior)
    result = match_domain(q, source_ip=ip)
    if result is None:
        # Try without source_ip as fallback check
        result = match_domain(q)
    if result is None:
        unlabeled_count += 1
        continue
    svc, cat, matched = result
    if svc == "apple_tv":
        apple_tv_hits.append((r["last_ts"], q, matched, r["n"]))
    else:
        other_labeled_hits.setdefault(svc, []).append((q, r["n"]))

print(f"Unlabelled (match_domain → None): {unlabeled_count}")
print(f"Labeled to something other than apple_tv: {sum(len(v) for v in other_labeled_hits.values())}")
print(f"Labeled as apple_tv: {len(apple_tv_hits)}")
print()

# ---------------------------------------------------------------------
# The answer we need: which queries triggered the apple_tv label?
# ---------------------------------------------------------------------
print("=== DNS queries from this device that match_domain labels as apple_tv ===")
if not apple_tv_hits:
    print("  (NONE — the dns_correlated path cannot produce apple_tv for this laptop)")
    print()
    print("  This is surprising. If you still see fresh apple_tv sessions,")
    print("  the label must be coming from one of:")
    print("    - A direct sni_hello or quic_hello event for this laptop.")
    print("      Check detection_events with detection_type IN ('sni_hello',")
    print("      'quic_hello') and ai_service='apple_tv'.")
    print("    - The sessionizer picking up stale geo_conversations rows")
    print("      from before the rebuild (historical data — Day 2.4 doesn't")
    print("      re-tag these).")
else:
    apple_tv_hits.sort(key=lambda x: x[0], reverse=True)
    for ts, q, matched, n in apple_tv_hits[:20]:
        print(f"  {ts}  query={q}")
        print(f"    → matched against seed: {matched}")
        print(f"    → observed {n}x in the last 2 hours")
    print()
    print("  → These are the hostnames triggering the label. Cross-reference")
    print("    with `sudo lsof -i -n -P | grep -i <hostname>` on the Mac to")
    print("    find the process. Or grep Little Snitch / LuLu logs if you")
    print("    have them.")

# Also show a top-10 of the OTHER labels, so we can see what the
# laptop's DNS landscape actually looks like and decide if anything
# else is mislabelled.
print()
print("=== Other labels from this device's DNS queries (top services) ===")
top_other = sorted(
    ((svc, len(entries), sum(n for _, n in entries))
     for svc, entries in other_labeled_hits.items()),
    key=lambda x: -x[2],
)[:15]
for svc, distinct, total in top_other:
    print(f"  {svc:<25}  {distinct:>4} distinct queries  ({total} total observations)")

conn.close()
PY
