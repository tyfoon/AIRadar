#!/usr/bin/env bash
#
# check_laptop_appletv_dns.sh
#
# Follow-up to check_laptop_appletv.sh. Finds WHICH domain(s) caused
# the apple_tv label for the laptop — i.e. what did the laptop itself
# DNS-resolve that matched apple_tv in known_domains. If the domain is
# something obvious like tv.apple.com → it's legit (some macOS process
# reached Apple TV). If it's a wildcard match on something generic
# (apple.com, icloud.com) → we have a seed bug where apple_tv matches
# too broadly.
#
# Usage:  sudo ./check_laptop_appletv_dns.sh 192.168.1.251

set -u

if [ $# -lt 1 ]; then
    echo "usage: $0 <laptop-ip>"
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
mac = row["mac_address"]
name = row["display_name"] or mac
print(f"Device: {name}  ({mac})")
print()

# Which known_domains entries match apple_tv?
print("-- known_domains entries with service=apple_tv")
c.execute("""
    SELECT domain, service_name, category, source, confidence
    FROM known_domains
    WHERE service_name = 'apple_tv'
    ORDER BY domain
""")
rows = c.fetchall()
if not rows:
    print("  (none — apple_tv is not in known_domains!)")
else:
    for r in rows:
        print(f"  {r['domain']:<40}  source={r['source']:<15}  conf={r['confidence']}")
print()

# Every DNS query this laptop has made in the last hour that resolves
# to a domain matching anything in the apple_tv seed (either exact or
# as a suffix match).
apple_tv_domains = [r["domain"] for r in rows]

print("-- DNS lookups from this laptop (last hour) that match apple_tv seed")
c.execute("""
    SELECT query, answer_ips, observed_at, ttl
    FROM dns_observations
    WHERE client_mac = ?
      AND observed_at > datetime('now','-1 hour')
    ORDER BY observed_at DESC
""", (mac,))
all_lookups = c.fetchall()

def _matches_apple_tv(q):
    ql = q.lower().rstrip(".")
    for d in apple_tv_domains:
        dl = d.lower().rstrip(".")
        # Match if query IS the seed domain or ENDS with ".seed_domain"
        if ql == dl or ql.endswith("." + dl):
            return d
    return None

matched = []
for r in all_lookups:
    m = _matches_apple_tv(r["query"])
    if m:
        matched.append((r["observed_at"], r["query"], m, r["answer_ips"]))

if not matched:
    print("  (no apple_tv-matching DNS lookups from the laptop in the last hour)")
    print()
    print("  This is interesting: dns_correlated fired for apple_tv but")
    print("  there are no matching DNS lookups from this device. Possible")
    print("  causes: (1) the DNS observation was older than 1 hour but the")
    print("  connection just happened now, (2) the laptop uses a different")
    print("  DNS resolver (DoH/DoT) and the query was never logged, (3)")
    print("  the domain pattern matching in match_domain uses a broader")
    print("  rule than what's in known_domains (a regex, or PSL-based).")
else:
    print(f"  Found {len(matched)} apple_tv-matching DNS lookup(s):")
    for ts, q, seed, ips in matched:
        print(f"    {ts}  query={q}")
        print(f"      → matched seed: {seed}")
        print(f"      → answers: {(ips or '')[:120]}")
        print()

# As a last sanity check: any DNS lookup from the laptop that resolved
# to 17.248.236.65 specifically (the "new" apple_tv IP from section B)
print("-- DNS lookups from this laptop that resolved to 17.248.236.65 specifically")
for r in all_lookups:
    if r["answer_ips"] and "17.248.236.65" in (r["answer_ips"] or ""):
        print(f"  {r['observed_at']}  query={r['query']}")
        print(f"    answers: {r['answer_ips']}")

conn.close()
PY
