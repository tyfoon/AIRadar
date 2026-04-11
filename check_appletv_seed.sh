#!/usr/bin/env bash
#
# check_appletv_seed.sh
#
# Quick seed diagnostic. After Day 2.4 we observed that the laptop gets
# labelled as "apple_tv" when it actually only DNS-resolved iCloud/
# CloudKit endpoints (api.apple-cloudkit.com, gateway.icloud.com). That
# means match_domain() is pairing a CloudKit hostname with an apple_tv
# service_name — a seed bug that predates Day 2.4 and got exposed when
# the DNS correlation path started exercising match_domain() more often.
#
# This script answers four questions:
#
#   1. Which domains in known_domains map to service=apple_tv? Any of
#      them suspiciously broad (apple.com, icloud.com, cloudkit.com)?
#
#   2. Are CloudKit / iCloud-gateway hostnames explicitly mapped to a
#      different service (icloud, cloudkit, apple_cloud), or do they
#      just fall through to an ancestor domain match?
#
#   3. For the exact hostnames we saw in the DNS observations
#      (api.apple-cloudkit.com, gateway.icloud.com): what would the
#      service map return? We simulate match_domain() by ranking all
#      known_domains rows that the hostname would suffix-match and
#      picking the longest-prefix winner.
#
#   4. Sanity-check the label a given hostname would get via the real
#      match_domain() function in zeek_tailer. This is a live import
#      inside the container so we get the exact same answer the tailer
#      would give.
#
# Usage:  sudo ./check_appletv_seed.sh

set -u

CONTAINER="airadar-app"
DB="/app/data/airadar.db"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

# ---------------------------------------------------------------------
# 1. All apple_tv seed entries
# ---------------------------------------------------------------------
print("=== 1. known_domains entries with service_name = 'apple_tv' ===")
rows = c.execute("""
    SELECT domain, service_name, category, source, confidence
    FROM known_domains
    WHERE service_name = 'apple_tv'
    ORDER BY length(domain), domain
""").fetchall()
if not rows:
    print("  (none — apple_tv is not in known_domains at all!)")
else:
    for r in rows:
        src = r["source"] or "?"
        conf = r["confidence"] if r["confidence"] is not None else "?"
        print(f"  {r['domain']:<40}  cat={r['category']:<10}  src={src:<15}  conf={conf}")

# Flag suspiciously broad entries
suspect = [r for r in rows
           if r["domain"].lower() in ("apple.com", "icloud.com", "cloudkit.com",
                                      "apple-cloudkit.com", "me.com",
                                      "itunes.apple.com")]
if suspect:
    print()
    print("  !! SUSPICIOUSLY BROAD entries (likely root cause):")
    for r in suspect:
        print(f"     {r['domain']} → apple_tv   ← too broad, should be icloud/apple/cloudkit")

print()

# ---------------------------------------------------------------------
# 2. All rows mentioning cloudkit or icloud in the domain
# ---------------------------------------------------------------------
print("=== 2. known_domains with 'cloudkit' or 'icloud' in the domain ===")
rows = c.execute("""
    SELECT domain, service_name, category, source
    FROM known_domains
    WHERE lower(domain) LIKE '%cloudkit%'
       OR lower(domain) LIKE '%icloud%'
       OR lower(domain) LIKE '%apple-cloud%'
    ORDER BY service_name, domain
""").fetchall()
if not rows:
    print("  (no cloudkit/icloud entries at all — match_domain has nothing to use)")
else:
    for r in rows:
        print(f"  {r['domain']:<40}  service={r['service_name']:<25}  src={r['source']}")

print()

# ---------------------------------------------------------------------
# 3. Simulate which known_domains row a given hostname would suffix-
#    match. Longest match wins (closest to how match_domain typically
#    works in domain-classification systems).
# ---------------------------------------------------------------------
def simulate_suffix_match(hostname, all_domains):
    hn = hostname.lower().rstrip(".")
    candidates = []
    for row in all_domains:
        d = row["domain"].lower().rstrip(".")
        if hn == d or hn.endswith("." + d):
            candidates.append(row)
    candidates.sort(key=lambda r: -len(r["domain"]))
    return candidates

all_rows = c.execute("""
    SELECT domain, service_name, category, source
    FROM known_domains
""").fetchall()

print("=== 3. Simulated suffix-match for the hostnames we saw ===")
for hostname in (
    "api.apple-cloudkit.com",
    "gateway.icloud.com",
    "tv.apple.com",
    "photos.icloud.com",
    "p100-sharedstreams.icloud.com",
):
    print(f"\n  hostname: {hostname}")
    matches = simulate_suffix_match(hostname, all_rows)
    if not matches:
        print("    (no matching row — match_domain would return None)")
        continue
    winner = matches[0]
    print(f"    winner:   {winner['domain']}  →  service={winner['service_name']}")
    if len(matches) > 1:
        print(f"    runners-up ({len(matches)-1}):")
        for m in matches[1:5]:
            print(f"      {m['domain']:<35}  →  {m['service_name']}")

print()

# ---------------------------------------------------------------------
# 4. Live match_domain() call — import from zeek_tailer and ask it.
#    This is the real answer the tailer pipeline would give, so it
#    catches any logic beyond plain suffix matching (regex, PSL, etc.).
# ---------------------------------------------------------------------
print("=== 4. Live match_domain() results (what the tailer actually returns) ===")
try:
    sys.path.insert(0, "/app")
    from zeek_tailer import match_domain  # type: ignore
    for hostname in (
        "api.apple-cloudkit.com",
        "gateway.icloud.com",
        "tv.apple.com",
        "apple-cloudkit.com",
        "cloudkit.apple.com",
    ):
        result = match_domain(hostname)
        if result is None:
            print(f"  {hostname:<30}  →  None (no match)")
        else:
            svc, cat, matched = result
            print(f"  {hostname:<30}  →  service={svc}  category={cat}  (via: {matched})")
except Exception as exc:
    print(f"  !! could not import / call match_domain: {exc}")

conn.close()
PY
