#!/usr/bin/env bash
#
# check_hayday.sh
#
# Diagnose why "Hay Day was played but I see nothing" on a specific device.
#
# Hypothesis: Supercell game endpoints are not in known_domains, so the
# tailers never label them, so no detection_event fires, so Daily usage
# is empty for the right reason — we have ZERO labelled gaming activity.
#
# This script confirms or refutes that hypothesis by checking five things:
#
#   1. Which device is currently at the given IP, and what MACs have ever
#      held that IP (handles DHCP rotation across the past week).
#   2. Detection_events for ALL those MACs over 7 days, by service +
#      category. If this shows nothing → labelling is the bottleneck.
#   3. geo_conversations (raw conn.log byte counters per device → IP)
#      for those MACs. If THIS has lots of rows but detection_events
#      doesn't, we have unlabelled traffic — exactly the Day 4 long-tail
#      gap. We can then look at the destination IPs / ASNs / PTRs to see
#      what Hay Day actually talks to.
#   4. Search detection_events / known_domains for ANY "hay", "supercell",
#      or "clash" matches across the whole DB. If zero → no Supercell
#      domains in our seed, period.
#   5. unknown_observations table (Day 4 staging area) for anything that
#      looks gaming-related. If we already have observations, the LLM
#      classifier will catch them; if not, we need to seed manually OR
#      look at the geo_conversations IPs to find the SNIs.
#
# Usage:  sudo ./check_hayday.sh 192.168.1.209

set -u

if [ $# -lt 1 ]; then
    echo "usage: $0 <ip>"
    exit 2
fi

CONTAINER="airadar-app"
DB="/app/data/airadar.db"
IP="$1"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" "$IP" <<'PY'
import sqlite3, sys, os

db_path, ip = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

def section(t):
    print()
    print(f"-- {t}")

def show(rows, headers, max_w=60):
    if not rows:
        print("  (no rows)")
        return
    widths = []
    for i, h in enumerate(headers):
        w = max(len(h), max(min(len(str(r[i])), max_w) for r in rows))
        widths.append(w)
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[(str(r[i])[:max_w]) for i in range(len(headers))]))

# ---------------------------------------------------------------------
# 1. Which MACs have ever had this IP?
# ---------------------------------------------------------------------
section("1. MAC(s) for this IP (any time)")
c.execute("""
    SELECT di.mac_address, d.display_name, d.hostname, d.vendor,
           di.first_seen, di.last_seen
    FROM device_ips di
    LEFT JOIN devices d ON d.mac_address = di.mac_address
    WHERE di.ip = ?
    ORDER BY di.last_seen DESC
""", (ip,))
mac_rows = c.fetchall()
show(mac_rows, ["mac", "display_name", "hostname", "vendor", "first_seen", "last_seen"])
macs = [r["mac_address"] for r in mac_rows]
if not macs:
    print(f"  !! NO device ever held {ip} — wrong IP, or the device only used IPv6")
    sys.exit(1)

qmarks = ",".join("?" * len(macs))

# ---------------------------------------------------------------------
# 2. detection_events for those MACs (last 7 days)
# ---------------------------------------------------------------------
section("2. detection_events last 7 days, ALL MACs above, by category")
c.execute(f"""
    SELECT category, COUNT(*) AS n
    FROM detection_events e
    JOIN device_ips di ON di.ip = e.source_ip
    WHERE di.mac_address IN ({qmarks})
      AND e.timestamp > datetime('now','-7 days')
    GROUP BY category
    ORDER BY n DESC
""", macs)
show(c.fetchall(), ["category", "n"])

section("2b. detection_events last 7 days, top 30 services")
c.execute(f"""
    SELECT category, ai_service, COUNT(*) AS n
    FROM detection_events e
    JOIN device_ips di ON di.ip = e.source_ip
    WHERE di.mac_address IN ({qmarks})
      AND e.timestamp > datetime('now','-7 days')
    GROUP BY category, ai_service
    ORDER BY n DESC
    LIMIT 30
""", macs)
show(c.fetchall(), ["category", "ai_service", "n"])

# ---------------------------------------------------------------------
# 3. geo_conversations for those MACs — what UNLABELLED bytes are flowing?
# ---------------------------------------------------------------------
section("3. geo_conversations: top 20 destinations by bytes (last 7 days)")
c.execute(f"""
    SELECT
      g.ai_service,
      g.resp_ip,
      g.country_code,
      SUM(g.bytes_transferred) AS bytes,
      SUM(g.hits) AS hits,
      MAX(g.last_seen) AS last_seen
    FROM geo_conversations g
    WHERE g.mac_address IN ({qmarks})
      AND g.last_seen > datetime('now','-7 days')
    GROUP BY g.ai_service, g.resp_ip, g.country_code
    ORDER BY bytes DESC
    LIMIT 20
""", macs)
rows = c.fetchall()
# Enrich with PTR + ASN if available
ips_to_enrich = [r["resp_ip"] for r in rows]
meta = {}
if ips_to_enrich:
    qm = ",".join("?" * len(ips_to_enrich))
    for m in c.execute(f"SELECT ip, ptr, asn, asn_org FROM ip_metadata WHERE ip IN ({qm})", ips_to_enrich):
        meta[m["ip"]] = m
print("  ai_service tag is None / 'unknown' = NOT labelled by any tailer")
print()
enriched = []
for r in rows:
    m = meta.get(r["resp_ip"])
    enriched.append((
        r["ai_service"] or "(unlabelled)",
        r["resp_ip"],
        r["country_code"] or "?",
        f"{r['bytes']:,}",
        r["hits"],
        m["asn_org"][:30] if m and m["asn_org"] else "",
        m["ptr"][:35] if m and m["ptr"] else "",
    ))
show(enriched, ["service", "resp_ip", "cc", "bytes", "hits", "asn_org", "ptr"], max_w=40)

# ---------------------------------------------------------------------
# 4. Search the DB for any 'hay'/'supercell'/'clash' references
# ---------------------------------------------------------------------
section("4-pre. how many GAMING domains do we even have in known_domains?")
c.execute("""
    SELECT category, COUNT(*) AS n
    FROM known_domains
    GROUP BY category
    ORDER BY n DESC
""")
show(c.fetchall(), ["category", "n"])
print()
print("  If 'gaming' is 0 or tiny, the issue is fundamental: we have no")
print("  game-vendor domains in our seed, so NO game can ever be labelled")
print("  as gaming — Hay Day, Clash, Roblox, Fortnite, all invisible.")

section("4. anything in known_domains matching hay / supercell / clash?")
c.execute("""
    SELECT domain, service_name, category, source, confidence
    FROM known_domains
    WHERE lower(domain) LIKE '%supercell%'
       OR lower(domain) LIKE '%hayday%'
       OR lower(domain) LIKE '%clash%'
       OR lower(service_name) LIKE '%hay%'
       OR lower(service_name) LIKE '%supercell%'
       OR lower(service_name) LIKE '%clash%'
    ORDER BY domain
""")
show(c.fetchall(), ["domain", "service_name", "category", "source", "confidence"])

section("4b. detection_events ANYWHERE in DB matching hay/supercell/clash?")
c.execute("""
    SELECT ai_service, COUNT(*) AS n
    FROM detection_events
    WHERE lower(ai_service) LIKE '%hay%'
       OR lower(ai_service) LIKE '%supercell%'
       OR lower(ai_service) LIKE '%clash%'
    GROUP BY ai_service
""")
show(c.fetchall(), ["ai_service", "n"])

# ---------------------------------------------------------------------
# 5. unknown_observations — has anything been queued for the LLM yet?
# ---------------------------------------------------------------------
section("5. unknown_observations — anything that looks gaming-related?")
try:
    c.execute("""
        SELECT kind, value, hit_count, first_seen, last_seen
        FROM unknown_observations
        WHERE kind = 'sni'
        ORDER BY hit_count DESC
        LIMIT 30
    """)
    rows = c.fetchall()
    if not rows:
        print("  (no rows — Day 4 LLM classifier hasn't been wired up to feed this table yet)")
    else:
        show(rows, ["kind", "value", "hit_count", "first_seen", "last_seen"])
except sqlite3.OperationalError as e:
    print(f"  !! {e}  (table missing)")

conn.close()
PY
