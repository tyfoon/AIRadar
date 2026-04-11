#!/usr/bin/env bash
#
# check_hayday_real_traffic.sh
#
# Find Hay Day's ACTUAL traffic for a device, regardless of whether the
# tailers labelled it. Goes around the labelling layer entirely and looks
# at raw geo_conversations rows + ip_metadata, hunting for:
#
#   - PTR records that mention supercell, hayday, gameserver, etc.
#   - ASN orgs that match Supercell's known infrastructure providers
#   - High-volume "unknown"-labeled flows that fit a mobile-game profile
#     (small bursts of short-lived flows to the same destinations,
#      typical of game polling)
#
# Also runs a temporal-correlation query: pairs every applovin / moloco
# tracking event with what the device was doing in the surrounding
# 5 minutes — if the same set of "unknown" destinations consistently
# co-occurs with applovin hits, those destinations are very likely
# Hay Day game servers.
#
# Usage:  sudo ./check_hayday_real_traffic.sh 192.168.1.209

set -u

if [ $# -lt 1 ]; then
    echo "usage: $0 <ip>"
    exit 2
fi

CONTAINER="airadar-app"
DB="/app/data/airadar.db"
IP="$1"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" "$IP" <<'PY'
import sqlite3, sys, os, re

db_path, ip = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

def section(t):
    print()
    print(f"-- {t}")

def show(rows, headers, max_w=45):
    if not rows:
        print("  (no rows)")
        return
    widths = []
    for i, h in enumerate(headers):
        w = max(len(h), max(min(len(str(r[i] if r[i] is not None else '')), max_w) for r in rows))
        widths.append(w)
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[(str(r[i] if r[i] is not None else '')[:max_w]) for i in range(len(headers))]))

# Resolve IP → MAC list
c.execute("SELECT mac_address FROM device_ips WHERE ip = ? ORDER BY last_seen DESC", (ip,))
macs = [r["mac_address"] for r in c.fetchall()]
if not macs:
    print(f"!! no device for {ip}")
    sys.exit(1)
print(f"MAC(s) for {ip}: {macs}")
qmarks = ",".join("?" * len(macs))

# ---------------------------------------------------------------------
# 1. ALL geo_conversations for this device, sorted by bytes — first 50
#    so we can see what's BEYOND the top 20 we already saw.
# ---------------------------------------------------------------------
section("1. ALL geo_conversations rows 21-50 (last 7 days, by bytes)")
c.execute(f"""
    SELECT g.ai_service, g.resp_ip, g.country_code,
           SUM(g.bytes_transferred) AS bytes,
           SUM(g.hits) AS hits,
           m.ptr, m.asn, m.asn_org
    FROM geo_conversations g
    LEFT JOIN ip_metadata m ON m.ip = g.resp_ip
    WHERE g.mac_address IN ({qmarks})
      AND g.last_seen > datetime('now','-7 days')
    GROUP BY g.ai_service, g.resp_ip, g.country_code
    ORDER BY bytes DESC
    LIMIT 50 OFFSET 20
""", macs)
show(
    [(r["ai_service"] or "(unlabelled)", r["resp_ip"], r["country_code"] or "?",
      f"{r['bytes']:,}", r["hits"],
      (r["asn_org"] or "")[:25], (r["ptr"] or "")[:35])
     for r in c.fetchall()],
    ["service", "resp_ip", "cc", "bytes", "hits", "asn_org", "ptr"],
    max_w=40,
)

# ---------------------------------------------------------------------
# 2. Anywhere in 7 days: PTR / ASN matching Supercell or known mobile
#    game infrastructure providers
# ---------------------------------------------------------------------
section("2. Any traffic with PTR/ASN matching Supercell-style infrastructure")
c.execute(f"""
    SELECT g.ai_service, g.resp_ip, g.country_code,
           SUM(g.bytes_transferred) AS bytes,
           SUM(g.hits) AS hits,
           MAX(g.last_seen) AS last_seen,
           m.ptr, m.asn, m.asn_org
    FROM geo_conversations g
    LEFT JOIN ip_metadata m ON m.ip = g.resp_ip
    WHERE g.mac_address IN ({qmarks})
      AND g.last_seen > datetime('now','-7 days')
      AND (
            lower(coalesce(m.ptr, '')) LIKE '%supercell%'
         OR lower(coalesce(m.ptr, '')) LIKE '%hayday%'
         OR lower(coalesce(m.ptr, '')) LIKE '%clashof%'
         OR lower(coalesce(m.asn_org, '')) LIKE '%supercell%'
         OR lower(g.ai_service) LIKE '%supercell%'
         OR lower(g.ai_service) LIKE '%hay%'
      )
    GROUP BY g.ai_service, g.resp_ip
    ORDER BY bytes DESC
""", macs)
show(
    [(r["ai_service"] or "(unlabelled)", r["resp_ip"], r["country_code"] or "?",
      f"{r['bytes']:,}", r["hits"], r["last_seen"],
      (r["asn_org"] or "")[:25], (r["ptr"] or "")[:35])
     for r in c.fetchall()],
    ["service", "resp_ip", "cc", "bytes", "hits", "last_seen", "asn_org", "ptr"],
    max_w=40,
)

# ---------------------------------------------------------------------
# 3. Top "unknown"-labelled destinations (the unlabelled long tail)
# ---------------------------------------------------------------------
section("3. Top 25 UNKNOWN/UNLABELLED destinations by bytes (last 7 days)")
c.execute(f"""
    SELECT g.resp_ip, g.country_code,
           SUM(g.bytes_transferred) AS bytes,
           SUM(g.hits) AS hits,
           MAX(g.last_seen) AS last_seen,
           m.ptr, m.asn, m.asn_org
    FROM geo_conversations g
    LEFT JOIN ip_metadata m ON m.ip = g.resp_ip
    WHERE g.mac_address IN ({qmarks})
      AND g.last_seen > datetime('now','-7 days')
      AND (g.ai_service IS NULL OR g.ai_service = '' OR g.ai_service = 'unknown')
    GROUP BY g.resp_ip
    ORDER BY bytes DESC
    LIMIT 25
""", macs)
show(
    [(r["resp_ip"], r["country_code"] or "?",
      f"{r['bytes']:,}", r["hits"], r["last_seen"],
      (r["asn_org"] or "")[:30], (r["ptr"] or "")[:40])
     for r in c.fetchall()],
    ["resp_ip", "cc", "bytes", "hits", "last_seen", "asn_org", "ptr"],
    max_w=45,
)

# ---------------------------------------------------------------------
# 4. detection_events for this device with applovin / moloco / google_ads
#    timestamps — these are mobile-game ad networks. If Hay Day was played,
#    these timestamps mark the sessions.
# ---------------------------------------------------------------------
section("4. mobile-game ad-network events (likely Hay Day timestamps)")
c.execute(f"""
    SELECT substr(e.timestamp,1,16) AS ts, e.ai_service, e.category, e.bytes_transferred
    FROM detection_events e
    JOIN device_ips di ON di.ip = e.source_ip
    WHERE di.mac_address IN ({qmarks})
      AND e.timestamp > datetime('now','-7 days')
      AND e.ai_service IN ('applovin','moloco','unity_ads','ironsource','vungle','chartboost')
    ORDER BY e.timestamp DESC
""", macs)
ad_events = c.fetchall()
show(
    [(r["ts"], r["ai_service"], r["category"], f"{r['bytes_transferred']:,}")
     for r in ad_events],
    ["ts", "ai_service", "category", "bytes"],
)
print()
print(f"  → {len(ad_events)} mobile-game-ad events. Each cluster of nearby")
print("    timestamps is one game session. If you see e.g. 5 applovin hits")
print("    within an hour, that's likely one Hay Day session.")

# ---------------------------------------------------------------------
# 5. detection_events around those ad timestamps — what other services
#    were active in the same minutes? That's where Hay Day's game servers
#    are hiding (under 'cloud' or 'unknown' labels).
# ---------------------------------------------------------------------
if ad_events:
    section("5. detection_events ±5min around each ad-event (correlated services)")
    co_services = {}
    for r in ad_events:
        ts = r["ts"]
        c.execute(f"""
            SELECT ai_service, category, COUNT(*) AS n
            FROM detection_events e
            JOIN device_ips di ON di.ip = e.source_ip
            WHERE di.mac_address IN ({qmarks})
              AND e.timestamp BETWEEN datetime(?, '-5 minutes') AND datetime(?, '+5 minutes')
              AND e.ai_service NOT IN ('applovin','moloco','unity_ads','ironsource','vungle','chartboost')
            GROUP BY ai_service
        """, (*macs, ts, ts))
        for cr in c.fetchall():
            key = (cr["ai_service"], cr["category"])
            co_services[key] = co_services.get(key, 0) + cr["n"]
    rows = sorted(co_services.items(), key=lambda x: -x[1])
    show(
        [(svc, cat, n) for (svc, cat), n in rows],
        ["co-occurring service", "category", "n"],
    )
    print()
    print("  → Services that consistently appear in the same 10-min window")
    print("    as mobile-game ads are likely the game's actual server traffic.")

conn.close()
PY
