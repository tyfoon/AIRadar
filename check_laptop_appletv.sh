#!/usr/bin/env bash
#
# check_laptop_appletv.sh
#
# Day 2.4 verification: after the rebuild, figure out whether fresh
# apple_tv labels for the laptop come from a LEGITIMATE direct SNI/QUIC
# observation (meaning Day 2.4 works as designed) or from the conn.log
# volumetric path inheriting a stale label (meaning Day 2.4 didn't
# catch the bug and we should revert).
#
# Three signatures to distinguish:
#
#   A. sni_hello / quic_hello / dns_correlated for apple_tv → legit
#      direct match. Day 2.4 can't (and shouldn't) block this.
#
#   B. volumetric_upload for apple_tv → inherited label from
#      _known_ips. If this exists post-rebuild, Day 2.4 didn't catch
#      the bug. REVERT.
#
#   C. geo_conversations row for (laptop_mac, apple_tv) with
#      first_seen > rebuild_time → conn.log tagged a NEW flow as
#      apple_tv. Also a sign the fix isn't sticking. REVERT.
#
# Usage:  sudo ./check_laptop_appletv.sh 192.168.1.251 "2026-04-11 21:00:00"

set -u

if [ $# -lt 2 ]; then
    echo "usage: $0 <laptop-ip> <rebuild-utc-ts>"
    echo "example: $0 192.168.1.251 '2026-04-11 21:00:00'"
    exit 2
fi

CONTAINER="airadar-app"
DB="/app/data/airadar.db"
IP="$1"
SINCE="$2"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" "$IP" "$SINCE" <<'PY'
import sqlite3, sys

db_path, ip, since = sys.argv[1], sys.argv[2], sys.argv[3]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

def section(t):
    print()
    print(f"-- {t}")

def show(rows, headers, max_w=50):
    if not rows:
        print("  (no rows)")
        return
    widths = [
        max(len(h), max(min(len(str(r[i] if r[i] is not None else '')), max_w)
                        for r in rows))
        for i, h in enumerate(headers)
    ]
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[(str(r[i] if r[i] is not None else '')[:max_w])
                           for i in range(len(headers))]))

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
print(f"Rebuild cutoff (UTC): {since}")

# ---------------------------------------------------------------------
# A. detection_events for this device with ai_service=apple_tv
#    after the rebuild cutoff, broken down by detection_type
# ---------------------------------------------------------------------
section("A. post-rebuild detection_events for apple_tv, by type")
c.execute("""
    SELECT e.detection_type, COUNT(*) AS n, MIN(e.timestamp) AS first, MAX(e.timestamp) AS last
    FROM detection_events e
    JOIN device_ips di ON di.ip = e.source_ip
    WHERE di.mac_address = ?
      AND e.ai_service = 'apple_tv'
      AND e.timestamp > ?
    GROUP BY e.detection_type
    ORDER BY n DESC
""", (mac, since))
rows = c.fetchall()
show(rows, ["detection_type", "count", "first_ts", "last_ts"])

# Split the findings into VERDICT categories
direct_types = {"sni_hello", "quic_hello", "dns_correlated"}
legit_count = sum(r["n"] for r in rows if r["detection_type"] in direct_types)
suspect_count = sum(r["n"] for r in rows if r["detection_type"] not in direct_types)

section("A-verdict")
if legit_count > 0 and suspect_count == 0:
    print(f"  ✓ {legit_count} LEGITIMATE direct-match apple_tv events.")
    print("  The laptop genuinely observed a TLS/QUIC hello with an")
    print("  apple_tv SNI. Day 2.4 is not designed to hide this and")
    print("  shouldn't. If you didn't knowingly open Apple TV content,")
    print("  something on macOS (Messages, Safari, Photos sharing,")
    print("  Apple Music with video previews, a widget) is reaching")
    print("  tv.apple.com. Check with: sudo lsof -i -n -P | grep -i apple")
elif suspect_count > 0:
    print(f"  ✗ {suspect_count} SUSPECT events (NOT direct-match types).")
    print("  These likely came from the conn.log volumetric path")
    print("  inheriting a stale _known_ips label. Day 2.4 did NOT")
    print("  catch the bug as expected. Consider reverting.")
else:
    print("  (no apple_tv detection_events post-rebuild for this device)")

# ---------------------------------------------------------------------
# B. geo_conversations rows for this device with ai_service=apple_tv
#    where first_seen > rebuild cutoff (= NEW rows, not old ones)
# ---------------------------------------------------------------------
section("B. NEW geo_conversations rows (first_seen > rebuild) for apple_tv")
c.execute("""
    SELECT g.resp_ip, g.country_code, g.bytes_transferred, g.hits,
           g.first_seen, g.last_seen, m.ptr, m.asn_org
    FROM geo_conversations g
    LEFT JOIN ip_metadata m ON m.ip = g.resp_ip
    WHERE g.mac_address = ?
      AND g.ai_service = 'apple_tv'
      AND g.first_seen > ?
    ORDER BY g.first_seen DESC
    LIMIT 20
""", (mac, since))
rows = c.fetchall()
show(
    [(r["resp_ip"], r["country_code"] or "?", f"{r['bytes_transferred']:,}",
      r["hits"], r["first_seen"], (r["asn_org"] or "")[:20], (r["ptr"] or "")[:35])
     for r in rows],
    ["resp_ip", "cc", "bytes", "hits", "first_seen", "asn_org", "ptr"],
    max_w=45,
)

section("B-verdict")
if not rows:
    print("  ✓ No NEW geo_conversations rows for apple_tv post-rebuild.")
    print("  Day 2.4 is preventing the volumetric path from tagging")
    print("  new flows as apple_tv. The label you see in Daily usage")
    print("  is either from a legitimate direct match (see section A)")
    print("  or from historical rows with last_seen updates on pre-")
    print("  existing first_seen entries.")
else:
    print(f"  ✗ {len(rows)} NEW geo_conversations rows are being tagged")
    print("  as apple_tv for this laptop AFTER the rebuild. Day 2.4")
    print("  didn't catch the bug. REVERT.")

# ---------------------------------------------------------------------
# C. UPDATED geo_conversations rows: first_seen old, last_seen new
#    These are pre-existing entries whose byte counter is being bumped
#    by new conn.log flushes.
# ---------------------------------------------------------------------
section("C. EXISTING geo_conv rows that got a byte bump post-rebuild")
c.execute("""
    SELECT g.resp_ip, g.country_code, g.bytes_transferred, g.hits,
           g.first_seen, g.last_seen, m.ptr
    FROM geo_conversations g
    LEFT JOIN ip_metadata m ON m.ip = g.resp_ip
    WHERE g.mac_address = ?
      AND g.ai_service = 'apple_tv'
      AND g.first_seen <= ?
      AND g.last_seen > ?
    ORDER BY g.last_seen DESC
    LIMIT 20
""", (mac, since, since))
rows = c.fetchall()
show(
    [(r["resp_ip"], r["country_code"] or "?", f"{r['bytes_transferred']:,}",
      r["hits"], r["first_seen"], r["last_seen"], (r["ptr"] or "")[:35])
     for r in rows],
    ["resp_ip", "cc", "bytes", "hits", "first_seen", "last_seen", "ptr"],
    max_w=45,
)

section("C-verdict")
if not rows:
    print("  (No pre-existing apple_tv rows are getting byte bumps.)")
else:
    print(f"  ℹ {len(rows)} pre-existing geo_conv rows are being updated.")
    print("  This is a grey area: the rows were ALREADY tagged as")
    print("  apple_tv before the fix, so the conn.log path is just")
    print("  updating byte counts on existing (mac, service, ip)")
    print("  tuples. Day 2.4 doesn't re-tag existing rows — a")
    print("  DELETE/migration would be needed for that. If these")
    print("  rows are frequent, consider a wipe:")
    print("  DELETE FROM geo_conversations")
    print("    WHERE mac_address = ? AND ai_service = 'apple_tv';")

conn.close()
PY
