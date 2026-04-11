#!/usr/bin/env bash
#
# list_apple_devices.sh
#
# List every Apple device on the network with its current IP, when it
# was last seen, and how many detection_events fired for it in the last
# hour. Use this when you played something on "the iPad" but the
# diagnostic on a specific IP turned up empty — there may be more than
# one iPad/iPhone on your network and you may be looking at the wrong
# one.
#
# Sorts by activity in the last hour (most active first), so the device
# you're actually using right now floats to the top.
#
# Usage:  sudo ./list_apple_devices.sh

set -u

CONTAINER="airadar-app"
DB="/app/data/airadar.db"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

# Find every device that smells like Apple — vendor match OR hostname/
# display_name containing iPad/iPhone/Mac. The OR catches custom-named
# devices where vendor lookup failed but the name betrays the OS.
rows = c.execute("""
    SELECT
        d.mac_address,
        d.display_name,
        d.hostname,
        d.vendor,
        d.last_seen,
        (SELECT GROUP_CONCAT(ip, ', ')
         FROM device_ips
         WHERE mac_address = d.mac_address) AS ips,
        (SELECT COUNT(*) FROM detection_events e
         JOIN device_ips di ON di.ip = e.source_ip
         WHERE di.mac_address = d.mac_address
           AND e.timestamp > datetime('now','-1 hour')) AS events_1h,
        (SELECT COUNT(*) FROM detection_events e
         JOIN device_ips di ON di.ip = e.source_ip
         WHERE di.mac_address = d.mac_address
           AND e.timestamp > datetime('now','-15 minutes')) AS events_15min,
        (SELECT COALESCE(SUM(bytes_transferred), 0) FROM geo_conversations g
         WHERE g.mac_address = d.mac_address
           AND g.last_seen > datetime('now','-1 hour')) AS bytes_1h
    FROM devices d
    WHERE lower(d.vendor) LIKE '%apple%'
       OR lower(d.hostname) LIKE '%ipad%'
       OR lower(d.display_name) LIKE '%ipad%'
       OR lower(d.hostname) LIKE '%iphone%'
       OR lower(d.display_name) LIKE '%iphone%'
       OR lower(d.hostname) LIKE '%macbook%'
       OR lower(d.display_name) LIKE '%macbook%'
    ORDER BY events_1h DESC, d.last_seen DESC
""").fetchall()

if not rows:
    print("No Apple devices found in the database.")
    sys.exit(0)

def fmt_bytes(n):
    if n is None or n == 0:
        return "0"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

print(f"Found {len(rows)} Apple device(s) — sorted by activity in the last hour:")
print()

for i, r in enumerate(rows, 1):
    name = r["display_name"] or r["hostname"] or "(no name)"
    activity_marker = ""
    if r["events_15min"] and r["events_15min"] > 0:
        activity_marker = "  ← ACTIVE NOW"
    elif r["events_1h"] and r["events_1h"] > 0:
        activity_marker = "  ← active in last hour"

    print(f"  [{i}] {name}{activity_marker}")
    print(f"      mac:           {r['mac_address']}")
    print(f"      vendor:        {r['vendor'] or '(unknown)'}")
    print(f"      last_seen:     {r['last_seen']}")
    print(f"      events 1h:     {r['events_1h']}  (15min: {r['events_15min']})")
    print(f"      bytes 1h:      {fmt_bytes(r['bytes_1h'])}")
    print(f"      ips:           {r['ips'] or '(none)'}")
    print()

# Quick guidance footer
active_now = [r for r in rows if r["events_15min"] and r["events_15min"] > 0]
if active_now:
    print(f"→ {len(active_now)} device(s) had detection events in the last 15 min.")
    print("  If you just played a game, the device you used should be among these.")
    print("  Re-run check_hayday_real_traffic.sh against that device's current IP.")
else:
    print("→ No Apple device had any detection events in the last 15 min.")
    print("  Possible reasons:")
    print("    - The iPad's traffic is bypassing the bridge entirely")
    print("    - The iPad's MAC is not yet known to AI-Radar (recently joined)")
    print("    - All recent traffic is going to unlabelled destinations")
    print("      (run a geo_conversations query for the suspect MAC to see raw bytes)")

conn.close()
PY
