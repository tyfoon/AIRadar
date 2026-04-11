#!/usr/bin/env bash
#
# check_device_activity.sh
#
# Diagnose why Daily usage shows nothing (or very little) for a specific
# device. Walks the same data path that /api/devices/{mac}/activity uses
# and prints the count at every step so you can see EXACTLY where the
# events are getting filtered out.
#
# Usage:
#   sudo ./check_device_activity.sh 192.168.1.122
#   sudo ./check_device_activity.sh aa:bb:cc:dd:ee:ff
#
# It will:
#   1. Resolve IP→MAC (or use the MAC directly)
#   2. Show all IPs the device has used recently (device_ips)
#   3. Count detection_events for those IPs in the last 24h, broken down
#      by detection_type AND by category
#   4. Re-run the activity sessionization SQL with the SAME thresholds
#      the API uses, and report how many sessions survive each filter
#   5. Print the actual /api/devices/{mac}/activity payload for today

set -u

if [ $# -lt 1 ]; then
    echo "usage: $0 <ip-or-mac>"
    exit 2
fi

CONTAINER="airadar-app"
DB="/app/data/airadar.db"
ARG="$1"

sudo docker compose exec -T "$CONTAINER" python3 - "$DB" "$ARG" <<'PY'
import sqlite3, sys, os, json, urllib.request

db_path = sys.argv[1]
arg     = sys.argv[2]

if not os.path.exists(db_path):
    print(f"!! DB not found at {db_path}")
    sys.exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

def section(t):
    print()
    print(f"-- {t}")

def show(rows, headers):
    if not rows:
        print("  (no rows)")
        return
    widths = [max(len(h), max(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(r[i]) for i in range(len(headers))]))

# ---------------------------------------------------------------------
# 1. Resolve to a MAC + device info
# ---------------------------------------------------------------------
section("1. device lookup")
if ":" in arg and len(arg) >= 12:
    # looks like a MAC
    mac = arg.lower()
    c.execute("SELECT mac_address, display_name, hostname, vendor, last_seen FROM devices WHERE lower(mac_address)=?", (mac,))
else:
    # treat as IP — find the most-recent MAC that used it
    c.execute("""
        SELECT d.mac_address, d.display_name, d.hostname, d.vendor, d.last_seen
        FROM device_ips di
        JOIN devices d ON d.mac_address = di.mac_address
        WHERE di.ip = ?
        ORDER BY di.last_seen DESC
        LIMIT 1
    """, (arg,))
row = c.fetchone()
if row is None:
    print(f"  !! no device found for {arg}")
    sys.exit(1)
mac = row["mac_address"]
print(f"  mac:          {mac}")
print(f"  display_name: {row['display_name']}")
print(f"  hostname:     {row['hostname']}")
print(f"  vendor:       {row['vendor']}")
print(f"  last_seen:    {row['last_seen']}")

# ---------------------------------------------------------------------
# 2. All IPs this device has used (device_ips)
# ---------------------------------------------------------------------
section("2. device_ips for this MAC")
c.execute("SELECT ip, first_seen, last_seen FROM device_ips WHERE mac_address=? ORDER BY last_seen DESC", (mac,))
ip_rows = c.fetchall()
show(ip_rows, ["ip", "first_seen", "last_seen"])
ips = [r["ip"] for r in ip_rows]
if not ips:
    print("  !! NO IPs known for this MAC — Daily usage cannot show anything")
    sys.exit(0)

# ---------------------------------------------------------------------
# 3. detection_events for those IPs in the last 24h, by type + category
# ---------------------------------------------------------------------
section("3. detection_events last 24h, by detection_type")
qmarks = ",".join("?" * len(ips))
c.execute(f"""
    SELECT detection_type, COUNT(*) AS n
    FROM detection_events
    WHERE source_ip IN ({qmarks})
      AND timestamp > datetime('now','-24 hours')
    GROUP BY detection_type
    ORDER BY n DESC
""", ips)
show(c.fetchall(), ["detection_type", "n"])

section("3b. detection_events last 24h, by category")
c.execute(f"""
    SELECT category, COUNT(*) AS n
    FROM detection_events
    WHERE source_ip IN ({qmarks})
      AND timestamp > datetime('now','-24 hours')
    GROUP BY category
    ORDER BY n DESC
""", ips)
show(c.fetchall(), ["category", "n"])

section("3c. detection_events last 24h, by (category, ai_service) — top 20")
c.execute(f"""
    SELECT category, ai_service, COUNT(*) AS n
    FROM detection_events
    WHERE source_ip IN ({qmarks})
      AND timestamp > datetime('now','-24 hours')
    GROUP BY category, ai_service
    ORDER BY n DESC
    LIMIT 20
""", ips)
show(c.fetchall(), ["category", "ai_service", "n"])

# ---------------------------------------------------------------------
# 4. Simulate the activity sessionizer for today, in the same activity
#    categories the API uses, and report how many sessions survive.
# ---------------------------------------------------------------------
ACTIVITY_CATEGORIES = ("social", "streaming", "gaming", "ai", "shopping")
GAP_SECONDS         = 600
MIN_EVENTS          = 3
MIN_SECONDS         = 60

section("4. sessionizer simulation (TODAY, Europe/Amsterdam → UTC window)")
print(f"  filter:   category IN {ACTIVITY_CATEGORIES}")
print(f"  gap:      {GAP_SECONDS}s")
print(f"  min:      {MIN_EVENTS} events AND {MIN_SECONDS}s duration")

# Compute today's UTC window like the API does
# (close enough — we're not handling DST edge cases in a diagnostic)
import datetime as dt
now_utc = dt.datetime.now(dt.timezone.utc)
# Approximate Amsterdam offset (CEST = +02:00 in spring/summer)
amsterdam = dt.timezone(dt.timedelta(hours=2))
today_local_start = now_utc.astimezone(amsterdam).replace(hour=0, minute=0, second=0, microsecond=0)
day_start = today_local_start.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
day_end   = (today_local_start + dt.timedelta(days=1)).astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
print(f"  window:   {day_start}  →  {day_end}  (UTC)")

# Step 4a: raw events that would enter the sessionizer
cat_qmarks = ",".join("?" * len(ACTIVITY_CATEGORIES))
c.execute(f"""
    SELECT COUNT(*)
    FROM detection_events e
    JOIN device_ips di ON di.ip = e.source_ip
    WHERE di.mac_address = ?
      AND e.timestamp >= ?
      AND e.timestamp <  ?
      AND e.category IN ({cat_qmarks})
""", (mac, day_start, day_end, *ACTIVITY_CATEGORIES))
raw_events = c.fetchone()[0]
print(f"  step A — raw events into sessionizer:        {raw_events}")

if raw_events == 0:
    print("  →→ this is the problem: ZERO events in user-facing categories")
    print("     for this device today. Either no traffic yet, or all of it")
    print("     is in 'cloud' / 'tracking' / 'other' which Daily usage skips.")

# Step 4b: run the actual sessionizer SQL
sql = f"""
WITH events AS (
  SELECT e.timestamp, e.ai_service, e.category, e.bytes_transferred
  FROM detection_events e
  JOIN device_ips di ON di.ip = e.source_ip
  WHERE di.mac_address = ?
    AND e.timestamp >= ?
    AND e.timestamp <  ?
    AND e.category IN ({cat_qmarks})
),
marked AS (
  SELECT *,
    CASE WHEN LAG(timestamp) OVER (PARTITION BY ai_service ORDER BY timestamp) IS NULL
              OR (julianday(timestamp) -
                  julianday(LAG(timestamp) OVER (PARTITION BY ai_service ORDER BY timestamp))
                 ) * 86400 > ?
         THEN 1 ELSE 0 END AS is_new
  FROM events
),
sessioned AS (
  SELECT *,
    SUM(is_new) OVER (PARTITION BY ai_service ORDER BY timestamp) AS sid
  FROM marked
)
SELECT ai_service, category, COUNT(*) AS event_count,
       (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 AS duration_s
FROM sessioned
GROUP BY ai_service, sid
ORDER BY event_count DESC
"""
c.execute(sql, (mac, day_start, day_end, *ACTIVITY_CATEGORIES, GAP_SECONDS))
candidate_sessions = c.fetchall()
print(f"  step B — candidate sessions (any size):      {len(candidate_sessions)}")

surviving = [s for s in candidate_sessions if s["event_count"] >= MIN_EVENTS and (s["duration_s"] or 0) >= MIN_SECONDS]
print(f"  step C — sessions passing min-events+min-secs: {len(surviving)}  ← what Daily usage shows")

if candidate_sessions and not surviving:
    print()
    print("  →→ Sessions exist but ALL are filtered out by the noise threshold.")
    print("     Top candidates that *almost* qualified:")
    show(candidate_sessions[:10],
         ["ai_service", "category", "event_count", "duration_s"])
    print()
    print("  Possible fixes:")
    print("    - lower ACTIVITY_SESSION_MIN_EVENTS (currently 3) — risk: noise")
    print("    - lower ACTIVITY_SESSION_MIN_SECONDS (currently 60)")
    print("    - feed the sessionizer additional events from geo_conversations")
    print("      (continuous byte-counter rows, not just hello/correlated events)")

# ---------------------------------------------------------------------
# 5. Actual API response for sanity
# ---------------------------------------------------------------------
section("5. live /api/devices/{mac}/activity?date=today")
try:
    today_iso = today_local_start.date().isoformat()
    url = f"http://localhost:8000/api/devices/{mac}/activity?date={today_iso}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())
    print(f"  sessions:            {len(data.get('sessions', []))}")
    print(f"  grand_total_seconds: {data.get('grand_total_seconds', 0)}")
    print(f"  totals_by_category:  {data.get('totals_by_category', [])}")
    print(f"  totals_by_service (top 5):")
    for s in (data.get("totals_by_service", []) or [])[:5]:
        print(f"    {s.get('service'):<20}  {s.get('duration_seconds')}s  {s.get('events')} events")
except Exception as exc:
    print(f"  !! API call failed: {exc}")

conn.close()
PY
