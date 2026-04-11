#!/usr/bin/env bash
#
# inspect_appletv_event.sh
#
# Finds the exact detection_events rows with ai_service='apple_tv' for
# a given device, and joins them with label_attributions to get the
# full rationale string which encodes WHY this label was chosen.
#
# For dns_correlated events the rationale is literally:
#     "DNS resolved {hostname} → {resp_ip} via {mac_last_8}"
# which tells us which hostname matched apple_tv and which IP the
# laptop was talking to at the time — enough to pinpoint the
# ambiguous DNS entry.
#
# For sni_hello / quic_hello events the rationale may be empty (the
# legacy path didn't write attributions) or may contain the SNI.
#
# Usage:  sudo ./inspect_appletv_event.sh 192.168.1.251

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

# Every apple_tv detection_event for this device in the last 24h,
# plus any matching label_attributions rows (LEFT JOIN so legacy
# events without attribution still show up).
print("=== apple_tv detection_events for this device (last 24h) ===")
c.execute("""
    SELECT e.id, e.timestamp, e.detection_type, e.source_ip,
           e.bytes_transferred, e.category,
           la.labeler, la.rationale, la.effective_score
    FROM detection_events e
    JOIN device_ips di ON di.ip = e.source_ip
    LEFT JOIN label_attributions la ON la.detection_event_id = e.id
    WHERE di.mac_address = ?
      AND e.ai_service = 'apple_tv'
      AND e.timestamp > datetime('now','-24 hours')
    ORDER BY e.timestamp DESC
""", (mac,))
rows = c.fetchall()

if not rows:
    print("  (no rows — apple_tv events must be older than 24h)")
    sys.exit(0)

print(f"Found {len(rows)} apple_tv detection_event row(s):")
print()
for r in rows:
    print(f"  id={r['id']}  ts={r['timestamp']}  type={r['detection_type']}")
    print(f"    source_ip:  {r['source_ip']}")
    print(f"    bytes:      {r['bytes_transferred']}")
    print(f"    category:   {r['category']}")
    if r['labeler']:
        print(f"    labeler:    {r['labeler']}  score={r['effective_score']}")
        print(f"    rationale:  {r['rationale']}")
    else:
        print("    (no label_attributions row — likely a legacy sni_hello")
        print("     write from before Day 1, no audit trail)")
    print()

conn.close()
PY
