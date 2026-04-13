#!/usr/bin/env bash
# check_coverage.sh — Quick coverage check for geo_conversations
# Usage: ./check_coverage.sh [hours]   (default: 2)

HOURS="${1:-2}"
DB="/home/goswijn/AIradar/data/airadar.db"

python3 -c "
import sqlite3
conn = sqlite3.connect('$DB')
h = $HOURS

print(f'=== GEO_CONVERSATIONS COVERAGE (last {h}h) ===')
print()

# Exclude inbound scans (resp_bytes=0, direction=inbound) — these are
# half-open connections with inflated orig_bytes that skew byte coverage.
REAL_TRAFFIC = 'NOT (direction = \"inbound\" AND resp_bytes = 0)'

r = conn.execute('''
    SELECT COUNT(*) as total,
           SUM(CASE WHEN ai_service NOT IN ('unknown','') AND ai_service IS NOT NULL THEN 1 ELSE 0 END) as labeled,
           SUM(bytes_transferred) as total_bytes,
           SUM(CASE WHEN ai_service NOT IN ('unknown','') AND ai_service IS NOT NULL THEN bytes_transferred ELSE 0 END) as labeled_bytes
    FROM geo_conversations
    WHERE first_seen > datetime(\"now\", \"-{} hours\")
    AND {}
'''.format(h, REAL_TRAFFIC)).fetchone()

if not r[0]:
    print('No data yet.')
    exit()

total, labeled, total_b, labeled_b = r
pct = labeled/total*100 if total else 0
pct_b = labeled_b/total_b*100 if total_b else 0
print(f'Conversations:  {labeled:,} / {total:,} labeled ({pct:.1f}%)')
print(f'Bytes:          {labeled_b:,.0f} / {total_b:,.0f} labeled ({pct_b:.1f}%)')
print()

print(f'=== BY LABELER SOURCE (last {h}h) ===')
rows = conn.execute('''
    SELECT labeler, COUNT(*) as wins
    FROM label_attributions
    WHERE created_at > datetime(\"now\", \"-{} hours\")
    AND is_winner = 1
    GROUP BY labeler ORDER BY wins DESC
'''.format(h)).fetchall()
if rows:
    for r in rows:
        print(f'  {r[0]:25s} {r[1]:6,} wins')
else:
    print('  (no attributions yet)')
print()

print(f'=== TOP 10 LABELED SERVICES (last {h}h) ===')
rows = conn.execute('''
    SELECT ai_service, COUNT(*) as c, SUM(bytes_transferred) as b
    FROM geo_conversations
    WHERE first_seen > datetime(\"now\", \"-{} hours\")
    AND ai_service NOT IN (\"unknown\",\"\") AND ai_service IS NOT NULL
    GROUP BY ai_service ORDER BY b DESC LIMIT 10
'''.format(h)).fetchall()
for r in rows:
    print(f'  {r[0]:30s} {r[1]:5,} convs  {r[2]:>13,.0f} bytes')
print()

print(f'=== TOP 10 UNLABELED BY ASN (last {h}h) ===')
rows = conn.execute('''
    SELECT COALESCE(m.asn_org, \"(no ASN)\") as org,
           COUNT(*) as convs, SUM(g.bytes_transferred) as b,
           COUNT(DISTINCT g.mac_address) as devs
    FROM geo_conversations g
    LEFT JOIN ip_metadata m ON m.ip = g.resp_ip
    WHERE g.first_seen > datetime(\"now\", \"-{} hours\")
    AND (g.ai_service IS NULL OR g.ai_service IN (\"unknown\",\"\"))
    AND {}
    GROUP BY org ORDER BY b DESC LIMIT 10
'''.format(h, REAL_TRAFFIC)).fetchall()
for r in rows:
    print(f'  {r[0]:40s} {r[1]:5,} convs  {r[2]:>13,.0f} bytes  {r[3]:2d} devs')

conn.close()
"
