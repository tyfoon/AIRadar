#!/usr/bin/env bash
#
# check_dns_correlation.sh
#
# Day-1 + Day-1.5 + Day-2 smoke test for the labeler pipeline. Verifies:
#   1. The airadar-app container is up.
#   2. The zeek tailer started tail_dns_log + persister + warm-up + the
#      new tail_quic_log without crashing on import or DB access.
#   3. detection_events is receiving rows in the last few minutes
#      (any rows — proves the tailer pipeline is alive).
#   4. dns_correlated detections are firing (Day 1 fallback path).
#   5. label_attributions has rows from each labeler.
#   6. Recent dns_correlated samples for visual sanity check.
#   7. dns_observations table is being filled by flush_dns_observations.
#   8. The cold-start warm-up actually restored entries on this rebuild.
#   9. quic_hello detections are firing (Day 2 direct QUIC SNI path).
#  10. Recent quic_hello samples.
#
# Run with: sudo ./check_dns_correlation.sh
#
# All queries hit the in-container SQLite at /app/data/airadar.db so we
# don't have to worry about host-side perms.

set -u

CONTAINER="airadar-app"
DB="/app/data/airadar.db"

echo "==> 1. container status"
sudo docker compose ps "$CONTAINER" 2>&1 | tail -n +1
echo

echo "==> 2. tailer banner, warm-up & any tracebacks (last 30 min)"
sudo docker compose logs --since=30m "$CONTAINER" 2>&1 \
  | grep -E "AI-Radar Zeek Tailer|DNS-IP correlation|QUIC SNI labeler|Tailing dns.log|Tailing quic.log|DNS observation persister|DNS cache warm-up|\[dns\] cache|\[dns-persist\]|\[dns-warmup\]|quic.log read error|Traceback|ImportError|ModuleNotFoundError" \
  | tail -30
echo

echo "==> DB queries (via python3 sqlite3 — no sqlite cli in container)"
sudo docker compose exec -T "$CONTAINER" python3 - "$DB" <<'PY'
import sqlite3, sys, os

db_path = sys.argv[1]
if not os.path.exists(db_path):
    print(f"!! DB not found at {db_path}")
    sys.exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

def section(title):
    print()
    print(f"-- {title}")

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

# 3. detection_events per type (last 5 min)
section("3. detection_events in the last 5 minutes (by detection_type)")
c.execute("""
    SELECT detection_type, COUNT(*) AS n
    FROM detection_events
    WHERE timestamp > datetime('now','-5 minutes')
    GROUP BY detection_type
    ORDER BY n DESC
""")
show(c.fetchall(), ["detection_type", "n"])

# 4. dns_correlated count (lifetime + last 5 min)
section("4. dns_correlated event count")
c.execute("SELECT COUNT(*) FROM detection_events WHERE detection_type='dns_correlated'")
lifetime = c.fetchone()[0]
c.execute("""
    SELECT COUNT(*) FROM detection_events
    WHERE detection_type='dns_correlated'
      AND timestamp > datetime('now','-5 minutes')
""")
last5 = c.fetchone()[0]
print(f"  lifetime: {lifetime}    last_5min: {last5}")

# 5. label_attributions per labeler (last 5 min)
section("5. label_attributions per labeler (last 5 min)")
try:
    c.execute("""
        SELECT labeler, COUNT(*) AS n
        FROM label_attributions
        WHERE created_at > datetime('now','-5 minutes')
        GROUP BY labeler
        ORDER BY n DESC
    """)
    show(c.fetchall(), ["labeler", "n"])
except sqlite3.OperationalError as e:
    print(f"  !! {e}  (table may not exist yet — Day-0 migration required)")

# 6. recent dns_correlated samples
section("6. recent dns_correlated samples (last 10)")
c.execute("""
    SELECT substr(timestamp,12,8) AS ts, ai_service, source_ip, bytes_transferred
    FROM detection_events
    WHERE detection_type='dns_correlated'
    ORDER BY id DESC
    LIMIT 10
""")
show(c.fetchall(), ["ts", "ai_service", "source_ip", "bytes"])

# 7. dns_observations persistence (Day 1.5)
section("7. dns_observations persistence (Day 1.5)")
try:
    c.execute("SELECT COUNT(*) FROM dns_observations")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM dns_observations WHERE observed_at > datetime('now','-5 minutes')")
    last5 = c.fetchone()[0]
    c.execute("SELECT MIN(observed_at), MAX(observed_at) FROM dns_observations")
    earliest, latest = c.fetchone()
    print(f"  total rows:      {total}")
    print(f"  added last 5min: {last5}")
    print(f"  earliest:        {earliest}")
    print(f"  latest:          {latest}")
    if total == 0:
        print("  !! no rows yet — flush_dns_observations may not have fired (interval is 30s)")
    elif last5 == 0:
        print("  !! no recent rows — persister may have stopped, check logs")
except sqlite3.OperationalError as e:
    print(f"  !! {e}  (dns_observations table missing — Day-0 migration required)")

# 8. warm-up evidence (Day 1.5) — was the cache primed before tail started?
section("8. warm-up evidence (Day 1.5)")
print("  Look at section 2 for a 'DNS cache warm-up: N entries restored' line.")
print("  N > 0 on a non-first rebuild means cold-start gap is closed.")
print("  N = 0 on the very first deploy after this change is expected")
print("  (the table was empty before flush_dns_observations existed).")

# 9. quic_hello detections (Day 2)
section("9. quic_hello event count (Day 2)")
c.execute("SELECT COUNT(*) FROM detection_events WHERE detection_type='quic_hello'")
qlife = c.fetchone()[0]
c.execute("""
    SELECT COUNT(*) FROM detection_events
    WHERE detection_type='quic_hello'
      AND timestamp > datetime('now','-5 minutes')
""")
qlast5 = c.fetchone()[0]
print(f"  lifetime: {qlife}    last_5min: {qlast5}")
try:
    c.execute("""
        SELECT COUNT(*) FROM label_attributions
        WHERE labeler='quic_sni_direct'
          AND created_at > datetime('now','-5 minutes')
    """)
    qattr = c.fetchone()[0]
    print(f"  label_attributions (quic_sni_direct, last 5min): {qattr}")
except sqlite3.OperationalError:
    pass
if qlife == 0:
    print("  !! no quic_hello events ever — check Zeek quic.log + tail banner")

# 10. recent quic_hello samples
section("10. recent quic_hello samples (last 10)")
c.execute("""
    SELECT substr(timestamp,12,8) AS ts, ai_service, source_ip, bytes_transferred
    FROM detection_events
    WHERE detection_type='quic_hello'
    ORDER BY id DESC
    LIMIT 10
""")
show(c.fetchall(), ["ts", "ai_service", "source_ip", "bytes"])

conn.close()
PY
echo

echo "==> done"
