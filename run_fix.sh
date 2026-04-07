#!/bin/bash
sudo docker compose exec airadar-app python -c "
import sqlite3
from collections import defaultdict

def n(m):
    parts = m.lower().replace('-', ':').split(':')
    return ':'.join(format(int(p, 16), '02x') for p in parts)

conn = sqlite3.connect('/app/data/airadar.db', timeout=60)
conn.execute('PRAGMA busy_timeout=60000')
conn.execute('PRAGMA foreign_keys=OFF')
c = conn.cursor()
c.execute('SELECT mac_address,hostname,vendor,display_name,first_seen,last_seen FROM devices')
g = defaultdict(list)
for r in c.fetchall():
    if r[0] and not r[0].startswith('unknown_'):
        g[n(r[0])].append(r)

def move_mac(old, new):
    # All tables that might have unique constraints involving mac: just delete old
    for t in ['device_baselines', 'tls_fingerprints', 'geo_conversations', 'device_group_members', 'service_policies']:
        c.execute(f'DELETE FROM {t} WHERE mac_address=?', (old,))
    # device_ips: drop conflicting IPs, move rest
    c.execute('DELETE FROM device_ips WHERE mac_address=? AND ip IN (SELECT ip FROM device_ips WHERE mac_address=?)', (old, new))
    c.execute('UPDATE device_ips SET mac_address=? WHERE mac_address=?', (new, old))
    # alert_exceptions: safe to update
    c.execute('UPDATE alert_exceptions SET mac_address=? WHERE mac_address=?', (new, old))
    c.execute('UPDATE alert_exceptions SET destination=? WHERE destination=?', (new, old))

f = m = 0
for nm, es in g.items():
    if len(es) == 1 and es[0][0] == nm:
        continue
    es.sort(key=lambda e: (e[1] is not None, e[3] is not None, e[2] is not None), reverse=True)
    k = es[0][0]
    ef = min(e[4] for e in es)
    ll = max(e[5] for e in es if e[5])
    for e in es[1:]:
        move_mac(e[0], k)
        c.execute('DELETE FROM devices WHERE mac_address=?', (e[0],))
        m += 1
    if k != nm:
        move_mac(k, nm)
        c.execute('UPDATE devices SET mac_address=?,first_seen=?,last_seen=? WHERE mac_address=?', (nm, ef, ll, k))
    else:
        c.execute('UPDATE devices SET first_seen=?,last_seen=? WHERE mac_address=?', (ef, ll, nm))
    f += 1
conn.commit()
print(f'Fixed {f} groups, merged {m} dupes')
c.execute('SELECT COUNT(*) FROM devices')
print(f'Total devices now: {c.fetchone()[0]}')
conn.close()
"
