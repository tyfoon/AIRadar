#!/usr/bin/env bash
# check_ndpi.sh — Debug nDPI tailer pipeline
# Usage: sudo ./check_ndpi.sh

CONTAINER="${1:-airadar-app}"
CSV="/app/data/ndpi_flows.csv"

echo "=== nDPI Status ==="
echo ""

# Check process
echo "--- Process ---"
sudo docker exec "$CONTAINER" ps aux 2>/dev/null | grep -E "ndpiReader|ndpi" | grep -v grep
echo ""

# Check CSV size
echo "--- CSV file ---"
sudo docker exec "$CONTAINER" wc -l "$CSV" 2>/dev/null || echo "CSV not found"
echo ""

# Check tailer logs
echo "--- Tailer logs ---"
sudo docker logs "$CONTAINER" 2>&1 | grep "\[ndpi\]" | tail -10
echo ""

# Analyze CSV content (runs in fresh process — no runtime state)
echo "--- CSV protocol analysis ---"
sudo docker exec "$CONTAINER" python3 -c "
import sys; sys.path.insert(0, '/app')
from ndpi_tailer import _normalize_ndpi_proto, NDPI_SERVICE_MAP, _is_local_ip

with open('$CSV') as f:
    header = f.readline().strip().lstrip('#').split('|')
    pi = header.index('ndpi_proto')
    si = header.index('src_ip')
    di = header.index('dst_ip')

    total = 0; mappable = 0; local_ok = 0
    skipped_generic = 0; skipped_no_map = 0
    both_local = 0; both_remote = 0
    by_svc = {}

    for line in f:
        parts = line.strip().split('|')
        if len(parts) <= pi: continue
        total += 1
        n = _normalize_ndpi_proto(parts[pi])
        if n is None:
            skipped_generic += 1
            continue
        if n not in NDPI_SERVICE_MAP:
            skipped_no_map += 1
            continue
        mappable += 1
        src, dst = parts[si], parts[di]
        sl, dl = _is_local_ip(src), _is_local_ip(dst)
        if sl and dl:
            both_local += 1
        elif not sl and not dl:
            both_remote += 1
        else:
            local_ok += 1
            svc = NDPI_SERVICE_MAP[n][0]
            by_svc[svc] = by_svc.get(svc, 0) + 1

print(f'Total flows:         {total}')
print(f'Skipped (generic):   {skipped_generic}')
print(f'Skipped (no map):    {skipped_no_map}')
print(f'Mappable:            {mappable}')
print(f'  Both local:        {both_local}')
print(f'  Both remote:       {both_remote}')
print(f'  Valid local/remote: {local_ok}  ← these populate _ndpi_ip_cache')
print()
print('Services detected by nDPI:')
for svc, cnt in sorted(by_svc.items(), key=lambda x: -x[1]):
    print(f'  {svc:20s}  {cnt:4d} flows')
print()
print('NOTE: 0 labeled in logs is expected when SNI/DNS was faster.')
print('The value is in _ndpi_ip_cache → used by geo_conversations cascade.')
"
