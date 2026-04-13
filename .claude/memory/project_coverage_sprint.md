---
name: Coverage sprint status (2026-04-12)
description: Fix & Fallback sprint to raise geo_conversations coverage from 27% to 80%+. Steps 1-2 shipped, 3-4 pending, measuring results.
type: project
---

# Coverage Fix & Fallback Sprint

**Why:** Original plan predicted 80% coverage after Day 3, but actual geo_conversations coverage was only 27%. Root causes: (1) DNS cache TTL too short (5 min) for long-lived connections, (2) geo_conversations bypassed the labeler pipeline entirely.

## Sprint steps

1. ✅ **DNS cache TTL → 12 hours** (commit `cf89a3c`)
   - `dns_cache.py` DEFAULT_MIN_TTL_SECONDS: 300 → 43200
   - Fixes: Netflix streams, video calls, etc. losing DNS correlation at conn.log teardown

2. ✅ **Wire geo_conversations through DNS fallback** (commit `cf89a3c`)
   - In `tail_conn_log`, added `_label_flow_via_dns()` call before `_record_geo_conversation()`
   - When `_known_ips` has no label, DNS cache is tried as fallback
   - On hit, also populates `_known_ips` for future flows

3. ⬜ **PTR-based labeling** (category only, not fake services)
   - Use PTR records from `ip_metadata` to assign category
   - e.g. `.1e100.net` → category=cloud, `.nflxvideo.net` → category=streaming

4. ⬜ **ASN-based labeling** (category only)
   - AS2906 Netflix → streaming, AS15169 Google → cloud, etc.

5. ⬜ **Measure and decide** — if coverage >70% after steps 1-4, LLM classifier (Day 4-5) is deprioritized. If <50%, pivot to nDPI sidecar.

## Results (2026-04-12)
- **1h after DNS+geo fix: 59.6% conversations, 81.5% bytes**
- **After PTR/ASN fallbacks shipped: pending 24h measurement (run ./check_coverage.sh 24 on 2026-04-13)**
- Netflix, YouTube, Disney+, nu.nl all visible
- Remaining unlabeled = CDN traffic (Google LLC, Amazon, Cloudflare, Akamai)

## Steps 3-4 shipped (2026-04-12 evening, commit ecbfb96)
- PTR patterns: googlevideo.com→youtube, nflxvideo.net→netflix, fbcdn.net→facebook, etc.
- ASN→category: 15 major ASNs mapped (Netflix→streaming, Google→cloud, Facebook→social)
- In-memory ip_meta_cache synced from ip_metadata every 5 min
- Pipeline order: _known_ips → DNS correlation → PTR/ASN → "unknown"
- Event loop breathing (sleep(0) every 1000 lines) + try/except in all 7 tail loops

## Also shipped today (non-sprint)
- Day 2.5: apple_tv seed fix (915 → 1 entry)
- Day 3: JA4 community DB sync
- Sankey chart refactor (device→category, all categories, sqrt scaling, controls)
- Activity timeline per-service colors
- Timezone harmonization (UTC internal, browser local in UI) — caused several breakages, all fixed
- Per-category MIN_BYTES filter for Daily Usage (streaming=5MB, social=1KB)
- Country drawer IPs clickable for reputation check
- `check_coverage.sh` diagnostic script
- DoT (port 853) redirect added to DNS intercept service
- UDM Pro API connected for validation (but NOT for production use)

## Timezone lessons learned
The `datetime.utcnow()` → `datetime.now(timezone.utc)` migration caused cascading breakages because:
1. SQLite stores naive datetimes — aware datetimes crash on write
2. Pydantic PlainSerializer converted datetimes to strings, breaking model_dump() → SQLAlchemy
3. Comparing aware `now` with naive DB values crashes

**Final solution:** All internal datetimes are **naive UTC** (`.replace(tzinfo=None)`). The 'Z' suffix for API output is added via `UTCJSONResponse` (custom FastAPI JSON encoder), not via Pydantic serializers. Never use `UtcDatetime` or `PlainSerializer` for datetime fields.
