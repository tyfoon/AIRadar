---
name: Labeler coverage roadmap (Day 0–6)
description: 7-day plan to lift AI-Radar service-label coverage from ~30% to ~90% via DNS snooping, QUIC SNI, JA4, and LLM classification. Day 0 through Day 3 shipped. Next: Day 4-5 (LLM classifier), then Day 6 (UI).
type: project
---

# Goal
Raise service-label coverage on detection_events from ~30% (SNI-direct only) to ~90% by chaining 4 fallback labelers, each below the previous one in a deterministic trust hierarchy. Quality is the top priority: a wrong label is worse than a missing one because it poisons sessionization, AI recap, alerts, and the operator's mental model.

**Why:** without this, ~70% of QUIC/ECH traffic shows up as "unknown" in the dashboard and the whole product story (visibility into AI/cloud/tracking on the home network) collapses for any household running modern apps.

**How to apply:** every labeler that proposes a service must go through `labeler.resolve()` with a `LabelProposal`, persist a `LabelAttribution` row, and respect the source-weight × confidence trust math. Never write to `detection_events.ai_service` directly from a probabilistic source.

# Trust hierarchy (canonical, in `labeler.py`)
`SOURCE_WEIGHTS`:
- manual_seed         1.00
- curated_v2fly       0.95
- sni_direct          0.95
- quic_sni_direct     0.90
- adguard_services    0.85
- ja4_community_db    0.80
- dns_correlation     0.75
- llm_inference       0.70
- ip_asn_heuristic    0.50

`effective_score = source_weight × confidence`. `CONFIDENCE_FLOOR = 0.60`. `AGREEMENT_WINDOW = 0.05` (boost).

**Critical: the tier gate (Day 1.5).** `DETERMINISTIC_LABELERS` is a frozenset of {manual_seed, curated_v2fly, sni_direct, quic_sni_direct, adguard_services, ja4_community_db, dns_correlation}. `resolve()` segments proposals: if ANY deterministic proposal exists, only those can win. Probabilistic proposals (llm_inference, ip_asn_heuristic) stay in the audit trail but cannot outscore a deterministic one regardless of nominal confidence. This was the user-approved fix for the "LLM 0.665 beats JA4 0.56" hole.

# Gemini's three required tweaks (all landed in the right place)
1. ✅ **CNAME-aware DNS parsing**: every IP in a Zeek dns.log answers chain maps to the ORIGINAL query, not to intermediate CNAMEs. In `dns_cache.parse_zeek_answers()`, verified by `tests/test_dns_cache.py`.
2. ✅ **OrderedDict LRU cache**: `dns_cache.DnsCache._store` uses `OrderedDict` with `popitem(last=False)`.
3. ⬜ **Privacy filter for LLM batches** (Day 4, not yet implemented): drop `.local`, `.lan`, `.arpa`, `.home.arpa`, raw IPs, and any RFC1918 hostnames BEFORE sending to the LLM. **MUST be in place before first LLM call fires.**

# Roadmap status

## Shipped
- **Day 0** ✅ commit `5e4c0c3` — Schema (4 new tables: `DnsObservation`, `LabelAttribution`, `JA4Signature`, `UnknownObservation`), `labeler.py` with trust hierarchy + `resolve()`, `/api/labeler/stats` endpoint, AdGuard service-map seed (`seed_adguard_services.py`).
- **Day 1** ✅ commit `7906197` — DNS snooping. `dns_cache.py` (LRU+TTL, per-(client_mac, server_ip) scoping, CNAME-aware), `tail_dns_log` in zeek_tailer, `_label_flow_via_dns` fallback in `tail_conn_log`, `/api/ingest` accepts `attribution` payload, `schemas.LabelAttributionCreate`.
- **Day 1.5** ✅ commit `3fba3df` — Trust-math **tier gate** (see above); `DnsObservation` persistence via `flush_dns_observations` every 30 s; warm-up at startup via `warmup_dns_cache_from_db` (honours wire TTL, skips expired rows); `LABELER_DNS_SNOOPING` env-var rollback. Live-verified: 6× more dns_correlated events, 317 dns_observations rows in 4 min, warm-up restored 190 entries on next rebuild.
- **Day 2** ✅ commit `3386e3a` — QUIC SNI tailer. `tail_quic_log()` in `zeek_tailer.py` emits `quic_hello` events with `labeler="quic_sni_direct"` (effective_score 0.90). Zeek's `quic.log` was already enabled on the host, no config change needed. `LABELER_QUIC_TAILER` env-var rollback. Live win: `dns_correlated` dropped from 6→1/5min because the same flows are now caught by the higher-tier QUIC labeler. iCloud/apple_tv/google_drive/reddit/facebook now visible via QUIC Initial SNI.
- **Day 2.1** ✅ commit `a89a329` — UI polish: `_apply_heartbeat_filter` extended to suppress zero-byte `quic_hello` and `dns_correlated` (otherwise the dashboard "real events today" counter floods with QUIC handshake noise); `_eventDescription` in app.js maps `quic_hello → "QUIC connection"` and `dns_correlated → "DNS-correlated"`; `ev.quicConnection` + `ev.dnsCorrelated` i18n keys in EN+NL.
- **Day 2.4** ✅ commit `4605760` — Per-client scoping for `_known_ips`. Changed key from `resp_ip` to `(client_mac, resp_ip)` across 4 write sites (`tail_ssl_log`, `tail_quic_log`, 2 dns_correlated paths in `tail_conn_log`) and 5 read sites (`cleanup_memory_caches`, `_record_geo_conversation`, stale eviction + presence check + primary read in `tail_conn_log`). Writers skip when client MAC is None. Pattern mirrors `dns_cache.DnsCache`. Live-verified: iPad Annie still shows Hay Day (regression check), laptop still gets apple_tv labels but all via the laptop's OWN DNS/SNI — no cross-device leakage. Revealed Day 2.5 seed-bug as a side effect.
- **Day 2.2/2.3** ✅ commit `7484a42` — Daily usage sessionizer overhaul. `news` added to `ACTIVITY_CATEGORIES`. Activity SQL in `/api/devices/{mac}/activity` is now a 3-way `UNION ALL`:
  1. `detection_events JOIN device_ips` (original)
  2. `geo_conversations` virtual start events (one per row at `first_seen`, clamped to `day_start`)
  3. `geo_conversations` virtual end events (one per row at `last_seen`, clamped to `day_end`)
  Bytes split 50/50 across 2a and 2b so `SUM(bytes_transferred)` matches totals. Service→category derived via a `service_cats` CTE (`SELECT service_name, MIN(category) FROM known_domains GROUP BY service_name`) because `geo_conversations` lacks a category column. `ACTIVITY_GEO_MIN_BYTES = 1024` suppresses trivial bursts. **The reason for Day 2.3**: SNI dedup (`SNI_DEDUP_SECONDS = 30min` on `(service, src_ip)`) starves mobile games of detection_events — a 17-min Hay Day session produced only 2 `supercell` events, killed by `MIN_EVENTS = 3`. With geo_conversations-as-second-source, the same session contributes ~12 virtual events across 6 Supercell IPs and passes the filter. Live-verified on iPad Annie.

- **Day 2.5** ✅ commits `5b6394e` + `e11d0a9` — Purge mislabeled apple_tv seed. Root cause: `service_updater.py` mapped v2fly's `apple` brand-protection list (915 domains — NTP, MDM, App Store, CDN, typosquats, country sites) wholesale to `apple_tv`. Fix: removed the v2fly/apple mapping; added 23 DOMAIN_MAP entries for proper Apple sub-services (`app_store`, `apple_music`, `siri`, `icloud`, `apple` generic); DB migration deletes 914 v2fly apple_tv seeds + all mislabeled detection_events, geo_conversations, and label_attributions. Only `tv.apple.com` (seed) remains as apple_tv. Live-verified: icloud/apple/app_store labels flowing within minutes of rebuild.

- **Day 3** ✅ commit `5b5a875` — JA4 community DB sync + TLS fingerprint labeling. New `ja4_db_sync.py` fetches FoxIO JA4+ database (69K records, ~2.7K with app names), upserts into `ja4_signatures`. Generic browsers/libraries dampened to 0.40 confidence, app-specific get 0.80. `needs_sync()` checks `updated_at` column (issue #6 fix — no more `asyncio.sleep(7*86400)` across restarts). In-memory `_ja4_lookup` map synced from DB every 5 min. ssl.log handler falls back to JA4 when SNI matching fails (non-generic only). `LABELER_JA4_MATCH` env var for rollback.

## Next up
- **Day 4–5** ⬜ LLM classifier — `ja4_db_sync.py` pulls FoxIO `ja4plus-mapping.csv` weekly into `ja4_signatures`; hookpoint in TLS-fingerprint ingest; dampen generic Cronet/OkHttp labels to halve confidence. Labeler key: `ja4_community_db`, weight 0.80. **Watch out for open issue #6** (weekly sync via `asyncio.sleep(7*86400)` is a no-op across container restarts — persist `last_sync_at` and check on startup instead).
- **Day 4–5** ⬜ LLM classifier — `unknown_classifier.py` background loop, batches 50 unknown SNIs via PydanticAI Haiku 4.5, persists ≥0.70 confidence to `KnownDomain`. **Privacy filter FIRST** (see Gemini tweak #3). Budget cap as dollars/day, not classifications/day (see open issue #4). **Drop the "≥2 devices" UnknownObservation filter** (open issue #5) — it excludes the long tail this is meant to catch.
- **Day 6** ⬜ Observability — `/api/labeler/conflicts`, `/api/labeler/recent-classifications`, Coverage UI widget on dashboard, attribution-on-hover info-icon in Activity tab ("via dns_correlation, 0.75 confidence").
- **Day 7** ⬜ Buffer + manual top-label verification.

# Open issues still unaddressed (filtered)
Keeping only the ones that are NOT yet resolved in shipped commits:

2. **Dispute window 0.05 too narrow** vs score spacing → boost path swallows everything, dispute path never fires. Widen dispute or narrow boost. Applies to `labeler.resolve()`. Day 6 observability work might surface this, or we fix preemptively.
4. **LLM cost math**: $0.50/day at Haiku 4.5 pricing covers ~2500 classifications, not 5000. Cap on dollars/day, not classifications/day. Day 4.
5. **`UnknownObservation` "≥2 devices" filter** systematically excludes the long tail. Day 4 must drop this or use `hit_count` instead.
6. **Weekly JA4 sync via `asyncio.sleep(7*86400)`** is a no-op across container restarts. Day 3.
7. **Coverage targets (65/75/80/88)** are unanchored — no per-step traffic-share math. Day 0/Day 6.
8. **`is_supercell_game: bool` in `DomainClassification`** is a vendor carve-out — generalize to `vendor_family: Optional[str]` before Day 4 LLM schema ships.

**Resolved in Day 1.5**: issue #1 (trust-math hole — fixed via `DETERMINISTIC_LABELERS` tier gate), issue #3 (DNS cache restart gap — fixed via persistence + warm-up).

# Devices reference (critical context — don't re-diagnose these)
Learned during Day 2.2/2.3 debugging. If we lose session context, these MAC↔IP↔role mappings save hours of re-investigation:

- **iPad Annie** = `4a:65:f5:eb:a3:4d` = `192.168.1.205` = **the Hay Day player**. 27 Supercell IPs / ~17 MB over 7 days. Dozens of applovin/moloco mobile-game-ad events. **THIS is the smoke test device** for any mobile-game labelling work.
- **ipad-van-antoinette** = `a6:bb:eb:78:93:48` = `192.168.1.209` = NOT a heavy Hay Day player. Plays rarely. Do NOT use for mobile-game smoke tests — spent hours on this device thinking it was the Hay Day one.
- **Goswijn Pixel 9** = `1e:fb:9b:69:8c:3b` = `192.168.1.122` = User's own Android. Has gemini, facebook, instagram, youtube, whatsapp, nu.nl activity. Was the original "empty Daily usage" case — diagnosed as the noise-filter × dedup interaction (partially addressed by Day 2.2/2.3).
- **Goswijn Macbook M3** = `ba:4a:52:ed:be:02` = `192.168.1.251` = User's primary laptop. The "Apple TV on the laptop" false positive that motivates Day 2.4 was observed here.

# Diagnostic scripts (built during debug sessions, in repo root)
Reusable. Each takes an IP or MAC arg except `list_apple_devices.sh`.

- **`check_dns_correlation.sh`** — Day 1 + Day 1.5 + Day 2 smoke test. Container health, tailer banners, detection_events per type, dns_correlated count, label_attributions, quic_hello count, dns_observations persistence, warm-up evidence. Run after every labeler rebuild.
- **`check_device_activity.sh <ip-or-mac>`** — Diagnoses why Daily usage is empty for a specific device. Walks the same data path as `/api/devices/{mac}/activity`: IP→MAC, device_ips, events by type/category/service, sessionizer simulation with step-by-step filter counts, live API call.
- **`check_hayday.sh <ip>`** — Mobile-game specific. Shows detection_events categories for a device, top unlabelled destinations, and whether `hay/supercell/clash` exists anywhere in `known_domains` or `detection_events`. Includes `unknown_observations` check for Day 4 staging.
- **`check_hayday_real_traffic.sh <ip>`** — Deeper dive. Goes around the labelling layer: geo_conversations rows 21-50 (beyond top 20), PTR/ASN matching on Supercell infrastructure, top unlabelled destinations by bytes, mobile-game-ad event timestamps, temporal correlation (services ±5 min around ad events).
- **`list_apple_devices.sh`** — No args. Lists every Apple-vendor or iPad/iPhone/Mac-named device, sorted by activity in the last hour. Used when "I played X on the iPad" turns up empty — maybe there's more than one iPad.
- **`check_laptop_appletv.sh <ip> <utc-ts>`** — Day 2.4 verification. Shows post-rebuild apple_tv events for a device with section A/B/C verdicts (direct-match / new geo_conv row / existing geo_conv bumped).
- **`check_laptop_appletv_dns.sh <ip>`** — Follow-up to above. Shows which specific DNS queries from the device match an apple_tv seed entry. Use after `check_laptop_appletv.sh` if the verdict is ambiguous.
- **`check_appletv_seed.sh`** — No args. Audits all apple_tv seed entries, flags suspiciously broad ones, simulates match_domain() on iCloud hostnames, then runs LIVE match_domain() from zeek_tailer on key samples. This is how you audit the Day 2.5 seed-bug surface area.
- **`find_appletv_trigger.sh <ip>`** — Runs match_domain() on every distinct DNS query this device made in the last 12h and classifies each as apple_tv / other / unlabelled. Uses source_ip for context-aware refinement. Shows the top-10 "real" labels as a bonus.
- **`inspect_appletv_event.sh <ip>`** — Joins detection_events with label_attributions so you see the rationale string on every apple_tv event ("DNS resolved hostname → resp_ip via MAC-suffix"). **This is the script that cracked the Day 2.5 seed-bug mystery** — it shows the exact hostnames being mislabeled, not just counts.

# Reference points
- Plan principles: **quality > coverage**; every label has herkomst + confidence; conflicts decided explicitly; multi-source corroboration boosts; audit trail; observability first-class; fail-closed ("prefer 70% @ 95% precision over 95% @ 70% precision").
- Per-labeler rollback env vars: `LABELER_DNS_SNOOPING` (since Day 1.5), `LABELER_QUIC_TAILER` (since Day 2). Default `true`. Follow the same naming for future labelers (`LABELER_JA4_MATCH`, `LABELER_LLM_CLASSIFIER`).
- The `/api/labeler/stats` endpoint exists (Day 0) but no UI consumes it yet. Day 6 work will surface it.
- CLAUDE.md commit-and-push rule: after every code change, commit + push without asking.
