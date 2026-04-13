# Memory Index

- [Always commit and push](feedback_always_push.md) — Auto commit+push after every code change, don't ask
- [Labeler coverage roadmap (Day 0–6)](project_labeler_roadmap.md) — 7-day plan from 30%→90% coverage; Day 0–3 shipped
- [Coverage sprint](project_coverage_sprint.md) — Steps 1-2 shipped (DNS TTL 12h + geo pipeline fix), coverage 27%→60%/81% bytes. Steps 3-4 (PTR/ASN) pending after 24h measurement
- [nDPI alternative plan](project_ndpi_alternative.md) — If pipeline fixes don't reach 50%, use nDPI sidecar for DPI-based classification (like UniFi)
- [Timezone lessons](project_coverage_sprint.md#timezone-lessons-learned) — Never use aware datetimes with SQLite; use UTCJSONResponse for Z suffix in API output
- [DNS bypass problem](project_dns_bypass.md) — DoT redirect added; DoH block parked (risk). If devices still miss DNS, consider DoH block with per-device testing
- [UDM Pro API](reference_udm_api.md) — Validation-only access to UniFi. No per-app DPI via API, but client list + traffic totals available
- [UniFi fingerprinting unreliable](feedback_unifi_fingerprinting.md) — Don't auto-import; 100% confidence on wrong models. Manual audit only.
- [Device identity corrections](user_device_corrections.md) — User-confirmed MAC→device mappings (.234=MacBook M4, .209=Robin iPhone, .7=AIradar server not TV)
