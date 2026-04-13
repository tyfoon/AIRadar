---
name: UniFi fingerprinting is unreliable — don't auto-import
description: UniFi claims 100% confidence on wrong device models. Use as manual audit tool only, never as automated data source.
type: feedback
---

UniFi's device fingerprinting is NOT reliable enough to auto-import.

**Why:** Tested on 2026-04-12 — UniFi claims 100% confidence that a MacBook Air is a "Samsung Galaxy Note 20 Ultra". Other wrong identifications at 60-98% confidence. Their fingerprinting is useful as a hint for manual review but not as a source of truth.

**How to apply:** Never build automated import from UniFi fingerprints into our device table. The UDM Pro API is for manual validation/comparison only. The `rest/user` and `v2/clients/active` endpoints give useful client lists for reconciliation, but the `fingerprint.model_name` field is unreliable.
