---
name: nDPI as alternative coverage strategy
description: If DNS+SNI+JA4 pipeline fixes don't reach 50%+ geo_conversations coverage, nDPI sidecar is the fallback plan for DPI-based classification (like UniFi uses)
type: project
---

# nDPI / DPI als alternatief coverage plan

UniFi's DPI identificeert YouTube/Snapchat/Spotify in encrypted verkeer via protocol signatures — iets wat onze SNI/DNS/JA4 stack niet kan. Vergelijking op Robin's iPhone (.209) toonde UniFi 80% YouTube vs AIradar nauwelijks.

**Wanneer activeren:** Als de DNS TTL fix (12h) + geo_conversations pipeline fix na 24-48 uur niet boven 50% coverage komen op geo_conversations.

**Beste optie: nDPI sidecar**
- Draai `ndpiReader -i br0` als apart process
- Tail de output (CSV/JSON) net zoals Zeek logs
- Geen Python C-bindings nodig, geen packet-level code
- Effort: 3-4 dagen
- Verwachte coverage boost: +30-40%

**Alternatieven:**
- ntopng (2 dagen, full DPI dashboard met nDPI ingebouwd)
- Zeek + Spicy parsers (2-3 dagen, custom protocol parsers)
- Zeek's bestaande protocol detection beter benutten (1 dag, +10-15%)

**Why:** Onze huidige stack leunt op metadata (SNI headers, DNS lookups, TLS fingerprints). DPI inspecteert packet payloads en herkent protocols zelfs in encrypted verkeer via traffic patterns, packet sizes, en timing. Dit is wat UniFi/Ubiquiti onder de hood doet.

**How to apply:** Beslis na de 24h meting van de huidige pipeline fixes. Als coverage <50% blijft, prioriteer nDPI boven de LLM classifier (Day 4-5) — DPI lost het fundamentele probleem op (missende hostnames), LLM niet.
