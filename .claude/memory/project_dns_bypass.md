---
name: DNS bypass problem and DoT/DoH fixes
description: Many devices bypass port-53 DNS redirect via DoH (port 443) and DoT (port 853). DoT redirect added, DoH block parked as too risky.
type: project
---

# DNS bypass probleem (2026-04-12)

## Probleem
7+ devices hebben 0 DNS observations ondanks actief verkeer. Oorzaak: ze gebruiken DoH (poort 443) of DoT (poort 853) in plaats van gewone DNS (poort 53). De iptables redirect vangt alleen poort 53.

**Zwaarste overtreders:**
- LG TV: 88K hits naar 1.1.1.1 (DoH)
- Google Home/Nest: 3K+ hits naar 8.8.8.8 (hardcoded IP, NIET te redirecten via DNS blokkade)
- Slide gordijnmotoren: duizenden hits naar 8.8.8.8
- Alle telefoons/tablets: tientallen hits naar 1.1.1.1/1.0.0.1

**Impact:** Goswijn's HONOR tablet (.131) had 45 min YouTube kijken dat niet in Daily Usage verscheen omdat er geen DNS observations waren om de conn.log flows te labelen.

## Wat we gedaan hebben
- ✅ **DoT redirect (poort 853)** toegevoegd aan airadar-dns-redirect.service — vangt Android "Private DNS"

## Wat we NIET gedaan hebben (bewust geparkeerd)
- ⬜ **DoH blokkeren via AdGuard** — blokkeer dns.google, cloudflare-dns.com, one.one.one.one als DNS domains zodat devices terugvallen op poort 53. **Risico:** sommige apps kunnen falen als ze geen DoH fallback hebben. Gebruiker wil dit niet zonder per-device testen.
- ⬜ **DNAT voor hardcoded 8.8.8.8** — iptables regel die verkeer naar 8.8.8.8:443 redirect naar AdGuard. **Risico:** kan HTTPS verkeer naar Google breken.

**Why:** DNS coverage is de basis voor de hele labeler pipeline. Zonder DNS observations valt de dns_correlation fallback weg en worden flows als "unknown" gelabeld.

**How to apply:** Als er na de DoT fix nog steeds devices zonder DNS observations zijn, overweeg dan DoH blokkade (optie 2) met per-device testing.
