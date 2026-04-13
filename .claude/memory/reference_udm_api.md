---
name: UDM Pro API access for validation
description: UniFi API credentials and available endpoints — for development/validation only, never production dependency
type: reference
---

# UDM Pro API (development/validation only)

**IMPORTANT:** Klanten hebben straks geen UDM toegang. De UDM API is ALLEEN een bron om van te leren en te valideren. Nooit als productie-dependency gebruiken.

## Credentials
- URL: https://192.168.1.1
- Username: Airadar
- Password: AIradartoegang1
- Role: Super Admin

## Login
```
curl -sk -X POST 'https://192.168.1.1/api/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"Airadar","password":"AIradartoegang1"}' \
  -c /tmp/unifi_cookies
```

## Available endpoints (tested 2026-04-12)
- `GET /proxy/network/api/s/default/stat/sta` — active clients (MAC, IP, hostname, tx/rx bytes)
- `GET /proxy/network/v2/api/site/default/clients/active` — v2 client list (80 clients)
- `GET /proxy/network/api/s/default/stat/sta/{mac}` — single client details
- `GET /proxy/network/api/s/default/stat/health` — network health

## NOT available via API
- Per-app DPI breakdown (the "YouTube 8.26 MB" data visible in UniFi UI) — stat/stadpi and stat/dpi return empty. Possibly needs different auth or is UI-only.

## Use cases
1. **Device reconciliation** — compare UniFi client list with our device table to fix wrong hostnames/vendors
2. **Coverage validation** — compare UniFi traffic stats with our geo_conversations totals per device
3. **Smoke testing** — when UniFi shows X MB for a device, do we show similar totals?
