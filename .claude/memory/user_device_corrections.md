---
name: Device identification corrections from user
description: User-confirmed device identities that override our hostname/vendor detection. Use when investigating device-specific issues.
type: user
---

# Confirmed device identities (from user, 2026-04-12)

| IP | MAC | We say | Actually is | Notes |
|----|-----|--------|-------------|-------|
| .234 | a8:4a:63:c7:f6:43 | TPV Display / AIRM4VANGOSWIJN | **Goswijn MacBook Air M4** | display_name already set correctly, vendor OUI is wrong (TPV chip in Apple) |
| .209 | a6:bb:eb:78:93:48 | ipad-van-antoinette | **Robin's iPhone** (iPhone 16e) | hostname is stale DHCP entry from old device |
| .131 | 76:cd:a9:63:95:aa | HONOR-MagicPad2 | **Goswijn's HONOR MagicPad2 tablet** | Correct ID, user confirmed |
| .7 | 84:47:09:78:b6:9b | lgwebostv | **AIradar server (Firebat AM02L)** | Bridge IP, not a TV. Should be filtered from device list or renamed |
| .228 | 8c:83:94:11:53:b2 | lgwebostv-z1wm-18 | **LG WebOS TV** | Real TV, confirmed clean |
| .236 | (same MAC as .7) | lgwebostv | **Does not exist** — phantom IP on the AIradar box |
| .205 | 4a:65:f5:eb:a3:4d | iPad Annie | **iPad Annie** (iPad 8th Gen) | Correct — THE Hay Day smoke test device |
| .130 | b4:10:7b:af:e2:84 | airthings-view | **Airthings View Plus** air quality sensor | 17MB spikes every 3 days — likely firmware updates, not exfiltration |
| .148 | 50:ed:3c:2a:5d:76 | macbook-air-van-robin | **Robin's MacBook Air** | UniFi wrongly says Samsung Galaxy Note 20 |
