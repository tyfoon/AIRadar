# AI-Radar Deployment Guide — Firebat AM02L

Stap-voor-stap handleiding om AI-Radar te deployen op de Firebat AM02L mini-PC.

**Hardware**: Firebat AM02L (Ryzen 5 6600H, 16GB RAM, 512GB SSD, 2x 1GbE ethernet)

---

## Wat je nodig hebt

- De Firebat AM02L mini-PC
- Een USB-stick (minimaal 4GB)
- Een toetsenbord + monitor (tijdelijk, alleen voor installatie)
- 2x ethernet kabels
- Je huidige netwerk: router + switch/access point
- Een laptop/PC om de USB-stick te maken

---

## Stap 1: Ubuntu Server USB-stick maken

Op je Mac:

1. Download **Ubuntu Server 24.04 LTS**:
   https://ubuntu.com/download/server

2. Download **balenaEtcher** (gratis):
   https://etcher.balena.io

3. Open balenaEtcher:
   - Klik "Flash from file" en selecteer het `.iso` bestand
   - Steek de USB-stick in je Mac
   - Selecteer de USB-stick
   - Klik "Flash!" en wacht tot het klaar is

---

## Stap 2: Ubuntu installeren op de AM02L

1. Steek de USB-stick in de AM02L
2. Sluit toetsenbord en monitor aan
3. Sluit **1 ethernet kabel** aan (tijdelijk, voor internet tijdens installatie)
4. Zet de AM02L aan
5. Druk herhaaldelijk op **F7** of **DEL** bij het opstarten om het boot menu te openen
6. Kies de USB-stick als boot device

**Tijdens de Ubuntu installatie**:
- Taal: English
- Keyboard: US (of jouw voorkeur)
- Installatie type: **Ubuntu Server (minimized)**
- Netwerk: laat op DHCP staan (wordt later aangepast)
- Disk: **Use entire disk** (bevestig dat het de 512GB NVMe is)
- Je naam: `airadar`
- Server naam: `airadar`
- Gebruikersnaam: `airadar`
- Wachtwoord: kies iets veiligs, **onthoud dit!**
- OpenSSH: **Install OpenSSH server** aanvinken (belangrijk!)
- Featured snaps: niets selecteren
- Wacht tot installatie klaar is en kies "Reboot Now"
- Verwijder de USB-stick wanneer gevraagd

---

## Stap 3: Inloggen en AI-Radar code ophalen

Na reboot verschijnt een login prompt op het scherm.

```bash
# Log in met je gebruikersnaam en wachtwoord
airadar login: airadar
Password: [typ je wachtwoord]
```

Nu ga je de code ophalen:

```bash
# Installeer git
sudo apt install -y git

# Clone AI-Radar
cd ~
git clone https://github.com/goswijnthijssen/AIRadar.git

# Ga naar de map
cd AIRadar
```

---

## Stap 4: Netwerk kabels aansluiten

**Zet de AM02L uit** (of laat hem aan, maakt niet uit):

De AM02L heeft 2 ethernet poorten aan de achterkant. De bekabeling wordt:

```
                        AM02L Mini-PC
                    ┌──────────────────┐
[UDM Pro / Router] ►│ RECHTS    LINKS  │► [Switch / Access Point]
                    │ (eno1)   (enp2s0)│
                    └──────────────────┘
                            │
                       AI-Radar draait
                       hier als bridge
```

- **Rechter poort** (eno1): kabel van je **router / UDM Pro**
- **Linker poort** (enp2s0): kabel naar je **switch of access point**

Al het netwerkverkeer loopt nu *door* de AM02L heen. De AM02L is onzichtbaar voor je apparaten (transparante bridge).

---

## Stap 5: Setup script draaien

```bash
# Terug inloggen als je had afgesloten
cd ~/AIRadar

# Maak het setup script uitvoerbaar
chmod +x setup.sh

# Draai het setup script (duurt ~5 minuten)
sudo ./setup.sh
```

Het script doet automatisch:
1. System update
2. Docker installeren
3. Zeek (netwerk monitor) installeren
4. Netwerk bridge configureren (detecteert automatisch je 2 ethernet poorten)
5. Zeek configureren
6. Mappen aanmaken
7. Backup cron instellen

**Tijdens het script**:
- Het vraagt: `Use bridge mode with these interfaces? (Y/n)` — typ **Y**
- Het vraagt: `Apply netplan now? (y/N)` — typ **y**
- Als het netwerk opnieuw configureert kun je even je verbinding kwijtraken. Wacht 30 seconden.

---

## Stap 6: .env configuratie bestand aanpassen

```bash
# Open het configuratie bestand
nano ~/AIRadar/.env
```

Pas deze regels aan:

```env
# Laat dit staan:
AIRADAR_DB_PATH=./data/airadar.db
ZEEK_LOG_DIR=/opt/zeek/logs/current

# AdGuard — pas je aan NA stap 8 (laat nu even staan)
ADGUARD_URL=http://localhost:80
ADGUARD_USER=jouw_email@voorbeeld.nl
ADGUARD_PASS=jouw_wachtwoord

# Gemini AI — optioneel, voor AI Reports per device
# Ga naar https://aistudio.google.com/app/apikey voor een gratis key
GEMINI_API_KEY=

# CrowdSec — pas je aan NA stap 9 (laat nu even staan)
CROWDSEC_URL=http://localhost:8080
CROWDSEC_API_KEY=

# Netwerk — het setup script heeft dit al ingevuld
# Pas BRIDGE_IP aan als 192.168.1.2 al in gebruik is
BRIDGE_IP=192.168.1.2/24
BRIDGE_GATEWAY=192.168.1.1
UPSTREAM_DNS=1.1.1.1
```

**Opslaan**: druk `Ctrl+X`, dan `Y`, dan `Enter`

> **Let op**: `BRIDGE_IP` moet een vrij IP-adres zijn in je netwerk.
> Als je router `192.168.1.1` is, is `192.168.1.2` meestal vrij.
> Check dit eventueel door op je Mac te pingen: `ping 192.168.1.2`
> Als er geen antwoord komt, is het vrij.

---

## Stap 7: Docker containers starten

```bash
cd ~/AIRadar

# Start alles op (eerste keer duurt ~3 minuten voor het downloaden)
sudo docker compose up -d --build
```

Je ziet nu iets als:
```
[+] Building ...
[+] Running 3/3
 ✔ Container adguardhome  Started
 ✔ Container crowdsec     Started
 ✔ Container airadar-app  Started
```

Controleer of alles draait:
```bash
sudo docker compose ps
```

Alle 3 containers moeten `Up` of `running (healthy)` zijn.

---

## Stap 8: AdGuard Home configureren

Open een browser op je laptop en ga naar:

```
http://192.168.1.2:3000
```

(vervang `192.168.1.2` door je gekozen BRIDGE_IP)

De AdGuard Home setup wizard verschijnt:

1. **Welkom** — klik "Get Started"
2. **Admin interface**: laat op poort `80` staan
3. **DNS server**: laat op poort `53` staan
4. **Maak een admin account**:
   - Gebruikersnaam: je e-mailadres
   - Wachtwoord: kies iets veiligs
5. Klik "Next" en "Open Dashboard"

**Nu terug naar de terminal** om de credentials in `.env` te zetten:

```bash
nano ~/AIRadar/.env
```

Pas aan:
```env
ADGUARD_USER=jouw_email@voorbeeld.nl
ADGUARD_PASS=het_wachtwoord_dat_je_net_koos
```

Opslaan: `Ctrl+X` → `Y` → `Enter`

---

## Stap 9: CrowdSec API key genereren

```bash
# Genereer een API key
sudo docker exec crowdsec cscli bouncers add airadar_dashboard
```

Er verschijnt een lange key, iets als:
```
API key for 'airadar_dashboard':

   a1b2c3d4e5f6g7h8i9j0...

Please keep this key since you will not be able to retrieve it!
```

Kopieer deze key en zet hem in `.env`:

```bash
nano ~/AIRadar/.env
```

Pas aan:
```env
CROWDSEC_API_KEY=a1b2c3d4e5f6g7h8i9j0...
```

Opslaan: `Ctrl+X` → `Y` → `Enter`

---

## Stap 10: Alles herstarten met de nieuwe config

```bash
cd ~/AIRadar

# Herstart zodat alle nieuwe config wordt opgepikt
sudo docker compose restart

# Start Zeek
sudo zeekctl deploy
```

---

## Stap 11: DNS — hoef je niks te doen!

Het setup script heeft **transparante DNS redirect** geconfigureerd. Alle DNS verkeer dat door de bridge loopt wordt automatisch onderschept en door AdGuard gefilterd.

Je hoeft **niks** aan te passen op je router, DHCP server, of apparaten. Zero-touch.

Hoe het werkt:
- Je apparaten sturen hun DNS naar je router (zoals altijd)
- Die DNS query gaat door de AM02L bridge
- De AM02L vangt het af en stuurt het naar AdGuard
- AdGuard filtert trackers/ads en stuurt het antwoord terug
- Je apparaat merkt er niks van

---

## Stap 12: Dashboard openen

Open in je browser:

```
http://192.168.1.2:8000
```

Je ziet nu het AI-Radar dashboard! Binnen een paar minuten verschijnen de eerste events.

---

## Klaar! Checklist

- [ ] Ubuntu Server geinstalleerd
- [ ] 2 ethernet kabels aangesloten (router → AM02L → switch)
- [ ] `sudo ./setup.sh` gedraaid
- [ ] `.env` ingevuld
- [ ] `docker compose up -d --build` gedraaid
- [ ] AdGuard Home wizard afgerond op `:3000`
- [ ] CrowdSec API key gegenereerd en in `.env` gezet
- [ ] `docker compose restart` gedraaid
- [ ] `sudo zeekctl deploy` gedraaid
- [ ] Dashboard werkt op `:8000`
- [ ] DNS filtering werkt (transparant, geen config nodig)

---

## Troubleshooting

**"Ik kan niet meer bij de AM02L via SSH"**
```bash
# Vanuit je Mac:
ssh airadar@192.168.1.2
```
Als dit niet werkt, sluit monitor + toetsenbord aan en check met `ip addr` welk IP de machine heeft.

**"AdGuard toont offline in het dashboard"**
```bash
sudo docker compose restart adguardhome
# Wacht 10 sec, check dan:
sudo docker compose ps
```

**"Geen events in het dashboard"**
```bash
# Check of Zeek draait:
sudo zeekctl status

# Als hij niet draait:
sudo zeekctl deploy

# Check of er logs zijn:
ls -la /opt/zeek/logs/current/
```

**"Docker containers starten niet"**
```bash
# Bekijk de logs:
sudo docker compose logs --tail=50

# Herstart alles:
sudo docker compose down
sudo docker compose up -d --build
```

**"Ik wil opnieuw beginnen"**
```bash
cd ~/AIRadar
sudo docker compose down
sudo rm -rf data/airadar.db
sudo docker compose up -d --build
```
