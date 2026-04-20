# Firewalla Reverse Engineering — Complete Technical Analysis

> **Date**: 2026-04-20
> **Target**: Firewalla Purple/Blue Plus at 192.168.1.138
> **Firmware branch**: `release_6_0` (production)
> **Kernel**: Linux 4.9.241-firewalla aarch64
> **Purpose**: Understand Firewalla's architecture and techniques to inform AIradar development

---

## Table of Contents

1. [Hardware & OS](#1-hardware--os)
2. [Service Architecture](#2-service-architecture)
3. [Zeek Integration & Custom Scripts](#3-zeek-integration--custom-scripts)
4. [BroDetect — The Zeek Log Processing Pipeline](#4-brodetect--the-zeek-log-processing-pipeline)
5. [DNS Processing & IP→Domain Correlation](#5-dns-processing--ipdomain-correlation)
6. [Connection Processing & Flow Enrichment](#6-connection-processing--flow-enrichment)
7. [HTTP Processing & User-Agent Extraction](#7-http-processing--user-agent-extraction)
8. [SSL/TLS Processing & SNI Extraction](#8-ssltls-processing--sni-extraction)
9. [Device Fingerprinting Pipeline](#9-device-fingerprinting-pipeline)
10. [mDNS/Bonjour Device Discovery](#10-mdnsbonjour-device-discovery)
11. [Domain Categorization System](#11-domain-categorization-system)
12. [Flow Aggregation & Storage](#12-flow-aggregation--storage)
13. [Flow Stashing & Batched Writes](#13-flow-stashing--batched-writes)
14. [App Time Usage Tracking](#14-app-time-usage-tracking)
15. [Alarm & Policy System](#15-alarm--policy-system)
16. [API Architecture](#16-api-architecture)
17. [DNS Filtering Stack](#17-dns-filtering-stack)
18. [Redis Data Model](#18-redis-data-model)
19. [Network Modes](#19-network-modes)
20. [Integration Points](#20-integration-points)
21. [Key Takeaways for AIradar](#21-key-takeaways-for-airadar)

---

## 1. Hardware & OS

**Device**: Firewalla Purple or Blue Plus (aarch64 ARM64)
- **Kernel**: `4.9.241-firewalla` (custom, PREEMPT SMP)
- **OS**: Ubuntu-based (exact version not determined, likely 20.04)
- **User**: Everything runs under the `pi` user at `/home/pi/`
- **SSH**: Password auto-generated, visible in app under Settings > Help > SSH Console
- **sudo**: Works without password
- **Uptime at inspection**: 60 days

**Storage layout**:
```
/home/pi/firewalla/      — Main application code (Node.js, AGPL-3.0)
/home/pi/firerouter/     — Router/network management code
/home/pi/.firewalla/     — Runtime config and data
/home/pi/.firewalla/config/post_main.d/  — Custom scripts (survive firmware updates)
/home/pi/.firewalla/config/dnsmasq_local/ — Custom DNS rules
/blog/current/           — Zeek log output directory
/alog/                   — ACL audit and alarm logs
```

**GitHub**: https://github.com/firewalla/firewalla (AGPL-3.0, ~600 stars)

---

## 2. Service Architecture

29 running services observed. The core Firewalla services are:

| Service | Description | Port |
|---------|-------------|------|
| `fireapi.service` | Express.js REST API | 8833 (localhost + LAN) |
| `firemain.service` | Main orchestration daemon | — |
| `firemon.service` | Network monitoring daemon | — |
| `firerouter.service` | Router/network management | — |
| `firerouter_dns.service` | Per-interface DNS (dnsmasq) | 53 |
| `firerouter_dhcp.service` | DHCP service | — |
| `firehb.service` | Heartbeat service | — |
| `firereset.service` | Bluetooth reset service | — |
| `firestatus.service` | Status dashboard | 9966 |
| `fwapc.service` | Asset controller | 8841 |
| `intelproxy.service` | Threat intelligence proxy | 9964 |
| `ftc.service` | FTC service | — |
| `dnscrypt.service` | DNS encryption proxy | 8854 |
| `redis-server.service` | Primary data store | 6379 (localhost only) |

**Primary language**: JavaScript/Node.js (~86% of codebase)
- Secondary: Shell (10.6%), Python (1.1%), Zeek scripts (0.9%), Lua, C

**Listening ports observed** (via `ss -tlnp`):
```
127.0.0.1:6379     — Redis (localhost only)
127.0.0.1:8834     — Internal API
127.0.0.1:8837     — FireRouter internal
127.0.0.1:8841     — Asset controller
127.0.0.1:8854     — dnscrypt-proxy
127.0.0.1:9964     — Intel proxy
127.0.0.1:9966     — Status page
127.0.0.1:47761-3  — Zeek workers (3 instances)
192.168.1.138:22   — SSH
192.168.1.138:53   — DNS (dnsmasq)
192.168.1.138:8833 — Local API (Express.js, exposed on LAN!)
```

---

## 3. Zeek Integration & Custom Scripts

Firewalla runs **Zeek** (formerly Bro) with 3 worker processes for traffic analysis. They customize Zeek extensively with custom scripts.

### Zeek Configuration (`local.bro`)

Located at `/home/pi/firewalla/platform/purple/hooks/before_bro/local.bro`:

```zeek
redef ignore_checksums = T;
redef SSL::disable_analyzer_after_detection = F;

@load misc/loaded-scripts
@load tuning/defaults
@load tuning/json-logs          # JSON output format
@load misc/scan                 # Port scan detection
@load misc/detect-traceroute
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/software/windows-version-detection
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load protocols/http/detect-sqli
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR
@load policy/protocols/ssl/heartbleed
@load policy/protocols/conn/mac-logging   # L2 MAC addresses in conn.log
@load base/protocols/dhcp

# Custom scripts:
@load bro-long-connection    # Periodic snapshots of long-lived connections
@load bro-heartbeat          # Zeek liveness heartbeat
@load heartbeat-flow         # Fake flow every 30 min for liveness detection
@load zeek-conn-log-filter   # Connection log filtering
@load zeek-ssl-clear-state   # SSL state cleanup
@load well-known-server-ports
@load dns-mac-logging.zeek   # MAC addresses in dns.log
@load http-fast-logging.zeek # Immediate HTTP logging after headers

redef restrict_filters += [["not-mdns"] = "not port 5353"];
redef udp_inactivity_timeout = 3 min;
redef dpd_buffer_size = 65536;
```

### Custom Zeek Script: `dns-mac-logging.zeek`

Adds L2 MAC addresses to DNS log entries (critical for device identification):

```zeek
@load base/protocols/conn

module DNS;

redef record Info += {
  orig_l2_addr: string &log &optional;
  resp_l2_addr: string &log &optional;
};

event dns_end(c: connection, msg: dns_msg) &priority=10
{
  if ( ! c?$dns ) return;
  if ( c$orig?$l2_addr )
    c$dns$orig_l2_addr = c$orig$l2_addr;
  if ( c$resp?$l2_addr )
    c$dns$resp_l2_addr = c$resp$l2_addr;
}
```

### Custom Zeek Script: `http-fast-logging.zeek`

Logs HTTP transactions immediately after headers are parsed (not waiting for response body):

```zeek
@load base/protocols/conn

module HTTP;

redef record Info += {
    orig_l2_addr: string &log &optional;
    resp_l2_addr: string &log &optional;
};

event http_begin_entity(c: connection, is_orig: bool) &priority = -5
{
  if ( c$orig?$l2_addr )
    c$http$orig_l2_addr = c$orig$l2_addr;
  if ( c$resp?$l2_addr )
    c$http$resp_l2_addr = c$resp$l2_addr;
  if ( c$http?$status_code && ! code_in_range(c$http$status_code, 100, 199) )
    Log::write(HTTP::LOG, c$http);
}
```

### Custom Zeek Script: `bro-long-connection/main.zeek`

Periodically logs snapshots of long-lived connections to `conn_long.log`:

```zeek
function long_callback(c: connection, cnt: count): interval
{
    Conn::set_conn_log_data_hack(c);
    if ( c$orig?$l2_addr )
      c$conn$orig_l2_addr = c$orig$l2_addr;
    if ( c$resp?$l2_addr )
      c$conn$resp_l2_addr = c$resp$l2_addr;
    Log::write(LongConnection::LOG, c$conn);
    return 1min;  # Re-log every 1 minute
}

event new_connection(c: connection)
{
    ConnPolling::watch(c, long_callback, 1, 2min);  # Start after 2 min
}
```

### Custom Zeek Script: `heartbeat-flow/main.zeek`

Emits a fake flow every 30 minutes for liveness detection:

```zeek
event log_heartbeat_flow()
{
    local id: conn_id = [
        $orig_h=0.0.0.0, $orig_p=0/unknown,
        $resp_h=0.0.0.0, $resp_p=0/unknown
    ];
    local msg: Conn::Info = [
        $ts=network_time(), $uid="0", $id=id, $proto=unknown_transport
    ];
    Log::write(Conn::LOG, msg);
    schedule 30 min { log_heartbeat_flow() };
}
```

### Zeek Log Output

Located at `/blog/current/`:
```
conn.log         — Connection metadata (with L2 MACs)
conn_long.log    — Long-lived connection snapshots (every 1 min)
dns.log          — DNS queries/responses (with L2 MACs)
dhcp.log         — DHCP transactions
ssh.log          — SSH connections
ntp.log          — NTP traffic
http.log         — HTTP requests (with L2 MACs, fast-logged)
ssl.log          — TLS handshakes (SNI, certs)
x509.log         — Certificate details
weird.log        — Anomalies
heartbeat.log    — Zeek liveness
stderr.log       — Zeek errors
stdout.log       — Zeek stdout
```

All logs are **JSON format** with L2 MAC addresses where applicable.

**Key observation for AIradar**: The mDNS filter (`not port 5353`) means Zeek does NOT capture mDNS traffic. They handle mDNS separately via the BonjourSensor (Node.js library).

---

## 4. BroDetect — The Zeek Log Processing Pipeline

**File**: `/home/pi/firewalla/net2/BroDetect.js`

BroDetect is the heart of Firewalla's traffic analysis. It tails all Zeek log files simultaneously and enriches each flow with domain, app, and threat information.

### Architecture

```
Zeek logs → LogReader (file tailer) → BroDetect processors → Redis + Events
```

### Log Watchers

```javascript
initWatchers() {
  const watchers = {
    "intelLog":      [config.intel.path,      this.processIntelData],
    "noticeLog":     [config.notice.path,     this.processNoticeData],
    "dnsLog":        [config.dns.path,        this.processDnsData],
    "httpLog":       [config.http.path,       this.processHttpData],
    "sslLog":        [config.ssl.path,        this.processSslData],
    "connLog":       [config.conn.path,       this.processConnData, 2000], // 2s delay!
    "connLongLog":   [config.connLong.path,   this.processLongConnData],
    "connLogDev":    [config.conn.pathdev,    this.processConnData],
    "x509Log":       [config.x509.path,       this.processX509Data],
    "knownHostsLog": [config.knownHosts.path, this.processknownHostsData],
    "signatureLog":  [config.signature.path,  this.processSignatureData],
  };
}
```

**Critical design pattern**: `connLog` has a **2-second delay** (`delayMs: 2000`) to allow DNS, HTTP, and SSL log entries to populate the `appmap` cache first. When a connection is processed, BroDetect can already look up which domain it's associated with.

### In-Memory Caches (LRU)

```javascript
this.appmap = new LRU({max: 1000, maxAge: 10800 * 1000});     // 3hr: uid → {host, proto, ip}
this.sigmap = new LRU({max: 1000, maxAge: 10800 * 1000});     // 3hr: signature data
this.proxyConn = new LRU({max: 100, maxAge: 60 * 1000});      // 1min: HTTP CONNECT proxy flows
this.dnsCache = new LRU({max: 100, maxAge: 3600 * 1000});     // 1hr: dedup DNS queries
this.bridgeLocalFlow = new LRU({max: 1000, maxAge: 10 * 1000}); // 10s: bridge flows
```

### Processing Order

The processing pipeline is:

1. **DNS log** → Resolves IP→domain mappings, stores in Redis (`rdns:ip:X.X.X.X`), populates conntrack
2. **HTTP log** → Extracts host header, user-agent; maps connection UID→domain in `appmap`
3. **SSL log** → Extracts SNI (server_name); maps connection→domain
4. **Connection log** (2s later) → Enriches with domain from appmap/conntrack, classifies direction, emits events

This order is critical because connections need domain context from DNS/HTTP/SSL before they can be properly classified.

---

## 5. DNS Processing & IP→Domain Correlation

**Function**: `processDnsData()` (line 567 of BroDetect.js)

This is how Firewalla correlates IP addresses to domain names — the fundamental technique that turns raw flows into meaningful data.

### Processing Steps

1. **Filter**: Only process port 53 responses with answers
2. **Skip**: Search domains and local domains
3. **Save DNS flow**: Store in Redis for historical query
4. **Dedup**: LRU cache (`dnsCache`) keyed by `query:qtype` — skip if all answers already cached
5. **PTR queries**: Handle reverse DNS (`.in-addr.arpa`) — store IP→domain mapping
6. **A/AAAA queries**:
   - Store domain→IP in `conntrack` (keyed by originator MAC or IP), TTL 600s
   - Store IP→domain in `rdns:ip:X.X.X.X` (Redis sorted set, scored by timestamp)
   - Store domain→IP in `rdns:domain:X` (reverse mapping)
   - Handle CNAME chains: all CNAMEs get the same IP mappings

### Redis Keys Used

```
rdns:ip:<ip>          — sorted set: domain names for this IP, scored by timestamp
rdns:domain:<domain>  — set: IP addresses this domain resolved to
```

### Conntrack Integration

```javascript
// L2 MAC is used as key when available (from dns-mac-logging.zeek)
await conntrack.setConnEntries(
  obj["orig_l2_addr"] ? obj["orig_l2_addr"].toUpperCase() : obj["id.orig_h"],
  "", answer, "", "dns",
  {proto: "dns", ip: answer, host: query.toLowerCase()}, 600
);
```

**Key insight**: The `orig_l2_addr` (MAC address from the custom Zeek script) is preferred over IP address as the conntrack key. This is because MAC addresses are stable across IP changes (DHCP renewals, IPv6 privacy addresses).

---

## 6. Connection Processing & Flow Enrichment

**Function**: `processConnData()` (line 860 of BroDetect.js)

The main flow processing function. This is the most complex function in BroDetect — approximately 300 lines of logic.

### Filtering (what gets dropped)

```javascript
// Heartbeat flows (from heartbeat-flow.zeek)
if (obj.uid == '0' && orig == '0.0.0.0' && resp == '0.0.0.0') → store heartbeat, return

// ICMP → drop
// DNS (port 53) → drop (handled by processDnsData)
// Loopback (127.0.0.1, ::1) → drop
// Zero-length flows (orig_ip_bytes == 0 && resp_ip_bytes == 0) → drop
// Zero-byte flows (orig_bytes == 0 && resp_bytes == 0) → drop
// Broadcast MAC (FF:FF:FF:FF:FF:FF) → drop
// Firewalla's own traffic → drop
// Multicast IPs → drop
```

### Data Validation (`validateConnData()`)

Sophisticated validation to detect Zeek artifacts:

```javascript
// Configurable thresholds:
const iptcpRatio = threshold.IPTCPRatio || 10000;
const S2S3MaxBytes = threshold.S2S3MaxBytes || 100000; // 100KB

// Drop if:
// 1. missed_bytes equals orig_bytes or resp_bytes (S2/S3 states with enough volume)
// 2. missed_bytes ratio too large relative to total bytes
// 3. IP/TCP ratio anomalous (likely packet reassembly artifact)
// 4. Bytes exceed theoretical max speed × duration
// 5. SSL traffic gets 2× multiplier (HTTPS drops rate is 50% in their config)
```

### TCP State Filtering

Firewalla drops incomplete TCP connections that indicate blocked traffic:

```javascript
// Drop these states if zero bytes in one direction:
// REJ, RSTOS0, RSTRH, SH, SHR, S0
if ((obj.conn_state == "REJ" || obj.conn_state == "RSTOS0" || ...) 
    && (obj.orig_bytes == 0 || obj.resp_bytes == 0)) → drop

// Drop likely TLS-blocked connections (≤10 packets, zero bytes one direction):
// RSTR, RSTO, S1, S3, SF
if (["RSTR", "RSTO", "S1", "S3", "SF"].includes(obj.conn_state) 
    && obj.orig_pkts <= 10 && ...) → drop
```

### Flow Direction Determination

Uses Zeek's `local_orig` and `local_resp` flags (based on `networks.cfg`):

```javascript
if (localOrig && localResp) {
  // Local-to-local flow (device-to-device on same network)
  // Only processed in router/bridge mode with feature flag
  localFlow = true;
}
else if (localOrig && !localResp) {
  flowdir = "in";   // Outbound: local device initiated connection to internet
  lhost = orig;
  dhost = resp;
  localMac = origMac;
}
else if (!localOrig && localResp) {
  flowdir = "out";  // Inbound: internet initiated connection to local device
  lhost = resp;
  dhost = orig;
  localMac = respMac;
}
```

**Note**: "in" means "initiated from inside" (outbound), "out" means "initiated from outside" (inbound). This naming is counterintuitive.

### Domain Resolution for Connection

After direction is determined, the connection is enriched with domain information:

1. Look up `appmap` (populated by HTTP/SSL processors using connection UID)
2. Look up `conntrack` entries (populated by DNS processor using MAC+IP)
3. Fall back to Redis `rdns:ip:` reverse DNS lookup

### Event Emission

After processing, two events are emitted:

```javascript
// 1. Enriched flow event (immediate)
sem.emitEvent({
  type: Message.MSG_FLOW_ENRICHED,
  flow: { ...tmpspec, intf: intfInfo.uuid, dIntf: dstIntfInfo.uuid }
});

// 2. DestIPFound event (1 second delay — allows DNS to be processed first)
setTimeout(() => {
  sem.emitEvent({
    type: 'DestIPFound',
    ip: remoteIPAddress,
    host: remoteHost,
    fd: tmpspec.fd,
    flow: { ...tmpspec, ip: remoteIPAddress, host: remoteHost },
    mac: localMac
  });
}, 1000);
```

### Device Heartbeat

Every valid flow also records a device heartbeat:

```javascript
if (obj.proto == 'tcp' || flowdir == 'in' && obj.orig_pkts || flowdir == 'out' && obj.resp_pkts)
  this.recordDeviceHeartbeat(localMac, timestamp, lhost, fam)
```

---

## 7. HTTP Processing & User-Agent Extraction

**Function**: `processHttpData()` (line 324 of BroDetect.js)

### Key Operations

1. **Host extraction**: Extracts `host` header, with workaround for [Zeek bug #1844](https://github.com/zeek/zeek/issues/1844) where host can be truncated hex
2. **Proxy detection**: If method is `CONNECT` or `proxied` flag is set, the flow is marked as proxy:
   - After 30-second delay, reverses all intel/DNS mappings for the proxy target
   - Removes appmap entries
   - Prevents the proxied IP from being classified as the actual destination
3. **UA extraction**: Delegates to `httpFlow.process(obj)` which:
   - Parses User-Agent using `node-device-detector` library
   - Stores parsed UA in Redis: `host:user_agent2:<mac>` (sorted set, scored by timestamp)
4. **App mapping**: Stores `uid → {host, proto, ip}` in `appmap` LRU and `conntrack`

### Device Detector

```javascript
// From HttpFlow.js
const DeviceDetector = require('../../vendor_lib/node-device-detector/')
this.detector = new DeviceDetector({
  skipBotDetection: true,
  skipClientDetection: true,
  baseRegexDir: regexPath,  // Cloud-downloaded regex files
})
```

The `node-device-detector` library parses User-Agent strings into:
- `device.type` (smartphone, tablet, desktop, tv, console, etc.)
- `device.brand` (Apple, Samsung, etc.)
- `device.model` (iPhone 14, Galaxy S23, etc.)
- `os.name` (iOS, Android, Windows, etc.)

Regex patterns are **cloud-downloaded** at runtime to `/home/pi/.firewalla/run/device-detector-regexes/`.

---

## 8. SSL/TLS Processing & SNI Extraction

**Function**: `processSslData()` (line 1621 of BroDetect.js)

### Key Operations

1. **Proxy filtering**: If the connection UID was seen as an HTTP CONNECT proxy, drop it
2. **Validation check**: Drop entries where `validation_status !== "ok"`
3. **Blocked IP filter**: Drop if destination is a reserved blocking IP
4. **SNI extraction**: Primary identification method — `obj.server_name`
5. **Certificate fallback**: If no SNI, extract domain from certificate:
   - Check `cert_chain_fuids` (Zeek 3.x) or `cert_chain_fps` (Zeek 4.x)
   - Look up certificate in Redis `flow:x509:<cert_id>`
   - Parse CN from certificate subject: `/CN=.*,/` → extract server name
   - Strip wildcard prefix (`*.example.com` → `example.com`)
6. **Storage**: Save to Redis `ssl:cert:<dst_ip>` with subject and server_name

### Redis Key

```
ssl:cert:<ip>  — hash: { subject: "...", server_name: "..." }
```

**Key insight for AIradar**: SSL SNI is the most reliable domain identification method for HTTPS traffic. When DNS is encrypted (DoH/DoT), SNI is often the only way to identify the destination service. AIradar should parse `ssl.log` for `server_name`.

---

## 9. Device Fingerprinting Pipeline

**File**: `/home/pi/firewalla/sensor/DeviceIdentificationSensor.js`

Firewalla identifies devices using multiple signals, with a voting/confidence system.

### Detection Flow

```
For each device (by MAC):
  1. Is it a Firewalla device? → return { name: 'Firewalla' }
  2. Try hostname→type mapping (keyword match)
  3. Collect User-Agent history from Redis
  4. Parse each UA → extract device type, brand, model, OS
  5. Vote on most common values
  6. Special case: too many types = router
  7. Merge with existing detection (keep bonjour, cloud, feedback sources)
```

### Hostname→Type Mapping

```javascript
const name = getPreferredName(host.o)
if (name) {
  const type = await nameToType(name)
  // nameToType uses keywordToType.json (cloud-downloaded)
  // Greedy longest-match-first against hostname
}
```

The `keywordToType.json` file maps hostname substrings to device types. Example keywords (inferred):
- "iphone" → "phone"
- "ipad" → "tablet"
- "macbook" → "laptop"
- "roku" → "tv"
- "echo" → "speaker"
- "chromecast" → "tv"
- etc.

### User-Agent Voting System

```javascript
const deviceType = {};   // { "smartphone": 5, "desktop": 2 }
const deviceBrand = {};  // { "Apple": 5, "Samsung": 2 }
const deviceModel = {};  // { "iPhone": 5 }
const osName = {};       // { "iOS": 5, "Mac OS": 2 }

for (const r of results) {
  // Normalize phone types
  if (['smartphone', 'feature phone', 'phablet'].includes(r.device.type))
    r.device.type = 'phone'

  this.incr(deviceType, r.device.type)
  this.incr(deviceModel, r.device.model)
  this.incr(deviceBrand, r.device.brand)
  this.incr(osName, r.os.name)
}
```

### Router Detection Heuristic

**If a MAC address shows 3+ different device types OR 5+ different OS names, it's classified as a router.** This is because routers forward traffic from many devices, and the User-Agent strings come from the devices behind the router.

```javascript
if (Object.keys(deviceType).length > 3 || Object.keys(osName).length > 5) {
  detect.type = 'router'
} else {
  // Take the most common value for each dimension
  detect.type = _.maxBy(Object.entries(deviceType), 1)[0]
  detect.brand = _.maxBy(Object.entries(deviceBrand), 1)[0]
  detect.model = _.maxBy(Object.entries(deviceModel), 1)[0]
  detect.os = _.maxBy(Object.entries(osName), 1)[0]
}
```

### Detection Source Priority

Multiple detection sources are merged, with user feedback taking highest priority:

```javascript
const keepsake = _.pick(host.o.detect, ['feedback', 'bonjour', 'cloud'])
host.o.detect = await this.detect(host)  // UA-based detection
Object.assign(host.o.detect, keepsake)   // Overlay preserved sources
```

Sources: `feedback` (user corrections) > `bonjour` (mDNS) > `cloud` (Firewalla cloud API) > UA detection.

### Redis Storage

```
host:mac:<MAC>  — hash containing:
  detect: '{"type":"phone","brand":"Apple","model":"iPhone","os":"iOS","bonjour":{"type":"phone"}}'
  macVendor: "Apple, Inc."
  bname: "iPhone"
```

---

## 10. mDNS/Bonjour Device Discovery

**File**: `/home/pi/firewalla/sensor/BonjourSensor.js`

### Architecture

Firewalla listens for mDNS (multicast DNS) announcements using the Node.js `bonjour` library. This is separate from Zeek — Zeek has `not port 5353` filter, so mDNS is handled entirely in Node.js.

### Service Discovery Flow

```javascript
// Listen on all monitored interfaces
for (const iface of monitoringInterfaces) {
  const instance = Bonjour({interface: iface.ip_address});
  const browser = instance.find({}, (service) => this.bonjourParse(service));
}

// Refresh every 5 minutes (clear dedup cache, re-query)
setInterval(() => {
  for (const listener of this.bonjourListeners) {
    // Remove all cached services to allow re-discovery
    Object.keys(listener.browser._serviceMap).forEach(
      fqdn => listener.browser._removeService(fqdn)
    );
    listener.browser.update();
  }
}, 1000 * 60 * 5);
```

### Service Processing

```javascript
async processService(service) {
  // 1. Resolve IP to MAC address
  let mac = await hostTool.getMacByIPWithCache(ipv4Addr);

  // 2. Skip Firewalla's own MAC
  if (sysManager.isMyMac(mac)) return;

  // 3. Dedup: skip same MAC+service_type within 30 seconds
  if (lastProcessTimeMap[mac + service.type] && timeDiff < 30) return;

  // 4. Extract device info from service metadata
  // (implementation continues in bonjourParse)
}
```

### What Bonjour Reveals

From mDNS service announcements, Firewalla extracts:
- **Service types**: `_airplay._tcp`, `_hap._tcp`, `_http._tcp`, `_raop._tcp`, etc.
- **Device names**: Human-readable names from service records
- **Apple HomeKit category IDs**: HAP (HomeAccessory Protocol) `ci` field → device type
- **Apple model identifiers**: From TXT records (e.g., `MacBookPro18,1`)

### Apple-Specific Detection

**File**: `/home/pi/firewalla/extension/detect/appleModel.js`

```javascript
// Model prefix → device type (cloud-downloaded JSON)
async function modelToType(identifier) {
  const main = identifier.split(',')[0]  // "MacBookPro18,1" → "MacBookPro18"
  // Strip numbers to get prefix: "MacBookPro"
  return modelPfxToType[prefix]  // → "laptop"
}

// Board code → model name (cloud-downloaded)
async function boardToModel(internalCode) {
  return boardToModel[internalCode.toLowerCase()]
}

// HAP Category ID → device type (cloud-downloaded)
async function hapCiToType(ci) {
  return ciMap[ci]
  // Apple HAP categories: 1=Other, 2=Bridge, 3=Fan, 5=GarageDoor, 
  // 6=Lightbulb, 7=DoorLock, 8=Outlet, 9=Switch, 10=Thermostat, etc.
}
```

All detection data files (`keywordToType.json`, `modelPfxToType.json`, `boardToModel.json`, `hapCiToType.json`) are **cloud-downloaded** at runtime via the Firewalla cloud service. They are NOT included in the GitHub repo. This means the detection intelligence is proprietary even though the code is open source.

---

## 11. Domain Categorization System

### Category Infrastructure

**Files**:
- `/home/pi/firewalla/control/CategoryUpdaterBase.js`
- `/home/pi/firewalla/control/CategoryUpdater.js`
- `/home/pi/firewalla/sensor/FastIntelPlugin.js`

### Categories Observed in Redis

```
dynamicCategoryDomain:intel
dynamicCategoryDomain:ad
dynamicCategoryDomain:drugs
dynamicCategoryDomain:gamble
dynamicCategoryDomain:shopping
dynamicCategoryDomain:p2p
dynamicCategoryDomain:social
dynamicCategoryDomain:x
dynamicCategoryDomain:av
dynamicCategoryDomain:vpn
```

And the built-in bundle categories:
```
default_c, adblock_strict, games, social, av, porn, gamble, p2p, vpn, shopping
```

### Redis Key Structure

```
dynamicCategoryDomain:<category>         — zset: domains detected in real-time
category:<category>:default:domain       — set: curated default domain list
category:<category>:exclude:domain       — set: excluded domains
category:<category>:include:domain       — set: user-added domains
category:<category>:data                 — data list
category:<category>:sigDetectedServers   — signature-detected servers
category:<category>_bf:strategy          — bloom filter strategy
category:<category>_bf:passthrough:domain — bloom filter passthrough
category:<category>_bf:hit:domain        — bloom filter hits
```

### Sample Category Data (Games)

```
*.steampowered.com
*.ea.com
*.battle.net
*.minecraft.net
*.playstation.com
*.leagueoflegends.com
*.lichess.org
*.poki.com
*.nexusmods.com
*.futbin.com
*.gamer.com.tw
*.gamewith.jp
```

### Bloom Filter Classification (FastIntelPlugin)

For high-performance domain classification, Firewalla uses **Bloom filters**:

```javascript
class FastIntelPlugin extends Sensor {
  constructor(config) {
    this.bfInfoMap = new Map();  // part → bloom filter info
    this.bfMap = {};             // part → BloomFilter instance
    this.targetListKey = "allcat_bf";
  }

  async run() {
    this.hookFeature("fast_intel");
    setInterval(this.refresh_bf.bind(this), config.regularInterval * 1000);
  }

  async getTargetList() {
    // Fetch bloom filter parts list from cloud
    const infoHashsetId = `info:app.allcat_bf`;
    const result = await bone.hashsetAsync(infoHashsetId);
    // Returns list of BF part IDs to download
  }

  async updateData(part, content) {
    // content = { data: [...], info: { s: size, e: errorRate } }
    let bfInfo = {key: part, size: obj.info.s, error: obj.info.e};
    this.bfInfoMap.set(part, bfInfo);
    // Write BF data to disk, load into memory
  }
}
```

The bloom filters are downloaded from Firewalla's cloud in parts, each representing a category. A domain lookup is O(1) against the bloom filter, making it extremely fast for real-time classification.

### Category Enforcement

Categories are enforced at two levels:
1. **DNS level**: dnsmasq blocks domains in blocked categories
2. **IP level**: ipset + iptables blocks IP addresses associated with blocked categories

```javascript
const redirectHttpPort = 8880;
const redirectHttpsPort = 8883;
const blackHoleHttpPort = 8881;
const blackHoleHttpsPort = 8884;
const IPSET_HASH_MAXELEM = 1048576; // 2^20 = 1M entries max
```

---

## 12. Flow Aggregation & Storage

**Files**:
- `/home/pi/firewalla/sensor/FlowAggregationSensor.js`
- `/home/pi/firewalla/net2/FlowAggrTool.js`

### Aggregation Pipeline

```javascript
class FlowAggregationSensor extends Sensor {
  async scheduledJob() {
    // Retrieve and reset caches atomically
    trafficCache = this.trafficCache;     this.trafficCache = {};
    categoryFlowCache = this.categoryFlowCache; this.categoryFlowCache = {};
    appFlowCache = this.appFlowCache;     this.appFlowCache = {};
    ipBlockCache = this.ipBlockCache;     this.ipBlockCache = {};
    dnsBlockCache = this.dnsBlockCache;   this.dnsBlockCache = {};
    ifBlockCache = this.ifBlockCache;     this.ifBlockCache = {};
    // Process each cache into Redis aggregations
  }
}
```

### Redis Key Format

```
aggrflow:<mac>:<direction>:<interval>:<tick>
  — sorted set: destination → traffic bytes

sumflow:<mac>:<dimension>:<begin>:<end>
  — sorted set: flow summary, max 400 entries per key

syssumflow:<dimension>:<begin>:<end>
  — system-wide summary
```

### FlowAggrTool Key Construction

```javascript
getFlowKey(mac, dimension, interval, ts, fd) {
  const tick = Math.ceil(ts / interval) * interval
  return `aggrflow:${mac}:${dimension}:${fd ? `${fd}:` : ""}${interval}:${tick}`;
}

getSumFlowKey(target, dimension, begin, end, fd) {
  return (!target ? 'syssumflow' :
    target.startsWith('global') ? 'syssumflow'+target.substring(6) : 'sumflow:'+target)
    + (dimension ? ':'+dimension : '')
    + (fd ? ':'+fd : '')
    + ((begin && end) ? `:${begin}:${end}` : '');
}
```

### Flow Trimming

To prevent memory exhaustion, flows are trimmed to the top N by traffic volume:

```javascript
const MAX_FLOW_PER_SUM = 400;

async trimSumFlow(sumFlowKey, options) {
  let max_flow = options.max_flow || MAX_FLOW_PER_SUM;
  // Keep only the max_flow highest-scoring entries
  await rclient.zremrangebyrankAsync(sumFlowKey, 0, -1 * max_flow);
}
```

---

## 13. Flow Stashing & Batched Writes

**Implemented in**: BroDetect.js constructor

### The Problem

Writing every Zeek flow directly to Redis would create enormous write amplification. On a busy network, there can be hundreds of flows per second.

### The Solution: Flow Stashing

Flows are accumulated in memory and flushed periodically:

```javascript
this.flowstash = {
  conn: { keys: new Set(['flow:conn:system']), ignore: {} },
  local: { keys: new Set(['flow:local:system']) },
  dns: { keys: new Set(['flow:dns:system']) }
}
```

### Staggered Rotation

Three flow types are rotated on independent schedules, staggered to flatten Redis IO:

```javascript
// conn: rotated on connFlowstashExpires interval
this.rotateFlowstashTask.conn = setInterval(() => {
  this.rotateFlowStash('conn')
}, config.conn.flowstashExpires * 1000)

// local: staggered by 1/3 of interval
setTimeout(() => {
  this.rotateFlowStash('local')
  this.rotateFlowstashTask.local = setInterval(() => {
    this.rotateFlowStash('local')
  }, config.local.flowstashExpires * 1000)
}, config.local.flowstashExpires * 1000 / 3)

// dns: staggered by 2/3 of interval
setTimeout(() => {
  this.rotateFlowStash('dns')
  this.rotateFlowstashTask.dns = setInterval(() => {
    this.rotateFlowStash('dns')
  }, config.dns.flowstashExpires * 1000)
}, config.dns.flowstashExpires * 1000 * 2 / 3)
```

### Traffic Time Series Cache

Additionally, traffic statistics are batched:

```javascript
this.timeSeriesCache = {}
this.tsWriteInterval = config.conn.tsWriteInterval || 10000  // 10 seconds
this.recordTrafficTask = setInterval(() => {
  this.writeTrafficCache()
}, this.tsWriteInterval)
```

### Long Connection Tracking

Active long-lived connections are tracked in a Map with monitoring for growth:

```javascript
this.activeLongConns = new Map();
// Warn if > 1000 active long connections
// Info if > 500
// Auto-expire if no update for config.connLong.expires seconds
```

---

## 14. App Time Usage Tracking

**File**: `/home/pi/firewalla/sensor/AppTimeUsageSensor.js`

### Architecture

Screen time / app usage tracking works by:
1. Building a **DomainTrie** from cloud-managed app→domain mappings
2. Listening for `MSG_FLOW_ENRICHED` events (from BroDetect)
3. For each flow, check if the domain matches any app in the trie
4. Track usage windows per device per app

```javascript
class AppTimeUsageSensor extends Sensor {
  async run() {
    this.hookFeature("app_time_usage");
    await this.loadConfig(true);  // Load cloud config

    sem.on(Message.MSG_FLOW_ENRICHED, async (event) => {
      if (event && !_.isEmpty(event.flow) && !event.flow.local)
        await this.processEnrichedFlow(event.flow);
    });
  }

  async loadConfig(forceReload = false) {
    await this.loadCloudConfig(forceReload);
    this.appConfs = Object.assign({},
      _.get(this.config, "appConfs", {}),      // Local config
      _.get(this.cloudConfig, "appConfs", {})   // Cloud config (overrides)
    );
    await this.updateSupportedApps();
    this.rebuildTrie();  // Build DomainTrie for fast domain→app lookup
  }

  // Cloud config refreshed daily at 23:30 + random 0-30 min offset
  // (to avoid all devices calling cloud at same time)
}
```

### Key Components

- **DomainTrie**: Efficient trie structure for domain→app matching
- **CIDRTrie**: IP range→app matching (for apps identified by IP range)
- **Cloud config**: Downloaded daily, contains app definitions with domain lists
- **TimeUsageTool**: Helper for calculating active usage windows

---

## 15. Alarm & Policy System

**File**: `/home/pi/firewalla/alarm/AlarmManager2.js`, `/home/pi/firewalla/alarm/Alarm.js`

### Alarm Types

```
ALARM_NEW_DEVICE          — New device joined network
ALARM_DEVICE_BACK_ONLINE  — Device came back online
ALARM_DEVICE_OFFLINE      — Device went offline
ALARM_SPOOFING_DEVICE     — ARP spoofing detected
ALARM_CUSTOMIZED          — Custom alarm
ALARM_CUSTOMIZED_SECURITY — Custom security alarm
ALARM_SURICATA_NOTICE     — Suricata IDS alert
ALARM_VPN_CLIENT_CONNECTION
ALARM_VPN_RESTORE
ALARM_VPN_DISCONNECT
ALARM_VULNERABILITY       — Vulnerability detected
ALARM_BRO_NOTICE          — Zeek (Bro) notice
ALARM_INTEL_REPORT        — Threat intelligence report
ALARM_INTEL               — Threat intelligence match
```

### Alarm Lifecycle

```
alarm_pending → alarm_active → alarm_archive
```

Redis keys:
```
alarm:id              — Auto-incrementing alarm ID
_alarm:<id>           — Alarm details hash
_alarmDetail:<id>     — Extended alarm details
alarm_pending         — Sorted set of pending alarms
alarm_active          — Sorted set of active alarms
alarm_archive         — Sorted set of archived alarms
```

### Custom Alarm Scripts

```javascript
// Alarms can trigger custom scripts:
await exec(`export ALARM_ID=${this.aid}; run-parts ${f.getUserConfigFolder()}/post_alarm_generated.d/`);
```

### Policy System

- **PolicyManager2**: Manages block/allow rules
- **ExceptionManager**: Manages alarm exceptions (whitelist)
- **TrustManager**: Manages trusted entities
- **PolicyDisturbManager**: Manages rule scheduling (time-based rules)

---

## 16. API Architecture

**File**: `/home/pi/firewalla/api/app-local.js`

### Production Lockdown

Most API routes are disabled in production:

```javascript
// Always enabled:
enableSubPath('encipher');
subpath_v1.use('/host', host);

// Only in development/alpha:
if (!firewalla.isProductionOrBeta()) {
  subpath_v1.use('/message', message);
  subpath_v1.use('/ss', shadowsocks);
  subpath_v1.use('/dns', dnsmasq);
  subpath_v1.use('/alarm', alarm);
  subpath_v1.use('/flow', flow);
  subpath_v1.use('/mode', mode);
  subpath_v1.use('/test', test);
  enableSubPath('policy');
  enableSubPath('exception');
  enableSubPath('system');
  enableSubPath('mac');
  enableSubPath('intel');
  enableSubPath('sensor');
  enableSubPath('proapi');
}
```

### Available Routes (when unlocked)

```
GET  /v1/flow/stats          — Flow statistics
GET  /v1/alarm/list           — Active alarms
GET  /v1/alarm/archive_list   — Archived alarms
GET  /v1/alarm/:id            — Specific alarm
POST /v1/alarm/create         — Create alarm
GET  /v1/policy/list          — Policy list
POST /v1/policy/create        — Create policy
POST /v1/policy/create/ip_port
DELETE /v1/policy/:policy     — Delete policy
GET  /v1/system/info          — System info
GET  /v1/system/status        — System status
GET  /v1/system/flow          — System flows
GET  /v1/system/topDownload   — Top downloaders
GET  /v1/system/topUpload     — Top uploaders
GET  /v1/system/recent        — Recent flows
GET  /v1/system/apps          — App list
GET  /v1/system/categories    — Category list
POST /v1/dns/filter/renew     — Renew DNS filter
GET  /v1/dns/status           — DNS status
GET  /v1/test/get             — Test endpoint
```

### Branch Detection

```javascript
function isProduction() {
  return branch.match(/^release_.*/);  // release_6_0 → production
}
function isBeta() {
  return branch.match(/^beta_.*/) && !isAlpha();
}
```

Current branch: `release_6_0` → `isProductionOrBeta()` returns `true` → API locked.

### Unlocking the API

To enable all routes on a production device, modify the check in `app-local.js`:

```bash
# Create persistent script
cat > /home/pi/.firewalla/config/post_main.d/enable-local-api.sh << 'EOF'
#!/bin/bash
sed -i 's/!firewalla.isProductionOrBeta()/true/g' /home/pi/firewalla/api/app-local.js
sudo systemctl restart fireapi
EOF
chmod +x /home/pi/.firewalla/config/post_main.d/enable-local-api.sh
```

**Note**: Scripts in `post_main.d` survive firmware updates.

---

## 17. DNS Filtering Stack

### Components

1. **dnsmasq** (forked) — Primary DNS server on port 53
   - Serves all LAN clients
   - Applies domain block rules
   - Per-interface configuration
   - Cache size: 3000 entries
   - Custom config in `/home/pi/.firewalla/config/dnsmasq_local/`

2. **dnscrypt-proxy** — DNS encryption on port 8854
   - Encrypts upstream DNS queries (DoH/DoT)
   - Running on localhost

3. **DNS Booster** (in Firewalla main process)
   - Intercepts all DNS queries on the LAN
   - Applies filtering rules before forwarding
   - Category-based blocking uses ipset + dnsmasq

### DNS Blocking Mechanism

When a domain is blocked:
1. dnsmasq returns a "black hole" IP instead of the real answer
2. The black hole IPs redirect to local HTTP/HTTPS servers on the Firewalla
3. These servers return block pages or connection resets

```javascript
const redirectHttpPort = 8880;
const redirectHttpsPort = 8883;
const blackHoleHttpPort = 8881;
const blackHoleHttpsPort = 8884;
```

### rsyslog Configuration

DNS and firewall events are logged via rsyslog:

```
/etc/rsyslog.d/12-dnsmasq.conf    — dnsmasq logs
/etc/rsyslog.d/13-dnsmasq.conf    — Additional dnsmasq logs
/etc/rsyslog.d/30-acl-audit.conf  — Firewall audit: [FW_ADT] → /alog/acl-audit.log
/etc/rsyslog.d/31-acl-alarm.conf  — Firewall alarms: [FW_ALM] → /alog/acl-alarm.log
/etc/rsyslog.d/32-quic-log.conf   — QUIC protocol logs
```

---

## 18. Redis Data Model

**Redis version**: 5.0.7 (forked by Firewalla)
**Total keys observed**: 9,341
**Devices tracked**: 197

### Key Patterns

```
# Device Records
host:mac:<MAC>                    — hash: device info (ip, vendor, detect, bname, intf, etc.)
host:user_agent:<MAC>             — set: legacy UA strings (raw JSON)
host:user_agent2:<MAC>            — zset: parsed UA results (scored by timestamp)

# DNS Cache
rdns:ip:<IP>                      — zset: domain names for IP (scored by timestamp)
rdns:domain:<domain>              — set: IP addresses for domain

# Flow Data
flow:conn:<MAC>                   — zset: connection flows (scored by timestamp)
flow:conn:00:00:00:00:00:00       — heartbeat flows
flow:local:system                 — local flow system key
flow:dns:system                   — DNS flow system key
flow:http:outbound:<MAC>          — HTTP outbound flows
flow:x509:<cert_id>               — X.509 certificate data

# Aggregated Flows
aggrflow:<MAC>:<direction>:<interval>:<tick>  — zset: aggregated flows
sumflow:<MAC>:<dimension>:<begin>:<end>       — zset: summary flows (max 400)
syssumflow:<dimension>:<begin>:<end>          — system-wide summary

# Intel (Threat Intelligence)
intel:ip:<IP>                     — hash: threat intel for IP
intel:url:<URL>                   — hash: threat intel for URL
inteldns:<domain>                 — hash: threat intel for domain

# SSL Certificates
ssl:cert:<IP>                     — hash: { subject, server_name }

# Categories
dynamicCategoryDomain:<category>  — zset: detected domains in category
category:<cat>:default:domain     — set: curated domain list
category:<cat>:exclude:domain     — set: excluded domains
category:<cat>:include:domain     — set: user-added domains

# Alarms
alarm:id                          — counter: next alarm ID
_alarm:<id>                       — hash: alarm details
alarm_pending                     — zset: pending alarms
alarm_active                      — zset: active alarms
alarm_archive                     — zset: archived alarms

# Conntrack (flow correlation)
# Keys managed by Conntrack module for MAC→IP→domain correlation

# System Config
sys:bone:info                     — JSON: system info (version, license, JWT, DDNS)
sys:config                        — hash: system configuration
```

### Sample Device Record

```
host:mac:D4:8C:49:48:7B:F0 → {
  mac: "D4:8C:49:48:7B:F0",
  ipv4Addr: "192.168.1.174",
  ipv4: "192.168.1.174",
  uid: "192.168.1.174",
  macVendor: "Espressif Inc.",
  bname: "Espressif Inc.",
  localDomain: "sc07-wx_491715",
  spoofing: "true",
  spoofingTime: "1775277723.086",
  lastActiveTimestamp: "1775277722.969",
  intf_uuid: "fed07258-3464-4230-ad93-1045eb9d1d96",
  intf_mac: "20:6d:31:ee:f6:33",
  stpPort: "eth1",
  dtype: '{"human":0}',
  detect: '{"cloud":{"_vendor":"Espressif Inc."},"_vendor":"Espressif Inc."}',
  _identifyExpiration: "1775301066.781",
  bnameCheckTime: "1775871344.537"
}
```

---

## 19. Network Modes

Firewalla supports multiple network modes:

```javascript
MODE_NONE          — Monitoring only, no enforcement
MODE_AUTO_SPOOF    — ARP spoofing mode (intercepts traffic via ARP)
MODE_MANUAL_SPOOF  — Manual ARP spoofing
MODE_DHCP_SPOOF    — DHCP + ARP spoofing
MODE_DHCP          — DHCP server mode
MODE_ROUTER        — Full router mode (gateway)
```

Functions:
```javascript
isRouterModeOn()     — Router mode active
isSpoofModeOn()      — Any spoof mode active (auto or DHCP)
isAutoSpoofModeOn()  — Auto ARP spoofing
isDHCPSpoofModeOn()  — DHCP-based spoofing
isDHCPModeOn()       — DHCP server mode
```

**Key insight**: In spoof mode, Firewalla uses ARP spoofing to position itself as man-in-the-middle between devices and the gateway. This allows traffic inspection without being the physical bridge/gateway. The `spoofing: true` field in device records indicates which devices are being spoofed.

---

## 20. Integration Points

### A. Zeek Log Forwarding (Best for AIradar)

Firewalla's Zeek logs at `/blog/current/` are JSON format with L2 MAC addresses — identical to what AIradar's `zeek_tailer.py` already parses.

**Option 1: rsyslog forwarding** (real-time, add to post_main.d)
```bash
# /home/pi/.firewalla/config/post_main.d/forward-zeek-logs.sh
cat > /etc/rsyslog.d/50-zeek-forward.conf << 'EOF'
module(load="imfile")

input(type="imfile" File="/blog/current/conn.log" Tag="zeek-conn" Severity="info" Facility="local0")
input(type="imfile" File="/blog/current/dns.log" Tag="zeek-dns" Severity="info" Facility="local0")
input(type="imfile" File="/blog/current/ssl.log" Tag="zeek-ssl" Severity="info" Facility="local0")
input(type="imfile" File="/blog/current/http.log" Tag="zeek-http" Severity="info" Facility="local0")

local0.* @192.168.1.7:514
EOF
systemctl restart rsyslog
```

**Option 2: SSH-based remote tailing** (zero changes on Firewalla)
```bash
ssh pi@192.168.1.138 "tail -F /blog/current/conn.log /blog/current/dns.log" | zeek_tailer.py
```

### B. Redis Access via SSH Tunnel

```bash
ssh -L 6380:localhost:6379 pi@192.168.1.138
# Then: redis-cli -p 6380 keys "host:mac:*"
```

### C. Local API (port 8833)

API is reachable from AIradar (returns 400 Bad Request, not connection refused). Only `/v1/encipher` and `/v1/host` are enabled in production. Full API requires patching `isProductionOrBeta()`.

### D. ACL Audit/Alarm Logs

```
/alog/acl-audit.log  — Firewall events tagged [FW_ADT]
/alog/acl-alarm.log  — Alarm events tagged [FW_ALM]
```
Currently empty on this device (no active block rules).

---

## 21. Key Takeaways for AIradar

### HIGH PRIORITY — Should Implement

#### 1. User-Agent Device Fingerprinting
- Parse Zeek `http.log` for `user_agent` field
- Use Python `device_detector` or `ua-parser` library
- Store detected type/brand/model/OS per MAC
- **Router detection heuristic**: 3+ device types or 5+ OS names from same MAC = router
- This is the single most impactful detection improvement AIradar can make

#### 2. SSL/TLS SNI Processing
- Parse Zeek `ssl.log` for `server_name` field
- SNI reveals the domain even when DNS is encrypted (DoH/DoT)
- Fall back to x509 certificate CN/SAN when SNI is absent
- This directly addresses the DoH bypass problem documented in `project_dns_bypass.md`

#### 3. Hostname→Device Type Mapping
- Build a keyword→device_type dictionary (start with 50-100 entries)
- Match against DHCP hostnames and mDNS names we already capture
- Longest-match-first for specificity
- Examples: "iphone"→phone, "roku"→tv, "echo"→speaker, "macbook"→laptop

#### 4. mDNS Service Parsing
- We already see mDNS traffic in Zeek dns.log (queries to 224.0.0.251)
- Parse service type fields (`_airplay._tcp`, `_hap._tcp`, etc.)
- Extract device names from mDNS TXT records
- OR use Python `zeroconf` library for active mDNS listening

### MEDIUM PRIORITY — Worth Adding

#### 5. Domain Category Lists
- Build curated domain lists per category (AI, gaming, social, streaming, work, etc.)
- Use open-source lists as starting point (many available on GitHub)
- Match during Zeek log processing
- No need for bloom filters at our scale — Python dicts are fine

#### 6. Connection Log Delay Pattern
- Firewalla delays conn.log processing by 2 seconds to allow DNS/HTTP/SSL to populate first
- This ensures domain information is available when the connection is processed
- AIradar could benefit from a similar correlation window

#### 7. Long-Lived Connection Monitoring
- Firewalla's custom Zeek script logs `conn_long.log` every minute for active connections
- Good for detecting persistent connections: VPNs, C2, streaming, tunnels
- We could add this Zeek script to AIradar's Zeek config

#### 8. Flow Stashing Pattern
- Buffer flows in memory, flush to database periodically
- Stagger different flow types to flatten IO
- Useful if AIradar hits SQLite write performance issues

### ARCHITECTURE LESSONS

#### What Firewalla Gets Right
- **Processing order matters**: DNS→HTTP→SSL→Connection (with delays)
- **Multiple detection signals**: Hostname + UA + mDNS + cloud = better than any single source
- **Voting/confidence system**: Most-common value wins, with special cases (router heuristic)
- **Batched writes**: Flow stashing prevents database write amplification
- **Custom Zeek scripts**: Small additions (MAC logging, fast HTTP, long connections) add huge value

#### What We Should NOT Copy
- **Redis as primary store**: SQLite is fine for our scale and gives us persistence
- **Cloud-dependent detection**: Their detection data is proprietary; we need self-contained alternatives
- **ARP spoofing**: We already use a transparent bridge, which is cleaner
- **Bloom filters**: Overkill for our domain count; Python dicts are O(1) with hashing
- **Complex alarm pipeline**: Our current approach is simpler and sufficient

### COMPARISON TABLE

| Aspect | Firewalla | AIradar | Gap |
|--------|-----------|---------|-----|
| Zeek log types processed | conn, dns, ssl, http, x509, notice, intel, knownHosts, signature, connLong | conn, dns | **ssl, http, connLong** |
| Device detection signals | MAC vendor + hostname + UA + mDNS + cloud | MAC vendor + DHCP hostname | **UA, mDNS, hostname keywords** |
| Domain identification | DNS + SNI + HTTP host + x509 CN + conntrack | DNS only | **SNI, HTTP host** |
| Flow correlation | 2s delay + LRU caches + conntrack | Direct DNS→conn | **Correlation window** |
| Domain categorization | Cloud bloom filters + curated lists | Service labelers | **Category lists** |
| Data store | Redis (in-memory, 9K keys) | SQLite (on-disk) | OK as-is |
| Devices tracked | 197 | ~30 | Firewalla sees more (ARP spoof) |
| Custom Zeek scripts | 8 scripts | 0 | **MAC logging, long conn** |

---

## Appendix: Source Code Locations

All paths relative to `/home/pi/firewalla/` on the Firewalla device:

```
net2/BroDetect.js                              — Zeek log processor (1700+ lines)
net2/DNSTool.js                                — DNS cache (rdns:ip, rdns:domain)
net2/IntelTool.js                              — Threat intel lookups
net2/FlowAggrTool.js                           — Flow aggregation helpers
net2/FlowTool.js                               — Flow utilities
net2/Conntrack.js                              — Connection tracking (MAC→IP→domain)
net2/Mode.js                                   — Network mode management

sensor/DeviceIdentificationSensor.js           — Device fingerprinting
sensor/BonjourSensor.js                        — mDNS device discovery
sensor/FastIntelPlugin.js                      — Bloom filter domain classification
sensor/FlowAggregationSensor.js                — Flow rollup scheduler
sensor/AppTimeUsageSensor.js                   — Screen time tracking
sensor/PcapZeekPlugin.js                       — Zeek lifecycle management
sensor/CategoryUpdateSensor.js                 — Category list updates
sensor/CategoryExaminerPlugin.js               — Category matching

control/CategoryUpdater.js                     — Category management
control/CategoryUpdaterBase.js                 — Category base class
control/DomainBlock.js                         — Domain blocking
control/Block.js                               — IP blocking

alarm/Alarm.js                                 — Alarm types
alarm/AlarmManager2.js                         — Alarm lifecycle
alarm/Exception.js                             — Alarm exceptions
alarm/ExceptionManager.js                      — Exception management
alarm/Policy.js                                — Block/allow policies
alarm/PolicyManager2.js                        — Policy lifecycle
alarm/TrustManager.js                          — Trust management

extension/detect/common.js                     — Hostname→device type
extension/detect/appleModel.js                 — Apple model detection
extension/flow/HttpFlow.js                     — HTTP flow processing + UA parsing

api/app-local.js                               — Local API (Express.js)
api/routes/flow.js                             — Flow API routes
api/routes/system.js                           — System API routes
api/routes/alarm.js                            — Alarm API routes
api/routes/policy.js                           — Policy API routes

platform/all/hooks/before_bro/dns-mac-logging.zeek
platform/all/hooks/before_bro/http-fast-logging.zeek
platform/all/hooks/before_bro/bro-long-connection/main.zeek
platform/all/hooks/before_bro/heartbeat-flow/main.zeek
platform/all/hooks/before_bro/zeek-conn-log-filter/main.zeek
platform/all/hooks/before_bro/well-known-server-ports/main.zeek
platform/purple/hooks/before_bro/local.bro     — Main Zeek config
```

---

*This document was generated by reverse-engineering a live Firewalla device via SSH on 2026-04-20. The Firewalla firmware is AGPL-3.0 licensed and the source code is available at https://github.com/firewalla/firewalla.*
