# AI-Radar — Family Page Redesign Plan

Status: **ready to execute** (after VLAN Fase 1 is deployed).

Goal: replace the current "Other" page with a focused **Family** page
that gives families and SMBs one pane of glass for lifestyle usage —
social, games, streaming, adult, safe search — and lets them act on
what they see using the blocking flows AI-Radar already has.

This document is the working spec for the implementation. Every section
is scoped so it can be picked up in a new Claude session without having
to re-research the problem space.

---

## 1. Why

The current "Other" page is a grab-bag of widgets. We already cover
AI/cloud/threats/IoT well on their own pages, but the **household
lifestyle side** — which is what actually matters to a parent or a
business owner managing staff — has no home.

Competitors (Firewalla, Circle, Bark, Qustodio, ControlD) cover this
well, and our research identified several features we either don't
have or hide behind unrelated screens. The Family page is where that
story gets told.

Target audience (order of priority):
1. **Parents** — want "what are my kids doing, is it safe, and can I
   stop it without yelling upstairs."
2. **Small business / family office** — want "what is my staff/home
   spending bandwidth and attention on, are we exposed, can I limit
   distractions during work hours."

Explicit non-goals:
- Hard per-app quotas (that's Circle/Qustodio territory — agent-based).
- Screen-time on device (we're network-only, we can't see Netflix on
  cellular or YouTube via 5G hotspot).
- Keystroke logging, content scanning, chat surveillance.

We compete on **transparent, network-level, honest insight + one-click
action**, not on surveillance.

---

## 2. Competitive intake (condensed)

Kept here so we don't re-derive this next session.

| Feature                       | Firewalla | Circle | ControlD | Bark | AI-Radar now | Family page |
|-------------------------------|-----------|--------|----------|------|--------------|-------------|
| App Usage Detection           | ✔         | ✔      | partial  | –    | partial (AI/cloud) | **✔** |
| Per-user (not per-device)     | ✔         | ✔      | ✔        | ✔    | –            | **✔** (Phase 2) |
| Activity time limits          | ✔         | ✔      | ✔        | –    | –            | **✔** (Phase 3) |
| Social Hour / quiet time      | ✔         | –      | partial  | –    | –            | **✔** (Phase 3) |
| Disturb / throttle (no block) | ✔         | –      | –        | –    | –            | **✔** (Phase 4) |
| Kid-facing request flow       | –         | ✔      | –        | ✔    | –            | **✔** (Phase 4 — differentiator) |
| SafeSearch enforcement        | partial   | ✔      | ✔        | ✔    | ✔ (hidden)   | **✔ (surfaced)** |
| Porn / adult category         | ✔         | ✔      | ✔        | ✔    | ✔ (AdGuard)  | **✔ (surfaced)** |
| Category blocklists           | ✔         | ✔      | ✔        | ✔    | partial      | **✔** |
| Filters × Services split      | –         | –      | ✔ (best) | –    | –            | **✔** (inspired by CD) |
| Tiered blocklists (Hagezi)    | –         | –      | ✔        | –    | –            | **✔** |
| Honest "cannot see" badges    | –         | –      | –        | –    | –            | **✔** (unique) |

Three things nobody else does well that we will:
1. **"Cannot see" honesty** — if traffic is QUIC with ECH, say so.
   Do not pretend.
2. **Kid-facing request flow** — instead of silent block, show the
   kid a friendly "this is blocked, ask a parent" page with a link
   that creates a pending request in the parent's dashboard.
3. **Transparent reasoning** — every block shows *which* rule caught
   it, so parents learn what their filters actually do.

---

## 3. Information architecture

Rename **"Other"** → **"Family"** (NL: "Gezin").

Sub-tabs:

```
Family
├── Overview        ← default landing; "what happened today"
├── People          ← per-user view (Phase 2)
├── Categories      ← social / games / streaming / adult / shopping
├── Rules           ← Filters × Services UX (ControlD-style)
└── Requests        ← pending kid/employee unblock requests (Phase 4)
```

Each tab is independently shippable. **Overview + Categories + Rules
in Phase 1**. People, time limits, requests, disturb land in Phase 2/3/4.

---

## 4. Phase 1 — Overview, Categories, Rules (ship first)

### 4.1 Overview tab

Single scrollable page with these blocks, top to bottom:

**A. Today at a glance (4 big cards)**
```
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│ 📱 Social  │ │ 🎮 Games   │ │ 📺 Streaming│ │ 🔞 Adult   │
│ 3h 12m     │ │ 1h 48m     │ │ 4h 05m     │ │ 0 blocked  │
│ ↑ 12% vs  │ │ ↓ 5% vs   │ │ ↑ 32% vs  │ │ ✓ Safe     │
│ 7d avg    │ │ 7d avg     │ │ 7d avg     │ │            │
└────────────┘ └────────────┘ └────────────┘ └────────────┘
```

Each card is clickable → drills into Categories tab pre-filtered.

"Time" is **foreground-weighted connection time**, not raw bytes, so
a single Netflix stream doesn't dwarf an hour of Instagram. See 4.4.

**B. Today's top apps/services**
Horizontal bar chart, top 10, grouped by category colour:
- `Instagram           ████████████████   1h 42m`
- `YouTube             ███████████        1h 12m`
- `Fortnite            ████████           48m`
- ...

Click → filter Categories tab.

**C. Quiet block (security + honesty)**
- "✓ Safe search enforced on 8 of 8 devices"
- "⚠ 2 devices bypassed DNS filter today (DoH on Chrome)"
- "ℹ 34% of traffic is encrypted and unattributed (QUIC/ECH)"

This is the **"cannot see" honesty** line. If we don't know, we say
we don't know. Massive differentiator vs marketing-driven competitors.

**D. Recently blocked**
Last 10 block events, with the rule that caught them:
```
19:42  TikTok          📱 Social     rule: "Quiet hours 19:00-20:30"
19:37  xhamster.com    🔞 Adult      rule: "Adult always blocked"
19:12  epicgames.com   🎮 Games      rule: "Screen time reached"
```
Each row has "Why?" → shows the full rule chain.

### 4.2 Categories tab

Left sidebar = category list (with counts). Right pane = selected
category's detail:

```
[Social]  2h 12m today, 14h 32m this week
─────────────────────────────────────────
Status: ✓ allowed   [Block all] [Quiet hours…] [Limit…]

Top services in this category:
  Instagram      1h 12m      [Block] [Limit] [Allow]
  TikTok         34m         [Block] [Limit] [Allow]
  Snapchat       12m         [Block] [Limit] [Allow]
  …

Devices using this category most:
  📱 Emma's iPhone       1h 45m
  💻 Lounge MacBook      28m
  …
```

Categories covered in Phase 1:
1. **Social** — Instagram, TikTok, Snapchat, Facebook, X/Twitter,
   Reddit, Discord, Pinterest, BeReal, Threads, Mastodon.
2. **Games** — Fortnite, Roblox, Minecraft, Steam, Epic, Xbox Live,
   PlayStation Network, League of Legends, Valorant, Rocket League,
   Clash Royale, Among Us.
3. **Streaming** — Netflix, YouTube, Disney+, HBO Max, Prime Video,
   Twitch, Spotify, Apple Music, Videoland, NPO Start.
4. **Shopping** — Amazon, Bol, Coolblue, Zalando, Shein, Temu,
   AliExpress, Marktplaats, Vinted.
5. **Adult** — via AdGuard's built-in adult category + our own
   curated SNI list as backstop.
6. **News** — NOS, NU.nl, Telegraaf, AD, NRC, BBC, NYT, Reuters.
7. **Dating** — Tinder, Bumble, Hinge, Grindr (important for parents,
   surfacing-only by default, not blocked).

Detection source: **SNI + DNS query log** from AdGuard. Reuse the
existing `SERVICE_RULES` in `zeek_tailer.py` — we already categorise
most of these for the AI/cloud pages, we just need a `family_category`
mapping layer.

### 4.3 Rules tab (ControlD-inspired)

The UX insight from ControlD: separate **"what you filter"** (Filters)
from **"what you explicitly allow or block"** (Services). This is
clearer than Firewalla's single giant target list.

```
Rules
├── Filters                     ← broad category toggles
│   ├── 🎓 Kids-safe preset     [Active on: Emma's iPad, …]
│   ├── 🔞 Adult                [Always block]
│   ├── 📱 Social               [Quiet hours 19:00-20:30]
│   ├── 🎮 Games                [Limit 2h/day on weekdays]
│   └── 🛒 Shopping             [Off]
│
├── Services                    ← explicit per-service overrides
│   ├── ✅ Allow   YouTube       (overrides kids-safe preset)
│   ├── ✅ Allow   Duolingo      (overrides social block)
│   ├── ❌ Block   TikTok        (permanent)
│   └── ❌ Block   Fortnite      (school nights 18:00-21:00)
│
└── Presets                     ← one-click profiles
    ├── 🎓 Kids-safe
    ├── 🌙 Bedtime
    ├── 💼 Work focus
    └── 🎉 Weekend
```

**Priority stack** (highest wins, Firewalla-style):
1. Device-specific Service rule
2. User-specific Service rule
3. Device-specific Filter rule
4. User-specific Filter rule
5. Global Service rule
6. Global Filter rule

Every rule in the list shows which of the above "layer" it sits in,
so conflicts are debuggable. Click a rule → see the test: "Would this
rule block instagram.com on Emma's iPhone right now? → Yes, because…"

### 4.4 Backend changes needed for Phase 1

**A. Service → family-category mapping**

New file `family_categories.py`:

```python
FAMILY_CATEGORIES: dict[str, str] = {
    # service_name (as produced by zeek_tailer) → family category
    "instagram": "social",
    "tiktok": "social",
    # …
    "netflix": "streaming",
    "youtube": "streaming",
    # …
}

# Services that span categories (YouTube = streaming AND social).
# Primary listed first — used for top-line totals.
CATEGORY_ALIASES: dict[str, list[str]] = {
    "youtube": ["streaming", "social"],
}
```

Exposed via helper:
```python
def family_category_for(service: str) -> str | None: ...
def all_family_categories_for(service: str) -> list[str]: ...
```

**B. New DB view / aggregation**

Reuse `GeoConversation` rows where they have a service label and a
local `mac`. No new table needed for Phase 1.

Query pattern:
```sql
SELECT mac, service, SUM(orig_bytes + resp_bytes), COUNT(*) AS conn_cnt,
       SUM(duration_s) AS total_duration
FROM geo_conversations
WHERE ts >= ? AND service IS NOT NULL
GROUP BY mac, service;
```

Then map `service → family_category` in Python.

**"Time" calculation** (weighted, not raw bytes):
- For each (mac, service) in a 5-minute bucket: if conn_cnt > 0, count
  **5 minutes of attention**.
- Sum buckets per category per day.
- This gives "how long was the person *engaged*" rather than "how
  much raw video data flowed". A 2-hour Netflix passive stream ≈ a
  2-hour Instagram scroll on this metric, which is what parents
  actually care about.

This requires `GeoConversation` to carry a coarse timestamp we can
bucket — check that `ts` column exists; if not, add it (see 4.5).

**C. New endpoints**

```
GET  /api/family/overview            → 4 cards, top apps, honesty block
GET  /api/family/category/{name}     → detail view for one category
GET  /api/family/services?q=         → search services (rules autocomplete)
GET  /api/family/rules               → list all filter + service rules
POST /api/family/rules               → create rule
PUT  /api/family/rules/{id}
DELETE /api/family/rules/{id}
POST /api/family/rules/test          → "would this rule block X now?"
GET  /api/family/presets             → kids-safe / bedtime / work / weekend
POST /api/family/presets/{name}/apply
```

All rule create/update/delete calls dispatch to the existing blocking
backends:
- **Category/service block** → AdGuard rewrite/block (reuse
  `adguard_client`).
- **Time-based** → stored in new `FamilyRule` table; enforcer task runs
  every 60s, toggles AdGuard rules on/off.
- **Per-device** → iptables FORWARD rule on MAC (reuse the existing
  `BlockRule` plumbing).

**D. New DB tables**

```python
class FamilyRule(Base):
    __tablename__ = "family_rules"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    kind = Column(String, nullable=False)   # "filter" | "service"
    action = Column(String, nullable=False) # "block" | "allow" | "limit" | "quiet"
    target_type = Column(String, nullable=False)  # "category" | "service" | "domain"
    target_value = Column(String, nullable=False)
    scope_type = Column(String, nullable=False)   # "global" | "user" | "device"
    scope_value = Column(String, nullable=True)   # user_id or mac
    schedule_json = Column(Text, nullable=True)   # e.g. {"days":["mon","tue"], "from":"18:00","to":"21:00"}
    limit_minutes = Column(Integer, nullable=True)  # for action=limit
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    created_by = Column(String, nullable=True)    # for audit

class FamilyRuleEvent(Base):
    """Every time a rule fires, we log it here so the Recent Blocks
    list on Overview has something to display and 'Why blocked?'
    works."""
    __tablename__ = "family_rule_events"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, nullable=False)
    rule_id = Column(Integer, ForeignKey("family_rules.id"))
    mac = Column(String, nullable=True)
    service = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    action_taken = Column(String, nullable=False)  # "blocked" | "limited" | "allowed-override"
```

**E. Frontend**

`static/app.js`:
- `_renderFamily()` — top-level router for the 5 sub-tabs.
- `_renderFamilyOverview()` — 4 cards + top apps + honesty + recent blocks.
- `_renderFamilyCategories()` — sidebar list + detail pane.
- `_renderFamilyRules()` — Filters + Services panels + Presets.
- Rule editor modal — dropdowns for category/service/device/schedule.

`static/index.html`:
- Replace the "Other" nav item with "Family". Keep the old widgets
  that were on "Other" but move them — anything not family-related
  goes to a new "Diagnostics" sub-tab of Settings.

`static/i18n.js`:
- EN + NL strings for every label in the plan above.

### 4.5 Schema migration checklist

Before Phase 1 backend work, verify:
- [ ] `GeoConversation.ts` is a proper DateTime with index — check
      `database.py`.
- [ ] `GeoConversation.service` field exists and gets populated —
      check `zeek_tailer.py` `_record_geo_conversation()`.
- [ ] `SERVICE_RULES` in `zeek_tailer.py` covers every service listed
      in section 4.2 — audit and extend. Bundle missing SNIs with a
      unit test list.
- [ ] AdGuard client exposes a "add blocklist rewrite for category" —
      if not, thin wrapper on top of `adguard_client.py`.

---

## 5. Phase 2 — People (users, not devices)

Families don't think in MAC addresses. They think "Emma", "Sam",
"Dad". This phase introduces a lightweight user layer.

**Model**

```python
class FamilyUser(Base):
    __tablename__ = "family_users"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="member")  # "admin"|"member"|"kid"
    avatar = Column(String, nullable=True)  # emoji or URL
    created_at = Column(DateTime, nullable=False)

class FamilyUserDevice(Base):
    __tablename__ = "family_user_devices"
    user_id = Column(Integer, ForeignKey("family_users.id"), primary_key=True)
    mac = Column(String, primary_key=True)
```

**UI**

- New **People** sub-tab.
- Each user = card with avatar, today's category breakdown pie,
  top services, and quick actions ("Bedtime now", "30 min extra").
- Drag-and-drop device assignment from an "Unassigned devices" drawer.
- Every existing `FamilyRule` gains an optional `scope=user` path.

**Auto-suggest user grouping**: if two devices share Bluetooth LE MAC
rotation patterns, same DHCP hostname root, and overlapping active
hours → suggest grouping them. Opt-in only.

---

## 6. Phase 3 — Time limits, schedules, quiet hours

Three rule actions, all built on top of the `FamilyRule` model from
Phase 1:

**6.1 `action=limit`** — e.g. "max 2h/day on Games". Implemented by
a 60s enforcer loop that:
1. Reads `FamilyRuleEvent` + `GeoConversation` for today.
2. Sums attention-minutes per (scope, target).
3. If ≥ limit, creates a temporary AdGuard block rule with TTL = end
   of day, logs a `FamilyRuleEvent("limited")`.

**6.2 `action=quiet`** — e.g. "Social quiet 19:00-20:30 school nights".
The same enforcer loop toggles the backing rule on schedule.

**6.3 Presets** — ship four:
- **Kids-safe** — adult blocked, safe search on, kids-YT alias.
- **Bedtime** — everything except news + music blocked 22:00-06:00.
- **Work focus** — social + games quieted 09:00-12:00, 13:00-17:00.
- **Weekend** — all limits off.

One-click apply via `POST /api/family/presets/{name}/apply`. Each
preset is a bundle of `FamilyRule` rows that get inserted atomically.
Undo is a reverse atomic delete.

---

## 7. Phase 4 — Differentiators (Disturb, Requests)

### 7.1 Disturb — throttle instead of block

Firewalla's underrated feature. Instead of killing a service, you
throttle it to e.g. 256 kbit/s. The kid gives up on their own
because TikTok buffers, without any "you're blocked" drama.

Implementation: `tc` (traffic control) on the bridge. Per-device, per
service is hard because we can't easily classify flows by SNI at the
`tc` level. But **per-device total** is cheap:

```
tc qdisc add dev br0 root handle 1: htb default 10
tc class add dev br0 parent 1: classid 1:10 htb rate 1Gbit
tc class add dev br0 parent 1: classid 1:20 htb rate 256kbit
# iptables marks packets from MAC X → classid 1:20
iptables -t mangle -A FORWARD -m mac --mac-source aa:bb:cc:dd:ee:ff -j CLASSIFY --set-class 1:20
```

Service-specific throttle is Phase 5 stretch — requires DNS-time
rewrite to a slower upstream or SNI-based classifier.

### 7.2 Kid-facing request flow (the big one)

When a kid hits a blocked page, AdGuard currently serves a bland
"blocked" page. We replace it with a friendly AI-Radar page:

```
┌────────────────────────────────────────────┐
│ 🛡  This is blocked by AI-Radar           │
│                                            │
│ instagram.com                              │
│ Category: Social                           │
│ Rule: Quiet hours until 20:30              │
│                                            │
│ [ Ask dad to unblock for 15 minutes ]      │
│                                            │
│ It's 19:42 now. Quiet time ends at 20:30.  │
└────────────────────────────────────────────┘
```

- Button opens a form: "Why do you need it?" (optional text).
- Submit → creates a `FamilyRequest` row.
- Parent gets a push via Home Assistant / Telegram / email.
- Parent approves → temporary `FamilyRule(action=allow, scope=device,
  target=instagram, expires=now+15min)` is inserted.
- Rule expires automatically; logged in Overview "Recent".

Schema:
```python
class FamilyRequest(Base):
    __tablename__ = "family_requests"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, nullable=False)
    mac = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("family_users.id"), nullable=True)
    target = Column(String, nullable=False)
    category = Column(String, nullable=True)
    reason = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")  # pending|approved|denied|expired
    decided_by = Column(String, nullable=True)
    decided_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
```

Serving the page: we already intercept DNS for blocked domains and
can rewrite them to the AI-Radar block page (we have nginx inside the
container, or we serve from FastAPI directly at `/blocked`). Phase 4
is mostly frontend + new endpoint:
```
GET  /blocked?domain=…&rule=…   → kid-facing HTML
POST /api/family/requests        → create
GET  /api/family/requests        → parent's pending list
POST /api/family/requests/{id}/approve
POST /api/family/requests/{id}/deny
```

Requests sub-tab on the Family page shows pending + history.

---

## 8. Phase 5 — Stretch

Not committed, listed so we remember:
- Per-service throttle (SNI classifier).
- Geo fencing ("block gambling sites on kid devices whenever school
  SSID is in use" — needs location signal we don't yet have).
- Weekly family digest email.
- "Focus mode" — user self-assigns 2h of study; all non-study
  services blocked, survives a reboot, no parent needed.
- Chromecast/TV show detection via mDNS + SNI — "TV watched 4h of
  YouTube Kids content today, 78% was in the 'recommended safe'
  subset".

---

## 9. Rollout order & effort estimate

| Phase | Scope                                      | Effort | Value  |
|-------|--------------------------------------------|--------|--------|
| 1     | Overview + Categories + Rules + mapping    | 4-6 d  | High   |
| 2     | People (users, device grouping)            | 2-3 d  | High   |
| 3     | Time limits + schedules + presets          | 3-4 d  | High   |
| 4     | Disturb + Kid request flow                 | 4-5 d  | **Differentiator** |
| 5     | Stretch goals                              | —      | Later  |

Ship Phase 1 end-to-end (backend + frontend + i18n) **before** moving
to Phase 2. Do not fan out — each phase must be usable on its own.

---

## 10. Files that will change

| File                          | Phase | Why                                           |
|-------------------------------|-------|-----------------------------------------------|
| `family_categories.py`        | 1     | New — service → category mapping              |
| `database.py`                 | 1-4   | New tables + migrations                       |
| `api.py`                      | 1-4   | New `/api/family/*` endpoints + enforcer loop |
| `zeek_tailer.py`              | 1     | Extend SERVICE_RULES for gaps                 |
| `adguard_client.py`           | 1     | Wrappers for category/service block add/remove |
| `static/app.js`               | 1-4   | New Family page render functions              |
| `static/index.html`           | 1     | Rename nav, add sub-tabs                      |
| `static/style.css`            | 1     | Family card grid, rule editor                 |
| `static/i18n.js`              | 1-4   | EN + NL strings                                |
| `docker-compose.yml`          | 4     | Expose `/blocked` page if not already exposed |

---

## 11. Verification

**Phase 1:**
- [ ] Family nav shows, Other is gone (or renamed).
- [ ] Overview cards show non-zero data after an hour of normal use.
- [ ] Click a card → Categories filtered correctly.
- [ ] Create a rule "Block TikTok on Emma's iPad"; open TikTok on
      that device → actually blocked and shows in Recent Blocks
      with the rule name.
- [ ] Create a rule "Social quiet 19:00-19:05"; wait; rule fires and
      expires on time.
- [ ] "Cannot see" honesty line shows QUIC/ECH percentage.

**Phase 2:**
- [ ] Create a user "Emma", assign 2 devices; Overview splits
      correctly per user.

**Phase 3:**
- [ ] Limit "Games 10 minutes today" on a device; play 10 minutes;
      11th minute is blocked; next day, blocked status resets.
- [ ] Apply "Bedtime" preset; check 4 rules created atomically;
      undo; check all 4 removed.

**Phase 4:**
- [ ] Kid hits blocked domain → sees AI-Radar page, not AdGuard's.
- [ ] Submit request → parent dashboard shows pending.
- [ ] Approve → service becomes reachable for exactly 15 minutes.
- [ ] Disturb on a device → actual bandwidth drops to the configured
      cap under `iperf3` test.

---

## 12. Open questions (decide at start of Phase 1)

1. **Attention-minute bucket size**: 5 min is suggested. Test with
   real data; may want 1 min for Games where sessions are shorter.
2. **Category for YouTube**: primary Streaming, secondary Social?
   Or let the user pick per-household?
3. **Adult category data source**: stick with AdGuard's list, add a
   curated SNI allowlist (e.g. medical sites false-positives), or
   subscribe to a third-party list?
4. **Preset storage**: hardcoded in Python, or user-editable JSON
   stored in DB? Start hardcoded, move to DB if users ask.
5. **Kid page branding**: neutral "AI-Radar" or white-label per
   household ("The Jansen family network")?
6. **Users vs devices in rules**: force user-first, or keep
   device-first as default and users as optional convenience?
   → Suggest: device-first default, users as optional grouping
   (lower migration risk).
