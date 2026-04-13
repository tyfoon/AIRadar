"""
AI-Radar — nDPI Deep Packet Inspection Tailer.

Tails ndpiReader's CSV output to identify applications in encrypted
traffic (Netflix via CloudFront, YouTube QUIC 0-RTT, WhatsApp calls,
etc.) and populates _known_ips so the labeling cascade picks them up.

nDPI labels only fill gaps — they never overwrite existing SNI/DNS/JA4
labels. The "only if absent" guard on _known_ips enforces this.

Run: launched automatically by entrypoint.sh alongside p0f.
"""
from __future__ import annotations

import asyncio
import csv
import ipaddress
import os
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NDPI_OUTPUT_FILE = os.environ.get(
    "NDPI_OUTPUT_FILE",
    os.path.join(os.path.dirname(__file__), "data", "ndpi_flows.csv"),
)

# Dedup: don't re-label the same (mac, ip) within this window
NDPI_DEDUP_SECONDS = 300

# ---------------------------------------------------------------------------
# nDPI protocol name → (service, category) mapping
# ---------------------------------------------------------------------------
# Only map protocols that identify a SPECIFIC service. Generic protocol
# names (TLS, HTTP, DNS, QUIC) are skipped — they don't tell us anything
# beyond what we already know.
#
# Service names MUST match the vocabulary used by SNI/DNS labeling in
# zeek_tailer.py to avoid duplicate services in the dashboard.

NDPI_SERVICE_MAP: dict[str, tuple[str, str]] = {
    # Streaming
    "Netflix":          ("netflix",          "streaming"),
    "YouTube":          ("youtube",          "streaming"),
    "YouTubeUpload":    ("youtube",          "streaming"),
    "Spotify":          ("spotify",          "streaming"),
    "Twitch":           ("twitch",           "streaming"),
    "AmazonVideo":      ("prime_video",      "streaming"),
    "AmazonPrime":      ("prime_video",      "streaming"),
    "DisneyPlus":       ("disney_plus",      "streaming"),
    "HBONow":           ("hbo_max",          "streaming"),
    "DAZN":             ("dazn",             "streaming"),
    "Vimeo":            ("vimeo",            "streaming"),
    "DailyMotion":      ("dailymotion",      "streaming"),
    "Hulu":             ("hulu",             "streaming"),
    "SoundCloud":       ("soundcloud",       "streaming"),

    # Social
    "Facebook":         ("facebook",         "social"),
    "Instagram":        ("instagram",        "social"),
    "TikTok":           ("tiktok",           "social"),
    "Snapchat":         ("snapchat",         "social"),
    "Twitter":          ("twitter",          "social"),
    "Pinterest":        ("pinterest",        "social"),
    "Reddit":           ("reddit",           "social"),
    "LinkedIn":         ("linkedin",         "social"),
    "Discord":          ("discord",          "social"),
    "WhatsApp":         ("whatsapp",         "social"),
    "WhatsAppCall":     ("whatsapp",         "social"),
    "Telegram":         ("telegram",         "social"),
    "Signal":           ("signal",           "social"),
    "Messenger":        ("facebook",         "social"),
    "FacebookMessenger":("facebook",         "social"),
    "LINE":             ("line",             "social"),

    # Communication
    "Teams":            ("microsoft_teams",  "communication"),
    "MicrosoftTeams":   ("microsoft_teams",  "communication"),
    "Zoom":             ("zoom",             "communication"),
    "Skype":            ("microsoft_teams",  "communication"),
    "SkypeTeams":       ("microsoft_teams",  "communication"),
    "Webex":            ("webex",            "communication"),
    "GoogleMeet":       ("google_meet",      "communication"),
    "GoToMeeting":      ("goto_meeting",     "communication"),
    "Slack":            ("slack",            "communication"),

    # AI
    "OpenAI":           ("openai",           "ai"),
    "ChatGPT":          ("openai",           "ai"),

    # Google (bare name + sub-services)
    "Google":           ("google",           "cloud"),
    "GoogleServices":   ("google",           "cloud"),
    "GoogleDocs":       ("google_drive",     "cloud"),
    "PlayStore":        ("play_store",       "cloud"),
    "GoogleMaps":       ("google_maps",      "cloud"),
    "GMail":            ("gmail",            "communication"),

    # Apple (bare name + sub-services)
    "Apple":            ("apple",            "cloud"),
    "AppleiCloud":      ("icloud",           "cloud"),
    "AppleiTunes":      ("apple_music",      "streaming"),
    "ApplePush":        ("apple",            "cloud"),
    "AppleSiri":        ("siri",             "cloud"),
    "iCloudPrivateRelay": ("icloud",         "cloud"),

    # Gaming
    "Steam":            ("steam",            "gaming"),
    "PlayStation":      ("playstation",      "gaming"),
    "Xbox":             ("xbox",             "gaming"),
    "Nintendo":         ("nintendo",         "gaming"),
    "RobloxGame":       ("roblox",           "gaming"),
    "Roblox":           ("roblox",           "gaming"),
    "EpicGames":        ("epic_games",       "gaming"),
    "Fortnite":         ("fortnite",         "gaming"),
    "MinecraftGame":    ("minecraft",        "gaming"),
    "Minecraft":        ("minecraft",        "gaming"),

    # Cloud
    "Dropbox":          ("dropbox",          "cloud"),
    "GoogleDrive":      ("google_drive",     "cloud"),
    "OneDrive":         ("onedrive",         "cloud"),
    "iCloud":           ("icloud",           "cloud"),
    "AppleiCloud":      ("icloud",           "cloud"),
    "GitHub":           ("github",           "cloud"),
    "GitLab":           ("gitlab",           "cloud"),
    "Microsoft365":     ("microsoft_365",    "cloud"),
    "Office365":        ("microsoft_365",    "cloud"),
    "Outlook":          ("outlook",          "communication"),
    "WindowsUpdate":    ("windows_update",   "cloud"),

    # Shopping
    "Amazon":           ("amazon",           "shopping"),
    "eBay":             ("ebay",             "shopping"),

    # News
    "CNN":              ("cnn",              "news"),
    "BBC":              ("bbc",              "news"),
    "Wikipedia":        ("wikipedia",        "news"),
}

# Generic protocol names to SKIP — these don't identify a specific service
_NDPI_SKIP: frozenset[str] = frozenset({
    "TLS", "HTTP", "HTTPS", "DNS", "QUIC", "Unknown", "ICMP", "IGMP",
    "NTP", "DHCP", "SSDP", "MDNS", "LLMNR", "STUN", "DTLS",
    "SSL", "SSH", "FTP", "SMTP", "POP3", "IMAP",
    "Cloudflare", "AmazonAWS", "GoogleCloud", "Azure", "AWS_EC2",
    "Akamai", "Fastly", "CloudFront",
    "TCP", "UDP", "ARP", "NetBIOS", "SMBv1", "SMBv23", "ICMPV6",
    "HTTP_Proxy", "UBNTAC2", "TPLINK_SHP", "TuyaLP",
    "DoH_DoT", "Canonical", "Alibaba", "Tencent",
    "AJP", "DHCPV6", "IMAPS",
    "Cybersec", "AWS_S3",
})

# ---------------------------------------------------------------------------
# IP-only cache for cascade fallback
# ---------------------------------------------------------------------------
# If nDPI identifies an IP as YouTube for ANY device, that identification
# likely applies to other devices too (it's server-side traffic patterns).
# This cache is queried by _label_via_ndpi() in zeek_tailer.py.

_ndpi_ip_cache: dict[str, tuple[str, str]] = {}

# Dedup for _known_ips writes
_ndpi_seen: dict[tuple[str, str], float] = {}  # (mac, ip) → timestamp


def _normalize_ndpi_proto(proto: str) -> str | None:
    """Normalize nDPI protocol name and return the base application name.

    Handles compound names like 'TLS.YouTube', 'QUIC.Google', etc.
    Returns None for generic/skippable protocols.
    """
    if not proto:
        return None

    # Strip common prefixes for compound protocols
    # nDPI uses: TLS.YouTube, QUIC.Google, HTTP.UBNTAC2, IMAPS.GMail,
    # HTTP_Connect.GoogleServices, DTLS.Signal, SSL.Facebook
    for prefix in ("TLS.", "QUIC.", "HTTP.", "SSL.", "DTLS.", "IMAPS.", "HTTP_Connect.", "HTTP_Proxy.", "NetBIOS."):
        if proto.startswith(prefix):
            proto = proto[len(prefix):]
            break

    if proto in _NDPI_SKIP:
        return None

    return proto


def label_via_ndpi(resp_ip: str) -> tuple[str, str] | None:
    """Check the nDPI IP cache for a label.

    Called from zeek_tailer.py's labeling cascade as a fallback.
    Returns (service, category) or None.
    """
    return _ndpi_ip_cache.get(resp_ip)


# ---------------------------------------------------------------------------
# Local IP check — use zeek_tailer's version which handles IPv6 prefixes
# ---------------------------------------------------------------------------

def _is_local_ip(ip: str) -> bool:
    """Return True if the IP is a local network address.

    Uses zeek_tailer's implementation which auto-detects the local IPv6
    prefix (e.g. 2a02:a447:d50b::/48) from interface addresses. Falls
    back to simple RFC1918 check if zeek_tailer isn't available yet.
    """
    try:
        from zeek_tailer import _is_local_ip as _zt_is_local
        return _zt_is_local(ip)
    except ImportError:
        pass
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# CSV output tailer
# ---------------------------------------------------------------------------
# ndpiReader v5's -C flag writes pipe-separated CSV with a header
# starting with '#'. Format:
#   #flow_id|protocol|first_seen|...|src_ip|src_port|dst_ip|dst_port|
#   ndpi_proto_num|ndpi_proto|...
# Delimiter is '|' (pipe), not comma.

# Column indices we care about (set from header on first read)
_col_src_ip: int = -1
_col_dst_ip: int = -1
_col_proto: int = -1


async def tail_ndpi_output(output_path: Path) -> None:
    """Tail ndpiReader's pipe-separated CSV output and populate _known_ips."""
    global _col_src_ip, _col_dst_ip, _col_proto

    print(f"[ndpi] Tailing CSV output: {output_path}")

    # Wait for ndpiReader to write its first batch (60s capture window)
    while True:
        if output_path.exists() and output_path.stat().st_size > 0:
            break
        await asyncio.sleep(2)

    print(f"[ndpi] CSV file detected, starting to parse")
    labeled = 0
    lines_read = 0

    while True:
        try:
            with open(output_path, "r") as f:
                # Read header to discover column positions
                header_line = f.readline()
                if header_line:
                    # Strip leading '#' and parse pipe-separated columns
                    header = header_line.strip().lstrip("#")
                    cols = [c.strip() for c in header.split("|")]
                    for i, col in enumerate(cols):
                        if col == "src_ip":
                            _col_src_ip = i
                        elif col == "dst_ip":
                            _col_dst_ip = i
                        elif col == "ndpi_proto":
                            _col_proto = i

                    if _col_proto >= 0:
                        print(
                            f"[ndpi] Header parsed: proto=col{_col_proto}, "
                            f"src_ip=col{_col_src_ip}, dst_ip=col{_col_dst_ip} "
                            f"({len(cols)} columns)"
                        )
                    else:
                        print(f"[ndpi] WARNING: ndpi_proto column not found in header")
                        print(f"[ndpi] Columns: {cols[:15]}...")
                        await asyncio.sleep(60)
                        continue

                # Seek to end — only process new flows
                f.seek(0, 2)

                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(output_path):
                                break  # file rotated
                        except OSError:
                            break
                        await asyncio.sleep(0.5)
                        continue

                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    lines_read += 1
                    if lines_read == 1:
                        print(f"[ndpi] First flow line received (tailing works)")
                    parts = line.split("|")
                    if len(parts) <= max(_col_src_ip, _col_dst_ip, _col_proto):
                        continue

                    result = _process_csv_flow(
                        parts[_col_src_ip].strip(),
                        parts[_col_dst_ip].strip(),
                        parts[_col_proto].strip(),
                    )
                    if result:
                        labeled += 1
                        if labeled <= 3 or labeled % 100 == 0:
                            print(
                                f"[ndpi] Labeled #{labeled}: "
                                f"{parts[_col_proto]} → {NDPI_SERVICE_MAP.get(_normalize_ndpi_proto(parts[_col_proto]), ('?','?'))[0]} "
                                f"({lines_read} lines read, {len(_ndpi_ip_cache)} IPs cached)"
                            )

                    # Periodic status + breathe
                    if lines_read % 500 == 0:
                        print(
                            f"[ndpi] Status: {lines_read} lines read, "
                            f"{labeled} labeled, {len(_ndpi_ip_cache)} IPs cached"
                        )
                        await asyncio.sleep(0)

        except (OSError, IOError) as exc:
            print(f"[ndpi] CSV read error: {exc}, retrying in 5s...")
            await asyncio.sleep(5)


def _process_csv_flow(src_ip: str, dst_ip: str, proto: str) -> bool:
    """Process a single nDPI CSV flow record.

    Returns True if a new label was injected into _known_ips.
    """
    normalized = _normalize_ndpi_proto(proto)
    if not normalized:
        return False

    mapping = NDPI_SERVICE_MAP.get(normalized)
    if not mapping:
        return False

    service, category = mapping

    # Determine local vs remote IP
    if _is_local_ip(src_ip) and not _is_local_ip(dst_ip):
        remote_ip = dst_ip
        local_ip = src_ip
    elif _is_local_ip(dst_ip) and not _is_local_ip(src_ip):
        remote_ip = src_ip
        local_ip = dst_ip
    else:
        return False  # both local or both remote — skip

    # Update IP-only cache (applies across all devices)
    _ndpi_ip_cache[remote_ip] = (service, category)

    # Look up MAC for the local IP (lazy import to avoid circular deps)
    try:
        from zeek_tailer import _ip_to_mac, _known_ips
    except ImportError:
        return False

    mac = _ip_to_mac.get(local_ip)
    if not mac:
        return False

    # Dedup check
    now = time.time()
    dedup_key = (mac, remote_ip)
    last = _ndpi_seen.get(dedup_key, 0)
    if (now - last) < NDPI_DEDUP_SECONDS:
        return False
    _ndpi_seen[dedup_key] = now

    # Only write if _known_ips doesn't already have an entry
    # (SNI/DNS/JA4 labels are never overwritten)
    if dedup_key not in _known_ips:
        _known_ips[dedup_key] = (service, category, now)
        return True
    else:
        # Already labeled by a higher-trust source — expected
        return False

    return False
