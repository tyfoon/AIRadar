"""
AI-Radar — RITA-inspired Beaconing Detector.

Scans Zeek's conn.log for highly periodic outbound connections that are
characteristic of malware C2 (Command & Control) channels. Unlike normal
app traffic — which is bursty and irregular — a beacon "phones home" on
a fixed interval with very low jitter. We detect this by:

  1. Grouping connections by (src_ip, dst_ip, proto, dst_port).
  2. For each group with enough samples, computing the mean interval
     between consecutive timestamps and the standard deviation.
  3. Flagging groups where the mean is > 30s (slower than keep-alives)
     AND the stddev is very tight (< 2s, i.e. "boringly regular").

This file does NOT touch the SQLite database. It returns findings as a
list of dicts and the caller (api.py) decides what to persist.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import statistics
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------

# Minimum connections in a group before we even look at it. RITA uses
# 20-30; we use 30 to stay conservative and reduce noise on a home network.
MIN_CONNECTIONS = 30

# Minimum mean interval in seconds. Intervals shorter than this usually
# come from legitimate app keep-alives, streaming heartbeats, or WebSocket
# pings — not malware C2 (which is slower to stay under the radar).
MIN_MEAN_INTERVAL_S = 30.0

# Maximum standard deviation of intervals in seconds. A beacon is
# "boringly regular" — its inter-arrival times cluster tightly around
# the mean. 2 seconds catches classic malware with <= 2s jitter.
MAX_STDDEV_S = 2.0

# Well-known protocol/port combinations that naturally produce regular
# traffic but are NOT malicious. We skip these to avoid false positives.
SAFE_PORTS: set[tuple[str, int]] = {
    ("udp", 53),    # DNS
    ("tcp", 53),    # DNS over TCP
    ("udp", 123),   # NTP
    ("udp", 67),    # DHCP
    ("udp", 68),    # DHCP
    ("udp", 5353),  # mDNS
    ("udp", 1900),  # SSDP
    ("udp", 137),   # NetBIOS name service
    ("udp", 138),   # NetBIOS datagram
    ("tcp", 139),   # NetBIOS session
    ("tcp", 445),   # SMB
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_external(ip: str) -> bool:
    """True if *ip* is a routable public address we care about.

    We only flag beacons whose destination is the public internet —
    LAN-to-LAN traffic produces plenty of regular patterns (SMB,
    printers, Unifi controllers) that are not security-relevant.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    # IPv6 Unique Local Address (fc00::/7) — treat as private
    if addr.version == 6:
        first_byte = int(addr) >> 120
        if (first_byte & 0xFE) == 0xFC:
            return False
    return True


def _collect_groups(log_path: Path) -> dict[tuple[str, str, str, int], list[float]]:
    """Read conn.log and bucket timestamps by (src, dst, proto, port)."""
    groups: dict[tuple[str, str, str, int], list[float]] = {}
    fields: list[str] = []

    try:
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                if not fields:
                    continue

                parts = line.rstrip("\n").split("\t")
                if len(parts) != len(fields):
                    continue
                rec = dict(zip(fields, parts))

                try:
                    ts = float(rec.get("ts", "0"))
                except (TypeError, ValueError):
                    continue

                src = rec.get("id.orig_h") or ""
                dst = rec.get("id.resp_h") or ""
                proto = (rec.get("proto") or "").lower()
                port_raw = rec.get("id.resp_p") or "0"
                try:
                    port = int(port_raw)
                except ValueError:
                    continue

                if not src or not dst or not proto:
                    continue

                # Skip LAN-to-LAN traffic and reserved addresses
                if not _is_external(dst):
                    continue

                # Skip legitimately periodic services
                if (proto, port) in SAFE_PORTS:
                    continue

                key = (src, dst, proto, port)
                groups.setdefault(key, []).append(ts)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        print(f"[beacon] conn.log read error: {exc}")
        return {}

    return groups


def _analyze_group(timestamps: list[float]) -> Optional[dict]:
    """Return beacon stats if the group's intervals look periodic, else None."""
    if len(timestamps) < MIN_CONNECTIONS:
        return None

    # Sort just in case (conn.log is usually append-ordered but we cannot
    # assume perfect monotonicity across Zeek workers).
    timestamps.sort()

    deltas = [
        t2 - t1
        for t1, t2 in zip(timestamps, timestamps[1:])
        if t2 > t1
    ]
    if len(deltas) < MIN_CONNECTIONS - 1:
        return None

    mean = statistics.mean(deltas)
    if mean < MIN_MEAN_INTERVAL_S:
        return None

    # pstdev (population stddev) because we're treating the observed
    # intervals as the complete set, not a sample.
    stddev = statistics.pstdev(deltas)
    if stddev > MAX_STDDEV_S:
        return None

    return {
        "connection_count": len(timestamps),
        "mean_interval_s": round(mean, 2),
        "stddev_s": round(stddev, 3),
        "first_ts": timestamps[0],
        "last_ts": timestamps[-1],
    }


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

async def run_beacon_analysis(log_dir: Optional[str] = None) -> list[dict]:
    """Scan conn.log and return a list of beaconing findings.

    Each finding is a dict:
        {
          "src":             "192.168.1.42",
          "dst":             "203.0.113.5",
          "proto":           "tcp",
          "port":            443,
          "connection_count": 142,
          "mean_interval_s": 60.05,
          "stddev_s":        0.12,
          "first_ts":        1712345678.0,
          "last_ts":         1712353878.0,
        }

    Parsing runs in a worker thread so the event loop stays responsive
    even on large conn.log files.
    """
    base = Path(log_dir or os.environ.get("ZEEK_LOG_DIR", "/app/logs"))
    log_path = base / "conn.log"
    if not log_path.exists():
        print(f"[beacon] conn.log not found at {log_path}")
        return []

    def _do_work() -> list[dict]:
        groups = _collect_groups(log_path)
        findings: list[dict] = []
        for (src, dst, proto, port), timestamps in groups.items():
            hit = _analyze_group(timestamps)
            if hit:
                findings.append({
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "port": port,
                    **hit,
                })
        # Sort: most suspicious (lowest stddev) first
        findings.sort(key=lambda f: (f["stddev_s"], -f["connection_count"]))
        return findings

    return await asyncio.to_thread(_do_work)
