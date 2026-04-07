"""
AI-Radar — RITA-inspired Beaconing Detector (v2).

Scans Zeek's conn.log for periodic outbound connections characteristic of
malware C2 (Command & Control) channels.  Uses the same multi-dimensional
scoring approach as RITA (Real Intelligence Threat Analytics):

  1. Group connections by (src_ip, dst_ip, proto, dst_port).
  2. For each group with enough samples, compute:
     - **Time score**: Bowley skewness + MADM of inter-arrival deltas
     - **Data size score**: Bowley skewness + MADM of payload sizes
     - **Connection count score**: density of connections over time
  3. Combine into a 0-100 beacon score.  Threshold: >= 70 = suspicious.

Why Bowley skewness + MADM instead of mean + stddev?
  - Mean/stddev break on a single outlier (network hiccup).
  - Bowley uses quartiles → robust to outliers.
  - Beacons with jitter (Cobalt Strike default: 10-50%) have symmetric
    delta distributions (Bowley ≈ 0) but high stddev (missed by v1).
  - MADM measures tightness around the median, not the mean.
  - Data size scoring catches C2 that randomizes timing but sends
    identical-sized heartbeat packets.

This file does NOT touch the SQLite database.  It returns findings as a
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

# Minimum connections in a group before we even look at it.
MIN_CONNECTIONS = 20

# Minimum mean interval in seconds.  Intervals shorter than this usually
# come from legitimate app keep-alives, streaming heartbeats, or WebSocket
# pings — not malware C2 (which is slower to stay under the radar).
MIN_MEAN_INTERVAL_S = 30.0

# Beacon score threshold (0-100).  >= 70 = suspicious.
SCORE_THRESHOLD = 70

# Well-known protocol/port combinations that naturally produce regular
# traffic but are NOT malicious.  We skip these to avoid false positives.
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
    """True if *ip* is a routable public address."""
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
    if addr.version == 6:
        first_byte = int(addr) >> 120
        if (first_byte & 0xFE) == 0xFC:
            return False
    return True


def _bowley_skewness(values: list[float]) -> float:
    """Compute Bowley (quartile) skewness.  Returns 0.0 on degenerate input.

    Formula: (Q1 + Q3 - 2*Q2) / (Q3 - Q1)
    Range: -1.0 to +1.0.  Near 0 = symmetric (beacon-like).
    """
    if len(values) < 4:
        return 0.0
    q1, q2, q3 = statistics.quantiles(values, n=4)  # Q1, Q2 (median), Q3
    denom = q3 - q1
    if denom == 0:
        return 0.0
    return (q1 + q3 - 2 * q2) / denom


def _madm(values: list[float]) -> float:
    """Median Absolute Deviation about the Median.

    Measures dispersion around the median — robust version of stddev.
    """
    if len(values) < 2:
        return 0.0
    med = statistics.median(values)
    abs_devs = [abs(v - med) for v in values]
    return statistics.median(abs_devs)


# ---------------------------------------------------------------------------
# Scoring (RITA-style multi-dimensional)
# ---------------------------------------------------------------------------

def _time_score(deltas: list[float], duration: float) -> float:
    """Score 0.0-1.0 based on how periodic the inter-arrival times are."""
    if not deltas:
        return 0.0

    # Skewness sub-score: symmetric distribution → high score
    skew = _bowley_skewness(deltas)
    skew_score = 1.0 - abs(skew)

    # MADM sub-score: tight clustering → high score
    # Normalize by 30s — anything with MADM > 30s is clearly not a beacon
    madm_val = _madm(deltas)
    madm_score = max(0.0, 1.0 - madm_val / 30.0)

    # Connection density sub-score: many connections over the period
    # Expect at least 1 connection per 10 seconds of duration for a beacon
    if duration > 0:
        density = len(deltas) / (duration / 10.0)
        conn_score = min(1.0, density)
    else:
        conn_score = 0.0

    return (skew_score + madm_score + conn_score) / 3.0


def _data_size_score(sizes: list[int]) -> float:
    """Score 0.0-1.0 based on how uniform the payload sizes are.

    C2 heartbeats tend to send near-identical packets.
    """
    if not sizes or len(sizes) < 4:
        return 0.0

    float_sizes = [float(s) for s in sizes]

    # Skewness sub-score: symmetric size distribution → high score
    skew = _bowley_skewness(float_sizes)
    skew_score = 1.0 - abs(skew)

    # MADM sub-score: tight size clustering → high score
    # Normalize by 32 bytes — anything with MADM > 32 bytes is varied
    madm_val = _madm(float_sizes)
    madm_score = max(0.0, 1.0 - madm_val / 32.0)

    # Smallness sub-score: C2 heartbeats are typically small
    mode_size = max(statistics.mode(sizes), 1) if sizes else 1
    small_score = max(0.0, 1.0 - mode_size / 65535.0)

    return (skew_score + madm_score + small_score) / 3.0


def _beacon_score(deltas: list[float], sizes: list[int], duration: float) -> float:
    """Composite beacon score 0-100.

    Weights: time analysis 60%, data size analysis 40%.
    Time is weighted higher because it is the strongest C2 indicator.
    """
    ts = _time_score(deltas, duration)
    ds = _data_size_score(sizes)

    # If we have no size data, rely entirely on time
    if not sizes or len(sizes) < 4:
        return round(ts * 100, 1)

    return round((ts * 0.6 + ds * 0.4) * 100, 1)


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _collect_groups(log_path: Path) -> dict[tuple[str, str, str, int], dict]:
    """Read conn.log and bucket timestamps + sizes by (src, dst, proto, port).

    Returns dict mapping group key to {"timestamps": [...], "sizes": [...]}.
    """
    groups: dict[tuple[str, str, str, int], dict] = {}
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
                if not _is_external(dst):
                    continue
                if (proto, port) in SAFE_PORTS:
                    continue

                # Collect orig_bytes (data sent by the internal host)
                orig_bytes_raw = rec.get("orig_bytes") or rec.get("orig_ip_bytes") or "-"
                try:
                    orig_bytes = int(orig_bytes_raw)
                except (TypeError, ValueError):
                    orig_bytes = 0

                key = (src, dst, proto, port)
                if key not in groups:
                    groups[key] = {"timestamps": [], "sizes": []}
                groups[key]["timestamps"].append(ts)
                if orig_bytes > 0:
                    groups[key]["sizes"].append(orig_bytes)

    except FileNotFoundError:
        return {}
    except OSError as exc:
        print(f"[beacon] conn.log read error: {exc}")
        return {}

    return groups


def _analyze_group(data: dict) -> Optional[dict]:
    """Return beacon stats if the group scores above threshold, else None."""
    timestamps = data["timestamps"]
    sizes = data["sizes"]

    if len(timestamps) < MIN_CONNECTIONS:
        return None

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

    duration = timestamps[-1] - timestamps[0]
    score = _beacon_score(deltas, sizes, duration)

    if score < SCORE_THRESHOLD:
        return None

    return {
        "connection_count": len(timestamps),
        "mean_interval_s": round(mean, 2),
        "stddev_s": round(statistics.pstdev(deltas), 3),
        "madm_s": round(_madm(deltas), 3),
        "bowley_skew": round(_bowley_skewness(deltas), 3),
        "score": score,
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
          "src":              "192.168.1.42",
          "dst":              "203.0.113.5",
          "proto":            "tcp",
          "port":             443,
          "connection_count":  142,
          "mean_interval_s":   60.05,
          "stddev_s":          3.41,
          "madm_s":            2.15,
          "bowley_skew":       0.02,
          "score":             87.3,
          "first_ts":          1712345678.0,
          "last_ts":           1712353878.0,
        }

    Parsing runs in a worker thread so the event loop stays responsive.
    """
    base = Path(log_dir or os.environ.get("ZEEK_LOG_DIR", "/app/logs"))
    log_path = base / "conn.log"
    if not log_path.exists():
        print(f"[beacon] conn.log not found at {log_path}")
        return []

    def _do_work() -> list[dict]:
        groups = _collect_groups(log_path)
        findings: list[dict] = []
        for (src, dst, proto, port), data in groups.items():
            hit = _analyze_group(data)
            if hit:
                findings.append({
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "port": port,
                    **hit,
                })
        # Sort: highest score first, then by connection count
        findings.sort(key=lambda f: (-f["score"], -f["connection_count"]))
        return findings

    return await asyncio.to_thread(_do_work)
