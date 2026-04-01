"""
AI-Radar — p0f Passive OS Fingerprinting Tailer.

Runs p0f in the background and tails its log output to extract OS
fingerprints, device class, and network distance for each source IP.
Updates device records in the API.

Usage:
    python3 p0f_tailer.py [--interface en0]

Or import and call `start_p0f_tailer()` as an asyncio task.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVICE_API_URL = os.environ.get(
    "AIRADAR_DEVICE_API_URL", "http://localhost:8000/api/devices"
)
P0F_BIN = os.environ.get("P0F_BIN", "/opt/homebrew/sbin/p0f")
P0F_FP_DB = os.environ.get("P0F_FP_DB", "/opt/homebrew/etc/p0f/p0f.fp")
P0F_INTERFACE = os.environ.get("P0F_INTERFACE", "en0")
P0F_LOG_FILE = os.environ.get(
    "P0F_LOG_FILE",
    os.path.join(os.path.dirname(__file__), "data", "p0f.log"),
)

# Dedup: don't update the same IP more than once per interval
UPDATE_INTERVAL_SECONDS = 300  # 5 minutes
_last_update: dict[str, float] = {}  # ip → timestamp

# ---------------------------------------------------------------------------
# p0f log line parser
# ---------------------------------------------------------------------------
# p0f log format (one line per event):
#   <date/time> mod=syn|mtu|http cli=1.2.3.4/12345 srv=5.6.7.8/443 subj=cli os=Linux 5.x dist=1 params=none raw_sig=...
#   or for SYN+ACK:
#   <date/time> mod=syn cli=1.2.3.4/12345 srv=5.6.7.8/443 subj=srv os=Windows 10.x dist=0 ...

# We care about lines where subj=cli (the client, i.e. our local device)
_P0F_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"mod=(?P<mod>\S+)\s+"
    r"cli=(?P<cli_ip>[^/]+)/(?P<cli_port>\d+)\s+"
    r"srv=(?P<srv_ip>[^/]+)/(?P<srv_port>\d+)\s+"
    r"subj=(?P<subj>\w+)\s+"
    r"(?P<rest>.*)"
)

_OS_RE = re.compile(r"os=(?P<os>[^|]+?)(?:\s+dist=|\s+params=|\s+raw_sig=|$)")
_DIST_RE = re.compile(r"dist=(?P<dist>\d+)")


def _parse_p0f_line(line: str) -> dict | None:
    """Parse a p0f log line into a structured dict.

    Returns None if the line can't be parsed or isn't relevant.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _P0F_LINE_RE.match(line)
    if not m:
        return None

    subj = m.group("subj")
    rest = m.group("rest")

    # We want the subject IP (the device being fingerprinted)
    if subj == "cli":
        ip = m.group("cli_ip")
    elif subj == "srv":
        ip = m.group("srv_ip")
    else:
        return None

    # Extract OS
    os_match = _OS_RE.search(rest)
    if not os_match:
        return None
    os_full = os_match.group("os").strip()
    if os_full == "???" or os_full.startswith("???"):
        return None

    # Extract distance
    dist_match = _DIST_RE.search(rest)
    distance = int(dist_match.group("dist")) if dist_match else None

    # Parse OS into name + version
    os_name, os_version = _parse_os_label(os_full)

    # Infer device class from OS
    device_class = _infer_device_class(os_full, os_name)

    return {
        "ip": ip,
        "os_name": os_name,
        "os_version": os_version,
        "os_full": os_full,
        "device_class": device_class,
        "network_distance": distance,
        "mod": m.group("mod"),
    }


def _parse_os_label(os_full: str) -> tuple[str, str | None]:
    """Split p0f OS label into (name, version).

    Examples:
        'Linux 5.x'          → ('Linux', '5.x')
        'Mac OS X 10.x'      → ('macOS', '10.x')
        'Windows 10.x'       → ('Windows', '10.x')
        'Windows NT kernel'   → ('Windows', 'NT kernel')
        'iOS'                 → ('iOS', None)
    """
    # Normalize common p0f labels
    label_map = {
        "Mac OS X": "macOS",
        "Mac OS": "macOS",
        "Apple iOS": "iOS",
        "Apple iPadOS": "iPadOS",
    }

    for prefix, normalized in label_map.items():
        if os_full.startswith(prefix):
            version = os_full[len(prefix):].strip() or None
            return (normalized, version)

    # Generic: split on first space that precedes a version-like string
    parts = os_full.split(" ", 1)
    if len(parts) == 2:
        return (parts[0], parts[1])
    return (os_full, None)


def _infer_device_class(os_full: str, os_name: str) -> str:
    """Guess device class from OS fingerprint."""
    lower = os_full.lower()

    if "ios" in lower or "iphone" in lower:
        return "phone"
    if "ipados" in lower or "ipad" in lower:
        return "tablet"
    if "android" in lower:
        return "phone"
    if "windows" in lower:
        return "laptop"
    if "mac os" in lower or os_name == "macOS":
        return "laptop"
    if "linux" in lower:
        # Linux can be anything — server, IoT, laptop
        return "computer"
    if "freebsd" in lower or "openbsd" in lower:
        return "server"
    if "smart" in lower or "embedded" in lower:
        return "iot"

    return "unknown"


# ---------------------------------------------------------------------------
# Local IP filter — only fingerprint devices on our network
# ---------------------------------------------------------------------------

def _is_local_ip(ip: str) -> bool:
    """Return True if the IP is a private / link-local address."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# API updater
# ---------------------------------------------------------------------------

async def _update_device_fingerprint(
    client: httpx.AsyncClient, data: dict
) -> None:
    """POST fingerprint data to the API."""
    ip = data["ip"]

    # Only fingerprint local devices, not remote servers
    if not _is_local_ip(ip):
        return

    # Dedup check
    now = time.time()
    last = _last_update.get(ip, 0)
    if (now - last) < UPDATE_INTERVAL_SECONDS:
        return
    _last_update[ip] = now

    payload = {
        "ip": ip,
        "os_name": data["os_name"],
        "os_version": data["os_version"],
        "os_full": data["os_full"],
        "device_class": data["device_class"],
        "network_distance": data["network_distance"],
    }

    try:
        resp = await client.post(
            f"{DEVICE_API_URL}/fingerprint",
            json=payload,
            timeout=5,
        )
        if resp.status_code == 200:
            print(
                f"[p0f] {ip} → {data['os_name']} {data.get('os_version', '')}"
                f" ({data['device_class']}, dist={data.get('network_distance', '?')})"
            )
        else:
            print(f"[p0f] API {resp.status_code} for {ip}: {resp.text[:200]}")
    except httpx.HTTPError as exc:
        print(f"[p0f] API error for {ip}: {exc}")


# ---------------------------------------------------------------------------
# Log tailer
# ---------------------------------------------------------------------------

async def _tail_p0f_log(log_path: Path, client: httpx.AsyncClient) -> None:
    """Tail the p0f log file and process new lines."""
    print(f"[p0f] Tailing log: {log_path}")

    while True:
        if not log_path.exists():
            await asyncio.sleep(2)
            continue

        try:
            with open(log_path, "r") as f:
                # Seek to end
                f.seek(0, 2)

                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if f.tell() > os.path.getsize(log_path):
                                break  # file rotated
                        except OSError:
                            break
                        await asyncio.sleep(0.5)
                        continue

                    data = _parse_p0f_line(line)
                    if data:
                        await _update_device_fingerprint(client, data)

        except (OSError, IOError) as exc:
            print(f"[p0f] Log read error: {exc}, retrying in 5s…")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# p0f process manager
# ---------------------------------------------------------------------------

async def _start_p0f_process(interface: str, log_file: str) -> subprocess.Popen | None:
    """Start p0f as a background process."""
    if not os.path.exists(P0F_BIN):
        print(f"[p0f] ⚠️  p0f binary not found at {P0F_BIN}")
        print(f"[p0f]    Install with: brew install p0f")
        return None

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove old log so p0f starts fresh
    if log_path.exists():
        log_path.unlink()

    cmd = [
        P0F_BIN,
        "-i", interface,
        "-f", P0F_FP_DB,
        "-o", str(log_path),
        "-p",  # Promiscuous mode — see all traffic on the network
    ]

    print(f"[p0f] Starting: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give it a moment to start
        await asyncio.sleep(1)

        if proc.poll() is not None:
            # Process exited immediately — probably a permission issue
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            print(f"[p0f] ⚠️  p0f exited immediately (code {proc.returncode})")
            if stderr:
                print(f"[p0f]    stderr: {stderr.strip()}")
            if "permission" in stderr.lower() or proc.returncode != 0:
                print(f"[p0f]    💡 Try running with sudo, or set capabilities:")
                print(f"[p0f]       sudo setcap cap_net_raw+ep {P0F_BIN}")
            return None

        print(f"[p0f] ✅ p0f running (PID {proc.pid})")
        return proc

    except FileNotFoundError:
        print(f"[p0f] ⚠️  p0f not found at {P0F_BIN}")
        return None
    except PermissionError:
        print(f"[p0f] ⚠️  Permission denied. Try: sudo python3 p0f_tailer.py")
        return None
    except Exception as exc:
        print(f"[p0f] ⚠️  Failed to start p0f: {exc}")
        return None


# ---------------------------------------------------------------------------
# Public API: start the p0f tailer as an asyncio task
# ---------------------------------------------------------------------------

async def start_p0f_tailer(
    interface: str | None = None,
    log_file: str | None = None,
) -> None:
    """Start p0f and tail its output. Designed to run as an asyncio task.

    Can be called from zeek_tailer.py or run standalone.
    """
    iface = interface or P0F_INTERFACE
    logf = log_file or P0F_LOG_FILE
    log_path = Path(logf)

    proc = await _start_p0f_process(iface, logf)
    if not proc:
        print("[p0f] ⚠️  p0f tailer disabled (could not start p0f)")
        # Still try to tail existing log file in case p0f was started externally
        # Wait a bit and check if the log file appears
        for _ in range(5):
            await asyncio.sleep(2)
            if log_path.exists():
                print("[p0f] Found existing p0f log file, tailing...")
                break
        else:
            print("[p0f] No p0f log file found. p0f tailer exiting.")
            return

    try:
        async with httpx.AsyncClient() as client:
            await _tail_p0f_log(log_path, client)
    finally:
        if proc and proc.poll() is None:
            print("[p0f] Stopping p0f process...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


# ---------------------------------------------------------------------------
# Lightweight log-only tailer (for embedding in zeek_tailer.py)
# ---------------------------------------------------------------------------

async def tail_p0f_standalone(log_path: Path) -> None:
    """Tail an existing p0f log file (p0f started externally with sudo).

    This is a simpler version of start_p0f_tailer that doesn't try to
    start the p0f process itself — it just watches the log file.
    """
    print(f"[p0f] Watching for p0f log at: {log_path}")
    async with httpx.AsyncClient() as client:
        await _tail_p0f_log(log_path, client)


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Radar p0f Tailer")
    parser.add_argument(
        "-i", "--interface",
        default=P0F_INTERFACE,
        help=f"Network interface to monitor (default: {P0F_INTERFACE})",
    )
    parser.add_argument(
        "-o", "--log-file",
        default=P0F_LOG_FILE,
        help=f"p0f log file path (default: {P0F_LOG_FILE})",
    )
    args = parser.parse_args()

    try:
        asyncio.run(start_p0f_tailer(interface=args.interface, log_file=args.log_file))
    except KeyboardInterrupt:
        print("\n[p0f] Shutting down.")
