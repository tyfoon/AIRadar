"""
AI-Radar — Periodic Network Scanner.

Runs nmap and nbtscan in the background to discover device hostnames,
OS info, and device types that passive monitoring (Zeek/p0f) might miss.

Designed to run as an asyncio task alongside zeek_tailer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET

import httpx

DEVICE_API_URL = os.environ.get(
    "AIRADAR_DEVICE_API_URL", "http://localhost:8000/api/devices"
)
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "900"))  # 15 minutes

# Legacy single-subnet var (kept for backwards compatibility).
SCAN_SUBNET = os.environ.get("SCAN_SUBNET", "192.168.1.0/24")


def _resolve_scan_subnets() -> list[str]:
    """Determine the list of subnets to scan.

    Resolution order:
      1. SCAN_SUBNETS env var (comma-separated CIDRs) — multi-VLAN override
      2. SCAN_SUBNET env var (single CIDR) — legacy single-subnet override
      3. Auto-detect from `ip -4 -o addr` — all attached RFC1918 subnets

    Returns a de-duplicated list of CIDR strings.
    """
    subnets: list[str] = []
    seen: set[str] = set()

    def _add(cidr: str) -> None:
        cidr = cidr.strip()
        if not cidr or cidr in seen:
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            print(f"[scanner] Invalid CIDR {cidr!r}, ignoring")
            return
        if not isinstance(net, ipaddress.IPv4Network):
            return
        subnets.append(str(net))
        seen.add(str(net))

    env_multi = os.environ.get("SCAN_SUBNETS", "").strip()
    if env_multi:
        for part in env_multi.split(","):
            _add(part)
        if subnets:
            print(f"[scanner] Using SCAN_SUBNETS from env: {subnets}")
            return subnets

    env_single = os.environ.get("SCAN_SUBNET", "").strip()
    if env_single:
        _add(env_single)
        if subnets:
            print(f"[scanner] Using SCAN_SUBNET from env: {subnets}")
            return subnets

    # Auto-detect from interface addresses
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            try:
                idx = parts.index("inet")
            except ValueError:
                continue
            if idx + 1 >= len(parts):
                continue
            cidr = parts[idx + 1]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            if net.is_loopback or net.is_link_local or not net.is_private:
                continue
            _add(str(net))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        print(f"[scanner] Auto-detect failed: {exc}")

    if subnets:
        print(f"[scanner] Auto-detected subnets: {subnets}")
    else:
        # Final fallback to the hardcoded default to preserve old behaviour
        _add(SCAN_SUBNET)
        print(f"[scanner] Falling back to default: {subnets}")
    return subnets


SCAN_SUBNETS: list[str] = _resolve_scan_subnets()


def _nmap_scan(subnet: str) -> list[dict]:
    """Run nmap -sn with hostname and OS hints, return device list."""
    devices = []
    try:
        result = subprocess.run(
            [
                "nmap", "-sn",       # Ping scan only (no port scan — fast)
                "--host-timeout", "5s",
                "--max-rate", "50",  # Limit to 50 packets/sec to avoid congestion
                "-T3",               # Normal timing (not aggressive)
                "-oX", "-",          # XML output to stdout
                subnet,
            ],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"[scanner] nmap exit {result.returncode}: {result.stderr[:200]}")
            return []

        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            if host.find("status").get("state") != "up":
                continue

            ip = None
            mac = None
            vendor = None
            hostname = None

            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "").lower().replace("-", ":")
                    vendor = addr.get("vendor")

            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hn in hostnames.findall("hostname"):
                    name = hn.get("name", "")
                    if name and not name.endswith(".in-addr.arpa"):
                        # Prefer user-set names, strip .local suffix
                        hostname = name.removesuffix(".local").removesuffix(".lan")
                        break

            if ip:
                entry = {"ip": ip}
                if mac:
                    entry["mac_address"] = mac
                if hostname:
                    entry["hostname"] = hostname
                devices.append(entry)

    except subprocess.TimeoutExpired:
        print("[scanner] nmap scan timed out")
    except (FileNotFoundError, OSError) as exc:
        print(f"[scanner] nmap not available: {exc}")
    except ET.ParseError as exc:
        print(f"[scanner] nmap XML parse error: {exc}")

    return devices


def _nbtscan(subnet: str) -> dict[str, str]:
    """Run nbtscan to get NetBIOS/Windows hostnames. Returns {ip: hostname}."""
    results = {}
    try:
        proc = subprocess.run(
            ["nbtscan", "-s", "\t", subnet],
            capture_output=True, text=True, timeout=30,
        )
        for line in proc.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[1].strip():
                ip = parts[0].strip()
                name = parts[1].strip()
                if name and name != "<unknown>" and not name.startswith("__"):
                    results[ip] = name
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return results


async def _register_devices(client: httpx.AsyncClient, devices: list[dict]) -> int:
    """Post discovered devices to the API. Returns count of updates."""
    updated = 0
    for dev in devices:
        try:
            resp = await client.post(DEVICE_API_URL, json=dev, timeout=5)
            if resp.status_code in (200, 201):
                updated += 1
        except httpx.HTTPError:
            pass
    return updated


async def run_network_scanner() -> None:
    """Periodically scan the local network(s) and register discovered devices.

    Scans all subnets in SCAN_SUBNETS sequentially (to keep network load
    bounded). VLAN-aware: by setting SCAN_SUBNETS in the environment, a
    customer with multiple VLANs can have every segment scanned without
    needing separate sensor instances.
    """
    print(
        f"[scanner] Network scanner started "
        f"(interval={SCAN_INTERVAL}s, subnets={SCAN_SUBNETS})"
    )

    # Wait for the API to be ready and initial traffic to settle
    await asyncio.sleep(30)

    async with httpx.AsyncClient() as client:
        while True:
            try:
                t0 = time.time()
                all_devices: list[dict] = []
                all_ips: set[str] = set()

                loop = asyncio.get_event_loop()

                for subnet in SCAN_SUBNETS:
                    try:
                        nmap_task = loop.run_in_executor(None, _nmap_scan, subnet)
                        nbts_task = loop.run_in_executor(None, _nbtscan, subnet)
                        nmap_devices, nbts_names = await asyncio.gather(
                            nmap_task, nbts_task
                        )
                    except Exception as scan_exc:
                        print(f"[scanner] Scan error on {subnet}: {scan_exc}")
                        continue

                    # Merge nbtscan hostnames into nmap results
                    for dev in nmap_devices:
                        ip = dev.get("ip", "")
                        if not dev.get("hostname") and ip in nbts_names:
                            dev["hostname"] = nbts_names[ip]

                    # Also create entries for IPs only found by nbtscan
                    nmap_ips = {d["ip"] for d in nmap_devices}
                    for ip, name in nbts_names.items():
                        if ip not in nmap_ips:
                            nmap_devices.append({"ip": ip, "hostname": name})

                    # De-dup across subnets (shouldn't normally overlap)
                    for dev in nmap_devices:
                        ip = dev.get("ip")
                        if ip and ip not in all_ips:
                            all_ips.add(ip)
                            all_devices.append(dev)

                if all_devices:
                    updated = await _register_devices(client, all_devices)
                    elapsed = time.time() - t0
                    print(
                        f"[scanner] Discovered {len(all_devices)} devices across "
                        f"{len(SCAN_SUBNETS)} subnet(s), updated {updated} "
                        f"({elapsed:.1f}s)"
                    )
                else:
                    print("[scanner] No devices found in scan")

            except Exception as exc:
                print(f"[scanner] Error: {exc}")

            await asyncio.sleep(SCAN_INTERVAL)
