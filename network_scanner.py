"""
AI-Radar — Periodic Network Scanner.

Runs nmap and nbtscan in the background to discover device hostnames,
OS info, and device types that passive monitoring (Zeek/p0f) might miss.

Designed to run as an asyncio task alongside zeek_tailer.
"""

from __future__ import annotations

import asyncio
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
SCAN_SUBNET = os.environ.get("SCAN_SUBNET", "192.168.1.0/24")


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
    """Periodically scan the local network and register discovered devices."""
    print(f"[scanner] Network scanner started (interval={SCAN_INTERVAL}s, subnet={SCAN_SUBNET})")

    # Wait for the API to be ready and initial traffic to settle
    await asyncio.sleep(30)

    async with httpx.AsyncClient() as client:
        while True:
            try:
                t0 = time.time()

                # Run nmap and nbtscan in parallel (via thread pool)
                loop = asyncio.get_event_loop()
                nmap_task = loop.run_in_executor(None, _nmap_scan, SCAN_SUBNET)
                nbts_task = loop.run_in_executor(None, _nbtscan, SCAN_SUBNET)

                nmap_devices, nbts_names = await asyncio.gather(nmap_task, nbts_task)

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

                if nmap_devices:
                    updated = await _register_devices(client, nmap_devices)
                    elapsed = time.time() - t0
                    print(
                        f"[scanner] Discovered {len(nmap_devices)} devices, "
                        f"updated {updated} ({elapsed:.1f}s)"
                    )
                else:
                    print("[scanner] No devices found in scan")

            except Exception as exc:
                print(f"[scanner] Error: {exc}")

            await asyncio.sleep(SCAN_INTERVAL)
