#!/usr/bin/env python3
"""One-shot script: merge duplicate devices caused by MAC zero-padding change.

Run inside the container:
    docker compose exec airadar python fix_mac_duplicates.py

Or stop the container first and run directly:
    python3 fix_mac_duplicates.py
"""
import sqlite3
import os
from collections import defaultdict

DB_PATH = os.environ.get("AIRADAR_DB_PATH", "/app/data/airadar.db")
# Fallback for running outside the container
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(os.path.dirname(__file__), "data", "airadar.db")


def normalize_mac(mac: str) -> str:
    try:
        parts = mac.lower().replace("-", ":").split(":")
        return ":".join(format(int(p, 16), "02x") for p in parts)
    except (ValueError, AttributeError):
        return mac.lower()


def main():
    print(f"Using database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = OFF")
    c = conn.cursor()

    fk_tables = ["device_ips", "tls_fingerprints"]
    ref_tables = [
        "detection_events", "block_rules", "alert_exceptions",
        "device_baselines", "service_policies",
        "geo_conversations", "device_group_members",
    ]
    all_tables = fk_tables + ref_tables

    # Load all devices
    c.execute(
        "SELECT mac_address, hostname, vendor, display_name, "
        "       first_seen, last_seen FROM devices"
    )
    devices = c.fetchall()

    groups = defaultdict(list)
    for row in devices:
        mac = row[0]
        if not mac or mac.startswith("unknown_"):
            continue
        groups[normalize_mac(mac)].append(row)

    fixed = 0
    merged = 0

    for norm_mac, entries in groups.items():
        if len(entries) == 1 and entries[0][0] == norm_mac:
            continue

        # Keep the richest record (hostname > display_name > vendor)
        entries.sort(
            key=lambda e: (e[1] is not None, e[3] is not None, e[2] is not None),
            reverse=True,
        )
        keeper_mac = entries[0][0]
        earliest_first = min(e[4] for e in entries)
        latest_last = max(e[5] for e in entries if e[5])

        # Merge non-keepers into keeper
        for entry in entries[1:]:
            old_mac = entry[0]
            print(f"  merge {old_mac} → {keeper_mac}")
            for tbl in all_tables:
                c.execute(
                    f"UPDATE {tbl} SET mac_address = ? WHERE mac_address = ?",
                    (keeper_mac, old_mac),
                )
            c.execute(
                "UPDATE alert_exceptions SET destination = ? WHERE destination = ?",
                (keeper_mac, old_mac),
            )
            c.execute("DELETE FROM devices WHERE mac_address = ?", (old_mac,))
            merged += 1

        # Rename keeper to normalized MAC
        if keeper_mac != norm_mac:
            print(f"  rename {keeper_mac} → {norm_mac}")
            for tbl in all_tables:
                c.execute(
                    f"UPDATE {tbl} SET mac_address = ? WHERE mac_address = ?",
                    (norm_mac, keeper_mac),
                )
            c.execute(
                "UPDATE alert_exceptions SET destination = ? WHERE destination = ?",
                (norm_mac, keeper_mac),
            )
            c.execute(
                "UPDATE devices SET mac_address = ?, first_seen = ?, last_seen = ? "
                "WHERE mac_address = ?",
                (norm_mac, earliest_first, latest_last, keeper_mac),
            )
        else:
            c.execute(
                "UPDATE devices SET first_seen = ?, last_seen = ? WHERE mac_address = ?",
                (earliest_first, latest_last, norm_mac),
            )
        fixed += 1

    # Fix destination column in alert_exceptions
    c.execute(
        "SELECT id, destination FROM alert_exceptions "
        "WHERE destination IS NOT NULL AND destination LIKE '%:%'"
    )
    ae_fixed = 0
    for row_id, dest in c.fetchall():
        norm = normalize_mac(dest)
        if norm != dest:
            c.execute(
                "UPDATE alert_exceptions SET destination = ? WHERE id = ?",
                (norm, row_id),
            )
            ae_fixed += 1

    conn.commit()
    conn.execute("PRAGMA foreign_keys = ON")
    conn.close()

    print(f"\nDone: {fixed} MAC group(s) normalized, {merged} duplicate(s) merged, "
          f"{ae_fixed} alert exception destination(s) fixed")


if __name__ == "__main__":
    main()
