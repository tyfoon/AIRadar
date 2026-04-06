#!/bin/bash
# AI-Radar: iptables LOG rules for CrowdSec port scan detection.
# Logs inbound NEW connections so CrowdSec's iptables-scan-multi_ports
# scenario can detect port scanning and HTTP probing.
# Rate-limited to 10/min to prevent log flooding.

# Clean up any existing AI-Radar rules
iptables -D INPUT -m comment --comment "airadar-log" -j LOG 2>/dev/null

# Log new inbound connections (rate-limited)
iptables -I INPUT -m state --state NEW -m limit --limit 10/min -m comment --comment "airadar-log" -j LOG --log-prefix "[AIRADAR] " --log-level 4

echo "[airadar] iptables LOG rules installed for CrowdSec port scan detection"
