#!/usr/bin/env bash
# ==============================================================================
# Script: simulate_threats.sh
# Project: P8 — MITRE ATT&CK Threat Hunting with Splunk
# Description: Generates safe, controlled Linux telemetry on ubuntu-p3 to validate
#              hunting hypotheses for T1548.003 (Sudo Abuse) and T1053.003 (Cron).
# Author: Natto Chakma
# Target Host: ubuntu-p3 (192.168.100.9)
# ==============================================================================

set -e

echo -e "\e[1;36m==================================================================\e[0m"
echo -e "\e[1;33m  P8 — LINUX THREAT HUNTING ADVERSARY EMULATION HARNESS           \e[0m"
echo -e "\e[1;36m==================================================================\e[0m"

# 1. Emulate Sudo Telemetry (T1548.003)
echo -e "\n\e[1;37m[1/3] Emulating Sudo Privilege Checking / Invocations (T1548.003)...\e[0m"
sudo -l >/dev/null 2>&1 || true
sudo whoami >/dev/null 2>&1 || true
echo -e "\e[1;32m  [+] Generated auth.log sudo invocation entries.\e[0m"

# 2. Emulate Crontab Inspection & Non-destructive Mutation (T1053.003)
echo -e "\n\e[1;37m[2/3] Emulating Crontab Telemetry (T1053.003)...\e[0m"
crontab -l >/dev/null 2>&1 || true
# Safe temporary crontab touch
(crontab -l 2>/dev/null; echo "# P8-Threat-Hunting-Validation-Check") | crontab -
echo -e "\e[1;32m  [+] Generated cron update telemetry in syslog / auth.log.\e[0m"

# 3. Clean up Crontab
echo -e "\n\e[1;37m[3/3] Cleaning up Crontab Test Entries...\e[0m"
crontab -l | grep -v "P8-Threat-Hunting-Validation-Check" | crontab - 2>/dev/null || true
echo -e "\e[1;32m  [+] Restored clean crontab.\e[0m"

echo -e "\n\e[1;36m==================================================================\e[0m"
echo -e "\e[1;32m  LINUX EMULATION COMPLETE: Telemetry streamed to index=linux_security\e[0m"
echo -e "\e[1;36m==================================================================\e[0m"
