# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T18:01:32Z
**Timeframe:** Approximately 2025-10-24T17:20:02Z to 2025-10-24T18:00:01Z
**Files Used:**
- agg_log_20251024T172002Z.json
- agg_log_20251024T174001Z.json
- agg_log_20251024T180001Z.json

## Executive Summary

This report summarizes 26,154 recorded events from the T-Pot honeypot network. The majority of attacks targeted the Dionaea and Honeytrap honeypots. The most targeted port was 445 (SMB), with a significant volume of traffic from the IP address 114.47.12.143. Several CVEs were detected, with the most frequent being CVE-2002-0013 and CVE-2002-0012. Analysis of Cowrie logs shows multiple attempts to download and execute malicious payloads.

## Detailed Analysis

### Attacks by Honeypot
- **Dionaea:** 12,566
- **Honeytrap:** 4,840
- **Suricata:** 3,890
- **Cowrie:** 2,736
- **Ciscoasa:** 1,689
- **Sentrypeer:** 164
- **Mailoney:** 113
- **ConPot:** 33
- **Redishoneypot:** 35
- **Tanner:** 42
- **H0neytr4p:** 23
- **ElasticPot:** 6
- **Adbhoney:** 5
- **Honeyaml:** 5
- **Heralding:** 3
- **Miniprint:** 2
- **Ipphoney:** 2

### Top Attacking IPs
- 114.47.12.143: 9,748
- 45.171.150.123: 2,165
- 109.205.211.9: 2,156
- 80.94.95.238: 1,562
- 144.130.11.9: 562
- 104.248.51.76: 242
- 14.225.207.171: 280
- 103.145.145.74: 278
- 204.76.203.28: 168
- 193.24.211.28: 192

### Top Targeted Ports/Protocols
- 445: 12,478
- 22: 378
- 5060: 164
- 8333: 152
- 8530/8531: 156
- 5901: 129
- 5903: 127
- 23: 77
- 25: 113

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2019-11500: 5
- CVE-2025-57819: 4
- CVE-1999-0183: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- uname -a
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- echo "root:Obzc2vMXSrm1"|chpasswd|bash

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1,989
- ET HUNTING RDP Authentication Bypass Attempt: 639
- ET DROP Dshield Block Listed Source group 1: 336
- ET SCAN NMAP -sS window 1024: 173
- ET INFO Reserved Internal IP Traffic: 56
- ET SCAN Suspicious inbound to MSSQL port 1433: 29
- ET CINS Active Threat Intelligence Poor Reputation IP: Multiple groups with counts from 8 to 13.

### Users / Login Attempts (Top 5)
- 345gs5662d34/345gs5662d34: 13
- root/Dramenard570314: 4
- root/Dress0w: 4
- root/3245gs5662d34: 4
- root/dragon99: 3

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- None recorded.

### SSH Clients and Servers
- **SSH Clients:** None recorded.
- **SSH Servers:** None recorded.

### Top Attacker AS Organizations
- None recorded.

## Key Observations and Anomalies
- The overwhelming majority of traffic is directed at port 445 (SMB), likely from automated scanners and worms.
- The IP 114.47.12.143 is responsible for a large portion of the total attack volume.
- A significant number of commands executed in the Cowrie honeypot are related to reconnaissance and establishing persistent access via SSH authorized_keys.
- The Adbhoney honeypot detected an attempt to download and execute several variants of the "urbotnetisass" malware.
- CVEs from as far back as 1999 are still being actively exploited.
- No HTTP user agents or SSH client/server strings were captured, suggesting that the attacks on these protocols were likely from automated tools that did not fully establish a session.
