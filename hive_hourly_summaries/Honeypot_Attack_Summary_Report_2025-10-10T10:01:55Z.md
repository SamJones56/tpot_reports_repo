# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T10:01:25Z
**Timeframe:** 2025-10-10T09:20:01Z to 2025-10-10T10:00:01Z
**Files Used:**
- agg_log_20251010T092001Z.json
- agg_log_20251010T094001Z.json
- agg_log_20251010T100001Z.json

## Executive Summary
This report summarizes 14,767 events from three honeypot log files. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. The most frequent attacks originated from IP address 109.237.71.198. The most targeted ports were 22 (SSH) and 445 (SMB). A number of CVEs were detected, with the most common being related to remote code execution.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5738
- **Honeytrap:** 3634
- **Suricata:** 2074
- **Ciscoasa:** 1760
- **Dionaea:** 914
- **Sentrypeer:** 358
- **Tanner:** 98
- **Redishoneypot:** 45
- **H0neytr4p:** 43
- **Mailoney:** 40
- **ElasticPot:** 22
- **ConPot:** 14
- **Honeyaml:** 13
- **Adbhoney:** 13
- **Wordpot:** 1

### Top Attacking IPs
- 109.237.71.198
- 167.250.224.25
- 212.87.220.20
- 143.44.164.80
- 5.250.184.177
- 27.254.192.185
- 88.210.63.16
- 201.186.40.161
- 101.36.113.241
- 172.190.89.127

### Top Targeted Ports/Protocols
- 22
- 445
- 5060
- 5903
- 1433
- 8333
- 5908
- 5909
- 5901
- 80

### Most Common CVEs
- CVE-2018-10562 CVE-2018-10561
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012
- CVE-1999-0183
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- supervisor/supervisor22
- root/Admin123456
- default/654321
- guest/guest13
- test/test1234567
- debian/debian7
- supervisor/112233
- guest/123qwe
- root/WSX@

### Files Uploaded/Downloaded
- gpon8080&ipv=0
- ?format=json
- sh
- Help:Contents

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies
- A significant number of commands are geared towards inspecting the system's hardware (`/proc/cpuinfo`, `lscpu`, `free -m`) and setting up SSH persistence.
- The command `cd /data/local/tmp; ...; ./boatnet.arm7 arm7` suggests an attempt to install a botnet client on an Android-based device.
- The high number of scans for MS Terminal Server and MSSQL on non-standard ports indicates a targeted campaign against these services.
- The presence of CVEs from as far back as 1999 suggests that attackers are still using old exploits, likely to find unpatched systems.
