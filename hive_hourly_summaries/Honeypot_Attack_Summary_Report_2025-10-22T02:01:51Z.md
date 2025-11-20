# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T02:01:25Z
**Timeframe:** 2025-10-22T01:20:01Z to 2025-10-22T02:00:01Z
**Files Used:**
- agg_log_20251022T012001Z.json
- agg_log_20251022T014002Z.json
- agg_log_20251022T020001Z.json

## Executive Summary

This report summarizes 13,759 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot (6,274), followed by Honeytrap (2,792) and Ciscoasa (1,767). The most frequent attacks originated from the IP address 114.96.87.140, and the most targeted port was 22 (SSH). Several CVEs were detected, with attackers attempting to exploit multiple vulnerabilities. A significant number of shell commands were executed, indicating attempts to establish control over compromised systems.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6,274
- **Honeytrap:** 2,792
- **Ciscoasa:** 1,767
- **Suricata:** 1,686
- **H0neytr4p:** 611
- **Sentrypeer:** 231
- **Dionaea:** 156
- **Mailoney:** 118
- **Tanner:** 40
- **Redishoneypot:** 23
- **ConPot:** 21
- **Miniprint:** 18
- **Adbhoney:** 8
- **Dicompot:** 6
- **Honeyaml:** 5
- **ElasticPot:** 2
- **Ipphoney:** 1

### Top Attacking IPs
- 114.96.87.140
- 72.146.232.13
- 64.225.67.101
- 13.125.88.79
- 114.34.106.146
- 88.210.63.16
- 209.141.47.6
- 107.170.36.5
- 34.128.77.56
- 194.107.115.11

### Top Targeted Ports/Protocols
- 22
- 443
- 5060
- 5903
- 25
- TCP/1433
- 1433
- 5901
- 8333
- TCP/1080

### Most Common CVEs
- CVE-2006-2369
- CVE-2019-11500
- CVE-2025-34036
- CVE-2018-10562, CVE-2018-10561
- CVE-2002-0013, CVE-2002-0012
- CVE-2024-3721
- CVE-1999-0517

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/B
- sa/
- root/B00tyl1c10us
- root/314159
- user/start0504@ujia
- user/sr9ckwRqIQFN
- user/sjfy@2020
- user/sina!@#$
- user/seehu@2020

### Files Uploaded/Downloaded
- gpon80&ipv=0
- 11
- fonts.gstatic.com
- string.js
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- )

### HTTP User-Agents
- No user agents were logged in this period.

### SSH Clients and Servers
- **SSH Clients:** No SSH clients were logged in this period.
- **SSH Servers:** No SSH servers were logged in this period.

### Top Attacker AS Organizations
- No AS organizations were logged in this period.

## Key Observations and Anomalies

- A large number of commands were executed, indicating that attackers were able to gain shell access to the honeypots.
- The command to add an SSH key to the `authorized_keys` file was seen multiple times, suggesting a persistent access attempt.
- The CVEs detected are a mix of old and new vulnerabilities, indicating a wide range of attack vectors.
- The high number of attacks on port 22 (SSH) and the variety of login attempts suggest a sustained brute-force attack campaign.
- The lack of HTTP User-Agents, SSH client/server information, and AS organization data might indicate a limitation in the current logging configuration.
