
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T14:01:36Z
**Timeframe:** 2025-10-13T13:20:01Z to 2025-10-13T14:00:01Z
**Files Used:**
- agg_log_20251013T132001Z.json
- agg_log_20251013T134002Z.json
- agg_log_20251013T140001Z.json

## Executive Summary

This report summarizes 13,666 attacks recorded across three honeypot log files. The majority of attacks targeted the Cowrie honeypot, indicating a strong focus on SSH and Telnet services. A significant number of attacks originated from IP address 178.128.232.91. The most common attack vectors include brute-force login attempts and exploitation of known vulnerabilities, particularly CVE-2006-0189. Attackers were observed attempting to gain persistence by adding their SSH keys to the system.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 10497
- Suricata: 1096
- Sentrypeer: 1049
- Honeytrap: 490
- Dionaea: 306
- Miniprint: 56
- Tanner: 41
- Redishoneypot: 25
- Mailoney: 31
- H0neytr4p: 31
- Adbhoney: 11
- Dicompot: 12
- ConPot: 8
- Ipphoney: 5
- Heralding: 3
- Ciscoasa: 2
- ssh-rsa: 2
- Honeyaml: 1

### Top Attacking IPs
- 178.128.232.91: 1247
- 124.225.88.153: 573
- 201.15.225.165: 458
- 121.52.154.238: 468
- 102.223.92.101: 384
- 194.135.25.76: 473
- 103.193.178.68: 473
- 27.112.79.178: 472
- 154.91.170.15: 393
- 178.17.53.209: 320
- 142.93.205.220: 395
- 117.2.142.24: 385
- 172.86.95.115: 338
- 172.86.95.98: 334
- 62.141.43.183: 321
- 91.99.17.180: 252
- 59.98.83.57: 251
- 36.50.54.25: 181
- 52.172.177.191: 179
- 122.160.201.198: 227

### Top Targeted Ports/Protocols
- 22: 1131
- 5060: 1049
- 23: 325
- 445: 228
- 9100: 56
- 80: 45
- UDP/5060: 63
- 25: 27
- 443: 31
- 6379: 25
- 27017: 20
- TCP/1080: 26
- TCP/22: 21
- 3306: 13
- 81: 10

### Most Common CVEs
- CVE-2006-0189: 23
- CVE-2022-27255 CVE-2022-27255: 23
- CVE-2002-0013 CVE-2022-0012: 13
- CVE-2005-4050: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2024-3721 CVE-2024-3721: 1
- CVE-2023-26801 CVE-2023-26801: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 72
- lockr -ia .ssh: 72
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 72
- cat /proc/cpuinfo | grep name | wc -l: 72
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 72
- ls -lh $(which ls): 72
- crontab -l: 72
- uname -m: 72
- uname -a: 72
- whoami: 72
- lscpu | grep Model: 72
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 72
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 29
- Enter new UNIX password: : 33

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 448
- ET SCAN NMAP -sS window 1024: 122
- ET INFO Reserved Internal IP Traffic: 59
- ET VOIP SIP UDP Softphone INVITE overflow: 23
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 23
- GPL INFO SOCKS Proxy attempt: 21
- ET DROP Spamhaus DROP Listed Traffic Inbound group 50: 12
- ET INFO CURL User Agent: 9
- ET SCAN Potential SSH Scan: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 12: 5
- ET CINS Active Threat Intelligence Poor Reputation IP group 61: 5
- ET CINS Active Threat Intelligence Poor Reputation IP group 2: 6
- ET Cins Active Threat Intelligence Poor Reputation IP group 98: 5

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 68
- root/3245gs5662d34: 37
- ftpuser/ftppassword: 13
- deploy/123123: 12
- root/Pa$$w0rd: 6
- root/Qaz123456!: 6
- user/user2013: 6
- root/Root@1234567: 6
- goran/goran: 6
- root/Hk123456: 9
- dev/dev123321: 9
- ubuntu/Test123: 9
- teamcity/123: 7

### Files Uploaded/Downloaded
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

### HTTP User-Agents
- N/A

### SSH Clients and Servers
- N/A
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was observed multiple times, indicating a consistent attempt by attackers to install their own SSH keys for persistent access.
- The `urbotnetisass` malware was downloaded in several different architectures, suggesting a widespread campaign targeting various types of devices.
- The high number of attacks on port 5060 (SIP) suggests a continued interest in VoIP-related vulnerabilities.
