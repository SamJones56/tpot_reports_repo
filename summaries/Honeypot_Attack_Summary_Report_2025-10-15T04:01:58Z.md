
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T04:01:30Z
**Timeframe:** 2025-10-15T03:20:01Z to 2025-10-15T04:00:01Z
**Files Used:**
- agg_log_20251015T032001Z.json
- agg_log_20251015T034001Z.json
- agg_log_20251015T040001Z.json

## Executive Summary

This report summarizes 23,796 events collected from the honeypot network. The majority of attacks were registered on the Cowrie, Honeytrap, and Dionaea honeypots. The most targeted services were SMB on port 445 and SSH on port 22. A significant number of attacks originated from the IP address 180.254.106.11. The most common attack signature detected was related to the DoublePulsar backdoor. Attackers were observed attempting to download and execute malicious payloads.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6361
- Honeytrap: 4532
- Dionaea: 3706
- Suricata: 2422
- Ciscoasa: 1855
- Redishoneypot: 1425
- Sentrypeer: 1635
- Mailoney: 910
- ssh-rsa: 92
- Tanner: 46
- ConPot: 42
- H0neytr4p: 34
- Miniprint: 9
- Honeyaml: 5
- Dicompot: 4
- Adbhoney: 4
- Heralding: 3
- ElasticPot: 1

### Top Attacking IPs
- 180.254.106.11: 3147
- 95.82.195.114: 1521
- 124.236.108.141: 1868
- 206.191.154.180: 1291
- 176.65.141.119: 821
- 117.156.227.3: 465
- 172.86.95.115: 422
- 172.86.95.98: 422
- 150.95.157.171: 399
- 185.243.5.121: 379
- 45.43.55.121: 330
- 62.141.43.183: 321
- 88.210.63.16: 261
- 103.172.204.220: 233
- 222.124.17.227: 359
- 216.10.242.161: 204
- 64.137.9.91: 303
- 51.195.149.120: 224
- 201.76.120.30: 189
- 14.34.157.138: 169

### Top Targeted Ports/Protocols
- 445: 3622
- TCP/445: 1519
- 6379: 1425
- 5060: 1635
- 22: 836
- 25: 910
- 6000: 241
- 5903: 187
- 8333: 159
- 8000: 76
- 5908: 83
- 5909: 81
- 5901: 74
- 80: 39
- TCP/1433: 32
- 23: 32
- TCP/443: 20
- 443: 25
- 1433: 24
- UDP/161: 37

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 32
- CVE-2002-0013 CVE-2024-0012 CVE-1999-0517: 17
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-1999-0517: 1
- CVE-2024-7399 CVE-2024-7399: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 37
- lockr -ia .ssh: 37
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 37
- cat /proc/cpuinfo | grep name | wc -l: 37
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 37
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 37
- ls -lh $(which ls): 36
- which ls: 36
- crontab -l: 36
- w: 36
- uname -m: 36
- cat /proc/cpuinfo | grep model | grep name | wc -l: 36
- top: 36
- uname: 36
- uname -a: 41
- whoami: 36
- lscpu | grep Model: 36
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 36
- Enter new UNIX password: : 23
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 8

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1515
- 2024766: 1515
- ET DROP Dshield Block Listed Source group 1: 449
- 2402000: 449
- ET SCAN NMAP -sS window 1024: 169
- 2009582: 169
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 164
- 2023753: 164
- ET HUNTING RDP Authentication Bypass Attempt: 65
- 2034857: 65
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61
- ET SCAN Suspicious inbound to MSSQL port 1433: 40
- 2010935: 40
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 21
- 2403344: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 21
- 2403345: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 26
- 2403348: 26

### Users / Login Attempts
- root/: 92
- 345gs5662d34/345gs5662d34: 35
- root/Qaz123qaz: 13
- root/123@@@: 13
- root/Password@2025: 10
- root/3245gs5662d34: 12
- debian/debian2004: 6
- default/1234567890: 6
- admin/00000: 6
- supervisor/supervisor2001: 4
- test/000: 4
- root/Tom@7102: 4
- root/064703a82f9c: 4
- nobody/999999: 4
- root/yomama3422: 4
- debian/9999: 4
- admin/5: 4
- root/ecu911.sdt: 4
- config/config2007: 4
- root/ef00e0896c48: 4

### Files Uploaded/Downloaded
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1

### HTTP User-Agents
- No HTTP user-agents were logged in this period.

### SSH Clients
- No SSH clients were logged in this period.

### SSH Servers
- No SSH servers were logged in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this period.

## Key Observations and Anomalies
- The vast majority of attacks were automated and script-based, focusing on well-known vulnerabilities and default credentials.
- The high number of events on port 445, particularly from the IP 180.254.106.11, suggests a widespread campaign targeting SMB services.
- The prevalent `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signature indicates that many attackers are attempting to install this known backdoor.
- A number of commands were executed to download and run payloads from various IP addresses. The downloaded files, such as `arm.urbotnetisass`, are likely malware designed for different architectures.
- The commands also show attempts to gather system information, modify SSH authorized_keys, and disable security measures.
- There is a noticeable lack of data for HTTP User-Agents, SSH clients/servers, and attacker AS organizations. This might be a limitation of the current honeypot configuration or the nature of the attacks.
