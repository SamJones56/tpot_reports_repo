
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T17:01:36Z
**Timeframe:** 2025-10-22T16:20:01Z to 2025-10-22T17:00:01Z
**Files Used:**
- agg_log_20251022T162001Z.json
- agg_log_20251022T164001Z.json
- agg_log_20251022T170001Z.json

## Executive Summary
This report summarizes honeypot activity over a short timeframe, revealing a high volume of automated attacks. A total of 11,611 events were recorded across various honeypots. The majority of attacks were captured by the Dionaea and Cowrie honeypots, indicating a strong focus on SMB/CIFS and SSH services. A single IP address, 182.8.161.75, was responsible for a significant portion of the attack traffic, primarily targeting port 445. Several CVEs were detected, and attackers attempted numerous commands, many of which were related to establishing persistent access via SSH.

## Detailed Analysis

### Attacks by Honeypot
- Dionaea: 4353
- Cowrie: 3336
- Ciscoasa: 1729
- Honeytrap: 1197
- Suricata: 467
- Sentrypeer: 380
- Tanner: 56
- Mailoney: 55
- Redishoneypot: 18
- H0neytr4p: 7
- Honeyaml: 6
- ElasticPot: 4
- Adbhoney: 2
- Ipphoney: 1

### Top Attacking IPs
- 182.8.161.75: 4233
- 62.210.114.122: 357
- 104.248.91.96: 350
- 89.39.246.58: 341
- 103.192.198.70: 248
- 14.225.220.107: 287
- 34.175.118.185: 288
- 34.122.106.61: 272
- 107.150.112.242: 188
- 118.145.189.160: 262
- 185.243.5.146: 192
- 107.170.36.5: 154
- 106.12.128.54: 155
- 185.243.5.152: 137
- 68.183.149.135: 112
- 141.52.36.57: 85
- 167.250.224.25: 68
- 129.13.189.202: 60
- 95.188.91.101: 45
- 5.189.173.63: 46

### Top Targeted Ports/Protocols
- 445: 4237
- 22: 457
- 5060: 380
- 8333: 157
- 1433: 97
- 5904: 78
- 5905: 76
- 25: 52
- 80: 52
- 5901: 50
- 5984: 58
- TCP/22: 42
- 5902: 39
- 5903: 37
- 6379: 15
- 23: 16
- 1434: 34

### Most Common CVEs
- CVE-2021-3449: 5
- CVE-2019-11500: 4
- CVE-2005-4050: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 18
- cat /proc/cpuinfo | grep name | wc -l: 18
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 18
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 18
- ls -lh $(which ls): 18
- which ls: 18
- crontab -l: 18
- w: 18
- uname -m: 18
- cat /proc/cpuinfo | grep model | grep name | wc -l: 18
- top: 18
- uname: 18
- uname -a: 18
- whoami: 18
- lscpu | grep Model: 18
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 18
- Enter new UNIX password: : 13
- Enter new UNIX password:: 13
- tftp; wget; /bin/busybox WZCQR: 1
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh: 1

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 123
- 2402000: 123
- ET SCAN NMAP -sS window 1024: 76
- 2009582: 76
- ET INFO Reserved Internal IP Traffic: 40
- 2002752: 40
- ET SCAN Potential SSH Scan: 26
- 2001219: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 14
- 2403302: 14
- ET SCAN Suspicious inbound to MSSQL port 1433: 10
- 2010935: 10
- ET INFO CURL User Agent: 7
- 2002824: 7
- ET EXPLOIT Possible Dovecot Memory Corruption Inbound (CVE-2019-11500): 4
- 2033451: 4
- ET EXPLOIT Possible OpenSSL TLSv1.2 DoS Inbound (CVE-2021-3449): 5
- 2032358: 5
- ET INFO Apache Solr System Information Request: 6
- 2031504: 6

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 17
- root/3245gs5662d34: 4
- pq/123: 3
- samira/samira123: 3
- rfarias/rfarias: 3
- rfarias/3245gs5662d34: 3
- root/123456ab@: 3
- root/: 3
- root/root///: 2
- root/bsdi911: 2
- www/123321: 2
- root/Password$1: 2
- root/pass@123: 2
- nabu/nabu: 2
- root/pass123$: 2
- divya/divya123: 2
- root/Bt1243: 2
- root/qazwsx@123: 2
- root/btf: 2
- root/qwerty98: 2
- root/dr123456: 2
- yuli/yuli123: 2
- root/lu123456: 2
- omar/omar123: 2
- dcuesta/dcuesta: 2
- admin/1234: 2
- test123/qwe123: 2
- phpmyadmin/phpmyadmin123: 2
- root/Bto159pbX: 2
- postgres/secret: 2
- asikhwal/asikhwal: 2

### Files Uploaded/Downloaded
- sh: 6
- ): 1

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies
- A single IP address, 182.8.161.75, was responsible for over a third of all attacks, indicating a targeted or persistent campaign from this source.
- The vast majority of attacks from 182.8.161.75 were directed at port 445, suggesting a focus on exploiting SMB vulnerabilities.
- Attackers on the Cowrie (SSH) honeypot repeatedly used a set of commands to inspect the system and attempt to add their own SSH key for persistent access. This is a common tactic for building a botnet.
- The presence of commands like `tftp` and `wget` suggests attempts to download additional malware onto the honeypot.
- The triggered Suricata signatures for CVE-2019-11500 and CVE-2021-3449, related to Dovecot and OpenSSL respectively, indicate that attackers are actively trying to exploit known vulnerabilities.
