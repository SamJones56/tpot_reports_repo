# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T06:02:21Z
**Timeframe:** 2025-10-26T05:20:01Z to 2025-10-26T06:00:01Z
**Files:** agg_log_20251026T052001Z.json, agg_log_20251026T054001Z.json, agg_log_20251026T060001Z.json

## Executive Summary

This report summarizes the honeypot activity over the past hour, based on data from three log files. A total of 16,843 attacks were recorded. The most targeted honeypot was Cowrie, with 5,942 events. The top attacking IP address was 109.205.211.9, with 1,128 attacks. Port 445 was the most targeted port. Several CVEs were detected, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistence.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5942
- Honeytrap: 4468
- Suricata: 3056
- Ciscoasa: 1784
- Dionaea: 788
- Sentrypeer: 453
- Adbhoney: 78
- Mailoney: 122
- H0neytr4p: 40
- Tanner: 30
- ssh-rsa: 30
- Miniprint: 19
- Honeyaml: 9
- Redishoneypot: 11
- ConPot: 6
- ElasticPot: 4
- Dicompot: 3

### Top Attacking IPs
- 109.205.211.9: 1128
- 80.94.95.238: 1133
- 178.128.241.191: 876
- 45.154.138.19: 467
- 115.113.198.245: 454
- 167.71.68.143: 482
- 186.118.116.150: 347
- 185.243.5.121: 365
- 107.155.50.50: 346
- 36.134.147.79: 206
- 103.31.39.66: 267
- 196.251.71.24: 266
- 107.170.36.5: 249
- 23.95.37.90: 174
- 125.39.93.73: 254
- 157.230.53.170: 208
- 167.99.78.165: 187
- 172.210.82.243: 109
- 122.166.248.162: 129
- 178.217.173.50: 128

### Top Targeted Ports/Protocols
- 445: 700
- 22: 934
- 5060: 453
- 5038: 469
- 5903: 133
- 25: 122
- 8333: 114
- 5901: 116
- TCP/22: 85
- TCP/80: 74
- 5905: 77
- 5904: 76
- 5908: 50
- 5907: 49
- 5909: 48
- 1433: 16
- 5902: 40
- 29092: 35
- 80: 15
- 8081: 19

### Most Common CVEs
- CVE-2017-3506 CVE-2017-3506 CVE-2017-3606: 3
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-1999-0183: 1
- CVE-2005-4050: 1
- CVE-2006-2369: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 27
- lockr -ia .ssh: 27
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 27
- cat /proc/cpuinfo | grep name | wc -l: 23
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 23
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 23
- ls -lh $(which ls): 23
- which ls: 23
- crontab -l: 23
- w: 23
- uname -m: 23
- cat /proc/cpuinfo | grep model | grep name | wc -l: 23
- top: 23
- uname: 23
- uname -a: 23
- whoami: 23
- lscpu | grep Model: 23
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 23
- Enter new UNIX password: : 14
- Enter new UNIX password:": 14

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1226
- 2023753: 1226
- ET DROP Dshield Block Listed Source group 1: 489
- 2402000: 489
- ET HUNTING RDP Authentication Bypass Attempt: 317
- 2034857: 317
- ET SCAN NMAP -sS window 1024: 182
- 2009582: 182
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Potential SSH Scan: 48
- 2001219: 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 24
- 2403347: 24
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 21
- 2400027: 21
- ET SCAN Suspicious inbound to MSSQL port 1433: 12
- 2010935: 12
- ET INFO curl User-Agent Outbound: 12
- 2013028: 12

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 23
- root/: 30
- sa/1: 10
- root/3245gs5662d34: 7
- postmaster/postmaster: 4
- ftpuser/!qaz2wsx: 4
- minecraft/minecraft!: 4
- root/g3nd3lf: 4
- root/g3tc0.n3t: 4
- root/g8net: 4
- root/G9a4bss: 4
- root/gading: 3
- feng/feng: 3
- git/GIT: 3
- denis/123456789: 3
- user/newpass: 3
- sa/: 3
- root/11221122: 3
- jacky/jacky123: 3
- root/test01: 3
- root/liuyang123: 5

### Files Uploaded/Downloaded
- wget.sh;: 24
- rondo.xcw.sh||busybox: 12
- rondo.xcw.sh||curl: 12
- string>: 12
- w.sh;: 6
- c.sh;: 6
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3

### HTTP User-Agents
- No HTTP User-Agents were logged in this timeframe.

### SSH Clients
- No SSH clients were logged in this timeframe.

### SSH Servers
- No SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- A significant number of attacks are coming from a small number of IP addresses, suggesting targeted attacks or botnets.
- The most common commands are related to reconnaissance and establishing persistence, such as modifying SSH authorized_keys.
- The high number of "ET SCAN MS Terminal Server Traffic on Non-standard Port" signatures suggests a focus on exploiting RDP vulnerabilities.
- Attackers are attempting to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`), indicating attempts to install malware or backdoors.
- A variety of usernames and passwords are being attempted, with a focus on common default credentials.
- The presence of commands attempting to download and execute `urbotnetisass` binaries suggests an ongoing campaign by a specific botnet.
