
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T22:01:36Z
**Timeframe:** 2025-10-09T21:20:01Z to 2025-10-09T22:00:01Z
**Files Used:**
- agg_log_20251009T212001Z.json
- agg_log_20251009T214001Z.json
- agg_log_20251009T220001Z.json

---

## Executive Summary

This report summarizes 18,487 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Honeytrap honeypots. The most prominent attack vector was over port 445 (SMB), with significant activity also observed on port 22 (SSH). Attackers from numerous IP addresses were observed, with the most frequent originating from `113.178.155.152`. A variety of CVEs were targeted, and attackers attempted numerous commands, primarily related to establishing SSH access and reconnaissance.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7546
- **Dionaea:** 3155
- **Honeytrap:** 3194
- **Suricata:** 2074
- **Ciscoasa:** 1683
- **Sentrypeer:** 421
- **Tanner:** 165
- **Mailoney:** 107
- **H0neytr4p:** 31
- **ConPot:** 27
- **ElasticPot:** 22
- **Redishoneypot:** 23
- **Dicompot:** 11
- **Miniprint:** 10
- **Honeyaml:** 10
- **ssh-rsa:** 6
- **Heralding:** 2

### Top Attacking IPs
- 113.178.155.152: 3104
- 167.250.224.25: 1610
- 47.237.96.241: 1244
- 210.236.249.126: 1239
- 212.87.220.20: 906
- 1.238.106.229: 243
- 88.210.63.16: 321
- 172.245.42.201: 243
- 10.140.0.3: 211
- 80.94.95.238: 197
- 185.93.89.97: 147
- 187.45.95.66: 204
- 103.163.215.10: 219
- 103.200.25.197: 204
- 180.76.250.117: 92
- 154.219.118.124: 99
- 141.11.167.206: 99
- 94.74.164.27: 105
- 191.13.244.160: 84
- 211.201.163.70: 120

### Top Targeted Ports/Protocols
- 445: 3104
- 22: 1356
- 5060: 421
- 5903: 204
- 80: 158
- 25: 109
- 5908: 85
- 5909: 83
- 5901: 74
- 8333: 52
- TCP/22: 46
- 443: 28
- TCP/5432: 30
- 9200: 21
- 23: 28
- TCP/80: 20
- 9000: 20
- 17000: 20
- 5907: 49
- TCP/1080: 16

### Most Common CVEs
- CVE-2002-1149
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-2021-35394
- CVE-1999-0517
- CVE-2006-2369
- CVE-2009-2765

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- 2010517
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- 2400027
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- 2403343
- GPL INFO SOCKS Proxy attempt
- 2100615
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- 2010939
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- 2403347
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- 2403341
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/issa.2024
- root/issa.2025
- root/issa.321
- root/issa123
- supervisor/qwerty12
- guest/qwerty1
- support/1980
- test/test0
- support/qwe123
- test/12345
- supervisor/dietpi
- config/config13
- root/issab3l!
- root/issa2023
- root/issa2024
- root/issa2025
- root/issa321
- root/issa@
- root/issa@123

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- botx.mpsl;
- Mozi.m
- mips.nn;
- #comment-1
- rondo.naz.sh|sh&...

### HTTP User-Agents
- No HTTP User-Agent data was recorded in this period.

### SSH Clients
- No specific SSH client data was recorded in this period.

### SSH Servers
- No specific SSH server data was recorded in this period.

### Top Attacker AS Organizations
- No Attacker AS Organization data was recorded in this period.

---

## Key Observations and Anomalies

- A significant amount of traffic was directed at port 445, suggesting widespread SMB scanning or exploitation attempts.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was consistently used, indicating a common tactic to install a persistent SSH key for backdoor access.
- Multiple signature IDs are duplicated (e.g., `2023753` for "ET SCAN MS Terminal Server Traffic..."). This is an anomaly in the logging that should be investigated.
- The majority of login attempts use common or default usernames like `root`, `supervisor`, `test`, and `guest`, with varied password attempts.
- The IP `113.178.155.152` was responsible for a large volume of attacks, focusing exclusively on port 445.
