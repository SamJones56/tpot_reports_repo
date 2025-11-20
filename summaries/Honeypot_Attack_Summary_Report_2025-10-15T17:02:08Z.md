# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T17:01:35Z
**Timeframe:** 2025-10-15T16:20:01Z to 2025-10-15T17:00:01Z
**Files Used:**
- agg_log_20251015T162001Z.json
- agg_log_20251015T164001Z.json
- agg_log_20251015T170001Z.json

## Executive Summary

This report summarizes 19,791 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Sentrypeer honeypots. The most targeted ports were 445 (SMB) and 5060 (SIP). A significant number of SSH-related commands were observed, primarily focused on reconnaissance and establishing persistent access by adding SSH keys.

## Detailed Analysis

### Attacks by Honeypot

*   Cowrie: 4456
*   Sentrypeer: 4252
*   Dionaea: 3217
*   Honeytrap: 3303
*   Ciscoasa: 1654
*   Suricata: 1231
*   ElasticPot: 371
*   Mailoney: 1179
*   Redishoneypot: 56
*   H0neytr4p: 29
*   Tanner: 21
*   Heralding: 6
*   Honeyaml: 8
*   Ipphoney: 6
*   Adbhoney: 1
*   ConPot: 1

### Top Attacking IPs

*   161.132.149.131: 3127
*   185.243.5.121: 1843
*   139.59.226.171: 1220
*   206.191.154.180: 1376
*   23.94.26.58: 890
*   176.65.141.119: 821
*   185.90.162.108: 523
*   172.86.95.98: 486
*   172.86.95.115: 483
*   79.143.89.199: 389
*   86.54.42.238: 321
*   62.141.43.183: 321
*   103.250.11.207: 268
*   23.95.225.23: 103
*   152.32.135.217: 93
*   1.238.106.229: 93
*   103.172.112.192: 86
*   109.206.241.199: 83
*   128.1.44.115: 79
*   198.12.68.114: 183
*   167.250.224.25: 85
*   68.183.149.135: 112
*   103.9.135.54: 76
*   185.243.5.158: 67
*   159.65.97.236: 119
*   23.92.30.189: 115
*   155.248.164.42: 92
*   142.93.44.112: 85
*   3.137.73.221: 38
*   3.131.215.38: 37
*   68.183.193.0: 69
*   41.77.220.188: 94
*   135.13.11.134: 89
*   181.115.147.5: 89
*   141.95.55.239: 83

### Top Targeted Ports/Protocols

*   445: 3133
*   5060: 4252
*   22: 684
*   25: 1181
*   9200: 371
*   23: 98
*   5903: 224
*   8333: 130
*   5901: 112
*   UDP/5060: 108
*   6379: 56
*   TCP/22: 100
*   5908: 84
*   5909: 83
*   TCP/1433: 53
*   1433: 43
*   5907: 48
*   5902: 39
*   5910: 24
*   9443: 40
*   20143: 18
*   8729: 15
*   6000: 34
*   TCP/1080: 15
*   51200: 14
*   10443: 35
*   TCP/80: 10
*   TCP/7574: 8
*   443: 8

### Most Common CVEs

*   CVE-2002-0013 CVE-2002-0012: 13
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
*   CVE-2018-10562 CVE-2018-10561: 1
*   CVE-2019-11500 CVE-2019-11500: 2
*   CVE-2021-3449 CVE-2021-3449: 3
*   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
*   CVE-2001-0414: 1
*   CVE-2006-2369: 1

### Commands Attempted by Attackers

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 13
*   lockr -ia .ssh: 13
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 13
*   cat /proc/cpuinfo | grep name | wc -l: 13
*   Enter new UNIX password: : 9
*   Enter new UNIX password:: 7
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 13
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 13
*   ls -lh $(which ls): 13
*   which ls: 13
*   crontab -l: 13
*   w: 13
*   uname -m: 13
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 13
*   top: 13
*   uname: 13
*   uname -a: 13
*   whoami: 13
*   lscpu | grep Model: 13
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 13
*   rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 4

### Signatures Triggered

*   ET DROP Dshield Block Listed Source group 1: 312
*   2402000: 312
*   ET SCAN NMAP -sS window 1024: 159
*   2009582: 159
*   GPL TELNET Bad Login: 25
*   2101251: 25
*   ET INFO Reserved Internal IP Traffic: 59
*   2002752: 59
*   ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 39
*   2012297: 39
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 11
*   2400027: 11
*   ET CINS Active Threat Intelligence Poor Reputation IP group 92: 10
*   2403391: 10
*   ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 34
*   2012296: 34
*   ET INFO libwww-perl User Agent: 28
*   2002934: 28
*   ET CINS Active Threat Intelligence Poor Reputation IP group 95: 8
*   2403394: 8
*   ET SCAN Potential SSH Scan: 64
*   2001219: 64
*   ET SCAN Suspicious inbound to MSSQL port 1433: 50
*   2010935: 50
*   GPL INFO SOCKS Proxy attempt: 14
*   2100615: 14
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 22
*   2023753: 22
*   ET INFO CURL User Agent: 5
*   2002824: 5

### Users / Login Attempts

*   345gs5662d34/345gs5662d34: 13
*   admin/admin2004: 6
*   debian/debian2020: 6
*   support/support22: 6
*   supervisor/supervisor2025: 4
*   nobody/1234567890: 6
*   root/admin@2021: 3
*   test/test2000: 6
*   debian/000000: 4
*   root/admin@2019: 4
*   debian/debian11: 4
*   blank/blank2000: 6
*   root/: 3
*   root/admin@2018: 3
*   admin/141287: 2
*   admin/14121992: 2
*   admin/14121981: 2
*   admin/14121978: 2
*   admin/14101976: 2
*   sa/: 2
*   operator/123123123: 2
*   hadoop/qwerty123: 2
*   dev/dev123456: 2
*   root/!Q2w3e4r: 2
*   pi/raspberry: 2
*   blank/999: 6
*   root/1234: 6
*   support/support2018: 4
*   root/admin@1122: 4
*   root/3245gs5662d34: 4
*   root/Pa$$w0rd: 2
*   postgres/123: 2
*   root/4r3e2w1q: 2
*   plexserver/plexserver: 2
*   sonar/sonar123: 2
*   app/app123: 2
*   tools/tools: 2
*   lighthouse/lighthouse123: 2
*   mysql/mysql123: 2
*   gpadmin/gpadmin: 2
*   oracle/qwe123: 2
*   root/1: 2
*   www/abc123: 2

### Files Uploaded/Downloaded

*   gpon80&ipv=0: 4
*   bot.html): 2
*   get?src=cl1ckh0use: 2
*   resty): 1

### HTTP User-Agents

No user agents were logged in this timeframe.

### SSH Clients and Servers

No SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations

No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

*   A large number of commands executed are related to reconnaissance of the system (e.g., `lscpu`, `uname -a`, `whoami`).
*   The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was seen 13 times, indicating a persistent attempt to install a malicious SSH key.
*   The `Dshield Block Listed Source group 1` signature was triggered most frequently, indicating that many of the attacking IPs are known malicious actors.
*   The top targeted ports are consistent with common services that are often scanned for vulnerabilities (SMB, SIP, SSH).
*   The variety of usernames and passwords attempted suggests that attackers are using common default credentials and password lists.
