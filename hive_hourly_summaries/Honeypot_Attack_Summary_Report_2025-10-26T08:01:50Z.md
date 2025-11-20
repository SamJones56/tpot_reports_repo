
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T08:01:24Z
**Timeframe:** 2025-10-26T07:20:01Z to 2025-10-26T08:00:02Z
**Files Used:**
- agg_log_20251026T072001Z.json
- agg_log_20251026T074001Z.json
- agg_log_20251026T080002Z.json

## Executive Summary
This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 20,010 events were recorded. The most active honeypot was Cowrie, and the most frequent attacker IP was 109.205.211.9. Attackers frequently targeted port 445 and attempted to gain access using default or weak credentials. Several CVEs were detected, and attackers attempted to download and execute malicious scripts.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5314
- Suricata: 5182
- Honeytrap: 4399
- Dionaea: 2256
- Ciscoasa: 1803
- Sentrypeer: 698
- Mailoney: 141
- Miniprint: 48
- H0neytr4p: 31
- Tanner: 39
- Adbhoney: 35
- Honeyaml: 22
- ConPot: 21
- ElasticPot: 11
- Redishoneypot: 6
- Dicompot: 4

### Top Attacking IPs
- 109.205.211.9: 4504
- 144.130.11.9: 533
- 20.80.236.78: 971
- 156.205.49.32: 501
- 81.10.26.152: 499
- 81.10.26.151: 481
- 185.243.5.121: 520
- 103.181.143.99: 307
- 107.174.78.139: 302
- 20.40.73.192: 283
- 129.226.183.73: 288
- 107.173.10.71: 246
- 211.253.37.225: 258
- 27.112.78.177: 245
- 175.178.123.4: 215
- 103.148.100.146: 237
- 80.94.95.238: 289
- 172.174.72.225: 184
- 167.71.68.143: 244
- 107.170.36.5: 251

### Top Targeted Ports/Protocols
- 445: 2075
- 22: 799
- 5060: 698
- 25: 141
- 8333: 115
- 5903: 140
- 5901: 116
- 1433: 62
- 9093: 57
- 9100: 48
- 5904: 77
- 5905: 77
- TCP/22: 46
- UDP/5060: 51
- 27017: 32
- 5908: 50
- 5907: 49
- 5909: 49
- 80: 35
- 443: 22

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-1999-0183: 1
- CVE-2006-2369: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 24
- lockr -ia .ssh: 24
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 24
- cat /proc/cpuinfo | grep name | wc -l: 24
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 24
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
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 23
- Enter new UNIX password: : 16
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 6

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2543
- 2023753: 2543
- ET HUNTING RDP Authentication Bypass Attempt: 1170
- 2034857: 1170
- ET DROP Dshield Block Listed Source group 1: 470
- 2402000: 470
- ET SCAN NMAP -sS window 1024: 176
- 2009582: 176
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 26
- 2403348: 26

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 23
- root/gB3N938: 4
- root/gbc1282: 4
- sa/: 7
- telecomadmin/admintelecom: 2
- root/123321123321: 2
- minecraft/minecraftpassword: 2
- minecraft/3245gs5662d34: 2
- builder/builder: 2
- root/potato: 2
- root/12345: 2
- root/Gbc1282: 4
- root/3245gs5662d34: 7

### Files Uploaded/Downloaded
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2

### HTTP User-Agents
- None recorded.

### SSH Clients and Servers
- None recorded.

### Top Attacker AS Organizations
- None recorded.

## Key Observations and Anomalies
- The IP address 109.205.211.9 was responsible for a significant portion of the total attack volume.
- A common attack pattern involved attempts to modify the `.ssh/authorized_keys` file to add a new SSH key, indicating a clear intent to establish persistent access.
- Attackers frequently attempted to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`) and other binaries (`.urbotnetisass`), suggesting automated malware infection campaigns.
- The high number of triggered "ET SCAN MS Terminal Server Traffic on Non-standard Port" and "ET HUNTING RDP Authentication Bypass Attempt" signatures indicates a strong focus on exploiting RDP vulnerabilities.
- Several older CVEs related to RPC and SMB were targeted, suggesting that attackers are still attempting to exploit legacy vulnerabilities.
- There is a lot of reconnaissance and system information gathering commands being executed.
