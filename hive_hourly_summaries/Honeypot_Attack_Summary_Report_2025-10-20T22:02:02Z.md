# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T22:01:31Z
**Timeframe:** 2025-10-20T21:20:01Z to 2025-10-20T22:00:01Z
**Files Used:**
- agg_log_20251020T212001Z.json
- agg_log_20251020T214001Z.json
- agg_log_20251020T220001Z.json

---

## Executive Summary

This report summarizes 17,296 malicious events captured by the honeypot network. The majority of attacks were SSH brute-force attempts and SMB scanning. A significant portion of the activity originated from IP address `186.89.3.142`, which was responsible for a large number of SMB-related events. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to exploit several known vulnerabilities.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 8,783
- **Honeytrap:** 3,613
- **Suricata:** 3,250
- **Dionaea:** 830
- **Sentrypeer:** 469
- **Tanner:** 70
- **Adbhoney:** 76
- **Redishoneypot:** 40
- **ElasticPot:** 38
- **Mailoney:** 44
- **Ciscoasa:** 31
- **H0neytr4p:** 18
- **ConPot:** 13
- **Honeyaml:** 9
- **Ipphoney:** 7
- **Dicompot:** 3
- **Wordpot:** 2

### Top Attacking IPs
- 186.89.3.142: 1297
- 72.146.232.13: 1254
- 66.116.196.243: 452
- 8.210.46.25: 433
- 185.243.5.158: 326
- 208.69.84.112: 312
- 43.229.78.35: 314
- 185.230.52.244: 262
- 103.186.1.120: 253
- 89.144.212.131: 227
- 180.76.145.111: 223
- 216.10.250.18: 236
- 193.24.211.28: 192
- 42.51.41.252: 186
- 103.250.11.114: 183
- 107.170.36.5: 253
- 143.198.76.169: 179
- 107.174.67.215: 168
- 68.233.116.124: 232
- 125.25.48.246: 164

### Top Targeted Ports/Protocols
- 22: 1499
- TCP/445: 1299
- 5060: 469
- 5903: 227
- TCP/21: 211
- 80: 93
- 21: 105
- TCP/80: 86
- 5901: 126
- 8333: 71
- 5905: 78
- 5904: 78
- 445: 58
- 6379: 23
- 9200: 36
- 2181: 45
- 25: 30
- 5908: 51
- 5907: 51
- 5909: 49

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-2024-3721 CVE-2024-3721: 6
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2006-2369: 1
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2016-20016 CVE-2016-20016: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2014-8361 CVE-2014-8361: 1
- CVE-2016-6563: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 51
- lockr -ia .ssh: 51
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr": 51
- cat /proc/cpuinfo | grep name | wc -l: 37
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 37
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 37
- ls -lh $(which ls): 37
- which ls: 37
- crontab -l: 37
- w: 37
- uname -m: 37
- cat /proc/cpuinfo | grep model | grep name | wc -l: 37
- top: 37
- uname: 37
- uname -a: 37
- whoami: 37
- lscpu | grep Model: 37
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 37
- Enter new UNIX password: : 29
- Enter new UNIX password:": 29

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1290
- 2024766: 1290
- ET DROP Dshield Block Listed Source group 1: 344
- 2402000: 344
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 312
- 2023753: 312
- ET SCAN NMAP -sS window 1024: 177
- 2009582: 177
- ET FTP FTP PWD command attempt without login: 105
- 2010735: 105
- ET FTP FTP CWD command attempt without login: 105
- 2010731: 105
- ET HUNTING RDP Authentication Bypass Attempt: 102
- 2034857: 102
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 40
- 2403345: 40
- ET INFO curl User-Agent Outbound: 18
- 2013028: 18
- ET HUNTING curl User-Agent to Dotted Quad: 18
- 2034567: 18

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 49
- user01/Password01: 18
- deploy/123123: 9
- root/3245gs5662d34: 10
- user01/3245gs5662d34: 12
- root/admon: 4
- root/admoon: 4
- root/admqn: 4
- root/admronnie1985: 4
- deploy/1234: 5
- root/huang123: 3
- sammy/sammysammy: 3
- guest/Aa123456@: 3
- user1/1qaz2wsx: 3
- ubuntu/DiarNisa11077#: 3
- botuser/botuser@2025: 3
- ubuntu/khongbiet: 3
- root/123: 3
- root/AdmTcc2o14: 4
- root/!Q2w3e4r: 3

### Files Uploaded/Downloaded
- sh: 98
- wget.sh;: 32
- w.sh;: 8
- c.sh;: 8
- mpsl: 4
- rondo.kqa.sh|sh&echo: 2
- `cd: 2
- Mozi.m: 2
- XMLSchema-instance: 2
- XMLSchema: 2
- ): 1

### HTTP User-Agents
- No HTTP User-Agents were logged in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this period.

### Top Attacker AS Organizations
- No AS organizations were logged in this period.

---

## Key Observations and Anomalies

- The high volume of traffic from `186.89.3.142` targeting TCP port 445 is indicative of a widespread SMB worm or scanner. The triggered signature `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` confirms this is likely related to the EternalBlue/DoublePulsar exploit.
- The majority of SSH commands are reconnaissance commands, with a follow-up to add an SSH key to the `.ssh/authorized_keys` file for persistence.
- A variety of CVEs were targeted, including older vulnerabilities, indicating that attackers are still attempting to exploit legacy systems.
- The file `sh` being downloaded 98 times is anomalous and suggests a common script or tool being used by attackers.
- The `mdrfckr` comment in the SSH key is a common indicator of a specific botnet.
