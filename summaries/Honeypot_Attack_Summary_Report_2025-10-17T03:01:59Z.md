# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T03:01:29Z
**Timeframe:** 2025-10-17T02:20:02Z to 2025-10-17T03:00:01Z
**Files Used:**
- agg_log_20251017T022002Z.json
- agg_log_20251017T024001Z.json
- agg_log_20251017T030001Z.json

## Executive Summary

This report summarizes 21,808 attacks recorded by the honeypot network. The majority of attacks were captured by the Honeytrap and Cowrie honeypots. The most prominent attacker IP was 77.83.240.70. The most targeted ports were 5060 (SIP) and 22 (SSH). Several CVEs were detected, with the most frequent being related to older vulnerabilities. A significant number of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 9339
- Cowrie: 6518
- Suricata: 1811
- Ciscoasa: 1671
- Sentrypeer: 1290
- Dionaea: 405
- Tanner: 284
- Mailoney: 152
- ElasticPot: 44
- Miniprint: 62
- Dicompot: 41
- Adbhoney: 25
- Redishoneypot: 30
- ConPot: 24
- H0neytr4p: 27
- Heralding: 34
- Honeyaml: 18
- ssh-rsa: 30
- Ipphoney: 3

### Top Attacking IPs
- 77.83.240.70: 6219
- 129.212.190.123: 1001
- 134.199.192.34: 1002
- 188.245.227.93: 1254
- 43.252.229.25: 482
- 27.111.32.174: 478
- 172.86.95.115: 502
- 172.86.95.98: 490
- 134.199.225.42: 376
- 107.170.36.5: 249
- 114.117.169.218: 256
- 122.166.49.42: 219
- 195.178.110.201: 188
- 113.167.129.176: 270
- 180.76.134.56: 145
- 103.174.115.72: 111
- 107.170.69.59: 91
- 14.103.117.84: 88
- 167.250.224.25: 88
- 68.183.149.135: 112

### Top Targeted Ports/Protocols
- 5060: 1290
- 22: 1052
- 80: 286
- 5903: 229
- 8333: 165
- 25: 152
- 445: 273
- 5901: 116
- 1950: 78
- 1433: 47
- 9100: 62
- 5905: 77
- 5904: 76
- 9200: 38
- 5908: 49
- 5907: 32
- 5909: 33
- TCP/22: 35
- TCP/80: 48
- 9090: 28
- 23: 34
- 6379: 18
- 27017: 24

### Most Common CVEs
- CVE-2002-1149
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2018-10562 CVE-2018-10561
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
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
- Enter new UNIX password: 
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- User-Agent: python-requests/2.6.0 CPython/2.7.5 Linux/3.10.0-1160.119.1.el7.x86_64

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET INFO VNC Authentication Failure
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system
- ET INFO CURL User Agent
- ET WEB_SERVER WEB-PHP phpinfo access
- ET CINS Active Threat Intelligence Poor Reputation IP group 52

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/
- support/support2005
- root/3245gs5662d34
- operator/operator2017
- config/config2023
- root/123@@@
- root/00suramericana102030
- root/1234root
- root/A1b2C3d4
- eb/eb
- root/011_sam_majid
- root/Qaz123qaz
- root/01144454548a
- debian/0
- unknown/maintenance
- root/01jan
- user/4444444

### Files Uploaded/Downloaded
- sh
- SOAP-ENV:Envelope>
- gpon80&ipv=0
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- ns#
- rdf-schema#
- types#
- core#
- XMLSchema#
- www.drupal.org)

### HTTP User-Agents
- No HTTP User-Agents were logged in this timeframe.

### SSH Clients
- No SSH clients were logged in this timeframe.

### SSH Servers
- No SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies
- A significant number of commands are related to modifying the `.ssh/authorized_keys` file, indicating a clear intent to establish persistent access.
- One of the interesting commands includes a long string that attempts to download and execute multiple malicious binaries for different architectures (ARM, x86, MIPS).
- The credentials attempted are a mix of common default passwords and more complex, seemingly targeted attempts.
- The most common signature triggered is related to a Dshield block list, which is effective at blocking known malicious actors.
- The presence of commands related to `python-requests` suggests that some of the attacks are automated scripts.
