
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T01:01:30Z
**Timeframe:** 2025-10-10T00:20:01Z to 2025-10-10T01:00:01Z
**Files Used:**
- agg_log_20251010T002001Z.json
- agg_log_20251010T004001Z.json
- agg_log_20251010T010001Z.json

## Executive Summary
This report summarizes 14,707 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the traffic involved SMB probes, likely related to the DoublePulsar backdoor, originating from a wide range of international IP addresses. Brute-force attempts against SSH (port 22) and SIP (port 5060) were also prevalent. Attackers commonly used system reconnaissance commands after gaining access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6,381
- Suricata: 2,991
- Honeytrap: 2,966
- Ciscoasa: 1,696
- Sentrypeer: 369
- Dionaea: 86
- H0neytr4p: 64
- Miniprint: 32
- Tanner: 31
- Redishoneypot: 25
- Mailoney: 21
- ConPot: 19
- ElasticPot: 8
- Honeyaml: 8
- Dicompot: 5
- Wordpot: 1
- Ipphoney: 2
- Adbhoney: 2

### Top Attacking IPs
- 167.250.224.25: 1,450
- 189.253.33.186: 1,354
- 185.76.34.16: 529
- 5.195.226.17: 327
- 14.103.120.242: 308
- 42.200.66.164: 248
- 58.213.147.49: 233
- 189.112.0.11: 233
- 103.84.119.130: 233
- 51.210.179.197: 193
- 45.134.26.3: 232
- 103.154.77.2: 233
- 45.61.187.30: 219
- 107.174.26.130: 199
- 60.188.59.200: 161
- 152.32.189.21: 158
- 23.88.43.131: 124
- 165.227.117.213: 124
- 103.181.143.69: 119
- 159.89.121.144: 98

### Top Targeted Ports/Protocols
- TCP/445: 1,365
- 22: 893
- 5060: 369
- 5903: 185
- 8333: 133
- 5909: 76
- 5908: 74
- 5901: 68
- TCP/1433: 43
- 443: 56
- 9100: 31
- 23: 29
- 5907: 43
- 1433: 38
- 6379: 22
- 54321: 26
- 5678: 21
- 1025: 19
- 5910: 21
- TCP/80: 15

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-44228
- CVE-2019-11500
- CVE-2005-4050

### Commands Attempted by Attackers
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
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,347
- ET DROP Dshield Block Listed Source group 1: 518
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 155
- ET SCAN NMAP -sS window 1024: 164
- ET INFO Reserved Internal IP Traffic: 60
- ET HUNTING RDP Authentication Bypass Attempt: 61
- ET SCAN Suspicious inbound to MSSQL port 1433: 42
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 38
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 22
- ET INFO Login Credentials Possibly Passed in POST Data: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 9

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 31
- default/123654: 6
- guest/123654: 6
- supervisor/p@ssw0rd: 6
- support/support7: 6
- centos/centos88: 6
- support/11111: 6
- supervisor/supervisor444: 6
- various root attempts (e.g., root/qaz12345, root/!zaq123, etc.)
- various supervisor attempts
- various admin attempts

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- nse.html
- soap-envelope
- addressing
- discovery
- env:Envelope>

### HTTP User-Agents
- No user agents recorded.

### SSH Clients and Servers
- No SSH clients or servers recorded.

### Top Attacker AS Organizations
- No attacker AS organizations recorded.

## Key Observations and Anomalies
- The high number of hits for the "DoublePulsar Backdoor" signature indicates widespread, automated scanning for SMB vulnerabilities.
- A recurring pattern observed is the attempt to modify the `.ssh/authorized_keys` file to establish persistent access.
- Attackers frequently perform system reconnaissance to understand the environment, checking CPU info, memory, and user accounts.
- The variety of credentials used suggests brute-force attacks from pre-compiled dictionaries targeting common default or weak passwords.
