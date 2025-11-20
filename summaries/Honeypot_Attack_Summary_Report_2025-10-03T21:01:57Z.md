Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T21:01:28Z
**Timeframe:** 2025-10-03T20:20:01Z to 2025-10-03T21:00:02Z
**Files Used:**
- agg_log_20251003T202001Z.json
- agg_log_20251003T204001Z.json
- agg_log_20251003T210002Z.json

### Executive Summary

This report summarizes 11,410 malicious events targeting the honeypot infrastructure. The primary attack vectors observed were SSH brute-force attempts and SMB probes. The most active honeypots were Cowrie, Dionaea, and Ciscoasa. The majority of attacks originated from IP address 38.34.18.221.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 4760
- **Dionaea:** 1991
- **Ciscoasa:** 1858
- **Suricata:** 1260
- **Mailoney:** 887
- **Sentrypeer:** 292
- **Honeytrap:** 144
- **Redishoneypot:** 68
- **H0neytr4p:** 53
- **Tanner:** 29
- **ConPot:** 18
- **Dicompot:** 18
- **Honeyaml:** 14
- **ElasticPot:** 6
- **ssh-rsa:** 4
- **Adbhoney:** 4
- **Heralding:** 3
- **Ipphoney:** 1

**Top Attacking IPs:**
- 38.34.18.221
- 106.75.131.128
- 176.65.141.117
- 77.239.96.92
- 157.10.160.102
- 188.18.49.50
- 185.156.73.166
- 161.49.89.39
- 46.105.87.113
- 103.174.215.18

**Top Targeted Ports/Protocols:**
- 445
- 22
- 5060
- 25
- 6379
- 23
- 443
- 80
- TCP/22
- TCP/80

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2024-3721 CVE-2024-3721
- CVE-2006-2369

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- top
- w
- crontab -l

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET SCAN Potential SSH Scan

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- a2billinguser/
- root/nPSpP4PBW0
- root/3245gs5662d34
- alex/alex
- root/P@ssw0rd!
- root/Aa112211.
- root/Qaz@123123
- sa/
- admin/planeacion

**Files Uploaded/Downloaded:**
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies

- A significant amount of reconnaissance and brute-force activity was directed at SSH (port 22) and SMB (port 445).
- The commands executed by attackers indicate attempts to establish persistent access by adding SSH keys to `authorized_keys`.
- The Suricata logs show a high number of events related to blocklisted IPs and network scanning activities.
- The lack of HTTP User-Agents, SSH client/server strings, and AS organization data might indicate a misconfiguration in the logging pipeline or that these fields were not present in the captured traffic.
