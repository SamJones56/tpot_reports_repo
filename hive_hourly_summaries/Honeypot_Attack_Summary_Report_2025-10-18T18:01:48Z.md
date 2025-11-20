
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T18:01:30Z
**Timeframe:** 2025-10-18T17:20:01Z to 2025-10-18T18:00:01Z
**Files Used:**
- agg_log_20251018T172001Z.json
- agg_log_20251018T174001Z.json
- agg_log_20251018T180001Z.json

## Executive Summary
This report summarizes 10,367 attacks recorded by honeypots between 17:20 and 18:00 UTC on October 18, 2025. The majority of attacks targeted the Cowrie honeypot, with significant activity also observed on Honeytrap and Ciscoasa. The most frequent attacks originated from IP address 134.199.204.5, and port 22 (SSH) was the most targeted port. Several CVEs were detected, and a variety of shell commands were attempted by attackers, indicating efforts to profile the system and establish persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5886
- **Honeytrap:** 1859
- **Ciscoasa:** 1203
- **Suricata:** 952
- **Sentrypeer:** 279
- **Dionaea:** 53
- **Adbhoney:** 35
- **Tanner:** 26
- **ConPot:** 22
- **Redishoneypot:** 23
- **H0neytr4p:** 12
- **ElasticPot:** 9
- **Dicompot:** 3
- **Mailoney:** 3
- **Ipphoney:** 2

### Top Attacking IPs
- **134.199.204.5:** 857
- **176.9.111.156:** 820
- **72.146.232.13:** 780
- **174.138.116.10:** 585
- **139.59.254.39:** 249
- **88.210.63.16:** 241
- **40.81.244.142:** 231
- **115.241.83.2:** 159
- **4.224.36.103:** 157
- **107.170.36.5:** 206
- **114.132.166.115:** 159
- **59.12.160.91:** 181
- **39.91.83.171:** 120

### Top Targeted Ports/Protocols
- **22:** 1247
- **5060:** 279
- **1976:** 156
- **5903:** 143
- **8333:** 78
- **5901:** 81
- **5905:** 77
- **5904:** 76
- **5902:** 41
- **TCP/22:** 29
- **445:** 11
- **23:** 18
- **80:** 20
- **6379:** 20

### Most Common CVEs
- CVE-2024-3721
- CVE-2005-3296
- CVE-2019-11500
- CVE-2024-11120
- CVE-2024-6047
- CVE-2002-0013
- CVE-2002-0012

### Commands Attempted by Attackers
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /data/local/tmp; ...

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET INFO CURL User Agent

### Users / Login Attempts
- root/123@Robert
- debian/debian2009
- nobody/1
- 345gs5662d34/345gs5662d34
- debian/debian333
- default/default2023
- root/31
- root/310314Am
- root/lol123
- ubuntu/ubuntu@2020
- ndd/123
- ubuntu/Aa123321
- ftpuser/ftppassword

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

### HTTP User-Agents
- No HTTP user agents were logged in the specified timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged.

### Top Attacker AS Organizations
- No attacker AS organizations were logged.

## Key Observations and Anomalies
- A high number of commands related to system enumeration and establishing SSH persistence were observed, particularly the modification of `~/.ssh/authorized_keys`.
- The command `rm -rf /data/local/tmp; ...` suggests attempts to download and execute malicious scripts from a remote server.
- The presence of CVEs from various years, including recent ones, indicates that attackers are using a broad range of exploits.
- The credentials attempted are a mix of common default passwords and more complex strings, suggesting both automated and targeted attacks.
