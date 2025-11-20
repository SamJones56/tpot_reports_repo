
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T09:01:30Z
**Timeframe:** 2025-10-13T08:20:01Z to 2025-10-13T09:00:01Z
**Files:** agg_log_20251013T082001Z.json, agg_log_20251013T084001Z.json, agg_log_20251013T090001Z.json

## Executive Summary

This report summarizes 12,467 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Ciscoasa honeypots. A significant portion of the attacks originated from the IP address 45.234.176.18. The most targeted ports were 5060 (SIP) and 22 (SSH).

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5049
- Honeytrap: 3208
- Ciscoasa: 1852
- Suricata: 1085
- Sentrypeer: 876
- Dionaea: 171
- Tanner: 63
- Redishoneypot: 48
- H0neytr4p: 34
- Mailoney: 25
- Adbhoney: 14
- ConPot: 13
- Honeyaml: 10
- Dicompot: 9
- Ipphoney: 6
- Miniprint: 4

### Top Attacking IPs
- 45.234.176.18: 3005
- 46.32.178.190: 878
- 139.59.46.176: 361
- 62.141.43.183: 325
- 103.144.3.34: 315
- 177.93.250.190: 271
- 113.31.103.129: 271
- 190.220.188.84: 270
- 45.61.187.30: 241
- 103.186.0.155: 208

### Top Targeted Ports/Protocols
- 5060: 876
- 22: 659
- 1433: 84
- 80: 64
- 23: 50
- 445: 49
- 6379: 48
- 443: 34
- 25: 25
- TCP/1433: 24

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2005-4050: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-35394 CVE-2021-35394: 1

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
- uname -a
- whoami
- top
- Enter new UNIX password:

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Potential SSH Scan
- 2001219
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- 2403347

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- support/p@ssw0rd
- debian/debian2006
- root/444
- centos/00
- default/default2009
- config/1234567890
- root/pcs
- deploy/123123

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm5.urbotnetisass;
- arm6.urbotnetisass;
- arm7.urbotnetisass;
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;

### HTTP User-Agents
- No user agents were captured.

### SSH Clients and Servers
- No SSH clients or servers were captured.

### Top Attacker AS Organizations
- No attacker AS organizations were captured.

## Key Observations and Anomalies
- The IP address 45.234.176.18 was responsible for a large number of events, primarily targeting the Honeytrap honeypot.
- A significant number of commands were executed on the Cowrie honeypot, indicating successful logins. The commands are typical of reconnaissance and establishing persistence.
- Several malware samples were downloaded, including variants of Mirai (urbotnetisass).
- The most common attack vector appears to be brute-force login attempts against SSH, followed by reconnaissance and malware download.
