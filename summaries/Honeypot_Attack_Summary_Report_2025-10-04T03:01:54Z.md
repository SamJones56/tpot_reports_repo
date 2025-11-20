# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T03:01:25Z
**Timeframe:** 2025-10-04T02:20:02Z to 2025-10-04T03:00:01Z
**Files Used:**
- agg_log_20251004T022002Z.json
- agg_log_20251004T024001Z.json
- agg_log_20251004T030001Z.json

## Executive Summary

This report summarizes 9,690 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Ciscoasa and Suricata. The most frequent attacks originated from the IP address 68.183.102.75. The most targeted port was 445/TCP, commonly associated with SMB file sharing. A variety of CVEs were observed, with the most common being related to older vulnerabilities. Attackers attempted a range of commands, primarily focused on establishing remote access and gathering system information.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 3826
- Ciscoasa: 1823
- Suricata: 1525
- Dionaea: 1004
- Mailoney: 841
- Honeytrap: 301
- Sentrypeer: 173
- H0neytr4p: 36
- Miniprint: 36
- Adbhoney: 25
- ConPot: 33
- Redishoneypot: 25
- Dicompot: 16
- Tanner: 19
- ElasticPot: 2
- Honeyaml: 5

### Top Attacking IPs

- 68.183.102.75: 1248
- 1.53.37.62: 804
- 176.65.141.117: 820
- 186.118.142.216: 322
- 175.100.24.139: 322
- 178.128.80.162: 243
- 178.94.142.39: 239
- 103.210.21.178: 229
- 185.156.73.166: 212
- 106.53.31.30: 220

### Top Targeted Ports/Protocols

- 445: 909
- 25: 837
- 22: 593
- 5060: 173
- 3306: 53
- 9100: 36
- TCP/1080: 37
- 443: 36
- 6379: 22
- 23: 31

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 19
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 15
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-1999-0183: 1
- CVE-2006-2369: 1

### Commands Attempted by Attackers

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 15
- lockr -ia .ssh: 15
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 15
- cat /proc/cpuinfo | grep name | wc -l: 15
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 15
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 15
- ls -lh $(which ls): 15
- which ls: 15
- crontab -l: 15
- w: 15
- uname -m: 15
- cat /proc/cpuinfo | grep model | grep name | wc -l: 15
- top: 15
- uname: 15
- uname -a: 15
- whoami: 15
- lscpu | grep Model: 15
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 15
- Enter new UNIX password: : 14
- Enter new UNIX password:: 14

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 581
- 2402000: 581
- ET SCAN NMAP -sS window 1024: 168
- 2009582: 168
- ET INFO Reserved Internal IP Traffic: 53
- 2002752: 53
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 25
- 2403344: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 32
- 2403348: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 32
- 2403346: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 32
- 2403342: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 24
- 2403347: 24
- GPL INFO SOCKS Proxy attempt: 27
- 2100615: 27

### Users / Login Attempts

- a2billinguser/: 52
- 345gs5662d34/345gs5662d34: 13
- test/zhbjETuyMffoL8F: 5
- root/LeitboGi0ro: 4
- superadmin/admin123: 4
- root/2glehe5t24th1issZs: 5
- common/common123: 4
- admin/: 2
- admin/7ujMko0admin: 2
- admin/Admin@1234: 2

### Files Uploaded/Downloaded

- wget.sh;: 4
- Mozi.a+varcron: 2
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
- No user agents were recorded in this timeframe.

### SSH clients and servers
- No SSH clients or servers were recorded in this timeframe.

### Top attacker AS organizations
- No AS organizations were recorded in this timeframe.

## Key Observations and Anomalies

- The high volume of traffic from a single IP address (68.183.102.75) suggests a targeted or automated attack campaign.
- The prevalence of commands related to modifying SSH authorized_keys indicates a clear intent to establish persistent remote access.
- The targeting of port 445 suggests that attackers are actively scanning for vulnerable SMB services.
- The observed CVEs are relatively old, indicating that attackers are still attempting to exploit legacy vulnerabilities.
- A significant number of files with names like `arm.urbotnetisass` and `Mozi.a+varcron` were downloaded, suggesting attempts to install botnet malware.
