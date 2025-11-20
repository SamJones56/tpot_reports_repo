
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T17:01:26Z
**Timeframe:** 2025-10-21T16:20:01Z to 2025-10-21T17:00:02Z
**Files Used:**
- agg_log_20251021T162001Z.json
- agg_log_20251021T164001Z.json
- agg_log_20251021T170002Z.json

## Executive Summary

This report summarizes 15,368 malicious events captured by the honeypot network over the past hour. The majority of attacks were SSH brute-force attempts and automated scans, with a significant number of events logged by the Cowrie honeypot. Attackers were observed attempting to gain initial access, perform reconnaissance, and establish persistence. A notable command pattern involved modifying SSH authorized_keys to maintain access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 9318
- Honeytrap: 2951
- Suricata: 1606
- Sentrypeer: 407
- Dionaea: 498
- Heralding: 266
- Tanner: 80
- Mailoney: 68
- H0neytr4p: 70
- Adbhoney: 17
- ConPot: 14
- Miniprint: 10
- Redishoneypot: 42
- Ipphoney: 6
- Honeyaml: 6
- ElasticPot: 3
- Ciscoasa: 6

### Top Attacking IPs
- 161.132.37.66
- 50.6.225.98
- 89.221.211.117
- 72.146.232.13
- 150.230.252.188
- 103.172.154.255
- 217.128.7.248
- 223.197.186.7
- 181.210.8.69
- 1.52.49.6
- 191.242.105.133
- 113.141.166.35
- 88.210.63.16
- 168.194.164.218
- 14.103.105.62

### Top Targeted Ports/Protocols
- 22
- 5060
- 445
- 1080 (TCP and socks5)
- 5903
- 8333
- 5901
- 80
- 443
- 6379
- 23
- 25

### Most Common CVEs
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-35394
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2014-8361
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2006-2369

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- GPL INFO SOCKS Proxy attempt
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET INFO CURL User Agent
- ET CINS Active Threat Intelligence Poor Reputation IP group 3
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- GPL SNMP request udp

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/Arkan
- jiel/123
- root/arlei2001
- root/Abc@123456789
- root/ARNtechltd
- root/ARphones
- pruebas/123
- gerrit/gerrit
- abc/abc
- root/1QAZxsw2
- root/arsec5555
- user/1
- www/abc123
- root/qwerty123

### Files Uploaded/Downloaded
- wget.sh;
- loader.sh|sh;#
- w.sh;
- c.sh;
- &currentsetting.htm=1

### HTTP User-Agents
- No user agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were identified in this period.

## Key Observations and Anomalies

- A high volume of attacks originated from a small number of IP addresses, suggesting targeted or persistent attackers.
- The overwhelming majority of commands are focused on reconnaissance and establishing persistence through SSH keys. The use of `chattr` and `lockr` indicates an attempt to make files immutable and prevent changes.
- The CVEs targeted are a mix of older and more recent vulnerabilities, indicating that attackers are using a broad set of exploits to maximize their chances of success.
- The most common signatures triggered are related to scanning activity and traffic from known malicious IP addresses, which is typical for a honeypot environment.

---
**End of Report**
