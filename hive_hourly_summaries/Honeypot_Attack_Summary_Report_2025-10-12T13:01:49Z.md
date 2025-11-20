
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T13:01:28Z
**Timeframe of a report:** 2025-10-12T12:20:01Z - 2025-10-12T13:00:01Z
**Files Used to Generate Report:**
- agg_log_20251012T122001Z.json
- agg_log_20251012T124001Z.json
- agg_log_20251012T130001Z.json

## Executive Summary
This report summarizes 15,814 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap and Ciscoasa. The most prominent attack vector was via port 5038, closely followed by SIP (5060) and SSH (22). A notable volume of activity originated from the IP address 143.198.96.196.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie
- Honeytrap
- Ciscoasa
- Sentrypeer
- Suricata
- Mailoney
- Redishoneypot
- ConPot
- Dionaea
- Tanner
- H0neytr4p
- ElasticPot
- Honeyaml
- Adbhoney
- Heralding
- Ipphoney

### Top Attacking IPs
- 143.198.96.196
- 173.239.216.40
- 45.128.199.212
- 85.185.120.213
- 158.51.124.56
- 103.250.10.42
- 46.245.82.13
- 62.141.43.183
- 103.174.215.18
- 172.86.95.98

### Top Targeted Ports/Protocols
- 5038
- 5060
- 22
- 25
- 5903
- 8888
- 8333
- 6379
- TCP/22

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2016-6563
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0517

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- uname -a
- whoami

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET INFO CURL User Agent
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET CINS Active Threat Intelligence Poor Reputation IP

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- admin/Abcd@1234
- admin/qwer1234
- ts3/ts3
- centos/123abc
- tcpdump/tcpdump
- root/welcome1
- sconsole/12345
- sysadmin/sysadmin

### Files Uploaded/Downloaded
- Mozi.m
- XMLSchema-instance
- XMLSchema
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No HTTP user agents were logged in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were identified in the logs.

## Key Observations and Anomalies
- A large number of commands executed are related to establishing a persistent SSH connection via authorized_keys, indicating a common tactic for maintaining access.
- The `urbotnetisass` malware was downloaded, suggesting a campaign targeting IoT devices (ARM, MIPS architectures).
- The IP address 143.198.96.196 was responsible for a disproportionately high number of events, suggesting a targeted or aggressive scan from a single source.
- The majority of CVEs exploited are relatively old, indicating that attackers are still targeting unpatched legacy systems.
