# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T00:01:28Z
**Timeframe:** 2025-10-14T23:20:01Z to 2025-10-15T00:00:01Z
**Files Used:**
- `agg_log_20251014T232001Z.json`
- `agg_log_20251014T234001Z.json`
- `agg_log_20251015T000001Z.json`

## Executive Summary
This report summarizes 22,051 events collected from the honeypot network. The majority of attacks were reconnaissance and brute-force attempts targeting a variety of services, with a significant number of attempts to download and execute malicious payloads. The most targeted services were SIP (5060), Redis (6379), and SSH (22).

## Detailed Analysis

### Attacks by Honeypot
- Cowrie
- Honeytrap
- Sentrypeer
- Suricata
- Ciscoasa
- Redishoneypot
- Mailoney
- Heralding
- Tanner
- Dionaea

### Top Attacking IPs
- 47.251.171.50
- 206.191.154.180
- 185.243.5.146
- 185.243.5.148
- 176.65.141.119
- 79.116.40.89
- 88.210.63.16
- 172.86.95.98
- 172.86.95.115
- 81.45.181.135

### Top Targeted Ports/Protocols
- 5060
- 6379
- 22
- 25
- vnc/5900
- 80
- 5903
- 8333
- 27017
- TCP/1433

### Most Common CVEs
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013

### Commands Attempted by Attackers
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `lockr -ia .ssh`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO VNC Authentication Failure
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 49

### Users / Login Attempts
- root/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Password@2025
- root/Qaz123qaz
- debian/debian1234
- admin/admin1234567
- support/777777
- ubnt/ubnt2025
- config/33

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- sh
- Help:Contents
- a>

### HTTP User-Agents
- No user agents were logged in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this period.

### Top Attacker AS Organizations
- No AS organizations were logged in this period.

## Key Observations and Anomalies
- A significant number of commands are focused on system reconnaissance (`uname`, `lscpu`, `free`, etc.).
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates attempts to install persistent SSH keys.
- The `nohup bash -c "exec 6<>/dev/tcp/...` commands suggest attempts to establish reverse shells and download further malware.
- The filenames `*.urbotnetisass` suggest a campaign related to the "urbotnet" botnet.
- A large number of VNC authentication failures were observed, indicating widespread scanning for open VNC servers.
