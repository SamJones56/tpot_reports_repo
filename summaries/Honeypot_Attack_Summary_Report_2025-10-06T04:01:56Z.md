# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T04:01:36Z
**Timeframe:** 2025-10-06T03:20:01Z to 2025-10-06T04:00:02Z
**Files Used:**
- `agg_log_20251006T032001Z.json`
- `agg_log_20251006T034001Z.json`
- `agg_log_20251006T040002Z.json`

## Executive Summary

This report summarizes 15,945 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force and command-line activity. A significant number of events were also logged by Suricata, Honeytrap, and Ciscoasa honeypots. The most prominent attack vector appears to be repeated attempts to gain shell access and deploy malicious scripts.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7,742
- **Honeytrap:** 2,735
- **Suricata:** 2,082
- **Ciscoasa:** 1,394
- **Mailoney:** 851
- **Sentrypeer:** 479
- **Heralding:** 301
- **Dionaea:** 105
- **H0neytr4p:** 89
- **Adbhoney:** 40
- **ConPot:** 53
- **Tanner:** 55
- **Honeyaml:** 12
- **Redishoneypot:** 6
- **Ipphoney:** 1

### Top Attacking IPs
- 8.152.211.133
- 176.65.141.117
- 80.94.95.238
- 4.144.169.44
- 172.86.95.98
- 161.248.147.124
- 140.249.22.89
- 125.88.225.11
- 4.227.178.94
- 41.59.86.232
- 197.248.8.33
- 64.225.55.168
- 115.190.13.99
- 209.97.161.72
- 160.251.196.99

### Top Targeted Ports/Protocols
- 22
- 25
- 5060
- vnc/5900
- 443
- 445
- 80
- 5902
- 5903
- 7443

### Most Common CVEs
- CVE-2021-44228 (Log4j)
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `whoami`
- `uname -a`
- `w`
- `crontab -l`
- `ls -lh $(which ls)`
- `which ls`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `cat /proc/cpuinfo | grep name | wc -l`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `top`
- `uname`
- `uname -m`
- `chmod 0755 /data/local/tmp/nohup`
- `chmod 0755 /data/local/tmp/trinity`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO VNC Authentication Failure
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228)
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET HUNTING RDP Authentication Bypass Attempt
- GPL INFO SOCKS Proxy attempt
- ET DROP Spamhaus DROP Listed Traffic Inbound

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- sa/
- admin/1234
- fairway/3245gs5662d34
- criminal/criminal
- academic/123
- fairway/fairway@123
- beryl/123
- graham/123
- angie/3245gs5662d34
- academic/academic123
- protozoa/protozoa123
- nepenthe/nepenthe123
- joanne/123
- suzie/123
- terminal/123

### Files Uploaded/Downloaded
- `?format=json`
- `1.sh;`
- `generate_204`
- `gpon80&ipv=0`
- `)`

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No specific SSH clients recorded in this period.

### SSH Servers
- No specific SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organization data recorded in this period.

## Key Observations and Anomalies

- **High Volume of SSH Activity:** The prevalence of commands related to SSH key manipulation (`.ssh/authorized_keys`) indicates a consistent campaign to establish persistent access.
- **Log4j Exploitation:** The `CVE-2021-44228` (Log4j) vulnerability continues to be a target for opportunistic attackers.
- **VNC Failures:** A large number of `ET INFO VNC Authentication Failure` signatures were triggered, suggesting brute-force attacks against VNC services.
- **Reconnaissance Commands:** Attackers frequently used reconnaissance commands (`uname`, `lscpu`, `whoami`, `df -h`) to gather system information immediately after attempting to gain access.
- **Mail Service Probes:** The Mailoney honeypot captured a significant number of events, primarily targeting port 25 (SMTP), indicating that mail servers are being actively scanned and targeted.
