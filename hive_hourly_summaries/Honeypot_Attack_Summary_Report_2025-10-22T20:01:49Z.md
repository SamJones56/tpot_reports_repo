
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T20:01:29Z
**Timeframe:** 2025-10-22T19:20:02Z to 2025-10-22T20:00:01Z

**Files Used:**
- agg_log_20251022T192002Z.json
- agg_log_20251022T194002Z.json
- agg_log_20251022T200001Z.json

---

## Executive Summary

This report summarizes 22,083 events collected from the honeypot network over the last hour. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. A significant number of attacks originated from IP addresses 1.55.243.125, 177.91.76.2, and 91.124.88.15. The most targeted ports were TCP/445 and 5038. Attackers attempted to exploit several vulnerabilities, with CVE-2021-3449 and CVE-2024-3721 being the most frequent. A large number of automated commands were observed, primarily related to establishing SSH backdoors and performing system reconnaissance.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7072
- Honeytrap: 6633
- Suricata: 4364
- Dionaea: 1072
- Ciscoasa: 1646
- Sentrypeer: 1000
- Tanner: 140
- Mailoney: 95
- H0neytr4p: 20
- Redishoneypot: 15
- ElasticPot: 8
- Dicompot: 6
- ConPot: 5
- Adbhoney: 5
- Ipphoney: 1
- Medpot: 1

### Top Attacking IPs
- 1.55.243.125: 1313
- 177.91.76.2: 1263
- 91.124.88.15: 2500
- 45.144.232.248: 1246
- 2.56.176.32: 974
- 167.172.130.181: 351
- 128.199.168.119: 347
- 139.59.229.250: 347
- 20.46.54.49: 424
- 88.210.63.16: 381

### Top Targeted Ports/Protocols
- TCP/445: 2628
- 5038: 2498
- 22: 1074
- 5060: 1000
- 445: 916
- 1433: 88
- 80: 135
- 23: 97
- 25: 95

### Most Common CVEs
- CVE-2021-3449
- CVE-2024-3721
- CVE-2024-4577
- CVE-1999-0183
- CVE-2019-11500
- CVE-2021-41773
- CVE-2021-42013
- CVE-2021-35394
- CVE-2020-2551
- CVE-2002-0013
- CVE-2002-0012
- CVE-2002-1149
- CVE-2022-27255

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `top`
- `uname`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `crontab -l`
- `w`

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2622
- ET DROP Dshield Block Listed Source group 1: 400
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 278
- ET SCAN NMAP -sS window 1024: 185
- ET HUNTING RDP Authentication Bypass Attempt: 123
- ET INFO Reserved Internal IP Traffic: 60

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/c0ms4lt
- root/C0nm3d
- carder/3245gs5662d34
- root/c0nv3rg14c0nv3rg14s3V3NM0B1L3...
- hubert/hubert
- rails/rails
- jdog/jdog
- goody/goody
- farida/farida123

### Files Uploaded/Downloaded
- sh
- wget.sh;
- Mozi.m;
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- fonts.gstatic.com
- 11

### HTTP User-Agents
- N/A

### SSH Clients and Servers
- **Clients:** N/A
- **Servers:** N/A

### Top Attacker AS Organizations
- N/A

---

## Key Observations and Anomalies

- **High Volume of SMB Scans:** The high number of attempts on TCP port 445 indicates widespread scanning for SMB vulnerabilities, likely related to exploits like EternalBlue. The triggered "DoublePulsar" Suricata signature supports this.
- **Repetitive SSH Commands:** The most common commands are part of an automated script to disable security attributes, clear existing SSH keys, and install a new public key for backdoor access. This is a typical tactic for botnets to expand their reach.
- **Mirai Botnet Activity:** The download of files like "Mozi.m" and various shell scripts (`w.sh`, `c.sh`) are characteristic of Mirai-style botnets attempting to infect IoT devices.

This concludes the Honeypot Attack Summary Report.
