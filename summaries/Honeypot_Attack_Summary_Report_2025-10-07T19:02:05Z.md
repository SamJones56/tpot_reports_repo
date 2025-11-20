
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T19:01:38Z
**Timeframe:** 2025-10-07T18:20:01Z to 2025-10-07T19:01:01Z
**Files Used:**
- agg_log_20251007T182001Z.json
- agg_log_20251007T184001Z.json
- agg_log_20251007T190001Z.json

## Executive Summary

This report summarizes 13,556 attacks recorded by our honeypot network. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of attacks originated from the IP address 86.54.42.238. The most frequently targeted ports were 25 (SMTP) and 22 (SSH). Several CVEs were detected, with CVE-2021-44228 (Log4Shell) being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistence.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 6126
- **Honeytrap:** 2721
- **Suricata:** 1467
- **Ciscoasa:** 1377
- **Mailoney:** 902
- **Sentrypeer:** 634
- **Dionaea:** 140
- **Tanner:** 81
- **H0neytr4p:** 43
- **Redishoneypot:** 24
- **Honeyaml:** 15
- **Adbhoney:** 9
- **Dicompot:** 7
- **ConPot:** 6
- **Ipphoney:** 2
- **ElasticPot:** 1
- **Miniprint:** 1

### Top Attacking IPs

- 86.54.42.238
- 170.64.161.21
- 185.255.126.223
- 138.197.43.50
- 151.95.223.48
- 103.149.230.61
- 103.217.145.104
- 38.47.94.38
- 103.157.25.60
- 143.198.195.7

### Top Targeted Ports/Protocols

- 25
- 22
- 5060
- 5910
- 8333
- 445
- 80
- 5903
- TCP/22
- 9000

### Most Common CVEs

- CVE-2021-44228
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-35394
- CVE-2023-26801
- CVE-2006-2369

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname -a`
- `whoami`

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET INFO Proxy CONNECT Request
- ET INFO CURL User Agent

### Users / Login Attempts

- 345gs5662d34/345gs5662d34
- sysadmin/sysadmin@1
- ts3/sftpuser!
- github/github12
- github/github!123
- remoto/remoto1
- scanner/Passw0rd@123
- bitrix/P@ssw0rd123
- minecraft/123456789
- student/student21

### Files Uploaded/Downloaded

- sh
- Mozi.m
- Space.mips;

### HTTP User-Agents

- Not observed in this period.

### SSH Clients and Servers

- Not observed in this period.

### Top Attacker AS Organizations

- Not observed in this period.

## Key Observations and Anomalies

- The high number of attacks on port 25 (SMTP) from a single IP (86.54.42.238) suggests a potential spam campaign or a targeted attack on mail services.
- The repeated attempts to modify SSH authorized_keys files indicate a clear intent to establish persistent access.
- The presence of the `Mozi.m` malware download is noteworthy, as Mozi is a known IoT botnet.
- The variety of honeypots that were triggered, including specialized ones like Dicompot and Miniprint, shows a broad spectrum of automated scanning and exploitation attempts.
- No HTTP User-Agents, SSH clients, or AS organizations were recorded in the logs during this period, which might indicate that the attacks were primarily from custom scripts or tools that do not advertise this information.
