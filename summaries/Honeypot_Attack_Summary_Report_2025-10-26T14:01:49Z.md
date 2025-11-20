
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T14:01:31Z
**Timeframe:** 2025-10-26T13:20:01Z to 2025-10-26T14:00:01Z

**Files Used:**
- agg_log_20251026T132001Z.json
- agg_log_20251026T134001Z.json
- agg_log_20251026T140001Z.json

## Executive Summary

This report summarizes the activity recorded by the T-Pot honeypot network over a 40-minute period. A total of 26,351 attacks were detected across various honeypots. The most targeted services were SSH (Cowrie) and SMB (Dionaea), with a significant number of events also captured by the Suricata IDS. The majority of attacks originated from the IP address 109.205.211.9. A variety of CVEs were targeted, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 10,250
- **Suricata:** 5,789
- **Honeytrap:** 4,720
- **Ciscoasa:** 1,773
- **Dionaea:** 1,677
- **Sentrypeer:** 1,634
- **Tanner:** 222
- **Mailoney:** 107
- **Miniprint:** 50
- **Adbhoney:** 49
- **Redishoneypot:** 24
- **H0neytr4p:** 23
- **Dicompot:** 12
- **ConPot:** 9
- **ElasticPot:** 6
- **Honeyaml:** 6

### Top Attacking IPs
- 109.205.211.9
- 172.188.91.73
- 41.139.164.134
- 144.172.108.231
- 203.171.29.193
- 62.60.131.18
- 185.243.5.121
- 50.84.211.204
- 162.240.109.153
- 8.243.50.114

### Top Targeted Ports/Protocols
- 22
- 5060
- 445
- 80
- 8333
- 5903
- TCP/22
- 5901
- 25
- 10089

### Most Common CVEs
- CVE-2018-10562, CVE-2018-10561
- CVE-2005-4050
- CVE-2006-2369
- CVE-2002-0013, CVE-2002-0012
- CVE-2024-4577
- CVE-2002-0953
- CVE-1999-0517
- CVE-2021-41773
- CVE-2021-42013

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- crontab -l
- w
- uname -m
- uname -a
- whoami

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET DROP Spamhaus DROP Listed Traffic Inbound

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- bash/Drag1823hcacatcuciocolataABC111
- root/02041992Ionela%^&
- jla/xurros22$
- ubuntu/tizi@123
- root/123456789
- root/adminHW
- root/I8CJ5CY9EP
- users/fuckoff
- pi/pi

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- arm.uhavenobotsxd;
- arm5.uhavenobotsxd;
- arm6.uhavenobotsxd;
- arm7.uhavenobotsxd;
- x86_32.uhavenobotsxd;
- mips.uhavenobotsxd;
- mipsel.uhavenobotsxd;
- sh
- a>

### HTTP User-Agents
- No HTTP user agents were recorded in the logs.

### SSH Clients and Servers
- No specific SSH clients or servers were recorded in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in the logs.

## Key Observations and Anomalies

- The volume of attacks is consistently high, indicating automated scanning and exploitation attempts.
- The commands executed by attackers suggest a focus on disabling security measures (chattr), establishing persistent SSH access, and performing system reconnaissance.
- The presence of commands attempting to download and execute shell scripts and binaries (e.g., `wget.sh`, `arm.uhavenobotsxd`) indicates attempts to deploy malware or establish botnet clients.
- The variety of CVEs targeted shows that attackers are attempting to exploit a wide range of vulnerabilities, from older to more recent ones.
- The high number of RDP-related signatures triggered on non-standard ports suggests widespread scanning for exposed Remote Desktop Protocol services.
