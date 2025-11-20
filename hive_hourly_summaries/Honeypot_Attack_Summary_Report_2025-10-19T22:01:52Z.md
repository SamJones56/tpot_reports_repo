
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T22:01:31Z
**Timeframe:** 2025-10-19T21:20:01Z to 2025-10-19T22:00:01Z
**Log Files:** agg_log_20251019T212001Z.json, agg_log_20251019T214002Z.json, agg_log_20251019T220001Z.json

---

## Executive Summary

This report summarizes 8,514 malicious activities detected by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. The most frequent attacker IP was 47.253.227.124. A significant number of attacks also targeted SIP (port 5060) and HTTP (port 80) services. Several CVEs were targeted, with CVE-2005-4050 being the most common. Attackers were observed attempting to modify SSH authorized_keys to maintain persistence.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4784
- Honeytrap: 1365
- Suricata: 926
- Sentrypeer: 590
- Ciscoasa: 568
- Tanner: 192
- Dionaea: 23
- Mailoney: 21
- H0neytr4p: 11
- Redishoneypot: 11
- ConPot: 10
- ssh-rsa: 6
- Honeyaml: 5
- Adbhoney: 2

### Top Attacking IPs
- 47.253.227.124
- 198.23.190.58
- 72.146.232.13
- 206.189.97.124
- 173.212.238.152
- 213.142.151.19
- 107.170.36.5
- 198.12.68.114
- 68.183.149.135
- 102.88.137.213
- 82.156.226.106
- 15.168.255.44
- 107.172.59.44
- 210.79.191.147
- 200.8.228.57
- 103.176.78.241
- 5.198.176.28
- 203.154.162.65
- 181.115.147.5
- 103.176.78.213

### Top Targeted Ports/Protocols
- 22
- 5060
- UDP/5060
- 80
- 8333
- 5905
- 5904
- 23
- 5901
- 5902
- 5903
- TCP/5432
- 25
- UDP/161
- 9500
- 9093
- 6379
- 10001
- 7657
- 443

### Most Common CVEs
- CVE-2005-4050
- CVE-2022-27255 CVE-2022-27255
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2022-1388 CVE-2022-1388
- CVE-2019-11500 CVE-2019-11500
- CVE-2024-3721 CVE-2024-3721
- CVE-2021-35395 CVE-2021-35395
- CVE-2016-20017 CVE-2016-20017
- CVE-2006-2369
- CVE-2001-0414

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 
- Enter new UNIX password:

### Signatures Triggered
- ET SCAN Sipsak SIP scan
- 2008598
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET VOIP MultiTech SIP UDP Overflow
- 2003237
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- 2038669
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- 2010939
- GPL SNMP request udp
- 2101417

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/
- sandeep/123
- root/zxcZXC123!@#
- root/Pa55w0rd!
- deploy/123123
- deploy/3245gs5662d34
- antonio/antonio123
- blank/888888
- git/git123
- debian/55
- root/sam
- admin/admin2014
- debian/33
- radio/a123456
- radio/3245gs5662d34
- ali/P@ssw0rd!
- debian/debian1234567890
- root/81jvaLXfPRtclgt

### Files Uploaded/Downloaded
- rondo.eby.sh|sh

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

---

## Key Observations and Anomalies

- **Persistent SSH Intrusion Attempts:** A significant portion of the observed commands are related to reconnaissance (`uname`, `lscpu`, `free -m`) and attempts to establish persistence by adding a public SSH key to `authorized_keys`. The use of `chattr` and a custom `lockr` command suggests an attempt to make their modifications immutable.
- **SIP Scanning:** The high volume of traffic on port 5060, flagged by "ET SCAN Sipsak SIP scan", points to widespread scanning for vulnerable Voice over IP (VoIP) systems.
- **File Downloads:** The download of `rondo.eby.sh` should be investigated. Shell scripts downloaded by attackers often contain malware, botnet clients, or crypto miners.

---
