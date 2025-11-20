
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T19:01:34Z
**Timeframe:** 2025-10-10T18:20:01Z to 2025-10-10T19:00:01Z
**Files Used:**
- agg_log_20251010T182001Z.json
- agg_log_20251010T184001Z.json
- agg_log_20251010T190001Z.json

---

## Executive Summary

This report summarizes 14,641 attacks recorded across multiple honeypots. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacker IP was 167.250.224.25, and the most targeted port was port 22 (SSH). Several CVEs were detected, with CVE-2022-27255 being the most common. A significant number of shell commands were executed, indicating attempts to profile the system and establish persistent access.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5666
- **Honeytrap:** 3214
- **Suricata:** 2416
- **Ciscoasa:** 1736
- **Dionaea:** 901
- **Tanner:** 199
- **Sentrypeer:** 199
- **Heralding:** 67
- **Mailoney:** 66
- **Miniprint:** 48
- **H0neytr4p:** 44
- **ElasticPot:** 16
- **Adbhoney:** 21
- **Redishoneypot:** 17
- **Honeyaml:** 16
- **Dicompot:** 11
- **ConPot:** 3
- **Ipphoney:** 1

### Top 10 Attacking IPs
- **167.250.224.25:** 557
- **88.210.63.16:** 372
- **119.207.254.77:** 349
- **31.40.204.154:** 291
- **198.12.77.137:** 224
- **178.185.136.57:** 218
- **200.7.101.139:** 184
- **103.179.57.31:** 178
- **103.191.92.110:** 216
- **93.183.95.143:** 242

### Top 10 Targeted Ports/Protocols
- **22:** 840
- **TCP/21:** 237
- **5060:** 199
- **5903:** 194
- **80:** 191
- **UDP/5060:** 140
- **21:** 118
- **23:** 76
- **8333:** 102
- **445:** 46

### Most Common CVEs
- **CVE-2022-27255:** 22
- **CVE-2019-11500:** 3
- **CVE-2021-3449:** 3
- **CVE-2021-35394:** 1

### Top 10 Commands Attempted by Attackers
- **cd ~ && rm -rf .ssh && ...:** 25
- **lockr -ia .ssh:** 25
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 25
- **cat /proc/cpuinfo | grep name | wc -l:** 25
- **uname -a:** 25
- **Enter new UNIX password: ** 19
- **Enter new UNIX password:** 19
- **free -m | grep Mem | ...:** 24
- **ls -lh $(which ls):** 24
- **which ls:** 24

### Top 10 Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 445
- **2402000:** 445
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 423
- **2023753:** 423
- **ET HUNTING RDP Authentication Bypass Attempt:** 196
- **2034857:** 196
- **ET SCAN NMAP -sS window 1024:** 149
- **2009582:** 149
- **ET FTP FTP PWD command attempt without login:** 117
- **2010735:** 117
- **ET FTP FTP CWD command attempt without login:** 117
- **2010731:** 117
- **ET SCAN Sipsak SIP scan:** 114
- **2008598:** 114

### Top 10 Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 25
- **root/nPSpP4PBW0:** 20
- **root/Ahgf3487@rtjhskl854hd47893@#a4nC:** 12
- **ubnt/00:** 6
- **debian/123abc:** 6
- **root/3245gs5662d34:** 5
- **admin/alpine:** 4
- **root/mark@pro@87A600:** 4
- **root/mark@pro@870600:** 4
- **root/t3kubj@2015@tix:** 4

### Files Uploaded/Downloaded
- **wget.sh;**: 4
- **welcome.jpg)**: 4
- **writing.jpg)**: 4
- **tags.jpg)**: 4
- **w.sh;**: 3
- **c.sh;**: 3
- **rondo.kqa.sh|sh&echo**: 2
- **k.php?a=x86_64,FLT8F4J68U4L2DZ6H**: 1

### HTTP User-Agents
- None observed in this period.

### SSH Clients and Servers
- None observed in this period.

### Top Attacker AS Organizations
- None observed in this period.

---

## Key Observations and Anomalies

- **Repetitive SSH Commands:** The high frequency of commands like `cd ~ && rm -rf .ssh && ...` suggests automated scripts are attempting to install SSH keys for persistent access.
- **System Profiling:** Attackers are consistently running commands such as `uname -a`, `lscpu`, and `cat /proc/cpuinfo` to understand the architecture of the honeypot, likely to tailor future attacks or payloads.
- **Targeted Services:** SSH (port 22) remains the primary target, but there is also significant scanning activity for VNC (5900-5910), SIP (5060), and FTP (21) services.
- **RDP Scans:** A large number of signatures for "MS Terminal Server Traffic" and "RDP Authentication Bypass Attempt" were triggered, indicating widespread scanning for vulnerable RDP servers.
- **Credential Stuffing:** The variety of usernames and passwords indicates brute-force attacks, likely using common credential lists.

---
