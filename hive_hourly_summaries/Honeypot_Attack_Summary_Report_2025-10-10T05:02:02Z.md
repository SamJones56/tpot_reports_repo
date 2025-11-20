# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T05:01:29Z
**Timeframe:** 2025-10-10 04:20:01Z to 2025-10-10 05:00:01Z
**Files Used:**
- agg_log_20251010T042001Z.json
- agg_log_20251010T044001Z.json
- agg_log_20251010T050001Z.json

## Executive Summary

This report summarizes 22,666 events collected from the honeypot network. The majority of attacks were reconnaissance and brute-force attempts targeting SSH, SMB, and SIP services. Multiple CVEs were triggered, and attackers attempted to run various commands to gather system information and establish persistence.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 9448
- Dionaea: 4510
- Suricata: 2624
- Honeytrap: 2161
- Ciscoasa: 1786
- Sentrypeer: 907
- H0neytr4p: 97
- Tanner: 25
- Mailoney: 30
- Adbhoney: 17
- ssh-rsa: 30
- ElasticPot: 11
- Redishoneypot: 12
- Ipphoney: 1
- Dicompot: 3
- ConPot: 2
- Honeyaml: 2

### Top Attacking IPs

- 160.202.11.138: 3117
- 137.184.179.27: 1244
- 51.89.1.86: 1243
- 46.32.178.94: 1248
- 31.40.204.154: 1069
- 167.250.224.25: 1122
- 189.192.19.4: 475
- 144.31.26.225: 692
- 177.12.16.118: 651
- 193.24.123.88: 198

### Top Targeted Ports/Protocols

- 445: 4327
- 22: 1731
- 5060: 907
- UDP/5060: 536
- 1433: 123
- 5903: 203
- 443: 91
- TCP/22: 104
- TCP/1433: 89
- 8333: 67

### Most Common CVEs

- CVE-2021-3449
- CVE-2005-4050
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2006-2369
- CVE-2021-35394

### Commands Attempted by Attackers

- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
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
- uname -s -v -n -r -m
- tftp; wget; /bin/busybox EXPWS

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 47, 43, 45, 48, 49, 50
- ET INFO CURL User Agent

### Users / Login Attempts

- 345gs5662d34/345gs5662d34
- Root/1q2w3e4r
- ubuntu/ubuntu
- root/zxc2025, root/zxc2024, root/qweasdzxc, root/asd, root/asd123, root/asd1234, root/asd12345, root/root123, root/toor
- guest/alpine, guest/toor
- user/123456789, user/user, user/test
- unknown/2222222222, unknown/222222
- support/Password01!
- supervisor/administrator
- admin/admin44
- nagios/nagios
- vpn/1234567
- sa/
- root/

### Files Uploaded/Downloaded

- wget.sh
- w.sh
- c.sh
- &currentsetting.htm=1
- hide.mpsl

### HTTP User-Agents

- No user agents recorded.

### SSH Clients

- No SSH clients recorded.

### SSH Servers

- No SSH servers recorded.

### Top Attacker AS Organizations

- No AS organizations recorded.

## Key Observations and Anomalies

- A significant amount of scanning and brute-force activity was observed from a small number of IP addresses, suggesting targeted attacks.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\" >> .ssh/authorized_keys` was frequently used, indicating attempts to install SSH keys for persistent access.
- Several attackers attempted to download and execute shell scripts (e.g., `wget.sh`, `w.sh`, `c.sh`), likely to install malware or backdoors.
- The presence of `Sipsak SIP scan` signatures indicates a high interest in VoIP-related services.
