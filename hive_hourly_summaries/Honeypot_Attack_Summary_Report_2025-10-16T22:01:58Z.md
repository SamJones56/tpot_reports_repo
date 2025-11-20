# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T22:01:30Z
**Timeframe:** 2025-10-16T21:20:01Z to 2025-10-16T22:00:01Z
**Files Used:**
- agg_log_20251016T212001Z.json
- agg_log_20251016T214001Z.json
- agg_log_20251016T220001Z.json

---

## Executive Summary

This report summarizes 20,339 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was 171.102.83.142, and the most targeted port was 445 (SMB). A variety of CVEs were exploited, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing control.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7736
- Dionaea: 4173
- Honeytrap: 2992
- Sentrypeer: 1708
- Ciscoasa: 1644
- Suricata: 1524
- Tanner: 241
- H0neytr4p: 97
- Redishoneypot: 99
- Mailoney: 61
- ElasticPot: 27
- Honeyaml: 17
- Adbhoney: 8
- Dicompot: 7
- ConPot: 4
- Wordpot: 1

### Top Attacking IPs
- 171.102.83.142
- 47.100.73.98
- 101.36.110.41
- 172.86.95.115
- 172.86.95.98
- 185.243.5.158
- 202.51.214.98
- 162.240.109.153
- 43.154.181.18
- 194.107.115.65

### Top Targeted Ports/Protocols
- 445
- 5060
- 22
- 5903
- 8333
- 80
- 6379
- 5901
- 5904
- 5905
- 25
- 3388

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2002-1149
- CVE-2001-0414

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/Qaz123qaz
- root/123@@@
- config/config2025
- centos/centos2019
- ftpuser/ftppassword
- root/Zc123456
- support/112233
- default/default2013
- centos/centos2001

### Files Uploaded/Downloaded
- sh
- ns#
- rdf-schema#
- types#
- core#
- XMLSchema#
- www.drupal.org)
- Mozi.m

---

## Key Observations and Anomalies

- The attacker at 171.102.83.142 is persistent and aggressive, accounting for a significant portion of the total attack volume.
- The overwhelming focus on port 445 suggests widespread SMB scanning, likely for vulnerabilities like EternalBlue.
- The commands executed by attackers indicate a clear pattern of reconnaissance, attempting to identify the system's architecture, resource, and user activity, followed by attempts to install SSH keys for persistent access.
- The presence of `Mozi.m` in downloaded files indicates botnet activity.
