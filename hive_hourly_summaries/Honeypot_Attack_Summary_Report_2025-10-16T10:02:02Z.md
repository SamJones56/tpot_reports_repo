
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T10:01:38Z
**Timeframe:** 2025-10-16T09:20:02Z to 2025-10-16T10:00:02Z
**Files Included:**
- agg_log_20251016T092002Z.json
- agg_log_20251016T094001Z.json
- agg_log_20251016T100002Z.json

---

## Executive Summary

This report summarizes 29,992 events collected from multiple honeypot sensors over the last hour. The majority of attacks were detected by the Suricata honeypot. The most prominent attack vector observed was VNC authentication attempts, originating primarily from the IP address `45.134.26.47`. A significant number of Cowrie SSH honeypot events were also recorded, with attackers attempting various system reconnaissance and SSH key manipulation commands. Several CVEs were targeted, with a focus on web application and remote code execution vulnerabilities.

---

## Detailed Analysis

### Attacks by Honeypot
- **Suricata:** 9,797
- **Heralding:** 5,795
- **Cowrie:** 4,890
- **Honeytrap:** 2,955
- **Dionaea:** 2,688
- **Sentrypeer:** 1,861
- **Ciscoasa:** 1,040
- **Mailoney:** 865
- **ElasticPot:** 21
- **ConPot:** 26
- **Tanner:** 18
- **H0neytr4p:** 10
- **Ipphoney:** 10
- **Dicompot:** 7
- **Adbhoney:** 4
- **Redishoneypot:** 3
- **Wordpot:** 2
- **Sentrypeer:** 554
- **Honeyaml:** 1

### Top Attacking IPs
- 172.31.36.128: 5801
- 45.134.26.47: 5795
- 103.207.4.234: 1340
- 186.96.151.146: 1296
- 78.188.37.174: 1128
- 14.97.11.58: 1197
- 77.83.240.70: 850
- 86.54.42.238: 822
- 196.251.88.103: 644
- 23.94.26.58: 598

### Top Targeted Ports/Protocols
- vnc/5900: 5795
- 445: 2660
- TCP/445: 2636
- 5060: 1861
- 22: 662
- 25: 865
- TCP/5900: 373
- 5903: 152
- 8333: 111

### Most Common CVEs
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-2023-1389
- CVE-2019-11500
- CVE-2001-0414
- CVE-1999-0517

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- crontab -l
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

### Signatures Triggered
- ET INFO VNC Authentication Failure
- 2002920
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- 2400041
- ET SCAN NMAP -sS window 1024
- 2009582

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- User-Agent: Go-http-client/1.1/Connection: close
- ubnt/ubnt2000
- root/123admin123
- user/user2019
- root/Qaz123qaz
- centos/centos2025
- root/123@@@

### Files Uploaded/Downloaded
- mips;
- )@ubuntu:~$

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

---

## Key Observations and Anomalies

- **High-Volume VNC Scans:** The dominant activity was VNC scans and authentication attempts on port 5900, primarily from `45.134.26.47`.
- **Repetitive Cowrie Commands:** Attackers on the Cowrie honeypot consistently ran a series of commands to gather system information and install a persistent SSH key, indicating an automated attack script.
- **DoublePulsar Activity:** The signature `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` was triggered frequently, suggesting attempts to exploit the SMB vulnerability.

---
