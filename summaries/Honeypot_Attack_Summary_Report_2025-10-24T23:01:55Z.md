# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T23:01:28Z
**Timeframe:** 2025-10-24T22:20:01Z to 2025-10-24T23:00:01Z

**Files Used:**
- agg_log_20251024T222001Z.json
- agg_log_20251024T224001Z.json
- agg_log_20251024T230001Z.json

## Executive Summary

This report summarizes 16,707 attacks recorded by the T-Pot honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. A significant portion of the attacks originated from the IP address 80.94.95.238. The most frequently targeted ports were 22 (SSH) and 5060 (SIP). A variety of CVEs were observed, with CVE-2005-4050 being the most common. Attackers attempted a range of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6413
- **Honeytrap:** 4016
- **Suricata:** 2838
- **Ciscoasa:** 1836
- **Sentrypeer:** 805
- **Tanner:** 451
- **Mailoney:** 120
- **Dionaea:** 68
- **Miniprint:** 52
- **Redishoneypot:** 29
- **Adbhoney:** 29
- **H0neytr4p:** 23
- **ElasticPot:** 14
- **Dicompot:** 7
- **ConPot:** 3
- **ssh-rsa:** 2
- **Honeyaml:** 1

### Top Attacking IPs
- 80.94.95.238: 1593
- 50.6.225.98: 1267
- 198.23.190.58: 607
- 222.108.100.117: 492
- 27.254.149.199: 492
- 101.36.116.29: 488
- 160.251.101.169: 482
- 118.145.207.125: 348
- 195.178.110.108: 340
- 189.36.132.232: 262

### Top Targeted Ports/Protocols
- 22: 857
- 5060: 805
- 80: 439
- UDP/5060: 337
- 8333: 185
- 10250: 98
- 5903: 134
- 5901: 116
- 25: 120
- TCP/22: 72

### Most Common CVEs
- CVE-2005-4050
- CVE-2022-27255
- CVE-2002-1149
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449
- CVE-2024-4577
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2023-31983
- CVE-2020-10987
- CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
- CVE-2021-41773
- CVE-2021-42013

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -m
- w
- crontab -l
- whoami
- uname -a

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 971
- 2023753: 971
- ET DROP Dshield Block Listed Source group 1: 391
- 2402000: 391
- ET SCAN Sipsak SIP scan: 238
- 2008598: 238
- ET SCAN NMAP -sS window 1024: 188
- 2009582: 188
- ET HUNTING RDP Authentication Bypass Attempt: 110
- 2034857: 110

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 35
- root/3245gs5662d34: 16
- root/Edsi1nH: 4
- root/edvzB2fZss1y: 4
- root/Qwerty@123789: 4
- root/eeds190789: 4
- root/cacti: 5
- root/Berbidvps.ir: 3
- root/qwerasdf1234: 3
- face/face: 3

### Files Uploaded/Downloaded
- sh: 98
- wget.sh;: 8
- ns#: 2
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 4
- rondo.qre.sh||busybox: 4
- rondo.qre.sh||curl: 4
- rondo.qre.sh)|sh: 4
- `busybox`: 4
- w.sh;: 2
- c.sh;: 2
- rdf-schema#: 1
- types#: 1
- core#: 1
- XMLSchema#: 1
- www.drupal.org): 1
- soap-envelope: 1
- addressing: 1
- discovery: 1
- env:Envelope>: 1

### HTTP User-Agents
- No user agents were observed in the logs.

### SSH Clients and Servers
- No SSH clients or servers were observed in the logs.

### Top Attacker AS Organizations
- No AS organizations were observed in the logs.

## Key Observations and Anomalies

- The high volume of attacks from a single IP address (80.94.95.238) suggests a targeted or persistent attacker.
- The prevalence of commands related to SSH key manipulation indicates that attackers are attempting to establish long-term access to compromised systems.
- The variety of observed CVEs, ranging from older to more recent vulnerabilities, highlights the opportunistic nature of the attacks.
- The absence of HTTP User-Agents, SSH clients/servers, and AS organization data may indicate that the attacks are being launched from custom scripts or tools that do not advertise this information.
