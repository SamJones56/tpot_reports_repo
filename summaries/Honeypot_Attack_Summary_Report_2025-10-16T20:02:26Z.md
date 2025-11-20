## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T20:01:30Z
**Timeframe:** 2025-10-16T19:20:01Z to 2025-10-16T20:00:01Z
**Files Used:**
- agg_log_20251016T192001Z.json
- agg_log_20251016T194001Z.json
- agg_log_20251016T200001Z.json

### Executive Summary

This report summarizes 18,767 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from IP address 45.78.193.108. The most targeted port was 5060 (SIP), and the most common vulnerability targeted was CVE-2022-27255. Attackers were observed attempting to modify SSH configurations and gather system information.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6693
- Honeytrap: 3578
- Sentrypeer: 3081
- Suricata: 2310
- Ciscoasa: 1547
- Mailoney: 880
- Dionaea: 434
- Tanner: 100
- H0neytr4p: 41
- ConPot: 35
- Adbhoney: 24
- Miniprint: 12
- Honeyaml: 9
- Redishoneypot: 9
- Dicompot: 7
- Ipphoney: 3
- Heralding: 3
- ElasticPot: 1

**Top Attacking IPs:**
- 45.78.193.108
- 198.23.190.58
- 47.237.96.241
- 86.54.42.238
- 23.94.26.58
- 35.199.82.7
- 172.86.95.115
- 172.86.95.98
- 185.243.5.158
- 81.30.212.94
- 186.118.142.216
- 45.140.17.52
- 103.210.21.178
- 84.247.183.114
- 57.129.74.123
- 107.170.36.5
- 85.198.83.143
- 198.12.68.114
- 179.40.112.10
- 147.93.29.213

**Top Targeted Ports/Protocols:**
- 5060
- 22
- 25
- UDP/5060
- 445
- TCP/5900
- 5903
- 8333
- 5901
- 80
- 5904
- 5905
- 8728
- 5908
- 5907
- 5909
- 443
- 5902
- TCP/5432
- 23

**Most Common CVEs:**
- CVE-2022-27255 CVE-2022-27255
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-1149
- CVE-2023-49103 CVE-2023-49103
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2001-0414
- CVE-2024-50340 CVE-2024-50340 CVE-2024-50340

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- Enter new UNIX password:
- Enter new UNIX password:

**Signatures Triggered:**
- ET SCAN Sipsak SIP scan
- 2008598
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- 2400041
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Qaz123qaz
- root/QWE123!@#qwe
- ubnt/4444444
- debian/debian2001
- operator/operator2012
- nobody/555555
- user/user2023
- ftpuser/ftppassword
- supervisor/supervisor123
- root/!123acesso2013
- operator/123123
- config/config000
- blank/66666
- blank/444444
- root/!1Intranet
- unknown/unknown2003
- root/!3l3ctr0nics
- blank/1234

**Files Uploaded/Downloaded:**
- ns#
- rdf-schema#
- types#
- core#
- XMLSchema#
- www.drupal.org)

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies
- A significant amount of reconnaissance and automated attacks were observed, particularly targeting SIP (5060) and SSH (22) services.
- Attackers frequently attempted to add their own SSH key to the authorized_keys file for persistent access.
- A wide variety of generic and default credentials were used in brute-force attempts.
- The most common commands are related to system information gathering.
- The triggered signatures indicate a mix of scanning activity, blocklisted IPs, and some specific exploit attempts.
