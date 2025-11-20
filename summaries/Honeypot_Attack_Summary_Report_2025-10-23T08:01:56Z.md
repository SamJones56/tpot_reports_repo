Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T08:01:39Z
**Timeframe:** 2025-10-23T07:20:01Z to 2025-10-23T08:00:01Z
**Files Analyzed:**
- agg_log_20251023T072001Z.json
- agg_log_20251023T074002Z.json
- agg_log_20251023T080001Z.json

### Executive Summary

This report summarizes 21,439 malicious events captured by the honeypot network. The most targeted honeypots were Honeytrap (7,419 events) and Cowrie (7,061 events). A significant portion of attacks originated from the IP address 109.205.211.9, which was responsible for 2,444 events. The most frequently targeted ports were 22 (SSH) and 5060 (SIP). Attackers were observed attempting to manipulate SSH authorized_keys files and running various reconnaissance commands.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 7,419
- Cowrie: 7,061
- Suricata: 3,961
- Ciscoasa: 1,713
- Sentrypeer: 907
- ConPot: 98
- Mailoney: 93
- Dionaea: 79
- Tanner: 43
- H0neytr4p: 17
- Miniprint: 12
- Redishoneypot: 12
- Adbhoney: 9
- ElasticPot: 8
- Dicompot: 3
- Heralding: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 109.205.211.9: 2,444
- 185.231.59.125: 1,239
- 185.68.247.151: 866
- 196.251.69.141: 416
- 154.12.82.166: 356
- 51.159.54.22: 356
- 64.227.44.227: 352
- 20.79.154.209: 257
- 107.170.36.5: 251
- 13.39.144.67: 272

**Top Targeted Ports/Protocols:**
- 22: 1,125
- 5060: 907
- 5903: 131
- 5901: 116
- 1434: 68
- 1025: 60
- 25: 52
- 5904: 52
- 5905: 52

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2020-2551
- CVE-2002-1149
- CVE-1999-0183
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2005-4050

**Commands Attempted by Attackers:**
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- uname -a
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake
- ET SCAN Suspicious inbound to Oracle SQL port 1521
- ET SCAN Suspicious inbound to MSSQL port 1433

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- ubuntu/ubuntu
- root/CentreM0014YRC4LLRPMO0
- root/CentreM001
- root/centrix!
- root/Cepillo567
- admin/123456789
- test/test
- test/12345
- mysql/mysql

**Files Uploaded/Downloaded:**
- welcome.jpg
- writing.jpg
- tags.jpg

**HTTP User-Agents:**
- No user agents were recorded in the logs.

**SSH Clients:**
- No SSH clients were recorded in the logs.

**SSH Servers:**
- No SSH servers were recorded in the logs.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in the logs.

### Key Observations and Anomalies

- The high volume of activity from a single IP (109.205.211.9) suggests a targeted or persistent attacker.
- The most common commands are related to establishing persistent access through SSH by adding a public key to `authorized_keys`, and gathering system information.
- A significant number of triggered Suricata signatures are related to scanning for MS Terminal Server and RDP services, indicating widespread reconnaissance for remote access vulnerabilities.
- The variety of honeypots that were triggered indicates that attackers are using a wide range of scanning and exploitation techniques, not focusing on a single protocol or service.
