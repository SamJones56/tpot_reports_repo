# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T01:01:29Z
**Timeframe:** 2025-10-06T00:20:01Z to 2025-10-06T01:00:01Z

**Files Used:**
- agg_log_20251006T002001Z.json
- agg_log_20251006T004001Z.json
- agg_log_20251006T010001Z.json

## Executive Summary

This report summarizes 11,501 events collected from the honeypot network. The majority of attacks targeted the Cowrie (SSH) and Mailoney (SMTP) honeypots. A significant number of attacks originated from IP addresses listed on the Dshield blocklist, indicating a high volume of automated scanning and exploitation attempts. Attackers were observed attempting to gain persistent access by adding SSH keys, downloading and executing malicious scripts, and performing system reconnaissance.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4617
- Mailoney: 2503
- Ciscoasa: 1396
- Suricata: 1339
- Honeytrap: 877
- Sentrypeer: 518
- Adbhoney: 45
- Dionaea: 53
- Tanner: 24
- Heralding: 16
- H0neytr4p: 16
- Redishoneypot: 17
- ConPot: 16
- Honeyaml: 17
- Wordpot: 3
- Dicompot: 3
- ElasticPot: 2
- ipphoney: 9
- ssh-rsa: 30

### Top Attacking IPs
- 176.65.141.117: 1640
- 86.54.42.238: 821
- 172.86.95.98: 450
- 47.254.0.169: 437
- 76.184.84.186: 288
- 128.1.131.163: 272
- 175.148.157.2: 238
- 85.209.134.43: 223
- 31.58.171.28: 222
- 172.190.117.128: 213
- 101.126.130.220: 214
- 223.241.247.214: 174
- 163.44.99.216: 198
- 14.103.122.182: 184
- 54.38.79.136: 209

### Top Targeted Ports/Protocols
- 25: 2503
- 22: 636
- 5060: 518
- 23: 156
- TCP/443: 71
- TCP/1433: 43
- 80: 27
- 443: 9
- 6379: 17
- 1433: 14
- TCP/80: 23
- 5902: 11
- 5903: 11
- 31112: 12
- 8083: 10

### Most Common CVEs
- CVE-2023-26801
- CVE-2001-0414
- CVE-2002-0013
- CVE-2002-0012
- CVE-2005-4050

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -m
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- top
- uname
- uname -a

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Possible SSL Brute Force attack or Site Crawl
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET DROP Spamhaus DROP Listed Traffic Inbound group 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 68

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/
- postgres/123
- postgres/postgres
- root/Monu@123
- ubuntu/p2ssw0rd
- liujue/!@#$%^
- sanjivani/sanjivani@123
- visco/123
- admin/kingdee
- admin/zhenjie
- admin/123qaz123qaz
- admin/!@#$qwerASDFzxcv

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- **High Volume of Automated Attacks:** The large number of events from IPs on the Dshield blocklist suggests that the majority of attacks are automated and indiscriminate.
- **Credential Stuffing and Brute Forcing:** The variety of usernames and passwords observed indicates widespread credential stuffing and brute-force attacks, particularly against SSH and other login services.
- **Living Off the Land Techniques:** Attackers are using common system commands (`uname`, `lscpu`, `df`, `free`) to gather information about the environment before deploying more advanced payloads.
- **Persistence Mechanisms:** The repeated attempts to add an SSH key to `~/.ssh/authorized_keys` is a clear indicator of attackers trying to establish persistent access to the compromised system.
- **Malware Delivery:** The downloading and execution of shell scripts (`wget.sh`, `w.sh`, `c.sh`) is a common method for delivering and executing malware on a compromised host.
