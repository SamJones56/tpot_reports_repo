
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T14:01:30Z
**Timeframe:** 2025-10-23T13:20:01Z to 2025-10-23T14:00:01Z
**Files Used:**
- agg_log_20251023T132001Z.json
- agg_log_20251023T134001Z.json
- agg_log_20251023T140001Z.json

## Executive Summary
This report summarizes 17,755 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Honeytrap, and Dionaea honeypots. The most targeted services were SMB (port 445), SSH (port 22), and SIP (port 5060). A significant number of brute-force attempts and automated attacks were observed, with a wide range of commands being executed on the Cowrie honeypot, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6792
- Honeytrap: 5288
- Dionaea: 998
- Ciscoasa: 1767
- Suricata: 1680
- Sentrypeer: 952
- Tanner: 109
- ConPot: 33
- Mailoney: 22
- Redishoneypot: 27
- H0neytr4p: 19
- ElasticPot: 13
- Adbhoney: 4
- Honeyaml: 6
- Dicompot: 18
- Miniprint: 27

### Top Attacking IPs
- 45.171.150.123: 880
- 196.251.88.103: 998
- 134.209.192.157: 534
- 38.146.28.202: 241
- 203.145.34.222: 229
- 36.89.28.139: 242
- 185.243.5.146: 272
- 107.170.36.5: 168
- 202.51.214.99: 227
- 103.189.89.76: 242
- 161.132.37.66: 227
- 85.208.84.222: 135
- 101.36.122.23: 150
- 216.10.242.161: 194

### Top Targeted Ports/Protocols
- 445: 948
- 22: 1059
- 5060: 952
- 5903: 142
- 80: 111
- 5901: 106
- 1911: 71
- 5904: 78
- 5905: 76
- 1434: 34

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551
- CVE-2018-10562 CVE-2018-10561
- CVE-2002-1149
- CVE-2006-2369

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
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
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- system
- shell
- q
- enable
- sh
- cat /proc/mounts; /bin/busybox CYEHP

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- GPL INFO SOCKS Proxy attempt
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- GPL SNMP request udp
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET DROP Spamhaus DROP Listed Traffic Inbound group 6
- ET INFO CURL User Agent
- ET SCAN Potential SSH Scan
- ET SCAN Suspicious inbound to Oracle SQL port 1521

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/CK6YJI4m6dj94
- root/cl0udv00x
- root/cla918a6
- root/clarineto
- root/Claro159
- root/ClaroNOC
- ssl/ssl
- root/admin$2017
- hadoop/123
- root/1029
- docker/docker
- guest/guest123
- root/sun
- elastic/elastic
- root/doitnow
- teamspeak/12345
- tax/tax
- wangjx/wangjx
- magang/magang
- root/8888888
- boda/boda
- hadoop/123123
- jh/jh123
- root/project
- crafty/crafty123
- ubuntu/Abc123
- root/88888888
- zabbix/zabbix
- kubernetes/kubernetes
- root/6yhnMJU&
- testuser/1qaz2wsx
- git/git
- root/admin411
- douglas/douglas
- root/007
- bot/bot
- root/qweqwe11
- git/654321

### Files Uploaded/Downloaded
- gpon80&ipv=0

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was consistently used across multiple attacking IPs, suggesting a coordinated campaign to inject a specific SSH key for persistent access.
- A high volume of scans for MS Terminal Server on non-standard ports was observed, indicating widespread scanning for vulnerable RDP services.
- The DoublePulsar backdoor was detected, which is a known payload associated with the EternalBlue exploit.
- The overwhelming majority of attacks originate from a diverse set of IP addresses, indicating the use of botnets or compromised machines for carrying out attacks.
- The CVEs detected are relatively old, suggesting that attackers are targeting unpatched and legacy systems.
