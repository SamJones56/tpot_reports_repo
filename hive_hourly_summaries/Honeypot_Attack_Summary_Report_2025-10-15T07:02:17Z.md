**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-15T07:01:40Z
**Timeframe:** 2025-10-15T06:20:01Z to 2025-10-15T07:00:02Z
**Files Used:**
- agg_log_20251015T062001Z.json
- agg_log_20251015T064001Z.json
- agg_log_20251015T070002Z.json

**Executive Summary**

This report summarizes 22,829 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was 188.246.224.87. The most targeted port was 5060 (SIP). A number of CVEs were targeted, and attackers attempted various commands, primarily focused on reconnaissance and establishing control.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 9146
- Honeytrap: 5400
- Suricata: 3235
- Ciscoasa: 2351
- Sentrypeer: 1770
- Dionaea: 615
- Tanner: 104
- Mailoney: 57
- H0neytr4p: 43
- ssh-rsa: 30
- Dicompot: 29
- Honeyaml: 12
- Miniprint: 9
- Redishoneypot: 9
- ConPot: 5
- Adbhoney: 4
- ElasticPot: 3
- Heralding: 3
- Wordpot: 3
- Ipphoney: 1

***Top Attacking IPs***
- 188.246.224.87: 2399
- 206.191.154.180: 1382
- 94.103.12.49: 889
- 193.24.123.88: 612
- 27.79.1.112: 511
- 172.86.95.98: 454
- 172.86.95.115: 454
- 172.174.5.146: 443
- 124.156.238.210: 419
- 185.243.5.121: 328
- 152.32.172.161: 300
- 94.181.203.60: 292
- 123.31.20.81: 217
- 62.141.43.183: 215
- 89.216.92.113: 201

***Top Targeted Ports/Protocols***
- 5060: 1770
- 22: 1276
- 1433: 501
- 5903: 189
- 8333: 117
- 80: 116
- TCP/1433: 115
- TCP/22: 111
- 5908: 83
- 5909: 83
- 5901: 81
- 23: 68
- UDP/5060: 36
- 25: 57

***Most Common CVEs***
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0183
- CVE-2016-6563
- CVE-2006-2369

***Commands Attempted by Attackers***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`

***Signatures Triggered***
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- 2403349
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- 2403348
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- 2400027

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Password@2025
- root/Qaz123qaz
- ftpuser/ftppassword
- root/123@@@
- root/
- default/1234
- admin/2222222
- config/1111

***Files Uploaded/Downloaded***
- `cd
- Mozi.m
- XMLSchema-instance
- XMLSchema

**Key Observations and Anomalies**

- A significant number of commands are related to reconnaissance of the system's hardware (`uname`, `lscpu`, `cat /proc/cpuinfo`).
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...` is a clear attempt to install a persistent SSH key for backdoor access.
- There are multiple attempts to change user passwords, indicated by the "Enter new UNIX password: " command.
- The presence of "Mozi.m" in downloaded files indicates activity from the Mozi botnet, a known P2P botnet targeting IoT devices.
- The wide range of targeted ports suggests broad, untargeted scanning activity.
- The high number of events on port 5060 (SIP) indicates a focus on VoIP-related attacks.
