Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T00:01:30Z
**Timeframe:** 2025-10-12T23:20:01Z to 2025-10-13T00:00:01Z
**Files Used:**
- agg_log_20251012T232001Z.json
- agg_log_20251012T234001Z.json
- agg_log_20251013T000001Z.json

### Executive Summary
This report summarizes 25,047 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Sentrypeer, and Suricata honeypots. The most frequent attacks originated from IP address 31.40.204.154. The most targeted port was 5060 (SIP). Several CVEs were detected, and attackers attempted numerous commands, primarily related to reconnaissance and establishing persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8422
- Sentrypeer: 4201
- Suricata: 3878
- Honeytrap: 4153
- Ciscoasa: 2054
- Mailoney: 1012
- Dionaea: 790
- H0neytr4p: 441
- Tanner: 44
- ConPot: 26
- Redishoneypot: 12
- Honeyaml: 9
- ElasticPot: 4

**Top Attacking IPs:**
- 31.40.204.154: 4880
- 82.223.10.156: 1246
- 51.89.1.88: 1059
- 196.251.88.103: 988
- 45.128.199.212: 994
- 86.54.42.238: 821
- 139.59.5.228: 560
- 94.182.174.254: 256
- 172.86.95.98: 346
- 62.141.43.183: 294
- 103.97.177.230: 293
- 20.2.136.52: 327
- 34.22.90.59: 167

**Top Targeted Ports/Protocols:**
- 5060: 4201
- 22: 1401
- UDP/5060: 2446
- 25: 1012
- 443: 434
- TCP/21: 198
- 5903: 171
- 21: 107
- 8333: 96
- 8888: 84
- 80: 50

**Most Common CVEs:**
- CVE-2020-2551
- CVE-2002-0013
- CVE-2002-0012
- CVE-2006-2369
- CVE-2005-4050
- CVE-2019-11500

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
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
- Enter new UNIX password:

**Signatures Triggered:**
- ET SCAN Sipsak SIP scan
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 68
- ET DROP Spamhaus DROP Listed Traffic Inbound group 29
- ET CINS Active Threat Intelligence Poor Reputation IP group 42

**Users / Login Attempts:**
- cron/: 45
- 345gs5662d34/345gs5662d34: 20
- holu/holu: 9
- holu/3245gs5662d34: 9
- admin1234/admin1234: 7
- root/0: 6
- sam/sam: 6
- akiwifi/*.H1k1k0_M0r1: 6
- admin/abcd@1234: 6
- admin/raspberry: 6
- ftp/ftp123: 5
- deploy/123123: 5
- vpn/vpnpass: 5

**Files Uploaded/Downloaded:**
- )
- cmd.txt

**HTTP User-Agents:**
- None observed in this period.

**SSH Clients:**
- None observed in this period.

**SSH Servers:**
- None observed in this period.

**Top Attacker AS Organizations:**
- None observed in this period.

### Key Observations and Anomalies
- A high volume of SIP scanning activity was observed, primarily targeting port 5060.
- A significant number of login attempts used common or default credentials, with `cron` being the most frequently used username.
- Attackers consistently attempted to add their SSH key to the `authorized_keys` file for persistent access. The command used was identical across multiple attacking IPs.
- The majority of commands are focused on system enumeration (CPU, memory, etc.) and checking for existing security configurations.
- The CVEs detected are relatively old, suggesting that some attackers are still attempting to exploit legacy vulnerabilities.
- There is a noticeable amount of scanning for FTP and MS Terminal Server services.
