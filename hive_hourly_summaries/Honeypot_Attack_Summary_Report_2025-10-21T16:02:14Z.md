Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T16:01:36Z
**Timeframe:** 2025-10-21T15:20:01Z to 2025-10-21T16:00:01Z
**Files Used:**
- agg_log_20251021T152001Z.json
- agg_log_20251021T154001Z.json
- agg_log_20251021T160001Z.json

### Executive Summary

This report summarizes 22,302 attacks recorded by honeypot sensors over the last hour. The most targeted services were SMB (port 445), SIP (port 5060), and SSH (port 22). A significant portion of the attacks originated from IP addresses 5.182.209.68 and 201.110.95.72. Attackers attempted various commands, including reconnaissance and attempts to add their SSH keys to the system. Several CVEs were targeted, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
*   Sentrypeer: 4370
*   Cowrie: 6855
*   Dionaea: 5927
*   Honeytrap: 3154
*   Suricata: 1531
*   Redishoneypot: 145
*   H0neytr4p: 95
*   Ciscoasa: 46
*   Mailoney: 72
*   Tanner: 56
*   ConPot: 25
*   Adbhoney: 12
*   Dicompot: 12
*   ElasticPot: 2

**Top Attacking IPs:**
*   5.182.209.68: 4070
*   201.110.95.72: 3092
*   45.171.150.123: 2141
*   72.146.232.13: 1132
*   129.212.179.93: 991
*   187.150.53.146: 495
*   89.221.212.117: 405
*   107.173.10.71: 252
*   171.213.187.92: 238
*   107.170.36.5: 231
*   120.48.35.28: 201
*   125.21.59.218: 252
*   88.210.63.16: 261
*   185.243.5.158: 200
*   194.107.115.199: 185
*   115.21.183.150: 223
*   103.114.147.217: 164
*   159.89.22.242: 173
*   172.245.92.99: 174
*   85.209.134.43: 204

**Top Targeted Ports/Protocols:**
*   5060: 4370
*   445: 5781
*   22: 1261
*   5903: 232
*   6379: 145
*   443: 86
*   25: 72
*   80: 46
*   TCP/22: 62
*   TCP/80: 35
*   5901: 114
*   TCP/21: 130
*   8333: 77
*   5905: 70
*   5904: 70
*   5907: 46
*   5908: 45
*   5909: 46
*   3307: 22
*   21: 18

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 10
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
*   CVE-2021-3449 CVE-2021-3449: 2
*   CVE-2001-0414: 2
*   CVE-2019-11500 CVE-2019-11500: 1

**Commands Attempted by Attackers:**
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 23
*   lockr -ia .ssh: 23
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 23
*   cat /proc/cpuinfo | grep name | wc -l: 22
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 22
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 22
*   ls -lh $(which ls): 22
*   which ls: 22
*   crontab -l: 22
*   w: 22
*   uname -m: 22
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 22
*   top: 22
*   uname: 21
*   uname -a: 21
*   whoami: 21
*   lscpu | grep Model: 21
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 21
*   Enter new UNIX password: : 15
*   Enter new UNIX password:: 15

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 306
*   ET DROP Dshield Block Listed Source group 1: 267
*   ET HUNTING RDP Authentication Bypass Attempt: 135
*   ET SCAN NMAP -sS window 1024: 159
*   ET INFO Reserved Internal IP Traffic: 55
*   ET SCAN Potential SSH Scan: 46
*   ET FTP FTP STOR command attempt without login: 97
*   ET INFO CURL User Agent: 32
*   GPL SNMP request udp: 8
*   GPL SNMP public access udp: 7
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 13
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 6
*   ET FTP FTP CWD command attempt without login: 17
*   ET FTP FTP PWD command attempt without login: 15
*   GPL TELNET Bad Login: 7
*   ET CINS Active Threat Intelligence Poor Reputation IP group 99: 6

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 22
*   odin/odin: 8
*   root/3245gs5662d34: 6
*   fleek/123: 6
*   user01/Password01: 5
*   root/araguaya2015: 4
*   root/argencoop: 3
*   root/aqhTh495R6: 3
*   tigergraph/123: 3
*   root/Aqwerty1234: 3
*   root/meng123456: 2
*   root/4rfv$RFV: 2
*   es/elastic: 2
*   root/Aa123654: 2
*   root/admin1234: 2
*   zhang/zhang: 2
*   mc/mc: 2
*   vbox/123: 2
*   deploy/12345678910: 2
*   ubuntu/Aa123456!: 2

**Files Uploaded/Downloaded:**
*   nse.html: 1

**HTTP User-Agents:**
*   None observed.

**SSH Clients:**
*   None observed.

**SSH Servers:**
*   None observed.

**Top Attacker AS Organizations:**
*   None observed.

### Key Observations and Anomalies

- The vast majority of attacks are automated, focusing on well-known vulnerabilities and default credentials.
- The commands executed suggest attackers are attempting to establish persistent access by adding their public SSH key to the `authorized_keys` file.
- The most frequent attacks are scans and brute-force attempts against SMB, SIP, and SSH.
- There is a notable amount of activity related to reconnaissance of system information (CPU, memory, etc.).

This concludes the Honeypot Attack Summary Report.