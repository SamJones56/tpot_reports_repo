Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T11:01:32Z
**Timeframe:** 2025-10-21T10:20:02Z to 2025-10-21T11:00:01Z
**Files Analyzed:**
- agg_log_20251021T102002Z.json
- agg_log_20251021T104001Z.json
- agg_log_20251021T110001Z.json

**Executive Summary**

This report summarizes 16,577 attacks recorded across three honeypot log files. The majority of attacks were captured by the `Cowrie`, `Honeytrap`, and `Suricata` honeypots. The most prominent attack vectors were directed at ports 445 (SMB) and 22 (SSH). The most active attacking IP addresses were `14.241.1.119`, `142.4.197.12`, and `106.51.31.166`. Several CVEs were observed, with `CVE-2002-0013` and `CVE-2002-0012` being the most frequently detected. A variety of commands were attempted by attackers, primarily aimed at system reconnaissance and establishing persistence.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 5766
- Honeytrap: 5015
- Suricata: 3161
- Dionaea: 1728
- Sentrypeer: 709
- Tanner: 63
- Mailoney: 29
- Ciscoasa: 27
- H0neytr4p: 20
- ConPot: 16
- Adbhoney: 9
- ElasticPot: 8
- Dicompot: 8
- Redishoneypot: 8
- Heralding: 6
- Ipphoney: 2
- Honeyaml: 2

***Top Attacking IPs***

- 14.241.1.119: 1471
- 142.4.197.12: 1156
- 106.51.31.166: 1403
- 72.167.220.12: 1266
- 72.146.232.13: 1217
- 185.243.5.158: 257
- 107.170.36.5: 251
- 45.120.216.232: 209
- 172.200.228.35: 199
- 35.200.237.19: 184
- 165.227.98.222: 365
- 1.94.38.61: 303
- 23.94.26.58: 263
- 221.121.100.32: 184
- 197.5.145.150: 130
- 77.83.207.203: 139
- 5.39.250.130: 146
- 5.181.86.179: 124
- 101.36.109.130: 114
- 69.74.29.21: 108
- 4.197.171.110: 108
- 103.171.85.219: 94
- 209.141.41.212: 94
- 196.251.115.80: 94

***Top Targeted Ports/Protocols***

- 445: 1650
- 22: 1186
- TCP/445: 1469
- 5060: 709
- 5903: 227
- 80: 50
- TCP/22: 93
- 8333: 90
- 5901: 114
- 5905: 78
- 5904: 77
- TCP/80: 39
- 2006: 39
- TCP/1080: 24
- 3306: 22
- 23: 37
- 25: 19
- UDP/161: 19
- TCP/9200: 12
- 3128: 16
- 8889: 16
- 8001: 13
- 8888: 13
- 51750: 11

***Most Common CVEs***

- CVE-2002-0013 CVE-2002-0012: 14
- CVE-2019-11500 CVE-2019-11500: 8
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-1999-0183: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 12
- lockr -ia .ssh: 12
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 12
- cat /proc/cpuinfo | grep name | wc -l: 12
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 12
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 12
- ls -lh $(which ls): 12
- which ls: 12
- crontab -l: 12
- w: 12
- uname -m: 12
- cat /proc/cpuinfo | grep model | grep name | wc -l: 12
- top: 12
- uname: 12
- uname -a: 13
- whoami: 12
- lscpu | grep Model: 13
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 13
- Enter new UNIX password: : 8
- Enter new UNIX password:": 8
- ./nbBs0fhH: 2
- echo "root:neht2eoL0eix"|chpasswd|bash: 1

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1465
- 2024766: 1465
- ET DROP Dshield Block Listed Source group 1: 461
- 2402000: 461
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 248
- 2023753: 248
- ET SCAN NMAP -sS window 1024: 186
- 2009582: 186
- ET HUNTING RDP Authentication Bypass Attempt: 94
- 2034857: 94
- ET SCAN Potential SSH Scan: 71
- 2001219: 71
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET INFO CURL User Agent: 18
- 2002824: 18
- GPL SNMP request udp: 10
- 2101417: 10
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 9
- 2400027: 9
- ET SCAN Suspicious inbound to MSSQL port 1433: 8
- 2010935: 8
- GPL INFO SOCKS Proxy attempt: 23
- 2100615: 23
- ET CINS Active Threat Intelligence Poor Reputation IP group 97: 6
- 2403396: 6

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34: 12
- root/Amir9361569: 4
- root/amistef123: 4
- root/amp111: 4
- root/AMORbonita1506: 4
- root/amperia2014: 4
- root/Ams400--: 4
- root/abc123: 4
- odin/odin: 3
- test01/test: 2
- sa/: 2
- pi/raspberry: 2
- root/test123@: 2
- root/config: 2
- apache/apache123: 2
- esroot/esroot: 2
- root/p@ssword: 2
- nginx/nginx123: 2
- lighthouse/lighthouse123: 2
- root/qQ123456: 2
- git/123: 2
- root/PASSw0rd: 2
- root/passwd!@: 2
- root/3245gs5662d34: 2

***Files Uploaded/Downloaded***

- sh: 98
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- ohsitsvegawellrip.sh|sh;#: 1

***HTTP User-Agents***

- No HTTP user agents were recorded in the logs.

***SSH Clients***

- No SSH clients were recorded in the logs.

***SSH Servers***

- No SSH servers were recorded in the logs.

***Top Attacker AS Organizations***

- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

- A significant number of attacks are leveraging the DoublePulsar backdoor, indicating a potential campaign targeting SMB vulnerabilities.
- Attackers are consistently attempting to add their SSH keys to the `authorized_keys` file to maintain persistent access.
- A wide variety of credentials are being used in brute-force attacks, suggesting the use of common credential lists.
- The command `lscpu | grep Model` was frequently used, indicating an interest in the underlying hardware of the honeypot.
- The file `ohsitsvegawellrip.sh` was downloaded, which is a known malware downloader script.
- The attackers are using a variety of architectures for their malware (arm, mips, x86), indicating a broad targeting strategy.
- The `Suricata` logs show a high number of alerts for `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`, which is a strong indicator of compromise.
