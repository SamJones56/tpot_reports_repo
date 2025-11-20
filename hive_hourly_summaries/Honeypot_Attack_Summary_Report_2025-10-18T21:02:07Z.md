Honeypot Attack Summary Report

Report Generation Time: 2025-10-18T21:01:47Z
Timeframe: 2025-10-18T20:20:01Z to 2025-10-18T21:00:02Z

Files Used to Generate Report:
- agg_log_20251018T202001Z.json
- agg_log_20251018T204001Z.json
- agg_log_20251018T210002Z.json

Executive Summary:
This report summarizes honeypot activity from three log files, totaling 14,554 events. The majority of attacks were captured by the Cowrie honeypot, with significant activity also detected by Suricata and Honeytrap. Attackers predominantly targeted SSH (port 22) and SMB (port 445). A large number of events were associated with the IP address 176.211.19.193, primarily related to SMB exploitation attempts. Multiple CVEs were detected, with CVE-2005-4050 being the most frequent.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 8847
- Suricata: 2382
- Honeytrap: 1426
- Ciscoasa: 1198
- Sentrypeer: 576
- Dionaea: 35
- Redishoneypot: 25
- Tanner: 17
- Mailoney: 15
- H0neytr4p: 9
- Heralding: 6
- ElasticPot: 5
- ssh-rsa: 4
- Adbhoney: 3
- Honeyaml: 3
- Ipphoney: 3

Top Attacking IPs:
- 176.211.19.193: 1441
- 194.50.16.73: 990
- 134.199.195.106: 987
- 176.9.111.156: 692
- 72.146.232.13: 651
- 49.247.175.53: 262
- 206.217.131.233: 366
- 36.50.177.248: 366
- 216.155.93.75: 298
- 20.203.59.187: 349
- 152.32.201.226: 252
- 62.171.157.55: 292
- 152.32.203.205: 262
- 14.225.167.148: 174
- 218.37.207.187: 179
- 43.138.14.165: 258
- 166.140.91.205: 169
- 198.23.190.58: 227
- 23.94.26.58: 217
- 107.170.36.5: 113

Top Targeted Ports/Protocols:
- 22: 1672
- TCP/445: 1436
- 5060: 576
- 8333: 144
- 5904: 78
- 5905: 78
- UDP/5060: 256
- TCP/22: 64
- 5903: 56
- 5901: 50
- 6379: 25
- 31337: 30
- 5902: 38
- 80: 18
- 443: 9

Most Common CVEs:
- CVE-2005-4050: 227
- CVE-2022-27255 CVE-2022-27255: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-3721 CVE-2024-3721: 2
- CVE-2021-35395 CVE-2021-35395: 2
- CVE-2016-20017 CVE-2016-20017: 2
- CVE-2001-0414: 1

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 34
- lockr -ia .ssh: 34
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 34
- cat /proc/cpuinfo | grep name | wc -l: 34
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 34
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 34
- ls -lh $(which ls): 34
- which ls: 34
- crontab -l: 33
- w: 33
- uname -m: 33
- cat /proc/cpuinfo | grep model | grep name | wc -l: 33
- top: 33
- uname: 33
- uname -a: 33
- whoami: 33
- lscpu | grep Model: 33
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 33
- Enter new UNIX password: : 22
- Enter new UNIX password:: 19

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1434
- 2024766: 1434
- ET VOIP MultiTech SIP UDP Overflow: 221
- 2003237: 221
- ET DROP Dshield Block Listed Source group 1: 167
- 2402000: 167
- ET SCAN NMAP -sS window 1024: 83
- 2009582: 83
- ET SCAN Potential SSH Scan: 57
- 2001219: 57
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 46
- 2023753: 46
- ET INFO Reserved Internal IP Traffic: 40
- 2002752: 40
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 18
- 2403350: 18
- ET HUNTING RDP Authentication Bypass Attempt: 17
- 2034857: 17
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 15
- 2010939: 15

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 30
- ftpuser/ftppassword: 15
- root/123@Robert: 13
- root/3245gs5662d34: 11
- root/P@ssw0rd#2025: 3
- martin/martin123: 3
- backupuser/backupuser123: 3
- wxg/123: 3
- autobuild/autobuild: 3
- samson/samson: 3
- game/game: 3
- bhanu/3245gs5662d34: 3
- tech/3245gs5662d34: 3
- admin/admin2024: 3
- root/37763776: 3
- root/Qaz123qaz: 4
- root/admin123456!: 3
- root/1111: 3
- server/123: 3

Files Uploaded/Downloaded:
- sora.sh;: 2

HTTP User-Agents:
- No user agents were logged in this timeframe.

SSH Clients:
- No SSH clients were logged in this timeframe.

SSH Servers:
- No SSH servers were logged in this timeframe.

Top Attacker AS Organizations:
- No attacker AS organizations were logged in this timeframe.

Key Observations and Anomalies:
- A significant amount of traffic from 176.211.19.193 was observed, targeting port 445 and triggering the 'DoublePulsar Backdoor' signature. This indicates a likely automated worm or exploit scanner.
- The most common commands attempted are reconnaissance commands to gather system information, followed by attempts to add an SSH key for persistence.
- A large number of login attempts used common or default credentials, highlighting the continued use of brute-force attacks.
- The 'sora.sh' file was downloaded, which is a known Mirai variant.
