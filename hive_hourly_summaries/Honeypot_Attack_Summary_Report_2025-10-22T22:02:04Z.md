Honeypot Attack Summary Report

Report Generation Time: 2025-10-22T22:01:42Z
Timeframe: 2025-10-22T21:20:01Z to 2025-10-22T22:00:01Z

Files Used:
- agg_log_20251022T212001Z.json
- agg_log_20251022T214001Z.json
- agg_log_20251022T220001Z.json

Executive Summary:
This report summarizes 19,140 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Dionaea honeypots. A significant portion of the attacks originated from the IP address 125.235.231.74. The most targeted port was 445/tcp (SMB). Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 6301
- Honeytrap: 4121
- Dionaea: 3986
- Ciscoasa: 1716
- Suricata: 1695
- Sentrypeer: 1039
- Mailoney: 99
- Tanner: 76
- ElasticPot: 22
- H0neytr4p: 21
- Redishoneypot: 20
- ConPot: 11
- Ipphoney: 5
- Adbhoney: 3
- Medpot: 4
- Honeyaml: 2
- Wordpot: 1

Top Attacking IPs:
- 125.235.231.74: 2397
- 177.46.198.90: 1438
- 118.145.207.125: 421
- 174.138.3.41: 315
- 103.176.78.28: 342
- 49.247.37.22: 346
- 14.116.200.5: 327
- 161.248.189.80: 341
- 107.170.36.5: 254
- 203.209.181.4: 163
- 185.243.5.146: 205
- 185.213.165.36: 219
- 46.253.45.10: 219
- 50.84.211.204: 214
- 27.71.230.3: 203

Top Targeted Ports/Protocols:
- 445: 3842
- 5060: 1039
- 22: 844
- 8333: 241
- 5903: 131
- 5901: 122
- 25: 99
- 80: 73
- 5905: 79
- 5904: 78
- TCP/80: 31
- 23: 42
- 1433: 89
- 5038: 132
- 9093: 115
- 6379: 17
- 9200: 18

Most Common CVEs:
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2002-0013 CVE-2002-0012
- CVE-2009-2765
- CVE-2002-1149
- CVE-2019-11500 CVE-2019-11500

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 34
- lockr -ia .ssh: 34
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 34
- cat /proc/cpuinfo | grep name | wc -l: 35
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 35
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 35
- ls -lh $(which ls): 35
- which ls: 35
- crontab -l: 35
- w: 35
- uname -m: 35
- cat /proc/cpuinfo | grep model | grep name | wc -l: 35
- top: 35
- uname: 35
- uname -a: 35
- whoami: 35
- lscpu | grep Model: 35
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 35
- Enter new UNIX password: : 28
- Enter new UNIX password:": 28
- rm -rf /data/local/tmp; ...: 1

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1: 374
- 2402000: 374
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 274
- 2023753: 274
- ET SCAN NMAP -sS window 1024: 173
- 2009582: 173
- ET HUNTING RDP Authentication Bypass Attempt: 100
- 2034857: 100
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 33
- root/3245gs5662d34: 7
- root/C3hr: 4
- root/o&m15213: 4
- shlee/shlee: 4
- root/C1tyR3d54515: 4
- komal/komal: 3
- root/10086: 3
- root/Asdfg123456: 3
- schumann/schumann123: 3
- gg/gg: 3
- root/C3ct.2015: 3

Files Uploaded/Downloaded:
- sh: 98
- 11: 16
- fonts.gstatic.com: 16
- css?family=Libre+Franklin...: 16
- ie8.css?ver=1.0: 16
- html5.js?ver=3.7.3: 16
- wget.sh;: 4
- SOAP-ENV:Envelope>: 3
- Mozi.m: 1
- w.sh;: 1
- c.sh;: 1

HTTP User-Agents:
- No user agents were logged in this timeframe.

SSH Clients:
- No SSH clients were logged in this timeframe.

SSH Servers:
- No SSH servers were logged in this timeframe.

Top Attacker AS Organizations:
- No attacker AS organizations were logged in this timeframe.

Key Observations and Anomalies:
- The high number of attacks on port 445 (SMB) suggests a continued focus on exploiting Windows vulnerabilities.
- The repeated execution of reconnaissance commands (e.g., `cat /proc/cpuinfo`, `uname -a`) indicates automated scripts gathering system information before deploying payloads.
- The command to add an SSH key to `authorized_keys` is a common technique for establishing persistent access.
- The presence of the Mozi.m file download is indicative of IoT botnet activity.
- The multiple CVEs being probed shows a multi-pronged approach by attackers to find any available vulnerability.
