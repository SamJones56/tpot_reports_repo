Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T02:02:00Z
**Timeframe:** 2025-10-24T01:20:01Z to 2025-10-24T02:00:01Z
**Files Used:**
- agg_log_20251024T012001Z.json
- agg_log_20251024T014001Z.json
- agg_log_20251024T020001Z.json

**Executive Summary**

This report summarizes 10,535 attacks recorded across three honeypot log files. The majority of attacks were captured by the Suricata, Cowrie, and Sentrypeer honeypots. A significant portion of the attacks originated from the IP address 31.40.204.154. The most targeted ports were 5060 (SIP) and 22 (SSH). A variety of CVEs were detected, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistence.

**Detailed Analysis**

***Attacks by Honeypot***
- Suricata: 2826
- Cowrie: 2199
- Sentrypeer: 1892
- Ciscoasa: 1746
- Honeytrap: 1656
- Tanner: 63
- Dionaea: 37
- H0neytr4p: 31
- ssh-rsa: 30
- Mailoney: 23
- ConPot: 12
- Miniprint: 10
- Dicompot: 6
- Honeyaml: 2
- Ipphoney: 1
- Heralding: 1

***Top Attacking IPs***
- 31.40.204.154: 3545
- 80.94.95.238: 455
- 101.36.119.218: 288
- 146.190.93.207: 288
- 103.191.178.123: 286
- 83.97.24.41: 278
- 182.93.50.90: 223
- 107.170.36.5: 157
- 102.88.137.213: 129
- 14.51.236.39: 129
- 68.183.149.135: 112
- 64.23.191.60: 91
- 141.52.36.57: 77
- 36.140.33.10: 73
- 167.250.224.25: 70
- 185.243.5.144: 63
- 172.31.36.128: 46
- 124.198.131.83: 37
- 121.160.178.20: 36
- 42.242.156.106: 33

***Top Targeted Ports/Protocols***
- 5060: 1892
- UDP/5060: 1776
- 22: 277
- 8333: 124
- 5905: 79
- 5904: 79
- TCP/80: 68
- 80: 60
- 8000: 46
- 5901: 45
- 5902: 38
- 5903: 38
- 443: 31
- 25: 22
- 8087: 16
- TCP/22: 13
- 23: 11
- 3306: 10
- TCP/1521: 9
- TCP/23: 8

***Most Common CVEs***
- CVE-2002-0953
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2009-2765
- CVE-2014-6271
- CVE-2015-2051
- CVE-2016-20017
- CVE-2019-10891
- CVE-2019-16920
- CVE-2021-35395
- CVE-2021-41773
- CVE-2021-42013
- CVE-2022-37056
- CVE-2023-31983
- CVE-2023-47565
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-12856
- CVE-2024-12885
- CVE-2024-33112
- CVE-2024-3721
- CVE-2024-4577
- CVE-2025-11488

***Commands Attempted by Attackers***
- uname -a: 14
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 13
- lockr -ia .ssh: 13
- cd ~ && rm -rf .ssh && mkdir .ssh...: 13
- cat /proc/cpuinfo | grep name | wc -l: 13
- cat /proc/cpuinfo | grep name | head -n 1 | awk...: 13
- free -m | grep Mem | awk...: 13
- ls -lh $(which ls): 13
- which ls: 13
- crontab -l: 13
- w: 13
- uname -m: 13
- cat /proc/cpuinfo | grep model | grep name | wc -l: 13
- top: 13
- uname: 13
- whoami: 13
- lscpu | grep Model: 13
- df -h | head -n 2 | awk...: 13
- Enter new UNIX password: : 10
- Enter new UNIX password::: 10

***Signatures Triggered***
- ET SCAN Sipsak SIP scan: 1772
- 2008598: 1772
- ET DROP Dshield Block Listed Source group 1: 359
- 2402000: 359
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 162
- 2023753: 162
- ET SCAN NMAP -sS window 1024: 95
- 2009582: 95
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 42
- 2010517: 42
- ET INFO Reserved Internal IP Traffic: 40
- 2002752: 40
- ET INFO CURL User Agent: 14
- 2002824: 14

***Users / Login Attempts***
- root/: 30
- 345gs5662d34/345gs5662d34: 13
- root/Admin1234!@#$: 4
- marcelino/marcelino: 4
- marcelino/3245gs5662d34: 4
- srikanth/srikanth: 4
- root/paradox: 4
- kopp/kopp: 4
- api/api: 3
- root/ASDqwe!@#: 2
- root/D31m4nD: 2
- root/rss123: 2
- gc/12345: 2
- root/3245gs5662d34: 2
- root/1qaz@WSX2026: 2
- ftp_test/ftp_test: 2
- root/D3b14nCentreM001river123Ben10Mil111111Gempsa2018: 2
- gitserver/gitserver: 2
- root/2222222222: 2
- natali/natali: 2

***Files Uploaded/Downloaded***
- sh: 98
- 3.253.97.195: 5
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 3
- rondo.dgx.sh||busybox: 3
- rondo.dgx.sh||curl: 3
- rondo.dgx.sh)|sh&: 3
- system.html: 2
- rondo.tkg.sh|sh&echo: 2
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2
- cfg_system_time.htm: 2

***HTTP User-Agents***
- No HTTP user-agents were logged.

***SSH Clients***
- No SSH clients were logged.

***SSH Servers***
- No SSH servers were logged.

***Top Attacker AS Organizations***
- No attacker AS organizations were logged.

**Key Observations and Anomalies**

- The high volume of traffic to port 5060 suggests a focus on exploiting VoIP systems.
- The commands executed by attackers indicate a pattern of system reconnaissance, followed by attempts to establish persistent access by modifying SSH authorized_keys.
- The variety of CVEs exploited highlights the diverse range of vulnerabilities being actively targeted.
- The IP address 31.40.204.154 was responsible for a disproportionately large number of attacks, indicating a targeted or automated campaign from this source.
- A significant number of files named 'sh' were downloaded, which is a common tactic for downloading and executing malicious scripts.
