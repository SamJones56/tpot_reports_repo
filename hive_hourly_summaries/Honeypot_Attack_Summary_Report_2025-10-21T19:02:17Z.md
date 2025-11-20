Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T19:01:52Z
**Timeframe:** 2025-10-21T18:20:01Z to 2025-10-21T19:00:01Z
**Files Used:**
- agg_log_20251021T182001Z.json
- agg_log_20251021T184001Z.json
- agg_log_20251021T190001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 19,458 attacks were recorded, with a significant portion targeting the Cowrie honeypot. Attackers predominantly used SSH (port 22) and SMB (port 445) protocols. A variety of CVEs were exploited, with CVE-2021-3449 being the most frequent. The most common commands attempted by attackers involved reconnaissance and attempts to modify SSH configurations.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 10810
- Honeytrap: 4523
- Suricata: 2068
- Ciscoasa: 899
- Dionaea: 626
- Sentrypeer: 147
- Tanner: 107
- Mailoney: 85
- H0neytr4p: 37
- Redishoneypot: 35
- ElasticPot: 30
- ConPot: 29
- Adbhoney: 21
- Miniprint: 17
- Dicompot: 16
- Honeyaml: 3
- Heralding: 3
- Ipphoney: 1
- Medpot: 1

***Top Attacking IPs***
- 51.89.1.87: 1255
- 45.78.193.116: 1239
- 72.146.232.13: 1212
- 134.199.195.74: 998
- 103.75.100.222: 622
- 103.79.155.140: 516
- 187.150.53.146: 515
- 88.210.63.16: 433
- 38.25.39.212: 425
- 118.193.43.167: 347
- 101.36.119.218: 356
- 103.149.28.125: 362
- 118.99.80.55: 283
- 95.79.112.59: 274
- 107.170.36.5: 250
- 81.177.101.45: 209
- 45.135.232.248: 213
- 36.50.54.8: 198
- 183.110.116.126: 192
- 171.104.143.176: 168

***Top Targeted Ports/Protocols***
- 22: 1951
- 445: 559
- 5903: 228
- 5060: 147
- 80: 109
- TCP/80: 98
- 8333: 112
- 5901: 117
- 5904: 79
- 5905: 78
- 25: 85
- TCP/22: 54
- 6379: 35
- 9200: 25
- UDP/5060: 29
- 443: 28
- 9443: 26

***Most Common CVEs***
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2021-35394 CVE-2021-35394: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 34
- lockr -ia .ssh: 34
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 34
- cat /proc/cpuinfo | grep name | wc -l: 33
- Enter new UNIX password: : 27
- Enter new UNIX password::: 27
- ls -lh $(which ls): 32
- which ls: 32
- crontab -l: 32
- w: 32
- uname -m: 32
- cat /proc/cpuinfo | grep model | grep name | wc -l: 32
- top: 32
- uname: 32
- uname -a: 32
- whoami: 32
- lscpu | grep Model: 32
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 32
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 31
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 31

***Signatures Triggered***
- ET DROP Dshield Block Listed Source group 1: 462
- 2402000: 462
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 443
- 2023753: 443
- ET SCAN NMAP -sS window 1024: 179
- 2009582: 179
- ET HUNTING RDP Authentication Bypass Attempt: 186
- 2034857: 186
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET SCAN Potential SSH Scan: 38
- 2001219: 38
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 24
- 2403343: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 21
- 2403342: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 17
- 2403349: 17

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 32
- pi/raspberry: 6
- root/!Q2w3e4r: 5
- odin/odin: 5
- root/asdfghjkl: 4
- root/asdfpoiu: 4
- root/Aslema2010: 4
- root/aspace12: 4
- test1/test1!: 3
- root/Test@2023: 3
- user7/user7123: 3
- user01/Password01: 3
- angel/angel: 3
- hive/hive: 3
- wang/wang123: 3
- user/111111: 3
- oracle/oracle: 3
- root/!qaz@WSX: 3
- user/user: 3
- user1/qwer1234: 3
- user/123: 3
- postgres/postgres: 3
- admin1/123456789: 3
- root/123abc321: 3

***Files Uploaded/Downloaded***
- sh: 98
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- loader.sh|sh;#: 1
- ): 1
- ohsitsvegawellrip.sh: 1

***HTTP User-Agents***
- No user agents reported in this period.

***SSH Clients***
- No SSH clients reported in this period.

***SSH Servers***
- No SSH servers reported in this period.

***Top Attacker AS Organizations***
- No AS organizations reported in this period.

**Key Observations and Anomalies**
- The high number of attacks on the Cowrie honeypot suggests a focus on SSH-based attacks.
- The most common commands are related to system information gathering, which is typical for the initial stages of a compromise.
- The presence of commands aimed at modifying SSH authorized_keys files indicates attempts to establish persistent access.
- A significant number of attacks originate from IPs listed in Dshield's block list, suggesting that many attacks are from known malicious sources.
- No HTTP User-Agents, SSH clients/servers, or AS organizations were reported in the logs, which might indicate a limitation in the logging configuration or that the attacks did not involve these elements.
