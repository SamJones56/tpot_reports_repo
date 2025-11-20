Honeypot Attack Summary Report

Report Generation Time: 2025-10-06T17:01:32Z
Timeframe: 2025-10-06T16:20:01Z to 2025-10-06T17:00:02Z
Files Used:
- agg_log_20251006T162001Z.json
- agg_log_20251006T164002Z.json
- agg_log_20251006T170002Z.json

Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three log files. A total of 13,589 attacks were recorded. The most targeted honeypot was Cowrie, indicating a high volume of SSH and Telnet brute-force attempts. A significant number of attacks originated from a small group of IP addresses, with repetitive commands being issued to compromise the systems and establish further access by adding SSH keys. The most common vulnerability scanner activity was related to Log4j (CVE-2021-44228).

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 6477
- Honeytrap: 2470
- Suricata: 1798
- Mailoney: 856
- Ciscoasa: 1203
- Sentrypeer: 400
- Dionaea: 111
- Adbhoney: 70
- Tanner: 67
- H0neytr4p: 61
- Redishoneypot: 21
- Honeyaml: 15
- ConPot: 17
- Dicompot: 6
- Miniprint: 9
- ElasticPot: 3
- Ipphoney: 5

Top Attacking IPs:
- 8.222.186.193: 1013
- 176.65.141.117: 820
- 116.198.207.211: 728
- 80.94.95.238: 1011
- 35.212.232.246: 537
- 172.86.95.98: 378
- 88.210.63.16: 293
- 212.33.235.243: 264
- 103.159.132.91: 312
- 165.154.168.234: 177
- 158.101.142.33: 183
- 107.170.36.5: 65
- 68.183.207.213: 62
- 128.199.59.41: 55
- 129.13.189.204: 47

Top Targeted Ports/Protocols:
- 22: 1146
- 25: 856
- 5060: 400
- 8333: 153
- 445: 75
- 5903: 94
- TCP/22: 57
- 80: 73
- 443: 54
- 23: 40
- 2375: 47
- 6379: 21
- 9001: 27

Most Common CVEs:
- CVE-2021-44228: 34
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2021-3449: 3
- CVE-2019-11500: 2
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 1

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 27
- lockr -ia .ssh: 27
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 27
- cat /proc/cpuinfo | grep name | wc -l: 26
- Enter new UNIX password: : 25
- Enter new UNIX password::: 25
- cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 25
- free -m | grep Mem | awk ...: 25
- ls -lh $(which ls): 25
- which ls: 25
- crontab -l: 25
- w: 25
- uname -m: 25
- cat /proc/cpuinfo | grep model | grep name | wc -l: 25
- top: 24
- uname: 24
- uname -a: 24
- whoami: 24
- lscpu | grep Model: 24
- df -h | head -n 2 | awk ...: 24

Signatures Triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 622
- 2023753: 622
- ET DROP Dshield Block Listed Source group 1: 363
- 2402000: 363
- ET SCAN NMAP -sS window 1024: 133
- 2009582: 133
- ET HUNTING RDP Authentication Bypass Attempt: 84
- 2034857: 84
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET SCAN Potential SSH Scan: 36
- 2001219: 36

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 23
- root/wsx44: 2
- root/adminHW: 2
- sol/Sol: 2
- solana/Solana: 2
- erpnext/1234: 2
- ubuntu/3245gs5662d34: 5
- admin/12051975: 3
- admin/12041992: 3
- admin/120385: 3
- admin/12031977: 3
- admin/12031974: 3
- jumpserver/jumpserver: 3

Files Uploaded/Downloaded:
- wget.sh;: 28
- w.sh;: 7
- c.sh;: 7
- soap-envelope: 1
- addressing: 1
- discovery: 1
- devprof: 1
- soap:Envelope>: 1

HTTP User-Agents:
- No HTTP User-Agents were recorded in this period.

SSH Clients and Servers:
- No specific SSH clients or servers were identified in the logs.

Top Attacker AS Organizations:
- No attacker AS organizations were recorded in this period.

Key Observations and Anomalies
- The Cowrie honeypot is attracting the vast majority of attacks, indicating a strong focus on SSH/Telnet vectors from automated scripts.
- A recurring pattern of commands was observed across multiple attacking IPs, suggesting a coordinated campaign or the use of the same attack toolkit. The sequence involves modifying SSH authorized_keys to maintain persistence.
- A significant number of Log4j scanning attempts (CVE-2021-44228) are still prevalent, showing that attackers continue to scan for this vulnerability.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...` is a clear indicator of interest in long-term access over simple reconnaissance.
