Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T02:01:31Z
**Timeframe:** 2025-10-08T01:20:01Z to 2025-10-08T02:00:01Z
**Files Used:** agg_log_20251008T012001Z.json, agg_log_20251008T014001Z.json, agg_log_20251008T020001Z.json

**Executive Summary**

This report summarizes 16,902 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant amount of activity was related to the DoublePulsar backdoor, as indicated by the most frequently triggered signature. Attackers predominantly targeted SMB (port 445) and SSH (port 22). Several CVEs were detected, with the most common being related to older vulnerabilities.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 5852
*   Suricata: 4315
*   Honeytrap: 2774
*   Dionaea: 2006
*   Ciscoasa: 1764
*   Mailoney: 45
*   Sentrypeer: 45
*   H0neytr4p: 27
*   ConPot: 23
*   Tanner: 21
*   Honeyaml: 13
*   Redishoneypot: 9
*   ElasticPot: 5
*   Dicompot: 3

***Top Attacking IPs***

*   103.6.4.2: 1941
*   131.226.105.106: 1411
*   58.186.29.77: 1470
*   103.140.127.215: 1333
*   171.231.192.112: 431
*   45.78.196.182: 273
*   27.79.44.79: 212
*   118.193.43.244: 203
*   187.45.95.66: 242
*   171.231.187.48: 176
*   51.222.155.186: 186
*   140.106.25.217: 164
*   143.198.70.37: 129
*   190.119.63.98: 194
*   27.112.78.73: 179
*   14.103.158.69: 118
*   45.78.196.218: 109
*   14.103.114.89: 105
*   154.92.109.196: 99
*   181.225.64.116: 144

***Top Targeted Ports/Protocols***

*   TCP/445: 2874
*   445: 1960
*   22: 1009
*   8333: 169
*   5903: 94
*   TCP/1433: 40
*   23: 30
*   25: 45
*   5060: 45
*   5984: 56
*   9042: 52
*   TCP/22: 26
*   5908: 49
*   5907: 49
*   5909: 48
*   8500: 36
*   4444: 24
*   80: 26
*   TCP/1521: 13
*   9002: 22

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012
*   CVE-2010-0569
*   CVE-2019-11500 CVE-2019-11500
*   CVE-1999-0183
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2021-35394 CVE-2021-35394

***Commands Attempted by Attackers***

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
*   lockr -ia .ssh: 18
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 18
*   cat /proc/cpuinfo | grep name | wc -l: 12
*   Enter new UNIX password: : 12
*   Enter new UNIX password::: 12
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 12
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 12
*   ls -lh $(which ls): 12
*   which ls: 12
*   crontab -l: 12
*   w: 12
*   uname -m: 12
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 12
*   top: 12
*   uname: 12
*   uname -a: 12
*   whoami: 12
*   lscpu | grep Model: 12
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 12

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2867
*   ET DROP Dshield Block Listed Source group 1: 463
*   ET SCAN NMAP -sS window 1024: 169
*   ET SCAN Suspicious inbound to MSSQL port 1433: 33
*   ET INFO Reserved Internal IP Traffic: 60
*   ET SCAN Potential SSH Scan: 23
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 15
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 12
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43: 28
*   ET CINS Active Threat Intelligence Poor Reputation IP group 49: 22
*   ET CINS Active Threat Intelligence Poor Reputation IP group 47: 31
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 10
*   ET INFO CURL User Agent: 11
*   ET SCAN Suspicious inbound to Oracle SQL port 1521: 11
*   ET CINS Active Threat Intelligence Poor Reputation IP group 68: 10
*   ET CINS Active Threat Intelligence Poor Reputation IP group 42: 12
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 10
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 9

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 19
*   sysadmin/sysadmin@1: 10
*   comcast/1234: 6
*   admin/p@ssw0rd: 6
*   nobody/nobody33: 6
*   pi/bananapi: 6
*   supervisor/marketing: 6
*   supervisor/supervisor33: 6
*   debian/debian9: 4
*   root/456321: 4
*   supervisor/Passw0rd: 4
*   supervisor/zyad1234: 4
*   user/12345678q: 4
*   vpn/vpn!: 4
*   unknown/unknown2: 6
*   root/odroid: 6
*   git/git: 7
*   vpn/123123: 3
*   mysql/mysql: 3
*   root/root123: 3

***Files Uploaded/Downloaded***

*   rondo.kqa.sh|sh&echo: 1

***HTTP User-Agents***

*   No user agents were reported in this timeframe

***SSH Clients***

*   No SSH clients were reported in this timeframe

***SSH Servers***

*   No SSH servers were reported in this timeframe

***Top Attacker AS Organizations***

*   No AS organizations were reported in this timeframe

**Key Observations and Anomalies**

*   The high number of triggers for the "DoublePulsar Backdoor" signature suggests a targeted campaign or widespread automated attacks exploiting this vulnerability.
*   The commands attempted by attackers indicate reconnaissance activity, with a focus on gathering system information such as CPU, memory, and disk space.
*   A recurring command sequence involves modifying the `.ssh/authorized_keys` file, indicating attempts to establish persistent access.
*   The variety of usernames and passwords attempted in login attempts suggests brute-force attacks using common or default credential lists.
*   The presence of the `rondo.kqa.sh` file download should be investigated further to understand its purpose and origin.

This report provides a snapshot of the threat landscape as observed by our honeypot network. Continuous monitoring is recommended to track these and other emerging threats.

