Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T04:01:25Z
**Timeframe:** 2025-10-02T03:20:01Z to 2025-10-02T04:00:02Z
**Files Used:**
- agg_log_20251002T032001Z.json
- agg_log_20251002T034001Z.json
- agg_log_20251002T040002Z.json

### Executive Summary

This report summarizes 29,995 total attacks recorded across three log files. The majority of attacks were captured by the Honeytrap honeypot. The most prominent attacker IP was 45.187.123.146. A significant number of attacks targeted TCP port 445 and port 25. Several CVEs were observed, with CVE-2016-5696 being the most frequent. Attackers attempted a variety of commands, including efforts to modify SSH configurations and download malicious payloads.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 20,749
- Cowrie: 3,964
- Suricata: 2,632
- Mailoney: 1,654
- Ciscoasa: 749
- Dionaea: 120
- Sentrypeer: 19
- Adbhoney: 19
- H0neytr4p: 24
- Tanner: 20
- Redishoneypot: 17
- ConPot: 9
- Dicompot: 9
- Miniprint: 6
- Honeyaml: 2
- Wordpot: 1
- Ipphoney: 1

**Top Attacking IPs:**
- 45.187.123.146: 13,070
- 45.234.176.18: 6,282
- 40.90.161.91: 1,240
- 116.229.104.221: 1,291
- 176.65.141.117: 1,640
- 92.46.235.230: 387
- 8.210.214.44: 374
- 39.112.232.226: 218
- 185.156.73.166: 255
- 92.63.197.55: 253
- 92.63.197.59: 238
- 20.102.116.25: 233
- 203.150.162.250: 189
- 103.250.10.66: 172
- 103.164.81.21: 168
- 103.211.217.182: 164
- 200.196.50.91: 159
- 189.165.66.123: 149
- 107.170.228.16: 83
- 196.251.84.140: 78

**Top Targeted Ports/Protocols:**
- TCP/445: 1,670
- 25: 1,654
- 22: 607
- TCP/1433: 44
- 1433: 41
- 5901: 46
- 8728: 23
- 19000: 19
- TCP/80: 18
- 443: 24
- 80: 15
- 6379: 11
- 445: 16
- 8333: 29
- 2323: 12
- 5060: 11

**Most Common CVEs:**
- CVE-2016-5696: 24
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2016-20016 CVE-2016-20016: 1

**Commands Attempted by Attackers:**
- uname -a: 16
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 15
- lockr -ia .ssh: 15
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 15
- cat /proc/cpuinfo | grep name | wc -l: 15
- free -m | grep Mem | awk ...: 15
- which ls: 15
- ls -lh $(which ls): 15
- crontab -l: 15
- w: 15
- uname -m: 15
- cat /proc/cpuinfo | grep model | grep name | wc -l: 15
- top: 15
- uname: 15
- whoami: 15
- lscpu | grep Model: 15
- df -h | head -n 2 | awk ...: 15
- Enter new UNIX password: : 12
- Enter new UNIX password:: 12
- cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 15
- cd /data/local/tmp/; rm *; busybox wget ...: 3
- uname -s -v -n -r -m: 1

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,665
- ET DROP Dshield Block Listed Source group 1: 254
- ET SCAN NMAP -sS window 1024: 121
- ET SCAN Suspicious inbound to MSSQL port 1433: 44
- ET INFO Reserved Internal IP Traffic: 47
- ET EXPLOIT RST Flood With Window: 24
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 13
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 15
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 4

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 15
- root/3245gs5662d34: 3
- seekcy/Joysuch@Locate2023: 3
- root/nPSpP4PBW0: 6
- admin/guestguest: 2
- admin/aplikant: 2
- admin/Admin2022*: 2
- admin/Aa123321!: 2
- root/Qwert!2345: 2
- test/zhbjETuyMffoL8F: 4
- seekcy/Joysuch@Locate2021: 2
- seekcy/3245gs5662d34: 2
- hadoop/hadoop: 2
- root/LeitboGi0ro: 2
- mysql/mysql123: 2
- superadmin/admin123: 3

**Files Uploaded/Downloaded:**
- arm.urbotnetisass;: 5
- arm.urbotnetisass: 5
- arm5.urbotnetisass;: 5
- arm5.urbotnetisass: 5
- arm6.urbotnetisass;: 5
- arm6.urbotnetisass: 5
- arm7.urbotnetisass;: 5
- arm7.urbotnetisass: 5
- x86_32.urbotnetisass;: 5
- x86_32.urbotnetisass: 5
- mips.urbotnetisass;: 5
- mips.urbotnetisass: 5
- mipsel.urbotnetisass;: 5
- mipsel.urbotnetisass: 5
- Mozi.a+jaws: 5
- fonts.gstatic.com: 5
- css?family=Libre+Franklin...: 5
- ie8.css?ver=1.0: 5
- html5.js?ver=3.7.3: 4
- 11: 5
- ?format=json: 2

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies

- The vast majority of attacks originate from a small number of IP addresses, with 45.187.123.146 and 45.234.176.18 being particularly aggressive.
- Attackers are using automated scripts to download and execute malicious payloads, as evidenced by the repeated `wget` and `curl` commands.
- The targeting of port 25 (SMTP) and 445 (SMB) suggests attempts to exploit email servers and Windows file sharing services.
- The presence of commands to manipulate SSH authorized_keys files indicates attempts to establish persistent access.
- A significant number of DoublePulsar backdoor installation attempts were detected, which is a known payload associated with the EternalBlue exploit.
