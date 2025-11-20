Honeypot Attack Summary Report

Report generated on 2025-10-13T19:01:37Z for the timeframe of 2025-10-13T18:20:02Z to 2025-10-13T19:00:02Z.
Files used to generate this report:
- agg_log_20251013T182002Z.json
- agg_log_20251013T184002Z.json
- agg_log_20251013T190002Z.json

Executive Summary
This report summarizes 18,989 malicious activities recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. A significant number of events were also logged by Sentrypeer and Honeytrap, suggesting widespread SIP and general TCP port scanning. The most frequent attacks originated from IP addresses 193.22.146.182, 20.164.21.26, and 45.171.150.123. The primary targets were ports 5060 (SIP) and 22 (SSH). Several CVEs were detected, with CVE-2022-27255 being the most common. Attackers commonly attempted to manipulate SSH authorized_keys files and download malicious scripts.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 10715
- Sentrypeer: 3024
- Honeytrap: 2091
- Suricata: 1468
- Dionaea: 1372
- H0neytr4p: 53
- Adbhoney: 50
- Tanner: 36
- Ciscoasa: 35
- Mailoney: 31
- ElasticPot: 26
- Redishoneypot: 23
- Honeyaml: 22
- ConPot: 20
- Dicompot: 14
- Miniprint: 6
- Heralding: 3

Top Attacking IPs:
- 193.22.146.182: 1372
- 20.164.21.26: 1247
- 45.171.150.123: 1241
- 185.243.5.146: 1148
- 45.236.188.4: 960
- 185.243.5.148: 705
- 94.103.12.49: 689
- 74.243.210.62: 283
- 121.122.65.105: 256
- 172.86.95.115: 351
- 172.86.95.98: 352
- 62.141.43.183: 323
- 122.168.194.41: 291
- 163.181.207.222: 318
- 152.32.145.25: 232
- 103.211.217.182: 226
- 216.108.227.59: 186
- 122.252.246.1: 193
- 5.75.202.157: 216
- 91.144.158.231: 217

Top Targeted Ports/Protocols:
- 5060: 3024
- 22: 1592
- 445: 1239
- UDP/5060: 121
- 1433: 71
- 23: 46
- 80: 46
- TCP/22: 58
- 443: 53
- TCP/80: 27
- 5555: 18
- TCP/443: 22
- 25: 37
- 9200: 23
- 6379: 15
- TCP/8080: 27
- TCP/5432: 28

Most Common CVEs:
- CVE-2022-27255
- CVE-2006-0189
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2023-26801
- CVE-2021-3449
- CVE-2020-2551
- CVE-2005-4050
- CVE-1999-0517
- CVE-2016-20016
- CVE-2021-35394
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 59
- lockr -ia .ssh: 59
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 59
- uname: 43
- uname -a: 43
- whoami: 43
- w: 43
- top: 43
- crontab -l: 43
- ls -lh $(which ls): 43
- which ls: 43
- cat /proc/cpuinfo | grep name | wc -l: 43
- cat /proc/cpuinfo | grep name | head -n 1 ...: 43
- cat /proc/cpuinfo | grep model | grep name | wc -l: 43
- free -m | grep Mem ...: 43
- df -h | head -n 2 ...: 43
- lscpu | grep Model: 43
- Enter new UNIX password: : 23
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 12

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1 / 2402000: 378
- ET SCAN NMAP -sS window 1024 / 2009582: 191
- ET INFO Reserved Internal IP Traffic / 2002752: 60
- ET SCAN Sipsak SIP scan / 2008598: 47
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255) / 2038669: 39
- ET SCAN Potential SSH Scan / 2001219: 34
- ET CINS Active Threat Intelligence Poor Reputation IP group 43 / 2403342: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 44 / 2403343: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 46 / 2403345: 18

Users / Login Attempts (username/password):
- 345gs5662d34/345gs5662d34: 57
- root/123@@@: 25
- root/3245gs5662d34: 21
- root/Qaz123qaz: 19
- root/Password@2025: 20
- ftpuser/ftppassword: 15
- sa/XMG3-Rel.1: 14
- sa/MonTelSys: 14
- metasyssysa/Sagent: 14

Files Uploaded/Downloaded:
- 11: 6
- fonts.gstatic.com: 6
- css?family=...: 6
- ie8.css?ver=1.0: 6
- html5.js?ver=3.7.3: 6
- json: 6
- wget.sh;: 4
- pen.sh;: 2
- discovery: 2
- arm.urbotnetisass;: 1
- c.sh;: 1

Key Observations and Anomalies
- A significant number of commands are focused on reconnaissance (uname, lscpu, free) and establishing persistence by modifying SSH keys.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` was consistently used across multiple attacks, suggesting a coordinated campaign.
- Attackers attempted to download and execute shell scripts (pen.sh, w.sh, wget.sh) and binaries (urbotnetisass), indicating attempts to install malware or join a botnet.
- The high number of SIP (port 5060) scans from Sentrypeer indicates ongoing reconnaissance for VoIP vulnerabilities.
- The variety of credentials attempted suggests that attackers are using common default password lists against multiple services (SSH, FTP, MSSQL).
