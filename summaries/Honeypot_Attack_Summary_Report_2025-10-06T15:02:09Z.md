Honeypot Attack Summary Report

Report Generation Time: 2025-10-06T15:01:41Z
Report Timeframe: 2025-10-06T14:20:01Z - 2025-10-06T15:00:01Z
Files Used: agg_log_20251006T142001Z.json, agg_log_20251006T144001Z.json, agg_log_20251006T150001Z.json

Executive Summary
This report summarizes 18,150 observed attacks across multiple honeypots. The most targeted services were SSH (Cowrie), email services (Mailoney), and SMB (Suricata). The primary attack vector continues to be brute-force login attempts and exploitation of known vulnerabilities. A significant number of commands executed post-compromise were aimed at establishing persistent access and gathering system information.

Detailed Analysis:
Attacks by honeypot:
- Cowrie: 10867
- Suricata: 2603
- Honeytrap: 1952
- Ciscoasa: 1163
- Mailoney: 874
- Sentrypeer: 445
- H0neytr4p: 55
- Dionaea: 43
- ConPot: 42
- Adbhoney: 19
- Tanner: 27
- Honeyaml: 20
- Dicompot: 15
- Redishoneypot: 15
- Ipphoney: 7
- Heralding: 3

Top attacking IPs:
- 196.251.88.103: 1700
- 170.64.159.245: 1472
- 186.167.82.33: 1297
- 159.89.20.223: 1250
- 176.65.141.117: 820
- 80.94.95.238: 517
- 45.78.193.108: 690
- 188.235.159.76: 428
- 172.86.95.98: 433

Top targeted ports/protocols:
- 22: 1886
- TCP/445: 1294
- 25: 874
- 5060: 445
- 23: 74
- 443: 55
- 8333: 92

Most common CVEs:
- CVE-2021-44228: 27
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2021-3449: 3
- CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2005-4050: 2
- CVE-2016-20016: 1
- CVE-2006-2369: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 27
- lockr -ia .ssh: 27
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 27
- cat /proc/cpuinfo | grep name | wc -l: 27
- Enter new UNIX password: : 27
- Enter new UNIX password:: 27
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 27
- ls -lh $(which ls): 27
- which ls: 27
- crontab -l: 27
- w: 27
- uname -m: 27
- cat /proc/cpuinfo | grep model | grep name | wc -l: 27
- top: 27
- uname: 27
- uname -a: 27
- whoami: 29
- lscpu | grep Model: 27
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 27
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 26

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1290
- ET DROP Dshield Block Listed Source group 1: 352
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 245
- ET SCAN NMAP -sS window 1024: 117
- ET SCAN Potential SSH Scan: 97
- ET INFO Reserved Internal IP Traffic: 59
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 23
- ET INFO CURL User Agent: 21
- ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228): 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 96: 6
- ET CINS Active Threat Intelligence Poor Reputation IP group 13: 6
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 5

Users / login attempts:
- 345gs5662d34/345gs5662d34: 24
- admin/qa: 3
- admin/1234567yh: 3
- admin/Tz@123456: 3
- admin/123456qwerty@: 3
- admin/123Fashion: 3
- es/es_1234567: 3
- erin/erin123: 3
- monica/monica: 3

Files uploaded/downloaded:
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- 11: 2
- fonts.gstatic.com: 2
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 2
- ie8.css?ver=1.0: 2
- html5.js?ver=3.7.3: 2

HTTP User-Agents:
- None Observed

SSH clients:
- None Observed

SSH servers:
- None Observed

Top attacker AS organizations:
- None Observed

Key Observations and Anomalies
- A significant number of attacks are associated with the DoublePulsar backdoor, indicating attempts to compromise and control systems.
- The most frequent commands are reconnaissance and privilege escalation attempts, suggesting a pattern of automated scripts probing for system information and weaknesses.
- The Log4j vulnerability (CVE-2021-44228) continues to be a target for exploitation.
- A large number of login attempts used common or default credentials, emphasizing the ongoing threat of brute-force attacks.
