Honeypot Attack Summary Report

Report Generation Time: 2025-10-15T19:01:34Z
Timeframe: 2025-10-15T18:20:01Z to 2025-10-15T19:00:02Z
Files Used:
- agg_log_20251015T182001Z.json
- agg_log_20251015T184001Z.json
- agg_log_20251015T190002Z.json

Executive Summary:
This report summarizes 24,500 observed attacks across various honeypots. The majority of attacks were captured by the Cowrie honeypot, with significant activity also detected on Honeytrap, Sentrypeer, and Suricata. Attackers predominantly targeted port 5060, with a high volume of SSH and SMB related traffic. A recurring pattern of SSH key manipulation and system reconnaissance commands was observed.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 10047
- Honeytrap: 3999
- Sentrypeer: 3546
- Suricata: 3069
- Ciscoasa: 1539
- Mailoney: 1687
- Dionaea: 366
- Tanner: 70
- Redishoneypot: 46
- H0neytr4p: 44
- ElasticPot: 30
- ConPot: 25
- Honeyaml: 10
- Adbhoney: 7
- Dicompot: 7
- Ipphoney: 3
- Heralding: 3
- ssh-ed25519: 2

Top Attacking IPs:
- 120.253.79.34: 1549
- 206.191.154.180: 1279
- 203.171.29.193: 1253
- 95.170.68.246: 1076
- 185.243.5.121: 1163
- 23.94.26.58: 856
- 129.212.188.101: 818
- 212.87.220.20: 848
- 86.54.42.238: 822
- 176.65.141.119: 821
- 143.198.201.181: 555
- 172.86.95.98: 494
- 172.86.95.115: 485
- 103.124.100.181: 467
- 103.183.74.130: 375
- 4.247.148.92: 385
- 51.159.59.17: 405
- 194.233.82.110: 319
- 103.67.78.102: 311
- 36.105.205.231: 304
- 62.141.43.183: 317

Top Targeted Ports/Protocols:
- 5060: 3546
- 25: 1687
- TCP/445: 1669
- 22: 1503
- 445: 315
- 5903: 222
- 5901: 113
- 23: 83
- 8333: 99
- UDP/5060: 84
- 5909: 82
- 5908: 83
- TCP/22: 76
- 6379: 42
- 80: 54
- 443: 43

Most Common CVEs:
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2006-2369: 1
- CVE-1999-0517: 1
- CVE-1999-0183: 1
- CVE-1999-0265: 1

Commands Attempted by Attackers:
- uname -a: 37
- whoami: 37
- lscpu | grep Model: 37
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 37
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 39
- lockr -ia .ssh: 39
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 39
- cat /proc/cpuinfo | grep name | wc -l: 39
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 39
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 39
- ls -lh $(which ls): 39
- which ls: 39
- crontab -l: 39
- w: 39
- uname -m: 39
- cat /proc/cpuinfo | grep model | grep name | wc -l: 39
- top: 39
- uname: 39
- Enter new UNIX password: : 28
- Enter new UNIX password:: 26
- uname -s -v -n -r -m: 9

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1666
- 2024766: 1666
- ET DROP Dshield Block Listed Source group 1: 381
- 2402000: 381
- ET SCAN NMAP -sS window 1024: 155
- 2009582: 155
- ET INFO Reserved Internal IP Traffic: 62
- 2002752: 62
- ET SCAN Potential SSH Scan: 67
- 2001219: 67
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 33
- 2023753: 33
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 34
- 2012296: 34
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 31
- 2012297: 31
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 20
- 2010517: 20

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 36
- root/3245gs5662d34: 10
- root/Qaz123qaz: 10
- config/77: 6
- root/123@@@: 9
- centos/centos2016: 6
- root/root2009: 6
- config/1qaz2wsx: 6
- guest/0000000: 6
- support/55: 7
- jenkins/jenkins: 5
- build/build: 4
- root/server@123: 4
- user/2222222: 4
- gc/3245gs5662d34: 4
- nvidia/nvidia: 7
- ali/1111: 6
- config/Passw@rd: 4
- student5/123: 4
- h/3245gs5662d34: 4
- supervisor/supervisor2006: 4
- selenium/selenium: 4
- root/!@#QWE123: 4

Files Uploaded/Downloaded:
- sh: 98
- 11: 21
- fonts.gstatic.com: 21
- css?family=Libre+Franklin...: 21
- ie8.css?ver=1.0: 21
- html5.js?ver=3.7.3: 21

HTTP User-Agents:
- No HTTP User-Agent data observed in this period.

SSH Clients:
- No SSH client data observed in this period.

SSH Servers:
- No SSH server data observed in this period.

Top Attacker AS Organizations:
- No attacker AS organization data observed in this period.

Key Observations and Anomalies:
- A high number of commands related to enumerating system information (uname, lscpu, free) were observed, indicating initial reconnaissance stages of an attack.
- The command to remove and replace SSH authorized_keys was consistently seen across multiple attacks, suggesting a common tactic to maintain persistence.
- The `boatnet.arm` download and execution attempt points to IoT botnet activity.
- The DoublePulsar backdoor signature was triggered a significant number of times, indicating attempts to exploit SMB vulnerabilities.
