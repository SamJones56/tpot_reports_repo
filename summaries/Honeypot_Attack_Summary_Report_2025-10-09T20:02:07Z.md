Honeypot Attack Summary Report

Report Generation Time: 2025-10-09T20:01:40Z
Timeframe: 2025-10-09T19:20:01Z to 2025-10-09T20:00:01Z
Files Used: agg_log_20251009T192001Z.json, agg_log_20251009T194001Z.json, agg_log_20251009T200001Z.json

Executive Summary
This report summarizes 23,061 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of brute-force login attempts and reconnaissance commands were observed. The most frequent attacks originated from IP addresses 167.250.224.25, 86.54.42.238, and 138.197.43.50. Several CVEs were detected, with the most common being related to older vulnerabilities.

Detailed Analysis:
Attacks by honeypot:
- Cowrie: 13,331
- Honeytrap: 3,365
- Suricata: 2,355
- Mailoney: 1,688
- Ciscoasa: 1,646
- Sentrypeer: 364
- Tanner: 82
- Dionaea: 66
- H0neytr4p: 42
- Redishoneypot: 42
- ConPot: 26
- Heralding: 16
- Dicompot: 14
- Honeyaml: 13
- ElasticPot: 7
- Ipphoney: 2
- ecdsa-sha2-nistp521: 2

Top attacking IPs:
- 167.250.224.25: 1,711
- 86.54.42.238: 1,641
- 138.197.43.50: 1,258
- 137.184.179.27: 1,253
- 89.23.100.133: 1,257
- 134.199.205.75: 974
- 80.94.95.238: 714
- 27.254.152.90: 331
- 57.129.61.16: 288
- 152.32.239.90: 273

Top targeted ports/protocols:
- 22: 2,066
- 25: 1,690
- 5060: 364
- 5903: 205
- 23: 86
- 80: 84
- 5908: 83
- 5909: 82
- 5901: 72
- 6379: 36

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2024-1709 CVE-2024-1709: 6
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-1999-0517: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 50
- lockr -ia .ssh: 50
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 50
- cat /proc/cpuinfo | grep name | wc -l: 50
- Enter new UNIX password: : 50
- w: 50
- uname -m: 49
- whoami: 49
- uname -a: 49
- top: 49
- cat /proc/cpuinfo | grep model | grep name | wc -l: 49
- uname: 49
- lscpu | grep Model: 49
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 49
- ls -lh $(which ls): 49

Signatures triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 810
- 2023753: 810
- ET DROP Dshield Block Listed Source group 1: 427
- 2402000: 427
- ET SCAN NMAP -sS window 1024: 167
- 2009582: 167
- ET HUNTING RDP Authentication Bypass Attempt: 164
- 2034857: 164
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 36
- 2010517: 36
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 28
- 2403342: 28
- ET SCAN Potential SSH Scan: 27
- 2001219: 27

Users / login attempts:
- 345gs5662d34/345gs5662d34: 46
- A large number of attempts were made with the username 'root' and various common passwords.
- Other attempted usernames include: support, ubuntu, supervisor, admin, jenkins, sol, guest, test1, administrator.

Files uploaded/downloaded:
- sh: 98
- 11: 32
- fonts.gstatic.com: 32
- css?family=Libre+Franklin...: 32
- ie8.css?ver=1.0: 32
- html5.js?ver=3.7.3: 32
- svg: 9
- xlink: 9
- mips: 2

HTTP User-Agents:
- No HTTP User-Agents were recorded in the logs.

SSH clients and servers:
- No specific SSH clients or servers were identified in the logs.

Top attacker AS organizations:
- No attacker AS organizations were identified in the logs.

Key Observations and Anomalies
- The overwhelming majority of attacks are automated, focusing on well-known ports for SSH (22) and SMTP (25).
- Attackers consistently attempt to add their SSH public key to the authorized_keys file, indicating a goal of establishing persistent access.
- The commands executed suggest attackers are performing reconnaissance to understand the system architecture (CPU, memory, etc.), likely to tailor further attacks or malware.
- The presence of CVEs, although some are dated, indicates that attackers are still attempting to exploit known vulnerabilities.
- The lack of data for HTTP User-Agents, SSH clients/servers, and AS organizations may suggest that the honeypots responsible for capturing this information did not observe significant activity during this period, or that the logging configuration for these fields is not enabled.
