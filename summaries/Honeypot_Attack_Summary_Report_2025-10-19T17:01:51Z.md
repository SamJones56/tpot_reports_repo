Honeypot Attack Summary Report

Report Generated: 2025-10-19T17:01:30Z
Timeframe: 2025-10-19T16:20:01Z to 2025-10-19T17:00:01Z
Log Files: agg_log_20251019T162001Z.json, agg_log_20251019T164002Z.json, agg_log_20251019T170001Z.json

Executive Summary:
This report summarizes 27,484 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Honeytrap, and Suricata honeypots. The most targeted services were PostgreSQL (port 5432), SMB (port 445), and Asterisk (port 5038). A significant number of attacks originated from IP address 198.44.138.123. The most frequently observed CVE was CVE-2005-4050, related to a SIP UDP overflow vulnerability.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 7554
- Honeytrap: 6860
- Suricata: 3689
- Heralding: 2882
- Dionaea: 2435
- Sentrypeer: 2290
- Mailoney: 997
- Ciscoasa: 640
- Redishoneypot: 50
- Tanner: 27
- Adbhoney: 27
- Miniprint: 15
- H0neytr4p: 11
- ConPot: 4
- Dicompot: 2
- ElasticPot: 1

Top Attacking IPs:
- 198.44.138.123
- 198.23.238.154
- 91.235.160.35
- 77.83.240.70
- 196.6.105.31
- 176.65.141.119
- 72.146.232.13
- 198.23.190.58
- 23.94.26.58
- 89.221.212.117
- 161.132.37.66
- 198.12.68.114

Top Targeted Ports/Protocols:
- postgresql/5432
- 445
- 5038
- 5060
- 22
- UDP/5060
- TCP/445
- 25
- 5903
- 8333

Most Common CVEs:
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2001-0414
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2002-1149

Commands Attempted by Attackers:
- uname -s -v -n -r -m
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET VOIP MultiTech SIP UDP Overflow
- 2003237
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753

Users / Login Attempts:
- postgres/123
- user/123
- root/123
- 345gs5662d34/345gs5662d34
- postgres/1234567
- public/1234567
- test/1234567
- guest/1234567
- root/1234567
- sa/1234567
- unknown/raspberry
- supervisor/supervisor2003
- test/123abc

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass
- json

HTTP User-Agents:
- N/A

SSH Clients:
- N/A

SSH Servers:
- N/A

Top Attacker AS Organizations:
- N/A

Key Observations and Anomalies:
- A large number of commands are related to reconnaissance and setting up SSH access.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, indicating attempts to install a persistent SSH key.
- Several downloaded files (e.g., `arm.urbotnetisass`, `wget.sh`) suggest the deployment of malware.
- The high number of `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signatures suggests active exploitation of the DoublePulsar backdoor.
- The lack of HTTP User-Agents, SSH clients, and server information in the logs for this period is noteworthy.
