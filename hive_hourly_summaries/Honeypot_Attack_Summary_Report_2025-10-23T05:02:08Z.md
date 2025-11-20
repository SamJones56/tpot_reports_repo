Honeypot Attack Summary Report

Report generated at: 2025-10-23T05:01:43Z
Timeframe: 2025-10-23T04:20:01Z to 2025-10-23T05:00:01Z
Files used for this report:
- agg_log_20251023T042001Z.json
- agg_log_20251023T044001Z.json
- agg_log_20251023T050001Z.json

Executive Summary
This report summarizes the honeypot activity over a period of approximately 40 minutes, analyzing data from three log files. A total of 21,558 attacks were recorded. The most active honeypot was Cowrie, and the most frequent attacker IP was 109.205.211.9. The most targeted port was 445/tcp (SMB), and the most common attack signature was "ET SCAN MS Terminal Server Traffic on Non-standard Port". Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 6205
- Honeytrap: 6490
- Suricata: 3687
- Dionaea: 2100
- Ciscoasa: 1765
- Sentrypeer: 1002
- ConPot: 162
- Adbhoney: 46
- Mailoney: 27
- Tanner: 24
- Redishoneypot: 17
- H0neytr4p: 19
- Honeyaml: 6
- Dicompot: 8

Top attacking IPs:
- 109.205.211.9: 2283
- 124.105.235.52: 1161
- 185.250.249.180: 1251
- 94.103.12.49: 717
- 211.22.131.98: 796
- 88.210.63.16: 510
- 174.138.38.19: 416
- 40.115.18.231: 258
- 202.131.237.254: 258
- 178.176.250.39: 204

Top targeted ports/protocols:
- 445: 2053
- 22: 903
- 5060: 1002
- 1025: 149
- 1067: 90
- 1034: 90
- 1068: 90
- 1037: 90
- 1050: 90
- 1049: 90

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2006-2369: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 29
- lockr -ia .ssh: 29
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 29
- cat /proc/cpuinfo | grep name | wc -l: 28
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 28
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 28
- ls -lh $(which ls): 28
- which ls: 28
- crontab -l: 28
- w: 28
- uname -m: 28

Signatures triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1524
- ET HUNTING RDP Authentication Bypass Attempt: 750
- ET DROP Dshield Block Listed Source group 1: 522
- ET SCAN NMAP -sS window 1024: 173
- ET INFO Reserved Internal IP Traffic: 54
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake: 36
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 25
- ET SCAN Potential SSH Scan: 23

Users / login attempts:
- 345gs5662d34/345gs5662d34: 28
- root/3245gs5662d34: 8
- root/Cbr1100xx!01: 4
- root/CBrito2015: 4
- root/Cc701950: 4
- root/ccaa22032012: 4
- root/CcmbYheefOdqyntm2010: 4
- hive/hive: 3
- git/git: 3
- wang/wang123: 3

Files uploaded/downloaded:
- ): 1

HTTP User-Agents:
- No user agents were logged in this timeframe.

SSH clients and servers:
- No SSH clients or servers were logged in this timeframe.

Top attacker AS organizations:
- No AS organizations were logged in this timeframe.

Key Observations and Anomalies
- The high number of attacks on port 445 (SMB) suggests continued interest in exploiting this service.
- The most common commands are related to reconnaissance and establishing persistence by adding an SSH key to `authorized_keys`.
- A significant number of signatures triggered are related to scanning and reconnaissance activities.
- The presence of CVEs, although in small numbers, indicates that attackers are still attempting to exploit known vulnerabilities.
- There is a large number of login attempts with default or weak credentials, highlighting the importance of strong password policies.
