Honeypot Attack Summary Report

Report Generation Time: 2025-10-16T07:01:38Z
Timeframe: 2025-10-16T06:20:01Z to 2025-10-16T07:00:01Z
Files Used:
- agg_log_20251016T062001Z.json
- agg_log_20251016T064001Z.json
- agg_log_20251016T070001Z.json

Executive Summary:
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 25,779 attacks were recorded, with a significant amount of activity targeting the SMB protocol on port TCP/445. The most active honeypot was Suricata, and the most prolific attacking IP was 222.212.130.218. A number of CVEs were targeted, and a variety of commands were attempted on compromised systems.

Detailed Analysis:

Attacks by Honeypot:
- Suricata: 10775
- Cowrie: 5354
- Honeytrap: 3124
- Sentrypeer: 2725
- Mailoney: 1675
- Ciscoasa: 1537
- Dionaea: 426
- H0neytr4p: 47
- ConPot: 34
- Tanner: 42
- Adbhoney: 9
- Redishoneypot: 6
- Dicompot: 12
- Honeyaml: 8
- ElasticPot: 4
- Ipphoney: 1

Top Attacking IPs:
- 222.212.130.218: 3836
- 103.28.245.6: 2802
- 117.99.162.46: 1482
- 178.20.181.143: 1386
- 143.198.201.181: 1244
- 86.54.42.238: 1643
- 23.94.26.58: 811
- 172.86.95.115: 454
- 172.86.95.98: 451
- 185.243.5.158: 404
- 36.88.28.122: 311
- 94.61.180.236: 256
- 103.146.23.183: 336
- 62.141.43.183: 296
- 41.203.213.8: 306
- 107.170.36.5: 230
- 176.109.80.72: 204
- 20.79.154.209: 159
- 198.12.68.114: 112
- 194.113.236.217: 178

Top Targeted Ports/Protocols:
- TCP/445: 9357
- 5060: 2725
- 25: 1672
- 22: 797
- 445: 220
- 5903: 207
- 3306: 124
- 8333: 109
- 5901: 106
- TCP/22: 49
- 23: 47
- 5905: 71
- 5904: 71
- 80: 54
- 5908: 47
- 5909: 45
- 5907: 44
- 5902: 46
- UDP/5060: 36
- 27017: 15

Most Common CVEs:
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2021-3449 CVE-2021-3449: 1

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 24
- lockr -ia .ssh: 24
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 24
- cat /proc/cpuinfo | grep name | wc -l: 24
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 24
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 24
- ls -lh $(which ls): 24
- which ls: 24
- crontab -l: 24
- w: 24
- uname -m: 24
- cat /proc/cpuinfo | grep model | grep name | wc -l: 24
- top: 24
- uname: 24
- uname -a: 24
- whoami: 24
- lscpu | grep Model: 24
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 24
- Enter new UNIX password: : 19
- Enter new UNIX password:: 19

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 9345
- 2024766: 9345
- ET DROP Dshield Block Listed Source group 1: 429
- 2402000: 429
- ET SCAN NMAP -sS window 1024: 156
- 2009582: 156
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 82
- 2023753: 82
- ET INFO Reserved Internal IP Traffic: 53
- 2002752: 53
- ET SCAN Sipsak SIP scan: 44
- 2008598: 44
- ET SCAN Potential SSH Scan: 28
- 2001219: 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 21
- 2403350: 21

Users / Login Attempts:
- root/: 122
- 345gs5662d34/345gs5662d34: 23
- operator/operator2003: 8
- support/support2025: 6
- blank/blank2006: 6
- root/Qaz123qaz: 11
- blank/blank2017: 6
- config/8888: 6
- config/default: 6
- root/123@@@: 7
- nobody/nobody12345: 4
- root/pass99word: 4
- support/ubuntu: 4
- root/passeASTERCOM: 4
- blank/blank444: 4
- root/passw0rd: 4
- support/passwd: 4

Files Uploaded/Downloaded:
- json: 2

HTTP User-Agents:
- None Observed

SSH Clients:
- None Observed

SSH Servers:
- None Observed

Top Attacker AS Organizations:
- None Observed

Key Observations and Anomalies:
- The overwhelming majority of attacks were SMB-related, specifically targeting TCP port 445. The high number of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signatures suggests that these attacks may be related to the EternalBlue exploit.
- The most common commands attempted by attackers are reconnaissance commands, suggesting that attackers are trying to understand the environment of the compromised system.
- The high number of login attempts for the user 'root' is expected, but the variety of other usernames and passwords suggests a wide range of targeted devices and services.
