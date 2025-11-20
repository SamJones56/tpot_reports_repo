Honeypot Attack Summary Report

Report Generated: 2025-10-07T01:01:46Z
Timeframe: 2025-10-07T00:20:01Z to 2025-10-07T01:00:01Z
Files Processed:
- agg_log_20251007T002001Z.json
- agg_log_20251007T004001Z.json
- agg_log_20251007T010001Z.json

Executive Summary
This report summarizes 12,650 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a total of 4,928 events. The most frequent attacks originated from IP address 86.54.42.238. The most targeted port was port 25 (SMTP), closely followed by port 22 (SSH). Several CVEs were detected, with CVE-2019-11500 and CVE-2023-26801 being the most common. Attackers attempted a variety of commands, with a significant number of attempts to manipulate SSH authorized_keys.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 4928
- Honeytrap: 3139
- Suricata: 1776
- Ciscoasa: 1255
- Mailoney: 839
- Sentrypeer: 468
- Dionaea: 58
- Adbhoney: 52
- H0neytr4p: 41
- ConPot: 27
- Tanner: 24
- Honeyaml: 15
- Redishoneypot: 13
- ElasticPot: 7
- Ipphoney: 4
- Miniprint: 3
- Wordpot: 1

Top Attacking IPs:
- 86.54.42.238: 776
- 80.94.95.238: 672
- 187.140.167.179: 455
- 34.47.232.78: 445
- 103.191.178.123: 450
- 172.86.95.98: 448
- 118.26.36.241: 382
- 107.150.110.167: 338
- 8.129.28.185: 332
- 85.208.253.156: 263
- 111.172.197.136: 259
- 189.13.2.69: 203
- 101.36.122.23: 184
- 190.223.60.209: 209
- 51.158.120.121: 199
- 3.137.148.99: 129
- 106.13.120.146: 115
- 103.4.92.103: 115
- 3.137.73.221: 107
- 103.220.207.174: 93

Top Targeted Ports/Protocols:
- 25: 839
- 22: 644
- 5060: 468
- 8333: 197
- 5903: 88
- TCP/80: 69
- 443: 41
- 8000: 27
- 5909: 45
- 5907: 44
- 5908: 44
- TCP/1433: 24
- TCP/22: 24
- 80: 25
- TCP/1521: 23
- 6443: 50
- 55577: 18
- 1025: 18
- 20015: 17
- 2323: 17

Most Common CVEs:
- CVE-2019-11500: 3
- CVE-2023-26801: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2002-0013 CVE-2002-0012: 1

Commands Attempted by Attackers:
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 30
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 30
- lockr -ia .ssh: 30
- cat /proc/cpuinfo | grep name | wc -l: 30
- Enter new UNIX password: : 30
- Enter new UNIX password:": 30
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 30
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 30
- ls -lh $(which ls): 30
- which ls: 30
- crontab -l: 30
- w: 30
- uname -m: 30
- cat /proc/cpuinfo | grep model | grep name | wc -l: 30
- top: 30
- uname: 30
- uname -a: 31
- whoami: 29
- lscpu | grep Model: 29
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 29

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1: 454
- 2402000: 454
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 344
- 2023753: 344
- ET SCAN NMAP -sS window 1024: 155
- 2009582: 155
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET INFO curl User-Agent Outbound: 24
- 2013028: 24
- ET HUNTING curl User-Agent to Dotted Quad: 24
- 2034567: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 23
- 2403350: 23
- ET COMPROMISED Known Compromised or Hostile Host Traffic group 5: 20
- 2500008: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 12
- 2403348: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 9
- 2403343: 9

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 29
- vpn/vpn!: 8
- vpn/3245gs5662d34: 8
- admin/12345696: 3
- admin/beta1234: 3
- admin/1234567890h: 3
- admin/123456987a: 3
- admin/a147258: 3
- minecraft/Password1: 3
- camellia/camellia: 3
- camellia/camellia1: 3
- camellia/camellia123: 3
- camellia/camellia1234: 3
- camellia/camellia12345: 3
- ubuntu/ubuntu123: 2
- bitrix/1234: 2
- cie/cie123: 2
- adminuser/password1: 2
- proxyuser/123321: 2
- roman/roman@2025: 2

Files Uploaded/Downloaded:
- wget.sh;: 24
- c.sh;: 6
- w.sh;: 6
- ?format=json: 4
- 11: 2
- fonts.gstatic.com: 2
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 2
- ie8.css?ver=1.0: 2
- html5.js?ver=3.7.3: 2

HTTP User-Agents:
- (No user agents recorded)

SSH Clients:
- (No SSH clients recorded)

SSH Servers:
- (No SSH servers recorded)

Top Attacker AS Organizations:
- (No AS organizations recorded)

Key Observations and Anomalies
- A significant amount of activity was related to attempts to add a public SSH key to the authorized_keys file. This is a common technique used by attackers to maintain persistent access to a compromised system.
- The high number of events on port 25 (SMTP) suggests a potential campaign of spam or phishing-related activity.
- The commands executed by attackers indicate a focus on system reconnaissance, such as checking CPU information, memory, and disk space.
- The presence of commands like `chattr` and `lockr` suggests more sophisticated attackers attempting to make their changes immutable.
- The filenames `w.sh`, `c.sh`, and `wget.sh` indicate the use of shell scripts for automated attacks, likely for downloading and executing malware.
