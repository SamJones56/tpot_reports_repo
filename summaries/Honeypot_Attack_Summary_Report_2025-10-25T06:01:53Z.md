Honeypot Attack Summary Report

Report Generated: 2025-10-25T06:01:29Z
Timeframe: 2025-10-25T05:20:01Z to 2025-10-25T06:00:01Z
Files used: agg_log_20251025T052001Z.json, agg_log_20251025T054001Z.json, agg_log_20251025T060001Z.json

Executive Summary
This report summarizes 16,543 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Suricata, and Honeytrap honeypots. The most frequent attacks originated from the IP address 125.209.88.26. The most targeted port was TCP/445, commonly associated with SMB. A variety of CVEs were targeted, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis

Attacks by honeypot:
- Cowrie: 5488
- Suricata: 4229
- Honeytrap: 3992
- Ciscoasa: 1816
- Tanner: 236
- H0neytr4p: 203
- Dionaea: 180
- Sentrypeer: 170
- Mailoney: 112
- Redishoneypot: 30
- ElasticPot: 20
- Adbhoney: 20
- ConPot: 14
- Honeyaml: 16
- Miniprint: 11
- Ipphoney: 3
- Dicompot: 3

Top attacking IPs:
- 125.209.88.26: 1425
- 80.94.95.238: 1310
- 104.248.153.53: 993
- 109.205.211.9: 388
- 88.214.50.58: 297
- 64.227.131.199: 341
- 102.88.137.145: 331
- 91.98.66.178: 258
- 107.170.36.5: 250
- 165.154.112.12: 238
- 200.73.135.75: 263
- 118.99.80.55: 225

Top targeted ports/protocols:
- TCP/445: 1422
- 22: 826
- 80: 236
- 8333: 213
- 5060: 170
- 443: 196
- 3306: 146
- 5903: 131
- 5901: 118
- 25: 112

Most common CVEs:
- CVE-2019-11500
- CVE-2016-20016
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2002-1149
- CVE-1999-0183

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 25
- lockr -ia .ssh: 25
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 25
- cat /proc/cpuinfo | grep name | wc -l: 24
- uname -a: 24
- whoami: 24
- lscpu | grep Model: 24
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 24
- uname: 24
- top: 24
- crontab -l: 23
- w: 23
- uname -m: 23
- cat /proc/cpuinfo | grep model | grep name | wc -l: 23
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 23
- ls -lh $(which ls): 23
- which ls: 23
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 23
- Enter new UNIX password: : 19
- Enter new UNIX password:": 19

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1418
- 2024766: 1418
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1093
- 2023753: 1093
- ET DROP Dshield Block Listed Source group 1: 568
- 2402000: 568
- ET HUNTING RDP Authentication Bypass Attempt: 206
- 2034857: 206
- ET SCAN NMAP -sS window 1024: 181
- 2009582: 181

Users / login attempts:
- 345gs5662d34/345gs5662d34: 24
- root/ElastixPBXfun: 4
- root/Elastixpym3s2014: 4
- root/elastixreitoria: 4
- root/elastixRIUadmin2015: 4
- root/Root12345678: 4
- kita/kita: 5
- user/Zjzy@2023: 3
- user/Zjzy@2022!: 3
- user/Zjzy@2021!: 3
- user/Zjzy@2021: 3
- user/Zjzy@2020: 3
- root/!qaz2wsx3edc4rfv: 3
- moni/moni: 3
- root/3245gs5662d34: 3
- root/north: 3
- root/12345678Qq: 3
- root/ElastixServer: 3
- sammy/a: 3
- root/!qaZ@wsX: 3
- git/asdf1234: 3
- root/Eldar: 3
- root/P@ssw0rd!!: 3

Files uploaded/downloaded:
- sh: 8
- json: 2
- ns#: 4
- rdf-schema#: 2
- types#: 2
- core#: 2
- XMLSchema#: 2
- www.drupal.org): 2
- www.drupal.org: 1

HTTP User-Agents:
- (No user agents recorded)

SSH clients and servers:
- (No SSH clients or servers recorded)

Top attacker AS organizations:
- (No attacker AS organizations recorded)

Key Observations and Anomalies
- The overwhelming number of events targeting TCP/445, paired with the "DoublePulsar Backdoor" signature, suggests a widespread, automated campaign likely exploiting the EternalBlue vulnerability (MS17-010).
- The repeated execution of reconnaissance commands (e.g., `lscpu`, `uname`, `free -m`) across multiple sessions indicates attackers are profiling systems for further exploitation after gaining initial access.
- A significant number of login attempts use default or easily guessable credentials (e.g., 'root', 'user', 'demo'), highlighting the continued effectiveness of brute-force attacks.
- Attackers are consistently attempting to add their SSH key to the `.ssh/authorized_keys` file to establish persistent access to the compromised systems.
