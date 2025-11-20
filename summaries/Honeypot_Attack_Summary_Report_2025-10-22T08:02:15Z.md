Honeypot Attack Summary Report

Report generated at: 2025-10-22T08:01:36Z
Timeframe: 2025-10-22T07:20:01Z to 2025-10-22T08:00:01Z
Files used to generate this report:
- agg_log_20251022T072001Z.json
- agg_log_20251022T074001Z.json
- agg_log_20251022T080001Z.json

Executive Summary
This report summarizes the honeypot activity over the last three collection periods, totaling 29,660 observed events. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and telnet-based attacks. The most frequent attacks originated from the IP address 111.175.37.46. VNC (port 5900) was the most targeted service, consistent with the high number of "VNC Authentication Failure" signatures triggered. Attackers were observed attempting to gain access using common credentials and executing post-exploitation commands, including attempts to modify SSH authorized_keys. Several CVEs were also detected, with CVE-2024-3721 being the most common.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 10222
- Suricata: 6906
- Heralding: 4936
- Honeytrap: 4099
- Ciscoasa: 1641
- Dionaea: 1274
- Sentrypeer: 294
- Mailoney: 78
- ConPot: 68
- Redishoneypot: 54
- Adbhoney: 30
- H0neytr4p: 24
- Tanner: 20
- ElasticPot: 11
- Ipphoney: 2
- Honeyaml: 1

Top attacking IPs:
- 111.175.37.46: 5156
- 10.208.0.3: 4949
- 185.243.96.105: 4940
- 42.113.170.173: 733
- 67.220.72.53: 808
- 195.66.25.166: 293
- 165.22.196.164: 200
- 107.170.36.5: 248
- 139.59.74.228: 222
- 95.237.254.79: 234
- 139.5.70.208: 217
- 50.6.5.235: 227

Top targeted ports/protocols:
- vnc/5900: 4936
- 22: 1735
- 445: 1131
- 5060: 294
- 5903: 228
- TCP/1433: 105
- 1433: 93
- 8333: 147
- 5901: 111
- 25: 78
- TCP/22: 72
- 1025: 55
- 6379: 54

Most common CVEs:
- CVE-2024-3721 CVE-2024-3721: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1

Commands attempted by attackers:
- uname -a: 28
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 26
- lockr -ia .ssh: 26
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 26
- cat /proc/cpuinfo | grep name | wc -l: 26
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 26
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 26
- ls -lh $(which ls): 26
- which ls: 26
- crontab -l: 26
- w: 26
- uname -m: 26
- cat /proc/cpuinfo | grep model | grep name | wc -l: 26
- top: 26
- uname: 26
- whoami: 26
- lscpu | grep Model: 25
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 25
- Enter new UNIX password: : 16
- Enter new UNIX password:": 16

Signatures triggered:
- ET INFO VNC Authentication Failure: 4935
- 2002920: 4935
- ET DROP Dshield Block Listed Source group 1: 438
- 2402000: 438
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 258
- 2023753: 258
- ET SCAN NMAP -sS window 1024: 176
- 2009582: 176
- ET HUNTING RDP Authentication Bypass Attempt: 109
- 2034857: 109
- ET SCAN Suspicious inbound to MSSQL port 1433: 101
- 2010935: 101
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57

Users / login attempts:
- /Passw0rd: 29
- 345gs5662d34/345gs5662d34: 23
- /1q2w3e4r: 19
- /passw0rd: 16
- odin/odin: 10
- /1qaz2wsx: 10
- /qwertyui: 7
- root/3245gs5662d34: 6
- root/bert5eMgr: 4
- kdm/kdm123: 4
- /asdqwe123: 3

Files uploaded/downloaded:
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- k.php?a=x86_64,909GQ0953V234968H: 1

HTTP User-Agents:
- (No data)

SSH clients and servers:
- (No data)

Top attacker AS organizations:
- (No data)

Key Observations and Anomalies:
- The high number of VNC authentication failures suggests a widespread scanning or brute-force campaign targeting VNC servers.
- The commands executed by attackers indicate a common pattern of attempting to disable security measures (`chattr`), clear existing SSH keys, and install their own persistent access.
- Attackers are actively attempting to download and execute malicious scripts (`wget.sh`, `w.sh`, `c.sh`, `k.php`), indicating attempts to deploy malware or add the compromised machine to a botnet.
- The presence of commands to gather system information (`uname`, `lscpu`, `free`, `df`) suggests attackers are profiling the system for further exploitation.
- The CVEs detected are a mix of older and more recent vulnerabilities, indicating that attackers are using a broad set of exploits to target a wide range of systems.
