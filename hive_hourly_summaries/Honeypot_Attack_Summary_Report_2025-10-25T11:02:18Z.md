Here is the Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-25T11:01:30Z
**Timeframe:** 2025-10-25T10:20:01Z to 2025-10-25T11:00:01Z
**Files Used:**
- agg_log_20251025T102001Z.json
- agg_log_20251025T104001Z.json
- agg_log_20251025T110001Z.json

**Executive Summary**

This report summarizes honeypot activity over the last hour, based on three log files. A total of 24,368 attacks were recorded. The most targeted services were VNC (vnc/5900) and SMB (445). The most common attacker IP was 185.243.96.105. Multiple CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted various commands, primarily related to establishing SSH access and gathering system information.

**Detailed Analysis**

***Attacks by honeypot:***
- Cowrie: 9192
- Heralding: 4353
- Dionaea: 3962
- Honeytrap: 2806
- Suricata: 1805
- Ciscoasa: 1728
- Sentrypeer: 277
- Adbhoney: 56
- Mailoney: 115
- ConPot: 38
- H0neytr4p: 17
- Tanner: 8
- Redishoneypot: 9
- ssh-rsa: 2

***Top attacking IPs:***
- 185.243.96.105: 4353
- 103.160.232.131: 2662
- 116.105.226.199: 867
- 157.245.72.224: 455
- 152.32.206.160: 420
- 171.231.188.241: 390
- 171.231.191.193: 342
- 94.182.174.219: 327
- 14.103.127.230: 327
- 20.255.62.58: 270
- 193.233.127.56: 273
- 107.170.36.5: 250
- 194.107.115.2: 263
- 201.186.40.250: 242
- 222.191.150.12: 221
- 158.174.211.17: 227
- 46.147.113.91: 213
- 185.50.38.20: 213
- 92.204.40.37: 197
- 23.158.56.22: 192

***Top targeted ports/protocols:***
- vnc/5900: 4353
- 445: 3692
- 22: 1219
- 5060: 277
- 3306: 198
- 5903: 134
- 25: 115
- 5901: 119
- 8333: 110
- 5904: 79
- 5905: 78
- TCP/22: 71
- 5907: 54
- 5909: 52
- 5908: 52
- UDP/161: 33
- 5902: 42
- 1433: 12
- 443: 15
- 81: 14

***Most common CVEs:***
- CVE-2002-0013 CVE-2002-0012: 24
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 13
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2025-34036 CVE-2025-34036: 1
- CVE-2001-0414: 1
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1

***Commands attempted by attackers:***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 54
- lockr -ia .ssh: 54
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 54
- cat /proc/cpuinfo | grep name | wc -l: 54
- uname -m: 54
- cat /proc/cpuinfo | grep model | grep name | wc -l: 54
- top: 54
- uname: 54
- uname -a: 54
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 53
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 53
- ls -lh $(which ls): 53
- which ls: 53
- crontab -l: 53
- w: 53
- whoami: 53
- lscpu | grep Model: 53
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 53
- Enter new UNIX password: : 41
- Enter new UNIX password:": 41

***Signatures triggered:***
- ET DROP Dshield Block Listed Source group 1: 426
- 2402000: 426
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 376
- 2023753: 376
- ET SCAN NMAP -sS window 1024: 186
- 2009582: 186
- ET HUNTING RDP Authentication Bypass Attempt: 145
- 2034857: 145
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET SCAN Potential SSH Scan: 33
- 2001219: 33
- GPL SNMP request udp: 18
- 2101417: 18
- ET SCAN Suspicious inbound to MSSQL port 1433: 10
- 2010935: 10
- ET DROP Spamhaus DROP Listed Traffic Inbound group 14: 9
- 2400013: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
- 2403346: 10

***Users / login attempts:***
- 345gs5662d34/345gs5662d34: 52
- /Passw0rd: 23
- root/3245gs5662d34: 12
- root/: 14
- /1q2w3e4r: 16
- /passw0rd: 9
- sa/000000: 10
- /qwertyui: 7
- root/ernesto.sebastian: 4
- root/EsDftyUiop368admin: 4
- root/ertyuiop: 4
- root/eseuadtp: 4
- ht/ht@123: 3
- hz/hz@123: 3
- user/sinister: 3
- user/shannon1: 3
- user/satana: 3
- user/sang: 3
- user/salomon: 3
- root/ersimco: 3

***Files uploaded/downloaded:***
- wget.sh;: 24
- w.sh;: 6
- c.sh;: 6
- arm.urbotnetisass;: 1
- arm5.urbotnetisass;: 1
- arm6.urbotnetisass;: 1
- arm7.urbotnetisass;: 1
- x86_32.urbotnetisass;: 1
- mips.urbotnetisass;: 1
- mipsel.urbotnetisass;: 1
- 34.165.197.224:8088: 2
- apply.cgi: 2
- string.js: 1
- json: 1

***HTTP User-Agents:***
- No user agents recorded in this timeframe.

***SSH clients and servers:***
- No SSH clients recorded in this timeframe.
- No SSH servers recorded in this timeframe.

***Top attacker AS organizations:***
- No attacker AS organizations recorded in this timeframe.

**Key Observations and Anomalies**

- A significant number of attacks are from the IP address 185.243.96.105, consistently targeting VNC services.
- Attackers are attempting to modify the `.ssh/authorized_keys` file to gain persistent access.
- Several commands indicate attempts to download and execute malicious scripts (e.g., `wget.sh`, `w.sh`, `c.sh`, and various `.urbotnetisass` files).
- The repeated use of commands to gather system information (`uname`, `lscpu`, `free`, `df`) suggests attackers are profiling the honeypot for further exploitation.
- The high number of "ET DROP Dshield Block Listed Source group 1" signatures indicates that many of the attacking IPs are already known to be malicious.
