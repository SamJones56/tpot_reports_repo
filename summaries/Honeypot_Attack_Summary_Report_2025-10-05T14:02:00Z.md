Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T14:01:27Z
**Timeframe:** 2025-10-05T13:20:01Z to 2025-10-05T14:00:01Z
**Files Used:**
- agg_log_20251005T132001Z.json
- agg_log_20251005T134002Z.json
- agg_log_20251005T140001Z.json

**Executive Summary**

This report summarizes 12,221 attacks recorded across three honeypot log files. The majority of attacks were captured by the Cowrie, Mailoney, and Suricata honeypots. The most targeted services were SMTP (port 25) and SIP (port 5060). A significant number of attacks originated from IP addresses 176.65.141.117 and 86.54.42.238. The most common vulnerability targeted was CVE-2005-4050. Attackers were observed attempting to add their SSH keys to the authorized_keys file.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 3818
- Mailoney: 2468
- Suricata: 2351
- Sentrypeer: 1316
- Ciscoasa: 1440
- Honeytrap: 536
- Dionaea: 73
- Miniprint: 52
- H0neytr4p: 32
- ConPot: 28
- Adbhoney: 23
- Redishoneypot: 21
- Tanner: 27
- Dicompot: 18
- ElasticPot: 7
- Honeyaml: 10
- Ipphoney: 1

***Top Attacking IPs***

- 176.65.141.117: 1640
- 86.54.42.238: 820
- 23.94.26.58: 960
- 172.86.95.98: 407
- 176.65.148.44: 308
- 88.214.50.58: 352
- 198.12.68.114: 268
- 185.243.5.68: 184
- 181.116.220.24: 183
- 158.174.210.161: 184
- 175.139.200.245: 194
- 154.221.23.24: 146
- 59.36.78.66: 234
- 113.193.234.210: 161
- 121.52.154.238: 238
- 113.45.15.8: 186
- 36.89.28.139: 95
- 119.82.65.219: 70
- 4.200.140.252: 142
- 3.130.96.91: 56

***Top Targeted Ports/Protocols***

- 25: 2468
- 5060: 1316
- 22: 546
- TCP/5900: 327
- UDP/5060: 534
- 445: 48
- 23: 60
- 443: 32
- 9100: 52
- 80: 26
- 6379: 18
- TCP/80: 22
- UDP/161: 24

***Most Common CVEs***

- CVE-2005-4050: 110
- CVE-2022-27255: 27
- CVE-2002-0013 CVE-2002-0012: 14
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-2021-3449: 2
- CVE-2023-26801: 1
- CVE-2009-2765: 1
- CVE-2019-16920: 1
- CVE-2023-31983: 1
- CVE-2020-10987: 1
- CVE-2023-47565: 1
- CVE-2014-6271: 1
- CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 1
- CVE-2006-2369: 1

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 25
- lockr -ia .ssh: 25
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 25
- cat /proc/cpuinfo | grep name | wc -l: 18
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 18
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 18
- ls -lh $(which ls): 18
- which ls: 18
- crontab -l: 17
- w: 17
- uname -m: 17
- cat /proc/cpuinfo | grep model | grep name | wc -l: 17
- top: 17
- uname: 17
- uname -a: 17
- whoami: 17
- lscpu | grep Model: 17
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 17
- Enter new UNIX password: : 10

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1: 492
- ET SCAN Sipsak SIP scan: 388
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 335
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 210
- ET SCAN NMAP -sS window 1024: 156
- ET VOIP MultiTech SIP UDP Overflow: 110
- ET HUNTING RDP Authentication Bypass Attempt: 105
- ET INFO Reserved Internal IP Traffic: 57
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 27
- ET CINS Active Threat Intelligence Poor Reputation IP group 69: 20

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34: 21
- novinhost/novinhost.org: 9
- root/09N1RCa1Hs31: 6
- root/3245gs5662d34: 7
- root/nPSpP4PBW0: 5
- debianuser/debian10svm: 5
- GET / HTTP/1.1/Host: ...: 3
- user/P@ssword123123: 2
- admin/admin256: 2
- user/nvrnn: 2
- user/viktor1: 2
- user/ovh123: 2
- user/Neno4eva!: 2
- root/Hl123456: 2
- rootftp/rootftp: 2
- root/Qwerty_1: 2
- esuser/M3gaP33!: 3
- pi/raspberry: 2
- ubnt/ubnt: 2
- admin/12345: 2

***Files Uploaded/Downloaded***

- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2
- `busybox`: 2
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 2
- rondo.sbx.sh|sh&echo${IFS}: 1
- login_pic.asp: 1

***HTTP User-Agents***

- No HTTP user agents were logged in the provided data.

***SSH Clients and Servers***

- No specific SSH clients or servers were logged in the provided data.

***Top Attacker AS Organizations***

- No attacker AS organizations were logged in the provided data.

**Key Observations and Anomalies**

- A large number of SMTP attacks were observed, primarily from two IP addresses. This could indicate a targeted campaign against mail servers.
- The repeated attempts to add an SSH key to the authorized_keys file by multiple attackers suggest a common attack vector for establishing persistent access.
- The presence of commands to gather system information (CPU, memory, etc.) is a common reconnaissance technique used by attackers to understand the compromised environment.
- The variety of honeypots that were triggered indicates a broad spectrum of scanning and exploitation attempts against different services.
