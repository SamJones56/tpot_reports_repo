Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T10:01:39Z
**Timeframe:** 2025-10-09T09:20:01Z to 2025-10-09T10:00:01Z
**Files Used:**
- agg_log_20251009T092001Z.json
- agg_log_20251009T094001Z.json
- agg_log_20251009T100001Z.json

### Executive Summary
This report summarizes 21,784 attacks recorded across three honeypot log files. The most targeted honeypot was Cowrie (SSH), followed by Suricata (IDS) and Honeytrap. A significant portion of the attacks originated from the IP address 167.250.224.25. The most targeted port was 22 (SSH). Attackers attempted various commands, including reconnaissance and efforts to install malware. Several CVEs were targeted, with CVE-2002-0013 and CVE-2002-0012 being the most common.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8351
- Suricata: 4448
- Honeytrap: 3237
- Heralding: 3151
- Ciscoasa: 1598
- Sentrypeer: 635
- Dionaea: 176
- Redishoneypot: 53
- Mailoney: 43
- H0neytr4p: 29
- Miniprint: 17
- Tanner: 20
- Adbhoney: 14
- ElasticPot: 6
- ssh-rsa: 2
- Honeyaml: 2
- Ipphoney: 1
- ConPot: 1

**Top Attacking IPs:**
- 167.250.224.25: 4659
- 188.253.1.20: 3127
- 10.17.0.5: 1178
- 10.140.0.3: 796
- 80.94.95.238: 728
- 78.31.71.38: 618
- 45.140.17.52: 499
- 210.79.190.46: 267
- 20.169.164.223: 228
- 42.200.66.164: 234
- 182.18.161.165: 203
- 58.213.147.49: 199
- 60.199.224.55: 168
- 45.81.23.80: 200
- 115.84.183.242: 149
- 41.223.40.77: 149
- 181.97.224.21: 124
- 192.3.159.176: 124
- 69.74.29.21: 149
- 80.253.31.232: 114

**Top Targeted Ports/Protocols:**
- vnc/5900: 3151
- 22: 1423
- 5060: 635
- 5903: 199
- 8333: 136
- 445: 71
- TCP/22: 116
- 1433: 45
- 6379: 53
- 5901: 70
- UDP/5060: 52
- 25: 43
- 5908: 48
- 5909: 46
- 5907: 47

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-35394 CVE-2021-35394: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 21
- lockr -ia .ssh: 21
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 21
- Enter new UNIX password: : 20
- Enter new UNIX password:: 20
- cat /proc/cpuinfo | grep name | wc -l: 20
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 20
- ls -lh $(which ls): 20
- which ls: 20
- crontab -l: 20
- w: 20
- uname -m: 20
- top: 20
- uname: 20
- uname -a: 23
- whoami: 20
- lscpu | grep Model: 20
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 20
- cat /proc/cpuinfo | grep model | grep name | wc -l: 20

**Signatures Triggered:**
- ET INFO VNC Authentication Failure / 2002920: 1974
- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 770
- ET DROP Dshield Block Listed Source group 1 / 2402000: 489
- ET HUNTING RDP Authentication Bypass Attempt / 2034857: 144
- ET SCAN NMAP -sS window 1024 / 2009582: 149
- ET SCAN Potential SSH Scan / 2001219: 102
- ET INFO Reserved Internal IP Traffic / 2002752: 57
- ET SCAN Suspicious inbound to MSSQL port 1433 / 2010935: 31
- ET CINS Active Threat Intelligence Poor Reputation IP group 46 / 2403345: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 49 / 2403348: 23
- ET CINS Active Threat Intelligence Poor Reputation IP group 42 / 2403341: 22

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 15
- /qazwsxed: 13
- /power123: 12
- /passw0rd: 11
- /1q2w3e4r: 9
- /qweasdzxc: 9
- support/support123456789: 6
- user/000: 6
- guest/password321: 6
- operator/pass: 6
- support/support1234567: 6
- root/root2008: 6

**Files Uploaded/Downloaded:**
- parm;: 6
- parm5;: 6
- parm6;: 6
- parm7;: 6
- psh4;: 6
- parc;: 6
- pmips;: 6
- pmipsel;: 6
- psparc;: 6
- px86_64;: 6
- pi686;: 6
- pi586;: 6
- 11: 4
- fonts.gstatic.com: 4
- css?family=Libre+Franklin...: 4
- ie8.css?ver=1.0: 4
- html5.js?ver=3.7.3: 4
- w.sh;: 2
- ?format=json: 2
- icanhazip.com: 2
- boatnet.mpsl;: 1
- c.sh;: 1

### Key Observations and Anomalies
- A significant number of attacks were logged in a short period, indicating automated scanning and exploitation attempts.
- The high number of login attempts on Cowrie (SSH honeypot) with a variety of usernames and passwords suggests widespread brute-force attacks.
- The `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` command indicates attempts to install a persistent SSH key for backdoor access.
- There was a large spike in VNC authentication failures, as shown by the "ET INFO VNC Authentication Failure" signature, likely from the Heralding honeypot.
- The variety of commands executed after successful logins on Cowrie suggests attackers are performing reconnaissance to understand the compromised system.
