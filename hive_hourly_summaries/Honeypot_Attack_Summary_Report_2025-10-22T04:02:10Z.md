Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T04:01:29Z
**Timeframe:** 2025-10-22T03:20:01Z to 2025-10-22T04:00:01Z
**Files Used:**
- agg_log_20251022T032001Z.json
- agg_log_20251022T034001Z.json
- agg_log_20251022T040001Z.json

**Executive Summary**
This report summarizes 25,603 events collected from the honeypot network. The majority of attacks were detected by Suricata, Heralding, and Cowrie honeypots. The most prominent attack vector was VNC, with port 5900 being the most targeted. A significant number of attacks originated from the IP address 185.243.96.105. Attackers were observed attempting to install SSH keys for persistence and executing various reconnaissance commands. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

**Detailed Analysis**

**Attacks by Honeypot:**
- Suricata: 8598
- Heralding: 5967
- Cowrie: 4660
- Honeytrap: 3916
- Ciscoasa: 1701
- Sentrypeer: 279
- Dionaea: 195
- Mailoney: 90
- H0neytr4p: 65
- Redishoneypot: 23
- ConPot: 28
- Tanner: 19
- Dicompot: 24
- Honeyaml: 14
- Adbhoney: 12
- Miniprint: 9
- Ipphoney: 3

**Top Attacking IPs:**
- 185.243.96.105: 5970
- 10.208.0.3: 5979
- 72.146.232.13: 1176
- 177.27.71.43: 598
- 185.231.59.125: 312
- 38.47.91.116: 273
- 200.69.236.207: 248
- 107.170.36.5: 242
- 193.24.211.28: 256
- 172.245.45.194: 194
- 85.174.183.14: 160
- 182.117.144.122: 200
- 61.219.181.31: 224
- 52.187.61.159: 174
- 88.210.63.16: 178
- 52.224.240.74: 114
- 216.108.227.59: 118
- 20.46.54.49: 114
- 115.190.136.184: 114
- 107.175.39.180: 109

**Top Targeted Ports/Protocols:**
- vnc/5900: 5967
- 22: 860
- TCP/445: 639
- 5060: 279
- 5903: 223
- 8333: 114
- 1433: 99
- TCP/1433: 105
- 5901: 111
- 25: 90
- 443: 65
- 2048: 74
- 5905: 74
- 5904: 72
- 5909: 48
- 5907: 50
- 5908: 49
- 23: 18
- 5902: 41
- 2332: 28

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 11
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2005-4050: 1

**Commands Attempted by Attackers:**
- uname -a: 20
- cat /proc/cpuinfo | grep name | wc -l: 19
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 19
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
- ls -lh $(which ls): 19
- which ls: 19
- crontab -l: 19
- w: 19
- uname -m: 19
- cat /proc/cpuinfo | grep model | grep name | wc -l: 19
- top: 19
- uname: 19
- whoami: 19
- lscpu | grep Model: 19
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 19
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 18
- Enter new UNIX password: : 17
- Enter new UNIX password:: 17

**Signatures Triggered:**
- ET INFO VNC Authentication Failure: 5966
- 2002920: 5966
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 637
- 2024766: 637
- ET DROP Dshield Block Listed Source group 1: 477
- 2402000: 477
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 354
- 2023753: 354
- ET SCAN NMAP -sS window 1024: 178
- 2009582: 178
- ET HUNTING RDP Authentication Bypass Attempt: 149
- 2034857: 149
- ET SCAN Suspicious inbound to MSSQL port 1433: 105
- 2010935: 105
- ET INFO Reserved Internal IP Traffic: 63
- 2002752: 63
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 15
- 2403347: 15
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 19
- 2403345: 19

**Users / Login Attempts:**
- /Passw0rd: 27
- /1q2w3e4r: 28
- /passw0rd: 19
- 345gs5662d34/345gs5662d34: 16
- /1qaz2wsx: 11
- /qwertyui: 9
- root/Babarch321: 4
- root/bacanal28: 4
- root/backinfoemit: 4
- root/BaE15.14: 4
- /abc12345: 4
- root/Babolsar1357: 3
- jeff/123: 3
- /123qwe123: 3
- root/123456qW: 3
- root/bagudo3110: 3
- /asdf1234: 2
- root/extreme: 2
- /q1w2e3r4: 2
- /operator: 2

**Files Uploaded/Downloaded:**
- wget.sh;: 4
- ?format=json: 2
- w.sh;: 1
- c.sh;: 1

**HTTP User-Agents:**
- (No data)

**SSH Clients:**
- (No data)

**SSH Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

**Key Observations and Anomalies**
- A high volume of VNC traffic was observed, suggesting a widespread scanning or brute-force campaign targeting VNC servers.
- Attackers consistently attempted to add their SSH key to the authorized_keys file for persistent access. The key is associated with the comment "mdrfckr".
- The DoublePulsar backdoor was detected, indicating attempts to exploit SMB vulnerabilities, likely related to the EternalBlue exploit.
- A number of reconnaissance commands were executed, such as `uname -a`, `lscpu`, and `cat /proc/cpuinfo`, which are used to gather system information for further exploitation.
- Login attempts show a mix of common default credentials and more complex passwords, indicating both automated and potentially targeted attacks.
