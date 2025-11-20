Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T20:01:43Z
**Timeframe of Analysis:** 2025-10-10T19:20:01Z to 2025-10-10T20:00:01Z
**Log Files Used:**
- agg_log_20251010T192001Z.json
- agg_log_20251010T194001Z.json
- agg_log_20251010T200001Z.json

**Executive Summary**
This report summarizes a total of 16,768 attacks recorded across three log files. The most targeted honeypot was Cowrie, with 7,569 events. The most active attacking IP address was 50.6.225.98, responsible for 1,569 events. The most targeted port was port 22 (SSH). A number of CVEs were detected, with CVE-2022-27255 being the most frequent. Attackers attempted a variety of commands, with a significant number of reconnaissance and persistence commands.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 7569
- Honeytrap: 3074
- Suricata: 2166
- Ciscoasa: 1803
- Mailoney: 875
- Dionaea: 847
- Sentrypeer: 228
- H0neytr4p: 48
- Adbhoney: 40
- ssh-rsa: 30
- Tanner: 23
- Redishoneypot: 23
- ConPot: 19
- Honeyaml: 19
- Dicompot: 3
- ElasticPot: 1

**Top Attacking IPs:**
- 50.6.225.98: 1569
- 176.65.141.117: 820
- 167.250.224.25: 526
- 88.210.63.16: 479
- 103.140.73.162: 366
- 119.207.254.77: 351
- 197.5.145.8: 371
- 58.98.200.129: 257
- 27.112.79.174: 257
- 109.230.196.142: 297
- 194.74.196.10: 292
- 31.40.204.154: 202
- 81.192.46.36: 203
- 23.227.147.163: 183
- 122.166.211.27: 163
- 197.5.145.150: 123
- 211.24.41.44: 126
- 51.89.150.103: 124
- 104.168.56.59: 119
- 14.103.135.94: 119

**Top Targeted Ports/Protocols:**
- 22: 1066
- 25: 866
- TCP/21: 242
- 5060: 228
- 5903: 193
- 21: 119
- UDP/5060: 88
- 5908: 85
- 5909: 84
- 5901: 72
- 23: 40
- 8333: 42
- 5907: 49
- 3443: 28
- 6379: 18
- 443: 33
- 10801: 42
- TCP/22: 24
- 18017: 28
- 3388: 19

**Most Common CVEs:**
- CVE-2022-27255 CVE-2022-27255: 12
- CVE-2002-0013 CVE-2002-0012: 6
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2024-3721 CVE-2024-3721: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 37
- lockr -ia .ssh: 37
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 37
- cat /proc/cpuinfo | grep name | wc -l: 37
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 37
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 37
- ls -lh $(which ls): 37
- which ls: 37
- crontab -l: 37
- w: 37
- uname -m: 37
- cat /proc/cpuinfo | grep model | grep name | wc -l: 37
- top: 37
- uname: 37
- uname -a: 44
- whoami: 37
- lscpu | grep Model: 37
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 36
- Enter new UNIX password: : 31
- Enter new UNIX password:: 31

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 420
- 2402000: 420
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 382
- 2023753: 382
- ET HUNTING RDP Authentication Bypass Attempt: 182
- 2034857: 182
- ET SCAN NMAP -sS window 1024: 154
- 2009582: 154
- ET FTP FTP PWD command attempt without login: 117
- 2010735: 117
- ET FTP FTP CWD command attempt without login: 117
- 2010731: 117
- ET SCAN Sipsak SIP scan: 72
- 2008598: 72
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 12
- 2403342: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 2: 11
- 2403301: 11

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 36
- root/: 30
- root/nPSpP4PBW0: 16
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 12
- admin/P@ssword: 6
- root/3245gs5662d34: 5
- guest/P@ssw0rd: 6
- support/123456789: 6
- runner/runnerpass: 5
- ali/ali!: 5
- root/root@123: 7
- admin/000: 6
- blank/00: 4
- root/make00@1!: 4
- root/Wnter@1183!: 4
- miguel/miguel: 4
- root/H4K1N6@NT: 4
- root/connvertex@123: 4
- root/edcpl1@9: 4
- root/48Ums6XupV@J_=!6: 4

**Files Uploaded/Downloaded:**
- ): 1

**HTTP User-Agents:**
- No user agents were logged in this timeframe.

**SSH Clients:**
- No SSH clients were logged in this timeframe.

**SSH Servers:**
- No SSH servers were logged in this timeframe.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged in this timeframe.

**Key Observations and Anomalies**
- A recurring command sequence was observed across multiple attacks, involving reconnaissance of the system specifications (`uname`, `lscpu`, `free`, `df`) followed by an attempt to add an SSH key to `authorized_keys`. This indicates a coordinated campaign with a clear playbook.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...` was seen 37 times, suggesting a persistent attempt by one or more actors to gain lasting access.
- The variety of credentials used, from default and simple passwords to more complex ones, indicates a broad-spectrum brute-force attack methodology.
- The "ET DROP Dshield Block Listed Source group 1" signature was the most triggered, indicating that many of the attacking IPs are already known malicious actors.
- A single file named ")" was downloaded. This is highly unusual and could be a malformed command or an attempt to exploit a vulnerability. Further investigation into the associated event is recommended.
