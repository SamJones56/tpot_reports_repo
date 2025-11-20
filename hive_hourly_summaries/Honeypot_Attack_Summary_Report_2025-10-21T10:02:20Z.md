Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T10:01:41Z
**Timeframe Covered:** 2025-10-21T09:20:01Z to 2025-10-21T10:00:01Z
**Log Files Used:**
- agg_log_20251021T092001Z.json
- agg_log_20251021T094002Z.json
- agg_log_20251021T100001Z.json

### Executive Summary
This report summarizes 21,145 events recorded across the honeypot network. The primary activity observed was from the Honeytrap and Cowrie honeypots, indicating significant scanning and SSH brute-force attempts. A high volume of attacks originated from the IP address 142.4.197.12. Network traffic analysis revealed a large number of events related to the DoublePulsar backdoor (ET EXPLOIT signature), primarily targeting SMB on port 445. Attackers consistently attempted to modify SSH authorized_keys files to maintain persistence and executed reconnaissance commands to gather system information.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 9625
- Cowrie: 7041
- Suricata: 3162
- Sentrypeer: 497
- Dionaea: 479
- Redishoneypot: 82
- Tanner: 56
- Ciscoasa: 58
- ConPot: 32
- Mailoney: 50
- H0neytr4p: 18
- Dicompot: 17
- Miniprint: 12
- Honeyaml: 7
- Adbhoney: 8
- ElasticPot: 1

**Top Attacking IPs:**
- 142.4.197.12: 5372
- 45.113.107.195: 1352
- 72.146.232.13: 1212
- 165.227.98.222: 867
- 185.243.5.158: 316
- 103.163.113.38: 343
- 188.166.169.185: 223
- 205.185.115.224: 90
- 131.100.242.102: 297
- 107.170.36.5: 252
- 40.67.140.77: 258
- 162.240.157.215: 214
- 183.15.123.188: 204

**Top Targeted Ports/Protocols:**
- TCP/445: 1741
- 22: 1250
- 5060: 497
- 5903: 225
- 23: 160
- 8333: 100
- 5901: 121
- 6379: 72
- TCP/80: 59
- 5904: 80
- 5905: 76
- UDP/5060: 58

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449
- CVE-2019-16920
- CVE-2014-6271
- CVE-2023-47565
- CVE-2023-31983
- CVE-2009-2765
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2021-42013
- CVE-2021-41773
- CVE-2024-4577
- CVE-2002-0953
- CVE-2023-26801
- CVE-2020-10987
- CVE-2016-6563
- CVE-1999-0183
- CVE-2016-20017
- CVE-2021-35395
- CVE-2024-12856
- CVE-2024-12885
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`
- `w`
- `crontab -l`
- `top`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (1346)
- ET DROP Dshield Block Listed Source group 1 (458)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (224)
- ET SCAN NMAP -sS window 1024 (200)
- ET HUNTING RDP Authentication Bypass Attempt (64)
- ET INFO Reserved Internal IP Traffic (62)
- ET VOIP MultiTech SIP UDP Overflow (51)
- ET SCAN Potential SSH Scan (32)
- GPL TELNET Bad Login (12)

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 22
- user01/Password01: 15
- deploy/123123: 11
- root/3245gs5662d34: 5
- root/Amatz2014!!: 4
- root/Amazing1: 4
- root/amdlinux08011265: 4
- root/american: 4
- root/amiga1!: 4
- root/aminoguana: 4
- user01/3245gs5662d34: 5

**Files Uploaded/Downloaded:**
- sh: 58
- 3.253.97.195: 5
- rondo.qre.sh||busybox: 4
- rondo.qre.sh||curl: 4
- rondo.qre.sh)|sh: 4
- server.cgi?func=server02_main_submit...: 5
- rondo.dgx.sh||busybox: 3
- rondo.dgx.sh||curl: 3
- rondo.dgx.sh)|sh&: 3
- Mozi.m: 2
- login_pic.asp: 2

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions were recorded in this period.

**Top Attacker AS Organizations:**
- No AS organization data was recorded in this period.

### Key Observations and Anomalies
- **High Volume SMB Exploitation:** The prevalence of the DoublePulsar signature indicates widespread, automated attempts to exploit the SMB vulnerability, likely by worm-like malware or botnets.
- **SSH Persistence Tactics:** A recurring pattern involves attackers attempting to remove SSH folder immutability (`chattr -ia`), delete the existing `.ssh` directory, and then add their own public key to `authorized_keys`. This is a clear and consistent tactic for gaining persistent access.
- **System Reconnaissance:** Post-login commands are standard for system reconnaissance (`uname`, `lscpu`, `free`, `df`), suggesting attackers are profiling compromised machines for further exploitation or inclusion in a botnet.
- **Concentrated Attack Source:** The IP address 142.4.197.12 was responsible for over 25% of all recorded events, indicating a highly active or persistent threat actor. The activity from this IP was primarily directed at the Honeytrap honeypot.
