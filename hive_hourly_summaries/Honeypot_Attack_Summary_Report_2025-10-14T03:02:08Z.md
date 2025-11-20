Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T03:01:38Z
**Timeframe:** 2025-10-14T02:20:01Z to 2025-10-14T03:00:01Z
**Files Used:**
- agg_log_20251014T022001Z.json
- agg_log_20251014T024001Z.json
- agg_log_20251014T030001Z.json

### Executive Summary
This report summarizes 26,833 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Dionaea and Suricata. The most targeted service was SMB on port 445, followed by SIP on port 5060 and SSH on port 22. A large number of attacks originated from IP addresses 125.227.67.3, 175.176.23.36 and 200.87.27.60.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 12151
- Dionaea: 5659
- Suricata: 3509
- Sentrypeer: 2938
- Honeytrap: 2219
- Tanner: 112
- Miniprint: 45
- Mailoney: 61
- ConPot: 35
- Redishoneypot: 26
- Dicompot: 16
- H0neytr4p: 31
- Honeyaml: 13
- Adbhoney: 5
- Ciscoasa: 7
- Heralding: 4
- ElasticPot: 2

**Top Attacking IPs:**
- 125.227.67.3: 3110
- 200.87.27.60: 1319
- 175.176.23.36: 1591
- 8.222.207.98: 1231
- 42.119.232.181: 1120
- 185.243.5.146: 1080
- 196.251.88.103: 634
- 185.243.5.148: 715
- 114.204.9.108: 515
- 45.236.188.4: 582
- 103.187.147.252: 444
- 103.165.236.27: 489
- 165.22.63.142: 494
- 217.199.252.113: 346
- 110.93.250.7: 316
- 57.128.173.133: 356
- 172.86.95.115: 355
- 103.179.57.139: 290
- 172.245.92.99: 257
- 172.86.95.98: 246

**Top Targeted Ports/Protocols:**
- 445: 5614
- 5060: 2938
- 22: 1382
- TCP/445: 1640
- 5903: 178
- 80: 116
- 4891: 66
- 5908: 75
- 5909: 75
- 25: 65
- UDP/5060: 66
- 5901: 69
- 9100: 45
- TCP/22: 62
- 5907: 46
- TCP/80: 68
- 6379: 21
- 5910: 33
- 1455: 78
- 9092: 56

**Most Common CVEs:**
- CVE-2005-4050: 58
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2024-4577 CVE-2024-4577: 4
- CVE-2024-4577 CVE-2002-0953: 4
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 2
- CVE-2021-42013 CVE-2021-42013: 2
- CVE-2001-0414: 1
- CVE-1999-0183: 1
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2018-10562 CVE-2018-10561: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 80
- lockr -ia .ssh: 80
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 80
- cat /proc/cpuinfo | grep name | wc -l: 79
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 78
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 78
- ls -lh $(which ls): 78
- which ls: 78
- uname -a: 78
- crontab -l: 77
- w: 77
- uname -m: 77
- cat /proc/cpuinfo | grep model | grep name | wc -l: 77
- top: 77
- uname: 77
- whoami: 77
- lscpu | grep Model: 77
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 77
- Enter new UNIX password: : 55
- Enter new UNIX password:: 55

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1633
- 2024766: 1633
- ET DROP Dshield Block Listed Source group 1: 621
- 2402000: 621
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 164
- 2023753: 164
- ET SCAN NMAP -sS window 1024: 146
- 2009582: 146
- ET HUNTING RDP Authentication Bypass Attempt: 72
- 2034857: 72
- ET VOIP MultiTech SIP UDP Overflow: 58
- 2003237: 58
- ET INFO Reserved Internal IP Traffic: 55
- 2002752: 55
- ET SCAN Potential SSH Scan: 48
- 2001219: 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 20
- 2403347: 20
- ET SCAN Suspicious inbound to MSSQL port 1433: 8
- 2010935: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 11
- 2403341: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
- 2403345: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
- 2403346: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 8
- 2403344: 8

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 74
- root/3245gs5662d34: 23
- root/123@@@: 20
- root/Qaz123qaz: 14
- root/pass123: 8
- root/abc123456: 8
- root/Admin123: 8
- root/guest: 8
- root/passwd: 8
- root/password@#: 8
- dev/p@ssw0rd: 8
- ubuntu/passw0rd: 8
- ftpuser/ftppassword: 11
- root/Password@2025: 13
- root/Jk123456.: 6
- ubnt/ubnt2009: 6
- ubuntu/ubuntu: 6
- dev/dev: 6
- user/asdfgh: 6
- root/123456789: 5
- user/user2017: 5
- root/qq123456: 5
- root/1qaz@WSX: 5
- root/Password1: 5

**Files Uploaded/Downloaded:**
- sh: 196
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png: 4
- gpon80&ipv=0: 4
- ns#: 2
- sign_in: 2
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png: 2
- 172.20.254.127: 2
- 11: 1
- fonts.gstatic.com: 1
- css?family=Libre+Franklin...: 1
- ie8.css?ver=1.0: 1
- html5.js?ver=3.7.3: 1
- boatnet.mpsl;: 1
- &currentsetting.htm=1: 1

**HTTP User-Agents:**
- No user agents were logged in this timeframe.

**SSH Clients and Servers:**
- No SSH clients or servers were logged in this timeframe.

**Top Attacker AS Organizations:**
- No AS organizations were logged in this timeframe.

### Key Observations and Anomalies
- The high number of events targeting port 445 (SMB) suggests widespread scanning and exploitation attempts for vulnerabilities like EternalBlue. The signature "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" confirms this.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a common technique used by attackers to install their own SSH key for persistent access.
- There is a significant amount of scanning for SIP (port 5060), indicating interest in VoIP infrastructure.
- The variety of credentials used in brute-force attacks shows that attackers are still relying on common and default passwords.
- A large number of commands executed are for system reconnaissance, such as checking CPU info, memory, and running processes.
