Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T08:01:29Z
**Timeframe:** 2025-10-02T07:20:01Z to 2025-10-02T08:00:01Z
**Files Used:**
- agg_log_20251002T072001Z.json
- agg_log_20251002T074001Z.json
- agg_log_20251002T080001Z.json

### Executive Summary

This report summarizes honeypot activity over a 40-minute period, based on data from three log files. A total of 23,013 attacks were recorded. The most targeted honeypot was Cowrie. The most frequent attacker IP was 103.220.207.174. The most targeted port was 445/TCP (SMB). Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7670
- Suricata: 4502
- Dionaea: 4066
- Honeytrap: 4642
- Ciscoasa: 1042
- Mailoney: 844
- Redishoneypot: 61
- H0neytr4p: 40
- Tanner: 45
- Adbhoney: 29
- ConPot: 25
- Heralding: 16
- Sentrypeer: 18
- ElasticPot: 3
- Ipphoney: 4
- Dicompot: 4
- Honeyaml: 7
- Miniprint: 3
- ssh-rsa: 2

**Top Attacking IPs:**
- 103.220.207.174: 3613
- 188.163.10.74: 3115
- 5.202.84.202: 1624
- 156.221.173.213: 1589
- 124.222.148.115: 718
- 176.65.141.117: 820
- 118.70.150.110: 580
- 197.5.145.8: 391
- 89.44.137.176: 367
- 216.10.242.161: 386
- 185.156.73.166: 359
- 92.63.197.55: 355
- 182.18.161.165: 312
- 107.170.228.16: 272
- 92.63.197.59: 326
- 103.48.192.48: 247
- 185.141.132.26: 265
- 138.197.107.48: 252
- 193.46.217.151: 258
- 83.97.24.41: 211

**Top Targeted Ports/Protocols:**
- 445: 5721
- 22: 1094
- 3306: 203
- 25: 844
- 8333: 95
- 9092: 115
- 6379: 61
- 80: 41
- 443: 37
- 135: 73
- TCP/80: 38
- TCP/22: 36
- 2222: 23
- 27017: 14
- 1433: 20
- UDP/161: 24
- TCP/1433: 24
- 23: 19
- 55577: 11
- 2049: 10

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 14
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-2025-57819 CVE-2025-57819: 6
- CVE-1999-0517: 3
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2021-35394 CVE-2021-35394: 2
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
- CVE-1999-0183: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 41
- lockr -ia .ssh: 41
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 42
- cat /proc/cpuinfo | grep name | wc -l: 40
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 40
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 40
- ls -lh $(which ls): 39
- which ls: 39
- crontab -l: 39
- w: 38
- uname -m: 39
- cat /proc/cpuinfo | grep model | grep name | wc -l: 39
- top: 39
- uname: 39
- uname -a: 46
- whoami: 39
- lscpu | grep Model: 39
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 39
- Enter new UNIX password: : 22
- Enter new UNIX password:: 11
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 12

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 340
- ET SCAN NMAP -sS window 1024: 169
- ET INFO Reserved Internal IP Traffic: 62
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 3200
- ET SCAN Suspicious inbound to MSSQL port 1433: 23
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 12
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 35
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 29
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 67: 11
- GPL SNMP request udp: 11
- ET INFO CURL User Agent: 10

**Users / Login Attempts:**
- dba/: 200
- 345gs5662d34/345gs5662d34: 40
- root/3245gs5662d34: 20
- root/nPSpP4PBW0: 16
- root/2glehe5t24th1issZs: 18
- test/zhbjETuyMffoL8F: 16
- foundry/foundry: 15
- root/LeitboGi0ro: 15
- superadmin/admin123: 14
- postgres/123: 2
- pi/raspberry: 2
- root/Qwer#1234: 2
- anonymous/: 2

**Files Uploaded/Downloaded:**
- config.php: 2
- arm.urbotnetisass: 4
- arm5.urbotnetisass: 4
- arm6.urbotnetisass: 4
- arm7.urbotnetisass: 4
- x86_32.urbotnetisass: 4
- mips.urbotnetisass: 4
- mipsel.urbotnetisass: 4
- 11: 5
- fonts.gstatic.com: 5
- css?family=Libre+Franklin...: 5
- ie8.css?ver=1.0: 5
- html5.js?ver=3.7.3: 5
- Space.mips;: 4

**HTTP User-Agents:**
- No HTTP User-Agents were recorded in this period.

**SSH Clients:**
- No SSH clients were recorded in this period.

**SSH Servers:**
- No SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in this period.

### Key Observations and Anomalies

- The high number of attacks on port 445 (SMB), particularly the `DoublePulsar Backdoor` signature, suggests a campaign targeting Windows systems with the EternalBlue exploit.
- A significant number of commands are related to establishing a foothold, such as manipulating SSH authorized_keys files and disabling security measures.
- Attackers are attempting to download and execute malicious binaries for various architectures (ARM, MIPS, x86), indicating automated and widespread infection attempts.
- The majority of login attempts use common or default credentials, highlighting the ongoing threat of brute-force attacks.
