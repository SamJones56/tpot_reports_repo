Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T17:01:40Z
**Timeframe:** Approximately 2025-10-14T16:20:01Z to 2025-10-14T17:00:01Z
**Files Used:**
- agg_log_20251014T162001Z.json
- agg_log_20251014T164002Z.json
- agg_log_20251014T170001Z.json

### Executive Summary
This report summarizes 17,354 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Sentrypeer, and Honeytrap honeypots. A significant amount of automated scanning and brute-force activity was observed, primarily targeting SSH (port 22) and SIP (port 5060). Attackers were observed attempting to add SSH keys for persistence and downloading payloads.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6191
- Sentrypeer: 3316
- Honeytrap: 3268
- Ciscoasa: 1769
- Suricata: 1482
- Mailoney: 912
- Dionaea: 123
- ElasticPot: 44
- H0neytr4p: 44
- ssh-rsa: 30
- Tanner: 38
- Miniprint: 33
- Redishoneypot: 30
- Honeyaml: 29
- Adbhoney: 22
- ConPot: 7
- Ipphoney: 13
- Heralding: 3

**Top Attacking IPs:**
- 95.170.68.246: 1252
- 86.54.42.238: 821
- 206.191.154.180: 1310
- 185.243.5.146: 1243
- 103.24.63.85: 567
- 185.243.5.148: 596
- 88.210.63.16: 417
- 172.86.95.98: 410
- 172.86.95.115: 395
- 196.22.48.114: 253
- 89.117.54.101: 295
- 62.141.43.183: 324

**Top Targeted Ports/Protocols:**
- 5060: 3316
- 22: 1036
- 25: 912
- 5903: 189
- 1433: 76
- TCP/1433: 77
- 5909: 82
- 5908: 81
- 5901: 74
- 6379: 30
- 9200: 41
- 80: 38
- 443: 37
- 23: 44

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-1999-0183: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2001-0414: 2

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 28
- lockr -ia .ssh: 28
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 28
- Enter new UNIX password: : 12
- Enter new UNIX password:": 12
- cat /proc/cpuinfo | grep name | wc -l: 12
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 12
- uname -a: 13
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 12
- ls -lh $(which ls): 12
- which ls: 12
- crontab -l: 12
- w: 12
- uname -m: 12
- cat /proc/cpuinfo | grep model | grep name | wc -l: 11
- top: 11
- uname: 11
- whoami: 11

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 331
- 2402000: 331
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 214
- 2023753: 214
- ET SCAN NMAP -sS window 1024: 159
- 2009582: 159
- ET HUNTING RDP Authentication Bypass Attempt: 104
- 2034857: 104
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61
- ET SCAN Suspicious inbound to MSSQL port 1433: 71
- 2010935: 71

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 29
- root/Password@2025: 14
- root/Qaz123qaz: 16
- ftpuser/ftppassword: 11
- root/123@@@: 10
- centos/password123: 6
- debian/debian2016: 6
- blank/99: 6
- root/777: 6
- guest/guest444: 6

**Files Uploaded/Downloaded:**
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- gpon8080&ipv=0: 4
- resty): 2

**HTTP User-Agents:**
- No HTTP user-agents were observed in the logs.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were identified in the logs.

### Key Observations and Anomalies
- A high volume of attacks originate from a small number of IP addresses, suggesting targeted or persistent attackers.
- The command `cd ~ && rm -rf .ssh && ...` is a common tactic to install a persistent SSH key. The key is associated with the alias `mdrfckr`.
- One of the attackers attempted to download and execute multiple versions of a payload named `urbotnetisass` for different architectures (arm, x86, mips). This indicates an attempt to infect a wide range of IoT or embedded devices.
- The most common signatures triggered are related to well-known blocklists (Dshield, Spamhaus) and scans for common services like RDP and MSSQL, indicating widespread, opportunistic scanning.
- Login attempts use a mix of common default credentials (e.g., `root/`, `admin/admin`) and more complex, possibly breached, passwords.
