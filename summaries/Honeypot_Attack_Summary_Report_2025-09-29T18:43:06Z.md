Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T18:42:14Z
**Timeframe:** 2025-09-29T18:00:01Z to 2025-09-29T18:40:01Z
**Files Analyzed:**
- agg_log_20250929T180001Z.json
- agg_log_20250929T182001Z.json
- agg_log_20250929T184001Z.json

### Executive Summary

This report summarizes 11,828 malicious events recorded by the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from the IP address 137.184.169.79. The most targeted ports were 445 (SMB) and 22 (SSH). A variety of CVEs were detected, with reconnaissance and exploitation attempts being common. A significant number of shell commands were executed, indicating attempts to download and execute malware, profile systems, and establish persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4783
- Honeytrap: 2749
- Suricata: 1530
- Ciscoasa: 1439
- Dionaea: 875
- Redishoneypot: 192
- Mailoney: 83
- Adbhoney: 37
- ElasticPot: 27
- Tanner: 24
- H0neytr4p: 31
- Sentrypeer: 23
- ConPot: 14
- ssh-rsa: 12
- Honeyaml: 4
- Dicompot: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 137.184.169.79: 870
- 58.186.122.40: 792
- 60.174.72.198: 454
- 2.59.62.188: 391
- 103.252.73.219: 391
- 103.181.143.216: 390
- 185.156.73.166: 374
- 92.63.197.55: 363
- 185.156.73.167: 368
- 103.31.39.66: 345
- 92.63.197.59: 338
- 5.227.118.140: 241
- 103.67.78.42: 214
- 47.83.31.202: 234
- 180.76.121.98: 162
- 101.91.230.147: 158
- 154.92.15.24: 129
- 172.245.163.134: 63
- 196.251.69.18: 61
- 124.131.95.236: 44

**Top Targeted Ports/Protocols:**
- 445: 812
- 22: 702
- 6379: 189
- 8333: 91
- 25: 76
- 23: 52
- TCP/80: 45
- TCP/22: 65
- 443: 52
- 4433: 35
- 9200: 26
- 80: 20
- 2323: 16
- 8081: 24
- 27017: 19
- 8008: 18
- 22022: 18
- 22222: 15
- TCP/5432: 15
- 2379: 14

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551: 2
- CVE-1999-0265: 2
- CVE-2006-2369: 1
- CVE-2024-3721 CVE-2024-3721: 1

**Commands Attempted by Attackers:**
- uname -a: 22
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
- lockr -ia .ssh: 20
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 20
- cat /proc/cpuinfo | grep name | wc -l: 20
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 20
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 20
- ls -lh $(which ls): 20
- which ls: 20
- crontab -l: 20
- w: 20
- uname -m: 20
- cat /proc/cpuinfo | grep model | grep name | wc -l: 20
- top: 20
- uname: 20
- whoami: 20
- lscpu | grep Model: 20
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20
- Enter new UNIX password: : 11
- Enter new UNIX password:: 5

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 391
- 2402000: 391
- ET SCAN NMAP -sS window 1024: 223
- 2009582: 223
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 47
- 2400031: 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 28
- 2403348: 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 34
- 2403344: 34
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 35
- 2403340: 35
- ET SCAN Potential SSH Scan: 27
- 2001219: 27
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 23
- 2403347: 23
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 22
- 2023753: 22

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 20
- foundry/foundry: 10
- test/zhbjETuyMffoL8F: 10
- root/: 12
- debian/admin123: 6
- deposito/deposito123: 5
- root/nPSpP4PBW0: 5
- admin/7ujMko0admin: 4
- root/LeitboGi0ro: 4
- config/config: 4
- user/P@$$word: 4
- root/Admin123!@: 4
- root/3245gs5662d34: 7
- user/147258: 6
- root/system32: 6
- root/jarvis: 5
- anonymous/: 4
- jack/changeme: 5
- qi/qi: 5
- akshay/akshay123: 6
- oguz/oguz: 6

**Files Uploaded/Downloaded:**
- wget.sh;: 8
- arm.urbotnetisass;: 4
- arm.urbotnetisass: 4
- arm5.urbotnetisass;: 4
- arm5.urbotnetisass: 4
- arm6.urbotnetisass;: 4
- arm6.urbotnetisass: 4
- arm7.urbotnetisass;: 4
- arm7.urbotnetisass: 4
- x86_32.urbotnetisass;: 4
- x86_32.urbotnetisass: 4
- mips.urbotnetisass;: 4
- mips.urbotnetisass: 4
- mipsel.urbotnetisass;: 4
- mipsel.urbotnetisass: 4
- w.sh;: 2
- c.sh;: 2
- k.php?a=x86_64,3V74AX6926R6GH83H: 1

**HTTP User-Agents:** (No data)

**SSH Clients:** (No data)

**SSH Servers:** (No data)

**Top Attacker AS Organizations:** (No data)

### Key Observations and Anomalies

- A high number of commands are associated with system reconnaissance (`uname`, `lscpu`, `free`, `df`) and attempts to establish persistence by modifying SSH authorized keys.
- Multiple download attempts of files with names like `arm.urbotnetisass`, `w.sh`, and `c.sh` suggest the use of botnet malware targeting various architectures (ARM, x86, MIPS).
- The repeated command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a clear indicator of attempts to inject a malicious SSH key for unauthorized access.
- Several `nohup bash -c "exec 6<>/dev/tcp/...` commands were observed, which are characteristic of reverse shell attacks, attempting to establish a connection back to an attacker-controlled server.
- The high volume of traffic to port 445 indicates widespread SMB scanning, likely searching for vulnerabilities like EternalBlue.

This report highlights a dynamic and aggressive threat landscape, with automated tools continuously scanning for and exploiting vulnerable services. The focus on SSH and SMB, along with the deployment of multi-architecture malware, underscores the need for robust security measures on internet-facing systems.
