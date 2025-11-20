Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T21:01:33Z
**Timeframe:** 2025-09-30T20:20:01Z to 2025-09-30T21:00:01Z
**Files Used:**
- agg_log_20250930T202001Z.json
- agg_log_20250930T204001Z.json
- agg_log_20250930T210001Z.json

### Executive Summary
This report summarizes 16,309 attacks recorded by honeypots over a 40-minute period. The majority of attacks were logged by the Cowrie honeypot. The most frequent attacks originated from the IP address 77.85.120.146. The most targeted port was 445/TCP. A variety of CVEs were detected, with CVE-2022-27255 being the most common. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6498
- Dionaea: 3156
- Honeytrap: 2464
- Suricata: 1561
- Mailoney: 868
- Ciscoasa: 1407
- Sentrypeer: 125
- ConPot: 64
- Tanner: 72
- H0neytr4p: 25
- Adbhoney: 6
- Redishoneypot: 12
- Honeyaml: 7
- Heralding: 39
- ssh-rsa: 2
- Ipphoney: 1
- ElasticPot: 2

**Top Attacking IPs:**
- 77.85.120.146: 3124
- 152.32.219.169: 2512
- 45.78.192.84: 868
- 86.54.42.238: 821
- 161.132.37.66: 310
- 152.32.145.111: 337
- 154.221.21.168: 270
- 67.207.84.144: 324
- 103.76.120.90: 144
- 213.199.59.75: 134
- 103.31.39.143: 177
- 92.63.197.55: 356
- 185.156.73.166: 360
- 185.156.73.167: 360
- 92.63.197.59: 327
- 45.145.165.22: 72
- 190.57.251.10: 176
- 201.249.204.129: 254
- 23.94.26.58: 218
- 181.42.63.126: 174

**Top Targeted Ports/Protocols:**
- 445: 3140
- 22: 1111
- 25: 868
- 5060: 119
- UDP/5060: 107
- 8333: 102
- 80: 79
- 23: 66
- 1025: 50
- vnc/5900: 36
- TCP/80: 32
- TCP/1433: 18
- 7547: 17
- 15672: 21
- 2222: 15
- 8728: 14
- 2379: 14
- 3128: 13
- TCP/5432: 13
- 12125: 12

**Most Common CVEs:**
- CVE-2022-27255 CVE-2022-27255: 11
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2009-2765: 1
- CVE-2005-4050: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

**Commands Attempted by Attackers:**
- uname -s -v -n -r -m: 14
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 19
- lockr -ia .ssh: 19
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 19
- cat /proc/cpuinfo | grep name | wc -l: 14
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 14
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 14
- ls -lh $(which ls): 14
- which ls: 14
- crontab -l: 14
- w: 14
- uname -m: 14
- cat /proc/cpuinfo | grep model | grep name | wc -l: 14
- top: 14
- uname: 14
- Enter new UNIX password: : 13
- Enter new UNIX password:: 9
- uname -a: 13
- whoami: 12
- lscpu | grep Model: 12

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 377
- 2402000: 377
- ET SCAN NMAP -sS window 1024: 216
- 2009582: 216
- ET SCAN Sipsak SIP scan: 94
- 2008598: 94
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 56
- 2023753: 56
- ET INFO VNC Authentication Failure: 36
- 2002920: 36
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 26
- 2400031: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 40: 20
- 2403339: 20
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 12
- 2010939: 12
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 11
- 2038669: 11

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 19
- root/LeitboGi0ro: 4
- root/nPSpP4PBW0: 4
- root/A123456789!: 3
- root/3245gs5662d34: 3
- ice/ice123: 3
- admin/qwe: 3
- root/asdfQWER1234: 3
- root/1qaz2wsx#EDC$RFV: 3
- root/zhbjETuyMffoL8F: 2
- admin/: 2
- root/WB123456.: 2
- agent/agent: 2
- root/!Q2w3e4r: 2
- pi/raspberry: 2
- hive/hive: 2
- git/git: 2
- wang/wang123: 2
- nginx/nginx: 2
- user/111111: 2

**Files Uploaded/Downloaded:**
- sh: 98
- Mozi.m: 1
- 11: 3
- fonts.gstatic.com: 3
- css?family=Libre+Franklin...: 3
- ie8.css?ver=1.0: 3
- html5.js?ver=3.7.3: 3
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies
- The high number of attacks on port 445 (SMB) from a single IP (77.85.120.146) suggests a targeted worm or vulnerability scanner.
- A significant number of commands are aimed at disabling security features (`chattr -ia .ssh`) and installing SSH keys for persistence.
- The `urbotnetisass` malware was downloaded multiple times, indicating a coordinated campaign.
- The variety of credentials used suggests dictionary attacks are prevalent across multiple services.
- The CVEs detected are a mix of old and new vulnerabilities, indicating that attackers are trying a wide range of exploits.
