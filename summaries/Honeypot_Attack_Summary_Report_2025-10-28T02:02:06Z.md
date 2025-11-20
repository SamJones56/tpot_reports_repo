
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T02:01:38Z
**Timeframe:** 2025-10-28T01:20:01Z to 2025-10-28T02:00:01Z
**Files Used:**
- agg_log_20251028T012001Z.json
- agg_log_20251028T014001Z.json
- agg_log_20251028T020001Z.json

## Executive Summary

This report summarizes 26,610 attacks recorded by the honeypot network. The most targeted services were Cowrie (SSH/Telnet), Honeytrap, and Dionaea (SMB). A significant portion of the attacks originated from IP address 154.241.53.218. The most targeted port was 445/TCP (SMB). Attackers were observed attempting to install backdoors and execute various reconnaissance commands.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 12287
- Honeytrap: 3557
- Suricata: 3467
- Dionaea: 3328
- Ciscoasa: 2050
- Sentrypeer: 1525
- Mailoney: 104
- Tanner: 99
- H0neytr4p: 43
- ConPot: 30
- Redishoneypot: 26
- Adbhoney: 20
- Honeyaml: 14
- Dicompot: 12
- Heralding: 3
- ElasticPot: 5

### Top Attacking IPs
- 154.241.53.218: 3001
- 183.149.163.92: 1315
- 5.167.79.4: 1308
- 144.172.108.231: 1089
- 189.126.4.42: 515
- 67.220.72.8: 483
- 49.49.234.156: 415
- 103.213.116.244: 409
- 27.71.230.3: 399
- 167.71.11.218: 458
- 51.83.46.40: 300
- 200.218.227.40: 250
- 203.194.106.66: 254
- 177.234.145.2: 330
- 81.211.72.167: 345
- 143.198.81.60: 279
- 185.68.246.174: 188
- 45.81.23.49: 282

### Top Targeted Ports/Protocols
- 445: 3291
- 22: 1751
- 5060: 1525
- TCP/445: 1310
- 2080: 130
- 5901: 215
- TCP/22: 123
- 25: 104
- 1089: 156
- 5903: 118
- 23: 47
- 5905: 81
- 5904: 78
- 80: 91

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-35394 CVE-2021-35394
- CVE-2019-11500 CVE-2019-11500
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2025-34036 CVE-2025-34036
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 63
- which ls: 63
- crontab -l: 63
- w: 63
- uname -m: 63
- cat /proc/cpuinfo | grep model | grep name | wc -l: 63
- top: 63
- uname: 63
- uname -a: 63
- whoami: 64
- lscpu | grep Model: 64
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 64
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 62
- lockr -ia .ssh: 62
- cat /proc/cpuinfo | grep name | wc -l: 62
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 62
- ls -lh $(which ls): 62
- Enter new UNIX password: : 39
- Enter new UNIX password:: 39

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1308
- 2024766: 1308
- ET DROP Dshield Block Listed Source group 1: 692
- 2402000: 692
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 312
- 2023753: 312
- ET SCAN NMAP -sS window 1024: 185
- 2009582: 185
- ET HUNTING RDP Authentication Bypass Attempt: 120
- 2034857: 120
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET SCAN Potential SSH Scan: 53
- 2001219: 53

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 58
- root/3245gs5662d34: 22
- postgres/secret: 7
- root/12122023: 7
- asikhwal/asikhwal: 7
- photo/photo: 5
- pbsdata/3245gs5662d34: 5
- samira/samira123: 5
- root/159951: 5
- console/console: 5
- root/Abcd1234!@#$: 5
- root/123456ab@: 5

### Files Uploaded/Downloaded
- sh: 98
- lol.sh;: 2
- arm.uhavenobotsxd;: 5
- arm.uhavenobotsxd: 5
- arm5.uhavenobotsxd;: 5
- arm5.uhavenobotsxd: 5
- arm6.uhavenobotsxd;: 5
- arm6.uhavenobotsxd: 5
- arm7.uhavenobotsxd;: 5
- arm7.uhavenobotsxd: 5
- x86_32.uhavenobotsxd;: 5
- x86_32.uhavenobotsxd: 5
- mips.uhavenobotsxd;: 5
- mips.uhavenobotsxd: 5
- mipsel.uhavenobotsxd;: 5
- mipsel.uhavenobotsxd: 5
- string.js: 1
- xhtml1-transitional.dtd: 1
- 19: 1

### HTTP User-Agents
No HTTP User-Agents were observed in this period.

### SSH Clients and Servers
No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations
No attacker AS organizations were identified in this period.

## Key Observations and Anomalies

- **SSH Key Injection:** A recurring command involves an attempt to add an SSH key to the `authorized_keys` file. This is a common technique for attackers to maintain persistent access to a compromised system.
- **Reconnaissance Commands:** Attackers frequently used commands like `lscpu`, `df -h`, `whoami`, `uname -a`, and `free -m` to gather information about the system's architecture, storage, and operating system.
- **Malware Download Attempts:** Several entries show attempts to download and execute files with names like `arm.uhavenobotsxd` and `lol.sh`. These are likely scripts or binaries for various architectures, indicating automated attacks targeting IoT or embedded devices.
- **DoublePulsar Activity:** The most triggered signature, "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication," suggests that many attacks are related to the infamous NSA-leaked exploit, which is often used to deliver ransomware and other malware.
