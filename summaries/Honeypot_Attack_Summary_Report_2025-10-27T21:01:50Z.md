
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T21:01:28Z
**Timeframe:** 2025-10-27T20:20:01Z to 2025-10-27T21:00:01Z
**Files Analyzed:**
- agg_log_20251027T202001Z.json
- agg_log_20251027T204001Z.json
- agg_log_20251027T210001Z.json

---

## Executive Summary

This report summarizes 14,359 security events collected from our honeypot network over the last hour. The primary activity involved reconnaissance and automated attacks, with a significant number of events targeting services like SSH and SMB. The most prominent attack vectors include attempts to exploit known vulnerabilities and brute-force login credentials. The majority of attacks originated from a diverse set of IP addresses, with 42.1.72.221 being the most active.

---

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 4504
- Cowrie: 3317
- Ciscoasa: 2025
- Suricata: 1972
- Sentrypeer: 1700
- Dionaea: 595
- Mailoney: 99
- Redishoneypot: 33
- Honeyaml: 22
- Adbhoney: 19
- ConPot: 18
- H0neytr4p: 15
- Tanner: 15
- Dicompot: 7
- ElasticPot: 6
- ssh-ed25519: 2

### Top 20 Attacking IPs
- 42.1.72.221: 1345
- 144.172.108.231: 1127
- 163.172.99.31: 356
- 203.81.241.55: 329
- 156.246.91.141: 314
- 107.170.36.5: 252
- 180.242.216.184: 253
- 187.45.95.66: 234
- 62.28.222.221: 208
- 115.21.183.150: 208
- 107.174.67.215: 188
- 65.1.142.20: 262
- 14.103.201.200: 156
- 155.94.170.106: 134
- 182.93.50.90: 134
- 144.172.108.161: 124
- 103.143.72.165: 124
- 103.179.56.9: 154
- 91.224.92.34: 202
- 37.221.66.121: 135

### Top 20 Targeted Ports/Protocols
- 5060: 1710
- 445: 559
- 22: 458
- TCP/445: 331
- 5901: 312
- 2079: 117
- 5903: 132
- 25: 99
- 8333: 84
- 23: 77
- TCP/22: 62
- 5905: 79
- 5904: 77
- 5907: 51
- 5909: 49
- 5908: 49
- 6379: 15
- 3333: 18
- 5984: 18
- 30000: 15

### Most Common CVEs
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500

### Top 20 Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 17
- lockr -ia .ssh: 17
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 17
- cat /proc/cpuinfo | grep name | wc -l: 17
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 17
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 17
- ls -lh $(which ls): 17
- which ls: 17
- crontab -l: 17
- w: 17
- uname -m: 17
- cat /proc/cpuinfo | grep model | grep name | wc -l: 17
- top: 17
- uname: 17
- uname -a: 17
- whoami: 17
- lscpu | grep Model: 17
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 17
- Enter new UNIX password: : 14
- Enter new UNIX password:: 14

### Top 10 Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 329
- 2024766: 329
- ET DROP Dshield Block Listed Source group 1: 382
- 2402000: 382
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 240
- 2023753: 240
- ET SCAN NMAP -sS window 1024: 192
- 2009582: 192
- ET HUNTING RDP Authentication Bypass Attempt: 86
- 2034857: 86

### Top 10 Users / Login Attempts
- 345gs5662d34/345gs5662d34: 17
- root/JamesBond007!: 4
- guanfengyan/guanfengyan: 4
- root/Jamshed00: 4
- root/jaPIdf9DA22a1hg8a: 4
- root/Jasd90asd90h: 4
- root/Javad09112920680: 4
- aniketp/aniketp: 3
- susanade/susanade: 3
- mitra/mitra: 3

### Files Uploaded/Downloaded
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- arm.urbotnetisass;: 1
- arm5.urbotnetisass;: 1
- arm6.urbotnetisass;: 1
- arm7.urbotnetisass;: 1
- x86_32.urbotnetisass;: 1
- mips.urbotnetisass;: 1
- mipsel.urbotnetisass;: 1
- arm.uhavenobotsxd;: 1
- arm5.uhavenobotsxd;: 1
- arm6.uhavenobotsxd;: 1
- arm7.uhavenobotsxd;: 1
- x86_32.uhavenobotsxd;: 1
- mips.uhavenobotsxd;: 1
- mipsel.uhavenobotsxd;: 1
- Mozi.a+jaws: 2

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients
- No specific SSH clients were logged in this timeframe.

### SSH Servers
- No specific SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

---

## Key Observations and Anomalies

- **Consistent Scanning Activity:** The high volume of events on ports like 5060 (SIP) and 445 (SMB) indicates widespread, automated scanning for vulnerable services.
- **Repetitive Commands:** The frequent use of commands to gather system information (`uname`, `lscpu`, `free`) and manipulate SSH keys suggests attackers are using standardized scripts to assess and compromise systems.
- **Malware Delivery:** The logs show attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) and ELF executables ( `...urbotnetisass`, `...uhavenobotsxd`), likely variants of Mirai or other IoT botnet malware.
- **DoublePulsar Detection:** The `DoublePulsar Backdoor installation communication` signature indicates attempts to exploit the SMB vulnerability (likely related to MS17-010).
- **Credential Stuffing:** The variety of usernames and passwords in login attempts is indicative of credential stuffing attacks against SSH services.
