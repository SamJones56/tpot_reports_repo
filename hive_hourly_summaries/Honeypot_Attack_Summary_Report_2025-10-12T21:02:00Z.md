# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T21:01:28Z
**Timeframe:** 2025-10-12T20:20:01Z to 2025-10-12T21:00:01Z

**Files Used:**
- `agg_log_20251012T202001Z.json`
- `agg_log_20251012T204002Z.json`
- `agg_log_20251012T210001Z.json`

## Executive Summary

This report summarizes 19,541 malicious events captured by the honeypot network. The majority of attacks were detected by the Cowrie and Honeytrap honeypots. The most targeted services were SIP (5060), SMB (445), and SSH (22). A significant number of attacks originated from IP addresses `45.128.199.212` and `103.97.177.230`. Attackers were observed attempting to exploit several CVEs, with `CVE-2024-3721` being the most frequent. A large number of automated attacks were observed, characterized by repeated login attempts and the execution of reconnaissance commands.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 6418
- Honeytrap: 4395
- Sentrypeer: 1893
- Ciscoasa: 1832
- Suricata: 1647
- Dionaea: 1638
- Mailoney: 935
- Tanner: 597
- H0neytr4p: 54
- ConPot: 40
- Adbhoney: 29
- ssh-rsa: 30
- Honeyaml: 20
- Redishoneypot: 6
- Dicompot: 3
- ElasticPot: 2
- Heralding: 1
- Ipphoney: 1

### Top Attacking IPs

- 45.128.199.212: 1099
- 103.97.177.230: 1060
- 86.54.42.238: 821
- 115.138.86.57: 741
- 45.91.193.63: 703
- 4.213.160.153: 511
- 43.163.109.179: 487
- 223.100.22.69: 399
- 62.141.43.183: 324
- 172.86.95.98: 326
- 177.89.170.4: 252
- 152.32.218.149: 238
- 147.78.100.99: 230
- 196.251.71.24: 193
- 51.75.194.10: 144
- 34.122.106.61: 139
- 183.83.194.85: 159
- 152.32.129.136: 93
- 143.198.195.7: 154
- 103.4.145.50: 159

### Top Targeted Ports/Protocols

- 5060: 1893
- 445: 1184
- 22: 989
- 25: 949
- 2121: 929
- 80: 597
- 5903: 192
- TCP/21: 90
- TCP/22: 32
- 3306: 41
- 81: 69
- 5908: 82
- 5901: 79
- 5909: 82
- 8333: 71
- 9999: 40
- 23: 31
- 14343: 20
- 5907: 33
- 7001: 19

### Most Common CVEs

- CVE-2024-3721: 8
- CVE-2019-11500: 6
- CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2020-2551: 2

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 27
- `lockr -ia .ssh`: 27
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...`: 27
- `uname -a`: 25
- `Enter new UNIX password: `: 18
- `Enter new UNIX password:`: 18
- `cat /proc/cpuinfo | grep name | wc -l`: 24
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 24
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 24
- `ls -lh $(which ls)`: 24
- `which ls`: 24
- `crontab -l`: 24
- `w`: 24
- `uname -m`: 24
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 24
- `top`: 24
- `uname`: 24
- `whoami`: 24
- `lscpu | grep Model`: 9
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 9

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 429
- ET SCAN NMAP -sS window 1024: 164
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 140
- ET INFO Reserved Internal IP Traffic: 57
- ET FTP FTP PWD command attempt without login: 36
- ET FTP FTP CWD command attempt without login: 36
- ET HUNTING RDP Authentication Bypass Attempt: 26
- ET WEB_SERVER PHP tags in HTTP POST: 30
- ET SCAN Potential SSH Scan: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11

### Users / Login Attempts

- cron/: 49
- root/: 30
- 345gs5662d34/345gs5662d34: 23
- deploy/123123: 7
- admin/4444: 6
- vpn/vpnpass: 7
- ftpuser/ftppassword: 6
- admin/!QAZ2wsx#EDC: 6
- holu/holu: 5
- config/P@ssword: 4
- ubnt/1qaz2wsx: 4
- root/agonzales: 4
- root/root2014: 4
- root/vampire: 4
- hadi/3245gs5662d34: 3
- root/3245gs5662d34: 3
- vpn/3245gs5662d34: 4
- root/adminHW: 2
- root/abc@2024: 2
- root/qwerty123: 8

### Files Uploaded/Downloaded

- welcome.jpg): 11
- writing.jpg): 11
- tags.jpg): 11
- ohshit.sh;: 4
- wget.sh;: 4
- json: 2
- w.sh;: 1
- c.sh;: 1
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

### HTTP User-Agents

- No HTTP User-Agents were observed in this period.

### SSH Clients and Servers

- No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations

- No attacker AS organizations were identified in this period.

## Key Observations and Anomalies

- **High Volume of Automated Attacks:** The high frequency of login attempts with common and default credentials suggests widespread automated scanning and brute-force attacks.
- **Reconnaissance Activity:** The prevalence of commands like `uname -a`, `whoami`, and `lscpu` indicates that attackers are performing reconnaissance to understand the system architecture before deploying payloads.
- **Malware Delivery Attempts:** The downloading of `.sh` and other executable files, such as `urbotnetisass`, points to attempts to install malware on compromised systems.
- **Focus on a Few Key Services:** The concentration of attacks on a small number of ports (5060, 445, 22) suggests that attackers are targeting known and often vulnerable services.
